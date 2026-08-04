#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

from collections.abc import Iterator
import io
from pathlib import Path
import sys

import pytest

from omci import cli
from omci.ai import diagnosis
from omci.ai.providers import AIProvider, AIProviderRequestError


class StubProvider(AIProvider):
    def __init__(self, fragments: list[str]) -> None:
        super().__init__()
        self.fragments = fragments
        self.calls: list[dict[str, str]] = []

    def list_models(self) -> list[str]:
        return []

    def stream_generate(
        self,
        *,
        model: str,
        system_prompt: str,
        user_prompt: str,
    ) -> Iterator[str]:
        self.calls.append(
            {
                "model": model,
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
            }
        )
        yield from self.fragments


class FlushTrackingOutput(io.StringIO):
    def __init__(self) -> None:
        super().__init__()
        self.flush_count = 0

    def flush(self) -> None:
        self.flush_count += 1
        super().flush()


def test_load_system_prompt_uses_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AI_DIAG_SYSTEM_PROMPT", raising=False)

    assert diagnosis.load_system_prompt() == diagnosis.DEFAULT_SYSTEM_PROMPT


def test_load_system_prompt_uses_custom_file_without_modification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompt_path = tmp_path / "system.md"
    prompt_path.write_text("Custom system prompt\n", encoding="utf-8")
    monkeypatch.setenv("AI_DIAG_SYSTEM_PROMPT", str(prompt_path))

    assert diagnosis.load_system_prompt() == "Custom system prompt\n"


def test_load_problem_prompt_preserves_content(tmp_path: Path) -> None:
    problem_path = tmp_path / "problem.md"
    content = "# Problem\n\n  Preserve whitespace.  \n"
    problem_path.write_text(content, encoding="utf-8")

    assert diagnosis.load_problem_prompt(problem_path) == content


def test_prompt_file_errors_are_clear(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing_path = tmp_path / "missing.md"
    monkeypatch.setenv("AI_DIAG_SYSTEM_PROMPT", str(missing_path))
    with pytest.raises(
        diagnosis.AIDiagnosisError, match="System prompt file not found"
    ):
        diagnosis.load_system_prompt()

    invalid_path = tmp_path / "invalid.md"
    invalid_path.write_bytes(b"\xff")
    with pytest.raises(diagnosis.AIDiagnosisError, match="not valid UTF-8"):
        diagnosis.load_problem_prompt(invalid_path)

    with pytest.raises(
        diagnosis.AIDiagnosisError, match="Problem Markdown file not found"
    ):
        diagnosis.load_problem_prompt(tmp_path / "missing-problem.md")


def test_empty_custom_system_prompt_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompt_path = tmp_path / "empty.md"
    prompt_path.write_text(" \n", encoding="utf-8")
    monkeypatch.setenv("AI_DIAG_SYSTEM_PROMPT", str(prompt_path))

    with pytest.raises(diagnosis.AIDiagnosisError, match="System prompt file is empty"):
        diagnosis.load_system_prompt()


def test_generate_overview_markdown_reuses_existing_implementation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pcap_path = tmp_path / "sample.pcap"
    overview_data = {"evidence": "observed"}
    generated_paths: list[str] = []

    def generate(path: str) -> dict[str, str]:
        generated_paths.append(path)
        return overview_data

    monkeypatch.setattr(diagnosis.overview, "generate_pcap_ai_overview_data", generate)
    monkeypatch.setattr(
        diagnosis.omcimd,
        "render_overview_md",
        lambda data: (
            "# Overview\n\nObserved evidence\n" if data is overview_data else ""
        ),
    )

    result = diagnosis.generate_overview_markdown(pcap_path)

    assert generated_paths == [str(pcap_path)]
    assert result == "# Overview\n\nObserved evidence\n"


def test_load_problem_prompt_rejects_empty_file(tmp_path: Path) -> None:
    problem_path = tmp_path / "problem.md"
    problem_path.write_text("", encoding="utf-8")

    with pytest.raises(
        diagnosis.AIDiagnosisError,
        match="Problem Markdown file is empty",
    ):
        diagnosis.load_problem_prompt(problem_path)


def test_run_diagnosis_streams_provider_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pcap_path = tmp_path / "sample.pcap"
    pcap_path.write_bytes(b"pcap")
    problem_path = tmp_path / "problem.md"
    problem_path.write_text("User problem", encoding="utf-8")
    provider = StubProvider(["First", " fragment"])
    output = FlushTrackingOutput()

    monkeypatch.delenv("AI_DIAG_SYSTEM_PROMPT", raising=False)
    monkeypatch.setattr(
        diagnosis, "generate_overview_markdown", lambda path: "# Overview\nEvidence\n"
    )
    monkeypatch.setattr(diagnosis, "create_provider", lambda name: provider)

    diagnosis.run_diagnosis(
        pcap_path,
        problem_path,
        "openrouter",
        "model-id",
        output,
    )

    assert provider.calls == [
        {
            "model": "model-id",
            "system_prompt": diagnosis.DEFAULT_SYSTEM_PROMPT,
            "user_prompt": diagnosis.compose_user_prompt(
                "User problem",
                "# Overview\nEvidence\n",
            ),
        }
    ]
    assert output.getvalue() == "First fragment\n"
    assert output.flush_count == 3


def test_run_diagnosis_reports_streaming_interruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class InterruptedProvider(StubProvider):
        def stream_generate(
            self,
            *,
            model: str,
            system_prompt: str,
            user_prompt: str,
        ) -> Iterator[str]:
            del model, system_prompt, user_prompt
            raise KeyboardInterrupt
            yield

    pcap_path = tmp_path / "sample.pcap"
    pcap_path.write_bytes(b"pcap")
    problem_path = tmp_path / "problem.md"
    problem_path.write_text("Problem", encoding="utf-8")
    monkeypatch.setattr(
        diagnosis, "generate_overview_markdown", lambda path: "Overview"
    )
    monkeypatch.setattr(
        diagnosis, "create_provider", lambda name: InterruptedProvider([])
    )

    with pytest.raises(diagnosis.AIDiagnosisError, match="streaming interrupted"):
        diagnosis.run_diagnosis(
            pcap_path,
            problem_path,
            "openrouter",
            "model",
            io.StringIO(),
        )


def test_ai_diag_cli_streams_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    pcap_path = tmp_path / "sample.pcap"
    pcap_path.write_bytes(b"pcap")
    problem_path = tmp_path / "problem.md"
    problem_path.write_text("Problem", encoding="utf-8")
    calls: list[tuple[Path, Path, str, str]] = []

    def run(
        pcap: Path,
        problem: Path,
        provider: str,
        model: str,
    ) -> None:
        calls.append((pcap, problem, provider, model))
        print("diagnosis", end="", flush=True)

    monkeypatch.setattr(cli.diagnosis, "run_diagnosis", run)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "omcipcap",
            "ai",
            "diag",
            str(pcap_path),
            "--problem-md",
            str(problem_path),
            "--provider",
            "openrouter",
            "--model",
            "anthropic/claude-opus-4.5",
        ],
    )

    cli.main()

    assert calls == [
        (
            pcap_path,
            problem_path,
            "openrouter",
            "anthropic/claude-opus-4.5",
        )
    ]
    assert capsys.readouterr().out == "diagnosis"


def test_ai_diag_help_lists_semantic_options(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["omcipcap", "ai", "diag", "--help"])

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    assert "--mib-json" in output
    assert "--semantic-dir" in output


@pytest.mark.parametrize(
    ("extra_args", "expected_loads"),
    [
        (["--mib-json", "vendor.json"], [("mib", "vendor.json")]),
        (["--semantic-dir", "semantics"], [("semantics", "semantics")]),
        (
            ["--mib-json", "vendor.json", "--semantic-dir", "semantics"],
            [("mib", "vendor.json"), ("semantics", "semantics")],
        ),
    ],
)
def test_ai_diag_loads_semantic_configuration_before_diagnosis(
    extra_args: list[str],
    expected_loads: list[tuple[str, str]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pcap_path = tmp_path / "sample.pcap"
    pcap_path.write_bytes(b"pcap")
    problem_path = tmp_path / "problem.md"
    problem_path.write_text("Problem", encoding="utf-8")
    events: list[tuple[str, str]] = []

    def load_mib(path: str) -> bool:
        events.append(("mib", path))
        return True

    def load_semantics(path: str) -> bool:
        events.append(("semantics", path))
        return True

    def run(
        pcap: Path,
        problem: Path,
        provider: str,
        model: str,
    ) -> None:
        del pcap, problem, provider, model
        events.append(("diagnosis", "run"))

    monkeypatch.setattr(cli, "load_mib_json", load_mib)
    monkeypatch.setattr(cli.omcisemantic, "load_external_semantics", load_semantics)
    monkeypatch.setattr(cli.diagnosis, "run_diagnosis", run)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "omcipcap",
            "ai",
            "diag",
            str(pcap_path),
            "--problem-md",
            str(problem_path),
            "--provider",
            "openrouter",
            "--model",
            "model",
            *extra_args,
        ],
    )

    cli.main()

    assert events == [*expected_loads, ("diagnosis", "run")]


def test_ai_diag_uses_overview_generated_after_semantic_loading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    pcap_path = tmp_path / "sample.pcap"
    pcap_path.write_bytes(b"pcap")
    problem_path = tmp_path / "problem.md"
    problem_path.write_text("Problem", encoding="utf-8")
    provider = StubProvider(["Diagnosis"])
    loaded: list[str] = []

    def load_mib(path: str) -> bool:
        loaded.append(f"mib:{path}")
        return True

    def load_semantics(path: str) -> bool:
        loaded.append(f"semantics:{path}")
        return True

    def generate(path: Path) -> str:
        del path
        assert loaded == ["mib:vendor.json", "semantics:semantics"]
        return "# Overview\n\nCustom semantic evidence\n"

    monkeypatch.setattr(cli, "load_mib_json", load_mib)
    monkeypatch.setattr(cli.omcisemantic, "load_external_semantics", load_semantics)
    monkeypatch.setattr(diagnosis, "generate_overview_markdown", generate)
    monkeypatch.setattr(diagnosis, "create_provider", lambda name: provider)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "omcipcap",
            "ai",
            "diag",
            str(pcap_path),
            "--problem-md",
            str(problem_path),
            "--provider",
            "openrouter",
            "--model",
            "model",
            "--mib-json",
            "vendor.json",
            "--semantic-dir",
            "semantics",
        ],
    )

    cli.main()

    assert provider.calls[0]["user_prompt"] == diagnosis.compose_user_prompt(
        "Problem",
        "# Overview\n\nCustom semantic evidence\n",
    )
    assert capsys.readouterr().out == "Diagnosis\n"


def test_ai_diag_semantic_loading_failure_prevents_provider_invocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    pcap_path = tmp_path / "sample.pcap"
    pcap_path.write_bytes(b"pcap")
    problem_path = tmp_path / "problem.md"
    problem_path.write_text("Problem", encoding="utf-8")

    def fail_if_run(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("provider workflow must not start")

    monkeypatch.setattr(cli.diagnosis, "run_diagnosis", fail_if_run)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "omcipcap",
            "ai",
            "diag",
            str(pcap_path),
            "--problem-md",
            str(problem_path),
            "--provider",
            "openrouter",
            "--model",
            "model",
            "--semantic-dir",
            str(tmp_path / "missing-semantics"),
        ],
    )

    cli.main()

    captured = capsys.readouterr()
    assert "Error loading semantic directory" in captured.out
    assert captured.err == ""


@pytest.mark.parametrize(
    "error",
    [
        diagnosis.AIDiagnosisError("Problem Markdown file not found: problem.md"),
        AIProviderRequestError("AI provider stream failed."),
    ],
)
def test_ai_diag_cli_reports_errors_to_stderr(
    error: Exception,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise error

    monkeypatch.setattr(cli.diagnosis, "run_diagnosis", fail)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "omcipcap",
            "ai",
            "diag",
            str(tmp_path / "sample.pcap"),
            "--problem-md",
            str(tmp_path / "problem.md"),
            "--provider",
            "openrouter",
            "--model",
            "model",
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code == 2
    captured = capsys.readouterr()
    assert str(error) in captured.err
    assert captured.out == ""


def test_compose_diff_user_prompt_has_deterministic_sections() -> None:
    prompt = diagnosis.compose_diff_user_prompt(
        "# Problem\nTarget service fails.\n\n",
        "# MIB Diff\nDiff evidence.\n\n",
        "# Overview\nGolden evidence.\n\n",
        "# Overview\nTarget evidence.\n\n",
    )

    headings = [
        "User-Reported Problem\n=====================",
        "Full Lifecycle Semantic MIB Diff\n================================",
        "OMCIPcap Analysis of the Golden PCAP\n====================================",
        "OMCIPcap Analysis of the Target PCAP\n====================================",
    ]
    positions = [prompt.index(heading) for heading in headings]
    assert positions == sorted(positions)
    assert "# Problem\nTarget service fails." in prompt
    assert "# MIB Diff\nDiff evidence." in prompt
    assert "# Overview\nGolden evidence." in prompt
    assert "# Overview\nTarget evidence." in prompt
    assert "Comparison direction: Target PCAP → Golden PCAP." in prompt
    assert "`old` values represent the Target PCAP" in prompt
    assert "`new` values represent the Golden PCAP" in prompt
    assert "`added` entries exist only in the Golden PCAP" in prompt
    assert "`removed` entries exist only in the Target PCAP" in prompt
    assert "`modified` entries exist in both captures but differ" in prompt
    assert prompt.endswith("\n")
    assert not prompt.endswith("\n\n")


def test_generate_full_lifecycle_diff_markdown_reuses_existing_pipeline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_path = tmp_path / "target.pcap"
    golden_path = tmp_path / "golden.pcap"
    target_packets = [(1, "target", None)]
    golden_packets = [(2, "golden", None)]
    target_mib = {"target": object()}
    golden_mib = {"golden": object()}
    diff_data = {"changes": ["difference"]}
    loaded: list[tuple[str, bool]] = []
    reconstructed: list[object] = []
    compared: list[tuple[object, object]] = []
    rendered: list[object] = []

    def load(path: str, include_raw: bool = False) -> list[tuple[int, str, None]]:
        loaded.append((path, include_raw))
        return target_packets if path == str(target_path) else golden_packets

    def reconstruct(packets: object) -> object:
        reconstructed.append(packets)
        return target_mib if packets is target_packets else golden_mib

    def compare(target: object, golden: object) -> object:
        compared.append((target, golden))
        return diff_data

    def render(data: object) -> str:
        rendered.append(data)
        return "# MIB Diff\n"

    monkeypatch.setattr(diagnosis, "load_omci_packets", load)
    monkeypatch.setattr(diagnosis.omciparser, "get_all_mib_db", reconstruct)
    monkeypatch.setattr(diagnosis.omciparser, "get_mib_diff_data", compare)
    monkeypatch.setattr(diagnosis.omcimd, "render_diff_md", render)

    result = diagnosis.generate_full_lifecycle_diff_markdown(
        target_path,
        golden_path,
    )

    assert loaded == [(str(target_path), False), (str(golden_path), False)]
    assert reconstructed == [target_packets, golden_packets]
    assert compared == [(target_mib, golden_mib)]
    assert rendered == [diff_data]
    assert result == "# MIB Diff\n"


def test_run_diagnosis_diff_builds_context_and_streams_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_path = tmp_path / "target.pcap"
    golden_path = tmp_path / "golden.pcap"
    problem_path = tmp_path / "problem.md"
    target_path.write_bytes(b"target")
    golden_path.write_bytes(b"golden")
    problem_path.write_text("Target problem", encoding="utf-8")
    provider = StubProvider(["Diagnosis"])
    output = FlushTrackingOutput()
    overview_paths: list[Path] = []

    def overview(path: Path) -> str:
        overview_paths.append(path)
        if path == golden_path:
            return "# Overview\nGolden evidence\n"
        return "# Overview\nTarget evidence\n"

    monkeypatch.setenv("AI_DIAG_SYSTEM_PROMPT", str(tmp_path / "system.md"))
    (tmp_path / "system.md").write_text("Custom system", encoding="utf-8")
    monkeypatch.setattr(
        diagnosis,
        "generate_full_lifecycle_diff_markdown",
        lambda target, golden: "# Diff\nSemantic evidence\n",
    )
    monkeypatch.setattr(diagnosis, "generate_overview_markdown", overview)
    monkeypatch.setattr(diagnosis, "create_provider", lambda name: provider)

    diagnosis.run_diagnosis_diff(
        target_path,
        golden_path,
        problem_path,
        "openrouter",
        "model-id",
        output,
    )

    assert overview_paths == [golden_path, target_path]
    assert provider.calls == [
        {
            "model": "model-id",
            "system_prompt": "Custom system",
            "user_prompt": diagnosis.compose_diff_user_prompt(
                "Target problem",
                "# Diff\nSemantic evidence\n",
                "# Overview\nGolden evidence\n",
                "# Overview\nTarget evidence\n",
            ),
        }
    ]
    assert output.getvalue() == "Diagnosis\n"


def test_ai_diag_diff_help_lists_required_and_semantic_options(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["omcipcap", "ai", "diag-diff", "--help"])

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    assert "--golden-pcap" in output
    assert "--problem-md" in output
    assert "--provider" in output
    assert "--model" in output
    assert "--mib-json" in output
    assert "--semantic-dir" in output


def test_ai_diag_diff_requires_all_inputs(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["omcipcap", "ai", "diag-diff", "target.pcap"])

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code == 2
    error = capsys.readouterr().err
    assert "--golden-pcap" in error
    assert "--problem-md" in error
    assert "--provider" in error
    assert "--model" in error


def test_ai_diag_diff_cli_forwards_arguments_after_semantic_loading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_path = tmp_path / "target.pcap"
    golden_path = tmp_path / "golden.pcap"
    problem_path = tmp_path / "problem.md"
    events: list[object] = []

    def load_mib(path: str) -> bool:
        events.append(("mib", path))
        return True

    def load_semantics(path: str) -> bool:
        events.append(("semantics", path))
        return True

    def run(*args: object) -> None:
        events.append(args)

    monkeypatch.setattr(cli, "load_mib_json", load_mib)
    monkeypatch.setattr(cli.omcisemantic, "load_external_semantics", load_semantics)
    monkeypatch.setattr(cli.diagnosis, "run_diagnosis_diff", run)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "omcipcap",
            "ai",
            "diag-diff",
            str(target_path),
            "--golden-pcap",
            str(golden_path),
            "--problem-md",
            str(problem_path),
            "--provider",
            "openrouter",
            "--model",
            "model-id",
            "--mib-json",
            "vendor.json",
            "--semantic-dir",
            "semantics",
        ],
    )

    cli.main()

    assert events == [
        ("mib", "vendor.json"),
        ("semantics", "semantics"),
        (target_path, golden_path, problem_path, "openrouter", "model-id"),
    ]


@pytest.mark.parametrize("missing", ["target", "golden"])
def test_run_diagnosis_diff_rejects_missing_capture_before_provider(
    missing: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_path = tmp_path / "target.pcap"
    golden_path = tmp_path / "golden.pcap"
    problem_path = tmp_path / "problem.md"
    if missing != "target":
        target_path.write_bytes(b"target")
    if missing != "golden":
        golden_path.write_bytes(b"golden")
    problem_path.write_text("Problem", encoding="utf-8")
    monkeypatch.setattr(
        diagnosis,
        "create_provider",
        lambda name: pytest.fail("provider must not be created"),
    )

    with pytest.raises(diagnosis.AIDiagnosisError, match="PCAP file not found"):
        diagnosis.run_diagnosis_diff(
            target_path,
            golden_path,
            problem_path,
            "openrouter",
            "model",
        )


def test_run_diagnosis_diff_rejects_empty_problem_before_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_path = tmp_path / "target.pcap"
    golden_path = tmp_path / "golden.pcap"
    problem_path = tmp_path / "problem.md"
    target_path.write_bytes(b"target")
    golden_path.write_bytes(b"golden")
    problem_path.write_text(" \n", encoding="utf-8")
    monkeypatch.setattr(
        diagnosis,
        "create_provider",
        lambda name: pytest.fail("provider must not be created"),
    )

    with pytest.raises(diagnosis.AIDiagnosisError, match="Problem Markdown file is empty"):
        diagnosis.run_diagnosis_diff(
            target_path,
            golden_path,
            problem_path,
            "openrouter",
            "model",
        )


def test_ai_diag_diff_semantic_failure_prevents_diagnosis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_if_run(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("provider workflow must not start")

    monkeypatch.setattr(cli.diagnosis, "run_diagnosis_diff", fail_if_run)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "omcipcap",
            "ai",
            "diag-diff",
            str(tmp_path / "target.pcap"),
            "--golden-pcap",
            str(tmp_path / "golden.pcap"),
            "--problem-md",
            str(tmp_path / "problem.md"),
            "--provider",
            "openrouter",
            "--model",
            "model",
            "--semantic-dir",
            str(tmp_path / "missing-semantics"),
        ],
    )

    cli.main()

    assert "Error loading semantic directory" in capsys.readouterr().out
