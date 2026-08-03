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
