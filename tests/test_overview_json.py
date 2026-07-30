#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.

import json
from pathlib import Path
import sys

import pytest

from omci import cli


OVERVIEW_DATA = {
    "check_summary": {"summary": {"resp_fail_count": 0}, "packets": []},
    "mib_database": {"256": {"me_name": "ONT-G", "instances": {}}},
    "vlan_operation_data": [],
    "tcont_flows_data": [],
    "topology_data": {"nodes": [], "edges": []},
    "onu_capability": {
        "pon_type": "XG-PON (Symmetric 10G/10G)",
        "pptp_count": 1,
        "pots_count": 0,
        "tcont_count": 2,
        "priority_queue_count": 24,
    },
}


def configure_overview_cli(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    arguments: list[str],
) -> Path:
    pcap_path = tmp_path / "sample.pcap"
    pcap_path.write_bytes(b"pcap")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        cli.overview,
        "generate_pcap_ai_overview_data",
        lambda path: OVERVIEW_DATA,
    )
    monkeypatch.setattr(
        cli.omcimd,
        "render_overview_md",
        lambda data: "# Overview\n\nRendered overview\n",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["omcipcap", "overview", str(pcap_path), *arguments],
    )
    return pcap_path


def assert_no_overview_files(tmp_path: Path) -> None:
    assert not (tmp_path / "overview.json").exists()
    assert not (tmp_path / "overview.md").exists()


def test_overview_is_registered(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["omcipcap", "overview", "--help"])

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code == 0
    assert "usage: omcipcap overview" in capsys.readouterr().out


def test_overview_json_is_not_registered(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["omcipcap", "overview-json"])

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code == 2
    assert "invalid choice: 'overview-json'" in capsys.readouterr().err


def test_overview_defaults_to_markdown_stdout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_overview_cli(monkeypatch, tmp_path, [])

    cli.main()

    output = capsys.readouterr().out
    assert output.startswith("# Overview")
    with pytest.raises(json.JSONDecodeError):
        json.loads(output)
    assert_no_overview_files(tmp_path)


def test_overview_json_mode_writes_json_stdout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_overview_cli(monkeypatch, tmp_path, ["-j"])

    cli.main()

    output = capsys.readouterr().out
    assert json.loads(output) == OVERVIEW_DATA
    assert "# Overview" not in output
    assert_no_overview_files(tmp_path)


def test_overview_explicit_markdown_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_overview_cli(monkeypatch, tmp_path, ["--md"])

    cli.main()

    assert capsys.readouterr().out.startswith("# Overview")
    assert_no_overview_files(tmp_path)


def test_overview_loads_mib_json_and_semantic_extensions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mib_json = tmp_path / "vendor.json"
    mib_json.write_text("{}", encoding="utf-8")
    semantic_dir = tmp_path / "semantics"
    semantic_dir.mkdir()
    configure_overview_cli(
        monkeypatch,
        tmp_path,
        ["--mib-json", str(mib_json), "--semantic-dir", str(semantic_dir)],
    )
    loaded: list[tuple[str, Path]] = []

    def load_mib(path: str) -> bool:
        loaded.append(("mib", Path(path)))
        return True

    def load_semantics(path: str) -> bool:
        loaded.append(("semantics", Path(path)))
        return True

    monkeypatch.setattr(cli, "load_mib_json", load_mib)
    monkeypatch.setattr(cli.omcisemantic, "load_external_semantics", load_semantics)

    cli.main()

    assert loaded == [("mib", mib_json), ("semantics", semantic_dir)]


def test_overview_json_and_markdown_are_mutually_exclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_overview_cli(monkeypatch, tmp_path, ["-j", "--md"])

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code == 2
    assert "not allowed with argument" in capsys.readouterr().err
    assert_no_overview_files(tmp_path)
