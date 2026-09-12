#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

import os
import subprocess
import sys
from pathlib import Path

import pytest


PCAP = Path(__file__).resolve().parents[1] / "examples" / "mib_before.pcap"
PCAP_COMMANDS = [
    "check", "mibdb", "mibdb-diff", "diff", "topology", "graphic",
    "vlan-tbl", "tcont-flow", "overview",
]
EXTENSION_COMMANDS = ["mibdb", "mibdb-diff", "diff", "overview", "diag", "diag-diff"]


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["omcipcap", *args], capture_output=True, text=True)


def command_args(command: str) -> list[str]:
    if command == "version":
        return [command]
    if command in ("mibdb-diff", "diff"):
        return [command, str(PCAP), str(PCAP)]
    if command in ("diag", "diag-diff"):
        args = [
            "ai", command, str(PCAP), "--problem-md", "unused.md",
            "--provider", "openai", "--model", "unused",
        ]
        if command == "diag-diff":
            args.extend(["--golden-pcap", str(PCAP)])
        return args
    return [command, str(PCAP)]


@pytest.mark.parametrize(
    "command", ["check", "mibdb", "vlan-tbl", "tcont-flow", "topology", "graphic", "overview"]
)
def test_missing_pcap(command: str, tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.pcap"
    result = run_cli(command, str(missing))
    assert result.returncode != 0
    assert result.stdout == f"[!] Error: PCAP file not found: {missing}\n"
    assert result.stderr == ""


@pytest.mark.parametrize("command", ["mibdb-diff", "diff"])
@pytest.mark.parametrize("missing_index", [0, 1])
def test_missing_diff_pcap(command: str, missing_index: int, tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.pcap"
    paths = [str(PCAP), str(PCAP)]
    paths[missing_index] = str(missing)
    result = run_cli(command, *paths)
    assert result.returncode != 0
    assert result.stdout == f"[!] Error: PCAP file not found: {missing}\n"
    assert result.stderr == ""


@pytest.mark.parametrize("command", EXTENSION_COMMANDS)
@pytest.mark.parametrize("kind", ["missing", "malformed", "directory"])
def test_invalid_mib_json(command: str, kind: str, tmp_path: Path) -> None:
    path = tmp_path / "invalid.json"
    if kind == "malformed":
        path.write_text("{invalid", encoding="utf-8")
    elif kind == "directory":
        path.mkdir()
    result = run_cli(*command_args(command), "--mib-json", str(path))
    assert result.returncode != 0
    if kind == "missing":
        assert result.stdout == ""
    else:
        assert f"[!] Error loading MIB file: {path}\n" in result.stdout
        assert "[!] MIB JSON Error:" in result.stdout
    assert result.stderr == ""


@pytest.mark.parametrize("command", EXTENSION_COMMANDS)
def test_invalid_semantic_dir(command: str, tmp_path: Path) -> None:
    missing = tmp_path / "missing-semantics"
    result = run_cli(*command_args(command), "--semantic-dir", str(missing))
    assert result.returncode != 0
    assert result.stdout == f"[!] Error loading semantic directory: {missing}\n\n\n"
    assert result.stderr == ""


@pytest.mark.parametrize("command", ["mibdb", "mibdb-diff", "diff"])
@pytest.mark.parametrize("value", ["abc", ""])
def test_invalid_class_id(command: str, value: str) -> None:
    result = run_cli(*command_args(command), "--class-id", value)
    assert result.returncode != 0
    assert result.stdout == (
        "[!] Error: Class ID must be numbers separated by commas (e.g. 84,171)\n"
    )
    assert result.stderr == ""


@pytest.mark.parametrize("command", ["version", *PCAP_COMMANDS])
def test_success(command: str, tmp_path: Path) -> None:
    args = command_args(command)
    output = tmp_path / "topology.html"
    if command in ("topology", "graphic"):
        args.extend(["-o", str(output)])
    result = run_cli(*args)
    if command in ("topology", "graphic"):
        assert output.is_file()
    assert result.returncode == 0, result.stderr
    assert result.stdout


def test_argparse_usage_error() -> None:
    result = run_cli("check")
    assert result.returncode == 2
    assert "usage:" in result.stderr


@pytest.mark.parametrize("command", PCAP_COMMANDS)
def test_invalid_pcap(command: str, tmp_path: Path) -> None:
    broken = tmp_path / "broken.pcap"
    broken.write_bytes(b"not a capture")
    args = command_args(command)
    args[1] = str(broken)
    result = run_cli(*args)
    assert result.returncode != 0
    assert "Error reading pcap:" in result.stdout
    assert not broken.with_suffix(".html").exists()


@pytest.mark.parametrize("command", ["mibdb-diff", "diff"])
def test_invalid_secondary_pcap(command: str, tmp_path: Path) -> None:
    broken = tmp_path / "broken.pcap"
    broken.write_bytes(b"not a capture")
    result = run_cli(command, str(PCAP), str(broken))
    assert result.returncode != 0
    assert "Error reading pcap:" in result.stdout


@pytest.mark.parametrize("kind", ["directory", "permissions"])
def test_unreadable_pcap(kind: str, tmp_path: Path) -> None:
    path = tmp_path / "unreadable.pcap"
    if kind == "directory":
        path.mkdir()
    else:
        path.write_bytes(PCAP.read_bytes())
        path.chmod(0)
        if os.access(path, os.R_OK):
            path.chmod(0o600)
            pytest.skip("Current user can read files without read permissions")
    try:
        result = run_cli("check", str(path))
        assert result.returncode != 0
        assert "Error reading pcap:" in result.stdout
    finally:
        if kind == "permissions":
            path.chmod(0o600)


@pytest.mark.parametrize("command", PCAP_COMMANDS)
def test_no_matching_omci_is_success(command: str, tmp_path: Path) -> None:
    from scapy.all import Ether, IP, UDP, wrpcap

    path = tmp_path / "non-omci.pcap"
    wrpcap(str(path), [Ether() / IP(dst="127.0.0.1") / UDP()])
    args = command_args(command)
    args[1] = str(path)
    if command in ("mibdb-diff", "diff"):
        args[2] = str(path)
    result = run_cli(*args)
    assert result.returncode == 0, result.stderr
    assert "Error reading pcap:" not in result.stdout


@pytest.mark.parametrize("option", ["--mib-json", "--semantic-dir"])
def test_explicit_empty_extension_path(option: str) -> None:
    result = run_cli("mibdb", str(PCAP), option, "")
    assert result.returncode != 0


def test_semantic_module_failure(tmp_path: Path) -> None:
    header = Path(__file__).read_text(encoding="utf-8").split("\n\n", 1)[0]
    (tmp_path / "broken.py").write_text(
        header + '\n\nraise ValueError("invalid test semantic data")\n',
        encoding="utf-8",
    )
    result = run_cli("mibdb", str(PCAP), "--semantic-dir", str(tmp_path))
    assert result.returncode != 0
    assert "invalid test semantic data" in result.stderr


def test_topology_output_failure(tmp_path: Path) -> None:
    result = run_cli("topology", str(PCAP), "-o", str(tmp_path))
    assert result.returncode != 0
    assert "Topology visualization saved" not in result.stdout


@pytest.mark.parametrize("args", [[], ["ai"], ["ai", "rag"]])
def test_no_subcommand(args: list[str]) -> None:
    result = run_cli(*args)
    assert result.returncode != 0
    assert "usage:" in result.stdout + result.stderr


def test_explicit_help_succeeds() -> None:
    result = run_cli("--help")
    assert result.returncode == 0
    assert "usage:" in result.stdout


def test_ai_providers_succeeds() -> None:
    result = run_cli("ai", "providers")
    assert result.returncode == 0
    assert "openai" in result.stdout


@pytest.mark.parametrize("completed", [False, True])
def test_ingest_completion_status(completed: bool) -> None:
    from omci import cli

    if not cli.rag_available:
        pytest.skip("Optional RAG dependencies are unavailable")
    # Isolate the CLI status contract without accessing a model or database.
    script = (
        "import sys\n"
        "from unittest.mock import patch\n"
        "from omci import cli\n"
        "sys.argv = ['omcipcap', 'ai', 'rag', 'ingest', '--case-id', 'test', "
        "'--issue-md', 'issue.md', 'capture.pcap']\n"
        f"with patch.object(cli, 'ingest_case', return_value={completed!r}):\n"
        "    sys.exit(cli.main())\n"
    )
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
    if completed:
        assert result.returncode == 0, result.stderr
        assert 'RAG case ingested: "test"' in result.stdout
    else:
        assert result.returncode != 0
        assert "RAG case ingested" not in result.stdout
