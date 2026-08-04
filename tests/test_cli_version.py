#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

import json
import sys

import pytest

from omci import __version__
from omci import cli


def run_cli(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    *arguments: str,
) -> tuple[int, str, str]:
    monkeypatch.setattr(sys, "argv", ["omcipcap", *arguments])

    try:
        cli.main()
    except SystemExit as exc:
        exit_code = exc.code
    else:
        exit_code = 0

    captured = capsys.readouterr()
    return exit_code, captured.out, captured.err


def test_version_command_reports_project_information(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code, stdout, stderr = run_cli(monkeypatch, capsys, "version")

    assert exit_code == 0
    assert stderr == ""
    assert f"omcipcap v{__version__}" in stdout
    assert "Dong-Yuan Shih" in stdout
    assert "https://github.com/RainbowCloudLabs/omcipcap" in stdout


@pytest.mark.parametrize("json_option", ["-j", "--json-output"])
def test_version_command_supports_json_output(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    json_option: str,
) -> None:
    exit_code, stdout, stderr = run_cli(
        monkeypatch, capsys, "version", json_option
    )

    assert exit_code == 0
    assert stderr == ""
    assert json.loads(stdout) == {
        "name": "omcipcap",
        "version": __version__,
        "author": "Dong-Yuan Shih",
        "email": "daneshih1125@gmail.com",
        "project": "https://github.com/RainbowCloudLabs/omcipcap",
    }


def test_version_option_matches_version_command(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    option_exit, option_stdout, option_stderr = run_cli(
        monkeypatch, capsys, "--version"
    )
    command_exit, command_stdout, command_stderr = run_cli(
        monkeypatch, capsys, "version"
    )

    expected_version = f"omcipcap v{__version__}"
    assert option_exit == command_exit == 0
    assert option_stderr == command_stderr == ""
    assert option_stdout.strip() == expected_version
    assert command_stdout.splitlines()[0] == expected_version


def test_help_includes_current_version(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code, stdout, stderr = run_cli(monkeypatch, capsys, "--help")

    assert exit_code == 0
    assert stderr == ""
    assert f"OMCI PCAP Diagnostic & Analysis Tool (v{__version__})" in stdout
