#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

import json
import sys
from collections.abc import Iterator
from pathlib import Path
from runpy import run_path

import pytest

from omci import cli, omcimib, omcigrapher

helpers = run_path(str(Path(__file__).resolve().parents[1] / "utils" / "gen_utils.py"))
generate_mib_pkts = helpers["generate_mib_pkts"]
generate_pcap_from_pkts = helpers["generate_pcap_from_pkts"]

CLASSES = "OMCIPCAP_SENSITIVE_ME_CLASSES"
ATTRIBUTES = "OMCIPCAP_SENSITIVE_ME_ATTRIBUTES"


@pytest.fixture(autouse=True)
def reset_masking(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    classes = set(omcimib.SENSITIVE_ME_CLASSES)
    attributes = set(omcimib.SENSITIVE_ME_ATTRIBUTES)
    monkeypatch.delenv(CLASSES, raising=False)
    monkeypatch.delenv(ATTRIBUTES, raising=False)
    omcimib.configure_sensitive_masking()
    yield
    omcimib.SENSITIVE_ME_CLASSES.clear()
    omcimib.SENSITIVE_ME_CLASSES.update(classes)
    omcimib.SENSITIVE_ME_ATTRIBUTES.clear()
    omcimib.SENSITIVE_ME_ATTRIBUTES.update(attributes)


@pytest.mark.parametrize("value", ["", "  \t"])
def test_empty_sets_and_restore(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    defaults = set(omcimib.SENSITIVE_ME_CLASSES)
    monkeypatch.setenv(CLASSES, value)
    monkeypatch.setenv(ATTRIBUTES, value)
    omcimib.configure_sensitive_masking()
    assert not omcimib.SENSITIVE_ME_CLASSES
    assert not omcimib.SENSITIVE_ME_ATTRIBUTES
    monkeypatch.delenv(CLASSES)
    monkeypatch.delenv(ATTRIBUTES)
    omcimib.configure_sensitive_masking()
    assert omcimib.SENSITIVE_ME_CLASSES == defaults
    assert omcimib.SENSITIVE_ME_ATTRIBUTES == {"password", "secret"}


def test_replacement_and_independent_sets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(CLASSES, " 0, 65535, 134,134 ")
    omcimib.configure_sensitive_masking()
    assert omcimib.SENSITIVE_ME_CLASSES == {0, 134, 65535}
    assert omcimib.SENSITIVE_ME_ATTRIBUTES == {"password", "secret"}
    monkeypatch.setenv(ATTRIBUTES, " PORT , port, pass ")
    omcimib.configure_sensitive_masking()
    assert omcimib.SENSITIVE_ME_ATTRIBUTES == {"port", "pass"}
    assert omcigrapher.generate_tooltip(134, 1, {"Value": 1}) == "Value: *****\n"
    assert omcigrapher.generate_tooltip(47, 1, {"Port": 1}) == "Port: *****\n"
    monkeypatch.setenv(CLASSES, "")
    omcimib.configure_sensitive_masking()
    assert omcigrapher.generate_tooltip(134, 1, {"Port": 1, "Value": 2}) == "Port: *****\nValue: 2\n"


@pytest.mark.parametrize("variable,value", [
    (CLASSES, "-1"), (CLASSES, "65536"), (CLASSES, "0x94"),
    (CLASSES, "abc"), (CLASSES, "148,,153"), (CLASSES, "148,"),
    (CLASSES, "1.5"), (CLASSES, "１２"), (ATTRIBUTES, "password,,secret"),
    (ATTRIBUTES, ",password"), (ATTRIBUTES, "secret, "),
])
def test_invalid_atomic_and_before_loading(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    variable: str, value: str,
) -> None:
    classes = set(omcimib.SENSITIVE_ME_CLASSES)
    attributes = set(omcimib.SENSITIVE_ME_ATTRIBUTES)
    monkeypatch.setenv(CLASSES, "134")
    monkeypatch.setenv(variable, value)
    monkeypatch.setattr(sys, "argv", ["omcipcap", "mibdb", "missing.pcap"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2
    output = capsys.readouterr()
    assert variable in output.err
    assert "invalid entry" in output.err
    assert not output.out
    assert omcimib.SENSITIVE_ME_CLASSES == classes
    assert omcimib.SENSITIVE_ME_ATTRIBUTES == attributes


@pytest.fixture
def captures(tmp_path: Path) -> tuple[Path, Path]:
    paths = (tmp_path / "before.pcap", tmp_path / "after.pcap")
    for path, password in zip(paths, [b"private-before", b"private-after"]):
        packets, _ = generate_mib_pkts([
            (256, 0, 0x0020, password.ljust(12, b"\x00")[:12]),
            (148, 1, 0x8000, b"\x01" if path == paths[0] else b"\x02"),
        ])
        generate_pcap_from_pkts(str(path), packets)
    return paths


@pytest.mark.parametrize("command", ["mibdb", "mibdb-diff", "diff", "overview"])
@pytest.mark.parametrize("mode", [[], ["-j"], ["--md"]])
def test_outputs_and_repeated_invocations(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    captures: tuple[Path, Path], command: str, mode: list[str],
) -> None:
    capsys.readouterr()  # Discard fixture generator status messages.
    args = ["omcipcap", command, str(captures[0])]
    if command in ("diff", "mibdb-diff"):
        args.append(str(captures[1]))
    args.extend(mode)
    monkeypatch.setattr(sys, "argv", args)
    cli.main()
    masked = capsys.readouterr().out
    assert "*****" in masked
    assert "private-befo" not in masked
    monkeypatch.setenv(CLASSES, "")
    monkeypatch.setenv(ATTRIBUTES, "")
    cli.main()
    unmasked = capsys.readouterr().out
    assert "private-befo" in unmasked
    if mode == ["-j"]:
        masked_data = json.loads(masked)
        unmasked_data = json.loads(unmasked)
        if command == "mibdb":
            assert masked_data["256"]["instances"]["0"]["Logical password"] == {"val": "*****", "text": "*****"}
            assert unmasked_data["256"]["instances"]["0"]["Logical password"] == {"val": "private-befo", "text": "private-befo"}
        elif command in ("diff", "mibdb-diff"):
            assert masked_data["summary"] == unmasked_data["summary"]
            change = next(c for c in masked_data["changes"] if c["attr_name"] == "Logical password")
            assert change["old"] == change["new"] == "*****"
        else:
            assert masked_data["mib_database"]["256"]["instances"]["0"]["Logical password"]["val"] == "*****"
    monkeypatch.delenv(CLASSES)
    monkeypatch.delenv(ATTRIBUTES)
    cli.main()
    assert capsys.readouterr().out == masked


@pytest.mark.parametrize("command", ["topology", "graphic"])
def test_html_uses_environment(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    tmp_path: Path, command: str,
) -> None:
    capture = tmp_path / "host.pcap"
    output = tmp_path / "host.html"
    packets, _ = generate_mib_pkts([(134, 1, 0x8000, b"\x01")])
    generate_pcap_from_pkts(str(capture), packets)
    monkeypatch.setenv(CLASSES, "134")
    monkeypatch.setattr(sys, "argv", ["omcipcap", command, str(capture), "-o", str(output)])
    cli.main()
    assert "IP options: *****" in output.read_text()
    monkeypatch.setenv(CLASSES, "")
    cli.main()
    assert "IP options: 1" in output.read_text()
    capsys.readouterr()


def test_unrelated_command_ignores_invalid_override(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(CLASSES, "invalid")
    monkeypatch.setattr(sys, "argv", ["omcipcap", "version"])
    cli.main()
    assert "omcipcap" in capsys.readouterr().out
