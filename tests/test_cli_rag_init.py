#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

import json
from datetime import datetime
from pathlib import Path

import pytest

from omci import __version__
from omci.ai.rag.workspace import WorkspaceInitError, initialize_workspace
from omci.cli import main


EXPECTED_DIRS = {"db", "issues", "mib-json", "semantics"}


def run_cli(monkeypatch: pytest.MonkeyPatch, args: list[str]) -> None:
    monkeypatch.setattr("sys.argv", ["omcipcap", *args])
    main()


@pytest.mark.parametrize("profile", ["standard", "workstation", "server"])
def test_rag_init_creates_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    profile: str,
) -> None:
    workspace = tmp_path / f"rag-{profile}"

    run_cli(
        monkeypatch,
        ["ai", "rag", "init", "--profile", profile, "--dir", str(workspace)],
    )

    assert EXPECTED_DIRS <= {path.name for path in workspace.iterdir()}
    assert not (workspace / "mib").exists()
    assert not (workspace / "profiles").exists()
    config = json.loads((workspace / "config.json").read_text())
    assert config == {
        "db_schema_version": 1,
        "profile_id": profile,
        "omcipcap_version": __version__,
        "created_at": config["created_at"],
    }
    assert datetime.fromisoformat(config["created_at"]).utcoffset().total_seconds() == 0
    assert not (workspace / "db" / "collection.json").exists()
    assert f"[+] RAG workspace initialized: {workspace}" in capsys.readouterr().out


def test_rag_init_can_be_repeated(tmp_path: Path) -> None:
    workspace = tmp_path / "rag-workspace"

    initialize_workspace(workspace, "standard")
    config = workspace / "config.json"
    original_config_mtime = config.stat().st_mtime_ns
    original_created_at = json.loads(config.read_text())["created_at"]

    initialize_workspace(workspace, "standard")

    assert config.stat().st_mtime_ns == original_config_mtime
    assert json.loads(config.read_text())["created_at"] == original_created_at


def test_rag_init_accepts_config_from_another_release(tmp_path: Path) -> None:
    workspace = tmp_path / "rag-workspace"
    initialize_workspace(workspace, "standard")
    config_path = workspace / "config.json"
    config = json.loads(config_path.read_text())
    config["omcipcap_version"] = "0.0.1"
    config_path.write_text(json.dumps(config))

    initialize_workspace(workspace, "standard")

    assert json.loads(config_path.read_text())["omcipcap_version"] == "0.0.1"


def test_rag_init_rejects_invalid_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "rag-workspace"
    monkeypatch.setattr(
        "sys.argv",
        [
            "omcipcap",
            "ai",
            "rag",
            "init",
            "--profile",
            "unsupported",
            "--dir",
            str(workspace),
        ],
    )

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 2
    assert not workspace.exists()


def test_rag_init_rejects_non_directory_path(tmp_path: Path) -> None:
    workspace = tmp_path / "not-a-directory"
    workspace.write_text("file")

    with pytest.raises(WorkspaceInitError, match="not a directory"):
        initialize_workspace(workspace, "standard")


def test_rag_init_rejects_unwritable_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "rag-workspace"
    original_mkdir = Path.mkdir

    def fail_for_workspace_child(
        path: Path,
        mode: int = 0o777,
        parents: bool = False,
        exist_ok: bool = False,
    ) -> None:
        if path.parent == workspace:
            raise PermissionError("permission denied")
        original_mkdir(path, mode=mode, parents=parents, exist_ok=exist_ok)

    monkeypatch.setattr(Path, "mkdir", fail_for_workspace_child)

    with pytest.raises(WorkspaceInitError, match="Cannot create RAG workspace"):
        initialize_workspace(workspace, "standard")
