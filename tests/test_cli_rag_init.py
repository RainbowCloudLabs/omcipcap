#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

import json
import os
from datetime import datetime
from pathlib import Path

import pytest

from omci import __version__
from omci.ai.rag import workspace as rag_workspace
from omci.ai.rag.workspace import (
    WorkspaceInitError,
    default_workspace_config_path,
    initialize_workspace,
    resolve_workspace,
)


EXPECTED_DIRS = {"db", "issues", "mib-json", "semantics"}


def configure_test_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    return home


@pytest.mark.parametrize("profile", ["standard", "workstation", "server"])
def test_rag_init_creates_workspace_and_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    profile: str,
) -> None:
    configure_test_home(tmp_path, monkeypatch)
    workspace = initialize_workspace(tmp_path / f"rag-{profile}", profile)

    assert EXPECTED_DIRS == {
        path.name for path in workspace.iterdir() if path.is_dir()
    }
    config = json.loads((workspace / "config.json").read_text(encoding="utf-8"))
    assert config == {
        "db_schema_version": 1,
        "profile_id": profile,
        "omcipcap_version": __version__,
        "created_at": config["created_at"],
    }
    timestamp = datetime.fromisoformat(config["created_at"])
    assert timestamp.utcoffset() is not None
    assert timestamp.utcoffset().total_seconds() == 0


def test_rag_init_creates_default_config_with_only_absolute_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = configure_test_home(tmp_path, monkeypatch)
    workdir = tmp_path / "parent" / ".." / "RAG"

    workspace = initialize_workspace(workdir, "workstation")

    user_config_path = home / ".local" / "omcipcap" / "rag_config.json"
    assert user_config_path == default_workspace_config_path()
    assert user_config_path.parent.is_dir()
    assert json.loads(user_config_path.read_text(encoding="utf-8")) == {
        "workspace_path": str(workspace)
    }
    assert workspace.is_absolute()
    assert workspace == workdir.resolve()


def test_rag_init_updates_existing_default_after_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure_test_home(tmp_path, monkeypatch)
    first = initialize_workspace(tmp_path / "first", "standard")
    second = initialize_workspace(tmp_path / "second", "server")

    assert first != second
    assert json.loads(default_workspace_config_path().read_text(encoding="utf-8")) == {
        "workspace_path": str(second)
    }


def test_atomic_json_writer_uses_same_directory_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "config" / "rag_config.json"
    replacements: list[tuple[Path, Path]] = []

    def record_replace(source: Path, target: Path) -> None:
        replacements.append((Path(source), Path(target)))

    monkeypatch.setattr(os, "replace", record_replace)

    rag_workspace._write_json_atomic(destination, {"workspace_path": "/tmp/RAG"})

    assert destination.parent.is_dir()
    assert len(replacements) == 1
    source, target = replacements[0]
    assert source.parent == destination.parent
    assert target == destination
    assert not source.exists()


def test_rag_reinitialization_preserves_existing_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure_test_home(tmp_path, monkeypatch)
    workspace = initialize_workspace(tmp_path / "RAG", "standard")
    issue = workspace / "issues" / "CASE-001.md"
    database_marker = workspace / "db" / "marker"
    issue.write_text("existing issue", encoding="utf-8")
    database_marker.write_text("existing database", encoding="utf-8")
    original_config = (workspace / "config.json").read_bytes()

    initialize_workspace(workspace, "standard")

    assert issue.read_text(encoding="utf-8") == "existing issue"
    assert database_marker.read_text(encoding="utf-8") == "existing database"
    assert (workspace / "config.json").read_bytes() == original_config


def test_rag_init_rejects_conflicting_profile_without_updating_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure_test_home(tmp_path, monkeypatch)
    workspace = initialize_workspace(tmp_path / "RAG", "standard")
    original_default = default_workspace_config_path().read_bytes()

    with pytest.raises(WorkspaceInitError, match="conflicts"):
        initialize_workspace(workspace, "server")

    assert default_workspace_config_path().read_bytes() == original_default


def test_rag_init_rejects_invalid_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure_test_home(tmp_path, monkeypatch)

    with pytest.raises(WorkspaceInitError, match="Unsupported RAG profile"):
        initialize_workspace(tmp_path / "RAG", "unsupported")

    assert not default_workspace_config_path().exists()


def test_rag_init_rejects_non_directory_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure_test_home(tmp_path, monkeypatch)
    workspace = tmp_path / "not-a-directory"
    workspace.write_text("file", encoding="utf-8")

    with pytest.raises(WorkspaceInitError, match="not a directory"):
        initialize_workspace(workspace, "standard")


def test_resolve_valid_default_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure_test_home(tmp_path, monkeypatch)
    initialized = initialize_workspace(tmp_path / "RAG", "workstation")

    workspace, config = resolve_workspace()

    assert workspace == initialized
    assert config["profile_id"] == "workstation"


def test_resolve_missing_per_user_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure_test_home(tmp_path, monkeypatch)

    with pytest.raises(WorkspaceInitError, match="rag init"):
        resolve_workspace()


def test_resolve_malformed_per_user_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure_test_home(tmp_path, monkeypatch)
    path = default_workspace_config_path()
    path.parent.mkdir(parents=True)
    path.write_text("{invalid", encoding="utf-8")

    with pytest.raises(WorkspaceInitError, match="configuration is invalid"):
        resolve_workspace()


@pytest.mark.parametrize("value", [None, "", "   "])
def test_resolve_missing_or_empty_workspace_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    value: str | None,
) -> None:
    configure_test_home(tmp_path, monkeypatch)
    path = default_workspace_config_path()
    path.parent.mkdir(parents=True)
    data = {} if value is None else {"workspace_path": value}
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(WorkspaceInitError, match="workspace_path"):
        resolve_workspace()


def test_resolve_configured_workspace_does_not_exist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure_test_home(tmp_path, monkeypatch)
    path = default_workspace_config_path()
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps({"workspace_path": str(tmp_path / "missing")}),
        encoding="utf-8",
    )

    with pytest.raises(WorkspaceInitError, match="does not exist"):
        resolve_workspace()


def test_resolve_missing_workspace_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure_test_home(tmp_path, monkeypatch)
    workspace = tmp_path / "RAG"
    workspace.mkdir()
    path = default_workspace_config_path()
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps({"workspace_path": str(workspace)}),
        encoding="utf-8",
    )

    with pytest.raises(WorkspaceInitError, match="metadata is missing"):
        resolve_workspace()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("db_schema_version", 999, "schema is incompatible"),
        ("profile_id", "unknown", "profile is unsupported"),
    ],
)
def test_resolve_incompatible_workspace_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
    message: str,
) -> None:
    configure_test_home(tmp_path, monkeypatch)
    workspace = initialize_workspace(tmp_path / "RAG", "standard")
    config_path = workspace / "config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config[field] = value
    config_path.write_text(json.dumps(config), encoding="utf-8")

    with pytest.raises(WorkspaceInitError, match=message):
        resolve_workspace()
