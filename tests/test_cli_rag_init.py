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
from omci.cli import main


EXPECTED_DIRS = {"db", "cases", "pcaps", "mib-json", "semantics"}
REAL_PREPARE_EMBEDDING_MODEL = rag_workspace.prepare_embedding_model


@pytest.fixture(autouse=True)
def avoid_model_download(monkeypatch: pytest.MonkeyPatch) -> None:
    def prepare_model(profile: str) -> object:
        return {"profile": profile}

    monkeypatch.setattr(rag_workspace, "prepare_embedding_model", prepare_model)


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
    issue = workspace / "cases" / "CASE-001.md"
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


def test_rag_init_prepares_selected_profile_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure_test_home(tmp_path, monkeypatch)
    prepared_profiles: list[str] = []

    def prepare_model(profile: str) -> object:
        prepared_profiles.append(profile)
        return {"tokenizer": object()}

    monkeypatch.setattr(rag_workspace, "prepare_embedding_model", prepare_model)

    workspace = initialize_workspace(tmp_path / "RAG", "workstation")

    assert prepared_profiles == ["workstation"]
    assert (workspace / "config.json").is_file()
    assert default_workspace_config_path().is_file()


def test_prepare_embedding_model_uses_online_cache_mode_and_tokenizer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_loads: list[tuple[str, bool]] = []

    class FakeModel:
        def __init__(self) -> None:
            self.tokenizer = object()

    def sentence_transformer(
        model_name: str, local_files_only: bool
    ) -> FakeModel:
        model_loads.append((model_name, local_files_only))
        return FakeModel()

    def load_dependencies() -> tuple[object, object]:
        return object(), sentence_transformer

    monkeypatch.setattr(
        rag_workspace,
        "prepare_embedding_model",
        REAL_PREPARE_EMBEDDING_MODEL,
    )
    monkeypatch.setattr(rag_workspace, "_load_ai_dependencies", load_dependencies)

    first = rag_workspace.prepare_embedding_model("standard")
    second = rag_workspace.prepare_embedding_model("standard")

    assert first.tokenizer is not None
    assert second.tokenizer is not None
    assert model_loads == [
        ("sentence-transformers/all-MiniLM-L6-v2", False),
        ("sentence-transformers/all-MiniLM-L6-v2", False),
    ]


def test_prepare_embedding_model_reuses_sentence_transformers_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_available = False
    downloads = 0

    class FakeModel:
        def __init__(self) -> None:
            self.tokenizer = object()

    def sentence_transformer(
        model_name: str, local_files_only: bool
    ) -> FakeModel:
        nonlocal cache_available, downloads
        assert model_name == "sentence-transformers/all-MiniLM-L6-v2"
        assert not local_files_only
        if not cache_available:
            downloads += 1
            cache_available = True
        return FakeModel()

    def load_dependencies() -> tuple[object, object]:
        return object(), sentence_transformer

    monkeypatch.setattr(
        rag_workspace,
        "prepare_embedding_model",
        REAL_PREPARE_EMBEDDING_MODEL,
    )
    monkeypatch.setattr(rag_workspace, "_load_ai_dependencies", load_dependencies)

    rag_workspace.prepare_embedding_model("standard")
    rag_workspace.prepare_embedding_model("standard")

    assert downloads == 1


def test_shared_model_loader_supports_strict_local_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_loads: list[tuple[str, bool]] = []

    class FakeModel:
        def __init__(self) -> None:
            self.tokenizer = object()

    def sentence_transformer(
        model_name: str, local_files_only: bool
    ) -> FakeModel:
        model_loads.append((model_name, local_files_only))
        return FakeModel()

    def load_dependencies() -> tuple[object, object]:
        return object(), sentence_transformer

    monkeypatch.setattr(rag_workspace, "_load_ai_dependencies", load_dependencies)

    model = rag_workspace.load_embedding_model(
        "workstation",
        local_files_only=True,
    )

    assert model.tokenizer is not None
    assert model_loads == [("BAAI/bge-m3", True)]


def test_rag_init_prints_success_only_after_model_is_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_test_home(tmp_path, monkeypatch)
    workspace = tmp_path / "RAG"
    events: list[str] = []

    def prepare_model(profile: str) -> object:
        assert profile == "workstation"
        assert "RAG workspace initialized" not in capsys.readouterr().out
        events.append("model-ready")
        return {"tokenizer": object()}

    monkeypatch.setattr(rag_workspace, "prepare_embedding_model", prepare_model)
    monkeypatch.setattr(
        "sys.argv",
        [
            "omcipcap",
            "ai",
            "rag",
            "init",
            "--profile",
            "workstation",
            "--dir",
            str(workspace),
        ],
    )

    main()
    events.append("command-returned")

    assert events == ["model-ready", "command-returned"]
    assert "RAG workspace initialized" in capsys.readouterr().out


def test_rag_init_model_failure_rolls_back_new_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure_test_home(tmp_path, monkeypatch)
    workspace = tmp_path / "RAG"

    def fail_preparation(profile: str) -> object:
        raise WorkspaceInitError(f"model preparation failed for {profile}")

    monkeypatch.setattr(rag_workspace, "prepare_embedding_model", fail_preparation)

    with pytest.raises(WorkspaceInitError, match="model preparation failed"):
        initialize_workspace(workspace, "server")

    assert not (workspace / "config.json").exists()
    assert not default_workspace_config_path().exists()


def test_rag_init_model_failure_restores_previous_default_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure_test_home(tmp_path, monkeypatch)
    first = initialize_workspace(tmp_path / "first", "standard")
    original_default = default_workspace_config_path().read_bytes()
    second = tmp_path / "second"

    def fail_preparation(profile: str) -> object:
        raise WorkspaceInitError(f"model preparation failed for {profile}")

    monkeypatch.setattr(rag_workspace, "prepare_embedding_model", fail_preparation)

    with pytest.raises(WorkspaceInitError, match="model preparation failed"):
        initialize_workspace(second, "workstation")

    assert first.is_dir()
    assert default_workspace_config_path().read_bytes() == original_default
    assert not (second / "config.json").exists()


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
