#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

import json
import sys
from pathlib import Path

import pytest

from omci.ai.rag import status as rag_status
from omci.ai.rag.ingest import COLLECTION_NAME
from omci.ai.rag.workspace import (
    WorkspaceInitError,
    default_workspace_config_path,
    initialize_workspace,
)
from omci.cli import main


class FakeCollection:
    def __init__(
        self,
        metadata: dict[str, object] | None,
        case_ids: list[str],
    ) -> None:
        self.metadata = metadata
        self.case_ids = case_ids

    def get(self, include: list[str]) -> dict[str, object]:
        assert include == ["metadatas"]
        return {
            "metadatas": [{"case_id": case_id} for case_id in self.case_ids]
        }


class FakeClient:
    def __init__(self, collection: FakeCollection | Exception) -> None:
        self.collection = collection

    def get_collection(self, name: str) -> FakeCollection:
        assert name == COLLECTION_NAME
        if isinstance(self.collection, Exception):
            raise self.collection
        return self.collection


class FakeChroma:
    def __init__(self, collection: FakeCollection | Exception) -> None:
        self.collection = collection
        self.paths: list[Path] = []

    def PersistentClient(self, path: str) -> FakeClient:
        self.paths.append(Path(path))
        return FakeClient(self.collection)


@pytest.fixture
def workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(
        "omci.ai.rag.workspace.prepare_embedding_model",
        lambda profile: {"profile": profile},
    )
    return initialize_workspace(tmp_path / "RAG", "standard")


def install_database(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    collection: FakeCollection | Exception,
) -> FakeChroma:
    (workspace / "db" / "chroma.sqlite3").touch()
    chroma = FakeChroma(collection)
    monkeypatch.setattr(rag_status, "_load_chromadb", lambda: chroma)
    return chroma


def test_rag_status_workspace_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    with pytest.raises(WorkspaceInitError, match="rag init"):
        rag_status.get_rag_status()


def test_rag_status_fresh_workspace_database_empty(workspace: Path) -> None:
    result = rag_status.get_rag_status()

    assert result.database_status == "empty"
    assert result.compatibility == "compatible"
    assert result.indexed_cases == 0


def test_rag_status_database_missing(workspace: Path) -> None:
    (workspace / "db").rmdir()

    result = rag_status.get_rag_status()

    assert result.database_status == "missing"
    assert result.compatibility == "not-applicable"
    assert result.indexed_cases == 0


def test_rag_status_database_empty(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_database(
        workspace,
        monkeypatch,
        FakeCollection(
            {"db_schema_version": 1, "profile_id": "standard"},
            [],
        ),
    )

    result = rag_status.get_rag_status()

    assert result.database_status == "empty"
    assert result.compatibility == "compatible"


def test_rag_status_ready_counts_unique_cases(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chroma = install_database(
        workspace,
        monkeypatch,
        FakeCollection(
            {"db_schema_version": 1, "profile_id": "standard"},
            ["CASE-001", "CASE-001", "CASE-002"],
        ),
    )

    result = rag_status.get_rag_status()

    assert result.workspace == workspace
    assert result.profile == "standard"
    assert result.database_status == "ready"
    assert result.compatibility == "compatible"
    assert result.indexed_cases == 2
    assert chroma.paths == [workspace / "db"]


def test_rag_status_incompatible_database(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_database(
        workspace,
        monkeypatch,
        FakeCollection(
            {"db_schema_version": 1, "profile_id": "server"},
            ["CASE-001"],
        ),
    )

    result = rag_status.get_rag_status()

    assert result.compatibility == "incompatible"


@pytest.mark.parametrize(
    "collection",
    [
        RuntimeError("broken database"),
        FakeCollection(None, []),
        FakeCollection({"profile_id": "standard"}, []),
    ],
)
def test_rag_status_invalid_database(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    collection: FakeCollection | Exception,
) -> None:
    install_database(workspace, monkeypatch, collection)

    result = rag_status.get_rag_status()

    assert result.database_status == "invalid"
    assert result.compatibility == "unknown"


def test_rag_status_cli_output(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    install_database(
        workspace,
        monkeypatch,
        FakeCollection(
            {"db_schema_version": 1, "profile_id": "standard"},
            ["CASE-001"],
        ),
    )
    monkeypatch.setattr(sys, "argv", ["omcipcap", "ai", "rag", "status"])

    main()

    output = capsys.readouterr().out
    assert f"Workspace:              {workspace}" in output
    assert "Database status:        ready" in output
    assert "Rebuild required" not in output
    assert "Indexed issue cases:    1" in output


def test_rag_profiles_without_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["omcipcap", "ai", "rag", "profiles"])

    main()

    output = capsys.readouterr().out
    assert "*" not in output
    assert output.index("standard") < output.index("workstation") < output.index("server")


def test_rag_profiles_marks_active_workspace(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["omcipcap", "ai", "rag", "profiles"])

    main()

    output = capsys.readouterr().out
    assert "standard      *" in output
    assert "sentence-transformers/all-MiniLM-L6-v2" in output
    assert "256" in output
    assert "32" in output


def test_rag_profiles_unknown_active_profile(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = workspace / "config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["profile_id"] = "unknown"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["omcipcap", "ai", "rag", "profiles"])

    main()

    output = capsys.readouterr().out
    assert "*" not in output
    assert "standard" in output
    assert "workstation" in output
    assert "server" in output
