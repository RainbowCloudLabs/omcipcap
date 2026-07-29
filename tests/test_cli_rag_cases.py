#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

import sys
from pathlib import Path

import pytest

from omci.ai.rag import database as rag_database
from omci.ai.rag.cases import (
    CaseSummary,
    RAGCasesError,
    aggregate_case_metadata,
    format_case_summaries,
    list_cases,
)
from omci.ai.rag.workspace import initialize_workspace
from omci.cli import main


class FakeCollection:
    def __init__(
        self,
        metadatas: list[dict[str, object]],
        collection_metadata: dict[str, object] | None = None,
    ) -> None:
        self.metadatas = metadatas
        self.metadata = (
            collection_metadata
            if collection_metadata is not None
            else {
                "hnsw:space": "cosine",
                "db_schema_version": 1,
                "profile_id": "standard",
                "omcipcap_version": "0.3.8",
            }
        )
        self.includes: list[list[str]] = []

    def get(self, include: list[str]) -> dict[str, object]:
        self.includes.append(include)
        return {"metadatas": self.metadatas}


class FakeClient:
    def __init__(self, collection: FakeCollection | Exception) -> None:
        self.collection = collection

    def get_collection(self, name: str) -> FakeCollection:
        assert name == "omcipcap_rag"
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
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(
        "omci.ai.rag.workspace.prepare_embedding_model",
        lambda profile: {"profile": profile},
    )
    return initialize_workspace(tmp_path / "RAG", "standard")


def chunk(case_id: str, problem: str) -> dict[str, object]:
    return {
        "case_id": case_id,
        "semantic_unit": "issue_summary",
        "chunk_index": 0,
        "priority": 90,
        "issue_file": f"{case_id}.md",
        "pcap_file": "sample.pcap",
        "problem": problem,
    }


def install_collection(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    collection: FakeCollection | Exception,
) -> FakeChroma:
    (workspace / "db" / "chroma.sqlite3").touch()
    chroma = FakeChroma(collection)
    monkeypatch.setattr(rag_database, "_load_chromadb", lambda: chroma)
    return chroma


def test_aggregate_cases_counts_chunks_and_sorts_case_ids() -> None:
    metadatas = [
        chunk("CASE-002", "Second problem"),
        chunk("CASE-001", "First problem"),
        chunk("CASE-002", "Second problem"),
    ]

    assert aggregate_case_metadata(metadatas) == [
        CaseSummary("CASE-001", 1, "First problem"),
        CaseSummary("CASE-002", 2, "Second problem"),
    ]


def test_aggregation_is_deterministic_for_metadata_order() -> None:
    forward = [
        chunk("CASE-002", "Second problem"),
        chunk("CASE-001", "First problem"),
    ]

    assert aggregate_case_metadata(forward) == aggregate_case_metadata(
        list(reversed(forward))
    )


def test_conflicting_problem_metadata_is_rejected() -> None:
    with pytest.raises(RAGCasesError, match='CASE-001.*conflicting problem'):
        aggregate_case_metadata(
            [
                chunk("CASE-001", "First problem"),
                chunk("CASE-001", "Different problem"),
            ]
        )


def test_list_cases_uses_collection_metadata_only(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stored_issue = workspace / "cases" / "CASE-001.md"
    stored_issue.write_text("not valid Markdown", encoding="utf-8")
    collection = FakeCollection([chunk("CASE-001", "Stored problem")])
    chroma = install_collection(workspace, monkeypatch, collection)
    monkeypatch.setattr(
        "omci.ai.rag.workspace.load_embedding_model",
        lambda *args, **kwargs: pytest.fail("embedding model must not load"),
    )
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda *args, **kwargs: pytest.fail("issue Markdown must not be read"),
    )

    assert list_cases() == [CaseSummary("CASE-001", 1, "Stored problem")]
    assert collection.includes == [["metadatas"]]
    assert chroma.paths == [workspace / "db"]


def test_list_cases_empty_initialized_database(workspace: Path) -> None:
    assert list_cases() == []


def test_list_cases_empty_collection(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_collection(workspace, monkeypatch, FakeCollection([]))

    assert list_cases() == []


def test_list_cases_rejects_invalid_database(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_collection(workspace, monkeypatch, RuntimeError("cannot open"))

    with pytest.raises(RAGCasesError, match="database is invalid.*cannot open"):
        list_cases()


def test_list_cases_rejects_incompatible_collection(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collection = FakeCollection(
        [chunk("CASE-001", "Problem")],
        collection_metadata={
            "hnsw:space": "cosine",
            "db_schema_version": 1,
            "profile_id": "server",
            "omcipcap_version": "0.3.8",
        },
    )
    install_collection(workspace, monkeypatch, collection)

    with pytest.raises(RAGCasesError, match="incompatible"):
        list_cases()


def test_list_cases_rejects_missing_problem_metadata(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata = chunk("CASE-001", "Problem")
    del metadata["problem"]
    install_collection(workspace, monkeypatch, FakeCollection([metadata]))

    with pytest.raises(RAGCasesError, match="chunk metadata is invalid"):
        list_cases()


def test_case_table_format_is_deterministic() -> None:
    cases = [
        CaseSummary("CASE-001", 8, "VEIP creation failure"),
        CaseSummary("Xtelecom0002", 6, "TR-069 provisioning failed"),
    ]

    assert format_case_summaries(cases) == (
        "CASE ID        CHUNKS  PROBLEM\n"
        "-------------  ------  -----------------------------------------------\n"
        "CASE-001       8       VEIP creation failure\n"
        "Xtelecom0002   6       TR-069 provisioning failed"
    )


def test_cases_cli_empty_message(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("omci.cli.list_cases", lambda: [])
    monkeypatch.setattr(sys, "argv", ["omcipcap", "ai", "rag", "cases"])

    main()

    assert capsys.readouterr().out == "No indexed issue cases found.\n"


def test_cases_cli_output(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "omci.cli.list_cases",
        lambda: [CaseSummary("CASE-001", 2, "Stored problem")],
    )
    monkeypatch.setattr(sys, "argv", ["omcipcap", "ai", "rag", "cases"])

    main()

    assert capsys.readouterr().out == (
        "CASE ID        CHUNKS  PROBLEM\n"
        "-------------  ------  -----------------------------------------------\n"
        "CASE-001       2       Stored problem\n"
    )


def test_cases_command_appears_in_help(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["omcipcap", "ai", "rag", "--help"])

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 0
    assert "cases" in capsys.readouterr().out
