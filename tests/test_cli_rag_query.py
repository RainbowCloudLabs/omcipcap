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

from omci.ai.rag import query as rag_query
from omci.ai.rag.query import (
    DEFAULT_TOP_K,
    MIN_SIMILARITY,
    QueryResult,
    RAGQueryError,
    RankedChunk,
    aggregate_cases,
    format_query_results,
    query_cases,
    rank_chunks,
)
from omci.ai.rag.workspace import initialize_workspace
from omci.cli import main


class FakeModel:
    def __init__(self) -> None:
        self.questions: list[list[str]] = []

    def encode(self, questions: list[str]) -> list[list[float]]:
        self.questions.append(questions)
        return [[0.25, 0.75]]


class FakeCollection:
    def __init__(
        self,
        records: list[tuple[dict[str, object], float]],
        metadata: dict[str, object] | None = None,
    ) -> None:
        self.records = records
        self.metadata = (
            metadata
            if metadata is not None
            else {
                "hnsw:space": "cosine",
                "db_schema_version": 1,
                "profile_id": "standard",
                "omcipcap_version": "0.3.8",
            }
        )
        self.queries: list[dict[str, object]] = []

    def count(self) -> int:
        return len(self.records)

    def query(
        self,
        *,
        query_embeddings: list[list[float]],
        n_results: int,
        include: list[str],
    ) -> dict[str, object]:
        self.queries.append(
            {
                "query_embeddings": query_embeddings,
                "n_results": n_results,
                "include": include,
            }
        )
        return {
            "metadatas": [[metadata for metadata, _ in self.records]],
            "distances": [[distance for _, distance in self.records]],
        }


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


def metadata(
    case_id: str,
    *,
    priority: int = 90,
    chunk_index: int = 0,
) -> dict[str, object]:
    return {
        "case_id": case_id,
        "semantic_unit": "issue_summary",
        "chunk_index": chunk_index,
        "priority": priority,
        "issue_file": f"{case_id}.md",
        "pcap_file": "sample.pcap",
    }


def install_query_dependencies(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    collection: FakeCollection | Exception,
) -> tuple[FakeChroma, FakeModel]:
    (workspace / "db" / "chroma.sqlite3").touch()
    chroma = FakeChroma(collection)
    model = FakeModel()
    monkeypatch.setattr(
        rag_query,
        "_load_ai_dependencies",
        lambda: (chroma, object()),
    )
    monkeypatch.setattr(
        rag_query,
        "load_embedding_model",
        lambda profile, local_files_only: model,
    )
    return chroma, model


def test_retrieval_constants() -> None:
    assert DEFAULT_TOP_K == 5
    assert MIN_SIMILARITY == 0.70


def test_cli_uses_default_top_k(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[tuple[str, int]] = []

    def query(question: str, top_k: int) -> list[QueryResult]:
        calls.append((question, top_k))
        return []

    monkeypatch.setattr("omci.cli.query_cases", query)
    monkeypatch.setattr(
        sys,
        "argv",
        ["omcipcap", "ai", "rag", "query", "ONU cannot create VEIP"],
    )

    main()

    assert calls == [("ONU cannot create VEIP", DEFAULT_TOP_K)]
    assert capsys.readouterr().out == "No matching issue cases found.\n"


def test_cli_accepts_explicit_top_k(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []

    def query(question: str, top_k: int) -> list[QueryResult]:
        del question
        calls.append(top_k)
        return []

    monkeypatch.setattr("omci.cli.query_cases", query)
    monkeypatch.setattr(
        sys,
        "argv",
        ["omcipcap", "ai", "rag", "query", "question", "--top-k", "2"],
    )

    main()

    assert calls == [2]


@pytest.mark.parametrize("value", ["0", "-1", "invalid"])
def test_cli_rejects_invalid_top_k(
    value: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["omcipcap", "ai", "rag", "query", "question", "--top-k", value],
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 2


def test_query_resolves_workspace_and_generates_embedding(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collection = FakeCollection([(metadata("CASE-001"), 0.10)])
    chroma, model = install_query_dependencies(
        workspace,
        monkeypatch,
        collection,
    )
    model_loads: list[tuple[str, bool]] = []

    def load_model(profile: str, local_files_only: bool) -> FakeModel:
        model_loads.append((profile, local_files_only))
        return model

    monkeypatch.setattr(rag_query, "load_embedding_model", load_model)

    results = query_cases("service failure")

    assert results == [QueryResult("CASE-001", 0.90)]
    assert chroma.paths == [workspace / "db"]
    assert model_loads == [("standard", True)]
    assert model.questions == [["service failure"]]
    assert collection.queries == [
        {
            "query_embeddings": [[0.25, 0.75]],
            "n_results": 1,
            "include": ["metadatas", "distances"],
        }
    ]


def test_query_missing_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    with pytest.raises(RAGQueryError, match="rag init"):
        query_cases("question")


def test_query_invalid_workspace(
    workspace: Path,
) -> None:
    (workspace / "config.json").write_text("{invalid", encoding="utf-8")

    with pytest.raises(RAGQueryError, match="workspace is invalid"):
        query_cases("question")


def test_query_missing_database(workspace: Path) -> None:
    (workspace / "db").rmdir()

    with pytest.raises(RAGQueryError, match="database is missing"):
        query_cases("question")


def test_query_invalid_database(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_query_dependencies(
        workspace,
        monkeypatch,
        RuntimeError("cannot open"),
    )

    with pytest.raises(RAGQueryError, match="database is invalid.*cannot open"):
        query_cases("question")


def test_query_rejects_missing_database_metadata(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collection = FakeCollection(
        [(metadata("CASE-001"), 0.10)],
        metadata={
            "hnsw:space": "cosine",
            "db_schema_version": 1,
            "profile_id": "standard",
        },
    )
    install_query_dependencies(workspace, monkeypatch, collection)

    with pytest.raises(RAGQueryError, match="metadata is missing or invalid"):
        query_cases("question")


def test_query_rejects_non_cosine_collection(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collection = FakeCollection(
        [(metadata("CASE-001"), 0.10)],
        metadata={
            "hnsw:space": "l2",
            "db_schema_version": 1,
            "profile_id": "standard",
            "omcipcap_version": "0.3.8",
        },
    )
    install_query_dependencies(workspace, monkeypatch, collection)

    with pytest.raises(RAGQueryError, match="distance metric mismatch"):
        query_cases("question")


def test_query_rejects_missing_distance_metric(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collection = FakeCollection(
        [(metadata("CASE-001"), 0.10)],
        metadata={
            "db_schema_version": 1,
            "profile_id": "standard",
            "omcipcap_version": "0.3.8",
        },
    )
    install_query_dependencies(workspace, monkeypatch, collection)

    with pytest.raises(RAGQueryError, match="distance metric mismatch"):
        query_cases("question")


def test_query_rejects_incompatible_database(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collection = FakeCollection(
        [(metadata("CASE-001"), 0.10)],
        metadata={
            "hnsw:space": "cosine",
            "db_schema_version": 1,
            "profile_id": "server",
            "omcipcap_version": "0.3.8",
        },
    )
    install_query_dependencies(workspace, monkeypatch, collection)

    with pytest.raises(RAGQueryError, match="incompatible"):
        query_cases("question")


def test_query_empty_initialized_database(workspace: Path) -> None:
    assert query_cases("question") is None


def test_query_empty_collection(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_query_dependencies(
        workspace,
        monkeypatch,
        FakeCollection([]),
    )

    assert query_cases("question") is None


def test_missing_local_model_has_clear_error(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collection = FakeCollection([(metadata("CASE-001"), 0.10)])
    install_query_dependencies(workspace, monkeypatch, collection)

    def missing_model(profile: str, local_files_only: bool) -> object:
        assert profile == "standard"
        assert local_files_only
        raise rag_query.WorkspaceInitError("model missing")

    monkeypatch.setattr(rag_query, "load_embedding_model", missing_model)

    with pytest.raises(
        RAGQueryError,
        match=r"(?s)not available locally.*rag init --profile standard",
    ):
        query_cases("question")


def test_similarity_is_primary_ranking_signal() -> None:
    chunks = [
        RankedChunk("CASE-LOW", 0.80, 100, 0),
        RankedChunk("CASE-HIGH", 0.81, 10, 5),
    ]

    assert [chunk.case_id for chunk in rank_chunks(chunks)] == [
        "CASE-HIGH",
        "CASE-LOW",
    ]


def test_priority_breaks_equal_similarity_ties() -> None:
    chunks = [
        RankedChunk("CASE-LOW", 0.80, 10, 0),
        RankedChunk("CASE-HIGH", 0.80, 100, 3),
    ]

    assert [chunk.case_id for chunk in rank_chunks(chunks)] == [
        "CASE-HIGH",
        "CASE-LOW",
    ]


def test_chunk_index_then_case_id_break_ties() -> None:
    chunks = [
        RankedChunk("CASE-B", 0.80, 90, 0),
        RankedChunk("CASE-A", 0.80, 90, 0),
        RankedChunk("CASE-C", 0.80, 90, 1),
    ]

    assert [chunk.case_id for chunk in rank_chunks(chunks)] == [
        "CASE-A",
        "CASE-B",
        "CASE-C",
    ]


def test_case_aggregation_uses_one_best_chunk_per_case() -> None:
    chunks = [
        RankedChunk("CASE-001", 0.91, 10, 2),
        RankedChunk("CASE-002", 0.89, 100, 0),
        RankedChunk("CASE-001", 0.88, 100, 0),
    ]

    assert aggregate_cases(chunks, 5) == [
        QueryResult("CASE-001", 0.91),
        QueryResult("CASE-002", 0.89),
    ]


def test_aggregation_returns_fewer_than_top_k_and_filters_similarity() -> None:
    chunks = [
        RankedChunk("CASE-001", 0.75, 90, 0),
        RankedChunk("CASE-002", 0.69, 100, 0),
    ]

    assert aggregate_cases(chunks, 5) == [QueryResult("CASE-001", 0.75)]


def test_no_match_message(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("omci.cli.query_cases", lambda question, top_k: [])
    monkeypatch.setattr(
        sys,
        "argv",
        ["omcipcap", "ai", "rag", "query", "question"],
    )

    main()

    assert capsys.readouterr().out == "No matching issue cases found.\n"


def test_no_indexed_cases_message(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("omci.cli.query_cases", lambda question, top_k: None)
    monkeypatch.setattr(
        sys,
        "argv",
        ["omcipcap", "ai", "rag", "query", "question"],
    )

    main()

    assert capsys.readouterr().out == "No indexed issue cases found.\n"


def test_deterministic_output_formatting() -> None:
    results = [
        QueryResult("CASE-023", 0.91),
        QueryResult("CASE-017", 0.84),
        QueryResult("CASE-002", 0.80),
    ]

    assert format_query_results(results) == (
        "Rank  Score  Case ID\n"
        "----  -----  --------\n"
        "1     0.91   CASE-023\n"
        "2     0.84   CASE-017\n"
        "3     0.80   CASE-002"
    )
