#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

from dataclasses import dataclass
from pathlib import Path

from omci.ai.rag.ingest import COLLECTION_NAME
from omci.ai.rag.workspace import (
    DB_SCHEMA_VERSION,
    WorkspaceInitError,
    _load_ai_dependencies,
    load_embedding_model,
    resolve_workspace,
)


DEFAULT_TOP_K = 5
MIN_SIMILARITY = 0.70


class RAGQueryError(Exception):
    """Raised when indexed RAG cases cannot be queried."""


@dataclass(frozen=True)
class RankedChunk:
    case_id: str
    similarity: float
    priority: int
    chunk_index: int


@dataclass(frozen=True)
class QueryResult:
    case_id: str
    similarity: float


def rank_chunks(chunks: list[RankedChunk]) -> list[RankedChunk]:
    return sorted(
        chunks,
        key=lambda chunk: (
            -chunk.similarity,
            -chunk.priority,
            chunk.chunk_index,
            chunk.case_id,
        ),
    )


def aggregate_cases(
    chunks: list[RankedChunk],
    top_k: int,
    min_similarity: float = MIN_SIMILARITY,
) -> list[QueryResult]:
    results: list[QueryResult] = []
    seen_cases: set[str] = set()
    for chunk in rank_chunks(chunks):
        if chunk.similarity < min_similarity:
            continue
        if chunk.case_id in seen_cases:
            continue
        seen_cases.add(chunk.case_id)
        results.append(
            QueryResult(
                case_id=chunk.case_id,
                similarity=chunk.similarity,
            )
        )
        if len(results) == top_k:
            break
    return results


def _distance_to_similarity(distance: object) -> float:
    if not isinstance(distance, (int, float)):
        raise RAGQueryError("RAG database returned an invalid chunk distance")
    return 1.0 - float(distance)


def _open_collection(
    workspace: Path,
    config: dict[str, object],
) -> object | None:
    db_path = workspace / "db"
    if not db_path.exists():
        raise RAGQueryError(f"RAG database is missing: '{db_path}'")
    if not db_path.is_dir():
        raise RAGQueryError(f"RAG database is invalid: '{db_path}' is not a directory")
    if not any(db_path.iterdir()):
        return None

    try:
        chromadb_module, _ = _load_ai_dependencies()
        client = chromadb_module.PersistentClient(path=str(db_path))
        collection = client.get_collection(name=COLLECTION_NAME)
    except WorkspaceInitError as exc:
        raise RAGQueryError(str(exc)) from exc
    except Exception as exc:
        raise RAGQueryError(f"RAG database is invalid: {exc}") from exc

    metadata = collection.metadata
    if not isinstance(metadata, dict):
        raise RAGQueryError("RAG database metadata is missing or invalid")
    if (
        metadata.get("hnsw:space") != "cosine"
        or metadata.get("db_schema_version") != DB_SCHEMA_VERSION
        or metadata.get("profile_id") != config["profile_id"]
    ):
        raise RAGQueryError(
            "RAG database metadata is incompatible with the active workspace "
            "(profile or distance metric mismatch)"
        )
    version = metadata.get("omcipcap_version")
    if not isinstance(version, str) or not version:
        raise RAGQueryError("RAG database metadata is missing or invalid")
    return collection


def _parse_query_chunks(response: object) -> list[RankedChunk]:
    if not isinstance(response, dict):
        raise RAGQueryError("RAG database returned an invalid query result")
    metadatas = response.get("metadatas")
    distances = response.get("distances")
    if (
        not isinstance(metadatas, list)
        or not metadatas
        or not isinstance(metadatas[0], list)
        or not isinstance(distances, list)
        or not distances
        or not isinstance(distances[0], list)
        or len(metadatas[0]) != len(distances[0])
    ):
        raise RAGQueryError("RAG database returned invalid query metadata")

    chunks: list[RankedChunk] = []
    for metadata, distance in zip(metadatas[0], distances[0]):
        if not isinstance(metadata, dict):
            raise RAGQueryError("RAG database chunk metadata is invalid")
        case_id = metadata.get("case_id")
        priority = metadata.get("priority")
        chunk_index = metadata.get("chunk_index")
        if (
            not isinstance(case_id, str)
            or not case_id
            or not isinstance(priority, int)
            or not isinstance(chunk_index, int)
        ):
            raise RAGQueryError("RAG database chunk metadata is invalid")
        chunks.append(
            RankedChunk(
                case_id=case_id,
                similarity=_distance_to_similarity(distance),
                priority=priority,
                chunk_index=chunk_index,
            )
        )
    return chunks


def query_cases(question: str, top_k: int = DEFAULT_TOP_K) -> list[QueryResult] | None:
    if top_k <= 0:
        raise RAGQueryError("top-k must be a positive integer")
    try:
        workspace, config = resolve_workspace(require_database_dir=False)
    except WorkspaceInitError as exc:
        raise RAGQueryError(str(exc)) from exc

    collection = _open_collection(workspace, config)
    if collection is None:
        return None
    try:
        chunk_count = collection.count()
    except Exception as exc:
        raise RAGQueryError(f"Cannot inspect the RAG database: {exc}") from exc
    if not isinstance(chunk_count, int) or chunk_count < 0:
        raise RAGQueryError("RAG database returned an invalid chunk count")
    if chunk_count == 0:
        return None

    profile = str(config["profile_id"])
    try:
        model = load_embedding_model(profile, local_files_only=True)
    except WorkspaceInitError as exc:
        raise RAGQueryError(
            f"Embedding model for profile '{profile}' is not available locally.\n\n"
            "Run:\n\n"
            f"    omcipcap ai rag init --profile {profile} --dir {workspace}"
        ) from exc

    try:
        vectors = model.encode([question])
        query_embedding = [float(value) for value in vectors[0]]
        response = collection.query(
            query_embeddings=[query_embedding],
            n_results=chunk_count,
            include=["metadatas", "distances"],
        )
    except RAGQueryError:
        raise
    except Exception as exc:
        raise RAGQueryError(f"Failed to query indexed RAG cases: {exc}") from exc

    chunks = _parse_query_chunks(response)
    return aggregate_cases(chunks, top_k)


def format_query_results(results: list[QueryResult]) -> str:
    lines = [
        "Rank  Score  Case ID",
        "----  -----  --------",
    ]
    lines.extend(
        f"{rank:<6}{result.similarity:.2f}   {result.case_id}"
        for rank, result in enumerate(results, start=1)
    )
    return "\n".join(lines)
