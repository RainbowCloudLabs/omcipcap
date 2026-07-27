#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

from dataclasses import dataclass

from omci.ai.rag.database import RAGDatabaseError, open_existing_collection
from omci.ai.rag.workspace import (
    WorkspaceInitError,
    load_embedding_model,
    resolve_workspace,
)


DEFAULT_TOP_K = 5
MIN_SIMILARITY = 0.50


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

    try:
        collection = open_existing_collection(workspace, config)
    except RAGDatabaseError as exc:
        raise RAGQueryError(str(exc)) from exc
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
