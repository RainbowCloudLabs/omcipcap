#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

from dataclasses import dataclass

from omci.ai.rag.database import RAGDatabaseError, open_existing_collection
from omci.ai.rag.workspace import WorkspaceInitError, resolve_workspace


class RAGCasesError(Exception):
    """Raised when indexed RAG cases cannot be listed."""


@dataclass(frozen=True)
class CaseSummary:
    case_id: str
    chunks: int
    problem: str


def aggregate_case_metadata(metadatas: object) -> list[CaseSummary]:
    if not isinstance(metadatas, list):
        raise RAGCasesError("RAG database returned invalid chunk metadata")

    cases: dict[str, CaseSummary] = {}
    for metadata in metadatas:
        if not isinstance(metadata, dict):
            raise RAGCasesError("RAG database chunk metadata is invalid")
        case_id = metadata.get("case_id")
        problem = metadata.get("problem")
        if (
            not isinstance(case_id, str)
            or not case_id
            or not isinstance(problem, str)
            or not problem
        ):
            raise RAGCasesError("RAG database chunk metadata is invalid")

        existing = cases.get(case_id)
        if existing is not None and existing.problem != problem:
            raise RAGCasesError(
                f'RAG case "{case_id}" has conflicting problem metadata'
            )
        cases[case_id] = CaseSummary(
            case_id=case_id,
            chunks=1 if existing is None else existing.chunks + 1,
            problem=problem,
        )
    return [cases[case_id] for case_id in sorted(cases)]


def list_cases() -> list[CaseSummary]:
    try:
        workspace, config = resolve_workspace(require_database_dir=False)
        collection = open_existing_collection(workspace, config)
    except (WorkspaceInitError, RAGDatabaseError) as exc:
        raise RAGCasesError(str(exc)) from exc
    if collection is None:
        return []

    try:
        result = collection.get(include=["metadatas"])
    except Exception as exc:
        raise RAGCasesError(f"Failed to read indexed RAG cases: {exc}") from exc
    if not isinstance(result, dict):
        raise RAGCasesError("RAG database returned invalid case metadata")
    return aggregate_case_metadata(result.get("metadatas"))


def format_case_summaries(cases: list[CaseSummary]) -> str:
    case_width = max(13, *(len(case.case_id) for case in cases))
    lines = [
        f"{'CASE ID':<{case_width}}  {'CHUNKS':<6}  PROBLEM",
        f"{'-' * case_width}  {'-' * 6}  {'-' * 47}",
    ]
    lines.extend(
        f"{case.case_id:<{case_width}}  {case.chunks:<6}  {case.problem}"
        for case in cases
    )
    return "\n".join(lines)
