#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

"""RAG workspace support."""


def _ensure_dependencies_available() -> None:
    """Raise ImportError when the optional RAG dependencies are unavailable."""
    import chromadb  # noqa: F401
    import sentence_transformers  # noqa: F401


from omci.ai.rag.cases import (
    RAGCasesError,
    format_case_summaries,
    list_cases,
)
from omci.ai.rag.ingest import RAGIngestError, ingest_case
from omci.ai.rag.query import (
    DEFAULT_TOP_K,
    MIN_SIMILARITY,
    RAGQueryError,
    format_query_results,
    query_cases,
)
from omci.ai.rag.status import RAGStatus, get_active_profile, get_rag_status
from omci.ai.rag.workspace import initialize_workspace, resolve_workspace

__all__ = [
    "RAGIngestError",
    "RAGCasesError",
    "RAGQueryError",
    "RAGStatus",
    "DEFAULT_TOP_K",
    "MIN_SIMILARITY",
    "format_query_results",
    "format_case_summaries",
    "get_active_profile",
    "get_rag_status",
    "ingest_case",
    "initialize_workspace",
    "list_cases",
    "query_cases",
    "resolve_workspace",
]
