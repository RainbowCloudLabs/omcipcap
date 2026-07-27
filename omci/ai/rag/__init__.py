#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

"""RAG workspace support."""

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
    "RAGQueryError",
    "RAGStatus",
    "DEFAULT_TOP_K",
    "MIN_SIMILARITY",
    "format_query_results",
    "get_active_profile",
    "get_rag_status",
    "ingest_case",
    "initialize_workspace",
    "query_cases",
    "resolve_workspace",
]
