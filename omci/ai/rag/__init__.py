#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

"""RAG workspace support."""

from omci.ai.rag.ingest import RAGIngestError, ingest_case
from omci.ai.rag.workspace import initialize_workspace, resolve_workspace

__all__ = [
    "RAGIngestError",
    "ingest_case",
    "initialize_workspace",
    "resolve_workspace",
]
