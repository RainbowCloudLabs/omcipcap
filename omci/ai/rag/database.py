#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

from pathlib import Path

from omci.ai.rag.workspace import DB_SCHEMA_VERSION


COLLECTION_NAME = "omcipcap_rag"


class RAGDatabaseError(Exception):
    """Raised when an existing RAG database cannot be used."""


def validate_collection_metadata(
    metadata: object,
    config: dict[str, object],
) -> dict[str, object]:
    if not isinstance(metadata, dict):
        raise RAGDatabaseError("RAG database metadata is missing or invalid")
    if (
        metadata.get("hnsw:space") != "cosine"
        or metadata.get("db_schema_version") != DB_SCHEMA_VERSION
        or metadata.get("profile_id") != config["profile_id"]
    ):
        raise RAGDatabaseError(
            "RAG database metadata is incompatible with the active workspace "
            "(profile or distance metric mismatch)"
        )
    version = metadata.get("omcipcap_version")
    if not isinstance(version, str) or not version:
        raise RAGDatabaseError("RAG database metadata is missing or invalid")
    return metadata


def _load_chromadb() -> object:
    try:
        import chromadb
    except ImportError as exc:
        raise RAGDatabaseError(
            "AI dependencies are not installed.\n\n"
            "Install them with:\n\n"
            '    pip install "omcipcap[rag]"'
        ) from exc
    return chromadb


def open_existing_collection(
    workspace: Path,
    config: dict[str, object],
) -> object | None:
    db_path = workspace / "db"
    if not db_path.exists():
        raise RAGDatabaseError(f"RAG database is missing: '{db_path}'")
    if not db_path.is_dir():
        raise RAGDatabaseError(
            f"RAG database is invalid: '{db_path}' is not a directory"
        )
    if not any(db_path.iterdir()):
        return None

    try:
        client = _load_chromadb().PersistentClient(path=str(db_path))
        collection = client.get_collection(name=COLLECTION_NAME)
    except RAGDatabaseError:
        raise
    except Exception as exc:
        raise RAGDatabaseError(f"RAG database is invalid: {exc}") from exc

    validate_collection_metadata(collection.metadata, config)
    return collection
