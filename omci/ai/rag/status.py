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
    PROFILE_CONFIGS,
    WorkspaceInitError,
    resolve_workspace,
)


@dataclass(frozen=True)
class RAGStatus:
    workspace: Path
    profile: str
    database_status: str
    compatibility: str
    rebuild_required: bool
    indexed_cases: int


def _load_chromadb() -> object:
    try:
        import chromadb
    except ImportError as exc:
        raise WorkspaceInitError(
            "AI dependencies are not installed.\n\n"
            "Install them with:\n\n"
            '    pip install "omcipcap[ai]"'
        ) from exc
    return chromadb


def _is_compatible(metadata: dict[str, object], profile: str) -> bool:
    return (
        metadata.get("db_schema_version") == DB_SCHEMA_VERSION
        and metadata.get("profile_id") == profile
    )


def get_rag_status() -> RAGStatus:
    workspace, config = resolve_workspace(require_database_dir=False)
    profile = str(config["profile_id"])
    db_path = workspace / "db"

    if not db_path.is_dir():
        return RAGStatus(
            workspace=workspace,
            profile=profile,
            database_status="missing",
            compatibility="not-applicable",
            rebuild_required=False,
            indexed_cases=0,
        )

    if not any(db_path.iterdir()):
        return RAGStatus(
            workspace=workspace,
            profile=profile,
            database_status="empty",
            compatibility=(
                "compatible" if _is_compatible(config, profile) else "incompatible"
            ),
            rebuild_required=not _is_compatible(config, profile),
            indexed_cases=0,
        )

    try:
        chromadb_module = _load_chromadb()
        client = chromadb_module.PersistentClient(path=str(db_path))
        collection = client.get_collection(name=COLLECTION_NAME)
        metadata = collection.metadata
        if not isinstance(metadata, dict):
            raise ValueError("collection metadata is missing")
        schema_version = metadata.get("db_schema_version")
        database_profile = metadata.get("profile_id")
        if not isinstance(schema_version, int) or not isinstance(
            database_profile, str
        ):
            raise ValueError("collection metadata is invalid")
        records = collection.get(include=["metadatas"])
        record_metadatas = records.get("metadatas") or []
        case_ids = {
            item["case_id"]
            for item in record_metadatas
            if isinstance(item, dict)
            and isinstance(item.get("case_id"), str)
            and item["case_id"]
        }
    except Exception:
        return RAGStatus(
            workspace=workspace,
            profile=profile,
            database_status="invalid",
            compatibility="unknown",
            rebuild_required=False,
            indexed_cases=0,
        )

    compatible = _is_compatible(metadata, profile)
    compatibility = "compatible" if compatible else "incompatible"
    return RAGStatus(
        workspace=workspace,
        profile=profile,
        database_status="ready" if case_ids else "empty",
        compatibility=compatibility,
        rebuild_required=not compatible,
        indexed_cases=len(case_ids),
    )


def get_active_profile() -> str | None:
    try:
        _, config = resolve_workspace()
    except WorkspaceInitError:
        return None
    profile = config.get("profile_id")
    return profile if isinstance(profile, str) and profile in PROFILE_CONFIGS else None
