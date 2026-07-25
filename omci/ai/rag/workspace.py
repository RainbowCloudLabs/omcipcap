#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

import json
import os
from datetime import datetime, timezone
from pathlib import Path
import tempfile

from omci import __version__


DB_SCHEMA_VERSION = 1
PROFILE_CONFIGS: dict[str, dict[str, object]] = {
    "standard": {
        "model": "sentence-transformers/all-MiniLM-L6-v2",
        "max_tokens": 256,
        "token_overlap": 32,
    },
    "workstation": {
        "model": "BAAI/bge-m3",
        "max_tokens": 512,
        "token_overlap": 64,
    },
    "server": {
        "model": "BAAI/bge-m3",
        "max_tokens": 512,
        "token_overlap": 64,
    },
}
SUPPORTED_PROFILES = tuple(PROFILE_CONFIGS)
WORKSPACE_DIRS = ("db", "issues", "mib-json", "semantics")
INIT_INSTRUCTION = "omcipcap ai rag init --profile <profile> --dir <workdir>"


class WorkspaceInitError(Exception):
    """Raised when a RAG workspace cannot be initialized."""


def _read_json(path: Path) -> dict[str, object]:
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkspaceInitError(f"Cannot read existing file '{path}': {exc}") from exc

    if not isinstance(data, dict):
        raise WorkspaceInitError(f"Existing file '{path}' must contain a JSON object")
    return data


def _write_json_atomic(path: Path, data: dict[str, object]) -> None:
    temp_path: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as f:
            temp_path = Path(f.name)
            json.dump(data, f, indent=2)
            f.write("\n")
        os.replace(temp_path, path)
    except OSError as exc:
        raise WorkspaceInitError(f"Cannot write file '{path}': {exc}") from exc
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass


def default_workspace_config_path() -> Path:
    return Path.home() / ".local" / "omcipcap" / "rag_config.json"


def _validate_workspace_metadata(
    workspace: Path, requested_profile: str | None = None
) -> dict[str, object]:
    config_path = workspace / "config.json"
    if not config_path.is_file():
        raise WorkspaceInitError(
            f"RAG workspace metadata is missing: '{config_path}'"
        )

    config = _read_json(config_path)
    if config.get("db_schema_version") != DB_SCHEMA_VERSION:
        raise WorkspaceInitError(
            f"RAG workspace schema is incompatible; expected version {DB_SCHEMA_VERSION}"
        )

    profile = config.get("profile_id")
    if not isinstance(profile, str) or profile not in SUPPORTED_PROFILES:
        raise WorkspaceInitError(
            f"RAG workspace profile is unsupported: '{profile}'"
        )
    if requested_profile is not None and profile != requested_profile:
        raise WorkspaceInitError(
            f"RAG workspace profile '{profile}' conflicts with requested profile "
            f"'{requested_profile}'"
        )

    version = config.get("omcipcap_version")
    created_at = config.get("created_at")
    if not isinstance(version, str) or not version:
        raise WorkspaceInitError("RAG workspace metadata has invalid omcipcap_version")
    if not isinstance(created_at, str) or not created_at:
        raise WorkspaceInitError("RAG workspace metadata has invalid created_at")
    try:
        timestamp = datetime.fromisoformat(created_at)
    except ValueError as exc:
        raise WorkspaceInitError(
            "RAG workspace metadata has invalid created_at"
        ) from exc
    if timestamp.utcoffset() != timezone.utc.utcoffset(timestamp):
        raise WorkspaceInitError("RAG workspace created_at must use UTC")

    for dirname in WORKSPACE_DIRS:
        if not (workspace / dirname).is_dir():
            raise WorkspaceInitError(
                f"RAG workspace is incomplete; missing directory: '{dirname}'"
            )
    return config


def _ensure_workspace_metadata(path: Path, profile: str) -> None:
    if path.exists():
        _validate_workspace_metadata(path.parent, profile)
        return

    _write_json_atomic(
        path,
        {
            "db_schema_version": DB_SCHEMA_VERSION,
            "profile_id": profile,
            "omcipcap_version": __version__,
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
    )


def _write_default_workspace(workspace: Path) -> None:
    _write_json_atomic(
        default_workspace_config_path(),
        {"workspace_path": str(workspace)},
    )


def initialize_workspace(workdir: Path, profile: str) -> Path:
    if profile not in SUPPORTED_PROFILES:
        supported = ", ".join(SUPPORTED_PROFILES)
        raise WorkspaceInitError(
            f"Unsupported RAG profile '{profile}'. Supported profiles: {supported}"
        )

    workspace = workdir.expanduser().resolve()
    try:
        if workspace.exists() and not workspace.is_dir():
            raise WorkspaceInitError(
                f"RAG workspace path is not a directory: '{workspace}'"
            )
        workspace.mkdir(parents=True, exist_ok=True)
        for dirname in WORKSPACE_DIRS:
            (workspace / dirname).mkdir(exist_ok=True)
    except OSError as exc:
        raise WorkspaceInitError(
            f"Cannot create RAG workspace '{workspace}': {exc}"
        ) from exc

    _ensure_workspace_metadata(workspace / "config.json", profile)
    _write_default_workspace(workspace)
    return workspace


def resolve_workspace() -> tuple[Path, dict[str, object]]:
    user_config_path = default_workspace_config_path()
    if not user_config_path.is_file():
        raise WorkspaceInitError(
            f"Default RAG workspace is not configured. Run: {INIT_INSTRUCTION}"
        )

    try:
        user_config = _read_json(user_config_path)
    except WorkspaceInitError as exc:
        raise WorkspaceInitError(
            f"Default RAG workspace configuration is invalid. "
            f"Run: {INIT_INSTRUCTION}. Details: {exc}"
        ) from exc

    workspace_value = user_config.get("workspace_path")
    if not isinstance(workspace_value, str) or not workspace_value.strip():
        raise WorkspaceInitError(
            f"Default RAG workspace configuration has no valid workspace_path. "
            f"Run: {INIT_INSTRUCTION}"
        )

    workspace = Path(workspace_value).expanduser().resolve()
    if not workspace.is_dir():
        raise WorkspaceInitError(
            f"Configured RAG workspace does not exist: '{workspace}'. "
            f"Run: {INIT_INSTRUCTION}"
        )

    try:
        config = _validate_workspace_metadata(workspace)
    except WorkspaceInitError as exc:
        raise WorkspaceInitError(
            f"Configured RAG workspace is invalid: {exc}. "
            f"Run: {INIT_INSTRUCTION}"
        ) from exc
    return workspace, config
