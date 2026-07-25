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
SUPPORTED_PROFILES = ("standard", "workstation", "server")
WORKSPACE_DIRS = ("db", "issues", "mib-json", "semantics")


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


def _write_json_once(path: Path, data: dict[str, object]) -> None:
    if path.exists():
        if _read_json(path) != data:
            raise WorkspaceInitError(
                f"Existing file '{path}' is incompatible with the requested workspace"
            )
        return

    temp_path = None
    try:
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


def _ensure_config(path: Path, profile: str) -> None:
    if path.exists():
        config = _read_json(path)
        if (
            config.get("db_schema_version") != DB_SCHEMA_VERSION
            or config.get("profile_id") != profile
        ):
            raise WorkspaceInitError(
                f"Existing file '{path}' is incompatible with the requested workspace"
            )
        return

    _write_json_once(
        path,
        {
            "db_schema_version": DB_SCHEMA_VERSION,
            "profile_id": profile,
            "omcipcap_version": __version__,
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
    )


def initialize_workspace(workdir: Path, profile: str) -> Path:
    if profile not in SUPPORTED_PROFILES:
        supported = ", ".join(SUPPORTED_PROFILES)
        raise WorkspaceInitError(
            f"Unsupported RAG profile '{profile}'. Supported profiles: {supported}"
        )

    workspace = workdir.expanduser()
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

    _ensure_config(workspace / "config.json", profile)
    return workspace
