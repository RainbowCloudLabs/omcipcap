#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

import subprocess
import sys


def test_help_omits_ai_when_rag_dependencies_are_unavailable() -> None:
    script = """
import importlib.abc
import sys

class BlockRAGDependencies(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if fullname in {"chromadb", "sentence_transformers"}:
            raise ImportError(f"blocked optional dependency: {fullname}")
        return None

sys.meta_path.insert(0, BlockRAGDependencies())
sys.argv = ["omcipcap", "--help"]

from omci.cli import main

main()
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=True,
    )

    assert "AI-assisted analysis commands" not in result.stdout
    assert "check" in result.stdout
    assert "mibdb" in result.stdout
    assert "topology" in result.stdout


def test_help_registers_ai_when_rag_dependencies_are_available() -> None:
    script = """
import sys
import types

sys.modules["chromadb"] = types.ModuleType("chromadb")
sys.modules["sentence_transformers"] = types.ModuleType("sentence_transformers")
sys.argv = ["omcipcap", "--help"]

from omci.cli import main

main()
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=True,
    )

    assert "AI-assisted analysis commands" in result.stdout
    assert "check" in result.stdout
    assert "mibdb" in result.stdout
    assert "topology" in result.stdout
