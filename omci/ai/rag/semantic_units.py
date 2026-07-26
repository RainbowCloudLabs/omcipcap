#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

from dataclasses import dataclass


@dataclass(frozen=True)
class SemanticUnitDefinition:
    semantic_unit: str
    display_name: str
    priority: int


SEMANTIC_UNIT_DEFINITIONS = (
    SemanticUnitDefinition("issue_summary", "Issue Summary", 90),
    SemanticUnitDefinition("failed_check_results", "Failed Check Results", 100),
    SemanticUnitDefinition("core_mib_summary", "Core MIB Summary", 70),
    SemanticUnitDefinition("service_path", "Service Path", 80),
    SemanticUnitDefinition("upload_mib", "Upload MIB", 50),
    SemanticUnitDefinition(
        "vendor_specific_mib",
        "Vendor-specific MIB",
        60,
    ),
    SemanticUnitDefinition("full_mib", "Full MIB", 10),
)
