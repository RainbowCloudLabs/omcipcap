#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

import pytest

from omci.omcigrapher import export_to_html, generate_tooltip
from omci.omcimib import SENSITIVE_ME_CLASSES
from omci import omcisemantic


@pytest.mark.parametrize("cid", sorted(SENSITIVE_ME_CLASSES))
def test_sensitive_class_tooltip(cid: int) -> None:
    assert generate_tooltip(cid, 1, {"Value": "private-value"}) == "Value: *****\n"


def test_sensitive_attributes_in_html() -> None:
    attrs = {"PASSWORD": "private-password", "Shared Secret": "private-secret", "Port": 7}
    data = {"nodes": [{"id": "134_1", "class_id": 134, "inst_id": 1,
                       "name": "IP_HOST_CONFIG_DATA", "attributes": attrs}], "edges": []}
    html = export_to_html(data)
    assert "private-password" not in html
    assert "private-secret" not in html
    assert "PASSWORD: *****" in html
    assert "Shared Secret: *****" in html
    assert "Port: 7" in html
    assert attrs["PASSWORD"] == "private-password"


@pytest.mark.parametrize("cid, name", [(47, "TP type"), (171, "Association type")])
def test_tooltip_semantics_preserved(cid: int, name: str) -> None:
    expected = omcisemantic.get_attr_semantic(cid, name, 1)
    assert generate_tooltip(cid, 1, {name: 1}) == f"{name}: {expected}\n"


def test_empty_tooltip() -> None:
    assert generate_tooltip(134, 1, {}) == "ME 134 (1)"
