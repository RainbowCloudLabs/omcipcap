#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.

import subprocess
import pytest
import json
import os


@pytest.fixture(scope="module", autouse=True)
def setup_test_files():
    """
    Generate the test pcap file using the utility script.
    """
    subprocess.run(["python3", "utils/generate_dual_gem_shared_tcont.py"], check=True)
    yield
    # Cleanup
    if os.path.exists("single_unit_1_tont_2_gem.pcap"):
        os.remove("single_unit_1_tont_2_gem.pcap")
    if os.path.exists("overview.json"):
        os.remove("overview.json")


def get_overview_json():
    """
    Helper to run the overview-json command and read the generated JSON file.
    """
    cmd = ["omcipcap", "overview-json", "single_unit_1_tont_2_gem.pcap"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)

    # Check if output file was created
    assert os.path.exists("overview.json"), "overview.json file was not generated"

    # Read and parse the JSON file
    with open("overview.json", "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            pytest.fail("Failed to parse JSON from overview.json file")


def test_onu_capability_pon_type():
    """
    Verify ONU capability PON type detection.
    """
    data = get_overview_json()
    onu_cap = data["onu_capability"]

    assert "pon_type" in onu_cap, "pon_type field is missing from onu_capability"
    assert onu_cap["pon_type"] == "XG-PON (Symmetric 10G/10G)", (
        f"Expected PON type 'XG-PON (Symmetric 10G/10G)', got '{onu_cap['pon_type']}'"
    )


def test_onu_capability_pptp_count():
    """
    Verify ONU capability PPTP Ethernet UNI port count.
    """
    data = get_overview_json()
    onu_cap = data["onu_capability"]

    assert "pptp_count" in onu_cap, "pptp_count field is missing from onu_capability"
    assert onu_cap["pptp_count"] == 1, (
        f"Expected 1 PPTP port, got {onu_cap['pptp_count']}"
    )


def test_onu_capability_pots_count():
    """
    Verify ONU capability POTS UNI port count.
    """
    data = get_overview_json()
    onu_cap = data["onu_capability"]

    assert "pots_count" in onu_cap, "pots_count field is missing from onu_capability"
    assert onu_cap["pots_count"] == 0, (
        f"Expected 0 POTS ports, got {onu_cap['pots_count']}"
    )


def test_onu_capability_tcont_count():
    """
    Verify ONU capability T-CONT count.
    """
    data = get_overview_json()
    onu_cap = data["onu_capability"]

    assert "tcont_count" in onu_cap, "tcont_count field is missing from onu_capability"
    assert onu_cap["tcont_count"] == 2, (
        f"Expected 2 T-CONTs, got {onu_cap['tcont_count']}"
    )


def test_onu_capability_priority_queue_count():
    """
    Verify ONU capability Priority Queue count.
    """
    data = get_overview_json()
    onu_cap = data["onu_capability"]

    assert "priority_queue_count" in onu_cap, (
        "priority_queue_count field is missing from onu_capability"
    )
    assert onu_cap["priority_queue_count"] == 24, (
        f"Expected 24 Priority Queues, got {onu_cap['priority_queue_count']}"
    )


def test_onu_capability_all_fields():
    """
    Comprehensive check: verify all expected fields exist in onu_capability.
    """
    data = get_overview_json()
    onu_cap = data["onu_capability"]

    expected_fields = {
        "pon_type": str,
        "pptp_count": int,
        "pots_count": int,
        "tcont_count": int,
        "priority_queue_count": int,
    }

    for field, field_type in expected_fields.items():
        assert field in onu_cap, f"Field '{field}' is missing from onu_capability"
        assert isinstance(onu_cap[field], field_type), (
            f"Field '{field}' should be {field_type.__name__}, "
            f"got {type(onu_cap[field]).__name__}"
        )
