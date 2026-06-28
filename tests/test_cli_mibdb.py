#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
#
import subprocess
import pytest
import json
import os


@pytest.fixture(scope="module", autouse=True)
def setup_test_files():

    subprocess.run(["python3", "utils/generate_dual_gem_shared_tcont.py"], check=True)
    subprocess.run(["python3", "utils/generate_mibdb_vendor.py"], check=True)

    yield

    test_files = ["single_unit_1_tont_2_gem.pcap", "mibdb_vendor.pcap"]

    for f in test_files:
        if os.path.exists(f):
            os.remove(f)


def test_mibdb_all():
    result = subprocess.run(
        [
            "omcipcap",
            "mibdb",
            "--json-output",
            "single_unit_1_tont_2_gem.pcap",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    #
    # verify stdout is valid json
    #
    try:
        mibdb_output = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        pytest.fail(f"stdout is not valid json\n{e}\n\nstdout:\n{result.stdout}")

    expected_classes = [
        "2",
        "5",
        "6",
        "11",
        "45",
        "47",
        "84",
        "130",
        "171",
        "262",
        "266",
        "268",
        "272",
        "277",
        "278",
        "280",
    ]
    assert len(mibdb_output) == 16, f"Expected 16 Class, Got {len(mibdb_output)} Class"
    for cid in expected_classes:
        assert cid in mibdb_output, f"Class ID not match{cid}"

    # cehck ME 2 (ONT Data)
    ont_data = mibdb_output["2"]["instances"]["0"]
    assert "MIB Data Sync" in ont_data
    assert "val" in ont_data["MIB Data Sync"]
    assert "text" in ont_data["MIB Data Sync"]
    assert ont_data["MIB Data Sync"]["val"] == "0x1"

    # cehck ME 5 Cardholder
    cardholders = mibdb_output["5"]["instances"]
    assert "257" in cardholders
    assert "384" in cardholders

    assert cardholders["257"]["Actual Equipment Id"]["text"] == "SFU10G"
    assert cardholders["384"]["Actual Plug-in Unit Type"]["text"] == "XG-PON10G10"

    # check ME 84
    vlan_filter = mibdb_output["84"]["instances"]["2"]
    assert vlan_filter["VLAN filter list"]["val"].startswith("0064")
    assert vlan_filter["VLAN filter list"]["text"] == "VID:100(P:0)"
    assert vlan_filter["Number of entries"]["text"] == "0x1"

    vlan_op = mibdb_output["171"]["instances"]["1"]

    assert (
        vlan_op["Association type"]["text"]
        == "Physical path termination point Ethernet UNI"
    )
    assert vlan_op["Association type"]["val"] == "0x2"

    assert vlan_op["Downstream mode"]["text"] == "Inverse (ONU Std)"
    assert vlan_op["Downstream mode"]["val"] == "0x0"


def test_mibdb_only_upload():
    """
    Verify 'omcipcap mibdb -j --only-upload' produces valid JSON and
    contains exactly 7 MEs.
    """
    result = subprocess.run(
        [
            "omcipcap",
            "mibdb",
            "-j",
            "--only-upload",
            "single_unit_1_tont_2_gem.pcap",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    # Verify stdout is valid json
    try:
        mibdb_output = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        pytest.fail(f"stdout is not valid json\n{e}\n\nstdout:\n{result.stdout}")

    # 1. Verify Class Count (Expected 7 MEs for only-upload)
    expected_classes = ["2", "5", "6", "262", "277", "278", "11"]
    assert len(mibdb_output) == 7, f"Expected 7 Classes, Got {len(mibdb_output)}"

    for cid in expected_classes:
        assert cid in mibdb_output, f"Missing expected Class ID: {cid}"

    # 2. Check ME 2 (ONT Data)
    ont_data = mibdb_output["2"]["instances"]["0"]
    assert "MIB Data Sync" in ont_data
    assert ont_data["MIB Data Sync"]["val"] == "0x1"
    assert ont_data["MIB Data Sync"]["text"] == "0x1"

    # 3. Check ME 5 (Cardholder) multi-instance
    cardholders = mibdb_output["5"]["instances"]
    assert "257" in cardholders
    assert "384" in cardholders

    # Check instance 257 equipment info
    assert cardholders["257"]["Actual Equipment Id"]["val"] == "SFU10G"
    assert cardholders["257"]["Actual Equipment Id"]["text"] == "SFU10G"

    # Check instance 384 plug-in unit type
    assert cardholders["384"]["Actual Plug-in Unit Type"]["val"] == "0xee"
    assert cardholders["384"]["Actual Plug-in Unit Type"]["text"] == "XG-PON10G10"

    # 4. Check ME 6 (Circuit Pack) details
    cp_inst = mibdb_output["6"]["instances"]["257"]
    assert cp_inst["Serial Number"]["val"] == "5043415000000001"
    assert cp_inst["Version"]["text"] == "V1.0"

    # 5. Check ME 262 (T-CONT) Alloc-ID baseline
    tcont_inst = mibdb_output["262"]["instances"]["32768"]
    # In initial upload, Alloc-ID is usually 0xffff
    assert tcont_inst["Alloc-ID"]["val"] == "0xffff"
    assert tcont_inst["Mode indicator"]["text"] == "0x1"

    # 6. Check ME 277 (Priority queue-G) related port
    pq_inst = mibdb_output["277"]["instances"]["32768"]
    assert pq_inst["Related port"]["val"] == "80000007"
    assert pq_inst["Allocated queue size"]["text"] == "0x4"


def test_mibdb_filter_class_id():

    result = subprocess.run(
        [
            "omcipcap",
            "mibdb",
            "-j",
            "--class-id=84,171",
            "single_unit_1_tont_2_gem.pcap",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    # Verify stdout is valid json
    try:
        mibdb_output = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        pytest.fail(f"stdout is not valid json\n{e}\n\nstdout:\n{result.stdout}")

    # 1. Verify Class Filtering: Only 84 and 171 should exist
    assert len(mibdb_output) == 2, (
        f"Expected exactly 2 classes, got {len(mibdb_output)}"
    )
    assert "84" in mibdb_output
    assert "171" in mibdb_output

    # 2. Verify ME 171 (Extended VLAN) attributes and table structure
    me171_inst1 = mibdb_output["171"]["instances"]["1"]

    # Check simple enumerations with semantic text
    assert me171_inst1["Association type"]["val"] == "0x2"
    assert (
        me171_inst1["Association type"]["text"]
        == "Physical path termination point Ethernet UNI"
    )
    assert me171_inst1["Downstream mode"]["text"] == "Inverse (ONU Std)"

    # Check the VLAN tagging operation table (should be a list of hex strings)
    vlan_table_val = me171_inst1["Received frame VLAN tagging operation table"]["val"]
    assert isinstance(vlan_table_val, list)
    assert len(vlan_table_val) == 4
    assert vlan_table_val[0].startswith("F800")

    # 3. Verify ME 84 (VLAN tagging filter data) decoding
    me84_instances = mibdb_output["84"]["instances"]
    assert "2" in me84_instances
    assert "3" in me84_instances

    # Instance 2: Should decode to VID 100
    assert me84_instances["2"]["VLAN filter list"]["text"] == "VID:100(P:0)"
    assert me84_instances["2"]["VLAN filter list"]["val"].startswith("0064")
    assert me84_instances["2"]["Number of entries"]["val"] == "0x1"

    # Instance 3: Should decode to VID 200
    assert me84_instances["3"]["VLAN filter list"]["text"] == "VID:200(P:0)"
    assert me84_instances["3"]["VLAN filter list"]["val"].startswith("00C8")
    assert me84_instances["3"]["Number of entries"]["val"] == "0x1"


# test mibdb --only-vendor
def test_mibdb_only_vendor():
    result = subprocess.run(
        [
            "omcipcap",
            "mibdb",
            "-j",
            "--only-vendor",
            "mibdb_vendor.pcap",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    # Verify stdout is valid json
    try:
        mibdb_output = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        pytest.fail(f"stdout is not valid json\n{e}\n\nstdout:\n{result.stdout}")

    # 1. Verify Class Filtering: Only 84 and 171 should exist
    assert len(mibdb_output) == 2, (
        f"Expected exactly 2 classes, got {len(mibdb_output)}"
    )
    assert "65300" in mibdb_output
    assert "65400" in mibdb_output

    me65300_inst1 = mibdb_output["65300"]["instances"]["1"]
    assert (
        me65300_inst1["0xf800"]["val"]
        == "4354430000010001000000000000000000000000000000000000"
    )
    assert (
        me65300_inst1["0xf800"]["text"]
        == "4354430000010001000000000000000000000000000000000000"
    )

    me65400_inst1 = mibdb_output["65400"]["instances"]["1"]
    assert (
        me65400_inst1["0xc000"]["val"]
        == "76312E302E35000001000000000000000000000000000000000000000000"
    )
    assert (
        me65400_inst1["0xc000"]["text"]
        == "76312E302E35000001000000000000000000000000000000000000000000"
    )
