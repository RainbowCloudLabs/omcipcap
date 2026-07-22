#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

import os
import subprocess
import pytest


@pytest.fixture(scope="module", autouse=True)
def setup_test_files():
    subprocess.run(["python3", "utils/generate_omcicheck_example.py"], check=True)
    subprocess.run(["python3", "utils/generate_omcidiff_example.py"], check=True)
    subprocess.run(["python3", "utils/generate_dual_gem_shared_tcont.py"], check=True)

    yield

    test_files = [
        "omcicheck_example.pcap",
        "mib_before.pcap",
        "mib_after.pcap",
        "mib_omcc_96.pcap",
        "mib_omcc_a0.pcap",
        "mib_vendor_v1.pcap",
        "mib_vendor_v2.pcap",
        "mib_mask_c000.pcap",
        "mib_mask_8000.pcap",
        "single_unit_1_tont_2_gem.pcap",
    ]

    for f in test_files:
        if os.path.exists(f):
            os.remove(f)


def test_cmd_check_md_output():
    result = subprocess.run(
        [
            "omcipcap",
            "check",
            "--md",
            "omcicheck_example.pcap",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    output = result.stdout

    assert "## OMCI Check Statistics" in output
    assert "## OMCI Check Details" in output

    assert "Response Fail Count" in output
    assert "ONU Upload Vendor ME Count" in output
    assert "OLT Provision Vendor ME Count" in output
    assert "Transaction ID Duplicate Count" in output

    assert "Err: INSTANCE_EXISTS" in output
    assert "Err: UNKNOWN_ME" in output
    assert "[LATE]" in output
    assert "[TID_DUPLICATE]" in output
    assert "ONT2-G" in output

    assert "| No. |" in output or "| No. |" in output
    assert "| TID |" in output
    assert "| Action |" in output


def test_cmd_vlan_md_output():
    result = subprocess.run(
        [
            "omcipcap",
            "vlan-tbl",
            "--md",
            "single_unit_1_tont_2_gem.pcap",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    output = result.stdout

    assert "## VLAN Operation Summary" in output
    assert "## VLAN Rules for ME Inst ID 1" in output
    assert "Physical path termination point Ethernet UNI" in output
    assert "Inverse" in output
    assert "Single Default: Discard" in output
    assert "Double Default: Discard" in output
    assert "C(100)-F -> X(100)-F" in output
    assert "C(200)-F -> X(200)-F" in output

    assert "| Filter outer TPID/DEI |" in output
    assert "| Filter Ethertype |" in output
    assert "| Treatment tags to remove |" in output
    assert "| Treatment outer priority |" in output

    assert "TPID:any" in output
    assert "Copy:Inner" in output
    assert "Any" in output  # Filter Ethertype = 0
    assert "| 1 |" in output  # Treatment tags to remove = 1 (single tag)
    assert "| 3 |" in output  # Treatment tags to remove = 3 (discard)
    assert "| 100 |" in output  # VID 100
    assert "| 200 |" in output  # VID 200


def test_cmd_tcont_flow_md_output():
    result = subprocess.run(
        [
            "omcipcap",
            "tcont-flow",
            "--md",
            "single_unit_1_tont_2_gem.pcap",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    output = result.stdout

    assert "## T-CONT Flow Statistics" in output
    assert "## T-CONT / GEM Flow Summary" in output
    assert "## T-CONT / GEM Flow Tree" in output

    assert "Total T-CONTs" in output
    assert "Bound T-CONTs" in output
    assert "Empty T-CONTs" in output
    assert "Total GEM Ports" in output

    assert "32768" in output
    assert "1000" in output
    assert "1001" in output
    assert "1002" in output
    assert "32775" in output
    assert "32769" in output
    assert "Unassigned" in output
    assert "No GEM ports" in output
    assert "CIR=0.128Mbps/PIR=9953.28Mbps" in output
    assert "CIR=0.128Mbps/PIR=100Mbps" in output
    assert "Unrestricted" in output


def test_cmd_mibdb_md_output():
    result = subprocess.run(
        [
            "omcipcap",
            "mibdb",
            "--md",
            "single_unit_1_tont_2_gem.pcap",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    output = result.stdout

    assert "## MIB Class Summary" in output
    assert "| Class ID | ME Name | Instance Count |" in output
    assert "ONT Data" in output
    assert "Cardholder" in output
    assert "PPTP Ethernet UNI" in output
    assert "Extended VLAN tagging operation configuration data" in output
    assert "T-CONT" in output
    assert "GEM Port Network CTP" in output

    assert "## Class 2 - ONT Data" in output
    assert "## Class 5 - Cardholder" in output
    assert "## Class 171 - Extended VLAN tagging operation configuration data" in output
    assert "## Class 262 - T-CONT" in output
    assert "## Class 268 - GEM Port Network CTP" in output

    assert "| Attribute | Raw Value | Semantic Text |" in output
    assert "10G GBASE-T Ethernet" in output
    assert "SFU10G" in output
    assert "XG-PON10G10" in output
    assert "VID:100(P:0)" in output
    assert "Inverse (ONU Std)" in output
    assert "32768" in output
    assert "0x3e8" in output  # Alloc-ID 1000
    assert "0x3e9" in output  # GEM Port ID 1001


def test_cmd_topology_md_output():
    result = subprocess.run(
        [
            "omcipcap",
            "topology",
            "--md",
            "single_unit_1_tont_2_gem.pcap",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    output = result.stdout

    assert "## Topology Nodes" in output
    assert "## Topology Edges" in output

    assert "| Node ID | Class ID | Instance ID | ME Name |" in output
    assert "| Source | Target | Relation | Label |" in output

    # Key nodes
    assert "262_32768" in output
    assert "T_CONT" in output
    assert "11_257" in output
    assert "PPTP_ETHERNET_UNI" in output
    assert "171_1" in output
    assert "EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA" in output
    assert "268_1" in output
    assert "GEM_PORT_NETWORK_CTP" in output

    # Key edges
    assert "vlan_op_associated_with_me" in output
    assert "belongs_to_bridge" in output
    assert "traffic_mapped_to_tcont" in output
    assert "iw_linked_to_gem_port" in output
    assert "vlan_filter_bind_to_port" in output

    # Specific edge pairs
    assert "171_1" in output and "11_257" in output
    assert "268_1" in output and "262_32768" in output
    assert "266_1" in output and "268_1" in output
