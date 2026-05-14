#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong Yuan, Shih daneshih1125@gmail.com
# Licensed under the MIT License.
#
import subprocess
import pytest
import os
import re

@pytest.fixture(scope="module", autouse=True)
def setup_test_files():
    # for omcipcap check
    subprocess.run(["python3", "utils/generate_omcicheck_example.py"], check=True)
    # for omcipcap diff
    subprocess.run(["python3", "utils/generate_omcidiff_example.py"], check=True)
    # for omcipcap graphic, vlan_tbl and tcont_flow
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
        "single_unit_1_tont_2_gem.pcap",
        "output.html",
    ]

    for f in test_files:
        if os.path.exists(f): os.remove(f)

def test_cmd_check_summary():
    result = subprocess.run(
        ["omcipcap", "check", "omcicheck_example.pcap"],
        capture_output=True,
        text=True,
        check=True
    )

    expected_summary = (
        "Summary: Found 2 failures, 5 Vendor packets, "
        "1 duplicate packets, 1 late packets"
    )

    assert expected_summary in result.stdout, (
        f"Result not match!\n"
        f"Expected: {expected_summary}\n"
        f"Actual output: {result.stdout.strip()}"
    )

    pattern = r"241\s+0x0001\s+0\s+Reserved for vendor"

    assert re.search(pattern, result.stdout), (
        f"\n[Fail] vendor ME info not correct！\n"
        f"Expected: {pattern}\n"
        f"Actual output: {result.stdout.strip()}"
    )

    pattern = r"350\s+0x0001\s+0\s+Reserved for vendor"

    assert re.search(pattern, result.stdout), (
        f"\n[Fail] vendor ME info not correct！\n"
        f"Expected: {pattern}\n"
        f"Actual output: {result.stdout.strip()}"
    )

    pattern = r"500\s+0x000a\s+0\s+Reserved for future"

    assert re.search(pattern, result.stdout), (
        f"\n[Fail] future ME info not correct！\n"
        f"Expected: {pattern}\n"
        f"Actual output: {result.stdout.strip()}"
    )

    pattern = r"84\s+0x0001\s+Err:\s+INSTANCE_EXISTS"

    assert re.search(pattern, result.stdout), (
        f"\n[Fail] should detect INSTANCE_EXISTS！\n"
        f"Expected: {pattern}\n"
        f"Actual output: {result.stdout.strip()}"
    )

    pattern = r"241\s+0x0001\s+Err:\s+UNKNOWN_ME"

    assert re.search(pattern, result.stdout), (
        f"\n[Fail] should detect UNKNOWN_ME！\n"
        f"Expected: {pattern}\n"
        f"Actual output: {result.stdout.strip()}"
    )

    pattern = r"\[LATE\]\s+ONT2-G"

    assert re.search(pattern, result.stdout), (
        f"\n[Fail] should detect late responses！\n"
        f"Expected: {pattern}\n"
        f"Actual output: {result.stdout.strip()}"
    )

    pattern = r"\[TID_DUPLICATE\]\s+ONT2-G"

    assert re.search(pattern, result.stdout), (
        f"\n[Fail] should detect duplicate transaction ID\n"
        f"Expected: {pattern}\n"
        f"Actual output: {result.stdout.strip()}"
    )

def test_cmd_diff():
    result = subprocess.run(
        ["omcipcap", "diff", "mib_before.pcap", "mib_after.pcap"],
        capture_output=True,
        text=True,
        check=True
    )

    pattern = r"\[\*\]\s+Cardholder\s+\(5\, 257\)"

    assert re.search(pattern, result.stdout), (
        f"\n[Fail] should detect changes in Cardholder ME attributes！\n"
        f"Expected: {pattern}\n"
        f"Actual output: {result.stdout.strip()}"
    )

    pattern = r"\[REMOVED\]\s+Cardholder\s+\(5\, 258\)"

    assert re.search(pattern, result.stdout), (
        f"\n[Fail] Should detect removed Cardholder ME！\n"
        f"Expected: {pattern}\n"
        f"Actual output: {result.stdout.strip()}"
    )

    pattern = r"\[\*\]\s+IP host config data\s+\(134\, 1\)"

    assert re.search(pattern, result.stdout), (
        f"\n[Fail] should detect changes in ME 134 attributes！\n"
        f"Expected: {pattern}\n"
        f"Actual output: {result.stdout.strip()}"
    )

    pattern = r"\[NEW\]\s+T-CONT\s+\(262\, 1\)"

    assert re.search(pattern, result.stdout), (
        f"\n[Fail] Should detect added T-CONT ME！\n"
        f"Expected: {pattern}\n"
        f"Actual output: {result.stdout.strip()}"
    )

    result = subprocess.run(
        ["omcipcap", "diff", "mib_vendor_v1.pcap", "mib_vendor_v2.pcap"],
        capture_output=True,
        text=True,
        check=True
    )

    expected_diff = (
        "4847550100000000000000000000000000000000000000000000"
        " -> "
        "5346550000000000000000000000000000000000000000000000"
    )

    assert expected_diff in result.stdout, (
        f"Diff Result not match!\n"
        f"Expected: {expected_diff}\n"
        f"Actual output: {result.stdout.strip()}"
    )

    result = subprocess.run(
        [
            "omcipcap", "diff",
            "mib_vendor_v1.pcap", "mib_vendor_v2.pcap",
            "--mib-json", "examples/vendor_355.json"
        ],
        capture_output=True,
        text=True,
        check=True
    )

    pattern = r"CPE mode\s+\|\s+\'HGU\'\s+\-\>\s+\'SFU\'"

    assert re.search(pattern, result.stdout), (
        f"\n[Fail] Diff result not correct！\n"
        f"Expected: {pattern}\n"
        f"Actual output: {result.stdout.strip()}"
    )

    pattern = r"Support VOIP\s+\|\s+0x1\s+\-\>\s+0x0"

    assert re.search(pattern, result.stdout), (
        f"\n[Fail] Diff result not correct！\n"
        f"Expected: {pattern}\n"
        f"Actual output: {result.stdout.strip()}"
    )

def test_cmd_graphic():

    pcap_file = "single_unit_1_tont_2_gem.pcap"
    output_file = "output.html"

    subprocess.run(["omcipcap", "graphic", pcap_file], check=True)

    assert os.path.exists(output_file), "{output_file} not exist"

    with open(output_file, "r", encoding="utf-8") as f:
        html_content = f.read()


    assert "<title>OMCI Graph - MAC Bridged Topology</title>" in html_content, (
        f"HTML title not match\n"
    )
    assert "vis-network.min.js" in html_content, (
        f"No VIS js\n"
    )

    # console.table(nodes.get()), total 15 nodes
    assert re.search(r'"id":\s*"262_32768"', html_content), (
        f"T-CONT inst 32768 not found\n"
    )

    assert re.search(r'"id":\s*"11_257"', html_content), (
        f"PPTP inst 257 not found\n"
    )

    assert re.search(r'"id":\s*"171_1"', html_content), (
        f"EXT_VLAN inst 1 not found\n"
    )

    assert re.search(r'"id":\s*"45_1"', html_content), (
        f"MAC_BRIDGE inst 1 not found\n"
    )

    assert re.search(r'"id":\s*"47_1"', html_content), (
        f"MAC_BRIDGE_PORT inst 1 not found\n"
    )

    assert re.search(r'"id":\s*"268_1"', html_content), (
        f"GEM_PORT_NETWORK_CTP inst 1 not found\n"
    )

    assert re.search(r'"id":\s*"268_2"', html_content), (
        f"GEM_PORT_NETWORK_CTP inst 2 not found\n"
    )

    assert re.search(r'"id":\s*"130_1"', html_content), (
        f"DOT1P_MAPPER inst 1 not found\n"
    )

    assert re.search(r'"id":\s*"47_2"', html_content), (
        f"MAC_BRIDGE_PORT inst 2 not found\n"
    )

    assert re.search(r'"id":\s*"266_1"', html_content), (
        f" 'GEM_INTERWORKING_TERMINATION_POINT inst 1 not found\n"
    )

    assert re.search(r'"id":\s*"84_2"', html_content), (
        f"VLAN_TAGGING_FILTER inst 2 not found\n"
    )

    assert re.search(r'"id":\s*"130_2"', html_content), (
        f"DOT1P_MAPPER inst 2 not found\n"
    )

    assert re.search(r'"id":\s*"47_3"', html_content), (
        f"MAC_BRIDGE_PORT inst 3 not found\n"
    )

    assert re.search(r'"id":\s*"266_2"', html_content), (
        f"GEM_INTERWORKING_TERMINATION_POINT inst 2 not found\n"
    )

    assert re.search(r'"id":\s*"84_3"', html_content), (
        f"VLAN_TAGGING_FILTER inst 3 not found\n"
    )

    # console.table(edges.get()), total 15 edges
    edge_pattern = r'"from":\s*"171_1",\s*"to":\s*"11_257"'
    assert re.search(edge_pattern, html_content), (
        f"Topology error: Could not find the connection from EXT_VLAN to PPTP.\n"
    )

    edge_pattern = r'"from":\s*"47_1",\s*"to":\s*"45_1"'
    assert re.search(edge_pattern, html_content), (
        f"Topology error: Could not find the connection from "
        f"MAC_BRIDGE_PORT (PPTP) to MAC_BRIDGE.\n"
    )

    edge_pattern = r'"from":\s*"47_1",\s*"to":\s*"11_257"'
    assert re.search(edge_pattern, html_content), (
        f"Topology error: Could not find the connection from "
        f"MAC_BRIDGE_PORT to PPTP UNI 1.\n"
    )

    edge_pattern = r'"from":\s*"268_1",\s*"to":\s*"262_32768"'
    assert re.search(edge_pattern, html_content), (
        f"Topology error: Could not find the connection from "
        f"GEM_PORT_NETWORK_CTP inst 1 to T-CONT (0x8000).\n"
    )

    edge_pattern = r'"from":\s*"268_2",\s*"to":\s*"262_32768"'
    assert re.search(edge_pattern, html_content), (
        f"Topology error: Could not find the connection from "
        f"GEM_PORT_NETWORK_CTP inst 2 to T-CONT (0x8000).\n"
    )

    edge_pattern = r'"from":\s*"47_2",\s*"to":\s*"45_1"'
    assert re.search(edge_pattern, html_content), (
        f"Topology error: Could not find the connection from "
        f"MAC_BRIDGE_PORT(8021P) inst 2 to MAC_BRIDGE.\n"
    )

    edge_pattern = r'"from":\s*"47_2",\s*"to":\s*"130_1"'
    assert re.search(edge_pattern, html_content), (
        f"Topology error: Could not find the connection from "
        f"MAC_BRIDGE_PORT(8021P) inst 2 to DOT1P_MAPPER inst 1\n"
    )

    edge_pattern = r'"from":\s*"266_1",\s*"to":\s*"268_1"'
    assert re.search(edge_pattern, html_content), (
        f"Topology error: Could not find the connection from "
        f"GEM_PORT_NETWORK_CTP inst 1 to GEM_PORT_NETWORK_CTP inst 1\n"
    )

    edge_pattern = r'"from":\s*"266_1",\s*"to":\s*"130_1"'
    assert re.search(edge_pattern, html_content), (
        f"Topology error: Could not find the connection from "
        f"GEM_PORT_NETWORK_CTP inst 1 to DOT1P_MAPPER inst 1\n"
    )

    edge_pattern = r'"from":\s*"84_2",\s*"to":\s*"47_2"'
    assert re.search(edge_pattern, html_content), (
        f"Topology error: Could not find the connection from "
        f"VLAN_TAGGING_FILTER inst 2 to MAC_BRIDGE_PORT inst 2\n"
    )

    edge_pattern = r'"from":\s*"47_3",\s*"to":\s*"45_1"'
    assert re.search(edge_pattern, html_content), (
        f"Topology error: Could not find the connection from "
        f"MAC_BRIDGE_PORT(8021P) inst 3 to MAC_BRIDGE.\n"
    )

    edge_pattern = r'"from":\s*"47_3",\s*"to":\s*"130_2"'
    assert re.search(edge_pattern, html_content), (
        f"Topology error: Could not find the connection from "
        f"MAC_BRIDGE_PORT(8021P) inst 3 to DOT1P_MAPPER inst 2\n"
    )

    edge_pattern = r'"from":\s*"266_2",\s*"to":\s*"268_2"'
    assert re.search(edge_pattern, html_content), (
        f"Topology error: Could not find the connection from "
        f"GEM_PORT_NETWORK_CTP inst 2 to GEM_PORT_NETWORK_CTP inst 2\n"
    )

    edge_pattern = r'"from":\s*"266_2",\s*"to":\s*"130_2"'
    assert re.search(edge_pattern, html_content), (
        f"Topology error: Could not find the connection from "
        f"GEM_PORT_NETWORK_CTP inst 2 to DOT1P_MAPPER inst 2\n"
    )

    edge_pattern = r'"from":\s*"84_3",\s*"to":\s*"47_3"'
    assert re.search(edge_pattern, html_content), (
        f"Topology error: Could not find the connection from "
        f"VLAN_TAGGING_FILTER inst 3 to MAC_BRIDGE_PORT inst 3\n"
    )

def test_cmd_vlan_tbl():

    pcap_file = "single_unit_1_tont_2_gem.pcap"

    result = subprocess.run(
        ["omcipcap", "vlan_tbl", pcap_file],
        capture_output=True,
        text=True,
        check=True
    )

    pattern = r"Single:.*Modify.*tag.*C\(100\)-F.*X\(100\)-F"

    assert re.search(pattern, result.stdout, re.DOTALL), (
        f"VLAN semantic mismatch!\n"
        f"Expected to find: Single: Modify tag... C(100)-F -> X(100)-F\n"
        f"Actual output snippet: {result.stdout[:1000]!r}"
    )

    pattern = r"Single:.*Modify.*tag.*C\(200\)-F.*X\(200\)-F"

    assert re.search(pattern, result.stdout, re.DOTALL), (
        f"VLAN semantic mismatch!\n"
        f"Expected to find: Single: Modify tag... C(200)-F -> X(200)-F\n"
        f"Actual output snippet: {result.stdout[:1000]!r}"
    )


def test_cmd_tcont_flow():

    pcap_file = "single_unit_1_tont_2_gem.pcap"

    result = subprocess.run(
        ["omcipcap", "tcont_flow", pcap_file],
        capture_output=True,
        text=True,
        check=True
    )

    tcont_pattern = r"T-CONT\s+32768\s+\(alloc-id=1000\)"
    assert re.search(tcont_pattern, result.stdout), (
        f"Could not find T-CONT 32768\n"
    )

    tcont_pattern = r'T-CONT\s+32769\s+\(Unassigned\)'
    assert re.search(tcont_pattern, result.stdout), (
        f"Could not find T-CONT 32769\n"
    )

    pattern = (
        r"GEM\s+1001.*.\[US\]\s+PQ 32775 → up:CIR=0.128Mbps/PIR=9953.28Mbps"
        r".*.\[DS\] PQ 0 → Priority Priority 0 dn:Unrestricted"
    )

    assert re.search(pattern, result.stdout, re.DOTALL), (
        f"GEM 1001 US/DS not match\n"
    )

    pattern = (
        r"GEM\s+1002.*.\[US\]\s+PQ 32768 → up:CIR=0.128Mbps/PIR=100Mbps"
        r".*.\[DS\] PQ 6 → Priority Priority 6 dn:Unrestricted"
    )

    assert re.search(pattern, result.stdout, re.DOTALL), (
        f"GEM 1002 US/DS not match\n"
    )
