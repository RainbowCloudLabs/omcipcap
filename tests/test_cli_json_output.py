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


def test_cmd_check_json_output():

    result = subprocess.run(
        [
            "omcipcap",
            "check",
            "--json-output",
            "examples/omcicheck_example.pcap",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    #
    # verify stdout is valid json
    #
    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        pytest.fail(f"stdout is not valid json\n{e}\n\nstdout:\n{result.stdout}")

    #
    # verify top-level structure
    #
    assert "packets" in output, "Missing 'packets' field in json output"

    assert "summary" in output, "Missing 'summary' field in json output"

    packets = output["packets"]
    summary = output["summary"]

    #
    # verify summary counters
    #
    assert summary["resp_fail_count"] == 2, "Should detect 2 OMCI response failures"

    assert summary["is_vendor_me_count"] == 5, (
        "Should detect 5 vendor/future ME packets"
    )

    assert summary["resp_late_count"] == 1, "Should detect 1 late OMCI response"

    assert summary["transaction_id_duplicate_count"] == 1, (
        "Should detect 1 duplicate transaction ID"
    )

    #
    # verify exported abnormal packet count
    #
    assert len(packets) == 8, "Expected 8 abnormal packets in json output"

    #
    # verify INSTANCE_EXISTS response exported correctly
    #
    instance_exists_pkt = next((pkt for pkt in packets if pkt["packet_no"] == 58), None)

    assert instance_exists_pkt is not None, "INSTANCE_EXISTS packet not found"

    assert instance_exists_pkt["action"] == "CREATE"

    assert instance_exists_pkt["me_class"] == 84

    assert instance_exists_pkt["result"]["success"] is False

    assert instance_exists_pkt["result"]["text"] == ("Err: INSTANCE_EXISTS")

    #
    # verify UNKNOWN_ME response exported correctly
    #
    unknown_me_pkt = next((pkt for pkt in packets if pkt["packet_no"] == 60), None)

    assert unknown_me_pkt is not None, "UNKNOWN_ME packet not found"

    assert unknown_me_pkt["action"] == "SET"

    assert unknown_me_pkt["me_class"] == 241

    assert unknown_me_pkt["result"]["success"] is False

    assert unknown_me_pkt["result"]["text"] == ("Err: UNKNOWN_ME")

    #
    # verify late response packet exported correctly
    #
    late_response_pkt = next(
        (pkt for pkt in packets if pkt["status"] == "[LATE]"), None
    )

    assert late_response_pkt is not None, "Late response packet not found"

    assert late_response_pkt["action"] == "GET"

    assert late_response_pkt["me_name"] == "ONT2-G"

    assert late_response_pkt["result"]["success"] is True

    #
    # verify duplicate transaction ID packet exported correctly
    #
    tid_duplicate_pkt = next(
        (pkt for pkt in packets if pkt["status"] == "[TID_DUPLICATE]"), None
    )

    assert tid_duplicate_pkt is not None, "Duplicate transaction ID packet not found"

    assert tid_duplicate_pkt["transaction_id"] == 32

    assert tid_duplicate_pkt["from_olt"] is True

    #
    # verify vendor/future ME packets exported correctly
    #
    vendor_me_classes = {
        pkt["me_class"]
        for pkt in packets
        if "vendor" in pkt["me_name"].lower() or "future" in pkt["me_name"].lower()
    }

    assert vendor_me_classes == {241, 350, 500}, "Vendor/Future ME classes mismatch"


def test_cmd_vlan_json_output():
    """
    Verify 'omcipcap vlan_tbl --json-output' produces valid JSON and
    correctly parses VLAN tagging operation rules (ME 171).
    """
    result = subprocess.run(
        [
            "omcipcap",
            "vlan-tbl",
            "--json-output",
            "single_unit_1_tont_2_gem.pcap",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        pytest.fail(f"stdout is not valid JSON\n{e}\n\nstdout:\n{result.stdout}")

    assert isinstance(output, list), "VLAN JSON output should be a list"
    assert len(output) > 0, "No VLAN instances found in output"

    vlan_inst = output[0]
    required_keys = ["inst_id", "rules", "assoc_ptr", "assoc_type", "ds_mode"]
    for key in required_keys:
        assert key in vlan_inst, f"Missing '{key}' field in VLAN JSON output"

    assert vlan_inst["inst_id"] == 1, "incorrect VLAN instance ID"
    assert vlan_inst["assoc_ptr"] == 257, "incorrect Associated ME pointer"
    assert vlan_inst["assoc_type"] == "Physical path termination point Ethernet UNI", (
        "incorrect Associated ME pointer"
    )
    assert vlan_inst["ds_mode"][:7] == "Inverse", "incorrect Associated Downstream Mode"

    rules = vlan_inst["rules"]
    assert isinstance(rules, list), "'rules' should be a list"
    assert len(rules) == 4, "Should get 4 VLAN rules"

    rule_0 = rules[0]
    assert rule_0["action_type"] == "Single Default: Discard", (
        "Rule 0 Action Type not match"
    )

    expected_r0_data = {
        "f_out_prio": 15,
        "f_out_vid": 4096,
        "f_out_tpid": 0,
        "f_in_prio": 14,
        "f_in_vid": 4096,
        "f_in_tpid": 0,
        "f_eth_type": 0,
        "t_tags_rem": 3,
        "t_out_prio": 15,
        "t_out_vid": 0,
        "t_out_tpid": 0,
        "t_in_prio": 15,
        "t_in_vid": 0,
        "t_in_tpid": 0,
    }

    assert rule_0["data"] == expected_r0_data, "Rule 0 data dictionary mismatch"

    rule_1 = rules[1]
    assert rule_1["action_type"] == "Double Default: Discard", (
        "Rule 1 Action Type not match"
    )

    expected_r1_data = {
        "f_out_prio": 14,
        "f_out_vid": 4096,
        "f_out_tpid": 0,
        "f_in_prio": 14,
        "f_in_vid": 4096,
        "f_in_tpid": 0,
        "f_eth_type": 0,
        "t_tags_rem": 3,
        "t_out_prio": 15,
        "t_out_vid": 0,
        "t_out_tpid": 0,
        "t_in_prio": 15,
        "t_in_vid": 0,
        "t_in_tpid": 0,
    }

    assert rule_1["data"] == expected_r1_data, "Rule 1 data dictionary mismatch"

    rule_2 = rules[2]
    assert (
        rule_2["action_type"] == "Single: Modify tag, keep prio  C(100)-F -> X(100)-F"
    ), "Rule 2 Action Type not match"

    expected_r2_data = {
        "f_out_prio": 15,
        "f_out_vid": 4096,
        "f_out_tpid": 0,
        "f_in_prio": 8,
        "f_in_vid": 100,
        "f_in_tpid": 0,
        "f_eth_type": 0,
        "t_tags_rem": 1,
        "t_out_prio": 15,
        "t_out_vid": 0,
        "t_out_tpid": 0,
        "t_in_prio": 8,
        "t_in_vid": 100,
        "t_in_tpid": 0,
    }

    assert rule_2["data"] == expected_r2_data, "Rule 2 data dictionary mismatch"

    rule_3 = rules[3]
    assert (
        rule_3["action_type"] == "Single: Modify tag, keep prio  C(200)-F -> X(200)-F"
    ), "Rule 3 Action Type not match"

    expected_r3_data = {
        "f_out_prio": 15,
        "f_out_vid": 4096,
        "f_out_tpid": 0,
        "f_in_prio": 8,
        "f_in_vid": 200,
        "f_in_tpid": 0,
        "f_eth_type": 0,
        "t_tags_rem": 1,
        "t_out_prio": 15,
        "t_out_vid": 0,
        "t_out_tpid": 0,
        "t_in_prio": 8,
        "t_in_vid": 200,
        "t_in_tpid": 0,
    }

    assert rule_3["data"] == expected_r3_data, "Rule 3 data dictionary mismatch"


def test_cmd_tcont_flow_json_output():
    """
    Verify 'omcipcap tcont_flow --json-output' produces valid JSON and
    correctly maps T-CONT -> GEM -> PQ hierarchy with descriptive error messages.
    """
    result = subprocess.run(
        [
            "omcipcap",
            "tcont-flow",
            "--json-output",
            "single_unit_1_tont_2_gem.pcap",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        pytest.fail(f"stdout is not valid JSON\n{e}\n\nstdout:\n{result.stdout}")

    assert isinstance(output, list), (
        f"Expected JSON list, but got {type(output).__name__}"
    )
    assert len(output) == 2, f"should have 2 T-CONT, but got {len(output)} T-CONT"

    tcont_32768 = next((t for t in output if t["tcont_id"] == 32768), None)
    assert tcont_32768 is not None, "T-CONT with inst_id 32768 not found in output"
    assert tcont_32768["alloc_id"] == 1000, (
        f"Expected Alloc-ID 1000 for T-CONT 32768, but got {tcont_32768['alloc_id']}"
    )
    assert len(tcont_32768["gem_ports"]) == 2, (
        f"T-CONT 32768 should have 2 GEM ports, found {len(tcont_32768['gem_ports'])}"
    )

    gem_1001 = next(
        (g for g in tcont_32768["gem_ports"] if g["gem_port_id"] == 1001), None
    )
    assert gem_1001 is not None, "GEM Port 1001 not found under T-CONT 32768"

    assert gem_1001["upstream"]["pq_ptr"] == 32775, (
        f"GEM 1001 Upstream PQ mismatch: expected 32775, got {gem_1001['upstream']['pq_ptr']}"
    )
    assert "CIR=0.128Mbps/PIR=9953.28Mbps" in gem_1001["upstream"]["bandwidth"], (
        f"GEM 1001 US Bandwidth error: {gem_1001['upstream']['bandwidth']}"
    )

    assert gem_1001["downstream"]["pq_ptr"] == 0, (
        f"GEM 1001 Downstream PQ mismatch: expected 0, got {gem_1001['downstream']['pq_ptr']}"
    )
    assert gem_1001["downstream"]["priority"] == 0, (
        f"GEM 1001 Downstream Priority mismatch: expected 0, got {gem_1001['downstream']['priority']}"
    )
    assert gem_1001["downstream"]["bandwidth"] == "Unrestricted", (
        f"GEM 1001 DS Bandwidth should be Unrestricted, got {gem_1001['downstream']['bandwidth']}"
    )

    gem_1002 = next(
        (g for g in tcont_32768["gem_ports"] if g["gem_port_id"] == 1002), None
    )
    assert gem_1002 is not None, "GEM Port 1002 not found under T-CONT 32768"

    assert gem_1002["upstream"]["pq_ptr"] == 32768, (
        f"GEM 1002 Upstream PQ mismatch: expected 32768, got {gem_1002['upstream']['pq_ptr']}"
    )

    assert "CIR=0.128Mbps/PIR=100Mbps" in gem_1002["upstream"]["bandwidth"], (
        f"GEM 1002 US Bandwidth error: {gem_1002['upstream']['bandwidth']}"
    )

    assert gem_1002["downstream"]["pq_ptr"] == 6, (
        f"GEM 1002 Downstream PQ mismatch: expected 6, got {gem_1002['downstream']['pq_ptr']}"
    )
    assert gem_1002["downstream"]["priority"] == 6, (
        f"GEM 1002 Downstream Priority mismatch: expected 6, got {gem_1002['downstream']['priority']}"
    )
    assert gem_1002["downstream"]["bandwidth"] == "Unrestricted", (
        f"GEM 1002 DS Bandwidth should be Unrestricted, got {gem_1002['downstream']['bandwidth']}"
    )

    tcont_32769 = next((t for t in output if t["tcont_id"] == 32769), None)
    assert tcont_32769 is not None, "T-CONT 32769 not found"
    assert tcont_32769["alloc_id"] is None, (
        f"T-CONT 32769 should have null alloc_id, but got {tcont_32769['alloc_id']}"
    )
    assert len(tcont_32769["gem_ports"]) == 0, (
        f"Unassigned T-CONT 32769 should have 0 GEM ports, found {len(tcont_32769['gem_ports'])}"
    )


def test_cmd_mibdb_diff_json_output():
    """
    Test the 'mibdb-diff -j' command to ensure it produces a valid and accurate JSON report.
    """
    result = subprocess.run(
        [
            "omcipcap",
            "mibdb-diff",
            "-j",
            "mib_before.pcap",
            "mib_after.pcap",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.returncode == 0

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        pytest.fail(f"stdout is not valid JSON\n{e}\n\nstdout:\n{result.stdout}")

    summary = data.get("summary", {})
    assert summary["added_count"] == 1
    assert summary["removed_count"] == 1
    assert summary["modified_count"] == 2
    assert summary["unknown_me_mask_mismatch_count"] == 0

    changes = data.get("changes", [])
    assert len(changes) == 4

    cardholder_mod = next(
        c for c in changes if c["class_id"] == 5 and c["inst_id"] == 257
    )
    assert cardholder_mod["status"] == "modified"
    assert cardholder_mod["old"] == "0x30"
    assert cardholder_mod["new"] == "0x31"
    assert cardholder_mod["attr_name"] == "Actual Plug-in Unit Type"

    ip_host_mod = next(c for c in changes if c["class_id"] == 134)
    assert ip_host_mod["attr_name"] == "MAC address"
    assert ip_host_mod["old"] == "00:00:00:00:00:00"
    assert ip_host_mod["new"] == "C0:A8:01:0A:00:00"

    tcont_add = next(c for c in changes if c["class_id"] == 262)
    assert tcont_add["status"] == "added"
    assert tcont_add["me_name"] == "T-CONT"

    cardholder_rem = next(
        c for c in changes if c["class_id"] == 5 and c["inst_id"] == 258
    )
    assert cardholder_rem["status"] == "removed"


def test_cmd_mibdb_diff_vendor_specific_json():
    """
    Test 'mibdb-diff -j' with vendor-specific MEs (Class 355).
    Verifies that the parser handles unknown MEs using Attribute Masks.
    """

    result = subprocess.run(
        [
            "omcipcap",
            "mibdb-diff",
            "-j",
            "mib_vendor_v1.pcap",
            "mib_vendor_v2.pcap",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.returncode == 0

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        pytest.fail(f"stdout is not valid JSON\n{e}\n\nstdout:\n{result.stdout}")

    summary = data.get("summary", {})
    assert summary["modified_count"] == 1
    assert summary["added_count"] == 0
    assert summary["removed_count"] == 0

    change = data["changes"][0]
    assert change["status"] == "modified"
    assert change["class_id"] == 355
    assert change["inst_id"] == 0

    assert "Reserved" in change["me_name"]

    assert change["attr_name"] == "Vendor Raw (Mask 0xC000)"

    expected_old = "4847550100000000000000000000000000000000000000000000"
    expected_new = "5346550000000000000000000000000000000000000000000000"
    assert change["old"] == expected_old
    assert change["new"] == expected_new


def test_cmd_mibdb_diff_multiple_vendor_attributes():
    """
    Test 'mibdb-diff -j' when a single vendor-specific ME has multiple attribute changes.
    Matches the scenario: CPE mode (HGU->SFU) and Support VOIP (0x1->0x0).
    """

    result = subprocess.run(
        [
            "omcipcap",
            "mibdb-diff",
            "-j",
            "mib_vendor_v1.pcap",
            "mib_vendor_v2.pcap",
            "--mib-json",
            "examples/vendor_355.json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.returncode == 0

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        pytest.fail(f"stdout is not valid JSON\n{e}\n\nstdout:\n{result.stdout}")

    summary = data.get("summary", {})
    assert summary["modified_count"] == 2
    assert summary["added_count"] == 0
    assert summary["removed_count"] == 0

    changes = data.get("changes", [])
    assert len(changes) == 2

    cpe_mod = next(c for c in changes if c["attr_name"] == "CPE mode")
    assert cpe_mod["status"] == "modified"
    assert cpe_mod["class_id"] == 355
    assert cpe_mod["old"] == "HGU"
    assert cpe_mod["new"] == "SFU"

    voip_mod = next(c for c in changes if c["attr_name"] == "Support VOIP")
    assert voip_mod["status"] == "modified"
    assert voip_mod["old"] == "0x1"
    assert voip_mod["new"] == "0x0"

    assert cpe_mod["inst_id"] == voip_mod["inst_id"] == 0


def test_cmd_mibdb_diff_mask_mismatch_handling():
    """
    Test 'mibdb-diff -j' when the same Class ID has mibdb-different attribute masks
    between two PCAPs (e.g., 0xC000 vs 0x8000).
    Verifies that the mismatch is caught and reported correctly.
    """

    result = subprocess.run(
        [
            "omcipcap",
            "mibdb-diff",
            "-j",
            "mib_mask_c000.pcap",
            "mib_mask_8000.pcap",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.returncode == 0

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        pytest.fail(f"stdout is not valid JSON\n{e}\n\nstdout:\n{result.stdout}")

    summary = data.get("summary", {})
    assert summary["modified_count"] == 0
    assert summary["unknown_me_mask_mismatch_count"] == 1

    mismatches = data.get("unknown_me_mask_mismatch", [])
    assert len(mismatches) == 1

    target_mismatch = mismatches[0]
    assert target_mismatch["class_id"] == 355
    assert target_mismatch["inst_id"] == 0

    assert len(data.get("changes", [])) == 0
