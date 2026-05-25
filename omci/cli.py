#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

import os
from omci import omcimib
from omci import omcigrapher
from omci import omciparser
from omci import omcisemantic
from omci import omcirich
from omci.ai_overview import run_ai_overview
import argparse
import json


def run_mibdb(pcap, only_upload=False, class_id_str=None, json_output=False):
    class_ids = None
    if class_id_str:
        try:
            class_ids = [int(c.strip()) for c in class_id_str.split(",")]
        except ValueError:
            print(
                "[!] Error: Class ID must be numbers separated by commas (e.g. 84,171)"
            )
            return

    mib_data = omciparser.get_mib_db_data(pcap, only_upload, class_ids)

    if json_output:
        print(json.dumps(mib_data, indent=2))
    else:
        omcirich.render_mibdb_table(mib_data)


def run_omcicheck(
    pcap_path,
    only_vendor=False,
    only_failed=False,
    rtt_threshold=1000,
    json_output=False,
):

    check_result = omciparser.get_check_results(
        pcap_path, only_vendor, only_failed, rtt_threshold
    )

    if json_output:
        print(json.dumps(check_result, indent=2))
    else:
        omcirich.render_check_table(check_result)


def run_omcidiff(pcap1, pcap2, full_diff=False, class_id_str=None, json_output=False):
    class_ids = None
    if full_diff:
        mib1 = omciparser.get_all_mib_db(pcap1)
        mib2 = omciparser.get_all_mib_db(pcap2)
    else:
        mib1 = omciparser.get_mib_snapshot(pcap1)
        mib2 = omciparser.get_mib_snapshot(pcap2)

    if class_id_str:
        try:
            class_ids = [int(c.strip()) for c in class_id_str.split(",")]
        except ValueError:
            print(
                "[!] Error: Class ID must be numbers separated by commas (e.g. 84,171)"
            )
            return

    filter_set = set(class_ids) if class_ids else None
    if filter_set:
        mib1 = {k: v for k, v in mib1.items() if k[0] in filter_set}
        mib2 = {k: v for k, v in mib2.items() if k[0] in filter_set}

    diff_data = omciparser.get_mib_diff_data(mib1, mib2)

    if json_output:
        print(json.dumps(diff_data, indent=2))
    else:
        omcirich.render_diff_table(diff_data)


def run_omcitopo(pcap, output_html=None, json_output=False):
    topo_data = omciparser.get_topology_data(pcap)

    if json_output:
        print(json.dumps(topo_data, indent=4))
        return

    if not output_html:
        base_name = os.path.splitext(pcap)[0]
        output_html = f"{base_name}.html"

    html_content = omcigrapher.export_to_html(topo_data)
    with open(output_html, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[+] Topology visualization saved to: {output_html}")


def run_omcivlan(pcap, tpid_dei=False, json_output=False):
    mib_db = omciparser.get_all_mib_db(pcap)
    vlan_data = omciparser.get_vlan_data(mib_db)

    if json_output:
        print(json.dumps(vlan_data, indent=2))
    else:
        omcirich.render_vlan_table(vlan_data, tpid_dei)


def run_tcont_flow(pcap, json_output=False):
    mib_db = omciparser.get_all_mib_db(pcap)
    flow_data = omciparser.get_flow_data(mib_db)

    if json_output:
        print(json.dumps(flow_data, indent=2))
    else:
        omcirich.render_tcont_flow_tree(flow_data)


def load_mib_json(json_path):
    """
    Dynamic loading of external JSON configurations, allowing users to overwritestandard ME definitions
    or define custom Vendor-specific ME specifications.
    """
    if not json_path or not os.path.exists(json_path):
        return
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            custom_me = json.load(f)
            for cid, spec in custom_me.items():
                omcimib.ME_SPEC[int(cid)] = tuple(spec)
            # print(f"[*] Successfully loaded {len(custom_me)} custom ME specs.")
    except Exception as e:
        print(f"[!] Error loading MIB JSON: {e}")


def main():
    parser = argparse.ArgumentParser(
        prog="omcipcap", description="OMCI PCAP Diagnostic & Analysis Tool"
    )

    common_args = argparse.ArgumentParser(add_help=False)
    common_args.add_argument(
        "-j", "--json-output", action="store_true", help="Output results in JSON format"
    )

    subparsers = parser.add_subparsers(
        dest="command", help="Available analysis commands"
    )
    # --- Sub-command: check ---
    check_p = subparsers.add_parser(
        "check", parents=[common_args], help="Analyze RTT, TID duplicates, and failures"
    )
    check_p.add_argument("pcap", help="Path to pcap file")
    check_p.add_argument(
        "--rtt-threshold", type=float, default=1000.0, help="RTT threshold in ms"
    )
    check_p.add_argument("--only-vendor", action="store_true")
    check_p.add_argument("--only-failed", action="store_true")

    # --- Sub-command: mibdb ---
    mibdb_p = subparsers.add_parser(
        "mibdb", parents=[common_args], help="Dump MIB database"
    )
    mibdb_p.add_argument("pcap", help="Path to pcap file")
    mibdb_p.add_argument("--only-upload", action="store_true")
    mibdb_p.add_argument(
        "--class-id",
        help="Filter by ME class IDs (comma-separated, e.g., 84,171)",
        type=str,
    )
    mibdb_p.add_argument("--mib-json", help="Custom ME JSON definition")
    mibdb_p.add_argument("--semantic-dir", help="ME attributes semantic extension dir")

    # --- Sub-command: diff ---
    diff_p = subparsers.add_parser(
        "mibdb-diff",
        aliases=["diff"],
        parents=[common_args],
        help="Compare MIB snapshots between two pcaps (only compare MIB upload MIBs by default)",
    )
    diff_p.add_argument("pcap1", help="Baseline pcap")
    diff_p.add_argument("pcap2", help="Target pcap")
    diff_p.add_argument(
        "--full",
        action="store_true",
        help="Compare the full MIB lifecycle (including OLT provisioning). "
        "If not set, only the initial MIB upload (Hardware Snapshot) is compared.",
    )
    diff_p.add_argument(
        "--class-id",
        help="Filter by ME class IDs (comma-separated, e.g., 84,171)",
        type=str,
    )
    diff_p.add_argument("--mib-json", help="Custom ME JSON definition")
    diff_p.add_argument("--semantic-dir", help="ME attributes semantic extension dir")

    # --- Sub-command: topology (formerly graphic) ---
    topo_p = subparsers.add_parser(
        "topology",
        aliases=["graphic"],
        parents=[common_args],
        help="Visualize and export ONT internal logical connection topology",
    )
    topo_p.add_argument("pcap", help="Path to pcap file")
    topo_p.add_argument(
        "-o",
        "--output-html",
        help="Output HTML file path (default: <pcap_name>.html)",
        default=None,
    )

    # --- Sub-command: vlan_tbl ---
    vlan_p = subparsers.add_parser(
        "vlan-tbl",
        parents=[common_args],
        help="Analye OMCI VLAN tagging logic (Table-driven)",
    )
    vlan_p.add_argument(
        "--tpid-dei", action="store_true", help="Display TPID/DEI operation"
    )
    vlan_p.add_argument("pcap", help="Path to pcap file")

    # --- Sub-command: tcont_flow ---
    tcont_p = subparsers.add_parser(
        "tcont-flow",
        parents=[common_args],
        help="Trace T-CONT -> GEM -> PQ traffic hierarchy",
    )
    tcont_p.add_argument("pcap", help="Path to pcap file")

    # --- Sub-command: ai-overview ---
    ai_p = subparsers.add_parser(
        "ai-overview",
        help="Generate AI-powered diagnostic overview (requires OpenRouter API key)",
    )
    ai_p.add_argument(
        "--model",
        help="Model to use (default: anthropic/claude-sonnet-4-5)",
        default="anthropic/claude-sonnet-4-5",
    )
    ai_p.add_argument("pcap", help="Path to pcap file")

    args = parser.parse_args()

    if args.command == "check":
        run_omcicheck(
            args.pcap,
            args.only_vendor,
            args.only_failed,
            args.rtt_threshold,
            json_output=args.json_output,
        )
    elif args.command == "mibdb":
        if args.mib_json:
            load_mib_json(args.mib_json)
        if args.semantic_dir:
            omcisemantic.load_external_semantics(args.semantic_dir)
        run_mibdb(
            args.pcap, args.only_upload, args.class_id, json_output=args.json_output
        )
    elif args.command in ["mibdb-diff", "diff"]:
        if args.mib_json:
            load_mib_json(args.mib_json)
        run_omcidiff(
            args.pcap1,
            args.pcap2,
            args.full,
            args.class_id,
            json_output=args.json_output,
        )
    elif args.command in ["topology", "graphic"]:
        run_omcitopo(args.pcap, args.output_html, json_output=args.json_output)
    elif args.command == "vlan-tbl":
        run_omcivlan(args.pcap, args.tpid_dei, json_output=args.json_output)
    elif args.command == "tcont-flow":
        run_tcont_flow(args.pcap, json_output=args.json_output)
    elif args.command == "ai-overview":
        run_ai_overview(args.pcap, model=args.model)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
