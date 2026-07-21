#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

import os
import argparse
import json

from omci import omcimib
from omci import omcigrapher
from omci import omciparser
from omci import omcisemantic
from omci import omcirich
from omci import omcimd
from omci import overview
from omci.omci import load_omci_packets


def output_result(
    data,
    *,
    json_output=False,
    md_output=False,
    md_renderer=None,
    rich_renderer=None,
    json_indent=2,
    rich_kwargs=None,
):
    rich_kwargs = rich_kwargs or {}

    if json_output:
        print(json.dumps(data, indent=json_indent))
    elif md_output:
        if md_renderer is None:
            raise ValueError("Markdown renderer is not provided.")
        print(md_renderer(data))
    else:
        if rich_renderer is None:
            raise ValueError("Rich renderer is not provided.")
        rich_renderer(data, **rich_kwargs)


def run_mibdb(
    pcap_path,
    only_upload=False,
    only_vendor=False,
    class_id_str=None,
    json_output=False,
    md_output=False,
):
    class_ids = None
    if class_id_str:
        try:
            class_ids = [int(c.strip()) for c in class_id_str.split(",")]
        except ValueError:
            print(
                "[!] Error: Class ID must be numbers separated by commas (e.g. 84,171)"
            )
            return

    omci_pkts = load_omci_packets(pcap_path, include_raw=False)
    mib_data = omciparser.get_mib_db_data(
        omci_pkts, only_upload, only_vendor, class_ids
    )

    output_result(
        mib_data,
        json_output=json_output,
        md_output=md_output,
        md_renderer=omcimd.render_mibdb_md,
        rich_renderer=omcirich.render_mibdb_table,
    )


def run_omcicheck(
    pcap_path,
    only_vendor=False,
    only_failed=False,
    rtt_threshold=1000,
    json_output=False,
    md_output=False,
):
    omci_pkts = load_omci_packets(pcap_path, include_raw=True)
    check_result = omciparser.get_check_results(
        omci_pkts, only_vendor, only_failed, rtt_threshold
    )

    output_result(
        check_result,
        json_output=json_output,
        md_output=md_output,
        md_renderer=omcimd.render_check_md,
        rich_renderer=omcirich.render_check_table,
    )


def run_omcidiff(
    pcap1,
    pcap2,
    full_diff=False,
    class_id_str=None,
    json_output=False,
    md_output=False,
):
    class_ids = None
    omci_pkts1 = load_omci_packets(pcap1, include_raw=False)
    omci_pkts2 = load_omci_packets(pcap2, include_raw=False)

    if full_diff:
        mib1 = omciparser.get_all_mib_db(omci_pkts1)
        mib2 = omciparser.get_all_mib_db(omci_pkts2)
    else:
        mib1 = omciparser.get_mib_snapshot(omci_pkts1)
        mib2 = omciparser.get_mib_snapshot(omci_pkts2)

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

    output_result(
        diff_data,
        json_output=json_output,
        md_output=md_output,
        md_renderer=omcimd.render_diff_md,
        rich_renderer=omcirich.render_diff_table,
    )


def run_omcitopo(pcap_path, output_html=None, json_output=False, md_output=False):
    omci_pkts = load_omci_packets(pcap_path, include_raw=False)
    topo_data = omciparser.get_topology_data(omci_pkts)

    if json_output:
        print(json.dumps(topo_data, indent=4))
        return
    elif md_output:
        print(omcimd.render_topology_md(topo_data))
        return

    if not output_html:
        base_name = os.path.splitext(pcap_path)[0]
        output_html = f"{base_name}.html"

    html_content = omcigrapher.export_to_html(topo_data)
    with open(output_html, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[+] Topology visualization saved to: {output_html}")


def run_omcivlan(pcap_path, tpid_dei=False, json_output=False, md_output=False):
    omci_pkts = load_omci_packets(pcap_path, include_raw=False)
    mib_db = omciparser.get_all_mib_db(omci_pkts)
    vlan_data = omciparser.get_vlan_data(mib_db)

    output_result(
        vlan_data,
        json_output=json_output,
        md_output=md_output,
        md_renderer=omcimd.render_vlan_md,
        rich_renderer=omcirich.render_vlan_table,
        rich_kwargs={"tpid_dei": tpid_dei},
    )


def run_tcont_flow(pcap_path, json_output=False, md_output=False):
    omci_pkts = load_omci_packets(pcap_path, include_raw=False)
    mib_db = omciparser.get_all_mib_db(omci_pkts)
    flow_data = omciparser.get_flow_data(mib_db)

    output_result(
        flow_data,
        json_output=json_output,
        md_output=md_output,
        md_renderer=omcimd.render_tcont_flow_md,
        rich_renderer=omcirich.render_tcont_flow_tree,
    )


def run_overview_json(pcap):
    """
    Output overview.json
    """
    overview.generate_pcap_ai_overview_json(pcap)


def load_mib_json(json_path):
    """
    Dynamic loading of external JSON configurations, allowing users to overwrite
    standard ME definitions or define custom Vendor-specific ME specifications.
    """
    if not json_path or not os.path.exists(json_path):
        return False

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            custom_me = json.load(f)
            for cid, spec in custom_me.items():
                omcimib.ME_SPEC[int(cid)] = tuple(spec)
        return True
    except Exception as e:
        print(f"[!] Error loading MIB file: {json_path}\n")
        print(f"[!] MIB JSON Error: {e}\n")
        return False


def args_load_json_semantic(args):
    if getattr(args, "mib_json", None):
        if not load_mib_json(args.mib_json):
            return False
    if getattr(args, "semantic_dir", None):
        if not omcisemantic.load_external_semantics(args.semantic_dir):
            return False
    return True


def main():
    parser = argparse.ArgumentParser(
        prog="omcipcap", description="OMCI PCAP Diagnostic & Analysis Tool"
    )

    common_args = argparse.ArgumentParser(add_help=False)
    format_group = common_args.add_mutually_exclusive_group()
    format_group.add_argument(
        "-j", "--json-output", action="store_true", help="Output results in JSON format"
    )
    format_group.add_argument(
        "--md", action="store_true", help="Output results in Markdown format"
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
    mibdb_p.add_argument("--only-vendor", action="store_true")
    mibdb_p.add_argument(
        "--class-id",
        help="Filter by ME class IDs (comma-separated, e.g., 84,171)",
        type=str,
    )
    mibdb_p.add_argument("--mib-json", help="Custom ME JSON definition")
    mibdb_p.add_argument("--semantic-dir", help="ME attributes semantic extension dir")

    # --- Sub-command: mibdb-diff (diff) ---
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

    # --- Sub-command: topology (graphic) ---
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

    # --- Sub-command: vlan-tbl ---
    vlan_p = subparsers.add_parser(
        "vlan-tbl",
        parents=[common_args],
        help="Analye OMCI VLAN tagging logic (Table-driven)",
    )
    vlan_p.add_argument(
        "--tpid-dei", action="store_true", help="Display TPID/DEI operation"
    )
    vlan_p.add_argument("pcap", help="Path to pcap file")

    # --- Sub-command: tcont-flow ---
    tcont_p = subparsers.add_parser(
        "tcont-flow",
        parents=[common_args],
        help="Trace T-CONT -> GEM -> PQ traffic hierarchy",
    )
    tcont_p.add_argument("pcap", help="Path to pcap file")

    # --- Sub-command: overview-json ---
    overview_p = subparsers.add_parser(
        "overview-json",
        parents=[common_args],
        help="Dump overview.json (Combines all sub-command JSON outputs)",
    )
    overview_p.add_argument("pcap", help="Path to pcap file")
    overview_p.add_argument("--mib-json", help="Custom ME JSON definition")
    overview_p.add_argument(
        "--semantic-dir", help="ME attributes semantic extension dir"
    )

    args = parser.parse_args()

    commands_need_pcap = [
        "check",
        "mibdb",
        "vlan-tbl",
        "tcont-flow",
        "topology",
        "graphic",
        "overview-json",
    ]
    if args.command in commands_need_pcap:
        if not hasattr(args, "pcap") or not args.pcap or not os.path.exists(args.pcap):
            print(f"[!] Error: PCAP file not found: {getattr(args, 'pcap', 'N/A')}")
            return

    if args.command == "check":
        run_omcicheck(
            args.pcap,
            args.only_vendor,
            args.only_failed,
            args.rtt_threshold,
            json_output=args.json_output,
            md_output=args.md,
        )
    elif args.command == "mibdb":
        if not args_load_json_semantic(args):
            return
        run_mibdb(
            args.pcap,
            args.only_upload,
            args.only_vendor,
            args.class_id,
            json_output=args.json_output,
            md_output=args.md,
        )
    elif args.command in ["mibdb-diff", "diff"]:
        if not os.path.exists(args.pcap1):
            print(f"[!] Error: PCAP file not found: {args.pcap1}")
            return
        if not os.path.exists(args.pcap2):
            print(f"[!] Error: PCAP file not found: {args.pcap2}")
            return
        if not args_load_json_semantic(args):
            return
        run_omcidiff(
            args.pcap1,
            args.pcap2,
            args.full,
            args.class_id,
            json_output=args.json_output,
            md_output=args.md,
        )
    elif args.command in ["topology", "graphic"]:
        run_omcitopo(
            args.pcap,
            args.output_html,
            json_output=args.json_output,
            md_output=args.md,
        )
    elif args.command == "vlan-tbl":
        run_omcivlan(
            args.pcap,
            args.tpid_dei,
            json_output=args.json_output,
            md_output=args.md,
        )
    elif args.command == "tcont-flow":
        run_tcont_flow(
            args.pcap,
            json_output=args.json_output,
            md_output=args.md,
        )
    elif args.command == "overview-json":
        if not args_load_json_semantic(args):
            return
        run_overview_json(args.pcap)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
