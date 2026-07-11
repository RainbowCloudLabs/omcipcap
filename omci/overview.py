#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.
import json
import sys
import argparse
from omci import omciparser
from omci.omci import load_omci_packets
from omci.omcimib import OMCIClass


def get_onu_capability(mib_db):
    tcont_db = omciparser.get_instances_by_class(mib_db, OMCIClass.T_CONT)
    tcont_count = len(tcont_db)
    pq_db = omciparser.get_instances_by_class(mib_db, OMCIClass.PRIORITY_QUEUE_G)
    pq_count = len(pq_db)
    pppt_db = omciparser.get_instances_by_class(mib_db, OMCIClass.PPTP_ETHERNET_UNI)
    pptp_count = len(pppt_db)
    pots_db = omciparser.get_instances_by_class(mib_db, OMCIClass.PPTP_POTS_UNI)
    pots_count = len(pots_db)
    card_db = omciparser.get_instances_by_class(mib_db, OMCIClass.CARDHOLDER)

    pon_type = "PON"
    for card in card_db:
        type_int = card.attributes.get("Actual Plug-in Unit Type", 0)
        if type_int == 248:
            pon_type = "GPON"
            break
        elif type_int == 237:
            pon_type = "XG-PON (Asymmetric)"
            break
        elif type_int == 238:
            pon_type = "XG-PON (Symmetric 10G/10G)"
            break
        elif type_int == 235:
            pon_type = "XGS-PON"
            break
        elif type_int == 230:
            pon_type = "Multi-PON"
            break

    return {
        "pon_type": pon_type,
        "pptp_count": pptp_count,
        "pots_count": pots_count,
        "tcont_count": tcont_count,
        "priority_queue_count": pq_count,
    }


def generate_pcap_ai_overview_data(pcap_path):
    omci_pkts = load_omci_packets(pcap_path, include_raw=True)
    mib_data = omciparser.get_mib_db_data(omci_pkts)
    check_result = omciparser.get_check_results(omci_pkts)
    topo_data = omciparser.get_topology_data(omci_pkts)
    mib_db = omciparser.get_all_mib_db(omci_pkts)
    vlan_data = omciparser.get_vlan_data(mib_db)
    tcont_flow = omciparser.get_flow_data(mib_db)
    overview_data = {
        "check_summary": check_result,
        "mib_database": mib_data,
        "vlan_operation_data": vlan_data,
        "tcont_flows_data": tcont_flow,
        "topology_data": topo_data,
        "onu_capability": get_onu_capability(mib_db),
    }
    return overview_data


def generate_pcap_ai_overview_json(pcap_path):

    overview_data = generate_pcap_ai_overview_data(pcap_path)
    output_file = "overview.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(overview_data, f)
    print(f"[+] Success! dumped to '{output_file}'\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OMCI Sub-Module: Overview Packer")
    parser.add_argument(
        "pcap_path", nargs="?", help="Path to the network capture pcap file"
    )

    args = parser.parse_args()
    if not args.pcap_path:
        parser.print_help()
        sys.exit(1)

    generate_pcap_ai_overview_json(args.pcap_path)
