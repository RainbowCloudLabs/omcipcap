import json
import sys
import argparse
from omci import omciparser


def generate_pcap_ai_overview(pcap_path):
    mib_data = omciparser.get_mib_db_data(pcap_path)
    check_result = omciparser.get_check_results(pcap_path)
    mib_db = omciparser.get_all_mib_db(pcap_path)
    vlan_data = omciparser.get_vlan_data(mib_db)
    tcont_flow = omciparser.get_flow_data(mib_db)
    topo_data = omciparser.get_topology_data(pcap_path)
    overview = {
        "check_summary": check_result,
        "mib_database": mib_data,
        "vlan_operation_data": vlan_data,
        "tcont_flows_data": tcont_flow,
        "topology_data": topo_data,
    }

    output_file = "overview.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(overview, f)
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

    generate_pcap_ai_overview(args.pcap_path)
