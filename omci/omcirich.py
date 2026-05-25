#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text
from rich.tree import Tree


def render_mibdb_table(mib_data):
    """
    Renders a professional CLI table for the MIB database using the rich library.

    This function visualizes the Semantic IR of the MIB, providing clear
    delineation between instances while displaying decoded attribute values.
    """
    console = Console()
    if not mib_data:
        console.print("[yellow]No MIB entries found with current filters.[/]")
        return

    table = Table(
        title="OMCI MIB Database Snapshot",
        box=box.HORIZONTALS,
        show_lines=True,
        header_style="bold magenta",
    )
    table.add_column("Class ID", justify="right", style="cyan")
    table.add_column("ME Name", style="green")
    table.add_column("Inst ID", justify="right", style="blue")
    table.add_column("Attributes (Semantic View)", style="white", overflow="fold")

    for cid in sorted(mib_data.keys()):
        me_info = mib_data[cid]
        for iid in sorted(me_info["instances"].keys()):
            attrs = me_info["instances"][iid]
            attr_display = "\n".join(
                [f"[dim]{k}[/]: {v['text']}" for k, v in attrs.items()]
            )

            table.add_row(str(cid), me_info["me_name"], str(iid), attr_display)

    console.print(table)


def render_check_table(check_result):
    """
    Renders the OMCI packet consistency check results in a formatted table.
    """

    pkts = check_result.get("packets", [])
    summary = check_result.get("summary", {})

    if len(pkts) == 0:
        print("No Vendor and failed packtes detected")
        return

    console = Console()
    table = Table(
        show_header=True,
        header_style="bold magenta",
        box=box.HORIZONTALS,
        padding=(0, 2),
        min_width=120,
        collapse_padding=True,
    )

    table.add_column("No.", style="cyan")
    table.add_column("ID", style="magenta")
    table.add_column("Action")
    table.add_column("ME Class")
    table.add_column("ME Instance")
    table.add_column("Result")
    table.add_column("RTT", justify="right")
    table.add_column("Status", style="red")
    table.add_column("ME desc", style="green")

    for pkt in check_result["packets"]:
        rtt_val = pkt.get("rtt")
        if rtt_val == 0.0:
            rtt_display = "0"
        else:
            rtt_display = f"{float(rtt_val):.6f}" if rtt_val is not None else "-"

        res = pkt.get("result", {})
        res_text = res.get("text", "")
        row_style = ""
        if "Err" in res_text or pkt.get("status"):
            row_style = "bold red"
        elif pkt.get("from_olt"):
            row_style = "cyan"
        table.add_row(
            str(pkt["packet_no"]),
            str(pkt["transaction_id"]),
            pkt["action"],
            str(pkt["me_class"]),
            f"0x{pkt['me_instance_id']:04x}",
            res_text,
            rtt_display,
            str(pkt["status"]),
            pkt["me_name"],
            style=row_style,
        )

    console.print(table)
    console.print(
        f"[bold]Summary:[/bold] Found [red]{summary['resp_fail_count']}[/red] failures, "
        f"{summary['onu_upload_vendor_me_count']} ONU Vendor packets, "
        f"{summary['olt_provision_vendor_me_count']} OLT Vendor packets, "
        f"{summary['transaction_id_duplicate_count']} duplicate packets, "
        f"{summary['resp_late_count']} late packets\n"
    )


def render_vlan_table(vlan_data_list):
    """
    Renders the OMCI VLAN Logic Analysis table (ME 171).
    - Decodes nested VLAN tagging operation rules.
    - Displays association pointers and downstream modes.
    """

    console = Console()
    if not vlan_data_list:
        console.print("[yellow]No VLAN (ME 171) instances found.[/]")
        return

    main_table = Table(
        title="[bold white]OMCI VLAN Logic Analyzer[/]",
        box=box.ROUNDED,
        header_style="bold magenta",
        show_lines=True,
        expand=True,
    )

    main_table.add_column("ME inst ID", justify="center", style="cyan", width=12)
    main_table.add_column("VLAN Rules (Sub-Table)", width=75)
    main_table.add_column("Association / Mode", justify="center", width=20)

    for vlan in vlan_data_list:
        # --- Sub-Table for VLAN rules ---
        sub_table = Table(box=box.SIMPLE, header_style="italic yellow", expand=True)
        sub_table.add_column("Idx", width=4, justify="center")
        sub_table.add_column("Action / Semantic", width=25)
        sub_table.add_column("Detailed Bit-Fields (Filter / Treatment / Tags Removed )")

        for idx, rule in enumerate(vlan["rules"]):
            d = rule["data"]
            bit_info = (
                f"[dim]F:[/] [cyan]O:{d['f_out_prio']}/{d['f_out_vid']} I:{d['f_in_prio']}/{d['f_in_vid']} E:{d['f_eth_type']}[/] "
                f"[dim]T:[/] [yellow]O:{d['t_out_prio']}/{d['t_out_vid']} I:{d['t_in_prio']}/{d['t_in_vid']}[/] "
                f"[magenta]R:{d['t_tags_rem']}[/]"
            )

            sub_table.add_row(
                Text(str(idx), style="bold red"),
                Text(rule["action_type"], style="bold green"),
                bit_info,
            )

        main_table.add_row(
            str(vlan["inst_id"]),
            sub_table,
            f"{vlan['assoc_type']}\n{vlan['assoc_ptr']}\n[dim]Mode: {vlan['ds_mode']}[/]",
        )

    console.print(main_table)


def render_tcont_flow_tree(flow_data):
    """
    Renders the GPON T-CONT -> GEM -> PQ hierarchy using a Rich Tree.
    This replaces the old direct-to-console logic.
    """
    console = Console()
    if not flow_data:
        console.print("[red]No T-CONT flow data found to render.[/red]")
        return

    # Create the root of the tree
    flow_tree = Tree("[bold cyan]GPON T-CONT Flow Analysis[/bold cyan]")

    for tcont in flow_data:
        # Handle unassigned Alloc-ID (which we set to None in get_tcont_flow_data)
        alloc_id = tcont.get("alloc_id")
        alloc_str = (
            f"alloc-id={alloc_id}" if alloc_id is not None else "[dim]Unassigned[/dim]"
        )

        # Add T-CONT node
        t_node = flow_tree.add(
            f"[bold magenta]T-CONT {tcont['tcont_id']}[/bold magenta] ({alloc_str})"
        )

        for gem in tcont.get("gem_ports", []):
            # Add GEM node
            gem_id = gem.get("gem_port_id", "N/A")
            gem_node = t_node.add(f"[bold yellow]GEM {gem_id}[/bold yellow]")

            # Add Upstream (US) details
            us = gem.get("upstream", {})
            gem_node.add(
                f"[bold cyan][US][/bold cyan] PQ {us.get('pq_ptr')} → up:{us.get('bandwidth')}"
            )

            # Add Downstream (DS) details
            ds = gem.get("downstream", {})
            prio = ds.get("priority")
            prio_str = f"Priority {prio}" if prio is not None else "Priority Unknown"
            gem_node.add(
                f"[bold green][DS][/bold green] PQ {ds.get('pq_ptr')} → {prio_str} dn:{ds.get('bandwidth')}"
            )

    console.print(flow_tree)


def render_diff_table(diff_result, pcap1_name="Pcap 1", pcap2_name="Pcap 2"):
    """
    Renders a visual comparison table of two MIB databases using Rich.

    This function processes the diff results and displays changes (modified,
    added, removed) and mask mismatches in a formatted CLI table with
    semantic color coding.

    Args:
        diff_result (dict): The dictionary containing diff data and summary
            statistics, typically generated by get_mib_diff_data().
        pcap1_name (str): Label for the baseline PCAP column.
        pcap2_name (str): Label for the target PCAP column.
    """

    console = Console()
    table = Table(
        show_header=True,
        header_style="bold magenta",
        box=box.HORIZONTALS,
        padding=(0, 2),
        min_width=120,
        collapse_padding=True,
    )

    table.add_column("Status", width=10)
    table.add_column("ME Name (ID)", style="cyan")
    table.add_column("Inst", justify="right", style="dim")
    table.add_column("Attribute", style="yellow")
    table.add_column(f"{pcap1_name}", justify="left", overflow="fold")
    table.add_column(f"{pcap2_name}", justify="left", overflow="fold")

    for change in diff_result.get("changes", []):
        status = change.get("status")
        me_name = change.get("me_name", "Unknown")
        class_id = change.get("class_id")
        inst_id = change.get("inst_id")
        attr_name = change.get("attr_name", "-")
        old_val = str(change.get("old", ""))
        new_val = str(change.get("new", ""))

        me_display = f"{me_name} ({class_id})"
        inst_display = hex(inst_id) if isinstance(inst_id, int) else str(inst_id)

        if status == "modified":
            table.add_row(
                "[yellow]MODIFIED[/]",
                me_display,
                inst_display,
                attr_name,
                old_val,
                f"[bold green]{new_val}[/]",
            )
        elif status == "added":
            table.add_row(
                "[green]+ NEW[/]",
                f"[green]{me_display}[/]",
                inst_display,
                "",
                "",
                "",
            )
        elif status == "removed":
            table.add_row(
                "[red]- REMOVED[/]",
                f"[red]{me_display}[/]",
                inst_display,
                "",
                "",
                "",
            )

    unknowns = diff_result.get("unknown_me_mask_mismatch", [])
    for u in unknowns:
        class_id = u.get("class_id")
        inst_id = u.get("inst_id")
        me_display = f"Unknown ({class_id})"
        inst_display = hex(inst_id) if isinstance(inst_id, int) else str(inst_id)
        table.add_row(
            "[red]MISMATCH[/]",
            f"[red]{me_display}[/]",
            inst_display,
            "",
            "",
            "",
        )

    summary = diff_result.get("summary", {})
    console.print(table)
    console.print(
        f"[bold]Summary:[/] [green]Added: {summary.get('added_count')}[/], "
        f"[red]Removed: {summary.get('removed_count')}[/], "
        f"[yellow]Modified: {summary.get('modified_count')}[/]"
    )

    mismatch = summary.get("unknown_me_mask_mismatch_count", 0)
    if mismatch > 0:
        console.print(f"[bold red]!!! Unknown ME Mask Mismatch detected: {mismatch}[/]")
