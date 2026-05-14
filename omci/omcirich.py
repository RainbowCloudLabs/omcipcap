#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

from rich.console import Console
from rich.table import Table
from rich import box


def render_check_table(check_result):

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
        f"{summary['is_vendor_me_count']} Vendor packets, "
        f"{summary['transaction_id_duplicate_count']} duplicate packets, "
        f"{summary['resp_late_count']} late packets\n"
    )
