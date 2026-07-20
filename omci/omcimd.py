#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

"""
Markdown renderers for omcipcap CLI outputs.

Rules:
- Return markdown strings only. Do not print here.
- Follow actual parser output schema from omciparser.py.
- Prefer deterministic, git-friendly markdown.
"""


def _s(value):
    if value is None:
        return ""
    return str(value)


def _escape_md(value):
    text = _s(value)
    text = text.replace("|", "\\|")
    text = text.replace("\n", "<br>")
    return text


def _format_float(value, digits=6):
    if value is None or value == "":
        return ""
    try:
        return f"{float(value):.{digits}f}"
    except (ValueError, TypeError):
        return _s(value)


def render_markdown_table(headers, rows):
    if not headers:
        return ""

    lines = []
    lines.append("| " + " | ".join(_escape_md(h) for h in headers) + " |")
    lines.append("| " + " | ".join("---" for _ in headers) + " |")

    for row in rows:
        row = list(row)
        if len(row) < len(headers):
            row.extend([""] * (len(headers) - len(row)))
        row = row[: len(headers)]
        lines.append("| " + " | ".join(_escape_md(v) for v in row) + " |")

    return "\n".join(lines)


def render_section(title, body):
    body = body.strip()
    if not body:
        return f"## {title}\n"
    return f"## {title}\n\n{body}\n"


def render_code_block(text, lang="text"):
    return f"```{lang}\n{text.rstrip()}\n```"


def render_check_md(check_result):
    """
    Schema from omciparser.get_check_results():

    {
      "packets": [
        {
          "packet_no": int,
          "transaction_id": int,
          "action": str,
          "me_class": int,
          "me_instance_id": int,
          "me_name": str,
          "result": {
            "code": int,
            "success": bool,
            "text": str,
          },
          "rtt": float,
          "status": str,
          "from_olt": bool,
        },
        ...
      ],
      "summary": {
        "resp_fail_count": int,
        "onu_upload_vendor_me_count": int,
        "olt_provision_vendor_me_count": int,
        "resp_late_count": int,
        "transaction_id_duplicate_count": int,
      }
    }
    """
    summary = check_result.get("summary", {})
    packets = check_result.get("packets", [])

    parts = []

    summary_rows = [
        ["Response Fail Count", summary.get("resp_fail_count", 0)],
        ["ONU Upload Vendor ME Count", summary.get("onu_upload_vendor_me_count", 0)],
        [
            "OLT Provision Vendor ME Count",
            summary.get("olt_provision_vendor_me_count", 0),
        ],
        ["Response Late Count", summary.get("resp_late_count", 0)],
        [
            "Transaction ID Duplicate Count",
            summary.get("transaction_id_duplicate_count", 0),
        ],
    ]
    parts.append(
        render_section(
            "OMCI Check Statistics",
            render_markdown_table(["Metric", "Value"], summary_rows),
        )
    )

    if packets:
        detail_rows = []
        for pkt in packets:
            result = pkt.get("result") or {}
            detail_rows.append(
                [
                    pkt.get("packet_no", ""),
                    pkt.get("transaction_id", ""),
                    pkt.get("action", ""),
                    pkt.get("me_class", ""),
                    pkt.get("me_instance_id", ""),
                    result.get("text", ""),
                    _format_float(pkt.get("rtt", "")),
                    pkt.get("status", ""),
                    pkt.get("me_name", ""),
                    "OLT" if pkt.get("from_olt") else "ONU",
                ]
            )

        parts.append(
            render_section(
                "OMCI Check Details",
                render_markdown_table(
                    [
                        "No.",
                        "TID",
                        "Action",
                        "ME Class",
                        "ME Instance",
                        "Result",
                        "RTT",
                        "Status",
                        "ME Name",
                        "From",
                    ],
                    detail_rows,
                ),
            )
        )

    return "\n".join(parts).rstrip() + "\n"


def render_vlan_md(vlan_data):
    """
    Schema from omciparser.get_vlan_data():

    [
      {
        "inst_id": int,
        "rules": [
          {
            "action_type": ...,
            "tpid_dei_operation": ...,
            "data": ...
          },
          ...
        ],
        "assoc_ptr": ...,
        "assoc_type": str,
        "ds_mode": str,
      },
      ...
    ]
    """
    if not vlan_data:
        return render_section("VLAN Operation Summary", "_No VLAN tagging data found._")

    parts = []

    summary_rows = []
    for item in vlan_data:
        summary_rows.append(
            [
                item.get("inst_id", ""),
                item.get("assoc_type", ""),
                item.get("assoc_ptr", ""),
                item.get("ds_mode", ""),
                len(item.get("rules", []) or []),
            ]
        )

    parts.append(
        render_section(
            "VLAN Operation Summary",
            render_markdown_table(
                [
                    "ME Inst ID",
                    "Association Type",
                    "Association Ptr",
                    "Mode",
                    "Rule Count",
                ],
                summary_rows,
            ),
        )
    )

    for item in vlan_data:
        inst_id = item.get("inst_id", "")
        rules = item.get("rules", []) or []

        rule_rows = []
        for idx, rule in enumerate(rules):
            rule_rows.append(
                [
                    idx,
                    rule.get("action_type", ""),
                    rule.get("tpid_dei_operation", ""),
                    rule.get("data", ""),
                ]
            )

        if rule_rows:
            parts.append(
                render_section(
                    f"VLAN Rules for ME Inst ID {inst_id}",
                    render_markdown_table(
                        ["Idx", "Action Type", "TPID/DEI Operation", "Data"],
                        rule_rows,
                    ),
                )
            )
        else:
            parts.append(
                render_section(
                    f"VLAN Rules for ME Inst ID {inst_id}",
                    "_No rules found._",
                )
            )

    return "\n".join(parts).rstrip() + "\n"


def render_diff_md(diff_data):
    """
    Schema from omciparser.get_mib_diff_data():

    {
      "changes": [
        {
          "status": "removed"|"added"|"modified",
          "me_name": str,
          "class_id": int,
          "inst_id": int,
          # for modified only:
          "attr_name": str,
          "old": ...,
          "new": ...
        }
      ],
      "unknown_me_mask_mismatch": [
        {
          "class_id": int,
          "inst_id": int,
        }
      ],
      "summary": {
        "modified_count": int,
        "removed_count": int,
        "added_count": int,
        "unknown_me_mask_mismatch_count": int,
      }
    }
    """
    summary = diff_data.get("summary", {})
    changes = diff_data.get("changes", [])
    mismatches = diff_data.get("unknown_me_mask_mismatch", [])

    parts = []

    summary_rows = [
        ["Added Count", summary.get("added_count", 0)],
        ["Removed Count", summary.get("removed_count", 0)],
        ["Modified Count", summary.get("modified_count", 0)],
        [
            "Unknown ME Mask Mismatch Count",
            summary.get("unknown_me_mask_mismatch_count", 0),
        ],
    ]
    parts.append(
        render_section(
            "MIB Diff Statistics",
            render_markdown_table(["Metric", "Value"], summary_rows),
        )
    )

    if changes:
        rows = []
        for item in changes:
            rows.append(
                [
                    item.get("status", ""),
                    item.get("me_name", ""),
                    item.get("class_id", ""),
                    item.get("inst_id", ""),
                    item.get("attr_name", ""),
                    item.get("old", ""),
                    item.get("new", ""),
                ]
            )

        parts.append(
            render_section(
                "MIB Diff Changes",
                render_markdown_table(
                    [
                        "Status",
                        "ME Name",
                        "Class ID",
                        "Inst ID",
                        "Attribute",
                        "Old",
                        "New",
                    ],
                    rows,
                ),
            )
        )

    if mismatches:
        rows = []
        for item in mismatches:
            rows.append([item.get("class_id", ""), item.get("inst_id", "")])

        parts.append(
            render_section(
                "Unknown ME Mask Mismatches",
                render_markdown_table(["Class ID", "Inst ID"], rows),
            )
        )

    return "\n".join(parts).rstrip() + "\n"


def render_mibdb_md(mib_data):
    """
    Schema from omciparser.get_mib_db_data():

    {
      class_id: {
        "me_name": str,
        "instances": {
          inst_id: {
            attr_name: {
              "val": ...,
              "text": ...
            }
          }
        }
      }
    }
    """
    if not mib_data:
        return render_section("MIB Database", "_No MIB data found._")

    parts = []

    summary_rows = []
    for cid in sorted(mib_data.keys(), key=lambda x: int(x)):
        item = mib_data[cid]
        instances = item.get("instances", {})
        summary_rows.append([cid, item.get("me_name", ""), len(instances)])

    parts.append(
        render_section(
            "MIB Class Summary",
            render_markdown_table(
                ["Class ID", "ME Name", "Instance Count"],
                summary_rows,
            ),
        )
    )

    for cid in sorted(mib_data.keys(), key=lambda x: int(x)):
        item = mib_data[cid]
        me_name = item.get("me_name", "")
        instances = item.get("instances", {})

        parts.append(f"## Class {cid} - {me_name}\n")

        for inst_id in sorted(instances.keys(), key=lambda x: int(x)):
            attrs = instances[inst_id]
            attr_rows = []
            for attr_name, attr_val in attrs.items():
                if isinstance(attr_val, dict):
                    attr_rows.append(
                        [
                            attr_name,
                            attr_val.get("val", ""),
                            attr_val.get("text", ""),
                        ]
                    )
                else:
                    attr_rows.append([attr_name, "", attr_val])

            parts.append(f"### Instance {inst_id}\n")
            parts.append(
                render_markdown_table(
                    ["Attribute", "Raw Value", "Semantic Text"],
                    attr_rows,
                )
            )
            parts.append("")

    return "\n".join(parts).rstrip() + "\n"


def render_tcont_flow_md(flow_data):
    """
    Schema from omciflow.get_tcont_flow_data():

    [
      {
        "tcont_id": int,
        "alloc_id": int | None,
        "gem_ports": [
          {
            "gem_port_id": int | str,
            "upstream": {
              "pq_ptr": int,
              "bandwidth": str,
            },
            "downstream": {
              "pq_ptr": int,
              "priority": int | None,
              "bandwidth": str,
            },
          },
          ...
        ],
      },
      ...
    ]
    """
    if not flow_data:
        return render_section(
            "T-CONT / GEM Flow Summary", "_No T-CONT flow data found._"
        )

    parts = []

    total_tcont = len(flow_data)
    total_gem = sum(len(tcont.get("gem_ports", []) or []) for tcont in flow_data)
    bound_tcont = sum(1 for tcont in flow_data if tcont.get("alloc_id") is not None)
    empty_tcont = sum(
        1 for tcont in flow_data if not (tcont.get("gem_ports", []) or [])
    )

    parts.append(
        render_section(
            "T-CONT Flow Statistics",
            render_markdown_table(
                ["Metric", "Value"],
                [
                    ["Total T-CONTs", total_tcont],
                    ["Bound T-CONTs", bound_tcont],
                    ["Empty T-CONTs", empty_tcont],
                    ["Total GEM Ports", total_gem],
                ],
            ),
        )
    )

    summary_rows = []
    for tcont in flow_data:
        tcont_id = tcont.get("tcont_id", "")
        alloc_id = tcont.get("alloc_id", "")
        gem_ports = tcont.get("gem_ports", []) or []

        if not gem_ports:
            summary_rows.append(
                [
                    tcont_id,
                    alloc_id if alloc_id is not None else "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                ]
            )
            continue

        for gem in gem_ports:
            upstream = gem.get("upstream", {}) or {}
            downstream = gem.get("downstream", {}) or {}

            summary_rows.append(
                [
                    tcont_id,
                    alloc_id if alloc_id is not None else "",
                    gem.get("gem_port_id", ""),
                    upstream.get("pq_ptr", ""),
                    upstream.get("bandwidth", ""),
                    downstream.get("pq_ptr", ""),
                    downstream.get("priority", ""),
                    downstream.get("bandwidth", ""),
                ]
            )

    parts.append(
        render_section(
            "T-CONT / GEM Flow Summary",
            render_markdown_table(
                [
                    "T-CONT ID",
                    "Alloc-ID",
                    "GEM Port ID",
                    "US PQ Ptr",
                    "US Bandwidth",
                    "DS PQ Ptr",
                    "DS Priority",
                    "DS Bandwidth",
                ],
                summary_rows,
            ),
        )
    )

    tree_lines = []
    for tcont in flow_data:
        tcont_id = tcont.get("tcont_id", "")
        alloc_id = tcont.get("alloc_id", None)
        gem_ports = tcont.get("gem_ports", []) or []

        alloc_text = "Unassigned" if alloc_id is None else alloc_id
        tree_lines.append(f"- T-CONT {tcont_id} (Alloc-ID: {alloc_text})")

        if not gem_ports:
            tree_lines.append("  - No GEM ports")
            continue

        for gem in gem_ports:
            gem_port_id = gem.get("gem_port_id", "")
            upstream = gem.get("upstream", {}) or {}
            downstream = gem.get("downstream", {}) or {}

            tree_lines.append(f"  - GEM {gem_port_id}")
            tree_lines.append(
                "    - Upstream: "
                f"pq_ptr={upstream.get('pq_ptr', '')}, "
                f"bandwidth={upstream.get('bandwidth', '')}"
            )
            tree_lines.append(
                "    - Downstream: "
                f"pq_ptr={downstream.get('pq_ptr', '')}, "
                f"priority={downstream.get('priority', '')}, "
                f"bandwidth={downstream.get('bandwidth', '')}"
            )

    parts.append(render_section("T-CONT / GEM Flow Tree", "\n".join(tree_lines)))

    return "\n".join(parts).rstrip() + "\n"
