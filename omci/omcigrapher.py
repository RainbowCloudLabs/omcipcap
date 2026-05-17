#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong Yuan, Shih daneshih1125@gmail.com
# Licensed under the MIT License.

import json
from omci.omcimib import OMCIClass
from omci.omcisemantic import ME_171_ASSOCIATION_TYPE, ME_47_TP_TYPE

INTERESTED_CLASSES = {
    OMCIClass.PPTP_ETHERNET_UNI,  # 11
    OMCIClass.VIRTUAL_ETHERNET_INTERFACE_POINT,  # 329
    OMCIClass.IP_HOST_CONFIG_DATA,  # 134
    OMCIClass.MAC_BRIDGE_SERVICE_PROFILE,  # 45
    OMCIClass.MAC_BRIDGE_CONFIGURATION_DATA,  # 46
    OMCIClass.MAC_BRIDGE_PORT_CONFIGURATION_DATA,  # 47
    OMCIClass.VLAN_TAGGING_FILTER_DATA,  # 84
    OMCIClass.DOT1P_MAPPER_SERVICE_PROFILE,  # 130
    OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA,  # 171
    OMCIClass.T_CONT,  # 262
    OMCIClass.GEM_INTERWORKING_TERMINATION_POINT,  # 266
    OMCIClass.GEM_PORT_NETWORK_CTP,  # 268
    OMCIClass.MULTICAST_GEM_INTERWORKING_TERMINATION_POINT,  # 281
}


def generate_tooltip(cid, iid, attrs):
    if not attrs:
        return f"ME {cid} ({iid})"

    lines = []

    for k, v in attrs.items():
        val_str = str(v)
        if cid == 47 and k == "TP type" and isinstance(v, int):
            val_str = f"{v} ({ME_47_TP_TYPE.get(v, 'Unknown')})"
        elif cid == 171 and k == "Association type" and isinstance(v, int):
            val_str = f"{v} ({ME_171_ASSOCIATION_TYPE.get(v, 'Unknown')})"

        lines.append(f"{k}: {val_str}\n")
    return "".join(lines)


def get_vis_elements(mib_db):
    nodes = []
    edges = []
    added_nodes = set()

    LEVEL_MAP = {
        11: 0,  # PPTP
        329: 0,  # VEIP
        134: 0,  # IP HOST
        171: 1,  # Extended VLAN
        47: 2,  # Bridge Port
        84: 1,  # VLAN Filter
        45: 3,  # Bridge Service
        46: 3,  # Bridge Config
        130: 3,  # 802.1p Mapper
        266: 4,  # GEM IWTP
        281: 4,  # Multicast GEM IWTP
        268: 5,  # GEM Port
        262: 6,  # T-CONT
    }

    def add_node(cid, iid):
        node_id = f"{cid}_{iid}"
        if node_id not in added_nodes and cid in INTERESTED_CLASSES:
            raw_name = OMCIClass(cid).name
            clean_name = (
                raw_name.replace("_CONFIGURATION_DATA", "")
                .replace("_SERVICE_PROFILE", "")
                .replace("_DATA", "")
            )

            attrs = inst.attributes if inst else {}
            tooltip_html = generate_tooltip(cid, iid, attrs)

            is_onu_created = cid in [11, 134, 329, 262]
            node_level = LEVEL_MAP.get(cid, 3)
            nodes.append(
                {
                    "id": node_id,
                    "label": f"{clean_name} ({cid})\n({iid})",
                    "title": tooltip_html,
                    "shape": "box",
                    "margin": 10,
                    "level": node_level,
                    "shapeProperties": {"borderRadius": 0 if is_onu_created else 8},
                    "color": {
                        "background": "#C2FABC" if is_onu_created else "#97C2FC",
                        "border": "#2B7CE9",
                    },
                    "font": {"multi": True, "size": 14},
                    "group": str(cid),
                }
            )
            added_nodes.add(node_id)
        return node_id

    for (cid, iid), inst in mib_db.items():
        if cid not in INTERESTED_CLASSES:
            continue

        attrs = inst.attributes
        # skip unused T-CONT ID
        if cid == OMCIClass.T_CONT:
            alloc_id = attrs.get("Alloc-ID")
            if alloc_id is None or alloc_id == 0xFFFF or alloc_id == 65535:
                continue
        u_id = add_node(cid, iid)

        if cid == OMCIClass.VLAN_TAGGING_FILTER_DATA:
            if (47, iid) in mib_db:
                edges.append(
                    {
                        "from": u_id,
                        "to": f"47_{iid}",
                        "label": "Filter-on",
                        "arrows": "to",
                        "dashes": True,
                    }
                )

        elif cid == OMCIClass.MAC_BRIDGE_PORT_CONFIGURATION_DATA:
            # Bridge Pointer
            b_ptr = attrs.get("Bridge id pointer")
            if b_ptr is not None:
                edges.append(
                    {
                        "from": u_id,
                        "to": add_node(45, b_ptr),
                        "label": "bridge_ptr",
                        "arrows": "to",
                    }
                )
            # TP Pointer
            tp_ptr = attrs.get("TP pointer")
            if tp_ptr is not None:
                for t_cid in [11, 130, 134, 329, 281]:
                    if (t_cid, tp_ptr) in mib_db:
                        edges.append(
                            {
                                "from": u_id,
                                "to": add_node(t_cid, tp_ptr),
                                "label": "tp_ptr",
                                "arrows": "to",
                            }
                        )

        elif cid == OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA:
            a_ptr = attrs.get("Associated ME pointer")
            if a_ptr:
                for t_cid in [47, 11, 329, 130, 134]:
                    if (t_cid, a_ptr) in mib_db:
                        edges.append(
                            {
                                "from": u_id,
                                "to": add_node(t_cid, a_ptr),
                                "label": "assoc_ptr",
                                "arrows": "to",
                            }
                        )

        elif cid == OMCIClass.GEM_INTERWORKING_TERMINATION_POINT:
            iw_ptr = attrs.get("Interworking TP pointer")
            if iw_ptr:
                edges.append(
                    {
                        "from": u_id,
                        "to": add_node(47, iw_ptr),
                        "label": "iw_tp",
                        "arrows": "to",
                    }
                )
            gem_ptr = attrs.get("GEM port network CTP pointer")
            if gem_ptr:
                edges.append(
                    {
                        "from": u_id,
                        "to": add_node(268, gem_ptr),
                        "label": "gem_ptr",
                        "arrows": "to",
                    }
                )
            iw_option = attrs.get("Interworking option")
            srv_ptr = attrs.get("Service profile pointer")
            if iw_option == 1:
                edges.append(
                    {
                        "from": u_id,
                        "to": add_node(45, srv_ptr),
                        "label": "srv_ptr",
                        "arrows": "to",
                    }
                )
            elif iw_option == 5:
                edges.append(
                    {
                        "from": u_id,
                        "to": add_node(130, srv_ptr),
                        "label": "srv_ptr",
                        "arrows": "to",
                    }
                )

        elif cid == OMCIClass.GEM_PORT_NETWORK_CTP:
            t_ptr = attrs.get("T-CONT pointer")
            if t_ptr:
                edges.append(
                    {
                        "from": u_id,
                        "to": add_node(262, t_ptr),
                        "label": "tcont_ptr",
                        "arrows": "to",
                    }
                )

    return nodes, edges


def export_to_html(mib_db):
    nodes, edges = get_vis_elements(mib_db)
    template = """
<!DOCTYPE html>
<head>
    <meta charset="UTF-8">
    <title>OMCI Graph - MAC Bridged Topology</title>
    <script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.2/standalone/umd/vis-network.min.js"></script>
    <style type="text/css">
        body { font-family: "Microsoft JhengHei", Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f7fa; }
        #omci-network {
            width: 100%;
            height: calc(100vh - 120px);
            border: 1px solid #d3d3d3;
            background-color: #ffffff;
            border-radius: 8px;
        }
        .legend { margin-top: 15px; display: flex; gap: 20px; font-size: 14px; }
        .box-sample { width: 16px; height: 16px; display: inline-block; vertical-align: middle; border: 1px solid #666; }
    </style>
</head>
<body>
    <h2>OMCI Logical Topology</h2>
    <div class="legend">
        <div><span class="box-sample" style="border-radius: 0px; background: #C2FABC;"></span> <b>ONU Created:</b></div>
        <div><span class="box-sample" style="border-radius: 6px; background: #97C2FC;"></span> <b>OLT Created:</b></div>
    </div>
    <div id="omci-network"></div>

    <script type="text/javascript">
        var container = document.getElementById('omci-network');
        var nodes = new vis.DataSet(__NODES__);
        var edges = new vis.DataSet(__EDGES__);
        var data = { nodes: nodes, edges: edges };
        var options = {
            layout: {
                hierarchical: {
                    enabled: true,
                    direction: 'DU',
                    sortMethod: 'defined',
                    levelSeparation: 150,
                    nodeSpacing: 150,
                    treeSpacing: 200,
                    edgeMinimization: true,
                    parentCentralization: true
                }
            },
            physics: {
                enabled: false,
                solver: 'forceAtlas2Based',
                forceAtlas2Based: {
                    gravitationalConstant: -100,
                    centralGravity: 0.01,
                    springLength: 150,
                    avoidOverlap: 1
                },
                stabilization: { iterations: 150 }
            },
            nodes: {
                margin: 15,
                widthConstraint: { minimum: 300, maximum: 450 },
                font: {
                    size: 32,
                    multi: true,
                    face: 'monospace',
                    bold: { color: '#000', size: 34 }
                },
                shadow: { enabled: true, size: 10 }
            },
            edges: {
                width: 3,
                smooth: {
                    enabled: true,
                    type: 'cubicBezier',
                    forceDirection: 'vertical',
                    roundness: 0.5
                },
                arrows: { to: { enabled: true, scaleFactor: 1.5 } }
            },
            interaction: {
                hover: true,
                navigationButtons: true
            }
        };
        var network = new vis.Network(container, data, options);
        network.once("stabilizationIterationsDone", function() {
            network.moveTo({
                position: {x: 0, y: 0},
                scale: 1.2,
                animation: false
            });
        });
    </script>
</body>
</html>
"""
    return template.replace("__NODES__", json.dumps(nodes)).replace(
        "__EDGES__", json.dumps(edges)
    )


# vim: set ts=4 sw=4 et:
