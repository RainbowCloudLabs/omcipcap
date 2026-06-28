#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

from scapy.all import rdpcap
from omci import omcimib
from omci import omciflow
from omci import omcivlan
from omci.omci import OMCIBaseline, OMCIPacket, OmciAction, OmciResult
from omci.omcimib import OMCIClass
from omci.omcimib import SENSITIVE_ME_CLASSES, SENSITIVE_ME_ATTRIBUTES


def get_omci_pkts(pcap_path, include_raw=False):
    """
    Reads pcap and yields filtered OMCI Baseline packets.

    Args:
        pcap_path (str): Path to the pcap file.

    Yields:
        tuple: (packet_no, omci_pkt, raw_pkt)
    """
    try:
        raw_pkts = rdpcap(pcap_path)
    except Exception as e:
        print(f"Error reading pcap: {e}")
        return

    for i, raw_pkt in enumerate(raw_pkts):
        # Filter for OMCI EtherType (0x88B5)
        if not raw_pkt.haslayer("Ether") or raw_pkt.getlayer("Ether").type != 0x88B5:
            continue

        try:
            raw_data = bytes(raw_pkt.lastlayer())
            omci_pkt = OMCIPacket.from_raw(raw_data)

            if isinstance(omci_pkt, OMCIBaseline):
                yield i, omci_pkt, (raw_pkt if include_raw else None)

        except Exception:
            continue


def get_all_mib_db(pcap_path, only_vendor=False):
    """
    Parses a PCAP file to build a comprehensive MIB database representing the final state.

    This function processes both the initial 'MIB Upload' phase and subsequent
    'OLT Provisioning' (Create/Set actions) to capture dynamic changes in
    Managed Entities (MEs).

    Args:
        pcap_path (str): The file path to the PCAP containing OMCI traffic.
        only_vendor (bool): If True, only parses vendor-specific and future
            standardization MEs.

    Returns:
        dict: A dictionary mapping (class_id, inst_id) tuples to MIBInstance objects,
              reflecting the most up-to-date state of the ONU.
    """
    mib_db = {}  # {(class_id, inst_id): MIBInstance}

    for i, omci_pkt, _ in get_omci_pkts(pcap_path):
        if only_vendor and (
            (not omci_pkt.mib_upload_is_vendor and not omci_pkt.mib_upload_is_feature)
            and (not omci_pkt.is_vendor_me and not omci_pkt.is_feature_me)
        ):
            continue
        mib_entity = omci_pkt.mib_upload_entity
        if mib_entity:
            me_class = mib_entity["me_class"]
            me_inst = mib_entity["me_instance"]
            attr_mask = mib_entity["attr_mask"]
            attr_data = mib_entity["attr_data"]
            key = (me_class, me_inst)

            if key not in mib_db:
                mib_db[key] = omcimib.MIBInstance(me_class, me_inst)
            mib_db[key].update(attr_mask, attr_data)
            continue

        if not omci_pkt.is_request:
            continue

        me_class = omci_pkt.me_class
        me_inst = omci_pkt.inst_id
        key = (me_class, me_inst)
        if omci_pkt.action == OmciAction.CREATE:
            if key not in mib_db:
                mib_db[key] = omcimib.MIBInstance(me_class, me_inst)
            mib_db[key].update_from_create(omci_pkt.content)
        elif omci_pkt.action == OmciAction.SET:
            if key not in mib_db:
                mib_db[key] = omcimib.MIBInstance(me_class, me_inst)
            attr_mask = int.from_bytes(omci_pkt.content[:2], byteorder="big")
            attr_data = omci_pkt.content[2:]
            mib_db[key].update(attr_mask, attr_data)

    return mib_db


def get_mib_snapshot(pcap_path, only_vendor=False):
    """
    Captures a snapshot of the MIB database immediately after the MIB Upload phase.

    This function filters only for MIB Upload Next responses, effectively
    representing the ONU's initial configuration before any OLT provisioning
    actions (such as Create or Set) occur.

    Args:
        pcap_path (str): The file path to the PCAP containing OMCI traffic.
        only_vendor (bool): If True, only parses vendor-specific and future
            standardization MEs.

    Returns:
        dict: A dictionary mapping (class_id, inst_id) tuples to MIBInstance objects,
              representing the static initial MIB image.
    """
    snapshot = {}  # {(class_id, inst_id): MIBInstance}

    for i, omci_pkt, _ in get_omci_pkts(pcap_path):
        if (
            only_vendor
            and not omci_pkt.mib_upload_is_vendor
            and not omci_pkt.mib_upload_is_feature
        ):
            continue
        mib_entity = omci_pkt.mib_upload_entity
        if mib_entity:
            me_class = mib_entity["me_class"]
            me_inst = mib_entity["me_instance"]
            attr_mask = mib_entity["attr_mask"]
            attr_data = mib_entity["attr_data"]
            key = (me_class, me_inst)
            if key not in snapshot:
                snapshot[key] = omcimib.MIBInstance(me_class, me_inst)
            snapshot[key].update(attr_mask, attr_data)

    return snapshot


def get_mib_db_data(pcap_path, only_upload=False, only_vendor=False, class_ids=None):
    """
    Extracts and filters a structured Semantic IR of the MIB database from a PCAP.

    This function serves as the core data provider for the 'mibdb' command,
    transforming raw MIB entries into a clean, hierarchical dictionary
    suitable for JSON export or professional table rendering.

    Args:
        pcap_path (str): Path to the target Wireshark PCAP file.
        only_upload (bool): If True, only parses the MIB Upload sequence to
            represent the ONU's baseline state (Snapshot). If False,
            incorporates subsequent Set/Create operations to reflect
            the current live state.
        only_vendor (bool): If True, only parses vendor-specific and future
            standardization MEs
        class_ids (list[int], optional): A list of OMCI Class IDs to filter the
            output (e.g., [84, 171] for VLAN-related entities).
            Returns all classes if None.

    Returns:
        dict: A semantic representation of the MIB database.
            Format:
            {
                class_id: {
                    "me_name": str,
                    "instances": {
                        inst_id: { attribute_name: semantic_value, ... }
                    }
                }
            }
    """
    # Initialize the MIB database by parsing the PCAP
    if only_upload:
        # get_mib_snapshot focuses on the initial provisioning baseline
        mib_db = get_mib_snapshot(pcap_path, only_vendor)
    else:
        mib_db = get_all_mib_db(pcap_path, only_vendor)

    mib_data = {}
    # Iterate through the parsed MIB entries (Key is a tuple of (class_id, inst_id))
    for (cid, iid), inst in mib_db.items():
        # Apply Class ID filtering for Semantic Reduction
        if class_ids and cid not in class_ids:
            continue

        me_name = omcimib.get_me_name(cid)

        if cid not in mib_data:
            mib_data[cid] = {"me_name": me_name, "instances": {}}

        if inst.is_unknown:
            for vendor_data in inst.vendor_data:
                mask, raw_data = vendor_data
                vendor_attr = hex(mask)
                mib_data[cid]["instances"][iid] = {
                    vendor_attr: {"val": raw_data, "text": raw_data}
                }
            continue

        # Convert raw attribute values into semantic strings (e.g., Hex for integers)
        # This ensures the data is deterministic and ready for AI/JSON reasoning.
        attrs = {}
        is_sensitive_class = cid in SENSITIVE_ME_CLASSES
        for k, v in inst.attributes.items():
            k_lower = k.lower()
            is_sensitive_attr = any(
                keyword in k_lower for keyword in SENSITIVE_ME_ATTRIBUTES
            )
            if is_sensitive_class or is_sensitive_attr:
                attrs[k] = {"val": "*****", "text": "*****"}
            else:
                text = inst.attr_semantic(k)
                raw_val = f"0x{v:x}" if isinstance(v, int) else v
                attrs[k] = {"val": raw_val, "text": text}

        mib_data[cid]["instances"][iid] = attrs

    return mib_data


def get_check_results(
    pcap_path, only_vendor=False, only_failed=False, rtt_threshold=1000
):
    """
    Analyzes OMCI traffic to identify protocol anomalies and vendor-specific configurations.

    This function performs a comprehensive check on the PCAP file, detecting:
    1. Response Failures: Non-success results from the ONU.
    2. Late Responses: ONU responses exceeding the specified RTT threshold.
    3. Duplicate TIDs: Reused Transaction IDs in requests.
    4. Vendor-Specific MEs: Non-standard Managed Entities.

    Args:
        pcap_path (str): Path to the PCAP file.
        only_vendor (bool): If True, filters results to only include vendor-specific MEs.
        only_failed (bool): If True, filters results to only include failed responses.
        rtt_threshold (int): Round-trip time threshold in milliseconds (default 1000ms).

    Returns:
        dict: A dictionary containing:
            - "packets": List of dictionaries, each describing a flagged OMCI packet.
            - "summary": Statistical counts of detected failures, late responses,
                         vendor MEs, and duplicate TIDs.
    """
    count_fail = 0
    count_olt_vendor = 0
    count_onu_vendor = 0
    count_duplicate = 0
    count_late = 0
    request_timestamps = {}
    check_result = {
        "packets": [],
        "summary": {
            "resp_fail_count": 0,
            "is_vendor_me_count": 0,
            "transaction_id_duplicate_count": 0,
            "resp_late_count": 0,
        },
    }

    for i, omci_pkt, raw_pkt in get_omci_pkts(pcap_path, include_raw=True):
        is_fail = False
        is_vendor = False
        is_duplicate = False
        is_late = False
        action_name = ""
        resp_result = {}
        rtt = 0
        status = ""

        # rtt
        if omci_pkt.is_request:
            if omci_pkt.transaction_id in request_timestamps:
                status = "[TID_DUPLICATE]"
                count_duplicate += 1
                is_duplicate = True
            request_timestamps[omci_pkt.transaction_id] = raw_pkt.time

        # Display Non-standard MEs reported by ONU during MIB Upload.
        mib_entity = omci_pkt.mib_upload_entity
        if mib_entity:
            me_class = mib_entity["me_class"]
            me_inst = mib_entity["me_instance"]
        else:
            me_class = omci_pkt.me_class
            me_inst = omci_pkt.inst_id

        # Display non-standard MEs and non-success responses during OLT provisioning.
        if omci_pkt.result is not None:
            res_val = omci_pkt.result
            resp_result["code"] = res_val
            if resp_result["code"] != OmciResult.SUCCESS:
                is_fail = True
                count_fail += 1
                resp_result["success"] = False
                try:
                    resp_result["text"] = f"Err: {OmciResult(res_val).name}"
                except ValueError:
                    resp_result["text"] = "Err: Unknown"
            else:
                resp_result["success"] = True
                resp_result["text"] = "SUCCESS"

            if omci_pkt.transaction_id in request_timestamps:
                rtt = raw_pkt.time - request_timestamps[omci_pkt.transaction_id]
                if rtt * 1000 > rtt_threshold:
                    is_late = True
                    count_late += 1
                    status = "[LATE]"

        if omci_pkt.is_vendor_me or omci_pkt.is_feature_me:
            is_vendor = True
            count_olt_vendor += 1

        if omci_pkt.mib_upload_is_vendor or omci_pkt.mib_upload_is_feature:
            is_vendor = True
            count_onu_vendor += 1

        if only_vendor and not is_vendor:
            continue
        if only_failed and not is_fail:
            continue

        me_desc = omcimib.get_me_name(me_class)
        if is_fail or is_vendor or is_duplicate or is_late:
            action_name = (
                omci_pkt.action.name
                if hasattr(omci_pkt.action, "name")
                else f"Action({omci_pkt.action})"
            )
            check_result["packets"].append(
                {
                    "packet_no": i + 1,
                    "transaction_id": omci_pkt.transaction_id,
                    "action": action_name,
                    "me_class": me_class,
                    "me_instance_id": me_inst,
                    "me_name": me_desc,
                    "result": resp_result,
                    "rtt": float(rtt),
                    "status": status,
                    "from_olt": omci_pkt.is_request,
                }
            )
    check_result["summary"] = {
        "resp_fail_count": count_fail,
        "onu_upload_vendor_me_count": count_onu_vendor,
        "olt_provision_vendor_me_count": count_olt_vendor,
        "resp_late_count": count_late,
        "transaction_id_duplicate_count": count_duplicate,
    }

    return check_result


def get_flow_data(mib_db):
    """
    Extracts the T-CONT traffic hierarchy from the provided MIB database.

    This function serves as a wrapper to analyze the relationships between
    T-CONTs, GEM Ports, and Priority Queues based on the current MIB state.

    Args:
        mib_db (dict): The MIB database containing Managed Entity instances.

    Returns:
        dict/list: A structured representation of the traffic flow hierarchy
                   processed by the omciflow module.
    """
    return omciflow.get_tcont_flow_data(mib_db)


def get_vlan_data(mib_db):
    """
    Extracts and parses VLAN tagging configurations from the MIB database.

    This function specifically targets Managed Entity (ME) 171 (VLAN Tagging
    Filter Data). It decodes the complex table-driven tagging operations,
    association pointers, and downstream operating modes.

    Args:
        mib_db (dict): The MIB database containing Managed Entity instances.

    Returns:
        list: A list of dictionaries, each representing a VLAN tagging configuration:
            - "inst_id": The Instance ID of the ME 171.
            - "rules": A list of parsed rules containing action types and raw data.
            - "assoc_ptr": Pointer to the associated ME (e.g., ANI-G or PPTP).
            - "assoc_type": Decoded association type description.
            - "ds_mode": Decoded downstream operating mode.
    """

    vlan_data = []
    vlan_db = get_instances_by_class(mib_db, 171)
    for vlan in vlan_db:
        attrs = vlan.attributes
        raw_rows = attrs.get("Received frame VLAN tagging operation table", [])
        rows = raw_rows if isinstance(raw_rows, list) else [raw_rows]

        rules = []
        for row_hex in rows:
            vlan_op = omcivlan.VlanTaggingOperation(row_hex)
            rules.append(
                {
                    "action_type": vlan_op.action_type,
                    "tpid_dei_operation": vlan_op.tpid_dei_operation,
                    "data": vlan_op.data,
                }
            )
        vlan_data.append(
            {
                "inst_id": vlan.inst_id,
                "rules": rules,
                "assoc_ptr": attrs.get("Associated ME pointer", "N/A"),
                "assoc_type": vlan.attr_semantic("Association type"),
                "ds_mode": vlan.attr_semantic("Downstream mode"),
            }
        )

    return vlan_data


def get_mib_diff_data(mib1, mib2):
    """
    Performs a comprehensive comparison between two MIB databases.

    This function identifies added, removed, and modified Managed Entities (MEs).
    For unknown MEs (Vendor Specific), it performs a deep comparison based on
    Attribute Masks and raw data hex strings.

    Args:
        mib1 (dict): The baseline MIB database (source).
        mib2 (dict): The target MIB database to compare against (destination).

    Returns:
        dict: A structured dictionary containing:
            - changes (list): Detailed list of individual attribute variations.
            - unknown_me_mask_mismatch (list): Instances where the ME definition
              (attribute layout) differs between the two PCAPs.
            - summary (dict): Statistical counters for the diff operation.
    """

    all_keys = sorted(set(mib1.keys()) | set(mib2.keys()))

    diff_data = {
        "changes": [],
        "unknown_me_mask_mismatch": [],
        "summary": {
            "modified_count": 0,
            "removed_count": 0,
            "added_count": 0,
            "unknown_mismatch_count": 0,
        },
    }

    modified_count = 0
    removed_count = 0
    added_count = 0
    unknown_me_mask_mismatch_count = 0

    for key in all_keys:
        class_id, inst_id = key
        me_name = omcimib.get_me_name(class_id)
        if key not in mib2:
            diff_data["changes"].append(
                {
                    "status": "removed",
                    "me_name": me_name,
                    "class_id": class_id,
                    "inst_id": inst_id,
                }
            )
            removed_count += 1
            continue

        if key not in mib1:
            diff_data["changes"].append(
                {
                    "status": "added",
                    "me_name": me_name,
                    "class_id": class_id,
                    "inst_id": inst_id,
                }
            )
            added_count += 1
            continue

        obj1 = mib1[key]
        obj2 = mib2[key]

        if obj1.is_unknown:
            obj1.vendor_data.sort(key=lambda x: x[0], reverse=True)
            obj2.vendor_data.sort(key=lambda x: x[0], reverse=True)

            masks1 = [m for m, d in obj1.vendor_data]
            masks2 = [m for m, d in obj2.vendor_data]
            if masks1 != masks2:
                diff_data["unknown_me_mask_mismatch"].append(
                    {
                        "class_id": class_id,
                        "inst_id": inst_id,
                    }
                )
                unknown_me_mask_mismatch_count += 1
            else:
                for i, (mask, d1) in enumerate(obj1.vendor_data):
                    d2 = obj2.vendor_data[i][1]
                    if d1 != d2:
                        attr_name = f"Vendor Raw (Mask 0x{mask:04X})"
                        diff_data["changes"].append(
                            {
                                "status": "modified",
                                "me_name": me_name,
                                "attr_name": attr_name,
                                "class_id": class_id,
                                "inst_id": inst_id,
                                "old": d1,
                                "new": d2,
                            }
                        )
                        modified_count += 1
        else:
            for attr, val1 in obj1.attributes.items():
                val2 = obj2.attributes.get(attr)
                if val1 != val2:
                    v1_str = obj1.attr_semantic(attr)
                    v2_str = obj2.attr_semantic(attr)
                    diff_data["changes"].append(
                        {
                            "status": "modified",
                            "me_name": me_name,
                            "attr_name": attr,
                            "class_id": class_id,
                            "inst_id": inst_id,
                            "old": v1_str,
                            "new": v2_str,
                        }
                    )
                    modified_count += 1

    diff_data["summary"] = {
        "removed_count": removed_count,
        "added_count": added_count,
        "modified_count": modified_count,
        "unknown_me_mask_mismatch_count": unknown_me_mask_mismatch_count,
    }

    return diff_data


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


def get_topology_data(pcap_path):
    """
    High-level entry point to extract topology from a pcap file.

    Args:
        pcap_path (str): Path to the input pcap file.

    Returns:
        dict: The abstract topology data containing 'nodes' and 'edges'.
    """
    # Assume get_all_mib_db is imported or defined to parse pcap into MIB DB
    mib_db = get_all_mib_db(pcap_path)
    return generate_topo_data(mib_db)


def generate_topo_data(mib_db):
    """
    Extract logical topology relationships from the MIB database.

    Args:
        mib_db (dict): A dictionary mapping (class_id, inst_id) to
                       ME instances with decoded semantic attributes.

    Returns:
        dict: A dictionary containing:
            - 'nodes' (list): Minimalist node definitions with attributes.
            - 'edges' (list): Logical links between MEs using source/target IDs.
    """
    nodes = []
    edges = []

    def node_str(cid, iid):
        # Helper to ensure consistent ID format: class_id_inst_id
        return f"{cid}_{iid}"

    for (class_id, inst_id), me_inst in mib_db.items():
        if class_id not in INTERESTED_CLASSES:
            continue

        attrs = me_inst.attributes
        if class_id == OMCIClass.T_CONT:
            alloc_id = attrs.get("Alloc-ID")
            if alloc_id is None or alloc_id == 0xFFFF or alloc_id == 0xFF:
                continue

        # ID format: {class_id}_{inst_id} (e.g., 262_1)
        node_id = f"{class_id}_{inst_id}"

        # Semantic attributes without visual formatting
        attrs = me_inst.attributes

        nodes.append(
            {
                "id": node_id,
                "class_id": int(class_id),
                "inst_id": int(inst_id),
                "attributes": attrs,
                "name": OMCIClass(class_id).name,
            }
        )

        # ME 84: VLAN Tagging Filter Data (Implicit match to ME 47)
        if class_id == OMCIClass.VLAN_TAGGING_FILTER_DATA:
            if (47, inst_id) in mib_db:
                edges.append(
                    {
                        "source": node_id,
                        "target": node_str(47, inst_id),
                        "relation": "vlan_filter_bind_to_port",
                        "label": "Filter-on",
                    }
                )

        # ME 47: MAC Bridge Port Configuration Data
        elif class_id == OMCIClass.MAC_BRIDGE_PORT_CONFIGURATION_DATA:
            # Bridge ID Pointer (Connects to ME 45)
            b_ptr = attrs.get("Bridge id pointer")
            if b_ptr is not None:
                edges.append(
                    {
                        "source": node_id,
                        "target": node_str(45, b_ptr),
                        "relation": "belongs_to_bridge",
                        "label": "bridge_ptr",
                    }
                )

            # TP Pointer (Connects to various Physical/Termination points)
            tp_ptr = attrs.get("TP pointer")
            if tp_ptr is not None:
                # 11: PPTP, 130: 802.1p, 134: IP Host, 329: VEIP, 281: MCAST
                for t_cid in [11, 130, 134, 329, 281]:
                    if (t_cid, tp_ptr) in mib_db:
                        edges.append(
                            {
                                "source": node_id,
                                "target": node_str(t_cid, tp_ptr),
                                "relation": "points_to_transport_termination",
                                "label": "tp_ptr",
                            }
                        )

        # ME 171: Extended VLAN Tagging Operation
        elif class_id == OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA:
            a_ptr = attrs.get("Associated ME pointer")
            if a_ptr:
                for t_cid in [47, 11, 329, 130, 134]:
                    if (t_cid, a_ptr) in mib_db:
                        edges.append(
                            {
                                "source": node_id,
                                "target": node_str(t_cid, a_ptr),
                                "relation": "vlan_op_associated_with_me",
                                "label": "assoc_ptr",
                            }
                        )

        # ME 266: GEM Interworking Termination Point
        elif class_id == OMCIClass.GEM_INTERWORKING_TERMINATION_POINT:
            # Interworking TP pointer -> Bridge Port (47)
            iw_ptr = attrs.get("Interworking TP pointer")
            if iw_ptr:
                edges.append(
                    {
                        "source": node_id,
                        "target": node_str(47, iw_ptr),
                        "relation": "iw_mapped_to_bridge_port",
                        "label": "iw_tp",
                    }
                )

            # GEM port network CTP pointer -> GEM CTP (268)
            gem_ptr = attrs.get("GEM port network CTP pointer")
            if gem_ptr:
                edges.append(
                    {
                        "source": node_id,
                        "target": node_str(268, gem_ptr),
                        "relation": "iw_linked_to_gem_port",
                        "label": "gem_ptr",
                    }
                )

            # Service Profile Pointer based on Interworking Option
            iw_option = attrs.get("Interworking option")
            srv_ptr = attrs.get("Service profile pointer")
            if srv_ptr:
                target_cid = None
                if iw_option == 1:
                    target_cid = 45  # MAC Bridge Service Profile
                elif iw_option == 5:
                    target_cid = 130  # 802.1p Mapper Service Profile

                if target_cid:
                    edges.append(
                        {
                            "source": node_id,
                            "target": node_str(target_cid, srv_ptr),
                            "relation": "service_profile_mapping",
                            "label": "srv_ptr",
                        }
                    )

        # ME 268: GEM Port Network CTP
        elif class_id == OMCIClass.GEM_PORT_NETWORK_CTP:
            t_ptr = attrs.get("T-CONT pointer")
            if t_ptr:
                edges.append(
                    {
                        "source": node_id,
                        "target": node_str(262, t_ptr),
                        "relation": "traffic_mapped_to_tcont",
                        "label": "tcont_ptr",
                    }
                )

    return {"nodes": nodes, "edges": edges}


def get_instances_by_class(mib_db, target_class_id):
    """
    Retrieves all Managed Entity instances belonging to a specific Class ID.

    The returned list is sorted by Instance ID to ensure deterministic output
    and easier analysis.

    Args:
        mib_db (dict): The MIB database to search.
        target_class_id (int): The OMCI Class ID to filter by (e.g., 84 for
                               VLAN Tagging Filter Data).

    Returns:
        list: A sorted list of MIBInstance objects matching the target Class ID.
    """
    matched = [inst for k, inst in mib_db.items() if k[0] == target_class_id]
    matched.sort(key=lambda x: x.inst_id)

    return matched
