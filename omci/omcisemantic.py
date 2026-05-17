#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih daneshih1125@gmail.com
# Licensed under the MIT License.


class OMCI_Semantic:
    """
    A dynamic registry to hold semantic translation functions for OMCI attributes.
    This avoids modifying the rigid ME_SPEC structure.
    """

    # Key: (class_id, attr_name) -> Value: translator_function
    _registry = {}

    @classmethod
    def register(cls, class_id, attr_name, translator):
        """Register a custom semantic translator."""
        cls._registry[(class_id, attr_name)] = translator

    @classmethod
    def translator(cls, class_id, attr_name):
        """Retrieve a translator for a specific attribute."""
        return cls._registry.get((class_id, attr_name))


ME_47_TP_TYPE = {
    1: "PPTP Ethernet UNI",
    2: "Interworking VCC TP",
    3: "802.1p mapper service profile",
    4: "IP host config data",
    5: "GEM interworking TP (ANI)",
    6: "Multicast GEM interworking TP",
    7: "PPTP xDSL UNI part 1",
    8: "PPTP VDSL UNI",
    9: "Ethernet flow TP",
    10: "Reserved",
    11: "VEIP",
    12: "PPTP MoCA UNI",
    13: "EFM bonding group",
}


ME_171_ASSOCIATION_TYPE = {
    0: "MAC bridge port configuration data",
    1: "IEEE 802.1p mapper service profile",
    2: "Physical path termination point Ethernet UNI",
    3: "IP host config data or IPv6 host config data",
    4: "Physical path termination point xDSL UNI",
    5: "GEM IW termination point",
    6: "Multicast GEM IW termination point",
    7: "Physical path termination point MoCA UNI",
    8: "Reserved",
    9: "Ethernet flow termination point",
    10: "Virtual Ethernet interface point",
    11: "MPLS pseudowire termination point",
    12: "EFM bonding group",
}


ME_171_DOWNSTREAM_MODE = {
    0: "Inverse (ONU Std)",
    1: "Transparent (No Change)",
    2: "Match VID+P -> Inverse (Else: Fwd)",
    3: "Match VID -> Inverse (Else: Fwd)",
    4: "Match Pbit -> Inverse (Else: Fwd)",
    5: "Match VID+P -> Inverse (Else: Drop)",
    6: "Match VID -> Inverse (Else: Drop)",
    7: "Match Pbit -> Inverse (Else: Drop)",
    8: "Block All",
}


def me47_tp_type_translator(val):
    """ME 47 TP Type translator"""
    return ME_47_TP_TYPE.get(val, f"Unknown ({val})")


def me171_assoc_type_translator(val):
    """ME 171 Association Type translator"""
    return ME_171_ASSOCIATION_TYPE.get(val, f"Unknown ({val})")


def me171_downstream_mode_translator(val):
    """ME 171 Downstream Mode translator"""
    return ME_171_DOWNSTREAM_MODE.get(val, f"Unknown ({val})")


def decode_me84_vlan_filter_list(val):
    """
    ME 84: VLAN filter list decoder.
    Parses the 24-byte hex string into a list of active VLAN TCI/VIDs.

    Structure: 12 entries of TCI (2 bytes each).
    TCI = Priority (3bit) + CFI (1bit) + VID (12bit).
    """
    if val is None:
        return "N/A"

    try:
        if isinstance(val, bytes):
            raw_data = val
        elif isinstance(val, str):
            clean_val = val.replace("0x", "").replace(" ", "")
            raw_data = bytes.fromhex(clean_val)
        else:
            clean_val = (
                hex(val).replace("0x", "")
                if isinstance(val, int)
                else str(val).replace("0x", "")
            )
            raw_data = bytes.fromhex(clean_val)
    except (ValueError, TypeError):
        return val

    vlan_entries = []
    for i in range(0, len(raw_data), 2):
        if i + 1 >= len(raw_data):
            break

        tci = int.from_bytes(raw_data[i : i + 2], byteorder="big")

        if tci == 0x0000 or tci == 0xFFFF:
            continue

        vid = tci & 0x0FFF
        priority = (tci >> 13) & 0x07

        vlan_entries.append(f"VID:{vid}(P:{priority})")

    return ",".join(vlan_entries) if vlan_entries else "Empty/All-Pass"


OMCI_Semantic.register(47, "TP type", me47_tp_type_translator)
OMCI_Semantic.register(171, "Association type", me171_assoc_type_translator)
OMCI_Semantic.register(171, "Downstream mode", me171_downstream_mode_translator)
OMCI_Semantic.register(84, "VLAN filter list", decode_me84_vlan_filter_list)
