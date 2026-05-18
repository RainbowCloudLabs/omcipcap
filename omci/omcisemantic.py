#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih daneshih1125@gmail.com
# Licensed under the MIT License.

import struct
import socket


class OMCISemantic:
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


def get_attr_semantic(class_id, attr_name, value):
    """
    Get the human-readable semantic meaning of an attribute value.

    Args:
        class_id (int): The OMCI Class ID.
        attr_name (str): The attribute name.
        value: The raw attribute value to be translated.

    Returns:
        str: The translated semantic string, or the raw value as string
             if no translator is found.
    """
    try:
        # Get the translator function for specific class and attribute
        trans_func = OMCISemantic.translator(class_id, attr_name)
        if trans_func:
            return trans_func(value)
    except (KeyError, AttributeError):
        # Fallback to raw value if translation logic is missing
        pass

    return str(value)


def trans_ipv4_address(value):
    """
    Translate a 4-byte value into a standard IPv4 dotted-decimal string.

    Args:
        value: Can be an integer, 4-byte hex string, or bytes.

    Returns:
        str: Human-readable IPv4 address (e.g., '192.168.1.10').
    """
    if value is None:
        return "0.0.0.0"

    try:
        # If the value is a hex string (e.g., "C0A8010A")
        if isinstance(value, str):
            # Remove 0x prefix if exists and convert to bytes
            clean_hex = value.replace("0x", "")
            # Ensure it's 8 characters for 4 bytes
            raw_bytes = bytes.fromhex(clean_hex.ljust(8, "0")[:8])
        # If the value is already an integer (u32)
        elif isinstance(value, int):
            raw_bytes = struct.pack(">I", value)
        # If it's already bytes
        elif isinstance(value, bytes):
            raw_bytes = value[:4]
        else:
            return str(value)

        # Convert bytes to dotted-decimal format
        return socket.inet_ntoa(raw_bytes)
    except Exception:
        return str(value)


def trans_mac_address(value):
    """
    Format 6-byte hex value to standard MAC address format (xx:xx:xx:xx:xx:xx).
    """
    if not value or value == "000000000000":
        return "00:00:00:00:00:00"

    # Remove prefix and format
    s = str(value).replace("0x", "")
    return ":".join(s[i : i + 2] for i in range(0, 12, 2))


OMCISemantic.register(47, "TP type", me47_tp_type_translator)
OMCISemantic.register(171, "Association type", me171_assoc_type_translator)
OMCISemantic.register(171, "Downstream mode", me171_downstream_mode_translator)
OMCISemantic.register(84, "VLAN filter list", decode_me84_vlan_filter_list)
# Mac
OMCISemantic.register(134, "MAC address", trans_mac_address)
# IPv4 Address
ipv4_fields = [
    "IP address",
    "Mask",
    "Gateway",
    "Primary DNS",
    "Secondary DNS",
    "Current address",
    "Current mask",
    "Current gateway",
    "Current primary DNS",
    "Current Secondary DNS",
]
for field in ipv4_fields:
    OMCISemantic.register(134, field, trans_ipv4_address)
