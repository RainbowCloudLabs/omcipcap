#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih daneshih1125@gmail.com
# Licensed under the MIT License.

import struct
import socket
import importlib.util
import os
import sys


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


def load_external_semantics(semantic_dir):
    """
    Dynamically load all Python files in the directory to trigger
    OMCISemantic.register() calls.
    """
    if not os.path.isdir(semantic_dir):
        print(f"[!] Error loading semantic directory: {semantic_dir}\n\n")
        return False

    # Add dir to sys.path so scripts can import each other if needed
    sys.path.append(semantic_dir)

    for filename in os.listdir(semantic_dir):
        if filename.endswith(".py") and not filename.startswith("__"):
            file_path = os.path.join(semantic_dir, filename)
            module_name = f"ext_semantic_{filename[:-3]}"

            spec = importlib.util.spec_from_file_location(module_name, file_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

    return True


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

G988_PLUGIN_UNIT_TYPES = {
    0: "No LIM",
    13: "C1.5 (DS1)",
    14: "C2.0 (E1)",
    15: "C6.3 (J2)",
    16: "C-DS1/E1",
    17: "C-DS1/E1/J1",
    22: "10BASE-T",
    23: "100BASE-T",
    24: "10/100 BASE-T",
    28: "C1.5 (J1)",
    32: "POTS",
    33: "ISDN-BRI",
    34: "Gigabit optical Ethernet",
    35: "xDSL",
    36: "SHDSL",
    37: "VDSL",
    38: "Video service",
    39: "LCT",
    40: "802.11",
    41: "xDSL/POTS",
    42: "VDSL/POTS",
    43: "Common equipment",
    44: "Combined video UNI and PON interface",
    45: "Mixed services equipment",
    46: "MoCA",
    47: "10/100/1000BASE-T",
    48: "VEIP",
    49: "10G GBASE-T Ethernet",
    50: "2.5GBASE-T Ethernet",
    51: "5GBASE-T Ethernet",
    52: "25GBASE-T Ethernet",
    53: "40GBASE-T Ethernet",
    54: "1000BASE-LX",
    55: "1000BASE-SX",
    56: "10GBASE-SR",
    57: "10GBASE-LX4",
    58: "10GBASE-LRM",
    59: "10GBASE-LR",
    60: "10GBASE-ER",
    61: "10GBASE-SW",
    62: "10GBASE-LW",
    63: "10GBASE-EW",
    64: "25GBASE-SR",
    65: "40GBASE-SR4",
    66: "40GBASE-LR4",
    67: "40GBASE-ER4",
    68: "Multi-Rate-10GBASE-T",
    69: "10G Optical Interface",
    70: "40G Optical Interface",
    71: "G.fast",
    72: "25G Optical Interface",
    73: "50G Optical Interface",
    74: "25GBASE-LR",
    75: "25GBASE-ER",
    76: "50GBASE-SR",
    77: "50GBASE-FR",
    78: "50GBASE-LR",
    79: "50GBASE-ER",
    80: "10GBASE-BR10",
    81: "10GBASE-BR20",
    82: "10GBASE-BR40",
    83: "25GBASE-BR10",
    84: "25GBASE-BR20",
    85: "25GBASE-BR40",
    86: "50GBASE-BR10",
    87: "50GBASE-BR20",
    88: "50GBASE-BR40",
    # 89..191: Reserved
    # 192..223: Vendor-specific
    # 224..226: Reserved
    227: "HSP50G50",
    228: "HSP50G25",
    229: "HSP50G12",
    230: "Multi-PON",
    231: "PtP WDM PON line rate class 1",
    232: "PtP WDM PON line rate class 2",
    233: "PtP WDM PON line rate class 3",
    234: "TWDM10G2",
    235: "TWDM10G10",
    236: "TWDM2G2",
    237: "XG-PON10G2488",
    238: "XG-PON10G10",
    239: "Mid-span PON reach extender UNI",
    240: "Mid-span PON reach extender ANI",
    241: "Mid-span PON reach extender upstream optical amplifier",
    242: "Mid-span PON 2488/1244 reach extender downstream optical amplifier",
    # 243..247: See [ITU-T G.984.4] G-PON interfaces of diverse rates
    248: "GPON24881244",
    # 249..254: See [ITU-T G.983.2] and [ITU-T G.984.4] G-PON and B-PON interfaces
    255: "Plug-and-play/Unknown",
}


def plugin_in_type_translator(val):
    """Plug-in type translator"""
    return G988_PLUGIN_UNIT_TYPES.get(val, f"Unknown ({val})")


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


ADMIN_STATE_MAP = {0: "Unlock", 1: "Lock"}
OP_STATE_MAP = {0: "Enable", 1: "Disable"}


def trans_admin_state(value):
    """
    Administrative state: 1 -> Lock, 0 -> Unlock
    """
    return ADMIN_STATE_MAP.get(value, f"Unknown ({value})")


def trans_op_state(value):
    """
    Operational state: 1 -> Disable, 0 -> Enable
    """
    return OP_STATE_MAP.get(value, f"Unknown ({value})")


admin_state_mes = [
    6,
    11,
    53,
    82,
    90,
    256,
    264,
    302,
    329,
    340,
]

op_state_mes = [
    6,
    11,
    53,
    82,
    90,
    256,
    266,
    281,
    329,
]

for me in admin_state_mes:
    OMCISemantic.register(me, "Administrative state", trans_admin_state)

for me in op_state_mes:
    OMCISemantic.register(me, "Operational state", trans_op_state)

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
    "Current secondary DNS",
]
for field in ipv4_fields:
    OMCISemantic.register(134, field, trans_ipv4_address)
# Plug-in Type
OMCISemantic.register(5, "Actual Plug-in Unit Type", plugin_in_type_translator)
OMCISemantic.register(5, "Expected Plug-in Unit Type", plugin_in_type_translator)
OMCISemantic.register(6, "Type", plugin_in_type_translator)
OMCISemantic.register(11, "Expected Type", plugin_in_type_translator)
OMCISemantic.register(11, "Sensed Type", plugin_in_type_translator)
