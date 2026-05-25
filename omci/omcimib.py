#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih daneshih1125@gmail.com
# Licensed under the MIT License.

import struct
from enum import IntEnum
from omci.omcisemantic import OMCISemantic


class OMCIClass(IntEnum):
    ONT_DATA = 2
    CARDHOLDER = 5
    CIRCUIT_PACK = 6
    SOFTWARE_IMAGE = 7
    PPTP_ETHERNET_UNI = 11
    ETHERNET_PM_HISTORY_DATA = 24
    MAC_BRIDGE_SERVICE_PROFILE = 45
    MAC_BRIDGE_CONFIGURATION_DATA = 46
    MAC_BRIDGE_PORT_CONFIGURATION_DATA = 47
    MAC_BRIDGE_PORT_DESIGNATION_DATA = 48
    MAC_BRIDGE_PORT_FILTER_TABLE_DATA = 49
    MAC_BRIDGE_PORT_BRIDGE_TABLE_DATA = 50
    MAC_BRIDGE_PM_HISTORY_DATA = 51
    MAC_BRIDGE_PORT_PM_HISTORY_DATA = 52
    PPTP_POTS_UNI = 53
    VOICE_SERVICE_PROFILE = 58
    VLAN_TAGGING_OPERATION_CONFIGURATION_DATA = 78
    MAC_BRIDGE_PORT_FILTER_PREASSIGN_TABLE = 79
    PPTP_VIDEO_UNI = 82
    VLAN_TAGGING_FILTER_DATA = 84
    ETHERNET_PM_HISTORY_DATA_2 = 89
    PPTP_VIDEO_ANI = 90
    DOT1P_MAPPER_SERVICE_PROFILE = 130
    OLT_G = 131
    ONU_POWER_SHEDDING = 133
    IP_HOST_CONFIG_DATA = 134
    IP_HOST_PM_HISTORY_DATA = 135
    TCP_UDP_CONFIG_DATA = 136
    NETWORK_ADDRESS = 137
    VOIP_CONFIG_DATA = 138
    VOIP_VOICE_CTP = 139
    CALL_CONTROL_PM_HISTORY_DATA = 140
    VOIP_LINE_STATUS = 141
    VOIP_MEDIA_PROFILE = 142
    RTP_PROFILE_DATA = 143
    RTP_PM_HISTORY_DATA = 144
    NETWORK_DIAL_PLAN_TABLE = 145
    VOIP_APPLICATION_SERVICE_PROFILE = 146
    VOIP_FEATURE_ACCESS_CODES = 147
    AUTHENTICATION_SECURITY_METHOD = 148
    SIP_CONFIG_PORTAL = 149
    SIP_AGENT_CONFIG_DATA = 150
    SIP_AGENT_PM_HISTORY_DATA = 151
    SIP_CALL_INITIATION_PM_HISTORY_DATA = 152
    SIP_USER_DATA = 153
    MGC_CONFIG_PORTAL = 154
    MGC_CONFIG_DATA = 155
    MGC_PM_HISTORY_DATA = 156
    LARGE_STRING = 157
    ONT_REMOTE_DEBUG = 158
    EQUIPMENT_PROTECTION_PROFILE = 159
    EQUIPMENT_EXTENSION_PACKAGE = 160
    EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA = 171
    ONT_G = 256
    ONT2_G = 257
    T_CONT = 262
    ANI_G = 263
    UNI_G = 264
    GEM_INTERWORKING_TERMINATION_POINT = 266
    GEM_PORT_PM_HISTORY_DATA = 267
    GEM_PORT_NETWORK_CTP = 268
    GAL_TDM_PROFILE = 271
    GAL_ETHERNET_PROFILE = 272
    THRESHOLD_DATA_1 = 273
    THRESHOLD_DATA_2 = 274
    GAL_TDM_PM_HISTORY_DATA = 275
    GAL_ETHERNET_PM_HISTORY_DATA = 276
    PRIORITY_QUEUE_G = 277
    TRAFFIC_SCHEDULER_G = 278
    PROTECTION_DATA = 279
    TRAFFIC_DESCRIPTOR = 280
    MULTICAST_GEM_INTERWORKING_TERMINATION_POINT = 281
    OMCI = 287
    MANAGED_ENTITY = 288
    ATTRIBUTE = 289
    DOT1X_PORT_EXTENSION_PACKAGE = 290
    DOT1X_CONFIGURATION_PROFILE = 291
    DOT1X_PM_HISTORY_DATA = 292
    RADIUS_PM_HISTORY_DATA = 293
    ETHERNET_PM_HISTORY_DATA_3 = 296
    PORT_MAPPING_PACKAGE = 297
    DOT1_RATE_LIMITER = 298
    DOT1AG_MAINTENANCE_DOMAIN = 299
    DOT1AG_MAINTENANCE_ASSOCIATION = 300
    DOT1AG_DEFAULT_MD_LEVEL = 301
    DOT1AG_MEP = 302
    DOT1AG_MEP_STATUS = 303
    DOT1AG_MEP_CCM_DATABASE = 304
    DOT1AG_CFM_STACK = 305
    DOT1AG_CHASSIS_MANAGEMENT_INFO = 306
    OCTET_STRING = 307
    GENERAL_PURPOSE_BUFFER = 308
    MULTICAST_OPERATIONS_PROFILE = 309
    MULTICAST_SUBSCRIBER_CONFIG_INFO = 310
    MULTICAST_SUBSCRIBER_MONITOR = 311
    FEC_PM_HISTORY_DATA = 312
    FILE_TRANSFER_CONTROLLER = 318
    ETHERNET_FRAME_PM_HISTORY_DATA_DS = 321
    ETHERNET_FRAME_PM_HISTORY_DATA_US = 322
    VIRTUAL_ETHERNET_INTERFACE_POINT = 329
    GENERIC_STATUS_PORTAL = 330
    ONU_E = 331
    ENHANCED_SECURITY_CONTROL = 332
    ETHERNET_FRAME_EXTENDED_PM = 334
    SNMP_CONFIGURATION_DATA = 335
    ONU_DYNAMIC_POWER_MANAGEMENT_CONTROL = 336
    TR_069_MANAGEMENT_SERVER = 340
    GEM_PORT_NETWORK_CTP_PM_HISTORY_DATA = 341
    TCP_UDP_PM_HISTORY_DATA = 342
    ETHERNET_FRAME_EXTENDED_PM_64_BIT = 425


ME_CLASS_NAMES = {
    2: "ONT Data",
    5: "Cardholder",
    6: "Circuit Pack",
    7: "Software Image",
    11: "PPTP Ethernet UNI",
    24: "Ethernet PM History Data",
    45: "MAC Bridge Service Profile",
    46: "MAC bridge configuration data",
    47: "MAC bridge port configuration data",
    48: "MAC bridge port designation data",
    49: "MAC bridge port filter table data",
    50: "MAC bridge port bridge table data",
    51: "MAC Bridge PM History Data",
    52: "MAC Bridge Port PM History Data",
    53: "Physical path termination point POTS UNI",
    58: "Voice service profile",
    78: "VLAN tagging operation configuration data",
    79: "MAC bridge port filter preassign table",
    82: "PPTP Video UNI",
    84: "VLAN tagging filter data",
    89: "Ethernet PM History Data 2",
    90: "PPTP Video ANI",
    130: "802.1P Mapper Service Profile",
    131: "OLT-G",
    133: "ONU Power Shedding",
    134: "IP host config data",
    135: "IP host performance monitoring history data",
    136: "TCP/UDP config data",
    137: "Network address",
    138: "VoIP config data",
    139: "VoIP voice CTP",
    140: "Call control performance monitoring history data",
    141: "VoIP line status",
    142: "VoIP media profile",
    143: "RTP profile data",
    144: "RTP performance monitoring history data",
    145: "Network dial plan table",
    146: "VoIP application service profile",
    147: "VoIP feature access codes",
    148: "Authentication security method",
    149: "SIP config portal",
    150: "SIP agent config data",
    151: "SIP agent performance monitoring history data",
    152: "SIP call initiation performance monitoring history data",
    153: "SIP user data",
    154: "MGC config portal",
    155: "MGC config data",
    156: "MGC performance monitoring history data",
    157: "Large string",
    158: "ONT remote debug",
    159: "Equipment protection profile",
    160: "Equipment extension package",
    171: "Extended VLAN tagging operation configuration data",
    256: "ONT-G",
    257: "ONT2-G",
    262: "T-CONT",
    263: "ANI-G",
    264: "UNI-G",
    266: "GEM interworking Termination Point",
    267: "GEM Port PM History Data",
    268: "GEM Port Network CTP",
    271: "GAL TDM profile",
    272: "GAL Ethernet profile",
    273: "Threshold Data 1",
    274: "Threshold Data 2",
    275: "GAL TDM PM History Data",
    276: "GAL Ethernet PM History Data",
    277: "Priority queue-G",
    278: "Traffic Scheduler-G",
    279: "Protection data",
    280: "Traffic descriptor",
    281: "Multicast GEM interworking termination point",
    287: "OMCI",
    288: "Managed entity",
    289: "Attribute",
    290: "Dot1X Port Extension Package",
    291: "Dot1X configuration profile",
    292: "Dot1X performance monitoring history data",
    293: "Radius performance monitoring history data",
    296: "Ethernet PM History Data 3",
    297: "Port mapping package",
    298: "Dot1 rate limiter",
    299: "Dot1ag maintenance domain",
    300: "Dot1ag maintenance association",
    301: "Dot1ag default MD level",
    302: "Dot1ag MEP",
    303: "Dot1ag MEP status",
    304: "Dot1ag MEP CCM database",
    305: "Dot1ag CFM stack",
    306: "Dot1ag chassis-management info",
    307: "Octet string",
    308: "General purpose buffer",
    309: "Multicast operations profile",
    310: "Multicast subscriber config info",
    311: "Multicast Subscriber Monitor",
    312: "FEC PM History Data",
    318: "File transfer controller",
    321: "Ethernet Frame PM History Data DS",
    322: "Ethernet Frame PM History Data US",
    329: "Virtual Ethernet interface point",
    330: "Generic status portal",
    331: "ONU-E",
    332: "Enhanced security control",
    334: "Ethernet frame extended PM",
    335: "SNMP configuration data",
    336: "ONU dynamic power management control",
    340: "TR-069 management server",
    341: "GEM port network CTP performance monitoring history data",
    342: "TCP/UDP performance monitoring history data",
    425: "Ethernet frame extended PM 64 bit",
}

"""
    Class ID: (Class Name, [
        (attribute, bytes, attribute type, set by created)
    ])
"""
ME_SPEC = {
    # 9.1.3 ONU data
    2: ("ONT Data", [("MIB Data Sync", 1, "u8", False)]),
    # 9.1.5 Cardholder
    5: (
        "Cardholder",
        [
            ("Actual Plug-in Unit Type", 1, "u8", False),
            ("Expected Plug-in Unit Type", 1, "u8", False),
            ("Expected Port Count", 1, "u8", False),
            ("Expected Equipment Id", 20, "str", False),
            ("Actual Equipment Id", 20, "str", False),
            ("Protection Profile Pointer", 1, "hex", False),
            ("Invoke Protection Switch", 1, "u8", False),
        ],
    ),
    # 9.1.6 Circuit pack
    6: (
        "Circuit Pack",
        [
            ("Type", 1, "u8", True),
            ("Number of ports", 1, "u8", False),
            ("Serial Number", 8, "hex", False),
            ("Version", 14, "str", False),
            ("Vendor Id", 4, "hex", False),
            ("Administrative State", 1, "u8", True),
            ("Operational State", 1, "u8", False),
            ("Bridged or IP Ind", 1, "u8", False),
            ("Equipment Id", 20, "str", False),
            ("Card Configuration", 1, "u8", True),
            ("Total T-CONT Buffer Number", 1, "u8", False),
            ("Total Priority Queue Number", 1, "u8", False),
            ("Total Traffic Scheduler Number", 1, "u8", False),
            ("Power Shed Override", 4, "u32", False),
        ],
    ),
    # 9.1.4 Software image
    7: (
        "Software Image",
        [
            ("Version", 14, "str", False),
            ("Is committed", 1, "u8", False),
            ("Is active", 1, "u8", False),
            ("Is valid", 1, "u8", False),
        ],
    ),
    # 9.5.1 Physical path termination point Ethernet UNI
    11: (
        "PPTP Ethernet UNI",
        [
            ("Expected Type", 1, "u8", False),
            ("Sensed Type", 1, "u8", False),
            ("Auto Detection Configuration", 1, "u8", False),
            ("Ethernet Loopback Configuration", 1, "u8", False),
            ("Administrative State", 1, "u8", False),
            ("Operational State", 1, "u8", False),
            ("Configuration Ind", 1, "u8", False),
            ("Max Frame Size", 2, "u16", False),
            ("DTE or DCE", 1, "u8", False),
            ("Pause Time", 2, "u16", False),
            ("Bridged or IP Ind", 1, "u8", False),
            ("ARC", 1, "u8", False),
            ("ARC Interval", 1, "u8", False),
            ("PPPoE Filter", 1, "u8", False),
            ("Power Control", 1, "u8", False),
        ],
    ),
    # 9.5.2 Ethernet performance monitoring history data
    24: (
        "Ethernet PM History Data",
        [
            ("Interval End Time", 1, "u8", False),
            ("Threshold Data 1/2 Id", 2, "hex", True),
            ("FCS errors Drop events", 4, "u32", False),
            ("Excessive Collision Counter", 4, "u32", False),
            ("Late Collision Counter", 4, "u32", False),
            ("Frames too long", 4, "u32", False),
            ("Buffer overflows on Receive", 4, "u32", False),
            ("Buffer overflows on Transmit", 4, "u32", False),
            ("Single Collision Frame Counter", 4, "u32", False),
            ("Multiple Collisions Frame Counter", 4, "u32", False),
            ("SQE counter", 4, "u32", False),
            ("Deferred Transmission Counter", 4, "u32", False),
            ("Internal MAC Transmit Error", 4, "u32", False),
            ("Carrier Sense Error", 4, "u32", False),
            ("Alignment Error Counter", 4, "u32", False),
            ("Internal MAC Receive Error", 4, "u32", False),
        ],
    ),
    # 9.3.1 MAC bridge service profile
    45: (
        "MAC Bridge Service Profile",
        [
            ("Spanning tree ind", 1, "u8", True),
            ("Learning ind", 1, "u8", True),
            ("Port bridging ind", 1, "u8", True),
            ("Priority", 2, "u16", True),
            ("Max age", 2, "u16", True),
            ("Hello time", 2, "u16", True),
            ("Forward delay", 2, "u16", True),
            ("Unknown MAC discard", 1, "u8", True),
            ("MAC learning depth", 1, "u8", True),
            ("Dynamic filtering ageing", 4, "u32", True),
        ],
    ),
    # 9.3.2 MAC bridge configuration data
    46: (
        "MAC bridge configuration data",
        [
            ("Bridge MAC address", 6, "hex", False),
            ("Bridge priority", 2, "u16", False),
            ("Designated root", 8, "hex", False),
            ("Root path cost", 4, "u32", False),
            ("Bridge port count", 1, "u8", False),
            ("Root port num", 2, "u16", False),
            ("Hello time", 2, "u16", False),
            ("Forward delay", 2, "u16", False),
        ],
    ),
    # 9.3.4 MAC bridge port configuration data
    47: (
        "MAC bridge port configuration data",
        [
            ("Bridge id pointer", 2, "u16", True),
            ("Port num", 1, "u8", True),
            ("TP type", 1, "u8", True),
            ("TP pointer", 2, "u16", True),
            ("Port priority", 2, "u16", True),
            ("Port path cost", 2, "u16", True),
            ("Port spanning tree ind", 1, "u8", True),
            ("Encapsulation method", 1, "u8", True),
            ("LAN FCS ind", 1, "u8", True),
            ("Port MAC address", 6, "hex", False),
            ("Outbound TD pointer", 2, "u16", False),
            ("Inbound TD pointer", 2, "u16", False),
        ],
    ),
    # 9.3.5 MAC bridge port designation data
    48: (
        "MAC bridge port designation data",
        [
            ("Designated bridge root cost port", 24, "hex", False),
            ("Port state", 1, "u8", False),
        ],
    ),
    # 9.3.6 MAC bridge port filter table data
    49: (
        "MAC bridge port filter table data",
        [("MAC filter table", 8, "table", False)],
    ),
    # 9.3.8 MAC bridge port bridge table data
    50: ("MAC bridge port bridge table data", [("Bridge table", 8, "table", False)]),
    # 9.3.3 MAC bridge performance monitoring history data
    51: (
        "MAC Bridge PM History Data",
        [
            ("Interval end time", 1, "u8", False),
            ("Threshold data 1/2 id", 2, "hex", True),
            ("Bridge learning entry discard count", 4, "u32", False),
        ],
    ),
    # 9.3.9 MAC bridge port performance monitoring history data
    52: (
        "MAC Bridge Port PM History Data",
        [
            ("Interval end time", 1, "u8", False),
            ("Threshold data 1/2 id", 2, "hex", True),
            ("Forwarded frame counter", 4, "u32", False),
            ("Delay exceeded discard counter", 4, "u32", False),
            ("MTU exceeded discard counter", 4, "u32", False),
            ("Received frame counter", 4, "u32", False),
            ("Received and discarded counter", 4, "u32", False),
        ],
    ),
    # 9.9.1 Physical path termination point POTS UNI
    53: (
        "PPTP POTS UNI",
        [
            ("Administrative state", 1, "u8", False),
            ("Deprecated", 2, "hex", False),
            ("ARC", 1, "u8", False),
            ("ARC interval", 1, "u8", False),
            ("Impedance", 1, "u8", False),
            ("Transmission path", 1, "u8", False),
            ("Rx gain", 1, "u8", False),
            ("Tx gain", 1, "u8", False),
            ("Operational state", 1, "u8", False),
            ("Hook state", 1, "u8", False),
            ("POTS holdover time", 2, "u16", False),
        ],
    ),
    # 9.9.6 Voice service profile
    58: (
        "Voice service profile",
        [
            ("Announcement type", 1, "u8", True),
            ("Jitter target", 2, "u16", True),
            ("Jitter buffer max", 2, "u16", True),
            ("Echo cancel ind", 1, "u8", True),
            ("PSTN protocol variant", 2, "u16", True),
            ("DTMF digit levels", 2, "u16", True),
            ("DTMF digit duration", 2, "u16", True),
            ("Hook flash minimum time", 2, "u16", True),
            ("Hook flash maximum time", 2, "u16", True),
            ("Tone pattern table", 20, "table", False),
            ("Tone event table", 7, "table", False),
            ("Ringing pattern table", 5, "table", False),
            ("Ringing event table", 7, "table", False),
        ],
    ),
    # 9.3.12 VLAN tagging operation configuration data
    78: (
        "VLAN tagging operation config",
        [
            ("Upstream VLAN tagging mode", 1, "u8", True),
            ("Upstream VLAN tag TCI value", 2, "u16", True),
            ("Downstream VLAN tagging mode", 1, "u8", True),
            ("Association type", 1, "u8", True),
            ("Associated ME pointer", 2, "u16", True),
        ],
    ),
    # 9.3.7 MAC bridge port filter pre-assign table
    79: (
        "MAC bridge port filter preassign table",
        [
            ("IPv4 multicast filtering", 1, "u8", False),
            ("IPv6 multicast filtering", 1, "u8", False),
            ("IPv4 broadcast filtering", 1, "u8", False),
            ("RARP filtering", 1, "u8", False),
            ("IPX filtering", 1, "u8", False),
            ("NetBEUI filtering", 1, "u8", False),
            ("AppleTalk filtering", 1, "u8", False),
            ("Bridge management information filtering", 1, "u8", False),
            ("ARP filtering", 1, "u8", False),
        ],
    ),
    # 9.13.1 Physical path termination point video UNI
    82: (
        "PPTP Video UNI",
        [
            ("Administrative State", 1, "u8", False),
            ("Operational State", 1, "u8", False),
            ("ARC", 1, "u8", False),
            ("ARC Interval", 1, "u8", False),
            ("Power Control", 1, "u8", False),
        ],
    ),
    # 9.3.11 VLAN tagging filter data
    84: (
        "VLAN tagging filter data",
        [
            ("VLAN filter list", 24, "hex", True),
            ("Forward operation", 1, "u8", True),
            ("Number of entries", 1, "u8", True),
        ],
    ),
    # 9.5.3 Ethernet performance monitoring history data 2
    89: (
        "Ethernet PM History Data 2",
        [
            ("Interval end time", 1, "u8", False),
            ("Threshold data 1/2 id", 2, "hex", True),
            ("PPPoE filtered frame counter", 4, "u32", False),
        ],
    ),
    # 9.13.2 Physical path termination point video ANI
    90: (
        "PPTP Video ANI",
        [
            ("Administrative State", 1, "u8", False),
            ("Operational State", 1, "u8", False),
            ("ARC", 1, "u8", False),
            ("ARC Interval", 1, "u8", False),
            ("Frequency Range Low", 1, "u8", False),
            ("Frequency Range High", 1, "u8", False),
            ("Signal Capability", 1, "u8", False),
            ("Optical Signal Level", 1, "u8", False),
            ("Pilot Signal Level", 1, "u8", False),
            ("Signal Level min", 1, "u8", False),
            ("Signal Level max", 1, "u8", False),
            ("Pilot Frequency", 4, "u32", False),
            ("AGC Mode", 1, "u8", False),
            ("AGC Setting", 1, "u8", False),
            ("Video Lower Optical Threshold", 1, "u8", False),
            ("Video Upper Optical Threshold", 1, "u8", False),
        ],
    ),
    # 9.3.10 IEEE 802.1p mapper service profile
    130: (
        "802.1p Mapper Service Profile",
        [
            ("TP pointer", 2, "u16", True),
            ("Interwork TP pointer P0", 2, "u16", True),
            ("Interwork TP pointer P1", 2, "u16", True),
            ("Interwork TP pointer P2", 2, "u16", True),
            ("Interwork TP pointer P3", 2, "u16", True),
            ("Interwork TP pointer P4", 2, "u16", True),
            ("Interwork TP pointer P5", 2, "u16", True),
            ("Interwork TP pointer P6", 2, "u16", True),
            ("Interwork TP pointer P7", 2, "u16", True),
            ("Unmarked frame option", 1, "u8", True),
            ("DSCP to P-bit mapping", 24, "hex", False),
            ("Default P-bit marking", 1, "u8", True),
            ("TP Type", 1, "u8", True),
        ],
    ),
    # 9.12.2 OLT-G
    131: (
        "OLT-G",
        [
            ("OLT vendor id", 4, "str", False),
            ("Equipment id", 20, "str", False),
            ("OLT version", 14, "str", False),
        ],
    ),
    # 9.1.7 ONU power shedding
    133: (
        "ONU Power Shedding",
        [
            ("Restore power timer reset interval", 2, "u16", False),
            ("Data class shedding interval", 2, "u16", False),
            ("Voice class shedding interval", 2, "u16", False),
            ("Video overlay class shedding interval", 2, "u16", False),
            ("Video return class shedding interval", 2, "u16", False),
            ("DSL class shedding interval", 2, "u16", False),
            ("ATM class shedding interval", 2, "u16", False),
            ("CES class shedding interval", 2, "u16", False),
            ("Frame class shedding interval", 2, "u16", False),
            ("SONET class shedding interval", 2, "u16", False),
            ("Shedding status", 2, "hex", False),
        ],
    ),
    # 9.4.1 IP host config data
    134: (
        "IP Host Config Data",
        [
            ("IP options", 1, "u8", False),
            ("MAC address", 6, "hex", False),
            ("Onu identifier", 25, "str", False),
            ("IP address", 4, "u32", False),
            ("Mask", 4, "u32", False),
            ("Gateway", 4, "u32", False),
            ("Primary DNS", 4, "u32", False),
            ("Secondary DNS", 4, "u32", False),
            ("Current address", 4, "u32", False),
            ("Current mask", 4, "u32", False),
            ("Current gateway", 4, "u32", False),
            ("Current primary DNS", 4, "u32", False),
            ("Current secondary DNS", 4, "u32", False),
            ("Domain name", 25, "str", False),
            ("Host name", 25, "str", False),
        ],
    ),
    # 9.4.2 IP host performance monitoring history data
    135: (
        "IP Host PM History Data",
        [
            ("Interval end time", 1, "u8", False),
            ("Threshold data 1/2 id", 2, "hex", True),
            ("ICMP errors", 4, "u32", False),
            ("DNS errors", 4, "u32", False),
            ("DHCP timeouts", 2, "u16", False),
            ("IP address conflict", 2, "u16", False),
            ("Out of memory", 2, "u16", False),
            ("Internal error", 2, "u16", False),
        ],
    ),
    # 9.4.3 TCP/UDP config data
    136: (
        "TCP/UDP Config Data",
        [
            ("Port id", 2, "u16", True),
            ("Protocol", 1, "u8", True),
            ("TOS/diffserv field", 1, "u8", True),
            ("IP host pointer", 2, "u16", True),
        ],
    ),
    # 9.12.3 Network address
    137: (
        "Network Address",
        [("Security pointer", 2, "u16", True), ("Address pointer", 2, "u16", True)],
    ),
    # 9.9.18 VoIP config data
    138: (
        "VoIP Config Data",
        [
            ("Available signalling protocols", 1, "u8", False),
            ("Signalling protocol used", 1, "u8", False),
            ("Available VoIP configuration methods", 4, "hex", False),
            ("VoIP configuration method used", 1, "u8", False),
            ("VoIP configuration address pointer", 2, "u16", False),
            ("VoIP configuration state", 1, "u8", False),
            ("Retrieve profile", 1, "u8", False),
            ("Profile version", 25, "str", False),
        ],
    ),
    # 9.9.4 VoIP voice CTP
    139: (
        "VoIP Voice CTP",
        [
            ("User protocol pointer", 2, "u16", True),
            ("PPTP pointer", 2, "u16", True),
            ("VoIP media profile pointer", 2, "u16", True),
            ("Signalling code", 1, "u8", True),
        ],
    ),
    # 9.9.12 Call control PM history data
    140: (
        "Call Control PM History Data",
        [
            ("Interval end time", 1, "u8", False),
            ("Threshold data 1/2 id", 2, "hex", True),
            ("Call setup failures", 4, "u32", False),
            ("Call setup timer", 4, "u32", False),
            ("Call terminate failures", 4, "u32", False),
            ("Analog port releases", 4, "u32", False),
            ("Analog port off-hook timer", 4, "u32", False),
        ],
    ),
    # 9.9.11 VoIP line status
    141: (
        "VoIP Line Status",
        [
            ("Voip codec used", 2, "u16", False),
            ("Voip voice server status", 1, "u8", False),
            ("Voip port session type", 1, "u8", False),
            ("Voip call 1 packet period", 2, "u16", False),
            ("Voip call 2 packet period", 2, "u16", False),
            ("Voip call 1 dest addr", 25, "str", False),
            ("Voip call 2 dest addr", 25, "str", False),
        ],
    ),
    # 9.9.5 VoIP media profile
    142: (
        "VoIP Media Profile",
        [
            ("Fax mode", 1, "u8", True),
            ("Voice service profile pointer", 2, "u16", True),
            ("Codec selection 1st", 1, "u8", True),
            ("Packet period selection 1st", 1, "u8", True),
            ("Silence suppression 1st", 1, "u8", True),
            ("Codec selection 2nd", 1, "u8", True),
            ("Packet period selection 2nd", 1, "u8", True),
            ("Silence suppression 2nd", 1, "u8", True),
            ("Codec selection 3rd", 1, "u8", True),
            ("Packet period selection 3rd", 1, "u8", True),
            ("Silence suppression 3rd", 1, "u8", True),
            ("Codec selection 4th", 1, "u8", True),
            ("Packet period selection 4th", 1, "u8", True),
            ("Silence suppression 4th", 1, "u8", True),
            ("OOB DTMF", 1, "u8", True),
            ("RTP profile pointer", 2, "u16", True),
        ],
    ),
    # 9.9.7 RTP profile data
    143: (
        "RTP Profile Data",
        [
            ("Local port min", 2, "u16", True),
            ("Local port max", 2, "u16", True),
            ("DSCP mark", 1, "u8", True),
            ("Piggyback events", 1, "u8", True),
            ("Tone events", 1, "u8", True),
            ("DTMF events", 1, "u8", True),
            ("CAS events", 1, "u8", True),
        ],
    ),
    # 9.9.13 RTP PM history data
    144: (
        "RTP PM History Data",
        [
            ("Interval end time", 1, "u8", False),
            ("Threshold data 1/2 id", 2, "hex", True),
            ("RTP errors", 4, "u32", False),
            ("Packet loss", 4, "u32", False),
            ("Maximum jitter", 4, "u32", False),
            ("Max time between RTCP", 4, "u32", False),
            ("Buffer underflows", 4, "u32", False),
            ("Buffer overflows", 4, "u32", False),
        ],
    ),
    # 9.9.10 Network dial plan table
    145: (
        "Network Dial Plan Table",
        [
            ("Dial plan number", 2, "u16", False),
            ("Dial plan table max size", 2, "u16", True),
            ("Critical dial timeout", 2, "u16", True),
            ("Partial dial timeout", 2, "u16", True),
            ("Dial plan format", 1, "u8", True),
            ("Dial plan table", 30, "table", False),
        ],
    ),
    # 9.9.8 VoIP application service profile
    146: (
        "VoIP App Service Profile",
        [
            ("CID features", 1, "u8", True),
            ("Call waiting features", 1, "u8", True),
            ("Call progress transfer", 2, "u16", True),
            ("Call presentation", 2, "u16", True),
            ("Direct connect feature", 1, "u8", True),
            ("Direct connect URI ptr", 2, "hex", True),
            ("Bridged line agent URI ptr", 2, "hex", True),
            ("Conference factory URI ptr", 2, "hex", True),
        ],
    ),
    # 9.9.9 VoIP feature access codes
    147: (
        "VoIP Feature Access Codes",
        [
            ("Cancel call waiting", 5, "str", False),
            ("Call hold", 5, "str", False),
            ("Call park", 5, "str", False),
            ("Caller ID activate", 5, "str", False),
            ("Caller ID deactivate", 5, "str", False),
            ("Do not disturb activation", 5, "str", False),
            ("Do not disturb deactivation", 5, "str", False),
            ("Do not disturb PIN change", 5, "str", False),
            ("Emergency service number", 5, "str", False),
            ("Intercom service", 5, "str", False),
            ("Unattended call transfer", 5, "str", False),
            ("Attended call transfer", 5, "str", False),
        ],
    ),
    # 9.12.4 Authentication security method
    148: (
        "Authentication Security Method",
        [
            ("Validation scheme", 1, "u8", False),
            ("Username 1", 25, "str", False),
            ("Password", 25, "str", False),
            ("Realm", 25, "str", False),
            ("Username 2", 25, "str", False),
        ],
    ),
    # 9.9.19 SIP config portal
    149: ("SIP Config Portal", [("Configuration text table", 1, "table", False)]),
    # 9.9.3 SIP agent config data
    150: (
        "SIP Agent Config Data",
        [
            ("Proxy server addr ptr", 2, "hex", True),
            ("Outbound proxy addr ptr", 2, "hex", True),
            ("Primary SIP DNS", 4, "hex", True),
            ("Secondary SIP DNS", 4, "hex", True),
            ("TCP/UDP pointer", 2, "u16", False),
            ("SIP registration exp time", 4, "u32", False),
            ("SIP rereg head start time", 4, "u32", False),
            ("Host part URI", 2, "u16", True),
            ("SIP status", 1, "u8", False),
            ("SIP registrar", 2, "u16", True),
            ("Softswitch", 4, "str", True),
            ("SIP response table", 5, "hex", False),
            ("SIP option transmit control", 1, "u8", True),
            ("SIP URI format", 1, "u8", True),
            ("Redundant SIP agent pointer", 2, "u16", True),
        ],
    ),
    # 9.9.14 SIP agent PM history data
    151: (
        "SIP Agent PM History Data",
        [
            ("Interval end time", 1, "u8", False),
            ("Threshold data 1/2 id", 2, "hex", True),
            ("Transactions", 4, "u32", False),
            ("Rx invite reqs", 4, "u32", False),
            ("Rx invite retrans", 4, "u32", False),
            ("Rx noninvite reqs", 4, "u32", False),
            ("Rx noninvite retrans", 4, "u32", False),
            ("Rx response", 4, "u32", False),
            ("Rx response retransmissions", 4, "u32", False),
            ("Rx response", 4, "u32", False),
            ("Tx invite reqs", 4, "u32", False),
            ("Tx invite retrans", 4, "u32", False),
            ("Tx noninvite reqs", 4, "u32", False),
            ("Tx noninvite retrans", 4, "u32", False),
            ("Tx response", 4, "u32", False),
            ("Tx response retransmissions", 4, "u32", False),
        ],
    ),
    # 9.9.15 SIP call initiation PM history data
    152: (
        "SIP Call Initiation PM",
        [
            ("Interval end time", 1, "u8", False),
            ("Threshold data 1/2 id", 2, "hex", True),
            ("Failed to connect counter", 4, "u32", False),
            ("Failed to validate counter", 4, "u32", False),
            ("Timeout counter", 4, "u32", False),
            ("Failure received counter", 4, "u32", False),
            ("Failed to authenticate counter", 4, "u32", False),
        ],
    ),
    # 9.9.2 SIP user data
    153: (
        "SIP User Data",
        [
            ("SIP agent config ptr", 2, "hex", True),
            ("User part AOR", 2, "u16", True),
            ("SIP display name", 25, "str", False),
            ("Username/password", 2, "u16", True),
            ("Voicemail server SIP URI", 2, "u16", True),
            ("Voicemail subscription expiration time", 4, "u32", True),
            ("Network dial plan pointer", 2, "u16", True),
            ("Application services profile pointer", 2, "u16", True),
            ("Feature code pointer", 2, "u16", True),
            ("PPTP pointer", 2, "u16", True),
            ("Release timer", 1, "u8", False),
            ("ROH timer", 1, "u8", False),
        ],
    ),
    # 9.9.20 MGC config portal
    154: ("MGC Config Portal", [("Configuration text table", 1, "table", False)]),
    # 9.9.16 MGC config data
    155: (
        "MGC Config Data",
        [
            ("Primary MGC", 2, "u16", True),
            ("Secondary MGC", 2, "u16", True),
            ("TCP/UDP pointer", 2, "u16", True),
            ("Version", 1, "u8", True),
            ("Message format", 1, "u8", True),
            ("Maximum retry time", 2, "u16", False),
            ("Maximum retry attempts", 2, "u16", True),
            ("Service change delay", 2, "u16", False),
            ("Termination ID base", 25, "str", False),
            ("Softswitch", 4, "str", True),
            ("Message ID pointer", 2, "u16", True),
        ],
    ),
    # 9.9.17 MGC PM history data
    156: (
        "MGC PM History Data",
        [
            ("Interval end time", 1, "u8", False),
            ("Threshold data 1/2 id", 2, "hex", True),
            ("Received messages", 4, "u32", False),
            ("Received octets", 4, "u32", False),
            ("Sent messages", 4, "u32", False),
            ("Sent octets", 4, "u32", False),
            ("Protocol errors", 4, "u32", False),
            ("Transport losses", 4, "u32", False),
            ("Last detected event", 1, "u8", False),
            ("Last detected event time", 4, "u32", False),
            ("Last detected reset time", 4, "u32", False),
        ],
    ),
    # 9.12.5 Large string
    157: (
        "Large String",
        [
            ("Number of parts", 1, "u8", False),
            ("String part 1", 25, "str", False),
            ("String part 2", 25, "str", False),
            ("String part 3", 25, "str", False),
            ("String part 4", 25, "str", False),
            ("String part 5", 25, "str", False),
            ("String part 6", 25, "str", False),
            ("String part 7", 25, "str", False),
            ("String part 8", 25, "str", False),
            ("String part 9", 25, "str", False),
            ("String part 10", 25, "str", False),
            ("String part 11", 25, "str", False),
            ("String part 12", 25, "str", False),
            ("String part 13", 25, "str", False),
            ("String part 14", 25, "str", False),
            ("String part 15", 25, "str", False),
        ],
    ),
    # 9.1.12 ONU remote debug
    158: (
        "ONT Remote Debug",
        [
            ("Command format", 1, "u8", False),
            ("Command", 25, "str", False),
            ("Reply table", 4, "table", False),
        ],
    ),
    # 9.1.11 Equipment protection profile
    159: (
        "Equipment protection profile",
        [
            ("Protect slot 1,protect slot 2", 2, "u16", True),
            (
                "working slot 1,working slot 2,working slot 3,working slot 4,working slot 5,working slot 6,working slot 7,working slot 8",
                8,
                "hex",
                True,
            ),
            ("Protect status 1,protect status 2", 2, "u16", False),
            ("Revertive ind", 1, "u8", True),
            ("Wait to restore time", 1, "u8", True),
        ],
    ),
    # 9.1.9 Equipment extension package
    160: (
        "Equipment extension package",
        [
            ("Environmental sense", 2, "u16", False),
            ("Contact closure output", 2, "u16", False),
        ],
    ),
    # 9.3.13 Extended VLAN tagging operation configuration data
    171: (
        "Extended VLAN tagging operation configuration data",
        [
            ("Association type", 1, "u8", True),
            ("Received frame VLAN tagging operation table max size", 2, "u16", False),
            ("Input TPID", 2, "hex", False),
            ("Output TPID", 2, "hex", False),
            ("Downstream mode", 1, "u8", False),
            ("Received frame VLAN tagging operation table", 16, "table", False),
            ("Associated ME pointer", 2, "u16", True),
            ("DSCP to P-bit mapping", 24, "hex", False),
        ],
    ),
    # 9.1.1 ONU-G
    256: (
        "ONT-G",
        [
            ("Vendor ID", 4, "str", False),
            ("Version", 14, "str", False),
            ("Serial number", 8, "hex", False),
            ("Traffic management option", 1, "u8", False),
            ("Deprecated 1", 1, "u8", False),
            ("Battery backup", 1, "u8", False),
            ("Administrative state", 1, "u8", False),
            ("Operational state", 1, "u8", False),
            ("ONU survival time", 1, "u8", False),
            ("Logical ONU ID", 24, "str", False),
            ("Logical password", 12, "str", False),
            ("Credentials flags", 1, "u8", False),
        ],
    ),
    # 9.1.2 ONU2-G
    257: (
        "ONT2-G",
        [
            ("Equipment ID", 20, "str", False),
            ("OMCC version", 1, "u8", False),
            ("Vendor product code", 2, "u16", False),
            ("Security capability", 1, "u8", False),
            ("Security mode", 1, "u8", False),
            ("Total priority queue number", 2, "u16", False),
            ("Total traffic scheduler number", 1, "u8", False),
            ("Deprecated 1", 1, "u8", False),
            ("Total GEM port id number", 2, "u16", False),
            ("SysUpTime", 4, "u32", False),
            ("Connectivity capability", 2, "hex", False),
            ("Current connectivity mode", 1, "u8", False),
        ],
    ),
    # 9.2.2 T-CONT
    262: (
        "T-CONT",
        [
            ("Alloc-ID", 2, "u16", False),
            ("Mode indicator", 1, "u8", False),
            ("Policy", 1, "u8", False),
        ],
    ),
    # 9.2.1 ANI-G
    263: (
        "ANI-G",
        [
            ("SR indication", 1, "u8", False),
            ("Total T-CONT number", 2, "u16", False),
            ("GEM block length", 2, "u16", False),
            ("Piggyback DBA reporting", 1, "u8", False),
            ("Whole ONT DBA reporting", 1, "u8", False),
            ("SF threshold", 1, "u8", False),
            ("SD threshold", 1, "u8", False),
            ("ARC", 1, "u8", False),
            ("ARC interval", 1, "u8", False),
            ("Optical signal level", 2, "u16", False),
            ("Lower optical threshold", 1, "u8", False),
            ("Upper optical threshold", 1, "u8", False),
            ("ONT response time", 2, "u16", False),
            ("Transmit optical level", 2, "u16", False),
            ("Lower transmit threshold", 1, "u8", False),
            ("Upper transmit threshold", 1, "u8", False),
        ],
    ),
    # 9.12.1 UNI-G
    264: (
        "UNI-G",
        [
            ("Deprecated", 2, "hex", False),
            ("Administrative state", 1, "u8", False),
            ("Management capability", 1, "u8", False),
        ],
    ),
    # 9.2.4 GEM interworking Termination Point
    266: (
        "GEM interworking Termination Point",
        [
            ("GEM port network CTP pointer", 2, "u16", True),
            ("Interworking option", 1, "u8", True),
            ("Service profile pointer", 2, "u16", True),
            ("Interworking TP pointer", 2, "u16", True),
            ("PPTP counter", 1, "u8", False),
            ("Operational state", 1, "u8", False),
            ("GAL profile pointer", 2, "u16", True),
            ("GAL loopback configuration", 1, "u8", False),
        ],
    ),
    # 9.2.13 GEM Port PM History Data
    267: (
        "GEM Port PM History Data",
        [
            ("Interval end time", 1, "u8", False),
            ("Threshold data 1/2 id", 2, "hex", True),
            ("Transmitted GEM frames", 4, "u32", False),
            ("Received GEM frames", 4, "u32", False),
            ("Received payload bytes", 8, "u64", False),
            ("Transmitted payload bytes", 8, "u64", False),
            ("Encryption key errors", 4, "u32", False),
        ],
    ),
    # 9.2.3 GEM Port Network CTP
    268: (
        "GEM Port Network CTP",
        [
            ("Port-ID", 2, "u16", True),
            ("T-CONT pointer", 2, "u16", True),
            ("Direction", 1, "u8", True),
            ("Traffic management pointer upstream", 2, "u16", True),
            ("Traffic descriptor profile pointer for upstream", 2, "u16", True),
            ("UNI counter", 1, "u8", False),
            ("Priority queue pointer for downstream", 2, "u16", True),
            ("Encryption state", 1, "u8", False),
            ("Traffic descriptor profile pointer for downstream", 2, "u16", False),
        ],
    ),
    # 9.2.7 GAL TDM profile
    271: ("GAL TDM profile", [("Maximum GEM payload size", 2, "16", True)]),
    # 9.2.6 GAL Ethernet profile
    272: ("GAL Ethernet profile", [("Maximum GEM payload size", 2, "u16", True)]),
    # 9.12.6 Threshold Data 1
    273: (
        "Threshold Data 1",
        [
            ("Threshold value 1", 4, "u32", True),
            ("Threshold value 2", 4, "u32", True),
            ("Threshold value 3", 4, "u32", True),
            ("Threshold value 4", 4, "u32", True),
            ("Threshold value 5", 4, "u32", True),
            ("Threshold value 6", 4, "u32", True),
            ("Threshold value 7", 4, "u32", True),
        ],
    ),
    # 9.12.7 Threshold Data 2
    274: (
        "Threshold Data 2",
        [
            ("Threshold value 8", 4, "u32", True),
            ("Threshold value 9", 4, "u32", True),
            ("Threshold value 10", 4, "u32", True),
            ("Threshold value 11", 4, "u32", True),
            ("Threshold value 12", 4, "u32", True),
            ("Threshold value 13", 4, "u32", True),
            ("Threshold value 14", 4, "u32", True),
        ],
    ),
    275: (
        "GAL TDM PM History Data",
        [
            ("Interval end time", 1, "u8", False),
            ("Threshold data 1/2 id", 2, "hex", True),
            ("Buffer underflows", 4, "u32", False),
            ("Buffer overflows", 4, "u32", False),
        ],
    ),
    276: (
        "GAL Ethernet PM History Data",
        [
            ("Interval end time", 1, "u8", False),
            ("Threshold data 1/2 id", 2, "hex", True),
            ("Discarded frames", 4, "u32", False),
        ],
    ),
    # 9.2.10 Priority queue-G
    277: (
        "Priority queue-G",
        [
            ("Queue configuration option", 1, "u8", False),
            ("Maximum queue size", 2, "u16", False),
            ("Allocated queue size", 2, "u16", False),
            ("Discard-block reset interval", 2, "u16", False),
            ("Threshold value for discarded blocks", 2, "u16", False),
            ("Related port", 4, "hex", False),
            ("Traffic scheduler pointer", 2, "u16", False),
            ("Weight", 1, "u8", False),
            ("Back-pressure operation", 2, "u16", False),
            ("Back-pressure time", 4, "u32", False),
            ("Back-pressure occur counter", 2, "u16", False),
            ("Back-pressure clear counter", 2, "u16", False),
        ],
    ),
    # 9.2.11 Traffic Scheduler-G
    278: (
        "Traffic Scheduler-G",
        [
            ("T-CONT pointer", 2, "u16", False),
            ("Traffic scheduler pointer", 2, "u16", False),
            ("Policy", 1, "u8", False),
            ("Priority/Weight", 1, "u8", False),
        ],
    ),
    # 9.1.10 Protection data
    279: (
        "Protection data",
        [
            ("Working ANI-G pointer", 2, "u16", False),
            ("Protection ANI-G pointer", 2, "u16", False),
            ("Protection type", 2, "u16", False),
            ("Revertive ind", 1, "u8", False),
            ("Wait to restore time", 1, "u8", False),
            ("Switching guard time", 2, "u16", False),
        ],
    ),
    # 9.2.12 Traffic descriptor
    280: (
        "Traffic descriptor",
        [
            ("CIR", 4, "u32", True),
            ("PIR", 4, "u32", True),
            ("CBS", 4, "u32", True),
            ("PBS", 4, "u32", True),
            ("Colour mode", 1, "u8", True),
            ("Ingress colour marking", 1, "u8", True),
            ("Egress colour marking", 1, "u8", True),
            ("Meter type", 1, "u8", True),
        ],
    ),
    # 9.2.5 Multicast GEM interworking termination point
    281: (
        "Multicast GEM interworking termination point",
        [
            ("GEM port network CTP pointer", 2, "u16", True),
            ("Interworking option", 1, "u8", True),
            ("Service profile pointer", 2, "u16", True),
            ("Interworking TP pointer", 2, "u16", True),
            ("PPTP counter", 1, "u8", False),
            ("Operational state", 1, "u8", False),
            ("GAL profile pointer", 2, "u16", True),
            ("GAL loopback configuration", 1, "u8", True),
            ("Multicast address table", 12, "table", False),
        ],
    ),
    # 9.12.8 OMCI
    287: (
        "OMCI",
        [
            ("OMCI ME type table", 2, "table", False),
            ("OMCI message type table", 1, "table", False),
        ],
    ),
    # 9.12.9 Managed entity
    288: (
        "Managed entity",
        [
            ("Name", 25, "str", False),
            ("Attributes table", 2, "table", False),
            ("Access", 1, "u8", False),
            ("Alarms table", 1, "table", False),
            ("AVCs table", 1, "table", False),
            ("Actions", 4, "hex", False),
            ("Instances table", 2, "table", False),
            ("Support", 1, "u8", False),
        ],
    ),
    # 9.12.10 Attribute
    289: (
        "Attribute",
        [
            ("Name", 25, "str", False),
            ("Size", 2, "u16", False),
            ("Access", 1, "u8", False),
            ("Format", 1, "u8", False),
            ("Lower bound", 4, "u32", False),
            ("Upper bound", 4, "u32", False),
            ("Bit field mask", 4, "hex", False),
            ("Code table", 2, "table", False),
            ("Support", 1, "u8", False),
        ],
    ),
    # 9.3.14 Dot1X Port Extension Package
    290: (
        "Dot1X Port Extension Package",
        [
            ("Dot1X enable", 1, "u8", False),
            ("Action Register", 1, "u8", False),
            ("Authenticator PAE state", 1, "u8", False),
            ("Backend authentication state", 1, "u8", False),
            ("Admin controlled directions", 1, "u8", False),
            ("Operational controlled directions", 1, "u8", False),
            ("Authenticator Controlled Port Status", 1, "u8", False),
            ("Quiet period", 2, "u16", False),
            ("Server Timeout Period", 2, "u16", False),
            ("Reauthentication Period", 2, "u16", False),
            ("Reauthentication Enabled", 1, "u8", False),
            ("Key transmission enable", 1, "u8", False),
        ],
    ),
    # 9.3.15 Dot1X configuration profile
    291: (
        "Dot1X configuration profile",
        [
            ("Circuit ID prefix", 2, "hex", False),
            ("Fallback policy", 1, "u8", False),
            ("Auth server 1", 2, "hex", False),
            ("Shared secret auth1", 25, "str", False),
            ("Auth server 2", 2, "hex", False),
            ("Shared secret auth2", 25, "str", False),
            ("Auth server 3", 2, "hex", False),
            ("Shared secret auth3", 25, "str", False),
            ("OLT proxy address", 4, "hex", False),
        ],
    ),
    # 9.3.16 Dot1X performance monitoring history data
    292: (
        "Dot1X performance monitoring history data",
        [
            ("Interval end time", 1, "u8", False),
            ("Threshold data 1/2 id", 2, "hex", True),
            ("EAPOL frames received", 4, "u32", False),
            ("EAPOL frames transmitted", 4, "u32", False),
            ("EAPOL start frames received", 4, "u32", False),
            ("EAPOL logoff frames received", 4, "u32", False),
            ("Invalid EAPOL frames received", 4, "u32", False),
            ("EAP resp/id frames received", 4, "u32", False),
            ("EAP response frames received", 4, "u32", False),
            ("EAP initial request frames transmitted", 4, "u32", False),
            ("EAP request frames transmitted", 4, "u32", False),
            ("EAP length error frames received", 4, "u32", False),
            ("EAP success frames generated autonomously", 4, "u32", False),
            ("EAP failure frames generated autonomously", 4, "u32", False),
        ],
    ),
    # 9.3.17 Radius performance monitoring history data
    293: (
        "Radius performance monitoring history data",
        [
            ("Interval end time", 1, "u8", False),
            ("Threshold data 1/2 id", 2, "hex", True),
            ("Access request packets transmitted", 4, "u32", False),
            ("Access request retransmissions", 4, "u32", False),
            ("Access-challenge packets received", 4, "u32", False),
            ("Access reject packets received", 4, "u32", False),
            ("Access-accept packets received", 4, "u32", False),
            ("Invalid radius packets received", 4, "u32", False),
        ],
    ),
    # 9.5.4 Ethernet PM History Data 3
    296: (
        "Ethernet PM History Data 3",
        [
            ("Interval end time", 1, "u8", False),
            ("Threshold data 1/2 id", 2, "hex", True),
            ("Drop events", 4, "u32", False),
            ("Octets", 4, "u32", False),
            ("Packets", 4, "u32", False),
            ("Broadcast packets", 4, "u32", False),
            ("Multicast packets", 4, "u32", False),
            ("Undersize packets", 4, "u32", False),
            ("Fragments", 4, "u32", False),
            ("Jabbers", 4, "u32", False),
            ("64 octets", 4, "u32", False),
            ("65-127 octets", 4, "u32", False),
            ("128-255 octets", 4, "u32", False),
            ("256-511 octets", 4, "u32", False),
            ("512-1023 octets", 4, "u32", False),
            ("1024-1518 octets", 4, "u32", False),
        ],
    ),
    # 9.1.8 Port mapping package
    297: (
        "Port mapping package",
        [
            ("Max ports", 1, "u8", False),
            ("Port list 1", 16, "hex", False),
            ("Port list 2", 16, "hex", False),
            ("Port list 3", 16, "hex", False),
            ("Port list 4", 16, "hex", False),
            ("Port list 5", 16, "hex", False),
            ("Port list 6", 16, "hex", False),
            ("Port list 7", 16, "hex", False),
            ("Port list 8", 16, "hex", False),
        ],
    ),
    # 9.3.18 Dot1 rate limiter
    298: (
        "Dot1 rate limiter",
        [
            ("Parent ME pointer", 2, "u16", True),
            ("TP type", 1, "u8", True),
            ("Upstream unicast flood rate pointer", 2, "u16", True),
            ("Upstream broadcast rate pointer", 2, "u16", True),
            ("Upstream multicast payload rate pointer", 2, "u16", True),
        ],
    ),
    # 9.3.19 Dot1ag maintenance domain
    299: (
        "Dot1ag maintenance domain",
        [
            ("MD level", 1, "u8", True),
            ("MD name format", 1, "u8", True),
            ("MD name 1, MD name 2", 50, "str", False),
            ("Maintenance intermediate point", 1, "u8", True),
            ("Sender ID permission", 1, "u8", True),
        ],
    ),
    # 9.3.20 Dot1ag maintenance association
    300: (
        "Dot1ag maintenance association",
        [
            ("MD pointer", 2, "u16", True),
            ("Short MA name format", 1, "u8", True),
            ("Short MA name", 50, "str", False),
            ("Continuity check message interval", 1, "u8", True),
            ("Associated VLANs", 24, "hex", False),
            ("MHF creation", 1, "u8", True),
            ("Sender ID permission", 1, "u8", True),
        ],
    ),
    # 9.3.21 Dot1ag default MD level
    301: (
        "Dot1ag default MD level",
        [
            ("Layer 2 type", 1, "u8", False),
            ("Catchall level", 1, "u8", False),
            ("Catchall MHF creation", 1, "u8", False),
            ("Catchall sender ID permission", 1, "u8", False),
            ("Default MD level table", 29, "hex", False),
        ],
    ),
    # 9.3.22 Dot1ag MEP
    302: (
        "Dot1ag MEP",
        [
            ("Layer 2 pointer", 2, "u16", True),
            ("Layer 2 type", 1, "u8", True),
            ("MA pointer", 2, "u16", True),
            ("MEP ID", 2, "u16", True),
            ("MEP control", 1, "u8", True),
            ("Primary VLAN", 2, "u16", True),
            ("Administrative state", 1, "u8", False),
            ("CCM LTM priority", 1, "u8", True),
            ("Egress identifier", 8, "hex", True),
            ("Peer MEP IDs", 24, "str", False),
            ("ETH AIS control", 1, "u8", False),
            ("Fault alarm threshold", 1, "u8", True),
            ("Alarm declaration soak time", 2, "u16", False),
            ("Alarm clear soak time", 2, "u16", False),
        ],
    ),
    # 9.3.23 Dot1ag MEP status
    303: (
        "Dot1ag MEP status",
        [
            ("MEP MAC address", 6, "hex", False),
            ("Fault notification generator state", 1, "u8", False),
            ("Highest priority defect observed", 1, "u8", False),
            ("Current defects", 1, "u8", False),
            ("Last received errored CCM table", 128, "table", False),
            ("Last received xcon CCM table", 128, "table", False),
            ("Out of sequence CCMs count", 4, "u32", False),
            ("CCMs transmitted count", 4, "u32", False),
            ("Unexpected LTRs count", 4, "u32", False),
            ("LBRs transmitted count", 4, "u32", False),
            ("Next loopback transaction identifier", 4, "u32", False),
            ("Next link trace transaction identifier", 4, "u32", False),
        ],
    ),
    # 9.3.24 Dot1ag MEP CCM database
    304: (
        "Dot1ag MEP CCM database",
        [
            ("RMEP 1 database table", 0, "table", False),
            ("RMEP 2 database table", 0, "table", False),
            ("RMEP 3 database table", 0, "table", False),
            ("RMEP 4 database table", 0, "table", False),
            ("RMEP 5 database table", 0, "table", False),
            ("RMEP 6 database table", 0, "table", False),
            ("RMEP 7 database table", 0, "table", False),
            ("RMEP 8 database table", 0, "table", False),
            ("RMEP 9 database table", 0, "table", False),
            ("RMEP 10 database table", 0, "table", False),
            ("RMEP 11 database table", 0, "table", False),
            ("RMEP 12 database table", 0, "table", False),
        ],
    ),
    # 9.3.25 Dot1ag CFM stack
    305: (
        "Dot1ag CFM stack",
        [
            ("Layer 2 type", 1, "u8", False),
            ("MP status table", 18, "hex", False),
            ("Configuration error list table", 5, "hex", False),
        ],
    ),
    # 9.3.26 Dot1ag chassis-management info
    306: (
        "Dot1ag chassis-management info",
        [
            ("Chassis ID length", 1, "u8", False),
            ("Chassis ID sub-type", 1, "u8", False),
            ("Chassis ID part 1, Chassis ID part 2", 50, "str", False),
            ("Management address domain length", 1, "u8", False),
            (
                "Management address domain 1, Management address domain 2",
                50,
                "str",
                False,
            ),
            ("Management address length", 1, "u8", False),
            ("Management address 1, Management address 2", 50, "str", False),
        ],
    ),
    # 9.12.11 Octet string
    307: (
        "Octet string",
        [
            ("Length", 2, "u16", False),
            ("Part 1", 25, "hex", False),
            ("Part 2", 25, "hex", False),
            ("Part 3", 25, "hex", False),
            ("Part 4", 25, "hex", False),
            ("Part 5", 25, "hex", False),
            ("Part 6", 25, "hex", False),
            ("Part 7", 25, "hex", False),
            ("Part 8", 25, "hex", False),
            ("Part 9", 25, "hex", False),
            ("Part 10", 25, "hex", False),
            ("Part 11", 25, "hex", False),
            ("Part 12", 25, "hex", False),
            ("Part 13", 25, "hex", False),
            ("Part 14", 25, "hex", False),
            ("Part 15", 25, "hex", False),
        ],
    ),
    # 9.12.12 General purpose buffer
    308: (
        "General purpose buffer",
        [("Maximum size", 4, "u32", True), ("Buffer table", 1, "table", False)],
    ),
    # 9.3.27 Multicast operations profile
    309: (
        "Multicast operations profile",
        [
            ("IGMP version", 1, "u8", True),
            ("IGMP function", 1, "u8", True),
            ("Immediate leave", 1, "u8", True),
            ("Upstream IGMP TCI", 2, "u16", True),
            ("Upstream IGMP tag control", 1, "u8", True),
            ("Upstream IGMP rate", 4, "u32", True),
            ("Dynamic access control list table", 24, "table", False),
            ("Static access control list table", 24, "table", False),
            ("Lost groups list table", 10, "table", False),
            ("Robustness", 1, "u8", True),
            ("Querier IP address", 4, "u32", True),
            ("Query interval", 4, "u32", True),
            ("Query max response time", 4, "u32", True),
            ("Last member query interval", 4, "u32", False),
            ("Unauthorized join behaviour", 1, "u8", False),
            ("Downstream IGMP TCI", 2, "u16", True),
        ],
    ),
    # 9.3.28 Multicast subscriber config info
    310: (
        "Multicast subscriber config info",
        [
            ("ME type", 1, "hex", True),
            ("Multicast operations profile pointer", 2, "u16", True),
            ("Max simultaneous groups", 2, "u16", True),
            ("Max multicast bandwidth", 4, "u32", True),
            ("Bandwidth enforcement", 1, "u8", True),
            ("Multicast service package table", 20, "table", False),
            ("Allowed preview groups table", 22, "table", False),
        ],
    ),
    # 9.3.29 Multicast Subscriber Monitor
    311: (
        "Multicast Subscriber Monitor",
        [
            ("ME type", 1, "hex", True),
            ("Current multicast bandwidth", 4, "u32", False),
            ("Max Join messages counter", 4, "u32", False),
            ("Bandwidth exceeded counter", 4, "u32", False),
            ("Active groups table", 25, "table", False),
        ],
    ),
    # 9.2.9 FEC PM History Data
    312: (
        "FEC PM History Data",
        [
            ("Interval end time", 1, "u8", False),
            ("Threshold data 1/2 id", 2, "hex", True),
            ("Corrected bytes", 4, "u32", False),
            ("Corrected code words", 4, "u32", False),
            ("Uncorrectable code words", 4, "u32", False),
            ("Total code words", 4, "u32", False),
            ("FEC seconds", 2, "u16", False),
        ],
    ),
    # 9.12.13 File transfer controller
    318: (
        "File transfer controller",
        [
            ("Supported transfer protocols", 2, "hex", False),
            ("File type", 2, "hex", False),
            ("File instanc", 2, "u16", False),
            ("Local file name pointer", 2, "u16", False),
            ("Network address pointer", 2, "u16", False),
            ("File transfer trigger", 1, "u8", False),
            ("File transfer status", 1, "u8", False),
            ("GEM IWTP pointer", 2, "u16", False),
            ("VLAN", 2, "u16", False),
            ("File size", 4, "u32", False),
            ("Directory listing table", 1, "u8", False),
        ],
    ),
    # 9.3.31 Ethernet frame PM History Data DS
    321: (
        "Ethernet Frame PM History Data DS",
        [
            ("Interval end time", 1, "u8", False),
            ("Threshold data 1/2 id", 2, "hex", True),
            ("Drop events", 4, "u32", False),
            ("Octets", 4, "u32", False),
            ("Packets", 4, "u32", False),
            ("Broadcast packets", 4, "u32", False),
            ("Multicast packets", 4, "u32", False),
            ("CRC errored packets", 4, "u32", False),
            ("Undersize packets", 4, "u32", False),
            ("Oversize packets", 4, "u32", False),
            ("64 octets", 4, "u32", False),
            ("65-127 octets", 4, "u32", False),
            ("128-255 octets", 4, "u32", False),
            ("256-511 octets", 4, "u32", False),
            ("512-1023 octets", 4, "u32", False),
            ("1024-1518 octets", 4, "u32", False),
        ],
    ),
    # 9.3.30 Ethernet frame PM History Data US
    322: (
        "Ethernet Frame PM History Data US",
        [
            ("Interval end time", 1, "u8", False),
            ("Threshold data 1/2 id", 2, "hex", True),
            ("Drop events", 4, "u32", False),
            ("Octets", 4, "u32", False),
            ("Packets", 4, "u32", False),
            ("Broadcast packets", 4, "u32", False),
            ("Multicast packets", 4, "u32", False),
            ("CRC errored packets", 4, "u32", False),
            ("Undersize packets", 4, "u32", False),
            ("Oversize packets", 4, "u32", False),
            ("64 octets", 4, "u32", False),
            ("65-127 octets", 4, "u32", False),
            ("128-255 octets", 4, "u32", False),
            ("256-511 octets", 4, "u32", False),
            ("512-1023 octets", 4, "u32", False),
            ("1024-1518 octets", 4, "u32", False),
        ],
    ),
    # 9.5.5 Virtual Ethernet interface point
    329: (
        "Virtual Ethernet interface point",
        [
            ("Administrative state", 1, "u8", False),
            ("Operational state", 1, "u8", False),
            ("Interdomain name", 25, "str", False),
            ("TCP/UDP pointer", 2, "u16", False),
            ("IANA assigned port", 2, "u16", False),
        ],
    ),
    # 9.12.14 Generic status portal
    330: (
        "Generic status portal",
        [
            ("Status document table", 1, "table", False),
            ("Configuration document table", 1, "table", False),
            ("AVC report rate", 1, "u8", False),
        ],
    ),
    # 9.1.13 ONU-E
    331: (
        "ONU-E",
        [
            ("Vendor ID", 4, "str", False),
            ("Version", 14, "str", False),
            ("Serial number", 8, "hex", False),
        ],
    ),
    # 9.13.11 Enhanced security control
    332: (
        "Enhanced security control",
        [
            ("OLT crypto capabilities table", 16, "table", False),
            ("OLT random challenge table", 17, "table", False),
            ("OLT challenge status", 1, "u8", False),
            ("ONU selected crypto capabilities", 1, "u8", False),
            ("ONU random challenge table", 16, "table", False),
            ("ONU authentication response table", 16, "table", False),
            ("OLT authentication result table", 17, "table", False),
            ("OLT result status", 1, "u8", False),
            ("ONU authentication status", 1, "u8", False),
            ("Master session key name", 16, "hex", False),
            ("Broadcast key table", 18, "hex", False),
            ("Effective key length", 2, "u16", False),
        ],
    ),
    # 9.3.32 Ethernet frame extended PM
    334: (
        "Ethernet frame extended PM",
        [
            ("Interval end time", 1, "u8", False),
            ("Control block", 16, "hex", True),
            ("Drop events", 4, "u32", False),
            ("Octets", 4, "u32", False),
            ("Frames", 4, "u32", False),
            ("Broadcast frames", 4, "u32", False),
            ("Multicast frames", 4, "u32", False),
            ("CRC errored frames", 4, "u32", False),
            ("Undersize frames", 4, "u32", False),
            ("Oversize frames", 4, "u32", False),
            ("64 octets", 4, "u32", False),
            ("65-127 octets", 4, "u32", False),
            ("128-255 octets", 4, "u32", False),
            ("256-511 octets", 4, "u32", False),
            ("512-1023 octets", 4, "u32", False),
            ("1024-1518 octets", 4, "u32", False),
        ],
    ),
    # 9.12.15 SNMP configuration data
    335: (
        "SNMP configuration data",
        [
            ("SNMP version", 2, "u16", True),
            ("SNMP agent address", 2, "u16", True),
            ("SNMP server address", 4, "hex", True),
            ("SNMP server port", 2, "u16", True),
            ("Security name pointer", 2, "u16", True),
            ("Community for read", 2, "u16", True),
            ("Community for write", 2, "u16", True),
            ("Sys name pointer", 2, "u16", True),
        ],
    ),
    # 9.1.14 ONU dynamic power management control
    336: (
        "ONU dynamic power management control",
        [
            ("Power reduction management capability", 2, "hex", False),
            ("Power reduction management mode", 1, "u8", False),
            ("Itransinitr", 2, "u16", False),
            ("Itxinit", 2, "u16", False),
            ("Maximum sleep interval", 4, "u32", False),
            ("Minimum aware interval", 4, "u32", False),
            ("Minimum active interval", 4, "u32", False),
        ],
    ),
    # 9.12.16 TR-069 management server
    340: (
        "TR-069 management server",
        [
            ("Administrative state", 1, "u8", False),
            ("ACS network address", 2, "u16", False),
            ("Associated tag", 2, "u16", False),
        ],
    ),
    # 9.3.12 MAC Bridge Port PM History Data
    341: (
        "GEM port network CTP performance monitoring history data",
        [
            ("Interval end time", 1, "u8", False),
            ("Threshold data 1/2 id", 2, "hex", True),
            ("Transmitted GEM frames", 4, "u32", False),
            ("Received GEM frames", 4, "u32", False),
            ("Received payload bytes", 8, "u64", False),
            ("Transmitted payload bytes", 8, "u64", False),
            ("Encryption key errors", 4, "u32", False),
        ],
    ),
    # 9.4.4 TCP/UDP performance monitoring history data
    342: (
        "TCP/UDP performance monitoring history data",
        [
            ("Interval end time", 1, "u8", False),
            ("Threshold data 1/2 id", 2, "hex", True),
            ("Socket failed", 2, "u16", False),
            ("Listen failed", 2, "u16", False),
            ("Bind failed", 2, "u16", False),
            ("Accept failed", 2, "u16", False),
            ("Select failed", 2, "u16", False),
        ],
    ),
    # 9.3.34 Ethernet frame extended PM 64 bit
    425: (
        "Ethernet frame extended PM 64 bit",
        [
            ("Interval end time", 1, "u8", False),
            ("Control block", 16, "hex", True),
            ("Drop events", 8, "u64", False),
            ("Octets", 8, "u64", False),
            ("Frames", 8, "u64", False),
            ("Broadcast frames", 8, "u64", False),
            ("Multicast frames", 8, "u64", False),
            ("CRC errored frames", 8, "u64", False),
            ("Undersize frames", 8, "u64", False),
            ("Oversize frames", 8, "u64", False),
            ("64 octets", 8, "u64", False),
            ("65-127 octets", 8, "u64", False),
            ("128-255 octets", 8, "u64", False),
            ("256-511 octets", 8, "u64", False),
            ("512-1023 octets", 8, "u64", False),
            ("1024-1518 octets", 8, "u64", False),
        ],
    ),
}


SENSITIVE_ME_CLASSES = {
    OMCIClass.SOFTWARE_IMAGE,
    OMCIClass.NETWORK_ADDRESS,
    OMCIClass.VOIP_CONFIG_DATA,
    OMCIClass.VOIP_MEDIA_PROFILE,
    OMCIClass.AUTHENTICATION_SECURITY_METHOD,
    OMCIClass.LARGE_STRING,
    OMCIClass.SIP_AGENT_CONFIG_DATA,
    OMCIClass.SIP_USER_DATA,
    OMCIClass.TR_069_MANAGEMENT_SERVER,
}

SENSITIVE_ME_ATTRIBUTES = {"password", "secret"}


def get_me_name(class_id):
    if class_id in ME_CLASS_NAMES:
        return ME_CLASS_NAMES[class_id]
    if 172 <= class_id <= 239:
        return "Reserved for future B-PON managed entities"
    elif 240 <= class_id <= 255:
        return "Reserved for vendor-specific managed entities"
    elif 350 <= class_id <= 399:
        return "Reserved for vendor-specific use"
    elif 467 <= class_id <= 65279:
        return "Reserved for future standardization"
    elif 65280 <= class_id <= 65535:
        return "Reserved for vendor-specific use"
    else:
        return "None"


class MIBInstance:
    def __init__(self, class_id, inst_id):
        self.class_id = class_id
        self.inst_id = inst_id
        self.attributes = {}
        self.is_unknown = class_id not in ME_SPEC

        if not self.is_unknown:
            _, attr_defs = ME_SPEC[class_id]
            for name, _, _, _ in attr_defs:
                self.attributes[name] = 0
        else:
            self.vendor_data = []  # format [(mask, hex_data)]

    def update(self, mask, data):
        # unknown MEs
        if self.is_unknown:
            self.vendor_data.append((mask, data.hex().upper()))
            return
        # SPEC MEs
        me_name, attr_definitions = ME_SPEC[self.class_id]
        offset = 0
        for i, (attr_name, length, attr_type, sbc) in enumerate(attr_definitions):
            mask_bit = 1 << (15 - i)
            if mask & mask_bit:
                if offset + length > len(data):
                    break
                chunk = data[offset : offset + length]

                if attr_type == "u8":
                    val = chunk[0]
                elif attr_type == "u16":
                    val = struct.unpack(">H", chunk)[0]
                elif attr_type == "u32":
                    val = struct.unpack(">I", chunk)[0]
                elif attr_type == "str":
                    val = chunk.decode("ascii", errors="ignore").strip("\x00 ")
                else:
                    val = chunk.hex().upper()

                if attr_type == "table":
                    if not isinstance(self.attributes.get(attr_name), list):
                        self.attributes[attr_name] = []
                    if val not in self.attributes[attr_name]:
                        self.attributes[attr_name].append(val)
                else:
                    self.attributes[attr_name] = val

                offset += length

    def update_from_create(self, raw_content):
        spec = ME_SPEC.get(self.class_id)
        if not spec:
            return

        attrs_list = spec[1]
        mask = 0
        for i, (attr_name, length, attr_type, sbc) in enumerate(attrs_list):
            if sbc:
                mask |= 0x8000 >> i
        self.update(mask, raw_content)

    def attr_semantic(self, attr_name):
        """
        Retrieves the human-readable semantic value for an attribute.
        Priority: Registered Translator > Hex Formatting or int > Raw String.
        """
        val = self.attributes.get(attr_name)
        if val is None:
            return "N/A"

        translator = OMCISemantic.translator(self.class_id, attr_name)
        if translator:
            try:
                return translator(val)
            except Exception:
                pass

        if isinstance(val, int):
            return f"0x{val:x}"

        return str(val)


# vim: set ts=4 sw=4 et:
