#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
#
# Generate: Single UNI, two VLANs (100 & 200), shared T-CONT
# Based on G.988 Figure II.1.2.1-1
#

import sys
import os
import time
import struct
from scapy.all import wrpcap

# Ensure project modules can be imported
sys.path.append(os.getcwd())
from utils.gen_utils import create_omci, msg_resp, msg_req
from utils.gen_utils import generate_mib_pkts, generate_pcap_from_pkts 
from omci.omci import OmciAction, OmciResult
from omci.omcimib import ME_SPEC
from omci.omcimib import OMCIClass

tid = 1
pkts = []

def build_std_me_data(me_class, attr_mask, attr_values, is_mib_upload=True, is_create=False):
    """
    build me data from ME_SPEC
    :param me_class: ME Class ID (int)
    :param attr_mask: 16-bit Attribute Mask (int)
    :param attr_values:  (attribute list)
    :param is_mib_upload: True return 25 bytes (MIB Upload Next)，False return bytes (Set/Create)
    """
    if me_class not in ME_SPEC:
        return b'\x00' * 25 if is_mib_upload else b''

    _, attr_definitions = ME_SPEC[me_class]
    data = b""
    val_idx = 0

    if not is_mib_upload and not is_create:
        data += attr_mask.to_bytes(2, 'big')

    for i, (attr_name, length, attr_type, sbc) in enumerate(attr_definitions):
        mask_bit = 1 << (15 - i)
        should_pack = False
        if is_create:
            if sbc:
                should_pack = True
        else:
            mask_bit = 1 << (15 - i)
            if attr_mask and (attr_mask & mask_bit):
                should_pack = True
        
        if should_pack:
            if val_idx >= len(attr_values):
                break
            
            val = attr_values[val_idx]
            val_idx += 1
            
            try:
                if attr_type == "u8":
                    data += struct.pack(">B", int(val))
                elif attr_type == "u16":
                    data += struct.pack(">H", int(val))
                elif attr_type == "u32":
                    data += struct.pack(">I", int(val))
                elif attr_type == "str":
                    s_bytes = str(val).encode("ascii", errors="ignore")
                    data += s_bytes.ljust(length, b'\x00')[:length]
                elif attr_type == "hex":
                    if isinstance(val, str):
                        data += bytes.fromhex(val).ljust(length, b'\x00')[:length]
                    else:
                        data += bytes(val).ljust(length, b'\x00')[:length]
                else:
                    data += bytes(val).ljust(length, b'\x00')[:length]
                    
            except Exception as e:
                print(f"[Build Error] ME {me_class} '{attr_name}': {e}")
                data += b'\x00' * length

    if is_mib_upload:
        return data.ljust(25, b'\x00')[:25]
    else:
        return data

def gen_mib_upload_pkts():

    mib_data = [
        (2, 0, 0x8000, b'\x01'),                      # ONT Data: MIB Sync=1
    ]

    # cardholder XG-PON10G and 10G eth
    card_data = build_std_me_data(OMCIClass.CARDHOLDER, 0xF000, [0xEE, 0xEE, 1, "SFU10G"])
    mib_data.append((OMCIClass.CARDHOLDER, 0x0180, 0xF000, card_data))
    card_data = build_std_me_data(OMCIClass.CARDHOLDER, 0x0E00, ["SFU10G", 0, 0])
    mib_data.append((OMCIClass.CARDHOLDER, 0x0180, 0x0E00, card_data))

    card_data = build_std_me_data(OMCIClass.CARDHOLDER, 0xF000, [0x31, 0x31, 1, "SFU10G"])
    mib_data.append((OMCIClass.CARDHOLDER, 0x0101, 0xF000, card_data))
    card_data = build_std_me_data(5, 0x0E00, ["SFU10G", 0, 0])
    mib_data.append((OMCIClass.CARDHOLDER, 0x0101, 0x0E00, card_data))

    # circuit XG-PON10G and 10G eth
    circuit_data = build_std_me_data(OMCIClass.CIRCUIT_PACK, 0xF000, [0xEE, 1, b'\x50\x43\x41\x50\x00\x00\x00\x01', "V1.0"])
    mib_data.append((OMCIClass.CIRCUIT_PACK, 0x0180, 0xF000, circuit_data))
    circuit_data = build_std_me_data(OMCIClass.CIRCUIT_PACK, 0x0F00, [0, 0, 0, 0])
    mib_data.append((OMCIClass.CIRCUIT_PACK, 0x0180, 0x0F00, circuit_data))

    circuit_data = build_std_me_data(OMCIClass.CIRCUIT_PACK, 0xF000, [0x31, 1, b'\x50\x43\x41\x50\x00\x00\x00\x01', "V1.0"])
    mib_data.append((OMCIClass.CIRCUIT_PACK, 0x0101, 0xF000, circuit_data))
    circuit_data = build_std_me_data(OMCIClass.CIRCUIT_PACK, 0x0F00, [0, 0, 0, 0])
    mib_data.append((OMCIClass.CIRCUIT_PACK, 0x0101, 0x0F00, circuit_data))

    # Briefly upload 2 T-CONTs
    tcont_data = build_std_me_data(OMCIClass.T_CONT, 0xE000, [0xFFFF, 1, 1])
    mib_data.append((OMCIClass.T_CONT, 0x8000, 0xE000, tcont_data))
    mib_data.append((OMCIClass.T_CONT, 0x8001, 0xE000, tcont_data))

    # priority queue related port related port 0x80000000 ~ 0x80000007
    pq_data = build_std_me_data(OMCIClass.PRIORITY_QUEUE_G, 0xFFF0,
                                [1, 0xffff, 4, 0, 0, b'\x80\x00\x00\x07', 0, 1, 0, 0, 0xffff, 0])
    mib_data.append((OMCIClass.PRIORITY_QUEUE_G, 0x8000, 0xFFF0, pq_data))
    pq_data = build_std_me_data(OMCIClass.PRIORITY_QUEUE_G, 0xFFF0,
                                [1, 0xffff, 4, 0, 0, b'\x80\x00\x00\x06', 0, 1, 0, 0, 0xffff, 0])
    mib_data.append((OMCIClass.PRIORITY_QUEUE_G, 0x8001, 0xFFF0, pq_data))
    pq_data = build_std_me_data(OMCIClass.PRIORITY_QUEUE_G, 0xFFF0,
                                [1, 0xffff, 4, 0, 0, b'\x80\x00\x00\x05', 0, 1, 0, 0, 0xffff, 0])
    mib_data.append((OMCIClass.PRIORITY_QUEUE_G, 0x8002, 0xFFF0, pq_data))
    pq_data = build_std_me_data(OMCIClass.PRIORITY_QUEUE_G, 0xFFF0,
                                [1, 0xffff, 4, 0, 0, b'\x80\x00\x00\x04', 0, 1, 0, 0, 0xffff, 0])
    mib_data.append((OMCIClass.PRIORITY_QUEUE_G, 0x8003, 0xFFF0, pq_data))
    pq_data = build_std_me_data(OMCIClass.PRIORITY_QUEUE_G, 0xFFF0,
                                [1, 0xffff, 4, 0, 0, b'\x80\x00\x00\x03', 0, 1, 0, 0, 0xffff, 0])
    mib_data.append((OMCIClass.PRIORITY_QUEUE_G, 0x8004, 0xFFF0, pq_data))
    pq_data = build_std_me_data(OMCIClass.PRIORITY_QUEUE_G, 0xFFF0,
                                [1, 0xffff, 4, 0, 0, b'\x80\x00\x00\x02', 0, 1, 0, 0, 0xffff, 0])
    mib_data.append((OMCIClass.PRIORITY_QUEUE_G, 0x8005, 0xFFF0, pq_data))
    pq_data = build_std_me_data(OMCIClass.PRIORITY_QUEUE_G, 0xFFF0,
                                [1, 0xffff, 4, 0, 0, b'\x80\x00\x00\x01', 0, 1, 0, 0, 0xffff, 0])
    mib_data.append((OMCIClass.PRIORITY_QUEUE_G, 0x8006, 0xFFF0, pq_data))
    pq_data = build_std_me_data(OMCIClass.PRIORITY_QUEUE_G, 0xFFF0,
                                [1, 0xffff, 4, 0, 0, b'\x80\x00\x00\x00', 0, 1, 0, 0, 0xffff, 0])
    mib_data.append((OMCIClass.PRIORITY_QUEUE_G, 0x8007, 0xFFF0, pq_data))
    # priority queue related port related port 0x80010000 ~ 0x80010007
    pq_data = build_std_me_data(OMCIClass.PRIORITY_QUEUE_G, 0xFFF0,
                                [1, 0xffff, 4, 0, 0, b'\x80\x01\x00\x07', 0, 1, 0, 0, 0xffff, 0])
    mib_data.append((OMCIClass.PRIORITY_QUEUE_G, 0x8008, 0xFFF0, pq_data))
    pq_data = build_std_me_data(OMCIClass.PRIORITY_QUEUE_G, 0xFFF0,
                                [1, 0xffff, 4, 0, 0, b'\x80\x01\x00\x06', 0, 1, 0, 0, 0xffff, 0])
    mib_data.append((OMCIClass.PRIORITY_QUEUE_G, 0x8009, 0xFFF0, pq_data))
    pq_data = build_std_me_data(OMCIClass.PRIORITY_QUEUE_G, 0xFFF0,
                                [1, 0xffff, 4, 0, 0, b'\x80\x01\x00\x05', 0, 1, 0, 0, 0xffff, 0])
    mib_data.append((OMCIClass.PRIORITY_QUEUE_G, 0x800a, 0xFFF0, pq_data))
    pq_data = build_std_me_data(OMCIClass.PRIORITY_QUEUE_G, 0xFFF0,
                                [1, 0xffff, 4, 0, 0, b'\x80\x01\x00\x04', 0, 1, 0, 0, 0xffff, 0])
    mib_data.append((OMCIClass.PRIORITY_QUEUE_G, 0x800b, 0xFFF0, pq_data))
    pq_data = build_std_me_data(OMCIClass.PRIORITY_QUEUE_G, 0xFFF0,
                                [1, 0xffff, 4, 0, 0, b'\x80\x01\x00\x03', 0, 1, 0, 0, 0xffff, 0])
    mib_data.append((OMCIClass.PRIORITY_QUEUE_G, 0x800c, 0xFFF0, pq_data))
    pq_data = build_std_me_data(OMCIClass.PRIORITY_QUEUE_G, 0xFFF0,
                                [1, 0xffff, 4, 0, 0, b'\x80\x01\x00\x02', 0, 1, 0, 0, 0xffff, 0])
    mib_data.append((OMCIClass.PRIORITY_QUEUE_G, 0x800d, 0xFFF0, pq_data))
    pq_data = build_std_me_data(OMCIClass.PRIORITY_QUEUE_G, 0xFFF0,
                                [1, 0xffff, 4, 0, 0, b'\x80\x01\x00\x01', 0, 1, 0, 0, 0xffff, 0])
    mib_data.append((OMCIClass.PRIORITY_QUEUE_G, 0x800e, 0xFFF0, pq_data))
    pq_data = build_std_me_data(OMCIClass.PRIORITY_QUEUE_G, 0xFFF0,
                                [1, 0xffff, 4, 0, 0, b'\x80\x01\x00\x00', 0, 1, 0, 0, 0xffff, 0])
    mib_data.append((OMCIClass.PRIORITY_QUEUE_G, 0x800f, 0xFFF0, pq_data))
    # priority queue related port related port 0x01010000 ~ 0x01010007 (PPTP)
    pq_data = build_std_me_data(OMCIClass.PRIORITY_QUEUE_G, 0xFFF0,
                                [1, 0xffff, 4, 0, 0, b'\x01\x01\x00\x07', 0, 1, 0, 0, 0xffff, 0])
    mib_data.append((OMCIClass.PRIORITY_QUEUE_G, 0x7, 0xFFF0, pq_data))
    pq_data = build_std_me_data(OMCIClass.PRIORITY_QUEUE_G, 0xFFF0,
                                [1, 0xffff, 4, 0, 0, b'\x01\x01\x00\x06', 0, 1, 0, 0, 0xffff, 0])
    mib_data.append((OMCIClass.PRIORITY_QUEUE_G, 0x6, 0xFFF0, pq_data))
    pq_data = build_std_me_data(OMCIClass.PRIORITY_QUEUE_G, 0xFFF0,
                                [1, 0xffff, 4, 0, 0, b'\x01\x01\x00\x05', 0, 1, 0, 0, 0xffff, 0])
    mib_data.append((OMCIClass.PRIORITY_QUEUE_G, 0x5, 0xFFF0, pq_data))
    pq_data = build_std_me_data(OMCIClass.PRIORITY_QUEUE_G, 0xFFF0,
                                [1, 0xffff, 4, 0, 0, b'\x01\x01\x00\x04', 0, 1, 0, 0, 0xffff, 0])
    mib_data.append((OMCIClass.PRIORITY_QUEUE_G, 0x4, 0xFFF0, pq_data))
    pq_data = build_std_me_data(OMCIClass.PRIORITY_QUEUE_G, 0xFFF0,
                                [1, 0xffff, 4, 0, 0, b'\x01\x01\x00\x03', 0, 1, 0, 0, 0xffff, 0])
    mib_data.append((OMCIClass.PRIORITY_QUEUE_G, 0x3, 0xFFF0, pq_data))
    pq_data = build_std_me_data(OMCIClass.PRIORITY_QUEUE_G, 0xFFF0,
                                [1, 0xffff, 4, 0, 0, b'\x01\x01\x00\x02', 0, 1, 0, 0, 0xffff, 0])
    mib_data.append((OMCIClass.PRIORITY_QUEUE_G, 0x2, 0xFFF0, pq_data))
    pq_data = build_std_me_data(OMCIClass.PRIORITY_QUEUE_G, 0xFFF0,
                                [1, 0xffff, 4, 0, 0, b'\x01\x01\x00\x01', 0, 1, 0, 0, 0xffff, 0])
    mib_data.append((OMCIClass.PRIORITY_QUEUE_G, 0x1, 0xFFF0, pq_data))
    pq_data = build_std_me_data(OMCIClass.PRIORITY_QUEUE_G, 0xFFF0,
                                [1, 0xffff, 4, 0, 0, b'\x01\x01\x00\x00', 0, 1, 0, 0, 0xffff, 0])
    mib_data.append((OMCIClass.PRIORITY_QUEUE_G, 0x0, 0xFFF0, pq_data))
    # Traffic Scheduler-G (278)
    ts_data = build_std_me_data(OMCIClass.TRAFFIC_SCHEDULER_G, 0xF000, [0x8000, 0, 2, 0])
    mib_data.append((OMCIClass.TRAFFIC_SCHEDULER_G, 0x8000, 0xF000, ts_data))
    ts_data = build_std_me_data(OMCIClass.TRAFFIC_SCHEDULER_G, 0xF000, [0x8001, 0, 2, 0])
    mib_data.append((OMCIClass.TRAFFIC_SCHEDULER_G, 0x8001, 0xF000, ts_data))
    # PPTP 10G
    pptp_data = build_std_me_data(OMCIClass.PPTP_ETHERNET_UNI, 0xFF00,
                                 [0x31, 0x31, 0, 0, 0, 0, 0, 0x05ee])
    mib_data.append((OMCIClass.PPTP_ETHERNET_UNI, 0x101, 0xFF00, pptp_data))
    

    return generate_mib_pkts(mib_data)

def gen_provisioning_pkts(start_tid=0x100):
    pkts = []
    tid = start_tid

    # ME 171 for PPTP UNI 1
    pkts.append(create_omci(tid, msg_req(OmciAction.CREATE), OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA, 0x1,
                           content=build_std_me_data(OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA, 0,
                                                     [2, 0x101],
                                                     is_mib_upload=False, is_create=True)))
    pkts.append(create_omci(tid, msg_resp(OmciAction.CREATE),
                            OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA, 1,
                            content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1

    pkts.append(create_omci(tid, msg_req(OmciAction.SET), OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA, 0x1,
                           content=build_std_me_data(OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA, 0x3800,
                                                     [b'\x81\x00', b'\x81\x00', 0],
                                                     is_mib_upload=False)))
    pkts.append(create_omci(tid, msg_resp(OmciAction.SET),
                            OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA, 1,
                            content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1

    pkts.append(create_omci(tid, msg_req(OmciAction.SET), OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA, 0x1,
                           content=build_std_me_data(OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA, 0x0400,
                                                     [b'\xf8\x00\x00\x00\xe8\x00\x00\x00\xc0\x0f\x00\x00\x00\x0f\x00\x00'],
                                                     is_mib_upload=False)))
    pkts.append(create_omci(tid, msg_resp(OmciAction.SET),
                            OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA, 1,
                            content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1

    pkts.append(create_omci(tid, msg_req(OmciAction.SET), OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA, 0x1,
                           content=build_std_me_data(OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA, 0x0400,
                                                     [b'\xe8\x00\x00\x00\xe8\x00\x00\x00\xc0\x0f\x00\x00\x00\x0f\x00\x00'],
                                                     is_mib_upload=False)))
    pkts.append(create_omci(tid, msg_resp(OmciAction.SET),
                            OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA, 1,
                            content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1
   
    # MAC_BRIDGE_SERVICE_PROFILE
    pkts.append(create_omci(tid, msg_req(OmciAction.CREATE), OMCIClass.MAC_BRIDGE_SERVICE_PROFILE, 0x1,
                           content=build_std_me_data(OMCIClass.MAC_BRIDGE_SERVICE_PROFILE, 0,
                                                     [0, 1, 1, 0, 0x2800, 0, 0x1e00, 0, 0, 0],
                                                     is_mib_upload=False, is_create=True)))
    pkts.append(create_omci(tid, msg_resp(OmciAction.CREATE),
                            OMCIClass.MAC_BRIDGE_SERVICE_PROFILE, 1,
                            content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1
    # ME 272 GAL Ethernet
    pkts.append(create_omci(tid, msg_req(OmciAction.CREATE), OMCIClass.GAL_ETHERNET_PROFILE, 10,
                           content=build_std_me_data(OMCIClass.MAC_BRIDGE_PORT_CONFIGURATION_DATA, 0,[0x07d0],is_mib_upload=False, is_create=True)))
    pkts.append(create_omci(tid, msg_resp(OmciAction.CREATE),OMCIClass.GAL_ETHERNET_PROFILE, 10,
                            content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1

    # ME 47 -> PPTP UNI 1
    pkts.append(create_omci(tid, msg_req(OmciAction.CREATE), OMCIClass.MAC_BRIDGE_PORT_CONFIGURATION_DATA, 0x1,
                           content=build_std_me_data(OMCIClass.MAC_BRIDGE_PORT_CONFIGURATION_DATA, 0,
                                                     [1, 1, 1, 0x101, 0x0014, 0x00c8, 0, 0, 1, 0],
                                                     is_mib_upload=False, is_create=True)))
    pkts.append(create_omci(tid, msg_resp(OmciAction.CREATE),
                            OMCIClass.MAC_BRIDGE_PORT_CONFIGURATION_DATA, 1,
                            content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1
    # set T-CONT allocate ID
    pkts.append(create_omci(tid, msg_req(OmciAction.SET), OMCIClass.T_CONT, 0x8000,
                           content=build_std_me_data(OMCIClass.T_CONT, 0x8000,
                                                     [1000],
                                                     is_mib_upload=False)))
    pkts.append(create_omci(tid, msg_resp(OmciAction.SET),
                            OMCIClass.T_CONT, 0x8000,
                            content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1

    # TD 1: 10G (PIR = 1,244,160,000 Bytes/s)
    td_10g_data = [16000, 1244160000, 0, 0, 0, 0, 0, 1]
    pkts.append(create_omci(tid, msg_req(OmciAction.CREATE), OMCIClass.TRAFFIC_DESCRIPTOR, 1,
                           content=build_std_me_data(OMCIClass.TRAFFIC_DESCRIPTOR, 0, td_10g_data, is_mib_upload=False, is_create=True)))
    pkts.append(create_omci(tid, msg_resp(OmciAction.CREATE), OMCIClass.TRAFFIC_DESCRIPTOR, 1,
                            content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1
    
    # TD 2: 100M (PIR = 12,500,000 Bytes/s)
    td_100m_data = [16000, 12500000, 0, 0, 0, 0, 0, 1]
    pkts.append(create_omci(tid, msg_req(OmciAction.CREATE), OMCIClass.TRAFFIC_DESCRIPTOR, 2,
                           content=build_std_me_data(OMCIClass.TRAFFIC_DESCRIPTOR, 0, td_100m_data, is_mib_upload=False, is_create=True)))
    pkts.append(create_omci(tid, msg_resp(OmciAction.CREATE), OMCIClass.TRAFFIC_DESCRIPTOR, 2,
                            content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1
    
    # GEM 1001 connect to T-CONT 0x8000, UP traffic desc -> 0x8007
    gem_1001_data = [1001, 0x8000, 3, 0x8007, 1, 0]
    pkts.append(create_omci(tid, msg_req(OmciAction.CREATE), OMCIClass.GEM_PORT_NETWORK_CTP, 1,
                           content=build_std_me_data(OMCIClass.GEM_PORT_NETWORK_CTP, 0, gem_1001_data, is_mib_upload=False, is_create=True)))
    pkts.append(create_omci(tid, msg_resp(OmciAction.CREATE), OMCIClass.GEM_PORT_NETWORK_CTP, 1,
                            content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1
    
    # GEM 1002 connect to T-CONT 0x8000, UP traffic desc -> 0x8000
    gem_1002_data = [1002, 0x8000, 3, 0x8000, 2, 6]
    pkts.append(create_omci(tid, msg_req(OmciAction.CREATE), OMCIClass.GEM_PORT_NETWORK_CTP, 2,
                           content=build_std_me_data(OMCIClass.GEM_PORT_NETWORK_CTP, 0, gem_1002_data, is_mib_upload=False, is_create=True)))
    pkts.append(create_omci(tid, msg_resp(OmciAction.CREATE), OMCIClass.GEM_PORT_NETWORK_CTP, 2,
                            content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1

    # 8021p and GEM interworking Termination Point
    pdata = [
       0xfffe, # tp poiner
       0xffff, # Interwork TP pointer for P-bit priority 0
       0xffff, # Interwork TP pointer for P-bit priority 1
       0xffff, # Interwork TP pointer for P-bit priority 2
       0xffff, # Interwork TP pointer for P-bit priority 3
       0xffff, # Interwork TP pointer for P-bit priority 4
       0xffff, # Interwork TP pointer for P-bit priority 5
       0xffff, # Interwork TP pointer for P-bit priority 6
       0xffff, # Interwork TP pointer for P-bit priority 7
       1,      # Unmarked frame option
       7,      # Default P-bit marking
       0,      # TP Type
    ]

    # ME 130 inst 1
    pkts.append(create_omci(tid, msg_req(OmciAction.CREATE), OMCIClass.DOT1P_MAPPER_SERVICE_PROFILE, 1,
                           content=build_std_me_data(OMCIClass.DOT1P_MAPPER_SERVICE_PROFILE, 0, pdata, is_mib_upload=False, is_create=True)))
    pkts.append(create_omci(tid, msg_resp(OmciAction.CREATE),
                            OMCIClass.DOT1P_MAPPER_SERVICE_PROFILE, 1,
                            content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1
    # ME 47 -> 8021P inst 1
    pkts.append(create_omci(tid, msg_req(OmciAction.CREATE), OMCIClass.MAC_BRIDGE_PORT_CONFIGURATION_DATA, 0x2,
                           content=build_std_me_data(OMCIClass.MAC_BRIDGE_PORT_CONFIGURATION_DATA, 0,
                                                     [1, 2, 3, 1, 0x0014, 0x00c8, 0, 0, 1, 0],
                                                     is_mib_upload=False, is_create=True)))
    pkts.append(create_omci(tid, msg_resp(OmciAction.CREATE),
                            OMCIClass.MAC_BRIDGE_PORT_CONFIGURATION_DATA, 2,
                            content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1
    # ME 266 GEM -> 1001, 8021P -> 1
    pkts.append(create_omci(tid, msg_req(OmciAction.CREATE), OMCIClass.GEM_INTERWORKING_TERMINATION_POINT, 0x1,
                           content=build_std_me_data(OMCIClass.GEM_INTERWORKING_TERMINATION_POINT, 0,
                                                     [1, 5, 1, 0, 10],
                                                     is_mib_upload=False, is_create=True)))
    pkts.append(create_omci(tid, msg_resp(OmciAction.CREATE),
                            OMCIClass.GEM_INTERWORKING_TERMINATION_POINT, 1,
                            content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1
    # ME 84 VLAN 100
    pkts.append(create_omci(tid, msg_req(OmciAction.CREATE), OMCIClass.VLAN_TAGGING_FILTER_DATA, 0x2,
                           content=build_std_me_data(OMCIClass.VLAN_TAGGING_FILTER_DATA, 0,
                                                     [b'\x00\x64' + b'\00' * 22, 0x10, 1],
                                                     is_mib_upload=False, is_create=True)))
    pkts.append(create_omci(tid, msg_resp(OmciAction.CREATE),
                            OMCIClass.VLAN_TAGGING_FILTER_DATA, 2,
                            content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1
    # 8021P all pbit pointer GEM internetwork 1
    pkts.append(create_omci(tid, msg_req(OmciAction.SET), OMCIClass.DOT1P_MAPPER_SERVICE_PROFILE, 1,
                           content=build_std_me_data(OMCIClass.DOT1P_MAPPER_SERVICE_PROFILE, 0x7f80,
                                                     [1] * 8,
                                                     is_mib_upload=False)))
    pkts.append(create_omci(tid, msg_resp(OmciAction.SET),
                            OMCIClass.DOT1P_MAPPER_SERVICE_PROFILE, 1,
                            content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1

    # ME 130 inst 2
    pkts.append(create_omci(tid, msg_req(OmciAction.CREATE), OMCIClass.DOT1P_MAPPER_SERVICE_PROFILE, 2,
                           content=build_std_me_data(OMCIClass.DOT1P_MAPPER_SERVICE_PROFILE, 0, pdata, is_mib_upload=False, is_create=True)))
    pkts.append(create_omci(tid, msg_resp(OmciAction.CREATE),
                            OMCIClass.DOT1P_MAPPER_SERVICE_PROFILE, 2,
                            content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1
    # ME 47 -> 8021P inst 2
    pkts.append(create_omci(tid, msg_req(OmciAction.CREATE), OMCIClass.MAC_BRIDGE_PORT_CONFIGURATION_DATA, 0x3,
                           content=build_std_me_data(OMCIClass.MAC_BRIDGE_PORT_CONFIGURATION_DATA, 0,
                                                     [1, 3, 3, 2, 0x0014, 0x00c8, 0, 0, 1, 0],
                                                     is_mib_upload=False, is_create=True)))
    pkts.append(create_omci(tid, msg_resp(OmciAction.CREATE),
                            OMCIClass.MAC_BRIDGE_PORT_CONFIGURATION_DATA, 2,
                            content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1
    # ME 266 GEM -> 1002, 8021P -> 2
    pkts.append(create_omci(tid, msg_req(OmciAction.CREATE), OMCIClass.GEM_INTERWORKING_TERMINATION_POINT, 0x2,
                           content=build_std_me_data(OMCIClass.GEM_INTERWORKING_TERMINATION_POINT, 0,
                                                     [2, 5, 2, 0, 10],
                                                     is_mib_upload=False, is_create=True)))
    pkts.append(create_omci(tid, msg_resp(OmciAction.CREATE),
                            OMCIClass.GEM_INTERWORKING_TERMINATION_POINT, 2,
                            content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1
    # ME 84 VLAN 200
    pkts.append(create_omci(tid, msg_req(OmciAction.CREATE), OMCIClass.VLAN_TAGGING_FILTER_DATA, 0x3,
                           content=build_std_me_data(OMCIClass.VLAN_TAGGING_FILTER_DATA, 0,
                                                     [b'\x00\xc8' + b'\00' * 22, 0x10, 1],
                                                     is_mib_upload=False, is_create=True)))
    pkts.append(create_omci(tid, msg_resp(OmciAction.CREATE),
                            OMCIClass.VLAN_TAGGING_FILTER_DATA, 3,
                            content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))

    # 8021P all pbit pointer GEM internetwork 2
    pkts.append(create_omci(tid, msg_req(OmciAction.SET), OMCIClass.DOT1P_MAPPER_SERVICE_PROFILE, 2,
                           content=build_std_me_data(OMCIClass.DOT1P_MAPPER_SERVICE_PROFILE, 0x7f80,
                                                     [2] * 8,
                                                     is_mib_upload=False)))
    pkts.append(create_omci(tid, msg_resp(OmciAction.SET),
                            OMCIClass.DOT1P_MAPPER_SERVICE_PROFILE, 2,
                            content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1

    # ME 171 VLAN 100
    pkts.append(create_omci(tid, msg_req(OmciAction.SET), OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA, 0x1,
                           content=build_std_me_data(OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA, 0x0400,
                                                     [b'\xf8\x00\x00\x00\x80\x32\x00\x00\x40\x0f\x00\x00\x00\x08\x03\x20'],
                                                     is_mib_upload=False)))
    pkts.append(create_omci(tid, msg_resp(OmciAction.SET),
                            OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA, 1,
                            content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1
    # ME 171 VLAN 200 
    pkts.append(create_omci(tid, msg_req(OmciAction.SET), OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA, 0x1,
                           content=build_std_me_data(OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA, 0x0400,
                                                     [b'\xf8\x00\x00\x00\x80\x64\x00\x00\x40\x0f\x00\x00\x00\x08\x06\x40'],
                                                     is_mib_upload=False)))
    pkts.append(create_omci(tid, msg_resp(OmciAction.SET),
                            OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA, 1,
                            content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1



    return pkts

def main():
    #gen_mib_upload_pkts()
    mib_uploads_pkts, tid = gen_mib_upload_pkts()
    mib_actions_pkts = gen_provisioning_pkts(tid)
    generate_pcap_from_pkts("single_unit_1_tont_2_gem.pcap", mib_uploads_pkts + mib_actions_pkts)


if __name__ == "__main__":
    main()
