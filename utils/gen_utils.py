#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.

from scapy.all import Ether, Raw, wrpcap
import sys
import os
sys.path.append(os.getcwd())
from omci.omci import OmciAction

OLT_MAC = "00:00:00:00:00:02"
ONU_MAC = "00:00:00:00:00:01"

def msg_resp(action_val):
    return action_val | 0x20

def msg_req(action_val):
    return action_val | 0x40

def create_omci(tid, msg_type, me_class, inst_id, content=None, is_from_olt=True):
    """
    Directly pack the OMCI fields into a 48-byte binary buffer.
    No need for OMCIBaseline object creation during pcap generation.
    """
    # Header (8 bytes)
    header = tid.to_bytes(2, 'big')
    header += int(msg_type).to_bytes(1, 'big')
    header += b'\x0a'  # Device ID
    header += me_class.to_bytes(2, 'big')
    header += inst_id.to_bytes(2, 'big')

    # Content (32 bytes)
    if content is None:
        content = b'\x00' * 32
    else:
        content = content.ljust(32, b'\x00')

    # Trailer (4 bytes)
    trailer = b'\x00\x00\x00\x28'

    raw_payload = header + content + trailer

    # Encapsulate with Ethernet
    src = OLT_MAC if is_from_olt else ONU_MAC
    dst = ONU_MAC if is_from_olt else OLT_MAC

    # Using Raw() ensures Scapy treats the 48 bytes as the payload
    return Ether(dst=dst, src=src, type=0x88B5) / Raw(load=raw_payload)

def generate_mib_pkts(mib_data_list, start_tid=1):
    """
    mib_data_list: list of tuples (class_id, inst_id, attr_mask, data_bytes)
    """
    pkts = []
    tid = start_tid

    pkts.append(create_omci(tid, OmciAction.MIB_UPLOAD, 2, 0))
    num_entities = len(mib_data_list)
    pkts.append(create_omci(tid, msg_resp(OmciAction.MIB_UPLOAD), 2, 0,
                           content=num_entities.to_bytes(2, 'big'), is_from_olt=False))
    tid += 1

    for me_class, me_inst, mask, data in mib_data_list:
        pkts.append(create_omci(tid, OmciAction.MIB_UPLOAD_NEXT, 2, 0))

        upload_content = (me_class.to_bytes(2, 'big') +
                         me_inst.to_bytes(2, 'big') +
                         mask.to_bytes(2, 'big') +
                         data)

        pkts.append(create_omci(tid, msg_resp(OmciAction.MIB_UPLOAD_NEXT), 2, 0,
                               content=upload_content, is_from_olt=False))
        tid += 1

    return pkts, tid

def generate_pcap_from_pkts(filename, pkts):
    wrpcap(filename, pkts)
    print(f"Generated {filename} with {len(pkts)} OMCI packets.")

# vim: set ts=4 sw=4 et:
