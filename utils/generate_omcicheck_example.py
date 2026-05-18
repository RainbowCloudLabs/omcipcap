#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.

import sys
import os
import time
from scapy.all import wrpcap

# Ensure project modules can be imported
sys.path.append(os.getcwd())
from utils.gen_utils import create_omci, msg_resp, msg_req
from omci.omci import OmciAction, OmciResult

def main():
    pkts = []
    tid = 1
    print(f"Generating full scenario: MIB Sync -> Service Provisioning...")

    # --- Phase 1: MIB Reset ---
    # OLT commands ONU to reset its MIB
    pkts.append(create_omci(tid, OmciAction.MIB_RESET, 2, 0))
    pkts.append(create_omci(tid, msg_resp(OmciAction.MIB_RESET), 2, 0, content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1

    # --- Phase 2: MIB Upload (Bulk reporting) ---
    # OLT initiates MIB upload to synchronize database
    # Define your MIB entities in an array (list of tuples)
    # Format: (Class ID, Instance ID)
    mib_entities = [
        (2, 0x0),     # ONT-G
        (5, 0x180),     # Cardholder 
        (5, 0x180),     # Cardholder 
        (5, 0x101),     # Cardholder 
        (5, 0x101),     # Cardholder 
        (5, 0x102),     # Cardholder 
        (5, 0x102),     # Cardholder 
        (6, 0x180),     # Circuit Pack
        (6, 0x180),     # Circuit Pack
        (6, 0x101),     # Circuit Pack
        (6, 0x101),     # Circuit Pack
        (6, 0x102),     # Circuit Pack
        (6, 0x102),     # Circuit Pack
        (329, 0xa01),   # VEIP
        (7, 0),     # Software image
        (7, 1),     # Software image
        (241, 1),   # Vendor Specific ME 1
        (350, 1),   # Vendor Specific ME 2
        (84, 1),    # VLAN tagging filter data
        (134, 0),   # IP host config data
        (134, 0),   # IP host config data
        (134, 1),   # IP host config data
        (134, 1),   # IP host config data
        (500, 0xa),   # Feature/Reserved ME
    ]

    total_entities = len(mib_entities)
    pkts.append(create_omci(tid, OmciAction.MIB_UPLOAD, 2, 0))
    pkts.append(create_omci(tid, msg_resp(OmciAction.MIB_UPLOAD), 2, 0, content=total_entities.to_bytes(2, 'big') + bytes([0]*26), is_from_olt=False))
    tid += 1


    # Simulate a stream of MIB Upload Next messages
    for i, (me_class, me_inst) in enumerate(mib_entities):
        # OLT requests the next entity
        pkts.append(create_omci(tid, OmciAction.MIB_UPLOAD_NEXT, 2, 0))

        # ONU reports the entity from our array
        # In MIB Upload Next Response, Class and Instance are in the content
        upload_content = me_class.to_bytes(2, 'big') + me_inst.to_bytes(2, 'big')
        pkts.append(create_omci(tid, msg_resp(OmciAction.MIB_UPLOAD_NEXT), 2, 0,
                               content=upload_content, is_from_olt=False))
        tid += 1

    # --- Phase 3: Service Provisioning (IPHost & VLAN) ---
    # Simulate OLT configuring services after sync
    
    # Set IP Host Config Data (Succes)
    pkts.append(create_omci(tid, msg_req(OmciAction.SET), 134, 1, is_from_olt=True))
    pkts.append(create_omci(tid, msg_resp(OmciAction.SET), 134, 1, content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1

    # Create VLAN Tagging Filter Data (Success)
    pkts.append(create_omci(tid, msg_req(OmciAction.CREATE), 84, 1, is_from_olt=True))
    pkts.append(create_omci(tid, msg_resp(OmciAction.CREATE), 84, 1, content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False))
    tid += 1

    # Create VLAN Tagging Filter Data (Instace Exist)
    pkts.append(create_omci(tid, msg_req(OmciAction.CREATE), 84, 1, is_from_olt=True))
    pkts.append(create_omci(tid, msg_resp(OmciAction.CREATE), 84, 1, content=bytes([OmciResult.INSTANCE_EXISTS] + [0]*27), is_from_olt=False))
    tid += 1

    # Simulate a failure: OLT tries to Set a Vendor ME that ONU rejects
    pkts.append(create_omci(tid, msg_req(OmciAction.SET), 241, 1, is_from_olt=True))
    # ONU responds with UNKNOWN_ME (4) error
    pkts.append(create_omci(tid, msg_resp(OmciAction.SET), 241, 1, content=bytes([OmciResult.UNKNOWN_ME] + [0]*27), is_from_olt=False))
    tid += 1

    # Test case (LATE) ---
    curr_time = time.time()
    curr_time += 1.0
    req = create_omci(tid, msg_req(OmciAction.GET), 257, 0, is_from_olt=True)
    req.time = curr_time
    pkts.append(req)

    resp = create_omci(tid, msg_resp(OmciAction.GET), 257, 0, content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False)
    resp.time = curr_time + 1.2
    pkts.append(resp)
    tid += 1

    # --- Test case (TID_DUPLICATE)
    curr_time = time.time()
    req1 = create_omci(tid, msg_req(OmciAction.GET), 257, 0, is_from_olt=True)
    req1.time = curr_time
    pkts.append(req1)

    req2 = create_omci(tid, msg_req(OmciAction.GET), 257, 0, is_from_olt=True)
    req2.time = curr_time + 0.1
    pkts.append(req2)

    resp = create_omci(tid, msg_resp(OmciAction.GET), 257, 0, content=bytes([OmciResult.SUCCESS] + [0]*27), is_from_olt=False)
    resp.time = curr_time + 0.2
    pkts.append(resp)

    # Save to file
    output_file = "omcicheck_example.pcap"
    wrpcap(output_file, pkts)
    print(f"\nGenerated {len(pkts)} packets in {output_file}")
    print(f"Run analysis: omcipcap check {output_file}")

if __name__ == "__main__":
    main()

# vim: set ts=4 sw=4 et:
