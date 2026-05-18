#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.

import sys
import os

sys.path.append(os.getcwd())
from utils.gen_utils import generate_mib_pkts, generate_pcap_from_pkts


def main():
    # IP Host Config (Class 134): Mask 0x4000 = IP Address (4 bytes)
    ip_before = b"\x00\x00\x00\x00"
    ip_after = b"\xc0\xa8\x01\x0a"  # 192.168.1.10

    # Cardholder (Class 5): Mask 0x8000 = Actual Type (1 byte)
    card_type_base = b"\x30"  # Type 48
    card_type_new = b"\x31"  # Type 49

    # --- Pcap 1:
    mib_v1 = [
        (2, 0, 0x8000, b"\x01"),  # ONT Data: MIB Sync=1
        (134, 1, 0x4000, ip_before),  # IP Host: 0.0.0.0
        (5, 257, 0x8000, card_type_base),  # Cardholder: Type 48
        (5, 258, 0x8000, b"\x47"),  # Cardholder: Type 47
    ]
    pkts, _ = generate_mib_pkts(mib_v1)
    generate_pcap_from_pkts("mib_before.pcap", pkts)

    # --- Pcap 2:
    mib_v2 = [
        (2, 0, 0x8000, b"\x01"),  # ONT Data: MIB Sync=1
        (134, 1, 0x4000, ip_after),  # IP Host: 192.168.1.10
        (5, 257, 0x8000, card_type_new),  # Cardholder: Type 49
        (262, 1, 0x8000, b"\x04\x00"),  # T-CONT 1: Alloc-ID 1024
    ]
    pkts, _ = generate_mib_pkts(mib_v2)
    generate_pcap_from_pkts("mib_after.pcap", pkts)

    # --- Pcap 3:
    mib_omcc_96 = [
        (256, 0, 0x8000, b"ALCL"),  # ONT-G: Vendor
        (257, 0, 0x4000, b"\x96"),  # ONT2-G: OMCC Version = 0x96 (G.988 2010)
        (263, 1, 0x4000, b"\x00\x08"),  # ANI-G: Total T-CONT = 8
    ]
    pkts, _ = generate_mib_pkts(mib_omcc_96)
    generate_pcap_from_pkts("mib_omcc_96.pcap", pkts)

    # --- Pcap 4:
    mib_omcc_a0 = [
        (256, 0, 0x8000, b"ALCL"),
        (257, 0, 0x4000, b"\xa0"),  # ONT2-G: OMCC Version = 0xA0 (G.988 2012)
        (263, 1, 0x4000, b"\x00\x10"),  # ANI-G: Total T-CONT = 16
        (262, 1, 0x8000, b"\x04\x01"),  # T-CONT
    ]
    pkts, _ = generate_mib_pkts(mib_omcc_a0)
    generate_pcap_from_pkts("mib_omcc_a0.pcap", pkts)

    # --- Pcap 5:
    mib_vendor_v1 = [
        (256, 0, 0x8000, b"HWTC"),
        (257, 0, 0x4000, b"\xa0"),  # ONT2-G: OMCC Version = 0xA0 (G.988 2012)
        (355, 0, 0xC000, b"\x48\x47\x55\x01"),  # Mock Vendor 355 ME
    ]
    pkts, _ = generate_mib_pkts(mib_vendor_v1)
    generate_pcap_from_pkts("mib_vendor_v1.pcap", pkts)

    # --- Pcap 6:
    mib_vendor_v2 = [
        (256, 0, 0x8000, b"HWTC"),
        (257, 0, 0x4000, b"\xa0"),  # ONT2-G: OMCC Version = 0xA0 (G.988 2012)
        (355, 0, 0xC000, b"\x53\x46\x55\x00"),  # Mock Vendor 355 ME
    ]
    pkts, _ = generate_mib_pkts(mib_vendor_v2)
    generate_pcap_from_pkts("mib_vendor_v2.pcap", pkts)

    # --- Pcap 7:
    mib_mask_c = [
        (256, 0, 0x8000, b"HWTC"),
        (257, 0, 0x4000, b"\xa0"),  # ONT2-G: OMCC Version = 0xA0 (G.988 2012)
        (355, 0, 0xC000, b"\x48\x47\x55\x01"),  # Mock Vendor 355 ME
    ]
    pkts, _ = generate_mib_pkts(mib_mask_c)
    generate_pcap_from_pkts("mib_mask_c000.pcap", pkts)

    # --- Pcap 8:
    mib_mask_8 = [
        (256, 0, 0x8000, b"HWTC"),
        (257, 0, 0x4000, b"\xa0"),  # ONT2-G: OMCC Version = 0xA0 (G.988 2012)
        (355, 0, 0x8000, b"\x00\x00\x00\x01"),  # Mock Vendor 355 ME
    ]
    pkts, _ = generate_mib_pkts(mib_mask_8)
    generate_pcap_from_pkts("mib_mask_8000.pcap", pkts)

    print("\nSuccess! Now you can run:")
    print("omcipcap diff mib_before.pcap mib_after.pcap")
    print("omcipcap diff mib_omcc_96.pcap mib_omcc_a0.pcap")
    print("omcipcap diff mib_vendor_v1.pcap  mib_vendor_v2.pcap")
    print("omcipcap diff mib_mask_c000.pcap  mib_mask_8000.pcap")


if __name__ == "__main__":
    main()

# vim: set ts=4 sw=4 et:
