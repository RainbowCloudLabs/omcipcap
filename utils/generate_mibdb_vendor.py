#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.

import sys
import os

sys.path.append(os.getcwd())
from utils.gen_utils import generate_mib_pkts, generate_pcap_from_pkts
from utils.gen_utils import create_omci, msg_resp, msg_req
from omci.omci import OmciAction, OmciResult


def main():
    # MIB upload 65300
    mib_vendor_65300 = [
        (2, 0, 0x8000, b"\x01"),  # ONT Data: MIB Sync=1
        (257, 0, 0x4000, b"\xa0"),  # ONT2-G: OMCC Version = 0x96 (G.988 2010)
        (263, 1, 0x4000, b"\x00\x08"),  # ANI-G: Total T-CONT = 8
        (65300, 0x1, 0xF800, b"CTC\x00\x00\x01\x00\x01\x00\x00"),
    ]
    pkts, tid = generate_mib_pkts(mib_vendor_65300)
    # MIB SET 65400
    pkts.append(
        create_omci(
            tid,
            msg_req(OmciAction.SET),
            65400,
            0x1,
            content=b"\xc0\x00v1.0.5\x00\x00\x01",
        )
    )
    pkts.append(
        create_omci(
            tid,
            msg_resp(OmciAction.SET),
            65400,
            0x1,
            content=bytes([OmciResult.SUCCESS] + [0] * 27),
            is_from_olt=False,
        )
    )
    generate_pcap_from_pkts("mibdb_vendor.pcap", pkts)


if __name__ == "__main__":
    main()
