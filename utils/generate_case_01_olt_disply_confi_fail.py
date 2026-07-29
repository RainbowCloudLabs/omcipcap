#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

from pathlib import Path
import sys

from scapy.packet import Packet

sys.path.append(str(Path(__file__).resolve().parents[1]))

from omci.omci import OmciAction, OmciResult
from omci.omcimib import OMCIClass
from utils.gen_utils import (
    create_omci,
    generate_mib_pkts,
    generate_pcap_from_pkts,
    msg_req,
    msg_resp,
)


OUTPUT_PATH = Path("examples/issues/case_01_olt_disply_confi_fail.pcap")
PPTP_INSTANCE_ID = 0x0101
PPTP_ADMIN_STATE_MASK = 0x0800
CAPTURE_START_TIME = 1_700_000_000.0


def generate_packets() -> list[Packet]:
    """Build the minimum deterministic packet sequence for CASE-01."""
    packets = [
        create_omci(1, OmciAction.MIB_RESET, 2, 0),
        create_omci(
            1,
            msg_resp(OmciAction.MIB_RESET),
            2,
            0,
            content=bytes([OmciResult.SUCCESS]),
            is_from_olt=False,
        ),
    ]

    mib_data = [
        (OMCIClass.ONT_G, 0, 0x8000, b"SYN1"),
        (OMCIClass.ONT2_G, 0, 0x4000, b"\xa0"),
        (OMCIClass.ANI_G, 0x8000, 0x4000, b"\x00\x01"),
        (
            OMCIClass.PPTP_ETHERNET_UNI,
            PPTP_INSTANCE_ID,
            0xFF00,
            b"\x2f\x2f\x00\x00\x01\x00\x00\x05\xee",
        ),
    ]
    upload_packets, next_tid = generate_mib_pkts(mib_data, start_tid=2)
    packets.extend(upload_packets)

    packets.append(
        create_omci(
            next_tid,
            msg_req(OmciAction.SET),
            OMCIClass.PPTP_ETHERNET_UNI,
            PPTP_INSTANCE_ID,
            content=PPTP_ADMIN_STATE_MASK.to_bytes(2, "big") + b"\x00",
        )
    )
    packets.append(
        create_omci(
            next_tid,
            msg_resp(OmciAction.SET),
            OMCIClass.PPTP_ETHERNET_UNI,
            PPTP_INSTANCE_ID,
            content=bytes([OmciResult.SUCCESS]),
            is_from_olt=False,
        )
    )

    for index, packet in enumerate(packets):
        packet.time = CAPTURE_START_TIME + index * 0.05
    packets[-1].time = float(packets[-2].time) + 1.2

    return packets


def main() -> None:
    """Write the CASE-01 capture to the examples issue directory."""
    generate_pcap_from_pkts(str(OUTPUT_PATH), generate_packets())


if __name__ == "__main__":
    main()
