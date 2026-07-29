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


C001_OUTPUT = Path("examples/issues/case_02_c001_vendor_missing.pcap")
D001_OUTPUT = Path("examples/issues/case_02_golden_d001_vendor_ok.pcap")
PPTP_INSTANCE_ID = 0x0101
CAPTURE_START_TIME = 1_700_000_100.0
SET_TRANSACTION_ID = 0x0100


def build_mib_data(
    equipment_id: str, include_vendor_me: bool
) -> list[tuple[int, int, int, bytes]]:
    """Build the reduced standard MIB and optional golden vendor record."""
    mib_data = [
        (OMCIClass.ONT_G, 0, 0x8000, b"SYN2"),
        (OMCIClass.ONT2_G, 0, 0x4000, b"\xa0"),
        (
            OMCIClass.CARDHOLDER,
            PPTP_INSTANCE_ID,
            0x1000,
            equipment_id.encode("ascii").ljust(20, b"\x00"),
        ),
        (OMCIClass.ANI_G, 0x8000, 0x4000, b"\x00\x01"),
        (
            OMCIClass.PPTP_ETHERNET_UNI,
            PPTP_INSTANCE_ID,
            0xFF00,
            b"\x2f\x2f\x00\x00\x01\x00\x00\x05\xee",
        ),
    ]
    if include_vendor_me:
        mib_data.append((65535, 1, 0xF000, b"\x01\x33\x34\x35\x00\x00\x01"))
    return mib_data


def generate_packets(equipment_id: str, include_vendor_me: bool) -> list[Packet]:
    """Build one deterministic CASE-02 request/response sequence."""
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
    upload_packets, _ = generate_mib_pkts(
        build_mib_data(equipment_id, include_vendor_me), start_tid=2
    )
    packets.extend(upload_packets)

    packets.append(
        create_omci(
            SET_TRANSACTION_ID,
            msg_req(OmciAction.SET),
            OMCIClass.PPTP_ETHERNET_UNI,
            PPTP_INSTANCE_ID,
            content=b"\x08\x00\x00",
        )
    )
    packets.append(
        create_omci(
            SET_TRANSACTION_ID,
            msg_resp(OmciAction.SET),
            OMCIClass.PPTP_ETHERNET_UNI,
            PPTP_INSTANCE_ID,
            content=bytes([OmciResult.SUCCESS]),
            is_from_olt=False,
        )
    )

    for index, packet in enumerate(packets):
        packet.time = CAPTURE_START_TIME + index * 0.05

    return packets


def main() -> None:
    """Generate the failing C001 and golden D001 captures."""
    generate_pcap_from_pkts(
        str(C001_OUTPUT), generate_packets("C001", include_vendor_me=False)
    )
    generate_pcap_from_pkts(
        str(D001_OUTPUT), generate_packets("D001", include_vendor_me=True)
    )


if __name__ == "__main__":
    main()
