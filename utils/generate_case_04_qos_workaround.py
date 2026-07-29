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
from utils.generate_dual_gem_shared_tcont import build_std_me_data


FAILURE_OUTPUT = Path("examples/issues/case_04_qos_applied_1g_failure.pcap")
WORKAROUND_OUTPUT = Path(
    "examples/issues/case_04_qos_unrestricted_10g_workaround.pcap"
)
CAPTURE_START_TIME = 1_700_000_200.0
TCONT_INSTANCE = 0x8000
GEM_INSTANCE = 1
PPTP_INSTANCE = 0x0101
DOWNSTREAM_PQ = 0
SHAPED_UPSTREAM_PQ = 0x8007
UNRESTRICTED_UPSTREAM_PQ = 0x801C


def build_mib_data() -> list[tuple[int, int, int, bytes]]:
    """Build the common reduced baseline copied from the reference topology."""
    card_data = build_std_me_data(
        OMCIClass.CARDHOLDER, 0xF000, [0x31, 0x31, 1, "SFU10G"]
    )
    card_equipment_data = build_std_me_data(
        OMCIClass.CARDHOLDER, 0x0E00, ["SFU10G", 0, 0]
    )
    tcont_data = build_std_me_data(
        OMCIClass.T_CONT, 0xE000, [0xFFFF, 1, 1]
    )
    downstream_pq_data = build_std_me_data(
        OMCIClass.PRIORITY_QUEUE_G,
        0xFFF0,
        [1, 0xFFFF, 4, 0, 0, b"\x01\x01\x00\x00", 0, 1, 0, 0, 0xFFFF, 0],
    )
    shaped_pq_data = build_std_me_data(
        OMCIClass.PRIORITY_QUEUE_G,
        0xFFF0,
        [1, 0xFFFF, 4, 0, 0, b"\x80\x00\x00\x07", 0, 1, 0, 0, 0xFFFF, 0],
    )
    unrestricted_pq_data = build_std_me_data(
        OMCIClass.PRIORITY_QUEUE_G,
        0xFFF0,
        [1, 0xFFFF, 4, 0, 0, b"\x80\x00\x00\x1c", 0, 1, 0, 0, 0xFFFF, 0],
    )
    pptp_data = build_std_me_data(
        OMCIClass.PPTP_ETHERNET_UNI,
        0xFF00,
        [0x31, 0x31, 0, 0, 0, 0, 0, 0x05EE],
    )

    return [
        (OMCIClass.CARDHOLDER, PPTP_INSTANCE, 0xF000, card_data),
        (OMCIClass.CARDHOLDER, PPTP_INSTANCE, 0x0E00, card_equipment_data),
        (OMCIClass.T_CONT, TCONT_INSTANCE, 0xE000, tcont_data),
        (OMCIClass.T_CONT, TCONT_INSTANCE + 1, 0xE000, tcont_data),
        (
            OMCIClass.PRIORITY_QUEUE_G,
            DOWNSTREAM_PQ,
            0xFFF0,
            downstream_pq_data,
        ),
        (
            OMCIClass.PRIORITY_QUEUE_G,
            SHAPED_UPSTREAM_PQ,
            0xFFF0,
            shaped_pq_data,
        ),
        (
            OMCIClass.PRIORITY_QUEUE_G,
            UNRESTRICTED_UPSTREAM_PQ,
            0xFFF0,
            unrestricted_pq_data,
        ),
        (OMCIClass.PPTP_ETHERNET_UNI, PPTP_INSTANCE, 0xFF00, pptp_data),
    ]


def append_successful_operation(
    packets: list[Packet],
    transaction_id: int,
    action: OmciAction,
    me_class: int,
    instance_id: int,
    content: bytes,
    timestamp: float,
) -> None:
    """Append one successful request/response pair at fixed timestamps."""
    request = create_omci(
        transaction_id,
        msg_req(action),
        me_class,
        instance_id,
        content=content,
    )
    request.time = timestamp
    packets.append(request)

    response = create_omci(
        transaction_id,
        msg_resp(action),
        me_class,
        instance_id,
        content=bytes([OmciResult.SUCCESS]),
        is_from_olt=False,
    )
    response.time = timestamp + 0.05
    packets.append(response)


def generate_packets(apply_upstream_descriptor: bool) -> list[Packet]:
    """Build one CASE-04 capture with the selected upstream QoS association."""
    packets, _ = generate_mib_pkts(build_mib_data())
    for index, packet in enumerate(packets):
        packet.time = CAPTURE_START_TIME + index * 0.05

    append_successful_operation(
        packets,
        0x0100,
        OmciAction.CREATE,
        OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA,
        1,
        build_std_me_data(
            OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA,
            0,
            [2, PPTP_INSTANCE],
            is_mib_upload=False,
            is_create=True,
        ),
        CAPTURE_START_TIME + 2.0,
    )
    append_successful_operation(
        packets,
        0x0101,
        OmciAction.SET,
        OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA,
        1,
        build_std_me_data(
            OMCIClass.EXTENDED_VLAN_TAGGING_OPERATION_CONFIGURATION_DATA,
            0x0400,
            [b"\xf8\x00\x00\x00\x80\x05\x00\x00\x40\x0f\x00\x00\x00\x08\x00\x50"],
            is_mib_upload=False,
        ),
        CAPTURE_START_TIME + 2.1,
    )
    append_successful_operation(
        packets,
        0x0102,
        OmciAction.SET,
        OMCIClass.T_CONT,
        TCONT_INSTANCE,
        build_std_me_data(
            OMCIClass.T_CONT,
            0x8000,
            [1000],
            is_mib_upload=False,
        ),
        CAPTURE_START_TIME + 2.2,
    )

    if apply_upstream_descriptor:
        append_successful_operation(
            packets,
            0x0103,
            OmciAction.CREATE,
            OMCIClass.TRAFFIC_DESCRIPTOR,
            1,
            build_std_me_data(
                OMCIClass.TRAFFIC_DESCRIPTOR,
                0,
                [16000, 1244160000, 0, 0, 0, 0, 0, 1],
                is_mib_upload=False,
                is_create=True,
            ),
            CAPTURE_START_TIME + 2.3,
        )

    upstream_pq = (
        SHAPED_UPSTREAM_PQ
        if apply_upstream_descriptor
        else UNRESTRICTED_UPSTREAM_PQ
    )
    upstream_descriptor = 1 if apply_upstream_descriptor else 0
    append_successful_operation(
        packets,
        0x0104,
        OmciAction.CREATE,
        OMCIClass.GEM_PORT_NETWORK_CTP,
        GEM_INSTANCE,
        build_std_me_data(
            OMCIClass.GEM_PORT_NETWORK_CTP,
            0,
            [
                1001,
                TCONT_INSTANCE,
                3,
                upstream_pq,
                upstream_descriptor,
                DOWNSTREAM_PQ,
            ],
            is_mib_upload=False,
            is_create=True,
        ),
        CAPTURE_START_TIME + 2.4,
    )
    return packets


def main() -> None:
    """Generate the shaped failure case and unrestricted workaround capture."""
    generate_pcap_from_pkts(
        str(FAILURE_OUTPUT), generate_packets(apply_upstream_descriptor=True)
    )
    generate_pcap_from_pkts(
        str(WORKAROUND_OUTPUT), generate_packets(apply_upstream_descriptor=False)
    )


if __name__ == "__main__":
    main()
