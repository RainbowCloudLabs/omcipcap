#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

from scapy.all import rdpcap
from enum import IntEnum


class OmciAction(IntEnum):
    """ITU-T G.988 Table 11.2.2-1 (Action ID)"""

    CREATE = 4
    DELETE = 6
    SET = 8
    GET = 9
    GET_ALL_ALARMS = 11
    GET_ALL_ALARMS_NEXT = 12
    MIB_UPLOAD = 13
    MIB_UPLOAD_NEXT = 14
    MIB_RESET = 15
    ALARM = 16
    ATTRIBUTE_VALUE_CHANGE = 17
    TEST = 18
    START_SOFTWARE_DOWNLOAD = 19
    DOWNLOAD_SECTION = 20
    END_SOFTWARE_DOWNLOAD = 21
    ACTIVATE_SOFTWARE = 22
    COMMIT_SOFTWARE = 23
    SYNCHRONIZE_TIME = 24
    REBOOT = 25
    GET_NEXT = 26
    TEST_RESULT = 27
    GET_CURRENT_DATA = 28
    SET_TABLE = 29


class OmciResult(IntEnum):
    """OMCI Result codes"""

    SUCCESS = 0
    PROCESSING_ERROR = 1
    NOT_SUPPORTED = 2
    PARAMETER_ERROR = 3
    UNKNOWN_ME = 4
    UNKNOWN_INSTANCE = 5
    DEVICE_BUSY = 6
    INSTANCE_EXISTS = 7
    ATTRIBUTE_FAILURE = 9


class OMCIPacket:
    __slots__ = (
        "transaction_id",
        "message_type",
        "device_id",
        "ak",
        "ar",
        "action",
        "me_class",
        "inst_id",
    )

    NO_RESULT_ACTIONS = {
        OmciAction.MIB_UPLOAD,
        OmciAction.MIB_UPLOAD_NEXT,
        OmciAction.GET_ALL_ALARMS,
        OmciAction.GET_ALL_ALARMS_NEXT,
    }

    def __init__(self, data):
        self.transaction_id = int.from_bytes(data[0:2], "big")
        self.message_type = data[2]
        self.device_id = data[3]
        self.ak = bool(self.message_type & 0x20)
        self.ar = bool(self.message_type & 0x40)
        self.me_class = int.from_bytes(data[4:6], "big")
        self.inst_id = int.from_bytes(data[6:8], "big")

        action_val = self.message_type & 0x1F
        try:
            self.action = OmciAction(action_val)
        except ValueError:
            self.action = action_val

    @classmethod
    def from_raw(cls, data):
        if len(data) < 4:
            raise ValueError("Data too short")
        dev_id = data[3]
        if dev_id == 0x0A:
            return OMCIBaseline(data)
        else:
            if len(data) < 14:
                raise ValueError("Data too short")
            return OMCIExtended(data)

    @staticmethod
    def is_vendor_range(c):
        # Table 11.2.4-1 Vendor ranges
        return (240 <= c <= 255) or (350 <= c <= 399) or (65280 <= c <= 65535)

    @staticmethod
    def is_feature_range(c):
        return (172 <= c <= 239) or (467 <= c <= 65279)

    @property
    def is_vendor_me(self):
        c = self.me_class
        return self.is_vendor_range(c)

    @property
    def is_feature_me(self):
        c = self.me_class
        return self.is_feature_range(c)

    @classmethod
    def from_values(cls, transaction_id, message_type, me_class, inst_id, content=None):
        # TID (2) + MT (1) + DevID (1) + ME Class (2) + ME Inst (2) = 8 bytes
        header = transaction_id.to_bytes(2, "big")
        header += message_type.to_bytes(1, "big")
        header += b"\x0a"  # Device ID (Baseline = 0x0A)
        header += me_class.to_bytes(2, "big")
        header += inst_id.to_bytes(2, "big")

        # 32 bytes of content
        if content is None:
            content = b"\x00" * 32
        elif len(content) < 32:
            content = content.ljust(32, b"\x00")

        # raw data (Header + Content), ignore trailer
        full_raw = header + content

        return cls(full_raw)

    @property
    def is_response(self):
        """
        Response message with AK bit set.
        """
        return self.ak

    @property
    def is_request(self):
        """
        Acknowledge Request (OLT initiated that expects a response)
        """
        return self.ar

    @property
    def is_notification(self):
        """
        ONU initiated autonomous messages (Alarm / AVC) that do NOT expect response.
        MT bit 6 (AR) == 0 and bit 5 (AK) == 0
        """
        return not self.ar and not self.ak

    @property
    def has_result_code(self):
        if not self.is_response:
            return False
        return self.action not in self.NO_RESULT_ACTIONS

    @property
    def result(self):
        if self.is_response and self.has_result_code:
            return self.content[0]
        else:
            return None

    @property
    def upload_me_class(self):
        if self.action == OmciAction.MIB_UPLOAD_NEXT and self.is_response:
            return int.from_bytes(self.content[0:2], "big")
        return None

    @property
    def mib_upload_is_vendor(self):
        c = self.upload_me_class
        if c is None:
            return False
        return self.is_vendor_range(c)

    @property
    def mib_upload_is_feature(self):
        c = self.upload_me_class
        if c is None:
            return False
        return self.is_feature_range(c)


class OMCIBaseline(OMCIPacket):
    __slots__ = ("content", "trailer")

    def __init__(self, raw_data, ignore_trailer=True):
        super().__init__(raw_data)
        if len(raw_data) < 40:
            raise ValueError(
                f"Baseline packet too short: {len(raw_data)} bytes (min 40)"
            )
        self.content = raw_data[8:40]

        if not ignore_trailer:
            if len(raw_data) < 48:
                raise ValueError(
                    f"Baseline trailer missing: {len(raw_data)} bytes (expected 48)"
                )
            self.trailer = raw_data[40:48]
        else:
            self.trailer = raw_data[40:48] if len(raw_data) >= 48 else None

    @property
    def mib_upload_entity(self):
        """
        For MIB Upload Next Response, parses the carried ME Class and Instance ID.
        Returns:
            dict: {"me_class": int, "me_instance": int} if it's a valid response, else None.
        """
        if self.action == OmciAction.MIB_UPLOAD_NEXT and self.is_response:
            # G.988:
            # content[0:2] = Reported ME Class ID (2 bytes)
            # content[2:4] = Reported ME Instance ID (2 bytes)
            try:
                me_class = int.from_bytes(self.content[0:2], "big")
                me_instance = int.from_bytes(self.content[2:4], "big")
                attr_mask = int.from_bytes(self.content[4:6], "big")
                attr_data = self.content[6:32]
                return {
                    "me_class": me_class,
                    "me_instance": me_instance,
                    "attr_mask": attr_mask,
                    "attr_data": attr_data,
                }
            except (IndexError, ValueError):
                return None
        return None


class OMCIExtended(OMCIPacket):
    __slots__ = ("length", "content")

    def __init__(self, raw_data, src_mac=None):
        super().__init__(raw_data)
        self.length = int.from_bytes(raw_data[8:10], byteorder="big")
        self.content = raw_data[10 : 10 + self.length]


def omci_packets_from_pcap(pcap_path, include_raw=False):
    """
    Generator: yields OMCI packets from PCAP file.

    Memory efficient for large PCAP files.

    Args:
        pcap_path (str): Path to PCAP file
        include_raw (bool): Include raw packet data

    Yields:
        tuple: (packet_no, omci_pkt, raw_pkt or None)
    """
    try:
        raw_pkts = rdpcap(pcap_path)
    except Exception as e:
        print(f"Error reading pcap: {e}")
        return

    for i, raw_pkt in enumerate(raw_pkts):
        if not raw_pkt.haslayer("Ether") or raw_pkt.getlayer("Ether").type != 0x88B5:
            continue

        try:
            raw_data = bytes(raw_pkt.lastlayer())
            omci_pkt = OMCIPacket.from_raw(raw_data)

            if isinstance(omci_pkt, OMCIBaseline):
                yield i, omci_pkt, (raw_pkt if include_raw else None)

        except Exception:
            continue


def load_omci_packets(pcap_path, include_raw=False):
    """
    Loader: loads all OMCI packets from PCAP file into memory.

    Convenience wrapper around omci_packets_from_pcap().

    Args:
        pcap_path (str): Path to PCAP file
        include_raw (bool): Include raw packet data

    Returns:
        list: List of (packet_no, omci_pkt, raw_pkt or None) tuples
    """
    return list(omci_packets_from_pcap(pcap_path, include_raw))


# vim: set ts=4 sw=4 et:
