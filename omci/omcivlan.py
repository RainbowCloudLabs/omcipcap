#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
#


class VlanTaggingOperation:
    def __init__(self, hex_str: str):
        self.raw_hex = hex_str
        self.val = int(hex_str, 16)
        self.data = {}
        self._unpack_bits()
        self.action_type = ""
        self.tpid_dei_operation = {}
        self._determine_action()
        self._determine_operation_tpid_dei()

    def _unpack_bits(self):
        """G.988 Table 9.3.13-1"""
        v = self.val
        self.data = {
            # Filter
            "f_out_prio": (v >> 124) & 0xF,  #  4 bits
            "f_out_vid": (v >> 111) & 0x1FFF,  # 13 bits
            "f_out_tpid_dei": (v >> 108) & 0x7,  #  3 bits
            # "f_reserved": (v >> 96) & 0xFFF, # 12 bits
            "f_in_prio": (v >> 92) & 0xF,  #  4 bits
            "f_in_vid": (v >> 79) & 0x1FFF,  # 13 bits
            "f_in_tpid_dei": (v >> 76) & 0x7,  #  3 bits
            # "f_reserved2": (v >> 68) & 0xFF,  #  8 bits
            "f_eth_type": (v >> 64) & 0xF,  #  4 bits
            # Treatment
            "t_tags_rem": (v >> 62) & 0x3,  #  2 bits
            # "t_reserved": (v >> 52) & 0x3FF,  # 10 bits
            "t_out_prio": (v >> 48) & 0xF,  #  4 bits
            "t_out_vid": (v >> 35) & 0x1FFF,  # 13 bits
            "t_out_tpid_dei": (v >> 32) & 0x7,  # 3 bits
            # "t_reserved2": (v >> 20) & 0xFFF,  # 12 bits
            "t_in_prio": (v >> 16) & 0xF,  # 4bits
            "t_in_vid": (v >> 3) & 0x1FFF,  # 13bits
            "t_in_tpid_dei": v & 0x7,
        }

    @staticmethod
    def _vid_str(vid: int) -> str:
        """Return '*' for the wildcard sentinel value 4096, else the VID as a string."""
        return "*" if vid == 4096 else str(vid)

    def _determine_action(self):
        """
        Determine the VLAN action type string based on G.988 ME 171 filter/treatment
        field combinations. Logic ported from omci.lua ME 171 dissector.
        Result is stored in self.action_type.
        """
        d = self.data
        fo_prio = d["f_out_prio"]
        fo_vid = d["f_out_vid"]
        fi_prio = d["f_in_prio"]
        fi_vid = d["f_in_vid"]
        fi_eth = d["f_eth_type"]
        t_rem = d["t_tags_rem"]
        to_prio = d["t_out_prio"]
        to_vid = d["t_out_vid"]
        ti_prio = d["t_in_prio"]
        ti_vid = d["t_in_vid"]

        fov = self._vid_str(fo_vid)
        fiv = self._vid_str(fi_vid)

        action = ""

        # --- Upstream: Untagged frames (fo_prio=15, fo_vid=4096, fi_prio=15, fi_vid=4096, fi_eth=0) ---
        if (
            fo_prio == 15
            and fo_vid == 4096
            and fi_prio == 15
            and fi_vid == 4096
            and fi_eth == 0
        ):
            if t_rem == 3:
                action = "Untagged: Discard"
            elif to_prio == 15 and ti_prio != 15:
                action = f"Untagged: Insert 1 tag  F -> X({ti_vid})-F"
            elif to_prio == 15 and ti_prio == 15:
                action = "Untagged: Default, do nothing"
            elif to_prio != 15 and ti_prio != 15 and ti_vid != 0 and to_vid != 0:
                action = f"Untagged: Insert 2 tags  F -> Y({to_vid})-X({ti_vid})-F"

        # --- Upstream: Single tagged frames (fo_prio=15, fo_vid=4096, fi_prio=8, fi_eth=0) ---
        elif fo_prio == 15 and fo_vid == 4096 and fi_prio == 8 and fi_eth == 0:
            if t_rem == 1:  # remove or modify C-VID
                if ti_prio != 8 and ti_prio != 15:
                    if to_prio == 15:
                        action = f"Single: Modify tag  C({fiv})-F -> X({ti_vid})-F"
                    else:
                        action = f"Single: Modify+insert tag  C({fiv})-F -> Y({to_vid})-X({ti_vid})-F"
                elif ti_prio == 8:
                    action = (
                        f"Single: Modify tag, keep prio  C({fiv})-F -> X({ti_vid})-F"
                    )
                elif ti_prio == 15:
                    action = f"Single: Remove tag  C({fiv})-F -> F"
            elif t_rem == 3:
                action = "Single: Discard"
            else:  # insert tag(s)
                # ti_vid == 4096 means copy inner VID from received frame
                if to_prio == 15 and ti_vid == 4096:
                    action = f"Single: Copy inner VID  C({fiv})"
                elif to_prio == 15 and ti_prio != 8:
                    action = f"Single: Insert 1 tag (X)  C({fiv})-F -> X({ti_vid})-C({fiv})-F"
                elif to_prio == 15 and ti_prio == 8:
                    action = f"Single: Insert 1 tag (X), copy prio  C({fiv})-F -> X({ti_vid})-C({fiv})-F"
                else:
                    action = f"Single: Insert 2 tags (X,Y)  C({fiv})-F -> Y({to_vid})-X({ti_vid})-C({fiv})-F"

        # --- Upstream: Double tagged frames (fo_prio=8, fi_prio=8, fi_eth=0) ---
        elif fo_prio == 8 and fi_prio == 8 and fi_eth == 0:
            if t_rem == 0:
                if ti_prio == 8:
                    action = (
                        f"Double: Insert 2 tags (X,Y), copy prios  "
                        f"S({fov})-C({fiv})-F -> Y({to_vid})-X({ti_vid})-S({fov})-C({fiv})-F"
                    )
                else:
                    action = (
                        f"Double: Insert 2 tags (X,Y)  "
                        f"S({fov})-C({fiv})-F -> Y({to_vid})-X({ti_vid})-S({fov})-C({fiv})-F"
                    )
            elif t_rem == 1 and to_prio == 15:
                if ti_prio == 15:
                    action = (
                        f"Double: Remove outer tag  S({fov})-C({fiv})-F -> C({fiv})-F"
                    )
                elif ti_prio == 9:
                    action = (
                        f"Double: Modify outer tag, keep prio  "
                        f"S({fov})-C({fiv})-F -> X({ti_vid})-C({fiv})-F"
                    )
                else:
                    action = f"Double: Modify outer tag  S({fov})-C({fiv})-F -> X({ti_vid})-C({fiv})-F"
            elif t_rem == 2:
                if ti_prio == 15 and to_prio == 15:
                    action = f"Double: Remove both tags  S({fov})-C({fiv})-F -> F"
                elif to_prio == 9:
                    action = (
                        f"Double: Modify both tags, keep prios  "
                        f"S({fov})-C({fiv})-F -> Y({to_vid})-X({ti_vid})-F"
                    )
                else:
                    action = f"Double: Modify both tags  S({fov})-C({fiv})-F -> Y({to_vid})-X({ti_vid})-F"

        # --- Single tagged: Default case ---
        elif fo_prio == 15 and fo_vid == 4096 and fi_prio == 14 and fi_vid == 4096:
            if to_prio == 15 and ti_prio == 15 and t_rem == 3:
                action = "Single Default: Discard"
            elif to_prio == 15 and ti_prio == 15 and t_rem == 0:
                action = "Single Default: do nothing"

        # --- Double tagged: Default case ---
        elif fo_prio == 14 and fo_vid == 4096 and fi_prio == 14 and fi_vid == 4096:
            if to_prio == 15 and ti_prio == 15 and t_rem == 0:
                action = "Double Default: do nothing"
            elif to_prio == 15 and ti_prio == 15 and t_rem == 3:
                action = "Double Default: Discard"

        self.action_type = action

    def _determine_operation_tpid_dei(self):
        """
        Translate the 3-bit TPID/DEI filter and treatment opcodes into human-readable
        and AI-friendly semantic strings based on ITU-T G.988.
        """
        d = self.data

        filter_map = {
            0b000: "TPID:any",
            0b100: "TPID:8100",
            0b101: "TPID:Input",
            0b110: "TPID:Input,DEI:0",
            0b111: "TPID:Input,DEI:1",
        }

        treatment_map = {
            0b000: "Copy:Inner",
            0b001: "Copy:Outer",
            0b010: "TPID:Out,DEI:Inn",
            0b011: "TPID:Out,DEI:Out",
            0b100: "Force:8100",
            0b101: "Reserved",
            0b110: "TPID:Out,DEI:0",
            0b111: "TPID:Out,DEI:1",
        }

        self.tpid_dei_operation = {
            "op_f_in_tpid_dei": filter_map.get(d["f_in_tpid_dei"], "Unknown"),
            "op_f_out_tpid_dei": filter_map.get(d["f_out_tpid_dei"], "Unknown"),
            "op_t_in_tpid_dei": treatment_map.get(d["t_in_tpid_dei"], "Unknown"),
            "op_t_out_tpid_dei": treatment_map.get(d["t_out_tpid_dei"], "Unknown"),
        }
