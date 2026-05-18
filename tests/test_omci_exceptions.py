#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
#
# Generate: Single UNI, two VLANs (100 & 200), shared T-CONT
# Based on G.988 Figure II.1.2.1-1
#

import pytest
from omci.omci import OMCIBaseline, OMCIPacket

def test_baseline_init_too_short():
    short_data = b'\x00\x01\x2d\x0a' + b'\x00' * 16
    
    with pytest.raises(ValueError) as excinfo:
        OMCIBaseline(short_data)
    
    assert "Baseline packet too short" in str(excinfo.value)

def test_baseline_trailer_missing_exception():
    data_40 = b'\x00\x01\x2d\x0a' + b'\x00' * 36
    
    with pytest.raises(ValueError) as excinfo:
        OMCIBaseline(data_40, ignore_trailer=False)
    
    assert "Baseline trailer missing" in str(excinfo.value)

def test_from_raw_too_short():
    tiny_data = b'\x00\x01\x02' 
    
    with pytest.raises(ValueError, match="Data too short"):
        OMCIPacket.from_raw(tiny_data)

def test_baseline_valid_length():
    valid_data = b'\x00\x01\x2d\x0a' + b'\x00' * 44
    pkt = OMCIBaseline(valid_data)
    assert len(pkt.content) == 32
    assert pkt.trailer is not None
