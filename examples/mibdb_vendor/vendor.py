#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.

try:
    from omci.omcisemantic import OMCISemantic
except ImportError:
    pass


def is_enable(value):
    if value & 0x1:
        return "Enabled"
    return "Disabled"


OMCISemantic.register(65300, "attribute 4", is_enable)
OMCISemantic.register(65400, "Health Check", is_enable)
