#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.


class AIProviderError(Exception):
    """Base exception for AI provider failures."""


class AIProviderConfigError(AIProviderError):
    """Raised when provider configuration is invalid or incomplete."""


class AIProviderRequestError(AIProviderError):
    """Raised when an AI provider request fails."""


class AIProviderResponseError(AIProviderError):
    """Raised when an AI provider response cannot be processed."""
