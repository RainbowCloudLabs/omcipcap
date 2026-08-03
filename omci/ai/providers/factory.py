#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

from collections.abc import Callable

from omci.ai.providers.base import AIProvider
from omci.ai.providers.claude import ClaudeProvider
from omci.ai.providers.errors import AIProviderConfigError
from omci.ai.providers.gemini import GeminiProvider
from omci.ai.providers.ollama import OllamaProvider
from omci.ai.providers.openai import OpenAIProvider
from omci.ai.providers.openrouter import OpenRouterProvider


_PROVIDER_TYPES: dict[str, Callable[[], AIProvider]] = {
    "claude": ClaudeProvider,
    "gemini": GeminiProvider,
    "ollama": OllamaProvider,
    "openai": OpenAIProvider,
    "openrouter": OpenRouterProvider,
}
SUPPORTED_PROVIDERS = tuple(sorted(_PROVIDER_TYPES))


def create_provider(name: str) -> AIProvider:
    """Create a provider adapter from a normalized provider name."""
    normalized = name.strip().lower()
    try:
        provider_type = _PROVIDER_TYPES[normalized]
    except KeyError as exc:
        raise AIProviderConfigError(f"Unknown AI provider: {name}") from exc
    return provider_type()
