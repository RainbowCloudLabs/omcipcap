#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

from collections.abc import Iterator

import requests

from omci.ai.providers.base import AIProvider
from omci.ai.providers.errors import AIProviderRequestError, AIProviderResponseError


class OpenRouterProvider(AIProvider):
    """OpenRouter REST API adapter."""

    _BASE_URL = "https://openrouter.ai/api/v1"

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._credential('OPENROUTER_API_KEY')}",
            "Content-Type": "application/json",
        }

    def list_models(self) -> list[str]:
        response = self._request(
            "GET", f"{self._BASE_URL}/models", headers=self._headers()
        )
        try:
            payload = self._response_json(response)
        finally:
            response.close()
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise AIProviderResponseError("OpenRouter returned an invalid model list.")
        identifiers = [
            item.get("id") for item in payload["data"] if isinstance(item, dict)
        ]
        return self._normalize_models(identifiers)

    def stream_generate(
        self,
        *,
        model: str,
        system_prompt: str,
        user_prompt: str,
    ) -> Iterator[str]:
        response = self._request(
            "POST",
            f"{self._BASE_URL}/chat/completions",
            headers=self._headers(),
            json_body={
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "stream": True,
            },
            stream=True,
        )
        try:
            for raw_line in response.iter_lines(decode_unicode=True):
                line = self._line_text(raw_line).strip()
                if not line or line.startswith(":") or not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    return
                event = self._event_json(data)
                if not isinstance(event, dict):
                    raise AIProviderResponseError(
                        "OpenRouter returned an invalid streaming event."
                    )
                if "error" in event:
                    raise AIProviderRequestError(
                        "OpenRouter stream reported an error."
                    )
                choices = event.get("choices")
                if not isinstance(choices, list):
                    raise AIProviderResponseError(
                        "OpenRouter returned invalid streaming choices."
                    )
                for choice in choices:
                    if not isinstance(choice, dict):
                        continue
                    delta = choice.get("delta")
                    if not isinstance(delta, dict):
                        continue
                    content = delta.get("content")
                    if isinstance(content, str) and content:
                        yield content
            raise AIProviderResponseError(
                "OpenRouter stream ended before completion."
            )
        except requests.RequestException as exc:
            raise self._stream_failure(exc) from exc
        finally:
            response.close()
