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


class OllamaProvider(AIProvider):
    """Local Ollama REST API adapter."""

    _BASE_URL = "http://localhost:11434/api"

    def list_models(self) -> list[str]:
        response = self._request("GET", f"{self._BASE_URL}/tags")
        try:
            payload = self._response_json(response)
        finally:
            response.close()
        if not isinstance(payload, dict) or not isinstance(payload.get("models"), list):
            raise AIProviderResponseError("Ollama returned an invalid model list.")
        identifiers = [
            item.get("name") for item in payload["models"] if isinstance(item, dict)
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
            f"{self._BASE_URL}/chat",
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
                if not line:
                    continue
                event = self._event_json(line)
                if not isinstance(event, dict):
                    raise AIProviderResponseError(
                        "Ollama returned an invalid streaming event."
                    )
                if "error" in event:
                    raise AIProviderRequestError("Ollama stream reported an error.")
                message = event.get("message")
                if message is not None:
                    if not isinstance(message, dict):
                        raise AIProviderResponseError(
                            "Ollama returned an invalid streaming message."
                        )
                    content = message.get("content")
                    if isinstance(content, str) and content:
                        yield content
                if event.get("done") is True:
                    return
            raise AIProviderResponseError("Ollama stream ended before completion.")
        except requests.RequestException as exc:
            raise self._stream_failure(exc) from exc
        finally:
            response.close()
