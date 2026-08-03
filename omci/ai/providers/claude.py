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


class ClaudeProvider(AIProvider):
    """Anthropic Claude REST API adapter."""

    _BASE_URL = "https://api.anthropic.com/v1"

    def _headers(self) -> dict[str, str]:
        return {
            "x-api-key": self._credential("ANTHROPIC_API_KEY"),
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

    def list_models(self) -> list[str]:
        identifiers: list[object] = []
        params: dict[str, str] | None = None
        while True:
            response = self._request(
                "GET",
                f"{self._BASE_URL}/models",
                headers=self._headers(),
                params=params,
            )
            try:
                payload = self._response_json(response)
            finally:
                response.close()
            if not isinstance(payload, dict) or not isinstance(
                payload.get("data"), list
            ):
                raise AIProviderResponseError("Claude returned an invalid model list.")
            identifiers.extend(
                item.get("id") for item in payload["data"] if isinstance(item, dict)
            )
            if payload.get("has_more") is not True:
                break
            last_id = payload.get("last_id")
            if not isinstance(last_id, str) or not last_id:
                raise AIProviderResponseError(
                    "Claude returned invalid pagination data."
                )
            params = {"after_id": last_id}
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
            f"{self._BASE_URL}/messages",
            headers=self._headers(),
            json_body={
                "model": model,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
                "max_tokens": 4096,
                "stream": True,
            },
            stream=True,
        )
        try:
            for raw_line in response.iter_lines():
                line = self._line_text(raw_line).strip()
                if not line or line.startswith(":") or not line.startswith("data:"):
                    continue
                event = self._event_json(line[5:].strip())
                if not isinstance(event, dict):
                    raise AIProviderResponseError(
                        "Claude returned an invalid streaming event."
                    )
                event_type = event.get("type")
                if event_type == "error":
                    raise AIProviderRequestError("Claude stream reported an error.")
                if event_type == "content_block_delta":
                    delta = event.get("delta")
                    if not isinstance(delta, dict):
                        raise AIProviderResponseError(
                            "Claude returned an invalid content delta."
                        )
                    if delta.get("type") == "text_delta":
                        text = delta.get("text")
                        if not isinstance(text, str):
                            raise AIProviderResponseError(
                                "Claude returned an invalid text delta."
                            )
                        if text:
                            yield text
                elif event_type == "message_stop":
                    return
            raise AIProviderResponseError("Claude stream ended before completion.")
        except requests.RequestException as exc:
            raise self._stream_failure(exc) from exc
        finally:
            response.close()
