#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

from collections.abc import Iterator
from urllib.parse import quote

import requests

from omci.ai.providers.base import AIProvider
from omci.ai.providers.errors import AIProviderRequestError, AIProviderResponseError


class GeminiProvider(AIProvider):
    """Google Gemini REST API adapter."""

    _BASE_URL = "https://generativelanguage.googleapis.com/v1beta"

    def _headers(self) -> dict[str, str]:
        return {
            "x-goog-api-key": self._credential("GEMINI_API_KEY"),
            "Content-Type": "application/json",
        }

    def list_models(self) -> list[str]:
        identifiers: list[object] = []
        params: dict[str, str] | None = {"pageSize": "1000"}
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
            if not isinstance(payload, dict) or not isinstance(payload.get("models"), list):
                raise AIProviderResponseError("Gemini returned an invalid model list.")
            for item in payload["models"]:
                if not isinstance(item, dict):
                    continue
                methods = item.get("supportedGenerationMethods")
                if isinstance(methods, list) and "generateContent" in methods:
                    identifiers.append(item.get("name"))
            token = payload.get("nextPageToken")
            if token is None:
                break
            if not isinstance(token, str) or not token:
                raise AIProviderResponseError("Gemini returned invalid pagination data.")
            params = {"pageSize": "1000", "pageToken": token}
        return self._normalize_models(identifiers)

    def stream_generate(
        self,
        *,
        model: str,
        system_prompt: str,
        user_prompt: str,
    ) -> Iterator[str]:
        model_name = model.removeprefix("models/")
        response = self._request(
            "POST",
            f"{self._BASE_URL}/models/{quote(model_name, safe='')}:streamGenerateContent",
            headers=self._headers(),
            params={"alt": "sse"},
            json_body={
                "system_instruction": {"parts": [{"text": system_prompt}]},
                "contents": [
                    {"role": "user", "parts": [{"text": user_prompt}]}
                ],
            },
            stream=True,
        )
        try:
            for raw_line in response.iter_lines(decode_unicode=True):
                line = self._line_text(raw_line).strip()
                if not line or line.startswith(":") or not line.startswith("data:"):
                    continue
                event = self._event_json(line[5:].strip())
                if not isinstance(event, dict):
                    raise AIProviderResponseError(
                        "Gemini returned an invalid streaming event."
                    )
                if "error" in event:
                    raise AIProviderRequestError("Gemini stream reported an error.")
                candidates = event.get("candidates")
                if candidates is None:
                    continue
                if not isinstance(candidates, list):
                    raise AIProviderResponseError(
                        "Gemini returned invalid streaming candidates."
                    )
                for candidate in candidates:
                    if not isinstance(candidate, dict):
                        continue
                    content = candidate.get("content")
                    if not isinstance(content, dict):
                        continue
                    parts = content.get("parts")
                    if not isinstance(parts, list):
                        continue
                    for part in parts:
                        if isinstance(part, dict) and isinstance(part.get("text"), str):
                            text = part["text"]
                            if text:
                                yield text
                    if isinstance(candidate.get("finishReason"), str):
                        return
            raise AIProviderResponseError("Gemini stream ended before completion.")
        except requests.RequestException as exc:
            raise self._stream_failure(exc) from exc
        finally:
            response.close()
