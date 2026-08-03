#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
import json
import os

import requests
from requests import Response

from omci.ai.providers.errors import (
    AIProviderConfigError,
    AIProviderRequestError,
    AIProviderResponseError,
)


REQUEST_TIMEOUT = (10, 120)


class AIProvider(ABC):
    """Common interface and transport helpers for AI provider adapters."""

    def __init__(self) -> None:
        self._session = requests.Session()

    @abstractmethod
    def list_models(self) -> list[str]:
        """Return available provider model identifiers."""

    @abstractmethod
    def stream_generate(
        self,
        *,
        model: str,
        system_prompt: str,
        user_prompt: str,
    ) -> Iterator[str]:
        """Yield generated text chunks."""

    @staticmethod
    def _credential(variable: str) -> str:
        credential = os.environ.get(variable, "").strip()
        if not credential:
            raise AIProviderConfigError(
                f"Required environment variable {variable} is not set."
            )
        return credential

    @staticmethod
    def _normalize_models(identifiers: Iterable[object]) -> list[str]:
        models = {
            identifier.strip()
            for identifier in identifiers
            if isinstance(identifier, str) and identifier.strip()
        }
        return sorted(models)

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        json_body: dict[str, object] | None = None,
        stream: bool = False,
    ) -> Response:
        try:
            response = self._session.request(
                method,
                url,
                headers=headers,
                params=params,
                json=json_body,
                stream=stream,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.Timeout as exc:
            raise AIProviderRequestError("AI provider request timed out.") from exc
        except requests.ConnectionError as exc:
            raise AIProviderRequestError(
                "Could not connect to the AI provider."
            ) from exc
        except requests.RequestException as exc:
            raise AIProviderRequestError("AI provider request failed.") from exc

        if response.status_code in (401, 403):
            response.close()
            raise AIProviderRequestError("AI provider authentication failed.")
        if not response.ok:
            status_code = response.status_code
            response.close()
            raise AIProviderRequestError(
                f"AI provider request failed with HTTP {status_code}."
            )
        return response

    @staticmethod
    def _response_json(response: Response) -> object:
        try:
            return response.json()
        except (ValueError, requests.RequestException) as exc:
            raise AIProviderResponseError(
                "AI provider returned malformed JSON."
            ) from exc

    @staticmethod
    def _event_json(data: str) -> object:
        try:
            return json.loads(data)
        except (TypeError, ValueError) as exc:
            raise AIProviderResponseError(
                "AI provider returned a malformed streaming event."
            ) from exc

    @staticmethod
    def _line_text(line: str | bytes) -> str:
        if isinstance(line, bytes):
            try:
                return line.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise AIProviderResponseError(
                    "AI provider returned invalid streaming text."
                ) from exc
        return line

    @staticmethod
    def _stream_failure(exc: requests.RequestException) -> AIProviderRequestError:
        if isinstance(exc, requests.Timeout):
            return AIProviderRequestError("AI provider stream timed out.")
        if isinstance(exc, requests.ConnectionError):
            return AIProviderRequestError("AI provider stream connection failed.")
        return AIProviderRequestError("AI provider stream failed.")
