#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

from collections.abc import Iterator
from typing import cast

import pytest
import requests

from omci.ai.providers import (
    AIProvider,
    AIProviderConfigError,
    AIProviderRequestError,
    AIProviderResponseError,
    SUPPORTED_PROVIDERS,
    create_provider,
)
from omci.ai.providers.claude import ClaudeProvider
from omci.ai.providers.gemini import GeminiProvider
from omci.ai.providers.ollama import OllamaProvider
from omci.ai.providers.openai import OpenAIProvider
from omci.ai.providers.openrouter import OpenRouterProvider


class FakeResponse:
    def __init__(
        self,
        *,
        payload: object = None,
        lines: list[str | bytes] | None = None,
        status_code: int = 200,
        stream_error: requests.RequestException | None = None,
    ) -> None:
        self.payload = payload
        self.lines = lines or []
        self.status_code = status_code
        self.ok = 200 <= status_code < 400
        self.closed = False
        self.stream_error = stream_error

    def json(self) -> object:
        if isinstance(self.payload, ValueError):
            raise self.payload
        return self.payload

    def iter_lines(self, decode_unicode: bool = False) -> Iterator[str | bytes]:
        del decode_unicode
        yield from self.lines
        if self.stream_error is not None:
            raise self.stream_error

    def close(self) -> None:
        self.closed = True


def set_request_response(
    provider: AIProvider,
    monkeypatch: pytest.MonkeyPatch,
    response: FakeResponse,
) -> None:
    def request(method: str, url: str, **kwargs: object) -> FakeResponse:
        del method, url, kwargs
        return response

    monkeypatch.setattr(provider._session, "request", request)


def set_provider_key(
    monkeypatch: pytest.MonkeyPatch,
    provider: AIProvider,
) -> None:
    variables = {
        OpenAIProvider: "OPENAI_API_KEY",
        ClaudeProvider: "ANTHROPIC_API_KEY",
        GeminiProvider: "GEMINI_API_KEY",
        OpenRouterProvider: "OPENROUTER_API_KEY",
    }
    variable = variables.get(type(provider))
    if variable is not None:
        monkeypatch.setenv(variable, "test-key")


def test_factory_creates_all_supported_providers() -> None:
    assert SUPPORTED_PROVIDERS == (
        "claude",
        "gemini",
        "ollama",
        "openai",
        "openrouter",
    )
    assert isinstance(create_provider(" OPENAI "), OpenAIProvider)
    assert isinstance(create_provider("claude"), ClaudeProvider)
    assert isinstance(create_provider("gemini"), GeminiProvider)
    assert isinstance(create_provider("openrouter"), OpenRouterProvider)
    assert isinstance(create_provider("ollama"), OllamaProvider)


def test_factory_rejects_unknown_provider() -> None:
    with pytest.raises(AIProviderConfigError, match="Unknown AI provider"):
        create_provider("unknown")


@pytest.mark.parametrize(
    ("provider", "variable"),
    [
        (OpenAIProvider(), "OPENAI_API_KEY"),
        (ClaudeProvider(), "ANTHROPIC_API_KEY"),
        (GeminiProvider(), "GEMINI_API_KEY"),
        (OpenRouterProvider(), "OPENROUTER_API_KEY"),
    ],
)
def test_missing_credentials_fail_before_request(
    provider: AIProvider,
    variable: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(variable, raising=False)
    called = False

    def request(method: str, url: str, **kwargs: object) -> FakeResponse:
        del method, url, kwargs
        nonlocal called
        called = True
        return FakeResponse(payload={"data": []})

    monkeypatch.setattr(provider._session, "request", request)
    with pytest.raises(AIProviderConfigError, match=variable):
        provider.list_models()
    assert called is False


def test_model_list_is_normalized_and_response_is_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = OpenAIProvider()
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    response = FakeResponse(
        payload={
            "data": [
                {"id": "z-model"},
                {"id": ""},
                {"id": "a-model"},
                {"id": "z-model"},
                {"name": "not-an-id"},
            ]
        }
    )
    set_request_response(provider, monkeypatch, response)

    assert provider.list_models() == ["a-model", "z-model"]
    assert response.closed is True


@pytest.mark.parametrize(
    ("base_url", "expected_base_url"),
    [
        (None, "http://localhost:11434"),
        ("http://192.168.1.100:11434", "http://192.168.1.100:11434"),
        ("http://192.168.1.100:11434/", "http://192.168.1.100:11434"),
    ],
)
def test_ollama_requests_use_configured_base_url(
    base_url: str | None,
    expected_base_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if base_url is None:
        monkeypatch.delenv("OLLAMA_BASE_URL", raising=False)
    else:
        monkeypatch.setenv("OLLAMA_BASE_URL", base_url)

    provider = OllamaProvider()
    requested_urls: list[str] = []
    responses = [
        FakeResponse(payload={"models": []}),
        FakeResponse(lines=['{"message":{"content":""},"done":true}']),
    ]

    def request(method: str, url: str, **kwargs: object) -> FakeResponse:
        del method, kwargs
        requested_urls.append(url)
        return responses.pop(0)

    monkeypatch.setattr(provider._session, "request", request)

    assert provider.list_models() == []
    assert list(
        provider.stream_generate(
            model="model", system_prompt="system", user_prompt="user"
        )
    ) == []
    assert requested_urls == [
        f"{expected_base_url}/api/tags",
        f"{expected_base_url}/api/chat",
    ]


@pytest.mark.parametrize(
    ("provider", "lines", "expected"),
    [
        (
            OpenAIProvider(),
            [
                'data: {"type":"response.output_text.delta","delta":"Hello"}',
                'data: {"type":"response.output_text.delta","delta":" world"}',
                'data: {"type":"response.completed"}',
            ],
            ["Hello", " world"],
        ),
        (
            ClaudeProvider(),
            [
                'event: content_block_delta',
                'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Claude"}}',
                'data: {"type":"message_stop"}',
            ],
            ["Claude"],
        ),
        (
            GeminiProvider(),
            [
                'data: {"candidates":[{"content":{"parts":[{"text":"Gemini"}]},"finishReason":"STOP"}]}',
            ],
            ["Gemini"],
        ),
        (
            OpenRouterProvider(),
            [
                'data: {"choices":[{"delta":{"content":"OpenRouter"}}]}',
                "data: [DONE]",
            ],
            ["OpenRouter"],
        ),
        (
            OllamaProvider(),
            [
                '{"message":{"content":"Ollama"},"done":false}',
                '{"message":{"content":""},"done":true}',
            ],
            ["Ollama"],
        ),
    ],
)
def test_streaming_extracts_plain_text_and_closes_response(
    provider: AIProvider,
    lines: list[str | bytes],
    expected: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_provider_key(monkeypatch, provider)
    response = FakeResponse(lines=lines)
    set_request_response(provider, monkeypatch, response)

    result = list(
        provider.stream_generate(
            model="model", system_prompt="system", user_prompt="user"
        )
    )

    assert result == expected
    assert response.closed is True


def test_malformed_stream_event_is_normalized_and_response_is_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = OpenAIProvider()
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    response = FakeResponse(lines=["data: not-json"])
    set_request_response(provider, monkeypatch, response)

    with pytest.raises(AIProviderResponseError, match="malformed streaming event"):
        list(
            provider.stream_generate(
                model="model", system_prompt="system", user_prompt="user"
            )
        )
    assert response.closed is True


def test_timeout_is_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = OllamaProvider()

    def request(method: str, url: str, **kwargs: object) -> FakeResponse:
        del method, url, kwargs
        raise requests.Timeout("private provider details")

    monkeypatch.setattr(provider._session, "request", request)
    with pytest.raises(AIProviderRequestError, match="timed out") as error:
        provider.list_models()
    assert "private provider details" not in str(error.value)


def test_stream_timeout_is_normalized_and_response_is_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = OllamaProvider()
    response = FakeResponse(stream_error=requests.Timeout("secret"))
    set_request_response(provider, monkeypatch, response)

    with pytest.raises(AIProviderRequestError, match="stream timed out"):
        list(
            provider.stream_generate(
                model="model", system_prompt="system", user_prompt="user"
            )
        )
    assert response.closed is True


def test_http_authentication_failure_is_normalized_and_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = OpenAIProvider()
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    response = FakeResponse(status_code=401)
    set_request_response(provider, monkeypatch, response)

    with pytest.raises(AIProviderRequestError, match="authentication failed"):
        provider.list_models()
    assert response.closed is True


def test_malformed_model_response_is_normalized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = OpenAIProvider()
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    response = FakeResponse(payload=cast(object, ValueError("bad json")))
    set_request_response(provider, monkeypatch, response)

    with pytest.raises(AIProviderResponseError, match="malformed JSON"):
        provider.list_models()
    assert response.closed is True
