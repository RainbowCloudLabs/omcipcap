#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

from collections.abc import Iterator
import sys

import pytest

from omci import cli
from omci.ai.providers import AIProvider, AIProviderConfigError


class StubProvider(AIProvider):
    def list_models(self) -> list[str]:
        return ["a-model", "z-model"]

    def stream_generate(
        self,
        *,
        model: str,
        system_prompt: str,
        user_prompt: str,
    ) -> Iterator[str]:
        del model, system_prompt, user_prompt
        yield from ()


def test_ai_providers_cli_is_deterministic(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["omcipcap", "ai", "providers"])

    cli.main()

    assert capsys.readouterr().out == "claude\ngemini\nollama\nopenai\nopenrouter\n"


def test_ai_models_cli_uses_factory(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    created: list[str] = []

    def create(name: str) -> AIProvider:
        created.append(name)
        return StubProvider()

    monkeypatch.setattr(cli, "create_provider", create)
    monkeypatch.setattr(
        sys,
        "argv",
        ["omcipcap", "ai", "models", "--provider", "OPENAI"],
    )

    cli.main()

    assert created == ["OPENAI"]
    assert capsys.readouterr().out == "a-model\nz-model\n"


def test_ai_models_cli_reports_clean_provider_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def create(name: str) -> AIProvider:
        del name
        raise AIProviderConfigError("Required environment variable is not set.")

    monkeypatch.setattr(cli, "create_provider", create)
    monkeypatch.setattr(
        sys,
        "argv",
        ["omcipcap", "ai", "models", "--provider", "openai"],
    )

    with pytest.raises(SystemExit) as error:
        cli.main()

    assert error.value.code == 2
    captured = capsys.readouterr()
    assert "Required environment variable is not set." in captured.err
    assert "Traceback" not in captured.err
