#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong-Yuan Shih <daneshih1125@gmail.com>
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

import sys

from omci.ai.providers import AIProviderError, create_provider


def main() -> int:
    provider = create_provider("openrouter")
    model = "openai/gpt-5-mini"

    try:
        for text in provider.stream_generate(
            model=model,
            system_prompt="You are a concise assistant.",
            user_prompt="Explain model routing in one sentence.",
        ):
            print(text, end="", flush=True)
    except AIProviderError as exc:
        print(f"OpenRouter request failed: {exc}", file=sys.stderr)
        return 1

    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
