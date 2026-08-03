# AI Provider Framework Specification

**Status:** Implemented
**Version:** 2

---

## Purpose

The AI Provider Framework provides a reusable abstraction for communicating
with Large Language Model (LLM) providers.

The AI Provider Framework is responsible only for communicating with
AI providers.

It is NOT responsible for prompt construction, diagnosis workflow, RAG,
or domain-specific logic.

Provider adapters must be reusable by all AI commands.

---

## Design Principles

Provider implementations MUST:

- use `requests`
- avoid official SDK packages
- be implemented independently
- expose a unified interface

Provider-specific logic MUST NOT leak into command-line code.

---

## Supported Providers

The first version supports:

- openai
- claude
- gemini
- openrouter
- ollama

---

## Provider Architecture

All providers MUST implement the same common interface.

Command-line code MUST communicate only with this interface.

Provider-specific response objects MUST NOT be exposed outside the provider
layer.

---

## Provider Package Layout

Suggested layout:

```
omci/ai/providers/
  __init__.py
  base.py
  factory.py
  errors.py
  openai.py
  claude.py
  gemini.py
  openrouter.py
  ollama.py
```

---

## Provider Responsibilities

Each provider adapter is responsible for:

- endpoint URL
- authentication
- request payload
- response parsing
- error handling

`base.py` MUST define the common provider interface used by all provider
adapters.

The common provider interface is defined in "Required Provider Operations".

---

## Required Provider Operations

Every provider adapter MUST expose the following two operations through the
common provider interface.

### List Models

```python
def list_models(self) -> list[str]:
    ...
```

`list_models()` retrieves the model identifiers available from the provider.

The returned value MUST:

- contain model identifiers only
- contain no empty identifiers
- contain no duplicate identifiers
- use deterministic ordering
- hide provider-specific response structures from consumers

When remote model discovery is supported, the adapter MUST use the provider's
official model-listing REST API.

When remote model discovery is unavailable, the adapter MAY return a documented
built-in model list.

The adapter MUST NOT invent model identifiers.

### Stream Generation

```python
from collections.abc import Iterator

def stream_generate(
    self,
    *,
    model: str,
    system_prompt: str,
    user_prompt: str,
) -> Iterator[str]:
    ...
```

`stream_generate()` sends one generation request and yields generated text as it
is received.

Inputs:

- `model`: provider-specific model identifier
- `system_prompt`: instructions describing the model's role and behavior
- `user_prompt`: user content and generated analysis context

The returned iterator MUST yield plain text chunks only.

It MUST NOT yield:

- raw SSE lines
- raw JSON objects
- provider event names
- completion markers
- usage metadata
- provider-specific response objects

The adapter MUST stop iteration when the provider reports normal completion.

Provider-specific streaming formats MUST remain internal to the adapter.

## Provider Factory

`factory.py` MUST expose a single factory function for creating provider
adapters.

Consumers MUST create providers through the factory.

Consumers MUST NOT import provider implementations directly.

`factory.py` MUST expose:

```python
def create_provider(name: str) -> AIProvider:
    ...
```

Unknown provider names MUST raise AIProviderConfigError.

---

## Authentication

Provider adapters MUST obtain credentials from environment variables.

The environment variable names are provider-specific.

API keys MUST NOT be accepted through command-line arguments.

Provider adapters MUST validate required credentials before making any HTTP request.

For Ollama, the adapter MAY read `OLLAMA_BASE_URL` from the environment.

If `OLLAMA_BASE_URL` is not specified, the default base URL MUST be:

```text
```
http://localhost:11434
```
```

---

## Model Discovery

Provider adapters are responsible for retrieving supported models.

If the provider supports remote model discovery, the adapter SHOULD query the
official API.

Otherwise, the adapter MAY provide a documented built-in model list.

Consumers MUST treat every provider identically.

---

## Streaming

Provider adapters MUST:

- use the official streaming REST API
- use `requests` with `stream=True`
- normalize provider events into plain text chunks
- stop on normal completion
- close the HTTP response on success or failure
- raise shared provider exceptions on stream failure

---

## Error Handling

`errors.py` MUST define common provider exceptions.

Provider adapters MUST convert provider-specific HTTP and parsing errors into
shared provider exceptions.

Consumers MUST NOT depend on provider-specific exceptions.

`errors.py` MUST define at least:

- `AIProviderError`
- `AIProviderConfigError`
- `AIProviderRequestError`
- `AIProviderResponseError`

---

## Testing Requirements

Provider implementations MUST be unit-testable.

Tests MUST mock HTTP requests.

Tests MUST NOT depend on external AI services or Internet connectivity.

---

## Implementation Requirements

Provider adapters MUST follow the provider's official REST API documentation.

Implementation requirements:

- Use the provider's official REST API.
- Follow the official `curl` examples published by the provider whenever possible.
- Implement HTTP requests using the Python `requests` package only.
- Do NOT use official Python SDKs (for example `openai`, `anthropic`, `google-genai`).
- Keep the implementation lightweight with minimal dependencies.
