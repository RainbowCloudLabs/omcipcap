# AI Provider Framework Specification

**Status:** Draft (Design Review)

---

## Purpose

The AI Provider Framework provides a reusable abstraction for communicating
with Large Language Model (LLM) providers.

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
ai/providers/
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

The interface MUST provide:

- list available models
- send generation requests
- stream generated responses

---

## Provider Factory

`factory.py` MUST expose a single factory function for creating provider
adapters.

Consumers MUST create providers through the factory.

Consumers MUST NOT import provider implementations directly.

---

## Authentication

Provider adapters MUST obtain credentials from environment variables.

API keys MUST NOT be accepted through command-line arguments.

Provider adapters MUST validate required credentials before making any HTTP
request.

---

## Model Discovery

Provider adapters are responsible for retrieving supported models.

If the provider supports remote model discovery, the adapter SHOULD query the
official API.

Otherwise, the adapter MAY provide a documented built-in model list.

Consumers MUST treat every provider identically.

---

## Streaming

The first implementation MUST support streaming responses.

Provider adapters MUST follow each provider's official streaming REST API and
implement it using `requests` with `stream=True`.

Official provider SDKs MUST NOT be used.

Provider-specific streaming events MUST be normalized into plain text chunks
before being returned to the consumer.

Consumers MUST:

- write generated text incrementally to stdout
- flush stdout after every chunk
- preserve Markdown formatting
- write warnings, progress, and errors to stderr
- remain compatible with shell redirection
- print a final newline after successful completion
- return a non-zero exit status if the stream fails

If a stream fails after partial output has already been written:

- keep the partial response on stdout
- report the failure on stderr
- return a non-zero exit status

---

## Error Handling

`errors.py` MUST define common provider exceptions.

Provider adapters MUST convert provider-specific HTTP and parsing errors into
shared provider exceptions.

Consumers MUST NOT depend on provider-specific exceptions.

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
- Reuse a single `requests.Session` when appropriate.
