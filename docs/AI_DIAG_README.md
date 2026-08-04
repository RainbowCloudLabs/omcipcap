# OMCIPcap AI Diagnosis User Guide

OMCIPcap AI Diagnosis combines existing protocol analysis with a selected AI
provider. It supports diagnosis of one capture and comparison of a Target
capture against known-good Golden provisioning.

## Provider setup

Supported providers are `openai`, `claude`, `gemini`, `openrouter`, and
`ollama`. List the provider adapters without credentials or a network request:

```bash
omcipcap ai providers
```

Cloud providers read their API keys from environment variables. API keys are
not accepted as command-line arguments:

| Provider | Environment variable |
| --- | --- |
| OpenAI | `OPENAI_API_KEY` |
| Claude | `ANTHROPIC_API_KEY` |
| Gemini | `GEMINI_API_KEY` |
| OpenRouter | `OPENROUTER_API_KEY` |

For example:

```bash
export OPENAI_API_KEY="your-api-key"
omcipcap ai models --provider openai
```

List the models reported by a provider with:

```bash
omcipcap ai models --provider openrouter
```

### Ollama configuration

Ollama does not require an API key by default and uses the local service at
`http://localhost:11434`. To use a remote or non-default Ollama server, set
`OLLAMA_BASE_URL` as an environment variable; there is no CLI option:

```bash
export OLLAMA_BASE_URL=http://192.168.1.100:11434
omcipcap ai models --provider ollama
```

## Problem description

Write the reported symptom and questions in a UTF-8 Markdown file such as
`examples/ai/problem.md`. OMCIPcap passes this content unchanged and appends the
automatically generated analysis Markdown as diagnosis evidence.

## System prompt

The diagnosis commands use the built-in AI diagnosis system prompt by default.
To replace it completely, set `AI_DIAG_SYSTEM_PROMPT` to a UTF-8 Markdown file:

```bash
export AI_DIAG_SYSTEM_PROMPT="${HOME}/my-system-prompt.md"
```

An invalid, unreadable, or empty custom prompt is reported as an error; the
command does not fall back to the built-in prompt.

## Diagnose one capture

`omcipcap ai diag` combines the problem description with the standard OMCIPcap
overview for one capture, then streams a diagnosis from the selected provider:

```bash
omcipcap ai diag examples/omci.pcap \
    --problem-md examples/ai/problem.md \
    --provider openrouter \
    --model anthropic/claude-opus-4.5 \
    --mib-json custom-me.json \
    --semantic-dir semantic/
```

The optional `--mib-json` and `--semantic-dir` inputs use the same custom
Managed Entity definitions and semantic extensions as `omcipcap overview`.
They are loaded before the diagnosis overview is generated.

The provider receives the built-in or configured system prompt separately. Its
user prompt contains the problem Markdown followed by the generated OMCIPcap
overview.

## Compare with a Golden capture

`omcipcap ai diag-diff` compares the complete observed MIB lifecycle of a
Target capture against a known-good Golden capture, then includes the Golden
and Target overviews as additional evidence:

```bash
omcipcap ai diag-diff target.pcap \
    --golden-pcap golden.pcap \
    --problem-md examples/ai/problem.md \
    --provider openrouter \
    --model anthropic/claude-opus-4.5 \
    --mib-json custom-me.json \
    --semantic-dir semantic/
```

The diff direction is Target to Golden: old and removed values describe the
Target, while new and added values describe the Golden capture. The command
uses the same system-prompt override and semantic inputs as `ai diag`.

## Streaming behavior

Both diagnosis commands stream provider output directly to stdout. Errors are
written to stderr.
