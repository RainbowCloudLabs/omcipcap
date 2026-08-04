# OMCIPcap AI/RAG User Guide

## AI Diagnosis

`omcipcap ai diag` combines a user-written troubleshooting question with the
standard OMCIPcap overview for one capture, then streams a diagnosis from the
selected AI provider.

### Provider setup

Set the provider's API key through its environment variable. For example,
OpenRouter uses `OPENROUTER_API_KEY`; API keys are not accepted as CLI options.
Use `omcipcap ai providers` to list adapters and `omcipcap ai models --provider
PROVIDER` to query available models. Ollama can run locally without an API key.

### Problem description

Write the reported symptom and questions in a UTF-8 Markdown file such as
`examples/ai/problem.md`. OMCIPcap passes this content unchanged and appends the
automatically generated overview Markdown as diagnosis evidence.

### System prompt

The command uses the built-in AI diagnosis system prompt by default. To replace
it completely, set `AI_DIAG_SYSTEM_PROMPT` to a UTF-8 Markdown file:

```bash
export AI_DIAG_SYSTEM_PROMPT="${HOME}/my-system-prompt.md"
```

An invalid, unreadable, or empty custom prompt is reported as an error; the
command does not fall back to the built-in prompt.

### Example

Configure the selected provider and run:

```bash
export OPENROUTER_API_KEY="your-api-key"
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
overview. Output is streamed directly to stdout. Errors are written to stderr.

### Compare with a Golden capture

`ai diag-diff` compares the complete observed MIB lifecycle of a Target capture
against a known-good Golden capture, then includes the Golden and Target
overviews as additional evidence:

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
uses the same system-prompt override, semantic inputs, and streaming behavior
as `ai diag`.

OMCIPcap's RAG feature lets you build a local library of previously diagnosed
OMCI issue cases and search it with natural-language questions.

## Installation

AI/RAG support is optional. Install OMCIPcap with the `rag` extra:

```bash
pip install "omcipcap[rag]"
```

This installs the additional embedding-model and vector-database packages used
by the RAG commands.

> **Note:** Standalone OMCIPcap binary releases do not include AI functionality.
> The AI subsystem depends on optional Python packages, so use the Python
> package installation above when you need RAG support.

After installation, the available commands are under:

```text
omcipcap ai rag
```

## Available Profiles

### Purpose

Profiles select the embedding model and chunking limits used by a RAG
workspace.

### Syntax

```bash
omcipcap ai rag profiles
```

### Example

```text
PROFILE       ACTIVE  EMBEDDING MODEL                             MAX TOKENS  OVERLAP
standard              sentence-transformers/all-MiniLM-L6-v2      256         32
workstation   *       BAAI/bge-m3                                  512         64
server                BAAI/bge-m3                                  512         64
```

The `*` marks the profile of the currently active workspace. If no workspace is
configured, the command still lists the supported profiles and leaves the
`ACTIVE` column blank.

### Choosing a profile

- `standard` uses the smaller MiniLM model and lower chunk limits. Choose it
  for older computers, low-memory systems, or CPU-constrained environments.
- `workstation` uses BGE-M3 and larger chunks for better local retrieval.
  This is the recommended profile for modern desktop PCs and Apple Silicon
  Macs, including M-series systems.
- `server` uses BGE-M3 with the same chunk limits as `workstation`. Choose it
  for a dedicated server environment.

### Output columns

- `PROFILE` is the profile name accepted by `rag init`.
- `ACTIVE` contains `*` when that profile belongs to the active workspace.
- `EMBEDDING MODEL` is the sentence-transformers model used to encode cases and
  queries.
- `MAX TOKENS` is the maximum token count for one stored semantic chunk.
- `OVERLAP` is the number of tokens repeated between adjacent chunks when a
  semantic unit must be split.

## Initialize a Workspace

### Purpose

`rag init` creates a workspace, selects its permanent profile, and prepares the
profile's embedding model and tokenizer.

### Syntax

```bash
omcipcap ai rag init --profile <profile> --dir <workspace>
```

Both options are required:

- `--profile` must be `standard`, `workstation`, or `server`.
- `--dir` selects the workspace directory.

### Example

```bash
omcipcap ai rag init \
    --profile workstation \
    --dir /home/user/RAG_TEST
```

Successful initialization prints:

```text
[+] RAG workspace initialized: /home/user/RAG_TEST (profile: workstation)
```

Initialization creates:

```text
/home/user/RAG_TEST/
├── db/
├── cases/
├── pcaps/
├── mib-json/
├── semantics/
└── config.json
```

It also prepares the selected embedding model. If the model is not already in
the normal sentence-transformers cache, initialization downloads it before
reporting success. Model files are not copied into the workspace.

The selected profile cannot be changed by reinitializing the same workspace
with another profile. Create a separate workspace when you need a different
profile.

### Per-user configuration

OMCIPcap records the currently active workspace in:

```text
~/.local/omcipcap/rag_config.json
```

Example:

```json
{
  "workspace_path": "/home/user/RAG_TEST"
}
```

`workspace_path` is the absolute path used by subsequent `status`, `ingest`,
`query`, and `cases` commands. Initializing another workspace successfully
makes that workspace active.

### Workspace configuration

The workspace itself contains `config.json`:

```json
{
  "db_schema_version": 1,
  "profile_id": "workstation",
  "omcipcap_version": "0.3.7",
  "created_at": "2026-07-29T14:56:43.946018+00:00"
}
```

- `db_schema_version` identifies the persisted RAG database schema.
- `profile_id` is the profile selected during initialization.
- `omcipcap_version` is the OMCIPcap version that created the workspace.
- `created_at` is the workspace creation time in UTC using ISO 8601 format.

## Workspace Status

### Purpose

`rag status` reports whether the active workspace and its database are ready
for use.

### Syntax and example

```bash
omcipcap ai rag status
```

```text
Workspace:              /home/user/RAG_TEST
Active profile:         workstation
Database status:        ready
Compatibility:          compatible
Indexed issue cases:    4
```

### Output fields

- `Workspace` is the active workspace resolved from the per-user
  `rag_config.json`.
- `Active profile` is the profile recorded by the workspace.
- `Database status` describes the ChromaDB data:
  - `ready` means the database is readable and contains indexed cases.
  - `empty` means the database exists but contains no indexed cases.
  - `missing` means no database directory exists.
  - `invalid` means the database or its required metadata cannot be read.
- `Compatibility` compares the database metadata with the active workspace:
  - `compatible` means the schema and profile match.
  - `incompatible` means they do not match.
  - `unknown` means compatibility cannot be determined from invalid or missing
    metadata.
  - `not-applicable` means there is no database to compare.
- `Indexed issue cases` is the number of unique case IDs, not the number of
  semantic chunks.

The command only inspects the workspace; it does not load an embedding model or
change any files.

## Ingest Issue Cases

### Purpose

`rag ingest` analyzes a capture and issue document, generates searchable
semantic chunks, and stores the complete case in the active workspace.

### Syntax

```bash
omcipcap ai rag ingest \
    --case-id <case-id> \
    --issue-md <issue.md> \
    <capture.pcap>
```

The required inputs are:

- `--case-id`: a non-empty, filename-safe identifier for the stored case.
- `--issue-md`: the issue-case Markdown document.
- `<capture.pcap>`: a PCAP or PCAPNG capture to analyze.

### Issue Markdown format

The document must contain these non-empty level-1 headings:

```markdown
# Problem

Describe the observed failure.

# Root-Cause

Describe the confirmed cause.

# Trigger-Condition

Describe when the issue occurs.

# How-To-Identify

Describe the diagnostic evidence.

# Solution

Describe the corrective action.
```

Heading matching is case-insensitive. An optional `# Environment` section and
unrelated additional sections are allowed. Canonical sections must use
level-1 headings.

### Example

```bash
omcipcap ai rag ingest \
    --case-id CASE-01 \
    --issue-md examples/issues/case_01_olt_disply_confi_fail.md \
    examples/issues/case_01_olt_disply_confi_fail.pcap
```

Successful ingestion prints:

```text
[+] RAG case ingested: "CASE-01"
```

During ingestion, OMCIPcap:

1. validates the Markdown and capture;
2. loads any workspace MIB definitions from `mib-json/` and semantic plugins
   from `semantics/`;
3. performs the normal OMCI checks, MIB reconstruction, VLAN, flow, and
   topology analysis;
4. generates and embeds semantic chunks; and
5. stores the issue document, an OMCI-only capture, and the ChromaDB records.

For `CASE-01`, the stored files are:

```text
<workspace>/cases/CASE-01.md
<workspace>/pcaps/CASE-01.pcap
```

The stored capture is always a standard `.pcap`, even when the input is
PCAPNG. It contains only packets successfully recognized as OMCI; unrelated
traffic is omitted. ChromaDB stores workspace-relative references to both
files.

### Replacing an existing case

If the case ID already exists, ingestion asks:

```text
Case "CASE-01" already exists.

Replace existing case? [y/N]
```

Enter `y` to replace the stored Markdown, filtered capture, semantic chunks,
and embeddings. Any other response cancels ingestion and keeps the existing
case unchanged.

## Query Similar Cases

### Purpose

`rag query` searches indexed issue cases using a natural-language description.
It returns case-level matches rather than individual semantic chunks.

### Syntax

```bash
omcipcap ai rag query "<question>"
omcipcap ai rag query "<question>" --top-k <N>
```

`--top-k` must be a positive integer and defaults to `5`. It limits the number
of unique issue cases returned.

### Example

```bash
omcipcap ai rag query \
    "PPTP Ethernet UNI Set response takes more than one second" \
    --top-k 3
```

Example output:

```text
Rank  Score  Case ID
----  -----  --------
1     0.91   CASE-01
2     0.67   CASE-04
```

### Output fields

- `Rank` starts at 1 and orders results from strongest to weakest match.
- `Score` is the similarity score of the best matching semantic chunk for that
  case, displayed to two decimal places.
- `Case ID` identifies the stored issue case.

The current minimum similarity threshold is `0.50`. Results below that
threshold are omitted, so the command may return fewer cases than `--top-k`.
Each case appears at most once.

Treat the results as likely related cases to inspect, not as a generated
diagnosis. The command retrieves indexed cases and does not generate an LLM
answer.

If the database has no indexed cases, the command prints:

```text
No indexed issue cases found.
```

If cases are indexed but none meet the similarity threshold, it prints:

```text
No matching issue cases found.
```

## Manage Issue Cases

The currently implemented case-management command lists indexed cases.

### List cases

#### Purpose

`rag cases` displays one row for every indexed case in the active workspace.

#### Syntax and example

```bash
omcipcap ai rag cases
```

```text
CASE ID        CHUNKS  PROBLEM
-------------  ------  -----------------------------------------------
CASE-001       8       VEIP creation failure
Xtelecom0002   6       TR-069 provisioning failed
```

#### Output fields

- `CASE ID` is the unique identifier supplied during ingestion.
- `CHUNKS` is the total number of indexed semantic chunks for that case.
- `PROBLEM` is the normalized text extracted from the issue document's
  `Problem` section.

Cases are sorted lexicographically by case ID. The command reads its summary
from the database and does not reanalyze captures or modify the workspace.

If no cases have been indexed, it prints:

```text
No indexed issue cases found.
```

## Example Issue Library

The repository includes several example issue cases under:

```text
examples/issues/
```

Each example contains one issue Markdown document and one or more PCAP files
that demonstrate a real OMCI troubleshooting scenario.

| Case | Description |
|------|-------------|
| case01 | OLT display configuration failure |
| case02 | Vendor-specific Managed Entity identification |
| case03 | Missing VLAN rule in the service path |
| case04 | 10G UNI QoS mapping issue |

To quickly create a demo workspace and ingest all example cases, run:

```bash
cd examples/issues
./rag_init.sh
```

The script will:

1. Remove any previous demo workspace.
2. Create a new RAG workspace.
3. Ingest all example issue cases.

After initialization, you can immediately experiment with commands such as:

```bash
omcipcap ai rag status

omcipcap ai rag query \
    "Why is the second VLAN rule missing?"

omcipcap ai rag query \
    "Vendor specific managed entity not recognized"

omcipcap ai rag query \
    "QoS mapping problem on 10G UNI"

omcipcap ai rag query \
    "OLT display configuration failed"
```

These examples are intended as reference data for learning how semantic
retrieval works and for validating a new installation.
