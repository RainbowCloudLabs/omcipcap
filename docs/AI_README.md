# OMCIPcap AI

The AI subsystem is under development. This document describes only behavior
that is currently implemented.

## Initialize a RAG workspace

Use the `standard`, `workstation`, or `server` profile:

```text
omcipcap ai rag init --profile standard --dir ./rag-workspace
```

Initialization creates this workspace layout:

```text
rag-workspace/
├── config.json
├── db/
├── issues/
├── mib-json/
└── semantics/
```

`config.json` records:

- `db_schema_version`
- `profile_id`
- `omcipcap_version`
- `created_at`, as an ISO 8601 UTC timestamp

Running the same initialization command again is safe when the existing schema
and profile are compatible. It preserves the original configuration, including
the workspace creation timestamp. Initialization also records the normalized
workspace path in `~/.local/omcipcap/rag_config.json`.

## Ingest an issue case

Ingestion resolves the active workspace from the per-user configuration:

```text
omcipcap ai rag ingest \
    --case-id CASE-001 \
    --issue-md issue.md \
    sample.pcap
```

The issue document must contain non-empty level-2 `Problem`, `Root-Cause`,
`Trigger-Condition`, `How-To-Identify`, and `Solution` sections. `Environment`
and additional sections are optional. The stored issue is written to
`issues/<case-id>.md`, and its semantic chunks are stored in ChromaDB under
`db/`. Semantic units are split with the selected embedding model's tokenizer
using the token limit and overlap configured by the active profile.

Install the optional AI dependencies before ingestion:

```text
pip install "omcipcap[ai]"
```

RAG query, rebuild, list, and show commands are not implemented yet.
