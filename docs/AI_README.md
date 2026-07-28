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
workspace path in `~/.local/omcipcap/rag_config.json`. Before reporting
success, initialization prepares the selected embedding model and tokenizer in
the normal sentence-transformers cache; model files are not copied into the
workspace. Initialization permits downloading a missing model and does not
report success until model loading completes.

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
using the token limit and overlap configured by the active profile. Before
capture analysis, ingestion loads top-level `.json` definitions from
`mib-json/` and semantic plugins from `semantics/`. Ingestion loads the
embedding model with `local_files_only=True`; it never downloads the model or
checks the Hugging Face Hub for updates. If the cached model is missing, rerun
`rag init` for the active profile and workspace.

Install the optional AI dependencies before ingestion:

```text
pip install "omcipcap[rag]"
```

RAG query, rebuild, list, and show commands are not implemented yet.

## Current profile and workspace limitations

`rag rebuild` is planned for a future release and is not currently available.
The first-stage RAG MVP does not support:

- changing the profile of an existing workspace;
- changing its embedding model;
- migrating an existing workspace to another profile;
- merging multiple workspaces; or
- rebuilding an existing workspace under another profile.

To use a different profile, create a new workspace with that profile and
re-ingest the issue cases into the new workspace.
