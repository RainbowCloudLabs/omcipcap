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
the workspace creation timestamp.

RAG ingest and query commands are not implemented yet.
