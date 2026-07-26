# OMCIPcap RAG Design

## Overview

The RAG subsystem provides semantic retrieval for OMCI issue analysis by
indexing previously collected issue cases and retrieving similar cases to
assist troubleshooting.

### Design Goals

- Stable CLI
- Profile-based configuration
- Semantic chunking
- Local-first deployment
- Profile/database compatibility validation

## Implementation Decisions

The first official implementation of the OMCIPcap RAG subsystem uses
**ChromaDB** as the vector database.

Reasons:

- Pure Python implementation
- Local persistent storage
- Lightweight deployment
- No external database server required
- Suitable for workstation and offline environments

Database abstraction is **not** a design goal for the current implementation.

Future support for additional vector databases may be considered, but is
currently out of scope.

## Database Compatibility

The RAG database stores metadata describing the indexing configuration used
to build it.

Before using an existing database, OMCIPcap validates that it is compatible
with the active profile.

If the database is incompatible, it must not be reused and should be rebuilt.

Database compatibility is determined primarily by the database schema version
and profile requirements rather than the OMCIPcap release version alone.

## Database Schema

The persistent storage format of the RAG database is defined in
`RAG_DB_SCHEMA.md`.

The schema document defines:

- Collection metadata
- Chunk metadata
- Semantic unit identifiers
- Schema versioning
- Database compatibility requirements

All RAG implementations must follow the latest schema defined in
`RAG_DB_SCHEMA.md`.

## Related Specifications

The RAG subsystem is specified by the following documents:

- `RAG_CLI.md`
- `RAG_DB_SCHEMA.md`

This document describes the overall architecture and design goals.
Command-line behavior is defined in `RAG_CLI.md`.
Database persistence is defined in `RAG_DB_SCHEMA.md`.

## Workspace Layout

A RAG workspace contains:

```text
<workspace>/
├── db/
├── cases/
├── mib-json/
├── semantics/
└── workspace.json
```

- `db/` contains the persistent ChromaDB database.
- `cases/` contains stored issue-case Markdown documents and source artifacts.
- `mib-json/` contains vendor-specific MIB JSON definitions.
- `semantics/` contains Python semantic plugins used by OMCI analysis.
- `workspace.json` contains workspace metadata.

The `mib-json/` and `semantics/` directories MUST be created by `rag init`,
even when they are initially empty.

### Workspace Analysis Resources

The RAG ingestion pipeline MUST use analysis resources stored in the active
workspace.

For every `rag ingest` operation, the implementation MUST:

1. Resolve the active workspace.
2. Discover vendor MIB JSON files from `<workspace>/mib-json/`.
3. Discover Python semantic plugins from `<workspace>/semantics/`.
4. Pass the discovered resources to the OMCI analysis pipeline.
5. Generate semantic units from the enriched analysis result.
6. Chunk, embed, and store those semantic units.

Workspace analysis resources MUST be applied before semantic units are
generated.

The ingestion pipeline MUST NOT generate RAG chunks from the base PCAP analysis
and then attempt to apply vendor MIB definitions or semantic plugins afterward.

### Compatibility with Existing MIB Analysis

RAG ingestion MUST reuse the existing OMCIPcap MIB analysis behavior.

The workspace analysis resources:

```text
<workspace>/mib-json/
<workspace>/semantics/
```

are the workspace equivalents of the existing `mibdb` options:

```text
--mib-json <file>
--semantic-dir <directory>
```

For example, the existing command:

```bash
omcipcap mibdb --only-vendor sample.pcap \
    --mib-json vendor.json \
    --semantic-dir semantics/
```

and RAG ingestion using equivalent workspace resources SHOULD produce
consistent vendor-specific MIB identification and semantic analysis results.

Workspace MIB definitions and semantic plugins MUST be applied before RAG
semantic units are generated.

The required analysis order is:

```text
PCAP input
    ↓
Load workspace vendor MIB definitions
    ↓
Load workspace semantic plugins
    ↓
Run the existing OMCIPcap MIB analysis pipeline
    ↓
Generate RAG semantic units
    ↓
Chunk and embed
    ↓
Store in the vector database
```

The RAG implementation MUST reuse the shared internal loaders and analysis APIs
used by the existing `mibdb` command.

The RAG implementation MUST NOT duplicate the existing:

- OMCI MIB parsing logic
- vendor MIB JSON loading logic
- semantic plugin discovery or loading logic
- vendor-specific MIB identification logic

Detailed discovery rules and command behavior are defined in `RAG_CLI.md`.
Global command architecture and CLI conventions are defined in `CLI_DESIGN.md`.

### Default Workspace Configuration

OMCIPcap stores the path of the active RAG workspace in the per-user
configuration file:

```text
~/.local/omcipcap/rag_config.json
```

The configuration file contains only the workspace location:

```json
{
  "workspace_path": "/home/user/RAG"
}
```

The `rag init` command MUST create or update this file after successfully
initializing the workspace. The stored path MUST be absolute and normalized.

Subsequent RAG commands, including `ingest`, `query`, `list`, `show`, `status`,
and `rebuild`, resolve the active workspace from this configuration file. Users
do not need to provide the workspace directory again for each command.

The per-user configuration file stores only user-level workspace selection.
Workspace metadata, including the database schema version, profile ID, OMCIPcap
version, and creation time, remains inside the workspace and MUST NOT be copied
into `~/.local/omcipcap/rag_config.json`.

If the configuration file is missing, invalid, or references a workspace that
does not exist, the command MUST fail with a clear message instructing the user
to run:

```text
omcipcap ai rag init --profile <profile> --dir <workdir>
```

The configuration file SHOULD be written atomically to avoid leaving a partial
or corrupted file.

---

## Profiles

Profiles define the indexing and retrieval characteristics of the RAG
subsystem.

The selected profile and workspace creation information are stored in the
collection metadata.

```json
{
  "db_schema_version": 1,
  "profile_id": "standard",
  "omcipcap_version": "0.3.8"
}
```

- `db_schema_version` identifies the database schema version.
- `profile_id` identifies the profile used to build or rebuild the database.
- `omcipcap_version` records the OMCIPcap version that created or last rebuilt
  the database.

### standard

**Purpose**

- Maximum compatibility
- CPU-friendly
- Small memory footprint

**Typical Characteristics**

- Smaller embedding model
- Conservative indexing configuration
- Smaller chunk-size limits
- Optimized for resource-constrained environments

---

### workstation

**Purpose**

Best retrieval quality for local development and troubleshooting.

**Typical Characteristics**

- Larger embedding model
- Larger chunk-size limits
- Optimized for interactive local use
- Higher indexing cost for better retrieval quality

---

### server

**Purpose**

Optimized for multi-user deployments.

**Typical Characteristics**

- High indexing throughput
- Efficient batch processing
- Hardware acceleration when available
- Retrieval quality equivalent to **workstation** when using the same indexing
  configuration

---

Profile implementations may evolve over time without changing the CLI.

The concrete embedding model, chunk-size limits, token budget, indexing
parameters, and other implementation-specific settings are defined by the
profile rather than this design document.

## Embedding Strategy

Embedding models are implementation details managed by profiles.

Users select a profile rather than specifying an embedding model directly.

Typical profile mappings include:

| Profile | Typical Embedding |
|---------|-------------------|
| standard | MiniLM |
| workstation | BGE-M3 |
| server | BGE-M3 |

The concrete embedding model may change in future revisions without changing
the CLI or user workflow.

### Embedding Model Preparation

Embedding models are prepared during workspace initialization rather than
during ingestion.

Each profile specifies a single embedding model.

The implementation MUST prepare that model during `rag init`.

Preparing a model means ensuring that:

- the model can be loaded successfully by SentenceTransformer
- tokenizer files are available
- model weights are available
- subsequent `rag ingest` commands do not trigger model downloads

The implementation MAY reuse the existing sentence-transformers cache.

The implementation MUST NOT copy embedding models into the RAG workspace.

The RAG workspace contains only indexed data and workspace metadata.

## Chunking Strategy

The RAG subsystem uses a domain-aware semantic chunking strategy instead of
relying solely on fixed-size token splitting.

All profiles share the same semantic chunking algorithm to ensure consistent
document structure and retrieval behavior.

Profiles may differ in chunk-size limits, indexing configuration, resource
limits, and implementation details while preserving the same semantic
structure.

### Semantic Units

The chunker recognizes the following semantic units.

| Display Name | semantic_unit |
|--------------|---------------|
| Issue Summary | `issue_summary` |
| Failed Check Results | `failed_check_results` |
| Core MIB Summary | `core_mib_summary` |
| Service Path | `service_path` |
| Upload MIB | `upload_mib` |
| Vendor-specific MIB | `vendor_specific_mib` |
| Full MIB | `full_mib` |

The chunker should preserve semantic boundaries whenever possible.

A semantic unit should only be split when required by the active profile's
indexing constraints, such as token budget or maximum chunk size.

When a semantic unit exceeds the profile's chunk-size limit, it is split into
multiple chunks.

Each chunk is identified by:

- `case_id`
- `semantic_unit`
- `chunk_index`

where `chunk_index` is zero-based and scoped to the combination of
`case_id` and `semantic_unit`.

### Profile Chunk Limits

Each profile MUST define an explicit maximum token count and token overlap for
semantic chunks.

The initial profile limits are:

| Profile | Maximum Tokens per Chunk | Token Overlap |
|---------|--------------------------|---------------|
| standard | 256 | 32 |
| workstation | 512 | 64 |
| server | 512 | 64 |

Token counts MUST be calculated using the tokenizer associated with the
embedding model selected by the active profile.

Character count and whitespace-separated word count MUST NOT be used as
substitutes for token count.

A semantic unit whose token count is less than or equal to the profile limit is
stored as one chunk with `chunk_index = 0`.

A semantic unit whose token count exceeds the profile limit MUST be divided
into multiple chunks:

```text
<case_id>:<semantic_unit>:0
<case_id>:<semantic_unit>:1
<case_id>:<semantic_unit>:2
```
Chunk indices MUST be deterministic and zero-based.

Chunking SHOULD prefer the following boundaries, in order:

1. Markdown headings
2. Paragraph boundaries
3. List-item boundaries
4. Line boundaries
5. Token-level splitting as a final fallback

Adjacent chunks MUST use the overlap configured by the active profile.

The chunker MUST preserve the original document order.

Empty chunks MUST NOT be stored.

### Profile Configuration

Profile settings MUST be defined in one shared configuration structure.

Profile configuration MUST include:

- Embedding model
- Maximum tokens per chunk
- Token overlap

Profile settings MUST NOT be duplicated across multiple dictionaries or modules.

Example:

```python
PROFILE_CONFIGS = {
    "standard": {
        "model": "sentence-transformers/all-MiniLM-L6-v2",
        "max_tokens": 256,
        "token_overlap": 32,
    },
    "workstation": {
        "model": "BAAI/bge-m3",
        "max_tokens": 512,
        "token_overlap": 64,
    },
    "server": {
        "model": "BAAI/bge-m3",
        "max_tokens": 512,
        "token_overlap": 64,
    },
}
```

The same profile configuration MUST be reused by:

- `rag init`
- `rag ingest`
- `rag status`
- `rag rebuild`

The ingestion pipeline MUST select the embedding model, token limit, and token
overlap from the active workspace profile.

The embedding tokenizer associated with the selected profile model MUST be used
for token counting and token-level splitting.

Character count, whitespace-separated word count, and fixed character slicing
MUST NOT be used as substitutes for tokenizer-based token counting.

## Issue Case Format

Issue cases are stored as Markdown documents and serve as the primary knowledge
source for RAG ingestion.

Each issue case MUST contain the following sections:

- Problem
- Root-Cause
- Trigger-Condition
- How-To-Identify
- Solution

The RAG ingestion pipeline validates the presence of these required sections
before indexing. Missing required sections SHALL result in an ingestion error.

Additional sections are permitted and are preserved during indexing.

### Environment (Optional)

The following environment information is recommended when available to improve
retrieval accuracy and assist issue classification:

- ONU Vendor
- ONU Firmware
- OLT Vendor
- OLT Firmware

Additional environment fields may also be included when relevant, such as
software version, hardware revision, deployment mode, or other vendor-specific
information.

Environment information is optional and is not required for successful
ingestion.

## Optional AI Dependencies

The `omcipcap ai` command group is an optional feature.

AI-related dependencies (embedding models, vector databases, LLM SDKs, etc.)
are **not** part of the core `omcipcap` installation.

The project SHALL provide AI functionality through Python optional
dependencies defined in `pyproject.toml`.

Example:

```toml
[project.optional-dependencies]
ai = [
    "chromadb>=1.5,<2.0",
    "sentence-transformers>=3.0.0",
]
```

Users who require AI features should install:

```bash
pip install "omcipcap[ai]"
```

This design keeps the core package lightweight and avoids installing large AI
dependencies for users who only require OMCI analysis.

## Binary Distribution

Official standalone binaries for:

- Windows
- Linux
- macOS

contain only the core `omcipcap` functionality.

The `omcipcap ai` command group is **not included** in binary releases because
AI functionality depends on optional Python packages that are installed
separately.

Users requiring AI features should install the Python package with the `ai`
optional dependency instead.
