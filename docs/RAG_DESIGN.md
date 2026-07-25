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

## Workspace Layout

A RAG workspace contains:

- RAG database
- Issue cases (Markdown)
- Vendor MIB JSON definitions
- Semantic plugins
- Profiles

---

## Target CLI

### Initialize

```text
omcipcap ai rag init --profile standard --dir <workdir>
```

### Data Management

```text
# ingest issue
omcipcap ai rag ingest \
    --case-id CASE-001 \
    --issue-md issue.md \
    sample.pcap

# query issues using a natural-language question
omcipcap ai rag query "ONU cannot create VEIP" --top-k 5

# list all cases
omcipcap ai rag list

# show one issue case
omcipcap ai rag show CASE-001
```

When ingesting an existing `case-id`, OMCIPcap must prompt before replacing
the existing case.

Example:

```text
Case "CASE-001" already exists.

Replace existing case? [y/N]
```

Selecting **Y** replaces the stored issue case and rebuilds its associated
semantic chunks.

Selecting **N** cancels the operation.

## Profile Management

```text
# show workspace status
omcipcap ai rag status

# rebuild database
omcipcap ai rag rebuild

# list available profiles
omcipcap ai rag profile list

# show profile information
omcipcap ai rag profile show <profile>
```

The `status` command reports:

- Workspace path
- Active profile
- Database status
- Profile/database compatibility
- Rebuild requirement
- Number of indexed issue cases

The `rebuild` command recreates the vector database from the stored issue
cases using the active profile.

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
