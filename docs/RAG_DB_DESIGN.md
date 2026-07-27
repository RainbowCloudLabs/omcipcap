# Database Schema

## Version 1

### Collection Metadata

| Field | Type | Description |
|---|---|---|
| `db_schema_version` | Integer | Database schema version |
| `profile_id` | String | Profile used to build the collection |
| `omcipcap_version` | String | OMCIPcap version that created the collection |

In a future release, a rebuild operation may update collection metadata. The
first-stage RAG MVP does not implement `rag rebuild` and cannot migrate an
existing collection to another profile or embedding model.

### Chunk Metadata

| Field | Type | Description |
|---|---|---|
| `case_id` | String | Issue case identifier |
| `semantic_unit` | String | Semantic unit represented by the chunk |
| `chunk_index` | Integer | Zero-based sequence within the semantic unit |
| `priority` | Integer | Fixed retrieval priority of the semantic unit |
| `issue_file` | String | Source issue Markdown filename |
| `pcap_file` | String | Source PCAP filename |
| `problem` | String | Introductory description extracted from the issue Markdown `Problem` section |

`chunk_index` is scoped to the combination of `case_id` and `semantic_unit`.

The `problem` metadata stores the introductory description from the `Problem`
section of the issue Markdown document.

The extracted text consists of the content following the `Problem` heading up
to, but not including, the next Markdown heading of the same or higher level.

The value MUST be identical for all chunks belonging to the same `case_id`.

### Semantic Unit Identifiers

Valid `semantic_unit` values in schema version 1 are:

- `issue_summary`
- `failed_check_results`
- `core_mib_summary`
- `service_path`
- `upload_mib`
- `vendor_specific_mib`
- `full_mib`

## Current Migration Limitations

Schema version 1 metadata records compatibility; it does not provide a
migration mechanism. The current implementation cannot change the profile or
embedding model of an existing workspace, migrate or merge workspaces, or
rebuild a collection under another profile.

To use a different profile, create a new workspace and re-ingest the issue
cases. `rag rebuild` remains planned for a future release.
