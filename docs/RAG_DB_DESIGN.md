# Database Schema

## Version 1

### Collection Metadata

| Field | Type | Description |
|---|---|---|
| `db_schema_version` | Integer | Database schema version |
| `profile_id` | String | Profile used to build or rebuild the collection |
| `omcipcap_version` | String | omcipcap version that created or last rebuilt the collection |

### Chunk Metadata

| Field | Type | Description |
|---|---|---|
| `case_id` | String | Issue case identifier |
| `semantic_unit` | String | Semantic unit represented by the chunk |
| `chunk_index` | Integer | Zero-based sequence within the semantic unit |
| `priority` | Integer | Fixed retrieval priority of the semantic unit |
| `issue_file` | String | Source issue Markdown filename |
| `pcap_file` | String | Source PCAP filename |

`chunk_index` is scoped to the combination of `case_id` and `semantic_unit`.

Valid `semantic_unit` values in schema version 1:

- `issue_summary`
- `failed_check_results`
- `core_mib_summary`
- `service_path`
- `upload_mib`
- `vendor_specific_mib`
- `full_mib`
