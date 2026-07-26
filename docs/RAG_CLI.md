# RAG CLI Specification

## Workspace Initialization

### Initialize

```text
omcipcap ai rag init --profile standard --dir <workdir>
```

The `rag init` command is responsible for preparing a workspace for immediate
RAG ingestion.

Initialization MUST perform the following steps in order:

1. Validate the selected profile.
2. Create the workspace directory.
3. Create the workspace metadata.
4. Create or update the global workspace configuration.
5. Verify that the required AI dependencies are installed.
6. Prepare the embedding model associated with the selected profile.

The embedding model preparation step MUST ensure that the model required by the
selected profile is available in the local sentence-transformers cache.

If the model is not already available locally, `rag init` MUST download it
before reporting successful initialization.

The command MUST NOT defer model download until the first `rag ingest`
operation.

After a successful `rag init`, the first `rag ingest` command SHOULD begin
indexing immediately without downloading embedding models.

Subsequent `rag ingest` operations SHOULD load the embedding model from the
local cache only.

If the embedding model required by the active profile is not available in the
local cache, `rag ingest` MUST fail with a clear error instructing the user to
run:

```text
omcipcap ai rag init --profile <profile> --dir <workdir>
```

The `rag ingest` command SHOULD NOT download embedding models or contact the
Hugging Face Hub during normal operation.

## Data Management

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

### Ingest

#### Synopsis

```text
omcipcap ai rag ingest \
    --case-id <case-id> \
    --issue-md <issue.md> \
    <capture.pcap>
```

#### Workflow

The `rag ingest` command MUST perform the following steps in order:

1. Resolve and validate the active workspace.
2. Load the active workspace profile.
3. Validate the issue Markdown document.
4. Discover vendor MIB JSON definitions from `<workspace>/mib-json/`.
5. Discover semantic plugins from `<workspace>/semantics/`.
6. Analyze the input capture using the existing OMCIPcap MIB analysis pipeline.
7. Generate semantic units from the analysis result.
8. Split semantic units according to the active profile.
9. Generate embeddings.
10. Store the issue case and semantic chunks atomically.

Vendor MIB definitions and semantic plugins MUST be loaded before semantic
units are generated.

The implementation MUST reuse the existing internal analysis pipeline used by
the `mibdb` command rather than implementing a separate analysis path.
```

#### Workspace Analysis Resource Discovery

Vendor MIB definitions are discovered from:

```text
<workspace>/mib-json/
```

Semantic plugins are discovered from:

```text
<workspace>/semantics/
```

Discovery requirements:

- Vendor MIB definition files MUST use the `.json` extension.
- Vendor MIB discovery MUST be deterministic.
- Discovery is non-recursive.
- Empty directories are valid.
- Invalid vendor MIB JSON files MUST cause ingestion to fail before any data is
  written to the vector database.
- Semantic plugin loading MUST follow the same behavior as the existing
  `mibdb --semantic-dir` implementation.

#### Error Handling

If vendor MIB definitions or semantic plugins cannot be loaded:

- ingestion MUST fail.
- Existing issue cases MUST remain unchanged.
- No semantic chunks MUST be committed.
- The error message SHOULD identify the failing file or plugin.

## Workspace Status

### Show Workspace Status

#### Synopsis

```text
omcipcap ai rag status
```

The `rag status` command reports the state of the active RAG workspace.

The command MUST resolve the active workspace from the global workspace
configuration.

The command MUST report:

- Workspace path
- Active profile
- Database status
- Profile/database compatibility
- Rebuild requirement
- Number of indexed issue cases

Example:

```text
Workspace:              /home/user/rag
Active profile:         workstation
Database status:        ready
Compatibility:          compatible
Rebuild required:       no
Indexed issue cases:    12
```

The database status MUST use one of the following values:

- `ready`
- `missing`
- `empty`
- `invalid`

The meanings are:

- `ready` — The vector database exists, can be opened, and contains indexed
  issue cases.
- `missing` — No vector database exists.
- `empty` — The vector database exists but contains no indexed issue cases.
- `invalid` — The vector database exists but cannot be opened, or its required
  metadata is missing or invalid.

The compatibility status MUST use one of the following values:

- `compatible`
- `incompatible`
- `unknown`
- `not-applicable`

The meanings are:

- `compatible` — The vector database metadata matches the active profile.
- `incompatible` — The vector database was built using settings that do not
  match the active profile.
- `unknown` — Compatibility cannot be determined because required metadata is
  missing or invalid.
- `not-applicable` — No vector database currently exists.

`Rebuild required` MUST be reported as `yes` when the database exists and is
incompatible with the active profile.

A missing or empty database does not by itself require a rebuild.

The indexed issue case count MUST represent the number of unique stored issue
cases, not the number of semantic chunks.

The `status` command MUST NOT:

- modify workspace files
- modify global workspace configuration
- create or rebuild the vector database
- download or load embedding models
- contact the Hugging Face Hub

If the global workspace configuration is missing or invalid, the command MUST
fail with a clear error instructing the user to run:

```text
omcipcap ai rag init --profile <profile> --dir <workdir>
```

If the configured workspace path does not exist or does not contain valid
workspace metadata, the command MUST fail without creating or modifying any
files.

---

## Profile Management

### List Profiles

#### Synopsis

```text
omcipcap ai rag profiles
```

The `rag profiles` command lists all RAG profiles supported by the installed
OMCIPcap version.

The command MUST NOT require an initialized RAG workspace.

The command MUST report:

- Profile name
- Embedding model
- Maximum tokens per chunk
- Token overlap

Profiles MUST be listed in deterministic order.

Example without an active workspace:

```text
PROFILE       ACTIVE  EMBEDDING MODEL                              MAX TOKENS  OVERLAP
standard              sentence-transformers/all-MiniLM-L6-v2      256         32
workstation           BAAI/bge-m3                                  512         64
server                BAAI/bge-m3                                  512         64
```

If an active workspace can be resolved, the active profile SHOULD be marked:

```text
PROFILE       ACTIVE  EMBEDDING MODEL                              MAX TOKENS  OVERLAP
standard              sentence-transformers/all-MiniLM-L6-v2      256         32
workstation   *       BAAI/bge-m3                                  512         64
server                BAAI/bge-m3                                  512         64
```

Failure to resolve an active workspace MUST NOT prevent supported profiles
from being listed.

If workspace metadata references an unknown profile, no profile MUST be marked
as active.

The command MUST read profile definitions from the same shared profile
configuration used by `rag init` and `rag ingest`.

Profile definitions MUST NOT be duplicated in command-specific CLI code.

The `profiles` command MUST NOT:

- initialize or modify a workspace
- create or open the vector database
- download or load embedding models
- contact the Hugging Face Hub

---

## Database Management

### Rebuild Database

#### Synopsis

```text
omcipcap ai rag rebuild
```

The `rag rebuild` command recreates the vector database from the stored issue
cases using the active profile.

The detailed rebuild behavior is specified separately.
