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

Selecting **Y** replaces the stored issue case and regenerates its associated
semantic chunks and embeddings.

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

### Query

#### Synopsis

```text
omcipcap ai rag query "<question>"
omcipcap ai rag query "<question>" --top-k <N>
```

The `rag query` command searches indexed semantic chunks internally and returns
a ranked list of unique issue cases.

The command MUST NOT print each matching semantic chunk as an independent result.

#### Default Retrieval Parameters

The implementation MUST define the following named constants:

```python
DEFAULT_TOP_K = 5
MIN_SIMILARITY = 0.70
```

If `--top-k` is omitted, the command MUST use `DEFAULT_TOP_K`.

`--top-k` represents the maximum number of unique issue cases returned, not the
maximum number of semantic chunks retrieved internally.

The value of `--top-k` MUST be a positive integer.

#### Case-Level Result Aggregation

Retrieval is performed against semantic chunks, but command output is aggregated
by `case_id`.

The command MUST perform the following steps:

1. Retrieve candidate semantic chunks from the active vector database.
2. Convert the database distance into a consistent similarity score.
3. Discard chunks whose similarity score is below `MIN_SIMILARITY`.
4. Group the remaining chunks by `case_id`.
5. Select one representative chunk for each case.
6. Rank the unique cases using their representative chunks.
7. Return no more than `top-k` unique cases.

Each `case_id` MUST appear at most once in the output.

The representative chunk for a case MUST be the highest-ranked matching chunk
belonging to that case.

Representative chunks MUST be compared using the following order:

1. Higher semantic similarity
2. Higher metadata `priority`
3. Lower `chunk_index`
4. Lexicographical `case_id`

Semantic similarity is the primary ranking signal. Metadata priority MUST NOT
cause a clearly less relevant chunk or case to outrank a clearly more relevant
one.

The displayed score for a case MUST be the similarity score of its
representative chunk.

The command MUST NOT return unrelated cases merely to fill `top-k`.

If fewer than `top-k` unique cases satisfy the minimum similarity threshold,
only the matching cases MUST be returned.

#### Output

The default output MUST use the following case-level table format:

```text
Rank  Score  Case ID
----  -----  --------
1     0.91   CASE-023
2     0.84   CASE-017
3     0.80   CASE-002
```

Output requirements:

- `Rank` starts at `1`.
- `Score` is the representative chunk similarity score.
- `Score` SHOULD be displayed with two decimal places.
- `Case ID` is the unique stored issue-case identifier.
- Results MUST be sorted from the strongest match to the weakest match.
- Output formatting MUST be deterministic.
- Chunk text and chunk metadata MUST NOT be printed in the default output.

Users can inspect a returned case with:

```text
omcipcap ai rag show <case-id>
```

If no semantic chunk satisfies `MIN_SIMILARITY`, the command MUST print:

```text
No matching issue cases found.
```

The no-match condition MUST exit normally and MUST NOT print unrelated cases.

If the vector database exists but contains no indexed issue cases, the command
MUST print:

```text
No indexed issue cases found.
```

#### Query Restrictions

The `rag query` command MUST NOT:

- modify the workspace
- modify indexed issue cases
- create the vector database
- download embedding models
- contact the Hugging Face Hub during normal operation
- generate an LLM answer
- summarize issue cases

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
- Number of indexed issue cases

Example:

```text
Workspace:              /home/user/rag
Active profile:         workstation
Database status:        ready
Compatibility:          compatible
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

The indexed issue case count MUST represent the number of unique stored issue
cases, not the number of semantic chunks.

The `status` command MUST NOT:

- modify workspace files
- modify global workspace configuration
- create the vector database
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

### Cases

#### Synopsis

```text
omcipcap ai rag cases
```

The `rag cases` command lists all indexed issue cases stored in the active RAG
workspace.

The command MUST resolve the active workspace from the global workspace
configuration.

#### Output

The default output MUST use the following table format:

```text
CASE ID        CHUNKS  PROBLEM
-------------  ------  -----------------------------------------------
CASE-001       8       VEIP creation failure after MIB synchronization
CASE-002       5       VLAN translation rule mismatch
Xtelecom0002   6       TR-069 WAN IPHost provisioning failed
```

Output requirements:

- `CASE ID` is the unique stored issue-case identifier.
- `CHUNKS` is the total number of indexed semantic chunks belonging to the case.
- `PROBLEM` is the extracted `Problem` section stored in the RAG metadata.
- Cases MUST be sorted lexicographically by `CASE ID`.
- Output formatting MUST be deterministic.

If no issue cases have been indexed, the command MUST print:

```text
No indexed issue cases found.
```

#### Data Source

The command MUST obtain information from the vector database.

Issue cases MUST be aggregated by `case_id`.

For each unique case:

- `CHUNKS` is the number of semantic chunks having the same `case_id`.
- `PROBLEM` is the stored problem summary associated with the case.

The implementation MUST NOT parse stored Markdown documents to obtain the
Problem section.

The Problem summary MUST be read from metadata stored during `rag ingest`.

#### Workflow

The `rag cases` command MUST perform the following steps in order:

1. Resolve and validate the active workspace.
2. Validate database compatibility.
3. Open the vector database.
4. Aggregate indexed chunks by `case_id`.
5. Display one row for each unique issue case.

#### Restrictions

The `rag cases` command MUST NOT:

- modify the workspace
- modify indexed issue cases
- regenerate semantic chunks
- re-run PCAP analysis
- download embedding models
- load embedding models
- contact the Hugging Face Hub

Users can inspect a listed issue case with:

```text
omcipcap ai rag show <case-id>
```

The `Problem` metadata MUST be identical for all chunks belonging to the same
`case_id`.

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

### Rebuild Database — Planned / Not Yet Implemented

`rag rebuild` is reserved for a future release and is not available in the
first-stage RAG MVP.

The current implementation does not support profile migration, workspace
migration, workspace merging, or changing the embedding model of an existing
workspace. Reinitializing an existing workspace with another profile is also
unsupported.

To use a different embedding profile, create a new workspace with the desired
profile and re-ingest the issue cases. Future rebuild behavior will be
specified separately; no future command syntax beyond the reserved
`rag rebuild` name is defined here.
