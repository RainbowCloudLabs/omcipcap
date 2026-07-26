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
