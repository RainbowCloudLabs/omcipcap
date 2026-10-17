# Architecture

## Overview

OMCIPcap loads OMCI captures, reconstructs observed MIB state, and derives
protocol checks, semantic differences, topology, VLAN rules, and traffic flows.
The CLI coordinates analysis, extensions, output selection, and AI workflows.

```text
CLI → capture loading/decoding → MIB reconstruction and analysis → rendering/export
```

AI diagnosis combines user problem descriptions with analysis reports and
streams provider responses. RAG separately indexes analysis and issue documents
for semantic case retrieval. Diagnosis currently does not retrieve RAG cases.

[AGENTS.md](../../AGENTS.md) defines development rules. Feature specifications
under `docs/design/spec/` define intended behavior and implementation details; this
map describes current module responsibilities and dependencies.

## Module Responsibilities

Paths are relative to the repository root. Related presentation and AI modules
are grouped to keep this map independent of their internal APIs.

| Module / Package | Responsibility |
|---|---|
| `omci/cli.py` | Command registration, validation, orchestration, extension loading, output dispatch, and topology file writing |
| `omci/omci.py` | Scapy capture loading and OMCI packet decoding |
| `omci/omcimib.py` | Managed-entity definitions, attribute decoding, and masking configuration |
| `omci/omcisemantic.py` | Built-in semantic translation and external translator registration/loading |
| `omci/omciparser.py` | Upload/full observed MIB reconstruction and structured check, diff, topology, VLAN, and flow results |
| `omci/omcivlan.py`, `omci/omciflow.py` | VLAN operation decoding and T-CONT/GEM/priority-queue analysis |
| `omci/omcirich.py`, `omci/omcimd.py` | Rich terminal presentation and Markdown report generation |
| `omci/omcigrapher.py` | Topology visualization data and HTML generation |
| `omci/overview.py` | Combined analysis reports and ONU capability summaries |
| `omci/ai/providers/` | Shared provider interface, provider selection, HTTP adapters, streaming, and error normalization |
| `omci/ai/diagnosis.py` | Diagnosis input handling, prompt composition, report reuse, and streamed output |
| `omci/ai/rag/` | Workspace/profile management, analysis ingestion, semantic chunking, embeddings, persistent storage, case retrieval, and status reporting |

## Feature-to-Module Mapping

All command families are registered and dispatched in `omci/cli.py`.
Module references below are relative to `omci/`; shared capture decoding and
semantic translation support the analysis families.

| Feature / CLI Command | Implementation Modules |
|---|---|
| Version: `version`, `--version` | `cli.py`, `__init__.py` |
| MIBDB: `mibdb` | `omciparser.py`, `omcimib.py`, `omcirich.py`, `omcimd.py` |
| MIBDB Diff: `mibdb-diff` / `diff` | `omciparser.py`, `omcimib.py`, `omcirich.py`, `omcimd.py` |
| Check: `check` | `omci.py`, `omciparser.py`, `omcirich.py`, `omcimd.py` |
| Topology: `topology` / `graphic` | `omciparser.py`, `omcigrapher.py`, `omcimd.py` |
| VLAN: `vlan-tbl` | `omciparser.py`, `omcivlan.py`, `omcirich.py`, `omcimd.py` |
| T-CONT Flow: `tcont-flow` | `omciparser.py`, `omciflow.py`, `omcirich.py`, `omcimd.py` |
| Overview: `overview` | `overview.py`, `omciparser.py`, `omcimd.py` |
| AI providers/models: `ai providers`, `ai models` | `ai/providers/` |
| AI diagnosis: `ai diag`, `ai diag-diff` | `ai/diagnosis.py`, `ai/providers/`, `overview.py`, `omciparser.py`, `omcimd.py` |
| RAG: `ai rag init`, `ingest`, `query`, `cases`, `status`, `profiles` | `ai/rag/`; ingestion also uses `omci.py`, `omciparser.py`, `omcimd.py`, `omcisemantic.py`, and the CLI extension loader |

## Dependencies

Scapy handles captures; Rich handles terminal tables and trees. Standard-library
JSON serialization supports structured output, while topology HTML uses
vis-network from a CDN. Parser results generally pass as dictionaries/lists to
presentation modules. The CLI selects formats and writes topology HTML.

MIB decoding uses shared managed-entity definitions and semantic translators.
The parser delegates specialized VLAN and traffic analysis to domain modules.
Overview aggregates these analyses directly for CLI output and diagnosis input.

Providers use the core `requests` dependency. Diagnosis reuses overview Markdown
and semantic diff output. Optional RAG dependencies are ChromaDB and
sentence-transformers; the CLI registers RAG commands only when they are
available. RAG ingestion renders analysis into semantic units before embedding;
query returns ranked cases without generating an LLM answer.

These dependencies do not form strict layers: RAG ingestion also imports the
CLI extension loader, and visualization uses semantic and masking helpers.
