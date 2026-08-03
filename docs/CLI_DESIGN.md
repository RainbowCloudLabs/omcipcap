# Non-AI CLI Design

## Purpose and scope

`omcipcap` is a command-line interface for inspecting OMCI traffic captured in
PCAP files. Its current non-AI commands check protocol behavior, reconstruct and
compare MIB state, derive VLAN and T-CONT/GEM relationships, render logical
topology, and produce a combined Markdown or JSON overview.

This document describes the implemented CLI in `omci.cli` and the non-AI
modules it calls. It also records the root registration of implemented AI
provider commands. Provider internals are defined in `docs/AI_PROVIDER.md`;
diagnosis and RAG behavior are outside this document.

The installed executable is declared in `pyproject.toml`:

```text
omcipcap = omci.cli:main
```

## Command hierarchy

`main()` creates one `argparse` root parser and a set of subparsers:

```text
omcipcap
├── ai
│   ├── providers
│   ├── models
│   ├── diag
│   └── rag (when optional RAG dependencies are installed)
├── check
├── mibdb
├── mibdb-diff
│   └── alias: diff
├── topology
│   └── alias: graphic
├── vlan-tbl
├── tcont-flow
└── overview
```

Running the program without a recognized command prints root help. Unknown
commands and invalid argument types are rejected by `argparse`.

The `ai` parser is always registered for provider and diagnosis commands. Its
`rag` child is registered only when the optional RAG dependencies are available.

Aliases are parser aliases, not separate implementations. `argparse` preserves
the spelling used by the caller in `args.command`, so dispatch explicitly
accepts both `mibdb-diff` and `diff`, and both `topology` and `graphic`.

## Shared command-line arguments

Every current subparser inherits a parent parser containing a mutually
exclusive format group:

| Argument | Parsed destination | Meaning |
| --- | --- | --- |
| `-j`, `--json-output` | `json_output` | Print structured data as JSON |
| `--md` | `md` | Print rendered Markdown |

The flags cannot be combined. They are shared syntactically, but their behavior
is not completely uniform:

- `check`, `mibdb`, `mibdb-diff`/`diff`, `vlan-tbl`, and `tcont-flow` support
  Rich output by default, JSON with `-j`, and Markdown with `--md`.
- `topology`/`graphic` supports JSON and Markdown, but its default is an HTML
  file rather than Rich terminal output.
- `overview` prints Markdown by default and JSON with `-j`. `--md` may be used
  to select Markdown explicitly.

No other argument is global. In particular, `--mib-json` and `--semantic-dir`
are present only on selected subcommands.

## Execution architecture

Most commands follow this pipeline:

```text
argparse and path checks
        │
        ├── optional extension loading
        ▼
load_omci_packets()
        ▼
omciparser extraction
        ▼
renderer-neutral dict/list data
        ▼
JSON, Markdown, Rich, or command-specific file output
```

### PCAP loading

`omci.omci.load_omci_packets()` materializes the generator returned by
`omci_packets_from_pcap()`. The loader:

- reads the capture with Scapy `rdpcap()`;
- considers Ethernet packets with EtherType `0x88B5`;
- parses OMCI payloads through `OMCIPacket.from_raw()`; and
- currently yields only successfully parsed `OMCIBaseline` packets.

Each yielded item is `(zero_based_packet_index, parsed_omci_packet, raw_packet)`.
The third element is `None` unless `include_raw=True`. `check` enables raw
packets because RTT analysis uses Scapy timestamps. The other command handlers
load without raw packets, except the combined overview, which also enables raw
packets for its check data.

Capture read failures are printed by the generator and converted into an empty
packet list. Individual unsupported or malformed candidate packets are skipped.

### Semantic data extraction

`omci.omciparser` is the main boundary between packet parsing and presentation.
It reconstructs MIB state and returns ordinary dictionaries and lists for:

- MIB dumps;
- anomaly/check results;
- MIB differences;
- topology nodes and edges;
- VLAN operation rules; and
- T-CONT/GEM/priority-queue flow data.

MIB reconstruction has two modes:

- `get_mib_snapshot()` consumes MIB Upload Next responses and represents the
  initial uploaded state.
- `get_all_mib_db()` starts with uploaded entities and applies later OLT
  `Create` and `Set` requests to represent the latest reconstructed state.

`omci.omcimib.MIBInstance` decodes attributes according to `ME_SPEC`.
`MIBInstance.attr_semantic()` consults the semantic translator registry first,
then falls back to hexadecimal formatting for integers or `str()` for other
values. Unknown classes preserve mask-associated raw hexadecimal data.

This intermediate representation is intentionally independent of Rich,
Markdown, and HTML presentation. Some extraction functions delegate specialized
logic to `omci.omcivlan` and `omci.omciflow`.

### Output rendering

`output_result()` centralizes format selection for five handlers. JSON has
highest priority, then Markdown, then Rich. It uses `json.dumps()` and requires
the caller to supply the applicable Markdown and Rich renderers.

Presentation modules are separated by target:

| Module | Responsibility |
| --- | --- |
| `omci.omcirich` | Rich tables and trees written to the terminal |
| `omci.omcimd` | Markdown strings printed by the CLI |
| `omci.omcigrapher` | vis-network HTML for topology |

`output_result()` is not universal. `topology` implements its own JSON,
Markdown, and HTML branches. `overview` uses command-specific JSON and Markdown
output control.

## Output modes

| Command | Default | JSON stdout | Markdown stdout | HTML/file output |
| --- | --- | --- | --- | --- |
| `check` | Rich table | Yes | Yes | No |
| `mibdb` | Rich table | Yes | Yes | No |
| `mibdb-diff`, `diff` | Rich table | Yes | Yes | No |
| `topology`, `graphic` | HTML file | Yes | Yes | Yes, default |
| `vlan-tbl` | Rich table | Yes | Yes | No |
| `tcont-flow` | Rich tree | Yes | Yes | No |
| `overview` | Markdown stdout | Yes | Yes, default | No |

The five `output_result()` users currently emit JSON with two-space indentation.
Topology uses four-space indentation. JSON object keys that originate as
integer dictionary keys are converted to strings by `json.dumps()`.

For topology, `-o/--output-html` selects the destination only in the default
HTML mode. Without it, the path is the PCAP path with its extension replaced by
`.html`. JSON or Markdown returns before any HTML file is written. Generated
HTML references vis-network from a CDN.

`overview` always writes its selected representation to stdout and does not
create an output file automatically.

## External extension mechanisms

Extensions are loaded before packet analysis, in this order: MIB JSON, then
semantic directory.

### `--mib-json`

Supported by `mibdb`, `mibdb-diff`/`diff`, and `overview`.

The JSON file must contain a mapping from class ID to an ME specification.
`load_mib_json()` converts each key with `int()` and replaces or adds the entry
in the process-wide `omci.omcimib.ME_SPEC` dictionary. The value is converted
to a tuple; nested attribute definitions remain JSON-derived sequences accepted
by the current decoder.

This mechanism can define vendor classes or override built-in definitions for
the remainder of the process. It is not a global CLI option and is not used by
`check`, topology, VLAN, or T-CONT flow commands.

### `--semantic-dir`

Supported by the same three commands.

`omci.omcisemantic.load_external_semantics()` appends the directory to
`sys.path`, imports every non-`__*.py` file in the directory, and relies on
module side effects such as:

```python
OMCISemantic.register(class_id, attribute_name, translator)
```

Translators are stored in the process-wide `OMCISemantic` registry. They affect
calls to `MIBInstance.attr_semantic()` made after loading. Directory iteration
is not sorted, so conflicting registrations do not have a defined filename
precedence.

An invalid directory is reported and aborts command execution. Exceptions
raised while importing an extension module are not caught by this loader.

## Command behavior

### `ai providers` / `ai models`

`ai providers` prints the supported provider names in deterministic order. It
does not require credentials or perform a network request.

`ai models --provider PROVIDER` creates an adapter through the provider factory
and prints the model identifiers returned by `list_models()`. Provider
configuration, authentication, HTTP communication, response normalization, and
shared exceptions remain inside `omci.ai.providers`. Normal provider failures
are reported as `argparse` errors without a traceback.

### `ai diag`

`ai diag PCAP --problem-md FILE --provider PROVIDER --model MODEL` generates the
standard overview Markdown for one capture and combines it with the unchanged
UTF-8 problem document. The diagnosis layer loads the built-in system prompt or
the complete replacement named by `AI_DIAG_SYSTEM_PROMPT`, creates the provider
through the shared factory, and writes each generated fragment to stdout with
an immediate flush. Input, provider, and streaming failures are reported as
`argparse` errors on stderr with a nonzero exit status.

`--mib-json PATH` and `--semantic-dir DIR` use the same command-specific loading
path as `overview`. MIB definitions are loaded first, followed by semantic
extensions, before overview generation or provider creation.

### `check`

Loads one PCAP with raw packet timestamps and calls
`omciparser.get_check_results()`. It reports non-success responses, late
responses, duplicate request transaction IDs, and vendor/future-range MEs.

| Option | Behavior |
| --- | --- |
| `pcap` | Required capture path |
| `--rtt-threshold FLOAT` | Late-response threshold in milliseconds; default `1000.0` |
| `--only-vendor` | Retain only vendor/future-range observations |
| `--only-failed` | Retain only failed responses |
| `-j`, `--json-output` | JSON stdout |
| `--md` | Markdown stdout |

The filters apply to detail rows. Summary counters are accumulated before those
filters and therefore describe all detected events.

### `mibdb`

Reconstructs a MIB and converts it to a class/instance/attribute representation
containing raw `val` and semantic `text` values. Sensitive classes and
attributes are masked by the extraction layer.

| Option | Behavior |
| --- | --- |
| `pcap` | Required capture path |
| `--only-upload` | Use the uploaded snapshot instead of applying later `Create`/`Set` requests |
| `--only-vendor` | Restrict MIB reconstruction to vendor and future ranges |
| `--class-id IDS` | Comma-separated decimal class IDs |
| `--mib-json PATH` | Load ME definitions before parsing |
| `--semantic-dir DIR` | Load attribute translators before parsing |
| `-j`, `--json-output`; `--md` | Select JSON or Markdown instead of Rich |

Example:

```text
omcipcap mibdb -j --only-upload --class-id 84,171 capture.pcap
```

### `mibdb-diff` / `diff`

Loads a baseline and target capture and compares reconstructed MIB instances.
The default compares uploaded snapshots. `--full` compares state after the full
observed lifecycle, including OLT provisioning. Results classify added,
removed, and modified entries and separately report unknown-ME mask mismatches.

| Option | Behavior |
| --- | --- |
| `pcap1`, `pcap2` | Required baseline and target paths |
| `--full` | Use full reconstructed MIBs rather than upload snapshots |
| `--class-id IDS` | Restrict both MIB dictionaries before comparison |
| `--mib-json PATH` | Load ME definitions before parsing |
| `--semantic-dir DIR` | Load attribute translators before parsing |
| `-j`, `--json-output`; `--md` | Select JSON or Markdown instead of Rich |

`diff` and `mibdb-diff` reach the same handler with identical options.

### `topology` / `graphic`

Builds the full reconstructed MIB, selects topology-relevant ME classes, and
emits node and relationship data. The default output is an interactive HTML
visualization.

| Option | Behavior |
| --- | --- |
| `pcap` | Required capture path |
| `-o`, `--output-html PATH` | HTML destination; default `<pcap_without_extension>.html` |
| `-j`, `--json-output` | Print topology data as JSON and do not write HTML |
| `--md` | Print node/edge tables as Markdown and do not write HTML |

`graphic` and `topology` are equivalent aliases. There is no Rich topology
renderer.

### `vlan-tbl`

Builds the full MIB and extracts ME 171 VLAN tagging operation entries,
associations, modes, and decoded rules.

| Option | Behavior |
| --- | --- |
| `pcap` | Required capture path |
| `--tpid-dei` | Change the Rich table detail column to TPID/DEI operations |
| `-j`, `--json-output`; `--md` | Select JSON or Markdown instead of Rich |

`--tpid-dei` is passed only to the Rich renderer. It does not alter extracted
data, JSON, or Markdown output.

### `tcont-flow`

Builds the full MIB and derives the T-CONT to GEM port and priority-queue
hierarchy, including decoded bandwidth information.

| Option | Behavior |
| --- | --- |
| `pcap` | Required capture path |
| `-j`, `--json-output`; `--md` | Select JSON or Markdown instead of the Rich tree |

### `overview`

Loads one capture and combines check results, MIB data, VLAN data, T-CONT flow
data, topology data, and basic ONU capability counts into one report.

| Option | Behavior |
| --- | --- |
| `pcap` | Required capture path |
| `--mib-json PATH` | Load ME definitions before analysis |
| `--semantic-dir DIR` | Load attribute translators before analysis |
| `-j`, `--json-output` | Print JSON instead of the default Markdown |
| `--md` | Select Markdown explicitly |

Markdown is printed to stdout by default:

```bash
omcipcap overview sample.pcap
omcipcap overview sample.pcap | glow -t
omcipcap overview sample.pcap > overview.md
```

Markdown output is suitable for human reading, GitHub preview, RAG, LLM
context, and issue attachments. The report begins with `# Overview`.

JSON contains the same combined overview data and is suitable for programs,
CI/CD pipelines, and automation:

```bash
omcipcap overview sample.pcap -j
omcipcap overview sample.pcap -j > overview.json
omcipcap overview sample.pcap -j | jq
```

Both formats are written to stdout. The command does not create
`overview.md` or `overview.json` automatically. `-j` and `--md` are mutually
exclusive.

## Validation and error handling

Validation is divided between `argparse`, `main()`, and loaders:

- `argparse` enforces required positional arguments, numeric
  `--rtt-threshold`, known options, and mutual exclusion of JSON and Markdown.
- `main()` checks one-PCAP command paths before dispatch. Diff paths are checked
  separately because they use `pcap1` and `pcap2`.
- `mibdb` and diff parse `--class-id` inside their handlers. A non-decimal item
  prints an example and returns.
- A missing MIB JSON path returns failure without a message from
  `load_mib_json()`; malformed content or update errors print MIB load errors.
- A missing semantic directory prints an error and aborts dispatch.
- PCAP read errors are printed by the packet generator; malformed candidate
  frames are silently skipped.
- Renderer absence would raise `ValueError`, although every current caller of
  `output_result()` supplies its required renderers.

Most manual validation failures print to stdout and return from `main()` rather
than raising `SystemExit` with a nonzero status. Consequently, callers cannot
rely on a failing process status for every invalid path, extension, class list,
or unreadable capture. Conversely, uncaught exceptions from semantic modules,
renderers, file writes, or analysis code propagate normally.

## Current inconsistencies and exceptions

These are descriptions of implemented behavior, not recommendations:

- `output_result()` covers five commands, while topology and overview use
  command-specific output control.
- Default output means Rich terminal rendering for most commands, HTML file
  creation for topology, and Markdown stdout for overview.
- JSON indentation is two spaces through `output_result()` and four spaces for
  topology; overview also writes indented JSON.
- `--tpid-dei` affects only Rich VLAN presentation.
- PCAP existence checks and diff path checks use separate dispatch branches.
- Some invalid inputs produce messages and a successful process exit; other
  failures are argparse errors or uncaught exceptions.
- PCAP read failure and “valid capture with no supported OMCI frames” both
  generally reach analysis as an empty packet list.
- Extension loading mutates module-level registries and does not restore their
  prior state. This is normally invisible in a one-command process but matters
  when `main()` or handlers are invoked repeatedly in one interpreter.
- External semantic modules execute arbitrary Python during loading, append
  their directory to `sys.path`, and have no ordering or isolation layer.
- The topology HTML generator owns file writing, while overview writes its
  selected output to stdout.

## Design principles

New CLI commands should preserve the existing separation between argument
parsing, semantic data extraction, and output rendering.

Analysis code should return renderer-neutral structured data before Rich,
Markdown, JSON, or file-specific presentation is applied.

Command options should only be exposed when the corresponding behavior is
implemented.
