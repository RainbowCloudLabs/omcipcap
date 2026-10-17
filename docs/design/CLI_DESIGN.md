# Non-AI CLI Design

## Purpose and scope

`omcipcap` is a command-line interface for inspecting OMCI traffic captured in
PCAP files. Its current non-AI commands check protocol behavior, reconstruct and
compare MIB state, derive VLAN and T-CONT/GEM relationships, render logical
topology, and produce a combined Markdown or JSON overview.

This document describes the implemented CLI in `omci.cli` and the non-AI
modules it calls. Sections explicitly marked as planned define target behavior
that is not yet implemented. It also records the root registration of implemented AI
provider commands. Provider internals are defined in `spec/AI_PROVIDER.md`;
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
│   ├── diag-diff
│   └── rag (when optional RAG dependencies are installed)
├── version
├── check
├── mibdb
├── mibdb-puzzle (planned)
│   └── alias: puzzle
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

The root parser description includes the version from `omci.__version__`.
`omcipcap --version` prints the short version and exits successfully.

The `ai` parser is always registered for provider and diagnosis commands. Its
`rag` child is registered only when the optional RAG dependencies are available.

Aliases are parser aliases, not separate implementations. `argparse` preserves
the spelling used by the caller in `args.command`, so dispatch explicitly
accepts both `mibdb-diff` and `diff`, and both `topology` and `graphic`.

The planned `mibdb-puzzle` and `puzzle` names must also share a single
parser/handler, not two implementations.

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
| `mibdb-puzzle`, `puzzle` (planned) | Interactive wizard (TTY) | No | No | Candidate JSON schema export |
| `mibdb-diff`, `diff` | Rich table | Yes | Yes | No |
| `topology`, `graphic` | HTML file | Yes | Yes | Yes, default |
| `vlan-tbl` | Rich table | Yes | Yes | No |
| `tcont-flow` | Rich tree | Yes | Yes | No |
| `overview` | Markdown stdout | Yes | Yes, default | No |
| `version` | Project information | Yes | No | No |

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

Supported by `mibdb`, `mibdb-diff`/`diff`, `overview`, `ai diag`, and
`ai diag-diff`.

The JSON file must contain a mapping from class ID to an ME specification.
`load_mib_json()` converts each key with `int()` and replaces or adds the entry
in the process-wide `omci.omcimib.ME_SPEC` dictionary. The value is converted
to a tuple; nested attribute definitions remain JSON-derived sequences accepted
by the current decoder.

This mechanism can define vendor classes or override built-in definitions for
the remainder of the process. It is not a global CLI option and is not used by
`check`, topology, VLAN, or T-CONT flow commands.

### `--semantic-dir`

Supported by the same commands.

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

## Sensitive-data masking environment overrides

The implementation uses the `SENSITIVE_ME_CLASSES` and
`SENSITIVE_ME_ATTRIBUTES` sets in `omci.omcimib`, resolving environment overrides
with `configure_sensitive_masking()` before analysis in the CLI.

Users can replace either masking set through environment variables,
without adding CLI arguments or a configuration file:

| Environment variable | Replacement value |
| --- | --- |
| `OMCIPCAP_SENSITIVE_ME_CLASSES` | Comma-separated decimal OMCI class IDs, each in the range `0` through `65535` |
| `OMCIPCAP_SENSITIVE_ME_ATTRIBUTES` | Comma-separated attribute-name fragments, matched case-insensitively |

Each variable is independent:

- When absent, use the corresponding built-in set.
- When present and nonempty, replace the corresponding set completely; do not
  append to the built-in entries.
- When empty or containing only whitespace, use an empty set, disabling that
  category of masking.

Trim surrounding whitespace from each entry, normalize attribute fragments to
lowercase, and collapse duplicate entries. Empty entries within a nonempty
comma-separated list are invalid. Class IDs must use decimal digits; reject
hexadecimal notation, negative values, nonnumeric entries, and out-of-range IDs.

An attribute is masked as `*****` when its class is in the effective class set
**or** its name contains any fragment in the effective attribute set. Clearing
one set does not disable masking provided by the other. To disable both
categories, users must explicitly clear both variables.

Resolve and validate the environment settings before capture loading or
analysis for commands that use these masking rules. Invalid settings must
produce a clear error on stderr identifying the variable and invalid entry,
and terminate with a nonzero exit status. Do not silently fall back to defaults
or partially apply an invalid list. Resolve settings for each command invocation
so repeated calls in one Python process do not retain a previous invocation's
overrides; preserve the built-in defaults separately from the effective sets.

The effective sets apply consistently to existing masking paths: MIB extraction
(`val` and `text`), semantic diff values (`old` and `new`), and topology HTML
tooltips. Commands that reuse these paths, including overview and AI reports,
inherit the same settings. Aliases use identical settings. Output schemas,
diff detection and counts, and semantic decoding of unmasked values remain
unchanged. This feature does not add masking to topology JSON attributes or
unknown-ME raw payloads, and does not change topology class selection.

Usage with replacement lists:

```bash
export OMCIPCAP_SENSITIVE_ME_CLASSES="148,153"
export OMCIPCAP_SENSITIVE_ME_ATTRIBUTES="password,secret"
omcipcap mibdb capture.pcap
```

Usage to disable both masking categories and expose original values:

```bash
export OMCIPCAP_SENSITIVE_ME_CLASSES=""
export OMCIPCAP_SENSITIVE_ME_ATTRIBUTES=""
omcipcap mibdb capture.pcap
```

Use `unset` on either variable to restore its built-in defaults. These settings
are documented in `README.md`. `tests/test_sensitive_env.py` covers absent,
replacement, empty, whitespace, malformed, and repeated-invocation settings,
both masking categories together, MIB Rich/JSON/Markdown, diff output and
aliases, overview reuse, and generated HTML tooltips. Invalid settings use
`parser.error()` and exit with status `2` before capture loading. Both lists are
validated before either effective set is updated. The sets are updated in place
so parser and grapher imports share the same effective rules, while immutable
copies retain the built-in defaults.

## Command behavior

### `version`

`version` prints stable human-readable version, author, project, and feedback
information. `-j`/`--json-output` emits the same project metadata as JSON.
Both the subcommand and the root `--version` option read the package version
from `omci.__version__`, which is also the version source used by packaging.

### `ai providers` / `ai models`

`ai providers` prints the supported provider names in deterministic order. It
does not require credentials or perform a network request.

`ai models --provider PROVIDER` creates an adapter through the provider factory
and prints the model identifiers returned by `list_models()`. Provider
configuration, authentication, HTTP communication, response normalization, and
shared exceptions remain inside `omci.ai.providers`. Normal provider failures
are reported as `argparse` errors without a traceback.

### `ai diag` / `ai diag-diff`

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

`ai diag-diff TARGET --golden-pcap GOLDEN --problem-md FILE --provider
PROVIDER --model MODEL` reconstructs the full observed MIB lifecycle for both
captures and applies the existing semantic diff pipeline in the Target-to-Golden
direction. Its provider user prompt contains the unchanged problem Markdown,
the rendered semantic diff with explicit direction semantics, the Golden
overview, and the Target overview, in that order. Both overviews use the same
generator and renderer as `overview`. Output and errors follow `ai diag`.

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

### `mibdb-puzzle` / `puzzle` (planned)

**Status: Planned — design only; not yet implemented.** `mibdb-puzzle` is the primary
command, and `puzzle` is an `argparse` alias of the *same* command/handler,
following the established `mibdb-diff`/`diff` convention. Candidate generation, constraint solving, filtering, deduplication, ordering,
and consistency classification **MUST follow** `docs/design/spec/MIBDB-PUZZLE-ALG.md`.
Usage examples belong in `docs/user/MIBDB-PUZZLE-README.md`.

The command reconstructs candidate attribute boundaries for unknown OMCI ME
classes using packet evidence and deterministic constraint solving. v1 supports
only the Interactive Wizard. The positional `pcap` argument is the only input;
Unknown ME selection takes place inside the Wizard.

```bash
omcipcap mibdb-puzzle examples/omci.pcap
omcipcap puzzle examples/omci.pcap
```

#### Options

| Option | Behavior |
| --- | --- |
| `pcap` | Required capture path |


#### Interactive wizard (TTY)

The `mibdb-puzzle <pcap>` invocation requires standard input to be a TTY. The
wizard follows the explicit sequence below; prompts must not advance on invalid
input. All identifiers displayed in a menu are **selection numbers**, not ME
class IDs or attribute indexes.

| Step | Prompt / display | User action | Next step |
| --- | --- | --- | --- |
| 1. Discover | List all unknown ME class IDs in the capture; show each class's observed instance count, packet count, and distinct masks | Select an ME by menu number | 2 |
| 2. Analyze | Show selected class, evidence summary, constraint coverage, and candidate layouts within internally defined display limits | Select a candidate by number | 3 |
| 3. Preview | Display ordered attribute indexes, sizes, unresolved positions, supporting observations, and export limitations | Confirm candidate, choose another candidate, or return to the ME menu | 4 or 2 or 1 |
| 4. Export | Show proposed `<class-id>-<candidate-id>.json` path | Accept path, enter another path, or cancel | 5 on successful export |
| 5. Re-decode | Show `omcipcap mibdb <pcap> --mib-json <path>` | Answer `[Y/n]` to invoke existing `mibdb` and display its results | 6 |
| 6. Result | Report export status and separately summarize candidate consistency; do not label decoding success as schema confirmation | Exit or return to ME selection to analyze another unknown class | End or 1 |

Example terminal session (illustrative data; **not** a predicted result):

```text
$ omcipcap puzzle examples/omci.pcap

Unknown ME classes:
  #   Class ID   Instances   Packets   Masks
  1   65530      3           28        4
  2   65535      1           12        2

Select unknown ME [1-2] (q=quit): 1

Class ID 65530 — candidate layouts
  #   Attribute lengths          Evidence
  1   attr1=2B, attr2=4B         consistent
  2   attr1=4B, attr2=2B         consistent

Select candidate [1-2] (b=back, q=quit): 1

Candidate #1 preview
  attr1: unknown_attr_1 (2 bytes, opaque)
  attr2: unknown_attr_2 (4 bytes, opaque)
  Validation: consistent with evaluated packet constraints
  Exportable: yes (all required positions resolved)

Export this candidate? [Y/n/b]: y
Output file [65530-1.json]:
Exported: 65530-1.json

Re-decode using existing mibdb? [Y/n]: y
  omcipcap mibdb examples/omci.pcap --mib-json 65530-1.json
  ... existing mibdb output ...

Consistency: consistent (not independently confirmed)
Analyze another unknown ME? [y/N]: n
```

**Wizard behavior and edge cases:**

- Discovery includes **all** unknown ME classes, not just vendor-reserved IDs.
  Unknown means no available built-in or loaded custom schema. Sort classes
  by numeric class ID for reproducibility. If there is exactly one class,
  display it and skip the class-selection prompt; if none, print a clear message
  and exit successfully.
- Candidate numbers are stable within an analysis result. Display limits and
  solver search limits are internally defined according to the algorithm
  specification; display limits do not change candidate IDs or solver results.
  Do not renumber candidates after pagination or interactive navigation.
  If there is no valid candidate, report why and do not offer export.
- Invalid menu input must show the allowed range and re-prompt. `b` returns
  to the preceding applicable selection screen; `q`, Ctrl-C, or EOF cancels
  gracefully without a partial JSON export.
- Preview must warn if required attribute positions are unresolved or SBC
  assumptions lack evidence. Such a candidate is **not exportable** if the
  existing positional `--mib-json` schema would misalign mask bits. The wizard
  may display it, but must not offer a misleading exported file.
- Default output is `<class-id>-<candidate-id>.json`; never silently overwrite
  an existing file. Ask for a new path or explicit overwrite confirmation.
  Use an atomic file write, so interruption cannot leave truncated JSON.
- Re-decode uses the existing `mibdb` command/handler and its established
  presentation (no new parser). Declining re-decode still leaves the exported
  JSON on disk. If re-decode fails, preserve the JSON, display the error,
  and report validation separately.
- If standard input is not a TTY, display a clear error that Puzzle requires
  an interactive terminal and exit with a nonzero status. Do not wait for input
  or fall back to non-interactive execution.

Candidate generation, evidence eligibility, constraint solving, candidate ordering and IDs, ambiguity reporting, and cross-packet consistency checks MUST follow `docs/design/spec/MIBDB-PUZZLE-ALG.md`.

The CLI Wizard is responsible only for interaction and presentation. It MUST NOT define an independent candidate-generation or scoring algorithm.

The existing `--mib-json` ME tuple schema is **positional**. If unobserved
attribute lengths prevent correct mask-bit alignment, the command must not
silently export a misleading schema. Attribute type and SBC assumptions must
be disclosed. Schema export should retain evidence/provenance separately if
the current loader cannot accept metadata.

After candidate selection/export, the wizard may display and invoke the
**existing** command rather than implementing a second decoder:

```bash
omcipcap mibdb examples/omci.pcap --mib-json 65530-1.json
```

A successful `mibdb` decode only shows that the selected definition can be
consumed. The solver must separately report whether all usable packet
constraints remain **consistent**; it must not call a candidate **confirmed**
without independent evidence. With no unknown ME, report an empty discovery
result and exit successfully in the Interactive Wizard. Non-TTY invocation
is rejected as described above.

The wizard presents candidates in the terminal and prompts for the output
filename when exporting the selected ME schema JSON. Unlike report-oriented
commands, `mibdb-puzzle` does not expose `-j`, `--json-output`, or `--md` in the proposed MVP. Any later
structured candidate-report format should be specified separately from the
`--mib-json`-compatible schema export.

This section records the proposed CLI surface; its arguments, status codes,
and output schema require source-level review before implementation.

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
  prints an example and exits with status `1`.
- A missing MIB JSON path returns failure without a message from
  `load_mib_json()`; malformed content or update errors print MIB load errors.
- A missing semantic directory prints an error and aborts dispatch.
- PCAP read errors are printed by the packet generator; malformed candidate
  frames are silently skipped.
- Renderer absence would raise `ValueError`, although every current caller of
  `output_result()` supplies its required renderers.

OMCIPcap explicitly defines the following exit statuses:

- `0`: The selected subcommand completed successfully.
- `1`: OMCIPcap explicitly detected and handled a command/input failure,
  including missing capture paths, invalid class lists, rejected MIB JSON or
  semantic directory inputs, and missing subcommands.

Python `argparse` handles argument parsing and usage errors, such as an omitted
required capture argument, and normally exits with status `2`. This is inherited
`argparse` behavior, not an OMCIPcap-defined exit status. Handled AI/provider/RAG
errors reported through `parser.error()` also follow this library behavior.

Manual validation messages generally remain on stdout; a nonzero exit status
does not imply a message on stderr. Uncaught exceptions from semantic modules,
renderers, file writes, or analysis code propagate normally and are not
normalized by a universal CLI exception handler.

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
- Explicit manual validation failures exit with status `1`; errors reported
  through `argparse` follow its inherited exit behavior, normally status `2`.
  Unexpected exceptions may still propagate uncaught.
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
