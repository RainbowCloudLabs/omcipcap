# AGENTS.md

## Repository overview

`omcipcap` is a Python 3.10+ command-line tool for decoding and analyzing OMCI
traffic in PCAP files. It uses Scapy for capture handling and Rich for terminal
output. The package is installed with setuptools; the `omcipcap` entry point is
`omci.cli:main`.

Treat the checked-in implementation and tests as the source of truth when
documenting existing behavior. An approved design document may define planned
target behavior before code changes. During implementation, an explicitly
referenced approved design document is the target behavior; do not silently
change it merely to match existing code. Clearly label planned behavior until
the implementation and tests are complete.

## Project architecture

- `omci/cli.py`: `argparse` command definitions, validation, extension loading,
  orchestration, and output-mode dispatch.
- `omci/omci.py`: OMCI packet models and PCAP loading. The current loader
  selects EtherType `0x88B5` and yields successfully parsed baseline frames.
- `omci/omcimib.py`: managed-entity identifiers, built-in `ME_SPEC`, MIB
  instances, attribute decoding, and semantic lookup.
- `omci/omcisemantic.py`: built-in semantic translators and dynamic translator
  registration.
- `omci/omciparser.py`: reconstruction of upload snapshots and full MIB state,
  plus renderer-neutral check, diff, topology, VLAN, and flow results.
- `omci/omcivlan.py`, `omci/omciflow.py`: focused VLAN and T-CONT/GEM/PQ domain
  logic.
- `omci/omcirich.py`, `omci/omcimd.py`, `omci/omcigrapher.py`: Rich,
  Markdown, and topology HTML presentation.
- `omci/overview.py`: aggregation of existing analyses into `overview.json`.
- `utils/`: deterministic PCAP generators used by tests.
- `tests/`: unit and subprocess-level CLI coverage.
- `examples/` and `extensions/`: sample captures, custom ME definitions,
  semantic extensions, images, and generated examples.
- `docs/`: design documentation. Read `docs/CLI_DESIGN.md` before changing CLI
  behavior.

Keep the main data flow intact:

```text
PCAP loading -> packet/MIB decoding -> semantic analysis data -> renderer
```

## Coding principles

- Make the smallest change that fully addresses the request.
- Preserve separation between capture parsing, domain analysis, and
  presentation. Analysis functions should return ordinary dictionaries/lists,
  without Rich markup, Markdown syntax, or HTML.
- Reuse `OMCIClass`, `ME_SPEC`, `MIBInstance`, and existing semantic helpers
  instead of duplicating protocol constants or decoders.
- Keep raw values and semantic text deterministic. Preserve masking of
  sensitive ME classes and attributes.
- Maintain Python 3.10 compatibility and avoid dependencies that are not
  justified in `pyproject.toml`.
- Follow the existing straightforward module style. There is no configured
  formatter or linter; avoid unrelated formatting churn.
- Preserve user changes and generated/sample assets unless the task explicitly
  includes them.

## Design-first workflow

Before implementing a user-visible behavior change, identify the corresponding
design document under `docs/`.

Examples include:

- `docs/CLI_DESIGN.md`
- `docs/RAG_DESIGN.md`

If the requested implementation conflicts with the approved design:

1. Do not silently modify the implementation.
2. Explain the inconsistency.
3. Ask whether the design document should be updated first, or whether the
   implementation should intentionally diverge from the current design.
4. Proceed only after the design direction is confirmed.
5. Do not modify the design document unless the user explicitly requests a
   design update.

When an approved design document is explicitly referenced by the task, treat it
as the target behavior for implementation.

## CLI architecture rules

- Define arguments and dispatch in `omci/cli.py`; keep substantive analysis in
  parser or domain modules and rendering in presentation modules.
- Decide explicitly whether a command uses `get_mib_snapshot()` or
  `get_all_mib_db()`. The distinction between upload state and the full observed
  lifecycle is public behavior.
- Request `include_raw=True` only when raw Scapy packets or timestamps are
  needed.
- Use `output_result()` for commands that genuinely support the standard
  Rich/JSON/Markdown pattern. Do not claim or assume it covers topology or
  file-producing commands.
- Add shared output flags only when they have meaningful implementations.
  Preserve the mutual exclusion of JSON and Markdown.
- Keep aliases behaviorally identical (`mibdb-diff`/`diff` and
  `topology`/`graphic`).
- Treat JSON shapes, Markdown structure, default output mode, filenames, and
  stdout status messages as public interfaces.
- `--mib-json` and `--semantic-dir` are command-specific extensions, not global
  configuration. Load them before analysis only for commands that declare them.
  Be aware that they mutate process-wide registries.
- Validate paths and values before expensive work. Existing error and exit-code
  behavior may be inconsistent; do not silently “normalize” it in an unrelated
  change.

## Documentation workflow

- Inspect implementation and tests before documenting existing behavior; use
  README examples only as supporting evidence.
- An approved design document may describe planned target behavior before
  implementation. During an implementation task, follow the explicitly
  referenced approved design and do not silently rewrite it to match current
  code.
- Clearly label and separate planned behavior from implemented behavior until
  the implementation and tests are complete.
- Update `README.md` for user-facing installation, command, or option changes.
- Update `docs/CLI_DESIGN.md` for CLI architecture, output-mode, extension, or
  execution-flow changes.
- Keep examples short and executable. Do not present planned commands,
  configuration systems, or formats as already implemented.
- Documentation-only changes should not modify source, tests, generated
  captures, or unrelated documents.

## Testing expectations

Run the narrowest relevant tests during development, then the full suite for
behavioral changes:

```bash
pytest -v
```

The CI suite runs on Python 3.10, 3.11, and 3.12. CLI tests invoke the installed
`omcipcap` executable and generate temporary PCAPs in the repository root, so
install the project in editable mode when needed:

```bash
python -m pip install -e .
```

Add or update tests for every affected interface:

- terminal content for Rich behavior;
- valid JSON and exact schema/values for JSON modes;
- headings/tables/content for Markdown;
- topology nodes, edges, aliases, and HTML file creation where applicable;
- MIB upload versus full-lifecycle reconstruction;
- custom MIB definitions and semantic extensions;
- malformed packets, invalid arguments, and file errors.

Tests and generators must clean up files they create. Do not weaken exact
assertions merely to make a changed implementation pass.

## Refactoring policy

Refactor only when required by the task or when it directly reduces risk in the
requested change. First characterize existing behavior with tests. Keep
refactors separate from feature changes where practical, and avoid broad
renames, module moves, schema rewrites, or output reformatting without explicit
scope.

Protocol parsing is high-risk: preserve byte offsets, masks, baseline/extended
framing behavior, vendor/future class ranges, and Create/Set reconstruction
semantics. Prefer extracting small pure helpers over introducing new framework
layers.

## Backward compatibility policy

Assume compatibility is required for:

- command names, aliases, option names, defaults, and accepted argument order;
- default Rich/HTML/file behavior and output destinations;
- JSON keys, nesting, value types, and semantic text;
- Markdown sections and tables used by tests or automation;
- external `--mib-json` schema and `OMCISemantic.register()` extensions;
- importable functions and classes already exercised by tests or examples;
- Python 3.10 through 3.12 and packaged/PyInstaller entry-point operation.

Any intentional incompatibility must be called out, justified, documented, and
covered by tests.

## Things an AI agent should avoid

- Do not invent or expose unimplemented commands, AI/RAG features, databases,
  profiles, workspaces, or configuration systems.
- Do not mix packet loading, semantic extraction, and rendering into one layer.
- Do not make every command support every output format by assumption.
- Do not treat `--mib-json` or `--semantic-dir` as global options.
- Do not change JSON schemas, semantic strings, Markdown headings, aliases, or
  output filenames casually.
- Do not replace deterministic fixture generators with opaque binary fixtures
  when generator coverage is practical.
- Do not swallow new exceptions broadly or change process exit behavior without
  tests and explicit intent.
- Do not execute or trust external semantic-extension Python as though it were
  inert data.
- Do not modify release workflows, dependencies, versioning, or packaging as a
  side effect of an unrelated task.
- Do not delete or overwrite user work, sample captures, or generated artifacts
  outside the requested scope.
