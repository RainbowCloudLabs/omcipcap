# MIBDB Puzzle — Candidate Reconstruction Algorithm

**Status:** Proposed (implementation specification)

## 1. Scope and authoritative contract

This document is the **authoritative implementation specification for candidate generation, filtering, deduplication, ordering, evidence accounting, and consistency classification** in `omcipcap mibdb-puzzle` (alias `puzzle`).

- CLI registration, flags, wizard prompts, navigation, export and re-decode UX: [`CLI_DESIGN.md`](../CLI_DESIGN.md).
- User operation: `../../user/MIBDB-PUZZLE-README.md`.
- Existing decoder and `--mib-json` semantics remain authoritative for actual re-decode. **Do not implement another ME decoder.**

If an implementation question concerns **how candidates are computed**, this document takes precedence over illustrative candidate examples in other documents. This feature does not need a language-model step.

## 2. Goals / non-goals

**Goals:** discover unknown MEs; extract trustworthy per-message evidence; infer possible attribute sizes and boundaries; compare observations across MIB Upload Next, Get and Set; expose ambiguity and inconsistency; produce reproducible candidate IDs and explain why each survives; identify what extra observation could reduce ambiguity.

**Non-goals:** invent semantic attribute names/types/access; assume every received payload byte is valid attribute data; infer a unique vendor schema from a successful parse; treat observed values as permanent state; solve table contents or arbitrary nested vendor encodings in the MVP.

## 3. Source-code integration points (reviewed against uploaded repo)

- `omci.omci.load_omci_packets()` loads parsed capture packets; the current implementation yields baseline OMCI packets. **Report unsupported extended messages as not evaluated; do not claim full-capture coverage.**
- `omci.omciparser` builds upload snapshots and full lifecycle MIBs. Reuse its protocol interpretations, but collect **raw per-message observations** before aggregation: an accumulated MIB can lose masks, capture order and failure status.
- `omci.omcimib.ME_SPEC` is an ordered attribute definition, indexed by mask position. `MIBInstance.is_unknown` is true for classes absent from `ME_SPEC`; its `vendor_data` collects `(mask, raw hex)`.
- `omci.cli.load_mib_json()` loads custom definitions into `ME_SPEC`; `omcipcap mibdb <pcap> --class-id <id> --mib-json <file>` remains the re-decode path.
- The current upload parser extracts a fixed `content[6:32]` region. **That slice is not proof of 26 meaningful attribute bytes**. Never equate its size with the sum of unknown attribute sizes without independently establishing the real data boundary.

The implementation MUST verify field offsets and message applicability against the project's OMCI packet model / supported protocol modes before treating observations as hard constraints. Do not copy sample offsets into a new parser.

## 4. Data model

Represent each observed candidate-relevant message with an immutable record:

```text
Evidence {
  packet_index; frame_time?; class_id; entity_id;
  direction; message_type; request_response_correlation?;
  attribute_mask?; selected_attribute_indices?;
  data_bytes; payload_boundary_kind;
  status; coverage; provenance; diagnostics[]
}
```

`payload_boundary_kind`:

- `exact`: verified attribute payload byte count (not frame length).
- `bounded`: reliable lower/upper limits, no unique byte count.
- `unknown`: framing/padding/table handling prevents length constraints.

`coverage` distinguishes `hard_length`, `hard_structural`, `soft_value`, `soft_temporal`, and `unusable`. Preserve why a packet was excluded. A failed Get response, truncated capture, non-attribute response, or unsupported format cannot silently become an exact equation.

Attribute index convention: **1-based slot** `i` corresponds to the high-to-low mask order (`i=1` → `0x8000`, `i=2` → `0x4000`, `i=3` → `0x2000`). Entity ID, message header, CRC, and padding are not attribute slots. Record packet direction and distinguish response masks from request masks.

## 5. Discovery and evidence eligibility

1. Load capture once using existing packet facilities. Determine the effective known classes **after applying supported custom definitions**, if any.
2. Traverse parsed packets in capture order. Enumerate unknown `class_id` values (not merely vendor-reserved ranges); group by class and entity instance. Discovery is independent of whether a packet yields a valid length constraint.
3. Recognize applicable message-specific attribute layouts and status semantics. Prioritize MIB Upload Next data, successful Get responses and Set requests; include other messages only after explicit rules are specified and tested.
4. Exclude protocol framing, set/get masks, result codes, and padding **using message-specific rules**. Preserve the raw bytes and extraction provenance.
5. For successful Get responses, use only actually returned attributes and the correctly interpreted returned mask; a request mask alone does not prove the response layout.
6. For Set requests, bytes show an attempted write. The write does not establish resulting MIB state without response and temporal evidence.
7. MIB Upload Next might carry only a subset of an ME's attributes; multiple fragments/responses are not an automatic contiguous full schema. Do not conflate upload sequence with attribute index.
8. Reject impossible masks, malformed/truncated input, and contradictory structural fields with a diagnostic; do not silently rewrite evidence.

**Critical:** An exact hard equality is admissible only when the byte count is verifiably exact for that message and there are no unexplained padding, continuation or table-length semantics. Otherwise record `bounded`/`unknown` evidence. Baseline fixed-width fields are *not* by themselves proof of an exact attribute-data length.

## 6. Hard constraint model

For unknown class `c`, let `L_i` be the size of one actual attribute slot, with `L_i` a positive integer for an observed, ordinary fixed-length attribute. Do not silently assume unobserved slots exist with known sizes. Use a bounded domain derived from applicable OMCI format rules, not an arbitrary universal upper bound.

For an `exact` eligible observation `j` with selected slot set `S_j` and verified data byte length `D_j`:

```text
sum(L_i for i in S_j) == D_j
```

For a legitimately bounded observation, derive only defensible inequalities. Structural exclusions (negative length, bit/slot mismatch, invalid message format) are always hard failures.

**Example (schematic only; assumes exact decoded attribute lengths, not raw baseline padding):**

```text
mask 0xE000, D=10  => L1 + L2 + L3 = 10
mask 0xA000, D= 6  => L1 + L3      =  6
mask 0x4000, D= 4  =>      L2      =  4
mask 0x8000, D= 2  => L1           =  2
```

The single solution for observed slots is `(L1,L2,L3)=(2,4,4)`; **this confirms only the lengths relative to the assumed exact packet evidence**. It does not infer names/types/access or guarantee that the custom schema can model CREATE/SBC.

### Unknown / variable-length / table attributes

A table or variable-length payload cannot be modeled as an ordinary constant `L_i` without an explicitly supported framing model. Classify evidence that depends on it as unsupported or unresolved; do not reject real captures solely because the fixed-length model cannot explain them. If all reliable observations are ineligible, report `insufficient_evidence`, not zero candidates or false inconsistency.

## 7. Deterministic solution strategy (MVP)

Use a **bounded integer constraint enumerator**, implemented in Python without a required external solver dependency. The problem has at most 16 mask slots per observation, but a naive Cartesian product is still explosive.

Suggested implementation:

1. Canonicalize and deduplicate equivalent hard constraints by `(slot-set, relation, value)`, retaining all supporting packet references.
2. Identify connected components in the attribute–constraint bipartite graph; solve independent components separately.
3. Apply safe domain propagation (single-slot exact equations, lower/upper bound narrowing, residual subtraction) until fixed point.
4. Use deterministic depth-first branch-and-bound for ambiguous components: choose the next variable with the smallest remaining domain, tie-breaking by attribute index; try sizes in ascending numerical order. Prune when a partial sum exceeds an exact total or cannot reach it given remaining bounds.
5. Enumerate only within explicit CPU/node/result safety budgets. Track `complete` vs `truncated`; do not describe the initially displayed solutions as exhaustive.
6. Re-evaluate every enumerated result against **all** applicable hard constraints as a final guard.
7. Collapse equivalent solutions only if they assign identical lengths to the same attribute indices and have identical unresolved-slot coverage; no fuzzy merge.

Avoid depending on incidental Python map/set iteration order. Repeated runs on identical evidence and solver settings must return the same candidate IDs.

**Uniqueness criterion:** `unique_length_solution` only when enumeration is complete and exactly one feasible assignment exists for all required observed slots. If truncated, never report uniqueness. If a slot is unconstrained, its size is unresolved even when other slots are unique.

**Contradiction vs insufficient evidence:** if an admissible, consistent fixed-length constraint system is exhaustively infeasible, report `inconsistent_hard_evidence` with minimal helpful conflicting observations if feasible. If the extraction model is incomplete, report an unsupported-model diagnostic instead of treating the device as erroneous.

## 8. Cross-packet and temporal evidence

Use these as **separate, non-authoritative supporting evidence** unless assumptions are independently satisfied:

- **Value agreement:** compare a putative attribute byte slice across MIB Upload/Get/Set only when the same class + instance + attribute index and aligned slice are known; track intervening activity and possible device-driven changes. Equal bytes support a layout but can coincide accidentally; differing bytes are not automatically a hard contradiction.
- **Successful Set / subsequent Get:** record state transitions only after correlating request to successful response and respecting capture order. A Set request alone does not prove state changed. No observed transition is proof of immutability.
- **MIB upload snapshot:** initial state is a point-in-time observation, not an automatic model for later messages.
- **Matching across captures:** candidate lengths are class-level hypotheses; do not assume values of different entity instances are equal.

Hard evidence is used to **eliminate** candidates. Soft evidence can be presented as `matches / comparable observations` and ranked secondarily only under an explicit, versioned scoring policy. It must never override hard constraints or produce invented confidence percentages. Missing/comparison-ineligible evidence must not count as a mismatch.

## 9. Candidate identity, rank and provenance

Define a canonical candidate representation:

```text
Candidate {
  class_id; ordered_lengths: [index -> int or unresolved];
  hard_constraints_passed; soft_matches; soft_evaluated;
  supporting_packet_indices; unresolved_slots; exportable;
  warnings; solver_version; evidence_digest;
}
```

Candidate output order MUST be deterministic. Proposed priority:

1. All emitted candidates satisfy hard constraints (no ranking of invalid candidates).
2. More comparable soft consistency matches, **only when support counts are meaningful and recorded**.
3. Fewer unsupported assumptions / fewer unresolved requirements for export.
4. Lexicographic ascending `(index, length)` tuple for reproducible tie-breaking.

If no comparative soft evidence exists, explain that surviving candidates are **equally consistent**, rather than presenting the order as probability. Assign contiguous 1-based candidate IDs only **after** canonical sorting; internally defined display limits affect display, not underlying IDs. Stable ordering must not depend on pagination or interactive navigation.

When enumeration hits its safety bound, distinguish `shown`, `enumerated`, and `estimated/unknown total`. Persist solver settings and an evidence digest in an **optional sidecar** or reproducible log; the existing loader schema must remain unchanged.

## 10. Schema export preflight

`--mib-json` uses `ME_SPEC[class_id] = (name, ordered attribute definitions)` with positional tuple/list items `(<name>, <size>, <type>, <sbc>)`.

**MUST reject export** if an unobserved intermediate slot would shift bit positions, an attribute needs unsupported variable-length semantics, or any required layout component lacks a valid representation. Do not manufacture a filler attribute size to make the loader accept JSON. An unexportable candidate may still appear in the wizard with reasons.

Use neutral attribute names, opaque/hex-compatible type as verified against `MIBInstance.update`, and explicitly surface the fact that type semantics, access and set-by-create metadata are *not inferred*. The required positional `sbc` boolean may need a compatibility placeholder; document that its value is not vendor evidence and **do not claim CREATE decode validity**. For cases relying on CREATE/SBC that cannot be safely represented, do not export without a separately approved policy.

Validate the generated file with the existing loader using an isolated ME definition state where possible. Write atomically and never silently overwrite an existing file. Evidence metadata must not be inserted into the legacy schema in a way that breaks loading.

## 11. Validation and user-visible status

The wizard's `mibdb` re-decode displays existing decoder output. Separately rerun candidate checks against each eligible observation and report:

| Status | Meaning |
| --- | --- |
| `consistent` | All evaluated hard constraints pass; not a proof of true vendor schema |
| `inconsistent` | At least one evaluated hard constraint fails |
| `insufficient_evidence` | No discriminatory hard evidence or important slots/model coverage unresolved |
| `unsupported_model` | Evidence needs features outside current fixed-length solver |
| `truncated_search` | Search budget reached; completeness/uniqueness cannot be claimed |

`confirmed` MUST NOT be emitted by this MVP. Print evaluated/excluded observation counts; state which packet kinds were not evaluated. A successful `mibdb` invocation is not proof of candidate correctness.

## 12. Optional next-capture recommendation

Only after complete candidate enumeration, evaluate potentially gettable attribute masks by how they partition surviving candidates by predicted response length. Prefer **minimizing worst-case remaining candidates** without inventing candidate probability distributions. Suggestions are conditional on the ability to issue the relevant operation and on message-specific Get restrictions. Do not recommend active Set actions as a default diagnostic step.

## 13. Acceptance tests

Include deterministic unit tests and end-to-end fixture PCAP tests:

1. Mask bit mapping: `0x8000 -> attr1`, `0x4000 -> attr2`, `0x2000 -> attr3`.
2. Independent exact equations derive unique and ambiguous solutions correctly.
3. Repeated masks do not artificially increase rank or imply new independent constraints.
4. Contradictory exact evidence produces a clear infeasible report, not arbitrary candidates.
5. Raw fixed baseline payload / padding does **not** automatically create an exact length equation.
6. Failed/partial Get, request/response confusion, truncated capture, upload fragments and unsupported extended message handling remain ineligible for unsupported hard constraints.
7. Set request without successful response does not establish new MIB state.
8. Cross-instance values are never treated as identical-state evidence.
9. Table/variable-length and unknown earlier positional slots block misleading exports.
10. Repeated analysis, display limits, and interactive navigation preserve candidate IDs and deterministic order.
11. Solver time/result budget is observed; truncated output never claims exhaustive or unique solutions.
12. Exported JSON is actually loadable by existing `load_mib_json`, and selected `mibdb` works without a second decoder.
13. No fabricated percentages, semantic types, access permissions or unsupported SBC claims.
14. Zero or one unknown class and rejection of non-TTY invocation comply with `../CLI_DESIGN.md`.

## 14. Implementation gates

Before coding, verify against current code/ITU-T G.988 and capture fixtures: exact per-message payload boundaries, GET success/partial semantics, upload response record layouts, baseline/extended support, existing `sbc` handling and decoder behavior on partial bytes. Where exact semantics cannot be established, prefer **inconclusive evidence** over an invalid equation. This gate is essential to algorithm correctness.
