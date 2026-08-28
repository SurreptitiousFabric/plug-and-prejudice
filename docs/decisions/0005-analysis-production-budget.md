# 0005: Deterministic result production budget

- Status: implemented; independent security and report-semantics approval pending
- Date: 2026-08-27

## Context

Inventory bounds input files and bytes, systemd bounds process resources, and
the broker rejects scanner stdout above 16 MiB. None of those controls prevents
the scanner from amplifying compact filesystem/source input into a large
in-memory result before serialization. Ten thousand long relative filenames can
make inventory metadata alone exceed the output ceiling. Within the current 2 MiB per-file limit, repeated one-character
shell commands can represent roughly one million calls. A single command line
can also contain hundreds of thousands of operands, each of which may derive a
resource and finding. One source line or argument can consume the entire file
budget and is currently copied into evidence. Nested collections are another
amplifier: a compact manifest can declare many kinds and entry points, an ELF
dynamic table can yield many imported-library strings, and a structurally valid
report can contain large argument, evidence, or related-operation arrays inside
otherwise bounded top-level collections.

Rejecting an oversized final report fails closed but discards otherwise useful
evidence and spends memory constructing a result that cannot be presented.
Silent truncation would be worse: it could make a partial scan appear complete.

## Options considered

### Rely only on cgroup and serialized-output limits

Rejected. These controls limit host impact but do not preserve a useful report,
and an out-of-memory kill cannot explain which analysis was omitted.

### One global entry-count limit

Rejected. Counts do not bound large strings and let an early flood of neutral
operations consume the entire allowance before a later high-impact finding.

### Separate count limits only

Rejected as incomplete. Separate operation/resource/finding limits preserve
category capacity but still allow multi-megabyte arguments and evidence fields.

### Combined count, string, and derived-byte budgets

Recommended. Account the exact JSON-encoded contribution of hostile strings,
including escaping, rather than their raw byte length. Apply all of the
following while producing scanner results:

- at most 3 MiB of aggregate encoded hostile string data retained in inventory
  metadata;
- at most 5,000 operations;
- at most 10,000 resources;
- at most 10,000 findings;
- at most 20,000 typed evidence relationships retained across resources and
  findings;
- at most 1,024 arguments retained per operation;
- at most 128 manifest kinds and 128 manifest entry points;
- at most 1,024 imported-library names retained per ELF and an aggregate ELF
  metadata charge within the inventory string budget;
- at most 8 evidence items and 16 related operation IDs retained per finding;
- at most 4 KiB for an individual command, argument, resource value, evidence
  operation, evidence excerpt, manifest string, entry-point key/value, or
  imported-library name; and
- at most 6 MiB of aggregate encoded hostile string data retained across operations,
  resources, findings, and their evidence.

These nested caps are compatibility headroom, not observed normal sizes:
Omarchy currently defines six known plugin kinds, deterministic findings use at
most two related operations and a small fixed evidence set, and ordinary ELF
binaries import far fewer than 1,024 libraries. The larger limits allow future
schema/rule growth without allowing one inner collection to consume the whole
report. Changing a cap remains a reviewed report and resource-policy change.

Paths repeated into operations, resources, findings, limitations, or errors are
charged each time they are serialized. JSON encoding size includes quotes and
escape expansion; raw byte counts are not a safe proxy. The combined hostile
string budgets are deliberately below the broker's 16 MiB stdout ceiling,
leaving room for fixed explanations, numeric/boolean fields, JSON structure,
limitations, and errors. Before stdout, encode through a bounded buffer and
assert the complete document remains within the broker ceiling. The serialized
limit remains an independent final defense, not something the estimates claim
to prove. The accepting report validator must independently reject inner
collections above the same structural maxima (arguments, manifest collections,
ELF libraries, evidence, and relationships), even though its top-level
cardinality ceilings are intentionally larger than normal producer budgets.

Budgets apply during construction, not after an unbounded temporary value has
already been built. In particular:

- shell evidence should use the parser's source byte offsets to retain a
  bounded inert source slice instead of pretty-printing an arbitrarily nested
  AST node and truncating the completed string;
- shell literal extraction uses a capped builder and marks the result dynamic
  and incomplete as soon as a command or argument exceeds its individual
  budget;
- QML command-array extraction stops retaining arguments at the cap while
  continuing only the minimum lexical work needed to classify the expression
  as partial/dynamic; and
- JSON encoded-size accounting occurs before appending a value to a retained
  result collection.

The selected shell parser constructs the AST before these steps, but evidence
formatting must not introduce an additional nested-tree traversal for every
operation. A bounded writer around the current pretty-printer is insufficient:
its buffered printer can continue walking the node after the destination has
refused more bytes.

## Proposed semantics

Crossing a budget must never be silent:

1. retain already-established entries and their valid relationships;
2. stop inventory deterministically when its metadata budget is exhausted and
   record that remaining directory entries were not inventoried;
3. do not append a finding or resource whose originating operation was not
   retained;
4. append one deduplicated `result-production-limit` limitation for each
   affected source path and scope;
5. make the report `incomplete`;
6. stop the affected derivation path, while continuing cheap coverage and
   inventory accounting where budgets permit; and
7. never reinterpret truncated text as a complete literal. If a bounded prefix
   is retained for display, mark the operation dynamic, lower confidence, and
   identify the omitted portion visibly.

For nested metadata specifically, manifest entry-point keys are sorted before
a bounded prefix is retained; manifest kind order remains author order. The
report receives a path-specific limitation stating that the author claim is
partial. Imported-library names are sorted before retaining a bounded prefix
and receive a path-specific limitation. A derived finding whose evidence or
relationship set cannot be retained consistently is omitted as a unit and
replaced by the production-limit limitation; it is never emitted with broken or
silently incomplete provenance.

Deterministic ordering decides which evidence is retained: canonical path order,
then source order, then rule order. Severity must not influence retention because
that would require deriving the very entries the budget is intended to bound.
The report validator's larger cardinality ceilings remain a producer-compromise
boundary and must not be reused as the normal analysis budget.

## Required verification

Implementation requires:

- exact-bound and first-over-bound tests for every dimension, including
  worst-case JSON escape expansion;
- exact-bound and first-over-bound tests for every nested manifest, ELF,
  argument, evidence, and relationship collection;
- many-long-filenames inventory tests;
- a many-small-commands fixture generated in memory, never executed;
- one-command/many-operands and one-huge-literal cases;
- deeply nested shell calls proving evidence construction is bounded during
  traversal rather than only truncated afterward;
- assertions that status is incomplete and limitations name the affected path;
- relationship validation after every truncation path;
- deterministic output across repeated runs;
- fuzz and race tests; and
- peak memory/output measurements below the systemd and broker ceilings on
  native ARM64 and AMD64 release candidates.

## Residual risk

The shell parser constructs an AST before the analyzer walks it, so production
budgets do not bound parser allocation. The verified 256 MiB cgroup, wall time,
source byte limits, and parser fuzzing remain the controls for that phase. A
parser resource failure may therefore still yield no report; it must fail closed
and must not be described as completed analysis. Likewise, Go's
`debug/elf.ImportedLibraries` materializes the dynamic section and matching
strings before the scanner can apply retained-result caps. The 64 MiB ELF file
limit and cgroup bound that parser phase; the proposed library caps prevent
subsequent report amplification but do not claim to make the standard-library
ELF parser allocation-free or streaming.
Manifest JSON parsing similarly occurs before retained-result accounting, but
the existing 2 MiB individual source-file limit bounds that parser input.
