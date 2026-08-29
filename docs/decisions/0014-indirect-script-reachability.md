# 0014: Bounded indirect script and configuration reachability

- Status: implemented in development tree; independent path/correlation review pending
- Date: 2026-08-28

## Context

Parsing every file independently shows what each file contains but not that a
runtime entry point can invoke a bundled helper. The previous scope heuristic
also promoted files when their basename appeared anywhere in referenced text,
which could mistake comments and longer lookalikes for reachability. Executing
or resolving paths against the host would violate containment.

## Decision

Build a bounded in-memory graph from already-retained operation facts and exact
target-relative inventory paths. Process operations contribute only a literal
script target recognized by the existing command/interpreter operand model.
Hyprland `source` contributes only a static include target. Absolute, dynamic,
missing, escaping, self, and non-candidate paths produce no edge.

For relative values, compare both target-root-relative and caller-directory-
relative interpretations. A single exact candidate produces a neutral
`plugin-path` execute resource linked to the caller. If the inspected callee
contains operations, an informational inference cites the caller plus up to the
bounded evidence/relationship limits of callee operations. The explanation
leaves working directory, control flow, mode, interpreter semantics, and
success unestablished. Two distinct matches produce an explicit
`unresolved-data-flow` unknown and no selected callee.

Runtime scope propagates from manifest/QML roots through these exact edges with
a queue, so traversal is linear in retained nodes/edges and supports bounded
multi-hop chains. QML textual scope references are now limited to exact static
quoted strings outside comments and template literals, then use the same
single-match resolver. Basename substrings no longer promote scope.

## Limits and hostile input

The graph consumes at most the producer-bounded operations and inventory/source
paths. Candidate lookup is map-based, each caller contributes at most one edge,
callee evidence is capped, output uses shared resource/finding/unknown/string/
relationship budgets, and scope traversal visits each reached path once. No
path is opened or followed. Tests cover direct interpreter invocation,
same-directory nesting, 256-hop propagation, Hyprland includes, ambiguity,
absolute/missing/self/dynamic targets, QML comment/lookalike negatives,
determinism, race behavior, and fuzzed path resolution.

## Residual risk and review gate

A single textual match is still an inference: runtime working directory and
language-specific path rules can differ. The first slice does not resolve
variable-built paths, imports/modules, symlinks, generated files, PATH lookup,
archive members, or binary loader references. Callee operations are cited but
their execution is not asserted as fact.

Independent human review is required for operand selection, normalization,
root-versus-caller ambiguity, traversal rejection, scope propagation, QML
literal extraction, confidence/severity, evidence bounds, and correlation
language before merge.
