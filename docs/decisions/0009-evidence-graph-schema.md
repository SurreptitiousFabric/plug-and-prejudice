# 0009: Stable evidence references and typed provenance graph

- Status: implemented in development tree; schema, validator, and hostile-rendering review pending
- Date: 2026-08-28

## Context

Internal operation, resource, and finding IDs are deterministic but long and
implementation-facing. Findings list related operation IDs, yet that untyped
array cannot distinguish a directly established fact from an inference,
unknown, duplicate observation, independent corroboration, or disagreement.
Provenance is also a single free-form string, so a reviewer cannot reliably
separate the rule, analyzer version, and evidence source.

## Decision

Adopt report schema `2.0.0` before the first stable release. Every operation,
resource, and finding receives:

- a public `PP-` reference derived from the first 128 bits of SHA-256 over its
  node kind and deterministic internal ID;
- a structured provenance object containing rule ID, analyzer identity,
  analyzer version, and evidence source; and
- its existing bounded target-relative source evidence.

The hash-derived reference is stable when unrelated nodes are inserted or
reordered. Internal IDs remain present for machine joins. The validator derives
the expected public reference again, rejects collisions, and never accepts a
producer-selected alias.

The report also contains a bounded typed relationship collection. Resources
use `derived-from`; fact and inference findings use `established-by` and
`inferred-from`. Unresolved behavior is a dedicated unknown node without
severity and uses `unknown-because`; it cannot masquerade as a finding. Optional future
cross-source edges use `corroborates` or `disagrees-with`; same-source repeated
observations use `duplicates`. The validator checks endpoint existence and
kind, recomputes edge IDs, requires every base edge, rejects extra forged base
edges, and validates a typed semantic comparison basis. Corroboration requires
compatible local/external observations from distinct analyzers; duplication
requires equivalent observations within one source/analyzer boundary;
disagreement is limited to a typed observation-to-coverage-difference shape.
Required edges are keyed by their complete typed tuples, never their display
hashes.

The deterministic producer retains at most 20,000 resource/finding edges and
applies the limitation/incomplete semantics from ADR 0005 before appending a
node whose provenance cannot be retained consistently. The accepting validator
has a larger fixed structural ceiling for compromised-producer rejection. The
16 MiB atomic serialization ceiling remains independent.

## Migration

Schema `1.0.0` is rejected rather than guessed, upgraded, or partially
rendered. Scanner, broker, QML consumer, golden report, report contract, and
tests move together. The local broker still re-encodes only the typed object it
validated. There is no network schema lookup or downgrade path.

## Presentation

QML shows the public reference, structured rule/analyzer/source provenance, and
bounded evidence-chain edges. All fields pass through the existing control and
bidi normalizer and render only as `Text.PlainText`. No reference becomes a
clickable path, URL, command, QML expression, HTML fragment, or Markdown.

## Residual risk and review gate

A 128-bit truncated reference has a very small but nonzero collision
possibility. Node and relationship construction track the complete identity or
typed tuple behind each display ID, and any collision is a fail-closed
validation failure, never aliasing. Full internal IDs remain the machine join.
References establish stable report identity, not source authenticity or signed
release provenance.

Independent human review is required for the schema interpretation, reference
derivation, relationship semantics, validator completeness, QML rendering, and
migration behavior before merge.
