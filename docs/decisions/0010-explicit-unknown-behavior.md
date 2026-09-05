# 0010: Explicit unknown behavior and bounded value origins

- Status: implemented in development tree; independent parser, schema, and UI review pending
- Date: 2026-08-28

## Context

Coverage limitations describe work the scanner could not complete, but they do
not identify a particular runtime value that remains unresolved. A dynamic
command is neither a security finding nor merely a generic coverage note. It
needs its own traceable record without inventing an executable or data flow.

## Decision

Schema `2.0.0` has a bounded top-level `unknowns` collection separate from
severity-bearing findings and scanner limitations. Each unknown records a
reason, scope, confidence, plain-language description, source evidence,
structured provenance, any affected operation IDs, rules whose conclusions
were withheld, and up to eight value origins.

Origins distinguish assignments, parameter expansions, QML property
assignments, and unresolved use sites. Shell origins are bounded textual
definitions preceding a use site; they do not claim that runtime control flow
reaches the definition. QML expressions and imperative assignments are never
evaluated. Unresolved nodes link to affected operations with typed
`unknown-because` edges.

The producer covers dynamic shell invocations, shell parameter expansions with
the nearest preceding textual assignment, dynamic declarative QML
`Process.command` values, imperative QML command assignments, and dynamic first
arguments to a reviewed set of Python `subprocess` and JavaScript
`child_process` APIs. Python/JavaScript identifiers nested in argument arrays
also cite their nearest preceding textual assignments. Parser failure and
origin-traversal budget exhaustion receive dedicated unknown records. Deeper
branch-sensitive flow remains future work and must not be represented as
complete.

JavaScript argument-list uncertainty is distinct from executable uncertainty.
A resolved string executable with unresolved arguments retains a neutral,
dynamic call and a dedicated argument unknown citing the affected expression
and available textual origins. It does not create a resolved process operation
from only the executable. The literal-only boundary accepts omitted arguments
and empty arrays; options/callback overloads remain explicitly unknown. This
uses the existing schema, provenance, graph, and production budgets and does
not add API support or change the Python boundary.

A report containing an explicit unknown is `incomplete`, even if no scanner
error occurred. The unknown does not assign severity and does not characterize
the plugin as unsafe or safe.

## Bounds and presentation

Unknown counts, evidence, origins, affected operations, suppressed rules,
relationship edges, encoded strings, and rendered rows all have explicit
limits. The validator rejects missing, forged, mistyped, or over-limit records.
The UI renders all plugin-controlled fields as normalized plain text.

## Residual risk and review gate

The nearest preceding shell assignment can be unreachable, overridden through
runtime indirection, or branch-dependent. It is labelled as a textual origin,
not proven data flow. Imperative QML currently records the first bounded source
location and retains a coverage limitation rather than guessing an operation.

Independent human review is required for the schema, parser traversal,
relationship validation, hostile-string accounting, and QML rendering before
merge.
