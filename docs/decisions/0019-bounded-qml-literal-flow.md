# 0019: Bounded QML literal command flow

- Status: implemented in development tree; independent parser and rule review pending
- Date: 2026-08-28

## Context

QML commonly stores a `Process.command` array in root-object properties. Treating
every property reference as wholly dynamic hides useful evidence and loses the
assignment origin. Evaluating QML or JavaScript to recover values would execute
hostile plugin content and violate the scanner boundary.

## Decision

Index only exact `property var` and `property string` declarations belonging to
the QML root object. Resolve only literal quoted strings, literal arrays, and
plain-identifier references to a unique indexed definition. Resolution is
bounded to 1,024 definitions, 16 reference hops, the shared argument/string
limits, and eight retained origins. The scanner does not evaluate expressions,
bindings, functions, imports, getters, signals, imperative assignments, object
properties, JavaScript, or QML runtime semantics.

A successfully resolved `Process.command` becomes the usual operation plus an
informational `qml-literal-command-flow` fact citing every retained assignment
and the command use site. This establishes textual value flow only, not runtime
control flow or successful execution.

Duplicate names, reference cycles, nested/shadowed properties, unsupported
types, dynamic expressions, and unresolved references never select a value.
Their process operation remains dynamic. Where a supported definition was
found, its property-assignment origin is attached to the unknown. The first
definition beyond the index limit creates a budget limitation and unknown.
Imperative `object.command = ...` remains separately unsupported and unknown.

## Security and limits

The lexer reads only retained bytes, skips comments and quoted/template text,
tracks brace depth, and never imports or executes the document. Result,
evidence, relationship, string, operation, finding, unknown, and elapsed-time
budgets remain enforced by the shared producer and sandbox boundaries.

Positive direct and multi-hop flows, duplicate definitions, cycles, nested
shadowing, budget exhaustion, comment/string lookalikes, imperative assignment,
malformed arrays, fuzz, race, determinism, and hostile report validation are
required tests.

## Residual risk and review gate

This is intentionally not a QML scope/type/binding implementation. Root brace
classification and the accepted literal grammar may disagree with a full QML
engine on malformed or exotic documents; disagreement must result in less
resolution, never execution or a guessed value. Independent review is required
for lexical boundaries, shadowing posture, origin chains, caps, and finding
language before merge.
