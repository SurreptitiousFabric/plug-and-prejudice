# 0011: Bounded desktop-entry and autostart analysis

- Status: implemented in development tree; independent parser and rule review pending
- Date: 2026-08-28

## Context

Desktop entries can launch helpers directly and files installed below an
autostart directory can establish session persistence. Treating `.desktop`
files as generic text misses this relationship, while loading them through a
desktop library would widen the hostile-input boundary and risk interpreting
plugin-controlled data outside the deterministic scanner.

## Decision

Parse `.desktop` files with a small bounded inert key-file reader. Only the
exact `[Desktop Entry]` section and exact `Exec`, `Hidden`, and structural
section syntax affect conclusions. Comments, localized `Exec[...]` keys, and
other sections are ignored. The scanner never invokes GLib, a desktop launcher,
or a shell.

An unambiguous `Exec` value produces a `process-execution-via-desktop-entry`
operation with source provenance. The tokenizer supports bounded whitespace,
double quotes, and backslash escaping. Freedesktop field codes make the
operation dynamic and produce a dedicated unknown linked to it; `%%` remains a
literal percent. Duplicate keys, malformed quoting, missing commands, line
budget exhaustion, and result-budget exhaustion fail without guessing and
remain explicit through unknowns and limitations.

A non-hidden entry whose target-relative path contains an exact `autostart`
component produces a medium persistence fact linked to the launch operation.
The explanation explicitly does not claim installation, enablement, or
execution. Ordinary application entries remain neutral operation facts.
Recognized literal commands reuse the existing command-capability rules.

An exact one-source file-transfer operation may connect an inspected desktop
entry to an exact autostart-file destination. The inference cites the transfer
and the source artifact's configured command. Ambiguous root-relative versus
caller-relative resolution becomes an unknown; multiple sources,
directory-only destinations, and extension mismatches do not correlate.

## Limits and hostile input

The parser consumes only inventory-retained source bytes, retains at most
20,000 lines, uses the shared argument/evidence/string/result/relationship
budgets, and renders every field as hostile plain text. It has positive,
negative, false-positive, duplicate, malformed, escaped-field-code, and
line-budget tests. No artifact content is executed, imported, sourced, or
evaluated.

## Residual risk and review gate

The tokenizer intentionally implements only the reviewed launch surface, not
the complete freedesktop locale and field-code specification. It does not prove
that a desktop implementation will accept the file, that the file will be
installed at the same path, or that the configured process will run.
The transfer relationship likewise does not prove control flow, transfer
success, launcher acceptance, enablement, or launch.

Independent human review is required for key precedence, tokenization,
autostart path classification, capability reuse, unknown production, and
hostile-input limits before merge.
