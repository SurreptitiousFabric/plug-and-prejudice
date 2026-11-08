# 0013: Bounded Hyprland configuration analysis

- Status: implemented in development tree; independent parser and rule review pending
- Date: 2026-08-28

## Context

Hyprland configuration can launch shell programs at startup, shutdown, reload,
or key dispatch; include other configuration; and load native compositor
plugins. A command/domain grep loses directive semantics and nested shell
relationships. Loading the file through Hyprland or `hyprctl` would interpret
hostile content inside the desktop session and violate the scanner boundary.

## Decision

Recognize only `hyprland.conf`, reviewed Hyprland-prefixed `.conf` names, or
`.conf` files below exact `hypr`/`hyprland` path components. Parse at most
20,000 inert UTF-8 physical lines and exact assignment keys. Invalid UTF-8 or
NUL fails closed. Comments and unrelated directives remain negative cases.

`exec`, `exec-once`, `exec-shutdown`, and exact `bind*` dispatchers whose
dispatcher is `exec` produce a configuration-directive operation. Optional
leading execution rules are removed only when their closing bracket is
visible. The remaining program is parsed with the existing non-executing shell
AST; nested operations, dynamic origins, pipelines, evidence, and limitations
are remapped to the original configuration line. No shell process is started.

Startup/shutdown lifecycle directives produce medium persistence facts citing
the directive and bounded nested operation IDs. Ordinary `exec` and key-bound
execution remain neutral facts unless their parsed nested behavior supports an
existing finding. Malformed rules, shell parse failures, empty programs,
truncated evidence, and unresolved values become explicit unknowns.

Exact `source` directives produce include-reference operations. Dynamic paths
are not joined to files. Exact `plugin` directives produce medium native-code-
loading facts; expansion or missing path evidence produces a native-behavior
unknown. Configuration text never establishes binary provenance or behavior.

## Limits and hostile input

The parser uses inventory-retained bytes plus shared operation, finding,
unknown, evidence, argument, relationship, encoded-string, and output budgets.
Nested shell parsing retains its parser timeout/resource containment and result
caps. Tests cover startup, rules, ordinary/described binds, comma-preserving
commands, comments/lookalikes, static/dynamic sources, native plugins,
malformed rules/shell, invalid text, line exhaustion, evidence remapping,
duplicate unknown IDs, path recognition, race behavior, and fuzz input.

## Residual risk and review gate

This is not a complete Hyprland parser. It does not model variable assignment,
keyword/category expansion, generated configuration, every bind flag or
dispatcher, plugin ABI compatibility, compositor lifecycle, include ordering,
or host path resolution. Textual source references and lifecycle facts do not
prove that the host loads this file.

Independent human review is required for path recognition, directive matching,
bind field selection, execution-rule stripping, embedded-shell evidence
remapping, lifecycle severity, native-plugin language, hostile-input budgets,
and unknown coverage before merge.
