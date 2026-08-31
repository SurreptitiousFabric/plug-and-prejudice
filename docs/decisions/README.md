# Architecture decision records

An Architecture Decision Record (ADR) explains one important design choice. It
states the problem, the options considered, the selected approach, and the
remaining risks or work. Reading an ADR should answer “why was it built this
way?”; the implementation and tests answer “does it actually behave that way?”

Issue text uses four digits, so **ADR 0002** means the file whose name starts
with `0002-` in this directory. An ADR marked implemented may still be blocked
on independent review. Always read the status at the top of the linked record
for the authoritative state.

## Decision index

| ADR | Plain-English question it answers | Summary status |
|---|---|---|
| [0001: Initial product boundaries](0001-initial-product-boundaries.md) | What will version 1 review, and what is deliberately out of scope? | Accepted |
| [0002: Python and JavaScript parser boundary](0002-python-javascript-parser-boundary.md) | How can those languages be parsed without running Python or Node? | Implemented; dependency and parser review pending |
| [0003: Systemd resource scope](0003-systemd-resource-scope.md) | How are memory, CPU, process, and time limits established and checked? | Implemented; security review pending |
| [0004: Arch package trust boundary](0004-arch-package-trust-boundary.md) | Why must trusted binaries be root-owned and installed separately from the plugin checkout? | Implemented in the development tree; approval and release evidence pending |
| [0005: Result production budget](0005-analysis-production-budget.md) | How does the scanner stop small hostile input from creating unbounded reports or memory use? | Implemented; security and semantics review pending |
| [0006: Selected-tree and nested-mount boundary](0006-nested-mount-boundary.md) | How is the chosen plugin directory pinned without symlink, path, mount, or rename escapes? | Implemented; path and security review pending |
| [0007: Canonical broker report](0007-canonical-broker-report.md) | Which exact validated JSON reaches the UI, and why is it re-encoded? | Implemented; rendering review pending |
| [0008: Behavior correlation engine](0008-correlation-engine.md) | When may separate observations be connected without pretending they prove control or data flow? | Implemented in the development tree; rule review pending |
| [0009: Evidence graph and provenance](0009-evidence-graph-schema.md) | How does every claim point back to stable evidence and the rule that produced it? | Implemented in the development tree; schema and rendering review pending |
| [0010: Explicit unknown behavior](0010-explicit-unknown-behavior.md) | How does the report represent a specific runtime value the scanner cannot resolve? | Implemented in the development tree; parser, schema, and UI review pending |
| [0011: Desktop-entry analysis](0011-desktop-entry-analysis.md) | Which `.desktop` and autostart syntax is understood without using a desktop launcher? | Implemented in the development tree; parser and rule review pending |
| [0012: systemd unit analysis](0012-systemd-unit-analysis.md) | Which unit, installation, and activation syntax is understood without asking systemd to load it? | Implemented in the development tree; parser and rule review pending |
| [0013: Hyprland configuration analysis](0013-hyprland-configuration-analysis.md) | Which execution, include, and native-plugin directives are recognized without loading the configuration? | Implemented in the development tree; parser and rule review pending |
| [0014: Indirect reachability](0014-indirect-script-reachability.md) | When may a caller be linked to another inspected file, and what ambiguity blocks that link? | Implemented in the development tree; path and correlation review pending |
| [0015: Archive metadata](0015-archive-metadata-inventory.md) | What ZIP/TAR information can be read without extracting member payloads? | Implemented in the development tree; archive review pending |
| [0016: ELF metadata](0016-bounded-elf-metadata.md) | What can be learned from a native binary without loading, executing, or disassembling it? | Implemented in the development tree; binary/parser review pending |
| [0017: Optional Omarchy audit evidence](0017-optional-omarchy-audit-evidence.md) | How may a pinned external audit be compared without executing it or adopting its verdict? | Implemented in the development tree; boundary and schema review pending |
| [0018: Independent review dimensions](0018-independent-review-dimensions.md) | Why are impact, confidence, coverage, and unknown behavior separate instead of one safety score? | Implemented in the development tree; rubric and UI review pending |
| [0019: QML literal command flow](0019-bounded-qml-literal-flow.md) | Which QML property values can be followed without evaluating QML or JavaScript? | Implemented in the development tree; parser and rule review pending |

## Related maps

- [Parser and grammar boundaries](../parser-boundaries.md) translates parser
  ADRs into selection, syntax, claim, failure, and resource boundaries.
- [Human review guide](../human-review-guide.md) groups ADRs into independent
  review tracks and defines the evidence needed for approval or rejection.
- [Architecture](../architecture.md) shows how the decisions fit together.
- [Threat model](../threat-model.md) records the hostile-input and containment
  assumptions those decisions must preserve.

When a change alters a lasting trust boundary, add or update an ADR before
treating the new behavior as approved. Do not rewrite an old decision so that
its original trade-off disappears; supersede it explicitly when necessary.
