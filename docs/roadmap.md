# Product roadmap

Plug & Prejudice is an independent forensic and static security-review layer
for Omarchy plugins. Omarchy's own plugin audit is the fast, first-party
capability check. This project remains useful after that check by supplying a
separately contained analysis, traceable evidence, behavior correlations,
explicit unknowns, and analysis-coverage information.

Work is scheduled in the public
[Sense & Scheduling project](https://github.com/users/SurreptitiousFabric/projects/10).
Repository issues are the task-level source of status. This document records
the product order and the boundaries those tasks must preserve.

## Product priorities

### 1. Preserve the independent security boundary

Keep the Go scanner, trusted broker, and fail-closed Bubblewrap containment.
The deterministic scan remains read-only, networkless, bounded, independent of
Omarchy, and unable to execute target content. The Omarchy integration stays a
thin selection and plain-text presentation layer.

Capability discovery for commands, domains, reads, and writes remains required,
but it is baseline evidence rather than the headline feature.

### 2. Correlate behavior across individual facts

Make multi-step behavior the primary analysis feature. Initial correlations
include:

- download followed by executable write and interpreter or shell execution;
- credential, browser, or session-file access combined with outbound network;
- autostart or shell-configuration writes combined with later execution;
- exact one-source desktop/systemd artifact transfers to persistent file paths
  connected to commands parsed from those precise artifacts;
- dynamic command construction combined with privilege escalation; and
- indirect scripts or payloads connected to their callers.

Correlations are inferences, never facts. Each must cite its input fact IDs,
rule version, severity rationale, confidence, and analysis provenance.

### 3. Make evidence chains and unknowns first-class

Assign stable identifiers to facts, inferences, and unknowns. Reports must show
the source location and analyzer that produced each fact, then show exactly
which facts support an inference.

When static analysis cannot resolve an executable, path, host, or data-flow
value, emit a bounded unknown instead of guessing. Where available, cite the
runtime data-flow origin and explain the analysis limitation.

Development status: bounded shell assignment origins, Python/JavaScript
single-definition literal flow, and QML root-property literal string/array flow
are implemented. QML expressions, imperative assignments, nested bindings,
imports, and runtime semantics remain explicit unknowns under ADR 0019.

### 4. Expand artifact coverage where first-party auditing stops

Extend bounded, non-executing review in this order:

1. deeper Python and JavaScript data flow;
2. desktop files, service definitions, systemd units, and Hyprland config;
3. scripts invoked indirectly;
4. archives and bundled payloads without extracting outside controlled limits;
5. ELF metadata such as imports, linked libraries, capabilities, setuid
   indicators, and embedded URLs, without claiming full reverse engineering.

Every new parser or artifact reader needs positive, negative, false-positive,
hostile-input, resource-limit, and deterministic-output tests.

Development status: bounded desktop-entry/autostart analysis is implemented
with ADR 0011, and bounded systemd service/install/activation analysis is
implemented with ADR 0012. Both await independent parser/rule review. Hyprland
configuration is implemented with ADR 0013. All three await independent
parser/rule review. Bounded literal indirect script/config reachability is
implemented with ADR 0014 and awaits independent path/correlation review.
Archive and bundled-payload metadata inventory is implemented without
extraction under ADR 0015. Bounded ELF imports, strings, embedded URLs, file
capabilities, and privilege-bit metadata are implemented under ADR 0016. Both
await independent parser/rule review. Bounded Python/JavaScript literal process
argument flow through single-definition module-level assignments is implemented
under ADR 0002 and awaits independent parser/rule review. Branch-sensitive,
interprocedural, import-alias, and computed-value flow remain explicit gaps.

### 5. Accept Omarchy audit as optional external evidence

Add a versioned, bounded, local-only adapter only after the independent evidence
model is stable. Omarchy findings retain their own provenance and never replace
the independent scan. Agreement is corroboration; disagreement is a coverage
finding. Unsupported or malformed input fails closed without weakening the
standalone scanner.

Development status: the optional `pr8439-732b104` adapter is implemented under
ADR 0017 with strict bounded decoding, read-only descriptor mounting, separate
provenance, exact agreement/coverage-difference edges, and an explicit unknown
because upstream JSON does not bind itself to a content digest. It awaits
independent boundary/schema review and requires a new format identifier if PR
#8439 changes or lands differently.

### 6. Report dimensions, not an unexplained safety score

Summarize security impact, evidence confidence, analysis coverage, and unknown
behavior separately. Any coverage percentage must publish its denominator and
limitations. The report may provide prioritization, but it must not call a
plugin safe or collapse uncertainty into one opaque number.

Development status: the required validator-recomputed review dimensions,
explicit retained-artifact denominator, fact/inference/unknown counts, stable
main-reason references, and bounded plain-text/accessibility presentation are
implemented under ADR 0018. Independent rubric, schema, UX, and accessibility
review remains required.

## Delivery order

The current board records four completed foundations and eight planned items:

- completed: bounded scanner containment, bounded canonical report delivery,
  non-executing Python/JavaScript parsing, and descriptor-pinned target mounts;
- next: trusted fixed-path packaging and protocol handshake;
- then: correlations, evidence chains, explicit unknown data flow, expanded
  artifact review, optional Omarchy audit ingestion, and multi-dimensional
  summaries;
- release gate: independent dependency, sandbox, parser, rendering, packaging,
  and LLM-boundary review plus the documented release evidence.

Completed implementation does not waive the independent human review gates in
the threat model and release-readiness checklist.

Release engineering status: a tag-only, commit-pinned native ARM64/x86-64
workflow now binds version-injected static binaries to a timestamp-free
CycloneDX SBOM, SHA-256 manifest, and GitHub artifact attestations. The first
approved hosted run, native Arch package builds, Pacman ownership checks,
installation/update/removal tests, signed maintainer tag, and human supply-chain
review remain release gates.

Human review is tracked as five independent, commit-bound work items rather
than one vague approval: containment/selected-tree (#16), hostile parsers and
correlations (#17), report/broker/rendering (#18), packaging/supply chain
(#19), and Omarchy UX/accessibility (#20). Their required evidence and sign-off
format are defined in `docs/human-review-guide.md` and
`docs/review-evidence/TEMPLATE.md`. None is approved merely because its
automated checks pass.
