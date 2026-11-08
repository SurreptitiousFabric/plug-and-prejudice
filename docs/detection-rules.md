# Contributing deterministic detection rules

This guide describes the analyzer that exists in this repository. It is not a
promise that every language or behavior is understood. Target plugin bytes are
hostile data: a rule may parse or compare them, but must never source, import,
evaluate, or execute them.

## Choose the right output

Use the narrowest statement established by the source:

| Output | Use it for | Do not use it for |
|---|---|---|
| `operations[]` | A parsed command or filesystem redirection | A risk conclusion |
| `resources[]` | A path, domain, persistence mechanism, or other accessed resource tied to an operation | Proof that access succeeded |
| `findings[]` with `fact` | A consequence directly established by parsed syntax, such as a downloader feeding an interpreter | Control flow or runtime values that were not established |
| `findings[]` with `inference` | A clearly explained correlation between independently established facts | A disguised fact or unsupported suspicion |
| `limitations[]` | Syntax, reachability, dynamic values, budgets, or behavior the scanner cannot safely resolve | A warning whose evidence is merely weak |

Severity represents potential consequence in the visible context. Confidence
represents how directly the source establishes the statement. Scope represents
apparent runtime reachability, repository tooling, or unresolved reachability.
Do not use one field as a substitute for another.

## Current analysis pipeline

`internal/analyze.Sources` is the authoritative ordering:

1. `manifest.go` parses author claims and records manifest-contract findings.
2. Source paths are sorted before shell, QML, artifact, and Python/JavaScript
   syntax-tree analyzers extract operations and syntax-local findings. The
   language analyzers may resolve only bounded single-definition module-level
   Python/JavaScript values and unique QML root-property literal values;
   ambiguous values remain unknown. Sorting is part of stable ID and output
   behavior.
3. Literal `sudo`, `doas`, `pkexec`, `command`, and `env` wrappers are expanded
   conservatively under a documented depth cap; unresolved forms are not
   guessed and produce analysis limitations.
4. `capabilities.go` derives resources and cross-operation correlations from
   retained operations. `installed_artifacts.go` then joins exact retained
   artifact names to those facts without reopening or interpreting files.
5. `scope.go` assigns runtime, repository-tooling, or unknown scope from the
   manifest and bounded textual reachability.
6. `coverage.go` adds explicit limitations for unsupported source languages.

`internal/analyze.Inventory` subsequently joins non-executing inventory and ELF
metadata into the result. Report construction and `internal/report` validation
remain separate boundaries. A new rule must not bypass those boundaries or
write presentation-ready text directly to QML.

## Implement a rule

Before editing code, write down:

- the parsed observable consumed by the rule;
- the exact context required for a fact or inference;
- the cases that intentionally produce only a neutral operation/resource;
- the dynamic or ambiguous forms that remain unknown;
- potential impact, claim type, confidence, and scope behavior; and
- the evidence and originating operation IDs a user can inspect.

Put syntax-local extraction in the existing parser for that language. Put
command-capability mapping and bounded operation correlations in
`capabilities.go`. Do not add a second parser, execute a language runtime, or
fall back to keyword searches. A parser or dependency change requires the
decision and review process in `docs/development.md` before implementation.

Every resource must reference an existing operation. Every finding must include
evidence and deterministic provenance; operation-derived findings must list the
related operation IDs. Reuse the existing evidence location and stable-ID
helpers. Never derive IDs from map iteration order, timestamps, absolute host
paths, or unbounded hostile strings.

Prefer conservative omission plus a scoped limitation over a confident but
ambiguous result. Never silently truncate a value and then reason about the
prefix as if it were complete.

## Required tests

Add focused table-driven tests beside the implementation. At minimum cover:

1. the intended suspicious or security-relevant form;
2. an ordinary legitimate use of the same command or syntax;
3. comments, strings, similarly named commands, and path-substring lookalikes;
4. option ordering, `--`, missing operands, dynamic values, and malformed input
   relevant to the rule;
5. severity, claim, confidence, scope, evidence, provenance, and related IDs;
6. resource access mode and sensitivity without claiming runtime success; and
7. deterministic output when the rule adds collections or relationships.

Use `runtimeShell` and the existing result helpers for focused shell tests.
Use QML-specific helpers in `qml_test.go` for lexical extraction. Add or extend
an inert scenario under `internal/analyze/testdata` only when end-to-end context
adds evidence beyond the unit test. Scenario scripts remain mode `0644`, carry a
warning when their text is dangerous, and are read only through
`loadScenario`; they are never invoked.

After focused tests, run the headless checks in `docs/development.md`. Live QML
and installed-plugin tests require an Omarchy session and explicit coordination
with whoever is using the desktop.

## Review checklist

- The rule states what happened, where, and why it matters without claiming the
  plugin is safe or that an attempted operation succeeded.
- A command name alone does not create a finding.
- Fact, inference, and unknown remain visibly distinct.
- Evidence is inert, bounded, target-relative, and connected to valid IDs.
- Benign and ambiguous cases are tested, not only hostile examples.
- Unsupported behavior makes the report incomplete where appropriate.
- No target byte reaches process execution, imports, network access, QML
  loading, a shell, or a language runtime.
- Documentation in `docs/analysis-rules.md` records both coverage and deliberate
  exclusions.
- Any trust-boundary, parser, dependency, schema, rendering, sandbox, packaging,
  update, or outbound-data change has the required decision and human review.
