# Plug & Prejudice

Plug & Prejudice is a work-in-progress security reviewer for
[Omarchy](https://omarchy.org/) plugins.

An Omarchy plugin can contain shell scripts, QML, configuration, native
programs, and installation instructions. Reading all of that by hand is hard.
This project is being built to turn the files into a structured report without
enabling or executing the plugin.

It does **not** declare a plugin safe. It shows evidence, explains what the
scanner can reasonably infer, and says when something remains unknown.

## Project status

This repository is pre-release. There is no approved package or stable release
to install yet.

The code on `main` contains an early bounded scanner, a fail-closed Bubblewrap
broker, and an Omarchy panel prototype. A larger candidate is being reviewed as
a sequence of focused pull requests. Its documentation and review links are
pinned to candidate commit
[`2a076b8f2c94efaa5534581c1e20c5cf401b6194`](https://github.com/SurreptitiousFabric/plug-and-prejudice/commit/2a076b8f2c94efaa5534581c1e20c5cf401b6194),
so the material cannot change underneath a reviewer.

Do not treat either branch as a security approval or public release.

## What a review does

At a high level, the deterministic scanner:

1. receives a selected plugin path as untrusted input;
2. inventories files without running plugin code;
3. recognizes a deliberately limited set of structured operations;
4. records the file, line, parser, and rule behind each claim; and
5. returns a bounded report that keeps facts, inferences, and unknowns separate.

The current rule catalogue covers manifests, shell syntax, QML process
commands, repository metadata, bounded ELF identification, and the Python
parser gate. It also lists known gaps rather than silently pretending to
understand unsupported syntax.

Read the [analysis rule catalogue](docs/analysis-rules.md) for exact behavior.

## How to read a report

The project uses several words very carefully:

- **Operation:** structured behavior recognized in source text, such as a
  command invocation.
- **Fact:** something directly supported by file and parser evidence.
- **Inference:** a conclusion supported by one or more facts, but not directly
  observed as completed runtime behavior.
- **Unknown:** behavior the bounded analysis cannot safely resolve.
- **Limitation:** a reason the report may be incomplete, such as unsupported
  syntax or a resource cap.
- **Severity:** the possible impact if the behavior occurs.
- **Confidence:** how strongly the available evidence supports the claim.
- **Scope:** which files or operations the claim covers.

These dimensions stay separate. A severe possibility may have low confidence;
a high-confidence fact may have low impact. A clean-looking scan never proves
that a plugin is safe.

## Independent reviewers wanted

The project needs review by people who did not write the implementation. You do
not need to review the entire system: taking one focused subsection and
recording partial findings is useful.

- [Containment and selected-tree boundary — issue #16](https://github.com/SurreptitiousFabric/plug-and-prejudice/issues/16)
- [Hostile parsers and correlation semantics — issue #17](https://github.com/SurreptitiousFabric/plug-and-prejudice/issues/17)
- [Report schema, broker, and hostile rendering — issue #18](https://github.com/SurreptitiousFabric/plug-and-prejudice/issues/18)
- [Packaging, CI, SBOM, and provenance — issue #19](https://github.com/SurreptitiousFabric/plug-and-prejudice/issues/19)
- [Omarchy UX and accessibility — issue #20](https://github.com/SurreptitiousFabric/plug-and-prejudice/issues/20)

Each issue is intended to be a self-contained review packet. It links directly
to the relevant decisions, definitions, code, tests, safe commands, evidence
requirements, and guardrail.

For parser review in particular, start with the candidate's
[plain-English parser boundary map](https://github.com/SurreptitiousFabric/plug-and-prejudice/blob/2a076b8f2c94efaa5534581c1e20c5cf401b6194/docs/parser-boundaries.md).

## Supported systems and reviewer machines

The intended product targets are:

- Linux on x86-64, also called AMD64; and
- Linux on ARM64, also called aarch64.

Thirty-two-bit x86, macOS, and Windows are not product targets. The containment
and desktop integration rely on Linux and, for the packaged workflow, Arch
Linux and Omarchy.

Most headless Go tests and parser review can be performed on ordinary x86-64 or
ARM64 Linux without Omarchy. Native CI runs on both architectures. A reviewer
using macOS or Windows should use a Linux VM for containment or integration
claims.

## Higher-assurance launch boundary

The stronger containment path is the separately installed command-line
reviewer launched from the normal host desktop session. Its guarantees assume
the real host user and mount namespaces, the normal host `/usr`, `/run`, procfs,
and cgroupfs views, plus trusted package installation.

Launching it from an attacker-created user or mount namespace is unsupported.
A same-user malicious plugin that is already enabled has broader session access
and may interfere with the desktop wrapper. That is why the independent
command-line interface is also the recovery path. The exact assumptions and
failure behavior live in the [sandbox policy](docs/sandbox-policy.md) and
[threat model](docs/threat-model.md).

## Documentation on `main`

- [Architecture](docs/architecture.md) — components and trust boundaries.
- [Threat model](docs/threat-model.md) — attackers, protected assets, and
  non-goals.
- [Sandbox policy](docs/sandbox-policy.md) — required containment guarantees.
- [Analysis rules](docs/analysis-rules.md) — recognized syntax and known gaps.
- [Report contract](docs/report-contract.md) — report structure and hostile-text
  handling.
- [Schema versioning](docs/schema-versioning.md) — compatibility rules for
  structured reports.
- [UI contract](docs/ui.md) — panel behavior and limitations.
- [ADR 0001](docs/decisions/0001-initial-product-boundaries.md) — initial
  product boundaries.
- [ADR 0002](docs/decisions/0002-python-javascript-parser-boundary.md) — the
  bounded Python and JavaScript parser decision.
- [ADR 0003](docs/decisions/0003-systemd-resource-scope.md) — systemd resource
  scope and containment accounting.
- [ADR 0005](docs/decisions/0005-analysis-production-budget.md) — production
  analysis limits.
- [ADR 0009](docs/decisions/0009-evidence-graph-schema.md) — evidence graph and
  provenance structure.

The full review candidate has a
[plain-English ADR index](https://github.com/SurreptitiousFabric/plug-and-prejudice/blob/2a076b8f2c94efaa5534581c1e20c5cf401b6194/docs/decisions/README.md)
covering the additional decisions under review.

## Contributing and security reports

Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing code or review
findings. Public bug reports must not contain secrets, private plugin source,
personal configuration, or live malware.

Report exploitable vulnerabilities privately through the repository's
[Security page](https://github.com/SurreptitiousFabric/plug-and-prejudice/security/advisories/new).
Community participation is governed by the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Core safety rule

Treat the target plugin as hostile data. Never source, import, execute, or
otherwise evaluate target-plugin code during inspection.

## License

MIT
