# Plug & Prejudice

An open-source security reviewer for Omarchy Shell plugins.

Plug & Prejudice is intended to help a reasonably technical user decide
whether they trust a plugin. It reports observable behavior, supporting
evidence, inferences, unknowns, and analysis limitations. It does **not** claim
that a plugin is safe.

## Status

The project is under active development. The bounded scanner, fail-closed
Bubblewrap broker, and tested Omarchy panel prototype exist, but analysis
coverage, release packaging, and release-stable report
schema are not complete. Do not treat this as a release.

The Omarchy checkout contains only the QML integration. It deliberately does
not build, download, or run a reviewer binary. The matching trusted scanner and
broker are installed separately as root-owned `/usr/bin/plug-prejudice` and
`/usr/bin/plug-prejudice-broker` files by the Arch package. Until a signed
release package exists, maintainers can render the integrity-pinned packaging
recipe with `scripts/render-arch-pkgbuild.sh VERSION SOURCE_URL SOURCE_SHA256`;
this does not install or publish anything.

The approved first release will:

- review installed Omarchy plugins without enabling or executing them;
- keep the Omarchy QML integration thin;
- perform deterministic analysis in an independent Go CLI;
- contain deterministic scans with Bubblewrap on Arch Linux;
- identify native binaries without attempting full disassembly;
- remain useful without an LLM; and
- exclude cloud LLM integration from version 1.

See [the architecture](docs/architecture.md), [threat model](docs/threat-model.md),
tested [sandbox policy](docs/sandbox-policy.md), and [security policy](SECURITY.md)
before contributing.

The [product roadmap](docs/roadmap.md) positions Plug & Prejudice as the
independent forensic review layer around Omarchy's fast first-party audit. Its
tasks and status are tracked publicly in
[Sense & Scheduling](https://github.com/users/SurreptitiousFabric/projects/10).

The versioned structured output and hostile-presentation rules are described in
the [report contract](docs/report-contract.md).
Compatibility and coordinated schema changes are governed by the
[schema versioning policy](docs/schema-versioning.md).
The [severity model](docs/severity-model.md) explains impact levels and why
severity remains separate from confidence, claim type, and scope.
The panel interaction and same-process limitations are described in the
[UI contract](docs/ui.md).

Detection behavior and current gaps are documented in the
[analysis rule catalogue](docs/analysis-rules.md).
Contributors extending that behavior should follow the
[deterministic rule playbook](docs/detection-rules.md).
The [release-readiness checklist](docs/release-readiness.md) records the
evidence and human approvals still required before any public release.
The [development guide](docs/development.md) maps components and separates safe
headless checks from desktop and uncontained development paths.
The [dependency audit](docs/dependencies.md) distinguishes production linkage
from graph-only test modules and defines the release review procedure. Shipped
third-party license obligations are retained in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## Core safety rule

The target plugin is hostile input. Never source, import, execute, or otherwise
evaluate target-plugin code as part of inspection.

## License

MIT
