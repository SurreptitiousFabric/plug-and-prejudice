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

The versioned structured output and hostile-presentation rules are described in
the [report contract](docs/report-contract.md).
The panel interaction and same-process limitations are described in the
[UI contract](docs/ui.md).

Detection behavior and current gaps are documented in the
[analysis rule catalogue](docs/analysis-rules.md).

## Core safety rule

The target plugin is hostile input. Never source, import, execute, or otherwise
evaluate target-plugin code as part of inspection.

## License

MIT
