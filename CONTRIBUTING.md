# Contributing

Thanks for taking a look. You do not need to understand the entire scanner to
help. Useful contributions include improving an explanation, adding a benign
false-positive case, checking one documented boundary, reproducing a public bug
with synthetic data, or reviewing a focused pull request.

If you are here for independent security review, start with the
[review tracks](README.md#independent-reviewers-wanted). The linked issues point
to the exact candidate documentation, code, tests, limits, and evidence format.

This project is pre-release. A confusing boundary or unexplained term is useful
feedback even when you are not proposing code.

## Make issues self-contained

A reader should not have to search the repository to understand an issue. When
opening or updating one:

- link every named ADR, document section, implementation directory, test
  script, parent issue, and focused pull request;
- explain specialist terms in one sentence before asking someone to review
  them;
- use a commit permalink for security-review material so the linked content
  cannot change underneath the reviewer; and
- state the expected evidence, safe commands, guardrail, and definition of
  completion in the issue itself.

A bare path such as `docs/analysis-rules.md` or a label such as “ADR 0002” is
not enough in a GitHub issue. Link directly to the relevant file or heading.

## Before changing code

Start with `AGENTS.md`, [the architecture](docs/architecture.md), and
[the threat model](docs/threat-model.md). Parser changes must also match
[the rule catalogue](docs/analysis-rules.md) and the relevant decision record.

Changes to a trust boundary, sandbox policy, report schema, update model,
dependency set, or external-data disclosure require a decision record and
security review before implementation.

Keep changes small and testable. Detection rules need benign cases as well as
malicious or suspicious cases so keyword matching does not become the product's
behavior.

## Fixture safety

Never commit credentials, private plugin source, copied personal
configuration, or live malware. Tests must read hostile-looking fixtures only
as inert bytes inside an explicitly controlled environment. Never invoke such a
fixture through a shell, language runtime, package hook, or ordinary test
discovery.

## Checks

For changes supported by current `main`, run:

```bash
go mod verify
go test ./...
go test -race ./...
go vet ./...
```

Run `scripts/test-qml.sh` when the required QML tools are installed and the
change affects the panel.

`scripts/test-installed-integration.sh` is deliberately separate because it
reviews a real installed plugin. The test invokes only the trusted reviewer and
passes the target to the scanner as data through the normal Bubblewrap policy.
Never use it with an untrusted fixture prepared for ordinary tests.

## Community expectations

Participation in this repository is governed by the
[Code of Conduct](CODE_OF_CONDUCT.md). Exploitable vulnerabilities belong in
the repository's [private reporting form](https://github.com/SurreptitiousFabric/plug-and-prejudice/security/advisories/new),
not a public issue.
