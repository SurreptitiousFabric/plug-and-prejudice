# Contributing

Thanks for taking a look. You do not need to understand the entire scanner to
help. Useful contributions include improving an explanation, adding a benign
false-positive case, checking one documented boundary, reproducing a public
bug with synthetic data, or reviewing a focused pull request.

If you are here to perform an independent security review, start with the
[review tracks](README.md#independent-reviewers-wanted) and
[human review guide](docs/human-review-guide.md). For parser and correlation
review issue #17, the [parser boundary map](docs/parser-boundaries.md) explains
the terminology and points to the exact decisions, code, tests, limits, and
dependency origin.

This project is pre-release. Before proposing a change, check the
[roadmap](docs/roadmap.md) and existing issues so that you can tell whether the
behavior is unfinished, deliberately excluded, or an unexpected bug. It is
fine to ask for clarification; a confusing boundary is itself useful feedback.

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

A path such as `docs/human-review-guide.md` or a label such as “ADR 0002” is not
enough on its own in a GitHub issue. It must be a direct link to the relevant
file or section.

## Before changing code

Start with `AGENTS.md`, `docs/architecture.md`, `docs/threat-model.md`, and the
[development guide](docs/development.md). Parser or dependency work must also
follow the [dependency audit and release procedure](docs/dependencies.md).
Use the [deterministic rule playbook](docs/detection-rules.md) when adding or
changing analysis behavior.
Read the [security policy and maintainer response workflow](SECURITY.md) before
handling a vulnerability report or security-sensitive reproduction.

Proposals that change a trust boundary, sandbox policy, report schema, update
model, dependency set, or external-data disclosure require a decision record
and security review before implementation.

Keep changes small and testable. Detection rules must include benign cases as
well as malicious or suspicious cases so that keyword matching does not become
the product's behavior.

Do not commit credentials, private plugin source, copied personal configuration,
or hostile fixtures whose ordinary execution could harm a contributor's system.

## Fixture safety

Static behavior scenarios live under `internal/analyze/testdata`. Fixture scripts
must be mode `0644` (never executable), carry an obvious warning when their text
would be dangerous if run, and be loaded only through the byte-reading test
helper in `scenarios_test.go`. Add a benign or legitimate counterpart whenever a
new scenario could otherwise encourage keyword-only detection. Never invoke a
fixture through `sh`, a language runtime, `go generate`, a test subprocess, or a
package/install hook.

## Checks

Run the deterministic checks with:

```bash
export GOFLAGS='-tags=grammar_subset,grammar_subset_python,grammar_subset_javascript'
go test ./...
go test -race ./...
go vet ./...
go mod verify
scripts/verify-production-dependencies.sh
scripts/verify-vulnerabilities.sh
scripts/verify-reproducible-build.sh
scripts/test-qml.sh
```

The reproducible-build check performs two native static builds in separate
temporary directories, compares their bytes, verifies the ELF architecture,
and rejects runtime interpreters or shared-library dependencies. Run it on each
release architecture; cross-compilation is not a substitute for native release
evidence.

The production-dependency check intentionally fails on any external module or
version drift. Do not update its allowlist alone: review the code purpose,
license, checksums, vulnerability result, attack-surface consequence,
`docs/dependencies.md`, and `THIRD_PARTY_NOTICES.md` together.

The vulnerability check reports vulnerabilities known to the Go database that
are reachable from analyzed packages. A clean result is not a safety claim and
does not cover unknown vulnerabilities, host executables, Omarchy, or behavior
outside the Go call graph.

`scripts/test-installed-integration.sh` is deliberately separate because it
reviews a real installed plugin. Set `PLUG_PREJUDICE_TEST_PLUGIN` to an installed
plugin ID to select the target. The test invokes only the trusted reviewer and
passes the target to the scanner as data through the normal Bubblewrap policy.
Never point ordinary test discovery at executable hostile fixtures.
