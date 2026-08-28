# Development and verification

This repository inspects hostile code. Development commands must preserve the
same central rule as production: target bytes are data and are never sourced,
imported, evaluated, or invoked.

## Component map

| Path | Responsibility | Trust boundary |
|---|---|---|
| `cmd/plug-prejudice` | Inventory, deterministic analysis, versioned JSON production | Runs inside containment in the installed product; never launches target code |
| `cmd/plug-prejudice-broker` | Installed-plugin selection, resource scope, Bubblewrap, strict report validation | Trusted user-session boundary with fixed executable policy |
| `internal/inventory` | Descriptor-relative bounded traversal and non-executing ELF metadata | Treats every filename and byte as hostile |
| `internal/analyze` | Shell AST and bounded QML lexical facts, correlations, limitations | Parses data only; unsupported semantics remain unknown |
| `internal/report` | Schema types and strict relationship/path/cardinality validation | Rejects output before presentation |
| `internal/resource` | Verified transient systemd user scope and process rlimits | Must fail closed |
| `internal/sandbox` | Pinned scanner/target descriptors and fixed Bubblewrap arguments | Must fail closed |
| `Panel.qml` | Plugin selection and restrained plain-text report presentation | Thin UI inside the shared Omarchy Shell process |

The architecture, threat model, sandbox policy, rule catalogue, report
contract, dependency audit, and release evidence are authoritative. A test
passing does not override an invariant documented there.

The [deterministic rule playbook](detection-rules.md) maps the analyzer stages,
output types, evidence requirements, false-positive cases, and review gates for
adding detection behavior.

## Headless checks

These commands do not start Omarchy or Quickshell:

```bash
export GOFLAGS='-tags=grammar_subset,grammar_subset_python,grammar_subset_javascript'
go test ./...
go test -race ./...
go vet ./...
go mod verify
scripts/verify-production-dependencies.sh
scripts/verify-parser-footprint.sh
scripts/verify-parser-oracles.sh
scripts/verify-vulnerabilities.sh
scripts/verify-reproducible-build.sh
scripts/verify-arch-package-template.sh
scripts/verify-ci-policy.sh
```

Fuzz one package explicitly, for example:

```bash
go test ./internal/report -run '^$' -fuzz '^FuzzDecodeNeverPanics$' -fuzztime=30s
```

The grammar tags are mandatory: they embed only the reviewed Python and
JavaScript grammars. Building without them embeds the parser registry's full
grammar set and is not a supported production profile.

Fuzz targets operate on in-memory bytes. Corpus files and scenario scripts are
inert data and must remain non-executable.

## Direct scanner mode

The scanner CLI can run independently and never intentionally executes target
content. A direct development invocation is nevertheless **not sandboxed**: a
parser or scanner vulnerability would have the developer process's ambient
filesystem access. Use direct mode only with repository-owned inert fixtures or
content whose disclosure boundary you accept. Its report records
`scan.sandboxed: false` and no resource policy.

Do not use `go run`, the raw scanner binary, a shell, or a language runtime to
inspect an untrusted installed plugin as a substitute for the broker. Production
review must enter the verified systemd scope and fixed Bubblewrap policy.

Both command-line programs suppress raw flag-parser diagnostics and emit errors
through the shared 4 KiB hostile-text normalizer. This protects direct terminal
use as well as QML process collection; it does not make an unsandboxed direct
scan appropriate for untrusted private input.

## QML and installed integration

`scripts/test-qml.sh` launches a short-lived Quickshell component test.
`scripts/test-installed-integration.sh` launches Quickshell and reviews one real
installed target through the broker. They are intentionally separate from the
headless checks and require an Omarchy session plus explicit authorization when
another person is using the desktop.

The visual harness contains only a trusted synthetic report. It does not prove
theme, scale, keyboard, pointer, or assistive-technology quality generally;
those remain human release gates.

## Changing security-sensitive code

Before implementation, present options and a recommendation for changes to
containment, path traversal, parser/dependency boundaries, report semantics,
rendering, packaging/update identity, or outbound data. Record the accepted
decision when it has lasting consequences. Add boundary and false-positive
tests, then request the human reviews listed in `AGENTS.md` and the release
readiness checklist.

`internal/securitypolicy` contains narrow architecture regression checks for
the non-execution and local-only boundaries. They prevent target-consuming
production packages from casually gaining common process, Go-plugin, or
network APIs. Inventory's `net/http` use is restricted to MIME sniffing via
`DetectContentType`. These checks are not a proof that target data cannot reach
every possible execution or network mechanism, so new parsers and target-data
flows still require manual security review.
