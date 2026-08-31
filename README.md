# Plug & Prejudice

Plug & Prejudice is a work-in-progress security reviewer for
[Omarchy](https://omarchy.org/) Shell plugins. It reads a plugin's files and
explains the behavior it can establish from those files **without running the
plugin**.

Think of it as a careful second pair of eyes. It can point to a command, file
access, network destination, startup mechanism, or combination of behaviors and
show the source evidence behind that observation. It also says when it could
not understand something. It does not call a plugin safe and it does not replace
human judgment.

> [!WARNING]
> This project is not released yet. The scanner, containment, report format,
> packaging, and panel are being developed and reviewed in a stack of draft
> pull requests. There is no supported installation path or trusted release
> binary yet.

## Why this project exists

An Omarchy plugin may contain QML, shell scripts, Python, JavaScript,
configuration files, archives, or native programs. Reading all of that by hand
is difficult. Running it to see what happens would give untrusted code a chance
to act.

Plug & Prejudice instead performs bounded static analysis: it treats every
plugin filename and byte as potentially hostile data, parses only documented
parts of supported formats, and records evidence for every conclusion. When a
value is dynamic, a parser rejects a file, or a safety limit is reached, the
report becomes incomplete and explains what remains unknown.

## What happens during a review

```text
Omarchy panel
    |
    | selected installed-plugin ID
    v
trusted local broker
    |
    | pinned directory + fixed limits
    v
networkless Bubblewrap sandbox
    |
    v
Go scanner ----> validated JSON report ----> plain-text display
```

In plain English:

1. The user selects an already-installed plugin.
2. A small trusted broker opens and pins that exact plugin directory.
3. The broker starts the scanner with fixed memory, CPU, process, time, file,
   output, filesystem, and network restrictions. If those restrictions cannot
   be established, the scan is rejected.
4. The Go scanner reads target files as data. It never asks a target shell,
   Python, Node, systemd, desktop launcher, archive extractor, or ELF loader to
   interpret or run them.
5. The broker validates the complete structured report before the Omarchy panel
   displays plugin-controlled text as plain text.

The scanner is useful without Omarchy and has no network or LLM dependency.
The detailed boundaries are in the [architecture](docs/architecture.md),
[threat model](docs/threat-model.md), and
[sandbox policy](docs/sandbox-policy.md).

## Supported systems and reviewer machines

The intended product platform is **Linux on ARM64 or x86-64**:

- `aarch64` / `arm64` includes this Arch Linux ARM development machine and
  other 64-bit ARM Linux systems;
- `x86_64` / `amd64` is the ordinary 64-bit Intel/AMD Linux PC platform; and
- 32-bit x86, macOS, and Windows are not version-one product targets.

CI runs the Go checks and native builds on both Ubuntu 24.04 x86-64 and Ubuntu
24.04 ARM64. The Arch package also declares both `x86_64` and `aarch64`. Final
native Arch installation evidence is still required on both architectures
before release.

A reviewer on an x86-64 Linux PC does **not** need a Mac or an ARM machine to
review Track B parsers and correlations. Omarchy is not required for those
headless checks. Containment tests need Linux user namespaces, Bubblewrap,
systemd, and other documented kernel facilities; installed UI testing needs a
supported Omarchy session. A macOS or Windows reviewer can still review source
and documentation, but should use an appropriate Linux machine or VM before
claiming platform test evidence. See the
[development platform matrix](docs/development.md#platform-matrix).

## How to read the report

The report deliberately keeps these ideas separate:

| Term | Plain-English meaning |
|---|---|
| **Operation** | A command or action visible in parsed source. This is neutral evidence, not automatically a warning. |
| **Fact** | Something the supported syntax directly establishes, such as network output being piped straight into a shell. |
| **Inference** | A clearly labelled connection between facts, such as a download and later execution of the same literal path. |
| **Unknown** | A specific value or behavior the scanner could not resolve without guessing or executing code. |
| **Limitation** | A gap in analysis caused by unsupported syntax, a parser failure, a size limit, or another explicit boundary. |
| **Severity** | The possible impact if the visible behavior occurs. It is not a probability or safety score. |
| **Confidence** | How directly the retained evidence supports the statement. |
| **Scope** | Whether the behavior appears reachable at runtime, belongs to repository tooling, or has unknown reachability. |

For example, an ordinary `curl` command is a neutral network operation.
`curl | bash` is a high-severity fact because the parsed pipeline directly
connects downloaded bytes to a shell. A file containing one unrelated download
and one unrelated shell command does not establish that flow.

See the [severity model](docs/severity-model.md),
[analysis rule catalogue](docs/analysis-rules.md), and
[report contract](docs/report-contract.md) for the exact rules.

## Independent reviewers wanted

The project needs people who did not write the implementation to challenge its
security assumptions. A reviewer is not being asked to certify the whole
project or declare any plugin safe. A volunteer may review one named track or a
clearly recorded subsection at one exact commit. The work may end in approval,
rejection, partial evidence, or concrete findings that must be fixed; only
combined coverage of every subsection can approve a whole track.

The current review tracks are:

- [containment and selected-tree handling (#16)](https://github.com/SurreptitiousFabric/plug-and-prejudice/issues/16);
- [hostile parsers and behavior correlations (#17)](https://github.com/SurreptitiousFabric/plug-and-prejudice/issues/17);
- [report schema, broker, and hostile rendering (#18)](https://github.com/SurreptitiousFabric/plug-and-prejudice/issues/18);
- [packaging, CI, SBOM, and provenance (#19)](https://github.com/SurreptitiousFabric/plug-and-prejudice/issues/19); and
- [Omarchy UX and accessibility (#20)](https://github.com/SurreptitiousFabric/plug-and-prejudice/issues/20).

If issue #17 sounds interesting, start with the
[plain-English parser boundary map](docs/parser-boundaries.md), then follow
[Track B in the human review guide](docs/human-review-guide.md#track-b-hostile-parsers-and-correlation-semantics).
The [decision index](docs/decisions/README.md) explains what “ADR 0002” means
and links every design decision. Review results use the
[evidence template](docs/review-evidence/TEMPLATE.md).

The minimum Track B checks are headless and treat repository fixtures as bytes
only:

```bash
export GOFLAGS='-tags=grammar_subset,grammar_subset_python,grammar_subset_javascript'
go test -race ./internal/analyze
scripts/verify-parser-footprint.sh
scripts/verify-parser-oracles.sh
```

The oracle script runs locally installed Python and Node only on small trusted
samples that the script creates itself. It never supplies a target plugin or a
hostile fixture to those runtimes. Automated success is evidence for a human
review, not approval by itself.

## Project status

The development tree contains a bounded scanner, fail-closed Bubblewrap broker,
versioned evidence report, and tested Omarchy panel prototype. Before a public
release, the project still needs the independent reviews above, final native
ARM64 and x86-64 package evidence, a signed release, and release-stable schema
approval. The current gates are tracked in the
[release-readiness checklist](docs/release-readiness.md) and public
[Sense & Scheduling project](https://github.com/users/SurreptitiousFabric/projects/10).

The intended first release will:

- review already-installed plugins without enabling or executing them;
- keep the Omarchy QML integration thin;
- perform deterministic analysis in an independent Go CLI;
- contain deterministic scans with Bubblewrap and systemd limits on Arch
  Linux;
- inspect bounded archive and native-binary metadata without extraction or
  loading;
- remain useful without an LLM; and
- exclude cloud LLM integration.

The Omarchy checkout contains only the QML integration. The trusted scanner and
broker will be installed separately as root-owned
`/usr/bin/plug-prejudice` and `/usr/bin/plug-prejudice-broker` files by the Arch
package. The plugin will not download, build, or install them on first use.

## Documentation map

| If you want to understand... | Start here |
|---|---|
| the short version of each design choice | [Architecture decision records (ADRs)](docs/decisions/README.md) |
| which files are parsed and what each parser may claim | [Parser and grammar boundaries](docs/parser-boundaries.md) |
| the components and trust boundaries | [Architecture](docs/architecture.md) |
| the attackers and failures the design considers | [Threat model](docs/threat-model.md) |
| filesystem, process, network, and resource containment | [Sandbox policy](docs/sandbox-policy.md) |
| current detections, exclusions, and known gaps | [Analysis rules](docs/analysis-rules.md) |
| facts, inferences, evidence, unknowns, and JSON validation | [Report contract](docs/report-contract.md) |
| dependencies, grammar origin, licenses, and supply chain | [Dependency audit](docs/dependencies.md) and [third-party notices](THIRD_PARTY_NOTICES.md) |
| how to build and run safe headless checks | [Development guide](docs/development.md) |
| how to contribute a detection rule | [Detection-rule guide](docs/detection-rules.md) |
| release work that is still missing | [Release readiness](docs/release-readiness.md) and [roadmap](docs/roadmap.md) |

An **ADR** is an Architecture Decision Record: a short document that records a
problem, the options considered, the chosen design, and its remaining risks.
They live under [`docs/decisions/`](docs/decisions/README.md); the four-digit
number in an issue is the filename prefix.

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md) and the
[development guide](docs/development.md). Security-sensitive changes must keep
facts, inferences, and unknowns distinct; add benign and hostile cases; and
follow the change gates in [AGENTS.md](AGENTS.md).

Do not use the unsandboxed development CLI on an untrusted plugin. Do not add
live malware, private plugin source, credentials, or personal configuration to
an issue or fixture. Potential vulnerabilities should be reported privately as
described in [SECURITY.md](SECURITY.md).

## Core safety rule

The target plugin is hostile input. Never source, import, execute, or otherwise
evaluate target-plugin code as part of inspection.

## License

[MIT](LICENSE)
