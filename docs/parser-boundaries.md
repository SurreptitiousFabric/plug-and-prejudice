# Parser and grammar boundaries

This page explains the “parser grammar boundaries” named in
[review issue #17](https://github.com/SurreptitiousFabric/plug-and-prejudice/issues/17).
It is an orientation map, not a replacement for the implementation or the
detailed [analysis rule catalogue](analysis-rules.md).

## What “grammar boundary” means here

A parser does not automatically understand everything a real program can do.
For each supported file type, Plug & Prejudice draws five boundaries:

1. **Selection:** which filenames or file signatures enter this parser.
2. **Syntax:** which parts of the format the parser recognizes.
3. **Claim:** what the scanner is allowed to conclude from that syntax.
4. **Failure:** what becomes unknown when input is malformed, dynamic,
   ambiguous, or unsupported.
5. **Resource:** how much input and work the parser may consume.

“Review the grammar boundary” therefore means checking that the implementation
does not make a broader claim than its recognized syntax can prove. It also
means checking that unsupported input is visible as an unknown or limitation,
not silently guessed or ignored as if analysis were complete.

No parser may source, import, evaluate, load, launch, or extract target-plugin
content. Parsing creates evidence; it does not grant permission to run the
thing being described.

## Boundary map

| Input | What selects it | What is deliberately understood | What is deliberately not claimed | Design and code |
|---|---|---|---|---|
| Manifest | The target-root `manifest.json` | Bounded JSON author claims and the documented Omarchy schema-1 contract | A valid manifest does not prove that entry points are safe or will run | [Analysis rules: manifest](analysis-rules.md#manifest-contract), [`manifest.go`](../internal/analyze/manifest.go) |
| Shell | `.sh`, `.bash`, `.zsh`, or a `sh`/`bash`/`zsh` shebang | A Bash-compatible abstract syntax tree; commands, arguments, pipelines, redirections, assignments, and a reviewed set of wrapper/command meanings | Shell execution, branch reachability, expansion results, function behavior, or success | [Analysis rules: shell](analysis-rules.md#shell-syntax), [`shell.go`](../internal/analyze/shell.go), [`capabilities.go`](../internal/analyze/capabilities.go) |
| QML | `.qml` | A bounded lexical model of top-level `Process.command`, literal arrays, unique root-property literal flow, and the location of imperative command assignment | Full QML/JavaScript semantics, bindings, property aliases, object lifecycle, or runtime control flow | [ADR 0019](decisions/0019-bounded-qml-literal-flow.md), [Analysis rules: QML](analysis-rules.md#qml-process-extraction), [`qml.go`](../internal/analyze/qml.go), [`qml_flow.go`](../internal/analyze/qml_flow.go) |
| Python | `.py`, `.pyw`, or a shebang containing Python | A strict pure-Go Tree-sitter syntax tree; call expressions; literal process arguments for a small `subprocess` API list; bounded single-definition module-level literal flow | Import resolution, aliases, computed values, branch-sensitive or interprocedural flow, or Python runtime equivalence | [ADR 0002](decisions/0002-python-javascript-parser-boundary.md), [Analysis rules: Python/JavaScript](analysis-rules.md#python-and-javascript-syntax-tree-boundary), [`treesitter.go`](../internal/analyze/treesitter.go) |
| JavaScript | `.js`, `.mjs`, `.cjs`, `.jsx`, or a shebang containing Node | A strict pure-Go Tree-sitter syntax tree; call expressions; literal process arguments for a small `child_process` API list; bounded single-definition module-level literal flow | TypeScript, import/alias resolution, computed property calls, branch-sensitive or interprocedural flow, or Node runtime equivalence | [ADR 0002](decisions/0002-python-javascript-parser-boundary.md), [Analysis rules: Python/JavaScript](analysis-rules.md#python-and-javascript-syntax-tree-boundary), [`treesitter.go`](../internal/analyze/treesitter.go) |
| Desktop entry | `.desktop` | Exact `[Desktop Entry]`, `Exec`, `Hidden`, bounded quoting/escaping, field-code uncertainty, and exact autostart path context | Full freedesktop launcher behavior, duplicate-key precedence, installation, enablement, or launch | [ADR 0011](decisions/0011-desktop-entry-analysis.md), [Analysis rules: desktop](analysis-rules.md#desktop-entries-and-autostart), [`desktop.go`](../internal/analyze/desktop.go) |
| systemd unit | Reviewed unit extensions and matching drop-in `.conf` paths | Reviewed `Exec*`, install metadata, timer/path/socket activation, quoting, continuation, and selected prefixes/substitutions | A full unit loader, manager state, installation, enablement, activation, or command success | [ADR 0012](decisions/0012-systemd-unit-analysis.md), [Analysis rules: systemd](analysis-rules.md#systemd-units-services-and-activation), [`systemd.go`](../internal/analyze/systemd.go) |
| Hyprland config | Exact reviewed names or `.conf` below a `hypr`/`hyprland` path component | Exact execution, bind-exec, source, and native-plugin directives; embedded commands reuse the shell parser | Full Hyprland configuration semantics, variable expansion, include order, compositor loading, or native behavior | [ADR 0013](decisions/0013-hyprland-configuration-analysis.md), [Analysis rules: Hyprland](analysis-rules.md#hyprland-configuration), [`hyprland.go`](../internal/analyze/hyprland.go) |
| ZIP/TAR/archive marker | Reviewed signatures, with `.tar` as an additional TAR selector | Bounded ZIP central-directory or TAR header metadata; compressed-only formats are identified | Member extraction, payload behavior, nested analysis, checksums, or decompression ratio | [ADR 0015](decisions/0015-archive-metadata-inventory.md), [Analysis rules: archives](analysis-rules.md#archives-and-bundled-payloads), [`inventory.go`](../internal/inventory/inventory.go) |
| ELF | ELF content identification | Bounded metadata through Go's `debug/elf`: libraries, imports, strings, URLs, privilege bits, and file capabilities | Loading, execution, disassembly, call reachability, arguments, or source equivalence | [ADR 0016](decisions/0016-bounded-elf-metadata.md), [Analysis rules: ELF](analysis-rules.md#native-elf-files), [`inventory.go`](../internal/inventory/inventory.go) |

The exact file-selection order is in
[`internal/analyze.Sources`](../internal/analyze/shell.go). Unsupported
runtime-relevant languages are recorded by
[`coverage.go`](../internal/analyze/coverage.go), rather than being described as
successfully analyzed.

## Python and JavaScript execution API boundary

The syntax-tree parser records call expressions neutrally, but only this small
list is treated as a possible process launch:

- Python: `subprocess.run`, `subprocess.Popen`, `subprocess.call`,
  `subprocess.check_call`, and `subprocess.check_output`;
- JavaScript: `child_process.spawn`, `child_process.spawnSync`,
  `child_process.execFile`, `child_process.execFileSync`, and
  `child_process.fork`.

A direct Python literal string or literal string array can become a process
operation. JavaScript requires a string executable and a complete string array
when arguments are present; omitted arguments and empty arrays are supported.
Unresolved arguments and unsupported options/callback overloads retain a
call-linked unknown and suppress the derived process operation. See the
[literal-argument contract](analysis-rules.md#python-and-javascript-syntax-tree-boundary).
A unique module-level literal assignment may be followed for at most 16
references through at most 1,024 retained definitions. Duplicate definitions,
branch-local definitions, cycles, computed values, unsupported literal forms,
or missing arguments remain unknown. A nearby textual assignment may be shown
as an origin, but is not presented as proven runtime data flow.

The authoritative API list and resolution rules are in
[`treesitter.go`](../internal/analyze/treesitter.go). Positive, negative,
lookalike, malformed, ambiguous, budget, deterministic, race, and fuzz evidence
is in [`treesitter_test.go`](../internal/analyze/treesitter_test.go),
[`determinism_test.go`](../internal/analyze/determinism_test.go), and
[`fuzz_test.go`](../internal/analyze/fuzz_test.go).

## Correlation is a separate boundary

Parsers produce operations and resources. The correlation stage may connect
those retained observations, but it does not get to invent missing parser
semantics.

For example:

- an adjacent parsed `curl | bash` pipeline is a syntax-local fact;
- a download to a literal path followed by invocation of that same literal path
  is an inference that cites both operations; and
- a sensitive-file read plus unrelated network capability is only a
  co-capability inference and explicitly does not claim data flow.

Exact matches, ambiguity behavior, deliberate exclusions, and bounded lookup
rules are described in [ADR 0008](decisions/0008-correlation-engine.md) and
[ADR 0014](decisions/0014-indirect-script-reachability.md). The implementation
is in [`correlations.go`](../internal/analyze/correlations.go),
[`installed_artifacts.go`](../internal/analyze/installed_artifacts.go), and
[`reachability.go`](../internal/analyze/reachability.go), with adjacent tests.

## Important limits

These are the main caps a parser reviewer should encounter. The linked decision
and constants are the source of truth; this table is a navigation aid.

| Boundary | Current cap | Where defined or explained |
|---|---:|---|
| Inventory files / directory depth | 10,000 / 32 | [`inventory.DefaultLimits`](../internal/inventory/inventory.go), [ADR 0005](decisions/0005-analysis-production-budget.md) |
| Ordinary source file / total source bytes | 2 MiB / 32 MiB | [`inventory.DefaultLimits`](../internal/inventory/inventory.go) |
| ELF file / total ELF bytes | 64 MiB / 128 MiB | [`inventory.DefaultLimits`](../internal/inventory/inventory.go) |
| Python/JavaScript parse timeout | 2 seconds per file | [`treesitter.go`](../internal/analyze/treesitter.go), [ADR 0002](decisions/0002-python-javascript-parser-boundary.md) |
| Python/JavaScript origin traversal | 100,000 syntax nodes | [`treesitter.go`](../internal/analyze/treesitter.go) |
| Python/JavaScript or QML retained definitions | 1,024 per file | [`treesitter.go`](../internal/analyze/treesitter.go), [`qml_flow.go`](../internal/analyze/qml_flow.go) |
| Python/JavaScript or QML literal-reference depth | 16 | [`treesitter.go`](../internal/analyze/treesitter.go), [`qml_flow.go`](../internal/analyze/qml_flow.go) |
| Desktop/systemd/Hyprland physical lines | 20,000 per file | [`desktop.go`](../internal/analyze/desktop.go), [`systemd.go`](../internal/analyze/systemd.go), [`hyprland.go`](../internal/analyze/hyprland.go) |
| Archive metadata entries | 4,096 per archive | [`report.go`](../internal/report/report.go), [ADR 0015](decisions/0015-archive-metadata-inventory.md) |
| Produced operations / resources / findings / unknowns | 5,000 / 10,000 / 10,000 / 5,000 | [`shell.go`](../internal/analyze/shell.go), [ADR 0005](decisions/0005-analysis-production-budget.md) |
| Final report | 16 MiB | [`policy/limits.go`](../internal/policy/limits.go), [report contract](report-contract.md) |
| Contained process | 256 MiB memory, no swap, 64 tasks, one CPU, 30 seconds | [`policy/limits.go`](../internal/policy/limits.go), [ADR 0003](decisions/0003-systemd-resource-scope.md) |

Crossing a limit must be visible. Depending on the boundary, the scanner keeps
only already-established evidence, adds a limitation or unknown, marks analysis
incomplete, rejects the scan, or fails containment closed. It must never treat a
truncated prefix as a complete literal.

## Parser dependencies and grammar provenance

The production Go module pins three external modules in [`go.mod`](../go.mod)
and authenticates their exact module contents through [`go.sum`](../go.sum):

| Dependency | Parser role | Origin evidence |
|---|---|---|
| `mvdan.cc/sh/v3 v3.13.1` | Bash-compatible syntax AST only; the interpreter package is not imported | Module hashes, [dependency audit](dependencies.md), and [third-party notice](../THIRD_PARTY_NOTICES.md) |
| `github.com/odvcencio/gotreesitter v0.51.0` | Pure-Go parser runtime and selectively embedded Python/JavaScript grammar blobs | Module hashes, upstream `grammars/languages.lock`, [dependency audit](dependencies.md), and [third-party notice](../THIRD_PARTY_NOTICES.md) |
| `golang.org/x/sys v0.47.0` | Descriptor-relative Linux filesystem and mount-boundary APIs; not a language parser | Module hashes, [dependency audit](dependencies.md), and [third-party notice](../THIRD_PARTY_NOTICES.md) |

The pinned `gotreesitter` release records these upstream grammar revisions:

- JavaScript: `tree-sitter/tree-sitter-javascript` commit
  `58404d8cf191d69f2674a8fd507bd5776f46cb11`;
- Python: `tree-sitter/tree-sitter-python` commit
  `26855eabccb19c6abf499fbc5b8dc7cc9ab8bc64`.

A reviewer can see the exact upstream lock carried by the authenticated module
without hunting through the Go cache manually:

```bash
go mod verify
module_dir="$(go env GOMODCACHE)/github.com/odvcencio/gotreesitter@v0.51.0"
rg '^(javascript|python) ' "$module_dir/grammars/languages.lock"
scripts/verify-production-dependencies.sh
```

Production builds require the
`grammar_subset,grammar_subset_python,grammar_subset_javascript` tags. The
[footprint check](../scripts/verify-parser-footprint.sh) confirms the selective
profile for ARM64 and AMD64. The
[oracle check](../scripts/verify-parser-oracles.sh) compares only trusted samples
created inside that script with locally installed Python and Node syntax tools;
it never runs a target plugin or hostile fixture.

The complete supply-chain review procedure, graph-only test dependencies,
licenses, and limits of what module hashes prove are in
[`docs/dependencies.md`](dependencies.md).

## Track B reading order

For an independent parser review, a useful order is:

1. Read [ADR 0002](decisions/0002-python-javascript-parser-boundary.md) and the
   relevant row above.
2. Compare the documented selection, syntax, claim, failure, and resource
   boundaries with the implementation and adjacent tests.
3. Review dependency and upstream grammar provenance using the commands above.
4. Read [ADR 0008](decisions/0008-correlation-engine.md) and verify that
   correlations do not overstate parser facts.
5. Check [fact, inference, unknown, severity, confidence, and scope](severity-model.md)
   independently rather than treating them as one score.
6. Follow the exact evidence and sign-off requirements in
   [Track B of the human review guide](human-review-guide.md#track-b-hostile-parsers-and-correlation-semantics).

Finding a disagreement is a successful review outcome. Record it with an exact
commit and file/line evidence; do not weaken a boundary merely to make a test
pass.
