# 0002: Python and JavaScript parser boundary

- Status: proposed; dependency approval pending
- Date: 2026-08-27

## Context

Runtime Python and JavaScript are common in real Omarchy plugins. Omitting them
would make reports misleading, while regex-only semantic claims would create
the keyword-scanner behavior this project rejects.

The parser must accept hostile input, remain bounded, run without executing
target code, preserve a self-contained ARM64/AMD64 scanner, and avoid widening
the deterministic sandbox with language runtimes or shared libraries.

## Options considered

### Execute CPython `ast.parse` in the sandbox

Rejected as the default architecture. Although `ast.parse` does not evaluate
the parsed module, this would mount and execute a large interpreter/runtime in
the deterministic scanner boundary, complicate distribution, and create a
second process and dependency surface.

### Official Go Tree-sitter bindings

Rejected for the current static release model because they use CGO and the C
Tree-sitter runtime. Cross-architecture builds and race/fuzz coverage would no
longer retain the current pure-Go boundary.

### Older pure-Go Python parser

Rejected because its Python 3.4 grammar is materially obsolete for current
plugins.

### Hand-written or regex semantic parser

Rejected. Python and JavaScript syntax, comments, strings, calls, and dynamic
features are too complex for a small local implementation to support credible
security findings.

### Selective pure-Go Tree-sitter runtime

Candidate recommendation: audit and pilot `odvcencio/gotreesitter` using only
embedded Python and JavaScript grammar subsets. It preserves CGO-free static
cross-compilation and exposes strict parsing with safety caps. However, it is a
young, substantial ground-up runtime; its parser core, grammar provenance,
binary-size cost, malformed-input behavior, and fuzz/race posture require an
explicit dependency review before adoption.

## Interim decision

Do not add a Python or JavaScript semantic dependency silently. Inventory those
files, derive reachability, and emit scoped coverage limitations that force the
report status to `incomplete`. Continue language-independent analysis from
already parsed shell/QML operations.

Before accepting the candidate dependency:

1. Pin an immutable released version and grammar provenance.
2. Measure static ARM64/AMD64 binary-size impact with only two grammars.
3. Run malformed, deep, large, timeout, race, and fuzz corpus tests.
4. Inspect the dependency graph, licenses, release/signing practice, and known
   vulnerabilities.
5. Compare parsed call facts with CPython/Node oracles in test-only tooling.
6. Require human approval of the resulting dependency and threat-model change.
