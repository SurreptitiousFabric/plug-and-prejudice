# 0015: Archive metadata inventory without extraction

- Status: implemented in development tree; independent archive/parser review pending
- Date: 2026-08-28

## Context

Plugins can bundle scripts, binaries, nested archives, traversal names, and
links inside container files. Ignoring them hides payload presence, while
extracting into a temporary directory introduces traversal, link, decompression
bomb, file-count, filesystem, and ordinary-test-discovery risks.

## Decision

Extend inspected regular-file inventory with bounded archive metadata. ZIP is
identified by reviewed signatures; TAR by its `ustar` header or exact `.tar`
extension. ZIP central-directory and TAR header metadata are read from the
already retained in-memory file bytes. No member stream is opened for content,
no path is created, and no member is added to ordinary source analysis.

ZIP/TAR retain at most 4,096 entries per archive: hostile member path, kind,
mode, link target where header-visible, declared uncompressed/compressed sizes,
encryption flag, and an independently computed unsafe-path flag. Absolute,
parent-traversing, or backslash paths are unsafe. Symbolic and hard links remain
distinct metadata. Entry names and aggregate declared sizes use the existing
encoded-string and integer-overflow boundaries.

Gzip, XZ, Zstandard, and bzip2 signatures are identified, but member inventory
is intentionally unavailable because obtaining it would require decompression.
Malformed containers, excessive entries, oversized metadata, size overflow,
and compressed-only formats produce limitations rather than extraction.

Analysis emits an informational archive-inventory fact, one aggregate medium
path/link-risk fact when supported by retained headers, and a dedicated
`unreachable-source` unknown for member payload semantics. Every archive keeps
an `archive-payload-not-analyzed` limitation: metadata is not evidence of
member behavior.

## Limits and hostile input

Archive files remain under the existing 2 MiB individual and 32 MiB aggregate
source-read budgets. Nested metadata is capped at 4,096 entries and charged to
the 3 MiB inventory encoded-string budget before the file is retained. The
report validator independently enforces format, collection, string, size, sum,
file-kind, and ELF/archive exclusivity constraints. The final 16 MiB report,
memory, CPU, process, and wall limits remain independent.

Tests create ZIP/TAR bytes strictly as data and verify safe/unsafe members,
links, no extracted inventory paths, unchanged retained container bytes,
compressed-only identification, malformed input, exact/over entry limits,
oversized names, validator mutations, unknown/fact separation, race behavior,
and fuzzed archive signatures. No malicious fixture is executed or discovered
as a test program.

## Residual risk and review gate

The standard-library ZIP reader constructs central-directory objects from a
bounded 2 MiB input before the report-entry cap is applied. Member bodies,
nested containers, ZIP symlink targets stored as payload bytes, checksums,
signatures, compression ratios, and executable semantics remain uninspected.
TAR extensions supported by the standard reader may expose more header metadata
than this model retains.

Independent human review is required for signature selection, standard-library
parser allocation behavior, TAR iteration, member/path classification, integer
accounting, nested schema validation, risk severity, and non-extraction claims
before merge.
