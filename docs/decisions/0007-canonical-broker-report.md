# 0007: Canonical broker-to-UI report

- Status: implemented; independent report-rendering approval pending
- Date: 2026-08-27

## Context

The sandbox caps scanner stdout at 16 MiB and the broker strictly decodes it
into the Go report type, rejects unknown fields, and validates semantic
relationships. The broker currently writes the original scanner bytes to
stdout after validation. QML then parses those bytes again with its JavaScript
JSON implementation.

That validates one interpretation but presents another parser's interpretation.
JSON permits interoperability hazards such as duplicate object member names;
escaped lone UTF-16 surrogates and future parser-version differences can also
produce different string values or rejection behavior. Even when today's Go
and QML implementations happen to agree on a case, passing the original bytes
does not establish that the UI received the exact object the broker approved.

This is separate from plain-text rendering. Escaping QML/HTML controls prevents
presentation injection only after the report object has been established.

## Options considered

### Continue forwarding the original scanner bytes

Rejected. It preserves scanner formatting but makes cross-parser equivalence an
unstated security assumption. Adding a custom duplicate-key pre-parser would
address only one ambiguity and create another parser-like component in the
trusted broker.

### Parse independently in QML and compare selected fields

Rejected. The thin wrapper should not duplicate the Go schema validator, and
field-by-field comparison is likely to omit exactly the nested value an attacker
targets.

### Re-encode the validated Go report through a bounded buffer

Recommended. After strict decode, semantic validation, selected-plugin binding,
root-digest presence, and resource-policy checks, pass the typed Go value to
the report contract's shared canonical bounded encoder. Emit only those new
bytes. QML then receives one canonical representation of the exact semantic
object the broker validated; unknown or duplicate source representation is not
preserved across the boundary.

The buffer must fail before stdout if canonical encoding exceeds the existing
16 MiB broker report ceiling. It must not stream a partial report to QML.
Arrays/objects validated as non-null remain arrays/objects, HTML-sensitive
characters retain standard-library escaping, and encoding errors fail closed.
Canonical here means “one broker-generated representation for this typed
value,” not RFC 8785 cryptographic canonical JSON and not a signature format.

ADR 0005 independently requires bounded scanner-side final serialization so a
buggy producer cannot construct or emit an oversized result. This decision
requires the broker to apply the ceiling again after typed re-encoding because
standard-library escaping can change byte length. If both decisions are
approved, scanner and broker use the same `report.EncodeCanonical` contract so
sorting, HTML escaping, validation, and the exact 16 MiB representation cannot
drift. Scanner stdout remains independently bounded by the sandbox, so the
checks still occur at distinct trust boundaries.

The standalone scanner remains independently useful and continues to emit its
own validated versioned JSON. Canonical broker re-encoding is a defense at the
second-parser/UI boundary, not a claim that raw scanner output is hostile code.

## Required verification

Implementation requires:

1. a report containing duplicate member names is either rejected during strict
   decode or demonstrably collapses only to the single typed value that the
   broker re-encodes;
2. escaped lone-surrogate and invalid UTF-8 inputs are rejected before typed
   decoding, while valid HTML-sensitive, C0/C1, and bidi strings round-trip;
3. an aggregate report over 16 MiB proves bounded encoding writes no partial
   stdout, and the broker is tested to delegate to the exact shared encoder;
4. a strict round trip of broker output through `report.Decode`;
5. existing hostile plain-text QML tests continue to pass;
6. normal/race/fuzz tests for the bounded encoder; and
7. human review of both Go report serialization and QML ingestion before merge.

## Consequences

- Scanner indentation and producer insertion order are not a UI protocol;
  canonical collection ordering is defined by the report contract.
- The UI sees only fields in the accepted typed schema.
- A validated report can still contain hostile string content; the existing
  QML plain-text normalization and row/string caps remain required.
- Cryptographic authenticity remains a release/package concern; re-encoding
  does not prove who produced the scanner binary or report.
