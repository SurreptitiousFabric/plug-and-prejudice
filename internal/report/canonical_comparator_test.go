package report

import (
	"bytes"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

func reportWithInventoryPath(path string) Report {
	r := validReport()
	r.Inventory = []File{{Path: path, Kind: "regular", Mode: "-rw-r--r--", Inspected: true, SHA256: strings.Repeat("a", 64), ContentType: "text/plain", Analysis: AnalysisAnalyzed}}
	r.Target.FileCount = 1
	refreshTestRootDigest(&r)
	return r
}

func encodeFindingEvidence(t *testing.T, evidence []Evidence) ([]byte, Report) {
	t.Helper()
	r := reportWithInventoryPath("plugin.sh")
	r.Findings = []Finding{{
		ID: "finding-canonical-evidence", Claim: ClaimFact, Severity: SeverityInformational,
		Confidence: ConfidenceHigh, Category: "canonical-test", Scope: ScopeUnknown,
		Title: "Canonical evidence", Explanation: "Comparator test", Evidence: evidence,
		Related: []string{}, Provenance: Provenance{RuleID: "canonical-test", Analyzer: DeterministicAnalyzer,
			AnalyzerVersion: r.Scan.ScannerVersion, EvidenceSource: EvidenceSourceTargetSource},
	}}
	if err := r.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeCanonical(r)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, r
}

func encodeUnknownEvidence(t *testing.T, evidence []Evidence) ([]byte, Report) {
	t.Helper()
	r := reportWithInventoryPath("plugin.sh")
	r.Status = StatusIncomplete
	r.Unknowns = []Unknown{{
		ID: "unknown-canonical-evidence", Category: "dynamic-command", Reason: UnknownDynamicValue,
		Scope: ScopeRuntime, Confidence: ConfidenceHigh, Title: "Dynamic command", Description: "Comparator test",
		Evidence: evidence, Origins: []ValueOrigin{}, AffectedOperations: []string{}, SuppressedRules: []string{},
		Provenance: Provenance{RuleID: "canonical-test", Analyzer: DeterministicAnalyzer,
			AnalyzerVersion: r.Scan.ScannerVersion, EvidenceSource: EvidenceSourceTargetSource},
	}}
	if err := r.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeCanonical(r)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, r
}

func encodeLimitations(t *testing.T, values []Limitation) []byte {
	t.Helper()
	r := validReport()
	r.Status = StatusIncomplete
	r.Limitations = append([]Limitation(nil), values...)
	encoded, err := EncodeCanonical(r)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func encodeErrors(t *testing.T, values []ScanError) []byte {
	t.Helper()
	r := validReport()
	r.Status = StatusError
	r.Errors = append([]ScanError(nil), values...)
	encoded, err := EncodeCanonical(r)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestCanonicalHostileFieldCollisionsAreOrderIndependent(t *testing.T) {
	evidenceA := Evidence{InputID: TargetEvidenceInputID, Path: "plugin.sh", Operation: "a\x00b", Excerpt: "c"}
	evidenceB := Evidence{InputID: TargetEvidenceInputID, Path: "plugin.sh", Operation: "a", Excerpt: "b\x00c"}
	for _, encode := range []struct {
		name string
		fn   func(*testing.T, []Evidence) ([]byte, Report)
	}{{"finding", encodeFindingEvidence}, {"unknown", encodeUnknownEvidence}} {
		t.Run(encode.name, func(t *testing.T) {
			forward, _ := encode.fn(t, []Evidence{evidenceA, evidenceB})
			reverse, _ := encode.fn(t, []Evidence{evidenceB, evidenceA})
			if !bytes.Equal(forward, reverse) {
				t.Fatal("canonical evidence bytes depend on insertion order")
			}
		})
	}

	limitationA := Limitation{Code: "a\x00b", Description: "d"}
	limitationB := Limitation{Code: "a", Path: "b", Description: "\x00d"}
	if forward, reverse := encodeLimitations(t, []Limitation{limitationA, limitationB}), encodeLimitations(t, []Limitation{limitationB, limitationA}); !bytes.Equal(forward, reverse) {
		t.Fatal("canonical limitation bytes depend on insertion order")
	}

	errorA := ScanError{Code: "a\x00b", Message: "d"}
	errorB := ScanError{Code: "a", Path: "b", Message: "\x00d"}
	if forward, reverse := encodeErrors(t, []ScanError{errorA, errorB}), encodeErrors(t, []ScanError{errorB, errorA}); !bytes.Equal(forward, reverse) {
		t.Fatal("canonical scan-error bytes depend on insertion order")
	}
}

func TestCanonicalEvidenceNumericLinesAndUnicodeRoundTrip(t *testing.T) {
	values := []Evidence{
		{InputID: TargetEvidenceInputID, Path: "plugin.sh", LineStart: 10, LineEnd: 11, Operation: "nul\x00replacement:\ufffd", Excerpt: "e\u0301"},
		{InputID: TargetEvidenceInputID, Path: "plugin.sh", LineStart: 2, LineEnd: 3, Operation: "日本語", Excerpt: "é"},
	}
	encoded, _ := encodeFindingEvidence(t, values)
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	got := decoded.Findings[0].Evidence
	if got[0].LineStart != 2 || got[1].LineStart != 10 {
		t.Fatalf("line numbers were not compared numerically: %#v", got)
	}
	if got[1].Operation != values[0].Operation || got[1].Excerpt != values[0].Excerpt || got[0].Operation != values[1].Operation || got[0].Excerpt != values[1].Excerpt {
		t.Fatalf("hostile Unicode did not round-trip exactly: %#v", got)
	}
}

func TestCanonicalExactDuplicateEvidenceIsDeterministic(t *testing.T) {
	duplicate := Evidence{InputID: TargetEvidenceInputID, Path: "plugin.sh", Operation: "same\x00value", Excerpt: "same"}
	forward, _ := encodeFindingEvidence(t, []Evidence{duplicate, duplicate})
	reverse, _ := encodeFindingEvidence(t, []Evidence{duplicate, duplicate})
	if !bytes.Equal(forward, reverse) {
		t.Fatal("exact duplicate evidence changed canonical output")
	}
}

func TestCanonicalComparatorsAreTotalOrders(t *testing.T) {
	hostile := []string{"", "a", "a\x00b", "a:b", "\\u0000", "é", "e\u0301", "日本語", "\x01"}
	evidence := []Evidence{{}}
	limitations := []Limitation{{}}
	errors := []ScanError{{}}
	for index, value := range hostile {
		evidence = append(evidence,
			Evidence{InputID: value}, Evidence{Path: value}, Evidence{LineStart: index + 1},
			Evidence{LineEnd: index + 1}, Evidence{Operation: value}, Evidence{Excerpt: value})
		limitations = append(limitations,
			Limitation{Code: value}, Limitation{Path: value}, Limitation{Scope: Scope(value)}, Limitation{Description: value})
		errors = append(errors, ScanError{Code: value}, ScanError{Path: value}, ScanError{Message: value})
	}
	testTotalOrder(t, evidence, compareEvidence)
	testTotalOrder(t, limitations, compareLimitation)
	testTotalOrder(t, errors, compareScanError)
}

func testTotalOrder[T comparable](t *testing.T, values []T, compare func(T, T) int) {
	t.Helper()
	values = append(values, values[0]) // exact duplicates compare equal and remain harmless
	for _, a := range values {
		for _, b := range values {
			ab, ba := compare(a, b), compare(b, a)
			if (ab == 0) != (a == b) {
				t.Fatalf("comparison equality does not match exact equality: %#v %#v", a, b)
			}
			if sign(ab) != -sign(ba) {
				t.Fatalf("comparison is not antisymmetric: %#v %#v", a, b)
			}
			for _, c := range values {
				if ab <= 0 && compare(b, c) <= 0 && compare(a, c) > 0 {
					t.Fatalf("comparison is not transitive: %#v %#v %#v", a, b, c)
				}
			}
		}
	}
}

func sign(value int) int {
	if value < 0 {
		return -1
	}
	if value > 0 {
		return 1
	}
	return 0
}

func TestCanonicalizationDoesNotMutateCallerSlices(t *testing.T) {
	evidence := []Evidence{{InputID: TargetEvidenceInputID, Path: "plugin.sh", Operation: "z"}, {InputID: TargetEvidenceInputID, Path: "plugin.sh", Operation: "a"}}
	_, report := encodeFindingEvidence(t, evidence)
	want := append([]Evidence(nil), report.Findings[0].Evidence...)
	if _, err := EncodeCanonical(report); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(report.Findings[0].Evidence, want) {
		t.Fatal("canonical encoding mutated caller-owned evidence")
	}

	limitations := []Limitation{{Code: "z", Description: "z"}, {Code: "a", Description: "a"}}
	r := validReport()
	r.Status = StatusIncomplete
	r.Limitations = limitations
	wantLimitations := append([]Limitation(nil), limitations...)
	if _, err := EncodeCanonical(r); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Limitations, wantLimitations) {
		t.Fatal("canonical encoding mutated caller-owned limitations")
	}
}

func TestReviewReasonsStableAcrossHostileLimitationPermutations(t *testing.T) {
	base := make([]Limitation, 10)
	for index := range base {
		base[index] = Limitation{Code: strings.Repeat("a", index%3+1) + "\x00" + string(rune('a'+index)), Description: "description\x00" + string(rune('z'-index)), Scope: ScopeUnknown}
	}
	wantBytes := encodeLimitations(t, base)
	want, err := Decode(wantBytes)
	if err != nil {
		t.Fatal(err)
	}
	for seed := 0; seed < 100; seed++ {
		permutation := append([]Limitation(nil), base...)
		rand.New(rand.NewSource(int64(seed))).Shuffle(len(permutation), func(i, j int) {
			permutation[i], permutation[j] = permutation[j], permutation[i]
		})
		gotBytes := encodeLimitations(t, permutation)
		if !bytes.Equal(gotBytes, wantBytes) {
			t.Fatalf("permutation %d changed canonical bytes", seed)
		}
		got, err := Decode(gotBytes)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got.Review.UnknownBehavior.Reasons, want.Review.UnknownBehavior.Reasons) || !reflect.DeepEqual(got.Review.MainReasons, want.Review.MainReasons) {
			t.Fatalf("permutation %d changed selected review reasons", seed)
		}
		if len(got.Review.UnknownBehavior.Reasons) != maxReviewReasons {
			t.Fatalf("permutation %d selected %d reasons", seed, len(got.Review.UnknownBehavior.Reasons))
		}
	}
}
