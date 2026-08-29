package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeRejectsDuplicateMembersBeforeTypedDecode(t *testing.T) {
	valid, err := json.Marshal(validReport())
	if err != nil {
		t.Fatal(err)
	}
	duplicateTop := bytes.Replace(valid, []byte(`"status":"complete"`), []byte(`"status":"incomplete","status":"complete"`), 1)
	duplicateNested := bytes.Replace(valid, []byte(`"scannerVersion":"test"`), []byte(`"scannerVersion":"forged","scannerVersion":"test"`), 1)
	for _, data := range [][]byte{duplicateTop, duplicateNested} {
		if _, err := Decode(data); err == nil || !strings.Contains(err.Error(), "duplicate JSON object member") {
			t.Fatalf("duplicate member result = %v", err)
		}
	}
}

func TestDecodeRejectsOversizedAndDeepInputBeforeReportAllocation(t *testing.T) {
	if _, err := Decode(make([]byte, MaxEncodedReportBytes+1)); err == nil || !strings.Contains(err.Error(), "encoded input exceeds") {
		t.Fatalf("oversized input result = %v", err)
	}
	deep := []byte(strings.Repeat("[", MaxJSONDepth+2) + "0" + strings.Repeat("]", MaxJSONDepth+2))
	if _, err := Decode(deep); err == nil || !strings.Contains(err.Error(), "nesting exceeds") {
		t.Fatalf("deep input result = %v", err)
	}
}

func TestEverySerializedStringAndMapKeyIsIndividuallyBounded(t *testing.T) {
	oversized := strings.Repeat("x", MaxHostileStringBytes)
	tests := []func(*Report){
		func(r *Report) { r.Scan.ScannerVersion = oversized },
		func(r *Report) {
			r.Target.Manifest = &Manifest{Kinds: []string{}, EntryPoints: map[string]string{oversized: "Panel.qml"}}
		},
		func(r *Report) {
			r.Limitations = []Limitation{{Code: oversized, Description: "bounded"}}
			r.Status = StatusIncomplete
		},
	}
	for _, mutate := range tests {
		r := validReport()
		mutate(&r)
		if r.Status == StatusIncomplete {
			_ = r.BuildReviewSummary(r.Review.AnalysisCoverage)
		}
		if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "encoded length") {
			t.Fatalf("oversized serialized string result = %v", err)
		}
	}
}

func TestCoverageIsRecomputedFromInventoryDispositions(t *testing.T) {
	r := validReport()
	r.Status = StatusIncomplete
	r.Target.FileCount = 1
	r.Target.ReadBytes = 1
	r.Inventory = []File{{Path: "plugin.sh", Kind: "regular", Mode: "-rw-r--r--", Size: 1, Inspected: true, SHA256: strings.Repeat("a", 64), ContentType: "text/plain", Analysis: AnalysisPartial, AnalysisReason: "dynamic behavior unresolved"}}
	r.Limitations = []Limitation{{Code: "dynamic", Description: "Dynamic behavior remains unresolved."}}
	forged := NewCoverageSummary(1, 0, 0)
	if err := r.BuildReviewSummary(forged); err == nil || !strings.Contains(err.Error(), "inventory dispositions") {
		t.Fatalf("forged coverage result = %v", err)
	}
	if err := r.BuildReviewSummary(NewCoverageSummary(0, 1, 0)); err != nil {
		t.Fatal(err)
	}
	r.Review.AnalysisCoverage = forged
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "inventory dispositions") {
		t.Fatalf("serialized forged coverage result = %v", err)
	}
}

func TestCompleteStatusRejectsIncompleteCoverage(t *testing.T) {
	r := validReport()
	r.Target.FileCount = 1
	r.Target.ReadBytes = 1
	r.Inventory = []File{{Path: "plugin.sh", Kind: "regular", Mode: "-rw-r--r--", Size: 1, Inspected: true, SHA256: strings.Repeat("a", 64), ContentType: "text/plain", Analysis: AnalysisPartial, AnalysisReason: "unsupported syntax"}}
	r.Review = nil
	if err := r.BuildReviewSummary(NewCoverageSummary(0, 1, 0)); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "complete analysis coverage") {
		t.Fatalf("complete partial-coverage result = %v", err)
	}
}

func TestUnknownCannotMasqueradeAsSeverityBearingFinding(t *testing.T) {
	r := validReport()
	r.Status = StatusIncomplete
	r.Findings = []Finding{{ID: "unknown-as-finding", Claim: ClaimType("unknown"), Severity: SeverityInformational, Confidence: ConfidenceHigh, Category: "coverage", Scope: ScopeUnknown, Title: "Unknown", Explanation: "Hidden as a finding.", Evidence: []Evidence{{Path: "plugin.sh"}}, Provenance: testProvenance}}
	r.Limitations = []Limitation{{Code: "coverage", Description: "Coverage incomplete."}}
	buildTestEvidence(t, &r)
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "invalid claim") {
		t.Fatalf("unknown finding result = %v", err)
	}
}

func TestInferenceRequiresDeclaredSupport(t *testing.T) {
	r := validReport()
	r.Findings = []Finding{{ID: "unsupported-inference", Claim: ClaimInference, Severity: SeverityHigh, Confidence: ConfidenceHigh, Category: "conclusion", Scope: ScopeRuntime, Title: "Unsupported", Explanation: "No supporting operation.", Evidence: []Evidence{{Path: "plugin.sh"}}, Provenance: testProvenance}}
	buildTestEvidence(t, &r)
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "no declared supporting operation") {
		t.Fatalf("unsupported inference result = %v", err)
	}
}

func TestLocalProvenanceMustMatchTrustedScannerIdentity(t *testing.T) {
	r := validReport()
	r.Operations = []Operation{{ID: "op", Category: "execution", Command: "true", Scope: ScopeRuntime, Confidence: ConfidenceHigh, Evidence: Evidence{Path: "plugin.sh"}, Provenance: testProvenance}}
	buildTestEvidence(t, &r)
	for _, mutate := range []func(*Provenance){
		func(p *Provenance) { p.Analyzer = "plugin-controlled/scanner" },
		func(p *Provenance) { p.AnalyzerVersion = "different-version" },
	} {
		bad := r
		bad.Operations = append([]Operation(nil), r.Operations...)
		mutate(&bad.Operations[0].Provenance)
		if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "trusted scanner identity") {
			t.Fatalf("forged provenance result = %v", err)
		}
	}
}

func TestComparisonCannotRelateDifferentNodeKinds(t *testing.T) {
	r := graphReport(t)
	if err := r.AddComparison(Comparison{Type: RelationshipCorroborates, FromKind: NodeFinding, FromID: r.Findings[0].ID, ToKind: NodeOperation, ToID: r.Operations[0].ID}); err == nil || !strings.Contains(err.Error(), "same node kind") {
		t.Fatalf("cross-kind comparison result = %v", err)
	}
}

func TestDedicatedUnknownRejectsNullStructuredCollections(t *testing.T) {
	r := graphReport(t)
	for _, mutate := range []func(*Unknown){
		func(value *Unknown) { value.Origins = nil },
		func(value *Unknown) { value.AffectedOperations = nil },
		func(value *Unknown) { value.SuppressedRules = nil },
	} {
		bad := r
		bad.Unknowns = append([]Unknown(nil), r.Unknowns...)
		mutate(&bad.Unknowns[0])
		if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "must be JSON arrays") {
			t.Fatalf("null unknown collection result = %v", err)
		}
	}
}

func TestGraphAndJSONEncodingAreDeterministicAcrossRepeatedBuilds(t *testing.T) {
	r := graphReport(t)
	var first []byte
	for iteration := 0; iteration < 100; iteration++ {
		if err := r.BuildEvidenceGraph(); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if iteration == 0 {
			first = encoded
		} else if !bytes.Equal(first, encoded) {
			t.Fatalf("iteration %d produced different bytes", iteration)
		}
	}
}
