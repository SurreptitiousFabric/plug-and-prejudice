package report

import (
	"slices"
	"strings"
	"testing"
)

func standaloneCoverageReport(t *testing.T, external bool) Report {
	t.Helper()
	r := graphReport(t)
	provenance := Provenance{RuleID: CoverageComparisonRule, Analyzer: DeterministicAnalyzer, AnalyzerVersion: r.Scan.ScannerVersion, EvidenceSource: EvidenceSourceTargetSource}
	evidence := r.Operations[0].Evidence
	if external {
		appendTestExternalInput(&r, "input-omarchy")
		provenance.EvidenceSource = EvidenceSourceOmarchyAudit
		evidence = Evidence{InputID: "input-omarchy", Path: "audit.json"}
	}
	r.Findings = append(r.Findings, Finding{ID: "standalone-coverage", Claim: ClaimFact, Severity: SeverityInformational, Confidence: ConfidenceHigh, Category: CoverageDifferenceCategory, Scope: ScopeUnknown, Title: "Coverage differs", Explanation: "Standalone reserved finding.", Evidence: []Evidence{evidence}, Related: []string{}, Provenance: provenance})
	if err := r.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
		t.Fatal(err)
	}
	return r
}

func coverageFinding(r *Report) *Finding {
	for i := range r.Findings {
		if r.Findings[i].Provenance.RuleID == CoverageComparisonRule || r.Findings[i].Category == CoverageDifferenceCategory {
			return &r.Findings[i]
		}
	}
	return nil
}

func coverageRelationship(r *Report) *Relationship {
	for i := range r.Relationships {
		if r.Relationships[i].Type == RelationshipDisagreesWith {
			return &r.Relationships[i]
		}
	}
	return nil
}

func TestReservedCoverageFindingRequiresIncomingDisagreement(t *testing.T) {
	for _, external := range []bool{false, true} {
		r := standaloneCoverageReport(t, external)
		if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "exactly one validated incoming disagreement") {
			t.Fatalf("external=%v missing disagreement result = %v", external, err)
		}
	}
}

func TestReservedCoverageFindingRejectsMalformedStandaloneShapes(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Finding, *Report)
	}{
		{"category-with-other-rule", func(f *Finding, _ *Report) { f.Provenance.RuleID = "other/rule" }},
		{"rule-with-other-category", func(f *Finding, _ *Report) { f.Category = "other-category" }},
		{"critical", func(f *Finding, _ *Report) { f.Severity = SeverityCritical }},
		{"high", func(f *Finding, _ *Report) { f.Severity = SeverityHigh }},
		{"medium", func(f *Finding, _ *Report) { f.Severity = SeverityMedium }},
		{"low", func(f *Finding, _ *Report) { f.Severity = SeverityLow }},
		{"inference", func(f *Finding, r *Report) { f.Claim = ClaimInference; f.Related = []string{r.Operations[0].ID} }},
		{"runtime", func(f *Finding, _ *Report) { f.Scope = ScopeRuntime }},
		{"tooling", func(f *Finding, _ *Report) { f.Scope = ScopeTooling }},
		{"zero-evidence", func(f *Finding, _ *Report) { f.Evidence = nil }},
		{"multiple-evidence", func(f *Finding, _ *Report) { f.Evidence = append(f.Evidence, f.Evidence[0]) }},
		{"related-operation", func(f *Finding, r *Report) { f.Related = []string{r.Operations[0].ID} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := standaloneCoverageReport(t, true)
			test.mutate(coverageFinding(&r), &r)
			if err := r.BuildEvidenceGraph(); err != nil {
				t.Fatal(err)
			}
			if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
				t.Fatal(err)
			}
			if err := r.Validate(); err == nil {
				t.Fatal("malformed reserved coverage finding accepted")
			}
		})
	}
}

func TestReservedCoverageRelationshipRejectsMismatches(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Report)
	}{
		{"unrelated-evidence", func(r *Report) { coverageFinding(r).Evidence[0].Path = "unrelated.json" }},
		{"wrong-input", func(r *Report) { coverageFinding(r).Evidence[0].InputID = TargetEvidenceInputID }},
		{"wrong-source", func(r *Report) { coverageFinding(r).Provenance.EvidenceSource = EvidenceSourceTargetSource }},
		{"wrong-source-kind", func(r *Report) {
			rel := coverageRelationship(r)
			rel.FromKind = NodeFinding
			rel.ID = relationshipID(rel.Type, rel.FromKind, rel.From, rel.ToKind, rel.To)
		}},
		{"wrong-basis-kind", func(r *Report) { coverageRelationship(r).Comparison.Kind = "operation" }},
		{"wrong-subject", func(r *Report) { coverageRelationship(r).Comparison.Subject = "command\x00different" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := coverageComparisonReport(t, true)
			test.mutate(&r)
			if err := r.Validate(); err == nil {
				t.Fatal("mismatched coverage relationship accepted")
			}
		})
	}
}

func TestReservedCoverageFindingRejectsTwoIncomingDisagreements(t *testing.T) {
	r := coverageComparisonReport(t, true)
	source := r.Operations[len(r.Operations)-1]
	source.ID, source.Reference = "external-wget-duplicate", ""
	r.Operations = append(r.Operations, source)
	if err := r.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"external-wget", "external-wget-duplicate"} {
		if err := r.AddComparison(Comparison{Type: RelationshipDisagreesWith, FromKind: NodeOperation, FromID: id, ToKind: NodeFinding, ToID: "coverage-difference", Basis: ComparisonBasis{Kind: "coverage", Subject: "command\x00wget"}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "more than one incoming disagreement") {
		t.Fatalf("two incoming result = %v", err)
	}
}

func TestReservedCoverageFindingRejectsOppositeSourceMatch(t *testing.T) {
	r := coverageComparisonReport(t, true)
	r.Operations = append(r.Operations, Operation{ID: "local-wget", Category: "command", Command: "wget", Arguments: []string{}, Scope: ScopeRuntime, Confidence: ConfidenceHigh, Evidence: r.Operations[0].Evidence, Provenance: testProvenance})
	if err := r.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	var from, to string
	for _, op := range r.Operations {
		if op.ID == "external-wget" {
			from = op.Reference
		}
	}
	to = coverageFinding(&r).Reference
	rel := Relationship{Type: RelationshipDisagreesWith, FromKind: NodeOperation, From: from, ToKind: NodeFinding, To: to, Comparison: &ComparisonBasis{Kind: "coverage", Subject: "command\x00wget"}}
	rel.ID = relationshipID(rel.Type, rel.FromKind, rel.From, rel.ToKind, rel.To)
	r.Relationships = append(r.Relationships, rel)
	if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err == nil {
		t.Fatal("coverage difference with opposite-source exact match accepted")
	}
}

func TestReservedCoverageFindingRequiresExternalContext(t *testing.T) {
	r := standaloneCoverageReport(t, false)
	from, to := r.Operations[0].Reference, coverageFinding(&r).Reference
	rel := Relationship{Type: RelationshipDisagreesWith, FromKind: NodeOperation, From: from, ToKind: NodeFinding, To: to, Comparison: &ComparisonBasis{Kind: "coverage", Subject: "command\x00curl"}}
	rel.ID = relationshipID(rel.Type, rel.FromKind, rel.From, rel.ToKind, rel.To)
	r.Relationships = append(r.Relationships, rel)
	if err := r.Validate(); err == nil {
		t.Fatal("coverage disagreement without external comparison context accepted")
	}
}

func TestReservedCoverageDirectionsCanonicalRoundTrip(t *testing.T) {
	for _, external := range []bool{false, true} {
		r := coverageComparisonReport(t, external)
		if external {
			slices.Reverse(r.EvidenceInputs)
		}
		encoded, err := EncodeCanonical(r)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Decode(encoded)
		if err != nil {
			t.Fatal(err)
		}
		f := coverageFinding(&decoded)
		rel := coverageRelationship(&decoded)
		if f == nil || rel == nil {
			t.Fatal("coverage finding or relationship missing after round trip")
		}
		wantSource := EvidenceSourceTargetSource
		wantInput := TargetEvidenceInputID
		if external {
			wantSource = EvidenceSourceOmarchyAudit
			wantInput = "input-omarchy"
		}
		if f.Provenance.Analyzer != DeterministicAnalyzer || f.Provenance.AnalyzerVersion != decoded.Scan.ScannerVersion || f.Provenance.RuleID != CoverageComparisonRule || f.Provenance.EvidenceSource != wantSource || f.Category != CoverageDifferenceCategory || f.Claim != ClaimFact || f.Severity != SeverityInformational || f.Scope != ScopeUnknown || f.Evidence[0].InputID != wantInput {
			t.Fatalf("external=%v finding=%#v", external, *f)
		}
		if rel.Type != RelationshipDisagreesWith || rel.To != f.Reference || rel.Comparison == nil || rel.Comparison.Kind != "coverage" {
			t.Fatalf("external=%v relationship=%#v", external, *rel)
		}
		if rel.From == "" || rel.Comparison.Subject == "" {
			t.Fatalf("external=%v incomplete relationship=%#v", external, *rel)
		}
	}
}
