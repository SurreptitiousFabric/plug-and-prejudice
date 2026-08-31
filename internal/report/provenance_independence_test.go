package report

import (
	"strings"
	"testing"
)

func rawOmarchyProvenance() Provenance {
	return Provenance{RuleID: OmarchyAuditObservationRule, Analyzer: OmarchyAuditAnalyzer, AnalyzerVersion: OmarchyAuditInputVersion, EvidenceSource: EvidenceSourceOmarchyAudit}
}

func localExternalProvenance(rule, scannerVersion string) Provenance {
	return Provenance{RuleID: rule, Analyzer: DeterministicAnalyzer, AnalyzerVersion: scannerVersion, EvidenceSource: EvidenceSourceOmarchyAudit}
}

func reportWithRawOmarchyOperation(t *testing.T, provenance Provenance) Report {
	t.Helper()
	r := validReport()
	appendTestExternalInput(&r, "input-omarchy")
	r.Operations = append(r.Operations, Operation{ID: "external-curl", Category: "omarchy-audit-command", Command: "curl", Arguments: []string{}, Scope: ScopeUnknown, Confidence: ConfidenceHigh, Evidence: Evidence{InputID: "input-omarchy", Path: "audit.json"}, Provenance: provenance})
	if err := r.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRawOmarchyObservationRequiresExternalAssertingAnalyzer(t *testing.T) {
	valid := reportWithRawOmarchyOperation(t, rawOmarchyProvenance())
	if err := valid.Validate(); err != nil {
		t.Fatalf("raw Omarchy observation rejected: %v", err)
	}

	local := rawOmarchyProvenance()
	local.Analyzer, local.AnalyzerVersion = DeterministicAnalyzer, valid.Scan.ScannerVersion
	if err := reportWithRawOmarchyOperation(t, local).Validate(); err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("raw observation claiming local analyzer result = %v", err)
	}
}

func TestExternalBindingUnknownRequiresLocalAssertingAnalyzer(t *testing.T) {
	r := validReport()
	appendTestExternalInput(&r, "input-omarchy")
	if err := r.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("local binding assessment rejected: %v", err)
	}

	findBinding := func(value *Report) *Unknown {
		for i := range value.Unknowns {
			if value.Unknowns[i].Reason == UnknownExternalBinding {
				return &value.Unknowns[i]
			}
		}
		t.Fatal("binding unknown missing")
		return nil
	}
	external := r
	external.Unknowns = append([]Unknown(nil), r.Unknowns...)
	findBinding(&external).Provenance = rawOmarchyProvenance()
	if err := external.Validate(); err == nil {
		t.Fatal("binding assessment claiming Omarchy analyzer accepted")
	}

	wrongVersion := r
	wrongVersion.Unknowns = append([]Unknown(nil), r.Unknowns...)
	findBinding(&wrongVersion).Provenance.AnalyzerVersion = "wrong-scanner"
	if err := wrongVersion.Validate(); err == nil || !strings.Contains(err.Error(), "scanner version") {
		t.Fatalf("binding assessment with wrong scanner version result = %v", err)
	}
}

func TestCoverageDifferenceUsesLocalAnalyzerForBothEvidenceDirections(t *testing.T) {
	for _, externalOnly := range []bool{false, true} {
		r := coverageComparisonReport(t, externalOnly)
		if err := r.Validate(); err != nil {
			t.Fatalf("externalOnly=%v: %v", externalOnly, err)
		}
		var finding Finding
		for _, candidate := range r.Findings {
			if candidate.Category == CoverageDifferenceCategory {
				finding = candidate
			}
		}
		if finding.Provenance.Analyzer != DeterministicAnalyzer || finding.Provenance.AnalyzerVersion != r.Scan.ScannerVersion {
			t.Fatalf("externalOnly=%v provenance = %#v", externalOnly, finding.Provenance)
		}
		wantSource := EvidenceSourceTargetSource
		if externalOnly {
			wantSource = EvidenceSourceOmarchyAudit
		}
		if finding.Provenance.EvidenceSource != wantSource {
			t.Fatalf("externalOnly=%v source = %q", externalOnly, finding.Provenance.EvidenceSource)
		}
		if externalOnly {
			for i := range r.Findings {
				if r.Findings[i].Category == CoverageDifferenceCategory {
					r.Findings[i].Provenance.Analyzer, r.Findings[i].Provenance.AnalyzerVersion = OmarchyAuditAnalyzer, OmarchyAuditInputVersion
				}
			}
			if err := r.Validate(); err == nil {
				t.Fatal("external-only coverage finding copied source analyzer")
			}
		}
	}
}

func TestComparisonBudgetUnknownIsLocalExternalEvidenceConclusion(t *testing.T) {
	r := validReport()
	appendTestExternalInput(&r, "input-omarchy")
	r.Unknowns = append(r.Unknowns, Unknown{ID: "comparison-budget", Category: "comparison-budget", Reason: UnknownBudgetExhaustion, Scope: ScopeUnknown, Confidence: ConfidenceHigh, Title: "Comparison budget exhausted", Description: "Further external comparisons were not constructed.", Evidence: []Evidence{{InputID: "input-omarchy", Path: "audit.json"}}, Origins: []ValueOrigin{}, AffectedOperations: []string{}, SuppressedRules: []string{}, Provenance: localExternalProvenance(ComparisonBudgetRule, r.Scan.ScannerVersion)})
	if err := r.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("local comparison budget conclusion rejected: %v", err)
	}
}

func TestExternalDataCannotSelectLocalConclusionRule(t *testing.T) {
	provenance := localExternalProvenance("attacker-selected/rule", "test")
	r := reportWithRawOmarchyOperation(t, provenance)
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("attacker-selected local rule result = %v", err)
	}

	disguised := validReport()
	appendTestExternalInput(&disguised, "input-omarchy")
	disguised.Unknowns = append(disguised.Unknowns, Unknown{ID: "disguised-binding", Category: "attacker-category", Reason: UnknownDynamicValue, Scope: ScopeUnknown, Confidence: ConfidenceHigh, Title: "Attacker record", Description: "Attempts to select a trusted local rule.", Evidence: []Evidence{{InputID: "input-omarchy", Path: "audit.json"}}, Origins: []ValueOrigin{}, AffectedOperations: []string{}, SuppressedRules: []string{}, Provenance: localExternalProvenance(ExternalBindingAssessmentRule, disguised.Scan.ScannerVersion)})
	if err := disguised.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	if err := disguised.BuildReviewSummary(coverageFromInventory(disguised.Inventory)); err != nil {
		t.Fatal(err)
	}
	if err := disguised.Validate(); err == nil || !strings.Contains(err.Error(), "required binding shape") {
		t.Fatalf("external data impersonating binding assessment result = %v", err)
	}
}

func TestCanonicalRoundTripPreservesIndependentProvenanceFields(t *testing.T) {
	r := coverageComparisonReport(t, true)
	encoded, err := EncodeCanonical(r)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var got Finding
	for _, finding := range decoded.Findings {
		if finding.Category == CoverageDifferenceCategory {
			got = finding
		}
	}
	want := localExternalProvenance(CoverageComparisonRule, r.Scan.ScannerVersion)
	if got.Provenance != want || len(got.Evidence) != 1 || got.Evidence[0].InputID != "input-omarchy" {
		t.Fatalf("round-trip provenance/evidence = %#v / %#v", got.Provenance, got.Evidence)
	}
}
