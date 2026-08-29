package report

import (
	"fmt"
	"strings"
	"testing"
)

func TestReviewSummarySeparatesImpactConfidenceCoverageUnknownsAndCounts(t *testing.T) {
	r := graphReport(t)
	r.Inventory = make([]File, 10)
	for index := range r.Inventory {
		r.Inventory[index] = File{Path: fmt.Sprintf("unit-%02d", index), Kind: "regular", Mode: "-rw-r--r--", Inspected: true, SHA256: strings.Repeat("a", 64), ContentType: "text/plain", Analysis: AnalysisAnalyzed}
	}
	r.Inventory[0].Path = "plugin.sh"
	r.Inventory[8].Analysis, r.Inventory[8].AnalysisReason = AnalysisPartial, "partial syntax support"
	r.Inventory[9].Inspected, r.Inventory[9].SHA256, r.Inventory[9].ContentType = false, "", ""
	r.Inventory[9].Analysis, r.Inventory[9].AnalysisReason = AnalysisUnanalyzed, "unsupported artifact"
	r.Target.FileCount = 10
	coverage := NewCoverageSummary(8, 1, 1)
	if err := r.BuildReviewSummary(coverage); err != nil {
		t.Fatal(err)
	}
	review := r.Review
	if review.SecurityImpact.Level != SeverityLow || len(review.SecurityImpact.Reasons) != 1 || review.SecurityImpact.Reasons[0].Reference != r.Findings[1].Reference {
		t.Fatalf("impact = %#v", review.SecurityImpact)
	}
	if review.EvidenceConfidence.Level != "medium" || review.EvidenceConfidence.High != 4 || review.EvidenceConfidence.Medium != 1 || review.EvidenceConfidence.Low != 0 {
		t.Fatalf("confidence = %#v", review.EvidenceConfidence)
	}
	if review.AnalysisCoverage.Level != "substantial" || review.AnalysisCoverage.Percentage == nil || *review.AnalysisCoverage.Percentage != 80 || review.AnalysisCoverage.TotalUnits != 10 {
		t.Fatalf("coverage = %#v", review.AnalysisCoverage)
	}
	if review.UnknownBehavior.Level != "high" || review.UnknownBehavior.Unknowns != 1 || len(review.UnknownBehavior.Reasons) != 1 || review.UnknownBehavior.Reasons[0].Reference != r.Unknowns[0].Reference {
		t.Fatalf("unknown behavior = %#v", review.UnknownBehavior)
	}
	if review.Counts != (ClaimCounts{Facts: 3, Inferences: 1, UnknownBehaviors: 1}) {
		t.Fatalf("counts = %#v", review.Counts)
	}
	if len(review.MainReasons) != 2 || review.MainReasons[0].Reference == "" || review.MainReasons[1].Reference == "" {
		t.Fatalf("main reasons = %#v", review.MainReasons)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("review summary rejected: %v", err)
	}
}

func TestCoveragePercentageRequiresExplicitNonzeroDenominator(t *testing.T) {
	empty := NewCoverageSummary(0, 0, 0)
	if empty.Level != "not-applicable" || empty.Percentage != nil || empty.Denominator != CoverageDenominator {
		t.Fatalf("empty coverage = %#v", empty)
	}
	partial := NewCoverageSummary(1, 1, 1)
	if partial.Percentage == nil || *partial.Percentage != 33 || partial.Level != "partial" {
		t.Fatalf("integer denominator coverage = %#v", partial)
	}
	forged := partial
	percentage := 34
	forged.Percentage = &percentage
	if err := validateCoverageSummary(forged); err == nil {
		t.Fatal("forged coverage percentage accepted")
	}
}

func TestValidateRejectsReviewSummaryThatDoesNotMatchEvidence(t *testing.T) {
	r := graphReport(t)
	if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
		t.Fatal(err)
	}
	r.Review.SecurityImpact.Level = SeverityCritical
	if err := r.Validate(); err == nil {
		t.Fatal("forged review impact accepted")
	}
}
