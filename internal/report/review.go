package report

import (
	"errors"
	"reflect"
	"strings"
)

const maxReviewReasons = 8

func (r *Report) BuildReviewSummary(coverage CoverageSummary) error {
	if r == nil {
		return errors.New("cannot build review summary for nil report")
	}
	if err := validateCoverageSummary(coverage); err != nil {
		return err
	}
	value := deriveReviewSummary(*r, coverage)
	r.Review = &value
	return nil
}

func deriveReviewSummary(r Report, coverage CoverageSummary) ReviewSummary {
	value := ReviewSummary{AnalysisCoverage: coverage, MainReasons: []ReviewReason{}}
	value.SecurityImpact = ImpactSummary{Level: SeverityInformational, Reasons: []ReviewReason{}}
	value.EvidenceConfidence = ConfidenceSummary{Level: "not-applicable", Reasons: []ReviewReason{}}
	value.UnknownBehavior = UnknownSummary{Level: "none", Unknowns: len(r.Unknowns), Limitations: len(r.Limitations), Errors: len(r.Errors), Reasons: []ReviewReason{}}
	for _, operation := range r.Operations {
		value.Counts.Facts++
		addConfidence(&value.EvidenceConfidence, operation.Confidence)
	}
	for _, resource := range r.Resources {
		value.Counts.Facts++
		addConfidence(&value.EvidenceConfidence, resource.Confidence)
	}
	impactRank := -1
	for _, finding := range r.Findings {
		addConfidence(&value.EvidenceConfidence, finding.Confidence)
		switch finding.Claim {
		case ClaimFact:
			value.Counts.Facts++
		case ClaimInference:
			value.Counts.Inferences++
		case ClaimUnknown:
			value.Counts.UnknownBehaviors++
			continue
		}
		rank := severityRank(finding.Severity)
		if rank > impactRank {
			impactRank = rank
			value.SecurityImpact.Level = finding.Severity
			value.SecurityImpact.Reasons = []ReviewReason{}
		}
		if rank == impactRank && len(value.SecurityImpact.Reasons) < maxReviewReasons {
			value.SecurityImpact.Reasons = append(value.SecurityImpact.Reasons, ReviewReason{Reference: finding.Reference, Title: finding.Title, Scope: finding.Scope})
		}
	}
	for _, unknown := range r.Unknowns {
		value.Counts.UnknownBehaviors++
		addConfidence(&value.EvidenceConfidence, unknown.Confidence)
	}
	if len(value.SecurityImpact.Reasons) > 0 {
		value.EvidenceConfidence.Level = confidenceForImpactReasons(r.Findings, value.SecurityImpact.Level)
		value.EvidenceConfidence.Reasons = append([]ReviewReason(nil), value.SecurityImpact.Reasons...)
	}
	value.UnknownBehavior.Level = unknownLevel(r)
	for _, scanError := range r.Errors {
		appendReviewReason(&value.UnknownBehavior.Reasons, ReviewReason{Title: "Scan error: " + scanError.Code})
	}
	for _, unknown := range r.Unknowns {
		if unknown.Reason == UnknownBudgetExhaustion || unknown.Reason == UnknownParserFailure || (unknown.Scope == ScopeRuntime && len(unknown.AffectedOperations) > 0) {
			appendReviewReason(&value.UnknownBehavior.Reasons, ReviewReason{Reference: unknown.Reference, Title: unknown.Title, Scope: unknown.Scope})
		}
	}
	for _, unknown := range r.Unknowns {
		appendReviewReason(&value.UnknownBehavior.Reasons, ReviewReason{Reference: unknown.Reference, Title: unknown.Title, Scope: unknown.Scope})
	}
	for _, limitation := range r.Limitations {
		if limitation.Scope == ScopeRuntime {
			appendReviewReason(&value.UnknownBehavior.Reasons, ReviewReason{Title: "Analysis limitation: " + limitation.Code, Scope: limitation.Scope})
		}
	}
	for _, limitation := range r.Limitations {
		appendReviewReason(&value.UnknownBehavior.Reasons, ReviewReason{Title: "Analysis limitation: " + limitation.Code, Scope: limitation.Scope})
	}
	value.MainReasons = append(value.MainReasons, value.SecurityImpact.Reasons...)
	for _, reason := range value.UnknownBehavior.Reasons {
		if len(value.MainReasons) >= maxReviewReasons {
			break
		}
		if !containsReason(value.MainReasons, reason.Reference) {
			value.MainReasons = append(value.MainReasons, reason)
		}
	}
	return value
}

func addConfidence(summary *ConfidenceSummary, value Confidence) {
	switch value {
	case ConfidenceHigh:
		summary.High++
	case ConfidenceMedium:
		summary.Medium++
	case ConfidenceLow:
		summary.Low++
	}
}
func confidenceForImpactReasons(findings []Finding, severity Severity) string {
	level := "high"
	for _, finding := range findings {
		if finding.Claim == ClaimUnknown || finding.Severity != severity {
			continue
		}
		if finding.Confidence == ConfidenceLow {
			return "low"
		}
		if finding.Confidence == ConfidenceMedium {
			level = "medium"
		}
	}
	return level
}
func severityRank(value Severity) int {
	switch value {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	case SeverityInformational:
		return 0
	}
	return -1
}
func unknownLevel(r Report) string {
	if len(r.Errors) > 0 {
		return "high"
	}
	level := "none"
	for _, unknown := range r.Unknowns {
		if unknown.Reason == UnknownBudgetExhaustion || unknown.Reason == UnknownParserFailure || (unknown.Scope == ScopeRuntime && len(unknown.AffectedOperations) > 0) {
			return "high"
		}
		if unknown.Scope == ScopeRuntime {
			level = "moderate"
		} else if level == "none" {
			level = "low"
		}
	}
	for _, limitation := range r.Limitations {
		if strings.Contains(limitation.Code, "budget") || strings.HasPrefix(limitation.Code, "max-") || limitation.Code == "result-production-limit" {
			return "high"
		}
		if limitation.Scope == ScopeRuntime {
			if level != "high" {
				level = "moderate"
			}
		} else if level == "none" {
			level = "low"
		}
	}
	return level
}
func containsReason(values []ReviewReason, reference string) bool {
	for _, value := range values {
		if reference != "" && value.Reference == reference {
			return true
		}
	}
	return false
}

func appendReviewReason(values *[]ReviewReason, reason ReviewReason) {
	if len(*values) >= maxReviewReasons {
		return
	}
	for _, existing := range *values {
		if reason.Reference != "" && existing.Reference == reason.Reference || reason.Reference == "" && existing.Reference == "" && existing.Title == reason.Title {
			return
		}
	}
	*values = append(*values, reason)
}

func validateReviewSummary(r Report) error {
	if r.Review == nil {
		return errors.New("review summary is required")
	}
	if err := validateCoverageSummary(r.Review.AnalysisCoverage); err != nil {
		return err
	}
	expected := deriveReviewSummary(r, r.Review.AnalysisCoverage)
	if !reflect.DeepEqual(*r.Review, expected) {
		return errors.New("review summary does not match retained report evidence")
	}
	return nil
}

func validateCoverageSummary(value CoverageSummary) error {
	if value.Denominator != CoverageDenominator || value.AnalyzedUnits < 0 || value.PartialUnits < 0 || value.UnanalyzedUnits < 0 || value.TotalUnits < 0 || value.AnalyzedUnits+value.PartialUnits+value.UnanalyzedUnits != value.TotalUnits {
		return errors.New("analysis coverage has an invalid denominator or unit counts")
	}
	if value.AnalyzedUnits > MaxInventoryEntries || value.PartialUnits > MaxInventoryEntries || value.UnanalyzedUnits > MaxInventoryEntries || value.TotalUnits > MaxInventoryEntries {
		return errors.New("analysis coverage unit counts exceed inventory limits")
	}
	level := "not-applicable"
	if value.TotalUnits == 0 {
		if value.Percentage != nil {
			return errors.New("analysis coverage percentage requires a nonzero denominator")
		}
	} else {
		percentage := value.AnalyzedUnits * 100 / value.TotalUnits
		if value.Percentage == nil || *value.Percentage != percentage {
			return errors.New("analysis coverage percentage does not match its explicit denominator")
		}
		if value.AnalyzedUnits == value.TotalUnits {
			level = "complete"
		} else if percentage >= 80 {
			level = "substantial"
		} else if percentage > 0 {
			level = "partial"
		} else {
			level = "limited"
		}
	}
	if value.Level != level {
		return errors.New("analysis coverage level does not match unit counts")
	}
	return nil
}

func NewCoverageSummary(analyzed, partial, unanalyzed int) CoverageSummary {
	value := CoverageSummary{Denominator: CoverageDenominator, AnalyzedUnits: analyzed, PartialUnits: partial, UnanalyzedUnits: unanalyzed, TotalUnits: analyzed + partial + unanalyzed}
	if value.TotalUnits == 0 {
		value.Level = "not-applicable"
		return value
	}
	percentage := analyzed * 100 / value.TotalUnits
	value.Percentage = &percentage
	if analyzed == value.TotalUnits {
		value.Level = "complete"
	} else if percentage >= 80 {
		value.Level = "substantial"
	} else if percentage > 0 {
		value.Level = "partial"
	} else {
		value.Level = "limited"
	}
	return value
}
