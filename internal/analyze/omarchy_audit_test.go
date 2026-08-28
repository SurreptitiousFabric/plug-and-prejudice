package analyze

import (
	"fmt"
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/omarchyaudit"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func TestOmarchyAuditIngestionSeparatesProvenanceAgreementAndDifferences(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{"plugin.sh": []byte("#!/bin/sh\ncurl https://same.example.test\ncat ~/.ssh/config\n")}))
	audit := omarchyaudit.Report{
		ID: "example.plugin", Declared: omarchyaudit.Declared{Commands: []string{}, Network: []string{}, Reads: []string{}, Writes: []string{}},
		Observed: omarchyaudit.Observed{Commands: []omarchyaudit.Command{{Name: "curl"}}, Network: []omarchyaudit.Host{{Host: "same.example.test"}, {Host: "only-omarchy.example.test"}}, Reads: []omarchyaudit.Path{}, Writes: []omarchyaudit.Path{}},
		Risks:    []omarchyaudit.Risk{{Severity: "medium", Kind: "dynamic-command", Detail: "command may be selected dynamically"}}, Verdict: omarchyaudit.Verdict{Level: "moderate", Reasons: []string{}},
	}
	comparisons := IngestOmarchyAudit(audit, &result)
	hasCorroboration, hasDisagreement := false, false
	for _, comparison := range comparisons {
		if comparison.Type == report.RelationshipCorroborates {
			hasCorroboration = true
		}
		if comparison.Type == report.RelationshipDisagreesWith {
			hasDisagreement = true
		}
	}
	if !hasCorroboration || !hasDisagreement {
		t.Fatalf("comparisons = %#v", comparisons)
	}
	if !hasFindingCategory(result, "omarchy-audit-coverage-disagreement") || !hasFindingCategory(result, "omarchy-audit-risk-dynamic-command") {
		t.Fatalf("imported findings = %#v", result.Findings)
	}
	for _, operation := range result.Operations {
		if operation.Category == "omarchy-audit-command" && operation.Provenance.EvidenceSource != report.EvidenceSourceOmarchyAudit {
			t.Fatalf("external operation provenance = %#v", operation)
		}
	}
}

func TestOmarchyComparisonBudgetExactAndFirstOver(t *testing.T) {
	makeResult := func(count int) Result {
		result := Result{}
		for index := 0; index < count; index++ {
			result.Operations = append(result.Operations, report.Operation{ID: fmt.Sprintf("own-%d", index), Category: "process-execution", Command: fmt.Sprintf("command-%d", index), Scope: report.ScopeUnknown, Confidence: report.ConfidenceHigh, Evidence: report.Evidence{Path: "plugin.sh", Operation: "command"}, Provenance: sourceProvenance("test/v1")})
		}
		return result
	}
	audit := omarchyaudit.Report{ID: "example.plugin", Declared: omarchyaudit.Declared{Commands: []string{}, Network: []string{}, Reads: []string{}, Writes: []string{}}, Observed: omarchyaudit.Observed{Commands: []omarchyaudit.Command{}, Network: []omarchyaudit.Host{}, Reads: []omarchyaudit.Path{}, Writes: []omarchyaudit.Path{}}, Risks: []omarchyaudit.Risk{}, Verdict: omarchyaudit.Verdict{Reasons: []string{}}}
	exact := makeResult(maxOmarchyAuditComparisons)
	_ = IngestOmarchyAudit(audit, &exact)
	if hasLimitationCode(exact, "omarchy-audit-comparison-budget") {
		t.Fatal("exact comparison limit rejected")
	}
	over := makeResult(maxOmarchyAuditComparisons + 1)
	_ = IngestOmarchyAudit(audit, &over)
	if !hasLimitationCode(over, "omarchy-audit-comparison-budget") {
		t.Fatalf("first-over comparison limit not reported: %#v", over.Limitations)
	}
}

func TestOmarchyDynamicObservationDoesNotBecomeIndependentCapability(t *testing.T) {
	result := Result{}
	audit := omarchyaudit.Report{ID: "example.plugin", Declared: omarchyaudit.Declared{Commands: []string{}, Network: []string{}, Reads: []string{}, Writes: []string{}}, Observed: omarchyaudit.Observed{Commands: []omarchyaudit.Command{}, Network: []omarchyaudit.Host{{Host: "(dynamic)"}}, Reads: []omarchyaudit.Path{}, Writes: []omarchyaudit.Path{}}, Risks: []omarchyaudit.Risk{}, Verdict: omarchyaudit.Verdict{Reasons: []string{}}}
	_ = IngestOmarchyAudit(audit, &result)
	if len(result.Resources) != 1 || !result.Resources[0].Dynamic || result.Resources[0].Confidence != report.ConfidenceMedium || result.Resources[0].Provenance.EvidenceSource != report.EvidenceSourceOmarchyAudit {
		t.Fatalf("dynamic external resource = %#v", result.Resources)
	}
}
