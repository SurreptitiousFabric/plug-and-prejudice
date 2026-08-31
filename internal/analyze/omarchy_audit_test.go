package analyze

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/buildinfo"
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
	comparisons := IngestOmarchyAudit(audit, &result, "test")
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
		if operation.Category == "omarchy-audit-command" && (operation.Provenance.Analyzer != report.OmarchyAuditAnalyzer || operation.Provenance.AnalyzerVersion != report.OmarchyAuditInputVersion || operation.Provenance.EvidenceSource != report.EvidenceSourceOmarchyAudit) {
			t.Fatalf("external operation provenance = %#v", operation)
		}
	}
	for _, unknown := range result.Unknowns {
		if unknown.Reason == report.UnknownExternalBinding && (unknown.Provenance.Analyzer != report.DeterministicAnalyzer || unknown.Provenance.AnalyzerVersion != "test" || unknown.Provenance.RuleID != report.ExternalBindingAssessmentRule || unknown.Provenance.EvidenceSource != report.EvidenceSourceOmarchyAudit) {
			t.Fatalf("binding conclusion provenance = %#v", unknown.Provenance)
		}
	}
	for _, finding := range result.Findings {
		if finding.Category == report.CoverageDifferenceCategory && (finding.Provenance.Analyzer != report.DeterministicAnalyzer || finding.Provenance.AnalyzerVersion != "test" || finding.Provenance.RuleID != report.CoverageComparisonRule) {
			t.Fatalf("coverage conclusion provenance = %#v", finding.Provenance)
		}
	}
}

func TestOmarchyTypedResourceComparisonKeysDoNotAliasNULFields(t *testing.T) {
	localProvenance := sourceProvenance("test/v1")
	result := Result{Resources: []report.Resource{
		{ID: "local-a", Kind: "filesystem-path", Access: "read\x00special", Value: "x", Confidence: report.ConfidenceHigh, Evidence: report.Evidence{InputID: report.TargetEvidenceInputID, Path: "plugin.sh", Operation: "a"}, Provenance: localProvenance},
		{ID: "local-b", Kind: "filesystem-path", Access: "read", Value: "special\x00x", Confidence: report.ConfidenceHigh, Evidence: report.Evidence{InputID: report.TargetEvidenceInputID, Path: "plugin.sh", Operation: "b"}, Provenance: localProvenance},
	}}
	audit := emptyAudit()
	audit.Observed.Reads = []omarchyaudit.Path{{Path: "special\x00x"}}
	comparisons := IngestOmarchyAudit(audit, &result, "test")
	corroboratedB, disagreedA := false, false
	for _, comparison := range comparisons {
		if comparison.Type == report.RelationshipCorroborates && comparison.FromID == "local-b" {
			corroboratedB = true
		}
		if comparison.Type == report.RelationshipDisagreesWith && comparison.FromID == "local-a" {
			disagreedA = true
		}
		if comparison.Type == report.RelationshipCorroborates && comparison.FromID == "local-a" {
			t.Fatal("colliding but distinct resource was falsely corroborated")
		}
	}
	if !corroboratedB || !disagreedA {
		t.Fatalf("typed comparisons = %#v", comparisons)
	}
	if operationComparisonKey("/usr/bin/curl") == resourceComparisonKey("operation", "", "curl") {
		t.Fatal("operation and resource keys aliased")
	}
}

func TestOmarchyComparisonKeyDeclarationOrderIsIrrelevant(t *testing.T) {
	first := map[omarchyComparisonKey]comparableNode{
		resourceComparisonKey("filesystem-path", "read", "a\x00b"): {},
		resourceComparisonKey("filesystem-path", "read\x00a", "b"): {},
		operationComparisonKey("curl"):                             {},
	}
	second := make(map[omarchyComparisonKey]comparableNode)
	second[operationComparisonKey("curl")] = comparableNode{}
	second[resourceComparisonKey("filesystem-path", "read\x00a", "b")] = comparableNode{}
	second[resourceComparisonKey("filesystem-path", "read", "a\x00b")] = comparableNode{}
	if got, want := unionSortedKeys(first, nil), unionSortedKeys(second, nil); !reflect.DeepEqual(got, want) {
		t.Fatalf("key order differs: %#v %#v", got, want)
	}
}

func TestOmarchyIngestionProducesCurrentValidatedContract(t *testing.T) {
	scannerVersion := buildinfo.Version
	source := []byte("#!/bin/sh\ncurl https://local.example.test\n")
	result := Sources(map[string][]byte{"plugin.sh": source})
	audit := emptyAudit()
	audit.Observed.Commands = []omarchyaudit.Command{{Name: "curl"}}
	audit.Observed.Network = []omarchyaudit.Host{{Host: "external.example.test"}}
	comparisons := IngestOmarchyAudit(audit, &result, scannerVersion)
	provenanceByID := make(map[string]report.EvidenceSource)
	for _, operation := range result.Operations {
		provenanceByID[operation.ID] = operation.Provenance.EvidenceSource
	}
	for _, resource := range result.Resources {
		provenanceByID[resource.ID] = resource.Provenance.EvidenceSource
	}
	localOnly, externalOnly := false, false
	for _, comparison := range comparisons {
		if comparison.Type != report.RelationshipDisagreesWith {
			continue
		}
		switch provenanceByID[comparison.FromID] {
		case report.EvidenceSourceOmarchyAudit:
			externalOnly = true
		case report.EvidenceSourceTargetSource, report.EvidenceSourceInventoryMetadata:
			localOnly = true
		}
	}
	if !localOnly || !externalOnly {
		t.Fatalf("missing coverage direction: local=%v external=%v comparisons=%#v", localOnly, externalOnly, comparisons)
	}

	inventory := []report.File{{Path: "plugin.sh", Kind: "regular", Mode: "-rw-r--r--", Size: int64(len(source)), SHA256: strings.Repeat("a", 64), ContentType: "text/x-shellscript", Inspected: true, Analysis: report.AnalysisAnalyzed}}
	digest, err := report.InventoryRootDigest(inventory)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	r := report.Report{SchemaVersion: report.SchemaVersion, Status: report.StatusIncomplete,
		Scan:   report.ScanMetadata{ScannerVersion: scannerVersion, PolicyVersion: "test", StartedAt: now, CompletedAt: now, Sandboxed: true, ResourceLimits: &report.ResourceLimits{MemoryMaxBytes: 1, TasksMax: 1, CPUQuotaPercent: 1, WallTimeSeconds: 1}},
		Target: report.Target{DisplayName: "example", RootDigest: digest, FileCount: 1, ReadBytes: int64(len(source))},
		EvidenceInputs: []report.EvidenceInput{
			{ID: report.TargetEvidenceInputID, Type: report.EvidenceInputTarget, Label: "target", SubjectRootDigest: digest, Format: report.TargetEvidenceInputFormat, Version: report.TargetEvidenceInputVersion},
			report.NewOmarchyAuditEvidenceInput(OmarchyAuditEvidenceInputID, "audit", []byte("pinned audit bytes")),
		}, Inventory: inventory, Operations: result.Operations, Resources: result.Resources, Findings: result.Findings, Unknowns: result.Unknowns,
		Relationships: []report.Relationship{}, Limitations: result.Limitations, Errors: []report.ScanError{}}
	if err := r.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	for _, comparison := range comparisons {
		if err := r.AddComparison(comparison); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.BuildReviewSummary(report.NewCoverageSummary(1, 0, 0)); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("current contract rejected integrated report: %v", err)
	}
	encoded, err := report.EncodeCanonical(r)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := report.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Status != report.StatusIncomplete {
		t.Fatalf("current Omarchy input status = %q", decoded.Status)
	}
	var externalInput report.EvidenceInput
	for _, input := range decoded.EvidenceInputs {
		if input.ID == OmarchyAuditEvidenceInputID {
			externalInput = input
		}
	}
	if externalInput.SubjectRootDigest != "" || externalInput.DocumentSHA256 == "" {
		t.Fatalf("external input binding = %#v", externalInput)
	}
}

func emptyAudit() omarchyaudit.Report {
	return omarchyaudit.Report{ID: "example.plugin", Declared: omarchyaudit.Declared{Commands: []string{}, Network: []string{}, Reads: []string{}, Writes: []string{}}, Observed: omarchyaudit.Observed{Commands: []omarchyaudit.Command{}, Network: []omarchyaudit.Host{}, Reads: []omarchyaudit.Path{}, Writes: []omarchyaudit.Path{}}, Risks: []omarchyaudit.Risk{}, Verdict: omarchyaudit.Verdict{Reasons: []string{}}}
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
	_ = IngestOmarchyAudit(audit, &exact, "test")
	if hasLimitationCode(exact, "omarchy-audit-comparison-budget") {
		t.Fatal("exact comparison limit rejected")
	}
	over := makeResult(maxOmarchyAuditComparisons + 1)
	_ = IngestOmarchyAudit(audit, &over, "test")
	if !hasLimitationCode(over, "omarchy-audit-comparison-budget") {
		t.Fatalf("first-over comparison limit not reported: %#v", over.Limitations)
	}
	for _, unknown := range over.Unknowns {
		if unknown.Provenance.RuleID == report.ComparisonBudgetRule && (unknown.Provenance.Analyzer != report.DeterministicAnalyzer || unknown.Provenance.AnalyzerVersion != "test" || unknown.Provenance.EvidenceSource != report.EvidenceSourceOmarchyAudit) {
			t.Fatalf("comparison-budget conclusion provenance = %#v", unknown.Provenance)
		}
	}
}

func TestOmarchyDynamicObservationDoesNotBecomeIndependentCapability(t *testing.T) {
	result := Result{}
	audit := omarchyaudit.Report{ID: "example.plugin", Declared: omarchyaudit.Declared{Commands: []string{}, Network: []string{}, Reads: []string{}, Writes: []string{}}, Observed: omarchyaudit.Observed{Commands: []omarchyaudit.Command{}, Network: []omarchyaudit.Host{{Host: "(dynamic)"}}, Reads: []omarchyaudit.Path{}, Writes: []omarchyaudit.Path{}}, Risks: []omarchyaudit.Risk{}, Verdict: omarchyaudit.Verdict{Reasons: []string{}}}
	_ = IngestOmarchyAudit(audit, &result, "test")
	if len(result.Resources) != 1 || !result.Resources[0].Dynamic || result.Resources[0].Confidence != report.ConfidenceMedium || result.Resources[0].Provenance.EvidenceSource != report.EvidenceSourceOmarchyAudit {
		t.Fatalf("dynamic external resource = %#v", result.Resources)
	}
}
