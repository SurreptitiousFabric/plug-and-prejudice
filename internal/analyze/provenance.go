package analyze

import "github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"

const deterministicAnalyzer = "plug-prejudice/deterministic"

func sourceProvenance(ruleID string) report.Provenance {
	return report.Provenance{
		RuleID:          ruleID,
		Analyzer:        deterministicAnalyzer,
		AnalyzerVersion: "development",
		EvidenceSource:  report.EvidenceSourceTargetSource,
	}
}

func inventoryProvenance(ruleID string) report.Provenance {
	value := sourceProvenance(ruleID)
	value.EvidenceSource = report.EvidenceSourceInventoryMetadata
	return value
}
