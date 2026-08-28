package analyze

import (
	"fmt"
	"sort"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func Inventory(files []report.File, contents map[string][]byte, result *Result) {
	ordered := append([]report.File(nil), files...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
	for _, file := range ordered {
		if file.Binary == nil {
			continue
		}
		result.Findings = append(result.Findings, report.Finding{
			ID:    "finding-native-binary-" + stablePathID(file.Path),
			Claim: report.ClaimUnknown, Severity: report.SeverityMedium, Confidence: report.ConfidenceHigh,
			Category: "native-binary", Title: "Bundles native executable code whose behavior is not established",
			Explanation: fmt.Sprintf("This %s %s ELF file is identified and hashed, but headers and imported libraries cannot establish what it will do when run. Manual source-to-binary provenance or deeper independent analysis is required.", file.Binary.Class, file.Binary.Machine),
			Evidence:    []report.Evidence{{Path: file.Path, Operation: "sha256:" + file.SHA256}},
			Provenance:  sourceProvenance("elf-metadata/v1"),
		})
		result.Limitations = append(result.Limitations, report.Limitation{
			Code: "native-binary-behavior", Description: "ELF metadata was inspected, but executable behavior and source provenance remain unknown.", Path: file.Path,
		})
	}
	annotateScopes(contents, files, result)
}
