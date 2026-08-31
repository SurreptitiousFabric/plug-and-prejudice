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
		result.Unknowns = append(result.Unknowns, report.Unknown{
			ID: "unknown-native-binary-" + stablePathID(file.Path), Reason: report.UnknownNativeBehavior,
			Scope: report.ScopeUnknown, Confidence: report.ConfidenceHigh, Category: "native-binary",
			Title:       "Bundled native executable behavior is not established",
			Description: fmt.Sprintf("This %s %s ELF file is identified and hashed, but headers and imported libraries cannot establish what it will do when run. Manual source-to-binary provenance or deeper independent analysis is required.", file.Binary.Class, file.Binary.Machine),
			Evidence:    []report.Evidence{{Path: file.Path, Operation: "sha256:" + file.SHA256}}, Origins: []report.ValueOrigin{}, AffectedOperations: []string{}, SuppressedRules: []string{},
			Provenance: sourceProvenance("elf-metadata/v1"),
		})
		result.Limitations = append(result.Limitations, report.Limitation{
			Code: "native-binary-behavior", Description: "ELF metadata was inspected, but executable behavior and source provenance remain unknown.", Path: file.Path,
		})
	}
	annotateScopes(contents, files, result)
}
