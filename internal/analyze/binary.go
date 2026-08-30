package analyze

import (
	"fmt"
	"sort"
	"strings"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func Inventory(files []report.File, contents map[string][]byte, result *Result) {
	ordered := append([]report.File(nil), files...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
	for _, file := range ordered {
		if file.Kind == "symlink" && !isGitMetadataPath(file.Path) {
			appendFinding(result, report.Finding{
				ID: "finding-plugin-symlink-" + stablePathID(file.Path), Claim: report.ClaimFact,
				Severity: report.SeverityMedium, Confidence: report.ConfidenceHigh,
				Category: "manifest", Title: "Plugin contains a symbolic link rejected by Omarchy installation policy",
				Explanation: "The official plugin validator rejects symbolic links outside .git because an installed link could refer to files beyond the plugin directory. The scanner inventoried this link but did not follow or read its target.",
				Evidence:    []report.Evidence{{Path: file.Path, Operation: "symbolic link -> " + file.LinkTarget}}, Provenance: inventoryProvenance("inventory-symlink/v1"),
			})
		}
		if file.Archive != nil {
			analyzeArchiveInventory(file, result)
		}
		if file.Binary != nil {
			analyzeELFInventory(file, result)
			result.Limitations = append(result.Limitations, report.Limitation{
				Code: "native-binary-behavior", Description: "ELF metadata was inspected, but executable behavior and source provenance remain unknown.", Path: file.Path,
			})
		}
	}
	annotateScopes(contents, files, result)
}

func analyzeELFInventory(file report.File, result *Result) {
	binary := file.Binary
	baseEvidence := report.Evidence{Path: file.Path, Operation: "ELF metadata; sha256:" + file.SHA256}
	appendFinding(result, report.Finding{
		ID: "finding-native-binary-metadata-" + stablePathID(file.Path), Claim: report.ClaimFact,
		Severity: report.SeverityInformational, Confidence: report.ConfidenceHigh, Category: "native-binary-metadata",
		Title:       "Inventories native executable metadata without running it",
		Explanation: fmt.Sprintf("The scanner identified a %s %s ELF file and retained bounded static metadata. Imports and strings indicate binary contents, not that any behavior occurred.", binary.Class, binary.Machine),
		Evidence:    []report.Evidence{baseEvidence}, Provenance: inventoryProvenance("elf-static-metadata/v1"),
	})
	if binary.SetUID || binary.SetGID || len(binary.FileCapabilities) > 0 {
		details := fmt.Sprintf("setuid=%t; setgid=%t; file capabilities=%v; effective capability flag=%t", binary.SetUID, binary.SetGID, binary.FileCapabilities, binary.CapabilityEffective)
		appendFinding(result, report.Finding{
			ID: "finding-native-privilege-metadata-" + stablePathID(file.Path), Claim: report.ClaimFact,
			Severity: report.SeverityHigh, Confidence: report.ConfidenceHigh, Category: "native-privilege-metadata",
			Title:       "Native file carries privilege-related installation metadata",
			Explanation: "The file mode or Linux security.capability attribute grants privilege-related execution metadata. Whether it is preserved during installation depends on the packaging and installer path.",
			Evidence:    []report.Evidence{{Path: file.Path, Operation: details}}, Provenance: inventoryProvenance("elf-privilege-metadata/v1"),
		})
	}
	interestingImports := relevantNativeImports(binary.ImportedSymbols)
	if len(interestingImports) > 0 {
		evidence := make([]report.Evidence, 0, min(len(interestingImports), report.MaxFindingEvidence))
		for _, value := range interestingImports {
			if len(evidence) == report.MaxFindingEvidence {
				break
			}
			evidence = append(evidence, report.Evidence{Path: file.Path, Operation: "undefined imported symbol: " + value})
		}
		appendFinding(result, report.Finding{
			ID: "finding-native-sensitive-imports-" + stablePathID(file.Path), Claim: report.ClaimFact,
			Severity: report.SeverityInformational, Confidence: report.ConfidenceHigh, Category: "native-sensitive-imports",
			Title:       "Native file imports security-relevant functions",
			Explanation: "The ELF dynamic symbol table declares these undefined imports. An import does not prove that reachable code calls it or establish runtime arguments.",
			Evidence:    evidence, Provenance: inventoryProvenance("elf-sensitive-imports/v1"),
		})
	}
	if len(binary.EmbeddedURLs) > 0 {
		evidence := make([]report.Evidence, 0, min(len(binary.EmbeddedURLs), report.MaxFindingEvidence))
		for _, value := range binary.EmbeddedURLs {
			if len(evidence) == report.MaxFindingEvidence {
				break
			}
			evidence = append(evidence, report.Evidence{Path: file.Path, Operation: "embedded URL string: " + value})
		}
		appendFinding(result, report.Finding{
			ID: "finding-native-url-strings-" + stablePathID(file.Path), Claim: report.ClaimFact,
			Severity: report.SeverityInformational, Confidence: report.ConfidenceHigh, Category: "native-url-strings",
			Title:       "Native file contains embedded URL strings",
			Explanation: "These literal strings were found in the ELF bytes. Their presence does not establish network access or that executable code references them.",
			Evidence:    evidence, Provenance: inventoryProvenance("elf-url-strings/v1"),
		})
	}
	appendUnknown(result, report.Unknown{
		ID: "unknown-native-binary-" + stablePathID(file.Path), Category: "native-binary", Reason: report.UnknownNativeBehavior,
		Scope: report.ScopeUnknown, Confidence: report.ConfidenceHigh, Title: "Native executable behavior is not established",
		Description: "ELF headers, imports, capabilities, privilege bits, bounded strings, and embedded URLs cannot establish control flow, runtime arguments, side effects, or source-to-binary provenance.",
		Evidence:    []report.Evidence{baseEvidence}, Origins: []report.ValueOrigin{}, AffectedOperations: []string{},
		SuppressedRules: []string{"native-control-flow/v1", "operation-correlation/v1"}, Provenance: inventoryProvenance("elf-behavior-unknown/v2"),
	})
}

func relevantNativeImports(values []string) []string {
	result := make([]string, 0)
	for _, value := range values {
		name := strings.SplitN(value, "@", 2)[0]
		if strings.HasPrefix(name, "exec") || strings.HasPrefix(name, "posix_spawn") || strings.HasPrefix(name, "send") ||
			name == "system" || name == "dlopen" || name == "connect" || name == "ptrace" || name == "capset" ||
			strings.HasPrefix(name, "setuid") || strings.HasPrefix(name, "setgid") || strings.HasPrefix(name, "setresuid") || strings.HasPrefix(name, "setresgid") {
			result = append(result, value)
		}
	}
	return result
}

func analyzeArchiveInventory(file report.File, result *Result) {
	archive := file.Archive
	if archive == nil {
		return
	}
	status := "complete"
	if !archive.InventoryComplete {
		status = "partial"
	}
	evidence := report.Evidence{Path: file.Path, Operation: fmt.Sprintf("%s archive; %d retained entries; %s metadata inventory; sha256:%s", archive.Format, len(archive.Entries), status, file.SHA256)}
	appendFinding(result, report.Finding{
		ID: "finding-archive-inventory-" + stablePathID(file.Path), Claim: report.ClaimFact, Severity: report.SeverityInformational, Confidence: report.ConfidenceHigh,
		Category: "archive-inventory", Title: "Inventories a bundled archive without extracting it",
		Explanation: "The scanner identified the archive and retained bounded member metadata without writing or extracting payloads. Member bytes and executable behavior were not semantically analyzed.",
		Evidence:    []report.Evidence{evidence}, Provenance: inventoryProvenance("archive-metadata/v1"),
	})
	unsafeEvidence := make([]report.Evidence, 0, report.MaxFindingEvidence)
	unsafeCount := 0
	for _, entry := range archive.Entries {
		if !entry.UnsafePath && entry.Kind != "symlink" && entry.Kind != "hardlink" {
			continue
		}
		unsafeCount++
		if len(unsafeEvidence) < report.MaxFindingEvidence {
			operation, _ := boundedEncodedString("archive member: " + entry.Path + " -> " + entry.LinkTarget)
			unsafeEvidence = append(unsafeEvidence, report.Evidence{Path: file.Path, Operation: operation})
		}
	}
	if unsafeCount > 0 {
		appendFinding(result, report.Finding{
			ID: "finding-archive-unsafe-path-" + stablePathID(file.Path), Claim: report.ClaimFact, Severity: report.SeverityMedium, Confidence: report.ConfidenceHigh,
			Category: "archive-path-risk", Title: "Archive contains traversal or link-style members",
			Explanation: fmt.Sprintf("The retained archive metadata contains %d path-traversal, absolute/backslash, symbolic-link, or hard-link member(s). The scanner did not extract them; risk depends on whether a later consumer validates extraction paths and link targets.", unsafeCount),
			Evidence:    unsafeEvidence, Provenance: inventoryProvenance("archive-path-risk/v1"),
		})
	}
	appendUnknown(result, report.Unknown{
		ID: "unknown-archive-payload-" + stablePathID(file.Path), Category: "archive-payload", Reason: report.UnknownUnreachableSource,
		Scope: report.ScopeUnknown, Confidence: report.ConfidenceHigh, Title: "Archive payload behavior was not semantically analyzed",
		Description: "Member metadata was retained where safely available, but payload bytes were not extracted, imported, executed, or passed to language analyzers. Nested archives and compressed member behavior therefore remain unknown.",
		Evidence:    []report.Evidence{evidence}, Origins: []report.ValueOrigin{}, AffectedOperations: []string{},
		SuppressedRules: []string{"archive-payload-analysis/v1", "command-capability/v1", "operation-correlation/v1"}, Provenance: inventoryProvenance("archive-payload-unknown/v1"),
	})
	result.Limitations = append(result.Limitations, report.Limitation{Code: "archive-payload-not-analyzed", Description: "Archive member payload bytes were not extracted or semantically analyzed; only bounded metadata was retained.", Path: file.Path})
}
