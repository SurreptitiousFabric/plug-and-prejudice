package analyze

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

const installedArtifactRuleID = "installed-startup-artifact-correlation/v1"

// correlateInstalledStartupArtifacts joins a literal one-source file transfer
// to an exact persistence destination and to commands parsed from that exact
// retained source artifact. It consumes existing facts only and never opens,
// installs, imports, or executes the artifact.
func correlateInstalledStartupArtifacts(contents map[string][]byte, result *Result) {
	candidates := make(map[string]bool, len(contents))
	executions := make(map[string][]*report.Operation)
	for name := range contents {
		clean := filepath.ToSlash(filepath.Clean(name))
		if clean != "." && !isGitMetadataPath(clean) {
			candidates[clean] = true
		}
	}
	for index := range result.Operations {
		operation := &result.Operations[index]
		if operation.Category != "process-execution-via-desktop-entry" && operation.Category != "process-execution-via-systemd-unit" {
			continue
		}
		path := filepath.ToSlash(filepath.Clean(operation.Evidence.Path))
		if len(executions[path]) < report.MaxFindingEvidence-1 {
			executions[path] = append(executions[path], operation)
		}
	}

	resourcesByOperation := make(map[string][]report.Resource)
	for _, resource := range result.Resources {
		resourcesByOperation[resource.RelatedOperationID] = append(resourcesByOperation[resource.RelatedOperationID], resource)
	}
	for index := range result.Operations {
		operation := &result.Operations[index]
		command := filepath.Base(operation.Command)
		if operation.Dynamic || (command != "cp" && command != "install" && command != "mv") {
			continue
		}
		sources, destinations := artifactTransferPaths(resourcesByOperation[operation.ID], command)
		if len(sources) != 1 || len(destinations) != 1 || !exactStartupArtifactDestination(destinations[0]) {
			continue
		}
		matches := resolveLiteralTarget(operation.Evidence.Path, sources[0], candidates)
		if len(matches) > 1 {
			appendUnknown(result, report.Unknown{
				ID: "unknown-installed-artifact-" + operation.ID, Category: "installed-startup-artifact", Reason: report.UnknownUnresolvedFlow,
				Scope: report.ScopeUnknown, Confidence: report.ConfidenceHigh, Title: "Startup artifact source matches multiple inspected files",
				Description: "The file-transfer source can resolve as either a target-root-relative or caller-directory-relative retained artifact. Runtime working-directory semantics are not established, so the scanner did not select configuration content for the persistent destination.",
				Evidence:    []report.Evidence{operation.Evidence}, Origins: []report.ValueOrigin{{Kind: report.OriginUseSite, Name: sources[0], Evidence: operation.Evidence}},
				AffectedOperations: []string{operation.ID}, SuppressedRules: []string{installedArtifactRuleID}, Provenance: sourceProvenance("installed-startup-artifact-unknown/v1"),
			})
			continue
		}
		if len(matches) != 1 || !compatibleStartupArtifact(matches[0], destinations[0]) {
			continue
		}
		execs := executions[matches[0]]
		if len(execs) == 0 {
			continue
		}
		evidence := []report.Evidence{operation.Evidence}
		related := []string{operation.ID}
		confidence := report.ConfidenceMedium
		for _, execution := range execs {
			if len(evidence) >= report.MaxFindingEvidence || len(related) >= report.MaxFindingRelated {
				break
			}
			evidence = append(evidence, execution.Evidence)
			related = append(related, execution.ID)
			if execution.Dynamic || execution.Confidence == report.ConfidenceLow {
				confidence = report.ConfidenceLow
			}
		}
		appendFinding(result, report.Finding{
			ID: "finding-installed-startup-artifact-" + operation.ID + "-" + stablePathID(matches[0]), Claim: report.ClaimInference,
			Severity: report.SeverityMedium, Confidence: confidence, Category: "installed-startup-artifact-execution",
			Title:       "Connects a persistent configuration transfer to its declared command",
			Explanation: "The file-transfer operation names retained artifact " + matches[0] + " as its sole source and exact startup-related path " + destinations[0] + " as its destination. That inspected artifact declares the cited command. Static analysis does not establish control flow, transfer success, installation state, enablement, activation, launch, or command success.",
			Evidence:    evidence, Related: related, Provenance: sourceProvenance(installedArtifactRuleID),
		})
	}

	sort.Slice(result.Unknowns, func(i, j int) bool { return result.Unknowns[i].ID < result.Unknowns[j].ID })
}

func artifactTransferPaths(resources []report.Resource, command string) ([]string, []string) {
	sources := make([]string, 0, 2)
	destinations := make([]string, 0, 2)
	for _, resource := range resources {
		if resource.Kind == "filesystem-path" && !resource.Dynamic {
			if resource.Access == "read" || (command == "mv" && resource.Access == "delete") {
				sources = append(sources, resource.Value)
			}
		}
		if resource.Kind == "persistence" && resource.Access == "modify" && !resource.Dynamic {
			destinations = append(destinations, resource.Value)
		}
	}
	sort.Strings(sources)
	sort.Strings(destinations)
	return sources, destinations
}

func exactStartupArtifactDestination(value string) bool {
	if !literalCorrelationPath(value) || strings.HasSuffix(value, "/") {
		return false
	}
	extension := strings.ToLower(filepath.Ext(filepath.Clean(value)))
	return extension == ".desktop" || isSystemdUnitExtension(extension)
}

func compatibleStartupArtifact(source, destination string) bool {
	sourceExtension := strings.ToLower(filepath.Ext(source))
	destinationExtension := strings.ToLower(filepath.Ext(filepath.Clean(destination)))
	if sourceExtension == ".desktop" || destinationExtension == ".desktop" {
		return sourceExtension == ".desktop" && destinationExtension == ".desktop"
	}
	return isSystemdUnitExtension(sourceExtension) && sourceExtension == destinationExtension
}

func isSystemdUnitExtension(extension string) bool {
	switch extension {
	case ".service", ".timer", ".socket", ".path", ".mount", ".automount", ".swap", ".target", ".slice", ".scope":
		return true
	default:
		return false
	}
}
