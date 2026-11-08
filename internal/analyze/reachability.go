package analyze

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

type invocationEdge struct {
	caller *report.Operation
	target string
}

// correlateIndirectInvocations joins only literal invocation targets to exact
// inventory-retained source paths. It never opens, imports, or executes the
// target. Ambiguous root-relative/source-relative matches remain unknown.
func correlateIndirectInvocations(contents map[string][]byte, result *Result) {
	candidates := make(map[string]bool, len(contents))
	operationsByPath := make(map[string][]*report.Operation)
	for name := range contents {
		clean := filepath.ToSlash(filepath.Clean(name))
		if clean != "." && !isGitMetadataPath(clean) {
			candidates[clean] = true
		}
	}
	for index := range result.Operations {
		operation := &result.Operations[index]
		path := filepath.ToSlash(filepath.Clean(operation.Evidence.Path))
		if len(operationsByPath[path]) < report.MaxFindingEvidence-1 {
			operationsByPath[path] = append(operationsByPath[path], operation)
		}
	}
	edges, ambiguous := literalInvocationEdges(result.Operations, candidates)
	for _, value := range ambiguous {
		appendUnknown(result, report.Unknown{
			ID: "unknown-indirect-target-" + value.caller.ID, Category: "indirect-invocation", Reason: report.UnknownUnresolvedFlow,
			Scope: report.ScopeUnknown, Confidence: report.ConfidenceHigh, Title: "Literal invocation target matches multiple inspected paths",
			Description: "The visible target can resolve as either a target-root-relative or caller-directory-relative path. Runtime working-directory semantics are not established, so no callee was selected.",
			Evidence:    []report.Evidence{value.caller.Evidence}, Origins: []report.ValueOrigin{{Kind: report.OriginUseSite, Name: value.target, Evidence: value.caller.Evidence}},
			AffectedOperations: []string{value.caller.ID}, SuppressedRules: []string{"indirect-script-reachability/v1", "operation-correlation/v1"}, Provenance: sourceProvenance("indirect-target-unknown/v1"),
		})
	}
	for _, edge := range edges {
		resource := report.Resource{
			ID: "resource-indirect-exec-" + edge.caller.ID + "-" + stablePathID(edge.target), Kind: "plugin-path", Access: "execute", Value: edge.target,
			Sensitive: false, Dynamic: false, Confidence: report.ConfidenceMedium, Evidence: edge.caller.Evidence, RelatedOperationID: edge.caller.ID,
			Provenance: sourceProvenance("indirect-script-target/v1"),
		}
		if !appendResource(result, resource) {
			continue
		}
		callees := operationsByPath[edge.target]
		if len(callees) == 0 {
			continue
		}
		evidence := []report.Evidence{edge.caller.Evidence}
		related := []string{edge.caller.ID}
		confidence := report.ConfidenceMedium
		for _, callee := range callees {
			if callee.ID == edge.caller.ID || len(evidence) >= report.MaxFindingEvidence || len(related) >= report.MaxFindingRelated {
				continue
			}
			evidence = append(evidence, callee.Evidence)
			related = append(related, callee.ID)
		}
		if len(related) == 1 {
			continue
		}
		appendFinding(result, report.Finding{
			ID: "finding-indirect-exec-" + edge.caller.ID + "-" + stablePathID(edge.target), Claim: report.ClaimInference, Severity: report.SeverityInformational, Confidence: confidence,
			Category: "indirect-script-execution", Title: "Links a literal invocation to an inspected plugin script",
			Explanation: "The invocation target matches an inspected target-relative source file whose operations are cited here. Runtime working directory, control flow, file mode, interpreter behavior, and successful execution remain unestablished.",
			Evidence:    evidence, Related: related, Provenance: sourceProvenance("indirect-script-reachability/v1"),
		})
	}
}

func literalInvocationEdges(operations []report.Operation, candidates map[string]bool) ([]invocationEdge, []invocationEdge) {
	edges := make([]invocationEdge, 0)
	ambiguous := make([]invocationEdge, 0)
	for index := range operations {
		operation := &operations[index]
		target := literalOperationTarget(*operation)
		if target == "" {
			continue
		}
		matches := resolveLiteralTarget(operation.Evidence.Path, target, candidates)
		if len(matches) == 1 && matches[0] != filepath.ToSlash(filepath.Clean(operation.Evidence.Path)) {
			edges = append(edges, invocationEdge{caller: operation, target: matches[0]})
		} else if len(matches) > 1 {
			ambiguous = append(ambiguous, invocationEdge{caller: operation, target: target})
		}
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].caller.Evidence.Path != edges[j].caller.Evidence.Path {
			return edges[i].caller.Evidence.Path < edges[j].caller.Evidence.Path
		}
		if edges[i].caller.Evidence.LineStart != edges[j].caller.Evidence.LineStart {
			return edges[i].caller.Evidence.LineStart < edges[j].caller.Evidence.LineStart
		}
		return edges[i].caller.ID < edges[j].caller.ID
	})
	sort.Slice(ambiguous, func(i, j int) bool { return ambiguous[i].caller.ID < ambiguous[j].caller.ID })
	return edges, ambiguous
}

func literalOperationTarget(operation report.Operation) string {
	if operation.Dynamic {
		return ""
	}
	if operation.Category == "hyprland-source-reference" {
		return operation.Command
	}
	return executionFileTarget(operation)
}

func resolveLiteralTarget(callerPath, target string, candidates map[string]bool) []string {
	if target == "" || filepath.IsAbs(target) || strings.Contains(target, "\\") || strings.Contains(target, "<dynamic>") || strings.ContainsRune(target, 0) {
		return nil
	}
	target = filepath.ToSlash(filepath.Clean(target))
	if target == "." || target == ".." || strings.HasPrefix(target, "../") {
		return nil
	}
	caller := filepath.ToSlash(filepath.Clean(callerPath))
	options := []string{target, filepath.ToSlash(filepath.Clean(filepath.Join(filepath.Dir(caller), target)))}
	matches := make([]string, 0, 2)
	seen := make(map[string]bool)
	for _, option := range options {
		if option == "." || option == ".." || strings.HasPrefix(option, "../") || seen[option] || !candidates[option] {
			continue
		}
		seen[option] = true
		matches = append(matches, option)
	}
	sort.Strings(matches)
	return matches
}
