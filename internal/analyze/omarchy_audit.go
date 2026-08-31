package analyze

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/omarchyaudit"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

const omarchyAuditAnalyzer = report.OmarchyAuditAnalyzer
const maxOmarchyAuditComparisons = 2048
const OmarchyAuditEvidenceInputID = "input-omarchy-audit"

type comparableNode struct {
	kind     report.NodeKind
	id       string
	evidence report.Evidence
	source   report.EvidenceSource
}

type omarchyComparisonKey struct {
	kind         report.NodeKind
	command      string
	resourceKind string
	access       string
	value        string
}

func operationComparisonKey(command string) omarchyComparisonKey {
	return omarchyComparisonKey{kind: report.NodeOperation, command: filepath.Base(command)}
}

func resourceComparisonKey(kind, access, value string) omarchyComparisonKey {
	return omarchyComparisonKey{kind: report.NodeResource, resourceKind: kind, access: access, value: value}
}

func (key omarchyComparisonKey) subject() string {
	if key.kind == report.NodeOperation {
		return report.OperationComparisonSubject(key.command)
	}
	return report.ResourceComparisonSubject(key.resourceKind, key.access, key.value)
}

func localExternalConclusionProvenance(ruleID, scannerVersion string, source report.EvidenceSource) report.Provenance {
	return report.Provenance{RuleID: ruleID, Analyzer: report.DeterministicAnalyzer, AnalyzerVersion: scannerVersion, EvidenceSource: source}
}

func IngestOmarchyAudit(audit omarchyaudit.Report, result *Result, scannerVersion string) []report.Comparison {
	independent := independentComparableNodes(result)
	external := make(map[omarchyComparisonKey]comparableNode)
	provenance := report.Provenance{RuleID: report.OmarchyAuditObservationRule, Analyzer: omarchyAuditAnalyzer, AnalyzerVersion: report.OmarchyAuditInputVersion, EvidenceSource: report.EvidenceSourceOmarchyAudit}
	evidence := func(kind, value string) report.Evidence {
		return report.Evidence{InputID: OmarchyAuditEvidenceInputID, Path: "omarchy-audit.json", Operation: boundedAuditEvidence(kind + ": " + value)}
	}
	appendUnknown(result, report.Unknown{ID: "unknown-omarchy-audit-snapshot-binding", Category: report.ExternalEvidenceBindingCategory, Reason: report.UnknownExternalBinding, Scope: report.ScopeUnknown, Confidence: report.ConfidenceHigh, Title: "Imported Omarchy audit is not cryptographically bound to the scanned bytes", Description: "The pinned PR #8439 JSON identifies the plugin ID but does not include a content digest. Plug & Prejudice verified the ID, but cannot establish that the imported audit was produced from exactly the current target snapshot.", Evidence: []report.Evidence{evidence("audit plugin ID", audit.ID)}, Origins: []report.ValueOrigin{}, AffectedOperations: []string{}, SuppressedRules: []string{report.ExternalSnapshotBindingRule}, Provenance: localExternalConclusionProvenance(report.ExternalBindingAssessmentRule, scannerVersion, report.EvidenceSourceOmarchyAudit)})
	for _, item := range audit.Observed.Commands {
		key := operationComparisonKey(item.Name)
		op := report.Operation{ID: "op-omarchy-command-" + stablePathID(item.Name), Category: "omarchy-audit-command", Command: item.Name, Arguments: []string{}, Dynamic: item.Name == "(dynamic)", Confidence: report.ConfidenceHigh, Evidence: evidence("observed command", item.Name), Provenance: provenance}
		op.Scope = report.ScopeUnknown
		if op.Dynamic {
			op.Confidence = report.ConfidenceMedium
		}
		if appendOperation(result, op) {
			external[key] = comparableNode{report.NodeOperation, op.ID, op.Evidence, op.Provenance.EvidenceSource}
		}
	}
	appendExternalResource := func(key omarchyComparisonKey, kind, access, value string, dynamic bool) {
		op := report.Operation{ID: "op-omarchy-resource-" + stablePathID(key.subject()), Category: "omarchy-audit-resource", Command: "omarchy-audit-observation", Arguments: []string{kind, access, value}, Dynamic: dynamic, Confidence: report.ConfidenceHigh, Evidence: evidence("observed "+kind, value), Provenance: provenance}
		op.Scope = report.ScopeUnknown
		if dynamic {
			op.Confidence = report.ConfidenceMedium
		}
		if !appendOperation(result, op) {
			return
		}
		resource := report.Resource{ID: "resource-omarchy-" + stablePathID(key.subject()), Kind: kind, Access: access, Value: value, Dynamic: dynamic, Scope: report.ScopeUnknown, Confidence: op.Confidence, Evidence: op.Evidence, RelatedOperationID: op.ID, Provenance: provenance}
		if appendResource(result, resource) {
			external[key] = comparableNode{report.NodeResource, resource.ID, resource.Evidence, resource.Provenance.EvidenceSource}
		}
	}
	for _, item := range audit.Observed.Network {
		appendExternalResource(resourceComparisonKey("network-domain", "connect", item.Host), "network-domain", "connect", item.Host, item.Host == "(dynamic)")
	}
	for _, item := range audit.Observed.Reads {
		appendExternalResource(resourceComparisonKey("filesystem-path", "read", item.Path), "filesystem-path", "read", item.Path, strings.Contains(item.Path, "(dynamic)"))
	}
	for _, item := range audit.Observed.Writes {
		appendExternalResource(resourceComparisonKey("filesystem-path", "write", item.Path), "filesystem-path", "write", item.Path, strings.Contains(item.Path, "(dynamic)"))
	}
	for index, risk := range audit.Risks {
		severity := report.SeverityInformational
		switch risk.Severity {
		case "high":
			severity = report.SeverityHigh
		case "medium":
			severity = report.SeverityMedium
		case "low":
			severity = report.SeverityLow
		}
		appendFinding(result, report.Finding{ID: fmt.Sprintf("finding-omarchy-risk-%d-%s", index+1, stablePathID(risk.Kind+"\x00"+risk.Detail)), Claim: report.ClaimFact, Severity: severity, Confidence: report.ConfidenceHigh, Category: "omarchy-audit-risk-" + risk.Kind, Scope: report.ScopeUnknown, Title: "Omarchy audit reports " + risk.Kind, Explanation: risk.Detail + " This is imported first-party audit output, not an independently established Plug & Prejudice conclusion.", Evidence: []report.Evidence{evidence("risk", risk.Kind+": "+risk.Detail)}, Provenance: provenance})
	}

	comparisons := make([]report.Comparison, 0)
	keys := unionSortedKeys(independent, external)
	for keyIndex, key := range keys {
		if keyIndex >= maxOmarchyAuditComparisons {
			result.Limitations = append(result.Limitations, report.Limitation{Code: "omarchy-audit-comparison-budget", Description: "The optional cross-analyzer comparison reached its 2,048-key limit; remaining independent and imported observations stay visible without agreement/disagreement classification.", Scope: report.ScopeUnknown})
			budgetProvenance := localExternalConclusionProvenance(report.ComparisonBudgetRule, scannerVersion, report.EvidenceSourceOmarchyAudit)
			appendUnknown(result, report.Unknown{ID: "unknown-omarchy-audit-comparison-budget", Category: "external-evidence-comparison", Reason: report.UnknownBudgetExhaustion, Scope: report.ScopeUnknown, Confidence: report.ConfidenceHigh, Title: "Some Omarchy audit comparisons were not classified", Description: "The bounded semantic-key comparison stopped after 2,048 keys. Retained observations remain available, but later agreement and coverage-difference relationships are unknown.", Evidence: []report.Evidence{evidence("comparison keys", fmt.Sprintf("%d retained keys", len(keys)))}, Origins: []report.ValueOrigin{}, AffectedOperations: []string{}, SuppressedRules: []string{report.CoverageComparisonRule}, Provenance: budgetProvenance})
			break
		}
		own, ownOK := independent[key]
		other, otherOK := external[key]
		if ownOK && otherOK {
			comparisons = append(comparisons, report.Comparison{Type: report.RelationshipCorroborates, FromKind: own.kind, FromID: own.id, ToKind: other.kind, ToID: other.id, Basis: report.ComparisonBasis{Kind: string(own.kind), Subject: key.subject()}})
			continue
		}
		var observed comparableNode
		var explanation string
		if otherOK {
			observed = other
			explanation = "The imported Omarchy audit retained this observation, while the independent scan retained no exact semantic counterpart. This is a coverage difference, not proof that either result is wrong."
		} else {
			observed = own
			explanation = "The independent scan retained this observation, while the imported Omarchy audit retained no exact semantic counterpart. Different scope or extraction rules may explain the difference."
		}
		findingProvenance := localExternalConclusionProvenance(report.CoverageComparisonRule, scannerVersion, observed.source)
		finding := report.Finding{ID: "finding-omarchy-coverage-disagreement-" + stablePathID(key.subject()), Claim: report.ClaimFact, Severity: report.SeverityInformational, Confidence: report.ConfidenceHigh, Category: report.CoverageDifferenceCategory, Scope: report.ScopeUnknown, Title: "Independent and Omarchy audit observations differ", Explanation: explanation, Evidence: []report.Evidence{observed.evidence}, Related: []string{}, Provenance: findingProvenance}
		if appendFinding(result, finding) {
			comparisons = append(comparisons, report.Comparison{Type: report.RelationshipDisagreesWith, FromKind: observed.kind, FromID: observed.id, ToKind: report.NodeFinding, ToID: finding.ID, Basis: report.ComparisonBasis{Kind: "coverage", Subject: key.subject()}})
		}
	}
	return comparisons
}

func independentComparableNodes(result *Result) map[omarchyComparisonKey]comparableNode {
	values := make(map[omarchyComparisonKey]comparableNode)
	for _, operation := range result.Operations {
		if operation.Provenance.EvidenceSource == report.EvidenceSourceOmarchyAudit || !isProcessExecution(operation) || operation.Dynamic {
			continue
		}
		key := operationComparisonKey(operation.Command)
		if _, exists := values[key]; !exists {
			values[key] = comparableNode{report.NodeOperation, operation.ID, operation.Evidence, operation.Provenance.EvidenceSource}
		}
	}
	for _, resource := range result.Resources {
		if resource.Provenance.EvidenceSource == report.EvidenceSourceOmarchyAudit || resource.Dynamic {
			continue
		}
		if resource.Kind != "network-domain" && resource.Kind != "filesystem-path" {
			continue
		}
		key := resourceComparisonKey(resource.Kind, resource.Access, resource.Value)
		if _, exists := values[key]; !exists {
			values[key] = comparableNode{report.NodeResource, resource.ID, resource.Evidence, resource.Provenance.EvidenceSource}
		}
	}
	return values
}

func unionSortedKeys(first, second map[omarchyComparisonKey]comparableNode) []omarchyComparisonKey {
	set := make(map[omarchyComparisonKey]bool, len(first)+len(second))
	for key := range first {
		set[key] = true
	}
	for key := range second {
		set[key] = true
	}
	values := make([]omarchyComparisonKey, 0, len(set))
	for key := range set {
		values = append(values, key)
	}
	sort.Slice(values, func(i, j int) bool {
		left, right := values[i], values[j]
		if left.kind != right.kind {
			return left.kind < right.kind
		}
		if left.command != right.command {
			return left.command < right.command
		}
		if left.resourceKind != right.resourceKind {
			return left.resourceKind < right.resourceKind
		}
		if left.access != right.access {
			return left.access < right.access
		}
		return left.value < right.value
	})
	return values
}

func boundedAuditEvidence(value string) string {
	encoded, _ := boundedEncodedString(value)
	return encoded
}
