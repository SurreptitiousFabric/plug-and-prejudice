package analyze

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/omarchyaudit"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

const omarchyAuditAnalyzer = "omarchy/plugin-audit"
const maxOmarchyAuditComparisons = 2048

type comparableNode struct {
	kind     report.NodeKind
	id       string
	evidence report.Evidence
}

func IngestOmarchyAudit(audit omarchyaudit.Report, result *Result) []report.Comparison {
	independent := independentComparableNodes(result)
	external := make(map[string]comparableNode)
	provenance := report.Provenance{RuleID: "omarchy-audit-observation/v1", Analyzer: omarchyAuditAnalyzer, AnalyzerVersion: omarchyaudit.FormatPR8439Revision732b104, EvidenceSource: report.EvidenceSourceOmarchyAudit}
	evidence := func(kind, value string) report.Evidence {
		return report.Evidence{Path: "omarchy-audit.json", Operation: boundedAuditEvidence(kind + ": " + value)}
	}
	appendUnknown(result, report.Unknown{ID: "unknown-omarchy-audit-snapshot-binding", Category: "external-evidence-binding", Reason: report.UnknownUnresolvedFlow, Scope: report.ScopeUnknown, Confidence: report.ConfidenceHigh, Title: "Imported Omarchy audit is not cryptographically bound to the scanned bytes", Description: "The pinned PR #8439 JSON identifies the plugin ID but does not include a content digest. Plug & Prejudice verified the ID, but cannot establish that the imported audit was produced from exactly the current target snapshot.", Evidence: []report.Evidence{evidence("audit plugin ID", audit.ID)}, Origins: []report.ValueOrigin{}, AffectedOperations: []string{}, SuppressedRules: []string{"external-snapshot-equivalence/v1"}, Provenance: provenance})
	for _, item := range audit.Observed.Commands {
		key := "command\x00" + filepath.Base(item.Name)
		op := report.Operation{ID: "op-omarchy-command-" + stablePathID(item.Name), Category: "omarchy-audit-command", Command: item.Name, Arguments: []string{}, Dynamic: item.Name == "(dynamic)", Confidence: report.ConfidenceHigh, Evidence: evidence("observed command", item.Name), Provenance: provenance}
		op.Scope = report.ScopeUnknown
		if op.Dynamic {
			op.Confidence = report.ConfidenceMedium
		}
		if appendOperation(result, op) {
			external[key] = comparableNode{report.NodeOperation, op.ID, op.Evidence}
		}
	}
	appendExternalResource := func(key, kind, access, value string, dynamic bool) {
		op := report.Operation{ID: "op-omarchy-resource-" + stablePathID(key), Category: "omarchy-audit-resource", Command: "omarchy-audit-observation", Arguments: []string{kind, access, value}, Dynamic: dynamic, Confidence: report.ConfidenceHigh, Evidence: evidence("observed "+kind, value), Provenance: provenance}
		op.Scope = report.ScopeUnknown
		if dynamic {
			op.Confidence = report.ConfidenceMedium
		}
		if !appendOperation(result, op) {
			return
		}
		resource := report.Resource{ID: "resource-omarchy-" + stablePathID(key), Kind: kind, Access: access, Value: value, Dynamic: dynamic, Scope: report.ScopeUnknown, Confidence: op.Confidence, Evidence: op.Evidence, RelatedOperationID: op.ID, Provenance: provenance}
		if appendResource(result, resource) {
			external[key] = comparableNode{report.NodeResource, resource.ID, resource.Evidence}
		}
	}
	for _, item := range audit.Observed.Network {
		appendExternalResource("network-domain\x00connect\x00"+item.Host, "network-domain", "connect", item.Host, item.Host == "(dynamic)")
	}
	for _, item := range audit.Observed.Reads {
		appendExternalResource("filesystem-path\x00read\x00"+item.Path, "filesystem-path", "read", item.Path, strings.Contains(item.Path, "(dynamic)"))
	}
	for _, item := range audit.Observed.Writes {
		appendExternalResource("filesystem-path\x00write\x00"+item.Path, "filesystem-path", "write", item.Path, strings.Contains(item.Path, "(dynamic)"))
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
			appendUnknown(result, report.Unknown{ID: "unknown-omarchy-audit-comparison-budget", Category: "external-evidence-comparison", Reason: report.UnknownBudgetExhaustion, Scope: report.ScopeUnknown, Confidence: report.ConfidenceHigh, Title: "Some Omarchy audit comparisons were not classified", Description: "The bounded semantic-key comparison stopped after 2,048 keys. Retained observations remain available, but later agreement and coverage-difference relationships are unknown.", Evidence: []report.Evidence{evidence("comparison keys", fmt.Sprintf("%d retained keys", len(keys)))}, Origins: []report.ValueOrigin{}, AffectedOperations: []string{}, SuppressedRules: []string{"omarchy-audit-coverage-comparison/v1"}, Provenance: sourceProvenance("omarchy-audit-comparison-budget/v1")})
			break
		}
		own, ownOK := independent[key]
		other, otherOK := external[key]
		if ownOK && otherOK {
			comparisons = append(comparisons, report.Comparison{Type: report.RelationshipCorroborates, FromKind: own.kind, FromID: own.id, ToKind: other.kind, ToID: other.id})
			continue
		}
		var observed comparableNode
		var findingProvenance report.Provenance
		var explanation string
		if otherOK {
			observed = other
			findingProvenance = sourceProvenance("omarchy-audit-coverage-comparison/v1")
			explanation = "The imported Omarchy audit retained this observation, while the independent scan retained no exact semantic counterpart. This is a coverage difference, not proof that either result is wrong."
		} else {
			observed = own
			findingProvenance = provenance
			findingProvenance.RuleID = "omarchy-audit-coverage-comparison/v1"
			explanation = "The independent scan retained this observation, while the imported Omarchy audit retained no exact semantic counterpart. Different scope or extraction rules may explain the difference."
		}
		finding := report.Finding{ID: "finding-omarchy-coverage-disagreement-" + stablePathID(key), Claim: report.ClaimFact, Severity: report.SeverityInformational, Confidence: report.ConfidenceHigh, Category: "omarchy-audit-coverage-disagreement", Scope: report.ScopeUnknown, Title: "Independent and Omarchy audit observations differ", Explanation: explanation, Evidence: []report.Evidence{observed.evidence}, Provenance: findingProvenance}
		if appendFinding(result, finding) {
			comparisons = append(comparisons, report.Comparison{Type: report.RelationshipDisagreesWith, FromKind: observed.kind, FromID: observed.id, ToKind: report.NodeFinding, ToID: finding.ID})
		}
	}
	return comparisons
}

func independentComparableNodes(result *Result) map[string]comparableNode {
	values := make(map[string]comparableNode)
	for _, operation := range result.Operations {
		if operation.Provenance.EvidenceSource == report.EvidenceSourceOmarchyAudit || !isProcessExecution(operation) || operation.Dynamic {
			continue
		}
		key := "command\x00" + filepath.Base(operation.Command)
		if _, exists := values[key]; !exists {
			values[key] = comparableNode{report.NodeOperation, operation.ID, operation.Evidence}
		}
	}
	for _, resource := range result.Resources {
		if resource.Provenance.EvidenceSource == report.EvidenceSourceOmarchyAudit || resource.Dynamic {
			continue
		}
		if resource.Kind != "network-domain" && resource.Kind != "filesystem-path" {
			continue
		}
		key := resource.Kind + "\x00" + resource.Access + "\x00" + resource.Value
		if _, exists := values[key]; !exists {
			values[key] = comparableNode{report.NodeResource, resource.ID, resource.Evidence}
		}
	}
	return values
}

func unionSortedKeys(first, second map[string]comparableNode) []string {
	set := make(map[string]bool, len(first)+len(second))
	for key := range first {
		set[key] = true
	}
	for key := range second {
		set[key] = true
	}
	values := make([]string, 0, len(set))
	for key := range set {
		values = append(values, key)
	}
	sort.Strings(values)
	return values
}

func boundedAuditEvidence(value string) string {
	encoded, _ := boundedEncodedString(value)
	return encoded
}
