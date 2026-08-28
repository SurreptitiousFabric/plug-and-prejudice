package analyze

import (
	"fmt"
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func TestLiteralInterpreterInvocationLinksInspectedScriptEvidence(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Runtime.qml":       []byte("Process { command: [\"bash\", \"scripts/helper.sh\"] }\n"),
		"scripts/helper.sh": []byte("#!/bin/sh\ncurl https://example.test/data\n"),
	}))
	if !hasFindingCategory(result, "indirect-script-execution") {
		t.Fatalf("indirect script evidence chain missing: %#v", result.Findings)
	}
	finding := findingByCategory(t, result, "indirect-script-execution")
	if finding.Claim != report.ClaimInference || len(finding.Related) < 2 || len(finding.Evidence) < 2 {
		t.Fatalf("indirect script provenance = %#v", finding)
	}
	foundTarget := false
	for _, resource := range result.Resources {
		if resource.Kind == "plugin-path" && resource.Access == "execute" && resource.Value == "scripts/helper.sh" {
			foundTarget = true
		}
	}
	if !foundTarget {
		t.Fatalf("literal inspected target resource missing: %#v", result.Resources)
	}
	for _, operation := range result.Operations {
		if operation.Evidence.Path == "scripts/helper.sh" && operation.Scope != report.ScopeRuntime {
			t.Fatalf("indirectly reached operation scope = %q: %#v", operation.Scope, operation)
		}
	}
}

func TestHyprlandStaticSourceLinksIncludedConfiguration(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Runtime.qml":                        []byte("property string config: \"config/hypr/hyprland.conf\"\n"),
		"config/hypr/hyprland.conf":          []byte("source = fragments/startup.conf\n"),
		"config/hypr/fragments/startup.conf": []byte("exec-once = /usr/bin/helper\n"),
	}))
	if !hasFindingCategory(result, "indirect-script-execution") {
		t.Fatalf("Hyprland source relationship missing: %#v", result.Findings)
	}
	for _, operation := range result.Operations {
		if operation.Evidence.Path == "config/hypr/fragments/startup.conf" && operation.Scope != report.ScopeRuntime {
			t.Fatalf("included Hyprland config scope = %q: %#v", operation.Scope, operation)
		}
	}
}

func TestDeepLiteralInvocationChainUsesBoundedGraphTraversal(t *testing.T) {
	const depth = 256
	contents := withValidManifest(map[string][]byte{
		"Runtime.qml": []byte("Process { command: [\"bash\", \"scripts/000.sh\"] }\n"),
	})
	for index := 0; index < depth; index++ {
		name := fmt.Sprintf("scripts/%03d.sh", index)
		if index+1 < depth {
			contents[name] = []byte(fmt.Sprintf("#!/bin/sh\nbash ./%03d.sh\n", index+1))
		} else {
			contents[name] = []byte("#!/bin/sh\nfinal-command\n")
		}
	}
	result := Sources(contents)
	for _, operation := range result.Operations {
		if operation.Command == "final-command" && operation.Scope != report.ScopeRuntime {
			t.Fatalf("deep final operation scope = %q", operation.Scope)
		}
	}
	if len(result.Findings) < depth {
		t.Fatalf("deep chain lost evidence links: findings=%d", len(result.Findings))
	}
	assertAnalyzerResult(t, result)
}

func TestIndirectReachabilityPropagatesAcrossBoundedMultipleHops(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Runtime.qml":         []byte("Process { command: [\"bash\", \"scripts/launcher.sh\"] }\n"),
		"scripts/launcher.sh": []byte("#!/bin/sh\nbash ./payload.sh\n"),
		"scripts/payload.sh":  []byte("#!/bin/sh\nwhoami\n"),
	}))
	for _, operation := range result.Operations {
		if operation.Evidence.Path == "scripts/launcher.sh" || operation.Evidence.Path == "scripts/payload.sh" {
			if operation.Scope != report.ScopeRuntime {
				t.Fatalf("multi-hop operation %q scope = %q", operation.Evidence.Path, operation.Scope)
			}
		}
	}
	count := 0
	for _, finding := range result.Findings {
		if finding.Category == "indirect-script-execution" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("multi-hop indirect findings = %d: %#v", count, result.Findings)
	}
}

func TestAmbiguousRootAndCallerRelativeTargetRemainsUnknown(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Runtime.qml":         []byte("Process { command: [\"bash\", \"scripts/launcher.sh\"] }\n"),
		"scripts/launcher.sh": []byte("#!/bin/sh\nbash helper.sh\n"),
		"helper.sh":           []byte("#!/bin/sh\nroot-command\n"),
		"scripts/helper.sh":   []byte("#!/bin/sh\nlocal-command\n"),
	}))
	found := false
	for _, unknown := range result.Unknowns {
		if unknown.Category == "indirect-invocation" && unknown.Reason == report.UnknownUnresolvedFlow {
			found = true
		}
	}
	if !found {
		t.Fatalf("ambiguous invocation did not remain unknown: %#v", result.Unknowns)
	}
	for _, finding := range result.Findings {
		if finding.Category == "indirect-script-execution" {
			for _, evidence := range finding.Evidence {
				if evidence.Path == "helper.sh" || evidence.Path == "scripts/helper.sh" {
					t.Fatalf("ambiguous helper was correlated: %#v", finding)
				}
			}
		}
	}
	for _, operation := range result.Operations {
		if (operation.Evidence.Path == "helper.sh" || operation.Evidence.Path == "scripts/helper.sh") && operation.Scope == report.ScopeRuntime {
			t.Fatalf("ambiguous helper was promoted to runtime: %#v", operation)
		}
	}
}

func TestDynamicAbsoluteMissingAndSelfTargetsDoNotCreateEdges(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Runtime.qml": []byte("Process { command: [\"bash\", root.script] }\n"),
		"caller.sh":   []byte("#!/bin/sh\nbash /host/path.sh\nbash missing.sh\nbash caller.sh\n"),
	}))
	for _, resource := range result.Resources {
		if resource.Kind == "plugin-path" {
			t.Fatalf("unsafe/missing/self target created edge: %#v", resource)
		}
	}
}

func TestQMLTextualReachabilityRequiresExactQuotedTargetPath(t *testing.T) {
	contents := withValidManifest(map[string][]byte{
		"Runtime.qml":       []byte("property string real: \"scripts/helper.sh\"\nproperty string lookalike: \"helper.sh.example\"\n// \"commented.sh\"\n"),
		"scripts/helper.sh": []byte("#!/bin/sh\nreal-command\n"),
		"helper.sh":         []byte("#!/bin/sh\nlookalike-command\n"),
		"commented.sh":      []byte("#!/bin/sh\ncomment-command\n"),
	})
	result := Sources(contents)
	for _, operation := range result.Operations {
		switch operation.Command {
		case "real-command":
			if operation.Scope != report.ScopeRuntime {
				t.Fatalf("exact QML reference was not propagated: %#v", operation)
			}
		case "lookalike-command":
			if operation.Scope == report.ScopeRuntime {
				t.Fatalf("QML substring lookalike became runtime: %#v", operation)
			}
		case "comment-command":
			if operation.Scope == report.ScopeRuntime {
				t.Fatalf("QML comment became runtime: %#v", operation)
			}
		}
	}
}
