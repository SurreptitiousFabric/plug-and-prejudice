package analyze

import (
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func TestNetworkDomainIsNeutralResourceNotWarning(t *testing.T) {
	result := Sources(runtimeShell("curl -fsS https://api.example.test/v1/data\n"))
	resource := resourceByKind(t, result, "network-domain")
	if resource.Value != "api.example.test" || resource.Access != "connect" || resource.Scope != report.ScopeRuntime {
		t.Fatalf("unexpected domain resource: %#v", resource)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("ordinary network access produced warning: %#v", result.Findings)
	}
}

func TestCredentialPathReadIsHighFinding(t *testing.T) {
	result := Sources(runtimeShell("cat ~/.ssh/id_ed25519\n"))
	finding := findingByCategory(t, result, "credential-access")
	if finding.Severity != report.SeverityHigh || finding.Scope != report.ScopeRuntime {
		t.Fatalf("credential finding lacks impact or scope: %#v", finding)
	}
	resource := resourceByKind(t, result, "filesystem-path")
	if !resource.Sensitive || resource.Access != "read" {
		t.Fatalf("credential resource not marked sensitive: %#v", resource)
	}
}

func TestDeletionSeverityUsesContext(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		severity report.Severity
	}{
		{name: "explicit temp file", command: "rm /tmp/plugin-cache\n", severity: report.SeverityLow},
		{name: "recursive cache", command: "rm -rf /tmp/plugin-cache\n", severity: report.SeverityMedium},
		{name: "home directory", command: "rm -rf /home/example\n", severity: report.SeverityHigh},
		{name: "root", command: "rm -rf /\n", severity: report.SeverityCritical},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := Sources(runtimeShell(test.command))
			finding := findingByCategory(t, result, "destructive-operation")
			if finding.Severity != test.severity {
				t.Fatalf("severity = %s, want %s: %#v", finding.Severity, test.severity, finding)
			}
		})
	}
}

func TestPersistenceFromStartupPathAndSystemdEnable(t *testing.T) {
	result := Sources(runtimeShell("touch ~/.config/autostart/example.desktop\nsystemctl --user enable example.service\n"))
	if countFindingCategory(result, "persistence") != 2 {
		t.Fatalf("persistence mechanisms not independently reported: %#v", result.Findings)
	}
	count := 0
	for _, resource := range result.Resources {
		if resource.Kind == "persistence" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("persistence resources = %d, want 2: %#v", count, result.Resources)
	}
}

func TestCapabilityWordsInCommentsRemainIgnored(t *testing.T) {
	result := Sources(runtimeShell("# rm -rf / and cat ~/.ssh/id_rsa\nprintf '%s\\n' 'https://example.test is documentation'\n"))
	if len(result.Resources) != 0 || len(result.Findings) != 0 {
		t.Fatalf("comments or ordinary printf data became capabilities: %#v", result)
	}
}

func TestDynamicNetworkTargetRemainsUnknown(t *testing.T) {
	result := Sources(runtimeShell("curl \"$endpoint\"\n"))
	resource := resourceByKind(t, result, "network-domain")
	if !resource.Dynamic || resource.Value != "<dynamic>" {
		t.Fatalf("dynamic endpoint was guessed or omitted: %#v", resource)
	}
}

func runtimeShell(program string) map[string][]byte {
	return withValidManifest(map[string][]byte{
		"Runtime.qml":   []byte("property string helper: \"bin/helper.sh\"\n"),
		"bin/helper.sh": []byte("#!/bin/sh\n" + program),
	})
}

func resourceByKind(t *testing.T, result Result, kind string) report.Resource {
	t.Helper()
	for _, resource := range result.Resources {
		if resource.Kind == kind {
			return resource
		}
	}
	t.Fatalf("missing %s resource in %#v", kind, result.Resources)
	return report.Resource{}
}
