package analyze

import (
	"reflect"
	"strings"
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

// All samples are inert source bytes consumed only by Sources.
func TestModuleConditionalReassignment(t *testing.T) {
	for _, api := range []string{"spawn", "execFile"} {
		for _, value := range []struct{ name, initial, call, literal, category string }{
			{"command", `"curl"`, `command, ["https://initial.example.test"]`, `"printf"`, "unresolved-command"},
			{"args", `["https://initial.example.test"]`, `"curl", args`, `["https://other.example.test"]`, "unresolved-process-arguments"},
			{"url", `"https://initial.example.test"`, `"curl", [url]`, `"https://other.example.test"`, "unresolved-process-arguments"},
		} {
			for _, replacement := range []string{value.literal, "chooseValue()"} {
				assignment := value.name + " = " + replacement
				for form, branch := range map[string]string{
					"if":             "if (enabled) { " + assignment + "; }",
					"else":           "if (enabled) { other = 'unused'; } else { " + assignment + "; }",
					"else-if":        "if (enabled) {} else if (other) { " + assignment + "; }",
					"nested":         "if (enabled) { if (other) { " + assignment + "; } }",
					"parenthesized":  "if (enabled) { ( /* assignment */ " + assignment + " ); }",
					"bare-comments":  "if (enabled) /* before */ " + assignment + "; // after\n",
					"block-comments": "if /* condition */ (enabled) { /* before */ " + assignment + "; /* after */ }",
				} {
					t.Run("javascript/"+api+"/"+value.name+"/"+replacement+"/"+form, func(t *testing.T) {
						source := "let " + value.name + " = " + value.initial + ";\n" + branch + "\nchild_process." + api + "(" + value.call + ");\n"
						result := Sources(withValidManifest(map[string][]byte{"helper.js": []byte(source)}))
						assertConditionalUnknown(t, result, "javascript", "child_process."+api, value.category, value.name, assignment)
					})
				}
			}
		}
	}
	for _, value := range []struct{ name, initial, call, literal, category string }{
		{"command", `["curl", "https://initial.example.test"]`, "command", `["printf", "ok"]`, "unresolved-command"},
		{"url", `"https://initial.example.test"`, `["curl", url]`, `"https://other.example.test"`, "unresolved-process-arguments"},
	} {
		for _, replacement := range []string{value.literal, "choose_value()"} {
			assignment := value.name + " = " + replacement
			for form, branch := range map[string]string{
				"if":     "if enabled:\n    " + assignment,
				"else":   "if enabled:\n    other = 'unused'\nelse:\n    " + assignment,
				"elif":   "if enabled:\n    pass\nelif other:\n    " + assignment,
				"nested": "if enabled:\n    if other:\n        " + assignment,
			} {
				t.Run("python/"+value.name+"/"+replacement+"/"+form, func(t *testing.T) {
					source := "import subprocess\n" + value.name + " = " + value.initial + "\n" + branch + "\nsubprocess.run(" + value.call + ")\n"
					result := Sources(withValidManifest(map[string][]byte{"helper.py": []byte(source)}))
					assertConditionalUnknown(t, result, "python", "subprocess.run", value.category, value.name, assignment)
				})
			}
		}
	}
}

func TestModuleConditionalReassignmentPreservesLiterals(t *testing.T) {
	for _, test := range []struct{ name, language, prefix, call, suffix string }{
		{"direct", "javascript", "", `child_process.spawn("curl", ["https://initial.example.test"]);`, ""},
		{"definition", "javascript", "let command = 'curl';\n", `child_process.execFile(command, ["https://initial.example.test"]);`, ""},
		{"chain", "javascript", "const first = 'curl';\nconst second = first;\nconst command = second;\n", `child_process.spawn(command, ["https://initial.example.test"]);`, ""},
		{"other-name", "javascript", "let command = 'curl';\nif (enabled) { other = chooseValue(); }\n", `child_process.spawn(command, ["https://initial.example.test"]);`, ""},
		{"after-call", "javascript", "let command = 'curl';\n", `child_process.spawn(command, ["https://initial.example.test"]);`, "\nif (enabled) { command = chooseValue(); }"},
		{"function-local", "javascript", "let command = 'curl';\nfunction local() { let command = 'printf'; if (enabled) { command = chooseValue(); } }\n", `child_process.spawn(command, ["https://initial.example.test"]);`, ""},
		{"arrow-local", "javascript", "let command = 'curl';\nconst local = () => { let command = 'printf'; if (enabled) { command = chooseValue(); } };\n", `child_process.spawn(command, ["https://initial.example.test"]);`, ""},
		{"class-local", "javascript", "let command = 'curl';\nclass Local { method() { let command = 'printf'; if (enabled) { command = chooseValue(); } } }\n", `child_process.spawn(command, ["https://initial.example.test"]);`, ""},
		{"block-declaration", "javascript", "let command = 'curl';\nif (enabled) { const command = 'printf'; }\n", `child_process.spawn(command, ["https://initial.example.test"]);`, ""},
		{"block-local-write", "javascript", "let command = 'curl';\nif (enabled) { let command = 'printf'; command = chooseValue(); }\n", `child_process.spawn(command, ["https://initial.example.test"]);`, ""},
		{"block-local-uninitialized", "javascript", "let command = 'curl';\nif (enabled) { let command; if (other) { command = chooseValue(); } }\n", `child_process.spawn(command, ["https://initial.example.test"]);`, ""},
		{"block-class-write", "javascript", "let command = 'curl';\nif (enabled) { class command {} command = chooseValue(); }\n", `child_process.spawn(command, ["https://initial.example.test"]);`, ""},
		{"block-class-nested-write", "javascript", "let command = 'curl';\nif (enabled) { class command {} if (other) { command = chooseValue(); } }\n", `child_process.spawn(command, ["https://initial.example.test"]);`, ""},
		{"block-function-strict", "javascript", "'use strict';\nlet command = 'curl';\nif (enabled) { function command() {} command = chooseValue(); }\n", `child_process.spawn(command, ["https://initial.example.test"]);`, ""},
		{"comments", "javascript", "let /* name */ command = 'curl';\nif (enabled) { /* unrelated */ other = chooseValue(); }\n", "child_process.spawn(/* call */ command, [/* array */ 'https://initial.example.test'] /* tail */);", ""},
		{"direct", "python", "import subprocess\n", `subprocess.run(["curl", "https://initial.example.test"])`, ""},
		{"definition", "python", "import subprocess\ncommand = ['curl', 'https://initial.example.test']\n", "subprocess.run(command)", ""},
		{"chain", "python", "import subprocess\nurl = 'https://initial.example.test'\nendpoint = url\ncommand = ['curl', endpoint]\n", "subprocess.run(command)", ""},
		{"other-name", "python", "import subprocess\ncommand = ['curl', 'https://initial.example.test']\nif enabled:\n    other = choose_value()\n", "subprocess.run(command)", ""},
		{"after-call", "python", "import subprocess\ncommand = ['curl', 'https://initial.example.test']\n", "subprocess.run(command)", "\nif enabled:\n    command = choose_value()"},
		{"function-local", "python", "import subprocess\ncommand = ['curl', 'https://initial.example.test']\ndef local():\n    command = ['printf']\n    if enabled:\n        command = choose_value()\n", "subprocess.run(command)", ""},
		{"class-local", "python", "import subprocess\ncommand = ['curl', 'https://initial.example.test']\nclass Local:\n    command = ['printf']\n    if enabled:\n        command = choose_value()\n", "subprocess.run(command)", ""},
	} {
		t.Run(test.language+"/"+test.name, func(t *testing.T) {
			ext := ".js"
			if test.language == "python" {
				ext = ".py"
			}
			result := Sources(withValidManifest(map[string][]byte{"helper" + ext: []byte(test.prefix + test.call + test.suffix + "\n")}))
			process := operationByCategory(t, result, "process-execution-via-"+test.language)
			if process.Command != "curl" || !reflect.DeepEqual(process.Arguments, []string{"https://initial.example.test"}) || process.Dynamic || process.Confidence != report.ConfidenceHigh || len(result.Unknowns) != 0 {
				t.Fatalf("valid literal evidence changed: process=%#v unknowns=%#v", process, result.Unknowns)
			}
			resource := resourceByKind(t, result, "network-domain")
			if resource.Value != "initial.example.test" || resource.RelatedOperationID != process.ID {
				t.Fatalf("literal resource lost its operation: %#v", resource)
			}
			for _, finding := range result.Findings {
				if finding.Category == test.language+"-literal-process-flow" && (!reflect.DeepEqual(finding.Related, []string{process.ID}) || finding.Claim != report.ClaimFact) {
					t.Fatalf("literal flow finding lost its operation: %#v", finding)
				}
			}
			if test.name != "direct" && !hasFindingCategory(result, test.language+"-literal-process-flow") {
				t.Fatal("supported assignment flow fact was lost")
			}
		})
	}
}

func TestModuleConditionalReviewCorrections(t *testing.T) {
	for _, test := range []struct{ name, language, initial, assignment, call, category, identifier string }{
		{"js-parenthesized-target", "javascript", "let command = 'curl';", "(command) = 'printf'", "child_process.spawn(command, ['https://initial.example.test']);", "unresolved-command", "command"},
		{"js-parenthesized-target-computed", "javascript", "let command = 'curl';", "(( /* note */ command )) = chooseValue()", "child_process.spawn(command, ['https://initial.example.test']);", "unresolved-command", "command"},
		{"js-parenthesized-arguments", "javascript", "let args = ['https://initial.example.test'];", "(args) = chooseValue()", "child_process.execFile('curl', args);", "unresolved-process-arguments", "args"},
		{"py-parenthesized-target", "python", "command = ['curl', 'https://initial.example.test']", "(command) = ['printf']", "subprocess.run(command)", "unresolved-command", "command"},
		{"py-parenthesized-target-computed", "python", "command = ['curl', 'https://initial.example.test']", "((command)) = choose_value()", "subprocess.run(command)", "unresolved-command", "command"},
		{"py-parenthesized-argument", "python", "url = 'https://initial.example.test'", "((url)) = choose_value()", "subprocess.run(['curl', url])", "unresolved-process-arguments", "url"},
		{"py-leading-list-comment", "python", "url = 'https://initial.example.test'", "url = choose_value()", "subprocess.run([\n # note\n 'curl', url\n])", "unresolved-process-arguments", "url"},
		{"py-leading-tuple-comment", "python", "url = 'https://initial.example.test'", "url = choose_value()", "subprocess.run((\n # note\n 'curl', url\n))", "unresolved-process-arguments", "url"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ext, api := ".js", "child_process.spawn"
			branch := "if (enabled) { " + test.assignment + "; }"
			if test.language == "python" {
				ext, api = ".py", "subprocess.run"
				branch = "if enabled:\n    " + test.assignment
			} else if strings.Contains(test.call, "execFile") {
				api = "child_process.execFile"
			}
			source := test.initial + "\n" + branch + "\n" + test.call + "\n"
			result := Sources(withValidManifest(map[string][]byte{"helper" + ext: []byte(source)}))
			assertConditionalUnknown(t, result, test.language, api, test.category, test.identifier, test.assignment)
		})
	}
}

func assertConditionalUnknown(t *testing.T, result Result, language, api, category, name, assignment string) {
	t.Helper()
	var call report.Operation
	for _, op := range result.Operations {
		if op.Category == "language-call" && op.Command == api {
			call = op
		}
		if op.Category == "process-execution-via-"+language {
			t.Errorf("conditional reassignment selected command=%q arguments=%q dynamic=%v confidence=%s", op.Command, op.Arguments, op.Dynamic, op.Confidence)
		}
	}
	if call.ID == "" || !call.Dynamic || call.Confidence != report.ConfidenceMedium {
		t.Errorf("ambiguous call retained incorrect certainty: command=%q dynamic=%v confidence=%s", call.Command, call.Dynamic, call.Confidence)
	}
	if len(result.Unknowns) != 1 {
		t.Fatalf("affected call %s needs one explicit unknown, got %#v", call.ID, result.Unknowns)
	}
	u := result.Unknowns[0]
	if u.Reason != report.UnknownUnresolvedFlow || u.Category != category || !reflect.DeepEqual(u.AffectedOperations, []string{call.ID}) || len(u.Evidence) != 1 || u.Evidence[0].Operation != call.Evidence.Operation || u.Confidence != report.ConfidenceHigh {
		t.Fatalf("unknown lost affected value/call: %#v; call=%#v", u, call)
	}
	if category == "unresolved-process-arguments" && (!strings.Contains(u.Title, "arguments") || strings.Contains(u.Title, "executable")) {
		t.Errorf("known executable described as unknown: %#v", u)
	}
	use, origin := false, false
	for _, o := range u.Origins {
		use = use || (o.Kind == report.OriginUseSite && o.Name == name)
		origin = origin || (o.Kind == report.OriginAssignment && o.Name == name && o.Evidence.Operation == assignment)
	}
	if !use || !origin || len(u.Origins) > report.MaxUnknownOrigins || !strings.Contains(u.Description, "not proof of runtime control flow") {
		t.Errorf("conditional textual origin missing or overstated: %#v", u)
	}
	if len(result.Resources) != 0 || hasFindingCategory(result, language+"-literal-process-flow") {
		t.Errorf("discarded literal still supplies dependent evidence: resources=%#v findings=%#v", result.Resources, result.Findings)
	}
	rule := language + "-dynamic-command-unknown/v1"
	if category == "unresolved-process-arguments" {
		rule = language + "-process-arguments-unknown/v1"
	}
	if u.Provenance != sourceProvenance(rule) || !reflect.DeepEqual(u.SuppressedRules, []string{"command-capability/v1", "operation-correlation/v1"}) {
		t.Errorf("unknown lost provenance/suppressed rules: %#v", u)
	}
}

func TestModuleConditionalReassignmentDeterministic(t *testing.T) {
	files := withValidManifest(map[string][]byte{
		"helper.js": []byte("let args = ['https://initial.example.test'];\nif (enabled) { args = chooseValue(); }\nchild_process.spawn('curl', args);\n"),
		"helper.py": []byte("command = ['curl']\nif enabled:\n    command = choose_value()\nsubprocess.run(command)\n"),
	})
	want := Sources(files)
	for i := 0; i < 3; i++ {
		if got := Sources(files); !reflect.DeepEqual(got, want) {
			t.Fatalf("identical conditional source was nondeterministic on run %d", i)
		}
	}
}
