package analyze

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
	ts "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

// Every sample is inert source data passed only to Sources, never invoked.
func TestSimpleFunctionParametersRejectModuleLiterals(t *testing.T) {
	for _, test := range []struct{ name, language, source, api, identifier, category string }{
		{"js-escaped-parameter", "javascript", "const url = 'https://example.test'; function launch(\\u0075rl) { child_process.spawn('curl', [url]); }", "child_process.spawn", "url", "unresolved-process-arguments"},
		{"js-escaped-use", "javascript", "const \\u0075rl = 'https://example.test'; function launch(url) { child_process.spawn('curl', [\\u0075rl]); }", "child_process.spawn", "\\u0075rl", "unresolved-process-arguments"},
		{"py-equivalent-parameter", "python", "K = 'https://example.test'\ndef launch(K):\n    subprocess.run(['curl', K])", "subprocess.run", "K", "unresolved-process-arguments"},
		{"py-equivalent-use", "python", "K = 'https://example.test'\ndef launch(K):\n    subprocess.run(['curl', K])", "subprocess.run", "K", "unresolved-process-arguments"},
		{"js-incomplete-unrelated", "javascript", "const url='https://example.test'; function launch(é) { child_process.spawn('curl',[url]); }", "child_process.spawn", "url", "unresolved-process-arguments"},
		{"py-incomplete-unrelated", "python", "url='https://example.test'\ndef launch(é):\n    subprocess.run(['curl',url])", "subprocess.run", "url", "unresolved-process-arguments"},
		{"js-escaped-executable", "javascript", "const command='curl'; function launch(\\u0063ommand) { child_process.spawn(command,[]); }", "child_process.spawn", "command", "unresolved-command"},
		{"py-equivalent-executable", "python", "K=['curl','https://example.test']\ndef launch(K):\n    subprocess.run(K)", "subprocess.run", "K", "unresolved-command"},
		{"js-export", "javascript", "const url='https://example.test'; export function launch(url) { child_process.spawn('curl',[url]); }", "child_process.spawn", "url", "unresolved-process-arguments"},
		{"js-export-default", "javascript", "const url='https://example.test'; export default function launch(url) { child_process.spawn('curl',[url]); }", "child_process.spawn", "url", "unresolved-process-arguments"},
		{"py-generator-withholding", "python", "url='https://example.test'\ndef launch(url):\n    subprocess.run(['curl',url])\n    yield 1", "subprocess.run", "url", "unresolved-process-arguments"},
		{"js-reassignment-withholding", "javascript", "const url='https://example.test'; function launch(url) { url='https://local.test'; child_process.spawn('curl',[url]); }", "child_process.spawn", "url", "unresolved-process-arguments"},
		{"js-command", "javascript", "const command = 'curl';\nfunction launch(command) { child_process.spawn(command, ['https://example.test']); }", "child_process.spawn", "command", "unresolved-command"},
		{"js-arguments", "javascript", "const args = ['https://example.test'];\nfunction launch(args) { child_process.execFile('curl', args); }", "child_process.execFile", "args", "unresolved-process-arguments"},
		{"js-element", "javascript", "const url = 'https://example.test';\nfunction launch(url) { child_process.spawn('curl', [url]); }", "child_process.spawn", "url", "unresolved-process-arguments"},
		{"js-comments", "javascript", "const url = 'https://example.test';\nfunction launch(/* first */ other, // between\n url /* last */, ) { child_process.execFile(/* executable */ 'curl', [url] /* tail */); }", "child_process.execFile", "url", "unresolved-process-arguments"},
		{"py-process-list", "python", "command = ['curl', 'https://example.test']\ndef launch(command):\n    subprocess.run(command)", "subprocess.run", "command", "unresolved-command"},
		{"py-executable", "python", "command = 'curl'\ndef launch(command):\n    subprocess.run([command, 'https://example.test'])", "subprocess.run", "command", "unresolved-command"},
		{"py-element", "python", "url = 'https://example.test'\ndef launch(url):\n    subprocess.run(['curl', url])", "subprocess.run", "url", "unresolved-process-arguments"},
		{"py-comments", "python", "url = 'https://example.test'\ndef launch( # before\n    other, # between\n    url, # after\n):\n    subprocess.run(['curl', url]) # call", "subprocess.run", "url", "unresolved-process-arguments"},
		{"js-already-unresolved", "javascript", "function launch(url) { child_process.spawn('curl', [url]); }", "child_process.spawn", "url", "unresolved-process-arguments"},
		{"py-already-unresolved", "python", "def launch(command):\n    subprocess.run(command)", "subprocess.run", "command", "unresolved-command"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := simpleParameterResult(test.language, test.source)
			var call report.Operation
			for _, op := range result.Operations {
				if op.Category == "language-call" && op.Command == test.api {
					call = op
				}
				if op.Category == "process-execution-via-"+test.language {
					t.Errorf("parameter selected module command=%q arguments=%q dynamic=%v confidence=%s at %q", op.Command, op.Arguments, op.Dynamic, op.Confidence, op.Evidence.Operation)
				}
			}
			if call.ID == "" || !call.Dynamic || call.Confidence != report.ConfidenceMedium {
				t.Errorf("parameter call has incorrect certainty: %#v", call)
			}
			if len(result.Resources) != 0 || hasFindingCategory(result, test.language+"-literal-process-flow") {
				t.Errorf("guessed parameter supplied dependent evidence: resources=%#v findings=%#v", result.Resources, result.Findings)
			}
			if len(result.Unknowns) != 1 {
				t.Fatalf("call %s needs exactly one parameter unknown, got %#v", call.ID, result.Unknowns)
			}
			u := result.Unknowns[0]
			if u.Reason != report.UnknownUnresolvedFlow || u.Category != test.category || !reflect.DeepEqual(u.AffectedOperations, []string{call.ID}) || len(u.Evidence) != 1 || u.Evidence[0].Operation != call.Evidence.Operation {
				t.Fatalf("unknown lost the affected call/value: %#v", u)
			}
			use := false
			for _, origin := range u.Origins {
				use = use || (origin.Kind == report.OriginUseSite && origin.Name == test.identifier && origin.Evidence.Operation == test.identifier)
				if origin.Kind == report.OriginAssignment && origin.Name == test.identifier {
					t.Errorf("module assignment is not the parameter's origin: %#v", origin)
				}
			}
			if !use || len(u.Origins) > report.MaxUnknownOrigins {
				t.Errorf("parameter use site missing or unbounded: %#v", u.Origins)
			}
			if test.category == "unresolved-process-arguments" && (!strings.Contains(u.Title, "arguments") || strings.Contains(u.Title, "executable")) {
				t.Errorf("known executable described as unknown: %#v", u)
			}
			rule := test.language + "-dynamic-command-unknown/v1"
			if test.category == "unresolved-process-arguments" {
				rule = test.language + "-process-arguments-unknown/v1"
			}
			if u.Provenance != sourceProvenance(rule) || !reflect.DeepEqual(u.SuppressedRules, []string{"command-capability/v1", "operation-correlation/v1"}) {
				t.Errorf("parameter unknown lost provenance or suppression: %#v", u)
			}
		})
	}
}

func TestSimpleFunctionParametersPreserveLiterals(t *testing.T) {
	for _, test := range []struct {
		name, language, source string
		calls                  int
		flow                   bool
	}{
		{"js-incomplete-literal", "javascript", "function launch(é) { child_process.spawn('curl',['https://example.test']); }", 1, false},
		{"py-incomplete-literal", "python", "def launch(K):\n    subprocess.run(['curl','https://example.test'])", 1, false},
		{"js-incomplete-sibling-module", "javascript", "const url='https://example.test'; function opaque(é) {} function sibling(other) { child_process.spawn('curl',[url]); } child_process.execFile('curl',[url]);", 2, true},
		{"py-incomplete-sibling-module", "python", "url='https://example.test'\ndef opaque(K):\n    pass\ndef sibling(other):\n    subprocess.run(['curl',url])\nsubprocess.run(['curl',url])", 2, true},
		{"js-unicode-comment", "javascript", "const url='https://example.test'; function launch(/* K */ $_2) { child_process.spawn('curl',[url]); }", 1, true},
		{"py-unicode-comment", "python", "url='https://example.test'\ndef launch(_a2): # K\n    subprocess.run(['curl',url])", 1, true},
		{"js-rhs-own-context", "javascript", "const é='https://example.test'; const args=[é]; function launch(other) { child_process.spawn('curl',args); }", 1, true},
		{"py-rhs-own-context", "python", "é='https://example.test'\nargs=['curl',é]\ndef launch(other):\n    subprocess.run(args)", 1, true},
		{"js-export-literal", "javascript", "export default function launch(url) { child_process.spawn('curl',['https://example.test']); }", 1, false},
		{"py-generator-literal", "python", "def launch(url):\n    subprocess.run(['curl','https://example.test'])\n    yield 1", 1, false},
		{"js-reassignment-literal", "javascript", "function launch(url) { url='changed'; child_process.spawn('curl',['https://example.test']); }", 1, false},
		{"js-direct-module", "javascript", "child_process.spawn('curl', ['https://example.test']);", 1, false},
		{"js-direct-body", "javascript", "function launch(url) { child_process.execFile('curl', ['https://example.test']); }", 1, false},
		{"js-definition", "javascript", "const args = ['https://example.test']; child_process.spawn('curl', args);", 1, true},
		{"js-chain", "javascript", "const url = 'https://example.test'; const next = url; const args = [next]; function launch(other) { child_process.spawn('curl', args); }", 1, true},
		{"js-sibling", "javascript", "const url = 'https://example.test'; function unrelated(url) {} function launch() { child_process.spawn('curl', [url]); }", 1, true},
		{"js-before-after", "javascript", "const url = 'https://example.test'; child_process.spawn('curl', [url]); function unrelated(url) {} child_process.execFile('curl', [url]);", 2, true},
		{"js-unrelated-comments", "javascript", "const url = 'https://example.test'; function launch(/* before */ other, // end\n) { child_process.spawn('curl', [url] /* tail */); }", 1, true},
		{"js-definition-context", "javascript", "const url = 'https://example.test'; const args = [url]; function launch(url) { child_process.spawn('curl', args); }", 1, true},
		{"py-direct-module", "python", "subprocess.run(['curl', 'https://example.test'])", 1, false},
		{"py-direct-body", "python", "def launch(url):\n    subprocess.run(['curl', 'https://example.test'])", 1, false},
		{"py-definition", "python", "args = ['curl', 'https://example.test']\nsubprocess.run(args)", 1, true},
		{"py-chain", "python", "url = 'https://example.test'\nnext = url\nargs = ['curl', next]\ndef launch(other):\n    subprocess.run(args)", 1, true},
		{"py-sibling", "python", "url = 'https://example.test'\ndef unrelated(url):\n    pass\ndef launch():\n    subprocess.run(['curl', url])", 1, true},
		{"py-before-after", "python", "url = 'https://example.test'\nsubprocess.run(['curl', url])\ndef unrelated(url):\n    pass\nsubprocess.run(['curl', url])", 2, true},
		{"py-unrelated-comments", "python", "url = 'https://example.test'\ndef launch( # before\n    other, # end\n):\n    subprocess.run(['curl', url]) # call", 1, true},
		{"py-definition-context", "python", "url = 'https://example.test'\nargs = ['curl', url]\ndef launch(url):\n    subprocess.run(args)", 1, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := simpleParameterResult(test.language, test.source)
			calls, processes, resources, flows := 0, 0, 0, 0
			for _, op := range result.Operations {
				if op.Category == "language-call" {
					calls++
					if op.Dynamic || op.Confidence != report.ConfidenceHigh {
						t.Errorf("literal call lost certainty: %#v", op)
					}
				}
				if op.Category != "process-execution-via-"+test.language {
					continue
				}
				processes++
				if op.Command != "curl" || !reflect.DeepEqual(op.Arguments, []string{"https://example.test"}) || op.Dynamic || op.Confidence != report.ConfidenceHigh {
					t.Errorf("literal process changed: %#v", op)
				}
				for _, r := range result.Resources {
					if r.Kind == "network-domain" && r.Value == "example.test" && r.RelatedOperationID == op.ID {
						resources++
					}
				}
				for _, f := range result.Findings {
					if f.Category == test.language+"-literal-process-flow" && f.Claim == report.ClaimFact && reflect.DeepEqual(f.Related, []string{op.ID}) {
						flows++
					}
				}
			}
			if calls != test.calls || processes != test.calls || resources != test.calls || len(result.Unknowns) != 0 || (test.flow && flows != test.calls) {
				t.Fatalf("preserved evidence counts: calls=%d processes=%d resources=%d flows=%d unknowns=%#v", calls, processes, resources, flows, result.Unknowns)
			}
		})
	}
}

func simpleParameterResult(language, source string) Result {
	ext := ".js"
	if language == "python" {
		ext = ".py"
		source = "import subprocess\n" + source
	}
	return Sources(withValidManifest(map[string][]byte{"helper" + ext: []byte(source + "\n")}))
}

func TestSimpleFunctionParametersKeepUnsupportedCallsUnknown(t *testing.T) {
	for _, expression := range []string{"buildArguments()", "['--url', runtimeURL]", "[] /* before */ , {shell: true}", "[] /* before */ , callback"} {
		t.Run(expression, func(t *testing.T) {
			result := simpleParameterResult("javascript", "function launch(other) { child_process.spawn('curl', "+expression+"); }")
			call := operationByCategory(t, result, "language-call")
			if !call.Dynamic || len(result.Unknowns) != 1 || !reflect.DeepEqual(result.Unknowns[0].AffectedOperations, []string{call.ID}) || result.Unknowns[0].Category != "unresolved-process-arguments" || len(result.Resources) != 0 {
				t.Fatalf("unsupported function call acquired certainty: %#v", result)
			}
			for _, op := range result.Operations {
				if op.Category == "process-execution-via-javascript" {
					t.Fatalf("unsupported overload produced a process: %#v", op)
				}
			}
		})
	}
}

func TestSimpleFunctionParametersBoundsAndDeterminism(t *testing.T) {
	for _, count := range []int{maxRetainedArguments, maxRetainedArguments + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			var parameters strings.Builder
			for i := 0; i < count-1; i++ {
				fmt.Fprintf(&parameters, "p%d,", i)
			}
			parameters.WriteString("url")
			source := "const url = 'https://example.test'; function launch(" + parameters.String() + ") { child_process.spawn('curl', [url]); } child_process.execFile('printf', []);"
			result := simpleParameterResult("javascript", source)
			if len(result.Unknowns) != 1 || len(result.Resources) != 0 {
				t.Fatalf("bounded parameter call lost its unknown: %#v", result)
			}
			wantReason := report.UnknownUnresolvedFlow
			if count > maxRetainedArguments {
				wantReason = report.UnknownBudgetExhaustion
			}
			u := result.Unknowns[0]
			if u.Reason != wantReason || len(u.AffectedOperations) != 1 || u.Origins[0].Kind != report.OriginUseSite {
				t.Fatalf("bounded context guessed a value or origin: %#v", u)
			}
			process := operationByCategory(t, result, "process-execution-via-javascript")
			if process.Command != "printf" || process.Dynamic {
				t.Fatalf("unrelated literal control changed: %#v", process)
			}
			for i := 0; i < 3; i++ {
				if got := simpleParameterResult("javascript", source); !reflect.DeepEqual(got, result) {
					t.Fatalf("identical parameter source was nondeterministic on run %d", i)
				}
			}
		})
	}
}

// Exercise the parameter-context budgets directly, without output-string limits
// masking the precise header/name boundary. The syntax is inert parser input.
func TestSimpleFunctionParametersContextBudgets(t *testing.T) {
	for _, language := range []string{"javascript", "python"} {
		grammar := grammars.JavascriptLanguage()
		source := "function launch(url) { child_process.spawn('curl',[url]); }"
		if language == "python" {
			grammar = grammars.PythonLanguage()
			source = "def launch(url):\n    subprocess.run(['curl',url])\n"
		}
		data := []byte(source)
		parser := ts.NewParser(grammar)
		parser.SetTimeoutMicros(treeSitterParseTimeoutMicros)
		tree, err := parser.ParseStrict(data)
		if err != nil {
			t.Fatal(err)
		}
		defer tree.Release()
		if tree.RootNode().HasErrorOrMissing() {
			t.Fatal("invalid inert syntax")
		}
		function := tree.RootNode().NamedChild(0)
		parameters := function.ChildByFieldName("parameters", grammar)
		exactSteps := function.ChildCount() + parameters.ChildCount()
		for _, test := range []struct {
			name         string
			names, steps int
			incomplete   bool
		}{
			{"exact", 1, exactSteps, false}, {"name-exhausted", 0, exactSteps, true}, {"step-exhausted", 1, exactSteps - 1, true},
		} {
			t.Run(language+"/"+test.name, func(t *testing.T) {
				names, steps := test.names, test.steps
				context := treeSitterSimpleParameters(function, grammar, data, language, &names, &steps)
				if context == nil || context.incomplete != test.incomplete || names < 0 || steps < 0 {
					t.Fatalf("unexpected bounded context: %#v names=%d steps=%d", context, names, steps)
				}
				var identifier *ts.Node
				for i := 0; i < parameters.ChildCount(); i++ {
					child := parameters.Child(i)
					if child.Type(grammar) == "identifier" {
						identifier = child
					}
				}
				if identifier == nil || !context.blocks(identifier, data) {
					t.Fatal("context lost parameter binding")
				}
			})
		}
	}
}

func TestSimpleFunctionParametersASCIIIdentifierBoundary(t *testing.T) {
	for _, name := range []string{"a", "Z", "_", "_a2", "a0"} {
		if !treeSitterASCIIIdentifier(name, false) || !treeSitterASCIIIdentifier(name, true) {
			t.Fatal(name)
		}
	}
	for _, name := range []string{"", "2a", "é", "K", `\u0075rl`, "a-b"} {
		if treeSitterASCIIIdentifier(name, false) || treeSitterASCIIIdentifier(name, true) {
			t.Fatal(name)
		}
	}
	if treeSitterASCIIIdentifier("$a2", false) || !treeSitterASCIIIdentifier("$a2", true) {
		t.Fatal("language-specific dollar rule")
	}
}
