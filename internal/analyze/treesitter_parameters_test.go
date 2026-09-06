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

// Inspect real parameter/use nodes without constructing reports containing long
// call excerpts. Report string ceilings must not mask the identity boundary.
func TestSimpleFunctionParameterIdentityTokenBoundary(t *testing.T) {
	for _, language := range []string{"javascript", "python"} {
		for _, position := range []string{"parameter", "use"} {
			for _, size := range []int{4095, 4096, 4097} {
				t.Run(fmt.Sprintf("%s/%s/%d", language, position, size), func(t *testing.T) {
					identifier := strings.Repeat("p", size)
					parameter, use := identifier, "url"
					if position == "use" {
						parameter, use = "other", identifier
					}
					source := "function launch(" + parameter + ") {\n child_process.spawn('curl',[" + use + "]);\n}"
					grammar := grammars.JavascriptLanguage()
					if language == "python" {
						source = "def launch(" + parameter + "):\n    subprocess.run(['curl'," + use + "])\n"
						grammar = grammars.PythonLanguage()
					}
					data := []byte(source)
					parser := ts.NewParser(grammar)
					parser.SetTimeoutMicros(treeSitterParseTimeoutMicros)
					tree, err := parser.ParseStrict(data)
					if err != nil {
						t.Fatal(err)
					}
					defer tree.Release()
					if tree.ParseStoppedEarly() || tree.RootNode().HasErrorOrMissing() {
						t.Fatal("incomplete inert parse")
					}
					calls, _, complete, _ := treeSitterOriginIndex(tree.RootNode(), grammar, "helper", data, newSourceIndex(data), language)
					if !complete || len(calls) != 1 {
						t.Fatal("missing bounded call context")
					}
					for _, call := range calls {
						if call.parameters == nil {
							t.Fatal("missing parameter context")
						}
						if position == "parameter" {
							if size <= 4096 && !call.parameters.names[identifier] {
								t.Fatal("complete parameter name not retained")
							}
							if size > 4096 && len(call.parameters.names) != 0 {
								t.Error("overlength parameter retained a usable prefix")
							}
						}
						stack := []*ts.Node{call.node}
						found, visited := false, 0
						for len(stack) > 0 && visited < 32 {
							node := stack[len(stack)-1]
							stack = stack[:len(stack)-1]
							visited++
							if node.Type(grammar) == "identifier" && string(data[node.StartByte():node.EndByte()]) == use {
								found = true
								if got := call.parameters.blocks(node, data); got != (size > 4096) {
									t.Errorf("identity blocked=%v at %s size=%d", got, position, size)
								}
							}
							for i := node.ChildCount() - 1; i >= 0; i-- {
								stack = append(stack, node.Child(i))
							}
						}
						if !found || len(stack) != 0 {
							t.Fatal("use not found within bounded traversal")
						}
					}
				})
			}
		}
	}
}

func TestSimpleFunctionParameterUncertaintyCause(t *testing.T) {
	for _, form := range []string{
		"child_process.spawn('curl', ['https://example.test'], callback)",
		"child_process.spawn('curl', ['https://example.test'], {shell: true})",
		"child_process.spawn('curl', buildArguments())",
	} {
		t.Run(form, func(t *testing.T) {
			// The first call requires identity evidence; the second fails for a
			// different reason in the same context; the third is a literal control.
			source := "const url='https://example.test';\nfunction launch(é) {\n child_process.spawn('curl',[url]);\n " + form + ";\n child_process.spawn('printf',['ok']);\n}"
			result := simpleParameterResult("javascript", source)
			var affected, control report.Operation
			for _, op := range result.Operations {
				if op.Category == "language-call" && op.Command == "child_process.spawn" && op.Evidence.LineStart == 4 {
					affected = op
				}
				if op.Category == "process-execution-via-javascript" && op.Command == "printf" {
					control = op
				}
			}
			if affected.ID == "" || !affected.Dynamic || control.Command != "printf" || !reflect.DeepEqual(control.Arguments, []string{"ok"}) || len(result.Resources) != 0 {
				t.Fatal("call form/control evidence changed")
			}
			found := false
			for _, u := range result.Unknowns {
				if !reflect.DeepEqual(u.AffectedOperations, []string{affected.ID}) {
					continue
				}
				found = true
				if u.Reason != report.UnknownUnresolvedFlow || u.Category != "unresolved-process-arguments" || !strings.Contains(u.Description, "literal-argument boundary") || strings.Contains(u.Description, "identity") {
					t.Errorf("unrelated identity context replaced actual call-form cause: %q", u.Description)
				}
			}
			if !found {
				t.Fatal("call-form unknown missing")
			}
		})
	}
}

func TestSimpleFunctionParameterIdentifierSpan(t *testing.T) {
	leaf := func(start, end uint32) *ts.Node {
		return ts.NewLeafNode(0, true, start, end, ts.Point{}, ts.Point{})
	}
	for _, test := range []struct {
		name    string
		node    *ts.Node
		data    string
		want    string
		failure treeSitterParameterFailure
	}{
		{"nil-node", nil, "url", "", treeSitterParameterSpan},
		{"empty-span", leaf(1, 1), "url", "", treeSitterParameterSpan},
		{"reversed-span", leaf(2, 1), "url", "", treeSitterParameterSpan},
		{"end-outside", leaf(0, 4), "url", "", treeSitterParameterSpan},
		{"both-outside", leaf(4, 5), "url", "", treeSitterParameterSpan},
		{"large-end", leaf(0, ^uint32(0)), "url", "", treeSitterParameterSpan},
		{"no-source", leaf(0, 3), "", "", treeSitterParameterSpan},
		{"complete", leaf(0, 3), "url", "url", treeSitterParameterNone},
		{"nonzero-offset", leaf(2, 5), "!!url!", "url", treeSitterParameterNone},
		{"nonascii", leaf(0, 2), "é", "", treeSitterParameterSpelling},
		{"escaped", leaf(0, 8), `\u0075rl`, "", treeSitterParameterSpelling},
	} {
		t.Run(test.name, func(t *testing.T) {
			name, failure := treeSitterParameterIdentifier(test.node, []byte(test.data), true)
			if name != test.want || failure != test.failure {
				t.Fatalf("complete identity=%q cause=%d, want %q cause=%d", name, failure, test.want, test.failure)
			}
		})
	}
	for _, size := range []int{4095, 4096, 4097} {
		t.Run(fmt.Sprintf("bytes-%d", size), func(t *testing.T) {
			identifier := strings.Repeat("p", size)
			name, failure := treeSitterParameterIdentifier(leaf(2, uint32(size+2)), []byte("!!"+identifier+"!"), false)
			if size <= 4096 {
				if name != identifier || failure != treeSitterParameterNone {
					t.Fatal("complete bounded identifier unavailable")
				}
			} else if name != "" || failure != treeSitterParameterLength {
				t.Fatal("overlength identity became a usable prefix")
			}
		})
	}
	for _, identifier := range []string{strings.Repeat("p", 4094) + "é", strings.Repeat("p", 4090) + `\u0078`} {
		name, failure := treeSitterParameterIdentifier(leaf(0, uint32(len(identifier))), []byte(identifier), true)
		if len(identifier) != 4096 || name != "" || failure != treeSitterParameterSpelling {
			t.Fatal("complete token suffix was not inspected")
		}
	}
}

func TestSimpleFunctionParameterResolutionBudgetCause(t *testing.T) {
	for _, language := range []string{"javascript", "python"} {
		for _, use := range []string{"url", "'https://example.test'"} {
			source := "function launch(url) { child_process.spawn('curl',[" + use + "]); }"
			grammar := grammars.JavascriptLanguage()
			if language == "python" {
				source = "def launch(url):\n    subprocess.run(['curl'," + use + "])"
				grammar = grammars.PythonLanguage()
			}
			data := []byte(source)
			parser := ts.NewParser(grammar)
			parser.SetTimeoutMicros(treeSitterParseTimeoutMicros)
			tree, err := parser.ParseStrict(data)
			if err != nil {
				t.Fatal(err)
			}
			defer tree.Release()
			if tree.ParseStoppedEarly() || tree.RootNode().HasErrorOrMissing() {
				t.Fatal("incomplete inert parse")
			}
			calls, assignments, complete, _ := treeSitterOriginIndex(tree.RootNode(), grammar, "helper", data, newSourceIndex(data), language)
			if !complete || len(calls) != 1 {
				t.Fatal("missing bounded call")
			}
			for _, call := range calls {
				call.parameters.incomplete = true
				var failure treeSitterParameterFailure
				_, _, _, resolved := resolveTreeSitterProcessValues(language, call.node, firstTreeSitterArgument(call.node, grammar, language), grammar, assignments, data, call.parameters, &failure)
				if use == "url" {
					if resolved || failure != treeSitterParameterBudget {
						t.Fatal("identifier lost actual context-budget cause")
					}
				} else if !resolved || failure != treeSitterParameterNone {
					t.Fatal("literal acquired unrelated context-budget cause")
				}
			}
		}
	}
}

// Synthetic target text is consumed only as parser/analyser bytes.
func TestSimpleFunctionParameterIdentityUncertainty(t *testing.T) {
	long := strings.Repeat("p", 4096)
	for _, tc := range []struct{ name, lang, module, parameter, use string }{
		{"js-escape4-parameter", "javascript", "url", `\u0075rl`, "url"},
		{"js-escape4-use", "javascript", `\u0075rl`, "url", `\u0075rl`},
		{"js-escape-brace-parameter", "javascript", "url", `\u{75}rl`, "url"},
		{"js-escape-brace-use", "javascript", `\u{75}rl`, "url", `\u{75}rl`},
		{"py-kelvin-parameter", "python", "K", "K", "K"},
		{"py-kelvin-use", "python", "K", "K", "K"},
		{"py-general-identity", "python", "url", "é", "url"},
		{"js-overlength-parameter", "javascript", "url", long + "x", "url"},
		{"js-nonascii-after-truncation", "javascript", "url", long + "é", "url"},
		{"py-overlength-parameter", "python", "url", long + "x", "url"},
		{"py-nonascii-after-truncation", "python", "url", long + "é", "url"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := "const " + tc.module + "='https://example.test';\nfunction launch(" + tc.parameter + ") {\n child_process.spawn('curl',[" + tc.use + "]);\n }"
			grammar := grammars.JavascriptLanguage()
			if tc.lang == "python" {
				source = tc.module + "='https://example.test'\ndef launch(" + tc.parameter + "):\n    subprocess.run(['curl'," + tc.use + "])\n"
				grammar = grammars.PythonLanguage()
			}
			parser := ts.NewParser(grammar)
			parser.SetTimeoutMicros(treeSitterParseTimeoutMicros)
			tree, err := parser.ParseStrict([]byte(source))
			if err != nil {
				t.Fatal(err)
			}
			defer tree.Release()
			if tree.RootNode().HasErrorOrMissing() || tree.ParseStoppedEarly() {
				t.Fatal("probe did not parse as complete inert source")
			}
			r := simpleParameterResult(tc.lang, source)
			var call report.Operation
			for _, op := range r.Operations {
				if op.Category == "language-call" {
					call = op
				}
				if op.Category == "process-execution-via-"+tc.lang {
					t.Errorf("unsupported identity selected command=%q arguments=%q dynamic=%v confidence=%s", op.Command, op.Arguments, op.Dynamic, op.Confidence)
				}
			}
			if len(r.Resources) != 0 {
				t.Errorf("unsupported identity produced %d dependent resources, first=%s:%s", len(r.Resources), r.Resources[0].Kind, r.Resources[0].Value)
			}
			if call.ID == "" || !call.Dynamic || call.Confidence != report.ConfidenceMedium {
				t.Errorf("affected call ID=%q dynamic=%v confidence=%s", call.ID, call.Dynamic, call.Confidence)
			}
			if len(r.Unknowns) != 1 {
				t.Fatalf("affected call %s needs identity uncertainty, unknown count=%d", call.ID, len(r.Unknowns))
			}
			u := r.Unknowns[0]
			if u.Reason != report.UnknownUnresolvedFlow || u.Category != "unresolved-process-arguments" || !reflect.DeepEqual(u.AffectedOperations, []string{call.ID}) {
				t.Errorf("incorrect call-linked identity uncertainty: reason=%s category=%s affected=%v", u.Reason, u.Category, u.AffectedOperations)
			}
			for _, o := range u.Origins {
				if o.Kind == report.OriginAssignment {
					t.Errorf("unsupported identity cited assignment origin %q", o.Name)
				}
			}
			text := strings.ToLower(u.Title + " " + u.Description)
			if !strings.Contains(text, "identifier identity") || strings.Contains(text, "cited assignment") || strings.Contains(text, "options") || strings.Contains(text, "callback") || strings.Contains(text, "selected at runtime") {
				t.Errorf("unknown does not explain unsupported identifier identity: title=%q description=%q", u.Title, u.Description)
			}
			cause := "spelling"
			if len(tc.parameter) > 4096 {
				cause = "4,096"
			}
			if !strings.Contains(u.Description, cause) {
				t.Errorf("identity cause %q missing from %q", cause, u.Description)
			}
			if strings.Contains(u.Title, "executable") || !strings.Contains(u.Description, "executable") {
				t.Errorf("known executable distinction lost: %q / %q", u.Title, u.Description)
			}
		})
	}
}

func TestSimpleFunctionParameterIdentityPreservation(t *testing.T) {
	for _, tc := range []struct {
		name, lang, source string
		command, argument  string
	}{
		{"js-case-sensitive", "javascript", "const url='https://example.test'; function launch(URL) { child_process.spawn('curl',[url]); }", "curl", "https://example.test"},
		{"py-case-sensitive", "python", "url='https://example.test'\ndef launch(URL):\n    subprocess.run(['curl',url])", "curl", "https://example.test"},
		{"js-comment-and-string", "javascript", "function launch(/* \\u{75}rl K */ other) { child_process.spawn('printf',[\"K \\\\u0075rl // /* text */\"]); }", "printf", `K \u0075rl // /* text */`},
		{"py-comment-and-string", "python", "def launch(other): # K \\u0075rl\n    subprocess.run(['printf',\"K \\\\u0075rl // /* text */\"])", "printf", `K \u0075rl // /* text */`},
		{"js-incomplete-literal", "javascript", "function launch(é) { child_process.spawn('curl',['https://example.test']); }", "curl", "https://example.test"},
		{"py-incomplete-literal", "python", "def launch(é):\n    subprocess.run(['curl','https://example.test'])", "curl", "https://example.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := simpleParameterResult(tc.lang, tc.source)
			var process report.Operation
			for _, op := range r.Operations {
				if op.Category == "process-execution-via-"+tc.lang {
					process = op
				}
			}
			if process.Command != tc.command || !reflect.DeepEqual(process.Arguments, []string{tc.argument}) || process.Dynamic || process.Confidence != report.ConfidenceHigh || len(r.Unknowns) != 0 {
				t.Fatalf("preservation changed: command=%q args=%q dynamic=%v confidence=%s unknowns=%v", process.Command, process.Arguments, process.Dynamic, process.Confidence, r.Unknowns)
			}
		})
	}
}

func TestSimpleFunctionParameterExecutableIdentityUncertainty(t *testing.T) {
	for _, tc := range []struct{ lang, source string }{
		{"javascript", "const command='curl'; function launch(é) { child_process.spawn(command,['https://example.test']); }"},
		{"python", "command=['curl','https://example.test']\ndef launch(é):\n    subprocess.run(command)"},
	} {
		t.Run(tc.lang, func(t *testing.T) {
			r := simpleParameterResult(tc.lang, tc.source)
			var call report.Operation
			for _, op := range r.Operations {
				if op.Category == "language-call" {
					call = op
				}
				if op.Category == "process-execution-via-"+tc.lang {
					t.Errorf("unsupported identity selected process %s", op.Command)
				}
			}
			if call.ID == "" || !call.Dynamic || len(r.Resources) != 0 || len(r.Unknowns) != 1 {
				t.Fatalf("missing bounded uncertainty: call=%s dynamic=%v resources=%d unknowns=%d", call.ID, call.Dynamic, len(r.Resources), len(r.Unknowns))
			}
			u := r.Unknowns[0]
			if u.Category != "unresolved-command" || !reflect.DeepEqual(u.AffectedOperations, []string{call.ID}) {
				t.Fatal("unknown lost executable/call relationship")
			}
			for _, o := range u.Origins {
				if o.Kind == report.OriginAssignment {
					t.Error("unrelated module assignment origin retained")
				}
			}
			if !strings.Contains(strings.ToLower(u.Title+" "+u.Description), "identity") || strings.Contains(u.Title, "selected at runtime") || strings.Contains(u.Description, "cited assignment") || !strings.Contains(u.Description, "spelling") {
				t.Errorf("unsupported identity presented as runtime selection: title=%q description=%q", u.Title, u.Description)
			}
		})
	}
}

func TestSimpleFunctionParameterIdentityWrappersAndBodies(t *testing.T) {
	for _, tc := range []struct{ name, lang, source string }{
		{"js-plain", "javascript", "const url='https://example.test'; function launch(url) { child_process.spawn('curl',[url]); }"},
		{"js-export", "javascript", "const url='https://example.test'; export /* before */ function launch(/* arg */ url) { child_process.spawn('curl',[url]); }"},
		{"js-default", "javascript", "const url='https://example.test'; export /* before */ default /* middle */ function launch(url) { child_process.spawn('curl',[url]); }"},
		{"py-yield", "python", "url='https://example.test'\ndef launch(url):\n    yield 1\n    subprocess.run(['curl',url])"},
		{"py-reassignment", "python", "url='https://example.test'\ndef launch(url):\n    url='https://replacement.test'\n    subprocess.run(['curl',url])"},
		{"js-reassignment", "javascript", "const url='https://example.test'; function launch(url) { url='https://replacement.test'; child_process.spawn('curl',[url]); }"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := simpleParameterResult(tc.lang, tc.source)
			var call report.Operation
			for _, op := range r.Operations {
				if op.Category == "language-call" {
					call = op
				}
				if op.Category == "process-execution-via-"+tc.lang {
					t.Errorf("selected process=%s args=%q", op.Command, op.Arguments)
				}
			}
			if call.ID == "" || !call.Dynamic || len(r.Resources) != 0 || len(r.Unknowns) != 1 {
				t.Fatalf("conservative result absent: dynamic=%v resources=%d unknowns=%d", call.Dynamic, len(r.Resources), len(r.Unknowns))
			}
			if !reflect.DeepEqual(r.Unknowns[0].AffectedOperations, []string{call.ID}) {
				t.Fatal("unknown is not exactly linked to call")
			}
		})
	}
}
