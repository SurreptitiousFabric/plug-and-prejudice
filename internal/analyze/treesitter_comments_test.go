package analyze

import (
	"reflect"
	"strings"
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

// JavaScript fixtures remain inert bytes consumed only by Sources.
func TestJavaScriptProcessTrailingComment(t *testing.T) {
	for _, source := range []string{
		`child_process.spawn("curl", ["https://example.test"]);`,
		`child_process.spawn("curl", ["https://example.test"] /* note */);`,
	} {
		t.Run(source, func(t *testing.T) {
			result := Sources(withValidManifest(map[string][]byte{"helper.js": []byte(source)}))
			var process report.Operation
			for _, op := range result.Operations {
				if op.Category == "process-execution-via-javascript" {
					process = op
				}
			}
			if process.Command != "curl" || !reflect.DeepEqual(process.Arguments, []string{"https://example.test"}) || process.Dynamic || process.Confidence != report.ConfidenceHigh {
				t.Errorf("literal process evidence lost: command=%q arguments=%q dynamic=%v confidence=%s", process.Command, process.Arguments, process.Dynamic, process.Confidence)
			}
			if len(result.Resources) != 1 || result.Resources[0].Kind != "network-domain" || result.Resources[0].Value != "example.test" || result.Resources[0].RelatedOperationID != process.ID {
				t.Errorf("literal process network evidence lost: %#v", result.Resources)
			}
			if len(result.Unknowns) != 0 {
				t.Errorf("literal call has spurious uncertainty: %#v", result.Unknowns)
			}
		})
	}
}

func TestJavaScriptProcessCommentPairs(t *testing.T) {
	for _, api := range []string{"spawn", "spawnSync", "execFile", "execFileSync"} {
		for _, test := range []struct {
			name, plain, commented string
			want                   []string
		}{
			{"trailing-block", `("curl", ["https://example.test"])`, `("curl", ["https://example.test"] /* note */)`, []string{"https://example.test"}},
			{"repeated-comments", `("curl", ["https://example.test"])`, "(" + strings.Repeat("/**/", 128) + `"curl", [` + strings.Repeat("/**/", 128) + `"https://example.test"]` + strings.Repeat("/**/", 128) + ")", []string{"https://example.test"}},
			{"before-executable", `("curl", ["https://example.test"])`, `(/* before */ "curl", ["https://example.test"])`, []string{"https://example.test"}},
			{"between-arguments", `("curl", ["https://example.test"])`, `("curl" /* before comma */, /* after comma */ ["https://example.test"])`, []string{"https://example.test"}},
			{"array-elements", `("curl", ["--url", "https://example.test"])`, `("curl", [/* first */ "--url" /* comma */, /* second */ "https://example.test" /* last */])`, []string{"--url", "https://example.test"}},
			{"empty-array", `("curl", [])`, `("curl", [/* empty */])`, nil},
			{"omitted-array", `("curl")`, `(/* first */ "curl" /* last */)`, nil},
			{"trailing-commas", `("curl", ["https://example.test",],)`, `("curl", ["https://example.test" /* before */, /* after */] /* before */, /* after */)`, []string{"https://example.test"}},
			{"line-comments", `("curl", ["https://example.test"])`, "(// executable\n\"curl\", // array\n[// element\n\"https://example.test\" // end element\n] // end call\n)", []string{"https://example.test"}},
			{"empty-line-comment", `("curl", [])`, "(\"curl\", [// empty\n])", nil},
			{"comment-text-in-strings", `("curl", ["https://example.test/path//part", "--header", "X-Note: /* literal */ // literal"])`, `(/* before */ "curl", ["https://example.test/path//part", /* between */ "--header", "X-Note: /* literal */ // literal"] /* after */)`, []string{"https://example.test/path//part", "--header", "X-Note: /* literal */ // literal"}},
		} {
			t.Run(api+"/"+test.name, func(t *testing.T) {
				for _, arguments := range []string{test.plain, test.commented} {
					result := Sources(withValidManifest(map[string][]byte{"helper.js": []byte("child_process." + api + arguments + ";")}))
					call := operationByCategory(t, result, "language-call")
					process := operationByCategory(t, result, "process-execution-via-javascript")
					if call.Command != "child_process."+api || call.Dynamic || call.Confidence != report.ConfidenceHigh ||
						process.Command != "curl" || !reflect.DeepEqual(process.Arguments, test.want) || process.Dynamic || process.Confidence != report.ConfidenceHigh || len(result.Unknowns) != 0 {
						t.Fatalf("comments changed literal semantics: call=%#v process=%#v unknowns=%#v", call, process, result.Unknowns)
					}
					wantResources := 0
					if len(test.want) > 0 {
						wantResources = 1
					}
					if len(result.Resources) != wantResources {
						t.Fatalf("comments changed literal capabilities: %#v", result.Resources)
					}
					for _, resource := range result.Resources {
						if resource.Kind != "network-domain" || resource.Value != "example.test" || resource.RelatedOperationID != process.ID {
							t.Errorf("comment-bearing capability lost its exact process link: %#v", resource)
						}
					}
					assertAnalyzerResult(t, result)
				}
			})
		}
	}
}

func TestJavaScriptProcessCommentsRetainUncertainty(t *testing.T) {
	for _, api := range []string{"spawn", "execFile"} {
		for _, test := range []struct {
			name, plain, commented, expression, commentedExpression string
		}{
			{"unresolved-list", `("curl", buildArguments())`, `(/* before */ "curl", /* argument */ buildArguments() /* after */)`, "buildArguments()", "buildArguments()"},
			{"partial-array", `("curl", ["https://example.test", runtimeURL])`, `("curl", ["https://example.test", /* value */ runtimeURL /* end */] /* after */)`, `["https://example.test", runtimeURL]`, `["https://example.test", /* value */ runtimeURL /* end */]`},
			{"options-second", `("curl", {shell: true})`, `("curl", /* options */ {shell: true} /* after */)`, "{shell: true}", "{shell: true}"},
			{"options-third", `("curl", ["https://example.test"], {shell: true})`, `(/* before */ "curl", ["https://example.test"] /* middle */, /* options */ {shell: true} /* after */)`, "{shell: true}", "{shell: true}"},
			{"callback-second", `("curl", () => {})`, `("curl", /* callback */ () => {} /* after */)`, "() => {}", "() => {}"},
			{"callback-third", `("curl", [], () => {})`, "(\"curl\", [] /* middle */, // callback\n() => {} /* after */)", "() => {}", "() => {}"},
			{"call-spread", `("curl", ...args)`, `("curl", /* spread */ ...args /* after */)`, "...args", "...args"},
			{"array-spread", `("curl", ["https://example.test", ...args])`, `("curl", ["https://example.test", /* spread */ ...args /* end */])`, `["https://example.test", ...args]`, `["https://example.test", /* spread */ ...args /* end */]`},
			{"sparse-middle", `("curl", ["https://example.test",, "value"])`, `("curl", ["https://example.test", /* hole */, "value"])`, `["https://example.test",, "value"]`, `["https://example.test", /* hole */, "value"]`},
			{"sparse-empty", `("curl", [,])`, `("curl", [/* hole */, /* end */])`, `[,]`, `[/* hole */, /* end */]`},
		} {
			t.Run(api+"/"+test.name, func(t *testing.T) {
				for index, arguments := range []string{test.plain, test.commented} {
					result := Sources(withValidManifest(map[string][]byte{"helper.js": []byte("child_process." + api + arguments + ";")}))
					call := operationByCategory(t, result, "language-call")
					if call.Command != "child_process."+api || !call.Dynamic || call.Confidence != report.ConfidenceMedium {
						t.Errorf("comments concealed uncertain call: %#v", call)
					}
					for _, operation := range result.Operations {
						if operation.Category == "process-execution-via-javascript" {
							t.Errorf("comments produced an unsupported process: %#v", operation)
						}
					}
					if len(result.Unknowns) != 1 {
						t.Fatalf("want the affected call's unknown: %#v", result.Unknowns)
					}
					unknown := result.Unknowns[0]
					expression := test.expression
					if index == 1 {
						expression = test.commentedExpression
					}
					if unknown.Category != "unresolved-process-arguments" || unknown.Reason != report.UnknownUnresolvedFlow ||
						len(unknown.AffectedOperations) != 1 || unknown.AffectedOperations[0] != call.ID ||
						len(unknown.Origins) == 0 || unknown.Origins[0].Evidence.Operation != expression ||
						unknown.Provenance != sourceProvenance("javascript-process-arguments-unknown/v1") {
						t.Errorf("unknown identifies a comment instead of the unsupported expression: %#v", unknown)
					}
					if len(result.Resources) != 0 || hasFindingCategory(result, "javascript-literal-process-flow") {
						t.Errorf("uncertain call produced dependent capabilities/findings: %#v, %#v", result.Resources, result.Findings)
					}
					assertAnalyzerResult(t, result)
				}
			})
		}
	}
	for _, source := range []string{
		`child_process.spawn("curl", ["https://example.test", );`,
		`child_process.spawn(/* before */ "curl", ["https://example.test", /* malformed */ );`,
	} {
		result := Sources(withValidManifest(map[string][]byte{"helper.js": []byte(source)}))
		if len(result.Operations) != 0 || len(result.Unknowns) != 1 || result.Unknowns[0].Reason != report.UnknownParserFailure || !hasLimitationCode(result, "javascript-syntax-analysis-incomplete") {
			t.Errorf("comments concealed malformed syntax: %#v", result)
		}
	}
}

func TestJavaScriptProcessCommentsPreserveLiteralFlowAndBounds(t *testing.T) {
	for _, count := range []int{maxRetainedArguments, maxRetainedArguments + 1} {
		for _, separator := range []string{",", ",/* argument */"} {
			source := "const arg = 'value';\nconst args = [" + strings.Repeat("arg"+separator, count) + "];\nchild_process.execFile(/* exe */ 'tool', /* args */ args /* end */);"
			result := Sources(withValidManifest(map[string][]byte{"helper.js": []byte(source)}))
			if count == maxRetainedArguments {
				process := operationByCategory(t, result, "process-execution-via-javascript")
				if len(process.Arguments) != count || len(result.Unknowns) != 0 {
					t.Fatalf("comments changed exact argument bound: %#v", result)
				}
			} else {
				if !hasLimitationCode(result, "result-production-limit") {
					t.Fatal("comments bypassed the argument bound")
				}
				for _, process := range result.Operations {
					if process.Category == "process-execution-via-javascript" {
						t.Fatal("over-limit arguments retained")
					}
				}
			}
			assertAnalyzerResult(t, result)
		}
	}
	for _, array := range []string{`["https://example.test"]`, `[/* before */ "https://example.test" /* after */]`} {
		result := Sources(withValidManifest(map[string][]byte{"helper.js": []byte("const args = " + array + ";\nchild_process.execFile('curl', args);")}))
		process := operationByCategory(t, result, "process-execution-via-javascript")
		found := false
		for _, finding := range result.Findings {
			if finding.Category == "javascript-literal-process-flow" && len(finding.Related) == 1 && finding.Related[0] == process.ID && finding.Claim == report.ClaimFact {
				found = true
			}
		}
		if !found || len(result.Unknowns) != 0 {
			t.Fatalf("comments discarded literal assignment evidence: %#v", result)
		}
	}
}
