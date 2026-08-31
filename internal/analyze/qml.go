package analyze

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
	"mvdan.cc/sh/v3/syntax"
)

type qmlBlock struct {
	start int
	end   int
}

type qmlExpression struct {
	start int
	end   int
	text  string
}

func analyzeQML(name string, data []byte, result *Result) {
	lines := newSourceIndex(data)
	assignments, assignmentsComplete := qmlRootLiteralAssignments(name, data, lines)
	if !assignmentsComplete {
		result.Limitations = append(result.Limitations, report.Limitation{Code: "qml-assignment-analysis-budget", Description: "The bounded QML root-property index reached its 1,024-definition limit. Commands remain visible, but later literal flow and origins may be incomplete.", Path: name})
		appendUnknown(result, report.Unknown{
			ID: "unknown-qml-assignment-budget-" + stablePathID(name), Category: "analysis-coverage", Reason: report.UnknownBudgetExhaustion,
			Scope: report.ScopeRuntime, Confidence: report.ConfidenceHigh, Title: "QML assignment indexing reached its definition budget",
			Description: "More than 1,024 supported root property definitions were present. Command use sites remain visible, but later literal-flow resolution and assignment origins may be unavailable.",
			Evidence:    []report.Evidence{{Path: name, Operation: "QML root properties"}}, SuppressedRules: []string{"qml-literal-command-flow/v1", "command-capability/v1", "operation-correlation/v1"}, Provenance: sourceProvenance("qml-assignment-budget-unknown/v1"),
		})
	}
	for _, block := range qmlProcessBlocks(data) {
		expressions := qmlCommandExpressions(data, block)
		if len(expressions) == 0 {
			continue
		}
		for _, expression := range expressions {
			command, arguments, flowOrigins, resolvedFlow := resolveQMLCommandExpression(expression.text, assignments)
			dynamic := false
			if !resolvedFlow {
				command, arguments, dynamic = qmlCommandArray(expression.text)
			}
			evidenceOperation, evidenceTruncated := boundedEncodedString(strings.TrimSpace(expression.text))
			dynamic = dynamic || evidenceTruncated
			line := lines.lineAt(expression.start)
			op := report.Operation{
				ID:       fmt.Sprintf("op-%s-%d-%d", stablePathID(name), line, len(result.Operations)+1),
				Category: "process-execution", Command: command, Arguments: arguments,
				Dynamic: dynamic, Confidence: report.ConfidenceHigh,
				Evidence:   report.Evidence{Path: name, LineStart: line, LineEnd: lines.lineAt(expression.end), Operation: evidenceOperation, Excerpt: lines.line(line)},
				Provenance: sourceProvenance("qml-process-command/v1"),
			}
			if dynamic {
				op.Confidence = report.ConfidenceMedium
			}
			if command == "" {
				op.Command = "<dynamic>"
				op.Dynamic = true
			}
			if !appendOperation(result, op) {
				continue
			}
			if op.Dynamic {
				origins := []report.ValueOrigin{{Kind: report.OriginUseSite, Name: "Process.command", Evidence: op.Evidence}}
				origins = appendBoundedOrigins(origins, flowOrigins)
				appendUnknown(result, report.Unknown{
					ID: "unknown-qml-command-" + op.ID, Category: "unresolved-command", Reason: report.UnknownDynamicValue,
					Scope: report.ScopeRuntime, Confidence: report.ConfidenceHigh, Title: "QML process command is selected at runtime",
					Description: "The executable or one or more arguments depend on a QML expression that the bounded static analyzer cannot resolve without executing plugin-controlled code.",
					Evidence:    []report.Evidence{op.Evidence}, Origins: origins,
					AffectedOperations: []string{op.ID}, SuppressedRules: []string{"command-capability/v1", "operation-correlation/v1"}, Provenance: sourceProvenance("qml-dynamic-command-unknown/v1"),
				})
			}
			if resolvedFlow && len(flowOrigins) > 0 {
				evidence := make([]report.Evidence, 0, len(flowOrigins)+1)
				for _, origin := range flowOrigins {
					if len(evidence) >= report.MaxFindingEvidence-1 {
						break
					}
					evidence = append(evidence, origin.Evidence)
				}
				evidence = append(evidence, op.Evidence)
				appendFinding(result, report.Finding{
					ID: "finding-qml-literal-flow-" + op.ID, Claim: report.ClaimFact, Severity: report.SeverityInformational, Confidence: report.ConfidenceHigh,
					Category: "qml-literal-command-flow", Title: "QML root property supplies a literal process command",
					Explanation: "Unique bounded root-property definitions supply the cited literal executable and arguments. This establishes static textual value flow, not that runtime control reaches the Process or that execution succeeds.",
					Evidence:    evidence, Related: []string{op.ID}, Provenance: sourceProvenance("qml-literal-command-flow/v1"),
				})
			}
			classifyCall(op, result)
			classifyQMLShell(op, result)
		}
	}
	if assignment, ok := imperativeQMLCommandAssignment(data); ok {
		result.Limitations = append(result.Limitations, report.Limitation{
			Code:        "qml-imperative-command-analysis-unavailable",
			Description: "QML assigns a Process command imperatively. The bounded lexical analyzer does not resolve JavaScript assignments, so the resulting executable and arguments remain unknown.",
			Path:        name,
		})
		line := lines.lineAt(assignment.start)
		evidence := report.Evidence{Path: name, LineStart: line, LineEnd: lines.lineAt(assignment.end), Operation: "imperative Process.command assignment", Excerpt: lines.line(line)}
		appendUnknown(result, report.Unknown{
			ID: "unknown-qml-imperative-" + stablePathID(name) + "-" + strconv.Itoa(line), Category: "unresolved-command", Reason: report.UnknownUnsupportedSyntax,
			Scope: report.ScopeRuntime, Confidence: report.ConfidenceHigh, Title: "Imperative QML command assignment is unresolved",
			Description: "A JavaScript-style property assignment can choose a Process command at runtime. The lexical analyzer records its source location but does not evaluate the assignment or guess which process will run.",
			Evidence:    []report.Evidence{evidence}, Origins: []report.ValueOrigin{{Kind: report.OriginPropertyAssignment, Name: "command", Evidence: evidence}},
			SuppressedRules: []string{"operation-extraction/v1", "command-capability/v1", "operation-correlation/v1"}, Provenance: sourceProvenance("qml-imperative-command-unknown/v1"),
		})
	}
}

func imperativeQMLCommandAssignment(data []byte) (qmlExpression, bool) {
	for index := 0; index < len(data); {
		next, _, ok := nextQMLToken(data, index)
		if !ok {
			return qmlExpression{}, false
		}
		start := index
		index = next
		dot := skipQMLSpaceAndComments(data, index)
		if dot >= len(data) || data[dot] != '.' {
			continue
		}
		after, property, ok := nextQMLToken(data, dot+1)
		if !ok {
			return qmlExpression{}, false
		}
		index = after
		if property != "command" {
			continue
		}
		equals := skipQMLSpaceAndComments(data, after)
		if equals < len(data) && data[equals] == '=' && (equals+1 >= len(data) || data[equals+1] != '=') {
			return qmlExpression{start: start, end: equals + 1}, true
		}
	}
	return qmlExpression{}, false
}

func hasImperativeQMLCommandAssignment(data []byte) bool {
	_, ok := imperativeQMLCommandAssignment(data)
	return ok
}

func classifyQMLShell(op report.Operation, result *Result) {
	command := filepath.Base(op.Command)
	program, shellSyntax, ok := inlineInterpreterProgram(command, op.Arguments)
	if !ok {
		return
	}
	severity := report.SeverityMedium
	title := "Starts a command interpreter with an inline program"
	explanation := "The plugin asks a command interpreter to parse a string at runtime. The nested program requires separate review and may contain expansions that static QML extraction cannot resolve."
	category := "shell-execution"
	ruleID := "qml-inline-shell/v1"
	if !shellSyntax {
		title = "Executes an inline language program"
		explanation = "The plugin asks a language runtime to execute inline source text. This scanner does not parse that language here, so calls and data flow inside the program remain unknown."
		category = "dynamic-execution"
		ruleID = "qml-inline-language/v1"
		result.Limitations = append(result.Limitations, report.Limitation{
			Code:        "inline-dynamic-language-analysis-unavailable",
			Description: "An inline " + command + " program was identified as data but was not semantically parsed. Calls, dependencies, data flow, and decoded or constructed behavior inside it remain unknown.",
			Path:        op.Evidence.Path,
		})
	} else if containsDownloadExecutePipeline(program) {
		severity = report.SeverityHigh
		title = "Downloads content and sends it directly to an interpreter"
		explanation = "The inline shell program contains a parsed pipeline from a network downloader to a command interpreter, allowing the remote response to become code running with the plugin user's authority."
		category = "download-and-execute"
	} else if containsDecodeExecutePipeline(program) {
		title = "Decodes content and sends it directly to an interpreter"
		explanation = "The inline shell program contains a parsed pipeline from a content decoder to a command interpreter. The original behavior is harder to inspect and the decoded content becomes code at runtime."
		category = "encoded-content-execution"
	}
	appendFinding(result, report.Finding{
		ID: "finding-qml-shell-" + op.ID, Claim: report.ClaimFact, Severity: severity,
		Confidence: op.Confidence, Category: category, Title: title, Explanation: explanation,
		Evidence: []report.Evidence{op.Evidence}, Related: []string{op.ID}, Provenance: sourceProvenance(ruleID),
	})
}

func inlineInterpreterProgram(command string, arguments []string) (string, bool, bool) {
	if !isInterpreter(command) {
		return "", false, false
	}
	shellSyntax := command == "sh" || command == "bash" || command == "zsh"
	for index, argument := range arguments {
		accepts := false
		switch command {
		case "node":
			accepts = argument == "-e" || argument == "--eval"
		case "sh", "bash", "zsh":
			accepts = argument == "-c" || (strings.HasPrefix(argument, "-") && !strings.HasPrefix(argument, "--") && strings.Contains(argument[1:], "c"))
		default:
			accepts = argument == "-c"
		}
		if accepts && index+1 < len(arguments) {
			return arguments[index+1], shellSyntax, true
		}
	}
	return "", shellSyntax, false
}

func containsDownloadExecutePipeline(program string) bool {
	return containsPipeline(program, func(left report.Operation, right string) bool {
		return isDownloader(left.Command) && isInterpreter(right)
	})
}

func containsDecodeExecutePipeline(program string) bool {
	return containsPipeline(program, func(left report.Operation, right string) bool {
		return isDecoderOperation(left) && isInterpreter(right)
	})
}

func containsPipeline(program string, matches func(report.Operation, string) bool) bool {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(program), "inline")
	if err != nil {
		return false
	}
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		binary, ok := node.(*syntax.BinaryCmd)
		if !ok || (binary.Op != syntax.Pipe && binary.Op != syntax.PipeAll) {
			return true
		}
		left, ok := directCallOperation(binary.X)
		if !ok {
			return true
		}
		right := directCallCommand(binary.Y)
		if matches(left, right) {
			found = true
			return false
		}
		return true
	})
	return found
}

func directCallOperation(statement *syntax.Stmt) (report.Operation, bool) {
	if stdoutRedirected(statement) {
		return report.Operation{}, false
	}
	call, ok := statement.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return report.Operation{}, false
	}
	command, dynamic := staticWord(call.Args[0])
	arguments := make([]string, 0, len(call.Args)-1)
	for _, word := range call.Args[1:] {
		value, argumentDynamic := staticWord(word)
		arguments = append(arguments, value)
		dynamic = dynamic || argumentDynamic
	}
	operation := report.Operation{Category: "process-execution", Command: command, Arguments: arguments, Dynamic: dynamic}
	return unwrapOperationForAnalysis(operation)
}

func directCallCommand(statement *syntax.Stmt) string {
	operation, ok := directCallOperation(statement)
	if !ok || operation.Dynamic {
		return ""
	}
	return operation.Command
}

func qmlProcessBlocks(data []byte) []qmlBlock {
	var blocks []qmlBlock
	for index := 0; index < len(data); {
		next, token, ok := nextQMLToken(data, index)
		if !ok {
			break
		}
		index = next
		if token != "Process" {
			continue
		}
		brace := skipQMLSpaceAndComments(data, index)
		if brace >= len(data) || data[brace] != '{' {
			continue
		}
		end, matched := matchQMLDelimiter(data, brace, '{', '}')
		if matched {
			blocks = append(blocks, qmlBlock{start: brace + 1, end: end})
			index = end + 1
		}
	}
	return blocks
}

func qmlCommandExpressions(data []byte, block qmlBlock) []qmlExpression {
	var expressions []qmlExpression
	for index := block.start; index < block.end; {
		next, token, ok := nextTopLevelQMLToken(data, index, block.end)
		if !ok {
			break
		}
		index = next
		if token != "command" {
			continue
		}
		colon := skipQMLSpaceAndComments(data, index)
		if colon >= block.end || data[colon] != ':' {
			continue
		}
		start := skipQMLSpaceAndComments(data, colon+1)
		if start >= block.end {
			continue
		}
		end := start
		if data[start] == '[' {
			matchedEnd, matched := matchQMLDelimiter(data[:block.end], start, '[', ']')
			if !matched {
				end = lineEnd(data, start, block.end)
			} else {
				end = matchedEnd + 1
			}
		} else {
			end = lineEnd(data, start, block.end)
		}
		expressions = append(expressions, qmlExpression{start: start, end: end, text: string(data[start:end])})
		index = end
	}
	return expressions
}

func nextTopLevelQMLToken(data []byte, start, limit int) (int, string, bool) {
	braceDepth, bracketDepth, parenDepth := 0, 0, 0
	for index := start; index < limit; {
		if data[index] == '"' || data[index] == '\'' || data[index] == '`' {
			index = skipQMLString(data[:limit], index)
			continue
		}
		if index+1 < limit && data[index] == '/' && data[index+1] == '/' {
			index = lineEnd(data, index, limit)
			continue
		}
		if index+1 < limit && data[index] == '/' && data[index+1] == '*' {
			index += 2
			for index+1 < limit && !(data[index] == '*' && data[index+1] == '/') {
				index++
			}
			if index+1 < limit {
				index += 2
			}
			continue
		}
		switch data[index] {
		case '{':
			braceDepth++
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		default:
			if braceDepth == 0 && bracketDepth == 0 && parenDepth == 0 && isIdentifierStart(rune(data[index])) {
				begin := index
				index++
				for index < limit && isIdentifierPart(rune(data[index])) {
					index++
				}
				return index, string(data[begin:index]), true
			}
		}
		index++
	}
	return limit, "", false
}

func qmlCommandArray(expression string) (string, []string, bool) {
	trimmed := strings.TrimSpace(expression)
	if !strings.HasPrefix(trimmed, "[") || !strings.HasSuffix(trimmed, "]") {
		return "", nil, true
	}
	body := trimmed[1 : len(trimmed)-1]
	var values []string
	dynamic := false
	for index := 0; index < len(body); {
		index = skipSimpleSpace(body, index)
		if index >= len(body) {
			break
		}
		if body[index] == ',' {
			index++
			continue
		}
		if body[index] != '"' && body[index] != '\'' {
			dynamic = true
			for index < len(body) && body[index] != ',' {
				index++
			}
			if len(values) < maxRetainedArguments+1 {
				values = append(values, "<dynamic>")
			}
			continue
		}
		quote := body[index]
		start := index
		index++
		for index < len(body) {
			if body[index] == '\\' {
				index += 2
				continue
			}
			if index < len(body) && body[index] == quote {
				index++
				break
			}
			index++
		}
		raw := body[start:index]
		value, err := strconv.Unquote(raw)
		if err != nil && quote == '\'' && len(raw) >= 2 {
			value = raw[1 : len(raw)-1]
			err = nil
		}
		if err != nil {
			dynamic = true
			value = "<dynamic>"
		}
		if len(value) > maxRetainedStringBytes {
			value = value[:maxRetainedStringBytes]
			dynamic = true
		}
		if len(values) < maxRetainedArguments+1 {
			values = append(values, value)
		} else {
			dynamic = true
		}
	}
	if len(values) == 0 {
		return "", []string{}, dynamic
	}
	return values[0], values[1:], dynamic
}

func nextQMLToken(data []byte, start int) (int, string, bool) {
	index := skipQMLSpaceAndComments(data, start)
	for index < len(data) {
		if data[index] == '"' || data[index] == '\'' || data[index] == '`' {
			index = skipQMLString(data, index)
			index = skipQMLSpaceAndComments(data, index)
			continue
		}
		if isIdentifierStart(rune(data[index])) {
			begin := index
			index++
			for index < len(data) && isIdentifierPart(rune(data[index])) {
				index++
			}
			return index, string(data[begin:index]), true
		}
		index++
		index = skipQMLSpaceAndComments(data, index)
	}
	return index, "", false
}

func skipQMLSpaceAndComments(data []byte, start int) int {
	index := start
	for index < len(data) {
		if unicode.IsSpace(rune(data[index])) {
			index++
			continue
		}
		if index+1 < len(data) && data[index] == '/' && data[index+1] == '/' {
			index = lineEnd(data, index, len(data))
			continue
		}
		if index+1 < len(data) && data[index] == '/' && data[index+1] == '*' {
			index += 2
			for index+1 < len(data) && !(data[index] == '*' && data[index+1] == '/') {
				index++
			}
			if index+1 < len(data) {
				index += 2
			}
			continue
		}
		break
	}
	return index
}

func matchQMLDelimiter(data []byte, start int, open, close byte) (int, bool) {
	depth := 0
	for index := start; index < len(data); index++ {
		if data[index] == '"' || data[index] == '\'' || data[index] == '`' {
			index = skipQMLString(data, index) - 1
			continue
		}
		if index+1 < len(data) && data[index] == '/' && data[index+1] == '/' {
			index = lineEnd(data, index, len(data)) - 1
			continue
		}
		if index+1 < len(data) && data[index] == '/' && data[index+1] == '*' {
			index += 2
			for index+1 < len(data) && !(data[index] == '*' && data[index+1] == '/') {
				index++
			}
			index++
			continue
		}
		if data[index] == open {
			depth++
		} else if data[index] == close {
			depth--
			if depth == 0 {
				return index, true
			}
		}
	}
	return len(data), false
}

func skipQMLString(data []byte, start int) int {
	quote := data[start]
	for index := start + 1; index < len(data); index++ {
		if data[index] == '\\' {
			index++
			continue
		}
		if data[index] == quote {
			return index + 1
		}
	}
	return len(data)
}

func lineEnd(data []byte, start, limit int) int {
	for index := start; index < limit; index++ {
		if data[index] == '\n' || data[index] == ';' {
			return index
		}
	}
	return limit
}

func skipSimpleSpace(value string, start int) int {
	for start < len(value) && unicode.IsSpace(rune(value[start])) {
		start++
	}
	return start
}

func isIdentifierStart(value rune) bool { return value == '_' || unicode.IsLetter(value) }
func isIdentifierPart(value rune) bool  { return isIdentifierStart(value) || unicode.IsDigit(value) }
