package analyze

import (
	"bytes"
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
	for _, block := range qmlProcessBlocks(data) {
		expressions := qmlCommandExpressions(data, block)
		if len(expressions) == 0 {
			continue
		}
		for _, expression := range expressions {
			command, arguments, dynamic := qmlCommandArray(expression.text)
			line := lineAt(data, expression.start)
			op := report.Operation{
				ID:       fmt.Sprintf("op-%s-%d-%d", stablePathID(name), line, len(result.Operations)+1),
				Category: "process-execution", Command: command, Arguments: arguments,
				Dynamic: dynamic, Confidence: report.ConfidenceHigh,
				Evidence: report.Evidence{Path: name, LineStart: line, LineEnd: lineAt(data, expression.end), Operation: strings.TrimSpace(expression.text), Excerpt: sourceLine(data, line)},
			}
			if command == "" {
				op.Command = "<dynamic>"
				op.Dynamic = true
				op.Confidence = report.ConfidenceMedium
			}
			result.Operations = append(result.Operations, op)
			classifyCall(op, result)
			classifyQMLShell(op, result)
		}
	}
	if hasImperativeQMLCommandAssignment(data) {
		result.Limitations = append(result.Limitations, report.Limitation{
			Code:        "qml-imperative-command-analysis-unavailable",
			Description: "QML assigns a Process command imperatively. The bounded lexical analyzer does not resolve JavaScript assignments, so the resulting executable and arguments remain unknown.",
			Path:        name,
		})
	}
}

func hasImperativeQMLCommandAssignment(data []byte) bool {
	for index := 0; index < len(data); {
		next, _, ok := nextQMLToken(data, index)
		if !ok {
			return false
		}
		index = next
		dot := skipQMLSpaceAndComments(data, index)
		if dot >= len(data) || data[dot] != '.' {
			continue
		}
		after, property, ok := nextQMLToken(data, dot+1)
		if !ok {
			return false
		}
		index = after
		if property != "command" {
			continue
		}
		equals := skipQMLSpaceAndComments(data, after)
		if equals < len(data) && data[equals] == '=' && (equals+1 >= len(data) || data[equals+1] != '=') {
			return true
		}
	}
	return false
}

func classifyQMLShell(op report.Operation, result *Result) {
	command := filepath.Base(op.Command)
	if !isInterpreter(command) || len(op.Arguments) < 2 || op.Arguments[0] != "-c" {
		return
	}
	severity := report.SeverityMedium
	title := "Starts a command interpreter with an inline program"
	explanation := "The plugin asks a command interpreter to parse a string at runtime. The nested program requires separate review and may contain expansions that static QML extraction cannot resolve."
	category := "shell-execution"
	if containsDownloadExecutePipeline(op.Arguments[1]) {
		severity = report.SeverityHigh
		title = "Downloads content and sends it directly to an interpreter"
		explanation = "The inline shell program contains a parsed pipeline from a network downloader to a command interpreter, allowing the remote response to become code running with the plugin user's authority."
		category = "download-and-execute"
	}
	result.Findings = append(result.Findings, report.Finding{
		ID: "finding-qml-shell-" + op.ID, Claim: report.ClaimFact, Severity: severity,
		Confidence: op.Confidence, Category: category, Title: title, Explanation: explanation,
		Evidence: []report.Evidence{op.Evidence}, Related: []string{op.ID}, Provenance: "deterministic:qml-lexical+shell-ast",
	})
}

func containsDownloadExecutePipeline(program string) bool {
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
		left := firstCallCommand(binary.X)
		right := firstCallCommand(binary.Y)
		if isDownloader(left) && isInterpreter(right) {
			found = true
			return false
		}
		return true
	})
	return found
}

func firstCallCommand(statement *syntax.Stmt) string {
	command := ""
	syntax.Walk(statement, func(node syntax.Node) bool {
		if command != "" {
			return false
		}
		if call, ok := node.(*syntax.CallExpr); ok && len(call.Args) > 0 {
			value, dynamic := staticWord(call.Args[0])
			if !dynamic {
				command = value
			}
			return false
		}
		return true
	})
	return command
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
		next, token, ok := nextQMLToken(data[:block.end], index)
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
			values = append(values, "<dynamic>")
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
		values = append(values, value)
	}
	if len(values) == 0 {
		return "", []string{}, dynamic
	}
	return values[0], values[1:], dynamic
}

func nextQMLToken(data []byte, start int) (int, string, bool) {
	index := skipQMLSpaceAndComments(data, start)
	for index < len(data) {
		if data[index] == '"' || data[index] == '\'' {
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
		if data[index] == '"' || data[index] == '\'' {
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

func lineAt(data []byte, offset int) int {
	if offset > len(data) {
		offset = len(data)
	}
	return 1 + bytes.Count(data[:offset], []byte{'\n'})
}

func skipSimpleSpace(value string, start int) int {
	for start < len(value) && unicode.IsSpace(rune(value[start])) {
		start++
	}
	return start
}

func isIdentifierStart(value rune) bool { return value == '_' || unicode.IsLetter(value) }
func isIdentifierPart(value rune) bool  { return isIdentifierStart(value) || unicode.IsDigit(value) }
