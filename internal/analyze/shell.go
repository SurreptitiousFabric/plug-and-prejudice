package analyze

import (
	"bytes"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
	"mvdan.cc/sh/v3/syntax"
)

type Result struct {
	Manifest    *report.Manifest
	Operations  []report.Operation
	Resources   []report.Resource
	Findings    []report.Finding
	Unknowns    []report.Unknown
	Limitations []report.Limitation
}

func Sources(contents map[string][]byte) Result {
	result := Result{}
	analyzeManifest(contents, &result)
	paths := make([]string, 0, len(contents))
	for name := range contents {
		paths = append(paths, name)
	}
	sort.Strings(paths)
	for _, name := range paths {
		data := contents[name]
		if isInertGitMetadata(name) {
			continue
		}
		if isShell(name, data) {
			analyzeShell(name, data, &result)
		} else if strings.EqualFold(filepath.Ext(name), ".qml") {
			analyzeQML(name, data, &result)
		}
	}
	deriveCapabilities(&result)
	annotateScopes(contents, nil, &result)
	addLanguageCoverageLimitations(contents, &result)
	return result
}

func isInertGitMetadata(name string) bool {
	clean := filepath.ToSlash(name)
	return strings.HasPrefix(clean, ".git/objects/") ||
		strings.HasPrefix(clean, ".git/logs/") ||
		(strings.HasPrefix(clean, ".git/hooks/") && strings.HasSuffix(clean, ".sample"))
}

func isShell(name string, data []byte) bool {
	ext := strings.ToLower(filepath.Ext(name))
	if ext == ".sh" || ext == ".bash" || ext == ".zsh" {
		return true
	}
	first, _, _ := bytes.Cut(data, []byte{'\n'})
	line := strings.ToLower(string(first))
	return strings.HasPrefix(line, "#!") && (strings.Contains(line, "sh") || strings.Contains(line, "bash") || strings.Contains(line, "zsh"))
}

func analyzeShell(name string, data []byte, result *Result) {
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(bytes.NewReader(data), name)
	if err != nil {
		result.Limitations = append(result.Limitations, report.Limitation{Code: "shell-parse-error", Description: err.Error(), Path: name})
		return
	}
	operationByCall := make(map[*syntax.CallExpr]report.Operation)
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		command, commandDynamic := staticWord(call.Args[0])
		arguments := make([]string, 0, len(call.Args)-1)
		dynamic := commandDynamic
		for _, word := range call.Args[1:] {
			value, wordDynamic := staticWord(word)
			arguments = append(arguments, value)
			dynamic = dynamic || wordDynamic
		}
		line := int(call.Pos().Line())
		op := report.Operation{
			ID:       fmt.Sprintf("op-%s-%d-%d", stablePathID(name), line, len(result.Operations)+1),
			Category: "process-execution", Command: command, Arguments: arguments,
			Dynamic: dynamic, Confidence: report.ConfidenceHigh,
			Evidence:   report.Evidence{Path: name, LineStart: line, LineEnd: int(call.End().Line()), Operation: printNode(call), Excerpt: sourceLine(data, line)},
			Provenance: sourceProvenance("shell-operation-extraction/v1"),
		}
		if command == "" {
			op.Command = "<dynamic>"
			op.Confidence = report.ConfidenceMedium
		}
		result.Operations = append(result.Operations, op)
		operationByCall[call] = op
		classifyCall(op, result)
		return true
	})
	syntax.Walk(file, func(node syntax.Node) bool {
		binary, ok := node.(*syntax.BinaryCmd)
		if !ok || (binary.Op != syntax.Pipe && binary.Op != syntax.PipeAll) {
			return true
		}
		left := firstOperation(binary.X, operationByCall)
		right := firstOperation(binary.Y, operationByCall)
		if left == nil || right == nil || !isDownloader(left.Command) || !isInterpreter(right.Command) {
			return true
		}
		line := int(binary.Pos().Line())
		result.Findings = append(result.Findings, report.Finding{
			ID:    fmt.Sprintf("finding-download-execute-%s-%d", stablePathID(name), line),
			Claim: report.ClaimFact, Severity: report.SeverityHigh, Confidence: report.ConfidenceHigh,
			Category: "download-and-execute", Title: "Downloads content and sends it directly to an interpreter",
			Explanation: "Network-provided content is passed to a command interpreter without an inspectable file or integrity check between retrieval and execution. The remote response can therefore become code running with the plugin user's authority.",
			Evidence:    []report.Evidence{{Path: name, LineStart: line, LineEnd: int(binary.End().Line()), Operation: printNode(binary), Excerpt: sourceLine(data, line)}},
			Related:     []string{left.ID, right.ID}, Provenance: sourceProvenance("shell-ast/v1"),
		})
		return true
	})
}

func classifyCall(op report.Operation, result *Result) {
	command := filepath.Base(op.Command)
	switch command {
	case "sudo", "pkexec", "su", "doas":
		result.Findings = append(result.Findings, report.Finding{
			ID: "finding-privilege-" + op.ID, Claim: report.ClaimFact,
			Severity: report.SeverityHigh, Confidence: op.Confidence, Category: "privilege-escalation",
			Title:       "Invokes a privilege-elevation command",
			Explanation: "This operation requests execution with another user's authority. Whether elevation succeeds and what authorization is required cannot be established by static analysis alone.",
			Evidence:    []report.Evidence{op.Evidence}, Related: []string{op.ID}, Provenance: sourceProvenance("shell-ast/v1"),
		})
	case "eval":
		result.Findings = append(result.Findings, report.Finding{
			ID: "finding-dynamic-eval-" + op.ID, Claim: report.ClaimFact,
			Severity: report.SeverityMedium, Confidence: op.Confidence, Category: "dynamic-execution",
			Title:       "Evaluates text as shell code",
			Explanation: "The shell reparses text as commands at runtime. Static analysis may not be able to determine the resulting operations, especially when the evaluated value is dynamic.",
			Evidence:    []report.Evidence{op.Evidence}, Related: []string{op.ID}, Provenance: sourceProvenance("shell-ast/v1"),
		})
	}
}

func firstOperation(statement *syntax.Stmt, operations map[*syntax.CallExpr]report.Operation) *report.Operation {
	var found *report.Operation
	syntax.Walk(statement, func(node syntax.Node) bool {
		if found != nil {
			return false
		}
		if call, ok := node.(*syntax.CallExpr); ok {
			if operation, exists := operations[call]; exists {
				copy := operation
				found = &copy
				return false
			}
		}
		return true
	})
	return found
}

func staticWord(word *syntax.Word) (string, bool) {
	var value strings.Builder
	dynamic := false
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			value.WriteString(part.Value)
		case *syntax.SglQuoted:
			value.WriteString(part.Value)
		case *syntax.DblQuoted:
			for _, nested := range part.Parts {
				if literal, ok := nested.(*syntax.Lit); ok {
					value.WriteString(literal.Value)
				} else {
					dynamic = true
					value.WriteString("<dynamic>")
				}
			}
		default:
			dynamic = true
			value.WriteString("<dynamic>")
		}
	}
	return value.String(), dynamic
}

func printNode(node syntax.Node) string {
	var output strings.Builder
	if err := syntax.NewPrinter(syntax.Minify(true)).Print(&output, node); err != nil {
		return ""
	}
	return output.String()
}

func sourceLine(data []byte, line int) string {
	lines := bytes.Split(data, []byte{'\n'})
	if line < 1 || line > len(lines) {
		return ""
	}
	const max = 500
	text := string(lines[line-1])
	if len(text) > max {
		return text[:max] + "…"
	}
	return text
}

func stablePathID(name string) string {
	replacer := strings.NewReplacer("/", "-", ".", "-", "_", "-", " ", "-")
	return strings.Trim(replacer.Replace(strings.ToLower(name)), "-")
}

func isDownloader(command string) bool {
	command = filepath.Base(command)
	return command == "curl" || command == "wget"
}

func isInterpreter(command string) bool {
	command = filepath.Base(command)
	return command == "sh" || command == "bash" || command == "zsh" || command == "python" || command == "python3" || command == "node"
}
