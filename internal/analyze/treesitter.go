package analyze

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
	gotreesitter "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

const treeSitterParseTimeoutMicros = 2_000_000

const maxTreeSitterOriginNodes = 100_000

type treeSitterAssignment struct {
	name     string
	offset   uint32
	value    *gotreesitter.Node
	topLevel bool
	origin   report.ValueOrigin
}

func treeSitterLanguage(name string, data []byte) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".py", ".pyw":
		return "python"
	case ".js", ".mjs", ".cjs", ".jsx":
		return "javascript"
	}
	firstLine := string(data)
	if newline := strings.IndexByte(firstLine, '\n'); newline >= 0 {
		firstLine = firstLine[:newline]
	}
	if !strings.HasPrefix(firstLine, "#!") {
		return ""
	}
	lower := strings.ToLower(firstLine)
	if strings.Contains(lower, "python") {
		return "python"
	}
	if strings.Contains(lower, "node") {
		return "javascript"
	}
	return ""
}

func analyzeTreeSitter(name string, data []byte, language string, result *Result) {
	var grammar *gotreesitter.Language
	switch language {
	case "python":
		grammar = grammars.PythonLanguage()
	case "javascript":
		grammar = grammars.JavascriptLanguage()
	default:
		return
	}
	if grammar == nil {
		addTreeSitterLimitation(result, name, language, "grammar could not be loaded")
		return
	}
	parser := gotreesitter.NewParser(grammar)
	parser.SetTimeoutMicros(treeSitterParseTimeoutMicros)
	tree, err := parser.ParseStrict(data)
	if err != nil {
		addTreeSitterLimitation(result, name, language, "source did not produce a complete syntax tree")
		return
	}
	defer tree.Release()
	if tree.ParseStoppedEarly() || tree.RootNode() == nil || tree.RootNode().HasErrorOrMissing() {
		addTreeSitterLimitation(result, name, language, "parsing stopped early or the syntax tree contains errors")
		return
	}
	lines := newSourceIndex(data)
	callNodes, assignments, traversalComplete, assignmentsComplete := treeSitterOriginIndex(tree.RootNode(), grammar, name, data, lines, language)
	if !traversalComplete {
		result.Limitations = append(result.Limitations, report.Limitation{
			Code: language + "-origin-analysis-budget", Description: "The bounded syntax-tree origin traversal reached its node limit. Retained call facts remain valid, but later value origins may be missing.", Path: name,
		})
		addTreeSitterUnknown(result, name, language, report.UnknownBudgetExhaustion, "Value-origin traversal reached its node budget", "The syntax tree exceeded the bounded origin-traversal node limit. Calls already retained remain valid, but later assignments and unresolved-value origins may be absent.")
	}
	if !assignmentsComplete {
		result.Limitations = append(result.Limitations, report.Limitation{Code: language + "-assignment-analysis-budget", Description: "The bounded assignment index reached its retained-definition limit. Calls remain valid, but literal flow and origins may be incomplete.", Path: name})
		addTreeSitterUnknown(result, name, language, report.UnknownBudgetExhaustion, "Assignment indexing reached its definition budget", "More than 1,024 assignment definitions were present. Calls remain visible, but later literal-flow resolution and textual origins are unavailable.")
	}
	for _, call := range gotreesitter.ExtractCalls(tree) {
		if call.Name == "" {
			continue
		}
		lineStart := lines.lineAt(boundedOffset(call.StartByte, len(data)))
		lineEnd := lines.lineAt(boundedOffset(call.EndByte, len(data)))
		command := call.Name
		if call.Receiver != "" {
			command = call.Receiver + "." + call.Name
		}
		op := report.Operation{
			ID:       fmt.Sprintf("op-%s-%d-%d", stablePathID(name), lineStart, len(result.Operations)+1),
			Category: "language-call", Command: command, Arguments: []string{},
			Dynamic: false, Confidence: report.ConfidenceHigh,
			Evidence:   report.Evidence{Path: name, LineStart: lineStart, LineEnd: lineEnd, Operation: boundedSourceSlice(data, call.StartByte, call.EndByte), Excerpt: lines.line(lineStart)},
			Provenance: sourceProvenance(language + "-call-extraction/v1"),
		}
		callNode := callNodes[treeSitterNodeKey(call.StartByte, call.EndByte)]
		argument := firstTreeSitterArgument(callNode, grammar)
		isExecution := isTreeSitterExecutionAPI(language, command)
		var processValues []string
		var processOrigins []report.ValueOrigin
		processResolved := false
		if isExecution {
			processValues, processOrigins, processResolved = resolveTreeSitterProcessValues(language, callNode, argument, grammar, assignments, data)
		}
		if isExecution && !processResolved {
			op.Dynamic = true
			op.Confidence = report.ConfidenceMedium
		}
		if !appendOperation(result, op) {
			return
		}
		if isExecution {
			if processResolved && len(processValues) > 0 {
				resolved := report.Operation{
					ID:       fmt.Sprintf("op-%s-%d-%d", stablePathID(name), lineStart, len(result.Operations)+1),
					Category: "process-execution-via-" + language, Command: processValues[0], Arguments: append([]string(nil), processValues[1:]...),
					Dynamic: false, Confidence: report.ConfidenceHigh, Evidence: op.Evidence,
					Provenance: sourceProvenance(language + "-literal-process-flow/v1"),
				}
				if appendOperation(result, resolved) && len(processOrigins) > 0 {
					appendFinding(result, report.Finding{
						ID: "finding-" + language + "-literal-process-flow-" + resolved.ID, Claim: report.ClaimFact,
						Severity: report.SeverityInformational, Confidence: report.ConfidenceHigh, Category: language + "-literal-process-flow",
						Title:       treeSitterLanguageLabel(language) + " literal assignment flows into process execution",
						Explanation: "A bounded, module-level, single-definition literal assignment supplies the executable or argument list. This establishes static textual value flow, not that runtime control reaches the call.",
						Evidence:    []report.Evidence{processOrigins[0].Evidence, resolved.Evidence}, Related: []string{resolved.ID}, Provenance: sourceProvenance(language + "-literal-process-flow/v1"),
					})
				}
			}
		}
		if op.Dynamic {
			origins := treeSitterDynamicOrigins(argument, grammar, assignments, name, data, lines)
			appendUnknown(result, report.Unknown{
				ID: "unknown-" + language + "-command-" + op.ID, Category: "unresolved-command", Reason: report.UnknownUnresolvedFlow,
				Scope: report.ScopeRuntime, Confidence: report.ConfidenceHigh, Title: treeSitterLanguageLabel(language) + " process executable is selected at runtime",
				Description: "A process-execution API receives a value that is not a bounded literal string or literal string array. The cited assignment is the nearest preceding textual definition, not proof of runtime control flow.",
				Evidence:    []report.Evidence{op.Evidence}, Origins: origins, AffectedOperations: []string{op.ID},
				SuppressedRules: []string{"command-capability/v1", "operation-correlation/v1"}, Provenance: sourceProvenance(language + "-dynamic-command-unknown/v1"),
			})
		}
	}
}

func treeSitterNodeKey(start, end uint32) uint64 { return uint64(start)<<32 | uint64(end) }

func treeSitterOriginIndex(root *gotreesitter.Node, grammar *gotreesitter.Language, name string, data []byte, lines sourceIndex, language string) (map[uint64]*gotreesitter.Node, []treeSitterAssignment, bool, bool) {
	calls := make(map[uint64]*gotreesitter.Node)
	assignments := make([]treeSitterAssignment, 0, 32)
	stack := []*gotreesitter.Node{root}
	visited := 0
	assignmentsComplete := true
	for len(stack) > 0 && visited < maxTreeSitterOriginNodes {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if node == nil {
			continue
		}
		visited++
		typeName := node.Type(grammar)
		if typeName == "call" || typeName == "call_expression" {
			calls[treeSitterNodeKey(node.StartByte(), node.EndByte())] = node
		}
		if assignmentName, value, topLevel, ok := treeSitterAssignmentParts(node, grammar, data, language); ok {
			if len(assignments) < 1024 {
				assignments = append(assignments, treeSitterAssignment{name: assignmentName, offset: node.StartByte(), origin: report.ValueOrigin{
					Kind: report.OriginAssignment, Name: assignmentName, Evidence: treeSitterNodeEvidence(name, data, lines, node),
				}, value: value, topLevel: topLevel})
			} else {
				assignmentsComplete = false
			}
		}
		for index := node.NamedChildCount() - 1; index >= 0; index-- {
			stack = append(stack, node.NamedChild(index))
		}
	}
	return calls, assignments, len(stack) == 0, assignmentsComplete
}

func treeSitterAssignmentParts(node *gotreesitter.Node, grammar *gotreesitter.Language, data []byte, language string) (string, *gotreesitter.Node, bool, bool) {
	typeName := node.Type(grammar)
	var left, value *gotreesitter.Node
	switch language {
	case "python":
		if typeName != "assignment" {
			return "", nil, false, false
		}
		left = node.ChildByFieldName("left", grammar)
		value = node.ChildByFieldName("right", grammar)
	case "javascript":
		if typeName == "variable_declarator" {
			left = node.ChildByFieldName("name", grammar)
			value = node.ChildByFieldName("value", grammar)
		} else if typeName == "assignment_expression" {
			left = node.ChildByFieldName("left", grammar)
			value = node.ChildByFieldName("right", grammar)
		} else {
			return "", nil, false, false
		}
	}
	if left == nil || value == nil || left.Type(grammar) != "identifier" {
		return "", nil, false, false
	}
	name := treeSitterNodeText(data, left)
	return name, value, treeSitterModuleLevelAssignment(node, grammar, language), name != ""
}

func treeSitterModuleLevelAssignment(node *gotreesitter.Node, grammar *gotreesitter.Language, language string) bool {
	parent := node.Parent()
	if language == "python" {
		return parent != nil && (parent.Type(grammar) == "module" || (parent.Parent() != nil && parent.Parent().Type(grammar) == "module"))
	}
	for steps := 0; parent != nil && steps < 2; steps++ {
		if parent.Type(grammar) == "program" {
			return true
		}
		parent = parent.Parent()
	}
	return false
}

func resolveTreeSitterProcessValues(language string, call, argument *gotreesitter.Node, grammar *gotreesitter.Language, assignments []treeSitterAssignment, data []byte) ([]string, []report.ValueOrigin, bool) {
	if argument == nil {
		return nil, nil, false
	}
	values, origins, ok := resolveTreeSitterLiteral(argument, grammar, assignments, data, argument.StartByte(), make(map[string]bool), 0)
	if !ok || language != "javascript" || len(values) != 1 || call == nil {
		return values, origins, ok
	}
	arguments := call.ChildByFieldName("arguments", grammar)
	if arguments == nil || arguments.NamedChildCount() < 2 {
		return values, origins, true
	}
	extra, extraOrigins, extraOK := resolveTreeSitterLiteral(arguments.NamedChild(1), grammar, assignments, data, arguments.NamedChild(1).StartByte(), make(map[string]bool), 0)
	if !extraOK {
		return values, origins, true
	}
	return append(values, extra...), append(origins, extraOrigins...), true
}

func resolveTreeSitterLiteral(node *gotreesitter.Node, grammar *gotreesitter.Language, assignments []treeSitterAssignment, data []byte, before uint32, seen map[string]bool, depth int) ([]string, []report.ValueOrigin, bool) {
	if node == nil || depth > 16 {
		return nil, nil, false
	}
	switch node.Type(grammar) {
	case "string", "string_literal":
		value, ok := decodeSimpleQuotedLiteral(treeSitterNodeText(data, node))
		return []string{value}, nil, ok
	case "list", "tuple", "array":
		if node.NamedChildCount() == 0 {
			return nil, nil, false
		}
		values := make([]string, 0, node.NamedChildCount())
		origins := make([]report.ValueOrigin, 0)
		for index := 0; index < node.NamedChildCount(); index++ {
			part, partOrigins, ok := resolveTreeSitterLiteral(node.NamedChild(index), grammar, assignments, data, before, seen, depth+1)
			if !ok || len(part) != 1 {
				return nil, nil, false
			}
			values = append(values, part[0])
			origins = append(origins, partOrigins...)
		}
		return values, origins, true
	case "identifier":
		name := treeSitterNodeText(data, node)
		if seen[name] {
			return nil, nil, false
		}
		var match *treeSitterAssignment
		for index := range assignments {
			candidate := &assignments[index]
			if candidate.name != name || candidate.offset >= before || !candidate.topLevel {
				continue
			}
			if match != nil {
				return nil, nil, false
			}
			match = candidate
		}
		if match == nil {
			return nil, nil, false
		}
		seen[name] = true
		values, origins, ok := resolveTreeSitterLiteral(match.value, grammar, assignments, data, match.offset, seen, depth+1)
		delete(seen, name)
		if !ok {
			return nil, nil, false
		}
		return values, append([]report.ValueOrigin{match.origin}, origins...), true
	}
	return nil, nil, false
}

func decodeSimpleQuotedLiteral(value string) (string, bool) {
	if len(value) < 2 || (value[0] != value[len(value)-1]) || (value[0] != '\'' && value[0] != '"') {
		return "", false
	}
	if value[0] == '"' {
		decoded, err := strconv.Unquote(value)
		return decoded, err == nil
	}
	inner := value[1 : len(value)-1]
	if strings.Contains(inner, "\\") {
		return "", false
	}
	return inner, true
}

func firstTreeSitterArgument(call *gotreesitter.Node, grammar *gotreesitter.Language) *gotreesitter.Node {
	if call == nil {
		return nil
	}
	arguments := call.ChildByFieldName("arguments", grammar)
	if arguments == nil || arguments.NamedChildCount() == 0 {
		return nil
	}
	return arguments.NamedChild(0)
}

func isTreeSitterExecutionAPI(language, command string) bool {
	switch language {
	case "python":
		return command == "subprocess.run" || command == "subprocess.Popen" || command == "subprocess.call" || command == "subprocess.check_call" || command == "subprocess.check_output"
	case "javascript":
		return command == "child_process.spawn" || command == "child_process.spawnSync" || command == "child_process.execFile" || command == "child_process.execFileSync" || command == "child_process.fork"
	}
	return false
}

func treeSitterDynamicOrigins(argument *gotreesitter.Node, grammar *gotreesitter.Language, assignments []treeSitterAssignment, name string, data []byte, lines sourceIndex) []report.ValueOrigin {
	if argument == nil {
		return []report.ValueOrigin{{Kind: report.OriginUseSite, Name: "dynamic value", Evidence: report.Evidence{Path: name, Operation: "dynamic value"}}}
	}
	origins := []report.ValueOrigin{{Kind: report.OriginUseSite, Name: treeSitterNodeText(data, argument), Evidence: treeSitterNodeEvidence(name, data, lines, argument)}}
	seen := make(map[string]bool)
	stack := []*gotreesitter.Node{argument}
	visited := 0
	for len(stack) > 0 && len(origins) < report.MaxUnknownOrigins && visited < 4096 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		visited++
		if node.Type(grammar) == "identifier" {
			identifier := treeSitterNodeText(data, node)
			if !seen[identifier] {
				origins = append(origins, report.ValueOrigin{Kind: report.OriginUseSite, Name: identifier, Evidence: treeSitterNodeEvidence(name, data, lines, node)})
				seen[identifier] = true
				if assignment, ok := nearestTreeSitterAssignment(assignments, identifier, node.StartByte()); ok && len(origins) < report.MaxUnknownOrigins {
					origins = append(origins, assignment.origin)
				}
			}
		}
		for index := node.NamedChildCount() - 1; index >= 0; index-- {
			stack = append(stack, node.NamedChild(index))
		}
	}
	if len(origins) > 1 && origins[0].Name == origins[1].Name {
		origins = origins[1:]
	}
	return origins
}

func nearestTreeSitterAssignment(assignments []treeSitterAssignment, name string, before uint32) (treeSitterAssignment, bool) {
	for index := len(assignments) - 1; index >= 0; index-- {
		if assignments[index].name == name && assignments[index].offset < before {
			return assignments[index], true
		}
	}
	return treeSitterAssignment{}, false
}

func treeSitterNodeText(data []byte, node *gotreesitter.Node) string {
	if node == nil {
		return "dynamic value"
	}
	return boundedSourceSlice(data, node.StartByte(), node.EndByte())
}

func treeSitterNodeEvidence(name string, data []byte, lines sourceIndex, node *gotreesitter.Node) report.Evidence {
	if node == nil {
		return report.Evidence{Path: name, Operation: "dynamic value"}
	}
	lineStart := lines.lineAt(boundedOffset(node.StartByte(), len(data)))
	lineEnd := lines.lineAt(boundedOffset(node.EndByte(), len(data)))
	return report.Evidence{Path: name, LineStart: lineStart, LineEnd: lineEnd, Operation: boundedSourceSlice(data, node.StartByte(), node.EndByte()), Excerpt: lines.line(lineStart)}
}

func boundedOffset(offset uint32, length int) int {
	if uint64(offset) > uint64(length) {
		return length
	}
	return int(offset)
}

func boundedSourceSlice(data []byte, start, end uint32) string {
	from := boundedOffset(start, len(data))
	to := boundedOffset(end, len(data))
	if to < from {
		to = from
	}
	const maxEvidenceBytes = 4096
	if to-from > maxEvidenceBytes {
		to = from + maxEvidenceBytes
	}
	return string(data[from:to])
}

func addTreeSitterLimitation(result *Result, name, language, reason string) {
	result.Limitations = append(result.Limitations, report.Limitation{
		Code:        language + "-syntax-analysis-incomplete",
		Description: "The non-executing " + language + " parser could not establish a complete syntax tree: " + reason + ". Calls and data flow may be missing.",
		Path:        name,
	})
	addTreeSitterUnknown(result, name, language, report.UnknownParserFailure, "Syntax could not be analyzed completely", "The non-executing parser could not establish a complete syntax tree. Calls, runtime values, and data-flow origins may be absent.")
}

func addTreeSitterUnknown(result *Result, name, language string, reason report.UnknownReason, title, description string) {
	evidence := report.Evidence{Path: name, Operation: language + " source file"}
	appendUnknown(result, report.Unknown{
		ID: "unknown-" + language + "-analysis-" + stablePathID(name) + "-" + string(reason), Category: "analysis-coverage", Reason: reason,
		Scope: report.ScopeRuntime, Confidence: report.ConfidenceHigh, Title: title, Description: description,
		Evidence: []report.Evidence{evidence}, Origins: []report.ValueOrigin{}, AffectedOperations: []string{},
		SuppressedRules: []string{language + "-call-extraction/v1", "command-capability/v1", "operation-correlation/v1"}, Provenance: sourceProvenance(language + "-analysis-unknown/v1"),
	})
}

func treeSitterLanguageLabel(language string) string {
	if language == "javascript" {
		return "JavaScript"
	}
	if language == "python" {
		return "Python"
	}
	return language
}
