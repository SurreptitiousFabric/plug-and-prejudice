package analyze

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
	"mvdan.cc/sh/v3/syntax"
)

type Result struct {
	Manifest                   *report.Manifest
	Operations                 []report.Operation
	Resources                  []report.Resource
	Findings                   []report.Finding
	Unknowns                   []report.Unknown
	Limitations                []report.Limitation
	retainedEncodedStringBytes int
	retainedRelationshipCount  int
}

const (
	maxProducedOperations         = 5_000
	maxProducedResources          = 10_000
	maxProducedFindings           = 10_000
	maxProducedUnknowns           = 5_000
	maxProducedRelationships      = 20_000
	maxRetainedArguments          = report.MaxOperationArguments
	maxRetainedStringBytes        = report.MaxHostileStringBytes - 2 // JSON quotes
	maxAnalysisEncodedStringBytes = 6 << 20
)

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
		} else if language := treeSitterLanguage(name, data); language != "" {
			analyzeTreeSitter(name, data, language, &result)
		}
	}
	expandLiteralCommandWrappers(&result)
	deriveCapabilities(&result)
	annotateScopes(contents, nil, &result)
	addLanguageCoverageLimitations(contents, &result)
	return result
}

const maxWrapperExpansionDepth = 4

func expandLiteralCommandWrappers(result *Result) {
	initial := len(result.Operations)
	for index := 0; index < initial; index++ {
		operation := result.Operations[index]
		if operation.Category != "process-execution" {
			continue
		}
		exhausted := true
		for depth := 0; depth < maxWrapperExpansionDepth; depth++ {
			command, arguments, category, state := literalWrappedCommand(operation)
			switch state {
			case wrapperNotApplicable, wrapperNonExecuting:
				exhausted = false
				break
			case wrapperUnresolved:
				addWrapperLimitation(result, operation, "command-wrapper-resolution", "A command-execution wrapper uses options or a dynamic target that this bounded analyzer cannot resolve without guessing. The wrapper remains visible, but the invoked program and its capabilities are unknown.")
				exhausted = false
				break
			}
			if !exhausted {
				break
			}
			wrapped := derivedWrapperOperation(operation, command, arguments, category)
			if !appendOperation(result, wrapped) {
				break
			}
			classifyCall(wrapped, result)
			operation = wrapped
		}
		if exhausted {
			_, _, _, state := literalWrappedCommand(operation)
			if state != wrapperResolved && state != wrapperUnresolved {
				continue
			}
			addWrapperLimitation(result, operation, "command-wrapper-depth", "A nested command-wrapper chain exceeds the analyzer's four-step expansion limit. Retained wrapper operations remain valid, but the final invoked program and its capabilities are unknown.")
		}
	}
}

func derivedWrapperOperation(operation report.Operation, command string, arguments []string, category string) report.Operation {
	wrapped := operation
	wrapped.ID = operation.ID + "-wrapped"
	wrapped.Category = category
	wrapped.Command = command
	wrapped.Arguments = append([]string(nil), arguments...)
	return wrapped
}

func unwrapOperationForAnalysis(operation report.Operation) (report.Operation, bool) {
	for depth := 0; depth < maxWrapperExpansionDepth; depth++ {
		command, arguments, category, state := literalWrappedCommand(operation)
		switch state {
		case wrapperNotApplicable:
			return operation, true
		case wrapperNonExecuting, wrapperUnresolved:
			return report.Operation{}, false
		case wrapperResolved:
			operation = derivedWrapperOperation(operation, command, arguments, category)
		}
	}
	if _, _, _, state := literalWrappedCommand(operation); state != wrapperNotApplicable {
		return report.Operation{}, false
	}
	return operation, true
}

type wrapperState uint8

const (
	wrapperNotApplicable wrapperState = iota
	wrapperResolved
	wrapperNonExecuting
	wrapperUnresolved
)

func literalWrappedCommand(operation report.Operation) (string, []string, string, wrapperState) {
	command := filepath.Base(operation.Command)
	switch command {
	case "sudo", "doas", "pkexec":
		arguments := operation.Arguments
		if len(arguments) > 0 && arguments[0] == "--" {
			arguments = arguments[1:]
		}
		if len(arguments) == 0 {
			return "", nil, "", wrapperNonExecuting
		}
		if !literalCommandName(arguments[0]) || strings.Contains(arguments[0], "=") {
			return "", nil, "", wrapperUnresolved
		}
		return arguments[0], arguments[1:], "process-execution-via-privilege-wrapper", wrapperResolved
	case "command":
		return literalCommandBuiltin(operation.Arguments)
	case "env":
		return literalEnvCommand(operation.Arguments)
	default:
		return "", nil, "", wrapperNotApplicable
	}
}

func literalCommandBuiltin(arguments []string) (string, []string, string, wrapperState) {
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if argument == "--" {
			index++
			if index >= len(arguments) {
				return "", nil, "", wrapperNonExecuting
			}
			if !literalCommandName(arguments[index]) {
				return "", nil, "", wrapperUnresolved
			}
			return arguments[index], arguments[index+1:], "process-execution-via-command-wrapper", wrapperResolved
		}
		if argument == "-v" || argument == "-V" || argument == "--help" {
			return "", nil, "", wrapperNonExecuting
		}
		if argument == "-p" {
			continue
		}
		if strings.HasPrefix(argument, "-") {
			return "", nil, "", wrapperUnresolved
		}
		if !literalCommandName(argument) {
			return "", nil, "", wrapperUnresolved
		}
		return argument, arguments[index+1:], "process-execution-via-command-wrapper", wrapperResolved
	}
	return "", nil, "", wrapperNonExecuting
}

func literalEnvCommand(arguments []string) (string, []string, string, wrapperState) {
	optionsEnded := false
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if !optionsEnded && argument == "--" {
			optionsEnded = true
			continue
		}
		if !optionsEnded && (argument == "--help" || argument == "--version") {
			return "", nil, "", wrapperNonExecuting
		}
		if !optionsEnded && (argument == "-i" || argument == "--ignore-environment" || argument == "-") {
			continue
		}
		if !optionsEnded && (argument == "-u" || argument == "--unset" || argument == "-C" || argument == "--chdir" || argument == "--argv0") {
			if index+1 >= len(arguments) {
				return "", nil, "", wrapperUnresolved
			}
			index++
			continue
		}
		if !optionsEnded && (strings.HasPrefix(argument, "--unset=") || strings.HasPrefix(argument, "--chdir=") || strings.HasPrefix(argument, "--argv0=")) {
			continue
		}
		if !optionsEnded && strings.HasPrefix(argument, "-") {
			return "", nil, "", wrapperUnresolved
		}
		if strings.Contains(argument, "=") {
			continue
		}
		if !literalCommandName(argument) {
			return "", nil, "", wrapperUnresolved
		}
		return argument, arguments[index+1:], "process-execution-via-command-wrapper", wrapperResolved
	}
	return "", nil, "", wrapperNonExecuting
}

func literalCommandName(value string) bool {
	return value != "" && !strings.HasPrefix(value, "-") && !strings.Contains(value, "<dynamic>")
}

func addWrapperLimitation(result *Result, operation report.Operation, code, description string) {
	for _, limitation := range result.Limitations {
		if limitation.Code == code && limitation.Path == operation.Evidence.Path {
			return
		}
	}
	result.Limitations = append(result.Limitations, report.Limitation{Code: code, Description: description, Path: operation.Evidence.Path})
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
	return recognizedShellShebang(string(first))
}

func recognizedShellShebang(line string) bool {
	if !strings.HasPrefix(line, "#!") {
		return false
	}
	fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "#!")))
	if len(fields) == 0 {
		return false
	}
	interpreter := filepath.Base(fields[0])
	if interpreter == "env" {
		interpreter = ""
		for _, field := range fields[1:] {
			if strings.HasPrefix(field, "-") || strings.Contains(field, "=") {
				continue
			}
			interpreter = filepath.Base(field)
			break
		}
	}
	return interpreter == "sh" || interpreter == "bash" || interpreter == "zsh"
}

func analyzeShell(name string, data []byte, result *Result) {
	lines := newSourceIndex(data)
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(bytes.NewReader(data), name)
	if err != nil {
		description, _ := boundedEncodedString("The shell parser rejected the source: " + err.Error())
		result.Limitations = append(result.Limitations, report.Limitation{Code: "shell-parse-error", Description: description, Path: name})
		evidence := report.Evidence{Path: name, Operation: "shell source file"}
		appendUnknown(result, report.Unknown{
			ID: "unknown-shell-parse-" + stablePathID(name), Category: "analysis-coverage", Reason: report.UnknownParserFailure,
			Scope: report.ScopeUnknown, Confidence: report.ConfidenceHigh, Title: "Shell syntax could not be analyzed completely",
			Description: "The non-executing shell parser rejected the source. Commands and runtime-value origins may be absent.", Evidence: []report.Evidence{evidence},
			Origins: []report.ValueOrigin{}, AffectedOperations: []string{}, SuppressedRules: []string{"operation-extraction/v1", "command-capability/v1", "operation-correlation/v1"}, Provenance: sourceProvenance("shell-analysis-unknown/v1"),
		})
		return
	}
	functions := declaredFunctions(file)
	assignments := shellAssignments(file, name, data, lines)
	functionLimitation := false
	operationByCall := make(map[*syntax.CallExpr]report.Operation)
	var firstDecoder, firstEval *report.Operation
	syntax.Walk(file, func(node syntax.Node) bool {
		if statement, ok := node.(*syntax.Stmt); ok {
			for _, redirect := range statement.Redirs {
				access, target, dynamic, ok := fileRedirection(redirect)
				if !ok {
					continue
				}
				line := int(redirect.Pos().Line())
				confidence := report.ConfidenceHigh
				if dynamic {
					confidence = report.ConfidenceMedium
				}
				appendOperation(result, report.Operation{
					ID:       fmt.Sprintf("op-%s-%d-%d", stablePathID(name), line, len(result.Operations)+1),
					Category: "filesystem-redirection", Command: "shell-redirection", Arguments: []string{access, target},
					Dynamic: dynamic, Confidence: confidence,
					Evidence: report.Evidence{Path: name, LineStart: line, LineEnd: int(redirect.End().Line()), Operation: boundedNodeSource(data, redirect), Excerpt: lines.line(line)},
				})
			}
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		command, commandDynamic := staticWord(call.Args[0])
		arguments := make([]string, 0, min(len(call.Args)-1, maxRetainedArguments))
		dynamic := commandDynamic
		for index, word := range call.Args[1:] {
			value, wordDynamic := staticWord(word)
			if index < maxRetainedArguments {
				arguments = append(arguments, value)
			} else {
				wordDynamic = true
			}
			dynamic = dynamic || wordDynamic
		}
		line := int(call.Pos().Line())
		op := report.Operation{
			ID:       fmt.Sprintf("op-%s-%d-%d", stablePathID(name), line, len(result.Operations)+1),
			Category: "process-execution", Command: command, Arguments: arguments,
			Dynamic: dynamic, Confidence: report.ConfidenceHigh,
			Evidence: report.Evidence{Path: name, LineStart: line, LineEnd: int(call.End().Line()), Operation: boundedNodeSource(data, call), Excerpt: lines.line(line)},
		}
		if dynamic {
			op.Confidence = report.ConfidenceMedium
		}
		if command == "" {
			op.Command = "<dynamic>"
		} else if declaredAt, exists := functions[command]; exists && call.Pos().Offset() > declaredAt {
			op.Category = "shell-function-invocation"
			op.Dynamic = true
			op.Confidence = report.ConfidenceMedium
			if !functionLimitation {
				result.Limitations = append(result.Limitations, report.Limitation{
					Code: "shell-function-resolution", Description: "A command name is also declared as a shell function earlier in this file. External-program capabilities are not attributed to that invocation because runtime function-definition control flow is not established.", Path: name,
				})
				functionLimitation = true
			}
		}
		if !appendOperation(result, op) {
			return true
		}
		if op.Dynamic {
			origins := shellDynamicOrigins(call, assignments, name, data, lines)
			if len(origins) == 0 {
				origins = []report.ValueOrigin{{Kind: report.OriginUseSite, Name: "dynamic shell word", Evidence: op.Evidence}}
			}
			appendUnknown(result, report.Unknown{
				ID: "unknown-shell-command-" + op.ID, Category: "unresolved-command", Reason: report.UnknownDynamicValue,
				Scope: report.ScopeRuntime, Confidence: report.ConfidenceHigh, Title: "Shell command contains runtime-selected values",
				Description: "The executable or arguments use shell expansion or substitution. Origins are bounded textual definitions seen before the use site; they are not a claim that runtime control flow reaches those definitions.",
				Evidence:    []report.Evidence{op.Evidence}, Origins: origins, AffectedOperations: []string{op.ID},
				SuppressedRules: []string{"command-capability/v1", "operation-correlation/v1"}, Provenance: sourceProvenance("shell-dynamic-command-unknown/v1"),
			})
		}
		operationByCall[call] = op
		if op.Category == "process-execution" {
			classifyCall(op, result)
			if firstDecoder == nil && isDecoderOperation(op) {
				copy := op
				firstDecoder = &copy
			}
			if firstEval == nil && filepath.Base(op.Command) == "eval" {
				copy := op
				firstEval = &copy
			}
		}
		return true
	})
	syntax.Walk(file, func(node syntax.Node) bool {
		binary, ok := node.(*syntax.BinaryCmd)
		if !ok || (binary.Op != syntax.Pipe && binary.Op != syntax.PipeAll) {
			return true
		}
		left := directOperation(binary.X, operationByCall)
		right := directOperation(binary.Y, operationByCall)
		if left == nil || right == nil || !isProcessExecution(*left) || !isProcessExecution(*right) || !isInterpreter(right.Command) {
			return true
		}
		line := int(binary.Pos().Line())
		evidence := []report.Evidence{{Path: name, LineStart: line, LineEnd: int(binary.End().Line()), Operation: boundedNodeSource(data, binary), Excerpt: lines.line(line)}}
		if isDownloader(left.Command) {
			appendFinding(result, report.Finding{
				ID:    "finding-download-execute-" + left.ID + "-" + right.ID,
				Claim: report.ClaimFact, Severity: report.SeverityHigh, Confidence: report.ConfidenceHigh,
				Category: "download-and-execute", Title: "Downloads content and sends it directly to an interpreter",
				Explanation: "Network-provided content is passed to a command interpreter without an inspectable file or integrity check between retrieval and execution. The remote response can therefore become code running with the plugin user's authority.",
				Evidence:    evidence, Related: []string{left.ID, right.ID}, Provenance: sourceProvenance("shell-pipeline-download-execute/v1"),
			})
		} else if isDecoderOperation(*left) {
			appendFinding(result, report.Finding{
				ID:    "finding-decoded-execute-" + left.ID + "-" + right.ID,
				Claim: report.ClaimFact, Severity: report.SeverityMedium, Confidence: report.ConfidenceHigh,
				Category: "encoded-content-execution", Title: "Decodes content and sends it directly to an interpreter",
				Explanation: "The parsed pipeline transforms encoded or hexadecimal content and passes the decoded bytes directly to a command interpreter. The original behavior is harder to inspect and the decoded content becomes code at runtime.",
				Evidence:    evidence, Related: []string{left.ID, right.ID}, Provenance: sourceProvenance("shell-pipeline-decoded-execute/v1"),
			})
		}
		return true
	})
	if firstDecoder != nil && firstEval != nil {
		appendFinding(result, report.Finding{
			ID:    "finding-decoder-eval-correlation-" + firstDecoder.ID + "-" + firstEval.ID,
			Claim: report.ClaimInference, Severity: report.SeverityMedium, Confidence: report.ConfidenceMedium,
			Category: "obfuscated-execution", Title: "Combines content decoding with dynamic shell evaluation",
			Explanation: "This source contains both a decoding operation and eval. Together they can conceal shell code until runtime, but static analysis has not established that bytes from the cited decoder reach the cited eval operation.",
			Evidence:    []report.Evidence{firstDecoder.Evidence, firstEval.Evidence}, Related: []string{firstDecoder.ID, firstEval.ID},
			Provenance: sourceProvenance("decoder-eval-correlation/v1"),
		})
	}
}

type shellAssignment struct {
	name   string
	offset uint
	origin report.ValueOrigin
}

func shellAssignments(file *syntax.File, name string, data []byte, lines sourceIndex) []shellAssignment {
	assignments := make([]shellAssignment, 0, 32)
	syntax.Walk(file, func(node syntax.Node) bool {
		assignment, ok := node.(*syntax.Assign)
		if !ok || assignment.Name == nil || len(assignments) >= 1024 {
			return true
		}
		line := int(assignment.Pos().Line())
		assignments = append(assignments, shellAssignment{name: assignment.Name.Value, offset: assignment.Pos().Offset(), origin: report.ValueOrigin{
			Kind: report.OriginAssignment, Name: assignment.Name.Value,
			Evidence: report.Evidence{Path: name, LineStart: line, LineEnd: int(assignment.End().Line()), Operation: boundedNodeSource(data, assignment), Excerpt: lines.line(line)},
		}})
		return true
	})
	return assignments
}

func shellDynamicOrigins(call *syntax.CallExpr, assignments []shellAssignment, name string, data []byte, lines sourceIndex) []report.ValueOrigin {
	origins := make([]report.ValueOrigin, 0, report.MaxUnknownOrigins)
	seen := make(map[string]bool)
	for _, word := range call.Args {
		syntax.Walk(word, func(node syntax.Node) bool {
			parameter, ok := node.(*syntax.ParamExp)
			if !ok || parameter.Param == nil || len(origins) >= report.MaxUnknownOrigins {
				return true
			}
			variable := parameter.Param.Value
			key := "parameter\x00" + variable
			if !seen[key] {
				line := int(parameter.Pos().Line())
				origins = append(origins, report.ValueOrigin{Kind: report.OriginParameterExpansion, Name: variable, Evidence: report.Evidence{
					Path: name, LineStart: line, LineEnd: int(parameter.End().Line()), Operation: boundedNodeSource(data, parameter), Excerpt: lines.line(line),
				}})
				seen[key] = true
			}
			for index := len(assignments) - 1; index >= 0 && len(origins) < report.MaxUnknownOrigins; index-- {
				assignment := assignments[index]
				if assignment.name == variable && assignment.offset < parameter.Pos().Offset() {
					assignmentKey := "assignment\x00" + variable + "\x00" + strconv.FormatUint(uint64(assignment.offset), 10)
					if !seen[assignmentKey] {
						origins = append(origins, assignment.origin)
						seen[assignmentKey] = true
					}
					break
				}
			}
			return true
		})
		if len(origins) >= report.MaxUnknownOrigins {
			break
		}
	}
	return origins
}

func fileRedirection(redirect *syntax.Redirect) (access, target string, dynamic, ok bool) {
	switch redirect.Op {
	case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.RdrAllClob, syntax.AppAll, syntax.AppAllClob:
		access = "write"
	case syntax.RdrIn:
		access = "read"
	case syntax.RdrInOut:
		access = "read-write"
	case syntax.DplOut:
		access = "write"
	default:
		return "", "", false, false
	}
	if redirect.Word == nil {
		return "", "", false, false
	}
	target, dynamic = staticWord(redirect.Word)
	if target == "" || target == "-" || (!dynamic && decimal(target)) {
		return "", "", false, false
	}
	return access, target, dynamic, true
}

func declaredFunctions(file *syntax.File) map[string]uint {
	functions := make(map[string]uint)
	syntax.Walk(file, func(node syntax.Node) bool {
		declaration, ok := node.(*syntax.FuncDecl)
		if !ok {
			return true
		}
		record := func(name *syntax.Lit) {
			if previous, exists := functions[name.Value]; !exists || declaration.Pos().Offset() < previous {
				functions[name.Value] = declaration.Pos().Offset()
			}
		}
		if declaration.Name != nil {
			record(declaration.Name)
		}
		for _, name := range declaration.Names {
			record(name)
		}
		return true
	})
	return functions
}

func classifyCall(op report.Operation, result *Result) {
	command := filepath.Base(op.Command)
	switch command {
	case "sudo", "pkexec", "su", "doas":
		appendFinding(result, report.Finding{
			ID: "finding-privilege-" + op.ID, Claim: report.ClaimFact,
			Severity: report.SeverityHigh, Confidence: op.Confidence, Category: "privilege-escalation",
			Title:       "Invokes a privilege-elevation command",
			Explanation: "This operation requests execution with another user's authority. Whether elevation succeeds and what authorization is required cannot be established by static analysis alone.",
			Evidence:    []report.Evidence{op.Evidence}, Related: []string{op.ID}, Provenance: sourceProvenance("privilege-elevation/v1"),
		})
	case "eval":
		appendFinding(result, report.Finding{
			ID: "finding-dynamic-eval-" + op.ID, Claim: report.ClaimFact,
			Severity: report.SeverityMedium, Confidence: op.Confidence, Category: "dynamic-execution",
			Title:       "Evaluates text as shell code",
			Explanation: "The shell reparses text as commands at runtime. Static analysis may not be able to determine the resulting operations, especially when the evaluated value is dynamic.",
			Evidence:    []report.Evidence{op.Evidence}, Related: []string{op.ID}, Provenance: sourceProvenance("dynamic-shell-eval/v1"),
		})
	}
}

func directOperation(statement *syntax.Stmt, operations map[*syntax.CallExpr]report.Operation) *report.Operation {
	if stdoutRedirected(statement) {
		return nil
	}
	call, ok := statement.Cmd.(*syntax.CallExpr)
	if !ok {
		return nil
	}
	operation, exists := operations[call]
	if !exists {
		return nil
	}
	unwrapped, ok := unwrapOperationForAnalysis(operation)
	if !ok {
		return nil
	}
	return &unwrapped
}

func stdoutRedirected(statement *syntax.Stmt) bool {
	for _, redirect := range statement.Redirs {
		if redirect.N != nil {
			if redirect.N.Value == "1" {
				return true
			}
			continue
		}
		switch redirect.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.DplOut, syntax.RdrClob,
			syntax.RdrAll, syntax.RdrAllClob, syntax.AppAll, syntax.AppAllClob:
			return true
		}
	}
	return false
}

func staticWord(word *syntax.Word) (string, bool) {
	var value strings.Builder
	dynamic := false
	write := func(text string) {
		remaining := maxRetainedStringBytes - value.Len()
		if remaining <= 0 {
			dynamic = true
			return
		}
		if len(text) > remaining {
			text = text[:remaining]
			dynamic = true
		}
		value.WriteString(text)
	}
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			write(part.Value)
		case *syntax.SglQuoted:
			write(part.Value)
		case *syntax.DblQuoted:
			for _, nested := range part.Parts {
				if literal, ok := nested.(*syntax.Lit); ok {
					write(literal.Value)
				} else {
					dynamic = true
					write("<dynamic>")
				}
			}
		default:
			dynamic = true
			write("<dynamic>")
		}
	}
	return value.String(), dynamic
}

func boundedNodeSource(data []byte, node syntax.Node) string {
	start, end := int(node.Pos().Offset()), int(node.End().Offset())
	if start < 0 || start > len(data) {
		return ""
	}
	if end < start {
		end = start
	}
	if end > len(data) {
		end = len(data)
	}
	if end-start > maxRetainedStringBytes {
		end = start + maxRetainedStringBytes
	}
	return string(data[start:end])
}

func appendOperation(result *Result, operation report.Operation) bool {
	if operation.Provenance.RuleID == "" {
		operation.Provenance = sourceProvenance("operation-extraction/v1")
	}
	if len(result.Operations) >= maxProducedOperations {
		addProductionLimitation(result, operation.Evidence.Path, "operations")
		return false
	}
	if len(operation.Arguments) > maxRetainedArguments {
		addProductionLimitation(result, operation.Evidence.Path, "operation argument")
		return false
	}
	stringsToCharge := []string{operation.Category, operation.Command, operation.Evidence.Path, operation.Evidence.Operation, operation.Evidence.Excerpt,
		operation.Provenance.RuleID, operation.Provenance.Analyzer, operation.Provenance.AnalyzerVersion, string(operation.Provenance.EvidenceSource)}
	stringsToCharge = append(stringsToCharge, operation.Arguments...)
	if !chargeAnalysisStrings(result, stringsToCharge...) {
		addProductionLimitation(result, operation.Evidence.Path, "encoded analysis strings")
		return false
	}
	result.Operations = append(result.Operations, operation)
	return true
}

func appendResource(result *Result, resource report.Resource) bool {
	if resource.Provenance.RuleID == "" {
		resource.Provenance = sourceProvenance("command-capability/v1")
	}
	if len(result.Resources) >= maxProducedResources {
		addProductionLimitation(result, resource.Evidence.Path, "resources")
		return false
	}
	if result.retainedRelationshipCount >= maxProducedRelationships {
		addProductionLimitation(result, resource.Evidence.Path, "evidence relationships")
		return false
	}
	if !chargeAnalysisStrings(result, resource.Kind, resource.Access, resource.Value, resource.Evidence.Path, resource.Evidence.Operation, resource.Evidence.Excerpt,
		resource.Provenance.RuleID, resource.Provenance.Analyzer, resource.Provenance.AnalyzerVersion, string(resource.Provenance.EvidenceSource)) {
		addProductionLimitation(result, resource.Evidence.Path, "encoded analysis strings")
		return false
	}
	result.Resources = append(result.Resources, resource)
	result.retainedRelationshipCount++
	return true
}

func appendFinding(result *Result, finding report.Finding) bool {
	path := ""
	if len(finding.Evidence) > 0 {
		path = finding.Evidence[0].Path
	}
	if len(result.Findings) >= maxProducedFindings {
		addProductionLimitation(result, path, "findings")
		return false
	}
	if len(finding.Evidence) > report.MaxFindingEvidence || len(finding.Related) > report.MaxFindingRelated {
		addProductionLimitation(result, path, "finding provenance")
		return false
	}
	if len(finding.Related) > maxProducedRelationships-result.retainedRelationshipCount {
		addProductionLimitation(result, path, "evidence relationships")
		return false
	}
	stringsToCharge := []string{finding.Category, finding.Title, finding.Explanation, finding.Provenance.RuleID,
		finding.Provenance.Analyzer, finding.Provenance.AnalyzerVersion, string(finding.Provenance.EvidenceSource)}
	for _, evidence := range finding.Evidence {
		stringsToCharge = append(stringsToCharge, evidence.Path, evidence.Operation, evidence.Excerpt)
	}
	if !chargeAnalysisStrings(result, stringsToCharge...) {
		addProductionLimitation(result, path, "encoded analysis strings")
		return false
	}
	result.Findings = append(result.Findings, finding)
	result.retainedRelationshipCount += len(finding.Related)
	return true
}

func appendUnknown(result *Result, unknown report.Unknown) bool {
	path := ""
	if len(unknown.Evidence) > 0 {
		path = unknown.Evidence[0].Path
	}
	if len(result.Unknowns) >= maxProducedUnknowns {
		addProductionLimitation(result, path, "unknowns")
		return false
	}
	if len(unknown.Evidence) == 0 || len(unknown.Evidence) > report.MaxUnknownEvidence ||
		len(unknown.Origins) > report.MaxUnknownOrigins || len(unknown.AffectedOperations) > report.MaxUnknownAffected ||
		len(unknown.SuppressedRules) > report.MaxUnknownSuppressed {
		addProductionLimitation(result, path, "unknown provenance")
		return false
	}
	if len(unknown.AffectedOperations) > maxProducedRelationships-result.retainedRelationshipCount {
		addProductionLimitation(result, path, "evidence relationships")
		return false
	}
	stringsToCharge := []string{unknown.Category, string(unknown.Reason), unknown.Title, unknown.Description,
		unknown.Provenance.RuleID, unknown.Provenance.Analyzer, unknown.Provenance.AnalyzerVersion, string(unknown.Provenance.EvidenceSource)}
	for _, evidence := range unknown.Evidence {
		stringsToCharge = append(stringsToCharge, evidence.Path, evidence.Operation, evidence.Excerpt)
	}
	for _, origin := range unknown.Origins {
		stringsToCharge = append(stringsToCharge, string(origin.Kind), origin.Name, origin.Evidence.Path, origin.Evidence.Operation, origin.Evidence.Excerpt)
	}
	stringsToCharge = append(stringsToCharge, unknown.SuppressedRules...)
	if !chargeAnalysisStrings(result, stringsToCharge...) {
		addProductionLimitation(result, path, "encoded analysis strings")
		return false
	}
	result.Unknowns = append(result.Unknowns, unknown)
	result.retainedRelationshipCount += len(unknown.AffectedOperations)
	return true
}

func chargeAnalysisStrings(result *Result, values ...string) bool {
	charge := 0
	for _, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil || len(encoded) > report.MaxHostileStringBytes || len(encoded) > maxAnalysisEncodedStringBytes-charge {
			return false
		}
		charge += len(encoded)
	}
	if charge > maxAnalysisEncodedStringBytes-result.retainedEncodedStringBytes {
		return false
	}
	result.retainedEncodedStringBytes += charge
	return true
}

func addProductionLimitation(result *Result, path, scope string) {
	if encoded, _ := json.Marshal(path); len(encoded) > report.MaxHostileStringBytes {
		path = ""
	}
	for _, limitation := range result.Limitations {
		if limitation.Code == "result-production-limit" && limitation.Path == path && strings.Contains(limitation.Description, scope) {
			return
		}
	}
	result.Limitations = append(result.Limitations, report.Limitation{Code: "result-production-limit", Description: "The deterministic " + scope + " production limit was reached; remaining derived entries were not retained.", Path: path})
}

type sourceIndex struct {
	data   []byte
	starts []int
}

func newSourceIndex(data []byte) sourceIndex {
	starts := make([]int, 1, 1+bytes.Count(data, []byte{'\n'}))
	for offset, value := range data {
		if value == '\n' {
			starts = append(starts, offset+1)
		}
	}
	return sourceIndex{data: data, starts: starts}
}

func (index sourceIndex) lineAt(offset int) int {
	if offset < 0 {
		offset = 0
	} else if offset > len(index.data) {
		offset = len(index.data)
	}
	return sort.Search(len(index.starts), func(i int) bool { return index.starts[i] > offset })
}

func (index sourceIndex) line(line int) string {
	if line < 1 || line > len(index.starts) {
		return ""
	}
	start := index.starts[line-1]
	end := len(index.data)
	if line < len(index.starts) {
		end = index.starts[line] - 1
	}
	const max = 500
	text := string(index.data[start:end])
	if len(text) > max {
		return text[:max] + "…"
	}
	return text
}

func stablePathID(name string) string {
	digest := sha256.Sum256([]byte(name))
	return fmt.Sprintf("%x", digest)
}

func isDownloader(command string) bool {
	command = filepath.Base(command)
	return command == "curl" || command == "wget"
}

func isInterpreter(command string) bool {
	command = filepath.Base(command)
	return command == "sh" || command == "bash" || command == "zsh" || command == "python" || command == "python3" || command == "node"
}

func isDecoderOperation(operation report.Operation) bool {
	if !isProcessExecution(operation) || operation.Dynamic {
		return false
	}
	command := filepath.Base(operation.Command)
	switch command {
	case "base64":
		return containsArgument(operation.Arguments, "-d") || containsArgument(operation.Arguments, "--decode")
	case "xxd":
		if !containsArgument(operation.Arguments, "-r") && !containsArgument(operation.Arguments, "--revert") {
			return false
		}
		positional := 0
		for _, argument := range operation.Arguments {
			if argument != "" && !strings.HasPrefix(argument, "-") {
				positional++
			}
		}
		return positional <= 1
	case "openssl":
		if len(operation.Arguments) == 0 || (!containsArgument(operation.Arguments, "-d") && !containsArgument(operation.Arguments, "-decrypt")) {
			return false
		}
		for _, argument := range operation.Arguments {
			if argument == "-out" || strings.HasPrefix(argument, "-out=") {
				return false
			}
		}
		return operation.Arguments[0] == "base64" || (operation.Arguments[0] == "enc" && (containsArgument(operation.Arguments, "-a") || containsArgument(operation.Arguments, "-base64")))
	default:
		return false
	}
}
