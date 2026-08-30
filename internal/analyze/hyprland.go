package analyze

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

const maxHyprlandLines = 20_000

func isHyprlandConfigPath(name string) bool {
	clean := strings.ToLower(filepath.ToSlash(filepath.Clean(name)))
	base := filepath.Base(clean)
	if base == "hyprland.conf" || strings.HasPrefix(base, "hyprland-") && filepath.Ext(base) == ".conf" {
		return true
	}
	if filepath.Ext(base) != ".conf" {
		return false
	}
	for _, component := range strings.Split(clean, "/") {
		if component == "hypr" || component == "hyprland" {
			return true
		}
	}
	return false
}

// analyzeHyprlandConfig reads a bounded set of exact directives as inert
// text. It does not ask Hyprland, hyprctl, or a shell process to load the file.
func analyzeHyprlandConfig(name string, data []byte, result *Result) {
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		evidence := report.Evidence{Path: name, Operation: "Hyprland configuration"}
		addHyprlandUnknown(result, name, report.UnknownParserFailure, "Hyprland configuration text is invalid", "The file contains invalid UTF-8 or a NUL byte. It was not parsed and no directive was guessed.", evidence, nil)
		result.Limitations = append(result.Limitations, report.Limitation{Code: "hyprland-invalid-text", Description: "The Hyprland configuration contains invalid UTF-8 or a NUL byte and was not parsed.", Path: name})
		return
	}
	lines := newSourceIndex(data)
	lineNumber := 0
	for offset := 0; offset <= len(data); {
		if lineNumber >= maxHyprlandLines {
			evidence := report.Evidence{Path: name, Operation: "Hyprland configuration"}
			addHyprlandUnknown(result, name, report.UnknownBudgetExhaustion, "Hyprland line budget exhausted", "The parser reached its bounded line limit; later directives were not analyzed.", evidence, nil)
			result.Limitations = append(result.Limitations, report.Limitation{Code: "hyprland-line-budget", Description: "The bounded Hyprland parser reached its line limit; later directives were not analyzed.", Path: name})
			break
		}
		end := offset
		for end < len(data) && data[end] != '\n' {
			end++
		}
		lineNumber++
		line := strings.TrimSuffix(string(data[offset:end]), "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			key, value, ok := strings.Cut(line, "=")
			if ok {
				key = strings.ToLower(strings.TrimSpace(key))
				value = strings.TrimSpace(value)
				evidenceText, truncated := boundedEncodedString(key + " = " + value)
				evidence := report.Evidence{Path: name, LineStart: lineNumber, LineEnd: lineNumber, Operation: evidenceText, Excerpt: lines.line(lineNumber)}
				switch {
				case key == "exec" || key == "exec-once" || key == "exec-shutdown":
					analyzeHyprlandExec(name, key, value, evidence, truncated, result)
				case hyprlandBindDirective(key):
					if command, ok := hyprlandBindExec(value, strings.Contains(key[len("bind"):], "d")); ok {
						analyzeHyprlandExec(name, "bind-exec", command, evidence, truncated, result)
					}
				case key == "source":
					analyzeHyprlandSource(name, value, evidence, truncated, result)
				case key == "plugin":
					analyzeHyprlandPlugin(name, value, evidence, truncated, result)
				}
			}
		}
		if end == len(data) {
			break
		}
		offset = end + 1
	}
}

func hyprlandBindDirective(key string) bool {
	if !strings.HasPrefix(key, "bind") {
		return false
	}
	for _, char := range key[len("bind"):] {
		if !strings.ContainsRune("delmnrt", char) {
			return false
		}
	}
	return true
}

func hyprlandBindExec(value string, hasDescription bool) (string, bool) {
	minimum := 2
	if hasDescription {
		minimum = 3
	}
	fieldStart := 0
	fieldIndex := 0
	for index := 0; index <= len(value); index++ {
		if index != len(value) && value[index] != ',' {
			continue
		}
		field := strings.TrimSpace(value[fieldStart:index])
		if fieldIndex >= minimum && field == "exec" {
			if index == len(value) {
				return "", false
			}
			return strings.TrimSpace(value[index+1:]), true
		}
		fieldIndex++
		fieldStart = index + 1
	}
	return "", false
}

func analyzeHyprlandExec(name, directive, value string, evidence report.Evidence, truncated bool, result *Result) {
	program, rulesUnknown := stripHyprlandExecRules(value)
	if program == "" || rulesUnknown {
		addHyprlandUnknown(result, name, report.UnknownUnsupportedSyntax, "Hyprland execution directive is unresolved", "The directive has malformed execution rules or no command. No executable was guessed.", evidence, nil)
		result.Limitations = append(result.Limitations, report.Limitation{Code: "hyprland-exec-unresolved", Description: "A Hyprland execution directive could not be parsed without guessing.", Path: name})
		return
	}
	retainedProgram, programTruncated := boundedEncodedString(program)
	if programTruncated {
		retainedProgram = "<dynamic>"
	}
	directiveOp := report.Operation{
		ID: fmt.Sprintf("op-%s-%d-%d", stablePathID(name), evidence.LineStart, len(result.Operations)+1), Category: "hyprland-exec-directive",
		Command: directive, Arguments: []string{retainedProgram}, Dynamic: truncated || programTruncated, Confidence: report.ConfidenceHigh,
		Evidence: evidence, Provenance: sourceProvenance("hyprland-" + directive + "/v1"),
	}
	if directiveOp.Dynamic {
		directiveOp.Confidence = report.ConfidenceMedium
	}
	if !appendOperation(result, directiveOp) {
		return
	}
	startOperations := len(result.Operations)
	startFindings := len(result.Findings)
	startUnknowns := len(result.Unknowns)
	analyzeShell(name, []byte(program), result)
	shiftHyprlandEmbeddedEvidence(result, startOperations, startFindings, startUnknowns, evidence)
	related := []string{directiveOp.ID}
	for index := startOperations; index < len(result.Operations) && len(related) < report.MaxFindingRelated; index++ {
		related = append(related, result.Operations[index].ID)
	}
	if len(result.Operations) == startOperations && len(result.Unknowns) == startUnknowns {
		addHyprlandUnknown(result, name, report.UnknownUnresolvedFlow, "Hyprland command produced no resolved executable", "The configured shell program did not yield a resolved process operation. No command was guessed.", evidence, []string{directiveOp.ID})
	}
	if directive == "exec-once" || directive == "exec-shutdown" {
		appendFinding(result, report.Finding{
			ID: "finding-hyprland-persistence-" + directiveOp.ID, Claim: report.ClaimFact, Severity: report.SeverityMedium, Confidence: directiveOp.Confidence,
			Category: "persistence", Title: "Declares session-lifecycle command execution", Explanation: "The Hyprland configuration declares a command for compositor startup or shutdown. Static review does not establish installation, configuration loading, session lifecycle, or command success.",
			Evidence: []report.Evidence{evidence}, Related: related, Provenance: sourceProvenance("hyprland-lifecycle-execution/v1"),
		})
	}
	if directiveOp.Dynamic {
		addHyprlandUnknown(result, name, report.UnknownDynamicValue, "Hyprland command evidence was truncated", "The configured program exceeded retained evidence limits, so its complete runtime behavior remains unresolved.", evidence, []string{directiveOp.ID})
	}
}

func stripHyprlandExecRules(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if !strings.HasPrefix(trimmed, "[") {
		return trimmed, false
	}
	end := strings.IndexByte(trimmed, ']')
	if end < 0 {
		return "", true
	}
	return strings.TrimSpace(trimmed[end+1:]), false
}

func shiftHyprlandEmbeddedEvidence(result *Result, operationStart, findingStart, unknownStart int, directive report.Evidence) {
	shift := func(evidence *report.Evidence) {
		if evidence.LineStart > 0 {
			evidence.LineStart += directive.LineStart - 1
			evidence.LineEnd += directive.LineStart - 1
		}
		evidence.Excerpt = directive.Excerpt
	}
	for index := operationStart; index < len(result.Operations); index++ {
		shift(&result.Operations[index].Evidence)
	}
	for index := findingStart; index < len(result.Findings); index++ {
		for evidenceIndex := range result.Findings[index].Evidence {
			shift(&result.Findings[index].Evidence[evidenceIndex])
		}
	}
	for index := unknownStart; index < len(result.Unknowns); index++ {
		result.Unknowns[index].ID += "-embedded-" + strconv.Itoa(directive.LineStart)
		for evidenceIndex := range result.Unknowns[index].Evidence {
			shift(&result.Unknowns[index].Evidence[evidenceIndex])
		}
		for originIndex := range result.Unknowns[index].Origins {
			shift(&result.Unknowns[index].Origins[originIndex].Evidence)
		}
	}
}

func analyzeHyprlandSource(name, value string, evidence report.Evidence, truncated bool, result *Result) {
	retained, valueTruncated := boundedEncodedString(value)
	dynamic := truncated || valueTruncated || strings.ContainsAny(value, "$%~")
	if valueTruncated {
		retained = "<dynamic>"
	}
	if retained == "" {
		addHyprlandUnknown(result, name, report.UnknownUnsupportedSyntax, "Hyprland source path is empty", "No included configuration path could be resolved.", evidence, nil)
		return
	}
	op := report.Operation{ID: fmt.Sprintf("op-%s-%d-%d", stablePathID(name), evidence.LineStart, len(result.Operations)+1), Category: "hyprland-source-reference", Command: retained,
		Arguments: []string{}, Dynamic: dynamic, Confidence: report.ConfidenceHigh, Evidence: evidence, Provenance: sourceProvenance("hyprland-source/v1")}
	if dynamic {
		op.Confidence = report.ConfidenceMedium
	}
	if !appendOperation(result, op) {
		return
	}
	if dynamic {
		addHyprlandUnknown(result, name, report.UnknownDynamicValue, "Hyprland source path is runtime-dependent", "The included configuration path contains expansion or exceeded retained evidence. No included file relationship was guessed.", evidence, []string{op.ID})
	}
}

func analyzeHyprlandPlugin(name, value string, evidence report.Evidence, truncated bool, result *Result) {
	retained, valueTruncated := boundedEncodedString(value)
	dynamic := truncated || valueTruncated || strings.ContainsAny(value, "$%~")
	if valueTruncated {
		retained = "<dynamic>"
	}
	if retained == "" {
		addHyprlandUnknown(result, name, report.UnknownUnsupportedSyntax, "Hyprland native plugin path is empty", "No plugin path could be resolved.", evidence, nil)
		return
	}
	op := report.Operation{ID: fmt.Sprintf("op-%s-%d-%d", stablePathID(name), evidence.LineStart, len(result.Operations)+1), Category: "native-plugin-load", Command: retained,
		Arguments: []string{}, Dynamic: dynamic, Confidence: report.ConfidenceHigh, Evidence: evidence, Provenance: sourceProvenance("hyprland-native-plugin/v1")}
	if dynamic {
		op.Confidence = report.ConfidenceMedium
	}
	if !appendOperation(result, op) {
		return
	}
	appendFinding(result, report.Finding{
		ID: "finding-hyprland-plugin-" + op.ID, Claim: report.ClaimFact, Severity: report.SeverityMedium, Confidence: op.Confidence,
		Category: "native-code-loading", Title: "Configures a native Hyprland plugin", Explanation: "Hyprland plugins are native code loaded into the compositor process. Static configuration review does not establish installation, loading, binary provenance, or native behavior.",
		Evidence: []report.Evidence{evidence}, Related: []string{op.ID}, Provenance: sourceProvenance("hyprland-native-plugin-loading/v1"),
	})
	if dynamic {
		addHyprlandUnknown(result, name, report.UnknownNativeBehavior, "Hyprland plugin path or behavior is unresolved", "The native plugin path contains expansion or exceeded retained evidence, and native behavior cannot be established from configuration text.", evidence, []string{op.ID})
	}
}

func addHyprlandUnknown(result *Result, name string, reason report.UnknownReason, title, description string, evidence report.Evidence, affected []string) {
	appendUnknown(result, report.Unknown{
		ID: "unknown-hyprland-" + stablePathID(name) + "-" + string(reason) + "-" + strconv.Itoa(evidence.LineStart), Category: "hyprland-analysis", Reason: reason,
		Scope: report.ScopeUnknown, Confidence: report.ConfidenceHigh, Title: title, Description: description, Evidence: []report.Evidence{evidence},
		Origins: []report.ValueOrigin{{Kind: report.OriginUseSite, Name: "Hyprland directive", Evidence: evidence}}, AffectedOperations: affected,
		SuppressedRules: []string{"hyprland-command/v1", "command-capability/v1", "operation-correlation/v1"}, Provenance: sourceProvenance("hyprland-unknown/v1"),
	})
}
