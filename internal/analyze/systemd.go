package analyze

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

const maxSystemdLines = 20_000

var systemdUnitExtensions = map[string]bool{
	".service": true, ".socket": true, ".timer": true, ".path": true,
	".mount": true, ".automount": true, ".target": true, ".device": true,
	".swap": true, ".slice": true, ".scope": true,
}

type systemdCommand struct {
	command    string
	arguments  []string
	dynamic    bool
	malformed  bool
	privileged bool
}

type systemdLogicalLine struct {
	start int
	end   int
	text  string
}

func isSystemdUnitPath(name string) bool {
	clean := strings.ToLower(filepath.ToSlash(filepath.Clean(name)))
	if systemdUnitExtensions[filepath.Ext(clean)] {
		return true
	}
	if filepath.Ext(clean) != ".conf" {
		return false
	}
	for _, component := range strings.Split(clean, "/") {
		if strings.HasSuffix(component, ".service.d") || strings.HasSuffix(component, ".socket.d") || strings.HasSuffix(component, ".timer.d") || strings.HasSuffix(component, ".path.d") {
			return true
		}
	}
	return false
}

// analyzeSystemdUnit interprets only a bounded, documented subset of unit-file
// syntax. It never calls systemd-analyze, systemctl, a shell, or an executable
// named by hostile unit content.
func analyzeSystemdUnit(name string, data []byte, result *Result) {
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		evidence := report.Evidence{Path: name, Operation: "systemd unit"}
		addSystemdUnknown(result, name, report.UnknownParserFailure, "Systemd unit text is not valid UTF-8", "The unit contains invalid UTF-8 or a NUL byte. It was not tokenized and no directive was guessed.", evidence, nil)
		result.Limitations = append(result.Limitations, report.Limitation{Code: "systemd-unit-invalid-text", Description: "The unit contains invalid UTF-8 or a NUL byte and was not parsed.", Path: name})
		return
	}
	sourceLines := newSourceIndex(data)
	logicalLines, withinBudget, continuationComplete := boundedSystemdLines(data)
	if !withinBudget {
		evidence := report.Evidence{Path: name, Operation: "systemd unit"}
		addSystemdUnknown(result, name, report.UnknownBudgetExhaustion, "Systemd unit line budget exhausted", "The unit parser reached its bounded physical-line limit; later directives were not analyzed.", evidence, nil)
		result.Limitations = append(result.Limitations, report.Limitation{Code: "systemd-unit-line-budget", Description: "The bounded unit parser reached its physical-line limit; later directives were not analyzed.", Path: name})
	}
	if !continuationComplete {
		evidence := report.Evidence{Path: name, Operation: "unterminated line continuation"}
		addSystemdUnknown(result, name, report.UnknownUnsupportedSyntax, "Systemd line continuation is incomplete", "The unit ends while a logical directive is continued. The incomplete directive was not interpreted.", evidence, nil)
		result.Limitations = append(result.Limitations, report.Limitation{Code: "systemd-unit-incomplete-continuation", Description: "The final logical unit directive has an unterminated continuation and was not parsed.", Path: name})
	}
	section := ""
	for _, line := range logicalLines {
		trimmed := strings.TrimSpace(line.text)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			continue
		}
		key, value, ok := strings.Cut(line.text, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		evidenceText, evidenceTruncated := boundedEncodedString(key + "=" + value)
		evidence := report.Evidence{Path: name, LineStart: line.start, LineEnd: line.end, Operation: evidenceText, Excerpt: sourceLines.line(line.start)}
		if systemdExecDirective(section, key) {
			analyzeSystemdExec(name, key, value, evidence, evidenceTruncated, result)
			continue
		}
		if section == "Install" && (key == "WantedBy" || key == "RequiredBy") && value != "" {
			analyzeSystemdInstall(name, key, value, evidence, evidenceTruncated, result)
			continue
		}
		if systemdActivationDirective(section, key) && value != "" {
			analyzeSystemdActivation(name, section, key, value, evidence, evidenceTruncated, result)
			continue
		}
		if (section == "Timer" || section == "Path" || section == "Socket") && key == "Unit" && value != "" {
			analyzeSystemdUnitReference(name, section, value, evidence, evidenceTruncated, result)
		}
	}
}

func systemdActivationDirective(section, key string) bool {
	switch section {
	case "Timer":
		switch key {
		case "OnActiveSec", "OnBootSec", "OnStartupSec", "OnUnitActiveSec", "OnUnitInactiveSec", "OnCalendar":
			return true
		}
	case "Path":
		switch key {
		case "PathExists", "PathExistsGlob", "PathChanged", "PathModified", "DirectoryNotEmpty":
			return true
		}
	case "Socket":
		switch key {
		case "ListenStream", "ListenDatagram", "ListenSequentialPacket", "ListenFIFO", "ListenSpecial", "ListenNetlink", "ListenMessageQueue", "ListenUSBFunction":
			return true
		}
	}
	return false
}

func analyzeSystemdActivation(name, section, directive, value string, evidence report.Evidence, dynamic bool, result *Result) {
	retained, truncated := boundedEncodedString(value)
	dynamic = dynamic || truncated || systemdRuntimeSubstitution(value)
	if truncated {
		retained = "<dynamic>"
	}
	op := report.Operation{
		ID: fmt.Sprintf("op-%s-%d-%d", stablePathID(name), evidence.LineStart, len(result.Operations)+1), Category: "systemd-activation-trigger",
		Command: section + "." + directive, Arguments: []string{retained}, Dynamic: dynamic, Confidence: report.ConfidenceHigh,
		Evidence: evidence, Provenance: sourceProvenance("systemd-activation-trigger/v1"),
	}
	if dynamic {
		op.Confidence = report.ConfidenceMedium
	}
	if !appendOperation(result, op) {
		return
	}
	appendFinding(result, report.Finding{
		ID: "finding-systemd-trigger-" + op.ID, Claim: report.ClaimFact, Severity: report.SeverityInformational, Confidence: op.Confidence,
		Category: "service-activation-metadata", Title: "Declares " + strings.ToLower(section) + "-based service activation",
		Explanation: "The unit declares an activation trigger. Static review does not establish installation, enablement, manager loading, trigger occurrence, or service execution.",
		Evidence:    []report.Evidence{evidence}, Related: []string{op.ID}, Provenance: sourceProvenance("systemd-activation-metadata/v1"),
	})
	if dynamic {
		addSystemdUnknown(result, name, report.UnknownDynamicValue, "Systemd activation trigger contains runtime substitution", "The trigger contains unresolved substitution or exceeded retained evidence, so its final runtime value is unknown.", evidence, []string{op.ID})
	}
}

func analyzeSystemdUnitReference(name, section, value string, evidence report.Evidence, dynamic bool, result *Result) {
	retained, truncated := boundedEncodedString(value)
	dynamic = dynamic || truncated || systemdRuntimeSubstitution(value)
	if truncated {
		retained = "<dynamic>"
	}
	op := report.Operation{
		ID: fmt.Sprintf("op-%s-%d-%d", stablePathID(name), evidence.LineStart, len(result.Operations)+1), Category: "systemd-unit-reference",
		Command: section + ".Unit", Arguments: []string{retained}, Dynamic: dynamic, Confidence: report.ConfidenceHigh,
		Evidence: evidence, Provenance: sourceProvenance("systemd-unit-reference/v1"),
	}
	if dynamic {
		op.Confidence = report.ConfidenceMedium
	}
	if !appendOperation(result, op) {
		return
	}
	if dynamic {
		addSystemdUnknown(result, name, report.UnknownDynamicValue, "Activated systemd unit name is unresolved", "The Unit reference contains runtime substitution or exceeded retained evidence, so no target service relationship was guessed.", evidence, []string{op.ID})
	}
}

func boundedSystemdLines(data []byte) ([]systemdLogicalLine, bool, bool) {
	lines := make([]systemdLogicalLine, 0, min(256, maxSystemdLines))
	var logical strings.Builder
	logicalStart := 0
	physicalLine := 0
	for offset := 0; offset <= len(data); {
		if physicalLine >= maxSystemdLines {
			return lines, false, true
		}
		end := offset
		for end < len(data) && data[end] != '\n' {
			end++
		}
		physicalLine++
		text := strings.TrimSuffix(string(data[offset:end]), "\r")
		if logicalStart == 0 {
			logicalStart = physicalLine
		}
		continued := hasOddTrailingBackslash(text)
		if continued {
			text = strings.TrimSuffix(text, "\\")
		}
		if logical.Len() > 0 {
			logical.WriteByte(' ')
		}
		logical.WriteString(text)
		if !continued {
			lines = append(lines, systemdLogicalLine{start: logicalStart, end: physicalLine, text: logical.String()})
			logical.Reset()
			logicalStart = 0
		}
		if end == len(data) {
			break
		}
		offset = end + 1
	}
	if logicalStart != 0 {
		return lines, true, false
	}
	return lines, true, true
}

func hasOddTrailingBackslash(value string) bool {
	count := 0
	for index := len(value) - 1; index >= 0 && value[index] == '\\'; index-- {
		count++
	}
	return count%2 == 1
}

func systemdExecDirective(section, key string) bool {
	if section == "Service" {
		switch key {
		case "ExecStart", "ExecStartPre", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost", "ExecCondition":
			return true
		}
	}
	if section == "Socket" {
		switch key {
		case "ExecStartPre", "ExecStartPost", "ExecStopPre", "ExecStopPost":
			return true
		}
	}
	return false
}

func analyzeSystemdExec(name, directive, value string, evidence report.Evidence, evidenceTruncated bool, result *Result) {
	if value == "" { // An empty assignment resets an earlier list; it is not a command.
		return
	}
	parsed := parseSystemdCommand(value)
	parsed.dynamic = parsed.dynamic || evidenceTruncated
	if parsed.malformed || parsed.command == "" {
		addSystemdUnknown(result, name, report.UnknownUnsupportedSyntax, "Systemd execution directive is unresolved", "The execution directive has malformed quoting, a trailing escape, or no executable token. No command was guessed.", evidence, nil)
		result.Limitations = append(result.Limitations, report.Limitation{Code: "systemd-exec-unresolved", Description: "A systemd execution directive could not be tokenized without guessing.", Path: name})
		return
	}
	op := report.Operation{
		ID: fmt.Sprintf("op-%s-%d-%d", stablePathID(name), evidence.LineStart, len(result.Operations)+1), Category: "process-execution-via-systemd-unit",
		Command: parsed.command, Arguments: parsed.arguments, Dynamic: parsed.dynamic, Confidence: report.ConfidenceHigh,
		Evidence: evidence, Provenance: sourceProvenance("systemd-" + strings.ToLower(directive) + "/v1"),
	}
	if op.Dynamic {
		op.Confidence = report.ConfidenceMedium
	}
	if !appendOperation(result, op) {
		return
	}
	classifyCall(op, result)
	classifySystemdInlineProgram(op, result)
	if op.Dynamic {
		addSystemdUnknown(result, name, report.UnknownDynamicValue, "Systemd command contains runtime substitution", "The directive contains environment-variable or systemd-specifier substitution, or exceeded retained evidence. The visible command is retained where possible, but final runtime values remain unresolved.", evidence, []string{op.ID})
	}
	if parsed.privileged {
		appendFinding(result, report.Finding{
			ID: "finding-systemd-privilege-" + op.ID, Claim: report.ClaimFact, Severity: report.SeverityHigh, Confidence: report.ConfidenceHigh,
			Category: "privilege-escalation", Title: "Requests elevated systemd execution semantics", Explanation: "The unit command uses a systemd execution prefix that relaxes configured identity or sandbox restrictions. Its actual authority still depends on the manager and unit context.",
			Evidence: []report.Evidence{evidence}, Related: []string{op.ID}, Provenance: sourceProvenance("systemd-exec-privilege-prefix/v1"),
		})
	}
}

func classifySystemdInlineProgram(op report.Operation, result *Result) {
	program, shellSyntax, ok := inlineInterpreterProgram(filepath.Base(op.Command), op.Arguments)
	if !ok {
		return
	}
	severity := report.SeverityMedium
	category := "shell-execution"
	title := "Starts a command interpreter from a systemd unit"
	explanation := "The unit asks a command interpreter to parse an inline program. The nested program requires separate review and may contain runtime substitutions that this unit-file parser cannot resolve."
	ruleID := "systemd-inline-shell/v1"
	if !shellSyntax {
		category = "dynamic-execution"
		title = "Executes an inline language program from a systemd unit"
		explanation = "The unit asks a language runtime to execute inline source text. This scanner records that text as evidence but does not parse its calls or data flow in this context."
		ruleID = "systemd-inline-language/v1"
		result.Limitations = append(result.Limitations, report.Limitation{Code: "inline-dynamic-language-analysis-unavailable", Description: "An inline " + filepath.Base(op.Command) + " program in a systemd unit was retained as data but not semantically parsed.", Path: op.Evidence.Path})
		addSystemdUnknown(result, op.Evidence.Path, report.UnknownUnsupportedSyntax, "Inline language behavior is unresolved", "Calls and data flow inside the inline language program were not semantically parsed in the unit-file context.", op.Evidence, []string{op.ID})
	} else if containsDownloadExecutePipeline(program) {
		severity = report.SeverityHigh
		category = "download-and-execute"
		title = "Systemd unit downloads content into an interpreter"
		explanation = "The parsed inline shell program contains an adjacent pipeline from a network downloader to a command interpreter. Remote response bytes can therefore become code if the configured unit runs."
	} else if containsDecodeExecutePipeline(program) {
		category = "encoded-content-execution"
		title = "Systemd unit decodes content into an interpreter"
		explanation = "The parsed inline shell program contains an adjacent pipeline from a content decoder to a command interpreter. Decoded bytes can become runtime code if the configured unit runs."
	}
	appendFinding(result, report.Finding{
		ID: "finding-systemd-inline-" + op.ID, Claim: report.ClaimFact, Severity: severity, Confidence: op.Confidence,
		Category: category, Title: title, Explanation: explanation, Evidence: []report.Evidence{op.Evidence}, Related: []string{op.ID}, Provenance: sourceProvenance(ruleID),
	})
}

func analyzeSystemdInstall(name, directive, value string, evidence report.Evidence, dynamic bool, result *Result) {
	targets := strings.Fields(value)
	if len(targets) == 0 {
		return
	}
	if len(targets) > maxRetainedArguments {
		targets = targets[:maxRetainedArguments]
		dynamic = true
	}
	for _, target := range targets {
		if systemdRuntimeSubstitution(target) {
			dynamic = true
		}
	}
	op := report.Operation{
		ID: fmt.Sprintf("op-%s-%d-%d", stablePathID(name), evidence.LineStart, len(result.Operations)+1), Category: "systemd-install-metadata",
		Command: directive, Arguments: targets, Dynamic: dynamic, Confidence: report.ConfidenceHigh, Evidence: evidence, Provenance: sourceProvenance("systemd-install-metadata/v1"),
	}
	if dynamic {
		op.Confidence = report.ConfidenceMedium
	}
	if !appendOperation(result, op) {
		return
	}
	appendFinding(result, report.Finding{
		ID: "finding-systemd-install-" + op.ID, Claim: report.ClaimFact, Severity: report.SeverityInformational, Confidence: op.Confidence,
		Category: "systemd-install-metadata", Title: "Declares systemd enablement targets", Explanation: "The unit declares install targets used when it is enabled. Static review does not establish that the unit will be installed, enabled, started, or granted the requested authority.",
		Evidence: []report.Evidence{evidence}, Related: []string{op.ID}, Provenance: sourceProvenance("systemd-install-persistence/v1"),
	})
	if dynamic {
		addSystemdUnknown(result, name, report.UnknownDynamicValue, "Systemd install target contains runtime substitution", "One or more enablement targets contain unresolved substitution or exceeded retained evidence.", evidence, []string{op.ID})
	}
}

func parseSystemdCommand(value string) systemdCommand {
	parsed := systemdCommand{}
	tokens, dynamic, malformed := tokenizeSystemd(value, systemdPrefixDisablesEnvironment(value))
	parsed.dynamic, parsed.malformed = dynamic, malformed
	if len(tokens) == 0 {
		return parsed
	}
	command := tokens[0]
	for len(command) > 0 {
		switch command[0] {
		case '-':
			command = command[1:]
		case '@', ':':
			command = command[1:]
		case '+', '!':
			parsed.privileged = true
			command = command[1:]
		default:
			goto prefixesDone
		}
	}
prefixesDone:
	if command == "" {
		parsed.malformed = true
		return parsed
	}
	if strings.Contains(command, "<dynamic>") {
		parsed.command = "<dynamic>"
		parsed.dynamic = true
	} else {
		parsed.command = command
	}
	parsed.arguments = tokens[1:]
	return parsed
}

func tokenizeSystemd(value string, disableEnvironment bool) ([]string, bool, bool) {
	characters := []rune(strings.TrimSpace(value))
	tokens := make([]string, 0, 8)
	var token strings.Builder
	quote := rune(0)
	escaped := false
	dynamic := false
	flush := func() {
		if token.Len() == 0 {
			return
		}
		value, truncated := boundedEncodedString(token.String())
		if truncated {
			value = "<dynamic>"
			dynamic = true
		}
		if len(tokens) < maxRetainedArguments+1 {
			tokens = append(tokens, value)
		} else {
			dynamic = true
		}
		token.Reset()
	}
	for index := 0; index < len(characters); index++ {
		char := characters[index]
		if escaped {
			token.WriteRune(char)
			escaped = false
			continue
		}
		if char == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if char == quote {
				quote = 0
			} else {
				token.WriteRune(char)
			}
			continue
		}
		if char == '\'' || char == '"' {
			quote = char
			continue
		}
		if char == ' ' || char == '\t' {
			flush()
			continue
		}
		if char == '%' {
			if index+1 < len(characters) && characters[index+1] == '%' {
				token.WriteRune('%')
				index++
				continue
			}
			dynamic = true
			token.WriteString("<dynamic>")
			if index+1 < len(characters) {
				index++
			}
			continue
		}
		if char == '$' {
			if disableEnvironment {
				token.WriteRune(char)
				continue
			}
			dynamic = true
			token.WriteString("<dynamic>")
			continue
		}
		token.WriteRune(char)
	}
	flush()
	return tokens, dynamic, escaped || quote != 0
}

func systemdPrefixDisablesEnvironment(value string) bool {
	trimmed := strings.TrimSpace(value)
	for index := 0; index < len(trimmed); index++ {
		switch trimmed[index] {
		case '-', '@', '+', '!':
			continue
		case ':':
			return true
		default:
			return false
		}
	}
	return false
}

func systemdRuntimeSubstitution(value string) bool {
	characters := []rune(value)
	for index := 0; index < len(characters); index++ {
		if characters[index] == '$' {
			return true
		}
		if characters[index] != '%' {
			continue
		}
		if index+1 < len(characters) && characters[index+1] == '%' {
			index++
			continue
		}
		return true
	}
	return false
}

func addSystemdUnknown(result *Result, name string, reason report.UnknownReason, title, description string, evidence report.Evidence, affected []string) {
	appendUnknown(result, report.Unknown{
		ID: "unknown-systemd-" + stablePathID(name) + "-" + string(reason) + "-" + fmt.Sprint(evidence.LineStart), Category: "systemd-unit-analysis", Reason: reason,
		Scope: report.ScopeUnknown, Confidence: report.ConfidenceHigh, Title: title, Description: description, Evidence: []report.Evidence{evidence},
		Origins: []report.ValueOrigin{{Kind: report.OriginUseSite, Name: "systemd unit directive", Evidence: evidence}}, AffectedOperations: affected,
		SuppressedRules: []string{"systemd-exec/v1", "command-capability/v1", "operation-correlation/v1"}, Provenance: sourceProvenance("systemd-unit-unknown/v1"),
	})
}
