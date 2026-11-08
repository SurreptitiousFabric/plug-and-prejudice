package analyze

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

const maxDesktopLines = 20_000

type desktopExec struct {
	line      int
	raw       string
	command   string
	args      []string
	dynamic   bool
	malformed bool
}

// analyzeDesktopEntry parses the freedesktop key-file surface strictly as
// inert text. It does not ask GLib, a desktop launcher, or a shell to interpret
// plugin-controlled content.
func analyzeDesktopEntry(name string, data []byte, result *Result) {
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		evidence := report.Evidence{Path: name, Operation: "desktop entry"}
		addDesktopUnknown(result, name, report.UnknownParserFailure, "Desktop entry text is not valid UTF-8", "The desktop entry contains invalid UTF-8 or a NUL byte. It was not tokenized and no launch command was guessed.", evidence, nil)
		result.Limitations = append(result.Limitations, report.Limitation{Code: "desktop-entry-invalid-text", Description: "The desktop entry contains invalid UTF-8 or a NUL byte and was not parsed.", Path: name})
		return
	}
	lines := newSourceIndex(data)
	section := ""
	var candidate *desktopExec
	seenExec := false
	duplicateExec := false
	hidden := false
	lineNumber := 0
	for offset := 0; offset <= len(data); {
		if lineNumber >= maxDesktopLines {
			addDesktopUnknown(result, name, report.UnknownBudgetExhaustion, "Desktop entry line budget exhausted", "The desktop-entry parser reached its bounded line limit; later keys were not analyzed.", report.Evidence{Path: name, Operation: "desktop entry"}, nil)
			result.Limitations = append(result.Limitations, report.Limitation{Code: "desktop-entry-line-budget", Description: "The desktop-entry parser reached its bounded line limit; later keys were not analyzed.", Path: name})
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
			if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
				section = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			} else if section == "Desktop Entry" {
				key, value, ok := strings.Cut(line, "=")
				if ok {
					switch strings.TrimSpace(key) {
					case "Hidden":
						hidden = strings.EqualFold(strings.TrimSpace(value), "true")
					case "Exec":
						if seenExec {
							if !duplicateExec {
								evidence := report.Evidence{Path: name, LineStart: lineNumber, LineEnd: lineNumber, Operation: "duplicate Exec key", Excerpt: lines.line(lineNumber)}
								addDesktopUnknown(result, name, report.UnknownUnsupportedSyntax, "Desktop entry has multiple Exec keys", "Multiple launch commands are declared in the same Desktop Entry section. The scanner does not guess which duplicate a launcher will select.", evidence, nil)
							}
							duplicateExec = true
							candidate = nil
						} else {
							seenExec = true
							exec := parseDesktopExec(value)
							exec.line = lineNumber
							evidenceTruncated := false
							exec.raw, evidenceTruncated = boundedEncodedString(strings.TrimSpace(value))
							exec.dynamic = exec.dynamic || evidenceTruncated
							candidate = &exec
						}
					}
				}
			}
		}
		if end == len(data) {
			break
		}
		offset = end + 1
	}
	if candidate == nil {
		return
	}
	evidence := report.Evidence{Path: name, LineStart: candidate.line, LineEnd: candidate.line, Operation: candidate.raw, Excerpt: lines.line(candidate.line)}
	if candidate.malformed || candidate.command == "" {
		addDesktopUnknown(result, name, report.UnknownUnsupportedSyntax, "Desktop launch command is malformed", "The Exec value has unterminated quoting, a trailing escape, or no executable token. No command was guessed.", evidence, nil)
		result.Limitations = append(result.Limitations, report.Limitation{Code: "desktop-entry-exec-unresolved", Description: "A Desktop Entry Exec value could not be tokenized without guessing.", Path: name})
		return
	}
	op := report.Operation{
		ID: fmt.Sprintf("op-%s-%d-%d", stablePathID(name), candidate.line, len(result.Operations)+1), Category: "process-execution-via-desktop-entry",
		Command: candidate.command, Arguments: candidate.args, Dynamic: candidate.dynamic, Confidence: report.ConfidenceHigh,
		Evidence: evidence, Provenance: sourceProvenance("desktop-entry-exec/v1"),
	}
	if op.Dynamic {
		op.Confidence = report.ConfidenceMedium
	}
	if !appendOperation(result, op) {
		return
	}
	classifyCall(op, result)
	if op.Dynamic {
		addDesktopUnknown(result, name, report.UnknownDynamicValue, "Desktop launch command contains runtime field codes", "The Exec value contains freedesktop field-code substitution or exceeded retained argument evidence. The visible command is retained, but the final runtime arguments remain unresolved.", evidence, []string{op.ID})
	}
	if desktopAutostartPath(name) && !hidden {
		appendFinding(result, report.Finding{
			ID: "finding-desktop-autostart-" + op.ID, Claim: report.ClaimFact, Severity: report.SeverityMedium, Confidence: report.ConfidenceHigh,
			Category: "persistence", Title: "Defines a desktop autostart command", Explanation: "This desktop entry is stored under an autostart path and declares a launch command. Static review does not establish that the file will be installed, enabled, or launched.",
			Evidence: []report.Evidence{evidence}, Related: []string{op.ID}, Provenance: sourceProvenance("desktop-autostart/v1"),
		})
	}
}

func parseDesktopExec(value string) desktopExec {
	result := desktopExec{}
	tokens := make([]string, 0, 8)
	var token strings.Builder
	inQuote := false
	escaped := false
	flush := func() {
		if token.Len() > 0 {
			value, truncated := boundedEncodedString(token.String())
			if truncated {
				value = "<dynamic>"
				result.dynamic = true
			}
			if len(tokens) < maxRetainedArguments+1 {
				tokens = append(tokens, value)
			} else {
				result.dynamic = true
			}
		}
		token.Reset()
	}
	characters := []rune(strings.TrimSpace(value))
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
		if char == '"' {
			inQuote = !inQuote
			continue
		}
		if !inQuote && (char == ' ' || char == '\t') {
			flush()
			continue
		}
		if char == '%' {
			if index+1 < len(characters) && characters[index+1] == '%' {
				token.WriteRune(char)
				index++
				continue
			}
			result.dynamic = true
		}
		token.WriteRune(char)
	}
	flush()
	if escaped || inQuote {
		result.malformed = true
	}
	if len(tokens) > 0 {
		if strings.Contains(tokens[0], "%") {
			result.command = "<dynamic>"
		} else {
			result.command = tokens[0]
		}
		result.args = tokens[1:]
	}
	return result
}

func desktopAutostartPath(name string) bool {
	clean := "/" + strings.ToLower(filepath.ToSlash(filepath.Clean(name))) + "/"
	return strings.Contains(clean, "/autostart/")
}

func addDesktopUnknown(result *Result, name string, reason report.UnknownReason, title, description string, evidence report.Evidence, affected []string) {
	appendUnknown(result, report.Unknown{
		ID: "unknown-desktop-" + stablePathID(name) + "-" + string(reason) + "-" + fmt.Sprint(evidence.LineStart), Category: "desktop-entry-analysis", Reason: reason,
		Scope: report.ScopeUnknown, Confidence: report.ConfidenceHigh, Title: title, Description: description, Evidence: []report.Evidence{evidence},
		Origins: []report.ValueOrigin{{Kind: report.OriginUseSite, Name: "Desktop Entry Exec", Evidence: evidence}}, AffectedOperations: affected,
		SuppressedRules: []string{"desktop-entry-exec/v1", "command-capability/v1", "operation-correlation/v1"}, Provenance: sourceProvenance("desktop-entry-unknown/v1"),
	})
}
