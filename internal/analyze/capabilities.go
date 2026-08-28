package analyze

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func deriveCapabilities(result *Result) {
	seen := make(map[string]bool)
	for _, operation := range result.Operations {
		if operation.Category == "shell-function-invocation" {
			continue
		}
		if operation.Category == "filesystem-redirection" {
			if len(operation.Arguments) == 2 {
				addPathResource(result, seen, operation, operation.Arguments[0], operation.Arguments[1])
			}
			continue
		}
		command := filepath.Base(operation.Command)
		if networkCommand(command) {
			domains := networkDomains(command, operation.Arguments)
			for _, domain := range domains {
				addResource(result, seen, operation, "network-domain", "connect", domain, false, false)
			}
			if len(domains) == 0 && operation.Dynamic {
				addResource(result, seen, operation, "network-domain", "connect", "<dynamic>", false, true)
			}
		}
		if command == "curl" || command == "wget" {
			for _, output := range downloadOutputPaths(command, operation.Arguments) {
				addPathResource(result, seen, operation, "write", output)
			}
		}
		if command == "dd" {
			deriveDDCapabilities(result, seen, operation)
			continue
		}
		if deriveFilesystemCommand(result, seen, operation, command) {
			continue
		}
		switch command {
		case "rm", "unlink", "rmdir":
			operands := destructiveOperands(operation.Arguments)
			for _, operand := range operands {
				addPathResource(result, seen, operation, "delete", operand)
			}
			if len(operands) > 0 {
				addDestructiveFinding(result, operation, operands)
			}
		case "ln":
			if destination := linkDestination(operation.Arguments); destination != "" {
				addPathResource(result, seen, operation, "write", destination)
			}
		case "systemctl":
			verb := firstNonOption(operation.Arguments)
			if verb == "enable" || verb == "reenable" {
				addPersistence(result, seen, operation, "systemd service enablement")
			}
		case "crontab":
			if !readOnlyCrontab(operation.Arguments) {
				addPersistence(result, seen, operation, "cron configuration")
			}
		}
	}
	correlateStagedDownloads(result)
	correlateBehaviorCombinations(result)
	sort.Slice(result.Resources, func(i, j int) bool { return result.Resources[i].ID < result.Resources[j].ID })
}

var rawStorageDevicePattern = regexp.MustCompile(`^/dev/(?:sd[a-z]+[0-9]*|hd[a-z]+[0-9]*|vd[a-z]+[0-9]*|xvd[a-z]+[0-9]*|nvme[0-9]+n[0-9]+(?:p[0-9]+)?|mmcblk[0-9]+(?:p[0-9]+)?|md[0-9]+(?:p[0-9]+)?|dm-[0-9]+|loop[0-9]+)$`)

func deriveDDCapabilities(result *Result, seen map[string]bool, operation report.Operation) {
	input, output, state := ddPaths(operation.Arguments)
	if state == operandsUnresolved {
		addWrapperLimitation(result, operation, "dd-operand-resolution", "A dd command uses malformed, duplicate, dynamic-name, or unsupported operands. The command remains visible, but its input and output paths are unknown.")
		return
	}
	if state == operandsNonExecuting {
		return
	}
	if input != "" && input != "-" {
		addPathResource(result, seen, operation, "read", input)
	}
	if output != "" && output != "-" {
		addPathResource(result, seen, operation, "write", output)
	}
}

func ddPaths(arguments []string) (string, string, operandParseState) {
	input := ""
	output := ""
	for _, argument := range arguments {
		if argument == "--help" || argument == "--version" {
			return "", "", operandsNonExecuting
		}
		name, value, exists := strings.Cut(argument, "=")
		if !exists || name == "" || value == "" || strings.Contains(name, "<dynamic>") {
			return "", "", operandsUnresolved
		}
		switch name {
		case "if":
			if input != "" {
				return "", "", operandsUnresolved
			}
			input = value
		case "of":
			if output != "" {
				return "", "", operandsUnresolved
			}
			output = value
		case "bs", "cbs", "conv", "count", "ibs", "iflag", "obs", "oflag", "seek", "skip", "status", "iseek", "oseek":
			// Recognized non-path operand.
		default:
			return "", "", operandsUnresolved
		}
	}
	return input, output, operandsResolved
}

func rawStorageDevice(value string) bool {
	clean := filepath.ToSlash(filepath.Clean(value))
	if clean == "/dev/mapper/control" {
		return false
	}
	return rawStorageDevicePattern.MatchString(clean) || strings.HasPrefix(clean, "/dev/mapper/") || strings.HasPrefix(clean, "/dev/disk/by-")
}

type operandGrammar struct {
	noValueShort       string
	valueShort         string
	referenceShort     string
	destinationShort   string
	directoryShort     string
	noDestinationShort string
	noValueLong        []string
	valueLong          []string
	optionalLong       []string
	referenceLong      []string
	destinationLong    []string
	directoryLong      []string
	noDestinationLong  []string
	dropLeading        int
	role               string
}

type parsedFilesystemOperands struct {
	positionals   []string
	references    []string
	destination   string
	directoryMode bool
	noDestination bool
	state         operandParseState
}

type operandParseState uint8

const (
	operandsResolved operandParseState = iota
	operandsNonExecuting
	operandsUnresolved
)

func deriveFilesystemCommand(result *Result, seen map[string]bool, operation report.Operation, command string) bool {
	grammar, recognized := filesystemOperandGrammar(command)
	if !recognized {
		return false
	}
	parsed := parseFilesystemOperands(operation.Arguments, grammar)
	if parsed.state == operandsUnresolved {
		addWrapperLimitation(result, operation, "filesystem-operand-resolution", "A recognized filesystem command uses option syntax whose operand roles this bounded analyzer cannot resolve without guessing. The command remains visible, but its file accesses are incomplete.")
		return true
	}
	if parsed.state == operandsNonExecuting {
		return true
	}
	for _, reference := range parsed.references {
		if reference != "-" {
			addPathResource(result, seen, operation, "read", reference)
		}
	}
	if parsed.directoryMode {
		for _, directory := range parsed.positionals {
			if directory != "-" {
				addPathResource(result, seen, operation, "write", directory)
			}
		}
		return true
	}
	dropLeading := grammar.dropLeading
	if len(parsed.references) > 0 && (command == "chmod" || command == "chown") {
		dropLeading = 0
	}
	if len(parsed.positionals) <= dropLeading {
		return true
	}
	operands := parsed.positionals[dropLeading:]
	switch grammar.role {
	case "read", "write":
		for _, operand := range operands {
			if operand != "-" {
				addPathResource(result, seen, operation, grammar.role, operand)
			}
		}
	case "copy":
		destination := parsed.destination
		sources := operands
		if destination == "" && len(operands) > 1 {
			destination = operands[len(operands)-1]
			sources = operands[:len(operands)-1]
		}
		if destination != "" && len(sources) > 0 {
			for _, operand := range sources {
				if operand != "-" {
					addPathResource(result, seen, operation, "read", operand)
				}
			}
			if destination != "-" {
				addPathResource(result, seen, operation, "write", destination)
			}
		}
	case "move":
		destination := parsed.destination
		sources := operands
		if destination == "" && len(operands) > 1 {
			destination = operands[len(operands)-1]
			sources = operands[:len(operands)-1]
		}
		if destination != "" && len(sources) > 0 {
			for _, operand := range sources {
				if operand != "-" {
					addPathResource(result, seen, operation, "delete", operand)
				}
			}
			if destination != "-" {
				addPathResource(result, seen, operation, "write", destination)
			}
		}
	}
	return true
}

func filesystemOperandGrammar(command string) (operandGrammar, bool) {
	switch command {
	case "cat":
		return operandGrammar{noValueShort: "AbEenstTuv", noValueLong: []string{"show-all", "number-nonblank", "show-ends", "number", "squeeze-blank", "show-tabs", "show-nonprinting"}, role: "read"}, true
	case "head":
		return operandGrammar{noValueShort: "qvz", valueShort: "cn", noValueLong: []string{"quiet", "silent", "verbose", "zero-terminated"}, valueLong: []string{"bytes", "lines"}, role: "read"}, true
	case "tail":
		return operandGrammar{noValueShort: "Ffqvz", valueShort: "cns", noValueLong: []string{"debug", "retry", "quiet", "silent", "verbose", "zero-terminated"}, valueLong: []string{"bytes", "lines", "max-unchanged-stats", "pid", "sleep-interval"}, optionalLong: []string{"follow"}, role: "read"}, true
	case "readlink":
		return operandGrammar{noValueShort: "femnqsvz", noValueLong: []string{"canonicalize", "canonicalize-existing", "canonicalize-missing", "no-newline", "quiet", "silent", "verbose", "zero"}, role: "read"}, true
	case "touch":
		return operandGrammar{noValueShort: "acfhm", valueShort: "dt", referenceShort: "r", noValueLong: []string{"no-create", "no-dereference"}, valueLong: []string{"date", "time"}, referenceLong: []string{"reference"}, role: "write"}, true
	case "mkdir":
		return operandGrammar{noValueShort: "pv", valueShort: "m", noValueLong: []string{"parents", "verbose"}, valueLong: []string{"mode"}, role: "write"}, true
	case "tee":
		return operandGrammar{noValueShort: "aip", noValueLong: []string{"append", "ignore-interrupts", "ignore-pipe-errors"}, optionalLong: []string{"output-error"}, role: "write"}, true
	case "truncate":
		return operandGrammar{noValueShort: "co", valueShort: "s", referenceShort: "r", noValueLong: []string{"no-create", "io-blocks"}, valueLong: []string{"size"}, referenceLong: []string{"reference"}, role: "write"}, true
	case "chmod":
		return operandGrammar{noValueShort: "cfvRHLP", noValueLong: []string{"changes", "silent", "quiet", "verbose", "dereference", "no-dereference", "no-preserve-root", "preserve-root", "recursive"}, referenceLong: []string{"reference"}, dropLeading: 1, role: "write"}, true
	case "chown":
		return operandGrammar{noValueShort: "cfvRhHLP", noValueLong: []string{"changes", "silent", "quiet", "verbose", "dereference", "no-dereference", "no-preserve-root", "preserve-root", "recursive"}, valueLong: []string{"from"}, referenceLong: []string{"reference"}, dropLeading: 1, role: "write"}, true
	case "cp":
		return operandGrammar{noValueShort: "abdfHilLnPrRsuvx", valueShort: "S", destinationShort: "t", noDestinationShort: "T", noValueLong: []string{"archive", "attributes-only", "copy-contents", "debug", "force", "interactive", "dereference", "no-dereference", "recursive", "no-clobber", "verbose"}, valueLong: []string{"suffix"}, optionalLong: []string{"backup"}, destinationLong: []string{"target-directory"}, noDestinationLong: []string{"no-target-directory"}, role: "copy"}, true
	case "install":
		return operandGrammar{noValueShort: "bCcDpsv", valueShort: "gmoS", destinationShort: "t", directoryShort: "d", noDestinationShort: "T", noValueLong: []string{"compare", "debug", "preserve-timestamps", "strip", "verbose"}, valueLong: []string{"group", "mode", "owner", "suffix"}, optionalLong: []string{"backup"}, destinationLong: []string{"target-directory"}, directoryLong: []string{"directory"}, noDestinationLong: []string{"no-target-directory"}, role: "copy"}, true
	case "mv":
		return operandGrammar{noValueShort: "bfinuv", valueShort: "S", destinationShort: "t", noDestinationShort: "T", noValueLong: []string{"debug", "exchange", "force", "interactive", "no-clobber", "no-copy", "strip-trailing-slashes", "verbose"}, valueLong: []string{"suffix"}, optionalLong: []string{"backup"}, destinationLong: []string{"target-directory"}, noDestinationLong: []string{"no-target-directory"}, role: "move"}, true
	default:
		return operandGrammar{}, false
	}
}

func parseFilesystemOperands(arguments []string, grammar operandGrammar) parsedFilesystemOperands {
	parsed := parsedFilesystemOperands{state: operandsResolved}
	optionsEnded := false
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if !optionsEnded && argument == "--" {
			optionsEnded = true
			continue
		}
		if !optionsEnded && (argument == "--help" || argument == "--version") {
			parsed.state = operandsNonExecuting
			return parsed
		}
		if !optionsEnded && strings.HasPrefix(argument, "--") {
			name, value, attached := strings.Cut(strings.TrimPrefix(argument, "--"), "=")
			if containsString(grammar.noValueLong, name) {
				if attached {
					parsed.state = operandsUnresolved
					return parsed
				}
				continue
			}
			if containsString(grammar.optionalLong, name) {
				continue
			}
			if containsString(grammar.directoryLong, name) {
				if attached || parsed.destination != "" || parsed.noDestination {
					parsed.state = operandsUnresolved
					return parsed
				}
				parsed.directoryMode = true
				continue
			}
			if containsString(grammar.noDestinationLong, name) {
				if attached || parsed.destination != "" || parsed.directoryMode {
					parsed.state = operandsUnresolved
					return parsed
				}
				parsed.noDestination = true
				continue
			}
			if containsString(grammar.referenceLong, name) || containsString(grammar.destinationLong, name) {
				if !attached {
					if index+1 >= len(arguments) {
						parsed.state = operandsUnresolved
						return parsed
					}
					index++
					value = arguments[index]
				}
				if value == "" || (containsString(grammar.destinationLong, name) && (parsed.destination != "" || parsed.directoryMode || parsed.noDestination)) ||
					(containsString(grammar.referenceLong, name) && len(parsed.references) > 0) {
					parsed.state = operandsUnresolved
					return parsed
				}
				if containsString(grammar.referenceLong, name) {
					parsed.references = append(parsed.references, value)
				} else {
					parsed.destination = value
				}
				continue
			}
			if containsString(grammar.valueLong, name) {
				if !attached {
					if index+1 >= len(arguments) {
						parsed.state = operandsUnresolved
						return parsed
					}
					index++
				}
				continue
			}
			parsed.state = operandsUnresolved
			return parsed
		}
		if !optionsEnded && strings.HasPrefix(argument, "-") && argument != "-" {
			options := []rune(argument[1:])
			valid := len(options) > 0
			for position, option := range options {
				if strings.ContainsRune(grammar.noDestinationShort, option) {
					if parsed.destination != "" || parsed.directoryMode {
						valid = false
						break
					}
					parsed.noDestination = true
					continue
				}
				if strings.ContainsRune(grammar.directoryShort, option) {
					if parsed.destination != "" || parsed.noDestination {
						valid = false
						break
					}
					parsed.directoryMode = true
					continue
				}
				if strings.ContainsRune(grammar.noValueShort, option) {
					continue
				}
				roleValue := strings.ContainsRune(grammar.referenceShort, option) || strings.ContainsRune(grammar.destinationShort, option)
				if strings.ContainsRune(grammar.valueShort, option) || roleValue {
					value := ""
					if position == len(options)-1 {
						if index+1 >= len(arguments) {
							parsed.state = operandsUnresolved
							return parsed
						}
						index++
						value = arguments[index]
					} else {
						value = string(options[position+1:])
					}
					if roleValue {
						if value == "" || (strings.ContainsRune(grammar.destinationShort, option) && (parsed.destination != "" || parsed.directoryMode || parsed.noDestination)) ||
							(strings.ContainsRune(grammar.referenceShort, option) && len(parsed.references) > 0) {
							valid = false
							break
						}
						if strings.ContainsRune(grammar.referenceShort, option) {
							parsed.references = append(parsed.references, value)
						} else {
							parsed.destination = value
						}
					}
					break
				}
				valid = false
				break
			}
			if valid {
				continue
			}
			parsed.state = operandsUnresolved
			return parsed
		}
		if argument != "" {
			parsed.positionals = append(parsed.positionals, argument)
		}
	}
	if (parsed.directoryMode && (parsed.destination != "" || parsed.noDestination)) || (parsed.destination != "" && parsed.noDestination) {
		parsed.state = operandsUnresolved
	}
	return parsed
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func downloadOutputPaths(command string, arguments []string) []string {
	var outputs []string
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		value := ""
		switch {
		case command == "curl" && (argument == "-o" || argument == "--output"):
			if index+1 < len(arguments) {
				index++
				value = arguments[index]
			}
		case command == "curl" && strings.HasPrefix(argument, "--output="):
			value = strings.TrimPrefix(argument, "--output=")
		case command == "curl" && strings.HasPrefix(argument, "-o") && len(argument) > 2:
			value = argument[2:]
		case command == "curl" && (argument == "-O" || argument == "--remote-name" || argument == "--remote-name-all"):
			value = "<dynamic>"
		case command == "wget" && (argument == "-O" || argument == "--output-document"):
			if index+1 < len(arguments) {
				index++
				value = arguments[index]
			}
		case command == "wget" && strings.HasPrefix(argument, "--output-document="):
			value = strings.TrimPrefix(argument, "--output-document=")
		case command == "wget" && strings.HasPrefix(argument, "-O") && len(argument) > 2:
			value = argument[2:]
		}
		if value != "" && value != "-" {
			outputs = append(outputs, value)
		}
	}
	return outputs
}

func correlateStagedDownloads(result *Result) {
	downloads := make(map[string]report.Operation)
	executableWrites := make(map[string]report.Operation)
	seen := make(map[string]bool)
	for _, operation := range result.Operations {
		command := filepath.Base(operation.Command)
		if isProcessExecution(operation) && (command == "curl" || command == "wget") {
			for _, output := range downloadOutputPaths(command, operation.Arguments) {
				if literalCorrelationPath(output) {
					downloads[operation.Evidence.Path+"\x00"+filepath.Clean(output)] = operation
				}
			}
		}
		if filepath.Base(operation.Command) == "chmod" && !operation.Dynamic && len(operation.Arguments) >= 2 {
			for _, target := range operation.Arguments[1:] {
				key := operation.Evidence.Path + "\x00" + filepath.Clean(target)
				if _, downloaded := downloads[key]; downloaded && executableModeChange(operation, target) {
					executableWrites[key] = operation
				}
			}
		}
		target := executionFileTarget(operation)
		if !literalCorrelationPath(target) {
			continue
		}
		download, exists := downloads[operation.Evidence.Path+"\x00"+filepath.Clean(target)]
		if !exists || download.ID == operation.ID || download.Evidence.LineStart > operation.Evidence.LineStart ||
			(download.Evidence.LineStart == operation.Evidence.LineStart && strings.HasPrefix(operation.Category, "process-execution-via-")) {
			continue
		}
		key := download.ID + "\x00" + operation.ID
		if seen[key] {
			continue
		}
		seen[key] = true
		evidence := []report.Evidence{download.Evidence, operation.Evidence}
		related := []string{download.ID, operation.ID}
		title := "Downloads content to a path later invoked as code"
		if modeChange, exists := executableWrites[operation.Evidence.Path+"\x00"+filepath.Clean(target)]; exists &&
			operationAfter(download.Evidence, modeChange.Evidence) && operationAfter(modeChange.Evidence, operation.Evidence) {
			evidence = []report.Evidence{download.Evidence, modeChange.Evidence, operation.Evidence}
			related = []string{download.ID, modeChange.ID, operation.ID}
			title = "Downloads content, marks it executable, and later invokes it"
		}
		appendFinding(result, report.Finding{
			ID:    "finding-staged-download-execute-" + download.ID + "-" + operation.ID,
			Claim: report.ClaimInference, Severity: report.SeverityHigh, Confidence: report.ConfidenceMedium,
			Category: "download-and-execute", Title: title,
			Explanation: "The source downloads content to " + target + " and later invokes that same literal path. This combination can execute remotely supplied code, but static analysis does not establish control flow, download success, file permissions, or the bytes present at invocation time.",
			Evidence:    evidence, Related: related,
			Provenance: sourceProvenance(correlationRuleID),
		})
	}
}

func literalCorrelationPath(value string) bool {
	return value != "" && value != "." && !strings.Contains(value, "<dynamic>") && literalDomain(value) == ""
}

func executionFileTarget(operation report.Operation) string {
	if operation.Dynamic || !isProcessExecution(operation) {
		return ""
	}
	command := filepath.Base(operation.Command)
	if strings.Contains(operation.Command, "/") {
		return operation.Command
	}
	switch command {
	case "source", ".", "exec":
		if len(operation.Arguments) > 0 && !strings.HasPrefix(operation.Arguments[0], "-") {
			return operation.Arguments[0]
		}
	case "sh", "bash", "zsh", "python", "python3", "node":
		return interpreterFileArgument(command, operation.Arguments)
	}
	return ""
}

func isProcessExecution(operation report.Operation) bool {
	return operation.Category == "process-execution" || strings.HasPrefix(operation.Category, "process-execution-via-")
}

func interpreterFileArgument(command string, arguments []string) string {
	optionsEnded := false
	for _, argument := range arguments {
		if !optionsEnded && argument == "--" {
			optionsEnded = true
			continue
		}
		if !optionsEnded && strings.HasPrefix(argument, "-") {
			if argument == "-c" || strings.Contains(argument, "--eval") ||
				(command == "node" && (argument == "-e" || argument == "-p" || argument == "--print")) ||
				((command == "python" || command == "python3") && argument == "-m") ||
				((command == "sh" || command == "bash" || command == "zsh") && !strings.HasPrefix(argument, "--") && strings.Contains(argument[1:], "c")) {
				return ""
			}
			if interpreterNoValueOption(command, argument) {
				continue
			}
			return ""
		}
		return argument
	}
	return ""
}

func interpreterNoValueOption(command, argument string) bool {
	switch command {
	case "sh", "bash", "zsh":
		if argument == "--noprofile" || argument == "--norc" || argument == "--posix" || argument == "--restricted" || argument == "--verbose" {
			return true
		}
		if len(argument) < 2 || strings.HasPrefix(argument, "--") {
			return false
		}
		for _, option := range argument[1:] {
			if !strings.ContainsRune("abefhknptuvx", option) {
				return false
			}
		}
		return true
	case "python", "python3":
		return argument == "-B" || argument == "-E" || argument == "-I" || argument == "-O" || argument == "-OO" ||
			argument == "-P" || argument == "-q" || argument == "-s" || argument == "-S" || argument == "-u" ||
			argument == "-v" || argument == "-V" || argument == "-x"
	case "node":
		return argument == "--no-warnings" || argument == "--use-strict" || argument == "--preserve-symlinks" || argument == "--preserve-symlinks-main"
	default:
		return false
	}
}

func networkCommand(command string) bool {
	switch command {
	case "curl", "wget", "git", "ssh", "scp", "sftp", "rsync", "nc", "ncat", "socat":
		return true
	default:
		return false
	}
}

func addPathResource(result *Result, seen map[string]bool, operation report.Operation, access, value string) {
	if rawStorageDevice(value) {
		added := addResource(result, seen, operation, "device-path", access, value, true, strings.Contains(value, "<dynamic>"))
		if added {
			addRawDeviceImpactFinding(result, operation, access, value)
		}
		return
	}
	sensitive := sensitivePath(value)
	added := addResource(result, seen, operation, "filesystem-path", access, value, sensitive, strings.Contains(value, "<dynamic>"))
	if sensitive && added {
		appendFinding(result, report.Finding{
			ID:    "finding-sensitive-path-" + operation.ID + "-" + stablePathID(value),
			Claim: report.ClaimFact, Severity: report.SeverityHigh, Confidence: operation.Confidence,
			Category: "credential-access", Title: "Accesses a credential-related path",
			Explanation: fmt.Sprintf("The operation attempts to %s %s, a path commonly associated with credentials, authentication material, or browser identity data. Static analysis does not establish whether the path exists or whether access succeeds.", access, value),
			Evidence:    []report.Evidence{operation.Evidence}, Related: []string{operation.ID}, Provenance: sourceProvenance("sensitive-path-access/v1"),
		})
	}
	if access != "read" && persistencePath(value) {
		addPersistence(result, seen, operation, value)
	}
}

func addRawDeviceImpactFinding(result *Result, operation report.Operation, access, value string) {
	command := filepath.Base(operation.Command)
	destructive := false
	sensitiveRead := false
	switch access {
	case "read":
		switch command {
		case "cat", "head", "tail", "cp", "install", "dd":
			sensitiveRead = true
		}
	case "write", "read-write":
		destructive = operation.Category == "filesystem-redirection"
		if !destructive {
			switch command {
			case "tee", "truncate", "cp", "install", "mv", "dd", "curl", "wget":
				destructive = true
			}
		}
	case "delete":
		if command != "rm" && command != "unlink" && command != "rmdir" {
			destructive = true
		}
	}
	if !destructive && !sensitiveRead {
		return
	}
	category := "sensitive-storage-access"
	title := "Reads directly from a raw storage device"
	explanation := "The operation names " + value + " as a raw storage input. Direct device reads can expose filesystem contents, deleted data, credentials, or other users' information. Static analysis does not establish that the device exists or that access succeeds."
	if destructive {
		category = "destructive-operation"
		title = "Modifies a raw storage device"
		explanation = "The operation names " + value + " as a raw storage output or destructive target. This can overwrite, replace, or remove partition, filesystem, disk data, or its device node. Static analysis does not establish that the device exists or that access succeeds."
	}
	appendFinding(result, report.Finding{
		ID: "finding-raw-device-" + access + "-" + operation.ID + "-" + stablePathID(value), Claim: report.ClaimFact,
		Severity: report.SeverityHigh, Confidence: operation.Confidence, Category: category,
		Title: title, Explanation: explanation, Evidence: []report.Evidence{operation.Evidence},
		Related: []string{operation.ID}, Provenance: sourceProvenance("raw-device-impact/v1"),
	})
}

func addResource(result *Result, seen map[string]bool, operation report.Operation, kind, access, value string, sensitive, dynamic bool) bool {
	key := operation.ID + "\x00" + kind + "\x00" + access + "\x00" + value
	if seen[key] {
		return false
	}
	seen[key] = true
	appendResource(result, report.Resource{
		ID:   "resource-" + operation.ID + "-" + stablePathID(kind+"-"+access+"-"+value),
		Kind: kind, Access: access, Value: value, Sensitive: sensitive, Dynamic: dynamic,
		Confidence: operation.Confidence, Evidence: operation.Evidence, RelatedOperationID: operation.ID,
	})
	return true
}

func addPersistence(result *Result, seen map[string]bool, operation report.Operation, mechanism string) {
	addResource(result, seen, operation, "persistence", "modify", mechanism, false, operation.Dynamic)
	appendFinding(result, report.Finding{
		ID:    "finding-persistence-" + operation.ID + "-" + stablePathID(mechanism),
		Claim: report.ClaimFact, Severity: report.SeverityMedium, Confidence: operation.Confidence,
		Category: "persistence", Title: "Configures a persistence mechanism",
		Explanation: "The operation modifies " + mechanism + ", which can cause code or services to run again after the immediate plugin interaction or in future sessions.",
		Evidence:    []report.Evidence{operation.Evidence}, Related: []string{operation.ID}, Provenance: sourceProvenance("persistence-capability/v1"),
	})
}

func addDestructiveFinding(result *Result, operation report.Operation, operands []string) {
	severity := report.SeverityLow
	if recursiveRemoval(operation.Arguments) || operation.Dynamic {
		severity = report.SeverityMedium
	}
	for _, operand := range operands {
		if operand == "/" {
			severity = report.SeverityCritical
		} else if rawStorageDevice(operand) || sensitivePath(operand) || persistencePath(operand) || operand == "/etc" || operand == "/home" || strings.HasPrefix(operand, "/home/") {
			if severity != report.SeverityCritical {
				severity = report.SeverityHigh
			}
		}
	}
	appendFinding(result, report.Finding{
		ID: "finding-delete-" + operation.ID, Claim: report.ClaimFact, Severity: severity,
		Confidence: operation.Confidence, Category: "destructive-operation", Title: "Deletes filesystem content",
		Explanation: "The command deletes " + strings.Join(operands, ", ") + ". Severity reflects the visible targets, recursive flags, and whether arguments are dynamic; static analysis cannot prove the paths present at runtime.",
		Evidence:    []report.Evidence{operation.Evidence}, Related: []string{operation.ID}, Provenance: sourceProvenance("destructive-operation/v1"),
	})
}

func literalDomain(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "ftp", "ftps", "ssh", "git", "rsync":
		return strings.ToLower(parsed.Hostname())
	default:
		return ""
	}
}

func networkDomains(command string, arguments []string) []string {
	var domains []string
	seen := make(map[string]bool)
	add := func(domain string) {
		domain = strings.ToLower(strings.TrimSuffix(domain, "."))
		if domain != "" && !seen[domain] {
			seen[domain] = true
			domains = append(domains, domain)
		}
	}
	switch command {
	case "curl", "wget":
		for _, argument := range arguments {
			add(literalDomain(argument))
		}
	case "ssh", "sftp":
		for _, argument := range arguments {
			add(literalDomain(argument))
		}
		add(sshDestination(arguments))
	case "scp", "rsync":
		for _, argument := range arguments {
			add(literalDomain(argument))
			add(remoteSpecDomain(argument))
		}
	case "git":
		verbIndex, verb := gitVerb(arguments)
		if verb == "clone" || verb == "fetch" || verb == "pull" || verb == "push" || verb == "ls-remote" {
			for _, argument := range arguments[verbIndex+1:] {
				add(literalDomain(argument))
				add(remoteSpecDomain(argument))
			}
		}
	case "nc", "ncat":
		if len(arguments) >= 2 && decimal(arguments[len(arguments)-1]) {
			add(literalHost(arguments[len(arguments)-2]))
		}
	case "socat":
		for _, argument := range arguments {
			add(socatDomain(argument))
		}
	}
	return domains
}

func sshDestination(arguments []string) string {
	optionsEnded := false
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if !optionsEnded && argument == "--" {
			optionsEnded = true
			continue
		}
		if !optionsEnded && strings.HasPrefix(argument, "-") {
			if sshOptionTakesNextArgument(argument) && index+1 < len(arguments) {
				index++
			}
			continue
		}
		return literalHost(argument)
	}
	return ""
}

func sshOptionTakesNextArgument(argument string) bool {
	if len(argument) != 2 {
		return false
	}
	return strings.Contains("BbCcDEeFIiJLlmOoPpQRSWw", argument[1:])
}

func remoteSpecDomain(value string) string {
	if strings.Contains(value, "://") || strings.Contains(value, "<dynamic>") || strings.HasPrefix(value, "-") {
		return ""
	}
	colon := strings.IndexByte(value, ':')
	if colon <= 0 || colon == len(value)-1 {
		return ""
	}
	host := value[:colon]
	if strings.Contains(host, "/") {
		return ""
	}
	return literalHost(host)
}

func socatDomain(value string) string {
	parts := strings.Split(value, ":")
	if len(parts) < 3 {
		return ""
	}
	switch strings.ToLower(parts[0]) {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6", "openssl":
		return literalHost(parts[1])
	default:
		return ""
	}
}

func literalHost(value string) string {
	if at := strings.LastIndexByte(value, '@'); at >= 0 {
		value = value[at+1:]
	}
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/:<>") {
		return ""
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' && character != '_' {
				return ""
			}
		}
	}
	return value
}

func decimal(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func gitVerb(arguments []string) (int, string) {
	optionsEnded := false
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if !optionsEnded && argument == "--" {
			optionsEnded = true
			continue
		}
		if !optionsEnded && strings.HasPrefix(argument, "-") {
			if gitOptionTakesNextArgument(argument) && index+1 < len(arguments) {
				index++
			}
			continue
		}
		return index, argument
	}
	return -1, ""
}

func gitOptionTakesNextArgument(argument string) bool {
	switch argument {
	case "-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env":
		return true
	default:
		return false
	}
}

func linkDestination(arguments []string) string {
	operands := make([]string, 0, len(arguments))
	optionsEnded := false
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if !optionsEnded && argument == "--" {
			optionsEnded = true
			continue
		}
		if !optionsEnded && (argument == "-t" || argument == "--target-directory" ||
			strings.HasPrefix(argument, "--target-directory=") ||
			(strings.HasPrefix(argument, "-t") && len(argument) > 2)) {
			return ""
		}
		if !optionsEnded && strings.HasPrefix(argument, "-") {
			if (argument == "-S" || argument == "--suffix") && index+1 < len(arguments) {
				index++
			}
			continue
		}
		if argument != "" {
			operands = append(operands, argument)
		}
	}
	if len(operands) < 2 {
		return ""
	}
	return operands[len(operands)-1]
}

func destructiveOperands(arguments []string) []string {
	operands := make([]string, 0, len(arguments))
	optionsEnded := false
	for _, argument := range arguments {
		if !optionsEnded && argument == "--" {
			optionsEnded = true
			continue
		}
		if !optionsEnded && strings.HasPrefix(argument, "-") {
			continue
		}
		if argument != "" {
			operands = append(operands, argument)
		}
	}
	return operands
}

func sensitivePath(value string) bool {
	normalized := "/" + strings.Trim(strings.ToLower(filepath.ToSlash(value)), "/") + "/"
	for _, marker := range []string{
		"/.ssh/", "/.gnupg/", "/.aws/credentials/", "/.config/gcloud/", "/.azure/",
		"/.docker/config.json/", "/.kube/config/", "/.config/gh/hosts.yml/",
		"/.netrc/", "/.npmrc/", "/.pypirc/", "/.git-credentials/", "/.authinfo/", "/.authinfo.gpg/",
		"/.password-store/", "/.config/1password/", "/.config/bitwarden/",
		"/keyring/", "/keyrings/", "/credentials/", "/credentials.toml/",
		"/id_rsa/", "/id_ed25519/", "/.mozilla/", "/chromium/", "/google-chrome/",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return strings.HasSuffix(strings.TrimSuffix(normalized, "/"), ".kdbx")
}

func persistencePath(value string) bool {
	normalized := "/" + strings.Trim(strings.ToLower(filepath.ToSlash(value)), "/") + "/"
	for _, marker := range []string{
		"/.bashrc/", "/.bash_profile/", "/.bash_login/", "/.profile/",
		"/.zshrc/", "/.zprofile/", "/.zlogin/", "/.xprofile/", "/.xinitrc/",
		"/.config/fish/config.fish/", "/.config/fish/conf.d/",
		"/autostart/", "/systemd/user/", "/environment.d/",
		"/cron.d/", "/cron.daily/", "/cron.hourly/", "/cron.weekly/", "/cron.monthly/",
		"/var/spool/cron/", "/crontab/", "/.ssh/authorized_keys/",
		"/.config/hypr/hyprland.conf/",
		"/etc/profile/", "/etc/bash.bashrc/", "/etc/zsh/zshenv/",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func recursiveRemoval(arguments []string) bool {
	for _, argument := range arguments {
		if argument == "-r" || argument == "-R" || argument == "--recursive" ||
			(strings.HasPrefix(argument, "-") && !strings.HasPrefix(argument, "--") && strings.ContainsAny(argument[1:], "rR")) {
			return true
		}
	}
	return false
}

func firstNonOption(arguments []string) string {
	for _, argument := range arguments {
		if argument == "--" {
			continue
		}
		if !strings.HasPrefix(argument, "-") {
			return argument
		}
	}
	return ""
}

func readOnlyCrontab(arguments []string) bool {
	list := false
	for index := 0; index < len(arguments); index++ {
		switch arguments[index] {
		case "-l":
			list = true
		case "-u":
			if index+1 >= len(arguments) {
				return false
			}
			index++
		default:
			return false
		}
	}
	return list
}

func containsArgument(arguments []string, wanted string) bool {
	for _, argument := range arguments {
		if argument == wanted {
			return true
		}
	}
	return false
}
