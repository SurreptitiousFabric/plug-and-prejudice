package analyze

import (
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func deriveCapabilities(result *Result) {
	seen := make(map[string]bool)
	for _, operation := range result.Operations {
		command := filepath.Base(operation.Command)
		if networkCommand(command) {
			domains := 0
			for _, argument := range operation.Arguments {
				if domain := literalDomain(argument); domain != "" {
					addResource(result, seen, operation, "network-domain", "connect", domain, false, false)
					domains++
				}
			}
			if domains == 0 && operation.Dynamic {
				addResource(result, seen, operation, "network-domain", "connect", "<dynamic>", false, true)
			}
		}
		switch command {
		case "cat", "head", "tail", "readlink":
			for _, operand := range pathOperands(operation.Arguments) {
				addPathResource(result, seen, operation, "read", operand)
			}
		case "touch", "mkdir", "tee", "truncate", "chmod", "chown":
			for _, operand := range pathOperands(operation.Arguments) {
				addPathResource(result, seen, operation, "write", operand)
			}
		case "rm", "unlink", "rmdir":
			operands := pathOperands(operation.Arguments)
			for _, operand := range operands {
				addPathResource(result, seen, operation, "delete", operand)
			}
			if len(operands) > 0 {
				addDestructiveFinding(result, operation, operands)
			}
		case "cp", "install":
			operands := pathOperands(operation.Arguments)
			if len(operands) > 1 {
				for _, operand := range operands[:len(operands)-1] {
					addPathResource(result, seen, operation, "read", operand)
				}
				addPathResource(result, seen, operation, "write", operands[len(operands)-1])
			}
		case "mv":
			operands := pathOperands(operation.Arguments)
			if len(operands) > 1 {
				addPathResource(result, seen, operation, "delete", operands[0])
				addPathResource(result, seen, operation, "write", operands[len(operands)-1])
			}
		case "systemctl":
			if containsArgument(operation.Arguments, "enable") || containsArgument(operation.Arguments, "reenable") {
				addPersistence(result, seen, operation, "systemd service enablement")
			}
		case "crontab":
			addPersistence(result, seen, operation, "cron configuration")
		}
	}
	sort.Slice(result.Resources, func(i, j int) bool { return result.Resources[i].ID < result.Resources[j].ID })
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
	sensitive := sensitivePath(value)
	added := addResource(result, seen, operation, "filesystem-path", access, value, sensitive, strings.Contains(value, "<dynamic>"))
	if sensitive && added {
		result.Findings = append(result.Findings, report.Finding{
			ID:    "finding-sensitive-path-" + operation.ID + "-" + stablePathID(value),
			Claim: report.ClaimFact, Severity: report.SeverityHigh, Confidence: operation.Confidence,
			Category: "credential-access", Title: "Accesses a credential-related path",
			Explanation: fmt.Sprintf("The operation attempts to %s %s, a path commonly associated with credentials, authentication material, or browser identity data. Static analysis does not establish whether the path exists or whether access succeeds.", access, value),
			Evidence:    []report.Evidence{operation.Evidence}, Related: []string{operation.ID}, Provenance: sourceProvenance("command-capability/v1"),
		})
	}
	if access != "read" && persistencePath(value) {
		addPersistence(result, seen, operation, value)
	}
}

func addResource(result *Result, seen map[string]bool, operation report.Operation, kind, access, value string, sensitive, dynamic bool) bool {
	key := operation.ID + "\x00" + kind + "\x00" + access + "\x00" + value
	if seen[key] {
		return false
	}
	seen[key] = true
	result.Resources = append(result.Resources, report.Resource{
		ID:   "resource-" + operation.ID + "-" + stablePathID(kind+"-"+access+"-"+value),
		Kind: kind, Access: access, Value: value, Sensitive: sensitive, Dynamic: dynamic,
		Confidence: operation.Confidence, Evidence: operation.Evidence, RelatedOperationID: operation.ID,
		Provenance: sourceProvenance("command-capability/v1"),
	})
	return true
}

func addPersistence(result *Result, seen map[string]bool, operation report.Operation, mechanism string) {
	addResource(result, seen, operation, "persistence", "modify", mechanism, false, operation.Dynamic)
	result.Findings = append(result.Findings, report.Finding{
		ID:    "finding-persistence-" + operation.ID + "-" + stablePathID(mechanism),
		Claim: report.ClaimFact, Severity: report.SeverityMedium, Confidence: operation.Confidence,
		Category: "persistence", Title: "Configures a persistence mechanism",
		Explanation: "The operation modifies " + mechanism + ", which can cause code or services to run again after the immediate plugin interaction or in future sessions.",
		Evidence:    []report.Evidence{operation.Evidence}, Related: []string{operation.ID}, Provenance: sourceProvenance("command-capability/v1"),
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
		} else if sensitivePath(operand) || persistencePath(operand) || operand == "/etc" || operand == "/home" || strings.HasPrefix(operand, "/home/") {
			if severity != report.SeverityCritical {
				severity = report.SeverityHigh
			}
		}
	}
	result.Findings = append(result.Findings, report.Finding{
		ID: "finding-delete-" + operation.ID, Claim: report.ClaimFact, Severity: severity,
		Confidence: operation.Confidence, Category: "destructive-operation", Title: "Deletes filesystem content",
		Explanation: "The command deletes " + strings.Join(operands, ", ") + ". Severity reflects the visible targets, recursive flags, and whether arguments are dynamic; static analysis cannot prove the paths present at runtime.",
		Evidence:    []report.Evidence{operation.Evidence}, Related: []string{operation.ID}, Provenance: sourceProvenance("command-capability/v1"),
	})
}

func literalDomain(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

func pathOperands(arguments []string) []string {
	var paths []string
	for _, argument := range arguments {
		if argument == "" || strings.HasPrefix(argument, "-") || literalDomain(argument) != "" {
			continue
		}
		if argument == "/" || strings.HasPrefix(argument, "/") || strings.HasPrefix(argument, "~") || strings.HasPrefix(argument, ".") || strings.Contains(argument, "/") || strings.Contains(argument, "<dynamic>") {
			paths = append(paths, argument)
		}
	}
	return paths
}

func sensitivePath(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{".ssh", ".gnupg", ".aws/credentials", ".config/gcloud", "keyring", "credentials", "id_rsa", "id_ed25519", "mozilla", "chromium", "google-chrome"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func persistencePath(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{".bashrc", ".zshrc", ".profile", "/autostart/", "/systemd/user/", "/cron.", "/crontab"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func recursiveRemoval(arguments []string) bool {
	for _, argument := range arguments {
		if argument == "-r" || argument == "-R" || argument == "--recursive" || (strings.HasPrefix(argument, "-") && strings.Contains(strings.ToLower(argument), "r")) {
			return true
		}
	}
	return false
}

func containsArgument(arguments []string, wanted string) bool {
	for _, argument := range arguments {
		if argument == wanted {
			return true
		}
	}
	return false
}
