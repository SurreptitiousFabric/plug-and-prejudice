package analyze

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

const correlationRuleID = "operation-correlation/v1"

// correlateBehaviorCombinations consumes only already-retained operations and
// resources. It never reparses source and never treats co-presence as proven
// data flow. Each loop is linear in a producer-bounded collection.
func correlateBehaviorCombinations(result *Result) {
	correlateSensitiveReadsWithNetwork(result)
	correlatePersistenceWithExecution(result)
	correlateDynamicPrivilege(result)
	correlateSystemdInstallExecution(result)
	correlateSystemdActivationExecution(result)
}

func correlateSystemdInstallExecution(result *Result) {
	type unitOperations struct {
		install *report.Operation
		execs   []*report.Operation
	}
	units := make(map[string]*unitOperations)
	for index := range result.Operations {
		operation := &result.Operations[index]
		if operation.Category != "systemd-install-metadata" && operation.Category != "process-execution-via-systemd-unit" {
			continue
		}
		unit := units[operation.Evidence.Path]
		if unit == nil {
			unit = &unitOperations{}
			units[operation.Evidence.Path] = unit
		}
		if operation.Category == "systemd-install-metadata" && unit.install == nil {
			unit.install = operation
		} else if operation.Category == "process-execution-via-systemd-unit" && len(unit.execs) < report.MaxFindingEvidence-1 {
			unit.execs = append(unit.execs, operation)
		}
	}
	paths := make([]string, 0, len(units))
	for path := range units {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		unit := units[path]
		if unit.install == nil || len(unit.execs) == 0 {
			continue
		}
		evidence := []report.Evidence{unit.install.Evidence}
		related := []string{unit.install.ID}
		confidence := report.ConfidenceHigh
		for _, operation := range unit.execs {
			evidence = append(evidence, operation.Evidence)
			related = append(related, operation.ID)
			if operation.Dynamic {
				confidence = report.ConfidenceMedium
			}
		}
		if unit.install.Dynamic {
			confidence = report.ConfidenceMedium
		}
		appendFinding(result, report.Finding{
			ID: "finding-systemd-persistent-exec-" + unit.install.ID, Claim: report.ClaimInference, Severity: report.SeverityMedium, Confidence: confidence,
			Category: "persistent-service-execution", Title: "Combines systemd enablement metadata with configured execution",
			Explanation: "The same unit file declares both commands and targets used during enablement. If installed and enabled, the configured service can run beyond the immediate plugin interaction; installation, enablement, activation, and command success remain unestablished.",
			Evidence:    evidence, Related: related, Provenance: sourceProvenance("systemd-install-execution-correlation/v1"),
		})
	}
}

func correlateSystemdActivationExecution(result *Result) {
	type activationUnit struct {
		triggers []*report.Operation
		target   *report.Operation
	}
	activations := make(map[string]*activationUnit)
	executions := make(map[string][]*report.Operation)
	for index := range result.Operations {
		operation := &result.Operations[index]
		switch operation.Category {
		case "systemd-activation-trigger", "systemd-unit-reference":
			unit := activations[operation.Evidence.Path]
			if unit == nil {
				unit = &activationUnit{}
				activations[operation.Evidence.Path] = unit
			}
			if operation.Category == "systemd-activation-trigger" && len(unit.triggers) < report.MaxFindingEvidence-1 {
				unit.triggers = append(unit.triggers, operation)
			} else if operation.Category == "systemd-unit-reference" && unit.target == nil {
				unit.target = operation
			}
		case "process-execution-via-systemd-unit":
			if len(executions[operation.Evidence.Path]) < report.MaxFindingEvidence-1 {
				executions[operation.Evidence.Path] = append(executions[operation.Evidence.Path], operation)
			}
		}
	}
	paths := make([]string, 0, len(activations))
	for source := range activations {
		paths = append(paths, source)
	}
	sort.Strings(paths)
	for _, source := range paths {
		activation := activations[source]
		if len(activation.triggers) == 0 {
			continue
		}
		target := defaultSystemdServicePath(source)
		if activation.target != nil {
			if activation.target.Dynamic || len(activation.target.Arguments) != 1 || !safeSystemdUnitName(activation.target.Arguments[0]) {
				continue
			}
			target = filepath.ToSlash(filepath.Join(filepath.Dir(source), activation.target.Arguments[0]))
		}
		execs := executions[target]
		if len(execs) == 0 {
			continue
		}
		evidence := make([]report.Evidence, 0, report.MaxFindingEvidence)
		related := make([]string, 0, report.MaxFindingRelated)
		confidence := report.ConfidenceHigh
		for _, trigger := range activation.triggers {
			evidence = append(evidence, trigger.Evidence)
			related = append(related, trigger.ID)
			if trigger.Dynamic {
				confidence = report.ConfidenceMedium
			}
		}
		if activation.target != nil && len(evidence) < report.MaxFindingEvidence {
			evidence = append(evidence, activation.target.Evidence)
			related = append(related, activation.target.ID)
		}
		for _, execution := range execs {
			if len(evidence) >= report.MaxFindingEvidence || len(related) >= report.MaxFindingRelated {
				break
			}
			evidence = append(evidence, execution.Evidence)
			related = append(related, execution.ID)
			if execution.Dynamic {
				confidence = report.ConfidenceMedium
			}
		}
		appendFinding(result, report.Finding{
			ID: "finding-systemd-triggered-exec-" + activation.triggers[0].ID, Claim: report.ClaimInference, Severity: report.SeverityMedium, Confidence: confidence,
			Category: "triggered-service-execution", Title: "Connects a systemd activation trigger to configured service execution",
			Explanation: "A timer, path, or socket unit references a service file that declares commands. If both units are installed and activated, the trigger can lead to those commands; installation, enablement, trigger occurrence, manager state, and command success remain unestablished.",
			Evidence:    evidence, Related: related, Provenance: sourceProvenance("systemd-activation-execution-correlation/v1"),
		})
	}
}

func defaultSystemdServicePath(source string) string {
	extension := filepath.Ext(source)
	if extension != ".timer" && extension != ".path" && extension != ".socket" {
		return ""
	}
	return strings.TrimSuffix(source, extension) + ".service"
}

func safeSystemdUnitName(value string) bool {
	return value != "" && filepath.Base(value) == value && !strings.Contains(value, "\\") && value != "." && value != ".." && strings.HasSuffix(value, ".service")
}

func correlateSensitiveReadsWithNetwork(result *Result) {
	var network *report.Resource
	for index := range result.Resources {
		resource := &result.Resources[index]
		if resource.Kind == "network-domain" && resource.Access == "connect" {
			network = resource
			break
		}
	}
	if network == nil {
		return
	}
	seenOperations := make(map[string]bool)
	for index := range result.Resources {
		sensitive := &result.Resources[index]
		if sensitive.Kind != "filesystem-path" || !sensitive.Sensitive ||
			(sensitive.Access != "read" && sensitive.Access != "read-write") ||
			seenOperations[sensitive.RelatedOperationID] {
			continue
		}
		seenOperations[sensitive.RelatedOperationID] = true
		if sensitive.RelatedOperationID == network.RelatedOperationID {
			continue
		}
		confidence := report.ConfidenceMedium
		if sensitive.Dynamic || network.Dynamic || sensitive.Confidence == report.ConfidenceLow || network.Confidence == report.ConfidenceLow {
			confidence = report.ConfidenceLow
		}
		appendFinding(result, report.Finding{
			ID:          "finding-sensitive-network-" + sensitive.RelatedOperationID + "-" + network.RelatedOperationID,
			Claim:       report.ClaimInference,
			Severity:    report.SeverityHigh,
			Confidence:  confidence,
			Category:    "sensitive-data-and-network",
			Title:       "Combines sensitive-file access with outbound network capability",
			Explanation: "The plugin contains one operation that attempts to read " + sensitive.Value + " and another that can contact " + network.Value + ". Together these capabilities could disclose credential, authentication, browser, or session data. Static analysis has not established control flow, successful access, or that bytes from the cited file reach the cited network operation.",
			Evidence:    []report.Evidence{sensitive.Evidence, network.Evidence},
			Related:     []string{sensitive.RelatedOperationID, network.RelatedOperationID},
			Provenance:  sourceProvenance(correlationRuleID),
		})
	}
}

func correlatePersistenceWithExecution(result *Result) {
	persistenceByPath := make(map[string]report.Resource)
	for _, resource := range result.Resources {
		if resource.Kind != "persistence" || resource.Dynamic || !literalCorrelationPath(resource.Value) {
			continue
		}
		clean := filepath.Clean(resource.Value)
		if _, exists := persistenceByPath[clean]; !exists {
			persistenceByPath[clean] = resource
		}
	}
	seen := make(map[string]bool)
	for _, operation := range result.Operations {
		target := executionFileTarget(operation)
		if !literalCorrelationPath(target) {
			continue
		}
		persistence, exists := persistenceByPath[filepath.Clean(target)]
		if !exists || persistence.RelatedOperationID == operation.ID ||
			!operationAfter(persistence.Evidence, operation.Evidence) {
			continue
		}
		key := persistence.RelatedOperationID + "\x00" + operation.ID
		if seen[key] {
			continue
		}
		seen[key] = true
		appendFinding(result, report.Finding{
			ID:          "finding-persistence-execute-" + persistence.RelatedOperationID + "-" + operation.ID,
			Claim:       report.ClaimInference,
			Severity:    report.SeverityMedium,
			Confidence:  report.ConfidenceMedium,
			Category:    "persistence-and-execution",
			Title:       "Modifies a startup path and later invokes that same path",
			Explanation: "The source modifies startup-related path " + target + " and later invokes that exact literal path as code. This can combine immediate execution with behavior that runs again in a future session. Static analysis does not establish control flow, the written bytes, write success, or the path contents at invocation time.",
			Evidence:    []report.Evidence{persistence.Evidence, operation.Evidence},
			Related:     []string{persistence.RelatedOperationID, operation.ID},
			Provenance:  sourceProvenance(correlationRuleID),
		})
	}
}

func correlateDynamicPrivilege(result *Result) {
	var dynamicExecution *report.Operation
	var privilege *report.Operation
	for index := range result.Operations {
		operation := &result.Operations[index]
		command := filepath.Base(operation.Command)
		if privilege == nil && (command == "sudo" || command == "pkexec" || command == "su" || command == "doas") {
			privilege = operation
		}
		if dynamicExecution == nil && isProcessExecution(*operation) && operation.Dynamic && command != "sudo" && command != "pkexec" && command != "su" && command != "doas" {
			dynamicExecution = operation
		}
		if privilege != nil && privilege.Dynamic {
			appendFinding(result, report.Finding{
				ID:          "finding-dynamic-privilege-" + privilege.ID,
				Claim:       report.ClaimInference,
				Severity:    report.SeverityHigh,
				Confidence:  report.ConfidenceMedium,
				Category:    "dynamic-privileged-execution",
				Title:       "Selects privileged execution behavior dynamically",
				Explanation: "A privilege-elevation operation contains a dynamically constructed command or argument. The requested authority is visible, but static analysis cannot resolve the executable or complete behavior selected at runtime.",
				Evidence:    []report.Evidence{privilege.Evidence},
				Related:     []string{privilege.ID},
				Provenance:  sourceProvenance(correlationRuleID),
			})
			return
		}
	}
	if dynamicExecution == nil || privilege == nil || dynamicExecution.ID == privilege.ID {
		return
	}
	appendFinding(result, report.Finding{
		ID:          "finding-dynamic-privilege-" + dynamicExecution.ID + "-" + privilege.ID,
		Claim:       report.ClaimInference,
		Severity:    report.SeverityHigh,
		Confidence:  report.ConfidenceLow,
		Category:    "dynamic-privileged-execution",
		Title:       "Combines dynamic execution with privilege elevation",
		Explanation: "The plugin contains both a dynamically selected execution operation and a privilege-elevation operation. Together they could run behavior that static analysis cannot resolve with additional authority, but no data flow or control-flow relationship between the cited operations has been established.",
		Evidence:    []report.Evidence{dynamicExecution.Evidence, privilege.Evidence},
		Related:     []string{dynamicExecution.ID, privilege.ID},
		Provenance:  sourceProvenance(correlationRuleID),
	})
}

func operationAfter(first, second report.Evidence) bool {
	if first.Path != second.Path {
		return false
	}
	return second.LineStart > first.LineStart
}

func executableModeChange(operation report.Operation, target string) bool {
	if filepath.Base(operation.Command) != "chmod" || operation.Dynamic || len(operation.Arguments) < 2 {
		return false
	}
	if !modeAddsExecute(operation.Arguments[0]) {
		return false
	}
	for _, argument := range operation.Arguments[1:] {
		if literalCorrelationPath(argument) && filepath.Clean(argument) == filepath.Clean(target) {
			return true
		}
	}
	return false
}

func modeAddsExecute(mode string) bool {
	if mode == "" || strings.HasPrefix(mode, "-") {
		return false
	}
	if numeric, err := strconv.ParseUint(mode, 8, 16); err == nil {
		return numeric&0o111 != 0
	}
	for _, clause := range strings.Split(mode, ",") {
		operator := strings.IndexAny(clause, "+=")
		if operator >= 0 && strings.Contains(clause[operator+1:], "x") {
			return true
		}
	}
	return false
}
