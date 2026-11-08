package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/buildinfo"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/policy"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
	"golang.org/x/sys/unix"
)

func TestInstalledPluginIDsListsOnlyRealValidDirectories(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"org.example.alpha", "zeta"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, ".hidden"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "plain-file"), []byte("not a plugin"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "zeta"), filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}

	got, err := installedPluginIDs(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"org.example.alpha", "zeta"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("installedPluginIDs() = %q, want %q", got, want)
	}
}

func TestExpectedResourceLimitsRequiresExactPolicy(t *testing.T) {
	limits := &report.ResourceLimits{
		MemoryMaxBytes: policy.MemoryMaxBytes, MemorySwapBytes: policy.MemorySwapBytes,
		TasksMax: policy.TasksMax, CPUQuotaPercent: policy.CPUQuotaPercent,
		WallTimeSeconds: int(policy.WallTime.Seconds()),
	}
	if !expectedResourceLimits(limits) {
		t.Fatal("exact resource policy was rejected")
	}
	limits.TasksMax++
	if expectedResourceLimits(limits) {
		t.Fatal("mismatched resource policy was accepted")
	}
}

func TestValidateBrokerReportBindsSelectedTargetAndPolicy(t *testing.T) {
	const selected = "org.example.plugin"
	valid := report.Report{
		Target: report.Target{DisplayName: selected, RootDigest: strings.Repeat("a", 64)},
		Scan: report.ScanMetadata{ScannerVersion: buildinfo.Version, ResourceLimits: &report.ResourceLimits{
			MemoryMaxBytes: policy.MemoryMaxBytes, MemorySwapBytes: policy.MemorySwapBytes,
			TasksMax: policy.TasksMax, CPUQuotaPercent: policy.CPUQuotaPercent,
			WallTimeSeconds: int(policy.WallTime.Seconds()),
		}},
	}
	if err := validateBrokerReport(valid, selected); err != nil {
		t.Fatalf("valid broker report was rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*report.Report)
		want   string
	}{
		{"wrong-target", func(r *report.Report) { r.Target.DisplayName = "org.example.other" }, "target identity"},
		{"wrong-scanner-version", func(r *report.Report) { r.Scan.ScannerVersion = "other" }, "scanner version"},
		{"missing-digest", func(r *report.Report) { r.Target.RootDigest = "" }, "root digest"},
		{"wrong-policy", func(r *report.Report) { r.Scan.ResourceLimits.TasksMax++ }, "resource policy"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := valid
			limits := *valid.Scan.ResourceLimits
			value.Scan.ResourceLimits = &limits
			test.mutate(&value)
			if err := validateBrokerReport(value, selected); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateBrokerReport() error = %v", err)
			}
		})
	}
}

func TestEncodeBrokerReportRoundTripsValidatedTypedValue(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "report", "testdata", "report-v2.0.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := report.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	value.Target.DisplayName = "<hostile>\u202e"
	encoded, err := encodeBrokerReport(value)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("<hostile>")) || !bytes.Contains(encoded, []byte(`\u003chostile\u003e`)) {
		t.Fatalf("canonical encoding did not retain JSON HTML escaping: %q", encoded[:min(len(encoded), 200)])
	}
	decoded, err := report.Decode(encoded)
	if err != nil || decoded.Target.DisplayName != value.Target.DisplayName {
		t.Fatalf("canonical round trip = %q, %v", decoded.Target.DisplayName, err)
	}
}

func TestEncodeBrokerReportRejectsOversizeWithoutOutput(t *testing.T) {
	value := report.Report{}
	base, err := encodeBrokerReport(value)
	if err != nil {
		t.Fatal(err)
	}
	value.Target.DisplayName = strings.Repeat("x", policy.MaxReportBytes-len(base))
	exact, err := encodeBrokerReport(value)
	if err != nil || len(exact) != policy.MaxReportBytes {
		t.Fatalf("exact canonical report = %d bytes, %v", len(exact), err)
	}
	value.Target.DisplayName += "x"
	over, err := encodeBrokerReport(value)
	if err == nil || over != nil || !strings.Contains(err.Error(), "exceeds byte limit") {
		t.Fatalf("first-byte-oversize canonical report = %d bytes, %v", len(over), err)
	}
}

func TestDuplicateScannerMemberIsNotForwarded(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "report", "testdata", "report-v2.0.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	duplicate := bytes.Replace(raw, []byte(`"displayName": "fixture.plugin"`), []byte(`"displayName": "first", "displayName": "fixture.plugin"`), 1)
	if bytes.Equal(duplicate, raw) {
		t.Fatal("test fixture did not receive duplicate member")
	}
	value, err := report.Decode(duplicate)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeBrokerReport(value)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(encoded, []byte(`"displayName"`)) != 1 || bytes.Contains(encoded, []byte(`"first"`)) {
		t.Fatalf("scanner representation crossed typed boundary: %s", encoded)
	}
}

func TestCanonicalBrokerReportPreservesDecodedHostileStringSemantics(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "report", "testdata", "report-v2.0.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	needle := []byte(`"displayName": "fixture.plugin"`)
	cases := map[string][]byte{
		"lone surrogate": []byte(`"displayName": "\ud800"`),
		"invalid UTF-8":  append([]byte(`"displayName": "`), []byte{0xff, '"'}...),
		"HTML":           []byte(`"displayName": "<>&"`),
		"C0":             []byte(`"displayName": "\u0001"`),
		"C1":             []byte("\"displayName\": \"\u0085\""),
		"bidi":           []byte("\"displayName\": \"\u202e\u2066\""),
	}
	for name, replacement := range cases {
		t.Run(name, func(t *testing.T) {
			hostile := bytes.Replace(raw, needle, replacement, 1)
			if bytes.Equal(hostile, raw) {
				t.Fatal("fixture display name was not replaced")
			}
			value, err := report.Decode(hostile)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := encodeBrokerReport(value)
			if err != nil {
				t.Fatal(err)
			}
			if !utf8.Valid(encoded) {
				t.Fatal("canonical output is not valid UTF-8")
			}
			decoded, err := report.Decode(encoded)
			if err != nil || decoded.Target.DisplayName != value.Target.DisplayName {
				t.Fatalf("canonical semantic round trip = %q, want %q, error %v", decoded.Target.DisplayName, value.Target.DisplayName, err)
			}
		})
	}
}

func TestBrokerDiagnosticIsSanitizedAndBoundedBeforeStderr(t *testing.T) {
	hostile := "before\x1b[31m\u202e" + strings.Repeat("x", maxBrokerDiagnosticBytes*2)
	got := brokerDiagnostic("validate scanner report", errors.New(hostile))
	if len(got) != maxBrokerDiagnosticBytes {
		t.Fatalf("broker diagnostic length = %d", len(got))
	}
	if strings.ContainsAny(got, "\x1b\u202e") || !strings.HasSuffix(got, "...[truncated]") {
		t.Fatalf("broker diagnostic was not sanitized and marked: %q", got[:min(len(got), 80)])
	}
}

func TestInstalledPluginIDsRejectsSymlinkRoot(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(t.TempDir(), "plugins")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := installedPluginIDs(link); err == nil {
		t.Fatal("symlink plugin root was accepted")
	}
}

func TestInstalledPluginIDsRejectsTooManyPlugins(t *testing.T) {
	root := t.TempDir()
	for index := 0; index < maxInstalledPlugins; index++ {
		if err := os.Mkdir(filepath.Join(root, fmt.Sprintf("plugin-%04d", index)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if plugins, err := installedPluginIDs(root); err != nil || len(plugins) != maxInstalledPlugins {
		t.Fatalf("exact plugin limit result = %d, %v", len(plugins), err)
	}
	if err := os.Mkdir(filepath.Join(root, "plugin-over-limit"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := installedPluginIDs(root); err == nil || !strings.Contains(err.Error(), "installed plugin count") {
		t.Fatalf("installedPluginIDs() error = %v", err)
	}
}

func TestInstalledPluginIDsBoundsAllRootEntries(t *testing.T) {
	root := t.TempDir()
	for index := 0; index < maxPluginRootEntries; index++ {
		name := filepath.Join(root, fmt.Sprintf(".ignored-%04d", index))
		if err := os.WriteFile(name, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if plugins, err := installedPluginIDs(root); err != nil || len(plugins) != 0 {
		t.Fatalf("exact root-entry limit result = %d, %v", len(plugins), err)
	}
	if err := os.WriteFile(filepath.Join(root, ".ignored-over-limit"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := installedPluginIDs(root); err == nil || !strings.Contains(err.Error(), "root entry count") {
		t.Fatalf("installedPluginIDs() error = %v", err)
	}
}

func TestValidPluginID(t *testing.T) {
	for _, value := range []string{"", ".hidden", "../escape", "a/child", "two..dots", "space name"} {
		if validPluginID(value) {
			t.Errorf("validPluginID(%q) = true", value)
		}
	}
	for _, value := range []string{"org.example.plugin", "plugin-name", "plugin_name", "Plugin1"} {
		if !validPluginID(value) {
			t.Errorf("validPluginID(%q) = false", value)
		}
	}
}

func TestOpenInstalledTargetSelectsDirectChildDescriptor(t *testing.T) {
	root := t.TempDir()
	targetPath := filepath.Join(root, "org.example.plugin")
	if err := os.Mkdir(targetPath, 0o700); err != nil {
		t.Fatal(err)
	}
	target, err := openInstalledTarget(root, "org.example.plugin")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	opened, err := target.Stat()
	if err != nil || !opened.IsDir() {
		t.Fatalf("opened target = %#v, %v", opened, err)
	}
}

func TestOpenInstalledTargetRejectsSymlinkChild(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "org.example.plugin")); err != nil {
		t.Fatal(err)
	}
	if target, err := openInstalledTarget(root, "org.example.plugin"); err == nil {
		target.Close()
		t.Fatal("descriptor-relative selection accepted symlink child")
	}
}

func TestOpenInstalledTargetRejectsSymlinkRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "plugins")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "org.example.plugin"), 0o700); err != nil {
		t.Fatal(err)
	}
	linkRoot := filepath.Join(parent, "linked-plugins")
	if err := os.Symlink(root, linkRoot); err != nil {
		t.Fatal(err)
	}
	if target, err := openInstalledTarget(linkRoot, "org.example.plugin"); err == nil {
		target.Close()
		t.Fatal("symlinked plugins root was accepted")
	}
}

func TestOpenedRootDescriptorCannotBeRedirectedByParentSwap(t *testing.T) {
	parent := t.TempDir()
	rootPath := filepath.Join(parent, "plugins")
	if err := os.MkdirAll(filepath.Join(rootPath, "org.example.plugin"), 0o700); err != nil {
		t.Fatal(err)
	}
	rootFD, err := unix.Open(rootPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)
	originalPath := filepath.Join(parent, "original")
	if err := os.Rename(rootPath, originalPath); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(rootPath, "org.example.plugin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "org.example.plugin", "replacement-marker"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	target, err := openTargetBeneath(rootFD, "org.example.plugin")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	markerFD, err := unix.Openat(int(target.Fd()), "replacement-marker", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err == nil {
		unix.Close(markerFD)
		t.Fatal("opened-root selection was redirected to replacement path")
	}
}
