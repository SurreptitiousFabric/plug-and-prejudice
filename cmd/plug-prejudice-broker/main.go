package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/boundedjson"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/buildinfo"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/omarchyaudit"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/policy"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/resource"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/safetext"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/sandbox"
	"golang.org/x/sys/unix"
)

var pluginIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

const (
	scannerPath              = "/usr/bin/plug-prejudice"
	maxInstalledPlugins      = 1024
	maxPluginRootEntries     = maxInstalledPlugins * 4
	pluginReadBatchEntries   = 128
	maxBrokerDiagnosticBytes = 4 << 10
)

type pluginList struct {
	SchemaVersion   string   `json:"schemaVersion"`
	ProtocolVersion string   `json:"protocolVersion"`
	ReviewerVersion string   `json:"reviewerVersion"`
	Plugins         []string `json:"plugins"`
}

type buildIdentity struct {
	ProtocolVersion string `json:"protocolVersion"`
	ReviewerVersion string `json:"reviewerVersion"`
}

func main() {
	os.Exit(run())
}

func run() int {
	flags := flag.NewFlagSet("plug-prejudice-broker", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	pluginID := flags.String("plugin", "", "installed Omarchy plugin ID")
	list := flags.Bool("list", false, "list installed Omarchy plugin IDs without reading plugin content")
	showVersion := flags.Bool("version", false, "print machine-readable broker protocol and build version")
	pluginsRoot := flags.String("plugins-root", defaultPluginsRoot(), "trusted installed-plugin directory")
	resourceScope := flags.String("resource-scope", "", "internal verified systemd scope")
	omarchyAuditPath := flags.String("omarchy-audit", "", "optional local Omarchy plugin-audit JSON file")
	omarchyAuditFormat := flags.String("omarchy-audit-format", "", "required pinned format identifier for --omarchy-audit")
	if err := flags.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, "usage: plug-prejudice-broker (--list | --plugin ID)")
			return 0
		}
		writeBrokerDiagnostic("parse arguments", err)
		return 2
	}
	selectedModes := 0
	if *list {
		selectedModes++
	}
	if *pluginID != "" {
		selectedModes++
	}
	if *showVersion {
		selectedModes++
	}
	if flags.NArg() != 0 || selectedModes != 1 || (*pluginID != "" && !validPluginID(*pluginID)) || ((*list || *showVersion) && (*resourceScope != "" || *omarchyAuditPath != "" || *omarchyAuditFormat != "")) || ((*omarchyAuditPath == "") != (*omarchyAuditFormat == "")) {
		fmt.Fprintln(os.Stderr, "usage: plug-prejudice-broker (--list | --plugin ID)")
		return 2
	}
	if *omarchyAuditPath != "" {
		if *omarchyAuditFormat != omarchyaudit.FormatPR8439Revision732b104 {
			fmt.Fprintln(os.Stderr, "unsupported Omarchy audit format")
			return 2
		}
		absolute, err := filepath.Abs(*omarchyAuditPath)
		if err != nil {
			writeBrokerDiagnostic("resolve Omarchy audit path", err)
			return 2
		}
		*omarchyAuditPath = absolute
	}
	if *showVersion {
		if err := json.NewEncoder(os.Stdout).Encode(buildIdentity{ProtocolVersion: buildinfo.ProtocolVersion, ReviewerVersion: buildinfo.Version}); err != nil {
			writeBrokerDiagnostic("write version", err)
			return 1
		}
		return 0
	}
	if *list {
		plugins, err := installedPluginIDs(*pluginsRoot)
		if err != nil {
			writeBrokerDiagnostic("list plugins", err)
			return 1
		}
		if err := json.NewEncoder(os.Stdout).Encode(pluginList{SchemaVersion: "1.0.0", ProtocolVersion: buildinfo.ProtocolVersion, ReviewerVersion: buildinfo.Version, Plugins: plugins}); err != nil {
			writeBrokerDiagnostic("write plugin list", err)
			return 1
		}
		return 0
	}
	manager, err := resource.DefaultManager()
	if err != nil {
		writeBrokerDiagnostic("initialize resource scope", err)
		return 1
	}
	if *resourceScope == "" {
		unit, err := resource.NewUnitName()
		if err != nil {
			writeBrokerDiagnostic("create resource scope identity", err)
			return 1
		}
		executable := fmt.Sprintf("/proc/%d/exe", os.Getpid())
		arguments := []string{
			"--plugin", *pluginID,
			"--plugins-root", *pluginsRoot,
			"--resource-scope", unit,
		}
		if *omarchyAuditPath != "" {
			arguments = append(arguments, "--omarchy-audit", *omarchyAuditPath, "--omarchy-audit-format", *omarchyAuditFormat)
		}
		if err := manager.Run(context.Background(), unit, executable, arguments); err != nil {
			var exited *exec.ExitError
			if errors.As(err, &exited) {
				return exited.ExitCode()
			}
			writeBrokerDiagnostic("enter resource scope", err)
			return 1
		}
		return 0
	}
	if err := manager.Verify(*resourceScope); err != nil {
		writeBrokerDiagnostic("verify resource scope", err)
		return 1
	}
	if err := manager.VerifyRuntime(context.Background(), *resourceScope); err != nil {
		writeBrokerDiagnostic("verify resource scope lifetime", err)
		return 1
	}
	if err := resource.ApplyProcessLimits(); err != nil {
		writeBrokerDiagnostic("apply process limits", err)
		return 1
	}
	target, err := openInstalledTarget(*pluginsRoot, *pluginID)
	if err != nil {
		writeBrokerDiagnostic("resolve plugin", err)
		return 1
	}
	defer target.Close()
	runner, err := sandbox.DefaultRunner()
	if err != nil {
		writeBrokerDiagnostic("initialize sandbox", err)
		return 1
	}
	output, err := runner.RunWithAudit(context.Background(), scannerPath, target, *pluginID, *omarchyAuditPath, *omarchyAuditFormat)
	if err != nil {
		writeBrokerDiagnostic("review plugin", err)
		return 1
	}
	decoded, err := report.Decode(output)
	if err != nil {
		writeBrokerDiagnostic("validate scanner report", err)
		return 1
	}
	if err := validateBrokerReport(decoded, *pluginID); err != nil {
		writeBrokerDiagnostic("validate scanner report", err)
		return 1
	}
	canonical, err := encodeBrokerReport(decoded)
	if err != nil {
		writeBrokerDiagnostic("encode validated report", err)
		return 1
	}
	if _, err := os.Stdout.Write(canonical); err != nil {
		writeBrokerDiagnostic("write report", err)
		return 1
	}
	return 0
}

func encodeBrokerReport(value report.Report) ([]byte, error) {
	encoded, err := boundedjson.Encode(value, policy.MaxReportBytes, "")
	if err != nil {
		return nil, fmt.Errorf("canonical report: %w", err)
	}
	return encoded, nil
}

func writeBrokerDiagnostic(context string, err error) {
	_, _ = fmt.Fprintln(os.Stderr, brokerDiagnostic(context, err))
}

func brokerDiagnostic(context string, err error) string {
	message := context
	if err != nil {
		message += ": " + err.Error()
	}
	return safetext.Diagnostic([]byte(message), maxBrokerDiagnosticBytes)
}

func validateBrokerReport(value report.Report, selectedPluginID string) error {
	if value.Scan.ScannerVersion != buildinfo.Version {
		return fmt.Errorf("scanner version %q does not match broker version %q", value.Scan.ScannerVersion, buildinfo.Version)
	}
	if value.Target.DisplayName != selectedPluginID {
		return fmt.Errorf("target identity %q does not match selected plugin %q", value.Target.DisplayName, selectedPluginID)
	}
	if value.Target.RootDigest == "" {
		return errors.New("target root digest is missing")
	}
	if !expectedResourceLimits(value.Scan.ResourceLimits) {
		return errors.New("resource policy metadata does not match broker policy")
	}
	return nil
}

func expectedResourceLimits(limits *report.ResourceLimits) bool {
	return limits != nil && limits.MemoryMaxBytes == policy.MemoryMaxBytes && limits.MemorySwapBytes == policy.MemorySwapBytes &&
		limits.TasksMax == policy.TasksMax && limits.CPUQuotaPercent == policy.CPUQuotaPercent &&
		limits.WallTimeSeconds == int(policy.WallTime.Seconds())
}

func installedPluginIDs(root string) ([]string, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("inspect plugins root: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("plugins root must be a real directory")
	}
	directory, err := os.Open(root)
	if err != nil {
		return nil, fmt.Errorf("open plugins root: %w", err)
	}
	defer directory.Close()
	openedInfo, err := directory.Stat()
	if err != nil || !os.SameFile(rootInfo, openedInfo) {
		return nil, errors.New("plugins root identity changed while being opened")
	}

	plugins := make([]string, 0, maxInstalledPlugins)
	totalEntries := 0
	for {
		entries, readErr := directory.ReadDir(pluginReadBatchEntries)
		for _, entry := range entries {
			totalEntries++
			if totalEntries > maxPluginRootEntries {
				return nil, fmt.Errorf("plugins root entry count exceeds %d", maxPluginRootEntries)
			}
			if !validPluginID(entry.Name()) || entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
				continue
			}
			plugins = append(plugins, entry.Name())
			if len(plugins) > maxInstalledPlugins {
				return nil, fmt.Errorf("installed plugin count exceeds %d", maxInstalledPlugins)
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("read plugins root: %w", readErr)
		}
	}
	sort.Strings(plugins)
	return plugins, nil
}

func validPluginID(id string) bool {
	return pluginIDPattern.MatchString(id) && !strings.Contains(id, "..")
}

func openInstalledTarget(root, id string) (*os.File, error) {
	if !validPluginID(id) {
		return nil, errors.New("invalid plugin ID")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("inspect plugins root: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("plugins root must be a real directory")
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open plugins root: %w", err)
	}
	rootFile := os.NewFile(uintptr(rootFD), "plugins-root")
	defer rootFile.Close()
	openedRoot, err := rootFile.Stat()
	if err != nil || !os.SameFile(rootInfo, openedRoot) {
		return nil, errors.New("plugins root identity changed while being opened")
	}
	target, err := openTargetBeneath(rootFD, id)
	if err != nil {
		return nil, fmt.Errorf("open selected plugin beneath root: %w", err)
	}
	info, err := target.Stat()
	if err != nil || !info.IsDir() {
		target.Close()
		return nil, errors.New("selected plugin must be a real directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink == 0 {
		target.Close()
		return nil, errors.New("selected plugin descriptor metadata is unavailable")
	}
	return target, nil
}

func openTargetBeneath(rootFD int, id string) (*os.File, error) {
	if !validPluginID(id) {
		return nil, errors.New("invalid plugin ID")
	}
	how := &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV}
	targetFD, err := unix.Openat2(rootFD, id, how)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(targetFD), id), nil
}

func defaultPluginsRoot() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "omarchy", "plugins")
}
