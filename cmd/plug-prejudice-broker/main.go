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

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/policy"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/resource"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/sandbox"
	"golang.org/x/sys/unix"
)

var pluginIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

const maxInstalledPlugins = 1024
const pluginReadBatchEntries = 128

type pluginList struct {
	SchemaVersion string   `json:"schemaVersion"`
	Plugins       []string `json:"plugins"`
}

type containmentChecks struct {
	verify        func(string) error
	verifyRuntime func(context.Context, string) error
	applyLimits   func() error
}

func main() {
	os.Exit(run())
}

func run() int {
	flags := flag.NewFlagSet("plug-prejudice-broker", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	pluginID := flags.String("plugin", "", "installed Omarchy plugin ID")
	list := flags.Bool("list", false, "list installed Omarchy plugin IDs without reading plugin content")
	pluginsRoot := flags.String("plugins-root", defaultPluginsRoot(), "trusted installed-plugin directory")
	scanner := flags.String("scanner", siblingScanner(), "trusted scanner executable")
	resourceScope := flags.String("resource-scope", "", "internal verified systemd scope")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if flags.NArg() != 0 || (*list == (*pluginID != "")) || (!*list && !validPluginID(*pluginID)) {
		fmt.Fprintln(os.Stderr, "usage: plug-prejudice-broker (--list | --plugin ID)")
		return 2
	}
	manager, err := resource.DefaultManager()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if *resourceScope == "" {
		unit, err := resource.NewUnitName()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		executable := fmt.Sprintf("/proc/%d/exe", os.Getpid())
		arguments := []string{"--plugins-root", *pluginsRoot, "--scanner", *scanner, "--resource-scope", unit}
		if *list {
			arguments = append([]string{"--list"}, arguments...)
		} else {
			arguments = append([]string{"--plugin", *pluginID}, arguments...)
		}
		if err := manager.Run(context.Background(), unit, executable, arguments); err != nil {
			var exited *exec.ExitError
			if errors.As(err, &exited) {
				return exited.ExitCode()
			}
			fmt.Fprintf(os.Stderr, "enter resource scope: %v\n", err)
			return 1
		}
		return 0
	}
	checks := containmentChecks{verify: manager.Verify, verifyRuntime: manager.VerifyRuntime, applyLimits: resource.ApplyProcessLimits}
	return afterVerifiedContainment(*resourceScope, checks, func() int {
		if *list {
			plugins, err := installedPluginIDs(*pluginsRoot)
			if err != nil {
				fmt.Fprintf(os.Stderr, "list plugins: %v\n", err)
				return 1
			}
			if err := json.NewEncoder(os.Stdout).Encode(pluginList{SchemaVersion: "1.0.0", Plugins: plugins}); err != nil {
				fmt.Fprintf(os.Stderr, "write plugin list: %v\n", err)
				return 1
			}
			return 0
		}
		target, err := openInstalledTarget(*pluginsRoot, *pluginID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "resolve plugin: %v\n", err)
			return 1
		}
		defer target.Close()
		runner, err := sandbox.DefaultRunner()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		output, err := runner.Run(context.Background(), *scanner, target, *pluginID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "review plugin: %v\n", err)
			return 1
		}
		decoded, err := report.Decode(output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "validate scanner report: %v\n", err)
			return 1
		}
		if !expectedResourceLimits(decoded.Scan.ResourceLimits) {
			fmt.Fprintln(os.Stderr, "validate scanner report: resource policy metadata does not match broker policy")
			return 1
		}
		if _, err := os.Stdout.Write(output); err != nil {
			fmt.Fprintf(os.Stderr, "write report: %v\n", err)
			return 1
		}
		return 0
	})
}

func afterVerifiedContainment(scope string, checks containmentChecks, action func() int) int {
	if err := checks.verify(scope); err != nil {
		fmt.Fprintf(os.Stderr, "verify resource scope: %v\n", err)
		return 1
	}
	if err := checks.verifyRuntime(context.Background(), scope); err != nil {
		fmt.Fprintf(os.Stderr, "verify resource scope lifetime: %v\n", err)
		return 1
	}
	if err := checks.applyLimits(); err != nil {
		fmt.Fprintf(os.Stderr, "apply process limits: %v\n", err)
		return 1
	}
	return action()
}

func expectedResourceLimits(limits *report.ResourceLimits) bool {
	return limits != nil && limits.MemoryMaxBytes == policy.MemoryMaxBytes && limits.MemorySwapBytes == policy.MemorySwapBytes &&
		limits.TasksMax == policy.TasksMax && limits.CPUQuotaPercent == policy.CPUQuotaPercent &&
		limits.WallTimeSeconds == int(policy.WallTime.Seconds())
}

func installedPluginIDs(root string) ([]string, error) {
	directory, err := openDirectoryPath(root)
	if err != nil {
		return nil, fmt.Errorf("open plugins root: %w", err)
	}
	defer directory.Close()
	plugins := make([]string, 0, maxInstalledPlugins)
	for {
		entries, readErr := directory.ReadDir(pluginReadBatchEntries)
		for _, entry := range entries {
			if len(plugins) >= maxInstalledPlugins {
				return nil, fmt.Errorf("plugins root entry count exceeds %d", maxInstalledPlugins)
			}
			if !validPluginID(entry.Name()) || entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
				return nil, errors.New("plugins root contains an unacceptable entry")
			}
			plugins = append(plugins, entry.Name())
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
	rootFile, err := openDirectoryPath(root)
	if err != nil {
		return nil, fmt.Errorf("open plugins root: %w", err)
	}
	defer rootFile.Close()
	fd, err := unix.Openat2(int(rootFile.Fd()), id, &unix.OpenHow{
		Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS |
			unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return nil, fmt.Errorf("open selected plugin beneath root: %w", err)
	}
	target := os.NewFile(uintptr(fd), id)
	info, err := target.Stat()
	if err != nil {
		_ = target.Close()
		return nil, errors.New("selected plugin descriptor metadata is unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Nlink == 0 {
		_ = target.Close()
		return nil, errors.New("selected plugin descriptor is not a live directory")
	}
	return target, nil
}

func openDirectoryPath(name string) (*os.File, error) {
	absolute, err := filepath.Abs(name)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, absolute, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), absolute)
	info, err := file.Stat()
	if err != nil || !info.IsDir() {
		_ = file.Close()
		return nil, errors.New("opened path is not a directory")
	}
	return file, nil
}

func defaultPluginsRoot() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "omarchy", "plugins")
}

func siblingScanner() string {
	executable, err := os.Executable()
	if err != nil {
		return "plug-prejudice"
	}
	return filepath.Join(filepath.Dir(executable), "plug-prejudice")
}
