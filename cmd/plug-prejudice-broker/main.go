package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/sandbox"
)

var pluginIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

const maxInstalledPlugins = 1024

type pluginList struct {
	SchemaVersion string   `json:"schemaVersion"`
	Plugins       []string `json:"plugins"`
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
	if err := flags.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if flags.NArg() != 0 || (*list == (*pluginID != "")) || (!*list && !validPluginID(*pluginID)) {
		fmt.Fprintln(os.Stderr, "usage: plug-prejudice-broker (--list | --plugin ID)")
		return 2
	}
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
	target, err := installedTarget(*pluginsRoot, *pluginID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve plugin: %v\n", err)
		return 1
	}
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
	if _, err := report.Decode(output); err != nil {
		fmt.Fprintf(os.Stderr, "validate scanner report: %v\n", err)
		return 1
	}
	if _, err := os.Stdout.Write(output); err != nil {
		fmt.Fprintf(os.Stderr, "write report: %v\n", err)
		return 1
	}
	return 0
}

func installedPluginIDs(root string) ([]string, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("inspect plugins root: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("plugins root must be a real directory")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read plugins root: %w", err)
	}
	plugins := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !validPluginID(entry.Name()) || entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
			continue
		}
		plugins = append(plugins, entry.Name())
		if len(plugins) > maxInstalledPlugins {
			return nil, fmt.Errorf("installed plugin count exceeds %d", maxInstalledPlugins)
		}
	}
	return plugins, nil
}

func validPluginID(id string) bool {
	return pluginIDPattern.MatchString(id) && !strings.Contains(id, "..")
}

func installedTarget(root, id string) (string, error) {
	if !validPluginID(id) {
		return "", errors.New("invalid plugin ID")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return "", fmt.Errorf("inspect plugins root: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("plugins root must be a real directory")
	}
	target := filepath.Join(root, id)
	info, err := os.Lstat(target)
	if err != nil {
		return "", fmt.Errorf("inspect selected plugin: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("selected plugin must be a real directory")
	}
	return target, nil
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
