package analyze

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func addLanguageCoverageLimitations(contents map[string][]byte, result *Result) {
	references := runtimeReferencedPaths(contents, nil, result.Manifest)
	paths := make([]string, 0, len(contents))
	for name := range contents {
		paths = append(paths, name)
	}
	sort.Strings(paths)
	for _, name := range paths {
		if toolingPath(name) || isInertGitMetadata(name) {
			continue
		}
		language := unsupportedLanguage(name, contents[name])
		if language == "" {
			continue
		}
		code := language + "-semantic-analysis-unavailable"
		description := coverageDescription(language)
		scope := scopeForPath(name, references)
		result.Limitations = append(result.Limitations, report.Limitation{Code: code, Description: description, Path: name, Scope: scope})
	}
}

func unsupportedLanguage(name string, data []byte) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".py", ".pyw":
		return "python"
	case ".js", ".mjs", ".cjs", ".jsx":
		return "javascript"
	case ".ts", ".mts", ".cts", ".tsx":
		return "typescript"
	case ".go":
		return "go"
	case ".rb":
		return "ruby"
	case ".pl", ".pm":
		return "perl"
	case ".lua":
		return "lua"
	case ".php":
		return "php"
	}
	firstLine := string(data)
	if newline := strings.IndexByte(firstLine, '\n'); newline >= 0 {
		firstLine = firstLine[:newline]
	}
	if !strings.HasPrefix(firstLine, "#!") {
		return ""
	}
	lower := strings.ToLower(firstLine)
	for _, candidate := range []string{"python", "node", "ruby", "perl", "lua", "php"} {
		if strings.Contains(lower, candidate) {
			if candidate == "node" {
				return "javascript"
			}
			return candidate
		}
	}
	return ""
}

func coverageDescription(language string) string {
	label := strings.ToUpper(language[:1]) + language[1:]
	return label + " source was inventoried but has not received syntax-tree semantic analysis. Calls, dependencies, and data flow may be missing."
}
