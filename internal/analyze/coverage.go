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
		ext := strings.ToLower(filepath.Ext(name))
		var code, description string
		switch ext {
		case ".py":
			code = "python-semantic-analysis-unavailable"
			description = "Python source was inventoried but has not received syntax-tree semantic analysis. Imports, calls, and data flow may be missing."
		case ".js", ".mjs", ".cjs":
			code = "javascript-semantic-analysis-unavailable"
			description = "JavaScript source outside QML was inventoried but has not received syntax-tree semantic analysis. Calls and data flow may be missing."
		default:
			continue
		}
		scope := scopeForPath(name, references)
		result.Limitations = append(result.Limitations, report.Limitation{Code: code, Description: description, Path: name, Scope: scope})
	}
}
