package analyze

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

// SummarizeCoverage uses one conservative file unit for each retained artifact
// that the deterministic analyzer recognizes as executable code,
// configuration, archive, native binary, or an explicitly unsupported source
// language. Partial units receive no fractional credit.
func SummarizeCoverage(files []report.File, contents map[string][]byte, limitations []report.Limitation, errors []report.ScanError) report.CoverageSummary {
	limited := make(map[string]bool)
	failed := make(map[string]bool)
	for _, limitation := range limitations {
		if limitation.Path != "" {
			limited[limitation.Path] = true
		}
	}
	for _, scanError := range errors {
		if scanError.Path != "" {
			failed[scanError.Path] = true
		}
	}
	analyzed, partial, unanalyzed := 0, 0, 0
	for _, file := range files {
		if file.Kind != "regular" {
			continue
		}
		data, retained := contents[file.Path]
		supported, unsupported := coverageArtifactClass(file, data, retained)
		if !supported && !unsupported {
			continue
		}
		if failed[file.Path] || !file.Inspected {
			unanalyzed++
			continue
		}
		if unsupported {
			unanalyzed++
			continue
		}
		if file.Binary != nil || file.Archive != nil || limited[file.Path] {
			partial++
			continue
		}
		analyzed++
	}
	return report.NewCoverageSummary(analyzed, partial, unanalyzed)
}

func coverageArtifactClass(file report.File, data []byte, retained bool) (supported, unsupported bool) {
	if file.Binary != nil || file.Archive != nil || file.ContentType == "application/x-elf" {
		return true, false
	}
	name := file.Path
	if name == "manifest.json" {
		return true, false
	}
	if retained {
		if isShell(name, data) || strings.EqualFold(filepath.Ext(name), ".qml") || strings.EqualFold(filepath.Ext(name), ".desktop") || isSystemdUnitPath(name) || isHyprlandConfigPath(name) || treeSitterLanguage(name, data) != "" {
			return true, false
		}
		if unsupportedLanguage(name, data) != "" {
			return false, true
		}
		return false, false
	}
	extension := strings.ToLower(filepath.Ext(name))
	if isSystemdUnitPath(name) || isHyprlandConfigPath(name) {
		return true, false
	}
	if oneOfCoverageExtension(extension, ".sh", ".bash", ".zsh", ".qml", ".desktop", ".py", ".pyw", ".js", ".mjs", ".cjs", ".jsx", ".zip", ".tar", ".gz", ".xz", ".zst", ".zstd", ".bz2") {
		return true, false
	}
	if oneOfCoverageExtension(extension, ".fish", ".ts", ".mts", ".cts", ".tsx", ".go", ".rb", ".pl", ".pm", ".lua", ".php") {
		return false, true
	}
	return false, false
}

func oneOfCoverageExtension(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if value == candidate {
			return true
		}
	}
	return false
}

func addLanguageCoverageLimitations(contents map[string][]byte, result *Result) {
	references := runtimeReferencedPaths(contents, nil, result.Manifest, result)
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
	case ".fish":
		return "fish"
	case ".py", ".pyw":
		return ""
	case ".js", ".mjs", ".cjs", ".jsx":
		return ""
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
	for _, candidate := range []string{"python", "node", "ruby", "perl", "lua", "php", "fish"} {
		if strings.Contains(lower, candidate) {
			if candidate == "node" {
				return ""
			}
			if candidate == "python" {
				return ""
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
