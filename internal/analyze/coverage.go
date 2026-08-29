package analyze

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

// AssignCoverageDispositions uses one conservative file unit for each retained artifact
// that the deterministic analyzer recognizes as executable code,
// configuration, archive, native binary, or an explicitly unsupported source
// language. It attaches the authoritative disposition to each inventory unit;
// partial units receive no fractional credit.
func AssignCoverageDispositions(files []report.File, contents map[string][]byte, limitations []report.Limitation, scanErrors []report.ScanError) ([]report.File, report.CoverageSummary) {
	result := append([]report.File(nil), files...)
	limited, failed := map[string]bool{}, map[string]bool{}
	for _, limitation := range limitations {
		if limitation.Path != "" {
			limited[limitation.Path] = true
		}
	}
	for _, scanError := range scanErrors {
		if scanError.Path != "" {
			failed[scanError.Path] = true
		}
	}
	for index := range result {
		file := &result[index]
		file.Analysis, file.AnalysisReason = report.AnalysisNotApplicable, "not a retained artifact class with semantic behavior analysis"
		if file.Kind != "regular" {
			continue
		}
		data, retained := contents[file.Path]
		supported, unsupported := coverageArtifactClass(*file, data, retained)
		if !supported && !unsupported {
			continue
		}
		if failed[file.Path] || !file.Inspected {
			file.Analysis, file.AnalysisReason = report.AnalysisUnanalyzed, "content was not retained for analysis"
		} else if unsupported {
			file.Analysis, file.AnalysisReason = report.AnalysisUnanalyzed, "the retained source language has no semantic analyzer in this stack"
		} else if file.Binary != nil || file.Archive != nil || limited[file.Path] {
			file.Analysis, file.AnalysisReason = report.AnalysisPartial, "retained metadata or an explicit limitation leaves behavior unresolved"
		} else {
			file.Analysis, file.AnalysisReason = report.AnalysisAnalyzed, ""
		}
	}
	return result, coverageFromFiles(result)
}

// SummarizeCoverage is retained for analyzer-level callers that need only the
// derived value. Report producers must use AssignCoverageDispositions so the
// authoritative per-file units are serialized too.
func SummarizeCoverage(files []report.File, contents map[string][]byte, limitations []report.Limitation, scanErrors []report.ScanError) report.CoverageSummary {
	_, coverage := AssignCoverageDispositions(files, contents, limitations, scanErrors)
	return coverage
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
		if isShell(name, data) || strings.EqualFold(filepath.Ext(name), ".qml") || treeSitterLanguage(name, data) != "" {
			return true, false
		}
		if unsupportedLanguage(name, data) != "" {
			return false, true
		}
		return false, false
	}
	extension := strings.ToLower(filepath.Ext(name))
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
		result.Limitations = append(result.Limitations, report.Limitation{Code: language + "-semantic-analysis-unavailable", Description: coverageDescription(language), Path: name, Scope: scopeForPath(name, references)})
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

func coverageRelevant(file report.File, data []byte) bool {
	if file.Path == "manifest.json" || file.Binary != nil || file.ContentType == "application/x-elf" || strings.EqualFold(filepath.Ext(file.Path), ".qml") {
		return true
	}
	return isShell(file.Path, data) || unsupportedLanguage(file.Path, data) != ""
}

func coverageFromFiles(files []report.File) report.CoverageSummary {
	var analyzed, partial, unanalyzed, excluded int
	for _, file := range files {
		switch file.Analysis {
		case report.AnalysisAnalyzed:
			analyzed++
		case report.AnalysisPartial:
			partial++
		case report.AnalysisUnanalyzed:
			unanalyzed++
		case report.AnalysisNotApplicable:
			excluded++
		}
	}
	return report.NewCoverageSummary(analyzed, partial, unanalyzed, excluded)
}
