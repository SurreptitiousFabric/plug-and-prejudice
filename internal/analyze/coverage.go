package analyze

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

// AssignCoverageDispositions attaches the schema-2 authoritative coverage unit
// to each retained inventory record. It does not change detection results.
// Later language/artifact stacks extend the recognized classes, while this
// adapter conservatively describes the analyzers present in stack 2.
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
		file.Analysis, file.AnalysisReason = report.AnalysisNotApplicable, ""
		if file.Kind != "regular" || !coverageRelevant(*file, contents[file.Path]) {
			continue
		}
		if failed[file.Path] || !file.Inspected {
			file.Analysis, file.AnalysisReason = report.AnalysisUnanalyzed, "content was not retained for analysis"
		} else if unsupportedLanguage(file.Path, contents[file.Path]) != "" {
			file.Analysis, file.AnalysisReason = report.AnalysisUnanalyzed, "the retained source language has no semantic analyzer in this stack"
		} else if file.Binary != nil || limited[file.Path] {
			file.Analysis, file.AnalysisReason = report.AnalysisPartial, "retained metadata or an explicit limitation leaves behavior unresolved"
		} else {
			file.Analysis = report.AnalysisAnalyzed
		}
	}
	return result, coverageFromFiles(result)
}

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
		result.Limitations = append(result.Limitations, report.Limitation{Code: language + "-semantic-analysis-unavailable", Description: coverageDescription(language), Path: name, Scope: scopeForPath(name, references)})
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

func coverageRelevant(file report.File, data []byte) bool {
	if file.Path == "manifest.json" || file.Binary != nil || file.ContentType == "application/x-elf" || strings.EqualFold(filepath.Ext(file.Path), ".qml") {
		return true
	}
	return isShell(file.Path, data) || unsupportedLanguage(file.Path, data) != ""
}

func coverageFromFiles(files []report.File) report.CoverageSummary {
	var analyzed, partial, unanalyzed int
	for _, file := range files {
		switch file.Analysis {
		case report.AnalysisAnalyzed:
			analyzed++
		case report.AnalysisPartial:
			partial++
		case report.AnalysisUnanalyzed:
			unanalyzed++
		}
	}
	return report.NewCoverageSummary(analyzed, partial, unanalyzed)
}
