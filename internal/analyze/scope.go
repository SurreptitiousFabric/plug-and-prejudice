package analyze

import (
	"path/filepath"
	"strings"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func annotateScopes(contents map[string][]byte, files []report.File, result *Result) {
	runtimeReferences := runtimeReferencedPaths(contents, files, result.Manifest)
	operationScopes := make(map[string]report.Scope, len(result.Operations))
	for index := range result.Operations {
		scope := scopeForPath(result.Operations[index].Evidence.Path, runtimeReferences)
		result.Operations[index].Scope = scope
		operationScopes[result.Operations[index].ID] = scope
	}
	for index := range result.Resources {
		resource := &result.Resources[index]
		if scope, exists := operationScopes[resource.RelatedOperationID]; exists {
			resource.Scope = scope
		} else {
			resource.Scope = report.ScopeUnknown
		}
	}
	for index := range result.Findings {
		finding := &result.Findings[index]
		if len(finding.Related) > 0 {
			finding.Scope = relatedScope(finding.Related, operationScopes)
		} else if len(finding.Evidence) > 0 {
			finding.Scope = scopeForPath(finding.Evidence[0].Path, runtimeReferences)
		} else {
			finding.Scope = report.ScopeUnknown
		}
	}
	for index := range result.Unknowns {
		unknown := &result.Unknowns[index]
		if len(unknown.AffectedOperations) > 0 {
			unknown.Scope = relatedScope(unknown.AffectedOperations, operationScopes)
		} else if len(unknown.Evidence) > 0 {
			unknown.Scope = scopeForPath(unknown.Evidence[0].Path, runtimeReferences)
		} else {
			unknown.Scope = report.ScopeUnknown
		}
	}
	for index := range result.Limitations {
		limitation := &result.Limitations[index]
		if limitation.Scope == "" && limitation.Path != "" {
			limitation.Scope = scopeForPath(limitation.Path, runtimeReferences)
		}
	}
}

func runtimeReferencedPaths(contents map[string][]byte, files []report.File, manifest *report.Manifest) map[string]bool {
	references := make(map[string]bool)
	candidates := make(map[string]bool, len(contents)+len(files))
	for candidate := range contents {
		clean := filepath.ToSlash(filepath.Clean(candidate))
		if !isGitMetadataPath(clean) {
			candidates[clean] = true
		}
	}
	for _, file := range files {
		clean := filepath.ToSlash(filepath.Clean(file.Path))
		if file.Kind == "regular" && !isGitMetadataPath(clean) {
			candidates[clean] = true
		}
	}
	if manifest != nil {
		for _, entry := range manifest.EntryPoints {
			references[filepath.ToSlash(filepath.Clean(entry))] = true
		}
	}
	for name, data := range contents {
		if strings.EqualFold(filepath.Ext(name), ".qml") && !toolingPath(name) {
			references[filepath.ToSlash(filepath.Clean(name))] = true
			markTextReferences(string(data), name, candidates, references)
		}
	}
	changed := true
	for changed {
		changed = false
		for referenced := range references {
			data, inspectable := contents[referenced]
			if !inspectable {
				continue
			}
			before := len(references)
			markTextReferences(string(data), referenced, candidates, references)
			if len(references) != before {
				changed = true
			}
		}
	}
	return references
}

func isGitMetadataPath(name string) bool {
	clean := filepath.ToSlash(filepath.Clean(name))
	return clean == ".git" || strings.HasPrefix(clean, ".git/")
}

func markTextReferences(text, source string, candidates, references map[string]bool) {
	for clean := range candidates {
		if clean == source || toolingPath(clean) {
			continue
		}
		if strings.Contains(text, clean) || strings.Contains(text, filepath.Base(clean)) {
			references[clean] = true
		}
	}
}

func scopeForPath(name string, runtimeReferences map[string]bool) report.Scope {
	clean := filepath.ToSlash(filepath.Clean(name))
	if toolingPath(clean) {
		return report.ScopeTooling
	}
	if runtimeReferences[clean] {
		return report.ScopeRuntime
	}
	return report.ScopeUnknown
}

func toolingPath(name string) bool {
	clean := "/" + strings.ToLower(filepath.ToSlash(filepath.Clean(name))) + "/"
	for _, segment := range []string{"/.github/", "/test/", "/tests/", "/testdata/", "/docs/", "/examples/"} {
		if strings.Contains(clean, segment) {
			return true
		}
	}
	base := strings.ToLower(filepath.Base(name))
	for _, marker := range []string{"build", "release", "package", "validate", "lint", "test", "check"} {
		if strings.Contains(base, marker) {
			return true
		}
	}
	return false
}

func relatedScope(ids []string, scopes map[string]report.Scope) report.Scope {
	selected := report.Scope("")
	for _, id := range ids {
		scope, exists := scopes[id]
		if !exists {
			return report.ScopeUnknown
		}
		if selected == "" {
			selected = scope
		} else if selected != scope {
			return report.ScopeUnknown
		}
	}
	if selected == "" {
		return report.ScopeUnknown
	}
	return selected
}
