package analyze

import (
	"bytes"
	"path/filepath"
	"sort"
	"strings"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func annotateScopes(contents map[string][]byte, files []report.File, result *Result) {
	runtimeReferences := runtimeReferencedPaths(contents, files, result.Manifest, result)
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

func runtimeReferencedPaths(contents map[string][]byte, files []report.File, manifest *report.Manifest, results ...*Result) map[string]bool {
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
		entryKey := map[string]string{"bar": "bar", "bar-widget": "barWidget", "menu": "menu", "overlay": "overlay", "panel": "panel", "service": "service"}
		for _, kind := range manifest.Kinds {
			if key, known := entryKey[kind]; known {
				if entry, exists := manifest.EntryPoints[key]; exists {
					references[filepath.ToSlash(filepath.Clean(entry))] = true
				}
			}
		}
	}
	for name, data := range contents {
		if strings.EqualFold(filepath.Ext(name), ".qml") && !toolingPath(name) {
			references[filepath.ToSlash(filepath.Clean(name))] = true
			markQMLLiteralReferences(data, name, candidates, references)
		}
	}
	var invocationGraph map[string][]string
	if len(results) > 0 && results[0] != nil {
		edges, _ := literalInvocationEdges(results[0].Operations, candidates)
		invocationGraph = make(map[string][]string)
		for _, edge := range edges {
			caller := filepath.ToSlash(filepath.Clean(edge.caller.Evidence.Path))
			invocationGraph[caller] = append(invocationGraph[caller], edge.target)
		}
	}
	queue := make([]string, 0, len(references))
	for referenced := range references {
		queue = append(queue, referenced)
	}
	sort.Strings(queue)
	for index := 0; index < len(queue); index++ {
		referenced := queue[index]
		if data, inspectable := contents[referenced]; inspectable {
			queue = append(queue, markQMLLiteralReferences(data, referenced, candidates, references)...)
		}
		for _, target := range invocationGraph[referenced] {
			if !references[target] {
				references[target] = true
				queue = append(queue, target)
			}
		}
	}
	return references
}

func isGitMetadataPath(name string) bool {
	clean := filepath.ToSlash(filepath.Clean(name))
	return clean == ".git" || strings.HasPrefix(clean, ".git/")
}

func markQMLLiteralReferences(data []byte, source string, candidates, references map[string]bool) []string {
	if !strings.EqualFold(filepath.Ext(source), ".qml") {
		return nil
	}
	added := make([]string, 0)
	for index := 0; index < len(data); {
		if index+1 < len(data) && data[index] == '/' && data[index+1] == '/' {
			for index < len(data) && data[index] != '\n' {
				index++
			}
			continue
		}
		if index+1 < len(data) && data[index] == '/' && data[index+1] == '*' {
			index += 2
			for index+1 < len(data) && !(data[index] == '*' && data[index+1] == '/') {
				index++
			}
			if index+1 < len(data) {
				index += 2
			}
			continue
		}
		if data[index] != '"' && data[index] != '\'' && data[index] != '`' {
			index++
			continue
		}
		start := index
		end := skipQMLString(data, start)
		if data[start] != '`' && end <= len(data) && end > start+1 && data[end-1] == data[start] {
			raw := data[start+1 : end-1]
			if !bytes.ContainsRune(raw, '\\') {
				matches := resolveLiteralTarget(source, string(raw), candidates)
				if len(matches) == 1 && !references[matches[0]] {
					references[matches[0]] = true
					added = append(added, matches[0])
				}
			}
		}
		index = max(end, start+1)
	}
	sort.Strings(added)
	return added
}

func scopeForPath(name string, runtimeReferences map[string]bool) report.Scope {
	clean := filepath.ToSlash(filepath.Clean(name))
	if runtimeReferences[clean] {
		return report.ScopeRuntime
	}
	if toolingPath(clean) {
		return report.ScopeTooling
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
	base := strings.TrimSuffix(strings.ToLower(filepath.Base(name)), strings.ToLower(filepath.Ext(name)))
	tokens := strings.FieldsFunc(base, func(value rune) bool { return value == '.' || value == '_' || value == '-' })
	for _, marker := range []string{"build", "release", "package", "validate", "lint", "test", "check"} {
		for _, token := range tokens {
			if token == marker {
				return true
			}
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
