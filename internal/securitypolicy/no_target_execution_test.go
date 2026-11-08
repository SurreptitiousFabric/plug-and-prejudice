package securitypolicy

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestTargetDataPathsDoNotGainExecutionOrNetworkAPIs is a regression guard for
// the project's central non-execution and local-only invariants. It is
// intentionally narrower than a security proof: human review must still trace
// target-derived data through every new parser and API.
func TestTargetDataPathsDoNotGainExecutionOrNetworkAPIs(t *testing.T) {
	repository := repositoryRoot(t)
	for _, relative := range []string{
		"cmd/plug-prejudice",
		"internal/analyze",
		"internal/inventory",
		"internal/report",
	} {
		root := filepath.Join(repository, relative)
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			checkBoundaryAPIs(t, repository, path)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", relative, err)
		}
	}
}

func checkBoundaryAPIs(t *testing.T, repository, path string) {
	t.Helper()
	for _, violation := range boundaryViolations(path) {
		t.Errorf("target-data path %s: %s", relativePath(repository, path), violation)
	}
}

func boundaryViolations(path string) []string {
	files := token.NewFileSet()
	syntax, err := parser.ParseFile(files, path, nil, 0)
	if err != nil {
		return []string{"cannot parse source: " + err.Error()}
	}

	var violations []string
	aliases := make(map[string]string)
	for _, spec := range syntax.Imports {
		importPath, unquoteErr := strconv.Unquote(spec.Path.Value)
		if unquoteErr != nil {
			violations = append(violations, "cannot decode import: "+unquoteErr.Error())
			continue
		}
		if importPath == "os/exec" || importPath == "go/plugin" {
			violations = append(violations, fmt.Sprintf("imports execution-capable package %q", importPath))
		}
		if importPath == "net/http" && spec.Name != nil && (spec.Name.Name == "." || spec.Name.Name == "_") {
			violations = append(violations, fmt.Sprintf("imports allowlisted package %q without an auditable qualifier", importPath))
		}
		switch importPath {
		case "net", "net/rpc", "net/rpc/jsonrpc", "crypto/tls":
			violations = append(violations, fmt.Sprintf("imports network-capable package %q", importPath))
		}
		name := filepath.Base(importPath)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		aliases[name] = importPath
	}

	ast.Inspect(syntax, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		identifier, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		qualified := aliases[identifier.Name] + "." + selector.Sel.Name
		if aliases[identifier.Name] == "net/http" && selector.Sel.Name != "DetectContentType" {
			position := files.Position(selector.Pos())
			violations = append(violations, fmt.Sprintf("line %d uses non-allowlisted network API %s", position.Line, qualified))
		}
		switch qualified {
		case "os.StartProcess", "syscall.Exec", "syscall.ForkExec":
			position := files.Position(call.Pos())
			violations = append(violations, fmt.Sprintf("line %d calls execution API %s", position.Line, qualified))
		}
		return true
	})
	return violations
}

func TestBoundaryViolationsDetectAliasesAndDirectCalls(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "hostile.go")
	source := []byte("package hostile\nimport runner \"os/exec\"\nimport system \"syscall\"\nimport web \"net/http\"\nfunc run() { _, _ = runner.Command(\"target\").Output(); _ = system.Exec(\"target\", nil, nil); _, _ = web.Get(\"https://target\") }\n")
	if err := os.WriteFile(path, source, 0o600); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(boundaryViolations(path), "\n")
	for _, expected := range []string{`imports execution-capable package "os/exec"`, "calls execution API syscall.Exec", "uses non-allowlisted network API net/http.Get"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("missing %q in violations:\n%s", expected, joined)
		}
	}
}

func TestBoundaryViolationsAllowContentTypeDetection(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "mime.go")
	source := []byte("package mime\nimport web \"net/http\"\nfunc detect(data []byte) string { return web.DetectContentType(data) }\n")
	if err := os.WriteFile(path, source, 0o600); err != nil {
		t.Fatal(err)
	}
	if violations := boundaryViolations(path); len(violations) != 0 {
		t.Fatalf("content-type detection was rejected: %v", violations)
	}
}

func TestBoundaryViolationsRejectDotImportedHTTP(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "hidden.go")
	source := []byte("package hidden\nimport . \"net/http\"\nvar _ = Get\n")
	if err := os.WriteFile(path, source, 0o600); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(boundaryViolations(path), "\n")
	if !strings.Contains(joined, "without an auditable qualifier") {
		t.Fatalf("dot import was not rejected: %s", joined)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate security-policy test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
}

func relativePath(repository, path string) string {
	relative, err := filepath.Rel(repository, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(relative)
}
