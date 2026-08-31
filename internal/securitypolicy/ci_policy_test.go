package securitypolicy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryWorkflowsSatisfyPolicy(t *testing.T) {
	repository := repositoryRoot(t)
	command := exec.Command(filepath.Join(repository, "scripts", "verify-ci-policy.sh"), filepath.Join(repository, ".github", "workflows"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("workflow policy failed: %v\n%s", err, output)
	}
}

func TestCIPolicyRejectsUnsafeWorkflowChanges(t *testing.T) {
	repository := repositoryRoot(t)
	verifier := filepath.Join(repository, "scripts", "verify-ci-policy.sh")
	base := "name: test\non:\n  pull_request:\npermissions:\n  contents: read\njobs:\n  test:\n    timeout-minutes: 5\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n        with:\n          persist-credentials: false\n"
	for _, test := range []struct {
		name  string
		alter func(string) string
		want  string
	}{
		{name: "floating action", alter: func(value string) string {
			return strings.Replace(value, "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd", "actions/checkout@main", 1)
		}, want: "not pinned"},
		{name: "secret", alter: func(value string) string { return value + "      - run: echo ${{ secrets.TOKEN }}\n" }, want: "references secrets"},
		{name: "write permission", alter: func(value string) string { return strings.Replace(value, "contents: read", "contents: write", 1) }, want: "exactly contents: read"},
		{name: "additional read permission", alter: func(value string) string {
			return strings.Replace(value, "  contents: read\n", "  contents: read\n  issues: read\n", 1)
		}, want: "exactly contents: read"},
		{name: "privileged trigger", alter: func(value string) string { return strings.Replace(value, "pull_request:", "pull_request_target:", 1) }, want: "privileged"},
		{name: "missing timeout", alter: func(value string) string { return strings.Replace(value, "    timeout-minutes: 5\n", "", 1) }, want: "no timeout"},
		{name: "persisted credentials", alter: func(value string) string {
			return strings.Replace(value, "persist-credentials: false", "persist-credentials: true", 1)
		}, want: "persists checkout credentials"},
		{name: "hidden failure", alter: func(value string) string { return value + "    continue-on-error: true\n" }, want: "hides a failing"},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.WriteFile(filepath.Join(directory, "ci.yml"), []byte(test.alter(base)), 0o600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(verifier, directory)
			output, err := command.CombinedOutput()
			if err == nil || !strings.Contains(string(output), test.want) {
				t.Fatalf("unsafe workflow result = %v, output %q; want %q", err, output, test.want)
			}
		})
	}
}
