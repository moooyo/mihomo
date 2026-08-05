package fivegpn_test

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// The fork's real cost is not the size of 5gpn/ -- it is how many upstream-owned
// files carry a 5gpn-shaped change, because those are the ones a rebase has to
// reconcile. Today that is tunnel/tunnel.go and nothing else.
//
// The way that number grows is one import at a time: someone needs a matcher
// from 5gpn/policy or a document from 5gpn/state, reaches for it directly from an
// upstream package, and the façade quietly stops being one. This test is the
// thing that notices.
//
// Upstream packages may import "5gpn". They may not import anything beneath it.
func TestUpstreamPackagesImportOnlyTheFacade(t *testing.T) {
	const module = "github.com/metacubex/mihomo"
	const facade = module + "/5gpn"

	cmd := exec.Command("go", "list", "-json", "./...")
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}

	type pkg struct {
		ImportPath  string
		Imports     []string
		TestImports []string
	}

	dec := json.NewDecoder(strings.NewReader(string(out)))
	var offenders []string
	for dec.More() {
		var p pkg
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("decode go list output: %v", err)
		}
		// Packages under 5gpn may import each other freely.
		if p.ImportPath == facade || strings.HasPrefix(p.ImportPath, facade+"/") {
			continue
		}
		for _, imp := range append(append([]string{}, p.Imports...), p.TestImports...) {
			if strings.HasPrefix(imp, facade+"/") {
				offenders = append(offenders, p.ImportPath+" -> "+imp)
			}
		}
	}

	if len(offenders) > 0 {
		t.Errorf("upstream packages reached past the 5gpn façade:\n  %s\n\n"+
			"Export what is needed from package fivegpn instead. Every direct import of a\n"+
			"5gpn sub-package is an upstream-owned file a future rebase has to reconcile.",
			strings.Join(offenders, "\n  "))
	}
}
