package engine

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

func TestManifestImportsCamelCaseBodyReplaceValueMap(t *testing.T) {
	body := strings.Replace(validManifest,
		`      inline: "function transform(context) { return {}; }"`,
		`      replaceBody:
        pattern: old
        to: "{{settings.region}}"
        valueMap:
          region:
            cn: replacement`, 1)
	module := parseFixture(t, body)

	replace := module.Scripts[0].ReplaceBody
	if replace == nil || replace.ValueMap["region"]["cn"] != "replacement" {
		t.Fatalf("valueMap was not imported: %+v", replace)
	}
}

func TestExecuteBodyReplaceRejectsExpansionAtActionLimit(t *testing.T) {
	rule := ScriptRule{
		Phase:        "request",
		BodyMode:     "text",
		MaxBodyBytes: 1024,
		ReplaceBody: &BodyReplace{
			Pattern: ".",
			To:      strings.Repeat("x", maxRewriteURLBytes),
		},
	}
	if _, err := executeBodyReplace(rule, Module{}, scriptMessage{Body: []byte("aa")}, nil); err == nil ||
		!strings.Contains(err.Error(), "1024") {
		t.Fatalf("executeBodyReplace error = %v, want action-limit rejection", err)
	}
}

func TestReplaceBodyBoundedPreservesRegexpExpansion(t *testing.T) {
	compiled := regexp.MustCompile(`(?P<word>[a-z]+)-([0-9]+)(?:/(missing))?`)
	body := []byte("abc-12 xyz-34/missing")
	template := `${word}:$2:$1:$$:$9:${unknown}:$3`
	want := compiled.ReplaceAll(body, []byte(template))
	got, err := replaceBodyBounded(compiled, body, template, 1<<20)
	if err != nil {
		t.Fatalf("replaceBodyBounded: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("replaceBodyBounded = %q, want %q", got, want)
	}
}

func TestReplaceBodyBoundedAcceptsLimitAndRejectsNextByte(t *testing.T) {
	compiled := regexp.MustCompile("a")
	within := bytes.Repeat([]byte("a"), 512)
	got, err := replaceBodyBounded(compiled, within, "bb", 1024)
	if err != nil {
		t.Fatalf("replacement at limit: %v", err)
	}
	if len(got) != 1024 {
		t.Fatalf("replacement length = %d, want 1024", len(got))
	}
	if _, err := replaceBodyBounded(compiled, append(within, 'a'), "bb", 1024); err == nil {
		t.Fatal("replacement beyond limit succeeded")
	}
}
