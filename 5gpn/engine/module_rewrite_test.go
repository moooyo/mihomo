package engine

import (
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
