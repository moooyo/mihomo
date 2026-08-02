package dns

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The query hot path must not log per-query client data.
//
// This was a shell grep in the installer repository, gating a package that no
// longer exists there. It belongs beside the code it constrains, and as an AST
// walk it closes the hole the grep documented in its own header: a log call
// with its argument on the next line slipped past a line-oriented match. Here
// the argument is an expression regardless of how it is formatted.
//
// The invariant is a privacy one, not a style one. A resolver sees every name
// every client on the gateway asks for; journald keeps that indefinitely and
// ships it wherever the operator forwards logs. An aggregate count is fine, a
// name or a client address is not. The query log is the deliberate exception --
// it is bounded, in-memory, and the operator opts into reading it -- which is
// why this checks logging calls specifically rather than all uses.
var piiExpressions = []*regexp.Regexp{
	regexp.MustCompile(`\bq\.Name\b`),
	regexp.MustCompile(`\.Question\b`),
	regexp.MustCompile(`\bRemoteAddr\b`),
	regexp.MustCompile(`\bq[Nn]ame\b`),
}

func TestQueryPathLogsNoPerQueryPII(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}

	fset := token.NewFileSet()
	scanned := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		scanned++

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isLogCall(call.Fun) {
				return true
			}
			for _, arg := range call.Args {
				rendered := render(fset, arg)
				for _, pattern := range piiExpressions {
					if pattern.MatchString(rendered) {
						t.Errorf(
							"%s: logging call passes per-query client data (%s)\n"+
								"\ta resolver log line naming a query or a client is a privacy regression;\n"+
								"\tlog an aggregate, or record it in the bounded query log instead",
							fset.Position(arg.Pos()), rendered,
						)
					}
				}
			}
			return true
		})
	}

	// A refactor that renames or moves these files must not turn this test into
	// a silent pass over nothing.
	if scanned == 0 {
		t.Fatal("no package sources were scanned")
	}
	for _, required := range []string{"resolver.go", "arbitrate.go", "upstream.go", "cache.go"} {
		if _, err := os.Stat(filepath.Clean(required)); err != nil {
			t.Errorf("expected query-path file %s is absent; retarget this test", required)
		}
	}
}

// isLogCall reports whether the callee is a selector on the log package.
//
// Matching the receiver name rather than resolving the import means a local
// variable called log would be checked too. That is the safe direction: the
// cost is a false positive on a badly named variable, and the alternative
// misses a genuine log call reached through an alias.
func isLogCall(fun ast.Expr) bool {
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	return ok && ident.Name == "log"
}

func render(fset *token.FileSet, node ast.Node) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, node); err != nil {
		return ""
	}
	return buf.String()
}
