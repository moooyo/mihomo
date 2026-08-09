package engine

import (
	"errors"
	"strings"
	"testing"

	"github.com/dop251/goja"
	"github.com/dop251/goja/ast"
)

func TestCompileModuleScriptUsesJavaScriptLexicalRules(t *testing.T) {
	t.Parallel()

	for name, source := range map[string]string{
		"numeric trailing point": `const value = 1. / 2; function transform(context) { return {body: String(value)}; }`,
		"unicode identifier":     `const π = 3.14; function transform(context) { return {body: String(π)}; }`,
		"regexp contents":        `const pattern = /\(\[\{\/\}\]\)/; function transform(context) { return {body: String(pattern)}; }`,
	} {
		source := source
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := compileModuleScript("extension:test", source); err != nil {
				t.Fatalf("compileModuleScript() error = %v", err)
			}
		})
	}
}

func TestCompileModuleScriptPreflightRejectsDeepExpressionsAfterAmbiguousTokens(t *testing.T) {
	t.Parallel()

	chain := strings.Repeat("!", maxScriptASTDepth+1) + "true"
	for name, source := range map[string]string{
		"numeric trailing point": "const value = 1. / " + chain + ";",
		"unicode identifier":     "const π = true; const value = π / " + chain + ";",
	} {
		source := source
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := compileModuleScript("extension:test", source); err == nil || !strings.Contains(err.Error(), "nested expressions") {
				t.Fatalf("compileModuleScript() error = %v, want parser nesting rejection", err)
			}
		})
	}
}

func TestCompileModuleScriptBoundsSourceBeforeParsing(t *testing.T) {
	t.Parallel()

	source := "function transform(context) { return {}; }" + strings.Repeat(" ", maxScriptBytes)
	if _, err := compileModuleScript("extension:test", source); err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("compileModuleScript() error = %v, want source-size rejection", err)
	}
}

func TestCompileModuleScriptRejectsInvalidUTF8BeforeParsing(t *testing.T) {
	t.Parallel()

	if _, err := compileModuleScript("extension:test", string([]byte{0xff})); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("compileModuleScript() error = %v, want UTF-8 rejection", err)
	}
}

func TestCompileModuleScriptPreflightBoundsParserNesting(t *testing.T) {
	t.Parallel()

	source := strings.Repeat("(", maxScriptParserNesting+1) + "1" + strings.Repeat(")", maxScriptParserNesting+1)
	if _, err := compileModuleScript("extension:test", source); err == nil || !strings.Contains(err.Error(), "nested expressions") {
		t.Fatalf("compileModuleScript() error = %v, want parser nesting rejection", err)
	}
}

func TestCompileModuleScriptBoundsASTNodes(t *testing.T) {
	t.Parallel()

	program := &ast.Program{Body: make([]ast.Statement, maxScriptASTNodes+1)}
	for index := range program.Body {
		program.Body[index] = &ast.EmptyStatement{}
	}
	if err := checkScriptAST(program); err == nil || !strings.Contains(err.Error(), "AST contains") {
		t.Fatalf("checkScriptAST() error = %v, want AST node rejection", err)
	}
}

func TestCompileModuleScriptRejectsAsyncGenerators(t *testing.T) {
	t.Parallel()

	// The pinned goja release has no AsyncGeneratorFunction runtime. Keep this
	// refusal explicit so a dependency update cannot silently add an unmasked
	// dynamic-code constructor.
	source := `async function* generated() { yield 1; } function transform(context) { return {}; }`
	if _, err := compileModuleScript("extension:test", source); err == nil {
		t.Fatal("compileModuleScript() accepted an async generator")
	}
}

func TestCompileModuleScriptBoundsRegexpParserNesting(t *testing.T) {
	t.Parallel()

	pattern := strings.Repeat("(", maxScriptRegexpNesting+1) + "x" + strings.Repeat(")", maxScriptRegexpNesting+1)
	source := "const pattern = /" + pattern + "/; function transform(context) { return {}; }"
	if _, err := compileModuleScript("extension:test", source); err == nil || !strings.Contains(err.Error(), "regular expression nests") {
		t.Fatalf("compileModuleScript() error = %v, want regexp nesting rejection", err)
	}
}

func TestCheckScriptRegexpIgnoresEscapedAndClassParentheses(t *testing.T) {
	t.Parallel()

	pattern := strings.Repeat(`\(`, maxScriptRegexpNesting+1) +
		"[" + strings.Repeat("(", maxScriptRegexpNesting+1) + "]"
	if err := checkScriptRegexp(pattern); err != nil {
		t.Fatalf("checkScriptRegexp() error = %v", err)
	}
}

func TestHardenScriptVMDisablesDynamicCodeGeneration(t *testing.T) {
	t.Parallel()

	for name, source := range map[string]string{
		"direct eval":                    `eval("1 + 1")`,
		"indirect eval":                  `(0, eval)("1 + 1")`,
		"global Function":                `Function("return 1")()`,
		"function constructor":           `(function(){}).constructor("return 1")()`,
		"object constructor chain":       `({}).constructor.constructor("return 1")()`,
		"built-in constructor":           `Object.constructor("return 1")()`,
		"built-in method constructor":    `[].filter.constructor("return 1")()`,
		"class constructor":              `(class {}).constructor("return 1")()`,
		"bound function constructor":     `(function(){}).bind(null).constructor("return 1")()`,
		"proxy function constructor":     `(new Proxy(function(){}, {})).constructor("return 1")()`,
		"reflected function prototype":   `Object.getPrototypeOf(function(){}).constructor("return 1")()`,
		"async function constructor":     `(async function(){}).constructor("return 1")()`,
		"generator function constructor": `(function*(){}).constructor("return 1")()`,
		"generator instance chain":       `(function*(){}).prototype.constructor.constructor("return 1")()`,
		"generator object chain":         `Object.getPrototypeOf((function*(){})()).constructor.constructor("return 1")()`,
		"unsupported async generator":    `Object.getPrototypeOf(async function*(){}).constructor("return 1")()`,
		"async generator instance chain": `(async function*(){}).prototype.constructor.constructor("return 1")()`,
	} {
		source := source
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			vm := goja.New()
			if err := hardenScriptVM(vm); err != nil {
				t.Fatalf("hardenScriptVM() error = %v", err)
			}
			if _, err := vm.RunString(source); err == nil {
				t.Fatalf("RunString(%q) unexpectedly generated code", source)
			}
		})
	}
}

func TestHardenScriptVMMakesCodeGenerationLocksImmutable(t *testing.T) {
	t.Parallel()

	vm := goja.New()
	if err := hardenScriptVM(vm); err != nil {
		t.Fatalf("hardenScriptVM() error = %v", err)
	}
	for name, source := range map[string]string{
		"global eval":            `Object.defineProperty(globalThis, "eval", {value: function(){}})`,
		"global Function":        `Object.defineProperty(globalThis, "Function", {value: function(){}})`,
		"function constructor":   `Object.defineProperty(Object.getPrototypeOf(function(){}), "constructor", {value: function(){}})`,
		"async constructor":      `Object.defineProperty(Object.getPrototypeOf(async function(){}), "constructor", {value: function(){}})`,
		"generator constructor":  `Object.defineProperty(Object.getPrototypeOf(function*(){}), "constructor", {value: function(){}})`,
		"regexp constructor":     `Object.defineProperty(Object.getPrototypeOf(/x/), "constructor", {value: function(){}})`,
		"regexp compile":         `Object.defineProperty(Object.getPrototypeOf(/x/), "compile", {value: function(){}})`,
		"string regexp coercion": `Object.defineProperty(String.prototype, "match", {value: function(){}})`,
	} {
		if _, err := vm.RunString(source); err == nil {
			t.Fatalf("%s lock was configurable after hardening", name)
		}
	}
	value, err := vm.RunString(`(function(value) { return value + 1; })(41)`)
	if err != nil {
		t.Fatalf("ordinary function failed after hardening: %v", err)
	}
	if got := value.ToInteger(); got != 42 {
		t.Fatalf("ordinary function result = %d, want 42", got)
	}
}

func TestHardenScriptVMDisablesDynamicRegexpCompilation(t *testing.T) {
	t.Parallel()

	for name, source := range map[string]string{
		"RegExp call":         `RegExp("x")`,
		"RegExp construct":    `new RegExp("x")`,
		"literal constructor": `/x/.constructor("x")`,
		"regexp compile":      `/x/.compile("x")`,
		"string match":        `"x".match("x")`,
		"string matchAll":     `Array.from("x".matchAll("x"))`,
		"string search":       `"x".search("x")`,
	} {
		source := source
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			vm := goja.New()
			if err := hardenScriptVM(vm); err != nil {
				t.Fatalf("hardenScriptVM() error = %v", err)
			}
			if _, err := vm.RunString(source); err == nil {
				t.Fatalf("RunString(%q) unexpectedly compiled a dynamic regular expression", source)
			}
		})
	}
}

func TestHardenScriptVMPreservesPrecompiledRegexpMethods(t *testing.T) {
	t.Parallel()

	vm := goja.New()
	if err := hardenScriptVM(vm); err != nil {
		t.Fatalf("hardenScriptVM() error = %v", err)
	}
	value, err := vm.RunString(`
		let symbolReads = 0;
		const oneShotMatcher = new Proxy({}, {
			get(target, key) {
				if (key === Symbol.match) {
					symbolReads++;
					return symbolReads === 1 ? function() { return ["safe"]; } : undefined;
				}
				if (key === "toString") return function() { return "(".repeat(100000); };
			}
		});
		/a/.test("a") &&
		"a".match(/a/)[0] === "a" &&
		Array.from("aa".matchAll(/a/g)).length === 2 &&
		"ba".search(/a/) === 1 &&
		"x".match(oneShotMatcher)[0] === "safe" &&
		symbolReads === 1
	`)
	if err != nil {
		t.Fatalf("precompiled regular expression failed after hardening: %v", err)
	}
	if !value.ToBoolean() {
		t.Fatal("precompiled regular expression returned false")
	}
}

func TestHardenScriptVMBoundsJavaScriptCallStack(t *testing.T) {
	t.Parallel()

	vm := goja.New()
	if err := hardenScriptVM(vm); err != nil {
		t.Fatalf("hardenScriptVM() error = %v", err)
	}
	_, err := vm.RunString(`(function recurse() { return recurse(); })()`)
	var stackOverflow *goja.StackOverflowError
	if !errors.As(err, &stackOverflow) {
		t.Fatalf("RunString() error = %T %v, want *goja.StackOverflowError", err, err)
	}
}
