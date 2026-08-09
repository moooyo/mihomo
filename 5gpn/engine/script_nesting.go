package engine

import (
	"fmt"
	"reflect"
	"strconv"
	"unicode/utf8"

	"github.com/dop251/goja"
	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
	tdparse "github.com/tdewolff/parse/v2"
	tdjs "github.com/tdewolff/parse/v2/js"
)

const (
	// The importer and persisted snapshot use the same source bound. A second,
	// depth-limited parser runs before goja, so accepting a large reviewed bundle
	// does not also accept source-shaped recursion against goja's Go stack.
	maxScriptBytes = 1 << 20

	// The AST limits bound recursive compiler work and the executable shape.
	// They are checked iteratively, after goja's real lexer and parser have
	// resolved regexp/division, numeric literals, templates, and Unicode names.
	maxScriptASTDepth = 256
	maxScriptASTNodes = 128 << 10

	// tdewolff's JavaScript parser checks these counters before descending. It
	// is the parser-stack gate that goja itself does not expose.
	maxScriptParserNesting = 256

	// RegExp literals bypass JavaScript AST nesting: goja transforms their
	// patterns with a separate recursive parser during compilation.
	maxScriptRegexpBytes   = 64 << 10
	maxScriptRegexpNesting = 256

	// Goja defaults to math.MaxInt32 calls. A recursive extension can otherwise
	// grow its goroutine stack until the process dies before its action timeout
	// gets a chance to interrupt it.
	maxScriptCallStack = 256
)

var dynamicCodeConstructorSamples = goja.MustCompile(
	"5gpn:dynamic-code-lockdown",
	`[function(){}, async function(){}, function*(){}]`,
	false,
)

// compileModuleScript is the sole parser/compiler path for untrusted extension
// JavaScript. A separate real JavaScript parser with explicit recursion limits
// runs first because AST validation happens too late to protect goja's recursive
// parser. Source maps are disabled because a snapshot is immutable and may not
// name a second, unreviewed input. The hand-written pre-lexer this replaced
// could not correctly resolve JavaScript lexical context (including 1. and
// Unicode identifiers); all structural decisions now come from real parsers.
func compileModuleScript(filename, source string) (*goja.Program, error) {
	if len(source) == 0 {
		return nil, fmt.Errorf("script is empty")
	}
	if len(source) > maxScriptBytes {
		return nil, fmt.Errorf("script is %d bytes, at most %d are allowed", len(source), maxScriptBytes)
	}
	if !utf8.ValidString(source) {
		return nil, fmt.Errorf("script is not valid UTF-8")
	}
	if tdjs.NestedExprLimit != maxScriptParserNesting || tdjs.NestedStmtLimit != maxScriptParserNesting {
		return nil, fmt.Errorf("depth-limited JavaScript preflight is misconfigured")
	}
	if _, err := tdjs.Parse(tdparse.NewInputString(source), tdjs.Options{}); err != nil {
		return nil, fmt.Errorf("depth-limited JavaScript preflight: %w", err)
	}

	program, err := goja.Parse(filename, source, parser.WithDisableSourceMaps)
	if err != nil {
		return nil, err
	}
	if err := checkScriptAST(program); err != nil {
		return nil, err
	}
	return goja.CompileAST(program, false)
}

type scriptASTItem struct {
	node  ast.Node
	depth int
}

type scriptASTIdentity struct {
	typeOf  reflect.Type
	pointer uintptr
}

var scriptASTNodeType = reflect.TypeOf((*ast.Node)(nil)).Elem()

// checkScriptAST walks iteratively so this guard cannot itself consume the Go
// stack it is meant to protect. DeclarationList fields point back to nodes that
// are also reachable through statement bodies; pointer identity avoids both
// double-counting and exponential revisits of those shared subtrees.
func checkScriptAST(program *ast.Program) error {
	work := []scriptASTItem{{node: program, depth: 1}}
	seenDepth := make(map[scriptASTIdentity]int)
	nodes := 0

	for len(work) > 0 {
		last := len(work) - 1
		item := work[last]
		work = work[:last]
		if item.node == nil {
			continue
		}
		if item.depth > maxScriptASTDepth {
			return fmt.Errorf("script AST nests more than %d levels deep", maxScriptASTDepth)
		}
		if function, ok := item.node.(*ast.FunctionLiteral); ok && function.Async && function.Generator {
			return fmt.Errorf("async generator functions are disabled")
		}
		if regexp, ok := item.node.(*ast.RegExpLiteral); ok {
			if err := checkScriptRegexp(regexp.Pattern); err != nil {
				return err
			}
		}

		value := reflect.ValueOf(item.node)
		identity := scriptASTIdentity{typeOf: value.Type()}
		if value.Kind() == reflect.Pointer {
			identity.pointer = value.Pointer()
			if previous, exists := seenDepth[identity]; exists && previous >= item.depth {
				continue
			}
			if _, exists := seenDepth[identity]; !exists {
				nodes++
				if nodes > maxScriptASTNodes {
					return fmt.Errorf("script AST contains more than %d nodes", maxScriptASTNodes)
				}
			}
			seenDepth[identity] = item.depth
		} else {
			nodes++
			if nodes > maxScriptASTNodes {
				return fmt.Errorf("script AST contains more than %d nodes", maxScriptASTNodes)
			}
		}

		for _, child := range scriptASTChildren(item.node) {
			work = append(work, scriptASTItem{node: child, depth: item.depth + 1})
		}
	}
	return nil
}

func checkScriptRegexp(pattern string) error {
	if len(pattern) > maxScriptRegexpBytes {
		return fmt.Errorf("regular expression is %d bytes, at most %d are allowed", len(pattern), maxScriptRegexpBytes)
	}
	depth := 0
	inClass := false
	for index := 0; index < len(pattern); index++ {
		switch pattern[index] {
		case '\\':
			index++
		case '[':
			if !inClass {
				inClass = true
			}
		case ']':
			if inClass {
				inClass = false
			}
		case '(':
			if !inClass {
				depth++
				if depth > maxScriptRegexpNesting {
					return fmt.Errorf("regular expression nests more than %d groups", maxScriptRegexpNesting)
				}
			}
		case ')':
			if !inClass && depth > 0 {
				depth--
			}
		}
	}
	return nil
}

func scriptASTChildren(node ast.Node) []ast.Node {
	value := reflect.ValueOf(node)
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return nil
	}

	children := make([]ast.Node, 0, value.NumField())
	for index := 0; index < value.NumField(); index++ {
		children = appendScriptASTNodes(children, value.Field(index))
	}
	return children
}

func appendScriptASTNodes(nodes []ast.Node, value reflect.Value) []ast.Node {
	if !value.IsValid() {
		return nodes
	}
	for value.Kind() == reflect.Interface {
		if value.IsNil() {
			return nodes
		}
		value = value.Elem()
	}

	switch value.Kind() {
	case reflect.Pointer:
		if value.IsNil() || !value.CanInterface() {
			return nodes
		}
		if node, ok := value.Interface().(ast.Node); ok {
			return append(nodes, node)
		}
	case reflect.Struct:
		if value.CanAddr() && value.Addr().CanInterface() && value.Addr().Type().Implements(scriptASTNodeType) {
			return append(nodes, value.Addr().Interface().(ast.Node))
		}
	case reflect.Slice, reflect.Array:
		for index := 0; index < value.Len(); index++ {
			nodes = appendScriptASTNodes(nodes, value.Index(index))
		}
	}
	return nodes
}

// hardenScriptVM removes every code-generation constructor goja exposes and
// gives JavaScript calls a finite stack. The properties are made immutable so
// untrusted code cannot restore them. Goja has no per-Runtime heap quota; this
// function deliberately makes no memory-isolation claim.
func hardenScriptVM(vm *goja.Runtime) error {
	vm.SetMaxCallStackSize(maxScriptCallStack)

	value, err := vm.RunProgram(dynamicCodeConstructorSamples)
	if err != nil {
		return fmt.Errorf("create dynamic-code constructor samples: %w", err)
	}
	samples := value.ToObject(vm)
	for index := 0; index < 3; index++ {
		function := samples.Get(strconv.Itoa(index)).ToObject(vm)
		prototype := function.Prototype()
		if prototype == nil {
			return fmt.Errorf("dynamic-code constructor sample %d has no prototype", index)
		}
		if err := disableConstructor(prototype); err != nil {
			return fmt.Errorf("disable dynamic-code constructor %d: %w", index, err)
		}

		// Generator instances expose GeneratorFunctionPrototype through their
		// shared prototype. Mask that secondary route as well.
		if index == 2 {
			instancePrototypeValue := function.Get("prototype")
			if instancePrototypeValue != nil && !goja.IsUndefined(instancePrototypeValue) && !goja.IsNull(instancePrototypeValue) {
				instancePrototype := instancePrototypeValue.ToObject(vm).Prototype()
				if instancePrototype != nil {
					if err := disableConstructor(instancePrototype); err != nil {
						return fmt.Errorf("disable generator instance constructor: %w", err)
					}
				}
			}
		}
	}
	if err := hardenDynamicRegexp(vm); err != nil {
		return err
	}

	global := vm.GlobalObject()
	for _, name := range []string{"eval", "Function", "RegExp"} {
		if err := global.DefineDataProperty(name, goja.Undefined(), goja.FLAG_FALSE, goja.FLAG_FALSE, goja.FLAG_FALSE); err != nil {
			return fmt.Errorf("disable global %s: %w", name, err)
		}
	}
	return nil
}

func hardenDynamicRegexp(vm *goja.Runtime) error {
	regexpConstructor := vm.Get("RegExp").ToObject(vm)
	regexpPrototype := regexpConstructor.Get("prototype").ToObject(vm)
	if err := disableConstructor(regexpPrototype); err != nil {
		return fmt.Errorf("disable RegExp constructor: %w", err)
	}
	if err := regexpPrototype.DefineDataProperty("compile", goja.Undefined(), goja.FLAG_FALSE, goja.FLAG_FALSE, goja.FLAG_FALSE); err != nil {
		return fmt.Errorf("disable RegExp.prototype.compile: %w", err)
	}

	stringConstructor := vm.Get("String").ToObject(vm)
	stringPrototype := stringConstructor.Get("prototype").ToObject(vm)
	methods := []struct {
		name   string
		symbol *goja.Symbol
	}{
		{name: "match", symbol: goja.SymMatch},
		{name: "matchAll", symbol: goja.SymMatchAll},
		{name: "search", symbol: goja.SymSearch},
	}
	for _, method := range methods {
		if _, ok := goja.AssertFunction(stringPrototype.Get(method.name)); !ok {
			return fmt.Errorf("String.prototype.%s is unavailable", method.name)
		}
		name := method.name
		symbol := method.symbol
		guarded := func(call goja.FunctionCall) goja.Value {
			argument, ok := call.Argument(0).(*goja.Object)
			if !ok {
				panic(vm.NewTypeError("String.prototype.%s requires a precompiled RegExp", name))
			}
			matcher, ok := goja.AssertFunction(argument.GetSymbol(symbol))
			if !ok {
				panic(vm.NewTypeError("String.prototype.%s requires a precompiled RegExp", name))
			}
			// Invoke the exact method that passed the guard. Delegating to the
			// original String method would read Symbol.match a second time; a Proxy
			// could return a function once and undefined next, forcing the original
			// method into its dynamic RegExp coercion path after validation.
			value, err := matcher(argument, call.This)
			if err != nil {
				panic(err)
			}
			return value
		}
		if err := stringPrototype.DefineDataProperty(name, vm.ToValue(guarded), goja.FLAG_FALSE, goja.FLAG_FALSE, goja.FLAG_FALSE); err != nil {
			return fmt.Errorf("guard String.prototype.%s: %w", name, err)
		}
	}
	return nil
}

func disableConstructor(prototype *goja.Object) error {
	return prototype.DefineDataProperty(
		"constructor",
		goja.Undefined(),
		goja.FLAG_FALSE,
		goja.FLAG_FALSE,
		goja.FLAG_FALSE,
	)
}
