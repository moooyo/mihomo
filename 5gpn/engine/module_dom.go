package engine

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/andybalholm/cascadia"
	"github.com/dop251/goja"
	"golang.org/x/net/html"
)

// The published Bilibili webpage bundle parses a response into a document,
// selects nodes, injects a script and a style, and serializes the whole
// document back. Surge runs it inside a webview; this runtime has no browser,
// so the document model below is the bounded stand-in.
//
// It is deliberately a real implementation of a small surface rather than a
// large approximate one. Everything the bundle can reach either works the way a
// browser works or is absent, because a half-present DOM method is the worst
// outcome available: the bundle guards on the property existing, then throws
// inside its own error handling, and the action reports success having changed
// nothing.
const (
	maxDOMDocumentBytes = 8 << 20
	maxDOMNodes         = 200000
	maxDOMTreeDepth     = 512
	maxDOMSelectorBytes = 1024
)

var errDOMOutputLimit = fmt.Errorf("document output exceeds %d bytes", maxDOMDocumentBytes)

// domDocument owns one parsed tree. Element wrappers are memoized so that
// identity holds: a script that removes a node it selected earlier, or compares
// parentElement against a node it already has, sees the same object a browser
// would.
type domDocument struct {
	vm      *goja.Runtime
	root    *html.Node
	wrapped map[*html.Node]*goja.Object
	// nodes is the reverse of wrapped. Without it nodeOf had to walk wrapped
	// looking for the object, which made the pinned remove-nodes idiom
	// (querySelectorAll then removeChild on each match) quadratic in the size of
	// the selection: every removeChild scanned every node the document had ever
	// handed out, in Go's randomized map order. Both maps are reclaimed with the
	// document, so this retains nothing past the action.
	nodes map[*goja.Object]*html.Node
}

func installDOMAPI(vm *goja.Runtime) error {
	constructor := func(call goja.ConstructorCall) *goja.Object {
		parser := call.This
		_ = parser.Set("parseFromString", func(inner goja.FunctionCall) goja.Value {
			source := inner.Argument(0).String()
			mime := strings.ToLower(strings.TrimSpace(inner.Argument(1).String()))
			// Only the HTML branch is implemented. An XML document has
			// different parsing and serialization rules, and silently handing
			// back an HTML tree would be a wrong answer rather than a missing
			// one.
			if mime != "text/html" {
				panic(vm.NewTypeError("parseFromString supports text/html only, got %q", mime))
			}
			document, err := newDOMDocument(vm, source)
			if err != nil {
				panic(vm.NewGoError(err))
			}
			return document
		})
		return nil
	}
	return vm.Set("DOMParser", constructor)
}

func newDOMDocument(vm *goja.Runtime, source string) (*goja.Object, error) {
	if len(source) > maxDOMDocumentBytes {
		return nil, fmt.Errorf("document exceeds %d bytes", maxDOMDocumentBytes)
	}
	root, err := html.Parse(strings.NewReader(source))
	if err != nil {
		return nil, fmt.Errorf("parse document: %w", err)
	}
	document := &domDocument{
		vm:      vm,
		root:    root,
		wrapped: make(map[*html.Node]*goja.Object),
		nodes:   make(map[*goja.Object]*html.Node),
	}
	if _, err := inspectDOMTree(root, nil); err != nil {
		return nil, err
	}
	return document.documentObject(), nil
}

type domTreeStats struct {
	nodes int
	depth int
}

// inspectDOMTree is the admission boundary for every operation that delegates
// to a recursive tree walker. The public DOM surface cannot write Node links
// directly, but guarding here keeps an invalid graph from reaching cascadia or
// x/net/html even if a later mutation method gets that invariant wrong.
func inspectDOMTree(root *html.Node, visit func(*html.Node) error) (domTreeStats, error) {
	if root == nil {
		return domTreeStats{}, errors.New("document tree has a nil root")
	}
	path := make(map[*html.Node]struct{})
	stats := domTreeStats{}
	var walk func(*html.Node, int) error
	walk = func(node *html.Node, depth int) error {
		if depth > maxDOMTreeDepth {
			return fmt.Errorf("document tree exceeds %d levels", maxDOMTreeDepth)
		}
		if _, exists := path[node]; exists {
			return errors.New("document tree contains a cycle")
		}
		path[node] = struct{}{}
		defer delete(path, node)
		stats.nodes++
		if stats.nodes > maxDOMNodes {
			return fmt.Errorf("document has more than %d nodes", maxDOMNodes)
		}
		if depth > stats.depth {
			stats.depth = depth
		}
		if visit != nil {
			if err := visit(node); err != nil {
				return err
			}
		}
		if hasDOMSiblingCycle(node.FirstChild) {
			return errors.New("document tree contains a sibling cycle")
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if child.Parent != node {
				return errors.New("document tree contains an invalid parent link")
			}
			if err := walk(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root, 1); err != nil {
		return domTreeStats{}, err
	}
	return stats, nil
}

func hasDOMSiblingCycle(first *html.Node) bool {
	slow, fast := first, first
	for fast != nil && fast.NextSibling != nil {
		slow = slow.NextSibling
		fast = fast.NextSibling.NextSibling
		if slow == fast {
			return true
		}
	}
	return false
}

func inspectDOMParentChain(node *html.Node) (int, error) {
	seen := make(map[*html.Node]struct{})
	depth := 0
	for current := node; current != nil; current = current.Parent {
		if _, exists := seen[current]; exists {
			return 0, errors.New("document parent chain contains a cycle")
		}
		seen[current] = struct{}{}
		depth++
		if depth > maxDOMTreeDepth {
			return 0, fmt.Errorf("document parent chain exceeds %d levels", maxDOMTreeDepth)
		}
	}
	return depth, nil
}

func (d *domDocument) documentObject() *goja.Object {
	object := d.vm.NewObject()
	_ = object.Set("createElement", func(call goja.FunctionCall) goja.Value {
		name := strings.ToLower(strings.TrimSpace(call.Argument(0).String()))
		if name == "" {
			panic(d.vm.NewTypeError("createElement requires a tag name"))
		}
		return d.wrap(&html.Node{Type: html.ElementNode, Data: name})
	})
	_ = object.Set("querySelectorAll", func(call goja.FunctionCall) goja.Value {
		return d.vm.ToValue(d.selectAll(d.root, call.Argument(0)))
	})
	_ = object.Set("querySelector", func(call goja.FunctionCall) goja.Value {
		// Query rather than selectAll-and-discard: the old shape walked the whole
		// subtree, allocated a goja object for every match and then returned the
		// first, so probing for one optional node cost as much as collecting every
		// node that matched.
		if _, err := inspectDOMTree(d.root, nil); err != nil {
			panic(d.vm.NewGoError(err))
		}
		match := cascadia.Query(d.root, d.compileSelector(call.Argument(0)))
		if match == nil {
			return goja.Null()
		}
		return d.wrap(match)
	})
	// documentElement, head, and body are looked up on every read rather than
	// captured once, because the bundle appends to head and then serializes
	// documentElement expecting to see its own change.
	_ = object.DefineAccessorProperty("documentElement",
		d.vm.ToValue(func(goja.FunctionCall) goja.Value { return d.firstElement("html") }),
		nil, goja.FLAG_FALSE, goja.FLAG_TRUE)
	_ = object.DefineAccessorProperty("head",
		d.vm.ToValue(func(goja.FunctionCall) goja.Value { return d.firstElement("head") }),
		nil, goja.FLAG_FALSE, goja.FLAG_TRUE)
	_ = object.DefineAccessorProperty("body",
		d.vm.ToValue(func(goja.FunctionCall) goja.Value { return d.firstElement("body") }),
		nil, goja.FLAG_FALSE, goja.FLAG_TRUE)
	return object
}

func (d *domDocument) firstElement(tag string) goja.Value {
	var found *html.Node
	stop := errors.New("element found")
	_, err := inspectDOMTree(d.root, func(node *html.Node) error {
		if node.Type == html.ElementNode && node.Data == tag {
			found = node
			return stop
		}
		return nil
	})
	if err != nil && !errors.Is(err, stop) {
		panic(d.vm.NewGoError(err))
	}
	if found == nil {
		return goja.Null()
	}
	return d.wrap(found)
}

func (d *domDocument) compileSelector(selector goja.Value) cascadia.Selector {
	text := selector.String()
	if len(text) > maxDOMSelectorBytes {
		panic(d.vm.NewTypeError("selector exceeds %d bytes", maxDOMSelectorBytes))
	}
	compiled, err := cascadia.Compile(text)
	if err != nil {
		panic(d.vm.NewGoError(fmt.Errorf("invalid selector %q: %w", text, err)))
	}
	return compiled
}

func (d *domDocument) selectAll(scope *html.Node, selector goja.Value) []goja.Value {
	if _, err := inspectDOMTree(scope, nil); err != nil {
		panic(d.vm.NewGoError(err))
	}
	if _, err := inspectDOMParentChain(scope); err != nil {
		panic(d.vm.NewGoError(err))
	}
	compiled := d.compileSelector(selector)
	matched := make([]goja.Value, 0)
	for _, node := range cascadia.QueryAll(scope, compiled) {
		matched = append(matched, d.wrap(node))
	}
	return matched
}

// wrap returns the one object representing this node.
func (d *domDocument) wrap(node *html.Node) *goja.Object {
	if existing, ok := d.wrapped[node]; ok {
		return existing
	}
	object := d.vm.NewObject()
	d.wrapped[node] = object
	d.nodes[object] = node

	_ = object.Set("appendChild", func(call goja.FunctionCall) goja.Value {
		child := d.nodeOf(call.Argument(0))
		if err := appendDOMChild(node, child); err != nil {
			panic(d.vm.NewTypeError(err.Error()))
		}
		return d.wrap(child)
	})
	_ = object.Set("removeChild", func(call goja.FunctionCall) goja.Value {
		child := d.nodeOf(call.Argument(0))
		if child.Parent != node {
			panic(d.vm.NewTypeError("removeChild target is not a child of this node"))
		}
		node.RemoveChild(child)
		return d.wrap(child)
	})
	_ = object.Set("querySelectorAll", func(call goja.FunctionCall) goja.Value {
		return d.vm.ToValue(d.selectAll(node, call.Argument(0)))
	})
	_ = object.Set("getAttribute", func(call goja.FunctionCall) goja.Value {
		name := strings.ToLower(call.Argument(0).String())
		for _, attribute := range node.Attr {
			if attribute.Key == name {
				return d.vm.ToValue(attribute.Val)
			}
		}
		return goja.Null()
	})
	_ = object.Set("setAttribute", func(call goja.FunctionCall) goja.Value {
		name := strings.ToLower(call.Argument(0).String())
		value := call.Argument(1).String()
		for index := range node.Attr {
			if node.Attr[index].Key == name {
				node.Attr[index].Val = value
				return goja.Undefined()
			}
		}
		node.Attr = append(node.Attr, html.Attribute{Key: name, Val: value})
		return goja.Undefined()
	})

	_ = object.DefineAccessorProperty("tagName",
		d.vm.ToValue(func(goja.FunctionCall) goja.Value {
			return d.vm.ToValue(strings.ToUpper(node.Data))
		}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)
	_ = object.DefineAccessorProperty("parentElement",
		d.vm.ToValue(func(goja.FunctionCall) goja.Value {
			if node.Parent == nil || node.Parent.Type != html.ElementNode {
				return goja.Null()
			}
			return d.wrap(node.Parent)
		}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)
	_ = object.DefineAccessorProperty("textContent",
		d.vm.ToValue(func(goja.FunctionCall) goja.Value {
			text, err := domTextContent(node)
			if err != nil {
				panic(d.vm.NewGoError(err))
			}
			return d.vm.ToValue(text)
		}),
		d.vm.ToValue(func(call goja.FunctionCall) goja.Value {
			text := call.Argument(0).String()
			if len(text) > maxDOMDocumentBytes {
				panic(d.vm.NewTypeError("textContent exceeds %d bytes", maxDOMDocumentBytes))
			}
			textNode := &html.Node{Type: html.TextNode, Data: text}
			if err := validateDOMAppend(node, textNode); err != nil {
				panic(d.vm.NewTypeError(err.Error()))
			}
			for node.FirstChild != nil {
				node.RemoveChild(node.FirstChild)
			}
			node.AppendChild(textNode)
			return goja.Undefined()
		}), goja.FLAG_FALSE, goja.FLAG_TRUE)
	_ = object.DefineAccessorProperty("outerHTML",
		d.vm.ToValue(func(goja.FunctionCall) goja.Value {
			rendered, err := domRender(node)
			if err != nil {
				panic(d.vm.NewGoError(err))
			}
			return d.vm.ToValue(rendered)
		}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)
	_ = object.DefineAccessorProperty("innerHTML",
		d.vm.ToValue(func(goja.FunctionCall) goja.Value {
			rendered, err := domRenderChildren(node)
			if err != nil {
				panic(d.vm.NewGoError(err))
			}
			return d.vm.ToValue(rendered)
		}), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)
	return object
}

// nodeOf recovers the tree node behind a wrapper. A script may only pass back
// an object this document handed it; anything else is rejected rather than
// coerced, because grafting a foreign object into the tree would corrupt it.
func (d *domDocument) nodeOf(value goja.Value) *html.Node {
	object, ok := value.(*goja.Object)
	if !ok {
		panic(d.vm.NewTypeError("expected a node from this document"))
	}
	node, ok := d.nodes[object]
	if !ok {
		panic(d.vm.NewTypeError("expected a node from this document"))
	}
	return node
}

func appendDOMChild(parent, child *html.Node) error {
	if err := validateDOMAppend(parent, child); err != nil {
		return err
	}
	if child.Parent != nil {
		child.Parent.RemoveChild(child)
	}
	parent.AppendChild(child)
	return nil
}

func validateDOMAppend(parent, child *html.Node) error {
	if parent == child {
		return errors.New("appendChild cannot append a node to itself")
	}
	seen := make(map[*html.Node]struct{})
	parentDepth := 0
	for ancestor := parent; ancestor != nil; ancestor = ancestor.Parent {
		if _, exists := seen[ancestor]; exists {
			return errors.New("appendChild parent chain contains a cycle")
		}
		seen[ancestor] = struct{}{}
		parentDepth++
		if parentDepth > maxDOMTreeDepth {
			return fmt.Errorf("appendChild parent exceeds %d levels", maxDOMTreeDepth)
		}
		if ancestor == child {
			return errors.New("appendChild cannot append an ancestor beneath its descendant")
		}
	}
	childStats, err := inspectDOMTree(child, nil)
	if err != nil {
		return fmt.Errorf("appendChild target is invalid: %w", err)
	}
	if parentDepth+childStats.depth > maxDOMTreeDepth {
		return fmt.Errorf("appendChild result would exceed %d levels", maxDOMTreeDepth)
	}
	return nil
}

type domOutput struct {
	buffer bytes.Buffer
	limit  int
}

func (o *domOutput) Write(body []byte) (int, error) {
	if len(body) > o.limit-o.buffer.Len() {
		return 0, errDOMOutputLimit
	}
	return o.buffer.Write(body)
}

func (o *domOutput) WriteString(text string) (int, error) {
	if len(text) > o.limit-o.buffer.Len() {
		return 0, errDOMOutputLimit
	}
	return o.buffer.WriteString(text)
}

func (o *domOutput) WriteByte(value byte) error {
	if o.buffer.Len() == o.limit {
		return errDOMOutputLimit
	}
	return o.buffer.WriteByte(value)
}

func (o *domOutput) String() string {
	return o.buffer.String()
}

func domTextContent(node *html.Node) (string, error) {
	output := domOutput{limit: maxDOMDocumentBytes}
	if _, err := inspectDOMTree(node, func(current *html.Node) error {
		if current.Type == html.TextNode {
			_, err := output.WriteString(current.Data)
			return err
		}
		return nil
	}); err != nil {
		return "", err
	}
	return output.String(), nil
}

func domRender(node *html.Node) (string, error) {
	if _, err := inspectDOMTree(node, nil); err != nil {
		return "", err
	}
	output := domOutput{limit: maxDOMDocumentBytes}
	if err := renderDOMNode(&output, node); err != nil {
		return "", err
	}
	return output.String(), nil
}

func domRenderChildren(node *html.Node) (string, error) {
	if _, err := inspectDOMTree(node, nil); err != nil {
		return "", err
	}
	output := domOutput{limit: maxDOMDocumentBytes}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if err := renderDOMNode(&output, child); err != nil {
			return "", err
		}
	}
	return output.String(), nil
}

func renderDOMNode(output *domOutput, node *html.Node) error {
	if _, err := inspectDOMParentChain(node); err != nil {
		return err
	}
	if node.Parent != nil && node.Type == html.ElementNode {
		// html.Render walks siblings for a detached node, so render through a
		// copy that has none.
		clone := *node
		clone.Parent, clone.PrevSibling, clone.NextSibling = nil, nil, nil
		node = &clone
	}
	if err := html.Render(output, node); err != nil {
		if errors.Is(err, errDOMOutputLimit) {
			return errDOMOutputLimit
		}
		return errors.New("document could not be serialized")
	}
	return nil
}
