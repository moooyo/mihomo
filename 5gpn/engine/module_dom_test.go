package engine

import (
	"strings"
	"testing"

	"github.com/dop251/goja"
	"golang.org/x/net/html"
)

func TestDOMAppendChildRejectsSelfAndAncestor(t *testing.T) {
	tests := []struct {
		name    string
		script  string
		message string
	}{
		{
			name: "self",
			script: `
const document = new DOMParser().parseFromString("<main><section></section></main>", "text/html");
const main = document.querySelector("main");
main.appendChild(main);`,
			message: "itself",
		},
		{
			name: "ancestor",
			script: `
const document = new DOMParser().parseFromString("<main><section></section></main>", "text/html");
const main = document.querySelector("main");
const section = document.querySelector("section");
section.appendChild(main);`,
			message: "ancestor",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vm := goja.New()
			if err := installDOMAPI(vm); err != nil {
				t.Fatalf("install DOM API: %v", err)
			}
			if _, err := vm.RunString(test.script); err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("appendChild error = %v, want message containing %q", err, test.message)
			}
		})
	}
	parent := &html.Node{Type: html.ElementNode, Data: "main"}
	child := &html.Node{Type: html.ElementNode, Data: "section"}
	parent.AppendChild(child)
	if err := appendDOMChild(child, parent); err == nil {
		t.Fatal("ancestor append succeeded")
	}
	if parent.Parent != nil || child.Parent != parent || parent.FirstChild != child {
		t.Fatal("rejected ancestor append mutated the tree")
	}
}

func TestDOMWalkersRejectCyclesAndExcessiveDepth(t *testing.T) {
	cyclic := &html.Node{Type: html.ElementNode, Data: "div"}
	cyclic.Parent = cyclic
	cyclic.FirstChild = cyclic
	if _, err := domTextContent(cyclic); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("textContent cycle error = %v", err)
	}
	if _, err := domRender(cyclic); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("render cycle error = %v", err)
	}
	siblingParent := &html.Node{Type: html.ElementNode, Data: "div"}
	sibling := &html.Node{Type: html.ElementNode, Data: "span", Parent: siblingParent}
	siblingParent.FirstChild = sibling
	sibling.NextSibling = sibling
	if _, err := domRender(siblingParent); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("render sibling-cycle error = %v", err)
	}
	ancestor := &html.Node{Type: html.ElementNode, Data: "section"}
	subtree := &html.Node{Type: html.ElementNode, Data: "div", Parent: ancestor}
	ancestor.Parent = subtree
	subtree.AppendChild(&html.Node{Type: html.ElementNode, Data: "script"})
	if _, err := domRender(subtree); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("render parent-cycle error = %v", err)
	}

	root := &html.Node{Type: html.ElementNode, Data: "div"}
	parent := root
	for range maxDOMTreeDepth {
		child := &html.Node{Type: html.ElementNode, Data: "div"}
		parent.AppendChild(child)
		parent = child
	}
	if _, err := domRender(root); err == nil || !strings.Contains(err.Error(), "levels") {
		t.Fatalf("render depth error = %v", err)
	}
}

func TestDOMSerializationAndTextOutputAreBounded(t *testing.T) {
	tooLarge := strings.Repeat("x", maxDOMDocumentBytes+1)
	text := &html.Node{Type: html.TextNode, Data: tooLarge}
	if _, err := domTextContent(text); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("textContent output error = %v", err)
	}
	if _, err := domRender(text); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("render output error = %v", err)
	}

	parent := &html.Node{Type: html.ElementNode, Data: "div"}
	parent.AppendChild(&html.Node{Type: html.TextNode, Data: strings.Repeat("a", maxDOMDocumentBytes/2+1)})
	parent.AppendChild(&html.Node{Type: html.TextNode, Data: strings.Repeat("b", maxDOMDocumentBytes/2+1)})
	if _, err := domRenderChildren(parent); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("innerHTML combined output error = %v", err)
	}
}

func TestDOMParserReturnsDeepDocumentError(t *testing.T) {
	depth := maxDOMTreeDepth + 2
	source := strings.Repeat("<div>", depth) + "x" + strings.Repeat("</div>", depth)
	if _, err := newDOMDocument(goja.New(), source); err == nil {
		t.Fatal("deep document parsed without an error")
	}
}
