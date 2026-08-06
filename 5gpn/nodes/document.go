package nodes

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

const proxiesGroupName = "Proxies"

type configDocument struct {
	document     *yaml.Node
	root         *yaml.Node
	proxies      *yaml.Node
	groups       *yaml.Node
	proxiesGroup *yaml.Node
}

func parseConfigDocument(raw []byte) (*configDocument, error) {
	document, err := decodeSingleYAML(raw)
	if err != nil {
		return nil, fmt.Errorf("parse mihomo YAML: %w", err)
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode || document.Content[0].Anchor != "" {
		return nil, fmt.Errorf("mihomo YAML root must be a concrete mapping")
	}
	root := document.Content[0]
	proxies, _, err := mappingValue(root, "proxies")
	if err != nil {
		return nil, err
	}
	if proxies != nil && (proxies.Kind != yaml.SequenceNode || proxies.Anchor != "") {
		return nil, fmt.Errorf("top-level proxies must be a concrete sequence")
	}

	groups, _, err := mappingValue(root, "proxy-groups")
	if err != nil {
		return nil, err
	}
	if groups == nil || groups.Kind != yaml.SequenceNode || groups.Anchor != "" {
		return nil, fmt.Errorf("top-level proxy-groups must contain the %q selector", proxiesGroupName)
	}

	var proxiesGroup *yaml.Node
	for index, item := range groups.Content {
		if item.Kind != yaml.MappingNode || item.Anchor != "" {
			return nil, fmt.Errorf("proxy group %d must be a concrete mapping", index)
		}
		nameNode, _, err := mappingValue(item, "name")
		if err != nil {
			return nil, fmt.Errorf("proxy group %d: %w", index, err)
		}
		if nameNode == nil {
			continue
		}
		name, err := scalarString(nameNode, "proxy group name")
		if err != nil {
			return nil, fmt.Errorf("proxy group %d: %w", index, err)
		}
		if name != proxiesGroupName {
			continue
		}
		if proxiesGroup != nil {
			return nil, fmt.Errorf("proxy group %q is defined more than once", proxiesGroupName)
		}
		proxiesGroup = item
	}
	if proxiesGroup == nil {
		return nil, fmt.Errorf("proxy group %q is required", proxiesGroupName)
	}
	typeNode, _, err := mappingValue(proxiesGroup, "type")
	if err != nil {
		return nil, err
	}
	groupType, err := scalarString(typeNode, "Proxies group type")
	if err != nil {
		return nil, err
	}
	if groupType != "select" {
		return nil, fmt.Errorf("proxy group %q must have type select", proxiesGroupName)
	}

	return &configDocument{
		document:     document,
		root:         root,
		proxies:      proxies,
		groups:       groups,
		proxiesGroup: proxiesGroup,
	}, nil
}

func decodeSingleYAML(raw []byte) (*yaml.Node, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("document is empty")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("multiple YAML documents are not allowed")
	}
	return &document, nil
}

func (d *configDocument) ensureProxySequence() *yaml.Node {
	if d.proxies != nil {
		return d.proxies
	}
	key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "proxies"}
	value := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	d.root.Content = append(d.root.Content, key, value)
	d.proxies = value
	return value
}

func (d *configDocument) ensureProxiesMembers() (*yaml.Node, error) {
	members, _, err := mappingValue(d.proxiesGroup, "proxies")
	if err != nil {
		return nil, err
	}
	if members == nil {
		key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "proxies"}
		members = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		d.proxiesGroup.Content = append(d.proxiesGroup.Content, key, members)
		return members, nil
	}
	if members.Kind != yaml.SequenceNode || members.Anchor != "" {
		return nil, fmt.Errorf("proxy group %q proxies must be a concrete sequence", proxiesGroupName)
	}
	return members, nil
}

func (d *configDocument) proxiesMembers() (map[string]struct{}, error) {
	members, _, err := mappingValue(d.proxiesGroup, "proxies")
	if err != nil {
		return nil, err
	}
	out := make(map[string]struct{})
	if members == nil {
		return out, nil
	}
	if members.Kind != yaml.SequenceNode || members.Anchor != "" {
		return nil, fmt.Errorf("proxy group %q proxies must be a concrete sequence", proxiesGroupName)
	}
	for index, item := range members.Content {
		name, err := scalarString(item, "Proxies member")
		if err != nil {
			return nil, fmt.Errorf("Proxies member %d: %w", index, err)
		}
		out[name] = struct{}{}
	}
	return out, nil
}

func (d *configDocument) view(revision string) (View, error) {
	members, err := d.proxiesMembers()
	if err != nil {
		return View{}, err
	}
	views := make([]NodeView, 0)
	if d.proxies != nil {
		views = make([]NodeView, 0, len(d.proxies.Content))
		for index, item := range d.proxies.Content {
			view, err := proxyView(item, members)
			if err != nil {
				return View{}, fmt.Errorf("static proxy %d: %w", index, err)
			}
			views = append(views, view)
		}
	}
	return View{Revision: revision, Group: proxiesGroupName, Nodes: views}, nil
}

func proxyView(item *yaml.Node, members map[string]struct{}) (NodeView, error) {
	item = resolvedNode(item)
	if item.Kind != yaml.MappingNode {
		return NodeView{}, fmt.Errorf("entry must be a mapping")
	}
	nameNode, _, err := mappingValue(item, "name")
	if err != nil {
		return NodeView{}, err
	}
	name, err := scalarString(nameNode, "proxy name")
	if err != nil {
		return NodeView{}, err
	}
	normalized, err := normalizeName(name)
	if err != nil {
		return NodeView{}, err
	}
	if normalized != name {
		return NodeView{}, fmt.Errorf("proxy name must not have leading or trailing whitespace")
	}
	typeNode, _, err := mappingValue(item, "type")
	if err != nil {
		return NodeView{}, err
	}
	proxyType, err := scalarString(typeNode, "proxy type")
	if err != nil {
		return NodeView{}, err
	}
	serverNode, _, err := mappingValue(item, "server")
	if err != nil {
		return NodeView{}, err
	}
	portNode, _, err := mappingValue(item, "port")
	if err != nil {
		return NodeView{}, err
	}
	_, inProxies := members[name]
	return NodeView{
		Name:      name,
		Type:      proxyType,
		Server:    scalarJSONValue(serverNode),
		Port:      scalarJSONValue(portNode),
		InProxies: inProxies,
	}, nil
}

func (d *configDocument) allNames() (map[string]string, error) {
	names := map[string]string{
		"DIRECT":      "built-in proxy",
		"REJECT":      "built-in proxy",
		"REJECT-DROP": "built-in proxy",
		"COMPATIBLE":  "built-in proxy",
		"PASS":        "built-in proxy",
		"PASS-RULE":   "built-in proxy",
	}
	if d.proxies != nil {
		for index, item := range d.proxies.Content {
			name, err := proxyName(item, false)
			if err != nil {
				return nil, fmt.Errorf("static proxy %d: %w", index, err)
			}
			if previous, exists := names[name]; exists {
				return nil, fmt.Errorf("proxy name %q conflicts with %s", name, previous)
			}
			if name == "GLOBAL" {
				return nil, fmt.Errorf("proxy name %q is reserved", name)
			}
			names[name] = "existing static proxy"
		}
	}
	for index, item := range d.groups.Content {
		nameNode, _, err := mappingValue(item, "name")
		if err != nil {
			return nil, fmt.Errorf("proxy group %d: %w", index, err)
		}
		name, err := scalarString(nameNode, "proxy group name")
		if err != nil {
			return nil, fmt.Errorf("proxy group %d: %w", index, err)
		}
		if previous, exists := names[name]; exists {
			return nil, fmt.Errorf("proxy group name %q conflicts with %s", name, previous)
		}
		names[name] = "existing proxy group"
	}
	if _, exists := names["GLOBAL"]; !exists {
		names["GLOBAL"] = "built-in proxy group"
	}
	return names, nil
}

func proxyName(item *yaml.Node, normalize bool) (string, error) {
	item = resolvedNode(item)
	if item.Kind != yaml.MappingNode {
		return "", fmt.Errorf("proxy entry must be a mapping")
	}
	nameNode, _, err := mappingValue(item, "name")
	if err != nil {
		return "", err
	}
	name, err := scalarString(nameNode, "proxy name")
	if err != nil {
		return "", err
	}
	clean, err := normalizeName(name)
	if err != nil {
		return "", err
	}
	if normalize {
		resolvedNode(nameNode).Value = clean
		return clean, nil
	}
	if clean != name {
		return "", fmt.Errorf("proxy name must not have leading or trailing whitespace")
	}
	return name, nil
}

func normalizeName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("proxy name must not be empty")
	}
	if len([]byte(name)) > MaxNameBytes {
		return "", fmt.Errorf("proxy name exceeds %d bytes", MaxNameBytes)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("proxy name contains an ASCII control character")
		}
	}
	return name, nil
}

func mappingValue(mapping *yaml.Node, key string) (*yaml.Node, int, error) {
	mapping = resolvedNode(mapping)
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil, -1, fmt.Errorf("expected a mapping while reading %q", key)
	}
	var value *yaml.Node
	valueIndex := -1
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		keyNode := resolvedNode(mapping.Content[index])
		if keyNode.Kind != yaml.ScalarNode || keyNode.Value != key {
			continue
		}
		if value != nil {
			return nil, -1, fmt.Errorf("mapping key %q is defined more than once", key)
		}
		value = mapping.Content[index+1]
		valueIndex = index + 1
	}
	return value, valueIndex, nil
}

func scalarString(node *yaml.Node, label string) (string, error) {
	node = resolvedNode(node)
	if node == nil || node.Kind != yaml.ScalarNode || node.Tag == "!!null" {
		return "", fmt.Errorf("%s must be a string", label)
	}
	var value string
	if err := node.Decode(&value); err != nil {
		return "", fmt.Errorf("%s must be a string: %w", label, err)
	}
	return value, nil
}

func scalarJSONValue(node *yaml.Node) any {
	node = resolvedNode(node)
	if node == nil || node.Kind != yaml.ScalarNode || node.Tag == "!!null" {
		return nil
	}
	var value any
	if err := node.Decode(&value); err != nil {
		return node.Value
	}
	return value
}

func resolvedNode(node *yaml.Node) *yaml.Node {
	seen := make(map[*yaml.Node]struct{})
	for node != nil && node.Kind == yaml.AliasNode && node.Alias != nil {
		if _, exists := seen[node]; exists {
			return node
		}
		seen[node] = struct{}{}
		node = node.Alias
	}
	return node
}

func encodeDocument(document *yaml.Node) ([]byte, error) {
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(document); err != nil {
		return nil, fmt.Errorf("encode mihomo YAML: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("finish mihomo YAML: %w", err)
	}
	return output.Bytes(), nil
}
