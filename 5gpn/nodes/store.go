package nodes

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"

	"gopkg.in/yaml.v3"
)

// Store performs revision-protected edits of one operator-owned config file.
type Store struct {
	path       string
	dir        string
	backupPath string
	lockPath   string
}

type importCandidate struct {
	bytes []byte
	added []string
	view  View
}

// New returns a static-node store for configPath.
func New(configPath string) (*Store, error) {
	if strings.TrimSpace(configPath) == "" {
		return nil, fmt.Errorf("%w: --config is required", ErrInvalidInput)
	}
	absolute, err := filepath.Abs(configPath)
	if err != nil {
		return nil, fmt.Errorf("resolve config path: %w", err)
	}
	absolute = filepath.Clean(absolute)
	dir := filepath.Dir(absolute)
	if err := validateParentDirectory(dir); err != nil {
		return nil, err
	}
	return &Store{
		path:       absolute,
		dir:        dir,
		backupPath: absolute + ".5gpn-nodes.bak",
		lockPath:   absolute + ".5gpn-nodes.lock",
	}, nil
}

// List reads the raw file revision and its static-node projection.
func (s *Store) List() (View, error) {
	raw, _, err := readRegularFile(s.path)
	if err != nil {
		return View{}, err
	}
	document, err := parseConfigDocument(raw)
	if err != nil {
		return View{}, err
	}
	return document.view(revisionOf(raw))
}

// PreviewImport performs the complete import and mihomo parse without writing
// the lock, backup, or config files.
func (s *Store) PreviewImport(expectedRevision string, content []byte) (ImportPreview, error) {
	if err := validateExpectedRevision(expectedRevision); err != nil {
		return ImportPreview{}, err
	}
	raw, _, err := readRegularFile(s.path)
	if err != nil {
		return ImportPreview{}, err
	}
	baseline := revisionOf(raw)
	if baseline != expectedRevision {
		return ImportPreview{}, &RevisionConflictError{Current: baseline}
	}
	candidate, err := s.buildImportCandidate(raw, content)
	if err != nil {
		return ImportPreview{}, err
	}
	latest, _, err := readRegularFile(s.path)
	if err != nil {
		return ImportPreview{}, err
	}
	latestRevision := revisionOf(latest)
	if latestRevision != baseline {
		return ImportPreview{}, &RevisionConflictError{Current: latestRevision}
	}
	return ImportPreview{
		Revision:          baseline,
		CandidateRevision: revisionOf(candidate.bytes),
		Added:             candidate.added,
		Nodes:             candidate.view.Nodes,
	}, nil
}

// Import validates and atomically persists a static-node import.
func (s *Store) Import(expectedRevision string, content []byte) (ImportResult, error) {
	if err := validateExpectedRevision(expectedRevision); err != nil {
		return ImportResult{}, err
	}
	initial, initialInfo, err := readRegularFile(s.path)
	if err != nil {
		return ImportResult{}, err
	}
	if initialRevision := revisionOf(initial); initialRevision != expectedRevision {
		return ImportResult{}, &RevisionConflictError{Current: initialRevision}
	}
	lock, err := acquireFileLock(s.lockPath, initialInfo)
	if err != nil {
		return ImportResult{}, err
	}
	defer lock.Close()

	raw, _, err := readRegularFile(s.path)
	if err != nil {
		return ImportResult{}, err
	}
	baseline := revisionOf(raw)
	if baseline != expectedRevision {
		return ImportResult{}, &RevisionConflictError{Current: baseline}
	}
	candidate, err := s.buildImportCandidate(raw, content)
	if err != nil {
		return ImportResult{}, err
	}

	latest, latestInfo, err := readRegularFile(s.path)
	if err != nil {
		return ImportResult{}, err
	}
	latestRevision := revisionOf(latest)
	if latestRevision != baseline {
		return ImportResult{}, &RevisionConflictError{Current: latestRevision}
	}
	if err := persistPreviousAndConfig(s.path, s.backupPath, latest, candidate.bytes, latestInfo); err != nil {
		return ImportResult{}, err
	}
	return ImportResult{
		Revision: revisionOf(candidate.bytes),
		Added:    candidate.added,
		Nodes:    candidate.view.Nodes,
	}, nil
}

// Delete removes one static node and its Proxies selector membership.
func (s *Store) Delete(expectedRevision, requestedName string) (DeleteResult, error) {
	if err := validateExpectedRevision(expectedRevision); err != nil {
		return DeleteResult{}, err
	}
	name, err := normalizeName(requestedName)
	if err != nil {
		return DeleteResult{}, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	initial, initialInfo, err := readRegularFile(s.path)
	if err != nil {
		return DeleteResult{}, err
	}
	if initialRevision := revisionOf(initial); initialRevision != expectedRevision {
		return DeleteResult{}, &RevisionConflictError{Current: initialRevision}
	}
	lock, err := acquireFileLock(s.lockPath, initialInfo)
	if err != nil {
		return DeleteResult{}, err
	}
	defer lock.Close()

	raw, _, err := readRegularFile(s.path)
	if err != nil {
		return DeleteResult{}, err
	}
	baseline := revisionOf(raw)
	if baseline != expectedRevision {
		return DeleteResult{}, &RevisionConflictError{Current: baseline}
	}
	candidateBytes, candidateView, err := s.buildDeleteCandidate(raw, name)
	if err != nil {
		return DeleteResult{}, err
	}

	latest, latestInfo, err := readRegularFile(s.path)
	if err != nil {
		return DeleteResult{}, err
	}
	latestRevision := revisionOf(latest)
	if latestRevision != baseline {
		return DeleteResult{}, &RevisionConflictError{Current: latestRevision}
	}
	if err := persistPreviousAndConfig(s.path, s.backupPath, latest, candidateBytes, latestInfo); err != nil {
		return DeleteResult{}, err
	}
	return DeleteResult{
		Revision: revisionOf(candidateBytes),
		Removed:  name,
		Nodes:    candidateView.Nodes,
	}, nil
}

func (s *Store) buildImportCandidate(raw, content []byte) (importCandidate, error) {
	document, err := parseConfigDocument(raw)
	if err != nil {
		return importCandidate{}, err
	}
	items, err := parseImportedProxies(content)
	if err != nil {
		return importCandidate{}, err
	}
	existingCount := 0
	if document.proxies != nil {
		existingCount = len(document.proxies.Content)
	}
	if existingCount+len(items) > MaxStaticNodes {
		return importCandidate{}, fmt.Errorf("%w: import would exceed %d static nodes", ErrInvalidInput, MaxStaticNodes)
	}
	names, err := document.allNames()
	if err != nil {
		return importCandidate{}, err
	}
	added := make([]string, 0, len(items))
	for index, item := range items {
		name, err := proxyName(item, false)
		if err != nil {
			return importCandidate{}, fmt.Errorf("%w: proxy %d: %v", ErrInvalidInput, index, err)
		}
		if previous, exists := names[name]; exists {
			return importCandidate{}, fmt.Errorf("%w: proxy name %q conflicts with %s", ErrInvalidInput, name, previous)
		}
		names[name] = "another proxy in this import"
		added = append(added, name)
	}

	proxySequence := document.ensureProxySequence()
	proxySequence.Content = append(proxySequence.Content, items...)
	members, err := document.ensureProxiesMembers()
	if err != nil {
		return importCandidate{}, err
	}
	for _, name := range added {
		members.Content = append(members.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name})
	}
	candidateBytes, err := encodeDocument(document.document)
	if err != nil {
		return importCandidate{}, err
	}
	if err := s.validateCandidate(candidateBytes); err != nil {
		return importCandidate{}, err
	}
	view, err := document.view(revisionOf(candidateBytes))
	if err != nil {
		return importCandidate{}, err
	}
	return importCandidate{bytes: candidateBytes, added: added, view: view}, nil
}

func (s *Store) buildDeleteCandidate(raw []byte, name string) ([]byte, View, error) {
	document, err := parseConfigDocument(raw)
	if err != nil {
		return nil, View{}, err
	}
	if document.proxies == nil {
		return nil, View{}, fmt.Errorf("%w: static proxy %q was not found", ErrInvalidInput, name)
	}
	found := -1
	for index, item := range document.proxies.Content {
		currentName, err := proxyName(item, false)
		if err != nil {
			return nil, View{}, fmt.Errorf("static proxy %d: %w", index, err)
		}
		if currentName == name {
			found = index
			break
		}
	}
	if found < 0 {
		return nil, View{}, fmt.Errorf("%w: static proxy %q was not found", ErrInvalidInput, name)
	}
	document.proxies.Content = append(document.proxies.Content[:found], document.proxies.Content[found+1:]...)

	members, err := document.ensureProxiesMembers()
	if err != nil {
		return nil, View{}, err
	}
	kept := members.Content[:0]
	for index, item := range members.Content {
		member, err := scalarString(item, "Proxies member")
		if err != nil {
			return nil, View{}, fmt.Errorf("Proxies member %d: %w", index, err)
		}
		if member != name {
			kept = append(kept, item)
		}
	}
	members.Content = kept

	if reference := findUnvalidatedReference(document.root, name); reference != "" {
		return nil, View{}, fmt.Errorf("%w: static proxy %q is still referenced by %s", ErrInvalidInput, name, reference)
	}
	candidateBytes, err := encodeDocument(document.document)
	if err != nil {
		return nil, View{}, err
	}
	if err := s.validateCandidate(candidateBytes); err != nil {
		return nil, View{}, err
	}
	view, err := document.view(revisionOf(candidateBytes))
	if err != nil {
		return nil, View{}, err
	}
	return candidateBytes, view, nil
}

func (s *Store) validateCandidate(candidate []byte) error {
	C.SetHomeDir(s.dir)
	C.SetConfig(s.path)
	if _, err := executor.ParseWithBytes(candidate); err != nil {
		return fmt.Errorf("%w: candidate mihomo configuration is invalid", ErrInvalidInput)
	}
	return nil
}

func findUnvalidatedReference(root *yaml.Node, name string) string {
	var walk func(*yaml.Node, string) string
	walk = func(node *yaml.Node, path string) string {
		node = resolvedNode(node)
		if node == nil {
			return ""
		}
		switch node.Kind {
		case yaml.MappingNode:
			for index := 0; index+1 < len(node.Content); index += 2 {
				key := resolvedNode(node.Content[index])
				value := node.Content[index+1]
				keyName := key.Value
				childPath := keyName
				if path != "" {
					childPath = path + "." + keyName
				}
				if key.Kind == yaml.ScalarNode && (keyName == "dialer-proxy" || keyName == "proxy") {
					if target, err := scalarString(value, keyName); err == nil && target == name {
						return childPath
					}
				}
				if reference := walk(value, childPath); reference != "" {
					return reference
				}
			}
		case yaml.SequenceNode:
			for index, child := range node.Content {
				if reference := walk(child, fmt.Sprintf("%s[%d]", path, index)); reference != "" {
					return reference
				}
			}
		case yaml.ScalarNode:
			if strings.HasPrefix(path, "dns.") && dnsFragmentReferences(node.Value, name) {
				return path + " DNS proxy fragment"
			}
		}
		return ""
	}
	return walk(root, "")
}

func dnsFragmentReferences(value, name string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Fragment == "" {
		return false
	}
	for _, part := range strings.Split(parsed.Fragment, "&") {
		if !strings.Contains(part, "=") && part == name {
			return true
		}
	}
	return false
}

func validateExpectedRevision(revision string) error {
	if len(revision) != sha256.Size*2 {
		return fmt.Errorf("%w: revision must be a 64-character SHA-256", ErrInvalidInput)
	}
	if _, err := hex.DecodeString(revision); err != nil || strings.ToLower(revision) != revision {
		return fmt.Errorf("%w: revision must be lowercase hexadecimal", ErrInvalidInput)
	}
	return nil
}

func revisionOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func readRegularFile(path string) ([]byte, os.FileInfo, error) {
	if err := validateParentDirectory(filepath.Dir(path)); err != nil {
		return nil, nil, err
	}
	file, err := openReadNoFollow(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open config without following links: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("read config metadata: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("config must be a regular file and not a symlink")
	}
	if err := requireSingleLinkFile(file, info); err != nil {
		return nil, nil, err
	}
	raw, err := io.ReadAll(file)
	if err != nil {
		return nil, nil, fmt.Errorf("read config: %w", err)
	}
	if len(raw) == 0 {
		return nil, nil, errors.New("config is empty")
	}
	afterInfo, err := file.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("recheck config metadata: %w", err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(afterInfo, pathInfo) {
		return nil, nil, fmt.Errorf("config changed while it was read")
	}
	if err := requireSingleLinkFile(file, afterInfo); err != nil {
		return nil, nil, err
	}
	return raw, info, nil
}
