//go:build !windows

package statevalidator

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/metacubex/mihomo/5gpn/bot"
	"github.com/metacubex/mihomo/5gpn/dns"
	"github.com/metacubex/mihomo/5gpn/engine"
)

func TestValidateRejectsSymlinkedStateDocument(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	targetDir := filepath.Join(root, "target")
	if err := os.Mkdir(targetDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeDocument(t, targetDir, dnsDocumentName, installedDNSDocument())
	if err := os.Symlink(filepath.Join(targetDir, dnsDocumentName), filepath.Join(dir, dnsDocumentName)); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(dir); err == nil {
		t.Fatal("Validate() accepted a symlinked state document")
	}
}

func TestValidateRejectsSymlinkedStateDirectory(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "state")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(link); err == nil {
		t.Fatal("Validate() accepted a symlinked state directory")
	}
}

func TestValidateRejectsSymlinkedStateDirectoryAncestor(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	dir := filepath.Join(target, "state")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeDocument(t, dir, dnsDocumentName, installedDNSDocument())
	ancestor := filepath.Join(root, "ancestor")
	if err := os.Symlink(target, ancestor); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(filepath.Join(ancestor, "state")); err == nil {
		t.Fatal("Validate() accepted a symlinked state-directory ancestor")
	}
}

func TestValidateRejectsHardLinkedStateDocument(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	targetDir := filepath.Join(root, "target")
	if err := os.Mkdir(targetDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeDocument(t, targetDir, dnsDocumentName, installedDNSDocument())
	if err := os.Link(filepath.Join(targetDir, dnsDocumentName), filepath.Join(dir, dnsDocumentName)); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(dir); err == nil {
		t.Fatal("Validate() accepted a hard-linked state document")
	}
}

func TestValidateRejectsUnsafeStateDocumentPermissions(t *testing.T) {
	dir := t.TempDir()
	writeDocument(t, dir, dnsDocumentName, installedDNSDocument())
	if err := os.Chmod(filepath.Join(dir, dnsDocumentName), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateForOwner(dir, os.Geteuid()); err == nil {
		t.Fatal("ValidateForOwner() accepted a state document that was not mode 0600")
	}
}

func TestValidateForOwnerRequiresTheNamedOwner(t *testing.T) {
	dir := t.TempDir()
	writeDocument(t, dir, dnsDocumentName, installedDNSDocument())
	uid := os.Geteuid()
	result, err := ValidateForOwner(dir, uid)
	if err != nil {
		t.Fatalf("ValidateForOwner() rejected the current owner: %v", err)
	}
	if want := []string{dnsDocumentName}; !reflect.DeepEqual(result.Validated, want) {
		t.Fatalf("validated = %v, want %v", result.Validated, want)
	}
	if _, err := ValidateForOwner(dir, uid+1); err == nil {
		t.Fatal("ValidateForOwner() accepted a file owned by a different UID")
	}
}

func TestRootValidateForOwnerAcceptsOnlyOneExplicitServiceOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-only ownership override")
	}
	const serviceUID = 65534
	dir := t.TempDir()
	writeDocument(t, dir, dnsDocumentName, installedDNSDocument())
	writeDocument(t, dir, interceptDocumentName, engine.DefaultDocument())
	writeDocument(t, dir, botDocumentName, bot.DefaultDocument())
	for _, name := range []string{dnsDocumentName, interceptDocumentName} {
		if err := os.Chown(filepath.Join(dir, name), serviceUID, serviceUID); err != nil {
			t.Skipf("cannot create cross-owner fixture: %v", err)
		}
	}
	if _, err := ValidateForOwner(dir, serviceUID); err == nil {
		t.Fatal("root accepted mixed-owner state documents")
	}
	if err := os.Chown(filepath.Join(dir, botDocumentName), serviceUID, serviceUID); err != nil {
		t.Skipf("cannot complete cross-owner fixture: %v", err)
	}
	result, err := ValidateForOwner(dir, serviceUID)
	if err != nil {
		t.Fatalf("root could not validate service-owned state: %v", err)
	}
	want := []string{dnsDocumentName, interceptDocumentName, botDocumentName}
	if !reflect.DeepEqual(result.Validated, want) {
		t.Fatalf("validated = %v, want %v", result.Validated, want)
	}
	if _, err := Validate(dir); err == nil {
		t.Fatal("root bypassed the ordinary current-owner contract")
	}
}

func TestRunAcceptsExplicitOwnerUID(t *testing.T) {
	dir := t.TempDir()
	writeDocument(t, dir, dnsDocumentName, installedDNSDocument())
	var output bytes.Buffer
	args := []string{"validate", "--owner-uid", strconv.Itoa(os.Geteuid()), dir}
	if code := Run(args, &output); code != 0 {
		t.Fatalf("Run() code = %d, output = %s", code, output.String())
	}
}
