package ca

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/fswatch"
)

func TestValidateTLSKeyPairLoadsFilesWithoutStartingAWatcher(t *testing.T) {
	home := t.TempDir()
	previousHome := C.Path.HomeDir()
	C.SetHomeDir(home)
	t.Cleanup(func() { C.SetHomeDir(previousHome) })

	certificate, privateKey, _, err := NewRandomTLSKeyPair(KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPrivateKey, _, err := NewRandomTLSKeyPair(KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "cert.pem"), []byte(certificate), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "key.pem"), []byte(privateKey), 0o600); err != nil {
		t.Fatal(err)
	}

	previousWatcher := newTLSKeyPairWatcher
	watcherCalls := 0
	newTLSKeyPairWatcher = func(fswatch.Options) (*fswatch.Watcher, error) {
		watcherCalls++
		return nil, errors.New("watcher must not start during validation")
	}
	t.Cleanup(func() { newTLSKeyPairWatcher = previousWatcher })

	for range 3 {
		if err := ValidateTLSKeyPair("cert.pem", "key.pem"); err != nil {
			t.Fatalf("valid file-backed key pair failed validation: %v", err)
		}
	}
	if watcherCalls != 0 {
		t.Fatalf("validation started %d filesystem watchers", watcherCalls)
	}

	if err := os.WriteFile(filepath.Join(home, "key.pem"), []byte(otherPrivateKey), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTLSKeyPair("cert.pem", "key.pem"); err == nil {
		t.Fatal("mismatched file-backed key pair was accepted")
	}
	if watcherCalls != 0 {
		t.Fatalf("failed validation started %d filesystem watchers", watcherCalls)
	}
}
