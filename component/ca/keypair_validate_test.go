package ca

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func TestValidateTLSKeyPairLoadsFilesWithoutStartingAReloadLoop(t *testing.T) {
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

	previousReloadLoader := newTLSKeyPairReloadLoader
	reloadLoaderCalls := 0
	newTLSKeyPairReloadLoader = func(string, string, time.Duration, func() time.Time) (*tlsKeyPairFileLoader, error) {
		reloadLoaderCalls++
		return nil, errors.New("reload loop must not start during validation")
	}
	t.Cleanup(func() { newTLSKeyPairReloadLoader = previousReloadLoader })

	for range 3 {
		if err := ValidateTLSKeyPair("cert.pem", "key.pem"); err != nil {
			t.Fatalf("valid file-backed key pair failed validation: %v", err)
		}
	}
	if reloadLoaderCalls != 0 {
		t.Fatalf("validation started %d reload loops", reloadLoaderCalls)
	}

	if err := os.WriteFile(filepath.Join(home, "key.pem"), []byte(otherPrivateKey), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTLSKeyPair("cert.pem", "key.pem"); err == nil {
		t.Fatal("mismatched file-backed key pair was accepted")
	}
	if reloadLoaderCalls != 0 {
		t.Fatalf("failed validation started %d reload loops", reloadLoaderCalls)
	}
}
