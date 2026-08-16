package engine

import (
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestCertificateRequestCallbackCoversRegistrationAndEveryDurableRewrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "intercept.json")
	if err := EnsureDocument(path); err != nil {
		t.Fatal(err)
	}
	store, err := newConfigStore(path)
	if err != nil {
		t.Fatal(err)
	}
	var wakes atomic.Int32
	store.setCertificateRequestReconcileCallback(func() { wakes.Add(1) })
	if got := wakes.Load(); got != 1 {
		t.Fatalf("registration wakes = %d, want 1 for the startup request", got)
	}

	cfg, err := store.Current()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.publishCertificateRequest(cfg); err != nil {
		t.Fatal(err)
	}
	request, err := readCertificateRequest(certificateRequestPath(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.writeCertificateRequest(request); err != nil {
		t.Fatal(err)
	}
	if got := wakes.Load(); got != 3 {
		t.Fatalf("callback wakes = %d, want registration plus two durable publications", got)
	}
}

func TestCertificateRequestCallbackDoesNotRunAfterFailedWrite(t *testing.T) {
	store := &configStore{path: filepath.Join(t.TempDir(), "missing", "intercept.json")}
	var wakes atomic.Int32
	store.setCertificateRequestReconcileCallback(func() { wakes.Add(1) })
	baseline := wakes.Load()
	request := desiredCertificateRequest(DefaultDocument(), "00000000000000000000000000000000")
	if err := store.writeCertificateRequest(request); err == nil {
		t.Fatal("certificate request write unexpectedly succeeded")
	}
	if got := wakes.Load(); got != baseline {
		t.Fatalf("failed write advanced callback count from %d to %d", baseline, got)
	}
}
