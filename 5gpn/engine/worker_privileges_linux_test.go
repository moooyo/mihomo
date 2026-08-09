//go:build linux

package engine

import "testing"

func TestVerifyWorkerCapabilityStatus(t *testing.T) {
	zero := []byte("CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\n")
	if err := verifyWorkerCapabilityStatus(zero); err != nil {
		t.Fatalf("zero capabilities rejected: %v", err)
	}
	retained := []byte("CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000400\nCapAmb:\t0000000000000000\n")
	if err := verifyWorkerCapabilityStatus(retained); err == nil {
		t.Fatal("retained effective capability accepted")
	}
}
