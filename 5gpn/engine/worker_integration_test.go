//go:build linux || windows

package engine

import "testing"

func TestWorkerControllerProbe(t *testing.T) {
	controller, err := newWorkerController()
	if err != nil {
		t.Fatalf("worker probe: %v", err)
	}
	t.Cleanup(func() {
		if err := controller.Close(); err != nil {
			t.Errorf("close worker controller: %v", err)
		}
	})
}
