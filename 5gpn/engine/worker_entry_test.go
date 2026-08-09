package engine

import "testing"

func TestWorkerTestBinaryPath(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		path string
		want bool
	}{
		{path: "/tmp/engine.test", want: true},
		{path: `C:\\Temp\\engine.test.exe`, want: true},
		{path: "/opt/5gpn/bin/5gpn-mihomo", want: false},
		{path: `C:\\Temp\\engine.exe`, want: false},
	} {
		if got := isWorkerTestBinaryPath(test.path); got != test.want {
			t.Errorf("isWorkerTestBinaryPath(%q) = %v, want %v", test.path, got, test.want)
		}
	}
}
