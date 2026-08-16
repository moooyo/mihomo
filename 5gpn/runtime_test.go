package fivegpn

import (
	"bytes"
	"testing"
)

func TestDeploymentRuntimeFromEnvironment(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		present bool
		goos    string
		want    deploymentRuntime
		wantErr bool
	}{
		{name: "unset host", goos: "linux", want: deploymentRuntimeHost},
		{name: "empty host", value: "", present: true, goos: "linux", want: deploymentRuntimeHost},
		{name: "exact container", value: "container", present: true, goos: "linux", want: deploymentRuntimeContainer},
		{name: "typo rejected", value: "docker", present: true, goos: "linux", wantErr: true},
		{name: "whitespace rejected", value: " container ", present: true, goos: "linux", wantErr: true},
		{name: "non linux rejected", value: "container", present: true, goos: "darwin", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := deploymentRuntimeFromEnvironment(func(string) (string, bool) {
				return test.value, test.present
			}, test.goos)
			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, test.wantErr)
			}
			if !test.wantErr && got != test.want {
				t.Fatalf("mode = %v, want %v", got, test.want)
			}
		})
	}
}

func TestContainerContractMainIsExactAndOffline(t *testing.T) {
	var output bytes.Buffer
	if code := ContainerContractMain(nil, &output); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if got, want := output.String(), "5gpn-container-runtime-v1\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
	output.Reset()
	if code := ContainerContractMain([]string{"unexpected"}, &output); code != 2 {
		t.Fatalf("argument error exit code = %d, want 2", code)
	}
	if output.Len() != 0 {
		t.Fatalf("argument error wrote %q", output.String())
	}
}
