package fivegpn

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"sync/atomic"
)

const runtimeEnvironment = "FIVEGPN_RUNTIME"

const (
	containerContractCommand = "5gpn-container-contract"
	containerContractVersion = "5gpn-container-runtime-v1"
)

type deploymentRuntime uint32

const (
	deploymentRuntimeHost deploymentRuntime = iota
	deploymentRuntimeContainer
)

var activeDeploymentRuntime atomic.Uint32

func configureDeploymentRuntime() error {
	mode, err := deploymentRuntimeFromEnvironment(os.LookupEnv, runtime.GOOS)
	if err != nil {
		return err
	}
	activeDeploymentRuntime.Store(uint32(mode))
	return nil
}

func deploymentRuntimeFromEnvironment(lookup func(string) (string, bool), goos string) (deploymentRuntime, error) {
	value, present := lookup(runtimeEnvironment)
	if !present || value == "" {
		return deploymentRuntimeHost, nil
	}
	if value != "container" {
		return deploymentRuntimeHost, fmt.Errorf("5gpn: %s must be unset or exactly %q", runtimeEnvironment, "container")
	}
	if goos != "linux" {
		return deploymentRuntimeHost, fmt.Errorf("5gpn: %s=container requires Linux", runtimeEnvironment)
	}
	return deploymentRuntimeContainer, nil
}

// ContainerMode selects the trusted in-process Docker certificate integration.
// Extension workers retain the same mandatory hard-isolation implementation
// and startup probe in every mode; process replacement stays external in both.
func ContainerMode() bool {
	return deploymentRuntime(activeDeploymentRuntime.Load()) == deploymentRuntimeContainer
}

// ContainerContractCommand is the offline CLI used by image assembly to prove
// that a pinned immutable mihomo artifact contains this container lifecycle.
func ContainerContractCommand() string { return containerContractCommand }

// ContainerContractMain prints the exact compile-time contract marker without
// opening state, constructing worker isolation, or touching cgroups.
func ContainerContractMain(args []string, output io.Writer) int {
	if len(args) != 0 || output == nil {
		return 2
	}
	if _, err := fmt.Fprintln(output, containerContractVersion); err != nil {
		return 1
	}
	return 0
}
