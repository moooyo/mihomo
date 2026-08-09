//go:build linux

package engine

import (
	"bytes"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const workerSelfStatusPath = "/proc/self/status"

func dropWorkerPrivileges() error {
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("clear ambient capabilities: %w", err)
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	if err := unix.Capset(&header, &data[0]); err != nil {
		return fmt.Errorf("clear process capabilities: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	status, err := os.ReadFile(workerSelfStatusPath)
	if err != nil {
		return fmt.Errorf("read process capability status: %w", err)
	}
	return verifyWorkerCapabilityStatus(status)
}

func verifyWorkerCapabilityStatus(status []byte) error {
	wanted := map[string]bool{"CapInh": false, "CapPrm": false, "CapEff": false, "CapAmb": false}
	for _, line := range bytes.Split(status, []byte{'\n'}) {
		fields := bytes.Fields(line)
		if len(fields) != 2 {
			continue
		}
		key := string(bytes.TrimSuffix(fields[0], []byte{':'}))
		if _, exists := wanted[key]; !exists {
			continue
		}
		if wanted[key] {
			return fmt.Errorf("process status repeats %s", key)
		}
		wanted[key] = true
		if len(fields[1]) == 0 {
			return fmt.Errorf("process status has empty %s", key)
		}
		for _, digit := range fields[1] {
			if digit != '0' {
				return fmt.Errorf("process retained %s=%s", key, fields[1])
			}
		}
	}
	for key, seen := range wanted {
		if !seen {
			return fmt.Errorf("process status omits %s", key)
		}
	}
	return nil
}
