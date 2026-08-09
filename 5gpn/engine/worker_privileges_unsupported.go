//go:build !linux && !windows

package engine

// Unsupported production platforms fail before accepting a gate. A linked Go
// test binary may run trusted fixtures in the separate-process test harness;
// that does not make the platform a supported runtime boundary.
func dropWorkerPrivileges() error {
	if isWorkerTestBinaryEarly() {
		return nil
	}
	return ErrHardIsolationUnavailable
}
