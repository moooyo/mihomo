//go:build linux

package fivegpn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const certificateHelperTerminationGrace = 10 * time.Second
const certificateHelperKillGrace = 5 * time.Second
const certificateHelperGroupPollInterval = 10 * time.Millisecond

var errCertificateHelperDescendants = errors.New("certificate helper left processes in its process group")

type processCertificateHelperRunner struct {
	terminationGrace time.Duration
	killGrace        time.Duration
}

func (r processCertificateHelperRunner) Run(ctx context.Context, spec certificateHelperSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cmd := exec.Command(spec.Path, spec.Args...)
	cmd.Env = append([]string(nil), spec.Environment...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s helper: %w", spec.Name, err)
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	select {
	case waitErr := <-waited:
		return r.finishProcessGroup(cmd.Process.Pid, waited, true, waitErr, ctx.Err())
	case <-ctx.Done():
		return r.finishProcessGroup(cmd.Process.Pid, waited, false, nil, ctx.Err())
	}
}

func (r processCertificateHelperRunner) finishProcessGroup(
	pgid int,
	waited <-chan error,
	directDone bool,
	directErr error,
	cause error,
) error {
	grace := r.terminationGrace
	if grace <= 0 {
		grace = certificateHelperTerminationGrace
	}
	var cleanupErr error
	var descendantsErr error
	if directDone {
		empty, err := certificateHelperGroupEmpty(pgid)
		cleanupErr = errors.Join(cleanupErr, err)
		if empty {
			return errors.Join(cause, directErr, certificateHelperCleanupFailure(cleanupErr))
		}
		descendantsErr = errCertificateHelperDescendants
	}

	termErr := signalCertificateHelperGroup(pgid, syscall.SIGTERM)
	timer := time.NewTimer(grace)
	defer timer.Stop()
	poll := time.NewTicker(certificateHelperGroupPollInterval)
	defer poll.Stop()
	for {
		if directDone {
			empty, err := certificateHelperGroupEmpty(pgid)
			cleanupErr = errors.Join(cleanupErr, err)
			if empty {
				return errors.Join(cause, directErr, descendantsErr,
					certificateHelperCleanupFailure(termErr, cleanupErr))
			}
		}
		select {
		case waitErr := <-waited:
			if !directDone {
				directDone = true
				directErr = waitErr
			}
		case <-poll.C:
		case <-timer.C:
			goto forceKill
		}
	}

forceKill:
	killErr := signalCertificateHelperGroup(pgid, syscall.SIGKILL)
	killGrace := r.killGrace
	if killGrace <= 0 {
		killGrace = certificateHelperKillGrace
	}
	killTimer := time.NewTimer(killGrace)
	defer killTimer.Stop()
	for {
		if directDone {
			empty, err := certificateHelperGroupEmpty(pgid)
			cleanupErr = errors.Join(cleanupErr, err)
			if empty {
				return errors.Join(cause, directErr, descendantsErr,
					certificateHelperCleanupFailure(termErr, killErr, cleanupErr))
			}
		}
		select {
		case waitErr := <-waited:
			if !directDone {
				directDone = true
				directErr = waitErr
			}
		case <-poll.C:
		case <-killTimer.C:
			return errors.Join(cause, directErr, descendantsErr,
				certificateHelperCleanupFailure(termErr, killErr, cleanupErr),
				errCertificateHelperGroupStuck)
		}
	}
}

func certificateHelperCleanupFailure(errs ...error) error {
	err := errors.Join(errs...)
	if err == nil {
		return nil
	}
	return errors.Join(errCertificateHelperCleanup, err)
}

func signalCertificateHelperGroup(pid int, signal syscall.Signal) error {
	if err := syscall.Kill(-pid, signal); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("signal certificate helper process group %d with %v: %w", pid, signal, err)
	}
	return nil
}

// certificateHelperGroupEmpty reaps only children in this helper's process
// group. In a container the monolith is PID 1, so grandchildren orphaned by a
// shell leader are adopted here; wait4(-pgid) collects those zombies without
// touching extension workers, which are born in different process groups.
func certificateHelperGroupEmpty(pgid int) (bool, error) {
	reapErr := reapCertificateHelperGroup(pgid)
	err := syscall.Kill(-pgid, 0)
	switch {
	case err == nil, errors.Is(err, syscall.EPERM):
		return false, reapErr
	case errors.Is(err, syscall.ESRCH):
		return true, reapErr
	default:
		return false, errors.Join(reapErr, fmt.Errorf("inspect certificate helper process group %d: %w", pgid, err))
	}
}

func reapCertificateHelperGroup(pgid int) error {
	for {
		var status syscall.WaitStatus
		pid, err := syscall.Wait4(-pgid, &status, syscall.WNOHANG, nil)
		switch {
		case pid > 0:
			continue
		case err == nil && pid == 0:
			return nil
		case errors.Is(err, syscall.ECHILD):
			return nil
		case errors.Is(err, syscall.EINTR):
			continue
		default:
			return fmt.Errorf("reap certificate helper process group %d: %w", pgid, err)
		}
	}
}
