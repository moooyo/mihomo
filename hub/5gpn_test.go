package hub

import (
	"errors"
	"testing"
	"time"
)

func TestFatalReportQueuesOrderlyExitAndArmsHardExitFallback(t *testing.T) {
	for {
		select {
		case <-fivegpnFatalEvents:
		default:
			goto drained
		}
	}

drained:
	previous := fivegpnHardExit
	fallback := make(chan struct{})
	fivegpnHardExit = func() { close(fallback) }
	fivegpnExitWatchdog.Store(false)
	fivegpnExitSeverity.Store(fivegpnExitNone)
	t.Cleanup(func() {
		fivegpnHardExit = previous
		fivegpnExitWatchdog.Store(false)
		fivegpnExitSeverity.Store(fivegpnExitNone)
		select {
		case <-fivegpnFatalEvents:
		default:
		}
	})

	want := errors.New("critical listener ended")
	reportFiveGPNFatal(want)
	select {
	case got := <-fivegpnFatalEvents:
		if !errors.Is(got, want) {
			t.Fatalf("fatal event = %v, want %v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("fatal event was not queued")
	}
	select {
	case <-fallback:
	case <-time.After(time.Second):
		t.Fatal("fatal hard-exit fallback was not armed")
	}
}

func TestRestartReportQueuesOrderlyExitAndArmsHardExitFallback(t *testing.T) {
	for {
		select {
		case <-fivegpnRestartEvents:
		default:
			goto drained
		}
	}

drained:
	previous := fivegpnHardExit
	fallback := make(chan struct{})
	fivegpnHardExit = func() { close(fallback) }
	fivegpnExitWatchdog.Store(false)
	fivegpnExitSeverity.Store(fivegpnExitNone)
	t.Cleanup(func() {
		fivegpnHardExit = previous
		fivegpnExitWatchdog.Store(false)
		fivegpnExitSeverity.Store(fivegpnExitNone)
		select {
		case <-fivegpnRestartEvents:
		default:
		}
	})

	reportFiveGPNRestart()
	select {
	case <-fivegpnRestartEvents:
	case <-time.After(time.Second):
		t.Fatal("restart event was not queued")
	}
	select {
	case <-fallback:
	case <-time.After(time.Second):
		t.Fatal("restart hard-exit fallback was not armed")
	}
}

func TestFatalSeverityUpgradesAnExistingRestartWatchdog(t *testing.T) {
	for {
		select {
		case <-fivegpnFatalEvents:
		case <-fivegpnRestartEvents:
		default:
			goto drained
		}
	}

drained:
	previous := fivegpnHardExit
	release := make(chan struct{})
	severity := make(chan int32, 1)
	fivegpnHardExit = func() {
		<-release
		severity <- fivegpnExitSeverity.Load()
	}
	fivegpnExitWatchdog.Store(false)
	fivegpnExitSeverity.Store(fivegpnExitNone)
	t.Cleanup(func() {
		fivegpnHardExit = previous
		fivegpnExitWatchdog.Store(false)
		fivegpnExitSeverity.Store(fivegpnExitNone)
		select {
		case <-fivegpnFatalEvents:
		default:
		}
		select {
		case <-fivegpnRestartEvents:
		default:
		}
	})

	reportFiveGPNRestart()
	reportFiveGPNFatal(errors.New("fatal after restart"))
	close(release)
	select {
	case got := <-severity:
		if got != fivegpnExitFatal || !FiveGPNFatalPending() {
			t.Fatalf("exit severity = %d, fatal pending=%v", got, FiveGPNFatalPending())
		}
	case <-time.After(time.Second):
		t.Fatal("shared exit watchdog did not observe upgraded fatal severity")
	}
}
