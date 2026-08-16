package main

import (
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestInitRegistersButDoesNotParseFlags(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	initStart := strings.Index(source, "func init()")
	mainStart := strings.Index(source, "func main()")
	if initStart < 0 || mainStart < 0 || initStart >= mainStart {
		t.Fatal("could not locate init/main boundaries")
	}
	if strings.Contains(source[initStart:mainStart], "flag.Parse()") {
		t.Fatal("init parses flags before testing registers -test.* flags")
	}
	dispatch := strings.Index(source, "os.Args[1] == fivegpn.ContainerContractCommand()")
	parse := strings.Index(source, "flag.Parse()")
	if dispatch < 0 || parse < 0 || dispatch > parse {
		t.Fatal("one-shot container contract no longer dispatches before ordinary flag parsing")
	}
}

func TestRunDispatchesContainerContractBeforeRuntimeStartup(t *testing.T) {
	previousArgs, previousStdout := os.Args, os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"5gpn-mihomo", "5gpn-container-contract"}
	os.Stdout = writer
	code := run()
	_ = writer.Close()
	os.Args, os.Stdout = previousArgs, previousStdout
	body, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 || string(body) != "5gpn-container-runtime-v1\n" {
		t.Fatalf("contract exit/output = %d/%q", code, body)
	}
}

func TestWaitForRuntimeExitReturnsFatalToOrderlyOwner(t *testing.T) {
	term := make(chan struct{})
	hup := make(chan os.Signal)
	fatal := make(chan error, 1)
	restart := make(chan struct{})
	want := errors.New("listener ended")
	fatal <- want
	got := waitForRuntimeExit(term, hup, fatal, restart, nil)
	if !errors.Is(got.fatal, want) || got.restart {
		t.Fatalf("exit = %+v, want fatal %v", got, want)
	}
	if code := runtimeExitCode(got); code == 0 {
		t.Fatal("fatal runtime exit returned success")
	}
}

func TestPollRuntimeExitPreservesQueuedStartupSignalAndFatalPriority(t *testing.T) {
	term := make(chan struct{}, 1)
	fatal := make(chan error, 1)
	restart := make(chan struct{}, 1)
	term <- struct{}{}
	restart <- struct{}{}
	want := errors.New("startup listener failed")
	fatal <- want
	got, ready := pollRuntimeExit(term, fatal, restart)
	if !ready || !errors.Is(got.fatal, want) {
		t.Fatalf("poll exit = %+v ready=%v, want fatal %v", got, ready, want)
	}
}

func TestWaitForRuntimeExitSeparatesContainerRestartAndReload(t *testing.T) {
	term := make(chan struct{})
	hup := make(chan os.Signal)
	fatal := make(chan error)
	restart := make(chan struct{}, 1)
	restart <- struct{}{}
	got := waitForRuntimeExit(term, hup, fatal, restart, nil)
	if !got.restart || got.fatal != nil {
		t.Fatalf("exit = %+v, want container restart", got)
	}

	term = make(chan struct{}, 1)
	hup = make(chan os.Signal, 1)
	restart = make(chan struct{})
	reloaded := make(chan struct{}, 1)
	exited := make(chan runtimeExit, 1)
	go func() {
		exited <- waitForRuntimeExit(term, hup, fatal, restart, func() { reloaded <- struct{}{} })
	}()
	hup <- syscall.SIGHUP
	<-reloaded
	term <- struct{}{}
	if got := <-exited; got.restart || got.fatal != nil {
		t.Fatalf("signal exit after reload = %+v", got)
	}
}

func TestRelayRuntimeTerminationArmsWatchdogBeforeQueuingExit(t *testing.T) {
	source := make(chan os.Signal, 1)
	target := make(chan struct{})
	stop := make(chan struct{})
	armed := make(chan struct{}, 1)
	go relayRuntimeTermination(source, target, stop, func() { armed <- struct{}{} })

	source <- syscall.SIGTERM
	select {
	case <-armed:
	case <-time.After(time.Second):
		t.Fatal("termination relay did not arm the hard-exit watchdog")
	}
	select {
	case <-target:
	case <-time.After(time.Second):
		t.Fatal("termination relay did not queue the orderly exit")
	}
	close(stop)
}

func TestFinishRuntimeExitShutsDownBeforePostDown(t *testing.T) {
	order := make([]string, 0, 2)
	finishRuntimeExit(
		func() { order = append(order, "shutdown") },
		func() { order = append(order, "post-down") },
	)
	if got := strings.Join(order, ","); got != "shutdown,post-down" {
		t.Fatalf("exit order = %q, want shutdown before post-down", got)
	}
}
