//go:build !windows

package main

import (
	"bufio"
	"bytes"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

func waitForSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	os.Stdout.WriteString("ready\n")
	select {
	case <-sigs:
		os.Exit(42)
	case <-time.After(10 * time.Second):
		os.Exit(5)
	}
}

func TestRunForwardsSignals(t *testing.T) {
	dir := newTestVaultDir(t)
	argv := append([]string{"run", "-d", dir, "--"}, helperArgv(t, "wait-signal")...)

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	done := make(chan int, 1)
	go func() {
		var stderr bytes.Buffer
		done <- run(argv, bytes.NewReader(nil), pw, &stderr)
		pw.Close()
	}()

	// Once the child is ready, hal-vault's own handler is installed:
	// signal ourselves and expect the child to receive it.
	line, err := bufio.NewReader(pr).ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatalf("child did not start: %q, %v", line, err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 42 {
			t.Errorf("exit code = %d, want 42 (child saw the forwarded signal)", code)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run did not return after the signal")
	}
}
