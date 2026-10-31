package shapetest

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"testing"
	"time"
)

// KillGrace is how long before the test binary's own deadline the guard cleans up and exits.
var KillGrace = 45 * time.Second

// Guard makes a killed run clean up what t.Cleanup would. Go's testing package runs no t.Cleanup on
// a signal or on its -timeout panic, so a Ctrl-C, a SIGTERM or a deadline a grace period away runs
// every OnKill function, last registered first, then calls exit(2). It is dropped when the test
// ends normally.
type Guard struct {
	mu   sync.Mutex
	kill []func()
}

// OnKill registers a function the guard runs when the run is killed: stopping a process by its
// recorded pid, deleting a cluster, removing a container by its recorded ID.
func (g *Guard) OnKill(f func()) {
	g.mu.Lock()
	g.kill = append(g.kill, f)
	g.mu.Unlock()
}

// NewGuard starts the guard. A zero deadline arms no timer.
func NewGuard(t *testing.T, exit func(int), deadline time.Time, grace time.Duration) *Guard {
	t.Helper()
	g := &Guard{}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{})
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		tm := time.NewTimer(time.Until(deadline) - grace)
		timeout = tm.C
		t.Cleanup(func() { tm.Stop() })
	}
	t.Cleanup(func() { signal.Stop(sig); close(done) })
	go func() {
		var why string
		select {
		case s := <-sig:
			why = "got " + s.String()
		case <-timeout:
			why = "the test's own deadline is " + grace.String() + " away"
		case <-done:
			return
		}
		fmt.Fprintf(os.Stderr, "\n  smoke guard: %s; cleaning up what the run started, then exiting\n", why)
		g.mu.Lock()
		kill := append([]func(){}, g.kill...)
		g.mu.Unlock()
		for i := len(kill) - 1; i >= 0; i-- {
			kill[i]()
		}
		exit(2)
	}()
	return g
}

// killPID is syscall.Kill, a variable so a test can see which pids a guard signals.
var killPID = func(pid int) { _ = syscall.Kill(pid, syscall.SIGKILL) }

// Process registers a started command: a killed run kills it by its recorded pid, never by name. The
// returned func is called right after cmd.Wait returns; from then on the kill does nothing, because
// the pid is free to be reused and a later signal could hit an unrelated process.
func (g *Guard) Process(cmd *exec.Cmd) (reaped func()) {
	pid := cmd.Process.Pid
	var mu sync.Mutex
	done := false
	g.OnKill(func() {
		mu.Lock()
		defer mu.Unlock()
		if !done {
			killPID(pid)
		}
	})
	return func() { mu.Lock(); done = true; mu.Unlock() }
}
