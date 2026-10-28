package shapetest

import (
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// A real SIGTERM, against fakes: the kill functions run, last registered first, then exit(2).
func TestGuardRunsTheKillFunctionsOnSIGTERM(t *testing.T) {
	exit := make(chan int, 1)
	var mu sync.Mutex
	var order []string
	g := NewGuard(t, func(c int) { exit <- c }, time.Time{}, time.Second)
	g.OnKill(func() { mu.Lock(); order = append(order, "cluster"); mu.Unlock() })
	g.OnKill(func() { mu.Lock(); order = append(order, "port49d"); mu.Unlock() })
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-exit:
		if c != 2 {
			t.Errorf("exit %d, want 2", c)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SIGTERM did not reach the guard")
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(order, ",") != "port49d,cluster" {
		t.Errorf("kill order %v, want port49d then cluster", order)
	}
}

func TestGuardRunsTheKillFunctionsBeforeTheDeadline(t *testing.T) {
	exit := make(chan int, 1)
	ran := make(chan struct{}, 1)
	g := NewGuard(t, func(c int) { exit <- c }, time.Now().Add(400*time.Millisecond), 300*time.Millisecond)
	g.OnKill(func() { ran <- struct{}{} })
	select {
	case <-exit:
	case <-time.After(5 * time.Second):
		t.Fatal("the guard did not fire ahead of the deadline")
	}
	select {
	case <-ran:
	default:
		t.Error("exit came without the kill function")
	}
}

func TestGuardIsQuietWhenTheTestEndsNormally(t *testing.T) {
	exit := make(chan int, 1)
	t.Run("sub", func(t *testing.T) { NewGuard(t, func(c int) { exit <- c }, time.Now().Add(time.Hour), time.Second) })
	time.Sleep(100 * time.Millisecond)
	select {
	case <-exit:
		t.Error("a guard of a finished test exited")
	default:
	}
}

func TestProcessIsKilledByPidUntilItIsReaped(t *testing.T) {
	var mu sync.Mutex
	var killed []int
	defer func(f func(int)) { killPID = f }(killPID)
	killPID = func(pid int) { mu.Lock(); killed = append(killed, pid); mu.Unlock() }
	run := func() (*exec.Cmd, *Guard) {
		cmd := exec.Command("sleep", "60")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		return cmd, &Guard{}
	}
	live, g := run()
	g.Process(live)
	reapedCmd, g2 := run()
	reaped := g2.Process(reapedCmd)
	_ = reapedCmd.Process.Kill()
	_ = reapedCmd.Wait()
	reaped() // Wait returned: its pid may now belong to someone else
	for _, c := range []*exec.Cmd{live, reapedCmd} {
		defer c.Process.Kill()
	}
	for _, gg := range []*Guard{g, g2} {
		for _, f := range gg.kill {
			f()
		}
	}
	if len(killed) != 1 || killed[0] != live.Process.Pid {
		t.Errorf("signalled %v, want only the live process %d", killed, live.Process.Pid)
	}
}
