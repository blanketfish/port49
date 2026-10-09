package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const subreaperEnv = "PORT49_TEST_SUBREAPER"

func init() { subreaperHook = subreaperMain }

// subreaperMain is a process that adopts orphans, as a systemd --user manager
// or a container init does. It runs a stand-in for ssh that starts the askpass
// and exits at once, so the askpass is reparented to it, then reports whether
// it was signalled.
func subreaperMain() {
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		fmt.Println("prctl:", err)
		os.Exit(2)
	}
	os.Unsetenv(subreaperEnv)
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT)
	exe, _ := os.Executable()
	ssh := exec.Command("sh", "-c", `"$0" "alice@leaf1's password: " & sleep 0.5; exit 255`, exe)
	ssh.Env = os.Environ()
	if err := ssh.Run(); err == nil {
		fmt.Println("the stand-in ssh did not exit 255")
		os.Exit(2)
	}
	select {
	case s := <-sigs:
		fmt.Println("signalled:", s)
	case <-time.After(3 * time.Second):
		fmt.Println("not signalled")
	}
	os.Exit(0)
}

// An askpass whose ssh has gone is not to signal whoever adopted it: only the
// process that was its parent when it started, as pidfd_open gave it (task 6
// re-review N-2).
func TestAnOrphanedAskpassDoesNotSignalItsAdopter(t *testing.T) {
	dir, err := os.MkdirTemp("", "p49s")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	// A port49 ssh that takes the prompt and goes away: the askpass reads EOF.
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = bufio.NewReader(c).ReadString('\n')
		time.Sleep(time.Second)
		c.Close()
	}()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), subreaperEnv+"=1", "SSH_ASKPASS_REQUIRE=force", askpassEnv+"="+sock)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("the subreaper: %v: %s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "not signalled" {
		t.Fatalf("the process that adopted the askpass: %s", got)
	}
}
