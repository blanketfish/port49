package main

import (
	"errors"
	"os"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The askpass path names this process by the pid /proc itself reports, so a
// /proc of another PID namespace cannot send ssh to another process's image
// (final review M-5).
func TestAskpassPathTakesThePidFromProcSelf(t *testing.T) {
	if got, want := askpassPath(""), "/proc/"+strconv.Itoa(os.Getpid())+"/exe"; got != want {
		t.Errorf("askpassPath() = %q, want %q", got, want)
	}
	for _, c := range []struct {
		link string
		err  error
		want string
	}{
		{"4242", nil, "/proc/4242/exe"},
		{"", errors.New("no /proc"), "/proc/self/exe"},
		{"not-a-pid", nil, "/proc/self/exe"},
		{"-5", nil, "/proc/self/exe"},
	} {
		if got := procExe(func(string) (string, error) { return c.link, c.err }); got != c.want {
			t.Errorf("readlink %q, %v: %q, want %q", c.link, c.err, got, c.want)
		}
	}
}

// A pidfd that cannot send for any reason but the parent being gone falls back
// to kill(2), behind the same Getppid check, so a seccomp profile that allows
// pidfd_open but not the send cannot leave ssh running to send an empty
// password (final review P11).
func TestTerminateFallsBackToKillWhenThePidfdCannotSend(t *testing.T) {
	prevSend, prevKill := pidfdSend, killProcess
	t.Cleanup(func() { pidfdSend, killProcess = prevSend, prevKill })
	var killed []int
	killProcess = func(pid int, sig syscall.Signal) error {
		killed = append(killed, pid)
		return nil
	}
	fd := func() int {
		fd, err := unix.Open("/dev/null", unix.O_RDONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		return fd
	}

	pidfdSend = func(int, unix.Signal) error { return unix.EPERM }
	sshParent{pid: os.Getppid(), fd: fd()}.terminate()
	if len(killed) != 1 || killed[0] != os.Getppid() {
		t.Fatalf("an EPERM send: kill called for %v", killed)
	}

	killed = nil
	pidfdSend = func(int, unix.Signal) error { return unix.ESRCH }
	sshParent{pid: os.Getppid(), fd: fd()}.terminate()
	if len(killed) != 0 {
		t.Fatalf("a parent already gone: kill called for %v", killed)
	}

	killed = nil
	pidfdSend = func(int, unix.Signal) error { return nil }
	sshParent{pid: os.Getppid(), fd: fd()}.terminate()
	if len(killed) != 0 {
		t.Fatalf("a send that worked: kill called for %v", killed)
	}

	killed = nil
	pidfdSend = func(int, unix.Signal) error { return unix.EPERM }
	sshParent{pid: os.Getppid() + 1, fd: fd()}.terminate()
	if len(killed) != 0 {
		t.Fatalf("a pid that is not the parent: kill called for %v", killed)
	}
}
