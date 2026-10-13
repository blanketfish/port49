package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// openPty is a pseudo-terminal: the master a test reads and types on, and the
// slave a program takes for its terminal.
func openPty(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	var unlock int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); e != 0 {
		t.Skipf("no pty: TIOCSPTLCK: %v", e)
	}
	var n uint32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); e != 0 {
		t.Skipf("no pty: TIOCGPTN: %v", e)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	t.Cleanup(func() { m.Close(); s.Close() })
	return m, s
}

// echoOn is whether the terminal behind f echoes what is typed.
func echoOn(t *testing.T, f *os.File) bool {
	t.Helper()
	var tio syscall.Termios
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TCGETS, uintptr(unsafe.Pointer(&tio))); e != 0 {
		t.Fatalf("TCGETS: %v", e)
	}
	return tio.Lflag&syscall.ECHO != 0
}

// An ^C at a jump host's password prompt leaves the operator's terminal with
// echo on, as OpenSSH's own prompt does (task 6 review I-2).
func TestControlCAtAJumpPasswordLeavesEchoOn(t *testing.T) {
	m, s := openPty(t)
	dir, err := os.MkdirTemp("", "p49p")
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
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 512)
			_, _ = c.Read(buf)
			_, _ = io.WriteString(c, "N\n")
			c.Close()
		}
	}()
	go func() { _, _ = io.Copy(io.Discard, m) }()

	t.Setenv("SSH_ASKPASS_PROMPT", "")
	cmd := exec.Command(os.Args[0], "bob@jump's password: ")
	cmd.Env = append(os.Environ(), askpassEnv+"="+sock, "SSH_ASKPASS_REQUIRE=force")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = s, s, s
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	deadline := time.Now().Add(5 * time.Second)
	for echoOn(t, m) {
		if time.Now().After(deadline) {
			t.Fatal("the askpass never turned echo off for the password")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := io.WriteString(m, "\x03"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Error("the askpass exited 0 after ^C")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the askpass did not end after ^C")
	}
	if !echoOn(t, m) {
		t.Fatal("echo is off after ^C: the operator types blind")
	}
}

// port49 ssh puts the terminal back as it found it when ssh ends, whatever
// ended the askpass that had changed it (task 6 review I-2).
func TestSSHRestoresTheTerminalWhenItEnds(t *testing.T) {
	m, s := openPty(t)
	dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, dev.key)
	fake := filepath.Join(t.TempDir(), "ssh")
	script := fakeSSHHead(r.known) + "stty -echo\nexit 0\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	r.flags[3] = fake
	prev := os.Stdin
	os.Stdin = s
	t.Cleanup(func() { os.Stdin = prev })
	if !echoOn(t, m) {
		t.Fatal("the test terminal starts with echo off")
	}
	code, _, errb := r.run(t, "leaf1")
	if code != 0 || strings.Contains(errb, "port49 ssh:") {
		t.Fatalf("code %d stderr %q", code, errb)
	}
	if !echoOn(t, m) {
		t.Fatal("ssh left echo off and port49 ssh did not put it back")
	}
}
