//go:build hwkey

package hwtest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// planted starts a real swtpm outside the harness and records it in dir as a
// harness whose test binary is owner.
func planted(t *testing.T, dir string, owner int) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("swtpm", "socket", "--tpm2",
		"--server", "type=tcp,bindaddr=127.0.0.1,port="+portOf(freeAddr(t)),
		"--ctrl", "type=tcp,bindaddr=127.0.0.1,port="+portOf(freeAddr(t)),
		"--tpmstate", "dir="+t.TempDir(),
		"--flags", "not-need-init,startup-clear")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	record(t, dir, cmd.Process.Pid, owner)
	return cmd
}

func record(t *testing.T, dir string, pid, owner int) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, strconv.Itoa(pid)), []byte(strconv.Itoa(owner)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func exitsWithin(cmd *exec.Cmd, d time.Duration) bool {
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

func TestReapKillsASwtpmWhoseTestBinaryDied(t *testing.T) {
	if _, err := exec.LookPath("swtpm"); err != nil {
		Missing(t, "swtpm is not installed (apt-get install swtpm swtpm-tools)")
	}
	dir := t.TempDir()
	dead := exec.Command("true")
	if err := dead.Run(); err != nil {
		t.Fatal(err)
	}
	orphan := planted(t, dir, dead.Process.Pid)
	// A swtpm whose test binary is alive (a parallel package's) is left alone.
	live := planted(t, dir, os.Getpid())
	// A pid that is not a swtpm any more (reused) is left alone, its file removed.
	other := exec.Command("sleep", "60")
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Process.Kill(); _ = other.Wait() })
	record(t, dir, other.Process.Pid, dead.Process.Pid)

	reapStale(dir)

	if !exitsWithin(orphan, 5*time.Second) {
		t.Fatal("the orphaned swtpm is still running")
	}
	if other.ProcessState != nil || exec.Command("kill", "-0", strconv.Itoa(other.Process.Pid)).Run() != nil {
		t.Fatal("reapStale killed a process that is not a swtpm")
	}
	if exitsWithin(live, 300*time.Millisecond) {
		t.Fatal("reapStale killed a swtpm whose test binary is alive")
	}
	left, _ := filepath.Glob(filepath.Join(dir, "*"))
	if len(left) != 1 || filepath.Base(left[0]) != strconv.Itoa(live.Process.Pid) {
		t.Fatalf("files left after reaping: %v, want only the live harness's", left)
	}
}
