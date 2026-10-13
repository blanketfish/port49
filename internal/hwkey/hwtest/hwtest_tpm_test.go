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
	if !waitSwtpm(cmd.Process.Pid, 5*time.Second) {
		t.Fatal("the planted swtpm never showed its command line")
	}
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

// swtpmAvailable skips (or fails, with $PORT49_TEST_HW_REQUIRED) without swtpm.
func swtpmAvailable(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("swtpm"); err != nil {
		Missing(t, "swtpm is not installed (apt-get install swtpm swtpm-tools)")
	}
}

// diedPid is the pid of a process that has exited.
func diedPid(t *testing.T) int {
	t.Helper()
	dead := exec.Command("true")
	if err := dead.Run(); err != nil {
		t.Fatal(err)
	}
	return dead.Process.Pid
}

// A record being written is empty or short: its owner cannot be told, so the
// swtpm it names is left alone and the record stays for the next start.
func TestReapSkipsAnEmptyOrPartialRecord(t *testing.T) {
	swtpmAvailable(t)
	dir := t.TempDir()
	empty := planted(t, dir, diedPid(t))
	if err := os.WriteFile(filepath.Join(dir, strconv.Itoa(empty.Process.Pid)), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	partial := planted(t, dir, diedPid(t))
	if err := os.WriteFile(filepath.Join(dir, strconv.Itoa(partial.Process.Pid)), []byte("12x"), 0o600); err != nil {
		t.Fatal(err)
	}
	reapStale(dir)
	for name, cmd := range map[string]*exec.Cmd{"empty": empty, "partial": partial} {
		if exitsWithin(cmd, 300*time.Millisecond) {
			t.Errorf("a swtpm with an %s record was killed", name)
		}
		if _, err := os.Stat(filepath.Join(dir, strconv.Itoa(cmd.Process.Pid))); err != nil {
			t.Errorf("the %s record was removed: %v", name, err)
		}
	}
}

// Root, or a directory another user owns, is never a reason to kill: the
// records in it are not ours to trust.
func TestReapLeavesADirectoryThatIsNotOursAlone(t *testing.T) {
	swtpmAvailable(t)
	for name, uid := range map[string]int{"root": 0, "another user": os.Getuid() + 1} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			orphan := planted(t, dir, diedPid(t))
			saved := getuid
			getuid = func() int { return uid }
			defer func() { getuid = saved }()
			reapStale(dir)
			if exitsWithin(orphan, 300*time.Millisecond) {
				t.Fatal("reapStale killed a swtpm from a directory that is not this user's")
			}
		})
	}
}

// A record is whole when it is seen: written to a name no reader looks at, then
// renamed. Nothing else is left in the directory.
func TestRecordPidLeavesOnlyTheWholeRecord(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	file := recordPid(os.Getpid())
	if file == "" {
		t.Fatal("no record written")
	}
	if b, err := os.ReadFile(file); err != nil || string(b) != strconv.Itoa(os.Getpid()) {
		t.Fatalf("the record: %q %v", b, err)
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(file), "*"))
	hidden, _ := filepath.Glob(filepath.Join(filepath.Dir(file), ".*"))
	if len(left) != 1 || len(hidden) != 0 {
		t.Fatalf("files left: %v %v", left, hidden)
	}
}

// The first harness start on a fresh /tmp has no pid directory yet: that is
// nothing to reap, not a crash.
func TestReapOnAMissingDirectoryDoesNothing(t *testing.T) {
	reapStale(filepath.Join(t.TempDir(), "no-such-dir"))
}

// A record is made by a rename: a direct write would leave a half record
// where a reader looks, so the final name must arrive through renameRecord.
func TestRecordPidArrivesByRename(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	var from, to string
	saved := renameRecord
	renameRecord = func(oldpath, newpath string) error {
		from, to = oldpath, newpath
		return saved(oldpath, newpath)
	}
	defer func() { renameRecord = saved }()
	file := recordPid(os.Getpid())
	if file == "" || to != file || from == file || filepath.Dir(from) != filepath.Dir(file) {
		t.Fatalf("record %q was renamed from %q to %q", file, from, to)
	}
}

// A swtpm that never shows its own command line is not recorded: it is
// killed, and launch says it is not up, so the harness tries again.
func TestLaunchKillsASwtpmItCannotConfirm(t *testing.T) {
	swtpmAvailable(t)
	t.Setenv("TMPDIR", t.TempDir())
	var started int
	saved := waitSwtpmFor
	waitSwtpmFor = func(pid int, _ time.Duration) bool { started = pid; return false }
	defer func() { waitSwtpmFor = saved }()
	s := &TPM{t: t, dir: t.TempDir(), command: freeAddr(t), control: freeAddr(t)}
	if s.launch() {
		s.Stop()
		t.Fatal("launch reported a swtpm it could not confirm as up")
	}
	if started == 0 || alive(started) {
		t.Fatalf("the swtpm (pid %d) is still running", started)
	}
	if left, _ := filepath.Glob(filepath.Join(pidDir(), "*")); len(left) != 0 {
		t.Fatalf("a record was made for it: %v", left)
	}
}

// A process just started shows its parent's command line until it execs, so a
// record made then would name nothing; the harness waits for swtpm's own.
func TestWaitSwtpmCmdline(t *testing.T) {
	swtpmAvailable(t)
	cmd := exec.Command("swtpm", "socket", "--tpm2",
		"--server", "type=tcp,bindaddr=127.0.0.1,port="+portOf(freeAddr(t)),
		"--ctrl", "type=tcp,bindaddr=127.0.0.1,port="+portOf(freeAddr(t)),
		"--tpmstate", "dir="+t.TempDir(), "--flags", "not-need-init,startup-clear")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	if !waitSwtpm(cmd.Process.Pid, 5*time.Second) {
		t.Fatal("a swtpm's command line was not seen")
	}
	other := exec.Command("sleep", "60")
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Process.Kill(); _ = other.Wait() })
	if start := time.Now(); waitSwtpm(other.Process.Pid, 300*time.Millisecond) || time.Since(start) < 250*time.Millisecond {
		t.Fatal("a sleep was taken for a swtpm, or the wait did not wait")
	}
}

// A process the harness starts finds the swtpm by the variable SWTPM sets:
// the agent a login starts is the test binary again.
func TestSWTPMNamesItselfToChildProcesses(t *testing.T) {
	SWTPM(t)
	v := os.Getenv(EnvSWTPM)
	if v == "" {
		t.Fatal("SWTPM set no variable for a child process")
	}
	c, err := dialAddrs(v)
	if err != nil {
		t.Fatalf("dialing %q: %v", v, err)
	}
	c.Close()
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
