//go:build hwkey

package hwtest

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/tcp"

	"github.com/blanketfish/port49/internal/hwkey/tpm"
)

// TPM is one swtpm: a software TPM 2.0 listening on two loopback ports, with
// its state in a directory of its own. tpm.Dial reaches it while it runs.
type TPM struct {
	t       testing.TB
	dir     string
	command string // host:port of the command channel
	control string // host:port of the platform (control) channel

	mu      sync.Mutex
	cmd     *exec.Cmd
	exited  chan struct{} // closed when cmd has exited
	pidFile string        // this swtpm's record in pidDir
	started bool          // swtpm has come up once: the ports are fixed
}

var (
	currentMu sync.Mutex
	current   *TPM // the swtpm tpm.Dial reaches
)

// freeAddr is a loopback address nothing listens on yet.
func freeAddr(t testing.TB) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hwtest: no free port: %v", err)
	}
	defer l.Close()
	return l.Addr().String()
}

func portOf(addr string) string {
	_, p, _ := net.SplitHostPort(addr)
	return p
}

// SWTPM starts a swtpm with a fresh state directory for one test and points
// tpm.Dial at it for the test's life; the SRK is its own. Stop is the unplug
// and Restart the re-insertion, with the same state directory and ports, so
// the same SRK. With $PORT49_TEST_HW_REQUIRED set, a missing swtpm fails the
// test instead of skipping it, as for SoftHSM.
func SWTPM(t *testing.T) *TPM {
	t.Helper()
	if _, err := exec.LookPath("swtpm"); err != nil {
		Missing(t, "swtpm is not installed (apt-get install swtpm swtpm-tools)")
	}
	reapOnce.Do(func() { reapStale(pidDir()) })
	s := &TPM{t: t, dir: t.TempDir(), command: freeAddr(t), control: freeAddr(t)}
	s.Restart()
	currentMu.Lock()
	prev, prevDial := current, tpm.Dial
	current = s
	currentMu.Unlock()
	tpm.Dial = s.dial
	t.Setenv(EnvSWTPM, s.command+" "+s.control)
	t.Cleanup(func() {
		s.Stop()
		currentMu.Lock()
		current = prev
		currentMu.Unlock()
		tpm.Dial = prevDial
	})
	return s
}

// SWTPMFresh stops the swtpm SWTPM started and starts a second one with a new
// state directory, so its SRK differs: another machine's TPM. tpm.Dial reaches
// the new one.
func SWTPMFresh(t *testing.T) *TPM {
	t.Helper()
	currentMu.Lock()
	old := current
	currentMu.Unlock()
	if old != nil {
		old.Stop()
	}
	s := &TPM{t: t, dir: t.TempDir(), command: freeAddr(t), control: freeAddr(t)}
	s.Restart()
	currentMu.Lock()
	current = s
	currentMu.Unlock()
	tpm.Dial = s.dial
	t.Setenv(EnvSWTPM, s.command+" "+s.control)
	t.Cleanup(s.Stop)
	return s
}

// dial is tpm.Dial for this swtpm: both channels. No PowerOn: swtpm starts
// itself (startup-clear) and answers the platform channel in its own protocol,
// not the simulator's, so go-tpm's PowerOn/NVOn fails against it.
func (s *TPM) dial() (transport.TPMCloser, error) {
	t, err := tcp.Open(tcp.Config{CommandAddress: s.command, PlatformAddress: s.control})
	if err != nil {
		return nil, err
	}
	return t, nil
}

// Restart starts the swtpm again on the same ports and state directory, and
// returns once both answer. It is a no-op while one runs.
func (s *TPM) Restart() {
	s.t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != nil {
		return
	}
	// The ports were free when picked and swtpm binds them later, so another
	// process may take one in between: swtpm then exits at once. Before it has
	// ever run, pick new ports and try again; after, the ports are the ones the
	// test's tpm.Dial already holds.
	attempts := 1
	if !s.started {
		attempts = 5
	}
	for i := 0; i < attempts; i++ {
		if i > 0 {
			s.command, s.control = freeAddr(s.t), freeAddr(s.t)
		}
		if s.launch() {
			s.started = true
			return
		}
	}
	s.t.Fatalf("hwtest: swtpm did not come up on %s and %s", s.command, s.control)
}

// launch starts swtpm and reports whether it is running and answering on both
// ports. A swtpm that exited, as when a port was taken, is not up even if
// something else answers on the port.
func (s *TPM) launch() bool {
	cmd := exec.Command("swtpm", "socket", "--tpm2",
		"--server", "type=tcp,bindaddr=127.0.0.1,port="+portOf(s.command),
		"--ctrl", "type=tcp,bindaddr=127.0.0.1,port="+portOf(s.control),
		"--tpmstate", "dir="+s.dir,
		"--flags", "not-need-init,startup-clear")
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		s.t.Fatalf("hwtest: starting swtpm: %v", err)
	}
	// A test binary killed or timed out skips t.Cleanup: the next harness start
	// finds this record and reaps the swtpm (reapStale). Recorded once the
	// process shows swtpm's own command line: a harness that starts between
	// the fork and the exec would take it for a stranger and drop the record.
	// One that never does is no swtpm to record: it is killed, and launch is
	// not up.
	if !waitSwtpmFor(cmd.Process.Pid, 2*time.Second) {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return false
	}
	pidFile := recordPid(cmd.Process.Pid)
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	for _, addr := range []string{s.command, s.control} {
		if !waitListening(addr, exited) {
			_ = cmd.Process.Kill()
			<-exited
			removePidFile(pidFile)
			return false
		}
	}
	select {
	case <-exited:
		removePidFile(pidFile)
		return false
	default:
	}
	s.cmd, s.exited, s.pidFile = cmd, exited, pidFile
	return true
}

// waitListening is true once addr accepts a connection, false if exited closes
// first or ten seconds pass.
func waitListening(addr string, exited <-chan struct{}) bool {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			return false
		default:
		}
		if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			c.Close()
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// Stop ends the swtpm, as unplugging the TPM would: a dial then fails.
func (s *TPM) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd == nil {
		return
	}
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-s.exited:
	case <-time.After(5 * time.Second):
		_ = s.cmd.Process.Kill()
		<-s.exited
	}
	removePidFile(s.pidFile)
	s.cmd = nil
}

func removePidFile(file string) {
	if file != "" {
		_ = os.Remove(file)
	}
}

// pidDir is where each running swtpm is recorded, one file per swtpm named by
// its pid and holding the pid of the test binary that started it. A test binary
// that dies (a timeout panic, kill -9) skips t.Cleanup and leaves its swtpm
// running; Pdeathsig does not help, as swtpm's AppArmor profile clears it at
// exec. The next harness start reaps what is left.
func pidDir() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("port49-swtpm-%d", os.Getuid()))
}

var reapOnce sync.Once

// getuid is os.Getuid, a var so a test can be another user.
var getuid = os.Getuid

// renameRecord and waitSwtpmFor are the rename that makes a pid record whole
// and the wait for swtpm's own command line, vars so a test sees the one and
// refuses the other.
var (
	renameRecord = os.Rename
	waitSwtpmFor = waitSwtpm
)

// EnvSWTPM names the running swtpm's two addresses ("command control") to a
// process the test starts, such as the agent a login starts, which is the test
// binary again and so imports this package: init points tpm.Dial at them.
// Nothing sets it outside SWTPM, so no process dials a swtpm by accident, and
// none dials the machine's TPM in its place while it is set.
const EnvSWTPM = "PORT49_TEST_SWTPM"

func init() {
	if v := os.Getenv(EnvSWTPM); v != "" {
		tpm.Dial = func() (transport.TPMCloser, error) { return dialAddrs(v) }
	}
}

// dialAddrs dials the swtpm that "command control" names, both channels.
func dialAddrs(v string) (transport.TPMCloser, error) {
	command, control, ok := strings.Cut(v, " ")
	if !ok {
		return nil, fmt.Errorf("hwtest: %s=%q is not \"command control\"", EnvSWTPM, v)
	}
	return tcp.Open(tcp.Config{CommandAddress: command, PlatformAddress: control})
}

// waitSwtpm is true once pid's command line is swtpm's, false after d. A
// process just started shows its parent's until it execs, so a record made
// then would name a process reapStale cannot tell from a stranger.
func waitSwtpm(pid int, d time.Duration) bool {
	for deadline := time.Now().Add(d); ; time.Sleep(10 * time.Millisecond) {
		if isSwtpm(pid) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
	}
}

// reapStale kills every swtpm recorded in dir whose test binary is gone, and
// removes the record of any whose process is gone or is no longer a swtpm (the
// pid was reused). A swtpm whose test binary is alive belongs to a package
// running in parallel and is left alone.
//
// Nothing is reaped as root, or from a directory this user does not own: a
// record there is not this user's, and a kill by pid on another's word is how
// an unrelated process dies. A record that is empty or short is one being
// written (recordPid renames it whole, but an older harness did not) and is
// left for the next start.
func reapStale(dir string) {
	fi, err := os.Stat(dir)
	if err != nil {
		return // no directory yet: nothing was ever recorded
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || getuid() == 0 || int(st.Uid) != getuid() {
		return
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		file := filepath.Join(dir, e.Name())
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		owner, _ := os.ReadFile(file)
		opid, err := strconv.Atoi(strings.TrimSpace(string(owner)))
		if err != nil || alive(opid) {
			continue
		}
		if isSwtpm(pid) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
		_ = os.Remove(file)
	}
}

// alive is true when a process with pid exists.
func alive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// isSwtpm is true when pid's command is swtpm.
func isSwtpm(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	argv0, _, _ := strings.Cut(string(b), "\x00")
	return filepath.Base(argv0) == "swtpm"
}

// recordPid notes a running swtpm in the pid directory and returns the file,
// "" if it could not be written.
func recordPid(pid int) string {
	dir := pidDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ""
	}
	// Written to a name reapStale does not read and renamed whole, so a
	// harness starting alongside never sees half a record.
	tmp, err := os.CreateTemp(dir, ".record-*")
	if err != nil {
		return ""
	}
	_, werr := tmp.WriteString(strconv.Itoa(os.Getpid()))
	if cerr := tmp.Close(); werr != nil || cerr != nil {
		os.Remove(tmp.Name())
		return ""
	}
	file := filepath.Join(dir, strconv.Itoa(pid))
	if renameRecord(tmp.Name(), file) != nil {
		os.Remove(tmp.Name())
		return ""
	}
	return file
}

func (s *TPM) String() string { return fmt.Sprintf("swtpm %s (state %s)", s.command, s.dir) }
