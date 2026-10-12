//go:build hwkey

package hwtest

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/tcp"

	"github.com/rhwendt/port49/internal/hwkey/tpm"
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
	s := &TPM{t: t, dir: t.TempDir(), command: freeAddr(t), control: freeAddr(t)}
	s.Restart()
	currentMu.Lock()
	prev, prevDial := current, tpm.Dial
	current = s
	currentMu.Unlock()
	tpm.Dial = s.dial
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
	// A test binary killed or timed out skips t.Cleanup; the kernel ends swtpm.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		s.t.Fatalf("hwtest: starting swtpm: %v", err)
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	for _, addr := range []string{s.command, s.control} {
		if !waitListening(addr, exited) {
			_ = cmd.Process.Kill()
			<-exited
			return false
		}
	}
	select {
	case <-exited:
		return false
	default:
	}
	s.cmd, s.exited = cmd, exited
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
	s.cmd = nil
}

func (s *TPM) String() string { return fmt.Sprintf("swtpm %s (state %s)", s.command, s.dir) }
