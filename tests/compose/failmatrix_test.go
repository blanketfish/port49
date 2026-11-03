//go:build compose && failmatrix

// The failure matrix (plan 12c, Task 9; design §12): each row the compose
// stack can reach is run against it, and deploy/failure-matrix.md names the
// subtest that is its evidence. It has its own tag so that `make
// compose-smoke` never builds or runs it; `make failure-matrix` and the
// failmatrix CI job do.
package compose

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/tacacs/wire"
	"github.com/blanketfish/port49/tests/shapes/shapetest"
	"gopkg.in/yaml.v3"
)

// The settings deploy/compose/config/port49d.yaml states and the defaults it leaves.
const (
	healthInterval = time.Second            // stores.directory.etcd.health.interval
	closeAfter     = 5                      // health.close_after
	openAfter      = 3                      // health.open_after
	callTimeout    = 500 * time.Millisecond // etcd.call_timeout default
	holdTTL        = 15 * time.Second       // etcd.hold_ttl default
	tacacsAddr     = "127.0.0.1:49"
	daemonMetrics  = "127.0.0.1:9049"
	brokerMetrics  = "127.0.0.1:9050"
	brokerAddr     = "127.0.0.1:8443"
	snapVolume     = project + "_snap"
	initialCluster = "etcd-1=https://etcd-1:2380,etcd-2=https://etcd-2:2380,etcd-3=https://etcd-3:2380"
)

var members = []string{"etcd-1", "etcd-2", "etcd-3"}

// matrix is the stack the subtests share, and what they log in with.
type matrix struct {
	s         stack
	dev       shapetest.Device
	brokerDir string
	root      string
}

// with is m with its failures reported to t: a subtest runs in its own
// goroutine, and the parent's Fatalf from there would not stop it.
func (m matrix) with(t *testing.T) matrix {
	m.s.t = t
	m.dev.T = t
	return m
}

// composeUp brings the stack up on a fresh PKI and waits for both processes.
func composeUp(t *testing.T) matrix {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	s := newStack(t)
	s.run("up", "-d", "--build")
	s.ready(daemonMetrics)
	s.ready(brokerMetrics)
	key, err := os.ReadFile(filepath.Join(s.local, "keys", "tacacs_v1"))
	if err != nil {
		t.Fatal(err)
	}
	return matrix{s: s, brokerDir: filepath.Join(s.local, "broker"), root: root,
		dev: shapetest.Device{T: t, Addr: tacacsAddr, Key: key}}
}

func (m matrix) mint() string { return shapetest.Mint(m.s.t, m.brokerDir, brokerAddr, "smoke1") }

// passes is a login that is answered PASS.
func (m matrix) passes(tok string) bool {
	st, err := m.dev.TryLogin("alice", tok)
	return err == nil && st == wire.AuthenStatusPass
}

// refused is a login that did not pass: no answer, or an answer that is not PASS.
func (m matrix) refused(tok string) bool { return !m.passes(tok) }

// listening is true when port49d holds TCP 49: a connection is made and stays
// open and quiet for 400ms. A published port whose container has closed its
// listener may still accept at the host (the userland proxy) and then close
// at once, which is not listening.
func listening(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	_, err = c.Read(make([]byte, 1))
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// restore leaves the stack as composeUp made it: whatever a subtest paused or
// stopped is running again, both processes are ready and port49d listens.
func (m matrix) restore() {
	t := m.s.t
	t.Helper()
	// One service at a time: compose stops at the first container that is not
	// paused ("is not paused"), and would leave the rest paused.
	for _, svc := range []string{"etcd-1", "etcd-2", "etcd-3", "port49d", "port49-broker"} {
		m.s.try("unpause", svc)
	}
	m.s.run("start", "etcd-1", "etcd-2", "etcd-3", "port49-broker", "port49d")
	m.s.ready(daemonMetrics)
	m.s.ready(brokerMetrics)
	shapetest.WaitFor(t, "port49d listening", 2*time.Minute, func() bool { return listening(tacacsAddr) })
	// Healthy means the store answers port49d's checks, not only that the
	// processes are up: the next subtest starts from a working store.
	shapetest.WaitFor(t, "port49_store_health_failures back at 0", time.Minute, func() bool {
		return m.gauge(daemonMetrics, "port49_store_health_failures") == 0
	})
	shapetest.WaitFor(t, "port49_policy_file_refused back at 0", time.Minute, func() bool {
		return m.gauge(daemonMetrics, "port49_policy_file_refused") == 0
	})
}

// dump logs the tail of both processes' stderr through the filter.
func (m matrix) dump() {
	out, _ := m.s.try("logs", "--no-color", "--tail", "40", "port49d", "port49-broker")
	m.s.t.Logf("port49d and port49-broker, last 40 lines each:\n%s", shapetest.Filtered(m.root, out))
}

// gauge reads an unlabelled gauge, retrying for 30s: port49d starts its run
// again in-process after a store gone, and its metrics listener is closed and
// bound afresh meanwhile (internal/port49d/main.go, runLoop), so a scrape in
// that window is reset or refused.
func (m matrix) gauge(addr, name string) float64 {
	m.s.t.Helper()
	var last error
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		v, found, err := scrape(addr, name)
		if err == nil && found {
			return v
		}
		last = err
		if err == nil {
			last = fmt.Errorf("no sample %s", name)
		}
	}
	m.s.t.Fatalf("metrics at %s: %v (for 30s)", addr, last)
	return 0
}

// scrape reads one unlabelled or fully written sample from addr's /metrics.
func scrape(addr, sample string) (v float64, found bool, err error) {
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, false, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if x, ok := strings.CutPrefix(line, sample+" "); ok {
			v, err = strconv.ParseFloat(strings.TrimSpace(x), 64)
			return v, err == nil, err
		}
	}
	return 0, false, nil
}

// tlsDial is a TLS connection to addr that checks nothing about the server: a
// stopped broker is the thing under test, not its certificate.
func tlsDial(addr string) (*tls.Conn, error) {
	return tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
}

func TestFailureMatrix(t *testing.T) {
	shapetest.RefuseOnKeyHost(t)
	m := composeUp(t)
	run := func(name string, f func(m matrix)) {
		t.Run(name, func(t *testing.T) {
			sm := m.with(t)
			// Registered first, so it runs last: after the subtest's own cleanups
			// and before the next subtest starts.
			t.Cleanup(sm.restore)
			t.Cleanup(func() {
				if t.Failed() {
					sm.dump()
				}
			})
			f(sm)
		})
	}
	// dark is a store row: while port49d still listens, a token login is
	// answered ERROR store_unavailable and a command of an open session FAIL
	// store_unavailable (design §12, the "Store hangs" and "Token store
	// unavailable" rows; spec §5.7: an authorization is FAIL, never ERROR). An unanswered
	// connection is allowed only once the listener has closed.
	dark := func(name string, listenBound time.Duration, down, up func(m matrix)) {
		run(name, func(m matrix) {
			t := m.s.t
			if st := m.dev.Login("alice", m.mint()); st != wire.AuthenStatusPass {
				t.Fatalf("login before the store went dark: status %d", st)
			}
			// The session's own authorization (priv 1) raises the context to the
			// role's level; a command at 15 before it is privilege_exceeded.
			if !m.dev.Permits("alice") {
				t.Fatal("the session authorization before the store went dark was refused")
			}
			tok := m.mint()
			down(m)
			st, err := m.dev.TryLogin("alice", tok)
			switch {
			case err == nil && st != wire.AuthenStatusError:
				t.Fatalf("a token login with the store dark was answered status %#x, want ERROR (%#x)", st, wire.AuthenStatusError)
			case err != nil && listening(tacacsAddr):
				t.Fatalf("a token login with the store dark and the listener open was not answered: %v", err)
			}
			cst, err := m.dev.AuthorStatus("alice", "show", "version")
			switch {
			case err == nil && cst != wire.AuthorStatusFail:
				t.Fatalf("a command with the store dark was answered status %#x, want FAIL (%#x)", cst, wire.AuthorStatusFail)
			case err != nil && listening(tacacsAddr):
				t.Fatalf("a command with the store dark and the listener open was not answered: %v", err)
			}
			shapetest.WaitFor(t, "the listener closed", closeAfter*healthInterval+callTimeout+2*time.Second,
				func() bool { return !listening(tacacsAddr) })
			shapetest.WaitFor(t, "port49_store_health_failures at close_after", 10*time.Second, func() bool {
				return m.gauge(daemonMetrics, "port49_store_health_failures") >= closeAfter
			})
			up(m)
			shapetest.WaitFor(t, "the listener open again", listenBound, func() bool { return listening(tacacsAddr) })
			next := m.mint()
			shapetest.WaitFor(t, "a login", 10*time.Second, func() bool { return m.passes(next) })
		})
	}
	// store_hangs: the brief's bound, open_after passes plus 2s. store_stopped
	// adds the members' own start and election, which the pause does not have.
	// It kills the members rather than stopping them: etcd's graceful stop took
	// 7s or more in CI, so port49d had closed its listener before `stop` returned
	// and the statuses of the 5.5s window could not be probed.
	dark("store_hangs", openAfter*healthInterval+2*time.Second+callTimeout,
		func(m matrix) { m.s.run("pause", "etcd-2", "etcd-3") },
		func(m matrix) { m.s.run("unpause", "etcd-2", "etcd-3") })
	dark("store_stopped", 30*time.Second,
		func(m matrix) { m.s.run("kill", "etcd-1", "etcd-2", "etcd-3") },
		func(m matrix) { m.s.run("start", "etcd-1", "etcd-2", "etcd-3") })

	run("one_member_dark", func(m matrix) {
		t := m.s.t
		// The mint's transaction is not hedged (a second copy would write a second
		// token), so the tokens are minted while every member answers: the claim
		// is about logins.
		var toks []string
		for i := 0; i < 30; i++ {
			toks = append(toks, m.mint())
		}
		m.s.run("pause", "etcd-2")
		var slowest time.Duration
		var failed []int
		for i := 0; i < 30; i++ {
			start := time.Now()
			ok := m.passes(toks[i])
			d := time.Since(start)
			if d > slowest {
				slowest = d
			}
			t.Logf("login %d of 30: pass %v in %v", i+1, ok, d)
			if !ok {
				failed = append(failed, i+1)
			}
		}
		if len(failed) > 0 {
			t.Errorf("logins %v of 30 with one member paused did not pass", failed)
		}
		t.Logf("slowest of 30 logins with one member dark: %v", slowest)
		if limit := 12*time.Second + callTimeout; slowest > limit {
			t.Fatalf("slowest login %v, want under 12s + call_timeout (%v)", slowest, limit)
		}
	})

	run("broker_stopped", func(m matrix) {
		t := m.s.t
		if st := m.dev.Login("alice", m.mint()); st != wire.AuthenStatusPass {
			t.Fatalf("login before the stop: status %d", st)
		}
		if !m.dev.Permits("alice") {
			t.Fatal("the session authorization before the stop was refused")
		}
		held := m.mint()
		m.s.run("stop", "port49-broker")
		if !m.dev.Permits("alice", "show", "version") {
			t.Fatal("an open session's next command was refused with the broker stopped")
		}
		if !m.passes(held) {
			t.Fatal("a token minted before the stop did not log in with the broker stopped (split deployment, L37)")
		}
		if conn, err := tlsDial(brokerAddr); err == nil {
			conn.Close()
			t.Fatal("a connection to the stopped broker succeeded: a mint cannot fail with a connection error")
		}
		m.s.run("start", "port49-broker")
		m.s.ready(brokerMetrics)
		if !m.passes(m.mint()) {
			t.Fatal("a mint and login after the broker started did not pass")
		}
	})

	run("port49d_stopped", func(m matrix) {
		m.s.run("stop", "port49d")
		refusedAtOnce(m.s.t, "port49d stopped")
	})

	run("store_absent_at_start", func(m matrix) {
		t := m.s.t
		m.s.run("stop", "etcd-1", "etcd-2", "etcd-3")
		m.s.run("restart", "port49d")
		shapetest.WaitFor(t, "/readyz answering 503 with no store", time.Minute, func() bool {
			resp, err := http.Get("http://" + daemonMetrics + "/readyz")
			if err != nil {
				return false
			}
			resp.Body.Close()
			return resp.StatusCode == http.StatusServiceUnavailable
		})
		if listening(tacacsAddr) {
			t.Fatal("port49d listens on TCP 49 with no store at its start")
		}
		m.s.run("start", "etcd-1", "etcd-2", "etcd-3")
		m.s.ready(daemonMetrics)
		shapetest.WaitFor(t, "the listener", time.Minute, func() bool { return listening(tacacsAddr) })
		next := m.mint()
		shapetest.WaitFor(t, "a login", 20*time.Second, func() bool { return m.passes(next) })
	})

	run("port49d_restarted", func(m matrix) {
		t := m.s.t
		if st := m.dev.Login("alice", m.mint()); st != wire.AuthenStatusPass {
			t.Fatalf("login before the restart: status %d", st)
		}
		if !m.dev.Permits("alice") || !m.dev.Permits("alice", "show", "version") {
			t.Fatal("the session or a command before the restart was refused")
		}
		before := lastCtxID(m.s.run("logs", "--no-color", "port49d"))
		held := m.mint()
		m.s.run("restart", "port49d")
		m.s.ready(daemonMetrics)
		shapetest.WaitFor(t, "the listener", time.Minute, func() bool { return listening(tacacsAddr) })
		since := time.Now().UTC().Format(time.RFC3339)
		// The open session's command first: a redemption would rejoin the context.
		if !m.dev.Permits("alice", "show", "version") {
			t.Fatal("an open session's next command after the restart was refused")
		}
		if !m.passes(held) {
			t.Fatal("a token minted before the restart did not redeem (split deployment, decision 36 ruling 7)")
		}
		after := lastCtxID(m.s.run("logs", "--no-color", "--since", since, "port49d"))
		if before == "" || after != before {
			t.Fatalf("the command after the restart was answered from ctx_id %q, want the session's %q", after, before)
		}
	})

	run("partition", func(m matrix) {
		tok := m.mint()
		m.s.run("pause", "port49d")
		_, err := m.dev.TryLogin("alice", tok)
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			m.s.t.Fatalf("a request to a paused port49d: %v, want silence (a read timeout), not a reply or a reset", err)
		}
	})

	run("retired_key", func(m matrix) { retiredKey(m) })

	run("policy_refused", func(m matrix) {
		t := m.s.t
		out, err := volumeSh(project+"_port49d-etc", "stat -c %a /e")
		if err != nil {
			t.Fatalf("stat the policy's directory: %v", err)
		}
		mode := strings.TrimSpace(out)
		if _, err := volumeSh(project+"_port49d-etc", "chmod g+w /e"); err != nil {
			t.Fatal(err)
		}
		defer volumeSh(project+"_port49d-etc", "chmod "+mode+" /e")
		shapetest.WaitFor(t, "port49_policy_file_refused at 1", 30*time.Second, func() bool {
			return m.gauge(daemonMetrics, "port49_policy_file_refused") == 1
		})
		if !m.passes(m.mint()) {
			t.Fatal("a login did not pass on the policy in force while the policy file was refused")
		}
		if _, err := volumeSh(project+"_port49d-etc", "chmod "+mode+" /e"); err != nil {
			t.Fatal(err)
		}
		shapetest.WaitFor(t, "port49_policy_file_refused back at 0", 30*time.Second, func() bool {
			return m.gauge(daemonMetrics, "port49_policy_file_refused") == 0
		})
	})

	run("restore_guarded", restoreGuarded)
}

// refusedAtOnce fails unless a connection to TCP 49 is refused (ECONNREFUSED)
// within 2s: a device then treats the server as down at once. A dial that times
// out, or one that connects and is closed, is the silence or the hang that
// costs a device its own timeout.
func refusedAtOnce(t *testing.T, when string) {
	t.Helper()
	start := time.Now()
	c, err := net.DialTimeout("tcp", tacacsAddr, 2*time.Second)
	if err == nil {
		c.Close()
		t.Fatalf("TCP 49 accepts a connection with %s: a device would not find it refused", when)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) || time.Since(start) > 2*time.Second {
		t.Fatalf("a connection to TCP 49 with %s: %v after %v, want ECONNREFUSED at once", when, err, time.Since(start))
	}
}

// counter reads one sample of a labelled counter, 0 when it has none yet,
// retrying for 30s a scrape that port49d's in-process restart refused.
func counter(t *testing.T, addr, sample string) float64 {
	t.Helper()
	var last error
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		v, _, err := scrape(addr, sample)
		if err == nil {
			return v
		}
		last = err
	}
	t.Fatalf("metrics at %s: %v (for 30s)", addr, last)
	return 0
}

var ctxIDRe = regexp.MustCompile(`"ctx_id":"([^"]+)"`)

// lastCtxID is the ctx_id of the last decision record in log, "" if none.
func lastCtxID(log string) string {
	all := ctxIDRe.FindAllStringSubmatch(log, -1)
	if len(all) == 0 {
		return ""
	}
	return all[len(all)-1][1]
}

// volumeSh runs script in a throwaway container on the setup image as root,
// with volume at /e.
func volumeSh(volume, script string) (string, error) {
	out, err := exec.Command("docker", "run", "--rm", "-v", volume+":/e", "--entrypoint", "sh",
		"port49-setup:dev", "-c", script).CombinedOutput()
	return string(out), err
}

// retiredKey: a policy edit moves the device's key version 1 to retired while
// the device still uses it. A new connection's first packet is an unvalidated
// record (matches_retired) and a strike: the source's next connection, even
// under a good key, meets the backoff. The open-connection half, a reset with
// no strike, is internal/daemon/server's
// TestAReloadThatWithdrawsTheVersionEndsItsConnectionWithoutAStrike.
func retiredKey(m matrix) {
	t := m.s.t
	c := composeRotator{s: m.s}
	policy, err := os.ReadFile(filepath.Join(m.s.config, "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(policy, &doc); err != nil {
		t.Fatal(err)
	}
	k := doc["keys"].(map[string]any)["k"].(map[string]any)
	v2 := "not-a-real-device-key-for-the-matrix"
	if err := c.WriteKey("tacacs_v2", []byte(v2)); err != nil {
		t.Fatal(err)
	}
	k["current"] = map[string]any{"version": 2, "secret_ref": "file:/run/port49/keys/tacacs_v2"}
	k["retired"] = []any{map[string]any{"version": 1, "secret_ref": "file:/run/port49/keys/tacacs_v1"}}
	next, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	tok := m.mint()
	// The version 1 policy goes back whatever happens below, or every later subtest meets a retired key.
	t.Cleanup(func() {
		if err := c.WritePolicy(policy); err != nil {
			t.Logf("putting the version 1 policy back: %v", err)
			return
		}
		// port49d reads the file at its watch interval, and a strike holds the
		// source for its backoff: the next subtest starts when v1 logs in again,
		// or its own policy edit meets a reload still pending.
		deadline := time.Now().Add(45 * time.Second)
		for !m.passes(m.mint()) && time.Now().Before(deadline) {
			time.Sleep(time.Second)
		}
	})
	if err := c.WritePolicy(next); err != nil {
		t.Fatal(err)
	}
	shapetest.WaitFor(t, "port49d reading the policy that retires version 1", 30*time.Second, func() bool {
		return strings.Contains(m.s.run("logs", "--no-color", "port49d"), "version 1 retired")
	})
	misses := counter(t, daemonMetrics, `port49_connection_events_total{event="key_miss_closed"}`)
	held := counter(t, daemonMetrics, `port49_connection_events_total{event="held_refused"}`)
	dv2 := shapetest.Device{T: t, Addr: tacacsAddr, Key: []byte(v2)}
	tok2 := m.mint()
	// The strike's first backoff is limits.malformed_backoff_base, 100ms: the
	// version 2 retry follows the miss at once, before anything else is read.
	st, err := m.dev.TryLogin("alice", tok)
	_, retryErr := dv2.TryLogin("alice", tok2)
	var ne net.Error
	if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
		t.Fatalf("a login keyed with the retired version: status %d, error %v, want a reset with no reply", st, err)
	}
	logs := m.s.run("logs", "--no-color", "port49d")
	found := false
	for _, line := range strings.Split(logs, "\n") {
		found = found || (strings.Contains(line, "unvalidated") && strings.Contains(line, "matches_retired"))
	}
	if !found {
		t.Fatal("no unvalidated record says matches_retired")
	}
	if got := counter(t, daemonMetrics, `port49_connection_events_total{event="key_miss_closed"}`); got <= misses {
		t.Fatalf("key_miss_closed went from %v to %v: the retired version's packet was not struck", misses, got)
	}
	// The strike's hold: the same source, under the good version 2 key, was
	// reset at Accept, and once the backoff has passed the same token redeems (a
	// connection reset at Accept redeems nothing).
	if retryErr == nil {
		t.Fatal("the next connection from the struck source was answered: the miss was not a strike")
	}
	if got := counter(t, daemonMetrics, `port49_connection_events_total{event="held_refused"}`); got <= held {
		t.Fatalf("held_refused went from %v to %v: the immediate retry was not refused by the hold", held, got)
	}
	shapetest.WaitFor(t, "a version 2 login once the backoff has passed", 30*time.Second, func() bool {
		st, err := dv2.TryLogin("alice", tok2)
		return err == nil && st == wire.AuthenStatusPass
	})
	if err := c.WritePolicy(policy); err != nil { // the version 1 policy back, and v1 logins waited for
		t.Fatal(err)
	}
	next2 := m.mint()
	shapetest.WaitFor(t, "a version 1 login after the policy is back and the backoff has passed", 30*time.Second,
		func() bool { return m.passes(next2) })
}

// snapshot saves etcd's state into the snap volume as the stack's etcd root
// (etcd-init.sh's client certificate) and returns when it was taken.
func (m matrix) snapshot() time.Time {
	t := m.s.t
	t.Helper()
	img := m.etcdImage()
	out, err := exec.Command("docker", "run", "--rm", "--user", "0", "--network", project+"_port49",
		"-v", project+"_etcd-root:/etcd-root:ro", "-v", snapVolume+":/snap", "--entrypoint", "etcdctl", img,
		"--endpoints=https://etcd-1:2379", "--cacert=/etcd-root/ca.pem", "--cert=/etcd-root/root.pem",
		"--key=/etcd-root/root-key.pem", "snapshot", "save", "/snap/snap.db").CombinedOutput()
	if err != nil {
		t.Fatalf("etcdctl snapshot save: %v\n%s", err, shapetest.Filtered(m.root, string(out)))
	}
	return time.Now()
}

func (m matrix) etcdImage() string {
	t := m.s.t
	t.Helper()
	id := strings.TrimSpace(m.s.run("ps", "-aq", "etcd-1"))
	out, err := exec.Command("docker", "inspect", "-f", "{{.Config.Image}}", id).Output()
	if err != nil {
		t.Fatalf("docker inspect etcd-1: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// restoreMembers replaces each stopped member's data directory with the
// snapshot restored under that member's name and peer URL, revision bumped by
// 1000000 and marked compacted, as the runbook says.
func (m matrix) restoreMembers() {
	t := m.s.t
	t.Helper()
	img := m.etcdImage()
	for _, name := range members {
		vol := project + "_" + name + "-data"
		out, err := exec.Command("docker", "run", "--rm", "--user", "0", "-v", snapVolume+":/snap:ro", "-v", vol+":/var/lib/etcd",
			"--entrypoint", "etcdutl", img, "snapshot", "restore", "/snap/snap.db",
			"--bump-revision", "1000000", "--mark-compacted", "--name", name,
			"--initial-cluster", initialCluster, "--initial-cluster-token", "port49-compose",
			"--initial-advertise-peer-urls", "https://"+name+":2380", "--data-dir", "/var/lib/etcd/new").CombinedOutput()
		if err != nil {
			t.Fatalf("etcdutl snapshot restore for %s: %v\n%s", name, err, shapetest.Filtered(m.root, string(out)))
		}
		if out, err := exec.Command("docker", "run", "--rm", "-v", vol+":/d", "--entrypoint", "sh", "port49-setup:dev", "-c",
			"set -eu; rm -rf /d/member; mv /d/new/member /d/member; rmdir /d/new; chown -R 65532:65532 /d/member").CombinedOutput(); err != nil {
			t.Fatalf("swapping %s's data directory: %v\n%s", name, err, shapetest.Filtered(m.root, string(out)))
		}
	}
}

// restoreGuarded is the restore guard end to end (spec decision 36; Task 9a).
// TestStoreSnapshotRestore is lab-tagged on a bare etcd binary; on compose the
// same steps are spelled out.
func restoreGuarded(m matrix) {
	t := m.s.t
	// A killed run's snapshot must not be the one restored.
	exec.Command("docker", "volume", "rm", "-f", snapVolume).Run()
	t.Cleanup(func() { exec.Command("docker", "volume", "rm", "-f", snapVolume).Run() })
	const guarded, until = "port49_redemption_restore_guarded", "port49_redemption_restore_guard_until_timestamp_seconds"
	// The runner rewrites meta/witness once a second, and only when the store
	// moved (witnessPass). A restore is seen only if the witness it brings back
	// is older than the one port49d followed, so the stack is given three
	// passes after the login that moves it: a stop inside the first second
	// leaves the snapshot's witness current, and the guard rightly sees no
	// restore (runner.go keepWitness: "about the most of a snapshot's lead over
	// the last witness that the check cannot see").
	witnessMovesPast := func() { time.Sleep(3 * time.Second) }

	// Steps 1-3: a token minted before the snapshot and redeemed after it is
	// the replay a restore brings back.
	replay := m.mint()
	snapAt := m.snapshot()
	if !m.passes(replay) {
		t.Fatal("the login that moves the store past the snapshot did not pass")
	}
	witnessMovesPast()
	m.s.run("stop", "etcd-1", "etcd-2", "etcd-3")
	// Steps 4-5.
	m.restoreMembers()
	m.s.run("start", "etcd-1", "etcd-2", "etcd-3")

	// Step 6: guarded, and the token that was redeemed is refused, not redeemed again.
	shapetest.WaitFor(t, guarded+" at 1", 2*time.Minute, func() bool { return m.gauge(daemonMetrics, guarded) == 1 })
	if !m.refused(replay) {
		t.Fatal("a token redeemed after the snapshot logged in again after the restore")
	}
	// Step 9: the time bound is armed, at the snapshot's time + 15m + 5m at most.
	u := m.gauge(daemonMetrics, until)
	if u == 0 || u < float64(snapAt.Unix())-5 || u > float64(snapAt.Add(20*time.Minute+time.Minute).Unix()) {
		t.Fatalf("%s is %.0f, want non-zero and within 15m + 5m + 60s of the snapshot (%d)", until, u, snapAt.Unix())
	}
	// Step 7: the brokers' witness sees the restore and their purge lifts it.
	shapetest.WaitFor(t, guarded+" back at 0", 2*holdTTL, func() bool { return m.gauge(daemonMetrics, guarded) == 0 })
	next := m.mint()
	shapetest.WaitFor(t, "a fresh login", 20*time.Second, func() bool { return m.passes(next) })

	// Step 8: with the guard standing and no broker to purge, stopping port49d
	// leaves the device's connection refused at once.
	again := m.mint()
	m.snapshot()
	if !m.passes(again) {
		t.Fatal("the login after the second snapshot did not pass")
	}
	witnessMovesPast()
	m.s.run("stop", "port49-broker")
	m.s.run("stop", "etcd-1", "etcd-2", "etcd-3")
	m.restoreMembers()
	m.s.run("start", "etcd-1", "etcd-2", "etcd-3")
	shapetest.WaitFor(t, guarded+" at 1 with the brokers stopped", 2*time.Minute, func() bool { return m.gauge(daemonMetrics, guarded) == 1 })
	m.s.run("stop", "port49d")
	refusedAtOnce(t, "the guard standing and port49d stopped")
	fmt.Fprintln(os.Stderr, "failure matrix: restore guard held, lifted by the purge, and port49d stopped at the 3am escape; guard until "+strconv.FormatFloat(u, 'f', 0, 64))
}
