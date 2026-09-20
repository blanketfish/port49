//go:build lab

// Package lab drives port49d against real network OS images in containerlab and
// records what the devices actually do, for the lab register in the policy
// engine spec (§15).
//
// The shape of a run is set by one fact: these images are VMs and each boot
// costs minutes. So a topology is deployed ONCE per `go test` run, every
// register test runs against that already-booted device, and the topology is
// destroyed at the end. Platforms run one after another, never together: they
// share a management subnet, a bridge address, and port 49 on the host.
//
// A register test passes when the measurement was made and fails when it is
// inconclusive. Whichever way the device behaved is the result and goes in the
// results note; "the login never happened" or "no matching record reached the
// log" is a failure, because nothing was measured.
package lab

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type platform struct {
	sel     string // selector in PORT49_LAB_PLATFORMS
	name    string // platform name in results/L<N>-<platform>.md
	topo    string // topology path, relative to tests/lab
	addr    string // management address
	node    string // node name, which is also the NAS name in the inventory
	image   string // container image, matched against `docker image inspect`
	version string // image version for the results note

	// boot is how long this image is given to become usable. It is per platform
	// and measured on the host that runs the lab, not guessed. On the bare-metal
	// lab host (KVM, nested virtualisation enabled): vEOS answers a breakglass
	// login 57s after `containerlab deploy`; vJunos-router 23.4R2-S2.1 answers
	// one in 1m31s, the same figure on three consecutive deploys; vSRX 21.4R3.15
	// reports `Startup complete` at 57s and is serving SSH authentication about
	// 3 minutes in. The budgets are several times those, because a budget exists
	// to end a run that is not going to finish, not to race the device.
	//
	// vSRX spends its whole budget every run and there is nothing wrong with the
	// device. The gate is a breakglass login, and vSRX will not fall through
	// `authentication-order` to a local password while the TACACS+ server is
	// unreachable — see results/juniper_vsrx-config-verified.md. Its budget is
	// therefore the shortest one that still clears the 3 minutes it needs to
	// serve SSH, so the wait is not longer than it has to be.
	//
	// These numbers are a property of the host. The previous host could not boot
	// a vmhost Junos image at all — see tests/lab/README.md, "Why this needs bare
	// metal" — and a 35-minute budget there still measured nothing. If Junos
	// stops making the budget on some future host, measure the boot and change
	// the number; do not assume the device is broken.
	boot time.Duration
}

var platforms = []platform{
	{"eos", "arista_eos", "topologies/eos.clab.yml", "172.100.100.11", "leaf1",
		"vrnetlab/arista_veos:4.32.2F", "vEOS-lab 4.32.2F", 6 * time.Minute},
	{"vjunos", "juniper_vjunos-router", "topologies/vjunos.clab.yml", "172.100.100.21", "srx1",
		"vrnetlab/juniper_vjunos-router:23.4R2-S2.1", "vJunos-router 23.4R2-S2.1", 8 * time.Minute},
	{"vsrx", "juniper_vsrx", "topologies/vsrx.clab.yml", "172.100.100.22", "vsrx1",
		"vrnetlab/juniper_vsrx:21.4R3.15", "vSRX3 21.4R3.15", 6 * time.Minute},
}

const (
	// These four values also live in the startup configs and in
	// port49d-lab.yaml, and nothing makes the compiler check that they agree.
	// Editing a config to rename the breakglass account or change the shared
	// secret breaks the harness silently — the readiness gate stops passing, or
	// every device packet fails key trial — with no build error and no obvious
	// cause. They are named here so the coupling has somewhere to be documented,
	// and each config carries a comment pointing back at these names.
	labKeyDefault      = "labsecret"       // `tacacs-server host ... key`, `tacplus-server ... secret`
	breakglassUser     = "breakglass"      // the local account both startup configs define
	breakglassPassword = "breakglass-only" // that account's password, in both configs

	spoolPath = "/tmp/port49-lab-acct.jsonl"
	metricsAddr   = "127.0.0.1:9049"
	tacacsAddr    = "172.100.100.1:49"
	labSubnet     = "172.100.100.0/24"
	tokenPoolSize = 16

	// capProbeAddr is where the capture's liveness probe connects. Nothing
	// listens there — port49d binds the clab bridge address, never the
	// loopback — so the kernel answers with a RST and the probe is two packets
	// that match the capture filter and reach nothing under test.
	capProbeAddr = "127.0.0.1:49"

	// pcapHeaderSize is the 24-byte file header tcpdump writes when it opens a
	// savefile. A file this size has captured nothing.
	pcapHeaderSize = 24
)

// A device password of each of these lengths is seeded under user longpw<N>.
// L8 reads back which lengths arrived intact.
var passwordLengths = []int{30, 64, 128, 138}

// longDenyPrefix is the first entry of lab.deny_prefixes in port49d-lab.yaml.
// L2 types this exact line to see how much of a long server_msg a device shows.
var longDenyPrefix = "show clock | include " + strings.Repeat("A", 150)

// shortDenyPrefix is the last entry of lab.deny_prefixes. It is a command every
// platform accepts at any privilege level, so a denial is reached even if the
// device never applied priv-lvl=15.
const shortDenyPrefix = "show clock"

var (
	root    string // repository root, absolute
	labYAML string // contents of port49d-lab.yaml, for seed checks

	globalOnce sync.Once
	globalErr  error

	selOnce      sync.Once
	selPlatforms []platform
	selExplicit  bool
	selErr       error

	labsMu sync.Mutex
	labs   = map[string]*lab{}
	active *lab // the one platform currently deployed; see bringUp
)

type lab struct {
	p platform

	once sync.Once
	skip string // image absent: every test skips this platform
	err  error  // setup failed: every test fails this platform

	deployed bool
	daemon   *exec.Cmd
	logFile  *os.File
	errFile  *os.File
	logPath  string
	errPath  string

	// configWarn records that the device's SSH answered but the startup config
	// could not be confirmed applied. Not fatal on its own; the tests will say
	// so if the device then behaves as though it has no AAA configuration.
	configWarn string

	mu      sync.Mutex
	tokenN  int
	capPath string // repo-relative, for the results note
	capAbs  string // absolute, for reading the capture back
}

// ---------------------------------------------------------------------------
// Setup and teardown
// ---------------------------------------------------------------------------

// TestMain owns only the teardown. Bring-up is lazy — the first test that asks
// for a platform deploys it — so a run that matches no test (`-run XXX`, the
// compile check) deploys nothing and costs nothing.
//
// The signal handler is not decoration. An interrupted run that skips teardown
// leaves a port49d bound to the bridge address, and the next run's device then
// has its AAA answered by a daemon that run does not own: every measurement
// after that is of the wrong process, and the symptom (logins denied for no
// visible reason) points nowhere near the cause.
func TestMain(m *testing.M) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		s := <-sig
		fmt.Fprintf(os.Stderr, "\nlab: %v received, tearing down before exit\n", s)
		teardown()
		os.Exit(1)
	}()
	code := m.Run()
	teardown()
	os.Exit(code)
}

// initGlobal does the once-per-run work that every platform needs: find the
// repository root, read the daemon config the tests check their seeds against,
// and give the built binary the capability to bind port 49 unprivileged.
func initGlobal() error {
	r, err := repoRoot()
	if err != nil {
		return err
	}
	root = r

	raw, err := os.ReadFile(filepath.Join(root, "tests", "lab", "port49d-lab.yaml"))
	if err != nil {
		return err
	}
	labYAML = string(raw)

	bin := filepath.Join(root, "bin", "port49d")
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("%s is not built; run `make build` first: %w", bin, err)
	}
	// Port 49 is privileged and the daemon runs unprivileged, so the binary
	// needs the capability. Say the exact command if this fails; a harness that
	// silently ran the daemon as root would be measuring a different thing.
	if out, err := exec.Command("sudo", "-n", "setcap", "cap_net_bind_service=+ep", bin).CombinedOutput(); err != nil {
		return fmt.Errorf("setcap failed (%v): %s\nrun: sudo setcap cap_net_bind_service=+ep %s", err, out, bin)
	}
	return nil
}

// bringUp deploys this platform and starts its daemon, once per run. Every
// register test then measures against the device it left running.
//
// Only one platform can be up at a time: they share the management subnet, the
// bridge address, and port 49 on the host. So bringing one up takes the
// previous one down. That makes a run that selects several platforms correct
// but slow — the platforms cycle once per test rather than once per run — which
// is why `make lab` runs one `go test` per platform instead of one for all.
func (l *lab) bringUp() {
	labsMu.Lock()
	prev := active
	active = l
	labsMu.Unlock()
	if prev != nil && prev != l {
		fmt.Fprintf(os.Stderr, "lab: taking %s down to bring %s up; run one platform per `go test` to avoid this\n",
			prev.p.name, l.p.name)
		prev.down()
		prev.resetForRedeploy()
	}
	l.deploy()
}

// resetForRedeploy lets a platform be brought up again later in the same run.
func (l *lab) resetForRedeploy() {
	l.once = sync.Once{}
	l.err = nil
	l.mu.Lock()
	l.tokenN = 0
	l.mu.Unlock()
}

func (l *lab) deploy() {
	if err := func() error {
		globalOnce.Do(func() { globalErr = initGlobal() })
		return globalErr
	}(); err != nil {
		l.err = err
		return
	}
	if exec.Command("docker", "image", "inspect", l.p.image).Run() != nil {
		absent := "image " + l.p.image + " is not present"
		if _, explicit, _ := platformSelection(); explicit {
			l.err = fmt.Errorf("%s, and this run named %q on PORT49_LAB_PLATFORMS; "+
				"a named platform that measures nothing is a failed run, not a skip. "+
				"Build it (tests/lab/README.md) or drop it from the selection", absent, l.p.sel)
			fmt.Fprintf(os.Stderr, "lab: %s: %v\n", l.p.name, l.err)
			return
		}
		l.skip = absent
		fmt.Fprintf(os.Stderr, "lab: %s: %s, skipping\n", l.p.name, l.skip)
		return
	}
	fmt.Fprintf(os.Stderr, "lab: %s: deploying %s\n", l.p.name, l.p.topo)
	start := time.Now()
	if err := l.up(); err != nil {
		l.err = err
		fmt.Fprintf(os.Stderr, "lab: %s: setup failed after %v: %v\n", l.p.name, time.Since(start).Round(time.Second), err)
		l.diagnose()
		return
	}
	fmt.Fprintf(os.Stderr, "lab: %s: ready after %v\n", l.p.name, time.Since(start).Round(time.Second))
}

// platformSelection reads PORT49_LAB_PLATFORMS once and says both which
// platforms to run and whether the run named them.
//
// The second half matters more than it looks. When nothing is named, an absent
// image skips its platform on purpose: one built image is enough to start, and
// `make lab` on a half-provisioned machine should still measure what it can.
// When a platform *is* named, that same skip is a run that measured nothing and
// exited 0, which is how a `make lab` over several platforms sails past one that
// never ran. So a named platform is a promise to measure it, and anything that
// stops it from being measured is an error.
//
// A selector that matches no platform is the same trap spelled differently:
// `PORT49_LAB_PLATFORMS=vjuno make lab` used to run zero tests and report
// success.
func platformSelection() ([]platform, bool, error) {
	selOnce.Do(func() {
		want := strings.TrimSpace(os.Getenv("PORT49_LAB_PLATFORMS"))
		if want == "" {
			selPlatforms = platforms
			return
		}
		selExplicit = true
		var known []string
		for _, p := range platforms {
			known = append(known, p.sel)
		}
		for _, s := range strings.Split(want, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			found := false
			for _, p := range platforms {
				if p.sel == s {
					selPlatforms = append(selPlatforms, p)
					found = true
					break
				}
			}
			if !found {
				selErr = fmt.Errorf("PORT49_LAB_PLATFORMS names %q, which is not a platform; known selectors are %s",
					s, strings.Join(known, ", "))
				return
			}
		}
		if len(selPlatforms) == 0 {
			selErr = fmt.Errorf("PORT49_LAB_PLATFORMS is %q, which selects no platform; known selectors are %s",
				want, strings.Join(known, ", "))
		}
	})
	return selPlatforms, selExplicit, selErr
}

// repoRoot resolves the repository root once. Everything the harness runs uses
// absolute paths built from it: a relative path in exec.Command depends on the
// test binary's working directory, which is not the root.
func repoRoot() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err == nil {
		if d := strings.TrimSpace(string(out)); d != "" {
			return d, nil
		}
	}
	d, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d, nil
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", fmt.Errorf("lab: no go.mod above %q; cannot find the repository root", d)
		}
		d = parent
	}
}

func (l *lab) topoPath() string { return filepath.Join(root, "tests", "lab", l.p.topo) }

// up deploys the topology, waits for the device, then starts the daemon. The
// order matters twice over: port49d binds the clab bridge's .1 address, which
// does not exist until the deploy creates the network; and a device whose AAA
// points at a port49 that is already answering would have no local fallback
// while it is still booting.
func (l *lab) up() error {
	topo := l.topoPath()
	out, err := exec.Command("sudo", "-n", "containerlab", "deploy", "--reconfigure", "-t", topo).CombinedOutput()
	if err != nil {
		return fmt.Errorf("containerlab deploy: %w\n%s", err, out)
	}
	l.deployed = true

	// Readiness is a successful breakglass login and nothing weaker. Every
	// cheaper signal proved false on the vJunos-router image: vrnetlab forwards
	// port 22 into the VM, so the TCP connect succeeds immediately, and
	// something answered a banner and even a key exchange around 40 seconds in
	// while Junos itself was still minutes from serving SSH. A breakglass login
	// cannot be faked by whatever answers first — that account exists only in
	// the config from tests/lab/configs, and port49 is not listening yet, so
	// reaching it also proves the device fell back to local as intended.
	//
	// waitSSH still runs first, for an early sign of life in the log, but it is
	// advisory and capped: on this image the banner never appeared at all for
	// the first four minutes, and letting that consume the boot budget would
	// starve the gate that actually decides.
	deadline := time.Now().Add(l.p.boot)
	if err := waitSSH(l.p.addr, min(2*time.Minute, time.Until(deadline))); err != nil {
		fmt.Fprintf(os.Stderr, "lab: %s: no SSH banner yet (%v); still waiting for a login\n", l.p.name, err)
	}
	// This gate gets the whole remaining boot budget, and the reason is a run
	// that was thrown away. It used to be capped at 8 minutes, on the theory
	// that the register tests could still say something against a device whose
	// local login had not come up. On vJunos-router that theory cost 17 minutes
	// and measured nothing: the gate gave up at 8m23s while the VM was still
	// mounting Junos packages, then all six register tests ran against a device
	// whose SSH would not complete a handshake, and every one of them failed on
	// the same i/o timeout. Waiting is what the budget is for; if the budget is
	// wrong, the budget is what to change.
	if err := l.waitConfigApplied(time.Until(deadline)); err != nil {
		// Not fatal: the register tests still run and report exactly what they
		// see, which is more useful than a bare setup failure. Every results
		// note carries this caveat.
		l.configWarn = err.Error()
		fmt.Fprintf(os.Stderr, "lab: %s: WARNING: %v\n", l.p.name, err)
	}

	// A spool left by an earlier run would drain into this run's log and be
	// read as this run's accounting.
	os.Remove(spoolPath)
	os.Remove(spoolPath + ".draining")

	return l.startDaemon()
}

func (l *lab) startDaemon() error {
	// Refuse to run beside a daemon this run does not own. A leftover port49d
	// still holds its socket on the bridge address even across a destroy and
	// redeploy, and it would answer this device's AAA with its own spent
	// tokens — measurements of the wrong process, with no symptom that says so.
	if c, err := net.DialTimeout("tcp", tacacsAddr, 2*time.Second); err == nil {
		c.Close()
		return fmt.Errorf("something is already listening on %s, most likely a port49d left by an interrupted run. "+
			"It would answer this device's AAA instead of the daemon this run starts. Find and stop it:\n"+
			"  sudo ss -lptn 'sport = :49'\n  pkill -f 'port49d -config .*tests/lab/port49d-lab.yaml'", tacacsAddr)
	}

	dir := filepath.Join(root, "tests", "lab", "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	l.logPath = filepath.Join(dir, "decisions-"+l.p.name+".jsonl")
	l.errPath = filepath.Join(dir, "port49d-"+l.p.name+".log")
	var err error
	if l.logFile, err = os.Create(l.logPath); err != nil {
		return err
	}
	if l.errFile, err = os.Create(l.errPath); err != nil {
		return err
	}

	key := os.Getenv("PORT49_LAB_KEY")
	if key == "" {
		key = labKeyDefault
	}
	l.daemon = exec.Command(filepath.Join(root, "bin", "port49d"),
		"-config", filepath.Join(root, "tests", "lab", "port49d-lab.yaml"))
	l.daemon.Dir = root
	l.daemon.Stdout = l.logFile
	l.daemon.Stderr = io.MultiWriter(l.errFile, os.Stderr)
	l.daemon.Env = append(os.Environ(), "PORT49_LAB_KEY="+key)
	if err := l.daemon.Start(); err != nil {
		return fmt.Errorf("start port49d: %w", err)
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if daemonHealthy() {
			return nil
		}
		if l.daemon.ProcessState != nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	stderr, _ := os.ReadFile(l.errPath)
	return fmt.Errorf("port49d did not come up within 30s; its stderr was:\n%s", stderr)
}

func daemonHealthy() bool {
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + metricsAddr + "/healthz")
	if err != nil {
		return false
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	c, err := net.DialTimeout("tcp", tacacsAddr, 2*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// waitSSH waits for the device's SSH to answer with a banner. It deliberately
// does not attempt authentication: an auth attempt against a device whose AAA
// is half-configured can hang for the TACACS timeout, and this is only asking
// whether the VM has finished booting.
func waitSSH(addr string, within time.Duration) error {
	deadline := time.Now().Add(within)
	var last error
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr+":22", 5*time.Second)
		if err != nil {
			last = err
			time.Sleep(5 * time.Second)
			continue
		}
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 64)
		n, rerr := c.Read(buf)
		c.Close()
		if rerr == nil && n > 0 && strings.HasPrefix(string(buf[:n]), "SSH-") {
			return nil
		}
		last = rerr
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("%s: SSH never answered within %v (last error: %v)", addr, within, last)
}

func (l *lab) waitConfigApplied(within time.Duration) error {
	deadline := time.Now().Add(within)
	var last error
	for time.Now().Before(deadline) {
		c, err := l.dial("breakglass", "breakglass-only", 30*time.Second)
		if err == nil {
			c.Close()
			return nil
		}
		last = err
		time.Sleep(10 * time.Second)
	}
	return fmt.Errorf("could not confirm the startup config was applied: breakglass never logged in within %v (last error: %v)", within, last)
}

// diagnose collects what an operator would want after a platform failed to come
// up, so the run's output carries the evidence without a second trip to the host.
func (l *lab) diagnose() {
	out, _ := exec.Command("sudo", "-n", "containerlab", "inspect", "-t", l.topoPath()).CombinedOutput()
	fmt.Fprintf(os.Stderr, "lab: %s: containerlab inspect:\n%s\n", l.p.name, out)
	name := "clab-" + strings.TrimSuffix(filepath.Base(l.p.topo), ".clab.yml") + "-" + l.p.node
	// The container name is derived from the topology's `name:`, not its file
	// name; ask docker for anything that looks like this node.
	ids, _ := exec.Command("docker", "ps", "-a", "--filter", "name="+l.p.node, "--format", "{{.Names}}").Output()
	for _, n := range strings.Fields(string(ids)) {
		logs, _ := exec.Command("docker", "logs", "--tail", "50", n).CombinedOutput()
		fmt.Fprintf(os.Stderr, "lab: %s: docker logs --tail 50 %s:\n%s\n", l.p.name, n, logs)
	}
	_ = name
}

func teardown() {
	labsMu.Lock()
	defer labsMu.Unlock()
	for _, l := range labs {
		l.down()
	}
}

func (l *lab) down() {
	if l.daemon != nil && l.daemon.Process != nil {
		// SIGTERM, not Kill: the daemon drains the accounting spool on the way
		// out, and a record still on disk is a record this run did not see.
		_ = l.daemon.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { l.daemon.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			_ = l.daemon.Process.Kill()
			<-done
		}
		l.daemon = nil
	}
	if l.logFile != nil {
		l.logFile.Close()
		l.logFile = nil
	}
	if l.errFile != nil {
		l.errFile.Close()
		l.errFile = nil
	}
	if l.deployed {
		out, err := exec.Command("sudo", "-n", "containerlab", "destroy", "-t", l.topoPath(), "--cleanup").CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "lab: %s: destroy failed: %v\n%s\n", l.p.name, err, out)
		}
		l.deployed = false
	}
}

// labFor returns the platform, deploying it on first use. It skips when the
// image is absent and fails when the bring-up failed: a platform that never
// came up has measured nothing, which is a failure, not a pass.
func labFor(t *testing.T, p platform) *lab {
	t.Helper()
	labsMu.Lock()
	l, ok := labs[p.name]
	if !ok {
		l = &lab{p: p}
		labs[p.name] = l
	}
	labsMu.Unlock()
	l.once.Do(l.bringUp)
	if l.skip != "" {
		t.Skipf("%s: %s", p.name, l.skip)
	}
	if l.err != nil {
		t.Fatalf("%s: platform never came up, so nothing could be measured: %v", p.name, l.err)
	}
	return l
}

// eachPlatform runs fn as a subtest per selected platform.
func eachPlatform(t *testing.T, fn func(t *testing.T, l *lab)) {
	sel, _, err := platformSelection()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range sel {
		p := p
		t.Run(p.name, func(t *testing.T) { fn(t, labFor(t, p)) })
	}
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

// nextLogin hands out the next unspent seeded login: a username and the token
// seeded under it. Two things make each login need its own username.
//
// Redemption deletes the token, so every login in a run spends one. And EOS
// reports `port` as the constant string "ssh" (L1), which makes the receipt key
// (nas, port, username) identical for every SSH login by one user: a second
// login inside receipt_ttl presents a different token against the first login's
// receipt and is refused as credential_mismatch. A username per login gives
// each its own receipt key, so the harness measures the device rather than that
// collision.
func (l *lab) nextLogin(t *testing.T) (user, secret string) {
	t.Helper()
	l.mu.Lock()
	n := l.tokenN + 1
	l.tokenN = n
	l.mu.Unlock()
	if n > tokenPoolSize {
		t.Fatalf("%s: the seeded login pool of %d is exhausted; seed more in tests/lab/port49d-lab.yaml", l.p.name, tokenPoolSize)
	}
	user, secret = fmt.Sprintf("alice%02d", n), fmt.Sprintf("p49_labtoken%02d", n)
	mustBeSeeded(t, secret)
	if !strings.Contains(labYAML, "username: "+user+",") {
		t.Fatalf("tests/lab/port49d-lab.yaml seeds no login for %q; the harness and the config have drifted apart", user)
	}
	return user, secret
}

// passwordOfLength is the seeded secret for user longpw<n>. The test computes
// it rather than copying it, and mustBeSeeded proves the YAML agrees.
func passwordOfLength(n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	s := "p49_" + strings.Repeat(alphabet, 4)
	return s[:n]
}

func mustBeSeeded(t *testing.T, secret string) {
	t.Helper()
	if !strings.Contains(labYAML, secret) {
		t.Fatalf("tests/lab/port49d-lab.yaml does not seed the secret this test uses (%d characters, starting %q); the two have drifted apart",
			len(secret), secret[:min(16, len(secret))])
	}
}

// ---------------------------------------------------------------------------
// SSH
// ---------------------------------------------------------------------------

// dial opens an SSH connection. The algorithm lists are deliberately wide:
// these are shipping network OS images, some of them years old, and a handshake
// this client refuses would look exactly like a device that failed to boot.
func (l *lab) dial(user, password string, timeout time.Duration) (*ssh.Client, error) {
	nc, err := net.DialTimeout("tcp", l.p.addr+":22", timeout)
	if err != nil {
		return nil, err
	}
	if err := nc.SetDeadline(time.Now().Add(timeout)); err != nil {
		nc.Close()
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = password
				}
				return answers, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
		HostKeyAlgorithms: []string{
			"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
			"rsa-sha2-512", "rsa-sha2-256", "ssh-rsa", "ssh-dss",
		},
		Config: ssh.Config{
			KeyExchanges: []string{
				"curve25519-sha256", "curve25519-sha256@libssh.org",
				"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
				"diffie-hellman-group-exchange-sha256",
				"diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512",
				"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1",
			},
			Ciphers: []string{
				"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
				"chacha20-poly1305@openssh.com",
				"aes128-ctr", "aes192-ctr", "aes256-ctr",
				"aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc",
			},
			MACs: []string{
				"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
				"hmac-sha2-256", "hmac-sha2-512", "hmac-sha1",
			},
		},
	}
	c, chans, reqs, err := ssh.NewClientConn(nc, l.p.addr+":22", cfg)
	if err != nil {
		nc.Close()
		return nil, err
	}
	nc.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

// login opens an SSH session with the given password (a seeded token) and runs
// commands, returning combined output per command. A command that the device
// rejects is not an error here: its output is the measurement.
func (l *lab) login(user, password string, commands ...string) ([]string, error) {
	c, err := l.dial(user, password, 45*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	var outs []string
	for _, cmd := range commands {
		s, err := c.NewSession()
		if err != nil {
			return outs, err
		}
		var buf bytes.Buffer
		s.Stdout, s.Stderr = &buf, &buf
		_ = s.Run(cmd)
		outs = append(outs, buf.String())
		s.Close()
	}
	return outs, nil
}

// holdSession opens an interactive shell with a pty and holds it idle for d.
// That is the session shape a WATCHDOG is sent for: a logged-in operator who is
// not typing.
func (l *lab) holdSession(user, password string, d time.Duration) error {
	c, err := l.dial(user, password, 45*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	s, err := c.NewSession()
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.RequestPty("vt100", 40, 120, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		return fmt.Errorf("request pty: %w", err)
	}
	stdin, err := s.StdinPipe()
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	s.Stdout, s.Stderr = &buf, &buf
	if err := s.Shell(); err != nil {
		return fmt.Errorf("start shell: %w", err)
	}
	time.Sleep(d)
	stdin.Close()
	go s.Wait()
	return nil
}

// ---------------------------------------------------------------------------
// The decision log
// ---------------------------------------------------------------------------

// mark returns the current end of the decision log. Every platform is deployed
// once and every test shares one daemon, so a test reads only the records
// written after its own mark.
func (l *lab) mark() int64 {
	fi, err := os.Stat(l.logPath)
	if err != nil {
		return 0
	}
	return fi.Size()
}

func (l *lab) recordsSince(off int64) []map[string]any {
	f, err := os.Open(l.logPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil
	}
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) == nil {
			out = append(out, m)
		}
	}
	return out
}

// waitForRecords polls until want is satisfied or the timeout expires, and
// returns whatever the log held at the end either way. Accounting in
// particular arrives after the exchange, by way of the durable spool.
func (l *lab) waitForRecords(off int64, timeout time.Duration, want func([]map[string]any) bool) []map[string]any {
	deadline := time.Now().Add(timeout)
	var recs []map[string]any
	for {
		recs = l.recordsSince(off)
		if want(recs) || !time.Now().Before(deadline) {
			return recs
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func sub(m map[string]any, key string) map[string]any {
	s, _ := m[key].(map[string]any)
	return s
}

func strs(m map[string]any, key string) []string {
	raw, _ := m[key].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func recTime(m map[string]any) (time.Time, bool) {
	t, err := time.Parse("2006-01-02T15:04:05.000Z07:00", str(m, "ts"))
	return t, err == nil
}

// summarize renders the records a failing test saw, so the failure says what
// did arrive rather than only what did not.
func summarize(recs []map[string]any) string {
	if len(recs) == 0 {
		return "(no records at all reached the decision log)"
	}
	var b strings.Builder
	for _, r := range recs {
		fmt.Fprintf(&b, "\n  event=%s verdict=%s reason=%s flags=%s", str(r, "event"), str(r, "verdict"), str(r, "reason"), str(r, "flags"))
		if s := sub(r, "session"); s != nil {
			fmt.Fprintf(&b, " user=%s port=%s", str(s, "username"), str(s, "port"))
		}
		if u := sub(r, "unvalidated"); u != nil {
			fmt.Fprintf(&b, " unvalidated_diagnosis=%s", str(u, "diagnosis"))
		}
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Captures
// ---------------------------------------------------------------------------

// capture runs tcpdump around a test.
//
// Two flags and two probes, and each one is here because its absence cost a
// measurement. `--immediate-mode` is the important one: without it libpcap
// hands tcpdump the kernel's ring buffer on a one-second read timeout, so a
// test that stops the capture within a second of its last packet loses that
// packet. That is exactly what happened to the first vEOS run — L10's whole
// exchange lasted 263ms and was never written, leaving a 24-byte file beside a
// results note that claimed a measurement, and L6 and L8 each lost their
// accounting tail the same way. `-U` then flushes each packet to the file as it
// is written, so the file is complete even if tcpdump is killed rather than
// interrupted.
//
// The probes turn "tcpdump is running" into "this file is capturing". One at
// the start must appear in the file before the test is allowed to generate
// traffic; one at the end must appear before tcpdump is stopped, which proves
// by ordering that everything the test produced is already on disk. They are
// loopback packets, so they never appear in the device-packet count a results
// note reports.
func (l *lab) capture(t *testing.T, name string) func() {
	t.Helper()
	dir := filepath.Join(root, "tests", "lab", "captures")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("captures directory: %v", err)
	}
	abs := filepath.Join(dir, fmt.Sprintf("%s-%s.pcap", name, l.p.name))
	l.capPath = filepath.Join("tests/lab/captures", filepath.Base(abs))
	l.capAbs = abs

	// tcpdump runs as root under sudo and drops privileges to its own user, so
	// it cannot be signalled directly and its pid is not the pid of sudo. The
	// shell wrapper writes the pid the harness must signal. Matching on the
	// command line instead would be one typo away from a capture that is never
	// stopped and a run that waits on it forever.
	pidPath := abs + ".pid"
	os.Remove(pidPath)
	os.Remove(abs)
	script := fmt.Sprintf("echo $$ > %s; exec tcpdump --immediate-mode -i any -U -n -s 0 -w %s 'tcp port 49'",
		shellQuote(pidPath), shellQuote(abs))
	cmd := exec.Command("sudo", "-n", "sh", "-c", script)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start tcpdump: %v", err)
	}
	// A test that runs without a live capture measures without evidence, and a
	// results note may not point at a capture that holds nothing, so this is
	// fatal rather than a warning.
	if err := waitCaptureLive(abs); err != nil {
		t.Fatalf("the capture for %s never became live, so this test would measure without evidence: %v\ntcpdump said: %s",
			abs, err, errBuf.String())
	}

	stopped := false
	return func() {
		if stopped {
			return
		}
		stopped = true
		l.flushCapture(t)
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		signalCapture(pidPath, "-INT")
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			signalCapture(pidPath, "-KILL")
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				// -U wrote every packet through as it arrived, so the file is
				// complete and readable whatever this process is now doing.
				t.Logf("WARNING: tcpdump for %s did not exit; the capture is still valid but a process was left behind", abs)
			}
		}
		// tcpdump wrote the file as its own dropped-privilege user.
		_ = exec.Command("sudo", "-n", "chown", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), abs).Run()
		os.Remove(pidPath)
		total, device, err := pcapCounts(abs)
		if err != nil {
			t.Logf("could not read the capture %s back (%v); tcpdump said: %s", abs, err, errBuf.String())
			return
		}
		t.Logf("capture %s: %d packets, %d of them between the device and port49d", abs, total, device)
		if device == 0 {
			t.Logf("WARNING: the capture %s holds no TACACS packet to or from %s; tcpdump said: %s",
				abs, labSubnet, errBuf.String())
		}
	}
}

// flushCapture makes tcpdump prove it has written everything the test produced,
// by sending a probe and waiting for it to reach the file. Packets are written
// in the order they arrive, so a probe that is on disk means every earlier
// packet is too. It is called both before the capture is stopped and before a
// results note quotes the capture, and is safe to call repeatedly.
func (l *lab) flushCapture(t *testing.T) {
	t.Helper()
	if l.capAbs == "" {
		return
	}
	before := pcapSize(l.capAbs)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		capProbe()
		for i := 0; i < 10 && time.Now().Before(deadline); i++ {
			if pcapSize(l.capAbs) > before {
				// A short settle: the probe's own RST follows its SYN.
				time.Sleep(200 * time.Millisecond)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	t.Logf("WARNING: the capture %s did not grow when probed, so its tail may be short", l.capAbs)
}

// waitCaptureLive blocks until a probe packet has reached the capture file,
// which is the only proof that tcpdump has its socket open, its filter set, and
// its savefile written to. A running tcpdump process is not that proof.
func waitCaptureLive(path string) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		capProbe()
		for i := 0; i < 10 && time.Now().Before(deadline); i++ {
			if pcapSize(path) > pcapHeaderSize {
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	return fmt.Errorf("no probe packet reached %s within 30s", path)
}

// capProbe generates the two loopback packets that prove a capture is live: a
// SYN to a port nothing listens on, and the kernel's RST.
func capProbe() {
	c, err := net.DialTimeout("tcp", capProbeAddr, 500*time.Millisecond)
	if err == nil {
		c.Close()
	}
}

func pcapSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// pcapCounts reads a capture back and returns how many packets it holds and how
// many of those are to or from the lab management subnet. The second number is
// the one a results note may rest on: it excludes the harness's own loopback
// liveness probes, so a note that quotes a capture is quoting device traffic.
//
// The parser handles only what this harness produces — a little-endian pcap of
// `-i any`, which on Linux is LINUX_SLL2 — and reports what it cannot read
// rather than guessing.
func pcapCounts(path string) (total, device int, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	if len(raw) < pcapHeaderSize {
		return 0, 0, fmt.Errorf("%s is %d bytes, shorter than a pcap file header", path, len(raw))
	}
	magic := binary.LittleEndian.Uint32(raw[0:4])
	if magic != 0xa1b2c3d4 && magic != 0xa1b23c4d {
		return 0, 0, fmt.Errorf("%s: unexpected pcap magic %#x; this parser reads only little-endian pcap", path, magic)
	}
	link := binary.LittleEndian.Uint32(raw[20:24])

	_, subnet, err := net.ParseCIDR(labSubnet)
	if err != nil {
		return 0, 0, err
	}

	for off := pcapHeaderSize; off+16 <= len(raw); {
		inclLen := int(binary.LittleEndian.Uint32(raw[off+8 : off+12]))
		off += 16
		if inclLen < 0 || off+inclLen > len(raw) {
			return total, device, fmt.Errorf("%s: truncated packet record at offset %d", path, off)
		}
		total++
		if src, dst, ok := ipv4Of(link, raw[off:off+inclLen]); ok && (subnet.Contains(src) || subnet.Contains(dst)) {
			device++
		}
		off += inclLen
	}
	return total, device, nil
}

// ipv4Of pulls the source and destination address out of one captured packet.
func ipv4Of(link uint32, b []byte) (src, dst net.IP, ok bool) {
	var hdr int
	var proto uint16
	switch link {
	case 276: // LINUX_SLL2, what `-i any` produces on Linux
		hdr, proto = 20, 0
		if len(b) < hdr {
			return nil, nil, false
		}
		proto = binary.BigEndian.Uint16(b[0:2])
	case 113: // LINUX_SLL
		hdr = 16
		if len(b) < hdr {
			return nil, nil, false
		}
		proto = binary.BigEndian.Uint16(b[14:16])
	case 1: // Ethernet
		hdr = 14
		if len(b) < hdr {
			return nil, nil, false
		}
		proto = binary.BigEndian.Uint16(b[12:14])
	default:
		return nil, nil, false
	}
	if proto != 0x0800 || len(b) < hdr+20 {
		return nil, nil, false
	}
	ip := b[hdr:]
	if ip[0]>>4 != 4 {
		return nil, nil, false
	}
	return net.IP(ip[12:16]), net.IP(ip[16:20]), true
}

func signalCapture(pidPath, sig string) {
	out, err := exec.Command("sudo", "-n", "cat", pidPath).Output()
	if err != nil {
		return
	}
	pid := strings.TrimSpace(string(out))
	if pid == "" {
		return
	}
	// The shell exec'd into tcpdump, so this pid is tcpdump's own.
	_ = exec.Command("sudo", "-n", "kill", sig, pid).Run()
}

// shellQuote wraps a path for the `sudo sh -c` wrapper above.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// ---------------------------------------------------------------------------
// Results notes
// ---------------------------------------------------------------------------

// result writes tests/lab/results/L<N>-<platform>.md in the form spec §15 rule
// 3 requires: platform, image version, observation, and a pointer to the
// capture.
//
// The capture line reports how many packets the file actually holds between the
// device and port49d, read back from the file at the moment the note is
// written. A note whose capture holds none of them cannot close a register row,
// and says so in place of a pointer that would imply evidence it does not have.
func (l *lab) result(t *testing.T, entry, claim, observation string) {
	t.Helper()
	dir := filepath.Join(root, "tests", "lab", "results")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("results directory: %v", err)
	}
	l.flushCapture(t)
	capLine := fmt.Sprintf("`%s`", l.capPath)
	if total, device, err := pcapCounts(l.capAbs); err != nil {
		capLine += fmt.Sprintf(" — **could not be read back** (%v), so this note quotes the decision log only", err)
		t.Errorf("the capture %s could not be read back: %v", l.capAbs, err)
	} else if device == 0 {
		capLine += fmt.Sprintf(" — **empty of device traffic**: %d packets, none of them to or from %s. "+
			"This note's observation rests on the decision log alone and cannot close a register row.", total, labSubnet)
		t.Errorf("the capture %s holds no packet to or from %s, so this measurement has no capture to point at",
			l.capAbs, labSubnet)
	} else {
		// The device-packet count, not the file's total: the harness brackets
		// every capture with loopback probes and adds one more pair when it
		// stops the capture, after this note is written. Counting only what
		// crossed the bridge gives a number the reader can reproduce.
		capLine += fmt.Sprintf(" — %d packets to or from the device, countable with "+
			"`tcpdump -r %s -n 'net %s' | wc -l`", device, l.capPath, labSubnet)
	}

	path := filepath.Join(dir, fmt.Sprintf("%s-%s.md", entry, l.p.name))
	var b strings.Builder
	fmt.Fprintf(&b, "# %s — %s\n\n", entry, l.p.name)
	fmt.Fprintf(&b, "- **Date measured:** %s\n", time.Now().UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "- **Platform:** %s (containerlab node `%s`, %s)\n", l.p.name, l.p.node, l.p.addr)
	fmt.Fprintf(&b, "- **Image version:** %s (`%s`)\n", l.p.version, l.p.image)
	fmt.Fprintf(&b, "- **Topology:** `tests/lab/%s`\n", l.p.topo)
	fmt.Fprintf(&b, "- **Capture:** %s\n", capLine)
	fmt.Fprintf(&b, "- **Transport:** SSH\n")
	if l.configWarn != "" {
		fmt.Fprintf(&b, "- **Caveat:** %s\n", l.configWarn)
	}
	fmt.Fprintf(&b, "\n## Claim\n\n%s\n\n## Observation\n\n%s\n", claim, observation)
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	t.Logf("wrote %s", path)
}

// ---------------------------------------------------------------------------
// The round trip everything else depends on
// ---------------------------------------------------------------------------

func TestLoginRoundTrip(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		stop := l.capture(t, "login")
		defer stop()
		off := l.mark()

		user, secret := l.nextLogin(t)
		out, err := l.login(user, secret, "show version")
		if err != nil {
			t.Fatalf("SSH login as %s failed, so no exchange happened: %v\nrecords:%s", user, err, summarize(l.recordsSince(off)))
		}
		if len(out) == 0 || strings.TrimSpace(out[0]) == "" {
			t.Logf("`show version` produced no output; the login itself is what this test asserts")
		}

		recs := l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
			return hasRedeem(rs) && hasSessionAuthz(rs)
		})
		if !hasRedeem(recs) {
			t.Fatalf("no successful redeem reached the decision log:%s", summarize(recs))
		}
		if !hasSessionAuthz(recs) {
			t.Fatalf("no authorize_session reached the decision log:%s", summarize(recs))
		}
		t.Logf("%s: login round trip complete; %d records", l.p.name, len(recs))
	})
}

func hasRedeem(recs []map[string]any) bool {
	for _, r := range recs {
		if str(r, "event") == "redeem" && str(r, "reason") == "token_redeemed" {
			return true
		}
	}
	return false
}

func hasSessionAuthz(recs []map[string]any) bool {
	for _, r := range recs {
		if str(r, "event") == "authorize_session" {
			return true
		}
	}
	return false
}
