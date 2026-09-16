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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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
}

var platforms = []platform{
	{"eos", "arista_eos", "topologies/eos.clab.yml", "172.100.100.11", "leaf1",
		"vrnetlab/arista_veos:4.32.2F", "vEOS-lab 4.32.2F"},
	{"vjunos", "juniper_vjunos-router", "topologies/vjunos.clab.yml", "172.100.100.21", "srx1",
		"vrnetlab/juniper_vjunos-router:23.4R2-S2.1", "vJunos-router 23.4R2-S2.1"},
	{"vsrx", "juniper_vsrx", "topologies/vsrx.clab.yml", "172.100.100.22", "vsrx1",
		"vrnetlab/juniper_vsrx:21.4R3.15", "vSRX3 21.4R3.15"},
}

const (
	labKeyDefault = "labsecret"
	spoolPath     = "/tmp/port49-lab-acct.jsonl"
	metricsAddr   = "127.0.0.1:9049"
	tacacsAddr    = "172.100.100.1:49"
	tokenPoolSize = 16
	bootWait      = 6 * time.Minute
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

	labsMu sync.Mutex
	labs   = map[string]*lab{}
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
	capPath string
}

// ---------------------------------------------------------------------------
// Setup and teardown
// ---------------------------------------------------------------------------

// TestMain owns only the teardown. Bring-up is lazy — the first test that asks
// for a platform deploys it — so a run that matches no test (`-run XXX`, the
// compile check) deploys nothing and costs nothing.
func TestMain(m *testing.M) {
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
func (l *lab) bringUp() {
	if err := func() error {
		globalOnce.Do(func() { globalErr = initGlobal() })
		return globalErr
	}(); err != nil {
		l.err = err
		return
	}
	if exec.Command("docker", "image", "inspect", l.p.image).Run() != nil {
		l.skip = "image " + l.p.image + " is not present"
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

func selectedPlatforms() []platform {
	want := os.Getenv("PORT49_LAB_PLATFORMS")
	if strings.TrimSpace(want) == "" {
		return platforms
	}
	set := map[string]bool{}
	for _, s := range strings.Split(want, ",") {
		set[strings.TrimSpace(s)] = true
	}
	var out []platform
	for _, p := range platforms {
		if set[p.sel] {
			out = append(out, p)
		}
	}
	return out
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

	if err := waitSSH(l.p.addr, bootWait); err != nil {
		return err
	}
	// The device's SSH answering is not the same as its startup config being
	// applied. port49 is not listening yet, so TACACS is refused outright and
	// the device falls back to local: a breakglass login proves the config from
	// tests/lab/configs is in place.
	if err := l.waitConfigApplied(3 * time.Minute); err != nil {
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
	for _, p := range selectedPlatforms() {
		p := p
		t.Run(p.name, func(t *testing.T) { fn(t, labFor(t, p)) })
	}
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

// nextToken hands out the next unspent seeded token. Redemption deletes the
// token, so every login in a run spends one and no test may reuse another's.
func (l *lab) nextToken(t *testing.T) string {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tokenN++
	if l.tokenN > tokenPoolSize {
		t.Fatalf("%s: the seeded token pool of %d is exhausted; seed more in tests/lab/port49d-lab.yaml", l.p.name, tokenPoolSize)
	}
	s := fmt.Sprintf("p49_labtoken%02d", l.tokenN)
	mustBeSeeded(t, s)
	return s
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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

// capture runs tcpdump around a test. -U writes each packet through, so the
// file is readable even if the process is killed rather than interrupted.
func (l *lab) capture(t *testing.T, name string) func() {
	t.Helper()
	dir := filepath.Join(root, "tests", "lab", "captures")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("captures directory: %v", err)
	}
	abs := filepath.Join(dir, fmt.Sprintf("%s-%s.pcap", name, l.p.name))
	l.capPath = filepath.Join("tests/lab/captures", filepath.Base(abs))

	args := []string{"-i", "any", "-U", "-n", "-s", "0", "-w", abs, "tcp port 49"}
	cmd := exec.Command("sudo", append([]string{"-n", "tcpdump"}, args...)...)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start tcpdump: %v", err)
	}
	// tcpdump prints "listening on ..." once the capture is live; a second is
	// enough on a loopback-speed bridge and keeps the first packet in the file.
	time.Sleep(time.Second)

	stopped := false
	return func() {
		if stopped {
			return
		}
		stopped = true
		// The leading [t] keeps the pattern from matching pkill's own command
		// line, which would kill the sudo that launched it.
		pattern := "[t]cpdump " + strings.Join(args[:len(args)-1], " ") + " " + abs
		_ = exec.Command("sudo", "-n", "pkill", "-INT", "-f", pattern).Run()
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = exec.Command("sudo", "-n", "pkill", "-KILL", "-f", pattern).Run()
			<-done
		}
		// tcpdump wrote the file as root; make it readable without sudo.
		_ = exec.Command("sudo", "-n", "chown", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), abs).Run()
		if fi, err := os.Stat(abs); err != nil || fi.Size() == 0 {
			t.Logf("capture %s is empty or missing (%v); tcpdump said: %s", abs, err, errBuf.String())
		}
	}
}

// ---------------------------------------------------------------------------
// Results notes
// ---------------------------------------------------------------------------

// result writes tests/lab/results/L<N>-<platform>.md in the form spec §15 rule
// 3 requires: platform, image version, observation, and a pointer to the
// capture.
func (l *lab) result(t *testing.T, entry, claim, observation string) {
	t.Helper()
	dir := filepath.Join(root, "tests", "lab", "results")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("results directory: %v", err)
	}
	path := filepath.Join(dir, fmt.Sprintf("%s-%s.md", entry, l.p.name))
	var b strings.Builder
	fmt.Fprintf(&b, "# %s — %s\n\n", entry, l.p.name)
	fmt.Fprintf(&b, "- **Date measured:** %s\n", time.Now().UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "- **Platform:** %s (containerlab node `%s`, %s)\n", l.p.name, l.p.node, l.p.addr)
	fmt.Fprintf(&b, "- **Image version:** %s (`%s`)\n", l.p.version, l.p.image)
	fmt.Fprintf(&b, "- **Topology:** `tests/lab/%s`\n", l.p.topo)
	fmt.Fprintf(&b, "- **Capture:** `%s`\n", l.capPath)
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

		out, err := l.login("alice", l.nextToken(t), "show version")
		if err != nil {
			t.Fatalf("SSH login as alice failed, so no exchange happened: %v\nrecords:%s", err, summarize(l.recordsSince(off)))
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
