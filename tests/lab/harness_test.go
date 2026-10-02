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
	"errors"
	"fmt"
	"io"
	"io/fs"
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

	"github.com/rhwendt/port49/tests/lab/labcreds"
	"github.com/rhwendt/port49/tests/lab/labpcap"
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
	// vSRX used to spend its whole budget every run, because the gate was a
	// breakglass login and on vSRX 21.4R3.15 no local account has a password:
	// the startup config's `plain-text-password-value` never becomes an
	// `encrypted-password` there, so breakglass cannot log in by any route
	// (results/juniper_vsrx-config-verified.md). That says nothing about whether
	// vSRX falls through `authentication-order`. waitDeviceReady now also accepts
	// an authentication rejection, so vSRX passes as soon as sshd is serving
	// rather than at the budget. Its budget stays the shortest that clears the
	// 3 minutes it takes to get there.
	//
	// These numbers are a property of the host. The previous host could not boot
	// a vmhost Junos image at all — see tests/lab/README.md, "Why this needs bare
	// metal" — and a 35-minute budget there still measured nothing. If Junos
	// stops making the budget on some future host, measure the boot and change
	// the number; do not assume the device is broken.
	boot time.Duration
}

var platforms = []platform{
	// The version string is what the DEVICE reports, not what the image is
	// tagged. `show version` on this image says `Software image version:
	// 4.31.2F` and `Internal build version: 4.31.2F-35442176.4312F`, three
	// times over in tests/lab/results/L16-arista_eos.md, while the docker tag
	// and the vmdk filename both say 4.32.2F -- the file was named for a
	// release it does not contain. Every EOS results note written before
	// 2026-09-21 carries `vEOS-lab 4.32.2F` in its header and is wrong about
	// the release; the observations in them stand, the label does not.
	// CLAUDE.md rule 4: the device is right and the docs are wrong.
	{"eos", "arista_eos", "topologies/eos.clab.yml", "172.100.100.11", "leaf1",
		"vrnetlab/arista_veos:4.32.2F", "vEOS-lab 4.31.2F (image tagged 4.32.2F)", 6 * time.Minute},
	{"vjunos", "juniper_vjunos-router", "topologies/vjunos.clab.yml", "172.100.100.21", "srx1",
		"vrnetlab/juniper_vjunos-router:23.4R2-S2.1", "vJunos-router 23.4R2-S2.1", 8 * time.Minute},
	{"vsrx", "juniper_vsrx", "topologies/vsrx.clab.yml", "172.100.100.22", "vsrx1",
		"vrnetlab/juniper_vsrx:21.4R3.15", "vSRX3 21.4R3.15", 6 * time.Minute},
	// N9Kv's budget is a placeholder, not a measurement: nothing on this host has
	// ever booted this image. 15 minutes is a starting figure chosen because the
	// vrnetlab launcher gives the VM 10 GB of RAM and 4 vCPUs and then drives a
	// POAP-prompt dialogue over the serial console before it applies any
	// configuration at all. Measure the first successful deploy and replace this
	// number with what was measured, the way the three platforms above were.
	{"nxos", "cisco_nxos", "topologies/nxos.clab.yml", "172.100.100.31", "nx1",
		"vrnetlab/cisco_n9kv:9300v64-10.4.2.F", "Nexus 9300v 10.4(2)F", 15 * time.Minute},
	// The c8000v is the fastest platform in this lab and the only one where
	// "booted" and "configured" are the same event: the launcher waits for
	// `CVAC-4-CONFIG_DONE` on the serial console, which is the device saying it
	// has applied the startup configuration, and reports `Startup complete in:
	// 0:01:21` — measured on this host on 2026-09-20. Six minutes is several
	// times that, which is what a budget is for.
	{"iosxe", "cisco_iosxe", "topologies/iosxe.clab.yml", "172.100.100.41", "xe1",
		"vrnetlab/cisco_c8000v:17.13.01a", "Catalyst 8000V 17.13.01a", 6 * time.Minute},
}

const (
	// These four values also live in the startup configs and in
	// port49d-lab.yaml, and nothing makes the compiler check that they agree.
	// Editing a config to rename the breakglass account or change the shared
	// secret breaks the harness silently — the readiness gate stops passing, or
	// every device packet fails key trial — with no build error and no obvious
	// cause. They are named here so the coupling has somewhere to be documented,
	// and each config carries a comment pointing back at these names.
	//
	// The values themselves live in tests/lab/labcreds, which is an ordinary
	// package rather than a test file, because `tests/lab/cmd/redact-pcap`
	// needs them too: it proves that no committed evidence file holds a lab
	// credential by searching for these exact strings, and a redactor
	// searching for a stale copy of the password would pass while the real one
	// sat in the file. One definition, three readers.
	labKeyDefault  = labcreds.Key            // `tacacs-server host ... key`, `tacplus-server ... secret`
	breakglassUser = labcreds.BreakglassUser // the local account both startup configs define

	// labEncKeyDefault is the encryption-at-rest key for a lab run, 32 bytes as
	// AES-256 requires. Unlike the constants around it this one is NOT a
	// credential anything authenticates with: the lab store is in memory, so it
	// seals nothing that survives the daemon, and no capture or evidence file
	// ever contains it. PORT49_LAB_ENC_KEY overrides it.
	labEncKeyDefault = "port49-lab-encryption-key-32byte"

	// breakglassPassword is that account's password. The EOS config carries it
	// verbatim; the Junos config carries a SHA-512 crypt hash of it under
	// `encrypted-password`, because the plain-text form does not produce a
	// usable password on vSRX 21.4R3.15. Regenerate that hash with
	// `openssl passwd -6 -salt p49labsalt` over this value if it changes.
	breakglassPassword = labcreds.BreakglassPassword

	// enableSecret is what `aaa authentication enable default group port49
	// enable` falls back to on IOS-XE, and it is deliberately the same
	// published lab constant as breakglassPassword: one value to keep in step
	// with configs/iosxe-startup.cfg rather than two. No other platform in this
	// lab has an enable secret -- EOS's enable takes the operator's own
	// credential, and NX-OS has no enable command without `feature privilege`.
	enableSecret = breakglassPassword

	spoolPath     = "/tmp/port49-lab-acct.jsonl"
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

	// runSeeds is every pair every daemon of this run minted, in the order the
	// files were read. It is a run-scoped union and not the last file on disk
	// because port49d truncates the seed-token file at each start: the file at
	// the end of a run names the LAST daemon's tokens, while the captures hold
	// every daemon's. Verifying the evidence against the file alone therefore
	// checks the exact tokens of the daemon that ran last — which, after an
	// L3-style restart-and-restore, is one that put nothing on the wire. That
	// reports "auditing against N exact secrets" while checking none of the
	// run's real ones, which is the failure labcreds.Secrets refuses for an
	// empty list, dressed up.
	runSeedsMu sync.Mutex
	runSeeds   []labcreds.SeedToken
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

	// daemonDone is closed when the daemon's single Wait goroutine sees port49d
	// exit, whether that is a crash during startup or the drain at teardown.
	// daemonErr is what Wait returned and is safe to read once daemonDone is
	// closed.
	daemonDone chan struct{}
	daemonErr  error

	// configWarn records that the device never served SSH authentication within
	// its boot budget — neither a breakglass login nor an authentication
	// rejection. Not fatal on its own; the tests run anyway and report what they
	// see, and any note written in that state carries this as a caveat.
	configWarn string

	mu     sync.Mutex
	tokenN int
	// seeds is what port49d minted for this platform's NAS on its current run,
	// keyed by username. It is reloaded from the seed-token file every time the
	// daemon starts, because the daemon truncates that file and mints a fresh
	// pair for every seed: a token from before a restart is not in the store any
	// more, and presenting one would be measured as token_not_found.
	seeds        map[string]labcreds.SeedToken
	capAbs       string // absolute path of the raw capture, which is git-ignored
	evidencePath string // repo-relative, committed, redacted: what a note points at
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
	if err := writeEvidence(); err != nil {
		fmt.Fprintf(os.Stderr, "lab: %v\n", err)
		code = 1
	}
	os.Exit(code)
}

// writeEvidence redacts this run's captures into tests/lab/evidence.
//
// It runs after teardown, which is the only point at which every tcpdump has
// been stopped and every capture file is complete. Before that the redactor
// would read a file still being written and refuse it as a partial record —
// correctly, and uselessly.
//
// Every results note this run wrote points at tests/lab/evidence, because
// tests/lab/captures is git-ignored and a pointer into it is a pointer to
// nothing for everyone but this machine. So a run that fails to produce the
// evidence has produced notes that cite files which do not exist, and that
// fails the run: `code = 1` above. The alternative — notes pointing at absent
// evidence — is the failure this whole mechanism exists to prevent.
func writeEvidence() error {
	if root == "" {
		return nil // no platform was ever brought up, so nothing captured
	}
	in := filepath.Join(root, "tests", "lab", "captures")
	out := filepath.Join(root, "tests", "lab", "evidence")
	key := os.Getenv("PORT49_LAB_KEY")
	if key == "" {
		key = labKeyDefault
	}
	// The credentials are the pairs port49d minted for this run. The config no
	// longer knows them: a seed names who gets a token and the daemon chooses
	// the secret.
	//
	// They come from the union the harness built as each daemon wrote its file
	// (runSeeds), not from the file on disk, because the file is truncated at
	// every start and a run that restarted the daemon has captures from
	// daemons whose tokens are no longer in it. The file is the fallback for a
	// run that never loaded one.
	runSeedsMu.Lock()
	seeds := append([]labcreds.SeedToken(nil), runSeeds...)
	runSeedsMu.Unlock()
	var secrets []string
	if len(seeds) > 0 {
		var err error
		if secrets, err = labcreds.SecretsOf(seeds); err != nil {
			return fmt.Errorf("evidence: the pairs this run's daemons minted: %w", err)
		}
	} else {
		seedPath, err := labcreds.SeedTokenFile(filepath.Join(root, "tests", "lab", "port49d-lab.yaml"))
		if err != nil {
			return fmt.Errorf("evidence: %w", err)
		}
		if secrets, err = labcreds.Secrets(seedPath); err != nil {
			return fmt.Errorf("evidence: %w", err)
		}
	}
	_, subnet, err := net.ParseCIDR(labSubnet)
	if err != nil {
		return err
	}
	res, err := labpcap.RedactDir(in, out, labpcap.Options{Key: key, KeyFor: labcreds.CaptureKey, Secrets: secrets, Subnet: subnet})
	if err != nil {
		return fmt.Errorf("evidence: %w", err)
	}
	var failed int
	for _, r := range res {
		if r.Err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "lab: evidence for %s: %v\n", r.Name, r.Err)
			continue
		}
		fmt.Fprintf(os.Stderr, "lab: evidence %s: %s\n", r.Name, r.Stats)
	}
	if failed > 0 {
		return fmt.Errorf("evidence: %d of %d capture(s) produced no evidence file; the results notes from this "+
			"run point at files that do not exist", failed, len(res))
	}
	return nil
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

// imageAbsent reads `docker image inspect image`'s answer: "" when the image
// is there, why not when it is absent, and an error when docker refused this
// shell. A shell without docker group access gets "permission denied" from
// the daemon's socket for every image, and reporting that as a missing image
// sends the operator off to rebuild one that is there.
func imageAbsent(image string, out []byte, err error) (string, error) {
	if err == nil {
		return "", nil
	}
	if strings.Contains(string(out), "permission denied") {
		return "", fmt.Errorf("docker refused this shell (%s); it cannot reach the docker daemon, so no image "+
			"can be checked or deployed. Add your user to the docker group and start a new login shell (or run "+
			"`newgrp docker`)", strings.TrimSpace(string(out)))
	}
	return "image " + image + " is not present", nil
}

// resetForRedeploy lets a platform be brought up again later in the same run.
func (l *lab) resetForRedeploy() {
	l.once = sync.Once{}
	l.err = nil
	l.mu.Lock()
	l.tokenN = 0
	l.seeds = nil
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
	out, err := exec.Command("docker", "image", "inspect", l.p.image).CombinedOutput()
	absent, err := imageAbsent(l.p.image, out, err)
	if err != nil {
		l.err = err
		fmt.Fprintf(os.Stderr, "lab: %s: %v\n", l.p.name, l.err)
		return
	}
	if absent != "" {
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
// startupConfigPath is the config file this platform's topology deploys, read
// out of the topology rather than assumed, so the check below cannot drift from
// what containerlab actually sends.
func (l *lab) startupConfigPath() (string, error) {
	raw, err := os.ReadFile(l.topoPath())
	if err != nil {
		return "", err
	}
	for _, ln := range strings.Split(string(raw), "\n") {
		ln = strings.TrimSpace(ln)
		rest, ok := strings.CutPrefix(ln, "startup-config:")
		if !ok {
			continue
		}
		p := strings.Trim(strings.TrimSpace(rest), `"'`)
		return filepath.Clean(filepath.Join(filepath.Dir(l.topoPath()), p)), nil
	}
	return "", fmt.Errorf("%s names no startup-config", l.topoPath())
}

// checkStartupConfigASCII refuses to deploy a startup config that is not pure
// ASCII, and this is not fastidiousness about character sets.
//
// The N9Kv launcher applies its config by typing it into the serial console one
// line at a time. On the first NX-OS deploy, `tests/lab/configs/nxos-startup.cfg`
// line 8 read:
//
//	! device line by line inside configuration mode — see `apply_config` in
//
// The em dash stopped the whole thing dead. Every line after it — the
// break-glass account, `feature tacacs+`, the server, the group, the method
// lists — was never sent. The device then came up perfectly: SSH serving,
// authentication answering, healthy in `containerlab inspect`, and with no AAA
// configuration at all. It cost a ten-minute boot to find out, and it would
// have cost nothing at all to notice before the deploy.
//
// The check runs for every platform even though only NX-OS is known to be
// vulnerable. The alternative is knowing which launchers type their config and
// which copy it, per image and per vrnetlab version, and being wrong once.
func (l *lab) checkStartupConfigASCII() error {
	path, err := l.startupConfigPath()
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for i, ln := range strings.Split(string(raw), "\n") {
		for _, b := range []byte(ln) {
			if b > 0x7e || (b < 0x20 && b != '\t' && b != '\r') {
				return fmt.Errorf("%s line %d holds a byte outside ASCII (%#02x):\n  %s\n"+
					"Startup configs must be pure ASCII, comments included. The N9Kv launcher types this file "+
					"into the serial console line by line, and one em dash in a comment stopped it there and "+
					"silently dropped every line after it — leaving a device that serves SSH and has no AAA. "+
					"Replace the character (an em dash is `--`, a curly quote is `'`) and redeploy",
					path, i+1, b, ln)
			}
		}
	}
	return nil
}

func (l *lab) up() error {
	if err := l.checkStartupConfigASCII(); err != nil {
		return err
	}
	topo := l.topoPath()
	out, err := exec.Command("sudo", "-n", "containerlab", "deploy", "--reconfigure", "-t", topo).CombinedOutput()
	if err != nil {
		return fmt.Errorf("containerlab deploy: %w\n%s", err, out)
	}
	l.deployed = true

	// Readiness is the device serving SSH authentication, proved by a breakglass
	// login or by an authentication rejection — see waitDeviceReady for why a
	// rejection counts and why requiring the login was a mistake.
	//
	// waitSSH still runs first, for an early sign of life in the log, but it is
	// advisory and capped: on vJunos-router the banner never appeared at all for
	// the first four minutes, and letting that consume the boot budget would
	// starve the gate that actually decides. A banner on its own proves nothing
	// anyway — vrnetlab forwards port 22 into the VM from container start, and
	// something answered a key exchange around 40 seconds in while Junos was
	// still minutes from serving SSH.
	deadline := time.Now().Add(l.p.boot)
	if err := waitSSH(l.p.addr, min(2*time.Minute, time.Until(deadline))); err != nil {
		fmt.Fprintf(os.Stderr, "lab: %s: no SSH banner yet (%v); still waiting for authentication\n", l.p.name, err)
	}
	// The gate gets the whole remaining boot budget, and the reason is a run
	// that was thrown away. It used to be capped at 8 minutes, on the theory
	// that the register tests could still say something against a device whose
	// login had not come up. On vJunos-router that theory cost 17 minutes and
	// measured nothing: the gate gave up at 8m23s while the VM was still
	// mounting Junos packages, then all six register tests ran against a device
	// whose SSH would not complete a handshake, and every one of them failed on
	// the same i/o timeout. Waiting is what the budget is for; if the budget is
	// wrong, the budget is what to change.
	if err := l.waitDeviceReady(time.Until(deadline)); err != nil {
		// Not fatal: the register tests still run and report exactly what they
		// see, which is more useful than a bare setup failure. A note written
		// against a device in this state carries the caveat.
		l.configWarn = err.Error()
		fmt.Fprintf(os.Stderr, "lab: %s: WARNING: %v\n", l.p.name, err)
	}

	// A spool left by an earlier run would drain into this run's log and be
	// read as this run's accounting.
	os.Remove(spoolPath)
	os.Remove(spoolPath + ".draining")

	if err := l.startDaemon(); err != nil {
		return err
	}
	// The gate that actually decides. See waitTACACSReady: everything above
	// proves sshd is serving, and nothing above proves the device is using
	// TACACS+ yet.
	return l.waitTACACSReady(tacacsReadyBudget)
}

// tacacsReadyBudget is how long a device is given, after its SSH authentication
// is serving, to be seen sending port49d a packet. It is separate from the boot
// budget because it measures a different thing: the boot budget ends a VM that
// is not going to come up, and this one ends a device that came up without the
// startup configuration this lab depends on. Eight minutes is what L4 and L13
// used for the same gate before it was shared.
const tacacsReadyBudget = 8 * time.Minute

// waitTACACSReady blocks until the device has been seen speaking TACACS+ to
// port49d, and exists because the run without it produced a measurement that
// was simply false.
//
// waitDeviceReady passes as soon as the device runs SSH authentication through
// to a rejection, and the long comment there says why that is the right gate
// for "is sshd serving". On vJunos-router it passed **11 seconds** after
// deploy, minutes before Junos had committed the startup configuration. L4's
// first cell therefore asked a device with no `breakglass` account and no
// `tacplus-server` whether it falls through to a local password, got "refused"
// in 10ms, and recorded a false negative that the same run's third cell
// contradicted.
//
// L4 and L13 grew this gate for themselves and the rest of the register tests
// did not have it. Their notes were written on runs that happened to be slower;
// nothing guaranteed the next one would be. So it is now part of bring-up, and
// a platform that never speaks TACACS+ fails every test on it rather than
// producing notes about a device that was not yet configured.
//
// What makes it a stronger gate is what the probe is: a login attempt that
// makes the device send port49 a packet. Only a device that has committed its
// `tacacs-server` / `tacplus-server` statement does that. The attempt is a
// login port49 will deny — the break-glass account has no token — so the gate
// assumes nothing about fall-through, which is the property L4 measures and
// must not be baked into the gate that L4 runs behind.
func (l *lab) waitTACACSReady(within time.Duration) error {
	deadline := time.Now().Add(within)
	for attempt := 1; ; attempt++ {
		off := l.mark()
		if c, err := l.dial(breakglassUser, breakglassPassword, 60*time.Second); err == nil {
			c.Close()
		}
		recs := l.waitForRecords(off, 20*time.Second, func(rs []map[string]any) bool {
			return redeemFor(rs, breakglassUser) != nil
		})
		if redeemFor(recs, breakglassUser) != nil {
			fmt.Fprintf(os.Stderr, "lab: %s: ready: the device sent port49d a packet after %d login attempt(s), "+
				"so its startup configuration is applied\n", l.p.name, attempt)
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("the device never sent port49d a packet within %v, so its startup configuration was "+
				"never seen to apply and nothing measured against it would be about the configuration under test",
				within)
		}
		time.Sleep(10 * time.Second)
	}
}

func (l *lab) startDaemon() error {
	cfg, err := l.configPath()
	if err != nil {
		return err
	}
	return l.startDaemonWith(cfg, false)
}

func labConfigPath() string { return filepath.Join(root, "tests", "lab", "port49d-lab.yaml") }

// platformSessionAttributes overrides `lab.session_attributes` for the
// platforms where the checked-in list is wrong, keyed on the lab platform
// name. A platform absent from this map runs the checked-in file byte for
// byte. Each entry is a measurement, not a preference:
//
// **cisco_iosxe — `priv-lvl=15` alone.** The comment on
// `lab.session_attributes` in port49d-lab.yaml claims
// `shell:roles*network-admin` is safe to send everywhere, because an OPTIONAL
// argument a device does not understand is ignored (RFC 8907 §8.2). EOS and
// Junos do ignore it. **IOS-XE 17.13.01a does not.** With it in the reply, a
// session port49 permitted `context_matched` is refused by the device with
//
//	% Authorization failed.
//
// and the SSH session is closed, so no token operator reaches a prompt and L2,
// L3 and L10 measure nothing. An invented optional attribute fails the same
// way, so this is "IOS-XE fails an EXEC authorization carrying any attribute
// it does not recognise", not "IOS-XE dislikes NX-OS's roles attribute".
// Measured 2026-09-20; tests/lab/results/L10-cisco_iosxe.md.
//
// **The Junos platforms — no attributes at all.** port49 answered every Junos
// session authorization `service_unsupported` until 2026-09-21, so no
// attribute it sent has ever reached a Junos device and none of them is
// measured there. Now that `junos-exec` is authorized, the reply would carry
// `priv-lvl=15` and `shell:roles*network-admin` on a platform where IOS-XE has
// already shown what an unrecognised attribute can cost, and where the real
// answer — class, `local-user-name`, `user-permissions`, the allow/deny
// regexes — is the session-only projection of decision 22, gated on L12 and
// owned by plan 5. An empty list is the only shape that measures the thing
// this session is measuring: does a Junos login now get a permit.
var platformSessionAttributes = map[string]string{
	"cisco_iosxe":           `["priv-lvl=15"]`,
	"juniper_vjunos-router": `[]`,
	"juniper_vsrx":          `[]`,
}

// configPath is the daemon config this platform runs against: the checked-in
// one unless platformSessionAttributes has something to say about it.
func (l *lab) configPath() (string, error) {
	return l.derivedConfig("", platformSessionAttributes[l.p.name], "")
}

// derivedConfig writes a copy of port49d-lab.yaml for this platform with
// `lab.session_attributes` replaced by attrs (a YAML flow sequence, e.g.
// `["priv-lvl=15"]`) when attrs is non-empty, and extra appended to the end of
// the file — a `platforms:` block, say, for a test that renames a platform's
// session service. With neither, it returns the checked-in file itself, so a
// platform that needs no derivation reads exactly what is committed.
//
// suffix names the derivation when one platform needs more than one in a run;
// "" is the platform's standing config.
func (l *lab) derivedConfig(suffix, attrs, extra string) (string, error) {
	return l.derivedConfigCmd(suffix, attrs, "", extra)
}

// derivedConfigCmd is derivedConfig with `lab.command_attributes` substitutable
// too. Register entry L18 is the only caller that sets it: it asks the same
// question of a session reply and of a per-command reply, and the two lists
// have to move independently or the variants cannot be told apart.
func (l *lab) derivedConfigCmd(suffix, attrs, cmdAttrs, extra string) (string, error) {
	if attrs == "" && cmdAttrs == "" && extra == "" {
		return labConfigPath(), nil
	}
	raw, err := os.ReadFile(labConfigPath())
	if err != nil {
		return "", err
	}
	out := string(raw)
	for _, sub := range []struct{ anchor, value string }{
		{"  session_attributes: ", attrs},
		{"  command_attributes: ", cmdAttrs},
	} {
		if sub.value == "" {
			continue
		}
		i := strings.Index(out, sub.anchor)
		if i < 0 {
			return "", fmt.Errorf("tests/lab/port49d-lab.yaml has no `%s` line, so the attribute set this platform "+
				"needs cannot be substituted and the run would measure the wrong reply", strings.TrimSpace(sub.anchor))
		}
		j := strings.Index(out[i:], "\n")
		if j < 0 {
			return "", fmt.Errorf("tests/lab/port49d-lab.yaml ends inside its %s line", strings.TrimSpace(sub.anchor))
		}
		out = out[:i] + sub.anchor + sub.value + out[i+j:]
	}
	if extra != "" {
		out += "\n" + extra
	}
	dir := filepath.Join(root, "tests", "lab", "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	name := "port49d-lab-" + l.p.name
	if suffix != "" {
		name += "-" + suffix
	}
	out, err = privatePolicy(out, filepath.Join(dir, name+"-policy"))
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, name+".yaml")
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// privatePolicy copies the file a `policy_file:` line names into dir, a
// directory only this user can write, and points the line at the copy.
// port49d refuses a policy file anyone else could have written, or one in a
// directory they could (spec §5.1.3), and a checkout under a umask of 002 —
// the usual one on a desktop distribution — leaves the repository's policy
// files and their directories group-writable. A config with a broker reads its
// inventory_file behind the same fence (plan 6a C2), so its top-level
// `inventory_file:` line is given a private copy too; the standing config,
// with no broker, is left reading the repository's file.
func privatePolicy(cfg, dir string) (string, error) {
	cfg, found, err := privateCopy(cfg, "  policy_file: ", dir, "policy.yaml")
	if err != nil || !found {
		return cfg, err
	}
	// A top-level key starts a line; the config's first line is a comment.
	cfg, found, err = privateCopy(cfg, "\ninventory_file: ", dir, "inventory.yaml")
	if err == nil && !found {
		err = errors.New("a broker config has no top-level `inventory_file:` line to give a private copy")
	}
	if err != nil {
		return cfg, err
	}
	// The revocations file is port49d's own state behind the same fence
	// (plan 7a): tests/lab/logs is 0775 under the desktop umask and would
	// refuse the start, and a mark one run left would refuse the next run's
	// mints. It goes in the private directory, fresh at every derived
	// config, written empty on purpose: port49d no longer creates it (spec
	// §13 decision 32, amended 2026-10-02).
	if i := strings.Index(cfg, "  revocations_file: "); i >= 0 {
		j := strings.Index(cfg[i:], "\n")
		if j < 0 {
			j = len(cfg) - i
		}
		dst := filepath.Join(dir, "revocations.json")
		for _, p := range []string{dst, dst + ".created"} {
			if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return "", err
			}
		}
		if err := writeEmptyRevocations(dst); err != nil {
			return "", err
		}
		cfg = cfg[:i] + "  revocations_file: " + dst + cfg[i+j:]
	}
	return cfg, nil
}

// writeEmptyRevocations writes {"revocations": []} to path, 0600, only when
// nothing is there: port49d never creates the file (spec §13 decision 32,
// amended 2026-10-02), and one already there may be held by a port49d still
// running, whose marks a truncation would lose (task 2 review m5).
func writeEmptyRevocations(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = f.WriteString("{\"revocations\": []}\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// privateCopy copies the file the line starting at anchor names to name in
// dir, mode 0700, as mode 0600, and points the line at the copy. found is
// false, and cfg unchanged, when no line starts at anchor.
func privateCopy(cfg, anchor, dir, name string) (string, bool, error) {
	i := strings.Index(cfg, anchor)
	if i < 0 {
		return cfg, false, nil
	}
	j := strings.Index(cfg[i+1:], "\n")
	if j < 0 {
		j = len(cfg) - i
	} else {
		j++
	}
	src := strings.TrimSpace(cfg[i+len(anchor) : i+j])
	if !filepath.IsAbs(src) {
		src = filepath.Join(root, src)
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		return "", false, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", false, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", false, err
	}
	dst := filepath.Join(dir, name)
	if err := os.WriteFile(dst, raw, 0o600); err != nil {
		return "", false, err
	}
	if err := os.Chmod(dst, 0o600); err != nil {
		return "", false, err
	}
	return cfg[:i] + anchor + dst + cfg[i+j:], true, nil
}

// startDaemonWith starts port49d against cfgPath. resume appends to this
// platform's log files instead of truncating them, which is what a test that
// stops and restarts the daemon mid-run needs: a truncated decision log would
// invalidate every offset an earlier mark() handed out, and the records the
// run has already measured against would simply vanish.
func (l *lab) startDaemonWith(cfgPath string, resume bool) error {
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
	open := os.Create
	if resume {
		open = func(p string) (*os.File, error) {
			return os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
		}
	}
	var err error
	if l.logFile, err = open(l.logPath); err != nil {
		return err
	}
	if l.errFile, err = open(l.errPath); err != nil {
		return err
	}

	key := os.Getenv("PORT49_LAB_KEY")
	if key == "" {
		key = labKeyDefault
	}
	l.daemon = exec.Command(filepath.Join(root, "bin", "port49d"), "-config", cfgPath)
	l.daemon.Dir = root
	l.daemon.Stdout = l.logFile
	l.daemon.Stderr = io.MultiWriter(l.errFile, os.Stderr)
	// The encryption-at-rest key is required (design §8) and has no default in
	// the config, so the harness supplies one. The lab store is in memory and
	// dies with the daemon, so this key protects nothing that outlives the run;
	// it is set so the lab exercises the same sealed path production does.
	encKey := os.Getenv("PORT49_LAB_ENC_KEY")
	if encKey == "" {
		encKey = labEncKeyDefault
	}
	l.daemon.Env = append(os.Environ(), "PORT49_LAB_KEY="+key, "PORT49_LAB_ENC_KEY="+encKey)
	if err := l.daemon.Start(); err != nil {
		return fmt.Errorf("start port49d: %w", err)
	}
	// Taken here so loadSeeds can tell this daemon's seed-token file from the
	// one the previous daemon left at the same path.
	started := time.Now()

	// One Wait goroutine for the daemon's whole life, because Cmd.Wait may be
	// called only once and both startup and shutdown need to know it exited.
	// daemonErr is written before daemonDone is closed, so anyone who has seen
	// the close may read it.
	//
	// This is also the only way to detect a daemon that died on startup:
	// ProcessState stays nil until something calls Wait, so the check that used
	// to live in the loop below could never fire, and a port49d that exited
	// immediately still cost the full 30 seconds before its stderr was printed.
	l.daemonDone = make(chan struct{})
	go func() {
		l.daemonErr = l.daemon.Wait()
		close(l.daemonDone)
	}()

	deadline := time.Now().Add(30 * time.Second)
	for {
		if daemonHealthy() {
			return l.loadSeeds(cfgPath, started)
		}
		select {
		case <-l.daemonDone:
			stderr, _ := os.ReadFile(l.errPath)
			return fmt.Errorf("port49d exited during startup (%v); its stderr was:\n%s", l.daemonErr, stderr)
		default:
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	stderr, _ := os.ReadFile(l.errPath)
	return fmt.Errorf("port49d did not come up within 30s; its stderr was:\n%s", stderr)
}

// loadSeeds reads the pairs port49d minted for this platform's NAS out of the
// seed-token file named by cfgPath, and is called on every daemon start.
//
// It exists because nothing in this repository knows a lab credential any more:
// a seed names who gets a token and the daemon chooses the secret (design §8).
// The harness therefore cannot compute a token the way it used to — it has to
// read the one this daemon just minted, which is also why the daemon has to be
// up before any test asks for a login.
//
// startedAt is when the daemon was started, and the file's modification time is
// checked against it. The check is the whole point of passing it: the file is
// truncated and rewritten at every start, so a file older than this process is
// the *previous* run's credentials, and every one of them is a token the store
// no longer holds. Reading them would produce a run in which every login is
// denied `token_not_found`, which is exactly what a device that mangles
// passwords looks like.
func (l *lab) loadSeeds(cfgPath string, startedAt time.Time) error {
	path, err := labcreds.SeedTokenFile(cfgPath)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		seeds, all, err := l.readSeeds(path, startedAt)
		if err == nil {
			l.mu.Lock()
			l.seeds = seeds
			l.mu.Unlock()
			// Every pair this daemon minted joins the run's union, not just
			// this platform's: the evidence verifier searches the captures for
			// strings, and a string that is not in them costs nothing.
			runSeedsMu.Lock()
			runSeeds = append(runSeeds, all...)
			runSeedsMu.Unlock()
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("the tokens port49d minted for NAS %q could not be read: %w", l.p.node, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// readSeeds is one attempt at loadSeeds's read: the file has to exist, to have
// been written by this daemon, and to carry at least one pair for this NAS.
// It returns this platform's pairs keyed by username, and every pair in the
// file for the run-scoped union.
func (l *lab) readSeeds(path string, startedAt time.Time) (map[string]labcreds.SeedToken, []labcreds.SeedToken, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if info.ModTime().Before(startedAt.Add(-time.Second)) {
		return nil, nil, fmt.Errorf("%s was last written %v, before this port49d started at %v, so it holds the "+
			"previous run's spent tokens", path, info.ModTime().Format(time.RFC3339), startedAt.Format(time.RFC3339))
	}
	all, err := labcreds.SeedTokens(path)
	if err != nil {
		return nil, nil, err
	}
	seeds := map[string]labcreds.SeedToken{}
	for _, s := range all {
		if s.NAS == l.p.node {
			seeds[s.Username] = s
		}
	}
	if len(seeds) == 0 {
		return nil, nil, fmt.Errorf("%s holds %d minted pair(s), none of them for NAS %q; check lab.seed_tokens in "+
			"the config this daemon was started with", path, len(all), l.p.node)
	}
	return seeds, all, nil
}

// loginToken is the login token port49d minted for user on this platform's NAS.
func (l *lab) loginToken(user string) (string, error) {
	l.mu.Lock()
	s, ok := l.seeds[user]
	n := len(l.seeds)
	l.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("port49d minted no token for %q on NAS %q (it minted %d for this NAS); "+
			"seed one in tests/lab/port49d-lab.yaml, or the harness and the config have drifted apart",
			user, l.p.node, n)
	}
	if s.Login == "" {
		return "", fmt.Errorf("the pair port49d minted for %q on NAS %q carries no login token", user, l.p.node)
	}
	return s.Login, nil
}

// enableToken is the enable token minted for user, which exists only where the
// seed asked for one with `enable: true`.
func (l *lab) enableToken(user string) (string, error) {
	l.mu.Lock()
	s, ok := l.seeds[user]
	l.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("port49d minted no token at all for %q on NAS %q", user, l.p.node)
	}
	if s.Enable == "" {
		return "", fmt.Errorf("the seed for %q on NAS %q did not ask for an enable token (`enable: true`), "+
			"so there is no enable credential to type", user, l.p.node)
	}
	return s.Enable, nil
}

// writeDelayConfig copies the lab daemon config with both failure-delay knobs
// set to d, and returns the new path. Both are set, not just the ceiling,
// because the base alone would take several failures to reach d and the
// measurement would then be of a different attempt than the one being timed.
func (l *lab) writeDelayConfig(t *testing.T, d time.Duration) string {
	t.Helper()
	base, err := l.configPath()
	if err != nil {
		t.Fatalf("derive this platform's daemon config: %v", err)
	}
	raw, err := os.ReadFile(base)
	if err != nil {
		t.Fatalf("read the lab daemon config: %v", err)
	}
	const anchor = "limits:\n"
	if !strings.Contains(string(raw), anchor) {
		t.Fatalf("tests/lab/port49d-lab.yaml has no `limits:` block to set a failure delay under")
	}
	inject := fmt.Sprintf("limits:\n  auth_failure_delay_base: %s\n  auth_failure_delay_max: %s\n", d, d)
	out := strings.Replace(string(raw), anchor, inject, 1)
	path := filepath.Join(root, "tests", "lab", "logs", fmt.Sprintf("port49d-lab-delay-%s.yaml", d))
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
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

// waitDeviceReady blocks until the device is serving SSH authentication. Either
// of two signals will do, and the weaker one is why this function exists.
//
// The strong signal is a breakglass login. It proves the startup config in
// tests/lab/configs reached the device, because that account exists nowhere
// else. The gate used to require it — and that was wrong, because it rests on
// Junos falling through `authentication-order [ tacplus password ]` to the
// local password while port49d is not listening yet. vJunos-router 23.4R2-S2.1
// does that. On vSRX 21.4R3.15 the gate could never pass — measured, though not
// for the reason first recorded: on that image the breakglass account has no
// password at all, because the startup config's plain-text-password-value never
// becomes an encrypted-password there, so `*` is what lands in
// /etc/master.passwd (results/juniper_vsrx-config-verified.md). A breakglass
// login cannot succeed on vSRX whatever fall-through does. So on one of three
// default platforms the gate burned the whole boot budget every run learning
// nothing, and stamped every vSRX results note with a caveat.
//
// The narrow signal is an authentication *rejection*: the device completed a
// key exchange and ran the authentication exchange through to a decision. That
// is exactly what the register tests need — sshd up, the authentication
// subsystem up — and it assumes nothing about fall-through. It is also not
// fakeable by whatever answers port 22 first, which was the original worry:
// vrnetlab forwards that port into the VM from container start, but a forwarded
// port cannot refuse a password.
//
// What the narrow signal does not prove is that the startup config applied.
// Nothing is lost: the register tests prove it far better, by exchanging TACACS+
// with a device that only this config points at port49. A device that had not
// applied it sends no TACACS+ packet at all, and every test fails on an empty
// capture — which is how the missing `authentication-order` was found.
//
// Only when neither signal appears within the budget is something wrong, and
// only then is configWarn set.
func (l *lab) waitDeviceReady(within time.Duration) error {
	deadline := time.Now().Add(within)
	var last error
	for {
		c, err := l.dial(breakglassUser, breakglassPassword, 30*time.Second)
		if err == nil {
			c.Close()
			fmt.Fprintf(os.Stderr, "lab: %s: ready: %s logged in, so the startup config is applied\n",
				l.p.name, breakglassUser)
			return nil
		}
		if isAuthRejection(err) {
			fmt.Fprintf(os.Stderr, "lab: %s: ready: the device ran SSH authentication to a rejection, so sshd and "+
				"its authentication subsystem are serving. %s was refused, which proves nothing either way: on "+
				"vSRX that account has no password at all, and on any image port49d is not listening yet.\n",
				l.p.name, breakglassUser)
			return nil
		}
		last = err
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("the device never served SSH authentication within %v: neither a %s login nor an "+
		"authentication rejection (last error: %v)", within, breakglassUser, last)
}

// isAuthRejection reports whether an SSH dial failed because the device ran the
// authentication exchange and refused, rather than because it never got that
// far. A refusal means the device is up; a timeout or a failed key exchange
// means it is not.
//
// x/crypto/ssh gives this no type, so the message is the only signal. Both
// strings below come from its own authentication failure path, and neither
// appears on a dial or key-exchange error.
func isAuthRejection(err error) bool {
	s := err.Error()
	return strings.Contains(s, "unable to authenticate") || strings.Contains(s, "no supported methods remain")
}

// diagnose collects what an operator would want after a platform failed to come
// up, so the run's output carries the evidence without a second trip to the host.
func (l *lab) diagnose() {
	out, _ := exec.Command("sudo", "-n", "containerlab", "inspect", "-t", l.topoPath()).CombinedOutput()
	fmt.Fprintf(os.Stderr, "lab: %s: containerlab inspect:\n%s\n", l.p.name, out)
	// The container name is derived from the topology's `name:`, not its file
	// name, so it cannot be built from l.p.topo; ask docker for anything that
	// looks like this node instead.
	ids, _ := exec.Command("docker", "ps", "-a", "--filter", "name="+l.p.node, "--format", "{{.Names}}").Output()
	for _, n := range strings.Fields(string(ids)) {
		logs, _ := exec.Command("docker", "logs", "--tail", "50", n).CombinedOutput()
		fmt.Fprintf(os.Stderr, "lab: %s: docker logs --tail 50 %s:\n%s\n", l.p.name, n, logs)
	}
}

func teardown() {
	labsMu.Lock()
	defer labsMu.Unlock()
	for _, l := range labs {
		l.down()
	}
}

// stopDaemon stops port49d and leaves the topology running, so a test can
// measure the device against a TACACS+ server that is not listening. It returns
// once the listening socket is gone: startDaemonWith refuses to start beside
// anything still bound to it, and a device that reached a socket in TIME_WAIT
// from the previous daemon would be measured against the wrong condition.
func (l *lab) stopDaemon() error {
	if l.daemon != nil && l.daemon.Process != nil {
		// SIGINT, not Kill: port49d installs signal.NotifyContext for SIGINT and
		// SIGTERM (cmd/port49d), and on either it stops the listener and drains
		// the accounting spool on the way out. A record still on disk is a record
		// this run did not see. Kill is the fallback below, after 20s.
		_ = l.daemon.Process.Signal(os.Interrupt)
		select {
		case <-l.daemonDone:
		case <-time.After(20 * time.Second):
			_ = l.daemon.Process.Kill()
			<-l.daemonDone
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
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", tacacsAddr, 2*time.Second)
		if err != nil {
			return nil
		}
		c.Close()
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("port49d was stopped but something is still listening on %s after 30s", tacacsAddr)
}

func (l *lab) down() {
	_ = l.stopDaemon()
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
// port49d minted under it for this platform's NAS. Redemption deletes the
// token, so every login in a run spends one.
//
// The token is read from the seed-token file rather than computed, because
// nothing but the daemon knows it: a seed names who gets a token and port49d
// chooses the secret (design §8). That is why the daemon has to be up before
// the first login — see loadSeeds, which is called from startDaemonWith.
//
// A username per login is also what makes the decision log readable as a set of
// sessions: the username is written on every record whether or not a context
// lookup found anything, so it is the only session key the log always carries
// (see portStability in register_test.go, which was measuring the wrong set
// until it grouped by this).
//
// It used to be load-bearing for a second reason that has expired. The receipt
// key was `(nas, port, username)`, and EOS reports `port` as the constant
// string "ssh" at authentication (L1), so every SSH login by one user shared a
// receipt: a second login inside the receipt window presented a fresh token
// against the first login's receipt and was refused `credential_mismatch`. The receipt
// key now carries the credential hash (spec §13, decision 15), so a fresh token
// finds no receipt and redeems normally. Repeating a username is no longer a
// collision; it is just harder to read.
func (l *lab) nextLogin(t *testing.T) (user, secret string) {
	t.Helper()
	l.mu.Lock()
	n := l.tokenN + 1
	l.tokenN = n
	l.mu.Unlock()
	if n > tokenPoolSize {
		t.Fatalf("%s: the seeded login pool of %d is exhausted; seed more in tests/lab/port49d-lab.yaml", l.p.name, tokenPoolSize)
	}
	user = fmt.Sprintf("alice%02d", n)
	secret, err := l.loginToken(user)
	if err != nil {
		t.Fatalf("%s: %v", l.p.name, err)
	}
	return user, secret
}

// nextLoginOrErr is nextLogin for a caller that cannot fail the test — a
// closure a driver hands to shared code, where a t.Fatal would fire on the
// wrong goroutine or abandon a device mid-restore. Same pool, same counter.
func (l *lab) nextLoginOrErr() (user, secret string, err error) {
	l.mu.Lock()
	n := l.tokenN + 1
	l.tokenN = n
	l.mu.Unlock()
	if n > tokenPoolSize {
		return "", "", fmt.Errorf("%s: the seeded login pool of %d is exhausted; seed more in "+
			"tests/lab/port49d-lab.yaml", l.p.name, tokenPoolSize)
	}
	user = fmt.Sprintf("alice%02d", n)
	secret, err = l.loginToken(user)
	if err != nil {
		return "", "", err
	}
	return user, secret, nil
}

// mustLogin is nextLogin for a caller that already knows which username it
// needs — a pool of its own, like the transport and Junos-options tests.
func (l *lab) mustLogin(t *testing.T, user string) string {
	t.Helper()
	secret, err := l.loginToken(user)
	if err != nil {
		t.Fatalf("%s: %v", l.p.name, err)
	}
	return secret
}

// mustBeInLabConfig fails the test unless port49d-lab.yaml contains s verbatim.
//
// It used to guard seeded secrets, which no longer exist in that file: port49d
// mints them (see nextLogin). What is left to guard is the text the config and
// a test have to agree on literally, which today is the deny prefixes L2 types.
func mustBeInLabConfig(t *testing.T, s string) {
	t.Helper()
	if !strings.Contains(labYAML, s) {
		t.Fatalf("tests/lab/port49d-lab.yaml does not contain the string this test depends on (%d characters, starting %q); the two have drifted apart",
			len(s), s[:min(16, len(s))])
	}
}

// ---------------------------------------------------------------------------
// SSH
// ---------------------------------------------------------------------------

// dial opens an SSH connection. The algorithm lists are deliberately wide:
// these are shipping network OS images, some of them years old, and a handshake
// this client refuses would look exactly like a device that failed to boot.
func (l *lab) dial(user, password string, timeout time.Duration) (*ssh.Client, error) {
	return l.dialHostPort(user, password, l.p.addr+":22", timeout)
}

// dialHostPort is dial against an explicit host:port. NETCONF is why it exists:
// the transport tests reach it on 830 on Junos and NX-OS and on 22 on EOS, and
// they need the same deliberately wide algorithm lists — a handshake refused
// for want of a 2016 cipher would look exactly like a device that has not
// enabled NETCONF at all.
func (l *lab) dialHostPort(user, password, hostport string, timeout time.Duration) (*ssh.Client, error) {
	nc, err := net.DialTimeout("tcp", hostport, timeout)
	if err != nil {
		return nil, err
	}
	if err := nc.SetDeadline(time.Now().Add(timeout)); err != nil {
		nc.Close()
		return nil, err
	}
	cfg := labSSHConfig(user, password)
	cfg.Timeout = timeout
	c, chans, reqs, err := ssh.NewClientConn(nc, hostport, cfg)
	if err != nil {
		nc.Close()
		return nil, err
	}
	nc.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

// labSSHConfig is the client configuration every lab dial uses: the password
// offered both as `password` and as the answer to every keyboard-interactive
// question, and the wide algorithm lists described on dial.
func labSSHConfig(user, password string) *ssh.ClientConfig {
	return &ssh.ClientConfig{
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

// notObserved is loginWithin's error when a session opened and some of its
// commands did not finish: each such command, with why ("deadline", or "not
// run" for one after a connection that had to be closed). What such a
// command did on the device is not observed, never a refusal: a caller that
// reads a missing authorization record as "refused by the device" must check
// for this first (task 17 review I1).
type notObserved struct {
	commands []string          // in the order sent
	why      map[string]string // command → reason
}

func (e *notObserved) add(cmd, why string) {
	if e.why == nil {
		e.why = map[string]string{}
	}
	e.commands = append(e.commands, cmd)
	e.why[cmd] = why
}

func (e *notObserved) Error() string {
	var parts []string
	for _, c := range e.commands {
		parts = append(parts, c+": "+e.why[c])
	}
	return "not observed (" + strings.Join(parts, "; ") + ")"
}

// loginWithin is login with a deadline on each command: a channel the device
// never answers is closed at per, rather than a run that waits forever. The
// first NX-OS run of TestAdapterReplies hung for 76 minutes on an exec
// channel the device opened no command on. If closing the channel does not
// free it within 10s, the whole connection is closed and the commands after
// it are not run. Either way the error is a *notObserved naming each command
// that did not finish; outs holds what arrived, one entry per command sent.
func (l *lab) loginWithin(user, password string, per time.Duration, commands ...string) ([]string, error) {
	if l.p.name == "cisco_iosxe" {
		return l.ptyCommands(user, password, per, commands...)
	}
	c, err := l.dial(user, password, 45*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	var outs []string
	var missed notObserved
	for i, cmd := range commands {
		var buf syncBuf
		done := make(chan error, 1)
		var s *ssh.Session
		var smu sync.Mutex
		go func() {
			sess, err := c.NewSession()
			if err != nil {
				done <- err
				return
			}
			smu.Lock()
			s = sess
			smu.Unlock()
			sess.Stdout, sess.Stderr = &buf, &buf
			_ = sess.Run(cmd)
			sess.Close()
			done <- nil
		}()
		select {
		case err := <-done:
			if err != nil {
				for _, rest := range commands[i:] {
					missed.add(rest, "not run: "+oneLine(err.Error()))
				}
				return outs, &missed
			}
			outs = append(outs, buf.String())
			continue
		case <-time.After(per):
		}
		smu.Lock()
		if s != nil {
			s.Close()
		}
		smu.Unlock()
		missed.add(cmd, "deadline")
		select {
		case <-done:
			outs = append(outs, buf.String())
			continue
		case <-time.After(10 * time.Second):
		}
		c.Close()
		outs = append(outs, buf.String())
		for _, rest := range commands[i+1:] {
			missed.add(rest, "not run")
		}
		return outs, &missed
	}
	if len(missed.commands) > 0 {
		return outs, &missed
	}
	return outs, nil
}

// ptyCommands is loginWithin for IOS-XE: the C8000V 17.13.01a runs one exec
// channel per SSH connection and answers the second with EOF (this task's
// first IOS-XE pass), so each command is typed at the prompt of one pty
// session instead, paging off first. A `[confirm]` is answered `n`: the
// command's authorization has already happened by then. A command that
// reaches configuration mode is followed by `end`. Each output is the
// command's reply without its echo or the prompt after it. A command whose
// prompt does not return within per ends the session: it and the rest are
// returned as *notObserved.
func (l *lab) ptyCommands(user, password string, per time.Duration, commands ...string) ([]string, error) {
	sh, err := l.shell(user, password)
	if err != nil {
		return nil, err
	}
	defer sh.Close()
	// A command that enters configuration mode ends at the configuration
	// prompt, and `end` leaves it again so the next command runs in exec.
	cfg := l.p.node + "(config"
	var outs []string
	for _, cmd := range commands {
		out, _, err := sh.runUntil(cmd, per, "[confirm]", cfg)
		if err == nil && strings.Contains(out, "[confirm]") {
			var more string
			more, _, err = sh.Run("n", per)
			out += more
		}
		if err == nil && strings.Contains(out, cfg) {
			_, _, err = sh.Run("end", per)
		}
		lines := strings.Split(strings.ReplaceAll(out, "\r", ""), "\n")
		if len(lines) > 0 {
			lines = lines[1:]
		}
		for len(lines) > 0 && (strings.TrimSpace(lines[len(lines)-1]) == "" ||
			strings.HasPrefix(strings.TrimSpace(lines[len(lines)-1]), l.p.node)) {
			lines = lines[:len(lines)-1]
		}
		outs = append(outs, strings.Join(lines, "\n"))
		if err != nil {
			// The prompt never came back, so this command and every one
			// after it are not observed.
			var missed notObserved
			missed.add(cmd, "deadline")
			for _, rest := range commands[len(outs):] {
				missed.add(rest, "not run")
			}
			return outs, &missed
		}
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

// drainRecords waits the full duration and returns everything that arrived,
// for a test whose answer is a count rather than the presence of a record.
//
// L5 needs this: "no WATCHDOG arrived" is its measurement, so there is nothing
// to wait *for* — only a window long enough that a late record cannot be
// mistaken for an absent one. Spelling that as waitForRecords with a predicate
// returning false works, but reads like a bug rather than a decision.
func (l *lab) drainRecords(off int64, d time.Duration) []map[string]any {
	return l.waitForRecords(off, d, func([]map[string]any) bool { return false })
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
// Results notes
// ---------------------------------------------------------------------------

// captureLine is the "Capture:" line of a results note, and the reason spec §15
// rule 3 can be satisfied at all: a pointer to evidence anyone can open.
//
// It reports how many packets the file actually holds between the device and
// port49d, read back from the capture at the moment the note is written. A note
// whose capture holds none of them cannot close a register row, and says so in
// place of a pointer that would imply evidence it does not have.
//
// The pointer names the evidence file, not the capture. tests/lab/captures is
// git-ignored — the lab tokens and the breakglass password are in it, readable
// by anyone with the published key — so a note citing it cites nothing anyone
// else can check. The redacted copy written at the end of the run holds the
// same packets, and the count quoted here is therefore its count too: the
// redactor keeps every TACACS+ packet and refuses outright to drop one to or
// from the lab subnet.
func (l *lab) captureLine(t *testing.T) string {
	t.Helper()
	l.flushCapture(t)
	return l.stoppedCaptureLine(t)
}

// stoppedCaptureLine is captureLine for a capture already stopped: nothing is
// flushed, and the count is the finished file's, so nothing that arrived
// between a flush and the stop is left out of it (L31).
func (l *lab) stoppedCaptureLine(t *testing.T) string {
	t.Helper()
	line := fmt.Sprintf("`%s`", l.evidencePath)
	if total, device, err := pcapCounts(l.capAbs); err != nil {
		line += fmt.Sprintf(" — **could not be read back** (%v), so this note quotes the decision log only.", err)
		t.Errorf("the capture %s could not be read back: %v", l.capAbs, err)
	} else if device == 0 {
		line += fmt.Sprintf(" — **empty of device traffic**: %d packets, none of them to or from %s. "+
			"This note's observation rests on the decision log alone and cannot close a register row.", total, labSubnet)
		t.Errorf("the capture %s holds no packet to or from %s, so this measurement has no capture to point at",
			l.capAbs, labSubnet)
	} else {
		// The device-packet count, not the file's total: the harness brackets
		// every capture with loopback probes and adds one more pair when it
		// stops the capture, after this note is written. Counting only what
		// crossed the bridge gives a number the reader can reproduce.
		line += fmt.Sprintf(" — %d packets to or from the device, countable with "+
			"`tcpdump -r %s -n 'net %s' | wc -l`.", device, l.evidencePath, labSubnet)
	}
	key := "the lab key (`tests/lab/README.md`)"
	if labcreds.CaptureKey(filepath.Base(l.evidencePath)) != "" {
		key = "the rotation key (`labcreds.RotationKey`, or `PORT49_L28_NEW_KEY`)"
	}
	return line + " A redacted copy of this run's capture: credential bytes overwritten with `x`, " +
		"everything else byte-identical, decodable with " + key + "."
}

// withAdminCLI runs fn against a break-glass CLI with port49d **stopped**, and
// restarts the daemon on this platform's standing config afterwards.
//
// Stopping it is not housekeeping, and L4 paid for the lesson first
// (l4_test.go, and tests/lab/results/L4-*.md): under
// `aaa authentication login default group port49 local` the device asks port49
// about `breakglass`, port49 answers FAIL because it holds no token for that
// name, and **on EOS, NX-OS and IOS-XE a FAIL is final** — the device never
// tries the local password. So a test that opens an admin CLI with the daemon
// running is refused by the device, and the refusal looks like a broken
// break-glass account rather than the measured behaviour it is. The first
// NX-OS run of TestL16Roles failed exactly this way:
//
//	no admin CLI to define the role on: the console did not reach "nx1#"
//	for breakglass; it said: Login incorrect User Access Verification login:
//
// With the daemon down the device treats the server as unreachable, which is
// the one condition where the local password is taken (L4, reading 3).
func (l *lab) withAdminCLI(t *testing.T, open func(*lab) (*cliConn, error), fn func(*cliConn) error) {
	t.Helper()
	if err := l.stopDaemon(); err != nil {
		t.Fatalf("could not stop port49d before opening an admin CLI: %v", err)
	}
	restart := func() {
		base, err := l.configPath()
		if err != nil {
			t.Fatalf("recovering this platform's standing config: %v", err)
		}
		if err := l.startDaemonWith(base, true); err != nil {
			t.Fatalf("restarting port49d after the admin CLI: %v", err)
		}
	}
	c, err := open(l)
	if err != nil {
		restart()
		t.Fatalf("no admin CLI (port49d was stopped for this, so the device should have taken the "+
			"local password): %v", err)
	}
	fnErr := fn(c)
	c.Close()
	restart()
	if fnErr != nil {
		t.Fatalf("configuring the device over the admin CLI: %v", fnErr)
	}
}

// negativeFinding is a claim of the form "this platform does not / cannot X".
// It exists because of an error made on 2026-09-20 and caught on 2026-09-21:
// `tests/lab/results/L3-cisco_nxos.md` asserted "the N9Kv has no enable
// exchange at all" and showed no transcript. The test types `disable` first,
// so the `% Invalid command at '^' marker.` it quoted was probably the
// device's answer to `disable` and `enable` was very likely never typed. A
// register row was closed on it and had to be reopened.
//
// The rule that came out of it: a negative is not a finding until the note
// shows **the exact thing sent and the exact thing the device said back**. A
// reader must be able to see, without trusting the test, that the command
// whose absence is being claimed is the command that was actually rejected.
//
// So this type cannot be rendered without both, and render() fails the test
// rather than writing a note without them — a negative without its transcript
// measures nothing, and a test that measured nothing must fail.
type negativeFinding struct {
	// Claim is the negative itself, e.g. "NX-OS has no `enable` command
	// without `feature privilege`".
	Claim string
	// Sent is the exact command typed or request put on the wire. Not a
	// paraphrase and not the test's name for it: the bytes.
	Sent string
	// Got is the device's exact reply, verbatim, including its punctuation and
	// its marker lines. An empty reply is itself a finding and must be written
	// as such in Got (see emptyDeviceReply), never left blank.
	Got string
	// Inferred marks a claim reached from side effects rather than from the
	// device saying so. The brief's distinction: an inferred claim is written
	// down as inferred and never as measured.
	Inferred bool
	// Why explains an inferred claim: which side effect, and why it implies
	// the claim. Required when Inferred is set.
	Why string
}

// emptyDeviceReply is what Got holds when the device answered with nothing at
// all. It is a sentence rather than an empty string so a note never renders a
// blank fenced block, which reads as "the device said nothing" whether that
// was measured or whether the transcript was simply never captured.
const emptyDeviceReply = "(the device returned no output at all: zero bytes on the channel)"

// render returns the markdown for a negative finding, or fails the test. Every
// branch that fails here is a note that would have asserted a negative with
// nothing behind it.
func (f negativeFinding) render(t *testing.T) string {
	t.Helper()
	if strings.TrimSpace(f.Claim) == "" {
		t.Fatal("a negativeFinding with no Claim: nothing is being asserted")
	}
	if strings.TrimSpace(f.Sent) == "" {
		t.Fatalf("negative finding %q has no Sent: a claim that a platform cannot do something "+
			"is not a measurement until the note shows the exact command or request that was sent. "+
			"This is the L3-cisco_nxos defect (see negativeFinding's comment); the test fails rather "+
			"than writing the note.", f.Claim)
	}
	if strings.TrimSpace(f.Got) == "" {
		t.Fatalf("negative finding %q has no Got: the device's exact reply is what makes the claim "+
			"checkable by a reader. If the device really answered nothing, set Got to emptyDeviceReply "+
			"and say so; do not leave it blank.", f.Claim)
	}
	if f.Inferred && strings.TrimSpace(f.Why) == "" {
		t.Fatalf("negative finding %q is marked Inferred with no Why: an inference has to name the "+
			"side effect it rests on, or a reader cannot tell it from a measurement.", f.Claim)
	}
	kind := "Measured"
	if f.Inferred {
		kind = "**Inferred, not measured**"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s\n\n", kind, f.Claim)
	fmt.Fprintf(&b, "Sent:\n\n```\n%s\n```\n\n", strings.TrimRight(f.Sent, "\n"))
	fmt.Fprintf(&b, "The device replied:\n\n```\n%s\n```\n", strings.TrimRight(f.Got, "\n"))
	if f.Inferred {
		fmt.Fprintf(&b, "\nThis is an inference from a side effect, not the device stating it: %s\n", f.Why)
	}
	return b.String()
}

// result writes tests/lab/results/L<N>-<platform>.md in the form spec §15 rule
// 3 requires: platform, image version, observation, and a pointer to the
// evidence.
func (l *lab) result(t *testing.T, entry, claim, observation string) {
	t.Helper()
	dir := filepath.Join(root, "tests", "lab", "results")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("results directory: %v", err)
	}
	path := filepath.Join(dir, fmt.Sprintf("%s-%s.md", entry, l.p.name))
	capLine := l.captureLine(t)
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
	// A note is committed, and an observation may copy a device's
	// configuration: every password and hash in it is redacted here, whatever
	// the test put in (a4c4738; plan 5b final review I-4).
	if err := os.WriteFile(path, []byte(labcreds.RedactNote(b.String())), 0o644); err != nil {
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
