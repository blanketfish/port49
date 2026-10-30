//go:build systemd

// Package systemd is the systemd shape's smoke (plan 12b, Task 9): the port49-server package
// installed into a Debian container whose PID 1 is systemd, with three etcd members as
// etcd@.service instances beside it, and port49d and port49-broker started as their units.
// `make systemd-smoke` runs it; `go test ./...` never builds it.
//
// UNVERIFIED until it runs: nothing in this file has met Docker, a real systemd or the package.
// The pure parts (the rewrites of the shipped files, the refusal matcher) are held by
// tests/systemd/sdtest. A failure names the unit, the file or the field and dumps every port49
// unit's journal through tests/qual/secret-filter.sh; the container is always removed.
package systemd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/tests/shapes/shapetest"
	"github.com/rhwendt/port49/tests/systemd/sdtest"
)

const (
	image     = "port49-systemd:dev"
	container = "port49systemd"
	network   = "port49systemd"
	subnet    = "172.31.49.0/24" // the bridge's; a host-published connection presents its gateway
	gateway   = "172.31.49.1"
	rootsRef  = "/etc/port49/broker/" + shapetest.RootsName
	bob       = "user:bob@example.com"
)

var members = []string{"https://localhost:2379", "https://localhost:2479", "https://localhost:2579"}

// box is the container: every command runs as root inside it, with docker exec.
type box struct {
	t    *testing.T
	root string // the repository
}

func (b box) docker(stdin string, args ...string) (string, error) {
	cmd := exec.Command("docker", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// exec runs argv in the container, feeding stdin when it is not empty.
func (b box) exec(stdin string, argv ...string) (string, error) {
	args := []string{"exec"}
	if stdin != "" {
		args = append(args, "-i")
	}
	return b.docker(stdin, append(append(args, container), argv...)...)
}

func (b box) sh(script string) string {
	b.t.Helper()
	out, err := b.exec("", "sh", "-c", script)
	if err != nil {
		b.t.Fatalf("in the container: %s: %v\n%s", firstLine(script), err, filter(out))
	}
	return out
}

func firstLine(s string) string { return strings.SplitN(strings.TrimSpace(s), "\n", 2)[0] }

// put writes body to path with owner and mode, by a rename in the same directory, so a reader
// never sees a half-written file. body travels on stdin and is never in an argument or a log.
func (b box) put(path, owner, mode, body string) {
	b.t.Helper()
	out, err := b.exec(body, "sh", "-c", sdtest.PutScript, "sh", path, owner, mode)
	if err != nil {
		b.t.Fatalf("writing %s in the container: %v\n%s", path, err, filter(out))
	}
}

// putFile is put for a file on the host.
func (b box) putFile(path, owner, mode, hostFile string) {
	b.t.Helper()
	body, err := os.ReadFile(hostFile)
	if err != nil {
		b.t.Fatal(err)
	}
	b.put(path, owner, mode, string(body))
}

func (b box) show(unit string, props ...string) map[string]string {
	b.t.Helper()
	args := []string{"systemctl", "show", unit}
	for _, p := range props {
		args = append(args, "-p", p)
	}
	out, err := b.exec("", args...)
	if err != nil {
		b.t.Fatalf("systemctl show %s: %v", unit, err)
	}
	return sdtest.ParseShow(out)
}

// journal is a unit's journal since the container started, or since epoch when it is not zero.
func (b box) journal(unit string, since int64) string {
	b.t.Helper()
	args := []string{"journalctl", "-u", unit, "--no-pager", "-o", "cat"}
	if since != 0 {
		args = append(args, "--since", fmt.Sprintf("@%d", since))
	}
	out, _ := b.exec("", args...)
	return out
}

// filter is tests/qual/secret-filter.sh on s.
func filter(s string) string {
	root, err := filepath.Abs("../..")
	if err != nil {
		return "(the secret filter was not found; output withheld)"
	}
	cmd := exec.Command("bash", filepath.Join(root, "tests", "qual", "secret-filter.sh"))
	cmd.Stdin = strings.NewReader(s)
	out, err := cmd.Output()
	if err != nil {
		return "(the secret filter failed; output withheld)"
	}
	return string(out)
}

func (b box) epoch() int64 {
	b.t.Helper()
	var n int64
	fmt.Sscan(strings.TrimSpace(b.sh("date +%s")), &n)
	return n
}

func readHost(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// newBox builds the image, creates the network, starts the container and arranges that both are
// removed, on failure too, after the journals of every port49 unit are logged.
func newBox(t *testing.T) box {
	t.Helper()
	shapetest.RefuseOnKeyHost(t) // before anything starts: this container is not an isolation boundary
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	b := box{t: t, root: root}
	// A run that was killed leaves its container and network behind: start from nothing.
	b.docker("", "rm", "-f", container)
	b.docker("", "network", "rm", network)
	if out, err := b.docker("", "build", "-t", image, filepath.Join(root, "tests", "systemd")); err != nil {
		t.Fatalf("docker build: %v\n%s", err, filter(out))
	}
	if out, err := b.docker("", "network", "create", "--subnet", subnet, "--gateway", gateway, network); err != nil {
		t.Fatalf("docker network create %s: %v\n%s", network, err, out)
	}
	// A SIGINT, a SIGTERM or the test's own deadline runs no t.Cleanup, so the guard removes the
	// container and the network itself: by name at once, and by the recorded ID once it is known.
	deadline, _ := t.Deadline()
	guard := shapetest.NewGuard(t, os.Exit, deadline, shapetest.KillGrace)
	guard.OnKill(func() { b.docker("", "network", "rm", network) })
	guard.OnKill(func() { b.docker("", "rm", "-f", container) })
	id := ""
	t.Cleanup(func() {
		if t.Failed() {
			for _, u := range []string{"port49d", "port49-broker", "etcd@etcd-1", "etcd@etcd-2", "etcd@etcd-3"} {
				t.Logf("journal of %s:\n%s", u, filter(b.journal(u, 0)))
			}
		}
		b.docker("", "rm", "-f", container)
		if id != "" {
			b.docker("", "rm", "-f", id)
		}
		b.docker("", "network", "rm", network)
	})
	out, err := b.docker("", sdtest.RunArgs(container, network, image)...)
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	id = strings.TrimSpace(out)
	guard.OnKill(func() { b.docker("", "rm", "-f", id) })
	shapetest.WaitFor(t, "systemd to finish booting", 2*time.Minute, func() bool {
		out, _ := b.exec("", "systemctl", "is-system-running")
		s := strings.TrimSpace(out)
		return s == "running" || s == "degraded"
	})
	return b
}

// rotator is shapetest.Rotator for the host's files: written through docker exec, by rename.
type rotator struct {
	b      box
	policy []byte
}

func (r rotator) KeyDir() string     { return "/etc/port49/keys" }
func (r rotator) BasePolicy() []byte { return r.policy }
func (r rotator) WritePolicy(p []byte) error {
	r.b.put("/etc/port49/policy.yaml", "root:root", "0644", string(p))
	return nil
}

// WriteKey is the README's recipe for a new version: a new file, never an overwrite.
func (r rotator) WriteKey(name string, secret []byte) error {
	out, err := r.b.exec(string(secret), "sh", "-c", `set -eu; umask 077; cd /etc/port49/keys
{ [ ! -e "$1" ] && [ ! -L "$1" ]; } || exit 1
t=$(mktemp ./.key.XXXXXX); trap 'rm -f "$t"' EXIT
cat > "$t"; chown root:port49d "$t"; chmod 0440 "$t"; ln "$t" "$1"`, "sh", name)
	if err != nil {
		return fmt.Errorf("%v: %s", err, filter(out))
	}
	return nil
}

func (r rotator) StartedAt() string {
	return r.b.show("port49d", "ExecMainStartTimestamp")["ExecMainStartTimestamp"]
}

// stack is a running port49 install in the container: the package, three etcd members, the broker
// and port49d as their units, with the shipped configs rewritten to the container's endpoints.
type stack struct {
	b               box
	root, pki       string
	brokerDir       string
	policy, subject string
	dev             shapetest.Device
	mint            func() string
}

// bringUp is everything TestSystemdSmoke does before its first cell, shared with L84's cell (a).
func bringUp(t *testing.T) stack {
	b := newBox(t)
	root := b.root

	// The package, from Task 8's build (make packages writes dist/).
	debs, _ := filepath.Glob(filepath.Join(root, "dist", "port49-server_*_amd64.deb"))
	if len(debs) != 1 {
		t.Fatalf("want exactly one dist/port49-server_*_amd64.deb (make packages), found %d", len(debs))
	}
	b.sh("mkdir -p /smoke")
	if out, err := b.docker("", "cp", debs[0], container+":/smoke/port49-server.deb"); err != nil {
		t.Fatalf("docker cp the package: %v\n%s", err, out)
	}
	b.sh("apt-get install -y --no-install-recommends /smoke/port49-server.deb")
	for _, u := range []string{"port49d", "port49-broker"} {
		if out := b.sh("systemctl is-enabled " + u + " || true"); strings.TrimSpace(out) == "enabled" {
			t.Fatalf("the package enabled %s: it must never enable or start a unit", u)
		}
	}

	// The PKI and keys, from testpki.WriteCompose's layout (host side, a 0700 temp directory).
	pki := t.TempDir()
	if err := testpki.WriteCompose(pki, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	brokerDir := filepath.Join(pki, "broker")
	rootsFile, subject := shapetest.AdminSetup(t, brokerDir)

	// etcd: the user, the three members, from deploy/systemd/examples.
	ex := filepath.Join(root, "deploy", "systemd", "examples")
	b.put("/etc/sysusers.d/etcd.conf", "root:root", "0644", readHost(t, filepath.Join(ex, "sysusers-etcd.conf")))
	b.put("/etc/tmpfiles.d/port49-etcd.conf", "root:root", "0644", readHost(t, filepath.Join(ex, "tmpfiles-etcd.conf")))
	b.sh("systemd-sysusers etcd.conf && systemd-tmpfiles --create port49-etcd.conf")
	b.put("/etc/systemd/system/etcd@.service", "root:root", "0644", readHost(t, filepath.Join(ex, "etcd@.service")))
	b.putFile("/etc/etcd/pki/ca.pem", "root:root", "0644", filepath.Join(pki, "etcd", "ca.pem"))
	b.putFile("/etc/etcd/pki/root.pem", "root:root", "0644", filepath.Join(pki, "etcd", "root.pem"))
	b.putFile("/etc/etcd/pki/root-key.pem", "root:root", "0400", filepath.Join(pki, "etcd", "root-key.pem"))
	for n := 1; n <= 3; n++ {
		name := fmt.Sprintf("etcd-%d", n)
		cfg, err := sdtest.Member(readHost(t, filepath.Join(ex, name+".yaml")), n)
		if err != nil {
			t.Fatal(err)
		}
		b.put("/etc/etcd/"+name+".yaml", "root:root", "0644", cfg)
		b.putFile("/etc/etcd/pki/"+name+".pem", "root:root", "0644", filepath.Join(pki, "etcd", name+".pem"))
		b.putFile("/etc/etcd/pki/"+name+"-key.pem", "etcd:etcd", "0400", filepath.Join(pki, "etcd", name+"-key.pem"))
	}
	b.sh("systemctl daemon-reload && systemctl enable --now etcd@etcd-1 etcd@etcd-2 etcd@etcd-3")

	// The directories port49's and etcd's files go in are tmpfiles.d's (the package's postinstall and
	// tmpfiles-etcd.conf): the smoke makes none of them, and fails if one is not there as shipped.
	for _, d := range []string{"/etc/port49/etcd", "/etc/port49/broker", "/etc/etcd", "/etc/etcd/pki"} {
		st, err := sdtest.ParseStat(b.sh("stat -c '%U:%G %a %n' " + d))
		if err != nil {
			t.Fatal(err)
		}
		if err := st[0].Want("root:root", "755"); err != nil {
			t.Fatalf("tmpfiles.d should have made it: %v", err)
		}
	}

	// port49's files, with the modes the README's table gives.
	for _, f := range []struct{ dst, owner, mode, src string }{
		{"/etc/port49/etcd/ca.pem", "root:root", "0644", "etcd/ca.pem"},
		{"/etc/port49/etcd/port49d.pem", "root:root", "0644", "etcd/port49d.pem"},
		{"/etc/port49/etcd/port49d-key.pem", "port49d:port49d", "0400", "etcd/port49d-key.pem"},
		{"/etc/port49/etcd/port49-broker.pem", "root:root", "0644", "etcd/port49-broker.pem"},
		{"/etc/port49/etcd/port49-broker-key.pem", "port49-broker:port49-broker", "0400", "etcd/port49-broker-key.pem"},
		{"/etc/port49/broker/broker.pem", "root:root", "0644", "broker/" + testpki.LabServerCert},
		{"/etc/port49/broker/broker-key.pem", "port49-broker:port49-broker", "0400", "broker/" + testpki.LabServerKey},
		{"/etc/port49/broker/client-ca.pem", "root:root", "0644", "broker/" + testpki.LabCA},
		{"/etc/port49/keys/tacacs_v1", "root:port49d", "0440", "keys/tacacs_v1"},
		{"/etc/port49/secrets/encryption.key", "port49d:port49d", "0400", "secrets/port49d-encryption.key"},
		{"/etc/port49/secrets/broker-encryption.key", "port49-broker:port49-broker", "0400", "secrets/broker-encryption.key"},
	} {
		b.putFile(f.dst, f.owner, f.mode, filepath.Join(pki, f.src))
	}
	b.putFile("/etc/port49/broker/"+shapetest.RootsName, "root:root", "0644", rootsFile)

	// The shipped configs, rewritten to the container's endpoints, subnet and the admin cells' roots.
	shipped := filepath.Join(root, "deploy", "systemd", "config")
	must := func(s string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	daemon := must(sdtest.Daemon(readHost(t, filepath.Join(shipped, "port49d.yaml"))))
	daemon = must(sdtest.Endpoints(daemon))
	broker := must(sdtest.Broker(readHost(t, filepath.Join(shipped, "port49-broker.yaml"))))
	broker = must(sdtest.Endpoints(broker))
	broker = shapetest.AdminBroker(t, broker, rootsRef)
	policy := must(sdtest.Policy(readHost(t, filepath.Join(shipped, "policy.yaml")), subnet))
	policy = shapetest.AdminPolicy(t, policy, subject)
	b.put("/etc/port49/port49d.yaml", "root:root", "0644", daemon)
	b.put("/etc/port49/port49-broker.yaml", "root:root", "0644", broker)
	b.put("/etc/port49/policy.yaml", "root:root", "0644", policy)
	b.put("/etc/port49/inventory.yaml", "root:root", "0644",
		"devices:\n  - {name: smoke1, platform: arista_eos, addresses: ["+gateway+"]}\n")

	// etcd's roles, once, as etcd's root (the chart's etcd-init, by hand): port49d prints the
	// etcdctl commands; each is run, then auth is enabled.
	etcdctl := []string{"env", "ETCDCTL_ENDPOINTS=" + strings.Join(members, ","), "ETCDCTL_CACERT=/etc/etcd/pki/ca.pem",
		"ETCDCTL_CERT=/etc/etcd/pki/root.pem", "ETCDCTL_KEY=/etc/etcd/pki/root-key.pem", "etcdctl"}
	shapetest.WaitFor(t, "the three etcd members to answer", 2*time.Minute, func() bool {
		_, err := b.exec("", append(etcdctl, "endpoint", "health")...)
		return err == nil
	})
	roles := b.sh("port49d store-roles --config /etc/port49/port49d.yaml --broker-config /etc/port49/port49-broker.yaml")
	for _, line := range strings.Split(roles, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if f[0] != "etcdctl" {
			t.Fatalf("store-roles printed a line that is not an etcdctl command: %q", f[0])
		}
		if out, err := b.exec("", append(etcdctl[:len(etcdctl)-1], f...)...); err != nil && !strings.Contains(out, "already exists") {
			t.Fatalf("applying store-roles' %s %s: %v\n%s", f[1], f[2], err, filter(out))
		}
	}
	for _, args := range [][]string{{"user", "add", "root", "--no-password"}, {"user", "grant-role", "root", "root"}, {"auth", "enable"}} {
		if out, err := b.exec("", append(etcdctl, args...)...); err != nil && !strings.Contains(out, "already exists") {
			t.Fatalf("etcdctl %s: %v\n%s", strings.Join(args, " "), err, filter(out))
		}
	}

	// The units.
	b.sh("systemctl enable --now port49-broker port49d")
	shapetest.Ready(t, "127.0.0.1:9050")
	shapetest.Ready(t, "127.0.0.1:9049")

	key := []byte(readHost(t, filepath.Join(pki, "keys", "tacacs_v1")))
	dev := shapetest.Device{T: t, Addr: "127.0.0.1:49", Key: key}
	mint := func() string { return shapetest.Mint(t, brokerDir, "127.0.0.1:8443", "smoke1") }
	return stack{b: b, root: root, pki: pki, brokerDir: brokerDir, policy: policy, subject: subject, dev: dev, mint: mint}
}

func TestSystemdSmoke(t *testing.T) {
	u := bringUp(t)
	b, root, brokerDir, policy, dev, mint := u.b, u.root, u.brokerDir, u.policy, u.dev, u.mint
	_ = root
	must := func(s string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	// 1. The login and the floor line, naming every member.
	if st := dev.Login("alice", mint()); st != wire.AuthenStatusPass {
		t.Fatalf("a device login through the unit: status %d", st)
	}
	if !dev.Permits("alice") || !dev.Permits("alice", "show", "version") {
		t.Fatal("the session's authorization was refused")
	}
	shapetest.FloorLine(t, b.journal("port49d", 0), members)

	// 2. A restart of both units: the session's next command is permitted, and the broker's state
	// directory is the unit's, 700 and the broker's, with no refusal in the journal.
	b.sh("systemctl restart port49d port49-broker")
	shapetest.Ready(t, "127.0.0.1:9050")
	shapetest.Ready(t, "127.0.0.1:9049")
	if !dev.Permits("alice", "show", "version") {
		t.Fatal("the session's next command after the restart was refused: its context did not survive in etcd")
	}
	if got := strings.TrimSpace(b.sh("stat -c '%U %a' /var/lib/port49-broker")); got != "port49-broker 700" {
		t.Fatalf("/var/lib/port49-broker is %q, want %q (StateDirectory= with StateDirectoryMode=0700)", got, "port49-broker 700")
	}
	if regexp.MustCompile(`state_dir .* is writable by its group or others`).MatchString(b.journal("port49-broker", 0)) {
		t.Fatal("the broker's journal holds a state_dir refusal")
	}

	// 3. A key version added with no restart (the README's recipe, as the rotator).
	shapetest.RotateCell(t, dev, "alice", mint, "127.0.0.1:9049", 180*time.Second, rotator{b: b, policy: []byte(policy)})

	// 4. Review focus 1: the fence's refusal of a group-writable /etc, and that the cell can tell
	// ProtectSystem=true (the unit's) from strict (which makes /etc read-only, where the fence
	// excuses the mode). The mode is restored in a cleanup that runs on failure too.
	etcMode := strings.TrimSpace(b.sh("stat -c %a /etc"))
	const dropIn = "/etc/systemd/system/port49d.service.d"
	t.Cleanup(func() {
		b.exec("", "sh", "-c", "rm -rf "+dropIn+"; chmod "+etcMode+" /etc; systemctl daemon-reload; systemctl restart port49d")
	})
	since := b.epoch()
	b.sh("chmod g+w /etc && systemctl restart port49d")
	refused := func() bool {
		for _, l := range strings.Split(b.journal("port49d", since), "\n") {
			if sdtest.Refusal(l, "/etc") {
				return true
			}
		}
		return false
	}
	deadline := time.Now().Add(time.Minute)
	for !refused() {
		if time.Now().After(deadline) {
			// the journal is not printed (the exit line may name a secret): its "is mode" lines, as a closed summary
			t.Fatalf("the journal's refusal of a group-writable /etc did not happen within 1m0s; the journal's mode refusals since %d:\n%s",
				since, sdtest.RefusalSummary(b.journal("port49d", since)))
		}
		time.Sleep(2 * time.Second)
	}
	if resp, err := b.docker("", "exec", container, "systemctl", "is-active", "--quiet", "port49d"); err == nil {
		t.Fatalf("port49d is active with a group-writable /etc (%s)", resp)
	}
	b.sh("mkdir -p " + dropIn + " && printf '[Service]\\nProtectSystem=strict\\nReadWritePaths=/var/spool/port49d\\n' > " + dropIn + "/smoke.conf && systemctl daemon-reload && systemctl restart port49d")
	shapetest.Ready(t, "127.0.0.1:9049") // /etc is read-only in the unit, so the same /etc passes
	if got := strings.TrimSpace(b.sh("stat -c %a /etc")); got == etcMode {
		t.Fatalf("/etc is still %s: the cell did not leave it group-writable for the strict run", got)
	}
	b.sh("rm -rf " + dropIn + "; chmod " + etcMode + " /etc; systemctl daemon-reload; systemctl restart port49d")
	shapetest.Ready(t, "127.0.0.1:9049")

	// 5. A policy with no keys: is refused at every start. The units set StartLimitIntervalSec=0 (plan
	// 7's 3am ruling, which supersedes the brief's Review Focus 2: a broker waiting on a bad or late
	// policy recovers by itself), so the unit retries every RestartSec and never reaches `failed`.
	// The cell asserts only that: two restarts at least, never failed, back without reset-failed.
	cur := b.sh("cat /etc/port49/policy.yaml")
	broken := must(sdtest.NoKeys(cur))
	b.put("/etc/port49/policy.yaml", "root:root", "0644", broken)
	b.sh("systemctl restart port49d")
	shapetest.WaitFor(t, "port49d to retry a start its policy refuses", 3*time.Minute, func() bool {
		s := b.show("port49d", "NRestarts", "ActiveState")
		return atLeast(s["NRestarts"], 2) && s["ActiveState"] != "failed"
	})
	if s := b.show("port49d", "ActiveState"); s["ActiveState"] == "failed" {
		t.Fatal("port49d is failed: the unit must keep retrying")
	}
	b.put("/etc/port49/policy.yaml", "root:root", "0644", cur)
	shapetest.Ready(t, "127.0.0.1:9049") // back with no reset-failed: nothing was ever failed

	// 5b. The shipped units' ExecReload: the attestation roots are re-read with no restart.
	reloadCell(t, u)

	// 5c. The hardening the units say systemd-analyze security scores.
	hardeningCell(t, b)

	// 5d. The shipped export and snapshot units, and the directories tmpfiles.d makes for them.
	backupsCell(t, u)

	// 6. The admin calls: an unproved revoke is 401 with a challenge; then the break-glass with the
	// broker stopped, as the README writes it (sudo -u port49-broker ...), revokes bob, and --lift lifts it.
	// As root the same command refuses and revokes nothing: the owner check comes before the write.
	shapetest.AdminNeedsTouch(t, brokerDir, "127.0.0.1:8443", bob)
	breakGlass := must(sdtest.BreakGlass(readHost(t, filepath.Join(u.root, "deploy", "systemd", "README.md"))))
	for _, lift := range []bool{false, true} {
		line := breakGlass
		if lift {
			line += " --lift"
		}
		b.sh("systemctl stop port49-broker")
		if !lift {
			// The refusal's words are internal/port49d/offline.go:offlineOwnerHint.
			asRoot := strings.TrimPrefix(line, "sudo -u port49-broker ")
			out, err := b.exec("", strings.Fields(asRoot)...)
			for _, want := range []string{
				"nothing was revoked",
				"run it as the user that owns broker.state_dir",
				"e.g. sudo -u port49-broker port49-broker revoke --offline ...",
				"do not chown the directory",
			} {
				if err == nil || !strings.Contains(out, want) {
					t.Fatalf("`port49-broker revoke --offline` as root must refuse with %q (err %v)", want, err)
				}
			}
			if listed := b.sh("sudo -u port49-broker port49-broker revoke --offline --list"); strings.Contains(listed, bob) {
				t.Fatalf("root's refused revoke left a mark for %s in the store", bob)
			}
		}
		b.sh(line)
		b.sh("systemctl start port49-broker")
		shapetest.Ready(t, "127.0.0.1:9050")
		if lift {
			shapetest.OfflineLifted(t, brokerDir, "127.0.0.1:8443", bob)
		} else {
			shapetest.OfflineRevoked(t, brokerDir, "127.0.0.1:8443", bob)
		}
	}
	fmt.Fprintln(os.Stderr, "systemd smoke: login, floor line, restart, state_dir, key version added, /etc fence, retry loop, reload, hardening, backups, admin cells")
}

func atLeast(s string, n int) bool {
	var v int
	_, err := fmt.Sscan(s, &v)
	return err == nil && v >= n
}
