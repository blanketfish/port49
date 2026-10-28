//go:build compose

// Package compose is the container shape's smoke test (plan 7f, Task 1; plan
// 12b, Task 6): deploy/compose brought up on a fresh PKI, a device login
// through it, the stack recreated with its volumes kept, and then the same
// session's next command answered, a token minted before redeemed, and the
// broker's broker.state_dir accepted as it was left. Then a device key
// version added with no restart, the admin cells (a revoke with no touch is
// 401, and the break-glass revoke and lift round trip), and a check that no
// secret is in any container's environment. `make compose-smoke` runs it;
// `go test ./...` never builds it.
package compose

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/tests/shapes/shapetest"
)

const (
	project  = "port49smoke"
	rootsRef = "/etc/port49/broker/" + shapetest.RootsName
)

// stack runs docker compose on deploy/compose/compose.yaml as project,
// with local as PORT49_COMPOSE_LOCAL and config as PORT49_COMPOSE_CONFIG.
type stack struct {
	t                   *testing.T
	file, local, config string
}

func (s stack) run(args ...string) string {
	s.t.Helper()
	out, err := s.try(args...)
	if err != nil {
		s.t.Fatalf("docker compose %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func (s stack) try(args ...string) (string, error) {
	cmd := exec.Command("docker", append([]string{"compose", "-p", project, "-f", s.file}, args...)...)
	cmd.Env = append(os.Environ(), "PORT49_COMPOSE_LOCAL="+s.local, "PORT49_COMPOSE_CONFIG="+s.config)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// newStack writes the trial PKI and a copy of the shipped config, rendered
// for the admin cells (AdminBroker, AdminPolicy), and returns the stack with
// the cleanup that takes it down, volumes too, even on failure.
func newStack(t *testing.T) stack {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	local := t.TempDir()
	if err := testpki.WriteCompose(local, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	_, subject := shapetest.AdminSetup(t, filepath.Join(local, "broker"))
	shipped := filepath.Join(root, "deploy", "compose", "config")
	cfg := t.TempDir()
	entries, err := os.ReadDir(shipped)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(shipped, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		switch e.Name() {
		case "port49-broker.yaml":
			b = []byte(shapetest.AdminBroker(t, string(b), rootsRef))
		case "policy.yaml":
			b = []byte(shapetest.AdminPolicy(t, string(b), subject))
		}
		if err := os.WriteFile(filepath.Join(cfg, e.Name()), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s := stack{t: t, file: filepath.Join(root, "deploy", "compose", "compose.yaml"), local: local, config: cfg}
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := s.try("logs", "--no-color")
			t.Logf("docker compose logs:\n%s", out)
		}
		s.try("down", "-v", "--remove-orphans")
	})
	return s
}

// ready is shapetest.Ready (the cleanup prints the logs on a failure).
func (s stack) ready(addr string) {
	s.t.Helper()
	shapetest.Ready(s.t, addr)
}

// waitMarks waits up to 30s for marks.json to exist and be non-empty in the
// broker-state volume, looked at from a throwaway container on the image
// the volume was made from.
func waitMarks(t *testing.T) {
	t.Helper()
	var out []byte
	var err error
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		out, err = exec.Command("docker", "run", "--rm", "-v", project+"_broker-state:/s", "--entrypoint", "test",
			"port49-setup:dev", "-s", "/s/marks.json").CombinedOutput()
		if err == nil {
			return
		}
	}
	t.Fatalf("broker.state_dir/marks.json was not written in 30s after the revoke: %v\n%s", err, out)
}

// composeRotator writes through a throwaway container on the setup image,
// which mounts the volumes the stack's processes read, as root (setup.sh's
// own owner and modes).
type composeRotator struct {
	s      stack
	policy []byte
}

func (c composeRotator) KeyDir() string     { return "/run/port49/keys" }
func (c composeRotator) BasePolicy() []byte { return c.policy }

func (c composeRotator) sh(stdin []byte, script string, args ...string) error {
	cmd := exec.Command("docker", append([]string{"run", "--rm", "-i",
		"-v", project + "_port49d-keys:/k", "-v", project + "_port49d-etc:/e", "-v", project + "_broker-etc:/b",
		"--entrypoint", "sh", "port49-setup:dev", "-c", script, "sh"}, args...)...)
	cmd.Stdin = strings.NewReader(string(stdin))
	if out, err := cmd.CombinedOutput(); err != nil {
		// The script's output is names and exit codes, never the bytes it was given.
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

// WritePolicy puts the policy into both -etc volumes, each by a temporary
// file and mv, so a reader never sees half a file.
func (c composeRotator) WritePolicy(policyYAML []byte) error {
	return c.sh(policyYAML, `set -eu; cat > /tmp/p
for d in /e /b; do install -o 0 -g 0 -m 0644 /tmp/p $d/.policy.new && mv $d/.policy.new $d/policy.yaml; done`)
}

// WriteKey makes keys/<name> root:65532 0440 in port49d-keys, never replacing one.
func (c composeRotator) WriteKey(name string, secret []byte) error {
	return c.sh(secret, `set -eu; umask 077; cd /k
[ ! -e "$1" ] && [ ! -L "$1" ]
t=$(mktemp ./.key.XXXXXX); trap 'rm -f "$t"' EXIT
cat > "$t"; chown 0:65532 "$t"; chmod 0440 "$t"; ln "$t" "$1"`, name)
}

func (c composeRotator) StartedAt() string {
	c.s.t.Helper()
	id := strings.TrimSpace(c.s.run("ps", "-q", "port49d"))
	out, err := exec.Command("docker", "inspect", "-f", "{{.State.StartedAt}}", id).CombinedOutput()
	if err != nil {
		c.s.t.Fatalf("docker inspect port49d: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func TestComposeSmoke(t *testing.T) {
	s := newStack(t)
	brokerDir := filepath.Join(s.local, "broker")
	s.run("up", "-d", "--build")
	s.ready("127.0.0.1:9050")
	s.ready("127.0.0.1:9049")

	key, err := os.ReadFile(filepath.Join(s.local, "keys", "tacacs_v1"))
	if err != nil {
		t.Fatal(err)
	}
	dev := shapetest.Device{T: t, Addr: "127.0.0.1:49", Key: key}
	mint := func() string { return shapetest.Mint(t, brokerDir, "127.0.0.1:8443", "smoke1") }
	if st := dev.Login("alice", mint()); st != wire.AuthenStatusPass {
		t.Fatalf("a device login through the stack: status %d", st)
	}
	if !dev.Permits("alice") || !dev.Permits("alice", "show", "version") {
		t.Fatal("the session's authorization was refused")
	}
	// Decision 54 ruling 14: the etcd floor, naming every member, never a VIP.
	shapetest.FloorLine(t, s.run("logs", "--no-color", "port49d"),
		[]string{"https://etcd-1:2379", "https://etcd-2:2379", "https://etcd-3:2379"})
	later := mint() // redeemed after the recreate

	// A revocation writes the broker's copy of the marks into
	// broker.state_dir (marks.json), which the recreate must keep.
	// The live form is the API with a security key press (spec §5.1.6), which a
	// stack with no key cannot make: the break-glass form writes the same mark
	// through etcd as the broker's own user. carol is not a principal the later
	// cells use.
	s.run("run", "--rm", "--no-deps", "port49-broker", "revoke", "--offline",
		"--principal", "user:carol@example.com") // s.run fails the test on a non-zero exit
	first := s.run("logs", "--no-color", "port49-broker")
	if !strings.Contains(first, "broker.state_dir/marks.json is absent") {
		t.Fatalf("a first start did not say its copy starts from the store:\n%s", first)
	}

	// The broker writes its copy from the store's watch, after the offline
	// revoke has returned (internal/port49d/markscopy.go): wait for marks.json
	// before the recreate, or a fast `down` makes "is absent" flaky.
	waitMarks(t)

	// Recreate every container; the named volumes stay.
	s.run("down")
	s.run("up", "-d")
	s.ready("127.0.0.1:9050")
	s.ready("127.0.0.1:9049")

	second := s.run("logs", "--no-color", "port49-broker")
	if strings.Contains(second, "is absent") || strings.Contains(second, "cannot tell whether the store was restored") {
		t.Fatalf("the recreated broker did not find its broker.state_dir as it was left:\n%s", second)
	}
	if !dev.Permits("alice", "show", "version") {
		t.Fatal("the session's next command after the recreate was refused: its context did not survive in etcd")
	}
	if st := dev.Login("alice", later); st != wire.AuthenStatusPass {
		t.Fatalf("a token minted before the recreate: status %d", st)
	}
	// The volume as the image made it, and as the broker left it.
	st, err := exec.Command("docker", "run", "--rm", "-v", project+"_broker-state:/s", "--entrypoint", "stat",
		"port49-setup:dev", "-c", "%u %g %a", "/s", "/s/marks.json").CombinedOutput()
	if err != nil {
		t.Fatalf("stat the broker-state volume: %v\n%s", err, st)
	}
	lines := strings.Split(strings.TrimSpace(string(st)), "\n")
	if len(lines) != 2 || lines[0] != "65532 65532 700" || !strings.HasPrefix(lines[1], "65532 ") {
		t.Fatalf("broker-state: %q, want the directory 65532 65532 700 and marks.json owned by 65532", lines)
	}
	sp, err := exec.Command("docker", "run", "--rm", "-v", project+"_port49d-spool:/s", "--entrypoint", "stat",
		"port49-setup:dev", "-c", "%u %g %a", "/s").CombinedOutput()
	if err != nil || strings.TrimSpace(string(sp)) != "65532 65532 700" {
		t.Fatalf("port49d-spool: %q (%v), want 65532 65532 700", sp, err)
	}

	// A key version added with no restart (decision 54 ruling 2).
	policy, err := os.ReadFile(filepath.Join(s.config, "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	shapetest.RotateCell(t, dev, "alice", mint, "127.0.0.1:9049", 90*time.Second, composeRotator{s: s, policy: policy})

	// The admin cells: a revoke with no touch is 401 and changes nothing, and
	// the break-glass form (every broker stopped) revokes and lifts.
	const bob = "user:bob@example.com"
	shapetest.AdminNeedsTouch(t, brokerDir, "127.0.0.1:8443", bob)
	for _, lift := range []bool{false, true} {
		args := []string{"run", "--rm", "--no-deps", "port49-broker", "revoke", "--offline", "--principal", bob}
		if lift {
			args = append(args, "--lift")
		}
		s.run("stop", "port49-broker")
		s.run(args...)
		s.run("start", "port49-broker")
		s.ready("127.0.0.1:9050")
		if lift {
			shapetest.OfflineLifted(t, brokerDir, "127.0.0.1:8443", bob)
		} else {
			shapetest.OfflineRevoked(t, brokerDir, "127.0.0.1:8443", bob)
		}
	}
	fmt.Fprintln(os.Stderr, "compose smoke: login, floor line, recreate, session kept, token redeemed, state_dir kept, key version added, admin cells")
}

// TestTheStackHasNoEnvSecret: no running container's environment holds a
// device key or a sealing key. Failures name the variable, never its value.
func TestTheStackHasNoEnvSecret(t *testing.T) {
	s := newStack(t)
	s.run("up", "-d", "--build")
	for _, id := range strings.Fields(s.run("ps", "-q")) {
		out, err := exec.Command("docker", "inspect", "-f", "{{range .Config.Env}}{{println .}}{{end}}", id).Output()
		if err != nil {
			t.Fatalf("docker inspect %s: %v", id, err)
		}
		for _, kv := range strings.Split(string(out), "\n") {
			name, _, _ := strings.Cut(kv, "=")
			if strings.HasPrefix(name, "PORT49_KEY_") || strings.HasPrefix(name, "PORT49_ENC") {
				t.Errorf("container %.12s has %s in its environment", id, name)
			}
		}
	}
}
