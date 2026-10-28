//go:build compose

// Package compose is the container shape's smoke test (plan 7f, Task 1):
// deploy/compose brought up on a fresh PKI, a device login through it, the
// stack recreated with its volumes kept, and then the same session's next
// command answered, a token minted before redeemed, and the broker's
// broker.state_dir accepted as it was left. `make compose-smoke` runs it;
// `go test ./...` never builds it.
package compose

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
)

const project = "port49smoke"

// stack runs docker compose on deploy/compose/compose.yaml as project,
// with local as PORT49_COMPOSE_LOCAL.
type stack struct {
	t           *testing.T
	file, local string
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
	cmd.Env = append(os.Environ(), "PORT49_COMPOSE_LOCAL="+s.local)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ready waits up to 3 minutes for /readyz at addr to answer 200.
func ready(t *testing.T, s stack, addr string) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Minute); ; time.Sleep(time.Second) {
		resp, err := http.Get("http://" + addr + "/readyz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s/readyz not 200 in 3m (%v)\n%s", addr, err, s.run("logs", "--no-color"))
		}
	}
}

// envValue is name's value in the env file at path.
func envValue(t *testing.T, path, name string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), name+"="); ok {
			return v
		}
	}
	t.Fatalf("%s names no %s", path, name)
	return ""
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

func TestComposeSmoke(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	local := t.TempDir()
	if err := testpki.WriteCompose(local, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	s := stack{t: t, file: filepath.Join(root, "deploy", "compose", "compose.yaml"), local: local}
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := s.try("logs", "--no-color")
			t.Logf("docker compose logs:\n%s", out)
		}
		s.try("down", "-v", "--remove-orphans")
	})
	s.run("up", "-d", "--build")
	ready(t, s, "127.0.0.1:9050")
	ready(t, s, "127.0.0.1:9049")

	dev := device{t: t, addr: "127.0.0.1:49", key: []byte(envValue(t, filepath.Join(local, "port49d.env"), "PORT49_KEY_TACACS"))}
	if st := dev.login("alice", mint(t, local, "127.0.0.1:8443", "smoke1")); st != wire.AuthenStatusPass {
		t.Fatalf("a device login through the stack: status %d", st)
	}
	if !dev.permits("alice") || !dev.permits("alice", "show", "version") {
		t.Fatal("the session's authorization was refused")
	}
	later := mint(t, local, "127.0.0.1:8443", "smoke1") // redeemed after the recreate

	// A revocation writes the broker's copy of the marks into
	// broker.state_dir (marks.json), which the recreate must keep.
	// The live form is the API with a security key press (spec §5.1.6), which a
	// stack with no key cannot make: the break-glass form writes the same mark
	// through etcd as the broker's own user.
	s.run("run", "--rm", "--no-deps", "--entrypoint", "port49-broker", "port49-broker", "revoke", "--offline",
		"--principal", "user:bob@example.com") // s.run fails the test on a non-zero exit
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
	ready(t, s, "127.0.0.1:9050")
	ready(t, s, "127.0.0.1:9049")

	second := s.run("logs", "--no-color", "port49-broker")
	if strings.Contains(second, "is absent") || strings.Contains(second, "cannot tell whether the store was restored") {
		t.Fatalf("the recreated broker did not find its broker.state_dir as it was left:\n%s", second)
	}
	if !dev.permits("alice", "show", "version") {
		t.Fatal("the session's next command after the recreate was refused: its context did not survive in etcd")
	}
	if st := dev.login("alice", later); st != wire.AuthenStatusPass {
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
	fmt.Fprintln(os.Stderr, "compose smoke: login, recreate, session kept, token redeemed, state_dir kept")
}
