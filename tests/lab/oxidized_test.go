//go:build lab

package lab

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

// Oxidized on the lab's compose stack (plan 8, L49): the example's wrapper
// mints a token per node, Oxidized logs in to the lab's devices with it.
const (
	// oxidizedImage is compose/oxidized.yaml's image, pinned by digest; a unit
	// test holds the two equal. `oxidized --version` says 0.37.0-101-g65125713.
	oxidizedImage   = "oxidized/oxidized:latest@sha256:b58a2db261be348990a2345ad3cec8dba03b373ac817865ef1080bd7db7d2ccc"
	oxidizedVersion = "0.37.0-101-g65125713"
	oxidizedREST    = "http://127.0.0.1:18888"
	// oxidizedAnchor is the workload CA in the broker's container
	// (compose/oxidized.yaml mounts it there).
	oxidizedAnchor = "/etc/port49-workload/workload-ca.pem"
	// oxidizedUser is the username the policy gives the workload (l48Subject).
	oxidizedUser = l48Subject
	// brokerPublished is the compose stack's broker on the host.
	brokerPublished = "https://127.0.0.1:8449"
)

// oxidized is Oxidized as TestL49Oxidized runs it: the compose stack with the
// overlay, its directory under c.local, and the workload's PKI beside it.
type oxidized struct {
	t        *testing.T
	l        *lab
	c        *composeStack
	dir      string // c.local/oxidized: Oxidized's config directory
	workload string // c.local/workload: the workload's CA, certificate and key
	nodes    string // the wrapper's OXIDIZED_NODES file
	repo     string
	http     *http.Client
}

// exampleRole is the role block of examples/oxidized/policy.yaml (raw): the
// text between "roles:" and "subjects:", comment lines dropped, and its name.
func exampleRole(raw string) (block, name string, err error) {
	_, after, ok := strings.Cut(raw, "\nroles:\n")
	if !ok {
		return "", "", errors.New("examples/oxidized/policy.yaml has no roles: block")
	}
	body, _, ok := strings.Cut(after, "\nsubjects:")
	if !ok {
		return "", "", errors.New("examples/oxidized/policy.yaml has no subjects: block after its roles")
	}
	var lines []string
	for _, ln := range strings.Split(body, "\n") {
		if t := strings.TrimSpace(ln); t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		lines = append(lines, ln)
	}
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "  - name: ") {
		return "", "", errors.New("examples/oxidized/policy.yaml's role does not start with `  - name:`")
	}
	return strings.Join(lines, "\n") + "\n", strings.TrimPrefix(lines[0], "  - name: "), nil
}

// workloadE2EFiles gives the compose stack's broker the identity block (the
// stack's human anchor, and the workload anchor oxidizedAnchor with
// spiffe_trust_domains [port49.lab]) and a policy granting l48ID svc-oxidized
// on every device. roleBlock, with the name roleName, is the role it gets: a
// `permit: ["**"]` one for phase A, examples/oxidized/policy.yaml's for the
// rest.
func workloadE2EFiles(files map[string]string, roleBlock, roleName string) error {
	b := files["port49-broker.yaml"]
	i := strings.Index(b, "  client_ca_file:")
	if i < 0 {
		return errors.New("port49-broker.yaml has no client_ca_file to replace")
	}
	j := strings.Index(b[i:], "\n") + i + 1
	anchor := strings.TrimSpace(strings.TrimPrefix(b[i:j-1], "  client_ca_file:"))
	files["port49-broker.yaml"] = b[:i] + "  identity:\n    humans:\n      - {type: x509, trust_anchor_file: " + anchor + "}\n" +
		"    machines:\n      - {type: x509, trust_anchor_file: " + oxidizedAnchor + ", spiffe_trust_domains: [port49.lab]}\n" + b[j:]
	for _, add := range []struct{ key, entries string }{
		{"roles:\n", roleBlock},
		{"subjects:\n", fmt.Sprintf("  - {name: svc_oxidized, identity: [%q], username: %s, token_ttl: 900s}\n", l48ID, oxidizedUser)},
		{"grants:\n", fmt.Sprintf("  - {subject: svc_oxidized, scope: all_devices, roles: [%s], max_privilege: admin}\n", roleName)},
	} {
		if !strings.Contains(files["policy.yaml"], add.key) {
			return fmt.Errorf("policy.yaml has no %q block to add to", strings.TrimSpace(add.key))
		}
		files["policy.yaml"] = strings.Replace(files["policy.yaml"], add.key, add.key+add.entries, 1)
	}
	return nil
}

// allRole is phase A's role: everything, so what Oxidized's models send is
// recorded whatever it is.
const allRole = "  - {name: oxidized_all, privilege: admin, permit: [\"**\"]}\n"

// startOxidized brings the compose stack up with Oxidized on it
// (startComposeWith with compose/oxidized.yaml) and waits for Oxidized's REST
// API. restricted false gives the workload phase A's role (permit **); true
// gives examples/oxidized/policy.yaml's. The stack's configs are copied into
// its volumes once, at `up`, so a different role is a different start. A fault
// is t.Fatal: INVALID, never a measured "no".
func startOxidized(t *testing.T, l *lab, restricted bool) *oxidized {
	t.Helper()
	repo, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	roleBlock, roleName := allRole, "oxidized_all"
	if restricted {
		raw, err := os.ReadFile(filepath.Join(repo, "examples", "oxidized", "policy.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if roleBlock, roleName, err = exampleRole(string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	o := &oxidized{t: t, l: l, repo: repo, http: &http.Client{Timeout: 15 * time.Second}}
	// The overlay runs Oxidized as the host user (compose/oxidized.yaml says why).
	t.Setenv("PORT49_LAB_UID", strconv.Itoa(os.Getuid()))
	t.Setenv("PORT49_LAB_GID", strconv.Itoa(os.Getgid()))
	o.c = l.startComposeWith(t, composeOptions{Overlay: "oxidized.yaml",
		Files:   func(files map[string]string) error { return workloadE2EFiles(files, roleBlock, roleName) },
		Prepare: o.prepare})
	// Oxidized's log may hold a login failure naming a username, which is a
	// token: it stays on disk and is never quoted in a note.
	if err := o.c.follow(composeProject+"-oxidized-1", "0s", filepath.Join(o.c.dir, "oxidized.out"),
		filepath.Join(o.c.dir, "oxidized.err")); err != nil {
		t.Fatal(err)
	}
	if err := o.awaitREST(3 * time.Minute); err != nil {
		t.Fatalf("Oxidized's REST API never answered: %v\ncompose.log (tail):\n%s", err, o.c.tail(30))
	}
	return o
}

// prepare writes what the overlay mounts, under c.local, before `up`: the
// workload PKI, and Oxidized's directory with examples/oxidized/config
// (rest on 127.0.0.1:18888), an empty router.db, and known_hosts filled by
// ssh-keyscan of the platform's device.
func (o *oxidized) prepare(c *composeStack) error {
	o.workload = filepath.Join(c.local, "workload")
	if err := testpki.WriteWorkloadLab(o.workload, l48ID, time.Now()); err != nil {
		return err
	}
	o.dir = filepath.Join(c.local, "oxidized")
	if err := os.MkdirAll(o.dir, 0o700); err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(o.repo, "examples", "oxidized", "config"))
	if err != nil {
		return err
	}
	cfg := string(raw)
	if !strings.Contains(cfg, "rest: 127.0.0.1:8888\n") {
		return errors.New("examples/oxidized/config has no `rest: 127.0.0.1:8888` line")
	}
	cfg = strings.Replace(cfg, "rest: 127.0.0.1:8888\n", "rest: 127.0.0.1:18888\n", 1)
	known, err := o.keyscan(o.l.p.addr, 90*time.Second)
	if err != nil {
		return err
	}
	o.nodes = filepath.Join(c.local, "oxidized-nodes")
	for path, body := range map[string]string{
		filepath.Join(o.dir, "config"):      cfg,
		filepath.Join(o.dir, "router.db"):   "",
		filepath.Join(o.dir, "known_hosts"): known,
		o.nodes:                             o.l.p.node + "\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// keyscan is `ssh-keyscan -T 10 addr`, retried while the device's sshd comes up.
func (o *oxidized) keyscan(addr string, within time.Duration) (string, error) {
	deadline := time.Now().Add(within)
	for {
		out, err := exec.Command("ssh-keyscan", "-T", "10", addr).Output()
		if err == nil && strings.TrimSpace(string(out)) != "" {
			return string(out), nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("ssh-keyscan %s found no host key in %s: %v", addr, within, err)
		}
		time.Sleep(3 * time.Second)
	}
}

// get is one GET on Oxidized's REST API: status and body.
func (o *oxidized) get(path string) (int, []byte, error) {
	resp, err := o.http.Get(oxidizedREST + path)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, body, err
}

// awaitREST waits for the REST API to answer.
func (o *oxidized) awaitREST(within time.Duration) error {
	deadline := time.Now().Add(within)
	for {
		code, _, err := o.get("/nodes?format=json")
		if err == nil && code == http.StatusOK {
			return nil
		}
		if err == nil {
			err = fmt.Errorf("/nodes answered %d", code)
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(2 * time.Second)
	}
}

// lastRun reads the "last" run out of a /node/show answer: its status and end
// time. Oxidized writes the time as "2006-01-02 15:04:05 UTC".
func lastRun(raw []byte) (string, time.Time, error) {
	var show struct {
		Last *struct {
			Status string `json:"status"`
			End    string `json:"end"`
		} `json:"last"`
	}
	if err := json.Unmarshal(raw, &show); err != nil {
		return "", time.Time{}, fmt.Errorf("node/show is not JSON: %w", err)
	}
	if show.Last == nil {
		return "", time.Time{}, nil // never run
	}
	var end time.Time
	for _, layout := range []string{"2006-01-02 15:04:05 MST", "2006-01-02 15:04:05 -0700", time.RFC3339} {
		if t, err := time.Parse(layout, show.Last.End); err == nil {
			end = t
			break
		}
	}
	if end.IsZero() && show.Last.End != "" {
		return show.Last.Status, time.Time{}, fmt.Errorf("node/show's end time %q is in no known layout", show.Last.End)
	}
	return show.Last.Status, end, nil
}

// nodeStatus is `GET /node/show/<node>?format=json`: the last run's status
// ("" and the zero time for a node that has not run) and end time.
func (o *oxidized) nodeStatus(node string) (string, time.Time, error) {
	code, body, err := o.get("/node/show/" + node + "?format=json")
	if err != nil {
		return "", time.Time{}, err
	}
	if code != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("node/show/%s answered %d", node, code)
	}
	return lastRun(body)
}

// fetchConfig is `GET /node/fetch/<node>?format=json`: the configuration
// Oxidized holds for the node.
func (o *oxidized) fetchConfig(node string) (string, error) {
	code, body, err := o.get("/node/fetch/" + node + "?format=json")
	if err != nil {
		return "", err
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("node/fetch/%s answered %d", node, code)
	}
	var s string
	if json.Unmarshal(body, &s) == nil {
		return s, nil
	}
	return string(body), nil
}

// oxidizedCommands are the commands in the daemon's authorize_command
// records for username, in order and once each.
func oxidizedCommands(recs []map[string]any, username string) []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range recs {
		if str(r, "event") != "authorize_command" || str(sub(r, "session"), "username") != username {
			continue
		}
		cmd := strings.Join(strs(sub(r, "request"), "vector"), " ")
		if cmd == "" || seen[cmd] {
			continue
		}
		seen[cmd] = true
		out = append(out, cmd)
	}
	return out
}

// runWrapper runs examples/oxidized/port49-oxidized-run as the host user with
// PORT49_BIN=bin/port49, the stack's broker URL and CA, the workload files,
// OXIDIZED_NODES holding the platform's node, OXIDIZED_ROUTER_DB the volume's
// router.db, OXIDIZED_REST, and PORT49_TTL=ttl. It returns the exit code and
// stderr (the wrapper never prints a token).
func (o *oxidized) runWrapper(ttl string) (int, string) {
	cmd := exec.Command("bash", filepath.Join(o.repo, "examples", "oxidized", "port49-oxidized-run"))
	cmd.Dir = o.repo
	cmd.Env = append(os.Environ(),
		"PORT49_BIN="+filepath.Join(o.repo, "bin", "port49"),
		"PORT49_BROKER="+brokerPublished,
		"PORT49_BROKER_CA="+filepath.Join(o.c.local, "broker", testpki.LabCA),
		"PORT49_CERT="+filepath.Join(o.workload, testpki.WorkloadCert),
		"PORT49_KEY="+filepath.Join(o.workload, testpki.WorkloadKey),
		"OXIDIZED_NODES="+o.nodes,
		"OXIDIZED_ROUTER_DB="+filepath.Join(o.dir, "router.db"),
		"OXIDIZED_REST="+oxidizedREST,
		"PORT49_TTL="+ttl)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, errb.String()
	case errors.As(err, &ee):
		return ee.ExitCode(), errb.String()
	}
	return -1, errb.String() + strings.TrimSpace(err.Error())
}

// TestL49Oxidized is the harness's bring-up for L49 (policy engine spec §15):
// the compose stack with one platform's devices and Oxidized on it, REST
// answering. Task 14 adds the phases; until then the test stops at a Skip, so
// `make lab-oxidized` can never read as a measurement.
func TestL49Oxidized(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		startOxidized(t, l, false)
		t.Skip("harness bring-up passed; L49's phases are plan 8 Task 14's")
	})
}
