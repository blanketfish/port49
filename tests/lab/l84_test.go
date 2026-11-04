//go:build lab

package lab

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/tacacs/wire"
	"github.com/blanketfish/port49/internal/testpki"
	"github.com/blanketfish/port49/tests/shapes/l84"
	"github.com/blanketfish/port49/tests/shapes/shapetest"
)

// l84DiskFloorMB is L84's own free-disk floor on /, not L66's 66 GiB (a hosted runner has about 14 GiB free).
// Measured from what the cells hold: port49:dev 120 MB, port49-setup:dev 74 MB and etcd 92 MB (docker images),
// the Debian systemd image of tests/systemd (about 120 MB base plus the packages), three small etcd volumes, and
// the build's dist/. About 1 GB at peak; 4 GiB leaves headroom. There is no env override.
const l84DiskFloorMB = 4096

// TestL84 measures spec §15 L84 on the lab host: host credential mechanisms against
// fence.ReadSecret. Cells (b) and (c) for Compose run here, on deploy/compose with the local
// port49:dev and port49-setup:dev images (nothing is pulled or built); cell (a) and (c) for
// systemd run in Task 9's container (tests/systemd/l84_test.go, tag systemd, `make lab-l84-systemd`)
// and arrive as PORT49_L84_A_CELLS, a JSON file of cells; without it they are NOT RUN in the note.
// The note (PORT49_L84_NOTE, a path) is built from the cells only (tests/shapes/l84.Note).
//
// Logs are read only through tests/qual/secret-filter.sh. Keys are random per run, written to
// 0700 temp directories, never printed; the compose project is port49l84, taken down with its
// volumes on every exit.
func TestL84(t *testing.T) {
	if os.Getenv("PORT49_LAB_L84") != "1" {
		t.Skip("PORT49_LAB_L84=1 runs L84 (make lab-l84); `make lab` does not")
	}
	if err := labGuardAt(l66StopSentinel, "/", l84DiskFloorMB); err != nil {
		t.Fatal(err)
	}
	if err := labOccupyForRun(labLockPath, fmt.Sprintf("TestL84 pid %d", os.Getpid())); err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	if root == "" {
		r, err := repoRoot()
		if err != nil {
			t.Fatalf("INVALID: repo root: %v", err)
		}
		root = r
		t.Cleanup(func() { root = "" })
	}
	env := l84Env(t)
	s := newL84Stack(t)
	cells := s.composeCells()
	if p := os.Getenv("PORT49_L84_A_CELLS"); p != "" {
		extra, err := l84.Load(p)
		if err != nil {
			t.Fatalf("INVALID: PORT49_L84_A_CELLS: %v", err)
		}
		cells = l84.Merge(cells, extra)
	}
	note := l84.Note(env, cells)
	if p := os.Getenv("PORT49_L84_NOTE"); p != "" {
		if err := os.WriteFile(p, []byte(note), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range cells {
		t.Logf("L84 cell %s: %s", c.ID, c.Verdict)
	}
	for _, mech := range []string{"systemd", "long", "short"} {
		t.Logf("L84: %s may be named for a device key: %v", mech, l84.MayOffer(cells, mech))
	}
}

func l84Out(name string, args ...string) string {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return "unavailable"
	}
	return strings.TrimSpace(string(out))
}

func l84Env(t *testing.T) l84.Env {
	t.Helper()
	img := func(ref string) string {
		id := l84Out("docker", "image", "inspect", "-f", "{{.Id}} {{.Created}}", ref)
		if id == "unavailable" {
			t.Fatalf("INVALID: image %s is not on this host (nothing is pulled or built)", ref)
		}
		return ref + " " + strings.TrimPrefix(strings.Fields(id)[0], "sha256:")[:12] + " created " + strings.Fields(id)[1]
	}
	return l84.Env{
		Date:    time.Now().UTC().Format("2006-01-02"),
		Docker:  l84Out("docker", "version", "--format", "{{.Server.Version}}"),
		Compose: l84Out("docker", "compose", "version", "--short"),
		Kernel:  l84Out("uname", "-r"),
		Systemd: "each systemd cell records its own: the Debian container's in the container cell (a)'s first row, the runner's in the first row of the host cells; none is run unless PORT49_L84_A_CELLS is given",
		Images: strings.Join([]string{img("port49:dev"), img("port49-setup:dev"), img("gcr.io/etcd-development/etcd:v3.6.15")}, "; ") +
			" (Docker, Compose and the kernel are the lab host's)",
	}
}

// l84Variant is how the host file for a secret is owned and moded: what Compose bind-mounts.
type l84Variant struct{ label, owner, mode string }

var l84Variants = []l84Variant{
	{"root:65532 0440 (the recommended file)", "0:65532", "0440"},
	{"root:65532 0444", "0:65532", "0444"},
	{"owned by the operator, 0440", "", "0440"},
}

type l84Stack struct {
	t                        *testing.T
	file, local, cfg, secdir string
	override, brokerDir      string
	dev                      shapetest.Device
	key                      []byte
	policy                   []byte
	started                  bool
}

func newL84Stack(t *testing.T) *l84Stack {
	t.Helper()
	s := &l84Stack{t: t, file: filepath.Join(root, "deploy", "compose", "compose.yaml")}
	for _, p := range []string{"127.0.0.1:49", "127.0.0.1:8443", "127.0.0.1:9049", "127.0.0.1:9050"} {
		// A dial, not a listen: 49 is privileged for this user, so a listen says "denied" either way.
		if c, err := net.DialTimeout("tcp", p, time.Second); err == nil {
			c.Close()
			t.Fatalf("INVALID: something listens on %s, which the stack publishes", p)
		}
	}
	if nets := l84Out("sh", "-c", "docker network ls -q | xargs docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}'"); strings.Contains(nets, "172.30.49.0/24") {
		t.Fatalf("INVALID: a Docker network already uses 172.30.49.0/24, the stack's")
	}
	s.local = t.TempDir()
	if err := testpki.WriteCompose(s.local, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	s.brokerDir = filepath.Join(s.local, "broker")
	// The secret files live in a directory the cleanup can remove after docker made some root's.
	dir, err := os.MkdirTemp("", "port49-l84-")
	if err != nil {
		t.Fatal(err)
	}
	s.secdir = dir
	t.Cleanup(func() {
		exec.Command("docker", "run", "--rm", "-v", dir+":/d", "--entrypoint", "chown", "port49-setup:dev",
			"-R", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "/d").Run()
		os.RemoveAll(dir)
	})
	s.cfg = t.TempDir()
	composeDir := filepath.Join(root, "deploy", "compose")
	shipped := filepath.Join(composeDir, "config")
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
		case "port49d.yaml":
			if strings.Contains(string(b), "key_secret_refs") {
				t.Fatalf("INVALID: the shipped port49d.yaml already names key_secret_refs; the cell must change it deliberately")
			}
			b = append(b, []byte("\nkey_secret_refs: {file_dir: "+l84.MountDir+"}\n")...)
		case "policy.yaml":
			const old = "file:/run/port49/keys/tacacs_v1"
			if !strings.Contains(string(b), old) {
				t.Fatalf("INVALID: the shipped policy no longer names %s", old)
			}
			b = []byte(strings.Replace(string(b), old, "file:"+l84.MountDir+"/key", 1))
			s.policy = b
		}
		if err := os.WriteFile(filepath.Join(s.cfg, e.Name()), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if s.policy == nil {
		t.Fatal("INVALID: no policy.yaml in deploy/compose/config")
	}
	if s.key, err = os.ReadFile(filepath.Join(s.local, "keys", "tacacs_v1")); err != nil {
		t.Fatal(err)
	}
	s.dev = shapetest.Device{T: t, Addr: "127.0.0.1:49", Key: s.key}
	s.override = filepath.Join(t.TempDir(), "override.yaml")
	s.try("down", "-v", "--remove-orphans")
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("port49d log, filtered:\n%s", l84Filter(s.logs("port49d")))
		}
		s.try("down", "-v", "--remove-orphans")
	})
	return s
}

func (s *l84Stack) try(args ...string) (string, error) {
	a := []string{"compose", "-p", "port49l84", "-f", s.file}
	if _, err := os.Stat(s.override); err == nil {
		a = append(a, "-f", s.override)
	}
	cmd := exec.Command("docker", append(a, args...)...)
	cmd.Env = append(os.Environ(), "PORT49_COMPOSE_LOCAL="+s.local, "PORT49_COMPOSE_CONFIG="+s.cfg)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (s *l84Stack) logs(svc string) string {
	out, _ := s.try("logs", "--no-color", "--tail", "40", svc)
	return out
}

// l84Filter is tests/qual/secret-filter.sh on text: the only way a log is read here.
func l84Filter(text string) string {
	cmd := exec.Command("bash", filepath.Join(root, "tests", "qual", "secret-filter.sh"))
	cmd.Stdin = strings.NewReader(text)
	out, err := cmd.Output()
	if err != nil {
		return "(the secret filter failed; output withheld)"
	}
	return string(out)
}

// tail is the last n lines of filtered, each cut to 160 bytes, and how many lines the filter dropped.
func l84Tail(raw string, n int) string {
	kept := strings.Split(strings.TrimSpace(l84Filter(raw)), "\n")
	total := len(strings.Split(strings.TrimSpace(raw), "\n"))
	if len(kept) > n {
		kept = kept[len(kept)-n:]
	}
	for i, l := range kept {
		if len(l) > 160 {
			kept[i] = l[:160]
		}
	}
	return strings.Join(kept, " / ") + fmt.Sprintf(" (%d of %d log lines withheld by the filter)", total-len(strings.Split(strings.TrimSpace(l84Filter(raw)), "\n")), total)
}

// hostSecret writes a secret file under secdir/<dir> with body, owned as owner ("" is the operator)
// and moded mode, and returns its path. Root's ownership is made by a container that sees the
// directory, never by reading the file.
func (s *l84Stack) hostSecret(dir, name string, body []byte, owner, mode string) string {
	s.t.Helper()
	d := filepath.Join(s.secdir, dir)
	if err := os.MkdirAll(d, 0o755); err != nil {
		s.t.Fatal(err)
	}
	p := filepath.Join(d, name)
	if err := os.WriteFile(p, body, 0o600); err != nil {
		s.t.Fatal(err)
	}
	if owner == "" {
		var m uint32
		fmt.Sscanf(mode, "%o", &m)
		if err := os.Chmod(p, os.FileMode(m)); err != nil {
			s.t.Fatal(err)
		}
		return p
	}
	if out, err := exec.Command("docker", "run", "--rm", "-v", d+":/d", "--entrypoint", "sh", "port49-setup:dev", "-c",
		"chown "+owner+" /d/"+name+" && chmod "+mode+" /d/"+name).CombinedOutput(); err != nil {
		s.t.Fatalf("making %s %s %s: %v\n%s", name, owner, mode, err, l84Filter(string(out)))
	}
	return p
}

func (s *l84Stack) guard() {
	s.t.Helper()
	if err := labGuardAt(l66StopSentinel, "/", l84DiskFloorMB); err != nil {
		s.t.Fatal(err)
	}
}

func (s *l84Stack) ready(addr string) bool {
	resp, err := http.Get("http://" + addr + "/readyz")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func (s *l84Stack) mint() string { return shapetest.Mint(s.t, s.brokerDir, "127.0.0.1:8443", "smoke1") }

// apply writes the override and brings port49d up with it: the whole stack the first time, and port49d
// alone, recreated, after.
func (s *l84Stack) apply(syntax string, secrets []l84.Secret) (string, error) {
	ov, err := l84.Override(syntax, secrets)
	if err != nil {
		s.t.Fatal(err)
	}
	if err := os.WriteFile(s.override, []byte(ov), 0o644); err != nil {
		s.t.Fatal(err)
	}
	if !s.started {
		s.started = true
		return s.try("up", "-d", "--no-build")
	}
	return s.try("up", "-d", "--no-build", "--no-deps", "--force-recreate", "port49d")
}

// started waits for port49d to start with the key: /readyz 200 and a device login keyed with it. It
// returns what it saw in words, and no log line the filter keeps beyond the last few.
func (s *l84Stack) outcome(within time.Duration) (bool, string) {
	s.t.Helper()
	deadline := time.Now().Add(within)
	for ; time.Now().Before(deadline); time.Sleep(2 * time.Second) {
		s.guard()
		if !s.ready("127.0.0.1:9050") || !s.ready("127.0.0.1:9049") {
			continue
		}
		st, err := s.dev.TryLogin("alice", s.mint())
		if err != nil {
			return false, "ready, but the login did not complete: " + err.Error()
		}
		if st == wire.AuthenStatusPass {
			return true, "ready and a login keyed with it passed"
		}
		return false, fmt.Sprintf("ready, but a login keyed with it was refused (status %d)", st)
	}
	state := l84Out("docker", "ps", "-a", "--no-trunc", "--filter", "id="+s.cid(), "--format", "{{.State}}: {{.Status}}")
	return false, "port49d did not become ready in " + within.String() + " (" + state + "); log: " + l84Tail(s.logs("port49d"), 4)
}

// startedAt is the timestamp of port49d's last "metrics on" line, which it prints at every start, read
// through the secret filter (the container's StartedAt would come from the inspect command, which the lab never uses).
func (s *l84Stack) startedAt(cid string) string {
	out, err := exec.Command("docker", "logs", "--timestamps", cid).CombinedOutput()
	if err != nil {
		return "unavailable"
	}
	last := "unavailable"
	for _, l := range strings.Split(l84Filter(string(out)), "\n") {
		if f := strings.Fields(l); len(f) > 2 && strings.Contains(l, "port49d: metrics on") {
			last = f[0]
		}
	}
	return last
}

// cid is port49d's container id.
func (s *l84Stack) cid() string {
	return l84Out("docker", "compose", "-p", "port49l84", "ps", "-q", "port49d")
}

func (s *l84Stack) probe() string {
	out, err := s.try("run", "--rm", "--no-deps", "probe", "-c", "%u:%g %a", l84.MountDir+"/key")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if err != nil {
		return "stat failed: " + l84Tail(out, 2)
	}
	return lines[len(lines)-1]
}

func (s *l84Stack) composeCells() []l84.Cell {
	var cells []l84.Cell
	passed := map[string]l84Variant{}
	for _, syntax := range []string{"long", "short"} {
		cell := l84.Cell{ID: "b-" + syntax, Verdict: l84.Fail}
		for i, v := range l84Variants {
			s.guard()
			file := s.hostSecret(syntax+fmt.Sprint(i), "key", s.key, v.owner, v.mode)
			out, err := s.apply(syntax, []l84.Secret{{Name: "key", File: file}})
			if err != nil {
				cell.Rows = append(cell.Rows, l84.Row{Case: v.label, Observation: "docker compose up failed: " + l84Tail(out, 3)})
				continue
			}
			within := 60 * time.Second
			if i == 0 && syntax == "long" {
				within = 3 * time.Minute // the first start brings etcd up too
			}
			ok, what := s.outcome(within)
			cell.Rows = append(cell.Rows, l84.Row{Case: v.label, Observation: "stat in the container (uid:gid mode) " + s.probe() + "; " + what})
			if i == 0 && ok {
				cell.Verdict = l84.Pass
				passed[syntax] = v
			}
		}
		cell.Rows = append(cell.Rows, l84.Row{Case: "why, from the code", Observation: "fence.ReadSecret (internal/fence/fence_linux.go, ownedByUsOrRoot and the perm&0o027 test) accepts a file owned by the process's user or root with no group-write and no world bit; the stat above is the host file's, so these options are not applied (compare the stat with the uid, gid and mode asked for)"})
		cells = append(cells, cell)
	}
	for _, syntax := range []string{"long", "short"} {
		cells = append(cells, s.addVersion(syntax, passed[syntax]))
	}
	return cells
}

// addVersion is cell (c) for syntax: tacacs_v2 is added to a stack whose port49d started with the
// recommended file, without restarting port49d. The policy names it first (read at its watch
// interval, port49d untouched); then a second secrets: entry is added and `docker compose up -d`
// is run, the operator's only way to change a service's mounts; PASS iff a login keyed with
// version 2 passes within 120 s and port49d's container id and last start line timestamp are unchanged.
func (s *l84Stack) addVersion(syntax string, v l84Variant) l84.Cell {
	t := s.t
	cell := l84.Cell{ID: "c-" + syntax, Verdict: l84.NotRun}
	if v.mode == "" {
		cell.Rows = []l84.Row{{Case: "state", Observation: "not run: cell (b) did not pass for this syntax, so there is no running mechanism to add to"}}
		return cell
	}
	s.guard()
	// The base policy first: a restart while the policy names a version 2 file that is not there is
	// refused at start (seen on the first run of this cell), so no recreate may find the last cell's.
	if err := os.WriteFile(filepath.Join(s.cfg, "policy.yaml"), s.policy, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := s.try("up", "-d", "--no-build"); err != nil {
		cell.Verdict = l84.Fail
		cell.Rows = []l84.Row{{Case: "state", Observation: "restoring the base policy (up -d) failed: " + l84Tail(out, 3)}}
		return cell
	}
	time.Sleep(12 * time.Second) // the policy's watch interval is 5 s
	// Back to the passing start, so the container under test is the one (b) passed.
	file := s.hostSecret("c-"+syntax, "key", s.key, v.owner, v.mode)
	if out, err := s.apply(syntax, []l84.Secret{{Name: "key", File: file}}); err != nil {
		cell.Verdict = l84.Fail
		cell.Rows = []l84.Row{{Case: "state", Observation: "the passing start could not be repeated: " + l84Tail(out, 3)}}
		return cell
	}
	if ok, what := s.outcome(90 * time.Second); !ok {
		cell.Verdict = l84.Fail
		cell.Rows = []l84.Row{{Case: "state", Observation: "the passing start was not repeated: " + what}}
		return cell
	}
	id := func() (string, string) {
		cid := s.cid()
		return cid, s.startedAt(cid)
	}
	id0, at0 := id()
	next, err := shapetest.WithAcceptV2(s.policy, l84.MountDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.cfg, "policy.yaml"), next, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := s.try("up", "-d", "--no-build"); err != nil {
		cell.Verdict = l84.Fail
		cell.Rows = []l84.Row{{Case: "state", Observation: "writing the policy (up -d) failed: " + l84Tail(out, 3)}}
		return cell
	}
	time.Sleep(12 * time.Second) // the policy's watch interval is 5 s
	if id1, at1 := id(); id1 != id0 || at1 != at0 {
		cell.Verdict = l84.Fail
		cell.Rows = []l84.Row{{Case: "state", Observation: "the policy change alone recreated port49d: the cell cannot separate it from the secret"}}
		return cell
	}
	v2Bytes, err := testpki.RandomSecret(32)
	if err != nil {
		t.Fatal(err)
	}
	dev2 := shapetest.Device{T: t, Addr: "127.0.0.1:49", Key: []byte(v2Bytes)}
	file2 := s.hostSecret("c-"+syntax, "tacacs_v2", []byte(v2Bytes), v.owner, v.mode)
	out, err := s.apply2(syntax, []l84.Secret{{Name: "key", File: file}, {Name: "tacacs_v2", File: file2}})
	if err != nil {
		cell.Verdict = l84.Fail
		cell.Rows = []l84.Row{{Case: "state", Observation: "docker compose up -d with the second secret failed: " + l84Tail(out, 3)}}
		return cell
	}
	id1, at1 := id()
	same := id1 == id0 && at1 == at0
	start := time.Now()
	tok := s.mint()
	inForce := false
	for time.Since(start) < 120*time.Second {
		s.guard()
		if st, err := dev2.TryLogin("alice", tok); err == nil && st == wire.AuthenStatusPass {
			inForce = true
			break
		}
		time.Sleep(2 * time.Second)
	}
	yes := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	cell.Rows = []l84.Row{
		{Case: "port49d before", Observation: "container " + id0[:12] + ", last start line at " + at0},
		{Case: "port49d after `docker compose up -d` with the second secrets: entry", Observation: "container " + id1[:12] + ", last start line at " + at1 + "; same container and start: " + yes(same)},
		{Case: "a login keyed with version 2 (policy names tacacs_v2)", Observation: fmt.Sprintf("in force within 120 s: %s (%.0f s)", yes(inForce), time.Since(start).Seconds())},
	}
	cell.Verdict = l84.Fail
	if inForce && same {
		cell.Verdict = l84.Pass
	}
	return cell
}

// apply2 is apply for a stack that is already up: `docker compose up -d` as an operator runs it,
// with no --force-recreate, so port49d is recreated only if compose decides its definition changed.
func (s *l84Stack) apply2(syntax string, secrets []l84.Secret) (string, error) {
	ov, err := l84.Override(syntax, secrets)
	if err != nil {
		s.t.Fatal(err)
	}
	if err := os.WriteFile(s.override, []byte(ov), 0o644); err != nil {
		s.t.Fatal(err)
	}
	return s.try("up", "-d", "--no-build")
}
