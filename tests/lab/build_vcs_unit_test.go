package lab

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/daemon/metrics"
)

const vcsSample = "bin/port49d: go1.26.0\n\tpath\tgithub.com/rhwendt/port49/cmd/port49d\n" +
	"\tbuild\tvcs=git\n\tbuild\tvcs.revision=0123456789abcdef0123456789abcdef01234567\n\tbuild\tvcs.modified=true\n"

func TestBuildVCSReadsRevisionAndModified(t *testing.T) {
	v, err := parseBuildVCS(vcsSample)
	if err != nil || v.Revision != "0123456789abcdef0123456789abcdef01234567" || !v.Modified {
		t.Fatalf("%+v %v", v, err)
	}
	if _, err := parseBuildVCS("bin/port49d: go1.26.0\n\tbuild\tvcs.modified=false\n"); err == nil {
		t.Fatal("no vcs.revision: a binary built with -buildvcs=false is refused")
	}
}

// Review I2: an arm's binary is checked, not taken on trust.
func TestL80ArmBinaryCheck(t *testing.T) {
	head := "1111111111111111111111111111111111111111"
	pre := "2222222222222222222222222222222222222222"
	hasFix := func(rev string) (bool, error) {
		switch rev {
		case head:
			return true, nil
		case pre:
			return false, nil
		}
		return false, errors.New("unknown revision")
	}
	for name, c := range map[string]struct {
		arm     string
		v       buildVCS
		invalid bool
	}{
		"fixed at HEAD, clean":        {"fixed", buildVCS{head, false}, false},
		"fixed at HEAD, modified":     {"fixed", buildVCS{head, true}, true},
		"fixed from an older build":   {"fixed", buildVCS{pre, false}, true},
		"baseline before the fix":     {"baseline", buildVCS{pre, false}, false},
		"baseline that holds the fix": {"baseline", buildVCS{head, false}, true},
		"baseline, unknown revision":  {"baseline", buildVCS{"3333333333333333333333333333333333333333", false}, true},
		"baseline, modified":          {"baseline", buildVCS{pre, true}, true},
	} {
		err := l80ArmCheck(c.arm, c.v, head, hasFix)
		if (err != nil) != c.invalid {
			t.Errorf("%s: %v, want invalid %v", name, err, c.invalid)
		}
		if err != nil && !strings.HasPrefix(err.Error(), "INVALID: ") {
			t.Errorf("%s: %v does not say INVALID", name, err)
		}
	}
}

// The qual run's offer comes from the binary's own revision: anything but
// the harness tree's clean HEAD is INVALID, since the table could differ.
func TestQualBinaryMatchesTheTree(t *testing.T) {
	head := "1111111111111111111111111111111111111111"
	if err := qualBinaryCheck(buildVCS{head, false}, head); err != nil {
		t.Fatal(err)
	}
	for _, v := range []buildVCS{{head, true}, {"2222222222222222222222222222222222222222", false}} {
		if err := qualBinaryCheck(v, head); err == nil || !strings.HasPrefix(err.Error(), "INVALID: ") {
			t.Errorf("%+v: %v", v, err)
		}
	}
}

// Review I1: tls_token_login's capture opens only once no connection is
// open, or the run is INVALID; the grade is never loosened instead.
func TestQualWaitNoConnections(t *testing.T) {
	seq := func(vals ...float64) func() (float64, bool) {
		i := 0
		return func() (float64, bool) {
			v := vals[min(i, len(vals)-1)]
			i++
			return v, true
		}
	}
	nap := func(time.Duration) {}
	if err := qualWaitNoConnections(seq(2, 1, 0), 10, nap); err != nil {
		t.Fatalf("drains to 0: %v", err)
	}
	if err := qualWaitNoConnections(seq(1), 10, nap); err == nil || !strings.HasPrefix(err.Error(), "INVALID: ") {
		t.Fatalf("never drains: %v", err)
	}
	if err := qualWaitNoConnections(func() (float64, bool) { return 0, false }, 10, nap); err != nil {
		t.Fatalf("a daemon that has had no connection exports no series: %v", err)
	}
}

// The selector is the daemon's own spelling, so an absent series means no
// connection, never a typo.
func TestQualConnectionsGaugeSpelling(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	m.Connections.WithLabelValues("open").Add(3)
	rec := httptest.NewRecorder()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if v, ok := l73MetricValue(rec.Body.String(), qualConnectionsOpen); !ok || v != 3 {
		t.Fatalf("%s reads %v %v from the daemon's metrics", qualConnectionsOpen, v, ok)
	}
}

// run.json's field names are genprofile's: a misspelling would read as
// false there and leave the facts absent forever (review O1).
func TestQualRunNamesTheCleanCaptureAndTheOffer(t *testing.T) {
	b, err := json.Marshal(qualRun{TLSServerSingleConnectOffered: true, TLSCaptureStartedClean: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"tls_server_single_connect_offered":true`, `"tls_capture_started_clean":true`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("run.json lacks %s: %s", key, b)
		}
	}
}

// gitRepo is a throwaway repository: run runs git in it and returns HEAD.
func gitRepo(t *testing.T) (dir string, run func(args ...string) string) {
	t.Helper()
	dir = t.TempDir()
	run = func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.email=t@example.invalid", "-c", "user.name=t",
			"-c", "commit.gpgsign=false"}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q", "-b", "main")
	return dir, run
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Review N5: l80HasFix against a real history. A revision holds the fix if
// the fix commit is its ancestor, or, after a rebase made that commit
// unreachable, if it carries the fix's table file.
func TestL80HasFixAgainstAHistory(t *testing.T) {
	dir, run := gitRepo(t)
	writeFile(t, filepath.Join(dir, "README"), "base\n")
	run("add", "-A")
	run("commit", "-q", "-m", "base")
	base := run("rev-parse", "HEAD")
	writeFile(t, filepath.Join(dir, "internal/platform/tlsoffer.go"), "package platform\n")
	run("add", "-A")
	run("commit", "-q", "-m", "fix")
	fix := run("rev-parse", "HEAD")
	writeFile(t, filepath.Join(dir, "after"), "x\n")
	run("add", "-A")
	run("commit", "-q", "-m", "after")
	after := run("rev-parse", "HEAD")
	// A rebased fix: same file, a branch that does not descend from fix.
	run("checkout", "-q", "-b", "rebased", base)
	writeFile(t, filepath.Join(dir, "internal/platform/tlsoffer.go"), "package platform\n")
	run("add", "-A")
	run("commit", "-q", "-m", "fix, rebased")
	rebased := run("rev-parse", "HEAD")
	for rev, want := range map[string]bool{base: false, fix: true, after: true, rebased: true} {
		got, err := l80HasFixAt(dir, fix, rev)
		if err != nil || got != want {
			t.Errorf("%s: %v %v, want %v", rev[:8], got, err, want)
		}
	}
	if _, err := l80HasFixAt(dir, fix, "0123456789abcdef0123456789abcdef01234567"); err == nil {
		t.Error("an unknown revision is an error")
	}
}

// Review N4: the dirty check sees untracked files under the paths too.
func TestTreeDirtySeesUntrackedFiles(t *testing.T) {
	dir, run := gitRepo(t)
	writeFile(t, filepath.Join(dir, "internal/a.go"), "package a\n")
	run("add", "-A")
	run("commit", "-q", "-m", "base")
	if d, err := treeDirty(dir, "internal", "tests/lab"); err != nil || d != "" {
		t.Fatalf("clean tree: %q %v", d, err)
	}
	writeFile(t, filepath.Join(dir, "tests/lab/evidence/x/new.txt"), "untracked\n")
	if d, err := treeDirty(dir, "internal", "tests/lab"); err != nil || d == "" {
		t.Fatalf("an untracked evidence file: %q %v", d, err)
	}
	writeFile(t, filepath.Join(dir, "elsewhere.txt"), "untracked\n")
	run("add", "tests")
	run("commit", "-q", "-m", "evidence")
	if d, err := treeDirty(dir, "internal", "tests/lab"); err != nil || d != "" {
		t.Fatalf("a change outside the paths: %q %v", d, err)
	}
	writeFile(t, filepath.Join(dir, "internal/a.go"), "package a // edited\n")
	if d, err := treeDirty(dir, "internal", "tests/lab"); err != nil || d == "" {
		t.Fatalf("a modified tracked file: %q %v", d, err)
	}
}

// Review N2: each INVALID about the build names the fix, since committing
// evidence moves HEAD past the build.
func TestBuildInvalidsNameTheFix(t *testing.T) {
	head := "1111111111111111111111111111111111111111"
	none := func(string) (bool, error) { return false, nil }
	for _, err := range []error{
		l80ArmCheck("fixed", buildVCS{"2222222222222222222222222222222222222222", false}, head, none),
		l80ArmCheck("fixed", buildVCS{head, true}, head, none),
		qualBinaryCheck(buildVCS{"2222222222222222222222222222222222222222", false}, head),
		qualBinaryCheck(buildVCS{head, true}, head),
	} {
		if err == nil || !strings.Contains(err.Error(), "rebuild after committing") {
			t.Errorf("%v", err)
		}
	}
}

// Review N4: the gauge is read again once the capture has started, so a
// connection opened between the last 0 and the capture's first SYN makes
// the run INVALID rather than an unclean "clean" capture.
func TestQualStillCleanAfterTheCaptureStarts(t *testing.T) {
	if err := qualStillClean(func() (float64, bool) { return 0, true }); err != nil {
		t.Fatal(err)
	}
	if err := qualStillClean(func() (float64, bool) { return 0, false }); err != nil {
		t.Fatalf("no series yet is no connection: %v", err)
	}
	if err := qualStillClean(func() (float64, bool) { return 1, true }); err == nil || !strings.HasPrefix(err.Error(), "INVALID: ") {
		t.Fatalf("a connection open at the capture's start: %v", err)
	}
}

// The wait outlasts the lab file's idle_timeout, which closes a connection
// the readiness login left held (review N1, R3).
func TestQualCleanWaitOutlastsTheLabIdleTimeout(t *testing.T) {
	raw, err := os.ReadFile("port49d-lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Limits struct {
			IdleTimeout time.Duration `yaml:"idle_timeout"`
		} `yaml:"limits"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil || cfg.Limits.IdleTimeout == 0 {
		t.Fatalf("idle_timeout: %v %v", cfg.Limits.IdleTimeout, err)
	}
	if time.Duration(qualCleanPolls)*time.Second < cfg.Limits.IdleTimeout+30*time.Second {
		t.Fatalf("the wait (%ds) does not outlast idle_timeout %v", qualCleanPolls, cfg.Limits.IdleTimeout)
	}
}

// Fix round 4: go build inside a git worktree nested under the main checkout
// stamps the main checkout's HEAD (Go's VCS lookup takes only a .git
// directory, not a worktree's .git file). buildPort49dAt builds from a
// private clone instead, so the stamp is the revision asked for. The
// fixture is a throwaway module with a worktree nested in it at an older
// commit than the outer checkout.
func TestBuildPort49dStampsTheRevisionFromANestedWorktree(t *testing.T) {
	outer, run := gitRepo(t)
	writeFile(t, filepath.Join(outer, "go.mod"), "module example.invalid/stamp\n\ngo 1.21\n")
	writeFile(t, filepath.Join(outer, "cmd/port49d/main.go"), "package main\n\nfunc main() {}\n")
	writeFile(t, filepath.Join(outer, ".gitignore"), "/.worktrees/\n")
	run("add", "-A")
	run("commit", "-q", "-m", "a")
	a := run("rev-parse", "HEAD")
	writeFile(t, filepath.Join(outer, "cmd/port49d/main.go"), "package main\n\nfunc main() { println() }\n")
	run("commit", "-q", "-am", "b")
	nested := filepath.Join(outer, ".worktrees", "w")
	run("worktree", "add", "-q", "--detach", nested, a)
	dst := filepath.Join(t.TempDir(), "port49d")
	v, err := buildPort49dAt(nested, "HEAD", t.TempDir(), dst)
	if err != nil {
		t.Fatal(err)
	}
	if v.Revision != a || v.Modified {
		t.Fatalf("stamped %+v, want %s clean", v, a)
	}
	got, err := binaryVCS(dst)
	if err != nil || got != v {
		t.Fatalf("the installed binary says %+v %v, want %+v", got, err, v)
	}
	if _, err := buildPort49dAt(nested, "0123456789abcdef0123456789abcdef01234567", t.TempDir(), dst); err == nil {
		t.Fatal("an unknown revision built")
	}
	// Every temporary tree is removed, on success and on failure.
	tmp := t.TempDir()
	buildPort49dAt(nested, "HEAD", tmp, dst)
	buildPort49dAt(nested, "0123456789abcdef0123456789abcdef01234567", tmp, dst)
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Fatalf("left behind %d entries in the temp root", len(left))
	}
}
