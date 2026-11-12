package lab

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// buildVCS is what `go version -m` says a binary was built from.
type buildVCS struct {
	Revision string `json:"vcs_revision"`
	Modified bool   `json:"vcs_modified"`
}

// recorded is v as written to run.json and the L80 summaries: the first
// twelve hex characters of the revision, under l73SummaryLeaks' 32, so the
// writer's leak check stays as strict as it is. The checks against HEAD run on
// the full revision, in memory, before anything is written.
func (v buildVCS) recorded() buildVCS {
	if len(v.Revision) > 12 {
		v.Revision = v.Revision[:12]
	}
	return v
}

// parseBuildVCS reads `go version -m` output. A binary with no
// vcs.revision (built with -buildvcs=false, or outside a checkout) is an
// error: what it was built from cannot be shown.
func parseBuildVCS(out string) (buildVCS, error) {
	var v buildVCS
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) != 2 || f[0] != "build" {
			continue
		}
		switch k, val, _ := strings.Cut(f[1], "="); k {
		case "vcs.revision":
			v.Revision = val
		case "vcs.modified":
			v.Modified = val == "true"
		}
	}
	if v.Revision == "" {
		return v, errors.New("the binary carries no vcs.revision")
	}
	return v, nil
}

// binaryVCS is `go version -m path`, read.
func binaryVCS(path string) (buildVCS, error) {
	out, err := exec.Command("go", "version", "-m", path).Output()
	if err != nil {
		return buildVCS{}, fmt.Errorf("go version -m %s: %w", path, err)
	}
	return parseBuildVCS(string(out))
}

// l80FixCommit is the commit that makes port49 offer single-connect to
// NX-OS over TLS (decision 50 ruling 20). A rebase changes it; the baseline
// check then fails INVALID on the unknown revision until it is updated.
const l80FixCommit = "bf71174d"

// l80ArmCheck is review I2's check of which build an L80 arm ran. The fixed
// arm needs a clean build of the harness tree's HEAD; the baseline arm a
// clean build that does not hold the fix. hasFix answers for a revision,
// and its error (an unknown revision) is INVALID too.
func l80ArmCheck(arm string, v buildVCS, head string, hasFix func(rev string) (bool, error)) error {
	return armCheckFor(arm, v, head, l80FixCommit, hasFix)
}

// armCheckFor is l80ArmCheck for the fix named fix (L80's, or L94's).
func armCheckFor(arm string, v buildVCS, head, fix string, hasFix func(rev string) (bool, error)) error {
	if v.Modified {
		return fmt.Errorf("INVALID: bin/port49d was built from a modified tree (%s) for arm %s: commit or remove what "+
			"git status shows (evidence included), and rebuild after committing (make build)", v.Revision, arm)
	}
	switch arm {
	case "fixed":
		if v.Revision != head {
			return fmt.Errorf("INVALID: arm fixed needs bin/port49d built from HEAD %s, it was built from %s: committing "+
				"evidence moves HEAD, so rebuild after committing (make build)", head, v.Revision)
		}
	case "baseline":
		has, err := hasFix(v.Revision)
		if err != nil {
			return fmt.Errorf("INVALID: cannot tell whether %s holds the fix: %v", v.Revision, err)
		}
		if has {
			return fmt.Errorf("INVALID: arm baseline ran bin/port49d built from %s, which holds the fix (%s)", v.Revision, fix)
		}
	default:
		return fmt.Errorf("INVALID: arm %q", arm)
	}
	return nil
}

// l80HasFix reports whether rev, in the checkout at dir, holds the fix.
func l80HasFix(dir, rev string) (bool, error) { return l80HasFixAt(dir, l80FixCommit, rev) }

// l80HasFixAt reports whether rev holds fix: fix is its ancestor, or, after
// a rebase made fix unreachable from it, rev carries the fix's table file.
// Either is enough; an unknown revision or commit is an error.
func l80HasFixAt(dir, fix, rev string) (bool, error) {
	return hasFixAt(dir, fix, "internal/platform/tlsoffer.go", rev)
}

// hasFixAt is l80HasFixAt for a fix whose sign, after a rebase, is file.
func hasFixAt(dir, fix, file, rev string) (bool, error) {
	err := exec.Command("git", "-C", dir, "merge-base", "--is-ancestor", fix, rev).Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &ee) && ee.ExitCode() == 1:
	default:
		return false, fmt.Errorf("git merge-base --is-ancestor %s %s: %v", fix, rev, err)
	}
	return exec.Command("git", "-C", dir, "cat-file", "-e", rev+":"+file).Run() == nil, nil
}

// treeDirty is `git status --porcelain` over paths: tracked changes and
// untracked files alike, so evidence a run wrote and nobody committed
// counts (review N4). "" is clean.
func treeDirty(dir string, paths ...string) (string, error) {
	out, err := exec.Command("git", append([]string{"-C", dir, "status", "--porcelain", "--"}, paths...)...).Output()
	if err != nil {
		return "", fmt.Errorf("git status: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// codePaths are the code a lab run's binary and harness are built from (go.mod and go.sum included).
// qualTreeDirty excludes tests/lab's results and evidence from it and adds the run's own outputs
// (qualOwnOutputs).
var codePaths = []string{"internal", "cmd", "platforms", "tests/lab", "tests/qual", "go.mod", "go.sum"}

// qualOwnOutputs are the results and evidence the qualify and L80 runs write
// themselves, for each prefix a run owns. Under :(glob) a * does not cross a
// /, so the evidence directories take their own pattern.
var qualOwnOutputs = func() []string {
	var p []string
	for _, prefix := range []string{"L80-", "QUAL-", "L78-"} {
		p = append(p,
			":(glob)tests/lab/results/"+prefix+"*",
			":(glob)tests/lab/evidence/"+prefix+"*",
			":(glob)tests/lab/evidence/"+prefix+"*/**")
	}
	return p
}()

// qualTreeDirty is the dirty check of the qualify and L80 runs: the code
// their binary and harness are built from, and the run's own outputs. The
// check is the binary's and the harness's provenance (review I2, N4); nothing
// reads or embeds other entries' notes or evidence, and requiring L80 to run
// first would hold only in a full run. It takes two calls, because a git
// exclude pathspec also removes a positive glob under it.
func qualTreeDirty(dir string) (string, error) {
	code := append(slices.Clone(codePaths), ":(exclude)tests/lab/results", ":(exclude)tests/lab/evidence")
	a, err := treeDirty(dir, code...)
	if err != nil {
		return "", err
	}
	b, err := treeDirty(dir, qualOwnOutputs...)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(a + "\n" + b), nil
}

// qualBinaryCheck holds the qual run's bin/port49d to the harness tree:
// run.json's tls_server_single_connect_offered is read from this tree's
// table, so the binary must be a clean build of this tree's HEAD, or the two
// could differ (review I2).
func qualBinaryCheck(v buildVCS, head string) error {
	if v.Modified || v.Revision != head {
		return fmt.Errorf("INVALID: bin/port49d was built from %s (modified %v), not from this tree's clean HEAD %s, so "+
			"the offer run.json records would not be the binary's: committing evidence moves HEAD, so rebuild after "+
			"committing (make build)", v.Revision, v.Modified, head)
	}
	return nil
}

// qualConnectionsOpen is the gauge qualWaitNoConnections reads; its spelling
// is pinned against the daemon's own metrics (TestQualConnectionsGaugeSpelling).
const qualConnectionsOpen = `port49_connections{state="open"}`

// qualWaitNoConnections polls qualConnectionsOpen (read) once a second, up
// to limit polls, until it is 0: a clean start for a capture whose
// connections are graded, so no connection held over from an earlier login
// overlaps the cell's own (review I1). The lab has one device, so the
// daemon-wide gauge is that device's. The series is created at a daemon's
// first connection, so its absence is a daemon that has had none: 0. A gauge
// that never drains is INVALID; the grade is never loosened instead.
func qualWaitNoConnections(read func() (float64, bool), limit int, sleep func(time.Duration)) error {
	last := -1.0
	for range limit {
		v, ok := read()
		if !ok || v == 0 {
			return nil
		}
		last = v
		sleep(time.Second)
	}
	return fmt.Errorf("INVALID: %v connections still open after %ds; the capture would not start clean", last, limit)
}

// qualCleanPolls bounds qualWaitNoConnections before tls_token_login: one
// poll a second for six minutes, past the lab file's idle_timeout (5m), which
// closes a connection the readiness login left held (an offered NX-OS one)
// with close_notify (review N1, R3).
const qualCleanPolls = 6 * 60

// qualStillClean reads the gauge once the capture has started: a connection
// opened between the last 0 and the capture's first SYN would be open and
// uncaptured, so it is INVALID (review N4). No series is no connection.
func qualStillClean(read func() (float64, bool)) error {
	if v, ok := read(); ok && v != 0 {
		return fmt.Errorf("INVALID: %v connections open when tls_token_login's capture started; it did not start clean", v)
	}
	return nil
}

// buildPort49dAt builds cmd/port49d of repo at rev and installs it at dst,
// and returns what the binary says it was built from (fix round 4). It never
// builds in place: Go's VCS stamp looks for a .git directory, not a
// worktree's .git file, so a build inside a worktree nested under the main
// checkout is stamped with the main checkout's HEAD, and one outside with
// nothing. It builds in a private clone (git clone --shared, which has its
// own .git directory) under tmpRoot, checked out at rev, and removes it on
// every path. The stamp must be rev, unmodified, or nothing is installed.
func buildPort49dAt(repo, rev, tmpRoot, dst string, tags ...string) (buildVCS, error) {
	out, err := exec.Command("git", "-C", repo, "rev-parse", "--verify", rev+"^{commit}").Output()
	if err != nil {
		return buildVCS{}, fmt.Errorf("INVALID: revision %s is not in %s: %w", rev, repo, err)
	}
	full := strings.TrimSpace(string(out))
	dir, err := os.MkdirTemp(tmpRoot, "port49d-build-")
	if err != nil {
		return buildVCS{}, err
	}
	defer os.RemoveAll(dir)
	src := filepath.Join(dir, "src")
	for _, args := range [][]string{
		{"clone", "-q", "--shared", "--no-checkout", repo, src},
		{"-C", src, "checkout", "-q", "--detach", full},
	} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			return buildVCS{}, fmt.Errorf("INVALID: git %s: %v %s", args[0], err, out)
		}
	}
	built := filepath.Join(dir, "port49d")
	args := []string{"build"}
	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}
	cmd := exec.Command("go", append(args, "-o", built, "./cmd/port49d")...)
	cmd.Dir, cmd.Env = src, append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		return buildVCS{}, fmt.Errorf("INVALID: go build at %s: %v %s", full, err, out)
	}
	v, err := binaryVCS(built)
	if err != nil {
		return v, fmt.Errorf("INVALID: %w", err)
	}
	if v.Revision != full || v.Modified {
		return v, fmt.Errorf("INVALID: the build at %s is stamped %s (modified %v)", full, v.Revision, v.Modified)
	}
	raw, err := os.ReadFile(built)
	if err != nil {
		return v, err
	}
	// Written beside dst and renamed over it, so a running port49d's text
	// file is never truncated in place.
	tmp := dst + ".new"
	if err := os.WriteFile(tmp, raw, 0o755); err != nil {
		return v, err
	}
	return v, os.Rename(tmp, dst)
}

// l80BaselineCommit is the commit before Task 7's code: the spec alone
// (docs: decision 50 ruling 20). L80's baseline arm builds from it.
const l80BaselineCommit = "9f97a84f"

// qualPort49dBuild is what TestQualify built bin/port49d from.
var qualPort49dBuild buildVCS

// labSetcap gives bin the capability to bind port 49 unprivileged, as
// initGlobal does for the binary it finds; a binary the harness built
// replaces that one.
func labSetcap(bin string) error {
	if out, err := exec.Command("sudo", "-n", "setcap", "cap_net_bind_service=+ep", bin).CombinedOutput(); err != nil {
		return fmt.Errorf("setcap failed (%v): %s", err, out)
	}
	return nil
}
