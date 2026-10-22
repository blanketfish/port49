package lab

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// buildVCS is what `go version -m` says a binary was built from.
type buildVCS struct {
	Revision string `json:"vcs_revision"`
	Modified bool   `json:"vcs_modified"`
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
	if v.Modified {
		return fmt.Errorf("INVALID: bin/port49d was built from a modified tree (%s); build it clean for arm %s", v.Revision, arm)
	}
	switch arm {
	case "fixed":
		if v.Revision != head {
			return fmt.Errorf("INVALID: arm fixed needs bin/port49d built from HEAD %s, it was built from %s: run make build", head, v.Revision)
		}
	case "baseline":
		fix, err := hasFix(v.Revision)
		if err != nil {
			return fmt.Errorf("INVALID: cannot tell whether %s holds the fix: %v", v.Revision, err)
		}
		if fix {
			return fmt.Errorf("INVALID: arm baseline ran bin/port49d built from %s, which holds the fix (%s)", v.Revision, l80FixCommit)
		}
	default:
		return fmt.Errorf("INVALID: arm %q", arm)
	}
	return nil
}

// l80HasFix reports whether rev, in the checkout at dir, holds the fix:
// l80FixCommit is its ancestor, or it has the fix's table file. Either is
// enough; an unknown revision or commit is an error.
func l80HasFix(dir, rev string) (bool, error) {
	cmd := exec.Command("git", "-C", dir, "merge-base", "--is-ancestor", l80FixCommit, rev)
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &ee) && ee.ExitCode() == 1:
	default:
		return false, fmt.Errorf("git merge-base --is-ancestor %s %s: %v", l80FixCommit, rev, err)
	}
	if exec.Command("git", "-C", dir, "cat-file", "-e", rev+":internal/platform/tlsoffer.go").Run() == nil {
		return true, nil
	}
	return false, nil
}

// qualBinaryCheck holds the qual run's bin/port49d to the harness tree:
// run.json's tls_server_single_connect_offered is read from this tree's
// table, so the binary must be a clean build of this tree's HEAD, or the two
// could differ (review I2).
func qualBinaryCheck(v buildVCS, head string) error {
	if v.Modified || v.Revision != head {
		return fmt.Errorf("INVALID: bin/port49d was built from %s (modified %v), not from this tree's HEAD %s: "+
			"the offer run.json records would not be the binary's; run make build", v.Revision, v.Modified, head)
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
