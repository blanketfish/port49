package l89

import (
	"context"
	"os/exec"
	"syscall"
	"time"

	"github.com/blanketfish/port49/tests/shapes/l82"
)

// The time L89 plans for under `make lab-l89`'s 55m -timeout (TestTheCellCapsFitTheTestTimeout): the
// bring-up before the first cell (the kind stack, the object store and Velero), each cell's cap, and the
// reserve kept at the end for the diagnosis, the results and the cluster's deletion, the guard's 45s
// inside it. A cell ends at its cap or at the test's deadline less the reserve, whichever comes first.
const (
	BringUp      = 9 * time.Minute
	ReserveAtEnd = 4 * time.Minute
)

// CellCap is a cell's cap, and the time it needs left to be worth starting: a cell started with less
// would be stopped by its budget part way, and is NOT RUN instead, saying so.
func CellCap(id string) (cap, need time.Duration) {
	switch id {
	case "a":
		return 14 * time.Minute, 8 * time.Minute
	case "b":
		return 3 * time.Minute, 1 * time.Minute
	case "c", "d":
		return 12 * time.Minute, 8 * time.Minute
	}
	return 0, 0
}

// Budget is the test's deadline (zero when go test has no -timeout) and the reserve kept before it.
type Budget struct {
	TestEnd time.Time
	Reserve time.Duration
}

// Cell is when a cell started now ends: at its cap, or at the test's deadline less the reserve if that
// is sooner. ok is false when less than need is left.
func (b Budget) Cell(now time.Time, cap, need time.Duration) (end time.Time, ok bool) {
	end = now.Add(cap)
	if !b.TestEnd.IsZero() {
		if last := b.TestEnd.Add(-b.Reserve); last.Before(end) {
			end = last
		}
	}
	return end, end.Sub(now) >= need
}

// Bound is one step's bound: its own, or what is left of the cell if that is less, and then capped is
// true (a step stopped by the cell's end is the harness's budget, not the step's measurement).
func Bound(now, end time.Time, own time.Duration) (d time.Duration, capped bool) {
	left := end.Sub(now)
	if left < 0 {
		left = 0
	}
	if left < own {
		return left, true
	}
	return own, false
}

// RunBounded runs script with bash -ec in dir (env nil: the test's own), and stops it at within: the
// whole process group is killed, so a velero or kubectl it started cannot hold the output open, and the
// pipes are closed 5s after. timedOut says the bound stopped it.
func RunBounded(dir string, env []string, script string, within time.Duration) (out string, timedOut bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-ec", script)
	cmd.Dir = dir
	if env != nil {
		cmd.Env = env
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	b, err := cmd.CombinedOutput()
	return string(b), ctx.Err() == context.DeadlineExceeded, err
}

// Stopped is the cells as the guard's kill writes them: the running cell NOT RUN, with a row saying why,
// and every other cell as it is. The cells given are not changed.
func Stopped(cells []l82.Cell, running, why string) []l82.Cell {
	out := make([]l82.Cell, len(cells))
	for i, c := range cells {
		c.Rows = append([]l82.Row(nil), c.Rows...)
		if c.ID == running {
			c.Verdict = ""
			c.Rows = append(c.Rows, l82.Row{Case: "the cell was stopped before it ended: not a measurement", Observation: why})
		}
		out[i] = c
	}
	return out
}
