package l89

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/blanketfish/port49/tests/shapes/l82"
)

// The time L89 plans for under `make lab-l89`'s -timeout, TestTimeout (TestTheCellCapsFitTheTestTimeout,
// which also reads the Makefile and lab-kind.yml's l89 job): the bring-up before the first cell (the kind
// stack, the object store and Velero), each cell's cap, and the reserve kept at the end for the diagnosis,
// the results and the cluster's deletion, the guard's 45s inside it. A cell ends at its cap or at the
// test's deadline less the reserve, whichever comes first.
const (
	TestTimeout  = 85 * time.Minute
	BringUp      = 12 * time.Minute
	ReserveAtEnd = 5 * time.Minute
)

// CellCap is a cell's cap, and the time it needs left to be worth starting: a cell started with less
// would be stopped by its budget part way, and is NOT RUN instead, saying so.
func CellCap(id string) (cap, need time.Duration) {
	switch id {
	case "a":
		return 18 * time.Minute, 10 * time.Minute
	case "b":
		return 4 * time.Minute, 1 * time.Minute
	case "c", "d":
		return 20 * time.Minute, 12 * time.Minute
	}
	return 0, 0
}

// StepBounds is each README step's own bound in cells (c) and (d), by its name in Steps: a backstop for
// a hang, at least the README's own --timeouts in the step plus BoundSlack
// (TestEachStepsBoundCoversItsREADMETimeouts), so a step the README's text lets finish is never cut.
// A step past it is NOT RUN, unless HangCause sees the README's cause; a README timeout fails the
// command itself, which is a measured FAIL.
var StepBounds = map[string]time.Duration{
	"restorezero": 8 * time.Minute, // velero --wait has no timeout of its own
	"restore":     8 * time.Minute,
	"etcdwait":    6 * time.Minute,
	"volumes":     time.Minute,
	"scalezero":   4 * time.Minute,
	"recover":     12 * time.Minute, // a rollout and a wait of 5m each
	"deletejob":   6 * time.Minute,  // its own loop of 120 tries, 2s apart
	"revoke":      6 * time.Minute,
	"scaleup":     22 * time.Minute, // two rollouts of 10m each
}

// BoundSlack is what a step's bound keeps above its README timeouts: the commands around them.
const BoundSlack = time.Minute

var timeoutFlag = regexp.MustCompile(`--timeout[= ](\S+)`)

// READMETimeouts is the sum of the --timeout values in a step's commands.
func READMETimeouts(cmd string) (time.Duration, error) {
	var sum time.Duration
	for _, m := range timeoutFlag.FindAllStringSubmatch(cmd, -1) {
		d, err := time.ParseDuration(m[1])
		if err != nil {
			return 0, fmt.Errorf("l89: the timeout %q: %w", m[1], err)
		}
		sum += d
	}
	return sum, nil
}

// PVR is one pod volume restore as HangProbe prints it: its phase ("New" while unset), pod and volume.
type PVR struct{ Phase, Pod, Volume string }

// HangProbe is the script the harness runs, bounded, when a restore's --wait did not end: the restore's
// phase, its pod volume restores, and the pods in ns. It names no Secret and prints no data.
func HangProbe(ns, restore string) string {
	return "kubectl -n velero get restore " + restore + ` -o jsonpath='phase {.status.phase}{"\n"}'` + "\n" +
		"kubectl -n velero get podvolumerestores -l velero.io/restore-name=" + restore +
		` -o jsonpath='{range .items[*]}pvr {.status.phase} {.spec.pod.name} {.spec.volume}{"\n"}{end}'` + "\n" +
		"kubectl -n " + ns + ` get pods -o jsonpath='{range .items[*]}pod {.metadata.name}{"\n"}{end}'` + "\n"
}

// ParseHang reads HangProbe's output.
func ParseHang(out string) (pvrs []PVR, pods map[string]bool, phase string) {
	pods = map[string]bool{}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		switch {
		case len(f) >= 1 && f[0] == "phase":
			if len(f) == 2 {
				phase = f[1]
			}
		case len(f) == 4 && f[0] == "pvr":
			pvrs = append(pvrs, PVR{f[1], f[2], f[3]})
		case len(f) == 3 && f[0] == "pvr": // no phase yet
			pvrs = append(pvrs, PVR{"New", f[1], f[2]})
		case len(f) == 2 && f[0] == "pod":
			pods[f[1]] = true
		}
	}
	return pvrs, pods, phase
}

var pvrEnded = map[string]bool{"Completed": true, "Failed": true, "Canceled": true}

// HangCause says whether a restore that did not end is the README's measured outcome: a pod volume
// restore not yet ended whose pod does not exist, which no wait can end (the suspected mechanism of c).
// rows are each unended pod volume restore and its pod, or that there was none.
func HangCause(pvrs []PVR, pods map[string]bool) (measured bool, rows []l82.Row) {
	for _, p := range pvrs {
		if pvrEnded[p.Phase] {
			continue
		}
		where := "present"
		if !pods[p.Pod] {
			where, measured = "absent", true
		}
		rows = append(rows, l82.Row{Case: "the pod volume restore of " + p.Pod + "/" + p.Volume + " when the restore's wait was stopped",
			Observation: p.Phase + "; pod " + p.Pod + " " + where})
	}
	if len(rows) == 0 {
		rows = append(rows, l82.Row{Case: "pod volume restores not ended when the restore's wait was stopped", Observation: "none"})
	}
	return measured, rows
}

// HangVerdict is a cell's verdict on a restore whose wait did not end: where the README says the restore
// hangs (cell c, its warning against restoring at 0 replicas), the hang HangCause measured is the PASS;
// where the README's order should finish (cell d), it is a FAIL. A hang whose cause was not seen is "":
// NOT RUN.
func HangVerdict(expectHang, measured bool) string {
	switch {
	case !measured:
		return ""
	case expectHang:
		return l82.Pass
	}
	return l82.Fail
}

// ZeroRestoreEnded is (c)'s verdict on a restore at 0 replicas that ended, from both StatefulSets'
// replicas ("0 0" when the lab's modifier applied) and HangProbe's read of the restore. Where the modifier
// did not apply nothing was measured: NOT RUN, with a row saying so. Otherwise the README's warning is
// wrong, a FAIL, with the restore's phase and each pod volume restore's (PartiallyFailed, Failed).
func ZeroRestoreEnded(replicas, phase string, pvrs []PVR) (string, []l82.Row) {
	if replicas != "0 0" {
		return "", []l82.Row{{Case: "the two StatefulSets' replicas after the restore at 0 replicas",
			Observation: replicas + ": the lab's resource modifier did not apply, not a measurement"}}
	}
	if phase == "" {
		phase = "unset"
	}
	rows := []l82.Row{{Case: "the two StatefulSets' replicas after the restore at 0 replicas", Observation: replicas},
		{Case: "the restore's phase when it ended", Observation: phase}}
	for _, p := range pvrs {
		rows = append(rows, l82.Row{Case: "the pod volume restore of " + p.Pod + "/" + p.Volume + " when the restore ended", Observation: p.Phase})
	}
	return l82.Fail, append(rows, l82.Row{Case: "the restore at 0 replicas ended", Observation: "the README's warning that it hangs is wrong"})
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

// NotMeasuredRowed says rows already hold one saying why the cell was not measured (a row ending "not a
// measurement": a setup failure, a step stopped by its bound or the cell's end, a wait of the harness's
// own), so the harness adds no generic "setup failed" row over it.
func NotMeasuredRowed(rows []l82.Row) bool {
	for _, row := range rows {
		if strings.HasSuffix(row.Case, "not a measurement") || strings.HasSuffix(row.Observation, "not a measurement") {
			return true
		}
	}
	return false
}
