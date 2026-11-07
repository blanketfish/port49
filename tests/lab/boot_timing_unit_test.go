//go:build lab

package lab

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

const procMeminfo = `MemTotal:       32768000 kB
MemFree:         1000000 kB
MemAvailable:   20480000 kB
Buffers:          100000 kB
SwapTotal:       8388608 kB
SwapFree:        8000000 kB
`

const procLoadavg = "1.50 2.25 3.75 4/812 12345\n"

func TestParseHostSampleReadsProc(t *testing.T) {
	s, err := parseHostSample(procMeminfo, procLoadavg)
	if err != nil {
		t.Fatal(err)
	}
	want := hostSample{
		MemTotalKB: 32768000, MemAvailableKB: 20480000, SwapTotalKB: 8388608, SwapFreeKB: 8000000,
		Load1: 1.5, Load5: 2.25, Load15: 3.75, Running: 4, Total: 812,
	}
	if s != want {
		t.Errorf("got %+v, want %+v", s, want)
	}
	noAvail := strings.Replace(procMeminfo, "MemAvailable:   20480000 kB\n", "", 1)
	if _, err := parseHostSample(noAvail, procLoadavg); err == nil || !strings.Contains(err.Error(), "MemAvailable") {
		t.Errorf("a meminfo without MemAvailable: err = %v, want one naming it", err)
	}
	if _, err := parseHostSample(procMeminfo, "1.50 2.25\n"); err == nil {
		t.Error("a short loadavg is not an error")
	}
}

func TestBootAndHostLinesAreSnakeCaseKeyValues(t *testing.T) {
	s, err := parseHostSample(procMeminfo, procLoadavg)
	if err != nil {
		t.Fatal(err)
	}
	phases := map[string]bool{}
	for _, p := range []string{phaseDeployStart, phaseDeployDone, phaseSSHBanner, phaseSSHAuth, phaseTACACSSeen} {
		phases[p] = true
		phases[p+"_missed"] = true
	}
	// The host lines' phases, around a whole deploy.
	hostPhases := map[string]bool{"deploy_start": true, "failed": true, "ready": true}
	clock := bootClock{name: "cisco_nxos", start: time.Date(2026, 11, 7, 1, 2, 3, 0, time.UTC)}
	key := regexp.MustCompile(`^[a-z0-9_]+$`)
	for _, c := range []struct {
		line string
		set  map[string]bool
	}{
		{clock.line(phaseSSHAuth, clock.start.Add(95*time.Second+300*time.Millisecond)), phases},
		{clock.line(phaseTACACSSeen+"_missed", clock.start.Add(8*time.Minute)), phases},
		{s.line("cisco_nxos", phaseDeployStart), hostPhases},
		{s.line("cisco_nxos", phaseFailed), hostPhases},
		{s.line("cisco_nxos", phaseReady), hostPhases},
	} {
		line := c.line
		if !strings.HasPrefix(line, "lab: cisco_nxos: ") {
			t.Errorf("line %q lacks the lab prefix", line)
		}
		sawPhase := false
		for _, f := range strings.Fields(line)[3:] {
			k, v, ok := strings.Cut(f, "=")
			if !ok || !key.MatchString(k) {
				t.Errorf("field %q of %q is not a snake_case key=value", f, line)
				continue
			}
			if k == "phase" {
				sawPhase = true
				if !c.set[v] {
					t.Errorf("phase %q is outside the closed set", v)
				}
			}
		}
		if !sawPhase {
			t.Errorf("line %q has no phase", line)
		}
	}
	if got := clock.line(phaseDeployDone, clock.start.Add(95*time.Second+600*time.Millisecond)); !strings.Contains(got, "since_deploy=1m36s") ||
		!strings.Contains(got, "at=2026-11-07T01:03:38") {
		t.Errorf("boot line %q", got)
	}
	if got := s.line("cisco_nxos", phaseDeployStart); !strings.Contains(got, "mem_available_kb=20480000") || !strings.Contains(got, "procs_running=4") {
		t.Errorf("host line %q", got)
	}
}
