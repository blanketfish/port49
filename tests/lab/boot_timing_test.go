//go:build lab

package lab

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// The boot phases a deploy logs, a closed set. A gate that gave up prints its
// phase with _missed appended, at its deadline.
const (
	phaseDeployStart = "deploy_start"
	phaseDeployDone  = "deploy_done"
	phaseSSHBanner   = "ssh_banner"
	phaseSSHAuth     = "ssh_auth"
	phaseTACACSSeen  = "tacacs_seen"

	// The host samples' own phases, around a whole deploy.
	phaseFailed = "failed"
	phaseReady  = "ready"
)

// hostSample is the lab host's memory and load, read from /proc/meminfo and
// /proc/loadavg only, so a hung boot can be read against host pressure.
type hostSample struct {
	MemTotalKB, MemAvailableKB, SwapTotalKB, SwapFreeKB int64
	Load1, Load5, Load15                                float64
	Running, Total                                      int
}

// parseHostSample reads the four meminfo fields and loadavg's three loads and
// running/total. A missing field is an error naming it.
func parseHostSample(meminfo, loadavg string) (hostSample, error) {
	var s hostSample
	fields := map[string]*int64{
		"MemTotal": &s.MemTotalKB, "MemAvailable": &s.MemAvailableKB,
		"SwapTotal": &s.SwapTotalKB, "SwapFree": &s.SwapFreeKB,
	}
	seen := map[string]bool{}
	for _, ln := range strings.Split(meminfo, "\n") {
		k, rest, ok := strings.Cut(ln, ":")
		p, want := fields[k]
		if !ok || !want {
			continue
		}
		v := strings.Fields(rest)
		if len(v) == 0 {
			return s, fmt.Errorf("meminfo: %s has no value", k)
		}
		n, err := strconv.ParseInt(v[0], 10, 64)
		if err != nil {
			return s, fmt.Errorf("meminfo: %s: %v", k, err)
		}
		*p, seen[k] = n, true
	}
	for _, k := range []string{"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"} {
		if !seen[k] {
			return s, fmt.Errorf("meminfo: no %s", k)
		}
	}
	f := strings.Fields(loadavg)
	if len(f) < 4 {
		return s, fmt.Errorf("loadavg: want at least 4 fields, got %d", len(f))
	}
	for i, p := range []*float64{&s.Load1, &s.Load5, &s.Load15} {
		v, err := strconv.ParseFloat(f[i], 64)
		if err != nil {
			return s, fmt.Errorf("loadavg: field %d: %v", i+1, err)
		}
		*p = v
	}
	run, total, ok := strings.Cut(f[3], "/")
	if !ok {
		return s, fmt.Errorf("loadavg: no running/total in field 4")
	}
	var err error
	if s.Running, err = strconv.Atoi(run); err != nil {
		return s, fmt.Errorf("loadavg: running: %v", err)
	}
	if s.Total, err = strconv.Atoi(total); err != nil {
		return s, fmt.Errorf("loadavg: total: %v", err)
	}
	return s, nil
}

// readHostSample reads /proc/meminfo and /proc/loadavg.
func readHostSample() (hostSample, error) {
	mem, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return hostSample{}, err
	}
	load, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return hostSample{}, err
	}
	return parseHostSample(string(mem), string(load))
}

// line is the sample as one lab log line.
func (s hostSample) line(name, phase string) string {
	return fmt.Sprintf("lab: %s: host: phase=%s mem_total_kb=%d mem_available_kb=%d swap_total_kb=%d swap_free_kb=%d "+
		"load1=%.2f load5=%.2f load15=%.2f procs_running=%d procs_total=%d",
		name, phase, s.MemTotalKB, s.MemAvailableKB, s.SwapTotalKB, s.SwapFreeKB,
		s.Load1, s.Load5, s.Load15, s.Running, s.Total)
}

// logHostSample prints a host line, or says the read failed. It never fails
// the run.
func logHostSample(name, phase string) {
	s, err := readHostSample()
	if err != nil {
		fmt.Fprintf(os.Stderr, "lab: %s: host: unreadable: %v\n", name, err)
		return
	}
	fmt.Fprintln(os.Stderr, s.line(name, phase))
}

// bootClock times a deploy's phases from its start.
type bootClock struct {
	name  string
	start time.Time
}

// line is one boot phase as a lab log line.
func (c bootClock) line(phase string, at time.Time) string {
	return fmt.Sprintf("lab: %s: boot: phase=%s at=%s since_deploy=%s",
		c.name, phase, at.UTC().Format(time.RFC3339), at.Sub(c.start).Round(time.Second))
}

// log prints phase as of now, to os.Stderr like the other lab: lines.
func (c bootClock) log(phase string) {
	fmt.Fprintln(os.Stderr, c.line(phase, time.Now()))
}
