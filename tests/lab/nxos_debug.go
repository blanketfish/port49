package lab

import (
	"regexp"
	"slices"
	"strings"
)

// NX-OS debug capture (L80; spec §13 decision 50 ruling 20). `debug
// tacacs+ all` and `debug aaa` write the request, the reply and the
// credential into the device's debug logfile, so nothing from that file is
// kept as it is. The L80 harness filters it with deviceDebugFilter, the
// "nxos" profile (device_debug.go): keep by facility (tacacsd, aaad), drop
// payload and hex-dump lines, redact the run's secrets and reversible
// encodings, mask 24+ character runs, and fail closed. The L80 enable
// sequence (a per-cell `debug logfile <label>` and `show debug logfile
// <label>`) is its own, so deviceDebugCmds has no NX-OS entry.
//
// No body byte is decoded, and no line is kept unfiltered.

// The L80 sequences (design Task 7, lab step 2). A sequence that types a new
// word adds it to nxosDebugWords in the same commit
// (TestNXOSDebugSequencesUseOnlyListedWords), so the harness never depends
// on the lab typing only safe commands.
var (
	// nxosSeqS1 and nxosSeqS3 are the A/B's s1 and s3.
	nxosSeqS1 = []string{"terminal length 0", "show version", "show users", "show clock", "show users"}
	nxosSeqS3 = []string{"terminal length 0", "configure terminal", "hostname nx1", "end", "show users"}
	// nxosSeqE1 is arm E's sequence 1, which the concurrent-sessions cell
	// runs in each CLI session, followed by `show users`.
	nxosSeqE1 = []string{"terminal length 0", "show clock", "terminal length 0", "show clock", "show version",
		"configure terminal", "hostname nx1", "hostname nx1", "end", "show clock", "show users"}
	// nxosSeqSpacing is the A/B's sp step: `terminal length 0`, a gap, then
	// `show users`. The idle-boundary cell runs it with its own gaps.
	nxosSeqSpacing = []string{"terminal length 0", "show users"}
)

// nxosDebugWords are the only words the L80 sequences type: the sequences
// own words, and <cr>. A typed command is never a secret.
var nxosDebugWords = []string{"show", "users", "version", "clock", "terminal", "length", "0", "configure",
	"hostname", "nx1", "end", "<cr>"}

var (
	// nxosDebugSecret is a credential word, a JWT prefix, or a payload line.
	// The device-debug filter no longer drops on it; the note writer and the
	// harness's own command lists still use it as a gate.
	nxosDebugSecret = regexp.MustCompile(`(?i)password|token|secret|eyJ|payload|passwd|challenge|nonce|signature`)
	// nxosDebugHexRun is eight or more space-separated hex bytes (NX-OS
	// prints them without a leading zero), or sixteen or more contiguous
	// hex digits.
	nxosDebugHexRun = regexp.MustCompile(`(?i)(^|\s)([0-9a-f]{1,2}\s+){7}[0-9a-f]{1,2}(\s|$)|[0-9a-f]{16,}`)
	nxosDebugLong   = regexp.MustCompile(`[A-Za-z0-9_+/=.-]{24,}`)
	nxosDebugANSI   = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]|\r`)
)

// nxosDebugCounts is the number of kept lines containing each marker, over
// text already passed through Keep.
func nxosDebugCounts(kept string) map[string]int {
	counts := map[string]int{}
	for _, ln := range strings.Split(kept, "\n") {
		for name, re := range nxosDebugMarkers {
			if re.MatchString(ln) {
				counts[name]++
			}
		}
	}
	return counts
}

// nxosSetupMarkers are the markers also counted over the setup phase, apart: the
// lines before the cell's first request, while port49d was stopped and the
// harness was setting up, which say nothing about the cell.
var nxosSetupMarkers = []string{"mark_server_dead", "fall_back_none", "ssl_open_failed", "ssl_open_retry"}

// nxosCellWindow splits kept at the cell's request: the last `aaa type:` line at
// or before the cell's first `nxos_ssl_open success`. What came before is the
// setup phase. The setup's own request, failed opens and dead lines come first,
// while port49d is stopped; the cell's request line comes before its open (a
// retry can sit between them), so the first success alone would lose the retry.
// With no success the window is unmeasured (ok is false) and nothing is graded
// from it.
func nxosCellWindow(kept string) (setup, cell string, ok bool) {
	lines := strings.Split(kept, "\n")
	first := -1
	for i, ln := range lines {
		if nxosDebugMarkers["ssl_open_success"].MatchString(ln) {
			first = i
			break
		}
	}
	if first < 0 {
		return kept, "", false
	}
	start := first
	for i := first; i >= 0; i-- {
		if strings.Contains(lines[i], "aaa type:") {
			start = i
			break
		}
	}
	return strings.Join(lines[:start], "\n"), strings.Join(lines[start:], "\n"), true
}

// nxosWindowedCounts is nxosDebugCounts over the cell window (window_unmeasured=1
// and zero counts when there is none), plus setup_<marker>
// for the markers in nxosSetupMarkers counted over the setup phase.
func nxosWindowedCounts(kept string) map[string]int {
	setup, cell, ok := nxosCellWindow(kept)
	counts := nxosDebugCounts(cell)
	if !ok {
		counts["window_unmeasured"] = 1
	}
	for k, n := range nxosDebugCounts(setup) {
		if slices.Contains(nxosSetupMarkers, k) {
			counts["setup_"+k] = n
		}
	}
	for _, k := range nxosSetupMarkers {
		if _, ok := counts["setup_"+k]; !ok {
			counts["setup_"+k] = 0
		}
	}
	return counts
}

// nxosDebugMarkers are the L80 measures, plus the request types by number
// and the TLS socket calls.
var nxosDebugMarkers = map[string]*regexp.Regexp{
	"ssl_read_failed":     regexp.MustCompile(`nxos_ssl_read\(\) failed`),
	"mark_server_dead":    regexp.MustCompile(`mark server\(.*\) dead|aaa_mark_server_dead \d`),
	"ssl_open_failed":     regexp.MustCompile(`nxos_ssl_open failed`),
	"ssl_open_retry":      regexp.MustCompile(`nxos_ssl_retry_open`),
	"fall_back_none":      regexp.MustCompile(`Fall back method none`),
	"tacacs_group_failed": regexp.MustCompile(`protocol TACACS failed with server group`),
	"connection_active":   regexp.MustCompile(`connection is Active`),
	"request_authen":      regexp.MustCompile(`aaa type: *1\b`),
	"request_author":      regexp.MustCompile(`aaa type: *2\b`),
	"request_acct":        regexp.MustCompile(`aaa type: *3\b`),
	"ssl_open_success":    regexp.MustCompile(`nxos_ssl_open success`),
}

// nxosFallback is one `Fall back method` line with what preceded it in the
// kept debug: the request it belongs to (from the last `aaa type` line, its
// allowed avstr= lines included) through the fallback, so each can be
// attributed (lab step 2: what was authorized, and whether it ran on the
// fallback).
type nxosFallback struct {
	At      string   // the device's own time
	Line    string   // the fallback line
	Before  string   // the line just before it
	Context []string // from the request's aaa type line through Before
}

// nxosFallbacks reads every fallback out of kept, which Keep has
// already filtered.
func nxosFallbacks(kept string) []nxosFallback {
	lines := strings.Split(kept, "\n")
	var out []nxosFallback
	start := -1
	for i, ln := range lines {
		if strings.Contains(ln, "aaa type:") {
			start = i
		}
		if !strings.Contains(ln, "Fall back method") {
			continue
		}
		f := nxosFallback{Line: ln}
		if at := ddClock.FindString(ln); at != "" {
			f.At = at
		}
		if i > 0 {
			f.Before = lines[i-1]
		}
		from := start
		if from < 0 || from >= i {
			from = max(0, i-1)
		}
		f.Context = append([]string(nil), lines[from:i]...)
		out = append(out, f)
	}
	return out
}
