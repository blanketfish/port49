//go:build lab

package lab

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// The graders of L66's cells (fix round 1, I4): each cell's verdict is a pure function of counts and strings,
// so a unit test can pin it, as L64 does with l64GradeSSHRefusal and l64GradeE2.

// l66ChangedKeyError is whether errText names a changed host key in the wording of the ssh type's client:
// pylibssh's KNOW_HOST_MSG_MAP for libssh, paramiko's BadHostKeyException for paramiko.
func l66ChangedKeyError(sshType, errText string) bool {
	switch sshType {
	case "libssh":
		return strings.Contains(errText, "Host key for server has changed") ||
			strings.Contains(errText, "Host key type for server has changed")
	case "paramiko":
		return strings.Contains(errText, "BadHostKeyException") ||
			(strings.Contains(errText, "Host key for server") && strings.Contains(errText, "does not match"))
	}
	return false
}

// l66ChangedIn is what L66's changed-key cell (c2) read.
type l66ChangedIn struct {
	SSHType          string
	Failed           bool // the play did not pass
	Packets, Redeems int
	Other            []string // records other than mint and blob
	ErrText          string
}

// l66GradeChanged reads the (c) claim for a changed key: the play fails before authentication, with the
// client's own words for it, no TACACS+ packet, no redeem and no record but mint and blob. why names what
// did not hold.
func l66GradeChanged(in l66ChangedIn) (bool, string) {
	var bad []string
	if !in.Failed {
		bad = append(bad, "the play did not fail")
	}
	if in.Packets != 0 {
		bad = append(bad, fmt.Sprintf("%d TACACS+ packets reached port49d", in.Packets))
	}
	if in.Redeems != 0 {
		bad = append(bad, fmt.Sprintf("%d redeem record(s): the token was presented", in.Redeems))
	}
	if len(in.Other) != 0 {
		bad = append(bad, fmt.Sprintf("records other than mint and blob: %v", in.Other))
	}
	if !l66ChangedKeyError(in.SSHType, in.ErrText) {
		bad = append(bad, fmt.Sprintf("the error does not name a changed host key in %s's wording (it was %q)", in.SSHType,
			trimTo(in.ErrText, 200)))
	}
	return len(bad) == 0, strings.Join(bad, "; ")
}

func trimTo(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// l66DeniedIn is what the denied-device cell (d) read.
type l66DeniedIn struct {
	Failed, Named, GoodRunGood bool
	MintDenies, DeniedPackets  int
	Other                      []string
	DeniedHits, GoodHits       []int
}

// l66GradeDenied reads the (d) claim: the denied task fails naming no_grants_matched, with a deny record and
// nothing sent to port49d as a TACACS+ packet, and no minted token's hash among the words of the -vvv output
// of the denied run or of a good one.
func l66GradeDenied(in l66DeniedIn) (bool, string) {
	var bad []string
	if !in.Failed {
		bad = append(bad, "the denied task did not fail")
	}
	if !in.Named {
		bad = append(bad, "the output does not name no_grants_matched")
	}
	if in.MintDenies == 0 {
		bad = append(bad, "no mint deny record")
	}
	if len(in.DeniedHits) != 0 {
		bad = append(bad, fmt.Sprintf("a minted token's hash matches words of the denied run's output (lines %v)", in.DeniedHits))
	}
	if len(in.GoodHits) != 0 {
		bad = append(bad, fmt.Sprintf("a minted token's hash matches words of the good run's output (lines %v)", in.GoodHits))
	}
	if !in.GoodRunGood {
		bad = append(bad, "the good run was not a good login, so its -vvv output had no token to leak")
	}
	if in.DeniedPackets != 0 {
		bad = append(bad, fmt.Sprintf("%d TACACS+ packets in the denied window", in.DeniedPackets))
	}
	if len(in.Other) != 0 {
		bad = append(bad, fmt.Sprintf("records other than mint and blob in the denied window: %v", in.Other))
	}
	return len(bad) == 0, strings.Join(bad, "; ")
}

// l66JSONRPC counts the `jsonrpc request:` lines of a persistent connection log and says whether one of them
// is a set_options.
func l66JSONRPC(log string) (requests int, setOptions bool) {
	for _, ln := range strings.Split(log, "\n") {
		if strings.Contains(ln, "jsonrpc request:") {
			requests++
			if strings.Contains(ln, "set_options") {
				setOptions = true
			}
		}
	}
	return requests, setOptions
}

// l66LogTasks is how many tasks the log-search plays have. The first task starts the persistent process and
// hands it its options in-process; only a later task finds the socket and sends set_options over it, with the
// password in the options, where persistent_log_messages logs the request.
const l66LogTasks = 3

// l66LogSearchIn is what the log-search cell (d2) read.
type l66LogSearchIn struct {
	RunGood                   bool
	Log                       string
	OutHits, ErrHits, LogHits []int
}

// l66GradeLogSearch returns whether the claim held (no token among the words of stdout, stderr and the
// persistent log), and, when the search proves nothing, why (INVALID): the run was not good, or the log does
// not hold the traffic that would have carried the token (two jsonrpc requests, one a set_options).
func l66GradeLogSearch(in l66LogSearchIn) (ok bool, invalid, why string) {
	requests, setOptions := l66JSONRPC(in.Log)
	switch {
	case !in.RunGood:
		return false, "the run was not a good login, so there was no connection to log", ""
	case requests < 2:
		return false, fmt.Sprintf("the persistent connection's log holds %d `jsonrpc request:` line(s), fewer than the two a later "+
			"task needs to send its options over the socket, so its search proves nothing", requests), ""
	case !setOptions:
		return false, "none of the persistent connection's `jsonrpc request:` lines is a set_options, the request that carries the " +
			"connection's options, so its search proves nothing", ""
	}
	var found []string
	if len(in.OutHits) != 0 {
		found = append(found, fmt.Sprintf("stdout lines %v", in.OutHits))
	}
	if len(in.ErrHits) != 0 {
		found = append(found, fmt.Sprintf("stderr lines %v", in.ErrHits))
	}
	if len(in.LogHits) != 0 {
		found = append(found, fmt.Sprintf("log lines %v", in.LogHits))
	}
	if len(found) != 0 {
		return false, "", "words that hash to a minted token are in " + strings.Join(found, ", ")
	}
	return true, "", ""
}

// l66GradeMoved reads the stand-in step of (e): invalid says the step measured nothing (the stand-in was never
// reached, or an attempt cannot be compared with any token). Otherwise presented is whether an attempt the
// stand-in logged is a token the run minted: known are the hashes of the run so far, r2 the step's own.
func l66GradeMoved(t l66StandinTally, known, r2 map[string]bool) (invalid string, presented bool) {
	if t.Connects == 0 {
		return "the stand-in saw no connection, so whether the token was presented to it was not measured", false
	}
	all := map[string]bool{}
	for h := range known {
		all[h] = true
	}
	for h := range r2 {
		all[h] = true
	}
	if t.Passwords+t.Kbdint > 0 && len(all) == 0 {
		return "the stand-in logged an attempt but the run knows no token hash to compare it with", false
	}
	return "", t.Presented(all)
}

// l66GradeGap is whether the task after the gap logged in again: a second authentication start, or a second
// redeem.
func l66GradeGap(starts, redeems int) bool { return starts > 1 || redeems > 1 }

// l66AliasRead is what one host's own ssh log (-E, LogLevel DEBUG3) says about its HostKeyAlias.
type l66AliasRead struct {
	// Lines are the lines that name the alias in a lookup or a filed key.
	Lines []string
	// Muxed: the connection reused an open master. Connected: it opened a TCP connection of its own.
	// Authenticated: that connection logged in. AliasUsed: ssh looked the alias up in known_hosts. Filed: it
	// added a key under the alias.
	Muxed, Connected, Authenticated, AliasUsed, Filed bool
}

var l66AliasLineRe = regexp.MustCompile(`hostkeyalias|Permanently added|is known and matches|Host '`)

// l66ReadAlias reads a host's ssh log. "auto-mux: Trying existing master" is printed whether or not a master
// exists, so a reused one is read from the hello exchange or the master's session id instead.
func l66ReadAlias(log, alias string) l66AliasRead {
	var r l66AliasRead
	word := regexp.MustCompile(`\b` + regexp.QuoteMeta(alias) + `\b`)
	for _, ln := range strings.Split(log, "\n") {
		if word.MatchString(ln) && l66AliasLineRe.MatchString(ln) {
			r.Lines = append(r.Lines, strings.TrimSpace(ln))
		}
	}
	r.Muxed = strings.Contains(log, "mux_client_hello_exchange: master version") || strings.Contains(log, "master session id")
	r.Connected = strings.Contains(log, "Connection established.")
	r.Authenticated = strings.Contains(log, "Authenticated to ")
	r.AliasUsed = strings.Contains(log, "using hostkeyalias: "+alias)
	r.Filed = strings.Contains(log, "Permanently added '"+alias+"'")
	return r
}

// l66GradeNames is why (e2) read nothing, when it did not: no logs, or a host's ssh log empty or without a
// debug line. Such a log cannot show a lookup, so the cell is INVALID.
func l66GradeNames(logs map[string]string) string {
	if len(logs) == 0 {
		return "no ssh log was read"
	}
	var bad []string
	for _, h := range slices.Sorted(maps.Keys(logs)) {
		switch l := logs[h]; {
		case strings.TrimSpace(l) == "":
			bad = append(bad, fmt.Sprintf("the ssh log of %s is empty", h))
		case !strings.Contains(l, "debug1:"):
			bad = append(bad, fmt.Sprintf("the ssh log of %s holds no debug1 line", h))
		}
	}
	return strings.Join(bad, "; ")
}

// l66ParamikoRefusedMarkers is whether the error is paramiko choking on an @revoked or @cert-authority line:
// its loader raises InvalidHostKey, which it does not catch.
func l66ParamikoRefusedMarkers(errText string) bool {
	return strings.Contains(errText, "InvalidHostKey") || strings.Contains(errText, "Invalid key")
}

// l66CommentKH is the known_hosts file of a comment line alone.
func l66CommentKH() string {
	return "# L66 baseline: a comment line a client that rewrites this file may drop\n"
}

// l66NSSPasswd and l66NSSGroup are the files nss_wrapper is given so that the user's passwd home is the
// private one (libssh reads the home from the passwd entry, not $HOME).
func l66NSSPasswd(name string, uid, gid int, home, shell string) string {
	s := "root:x:0:0:root:/root:/bin/sh\n"
	if uid != 0 {
		s += fmt.Sprintf("%s:x:%d:%d:L66 private home:%s:%s\n", name, uid, gid, home, shell)
	}
	return s
}

func l66NSSGroup(name string, gid int) string {
	s := "root:x:0:\n"
	if gid != 0 {
		s += fmt.Sprintf("%s:x:%d:\n", name, gid)
	}
	return s
}

// l66FindNSSWrapper is the path of libnss_wrapper.so under dirs, if there is one.
func l66FindNSSWrapper(dirs []string) (string, bool) {
	for _, d := range dirs {
		p := filepath.Join(d, "libnss_wrapper.so")
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, true
		}
	}
	return "", false
}

// l66CellBudget is how long a cell may run given the test's deadline: its own budget, less than that when the
// deadline is near (reserve is kept for the teardown), and not at all when less than min would be left to it.
func l66CellBudget(want time.Duration, deadline time.Time, hasDeadline bool, now time.Time, reserve, min time.Duration) (time.Duration, bool) {
	if !hasDeadline {
		return want, true
	}
	left := deadline.Sub(now) - reserve
	if left < min {
		return 0, false
	}
	return min2(want, left), true
}

func min2(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
