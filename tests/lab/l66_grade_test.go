//go:build lab

package lab

import (
	"errors"
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
		// netcommon 8.7.0 catches BadHostKeyException and raises "host key mismatch for <host>".
		return strings.Contains(errText, "host key mismatch for") || strings.Contains(errText, "BadHostKeyException") ||
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
//
// Ansible prints str(InvalidHostKey), which is the offending line and the decode error, not the class name:
// ('@revoked unrelated.l66.invalid ssh-ed25519 AAAA...', Error('Incorrect padding')).
func l66ParamikoRefusedMarkers(errText string) bool {
	if strings.Contains(errText, "InvalidHostKey") {
		return true
	}
	marker := strings.Contains(errText, "'@revoked ") || strings.Contains(errText, "'@cert-authority ")
	return marker && strings.Contains(errText, "Error('")
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

// l66PrivateEnv is base with the home, nss_wrapper and every ANSIBLE_* setting of the caller replaced: HOME is
// the private one, and the passwd lookup (which libssh and Python's pwd use) agrees with it. Every Ansible
// command of the harness, the preflight's included, is run in it, so none writes the operator's ~/.ansible.
func l66PrivateEnv(base []string, home, nssLib, passwd, group string) []string {
	env := slices.DeleteFunc(slices.Clone(base), func(kv string) bool {
		for _, p := range []string{"HOME=", "LD_PRELOAD=", "NSS_WRAPPER_", "ANSIBLE_"} {
			if strings.HasPrefix(kv, p) {
				return true
			}
		}
		return false
	})
	return append(env, "HOME="+home, "LD_PRELOAD="+nssLib, "NSS_WRAPPER_PASSWD="+passwd, "NSS_WRAPPER_GROUP="+group)
}

// l66PreflightEnv is the environment the preflight runs Python and Ansible in: l66PrivateEnv with its own
// private directory, and no bytecode written.
func l66PreflightEnv(base []string, pre, lib string) []string {
	return append(l66PrivateEnv(base, pre, lib, filepath.Join(pre, "nss_passwd"), filepath.Join(pre, "nss_group")),
		"PYTHONDONTWRITEBYTECODE=1")
}

// l66StepOneIn is what a cell that starts from an earlier contact read of that contact: the play passed,
// a login reached port49d (a redeem), how many key lines it filed, and whether another cell of this same run
// measured the client not filing one.
type l66StepOneIn struct {
	Passed, LoggedIn bool
	Filed            int
	MeasuredNoFile   bool
}

// l66GradeStepOne is "ok" when the contact logged in and filed a key; "not run" only when the play passed,
// logged in, filed nothing and a cell of this run measured exactly that for the client; and "invalid" for
// everything else (a docker, network or device failure leaves nothing measured).
func l66GradeStepOne(in l66StepOneIn) (verdict, why string) {
	switch {
	case in.Filed > 0 && in.LoggedIn:
		return "ok", ""
	case in.Filed > 0:
		return "invalid", "the earlier contact filed a key but no login reached port49d, so it was not a contact that logged in"
	case in.Passed && in.LoggedIn && in.MeasuredNoFile:
		return "not run", "the client logs in without filing a key, as the first-contact cell of this run measured"
	case in.Passed && in.LoggedIn:
		return "invalid", "the earlier contact filed no key and no cell of this run measured the client doing that"
	}
	return "invalid", "the earlier contact did not pass and log in (a device, network, docker or port49d failure), so nothing was measured"
}

// l66PlayEnd is why the ansible-playbook run name did not end on its own, or "" when it did. A run that was ended
// (the deadline, a signal: exit -1) or could not be waited on (err), or that printed no PLAY RECAP, never ran its
// play to an end, so nothing a cell reads from it is a measurement. Any other exit, 2 and 4 included, is
// Ansible's own verdict and is the cell's to read. runPlay makes the cell INVALID with this.
func l66PlayEnd(name string, exit int, err error, recapHosts int) string {
	switch {
	case err != nil:
		return fmt.Sprintf("the play %s ended abnormally (%v), so it measured nothing", name, err)
	case exit < 0:
		return fmt.Sprintf("the play %s was killed by a signal (exit %d), so it measured nothing", name, exit)
	case recapHosts == 0:
		return fmt.Sprintf("the play %s printed no PLAY RECAP (exit %d), so it never ran to an end and measured nothing", name, exit)
	}
	return ""
}

// l66NoFile is whether a first-contact play measured a client that logs in and files no key line: it passed,
// a login reached port49d, nothing was added to the file, and the play ended on its own (end is
// l66PlayEnd's reading, "" for a normal end).
func l66NoFile(passed bool, redeems, added int, end string) bool {
	return passed && redeems > 0 && added == 0 && end == ""
}

// l66FirstContactNeverConnected says why a first-contact play never reached the device, or "" when it did:
// no task of the play succeeded, or the mint was not permitted. Such a play says nothing about the client's
// handling of the key, so the cell is INVALID and not a FAIL.
func l66FirstContactNeverConnected(recapOK, mints, mintDenies int) string {
	switch {
	case recapOK == 0:
		return "no task of the first-contact play succeeded, so it never reached the device"
	case mints-mintDenies <= 0:
		return "the first-contact play's window holds no permitted mint record, so no token was minted to present"
	}
	return ""
}

// l66RedeemsOfMinted counts the window's redeem records whose credential_sha256 is the token_sha256 of a mint
// record in the same window: a login with a token this run minted.
func l66RedeemsOfMinted(recs []map[string]any) int {
	minted := map[string]bool{}
	for _, r := range recs {
		if str(r, "event") == "mint" {
			for _, s := range strs(sub(r, "mint"), "token_sha256") {
				minted[s] = true
			}
		}
	}
	n := 0
	for _, r := range recs {
		if str(r, "event") == "redeem" && minted[str(sub(r, "auth"), "credential_sha256")] {
			n++
		}
	}
	return n
}

// l66Settle decides a cell's final outcome. A fatal or an invalid set during the cell comes before NOT RUN and
// before TIMEOUT: a cell that could not measure must not read as one that was blocked, and a cell whose budget
// ran out while a play ran had that play ended at the deadline (l66PlayEnd).
func l66Settle(outcome, fatal, invalid, notRun string, unread bool) string {
	switch {
	case fatal != "" || invalid != "" || unread:
		return "INVALID"
	case outcome == "TIMEOUT":
		return outcome
	case notRun != "":
		return "NOT RUN (" + notRun + ")"
	}
	return outcome
}

// l66CellCap is the token.candidate_cap a cell runs under: 0 for L66a, which measures the cap and runs under
// port49's default (what an operator gets), and l48CandidateCap for every other cell, none of which measures
// it and several of which mint more than the default's 8 in one cell.
func l66CellCap(id string) int {
	if id == "L66a" {
		return 0
	}
	return l48CandidateCap
}

// l66CapConfig is a daemon config with token.candidate_cap set to cap, or base unchanged for cap 0 (the
// default). A base that already has a top-level token block is an error: a second one is a duplicate key.
func l66CapConfig(base string, cap int) (string, error) {
	if cap == 0 {
		return base, nil
	}
	if strings.HasPrefix(base, "token:") || strings.Contains(base, "\ntoken:") {
		return "", errors.New("the daemon config already has a top-level token block, so a second one would be a duplicate key")
	}
	if !strings.HasSuffix(base, "\n") {
		base += "\n"
	}
	return fmt.Sprintf("%s\ntoken: {candidate_cap: %d}\n", base, cap), nil
}

// l66CapNote is the sentence each cell's note gives for the cap it ran under.
func l66CapNote(cap int) string {
	if cap == 0 {
		return fmt.Sprintf("Candidate cap: port49's default of %d unspent tokens per device and username (this cell measures it), on a port49d restarted with an empty token store.", l48DefaultCandidateCap)
	}
	return fmt.Sprintf("Candidate cap: raised to %d with `token.candidate_cap` (this cell does not measure the cap; port49's default is %d), on a port49d restarted with an empty token store.", cap, l48DefaultCandidateCap)
}

// l66MintRefusedByCap says whether the first mint record in a window is already a candidate_cap_reached
// denial: the store did not start empty for this cell, so nothing the cell measured can be read.
func l66MintRefusedByCap(recs []map[string]any) bool {
	for _, r := range recs {
		if str(r, "event") == "mint" {
			return str(r, "verdict") == "deny" && str(r, "reason") == "candidate_cap_reached"
		}
	}
	return false
}

// l66CapIn is what L66a read from its one play.
type l66CapIn struct {
	Recap            l66Recap
	Counts           l66Counts
	Starts           int
	FirstMintRefused bool
	// ConnLookups is how many lookups the play's connection variables hold (l66ConnLookups).
	ConnLookups int
}

// l66GradeCap grades L66a, the lookups in the connection variables under the default cap. The first task's
// good login (a redeem, a TACACS+ authentication start and a task that passed) is the positive control for the
// counts. With it, the outcome is the measurement: PASS, whether the play ran ten tasks or failed at task N
// with candidate_cap_reached. Without it, or when the counts contradict the cap, INVALID. The text states what
// was counted, and mints per task only as the ratio of the two counts. failedAt is 0 when no task number is
// read: none failed, or the recap does not show the one failed task a refusal would give.
func l66GradeCap(in l66CapIn) (outcome string, failedAt int, text string) {
	c, rc := in.Counts, in.Recap
	attempted := rc.OK + rc.Failed + rc.Unreachable
	counts := fmt.Sprintf("%d mint records (%d denied), %d redeem records and %d TACACS+ authentication starts", c.Mints, c.MintDenies, c.Redeems, in.Starts)
	measured := counts
	if attempted > 0 {
		measured = fmt.Sprintf("%s for %d tasks attempted (%d ok, %d failed, %d unreachable in the recap) on one host: %.2f mint records "+
			"per task attempted, with %d lookups of port49.client.token in the connection variables", counts, attempted, rc.OK, rc.Failed,
			rc.Unreachable, float64(c.Mints)/float64(attempted), in.ConnLookups)
	}
	switch {
	case in.FirstMintRefused:
		return "INVALID", 0, "the first mint of the cell was already refused with candidate_cap_reached, so the token store was not fresh " +
			"and the count below is not this play's: " + counts
	case rc.OK == 0 || c.Redeems == 0 || in.Starts == 0:
		return "INVALID", 0, "the positive control failed: the first task's good login (a task that passed, a redeem record and a TACACS+ " +
			"authentication start) was not seen, so these counts are not a measurement: " + counts
	}
	if rc.Failed == 0 && rc.Unreachable == 0 {
		if rc.OK != 10 {
			return "INVALID", 0, fmt.Sprintf("the recap shows %d ok and nothing failed, not the ten tasks the play holds: %s", rc.OK, measured)
		}
		// A redeem spends at most one token, so permitted mints less redeems is the fewest left unspent. More
		// than the cap, with none refused, is a reading the cap forbids (unless tokens expired mid-play).
		if unspent := c.Mints - c.MintDenies - c.Redeems; unspent > l48DefaultCandidateCap {
			return "INVALID", 0, fmt.Sprintf("all ten tasks passed, which contradicts the default token.candidate_cap of %d: %d permitted "+
				"mints and %d redeems leave at least %d tokens unspent, yet no mint was refused (did tokens expire during the play?): %s",
				l48DefaultCandidateCap, c.Mints-c.MintDenies, c.Redeems, unspent, measured)
		}
		return "PASS", 0, fmt.Sprintf("With the default token.candidate_cap of %d, all 10 tasks passed. %s.", l48DefaultCandidateCap, measured)
	}
	at := rc.OK + 1
	if refused := c.MintReasons["candidate_cap_reached"]; refused > 0 {
		if rc.Failed != 1 || rc.Unreachable != 0 {
			return "PASS", 0, fmt.Sprintf("With the default token.candidate_cap of %d, %d mints were refused with candidate_cap_reached, but "+
				"the recap (%d ok, %d failed, %d unreachable) does not show the one failed task a refusal gives, so no task number is read "+
				"from it. %s.", l48DefaultCandidateCap, refused, rc.OK, rc.Failed, rc.Unreachable, measured)
		}
		return "PASS", at, fmt.Sprintf("With the default token.candidate_cap of %d, the play fails at task %d with candidate_cap_reached. %s.",
			l48DefaultCandidateCap, at, measured)
	}
	return "PASS", at, fmt.Sprintf("The play failed at task %d and that was not the cap (no mint was refused with candidate_cap_reached; "+
		"mint reasons %v). %s.", at, c.MintReasons, measured)
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
