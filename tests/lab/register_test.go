//go:build lab

package lab

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// L1: what the `port` field contains per platform and per transport, and
// whether it is unique per concurrent session. This plan measures SSH only;
// eAPI and NX-API are plan 3.
func TestL1PortField(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		stop := l.capture(t, "L1")
		defer stop()
		off := l.mark()

		// The claim is about CONCURRENT sessions, so the two logins overlap:
		// each holds an interactive shell open while the other is logging in.
		// Two logins one after the other would not tell them apart.
		u1, s1 := l.nextLogin(t)
		u2, s2 := l.nextLogin(t)
		var wg sync.WaitGroup
		errs := make([]error, 2)
		wg.Add(2)
		go func() { defer wg.Done(); errs[0] = l.holdSession(u1, s1, 20*time.Second) }()
		time.Sleep(2 * time.Second) // let the first session be established first
		go func() { defer wg.Done(); errs[1] = l.holdSession(u2, s2, 15*time.Second) }()
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("concurrent SSH login %d failed, so no port value was observed: %v", i+1, err)
			}
		}

		recs := l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
			return len(redeemPorts(rs)) >= 2
		})
		ports := redeemPorts(recs)
		if len(ports) < 2 {
			t.Fatalf("expected a port value from each of two concurrent logins, got %d (%q):%s", len(ports), ports, summarize(recs))
		}

		unique := ports[0] != ports[1]
		uniqueNote := "**The two concurrent sessions reported the SAME `port` value.** The login context key " +
			"`(nas, port)` therefore does not distinguish them: the second login overwrites the first login's " +
			"context, and the receipt key `(nas, port, username)` collides for repeated logins by one user."
		if unique {
			uniqueNote = "**The two concurrent sessions reported DIFFERENT `port` values**, so the login context " +
				"key `(nas, port)` distinguishes them."
		}
		obs := fmt.Sprintf("Two overlapping SSH sessions, each holding an interactive shell open, produced these "+
			"`port` values on the authentication START:\n\n"+
			"| session | user | `port` |\n|---|---|---|\n| 1 | %s | `%s` |\n| 2 | %s | `%s` |\n\n%s\n\n"+
			"All %d `port` values seen in this test: %q.\n\n"+
			"Stability for the life of a session: %s\n\n"+
			"Transport measured: SSH only. Console, eAPI, NX-API and NETCONF are not measured here "+
			"(eAPI and NX-API are plan 3), so L1 is not answered for those transports.",
			u1, ports[0], u2, ports[1], uniqueNote, len(ports), ports, portStability(recs))
		l.result(t, "L1", "What the `port` field contains, per platform and per transport — SSH, console, eAPI, "+
			"NX-API, NETCONF. Whether it is unique per concurrent session and stable for its life.", obs)
	})
}

// portStability answers the second half of L1 from the records rather than
// asserting it: every record carrying a ctx_id belongs to one session, so if a
// session's `port` ever changed, that ctx_id would show two values.
func portStability(recs []map[string]any) string {
	byCtx := map[string]map[string]bool{}
	records := 0
	for _, r := range recs {
		s := sub(r, "session")
		if s == nil {
			continue
		}
		ctx := str(s, "ctx_id")
		if ctx == "" {
			continue
		}
		records++
		if byCtx[ctx] == nil {
			byCtx[ctx] = map[string]bool{}
		}
		byCtx[ctx][str(s, "port")] = true
	}
	if len(byCtx) == 0 {
		return "not measured: no record in this window carried a ctx_id."
	}
	var unstable []string
	for ctx, ports := range byCtx {
		if len(ports) > 1 {
			unstable = append(unstable, ctx)
		}
	}
	if len(unstable) == 0 {
		return fmt.Sprintf("stable. Across %d sessions and %d records carrying a ctx_id, every record for a "+
			"session reported the same `port` as that session's authentication START.", len(byCtx), records)
	}
	sort.Strings(unstable)
	return fmt.Sprintf("**NOT stable**: %d of %d sessions reported more than one `port` value over their life (%s).",
		len(unstable), len(byCtx), strings.Join(unstable, ", "))
}

func redeemPorts(recs []map[string]any) []string {
	var out []string
	for _, r := range recs {
		if str(r, "event") != "redeem" || str(r, "reason") != "token_redeemed" {
			continue
		}
		if s := sub(r, "session"); s != nil {
			out = append(out, str(s, "port"))
		}
	}
	return out
}

// L2: whether `server_msg` on an authorization REPLY is displayed to the
// operator, and at what length it truncates.
func TestL2ServerMsgDisplayed(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if strings.HasPrefix(l.p.name, "juniper_") {
			t.Skip("session-only platform: no per-command REPLY (spec decision 21)")
		}
		stop := l.capture(t, "L2")
		defer stop()
		off := l.mark()

		user, secret := l.nextLogin(t)
		out, err := l.login(user, secret, shortDenyPrefix)
		if err != nil {
			t.Fatalf("SSH login failed, so no denial could be shown: %v", err)
		}
		if len(out) == 0 {
			t.Fatal("the device returned no output for the denied command, so nothing could be observed")
		}
		shortMsg := denialMessage(shortDenyPrefix)

		recs := l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
			return findDenial(rs, shortMsg) != nil
		})
		if findDenial(recs, shortMsg) == nil {
			t.Fatalf("the device never asked port49 to authorize %q, so whether it would display a server_msg "+
				"could not be measured. Device output was:\n%s\nrecords:%s", shortDenyPrefix, out[0], summarize(recs))
		}

		shown := strings.Contains(out[0], shortMsg)
		verdict := "NOT displayed"
		if shown {
			verdict = "displayed"
		}

		// Second half of the claim, best effort: a denial whose server_msg is
		// long enough to truncate. A device that never sends this line for
		// authorization leaves the truncation length unmeasured, which is
		// recorded rather than failed — the display question above is the one
		// this test guarantees.
		longNote := measureTruncation(t, l)

		obs := fmt.Sprintf("Command `%s` was denied by the lab authorizer with a %d-character `server_msg`:\n\n"+
			"```\n%s\n```\n\n**The operator saw it: %s.**\n\nWhat the device printed for the denied command:\n\n"+
			"```\n%s\n```\n\n### Truncation length\n\n%s\n",
			shortDenyPrefix, len(shortMsg), shortMsg, verdict, strings.TrimRight(out[0], "\n"), longNote)
		l.result(t, "L2", "Whether `server_msg` on an authorization REPLY is displayed to the operator, and at "+
			"what length it truncates.", obs)
	})
}

// denialMessage is the server_msg author.Lab builds for a denied prefix. The
// test compares the device's output against it verbatim.
func denialMessage(prefix string) string {
	return "port49: denied by lab_deny (" + prefix + "); see 'port49 explain'"
}

func findDenial(recs []map[string]any, msg string) map[string]any {
	for _, r := range recs {
		if str(r, "event") == "authorize_command" && str(r, "verdict") == "deny" && str(r, "server_msg") == msg {
			return r
		}
	}
	return nil
}

func measureTruncation(t *testing.T, l *lab) string {
	t.Helper()
	mustBeSeeded(t, longDenyPrefix)
	off := l.mark()
	user, secret := l.nextLogin(t)
	out, err := l.login(user, secret, longDenyPrefix)
	if err != nil {
		return fmt.Sprintf("Not measured: the second login, for the long denial, failed (%v).", err)
	}
	longMsg := denialMessage(longDenyPrefix)
	recs := l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
		return findDenial(rs, longMsg) != nil
	})
	if findDenial(recs, longMsg) == nil {
		return fmt.Sprintf("Not measured, and the reason is itself an observation. The operator typed a "+
			"%d-character line, but the device did not send that line for authorization, so port49 never "+
			"built a long `server_msg` to truncate. What the device actually asked port49 to authorize:\n\n"+
			"```\n%s\n```\n\nThe device printed:\n\n```\n%s\n```",
			len(longDenyPrefix), strings.Join(vectorsAuthorized(recs), "\n"), strings.TrimRight(outFirst(out), "\n"))
	}
	printed := outFirst(out)
	if strings.Contains(printed, longMsg) {
		return fmt.Sprintf("A %d-character `server_msg` was displayed in full; no truncation at this length.", len(longMsg))
	}
	shownPrefix := longestCommonPrefixShown(printed, longMsg)
	return fmt.Sprintf("A %d-character `server_msg` was **not** shown in full. The longest run of it the device "+
		"printed was %d characters:\n\n```\n%s\n```\n\nFull device output:\n\n```\n%s\n```",
		len(longMsg), len(shownPrefix), shownPrefix, strings.TrimRight(printed, "\n"))
}

// vectorsAuthorized lists the command vectors the device actually asked port49
// to authorize, which is how a device that rewrites the operator's line before
// sending it shows up in the results note.
func vectorsAuthorized(recs []map[string]any) []string {
	var out []string
	for _, r := range recs {
		if str(r, "event") != "authorize_command" {
			continue
		}
		v := strs(sub(r, "request"), "vector")
		out = append(out, fmt.Sprintf("%q", strings.Join(v, " ")))
	}
	if len(out) == 0 {
		return []string{"(the device sent no command authorization request at all)"}
	}
	return out
}

func outFirst(out []string) string {
	if len(out) == 0 {
		return ""
	}
	return out[0]
}

// longestCommonPrefixShown returns the longest leading run of msg that appears
// verbatim in printed, which is where a device cut the message off.
func longestCommonPrefixShown(printed, msg string) string {
	best := ""
	for n := len(msg); n > 0; n-- {
		if strings.Contains(printed, msg[:n]) {
			best = msg[:n]
			break
		}
	}
	return best
}

// L5: which platforms send accounting WATCHDOG, how often, and with or without
// arguments.
func TestL5Watchdog(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		stop := l.capture(t, "L5")
		defer stop()
		off := l.mark()

		const hold = 150 * time.Second
		t0 := time.Now()
		user, secret := l.nextLogin(t)
		if err := l.holdSession(user, secret, hold); err != nil {
			t.Fatalf("could not hold an interactive session open, so no watchdog window existed: %v", err)
		}

		// Nothing to wait for: "no WATCHDOG arrived" is the measurement, so this
		// only needs a window wide enough that a late record cannot be mistaken
		// for an absent one, and the spool drained into the log before counting.
		recs := l.drainRecords(off, 30*time.Second)
		acct := recordsOfEvent(recs, "account")
		if len(acct) == 0 {
			t.Fatalf("no accounting record of any kind arrived during a %v session, so whether this platform "+
				"sends WATCHDOG could not be measured:%s", hold, summarize(recs))
		}

		var watchdogs []map[string]any
		withArgs := 0
		for _, r := range acct {
			if str(r, "flags") != "watchdog" {
				continue
			}
			watchdogs = append(watchdogs, r)
			if rec := sub(r, "record"); rec != nil && len(strs(rec, "raw")) > 2 {
				withArgs++
			}
		}

		var gaps []string
		var prev time.Time
		for _, r := range watchdogs {
			ts, ok := recTime(r)
			if !ok {
				continue
			}
			if !prev.IsZero() {
				gaps = append(gaps, ts.Sub(prev).Round(time.Second).String())
			}
			prev = ts
		}

		summary := fmt.Sprintf("**%d WATCHDOG records** over a %v idle interactive session (login at %s UTC).",
			len(watchdogs), hold, t0.UTC().Format(time.RFC3339))
		if len(watchdogs) == 0 {
			summary += "\n\nThis platform sent no WATCHDOG at all in that window. It did send accounting: " +
				accountFlagsTable(acct)
		} else {
			summary += fmt.Sprintf("\n\n- Carrying arguments (more than two AV pairs): %d of %d.\n- Intervals between them: %s.\n\n"+
				"First WATCHDOG's raw AV pairs:\n\n```\n%s\n```\n\nAll accounting seen in the window: %s",
				withArgs, len(watchdogs), strings.Join(gaps, ", "), strings.Join(rawOf(watchdogs[0]), "\n"), accountFlagsTable(acct))
		}
		l.result(t, "L5", "Which platforms send accounting WATCHDOG, how often, and with or without arguments.", summary)
	})
}

func recordsOfEvent(recs []map[string]any, event string) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if str(r, "event") == event {
			out = append(out, r)
		}
	}
	return out
}

func rawOf(r map[string]any) []string {
	rec := sub(r, "record")
	if rec == nil {
		return nil
	}
	return strs(rec, "raw")
}

func accountFlagsTable(acct []map[string]any) string {
	counts := map[string]int{}
	for _, r := range acct {
		counts[str(r, "flags")]++
	}
	var parts []string
	for _, f := range []string{"start", "watchdog", "stop", "unknown"} {
		if counts[f] > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", f, counts[f]))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// L6: how reliably and how late exec accounting START and STOP arrive.
func TestL6AccountingLatency(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		stop := l.capture(t, "L6")
		defer stop()
		off := l.mark()

		t0 := time.Now()
		user, secret := l.nextLogin(t)
		if _, err := l.login(user, secret, "show version"); err != nil {
			t.Fatalf("SSH login failed, so there was no session to account for: %v", err)
		}
		t1 := time.Now() // the SSH connection is closed by the time login returns

		recs := l.waitForRecords(off, 60*time.Second, func(rs []map[string]any) bool {
			s, st := execStartStop(rs, l.p.name)
			return !s.IsZero() && !st.IsZero()
		})
		acct := recordsOfEvent(recs, "account")
		if len(acct) == 0 {
			t.Fatalf("no accounting record arrived within 60s of a complete login and logout, so neither the "+
				"reliability nor the latency of exec START and STOP could be measured:%s", summarize(recs))
		}

		start, stopT := execStartStop(recs, l.p.name)
		startNote, stopNote := "**never arrived**", "**never arrived**"
		if !start.IsZero() {
			startNote = fmt.Sprintf("arrived %v after the login began", start.Sub(t0).Round(time.Millisecond))
		}
		if !stopT.IsZero() {
			stopNote = fmt.Sprintf("arrived %v after the session closed", stopT.Sub(t1).Round(time.Millisecond))
		}

		obs := fmt.Sprintf("One SSH login that ran `show version` and disconnected. Login began %s UTC; the "+
			"connection closed %s UTC.\n\n- Exec **START**: %s.\n- Exec **STOP**: %s.\n\n"+
			"Accounting records in the window: %s (an exec record is one that carries no command at all, as on "+
			"EOS, or carries only `login` or `logout`, as on Junos; anything else is a per-command record).\n\n"+
			"All accounting AV pairs, in arrival order:\n\n```\n%s\n```\n\n"+
			"Retry-to-the-next-server behavior is not measured here: this lab has a single TACACS+ server, so "+
			"nothing in this run shows what the device does when one is unreachable.",
			t0.UTC().Format(time.RFC3339Nano), t1.UTC().Format(time.RFC3339Nano),
			startNote, stopNote, accountFlagsTable(acct), acctDump(acct))
		l.result(t, "L6", "How reliably and how late exec accounting START and STOP arrive, and whether a device "+
			"retries accounting to the same server or fails to the next.", obs)
	})
}

// execStartStop returns the first exec START and the first exec STOP, using the
// platform's rule for what counts as an exec record.
func execStartStop(recs []map[string]any, platform string) (start, stop time.Time) {
	for _, r := range recs {
		if str(r, "event") != "account" {
			continue
		}
		rec := sub(r, "record")
		if rec == nil || !isExecRecord(rec, platform) {
			continue
		}
		ts, ok := recTime(r)
		if !ok {
			continue
		}
		switch str(r, "flags") {
		case "start":
			if start.IsZero() {
				start = ts
			}
		case "stop":
			if stop.IsZero() {
				stop = ts
			}
		}
	}
	return start, stop
}

// isExecRecord says whether an accounting record describes the session rather
// than a command the operator typed. The rule is per platform because the
// devices disagree about how a session record looks.
//
// Everywhere, a record with no command vector is an exec record. On EOS that is
// the whole rule: its session START and STOP carry `task_id`, `service` and
// timestamps and nothing else.
//
// Junos does not do that. It sends the session START and STOP as `cmd=login`
// and `cmd=logout`, which parse into a command vector like any other, and
// reading those as per-command records made the L6 note announce that exec
// START and STOP "never arrived" immediately above the two records that were
// exactly that.
//
// That extra rule is confined to Junos on purpose. `logout` IS a command an
// operator can type on EOS, so applying it everywhere would mean a future test
// that types `logout` silently has it counted as a session marker. Nothing
// types it today — L6 runs `show version` — but the reasoning only ever held
// for one vendor, so neither should the code.
func isExecRecord(rec map[string]any, platform string) bool {
	if rec["vector"] == nil {
		return true
	}
	if !strings.HasPrefix(platform, "juniper_") {
		return false
	}
	v := strs(rec, "vector")
	return len(v) == 1 && (v[0] == "login" || v[0] == "logout")
}

func acctDump(acct []map[string]any) string {
	var b strings.Builder
	for _, r := range acct {
		fmt.Fprintf(&b, "%s flags=%s attribution=%s raw=%v\n", str(r, "ts"), str(r, "flags"), str(r, "attribution"), rawOf(r))
	}
	return strings.TrimRight(b.String(), "\n")
}

// L8: the maximum password length the platform accepts at an interactive
// prompt. A token of each length is seeded under its own username, so a device
// that truncates yields credential_mismatch against that user rather than a
// silent pass against a shorter token.
func TestL8PasswordLength(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		stop := l.capture(t, "L8")
		defer stop()

		var rows []l8Row
		longestOK := 0

		for _, n := range passwordLengths {
			pw := passwordOfLength(n)
			mustBeSeeded(t, pw)
			user := fmt.Sprintf("longpw%d", n)
			off := l.mark()
			_, err := l.login(user, pw, "show version")
			recs := l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
				return redeemFor(rs, user) != nil
			})
			r := l8Row{n: n, loginErr: err}
			if rec := redeemFor(recs, user); rec != nil {
				r.seen, r.verdict, r.reason = true, str(rec, "verdict"), str(rec, "reason")
				if r.reason == "token_redeemed" && n > longestOK {
					longestOK = n
				}
			}
			rows = append(rows, r)
		}

		anySeen := false
		for _, r := range rows {
			anySeen = anySeen || r.seen
		}
		if !anySeen {
			t.Fatalf("no redeem record arrived for any of the %d password lengths, so the device's maximum "+
				"accepted password length could not be measured", len(rows))
		}

		var table strings.Builder
		table.WriteString("| length | reached port49 | verdict | reason | SSH result |\n|---|---|---|---|---|\n")
		for _, r := range rows {
			reached, verdict, reason := "no", "—", "—"
			if r.seen {
				reached, verdict, reason = "yes", r.verdict, r.reason
			}
			ssh := "logged in"
			if r.loginErr != nil {
				ssh = "rejected"
			}
			fmt.Fprintf(&table, "| %d | %s | %s | `%s` | %s |\n", r.n, reached, verdict, reason, ssh)
		}

		longest := "**none of the lengths tested arrived intact.**"
		if longestOK > 0 {
			longest = fmt.Sprintf("**Longest password that arrived intact: %d characters.**", longestOK)
		}
		obs := fmt.Sprintf("A seeded token of each length, each under its own username, presented at the SSH "+
			"password prompt:\n\n%s\n%s\n\n"+
			"How to read this: `token_redeemed` means the full password reached port49 byte for byte. "+
			"`token_not_found` means the device did send a password under this username and no seeded "+
			"token matched it, so the device altered or truncated what was typed -- each length has its "+
			"own username, so there is no earlier receipt to compare against and truncation lands here, "+
			"not on `credential_mismatch`. `credential_mismatch` would mean a second attempt under a "+
			"username that already had a receipt, which this test does not do. No record at all means the "+
			"device refused the password locally and sent nothing.\n\n"+
			"The 30-character handle the design document depends on: %s.\n\n"+
			"PAP is not measured here; this is the interactive SSH prompt only.",
			table.String(), longest, handleVerdict(rows30(rows)))
		l.result(t, "L8", "The maximum password length each platform accepts at an interactive prompt and via PAP.", obs)
	})
}

// l8Row is one password length's outcome: whether the login succeeded over SSH,
// and what port49 made of what actually arrived.
type l8Row struct {
	n        int
	loginErr error
	verdict  string
	reason   string
	seen     bool
}

func rows30(rows []l8Row) string {
	for _, r := range rows {
		if r.n == 30 {
			return r.reason
		}
	}
	return ""
}

func handleVerdict(reason string) string {
	if reason == "token_redeemed" {
		return "**accepted**"
	}
	if reason == "" {
		return "**not measured** (no record for the 30-character login)"
	}
	return fmt.Sprintf("**not accepted** (`%s`)", reason)
}

func redeemFor(recs []map[string]any, user string) map[string]any {
	for _, r := range recs {
		if str(r, "event") != "redeem" {
			continue
		}
		if s := sub(r, "session"); s != nil && str(s, "username") == user {
			return r
		}
	}
	return nil
}

// L10: whether `service` arrives as `shell` or `junos-exec`, and the exact
// spelling of every attribute on an authorization request.
func TestL10ServiceAndAttributeSpellings(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		stop := l.capture(t, "L10")
		defer stop()
		off := l.mark()

		user, secret := l.nextLogin(t)
		if _, err := l.login(user, secret, "show version"); err != nil {
			t.Fatalf("SSH login failed, so no authorization request was sent: %v", err)
		}
		recs := l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
			return len(authzRequests(rs)) > 0
		})
		reqs := authzRequests(recs)
		if len(reqs) == 0 {
			t.Fatalf("no authorization request reached port49, so neither the `service` value nor any attribute "+
				"spelling could be measured:%s", summarize(recs))
		}

		services := map[string]int{}
		names := map[string]bool{}
		var perEvent strings.Builder
		for _, r := range reqs {
			raw := strs(sub(r, "request"), "raw")
			fmt.Fprintf(&perEvent, "\n%s (%s/%s):\n", str(r, "event"), str(r, "verdict"), str(r, "reason"))
			for _, a := range raw {
				fmt.Fprintf(&perEvent, "  %s\n", a)
				k, v := splitAV(a)
				names[k] = true
				if k == "service" {
					services[v]++
				}
			}
		}

		serviceNote := "**no `service` attribute was present on any request.**"
		if len(services) > 0 {
			var parts []string
			for v, n := range services {
				parts = append(parts, fmt.Sprintf("`%s` (%d requests)", v, n))
			}
			serviceNote = "`service` arrived as " + strings.Join(parts, ", ") + "."
		}

		// Sort the bare names, then wrap. Sorting the backtick-wrapped strings
		// put `cmd-arg` before `cmd`, because `-` sorts below the backtick.
		// Presentation order only; it changes no measurement.
		var keys []string
		for k := range names {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			keys[i] = "`" + k + "`"
		}

		obs := fmt.Sprintf("One SSH login running `show version` produced %d authorization request(s).\n\n"+
			"%s\n\nAttribute names seen, exactly as spelled on the wire: %s.\n\n"+
			"Every AV pair, per request:\n\n```%s```\n\n"+
			"Only this platform's own spellings are measured here; a shipped adapter is `VERIFIED` only for "+
			"the platform its note names.",
			len(reqs), serviceNote, strings.Join(keys, ", "), perEvent.String())
		l.result(t, "L10", "Whether `service` arrives as `shell` or `junos-exec`, and the exact spelling of every "+
			"attribute in a shipped adapter.", obs)
	})
}

func authzRequests(recs []map[string]any) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		e := str(r, "event")
		if e != "authorize_session" && e != "authorize_command" {
			continue
		}
		if sub(r, "request") != nil {
			out = append(out, r)
		}
	}
	return out
}

// splitAV splits an AV pair on the first `=` or `*`, which is how the protocol
// separates a mandatory from an optional argument.
func splitAV(a string) (string, string) {
	i := strings.IndexAny(a, "=*")
	if i < 0 {
		return a, ""
	}
	return a[:i], a[i+1:]
}
