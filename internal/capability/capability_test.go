package capability

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/platform"
)

var t0 = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

type logb struct {
	recs []decision.Record
	at   time.Duration
}

func (l *logb) add(event, device, platformName, ctx string, edit func(*decision.Record)) {
	l.at += time.Second
	r := decision.Record{TS: t0.Add(l.at), Event: event, Device: &decision.Device{Name: device, Platform: platformName},
		Session: &decision.Session{CtxID: ctx}}
	if edit != nil {
		edit(&r)
	}
	l.recs = append(l.recs, r)
}

func (l *logb) command(device, ctx, verdict string, words ...string) {
	l.add(decision.EventAuthorizeCommand, device, "arista_eos", ctx, func(r *decision.Record) {
		r.Verdict, r.Request = verdict, &decision.Request{Vector: append(words, "<cr>")}
	})
}

func (l *logb) account(device, ctx, attribution string, words ...string) {
	l.add(decision.EventAccount, device, "arista_eos", ctx, func(r *decision.Record) {
		r.Flags, r.Attribution = "stop", attribution
		raw := []string{"task_id=1"}
		if len(words) > 0 {
			raw = append(raw, "cmd="+strings.Join(words, " "))
		}
		r.AcctRecord = &decision.AcctRecord{Raw: raw, Vector: words}
	})
}

var eos = []string{Session, Commands}

func TestTheMatrix(t *testing.T) {
	var l logb
	// leaf-01: sessions and commands, and every command it accounted for
	// was asked about.
	l.add(decision.EventAuthorizeSession, "leaf-01", "arista_eos", "c1", nil)
	l.command("leaf-01", "c1", decision.VerdictPermit, "show", "version")
	l.account("leaf-01", "c1", "resolved", "show", "version", "<cr>")
	// leaf-04: sessions, and commands in accounting nobody asked about.
	l.add(decision.EventAuthorizeSession, "leaf-04", "arista_eos", "c4", nil)
	for _, cmd := range []string{"show interfaces", "show version", "ping 10.0.0.1", "show version"} {
		l.account("leaf-04", "c4", "resolved", strings.Fields(cmd)...)
	}
	l.account("leaf-04", "", "unattributed", "show", "clock")
	devices := []Device{{Name: "leaf-01", Platform: "arista_eos", Supports: eos},
		{Name: "leaf-04", Platform: "arista_eos", Supports: eos},
		{Name: "ntp-01", Platform: "meinberg", Supports: []string{Session}},
		{Name: "xr-edge-1", Platform: "cisco_ios_xr", Supports: eos, Quarantine: "@management undefined"}}
	rep := Infer(l.recs, devices, Options{})
	if !rep.Qualified() || len(rep.Rows) != 4 {
		t.Fatalf("%+v", rep)
	}
	if r := rep.Rows[0]; !reflect.DeepEqual(r.Observed, eos) || len(r.Warnings) != 0 {
		t.Errorf("leaf-01: %+v", r)
	}
	if r := rep.Rows[1]; r.Unauthorized != 3 || !reflect.DeepEqual(r.Examples, []string{"ping 10.0.0.1", "show interfaces",
		"show version"}) || r.Unattributed != 1 || len(r.Warnings) != 1 {
		t.Errorf("leaf-04: %+v", r)
	}
	if r := rep.Rows[2]; len(r.Warnings) != 0 || !reflect.DeepEqual(r.Notes,
		[]string{"never seen: no TACACS+ record in the window, so nothing is inferred"}) {
		t.Errorf("ntp-01: %+v", r)
	}
	if r := rep.Rows[3]; len(r.Warnings) != 0 {
		t.Errorf("a quarantined device is not reported unseen: %+v", r)
	}
}

// Configuration entries no authorization followed, over a window, say
// config-commands is probably off; one session that left at once does not.
func TestConfigCommandsProbablyOff(t *testing.T) {
	var l logb
	for i, ctx := range []string{"a", "b", "c", "d", "e"} {
		l.command("leaf-04", ctx, decision.VerdictPermit, "configure", "terminal")
		if i == 0 {
			l.command("leaf-04", ctx, decision.VerdictPermit, "interface", "Ethernet1")
		}
		l.account("leaf-04", ctx, "resolved") // the exec STOP
	}
	devices := []Device{{Name: "leaf-04", Platform: "arista_eos", Supports: eos}}
	r := Infer(l.recs, devices, Options{}).Rows[0]
	if r.ConfigEntered != 5 || r.ConfigSilent != 4 || !strings.Contains(strings.Join(r.Warnings, ";"), "config-commands probably off") ||
		!reflect.DeepEqual(r.Observed, []string{Commands, ConfigCommands}) {
		t.Fatalf("%+v", r)
	}
	r = Infer(l.recs[:3], devices, Options{}).Rows[0]
	if len(r.Warnings) != 0 {
		t.Fatalf("one entry is not a window: %+v", r)
	}
}

// A gap in the accounting stream qualifies the window; the window bounds
// what is read; a session-only platform's commands are never reconciled.
func TestGapsWindowsAndSessionOnly(t *testing.T) {
	var l logb
	l.account("srx-1", "s1", "resolved", "show", "version")
	l.add(decision.EventAccountGap, "", "", "", func(r *decision.Record) {
		r.Device, r.Session, r.Gap = nil, nil, &decision.Gap{Stage: "drain_unparseable", Records: 2}
	})
	devices := []Device{{Name: "srx-1", Platform: "juniper_junos", Supports: []string{Session}}}
	rep := Infer(l.recs, devices, Options{})
	if rep.Qualified() || rep.Rows[0].Unauthorized != 0 {
		t.Fatalf("%+v", rep)
	}
	if rep := Infer(l.recs, devices, Options{From: t0.Add(90 * time.Minute)}); len(rep.Gaps) != 0 {
		t.Fatalf("window: %+v", rep)
	}
}

// An example is echoed from the log, so it goes through the platform's
// redaction first: a secret typed on a device that never asked about it is
// no safer in a report than in a log (spec §5.8).
func TestExamplesAreRedacted(t *testing.T) {
	var l logb
	l.add(decision.EventAuthorizeSession, "leaf-04", "arista_eos", "c4", nil)
	l.account("leaf-04", "c4", "resolved", "username", "bob", "secret", "Hunter2")
	devices := []Device{{Name: "leaf-04", Platform: "arista_eos", Supports: eos}}
	r := Infer(l.recs, devices, Options{}).Rows[0]
	if r.Unauthorized != 1 || len(r.Examples) != 1 || !strings.HasPrefix(r.Examples[0], "username bob secret ") {
		t.Fatalf("%+v", r)
	}
	if s := strings.ToLower(fmt.Sprintf("%+v", r)); strings.Contains(s, "hunter2") {
		t.Fatalf("the secret reached the report: %s", s)
	}
}

// A gap is charged to when its records arrived, since, through when it was
// written: one written after the window for drops inside it qualifies the
// window, and one whose drops all came before it does not. Every row of an
// unqualified report says so, and its reconciliation says "possibly".
func TestGapsOverlapTheWindowBySince(t *testing.T) {
	var l logb
	l.add(decision.EventAuthorizeSession, "leaf-04", "arista_eos", "c4", nil)
	l.account("leaf-04", "c4", "resolved", "show", "clock")
	l.add(decision.EventAccountGap, "", "", "", func(r *decision.Record) {
		r.TS = t0.Add(3 * time.Hour) // drained hours late
		r.Device, r.Session, r.Gap = nil, nil, &decision.Gap{Stage: "drain_unparseable", Records: 2,
			Since: decision.FormatTime(t0.Add(30 * time.Minute))}
	})
	devices := []Device{{Name: "leaf-04", Platform: "arista_eos", Supports: eos},
		{Name: "leaf-05", Platform: "arista_eos", Supports: eos}}
	rep := Infer(l.recs, devices, Options{To: t0.Add(time.Hour)})
	if rep.Qualified() || len(rep.Gaps) != 1 {
		t.Fatalf("a late-written gap for drops in the window: %+v", rep)
	}
	for _, r := range rep.Rows {
		if !slices.ContainsFunc(r.Notes, func(n string) bool { return strings.Contains(n, "account_gap") }) {
			t.Errorf("row does not say the window is qualified: %+v", r)
		}
	}
	if w := strings.Join(rep.Rows[0].Warnings, ";"); !strings.Contains(w, "possibly") {
		t.Errorf("an unqualified reconciliation is stated as fact: %q", w)
	}
	if rep := Infer(l.recs, devices, Options{From: t0.Add(4 * time.Hour)}); !rep.Qualified() {
		t.Fatalf("a gap written before the window: %+v", rep)
	}
	if rep := Infer(l.recs, devices, Options{From: t0.Add(2 * time.Hour)}); rep.Qualified() {
		t.Fatalf("a gap whose drops span into the window: %+v", rep)
	}
	rep = Infer(l.recs[:2], devices, Options{})
	if !rep.Qualified() || strings.Contains(strings.Join(rep.Rows[0].Warnings, ";"), "possibly") ||
		len(rep.Rows[0].Notes) != 0 {
		t.Fatalf("a whole stream: %+v", rep)
	}
}

// A command authorized just before the window and accounted just inside it
// was asked about: the From bound applies to what is judged, never to the
// authorizations that answer it, or every boundary a command straddles
// accuses a correctly configured device.
func TestAuthorizationBeforeTheWindowCounts(t *testing.T) {
	l := logb{at: time.Second}
	l.command("leaf-01", "c1", decision.VerdictPermit, "show", "tech")     // t0+2s
	l.account("leaf-01", "c1", "resolved", "show", "tech-support", "<cr>") // t0+3s
	devices := []Device{{Name: "leaf-01", Platform: "arista_eos", Supports: eos}}
	r := Infer(l.recs, devices, Options{From: t0.Add(2500 * time.Millisecond)}).Rows[0]
	if r.Unauthorized != 0 || len(r.Warnings) != 0 {
		t.Fatalf("an authorization before From was not counted: %+v", r)
	}
}

// The report's window is what was searched: the requested bounds where the
// options set them, the records' span only where they do not, and "no
// records" where neither says, never year 0001.
func TestTheWindowIsWhatWasSearched(t *testing.T) {
	var l logb
	l.add(decision.EventAuthorizeSession, "leaf-01", "arista_eos", "c1", nil) // t0+1s
	l.add(decision.EventAuthorizeSession, "leaf-01", "arista_eos", "c2", nil) // t0+2s
	devices := []Device{{Name: "leaf-01", Platform: "arista_eos", Supports: eos}}
	from, to := t0.Add(-24*time.Hour), t0.Add(time.Hour)
	if rep := Infer(l.recs, devices, Options{From: from, To: to}); !rep.From.Equal(from) || !rep.To.Equal(to) {
		t.Errorf("bounded: %v to %v", rep.From, rep.To)
	}
	if rep := Infer(l.recs, devices, Options{From: from}); !rep.From.Equal(from) || !rep.To.Equal(t0.Add(2*time.Second)) {
		t.Errorf("open after: %v to %v", rep.From, rep.To)
	}
	if w := Infer(l.recs, devices, Options{From: from}).Window(); w != decision.FormatTime(from)+" to "+
		decision.FormatTime(t0.Add(2*time.Second)) {
		t.Errorf("window: %q", w)
	}
	if w := Infer(nil, devices, Options{}).Window(); w != "no records" {
		t.Errorf("an empty log: %q", w)
	}
	if w := Infer(nil, devices, Options{From: from}).Window(); w != "no records" {
		t.Errorf("an empty log, open after: %q", w)
	}
}

// "never seen" is a device with no record at all in the window: one whose
// only records are accounting has been seen, and nothing about it is unseen.
func TestNeverSeenIsNoRecordAtAll(t *testing.T) {
	var l logb
	l.account("leaf-01", "", "system", "show", "clock")
	devices := []Device{{Name: "leaf-01", Platform: "arista_eos", Supports: eos}}
	if r := Infer(l.recs, devices, Options{}).Rows[0]; len(r.Notes) != 0 || r.System != 1 {
		t.Fatalf("%+v", r)
	}
}

// A device only the broker's mints name never sent a TACACS+ packet: it is
// never seen, and the note says tokens were minted for it, the one fact
// worth knowing (its AAA may not point at port49). It stays a note.
func TestMintsAloneAreNeverSeen(t *testing.T) {
	var l logb
	for range 2 {
		l.add(decision.EventMint, "xe1", "lab", "", func(r *decision.Record) {
			r.Session, r.Verdict = nil, decision.VerdictPermit
			r.Mint = &decision.Mint{TokenSHA256: []string{"a", "b"}}
		})
	}
	devices := []Device{{Name: "xe1", Platform: "cisco_iosxe", Supports: eos}}
	r := Infer(l.recs, devices, Options{}).Rows[0]
	if len(r.Warnings) != 0 || !slices.Equal(r.Notes,
		[]string{"never seen: no TACACS+ record in the window, so nothing is inferred (4 tokens minted for it)"}) {
		t.Fatalf("%+v", r)
	}
}

// The Redactor is the one a caller passes, not only the built-in patterns:
// a policy's own pattern hides its secret in an example, for a consumer of
// Report with no redacting writer in front of it (task 18 review M1).
func TestExamplesUseTheCallersRedactor(t *testing.T) {
	var l logb
	l.add(decision.EventAuthorizeSession, "leaf-04", "arista_eos", "c4", nil)
	l.account("leaf-04", "c4", "resolved", "crypto", "key", "psk", "Hunter2")
	devices := []Device{{Name: "leaf-04", Platform: "arista_eos", Supports: eos}}
	psk := func(string) []platform.Redaction { return []platform.Redaction{{Match: []string{"**"}, After: "psk"}} }
	r := Infer(l.recs, devices, Options{Redactor: psk}).Rows[0]
	if len(r.Examples) != 1 || r.Examples[0] != "crypto key psk "+platform.Redacted {
		t.Fatalf("%+v", r)
	}
}

// Where one configuration entry in five saw a request after it, the matrix
// shows config_commands observed, and the warning says what that one was
// likely to be, so the row does not contradict itself.
func TestProbablyOffNamesTheEntriesThatWereFollowed(t *testing.T) {
	var l logb
	for i, ctx := range []string{"a", "b", "c", "d", "e"} {
		l.command("leaf-04", ctx, decision.VerdictPermit, "configure", "terminal")
		if i == 0 {
			l.command("leaf-04", ctx, decision.VerdictPermit, "write", "memory")
		}
		l.account("leaf-04", ctx, "resolved")
	}
	devices := []Device{{Name: "leaf-04", Platform: "arista_eos", Supports: eos}}
	r := Infer(l.recs, devices, Options{}).Rows[0]
	if w := strings.Join(r.Warnings, ";"); !strings.Contains(w, "4 of 5") || !strings.Contains(w, "the 1 that did") {
		t.Fatalf("%q", w)
	}
}

// An entry whose session's STOP never arrives, because it crosses the
// window's end or a gap took it, is silent: nothing after it answered.
func TestAnEntryWithNoStopIsSilent(t *testing.T) {
	var l logb
	for _, ctx := range []string{"a", "b", "c", "d", "e"} {
		l.command("leaf-04", ctx, decision.VerdictPermit, "configure", "terminal")
	}
	devices := []Device{{Name: "leaf-04", Platform: "arista_eos", Supports: eos}}
	if r := Infer(l.recs, devices, Options{}).Rows[0]; r.ConfigEntered != 5 || r.ConfigSilent != 5 {
		t.Fatalf("%+v", r)
	}
}

// The session ends at its platform's exec STOP, by the same definition the
// join uses: Junos's carries cmd=logout, and a request after it in a reused
// context does not answer an entry before it.
func TestTheSessionEndsAtThePlatformsExecStop(t *testing.T) {
	var l logb
	l.command("srx-1", "a", decision.VerdictPermit, "configure")
	l.account("srx-1", "a", "resolved", "logout")
	l.command("srx-1", "a", decision.VerdictPermit, "show", "version")
	devices := []Device{{Name: "srx-1", Platform: "juniper_junos", Supports: eos}}
	if r := Infer(l.recs, devices, Options{}).Rows[0]; r.ConfigSilent != 1 {
		t.Fatalf("%+v", r)
	}
}

// Row and Report marshal with snake_case keys, as all port49 data does.
func TestReportKeysAreSnakeCase(t *testing.T) {
	var l logb
	l.add(decision.EventAuthorizeSession, "leaf-01", "arista_eos", "c1", nil)
	devices := []Device{{Name: "leaf-01", Platform: "arista_eos", Supports: eos}}
	b, err := json.Marshal(Infer(l.recs, devices, Options{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{`"from"`, `"rows"`, `"device"`, `"platform"`, `"observed"`, `"config_entered"`,
		`"config_silent"`, `"unattributed"`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("no %s in %s", k, b)
		}
	}
}
