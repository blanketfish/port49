package capability

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/decision"
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
		[]string{"never seen: no record in the window, so nothing is inferred"}) {
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
