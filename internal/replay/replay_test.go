package replay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/daemon/acct"
	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/author"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// daemonLog runs real authorizations through the daemon's handler and the
// engine, and returns the log they wrote with the blob event the broker would
// have written first: the corpus spec §14's replay assertions run over.
func daemonLog(t *testing.T) (string, string) {
	t.Helper()
	b := engine.Blob{Bundle: "sha256:policy", Platform: "arista_eos",
		Normalize: engine.Normalize{PipeToken: "|", StripCR: true}, Privilege: "admin",
		Attributes: []string{"priv-lvl=15", "home-directory*/home/{username}"},
		Rules: []engine.Rule{
			{Verdict: engine.Permit, Rule: "copy **", Role: "net_operator"},
			{Verdict: engine.Permit, Rule: "show **", Role: "read_only"},
			{Verdict: engine.Deny, Rule: "* * /^tftp:/", Role: "no_exfil"},
		},
		Pipe: []string{"include **"}}
	body, hash, err := engine.Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	sink := decision.NewJSONLines(&log)
	sink.Emit(decision.Record{TS: time.Now(), Event: decision.EventBlob, Blob: &decision.Blob{Hash: hash, Body: body}})
	st := memory.New(time.Now)
	st.PutBlob(context.Background(), hash, body, time.Hour)
	st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "ctx1", Username: "alice", Principal: "user:alice@example.com", PrivLvl: 15,
			BlobHash: hash}, time.Hour)
	m := metrics.New(prometheus.NewRegistry())
	h := author.New(st, &author.Engine{Store: st, Metrics: m}, sink, m, time.Now, platform.Defaults(),
		time.Hour, time.Minute, time.Hour)
	peer := authen.Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "arista_eos"}
	for _, line := range []string{
		"",                                      // session: context_matched
		"show version",                          // permit_dominates
		"copy running-config tftp://10.9.9.9/x", // no_permit_dominates_deny
		"configure terminal",                    // no_rule_matched
		"show run | redirect ftp://x",           // pipe_stage_denied
	} {
		r := wire.AuthorRequest{PrivLvl: 15, User: []byte("alice"), Port: []byte("vty0"),
			Args: [][]byte{[]byte("service=shell"), []byte("cmd=")}}
		if f := strings.Fields(line); len(f) > 0 {
			r.Args = [][]byte{[]byte("service=shell"), []byte("cmd=" + f[0])}
			for _, a := range f[1:] {
				r.Args = append(r.Args, []byte("cmd-arg="+a))
			}
			r.Args = append(r.Args, []byte("cmd-arg=<cr>"))
		}
		h.Handle(context.Background(), peer, r)
	}
	// A record decided before any policy ran is in the log and not replayed.
	h.Handle(context.Background(), peer, wire.AuthorRequest{User: []byte("carol"),
		Args: [][]byte{[]byte("service=shell"), []byte("cmd=show")}})
	return log.String(), hash
}

func replayAll(t *testing.T, log string) []Result {
	t.Helper()
	res, err := Replay(strings.NewReader(log), 0)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// Every record in the corpus replays against its named blob and reproduces
// the logged verdict, reason and matched rules (spec §14, "Replay agreement").
func TestEveryRecordReplaysToTheSameDecision(t *testing.T) {
	log, _ := daemonLog(t)
	all := replayAll(t, log)
	// carol's context_missing was decided before policy ran: it is counted,
	// not replayed.
	if last := all[len(all)-1]; last.Status != Skipped || last.Reason != decision.ContextMissing {
		t.Fatalf("the context_missing record: %+v", last)
	}
	res := all[:len(all)-1]
	if len(res) != 5 {
		t.Fatalf("five decisions consulted the blob, replayed %d: %+v", len(res), res)
	}
	for _, r := range res {
		if r.Status != Agree {
			t.Errorf("line %d (%s): %s %s", r.Line, r.Event, r.Status, r.Detail)
		}
	}
	// A blob event after the records that name it still replays them.
	lines := strings.Split(strings.TrimSpace(log), "\n")
	late := replayAll(t, strings.Join(append(lines[1:], lines[0]), "\n"))
	for _, r := range late[:5] {
		if r.Status != Agree {
			t.Errorf("blob last: line %d (%s): %s %s", r.Line, r.Event, r.Status, r.Detail)
		}
	}
	one, err := Replay(strings.NewReader(log), res[2].Line)
	if err != nil || len(one) != 1 || one[0].Line != res[2].Line {
		t.Fatalf("one line: %+v %v", one, err)
	}
}

// A record whose verdict was edited, whose matched rule was edited, or whose
// blob was substituted is reported as divergent rather than silently
// accepted; a record whose blob the log never carried cannot be verified
// (spec §14, "Replay divergence is detected").
func TestTamperingIsDetected(t *testing.T) {
	log, hash := daemonLog(t)
	lines := strings.Split(strings.TrimSpace(log), "\n")
	dropPolicy := func(i int) string {
		var m map[string]any
		if err := json.Unmarshal([]byte(lines[i]), &m); err != nil || m["policy"] == nil {
			t.Fatalf("line %d: %v %s", i, err, lines[i])
		}
		delete(m, "policy")
		b, _ := json.Marshal(m)
		out := append([]string(nil), lines...)
		out[i] = string(b)
		return strings.Join(out, "\n")
	}
	edit := func(i int, old, new string) string {
		out := append([]string(nil), lines...)
		if !strings.Contains(out[i], old) {
			t.Fatalf("line %d has no %q: %s", i, old, out[i])
		}
		out[i] = strings.Replace(out[i], old, new, 1)
		return strings.Join(out, "\n")
	}
	for name, tt := range map[string]struct {
		log    string
		status Status
		detail string
	}{
		"an edited verdict": {edit(3, `"verdict":"deny","reason":"no_permit_dominates_deny"`,
			`"verdict":"permit","reason":"permit_dominates"`), Diverge, "logged permit permit_dominates, replayed deny"},
		"an edited rule": {edit(3, `"role":"no_exfil"`, `"role":"read_only"`), Diverge, "matched rules do not"},
		"an edited session reply": {edit(1, `"home-directory*/home/alice"`, `"home-directory*/home/mallory"`), Diverge,
			"session attributes do not"},
		"a substituted blob": {edit(0, `"role":"no_exfil"`, `"role":"nobody"`), Diverge, "does not hash to its name"},
		"a missing blob":     {strings.Join(lines[1:], "\n"), Unverifiable, "no blob event for " + hash},
		"another bundle":     {edit(2, `"bundle":"sha256:policy"`, `"bundle":"sha256:other"`), Diverge, "names bundle"},
		// Edits that would make replay pass over a record rather than
		// replay it.
		"a permit given an operational reason": {edit(3, `"verdict":"deny","reason":"no_permit_dominates_deny"`,
			`"verdict":"permit","reason":"device_quarantined"`), Diverge, "only ever a denial"},
		"a deleted policy": {dropPolicy(3), Diverge, "names no blob"},
		"a blanked blob":   {edit(3, `"blob":"`+hash+`"`, `"blob":""`), Diverge, "names no blob"},
		"an altered copy of the blob after the genuine one": {log + strings.Replace(lines[0], `"role":"no_exfil"`, `"role":"nobody"`, 1),
			Diverge, "does not hash to its name"},
	} {
		var hit bool
		for _, r := range replayAll(t, tt.log) {
			if r.Status == tt.status && strings.Contains(r.Detail, tt.detail) {
				hit = true
			}
		}
		if !hit {
			t.Errorf("%s: no %s result mentioning %q in %+v", name, tt.status, tt.detail, replayAll(t, tt.log))
		}
	}
}

// A string from the log never reaches the auditor's console as a control
// sequence.
func TestADetailCarriesNoControlCharacters(t *testing.T) {
	log, _ := daemonLog(t)
	lines := strings.Split(strings.TrimSpace(log), "\n")
	lines[3] = strings.Replace(lines[3], `"verdict":"deny"`, `"verdict":"\u001b[2J\u009b"`, 1)
	for _, r := range replayAll(t, strings.Join(lines, "\n")) {
		if strings.ContainsAny(r.Detail, "\x1b\u009b") {
			t.Fatalf("line %d: %q", r.Line, r.Detail)
		}
	}
}

// A line too long to be a record says which line it was.
func TestAnOverlongLineNamesItsLine(t *testing.T) {
	log := "{\"ts\":\"2026-09-23T00:00:00.000Z\",\"event\":\"mint\"}\n" + strings.Repeat("x", 17<<20) + "\n"
	if _, err := Replay(strings.NewReader(log), 0); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("%v", err)
	}
}

// A line that is not a record — a write torn by a full disk, which the log
// then writes again whole, or an edit — diverges and the rest of the log is
// still replayed: one bad line does not make the log unreplayable.
func TestALineThatIsNotARecordDivergesAndTheRestReplays(t *testing.T) {
	log, _ := daemonLog(t)
	lines := strings.Split(log, "\n")
	torn := lines[2][:len(lines[2])/2]
	lines = append(lines[:2], append([]string{torn}, lines[2:]...)...)
	res := replayAll(t, strings.Join(lines, "\n"))
	i := slices.IndexFunc(res, func(r Result) bool { return r.Line == 3 })
	if i < 0 || res[i].Status != Diverge || !strings.Contains(res[i].Detail, "not a decision record: truncated or altered") {
		t.Fatalf("the torn line: %+v", res)
	}
	agree := 0
	for _, r := range res[i+1:] {
		if r.Status == Agree {
			agree++
		}
	}
	if agree == 0 {
		t.Fatalf("nothing after the torn line replayed: %+v", res)
	}
	if one, err := Replay(strings.NewReader(strings.Join(lines, "\n")), 3); err != nil || len(one) != 1 || one[0].Status != Diverge {
		t.Fatalf("--line on the torn line: %+v %v", one, err)
	}
}

// A record redacted before it was written (spec §5.8) does not carry the
// command it decided, so the replay says so rather than claim an agreement
// over the redacted words.
func TestARedactedRecordIsUnverifiable(t *testing.T) {
	log, _ := daemonLog(t)
	lines := strings.Split(strings.TrimSpace(log), "\n")
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[2]), &rec); err != nil {
		t.Fatal(err)
	}
	rec["request"].(map[string]any)["redacted"] = true
	edited, _ := json.Marshal(rec)
	lines[2] = string(edited)
	res := replayAll(t, strings.Join(lines, "\n"))
	if r := res[1]; r.Status != Unverifiable || !strings.Contains(r.Detail, "redacted before it was written") {
		t.Fatalf("%+v", r)
	}
}

// A secret typed into a command is decided as sent and written nowhere: not
// in the accounting spool file, not in the decision log, not in the denial's
// server_msg, and not in what a replay of that log reports (spec §5.7, §5.8).
func TestATypedSecretIsWrittenNowhere(t *testing.T) {
	const secret = "Hunter2"
	b := engine.Blob{Bundle: "sha256:policy", Platform: "arista_eos",
		Normalize: engine.Normalize{PipeToken: "|", StripCR: true}, Privilege: "admin",
		Rules: []engine.Rule{
			{Verdict: engine.Permit, Rule: "username **", Role: "net_admin"},
			{Verdict: engine.Permit, Rule: "enable **", Role: "net_admin"},
			{Verdict: engine.Deny, Rule: "username * secret **", Role: "no_backdoor"},
		}}
	body, hash, err := engine.Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	sink := decision.NewJSONLines(&log)
	sink.Emit(decision.Record{TS: time.Now(), Event: decision.EventBlob, Blob: &decision.Blob{Hash: hash, Body: body}})
	st := memory.New(time.Now)
	st.PutBlob(context.Background(), hash, body, time.Hour)
	st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "ctx1", Username: "alice", Principal: "user:alice@example.com", PrivLvl: 15,
			BlobHash: hash}, time.Hour)
	m := metrics.New(prometheus.NewRegistry())
	h := author.New(st, &author.Engine{Store: st, Metrics: m}, sink, m, time.Now, platform.Defaults(),
		time.Hour, time.Minute, time.Hour)
	spoolPath := filepath.Join(t.TempDir(), "spool.jsonl")
	sp, err := acct.NewSpool(16, spoolPath, decision.NewJSONLines(&bytes.Buffer{}), m)
	if err != nil {
		t.Fatal(err)
	}
	ah := acct.New(st, sp, m, time.Now, nil)
	peer := authen.Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "arista_eos"}

	var msgs []string
	for _, line := range []string{"username bob secret 0 " + secret, "enable secret 0 " + secret} {
		args := []string{"service=shell"}
		for i, w := range strings.Fields(line) {
			if i == 0 {
				args = append(args, "cmd="+w)
			} else {
				args = append(args, "cmd-arg="+w)
			}
		}
		args = append(args, "cmd-arg=<cr>")
		r := wire.AuthorRequest{PrivLvl: 15, User: []byte("alice"), Port: []byte("vty0")}
		a := wire.AcctRequest{Flags: wire.AcctFlagStop, PrivLvl: 15, User: []byte("alice"), Port: []byte("vty0")}
		for _, arg := range args {
			r.Args, a.Args = append(r.Args, []byte(arg)), append(a.Args, []byte(arg))
		}
		msgs = append(msgs, string(h.Handle(context.Background(), peer, r).ServerMsg))
		ah.Handle(context.Background(), peer, a)
	}

	if msgs[0] == "" || strings.Contains(strings.Join(msgs, "\n"), secret) {
		t.Fatalf("server_msg: %q", msgs)
	}
	lines := strings.Split(strings.TrimSpace(log.String()), "\n")
	if len(lines) != 3 || strings.Contains(strings.Join(lines[1:], "\n"), secret) {
		t.Fatalf("the decision log: %s", log.String())
	}
	spooled, err := os.ReadFile(spoolPath)
	if err != nil || strings.Contains(string(spooled), secret) || strings.Count(string(spooled), "\n") != 2 {
		t.Fatalf("the spool file: %s %v", spooled, err)
	}
	res := replayAll(t, log.String())
	if len(res) != 2 {
		t.Fatalf("%+v", res)
	}
	for _, r := range res {
		if r.Status != Unverifiable || strings.Contains(fmt.Sprintf("%+v", r), secret) {
			t.Fatalf("replay: %+v", r)
		}
	}
}

// A blob event whose rule text was redacted before it was logged (spec §5.8)
// is not the blob its hash names: every record naming it is unverifiable,
// the event itself is no divergence, and a verbatim copy of the blob read
// before them, where the log has one, replays them as ever.
func TestARedactedBlobEventLeavesItsRecordsUnverifiable(t *testing.T) {
	log, hash := daemonLog(t)
	lines := strings.Split(strings.TrimSpace(log), "\n")
	var rec decision.Record
	if err := rec.UnmarshalJSON([]byte(lines[0])); err != nil {
		t.Fatal(err)
	}
	verbatim := lines[0]
	rec.Blob.Body = []byte(strings.Replace(string(rec.Blob.Body), "tftp", platform.Redacted, 1))
	rec.Blob.Redacted = true
	edited, _ := json.Marshal(rec)
	lines[0] = string(edited)
	res := replayAll(t, strings.Join(lines, "\n"))
	for _, r := range res[:len(res)-1] {
		if r.Event == decision.EventBlob || r.Status != Unverifiable || !strings.Contains(r.Detail, "redacted") ||
			!strings.Contains(r.Detail, hash) {
			t.Fatalf("%+v", r)
		}
	}
	for _, r := range replayAll(t, strings.Join(append([]string{verbatim}, lines...), "\n"))[:len(res)-1] {
		if r.Status != Agree {
			t.Fatalf("a verbatim copy replays: %+v", r)
		}
	}
}
