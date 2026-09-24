package replay

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

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
	res := replayAll(t, log)
	if len(res) != 5 {
		t.Fatalf("five decisions consulted the blob, replayed %d: %+v", len(res), res)
	}
	for _, r := range res {
		if r.Status != Agree {
			t.Errorf("line %d (%s): %s %s", r.Line, r.Event, r.Status, r.Detail)
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

// A decision log is JSON lines and nothing else.
func TestALineThatIsNotARecordIsAnError(t *testing.T) {
	if _, err := Replay(strings.NewReader("{\"ts\":\"2026-09-23T00:00:00.000Z\",\"event\":\"mint\"}\nnot json\n"), 0); err == nil ||
		!strings.Contains(err.Error(), "line 2") {
		t.Fatalf("%v", err)
	}
}
