package acct

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

var peer = authen.Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "arista_eos"}

// setup hands back the store as well as the log: the annotation these tests
// check is a write to the context, not a field on the record, so a test that
// can only read the log cannot see it at all.
//
// `test_system_users` is a platform name that exists only in the map this
// handler is given. Nothing registers it anywhere, the shipped table stays
// empty (internal/platform), and the rule is still exercised.
func setup(t *testing.T) (*Handler, *memory.Store, *bytes.Buffer, func()) {
	t.Helper()
	st := memory.New(time.Now)
	st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "ctx1", Principal: "user:alice@example.com", Username: "alice", Port: "ssh"}, time.Hour)
	out := &bytes.Buffer{}
	sp, err := NewSpool(16, filepath.Join(t.TempDir(), "o.jsonl"), decision.NewJSONLines(out), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sp.Run(ctx); close(done) }()
	h := New(st, sp, metrics.New(prometheus.NewRegistry()), time.Now, time.Hour,
		map[string][]string{"test_system_users": {"root"}})
	return h, st, out, func() { cancel(); <-done }
}

func acct(flags uint8, user, port string, args ...string) wire.AcctRequest {
	r := wire.AcctRequest{Flags: flags, AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 15, AuthenType: wire.AuthenTypeASCII,
		Service: wire.AuthenServiceLogin, User: []byte(user), Port: []byte(port), RemAddr: []byte("198.51.100.4")}
	for _, a := range args {
		r.Args = append(r.Args, []byte(a))
	}
	return r
}

func TestCommandStopIsResolvedAndCRStripped(t *testing.T) {
	h, _, out, stop := setup(t)
	reply := h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "alice", "vty0",
		"task_id=43", "service=shell", "cmd=show", "cmd-arg=running-config", "cmd-arg=<cr>", "start_time=1757041502", "stop_time=1757041502"))
	stop()
	if reply.Status != wire.AcctStatusSuccess {
		t.Fatalf("%+v", reply)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &m); err != nil {
		t.Fatal(err)
	}
	rec := m["record"].(map[string]any)
	if m["event"] != "account" || m["flags"] != "stop" || m["attribution"] != "resolved" || m["task_id"] != "43" ||
		m["principal"] != "user:alice@example.com" || m["session"].(map[string]any)["ctx_id"] != "ctx1" {
		t.Fatalf("%v", m)
	}
	if raw := rec["raw"].([]any); raw[len(raw)-1] != "stop_time=1757041502" || len(raw) != 7 {
		t.Fatalf("raw %v", raw)
	}
	if vec := rec["vector"].([]any); len(vec) != 2 || vec[1] != "running-config" {
		t.Fatalf("vector %v", vec)
	}
	if rec["stop_time"].(float64) != 1757041502 {
		t.Fatalf("%v", rec)
	}
}

func TestUnattributedIsRecordedNotDiscarded(t *testing.T) {
	h, _, out, stop := setup(t)
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStart, "bob", "vty0", "task_id=9", "service=shell", "cmd="))
	stop()
	var m map[string]any
	json.Unmarshal([]byte(strings.TrimSpace(out.String())), &m)
	if m["attribution"] != "unattributed" || m["session"].(map[string]any)["ctx_id"] != "" {
		t.Fatalf("%v", m)
	}
}

// TestSpoolFailureAnswersErrorAndCountsIt covers the one reply accounting
// ever refuses with: the durable write failed, so the device must be told
// ERROR and retry rather than believe a record was kept. The reply carries a
// server_msg an operator can read, and the request is counted as an error.
func TestSpoolFailureAnswersErrorAndCountsIt(t *testing.T) {
	st := memory.New(time.Now)
	m := metrics.New(prometheus.NewRegistry())
	// A path under a directory that does not exist: every Offer fails the same
	// way a full or unwritable disk does.
	sp := brokenSpool(filepath.Join(t.TempDir(), "absent", "o.jsonl"), m)
	h := New(st, sp, m, time.Now, time.Hour, nil)

	reply := h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "alice", "vty0", "task_id=1", "service=shell", "cmd="))
	if reply.Status != wire.AcctStatusError {
		t.Fatalf("want AcctStatusError when the spool write fails, got %+v", reply)
	}
	if !strings.Contains(string(reply.ServerMsg), "spool") {
		t.Fatalf("the reply must say what failed, got %q", reply.ServerMsg)
	}
	if got := testutil.ToFloat64(m.Requests.WithLabelValues("acct", "error")); got != 1 {
		t.Fatalf("want requests_total{acct,error} == 1, got %v", got)
	}
}

func TestWatchdogIsRecorded(t *testing.T) {
	h, _, out, stop := setup(t)
	reply := h.Handle(context.Background(), peer, acct(wire.AcctFlagWatchdog, "alice", "vty0", "task_id=42", "service=shell", "cmd="))
	stop()
	if reply.Status != wire.AcctStatusSuccess || !strings.Contains(out.String(), `"flags":"watchdog"`) {
		t.Fatalf("%+v %s", reply, out.String())
	}
}

var junos = authen.Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "juniper_junos"}

func ctxOf(t *testing.T, st *memory.Store) store.Context {
	t.Helper()
	c, _ := st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
	return c
}

func putCtx(t *testing.T, st *memory.Store, c store.Context) {
	t.Helper()
	c.Username = "alice"
	if err := st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"}, c, time.Hour); err != nil {
		t.Fatal(err)
	}
}

func TestExecStartBindsTheDiscriminatorAndClearsClosing(t *testing.T) {
	h, st, _, stop := setup(t)
	putCtx(t, st, store.Context{CtxID: "ctx1", Principal: "user:alice@example.com", AccountingState: "closing"})
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStart, "alice", "vty0", "task_id=42", "service=shell", "cmd="))
	stop()
	if c := ctxOf(t, st); c.SessionDiscriminator != "42" || c.AccountingState != "" {
		t.Fatalf("%+v", c)
	}
}

// Junos is why the discriminator is per platform: task_id restarts at 1 per
// session there, so the adapter names session_pid instead
// (tests/lab/results/L17-juniper_vsrx.md, L17-juniper_vjunos-router.md). The
// record is `cmd=login`, which is also why exec detection is per platform:
// on Junos an exec record is not the one with no command
// (tests/lab/results/L6-juniper_vsrx.md, L6-juniper_vjunos-router.md).
func TestJunosBindsSessionPIDNotTaskID(t *testing.T) {
	h, st, _, stop := setup(t)
	h.Handle(context.Background(), junos, acct(wire.AcctFlagStart, "alice", "0", "task_id=1", "session_pid=14656", "service=shell", "cmd=login"))
	stop()
	if c := ctxOf(t, st); c.SessionDiscriminator != "14656" {
		t.Fatalf("%+v", c)
	}
}

// The AV pair as the device actually sends it. vSRX 21.4R3.15 and
// vJunos-router 23.4R2-S2.1 send `session_pid = 31050` with a space on each
// side of the `=`, while every other argument in the same record has none
// (tests/lab/results/L17-juniper_vsrx.md, L6-juniper_vsrx.md). A reader that
// does not trim binds nothing here, on the one platform whose discriminator is
// the only thing separating two concurrent sessions — and it fails silently,
// as the unset branch, so nothing alarms.
func TestJunosSessionPIDArrivesWithSpacesAroundTheEquals(t *testing.T) {
	h, st, _, stop := setup(t)
	h.Handle(context.Background(), junos, acct(wire.AcctFlagStart, "alice", "0", "task_id=1", "session_pid = 31050", "service=shell", "cmd=login"))
	stop()
	if c := ctxOf(t, st); c.SessionDiscriminator != "31050" {
		t.Fatalf("the spaced AV pair Junos actually sends was not read: %+v", c)
	}
}

// The Junos exec STOP is `cmd=logout`, and the per-command STOP between them
// must not annotate (tests/lab/results/L6-juniper_vsrx.md).
func TestJunosExecStopIsLogoutAndCommandRecordsAreNot(t *testing.T) {
	h, st, _, stop := setup(t)
	putCtx(t, st, store.Context{CtxID: "ctx1", SessionDiscriminator: "28913"})
	h.Handle(context.Background(), junos, acct(wire.AcctFlagStop, "alice", "0", "task_id=2", "session_pid = 28913", "service=shell", "cmd=show version", "cmd-arg=<cr>"))
	if c := ctxOf(t, st); c.AccountingState != "" {
		t.Fatalf("a per-command record must not annotate: %+v", c)
	}
	h.Handle(context.Background(), junos, acct(wire.AcctFlagStop, "alice", "0", "task_id=1", "session_pid = 28913", "service=shell", "cmd=logout", "elapsed_time=0"))
	stop()
	if c := ctxOf(t, st); c.AccountingState != "closing" {
		t.Fatalf("%+v", c)
	}
}

func TestExecStopSetsClosingOnlyOnADiscriminatorMatch(t *testing.T) {
	h, st, _, stop := setup(t)
	putCtx(t, st, store.Context{CtxID: "ctx1", SessionDiscriminator: "42"})
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "alice", "vty0", "task_id=41", "service=shell", "cmd=", "elapsed_time=10"))
	if c := ctxOf(t, st); c.AccountingState != "" {
		t.Fatalf("a STOP from another session must not annotate: %+v", c)
	}
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "alice", "vty0", "task_id=42", "service=shell", "cmd=", "elapsed_time=10"))
	stop()
	if c := ctxOf(t, st); c.AccountingState != "closing" {
		t.Fatalf("%+v", c)
	}
}

func TestExecStopWithoutABoundDiscriminatorMatchesOnUsername(t *testing.T) {
	h, st, _, stop := setup(t)
	putCtx(t, st, store.Context{CtxID: "ctx1"})
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "alice", "vty0", "task_id=7", "service=shell", "cmd="))
	stop()
	if c := ctxOf(t, st); c.AccountingState != "closing" {
		t.Fatalf("%+v", c)
	}
}

func TestSecondExecStartOnABoundContextIsForeign(t *testing.T) {
	h, st, out, stop := setup(t)
	putCtx(t, st, store.Context{CtxID: "ctx1", SessionDiscriminator: "42"})
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStart, "alice", "vty0", "task_id=99", "service=shell", "cmd="))
	stop()
	if !strings.Contains(out.String(), `"attribution":"foreign"`) {
		t.Fatalf("foreign session not flagged: %s", out.String())
	}
	if c := ctxOf(t, st); c.SessionDiscriminator != "42" {
		t.Fatalf("accounting must never rebind: %+v", c)
	}
}

// A device retransmitting the exec START, or sending a second one carrying the
// discriminator already bound, is this session again — not a login port49
// never saw. `foreign` is the alert someone gets paged for, so the equality
// case has to be told apart from the different case (spec §5.8).
func TestRepeatedExecStartCarryingTheBoundDiscriminatorIsNotForeign(t *testing.T) {
	h, st, out, stop := setup(t)
	putCtx(t, st, store.Context{CtxID: "ctx1", SessionDiscriminator: "42", AccountingState: "closing"})
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStart, "alice", "vty0", "task_id=42", "service=shell", "cmd="))
	stop()
	if strings.Contains(out.String(), `"attribution":"foreign"`) {
		t.Fatalf("a repeat of this session's own START must not be foreign: %s", out.String())
	}
	if c := ctxOf(t, st); c.AccountingState != "" || c.SessionDiscriminator != "42" {
		t.Fatalf("%+v", c)
	}
}

// A device acting on its own behalf is `system`, never `foreign`: the alarm
// foreign exists for is "someone authenticated somewhere other than port49",
// and a Junos root RPC is not that.
func TestDeclaredSystemUserIsSystemNotForeign(t *testing.T) {
	h, _, out, stop := setup(t)
	sys := authen.Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "test_system_users"}
	h.Handle(context.Background(), sys, acct(wire.AcctFlagStop, "root", "non-tty", "task_id=3", "service=shell", "cmd=show version"))
	stop()
	if !strings.Contains(out.String(), `"attribution":"system"`) || strings.Contains(out.String(), `"attribution":"foreign"`) {
		t.Fatalf("%s", out.String())
	}
}

// The same username on a platform that declares no system users is
// unattributed. Every shipped platform is in that state today, so this is the
// behaviour of the binary as it ships (internal/platform).
func TestSystemUserIsPerPlatform(t *testing.T) {
	h, _, out, stop := setup(t)
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "root", "non-tty", "task_id=3", "service=shell", "cmd=show version"))
	stop()
	if !strings.Contains(out.String(), `"attribution":"unattributed"`) {
		t.Fatalf("%s", out.String())
	}
}

func TestUnknownUserIsUnattributedNotSystem(t *testing.T) {
	h, _, out, stop := setup(t)
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStart, "mallory", "vty0", "task_id=9", "service=shell", "cmd="))
	stop()
	if !strings.Contains(out.String(), `"attribution":"unattributed"`) {
		t.Fatalf("%s", out.String())
	}
}

func TestCommandRecordsDoNotAnnotate(t *testing.T) {
	h, st, _, stop := setup(t)
	putCtx(t, st, store.Context{CtxID: "ctx1"})
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "alice", "vty0", "task_id=43", "service=shell", "cmd=show", "cmd-arg=version"))
	stop()
	if c := ctxOf(t, st); c.SessionDiscriminator != "" || c.AccountingState != "" {
		t.Fatalf("%+v", c)
	}
}

// Accounting never deletes a context and never denies (spec §5.8). An
// annotation that found no context to annotate must leave the store exactly as
// it was, including a context under another username.
func TestAnnotationNeverCreatesOrDeletesAContext(t *testing.T) {
	h, st, _, stop := setup(t)
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStart, "mallory", "vty0", "task_id=9", "service=shell", "cmd="))
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "mallory", "vty0", "task_id=9", "service=shell", "cmd="))
	stop()
	if _, err := st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "mallory"}); err == nil {
		t.Fatal("accounting created a context for a user it could not attribute")
	}
	if c := ctxOf(t, st); c.CtxID != "ctx1" {
		t.Fatalf("alice's context was disturbed by a record naming someone else: %+v", c)
	}
}

// An unmodeled platform has no discriminator, so it binds nothing and takes
// the username-only branch — it annotates less, never more (spec §5.8).
func TestUnmodeledPlatformBindsNothingAndStillClosesOnUsername(t *testing.T) {
	h, st, _, stop := setup(t)
	odd := authen.Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "meinberg_lantime"}
	putCtx(t, st, store.Context{CtxID: "ctx1"})
	h.Handle(context.Background(), odd, acct(wire.AcctFlagStart, "alice", "vty0", "task_id=42", "service=shell", "cmd="))
	if c := ctxOf(t, st); c.SessionDiscriminator != "" {
		t.Fatalf("nothing measured says what separates sessions here: %+v", c)
	}
	h.Handle(context.Background(), odd, acct(wire.AcctFlagStop, "alice", "vty0", "task_id=42", "service=shell", "cmd="))
	stop()
	if c := ctxOf(t, st); c.AccountingState != "closing" {
		t.Fatalf("%+v", c)
	}
}
