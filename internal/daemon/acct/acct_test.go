package acct

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/platform"
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
	h := New(st, sp, metrics.New(prometheus.NewRegistry()), time.Now,
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
	h := New(st, sp, m, time.Now, nil)

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

// discs renders a context's set as the raw values it was built from, so a
// failure message names `31050` rather than 16 bytes of hex.
func discs(t *testing.T, c store.Context, candidates ...string) []string {
	t.Helper()
	byHash := map[string]string{}
	for _, v := range candidates {
		byHash[store.HashDiscriminator(v)] = v
	}
	out := make([]string, 0, len(c.SessionDiscriminators))
	for _, h := range c.SessionDiscriminators {
		if v, ok := byHash[h]; ok {
			out = append(out, v)
		} else {
			out = append(out, "unknown:"+h)
		}
	}
	return out
}

func hasDisc(c store.Context, v string) bool {
	for _, h := range c.SessionDiscriminators {
		if h == store.HashDiscriminator(v) {
			return true
		}
	}
	return false
}

func TestExecStartAddsTheDiscriminatorAndClearsClosing(t *testing.T) {
	h, st, _, stop := setup(t)
	putCtx(t, st, store.Context{CtxID: "ctx1", Principal: "user:alice@example.com",
		AccountingState: store.AccountingStateClosing})
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStart, "alice", "vty0", "task_id=42", "service=shell", "cmd="))
	stop()
	c := ctxOf(t, st)
	if !hasDisc(c, "42") || c.AccountingState != store.AccountingStateOpen {
		t.Fatalf("%+v %v", c, discs(t, c, "42"))
	}
}

// The discriminator is stored hashed, never in the clear. It matters on NX-OS,
// where the measured task_id is `172.100.100.1@pts/3`
// (tests/lab/results/L1-cisco_nxos.md) — the client's source address, which
// rem_addr is sealed to keep a store dump from enumerating.
func TestTheStoredDiscriminatorIsHashedNotTheValue(t *testing.T) {
	h, st, _, stop := setup(t)
	nxos := authen.Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "cisco_nxos"}
	putCtx(t, st, store.Context{CtxID: "ctx1"})
	h.Handle(context.Background(), nxos, acct(wire.AcctFlagStart, "alice", "0", "task_id=172.100.100.1@pts/3", "service=none"))
	stop()
	c := ctxOf(t, st)
	if !hasDisc(c, "172.100.100.1@pts/3") {
		t.Fatalf("the discriminator was not bound: %+v", c)
	}
	for _, h := range c.SessionDiscriminators {
		if strings.Contains(h, "172.100.100.1") || strings.Contains(h, "pts") {
			t.Fatalf("the client's source address is in the store in the clear: %q", h)
		}
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
	putCtx(t, st, store.Context{CtxID: "ctx1"})
	h.Handle(context.Background(), junos, acct(wire.AcctFlagStart, "alice", "0", "task_id=1", "session_pid=14656", "service=shell", "cmd=login"))
	stop()
	c := ctxOf(t, st)
	if !hasDisc(c, "14656") || hasDisc(c, "1") {
		t.Fatalf("%v", discs(t, c, "14656", "1"))
	}
}

// The AV pair as the device actually sends it. vSRX 21.4R3.15 and
// vJunos-router 23.4R2-S2.1 send `session_pid = 31050` with a space on each
// side of the `=`, while every other argument in the same record has none
// (tests/lab/results/L17-juniper_vsrx.md, L6-juniper_vsrx.md). A reader that
// does not trim binds nothing here, on the one platform whose discriminator is
// the only thing separating two concurrent sessions — and it fails silently,
// as the empty-set branch, so nothing alarms.
func TestJunosSessionPIDArrivesWithSpacesAroundTheEquals(t *testing.T) {
	h, st, _, stop := setup(t)
	putCtx(t, st, store.Context{CtxID: "ctx1"})
	h.Handle(context.Background(), junos, acct(wire.AcctFlagStart, "alice", "0", "task_id=1", "session_pid = 31050", "service=shell", "cmd=login"))
	stop()
	if c := ctxOf(t, st); !hasDisc(c, "31050") {
		t.Fatalf("the spaced AV pair Junos actually sends was not read: %+v", c)
	}
}

// §5.8 says an accounting reader MUST trim both halves, not only the
// discriminator: every AV pair this handler consumes goes through the same
// reader. Untrimmed, `task_id = 7` logs an empty task_id and reconciliation
// loses the join, and `elapsed_time = 20` becomes 0 with no error.
func TestEveryAVPairTheReaderConsumesIsTrimmed(t *testing.T) {
	h, _, out, stop := setup(t)
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "alice", "vty0",
		"task_id = 7", "service=shell", "cmd = ", "start_time = 100", "stop_time = 120", "elapsed_time = 20"))
	stop()
	var m map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &m); err != nil {
		t.Fatal(err)
	}
	if m["task_id"] != "7" {
		t.Fatalf("task_id not trimmed: %v", m)
	}
	rec := m["record"].(map[string]any)
	if rec["start_time"].(float64) != 100 || rec["stop_time"].(float64) != 120 || rec["elapsed_time"].(float64) != 20 {
		t.Fatalf("the times were read from an untrimmed value: %v", rec)
	}
}

// `cmd = ` with spaces is still an exec record: the trim reaches the field
// that decides whether anything annotates at all.
func TestASpacedEmptyCmdIsStillAnExecRecord(t *testing.T) {
	h, st, _, stop := setup(t)
	putCtx(t, st, store.Context{CtxID: "ctx1"})
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStart, "alice", "vty0", "task_id = 42", "service=shell", "cmd = "))
	stop()
	if c := ctxOf(t, st); !hasDisc(c, "42") {
		t.Fatalf("a spaced cmd made the exec record look like a command record: %+v", c)
	}
}

// The Junos exec STOP is `cmd=logout`, and the per-command STOP between them
// must not annotate (tests/lab/results/L6-juniper_vsrx.md).
func TestJunosExecStopIsLogoutAndCommandRecordsAreNot(t *testing.T) {
	h, st, _, stop := setup(t)
	putCtx(t, st, store.Context{CtxID: "ctx1", SessionDiscriminators: []string{store.HashDiscriminator("28913")}})
	h.Handle(context.Background(), junos, acct(wire.AcctFlagStop, "alice", "0", "task_id=2", "session_pid = 28913", "service=shell", "cmd=show version", "cmd-arg=<cr>"))
	if c := ctxOf(t, st); c.AccountingState != "" {
		t.Fatalf("a per-command record must not annotate: %+v", c)
	}
	h.Handle(context.Background(), junos, acct(wire.AcctFlagStop, "alice", "0", "task_id=1", "session_pid = 28913", "service=shell", "cmd=logout", "elapsed_time=0"))
	stop()
	if c := ctxOf(t, st); c.AccountingState != store.AccountingStateClosing {
		t.Fatalf("%+v", c)
	}
}

// `closing` is set when the STOP's discriminator is in the set — ANY member,
// because with concurrent sessions the field means "at least one session of
// this user closed" (spec §5.8).
func TestExecStopSetsClosingOnAMatchWithAnyMemberOfTheSet(t *testing.T) {
	h, st, _, stop := setup(t)
	putCtx(t, st, store.Context{CtxID: "ctx1", SessionDiscriminators: []string{
		store.HashDiscriminator("42"), store.HashDiscriminator("43")}})
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "alice", "vty0", "task_id=43", "service=shell", "cmd=", "elapsed_time=10"))
	stop()
	c := ctxOf(t, st)
	if c.AccountingState != store.AccountingStateClosing {
		t.Fatalf("%+v", c)
	}
	// The STOP does not remove it: narrowing the set would cost a second write
	// for a field no decision reads, and would make a duplicate STOP foreign.
	if len(c.SessionDiscriminators) != 2 {
		t.Fatalf("a STOP removed its discriminator: %v", discs(t, c, "42", "43"))
	}
}

func TestExecStopWithAnEmptySetMatchesOnUsername(t *testing.T) {
	h, st, _, stop := setup(t)
	putCtx(t, st, store.Context{CtxID: "ctx1"})
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "alice", "vty0", "task_id=7", "service=shell", "cmd="))
	stop()
	if c := ctxOf(t, st); c.AccountingState != store.AccountingStateClosing {
		t.Fatalf("stop-only accounting and a lost START take the username branch: %+v", c)
	}
}

// Stop-only accounting must not page. An empty set is never `foreign`: port49
// has watched no session of this user begin here, so it has no grounds to say
// this one is a login it never saw.
func TestAnEmptySetIsNeverForeign(t *testing.T) {
	h, st, out, stop := setup(t)
	putCtx(t, st, store.Context{CtxID: "ctx1"})
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "alice", "vty0", "task_id=7", "service=shell", "cmd="))
	stop()
	if strings.Contains(out.String(), `"attribution":"foreign"`) {
		t.Fatalf("%s", out.String())
	}
}

// The signal `foreign` is worth firing on: a record for a session whose START
// port49 never saw, on a device where it did watch this user's others begin —
// a local fallback, a console login, or a device-local account sharing the
// name (spec §5.6, §5.8).
func TestExecStopOutsideANonEmptySetIsForeign(t *testing.T) {
	h, st, out, stop := setup(t)
	putCtx(t, st, store.Context{CtxID: "ctx1", SessionDiscriminators: []string{store.HashDiscriminator("42")}})
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "alice", "vty0", "task_id=99", "service=shell", "cmd=", "elapsed_time=10"))
	stop()
	if !strings.Contains(out.String(), `"attribution":"foreign"`) {
		t.Fatalf("foreign session not flagged: %s", out.String())
	}
	c := ctxOf(t, st)
	if c.AccountingState != "" {
		t.Fatalf("a foreign record must annotate nothing: %+v", c)
	}
	if len(c.SessionDiscriminators) != 1 || !hasDisc(c, "42") {
		t.Fatalf("a foreign record must not touch the set: %v", discs(t, c, "42", "99"))
	}
}

// A keepalive for a session port49 never saw begin is the same signal as its
// STOP, so a WATCHDOG can be foreign. It still annotates nothing: it neither
// adds a discriminator — it is not a START — nor says a session closed.
//
// The subtests run both encodings a device may use. `START|WATCHDOG` (0x0a) is
// a legal combination that wire.DecodeAcctRequest accepts and Cisco IOS sends
// for interim updates; treating it as a START would let a device that sets the
// START bit on every record switch `foreign` off for itself, while its own log
// lines still said `watchdog`.
func TestAWatchdogCanBeForeignAndAnnotatesNothing(t *testing.T) {
	for _, tt := range []struct {
		name  string
		flags uint8
	}{
		{"watchdog", wire.AcctFlagWatchdog},
		{"start_watchdog", wire.AcctFlagStart | wire.AcctFlagWatchdog},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, st, out, stop := setup(t)
			putCtx(t, st, store.Context{CtxID: "ctx1", SessionDiscriminators: []string{store.HashDiscriminator("42")}})
			h.Handle(context.Background(), peer, acct(tt.flags, "alice", "vty0", "task_id=99", "service=shell", "cmd="))
			h.Handle(context.Background(), peer, acct(tt.flags, "alice", "vty0", "task_id=42", "service=shell", "cmd="))
			stop()
			lines := strings.Split(strings.TrimSpace(out.String()), "\n")
			if len(lines) != 2 {
				t.Fatalf("want 2 records, got %d: %s", len(lines), out.String())
			}
			if !strings.Contains(lines[0], `"attribution":"foreign"`) {
				t.Fatalf("a keepalive for a session port49 never saw begin is the same signal as its STOP: %s", lines[0])
			}
			if !strings.Contains(lines[1], `"attribution":"resolved"`) {
				t.Fatalf("a keepalive for a bound session is resolved: %s", lines[1])
			}
			// The log calls both of these `watchdog`, so the annotation must
			// agree: nothing added, nothing closed, nothing opened.
			for _, line := range lines {
				if !strings.Contains(line, `"flags":"watchdog"`) {
					t.Fatalf("flagsName and the annotation disagree about what this record is: %s", line)
				}
			}
			c := ctxOf(t, st)
			if c.AccountingState != "" || len(c.SessionDiscriminators) != 1 {
				t.Fatalf("a watchdog is a keepalive, not a session beginning or ending: %+v", c)
			}
			if hasDisc(c, "99") {
				t.Fatalf("an interim update added a discriminator: %v", discs(t, c, "42", "99"))
			}
		})
	}
}

// The wire decoder accepts START|WATCHDOG, which is what makes the handler's
// own test above meaningful: if this combination were rejected at decode, the
// case could not reach the annotation at all.
func TestStartWatchdogIsALegalFlagCombinationOnTheWire(t *testing.T) {
	b := acct(wire.AcctFlagStart|wire.AcctFlagWatchdog, "alice", "vty0", "task_id=1", "service=shell", "cmd=").Encode()
	got, err := wire.DecodeAcctRequest(b)
	if err != nil {
		t.Fatalf("0x0a must decode: %v", err)
	}
	if got.Flags != wire.AcctFlagStart|wire.AcctFlagWatchdog {
		t.Fatalf("flags = %#x", got.Flags)
	}
}

// The behaviour the single-discriminator model got wrong: under the
// (nas, username) key one context covers every concurrent session of one
// operator (§13, decision 15), so an operator opening a second window used to
// page somebody. A START always adds, and both sessions end up in the set.
func TestASecondConcurrentSessionIsResolvedNotForeign(t *testing.T) {
	h, st, out, stop := setup(t)
	putCtx(t, st, store.Context{CtxID: "ctx1"})
	h.Handle(context.Background(), junos, acct(wire.AcctFlagStart, "alice", "0", "task_id=1", "session_pid = 31048", "service=shell", "cmd=login"))
	h.Handle(context.Background(), junos, acct(wire.AcctFlagStart, "alice", "1", "task_id=1", "session_pid = 31050", "service=shell", "cmd=login"))
	stop()
	if strings.Contains(out.String(), `"attribution":"foreign"`) {
		t.Fatalf("an operator's second window must not page: %s", out.String())
	}
	c := ctxOf(t, st)
	if !hasDisc(c, "31048") || !hasDisc(c, "31050") {
		t.Fatalf("both concurrent sessions must be bound: %v", discs(t, c, "31048", "31050"))
	}
	// And now each session's own STOP closes without alerting.
	h2, st2, out2, stop2 := setup(t)
	putCtx(t, st2, c)
	h2.Handle(context.Background(), junos, acct(wire.AcctFlagStop, "alice", "0", "task_id=1", "session_pid = 31048", "service=shell", "cmd=logout"))
	stop2()
	if strings.Contains(out2.String(), `"attribution":"foreign"`) {
		t.Fatalf("%s", out2.String())
	}
	if c := ctxOf(t, st2); c.AccountingState != store.AccountingStateClosing {
		t.Fatalf("%+v", c)
	}
}

// A device retransmitting the exec START must not consume a slot, and must not
// page.
func TestARetransmittedStartIsNotForeignAndAddsNoSlot(t *testing.T) {
	h, st, out, stop := setup(t)
	putCtx(t, st, store.Context{CtxID: "ctx1", SessionDiscriminators: []string{store.HashDiscriminator("42")},
		AccountingState: store.AccountingStateClosing})
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStart, "alice", "vty0", "task_id=42", "service=shell", "cmd="))
	stop()
	if strings.Contains(out.String(), `"attribution":"foreign"`) {
		t.Fatalf("a repeat of this session's own START must not be foreign: %s", out.String())
	}
	c := ctxOf(t, st)
	if c.AccountingState != store.AccountingStateOpen || len(c.SessionDiscriminators) != 1 {
		t.Fatalf("%+v", c)
	}
}

// The cap's cost, stated rather than discovered: a ninth concurrent session
// evicts the first, so the first session's STOP is then `foreign` (spec §5.8).
// The test exists so that the false alert is a decision someone made.
func TestTheNinthConcurrentSessionEvictsTheFirst(t *testing.T) {
	h, st, _, stop := setup(t)
	putCtx(t, st, store.Context{CtxID: "ctx1"})
	for i := 0; i < store.MaxSessionDiscriminators+1; i++ {
		h.Handle(context.Background(), peer, acct(wire.AcctFlagStart, "alice", "vty0",
			fmt.Sprintf("task_id=%d", i), "service=shell", "cmd="))
	}
	stop()
	c := ctxOf(t, st)
	if len(c.SessionDiscriminators) != store.MaxSessionDiscriminators {
		t.Fatalf("the cap did not hold: %d entries", len(c.SessionDiscriminators))
	}
	if hasDisc(c, "0") {
		t.Fatal("the cap evicted nothing")
	}
	if !hasDisc(c, "8") {
		t.Fatal("the cap evicted the newest session instead of the oldest")
	}
}

// A device acting on its own behalf is `system`, never `foreign`: the alarm
// foreign exists for is "someone authenticated somewhere other than port49",
// and a vSRX alarm RPC is not that.
func TestDeclaredSystemUserIsSystemNotForeign(t *testing.T) {
	h, _, out, stop := setup(t)
	sys := authen.Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "test_system_users"}
	h.Handle(context.Background(), sys, acct(wire.AcctFlagStop, "root", "non-tty", "task_id=3", "service=shell", "cmd=show version"))
	stop()
	if !strings.Contains(out.String(), `"attribution":"system"`) || strings.Contains(out.String(), `"attribution":"foreign"`) {
		t.Fatalf("%s", out.String())
	}
}

// The shipped table, on the records that are actually in the tree: the three
// root records in tests/lab/evidence/L1-juniper_vsrx.pcap, replayed. Without
// the juniper_junos row a healthy vSRX reports sessions port49 did not
// authenticate (internal/platform).
func TestJunosRootRecordsFromTheCaptureAreSystem(t *testing.T) {
	st := memory.New(time.Now)
	out := &bytes.Buffer{}
	sp, err := NewSpool(16, filepath.Join(t.TempDir(), "o.jsonl"), decision.NewJSONLines(out), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sp.Run(ctx); close(done) }()
	h := New(st, sp, metrics.New(prometheus.NewRegistry()), time.Now, platform.SystemUsers())

	for _, r := range []wire.AcctRequest{
		acct(wire.AcctFlagStart, "root", "non-tty", "task_id=1", "service=shell", "session_pid = 28771", "cmd=login"),
		acct(wire.AcctFlagStop, "root", "non-tty", "task_id=2", "service=shell", "session_pid = 28771", "cmd=set alarm yellow alarm-id 0small-msg", "cmd-arg=<cr>"),
		acct(wire.AcctFlagStop, "root", "non-tty", "task_id=1", "service=shell", "session_pid = 28771", "elapsed_time=0", "cmd=logout"),
	} {
		h.Handle(context.Background(), junos, r)
	}
	cancel()
	<-done

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 records, got %d: %s", len(lines), out.String())
	}
	for _, line := range lines {
		if !strings.Contains(line, `"attribution":"system"`) {
			t.Fatalf("a vSRX root record must not read as a session port49 did not authenticate: %s", line)
		}
	}
}

// The same username on a platform that declares no system users is
// unattributed: the table is per platform, and only juniper_junos has a row.
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
	if c := ctxOf(t, st); len(c.SessionDiscriminators) != 0 || c.AccountingState != "" {
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

// Accounting is not activity for the idle TTL (spec §5.8): a device sending
// only STOPs — records saying a session ENDED — must not be able to hold a
// context open. The authorizer's half-TTL extension is Task 10's and stays
// there.
func TestAnnotationDoesNotExtendTheIdleTTL(t *testing.T) {
	now := time.Unix(1000, 0)
	st := memory.New(func() time.Time { return now })
	out := &bytes.Buffer{}
	sp, err := NewSpool(16, filepath.Join(t.TempDir(), "o.jsonl"), decision.NewJSONLines(out), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sp.Run(ctx); close(done) }()
	h := New(st, sp, metrics.New(prometheus.NewRegistry()), func() time.Time { return now }, nil)
	key := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	st.PutContext(context.Background(), key, store.Context{CtxID: "ctx1", Username: "alice"}, time.Minute)

	stamped := now
	now = now.Add(30 * time.Second)
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStart, "alice", "vty0", "task_id=42", "service=shell", "cmd="))
	cancel()
	<-done

	c, err := st.GetContext(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if !c.LastTouchedAt.Equal(stamped) {
		t.Fatalf("the annotation stamped the TTL clock: %+v", c)
	}
	now = now.Add(31 * time.Second) // past the original expiry
	if _, err := st.GetContext(context.Background(), key); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("the annotation extended the expiry; only authorization may")
	}
}

// An unmodeled platform has no discriminator, so it binds nothing and takes
// the username-only branch — it annotates less, never more (spec §5.8).
func TestUnmodeledPlatformBindsNothingAndStillClosesOnUsername(t *testing.T) {
	h, st, _, stop := setup(t)
	odd := authen.Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "meinberg_lantime"}
	putCtx(t, st, store.Context{CtxID: "ctx1"})
	h.Handle(context.Background(), odd, acct(wire.AcctFlagStart, "alice", "vty0", "task_id=42", "service=shell", "cmd="))
	if c := ctxOf(t, st); len(c.SessionDiscriminators) != 0 {
		t.Fatalf("nothing measured says what separates sessions here: %+v", c)
	}
	h.Handle(context.Background(), odd, acct(wire.AcctFlagStop, "alice", "vty0", "task_id=42", "service=shell", "cmd="))
	stop()
	if c := ctxOf(t, st); c.AccountingState != store.AccountingStateClosing {
		t.Fatalf("%+v", c)
	}
}

// Every record the spool accepted is counted by its attribution, and `foreign`
// is the one to alert on (spec §5.8): a session port49 did not authenticate,
// under a name it does. The label is the attribution and nothing else — no
// device and no user, which CLAUDE.md forbids in a metric label.
func TestEveryAttributionIsCounted(t *testing.T) {
	h, st, _, stop := setup(t)
	sys := authen.Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "test_system_users"}
	putCtx(t, st, store.Context{CtxID: "ctx1", Principal: "user:alice@example.com",
		SessionDiscriminators: []string{store.HashDiscriminator("42")}})
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStart, "alice", "vty0", "task_id=42", "service=shell", "cmd="))
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "alice", "vty0", "task_id=99", "service=shell", "cmd="))
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "mallory", "vty0", "task_id=7", "service=shell", "cmd="))
	h.Handle(context.Background(), sys, acct(wire.AcctFlagStop, "root", "non-tty", "task_id=3", "service=shell", "cmd="))
	stop()
	for _, a := range []string{"resolved", "foreign", "unattributed", "system"} {
		if got := testutil.ToFloat64(h.metrics.Attributions.WithLabelValues(a)); got != 1 {
			t.Errorf("port49_accounting_attributions_total{attribution=%q} = %v, want 1", a, got)
		}
	}
}

// A record the spool refused is not counted: the device was answered ERROR and
// will send it again, and counting both would double it.
func TestARefusedRecordIsNotCounted(t *testing.T) {
	st := memory.New(time.Now)
	m := metrics.New(prometheus.NewRegistry())
	h := New(st, brokenSpool(filepath.Join(t.TempDir(), "absent", "o.jsonl"), m), m, time.Now, nil)
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "mallory", "vty0", "task_id=1", "service=shell", "cmd="))
	if got := testutil.ToFloat64(m.Attributions.WithLabelValues("unattributed")); got != 0 {
		t.Fatalf("a refused record was counted: %v", got)
	}
}

// A console login as a system user stays `system` (spec §5.8): `root` on
// juniper_junos is the device's own machinery in the capture, and port49
// cannot tell that from a person at the console under the same name. What it
// can do is keep the port on the record, so a log reader sees where the
// session was. The port value here is illustrative: what a Junos console
// presents in `port` is unmeasured in this lab.
func TestASystemRecordCarriesItsPort(t *testing.T) {
	h, _, out, stop := setup(t)
	sys := authen.Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "test_system_users"}
	h.Handle(context.Background(), sys, acct(wire.AcctFlagStart, "root", "ttyd0", "task_id=1", "service=shell", "cmd="))
	stop()
	var m map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &m); err != nil {
		t.Fatal(err)
	}
	if m["attribution"] != "system" || m["session"].(map[string]any)["port"] != "ttyd0" {
		t.Fatalf("a system record must stay system and carry the port it arrived on: %v", m)
	}
}

// Command accounting carries typed text verbatim, so a secret is replaced
// before the record reaches the spool, which is on disk (spec §5.8). The
// record keeps its shape and says it was redacted, and the attribution was
// read from the record as sent.
func TestAccountingNeverWritesASecret(t *testing.T) {
	h, _, out, stop := setup(t)
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "alice", "vty0", "task_id=44", "service=shell",
		"cmd=enable", "cmd-arg=secret", "cmd-arg=0", "cmd-arg=Hunter2", "cmd-arg=<cr>"))
	junos := authen.Peer{NAS: "srx-01", NASAddr: "10.20.0.8", Platform: "juniper_junos"}
	h.Handle(context.Background(), junos, acct(wire.AcctFlagStop, "alice", "0", "task_id=2", "service=shell",
		"session_pid = 31050", `cmd=set system root-authentication encrypted-password "$6$abc" <cr>`))
	stop()
	if strings.Contains(out.String(), "Hunter2") || strings.Contains(out.String(), "$6$abc") {
		t.Fatalf("a secret reached the sink: %s", out.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatal(err)
	}
	rec := m["record"].(map[string]any)
	vec := rec["vector"].([]any)
	if m["attribution"] != "resolved" || rec["redacted"] != true || len(vec) != 4 || vec[2] != platform.Redacted ||
		vec[3] != platform.Redacted {
		t.Fatalf("%v", m)
	}
}

// The spool is a file, and it is written before the sink ever sees the
// record: a secret must be gone by then, not only by the time the record is
// forwarded (spec §5.8). A redactor the daemon is given applies in place of
// the built-in one.
func TestTheSpoolFileNeverHoldsASecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spool.jsonl")
	sp, err := NewSpool(16, path, decision.NewJSONLines(&bytes.Buffer{}), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	// No Run: nothing drains, so every record stays in the file.
	h := New(memory.New(time.Now), sp, metrics.New(prometheus.NewRegistry()), time.Now, nil)
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "alice", "vty0", "task_id=45", "service=shell",
		"cmd=username", "cmd-arg=bob", "cmd-arg=secret", "cmd-arg=Hunter2", "cmd-arg=<cr>"))
	h.WithRedactor(func(string) []platform.Redaction {
		return []platform.Redaction{{Match: []string{"**"}, After: "psk"}}
	})
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "alice", "vty0", "task_id=46", "service=shell",
		"cmd=crypto", "cmd-arg=psk", "cmd-arg=s3cret", "cmd-arg=<cr>"))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "Hunter2") || strings.Contains(string(b), "s3cret") ||
		strings.Count(string(b), `"redacted":true`) != 2 {
		t.Fatalf("the spool file: %s", b)
	}
}
