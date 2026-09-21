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

func setup(t *testing.T) (*Handler, *bytes.Buffer, func()) {
	t.Helper()
	st := memory.New(time.Now)
	st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Port: "vty0"},
		store.Context{CtxID: "ctx1", Principal: "user:alice@example.com", Username: "alice"}, time.Hour)
	out := &bytes.Buffer{}
	sp, err := NewSpool(16, filepath.Join(t.TempDir(), "o.jsonl"), decision.NewJSONLines(out), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sp.Run(ctx); close(done) }()
	h := New(st, sp, metrics.New(prometheus.NewRegistry()), time.Now)
	return h, out, func() { cancel(); <-done }
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
	h, out, stop := setup(t)
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
	h, out, stop := setup(t)
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
	h := New(st, sp, m, time.Now)

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
	h, out, stop := setup(t)
	reply := h.Handle(context.Background(), peer, acct(wire.AcctFlagWatchdog, "alice", "vty0", "task_id=42", "service=shell", "cmd="))
	stop()
	if reply.Status != wire.AcctStatusSuccess || !strings.Contains(out.String(), `"flags":"watchdog"`) {
		t.Fatalf("%+v %s", reply, out.String())
	}
}
