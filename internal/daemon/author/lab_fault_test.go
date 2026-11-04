package author

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/platform"
	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/memory"
	"github.com/blanketfish/port49/internal/tacacs/wire"
)

func setFault(t *testing.T, path, fault string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(fault+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLabFaultIsOffWithoutAFile(t *testing.T) {
	for _, f := range []LabFault{{}, {Path: filepath.Join(t.TempDir(), "absent")}} {
		if f.Is(FaultStoreUnavailable) || f.Is(FaultCommandError) || f.Is(FaultCommandFail) {
			t.Fatalf("%+v reports a fault with no file", f)
		}
	}
	path := filepath.Join(t.TempDir(), "fault")
	setFault(t, path, "")
	if (LabFault{Path: path}).Is(FaultCommandError) {
		t.Fatal("an empty fault file is a fault")
	}
}

func TestLabFaultIsReadPerRequest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fault")
	f := LabFault{Path: path}
	setFault(t, path, FaultCommandError)
	if !f.Is(FaultCommandError) || f.Is(FaultStoreUnavailable) {
		t.Fatal("command_error not read")
	}
	setFault(t, path, FaultStoreUnavailable)
	if f.Is(FaultCommandError) || !f.Is(FaultStoreUnavailable) {
		t.Fatal("the switch was not re-read")
	}
}

// A command answered under command_error is an ERROR on the wire, not a FAIL:
// that difference is the whole of what register entry L4 (b) measures.
func TestCommandErrorFaultRepliesError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fault")
	now := time.Now
	st := memory.New(now)
	st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "ctx1", Username: "alice", PrivLvl: 15, RefreshedAt: now()}, time.Hour)
	log := &bytes.Buffer{}
	lab := &Lab{Fault: LabFault{Path: path}}
	h := New(st, lab, decision.NewJSONLines(log), metrics.New(prometheus.NewRegistry()), now,
		platform.Defaults(), time.Hour, time.Minute, time.Hour)
	cmd := req("alice", "vty0", "service=shell", "cmd=show", "cmd-arg=version", "cmd-arg=<cr>")

	if resp := h.Handle(context.Background(), peer, cmd); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("no fault: %+v", resp)
	}
	setFault(t, path, FaultCommandError)
	resp := h.Handle(context.Background(), peer, cmd)
	if resp.Status != wire.AuthorStatusError || len(resp.Args) != 0 {
		t.Fatalf("command_error: %+v", resp)
	}
	if r := lastRecord(t, log); r["verdict"] != "deny" || r["reason"] != string(decision.StoreUnavailable) {
		t.Fatalf("%v", r)
	}
	setFault(t, path, FaultCommandFail)
	if resp := h.Handle(context.Background(), peer, cmd); resp.Status != wire.AuthorStatusFail {
		t.Fatalf("command_fail: %+v", resp)
	}
	// Neither command fault touches the session reply: the session has to open
	// for there to be a command to measure.
	setFault(t, path, FaultCommandError)
	if resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=")); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("session under command_error: %+v", resp)
	}
}

// session_error is an ERROR on the session authorization and leaves commands alone (L87 c).
func TestSessionErrorFaultRepliesError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fault")
	now := time.Now
	st := memory.New(now)
	st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "ctx1", Username: "alice", PrivLvl: 15, RefreshedAt: now()}, time.Hour)
	log := &bytes.Buffer{}
	lab := &Lab{Fault: LabFault{Path: path}}
	h := New(st, lab, decision.NewJSONLines(log), metrics.New(prometheus.NewRegistry()), now,
		platform.Defaults(), time.Hour, time.Minute, time.Hour)
	session := req("alice", "vty0", "service=shell", "cmd=")
	cmd := req("alice", "vty0", "service=shell", "cmd=show", "cmd-arg=version", "cmd-arg=<cr>")

	setFault(t, path, FaultSessionError)
	resp := h.Handle(context.Background(), peer, session)
	if resp.Status != wire.AuthorStatusError || len(resp.Args) != 0 {
		t.Fatalf("session_error: %+v", resp)
	}
	if r := lastRecord(t, log); r["verdict"] != "deny" || r["reason"] != string(decision.StoreUnavailable) {
		t.Fatalf("%v", r)
	}
	if resp := h.Handle(context.Background(), peer, cmd); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("command under session_error: %+v", resp)
	}
	setFault(t, path, "")
	if resp := h.Handle(context.Background(), peer, session); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("no fault: %+v", resp)
	}
}

func TestFaultStoreFailsTheFirstReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fault")
	inner := memory.New(time.Now)
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	inner.PutContext(context.Background(), k, store.Context{CtxID: "ctx1", Username: "alice"}, time.Hour)
	s := &FaultStore{Store: inner, Fault: LabFault{Path: path}}

	if _, err := s.GetContext(context.Background(), k); err != nil {
		t.Fatalf("no fault: %v", err)
	}
	setFault(t, path, FaultStoreUnavailable)
	if _, err := s.GetContext(context.Background(), k); err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetContext: %v", err)
	}
	if _, err := s.GetReceipt(context.Background(), store.ReceiptKey{NAS: "leaf-01", Username: "alice"}); err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetReceipt: %v", err)
	}
	if _, err := s.Candidates(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"}); err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Candidates: %v", err)
	}
}
