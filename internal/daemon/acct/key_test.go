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

	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/memory"
	"github.com/blanketfish/port49/internal/tacacs/wire"
)

// Accounting resolves its context by (nas, username) like every other
// exchange (spec §5.8), so a record whose port is a value the authentication
// never carried still attributes. On Junos the accounting port is `0`, `1` or
// `non-tty` while the authentication port was the empty string; on vEOS the
// stop carries `vty<n>` where the start carried `ssh`.
func TestAttributionIgnoresThePort(t *testing.T) {
	for _, port := range []string{"vty0", "non-tty", "", "0", "vty4"} {
		t.Run("port="+port, func(t *testing.T) {
			h, _, out, stop := setup(t)
			h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "alice", port,
				"task_id=43", "service=shell", "cmd="))
			stop()
			var m map[string]any
			if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &m); err != nil {
				t.Fatal(err)
			}
			s := m["session"].(map[string]any)
			if m["attribution"] != "resolved" || s["ctx_id"] != "ctx1" {
				t.Fatalf("%v", m)
			}
			// Requirement (e): the port and rem_addr as seen on this exchange
			// are recorded, whatever the context holds.
			if s["port"] != port {
				t.Fatalf("port on the record: %v, want %q", s["port"], port)
			}
			if s["rem_addr"] != "198.51.100.4" {
				t.Fatalf("rem_addr on the record: %v", s["rem_addr"])
			}
		})
	}
}

// wrongContextStore answers GetContext with a context belonging to somebody
// else, whatever key it was asked for. No correct store does this; the point is
// that accounting must not take the store's word for it, because the record it
// writes is the audit trail.
type wrongContextStore struct {
	*memory.Store
}

func (wrongContextStore) GetContext(context.Context, store.ContextKey) (store.Context, error) {
	return store.Context{CtxID: "ctxOTHER", Principal: "user:bob@example.com", Username: "bob", Port: "ssh"}, nil
}

// TestAStoreFaultDoesNotAttributeToAnotherPrincipal: the lookup key selects on
// the username, so this re-check is only reachable when the store answers with
// a record it was not asked for. When it does, the record must stay
// `unattributed` rather than name the wrong principal (review I-1).
func TestAStoreFaultDoesNotAttributeToAnotherPrincipal(t *testing.T) {
	out := &bytes.Buffer{}
	m := metrics.New(prometheus.NewRegistry())
	sp, err := NewSpool(16, filepath.Join(t.TempDir(), "o.jsonl"), decision.NewJSONLines(out), m)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sp.Run(ctx); close(done) }()
	h := New(wrongContextStore{Store: memory.New(time.Now)}, sp, m, time.Now, nil)

	h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "alice", "vty0", "task_id=1", "service=shell", "cmd="))
	cancel()
	<-done

	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["attribution"] != "unattributed" {
		t.Fatalf("a context for another principal must not resolve: %v", rec)
	}
	if rec["principal"] != nil {
		t.Fatalf("the record must not name the other principal: %v", rec["principal"])
	}
	s := rec["session"].(map[string]any)
	if s["username"] != "alice" {
		t.Fatalf("the record must name the account on the wire, got %v", s["username"])
	}
	if s["ctx_id"] != "" {
		t.Fatalf("the record must not carry the other principal's ctx_id, got %v", s["ctx_id"])
	}
}
