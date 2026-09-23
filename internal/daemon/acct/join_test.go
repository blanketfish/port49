package acct

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/limits"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/token"
)

// Test 2 of the decisions, end to end through the authentication and
// accounting handlers: window A logs in and accounting binds its session;
// window B logs in and accounting binds its own; window A's exec STOP is then
// `resolved`. Before the join, B's login wrote a fresh context with an empty
// discriminator set, B's START put only B's discriminator in it, and A's STOP —
// a session port49 had authenticated — paged as `foreign`.
func TestTheFirstWindowsStopAfterASecondLoginIsResolved(t *testing.T) {
	tagKey := token.TagKey([]byte("labkey"))
	tag := token.Tag(tagKey, "leaf-01")
	st := memory.New(time.Now)
	windowA, windowB := tag+"tokatokatokatokatokatoka", tag+"tokbtokbtokbtokbtokbtokb"
	for id, secret := range map[string]string{"a": windowA, "b": windowB} {
		if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
			store.Token{ID: id, Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
				Principal: "user:alice@example.com", ExpiresAt: time.Now().Add(15 * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	ids := 0
	l := limits.New(limits.Config{AuthFailureDelayBase: time.Millisecond, AuthFailureDelayMax: 2 * time.Millisecond,
		AuthFailureWindow: time.Minute}, time.Now)
	an := authen.New(st, decision.NewJSONLines(&bytes.Buffer{}), l, metrics.New(prometheus.NewRegistry()), time.Now,
		func() string { ids++; return fmt.Sprintf("ctx%d", ids) },
		15*time.Minute, 2*time.Hour, time.Hour, time.Hour, token.NewTagWindow(tagKey))
	login := func(secret string) {
		t.Helper()
		reply, _ := an.NewSession(peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
			PrivLvl: 1, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
			Port: []byte("ssh"), RemAddr: []byte("198.51.100.4"), Data: []byte(secret)})
		if reply.Status != wire.AuthenStatusPass {
			t.Fatalf("login: %+v", reply)
		}
	}

	out := &bytes.Buffer{}
	sp, err := NewSpool(16, filepath.Join(t.TempDir(), "o.jsonl"), decision.NewJSONLines(out), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sp.Run(ctx); close(done) }()
	h := New(st, sp, metrics.New(prometheus.NewRegistry()), time.Now, nil)

	login(windowA)
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStart, "alice", "vty4", "task_id=42", "service=shell", "cmd="))
	login(windowB)
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStart, "alice", "vty6", "task_id=43", "service=shell", "cmd="))
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "alice", "vty4", "task_id=42", "service=shell", "cmd=", "elapsed_time=60"))
	cancel()
	<-done

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 records, got %d: %s", len(lines), out.String())
	}
	if !strings.Contains(lines[2], `"attribution":"resolved"`) {
		t.Fatalf("window A's STOP must resolve, not page: %s", lines[2])
	}
	c, _ := st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
	if !hasDisc(c, "42") || !hasDisc(c, "43") || c.CtxID != "ctx1" {
		t.Fatalf("both windows' sessions must be bound to the one context: %v %+v", discs(t, c, "42", "43"), c)
	}
}
