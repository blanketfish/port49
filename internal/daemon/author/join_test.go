package author

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/daemon/authen"
	"github.com/blanketfish/port49/internal/daemon/limits"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/platform"
	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/memory"
	"github.com/blanketfish/port49/internal/tacacs/wire"
	"github.com/blanketfish/port49/internal/token"
)

// joinTagKey is this file's device-tag key. Every secret is the device's tag
// followed by filler, as in package authen's tests.
var joinTagKey = token.TagKey([]byte("labkey"))

// realAuthen is the authentication handler over the same store the authorizer
// reads, so a test here drives a login the way the daemon does rather than
// seeding the context it would have written.
func realAuthen(st store.Store) *authen.Handler {
	ids := 0
	l := limits.New(limits.Config{AuthFailureDelayBase: time.Millisecond, AuthFailureDelayMax: 2 * time.Millisecond,
		AuthFailureWindow: time.Minute}, time.Now)
	return authen.New(st, decision.NewJSONLines(&bytes.Buffer{}), l, metrics.New(prometheus.NewRegistry()), time.Now,
		func() string { ids++; return fmt.Sprintf("ctx%d", ids) },
		15*time.Minute, 2*time.Hour, time.Hour, time.Hour, token.NewTagWindow(joinTagKey))
}

func papLogin(t *testing.T, h *authen.Handler, secret string) {
	t.Helper()
	reply, _ := h.NewSession(peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		PrivLvl: 1, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
		Port: []byte("ssh"), RemAddr: []byte("198.51.100.4"), Data: []byte(secret)})
	if reply.Status != wire.AuthenStatusPass {
		t.Fatalf("login: %+v", reply)
	}
}

// Test 1 of the decisions, end to end through both handlers: window A enables
// to 15; window B logs in and its session authorization is granted less; window
// A's next command at 15 is still permitted. Before the join, B's login wrote a
// fresh context at level 1 over A's, and A was denied `privilege_exceeded` on a
// session port49 had just escalated.
func TestASecondWindowDoesNotTakeTheFirstWindowsEnable(t *testing.T) {
	st := memory.New(time.Now)
	tag := token.Tag(joinTagKey, "leaf-01")
	windowA, windowB := tag+"tokatokatokatokatokatoka", tag+"tokbtokbtokbtokbtokbtokb"
	for id, secret := range map[string]string{"a": windowA, "b": windowB} {
		if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
			store.Token{ID: id, Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
				Principal: "user:alice@example.com", Enable: "auto", MaxPrivilege: 15,
				ExpiresAt: time.Now().Add(15 * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	an := realAuthen(st)
	log := &bytes.Buffer{}
	az := New(st, &Lab{SessionAttributes: []string{"priv-lvl=1"}}, decision.NewJSONLines(log),
		metrics.New(prometheus.NewRegistry()), time.Now, platform.Defaults(), time.Hour, time.Minute, time.Hour)

	// Window A: login, session authorization, enable to 15.
	papLogin(t, an, windowA)
	sess := req("alice", "vty4", "service=shell", "cmd=")
	sess.PrivLvl = 1
	if resp := az.Handle(context.Background(), peer, sess); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("window A session: %+v", resp)
	}
	en := an.NewSession(peer)
	en.Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 15,
		AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceEnable, User: []byte("alice"),
		Port: []byte("vty4"), RemAddr: []byte("198.51.100.4")})
	if reply, _ := en.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte("anything")}); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("window A enable: %+v", reply)
	}

	// Window B: login, and a session authorization granted 1.
	papLogin(t, an, windowB)
	sess = req("alice", "vty6", "service=shell", "cmd=")
	sess.PrivLvl = 1
	if resp := az.Handle(context.Background(), peer, sess); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("window B session: %+v", resp)
	}

	// Window A, still enabled.
	cmd := req("alice", "vty4", "service=shell", "cmd=configure", "cmd-arg=<cr>")
	cmd.PrivLvl = 15
	if resp := az.Handle(context.Background(), peer, cmd); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("window A lost its enable to window B's login: %+v %v", resp, lastRecord(t, log))
	}
	if c, _ := st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"}); c.CtxID != "ctx1" {
		t.Fatalf("both windows must share the first login's ctx_id: %+v", c)
	}
}
