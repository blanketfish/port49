//go:build linux

package main

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/blanketfish/port49/internal/hwkey"
)

// L86 (d): the touch key pulled with the agent running, then an admin call.
// The CLI says to insert the key, exits 1, and nothing reaches the broker:
// no request, so no challenge. Put back, the same call is sent exactly once
// and asked once.
func TestAPulledTouchKeySendsNoAdminRequest(t *testing.T) {
	var revokes atomic.Int32
	front := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/tokens/revoke" {
				revokes.Add(1)
			}
			next.ServeHTTP(w, r)
		})
	}
	m := adminLab(t, front)
	m.touch.Pull(true)
	code, _, se := cli("revoke", "--principal", "user:bob@example.com", "--yes")
	if code != 1 || !strings.Contains(se, "port49 revoke: insert your key; your session goes on until") {
		t.Fatalf("exit %d: %q", code, se)
	}
	if strings.Contains(se, "touch your key") {
		t.Fatalf("prompted a touch for a key that is out: %q", se)
	}
	if n := revokes.Load(); n != 0 || m.touch.Signs() != 0 {
		t.Fatalf("the broker saw %d admin requests and the key signed %d times, want 0 and 0", n, m.touch.Signs())
	}

	m.touch.Pull(false)
	m.touch.SetState(hwkey.Present)
	code, _, se = cli("revoke", "--principal", "user:bob@example.com", "--yes")
	if code != 0 || strings.Count(se, "touch your key to revoke_principal user:bob@example.com") != 1 {
		t.Fatalf("with the key back: exit %d: %q", code, se)
	}
	// One ask (answered with the challenge) and one proved retry.
	if n := revokes.Load(); n != 2 || m.touch.Signs() != 1 {
		t.Fatalf("with the key back the broker saw %d admin requests and the key signed %d times, want 2 and 1",
			n, m.touch.Signs())
	}
}
