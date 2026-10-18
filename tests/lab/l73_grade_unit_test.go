//go:build lab

package lab

import (
	"testing"
	"time"
)

func TestL73Grade(t *testing.T) {
	for _, c := range []struct {
		ok, red, hf bool
		want        string
	}{
		{true, true, false, "accepted"},
		{false, false, true, "refused"},
		{false, false, false, "login failed, cause unproven"},
		{true, false, false, "login failed, cause unproven"},
	} {
		if got := l73Grade(c.ok, c.red, c.hf); got != c.want {
			t.Errorf("%+v: %q", c, got)
		}
	}
}

func TestL73HandshakeFailedNeedsTheRecord(t *testing.T) {
	failed := map[string]any{"unvalidated": map[string]any{"tls_outcome": "handshake_failed"}}
	other := map[string]any{"unvalidated": map[string]any{"tls_outcome": "sni_mismatch"}}
	if !l73HandshakeFailed([]map[string]any{other, failed}) || l73HandshakeFailed([]map[string]any{other}) || l73HandshakeFailed(nil) {
		t.Fatal("handshake_failed must be read from tls_outcome alone")
	}
}

func TestL73LoginWindowsKeepLateConnectionsWithTheirLogin(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	at := func(s float64, host string) l73Conn {
		return l73Conn{Server: host + ":300", SYNAt: t0.Add(time.Duration(s * float64(time.Second)))}
	}
	conns := []l73Conn{at(-1, "h"), at(1, "h"), at(2.5, "h"), at(5, "h"), at(6, "h"), at(9, "h"), at(3, "x"), at(20, "h")}
	w := l73LoginWindows(conns, "h", []time.Time{{}, t0, t0.Add(5 * time.Second)}, t0.Add(10*time.Second))
	if len(w[0]) != 1 || len(w[1]) != 2 || len(w[2]) != 3 {
		t.Fatalf("probe %d login1 %d login2 %d", len(w[0]), len(w[1]), len(w[2]))
	}
	// A login's accounting connection opening after tokenLogin returned is
	// its own: the 2.5s one is login 1's, as a [start,end] window would lose.
}
