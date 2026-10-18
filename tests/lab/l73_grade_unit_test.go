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

func TestL73LoginWindowsGiveEveryLoginTheSameTail(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	at := func(s float64, host string) l73Conn {
		return l73Conn{Server: host + ":300", SYNAt: t0.Add(time.Duration(s * float64(time.Second)))}
	}
	// login 1 spans 1s-2s, login 2 spans 7s-8s; the tail is 5s.
	spans := []l73Span{{t0.Add(time.Second), t0.Add(2 * time.Second)}, {t0.Add(7 * time.Second), t0.Add(8 * time.Second)}}
	conns := []l73Conn{at(0.5, "h"), at(1, "h"), at(6.9, "h"), at(7, "h"), at(12.9, "h"), at(13.1, "h"), at(3, "x")}
	w := l73LoginWindows(conns, "h", spans)
	// 6.9s is 4.9s after login 1 returned and 12.9s is 4.9s after login 2: each
	// keeps its own late connection; 7s and 13.1s fall outside the other tail.
	if len(w[0]) != 2 || len(w[1]) != 2 || w[0][1].SYNAt != t0.Add(6900*time.Millisecond) || w[1][1].SYNAt != t0.Add(12900*time.Millisecond) {
		t.Fatalf("login1 %+v login2 %+v", w[0], w[1])
	}
}
