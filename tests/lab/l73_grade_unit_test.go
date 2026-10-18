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

func TestL73RefusedForNeedsTheCellsReason(t *testing.T) {
	rec := func(outcome, detail string) map[string]any {
		return map[string]any{"unvalidated": map[string]any{"tls_outcome": outcome, "detail": detail}}
	}
	aborted := rec("handshake_failed", "the device aborted the handshake (it may refuse port49's certificate; see x)")
	timedOut := rec("handshake_failed", "the TLS handshake did not complete")
	unknown := rec("unknown_ca", "x509: certificate signed by unknown authority (possibly because of ...)")
	if !l73RefusedFor([]map[string]any{aborted}, "handshake_failed", l73DeviceAborted) ||
		!l73RefusedFor([]map[string]any{unknown}, "unknown_ca", l73UnknownAuthority) {
		t.Fatal("the cell's own reason must be proven")
	}
	// A handshake_failed port49 ended itself, or another outcome, proves nothing.
	if l73RefusedFor([]map[string]any{timedOut, unknown}, "handshake_failed", l73DeviceAborted) ||
		l73RefusedFor([]map[string]any{aborted}, "unknown_ca", l73UnknownAuthority) || l73RefusedFor(nil, "unknown_ca", "") {
		t.Fatal("another reason was taken for the cell's")
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
