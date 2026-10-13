package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/hwkey"
)

// A key not touched in time fails the handshake's signature. crypto/tls
// flattens that error to text, so the agent finds it again by its words. The
// operator is told what the error says, verbatim: not that the broker is
// unreachable, not that the key needs its PIN or is absent. The Sign is asked
// once per ask (no retry that would blink the key a second time), and the
// session stays up, since the key is unlocked and the next ask may try again.
func TestATouchTimeoutAtTheHandshakeIsShownAsItIs(t *testing.T) {
	r := newRigWith(t, rigOpts{hw: true})
	if _, err := r.a.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The key is wrapped as the pkcs11 signer wraps it, so the sentinel is
	// reachable only through the error's text once the handshake has had it.
	r.key.signErr = hwkey.ErrTouchTimeout
	c := socketFor(t, r.a)
	for _, tc := range []struct {
		name string
		ask  func() error
	}{
		{"mint", func() error { _, err := r.a.Mint(context.Background(), "leaf1", false, 0); return err }},
		{"mint through the socket", func() error {
			_, err := c.Token(context.Background(), TokenRequest{Device: "leaf1"})
			return err
		}},
		{"identity", func() error { _, err := r.a.Identity(context.Background()); return err }},
		{"refresh", func() error { _, err := r.a.Refresh(context.Background()); return err }},
		{"refresh through the socket", func() error { _, err := c.Refresh(context.Background()); return err }},
	} {
		r.srv.CloseClientConnections()
		r.a.client.CloseIdleConnections()
		r.key.mu.Lock()
		before := r.key.signs
		r.key.mu.Unlock()
		err := tc.ask()
		if err == nil || !strings.Contains(err.Error(), hwkey.ErrTouchTimeout.Error()) {
			t.Fatalf("%s: %v, want the touch timeout's words", tc.name, err)
		}
		for _, bad := range []string{"unreachable", "PIN", "needs its", "not present", "internal error"} {
			if strings.Contains(err.Error(), bad) {
				t.Errorf("%s: %q says %q", tc.name, err, bad)
			}
		}
		r.key.mu.Lock()
		n := r.key.signs - before
		r.key.mu.Unlock()
		if n != 1 {
			t.Errorf("%s: the key was asked to sign %d times, want 1 (no retry)", tc.name, n)
		}
		select {
		case <-r.a.Done():
			t.Fatalf("%s: a touch timeout ended the session", tc.name)
		default:
		}
		if st := r.key.State(); st != hwkey.Present {
			t.Errorf("%s: the key is %s after a touch timeout, want present", tc.name, st)
		}
	}

	// And the next ask, touched in time, goes through.
	r.key.mu.Lock()
	r.key.signErr = nil
	r.key.mu.Unlock()
	r.srv.CloseClientConnections()
	r.a.client.CloseIdleConnections()
	if _, err := r.a.Mint(context.Background(), "leaf1", false, 0); err != nil {
		t.Fatalf("after the touch: %v", err)
	}
}

// The first connect, at login, says the same.
func TestATouchTimeoutAtConnectIsShownAsItIs(t *testing.T) {
	r := newRigWith(t, rigOpts{hw: true, signErr: hwkey.ErrTouchTimeout})
	_, err := r.a.Connect(context.Background())
	if err == nil || !strings.Contains(err.Error(), hwkey.ErrTouchTimeout.Error()) ||
		strings.Contains(err.Error(), "unreachable") || strings.Contains(err.Error(), "PIN") {
		t.Fatalf("Connect = %v, want the touch timeout's words", err)
	}
}
