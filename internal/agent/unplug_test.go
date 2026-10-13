package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/hwkey"
)

// dropHeldConnection makes the next ask dial: the broker closes the held
// connection and the agent forgets it.
func dropHeldConnection(r *rig) {
	r.srv.CloseClientConnections()
	r.a.client.CloseIdleConnections()
}

// A key pulled out never ends the session. The held connection goes on
// minting; what needs the key (a refresh, a reconnect's handshake) says to
// insert it and ends nothing; and the key back, the next refresh works.
func TestAKeyUnpluggedNeverEndsTheSession(t *testing.T) {
	r := newRigWith(t, rigOpts{hw: true})
	r.key.backFree = true
	ctx := context.Background()
	r.key.setPresent(false)

	// The held connection mints: the key was used at the handshake.
	if _, err := r.a.Mint(ctx, "leaf1", false, 0); err != nil {
		t.Fatalf("mint on the held connection with the key out: %v", err)
	}
	// A refresh needs the key: it says so, and signs nothing.
	signs := r.key.nSigns()
	_, err := r.a.Refresh(ctx)
	var absent *KeyAbsentError
	if !errors.As(err, &absent) || absent.State != hwkey.Absent || !strings.Contains(err.Error(), "insert your key") ||
		!strings.Contains(err.Error(), "your session goes on until") {
		t.Fatalf("refresh with the key out = %v", err)
	}
	if !errors.Is(err, hwkey.ErrKeyAbsent) || KeyCode(err) != "key_absent" {
		t.Fatalf("refresh with the key out = %v, want the key_absent KeyError underneath", err)
	}
	if r.key.nSigns() != signs {
		t.Fatal("a refresh signed with a key that is out")
	}
	// A reconnect needs the key at the handshake: the broker drops the
	// connection, the next mint dials, and the handshake's signature fails
	// inside crypto/tls as text alone.
	dropHeldConnection(r)
	absent = nil
	if _, err = r.a.Mint(ctx, "leaf1", false, 0); !errors.As(err, &absent) || absent.State != hwkey.Absent {
		t.Fatalf("mint needing a reconnect with the key out = %v, want *KeyAbsentError", err)
	}
	select {
	case <-r.a.Done():
		t.Fatal("the session ended on an unplugged key")
	default:
	}
	// Re-inserted: Refresh asks State, which re-probes from Absent; nothing
	// signed in between.
	r.key.setPresent(true)
	if _, err := r.a.Refresh(ctx); err != nil {
		t.Fatalf("refresh after the key came back: %v", err)
	}
}

// A key that is back but wants its PIN says to log in, with the session's end.
func TestALockedKeyAtARefreshSaysToLogIn(t *testing.T) {
	r := newRigWith(t, rigOpts{hw: true}) // comes back Locked by default
	r.key.setPresent(false)
	_ = r.key.State()
	r.key.setPresent(true)
	_, err := r.a.Refresh(context.Background())
	var locked *KeyAbsentError
	if !errors.As(err, &locked) || locked.State != hwkey.Locked || !strings.Contains(err.Error(), "run `port49 login`") ||
		!strings.Contains(err.Error(), "your session goes on until") || KeyCode(err) != "key_locked" {
		t.Fatalf("refresh with the key back and locked = %v", err)
	}
	select {
	case <-r.a.Done():
		t.Fatal("the session ended on a locked key")
	default:
	}
}

// A touch timeout is neither absent nor locked: it keeps its own words and
// code, and is not folded into KeyAbsentError.
func TestATouchTimeoutIsNotAnAbsentKey(t *testing.T) {
	r := newRigWith(t, rigOpts{hw: true})
	r.key.signErr = hwkey.ErrTouchTimeout
	_, err := r.a.Refresh(context.Background())
	var absent *KeyAbsentError
	if errors.As(err, &absent) || KeyCode(err) != "touch_timeout" || strings.Contains(err.Error(), "insert your key") {
		t.Fatalf("refresh with a touch timeout = %v", err)
	}
}

// TestAReinsertedKeyIsSeenWithoutASignature is the 3am trace: the held
// connection never drops, so no handshake signs after the key comes back.
// The key must still be seen (decision 45 ruling 8; pre-flight C2).
func TestAReinsertedKeyIsSeenWithoutASignature(t *testing.T) {
	r := newRigWith(t, rigOpts{hw: true})
	c := socketFor(t, r.a)
	ctx := context.Background()
	status := func() string {
		st, err := c.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return st.KeyState
	}
	r.key.setPresent(false)
	if _, err := r.a.Refresh(ctx); err == nil {
		t.Fatal("refresh with the key out succeeded")
	}
	if got := status(); got != "absent" {
		t.Fatalf("status with the key out = %q, want absent", got)
	}
	// Back, and needing its PIN. No mint, no refresh, no handshake.
	r.key.setPresent(true)
	signs, probes := r.key.nSigns(), r.key.nProbes()
	if got := status(); got != "locked" {
		t.Fatalf("status after re-insertion = %q, want locked (State must re-probe from Absent)", got)
	}
	if r.key.nSigns() != signs || r.key.nProbes() == probes {
		t.Fatalf("seen by %d signs and %d probes; want a probe and no sign", r.key.nSigns()-signs, r.key.nProbes()-probes)
	}
	// Absent then Present on the next probe, no PIN needed: present at once.
	r.key.setPresent(false)
	_, _ = r.a.Refresh(ctx)
	r.key.mu.Lock()
	r.key.backFree = true
	r.key.mu.Unlock()
	r.key.setPresent(true)
	if got := status(); got != "present" {
		t.Fatalf("status after re-insertion = %q, want present", got)
	}
}

// The change must not swallow a real refusal: with the key present and the
// broker refusing the certificate at a reconnect, the session ends.
func TestARefusedCertificateStillEndsTheSession(t *testing.T) {
	r := newRigWith(t, rigOpts{hw: true})
	r.refuse.Store(true)
	dropHeldConnection(r)
	if _, err := r.a.Mint(context.Background(), "leaf1", false, 0); err == nil {
		t.Fatal("mint after a refused reconnect succeeded")
	}
	select {
	case <-r.a.Done():
	default:
		t.Fatal("a refused certificate did not end the session")
	}
}
