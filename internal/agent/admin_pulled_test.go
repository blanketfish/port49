package agent

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/blanketfish/port49/internal/hwkey"
)

// L86 (d): the touch key pulled with the agent running. State still says what
// it last saw, as a real token's Signer does until something looks, so the
// agent looks before it asks: no request reaches the broker, no challenge is
// issued, nothing is signed, and the error is the key's absence.
func TestAPulledTouchKeySendsNothing(t *testing.T) {
	r := newRealRigWith(t, realOpts{mfa: true, admin: true})
	r.touch.Pull(true)
	if r.touch.State() != hwkey.Present {
		t.Fatal("the fake's State saw the pull: the test would not show the stale state")
	}
	var prompts []string
	_, err := r.a.AdminPrompt(context.Background(), revokeCall(bobBody), func(l string) { prompts = append(prompts, l) })
	var ka *KeyAbsentError
	if !errors.As(err, &ka) || ka.State != hwkey.Absent || !ka.Held {
		t.Fatalf("got %v, want a *KeyAbsentError for an absent key on the held connection", err)
	}
	if len(prompts) != 0 {
		t.Fatalf("prompted %q for a key that is out", prompts)
	}
	if n := r.logRecords(t, "admin_touch", ""); n != 0 {
		t.Fatalf("the broker recorded %d admin_touch records, want 0: the request was sent", n)
	}
	if r.logRecords(t, "revoke", "") != 0 || r.touch.Signs() != 0 {
		t.Fatal("the revocation ran or the key signed")
	}
}

// A present key still sends exactly once: one challenge, one proof, one sign.
func TestAPresentTouchKeySendsOnce(t *testing.T) {
	r := newRealRigWith(t, realOpts{mfa: true, admin: true})
	out, err := r.a.Admin(context.Background(), revokeCall(bobBody))
	if err != nil || out.Status != http.StatusOK {
		t.Fatalf("%d %v", out.Status, err)
	}
	if n := r.logRecords(t, "admin_touch", "admin_touch_required"); n != 1 {
		t.Fatalf("the broker issued %d challenges, want 1", n)
	}
	if n := r.logRecords(t, "admin_touch", "admin_touch_proved"); n != 1 {
		t.Fatalf("the broker proved %d touches, want 1", n)
	}
	if r.touch.Signs() != 1 {
		t.Fatalf("the key signed %d times, want 1", r.touch.Signs())
	}
}
