package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/hwkey"
)

// mfaChallenge asks the broker to mint leaf1 and returns the challenge it
// answers with, and the requirement it came in.
func mfaChallenge(t *testing.T, r *realRig) (string, api.PerLoginMFA) {
	t.Helper()
	_, err := r.a.Mint(context.Background(), "leaf1", false, 0, "")
	var need *MFARequiredError
	if !errors.As(err, &need) || need.Requirement.Challenge == "" {
		t.Fatalf("the mint under a requirement: %v", err)
	}
	return need.Requirement.Challenge, need.Requirement
}

// A mint under a per-login requirement is an *MFARequiredError carrying the
// requirement; a touch proves it over the held connection, and the mint made
// again naming the challenge is a permit, once.
func TestAMintUnderARequirementIsProvedByATouchAndMintedAgain(t *testing.T) {
	r := newRealRigWith(t, realOpts{mfa: true})
	ch, req := mfaChallenge(t, r)
	if req.Device != "leaf1" || len(req.Methods) != 1 || req.Methods[0] != "hardware_key_touch" {
		t.Fatalf("the requirement: %+v", req)
	}
	if err := r.a.ProveTouch(context.Background(), ch); err != nil {
		t.Fatal(err)
	}
	item, err := r.a.Mint(context.Background(), "leaf1", false, 0, ch)
	if err != nil || item.Verdict != "permit" || item.Login == "" {
		t.Fatalf("the mint naming the challenge: %v %v", item.Verdict, err)
	}
	if r.touch.Signs() != 1 {
		t.Errorf("the touch key signed %d times, want 1", r.touch.Signs())
	}
}

// Over the agent's socket the requirement is a 428 the client rebuilds, and a
// touch is POST /mfa/touch.
func TestTheRequirementAndTheTouchTravelTheSocket(t *testing.T) {
	r := newRealRigWith(t, realOpts{mfa: true})
	c := socketFor(t, r.a)
	ctx := context.Background()
	_, err := c.Token(ctx, TokenRequest{Device: "leaf1"})
	var need *MFARequiredError
	if !errors.As(err, &need) || need.Requirement.Challenge == "" || need.Requirement.ReuseFrom == "" {
		t.Fatalf("Token under a requirement: %v", err)
	}
	if err := c.ProveTouch(ctx, need.Requirement.Challenge); err != nil {
		t.Fatal(err)
	}
	item, err := c.Token(ctx, TokenRequest{Device: "leaf1", PerLoginMFAChallenge: need.Requirement.Challenge})
	if err != nil || item.Verdict != "permit" {
		t.Fatalf("Token naming the challenge: %+v %v", item.Verdict, err)
	}
	st, err := c.Status(ctx)
	if err != nil || !st.TouchKey {
		t.Fatalf("status: %+v %v", st, err)
	}
}

// A refresh that left a context for want of a proof answers with the one
// challenge to prove; proved, a second refresh naming it extends the context
// with no pacing between the two.
func TestARefreshIsProvedOnceAndRefreshesAgain(t *testing.T) {
	r := newRealRigWith(t, realOpts{mfa: true})
	c := socketFor(t, r.a)
	ctx := context.Background()
	out, err := c.Refresh(ctx, "")
	if err != nil || out.PerLoginMFA == nil || out.PerLoginMFA.Challenge == "" {
		t.Fatalf("the first refresh: %+v %v", out, err)
	}
	if len(out.Sessions) != 1 || out.Sessions[0].Outcome != "per_login_mfa_required" {
		t.Fatalf("the first refresh's contexts: %+v", out.Sessions)
	}
	ch := out.PerLoginMFA.Challenge
	if err := c.ProveTouch(ctx, ch); err != nil {
		t.Fatal(err)
	}
	out, err = c.Refresh(ctx, ch)
	if err != nil || out.PerLoginMFA != nil || len(out.Sessions) != 1 || out.Sessions[0].Outcome != "extended" {
		t.Fatalf("the second refresh: %+v %v", out, err)
	}
}

// Refresh's pre-check on the key's state comes before any challenge is asked
// for or posted, whatever challenge it is given.
func TestARefreshNamingAChallengeStillChecksTheKeyFirst(t *testing.T) {
	r := newRealRigWith(t, realOpts{mfa: true})
	r.session.SetState(hwkey.Absent)
	before := r.session.Signs()
	_, err := r.a.Refresh(context.Background(), "AAAA")
	var gone *KeyAbsentError
	if !errors.As(err, &gone) || gone.State != hwkey.Absent {
		t.Fatalf("a refresh with the key gone: %v", err)
	}
	if got := r.logs.String(); strings.Contains(got, "per_login_mfa") {
		t.Fatalf("the broker was asked about a proof: %s", got)
	}
	if r.session.Signs() != before {
		t.Error("the key was asked to sign for a refresh it is not there for")
	}
}

// A touch that is not made in time is the key's own error, once: never
// retried (a retry would blink the key again for a touch nobody made), the
// session kept, and the same words on the socket.
func TestAMissedTouchIsTheKeysOwnErrorAndIsNotRetried(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code string
	}{
		{"a touch timeout", hwkey.ErrTouchTimeout, "touch_timeout"},
		{"a locked key", hwkey.ErrLocked, "key_locked"},
		{"a key that is gone", hwkey.ErrKeyAbsent, "key_absent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRealRigWith(t, realOpts{mfa: true})
			c := socketFor(t, r.a)
			ch, _ := mfaChallenge(t, r)
			r.touch.OnSign(func() error { return tc.err })
			for _, ask := range []struct {
				name string
				do   func() error
			}{
				{"agent", func() error { return r.a.ProveTouch(context.Background(), ch) }},
				{"socket", func() error { return c.ProveTouch(context.Background(), ch) }},
			} {
				before := r.touch.Signs()
				err := ask.do()
				var ke *KeyError
				if !errors.As(err, &ke) || !errors.Is(err, tc.err) || KeyCode(err) != tc.code {
					t.Fatalf("%s: %v, want a *KeyError for %v", ask.name, err, tc.err)
				}
				if n := r.touch.Signs() - before; n != 1 {
					t.Errorf("%s: the touch key signed %d times, want 1", ask.name, n)
				}
				if tc.err == hwkey.ErrTouchTimeout && !strings.Contains(err.Error(), "no touch within 15s; touch the key when it blinks and try again") {
					t.Errorf("%s: %q", ask.name, err)
				}
			}
			select {
			case <-r.a.Done():
				t.Fatal("a missed touch ended the session")
			default:
			}
			// The challenge is unspent: a touch made now proves it.
			r.touch.OnSign(nil)
			if err := r.a.ProveTouch(context.Background(), ch); err != nil {
				t.Fatalf("the touch made at last: %v", err)
			}
		})
	}
}

// With no touch key the agent says so, and signs nothing.
func TestProveTouchWithNoTouchKeyIsRefused(t *testing.T) {
	r := newRig(t)
	err := r.a.ProveTouch(context.Background(), "AAAA")
	if err == nil || !strings.Contains(err.Error(), "no touch_key is configured") {
		t.Fatalf("%v", err)
	}
}

// ruling 14, re-review R6: the wire is held to read the exporter value and to
// post, never across the touch. A connection replaced while the key waited for
// its touch makes the signature one over a connection that is gone: it is
// not posted (so no per_login_mfa_refused is recorded) and the challenge stays
// unspent.
func TestAConnectionChangedDuringTheTouchIsNotPosted(t *testing.T) {
	r := newRealRigWith(t, realOpts{mfa: true})
	ctx := context.Background()
	ch, _ := mfaChallenge(t, r)
	entered, release := make(chan struct{}), make(chan struct{})
	r.touch.OnSign(func() error {
		close(entered)
		<-release
		return nil
	})
	done := make(chan error, 1)
	go func() { done <- r.a.ProveTouch(ctx, ch) }()
	<-entered
	// The wire is free during the touch: anything else the agent does goes
	// at once, and a connection dropped now is dialed again by it.
	handshakes := r.a.Handshakes()
	r.a.client.CloseIdleConnections()
	_, _ = r.a.Identity(ctx)
	if r.a.Handshakes() == handshakes {
		t.Fatal("the held connection was not replaced")
	}
	close(release)
	if err := <-done; !errors.Is(err, ErrConnectionChanged) {
		t.Fatalf("ProveTouch over a replaced connection: %v", err)
	}
	if got := r.logs.String(); strings.Contains(got, "per_login_mfa_refused") || strings.Contains(got, "per_login_mfa_proved") {
		t.Fatalf("the broker judged a proof: %s", got)
	}
	// Unspent: touched at once on the new connection, the same challenge is 200.
	r.touch.OnSign(nil)
	if err := r.a.ProveTouch(ctx, ch); err != nil {
		t.Fatalf("the same challenge on the new connection: %v", err)
	}
	if got := r.logs.String(); !strings.Contains(got, "per_login_mfa_proved") {
		t.Fatalf("the broker recorded no proof: %s", got)
	}
}

// A proof is posted to the broker named and nowhere else: a redirect from
// /v1/mfa is not followed (a 303 would be followed as a GET carrying the
// agent session header to whatever it names), and it is not a 200.
func TestAProofIsNotPostedWhereARedirectSends(t *testing.T) {
	var hits atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(elsewhere.Close)
	r := newRealRigWith(t, realOpts{mfa: true, redirectMFA: elsewhere.URL + "/v1/mfa"})
	ch, _ := mfaChallenge(t, r)
	err := r.a.ProveTouch(context.Background(), ch)
	if err == nil || !strings.Contains(err.Error(), "303") {
		t.Fatalf("a proof answered with a redirect: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("the redirect was followed: %d requests reached the other server", hits.Load())
	}
}

// Task 8: the CRL check applies to the proof's connection. A broker
// certificate the check refuses is the check's own error, unwrapped, never
// "unreachable", never retried, and the key is not touched for it.
func TestAProofToABrokerTheCRLCheckRefusesIsRefusedUnwrapped(t *testing.T) {
	var refuse atomic.Bool
	r := newRealRigWith(t, realOpts{mfa: true, verify: func(tls.ConnectionState) error {
		if refuse.Load() {
			return errors.New("certificate serial 0x1 is revoked by the broker CA's CRL")
		}
		return nil
	}})
	ch, _ := mfaChallenge(t, r)
	refuse.Store(true)
	r.a.client.CloseIdleConnections()
	before := r.touch.Signs()
	err := r.a.ProveTouch(context.Background(), ch)
	var no *BrokerRefusedError
	if !errors.As(err, &no) || strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("ProveTouch to a revoked broker: %v", err)
	}
	if r.touch.Signs() != before {
		t.Error("the key was touched for a broker the check refused")
	}
	select {
	case <-r.a.Done():
		t.Fatal("the check's refusal ended the session")
	case <-time.After(10 * time.Millisecond):
	}
}
