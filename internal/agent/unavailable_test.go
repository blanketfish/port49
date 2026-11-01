package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/hwkey"
)

// A broker the agent could not reach, or one that answered 503, is its own
// socket code (broker_unavailable) and is rebuilt by the Client as a
// *BrokerUnavailableError, so a caller can tell an outage (try again) from a
// fault (do not). A hollow answer from the broker stays a plain error.
func TestTheSocketCarriesABrokerOutageWithItsOwnCode(t *testing.T) {
	for _, tc := range []struct {
		name        string
		setup       func(r *rig)
		unavailable bool
	}{
		{"unreachable", func(r *rig) { r.srv.CloseClientConnections(); r.srv.Close() }, true},
		{"503", func(r *rig) { r.fb.mu.Lock(); r.fb.certStatus = true; r.fb.mu.Unlock() }, true},
		{"a hollow answer", func(r *rig) { r.fb.mu.Lock(); r.fb.hollow = true; r.fb.mu.Unlock() }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			c := socketFor(t, r.a)
			tc.setup(r)
			_, err := c.Token(context.Background(), TokenRequest{Device: "leaf1"})
			var down *BrokerUnavailableError
			if got := errors.As(err, &down); got != tc.unavailable || err == nil {
				t.Fatalf("%v: BrokerUnavailableError %v, want %v", err, got, tc.unavailable)
			}
			if tc.unavailable && !strings.HasPrefix(err.Error(), "agent: ") {
				t.Errorf("%q lost its agent prefix", err)
			}
			resp, perr := c.http.Post("http://agent/token", "application/json", strings.NewReader(`{"device":"leaf1"}`))
			if perr != nil {
				t.Fatal(perr)
			}
			var e api.Error
			_ = json.NewDecoder(resp.Body).Decode(&e)
			resp.Body.Close()
			if (e.Error == "broker_unavailable") != tc.unavailable {
				t.Errorf("code %q (status %d), unavailable %v", e.Error, resp.StatusCode, tc.unavailable)
			}
			if tc.unavailable && resp.StatusCode != http.StatusServiceUnavailable {
				t.Errorf("status %d, want 503", resp.StatusCode)
			}
		})
	}
}

// A key error under an outage wrapper (the race in ProveTouch's post) is still
// the key's code, as POST /token has it: key_locked, not broker_unavailable.
func TestAnswerSaysAKeyErrorBeforeAnOutage(t *testing.T) {
	err := &BrokerUnavailableError{fmt.Errorf("agent: the broker at x is unreachable: %w", &KeyError{Err: hwkey.ErrLocked})}
	w := httptest.NewRecorder()
	answer(w, struct{}{}, err)
	var e api.Error
	_ = json.Unmarshal(w.Body.Bytes(), &e)
	if e.Error != "key_locked" {
		t.Fatalf("status %d code %q, want key_locked", w.Code, e.Error)
	}
}

// A touch proof that meets a broker outage is the same typed error as a mint
// that does (so `port49 token --json` never tells the person to prove a second
// factor when the broker is the problem); one the broker refused is an
// *APIError; both across the socket.
func TestATouchProofMeetsABrokerOutageAndARefusalWithTheirOwnErrors(t *testing.T) {
	t.Run("unreachable", func(t *testing.T) {
		r := newRealRigWith(t, realOpts{mfa: true})
		ch, _ := mfaChallenge(t, r)
		c := socketFor(t, r.a)
		r.a.broker = "https://127.0.0.1:1" // nothing listens: a broker that is down
		r.a.client.CloseIdleConnections()
		r.a.mfaClient.CloseIdleConnections()
		err := c.ProveTouch(context.Background(), ch)
		var down *BrokerUnavailableError
		if !errors.As(err, &down) {
			t.Fatalf("%v, want a *BrokerUnavailableError", err)
		}
	})
	t.Run("refused", func(t *testing.T) {
		r := newRealRigWith(t, realOpts{mfa: true})
		ch, _ := mfaChallenge(t, r)
		c := socketFor(t, r.a)
		if err := c.ProveTouch(context.Background(), ch); err != nil {
			t.Fatal(err)
		}
		err := c.ProveTouch(context.Background(), ch) // a challenge already proved: the broker refuses it
		var refused *APIError
		var down *BrokerUnavailableError
		if !errors.As(err, &refused) || errors.As(err, &down) || refused.Status >= 500 {
			t.Fatalf("%v, want a 4xx *APIError", err)
		}
	})
}
