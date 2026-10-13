package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/broker/api"
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
