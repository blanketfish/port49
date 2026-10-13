package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/brokercrl"
)

// A broker the CRL check refuses, met through the socket, is its own code
// (broker_refused) and is rebuilt by the Client as a *BrokerRefusedError that
// still wraps the check's own type, so a caller's errors.As works across the
// socket as it does in-process (Task 8 parity). It is never "unreachable" and
// is asked once.
func TestTheSocketCarriesABrokerRefusalWithItsOwnCode(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cause error
		check func(t *testing.T, err error)
	}{
		{"revoked", &brokercrl.RevokedError{Subject: "CN=broker", Serial: "7", List: "http://crl.example/ca.crl"},
			func(t *testing.T, err error) {
				var revoked *brokercrl.RevokedError
				if !errors.As(err, &revoked) || revoked.Serial != "7" || revoked.List != "http://crl.example/ca.crl" {
					t.Errorf("%v, want a wrapped *brokercrl.RevokedError with its serial and list", err)
				}
			}},
		{"unchecked", &brokercrl.UncheckedError{Detail: "the CRL server did not answer"},
			func(t *testing.T, err error) {
				var unchecked *brokercrl.UncheckedError
				if !errors.As(err, &unchecked) || unchecked.Detail != "the CRL server did not answer" {
					t.Errorf("%v, want a wrapped *brokercrl.UncheckedError", err)
				}
			}},
		{"other", errors.New("some other refusal"), func(*testing.T, error) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var refuse atomic.Bool
			var calls atomic.Int32
			r := newRigWith(t, rigOpts{verify: func(tls.ConnectionState) error {
				calls.Add(1)
				if refuse.Load() {
					return tc.cause
				}
				return nil
			}})
			if _, err := r.a.Connect(context.Background()); err != nil {
				t.Fatal(err)
			}
			c := socketFor(t, r.a)
			refuse.Store(true)
			for _, ask := range []struct {
				name string
				do   func() error
			}{
				{"token", func() error { _, err := c.Token(context.Background(), TokenRequest{Device: "leaf1"}); return err }},
				{"refresh", func() error { _, err := c.Refresh(context.Background(), ""); return err }},
				{"identity", func() error { _, err := c.Identity(context.Background()); return err }},
			} {
				r.srv.CloseClientConnections()
				r.a.client.CloseIdleConnections()
				before := calls.Load()
				err := ask.do()
				var refused *BrokerRefusedError
				if !errors.As(err, &refused) || strings.Contains(err.Error(), "unreachable") {
					t.Fatalf("%s: %v, want a *BrokerRefusedError and not 'unreachable'", ask.name, err)
				}
				if err.Error() != (&BrokerRefusedError{Err: tc.cause}).Error() {
					t.Errorf("%s: %q, want the check's own words %q", ask.name, err.Error(), (&BrokerRefusedError{Err: tc.cause}).Error())
				}
				tc.check(t, err)
				if n := calls.Load() - before; n != 1 {
					t.Errorf("%s: the check ran %d times, want 1 (no retry)", ask.name, n)
				}
			}
			select {
			case <-r.a.Done():
				t.Fatal("a CRL refusal ended the session")
			default:
			}
		})
	}
}

// The code itself on the wire is broker_refused, not broker_error.
func TestTheSocketsCodeForABrokerRefusalIsBrokerRefused(t *testing.T) {
	var refuse atomic.Bool
	r := newRigWith(t, rigOpts{verify: func(tls.ConnectionState) error {
		if refuse.Load() {
			return errors.New("revoked")
		}
		return nil
	}})
	if _, err := r.a.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	c := socketFor(t, r.a)
	refuse.Store(true)
	for _, path := range []string{"/token", "/refresh"} {
		r.srv.CloseClientConnections()
		r.a.client.CloseIdleConnections()
		var body io.Reader = http.NoBody // /refresh takes no field but the challenge
		if path == "/token" {
			body = strings.NewReader(`{"device":"leaf1"}`)
		}
		resp, err := c.http.Post("http://agent"+path, "application/json", body)
		if err != nil {
			t.Fatal(err)
		}
		var e api.Error
		_ = json.NewDecoder(resp.Body).Decode(&e)
		resp.Body.Close()
		if e.Error != "broker_refused" {
			t.Errorf("%s: code %q, want broker_refused", path, e.Error)
		}
	}
}

// POST /refresh's body is the optional challenge and nothing else: no body
// and {} are a refresh, and a field it does not know is a 400 naming it, so a
// misspelled challenge is never dropped in silence (which would refresh
// without the proof and leave it unspent).
func TestTheRefreshSocketRefusesAnUnknownField(t *testing.T) {
	r := newRig(t)
	c := socketFor(t, r.a)
	post := func(body string) (int, api.Error) {
		var rd io.Reader = http.NoBody
		if body != "" {
			rd = strings.NewReader(body)
		}
		resp, err := c.http.Post("http://agent/refresh", "application/json", rd)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var e api.Error
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return resp.StatusCode, e
	}
	code, e := post(`{"per_login_mfa_chalenge":"abc"}`)
	if code != http.StatusBadRequest || e.Error != "bad_request" || !strings.Contains(e.Detail, "per_login_mfa_chalenge") {
		t.Fatalf("a misspelled field: %d %+v, want 400 bad_request naming the field", code, e)
	}
	if code, e = post(`{"device":"leaf1"}`); code != http.StatusBadRequest || !strings.Contains(e.Detail, "device") {
		t.Fatalf("an unrelated field: %d %+v, want 400 naming it", code, e)
	}
	for _, body := range []string{"", "{}"} {
		if code, e = post(body); code == http.StatusBadRequest {
			t.Fatalf("body %q: %d %+v, want a refresh", body, code, e)
		}
	}
}
