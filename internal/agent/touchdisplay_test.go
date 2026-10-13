package agent

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/hwkey"
)

// A hardware key that fails the handshake's signature (not touched in time,
// locked, or gone) is the key's failure. crypto/tls flattens the signer's
// error to text, so the dialer reads it from a recorder around the key. The
// operator is told what the key said, as the key's own error: not that the
// broker is unreachable, and not as a broker_error on the socket. The Sign is
// asked once per ask (no retry that would blink the key a second time), and
// the session stays up.
func TestAKeyFailureAtTheHandshakeIsTheKeysOwnErrorAndIsNotRetried(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code string
		// words is what the operator reads: the key's own for a touch
		// timeout, Task 6's for a key that is gone or locked.
		words string
	}{
		{"a touch timeout", hwkey.ErrTouchTimeout, "touch_timeout", hwkey.ErrTouchTimeout.Error()},
		{"a locked key", hwkey.ErrLocked, "key_locked", "run `port49 login`"},
		{"a key that is gone", hwkey.ErrKeyAbsent, "key_absent", "insert your key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRigWith(t, rigOpts{hw: true})
			if _, err := r.a.Connect(context.Background()); err != nil {
				t.Fatal(err)
			}
			r.key.signErr = tc.err
			c := socketFor(t, r.a)
			for _, ask := range []struct {
				name   string
				socket bool
				do     func() error
			}{
				{"mint", false, func() error { _, err := r.a.Mint(context.Background(), "leaf1", false, 0, ""); return err }},
				{"mint through the socket", true, func() error {
					_, err := c.Token(context.Background(), TokenRequest{Device: "leaf1"})
					return err
				}},
				{"identity", false, func() error { _, err := r.a.Identity(context.Background()); return err }},
				{"identity through the socket", true, func() error { _, err := c.Identity(context.Background()); return err }},
				{"refresh", false, func() error { _, err := r.a.Refresh(context.Background(), ""); return err }},
				{"refresh through the socket", true, func() error { _, err := c.Refresh(context.Background(), ""); return err }},
			} {
				r.srv.CloseClientConnections()
				r.a.client.CloseIdleConnections()
				r.key.mu.Lock()
				before := r.key.signs
				r.key.mu.Unlock()
				err := ask.do()
				var ke *KeyError
				if !errors.As(err, &ke) || !errors.Is(err, tc.err) || KeyCode(err) != tc.code {
					t.Fatalf("%s: %v, want a *KeyError for %v (code %s)", ask.name, err, tc.err, tc.code)
				}
				if !strings.Contains(err.Error(), tc.words) {
					t.Errorf("%s: %q does not carry the words %q", ask.name, err, tc.words)
				}
				for _, bad := range []string{"unreachable", "broker_error", "refresh_failed", "internal error"} {
					if strings.Contains(err.Error(), bad) {
						t.Errorf("%s: %q says %q", ask.name, err, bad)
					}
				}
				r.key.mu.Lock()
				n := r.key.signs - before
				r.key.mu.Unlock()
				if n != 1 {
					t.Errorf("%s: the key was asked to sign %d times, want 1 (no retry)", ask.name, n)
				}
				select {
				case <-r.a.Done():
					t.Fatalf("%s: a key failure ended the session", ask.name)
				default:
				}
			}

			// And the next ask, with the key answering, goes through.
			r.key.mu.Lock()
			r.key.signErr = nil
			r.key.mu.Unlock()
			r.srv.CloseClientConnections()
			r.a.client.CloseIdleConnections()
			if _, err := r.a.Mint(context.Background(), "leaf1", false, 0, ""); err != nil {
				t.Fatalf("after the key answered: %v", err)
			}
		})
	}
}

// The socket's answer carries the code itself, snake_case, and not
// broker_error.
func TestTheSocketAnswersAKeyFailureWithItsOwnCode(t *testing.T) {
	for _, tc := range []struct {
		err   error
		code  string
		words string
	}{
		{hwkey.ErrTouchTimeout, "touch_timeout", hwkey.ErrTouchTimeout.Error()},
		{hwkey.ErrLocked, "key_locked", "run `port49 login`"},
		{hwkey.ErrKeyAbsent, "key_absent", "insert your key"},
	} {
		r := newRigWith(t, rigOpts{hw: true})
		if _, err := r.a.Connect(context.Background()); err != nil {
			t.Fatal(err)
		}
		c := socketFor(t, r.a)
		r.key.signErr = tc.err
		hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", c.socket)
		}}}
		for _, path := range []string{"/token", "/refresh"} {
			r.srv.CloseClientConnections()
			r.a.client.CloseIdleConnections()
			body := strings.NewReader(`{"device":"leaf1"}`)
			resp, err := hc.Post("http://agent"+path, "application/json", body)
			if err != nil {
				t.Fatal(err)
			}
			var e api.Error
			_ = json.NewDecoder(resp.Body).Decode(&e)
			resp.Body.Close()
			if e.Error != tc.code || !strings.Contains(e.Detail, tc.words) {
				t.Errorf("%s with %v: code %q detail %q, want %s", path, tc.err, e.Error, e.Detail, tc.code)
			}
		}
	}
}

// A key failure is not attributed to a later dial that failed for another
// reason: the broker not answering is still "unreachable", and the recorder is
// cleared by a Sign that succeeds.
func TestAnOldKeyFailureIsNotBlamedForALaterOutage(t *testing.T) {
	r := newRigWith(t, rigOpts{hw: true})
	if _, err := r.a.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.key.signErr = hwkey.ErrTouchTimeout
	r.srv.CloseClientConnections()
	r.a.client.CloseIdleConnections()
	if _, err := r.a.Mint(context.Background(), "leaf1", false, 0, ""); KeyCode(err) != "touch_timeout" {
		t.Fatalf("setup: %v", err)
	}
	r.key.mu.Lock()
	r.key.signErr = nil
	r.key.mu.Unlock()
	r.fault.Store(true) // the broker drops the handshake before the key signs
	r.srv.CloseClientConnections()
	r.a.client.CloseIdleConnections()
	_, err := r.a.Mint(context.Background(), "leaf1", false, 0, "")
	if err == nil || KeyCode(err) != "" || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("Mint during an outage = %v, want the broker unreachable and no key error", err)
	}
}

// Each dial has its own recorder. One dial's handshake is held at the broker
// while another's key fails; the held one then fails for the broker's reasons
// and must not be reported as the other dial's key error.
func TestTwoConcurrentDialsNeverSeeEachOthersSignError(t *testing.T) {
	r := newRigWith(t, rigOpts{hw: true})
	r.key.signErr = hwkey.ErrLocked
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	go func() { // accepts and says nothing: the handshake waits for its deadline
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	var brokerErr, keyErr error
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		close(started)
		_, brokerErr = r.a.dialTLS(ctx, "tcp", silent.Addr().String())
	}()
	<-started
	time.Sleep(100 * time.Millisecond) // the silent dial is under way
	_, keyErr = r.a.dialTLS(context.Background(), "tcp", r.srv.Listener.Addr().String())
	<-done
	if KeyCode(keyErr) != "key_locked" {
		t.Errorf("the dial whose key failed = %v, want its own key_locked", keyErr)
	}
	if brokerErr == nil || KeyCode(brokerErr) != "" {
		t.Errorf("the dial the broker never answered = %v, want a plain error, not the other dial's key error", brokerErr)
	}
}

func TestTheRecorderForgetsAnErrorOnceTheKeySigns(t *testing.T) {
	k := newFakeKey(t, hwkey.Present)
	k.signErr = hwkey.ErrLocked
	rec := &signRecorder{Signer: k}
	digest := make([]byte, 32)
	if _, err := rec.Sign(nil, digest, crypto.SHA256); err == nil {
		t.Fatal("the fake key signed")
	}
	if rec.keyError() == nil {
		t.Fatal("the recorder holds no error after a failed Sign")
	}
	k.mu.Lock()
	k.signErr = nil
	k.mu.Unlock()
	if _, err := rec.Sign(nil, digest, crypto.SHA256); err != nil {
		t.Fatal(err)
	}
	if rec.keyError() != nil {
		t.Fatal("the recorder still holds an error after a Sign that succeeded")
	}
}

// The first connect, at login, says the same.
func TestAKeyFailureAtConnectIsShownAsItIs(t *testing.T) {
	for _, e := range []error{hwkey.ErrTouchTimeout, hwkey.ErrLocked, hwkey.ErrKeyAbsent} {
		r := newRigWith(t, rigOpts{hw: true, signErr: e})
		_, err := r.a.Connect(context.Background())
		var ke *KeyError
		if !errors.As(err, &ke) || !errors.Is(err, e) || strings.Contains(err.Error(), "unreachable") {
			t.Fatalf("Connect with %v = %v, want a *KeyError", e, err)
		}
		r.key.mu.Lock()
		n := r.key.signs
		r.key.mu.Unlock()
		if n != 1 {
			t.Errorf("Connect with %v: %d Signs, want 1", e, n)
		}
	}
}
