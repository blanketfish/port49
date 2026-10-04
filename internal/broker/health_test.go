package broker

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
)

// brokenStore is a store that is down: every read a mint begins with, and
// every write one makes, fails, so a test can see that nothing a probe
// answers depends on the store.
type brokenStore struct{ store.Store }

var errStoreDown = errors.New("store down")

func (brokenStore) GetRevocation(context.Context, string, string) (store.Revocation, error) {
	return store.Revocation{}, errStoreDown
}

func (brokenStore) ListRevocations(context.Context) ([]store.Revocation, error) {
	return nil, errStoreDown
}

func (brokenStore) PutBlob(context.Context, string, []byte, time.Duration) error { return errStoreDown }

// /healthz is 200 while the handler answers; /readyz is 503 until the
// broker serves, 200 while it does, 503 from shutdown; neither needs a
// certificate or writes a record, and a store that fails every call does
// not move either, while a mint on the same broker is refused
// store_unavailable by it (design §12; decision 34).
func TestHealthAndReadiness(t *testing.T) {
	f := newFixture(t, 8)
	f.b.Store = brokenStore{f.st}
	get := func(path string) (int, string) {
		n := f.log.Len()
		w := httptest.NewRecorder()
		f.b.Handler().ServeHTTP(w, httptest.NewRequest("GET", path, nil)) // no TLS at all
		if f.log.Len() != n {
			t.Fatalf("%s wrote a record: %s", path, f.log.String()[n:])
		}
		return w.Code, strings.TrimSpace(w.Body.String())
	}
	if code, body := get("/healthz"); code != 200 || body != "ok" {
		t.Fatalf("healthz: %d %q", code, body)
	}
	if code, body := get("/readyz"); code != 503 || body != ReadyStarting {
		t.Fatalf("readyz before serving: %d %q", code, body)
	}
	f.b.SetReady(ReadyServing)
	// The store is down for this broker: a mint is refused for it.
	if w := f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, ""); w.Code != 503 ||
		!strings.Contains(w.Body.String(), `"store_unavailable"`) {
		t.Fatalf("a mint with the store down: %s", answer(w))
	}
	if code, body := get("/readyz"); code != 200 || body != ReadyServing {
		t.Fatalf("readyz serving, store down: %d %q", code, body)
	}
	if code, body := get("/healthz"); code != 200 || body != "ok" {
		t.Fatalf("healthz, store down: %d %q", code, body)
	}
	f.b.SetReady(ReadyDraining)
	if code, body := get("/readyz"); code != 503 || body != ReadyDraining {
		t.Fatalf("readyz draining: %d %q", code, body)
	}
	// Each process names itself (Task 15a C1).
	if ReadyDrainingOf("port49d") != ReadyDraining {
		t.Fatalf("port49d drains as %q", ReadyDrainingOf("port49d"))
	}
	f.b.SetReady(ReadyDrainingOf("port49-broker"))
	if code, body := get("/readyz"); code != 503 || body != "draining: port49-broker is shutting down" {
		t.Fatalf("readyz draining port49-broker: %d %q", code, body)
	}

	// With no store at all, any store call a probe made would panic here,
	// brokenStore's own methods included.
	f.b.Store = nil
	f.b.SetReady(ReadyServing)
	if code, body := get("/readyz"); code != 200 || body != ReadyServing {
		t.Fatalf("readyz, no store: %d %q", code, body)
	}
	if code, body := get("/healthz"); code != 200 || body != "ok" {
		t.Fatalf("healthz, no store: %d %q", code, body)
	}
}

// While the mint gate refuses the policy in force, /readyz answers 503 so a
// load balancer sends mints to a replica that can mint; once it opens,
// serving again (Task 15a re-review 2, M-8). Draining still says draining.
func TestReadinessFollowsTheMintGate(t *testing.T) {
	f := newFixture(t, 8)
	get := func() (int, string) {
		w := httptest.NewRecorder()
		f.b.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
		return w.Code, strings.TrimSpace(w.Body.String())
	}
	shut := true
	f.b.MintGate = func(*policy.Policy) error {
		if shut {
			return errors.New("not yet flagged")
		}
		return nil
	}
	f.b.SetReady(ReadyServing)
	if code, body := get(); code != 503 || body != ReadyFlagging {
		t.Fatalf("readyz with the gate shut: %d %q", code, body)
	}
	shut = false
	if code, body := get(); code != 200 || body != ReadyServing {
		t.Fatalf("readyz with the gate open: %d %q", code, body)
	}
	shut = true
	f.b.SetReady(ReadyDrainingOf("port49-broker"))
	if code, body := get(); code != 503 || body != "draining: port49-broker is shutting down" {
		t.Fatalf("readyz draining with the gate shut: %d %q", code, body)
	}
}
