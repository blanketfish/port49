package broker

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
