package broker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/store"
)

// twoRegions is two brokers, each on its own session store (its own
// fixture's), sharing one directory: a's enrollment store (plan 11a).
func twoRegions(t *testing.T) (a, b *fixture) {
	t.Helper()
	a, _ = newSignInFixture(t)
	b, _ = newSignInFixture(t)
	b.b.Enrollments = a.b.Enrollments
	return a, b
}

// Review Focus 3: one code, presented to two regions at once, signs in
// once: the used step is a compare-and-set on the one directory record.
func TestOneCodeSignsInOnceAcrossRegions(t *testing.T) {
	a, b := twoRegions(t)
	secret := a.enrolled(t, alicePrincipal, "uuid:alice")
	req := api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, secret, a.now), CSR: csrOf(t, newECKey(t))}
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i, f := range []*fixture{a, b} {
		wg.Add(1)
		go func() { defer wg.Done(); codes[i] = f.signIn(t, req).Code }()
	}
	wg.Wait()
	passed := 0
	for _, c := range codes {
		if c == http.StatusOK {
			passed++
		}
	}
	if passed != 1 {
		t.Fatalf("answers %v: one code signed in %d times across two regions", codes, passed)
	}
	// And one after the other: the second region refuses the spent code.
	if w := b.signIn(t, req); w.Code == http.StatusOK {
		t.Fatalf("a spent code signed in again in another region: %s", shown(w))
	}
}

// R15: an unlock in one region starts the count in another: the count is
// regional, the unlock is a directory record.
func TestAnUnlockReachesEveryRegionsCount(t *testing.T) {
	ctx := context.Background()
	a, b := twoRegions(t)
	secret := a.enrolled(t, alicePrincipal, "uuid:alice")
	for range 5 {
		if _, _, err := b.b.Store.NoteSignInAttempt(ctx, alicePrincipalKey, b.b.PasswordSignIn.Window); err != nil {
			t.Fatal(err)
		}
	}
	req := api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, secret, b.now), CSR: csrOf(t, newECKey(t))}
	if w := b.signIn(t, req); w.Code != http.StatusTooManyRequests {
		t.Fatalf("setup: region b did not throttle: %s", shown(w))
	}
	text, err := a.b.UnlockSignIn(ctx, alicePrincipal, "admin_socket uid 0")
	if err != nil || text != "cleared 0 failed sign-ins for "+alicePrincipal+" here; every region's count starts again" {
		t.Fatalf("%q %v", text, err)
	}
	if w := b.signIn(t, req); w.Code != http.StatusOK {
		t.Fatalf("region b after an unlock in region a: %s", shown(w))
	}
}

// failingUnlocks is an enrollment store whose unlock reads fail as a cut
// directory's do.
type failingUnlocks struct{ store.Enrollments }

func (failingUnlocks) GetUnlock(context.Context, string) (time.Time, error) {
	return time.Time{}, store.ErrUnavailable
}

// R16: a sign-in whose directory does not answer is refused 503
// store_unavailable before anything is counted or judged.
func TestASignInWithTheDirectoryCutIsRefused(t *testing.T) {
	f, _ := newSignInFixture(t)
	secret := f.enrolled(t, alicePrincipal, "uuid:alice")
	f.b.Enrollments = failingUnlocks{f.b.Enrollments}
	req := api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))}
	w := f.signIn(t, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("%s", shown(w))
	}
	assertErrorCode(t, w, "store_unavailable")
}

// assertErrorCode checks a refusal's API error code, and nothing of its
// body beyond it.
func assertErrorCode(t *testing.T, w *httptest.ResponseRecorder, code string) {
	t.Helper()
	var e api.Error
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil || e.Error != code {
		t.Fatalf("error %q (%v), want %q", e.Error, err, code)
	}
}
