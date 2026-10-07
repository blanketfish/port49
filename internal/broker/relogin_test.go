package broker

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/token"
)

// detailOf is the detail of a 401 credential_revoked answer.
func detailOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var e api.Error
	if w.Code != 401 || json.Unmarshal(w.Body.Bytes(), &e) != nil || e.Error != string(decision.CredentialRevoked) {
		t.Fatalf("want 401 credential_revoked: %s", shown(w))
	}
	if strings.Contains(e.Detail, "\n") {
		t.Fatalf("the detail is more than one line: %q", e.Detail)
	}
	return e.Detail
}

// subLogoutAt writes the sub record of alice's logout at at.
func subLogoutAt(t *testing.T, f *fixture, iss string, at time.Time) {
	t.Helper()
	if err := f.st.PutLogout(context.Background(), store.Logout{Key: store.OIDCKey(store.OIDCSub, iss, "sub-alice"),
		At: at}, time.Hour); err != nil {
		t.Fatal(err)
	}
}

// reloginFrom is the time a login is taken after a logout at at: at plus
// clock_skew, rounded up to the next whole second.
func reloginFrom(f *fixture, at time.Time) string {
	return at.Add(f.b.Identity.Timing.ClockSkew).Truncate(time.Second).Add(time.Second).UTC().Format(time.RFC3339)
}

// A refusal by a logout's sub record names the time from which a login is
// taken; a token issued after it is not refused; one issued at it is.
func TestASubLogoutRefusalNamesWhenALoginIsTaken(t *testing.T) {
	ctx := context.Background()
	for name, frac := range map[string]time.Duration{"a whole-second logout": 0, "a logout part way through a second": 400 * time.Millisecond} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 8)
			iss := f.withOIDC(t)
			// Keycloak's logout carries both: the sid's record and the sub's.
			at := f.b.Now().Add(frac)
			if err := f.st.PutLogout(ctx, store.Logout{Key: store.SidKey(iss.URL, "s-sub-alice"), At: at}, time.Hour); err != nil {
				t.Fatal(err)
			}
			subLogoutAt(t, f, iss.URL, at)
			skew := f.b.Identity.Timing.ClockSkew
			// A fresh login (a new sid) inside the window is the sub's refusal.
			fresh := map[string]any{"sid": "s-new"}
			f.advance(skew / 2)
			d := detailOf(t, f.bearer(ctx, "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, fresh)))
			want := "log in again from " + reloginFrom(f, at)
			if !strings.HasSuffix(d, want) || !strings.Contains(d, "(back-channel logout)") ||
				!strings.Contains(d, at.UTC().Format(time.RFC3339)) {
				t.Fatalf("detail %q, want it to end %q", d, want)
			}
			for _, secret := range []string{"s-new", "s-sub-alice", "sub-alice"} {
				if strings.Contains(d, secret) {
					t.Fatalf("the detail names %q: %q", secret, d)
				}
			}
			// iat == floor(logout + skew) is still refused; one second later is a login.
			f.advance(skew / 2)
			if w := f.bearer(ctx, "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, fresh)); w.Code != 401 {
				t.Fatalf("a token issued at the logout plus clock_skew: %s", shown(w))
			}
			f.advance(time.Second)
			if w := f.bearer(ctx, "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, fresh)); w.Code != 200 {
				t.Fatalf("a token issued 1s after the time named (%s): %s", reloginFrom(f, at), shown(w))
			}
		})
	}
}

// A logout by sid alone ends that session; another session of the person is
// unaffected, and the refused one is told its own session ended, with no time
// to wait for.
func TestASidLogoutRefusalNamesNoLoginTime(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	ctx := context.Background()
	if err := f.st.PutLogout(ctx, store.Logout{Key: store.SidKey(iss.URL, "s-one"), At: f.b.Now()}, time.Hour); err != nil {
		t.Fatal(err)
	}
	d := detailOf(t, f.bearer(ctx, "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, map[string]any{"sid": "s-one"})))
	if !strings.Contains(d, "ended this session at ") || strings.Contains(d, "from") || !strings.HasSuffix(d, "log in again") {
		t.Fatalf("the sid form: %q", d)
	}
	if w := f.bearer(ctx, "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, map[string]any{"sid": "s-two"})); w.Code != 200 {
		t.Fatalf("another session of the person: %s", shown(w))
	}
}

// Every path that answers a logged-out session answers a sub record's
// refusal with the login time.
func TestEveryLogoutRefusalPathNamesTheLoginTimeForASubRecord(t *testing.T) {
	ctx := context.Background()
	check := func(t *testing.T, f *fixture, at time.Time, w *httptest.ResponseRecorder) {
		t.Helper()
		d := detailOf(t, w)
		if want := "log in again from " + reloginFrom(f, at); !strings.HasSuffix(d, want) {
			t.Fatalf("detail %q, want it to end %q", d, want)
		}
	}
	t.Run("the bearer request path", func(t *testing.T) {
		f := newFixture(t, 8)
		iss := f.withOIDC(t)
		at := f.b.Now()
		subLogoutAt(t, f, iss.URL, at)
		for _, c := range []struct{ method, path, body string }{
			{"POST", "/v1/tokens", mintLeaf1}, {"GET", "/v1/identity", ""},
			{"POST", "/v1/explain", `{"device":"leaf1"}`}, {"POST", "/v1/tokens/revoke", `{"mine":true}`},
		} {
			check(t, f, at, f.bearer(ctx, c.method, c.path, c.body, f.idToken(t, iss, nil)))
		}
	})
	t.Run("a logout landing during a mint", func(t *testing.T) {
		f := newFixture(t, 8)
		iss := f.withOIDC(t)
		at := f.b.Now()
		hooked := hookStore{Store: f.st, before: map[string]func() error{"PutToken": func() error {
			return f.st.PutLogout(ctx, store.Logout{Key: store.OIDCKey(store.OIDCSub, iss.URL, "sub-alice"), At: at}, time.Hour)
		}}}
		f.b.Minter = token.NewMinter(hooked, f.b.Log, rand.Reader, token.TagKey([]byte("k")), f.b.Now, 8)
		check(t, f, at, f.bearer(ctx, "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, nil)))
	})
	for name, failAfter := range map[string]bool{
		"a logout landing during a refresh":             false,
		"a logout landing during a refresh that failed": true,
	} {
		t.Run(name, func(t *testing.T) {
			f, tok, iss := oidcSession(t)
			twoContexts(t, f)
			nonce := challenge(t, f, tok(nil))
			f.advance(time.Minute)
			at := f.b.Now()
			calls := 0
			f.b.Store = hookStore{Store: f.st, before: map[string]func() error{"RefreshContext": func() error {
				calls++
				if calls == 1 {
					return f.st.PutLogout(ctx, store.Logout{Key: store.OIDCKey(store.OIDCSub, iss, "sub-alice"), At: at}, time.Hour)
				}
				if failAfter {
					return store.ErrUnavailable
				}
				return nil
			}}}
			check(t, f, at, f.bearer(ctx, "POST", "/v1/refresh", "{}", tok(map[string]any{"nonce": nonce,
				"sid": "s-second", "auth_time": f.b.Now().Unix()})))
		})
	}
}

// The time named is a literal, not the implementation's formula: a logout at
// 15:30:04.4 with clock_skew 60s refuses a login until 15:31:04.4, so one is
// taken from 15:31:05.
func TestASubLogoutRefusalNamesALiteralLoginTime(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	f.b.Identity.Timing.ClockSkew = 60 * time.Second
	at := time.Date(2026, 10, 7, 15, 30, 4, 400_000_000, time.UTC)
	f.mu.Lock()
	f.now = time.Date(2026, 10, 7, 15, 30, 30, 0, time.UTC)
	f.mu.Unlock()
	subLogoutAt(t, f, iss.URL, at)
	d := detailOf(t, f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, nil)))
	want := "your identity provider ended your sessions at 2026-10-07T15:30:04Z (back-channel logout); " +
		"log in again from 2026-10-07T15:31:05Z"
	if d != want {
		t.Fatalf("detail %q, want %q", d, want)
	}
}

// Keycloak's logout writes the sid's record and the sub's. The session that
// was logged out carries the sid, and is told when a login is taken, not just
// to log in again: a login at once would be refused a second time.
func TestAKeycloakLogoutNamesTheLoginTimeToTheLoggedOutSession(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	ctx := context.Background()
	at := f.b.Now()
	if err := f.st.PutLogout(ctx, store.Logout{Key: store.SidKey(iss.URL, "s-sub-alice"), At: at}, time.Hour); err != nil {
		t.Fatal(err)
	}
	subLogoutAt(t, f, iss.URL, at)
	d := detailOf(t, f.bearer(ctx, "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, map[string]any{"sid": "s-sub-alice"})))
	if want := "log in again from " + reloginFrom(f, at); !strings.HasSuffix(d, want) {
		t.Fatalf("detail %q, want it to end %q", d, want)
	}
}

// A sub record whose window has passed does not hold a later session, but a
// sid record for that later session still refuses it, in the sid form: the
// sub record being found must not end the lookup.
func TestALaterSessionLoggedOutBySidIsRefusedAfterTheSubWindow(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	ctx := context.Background()
	subLogoutAt(t, f, iss.URL, f.b.Now())
	f.advance(f.b.Identity.Timing.ClockSkew + 2*time.Second)
	if err := f.st.PutLogout(ctx, store.Logout{Key: store.SidKey(iss.URL, "s-later"), At: f.b.Now()}, time.Hour); err != nil {
		t.Fatal(err)
	}
	d := detailOf(t, f.bearer(ctx, "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, map[string]any{"sid": "s-later"})))
	if !strings.Contains(d, "ended this session at ") || strings.Contains(d, "from") || !strings.HasSuffix(d, "log in again") {
		t.Fatalf("the sid form: %q", d)
	}
	if w := f.bearer(ctx, "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, map[string]any{"sid": "s-other"})); w.Code != 200 {
		t.Fatalf("another later session: %s", shown(w))
	}
}

// logoutReadFault fails the read of one logout key and passes every other.
type logoutReadFault struct {
	store.Store
	key string
}

func (s logoutReadFault) GetLogout(ctx context.Context, key string) (store.Logout, error) {
	if key == s.key {
		return store.Logout{}, store.ErrUnavailable
	}
	return s.Store.GetLogout(ctx, key)
}

// A logout record that cannot be read refuses the request as the store being
// down, whichever of the sub's and the sid's it is, rather than letting a
// possibly logged-out session through.
func TestAnUnreadableLogoutRecordFailsClosed(t *testing.T) {
	for name, key := range map[string]func(iss string) string{
		"the sub record": func(iss string) string { return store.OIDCKey(store.OIDCSub, iss, "sub-alice") },
		"the sid record": func(iss string) string { return store.SidKey(iss, "s-one") },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 8)
			iss := f.withOIDC(t)
			f.b.Store = logoutReadFault{Store: f.st, key: key(iss.URL)}
			w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, map[string]any{"sid": "s-one"}))
			if w.Code != 503 || !strings.Contains(w.Body.String(), string(decision.StoreUnavailable)) {
				t.Fatalf("want 503 store_unavailable: %s", shown(w))
			}
		})
	}
}
