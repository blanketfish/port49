package oidc_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/oidc/oidctest"
)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }
func (c *clock) Set(t time.Time)     { c.mu.Lock(); c.now = t; c.mu.Unlock() }
func newClock() *clock               { return &clock{now: time.Now().Truncate(time.Second)} }

type said struct {
	mu    sync.Mutex
	lines []string
}

func (s *said) Say(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, fmt.Sprintf(format, args...))
}
func (s *said) all() string { s.mu.Lock(); defer s.mu.Unlock(); return strings.Join(s.lines, "\n") }

// keep is a Save that records the file it was given: Save runs after Fetch
// returns, so a test waits for it.
type keep struct {
	mu   sync.Mutex
	b    []byte
	n    int
	done chan struct{}
}

func newKeep() *keep { return &keep{done: make(chan struct{}, 16)} }

func (k *keep) Save(b []byte) error {
	k.mu.Lock()
	k.b, k.n = append([]byte(nil), b...), k.n+1
	k.mu.Unlock()
	k.done <- struct{}{}
	return nil
}

// wait returns once a Save has run.
func (k *keep) wait(t *testing.T) {
	t.Helper()
	select {
	case <-k.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the fetched set was never saved")
	}
}

func (k *keep) file() []byte { k.mu.Lock(); defer k.mu.Unlock(); return k.b }
func (k *keep) saves() int   { k.mu.Lock(); defer k.mu.Unlock(); return k.n }

// await waits for the said lines to hold at least n of sub: a fetch says
// its lines after it returns.
func (s *said) await(t *testing.T, sub string, n int) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(time.Millisecond) {
		if strings.Count(s.all(), sub) >= n {
			return
		}
	}
	t.Fatalf("%d lines with %q never said:\n%s", n, sub, s.all())
}

func keySet(t *testing.T, iss *oidctest.Issuer, c *clock, s *said) *oidc.KeySet {
	t.Helper()
	return oidc.NewKeySet(oidc.KeySetConfig{Issuer: iss.URL, Client: oidc.NewClient(iss.Roots()),
		Refresh: time.Hour, MaxAge: 24 * time.Hour, Now: c.Now, Say: s.Say,
		M: metrics.New(prometheus.NewRegistry())})
}

func TestAFetchReadsDiscoveryThenKeys(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	ks := keySet(t, iss, c, s)
	if err := ks.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Key(context.Background(), "k1", oidc.RS256); err != nil {
		t.Fatal(err)
	}
	keys, fetched, lastErr := ks.Status()
	if len(keys) != 1 || !fetched.Equal(c.Now()) || lastErr != nil {
		t.Fatalf("status: %d keys, fetched %v, %v", len(keys), fetched, lastErr)
	}
	// The jwks_uri is said at the first fetch, and not again while it stands
	// (pre-flight M-7).
	s.await(t, "keys from "+iss.URL+"/jwks", 1)
	c.Add(time.Hour)
	if err := ks.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(s.all(), "keys from "+iss.URL+"/jwks"); n != 1 {
		t.Fatalf("the jwks_uri said %d times:\n%s", n, s.all())
	}
}

// The provider is reached through the environment's proxy (pre-flight I-5),
// and the start line names it without its password.
func TestTheClientUsesTheEnvironmentsProxy(t *testing.T) {
	tr, ok := oidc.NewClient(nil).Transport.(*http.Transport)
	if !ok || tr.Proxy == nil {
		t.Fatal("the provider's client ignores HTTPS_PROXY: a site whose egress is a proxy never fetches a key")
	}
	// A proxy value the transport would misread is refused, never dialled.
	t.Setenv("HTTPS_PROXY", "http://svc:FAKE-pw#x@proxy.example.com:3128")
	req, _ := http.NewRequest(http.MethodGet, "https://idp.example.com/", nil)
	if u, err := tr.Proxy(req); u != nil || err == nil || strings.Contains(err.Error(), "FAKE-pw") {
		t.Fatalf("a bad HTTPS_PROXY: %v, %v", u, err)
	}
}

// A client that hangs up during the refetch it started does not poison it
// (pre-flight I-3): the fetch runs on, nothing stores its cancellation, and
// the next token under the rotated-in key is accepted at once, not a
// minute later.
func TestACallerHangingUpDoesNotPoisonTheRefetch(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	ks := keySet(t, iss, c, s)
	if err := ks.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.Add(2 * time.Minute)
	iss.AddKey(t, "k2", oidc.ES256)
	arrived, release := iss.Hold()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := ks.Key(ctx, "k2", oidc.ES256); done <- err }()
	<-arrived
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("the hung-up caller: %v", err)
	}
	release()
	if _, err := ks.Key(context.Background(), "k2", oidc.ES256); err != nil {
		t.Fatalf("the next token under the rotated-in key: %v", err)
	}
	if _, _, lastErr := ks.Status(); lastErr != nil {
		t.Fatalf("the caller's cancellation was stored as the issuer's: %v", lastErr)
	}
}

// The staleness gauge exists from the key set's creation and carries a
// restored set's age (pre-flight I-4): a broker restarted during an outage
// still alerts.
func TestTheLastSuccessGaugeSurvivesARestart(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	m := metrics.New(prometheus.NewRegistry())
	kept := newKeep()
	cfg := oidc.KeySetConfig{Issuer: iss.URL, Client: oidc.NewClient(iss.Roots()), Refresh: time.Hour,
		MaxAge: 24 * time.Hour, Now: c.Now, Say: s.Say, M: m, Save: kept.Save}
	ks := oidc.NewKeySet(cfg)
	if n := testutil.CollectAndCount(m.OIDCKeysLastSuccess); n != 1 {
		t.Fatalf("%d series before any fetch: absent() would be the only alert", n)
	}
	if v := testutil.ToFloat64(m.OIDCKeysLastSuccess.WithLabelValues(iss.URL)); v != 0 {
		t.Fatalf("before any fetch: %v", v)
	}
	if err := ks.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	kept.wait(t)
	fetched := c.Now()
	iss.Fail(503)
	c.Add(10 * time.Hour)
	m2 := metrics.New(prometheus.NewRegistry())
	cfg.M, cfg.Save, cfg.Load = m2, nil, func() ([]byte, error) { return kept.file(), nil }
	if _, _, err := oidc.NewKeySet(cfg).Restore(); err != nil {
		t.Fatal(err)
	}
	if v := testutil.ToFloat64(m2.OIDCKeysLastSuccess.WithLabelValues(iss.URL)); v != float64(fetched.Unix()) {
		t.Fatalf("after a restore: %v, want the kept set's %d", v, fetched.Unix())
	}
}

// A JWKS with nothing usable is a failed fetch (pre-flight M-2): the last
// good set stands, the good file is not overwritten, and it is counted.
func TestAJWKSWithNoUsableKeyKeepsTheLastGoodSet(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	m := metrics.New(prometheus.NewRegistry())
	kept := newKeep()
	ks := oidc.NewKeySet(oidc.KeySetConfig{Issuer: iss.URL, Client: oidc.NewClient(iss.Roots()), Refresh: time.Hour,
		MaxAge: 24 * time.Hour, Now: c.Now, Say: s.Say, M: m, Save: kept.Save})
	ctx := context.Background()
	if err := ks.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	kept.wait(t)
	for _, body := range []string{`{"keys":[]}`, `{"keys":[{"kty":"oct","kid":"h","k":"c2VjcmV0"}]}`} {
		iss.ServeJWKS([]byte(body))
		c.Add(time.Hour)
		if err := ks.Fetch(ctx); err == nil || !strings.Contains(err.Error(), "no key port49 can verify with") {
			t.Fatalf("%s: %v", body, err)
		}
		if _, err := ks.Key(ctx, "k1", oidc.RS256); err != nil {
			t.Fatalf("%s: the last good key: %v", body, err)
		}
	}
	if saves := kept.saves(); saves != 1 {
		t.Fatalf("%d saves: an unusable set was kept over the good one", saves)
	}
	if got := testutil.ToFloat64(m.OIDCKeysFetchFailures.WithLabelValues(iss.URL)); got != 2 {
		t.Fatalf("%v failures counted", got)
	}
}

// keys:null is no set at all: a failed fetch, the last good set kept, and
// refused once jwks_max_age passes.
func TestAJWKSWithNullKeysIsAFailedFetch(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	ks := keySet(t, iss, c, s)
	ctx := context.Background()
	if err := ks.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	iss.ServeJWKS([]byte(`{"keys":null}`))
	c.Add(time.Hour)
	if err := ks.Fetch(ctx); err == nil {
		t.Fatal("keys:null fetched")
	}
	if _, err := ks.Key(ctx, "k1", oidc.RS256); err != nil {
		t.Fatalf("the last good key: %v", err)
	}
	c.Add(24 * time.Hour)
	if _, err := ks.Key(ctx, "k1", oidc.RS256); !errors.Is(err, oidc.ErrUnavailable) {
		t.Fatalf("past jwks_max_age: %v", err)
	}
}

// A skipped key is said when the set of skips changes, not at every fetch
// (pre-flight M-3): Keycloak publishes an RSA-OAEP enc key by default.
func TestASkipIsSaidWhenTheSkipsChange(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	good := oidctest.NewKey(t, oidc.RS256)
	encKey := func(kid string) map[string]any {
		k := oidctest.JWK(kid, "", oidctest.NewKey(t, oidc.RS256).Public())
		k["use"] = "enc"
		return k
	}
	serve := func(extra ...map[string]any) {
		raw, _ := json.Marshal(map[string]any{"keys": append([]map[string]any{oidctest.JWK("k1", oidc.RS256,
			good.Public())}, extra...)})
		iss.ServeJWKS(raw)
	}
	e1, e2 := encKey("enc-1"), encKey("enc-2")
	serve(e1)
	ks := keySet(t, iss, c, s)
	for range 3 {
		if err := ks.Fetch(context.Background()); err != nil {
			t.Fatal(err)
		}
		c.Add(time.Hour)
	}
	s.await(t, "is skipped", 1)
	if n := strings.Count(s.all(), "is skipped"); n != 1 {
		t.Fatalf("one unchanged skip said %d times:\n%s", n, s.all())
	}
	serve(e1, e2)
	if err := ks.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.await(t, "is skipped", 3)
	if n := strings.Count(s.all(), "is skipped"); n != 3 {
		t.Fatalf("a changed set of skips is said whole: %d lines:\n%s", n, s.all())
	}
}

// Discovery's issuer must be the configured one, its jwks_uri https, and a
// redirect is never followed (OIDC Discovery §4.3; Ruling 4).
func TestDiscoveryIsCheckedAndRedirectsAreNotFollowed(t *testing.T) {
	for name, hook := range map[string]func(map[string]any){
		"another issuer": func(d map[string]any) { d["issuer"] = "https://evil.example" },
		"plain http":     func(d map[string]any) { d["jwks_uri"] = strings.Replace(d["jwks_uri"].(string), "https", "http", 1) },
		"a redirect":     func(d map[string]any) { d["jwks_uri"] = strings.TrimSuffix(d["jwks_uri"].(string), "/jwks") + "/moved" },
	} {
		iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
		iss.Discovery(hook)
		ks := keySet(t, iss, c, s)
		if err := ks.Fetch(context.Background()); err == nil {
			t.Errorf("%s: the fetch succeeded", name)
		}
		if _, err := ks.Key(context.Background(), "k1", oidc.RS256); !errors.Is(err, oidc.ErrUnavailable) {
			t.Errorf("%s: a key with no good fetch: %v", name, err)
		}
	}
}

// The discovery document's members are read by exact name, none repeated: a
// repeated issuer or jwks_uri, or one spelled in another case, is not read
// as the one a different parser would take.
func TestDiscoveryMembersAreReadByExactName(t *testing.T) {
	var doc func(issuer string) string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			_, _ = w.Write([]byte(doc("https://" + r.Host)))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	for name, d := range map[string]func(string) string{
		"issuer repeated": func(i string) string {
			return `{"issuer":"https://evil.example","issuer":"` + i + `","jwks_uri":"` + i + `/jwks"}`
		},
		"jwks_uri repeated": func(i string) string {
			return `{"issuer":"` + i + `","jwks_uri":"` + i + `/jwks","jwks_uri":"` + i + `/other"}`
		},
		"issuer by case":   func(i string) string { return `{"ISSUER":"` + i + `","jwks_uri":"` + i + `/jwks"}` },
		"jwks_uri by case": func(i string) string { return `{"issuer":"` + i + `","JWKS_URI":"` + i + `/jwks"}` },
	} {
		doc = d
		c, s := newClock(), &said{}
		ks := oidc.NewKeySet(oidc.KeySetConfig{Issuer: srv.URL, Client: oidc.NewClient(pool), Refresh: time.Hour,
			MaxAge: 24 * time.Hour, Now: c.Now, Say: s.Say, M: metrics.New(prometheus.NewRegistry())})
		if err := ks.Fetch(context.Background()); err == nil {
			t.Errorf("%s: the fetch succeeded", name)
		}
	}
}

// Review Focus 2: a new kid is fetched, once a minute at most, however many
// tokens name an unknown one.
func TestANewKidIsFetchedOnceAMinute(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	ks := keySet(t, iss, c, s)
	ctx := context.Background()
	if err := ks.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	c.Add(2 * time.Minute)
	iss.AddKey(t, "k2", oidc.ES256)
	if _, err := ks.Key(ctx, "k2", oidc.ES256); err != nil {
		t.Fatalf("a rotated-in key: %v", err)
	}
	n := iss.JWKSFetches()
	for range 50 {
		if _, err := ks.Key(ctx, "forged", oidc.RS256); !errors.Is(err, oidc.ErrUnknownKey) {
			t.Fatalf("a forged kid: %v", err)
		}
	}
	if got := iss.JWKSFetches(); got != n {
		t.Fatalf("50 forged kids within the minute fetched %d times", got-n)
	}
	c.Add(oidc.RefetchEvery)
	_, _ = ks.Key(ctx, "forged", oidc.RS256)
	if got := iss.JWKSFetches(); got != n+1 {
		t.Fatalf("a minute later: %d fetches, want 1", got-n)
	}
}

func TestADroppedKeyIsRefusedAtOnce(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	ks := keySet(t, iss, c, s)
	ctx := context.Background()
	if err := ks.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	iss.AddKey(t, "k2", oidc.RS256)
	iss.Unpublish("k1")
	c.Add(time.Hour)
	if err := ks.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Key(ctx, "k1", oidc.RS256); !errors.Is(err, oidc.ErrUnknownKey) {
		t.Fatalf("a key the provider dropped: %v", err)
	}
}

// Review Focus 2: with the provider gone, the last good set serves until
// jwks_max_age, then nothing does, and the line says when.
func TestAStaleSetRefusesAfterMaxAge(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	ks := keySet(t, iss, c, s)
	ctx := context.Background()
	if err := ks.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	fetched := c.Now()
	iss.Fail(503)
	c.Add(23 * time.Hour)
	if _, err := ks.Key(ctx, "k1", oidc.RS256); err != nil {
		t.Fatalf("at 23h with the provider failing: %v", err)
	}
	if err := ks.Fetch(ctx); err == nil {
		t.Fatal("a failing provider fetched")
	}
	s.await(t, "keys not refreshed since", 1)
	if !strings.Contains(s.all(), "keys not refreshed since "+fetched.UTC().Format(time.RFC3339)) ||
		!strings.Contains(s.all(), "accepted until "+fetched.Add(24*time.Hour).UTC().Format(time.RFC3339)) {
		t.Fatalf("the stale line:\n%s", s.all())
	}
	c.Add(time.Hour + time.Second)
	if _, err := ks.Key(ctx, "k1", oidc.RS256); !errors.Is(err, oidc.ErrUnavailable) {
		t.Fatalf("past jwks_max_age: %v", err)
	}
	iss.Fail(0)
	c.Add(oidc.RefetchEvery)
	if _, err := ks.Key(ctx, "k1", oidc.RS256); err != nil {
		t.Fatalf("the provider back: %v", err)
	}
}

// A failed fetch is said once an hour, not at every try.
func TestAFailedFetchIsSaidOnceAnHour(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	ks := keySet(t, iss, c, s)
	if err := ks.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	iss.Fail(503)
	for range 10 {
		c.Add(2 * time.Minute)
		_ = ks.Fetch(context.Background())
	}
	s.await(t, "keys not refreshed since", 1)
	if n := strings.Count(s.all(), "keys not refreshed since"); n != 1 {
		t.Fatalf("%d lines in 20 minutes:\n%s", n, s.all())
	}
}

// Review Focus 3: a restart restores the persisted set, which serves until
// jwks_max_age after its own fetch, never longer.
func TestARestoredSetServesUntilMaxAge(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	kept := newKeep()
	cfg := oidc.KeySetConfig{Issuer: iss.URL, Client: oidc.NewClient(iss.Roots()), Refresh: time.Hour,
		MaxAge: 24 * time.Hour, Now: c.Now, Say: s.Say, M: metrics.New(prometheus.NewRegistry()),
		Save: kept.Save}
	if err := oidc.NewKeySet(cfg).Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	kept.wait(t)
	saved := kept.file()
	fetched := c.Now()
	iss.Fail(503)
	c.Add(20 * time.Hour)
	cfg.Save = nil
	cfg.Load = func() ([]byte, error) { return saved, nil }
	ks := oidc.NewKeySet(cfg)
	n, at, err := ks.Restore()
	if err != nil || n != 1 || !at.Equal(fetched) {
		t.Fatalf("restore: %d keys fetched %v, %v", n, at, err)
	}
	if _, err := ks.Key(context.Background(), "k1", oidc.RS256); err != nil {
		t.Fatalf("a restored key: %v", err)
	}
	c.Add(4*time.Hour + time.Second)
	if _, err := ks.Key(context.Background(), "k1", oidc.RS256); !errors.Is(err, oidc.ErrUnavailable) {
		t.Fatalf("a restored set past jwks_max_age: %v", err)
	}
	// A file for another issuer, or from the future, restores nothing.
	other := strings.Replace(string(saved), iss.URL, "https://other.example", 1)
	cfg.Load = func() ([]byte, error) { return []byte(other), nil }
	if _, _, err := oidc.NewKeySet(cfg).Restore(); err == nil {
		t.Fatal("another issuer's file restored")
	}
	c.Set(fetched.Add(-time.Hour))
	cfg.Load = func() ([]byte, error) { return saved, nil }
	if _, _, err := oidc.NewKeySet(cfg).Restore(); err == nil {
		t.Fatal("a file fetched in the future restored")
	}
}

// A kid two keys share, or no kid with two keys of the type, names no key:
// port49 never tries every key.
func TestAKeyIsChosenByKidAlone(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	iss.AddKey(t, "k1b", oidc.RS256)
	ks := keySet(t, iss, c, s)
	ctx := context.Background()
	if err := ks.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Key(ctx, "", oidc.RS256); !errors.Is(err, oidc.ErrUnknownKey) {
		t.Fatalf("no kid among two RSA keys: %v", err)
	}
	if _, err := ks.Key(ctx, "", oidc.ES256); !errors.Is(err, oidc.ErrUnknownKey) {
		t.Fatalf("no kid and no key of the type: %v", err)
	}
	iss.Unpublish("k1b")
	c.Add(time.Hour)
	if err := ks.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Key(ctx, "", oidc.RS256); err != nil {
		t.Fatalf("no kid and one RSA key: %v", err)
	}
	if _, err := ks.Key(ctx, "k1", oidc.ES256); !errors.Is(err, oidc.ErrUnknownKey) {
		t.Fatalf("a kid whose key is not of the algorithm's type: %v", err)
	}
}

func TestTheRefreshWaitBacksOffToFiveMinutes(t *testing.T) {
	if got := oidc.NextWait(false, 0); got != 30*time.Second {
		t.Fatalf("the first failure waits %v", got)
	}
	w := 30 * time.Second
	for range 10 {
		w = oidc.NextWait(false, w)
	}
	if w != 5*time.Minute {
		t.Fatalf("the backoff reaches %v", w)
	}
	if got := oidc.NextWait(true, w); got != 0 {
		t.Fatalf("a success resets the backoff to %v", got)
	}
}

func TestAKidNamingTwoKeysIsRefused(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	a, b := oidctest.NewKey(t, oidc.RS256), oidctest.NewKey(t, oidc.RS256)
	raw, _ := json.Marshal(map[string]any{"keys": []any{oidctest.JWK("dup", "", a.Public()),
		oidctest.JWK("dup", "", b.Public())}})
	iss.ServeJWKS(raw)
	ks := keySet(t, iss, c, s)
	if err := ks.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Key(context.Background(), "dup", oidc.RS256); !errors.Is(err, oidc.ErrUnknownKey) {
		t.Fatalf("a kid two keys share: %v", err)
	}
}

// A Save that never returns holds nothing the fetches need (review I2): the
// next fetch an hour later reaches the provider, failures are still counted
// and the key is still served.
func TestAHungSaveDoesNotWedgeTheRefresh(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	m := metrics.New(prometheus.NewRegistry())
	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })
	ks := oidc.NewKeySet(oidc.KeySetConfig{Issuer: iss.URL, Client: oidc.NewClient(iss.Roots()), Refresh: time.Hour,
		MaxAge: 24 * time.Hour, Now: c.Now, Say: s.Say, M: m, Save: func([]byte) error { <-stuck; return nil }})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := ks.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	n := iss.JWKSFetches()
	c.Add(time.Hour)
	if err := ks.Fetch(ctx); err != nil {
		t.Fatalf("a second fetch behind a hung Save: %v", err)
	}
	if got := iss.JWKSFetches(); got != n+1 {
		t.Fatalf("the second fetch never reached the provider (%d fetches)", got-n)
	}
	iss.Fail(503)
	c.Add(time.Hour)
	if err := ks.Fetch(ctx); err == nil {
		t.Fatal("a failing provider fetched")
	}
	if got := testutil.ToFloat64(m.OIDCKeysFetchFailures.WithLabelValues(iss.URL)); got != 1 {
		t.Fatalf("%v failures counted", got)
	}
	if _, err := ks.Key(ctx, "k1", oidc.RS256); err != nil {
		t.Fatalf("the held key: %v", err)
	}
}

// Review M2, spec 5.7's third 503: a fresh set, an unknown kid and a refetch
// that fails is unavailable at once, not a 401.
func TestAnUnknownKidWithAFailingRefetchIsUnavailable(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	ks := keySet(t, iss, c, s)
	ctx := context.Background()
	if err := ks.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	iss.Fail(503)
	c.Add(2 * time.Minute)
	if _, err := ks.Key(ctx, "k2", oidc.RS256); !errors.Is(err, oidc.ErrUnavailable) {
		t.Fatalf("an unknown kid, the refetch failing: %v", err)
	}
}

// Review M1: forged kids arriving together cause one fetch, not one for
// each caller that read the clock before the first fetch began.
func TestConcurrentForgedKidsFetchOnce(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	ks := keySet(t, iss, c, s)
	ctx := context.Background()
	if err := ks.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	for round := range 20 {
		c.Add(2 * time.Minute)
		n := iss.JWKSFetches()
		var wg sync.WaitGroup
		start := make(chan struct{})
		for range 200 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, _ = ks.Key(ctx, "forged", oidc.RS256)
			}()
		}
		close(start)
		wg.Wait()
		if got := iss.JWKSFetches() - n; got != 1 {
			t.Fatalf("round %d: %d fetches for one minute's forged kids", round, got)
		}
	}
}

// Review M3: a jwks_uri with userinfo is refused, and nothing says it.
func TestAJWKSURIWithCredentialsIsRefused(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	iss.Discovery(func(d map[string]any) {
		d["jwks_uri"] = strings.Replace(d["jwks_uri"].(string), "https://", "https://svc:fake-pw@", 1)
	})
	ks := keySet(t, iss, c, s)
	err := ks.Fetch(context.Background())
	if err == nil || strings.Contains(err.Error(), "fake-pw") || strings.Contains(s.all(), "fake-pw") {
		t.Fatalf("fetch: %v\n%s", err, s.all())
	}
}

// Review M4: a restore never replaces a set fetched after the file was.
func TestARestoreNeverReplacesANewerSet(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	kept := newKeep()
	cfg := oidc.KeySetConfig{Issuer: iss.URL, Client: oidc.NewClient(iss.Roots()), Refresh: time.Hour,
		MaxAge: 24 * time.Hour, Now: c.Now, Say: s.Say, M: metrics.New(prometheus.NewRegistry()), Save: kept.Save}
	ks := oidc.NewKeySet(cfg)
	if err := ks.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	kept.wait(t)
	c.Add(time.Hour)
	if err := ks.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	kept.wait(t)
	newer := c.Now()
	old := kept.file()
	// The file the restore reads is the first one: an hour older.
	first := strings.Replace(string(old), newer.UTC().Format(time.RFC3339), newer.Add(-time.Hour).UTC().Format(time.RFC3339), 1)
	cfg.Load = func() ([]byte, error) { return []byte(first), nil }
	ks.SetLoadForTest(cfg.Load)
	if _, _, err := ks.Restore(); err != nil {
		t.Fatal(err)
	}
	if _, fetched, _ := ks.Status(); !fetched.Equal(newer) {
		t.Fatalf("a restore moved fetched back to %v from %v", fetched, newer)
	}
}

// Review M5: the failure counter exists at 0 from construction.
func TestTheFailureCounterExistsFromTheStart(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	m := metrics.New(prometheus.NewRegistry())
	oidc.NewKeySet(oidc.KeySetConfig{Issuer: iss.URL, Client: oidc.NewClient(iss.Roots()), Refresh: time.Hour,
		MaxAge: 24 * time.Hour, Now: c.Now, Say: s.Say, M: m})
	if n := testutil.CollectAndCount(m.OIDCKeysFetchFailures); n != 1 {
		t.Fatalf("%d failure series before any failure", n)
	}
}

// Review N1: a fetch that completes between a caller's first look and the
// minute gate turning it away is looked at again, so a key it rotated in is
// found, not refused 401.
func TestAKeyRotatedInByAFetchDuringTheGateIsFound(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	ks := keySet(t, iss, c, s)
	ctx := context.Background()
	if err := ks.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	c.Add(2 * time.Minute)
	iss.AddKey(t, "k2", oidc.ES256)
	ks.SetAfterFirstTryForTest(func() {
		if err := ks.Fetch(ctx); err != nil {
			t.Error(err)
		}
	})
	if _, err := ks.Key(ctx, "k2", oidc.ES256); err != nil {
		t.Fatalf("a key a fetch rotated in just before the gate: %v", err)
	}
}

// Review N2: with Save hung, successive fetches leave one pending file, not
// a goroutine each, and the newest is what is written once Save returns.
func TestAHungSaveKeepsOnePendingFile(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	var mu sync.Mutex
	var files [][]byte
	first, gate := make(chan struct{}), make(chan struct{})
	ks := oidc.NewKeySet(oidc.KeySetConfig{Issuer: iss.URL, Client: oidc.NewClient(iss.Roots()), Refresh: time.Hour,
		MaxAge: 24 * time.Hour, Now: c.Now, Say: s.Say, M: metrics.New(prometheus.NewRegistry()),
		Save: func(b []byte) error {
			mu.Lock()
			files = append(files, append([]byte(nil), b...))
			n := len(files)
			mu.Unlock()
			if n == 1 {
				close(first)
				<-gate
			}
			return nil
		}})
	ctx := context.Background()
	if err := ks.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	<-first
	before := runtime.NumGoroutine()
	const n = 30
	for range n {
		c.Add(time.Hour)
		if err := ks.Fetch(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// Each fetch's goroutine has returned or is the one pending file's.
	time.Sleep(50 * time.Millisecond)
	if grew := runtime.NumGoroutine() - before; grew > 3 {
		t.Fatalf("%d fetches behind a hung Save grew the goroutines by %d", n, grew)
	}
	close(gate)
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		got := len(files)
		mu.Unlock()
		if got >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(files) != 2 {
		t.Fatalf("%d saves, want the first and the newest", len(files))
	}
	var p struct {
		FetchedAt time.Time `json:"fetched_at"`
	}
	if err := json.Unmarshal(files[1], &p); err != nil || !p.FetchedAt.Equal(c.Now()) {
		t.Fatalf("the second save is fetched_at %v, want the newest %v (%v)", p.FetchedAt, c.Now(), err)
	}
}

// Review R2-I1: fetches are ordered by the flight, but each reaches Save
// after its own Say. A fetch held in Say must not write its older file after
// a newer fetch's.
func TestAnOlderFileIsNeverSavedAfterANewerOne(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	var mu sync.Mutex
	var files [][]byte
	inSay, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	ks := oidc.NewKeySet(oidc.KeySetConfig{Issuer: iss.URL, Client: oidc.NewClient(iss.Roots()), Refresh: time.Hour,
		MaxAge: 24 * time.Hour, Now: c.Now, M: metrics.New(prometheus.NewRegistry()),
		Say: func(f string, a ...any) {
			if strings.Contains(fmt.Sprintf(f, a...), "keys from") {
				once.Do(func() { close(inSay); <-release })
			}
		},
		Save: func(b []byte) error {
			mu.Lock()
			files = append(files, append([]byte(nil), b...))
			mu.Unlock()
			return nil
		}})
	ctx := context.Background()
	if err := ks.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	<-inSay
	c.Add(time.Hour)
	if err := ks.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(time.Millisecond) {
		mu.Lock()
		n := len(files)
		mu.Unlock()
		if n >= 1 {
			break
		}
	}
	close(release)
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	var p struct {
		FetchedAt time.Time `json:"fetched_at"`
	}
	if len(files) == 0 || json.Unmarshal(files[len(files)-1], &p) != nil || !p.FetchedAt.Equal(c.Now()) {
		t.Fatalf("%d files; the last is fetched_at %v, want the newest %v", len(files), p.FetchedAt, c.Now())
	}
}

// The stale line names the process that holds the keys, as the broker may be
// embedded in port49d (final review F5), and never one it was not told of.
func TestTheStaleLineNamesTheProcessToRestart(t *testing.T) {
	for _, tc := range []struct{ proc, want string }{
		{"port49d", "and restart port49d"},
		{"port49-broker", "and restart port49-broker"},
		{"", "and restart the broker's process"},
	} {
		iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
		ks := oidc.NewKeySet(oidc.KeySetConfig{Issuer: iss.URL, Client: oidc.NewClient(iss.Roots()), Refresh: time.Hour,
			MaxAge: 24 * time.Hour, Now: c.Now, Say: s.Say, Proc: tc.proc, M: metrics.New(prometheus.NewRegistry())})
		if err := ks.Fetch(context.Background()); err != nil {
			t.Fatal(err)
		}
		iss.Fail(503)
		c.Add(25 * time.Hour)
		if err := ks.Fetch(context.Background()); err == nil {
			t.Fatal("a failing provider fetched")
		}
		s.await(t, "no key refreshed within", 1)
		if out := s.all(); !strings.Contains(out, tc.want) || (tc.proc != "port49-broker" && strings.Contains(out, "port49-broker")) {
			t.Errorf("proc %q: the stale line:\n%s", tc.proc, out)
		}
	}
}
