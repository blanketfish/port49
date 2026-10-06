package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/printsafe"
)

// ErrUnavailable is an issuer whose keys cannot be used: none fetched or
// restored yet, or none refreshed within jwks_max_age (Ruling 4). The API
// answers 503 identity_provider_unavailable, to be retried.
var ErrUnavailable = errors.New("oidc: the identity provider's keys are not available")

// ErrUnknownKey is a token whose kid names no key of a set fetched within
// the last RefetchEvery, or names two, or, with no kid, a set holding other
// than one key of the algorithm's type: 401.
var ErrUnknownKey = errors.New("oidc: no one key in the provider's set matches the token")

// RefetchEvery bounds the fetches an unknown kid triggers: one per issuer
// per minute, so a flood of forged kids costs the provider one request a
// minute (Ruling 4).
const RefetchEvery = time.Minute

const (
	fetchTimeout  = 10 * time.Second
	maxBody       = 1 << 20
	sayStaleEvery = time.Hour
)

// KeySetConfig is one issuer's key set (Ruling 4).
type KeySetConfig struct {
	Issuer string
	// Client fetches discovery and the JWKS (NewClient).
	Client *http.Client
	// Refresh is jwks_refresh_interval, MaxAge jwks_max_age.
	Refresh, MaxAge time.Duration
	Now             func() time.Time
	// Save keeps a fetched set across a restart, and Load reads it back
	// (Restore); nil keeps none.
	Save func([]byte) error
	Load func() ([]byte, error)
	Say  func(format string, args ...any)
	M    *metrics.Metrics
}

// NewClient is a provider's HTTP client: TLS 1.2 or later against roots
// (nil: the system's), fetchTimeout, no redirect followed, and the
// environment's proxy (HTTPS_PROXY, NO_PROXY), which DefaultTransport's
// clone keeps: a site whose egress is a proxy would otherwise never fetch a
// key (pre-flight I-5). The targets are the configured issuer and the
// jwks_uri its own discovery names, so no request goes where configuration
// did not send it.
func NewClient(roots *x509.CertPool) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	return &http.Client{Transport: tr, Timeout: fetchTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// ProxyFor is the proxy NewClient's transport takes to reach issuer: the
// environment's, or nil for none.
func ProxyFor(issuer string) (*url.URL, error) {
	req, err := http.NewRequest(http.MethodGet, issuer, nil)
	if err != nil {
		return nil, err
	}
	return http.ProxyFromEnvironment(req)
}

// DescribeProxy is the start line's words for u: its URL with any password
// redacted, or directly.
func DescribeProxy(u *url.URL) string {
	if u == nil {
		return "directly (no HTTPS_PROXY)"
	}
	return "through the proxy " + u.Redacted() + " (HTTPS_PROXY)"
}

// KeyFileName is the name of the file an issuer's fetched keys are kept in,
// in the broker's state directory (Ruling 4): config checks no other file
// collides with it, and port49d writes it.
func KeyFileName(issuer string) string {
	sum := sha256.Sum256([]byte(issuer))
	return "oidc-" + hex.EncodeToString(sum[:8]) + ".json"
}

// KeySet is one issuer's verification keys.
type KeySet struct {
	c KeySetConfig

	mu        sync.Mutex
	keys      []Key
	fetched   time.Time // when keys were fetched; zero before any
	lastTry   time.Time
	lastErr   error
	saidStale time.Time
	jwksURI   string        // the last fetch's, said when it changes (pre-flight M-7)
	skipped   []string      // the last fetch's skips, said when they change (pre-flight M-3)
	flight    chan struct{} // a fetch in progress; nil when none
}

// NewKeySet holds no key until Restore or Fetch. Its issuer's last-success
// gauge exists from now, at 0, so absent() never hides an issuer that has
// no keys (pre-flight I-4).
func NewKeySet(c KeySetConfig) *KeySet {
	if c.Say == nil {
		c.Say = func(string, ...any) {}
	}
	c.M.OIDCKeysLastSuccess.WithLabelValues(c.Issuer).Set(0)
	return &KeySet{c: c}
}

// Issuer is the configured issuer.
func (s *KeySet) Issuer() string { return s.c.Issuer }

// persisted is the file Save writes.
type persisted struct {
	Issuer    string          `json:"issuer"`
	FetchedAt time.Time       `json:"fetched_at"`
	JWKS      json.RawMessage `json:"jwks"`
}

// Restore loads the persisted set, when Load gives one for this issuer
// fetched no later than now and within MaxAge (Review Focus 3).
func (s *KeySet) Restore() (int, time.Time, error) {
	if s.c.Load == nil {
		return 0, time.Time{}, nil
	}
	raw, err := s.c.Load()
	if err != nil || len(raw) == 0 {
		return 0, time.Time{}, err
	}
	var p persisted
	if json.Unmarshal(raw, &p) != nil {
		return 0, time.Time{}, errors.New("the kept key file does not decode")
	}
	now := s.c.Now()
	switch {
	case p.Issuer != s.c.Issuer:
		return 0, time.Time{}, errors.New("the kept key file is another issuer's")
	case p.FetchedAt.After(now):
		return 0, time.Time{}, errors.New("the kept key file says it was fetched in the future")
	case now.Sub(p.FetchedAt) > s.c.MaxAge:
		return 0, p.FetchedAt, fmt.Errorf("the kept keys were fetched %s, past jwks_max_age",
			p.FetchedAt.UTC().Format(time.RFC3339))
	}
	keys, _, err := ParseJWKS(p.JWKS)
	if err != nil {
		return 0, time.Time{}, err
	}
	if len(keys) == 0 {
		return 0, time.Time{}, errors.New("the kept key file holds no usable key")
	}
	s.mu.Lock()
	s.keys, s.fetched = keys, p.FetchedAt
	s.mu.Unlock()
	// The gauge carries the kept set's age, so the staleness alert keeps
	// firing for a broker restarted during an outage (pre-flight I-4).
	s.c.M.OIDCKeysLastSuccess.WithLabelValues(s.c.Issuer).Set(float64(p.FetchedAt.Unix()))
	return len(keys), p.FetchedAt, nil
}

// Fetch reads discovery and the JWKS once; a fetch in progress is waited
// for and its outcome shared. The fetch is the issuer's, not the caller's:
// it runs on a context no caller's hang-up cancels, bounded by
// fetchTimeout, and each caller waits for it under its own ctx, returning
// ctx.Err() if that ends first. A caller's cancellation is never stored as
// the issuer's last error (pre-flight I-3).
func (s *KeySet) Fetch(ctx context.Context) error {
	s.mu.Lock()
	ch := s.flight
	if ch == nil {
		ch = make(chan struct{})
		s.flight, s.lastTry = ch, s.c.Now()
		go s.fetchOnce(context.WithoutCancel(ctx), ch)
	}
	s.mu.Unlock()
	select {
	case <-ch:
	case <-ctx.Done():
		return ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastErr
}

// fetchOnce is one fetch, its outcome recorded and its effects done before
// ch closes. A success
// replaces the set whole, so a key the provider dropped is dropped. A
// failure, a set with no usable key among them (pre-flight M-2), keeps the
// last good set and says so once an hour. Skips and the jwks_uri are said
// when they change.
func (s *KeySet) fetchOnce(ctx context.Context, ch chan struct{}) {
	uri, body, keys, skipped, err := s.fetch(ctx)
	now := s.c.Now()
	s.mu.Lock()
	s.lastErr = err
	if err == nil {
		s.keys, s.fetched = keys, now
	}
	fetched, held := s.fetched, len(s.keys)
	stale := err != nil && (s.saidStale.IsZero() || now.Sub(s.saidStale) >= sayStaleEvery)
	if stale {
		s.saidStale = now
	}
	sayURI := err == nil && uri != s.jwksURI
	saySkips := err == nil && !slices.Equal(skipped, s.skipped)
	if err == nil {
		s.saidStale, s.jwksURI, s.skipped = time.Time{}, uri, skipped
	}
	s.mu.Unlock()
	// The side effects finish before the fetch is done, so a Fetch that
	// returns has saved what it fetched.
	defer func() {
		s.mu.Lock()
		s.flight = nil
		s.mu.Unlock()
		close(ch)
	}()

	iss := s.c.Issuer
	if err != nil {
		s.c.M.OIDCKeysFetchFailures.WithLabelValues(iss).Inc()
		if stale {
			s.sayStale(fetched, held, err, now)
		}
		return
	}
	s.c.M.OIDCKeysLastSuccess.WithLabelValues(iss).Set(float64(now.Unix()))
	if sayURI {
		s.c.Say("identity: %s: keys from %s", iss, printsafe.Line(uri, 300))
	}
	if saySkips {
		for _, why := range skipped {
			s.c.Say("identity: %s: a key in the JWKS is skipped: %s", iss, why)
		}
	}
	if s.c.Save != nil {
		file, _ := json.Marshal(persisted{Issuer: iss, FetchedAt: now, JWKS: body})
		if err := s.c.Save(file); err != nil {
			s.c.Say("identity: %s: the keys were fetched but could not be kept for a restart: %v", iss, err)
		}
	}
}

func (s *KeySet) sayStale(fetched time.Time, held int, err error, now time.Time) {
	iss, why := s.c.Issuer, printsafe.Line(err.Error(), 300)
	switch {
	case fetched.IsZero():
		s.c.Say("identity: %s: no keys fetched yet (%s); every token from it is refused "+
			"identity_provider_unavailable until a fetch succeeds", iss, why)
	case now.Sub(fetched) > s.c.MaxAge:
		s.c.Say("identity: %s: no key refreshed within broker.identity.jwks_max_age (%s; the last at %s); every "+
			"token from it is refused identity_provider_unavailable until a fetch succeeds; certificate logins "+
			"and live device sessions are unaffected; to accept the held keys meanwhile, raise "+
			"broker.identity.jwks_max_age (up to 720h) and restart port49-broker", iss, s.c.MaxAge,
			fetched.UTC().Format(time.RFC3339))
	default:
		s.c.Say("identity: %s: keys not refreshed since %s (the last error: %s); tokens signed by the %d keys "+
			"held are accepted until %s (broker.identity.jwks_max_age), then refused identity_provider_unavailable",
			iss, fetched.UTC().Format(time.RFC3339), why, held, fetched.Add(s.c.MaxAge).UTC().Format(time.RFC3339))
	}
}

// discoveryMember is the string member name of the discovery document doc,
// read by exact name from a document with no repeated member.
func discoveryMember(doc map[string]json.RawMessage, name string) (string, bool) {
	var v string
	return v, json.Unmarshal(doc[name], &v) == nil && v != ""
}

// fetch is one discovery read and one JWKS read: the jwks_uri, the raw
// JWKS, its keys, and its skips. A JWKS with no usable key is an error, a
// failed fetch (pre-flight M-2): one bad publish never replaces the last
// good set or the kept file.
func (s *KeySet) fetch(ctx context.Context) (string, []byte, []Key, []string, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	raw, err := s.get(ctx, strings.TrimSuffix(s.c.Issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return "", nil, nil, nil, err
	}
	// issuer and jwks_uri are read by exact name, neither repeated: the
	// document decides where keys are fetched from.
	doc, err := exactObject(raw)
	if err != nil {
		return "", nil, nil, nil, errors.New("the discovery document is not a JSON object of distinct members")
	}
	if iss, _ := discoveryMember(doc, "issuer"); iss != s.c.Issuer {
		return "", nil, nil, nil, errors.New("the discovery document names another issuer (OpenID Connect Discovery §4.3)")
	}
	jwksURI, _ := discoveryMember(doc, "jwks_uri")
	u, err := url.Parse(jwksURI)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", nil, nil, nil, errors.New("the discovery document's jwks_uri is not an https URL")
	}
	body, err := s.get(ctx, u.String())
	if err != nil {
		return "", nil, nil, nil, err
	}
	keys, skipped, err := ParseJWKS(body)
	switch {
	case err != nil:
		return "", nil, nil, nil, err
	case len(keys) == 0:
		return "", nil, nil, nil, fmt.Errorf("the JWKS holds no key port49 can verify with (%d skipped)", len(skipped))
	}
	return u.String(), body, keys, skipped, nil
}

func (s *KeySet) get(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return nil, fmt.Errorf("GET %s: redirected (%s); a redirect is not followed", u, resp.Status)
		}
		return nil, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", u, err)
	}
	if len(b) > maxBody {
		return nil, fmt.Errorf("GET %s: over %d bytes", u, maxBody)
	}
	return b, nil
}

// pick is the one key kid names, or with no kid the one key of alg's
// type, and whether there is exactly one and it fits alg.
func pick(keys []Key, kid string, alg Alg) (Key, bool) {
	var out []Key
	for _, k := range keys {
		if (kid != "" && k.Kid == kid) || (kid == "" && k.Fits(alg)) {
			out = append(out, k)
		}
	}
	if len(out) != 1 || !out[0].Fits(alg) {
		return Key{}, false
	}
	return out[0], true
}

// Key is the key a token's kid (or, with none, its algorithm's type)
// names, refetching once per RefetchEvery when the set has none or is
// stale, and joining a refetch already running. ErrUnavailable when no
// fresh set can be had; ErrUnknownKey when a fresh set has no one match;
// ctx.Err() when the caller's own context ends while it waits.
func (s *KeySet) Key(ctx context.Context, kid string, alg Alg) (Key, error) {
	type state struct {
		k                   Key
		ok, fresh, inFlight bool
		lastErr             error
		lastTry             time.Time
	}
	try := func() state {
		s.mu.Lock()
		defer s.mu.Unlock()
		k, ok := pick(s.keys, kid, alg)
		fresh := !s.fetched.IsZero() && s.c.Now().Sub(s.fetched) <= s.c.MaxAge
		return state{k, ok, fresh, s.flight != nil, s.lastErr, s.lastTry}
	}
	st := try()
	if st.ok && st.fresh {
		return st.k, nil
	}
	if st.inFlight || st.lastTry.IsZero() || s.c.Now().Sub(st.lastTry) >= RefetchEvery {
		if err := s.Fetch(ctx); err != nil && ctx.Err() != nil {
			return Key{}, ctx.Err()
		}
		if st = try(); st.ok && st.fresh {
			return st.k, nil
		}
	}
	if !st.fresh || st.lastErr != nil {
		return Key{}, ErrUnavailable
	}
	return Key{}, ErrUnknownKey
}

// Status is the set held, when it was fetched, and the last fetch's error.
func (s *KeySet) Status() ([]Key, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Key(nil), s.keys...), s.fetched, s.lastErr
}

// NextWait is the refresh loop's wait after a fetch: 0 after a success
// (Run waits Refresh), else 30s doubling to 5m.
func NextWait(ok bool, prev time.Duration) time.Duration {
	if ok {
		return 0
	}
	return min(max(2*prev, 30*time.Second), 5*time.Minute)
}

// Run fetches at once when the set is older than Refresh (or empty), then
// every Refresh, backing off after a failure, until ctx ends.
func (s *KeySet) Run(ctx context.Context) {
	var backoff time.Duration
	for {
		_, fetched, _ := s.Status()
		wait := s.c.Refresh - s.c.Now().Sub(fetched)
		if backoff > 0 {
			wait = backoff
		}
		if fetched.IsZero() && backoff == 0 {
			wait = 0
		}
		t := time.NewTimer(max(wait, 0))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		err := s.Fetch(ctx)
		if ctx.Err() != nil {
			return
		}
		backoff = NextWait(err == nil, backoff)
	}
}
