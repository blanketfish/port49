package oidctest

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/oidc"
)

// Issuer is an OpenID provider on an httptest TLS server: discovery at
// /.well-known/openid-configuration, a JWKS at /jwks, and tokens signed by
// the keys it holds. Its URL is its issuer.
type Issuer struct {
	URL string

	srv       *httptest.Server
	mu        sync.Mutex
	keys      map[string]held
	published map[string]bool
	status    int
	discovery func(map[string]any)
	raw       []byte
	gate      chan struct{} // non-nil: /jwks waits for it to close (Hold)
	arrive    func()
	fetches   atomic.Int64
	auth      *AuthServer // nil: /authorize and /token answer 404
}

type held struct {
	alg oidc.Alg
	key crypto.Signer
}

// NewIssuer starts a provider publishing one RS256 key, kid "k1".
func NewIssuer(t testing.TB) *Issuer {
	t.Helper()
	i := &Issuer{keys: map[string]held{}, published: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		i.mu.Lock()
		status, hook, auth := i.status, i.discovery, i.auth
		i.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		doc := map[string]any{"issuer": i.URL, "jwks_uri": i.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"}}
		if auth != nil {
			auth.mu.Lock()
			doc["authorization_endpoint"] = i.URL + "/authorize"
			doc["token_endpoint"] = i.URL + "/token"
			doc["code_challenge_methods_supported"] = []string{"S256"}
			doc["authorization_response_iss_parameter_supported"] = !auth.noIss
			auth.mu.Unlock()
		}
		if hook != nil {
			hook(doc)
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		i.fetches.Add(1)
		i.mu.Lock()
		gate, arrive := i.gate, i.arrive
		i.mu.Unlock()
		if gate != nil {
			arrive()
			select {
			case <-gate:
			case <-r.Context().Done():
				return
			}
		}
		i.mu.Lock()
		defer i.mu.Unlock()
		if i.status != 0 {
			w.WriteHeader(i.status)
			return
		}
		if i.raw != nil {
			_, _ = w.Write(i.raw)
			return
		}
		var keys []map[string]any
		for kid, h := range i.keys {
			if i.published[kid] {
				keys = append(keys, JWK(kid, h.alg, h.key.Public()))
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
	mux.HandleFunc("GET /moved", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, i.URL+"/jwks", http.StatusFound)
	})
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		i.mu.Lock()
		a := i.auth
		i.mu.Unlock()
		if a == nil {
			http.NotFound(w, r)
			return
		}
		a.authorize(w, r)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		i.mu.Lock()
		a := i.auth
		i.mu.Unlock()
		if a == nil {
			http.NotFound(w, r)
			return
		}
		a.token(w, r)
	})
	i.srv = httptest.NewTLSServer(mux)
	i.URL = i.srv.URL
	i.AddKey(t, "k1", oidc.RS256)
	t.Cleanup(i.Close)
	return i
}

// Roots trusts the server's certificate.
func (i *Issuer) Roots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(i.srv.Certificate())
	return p
}

// CertPEM is the server's TLS certificate, PEM, as an operator's ca_file
// holds it.
func (i *Issuer) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.srv.Certificate().Raw})
}

// AddKey makes and publishes a key.
func (i *Issuer) AddKey(t testing.TB, kid string, alg oidc.Alg) {
	k := NewKey(t, alg)
	i.mu.Lock()
	defer i.mu.Unlock()
	i.keys[kid], i.published[kid] = held{alg: alg, key: k}, true
}

// Unpublish drops kid from the JWKS; the provider can still sign with it.
func (i *Issuer) Unpublish(kid string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	delete(i.published, kid)
}

// Fail answers discovery and the JWKS with status; 0 answers them again.
func (i *Issuer) Fail(status int) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.status = status
}

// ServeJWKS serves raw at /jwks in place of the keys; nil serves the keys.
func (i *Issuer) ServeJWKS(raw []byte) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.raw = raw
}

// Discovery alters the discovery document before it is sent.
func (i *Issuer) Discovery(f func(map[string]any)) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.discovery = f
}

// Hold stalls every /jwks request until release is called; arrived closes
// when the first stalled request comes in. A test holds a fetch in flight.
func (i *Issuer) Hold() (arrived <-chan struct{}, release func()) {
	gate, in := make(chan struct{}), make(chan struct{})
	var once sync.Once
	i.mu.Lock()
	i.gate, i.arrive = gate, func() { once.Do(func() { close(in) }) }
	i.mu.Unlock()
	return in, func() {
		i.mu.Lock()
		i.gate, i.arrive = nil, nil
		i.mu.Unlock()
		close(gate)
	}
}

// JWKSFetches is how many times /jwks was asked.
func (i *Issuer) JWKSFetches() int64 { return i.fetches.Load() }

// Token signs claims with kid's key, the header naming kid.
func (i *Issuer) Token(t testing.TB, kid string, claims map[string]any) string {
	return i.TokenWith(t, kid, map[string]any{"kid": kid}, claims)
}

// TokenWith signs claims with kid's key under header as given.
func (i *Issuer) TokenWith(t testing.TB, kid string, header, claims map[string]any) string {
	t.Helper()
	i.mu.Lock()
	h, ok := i.keys[kid]
	i.mu.Unlock()
	if !ok {
		t.Fatalf("oidctest: no key %q", kid)
	}
	return Sign(t, h.alg, h.key, header, claims)
}

// TokenRaw signs the payload body exactly as written, the header naming kid.
func (i *Issuer) TokenRaw(t testing.TB, kid, body string) string {
	t.Helper()
	i.mu.Lock()
	h, ok := i.keys[kid]
	i.mu.Unlock()
	if !ok {
		t.Fatalf("oidctest: no key %q", kid)
	}
	return SignRaw(t, h.alg, h.key, map[string]any{"kid": kid}, []byte(body))
}

// IDToken is a human's ID token for clientID at now: iss, aud, sub, iat,
// exp (now+5m), auth_time (now), sid "s-"+sub, and extra, where a nil
// value deletes a claim.
func (i *Issuer) IDToken(t testing.TB, kid, clientID, sub string, now time.Time, extra map[string]any) string {
	c := map[string]any{"iss": i.URL, "aud": clientID, "sub": sub, "iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(), "auth_time": now.Unix(), "sid": "s-" + sub}
	for k, v := range extra {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return i.Token(t, kid, c)
}

// Close stops the server: the provider is unreachable.
func (i *Issuer) Close() { i.srv.Close() }
