package broker

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/session"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/token"
)

const testPolicy = `
scopes:
  - {name: all_devices, match: {}}
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
  - {name: no_reload, deny: ["reload **"]}
subjects:
  - {name: netops, identity: ["user:alice@example.com"], username: alice, enable: token, token_ttl: 60s}
  - {name: idle, identity: ["user:carol@example.com"], username: carol, token_ttl: 60s}
grants:
  - {subject: netops, scope: all_devices, roles: [network_admin, no_reload], max_privilege: admin}
`

type fixture struct {
	b     *Broker
	st    *memory.Store
	log   *bytes.Buffer
	now   time.Time
	ca    *testpki.CA
	alice tls.Certificate
	mu    sync.Mutex
	// devices is the inventory the fixture's policy is loaded against, by
	// name, for tests that load another policy over it.
	devices map[string]admission.Device
}

// newFixture's clock starts at the real time: Task 10's handshakes verify
// certificates against it, and the fixture's certificates are cut around it.
// "bare" is in inventory with no platform, which admission.LoadFile allows.
func newFixture(t *testing.T, candidateCap int) *fixture {
	t.Helper()
	f := &fixture{log: &bytes.Buffer{}, now: time.Now().Truncate(time.Second)}
	clock := func() time.Time {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.now
	}
	f.st = memory.New(clock)
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(testPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	devices := map[string]admission.Device{
		"leaf1": {Name: "leaf1", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.11")}},
		"nx1":   {Name: "nx1", Platform: "cisco_nxos", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.31")}},
		"bare":  {Name: "bare", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.41")}},
	}
	pol, err := policy.Load(path, policy.Env{Devices: []admission.Device{devices["leaf1"], devices["nx1"], devices["bare"]}})
	if err != nil {
		t.Fatal(err)
	}
	f.devices = devices
	if f.ca, err = testpki.NewCA("port49 test ca", f.now.Add(-time.Hour), f.now.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	f.alice = f.client(t, "alice@example.com", f.now.Add(24*time.Hour))
	log := decision.NewJSONLines(f.log)
	f.b = &Broker{Policy: policy.NewLive(pol),
		Minter: token.NewMinter(f.st, log, rand.Reader, token.TagKey([]byte("k")), clock, candidateCap),
		Store:  f.st, Log: log, Metrics: metrics.New(prometheus.NewRegistry()), Now: clock,
		MaxSessionAge: 12 * time.Hour, BatchMax: 4, Sessions: session.New(f.st, clock, time.Hour, time.Hour)}
	return f
}

// liveContext writes a live context for principal under (device, username),
// indexed by principal and certificate, as a redemption would.
func (f *fixture) liveContext(t *testing.T, device, username, principal, certKey string) {
	t.Helper()
	ctx := context.Background()
	k := store.ContextKey{NAS: device, Username: username}
	if err := f.st.PutContext(ctx, k, store.Context{CtxID: "ctx_" + device, Principal: principal, Username: username,
		PrivLvl: 1, AuthTime: f.now, RefreshedAt: f.now}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.IndexContext(ctx, principal, "", certKey, store.ContextRef{NAS: device, Username: username},
		time.Hour); err != nil {
		t.Fatal(err)
	}
}

// certKey is the mark key of c, as Identity names its credential.
func certKey(c tls.Certificate) string {
	return store.CertKey(c.Leaf.Issuer.String(), c.Leaf.SerialNumber.Text(16))
}

// advance moves the clock under the lock, for tests where a server goroutine
// reads it. Single-goroutine tests may still assign f.now directly.
func (f *fixture) advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

func (f *fixture) client(t *testing.T, email string, notAfter time.Time) tls.Certificate {
	t.Helper()
	c, err := f.ca.Issue(testpki.Leaf{CommonName: email, Emails: []string{email}, Client: true,
		NotBefore: f.now.Add(-time.Hour), NotAfter: notAfter})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fixture) state(c tls.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{c.Leaf, f.ca.Cert}}}
}

func (f *fixture) post(ctx context.Context, cs *tls.ConnectionState, body, key string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/v1/tokens", strings.NewReader(body)).WithContext(ctx)
	r.TLS = cs
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	w := httptest.NewRecorder()
	f.b.Handler().ServeHTTP(w, r)
	return w
}

func (f *fixture) records(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(f.log.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

// blobRecords are the log's blob events with their bodies as the exact bytes
// written, which a map would re-encode.
func (f *fixture) blobRecords(t *testing.T) []decision.Blob {
	t.Helper()
	var out []decision.Blob
	for _, line := range strings.Split(strings.TrimSpace(f.log.String()), "\n") {
		var r struct {
			Event string         `json:"event"`
			Blob  *decision.Blob `json:"blob"`
		}
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		if r.Event == decision.EventBlob {
			if r.Blob == nil {
				t.Fatalf("a blob event with no blob: %s", line)
			}
			out = append(out, *r.Blob)
		}
	}
	return out
}

func decodeMint(t *testing.T, w *httptest.ResponseRecorder) api.MintResponse {
	t.Helper()
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var r api.MintResponse
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func eventsOf(recs []map[string]any, event string) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if r["event"] == event {
			out = append(out, r)
		}
	}
	return out
}
