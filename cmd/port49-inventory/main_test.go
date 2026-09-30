package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/inventory"
	"github.com/rhwendt/port49/internal/keyfile"
	"github.com/rhwendt/port49/internal/testpki"
)

type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type fixture struct {
	dir, cfg, source string
	pki              string
}

const servicePolicy = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: lab_key}]
`

func newFixture(t *testing.T, keyMode os.FileMode) fixture {
	t.Helper()
	f := fixture{dir: t.TempDir()}
	if err := os.Chmod(f.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f.pki = filepath.Join(f.dir, "pki")
	if err := testpki.WriteInventoryLab(f.pki, time.Now()); err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	privPEM, _, err := keyfile.EncodeEd25519(priv)
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(f.dir, "signing.key")
	if err := os.WriteFile(key, privPEM, keyMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(key, keyMode); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "policy.yaml"), []byte(servicePolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	f.source = filepath.Join(f.dir, "inventory.yaml")
	f.writeSource(t, 1)
	f.cfg = filepath.Join(f.dir, "port49-inventory.yaml")
	if err := os.WriteFile(f.cfg, []byte(fmt.Sprintf(`
listen: 127.0.0.1:0
metrics_listen: 127.0.0.1:0
tls_cert_file: %[1]s/%[2]s
tls_key_file: %[1]s/%[3]s
client_ca_file: %[1]s/%[4]s
readers: [%[5]q]
syncers: ["user:alice@slice.port49.test"]
signing_key_file: %[6]s
policy_file: %[7]s
state_dir: %[8]s
sync: [{name: lab_file, type: file, path: %[9]s}]
`, f.pki, testpki.InvServerCert, testpki.InvServerKey, testpki.InvCA, testpki.InvDaemonID, key,
		filepath.Join(f.dir, "policy.yaml"), filepath.Join(f.dir, "state"), f.source)), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f fixture) writeSource(t *testing.T, n int) {
	t.Helper()
	var b strings.Builder
	b.WriteString("devices:\n")
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "  - {name: leaf-%02d, platform: arista_eos, addresses: [10.0.0.%d]}\n", i, i)
	}
	if err := os.WriteFile(f.source, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f fixture) client(t *testing.T, cert, key string) *http.Client {
	t.Helper()
	c, err := tls.LoadX509KeyPair(filepath.Join(f.pki, cert), filepath.Join(f.pki, key))
	if err != nil {
		t.Fatal(err)
	}
	caPEM, _ := os.ReadFile(filepath.Join(f.pki, testpki.InvCA))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pool, Certificates: []tls.Certificate{c}}}}
}

// start runs the service and returns its API and metrics addresses.
func start(t *testing.T, f fixture, out *syncBuffer, hup chan os.Signal) (string, string, chan error) {
	t.Helper()
	e := stderr
	t.Cleanup(func() { stderr = e; onListening = nil })
	stderr = out
	addrs := make(chan [2]string, 1)
	onListening = func(api, metrics string) { addrs <- [2]string{api, metrics} }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, f.cfg, hup) }()
	t.Cleanup(func() { cancel(); <-done })
	select {
	case a := <-addrs:
		return a[0], a[1], done
	case err := <-done:
		t.Fatalf("run: %v; stderr %s", err, out)
	case <-time.After(10 * time.Second):
		t.Fatalf("not listening: %s", out)
	}
	return "", "", nil
}

func waitFor(t *testing.T, out *syncBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(out.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("waited for %q; have %q", want, out)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func get(t *testing.T, c *http.Client, url string) (int, string) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestTheServiceStartsSyncsAndResyncsOnSIGHUP(t *testing.T) {
	f := newFixture(t, 0o600)
	var out syncBuffer
	hup := make(chan os.Signal, 1)
	api, metrics, _ := start(t, f, &out, hup)
	waitFor(t, &out, "port49-inventory: sync (startup): published bundle 1 ")
	if code, _ := get(t, http.DefaultClient, "http://"+metrics+"/readyz"); code != 200 {
		t.Fatalf("readyz %d", code)
	}
	reader := f.client(t, testpki.InvDaemonCert, testpki.InvDaemonKey)
	if code, body := get(t, reader, "https://"+api+"/v1/bundle/version"); code != 200 ||
		!strings.Contains(body, `"sequence":1`) {
		t.Fatalf("%d %s", code, body)
	}
	f.writeSource(t, 2)
	hup <- syscall.SIGHUP
	waitFor(t, &out, "port49-inventory: sync (signal): published bundle 2 ")
}

// No source, no bundle: the service is up and says why, and is not ready.
func TestAServiceWithNoBundleIsNotReady(t *testing.T) {
	f := newFixture(t, 0o600)
	os.Remove(f.source)
	var out syncBuffer
	_, metrics, _ := start(t, f, &out, make(chan os.Signal))
	waitFor(t, &out, "port49-inventory: sync (startup) failed; no bundle is published yet: source lab_file:")
	if code, _ := get(t, http.DefaultClient, "http://"+metrics+"/readyz"); code != 503 {
		t.Fatalf("readyz %d", code)
	}
}

func TestASigningKeyOthersCanReadRefusesTheStart(t *testing.T) {
	f := newFixture(t, 0o640)
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	err := run(context.Background(), f.cfg, make(chan os.Signal))
	if err == nil || !strings.Contains(err.Error(), "signing_key_file") || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("got %v", err)
	}
}

// A signing key file that does not decode is named, never echoed.
func TestASigningKeyThatDoesNotDecodeIsNotEchoed(t *testing.T) {
	f := newFixture(t, 0o600)
	const secret = "not-a-key-but-secret-bytes-7f3a"
	key := filepath.Join(f.dir, "signing.key")
	if err := os.WriteFile(key, []byte("-----BEGIN PRIVATE KEY-----\n"+secret+"\n-----END PRIVATE KEY-----\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	err := run(context.Background(), f.cfg, make(chan os.Signal))
	if err == nil || !strings.Contains(err.Error(), "signing_key_file") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(out.String(), secret) {
		t.Fatalf("the key file's text reached the error or the log: %v; %s", err, &out)
	}
}

// A state_dir bundle the service cannot open refuses the start: it never
// listens, and the error says so once.
func TestAStateBundleThatDoesNotOpenRefusesTheStart(t *testing.T) {
	f := newFixture(t, 0o600)
	state := filepath.Join(f.dir, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "published.json"), []byte(`{"not":"a bundle"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	e := stderr
	defer func() { stderr = e; onListening = nil }()
	stderr = &out
	onListening = func(string, string) { t.Error("listened after a Restore error") }
	err := run(context.Background(), f.cfg, make(chan os.Signal))
	if err == nil || !strings.Contains(err.Error(), "does not start") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(out.String(), "does not start") {
		t.Fatalf("said twice: %s", &out)
	}
}

// Health lives on the metrics listener; the mutual-TLS API has no such path.
func TestHealthIsOnlyOnTheMetricsListener(t *testing.T) {
	f := newFixture(t, 0o600)
	var out syncBuffer
	api, metrics, _ := start(t, f, &out, make(chan os.Signal))
	if code, _ := get(t, http.DefaultClient, "http://"+metrics+"/healthz"); code != 200 {
		t.Fatalf("metrics healthz %d", code)
	}
	reader := f.client(t, testpki.InvDaemonCert, testpki.InvDaemonKey)
	for _, p := range []string{"/healthz", "/readyz"} {
		if code, _ := get(t, reader, "https://"+api+p); code != 404 {
			t.Fatalf("api %s %d", p, code)
		}
	}
}

// A shutdown closes both listeners, joins every goroutine before run
// returns, and says nothing false on the way out.
func TestShutdownClosesEverythingAndSaysNothingFalse(t *testing.T) {
	f := newFixture(t, 0o600)
	var out syncBuffer
	e := stderr
	defer func() { stderr = e; onListening = nil }()
	stderr = &out
	addrs := make(chan [2]string, 1)
	onListening = func(api, metrics string) { addrs <- [2]string{api, metrics} }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, f.cfg, make(chan os.Signal)) }()
	var a [2]string
	select {
	case a = <-addrs:
	case err := <-done:
		t.Fatalf("run: %v; %s", err, &out)
	case <-time.After(10 * time.Second):
		t.Fatalf("not listening: %s", &out)
	}
	waitFor(t, &out, "sync (startup): published bundle 1 ")
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("run did not return: %s", &out)
	}
	said := out.String()
	if strings.Contains(said, "failed") || strings.Contains(said, "context canceled") {
		t.Fatalf("a false line at shutdown: %s", said)
	}
	if !strings.HasSuffix(said, "port49-inventory: signal received, exiting\n") {
		t.Fatalf("last line: %s", said)
	}
	c := &http.Client{Timeout: 2 * time.Second}
	if _, err := c.Get("http://" + a[1] + "/healthz"); err == nil {
		t.Fatal("metrics still listening")
	}
	if conn, err := net.DialTimeout("tcp", a[0], 2*time.Second); err == nil {
		conn.Close()
		t.Fatal("API still listening")
	}
}

// heldSource answers its first fetch, then holds every later one until its
// ctx is done, telling held when it starts holding.
type heldSource struct {
	fetches atomic.Int32
	held    chan struct{}
}

func (h *heldSource) Name() string { return "lab_file" }
func (h *heldSource) Fetch(ctx context.Context) (admission.Inventory, error) {
	if h.fetches.Add(1) == 1 {
		return admission.Inventory{Devices: []admission.Device{{Name: "leaf-01", Platform: "arista_eos",
			Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}, Transport: admission.TransportTCP}}}, nil
	}
	h.held <- struct{}{}
	<-ctx.Done()
	return admission.Inventory{}, ctx.Err()
}

// A shutdown ends a POST /v1/sync in flight at once, not at sync_timeout,
// and says nothing of it.
func TestShutdownEndsAnAPISyncInFlight(t *testing.T) {
	f := newFixture(t, 0o600)
	src := &heldSource{held: make(chan struct{}, 1)}
	orig := newSources
	defer func() { newSources = orig }()
	newSources = func([]inventory.SourceConfig) ([]inventory.Source, error) { return []inventory.Source{src}, nil }
	var out syncBuffer
	e := stderr
	defer func() { stderr = e; onListening = nil }()
	stderr = &out
	addrs := make(chan [2]string, 1)
	onListening = func(api, metrics string) { addrs <- [2]string{api, metrics} }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, f.cfg, make(chan os.Signal)) }()
	var a [2]string
	select {
	case a = <-addrs:
	case err := <-done:
		t.Fatalf("run: %v; %s", err, &out)
	case <-time.After(10 * time.Second):
		t.Fatalf("not listening: %s", &out)
	}
	waitFor(t, &out, "sync (startup): published bundle 1 ")
	syncer := f.client(t, testpki.InvOperatorCert, testpki.InvOperatorKey)
	posted := make(chan error, 1)
	go func() {
		resp, err := syncer.Post("https://"+a[0]+"/v1/sync", "application/json", nil)
		if err == nil {
			resp.Body.Close()
		}
		posted <- err
	}()
	select {
	case <-src.held:
	case <-time.After(10 * time.Second):
		t.Fatalf("the API sync never reached the source: %s", &out)
	}
	began := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("run did not return: %s", &out)
	}
	if d := time.Since(began); d >= grace {
		t.Fatalf("shutdown waited %v, the full grace: the API sync was not canceled", d)
	}
	<-posted
	if said := out.String(); strings.Contains(said, "failed") || strings.Contains(said, "context canceled") {
		t.Fatalf("a false line at shutdown: %s", said)
	}
}

// An empty client_ca_file refuses the start: the API never falls back to the
// host's system roots.
func TestAnEmptyClientCARefusesTheStart(t *testing.T) {
	f := newFixture(t, 0o600)
	if err := os.WriteFile(filepath.Join(f.pki, testpki.InvCA), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	e := stderr
	defer func() { stderr = e; onListening = nil }()
	stderr = &out
	onListening = func(string, string) { t.Error("listened without a client trust anchor") }
	err := run(context.Background(), f.cfg, make(chan os.Signal))
	if err == nil || !strings.Contains(err.Error(), "client_ca_file") {
		t.Fatalf("got %v", err)
	}
}
