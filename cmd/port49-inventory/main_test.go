package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/inventory"
	"github.com/rhwendt/port49/internal/keyfile"
	"github.com/rhwendt/port49/internal/sot/sottest"
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
	newSources = func([]inventory.SourceConfig, io.Writer) ([]inventory.Source, error) {
		return []inventory.Source{src}, nil
	}
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

// Final review I3: a Restore held up by a mirror mount that hangs is
// visible — the metrics listener is up and not ready — and a SIGTERM still
// stops the service, quietly.
func TestAStartHeldUpByTheMirrorIsVisibleAndStopsOnSIGTERM(t *testing.T) {
	f := newFixture(t, 0o600)
	var out syncBuffer
	e, r := stderr, restore
	defer func() { stderr, restore, onListening = e, r, nil }()
	stderr = &out
	onListening = func(string, string) { t.Error("the API listened with Restore still waiting") }
	entered := make(chan struct{})
	restore = func(_ *inventory.Syncer, ctx context.Context) error {
		close(entered)
		<-ctx.Done() // a mount that hangs, until the signal
		return ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, f.cfg, make(chan os.Signal)) }()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("run: %v; stderr %s", err, &out)
	case <-time.After(10 * time.Second):
		t.Fatalf("Restore was never reached: %s", &out)
	}
	m := regexp.MustCompile(`port49-inventory: metrics on (127\.0\.0\.1:\d+)`).FindStringSubmatch(out.String())
	if m == nil {
		cancel()
		<-done
		t.Fatalf("the metrics listener is not up before Restore: %s", &out)
	}
	if code, _ := get(t, http.DefaultClient, "http://"+m[1]+"/healthz"); code != 200 {
		t.Errorf("healthz %d", code)
	}
	if code, _ := get(t, http.DefaultClient, "http://"+m[1]+"/readyz"); code != 503 {
		t.Errorf("readyz %d", code)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a SIGTERM during Restore is an error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("SIGTERM did not stop a service held up in Restore: %s", &out)
	}
}

const (
	testHookSecret  = "l33-unit-test-webhook-secret-0123456789"
	testNetboxToken = "nbt_abcdefabcdef.0123456789abcdef0123456789abcdef01234567"
)

func signHook(body []byte) string {
	mac := hmac.New(sha512.New, []byte(testHookSecret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// hookFixture is newFixture with a NetBox source taking webhooks on
// listen in place of the file source, and the debouncer's settle and gap.
func hookFixture(t *testing.T, listen string, settle, gap time.Duration) (fixture, *sottest.Server) {
	t.Helper()
	s, g := webhookSettle, webhookGap
	t.Cleanup(func() { webhookSettle, webhookGap = s, g })
	webhookSettle, webhookGap = settle, gap
	t.Setenv("PORT49_TEST_NETBOX_TOKEN", testNetboxToken)
	t.Setenv("PORT49_TEST_NETBOX_HOOK", testHookSecret)
	nb := sottest.New(t, "netbox-4", 3)
	nb.Auth = "Bearer " + testNetboxToken
	f := newFixture(t, 0o600)
	raw, err := os.ReadFile(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.Replace(string(raw), "sync: [{name: lab_file, type: file, path: "+f.source+"}]",
		fmt.Sprintf("webhook_listen: %s\nsync:\n  - {name: netbox_prod, type: netbox, url: %q, ca_file: %s, "+
			"token_secret_ref: env:PORT49_TEST_NETBOX_TOKEN, webhook_secret_ref: env:PORT49_TEST_NETBOX_HOOK}\n", listen,
			nb.URL, nb.CAFile), 1)
	if cfg == string(raw) {
		t.Fatal("the fixture's sync line moved; update this test")
	}
	if err := os.WriteFile(f.cfg, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return f, nb
}

// startHooked starts the service and returns the webhook listener's
// address once the startup sync has published.
func startHooked(t *testing.T, f fixture, out *syncBuffer, hup chan os.Signal) (string, string) {
	t.Helper()
	hooks := make(chan string, 1)
	onWebhook = func(addr string) { hooks <- addr }
	t.Cleanup(func() { onWebhook = nil })
	_, metrics, _ := start(t, f, out, hup)
	addr := <-hooks
	waitFor(t, out, "sync (startup): published bundle 1")
	waitFor(t, out, "webhooks on "+addr+" for netbox_prod")
	return addr, metrics
}

// postHook posts a delivery stamped now, signed by sig or, when sig is "",
// by testHookSecret, and returns the status code.
func postHook(t *testing.T, c *http.Client, addr, sig string) int {
	t.Helper()
	b := []byte(`{"event": "created", "timestamp": "` +
		time.Now().UTC().Format("2006-01-02T15:04:05.000000-07:00") + `", "object_type": "dcim.device"}`)
	if sig == "" {
		sig = signHook(b)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://"+addr+"/v1/webhook/netbox_prod", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hook-Signature", sig)
	resp, err := c.Do(req)
	if err != nil {
		t.Error(err)
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

// Spec §10, decision 31: a NetBox source, its webhook on a TLS listener of
// its own, and an authentic delivery that syncs the source; a mis-signed one
// syncs nothing.
func TestAWebhookTriggersASyncOfItsSource(t *testing.T) {
	f, nb := hookFixture(t, "127.0.0.1:0", 10*time.Millisecond, 10*time.Millisecond)
	var out syncBuffer
	addr, metrics := startHooked(t, f, &out, make(chan os.Signal, 1))
	nb.SetDevices(4)
	c := f.client(t, testpki.InvOperatorCert, testpki.InvOperatorKey)
	if code := postHook(t, c, addr, strings.Repeat("ab", 64)); code != http.StatusUnauthorized {
		t.Fatalf("mis-signed: %d", code)
	}
	// The refusal is counted before this looks, and a Notify it made would
	// sync 10ms (the settle) later. The handler's tests pin that a 401
	// notifies no one; this is the end-to-end smoke check.
	waitForMetric(t, metrics, `port49_inventory_webhooks_total{outcome="bad_signature",source="netbox_prod"} 1`)
	time.Sleep(100 * time.Millisecond)
	if strings.Contains(out.String(), "sync (webhook)") {
		t.Fatalf("a mis-signed delivery synced: %s", &out)
	}
	if code := postHook(t, c, addr, ""); code != http.StatusAccepted {
		t.Fatalf("signed: %d", code)
	}
	waitFor(t, &out, "sync (webhook): published bundle 2")
	for _, leak := range []string{testNetboxToken, testHookSecret} {
		if strings.Contains(out.String(), leak) {
			t.Fatalf("the log holds a secret: %s", &out)
		}
	}
}

// A webhook_listen already taken refuses the start, naming the key.
func TestAWebhookListenInUseRefusesTheStart(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	f, _ := hookFixture(t, taken.Addr().String(), time.Hour, time.Hour)
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	err = run(context.Background(), f.cfg, make(chan os.Signal))
	if err == nil || !strings.HasPrefix(err.Error(), "webhook_listen "+taken.Addr().String()+": ") {
		t.Fatalf("run: %v", err)
	}
}

// A shutdown with a webhook sync pending drops it: run returns at once,
// starts no sync, and says nothing false.
func TestShutdownWithAWebhookSyncPending(t *testing.T) {
	f, nb := hookFixture(t, "127.0.0.1:0", time.Hour, time.Hour)
	var out syncBuffer
	hooks := make(chan string, 1)
	onWebhook = func(addr string) { hooks <- addr }
	defer func() { onWebhook = nil }()
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, f.cfg, make(chan os.Signal)) }()
	var addr string
	select {
	case addr = <-hooks:
	case err := <-done:
		t.Fatalf("run: %v; %s", err, &out)
	case <-time.After(10 * time.Second):
		t.Fatalf("no webhook listener: %s", &out)
	}
	waitFor(t, &out, "sync (startup): published bundle 1 ")
	nb.SetDevices(4)
	c := f.client(t, testpki.InvOperatorCert, testpki.InvOperatorKey)
	if code := postHook(t, c, addr, ""); code != http.StatusAccepted {
		t.Fatalf("signed: %d", code)
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
		t.Fatalf("shutdown took %v", d)
	}
	said := out.String()
	if strings.Contains(said, "sync (webhook)") || strings.Contains(said, "failed") ||
		strings.Contains(said, "context canceled") {
		t.Fatalf("a pending webhook sync was run or said at shutdown: %s", said)
	}
	if !strings.HasSuffix(said, "port49-inventory: signal received, exiting\n") {
		t.Fatalf("last line: %s", said)
	}
	if conn, err := net.DialTimeout("tcp", addr, 2*time.Second); err == nil {
		conn.Close()
		t.Fatal("the webhook listener is still open")
	}
}

// gated holds a source's second Fetch (the webhook's) until release, and
// counts fetches in flight.
type gated struct {
	inventory.Source
	calls, in, maxIn *int32
	entered, release chan struct{}
}

func (g gated) Fetch(ctx context.Context) (admission.Inventory, error) {
	n := atomic.AddInt32(g.calls, 1)
	cur := atomic.AddInt32(g.in, 1)
	for m := atomic.LoadInt32(g.maxIn); cur > m && !atomic.CompareAndSwapInt32(g.maxIn, m, cur); m = atomic.LoadInt32(g.maxIn) {
	}
	defer atomic.AddInt32(g.in, -1)
	if n == 2 {
		g.entered <- struct{}{}
		<-g.release
	}
	return g.Source.Fetch(ctx)
}

// A SIGHUP taken while a webhook's sync is inside its Fetch: the signal's
// sync waits for it, never fetching beside it, then runs.
func TestASIGHUPRacingAWebhookSync(t *testing.T) {
	f, nb := hookFixture(t, "127.0.0.1:0", time.Millisecond, time.Millisecond)
	var calls, in, maxIn int32
	entered, release := make(chan struct{}, 1), make(chan struct{})
	orig := newSources
	t.Cleanup(func() { newSources = orig })
	newSources = func(c []inventory.SourceConfig, w io.Writer) ([]inventory.Source, error) {
		ss, err := orig(c, w)
		for i := range ss {
			ss[i] = gated{ss[i], &calls, &in, &maxIn, entered, release}
		}
		return ss, err
	}
	var out syncBuffer
	hup := make(chan os.Signal) // unbuffered: the send returns once the main loop has it
	addr, metrics := startHooked(t, f, &out, hup)
	nb.SetDevices(4)
	c := f.client(t, testpki.InvOperatorCert, testpki.InvOperatorKey)
	if code := postHook(t, c, addr, ""); code != http.StatusAccepted {
		t.Fatalf("signed: %d", code)
	}
	<-entered
	hup <- syscall.SIGHUP
	close(release)
	waitFor(t, &out, "sync (webhook): published bundle 2")
	waitForMetric(t, metrics, `trigger="signal"}`)
	if n := atomic.LoadInt32(&calls); n != 3 {
		t.Fatalf("%d fetches", n)
	}
	if m := atomic.LoadInt32(&maxIn); m != 1 {
		t.Fatalf("%d fetches at once", m)
	}
	if strings.Contains(out.String(), "failed") {
		t.Fatalf("%s", &out)
	}
}

// waitForMetric polls the metrics listener until its text holds want. An
// unchanged sync logs nothing, so a metric is how a test sees it.
func waitForMetric(t *testing.T, metrics, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, body := get(t, http.DefaultClient, "http://"+metrics+"/metrics")
		if strings.Contains(body, want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited for %q in %s", want, body)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// writeSelfSigned writes a P-256 certificate for 127.0.0.1 named cn, and
// its key, mode 0600, into dir.
func writeSelfSigned(t *testing.T, dir, cn string) (string, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	cf, kf := filepath.Join(dir, "webhook.pem"), filepath.Join(dir, "webhook-key.pem")
	if err := os.WriteFile(cf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
	return cf, kf
}

// Decision 31: the webhook listener presents webhook_tls_cert_file's
// certificate, not the API's; answers plain HTTP with 400 before any
// handler; and holds at most maxWebhookConns connections, counted before
// the handshake, so no caller holds more pre-auth reads than that.
func TestTheWebhookListenerHasItsOwnCertificateAndACap(t *testing.T) {
	f, _ := hookFixture(t, "127.0.0.1:0", time.Hour, time.Hour)
	cf, kf := writeSelfSigned(t, f.dir, "webhook-own")
	raw, err := os.ReadFile(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.Replace(string(raw), "webhook_listen:",
		"webhook_tls_cert_file: "+cf+"\nwebhook_tls_key_file: "+kf+"\nwebhook_listen:", 1)
	if err := os.WriteFile(f.cfg, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	addr, _ := startHooked(t, f, &out, make(chan os.Signal, 1))
	insecure := &tls.Config{InsecureSkipVerify: true}

	conn, err := tls.Dial("tcp", addr, insecure)
	if err != nil {
		t.Fatal(err)
	}
	if cn := conn.ConnectionState().PeerCertificates[0].Subject.CommonName; cn != "webhook-own" {
		t.Fatalf("the webhook listener presented %q", cn)
	}
	conn.Close()

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Post("http://"+addr+"/v1/webhook/netbox_prod",
		"application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("plain HTTP: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("plain HTTP answered %d", resp.StatusCode)
	}

	// maxWebhookConns raw connections that never handshake hold every slot.
	held := make([]net.Conn, 0, maxWebhookConns)
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for i := 0; i < maxWebhookConns; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	if c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr, insecure); err == nil {
		c.Close()
		t.Fatalf("connection %d completed a handshake", maxWebhookConns+1)
	}
	held[0].Close()
	held = held[1:]
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, insecure)
	if err != nil {
		t.Fatalf("after a slot was freed: %v", err)
	}
	c.Close()
}

// The start says how each source is fetched, and never the proxy's
// credentials or a proxy value it could not read.
func TestTheStartSaysHowEachSourceIsFetched(t *testing.T) {
	sync := []inventory.SourceConfig{{Name: "lab_file", Type: "file"},
		{Name: "netbox_prod", Type: "netbox", URL: "https://netbox.example.com"}}
	for env, want := range map[string]string{
		"": "source netbox_prod is fetched directly (no HTTPS_PROXY)",
		"http://svc:FAKE-pw@proxy.example.com:3128":   "source netbox_prod is fetched through the proxy http://proxy.example.com:3128 (with credentials) (HTTPS_PROXY)",
		"http://svc:FAKE-pw#x@proxy.example.com:3128": "source netbox_prod is fetched with an HTTPS_PROXY that does not parse as a proxy URL",
	} {
		t.Setenv("HTTPS_PROXY", env)
		var out bytes.Buffer
		sayEgress(&out, sync)
		if !strings.Contains(out.String(), want) || strings.Contains(out.String(), "FAKE-pw") ||
			strings.Contains(out.String(), "lab_file") {
			t.Errorf("HTTPS_PROXY set %v: %q", env != "", out.String())
		}
	}
}
