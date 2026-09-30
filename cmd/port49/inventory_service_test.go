package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/inventory"
	"github.com/rhwendt/port49/internal/testpki"
)

const servicePolicy = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: lab_key}]
`

const leaf01 = "  - {name: leaf-01, platform: arista_eos, addresses: [10.0.0.1]}\n"

// testService is port49-inventory in-process, its syncer the operator's
// certificate may drive: the lab inventory PKI's operator is a syncer.
type testService struct {
	url, ca, cert, key, dir string
	syncer                  *inventory.Syncer
}

func startService(t *testing.T) *testService {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	pki := filepath.Join(dir, "pki")
	if err := testpki.WriteInventoryLab(pki, time.Now()); err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(servicePolicy), 0o600)
	s := &testService{dir: dir, ca: filepath.Join(pki, testpki.InvCA), cert: filepath.Join(pki, testpki.InvOperatorCert),
		key: filepath.Join(pki, testpki.InvOperatorKey)}
	s.writeSource(t, leaf01)
	m := inventory.NewMetrics(prometheus.NewRegistry())
	s.syncer = &inventory.Syncer{Sources: []inventory.Source{inventory.FileSource{SourceName: "lab_file",
		Path: filepath.Join(dir, "inventory.yaml")}}, Bounds: map[string]int{}, Default: 10,
		PolicyFile: filepath.Join(dir, "policy.yaml"), Key: key, Metrics: m, Now: time.Now, Log: io.Discard,
		State: inventory.State{Dir: filepath.Join(dir, "state"), Keep: 64}}
	api := &inventory.API{Syncer: s.syncer, Syncers: []string{"user:alice@slice.port49.test"}, Now: time.Now,
		Log: io.Discard, Metrics: m}
	s.url = serveTLS(t, pki, api.Handler())
	return s
}

// serveTLS serves h as the lab inventory PKI's service, and is its URL.
func serveTLS(t *testing.T, pki string, h http.Handler) string {
	t.Helper()
	cert, anchor, err := broker.LoadTLS(filepath.Join(pki, testpki.InvServerCert), filepath.Join(pki, testpki.InvServerKey),
		filepath.Join(pki, testpki.InvCA))
	if err != nil {
		t.Fatal(err)
	}
	hs, err := inventory.Server("127.0.0.1:0", cert, anchor, h, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(hs.Handler)
	srv.TLS = hs.TLSConfig
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL
}

// writeSource writes "devices:" and body (device lines, or nothing).
func (s *testService) writeSource(t *testing.T, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(s.dir, "inventory.yaml"), []byte("devices:\n"+body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (s *testService) sync(t *testing.T) {
	t.Helper()
	if res := s.syncer.Sync(context.Background(), "api"); res.Outcome != "published" {
		t.Fatalf("%+v", res)
	}
}

func TestInventorySyncPrintsWhatTheServiceDid(t *testing.T) {
	svc := startService(t) // the in-process service, one device in its source
	var out, errOut bytes.Buffer
	args := []string{"inventory", "sync", "--service", svc.url, "--ca", svc.ca, "--cert", svc.cert, "--key", svc.key}
	if code := run(args, &out, &errOut); code != 0 || !strings.Contains(out.String(), "published bundle 1 (") {
		t.Fatalf("exit %d: %s %s", code, out.String(), errOut.String())
	}
	out.Reset()
	if code := run(args, &out, &errOut); code != 0 || !strings.Contains(out.String(), "unchanged: bundle 1 is current") {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	svc.writeSource(t, "") // no device: refused
	out.Reset()
	if code := run(args, &out, &errOut); code != 1 ||
		!strings.Contains(out.String(), "refused; still publishing bundle 1: the sources name no device") {
		t.Fatalf("exit %d: %s", code, out.String())
	}
}

func TestInventoryDiffAgainstTheService(t *testing.T) {
	svc := startService(t)
	svc.sync(t)
	svc.writeSource(t, leaf01+"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.0.2]}\n")
	svc.sync(t)
	var out, errOut bytes.Buffer
	if code := run([]string{"inventory", "diff", "--service", svc.url, "--ca", svc.ca, "--cert", svc.cert, "--key",
		svc.key, "--from", "1"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "bundle 1 → 2") ||
		!strings.Contains(out.String(), "! device added leaf-02") {
		t.Fatalf("exit %d: %s %s", code, out.String(), errOut.String())
	}
}

// --service is one mode and the offline diff the other: mixing them, or a
// client flag without --service, is a usage error.
func TestInventoryDiffServiceFlagsDoNotMix(t *testing.T) {
	for _, args := range [][]string{
		{"inventory", "diff", "--service", "https://inv.example", "--ca", "a", "--cert", "b", "--key", "c", "--from",
			"1", "--policy", "p"},
		{"inventory", "diff", "--service", "https://inv.example", "--ca", "a", "--cert", "b", "--key", "c", "--from",
			"1", "old.yaml", "new.yaml"},
		{"inventory", "diff", "--service", "https://inv.example", "--ca", "a", "--cert", "b", "--key", "c"},
		{"inventory", "diff", "--policy", "p", "--from", "1", "old.yaml", "new.yaml"},
		{"inventory", "sync", "--service", "https://inv.example", "--ca", "a", "--cert", "b"},
	} {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != 2 {
			t.Errorf("%v: exit %d: %s", args, code, errOut.String())
		}
	}
}

// F16: a sync is waited for up to syncWait, and one not answered in time
// says how long it was waited for and that the service may still finish it.
func TestInventorySyncSaysHowLongItWaited(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	pki := filepath.Join(dir, "pki")
	if err := testpki.WriteInventoryLab(pki, time.Now()); err != nil {
		t.Fatal(err)
	}
	url := serveTLS(t, pki, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer func(w time.Duration) { syncWait = w }(syncWait)
	syncWait = 200 * time.Millisecond
	var out, errOut bytes.Buffer
	code := run([]string{"inventory", "sync", "--service", url, "--ca", filepath.Join(pki, testpki.InvCA), "--cert",
		filepath.Join(pki, testpki.InvOperatorCert), "--key", filepath.Join(pki, testpki.InvOperatorKey)}, &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "no answer within 200ms") ||
		!strings.Contains(errOut.String(), "may still finish") {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
}

// What the service says is printed as text, never as terminal control.
func TestPrintResultPrintsNoControlCharacters(t *testing.T) {
	var out bytes.Buffer
	code := printResult(&out, inventory.Result{Outcome: "refused", Sequence: 3, Reason: "bad\x1b[2Jthing\nforged line"})
	if code != 1 || strings.ContainsAny(out.String(), "\x1b") || strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("exit %d: %q", code, out.String())
	}
}
