package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/edkey"
	"github.com/rhwendt/port49/internal/fence"
	"github.com/rhwendt/port49/internal/inventory"
	"github.com/rhwendt/port49/internal/policy"
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
	url, ca, cert, key, dir, pub string
	syncer                       *inventory.Syncer
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
	_, pubPEM, err := edkey.EncodeEd25519(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "signing.pub"), pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(servicePolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &testService{dir: dir, ca: filepath.Join(pki, testpki.InvCA), cert: filepath.Join(pki, testpki.InvOperatorCert),
		key: filepath.Join(pki, testpki.InvOperatorKey), pub: filepath.Join(dir, "signing.pub")}
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

// A service that cannot be reached was asked for nothing: the CLI says so,
// not that a sync may still finish.
func TestInventorySyncToNoServiceSaysNoSyncWasAsked(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	pki := filepath.Join(dir, "pki")
	if err := testpki.WriteInventoryLab(pki, time.Now()); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens there now
	var out, errOut bytes.Buffer
	code := run([]string{"inventory", "sync", "--service", "https://" + addr, "--ca", filepath.Join(pki, testpki.InvCA),
		"--cert", filepath.Join(pki, testpki.InvOperatorCert), "--key", filepath.Join(pki, testpki.InvOperatorKey)},
		&out, &errOut)
	if code != 1 || strings.Contains(errOut.String(), "may still finish") ||
		!strings.Contains(errOut.String(), "no sync was asked for") {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
}

// What the service says is printed as text, never as terminal control.
func TestPrintResultPrintsNoControlCharacters(t *testing.T) {
	var out bytes.Buffer
	code := printResult(&out, inventory.Result{Outcome: "refused", Sequence: 3,
		Reason: "bad\x1b[2Jthing\nforged line\u2028and\u2029another\u202eflipped"})
	if code != 1 || strings.ContainsAny(out.String(), "\x1b\u2028\u2029\u202e") || strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("exit %d: %q", code, out.String())
	}
}

func TestInventorySyncPrintsAGenericPlatform(t *testing.T) {
	svc := startService(t)
	svc.writeSource(t, "  - {name: leaf-01, platform: eos-lab, addresses: [10.0.0.1]}\n")
	var out, errOut bytes.Buffer
	args := []string{"inventory", "sync", "--service", svc.url, "--ca", svc.ca, "--cert", svc.cert, "--key", svc.key}
	if code := run(args, &out, &errOut); code != 0 ||
		!strings.Contains(out.String(), "  platform eos-lab (1 device(s)) has no adapter in the policy and is served "+
			"by the generic one, priv-lvl only (spec §8)") {
		t.Fatalf("exit %d: %s %s", code, out.String(), errOut.String())
	}
}

func exportArgs(svc *testService, more ...string) []string {
	return append([]string{"inventory", "export", "--service", svc.url, "--ca", svc.ca, "--cert", svc.cert, "--key",
		svc.key, "--verify-key", svc.pub}, more...)
}

// Spec §12: the export is a file the offline tools take, for the same
// bundle the service published, and it never writes over a file.
func TestInventoryExportWritesWhatTheOfflineToolsRead(t *testing.T) {
	svc := startService(t)
	svc.writeSource(t, leaf01+"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.0.2, \"2001:db8::2\"], "+
		"attributes: {site: dc1}}\n")
	svc.sync(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil { // the fence refuses a directory others could write
		t.Fatal(err)
	}
	out := filepath.Join(dir, "inventory.yaml")
	var stdout, stderr bytes.Buffer
	if code := run(exportArgs(svc, "--out", out), &stdout, &stderr); code != 0 ||
		!strings.Contains(stderr.String(), "port49 inventory export: bundle 1, 2 device(s), written to "+out) {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	fi, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("the export's mode is %v, not 0600", fi.Mode().Perm()) // pre-flight M8
	}
	// port49d reads inventory_file behind the fence, then parses it and the
	// policy into the bundle it serves.
	raw, err := fence.Read(out, 64<<20, "inventory file")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := admission.ParseFile(raw, out)
	if err != nil || len(inv.Devices) != 2 {
		t.Fatalf("%+v %v", inv, err)
	}
	pol, err := os.ReadFile(filepath.Join(svc.dir, "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := bundle.ID(pol, inv), svc.syncer.Current().Doc.Bundle; got != want {
		t.Fatalf("the export is bundle %s, the service published %s", got, want)
	}
	if p, err := bundle.Load(filepath.Join(svc.dir, "policy.yaml"), out, policy.Env{}); err != nil ||
		p.Bundle != svc.syncer.Current().Doc.Bundle {
		t.Fatalf("port49d's load: %v", err)
	}
	stderr.Reset()
	if code := run(exportArgs(svc, "--out", out), &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "exists") {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}

func TestInventoryExportReadsTheHistory(t *testing.T) {
	svc := startService(t)
	svc.sync(t)
	svc.writeSource(t, leaf01+"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.0.2]}\n")
	svc.sync(t)
	var stdout, stderr bytes.Buffer
	if code := run(exportArgs(svc, "--from", "1"), &stdout, &stderr); code != 0 ||
		!strings.HasPrefix(stdout.String(), "# port49 inventory export: bundle 1 (sha256:") ||
		!strings.Contains(stdout.String(), "name: leaf-01") || strings.Contains(stdout.String(), "leaf-02") {
		t.Fatalf("exit %d: %s %s", code, stdout.String(), stderr.String())
	}
	stderr.Reset()
	if code := run(exportArgs(svc, "--from", "99"), &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "answered 404 (not_kept)") {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}

// Decision 31: a bundle that does not open under the verify keys writes
// nothing.
func TestInventoryExportVerifiesBeforeItWrites(t *testing.T) {
	svc := startService(t)
	svc.sync(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPEM, _ := edkey.EncodeEd25519(other)
	otherPub := filepath.Join(t.TempDir(), "other.pub")
	if err := os.WriteFile(otherPub, otherPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "inventory.yaml")
	args := []string{"inventory", "export", "--service", svc.url, "--ca", svc.ca, "--cert", svc.cert, "--key", svc.key,
		"--verify-key", otherPub, "--out", out}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "does not open under "+
		"--verify-key") || stdout.Len() != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("wrote a file")
	}
	if code := run([]string{"inventory", "export", "--service", svc.url, "--ca", svc.ca, "--cert", svc.cert, "--key",
		svc.key}, &stdout, &stderr); code != 2 {
		t.Fatalf("no --verify-key: exit %d", code)
	}
}

// Pre-flight M7: a genuine bundle that is not the one --from asked for is
// refused. The stub answers bundle 2 to every ask.
func TestInventoryExportFromChecksTheSequence(t *testing.T) {
	svc := startService(t)
	svc.sync(t)
	svc.writeSource(t, leaf01+"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.0.2]}\n")
	svc.sync(t)
	two := svc.syncer.Current().Raw
	stub := serveTLS(t, filepath.Join(svc.dir, "pki"), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(two)
	}))
	out := filepath.Join(t.TempDir(), "inventory.yaml")
	args := []string{"inventory", "export", "--service", stub, "--ca", svc.ca, "--cert", svc.cert, "--key", svc.key,
		"--verify-key", svc.pub, "--from", "1", "--out", out}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "the service answered bundle 2 for --from 1") {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("wrote a file")
	}
}

// Decision 31: a bundle whose signature was forged — its document changed
// after sealing — opens under no key, and nothing is written, to --out or
// to standard output.
func TestInventoryExportRefusesAForgedBundle(t *testing.T) {
	svc := startService(t)
	svc.sync(t)
	var env map[string]any
	if err := json.Unmarshal(svc.syncer.Current().Raw, &env); err != nil {
		t.Fatal(err)
	}
	doc, err := base64.StdEncoding.DecodeString(env["document"].(string))
	if err != nil || !bytes.Contains(doc, []byte("leaf-01")) {
		t.Fatalf("%v %s", err, doc)
	}
	env["document"] = base64.StdEncoding.EncodeToString(bytes.Replace(doc, []byte("leaf-01"), []byte("leaf-99"), 1))
	forged, err := json.Marshal(env) // the signature kept, the document changed
	if err != nil {
		t.Fatal(err)
	}
	stub := serveTLS(t, filepath.Join(svc.dir, "pki"), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(forged)
	}))
	for _, more := range [][]string{nil, {"--out", filepath.Join(t.TempDir(), "inventory.yaml")}} {
		args := append([]string{"inventory", "export", "--service", stub, "--ca", svc.ca, "--cert", svc.cert, "--key",
			svc.key, "--verify-key", svc.pub}, more...)
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 1 || stdout.Len() != 0 ||
			!strings.Contains(stderr.String(), "does not open under --verify-key") ||
			!strings.Contains(stderr.String(), "nothing is written") {
			t.Fatalf("%v: exit %d: %s %s", more, code, stdout.String(), stderr.String())
		}
		if len(more) > 0 {
			if _, err := os.Lstat(more[1]); err == nil {
				t.Fatal("wrote a file")
			}
		}
	}
}

// An --out that is a symbolic link is never followed: not to a file it
// would overwrite, and not to a name it would create (a dangling link).
func TestInventoryExportNeverWritesThroughALink(t *testing.T) {
	svc := startService(t)
	svc.sync(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, to := range map[string]string{"to-a-file": target, "dangling": filepath.Join(dir, "absent")} {
		link := filepath.Join(dir, name)
		if err := os.Symlink(to, link); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if code := run(exportArgs(svc, "--out", link), &stdout, &stderr); code != 1 ||
			!strings.Contains(stderr.String(), link+" is a symbolic link") {
			t.Fatalf("%s: exit %d: %s", name, code, stderr.String())
		}
	}
	if raw, _ := os.ReadFile(target); string(raw) != "keep\n" {
		t.Fatalf("the link's target is now %q", raw)
	}
	if _, err := os.Lstat(filepath.Join(dir, "absent")); err == nil {
		t.Fatal("created the dangling link's target")
	}
}

// --from is a positive sequence; anything else is a usage error, asked of
// no service.
func TestInventoryExportRefusesAMalformedFrom(t *testing.T) {
	for _, from := range []string{"0", "-1", "x", "1.5", "9223372036854775808"} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{"inventory", "export", "--service", "https://inv.example", "--ca", "a", "--cert", "b",
			"--key", "c", "--verify-key", "d", "--from", from}, &stdout, &stderr); code != 2 {
			t.Errorf("--from %s: exit %d: %s", from, code, stderr.String())
		}
	}
}

// Fix round 1 (I1): an export standard output did not take fails, and says
// no bundle was exported.
func TestInventoryExportFailsWhenStandardOutputDoes(t *testing.T) {
	svc := startService(t)
	svc.sync(t)
	var stderr bytes.Buffer
	if code := run(exportArgs(svc), failingWriter{}, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "standard output: "+os.ErrClosed.Error()) ||
		strings.Contains(stderr.String(), "device(s)") {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}

// Fix round 1 (M2): the header names the service by scheme and host; a
// path in --service is not copied into the file.
func TestInventoryExportHeaderNamesOnlyTheServiceHost(t *testing.T) {
	svc := startService(t)
	svc.sync(t)
	raw := svc.syncer.Current().Raw
	stub := serveTLS(t, filepath.Join(svc.dir, "pki"), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw)
	}))
	var stdout, stderr bytes.Buffer
	if code := run([]string{"inventory", "export", "--service", stub + "/not-for-the-file", "--ca", svc.ca, "--cert",
		svc.cert, "--key", svc.key, "--verify-key", svc.pub}, &stdout, &stderr); code != 0 ||
		!strings.Contains(stdout.String(), "from "+stub+".\n") || strings.Contains(stdout.String(), "not-for-the-file") {
		t.Fatalf("exit %d: %s %s", code, stdout.String(), stderr.String())
	}
}
