package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/fence"
	"github.com/rhwendt/port49/internal/inventory"
	"github.com/rhwendt/port49/internal/keyfile"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
)

// e2ePolicy is both port49d's policy and the service's copy: they agree.
// 127.0.0.0/8 admits leaf0, which the tests' own TACACS+ client speaks as.
const e2ePolicy = minimalPolicy + "key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: k}, " +
	"{match: {cidr: 127.0.0.0/8}, key_ref: k}]\n"

// e2ePoll is poll_interval in writeServiceRunConfig's port49d.yaml, the
// shortest config.Load accepts.
const e2ePoll = 5 * time.Second

// pokeWait bounds a wait for what a SIGHUP's fetch brings. It is inside
// e2ePoll, so a pass is the poke's doing only while each poke comes soon
// after the fetch before it: here within about 1s, a 2s margin.
const pokeWait = 3 * time.Second

// scrapeClient bounds every request the tests make of port49d's metrics
// listener: no wait in these tests is without a deadline.
var scrapeClient = &http.Client{Timeout: 5 * time.Second}

// e2eService is port49-inventory in-process, as cmd/port49-inventory wires it.
type e2eService struct {
	dir, url, addr, pubFile string
	syncer                  *inventory.Syncer
	srv                     *http.Server
	served                  chan error
	log                     *syncBuffer
	stopped                 bool
}

// startService runs the service on addr ("127.0.0.1:0" for a fresh port)
// from dir: its file source, policy, state, mirror and PKI, all under dir.
// It publishes bundle 1, two devices, before it returns. A key, PKI or
// state already in dir (a restart) is reused.
func startService(t *testing.T, dir, addr string) *e2eService {
	t.Helper()
	return startServiceSigning(t, dir, addr, nil)
}

// startServiceSigning is startService signing with key in place of dir's
// own, when key is not nil: a service whose key was changed and port49d
// not told. dir's key stays among the keys its state is read against, as
// verify_key_files keeps the old key through a rotation.
func startServiceSigning(t *testing.T, dir, addr string, key ed25519.PrivateKey) *e2eService {
	t.Helper()
	s := &e2eService{dir: dir, served: make(chan error, 1), log: &syncBuffer{}}
	if _, err := os.Stat(s.pki()); err != nil {
		if err := testpki.WriteInventoryLab(s.pki(), time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	keyFile := filepath.Join(dir, "signing.key")
	s.pubFile = filepath.Join(dir, "signing.pub")
	if _, err := os.Stat(keyFile); err != nil {
		writeServiceFiles(t, dir)
	}
	own, err := keyfile.LoadEd25519(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	var verify []ed25519.PublicKey
	if key == nil {
		key = own
	} else {
		verify = []ed25519.PublicKey{own.Public().(ed25519.PublicKey)}
	}
	cert, anchor, err := broker.LoadTLS(filepath.Join(s.pki(), testpki.InvServerCert),
		filepath.Join(s.pki(), testpki.InvServerKey), filepath.Join(s.pki(), testpki.InvCA))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	m := inventory.NewMetrics(prometheus.NewRegistry())
	s.syncer = &inventory.Syncer{Sources: []inventory.Source{inventory.FileSource{SourceName: "lab_file",
		Path: filepath.Join(dir, "inventory.yaml")}}, Bounds: map[string]int{}, Default: 10,
		PolicyFile: filepath.Join(dir, "policy.yaml"), Key: key, VerifyKeys: verify, Metrics: m, Now: time.Now,
		Log: s.log, State: inventory.State{Dir: filepath.Join(dir, "state"), MirrorDir: filepath.Join(dir, "mirror"),
			Keep: 64}}
	if err := s.syncer.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	api := &inventory.API{Syncer: s.syncer, Readers: []string{testpki.InvDaemonID},
		Syncers: []string{"user:alice@slice.port49.test"}, Now: time.Now, Log: s.log, Metrics: m}
	s.srv, err = inventory.Server(addr, cert, anchor, api.Handler(), log.New(s.log, "port49-inventory: api: ", 0))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	s.addr = ln.Addr().String()
	s.url = "https://" + s.addr
	go func() { s.served <- s.srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { s.stop(t) })
	if res := s.sync(t); res.Outcome != inventory.OutcomePublished && res.Outcome != inventory.OutcomeUnchanged {
		t.Fatalf("the first sync: %+v; the service said %s", res, s.log.String())
	}
	return s
}

// writeServiceFiles writes what the service reads from dir before its first
// start: its signing key, the public half port49d verifies with, its policy
// copy, a mirror directory, and a source of two devices.
func writeServiceFiles(t *testing.T, dir string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privPEM, pubPEM, err := keyfile.EncodeEd25519(priv)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct {
		name string
		body []byte
		mode os.FileMode
	}{{"signing.key", privPEM, 0o600}, {"signing.pub", pubPEM, 0o644}, {"policy.yaml", []byte(e2ePolicy), 0o600}} {
		if err := os.WriteFile(filepath.Join(dir, f.name), f.body, f.mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "mirror"), 0o755); err != nil {
		t.Fatal(err)
	}
	(&e2eService{dir: dir}).writeSource(t, 2)
}

// stop closes the service and waits for its Serve to return.
func (s *e2eService) stop(t *testing.T) {
	t.Helper()
	if s.stopped {
		return
	}
	s.stopped = true
	s.srv.Close()
	select {
	case err := <-s.served:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("the service's Serve: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("the service's Serve did not return after Close")
	}
}

// pki is the service's PKI directory, which port49d's config names too, so
// the two verify each other with real certificates (pre-flight M8).
func (s *e2eService) pki() string { return filepath.Join(s.dir, "pki") }

// writeSource writes leaf0 at 127.0.0.1 and n devices, leaf1..leafn at
// 10.0.0.i, under the fence.
func (s *e2eService) writeSource(t *testing.T, n int) {
	t.Helper()
	var b strings.Builder
	b.WriteString("devices:\n  - {name: leaf0, platform: arista_eos, addresses: [127.0.0.1]}\n")
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "  - {name: leaf%d, platform: arista_eos, addresses: [10.0.0.%d]}\n", i, i)
	}
	if err := os.WriteFile(filepath.Join(s.dir, "inventory.yaml"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// sync runs one sync, bounded, as POST /v1/sync would.
func (s *e2eService) sync(t *testing.T) inventory.Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return s.syncer.Sync(ctx, "api")
}

// port49dOn starts run on a config naming svcURL, stateDir and mirrorDir,
// with the service's own PKI (pki), and returns its stderr, its decision log
// and a stop that waits for it.
func port49dOn(t *testing.T, svcURL, pki, pubFile, stateDir, mirrorDir string) (out, log *syncBuffer, stop func()) {
	t.Helper()
	out, log = &syncBuffer{}, &syncBuffer{}
	b := brokerConfig(t, e2ePolicy).Broker
	cfgPath := writeServiceRunConfig(t, b, &config.InventoryServiceConfig{URL: svcURL, StateDir: stateDir,
		MirrorDir: mirrorDir}, pki, pubFile)
	e, o := stderr, stdout
	stderr, stdout = out, log
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("run: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Errorf("run did not return when its context ended: %s", out.String())
		}
		stderr, stdout = e, o
	}
	t.Cleanup(stop)
	return out, log, stop
}

// waitWithin polls buf until it holds want, or fails the test once d has
// passed.
func waitWithin(t *testing.T, buf *syncBuffer, want string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !strings.Contains(buf.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("waited %s for %q; have %q", d, want, buf.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func metricsAddr(t *testing.T, out *syncBuffer) string {
	t.Helper()
	m := regexp.MustCompile(`metrics on (127\.0\.0\.1:\d+)`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("the metrics address is not said: %s", out.String())
	}
	return m[1]
}

func readyz(t *testing.T, out *syncBuffer) int {
	t.Helper()
	resp, err := scrapeClient.Get("http://" + metricsAddr(t, out) + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// gauge is one series' value at a scrape of port49d: a metric's name, with
// its labels as the scrape spells them.
func gauge(t *testing.T, out *syncBuffer, series string) float64 {
	t.Helper()
	body := scrape(t, out)
	m := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(series) + ` (\S+)$`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no %s in the scrape:\n%s", series, body)
	}
	v, err := strconv.ParseFloat(string(m[1]), 64)
	if err != nil {
		t.Fatalf("%s: %v", series, err)
	}
	return v
}

// fetchesAtLeast waits until port49d has counted n fetches of outcome, or
// fails the test.
func fetchesAtLeast(t *testing.T, out *syncBuffer, outcome string, n float64) {
	t.Helper()
	series := `port49_inventory_fetches_total{outcome="` + outcome + `"}`
	deadline := time.Now().Add(pokeWait)
	for {
		if strings.Contains(scrape(t, out), series+" ") && gauge(t, out, series) >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited %s for %v %s; stderr %s", pokeWait, n, series, out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func scrape(t *testing.T, out *syncBuffer) string {
	t.Helper()
	resp, err := scrapeClient.Get("http://" + metricsAddr(t, out) + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return string(body)
}

// poke sends port49d SIGHUP, which pokes the fetcher to ask the service at
// once: the tests wait a poll_interval only where the poll is what they test.
func poke(t *testing.T) {
	t.Helper()
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
}

// leaf0 is the tests' TACACS+ client, speaking as leaf0 at 127.0.0.1 to the
// listener port49d said.
func leaf0(t *testing.T, out *syncBuffer) tacacsClient {
	t.Helper()
	m := regexp.MustCompile(`listening on (127\.0\.0\.1:\d+)`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("the TACACS+ address is not said: %s", out.String())
	}
	return tacacsClient{t: t, addr: m[1], key: []byte("run-test-secret")}
}

// persistedSequence is the sequence of port49d's persisted copy in state,
// opened under the service's key.
func persistedSequence(t *testing.T, state, pubFile string) int64 {
	t.Helper()
	keys, err := fence.ReadVerifyKeys("verify_key_files", []string{pubFile})
	if err != nil {
		t.Fatal(err)
	}
	p, err := readPersisted(state, keys)
	if err != nil || p == nil {
		t.Fatalf("persisted: %v %v", p, err)
	}
	return p.Doc.Sequence
}

// Spec §10 end to end: port49d starts from the service over mutual TLS,
// serves TACACS+ from the bundle it pulled — in service mode there is no
// inventory file, so leaf0 is admitted only by it — follows a source change
// within one poll_interval with no poke, writes the inventory_change record
// a file reload writes, persists what it follows, and takes a SIGHUP as a
// poke.
func TestPort49dFollowsTheService(t *testing.T) {
	svc := startService(t, safeDir(t), "127.0.0.1:0")
	state := filepath.Join(safeDir(t), "state")
	out, log, _ := port49dOn(t, svc.url, svc.pki(), svc.pubFile, state, "")
	waitFor(t, out, "port49d: listening on")
	if !strings.Contains(out.String(), "port49d: inventory: starting from bundle 1 (the service), published") {
		t.Fatalf("%s", out.String())
	}
	if st := leaf0(t, out).login("nobody", "not-a-token"); st != wire.AuthenStatusFail {
		t.Fatalf("leaf0, admitted by the pulled bundle, answered %d", st)
	}
	if readyz(t, out) != http.StatusOK {
		t.Fatal("not ready with the service's bundle")
	}
	svc.writeSource(t, 3)
	if res := svc.sync(t); res.Outcome != inventory.OutcomePublished || res.Sequence != 2 {
		t.Fatalf("%+v", res)
	}
	// One poll_interval, and a margin for the fetch and the reload: no poke.
	waitWithin(t, out, "port49d: inventory reloaded (inventory service, bundle 2)", e2ePoll+3*time.Second)
	// The records are written after the reload's line, and said once written.
	waitFor(t, out, "port49d: inventory: 1 security change(s) written as inventory_change records")
	var added bool
	for _, r := range records(t, log, "inventory_change") {
		c, _ := r["change"].(map[string]any)
		d, _ := r["device"].(map[string]any)
		added = added || (c["kind"] == "device_added" && d["name"] == "leaf3")
	}
	if !added {
		t.Fatalf("no inventory_change device_added record: %s", log.String())
	}
	if n := persistedSequence(t, state, svc.pubFile); n != 2 {
		t.Fatalf("persisted bundle %d, want 2", n)
	}
	if g := gauge(t, out, "port49_inventory_bundle_sequence"); g != 2 {
		t.Fatalf("port49_inventory_bundle_sequence %v", g)
	}
	// SIGHUP pokes the fetcher, which asks again at once.
	svc.writeSource(t, 4)
	if res := svc.sync(t); res.Outcome != inventory.OutcomePublished || res.Sequence != 3 {
		t.Fatalf("%+v", res)
	}
	poke(t)
	waitWithin(t, out, "port49d: inventory reloaded (inventory service, bundle 3)", pokeWait)
	if st := leaf0(t, out).login("nobody", "not-a-token"); st != wire.AuthenStatusFail {
		t.Fatalf("after two reloads leaf0 answered %d", st)
	}
}

// A restart in place with the service down starts from the persisted copy
// and says, once, that the service does not answer.
func TestPort49dRestartsFromItsCopyWithTheServiceDown(t *testing.T) {
	svc := startService(t, safeDir(t), "127.0.0.1:0")
	state := filepath.Join(safeDir(t), "state")
	out, _, stop := port49dOn(t, svc.url, svc.pki(), svc.pubFile, state, "")
	waitFor(t, out, "port49d: listening on")
	stop()
	svc.stop(t)
	out, _, _ = port49dOn(t, svc.url, svc.pki(), svc.pubFile, state, "")
	waitFor(t, out, "port49d: listening on")
	if !strings.Contains(out.String(), "port49d: inventory: starting from bundle 1 (the persisted copy), published") {
		t.Fatalf("%s", out.String())
	}
	if readyz(t, out) != http.StatusOK {
		t.Fatal("not ready with the persisted copy")
	}
	if st := leaf0(t, out).login("nobody", "not-a-token"); st != wire.AuthenStatusFail {
		t.Fatalf("leaf0, admitted by the persisted copy, answered %d", st)
	}
	// The fetcher's first ask is at once; a poke asks again, and fails again
	// without a second line.
	waitFor(t, out, "port49d: inventory: the inventory service at "+svc.url+" did not answer")
	fetchesAtLeast(t, out, "failed", 1)
	poke(t)
	fetchesAtLeast(t, out, "failed", 2)
	// The counter moves before the line is said; the fetcher is serial, so
	// once a third fetch has failed, the second's line, if any, is written.
	poke(t)
	fetchesAtLeast(t, out, "failed", 3)
	if n := strings.Count(out.String(), "did not answer"); n != 1 {
		t.Fatalf("said %d times: %s", n, out.String())
	}
}

// Spec §14, the snapshot never expires, in service mode (pre-flight minor
// 12): with the service gone, the age climbs, /readyz stays 200, and the
// device is still admitted and answered from the last good bundle.
func TestTheSnapshotNeverExpiresWithTheServiceDown(t *testing.T) {
	svc := startService(t, safeDir(t), "127.0.0.1:0")
	out, _, _ := port49dOn(t, svc.url, svc.pki(), svc.pubFile, filepath.Join(safeDir(t), "state"), "")
	waitFor(t, out, "port49d: listening on")
	svc.stop(t)
	poke(t)
	waitWithin(t, out, "did not answer", pokeWait)
	first := gauge(t, out, "port49_inventory_snapshot_age_seconds")
	time.Sleep(1500 * time.Millisecond)
	second := gauge(t, out, "port49_inventory_snapshot_age_seconds")
	if !(second >= first+1) {
		t.Fatalf("the age does not climb: %v then %v", first, second)
	}
	if readyz(t, out) != http.StatusOK {
		t.Fatal("not ready on the last good bundle")
	}
	if g := gauge(t, out, "port49_inventory_bundle_sequence"); g != 1 {
		t.Fatalf("port49_inventory_bundle_sequence %v", g)
	}
	// Admission is unchanged: leaf0's packet is answered (FAIL: no token),
	// not closed.
	if st := leaf0(t, out).login("nobody", "not-a-token"); st != wire.AuthenStatusFail {
		t.Fatalf("status %d", st)
	}
}

// Spec §10: a document signed by a key port49d does not list is refused,
// said and alarmed, and the bundle in force keeps serving — here the
// service's key was changed and port49d not told.
func TestADocumentSignedByAnUnlistedKeyIsRefused(t *testing.T) {
	dir := safeDir(t)
	svc := startService(t, dir, "127.0.0.1:0")
	state := filepath.Join(safeDir(t), "state")
	out, log, _ := port49dOn(t, svc.url, svc.pki(), svc.pubFile, state, "")
	waitFor(t, out, "port49d: listening on")
	svc.stop(t)
	_, rogue, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The service re-seals bundle 1 under the key it now holds as bundle 2
	// (final review I1): a document signed by a key port49d does not list.
	svc = startServiceSigning(t, dir, svc.addr, rogue)
	if cur := svc.syncer.Current(); cur.Doc.Sequence != 2 {
		t.Fatalf("the service serves bundle %d, want 2: %s", cur.Doc.Sequence, svc.log.String())
	}
	poke(t)
	waitWithin(t, out, "port49d: inventory reload (inventory service) refused; still serving bundle ", pokeWait)
	if !strings.Contains(out.String(), "(1): the document does not open") ||
		!strings.Contains(out.String(), "inventory.service.verify_key_files") {
		t.Fatalf("%s", out.String())
	}
	if g := gauge(t, out, "port49_inventory_bundle_refused"); g != 1 {
		t.Fatalf("port49_inventory_bundle_refused %v", g)
	}
	if g := gauge(t, out, "port49_inventory_bundle_sequence"); g != 1 {
		t.Fatalf("port49_inventory_bundle_sequence %v", g)
	}
	if readyz(t, out) != http.StatusOK {
		t.Fatal("not ready on the bundle in force")
	}
	if st := leaf0(t, out).login("nobody", "not-a-token"); st != wire.AuthenStatusFail {
		t.Fatalf("status %d", st)
	}
	if n := persistedSequence(t, state, svc.pubFile); n != 1 {
		t.Fatalf("persisted bundle %d, want 1", n)
	}
	if len(records(t, log, "inventory_change")) != 0 {
		t.Fatalf("a refused document changed the inventory: %s", log.String())
	}
	// A SIGHUP tries the document held again under the keys in force, and
	// says so; the fetch it pokes brings the same document whole, which is
	// not said again. Bundle 1 serves throughout.
	invalid := gauge(t, out, `port49_inventory_fetches_total{outcome="invalid"}`)
	poke(t)
	waitWithin(t, out, "port49d: inventory reload (SIGHUP) refused; still serving bundle ", pokeWait)
	fetchesAtLeast(t, out, "invalid", invalid+1)
	// The counter moves before the reloader speaks; once the next fetch is
	// counted, whatever the last one made it say is written.
	poke(t)
	fetchesAtLeast(t, out, "invalid", invalid+2)
	if n := strings.Count(out.String(), "(inventory service) refused"); n != 1 {
		t.Fatalf("said %d times: %s", n, out.String())
	}
	if g := gauge(t, out, "port49_inventory_bundle_sequence"); g != 1 {
		t.Fatalf("port49_inventory_bundle_sequence %v after SIGHUP", g)
	}
}

// A fresh port49d, the service down, starts from the mirror's copy.
func TestAFreshPort49dStartsFromTheMirror(t *testing.T) {
	dir := safeDir(t)
	svc := startService(t, dir, "127.0.0.1:0")
	svc.stop(t)
	out, _, _ := port49dOn(t, svc.url, svc.pki(), svc.pubFile, filepath.Join(safeDir(t), "state"),
		filepath.Join(dir, "mirror"))
	waitFor(t, out, "port49d: listening on")
	if !strings.Contains(out.String(), "port49d: inventory: starting from bundle 1 (the mirror's copy), published") {
		t.Fatalf("%s", out.String())
	}
	if readyz(t, out) != http.StatusOK {
		t.Fatal("not ready with the mirror's copy")
	}
	if st := leaf0(t, out).login("nobody", "not-a-token"); st != wire.AuthenStatusFail {
		t.Fatalf("leaf0, admitted by the mirror's copy, answered %d", st)
	}
}

// A fresh port49d with nothing waits, not ready and not serving, and starts
// when the service does.
func TestAFreshPort49dWithNothingWaitsForTheService(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	dir := safeDir(t)
	// The key the service will sign with and the PKI it will serve, written
	// before port49d starts: startService reuses what dir holds, so the
	// service port49d later meets is the one its config trusts (M8).
	writeServiceFiles(t, dir)
	if err := testpki.WriteInventoryLab(filepath.Join(dir, "pki"), time.Now()); err != nil {
		t.Fatal(err)
	}
	out, _, _ := port49dOn(t, "https://"+addr, filepath.Join(dir, "pki"), filepath.Join(dir, "signing.pub"),
		filepath.Join(safeDir(t), "state"), "")
	waitFor(t, out, "port49d: inventory: no bundle yet")
	if readyz(t, out) != http.StatusServiceUnavailable || strings.Contains(out.String(), "port49d: listening on") {
		t.Fatalf("serving with no bundle: %s", out.String())
	}
	startService(t, dir, addr)
	// Cold start asks again every poll_interval.
	waitWithin(t, out, "port49d: listening on", e2ePoll+3*time.Second)
	if !strings.Contains(out.String(), "starting from bundle 1 (the service), published") ||
		readyz(t, out) != http.StatusOK {
		t.Fatalf("%s", out.String())
	}
}

// Final review I1, the rotation as the operator notes give it: port49d lists
// both keys, the service restarts on the new key, and on a stable fleet it
// re-seals the bundle in force as the next sequence, which port49d takes as
// the same devices and persists. Then the old key is dropped: port49d
// restarts, the service down, from its persisted copy and serves.
func TestARotationOnAStableFleetLetsTheOldKeyBeDropped(t *testing.T) {
	dir := safeDir(t)
	svc := startService(t, dir, "127.0.0.1:0")
	_, newKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPub := keyPath(t, newKey)
	state := filepath.Join(safeDir(t), "state")
	out, _, stop := port49dOn(t, svc.url, svc.pki(), svc.pubFile+", "+newPub, state, "")
	waitFor(t, out, "port49d: listening on")
	svc.stop(t)
	svc = startServiceSigning(t, dir, svc.addr, newKey)
	if cur := svc.syncer.Current(); cur.Doc.Sequence != 2 {
		t.Fatalf("the service serves bundle %d after the rotation, want 2 re-sealed; it said %s", cur.Doc.Sequence,
			svc.log.String())
	}
	poke(t)
	deadline := time.Now().Add(pokeWait)
	for gauge(t, out, "port49_inventory_bundle_sequence") != 2 {
		if time.Now().After(deadline) {
			t.Fatalf("port49d did not take bundle 2: %s", out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n := persistedSequence(t, state, newPub); n != 2 {
		t.Fatalf("persisted bundle %d, want 2", n)
	}
	stop()
	svc.stop(t)
	out, _, _ = port49dOn(t, svc.url, svc.pki(), newPub, state, "")
	waitFor(t, out, "port49d: listening on")
	if !strings.Contains(out.String(), "port49d: inventory: starting from bundle 2 (the persisted copy)") ||
		readyz(t, out) != http.StatusOK {
		t.Fatalf("%s", out.String())
	}
}
