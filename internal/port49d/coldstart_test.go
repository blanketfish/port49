package port49d

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/bundle"
	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/inventory"
)

// fakeService answers from a script; a nil entry fails as a dial does.
type fakeService struct {
	bundles [][]byte
	calls   int
	t       *testing.T
	forbid  bool
}

func (f *fakeService) Version(context.Context) (inventory.VersionInfo, error) {
	return inventory.VersionInfo{}, errors.New("unused")
}

func (f *fakeService) Bundle(_ context.Context, _ string) ([]byte, string, bool, error) {
	if f.forbid {
		f.t.Fatal("the service was asked with a copy at hand")
	}
	i := min(f.calls, len(f.bundles)-1)
	f.calls++
	if f.bundles[i] == nil {
		return nil, "", false, errors.New("dial tcp 127.0.0.1:1: connect: connection refused")
	}
	return f.bundles[i], bundle.ETag(f.bundles[i]), false, nil
}

// coldStart is the copy coldCopies would start from, before the policy's
// word (startCopy).
func coldStart(ctx context.Context, svc *config.InventoryServiceConfig, keys []ed25519.PublicKey,
	c fetchClient, m *metrics.Metrics, rd *readiness) (*inventory.Published, string, error) {
	picks, err := coldCopies(ctx, "port49d", svc, keys, c, m, rd)
	if err != nil {
		return nil, "", err
	}
	return picks[0].p, picks[0].from, nil
}

func sealedDoc(t *testing.T, key ed25519.PrivateKey, seq int64, n int) []byte {
	t.Helper()
	return sealedDocAt(t, key, seq, n, time.Now())
}

// sealedDocAt is sealedDoc published at at.
func sealedDocAt(t *testing.T, key ed25519.PrivateKey, seq int64, n int, at time.Time) []byte {
	t.Helper()
	var inv admission.Inventory
	for i := 1; i <= n; i++ {
		inv.Devices = append(inv.Devices, admission.Device{Name: "leaf" + string(rune('0'+i)), Platform: "arista_eos",
			Addresses: []netip.Addr{netip.AddrFrom4([4]byte{10, 0, 0, byte(i)})}, Transport: admission.TransportTCP})
	}
	raw, err := bundle.Seal(bundle.NewDocument(seq, at, []byte(minimalPolicy), "1.1.0", inv, nil), key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func coldRig(t *testing.T) (*config.InventoryServiceConfig, ed25519.PrivateKey, []ed25519.PublicKey) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	svc := &config.InventoryServiceConfig{URL: "https://inv.test:8443", StateDir: filepath.Join(safeDir(t), "state"),
		MirrorDir: safeDir(t), PollInterval: 10 * time.Millisecond}
	return svc, key, []ed25519.PublicKey{pub}
}

func TestColdStartTakesTheNewerCopyAndNeverAsksTheService(t *testing.T) {
	svc, key, keys := coldRig(t)
	if err := persistBundle(svc.StateDir, sealedDocAt(t, key, 3, 1, time.Now().Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	mustMirror(t, svc.MirrorDir, sealedDoc(t, key, 5, 2))
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	p, from, err := coldStart(context.Background(), svc, keys, &fakeService{t: t, forbid: true}, testMetrics(), nil)
	if err != nil || p.Doc.Sequence != 5 || from != "the mirror's copy" {
		t.Fatalf("%v %q %v", p, from, err)
	}
}

// Pre-flight minor 11: newer is later publication, not a higher sequence,
// which a service reset starts again at 1.
func TestColdStartPrefersTheLaterPublicationOverTheHigherSequence(t *testing.T) {
	svc, key, keys := coldRig(t)
	mustPersist(t, svc.StateDir, sealedDocAt(t, key, 40, 1, time.Now().Add(-48*time.Hour)))
	mustMirror(t, svc.MirrorDir, sealedDoc(t, key, 2, 2))
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	p, from, err := coldStart(context.Background(), svc, keys, &fakeService{t: t, forbid: true}, testMetrics(), nil)
	if err != nil || p.Doc.Sequence != 2 || from != "the mirror's copy" ||
		!strings.Contains(out.String(), "published later than the persisted copy") {
		t.Fatalf("%v %q %v %s", p, from, err, out.String())
	}
}

// Pre-flight M4: a mirror mount that hangs is passed over at its deadline,
// said, and the start goes on from the persisted copy.
func TestAHungMirrorNeverHoldsUpAStartFromThePersistedCopy(t *testing.T) {
	svc, key, keys := coldRig(t)
	mustPersist(t, svc.StateDir, sealedDoc(t, key, 3, 1))
	hang := make(chan struct{})
	defer close(hang)
	defer func(r func(string, []ed25519.PublicKey) (*inventory.Published, error), d time.Duration) {
		readMirror, mirrorDeadline = r, d
	}(readMirror, mirrorDeadline)
	readMirror = func(string, []ed25519.PublicKey) (*inventory.Published, error) { <-hang; return nil, nil }
	mirrorDeadline = 50 * time.Millisecond
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	start := time.Now()
	p, from, err := coldStart(context.Background(), svc, keys, &fakeService{t: t, forbid: true}, testMetrics(), nil)
	if err != nil || from != "the persisted copy" || p.Doc.Sequence != 3 || time.Since(start) > 5*time.Second ||
		!strings.Contains(out.String(), "the mirror's copy is passed over: mirror_dir "+svc.MirrorDir+" did not answer in") {
		t.Fatalf("%v %q %v %s", p, from, err, out.String())
	}
}

// Pre-flight M5: a start from a copy dates the snapshot from its
// publication, so a restart never makes an old snapshot look fresh.
func TestAStartFromACopyCountsTheAgeFromItsPublication(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	raw := sealedDocAt(t, key, 7, 1, rig.now.Add(-48*time.Hour))
	doc, inv, err := bundle.Open(raw, []ed25519.PublicKey{key.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	rig.r.startDocument(&inventory.Published{Raw: raw, Doc: doc, Inv: inv}, "the persisted copy")
	if age := testutil.ToFloat64(rig.m.InventorySnapshotAge); age < 47*3600 || age > 49*3600 {
		t.Fatalf("age %v, want about two days", age)
	}
	rig.r.startDocument(&inventory.Published{Raw: raw, Doc: doc, Inv: inv}, "the service")
	if age := testutil.ToFloat64(rig.m.InventorySnapshotAge); age > 1 {
		t.Fatalf("a start from the service is a confirmation: age %v", age)
	}
}

// mustPersist is persistBundle, failing the test on a setup error.
func mustPersist(t *testing.T, dir string, raw []byte) {
	t.Helper()
	if err := persistBundle(dir, raw); err != nil {
		t.Fatal(err)
	}
}

// mustMirror writes raw as the mirror's copy in dir, failing the test on a
// setup error.
func mustMirror(t *testing.T, dir string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "bundle.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// seqOf is p's sequence for a failure message, 0 for none.
func seqOf(p *inventory.Published) int64 {
	if p == nil {
		return 0
	}
	return p.Doc.Sequence
}

func testMetrics() *metrics.Metrics { return metrics.New(prometheus.NewRegistry()) }

// A copy the service did not sign is passed over, said, and alarmed (spec
// §10: "refused, said once, and alarmed").
func TestACopyThatDoesNotVerifyIsPassedOver(t *testing.T) {
	svc, key, keys := coldRig(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	mustPersist(t, svc.StateDir, sealedDoc(t, key, 3, 1))
	mustMirror(t, svc.MirrorDir, sealedDoc(t, other, 9, 2))
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	m := testMetrics()
	p, from, err := coldStart(context.Background(), svc, keys, &fakeService{t: t, forbid: true}, m, nil)
	if err != nil || p.Doc.Sequence != 3 || from != "the persisted copy" ||
		!strings.Contains(out.String(), "which no verify key holds") {
		t.Fatalf("%v %q %v %s", p, from, err, out.String())
	}
	if testutil.ToFloat64(m.InventoryBundleRefused) != 1 {
		t.Fatal("port49_inventory_bundle_refused is not 1 for a copy that does not open")
	}
}

// The persisted copy is port49d's own and read behind the write fence.
func TestAPersistedCopyOthersCouldWriteIsPassedOver(t *testing.T) {
	svc, key, keys := coldRig(t)
	mustPersist(t, svc.StateDir, sealedDoc(t, key, 3, 1))
	if err := os.Chmod(filepath.Join(svc.StateDir, "bundle.json"), 0o664); err != nil {
		t.Fatal(err)
	}
	if p, err := readPersisted(svc.StateDir, keys); p != nil || err == nil || !strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("%v %v", p, err)
	}
}

// With neither copy, port49d waits for the service and says why once per
// reason. What it gets is persisted only once the policy and the broker have
// taken it (persistStart; final review I2), never by the wait itself.
func TestWithNoCopyItWaitsForTheServiceSayingWhyOnce(t *testing.T) {
	svc, key, keys := coldRig(t)
	svc.MirrorDir = ""
	doc := sealedDoc(t, key, 1, 2)
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	p, from, err := coldStart(context.Background(), svc, keys, &fakeService{bundles: [][]byte{nil, nil, nil, doc}}, testMetrics(), nil)
	if err != nil || p.Doc.Sequence != 1 || from != "the service" {
		t.Fatalf("%v %q %v", p, from, err)
	}
	if n := strings.Count(out.String(), "port49d: inventory: no bundle yet (persisted copy: none in "); n != 1 ||
		!strings.Contains(out.String(), "mirror: none configured; service at https://inv.test:8443: dial tcp") ||
		!strings.Contains(out.String(), "TACACS+ is not served until one arrives, and /readyz answers 503") {
		t.Fatalf("said %d times: %s", n, out.String())
	}
	if _, err := os.Stat(filepath.Join(svc.StateDir, "bundle.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("persisted before the policy took it: %v", err)
	}
	persistStart("port49d", svc, coldPick{p, from}, testMetrics())
	fi, err := os.Stat(filepath.Join(svc.StateDir, "bundle.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("not persisted: %v %v", fi, err)
	}
}

// port49-broker's wait names what it holds back: its API, not TACACS+
// (Task 15a review M-5).
func TestTheBrokersColdStartWaitNamesItsAPI(t *testing.T) {
	svc, key, keys := coldRig(t)
	svc.MirrorDir = ""
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	c := &fakeService{bundles: [][]byte{nil, sealedDoc(t, key, 1, 2)}}
	if _, err := coldCopies(context.Background(), "port49-broker", svc, keys, c, testMetrics(), nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "port49-broker: inventory: no bundle yet (") ||
		!strings.Contains(out.String(), "the API is not served until one arrives, and /readyz answers 503") ||
		strings.Contains(out.String(), "TACACS+") {
		t.Fatalf("said: %s", out.String())
	}
}

func TestColdStartEndsWithItsContext(t *testing.T) {
	svc, _, keys := coldRig(t)
	svc.MirrorDir = ""
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	e := stderr
	defer func() { stderr = e }()
	stderr = &syncBuffer{}
	if _, _, err := coldStart(ctx, svc, keys, &fakeService{bundles: [][]byte{nil}}, testMetrics(), nil); !errors.Is(err,
		context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}

// A start from the service confirms the bundle in force, so a copy refused on
// the way no longer holds the alarm.
func TestAStartFromTheServiceClearsTheRefusedAlarm(t *testing.T) {
	svc, key, keys := coldRig(t)
	svc.MirrorDir = ""
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	mustPersist(t, svc.StateDir, sealedDoc(t, other, 3, 1))
	e := stderr
	defer func() { stderr = e }()
	stderr = &syncBuffer{}
	m := testMetrics()
	p, from, err := coldStart(context.Background(), svc, keys, &fakeService{bundles: [][]byte{sealedDoc(t, key, 4, 1)}}, m, nil)
	if err != nil || from != "the service" || p.Doc.Sequence != 4 {
		t.Fatalf("%v %q %v", p, from, err)
	}
	if testutil.ToFloat64(m.InventoryBundleRefused) != 0 {
		t.Fatal("port49_inventory_bundle_refused is still 1 after the service sent the bundle in force")
	}
}

// A mirror that did not answer gave no document, so nothing was refused.
func TestAHungMirrorIsNotARefusal(t *testing.T) {
	svc, key, keys := coldRig(t)
	mustPersist(t, svc.StateDir, sealedDoc(t, key, 3, 1))
	hang := make(chan struct{})
	defer close(hang)
	defer func(r func(string, []ed25519.PublicKey) (*inventory.Published, error), d time.Duration) {
		readMirror, mirrorDeadline = r, d
	}(readMirror, mirrorDeadline)
	readMirror = func(string, []ed25519.PublicKey) (*inventory.Published, error) { <-hang; return nil, nil }
	mirrorDeadline = 10 * time.Millisecond
	e := stderr
	defer func() { stderr = e }()
	stderr = &syncBuffer{}
	m := testMetrics()
	if _, from, err := coldStart(context.Background(), svc, keys, &fakeService{t: t, forbid: true}, m, nil); err != nil ||
		from != "the persisted copy" {
		t.Fatalf("%q %v", from, err)
	}
	if testutil.ToFloat64(m.InventoryBundleRefused) != 0 {
		t.Fatal("a hung mirror is alarmed as a refused bundle")
	}
	if testutil.ToFloat64(m.InventoryMirrorUnreadable) != 1 {
		t.Fatal("port49_inventory_mirror_unreadable is not 1 for a mirror that hung")
	}
}

// A mirror whose read fails — here a directory where the copy should be —
// is unreadable, not refused: no document was judged.
func TestAMirrorThatDoesNotReadIsUnreadableNotRefused(t *testing.T) {
	svc, key, keys := coldRig(t)
	mustPersist(t, svc.StateDir, sealedDoc(t, key, 3, 1))
	if err := os.Mkdir(filepath.Join(svc.MirrorDir, "bundle.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	m := testMetrics()
	if _, from, err := coldStart(context.Background(), svc, keys, &fakeService{t: t, forbid: true}, m, nil); err != nil ||
		from != "the persisted copy" || !strings.Contains(out.String(), "the mirror's copy is passed over: ") {
		t.Fatalf("%q %v %s", from, err, out.String())
	}
	if testutil.ToFloat64(m.InventoryMirrorUnreadable) != 1 || testutil.ToFloat64(m.InventoryBundleRefused) != 0 {
		t.Fatalf("unreadable %v, refused %v", testutil.ToFloat64(m.InventoryMirrorUnreadable),
			testutil.ToFloat64(m.InventoryBundleRefused))
	}
}

// A persisted copy the fence refuses was never read as a document: said,
// with why, and not counted as refused (the rule in coldStart's comment).
func TestAPersistedCopyTheFenceRefusesIsNotCountedRefused(t *testing.T) {
	svc, key, keys := coldRig(t)
	mustPersist(t, svc.StateDir, sealedDocAt(t, key, 3, 1, time.Now().Add(-time.Hour)))
	if err := os.Chmod(filepath.Join(svc.StateDir, "bundle.json"), 0o664); err != nil {
		t.Fatal(err)
	}
	mustMirror(t, svc.MirrorDir, sealedDocAt(t, key, 2, 1, time.Now().Add(-2*time.Hour)))
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	m := testMetrics()
	if _, from, err := coldStart(context.Background(), svc, keys, &fakeService{t: t, forbid: true}, m, nil); err != nil ||
		from != "the mirror's copy" || !strings.Contains(out.String(), "the persisted copy is passed over: ") ||
		!strings.Contains(out.String(), "writable by others") {
		t.Fatalf("%q %v %s", from, err, out.String())
	}
	if testutil.ToFloat64(m.InventoryBundleRefused) != 0 {
		t.Fatal("a copy the fence refused, never read as a document, is counted as a refused bundle")
	}
}

// A tie in published_at keeps the persisted copy, whatever the sequences:
// it is port49d's own, and nothing is rewritten.
func TestATieInPublicationKeepsThePersistedCopy(t *testing.T) {
	svc, key, keys := coldRig(t)
	at := time.Now().Add(-time.Hour).Truncate(time.Second)
	mustPersist(t, svc.StateDir, sealedDocAt(t, key, 3, 1, at))
	mustMirror(t, svc.MirrorDir, sealedDocAt(t, key, 9, 2, at))
	e := stderr
	defer func() { stderr = e }()
	stderr = &syncBuffer{}
	p, from, err := coldStart(context.Background(), svc, keys, &fakeService{t: t, forbid: true}, testMetrics(), nil)
	if err != nil || from != "the persisted copy" || p.Doc.Sequence != 3 {
		t.Fatalf("bundle %d %q %v", seqOf(p), from, err)
	}
}

// A copy published more than maxPublishedSkew ahead of this clock is refused
// and alarmed: it would beat every later copy, and date the snapshot ahead.
func TestACopyPublishedInTheFutureIsRefused(t *testing.T) {
	svc, key, keys := coldRig(t)
	mustPersist(t, svc.StateDir, sealedDocAt(t, key, 3, 1, time.Now().Add(-time.Hour)))
	mustMirror(t, svc.MirrorDir, sealedDocAt(t, key, 9, 2, time.Now().Add(time.Hour)))
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	m := testMetrics()
	p, from, err := coldStart(context.Background(), svc, keys, &fakeService{t: t, forbid: true}, m, nil)
	if err != nil || from != "the persisted copy" || p.Doc.Sequence != 3 ||
		!strings.Contains(out.String(), "the mirror's copy is refused until this host's clock reaches it: ") ||
		!strings.Contains(out.String(), "more than 5m0s after this host's clock") ||
		!strings.Contains(out.String(), "this host's clock or the signer's is wrong") {
		t.Fatalf("bundle %d %q %v %s", seqOf(p), from, err, out.String())
	}
	if testutil.ToFloat64(m.InventoryBundleRefused) != 1 {
		t.Fatal("port49_inventory_bundle_refused is not 1 for a copy published in the future")
	}
}

// The service's document is held to the same rule; the next one, dated
// right, is taken and clears the alarm.
func TestADocumentFromTheServicePublishedInTheFutureIsRefused(t *testing.T) {
	svc, key, keys := coldRig(t)
	svc.MirrorDir = ""
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	m := testMetrics()
	c := &fakeService{bundles: [][]byte{sealedDocAt(t, key, 2, 1, time.Now().Add(time.Hour)), sealedDoc(t, key, 3, 1)}}
	p, from, err := coldStart(context.Background(), svc, keys, c, m, nil)
	if err != nil || from != "the service" || p.Doc.Sequence != 3 ||
		!strings.Contains(out.String(), "its bundle is refused: bundle 2 is published ") {
		t.Fatalf("bundle %d %q %v %s", seqOf(p), from, err, out.String())
	}
	if testutil.ToFloat64(m.InventoryBundleRefused) != 0 {
		t.Fatal("the service's good document did not clear the alarm")
	}
}

// A host that boots with its clock behind, the service down, refuses its
// genuine copies as published ahead of it, and serves nothing; once its
// clock is put right the next pass of the wait judges them again and starts
// from the persisted copy, clearing the alarm (spec §10: a restart in place
// needs nothing). NTP steps the clock right after the next pass's first
// reading of it: every copy of a pass is held to one reading, so the step
// does not refuse the newer copy and take the older one judged after it.
func TestACopyRefusedForTheClockIsTakenOnceTheClockCatchesUp(t *testing.T) {
	svc, key, keys := coldRig(t)
	published := time.Now().Truncate(time.Second)
	mustPersist(t, svc.StateDir, sealedDocAt(t, key, 8, 1, published))
	mustMirror(t, svc.MirrorDir, sealedDocAt(t, key, 7, 1, published.Add(-time.Minute)))
	var clock atomic.Int64
	var step atomic.Bool
	clock.Store(published.Add(-time.Hour).UnixNano()) // booted an hour behind
	defer func(c func() time.Time) { coldNow = c }(coldNow)
	coldNow = func() time.Time {
		now := time.Unix(0, clock.Load())
		if step.CompareAndSwap(true, false) {
			clock.Store(published.UnixNano()) // NTP puts it right, just after this reading
		}
		return now
	}
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	m := testMetrics()
	type result struct {
		p    *inventory.Published
		from string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		p, from, err := coldStart(context.Background(), svc, keys, &fakeService{bundles: [][]byte{nil}}, m, nil)
		done <- result{p, from, err}
	}()
	waitFor(t, &out, "port49d: inventory: no bundle yet")
	select {
	case r := <-done:
		t.Fatalf("started with the clock behind: bundle %d %q %v", seqOf(r.p), r.from, r.err)
	case <-time.After(50 * time.Millisecond): // several passes of the 10ms wait
	}
	if n := strings.Count(out.String(), "is refused until this host's clock reaches it"); n != 2 ||
		testutil.ToFloat64(m.InventoryBundleRefused) != 1 {
		t.Fatalf("refused %d times, alarm %v: %s", n, testutil.ToFloat64(m.InventoryBundleRefused), out.String())
	}
	step.Store(true)
	select {
	case r := <-done:
		if r.err != nil || r.from != "the persisted copy" || seqOf(r.p) != 8 {
			t.Fatalf("bundle %d %q %v", seqOf(r.p), r.from, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("still waiting after the clock caught up: %s", out.String())
	}
	if testutil.ToFloat64(m.InventoryBundleRefused) != 0 {
		t.Fatal("port49_inventory_bundle_refused is still 1 with every refusal the clock's, and the clock right")
	}
}

// A refusal that was not the clock's — here a persisted copy another key
// signed — keeps the alarm when the mirror's copy is taken on the clock
// catching up: only the service's word clears it.
func TestAClockCatchUpDoesNotClearARealRefusal(t *testing.T) {
	svc, key, keys := coldRig(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	published := time.Now().Truncate(time.Second)
	mustPersist(t, svc.StateDir, sealedDocAt(t, other, 8, 1, published))
	mustMirror(t, svc.MirrorDir, sealedDocAt(t, key, 7, 1, published))
	var clock atomic.Int64
	clock.Store(published.Add(-time.Hour).UnixNano())
	defer func(c func() time.Time) { coldNow = c }(coldNow)
	coldNow = func() time.Time { return time.Unix(0, clock.Load()) }
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	m := testMetrics()
	done := make(chan string, 1)
	go func() {
		_, from, _ := coldStart(context.Background(), svc, keys, &fakeService{bundles: [][]byte{nil}}, m, nil)
		done <- from
	}()
	waitFor(t, &out, "port49d: inventory: no bundle yet")
	clock.Store(published.UnixNano())
	select {
	case from := <-done:
		if from != "the mirror's copy" {
			t.Fatalf("from %q: %s", from, out.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("still waiting: %s", out.String())
	}
	if testutil.ToFloat64(m.InventoryBundleRefused) != 1 {
		t.Fatal("the clock catching up cleared the alarm for a copy another key signed")
	}
}

// The service's document refused for anything but its date — here another
// key's signature — is a real refusal: a copy taken later on the clock
// catching up does not clear the alarm.
func TestAClockCatchUpDoesNotClearTheServicesRefusal(t *testing.T) {
	svc, key, keys := coldRig(t)
	svc.MirrorDir = ""
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	published := time.Now().Truncate(time.Second)
	mustPersist(t, svc.StateDir, sealedDocAt(t, key, 8, 1, published))
	var clock atomic.Int64
	clock.Store(published.Add(-time.Hour).UnixNano())
	defer func(c func() time.Time) { coldNow = c }(coldNow)
	coldNow = func() time.Time { return time.Unix(0, clock.Load()) }
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	m := testMetrics()
	done := make(chan string, 1)
	go func() {
		_, from, _ := coldStart(context.Background(), svc, keys,
			&fakeService{bundles: [][]byte{sealedDocAt(t, other, 9, 1, published.Add(-2*time.Hour))}}, m, nil)
		done <- from
	}()
	waitFor(t, &out, "its bundle is refused: ")
	clock.Store(published.UnixNano())
	select {
	case from := <-done:
		if from != "the persisted copy" {
			t.Fatalf("from %q: %s", from, out.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("still waiting: %s", out.String())
	}
	if testutil.ToFloat64(m.InventoryBundleRefused) != 1 {
		t.Fatal("the clock catching up cleared the alarm for the service's document another key signed")
	}
}

// Within the skew, a document dated a little ahead is taken, and its age is
// 0, never negative.
func TestTheSnapshotAgeIsNeverNegative(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	raw := sealedDocAt(t, key, 7, 1, rig.now.Add(2*time.Minute))
	doc, inv, err := bundle.Open(raw, []ed25519.PublicKey{key.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	rig.r.startDocument(&inventory.Published{Raw: raw, Doc: doc, Inv: inv}, "the mirror's copy")
	if age := testutil.ToFloat64(rig.m.InventorySnapshotAge); age != 0 {
		t.Fatalf("age %v, want 0", age)
	}
}

// /readyz says why it is not ready, in fixed text, and a different line
// when draining than while waiting for a first bundle.
func TestReadyzSaysWhy(t *testing.T) {
	rd := newReadiness()
	get := func() (int, string) {
		w := httptest.NewRecorder()
		rd.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		return w.Code, strings.TrimSpace(w.Body.String())
	}
	for _, step := range []struct {
		do   func()
		code int
		body string
	}{
		{func() {}, 503, "starting: the TACACS+ listener is not open yet"},
		{rd.waiting, 503, "waiting for a first bundle from the inventory service"},
		{rd.serving, 200, "serving"},
		{rd.draining, 503, "draining: port49d is shutting down, and the TACACS+ listener is closed or closing"},
	} {
		step.do()
		if code, body := get(); code != step.code || body != step.body {
			t.Fatalf("%d %q, want %d %q", code, body, step.code, step.body)
		}
	}
}

// A copy that cannot be kept is said and alarmed: a restart with the service
// down would start from an older copy, or none.
func TestAPersistThatFailsIsAlarmed(t *testing.T) {
	svc, key, keys := coldRig(t)
	svc.MirrorDir = ""
	if err := os.WriteFile(svc.StateDir, nil, 0o600); err != nil { // a file where the directory should be
		t.Fatal(err)
	}
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	m := testMetrics()
	p, from, err := coldStart(context.Background(), svc, keys, &fakeService{bundles: [][]byte{sealedDoc(t, key, 1, 1)}},
		m, nil)
	if err != nil || from != "the service" {
		t.Fatalf("%q %v", from, err)
	}
	persistStart("port49d", svc, coldPick{p, from}, m)
	if testutil.ToFloat64(m.InventoryPersistFailed) != 1 || !strings.Contains(out.String(), "a restart with the service down") {
		t.Fatalf("not alarmed: %s", out.String())
	}
}

// A start with no local copy took its bundle from the service, and says so:
// the operator reading the log at 3am sees that nothing local backed it (policy M5).
func TestAColdStartWithNoLocalCopySaysWhatItTook(t *testing.T) {
	svc, key, keys := coldRig(t)
	svc.MirrorDir = ""
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	at := time.Date(2026, 11, 5, 3, 0, 0, 0, time.UTC)
	p, from, err := coldStart(context.Background(), svc, keys,
		&fakeService{bundles: [][]byte{sealedDocAt(t, key, 4, 1, at)}}, testMetrics(), nil)
	if err != nil || from != "the service" {
		t.Fatalf("%v %q %v", p, from, err)
	}
	sayStart("port49d", svc, coldPick{p, from})
	want := "port49d: inventory: no local copy; took bundle 4 published 2026-11-05T03:00:00Z from the service;"
	if !strings.Contains(out.String(), want) {
		t.Fatalf("the start line lacks %q:\n%s", want, out.String())
	}
}
