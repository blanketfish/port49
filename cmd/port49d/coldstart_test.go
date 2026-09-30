package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/inventory"
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
	os.WriteFile(filepath.Join(svc.MirrorDir, "bundle.json"), sealedDoc(t, key, 5, 2), 0o644)
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	p, from, err := coldStart(context.Background(), svc, keys, &fakeService{t: t, forbid: true}, testMetrics())
	if err != nil || p.Doc.Sequence != 5 || from != "the mirror's copy" {
		t.Fatalf("%v %q %v", p, from, err)
	}
}

// Pre-flight minor 11: newer is later publication, not a higher sequence,
// which a service reset starts again at 1.
func TestColdStartPrefersTheLaterPublicationOverTheHigherSequence(t *testing.T) {
	svc, key, keys := coldRig(t)
	persistBundle(svc.StateDir, sealedDocAt(t, key, 40, 1, time.Now().Add(-48*time.Hour)))
	os.WriteFile(filepath.Join(svc.MirrorDir, "bundle.json"), sealedDoc(t, key, 2, 2), 0o644)
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	p, from, err := coldStart(context.Background(), svc, keys, &fakeService{t: t, forbid: true}, testMetrics())
	if err != nil || p.Doc.Sequence != 2 || from != "the mirror's copy" ||
		!strings.Contains(out.String(), "published later than the persisted copy") {
		t.Fatalf("%v %q %v %s", p, from, err, out.String())
	}
}

// Pre-flight M4: a mirror mount that hangs is passed over at its deadline,
// said, and the start goes on from the persisted copy.
func TestAHungMirrorNeverHoldsUpAStartFromThePersistedCopy(t *testing.T) {
	svc, key, keys := coldRig(t)
	persistBundle(svc.StateDir, sealedDoc(t, key, 3, 1))
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
	p, from, err := coldStart(context.Background(), svc, keys, &fakeService{t: t, forbid: true}, testMetrics())
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

func testMetrics() *metrics.Metrics { return metrics.New(prometheus.NewRegistry()) }

// A copy the service did not sign is passed over, said, and alarmed (spec
// §10: "refused, said once, and alarmed").
func TestACopyThatDoesNotVerifyIsPassedOver(t *testing.T) {
	svc, key, keys := coldRig(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	persistBundle(svc.StateDir, sealedDoc(t, key, 3, 1))
	os.WriteFile(filepath.Join(svc.MirrorDir, "bundle.json"), sealedDoc(t, other, 9, 2), 0o644)
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	m := testMetrics()
	p, from, err := coldStart(context.Background(), svc, keys, &fakeService{t: t, forbid: true}, m)
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
	persistBundle(svc.StateDir, sealedDoc(t, key, 3, 1))
	os.Chmod(filepath.Join(svc.StateDir, "bundle.json"), 0o664)
	if p, err := readPersisted(svc.StateDir, keys); p != nil || err == nil || !strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("%v %v", p, err)
	}
}

// With neither copy, port49d waits for the service, says why once per
// reason, and persists what it gets.
func TestWithNoCopyItWaitsForTheServiceSayingWhyOnce(t *testing.T) {
	svc, key, keys := coldRig(t)
	svc.MirrorDir = ""
	doc := sealedDoc(t, key, 1, 2)
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	p, from, err := coldStart(context.Background(), svc, keys, &fakeService{bundles: [][]byte{nil, nil, nil, doc}}, testMetrics())
	if err != nil || p.Doc.Sequence != 1 || from != "the service" {
		t.Fatalf("%v %q %v", p, from, err)
	}
	if n := strings.Count(out.String(), "port49d: inventory: no bundle yet (persisted copy: none in "); n != 1 ||
		!strings.Contains(out.String(), "mirror: none configured; service at https://inv.test:8443: dial tcp") ||
		!strings.Contains(out.String(), "TACACS+ is not served until one arrives, and /readyz answers 503") {
		t.Fatalf("said %d times: %s", n, out.String())
	}
	fi, err := os.Stat(filepath.Join(svc.StateDir, "bundle.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("not persisted: %v %v", fi, err)
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
	if _, _, err := coldStart(ctx, svc, keys, &fakeService{bundles: [][]byte{nil}}, testMetrics()); !errors.Is(err,
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
	persistBundle(svc.StateDir, sealedDoc(t, other, 3, 1))
	e := stderr
	defer func() { stderr = e }()
	stderr = &syncBuffer{}
	m := testMetrics()
	p, from, err := coldStart(context.Background(), svc, keys, &fakeService{bundles: [][]byte{sealedDoc(t, key, 4, 1)}}, m)
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
	persistBundle(svc.StateDir, sealedDoc(t, key, 3, 1))
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
	if _, from, err := coldStart(context.Background(), svc, keys, &fakeService{t: t, forbid: true}, m); err != nil ||
		from != "the persisted copy" {
		t.Fatalf("%q %v", from, err)
	}
	if testutil.ToFloat64(m.InventoryBundleRefused) != 0 {
		t.Fatal("a hung mirror is alarmed as a refused bundle")
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
	if _, from, err := coldStart(context.Background(), svc, keys, &fakeService{bundles: [][]byte{sealedDoc(t, key, 1, 1)}},
		m); err != nil || from != "the service" {
		t.Fatalf("%q %v", from, err)
	}
	if testutil.ToFloat64(m.InventoryPersistFailed) != 1 || !strings.Contains(out.String(), "a restart with the service down") {
		t.Fatalf("not alarmed: %s", out.String())
	}
}
