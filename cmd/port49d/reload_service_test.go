package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/inventory"
	"github.com/rhwendt/port49/internal/keyfile"
)

const groupedPolicy = minimalPolicy + "key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: lab_key}]\n"

type serviceRig struct {
	*reloadRig
	key ed25519.PrivateKey
	pub ed25519.PublicKey
}

// newServiceRig is a reload rig whose inventory comes from the service: no
// inventory_file, a state_dir, and one verify key.
func newServiceRig(t *testing.T, policyBody string) *serviceRig {
	t.Helper()
	rig := &serviceRig{reloadRig: newReloadRig(t, policyBody)}
	rig.pub, rig.key, _ = ed25519.GenerateKey(rand.Reader)
	rig.cfg.InventoryFile = ""
	rig.cfg.InventoryService = &config.InventoryServiceConfig{URL: "https://inv.test:8443",
		StateDir: filepath.Join(safeDir(t), "state"), PollInterval: 30 * time.Second}
	rig.r.cfg = rig.cfg
	keys := []ed25519.PublicKey{rig.pub}
	rig.r.verifyKeys.Store(&keys)
	return rig
}

// doc is what the fetcher hands over for devices leaf1..leafN at 10.0.0.i,
// sealed and opened as it opens one, built against policyBody.
func (rig *serviceRig) doc(t *testing.T, seq int64, policyBody string, n int, extra ...admission.Device) received {
	t.Helper()
	var inv admission.Inventory
	for i := 1; i <= n; i++ {
		inv.Devices = append(inv.Devices, admission.Device{Name: fmt.Sprintf("leaf%d", i), Platform: "arista_eos",
			Addresses: []netip.Addr{netip.AddrFrom4([4]byte{10, 0, 0, byte(i)})}, Transport: admission.TransportTCP})
	}
	inv.Devices = append(inv.Devices, extra...)
	raw, err := bundle.Seal(bundle.NewDocument(seq, rig.now, []byte(policyBody), "1.1.0", inv, nil), rig.key)
	if err != nil {
		t.Fatal(err)
	}
	doc, opened, err := bundle.Open(raw, []ed25519.PublicKey{rig.pub})
	if err != nil {
		t.Fatal(err)
	}
	return received{pub: &inventory.Published{Raw: raw, Doc: doc, Inv: opened}, raw: raw, etag: bundle.ETag(raw)}
}

func (rig *serviceRig) receive(d received) {
	rig.with(func() { rig.r.receive(context.Background(), d) })
}

func TestADocumentIsLoadedAsAReloadIsAndPersisted(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	var buf syncBuffer
	rig.b.Log = decision.NewJSONLines(&buf)
	rig.receive(rig.doc(t, 1, groupedPolicy, 2))
	if _, ok := rig.b.Policy.Load().Device("leaf2"); !ok {
		t.Fatalf("not loaded: %s", rig.out.String())
	}
	if !strings.Contains(rig.out.String(), "port49d: inventory reloaded (inventory service, bundle 1): bundle ") {
		t.Fatalf("the swap line: %s", rig.out.String())
	}
	if !strings.Contains(buf.String(), `"kind":"device_added"`) {
		t.Fatalf("no inventory_change record: %s", buf.String())
	}
	p, err := readPersisted(rig.cfg.InventoryService.StateDir, []ed25519.PublicKey{rig.pub})
	if err != nil || p == nil || p.Doc.Sequence != 1 {
		t.Fatalf("persisted: %v %v", p, err)
	}
	if testutil.ToFloat64(rig.m.InventoryBundleSequence) != 1 ||
		testutil.ToFloat64(rig.m.InventoryReloads.WithLabelValues("applied")) != 1 {
		t.Fatal("metrics")
	}
}

// Spec §10: the daemon MUST NOT trust the payload — its own bound applies,
// said once per document, and SIGHUP after raising it applies the document
// held.
func TestADocumentOverTheBoundIsRefusedOnceAndSIGHUPAppliesIt(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	rig.receive(rig.doc(t, 1, groupedPolicy, 10))
	over := rig.doc(t, 2, groupedPolicy, 5)
	rig.receive(over)
	rig.receive(over)
	out := rig.out.String()
	if strings.Count(out, "port49d: inventory reload (inventory service, bundle 2) refused; still serving bundle") != 1 ||
		!strings.Contains(out, "removes 5 of 10 devices") || !strings.Contains(out, "fix the source of truth") ||
		strings.Contains(out, "key_groups was deleted") {
		t.Fatalf("the refusal: %s", out)
	}
	if testutil.ToFloat64(rig.m.InventoryBundleRefused) != 1 {
		t.Fatal("port49_inventory_bundle_refused is not 1")
	}
	rig.sighupWithBound(t, 100)
	if len(rig.b.Policy.Load().Devices()) != 5 || testutil.ToFloat64(rig.m.InventoryBundleRefused) != 0 {
		t.Fatalf("SIGHUP did not apply the document held: %s", rig.out.String())
	}
}

// Decided 12: a document signed by a key port49d does not hold yet is
// refused once, and applies at the SIGHUP that adds the key.
func TestADocumentThatDoesNotVerifyAppliesOnceItsKeyIsAdded(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	rig.receive(rig.doc(t, 1, groupedPolicy, 2))
	newPub, newKey, _ := ed25519.GenerateKey(rand.Reader)
	rotated := &serviceRig{reloadRig: rig.reloadRig, key: newKey, pub: newPub}
	d := rotated.doc(t, 2, groupedPolicy, 3)
	_, _, err := bundle.Open(d.raw, []ed25519.PublicKey{rig.pub})
	rig.receive(received{raw: d.raw, etag: d.etag, err: err})
	if !strings.Contains(rig.out.String(), "which no verify key holds") ||
		!strings.Contains(rig.out.String(), "add its public key to inventory.service.verify_key_files and send SIGHUP") {
		t.Fatalf("the refusal: %s", rig.out.String())
	}
	_, pubPEM, _ := keyfile.EncodeEd25519(newKey)
	// safeDir: a verify key is read behind the write fence.
	newFile := filepath.Join(safeDir(t), "new.pub")
	oldFile := filepath.Join(safeDir(t), "old.pub")
	os.WriteFile(newFile, pubPEM, 0o644)
	_, oldPEM, _ := keyfile.EncodeEd25519(rig.key)
	os.WriteFile(oldFile, oldPEM, 0o644)
	rig.r.cfgPath = filepath.Join(t.TempDir(), "port49d.yaml")
	os.WriteFile(rig.r.cfgPath, []byte(fmt.Sprintf(`inventory:
  service: {url: "https://inv.test:8443", ca_file: /x, tls_cert_file: /x, tls_key_file: /x,
            state_dir: /x, verify_key_files: [%s, %s]}
`, oldFile, newFile)), 0o600)
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	if len(rig.b.Policy.Load().Devices()) != 3 {
		t.Fatalf("not applied after the key was added: %s", rig.out.String())
	}
}

// Pre-flight minor 4: a signature that does not verify under a key port49d
// holds is not a rotation, and the line says to investigate.
func TestATamperedDocumentIsCalledOutNotExplainedAsARotation(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	d := rig.doc(t, 1, groupedPolicy, 2)
	tampered := []byte(strings.Replace(string(d.raw), `"signature":"`, `"signature":"AAAA`, 1))
	_, _, err := bundle.Open(tampered, []ed25519.PublicKey{rig.pub})
	rig.receive(received{raw: tampered, etag: bundle.ETag(tampered), err: err})
	out := rig.out.String()
	if !strings.Contains(out, "investigate") || strings.Contains(out, "signing key was rotated") {
		t.Fatalf("%s", out)
	}
}

// Pre-flight M3: a SIGHUP that finds a verify key others could write keeps
// the keys in force.
func TestASIGHUPReReadOfAnUnfencedVerifyKeyKeepsTheKeysInForce(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	_, pubPEM, _ := keyfile.EncodeEd25519(rig.key)
	dir := t.TempDir()
	loose := filepath.Join(dir, "loose.pub")
	os.WriteFile(loose, pubPEM, 0o664)
	os.Chmod(loose, 0o664)
	rig.r.cfgPath = filepath.Join(t.TempDir(), "port49d.yaml")
	os.WriteFile(rig.r.cfgPath, []byte(fmt.Sprintf(`inventory:
  service: {url: "https://inv.test:8443", ca_file: /x, tls_cert_file: /x, tls_key_file: /x,
            state_dir: /x, verify_key_files: [%s]}
`, loose)), 0o600)
	before := *rig.r.verifyKeys.Load()
	rig.with(func() { rig.r.rereadVerifyKeys() })
	if !strings.Contains(rig.out.String(), "not re-read") || !strings.Contains(rig.out.String(), "writable by others") ||
		len(*rig.r.verifyKeys.Load()) != len(before) {
		t.Fatalf("%s", rig.out.String())
	}
}

// The service confirming the document in force keeps the snapshot young.
func TestAnUnchangedAnswerKeepsTheSnapshotYoung(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	d := rig.doc(t, 1, groupedPolicy, 2)
	rig.receive(d)
	rig.now = rig.now.Add(10 * time.Minute)
	rig.receive(received{etag: d.etag, unchanged: true})
	if age := testutil.ToFloat64(rig.m.InventorySnapshotAge); age > 1 {
		t.Fatalf("age %v", age)
	}
}

// Decided 3: a sequence that goes backwards is applied and said. A service
// whose state_dir was reset publishes later than the document in force, which
// is what tells it from a replay (TestAnOlderDocumentSentAgainIsRefused).
func TestASequenceThatGoesBackIsSaid(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	rig.receive(rig.doc(t, 40, groupedPolicy, 2))
	rig.now = rig.now.Add(time.Minute)
	rig.receive(rig.doc(t, 1, groupedPolicy, 2, admission.Device{Name: "leaf9", Platform: "arista_eos",
		Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.9")}, Transport: admission.TransportTCP}))
	if !strings.Contains(rig.out.String(), "the service's sequence went back from 40 to 1") {
		t.Fatalf("%s", rig.out.String())
	}
}

// Ruling 2: a document neither of a higher sequence nor published later than
// the one in force is an older genuine document sent again. It is refused,
// said once, counted and alarmed, and the bundle in force keeps serving.
func TestAnOlderDocumentSentAgainIsRefused(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	older := rig.doc(t, 1, groupedPolicy, 3)
	rig.now = rig.now.Add(time.Minute)
	rig.receive(rig.doc(t, 2, groupedPolicy, 2))
	rig.receive(older)
	rig.receive(older)
	out := rig.out.String()
	if strings.Count(out, "port49d: inventory reload (inventory service, bundle 1) refused; still serving bundle") != 1 ||
		!strings.Contains(out, "is not later than bundle 2 in force") || !strings.Contains(out, "investigate") {
		t.Fatalf("the refusal: %s", out)
	}
	if len(rig.b.Policy.Load().Devices()) != 2 || rig.r.seq != 2 {
		t.Fatalf("the older document was applied: %s", out)
	}
	if testutil.ToFloat64(rig.m.InventoryBundleRefused) != 1 ||
		testutil.ToFloat64(rig.m.InventoryReloads.WithLabelValues("refused")) != 2 {
		t.Fatal("the replay is not alarmed and counted")
	}
	// The same sequence published at the same instant, with other bytes, is
	// not later either.
	same := rig.doc(t, 2, groupedPolicy, 4)
	rig.receive(same)
	if len(rig.b.Policy.Load().Devices()) != 2 {
		t.Fatalf("a second document at the same sequence and instant was applied: %s", rig.out.String())
	}
}

// Review Important 1: after a reset, a genuine document from before it has
// the higher sequence but the earlier published_at, and a replay of it is
// refused: documents are ordered by (published_at, sequence).
func TestAReplayFromBeforeAResetIsRefused(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	before := rig.doc(t, 40, groupedPolicy, 2)
	rig.receive(before)
	rig.now = rig.now.Add(time.Hour)
	rig.receive(rig.doc(t, 1, groupedPolicy, 2, admission.Device{Name: "leaf9", Platform: "arista_eos",
		Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.9")}, Transport: admission.TransportTCP}))
	rig.receive(before)
	out := rig.out.String()
	if _, ok := rig.b.Policy.Load().Device("leaf9"); !ok || rig.r.seq != 1 {
		t.Fatalf("the replay from before the reset was applied: %s", out)
	}
	if !strings.Contains(out, "bundle 40, published") || !strings.Contains(out, "or the service's clock went back") ||
		testutil.ToFloat64(rig.m.InventoryBundleRefused) != 1 {
		t.Fatalf("%s", out)
	}
}

// Review Critical 1: a document held after a refusal is opened again under
// the keys in force when it is tried again, so a SIGHUP that removes its
// signer and raises the bound does not apply it.
func TestASIGHUPThatRemovesTheSignerDoesNotApplyTheDocumentHeld(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	rig.receive(rig.doc(t, 1, groupedPolicy, 10))
	rig.receive(rig.doc(t, 2, groupedPolicy, 5)) // over the bound, held
	before := rig.b.Policy.Load().Bundle
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPEM, _ := keyfile.EncodeEd25519(otherKey)
	keyFile := filepath.Join(safeDir(t), "other.pub")
	os.WriteFile(keyFile, otherPEM, 0o644)
	rig.r.cfgPath = filepath.Join(t.TempDir(), "port49d.yaml")
	os.WriteFile(rig.r.cfgPath, []byte(fmt.Sprintf(`inventory:
  max_removed_percent: 100
  service: {url: "https://inv.test:8443", ca_file: /x, tls_cert_file: /x, tls_key_file: /x,
            state_dir: /x, verify_key_files: [%s]}
`, keyFile)), 0o600)
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	out := rig.out.String()
	if rig.b.Policy.Load().Bundle != before || rig.r.seq != 1 {
		t.Fatalf("the document signed by the removed key was applied: %s", out)
	}
	if !strings.Contains(out, "inventory reload (SIGHUP) refused") || !strings.Contains(out, "which no verify key holds") ||
		testutil.ToFloat64(rig.m.InventoryBundleRefused) != 1 {
		t.Fatalf("%s", out)
	}
	// Review minor 3: the document in force no longer opens either, so the
	// service confirming it keeps the alarm, said once.
	rig.receive(received{etag: rig.r.inForce, unchanged: true})
	rig.receive(received{etag: rig.r.inForce, unchanged: true})
	if testutil.ToFloat64(rig.m.InventoryBundleRefused) != 1 ||
		strings.Count(rig.out.String(), "in force, no longer opens under the verify keys in force") != 1 {
		t.Fatalf("%s", rig.out.String())
	}
}

// Review minor 1: a document refused only for being published ahead of this
// clock is judged again at each confirmation of it, and applies once the
// clock reaches it.
func TestADocumentAheadOfTheClockAppliesOnceTheClockCatchesUp(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	now := rig.now
	rig.now = now.Add(time.Hour)
	ahead := rig.doc(t, 1, groupedPolicy, 2)
	rig.now = now
	rig.receive(ahead)
	rig.receive(received{etag: ahead.etag, unchanged: true})
	rig.receive(received{etag: ahead.etag, unchanged: true})
	if _, ok := rig.b.Policy.Load().Device("leaf2"); ok {
		t.Fatal("applied while still ahead")
	}
	// Judged again at each poll, but refused once per document: the counter
	// is not a poll counter.
	if n := testutil.ToFloat64(rig.m.InventoryReloads.WithLabelValues("refused")); n != 1 {
		t.Fatalf("reloads_total{refused} is %v for one document still ahead", n)
	}
	if strings.Count(rig.out.String(), "refused; still serving") != 1 {
		t.Fatalf("%s", rig.out.String())
	}
	rig.now = now.Add(time.Hour)
	rig.receive(received{etag: ahead.etag, unchanged: true})
	if _, ok := rig.b.Policy.Load().Device("leaf2"); !ok || testutil.ToFloat64(rig.m.InventoryBundleRefused) != 0 {
		t.Fatalf("not applied once the clock caught up: %s", rig.out.String())
	}
}

// Spec §10: a document published more than maxPublishedSkew ahead of this
// clock is refused from the service as from a copy.
func TestAPulledDocumentPublishedInTheFutureIsRefused(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	now := rig.now
	rig.now = now.Add(time.Hour)
	ahead := rig.doc(t, 1, groupedPolicy, 2)
	rig.now = now
	before := rig.b.Policy.Load().Bundle
	rig.receive(ahead)
	if rig.b.Policy.Load().Bundle != before || !strings.Contains(rig.out.String(), "more than 5m0s after this host's clock") ||
		testutil.ToFloat64(rig.m.InventoryBundleRefused) != 1 {
		t.Fatalf("%s", rig.out.String())
	}
}

// Ruling 7: after a start from a copy — whose persist may have failed, and
// with a refusal alarmed on the way — the service confirming the document in
// force clears port49_inventory_bundle_refused and writes the copy owed,
// clearing port49_inventory_persist_failed.
func TestAConfirmationAfterAStartFromACopyClearsTheAlarms(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	d := rig.doc(t, 7, groupedPolicy, 2)
	rig.r.startDocument(d.pub, "the mirror's copy")
	rig.m.InventoryBundleRefused.Set(1)
	rig.m.InventoryPersistFailed.Set(1)
	rig.receive(received{etag: d.etag, unchanged: true})
	if testutil.ToFloat64(rig.m.InventoryBundleRefused) != 0 || testutil.ToFloat64(rig.m.InventoryPersistFailed) != 0 {
		t.Fatal("the confirmation did not clear the alarms")
	}
	p, err := readPersisted(rig.cfg.InventoryService.StateDir, []ed25519.PublicKey{rig.pub})
	if err != nil || p == nil || p.Doc.Sequence != 7 {
		t.Fatalf("the copy owed was not written: %v %v", p, err)
	}
	// The same document sent whole — the fetch a SIGHUP asks for — is a
	// confirmation, not a replay refused.
	rig.m.InventoryBundleRefused.Set(1)
	rig.receive(d)
	if testutil.ToFloat64(rig.m.InventoryBundleRefused) != 0 || strings.Contains(rig.out.String(), "refused") {
		t.Fatalf("%s", rig.out.String())
	}
}

// Ruling 8: a persist that fails is said once and alarmed, serving goes on
// with the document applied, and the next confirmation writes it.
func TestAPersistThatFailsKeepsServingAndIsRetriedAtTheNextConfirmation(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	parent := filepath.Dir(rig.cfg.InventoryService.StateDir)
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(parent, 0o755)
	if os.WriteFile(filepath.Join(parent, "probe"), nil, 0o600) == nil {
		t.Skip("running as a user the directory mode does not stop")
	}
	d := rig.doc(t, 1, groupedPolicy, 2)
	rig.receive(d)
	rig.receive(received{etag: d.etag, unchanged: true})
	if _, ok := rig.b.Policy.Load().Device("leaf2"); !ok {
		t.Fatalf("not serving the document: %s", rig.out.String())
	}
	if strings.Count(rig.out.String(), "a restart with the service down would start from an older copy") != 1 ||
		testutil.ToFloat64(rig.m.InventoryPersistFailed) != 1 {
		t.Fatalf("%s", rig.out.String())
	}
	os.Chmod(parent, 0o755)
	rig.receive(received{etag: d.etag, unchanged: true})
	if testutil.ToFloat64(rig.m.InventoryPersistFailed) != 0 {
		t.Fatal("the confirmation did not retry the persist")
	}
	if p, err := readPersisted(rig.cfg.InventoryService.StateDir, []ed25519.PublicKey{rig.pub}); err != nil || p == nil {
		t.Fatalf("%v %v", p, err)
	}
}

// Ruling 9: a SIGHUP that finds the inventory.service block gone is never
// read as no verify keys: the keys in force stay, and it is said.
func TestASIGHUPWithTheServiceBlockRemovedKeepsTheKeysInForce(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	rig.r.cfgPath = filepath.Join(t.TempDir(), "port49d.yaml")
	os.WriteFile(rig.r.cfgPath, []byte("inventory: {max_removed_percent: 10}\n"), 0o600)
	rig.with(func() { rig.r.rereadVerifyKeys() })
	if len(*rig.r.verifyKeys.Load()) != 1 || !strings.Contains(rig.out.String(), "has no inventory.service block") {
		t.Fatalf("%s", rig.out.String())
	}
}

// askedService is a service with one document that sends on asked each
// time the document is asked for, with the If-None-Match sent; an ask no test
// receives waits until its context ends.
type askedService struct {
	raw   []byte
	asked chan string
}

func (s *askedService) Version(context.Context) (inventory.VersionInfo, error) {
	return inventory.VersionInfo{ETag: bundle.ETag(s.raw)}, nil
}

func (s *askedService) Bundle(ctx context.Context, etag string) ([]byte, string, bool, error) {
	select {
	case s.asked <- etag:
	case <-ctx.Done():
		return nil, "", false, ctx.Err()
	}
	return s.raw, bundle.ETag(s.raw), false, nil
}

// The fetcher's documents reach the reloader's run loop, a SIGHUP asks for
// the document whole again, and at shutdown run returns only once the
// fetcher has, with no line about a service that did not answer (conflict
// scan F8, F11).
func TestTheFetcherFeedsRunAndIsJoinedAtShutdown(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	d := rig.doc(t, 1, groupedPolicy, 2)
	svc := &askedService{raw: d.raw, asked: make(chan string)}
	defer func(w io.Writer) { stderr = w }(stderr)
	stderr = rig.out
	ctx, cancel := context.WithCancel(context.Background())
	fetchDone := startFetcher(ctx, rig.r, svc, rig.m)
	hup := make(chan os.Signal, 1)
	runDone := make(chan struct{})
	go func() { rig.r.run(ctx, hup); close(runDone) }()
	select {
	case etag := <-svc.asked:
		if etag != "" {
			t.Fatalf("the first ask sent If-None-Match %q with no document in force", etag)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the fetcher did not ask")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(rig.out.String(), "inventory reloaded (inventory service, bundle 1)") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	hup <- syscall.SIGHUP
	select {
	case etag := <-svc.asked:
		if etag != "" {
			t.Fatalf("the SIGHUP fetch sent If-None-Match %q", etag)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("SIGHUP did not ask for the document again: %s", rig.out.String())
	}
	cancel()
	for _, done := range []<-chan struct{}{runDone, fetchDone} {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("run or the fetcher did not return when the context ended")
		}
	}
	out := rig.out.String()
	if _, ok := rig.b.Policy.Load().Device("leaf2"); !ok || strings.Contains(out, "did not answer") ||
		strings.Contains(out, "refused;") {
		t.Fatalf("%s", out)
	}
}

// Decision 29: a document built against another policy is applied against
// the policy in force, said once per pair, and alarmed until they agree.
func TestAPolicyMismatchIsSaidAndAlarmedAndTheInventoryApplied(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	other := groupedPolicy + "# the service's copy is a commit ahead\n"
	rig.receive(rig.doc(t, 1, other, 2))
	rig.receive(rig.doc(t, 2, other, 3))
	if len(rig.b.Policy.Load().Devices()) != 3 {
		t.Fatalf("the inventory was not applied: %s", rig.out.String())
	}
	if rig.b.Policy.Load().Source != engine.HashOf([]byte(groupedPolicy)) {
		t.Fatal("the policy in force changed")
	}
	out := rig.out.String()
	if n := strings.Count(out, "port49d: inventory: the service built bundle "); n != 1 ||
		!strings.Contains(out, "against policy "+engine.HashOf([]byte(other))) ||
		!strings.Contains(out, "nothing the service sends changes the policy") {
		t.Fatalf("said %d times: %s", n, out)
	}
	if testutil.ToFloat64(rig.m.InventoryPolicyMismatch) != 1 {
		t.Fatal("port49_inventory_policy_mismatch is not 1")
	}
	// port49d's own policy reload brings it level: said, and cleared.
	rig.write(t, other)
	rig.pollTwice()
	if testutil.ToFloat64(rig.m.InventoryPolicyMismatch) != 0 ||
		!strings.Contains(rig.out.String(), "port49d: inventory: the service's policy and the policy in force agree again") {
		t.Fatalf("not cleared: %s", rig.out.String())
	}
}

func TestAMatchingPolicyRaisesNothing(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	rig.receive(rig.doc(t, 1, groupedPolicy, 2))
	if testutil.ToFloat64(rig.m.InventoryPolicyMismatch) != 0 || strings.Contains(rig.out.String(), "service built") {
		t.Fatalf("%s", rig.out.String())
	}
}

// The other way the alarm clears (decision 29): the service's next document
// is built against the policy in force. A mismatch is never a refusal.
func TestAMatchingDocumentClearsTheMismatch(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	rig.receive(rig.doc(t, 1, groupedPolicy+"# ahead\n", 2))
	if testutil.ToFloat64(rig.m.InventoryPolicyMismatch) != 1 || testutil.ToFloat64(rig.m.InventoryBundleRefused) != 0 {
		t.Fatalf("not alarmed, or refused: %s", rig.out.String())
	}
	rig.receive(rig.doc(t, 2, groupedPolicy, 2))
	if testutil.ToFloat64(rig.m.InventoryPolicyMismatch) != 0 ||
		!strings.Contains(rig.out.String(), "port49d: inventory: the service's policy and the policy in force agree again") {
		t.Fatalf("not cleared: %s", rig.out.String())
	}
}

// The start's document is judged as a pulled one is (decision 29).
func TestTheStartsDocumentIsJudgedForAPolicyMismatch(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	d := rig.doc(t, 1, groupedPolicy+"# ahead\n", 2)
	rig.with(func() { rig.r.startDocument(d.pub, "the persisted copy") })
	if testutil.ToFloat64(rig.m.InventoryPolicyMismatch) != 1 ||
		!strings.Contains(rig.out.String(), "port49d: inventory: the service built bundle 1 against policy ") {
		t.Fatalf("not said at start: %s", rig.out.String())
	}
}
