package inventory

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/bundle"
)

const syncPolicy = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: lab_key}]
`

// memSource is a source a test sets by hand.
type memSource struct {
	name string
	inv  admission.Inventory
	err  error
}

func (m *memSource) Name() string { return m.name }
func (m *memSource) Fetch(context.Context) (admission.Inventory, error) {
	return m.inv, m.err
}

// devices is n arista_eos devices leaf-01..leaf-n at 10.0.0.1.. .
func devices(n int) admission.Inventory {
	var inv admission.Inventory
	for i := 1; i <= n; i++ {
		inv.Devices = append(inv.Devices, admission.Device{Name: fmt.Sprintf("leaf-%02d", i), Platform: "arista_eos",
			Addresses: []netip.Addr{netip.AddrFrom4([4]byte{10, 0, 0, byte(i)})}, Transport: admission.TransportTCP})
	}
	return inv
}

type syncRig struct {
	s   *Syncer
	src *memSource
	out *bytes.Buffer
	pub ed25519.PublicKey
	dir string
}

func newSyncRig(t *testing.T, policyBody string, inv admission.Inventory) *syncRig {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(pol, []byte(policyBody), 0o600); err != nil {
		t.Fatal(err)
	}
	rig := &syncRig{src: &memSource{name: "a", inv: inv}, out: &bytes.Buffer{}, pub: pub, dir: dir}
	rig.s = rig.syncer(key)
	if err := os.MkdirAll(rig.s.State.MirrorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return rig
}

func (rig *syncRig) syncer(key ed25519.PrivateKey) *Syncer {
	return &Syncer{Sources: []Source{rig.src}, Bounds: map[string]int{"a": 10}, Default: 10,
		PolicyFile: filepath.Join(rig.dir, "policy.yaml"), Key: key,
		State:   State{Dir: filepath.Join(rig.dir, "state"), MirrorDir: filepath.Join(rig.dir, "mirror"), Keep: 64},
		Metrics: NewMetrics(prometheus.NewRegistry()), Now: time.Now, Log: rig.out}
}

func (rig *syncRig) pubs() []ed25519.PublicKey { return []ed25519.PublicKey{rig.pub} }

func (rig *syncRig) sync(t *testing.T) Result {
	t.Helper()
	return rig.s.Sync(context.Background(), "schedule")
}

func TestTheFirstSyncPublishesBundleOneEverywhere(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	res := rig.sync(t)
	if res.Outcome != "published" || res.Sequence != 1 {
		t.Fatalf("%+v %s", res, rig.out)
	}
	for _, get := range []func([]ed25519.PublicKey) (*Published, error){rig.s.State.Latest, rig.s.State.Mirror} {
		p, err := get(rig.pubs())
		if err != nil || p.Doc.Sequence != 1 || len(p.Inv.Devices) != 3 {
			t.Fatalf("%v %v", p, err)
		}
	}
	if !strings.Contains(rig.out.String(), "port49-inventory: sync (schedule): published bundle 1 (sha256:") ||
		!strings.Contains(rig.out.String(), "): first bundle: +3 device(s); 0 quarantined") {
		t.Fatalf("the line: %s", rig.out)
	}
	if testutil.ToFloat64(rig.s.Metrics.Published) != 1 || testutil.ToFloat64(rig.s.Metrics.Devices) != 3 {
		t.Fatal("metrics")
	}
}

func TestAnUnchangedSyncPublishesNothingAndSaysNothing(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	rig.sync(t)
	rig.out.Reset()
	if res := rig.sync(t); res.Outcome != "unchanged" || res.Sequence != 1 || rig.out.Len() != 0 {
		t.Fatalf("%+v %q", res, rig.out)
	}
}

func TestAChangeIsTheNextSequenceAndItsSecurityChangesAreSaid(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	rig.sync(t)
	inv := devices(3)
	inv.Devices[0].Addresses = append(inv.Devices[0].Addresses, netip.MustParseAddr("10.66.0.1"))
	rig.src.inv = inv
	res := rig.sync(t)
	if res.Outcome != "published" || res.Sequence != 2 {
		t.Fatalf("%+v", res)
	}
	if !strings.Contains(rig.out.String(), "port49-inventory: bundle 2: ! address added leaf-01: 10.66.0.1") {
		t.Fatalf("the security line: %s", rig.out)
	}
}

// Spec §10, "Bounded change per sync": a source that removes more than its
// bound refuses the sync, the bundle published stays, said once.
func TestASourceOverItsBoundIsRefusedOnce(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(10))
	rig.sync(t)
	rig.src.inv = devices(5)
	for i := 0; i < 2; i++ {
		if res := rig.sync(t); res.Outcome != "refused" || res.Sequence != 1 {
			t.Fatalf("%+v", res)
		}
	}
	out := rig.out.String()
	if strings.Count(out, "sync (schedule) refused; still publishing bundle 1") != 1 ||
		!strings.Contains(out, "source a removes 5 of 10 devices and refuses 0 more (50%), more than its "+
			"safety.max_removed_percent (10%)") ||
		!strings.Contains(out, "raise safety.max_removed_percent in port49-inventory.yaml and restart port49-inventory") {
		t.Fatalf("the refusal: %s", out)
	}
	if testutil.ToFloat64(rig.s.Metrics.SyncRefused) != 1 {
		t.Fatal("port49_inventory_sync_refused is not 1")
	}
	rig.s.Bounds["a"] = 60
	if res := rig.sync(t); res.Outcome != "published" || res.Sequence != 2 {
		t.Fatalf("raised: %+v", res)
	}
	if testutil.ToFloat64(rig.s.Metrics.SyncRefused) != 0 {
		t.Fatal("port49_inventory_sync_refused stayed 1")
	}
}

// Newly refused admission counts as a removal: a source that moves devices
// out of every key group's reach takes them out of service as surely as it
// removes them (pre-flight M1: the source makes them unadmittable).
func TestNewlyRefusedDevicesCountTowardTheBound(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(10))
	rig.sync(t)
	inv := devices(10)
	for i := 0; i < 3; i++ {
		inv.Devices[i].Addresses = []netip.Addr{netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})}
	}
	rig.src.inv = inv
	res := rig.sync(t)
	if res.Outcome != "refused" || !strings.Contains(res.Reason, "removes 0 of 10 devices and refuses 3 more") {
		t.Fatalf("%+v", res)
	}
}

// The bound measures what the sources changed. An edit to the service's own
// policy_file changes no daemon's admission (each applies the inventory
// against its own policy, decision 29), so it publishes, unbounded. Do not
// "fix" sync() to bound it: prevPol is parsed under the policy now on purpose.
func TestAServicePolicyEditAlonePublishesUnbounded(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(10))
	rig.sync(t)
	if err := os.WriteFile(rig.s.PolicyFile, []byte(strings.Replace(syncPolicy, "10.0.0.0/8", "10.0.0.0/29", 1)),
		0o600); err != nil {
		t.Fatal(err)
	}
	if res := rig.sync(t); res.Outcome != "published" || res.Sequence != 2 {
		t.Fatalf("%+v %s", res, rig.out)
	}
}

// Pre-flight M2: whatever the syncer publishes, Open accepts; what Open would
// refuse, the syncer leaves out.
func TestWhatTheSyncerPublishesPort49dOpens(t *testing.T) {
	inv := devices(4)
	inv.Devices[1].Transport = "tls "
	inv.Devices[2].Addresses = []netip.Addr{netip.MustParseAddr("fe80::1%eth0")}
	rig := newSyncRig(t, syncPolicy, inv)
	res := rig.sync(t)
	if res.Outcome != "published" || len(res.LeftOut) != 2 {
		t.Fatalf("%+v", res)
	}
	if _, _, err := bundle.Open(rig.s.Current().Raw, rig.pubs()); err != nil {
		t.Fatalf("port49d would refuse what the service published: %v", err)
	}
}

// Pre-flight M6: a signing-key rotation keeps the sequence and the bound —
// the old key is in the new service's verify keys.
func TestASigningKeyRotationKeepsTheSequenceAndTheBound(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(10))
	rig.sync(t)
	_, newKey, _ := ed25519.GenerateKey(rand.Reader)
	rotated := rig.syncer(newKey)
	rotated.VerifyKeys = []ed25519.PublicKey{rig.pub}
	// Restore re-seals bundle 1 under the new key as bundle 2 (final review I1).
	if err := rotated.Restore(); err != nil || rotated.Current() == nil || rotated.Current().Doc.Sequence != 2 {
		t.Fatalf("%v %v", rotated.Current(), err)
	}
	rig.src.inv = devices(5)
	if res := rotated.Sync(context.Background(), "startup"); res.Outcome != "refused" {
		t.Fatalf("the bound did not survive the rotation: %+v", res)
	}
	rig.src.inv = devices(11)
	if res := rotated.Sync(context.Background(), "startup"); res.Outcome != "published" || res.Sequence != 3 {
		t.Fatalf("%+v", res)
	}
}

// Final review I1: after a rotation the bundle published is re-sealed under
// the new key as the next sequence, the fleet unchanged — at Restore, or at
// the next sync when Restore could not keep it — so once every port49d holds
// it the old key can leave verify_key_files, and a service restarted without
// it starts.
func TestARotatedKeyReSealsTheBundleOnAStableFleet(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	first := rig.sync(t)
	_, newKey, _ := ed25519.GenerateKey(rand.Reader)
	newPub := []ed25519.PublicKey{newKey.Public().(ed25519.PublicKey)}
	rotated := rig.syncer(newKey)
	rotated.VerifyKeys = []ed25519.PublicKey{rig.pub}
	if err := rotated.Restore(); err != nil {
		t.Fatal(err)
	}
	cur := rotated.Current()
	if cur == nil || cur.Doc.Sequence != 2 || cur.Doc.Bundle != first.Bundle || !cur.Doc.PublishedAt.After(time.Time{}) {
		t.Fatalf("not re-sealed as bundle 2 of the same fleet: %+v", cur)
	}
	for what, get := range map[string]func([]ed25519.PublicKey) (*Published, error){"state_dir": rotated.State.Latest,
		"mirror": rotated.State.Mirror} {
		if p, err := get(newPub); err != nil || p.Doc.Sequence != 2 {
			t.Fatalf("%s does not hold bundle 2 under the new key alone: %v %v", what, p, err)
		}
	}
	if !strings.Contains(rig.out.String(), "port49-inventory: bundle 1 is signed by another key than the signing key "+
		bundle.KeyIDOf(newPub[0])+"; re-sealed as bundle 2") {
		t.Fatalf("not said: %s", rig.out)
	}
	if res := rotated.Sync(context.Background(), "schedule"); res.Outcome != "unchanged" || res.Sequence != 2 {
		t.Fatalf("a second pass re-sealed again: %+v", res)
	}
	// The old key dropped: the service restarts on what it now holds.
	dropped := rig.syncer(newKey)
	if err := dropped.Restore(); err != nil || dropped.Current().Doc.Sequence != 2 {
		t.Fatalf("restart without the old key: %v %v", dropped.Current(), err)
	}
}

// Final review I1: a Restore that could not keep the re-sealed bundle serves
// the old one, and the next sync re-seals it, the fleet unchanged.
func TestARotatedKeyReSealsAtTheNextSyncWhenRestoreCouldNot(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	rig.sync(t)
	_, newKey, _ := ed25519.GenerateKey(rand.Reader)
	rotated := rig.syncer(newKey)
	rotated.VerifyKeys = []ed25519.PublicKey{rig.pub}
	if err := os.Chmod(rotated.State.Dir, 0o500); err != nil { // published.json cannot be written
		t.Fatal(err)
	}
	err := rotated.Restore()
	os.Chmod(rotated.State.Dir, 0o700)
	if err != nil || rotated.Current().Doc.Sequence != 1 {
		t.Fatalf("%v %v", rotated.Current(), err)
	}
	if !strings.Contains(rig.out.String(), "could not be kept") {
		t.Fatalf("not said: %s", rig.out)
	}
	res := rotated.Sync(context.Background(), "schedule")
	if res.Sequence != 2 || rotated.Current().Doc.Sequence != 2 {
		t.Fatalf("not re-sealed at the next sync: %+v", res)
	}
	if _, _, err := bundle.Open(rotated.Current().Raw, []ed25519.PublicKey{newKey.Public().(ed25519.PublicKey)}); err != nil {
		t.Fatal(err)
	}
}

// Pre-flight M7: a mirror wiped, or once not written, is written again at the
// next sync, whatever the sync found.
func TestAMirrorThatFellBehindIsWrittenAgain(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	rig.sync(t)
	os.Remove(filepath.Join(rig.s.State.MirrorDir, "bundle.json"))
	if res := rig.sync(t); res.Outcome != "unchanged" {
		t.Fatalf("%+v", res)
	}
	raw, err := rig.s.State.MirrorRaw()
	if err != nil || !bytes.Equal(raw, rig.s.Current().Raw) {
		t.Fatalf("the mirror was not written again: %v", err)
	}
	if testutil.ToFloat64(rig.s.Metrics.MirrorBehind) != 0 {
		t.Fatal("port49_inventory_mirror_behind is not 0")
	}
}

func TestAnEmptyOrUnadmittedSyncIsRefusedWhateverTheBound(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, admission.Inventory{})
	rig.s.Bounds["a"] = 100
	if res := rig.sync(t); res.Outcome != "refused" || !strings.Contains(res.Reason, "name no device") {
		t.Fatalf("empty: %+v", res)
	}
	none := newSyncRig(t, strings.Replace(syncPolicy, "10.0.0.0/8", "192.0.2.0/24", 1), devices(2))
	if res := none.sync(t); res.Outcome != "refused" || !strings.Contains(res.Reason, "admits none of the 2") {
		t.Fatalf("none admitted: %+v", res)
	}
}

func TestAFailingSourceKeepsTheBundleAndIsSaidOnce(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	rig.sync(t)
	rig.src.err = errors.New("dial tcp: connection refused")
	for i := 0; i < 3; i++ {
		if res := rig.sync(t); res.Outcome != "failed" || res.Sequence != 1 {
			t.Fatalf("%+v", res)
		}
	}
	if n := strings.Count(rig.out.String(), "sync (schedule) failed; still publishing bundle 1: source a: dial tcp"); n != 1 {
		t.Fatalf("said %d times: %s", n, rig.out)
	}
	if testutil.ToFloat64(rig.s.Metrics.SyncFailing) != 1 {
		t.Fatal("port49_inventory_sync_failing is not 1")
	}
	rig.src.err = nil
	rig.sync(t)
	if testutil.ToFloat64(rig.s.Metrics.SyncFailing) != 0 {
		t.Fatal("port49_inventory_sync_failing stayed 1")
	}
}

// Spec §10: each source syncs on its own interval. A sync of one source
// fetches it alone and rebuilds the bundle with the other's latest fetch.
func TestASyncOfOneSourceKeepsTheOthersLatestFetch(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(2))
	b := &memSource{name: "b", inv: admission.Inventory{Devices: []admission.Device{{Name: "leaf-b",
		Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("10.1.0.1")},
		Transport: admission.TransportTCP}}}}
	rig.s.Sources = append(rig.s.Sources, b)
	rig.sync(t)
	rig.src.inv = devices(3) // source a changes, but only b is due
	b.inv.Devices = append(b.inv.Devices, admission.Device{Name: "leaf-b2", Platform: "arista_eos",
		Addresses: []netip.Addr{netip.MustParseAddr("10.1.0.2")}, Transport: admission.TransportTCP})
	res := rig.s.Sync(context.Background(), "schedule", "b")
	if res.Outcome != "published" || len(rig.s.Current().Inv.Devices) != 4 {
		t.Fatalf("%+v: %d devices, want a's two and b's two", res, len(rig.s.Current().Inv.Devices))
	}
	if res := rig.s.Sync(context.Background(), "schedule", "a"); len(rig.s.Current().Inv.Devices) != 5 {
		t.Fatalf("%+v", res)
	}
}

func TestADeviceInTwoSourcesIsRefused(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(2))
	b := devices(2)
	b.Devices[1].Name = "bad name"
	rig.s.Sources = append(rig.s.Sources, &memSource{name: "b", inv: b})
	if res := rig.sync(t); res.Outcome != "refused" || !strings.Contains(res.Reason,
		"device leaf-01 is in both source a and source b") {
		t.Fatalf("%+v", res)
	}
	// Counted though the sync was refused: every source was read.
	if testutil.ToFloat64(rig.s.Metrics.LeftOut) != 1 {
		t.Fatal("port49_inventory_devices_left_out is not 1")
	}
}

// Decided 10: a device that cannot reach a line safely is left out, said by
// position, and counted; the rest publishes.
func TestAnUnusableDeviceIsLeftOutAndSaidByPosition(t *testing.T) {
	inv := devices(3)
	inv.Devices[1].Name = "leaf\nINJECTED"
	rig := newSyncRig(t, syncPolicy, inv)
	res := rig.sync(t)
	if res.Outcome != "published" || len(res.LeftOut) != 1 || strings.Contains(rig.out.String(), "INJECTED") ||
		!strings.Contains(rig.out.String(), "left out: source a: device #1") {
		t.Fatalf("%+v %s", res, rig.out)
	}
	if testutil.ToFloat64(rig.s.Metrics.LeftOut) != 1 {
		t.Fatal("port49_inventory_devices_left_out is not 1")
	}
	// The document lists only NameOK names under sources, so port49d opens it.
	doc, _, err := bundle.Open(rig.s.Current().Raw, rig.pubs())
	if err != nil || !slices.Equal(doc.Sources["a"], []string{"leaf-01", "leaf-03"}) {
		t.Fatalf("%v %v", doc.Sources, err)
	}
}

// A restart serves what it published and continues the sequence; a lost
// state_dir continues from the mirror.
func TestARestartContinuesTheSequence(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	rig.sync(t)
	rig.src.inv = devices(4)
	rig.sync(t)
	again := rig.syncer(rig.s.Key)
	if err := again.Restore(); err != nil || again.Current().Doc.Sequence != 2 {
		t.Fatalf("%v %v", again.Current(), err)
	}
	os.RemoveAll(rig.s.State.Dir)
	lost := rig.syncer(rig.s.Key)
	if err := lost.Restore(); err != nil || lost.Current().Doc.Sequence != 2 {
		t.Fatalf("from the mirror: %v %v", lost.Current(), err)
	}
	rig.src.inv = devices(5)
	if res := lost.Sync(context.Background(), "startup"); res.Sequence != 3 {
		t.Fatalf("%+v", res)
	}
}

const unmappedPolicy = `
privilege_levels: [{name: readonly}, {name: operator}, {name: unmapped}, {name: admin}]
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: unmapped, permit: ["show **"]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: lab_key}]
`

// Spec §10: a sync the service's policy quarantines a device in publishes,
// and says which, with the cause.
func TestAQuarantinedDeviceIsPublishedAndSaid(t *testing.T) {
	rig := newSyncRig(t, unmappedPolicy, devices(1))
	res := rig.sync(t)
	if res.Outcome != "published" || len(res.Quarantined) != 1 || res.Quarantined[0].Device != "leaf-01" ||
		!strings.Contains(rig.out.String(), "device leaf-01 (arista_eos) is quarantined against the service's policy") {
		t.Fatalf("%+v %s", res, rig.out)
	}
}

// Restore takes the sync lock, so it is safe whenever it is called, not only
// before the first Sync (run under -race).
func TestRestoreIsSafeBesideASync(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	rig.sync(t)
	done := make(chan struct{})
	errs := make(chan error, 20)
	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			errs <- rig.s.Restore()
		}
	}()
	for i := 0; i < 20; i++ {
		rig.sync(t)
	}
	<-done
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// Review Important 1: with state_dir lost and a mirror that does not open
// (here a signing-key rotation without the old key in VerifyKeys), the
// service does not start again at bundle 1, unbounded, over the mirror's
// newer copy: it refuses to start, and the mirror stays.
func TestALostStateDirAndAMirrorThatDoesNotOpenRefuseTheStart(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(4))
	rig.sync(t)
	rig.src.inv.Devices[0].Addresses = append(rig.src.inv.Devices[0].Addresses, netip.MustParseAddr("10.9.0.1"))
	if res := rig.sync(t); res.Sequence != 2 {
		t.Fatalf("%+v", res)
	}
	before, _ := rig.s.State.MirrorRaw()
	if err := os.RemoveAll(rig.s.State.Dir); err != nil {
		t.Fatal(err)
	}
	_, newKey, _ := ed25519.GenerateKey(rand.Reader)
	rotated := rig.syncer(newKey)
	err := rotated.Restore()
	mirror := filepath.Join(rig.s.State.MirrorDir, "bundle.json")
	if err == nil || !strings.Contains(err.Error(), mirror) || !strings.Contains(err.Error(), "move it aside") {
		t.Fatalf("the start was not refused: %v", err)
	}
	if strings.Contains(err.Error(), "leaf-0") {
		t.Fatalf("the error quotes the copy: %v", err)
	}
	// Should the service start regardless, the 75% cut is published to
	// state_dir alone: the mirror's newer copy is never written over.
	rig.src.inv = devices(1)
	rotated.Sync(context.Background(), "startup")
	if after, _ := rig.s.State.MirrorRaw(); !bytes.Equal(before, after) {
		t.Fatal("the mirror's bundle 2 was written over")
	}
	if testutil.ToFloat64(rotated.Metrics.MirrorBehind) != 1 {
		t.Fatal("port49_inventory_mirror_behind is not 1")
	}
}

// A mirror that is not there at all is a fresh start, as before.
func TestNoCopyAnywhereIsAFreshStart(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(1))
	if err := rig.s.Restore(); err != nil || rig.s.Current() != nil {
		t.Fatalf("%v %v", rig.s.Current(), err)
	}
}

// A bundle the service could not keep is not published.
func TestAFailedSavePublishesNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a read-only directory")
	}
	rig := newSyncRig(t, syncPolicy, devices(3))
	rig.sync(t)
	if err := os.Chmod(rig.s.State.Dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(rig.s.State.Dir, 0o700) })
	rig.src.inv = devices(4)
	if res := rig.sync(t); res.Outcome != "failed" || res.Sequence != 1 || !strings.Contains(res.Reason, "state_dir") {
		t.Fatalf("%+v", res)
	}
	if rig.s.Current().Doc.Sequence != 1 || testutil.ToFloat64(rig.s.Metrics.Published) != 1 {
		t.Fatal("a bundle not kept was served")
	}
	if p, err := rig.s.State.Mirror(rig.pubs()); err != nil || p.Doc.Sequence != 1 {
		t.Fatalf("the mirror: %v %v", p, err)
	}
}

// A source that fails is not fetched again by another source's sync, and
// its fetch that failed never replaces its last good one.
func TestAFailingSourceKeepsItsLastFetchThroughAnotherSourcesSync(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(2))
	b := &memSource{name: "b", inv: admission.Inventory{Devices: []admission.Device{{Name: "leaf-b",
		Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("10.1.0.1")},
		Transport: admission.TransportTCP}}}}
	rig.s.Sources = append(rig.s.Sources, b)
	rig.sync(t)
	b.err = errors.New("dial tcp: connection refused")
	if res := rig.s.Sync(context.Background(), "schedule", "b"); res.Outcome != "failed" {
		t.Fatalf("%+v", res)
	}
	rig.src.inv = devices(3)
	res := rig.s.Sync(context.Background(), "schedule", "a")
	if res.Outcome != "published" || len(rig.s.Current().Inv.Devices) != 4 {
		t.Fatalf("%+v: %d devices, want a's three and b's one", res, len(rig.s.Current().Inv.Devices))
	}
}

// A device newly left out is said even when the bundle is unchanged, once.
func TestADeviceNewlyLeftOutIsSaidOnAnUnchangedSync(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	rig.sync(t)
	rig.src.inv.Devices = append(rig.src.inv.Devices, admission.Device{Name: "bad\tname", Platform: "arista_eos",
		Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.9")}, Transport: admission.TransportTCP})
	rig.out.Reset()
	for i := 0; i < 2; i++ {
		if res := rig.sync(t); res.Outcome != "unchanged" {
			t.Fatalf("%+v", res)
		}
	}
	if n := strings.Count(rig.out.String(), "port49-inventory: bundle 1: left out: source a: device #3"); n != 1 {
		t.Fatalf("said %d times: %q", n, rig.out)
	}
}

// Beside a good state_dir, a mirror that cannot be read does not stop the
// start: the mirror is a copy. It is said, and mirror_behind shows it.
func TestAGoodStateDirStartsBesideAnUnreadableMirror(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	rig.sync(t)
	mirror := filepath.Join(rig.s.State.MirrorDir, "bundle.json")
	if err := os.Remove(mirror); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(rig.dir, "policy.yaml"), mirror); err != nil {
		t.Fatal(err)
	}
	again := rig.syncer(rig.s.Key)
	rig.out.Reset()
	if err := again.Restore(); err != nil || again.Current() == nil || again.Current().Doc.Sequence != 1 {
		t.Fatalf("%v %v", again.Current(), err)
	}
	if testutil.ToFloat64(again.Metrics.MirrorBehind) != 1 {
		t.Fatal("port49_inventory_mirror_behind is not 1")
	}
	if n := strings.Count(rig.out.String(), "mirror_dir "+rig.s.State.MirrorDir+" holds a copy the service cannot open"); n != 1 {
		t.Fatalf("said %d times: %s", n, rig.out)
	}
	if strings.Contains(rig.out.String(), "scopes:") {
		t.Fatalf("the line quotes the file: %s", rig.out)
	}
}

// blockSource answers only when its ctx is done.
type blockSource struct{ name string }

func (b blockSource) Name() string { return b.name }
func (b blockSource) Fetch(ctx context.Context) (admission.Inventory, error) {
	<-ctx.Done()
	return admission.Inventory{}, fmt.Errorf("fetch: %w", ctx.Err())
}

// A sync its caller cancels, at shutdown, returns quietly: nothing failed
// that a line or a gauge should say, and the bundle published stands.
func TestASyncItsCallerCancelsIsQuiet(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	rig.sync(t)
	rig.s.Sources = []Source{blockSource{name: "a"}}
	rig.out.Reset()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	if res := rig.s.Sync(ctx, "schedule"); res.Outcome != OutcomeFailed || res.Sequence != 1 {
		t.Fatalf("%+v", res)
	}
	if rig.out.Len() != 0 {
		t.Fatalf("said: %s", rig.out)
	}
	if testutil.ToFloat64(rig.s.Metrics.SyncFailing) != 0 ||
		testutil.ToFloat64(rig.s.Metrics.Syncs.WithLabelValues("schedule", OutcomeFailed)) != 0 ||
		testutil.ToFloat64(rig.s.Metrics.SourceErrors.WithLabelValues("a")) != 0 {
		t.Fatal("a canceled sync was counted")
	}
	if cur := rig.s.Current(); cur == nil || cur.Doc.Sequence != 1 {
		t.Fatalf("the bundle published moved: %v", cur)
	}
}

// A source that runs past sync_timeout while its caller is live has failed,
// and says so.
func TestASyncPastItsOwnDeadlineIsAFailure(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(3))
	rig.sync(t)
	rig.s.Sources = []Source{blockSource{name: "a"}}
	rig.s.Timeout = 20 * time.Millisecond
	if res := rig.s.Sync(context.Background(), "schedule"); res.Outcome != OutcomeFailed || res.Sequence != 1 {
		t.Fatalf("%+v", res)
	}
	if !strings.Contains(rig.out.String(), "sync (schedule) failed; still publishing bundle 1: source a: fetch: "+
		"context deadline exceeded") {
		t.Fatalf("not said: %s", rig.out)
	}
	if testutil.ToFloat64(rig.s.Metrics.SyncFailing) != 1 {
		t.Fatal("port49_inventory_sync_failing is not 1")
	}
	if testutil.ToFloat64(rig.s.Metrics.SourceErrors.WithLabelValues("a")) != 1 {
		t.Fatal("port49_inventory_source_errors_total{source=a} is not 1")
	}
	if cur := rig.s.Current(); cur == nil || cur.Doc.Sequence != 1 {
		t.Fatalf("the bundle published moved: %v", cur)
	}
}
