package port49d

import (
	"context"
	"crypto/ed25519"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/bundle"
)

// sealedDocOn is sealedDocAt with its n devices on first.0.0.i, so a test can
// put a fleet where the policy's key groups do not reach it.
func sealedDocOn(t *testing.T, key ed25519.PrivateKey, seq int64, n int, at time.Time, first byte) []byte {
	t.Helper()
	var inv admission.Inventory
	for i := 1; i <= n; i++ {
		inv.Devices = append(inv.Devices, admission.Device{Name: "leaf" + string(rune('0'+i)), Platform: "arista_eos",
			Addresses: []netip.Addr{netip.AddrFrom4([4]byte{first, 0, 0, byte(i)})}, Transport: admission.TransportTCP})
	}
	raw, err := bundle.Seal(bundle.NewDocument(seq, at, []byte(minimalPolicy), "1.1.0", inv, nil), key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// runToListening runs port49d on cfgPath until it says it is listening, and
// fails the test if run returns first: a start that exits is the crash loop
// these tests guard against. stop ends it.
func runToListening(t *testing.T, cfgPath string, out *syncBuffer) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(out.String(), "port49d: listening on") {
		select {
		case err := <-done:
			cancel()
			t.Fatalf("port49d exited at start: %v\n%s", err, out.String())
		case <-time.After(20 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("not listening: %s", out.String())
		}
	}
	return func() { cancel(); <-done }
}

// Final review I2: a restart in the re-address window — the source of truth
// moved the fleet, the mirror holds that bundle, and the policy that admits
// the new addresses has not reached this port49d — starts from the persisted
// copy, which the policy admits, and leaves it on disk, so the next restart
// does the same rather than crash-looping on the mirror's copy.
func TestARestartInTheReAddressWindowStartsFromThePersistedCopy(t *testing.T) {
	var log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stdout = &log
	b := brokerConfig(t, minimalPolicy+"key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: k}]\n").Broker
	svc, key, keys := coldRig(t)
	svc.URL = "https://127.0.0.1:1"
	mustPersist(t, svc.StateDir, sealedDocAt(t, key, 7, 2, time.Now().Add(-time.Hour)))
	mustMirror(t, svc.MirrorDir, sealedDocOn(t, key, 8, 2, time.Now(), 192))
	cfgPath := writeServiceRunConfig(t, b, svc, "", keyPath(t, key))
	for restart := 1; restart <= 2; restart++ {
		var out syncBuffer
		stderr = &out
		stop := runToListening(t, cfgPath, &out)
		stop()
		if !strings.Contains(out.String(), "port49d: inventory: starting from bundle 7 (the persisted copy)") ||
			!strings.Contains(out.String(), "port49d: inventory: the mirror's copy, bundle 8, is not taken: ") {
			t.Fatalf("restart %d: %s", restart, out.String())
		}
		if p, err := readPersisted(svc.StateDir, keys); err != nil || seqOf(p) != 7 {
			t.Fatalf("restart %d: the persisted copy is bundle %d (%v), want 7", restart, seqOf(p), err)
		}
	}
}

// Final review I2: the newer copy the policy refuses is passed over, said,
// and the other copy starts; only a copy the policy and the broker accepted
// is persisted.
func TestAStartFallsBackToTheOtherCopyWhenThePolicyRefusesTheNewer(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	b := brokerConfig(t, minimalPolicy+"key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: k}]\n").Broker
	svc, key, keys := coldRig(t)
	svc.URL = "https://127.0.0.1:1"
	mustPersist(t, svc.StateDir, sealedDocOn(t, key, 9, 2, time.Now(), 192))
	mustMirror(t, svc.MirrorDir, sealedDocAt(t, key, 8, 2, time.Now().Add(-time.Hour)))
	cfgPath := writeServiceRunConfig(t, b, svc, "", keyPath(t, key))
	stop := runToListening(t, cfgPath, &out)
	stop()
	if !strings.Contains(out.String(), "port49d: inventory: the persisted copy, bundle 9, is not taken: broker.policy_file ") ||
		!strings.Contains(out.String(), "admits none of the 2 device(s)") ||
		!strings.Contains(out.String(), "port49d: inventory: starting from bundle 8 (the mirror's copy)") {
		t.Fatalf("%s", out.String())
	}
	if p, err := readPersisted(svc.StateDir, keys); err != nil || seqOf(p) != 8 {
		t.Fatalf("the persisted copy is bundle %d (%v), want the mirror's 8 once the policy took it", seqOf(p), err)
	}
}

// Final review I2: a start from the mirror's copy is bounded by port49d's
// own inventory.max_removed_percent against the persisted copy, as a pulled
// document is.
func TestTheMirrorsCopyIsBoundedAgainstThePersistedCopyAtStart(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	b := brokerConfig(t, minimalPolicy+"key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: k}]\n").Broker
	svc, key, keys := coldRig(t)
	svc.URL = "https://127.0.0.1:1"
	mustPersist(t, svc.StateDir, sealedDocAt(t, key, 7, 9, time.Now().Add(-time.Hour)))
	mustMirror(t, svc.MirrorDir, sealedDocAt(t, key, 8, 1, time.Now()))
	cfgPath := writeServiceRunConfig(t, b, svc, "", keyPath(t, key))
	stop := runToListening(t, cfgPath, &out)
	stop()
	if !strings.Contains(out.String(), "port49d: inventory: the mirror's copy, bundle 8, is not taken: the new "+
		"inventory removes 8 of 9 devices") ||
		!strings.Contains(out.String(), "port49d: inventory: starting from bundle 7 (the persisted copy)") {
		t.Fatalf("%s", out.String())
	}
	if p, err := readPersisted(svc.StateDir, keys); err != nil || seqOf(p) != 7 {
		t.Fatalf("the persisted copy is bundle %d (%v), want 7", seqOf(p), err)
	}
}
