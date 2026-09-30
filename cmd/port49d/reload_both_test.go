package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/keyfile"
)

// deviceAt is an arista_eos device on TCP at addr, for a document's extra
// devices.
func deviceAt(name, addr string) admission.Device {
	return admission.Device{Name: name, Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr(addr)},
		Transport: admission.TransportTCP}
}

// A whole-fleet re-address with its key group: each file alone admits none,
// so each alone is refused; together they load, as one swap, and alice's
// session survives it.
func TestAWholeFleetReAddressLoadsTogetherAtSIGHUP(t *testing.T) {
	rig := newReloadRig(t, policyWithGroups)
	rig.writeInventory(t, withoutGroups)
	rig.pollTwice()
	k := rig.aliceLoggedIn(t)
	rig.write(t, strings.Replace(policyWithGroups, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1))
	rig.writeInventory(t, strings.ReplaceAll(withoutGroups, "10.0.0.", "11.0.0."))
	rig.sighupWithBound(t, 10)
	out := rig.out.String()
	// Every swap line ends "… N refused admission"; the refusal forms are what
	// must be absent (conflict scan F3).
	if !strings.Contains(out, "port49d: policy and inventory reloaded together (SIGHUP)") ||
		strings.Contains(out, " refused; ") || strings.Contains(out, "refused together") {
		t.Fatalf("%s", out)
	}
	if d, ok := rig.b.Policy.Load().Device("leaf1"); !ok || d.Addresses[0].String() != "11.0.0.1" ||
		len(rig.b.Policy.Load().AdmissionRefusals()) != 0 {
		t.Fatalf("not applied: %+v", d)
	}
	if c, err := rig.st.GetContext(context.Background(), k); err != nil || !c.RevokedAt.IsZero() {
		t.Fatalf("the session was revoked: %+v, %v", c, err)
	}
}

// The watch finds the same: the policy settles, alone it is refused, and the
// inventory the last poll agreed on is tried with it.
func TestAWholeFleetReAddressLoadsTogetherFromTheWatch(t *testing.T) {
	rig := newReloadRig(t, policyWithGroups)
	rig.writeInventory(t, withoutGroups)
	rig.pollTwice()
	rig.write(t, strings.Replace(policyWithGroups, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1))
	rig.writeInventory(t, strings.ReplaceAll(withoutGroups, "10.0.0.", "11.0.0."))
	rig.pollTwice()
	rig.pollTwice()
	if !strings.Contains(rig.out.String(), "port49d: policy and inventory reloaded together (file changed)") ||
		len(rig.b.Policy.Load().AdmissionRefusals()) != 0 {
		t.Fatalf("%s", rig.out.String())
	}
}

// Together over the bound: neither applies, one line names both, both alarms
// are up.
func TestBothRefusedTogetherApplyNeither(t *testing.T) {
	rig := newReloadRig(t, policyWithGroups)
	rig.writeInventory(t, withoutGroups)
	rig.pollTwice()
	serving := rig.b.Policy.Load().Bundle
	rig.write(t, strings.Replace(policyWithGroups, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1))
	rig.writeInventory(t, "devices:\n  - {name: leaf1, platform: arista_eos, addresses: [11.0.0.1]}\n")
	rig.sighupWithBound(t, 10)
	out := rig.out.String()
	if !strings.Contains(out, "port49d: policy and inventory reload (SIGHUP) refused together; still serving") ||
		!strings.Contains(out, "removes 1 of 2 devices") || rig.b.Policy.Load().Bundle != serving {
		t.Fatalf("%s", out)
	}
	if testutil.ToFloat64(rig.m.PolicyFileRefused) != 1 || testutil.ToFloat64(rig.m.InventoryFileRefused) != 1 {
		t.Fatal("both alarms are not up")
	}
}

// Service mode: a re-addressed document refused alone loads with the policy
// edit that goes with it.
func TestAReAddressFromTheServiceLoadsWithThePolicy(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	rig.receive(rig.doc(t, 1, groupedPolicy, 2))
	readdressed := rig.doc(t, 2, groupedPolicy, 0, deviceAt("leaf1", "11.0.0.1"), deviceAt("leaf2", "11.0.0.2"))
	rig.receive(readdressed)
	if !strings.Contains(rig.out.String(), "inventory reload (inventory service, bundle 2) refused") {
		t.Fatalf("alone it should be refused: %s", rig.out.String())
	}
	rig.write(t, strings.Replace(groupedPolicy, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1))
	rig.pollTwice()
	if !strings.Contains(rig.out.String(), "port49d: policy and inventory reloaded together") ||
		len(rig.b.Policy.Load().AdmissionRefusals()) != 0 {
		t.Fatalf("%s", rig.out.String())
	}
	if rig.r.inForce != readdressed.etag || rig.r.seq != 2 || !rig.r.inForceAt.Equal(readdressed.pub.Doc.PublishedAt) ||
		testutil.ToFloat64(rig.m.InventoryBundleRefused) != 0 {
		t.Fatalf("the document in force is not the one applied: seq %d", rig.r.seq)
	}
}

// Task 15 review, ruling 1, on the combined path: the document held is
// opened again under the keys this SIGHUP put in force, so a SIGHUP that
// removes its signer while the policy edit that goes with it is on disk
// applies neither, and the bundle in force keeps serving.
func TestACombinedSIGHUPThatRemovesTheSignerAppliesNeither(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	rig.receive(rig.doc(t, 1, groupedPolicy, 2))
	rig.receive(rig.doc(t, 2, groupedPolicy, 0, deviceAt("leaf1", "11.0.0.1"), deviceAt("leaf2", "11.0.0.2")))
	serving := rig.b.Policy.Load().Bundle
	rig.write(t, strings.Replace(groupedPolicy, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1))
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPEM, _ := keyfile.EncodeEd25519(otherKey)
	keyFile := filepath.Join(safeDir(t), "other.pub")
	os.WriteFile(keyFile, otherPEM, 0o644)
	rig.r.cfgPath = filepath.Join(t.TempDir(), "port49d.yaml")
	os.WriteFile(rig.r.cfgPath, []byte(fmt.Sprintf(`inventory:
  service: {url: "https://inv.test:8443", ca_file: /x, tls_cert_file: /x, tls_key_file: /x,
            state_dir: /x, verify_key_files: [%s]}
`, keyFile)), 0o600)
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	out := rig.out.String()
	if rig.b.Policy.Load().Bundle != serving || rig.r.seq != 1 || strings.Contains(out, "reloaded together") {
		t.Fatalf("the document signed by the removed key was applied: %s", out)
	}
	if !strings.Contains(out, "inventory reload (SIGHUP) refused") || !strings.Contains(out, "which no verify key holds") ||
		testutil.ToFloat64(rig.m.InventoryBundleRefused) != 1 || testutil.ToFloat64(rig.m.PolicyFileRefused) != 1 {
		t.Fatalf("%s", out)
	}
}
