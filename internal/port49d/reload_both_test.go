package port49d

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
//
// The bundle stays because this policy alone admits none, so it is refused
// alone too. A policy that passed alone would apply alone here, and that is
// right as well: with the document unopenable there is no inventory to pair
// it with, so the SIGHUP is two separate loads, not a half-applied pair.
func TestACombinedSIGHUPThatRemovesTheSignerAppliesNeither(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	rig.receive(rig.doc(t, 1, groupedPolicy, 2))
	rig.receive(rig.doc(t, 2, groupedPolicy, 0, deviceAt("leaf1", "11.0.0.1"), deviceAt("leaf2", "11.0.0.2")))
	serving := rig.b.Policy.Load().Bundle
	rig.write(t, strings.Replace(groupedPolicy, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1))
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPEM, err := keyfile.EncodeEd25519(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(safeDir(t), "other.pub")
	if err := os.WriteFile(keyFile, otherPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	rig.r.cfgPath = filepath.Join(t.TempDir(), "port49d.yaml")
	if err := os.WriteFile(rig.r.cfgPath, []byte(fmt.Sprintf(`inventory:
  service: {url: "https://inv.test:8443", ca_file: /x, tls_cert_file: /x, tls_key_file: /x,
            state_dir: /x, verify_key_files: [%s]}
`, keyFile)), 0o600); err != nil {
		t.Fatal(err)
	}
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

// Review I1: a policy that does not parse is its own fault, said alone with
// its own text; an inventory edit on the watch at the same time is not held
// up or alarmed by it, and putting the policy back clears the policy's alarm
// and leaves the inventory in force.
func TestAPolicyTypoDoesNotHoldUpAGoodInventoryEdit(t *testing.T) {
	rig := newReloadRig(t, policyWithGroups)
	rig.writeInventory(t, withoutGroups)
	rig.pollTwice()
	rig.write(t, policyWithGroups+"this is: [not valid\n")
	rig.writeInventory(t, withoutGroups+"  - {name: leaf3, platform: arista_eos, addresses: [10.0.0.3]}\n")
	rig.pollTwice()
	rig.pollTwice()
	out := rig.out.String()
	if !strings.Contains(out, "port49d: policy reload (file changed) refused") || !strings.Contains(out, "yaml") ||
		strings.Contains(out, "refused together") {
		t.Fatalf("the policy's fault is not said alone: %s", out)
	}
	if _, ok := rig.b.Policy.Load().Device("leaf3"); !ok || testutil.ToFloat64(rig.m.InventoryFileRefused) != 0 ||
		testutil.ToFloat64(rig.m.PolicyFileRefused) != 1 {
		t.Fatalf("the inventory edit was held up: %s", out)
	}
	rig.write(t, policyWithGroups)
	rig.pollTwice()
	if !strings.Contains(rig.out.String(), "is the policy in force again") ||
		testutil.ToFloat64(rig.m.PolicyFileRefused) != 0 || testutil.ToFloat64(rig.m.InventoryFileRefused) != 0 {
		t.Fatalf("%s", rig.out.String())
	}
	if _, ok := rig.b.Policy.Load().Device("leaf3"); !ok {
		t.Fatal("leaf3 left")
	}
}

// Review I1 and I3: a typo in the policy half of a whole-fleet re-address.
// The typo is said alone; the inventory, refused alone for what it admits,
// is refused on its own terms, not together with a policy that cannot load.
// Fixing the policy then loads both, together.
func TestFixingAPolicyTypoLoadsTheReAddressTogether(t *testing.T) {
	rig := newReloadRig(t, policyWithGroups)
	rig.writeInventory(t, withoutGroups)
	rig.pollTwice()
	moved := strings.Replace(policyWithGroups, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1)
	rig.write(t, moved+"this is: [not valid\n")
	rig.writeInventory(t, strings.ReplaceAll(withoutGroups, "10.0.0.", "11.0.0."))
	rig.pollTwice()
	rig.pollTwice()
	out := rig.out.String()
	if strings.Contains(out, "refused together") || !strings.Contains(out, "port49d: policy reload (file changed) refused") ||
		!strings.Contains(out, "port49d: inventory reload (inventory file changed) refused") {
		t.Fatalf("%s", out)
	}
	rig.write(t, moved)
	rig.pollTwice()
	if !strings.Contains(rig.out.String(), "port49d: policy and inventory reloaded together (file changed)") ||
		testutil.ToFloat64(rig.m.PolicyFileRefused) != 0 || testutil.ToFloat64(rig.m.InventoryFileRefused) != 0 {
		t.Fatalf("%s", rig.out.String())
	}
	if d, ok := rig.b.Policy.Load().Device("leaf1"); !ok || d.Addresses[0].String() != "11.0.0.1" ||
		len(rig.b.Policy.Load().AdmissionRefusals()) != 0 {
		t.Fatalf("not applied: %s", rig.out.String())
	}
}

// Review I2: a policy file someone else could write is refused with the
// fence's own words, and an inventory edit pending at the time is not
// refused with it.
func TestAnUnreadablePolicyIsSaidWithItsOwnFault(t *testing.T) {
	rig := newReloadRig(t, policyWithGroups)
	rig.writeInventory(t, withoutGroups)
	rig.pollTwice()
	rig.write(t, strings.Replace(policyWithGroups, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1))
	if err := os.Chmod(rig.cfg.Broker.PolicyFile, 0o666); err != nil {
		t.Fatal(err)
	}
	rig.writeInventory(t, withoutGroups+"  - {name: leaf3, platform: arista_eos, addresses: [10.0.0.3]}\n")
	rig.pollTwice()
	rig.pollTwice()
	out := rig.out.String()
	if !strings.Contains(out, "chmod go-w") || strings.Contains(out, "refused together") ||
		strings.Contains(out, "declares no subjects") {
		t.Fatalf("the fence's fault is not the one said: %s", out)
	}
	if _, ok := rig.b.Policy.Load().Device("leaf3"); !ok || testutil.ToFloat64(rig.m.InventoryFileRefused) != 0 {
		t.Fatalf("the inventory edit was refused with it: %s", out)
	}
}

// Review I1: a combined try the policy's load asked for, refused, leaves an
// inventory edit the watch has only seen pending — no alarm — to be tried
// alone at its turn; that try, refused with the same policy, is not said a
// second time.
func TestACombinedRefusalLeavesAPendingInventoryPending(t *testing.T) {
	rig := newReloadRig(t, policyWithGroups)
	rig.writeInventory(t, withoutGroups)
	rig.pollTwice()
	rig.write(t, strings.Replace(policyWithGroups, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1))
	rig.writeInventory(t, "devices:\n  - {name: leaf1, platform: arista_eos, addresses: [11.0.0.1]}\n")
	ctx := context.Background()
	rig.with(func() {
		rig.r.pollInventory(ctx)
		rig.r.pollPolicy(ctx)
		rig.r.pollPolicy(ctx)
	})
	if !strings.Contains(rig.out.String(), "refused together") || rig.r.invRefused != "" || rig.r.invPending == "" ||
		testutil.ToFloat64(rig.m.InventoryFileRefused) != 0 || testutil.ToFloat64(rig.m.PolicyFileRefused) != 1 {
		t.Fatalf("the pending inventory was marked refused: %s", rig.out.String())
	}
	rig.with(func() { rig.r.pollInventory(ctx) })
	if strings.Count(rig.out.String(), "refused together") != 1 || testutil.ToFloat64(rig.m.InventoryFileRefused) != 1 {
		t.Fatalf("%s", rig.out.String())
	}
}

// Review I3 (service mode): a document refused against the policy in force
// is tried again, opened under the keys in force, when a policy that admits
// it loads alone.
func TestARefusedDocumentIsRetriedWhenAPolicyThatAdmitsItLoads(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	rig.receive(rig.doc(t, 1, groupedPolicy, 2))
	readdressed := rig.doc(t, 2, groupedPolicy, 0, deviceAt("leaf1", "11.0.0.1"), deviceAt("leaf2", "11.0.0.2"))
	rig.receive(readdressed)
	if testutil.ToFloat64(rig.m.InventoryBundleRefused) != 1 {
		t.Fatalf("setup: %s", rig.out.String())
	}
	rig.write(t, strings.Replace(groupedPolicy, "key_groups: [", "key_groups: [{match: {cidr: 11.0.0.0/8}, key_ref: lab_key}, ", 1))
	rig.pollTwice()
	out := rig.out.String()
	if !strings.Contains(out, "port49d: policy reloaded (file changed)") || strings.Contains(out, "together") ||
		!strings.Contains(out, "port49d: inventory reloaded (file changed, bundle 2)") {
		t.Fatalf("%s", out)
	}
	if rig.r.inForce != readdressed.etag || testutil.ToFloat64(rig.m.InventoryBundleRefused) != 0 ||
		len(rig.b.Policy.Load().AdmissionRefusals()) != 0 {
		t.Fatalf("not applied: %s", out)
	}
}

// Fix-wave re-review: the combined SIGHUP refuses the document held with the
// policy edit, and the fetch that SIGHUP asks for brings the same document
// back whole; refused again under the same keys, policy and bound, it is
// counted once, as the separate path counts it (final review Minor 6).
func TestACombinedSIGHUPCountsARefusedDocumentOnce(t *testing.T) {
	rig := newServiceRig(t, groupedPolicy)
	rig.receive(rig.doc(t, 1, groupedPolicy, 2))
	readdressed := rig.doc(t, 2, groupedPolicy, 0, deviceAt("leaf1", "11.0.0.1"), deviceAt("leaf2", "11.0.0.2"))
	rig.receive(readdressed)
	// The policy moves its key group, but not to where the fleet went.
	rig.write(t, strings.Replace(groupedPolicy, "cidr: 10.0.0.0/8", "cidr: 12.0.0.0/8", 1))
	before := testutil.ToFloat64(rig.m.InventoryReloads.WithLabelValues("refused"))
	rig.sighupWithBound(t, 10)
	rig.receive(readdressed) // the poke's fetch: the same bytes, whole
	if !strings.Contains(rig.out.String(), "port49d: policy and inventory reload (SIGHUP) refused together") {
		t.Fatalf("the fixture's SIGHUP did not take the combined path: %s", rig.out.String())
	}
	if n := testutil.ToFloat64(rig.m.InventoryReloads.WithLabelValues("refused")) - before; n != 1 {
		t.Fatalf("a combined SIGHUP counted the document held %v times", n)
	}
}

// dcUnmapped lands every device in the dc scope at a level no built-in
// platform renders, so it quarantines each, and the rest of the fleet reads.
const dcUnmapped = unmappedLevel + `
scopes: [{name: all_devices, match: {}}, {name: dc, match: {site: dc1}}]
roles: [{name: ro, privilege: readonly, permit: [show **]}, {name: u, privilege: unmapped, permit: ["**"]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [ro]}, {subject: s, scope: dc, roles: [u]}]
key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: lab_key}]
` + runKeys

// A combined reload is bounded on what its policy does (task 10 review I1):
// the same policy text, a comment added, with an inventory that moves leaf1
// into the capped scope, applies and quarantines leaf1, as the inventory
// alone would (decision 20). A policy that caps the scope the inventory
// moves leaf1 into is the policy's doing: refused together, the line naming
// the policy file and saying both refused files would load at a restart.
func TestACombinedReloadIsBoundedOnThePolicysEffect(t *testing.T) {
	moved := strings.Replace(withoutGroups, "addresses: [10.0.0.1]}", "addresses: [10.0.0.1], attributes: {site: dc1}}", 1)
	rig := newReloadRig(t, dcUnmapped)
	rig.writeInventory(t, withoutGroups)
	rig.pollTwice()
	rig.write(t, dcUnmapped+"# the same policy\n")
	rig.writeInventory(t, moved)
	rig.sighupWithBound(t, 10)
	if out := rig.out.String(); !strings.Contains(out, "port49d: policy and inventory reloaded together (SIGHUP)") {
		t.Fatalf("the inventory's quarantine refused the pair: %s", out)
	}
	if _, q := rig.b.Policy.Load().Quarantined("leaf1", rig.now); !q {
		t.Fatal("leaf1 is not quarantined")
	}

	rig = newReloadRig(t, strings.Replace(dcUnmapped, "scope: dc, roles: [u]}", "scope: dc, roles: [ro]}", 1))
	rig.writeInventory(t, withoutGroups)
	rig.pollTwice()
	serving := rig.b.Policy.Load().Bundle
	rig.write(t, dcUnmapped)
	rig.writeInventory(t, moved)
	rig.sighupWithBound(t, 10)
	out := rig.out.String()
	if !strings.Contains(out, "refused together") || !strings.Contains(out, "broker.policy_file ") ||
		!strings.Contains(out, "it quarantines 1: leaf1") ||
		!strings.Contains(out, "the refused files are still on disk and are NOT what is serving") ||
		rig.b.Policy.Load().Bundle != serving {
		t.Fatalf("the policy's quarantine: %s", out)
	}
}
