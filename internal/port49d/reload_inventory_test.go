//go:build linux

package port49d

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/keyring"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// An inventory edit is loaded once two reads agree, as a policy edit is, and
// the swap is said in one line (spec §10, "Every swap logs a summary").
func TestAnInventoryEditIsLoadedOnceTwoReadsAgree(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.writeInventory(t, twoDevices)
	rig.with(func() { rig.r.poll(context.Background()) })
	if _, ok := rig.b.Policy.Load().Device("leaf2"); ok {
		t.Fatal("loaded on one read")
	}
	rig.with(func() { rig.r.poll(context.Background()) })
	if _, ok := rig.b.Policy.Load().Device("leaf2"); !ok {
		t.Fatalf("not loaded: %s", rig.out.String())
	}
	out := rig.out.String()
	if !strings.Contains(out, "port49d: inventory reloaded (inventory file changed): bundle ") ||
		!strings.Contains(out, "+1 device(s), -0, 1 changed") {
		t.Fatalf("the swap line: %s", out)
	}
	if n := testutil.ToFloat64(rig.m.InventoryReloads.WithLabelValues("applied")); n != 1 {
		t.Fatalf("applied = %v", n)
	}
	if testutil.ToFloat64(rig.m.PolicyRefreshPending) != 1 {
		t.Fatal("the swap did not open a settle pass")
	}
}

// Spec §10, bounded change: a snapshot that drops more than the configured
// share is refused and the bundle in force keeps serving; said once.
func TestAnInventoryThatDropsTooManyDevicesIsRefused(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.writeInventory(t, twoDevices)
	rig.pollTwice()
	serving := rig.b.Policy.Load().Bundle
	rig.writeInventory(t, "devices:\n  - {name: leaf1, platform: arista_eos, addresses: [10.0.0.1], key_ref: lab_key}\n")
	rig.pollTwice()
	rig.pollTwice()
	if _, ok := rig.b.Policy.Load().Device("leaf2"); !ok {
		t.Fatal("the over-shrinking inventory was applied")
	}
	out := rig.out.String()
	if strings.Count(out, "inventory reload (inventory file changed) refused; still serving bundle "+serving) != 1 ||
		!strings.Contains(out, "removes 1 of 2 devices and refuses 0 more (50%)") ||
		!strings.Contains(out, "raise inventory.max_removed_percent in port49d.yaml and send SIGHUP") {
		t.Fatalf("the refusal: %s", out)
	}
	if testutil.ToFloat64(rig.m.InventoryFileRefused) != 1 ||
		testutil.ToFloat64(rig.m.InventoryReloads.WithLabelValues("refused")) != 1 {
		t.Fatal("port49_inventory_file_refused is not 1, or the refusal was not counted once")
	}
	// I1, the operator's path, through the real reload: raise the bound in
	// port49d.yaml and send SIGHUP; nothing is set in memory.
	rig.sighupWithBound(t, 100)
	if _, ok := rig.b.Policy.Load().Device("leaf2"); ok {
		t.Fatalf("SIGHUP with the bound raised did not apply: %s", rig.out.String())
	}
	if testutil.ToFloat64(rig.m.InventoryFileRefused) != 0 {
		t.Fatal("port49_inventory_file_refused stayed 1")
	}
	if !strings.Contains(rig.out.String(), "inventory.max_removed_percent is now 100%") {
		t.Fatalf("the re-read bound was not said: %s", rig.out.String())
	}
}

// A port49d.yaml that does not read at SIGHUP keeps the bound in force, said:
// a typo is never the default, and never 100.
func TestABoundThatDoesNotReadKeepsTheBoundInForce(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.r.cfgPath = filepath.Join(t.TempDir(), "port49d.yaml")
	if err := os.WriteFile(rig.r.cfgPath, []byte("inventory: {max_removed_percnt: 100}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	if rig.r.cfg.MaxRemovedPercent != 10 ||
		!strings.Contains(rig.out.String(), "inventory.max_removed_percent not re-read from "+rig.r.cfgPath) ||
		!strings.Contains(rig.out.String(), "keeping 10%") {
		t.Fatalf("bound %d: %s", rig.r.cfg.MaxRemovedPercent, rig.out.String())
	}
}

// C2 on a reload: an inventory file others could write is refused once, the
// bundle in force keeps serving, and the alarm is set; put right, it loads.
func TestAnInventoryFileOthersCouldWriteIsRefusedAtAReload(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.writeInventory(t, twoDevices)
	if err := os.Chmod(rig.cfg.InventoryFile, 0o664); err != nil {
		t.Fatal(err)
	}
	rig.pollTwice()
	rig.pollTwice()
	if _, ok := rig.b.Policy.Load().Device("leaf2"); ok {
		t.Fatal("a group-writable inventory was applied")
	}
	if n := strings.Count(rig.out.String(), "inventory reload (inventory file changed) refused"); n != 1 ||
		testutil.ToFloat64(rig.m.InventoryFileRefused) != 1 || !strings.Contains(rig.out.String(), "writable by others") {
		t.Fatalf("said %d times: %s", n, rig.out.String())
	}
	// SIGHUP reads through the fence too.
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	if _, ok := rig.b.Policy.Load().Device("leaf2"); ok {
		t.Fatal("SIGHUP applied a group-writable inventory")
	}
	if err := os.Chmod(rig.cfg.InventoryFile, 0o600); err != nil {
		t.Fatal(err)
	}
	rig.pollTwice()
	if _, ok := rig.b.Policy.Load().Device("leaf2"); !ok {
		t.Fatalf("the file put right was not loaded: %s", rig.out.String())
	}
	if testutil.ToFloat64(rig.m.InventoryFileRefused) != 0 {
		t.Fatal("port49_inventory_file_refused stayed 1")
	}
}

// C2: a named pipe swapped in for the inventory after start is refused, never
// read: a poll or a SIGHUP that blocked on it would stop every reload and
// every refresh behind it.
func TestAnInventoryFIFOSwappedInAfterStartDoesNotHangTheReloader(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.writeInventory(t, twoDevices)
	rig.pollTwice()
	if err := os.Remove(rig.cfg.InventoryFile); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(rig.cfg.InventoryFile, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		rig.pollTwice()
		rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the reloader blocked on a named pipe")
	}
	if _, ok := rig.b.Policy.Load().Device("leaf2"); !ok || testutil.ToFloat64(rig.m.InventoryFileRefused) != 1 ||
		!strings.Contains(rig.out.String(), "is not a regular file") {
		t.Fatalf("stderr: %s", rig.out.String())
	}
}

// Admit-none, the inventory path: an inventory that admits no device is
// refused whatever the bound, and the line names stopping port49d as the
// deliberate path.
func TestAnInventoryThatAdmitsNoDeviceIsRefusedWhateverTheBound(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.writeInventory(t, twoDevices)
	rig.pollTwice()
	rig.writeInventory(t, withoutGroups) // unpinned, and the policy has no key group
	rig.sighupWithBound(t, 100)
	pol := rig.b.Policy.Load()
	if len(pol.AdmissionRefusals()) != 0 || len(pol.Devices()) != 2 {
		t.Fatalf("applied: refused %+v", pol.AdmissionRefusals())
	}
	out := rig.out.String()
	if !strings.Contains(out, "the new inventory admits none of the 2 device(s)") ||
		!strings.Contains(out, "stop port49d") || testutil.ToFloat64(rig.m.InventoryFileRefused) != 1 {
		t.Fatalf("the refusal: %s", out)
	}
}

// C3: the key-group move, in every order, never refuses the fleet. The
// inventory starts with the block and unpinned devices.

func migrationRig(t *testing.T) *reloadRig {
	t.Helper()
	rig := newReloadRig(t, minimalPolicy)
	rig.writeInventory(t, withGroups)
	rig.pollTwice()
	if len(rig.b.Policy.Load().AdmissionRefusals()) != 0 {
		t.Fatalf("the starting point refuses: %+v", rig.b.Policy.Load().AdmissionRefusals())
	}
	return rig
}

// restart is what a start makes of the files on disk now: the fenced read
// and the one load (fencedInventory, loadPolicy).
func (rig *reloadRig) restart(t *testing.T) error {
	t.Helper()
	cfg := rig.cfg
	inv, _, err := fencedInventory(cfg)
	if err != nil {
		return err
	}
	cfg.Inventory = inv
	pol, err := loadPolicy(cfg, "inventory_file "+cfg.InventoryFile)
	if err == nil && (len(pol.Devices()) != 2 || len(pol.AdmissionRefusals()) != 0) {
		return fmt.Errorf("%d devices, refused %+v", len(pol.Devices()), pol.AdmissionRefusals())
	}
	return err
}

func TestTheKeyGroupMoveInEveryOrder(t *testing.T) {
	admitsAll := func(t *testing.T, rig *reloadRig, when string) {
		t.Helper()
		pol := rig.b.Policy.Load()
		if len(pol.Devices()) != 2 || len(pol.AdmissionRefusals()) != 0 {
			t.Fatalf("%s: %d devices, refused %+v\n%s", when, len(pol.Devices()), pol.AdmissionRefusals(), rig.out.String())
		}
	}
	t.Run("policy first, as documented", func(t *testing.T) {
		rig := migrationRig(t)
		rig.write(t, policyWithGroups)
		rig.pollTwice()
		admitsAll(t, rig, "both files carry the block")
		if !strings.Contains(rig.out.String(), "is ignored, since the policy file has its own") {
			t.Fatalf("no notice: %s", rig.out.String())
		}
		// A restart here, mid-migration, loads the fleet.
		if err := rig.restart(t); err != nil {
			t.Fatalf("a restart mid-migration: %v", err)
		}
		rig.writeInventory(t, withoutGroups)
		rig.pollTwice()
		admitsAll(t, rig, "the move done")
		if err := rig.restart(t); err != nil {
			t.Fatalf("a restart after the move: %v", err)
		}
	})
	t.Run("inventory first", func(t *testing.T) {
		rig := migrationRig(t)
		rig.writeInventory(t, withoutGroups)
		rig.pollTwice()
		admitsAll(t, rig, "the refused step")
		if !strings.Contains(rig.out.String(), "add it to the policy file first") {
			t.Fatalf("the refusal does not name the order: %s", rig.out.String())
		}
		rig.write(t, policyWithGroups)
		rig.pollTwice()
		admitsAll(t, rig, "the policy then carries it")
		// The policy reload clears the inventory's refusal, so the edit
		// refused before is tried again, against the new policy, and loads.
		rig.pollTwice()
		if !strings.Contains(rig.out.String(), "port49d: inventory reloaded") {
			t.Fatalf("the refused inventory was not retried: %s", rig.out.String())
		}
		admitsAll(t, rig, "the move done")
		if testutil.ToFloat64(rig.m.InventoryFileRefused) != 0 {
			t.Fatal("port49_inventory_file_refused stayed 1")
		}
	})
	t.Run("inventory first, restarted before the policy edit", func(t *testing.T) {
		// The running daemon refused the edit and serves the fleet. A
		// restart now reads a bundle that admits no device, and a start
		// refuses that as a reload does (plan 6a Decided 5), naming the
		// order; the policy edit then starts it.
		rig := migrationRig(t)
		rig.writeInventory(t, withoutGroups)
		rig.pollTwice()
		admitsAll(t, rig, "the refused step")
		if err := rig.restart(t); err == nil || !strings.Contains(err.Error(), "add it to the policy file") {
			t.Fatalf("the start: %v", err)
		}
		rig.write(t, policyWithGroups)
		if err := rig.restart(t); err != nil {
			t.Fatalf("a restart with the policy edited: %v", err)
		}
	})
	t.Run("both edits, then SIGHUP", func(t *testing.T) {
		rig := migrationRig(t)
		rig.write(t, policyWithGroups)
		rig.writeInventory(t, withoutGroups)
		rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
		admitsAll(t, rig, "after SIGHUP")
	})
	t.Run("both edits, then the watch", func(t *testing.T) {
		rig := migrationRig(t)
		rig.write(t, policyWithGroups)
		rig.writeInventory(t, withoutGroups)
		rig.pollTwice()
		admitsAll(t, rig, "after the watch")
		if strings.Contains(rig.out.String(), "refused;") {
			t.Fatalf("a step was refused: %s", rig.out.String())
		}
	})
}

func TestAnEmptyOrMalformedInventoryIsRefused(t *testing.T) {
	for _, body := range []string{"devices: []\n", "devices: [\n",
		"devices:\n  - {name: a, addresses: [10.0.0.1]}\n  - {name: b, addresses: [10.0.0.1]}\n"} {
		rig := newReloadRig(t, minimalPolicy)
		rig.r.cfg.MaxRemovedPercent = 100
		rig.writeInventory(t, twoDevices)
		rig.pollTwice()
		rig.writeInventory(t, body)
		rig.pollTwice()
		if _, ok := rig.b.Policy.Load().Device("leaf2"); !ok {
			t.Fatalf("%q was applied", body)
		}
		if testutil.ToFloat64(rig.m.InventoryFileRefused) != 1 ||
			!strings.Contains(rig.out.String(), "inventory_file "+rig.cfg.InventoryFile) {
			t.Fatalf("%q: %s", body, rig.out.String())
		}
	}
}

// A device removed from inventory has its live contexts revoked by the
// refresh the swap runs (plan 4b's hand-off to plan 6), device_unknown's
// path. Its platform is the one the policy before knew (Task 11 M3): an EOS
// context is reached, so it is not counted as a session left until logout.
func TestAnInventoryReloadRevokesAContextOnARemovedDevice(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	k := rig.aliceLoggedIn(t)
	rig.r.cfg.MaxRemovedPercent = 100
	rig.writeInventory(t, "devices:\n  - {name: leaf2, platform: arista_eos, addresses: [10.0.0.2], key_ref: lab_key}\n")
	rig.pollTwice()
	c, err := rig.st.GetContext(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	if c.RevokedAt.IsZero() {
		t.Fatalf("the context on the removed leaf1 is live: %s", rig.out.String())
	}
	out := rig.out.String()
	if !strings.Contains(out, "1 revoked") || strings.Contains(out, "do not authorize commands") {
		t.Fatalf("the refresh line: %s", out)
	}
}

// N1, through the real policy reload: a key_groups typo that would refuse
// most of the fleet is refused, and every live session and unspent token
// survives; raising the bound and sending SIGHUP applies it.
func TestAKeyGroupsTypoCannotLogOutTheFleet(t *testing.T) {
	rig := newReloadRig(t, policyWithGroups)
	// leaf3 is pinned, so the typo leaves one device admitted: this is the
	// bound's refusal, not admit-none's.
	rig.writeInventory(t, withoutGroups+
		"  - {name: leaf3, platform: arista_eos, addresses: [10.0.0.3], key_ref: lab_key}\n")
	rig.r.cfg.MaxRemovedPercent = 100
	rig.pollTwice()
	rig.r.cfg.MaxRemovedPercent = 10
	if n := len(rig.b.Policy.Load().Devices()); n != 3 {
		t.Fatalf("%d devices: %s", n, rig.out.String())
	}
	k := rig.aliceLoggedIn(t)
	tk := store.TokenKey{NAS: "leaf1", Username: "alice"}
	if _, err := rig.st.PutToken(context.Background(), tk, store.Token{ID: "t1", Secret: []byte("p49_t1"),
		Kind: store.KindLogin, Principal: "user:alice@example.com", ExpiresAt: rig.now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	serving := rig.b.Policy.Load().Bundle
	rig.write(t, strings.Replace(policyWithGroups, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1))
	rig.pollTwice()
	rig.pollTwice()
	out := rig.out.String()
	if strings.Count(out, "policy reload (file changed) refused") != 1 ||
		!strings.Contains(out, "refuses admission to 2 of 3 devices") || !strings.Contains(out, "leaf1, leaf2") ||
		!strings.Contains(out, "(bundle "+serving+")") {
		t.Fatalf("the refusal: %s", out)
	}
	if testutil.ToFloat64(rig.m.PolicyFileRefused) != 1 {
		t.Fatal("port49_policy_file_refused is not 1")
	}
	if c, err := rig.st.GetContext(context.Background(), k); err != nil || !c.RevokedAt.IsZero() {
		t.Fatalf("the session was revoked: %+v, %v", c, err)
	}
	if toks, _ := rig.st.Candidates(context.Background(), tk); len(toks) != 1 {
		t.Fatalf("the token went: %d left", len(toks))
	}
	rig.sighupWithBound(t, 100)
	if len(rig.b.Policy.Load().AdmissionRefusals()) != 2 || testutil.ToFloat64(rig.m.PolicyFileRefused) != 0 {
		t.Fatalf("SIGHUP with the bound raised did not apply: %s", rig.out.String())
	}
	// Applied, the refusal takes the refused devices' sessions (Task 11).
	if c, _ := rig.st.GetContext(context.Background(), k); c.RevokedAt.IsZero() {
		t.Fatal("the session on the refused leaf1 is live")
	}
}

// Admit-none on port49-broker: the refusal's advice is its own, port49-broker.yaml
// and stopping every port49d, since it serves no device (Task 18).
func TestAPolicyThatAdmitsNoDeviceAdvisesPort49BrokerInItsOwnTerms(t *testing.T) {
	rig := newReloadRig(t, policyWithGroups)
	rig.r.proc = "port49-broker"
	rig.writeInventory(t, withoutGroups)
	rig.pollTwice()
	rig.write(t, strings.Replace(policyWithGroups, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1))
	rig.sighupWithBound(t, 100)
	out := rig.out.String()
	if !strings.Contains(out, "the new policy admits none of the 2 device(s)") ||
		!strings.Contains(out, "the key_refs port49-broker.yaml defines") ||
		!strings.Contains(out, "to take the whole fleet off deliberately, stop every port49d (port49-broker serves no device)") ||
		strings.Contains(out, "port49d.yaml") || strings.Contains(out, "stop port49d") {
		t.Fatalf("the refusal: %s", out)
	}
}

// Admit-none, the policy path: a policy that admits no device is refused
// whatever the bound, and the live sessions survive it.
func TestAPolicyThatAdmitsNoDeviceIsRefusedWhateverTheBound(t *testing.T) {
	rig := newReloadRig(t, policyWithGroups)
	rig.writeInventory(t, withoutGroups)
	rig.pollTwice()
	k := rig.aliceLoggedIn(t)
	rig.write(t, strings.Replace(policyWithGroups, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1))
	rig.sighupWithBound(t, 100)
	out := rig.out.String()
	// A start refuses it too, so the line does not say a restart would
	// load it unguarded.
	if !strings.Contains(out, "the new policy admits none of the 2 device(s)") || !strings.Contains(out, "stop port49d") ||
		strings.Contains(out, "a restart of port49d would load it") || testutil.ToFloat64(rig.m.PolicyFileRefused) != 1 {
		t.Fatalf("the refusal: %s", out)
	}
	if len(rig.b.Policy.Load().AdmissionRefusals()) != 0 {
		t.Fatal("applied")
	}
	if c, err := rig.st.GetContext(context.Background(), k); err != nil || !c.RevokedAt.IsZero() {
		t.Fatalf("the session was revoked: %+v, %v", c, err)
	}
}

// A policy edit refused against the inventory in force is tried again when
// an inventory edit loads, as a refused inventory is when a policy loads
// (C3): the order two files are edited in never leaves a good pair unloaded.
func TestARefusedPolicyIsRetriedAfterAnInventoryLoads(t *testing.T) {
	rig := migrationRig(t)
	// The policy's key group is where the devices are going: against the
	// inventory in force it admits none, so it is refused.
	moved := strings.Replace(policyWithGroups, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1)
	rig.write(t, moved)
	rig.pollTwice()
	if testutil.ToFloat64(rig.m.PolicyFileRefused) != 1 {
		t.Fatalf("setup: %s", rig.out.String())
	}
	// The devices move, carrying their own key group, which the policy in
	// force (no block) takes: it loads, and the policy is tried again.
	rig.writeInventory(t, strings.ReplaceAll(strings.ReplaceAll(withGroups, "10.0.0.0/8", "11.0.0.0/8"), "10.0.0.",
		"11.0.0."))
	rig.pollTwice()
	rig.pollTwice()
	pol := rig.b.Policy.Load()
	if pol.Source != engine.HashOf([]byte(moved)) || len(pol.AdmissionRefusals()) != 0 || len(pol.Devices()) != 2 ||
		testutil.ToFloat64(rig.m.PolicyFileRefused) != 0 {
		t.Fatalf("not both in force: %s", rig.out.String())
	}
}

// M5: every reload line names the bundle, not only the policy's hash.
func TestReloadLinesNameTheBundle(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	bundle := rig.b.Policy.Load().Bundle
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	if !strings.Contains(rig.out.String(), "unchanged, "+rig.b.Policy.Load().Source+" in force (bundle "+bundle+")") {
		t.Fatalf("unchanged: %s", rig.out.String())
	}
	rig.write(t, strings.Replace(minimalPolicy, "privilege: admin", "privilege: root", 1))
	rig.pollTwice()
	if !strings.Contains(rig.out.String(), "refused; still serving "+rig.b.Policy.Load().Source+" (bundle "+bundle+")") {
		t.Fatalf("refused: %s", rig.out.String())
	}
	for i := 0; i < stillChangingAfter; i++ {
		rig.write(t, fmt.Sprintf("# %d\n%s", i, minimalPolicy))
		rig.with(func() { rig.r.poll(context.Background()) })
	}
	if !strings.Contains(rig.out.String(), "not loaded; still serving "+rig.b.Policy.Load().Source+" (bundle "+bundle+")") {
		t.Fatalf("still changing: %s", rig.out.String())
	}
}

// port49_inventory_snapshot_age_seconds is the time since the inventory was
// last read and found in force, or loaded; a refused file does not reset it.
func TestTheInventorySnapshotAgeIsSinceTheLastGoodRead(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.now = rig.now.Add(90 * time.Second)
	if age := testutil.ToFloat64(rig.m.InventorySnapshotAge); age != 90 {
		t.Fatalf("age %v", age)
	}
	rig.with(func() { rig.r.poll(context.Background()) })
	if age := testutil.ToFloat64(rig.m.InventorySnapshotAge); age != 0 {
		t.Fatalf("a read of the file in force: age %v", age)
	}
	rig.writeInventory(t, "devices: [\n")
	rig.pollTwice()
	rig.now = rig.now.Add(time.Minute)
	if age := testutil.ToFloat64(rig.m.InventorySnapshotAge); age != 60 {
		t.Fatalf("a refused file: age %v", age)
	}
}

// The snapshot age is read at scrape, from another goroutine than the
// reloader's: run under -race.
func TestTheInventorySnapshotAgeIsReadAtScrapeWhileTheWatchRuns(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.writeInventory(t, twoDevices)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			testutil.ToFloat64(rig.m.InventorySnapshotAge)
		}
	}()
	for i := 0; i < 10; i++ {
		rig.pollTwice()
	}
	<-done
}

// The inventory's own lines name the bundle (M5): the same devices respelled
// are "unchanged", and a file that never settles is said once and alarmed.
func TestInventoryLinesNameTheBundle(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.writeInventory(t, twoDevices)
	rig.pollTwice()
	bundle := rig.b.Policy.Load().Bundle
	lines := strings.Split(strings.TrimSpace(twoDevices), "\n")
	rig.writeInventory(t, lines[0]+"\n"+lines[2]+"\n"+lines[1]+"\n")
	rig.pollTwice()
	if rig.b.Policy.Load().Bundle != bundle ||
		testutil.ToFloat64(rig.m.InventoryReloads.WithLabelValues("unchanged")) != 1 ||
		!strings.Contains(rig.out.String(), "the same inventory, respelled; bundle "+bundle+" in force") {
		t.Fatalf("respelled: %s", rig.out.String())
	}
	for i := 0; i < 2*stillChangingAfter; i++ {
		rig.writeInventory(t, fmt.Sprintf("# written %d\n%s", i, twoDevices))
		rig.with(func() { rig.r.poll(context.Background()) })
	}
	if n := strings.Count(rig.out.String(), "has changed at each of the last"); n != 1 ||
		!strings.Contains(rig.out.String(), "still serving bundle "+bundle) ||
		testutil.ToFloat64(rig.m.InventoryFileRefused) != 1 {
		t.Fatalf("said %d times: %s", n, rig.out.String())
	}
	rig.writeInventory(t, twoDevices)
	rig.with(func() { rig.r.poll(context.Background()) })
	rig.with(func() { rig.r.poll(context.Background()) })
	if testutil.ToFloat64(rig.m.InventoryFileRefused) != 0 {
		t.Fatalf("a file that settles clears the alarm: %s", rig.out.String())
	}
}

// Spec §10: an address added to a device already in inventory, and a device
// joining or leaving a security_log scope, are security events — one
// inventory_change record each, counted.
func TestASwapThatMovesPrivilegeIsLogged(t *testing.T) {
	watched := strings.Replace(minimalPolicy, "scopes: [{name: all_devices, match: {}}]",
		"scopes: [{name: all_devices, match: {}}, {name: watched, match: {name: [leaf2]}, security_log: true}]", 1)
	rig := newReloadRig(t, watched)
	var buf syncBuffer
	rig.b.Log = decision.NewJSONLines(&buf)
	rig.r.log = rig.b.Log // the reloader writes its inventory_change records here
	rig.writeInventory(t, twoDevices)
	rig.pollTwice()
	got := buf.String()
	for _, want := range []string{`"event":"inventory_change"`, `"kind":"address_added"`, `"address":"10.0.0.1"`,
		`"kind":"scope_joined"`, `"scope":"watched"`, `"name":"leaf2"`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
	if n := testutil.ToFloat64(rig.m.InventoryChanges.WithLabelValues("address_added")); n != 1 {
		t.Fatalf("address_added = %v", n)
	}
	if n := testutil.ToFloat64(rig.m.InventoryChanges.WithLabelValues("scope_joined")); n != 1 {
		t.Fatalf("scope_joined = %v", n)
	}
	// Exactly these, and leaf2 added and admitted: one record per change.
	if n := strings.Count(got, `"event":"inventory_change"`); n != 3 ||
		!strings.Contains(got, `"kind":"device_added"`) || !strings.Contains(got, `"to":"admitted"`) {
		t.Fatalf("%d records: %s", n, got)
	}
	bundle := rig.b.Policy.Load().Bundle
	if !strings.Contains(got, `"to_bundle":"`+bundle+`"`) {
		t.Fatalf("the records do not name the bundle swapped in, %s: %s", bundle, got)
	}
	if !strings.Contains(rig.out.String(), "port49d: inventory: 3 security change(s) written as inventory_change records") {
		t.Fatalf("the inventory swap does not say it wrote them: %s", rig.out.String())
	}
}

// A refused swap moved nothing, so it writes no inventory_change record: its
// refusal line and metric are what it says.
func TestARefusedSwapWritesNoInventoryChange(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.writeInventory(t, twoDevices)
	rig.pollTwice()
	var buf syncBuffer
	rig.b.Log = decision.NewJSONLines(&buf)
	rig.r.log = rig.b.Log // the reloader writes its inventory_change records here
	before := testutil.ToFloat64(rig.m.InventoryChanges.WithLabelValues("address_added"))
	// An address added to leaf1, in a file that drops half the fleet.
	rig.writeInventory(t, "devices:\n  - {name: leaf1, platform: arista_eos, addresses: [10.0.0.1, 10.0.0.9], "+
		"key_ref: lab_key}\n")
	rig.pollTwice()
	if testutil.ToFloat64(rig.m.InventoryReloads.WithLabelValues("refused")) != 1 {
		t.Fatalf("not refused: %s", rig.out.String())
	}
	if strings.Contains(buf.String(), "inventory_change") ||
		testutil.ToFloat64(rig.m.InventoryChanges.WithLabelValues("address_added")) != before {
		t.Fatalf("a refused swap was logged as a change: %s", buf.String())
	}
}

// A swap that moves no privilege — an attribute edited — writes no record.
func TestABenignSwapWritesNoInventoryChange(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.writeInventory(t, twoDevices)
	rig.pollTwice()
	var buf syncBuffer
	rig.b.Log = decision.NewJSONLines(&buf)
	rig.r.log = rig.b.Log // the reloader writes its inventory_change records here
	mark := len(rig.out.String())
	rig.writeInventory(t, strings.Replace(twoDevices, "addresses: [10.0.0.2],",
		"addresses: [10.0.0.2], attributes: {site: dc1},", 1))
	rig.pollTwice()
	if testutil.ToFloat64(rig.m.InventoryReloads.WithLabelValues("applied")) != 2 {
		t.Fatalf("the attribute edit was not applied: %s", rig.out.String())
	}
	if strings.Contains(buf.String(), "inventory_change") ||
		strings.Contains(rig.out.String()[mark:], "written as inventory_change records") {
		t.Fatalf("a benign swap was logged as a security change: %s%s", buf.String(), rig.out.String()[mark:])
	}
}

// A policy swap is a swap too: a device moved into a security_log scope by a
// policy edit is recorded as an inventory edit would be (spec §5.5, §10).
func TestAPolicySwapThatMovesPrivilegeIsLogged(t *testing.T) {
	watching := func(name string) string {
		return strings.Replace(minimalPolicy, "scopes: [{name: all_devices, match: {}}]",
			"scopes: [{name: all_devices, match: {}}, {name: watched, match: {name: ["+name+
				"]}, security_log: true}]", 1)
	}
	rig := newReloadRig(t, watching("leaf2"))
	rig.writeInventory(t, twoDevices)
	rig.pollTwice()
	var buf syncBuffer
	rig.b.Log = decision.NewJSONLines(&buf)
	rig.r.log = rig.b.Log // the reloader writes its inventory_change records here
	rig.write(t, watching("leaf1"))
	rig.pollTwice()
	got := buf.String()
	for _, want := range []string{`"kind":"scope_joined","scope":"watched"`, `"kind":"scope_left","scope":"watched"`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
	if n := strings.Count(got, `"event":"inventory_change"`); n != 2 {
		t.Fatalf("%d records: %s", n, got)
	}
	if n := testutil.ToFloat64(rig.m.InventoryChanges.WithLabelValues("scope_left")); n != 1 {
		t.Fatalf("scope_left = %v", n)
	}
	// The line names the file whose swap changed access: the policy file.
	if !strings.Contains(rig.out.String(), "port49d: policy: 2 security change(s) written as inventory_change records") {
		t.Fatalf("the policy swap's line does not name the policy file: %s", rig.out.String())
	}
}

// Task 12 m3: a named pipe put at port49d.yaml's path is refused at SIGHUP,
// never read: a reloader blocked on it would stop every poll and refresh,
// and SIGTERM would wait on it for good. The bound in force is kept, said.
func TestABoundReadFromANamedPipeKeepsTheBoundAndDoesNotHang(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.r.cfgPath = filepath.Join(t.TempDir(), "port49d.yaml")
	if err := syscall.Mkfifo(rig.r.cfgPath, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SIGHUP blocked on a named pipe at port49d.yaml's path")
	}
	out := rig.out.String()
	if rig.r.cfg.MaxRemovedPercent != 10 || strings.Count(out, "inventory.max_removed_percent not re-read") != 1 ||
		!strings.Contains(out, "is not a regular file") || !strings.Contains(out, "keeping 10%") {
		t.Fatalf("bound %d: %s", rig.r.cfg.MaxRemovedPercent, out)
	}
}

// A port49d.yaml past the size bound is not read into memory at SIGHUP.
func TestABoundReadFromAnOversizedFileKeepsTheBound(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.r.cfgPath = filepath.Join(t.TempDir(), "port49d.yaml")
	big := "inventory: {max_removed_percent: 100}\n" + strings.Repeat("#\n", config.MaxConfigSize)
	if err := os.WriteFile(rig.r.cfgPath, []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	if rig.r.cfg.MaxRemovedPercent != 10 || !strings.Contains(rig.out.String(), "larger than") {
		t.Fatalf("bound %d: %s", rig.r.cfg.MaxRemovedPercent, rig.out.String())
	}
}

// Task 12 m2: an operator who answers a refused inventory by putting back the
// one in force clears the alarm at the next poll, said once, with no swap.
// (SIGHUP skips an inventory whose version is the one in force, so on that
// path the alarm clears at the next poll, one interval later.)
func TestRevertingToTheInventoryInForceClearsTheAlarm(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.writeInventory(t, twoDevices)
	rig.pollTwice()
	serving := rig.b.Policy.Load().Bundle
	rig.writeInventory(t, "devices:\n  - {name: leaf1, platform: arista_eos, addresses: [10.0.0.1], key_ref: lab_key}\n")
	rig.pollTwice()
	if testutil.ToFloat64(rig.m.InventoryFileRefused) != 1 {
		t.Fatalf("the over-shrinking inventory was not refused: %s", rig.out.String())
	}
	rig.writeInventory(t, twoDevices)
	rig.with(func() { rig.r.poll(context.Background()) })
	if testutil.ToFloat64(rig.m.InventoryFileRefused) != 0 {
		t.Fatalf("the revert left port49_inventory_file_refused at 1: %s", rig.out.String())
	}
	rig.pollTwice()
	if n := strings.Count(rig.out.String(), "is the inventory in force again (bundle "+serving+")"); n != 1 {
		t.Fatalf("said %d times: %s", n, rig.out.String())
	}
	if rig.b.Policy.Load().Bundle != serving ||
		testutil.ToFloat64(rig.m.InventoryReloads.WithLabelValues("applied")) != 1 {
		t.Fatal("the revert swapped a bundle")
	}
}

// An inventory fault names the file once (final review m9).
func TestAnInventoryFaultNamesTheFileOnce(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.writeInventory(t, "devices:\n  - {name: leaf1, platform: arista_eos, addresses: [nope], key_ref: lab_key}\n")
	rig.pollTwice()
	out := rig.out.String()
	if !strings.Contains(out, "addresses[0] is not an IP address") || strings.Count(out, rig.cfg.InventoryFile) != 1 {
		t.Fatalf("stderr: %s", out)
	}
}

// Final review m6: a swap forgets a device the new bundle no longer admits
// under the key_ref it was seen on, in the key-version count and the packets
// held for keys diagnose.
func TestASwapForgetsWhatItNoLongerAdmits(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.writeInventory(t, twoDevices)
	rig.pollTwice()
	rig.r.seen, rig.r.held = &keyring.Seen{}, &keyring.Held{}
	for _, d := range []string{"leaf1", "leaf2"} {
		rig.r.seen.Mark(d, "lab_key", 1)
		rig.r.held.Put(d, netip.MustParseAddr("10.0.0.1"), wire.Header{}, []byte("x"), rig.now)
	}
	rig.writeInventory(t, "devices:\n  - {name: leaf1, platform: arista_eos, addresses: [10.0.0.1], key_ref: lab_key}\n")
	rig.sighupWithBound(t, 100)
	if _, ok := rig.b.Policy.Load().Device("leaf2"); ok {
		t.Fatalf("leaf2 was not removed: %s", rig.out.String())
	}
	if n := rig.r.seen.Count("lab_key", 1); n != 1 {
		t.Fatalf("key_version_devices counts %d; leaf2 is gone", n)
	}
	if _, ok := rig.r.held.Get("leaf2"); ok {
		t.Fatal("keys diagnose still answers for a removed device")
	}
	if _, ok := rig.r.held.Get("leaf1"); !ok {
		t.Fatal("a device still admitted lost its held packet")
	}
}
