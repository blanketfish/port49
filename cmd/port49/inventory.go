package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/policy"
)

func inventoryCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "diff" {
		return inventoryDiff(args[1:], stdout, stderr)
	}
	fmt.Fprint(stderr, usage)
	return 2
}

// inventoryDiff is `port49 inventory diff` (spec §10, §12): what a change to
// the inventory does to the bundle — devices, addresses, keys, admission and
// scope membership, the security lines marked `!` as port49d writes them
// inventory_change records — and whether port49d would load it, by the
// checks its reload runs (bundle.Check; with --new-policy,
// bundle.CheckAdmission for the policy's reload too).
func inventoryDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 inventory diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	polPath := fs.String("policy", "", "the policy the old inventory is loaded against")
	newPol := fs.String("new-policy", "", "the policy the new one is loaded against (default: --policy)")
	maxRemoved := fs.Int("max-removed-percent", 10, "port49d.yaml's inventory.max_removed_percent")
	cfgPath := fs.String("config", "", "port49d.yaml: the key_refs it defines and inventory.max_removed_percent, "+
		"as port49d reads them; no secret is read")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *polPath == "" || fs.NArg() != 2 || *maxRemoved < 0 || *maxRemoved > 100 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	if *cfgPath != "" && flagSet(fs, "max-removed-percent") {
		fmt.Fprintln(stderr, "port49 inventory diff: --config sets the bound from inventory.max_removed_percent; "+
			"give one or the other")
		return 2
	}
	if *newPol == "" {
		*newPol = *polPath
	}
	// Without --config every key_ref is read as defined, as an offline load
	// does; with it, a device assigned a key port49d.yaml does not define is
	// refused, as port49d refuses it.
	var refs []string
	bound := *maxRemoved
	if *cfgPath != "" {
		raw, err := os.ReadFile(*cfgPath)
		if err != nil {
			fmt.Fprintln(stderr, "port49 inventory diff:", err)
			return 1
		}
		sets, err := config.KeySets(raw)
		if err == nil {
			bound, err = config.InventoryBound(raw)
		}
		if err != nil {
			fmt.Fprintf(stderr, "port49 inventory diff: %s: %v\n", *cfgPath, err)
			return 1
		}
		refs = keyRefsOf(sets)
	}
	env := policy.Env{KeyRefs: refs}
	oldInv, newInv := fs.Arg(0), fs.Arg(1)
	old, err := bundle.Load(*polPath, oldInv, env)
	if err != nil {
		fmt.Fprintln(stderr, "port49 inventory diff: the bundle in force (--policy, OLD_INVENTORY):", loadFault(err))
		return 1
	}
	new, err := bundle.Load(*newPol, newInv, env)
	if err != nil {
		fmt.Fprintf(stdout, "refused: port49d would not load the new inventory: %s\n", loadFault(err))
		return 1
	}
	now := time.Now()
	// Every admitted device rests on a key_ref; without --config none was
	// checked against the keys port49d.yaml defines, and a pin to one it
	// does not define is refused there, not here. Every verdict says so.
	unchecked := ""
	if *cfgPath == "" && len(new.AdmissionRefusals()) < len(new.Devices()) {
		unchecked = "; key_refs not checked against port49d.yaml: pass --config to check them"
	}
	if bytes.Equal(old.Raw(), new.Raw()) {
		// One file changed: one inventory reload, against the policy in force,
		// checked before the bundles are compared, as port49d does.
		rep := bundle.Diff(old, new, now)
		fmt.Fprintln(stdout, rep.Summary())
		if new.Bundle != old.Bundle {
			printChanges(stdout, rep, new)
		}
		if err := bundle.Check(old, new, bound); err != nil {
			fmt.Fprintf(stdout, "refused: %v%s\n", err, unchecked)
			return 1
		}
		if new.Bundle == old.Bundle {
			fmt.Fprintf(stdout, "unchanged: the same inventory, respelled; bundle %s stays in force%s\n", old.Bundle,
				unchecked)
			return 0
		}
		fmt.Fprintf(stdout, "ok: port49d would take the new inventory (inventory.max_removed_percent %d%%)%s\n", bound,
			unchecked)
		return 0
	}
	// Both files changed: two reloads, each loading its file against the
	// other in force, bounded, and logged as its own swap. Each order is shown
	// step by step, as port49d would log it: a device that joins a scope in
	// one step and leaves it in the next is two inventory_change records.
	fmt.Fprintln(stdout, bundle.Diff(old, new, now).Summary())
	orders := []order{
		reloadOrder(stdout, now, old, new,
			func() (*policy.Policy, error) { return bundle.Load(*newPol, oldInv, env) },
			func(mid *policy.Policy) error { return bundle.CheckAdmission(old, mid, bound) },
			func(mid *policy.Policy) error { return bundle.Check(mid, new, bound) },
			"policy", "inventory"),
		reloadOrder(stdout, now, old, new,
			func() (*policy.Policy, error) { return bundle.Load(*polPath, newInv, env) },
			func(mid *policy.Policy) error { return bundle.Check(old, mid, bound) },
			func(mid *policy.Policy) error { return bundle.CheckAdmission(mid, new, bound) },
			"inventory", "policy"),
	}
	// An order whose first reload is taken and whose second is refused
	// leaves port49d on the bundle between: the refused file is tried again
	// only when the other file changes again (plan 6a, C3), and a SIGHUP
	// runs the same check on the same state. That fails the diff.
	stuck := false
	for _, o := range orders {
		if o.stuck != nil {
			stuck = true
			fmt.Fprintf(stdout, "refused: if the %s file lands first, port49d takes it, then refuses the %s file (%v) "+
				"and stays on that bundle until the %s file changes again%s\n", o.first, o.second, o.stuck, o.first,
				unchecked)
		}
	}
	if stuck {
		return 1
	}
	// Otherwise an order refused is refused at its first reload, which swaps
	// nothing: the other file's reload runs next, as the other order.
	policyFirst, inventoryFirst := orders[0].err, orders[1].err
	switch {
	case policyFirst == nil && inventoryFirst == nil:
		fmt.Fprintf(stdout, "ok: port49d would take both, in either order (inventory.max_removed_percent %d%%)%s\n",
			bound, unchecked)
	case policyFirst == nil || inventoryFirst == nil:
		first, then := "policy", "inventory"
		if policyFirst != nil {
			first, then = then, first
		}
		fmt.Fprintf(stdout, "ok: port49d would take both (inventory.max_removed_percent %d%%); if the %s file "+
			"lands first, its reload is refused until the %s file lands%s\n", bound, then, first, unchecked)
	default:
		fmt.Fprintf(stdout, "refused: port49d would take both files in neither order%s\n", unchecked)
		return 1
	}
	return 0
}

// order is one order of a two-file change's reloads: err is nil when both
// are taken, and stuck is the second reload's refusal when the first was
// taken, which leaves port49d on the bundle between.
type order struct {
	first, second string
	err, stuck    error
}

// reloadOrder prints two reloads in turn, first then second, as port49d runs
// them: the first file's loaded against the other in force (load) and
// bounded (firstCheck), then the second's (secondCheck). Each step taken is
// printed with its changes, the security ones marked as that swap's
// inventory_change records; a step refused swaps nothing and logs nothing.
// It ends with the order's verdict line.
func reloadOrder(w io.Writer, now time.Time, old, new *policy.Policy,
	load func() (*policy.Policy, error), firstCheck, secondCheck func(*policy.Policy) error,
	first, second string) order {
	heading := first + " file first"
	fmt.Fprintf(w, "%s:\n", heading)
	o := order{first: first, second: second}
	mid, err := load()
	var cerr error
	if err == nil {
		cerr = firstCheck(mid)
	}
	switch {
	case err != nil:
		o.err = fmt.Errorf("the %s reload is refused: port49d would not load it against the %s in force: %s",
			first, second, loadFault(err))
	case cerr != nil:
		o.err = fmt.Errorf("the %s reload is refused: %w", first, cerr)
	default:
		step(w, now, first, old, mid)
		if err := secondCheck(mid); err != nil {
			o.stuck = err
			o.err = fmt.Errorf("the %s reload after it is refused, and port49d stays on the bundle between: %w",
				second, err)
			break
		}
		step(w, now, second, mid, new)
	}
	if o.err != nil {
		fmt.Fprintf(w, "%s: %v\n", heading, o.err)
		return o
	}
	fmt.Fprintf(w, "%s: taken\n", heading)
	return o
}

// step prints one reload port49d takes: its summary line and its changes.
func step(w io.Writer, now time.Time, file string, from, to *policy.Policy) {
	rep := bundle.Diff(from, to, now)
	fmt.Fprintf(w, "the %s reload: %s\n", file, rep.Summary())
	printChanges(w, rep, to)
}

// printChanges is rep's changes, one per line, with to's addresses for an
// added device.
func printChanges(w io.Writer, rep bundle.Report, to *policy.Policy) {
	addresses := map[string]string{}
	for _, d := range to.Devices() {
		as := make([]string, len(d.Addresses))
		for i, a := range d.Addresses {
			as[i] = a.String()
		}
		addresses[d.Name] = strings.Join(as, ", ")
	}
	for _, c := range rep.Changes {
		fmt.Fprintln(w, changeLine(c, addresses[c.Device]))
	}
}

// loadFault is a load error with the file at fault named: an inventory
// fault names the inventory file, not the policy.
func loadFault(err error) string {
	var inv *bundle.InventoryError
	if errors.As(err, &inv) {
		return fmt.Sprintf("inventory %s: %v", inv.Path, inv.Err)
	}
	return err.Error()
}

// flagSet is whether name was given on the command line.
func flagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) { set = set || f.Name == name })
	return set
}

// changeLine is one change, `!` first where the log would carry it as a
// security event. addresses is the device's in the new inventory, for an
// added device: each is a new place a mint sends an operator.
func changeLine(c bundle.Change, addresses string) string {
	mark := " "
	if c.Security {
		mark = "!"
	}
	switch c.Kind {
	case bundle.DeviceAdded:
		return fmt.Sprintf("%s device added %s (%s) at %s: %s", mark, c.Device, c.Platform, addresses, c.To)
	case bundle.DeviceRemoved:
		return fmt.Sprintf("%s device removed %s (%s)", mark, c.Device, c.Platform)
	case bundle.AddressAdded:
		return fmt.Sprintf("%s address added %s: %s", mark, c.Device, c.Address)
	case bundle.AddressRemoved:
		return fmt.Sprintf("%s address removed %s: %s", mark, c.Device, c.Address)
	case bundle.ScopeJoined, bundle.ScopeLeft:
		verb, tag := "joined", ""
		if c.Kind == bundle.ScopeLeft {
			verb = "left"
		}
		if c.Security {
			tag = " (security_log)"
		}
		return fmt.Sprintf("%s scope %s%s: %s %s", mark, c.Scope, tag, c.Device, verb)
	}
	return fmt.Sprintf("%s %s %s: %s → %s", mark, c.Kind, c.Device, c.From, c.To)
}
