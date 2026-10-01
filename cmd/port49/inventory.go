package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/inventory"
	"github.com/rhwendt/port49/internal/keyfile"
	"github.com/rhwendt/port49/internal/policy"
)

func inventoryCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "diff" {
		return inventoryDiff(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "sync" {
		return inventorySync(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "keygen" {
		return inventoryKeygen(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "export" {
		return inventoryExport(args[1:], stdout, stderr)
	}
	fmt.Fprint(stderr, usage)
	return 2
}

// inventoryDiff is `port49 inventory diff` (spec §10, §12): what a change to
// the inventory does to the bundle — devices, addresses, keys, admission and
// scope membership, the security lines marked `!` as port49d writes them
// inventory_change records — and whether port49d would load it, by the
// checks its reload runs (bundle.Check; with --new-policy,
// bundle.CheckAdmission for the policy's reload too). With --service it is
// the service's diff instead: from bundle --from to the one it publishes.
func inventoryDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 inventory diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	polPath := fs.String("policy", "", "the policy the old inventory is loaded against")
	newPol := fs.String("new-policy", "", "the policy the new one is loaded against (default: --policy)")
	maxRemoved := fs.Int("max-removed-percent", 10, "port49d.yaml's inventory.max_removed_percent")
	cfgPath := fs.String("config", "", "port49d.yaml: the key_refs it defines and inventory.max_removed_percent, "+
		"as port49d reads them; no secret is read")
	svc := serviceFlags(fs)
	from := fs.Int64("from", 0, "with --service: the sequence of the bundle to diff from")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if svc.url != "" {
		if flagSet(fs, "policy") || flagSet(fs, "new-policy") || flagSet(fs, "max-removed-percent") ||
			flagSet(fs, "config") || fs.NArg() != 0 || !svc.complete() || *from < 1 {
			fmt.Fprint(stderr, usage)
			return 2
		}
		return serviceDiff(svc, *from, stdout, stderr)
	}
	if svc.any() || flagSet(fs, "from") {
		fmt.Fprint(stderr, usage)
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
		fmt.Fprintln(w, c.Line(addresses[c.Device]))
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

// inventoryKeygen is `port49 inventory keygen`: the inventory service's
// signing key pair (spec §13, decision 30). signing.key goes to the service
// alone, signing.pub to every port49d's inventory.service.verify_key_files.
// Neither file is ever overwritten: a new key beside a daemon still holding
// the old public half would strand it on the bundle in force.
func inventoryKeygen(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("port49 inventory keygen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", "", "the directory to write signing.key and signing.pub into")
	if err := flags.Parse(args); err != nil || *dir == "" || flags.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	// Refuse before writing either, so a refusal never leaves one new file
	// beside an old one (conflict scan F14).
	for _, name := range []string{"signing.key", "signing.pub"} {
		if _, err := os.Lstat(filepath.Join(*dir, name)); err == nil {
			fmt.Fprintf(stderr, "port49 inventory keygen: %s already exists; a new key is written beside no old one\n",
				filepath.Join(*dir, name))
			return 1
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(stderr, "port49 inventory keygen:", err)
		return 1
	}
	privPEM, pubPEM, err := keyfile.EncodeEd25519(priv)
	if err != nil {
		fmt.Fprintln(stderr, "port49 inventory keygen:", err)
		return 1
	}
	var written []string
	undo := func() {
		for _, w := range written {
			os.Remove(w)
		}
	}
	for _, f := range []struct {
		name string
		body []byte
		mode os.FileMode
	}{{"signing.key", privPEM, 0o600}, {"signing.pub", pubPEM, 0o644}} {
		path := filepath.Join(*dir, f.name)
		// O_EXCL still: a file that appeared since the check is not overwritten.
		out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, f.mode)
		if err != nil {
			undo()
			fmt.Fprintln(stderr, "port49 inventory keygen:", err)
			return 1
		}
		written = append(written, path)
		// The mode exactly, whatever the umask: signing.pub is meant to be
		// copied out, signing.key read by its owner alone.
		werr := out.Chmod(f.mode)
		if werr == nil {
			_, werr = out.Write(f.body)
		}
		if werr == nil {
			werr = out.Sync()
		}
		if cerr := out.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			undo() // the first file is removed if the second fails
			fmt.Fprintln(stderr, "port49 inventory keygen:", werr)
			return 1
		}
	}
	// The directory too, so a crash after the success line cannot lose
	// either name.
	if err := syncDir(*dir); err != nil {
		undo()
		fmt.Fprintln(stderr, "port49 inventory keygen:", err)
		return 1
	}
	fmt.Fprintf(stdout, "port49 inventory keygen: wrote %s (0600: port49-inventory's signing_key_file) and %s "+
		"(every port49d's inventory.service.verify_key_files); key_id %s\n", filepath.Join(*dir, "signing.key"),
		filepath.Join(*dir, "signing.pub"), keyfile.Ed25519KeyID(priv.Public().(ed25519.PublicKey)))
	return 0
}

// service is the flags that name the inventory service and the client's
// certificate for it.
type service struct{ url, ca, cert, key string }

func serviceFlags(fs *flag.FlagSet) *service {
	s := &service{}
	fs.StringVar(&s.url, "service", "", "the inventory service, https://host[:port]")
	fs.StringVar(&s.ca, "ca", "", "the CA file that issues the service's certificate, and nothing else")
	fs.StringVar(&s.cert, "cert", "", "the client certificate the service names you by")
	fs.StringVar(&s.key, "key", "", "its private key (owner-only)")
	return s
}

func (s *service) complete() bool { return s.url != "" && s.ca != "" && s.cert != "" && s.key != "" }
func (s *service) any() bool      { return s.url != "" || s.ca != "" || s.cert != "" || s.key != "" }

// syncWait is how long `port49 inventory sync` waits for the service's
// answer: longer than the sync_timeout default, 5m, which bounds the sync
// itself (conflict scan F16). A variable for the test.
var syncWait = 6 * time.Minute

// inventorySync is `port49 inventory sync`: the service syncs now, as its
// timer would, and says what it did. It exits 0 when the service published
// or found nothing changed, 1 otherwise.
func inventorySync(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 inventory sync", flag.ContinueOnError)
	fs.SetOutput(stderr)
	svc := serviceFlags(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !svc.complete() || fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	c, err := inventory.NewClient(svc.url, svc.ca, svc.cert, svc.key)
	if err != nil {
		fmt.Fprintln(stderr, "port49 inventory sync:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), syncWait)
	defer cancel()
	res, err := c.Sync(ctx)
	if err != nil {
		// A connection never made asked for nothing. Only an ask sent and
		// not answered in time may still be running at the service.
		var ne net.Error
		switch {
		case errors.Is(err, inventory.ErrNoConnection):
			fmt.Fprintf(stderr, "port49 inventory sync: %v; no sync was asked for\n", err)
		case ctx.Err() == context.DeadlineExceeded || (errors.As(err, &ne) && ne.Timeout()):
			fmt.Fprintf(stderr, "port49 inventory sync: no answer within %v; the service may still finish the sync: "+
				"its log, or port49 inventory diff --service, says what it did\n", syncWait)
		default:
			fmt.Fprintln(stderr, "port49 inventory sync:", err)
		}
		return 1
	}
	return printResult(stdout, res)
}

// diffWait is how long `port49 inventory diff --service` waits for the
// service's answer: a diff is a read, and the usage says so.
const diffWait = time.Minute

// serviceDiff is `port49 inventory diff --service`: what changed from bundle
// from to the one the service publishes, as the service judges it.
func serviceDiff(svc *service, from int64, stdout, stderr io.Writer) int {
	c, err := inventory.NewClient(svc.url, svc.ca, svc.cert, svc.key)
	if err != nil {
		fmt.Fprintln(stderr, "port49 inventory diff:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), diffWait)
	defer cancel()
	d, err := c.Diff(ctx, from)
	if err != nil {
		fmt.Fprintln(stderr, "port49 inventory diff:", err)
		return 1
	}
	fmt.Fprintf(stdout, "bundle %d → %d: %s\n", d.From, d.To, inventory.Printable(d.Summary))
	for _, c := range d.Changes {
		fmt.Fprintln(stdout, inventory.Printable(c.Line("")))
	}
	return 0
}

// printResult is a sync's outcome as `port49 inventory sync` prints it, and
// its exit code: 0 for published and unchanged, 1 otherwise. Every string
// is the service's, so each is printed through inventory.Printable.
func printResult(w io.Writer, res inventory.Result) int {
	switch res.Outcome {
	case "published":
		fmt.Fprintf(w, "published bundle %d (%s): %s; %d quarantined\n", res.Sequence, inventory.Printable(res.Bundle),
			inventory.Printable(res.Summary), len(res.Quarantined))
		for _, c := range res.Changes {
			fmt.Fprintln(w, inventory.Printable(c.Line("")))
		}
		for _, q := range res.Quarantined {
			fmt.Fprintf(w, "  device %s (%s) is quarantined against the service's policy: %s\n", inventory.Printable(q.Device),
				inventory.Printable(q.Platform), inventory.Printable(q.Cause))
		}
		for _, g := range res.Generic {
			fmt.Fprintf(w, "  platform %s (%d device(s)) has no adapter in the policy and is served by the generic "+
				"one, priv-lvl only (spec §8)\n", inventory.Printable(g.Platform), g.Devices)
		}
		for _, l := range res.LeftOut {
			fmt.Fprintf(w, "  left out: %s\n", inventory.Printable(l))
		}
		return 0
	case "unchanged":
		fmt.Fprintf(w, "unchanged: bundle %d is current\n", res.Sequence)
		for _, g := range res.Generic {
			fmt.Fprintf(w, "  platform %s (%d device(s)) has no adapter in the policy and is served by the generic "+
				"one, priv-lvl only (spec §8)\n", inventory.Printable(g.Platform), g.Devices)
		}
		return 0
	}
	still := "no bundle is published yet"
	if res.Sequence > 0 {
		still = fmt.Sprintf("still publishing bundle %d", res.Sequence)
	}
	fmt.Fprintf(w, "%s; %s: %s\n", inventory.Printable(res.Outcome), still, inventory.Printable(res.Reason))
	return 1
}

// stringsFlag is a flag given once per value.
type stringsFlag []string

func (f *stringsFlag) String() string     { return strings.Join(*f, ",") }
func (f *stringsFlag) Set(v string) error { *f = append(*f, v); return nil }

// inventoryExport is `port49 inventory export` (spec §12): the bundle the
// service publishes, or bundle --from from its history, opened against
// --verify-key as port49d opens it (decision 31), and its inventory written
// in inventory_file's schema — to --out, never over an existing file, or to
// standard output — so the offline tools keep an --inventory when no source
// is a file. A bundle that does not open writes nothing.
func inventoryExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 inventory export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	svc := serviceFlags(fs)
	var verify stringsFlag
	fs.Var(&verify, "verify-key", "the service's public key (signing.pub), as port49d's verify_key_files holds it; "+
		"once per key")
	from := fs.Int64("from", 0, "a bundle's sequence in the service's history (default: the bundle it publishes)")
	outPath := fs.String("out", "", "the file to write, which must not exist, mode 0600 (default: standard output)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// An explicit --from is a sequence, 1 or more: --from 0 is not "the
	// published bundle" by accident.
	if !svc.complete() || len(verify) == 0 || fs.NArg() != 0 || (flagSet(fs, "from") && *from < 1) {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var keys []ed25519.PublicKey
	for _, p := range verify {
		raw, err := os.ReadFile(p)
		var k ed25519.PublicKey
		if err == nil {
			k, err = keyfile.ParseEd25519Public(raw, p)
		}
		if err != nil {
			fmt.Fprintln(stderr, "port49 inventory export: --verify-key:", err)
			return 1
		}
		keys = append(keys, k)
	}
	c, err := inventory.NewClient(svc.url, svc.ca, svc.cert, svc.key)
	if err != nil {
		fmt.Fprintln(stderr, "port49 inventory export:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), diffWait)
	defer cancel()
	var raw []byte
	if *from > 0 {
		raw, err = c.BundleAt(ctx, *from)
	} else {
		raw, _, _, err = c.Bundle(ctx, "")
	}
	if err != nil {
		fmt.Fprintln(stderr, "port49 inventory export:", err)
		return 1
	}
	doc, inv, err := bundle.Open(raw, keys)
	if err != nil {
		fmt.Fprintf(stderr, "port49 inventory export: the service's bundle does not open under --verify-key: %s; "+
			"nothing is written\n", inventory.Printable(err.Error()))
		return 1
	}
	if *from > 0 && doc.Sequence != *from {
		// A genuine bundle, but not the one asked for (pre-flight M7).
		fmt.Fprintf(stderr, "port49 inventory export: the service answered bundle %d for --from %d; nothing is "+
			"written\n", doc.Sequence, *from)
		return 1
	}
	body, err := admission.EncodeFile(inv)
	if err != nil {
		fmt.Fprintln(stderr, "port49 inventory export:", err)
		return 1
	}
	// The service's scheme and host only: a path is the operator's text,
	// and the file is passed around.
	origin := "the service"
	if u, err := url.Parse(svc.url); err == nil {
		origin = inventory.Printable(u.Scheme + "://" + u.Host)
	}
	header := fmt.Sprintf("# port49 inventory export: bundle %d (%s), published %s, from %s.\n"+
		"# The inventory service's facts only: no key assignment (spec §13, decision 30).\n", doc.Sequence, doc.Bundle,
		doc.PublishedAt.Format(time.RFC3339), origin)
	body = append([]byte(header), body...)
	where := ""
	if *outPath == "" {
		// A short write is a truncated inventory that may still parse, as
		// part of the fleet: it fails the export.
		if _, err := stdout.Write(body); err != nil {
			fmt.Fprintln(stderr, "port49 inventory export: standard output:", err)
			return 1
		}
	} else {
		if err := writeNew(*outPath, body); err != nil {
			fmt.Fprintln(stderr, "port49 inventory export:", err)
			return 1
		}
		where = ", written to " + *outPath
	}
	fmt.Fprintf(stderr, "port49 inventory export: bundle %d, %d device(s)%s\n", doc.Sequence, len(inv.Devices), where)
	return 0
}

// writeNew writes body to path, which must not exist, 0600, and syncs it; a
// failure removes what it wrote. 0600: the fleet list and its addresses are
// not for the world, as plan 6b made the mirror 0640 (pre-flight M8).
func writeNew(path string, body []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			if fi, lerr := os.Lstat(path); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%s is a symbolic link; an export is never written through one", path)
			}
			return fmt.Errorf("%s exists; an export is written beside no old one", path)
		}
		return err
	}
	_, err = f.Write(body)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}
