package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/policy"
)

// platformCmd runs `port49 platform SUBCOMMAND` (spec §8, "Knowing what is
// shipped"): the built-in adapters are files, and these print them, with a
// policy's `platforms:` blocks laid over them where one is named.
func platformCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "list":
		return platformList(args[1:], stdout, stderr)
	case "show":
		return platformShow(args[1:], stdout, stderr, false)
	case "export":
		return platformShow(args[1:], stdout, stderr, true)
	case "upgrade":
		return platformUpgrade(args[1:], stdout, stderr)
	}
	fmt.Fprint(stderr, usage)
	return 2
}

// adapters are the platforms a platform command reads: a built-in set, or,
// with --policy and --inventory, the policy's set with its blocks over it.
type adapters struct {
	files policyFiles
	set   string
}

func (a *adapters) register(fs *flag.FlagSet) {
	a.files.register(fs)
	fs.StringVar(&a.set, "set", platform.DefaultSet, "the built-in platform set, when no --policy is given")
}

// load returns the policy, nil without --policy, and a lookup for the
// adapters in force.
func (a *adapters) load() (*policy.Policy, map[string]platform.Dialect, error) {
	if a.files.policy == "" && a.files.inventory == "" {
		set, ok := platform.Set(a.set)
		if !ok {
			return nil, nil, fmt.Errorf("--set %s is not a set this binary ships; it ships %s", a.set,
				strings.Join(platform.Sets(), ", "))
		}
		return nil, set, nil
	}
	if a.files.missing() {
		return nil, nil, fmt.Errorf("--policy and --inventory go together")
	}
	p, err := a.files.load()
	if err != nil {
		return nil, nil, err
	}
	out := map[string]platform.Dialect{}
	for _, name := range p.PlatformNames() {
		out[name] = p.Dialect(name)
	}
	return p, out, nil
}

// platformList prints one line per platform: where its adapter comes from,
// how it was verified, and what it authorizes. A built-in adapter an
// operator's block changed is not the one the lab verified, so it prints `—`.
func platformList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 platform list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var a adapters
	a.register(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	p, set, err := a.load()
	if err != nil {
		fmt.Fprintln(stderr, "port49 platform list:", err)
		return 1
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(tw, "PLATFORM\tSOURCE\tVERIFIED\tSUPPORTS")
	for _, name := range sortedNames(set) {
		d, source := set[name], "built-in"
		if p != nil {
			source = p.PlatformSource(name)
		}
		verified := d.Verified
		if verified == "" || source != "built-in" {
			verified = "—"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", name, source, verified, strings.Join(d.Supports, ","))
	}
	tw.Flush()
	return 0
}

// platformShow prints one platform's adapter as a file writes it. `show`
// heads it with where it came from and follows it with the built-in
// redaction patterns, which are not part of a set; `export` prints the file
// alone, for an upstream pull request (spec §8), and with --all --dir writes
// one file per platform.
func platformShow(args []string, stdout, stderr io.Writer, export bool) int {
	name := "port49 platform show"
	if export {
		name = "port49 platform export"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var a adapters
	a.register(fs)
	all := fs.Bool("all", false, "every platform, one file each in --dir (export only)")
	dir := fs.String("dir", "", "the directory --all writes to")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	switch {
	case *all && (!export || *dir == "" || fs.NArg() != 0), !*all && (*dir != "" || fs.NArg() != 1):
		fmt.Fprint(stderr, usage)
		return 2
	}
	p, set, err := a.load()
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", name, err)
		return 1
	}
	if *all {
		for _, platformName := range sortedNames(set) {
			body, err := adapterFile(platformName, set[platformName])
			if err == nil {
				err = os.WriteFile(filepath.Join(*dir, platformName+".yaml"), body, 0o644)
			}
			if err != nil {
				fmt.Fprintf(stderr, "%s: %v\n", name, err)
				return 1
			}
		}
		return 0
	}
	platformName := fs.Arg(0)
	d, ok := set[platformName]
	if !ok {
		fmt.Fprintf(stderr, "%s: %q has no adapter here; the platforms are %s\n", name, platformName,
			strings.Join(sortedNames(set), ", "))
		return 1
	}
	body, err := adapterFile(platformName, d)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", name, err)
		return 1
	}
	if !export {
		source, setName := "built-in", a.set
		if p != nil {
			source, setName = p.PlatformSource(platformName), p.PlatformSet()
		}
		fmt.Fprintf(stdout, "# %s: %s, platform set %s\n", platformName, source, setName)
	}
	stdout.Write(body)
	if !export {
		fmt.Fprintln(stdout, "# built-in redaction, applied before any record is written and not part of a set (spec §5.8):")
		for _, r := range platform.Redactions(platformName) {
			fmt.Fprintf(stdout, "#   %s\n", redactionLine(r))
		}
	}
	return 0
}

// platformUpgrade moves a policy's platform_set pin and reports exactly what
// the move changes (spec §8, §12): every adapter key that differs between the
// two sets on a platform the inventory has, with the devices and subjects it
// reaches, and every key a `platforms:` block keeps its own value for while
// the built-in under it changes. The report is the output; --write also
// rewrites the pin in the file, and nothing else in it. `port49 policy diff`
// on the two files is the gate: this says what it will find, and prints the
// acknowledge: entries the gated keys need.
func platformUpgrade(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 platform upgrade", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var files policyFiles
	files.register(fs)
	to := fs.String("to", "", "the platform set to pin")
	write := fs.Bool("write", false, "rewrite the pin in the policy file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if files.missing() || *to == "" || fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	inv, err := admission.LoadFile(files.inventory)
	if err != nil {
		fmt.Fprintln(stderr, "port49 platform upgrade:", err)
		return 1
	}
	raw, err := os.ReadFile(files.policy)
	if err != nil {
		fmt.Fprintln(stderr, "port49 platform upgrade:", err)
		return 1
	}
	before, err := policy.Parse(raw, offlineEnv(inv.Devices))
	if err != nil {
		fmt.Fprintln(stderr, "port49 platform upgrade:", err)
		return 1
	}
	moved, err := policy.SetPlatformSet(raw, *to)
	if err != nil {
		fmt.Fprintln(stderr, "port49 platform upgrade:", err)
		return 1
	}
	after, err := policy.Parse(moved, offlineEnv(inv.Devices))
	if err != nil {
		fmt.Fprintf(stderr, "port49 platform upgrade: the policy does not load on platform set %s, so nothing was "+
			"written: %v\n", *to, err)
		return 1
	}
	upgradeReport(stdout, before, after, time.Now())
	if *write {
		if err := replaceFile(files.policy, moved); err != nil {
			fmt.Fprintln(stderr, "port49 platform upgrade:", err)
			return 1
		}
	}
	return 0
}

// upgradeReport is what moving the pin from before's set to after's changes:
// each adapter key, with what it reaches and, where the gate reads it, the
// acknowledge: entry that clears it, ready to paste (spec §12: the entry names
// the new value's sha256, so it acknowledges this move and no later edit);
// each key a block keeps over a built-in that moved. The generic adapter's
// keys are among the changes, gated like any platform's.
func upgradeReport(w io.Writer, before, after *policy.Policy, now time.Time) {
	fmt.Fprintf(w, "platform_set %s -> %s\n", before.PlatformSet(), after.PlatformSet())
	d := policy.Compare(before, after, now)
	for _, a := range d.Adapters {
		devices, subjects := before.Reach(a.Platform, now)
		key := "platforms." + a.Platform + "." + a.Field
		if a.Platform == "generic" {
			// What every device of a platform with no adapter receives.
			key = "generic." + a.Field
		}
		fmt.Fprintf(w, "  %s\n    %s -> %s\n    affects %d devices, %d subjects\n", key, a.Old, a.New, devices,
			subjects)
		switch {
		case !a.Gated:
			fmt.Fprintln(w, "    reported")
		case a.Acknowledged:
			fmt.Fprintf(w, "    gated, acknowledged: %s\n", a.AcknowledgedBy)
		default:
			fmt.Fprintf(w, "    gated: add {platform: %s, field: %s, sha256: %s, reason: \"...\"} under acknowledge:\n",
				a.Platform, a.Field, a.Sha256)
		}
	}
	for _, key := range after.ShadowedBuiltIns(before.PlatformSet()) {
		fmt.Fprintf(w, "  shadowed: %s: set %s changes the built-in value and the policy's block keeps its "+
			"own; compare the two\n", key, after.PlatformSet())
	}
	if len(d.Adapters) == 0 {
		fmt.Fprintln(w, "  no adapter the inventory uses changes")
	}
	if d.UnacknowledgedAdapters() > 0 {
		fmt.Fprintf(w, "  port49 policy diff fails on the move until every gated entry above is under acknowledge: "+
			"(spec §12); it also shows the replies the move changes\n")
	}
}

// adapterFile is d as an adapter file: `platforms: {name: ...}`.
func adapterFile(name string, d platform.Dialect) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(map[string]map[string]platform.Spec{"platforms": {name: platform.SpecOf(d)}}); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// redactionLine is a pattern as redact.yaml writes it.
func redactionLine(r platform.Redaction) string {
	words := make([]string, len(r.Match))
	for i, w := range r.Match {
		words[i] = "'" + w + "'"
	}
	if r.From != nil {
		return fmt.Sprintf("{match: [%s], from: %d}", strings.Join(words, ", "), *r.From)
	}
	return fmt.Sprintf("{match: [%s], after: %s}", strings.Join(words, ", "), r.After)
}

func sortedNames(set map[string]platform.Dialect) []string {
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}
