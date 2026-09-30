package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/config"
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
	fs.StringVar(&a.set, "set", "", "the built-in platform set, when no --policy is given (default "+
		platform.DefaultSet+")")
}

// conflicting reports --set given with --policy or --inventory: the policy
// pins its own set, and the usage line offers one or the other.
func (a *adapters) conflicting() bool {
	return a.set != "" && (a.files.policy != "" || a.files.inventory != "")
}

// load returns the policy, nil without --policy, and a lookup for the
// adapters in force.
func (a *adapters) load() (*policy.Policy, map[string]platform.Dialect, error) {
	if a.files.policy == "" && a.files.inventory == "" {
		if a.set == "" {
			a.set = platform.DefaultSet
		}
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
	if fs.NArg() != 0 || a.conflicting() {
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
	classes := fs.Bool("classes", false, "a projected platform's reference device configuration, as set lines "+
		"(export only)")
	cfgPath := fs.String("config", "", "port49d.yaml: its session.max_session_age_default is the classes' "+
		"idle-timeout (with --classes)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	switch {
	case *all && (!export || *dir == "" || fs.NArg() != 0), !*all && (*dir != "" || fs.NArg() != 1),
		a.conflicting(), *classes && (!export || *all || *cfgPath == ""), !*classes && *cfgPath != "":
		fmt.Fprint(stderr, usage)
		return 2
	}
	p, set, err := a.load()
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", name, err)
		return 1
	}
	// A block's device_config line or config check may carry a secret, and
	// what show and export print lands in terminals, CI logs and upstream pull
	// requests: each is redacted by every pattern that applies, and policy
	// test reports the lines (spec §5.8). A set's own print as written.
	patterns, secret := platform.AllRedactions(), map[string]bool{}
	if p != nil {
		patterns, secret = p.Redactions(), p.SecretClasses()
	}
	for platformName, d := range set {
		set[platformName] = platform.RedactAdapter(patterns, secret, d)
	}
	if *all {
		// A file already there would be read back as part of the set.
		if entries, err := os.ReadDir(*dir); err != nil || len(entries) != 0 {
			if err == nil {
				err = fmt.Errorf("%s is not empty; export --all writes a whole set into an empty directory", *dir)
			}
			fmt.Fprintf(stderr, "%s: %v\n", name, err)
			return 1
		}
		for _, platformName := range sortedNames(set) {
			body, err := adapterFile(platformName, set[platformName], exportSet)
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
	if *classes {
		var hidden map[int]bool
		if p != nil {
			if d.DeviceConfig, hidden, err = referenceDeviceConfig(p, platformName, patterns, secret); err != nil {
				fmt.Fprintf(stderr, "%s: %v\n", name, err)
				return 1
			}
		}
		return exportClasses(stdout, stderr, name, platformName, d, *cfgPath, a, p, hidden)
	}
	mode := exportShow
	if export {
		mode = exportBlock
	}
	body, err := adapterFile(platformName, d, mode)
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
		// A variant's built-in redaction is its base's (spec §8).
		builtIn := platformName
		if p != nil {
			builtIn = p.WirePlatform(platformName)
		}
		for _, r := range platform.Redactions(builtIn) {
			fmt.Fprintf(stdout, "#   %s\n", redactionLine(r))
		}
		fmt.Fprintln(stdout, "# and a URL's password (scheme://user:password@host) and a credential in its query string "+
			"(X-Amz-Signature=, token=, access_token=, ...), in any word, whatever the patterns say")
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
	// The report goes to CI logs as policy diff's does: every quoted value is
	// redacted, by the policy's patterns once it loads (spec §5.8; final
	// review I3).
	out, errOut, flush := redactOutput(stdout, stderr)
	defer flush()
	stdout, stderr = out, errOut
	inv, err := bundle.LoadInventory(files.inventory)
	if err != nil {
		fmt.Fprintln(stderr, "port49 platform upgrade:", err)
		return 1
	}
	raw, err := os.ReadFile(files.policy)
	if err != nil {
		fmt.Fprintln(stderr, "port49 platform upgrade:", err)
		return 1
	}
	before, err := bundle.Parse(raw, inv, policy.Env{})
	if err != nil {
		// Nothing to compare against: a pin this binary no longer ships is
		// moved by the binary that still ships it (spec §8).
		fmt.Fprintf(stderr, "port49 platform upgrade: the policy as it is does not load, so there is nothing to "+
			"compare the move against: %v; if its platform_set is one this binary no longer ships, run the upgrade "+
			"with a binary that ships both sets\n", err)
		return 1
	}
	moved, err := policy.SetPlatformSet(raw, *to)
	if err != nil {
		fmt.Fprintln(stderr, "port49 platform upgrade:", err)
		return 1
	}
	after, err := bundle.Parse(moved, inv, policy.Env{})
	if err != nil {
		fmt.Fprintf(stderr, "port49 platform upgrade: the policy does not load on platform set %s, so nothing was "+
			"written: %v\n", *to, err)
		return 1
	}
	if after.PlatformSet() != *to {
		fmt.Fprintf(stderr, "port49 platform upgrade: the rewritten file pins %s, not %s, so nothing was written\n",
			after.PlatformSet(), *to)
		return 1
	}
	out.learn(before, after)
	errOut.learn(before, after)
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
		fmt.Fprintf(w, "  %s\n    %s -> %s\n    affects %d devices, %d subjects\n", adapterKey(a), a.OldShown,
			a.NewShown, devices, subjects)
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
	// What the move quarantines or fails closed, before anyone runs the
	// gate: each fails policy test (plan 5b pre-flight I10).
	for _, q := range after.Quarantines(now) {
		for _, e := range q.Entries {
			fmt.Fprintf(w, "  quarantine on %s: %s (%s): %s\n", after.PlatformSet(), q.Device, q.Platform,
				quarantineLine(e, now))
		}
	}
	for _, f := range after.Projections(now) {
		if f.Kind == policy.FindingProjectionRefused || f.Kind == policy.FindingProjectionOverflow {
			fmt.Fprintf(w, "  %s on %s: %s\n", f.Kind, after.PlatformSet(), f.Message)
		}
	}
	switch {
	case len(d.Adapters) == 0:
		fmt.Fprintln(w, "  no adapter changes")
	case d.UnacknowledgedAdapters() > 0:
		fmt.Fprintf(w, "  port49 policy diff fails on the move until every gated entry above is under acknowledge: "+
			"(spec §12); it also shows the replies the move changes\n")
	default:
		fmt.Fprintln(w, "  port49 policy diff on the move also shows the replies it changes")
	}
}

// adapterKey is the key an adapter change is to, as policy diff and platform
// upgrade both name it: platforms.<p>.<key>, and generic.<key> for the
// generic adapter, which every device of a platform with no adapter receives
// and no block writes.
func adapterKey(a policy.AdapterChange) string {
	if a.Platform == "generic" {
		return "generic." + a.Field
	}
	return "platforms." + a.Platform + "." + a.Field
}

// exportMode is what adapterFile writes a block's fallback note as.
type exportMode int

const (
	// exportShow prints fallback and fallback_note, and unreachable and
	// unreachable_note, apart, as port49 holds them.
	exportShow exportMode = iota
	// exportBlock writes the note under fallback, where the block wrote it,
	// commented as the operator's, so the file pastes back as a block:
	// fallback_note is port49's own record, which a block may not set, and
	// the set's measured text a block cannot change goes with it. verified,
	// port49's claim about its lab, is left out for the same reason.
	exportBlock
	// exportSet writes a platform set, which carries only what the lab
	// measured: the note is dropped (spec §8).
	exportSet
)

// notMeasured is the comment on a fallback level exportBlock folded a note
// into.
const notMeasured = "operator note, not measured"

// operatorListed is the comment on an unreachable rule exportBlock folded
// back from the operator's list.
const operatorListed = "operator-listed, not measured"

// adapterFile is d as an adapter file: `platforms: {name: ...}`, with a
// block's fallback note written as mode says (spec §8, §12).
func adapterFile(name string, d platform.Dialect, mode exportMode) ([]byte, error) {
	spec := platform.SpecOf(d)
	if mode == exportBlock {
		spec.Verified = nil
	}
	// A block's unreachable rules the set did not measure go back under
	// unreachable, commented as the operator's, and a set carries none of
	// them (task 14 review M7).
	var listed map[string][]string
	if mode != exportShow && spec.UnreachableNote != nil {
		if mode == exportBlock {
			listed = *spec.UnreachableNote
			unreachable := map[string][]string{}
			if spec.Unreachable != nil {
				for level, rules := range *spec.Unreachable {
					unreachable[level] = slices.Clone(rules)
				}
			}
			for level, rules := range listed {
				unreachable[level] = append(unreachable[level], rules...)
			}
			spec.Unreachable = &unreachable
		}
		spec.UnreachableNote = nil
	}
	var folded []string
	if mode != exportShow && spec.FallbackNote != nil {
		if mode == exportBlock {
			fallback := map[string]string{}
			if spec.Fallback != nil {
				fallback = maps.Clone(*spec.Fallback)
			}
			for level, note := range *spec.FallbackNote {
				fallback[level] = note
				folded = append(folded, level)
			}
			spec.Fallback = &fallback
		}
		spec.FallbackNote = nil
	}
	var doc yaml.Node
	if err := doc.Encode(map[string]map[string]platform.Spec{"platforms": {name: spec}}); err != nil {
		return nil, err
	}
	if unreachable := mappingValue(mappingValue(mappingValue(&doc, "platforms"), name), "unreachable"); unreachable != nil {
		for level, rules := range listed {
			if v := mappingValue(unreachable, level); v != nil && v.Kind == yaml.SequenceNode {
				for _, item := range v.Content {
					if slices.Contains(rules, item.Value) {
						item.LineComment = operatorListed
					}
				}
			}
		}
	}
	if fallback := mappingValue(mappingValue(mappingValue(&doc, "platforms"), name), "fallback"); fallback != nil {
		for _, level := range folded {
			if v := mappingValue(fallback, level); v != nil {
				v.LineComment = notMeasured
			}
		}
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// mappingValue is the value under key in a mapping node, or nil.
func mappingValue(n *yaml.Node, key string) *yaml.Node {
	if n != nil && n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		n = n.Content[0]
	}
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
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

// exportClasses prints a projected platform's reference device configuration
// (spec §8): the configuration its replies rest on, the bitless `remote`
// template, and each level's template and class where the adapter sends one,
// every class carrying idle-timeout from port49d.yaml's
// session.max_session_age_default (spec §5.6; §13 decision 21). Loading it
// clears what is written under each template, and not what reaches one from
// outside — a group applied from above, a deactivated or protected ancestor
// (platform.ReferenceClasses) — so the header says check-config is what
// proves the device. A compliance tool checks devices against it; port49
// never logs into one.
//
// A device_config line redaction changed — a block's `tacplus-server ...
// secret` — prints as a `#` comment, which `load set terminal` does not
// apply: loaded, the marker would replace the device's TACACS+ secret, and
// every login would fall to local. stderr counts those lines, each one the
// operator writes by hand with its real value; check-config reads the
// unredacted floor, so it reports the line missing until the device carries
// it (task 13 re-review I4). hidden names them by index in d.DeviceConfig,
// and any line carrying the marker is one whatever hidden says.
func exportClasses(stdout, stderr io.Writer, name, platformName string, d platform.Dialect, cfgPath string, a adapters,
	p *policy.Policy, hidden map[int]bool) int {
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", name, err)
		return 1
	}
	age, err := config.MaxSessionAge(raw)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %s: %v\n", name, cfgPath, err)
		return 1
	}
	lines, err := platform.ReferenceClasses(d, age)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %s: %v\n", name, platformName, err)
		return 1
	}
	setName := a.set
	if p != nil {
		setName = p.PlatformSet()
	}
	fmt.Fprintf(stdout, "# %s: reference configuration, platform set %s (spec §8). Load it with `load set "+
		"terminal`: each template class and user is deleted before it is set, which clears what was written under "+
		"one. It does not clear what reaches a template from outside it: a configuration group applied from above "+
		"still applies to the loaded class, a deactivated ancestor leaves the loaded lines inactive, and a protected "+
		"one fails the load. `port49 devices check-config --config` on a whole `show configuration | display set` "+
		"capture is what proves the device carries the template and nothing more. idle-timeout is "+
		"session.max_session_age_default (%s) in whole minutes: a session-only device never asks port49 again after "+
		"login, so this timer is what ends a session there (decision 21).\n", platformName, setName, age)
	held := 0
	for i, line := range lines {
		if i < len(d.DeviceConfig) && hidden[i] || strings.Contains(line, platform.Redacted) {
			held++
			line = "# " + strings.ReplaceAll(line, platform.Redacted, "<set this yourself: redacted>")
		}
		fmt.Fprintln(stdout, line)
	}
	if held > 0 {
		fmt.Fprintf(stderr, "%s: %s: %d device_config lines carry a secret, so each is printed as a # comment that "+
			"`load set terminal` does not apply: write each by hand with its real value; check-config reports it "+
			"MISSING until the device carries it\n", name, platformName, held)
	}
	return 0
}

// referenceDeviceConfig is the device_config floor check-config holds a
// device to (Policy.ConfigDialect), so the reference prints the same lines —
// one a `replace: true` block drops is still one the check reports missing —
// redacted, with the index of every line redaction changed.
func referenceDeviceConfig(p *policy.Policy, platformName string, patterns []platform.Redaction,
	secret map[string]bool) ([]string, map[int]bool, error) {
	floor, err := p.ConfigDialect(platformName)
	if err != nil {
		return nil, nil, err
	}
	shown := platform.RedactAdapter(patterns, secret, floor).DeviceConfig
	hidden := map[int]bool{}
	for i, line := range shown {
		if line != floor.DeviceConfig[i] {
			hidden[i] = true
		}
	}
	return shown, hidden, nil
}
