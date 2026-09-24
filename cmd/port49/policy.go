package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/replay"
)

// policyFiles are the two files every policy tool reads: the policy and the
// inventory it is checked against (spec §10, §12). The tools run offline, as
// CI runs them; they never ask a broker.
type policyFiles struct{ policy, inventory string }

// offlineEnv is the environment the offline tools load a policy in: the
// inventory, and the built-in enable-username table port49d resolves from
// config, so a joint check port49d runs (`enable: auto`) runs here too.
// Config accepts no override of it today (config.resolveEnableUsernames).
func offlineEnv(devices []admission.Device) policy.Env {
	return policy.Env{Devices: devices, EnableUsernames: platform.EnableUsernames()}
}

func (f *policyFiles) register(fs *flag.FlagSet) {
	fs.StringVar(&f.policy, "policy", "", "the policy file")
	fs.StringVar(&f.inventory, "inventory", "", "the inventory file the daemon admits from (inventory_file)")
}

func (f *policyFiles) load() (*policy.Policy, error) {
	if f.policy == "" || f.inventory == "" {
		return nil, fmt.Errorf("--policy and --inventory are both required")
	}
	inv, err := admission.LoadFile(f.inventory)
	if err != nil {
		return nil, err
	}
	return policy.Load(f.policy, offlineEnv(inv.Devices))
}

// explainCmd resolves a hypothetical decision and prints exactly one reason
// (spec §12). It exits 0 whether the answer is permit or deny: the answer is
// the output, and an error is a policy or a name that did not load.
func explainCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 explain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var files policyFiles
	files.register(fs)
	subject := fs.String("subject", "", "the subject, by its name in the policy")
	principal := fs.String("principal", "", "or the principal, e.g. user:alice@example.com")
	device := fs.String("device", "", "the device, by its inventory name")
	command := fs.String("command", "", "the command line, quoted; omit it to see the session")
	attrs := fs.Bool("show-attributes", false, "show the session attributes and where each came from")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if (*subject == "") == (*principal == "") || *device == "" || fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	p, err := files.load()
	if err != nil {
		fmt.Fprintln(stderr, "port49 explain:", err)
		return 1
	}
	e, err := p.Explain(*subject, *principal, *device, *command, time.Now())
	if err != nil {
		fmt.Fprintln(stderr, "port49 explain:", err)
		return 1
	}
	e.Render(stdout, *attrs)
	return 0
}

// policyCmd runs `port49 policy SUBCOMMAND`.
func policyCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "test":
		return policyTest(args[1:], stdout, stderr)
	case "replay":
		return policyReplay(args[1:], stdout, stderr)
	case "diff":
		return policyDiff(args[1:], stdout, stderr)
	}
	fmt.Fprint(stderr, usage)
	return 2
}

// policyTest is the CI gate (spec §11, §12): it loads the policy against the
// inventory — every load-time check is a failure here — prints what CI must
// report without refusing, the shadowed-deny report, then runs the file's
// tests. It exits 1 if the policy does not load, any test fails, or a deny is
// shadowed and no test exercises it.
func policyTest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 policy test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var files policyFiles
	files.register(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	p, err := files.load()
	if err != nil {
		fmt.Fprintln(stderr, "port49 policy test:", err)
		return 1
	}
	now := time.Now()
	// A quarantined device is reported, not a failure of its own: the policy
	// loaded, and decision 20 exists so one device cannot block the rest. A
	// test on it fails in the ordinary way, as device_quarantined. An entry an
	// expiry will bring on is reported too, so CI sees it before it lands.
	for _, q := range p.Quarantines(now) {
		for _, e := range q.Entries {
			fmt.Fprintf(stdout, "quarantine: %s (%s): %s\n", q.Device, q.Platform, e.Message(now))
		}
	}
	for _, f := range p.Lint(now) {
		fmt.Fprintf(stdout, "report: %s: %s\n", f.Kind, f.Message)
	}
	// The shadowed-deny report is what replaces the guarantee deny-overrides
	// gave (spec §12): every deny a more specific permit beats, for whom, and
	// by what, now and once any grant expires. One no policy test exercises
	// fails the gate; a possible one, which two regex or class terms decide,
	// is reported and does not, until a test proves the two meet.
	shadows := p.ShadowedDenies(now)
	unacknowledged := 0
	for _, s := range shadows {
		line := fmt.Sprintf("%q (%s) does not bind %s where %q (%s) is more specific, on %s", s.Deny, s.DenyRole,
			s.Subject, s.Permit, s.PermitRole, strings.Join(s.Platforms, ", "))
		switch {
		case s.Acknowledged:
			fmt.Fprintf(stdout, "shadowed: %s; a policy test exercises it\n", line)
		case s.Possible:
			fmt.Fprintf(stdout, "possibly shadowed: %s; two regex or class terms decide it, which is not "+
				"decidable cheaply\n", line)
		default:
			// The pair is judged alone: another deny may stop the permit on
			// every command it meets this one, and then no test can pass.
			unacknowledged++
			fmt.Fprintf(stdout, "shadowed: %s; no policy test exercises it: add one that expects permit on a "+
				"command where this permit wins, or narrow the permit (a permit another deny always stops "+
				"cannot win: narrow it)\n", line)
		}
	}
	results := p.RunTests(now)
	failed := 0
	for _, r := range results {
		who := r.Test.Subject
		if who == "" {
			who = r.Test.Principal
		}
		got := "deny"
		if r.Permit {
			got = "permit"
		}
		status := "PASS"
		if !r.Pass {
			status = "FAIL"
			failed++
		}
		line := fmt.Sprintf("%s %s on %s: %q -> %s %s", status, who, r.Test.Device, r.Test.Command, got, r.Reason)
		if r.MintError != "" {
			line = fmt.Sprintf("%s %s on %s: %q -> deny: the broker refuses the mint, %s", status, who,
				r.Test.Device, r.Test.Command, r.MintError)
		}
		if r.Err != nil {
			line = fmt.Sprintf("%s %s on %s: %q -> error: %v", status, who, r.Test.Device, r.Test.Command, r.Err)
		} else if !r.Pass {
			want := r.Test.Expect
			if r.Test.Reason != "" {
				want += " " + r.Test.Reason
			}
			line += ", want " + want
		}
		fmt.Fprintln(stdout, line)
		for _, c := range r.Caveats {
			fmt.Fprintf(stdout, "     note: %s\n", c)
		}
	}
	fmt.Fprintf(stdout, "%d tests, %d failed; %d shadowed denies, %d unacknowledged\n", len(results), failed,
		len(shadows), unacknowledged)
	if failed > 0 || unacknowledged > 0 {
		return 1
	}
	return 0
}

// policyDiff is the effective-permission diff and the privilege-expansion
// gate (spec §12): both versions of a policy, loaded against one inventory,
// compared for every subject on every device over every command shape their
// rules distinguish, now and at every later grant expiry. It prints each
// change and exits 1 on a command the old version refused (by a deny, at a
// pipeline stage, or by quarantining the device) that the new version
// permits and no policy test in it exercises, on a device the new version
// quarantines for a new cause, on a subject whose mint the new version's
// broker refuses where the old did not, and on a composition it could not
// compare.
func policyDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 policy diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	oldPath := fs.String("old", "", "the policy file as it is")
	newPath := fs.String("new", "", "the policy file as the change would leave it")
	inventory := fs.String("inventory", "", "the inventory file the daemon admits from (inventory_file)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" || *inventory == "" || fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	inv, err := admission.LoadFile(*inventory)
	if err != nil {
		fmt.Fprintln(stderr, "port49 policy diff:", err)
		return 1
	}
	before, err := policy.Load(*oldPath, offlineEnv(inv.Devices))
	if err != nil {
		fmt.Fprintln(stderr, "port49 policy diff: --old:", err)
		return 1
	}
	after, err := policy.Load(*newPath, offlineEnv(inv.Devices))
	if err != nil {
		fmt.Fprintln(stderr, "port49 policy diff: --new:", err)
		return 1
	}
	now := time.Now()
	d := policy.Compare(before, after, now)
	// A change that first holds at a later grant expiry says when.
	from := func(at time.Time) string {
		if at.After(now) {
			return " (from " + decision.FormatTime(at) + ")"
		}
		return ""
	}
	for _, u := range d.Unresolved {
		fmt.Fprintf(stdout, "UNRESOLVED: %s; the diff cannot vouch for it\n", u)
	}
	for _, q := range d.Quarantined {
		for _, e := range q.Entries {
			fmt.Fprintf(stdout, "QUARANTINES: %s (%s): %s\n", q.Device, q.Platform, e.Message(now))
		}
	}
	for _, r := range d.Refused {
		fmt.Fprintf(stdout, "REFUSED: %s on %s%s: the new version's broker refuses every mint there, %s (%s)\n",
			r.Subject, strings.Join(r.Devices, ", "), from(r.At), r.Code, r.Detail)
	}
	for _, r := range d.Released {
		fmt.Fprintf(stdout, "RELEASES: %s (%s)%s: the old version quarantines it, so every command the new one "+
			"permits there is an expansion\n", r.Device, r.Platform, from(r.At))
	}
	for _, a := range d.Access {
		verb := "loses"
		if a.Gained {
			verb = "gains"
		}
		fmt.Fprintf(stdout, "access: %s %s every grant on %s%s\n", a.Subject, verb, strings.Join(a.Devices, ", "),
			from(a.At))
	}
	for _, l := range d.Levels {
		fmt.Fprintf(stdout, "privilege: %s on %s%s: level %s -> %s, max_privilege %s -> %s\n", l.Subject,
			strings.Join(l.Devices, ", "), from(l.At), orNone(l.OldLevel), orNone(l.NewLevel), orNone(l.OldCeiling),
			orNone(l.NewCeiling))
	}
	widen, narrow := 0, 0
	for _, c := range d.Changes {
		on := c.Subject + " on " + strings.Join(c.Devices, ", ") + from(c.At)
		if !c.New.Permit {
			narrow++
			fmt.Fprintf(stdout, "narrows: %s: %q was permitted by %q (%s), now %s\n", on, c.Command,
				c.Old.Decided.Rule, c.Old.Decided.Role, c.New.Reason)
			continue
		}
		widen++
		permitted := fmt.Sprintf("now permitted by %q (%s)", c.New.Decided.Rule, c.New.Decided.Role)
		if !c.Gated {
			fmt.Fprintf(stdout, "widens: %s: %q was %s, %s\n", on, c.Command, c.Old.Reason, permitted)
			continue
		}
		label := "EXPANDS"
		if c.Acknowledged {
			label = "expands (a policy test exercises it)"
		}
		var was string
		switch {
		case c.OldRefused != "":
			was = "refused at the mint (" + c.OldRefused + ")"
		case c.Old.Reason == decision.DeviceQuarantined:
			was = "refused (device_quarantined)"
		case c.Old.Reason == decision.PipeStageDenied:
			was = fmt.Sprintf("refused at pipeline stage %d (pipe_stage_denied)", c.Old.Stage)
			permitted = fmt.Sprintf("now permitted by the pipe allowlist entry %q", c.PipeEntry)
		default:
			was = fmt.Sprintf("denied by %q (%s)", c.Old.Deny.Rule, c.Old.Deny.Role)
		}
		fmt.Fprintf(stdout, "%s: %s: %q was %s, %s\n", label, on, c.Command, was, permitted)
	}
	for _, r := range d.Regex {
		on := r.Subject + " on " + strings.Join(r.Devices, ", ") + from(r.At)
		verb := "removed"
		if r.Added {
			verb = "added"
		}
		if r.Deny.Rule != "" {
			fmt.Fprintf(stdout, "regex-constrained: %s: permit %q (%s) meets deny %q (%s), which the change %s; "+
				"the commands they share are not enumerated (spec §12)\n", on, r.Rule.Rule, r.Rule.Role, r.Deny.Rule,
				r.Deny.Role, verb)
			continue
		}
		fmt.Fprintf(stdout, "regex-constrained: %s: %s %q (%s) %s; the commands it matches are not "+
			"enumerated (spec §12)\n", on, r.Rule.Verdict, r.Rule.Rule, r.Rule.Role, verb)
	}
	fmt.Fprintf(stdout, "%d commands changed: %d widen, %d narrow; %d unacknowledged expansions past a deny; "+
		"%d devices newly quarantined, %d released; %d mints newly refused; %d unresolved\n", len(d.Changes), widen,
		narrow, d.Unacknowledged(), len(d.Quarantined), len(d.Released), len(d.Refused), len(d.Unresolved))
	if d.Unacknowledged() > 0 || len(d.Quarantined) > 0 || len(d.Refused) > 0 || len(d.Unresolved) > 0 {
		return 1
	}
	return 0
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// policyReplay re-evaluates a decision log against the blobs it carries
// (spec §5.7, "Replay"): an auditor's reconstruction, a regression check of a
// captured corpus against this build, and an integrity check of the log. It
// prints every record that did not agree and exits 1 if any did not; with
// --line it replays that one record and prints it either way. A record
// denied before policy ran is counted, by reason, and not replayed.
//
// Agreement is about the decision, not about who asked: a command's verdict
// does not depend on the username or principal, so an edit to either on a
// command record replays in agreement. The username, principal and device
// are checked only where they shaped the answer, a session's attributes.
func policyReplay(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 policy replay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	only := fs.Int("line", 0, "replay only the record on this line of the log")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	in := io.Reader(os.Stdin)
	if name := fs.Arg(0); name != "-" {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(stderr, "port49 policy replay:", err)
			return 1
		}
		defer f.Close()
		in = f
	}
	results, err := replay.Replay(in, *only)
	if err != nil {
		fmt.Fprintln(stderr, "port49 policy replay:", err)
		return 1
	}
	counts := map[replay.Status]int{}
	skipped := map[decision.Reason]int{}
	for _, r := range results {
		counts[r.Status]++
		if r.Status == replay.Skipped {
			skipped[r.Reason]++
		}
		if (r.Status != replay.Agree && r.Status != replay.Skipped) || *only != 0 {
			fmt.Fprintf(stdout, "line %d %s: %s %s\n", r.Line, r.Event, r.Status, r.Detail)
		}
	}
	summary := fmt.Sprintf("replayed %d records: %d agree, %d diverge, %d unverifiable; %d not replayed",
		counts[replay.Agree]+counts[replay.Diverge]+counts[replay.Unverifiable],
		counts[replay.Agree], counts[replay.Diverge], counts[replay.Unverifiable], counts[replay.Skipped])
	if len(skipped) > 0 {
		var by []string
		for reason, n := range skipped {
			by = append(by, fmt.Sprintf("%s %d", reason, n))
		}
		slices.Sort(by)
		summary += " (" + strings.Join(by, ", ") + ")"
	}
	fmt.Fprintln(stdout, summary)
	if *only != 0 && len(results) == counts[replay.Skipped] {
		fmt.Fprintf(stderr, "port49 policy replay: line %d is not an authorization record that consulted a blob\n", *only)
		return 1
	}
	if counts[replay.Diverge]+counts[replay.Unverifiable] > 0 {
		return 1
	}
	return 0
}

// accessReview renders the flat grant table for one subject (spec §12): every
// row it appears in, with the scope's size against the inventory and the
// row's expiry. It is the report an access review signs, and `port49 grants
// remove` is what acts on it.
func accessReview(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 access review", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var files policyFiles
	files.register(fs)
	subject := fs.String("subject", "", "the subject, by its name in the policy")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *subject == "" || fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	p, err := files.load()
	if err != nil {
		fmt.Fprintln(stderr, "port49 access review:", err)
		return 1
	}
	now := time.Now()
	rows, err := p.Review(*subject, now)
	if err != nil {
		fmt.Fprintln(stderr, "port49 access review:", err)
		return 1
	}
	s, _ := p.Subject(*subject)
	who := "group " + s.Group
	if s.Group == "" {
		who = "identity " + strings.Join(s.Identity, ", ")
	}
	fmt.Fprintf(stdout, "%s (%s; %s)\n", *subject, s.Domain, who)
	if len(rows) == 0 {
		fmt.Fprintln(stdout, "no grant rows: the subject matches nothing; `port49 grants remove` deletes the block")
		return 0
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SCOPE\tROLES\tMAX_PRIVILEGE\tEXPIRES\tDEVICES")
	for _, r := range rows {
		ceiling, expires := r.MaxPrivilege, "never"
		if ceiling == "" {
			ceiling = "-"
		}
		if !r.Expires.IsZero() {
			expires = r.Expires.UTC().Format(time.RFC3339)
			if r.Expired {
				expires += " (expired)"
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\n", r.Scope, strings.Join(r.Roles, " "), ceiling, expires, r.Devices)
	}
	tw.Flush()
	return 0
}

// grantsRemove is the offboarding path for machine subjects and literal
// identities (spec §12): the policy file with every grant row naming the
// subject deleted, and the subject block with them. It prints the new file on
// stdout for a pull request, or with --write replaces the file in place; the
// result must load against the inventory before anything is written. What it
// removed goes to stderr.
func grantsRemove(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 grants remove", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var files policyFiles
	files.register(fs)
	subject := fs.String("subject", "", "the subject to offboard, by its name in the policy")
	write := fs.Bool("write", false, "replace the policy file instead of printing the result")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *subject == "" || files.policy == "" || files.inventory == "" || fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	raw, err := os.ReadFile(files.policy)
	if err != nil {
		fmt.Fprintln(stderr, "port49 grants remove:", err)
		return 1
	}
	out, removed, err := policy.RemoveSubject(raw, *subject)
	if err != nil {
		fmt.Fprintln(stderr, "port49 grants remove:", err)
		return 1
	}
	inv, err := admission.LoadFile(files.inventory)
	if err != nil {
		fmt.Fprintln(stderr, "port49 grants remove:", err)
		return 1
	}
	if _, err := policy.Parse(out, offlineEnv(inv.Devices)); err != nil {
		fmt.Fprintf(stderr, "port49 grants remove: the policy without %s does not load, so nothing was written: %v\n",
			*subject, err)
		return 1
	}
	if *write {
		if err := replaceFile(files.policy, out); err != nil {
			fmt.Fprintln(stderr, "port49 grants remove:", err)
			return 1
		}
	} else if _, err := stdout.Write(out); err != nil {
		fmt.Fprintln(stderr, "port49 grants remove:", err)
		return 1
	}
	fmt.Fprintf(stderr, "port49 grants remove: %s: %d grant row(s), the subject block, and %d test(s) removed\n",
		*subject, removed.Grants, removed.Tests)
	return 0
}

// replaceFile writes data beside path and renames it over path, so a policy
// file is never left half-written: the data is synced before the rename and
// the directory after it, so a power cut leaves the old file or the new one.
// A symlinked path is followed, so the file it names is what changes, and the
// new file keeps the old one's mode and, where the caller may set them, its
// owner and group, so a daemon that reads it on reload still can.
func replaceFile(path string, data []byte) error {
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := writeSynced(tmp, data, info); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// writeSynced writes data to tmp with old's mode and ownership and syncs it.
func writeSynced(tmp *os.File, data []byte, old os.FileInfo) error {
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(old.Mode().Perm()); err != nil {
		return err
	}
	if st, ok := old.Sys().(*syscall.Stat_t); ok && (int(st.Uid) != os.Geteuid() || int(st.Gid) != os.Getegid()) {
		if err := tmp.Chown(int(st.Uid), int(st.Gid)); err != nil {
			return fmt.Errorf("keeping %s's owner: %w", old.Name(), err)
		}
	}
	return tmp.Sync()
}
