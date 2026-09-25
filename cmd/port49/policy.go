package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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
// inventory, and nothing else. Every adapter fact a joint check reads — the
// enable username that `enable: auto` needs included — is in the policy
// file's platform set and `platforms:` blocks, which port49d loads the same
// way, so CI answers what port49d answers (plan 4 pre-flight N5).
func offlineEnv(devices []admission.Device) policy.Env {
	return policy.Env{Devices: devices}
}

func (f *policyFiles) register(fs *flag.FlagSet) {
	fs.StringVar(&f.policy, "policy", "", "the policy file")
	fs.StringVar(&f.inventory, "inventory", "", "the inventory file the daemon admits from (inventory_file)")
}

// missing reports a usage error: a policy tool needs both files.
func (f *policyFiles) missing() bool { return f.policy == "" || f.inventory == "" }

func (f *policyFiles) load() (*policy.Policy, error) {
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
	if (*subject == "") == (*principal == "") || *device == "" || files.missing() || fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	// What explain prints may be kept: every rule and command it names is
	// redacted as the daemon's records are (spec §5.8).
	out, errOut, flush := redactOutput(stdout, stderr)
	defer flush()
	stdout, stderr = out, errOut
	p, err := files.load()
	if err != nil {
		fmt.Fprintln(stderr, "port49 explain:", err)
		return 1
	}
	out.rules, errOut.rules = p.Redactions(), p.Redactions()
	e, err := p.Explain(*subject, *principal, *device, *command, time.Now())
	if err != nil {
		fmt.Fprintln(stderr, "port49 explain:", err)
		return 1
	}
	e.Redacted(p.Redactions()).Render(stdout, *attrs)
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
// report, the shadowed-deny report, then runs the file's tests. It exits 1 if
// the policy does not load, any test fails, a deny is shadowed and no test
// exercises it, a device is quarantined now or at a later expiry, or a
// composition gets a projection's fail-closed reply (spec §8, "CI MUST refuse
// the policy"; §13 decision 26).
func policyTest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 policy test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var files policyFiles
	files.register(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if files.missing() || fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	// CI keeps what this prints: every rule and command it quotes is
	// redacted as the daemon's records are (spec §5.8).
	out, errOut, flush := redactOutput(stdout, stderr)
	defer flush()
	stderr = errOut
	p, err := files.load()
	if err != nil {
		fmt.Fprintln(stderr, "port49 policy test:", err)
		return 1
	}
	out.rules, errOut.rules = p.Redactions(), p.Redactions()
	stdout = out
	now := time.Now()
	// The set the policy renders with, first: a reviewer reading a rendering
	// change needs to know which adapters produced it (spec §8).
	fmt.Fprintf(stdout, "platform_set: %s\n", p.PlatformSet())
	// A quarantined device fails the gate: the daemon still loads the policy
	// and serves the rest (decision 20), but CI refuses to ship one. An entry
	// an expiry will bring on fails it too, so CI sees it before it lands.
	quarantined := 0
	for _, q := range p.Quarantines(now) {
		for _, e := range q.Entries {
			quarantined++
			fmt.Fprintf(stdout, "quarantine: %s (%s): %s\n", q.Device, q.Platform, quarantineLine(e, now))
		}
	}
	findings := p.Lint(now)
	for _, f := range findings {
		fmt.Fprintf(stdout, "report: %s: %s\n", f.Kind, f.Message)
	}
	refused := policy.ProjectionRefusals(findings)
	// An acknowledge: entry is the author's written word for a widening no
	// test can show (spec §12); review reads each one.
	for _, a := range p.Acknowledgments() {
		fmt.Fprintf(stdout, "acknowledge: %s: %s\n", ackName(a), a.Reason)
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
		if r.Test.Session() {
			line = fmt.Sprintf("%s %s on %s: session -> deny %s", status, who, r.Test.Device, r.Reason)
			if r.Ceiling != "" {
				line = fmt.Sprintf("%s %s on %s: session -> level %s, max_privilege %s, priv_lvl %s, enable %s", status,
					who, r.Test.Device, orNone(r.Level), r.Ceiling, r.PrivLvl, r.Enable)
			}
		} else if (r.Test.Level != "" || r.Test.MaxPrivilege != "" || r.Test.PrivLvl != "" || r.Test.Enable != "") &&
			r.Ceiling != "" {
			line += fmt.Sprintf(" at level %s, max_privilege %s, priv_lvl %s, enable %s", orNone(r.Level), r.Ceiling,
				r.PrivLvl, r.Enable)
		}
		if r.MintError != "" {
			line = fmt.Sprintf("%s %s on %s: %q -> deny: the broker refuses the mint, %s", status, who,
				r.Test.Device, r.Test.Command, r.MintError)
		}
		if r.Err != nil {
			line = fmt.Sprintf("%s %s on %s: %q -> error: %v", status, who, r.Test.Device, r.Test.Command, r.Err)
		} else if !r.Pass {
			var want []string
			if r.Test.Expect != "" {
				want = append(want, r.Test.Expect)
			}
			if r.Test.Reason != "" {
				want = append(want, r.Test.Reason)
			}
			if r.Test.Level != "" {
				want = append(want, "level "+r.Test.Level)
			}
			if r.Test.MaxPrivilege != "" {
				want = append(want, "max_privilege "+r.Test.MaxPrivilege)
			}
			if r.Test.PrivLvl != "" {
				want = append(want, "priv_lvl "+r.Test.PrivLvl)
			}
			if r.Test.Enable != "" {
				want = append(want, "enable "+r.Test.Enable)
			}
			if r.Test.AssertsReply {
				line += ", reply " + yamlList(r.Reply)
				want = append(want, "reply "+yamlList(r.Test.Reply))
			}
			if r.Test.AssertsAPI {
				line += ", api " + yamlList(r.API)
				want = append(want, "api "+yamlList(r.Test.API))
			}
			line += ", want " + strings.Join(want, " ")
		}
		fmt.Fprintln(stdout, line)
		for _, c := range r.Caveats {
			fmt.Fprintf(stdout, "     note: %s\n", c)
		}
	}
	fmt.Fprintf(stdout, "%d tests, %d failed; %d shadowed denies, %d unacknowledged; %d quarantined, %d "+
		"projection refusals\n", len(results), failed, len(shadows), unacknowledged, quarantined, refused)
	if failed > 0 || unacknowledged > 0 || quarantined > 0 || refused > 0 {
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
// permits and no policy test in it exercises, on a level or ceiling raise no
// session test in it asserts, on a regex-constrained widening no policy test
// in it exercises, on a principal who gains a subject or a username change no
// principal session test in it asserts, on a device the new version quarantines for a
// new cause, on a subject whose mint the new version's
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
	// CI keeps what this prints: every rule and command it quotes is
	// redacted as the daemon's records are (spec §5.8).
	out, errOut, flush := redactOutput(stdout, stderr)
	defer flush()
	stderr = errOut
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
	out.rules = append(before.Redactions(), after.Redactions()...)
	errOut.rules = out.rules
	stdout = out
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
			fmt.Fprintf(stdout, "QUARANTINES: %s (%s): %s\n", q.Device, q.Platform, quarantineLine(e, now))
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
	for _, a := range d.StaleAcknowledgments {
		fmt.Fprintf(stdout, "report: acknowledge_stale: %s (%s): no change in this diff is the one it names, so "+
			"it acknowledges nothing; delete it (spec §12)\n", ackName(a), a.Reason)
	}
	for _, a := range d.Adapters {
		change := fmt.Sprintf("%s %s -> %s", adapterKey(a), a.OldShown, a.NewShown)
		switch {
		case !a.Gated:
			fmt.Fprintf(stdout, "adapter: %s\n", change)
		case a.Acknowledged:
			fmt.Fprintf(stdout, "adapter (acknowledged: %s): %s\n", a.AcknowledgedBy, change)
		default:
			fmt.Fprintf(stdout, "ADAPTER: %s: the key changes what port49 decides or what this gate reads, so the "+
				"diff cannot vouch for it; add {platform: %s, field: %s, sha256: %s, reason: \"...\"} under acknowledge: "+
				"(spec §12)\n", change, a.Platform, a.Field, a.Sha256)
		}
	}
	for _, p := range d.Principals {
		switch {
		case !p.Gated:
			fmt.Fprintf(stdout, "principal: %s no longer resolves to a subject (was %s)\n", p.Principal, p.OldSubject)
		case p.Acknowledged:
			fmt.Fprintf(stdout, "principal (a session test asserts it): %s now resolves to subject %s (was %s)\n",
				p.Principal, p.NewSubject, orNone(p.OldSubject))
		default:
			assert := "level: ..."
			if len(p.APIGained) > 0 {
				assert += ", api: " + yamlList(p.APIGained) + " (the subject's whole list)"
			}
			fmt.Fprintf(stdout, "PRINCIPAL: %s now resolves to subject %s (was %s): that person now holds %s's access; "+
				"no session test names the principal: add {principal: %q, device: <a device %s reaches>, %s}\n",
				p.Principal, p.NewSubject, orNone(p.OldSubject), p.NewSubject, p.Principal, p.NewSubject, assert)
		}
	}
	for _, s := range d.Subjects {
		if s.OldGroup != s.NewGroup {
			fmt.Fprintf(stdout, "subject: %s's group %q -> %q; a group subject mints for no one until plan 7\n", s.Subject,
				s.OldGroup, s.NewGroup)
		}
		if !slices.Equal(s.OldAPI, s.NewAPI) {
			label, tail := "api", ""
			switch {
			case len(s.APIGained) > 0 && s.Acknowledged:
				label = "api (a test asserts it)"
			case len(s.APIGained) > 0:
				label, tail = "API", fmt.Sprintf("; the new rights act on other people's sessions, and no test asserts "+
					"them: add {subject: %s, device: <any device>, api: %s}", s.Subject, yamlList(s.NewAPI))
			}
			fmt.Fprintf(stdout, "%s: subject %s's broker rights %s -> %s%s\n", label, s.Subject, yamlList(s.OldAPI),
				yamlList(s.NewAPI), tail)
		}
		if s.OldUsername == s.NewUsername {
			continue
		}
		label, tail := "USERNAME", "; no session test names one of its principals: add one"
		if s.Acknowledged {
			label, tail = "username (a session test asserts it)", ""
		}
		fmt.Fprintf(stdout, "%s: subject %s's username %s -> %s: what every device sees and logs for it%s\n", label,
			s.Subject, s.OldUsername, s.NewUsername, tail)
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
		label, tail := "privilege", ""
		switch {
		case l.Raise && l.Acknowledged:
			label = "raises (a session test asserts it)"
		case l.Raise:
			// The test that acknowledges it, on the first device, asserting
			// each value that rose.
			hint := "{subject: " + l.Subject + ", device: " + l.Devices[0]
			for _, field := range l.Raised {
				if field == "reply" {
					hint += ", reply: " + yamlList(l.NewReply)
					continue
				}
				hint += ", " + field + ": " + orNone(l.NewValue(field))
			}
			label, tail = "RAISES", "; no session test asserts it: add "+hint+"}"
			if slices.Contains(l.Raised, "max_privilege") {
				// The ceiling is how far enable may take the session.
				if l.NewEnable == "none" {
					tail += " (enable is none, so nothing escalates to the ceiling today; setting enable later would)"
				} else {
					tail += " (enable: " + l.NewEnable + " can now escalate the session to the new ceiling)"
				}
			}
		}
		reply := ""
		if !slices.Equal(l.OldReply, l.NewReply) {
			reply = ", reply " + yamlList(l.OldReply) + " -> " + yamlList(l.NewReply)
		}
		fmt.Fprintf(stdout, "%s: %s on %s%s: level %s -> %s, max_privilege %s -> %s, priv_lvl %s -> %s, enable %s -> %s%s%s\n",
			label, l.Subject, strings.Join(l.Devices, ", "), from(l.At), orNone(l.OldLevel), orNone(l.NewLevel),
			orNone(l.OldCeiling), orNone(l.NewCeiling), l.OldPrivLvl, l.NewPrivLvl, l.OldEnable, l.NewEnable, reply, tail)
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
		label, tail := "regex-constrained", ""
		switch {
		case r.Gated && r.AcknowledgedBy != "":
			label = "regex-constrained (acknowledged: " + r.AcknowledgedBy + ")"
		case r.Gated && r.Acknowledged:
			label = "regex-constrained (a policy test exercises it)"
		case r.Gated:
			label, tail = "REGEX-CONSTRAINED", ", and no policy test exercises it"
		}
		if r.Deny.Rule != "" {
			fmt.Fprintf(stdout, "%s: %s: permit %q (%s) meets deny %q (%s), which the change %s; "+
				"the commands they share are not enumerated (spec §12)%s\n", label, on, r.Rule.Rule, r.Rule.Role,
				r.Deny.Rule, r.Deny.Role, verb, tail)
			continue
		}
		fmt.Fprintf(stdout, "%s: %s: %s %q (%s) %s; the commands it matches are not "+
			"enumerated (spec §12)%s\n", label, on, r.Rule.Verdict, r.Rule.Rule, r.Rule.Role, verb, tail)
	}
	fmt.Fprintf(stdout, "%d commands changed: %d widen, %d narrow; %d unacknowledged expansions past a deny; "+
		"%d unacknowledged privilege raises; %d unacknowledged regex-constrained widenings; %d unacknowledged "+
		"principal or username changes; %d devices newly quarantined, %d released; %d mints newly refused; "+
		"%d unresolved; %d unacknowledged adapter edits\n", len(d.Changes), widen, narrow, d.Unacknowledged(),
		d.UnacknowledgedLevels(), d.UnacknowledgedRegex(), d.UnacknowledgedPrincipals(), len(d.Quarantined),
		len(d.Released), len(d.Refused), len(d.Unresolved), d.UnacknowledgedAdapters())
	if d.Unacknowledged() > 0 || d.UnacknowledgedLevels() > 0 || d.UnacknowledgedRegex() > 0 ||
		d.UnacknowledgedPrincipals() > 0 || len(d.Quarantined) > 0 || len(d.Refused) > 0 || len(d.Unresolved) > 0 ||
		d.UnacknowledgedAdapters() > 0 {
		return 1
	}
	return 0
}

// yamlList is a list as a policy file writes it in flow style, each item
// quoted, so a RAISES hint can be pasted as a test.
func yamlList(items []string) string {
	quoted := make([]string, len(items))
	for i, it := range items {
		quoted[i] = strconv.Quote(it)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// ackName is an acknowledge: entry as review reads it: the deny by role and
// rule, or the adapter key by platform and field.
func ackName(a policy.Acknowledgment) string {
	if a.Platform != "" {
		return "platforms." + a.Platform + "." + a.Field
	}
	return fmt.Sprintf("%s %q", a.Role, a.Rule)
}

// quarantineLine is an entry after a label that already says quarantine:
// the cause for one in force now, and when for one an expiry brings on.
func quarantineLine(e policy.QuarantineEntry, now time.Time) string {
	if e.Current(now) {
		return e.Cause
	}
	return e.Message(now)
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
	if *subject == "" || files.missing() || fs.NArg() != 0 {
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
		fmt.Fprintln(stdout, "no grant rows: the subject reaches no device; `port49 grants remove` deletes the block")
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
// stdout, or with --write replaces the file in place, or with --pr opens the
// pull request that carries it (removalPR); the result must load against the
// inventory before anything is written. What it removed goes to stderr.
func grantsRemove(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 grants remove", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var files policyFiles
	files.register(fs)
	subject := fs.String("subject", "", "the subject to offboard, by its name in the policy")
	write := fs.Bool("write", false, "replace the policy file instead of printing the result")
	pr := fs.Bool("pr", false, "open a pull request that carries the removal, leaving the checkout alone")
	remote := fs.String("remote", "origin", "the remote --pr pushes its branch to")
	base := fs.String("base", "main", "the branch --pr asks to merge into")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *subject == "" || files.missing() || fs.NArg() != 0 || (*write && *pr) {
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
	after, err := policy.Parse(out, offlineEnv(inv.Devices))
	if err != nil {
		fmt.Fprintf(stderr, "port49 grants remove: the policy without %s does not load, so nothing was written: %v\n",
			*subject, err)
		return 1
	}
	switch {
	case *pr:
		// The pull request and git's errors quote the policy; both are
		// redacted as `policy diff`'s output is (spec §5.8).
		url, err := removalPR(files.policy, *subject, out, removed, *remote, *base, after.Redactions())
		if url != "" {
			// Open, even if what followed failed: the error says what is
			// left to clear up.
			fmt.Fprintln(stdout, url)
		}
		if err != nil {
			errOut := &redacting{w: stderr, rules: after.Redactions()}
			fmt.Fprintln(errOut, "port49 grants remove:", err)
			return 1
		}
	case *write:
		if err := replaceFile(files.policy, out); err != nil {
			fmt.Fprintln(stderr, "port49 grants remove:", err)
			return 1
		}
	default:
		if _, err := stdout.Write(out); err != nil {
			fmt.Fprintln(stderr, "port49 grants remove:", err)
			return 1
		}
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
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("%s was replaced, but syncing its directory failed, so a power cut may still bring the "+
			"old file back; check it is on disk: %w", path, err)
	}
	return nil
}

// syncDir makes a rename in dir durable. A test swaps it to fail.
var syncDir = func(dir string) error {
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

// redacting passes what is written through to w a line at a time, with every
// quoted value in each line redacted by rules (platform.RedactQuoted). Until
// a policy loads there are none: a load error quotes no rule text (policy.Parse
// names a rule by role, list and position), and the file's own patterns never
// loaded (spec §5.8).
type redacting struct {
	w     io.Writer
	rules []platform.Redaction
	buf   []byte
}

func (r *redacting) Write(p []byte) (int, error) {
	r.buf = append(r.buf, p...)
	for {
		i := bytes.IndexByte(r.buf, '\n')
		if i < 0 {
			return len(p), nil
		}
		if _, err := io.WriteString(r.w, platform.RedactQuoted(r.rules, string(r.buf[:i+1]))); err != nil {
			return 0, err
		}
		r.buf = r.buf[i+1:]
	}
}

// redactOutput wraps stdout and stderr in redacting writers; flush writes
// what is left of an unfinished line.
func redactOutput(stdout, stderr io.Writer) (out, errOut *redacting, flush func()) {
	out, errOut = &redacting{w: stdout}, &redacting{w: stderr}
	return out, errOut, func() {
		for _, r := range []*redacting{out, errOut} {
			if len(r.buf) > 0 {
				io.WriteString(r.w, platform.RedactQuoted(r.rules, string(r.buf)))
				r.buf = nil
			}
		}
	}
}
