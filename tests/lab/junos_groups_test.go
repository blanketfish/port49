//go:build lab

package lab

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	adapter "github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// throwawayCryptHash is a SHA-512 crypt hash of 32 random bytes that are
// discarded at once, so nothing can log in with it. The hash goes only to the
// device, never to a note or a log.
func throwawayCryptHash() (string, error) {
	pw := make([]byte, 32)
	if _, err := rand.Read(pw); err != nil {
		return "", err
	}
	cmd := exec.Command("openssl", "passwd", "-6", "-stdin")
	cmd.Stdin = strings.NewReader(hex.EncodeToString(pw) + "\n")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("openssl passwd: %v", err)
	}
	h := strings.TrimSpace(string(out))
	if !strings.HasPrefix(h, "$6$") {
		return "", fmt.Errorf("openssl passwd did not print a SHA-512 crypt hash")
	}
	return h, nil
}

// TestL57JunosGroups (below) measures what a configuration capture carries for
// groups that reach port49's template classes (spec §15 L57; decision 44
// ruling 7).
var junosGroupsLines = []string{
	"set groups p49g-tip system login class <*> login-tip",
	"set groups p49g-perm system login class <p49-*> permissions view-configuration",
	`set groups p49g-perm system login class <p49-*> allow-commands "^show version$"`,
	"set groups p49g-excepted system login class <*> permissions clear",
	"set groups p49g-unapplied system login class <*> permissions all",
	"set groups p49g-timeout system login class <*> idle-timeout 30",
	// A class that writes its own permissions, under p49g-perm's <p49-*>:
	// whether Junos adds a group's leaf-list value beside a local one, as a
	// local_user_name template would meet it (pre-flight, R5).
	"set system login class p49-l57own permissions view",
	// The user a same-run session logs in as, to land in p49-l57own: the
	// probe's positive control (`show cli authorization` must run there).
	"set system login user p49-l57own class p49-l57own",
	"set apply-groups p49g-tip",
	"set apply-groups p49g-perm",
	"set apply-groups p49g-excepted",
	"set apply-groups p49g-timeout",
	"set system login class p49-remote apply-groups-except p49g-excepted",
}

// junosGroupsNested is committed apart: whether Junos takes a group applied
// from inside another's definition is itself a cell. The inner group adds
// `permissions view`, which a session under p49-remote (view-configuration
// alone) can show by running `show cli authorization`: if the nested group
// applies at login, that command runs.
var junosGroupsNested = []string{
	"set groups p49g-inner system login class <p49-*> permissions view",
	"set groups p49g-outer apply-groups p49g-inner",
	"set apply-groups p49g-outer",
}

// junosGroupsClassLevel is committed apart too: a group applied on the class
// itself, with a harmless leaf under `<p49-*>`. Whether the inherited capture
// strips that `apply-groups` line as it strips the top-level ones decides how a
// capture is tested for "not inherited" (spec §12; ruling 7).
var junosGroupsClassLevel = []string{
	"set groups p49g-classlevel system login class <p49-*> login-alarms",
	"set system login class p49-remote apply-groups p49g-classlevel",
}

var junosGroupsDelete = []string{
	"delete apply-groups p49g-tip", "delete apply-groups p49g-perm", "delete apply-groups p49g-excepted",
	"delete apply-groups p49g-timeout", "delete apply-groups p49g-outer",
	"delete system login class p49-remote apply-groups-except",
	"delete system login class p49-remote apply-groups p49g-classlevel", "delete groups p49g-classlevel",
	"delete groups p49g-tip", "delete groups p49g-perm", "delete groups p49g-excepted", "delete groups p49g-unapplied",
	"delete groups p49g-timeout", "delete groups p49g-outer", "delete groups p49g-inner",
	"delete system login user p49-l57own", "delete system login class p49-l57own",
}

// l57Reading is what one capture says about p49-remote.
type l57Reading struct {
	remote                      []string // every set line under system login class p49-remote
	parsed                      bool     // the capture holds `set` lines at all (the curly form does not)
	applyLines, groupLines      bool     // an `apply-groups` word at any level (not -except), and `set groups` lines
	tip, perm, excepted, nested bool     // each group's statement expanded under p49-remote
	ownTimeout                  bool     // idle-timeout is the reference's 720, not the group's 30
	ownPerm                     bool     // p49g-perm's view-configuration beside p49-l57own's own view
}

func l57Readings(capture string) l57Reading {
	var r l57Reading
	for _, ln := range strings.Split(strings.ReplaceAll(capture, "\r", ""), "\n") {
		ln = strings.TrimSpace(ln)
		r.parsed = r.parsed || strings.HasPrefix(ln, "set ")
		if slices.Contains(strings.Fields(ln), "apply-groups") {
			r.applyLines = true
		}
		switch {
		case strings.HasPrefix(ln, "set groups "):
			r.groupLines = true
		case strings.HasPrefix(ln, "set system login class p49-remote "):
			r.remote = append(r.remote, ln)
			rest := strings.TrimPrefix(ln, "set system login class p49-remote ")
			r.tip = r.tip || strings.HasPrefix(rest, "login-tip")
			r.perm = r.perm || rest == "permissions view-configuration"
			r.excepted = r.excepted || rest == "permissions clear"
			r.nested = r.nested || rest == "permissions view"
			r.ownTimeout = r.ownTimeout || rest == "idle-timeout 720"
		case ln == "set system login class p49-l57own permissions view-configuration":
			r.ownPerm = true
		}
	}
	return r
}

// l57Cell is a reading's table cell: the curly form has no `set` lines, so
// nothing in it was parsed, and "no" would claim a measurement.
func l57Cell(r l57Reading, v bool) string {
	if !r.parsed {
		return "not parsed"
	}
	return yesNo(v)
}

// l57ControlCmd is the remote session's control: p49g-perm gives p49-remote
// view-configuration, so junosHostProbe must run in a session landing there. Its
// evidence is the host name, which a refused command's retyped line lacks.
const l57ControlCmd = "show configuration system host-name"

// l57OwnClass is the class the second session lands in: it holds its own
// `view`, so `show cli authorization` must run there. That is the probe's
// positive control.
const l57OwnClass = "p49-l57own"

// l57NestedWords are the sentences each nested-group session cell prints.
var l57NestedWords = map[string]string{
	"applies": "The nested group APPLIES in a session: `view` reached p49-remote though the inherited capture shows " +
		"no `set groups` line and does not expand it, so check-config cannot see it (a fail-open).",
	"not applied": "The nested group is not applied in a session: `show cli authorization` was refused, its caret under " +
		"`cli`, while the remote session's control ran and the same command printed `Current user` under " + l57OwnClass +
		".",
	"not observed": "Not observed: a session did not open, a control did not run, `show cli authorization` printed " +
		"nothing readable or was refused for another reason. L57 does not close on this cell.",
}

// l57NestedCell reads the nested-group sessions. The remote session (p49-remote,
// view-configuration alone) and the own session (p49-l57own, its own `view`)
// both opened, the remote's control ran with the host name in its output, and
// the own session printed `Current user`; then the remote's `show cli
// authorization` is "applies" where it printed `Current user`, "not applied"
// where it was refused with the caret under `cli`. Anything else is "not
// observed".
func l57NestedCell(remote junosRun, remoteOpened bool, own junosRun, ownOpened bool) string {
	switch {
	case !remoteOpened, remote.loginErr != "", slices.Contains(remote.unobserved, "show cli authorization"),
		slices.Contains(remote.unobserved, l57ControlCmd), !remote.runs(junosProbe{cmd: l57ControlCmd, evidence: junosHostProbe.evidence}),
		strings.TrimSpace(remote.auth) == "":
		return "not observed"
	case !ownOpened, own.loginErr != "", slices.Contains(own.unobserved, "show cli authorization"),
		!strings.Contains(own.auth, "Current user"):
		return "not observed"
	case strings.Contains(remote.auth, "Current user"):
		return "applies"
	case containsAny(strings.ToLower(remote.auth), junosRefusal) &&
		caretOn(caretAt("show cli authorization\n"+remote.auth, len(remote.user+"@"+junosHost+"> ")), "cli"):
		return "not applied"
	}
	return "not observed"
}

var l57Captures = []string{
	"show configuration | display set | display inheritance | no-more",
	"show configuration | display inheritance | display set | no-more",
	"show configuration | display set | no-more",
	"show configuration system login | display inheritance | no-more",
}

func TestL57JunosGroups(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
			t.Skip("Junos only")
		}
		set, ok := adapter.Set("1.1.0")
		if !ok {
			t.Fatal("no set 1.1.0")
		}
		reference, err := adapter.ReferenceClasses(set["juniper_junos"], 12*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		stop := l.capture(t, "L57")
		defer stop()
		l.junosConfigureAdmin(t, reference)
		defer l.junosConfigureAdmin(t, projectionRestore(reference))
		// vSRX 21.4's lab image holds a root-authentication with no password, and
		// a group applied under `system` makes its commit re-check that stanza
		// ("Missing mandatory statement: 'encrypted-password'"); vJunos 23.4 does
		// not. Only there, root gets a throwaway hash for the run: the hash of a
		// random password that is never kept or printed.
		if _, err := l.junosTryConfigure(t, junosGroupsLines); err != nil {
			if !strings.Contains(err.Error(), "Missing mandatory statement: 'encrypted-password'") {
				t.Fatalf("configuring the groups: %v", err)
			}
			hash, err := throwawayCryptHash()
			if err != nil {
				t.Fatalf("INVALID: no throwaway root hash for vSRX's mandatory check: %v", err)
			}
			if err := l.junosTryConfigureWithheld(t, []string{`set system root-authentication encrypted-password "` + hash + `"`},
				"system root-authentication"); err != nil {
				t.Fatalf("INVALID: the throwaway root hash did not commit: %v", err)
			}
			// Not deleted on teardown: deleting it fails the same mandatory check,
			// and the lab's vSRX is a fresh container per run, gone afterwards.
			t.Logf("root-authentication had no password; a throwaway hash was set for this run")
		} else {
			l.junosConfigureAdmin(t, junosGroupsDelete)
		}
		commit := l.junosConfigureAdmin(t, junosGroupsLines)
		defer l.junosConfigureAdmin(t, junosGroupsDelete)
		nestedCommit := l.junosConfigureAdmin(t, junosGroupsNested)
		if !strings.Contains(nestedCommit, "commit complete") {
			l.junosConfigureAdmin(t, []string{"delete apply-groups p49g-outer", "delete groups p49g-outer",
				"delete groups p49g-inner"})
		}
		classCommit := l.junosConfigureAdmin(t, junosGroupsClassLevel)
		if !strings.Contains(classCommit, "commit complete") {
			l.junosConfigureAdmin(t, []string{"delete system login class p49-remote apply-groups p49g-classlevel",
				"delete groups p49g-classlevel"})
		}
		caps := map[string]string{}
		bg, err := l.junosCLI(breakglassUser, breakglassPassword)
		if err != nil {
			t.Fatalf("INVALID: no break-glass CLI: %v", err)
		}
		for _, cmd := range l57Captures {
			out, err := junosShow(bg, cmd)
			if err != nil {
				t.Fatalf("INVALID: %s: %v", cmd, err)
			}
			caps[cmd] = redactConfigCapture(labcreds.RedactNote(out))
		}
		bg.Close()
		// Positive control: p49g-tip has no wildcard but <*>, is applied at the
		// top, and nothing excepts it. If neither inherited capture carries it,
		// the groups did not apply, and nothing below says anything. The
		// fixture is the first inherited form that does: the one Task 7's
		// ConfigCapture becomes.
		inheritedForm := l57Captures[0]
		if !l57Readings(caps[inheritedForm]).tip {
			inheritedForm = l57Captures[1]
		}
		if !l57Readings(caps[inheritedForm]).tip {
			t.Fatalf("INVALID: neither inherited form shows p49g-tip's login-tip under p49-remote; no note is written")
		}
		// A session landing in remote: what a group added, the session holds.
		// Its login already ran `show cli authorization`. The positive control is
		// p49g-perm's view-configuration, which must let `show configuration
		// system host-name` run, or the session says nothing about the nested
		// group.
		c, run, _ := l.junosLogin(t, "L57 remote", `[]`)
		if c != nil {
			out, err := l.junosProbe(c, junosProbe{cmd: l57ControlCmd})
			run.outs[l57ControlCmd] = out
			if err != nil {
				run.unobserved = append(run.unobserved, l57ControlCmd)
			}
			c.Close()
		}
		// The probe's positive control: a session landing in p49-l57own, which
		// holds its own `view`; its login ran `show cli authorization`.
		oc, own, _ := l.junosLogin(t, "L57 own", `["local-user-name=`+l57OwnClass+`"]`)
		if oc != nil {
			oc.Close()
		}
		nestedCell := l57NestedCell(run, c != nil, own, oc != nil)
		var b strings.Builder
		fmt.Fprintf(&b, "Reference (set 1.1.0, 12h) applied, then the groups: %s. Nested: %s. Class-level: %s.\n\n```\n%s\n%s\n%s\n```\n\n",
			commitWord(commit), commitWord(nestedCommit), commitWord(classCommit), strings.Join(junosGroupsLines, "\n"),
			strings.Join(junosGroupsNested, "\n"), strings.Join(junosGroupsClassLevel, "\n"))
		b.WriteString("| capture | `apply-groups` word line (not -except) | set groups lines | p49g-tip | p49g-perm | p49g-excepted | " +
			"nested | own idle-timeout 720 | group permission beside own |\n|---|---|---|---|---|---|---|---|---|\n")
		for _, cmd := range l57Captures {
			r := l57Readings(caps[cmd])
			cell := func(v bool) string { return l57Cell(r, v) }
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s | %s | %s | %s |\n", tableCell(cmd), cell(r.applyLines),
				cell(r.groupLines), cell(r.tip), cell(r.perm), cell(r.excepted), cell(r.nested), cell(r.ownTimeout),
				cell(r.ownPerm))
		}
		fmt.Fprintf(&b, "\nA token session with no reply attributes (lands in `remote`), `show cli authorization`:\n\n```\n%s\n```\n",
			strings.TrimSpace(run.auth))
		fmt.Fprintf(&b, "\nNested group in a session: the inner group adds `permissions view`, so `show cli authorization` runs "+
			"if it was applied at login. Session control `%s` (p49g-perm's view-configuration; ran only with the host "+
			"name in its output):\n\n```\n%s\n```\n\nProbe control, `show cli authorization` under %s (its own `view`; must "+
			"print `Current user`):\n\n```\n%s\n```\n\n"+
			"Nested-group session cell: **%s**. %s\n", l57ControlCmd, strings.TrimSpace(run.outs[l57ControlCmd]), l57OwnClass,
			strings.TrimSpace(own.auth), nestedCell, l57NestedWords[nestedCell])
		for _, cmd := range l57Captures {
			fmt.Fprintf(&b, "\n### `%s` (p49-remote and the group lines)\n\n```\n%s\n```\n", cmd, l57Excerpt(caps[cmd]))
		}
		// The fixture is committed too: no capture may hold a pool token.
		for _, cmd := range l57Captures {
			if err := leakIn(caps[cmd], poolSecrets()); err != nil {
				t.Fatalf("the capture of %q is withheld, and no fixture or note is written: %v", cmd, err)
			}
		}
		fixture := filepath.Join(root, "internal", "platform", "testdata", "l57-"+l.p.name+".set")
		if err := os.MkdirAll(filepath.Dir(fixture), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixture, []byte(caps[inheritedForm]), 0o644); err != nil {
			t.Fatal(err)
		}
		l.entryResult(t, "L57", "What a Junos configuration capture carries for configuration groups that reach port49's "+
			"template class p49-remote: a `<*>` and a `<p49-*>` group applied at the top, one kept off the class by "+
			"`apply-groups-except`, one applied nowhere, one applied from inside another, one applied on the class itself, and a group's idle-timeout "+
			"beside the class's own; in both inherited set forms, plain set form and the inherited curly form; and "+
			"what a session landing in `remote` holds (spec §15 L57; decision 44 ruling 7).", b.String())
	})
}

// l57Excerpt is a capture's lines naming p49g-, apply-groups or p49-remote.
func l57Excerpt(capture string) string {
	var out []string
	for _, ln := range strings.Split(capture, "\n") {
		if strings.Contains(ln, "p49g-") || strings.Contains(ln, "apply-groups") || strings.Contains(ln, "p49-remote") {
			out = append(out, strings.TrimRight(ln, "\r"))
		}
	}
	return strings.Join(out, "\n")
}
