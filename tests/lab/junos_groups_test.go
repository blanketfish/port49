//go:build lab

package lab

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

// TestL57JunosGroups measures what a configuration capture carries for groups
// that reach port49's template classes (spec §15 L57; decision 44 ruling 7).
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
	"set apply-groups p49g-tip",
	"set apply-groups p49g-perm",
	"set apply-groups p49g-excepted",
	"set apply-groups p49g-timeout",
	"set system login class p49-remote apply-groups-except p49g-excepted",
}

// junosGroupsNested is committed apart: whether Junos takes a group applied
// from inside another's definition is itself a cell.
var junosGroupsNested = []string{
	"set groups p49g-inner system login class <p49-*> permissions network",
	"set groups p49g-outer apply-groups p49g-inner",
	"set apply-groups p49g-outer",
}

var junosGroupsDelete = []string{
	"delete apply-groups p49g-tip", "delete apply-groups p49g-perm", "delete apply-groups p49g-excepted",
	"delete apply-groups p49g-timeout", "delete apply-groups p49g-outer",
	"delete system login class p49-remote apply-groups-except",
	"delete groups p49g-tip", "delete groups p49g-perm", "delete groups p49g-excepted", "delete groups p49g-unapplied",
	"delete groups p49g-timeout", "delete groups p49g-outer", "delete groups p49g-inner",
	"delete system login class p49-l57own",
}

// l57Reading is what one capture says about p49-remote.
type l57Reading struct {
	remote                      []string // every set line under system login class p49-remote
	applyLines, groupLines      bool     // `set apply-groups` and `set groups` lines printed
	tip, perm, excepted, nested bool     // each group's statement expanded under p49-remote
	ownTimeout                  bool     // idle-timeout is the reference's 720, not the group's 30
	ownPerm                     bool     // p49g-perm's view-configuration beside p49-l57own's own view
}

func l57Readings(capture string) l57Reading {
	var r l57Reading
	for _, ln := range strings.Split(strings.ReplaceAll(capture, "\r", ""), "\n") {
		ln = strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(ln, "set apply-groups "):
			r.applyLines = true
		case strings.HasPrefix(ln, "set groups "):
			r.groupLines = true
		case strings.HasPrefix(ln, "set system login class p49-remote "):
			r.remote = append(r.remote, ln)
			rest := strings.TrimPrefix(ln, "set system login class p49-remote ")
			r.tip = r.tip || strings.HasPrefix(rest, "login-tip")
			r.perm = r.perm || rest == "permissions view-configuration"
			r.excepted = r.excepted || rest == "permissions clear"
			r.nested = r.nested || rest == "permissions network"
			r.ownTimeout = r.ownTimeout || rest == "idle-timeout 720"
		case ln == "set system login class p49-l57own permissions view-configuration":
			r.ownPerm = true
		}
	}
	return r
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
			if _, err := l.junosTryConfigure(t, []string{`set system root-authentication encrypted-password "` + hash + `"`}); err != nil {
				t.Fatalf("INVALID: the throwaway root hash did not commit (output withheld: it echoes the hash)")
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
		c, run, _ := l.junosLogin(t, "L57 remote", `[]`)
		if c != nil {
			c.Close()
		}
		var b strings.Builder
		fmt.Fprintf(&b, "Reference (set 1.1.0, 12h) applied, then the groups: %s. Nested: %s.\n\n```\n%s\n%s\n```\n\n",
			commitWord(commit), commitWord(nestedCommit), strings.Join(junosGroupsLines, "\n"),
			strings.Join(junosGroupsNested, "\n"))
		b.WriteString("| capture | apply-groups lines | set groups lines | p49g-tip | p49g-perm | p49g-excepted | " +
			"nested | own idle-timeout 720 | group permission beside own |\n|---|---|---|---|---|---|---|---|---|\n")
		for _, cmd := range l57Captures {
			r := l57Readings(caps[cmd])
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s | %s | %s | %s |\n", tableCell(cmd), yesNo(r.applyLines),
				yesNo(r.groupLines), yesNo(r.tip), yesNo(r.perm), yesNo(r.excepted), yesNo(r.nested), yesNo(r.ownTimeout),
				yesNo(r.ownPerm))
		}
		fmt.Fprintf(&b, "\nA token session with no reply attributes (lands in `remote`), `show cli authorization`:\n\n```\n%s\n```\n",
			strings.TrimSpace(run.auth))
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
			"`apply-groups-except`, one applied nowhere, one applied from inside another, and a group's idle-timeout "+
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
