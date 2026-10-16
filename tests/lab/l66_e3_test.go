//go:build lab

package lab

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// L66 (e3) (plan 9f, Task 4): (e)'s moved address, run through the lookup, which checks the address's keys
// against the keys filed under the port49 name before it mints. Run it alone with PORT49_L66_ONLY=e3; it writes
// tests/lab/logs/l66e3-<platform>.md, a section for the results note, and never the note itself.
//
// The premise is `port49 ssh`'s: the device's keys are filed under its name. The cell files them from
// ssh-keyscan. A control then logs in at the device's own address, which has no entry: the lookup copies the
// name's keys there and the play logs in. Then the stand-in's own keys are filed under the stand-in's address
// (an earlier contact that Ansible's auto-add made), the inventory's ansible_host moves there, and the lookup
// must refuse host_key_changed, naming both keys, with no mint, no TACACS+ packet and no connection to the
// stand-in. L66e3b is the same move to a stand-in address with no entry at all: the lookup copies the name's
// keys there and mints, and what the client then does with the stand-in's other key is recorded.

// l66KeyFP is the SHA256 fingerprint ssh-keygen -l prints for a base64 key blob.
func l66KeyFP(blob string) string {
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// l66ScanKeys reads ssh-keyscan's output into "type blob" lines, one per key, in the order given.
func l66ScanKeys(out string) []string {
	var keys []string
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) != 3 || strings.HasPrefix(ln, "#") {
			continue
		}
		keys = append(keys, f[1]+" "+f[2])
	}
	return keys
}

// l66KeyByType maps a key type to the blobs of "type blob" lines.
func l66KeyByType(keys []string) map[string][]string {
	m := map[string][]string{}
	for _, k := range keys {
		t, b, _ := strings.Cut(k, " ")
		m[t] = append(m[t], b)
	}
	return m
}

// l66E3In is what the (e3) refusal is graded on.
type l66E3In struct {
	Failed                  bool
	ErrText                 string
	Dev, Stand              []string // "type blob" lines of the device's keys (filed under its name) and the stand-in's
	Mints, Redeems, Packets int
	Other                   []string
	StandinConnects         int
}

// l66GradeE3 is whether the lookup refused as ruling 15 says: host_key_changed, naming both keys of every type
// the device and the stand-in share, with nothing minted, no TACACS+ exchange and no connection to the stand-in.
func l66GradeE3(in l66E3In) (bool, string) {
	var why []string
	if !in.Failed {
		why = append(why, "the play did not fail")
	}
	if !strings.Contains(in.ErrText, "host_key_changed") {
		why = append(why, "the error does not carry the code host_key_changed")
	}
	dev, st := l66KeyByType(in.Dev), l66KeyByType(in.Stand)
	shared := 0
	for t, blobs := range dev {
		if _, ok := st[t]; !ok {
			continue
		}
		shared++
		for _, b := range append(append([]string{}, blobs...), st[t]...) {
			if fp := l66KeyFP(b); fp == "" || !strings.Contains(in.ErrText, fp) {
				why = append(why, fmt.Sprintf("the error does not name the %s key %s", t, fp))
			}
		}
	}
	if shared == 0 {
		why = append(why, "the device and the stand-in share no key type, so the cell cannot be graded")
	}
	if in.Mints != 0 {
		why = append(why, fmt.Sprintf("%d mint record(s): the broker minted", in.Mints))
	}
	if in.Redeems != 0 || in.Packets != 0 || len(in.Other) != 0 {
		why = append(why, fmt.Sprintf("a TACACS+ exchange: %d packets, %d redeems, other records %v", in.Packets, in.Redeems, in.Other))
	}
	if in.StandinConnects != 0 {
		why = append(why, fmt.Sprintf("the stand-in saw %d connection(s)", in.StandinConnects))
	}
	return len(why) == 0, strings.Join(why, "; ")
}

var l66ProbeRe = regexp.MustCompile(`L66PROBE\[([^\]]*)\]`)

// l66KeywordPlay makes a rendered play a `connection:` keyword play, with a probe task that reads, first,
// what `ansible_connection` is to a lookup (the vars lookup is given the variables a lookup is given) and,
// second, what hostvars says.
func l66KeywordPlay(pb string) string {
	pb = strings.Replace(pb, "  hosts: all\n", "  hosts: all\n  connection: ansible.netcommon.network_cli\n", 1)
	probe := "  pre_tasks:\n    - name: probe the connection variable\n      ansible.builtin.debug:\n" +
		"        msg: \"L66PROBE[lookup={{ lookup('ansible.builtin.vars', 'ansible_connection', default='UNSET') }} " +
		"hostvars={{ hostvars[inventory_hostname].ansible_connection | default('UNSET') }}]\"\n"
	return strings.Replace(pb, "  pre_tasks:\n", probe, 1)
}

// scan reads the host keys of addr with ssh-keyscan, in a private home, and returns "type blob" lines.
func (e *l66Env) scan(ctx context.Context, addr string) ([]string, error) {
	out, se, exit, err := l64Run(ctx, e.env(), e.home, "ssh-keyscan", "-T", "10", addr)
	keys := l66ScanKeys(out)
	if err != nil || len(keys) == 0 {
		return nil, fmt.Errorf("ssh-keyscan %s: exit %d %v, %d keys %s", addr, exit, err, len(keys), trimForNote(se))
	}
	return keys, nil
}

// fileKeys appends "host type blob" lines to the private known_hosts file.
func (e *l66Env) fileKeys(host string, keys []string) error {
	f, err := os.OpenFile(e.khPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, k := range keys {
		if _, err := fmt.Fprintf(f, "%s %s\n", host, k); err != nil {
			return err
		}
	}
	return nil
}

func l66FPs(keys []string) string {
	var out []string
	for _, k := range keys {
		t, b, _ := strings.Cut(k, " ")
		out = append(out, t+" "+l66KeyFP(b))
	}
	return strings.Join(out, ", ")
}

// cellE3 is one (e3) cell. mode is "std" (the stand-in's keys are filed under its address), "fresh" (the stand-in
// has no entry: record) or "keyword" (std, with the connection named by the play's keyword alone).
func (e *l66Env) cellE3(id, sshType, mode string) {
	e.labGuard()
	kind := "refusal"
	if mode == "fresh" {
		kind = "record"
	}
	fresh := mode == "fresh" || mode == "noauto"
	e.cell(id, kind, l66Budget, func(ctx context.Context) (bool, string) {
		if _, err := e.baseline(ctx, false); err != nil {
			e.addInvalid(err.Error())
			return false, ""
		}
		dev, err := e.scan(ctx, e.l.p.addr)
		if err != nil {
			e.addInvalid(err.Error())
			return false, ""
		}
		if err := e.fileKeys(e.node, dev); err != nil {
			e.addInvalid("filing the device's keys under its name: " + err.Error())
			return false, ""
		}
		if err := e.startStandin(ctx); err != nil {
			e.addInvalid("the stand-in sshd could not be started: " + err.Error())
			return false, ""
		}
		stand, err := e.scan(ctx, l66StandinAddr)
		if err != nil {
			e.addInvalid(err.Error())
			return false, ""
		}
		mk := func(addr string) l66InvSpec {
			s := e.spec("fact", sshType)
			s.Hosts[0].Address = addr
			s.NoConn = mode == "keyword"
			return s
		}
		opts := l66Opts{hostKeys: true, noAutoAdd: mode == "noauto"}
		if mode == "keyword" {
			opts.playbook = l66KeywordPlay
		}
		before := e.readKnownHosts()
		r1, err := e.runPlay(ctx, id+"-device", "once", 1, "", mk(e.l.p.addr), opts)
		if err != nil {
			e.addInvalid(err.Error())
			return false, ""
		}
		e.controlOK = l64ControlOK(r1.packets, r1.counts.Redeems) && r1.recap[e.node].Passed()
		kh1 := e.readKnownHosts()
		d1 := l66DiffKH(before, kh1)
		probe := ""
		if m := l66ProbeRe.FindStringSubmatch(r1.stdout); m != nil {
			probe = " The probe task read `ansible_connection` as `" + m[1] + "`."
		} else if mode == "keyword" {
			probe = " The probe task's output was not found."
		}
		ctl := fmt.Sprintf("The control, at the device's own address `%s` with no entry for it, the device's keys filed under `%s` (%s): "+
			"%s. The lookup or Ansible filed %d line(s) (%s); control %v.%s", e.l.p.addr, e.node, l66FPs(dev), r1.summary(e.node),
			len(d1.Added), l66Shorts(d1.Added), e.controlOK, probe)
		if !fresh {
			if err := e.fileKeys(l66StandinAddr, stand); err != nil {
				e.addInvalid("filing the stand-in's keys under its address: " + err.Error())
				return false, ""
			}
		}
		mark := len(l66ParseStandin(e.standinLog(ctx)))
		quiet := e.waitQuiet(ctx)
		r2, err := e.runPlay(ctx, id+"-standin", "once", 1, "", mk(l66StandinAddr), opts)
		if err != nil {
			e.addInvalid(err.Error())
			return false, ""
		}
		d2 := l66DiffKH(kh1, e.readKnownHosts())
		tally := l66TallyStandin(l66ParseStandin(e.standinLog(ctx))[mark:])
		errText := l66ErrorText(r2.text(), 3000)
		move := fmt.Sprintf("Step 2, `ansible_host` moved to the stand-in `%s` (host keys %s)", l66StandinAddr, l66FPs(stand))
		if !fresh {
			move += ", whose keys were filed under that address first (the contact an earlier auto-add made)"
		} else {
			move += ", with no entry for that address"
		}
		move += fmt.Sprintf(". %s. ansible-playbook: %s. The error: `%s`. File changes: added %s, gone %s. The broker minted %d time(s) "+
			"for this play; TACACS+ packets %d, redeems %d. The stand-in saw %d connection(s), %d password attempt(s), %d keyboard-interactive "+
			"answer(s).", quiet, r2.summary(e.node), errText, l66Shorts(d2.Added), l66Shorts(d2.Removed), r2.counts.Mints, r2.packets,
			r2.counts.Redeems, tally.Connects, tally.Passwords, tally.Kbdint)
		if mode == "noauto" {
			_, presented := l66GradeMoved(tally, e.hashes, r2.hashes)
			ok := !r2.recap[e.node].Passed() && !presented && r2.packets == 0 && r2.counts.Redeems == 0 && e.controlOK
			note := fmt.Sprintf(" With host_key_checking true and host_key_auto_add false: the play was refused: %v; the minted token was "+
				"presented to the stand-in: %v. The lookup minted %d time(s) (it copies the name's key to the address first).",
				!r2.recap[e.node].Passed(), presented, r2.counts.Mints)
			return ok, ctl + "\n\n" + move + note
		}
		if mode == "fresh" {
			invalid, presented := l66GradeMoved(tally, e.hashes, r2.hashes)
			if invalid != "" {
				// A client that never reached the stand-in is a finding here, not a broken run.
				move += " The stand-in was not reached, so the token was not presented to it."
			} else {
				move += fmt.Sprintf(" **The minted token was presented to the stand-in: %v.**", presented)
			}
			return true, ctl + "\n\n" + move
		}
		pass, why := l66GradeE3(l66E3In{Failed: !r2.recap[e.node].Passed(), ErrText: r2.text(), Dev: dev, Stand: stand,
			Mints: r2.counts.Mints, Redeems: r2.counts.Redeems, Packets: r2.packets, Other: r2.counts.Other, StandinConnects: tally.Connects})
		if why != "" {
			why = " **Not as claimed:** " + why + "."
		}
		return pass, ctl + "\n\n" + move + why
	})
}

// runL66E3 runs the (e3) cells and writes their section.
func runL66E3(e *l66Env, only string) {
	if only == "e3d" {
		for _, t := range []string{"libssh", "paramiko"} {
			e.cellE3("L66e3d-"+t, t, "noauto")
		}
		l66WriteE3(e)
		return
	}
	for _, t := range []string{"libssh", "paramiko"} {
		e.cellE3("L66e3-"+t, t, "std")
	}
	for _, t := range []string{"libssh", "paramiko"} {
		e.cellE3("L66e3c-"+t, t, "keyword")
	}
	for _, t := range []string{"libssh", "paramiko"} {
		e.cellE3("L66e3b-"+t, t, "fresh")
	}
	l66WriteE3(e)
}

// l66WriteE3 writes the section a results note gets, unless a cell was INVALID. It is a fragment in
// tests/lab/logs, copied into the note by hand after the run is read; nothing here overwrites a note.
func l66WriteE3(e *l66Env) {
	t, l := e.t, e.l
	if ok, why := l66Writable(e.results); !ok {
		fmt.Fprintf(os.Stdout, "L66 %s NO_NOTE %s\n", l.p.name, why)
		t.Errorf("%s: the run is INVALID, so no section is written (%s)", l.p.name, why)
		return
	}
	var b strings.Builder
	day := time.Now().UTC().Format("2006-01-02")
	fmt.Fprintf(&b, "## (e3) — %s\n\n", day)
	fmt.Fprintf(&b, "- **Platform:** %s (containerlab node `%s`, %s)\n- **Image version:** %s (`%s`)\n- **Capture:** %s\n- **Run:** %s, `PORT49_L66_ONLY=e3`\n\n",
		l.p.name, l.p.node, l.p.addr, l.p.version, l.p.image, l.captureLine(t), runLine())
	fmt.Fprintf(&b, "Versions in this run: %s.\n\n", e.versions)
	b.WriteString("| cell | outcome | elapsed |\n|---|---|---|\n")
	for _, r := range e.results {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", r.id, r.outcome, r.elapsed.Round(100*time.Millisecond))
	}
	for _, r := range e.results {
		fmt.Fprintf(&b, "\n### %s: %s\n\n%s\n", r.id, r.outcome, r.observation)
	}
	dir := filepath.Join(root, "tests", "lab", "logs")
	_ = os.MkdirAll(dir, 0o755)
	p := filepath.Join(dir, "l66e3-"+l.p.name+".md")
	if err := os.WriteFile(p, []byte(labcreds.RedactNote(l66Scrub(b.String(), e.hashes, labcreds.TokenLen))), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	t.Logf("wrote %s", p)
}

// l66StopSentinel and l66DiskFloorMB are the lab's rules: a file there stops every run at its next cell, and a
// free root filesystem below the floor does too.
const (
	l66StopSentinel = "/tmp/port49-STOP-LAB"
	l66DiskFloorMB  = 67584
)

// labGuard ends the run (a Fatal, so the teardown defers run) when the stop sentinel exists or the disk is below
// the floor. It runs before each cell.
func (e *l66Env) labGuard() {
	if _, err := os.Stat(l66StopSentinel); err == nil {
		e.t.Fatalf("%s exists: the lab run stops before %s", l66StopSentinel, "the next cell")
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil {
		e.t.Fatalf("statfs /: %v", err)
	}
	if free := int64(st.Bavail) * int64(st.Bsize) / (1 << 20); free < l66DiskFloorMB {
		e.t.Fatalf("%dM free on /, below the %dM floor: the lab run stops", free, l66DiskFloorMB)
	}
}
