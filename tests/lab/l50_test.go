//go:build lab

package lab

// TestL50WorkloadAttributeWriters is lab register row L50: who can write the
// attribute a workload certificate's directory mapping reads (spec §13
// decision 41 ruling 10), on Samba AD and on Windows Server AD. Run it, from a
// worktree pinned at the commit under test, with
//
//	PORT49_LAB_L50=1 go test -tags lab ./tests/lab/ -run '^TestL50WorkloadAttributeWriters$' -count=1 -v -timeout 240m
//
// PORT49_LAB_WINDOWS_REUSE runs on a kept DC, as L44's does.

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const l50Claim = "Who can write the directory attribute a workload certificate's directory mapping reads (plan 8b; §13 decisions 16, " +
	"40 ruling 5 and 41 ruling 10): on Windows AD and on Samba AD, for a service account's entry in its own OU, and for each " +
	"of `uid`, `description`, `wWWHomePage` and `url` holding a SPIFFE ID, whether the entry itself (`SELF`), a member of " +
	"Account Operators, a delegated OU administrator (\"create, delete and manage user accounts\" on the OU) and an ordinary " +
	"domain user can write it, under the default ACLs and under a candidate ACL plan 8b's docs might prescribe once this row " +
	"closes (an inherited deny of write on that attribute on the OU for each writer that is not a domain administrator); and " +
	"whether each write, accepted or refused, is in the directory's audit log as installed and with directory-change " +
	"auditing turned on (policy engine spec §15 L50)."

var l50Attributes = []string{"uid", "description", "wWWHomePage", "url"}

// l50Writers: the first is the target entry itself (SELF).
var l50Writers = []string{"svc-oxidized-01", "l50-acctop", "l50-ouadmin", "l50-user"}

const (
	l50Default    = "default"
	l50Prescribed = "prescribed"
)

// l50Cell is one write of one attribute by one writer under one ACL state.
// code is the LDAP result code on Samba, 0 when written, and -1 for Windows'
// typed refusal.
type l50Cell struct {
	attr, writer, acl  string
	written, readsBack bool
	code               int
	refused            string
}

func l50RequireOptIn(t *testing.T) {
	t.Helper()
	if os.Getenv("PORT49_LAB_L50") != "1" {
		t.Skip("starts the directories and the Windows DC; set PORT49_LAB_L50=1 to run it")
	}
}

// l50Value is distinct for every write, so a reads-back is never an earlier
// write's.
func l50Value(attr, writer, acl string) string {
	return "spiffe://corp.example.com/host/l50-" + attr + "-" + writer + "-" + acl
}

func TestL50WorkloadAttributeWriters(t *testing.T) {
	l50RequireOptIn(t)
	password, err := winPassword()
	if err != nil {
		t.Fatal(err)
	}
	// Samba first, in its own subtest: its containers are down (and samba.log
	// kept) before the Windows phase's newDirectories removes the logs tree.
	t.Run("samba_ad", func(t *testing.T) {
		sd := startDirectories(t)
		sd.runSel = "^TestL50WorkloadAttributeWriters$"
		sd.extra = append(sd.extra, password)
		ev := evidence(t, sd, "L50-samba_ad")
		cells, notes := sd.samba.l50Samba(t, ev, password)
		ev.assertClean(t, password, sd.password)
		writeResult(t, sd, "L50", sd.samba, l50Claim, sd.samba.version(t),
			sd.samba.configNote()+notes+l50Table(cells), "tests/lab/evidence/L50-samba_ad.json")
	})
	// Then Windows, pass or fail: each platform's note is written even when the
	// other fails.
	t.Run("windows_ad", func(t *testing.T) {
		d := newDirectories(t)
		d.runSel = "^TestL50WorkloadAttributeWriters$"
		d.extra = append(d.extra, password)
		dc := startWindowsDC(t, d)
		ev := evidence(t, d, "L50-windows_ad")
		cells, notes := dc.l50Windows(t, ev, password)
		ev.assertClean(t, append(dc.l44Secrets(), password)...)
		writeResult(t, d, "L50", dc, l50Claim, dc.version(t), notes+l50Table(cells), "tests/lab/evidence/L50-windows_ad.json")
	})
}

// l50Table is the matrix, then one line per writer and ACL naming the
// attributes it could write.
func l50Table(cells []l50Cell) string {
	var b strings.Builder
	b.WriteString("\n### The matrix\n\n| attribute | writer | ACL | written | reads back | refusal |\n|---|---|---|---|---|---|\n")
	for _, c := range cells {
		refusal := "-"
		if !c.written {
			refusal = l44MDCell(c.refused)
			if c.code > 0 {
				refusal = fmt.Sprintf("LDAP result %d: %s", c.code, refusal)
			}
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %v | %v | %s |\n", c.attr, c.writer, c.acl, c.written, c.readsBack, refusal)
	}
	b.WriteString("\n### Who could write what\n\n")
	for _, acl := range []string{l50Default, l50Prescribed} {
		for _, w := range l50Writers {
			var can []string
			for _, c := range cells {
				if c.acl == acl && c.writer == w && c.written && c.readsBack {
					can = append(can, "`"+c.attr+"`")
				}
			}
			list := "none"
			if len(can) > 0 {
				list = strings.Join(can, ", ")
			}
			fmt.Fprintf(&b, "- under the %s ACL, %s could write: %s\n", acl, w, list)
		}
	}
	return b.String() + "\n"
}

// l50AuditPair picks the audit probes from the default cells: a write that was
// accepted and one that was refused (empty when the matrix had none).
func l50AuditPair(cells []l50Cell) (accepted, refused *l50Cell) {
	for i := range cells {
		c := &cells[i]
		if c.acl != l50Default {
			continue
		}
		if c.written && accepted == nil {
			accepted = c
		}
		if !c.written && refused == nil {
			refused = c
		}
	}
	return accepted, refused
}

// ---------------------------------------------------------------------------
// Samba AD
// ---------------------------------------------------------------------------

const l50SambaTarget = "CN=svc-oxidized-01,OU=Workloads," + dirBase

// l50SambaWrite binds as writer and replaces attr on the target with value.
func (l *labDir) l50SambaWrite(ev *evidenceLog, attr, writer, value, acl string, secrets ...string) l50Cell {
	cell := l50Cell{attr: attr, writer: writer, acl: acl, code: -1}
	tc, err := l.d.pki.clientTLS(l.uri)
	if err != nil {
		cell.refused = oneLineMax(err.Error(), 160)
		return cell
	}
	c, err := l.dialTLS(tc)
	if err != nil {
		cell.refused = "dial: " + oneLineMax(winScrub(err.Error(), secrets...), 160)
		return cell
	}
	defer c.Close()
	c.SetTimeout(30 * time.Second)
	if err := c.Bind(writer+"@corp.example.com", secrets[0]); err != nil {
		cell.code = ldapCode(err)
		cell.refused = "bind: " + oneLineMax(winScrub(err.Error(), secrets...), 160)
		return cell
	}
	req := ldap.NewModifyRequest(l50SambaTarget, nil)
	req.Replace(attr, []string{value})
	err = c.Modify(req)
	cell.code = ldapCode(err)
	ev.mark("l50 samba: %s by %s under %s: code %d", attr, writer, acl, cell.code)
	if err != nil {
		cell.refused = oneLineMax(winScrub(err.Error(), secrets...), 160)
		return cell
	}
	cell.written = true
	res, err := c.Search(ldap.NewSearchRequest(l50SambaTarget, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 15, false,
		"(objectClass=*)", []string{attr}, nil))
	if err == nil && len(res.Entries) == 1 {
		cell.readsBack = slices.Contains(res.Entries[0].GetAttributeValues(attr), value)
	}
	return cell
}

// l50SambaSeed runs l50-seed.sh in the container; the password is an
// argument and is never printed. A failure is the harness's.
func (l *labDir) l50SambaSeed(t *testing.T, password string, args ...string) string {
	t.Helper()
	out, err := l.exec(append([]string{"/lab/l50-seed.sh", password}, args...)...)
	if err != nil {
		t.Fatalf("l50-seed.sh %s: %v\n%s", strings.Join(args, " "), err, tailOf(winScrub(out, password), 600))
	}
	return out
}

func (l *labDir) l50Samba(t *testing.T, ev *evidenceLog, password string) (cells []l50Cell, notes string) {
	t.Helper()
	secrets := []string{password, l.d.password}
	var b strings.Builder
	ev.mark("l50 samba: seed")
	l.l50SambaSeed(t, password)
	sddl := l.l50SambaSeed(t, password, "sddl")
	ev.mark("l50 samba: the OU's security descriptor before the default cells was read")
	fmt.Fprintf(&b, "### The OU's security descriptor before the default cells\n\nThe container is fresh each run, so this is the "+
		"default: `samba-tool dsacl get --objectdn=OU=Workloads,%s`\n\n```\n%s\n```\n\n", dirBase, tailOf(winScrub(sddl, secrets...), 4000))

	for _, attr := range l50Attributes {
		for _, w := range l50Writers {
			cells = append(cells, l.l50SambaWrite(ev, attr, w, l50Value(attr, w, l50Default), l50Default, password, l.d.password))
		}
	}
	for _, attr := range l50Attributes {
		ev.mark("l50 samba: acl set %s", attr)
		l.l50SambaSeed(t, password, "acl", "set", attr)
		for _, w := range l50Writers {
			cells = append(cells, l.l50SambaWrite(ev, attr, w, l50Value(attr, w, l50Prescribed), l50Prescribed, password, l.d.password))
		}
		ev.mark("l50 samba: acl clear %s", attr)
		l.l50SambaSeed(t, password, "acl", "clear", attr)
	}

	// The audit. The container runs `samba -i`, which logs to stdout.
	acc, ref := l50AuditPair(cells)
	if acc == nil {
		t.Fatalf("no write was accepted under the default ACLs; the audit has nothing to probe")
	}
	probe := func(phase string) []string {
		since := time.Now().UTC().Format(time.RFC3339)
		time.Sleep(time.Second)
		l.l50SambaWrite(ev, acc.attr, acc.writer, l50Value(acc.attr, acc.writer, "audit-"+phase), "audit-"+phase, password, l.d.password)
		if ref != nil {
			l.l50SambaWrite(ev, ref.attr, ref.writer, l50Value(ref.attr, ref.writer, "audit-"+phase), "audit-"+phase, password, l.d.password)
		}
		time.Sleep(2 * time.Second)
		out, err := l.d.dockerCompose("logs", "--no-color", "--since", since, l.service).CombinedOutput()
		if err != nil {
			t.Fatalf("reading the samba log: %v\n%s", err, tailOf(winScrub(string(out), secrets...), 400))
		}
		var hits []string
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "dsdbChange") && strings.Contains(strings.ToLower(line), strings.ToLower(l50SambaTarget)) {
				hits = append(hits, oneLineMax(winScrub(line, secrets...), 600))
			}
		}
		return hits
	}
	b.WriteString("### The audit\n\nOne accepted write (" + fmt.Sprintf("`%s` by %s", acc.attr, acc.writer) + ")")
	if ref != nil {
		fmt.Fprintf(&b, " and one refused (`%s` by %s)", ref.attr, ref.writer)
	} else {
		b.WriteString(" (no write was refused under the default ACLs, so no refused probe)")
	}
	b.WriteString(" are made twice; the container's log (`docker compose logs`, since the probe) is searched for a `dsdbChange` record naming the target.\n\n")

	ev.mark("l50 samba: audit as installed")
	hits := probe("installed")
	for _, h := range hits {
		ev.mark("l50 samba: as installed: %s", h)
	}
	if len(hits) == 0 {
		b.WriteString("- **As installed: not in the log.** No `dsdbChange` record named the target.\n")
	} else {
		fmt.Fprintf(&b, "- **As installed: in the log** (%d `dsdbChange` record(s)).\n", len(hits))
	}

	// "all", not "samba": the LDAP server's pre-forked workers are separate
	// processes, and "samba" reached only the root process (measured: with
	// "samba" a write through LDAPS logged no dsdbChange).
	if out, err := l.exec("smbcontrol", "all", "debug", "dsdb_json_audit:5 dsdb_audit:5"); err != nil {
		t.Fatalf("smbcontrol debug: %v\n%s", err, tailOf(out, 400))
	}
	ev.mark("l50 samba: audit with dsdb_json_audit:5 dsdb_audit:5")
	hits = probe("debug")
	for _, h := range hits {
		ev.mark("l50 samba: debug: %s", h)
	}
	if len(hits) == 0 {
		t.Fatalf("the audit control saw no dsdbChange after debug dsdb_json_audit:5")
	}
	fmt.Fprintf(&b, "- **After `smbcontrol all debug \"dsdb_json_audit:5 dsdb_audit:5\"`: in the log** (%d `dsdbChange` record(s); `smbcontrol samba debug` reaches only the root process, not the LDAP workers):\n\n", len(hits))
	for _, h := range hits {
		fmt.Fprintf(&b, "  - `%s`\n", strings.ReplaceAll(h, "`", "'"))
	}
	b.WriteString("\n")
	return cells, b.String()
}

// ---------------------------------------------------------------------------
// Windows Server AD
// ---------------------------------------------------------------------------

type l50WinWrite struct {
	Written     bool   `json:"written"`
	ReadsBack   bool   `json:"reads_back"`
	RefusedType string `json:"refused_type"`
	Refused     string `json:"refused"`
}

func (l *labDir) l50WinWrite(t *testing.T, ev *evidenceLog, target, attr, writer, acl, value, password string) l50Cell {
	t.Helper()
	var r l50WinWrite
	l.win.run(t, "write_as", map[string]any{"dn": target, "attribute": attr, "value": value, "user": writer,
		"password": password}, 3*time.Minute, &r)
	cell := l50Cell{attr: attr, writer: writer, acl: acl, written: r.Written, readsBack: r.ReadsBack}
	if !r.Written {
		cell.code = -1
		cell.refused = oneLineMax(winScrub(r.RefusedType+": "+r.Refused, l.l44Secrets()...), 160)
	}
	ev.mark("l50 windows: %s by %s under %s: written %v", attr, writer, acl, r.Written)
	return cell
}

func (l *labDir) l50WinAcl(t *testing.T, ev *evidenceLog, attr, state string) string {
	t.Helper()
	var r struct {
		SDDL string `json:"sddl"`
	}
	l.win.run(t, "audit", map[string]any{"mode": "acl", "attribute": attr, "state": state}, 3*time.Minute, &r)
	ev.mark("l50 windows: acl %s %s: the OU's SDDL is %s", state, attr, oneLineMax(r.SDDL, 4000))
	return r.SDDL
}

func (l *labDir) l50Windows(t *testing.T, ev *evidenceLog, password string) (cells []l50Cell, notes string) {
	t.Helper()
	w := l.win
	secrets := l.l44Secrets()
	var b strings.Builder
	var seed struct {
		OU            string `json:"ou"`
		Target        string `json:"target"`
		RemovedDenies int    `json:"removed_denies"`
		SDDL          string `json:"sddl"`
	}
	w.run(t, "l50_seed", map[string]any{"actor_password": password}, 5*time.Minute, &seed)
	ev.mark("l50 windows: seed; denies removed from a previous run: %d; the OU's SDDL: %s", seed.RemovedDenies, oneLineMax(seed.SDDL, 4000))
	state := "built by this run (not reused): the install's defaults"
	if w.reused {
		state = "a REUSED DC: whatever the previous run left"
	}
	fmt.Fprintf(&b, "### The OU's security descriptor before the default cells\n\nThe DC is %s. The seed removed %d prescribed "+
		"deny(s) of an earlier run from `%s` before the default cells, and the SDDL after that is:\n\n```\n%s\n```\n\n",
		state, seed.RemovedDenies, seed.OU, oneLineMax(winScrub(seed.SDDL, secrets...), 4000))

	// The audit settings as found, before anything changes them (re-review N-1).
	var found struct {
		Changes string `json:"changes"`
		Access  string `json:"access"`
		SACL    string `json:"sacl"`
	}
	w.run(t, "audit", map[string]any{"mode": "state"}, 3*time.Minute, &found)
	ev.mark("l50 windows: audit settings as found: changes=%s | access=%s | sacl=%s", oneLineMax(found.Changes, 400),
		oneLineMax(found.Access, 400), oneLineMax(found.SACL, 400))
	fmt.Fprintf(&b, "### The audit settings as found, before this run changed any\n\nOn %s.\n\n"+
		"- `auditpol` Directory Service Changes: `%s`\n- `auditpol` Directory Service Access: `%s`\n- SACL on the OU: `%s`\n\n",
		state, oneLineMax(found.Changes, 400), oneLineMax(found.Access, 400), oneLineMax(found.SACL, 400))

	for _, attr := range l50Attributes {
		for _, wr := range l50Writers {
			cells = append(cells, l.l50WinWrite(t, ev, seed.Target, attr, wr, l50Default, l50Value(attr, wr, l50Default), password))
		}
	}
	for _, attr := range l50Attributes {
		l.l50WinAcl(t, ev, attr, "set")
		for _, wr := range l50Writers {
			cells = append(cells, l.l50WinWrite(t, ev, seed.Target, attr, wr, l50Prescribed, l50Value(attr, wr, l50Prescribed), password))
		}
		l.l50WinAcl(t, ev, attr, "clear")
	}
	sddl := l.l50WinAcl(t, ev, l50Attributes[0], "clear")
	fmt.Fprintf(&b, "### The OU's security descriptor after the prescribed cells\n\nAfter every `acl clear`, so it is the seed's again:\n\n```\n%s\n```\n\n",
		oneLineMax(winScrub(sddl, secrets...), 4000))

	acc, ref := l50AuditPair(cells)
	if acc == nil {
		t.Fatalf("no write was accepted under the default ACLs; the audit has nothing to probe")
	}
	// probe makes the accepted and the refused write and reads the Security
	// log's 5136 and 4662 events since just before each.
	probe := func(phase string) (accEv, refEv []winEvent) {
		for i, c := range []*l50Cell{acc, ref} {
			if c == nil {
				continue
			}
			since := w.clock(t)
			l.l50WinWrite(t, ev, seed.Target, c.attr, c.writer, "audit-"+phase, l50Value(c.attr, c.writer, "audit-"+phase), password)
			time.Sleep(5 * time.Second)
			var r struct {
				Events []winEvent `json:"events"`
			}
			w.run(t, "audit", map[string]any{"mode": "read", "since": since}, 3*time.Minute, &r)
			evs := l44CleanEvents(r.Events, secrets...)
			for k := range evs {
				evs[k].Message = oneLineMax(evs[k].Message, 600)
			}
			for _, e := range evs {
				ev.mark("l50 windows: %s event %d at %s: %s", phase, e.ID, e.Time, e.Message)
			}
			if i == 0 {
				accEv = evs
			} else {
				refEv = evs
			}
		}
		return
	}
	names := func(evs []winEvent, attr string) string {
		var hit5136, hit4662 int
		for _, e := range evs {
			m := strings.ToLower(e.Message)
			named := strings.Contains(m, strings.ToLower(seed.Target)) || strings.Contains(m, "svc-oxidized-01")
			if e.ID == 5136 && named && strings.Contains(m, strings.ToLower(attr)) {
				hit5136++
			}
			if e.ID == 4662 && named {
				hit4662++
			}
		}
		return fmt.Sprintf("%d event(s) read; %d 5136 naming the target and `%s`, %d 4662 naming the target", len(evs), hit5136, attr, hit4662)
	}
	fmt.Fprintf(&b, "### The audit\n\nOne accepted write (`%s` by %s)", acc.attr, acc.writer)
	if ref != nil {
		fmt.Fprintf(&b, " and one refused (`%s` by %s)", ref.attr, ref.writer)
	}
	b.WriteString(" are made twice, each followed by a read of the Security log's 5136 (attribute modified) and 4662 (an access) events since just before it. " +
		"The DC's events are listed in the evidence, each cut at 600 characters.\n\n")

	ev.mark("l50 windows: audit as installed")
	accEv, refEv := probe("installed")
	fmt.Fprintf(&b, "- **As installed** (the settings above): accepted write: %s. ", names(accEv, acc.attr))
	if ref != nil {
		fmt.Fprintf(&b, "Refused write: %s.", names(refEv, ref.attr))
	}
	b.WriteString("\n")

	var on struct {
		Audit string `json:"audit"`
	}
	w.run(t, "audit", map[string]any{"mode": "on"}, 3*time.Minute, &on)
	ev.mark("l50 windows: audit on: %s", oneLineMax(on.Audit, 400))
	accEv, refEv = probe("on")
	fmt.Fprintf(&b, "- **With directory-change auditing on** (`audit.ps1 on`: success and failure for Directory Service Changes and Access, and a success-and-failure SACL for Everyone's writes on the OU, inherited): accepted write: %s. ", names(accEv, acc.attr))
	if ref != nil {
		fmt.Fprintf(&b, "Refused write: %s.", names(refEv, ref.attr))
	}
	b.WriteString("\n\n")
	return cells, b.String()
}
