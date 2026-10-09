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
	"regexp"
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
		sd.capture = "one JSON line per mark: each write (attribute, writer, ACL, the LDAP result code), the security descriptors " +
			"read back after every ACL change and every re-seed, and the audit-log lines found. There are no search or bind lines; the " +
			"wire is LDAPS, so a pcap would be encrypted."
		sd.credentials = "none appear here or in the evidence. The writers' shared password is generated for each run; it is never " +
			"printed or logged, and reaches the container only as an argument of `l50-seed.sh`."
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
		d.capture = "one JSON line per mark: each write (attribute, writer, ACL, whether it was accepted), the OU's SDDL after every " +
			"ACL change, the audit settings as found, and the Security log's 5136 and 4662 events (each cut at 600 characters). " +
			"There are no search or bind lines."
		d.credentials = "none appear here or in the evidence. The writers' shared password and the Administrator and DSRM passwords are " +
			"generated for each run and never printed or logged; L50 uses no keytab, ticket or certificate."
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
			// A go-ldap refusal already reads `LDAP Result Code 50 "...": ...`.
			if c.code > 0 && !strings.Contains(refusal, fmt.Sprintf("Code %d", c.code)) {
				refusal = fmt.Sprintf("LDAP result %d: %s", c.code, refusal)
			}
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %v | %v | %s |\n", c.attr, c.writer, c.acl, c.written, c.readsBack, refusal)
	}
	b.WriteString("\nThe rows whose writer is `l50-ouadmin` with a parenthesis are the delegated administrator trying to get around the " +
		"prescribed deny on `uid`. A row that names a step (adds an ACE, creates an entry, takes ownership) is the step itself: " +
		"`written` is whether the directory accepted it, and `reads back` is `false` as nothing is read. A row that names a write is " +
		"the write of `uid` that followed it. Every ACE, entry and ownership change those rows made was undone afterwards.\n")
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
	return l.l50SambaWriteTo(ev, l50SambaTarget, attr, writer, value, acl, secrets...)
}

// l50SambaWriteTo is l50SambaWrite on the entry dn.
func (l *labDir) l50SambaWriteTo(ev *evidenceLog, dn, attr, writer, value, acl string, secrets ...string) l50Cell {
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
	req := ldap.NewModifyRequest(dn, nil)
	req.Replace(attr, []string{value})
	err = c.Modify(req)
	cell.code = ldapCode(err)
	ev.mark("l50 samba: %s by %s under %s: code %d", attr, writer, acl, cell.code)
	if err != nil {
		cell.refused = oneLineMax(winScrub(err.Error(), secrets...), 160)
		return cell
	}
	cell.written = true
	res, err := c.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 15, false,
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

var l50DenyACE = regexp.MustCompile(`\(OD;[^)]*\)`)

// l50Denies is the deny ACEs in the OU's descriptor and in the target's, from
// the output of l50-seed.sh's "sddl" (two `samba-tool dsacl get` blocks).
func l50Denies(t *testing.T, out string) (ou, target []string) {
	t.Helper()
	blocks := strings.Split(out, "descriptor for ")
	if len(blocks) != 3 {
		t.Fatalf("l50-seed.sh printed %d descriptors, want the OU's and the target's", len(blocks)-1)
	}
	return l50DenyACE.FindAllString(blocks[1], -1), l50DenyACE.FindAllString(blocks[2], -1)
}

// l50SambaACL sets or clears (a re-seed) the prescribed deny on attr, checks
// the descriptor it printed holds what the step claims, marks the descriptors
// as evidence (review I-1) and answers one line for the note.
func (l *labDir) l50SambaACL(t *testing.T, ev *evidenceLog, password, op, attr string, first *[]string) string {
	t.Helper()
	ev.mark("l50 samba: acl %s %s", op, attr)
	out := l.l50SambaSeed(t, password, "acl", op, attr)
	ou, target := l50Denies(t, out)
	ev.mark("l50 samba: after acl %s %s, the OU's and the target's security descriptors: %s", op, attr,
		oneLineMax(winScrub(out, password, l.d.password), 12000))
	switch {
	case op == "set" && len(ou) != 3:
		t.Fatalf("l50 samba: after acl set %s the OU holds %d deny ACEs, want 3 (SELF, Account Operators, l50-ouadmin)", attr, len(ou))
	case op == "clear" && (len(ou) != 0 || len(target) != 0):
		t.Fatalf("l50 samba: after acl clear %s the OU holds %d and the target %d deny ACEs, want none", attr, len(ou), len(target))
	}
	if op == "set" && first != nil && *first == nil {
		*first = append(append([]string{"OU:"}, ou...), "target:")
		*first = append(*first, target...)
	}
	return fmt.Sprintf("- after `acl %s %s`: the OU holds %d deny ACE(s), the target %d (inherited)\n", op, attr, len(ou), len(target))
}

// l50SambaDelegated is the delegated administrator's attempts to get round the
// prescribed deny on uid (review I-3), as l50-ouadmin: (b) it creates an entry
// in the OU and writes uid on it, (a) it adds an allow of write on uid for
// itself to the target's DACL and writes uid, (c) it takes ownership of the
// target, then does (a). The deny must be set; a re-seed undoes the ACE, the
// entry and the ownership (it recreates the OU and the target), and the caller
// does one last. The ACE and the owner change are made by l50-dacl.py, as
// samba-tool dsacl stops for a delegated admin before changing anything.
func (l *labDir) l50SambaDelegated(t *testing.T, ev *evidenceLog, password string, b *strings.Builder) (cells []l50Cell) {
	t.Helper()
	secrets := []string{password, l.d.password}
	madeDN := "CN=l50-made,OU=Workloads," + dirBase
	step := func(label string, args ...string) (l50Cell, bool) {
		out, err := l.exec(append([]string{"/lab/l50-seed.sh", password}, args...)...)
		c := l50Cell{attr: "uid", writer: label, acl: l50Prescribed, code: -1, written: err == nil}
		if err != nil {
			c.refused = oneLineMax(winScrub(out, secrets...), 400)
		}
		ev.mark("l50 samba: %s: accepted %v: %s", label, err == nil, oneLineMax(winScrub(out, secrets...), 400))
		if err == nil && strings.TrimSpace(out) != "" {
			fmt.Fprintf(b, "- %s: `%s`\n", label, strings.ReplaceAll(oneLineMax(winScrub(out, secrets...), 400), "`", "'"))
		}
		return c, err == nil
	}
	sd := func(cn string) string {
		out, err := l.exec("/lab/l50-seed.sh", password, "dacl", "get", cn)
		if err != nil {
			t.Fatalf("l50-seed.sh dacl get %s: %v\n%s", cn, err, tailOf(winScrub(out, secrets...), 600))
		}
		out = oneLineMax(winScrub(out, secrets...), 8000)
		ev.mark("l50 samba: security descriptor of %s: %s", cn, out)
		return out
	}
	owner := func(sddl string) string {
		if i := strings.Index(sddl, " O:"); i >= 0 {
			if j := strings.Index(sddl[i:], "G:"); j > 0 {
				return strings.TrimSpace(sddl[i : i+j])
			}
		}
		return "(not read)"
	}

	// (b) an entry it creates, and so owns.
	const mkLabel = "l50-ouadmin (creates l50-made in the OU)"
	const mkWrite = "l50-ouadmin (writes l50-made, which it created)"
	c, ok := step(mkLabel, "dacl", "create")
	cells = append(cells, c)
	if ok {
		fmt.Fprintf(b, "- (b) `l50-made`, created by l50-ouadmin, has owner and group `%s`.\n", owner(sd("l50-made")))
		w := l.l50SambaWriteTo(ev, madeDN, "uid", "l50-ouadmin", l50Value("uid", "l50-ouadmin-made", l50Prescribed), l50Prescribed, secrets...)
		w.writer = mkWrite
		cells = append(cells, w)
		if out, err := l.exec("/lab/l50-seed.sh", password, "dacl", "delete"); err != nil {
			t.Fatalf("l50-seed.sh dacl delete: %v\n%s", err, tailOf(winScrub(out, secrets...), 600))
		}
	}

	// (a) an explicit allow it adds to the target's own DACL.
	const aceLabel = "l50-ouadmin (adds an allow ACE for itself on the target)"
	const aceWrite = "l50-ouadmin (writes the target after that ACE)"
	before := sd("svc-oxidized-01")
	fmt.Fprintf(b, "- (a) The target's owner and group before the ACE: `%s`.\n", owner(before))
	c, ok = step(aceLabel, "dacl", "allow", "uid")
	cells = append(cells, c)
	if ok {
		after := sd("svc-oxidized-01")
		fmt.Fprintf(b, "- (a) The target's descriptor now holds an explicit allow for l50-ouadmin: %v.\n", strings.Contains(after, "(OA;;WP;0bb0fca0-"))
		w := l.l50SambaWriteTo(ev, l50SambaTarget, "uid", "l50-ouadmin", l50Value("uid", "l50-ouadmin-ace", l50Prescribed), l50Prescribed, secrets...)
		w.writer = aceWrite
		cells = append(cells, w)
	}

	// (c) ownership first, then (a), on a fresh OU and target (a re-seed, then the
	// deny again, undoes (a)'s ACE).
	l.l50SambaACL(t, ev, password, "clear", "uid", nil)
	l.l50SambaACL(t, ev, password, "set", "uid", nil)
	c, ok = step("l50-ouadmin (takes ownership of the target)", "dacl", "own")
	cells = append(cells, c)
	if ok {
		fmt.Fprintf(b, "- (c) The target's owner and group after l50-ouadmin took ownership: `%s`.\n", owner(sd("svc-oxidized-01")))
		w := l.l50SambaWriteTo(ev, l50SambaTarget, "uid", "l50-ouadmin", l50Value("uid", "l50-ouadmin-own", l50Prescribed), l50Prescribed, secrets...)
		w.writer = "l50-ouadmin (writes the target after taking ownership, no ACE)"
		cells = append(cells, w)
		c, ok = step("l50-ouadmin (after taking ownership, adds an allow ACE for itself)", "dacl", "allow", "uid")
		cells = append(cells, c)
		if ok {
			w := l.l50SambaWriteTo(ev, l50SambaTarget, "uid", "l50-ouadmin", l50Value("uid", "l50-ouadmin-own-ace", l50Prescribed), l50Prescribed, secrets...)
			w.writer = "l50-ouadmin (writes the target after taking ownership and that ACE)"
			cells = append(cells, w)
		}
	}
	return cells
}

func (l *labDir) l50Samba(t *testing.T, ev *evidenceLog, password string) (cells []l50Cell, notes string) {
	t.Helper()
	secrets := []string{password, l.d.password}
	var b strings.Builder
	ev.mark("l50 samba: seed")
	l.l50SambaSeed(t, password)
	sddl := l.l50SambaSeed(t, password, "sddl")
	ev.mark("l50 samba: the OU's and the target's security descriptors before the default cells: %s", oneLineMax(winScrub(sddl, secrets...), 12000))
	fmt.Fprintf(&b, "### The OU's and the target's security descriptors before the default cells\n\nThe container is fresh each run, so this is the "+
		"default: `samba-tool dsacl get --objectdn=OU=Workloads,%s`, then the same for `CN=svc-oxidized-01` in it.\n\n```\n%s\n```\n\n",
		dirBase, tailOf(winScrub(sddl, secrets...), 8000))

	for _, attr := range l50Attributes {
		for _, w := range l50Writers {
			cells = append(cells, l.l50SambaWrite(ev, attr, w, l50Value(attr, w, l50Default), l50Default, password, l.d.password))
		}
	}
	// Samba 4.17's samba-tool has no dsacl delete, so each "acl clear" re-seeds
	// the OU (deletes it and its subtree, and seeds it again). That recreates the
	// target too, with a new SID: every prescribed attribute ran against a fresh
	// OU and a fresh entry. After every set and every re-seed the descriptors are
	// read back and kept as evidence (review I-1).
	var proof strings.Builder
	var firstSet []string
	for _, attr := range l50Attributes {
		proof.WriteString(l.l50SambaACL(t, ev, password, "set", attr, &firstSet))
		for _, w := range l50Writers {
			cells = append(cells, l.l50SambaWrite(ev, attr, w, l50Value(attr, w, l50Prescribed), l50Prescribed, password, l.d.password))
		}
		proof.WriteString(l.l50SambaACL(t, ev, password, "clear", attr, nil))
	}
	b.WriteString("### How the prescribed deny was set and cleared on Samba\n\n" +
		"`acl set` writes three ACEs (`OD;CI;WP;<the attribute's schemaIDGUID>;<user class>;` for SELF `PS`, Account Operators `AO` and " +
		"l50-ouadmin) with `samba-tool dsacl set`. Samba 4.17's `samba-tool` has no `dsacl delete`, so `acl clear` **re-seeds the OU**: it " +
		"deletes `OU=Workloads` and its subtree and seeds it again, which also **recreates the target `svc-oxidized-01` with a new SID**. " +
		"Every prescribed attribute therefore ran against a fresh OU and a fresh target. After every set and every re-seed the harness " +
		"reads both descriptors back, stops if the set did not leave exactly three deny ACEs on the OU or the re-seed left any, and " +
		"keeps the descriptors in the evidence (`l50 samba: after acl ...` marks). What it found:\n\n" + proof.String() + "\n")
	if len(firstSet) > 0 {
		b.WriteString("The deny ACEs after `acl set uid`:\n\n```\n" + strings.Join(firstSet, "\n") + "\n```\n\n")
	}

	// The delegated administrator's attempts to get round the deny on uid.
	b.WriteString("### The delegated administrator against the prescribed deny on `uid`\n\n")
	l.l50SambaACL(t, ev, password, "set", "uid", nil)
	cells = append(cells, l.l50SambaDelegated(t, ev, password, &b)...)
	l.l50SambaACL(t, ev, password, "clear", "uid", nil)
	b.WriteString("\nThe re-seeds that followed (one between (a) and (c), one after (c)) undid the ACE, the entry and the ownership change: " +
		"each recreates the OU and the target.\n\n")

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
		b.WriteString("- **As installed: not in the log.** No `dsdbChange` record named the target. \"As installed\" is `log level = 1` " +
			"(`tests/lab/directory/samba/entrypoint.sh:30`, written into `smb.conf`), with no `dsdb_json_audit` or `dsdb_audit` class set.\n")
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

// l50WinStep is what l50_dacl.ps1 answers.
type l50WinStep struct {
	Accepted    bool   `json:"accepted"`
	DN          string `json:"dn"`
	SDDL        string `json:"sddl"`
	RemovedACEs int    `json:"removed_aces"`
	RefusedType string `json:"refused_type"`
	Refused     string `json:"refused"`
}

// l50WinDelegated is the delegated administrator's attempts to get round the
// prescribed deny on uid (review I-3), as l50-ouadmin: (b) it creates an entry
// in the OU and writes uid on it, (a) it adds an allow of write on uid for
// itself to the target's DACL and writes uid, (c) it takes ownership of the
// target, then does (a). The deny must be set. Each scenario is undone, and the
// target's descriptor must be what it was before (else the test fails).
func (l *labDir) l50WinDelegated(t *testing.T, ev *evidenceLog, target, password string, b *strings.Builder) (cells []l50Cell) {
	t.Helper()
	secrets := l.l44Secrets()
	const ouadmin = "l50-ouadmin"
	step := func(label, what string) (res l50WinStep, c l50Cell) {
		p := map[string]any{"step": what, "dn": target, "attribute": "uid", "name": "l50-made", "user": ouadmin, "password": password}
		l.win.run(t, "l50_dacl", p, 3*time.Minute, &res)
		c = l50Cell{attr: "uid", writer: label, acl: l50Prescribed, written: res.Accepted, code: -1}
		if !res.Accepted {
			c.refused = oneLineMax(winScrub(res.RefusedType+": "+res.Refused, secrets...), 300)
		}
		ev.mark("l50 windows: %s: accepted %v: %s; sddl %s", label, res.Accepted, c.refused, oneLineMax(winScrub(res.SDDL, secrets...), 6000))
		return res, c
	}
	show := func() string {
		var r l50WinStep
		l.win.run(t, "l50_dacl", map[string]any{"step": "show", "dn": target}, 3*time.Minute, &r)
		ev.mark("l50 windows: the target's SDDL: %s", oneLineMax(winScrub(r.SDDL, secrets...), 6000))
		return r.SDDL
	}
	// cleanup removes ouadmin's explicit allow, gives the target back to Domain
	// Admins and deletes l50-made; the result must equal the SDDL before.
	cleanup := func(what, before string) {
		var r l50WinStep
		l.win.run(t, "l50_dacl", map[string]any{"step": "cleanup", "dn": target, "attribute": "uid", "user": ouadmin, "name": "l50-made"},
			3*time.Minute, &r)
		ev.mark("l50 windows: cleanup after %s removed %d ACE(s); the target's SDDL: %s", what, r.RemovedACEs, oneLineMax(winScrub(r.SDDL, secrets...), 6000))
		if r.SDDL != before {
			t.Errorf("l50 windows: after %s and its cleanup the target's SDDL is not what it was before", what)
			fmt.Fprintf(b, "- **The target's SDDL after the cleanup of %s differs from before it** (the evidence holds both).\n", what)
		}
	}
	writeOn := func(label, dn, valueKey string) l50Cell {
		c := l.l50WinWrite(t, ev, dn, "uid", ouadmin, l50Prescribed, l50Value("uid", valueKey, l50Prescribed), password)
		c.writer = label
		return c
	}

	before := show()
	fmt.Fprintf(b, "- The target's owner and group before: `%s`.\n", l50SDDLOwner(before))

	// (b) an entry it creates, and so owns.
	r, c := step("l50-ouadmin (creates l50-made in the OU)", "create")
	cells = append(cells, c)
	if r.Accepted {
		fmt.Fprintf(b, "- (b) `l50-made`, created by l50-ouadmin, has owner and group `%s`.\n", l50SDDLOwner(r.SDDL))
		cells = append(cells, writeOn("l50-ouadmin (writes l50-made, which it created)", r.DN, "l50-ouadmin-made"))
	}
	cleanup("(b)", before)

	// (a) an explicit allow it adds to the target's own DACL.
	r, c = step("l50-ouadmin (adds an allow ACE for itself on the target)", "allow")
	cells = append(cells, c)
	if r.Accepted {
		cells = append(cells, writeOn("l50-ouadmin (writes the target after that ACE)", target, "l50-ouadmin-ace"))
	}
	cleanup("(a)", before)

	// (c) ownership first, then (a).
	r, c = step("l50-ouadmin (takes ownership of the target)", "own")
	cells = append(cells, c)
	if r.Accepted {
		fmt.Fprintf(b, "- (c) The target's owner and group after l50-ouadmin took ownership: `%s`.\n", l50SDDLOwner(r.SDDL))
		cells = append(cells, writeOn("l50-ouadmin (writes the target after taking ownership, no ACE)", target, "l50-ouadmin-own"))
		r, c = step("l50-ouadmin (after taking ownership, adds an allow ACE for itself)", "allow")
		cells = append(cells, c)
		if r.Accepted {
			cells = append(cells, writeOn("l50-ouadmin (writes the target after taking ownership and that ACE)", target, "l50-ouadmin-own-ace"))
		}
	}
	cleanup("(c)", before)
	return cells
}

// l50SDDLOwner is the "O:...G:..." part of an SDDL string.
func l50SDDLOwner(sddl string) string {
	if i := strings.Index(sddl, "O:"); i >= 0 {
		if j := strings.Index(sddl[i:], "D:"); j > 0 {
			return sddl[i : i+j]
		}
	}
	return "(not read)"
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
	fmt.Fprintf(&b, "### The audit settings as found, before this run changed any\n\nThe DC is %s.\n\n"+
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

	// The delegated administrator against the deny on uid.
	b.WriteString("### The delegated administrator against the prescribed deny on `uid`\n\n")
	l.l50WinAcl(t, ev, "uid", "set")
	cells = append(cells, l.l50WinDelegated(t, ev, seed.Target, password, &b)...)
	l.l50WinAcl(t, ev, "uid", "clear")
	b.WriteString("\nEach scenario was undone (the ACE removed, ownership returned to Domain Admins, `l50-made` deleted) and the target's " +
		"SDDL read again: it equalled the SDDL before.\n\n")

	sddl := l.l50WinAcl(t, ev, l50Attributes[0], "show")
	fmt.Fprintf(&b, "### The OU's security descriptor after the prescribed cells\n\nAfter every `acl clear`, so it is the seed's again (read without a change):\n\n```\n%s\n```\n\n",
		oneLineMax(winScrub(sddl, secrets...), 4000))

	acc, ref := l50AuditPair(cells)
	if acc == nil {
		t.Fatalf("no write was accepted under the default ACLs; the audit has nothing to probe")
	}
	// probe makes the accepted and the refused write, waits for the DC (it
	// logs a 5136 about 9 s after the 4662, one sample), and reads the
	// Security log's 5136 and 4662 events since before both. Each event is
	// assigned to a write by the "Account Name" in its message, which is read
	// at up to 1500 characters; the evidence keeps 600.
	probe := func(phase string) []winEvent {
		since := w.clock(t)
		for _, c := range []*l50Cell{acc, ref} {
			if c != nil {
				l.l50WinWrite(t, ev, seed.Target, c.attr, c.writer, "audit-"+phase, l50Value(c.attr, c.writer, "audit-"+phase), password)
			}
		}
		time.Sleep(30 * time.Second)
		var r struct {
			Events []winEvent `json:"events"`
		}
		w.run(t, "audit", map[string]any{"mode": "read", "since": since}, 3*time.Minute, &r)
		evs := make([]winEvent, len(r.Events))
		for i, e := range r.Events {
			e.Message = oneLineMax(winScrub(e.Message, secrets...), 1500)
			evs[i] = e
			ev.mark("l50 windows: %s event %d at %s: %s", phase, e.ID, e.Time, oneLineMax(e.Message, 600))
		}
		return evs
	}
	// seen says what the events hold for one write: the 5136 (attribute
	// modified) naming the target and the attribute, and the 4662 (an access)
	// naming the target, each by the writer's account.
	seen := func(evs []winEvent, c *l50Cell) string {
		var hit5136, hit4662 int
		for _, e := range evs {
			m := strings.ToLower(e.Message)
			if !strings.Contains(m, "account name: "+strings.ToLower(c.writer)) {
				continue
			}
			// A 5136 names the object by DN and the attribute by name; a 4662 names
			// the object by its class and GUID only (measured), so it is assigned
			// by the account alone.
			if e.ID == 5136 && strings.Contains(m, "dn: "+strings.ToLower(seed.Target)) && strings.Contains(m, "ldap display name: "+strings.ToLower(c.attr)) {
				hit5136++
			}
			if e.ID == 4662 {
				hit4662++
			}
		}
		return fmt.Sprintf("`%s` by %s: %d 5136 event(s) naming the target's DN and the attribute, %d 4662 event(s) by that account (a 4662 names the object by GUID, not DN)", c.attr, c.writer, hit5136, hit4662)
	}
	both := func(evs []winEvent) string {
		s := fmt.Sprintf("%d event(s) read in all. Accepted write, %s.", len(evs), seen(evs, acc))
		if ref != nil {
			s += " Refused write, " + seen(evs, ref) + "."
		}
		return s
	}
	fmt.Fprintf(&b, "### The audit\n\nOne accepted write (`%s` by %s)", acc.attr, acc.writer)
	if ref != nil {
		fmt.Fprintf(&b, " and one refused (`%s` by %s)", ref.attr, ref.writer)
	}
	b.WriteString(" are made twice, each pair followed, 30 seconds later (in one sample the DC logged a 5136 about 9 seconds after the write's 4662), by a read of the " +
		"Security log's 5136 (attribute modified) and 4662 (an access) events since before the pair. Each event is assigned to a write by " +
		"its `Account Name`. The DC's events are in the evidence, each cut at 600 characters.\n\n")

	ev.mark("l50 windows: audit as installed")
	fmt.Fprintf(&b, "- **As installed** (the settings above): %s\n", both(probe("installed")))

	var on struct {
		Audit string `json:"audit"`
	}
	w.run(t, "audit", map[string]any{"mode": "on"}, 3*time.Minute, &on)
	ev.mark("l50 windows: audit on: %s", oneLineMax(on.Audit, 400))
	fmt.Fprintf(&b, "- **With directory-change auditing on** (`audit.ps1 on`: success and failure for Directory Service Changes and Access, and a "+
		"success-and-failure SACL for Everyone's writes on the OU, inherited): %s\n\n", both(probe("on")))
	return cells, b.String()
}
