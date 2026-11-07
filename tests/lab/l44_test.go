//go:build lab

package lab

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/blanketfish/port49/internal/directory"
)

// TestL44Bringup is the DC's bring-up alone, with no measurement: everything
// L44 needs before it measures anything. It writes no note. Run it with
//
//	PORT49_LAB_L44=1 go test -tags lab ./tests/lab/ -run '^TestL44Bringup$' -count=1 -v -timeout 240m
//
// Its evidence file, L44-bringup.json, goes under tests/lab/logs/windows of the
// run's output root, which git ignores; set PORT49_LAB_DIRECTORY_OUT to write
// it elsewhere.
//
// TestL44WindowsAD is the measurement (its comment has its command).
func TestL44Bringup(t *testing.T) {
	l44RequireOptIn(t)
	d := newDirectories(t)
	dc := startWindowsDC(t, d)
	c := dc.win.certs
	// Not a failed bring-up: the run goes on, those cells INVALID (Step 6).
	for _, why := range dc.win.invalid {
		t.Logf("windows: INVALID (R6): a setup step failed three times; its cells will be INVALID: %s", why)
	}
	if c.aliceSID != nil {
		if _, err := directory.SIDOf(c.aliceSID); err != nil {
			t.Errorf("alice's User certificate carries no SID extension: %v", err)
		}
	}
	if _, err := directory.SIDOf(c.aliceADCS); err == nil {
		t.Errorf("alice's OfflineRouter certificate carries a SID extension; the matrix needs one without")
	}
	ev := evidence(t, d, "L44-bringup")
	if r := dc.tryBind(t, ev, "simple", dc.bindSimple(), d.password); !r.ok || r.read != 1 {
		t.Errorf("the simple bind over LDAPS, the lab's premise: %+v", r)
	}
	if why := dc.win.invalidFor("keytab"); why != "" {
		t.Logf("GSSAPI: no keytab (%s); its cells will be INVALID", why)
	} else if r := dc.tryBind(t, ev, "gssapi", dc.bindGSSAPI(t), ""); !r.ok {
		t.Logf("GSSAPI as installed: %s (measured in TestL44WindowsAD, not a bring-up failure)", winScrub(r.text, dc.l44Secrets()...))
	}
	ev.assertClean(t, append([]string{d.password}, d.extra...)...)
	t.Logf("windows: %s; fixture loaded, LDAPS verified, keytab and certificates issued", dc.win.version())
}

const l44Claim = "The Active Directory claims on a Windows DC: on L42's fixture and its loop, which groups " +
	"`member:1.2.840.113556.1.4.1941:=<user DN>` returns and how the loop is answered; SASL EXTERNAL over LDAPS with a " +
	"client certificate (measured over StartTLS; [MS-ADTS] 5.1.1.2, with what LDAPS answers it); GSSAPI with a keytab and no SASL security layer against the Windows KDC; whether " +
	"`altSecurityIdentities` values written in port49's `X509:<I>{issuer}<SR>{serial}` form (issuer from the raw DER, " +
	"`DC=` included) match the certificate the DC itself maps; whether the SID extension's value equals `objectSid`; and " +
	"how KB5014754's strong-mapping enforcement treats each (policy engine spec §15 L44). Also measured, for two questions " +
	"plan 7g carried: whether the DC advertises the AD capability 1.2.840.113556.1.4.800, and the LDAP result an EXTERNAL " +
	"bind it refuses carries."

// l44RequireOptIn skips a test that starts the Windows DC unless the operator
// asked for it: a pattern that matches by accident must not start a lab (and
// destroy a live run's).
func l44RequireOptIn(t *testing.T) {
	t.Helper()
	if os.Getenv("PORT49_LAB_L44") != "1" {
		t.Skip("starts the Windows DC; set PORT49_LAB_L44=1 to run it")
	}
}

const l44ADCapability = "1.2.840.113556.1.4.800"

// l44Case is one certificate offered to the DC's KDC by PKINIT, with the
// altSecurityIdentities alice holds while it is (none when altsec is nil).
type l44Case struct {
	label, what string
	cert        *x509.Certificate
	key         *rsa.PrivateKey
	altsec      func(*x509.Certificate) (string, error)
}

// TestL44WindowsAD is lab register row L44 on a Windows Server 2025 DC. Run it,
// from a worktree pinned at the commit under test (tests/lab/directory/windows/
// compose.yaml's header has the operator's notes), with
//
//	PORT49_LAB_L44=1 go test -tags lab ./tests/lab/ -run '^TestL44WindowsAD$' -count=1 -v -timeout 240m
func TestL44WindowsAD(t *testing.T) {
	l44RequireOptIn(t)
	compare := l44CompareCapabilities(t) // first: the containers share tests/lab/logs/directory
	d := newDirectories(t)
	d.runSel = "^TestL44WindowsAD$"
	dc := startWindowsDC(t, d)
	ev := evidence(t, d, "L44-"+platWindows)
	var obs strings.Builder
	obs.WriteString(dc.win.configNote())
	obs.WriteString(dc.win.factsSection())
	obs.WriteString("### Nested groups: L42's fixture\n\n")
	obs.WriteString(dc.l42Observe(t, ev))
	obs.WriteString(dc.l44Capabilities(t, ev, compare))
	obs.WriteString(dc.l44Binds(t, ev))
	obs.WriteString(dc.l44SID(t, ev))
	obs.WriteString(dc.mappingChecks(t, ev))
	obs.WriteString(dc.l44Matrix(t, ev))
	obs.WriteString(dc.l44OR1(t, ev)) // last: its KDC is down for l44KDCDown, with no SSH logon to the DC
	ev.assertClean(t, dc.l44Secrets()...)
	writeResult(t, d, "L44", dc, l44Claim, dc.version(t), obs.String(), "tests/lab/evidence/L44-"+platWindows+".json")
}

// l44CompareCapabilities is the root DSE's supportedCapabilities on OpenLDAP
// and Samba AD, for plan 7g's carried question (a). Not a register cell: L42
// and L43 are closed. A directory the subtest did not read is absent from the
// map, never an empty list.
func l44CompareCapabilities(t *testing.T) map[string][]string {
	out := map[string][]string{}
	t.Run("compare", func(t *testing.T) {
		d := startDirectories(t)
		for _, dir := range d.all() {
			out[dir.name] = dir.capabilities(t)
		}
	})
	return out
}

// l44Secrets is every secret of the run: the text of an error, a kinit trace
// or a DC event is scrubbed of them (winScrub) before it is cut or shown.
func (l *labDir) l44Secrets() []string { return append([]string{l.d.password}, l.d.extra...) }

// l44Err is err's text, scrubbed and on one line, for a log or a cell.
func (l *labDir) l44Err(err error) string {
	if err == nil {
		return "ok"
	}
	return oneLineMax(winScrub(err.Error(), l.l44Secrets()...), 200)
}

// l44Events is what the DC logged since, each message scrubbed and cut.
func (l *labDir) l44Events(t *testing.T, since string) []winEvent {
	t.Helper()
	return l44CleanEvents(l.win.events(t, since), l.l44Secrets()...)
}

// l44CleanEvents scrubs each event's message, then cuts it to 160 characters.
func l44CleanEvents(evs []winEvent, secrets ...string) []winEvent {
	out := make([]winEvent, len(evs))
	for i, e := range evs {
		e.Message = oneLineMax(winScrub(e.Message, secrets...), 160)
		out[i] = e
	}
	return out
}

// l44CleanResult scrubs what a kinit's trace and last line said.
func l44CleanResult(r winPKINITResult, secrets ...string) winPKINITResult {
	errs := make([]string, len(r.kdcErrs))
	for i, e := range r.kdcErrs {
		errs[i] = oneLineMax(winScrub(e, secrets...), 160)
	}
	r.kdcErrs = errs
	r.last = oneLineMax(winScrub(r.last, secrets...), 200)
	return r
}

func (l *labDir) l44Capabilities(t *testing.T, ev *evidenceLog, compare map[string][]string) string {
	t.Helper()
	ev.mark("L44 root DSE supportedCapabilities")
	var b strings.Builder
	b.WriteString("\n### The AD capability (plan 7g's carried question a)\n\n" +
		"| directory | advertises `" + l44ADCapability + "` | `in_chain` (L42) | supportedCapabilities |\n|---|---|---|---|\n")
	row := func(name, inChain string, caps []string, read bool) {
		if !read {
			fmt.Fprintf(&b, "| %s | not measured (compare failed) | %s | not measured (compare failed) |\n", name, inChain)
			return
		}
		fmt.Fprintf(&b, "| %s | %v | %s | %s |\n", name, slices.Contains(caps, l44ADCapability), inChain, strings.Join(caps, ", "))
	}
	row(platWindows, "the table above", l.capabilities(t), true)
	caps, read := compare[platOpenLDAP]
	row(platOpenLDAP, "answers empty, no error (`L42-openldap.md`)", caps, read)
	caps, read = compare[platSamba]
	row(platSamba, "answers in full (`L42-samba_ad.md`)", caps, read)
	return b.String()
}

// l44Binds is L43's binds on the DC, EXTERNAL with the broker's AD CS
// certificate mapped and unmapped, GSSAPI as installed and under
// LdapEnforceChannelBinding 2, and OR-1's cell: a mapped certificate while
// the DC's KDC is stopped.
func (l *labDir) l44Binds(t *testing.T, ev *evidenceLog) string {
	t.Helper()
	w := l.win
	since := w.clock(t)
	brokerDN := "CN=port49,OU=Svc," + dirBase
	adcsExt := directory.Bind{Mechanism: "external", TLSCertFile: w.certs.brokerCertFile, TLSKeyFile: w.certs.brokerKeyFile}
	cbtInstalled := w.facts.NTDSLDAP["LdapEnforceChannelBinding"]
	cbt := cbtInstalled
	if cbt == "" {
		cbt = "absent (this build's default)"
	}
	// GSSAPI needs the keytab; without one its cells are INVALID (R6), never
	// a refusal.
	noKeytab := w.invalidFor("keytab")
	gssapi := func(label, what string) string {
		if noKeytab != "" {
			t.Errorf("L44 %s: no keytab (%s); the cell is INVALID (R6)", label, noKeytab)
			return fmt.Sprintf("| %s | INVALID (R6): no keytab: `%s` | n/a | — |\n", what, l44MDCell(noKeytab))
		}
		c := l.tryBind(t, ev, label, l.bindGSSAPI(t), "")
		c.text = winScrub(c.text, l.l44Secrets()...)
		row, invalid := l44GSSAPIRow(what, c)
		if invalid != "" {
			t.Errorf("L44 %s: %s; the cell is INVALID (R6)", label, invalid)
		}
		return row
	}
	var b strings.Builder
	b.WriteString("\n### Binds\n\n| mechanism | outcome | LDAP result | time |\n|---|---|---|---|\n")
	ev.mark("L44 simple over LDAPS")
	simple := l.tryBind(t, ev, "simple", l.bindSimple(), l.d.password)
	b.WriteString(simple.row("simple bind over LDAPS"))
	ev.mark("L44 simple over plain LDAP")
	plain := l.tryPlain(t, ev, "simple over plain LDAP, by hand")
	b.WriteString(plain.row("simple bind over plain LDAP, built by hand (an observation of this build's default)"))
	ev.mark("L44 gssapi, LdapEnforceChannelBinding %s", cbt)
	b.WriteString(gssapi("gssapi", "GSSAPI over LDAPS, keytab, no SASL security layer, `LdapEnforceChannelBinding` "+cbt))

	w.setAltSec(t, brokerDN, directory.ADIssuerSerial(w.certs.brokerADCS))
	ev.mark("L44 external, AD CS certificate, port49's form on port49")
	e1 := l.l44External(t, ev, "external", adcsExt, true)
	b.WriteString(l44ExtRow("SASL EXTERNAL over StartTLS, the broker's AD CS certificate, `altSecurityIdentities` on port49 in port49's form", e1))
	// A documented observation, not the measurement: [MS-ADTS] 5.1.1.2 rejects
	// EXTERNAL on the LDAPS port, where the DC maps the certificate itself.
	ev.mark("L44 external over LDAPS, mapped, a documented observation")
	eL := l.l44ExternalOn(t, ev, "external over LDAPS", adcsExt, false)
	b.WriteString(l44ExtRow("SASL EXTERNAL over LDAPS, the same mapped certificate (a documented observation; [MS-ADTS] 5.1.1.2 says EXTERNAL is rejected there)", eL))
	if eL.ok {
		t.Logf("L44: LDAPS accepted an EXTERNAL bind, contrary to MS-ADTS 5.1.1.2 (an observation, not a harness fault)")
	}
	b.WriteString(l.l44LDAPSNoBind(t, ev, adcsExt))
	w.setAltSec(t, brokerDN, "")
	ev.mark("L44 external, AD CS certificate, no mapping")
	e2 := l.l44External(t, ev, "external, unmapped", adcsExt, false)
	b.WriteString(l44ExtRow("SASL EXTERNAL over StartTLS, the same certificate, no `altSecurityIdentities` on port49 (carried question b)", e2))
	ev.mark("L44 external, a certificate from the lab directory CA")
	e3 := l.l44External(t, ev, "external, lab CA", l.bindExternal(t), false)
	b.WriteString(l44ExtRow("SASL EXTERNAL over StartTLS, a certificate from the lab directory CA (in the DC's Root store, not in NTAuth), unmapped (carried question b)", e3))

	restoreCBT := l.l44GuardRegistry(t, "LdapEnforceChannelBinding", l44AsInstalled(cbtInstalled))
	defer restoreCBT()
	// The broker's mapping for the EXTERNAL cell under 2 is set before the
	// change: it survives the reboot, and no fatal step then runs between the
	// boot reads around the cells.
	w.setAltSec(t, brokerDN, directory.ADIssuerSerial(w.certs.brokerADCS))
	got := l.setRegistry(t, "LdapEnforceChannelBinding", 2)
	// Measured once: lsass crashed 15s after NTDS restarted on 2, and which
	// set it off was not separated. A cell under 2 that met a DC going down
	// is no measurement, so the boot is read before and after them, and a
	// change makes every one of them INVALID.
	bootBefore, berr := w.bootNow()
	var under2 []l44Cell
	ev.mark("L44 gssapi, LdapEnforceChannelBinding %s", got)
	what := "GSSAPI over LDAPS, keytab, no SASL security layer, `LdapEnforceChannelBinding` " + got + " (port49 sends no channel binding token)"
	under2 = append(under2, l44Cell{what, gssapi("gssapi, channel binding 2", what)})
	ev.mark("L44 external, LdapEnforceChannelBinding %s", got)
	e4 := l.l44External(t, ev, "external, channel binding 2", adcsExt, true)
	what = "SASL EXTERNAL over StartTLS, mapped, `LdapEnforceChannelBinding` " + got
	under2 = append(under2, l44Cell{what, l44ExtRow(what, e4)})
	ev.mark("L44 simple, LdapEnforceChannelBinding %s", got)
	simple2 := l.tryBind(t, ev, "simple, channel binding 2", l.bindSimple(), l.d.password)
	what = "simple bind over LDAPS, `LdapEnforceChannelBinding` " + got
	under2 = append(under2, l44Cell{what, simple2.row(what)})
	bootAfter, aerr := w.bootNow()
	var bootErr error
	if err := errors.Join(berr, aerr); err != nil {
		bootErr = errors.New(oneLineMax(winScrub(err.Error(), l.l44Secrets()...), 300))
	}
	rows, invalid := l44RowsUnder2(under2, bootBefore, bootAfter, bootErr)
	if invalid != "" {
		t.Errorf("L44: the cells under LdapEnforceChannelBinding 2 are INVALID (R6): %s", invalid)
	}
	b.WriteString(rows)
	restoreCBT()
	l.waitLDAPS(t, 5*time.Minute) // the restore rebooted the DC

	b.WriteString(l44BindsTail(l.certRequested(t), eL.ok))
	if !simple.ok || simple.read != 1 || !simple2.ok {
		t.Errorf("the simple bind over LDAPS is the lab's premise and was not accepted: ok %v/%v, read %d", simple.ok, simple2.ok, simple.read)
	}
	// The plain-LDAP simple bind is this build's default, recorded above; on
	// Windows it is an observation, not the harness's premise.
	refusals, bad := l.refusalChecks(t, ev)
	b.WriteString(refusals)
	fmt.Fprintf(&b, "\nWhat the DC logged during the binds: %s\n", l44EventsCell(l.l44Events(t, since)))
	ev.assertClean(t, bad)
	return b.String()
}

// l44OR1 is OR-1 (pre-flight I5): result 1 is a generic server-side code. If a
// DC whose own mapping path is broken (here: its KDC, which Schannel's S4U2Self
// needs, stopped) answers a mapped certificate with the same code an unmapped
// one gets, that code cannot tell "the broker's certificate is refused" from
// "this DC is broken". The cell is valid only when the same mapped bind
// succeeds with the KDC up, just before and just after, and its own bind ended
// well before the KDC's scheduled start. It runs last: an SSH logon fails
// while the KDC is down, so the stop registers a task that starts it again
// l44KDCDown later, nothing calls the DC until then, and nothing after it
// needs the KDC. A KDC that does not come back is the cell's INVALID, never
// the run's.
func (l *labDir) l44OR1(t *testing.T, ev *evidenceLog) string {
	t.Helper()
	w := l.win
	brokerDN := "CN=port49,OU=Svc," + dirBase
	adcsExt := directory.Bind{Mechanism: "external", TLSCertFile: w.certs.brokerCertFile, TLSKeyFile: w.certs.brokerKeyFile}
	var (
		t0      time.Time
		stopped bool
		stop    winKDCStop
	)
	defer func() { // the backstop: a fatal between the stop and the wait still waits for the start
		if stopped {
			if _, err := l.l44AwaitKDC(t, t0, stop.StoppedAt); err != nil {
				t.Errorf("L44 OR-1: the KDC did not come back: %s", l.l44Err(err))
			}
		}
	}()
	w.setAltSec(t, brokerDN, directory.ADIssuerSerial(w.certs.brokerADCS))
	ev.mark("L44 OR-1 external, mapped, the DC's KDC up")
	e0 := l.l44External(t, ev, "external, KDC up", adcsExt, true)
	ev.mark("L44 OR-1 external, mapped, the DC's KDC stopped")
	stopped = true
	t0 = time.Now()
	stop = w.stopKDC(t, l44KDCDown)
	e5 := l.l44External(t, ev, "external, KDC stopped", adcsExt, true)
	e5Ended := time.Since(t0)
	var e6 l44Ext
	var check l44KDCCheck
	if c, err := l.l44AwaitKDC(t, t0, stop.StoppedAt); err != nil {
		e6 = l44Ext{l43Cell: l43Cell{mech: "external", code: -1}, invalid: "the KDC did not come back: " + l.l44Err(err)}
		t.Errorf("L44 OR-1: %s; the cell is INVALID (R6)", e6.invalid)
		t.Errorf("L44 OR-1: the DC's KDC may be left stopped; no SSH logon works until it runs, and only a restart " +
			"from outside Windows (docker compose restart dc) recovers it")
		t.Logf("L44 OR-1: the broker's altSecurityIdentities is left set; the DC is destroyed at teardown")
	} else {
		stopped, check = false, c
		ev.mark("L44 OR-1 external, mapped, the DC's KDC started again")
		e6 = l.l44External(t, ev, "external, KDC started again", adcsExt, true)
		// Only with the KDC back: a failed SSH call here is fatal and would lose the
		// note. Otherwise the mapping stays; the DC is destroyed at teardown.
		w.setAltSec(t, brokerDN, "")
	}
	if e5.invalid == "" {
		if e5.invalid = l44KDCTooNear(e5Ended); e5.invalid != "" {
			t.Errorf("L44 external, KDC stopped: %s; the cell is INVALID (R6)", e5.invalid)
		}
	}
	if e5.invalid == "" {
		if e5.invalid = l44KDCDownInvalid(e0, e6); e5.invalid != "" {
			t.Errorf("L44 external, KDC stopped: %s; the cell is INVALID (R6)", e5.invalid)
		}
	}
	var b strings.Builder
	b.WriteString("\n### OR-1: a mapped certificate while the DC's KDC is stopped\n\n| mechanism | outcome | LDAP result | time |\n|---|---|---|---|\n")
	b.WriteString(l44ExtRow("SASL EXTERNAL over StartTLS, mapped, the KDC up (e5's control, before)", e0))
	b.WriteString(l44ExtRow("SASL EXTERNAL over StartTLS, mapped, **the DC's KDC stopped**", e5))
	b.WriteString(l44ExtRow("SASL EXTERNAL over StartTLS, mapped, the KDC started again (e5's control, after)", e6))
	if strings.HasPrefix(e6.invalid, "the KDC did not come back") {
		b.WriteString("\nThe DC's KDC may be left stopped: no SSH logon works until it runs, its start task repeats every two " +
			"minutes for half an hour, and after that only a restart from outside Windows (`docker compose restart dc`) " +
			"recovers it.\n")
	}
	if check.Now != "" {
		fmt.Fprintf(&b, "\nThe KDC's outage, on the DC's clock: stopped %s, its start task scheduled for %s and run at %s "+
			"(the Task Scheduler's trigger is whole seconds, so the run time can precede the scheduled instant by under a "+
			"second), found running at %s (result %s). An SSH logon fails while the KDC is down, so the stop registered that "+
			"task and nothing called the DC until it had run. e5's bind ended %s after the stop was asked.\n",
			stop.StoppedAt, stop.StartAt, check.TaskRan, check.Now, check.TaskResult, e5Ended.Round(time.Millisecond))
	}
	return b.String()
}

// l44KDCDownInvalid is why the KDC-stopped cell (OR-1's e5) shows nothing, or
// "" when it is valid: the same mapped bind must have succeeded, and mapped
// as port49, with the KDC up before (e1) and after (e6).
func l44KDCDownInvalid(e1, e6 l44Ext) string {
	if !e1.ok || !e6.ok || e1.invalid != "" || e6.invalid != "" {
		return "the mapped bind did not succeed with the KDC up (e1 and e6), so a KDC-down answer shows nothing about the KDC"
	}
	return ""
}

// l44SID compares the SID extension of the certificates AD CS issued with
// the objectSid of the account each names, and runs port49's sid and
// issuer_serial mappings on them (port49's guarantees, asserted).
func (l *labDir) l44SID(t *testing.T, ev *evidenceLog) string {
	t.Helper()
	w := l.win
	c := w.certs
	var b strings.Builder
	b.WriteString("\n### The SID extension and objectSid\n\n| certificate | SID extension | objectSid | equal |\n|---|---|---|---|\n")
	noSID := w.invalidFor("sid") // enroll_as failed three times: alice's User certificate does not exist
	row := func(what string, cert *x509.Certificate, filter string) {
		if cert == nil {
			t.Errorf("L44 %s: %s; the cell is INVALID (R6)", what, noSID)
			fmt.Fprintf(&b, "| %s | INVALID (R6): `%s` | — | — |\n", what, l44MDCell(noSID))
			return
		}
		ext, err := directory.SIDOf(cert)
		obj := l.ldapObjectSID(t, filter)
		cell := "`" + ext + "`"
		if err != nil {
			cell = "none: " + oneLineMax(winScrub(err.Error(), l.l44Secrets()...), 120)
		}
		fmt.Fprintf(&b, "| %s | %s | `%s` | %v |\n", what, cell, obj, err == nil && ext == obj)
	}
	ev.mark("L44 SID extensions against objectSid")
	row("alice's, AD CS `User` template, requested as alice", c.aliceSID, "(sAMAccountName=alice)")
	row("a KDC-EKU certificate from the DC's store (`KerberosAuthentication`; not necessarily the one the KDC presents)", c.dcKDC, "(sAMAccountName=DC1$)")
	row("alice's, AD CS `OfflineRouter` (subject from the request)", c.aliceADCS, "(sAMAccountName=alice)")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	b.WriteString("\n| port49's mapping on the DC's certificates (asserted: port49's guarantees, not the DC's) | observed |\n|---|---|\n")
	if c.aliceSID == nil {
		t.Errorf("L44 sid mapping: %s; the cell is INVALID (R6)", noSID)
		fmt.Fprintf(&b, "| `sid`, alice's `User` certificate | INVALID (R6): `%s` |\n", l44MDCell(noSID))
	} else {
		ev.mark("L44 port49 sid mapping on alice's User certificate")
		r := l.resolverWith(t, l.config("direct", l.groupsBaseDN, l.bindSimple(), directory.Mapping{Kind: directory.MapSID, Attribute: "objectSid"}), l.d.password, ev)
		a, err := r.Map(ctx, c.aliceSID)
		if err != nil || a.Principal != l.principal("alice") {
			t.Errorf("sid did not map alice's User certificate to her: %q, %s", a.Principal, l.l44Err(err))
		}
		fmt.Fprintf(&b, "| `sid`, alice's `User` certificate | %s as `%s` |\n", l.l44Err(err), a.Principal)
	}
	aliceDN := "CN=alice,OU=Staff," + dirBase
	w.setAltSec(t, aliceDN, directory.ADIssuerSerial(c.aliceADCS))
	ev.mark("L44 port49 issuer_serial mapping on alice's OfflineRouter certificate")
	r := l.resolverWith(t, l.config("direct", l.groupsBaseDN, l.bindSimple(), directory.Mapping{Kind: directory.MapIssuerSerial, Attribute: "altSecurityIdentities"}), l.d.password, ev)
	a, err := r.Map(ctx, c.aliceADCS)
	if err != nil || a.Principal != l.principal("alice") {
		t.Errorf("issuer_serial did not map alice's AD CS certificate to her: %q, %s", a.Principal, l.l44Err(err))
	}
	fmt.Fprintf(&b, "| `issuer_serial`, alice's `OfflineRouter` certificate, alice holding port49's form | %s as `%s` |\n", l.l44Err(err), a.Principal)
	if q, qerr := winAltSecQuoted(c.quirk["comma"].cert); qerr == nil {
		w.setAltSec(t, aliceDN, q)
		ev.mark("L44 port49 issuer_serial on the comma CA's certificate, alice holding the quoted form")
		a, err = r.Map(ctx, c.quirk["comma"].cert)
		if err != nil || a.Principal != l.principal("alice") {
			t.Errorf("issuer_serial did not map the comma CA's certificate to alice: %q, %s", a.Principal, l.l44Err(err))
		}
		fmt.Fprintf(&b, "| `issuer_serial`, the comma CA's certificate, alice holding the quoted form | %s as `%s` |\n", l.l44Err(err), a.Principal)
	}
	w.setAltSec(t, aliceDN, directory.ADIssuerSerial(l.d.pki.alice))
	return b.String()
}

// l44QuirkCases are the quirk CAs' rows (Task 7a): alice offered each CA's
// certificate under port49's form (through directory.ADIssuerSerial), the
// value quoted as CertNameToStr quotes it, and the value escaped as RFC 4514
// escapes it; and, for every CA but the comma's (run 8 measured the unquoted
// comma), the value as it is. Every row is asserted against winQuirkWant, the
// verdict L44 measured.
func l44QuirkCases(c winCerts, port49Form func(*x509.Certificate) (string, error)) []l44Case {
	var cases []l44Case
	for _, q := range winQuirks {
		qc := c.quirk[q.slug]
		cases = append(cases,
			l44Case{q.slug + "-port49", fmt.Sprintf("a CA whose CN holds %s (`%s`), alice holding port49's form", q.holds, q.cn),
				qc.cert, qc.key, port49Form},
			l44Case{q.slug + "-quoted", "the same, alice holding the value quoted as CertNameToStr quotes it",
				qc.cert, qc.key, winAltSecQuoted},
			l44Case{q.slug + "-escaped", "the same, alice holding the value escaped as RFC 4514 escapes it",
				qc.cert, qc.key, winAltSecEscaped})
		if q.slug != "comma" {
			cases = append(cases, l44Case{q.slug + "-raw", "the same, alice holding the value as it is, neither quoted nor escaped",
				qc.cert, qc.key, winAltSecRaw})
		}
	}
	return cases
}

// l44QuirkSlug is the quirk CA a case label belongs to ("back" of
// "back-port49"), or "" for any other case.
func l44QuirkSlug(label string) string {
	slug, _, _ := strings.Cut(label, "-")
	for _, q := range winQuirks {
		if q.slug == slug {
			return slug
		}
	}
	return ""
}

// l44Matrix offers each certificate to the DC's KDC by PKINIT under each
// KB5014754 setting, alice holding only the altSecurityIdentities the case
// names, and the broker's AD CS certificate to the DC by EXTERNAL over
// StartTLS, recording what the KDC answered and logged. Each block starts with control-ski, a
// strong mapping no part of the claim is about: if it gets no TGT, the
// block's PKINIT is broken and every cell in it is INVALID. A setup failure
// marks a cell INVALID (R6); only l44Judge's "refused" is a verdict.
func (l *labDir) l44Matrix(t *testing.T, ev *evidenceLog) string {
	t.Helper()
	w := l.win
	c := w.certs
	port49Form := func(x *x509.Certificate) (string, error) { return directory.ADIssuerSerial(x), nil }
	cases := []l44Case{
		{"control-ski", "control: AD CS `OfflineRouter`, alice holding the strong `X509:<SKI>` mapping", c.aliceADCS, c.aliceADCSKey, winAltSecSKI},
		{"adcs-none", "AD CS `OfflineRouter` (UPN SAN, no SID extension)", c.aliceADCS, c.aliceADCSKey, nil},
		{"adcs-port49", "the same, alice holding port49's form", c.aliceADCS, c.aliceADCSKey, port49Form},
		{"adcs-forward", "the same, alice holding the issuer least significant RDN first", c.aliceADCS, c.aliceADCSKey, winAltSecForward},
		{"adcs-unreversed", "the same, alice holding the serial in certificate byte order", c.aliceADCS, c.aliceADCSKey, winAltSecUnreversed},
		{"sid-none", "AD CS `User`, requested as alice (SID extension)", c.aliceSID, c.aliceSIDKey, nil},
	}
	cases = append(cases, l44QuirkCases(c, port49Form)...)
	cases = append(cases,
		l44Case{"highbit-port49", "the lab users CA, a serial whose top bit is set, alice holding port49's form", c.aliceHighBit, c.aliceHighBitKey, port49Form},
		l44Case{"highbit-signbyte", "the same, alice holding the serial with its DER sign byte", c.aliceHighBit, c.aliceHighBitKey, winAltSecSignByte})
	aliceDN := "CN=alice,OU=Staff," + dirBase
	brokerDN := "CN=port49,OU=Svc," + dirBase
	adcsExt := directory.Bind{Mechanism: "external", TLSCertFile: c.brokerCertFile, TLSKeyFile: c.brokerKeyFile}
	var b strings.Builder
	b.WriteString("\n### KB5014754: what the DC itself maps\n\n" +
		"Each certificate is offered to the KDC by PKINIT (MIT `kinit`) as `alice@CORP.EXAMPLE.COM`, alice holding exactly " +
		"the `altSecurityIdentities` the row names; the KDC is restarted after each `StrongCertificateBindingEnforcement` " +
		"change. The first row of each block is the control. \"refused\" means the KDC itself refused, for no setup reason, " +
		"while the control got a TGT; anything else is INVALID (R6), with the reason. The last row of each block is the " +
		"broker's AD CS certificate by SASL EXTERNAL over StartTLS (on LDAPS it is rejected, [MS-ADTS] 5.1.1.2), port49's form on its account.\n\n" +
		"| `StrongCertificateBindingEnforcement` | certificate | `altSecurityIdentities` held | outcome | the KDC said | DC events | time |\n" +
		"|---|---|---|---|---|---|---|\n")
	noSID := w.invalidFor("sid")
	// The CRL setting is not in the facts table; the harness's DC ships without it.
	restoreCRL := l.l44GuardRegistry(t, "UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors", -1)
	defer restoreCRL()
	restoreMode := l.l44GuardRegistry(t, "StrongCertificateBindingEnforcement", l44AsInstalled(w.facts.StrongBinding))
	defer restoreMode()
	l.setRegistry(t, "UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors", 1)
	for _, mode := range []int{-1, 1, 2} {
		inForce := l.setRegistry(t, "StrongCertificateBindingEnforcement", mode)
		w.checkSkew(t)
		control := "" // why the block's control failed; "" while it holds
		for _, cs := range cases {
			why := ""
			if cs.cert == nil { // the sid cells, when enroll_as failed three times
				why = noSID
			} else if slug := l44QuirkSlug(cs.label); slug != "" { // a quirk CA that failed to publish
				why = w.invalidFor("ca_" + slug)
			}
			if why != "" {
				t.Errorf("L44 %s under %s: %s; the cell is INVALID (R6)", cs.label, inForce, why)
				fmt.Fprintf(&b, "| %s | %s | — | INVALID (R6): `%s` | — | — | — |\n", inForce, cs.what, l44MDCell(why))
				continue
			}
			held := ""
			if cs.altsec != nil {
				v, err := cs.altsec(cs.cert)
				if err != nil {
					outcome := "INVALID (R6): the mapping could not be written: " + l.l44Err(err)
					t.Errorf("L44 %s under %s: %s", cs.label, inForce, outcome)
					fmt.Fprintf(&b, "| %s | %s | — | %s | — | — | — |\n", inForce, cs.what, l44MDCell(outcome))
					if cs.label == "control-ski" {
						control = "control-ski could not be offered"
					}
					continue
				}
				held = v
			}
			w.setAltSec(t, aliceDN, held)
			since := w.clock(t)
			ev.mark("L44 pkinit %s, StrongCertificateBindingEnforcement %s", cs.label, inForce)
			r := l44CleanResult(w.kinit(t, cs.label, "alice@"+dirRealm, cs.cert, cs.key), l.l44Secrets()...)
			evs := l.l44Events(t, since)
			ev.add(evidenceLine{Event: "kinit", Label: cs.label + ", enforcement " + inForce, Error: r.kdcSaid(),
				DurationMS: ms(r.took), DCEvents: l44EventStrings(evs)})
			outcome := l44Judge(r, evs, control)
			if cs.label == "control-ski" && !strings.HasPrefix(outcome, "**TGT issued**") {
				control = "control-ski got no TGT (" + outcome + ")"
				outcome = "INVALID (R6): " + control
			}
			b.WriteString(l44MatrixRow(inForce, cs.what, held, outcome, r, evs))
			if strings.HasPrefix(outcome, "INVALID") {
				t.Errorf("L44 %s under %s: %s", cs.label, inForce, outcome)
			} else if want, ok := l44QuirkWant(cs.label); ok && outcome != want {
				t.Errorf("L44 %s under %s: %s, measured %s", cs.label, inForce, outcome, want)
			}
		}
		w.setAltSec(t, brokerDN, directory.ADIssuerSerial(c.brokerADCS))
		since := w.clock(t)
		ev.mark("L44 external under StrongCertificateBindingEnforcement %s", inForce)
		e := l.l44External(t, ev, "external, enforcement "+inForce, adcsExt, true)
		evs := l.l44Events(t, since)
		b.WriteString(l44ExternalRow(inForce, e, evs))
		w.setAltSec(t, brokerDN, "")
	}
	restoreMode()
	restoreCRL()
	w.setAltSec(t, aliceDN, directory.ADIssuerSerial(l.d.pki.alice))
	return b.String()
}

// l44Judge is a PKINIT cell's outcome. A refusal is KB5014754's verdict only
// when its cause is proven: the block's control got a TGT (control is ""),
// the KDC logged no setup event, said no certificate-validation code, and
// itself refused. Anything else is INVALID (R6), never "refused".
func l44Judge(r winPKINITResult, evs []winEvent, control string) string {
	switch ids, codes := l44PreconditionIDs(evs), r.setupCodes(); {
	case control != "":
		return "INVALID (R6): " + control
	case len(ids) > 0:
		return fmt.Sprintf("INVALID (R6): the KDC logged %v, a setup failure", ids)
	case r.ok:
		return "**TGT issued**"
	case len(codes) > 0:
		return fmt.Sprintf("INVALID (R6): KDC error %s, a certificate-validation failure", strings.Trim(fmt.Sprint(codes), "[]"))
	case !r.kdcRefused():
		return "INVALID (R6): the KDC refused nothing; the client failed on its own side"
	}
	return "refused"
}

// l44MatrixRow is one PKINIT cell, its outcome l44Judge's.
func l44MatrixRow(enforcement, what, held, outcome string, r winPKINITResult, evs []winEvent) string {
	if held == "" {
		held = "(none)"
	} else {
		held = "`" + held + "`"
	}
	return fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s |\n", enforcement, what, held, l44MDCell(outcome),
		l44MDCell(r.kdcSaid()), l44EventsCell(evs), r.took.Round(time.Millisecond))
}

// l44Ext is one EXTERNAL cell: port49's bind, why it is INVALID (R6) when it
// is, and on an accepted bind the identity the DC mapped the certificate to.
type l44Ext struct {
	l43Cell
	invalid string
	authzID string
}

// dialTLS is a TLS connection to l the way port49 makes one: the handshake on
// connect for ldaps://, or StartTLS on the plain port.
func (l *labDir) dialTLS(tc *tls.Config) (*ldap.Conn, error) {
	d := ldap.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second})
	if !l.startTLS {
		return ldap.DialURL(l.uri, d, ldap.DialWithTLSConfig(tc))
	}
	conn, err := ldap.DialURL(l.uri, d)
	if err != nil {
		return nil, err
	}
	if err := conn.StartTLS(tc); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// certPresented reports whether Go's TLS client, configured as port49's
// dialer configures it (tls.Config.Certificates), would send certFile to
// l's server, over StartTLS when l is one. When the DC's CertificateRequest
// lists acceptable CAs, Go sends a certificate only if SupportsCertificate
// passes and otherwise silently sends none; the bind is then refused for "no
// certificate", which is no answer about the mapping (pre-flight I2).
func (l *labDir) certPresented(t *testing.T, certFile, keyFile string) (bool, string) {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("%s: loading %s: %s", l.name, certFile, l.l44Err(err))
	}
	tc, err := l.d.pki.clientTLS(l.uri)
	if err != nil {
		t.Fatal(l.l44Err(err))
	}
	asked, sent, why := false, false, ""
	tc.GetClientCertificate = func(ri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		asked = true
		if err := ri.SupportsCertificate(&cert); err != nil {
			why = oneLineMax(winScrub(err.Error(), l.l44Secrets()...), 160)
			return &tls.Certificate{}, nil
		}
		sent = true
		return &cert, nil
	}
	conn, err := l.dialTLS(tc)
	if err != nil {
		return false, "the probe's handshake failed: " + oneLineMax(winScrub(err.Error(), l.l44Secrets()...), 120)
	}
	conn.Close()
	switch {
	case !asked:
		return false, "the server sent no CertificateRequest"
	case !sent:
		return false, "Go would send no certificate: " + why
	}
	return true, ""
}

// l44WhoAmI is the identity the DC gives a connection that presented bind's
// certificate, after an EXTERNAL bind when externalBind (RFC 4532, which AD
// supports as 1.3.6.1.4.1.4203.1.11.3), on a connection built by hand:
// port49's Client exposes searches only.
func (l *labDir) l44WhoAmI(t *testing.T, bind directory.Bind, externalBind bool) (string, error) {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(bind.TLSCertFile, bind.TLSKeyFile)
	if err != nil {
		return "", err
	}
	tc, err := l.d.pki.clientTLS(l.uri)
	if err != nil {
		return "", err
	}
	tc.Certificates = []tls.Certificate{cert}
	conn, err := l.dialTLS(tc)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetTimeout(15 * time.Second)
	if externalBind {
		if err := conn.ExternalBind(); err != nil {
			return "", err
		}
	}
	r, err := conn.WhoAmI(nil)
	if err != nil {
		return "", err
	}
	return r.AuthzID, nil
}

// l44External is one EXTERNAL cell. A certificate Go would not present makes
// it INVALID before any bind. On an accepted bind, WhoAmI names the account
// the DC mapped; when mapped (port49's form on port49), anything but
// CORP\port49 makes it INVALID: "bound" alone does not prove port49's form
// mapped it (pre-flight M12).
//
// It measures over StartTLS ([MS-ADTS] 5.1.1.2: EXTERNAL is rejected on the
// LDAPS port, which authenticates the certificate itself).
func (l *labDir) l44External(t *testing.T, ev *evidenceLog, label string, bind directory.Bind, mapped bool) l44Ext {
	t.Helper()
	return l.viaStartTLS().l44ExternalOn(t, ev, label, bind, mapped)
}

// l44ExternalOn is l44External on l's own server, whatever its transport.
func (l *labDir) l44ExternalOn(t *testing.T, ev *evidenceLog, label string, bind directory.Bind, mapped bool) l44Ext {
	t.Helper()
	if ok, why := l.certPresented(t, bind.TLSCertFile, bind.TLSKeyFile); !ok {
		x := l44Ext{l43Cell: l43Cell{mech: "external", code: -1}, invalid: "the certificate was never presented: " + why}
		t.Errorf("L44 %s: %s; the cell is INVALID (R6)", label, x.invalid)
		return x
	}
	// tryBind cuts its error text before this scrub, and that is safe: no
	// password reaches a bind error. The admin and DSRM passwords never enter the
	// LDAP path; port49's own reaches the directory code only through
	// LoadCredentials, whose errors name the variable and not the value; the
	// dialer's refusals are port49's formatted text plus AD's diagnostic; and
	// refusalChecks asserts, against this DC, that nothing the pool said holds a
	// password. A half-password needs a password in the text first. Do not
	// "fix" L43's cut.
	x := l44Ext{l43Cell: l.tryBind(t, ev, label, bind, "")}
	x.text = winScrub(x.text, l.l44Secrets()...)
	if !x.ok {
		if x.invalid = l44ConnFailed(x.l43Cell); x.invalid != "" {
			t.Errorf("L44 %s: %s; the cell is INVALID (R6)", label, x.invalid)
		}
		return x
	}
	id, err := l.l44WhoAmI(t, bind, true)
	switch {
	case err != nil:
		x.authzID = "WhoAmI failed: " + oneLineMax(winScrub(err.Error(), l.l44Secrets()...), 120)
	default:
		x.authzID = winScrub(id, l.l44Secrets()...)
	}
	if mapped && !strings.EqualFold(x.authzID, `u:CORP\port49`) {
		x.invalid = fmt.Sprintf("bound, but WhoAmI says %q, not u:CORP\\port49", x.authzID)
		t.Errorf("L44 %s: %s; the cell is INVALID (R6)", label, x.invalid)
	}
	return x
}

// l44LDAPSNoBind is the identity the DC gives an LDAPS connection that
// presented bind's certificate and bound nothing.
func (l *labDir) l44LDAPSNoBind(t *testing.T, ev *evidenceLog, bind directory.Bind) string {
	t.Helper()
	ev.mark("L44 LDAPS, the mapped certificate, no bind, a documented observation")
	id, err := l.l44WhoAmI(t, bind, false)
	id, err = winScrub(id, l.l44Secrets()...), l44ErrOrNil(err, l.l44Secrets())
	ev.whoami("ldaps, no bind", id, err)
	return l44NoBindRow(id, err)
}

// l44ErrOrNil is err scrubbed and cut, or nil.
func l44ErrOrNil(err error, secrets []string) error {
	if err == nil {
		return nil
	}
	return errors.New(oneLineMax(winScrub(err.Error(), secrets...), 160))
}

// l44NoBindRow is the Binds row for an LDAPS connection that presented the
// mapped certificate and bound nothing: AD authenticates it at the handshake.
func l44NoBindRow(id string, err error) string {
	what := "LDAPS with the mapped certificate and no bind, an observation: WhoAmI is "
	switch {
	case err != nil:
		return fmt.Sprintf("| %s | WhoAmI failed: `%s` | — | — |\n", what[:len(what)-len("WhoAmI is ")], l44MDCell(err.Error()))
	case id == "":
		return fmt.Sprintf("| %sanonymous (empty) | — | — | — |\n", what)
	}
	return fmt.Sprintf("| %s`%s` | — | — | — |\n", what, l44MDCell(id))
}

// l44BindsTail is what follows the Binds table: whether the LDAPS port asked
// for a certificate and, when LDAPS accepted EXTERNAL, a plain sentence saying
// so. It is written after the table: a blank line inside it would split it.
func l44BindsTail(requested string, ldapsAccepted bool) string {
	s := fmt.Sprintf("\nWhether the DC's LDAPS asked the client for a certificate (what EXTERNAL needs): %s.\n", requested)
	if ldapsAccepted {
		s += "\nLDAPS accepted EXTERNAL here, contrary to [MS-ADTS] 5.1.1.2.\n"
	}
	return s
}

// l44ConnFailed is why a refused EXTERNAL cell is no refusal, or "" when it is
// one: only port49's own bind error (an *ldap.Error whose cause is "bind
// external as ...", which l44FromBind reads off the error itself) carrying the
// directory's result code (1 to 199) is the DC saying no. A TLS or StartTLS
// failure before the bind (port49 returns it unwrapped, and a server can refuse
// StartTLS with an LDAP result too) and a timeout say nothing about the mapping.
func l44ConnFailed(c l43Cell) string {
	if c.fromBind && c.code > 0 && c.code < 200 {
		return ""
	}
	return "the connection failed before the bind (TLS, StartTLS or a timeout): " + c.text
}

// l44GSSAPIFailed is why a refused GSSAPI cell is no refusal, or "" when it is
// one: AD's answer to the bind (port49's own bind error with a code from 1 to
// 199) or the KDC refusing port49's own principal (directory.ErrBindRefused,
// and the KDC's text names the client). conn.go reads every KDC error that is
// not infrastructure as ErrBindRefused, which includes the service ticket
// (KDC_ERR_S_PRINCIPAL_UNKNOWN, as when ldap/localhost dropped off DC1$ in gate
// runs 8 and 9) and the clock (KRB_AP_ERR_SKEW): those are the lab failing, not
// a verdict on port49. A KDC that does not answer, a timeout and a network
// error are the setup failing too.
func l44GSSAPIFailed(c l43Cell) string {
	if c.fromBind && c.code > 0 && c.code < 200 {
		return ""
	}
	if c.kdcRefused {
		for _, client := range []string{"KDC_ERR_C_PRINCIPAL_UNKNOWN", "KDC_ERR_PREAUTH_FAILED", "KDC_ERR_CLIENT_REVOKED"} {
			if strings.Contains(c.text, client) {
				return ""
			}
		}
		return "the connection or the KDC failed before the bind (the KDC refused something other than port49's principal, " +
			"such as the service ticket or the clock): " + c.text
	}
	return "the connection or the KDC failed before the bind: " + c.text
}

// l44GSSAPIRow is a GSSAPI cell's Binds row and, when the cell is INVALID
// (R6), why. c.text arrives scrubbed.
func l44GSSAPIRow(what string, c l43Cell) (string, string) {
	if c.ok || c.atLoad {
		return c.row(what), ""
	}
	if why := l44GSSAPIFailed(c); why != "" {
		return fmt.Sprintf("| %s | INVALID (R6): %s | %d | %s |\n", what, l44MDCell(why), c.code, c.took.Round(time.Millisecond)), why
	}
	return c.row(what), ""
}

// l44ExtRow is an EXTERNAL cell in the Binds table.
func l44ExtRow(label string, x l44Ext) string {
	switch {
	case x.invalid != "":
		return fmt.Sprintf("| %s | INVALID (R6): %s | %d | %s |\n", label, l44MDCell(x.invalid), x.code, x.took.Round(time.Millisecond))
	case x.ok:
		return fmt.Sprintf("| %s | accepted; WhoAmI `%s`; a search for alice found %d entry | 0 | %s |\n", label,
			l44MDCell(x.authzID), x.read, x.took.Round(time.Millisecond))
	}
	return x.row(label)
}

// l44ExternalRow is one EXTERNAL cell in the matrix.
func l44ExternalRow(enforcement string, x l44Ext, evs []winEvent) string {
	outcome := fmt.Sprintf("refused, LDAP result %d", x.code)
	switch {
	case x.invalid != "":
		outcome = "INVALID (R6): " + x.invalid
	case x.ok:
		outcome = "**bound** as `" + x.authzID + "`"
	}
	return fmt.Sprintf("| %s | the broker's AD CS certificate, SASL EXTERNAL over StartTLS | port49's form, on port49 | %s | %s | %s | %s |\n",
		enforcement, l44MDCell(outcome), l44MDCell(x.text), l44EventsCell(evs), x.took.Round(time.Millisecond))
}

// l44EventsCell is a cell's events, each "<source> <id>: <message>", pipes
// escaped; "(none)" when there are none. The events come from l44Events,
// whose messages are scrubbed and cut already.
func l44EventsCell(evs []winEvent) string {
	if len(evs) == 0 {
		return "(none)"
	}
	return l44MDCell(strings.Join(l44EventStrings(evs), "; "))
}

func l44EventStrings(evs []winEvent) []string {
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		src := e.Provider
		switch {
		case strings.Contains(src, "Kerberos-Key-Distribution-Center") || src == "KDC":
			src = "KDC"
		case strings.Contains(src, "DomainService") || strings.Contains(src, "Directory"):
			src = "DS"
		}
		out = append(out, fmt.Sprintf("%s %d: %s", src, e.ID, strings.Join(strings.Fields(e.Message), " ")))
	}
	return out
}

// l44PreconditionIDs is every KDC event among evs that means the setup
// failed, not the mapping (winKDCPrecondition).
func l44PreconditionIDs(evs []winEvent) []int {
	var out []int
	for _, e := range evs {
		if (strings.Contains(e.Provider, "Kerberos-Key-Distribution-Center") || e.Provider == "KDC") && winKDCPrecondition(e.ID) {
			out = append(out, e.ID)
		}
	}
	return out
}

func l44MDCell(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

// l44Cell is one row of the binds table and what it measured.
type l44Cell struct{ what, row string }

// l44RowsUnder2 is the rows of the cells measured under
// LdapEnforceChannelBinding 2, or, when the DC booted again during them or a
// boot could not be read, an INVALID (R6) row for each and the reason. err
// arrives scrubbed and on one line; a row never spans lines regardless.
func l44RowsUnder2(cells []l44Cell, before, after string, err error) (string, string) {
	reason := ""
	switch {
	case err != nil:
		reason = "the DC's boot could not be read around them: " + err.Error()
	case winBootChanged(before, after):
		reason = fmt.Sprintf("the DC booted again during them (boot %s, then %s)", before, after)
	}
	var b strings.Builder
	for _, c := range cells {
		if reason == "" {
			b.WriteString(c.row)
		} else {
			fmt.Fprintf(&b, "| %s | INVALID (R6): %s | n/a | — |\n", l44MDCell(c.what), l44MDCell(strings.Join(strings.Fields(reason), " ")))
		}
	}
	return b.String(), reason
}

// l44AsInstalled is the registry value a facts-table entry records, as
// registry.ps1 sets it (-1 deletes): "absent" is the only value that means none.
func l44AsInstalled(v string) int {
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return -1
	}
	return n
}

// l44GuardRegistry returns the restore of a setting the run is about to
// change: it puts name back to installed (a value from the facts table, -1 for
// absent). Callers defer it before the change and call it on the normal path;
// it runs once, and never fails the test fatally, because it may run while a
// failure unwinds (t.Fatalf there would re-enter Goexit).
func (l *labDir) l44GuardRegistry(t *testing.T, name string, installed int) func() {
	done := false
	return func() {
		if done {
			return
		}
		done = true
		var r winRegistryResult
		if err := l.win.try(t, "registry", map[string]any{"name": name, "value": installed}, winRegistryWithin, &r); err != nil {
			t.Errorf("L44: restoring %s to the value installed: %s", name, l.l44Err(err))
			return
		}
		if r.Restarted == "reboot" {
			if err := l.win.awaitReboot(t, r.Boot, winRebootWithin); err != nil {
				t.Errorf("L44: restoring %s to the value installed: %v", name, err)
			}
		}
	}
}

// l44KDCDown is how long OR-1 keeps the KDC down: the scheduled start fires
// that long after the stop registered it. l44KDCMargin is how close to it e5's
// bind may end.
const (
	l44KDCDown   = 90 * time.Second
	l44KDCMargin = 10 * time.Second
)

// l44KDCTooNear is why e5, which began after the stop and ended elapsed after
// t0 (taken just before it), shows nothing: its bind ended too near the KDC's
// scheduled start to have run against a stopped KDC. "" when it is valid.
func l44KDCTooNear(elapsed time.Duration) string {
	if elapsed > l44KDCDown-l44KDCMargin {
		return fmt.Sprintf("the bind ended %s after the stop, too near the KDC's scheduled start (%s)",
			elapsed.Round(time.Millisecond), l44KDCDown)
	}
	return ""
}

// l44KDCCheck is what service.ps1's check answers, on the DC's clock.
type l44KDCCheck struct {
	Status     string `json:"status"`
	Now        string `json:"now"`
	TaskRan    string `json:"task_ran"`
	TaskResult string `json:"task_result"`
	TaskLeft   bool   `json:"task_left"`
}

// l44KDCRecovered is why a check does not prove the KDC came back, or "" when
// it does: Running, started by a task that ended with 0, the task gone, and
// that task run no earlier than the stop (stoppedAt, "" if unknown, less two
// seconds: the Task Scheduler cuts its trigger to the whole second).
func l44KDCRecovered(c l44KDCCheck, stoppedAt string) string {
	if stoppedAt == "" && c.Status == "Running" && c.TaskRan == "" && !c.TaskLeft {
		return "" // the stop never happened (its task was not registered): nothing to come back from
	}
	switch {
	case c.Status != "Running":
		return "the KDC is " + c.Status
	case c.TaskResult != "0":
		return "the start task's result is " + strconv.Quote(c.TaskResult)
	case c.TaskLeft:
		return "the start task could not be removed"
	}
	if stoppedAt == "" {
		return ""
	}
	stopped, err := time.Parse(time.RFC3339Nano, stoppedAt)
	if err != nil {
		return "the stop time is unreadable: " + err.Error()
	}
	ran, err := time.Parse(time.RFC3339Nano, c.TaskRan)
	if err != nil {
		return "the start task's run time is unreadable: " + err.Error()
	}
	if ran.Before(stopped.Add(-2 * time.Second)) {
		return "the start task last ran before the stop"
	}
	return ""
}

// l44AwaitKDC waits out the KDC's scheduled start (t0 is the host's clock just
// before the stop), then asks service.ps1's check until the KDC is proved back
// or the start is three minutes late. It calls nothing before the start: no
// SSH logon works while the KDC is down. A failed logon after it is expected,
// not an error. It never fails the test, and returns the last check it read.
func (l *labDir) l44AwaitKDC(t *testing.T, t0 time.Time, stoppedAt string) (l44KDCCheck, error) {
	t.Helper()
	w := l.win
	time.Sleep(time.Until(t0.Add(l44KDCDown + 2*time.Second)))
	deadline := t0.Add(l44KDCDown + 3*time.Minute)
	var last l44KDCCheck
	why := "no check answered"
	for {
		var r l44KDCCheck
		if err := w.try(t, "service", map[string]any{"name": "Kdc", "state": "check"}, time.Minute, &r); err != nil {
			why = "no check answered: " + l.l44Err(err)
		} else if last, why = r, l44KDCRecovered(r, stoppedAt); why == "" {
			return last, nil
		}
		if time.Now().After(deadline) {
			return last, errors.New(why)
		}
		time.Sleep(10 * time.Second)
	}
}
