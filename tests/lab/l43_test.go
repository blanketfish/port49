//go:build lab

package lab

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/directory"
)

const l43Claim = "Which bind mechanisms each directory accepts from port49-broker, and how each refusal reads: SASL " +
	"EXTERNAL over LDAPS with a client certificate (OpenLDAP mapping it by `olcAuthzRegexp`); GSSAPI with a keytab " +
	"and no SASL security layer, over LDAPS (Samba AD's KDC); simple bind over LDAPS; and a simple bind over plain " +
	"LDAP to a directory configured to require TLS (policy engine spec §15 L43). Samba's GSSAPI and plain-LDAP " +
	"cells are measured under `ldap server require strong auth = yes` and again under the setting that permits " +
	"SASL over TLS."

// l43Cell is one bind attempt's outcome.
type l43Cell struct {
	mech    string
	ok      bool
	code    int    // LDAP result code of a refusal; -1 for none (a load error, a Kerberos refusal)
	text    string // the error as port49 wrote it, never a secret
	read    int    // entries a search for alice found on an accepted bind
	took    time.Duration
	atLoad  bool // refused before any connection: the credential did not load
	rawText string
}

func (c l43Cell) row(label string) string {
	switch {
	case c.ok:
		return fmt.Sprintf("| %s | accepted; a search for alice found %d entry | 0 | %s |\n", label, c.read, c.took.Round(time.Millisecond))
	case c.atLoad:
		return fmt.Sprintf("| %s | refused at load, no connection made: `%s` | n/a | %s |\n", label, c.text, c.took.Round(time.Millisecond))
	}
	return fmt.Sprintf("| %s | refused: `%s` | %d | %s |\n", label, c.text, c.code, c.took.Round(time.Millisecond))
}

// tryBind dials and binds through the broker's own NewDialer and, when it is
// accepted, searches for alice to show the bound identity can read the
// directory. password is the simple bind's.
func (l *labDir) tryBind(t *testing.T, ev *evidenceLog, label string, bind directory.Bind, password string) l43Cell {
	t.Helper()
	cell := l43Cell{mech: string(bind.Mechanism), code: -1}
	cfg := l.config("direct", l.groupsBaseDN, bind, sanEmail())
	start := time.Now()
	cr, err := directory.LoadCredentials(bind, getenvOf(password))
	if err != nil {
		cell.atLoad, cell.text, cell.took = true, oneLineMax(err.Error(), 300), time.Since(start)
		ev.bind(label, err, cell.took)
		return cell
	}
	dial, err := directory.NewDialer(cfg, cr)
	if err != nil {
		t.Fatalf("%s %s: %v", l.name, label, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := dial(ctx, cfg.Servers[0])
	cell.took = time.Since(start)
	ev.bind(label, err, cell.took)
	if err != nil {
		cell.text, cell.code = oneLineMax(err.Error(), 300), ldapCode(err)
		// Every refusal is said with the mechanism and, when the directory
		// gave one, the code (port49's side of the claim).
		if !strings.Contains(err.Error(), "bind "+string(bind.Mechanism)+" as ") {
			t.Errorf("%s %s: the refusal does not name the mechanism: %v", l.name, label, err)
		}
		if code := ldapCode(err); code > 0 && !strings.Contains(err.Error(), fmt.Sprintf("LDAP result %d", code)) {
			t.Errorf("%s %s: the refusal does not name the result code %d: %v", l.name, label, code, err)
		}
		return cell
	}
	defer c.Close()
	res, err := c.SearchContext(ctx, ldap.NewSearchRequest(l.baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 15, false,
		fmt.Sprintf("(&%s(%s=alice))", l.userFilter, l.usernameAttr), []string{"mail"}, nil), 0)
	if err != nil {
		t.Errorf("%s %s: accepted, but the search for alice failed: %v", l.name, label, err)
		return cell
	}
	cell.ok, cell.read = true, len(res.Entries)
	return cell
}

// tryPlain is a simple bind over plain LDAP, built by hand because port49
// refuses to make one (NewDialer: ldap:// needs start_tls).
func (l *labDir) tryPlain(t *testing.T, ev *evidenceLog, label string) l43Cell {
	t.Helper()
	cell := l43Cell{mech: "simple (plain LDAP)", code: -1}
	start := time.Now()
	conn, err := ldap.DialURL(l.plainURI)
	if err != nil {
		t.Fatalf("%s: dialling %s: %v", l.name, l.plainURI, err)
	}
	defer conn.Close()
	conn.SetTimeout(15 * time.Second)
	err = conn.Bind(l.bindDN, l.d.password)
	cell.took = time.Since(start)
	ev.bind(label, err, cell.took)
	if err == nil {
		cell.ok = true
		return cell
	}
	cell.code = ldapCode(err)
	// What the directory says, not what port49 says: the result code and
	// go-ldap's text, which carries the directory's diagnostic and never the
	// password the bind sent.
	cell.text = oneLineMax(err.Error(), 300)
	return cell
}

func TestL43BindMechanisms(t *testing.T) {
	d := startDirectories(t)
	for _, dir := range d.all() { // openldap, samba_ad
		t.Run(dir.name, func(t *testing.T) {
			ev := evidence(t, d, "L43-"+dir.name)
			var obs strings.Builder
			obs.WriteString(dir.configNote())
			obs.WriteString("### Bind\n\n| mechanism | outcome | LDAP result | time |\n|---|---|---|---|\n")

			ev.mark("L43 external")
			ext := dir.tryBind(t, ev, "external", dir.bindExternal(), "")
			obs.WriteString(ext.row("SASL EXTERNAL over LDAPS, the broker's certificate"))
			ev.mark("L43 simple over LDAPS")
			simple := dir.tryBind(t, ev, "simple", dir.bindSimple(), d.password)
			obs.WriteString(simple.row("simple bind over LDAPS"))
			// GSSAPI and the plain-LDAP bind depend on Samba's strong-auth
			// setting, so Samba runs them under both values.
			setting := ""
			if dir.name == platSamba {
				setting = " (`ldap server require strong auth = yes`)"
			}
			var gss l43Cell
			if dir.name == platSamba {
				ev.mark("L43 gssapi, strong auth yes")
				gss = dir.tryBind(t, ev, "gssapi, strong auth yes", dir.bindGSSAPI(), "")
				obs.WriteString(gss.row("GSSAPI over LDAPS, keytab, no SASL security layer" + setting))
			} else {
				obs.WriteString("| GSSAPI | not run: the OpenLDAP container has no KDC | n/a | n/a |\n")
			}
			ev.mark("L43 simple over plain LDAP")
			plain := dir.tryPlain(t, ev, "simple over plain LDAP, by hand"+strings.ReplaceAll(setting, "`", ""))
			obs.WriteString(plain.row("simple bind over plain LDAP, built by hand" + setting))
			if dir.name == platSamba {
				val := dir.setStrongAuth(t, "allow_sasl_over_tls")
				setting2 := " (`" + val + "`, after a restart)"
				ev.mark("L43 gssapi, strong auth allow_sasl_over_tls")
				gss2 := dir.tryBind(t, ev, "gssapi, strong auth allow_sasl_over_tls", dir.bindGSSAPI(), "")
				obs.WriteString(gss2.row("GSSAPI over LDAPS, keytab, no SASL security layer" + setting2))
				ev.mark("L43 simple over LDAPS, strong auth allow_sasl_over_tls")
				simple2 := dir.tryBind(t, ev, "simple, strong auth allow_sasl_over_tls", dir.bindSimple(), d.password)
				obs.WriteString(simple2.row("simple bind over LDAPS" + setting2))
				plain2 := dir.tryPlain(t, ev, "simple over plain LDAP, by hand, strong auth allow_sasl_over_tls")
				obs.WriteString(plain2.row("simple bind over plain LDAP, built by hand" + setting2))
				if !simple2.ok {
					t.Errorf("the simple bind over LDAPS stopped working under allow_sasl_over_tls: %+v", simple2)
				}
				if plain2.ok {
					t.Errorf("Samba accepted a simple bind over plain LDAP under allow_sasl_over_tls: %+v", plain2)
				}
			}
			fmt.Fprintf(&obs, "\nWhether the directory's LDAPS asked the client for a certificate (what EXTERNAL needs): %s. "+
				"A Samba refusal of EXTERNAL says nothing about a Windows DC (L44).\n", dir.certRequested(t))

			// The harness's own preconditions: a directory this lab
			// configured to accept a mechanism, and that does not, is a
			// broken fixture, not a result.
			if !simple.ok || simple.read != 1 {
				t.Errorf("the simple bind over LDAPS is the lab's premise and was not accepted: %+v", simple)
			}
			if dir.name == platOpenLDAP && (!ext.ok || ext.read != 1) {
				t.Errorf("OpenLDAP's authz-regexp maps the broker's certificate to port49's account by construction; EXTERNAL %+v", ext)
			}
			if plain.ok {
				t.Errorf("the directory accepted a simple bind over plain LDAP: it was configured to require TLS (%+v)", plain)
			}

			refusals, bad := dir.refusalChecks(t, ev)
			obs.WriteString(refusals)
			obs.WriteString(dir.mappingChecks(t, ev))
			ev.assertClean(t, d.password, bad)
			writeResult(t, d, "L43", dir.name, l43Claim, dir.version(t), obs.String(), "tests/lab/evidence/L43-"+dir.name+".json")
		})
	}
}

// refusalChecks binds with a wrong password through a resolver: the refusal
// is not a server fault, the query is directory_unavailable (so grace
// applies), the hold-off keeps a second bind from being sent, and nothing
// the pool said holds either password (pre-flight I-2).
func (l *labDir) refusalChecks(t *testing.T, ev *evidenceLog) (string, string) {
	t.Helper()
	ev.mark("L43 a wrong password through the pool")
	wrong := make([]byte, 8)
	_, _ = rand.Read(wrong)
	bad := "Wrong-" + hex.EncodeToString(wrong)
	cfg := l.config("direct", l.groupsBaseDN, l.bindSimple(), sanEmail())
	r := l.resolverWith(t, cfg, bad, ev)
	label := cfg.Servers[0].Label()
	l.d.takeSaid()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	_, err := r.Verify(ctx, l.principal("alice"))
	if !errors.Is(err, directory.ErrUnavailable) {
		t.Errorf("a query against a directory refusing the bind returned %v, want directory.ErrUnavailable (so grace applies)", err)
	}
	refusal := ""
	if err != nil {
		refusal = oneLineMax(err.Error(), 300)
	}
	if !strings.Contains(refusal, "LDAP result 49") {
		t.Errorf("the refusal does not read as result 49 (invalid credentials): %q", refusal)
	}
	q := func(outcome string) float64 {
		return testutil.ToFloat64(r.M.DirectoryQueries.WithLabelValues(label, outcome))
	}
	if q("refused") != 1 || q("fault") != 0 {
		t.Errorf("one refused bind, no fault counted: refused %v, fault %v", q("refused"), q("fault"))
	}
	if up := testutil.ToFloat64(r.M.DirectoryServerUp.WithLabelValues(label)); up != 1 {
		t.Errorf("a refused bind opened the server's breaker: port49_directory_server_up %v", up)
	}
	// Grace with nothing stored refuses too, saying why.
	_, merr := r.Map(ctx, l.d.pki.alice)
	if !errors.Is(merr, directory.ErrUnavailable) {
		t.Errorf("Map with the bind refused and nothing stored returned %v, want directory.ErrUnavailable", merr)
	}
	// The hold-off: no second bind is sent while it runs.
	if q("refused") != 1 {
		t.Errorf("a second query during the hold-off sent another bind: refused %v", q("refused"))
	}
	said := l.d.takeSaid()
	for _, s := range said {
		if strings.Contains(s, bad) || strings.Contains(s, l.d.password) {
			t.Fatalf("a line the pool said holds a bind password")
		}
	}
	if err != nil && (strings.Contains(err.Error(), bad) || strings.Contains(err.Error(), l.d.password)) {
		t.Fatalf("the refusal holds a bind password")
	}
	var b strings.Builder
	b.WriteString("\n### A refused bind through the pool (a wrong password)\n\n| check | observed |\n|---|---|\n")
	fmt.Fprintf(&b, "| `Resolver.Verify` | `%s` |\n", refusal)
	fmt.Fprintf(&b, "| `Resolver.Map`, nothing stored | `%s` |\n", errOrOK(merr))
	fmt.Fprintf(&b, "| counters | queries{refused}=%v, queries{fault}=%v, server_up=1 |\n", q("refused"), q("fault"))
	fmt.Fprintf(&b, "| lines the pool said | %d, none holding a password |\n", len(said))
	return b.String(), bad
}

// mappingChecks is port49's mapping end to end through Resolver.Map and
// Verify, each asserted: these are port49's guarantees, not a directory's.
func (l *labDir) mappingChecks(t *testing.T, ev *evidenceLog) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("\n### Also asserted: port49's mapping guarantees (not part of L43's claim)\n\n" +
		"These are port49's own guarantees on a real directory and close nothing in the register. The `issuer_serial` and `sid` " +
		"rows compare port49's `X509:<I>...<SR>...` form and its SID extension with what port49 itself wrote or built: they show " +
		"the value survives filter escaping and a string-form `objectSid` matches, not that a DC accepts it (L44).\n\n" +
		"| check | observed |\n|---|---|\n")
	row := func(check, observed string) { fmt.Fprintf(&b, "| %s | %s |\n", check, observed) }
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cfgFor := func(m directory.Mapping, groupsBase string) directory.Config {
		return l.config("direct", groupsBase, l.bindSimple(), m)
	}
	alicePrincipal := l.principal("alice")

	// alice's certificate under san_email, pinned to the lab users CA.
	ev.mark("L43 mapping san_email alice")
	r := l.resolverWith(t, cfgFor(sanEmail(), l.groupsBaseDN), l.d.password, ev)
	a, err := r.Map(ctx, l.d.pki.alice)
	if err != nil || a.Principal != alicePrincipal || a.Username != "alice" || a.Source != directory.Fresh {
		t.Errorf("san_email did not map alice's certificate to her: %+v, %v", a, err)
	}
	row("alice's certificate under `san_email`, issuer pinned to `"+dirUsersCAIssuer+"`",
		fmt.Sprintf("%s as `%s`, username `%s`, DN `%s`", errOrOK(err), a.Principal, a.Username, a.DN))

	if l.name == platSamba {
		ev.mark("L43 mapping issuer_serial alice")
		r = l.resolverWith(t, cfgFor(directory.Mapping{Kind: directory.MapIssuerSerial}, l.groupsBaseDN), l.d.password, ev)
		a, err = r.Map(ctx, l.d.pki.alice)
		if err != nil || a.Principal != alicePrincipal {
			t.Errorf("issuer_serial did not map alice's certificate to her: %+v, %v", a, err)
		}
		row("alice's certificate under `issuer_serial`, the `altSecurityIdentities` the seed wrote from `directory.ADIssuerSerial`",
			fmt.Sprintf("%s as `%s`, DN `%s`", errOrOK(err), a.Principal, a.DN))

		ev.mark("L43 mapping sid alice")
		sidCert, _, cerr := l.d.pki.personCert("alice", "alice@corp.example.com", l.aliceSID(t), time.Now())
		if cerr != nil {
			t.Fatal(cerr)
		}
		r = l.resolverWith(t, cfgFor(directory.Mapping{Kind: directory.MapSID}, l.groupsBaseDN), l.d.password, ev)
		a, err = r.Map(ctx, sidCert)
		if err != nil || a.Principal != alicePrincipal {
			t.Errorf("sid did not map alice's certificate to her: %+v, %v", a, err)
		}
		row("alice's certificate under `sid`, the extension holding her `objectSid`",
			fmt.Sprintf("%s as `%s`, DN `%s`", errOrOK(err), a.Principal, a.DN))
	} else {
		row("`issuer_serial` and `sid`", "not run: OpenLDAP has no `altSecurityIdentities` or `objectSid`")
	}

	// eve's two entries hold one mail.
	ev.mark("L43 mapping san_email eve")
	r = l.resolverWith(t, cfgFor(sanEmail(), l.groupsBaseDN), l.d.password, ev)
	_, err = r.Map(ctx, l.d.pki.eve)
	if !errors.Is(err, directory.ErrAmbiguous) || !containsAllFold(errString(err), "ou=staff", "ou=contractors", "eve2") {
		t.Errorf("eve's certificate (two entries hold her mail) was not identity_ambiguous naming both: %v", err)
	}
	row("eve's certificate under `san_email` (`eve` and `eve2` hold one `mail`)", "`"+errOrOK(err)+"`")

	if l.name == platSamba {
		l.mailCollision(t, ev, &b, cfgFor(directory.Mapping{Kind: directory.MapIssuerSerial}, l.groupsBaseDN))
	}

	// two groups named netops-oncall: the name matches no one, the DN matches carol.
	ev.mark("L43 shared group name")
	l.d.takeSaid()
	r = l.resolverWith(t, cfgFor(sanEmail(), l.baseDN), l.d.password, ev)
	carol, err := r.Verify(ctx, l.principal("carol"))
	want := directory.CanonicalDN("cn=netops-oncall,ou=G," + l.baseDN)
	var dns []string
	for _, dn := range carol.GroupDNs {
		dns = append(dns, directory.CanonicalDN(dn))
	}
	said := strings.Join(l.d.takeSaid(), "\n")
	if err != nil || slices.Contains(carol.GroupNames, "netops-oncall") || !slices.Contains(dns, want) || !strings.Contains(said, "shared by") {
		t.Errorf("a name two groups share must match no one while the DN still matches carol: names %v, DNs %v, said %q, err %v",
			carol.GroupNames, carol.GroupDNs, said, err)
	}
	names := strings.Join(carol.GroupNames, ", ")
	if names == "" {
		names = "(none)"
	}
	row("`netops-oncall` named by two groups (`OU=G` and `OU=Users-Can-Create`), groups base the whole domain, carol (direct member of the first)",
		fmt.Sprintf("names `%s`; DNs `%s`; the line said: `%s`", names, strings.Join(carol.GroupDNs, "; "),
			oneLineMax(said, 260)))
	return b.String()
}

// mailCollision is pre-flight C-2 on Samba: bob is given alice's mail, and
// both people are refused, by the certificate and by the principal; then the
// mail is put back and alice maps again.
func (l *labDir) mailCollision(t *testing.T, ev *evidenceLog, b *strings.Builder, cfg directory.Config) {
	t.Helper()
	bobDN := "CN=bob,OU=Staff," + dirBase
	set := func(mail string) {
		if out, err := l.exec("/lab/set-attr.sh", bobDN, "mail", mail); err != nil {
			t.Fatalf("setting bob's mail: %v\n%s", err, tailOf(out, 400))
		}
	}
	set("alice@corp.example.com")
	restored := false
	restore := func() {
		if !restored {
			set("bob@corp.example.com")
			restored = true
		}
	}
	t.Cleanup(restore)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ev.mark("L43 mapping mail collision: bob given alice's mail")
	r := l.resolverWith(t, cfg, l.d.password, ev)
	_, err1 := r.Map(ctx, l.d.pki.alice)
	_, err2 := r.Verify(ctx, l.principal("alice"))
	for what, err := range map[string]error{"Map by issuer_serial": err1, "Verify by principal": err2} {
		if !errors.Is(err, directory.ErrAmbiguous) || !containsAllFold(errString(err), "cn=alice,ou=staff", "cn=bob,ou=staff") {
			t.Errorf("%s: with bob holding alice's mail it was not identity_ambiguous naming both DNs: %v", what, err)
		}
	}
	restore()
	ev.mark("L43 mapping mail collision: bob's mail restored")
	_, err3 := r.Map(ctx, l.d.pki.alice)
	if err3 != nil {
		t.Errorf("with bob's mail restored alice's certificate still does not map: %v", err3)
	}
	fmt.Fprintf(b, "| `principal_attribute: mail`; `samba-tool`-equivalent edit gives bob alice's `mail`; alice's certificate under `issuer_serial` | `%s` |\n", errOrOK(err1))
	fmt.Fprintf(b, "| the same, `Verify` of `user:alice@corp.example.com` | `%s` |\n", errOrOK(err2))
	fmt.Fprintf(b, "| bob's `mail` restored, alice's certificate again | %s |\n", errOrOK(err3))
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// containsAllFold reports whether s holds every sub, ignoring case.
func containsAllFold(s string, subs ...string) bool {
	s = strings.ToLower(s)
	for _, sub := range subs {
		if !strings.Contains(s, strings.ToLower(sub)) {
			return false
		}
	}
	return true
}
