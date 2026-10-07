package directory

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	krbflags "github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/testpki"
)

// A simple bind's password and a keytab's bytes never appear in any
// formatting of the credentials (Global Constraints; Ruling 18).
func TestCredentialsWithholdTheirSecrets(t *testing.T) {
	cr, err := LoadCredentials(Bind{Mechanism: "simple", BindDN: "CN=port49,DC=corp", PasswordEnv: "P"},
		func(string) string { return "hunter2-very-secret" })
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{fmt.Sprint(cr), fmt.Sprintf("%v", cr), fmt.Sprintf("%+v", cr), fmt.Sprintf("%#v", cr),
		fmt.Sprintf("%s", cr)} {
		if strings.Contains(s, "hunter2") {
			t.Fatalf("the password leaked: %s", s)
		}
	}
	if cr.Who() != "CN=port49,DC=corp" || !strings.Contains(cr.String(), "simple") {
		t.Fatalf("%s / %s", cr.Who(), cr.String())
	}
}

// A keytab another user could read is refused, before gokrb5 sees it: the
// keytab here is valid, so only the permission check can say no.
func TestAGroupReadableKeytabIsRefused(t *testing.T) {
	dir := t.TempDir()
	kt := writeKeytab(t, dir)
	if err := os.Chmod(kt, 0o640); err != nil {
		t.Fatal(err)
	}
	krb := filepath.Join(dir, "krb5.conf")
	os.WriteFile(krb, []byte(krb5conf("127.0.0.1:88")), 0o644)
	_, err := LoadCredentials(Bind{Mechanism: "gssapi", KeytabFile: kt, Principal: "port49$@CORP.EXAMPLE.COM",
		KRB5Conf: krb}, os.Getenv)
	if err == nil || !strings.Contains(err.Error(), "keytab_file") || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("%v", err)
	}
}

// Start refuses what a bind would otherwise read as the KDC's refusal: a
// principal without a realm, a keytab with no key for it, a realm no KDC is
// configured for.
func TestGSSAPICredentialsAreCheckedAtStart(t *testing.T) {
	dir := t.TempDir()
	kt := writeKeytab(t, dir)
	conf := func(body string) string {
		p := filepath.Join(t.TempDir(), "krb5.conf")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for name, tc := range map[string]struct {
		principal, conf, want string
	}{
		"no realm":    {"port49$", conf("[libdefaults]\n default_realm = CORP.EXAMPLE.COM\n"), "principal"},
		"empty realm": {"port49$@", conf(krb5conf("127.0.0.1:88")), "principal"},
		"no key":      {"someone-else@CORP.EXAMPLE.COM", conf(krb5conf("127.0.0.1:88")), "no key"},
		"no KDC":      {"port49$@CORP.EXAMPLE.COM", conf("[libdefaults]\n default_realm = CORP.EXAMPLE.COM\n[realms]\n CORP.EXAMPLE.COM = {\n }\n"), "KDC"},
	} {
		_, err := LoadCredentials(Bind{Mechanism: "gssapi", KeytabFile: kt, Principal: tc.principal, KRB5Conf: tc.conf}, os.Getenv)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TLS verifies the server against ca_file under the URI's host name, and
// presents the broker's own certificate only for EXTERNAL.
func TestTLSConfigVerifiesTheServerName(t *testing.T) {
	pki, err := testpki.NewCA("lab directory CA", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pki.PEM(), 0o644)
	tc, err := tlsConfig(Config{CAFile: ca}, Server{URI: "ldaps://dc-01.corp.example.com:636"}, &Credentials{mech: "simple"})
	if err != nil || tc.ServerName != "dc-01.corp.example.com" || tc.InsecureSkipVerify || tc.RootCAs == nil ||
		len(tc.Certificates) != 0 {
		t.Fatalf("%+v %v", tc, err)
	}
}

// Nothing is dialled in clear: an ldap:// server with no StartTLS is
// refused before any connection is made.
func TestTheDialerRefusesAClearConnection(t *testing.T) {
	dial, err := NewDialer(Config{CAFile: "/nonexistent", QueryTimeout: time.Second}, &Credentials{mech: "simple"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = dial(context.Background(), Server{URI: "ldap://dc-01.corp.example.com"})
	if err == nil || !strings.Contains(err.Error(), "start_tls") || Refusal(err) || Fault(err) {
		t.Fatalf("%v", err)
	}
}

// ldapBindServer answers one bind request on a pipe with result code, a
// diagnostic naming a secret, and returns the client's end.
func ldapBindServer(t *testing.T, code int64, diag string) *ldap.Conn {
	t.Helper()
	cc, sc := net.Pipe()
	go func() {
		defer sc.Close()
		p, err := ber.ReadPacket(sc)
		if err != nil {
			return
		}
		env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, p.Children[0].Value, "MessageID"))
		resp := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindResponse, nil, "Bind Response")
		resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "resultCode"))
		resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
		resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diag, "diagnosticMessage"))
		env.AppendChild(resp)
		_, _ = sc.Write(env.Bytes())
		_, _ = io.Copy(io.Discard, sc)
	}()
	conn := ldap.NewConn(cc, false)
	conn.Start()
	t.Cleanup(func() { conn.Close() })
	return conn
}

// A simple bind's LDAP result is kept as a code (invalidCredentials is a
// refusal, busy a fault) and the server's diagnostic and the password are
// in no error.
func TestASimpleBindClassifiesItsResult(t *testing.T) {
	cr, _ := LoadCredentials(Bind{Mechanism: "simple", BindDN: "CN=port49,DC=corp", PasswordEnv: "P"},
		func(string) string { return "hunter2-very-secret" })
	for _, tc := range []struct {
		code           int64
		refusal, fault bool
	}{
		{ldap.LDAPResultInvalidCredentials, true, false},
		{ldap.LDAPResultStrongAuthRequired, true, false},
		{ldap.LDAPResultBusy, false, true},
	} {
		err := bind(context.Background(), ldapBindServer(t, tc.code, "80090308: LdapErr data 52e, hunter2-very-secret"), Server{URI: "ldaps://dc-01"}, cr)
		if err == nil || Refusal(err) != tc.refusal || Fault(err) != tc.fault {
			t.Fatalf("code %d: refusal %v fault %v: %v", tc.code, Refusal(err), Fault(err), err)
		}
		if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "LdapErr") {
			t.Fatalf("code %d leaked: %v", tc.code, err)
		}
	}
}

// stubGSS is a GSSAPI client that sends one token and records the AP options
// it was asked to send it with; the fake LDAP server then answers the bind.
type stubGSS struct{ apOptions *[]int }

func (g stubGSS) InitSecContext(string, []byte) ([]byte, bool, error) {
	return g.InitSecContextWithOptions("", nil, nil)
}
func (g stubGSS) InitSecContextWithOptions(_ string, _ []byte, opts []int) ([]byte, bool, error) {
	*g.apOptions = opts
	return []byte("token"), false, nil
}
func (stubGSS) NegotiateSaslAuth([]byte, string) ([]byte, error) { return nil, nil }
func (stubGSS) DeleteSecContext() error                          { return nil }

// A bind's *ldap.Error cause reads "bind <mech> as <who>: LDAP result <code>".
// The L44 harness (tests/lab, l44FromBind) tells the directory's own answer
// from a failure before the bind by that prefix; a reword would turn real
// refusals INVALID there.
func TestABindErrorNamesItsMechanismAndWho(t *testing.T) {
	// bind reads only mech and who of an external credential (the
	// certificate is the TLS handshake's).
	external := &Credentials{mech: "external", who: "CN=port49-svc,O=lab"}
	simple, _ := LoadCredentials(Bind{Mechanism: "simple", BindDN: "CN=port49,DC=corp", PasswordEnv: "P"},
		func(string) string { return "pw" })
	gss := gssapiCredentials(t, "127.0.0.1:1")
	gss.gssCtx = func() ldap.GSSAPIClient { return stubGSS{apOptions: new([]int)} }
	for _, cr := range []*Credentials{simple, external, gss} {
		err := bind(context.Background(), ldapBindServer(t, ldap.LDAPResultInvalidCredentials, "diag"),
			Server{URI: "ldaps://dc-01.corp.example.com"}, cr)
		var le *ldap.Error
		if !errors.As(err, &le) || le.Err == nil {
			t.Fatalf("%s: not an *ldap.Error with a cause: %v", cr.mech, err)
		}
		want := fmt.Sprintf("bind %s as %s: LDAP result 49", cr.mech, cr.who)
		if le.Err.Error() != want {
			t.Errorf("%s: cause %q, want %q", cr.mech, le.Err.Error(), want)
		}
	}
}

// AD answers an AP-REQ without mutual-required with 49 (AcceptSecurityContext
// data 57, L44), though go-ldap's client asks for mutual authentication in the
// checksum; the bind must send the option, as MIT's client does.
func TestAGSSAPIBindAsksForMutualRequired(t *testing.T) {
	var got []int
	cr := gssapiCredentials(t, "127.0.0.1:1")
	cr.gssCtx = func() ldap.GSSAPIClient { return stubGSS{apOptions: &got} }
	_ = bind(context.Background(), ldapBindServer(t, ldap.LDAPResultInvalidCredentials, ""),
		Server{URI: "ldaps://dc-01.corp.example.com"}, cr)
	if !slices.Contains(got, krbflags.APOptionMutualRequired) {
		t.Fatalf("AP options %v lack mutual-required (%d)", got, krbflags.APOptionMutualRequired)
	}
}

// writeKeytab is a keytab for port49$@CORP.EXAMPLE.COM, mode 0600.
func writeKeytab(t *testing.T, dir string) string {
	t.Helper()
	kt := keytab.New()
	if err := kt.AddEntry("port49$", "CORP.EXAMPLE.COM", "not-a-real-key", time.Now(), 1, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatal(err)
	}
	raw, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "port49.keytab")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// krb5conf is a krb5.conf for CORP.EXAMPLE.COM with one KDC, TCP only.
func krb5conf(kdc string) string {
	return fmt.Sprintf("[libdefaults]\n default_realm = CORP.EXAMPLE.COM\n udp_preference_limit = 1\n"+
		"[realms]\n CORP.EXAMPLE.COM = {\n  kdc = %s\n }\n", kdc)
}

// gssapiCredentials is credentials for a KDC at kdc (host:port), TCP only.
func gssapiCredentials(t *testing.T, kdc string) *Credentials {
	t.Helper()
	dir := t.TempDir()
	krb := filepath.Join(dir, "krb5.conf")
	if err := os.WriteFile(krb, []byte(krb5conf(kdc)), 0o644); err != nil {
		t.Fatal(err)
	}
	cr, err := LoadCredentials(Bind{Mechanism: "gssapi", KeytabFile: writeKeytab(t, dir), Principal: "port49$@CORP.EXAMPLE.COM",
		KRB5Conf: krb}, os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	return cr
}

// fakeKDC answers every TCP request with a KRB-ERROR of code, and returns
// its address.
func fakeKDC(t *testing.T, code int32) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var n [4]byte
				if _, err := io.ReadFull(c, n[:]); err != nil {
					return
				}
				if _, err := io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint32(n[:]))); err != nil {
					return
				}
				e := messages.NewKRBError(types.NewPrincipalName(2, "krbtgt/CORP.EXAMPLE.COM"), "CORP.EXAMPLE.COM", code, "")
				b, _ := e.Marshal()
				binary.BigEndian.PutUint32(n[:], uint32(len(b)))
				_, _ = c.Write(append(n[:], b...))
			}()
		}
	}()
	return ln.Addr().String()
}

func idleConn(t *testing.T) *ldap.Conn {
	t.Helper()
	cc, sc := net.Pipe()
	t.Cleanup(func() { sc.Close() })
	conn := ldap.NewConn(cc, false)
	conn.Start()
	t.Cleanup(func() { conn.Close() })
	return conn
}

// A KDC that refuses the principal or the clock is the credential refused
// (ErrBindRefused: the pool's hold-off); a KDC that does not answer is a
// server fault (the breaker). Neither error carries the keytab.
func TestAGSSAPIBindClassifiesTheKDC(t *testing.T) {
	for _, code := range []int32{errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN, errorcode.KRB_AP_ERR_SKEW,
		errorcode.KDC_ERR_PREAUTH_FAILED} {
		cr := gssapiCredentials(t, fakeKDC(t, code))
		err := bind(context.Background(), idleConn(t), Server{URI: "ldaps://dc-01.corp.example.com"}, cr)
		if err == nil || !errors.Is(err, ErrBindRefused) || !Refusal(err) || Fault(err) {
			t.Fatalf("KDC error %d: %v", code, err)
		}
		if strings.Contains(err.Error(), "not-a-real-key") {
			t.Fatalf("leaked: %v", err)
		}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()
	err = bind(context.Background(), idleConn(t), Server{URI: "ldaps://dc-01.corp.example.com"}, gssapiCredentials(t, dead))
	if err == nil || errors.Is(err, ErrBindRefused) || Refusal(err) || !strings.Contains(err.Error(), "Networking_Error") {
		t.Fatalf("an unreachable KDC is no refusal: %v", err)
	}
}

// The classification alone: what gokrb5 reports as text.
func TestKerberosErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		err     error
		refused bool
	}{
		{fmt.Errorf("could not get valid TGT for client's realm: [Root cause: Networking_Error] x"), false},
		{fmt.Errorf("communication error with KDC via TCP: x"), false},
		{fmt.Errorf("[Root cause: Configuration_Error] AS Exchange cannot be performed"), false},
		{context.DeadlineExceeded, false},
		{&net.OpError{Op: "dial", Err: errors.New("refused")}, false},
		{fmt.Errorf("[Root cause: KDC_Error] KRB Error: KDC_ERR_PREAUTH_FAILED"), true},
		{fmt.Errorf("[Root cause: KRBMessage_Handling_Error] AS_REP is not valid or client password/keytab incorrect"), true},
	} {
		if got := kerberosRefused(tc.err); got != tc.refused {
			t.Errorf("%v: refused %v", tc.err, got)
		}
	}
}

// stalledKDC accepts and never answers.
func stalledKDC(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
	return ln.Addr().String()
}

// A KDC that never answers holds a bind only to its own query's deadline:
// the error is no refusal, the connection is closed, and two binds at once
// are not queued behind each other (no lock is held across the KDC).
func TestAStalledKDCHoldsABindOnlyToItsDeadline(t *testing.T) {
	cr := gssapiCredentials(t, stalledKDC(t))
	srv := Server{URI: "ldaps://dc-01.corp.example.com"}
	start := time.Now()
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			errs <- bind(ctx, idleConn(t), srv, cr)
		}()
	}
	for range 2 {
		if err := <-errs; err == nil || Refusal(err) || !errors.Is(err, context.DeadlineExceeded) || !Fault(err) {
			t.Fatalf("%v", err)
		}
	}
	if d := time.Since(start); d > 550*time.Millisecond {
		t.Fatalf("the binds took %v: one waited on the other", d)
	}
}

// The search a failover repeats is not changed by the first: the caller's
// request keeps its controls.
func TestSearchContextLeavesTheRequestAlone(t *testing.T) {
	req := ldap.NewSearchRequest("dc=corp", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(a=b)", nil, nil)
	cc, sc := net.Pipe()
	sc.Close()
	conn := ldap.NewConn(cc, false)
	conn.Start()
	defer conn.Close()
	_, _ = ldapClient{c: conn}.SearchContext(context.Background(), req, 100)
	if len(req.Controls) != 0 {
		t.Fatalf("%d controls", len(req.Controls))
	}
}

// A connection the server closed answers a search with a fault, never with
// an empty result: go-ldap's SearchAsync returns no results and no error on
// a closing connection, which the resolver would read as "no such entry"
// (identity_unmapped, a refusal stored over grace) for as long as the pool
// kept the connection (plan 7g Task 18, found on a stopped OpenLDAP).
func TestASearchOnAClosedConnectionIsAFault(t *testing.T) {
	cc, sc := net.Pipe()
	conn := ldap.NewConn(cc, false)
	conn.Start()
	t.Cleanup(func() { conn.Close() })
	sc.Close()
	for i := 0; !conn.IsClosing(); i++ {
		if i > 200 {
			t.Fatal("the connection never noticed the server had closed it")
		}
		time.Sleep(10 * time.Millisecond)
	}
	req := ldap.NewSearchRequest("dc=corp", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 5, false,
		"(mail=alice@corp.example.com)", []string{"dn"}, nil)
	res, err := ldapClient{c: conn}.SearchContext(context.Background(), req, 0)
	if err == nil || !Fault(err) {
		t.Fatalf("a search on a closed connection answered %+v, %v; want a fault", res, err)
	}
}

// scriptedConn is a searchConn scripted page by page: a page is its entries and
// whether the connection is closing after it, so a server that closes between
// two pages is exercised deterministically (the race with go-ldap's own check
// is the one a real server hits).
type scriptedConn struct {
	pages   []scriptedPage
	n       int
	closing bool
}

type scriptedPage struct {
	entries []*ldap.Entry
	cookie  []byte
	err     error
	close   bool // the server closes during this page: it ends with no result at all
}

func (f *scriptedConn) IsClosing() bool { return f.closing }
func (f *scriptedConn) Close() error    { f.closing = true; return nil }
func (f *scriptedConn) SearchAsync(_ context.Context, _ *ldap.SearchRequest, _ int) ldap.Response {
	p := f.pages[f.n]
	f.n++
	if p.close {
		f.closing = true
	}
	return &scriptedResponse{page: p}
}

type scriptedResponse struct {
	page scriptedPage
	i    int
	cur  *ldap.Entry
	ctl  []ldap.Control
}

func (r *scriptedResponse) Next() bool {
	r.cur, r.ctl = nil, nil
	if r.page.close {
		return false
	}
	if r.i < len(r.page.entries) {
		r.cur = r.page.entries[r.i]
		r.i++
		return true
	}
	if r.i == len(r.page.entries) && r.page.err == nil {
		r.i++
		pc := ldap.NewControlPaging(1)
		pc.SetCookie(r.page.cookie)
		r.ctl = []ldap.Control{pc}
		return true
	}
	return false
}
func (r *scriptedResponse) Entry() *ldap.Entry       { return r.cur }
func (r *scriptedResponse) Referral() string         { return "" }
func (r *scriptedResponse) Controls() []ldap.Control { return r.ctl }
func (r *scriptedResponse) Err() error {
	if r.i >= len(r.page.entries) {
		return r.page.err
	}
	return nil
}

func pageEntry(dn string) *ldap.Entry { return &ldap.Entry{DN: dn} }

func searchReq() *ldap.SearchRequest {
	return ldap.NewSearchRequest("dc=corp", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 5, false,
		"(objectClass=group)", []string{"dn"}, nil)
}

// A server that closes between two pages is a fault, never a truncated list
// read as complete: a narrowed group list revokes (Task 18 review, C1).
func TestAPagedSearchClosedBetweenPagesIsAFault(t *testing.T) {
	f := &scriptedConn{pages: []scriptedPage{{entries: []*ldap.Entry{pageEntry("cn=a")}, cookie: []byte("next")}, {close: true}}}
	res, err := ldapClient{c: f}.SearchContext(context.Background(), searchReq(), 1)
	if err == nil || !Fault(err) {
		t.Fatalf("answered %d entries, %v; want a fault", len(res.Entries), err)
	}
}

// Healthy answers stay answers: two pages, and an empty one (no such entry is
// an answer, and means unmapped or no groups).
func TestAHealthyPagedOrEmptySearchStaysAnAnswer(t *testing.T) {
	f := &scriptedConn{pages: []scriptedPage{{entries: []*ldap.Entry{pageEntry("cn=a")}, cookie: []byte("next")}, {entries: []*ldap.Entry{pageEntry("cn=b")}}}}
	res, err := ldapClient{c: f}.SearchContext(context.Background(), searchReq(), 1)
	if err != nil || len(res.Entries) != 2 {
		t.Fatalf("two pages: %d entries, %v", len(res.Entries), err)
	}
	f = &scriptedConn{pages: []scriptedPage{{}}}
	res, err = ldapClient{c: f}.SearchContext(context.Background(), searchReq(), 1)
	if err != nil || len(res.Entries) != 0 {
		t.Fatalf("empty: %d entries, %v", len(res.Entries), err)
	}
}

// A server that closes during a search ends it with a plain-text read error,
// which is the server's fault: it is an ErrorNetwork, so the query fails over,
// grace serves, and the dead connection leaves the pool (Task 18 review, I1).
// An LDAP result on the same connection is the server's answer and stays.
func TestAServerCloseMidSearchIsAFault(t *testing.T) {
	read := errors.New("unable to read LDAP response packet: EOF")
	for name, pages := range map[string][]scriptedPage{
		"before an entry": {{err: read, close: false}},
		"after an entry":  {{entries: []*ldap.Entry{pageEntry("cn=a")}, err: read}},
		"on a later page": {{entries: []*ldap.Entry{pageEntry("cn=a")}, cookie: []byte("n")}, {err: read}},
	} {
		f := &scriptedConn{pages: pages, closing: false}
		// the reader marks the connection closing before it reports the read
		cc := &closingAfterErr{scriptedConn: f}
		_, err := ldapClient{c: cc}.SearchContext(context.Background(), searchReq(), 1)
		if err == nil || !Fault(err) {
			t.Errorf("%s: %v is not a fault", name, err)
		}
	}
	f := &scriptedConn{pages: []scriptedPage{{err: ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("x"))}}, closing: true}
	f.closing = false
	cc := &closingAfterErr{scriptedConn: f}
	if _, err := (ldapClient{c: cc}).SearchContext(context.Background(), searchReq(), 1); err == nil || Fault(err) {
		t.Errorf("an LDAP result is an answer, not a fault: %v", err)
	}
}

// closingAfterErr marks the connection closing once a page's error is read.
type closingAfterErr struct{ *scriptedConn }

func (c *closingAfterErr) SearchAsync(ctx context.Context, r *ldap.SearchRequest, n int) ldap.Response {
	resp := c.scriptedConn.SearchAsync(ctx, r, n)
	return &closeOnErr{Response: resp, c: c.scriptedConn}
}

type closeOnErr struct {
	ldap.Response
	c *scriptedConn
}

func (r *closeOnErr) Err() error {
	err := r.Response.Err()
	if err != nil {
		r.c.closing = true
	}
	return err
}

// A mid-search close through the pool: the query is ErrUnavailable (so grace
// serves above it), the dead connection leaves the pool, and the next query
// dials a fresh one that answers (Task 18 review, I1).
func TestAMidSearchCloseServesGraceAndTheNextSearchDialsFresh(t *testing.T) {
	w := newWorld(t)
	dials := 0
	dial := func(context.Context, Server) (Client, error) {
		dials++
		if dials == 1 {
			return ldapClient{c: &closingAfterErr{scriptedConn: &scriptedConn{pages: []scriptedPage{
				{entries: []*ldap.Entry{pageEntry("cn=a")}, err: errors.New("unable to read LDAP response packet: EOF")}}}}}, nil
		}
		return ldapClient{c: &scriptedConn{pages: []scriptedPage{{entries: []*ldap.Entry{pageEntry("cn=a")}}}}}, nil
	}
	p := NewPool(w.r.Cfg, dial, noCheck, w.clk.Now, metrics.New(prometheus.NewRegistry()), w.say.say)
	q := func() (*ldap.SearchResult, error) {
		var res *ldap.SearchResult
		_, err := p.Do(context.Background(), func(s Searcher) (err error) { res, err = s.Search(searchReq()); return })
		return res, err
	}
	if _, err := q(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("the mid-search close: %v, want ErrUnavailable", err)
	}
	if res, err := q(); err != nil || len(res.Entries) != 1 || dials != 2 {
		t.Fatalf("the next search: %v %v after %d dial(s), want one entry on a fresh dial", res, err, dials)
	}
}
