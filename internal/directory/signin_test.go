package directory

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"

	"github.com/rhwendt/port49/internal/testpki"
)

const aliceDN = "CN=Alice,OU=Staff,DC=corp"

// writeCA is a fresh CA's PEM in a temp file, as ca_file.
func writeCA(t *testing.T) string {
	t.Helper()
	pki, err := testpki.NewCA("lab directory CA", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pki.PEM(), 0o644); err != nil {
		t.Fatal(err)
	}
	return ca
}

// signInWorld is newWorld with alice findable by sAMAccountName under the
// verifier's filter, created at 2026-10-01T12:00:00Z.
func signInWorld(t *testing.T) *world {
	t.Helper()
	w := newWorld(t)
	a := entry(aliceDN, map[string][]string{"userPrincipalName": {"alice@corp.example.com"},
		"sAMAccountName": {"alice"}, "mail": {"alice@corp.example.com"}, "whenCreated": {"20261001120000.0Z"}})
	w.dir.on("(&(objectClass=person)(memberOf=cn=people)(sAMAccountName=alice))", a)
	return w
}

// The name is matched on username_attribute under both filters, escaped;
// the entry gives its principal and username; its creation time is read.
func TestSignInEntryFindsTheOneEntry(t *testing.T) {
	w := signInWorld(t)
	e, err := w.r.SignInEntry(context.Background(), "alice", "(memberOf=cn=people)")
	if err != nil {
		t.Fatal(err)
	}
	if e.Principal != "user:alice@corp.example.com" || e.Username != "alice" || e.DN != aliceDN ||
		!e.CreatedAt.Equal(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)) || e.Server.URI != dc01 {
		t.Fatalf("%+v", e)
	}
	var first *ldap.SearchRequest
	for _, c := range w.dir.calls {
		if strings.Contains(c.Filter, "memberOf") {
			first = c
		}
	}
	if first == nil || first.Filter != "(&(objectClass=person)(memberOf=cn=people)(sAMAccountName=alice))" ||
		!slicesContain(first.Attributes, "whenCreated") || !slicesContain(first.Attributes, "createTimestamp") ||
		slicesContain(first.Attributes, "") {
		t.Fatalf("the search: %+v", first)
	}
}

func slicesContain(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// A name holding filter metacharacters is escaped, never parsed.
func TestSignInEntryEscapesTheName(t *testing.T) {
	w := signInWorld(t)
	_, err := w.r.SignInEntry(context.Background(), "a*)(uid=*", "")
	if !errors.Is(err, ErrUnmapped) {
		t.Fatalf("%v", err)
	}
	last := w.dir.calls[len(w.dir.calls)-1]
	if last.Filter != `(&(objectClass=person)(sAMAccountName=a\2a\29\28uid=\2a))` {
		t.Fatalf("filter %q", last.Filter)
	}
}

// Two entries for one name are ErrAmbiguous; none is ErrUnmapped; a
// workload's entry is ErrUnmapped; a stopped server is ErrUnavailable,
// never ErrUnmapped.
func TestSignInEntryRefusals(t *testing.T) {
	ctx := context.Background()
	t.Run("two", func(t *testing.T) {
		w := signInWorld(t)
		w.dir.on("(&(objectClass=person)(sAMAccountName=bob))", entry("CN=Bob,OU=A,DC=corp", nil),
			entry("CN=Bob,OU=B,DC=corp", nil))
		if _, err := w.r.SignInEntry(ctx, "bob", ""); !errors.Is(err, ErrAmbiguous) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("none", func(t *testing.T) {
		w := signInWorld(t)
		if _, err := w.r.SignInEntry(ctx, "nobody", ""); !errors.Is(err, ErrUnmapped) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("a workload's", func(t *testing.T) {
		w := signInWorld(t)
		w.r.Cfg.Workload = &WorkloadMapping{Attribute: "uid"}
		w.dir.on("(&(objectClass=person)(sAMAccountName=svc))", entry("CN=svc,OU=Svc,DC=corp", map[string][]string{
			"userPrincipalName": {"svc@corp.example.com"}, "sAMAccountName": {"svc"},
			"uid": {"spiffe://corp.example.com/svc"}}))
		if _, err := w.r.SignInEntry(ctx, "svc", ""); !errors.Is(err, ErrUnmapped) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("stopped", func(t *testing.T) {
		w := signInWorld(t)
		w.down()
		_, err := w.r.SignInEntry(ctx, "alice", "(memberOf=cn=people)")
		if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrUnmapped) {
			t.Fatalf("%v", err)
		}
	})
}

// personServer is PersonDial over a pipe: each dial is answered with one
// bind response carrying code and diag, and, when ppolicy >= 0, a Behera
// password-policy control with that error. It counts dials and closes,
// and down refuses the dial; hang never answers.
type personServer struct {
	mu            sync.Mutex
	code          int64
	diag          string
	ppolicy       int
	down, hang    bool
	dials, closed int
}

func newPersonServer(code int64, diag string) *personServer {
	return &personServer{code: code, diag: diag, ppolicy: -1}
}

type countedConn struct {
	*ldap.Conn
	p    *personServer
	once sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(func() { c.p.mu.Lock(); c.p.closed++; c.p.mu.Unlock() })
	return c.Conn.Close()
}

func (p *personServer) dial(ctx context.Context, s Server) (PersonConn, error) {
	p.mu.Lock()
	p.dials++
	code, diag, pp, down, hang := p.code, p.diag, p.ppolicy, p.down, p.hang
	p.mu.Unlock()
	if down {
		return nil, ldap.NewError(ldap.ErrorNetwork, errors.New("dial tcp: connection refused"))
	}
	cc, sc := net.Pipe()
	go func() {
		defer sc.Close()
		pk, err := ber.ReadPacket(sc)
		if err != nil || hang {
			_, _ = io.Copy(io.Discard, sc)
			return
		}
		env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, pk.Children[0].Value, "MessageID"))
		resp := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindResponse, nil, "Bind Response")
		resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "resultCode"))
		resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
		resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diag, "diagnosticMessage"))
		env.AppendChild(resp)
		if pp >= 0 {
			env.AppendChild(beheraResponse(pp))
		}
		_, _ = sc.Write(env.Bytes())
		_, _ = io.Copy(io.Discard, sc)
	}()
	conn := ldap.NewConn(cc, false)
	conn.Start()
	return &countedConn{Conn: conn, p: p}, nil
}

// beheraResponse is a response's controls, [0], holding one Behera
// password-policy control whose value carries error e
// (draft-behera-ldap-password-policy-10 §6.2).
func beheraResponse(e int) *ber.Packet {
	controls := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
	c := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	c.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		ldap.ControlTypeBeheraPasswordPolicy, "Control Type"))
	v := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PasswordPolicyResponseValue")
	v.AppendChild(ber.NewInteger(ber.ClassContext, ber.TypePrimitive, 1, int64(e), "error"))
	c.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(v.Bytes()), "Control Value"))
	controls.AppendChild(c)
	return controls
}

// personResolver is a Resolver with no pool at all: CheckPassword must
// never need one (Review Focus 6).
func personResolver(p *personServer) *Resolver {
	return &Resolver{Cfg: adCfg(), PersonDial: p.dial}
}

var dc = Server{URI: "ldaps://dc-01"}

// An empty password is never sent: no dial is made (Review Focus 1).
func TestAnEmptyPasswordIsNeverSent(t *testing.T) {
	p := newPersonServer(0, "")
	for _, pw := range []string{"", " ", "\t"} {
		if err := personResolver(p).CheckPassword(context.Background(), dc, aliceDN, pw); !errors.Is(err, ErrEmptyPassword) {
			t.Fatalf("%q: %v", pw, err)
		}
	}
	if p.dials != 0 {
		t.Fatal("an empty password dialled the directory")
	}
}

// AD's data code is kept from the message, the rest dropped; a wrong
// password and a locked account read apart (ruling 6).
func TestARefusedPasswordKeepsADsDataCode(t *testing.T) {
	for _, tc := range []struct {
		msg, data string
		state     bool
	}{
		{"80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e, v4f7c", "52e", false},
		{"80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 775, v4f7c", "775", true},
		{"80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 773, v4f7c", "773", true},
		{"80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 999, v4f7c", "", false},
		{"Invalid credentials", "", false},
	} {
		p := newPersonServer(ldap.LDAPResultInvalidCredentials, tc.msg)
		err := personResolver(p).CheckPassword(context.Background(), dc, aliceDN, "x")
		var r *PasswordRefusal
		if !errors.As(err, &r) || r.Result != 49 || r.Data != tc.data || r.State() != tc.state ||
			!errors.Is(err, ErrPasswordRefused) || strings.Contains(err.Error(), "DSID") ||
			strings.Contains(err.Error(), "AcceptSecurityContext") {
			t.Errorf("%q: %v", tc.msg, err)
		}
		if p.closed != p.dials {
			t.Errorf("%q: %d dials, %d closed", tc.msg, p.dials, p.closed)
		}
	}
}

// OpenLDAP's ppolicy control is read on a refusal and on a success
// (I4): expired and locked on a 49, change-after-reset on a 0.
func TestThePasswordPolicyControlIsRead(t *testing.T) {
	for _, tc := range []struct {
		code   int64
		pp     int
		data   string
		result int
	}{
		{49, 0, "password_expired", 49},
		{49, 1, "account_locked", 49},
		{0, 2, "change_after_reset", 0},
	} {
		p := newPersonServer(tc.code, "")
		p.ppolicy = tc.pp
		err := personResolver(p).CheckPassword(context.Background(), dc, aliceDN, "x")
		var r *PasswordRefusal
		if !errors.As(err, &r) || r.Data != tc.data || r.Result != tc.result || !r.State() {
			t.Errorf("code %d ppolicy %d: %v", tc.code, tc.pp, err)
		}
	}
	if err := personResolver(newPersonServer(0, "")).CheckPassword(context.Background(), dc, aliceDN, "x"); err != nil {
		t.Fatalf("a plain success: %v", err)
	}
}

// A refused password moves no breaker and starts no hold-off (Review
// Focus 6): CheckPassword runs with no pool at all, and on a world's
// resolver ten refusals leave its selection and its dials as they were.
func TestARefusedPasswordLeavesThePoolAlone(t *testing.T) {
	ctx := context.Background()
	p := newPersonServer(ldap.LDAPResultInvalidCredentials, "data 52e")
	for range 10 {
		if err := personResolver(p).CheckPassword(ctx, dc, aliceDN, "wrong"); !errors.Is(err, ErrPasswordRefused) {
			t.Fatal(err)
		}
	}
	w := signInWorld(t)
	w.r.PersonDial = p.dial
	if _, err := w.r.SignInEntry(ctx, "alice", "(memberOf=cn=people)"); err != nil {
		t.Fatal(err)
	}
	before, _ := w.r.Pool.Selected()
	dials := w.srv.dials[dc01]
	for range 10 {
		_ = w.r.CheckPassword(ctx, before, aliceDN, "wrong")
	}
	after, ok := w.r.Pool.Selected()
	if !ok || after.URI != before.URI || w.srv.dials[dc01] != dials || w.say.has("hold-off") {
		t.Fatalf("the pool moved: %v -> %v, dials %d -> %d", before, after, dials, w.srv.dials[dc01])
	}
}

// The person's bind is on a connection of its own, closed after the one
// bind, and the real dial presents no client certificate even when the
// broker binds by EXTERNAL.
func TestThePersonsBindIsItsOwnConnection(t *testing.T) {
	p := newPersonServer(0, "")
	if err := personResolver(p).CheckPassword(context.Background(), dc, aliceDN, "right"); err != nil {
		t.Fatal(err)
	}
	if p.dials != 1 || p.closed != 1 {
		t.Fatalf("%d dials, %d closed", p.dials, p.closed)
	}
	cfg := adCfg()
	cfg.CAFile = writeCA(t)
	cfg.Bind.Mechanism = "external"
	tc, err := personTLS(cfg, dc)
	if err != nil || len(tc.Certificates) != 0 || tc.GetClientCertificate != nil || tc.RootCAs == nil ||
		tc.ServerName != "dc-01" || tc.InsecureSkipVerify {
		t.Fatalf("the person's TLS presents a certificate: %v", err)
	}
}

// A server that does not answer is ErrUnavailable, never a refusal; a
// bind that hangs ends at the caller's deadline.
func TestAStoppedServerIsUnavailable(t *testing.T) {
	p := newPersonServer(0, "")
	p.down = true
	err := personResolver(p).CheckPassword(context.Background(), dc, aliceDN, "x")
	var r *PasswordRefusal
	if !errors.Is(err, ErrUnavailable) || errors.As(err, &r) {
		t.Fatalf("%v", err)
	}
	// busy and unavailable are the server's state, not a refusal.
	for _, code := range []int64{ldap.LDAPResultBusy, ldap.LDAPResultUnavailable} {
		p := newPersonServer(code, "")
		err := personResolver(p).CheckPassword(context.Background(), dc, aliceDN, "x")
		if !errors.Is(err, ErrUnavailable) || errors.As(err, &r) || p.dials != 1 || p.closed != 1 {
			t.Errorf("code %d: %v (%d dials, %d closed)", code, err, p.dials, p.closed)
		}
	}
	p = newPersonServer(0, "")
	p.hang = true
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := personResolver(p).CheckPassword(ctx, dc, aliceDN, "x"); !errors.Is(err, ErrUnavailable) ||
		time.Since(start) > time.Second {
		t.Fatalf("%v after %s", err, time.Since(start))
	}
	if p.closed != p.dials {
		t.Fatalf("%d dials, %d closed", p.dials, p.closed)
	}
}

// An unwilling-to-perform bind (389-DS, eDirectory: an inactivated or
// locked account) is a refusal of the account's state, not of the password.
func TestAnUnwillingBindNamesTheAccountsState(t *testing.T) {
	p := newPersonServer(ldap.LDAPResultUnwillingToPerform, "")
	err := personResolver(p).CheckPassword(context.Background(), dc, aliceDN, "x")
	var r *PasswordRefusal
	if !errors.As(err, &r) || r.Result != 53 || r.Data != "" || !r.State() || p.closed != p.dials {
		t.Fatalf("%v", err)
	}
}
