package directory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
	krbclient "github.com/jcmturner/gokrb5/v8/client"
	krbconfig "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/types"

	"github.com/rhwendt/port49/internal/keyfile"
)

// Credentials are how the broker binds (Ruling 8). The secret each holds is
// unexported and never formatted: String and GoString name the mechanism and
// who, nothing else.
type Credentials struct {
	mech     BindMechanism
	who      string
	cert     *tls.Certificate  // external
	krb      *krbclient.Client // gssapi; shared by every bind, each of which has a gssapi.Client (a security context) of its own
	password string            // simple
}

func (c *Credentials) String() string             { return fmt.Sprintf("directory bind %s as %s", c.mech, c.who) }
func (c *Credentials) GoString() string           { return c.String() }
func (c *Credentials) Format(f fmt.State, _ rune) { fmt.Fprint(f, c.String()) }
func (c *Credentials) Who() string                { return c.who }

// LoadCredentials reads the bind's secret once, at start. A keytab is read
// through keyfile.ReadSecret: owned by port49's user or root, no group or
// other bit, no link.
func LoadCredentials(b Bind, getenv func(string) string) (*Credentials, error) {
	c := &Credentials{mech: b.Mechanism}
	switch b.Mechanism {
	case "external":
		cert, err := keyfile.LoadX509KeyPair(b.TLSCertFile, b.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("broker.directory.bind tls_cert_file %s, tls_key_file %s: %w", b.TLSCertFile,
				b.TLSKeyFile, err)
		}
		c.cert = &cert
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			c.who = leaf.Subject.String()
		}
	case "gssapi":
		raw, err := keyfile.ReadSecret(b.KeytabFile)
		if err != nil {
			return nil, fmt.Errorf("broker.directory.bind.keytab_file %s: %w", b.KeytabFile, err)
		}
		kt := keytab.New()
		if err := kt.Unmarshal(raw); err != nil {
			return nil, fmt.Errorf("broker.directory.bind.keytab_file %s: not a keytab", b.KeytabFile)
		}
		conf, err := os.ReadFile(b.KRB5Conf)
		if err != nil {
			return nil, fmt.Errorf("broker.directory.bind.krb5_conf: %w", err)
		}
		kc, err := krbconfig.NewFromString(string(conf))
		if err != nil {
			return nil, fmt.Errorf("broker.directory.bind.krb5_conf %s: %v", b.KRB5Conf, err)
		}
		// Everything a bind would otherwise discover from a KDC's or a
		// directory's answer, and read as a refusal, is a start error here.
		user, realm := splitPrincipal(b.Principal)
		if user == "" || realm == "" {
			return nil, fmt.Errorf("broker.directory.bind.principal %q: want user@REALM", b.Principal)
		}
		name := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, user)
		held := false
		for _, et := range kc.LibDefaults.DefaultTktEnctypeIDs {
			if _, _, err := kt.GetEncryptionKey(name, realm, 0, et); err == nil {
				held = true
				break
			}
		}
		if !held {
			return nil, fmt.Errorf("broker.directory.bind.keytab_file %s holds no key for %s in an enctype krb5_conf allows",
				b.KeytabFile, b.Principal)
		}
		cl := krbclient.NewWithKeytab(user, realm, kt, kc, krbclient.DisablePAFXFAST(true))
		if ok, err := cl.IsConfigured(); !ok {
			return nil, fmt.Errorf("broker.directory.bind.krb5_conf %s: %v", b.KRB5Conf, err)
		}
		c.krb = cl
		c.who = b.Principal
	case "simple":
		c.password, c.who = getenv(b.PasswordEnv), b.BindDN
		if c.password == "" {
			return nil, fmt.Errorf("broker.directory.bind.password_env %s is not set", b.PasswordEnv)
		}
	default:
		return nil, fmt.Errorf("broker.directory.bind.mechanism %q", b.Mechanism)
	}
	return c, nil
}

// splitPrincipal is user and realm of "user@REALM".
func splitPrincipal(p string) (string, string) {
	if i := strings.LastIndexByte(p, '@'); i >= 0 {
		return p[:i], p[i+1:]
	}
	return p, ""
}

// tlsConfig verifies s against ca_file under its URI's host, TLS 1.2 or
// later, and presents the broker's certificate only for EXTERNAL.
func tlsConfig(cfg Config, s Server, cr *Credentials) (*tls.Config, error) {
	u, err := url.Parse(s.URI)
	if err != nil {
		return nil, err
	}
	pem, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("broker.directory.ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("broker.directory.ca_file %s holds no certificate", cfg.CAFile)
	}
	tc := &tls.Config{RootCAs: pool, ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}
	if cr.cert != nil {
		tc.Certificates = []tls.Certificate{*cr.cert}
	}
	return tc, nil
}

// NewDialer dials, secures and binds one connection per call. Nothing is
// ever sent in clear: an ldap:// server without start_tls is refused before
// it is dialled. Every search on the connection runs through SearchAsync
// under its query's deadline (ldapClient), and is bounded by query_timeout
// on the wire as well (SetTimeout). Nothing closes the connection on one
// query's timeout.
func NewDialer(cfg Config, cr *Credentials) (Dialer, error) {
	return func(ctx context.Context, s Server) (Client, error) {
		if u, err := url.Parse(s.URI); err != nil || (!s.StartTLS && u.Scheme != "ldaps") {
			return nil, fmt.Errorf("directory %s: ldap:// needs start_tls; no connection is made in clear", s.Label())
		}
		tc, err := tlsConfig(cfg, s, cr)
		if err != nil {
			return nil, err
		}
		d := &net.Dialer{}
		if dl, ok := ctx.Deadline(); ok {
			d.Deadline = dl
		}
		opts := []ldap.DialOpt{ldap.DialWithDialer(d)}
		if !s.StartTLS {
			opts = append(opts, ldap.DialWithTLSConfig(tc))
		}
		conn, err := ldap.DialURL(s.URI, opts...)
		if err != nil {
			return nil, err
		}
		conn.SetTimeout(cfg.QueryTimeout)
		// The query's deadline ends the handshake and the bind, which have
		// no context of their own, by closing the connection under them.
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		if s.StartTLS {
			if err := conn.StartTLS(tc); err != nil {
				conn.Close()
				return nil, err
			}
		}
		if err := bind(ctx, conn, s, cr); err != nil {
			conn.Close()
			return nil, err
		}
		return ldapClient{c: conn}, nil
	}, nil
}

// ldapClient is a bound *ldap.Conn as a Client (pre-flight I-3): every
// search runs through SearchAsync under the query's ctx, so a deadline
// abandons that search's message alone and the connection serves every
// other query on it. SearchAsync reports a cancelled search as no error
// (go-ldap search.go:625-630), so ctx's error is returned in its place.
// Paging follows SearchWithPaging (search.go:503): a paging control, the
// cookie from each page's done result, until it comes back empty.
type ldapClient struct{ c *ldap.Conn }

func (l ldapClient) Close() error { return l.c.Close() }

func (l ldapClient) SearchContext(ctx context.Context, req *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error) {
	out := &ldap.SearchResult{}
	// A copy: a failover reuses the caller's request, and an appended paging
	// control would carry the last server's cookie.
	r0 := *req
	req = &r0
	var paging *ldap.ControlPaging
	if pagingSize > 0 {
		paging = ldap.NewControlPaging(pagingSize)
		req.Controls = append(slices.Clip(req.Controls), paging)
	}
	for {
		r := l.c.SearchAsync(ctx, req, 0)
		var controls []ldap.Control
		for r.Next() {
			if e := r.Entry(); e != nil {
				out.Entries = append(out.Entries, e)
			}
			if c := r.Controls(); len(c) > 0 {
				controls = c
			}
		}
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if err := r.Err(); err != nil {
			return out, err
		}
		if paging == nil {
			return out, nil
		}
		pc, ok := ldap.FindControl(controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
		if !ok || len(pc.Cookie) == 0 {
			return out, nil
		}
		paging.SetCookie(pc.Cookie)
	}
}

// bind authenticates conn as the broker within ctx. Its error names the
// mechanism, who and the result code, never a secret or the server's
// diagnostic. A refusal (an LDAP result Refusal knows, or a KDC refusing the
// principal as ErrBindRefused) starts the pool's bind hold-off; anything
// else is a fault.
//
// gokrb5 takes no context and a blackholed KDC holds it for its own timeouts
// (5s a KDC and transport), so the bind runs in a goroutine and ctx ends the
// wait: the connection is closed, which ends an LDAP exchange at once, and
// the goroutine ends when gokrb5's timeouts do.
func bind(ctx context.Context, conn *ldap.Conn, s Server, cr *Credentials) error {
	done := make(chan error, 1)
	go func() {
		switch cr.mech {
		case "external":
			done <- conn.ExternalBind()
		case "gssapi":
			u, _ := url.Parse(s.URI)
			done <- conn.GSSAPIBind(&gssapi.Client{Client: cr.krb}, "ldap/"+u.Hostname(), "")
		default:
			done <- conn.Bind(cr.who, cr.password)
		}
	}()
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = conn.Close()
		return fmt.Errorf("bind %s as %s: %w", cr.mech, cr.who, ctx.Err())
	}
	if err == nil {
		return nil
	}
	// The directory's own answer keeps its code, which Refusal and Fault
	// classify on, and drops its message, which a directory may fill with
	// anything. A client-side code (200 and up: the network, the TLS
	// handshake) is local text and stays.
	var le *ldap.Error
	if errors.As(err, &le) {
		cause := fmt.Errorf("bind %s as %s: LDAP result %d", cr.mech, cr.who, le.ResultCode)
		if le.ResultCode >= 200 && le.Err != nil {
			cause = fmt.Errorf("bind %s as %s: LDAP result %d: %v", cr.mech, cr.who, le.ResultCode, le.Err)
		}
		return &ldap.Error{ResultCode: le.ResultCode, MatchedDN: le.MatchedDN, Err: cause}
	}
	if cr.mech == "gssapi" && kerberosRefused(err) {
		return fmt.Errorf("bind gssapi as %s refused: %w (%v)", cr.who, ErrBindRefused, err)
	}
	return fmt.Errorf("bind %s as %s: %w", cr.mech, cr.who, err)
}

// kerberosRefused reports whether a non-LDAP error from the GSSAPI bind is the
// KDC refusing the principal (unknown principal, preauth failed, a wrong key,
// clock skew) rather than the KDC not answering. gokrb5 flattens its errors
// to text, so the class is read from its root-cause tags: a networking or
// configuration error, a transport error or a deadline is the infrastructure,
// and anything else is the credential refused. TestAGSSAPIBindClassifiesTheKDC
// is the gate for a gokrb5 upgrade: it runs these tags against a real KDC exchange.
func kerberosRefused(err error) bool {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || errors.As(err, &ne) {
		return false
	}
	msg := err.Error()
	for _, infra := range []string{"Networking_Error", "Configuration_Error", "communication error with KDC",
		"failed to communicate with KDC", "error sending to a KDC"} {
		if strings.Contains(msg, infra) {
			return false
		}
	}
	return true
}

// RootDSE is the health check's query: the root DSE's supported LDAP
// versions, base scope, which every directory answers to a bound client.
func RootDSE(ctx context.Context, s Searcher) error {
	_, err := s.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1,
		int(timeLeft(ctx).Seconds())+1, false, "(objectClass=*)", []string{"supportedLDAPVersion"}, nil))
	return err
}

func timeLeft(ctx context.Context) time.Duration {
	if dl, ok := ctx.Deadline(); ok {
		return time.Until(dl)
	}
	return 0
}
