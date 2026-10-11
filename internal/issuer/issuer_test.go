package issuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

// files is a new CA's two files.
func files(t *testing.T, now time.Time) map[string][]byte {
	t.Helper()
	c, k, err := New(now)
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{CertFile: c, KeyFile: k}
}

// alice is a sign-in whose sid needs escaping in a URI.
func alice(now time.Time) SignIn {
	return SignIn{Principal: "user:alice@example.com", Issuer: "https://kc.example/realms/corp", Subject: "sub-alice",
		Sid: "s&1=2", AMR: []string{"pwd", "otp"}, ACR: "1", AuthTime: now.Add(-time.Minute), IssuedAt: now}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// A new CA loads, issues a client certificate that verifies against it, and
// the certificate carries its sign-in (decision 43 ruling 9).
func TestNewLoadAndIssue(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	c, lines := Load(Mem(files(t, now)), now)
	if c.Unavailable != nil || len(c.Trusted) != 1 || len(lines) != 1 || !strings.HasPrefix(lines[0], "issuing as ") {
		t.Fatalf("%v %q", c.Unavailable, lines)
	}
	s := alice(now)
	cert, err := c.Issue(newKey(t).Public(), s, now, 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(c.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if cert.Subject.CommonName != s.Principal || !cert.NotAfter.Equal(now.Add(12*time.Hour)) ||
		!cert.NotBefore.Equal(now.Add(-time.Minute)) || len(cert.EmailAddresses) != 0 || cert.SerialNumber.Sign() <= 0 {
		t.Fatalf("CN %q, %s to %s, emails %v, serial %v", cert.Subject.CommonName, cert.NotBefore, cert.NotAfter,
			cert.EmailAddresses, cert.SerialNumber)
	}
	got, err := ReadSignIn(cert)
	if err != nil || got.Principal != s.Principal || got.Issuer != s.Issuer || got.Subject != s.Subject ||
		got.Sid != s.Sid || got.ACR != s.ACR || !reflect.DeepEqual(got.AMR, s.AMR) ||
		!got.AuthTime.Equal(s.AuthTime) || !got.IssuedAt.Equal(s.IssuedAt) {
		t.Fatalf("%+v %v", got, err)
	}
	if issued, mixed := c.Ends([][]*x509.Certificate{{cert, c.Cert}}); !issued || mixed {
		t.Fatalf("issued %v mixed %v", issued, mixed)
	}
	if p := string(c.PEM(cert)); strings.Count(p, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("the chain: %s", p)
	}
}

// A certificate never outlives the CA that issued it.
func TestACertificateNeverOutlivesItsCA(t *testing.T) {
	now := time.Now()
	c, err := Ephemeral(now)
	if err != nil {
		t.Fatal(err)
	}
	late := c.Cert.NotAfter.Add(-time.Hour)
	cert, err := c.Issue(newKey(t).Public(), alice(late), late, 12*time.Hour)
	if err != nil || !cert.NotAfter.Equal(c.Cert.NotAfter) {
		t.Fatalf("%v %v", cert.NotAfter, err)
	}
}

// What is missing or unusable is said, and a start goes on: a missing key
// stops issuance and keeps trust; a missing CA stops both (ruling 14).
func TestLoadSaysWhatIsMissing(t *testing.T) {
	now := time.Now()
	c, lines := Load(Mem(nil), now)
	if c.Unavailable == nil || len(c.Trusted) != 0 || !strings.Contains(strings.Join(lines, "\n"), "run init-issuer once") {
		t.Fatalf("no files: %v %q", c.Unavailable, lines)
	}
	if _, err := c.Issue(newKey(t).Public(), alice(now), now, time.Hour); err == nil {
		t.Fatal("a CA with no files issued")
	}
	m := files(t, now)
	delete(m, KeyFile)
	c, lines = Load(Mem(m), now)
	if c.Unavailable == nil || len(c.Trusted) != 1 ||
		!strings.Contains(strings.Join(lines, "\n"), "the certificates already issued are trusted") {
		t.Fatalf("no key: %v %q", c.Unavailable, lines)
	}
	m[KeyFile] = files(t, now)[KeyFile]
	if c, _ = Load(Mem(m), now); c.Unavailable == nil || !strings.Contains(c.Unavailable.Error(), "not the key of") {
		t.Fatalf("another CA's key: %v", c.Unavailable)
	}
	if c, _ = Load(Mem(files(t, now)), now.Add(6*365*24*time.Hour)); c.Unavailable == nil ||
		!strings.Contains(c.Unavailable.Error(), "expired") || len(c.Trusted) != 0 {
		t.Fatalf("an expired CA: %v %d", c.Unavailable, len(c.Trusted))
	}
	f := Mem(files(t, now))
	f.Key = func(string) ([]byte, error) { return nil, errors.New("permission denied") }
	if c, _ = Load(f, now); c.Unavailable == nil || !strings.Contains(c.Unavailable.Error(), "permission denied") {
		t.Fatalf("an unreadable key: %v", c.Unavailable)
	}
}

// The staged next CA and the previous one are trusted, and only the current
// signs (ruling 14).
func TestTheNextAndPreviousAreTrustedNotSigning(t *testing.T) {
	now := time.Now()
	m := files(t, now)
	next, prev := files(t, now), files(t, now)
	m[NextCertFile], m[NextKeyFile], m[PreviousCertFile] = next[CertFile], next[KeyFile], prev[CertFile]
	c, lines := Load(Mem(m), now)
	if c.Unavailable != nil || len(c.Trusted) != 3 || !strings.Contains(strings.Join(lines, "\n"), "remove "+PreviousCertFile) {
		t.Fatalf("%v %d %q", c.Unavailable, len(c.Trusted), lines)
	}
	cert, err := c.Issue(newKey(t).Public(), alice(now), now, time.Hour)
	if err != nil || cert.CheckSignatureFrom(c.Cert) != nil || cert.CheckSignatureFrom(c.Trusted[1]) == nil {
		t.Fatalf("signed by the current alone: %v", err)
	}
}

// A connection whose chains end at the CA and at another anchor is mixed,
// which the broker refuses; a nil CA issued nothing.
func TestEndsRefusesAMixedChain(t *testing.T) {
	now := time.Now()
	c, _ := Ephemeral(now)
	o, _ := Ephemeral(now)
	leaf := &x509.Certificate{}
	if issued, mixed := c.Ends([][]*x509.Certificate{{leaf, c.Cert}, {leaf, o.Cert}}); issued || !mixed {
		t.Fatalf("both: issued %v mixed %v", issued, mixed)
	}
	if issued, mixed := c.Ends([][]*x509.Certificate{{leaf, o.Cert}}); issued || mixed {
		t.Fatalf("another's: issued %v mixed %v", issued, mixed)
	}
	var none *CA
	if issued, mixed := none.Ends([][]*x509.Certificate{{leaf, c.Cert}}); issued || mixed {
		t.Fatalf("no CA: issued %v mixed %v", issued, mixed)
	}
}

// ReadSignIn reads only what this CA issues.
func TestReadSignInRefusesWhatItDidNotIssue(t *testing.T) {
	now := time.Now()
	good := alice(now).URI()
	with := func(edit func(url.Values)) *url.URL {
		u := *good
		q := u.Query()
		edit(q)
		u.RawQuery = q.Encode()
		return &u
	}
	mk := func(cn string, uris []*url.URL, emails []string) *x509.Certificate {
		return &x509.Certificate{Subject: pkix.Name{CommonName: cn}, URIs: uris, EmailAddresses: emails}
	}
	const p = "user:alice@example.com"
	for name, c := range map[string]struct {
		cert *x509.Certificate
		want string
	}{
		"an email SAN":           {mk(p, []*url.URL{good}, []string{"alice@example.com"}), "email"},
		"no URI":                 {mk(p, nil, nil), "no port49-sign-in"},
		"two URIs":               {mk(p, []*url.URL{good, good}, nil), "more than one"},
		"another scheme":         {mk(p, []*url.URL{{Scheme: "spiffe", Host: "x", Path: "/y"}}, nil), "no port49-sign-in"},
		"an unknown member":      {mk(p, []*url.URL{with(func(q url.Values) { q.Set("role", "admin") })}, nil), "unknown member"},
		"sub twice":              {mk(p, []*url.URL{with(func(q url.Values) { q.Add("sub", "b") })}, nil), "twice"},
		"no sub":                 {mk(p, []*url.URL{with(func(q url.Values) { q.Del("sub") })}, nil), "sub"},
		"a CN that is no user":   {mk("alice@example.com", []*url.URL{good}, nil), "principal"},
		"an http issuer":         {mk(p, []*url.URL{with(func(q url.Values) { q.Set("iss", "http://kc") })}, nil), "iss"},
		"auth_time not a number": {mk(p, []*url.URL{with(func(q url.Values) { q.Set("auth_time", "x") })}, nil), "auth_time"},
	} {
		if _, err := ReadSignIn(c.cert); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}
