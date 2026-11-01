package inventory

import (
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/testpki"
)

// CallerOf names a workload only by a hierarchical URI SAN, and a person
// (`user:`) only by an email SAN: the two never share a name, so a URI SAN
// cannot take a person's rights. One URI SAN and one email SAN name the
// workload, never the person. The error never carries the certificate's text.
func TestCallerOf(t *testing.T) {
	ca, err := testpki.NewCA("caller CA", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	state := func(l testpki.Leaf) *tls.ConnectionState {
		t.Helper()
		if !l.Client && !l.NoExtKeyUsage && l.CommonName != "server" {
			l.Client = true
		}
		l.NotBefore, l.NotAfter = now.Add(-time.Minute), now.Add(time.Minute)
		c, err := ca.Issue(l)
		if err != nil {
			t.Fatal(err)
		}
		return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{c.Leaf, ca.Cert}}}
	}
	uris := func(ss ...string) []*url.URL {
		var out []*url.URL
		for _, s := range ss {
			out = append(out, uri(s))
		}
		return out
	}
	for _, c := range []struct {
		name string
		cs   *tls.ConnectionState
		at   time.Time
		want string // "" is refused
	}{
		{"no connection state", nil, now, ""},
		{"no verified chain", &tls.ConnectionState{}, now, ""},
		{"an empty verified chain", &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{}}}, now, ""},
		{"a URI SAN", state(testpki.Leaf{URIs: uris("spiffe://port49.test/port49d")}), now,
			"spiffe://port49.test/port49d"},
		{"an email SAN, lower-cased", state(testpki.Leaf{Emails: []string{"Alice@Example.com"}}), now,
			"user:alice@example.com"},
		{"no extended key usage is any purpose", state(testpki.Leaf{NoExtKeyUsage: true,
			URIs: uris("spiffe://port49.test/port49d")}), now, "spiffe://port49.test/port49d"},
		{"one URI SAN and one email SAN name the workload", state(testpki.Leaf{
			URIs: uris("spiffe://port49.test/port49d"), Emails: []string{"alice@example.com"}}), now,
			"spiffe://port49.test/port49d"},
		{"a URI SAN user:alice@example.com", state(testpki.Leaf{URIs: uris("user:alice@example.com")}), now, ""},
		{"a URI SAN user://alice@example.com", state(testpki.Leaf{URIs: uris("user://alice@example.com")}), now, ""},
		{"an opaque URI SAN", state(testpki.Leaf{URIs: uris("urn:alice:example")}), now, ""},
		{"a user: URI SAN beside an email SAN", state(testpki.Leaf{URIs: uris("user:alice@example.com"),
			Emails: []string{"alice@example.com"}}), now, ""},
		{"two URI SANs", state(testpki.Leaf{URIs: uris("spiffe://a.test/x", "spiffe://a.test/y")}), now, ""},
		{"two email SANs", state(testpki.Leaf{Emails: []string{"alice@example.com", "bob@example.com"}}), now, ""},
		{"no SAN", state(testpki.Leaf{CommonName: "alice@example.com"}), now, ""},
		{"a server-only certificate", state(testpki.Leaf{CommonName: "server",
			URIs: uris("spiffe://port49.test/port49d")}), now, ""},
		{"outside its validity now", state(testpki.Leaf{URIs: uris("spiffe://port49.test/port49d")}),
			now.Add(time.Hour), ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := CallerOf(c.cs, c.at)
			if c.want == "" {
				if err == nil {
					t.Fatalf("named %q", got)
				}
				if strings.Contains(err.Error(), "alice") || strings.Contains(err.Error(), "example") {
					t.Fatalf("the error quotes the certificate: %v", err)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("got %q, %v; want %q", got, err, c.want)
			}
		})
	}
}
