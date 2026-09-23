package broker

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/policy"
	"github.com/rhwendt/port49/internal/testpki"
)

func TestIdentity(t *testing.T) {
	now := time.Now()
	ca, err := testpki.NewCA("test ca", now.Add(-time.Hour), now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	leaf := func(emails ...string) *x509.Certificate {
		c, err := ca.Issue(testpki.Leaf{CommonName: "x", Emails: emails, Client: true,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		return c.Leaf
	}
	state := func(l *x509.Certificate) *tls.ConnectionState {
		return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{l, ca.Cert}}}
	}

	p, cred, err := Identity(state(leaf("Alice@Example.com")), now)
	if err != nil || p != "user:alice@example.com" {
		t.Fatalf("principal: %q %v", p, err)
	}
	if cred.Method != "cert" || cred.Issuer == "" || cred.Serial == "" || !strings.HasPrefix(cred.Fingerprint, "sha256:") {
		t.Fatalf("credential: %+v", cred)
	}

	// A leaf issued to outlive its CA: the chain is only as valid as the
	// anchor, however long the leaf says it lasts.
	shortCA, err := testpki.NewCA("short ca", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	long, err := shortCA.Issue(testpki.Leaf{CommonName: "x", Emails: []string{"a@example.com"}, Client: true,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	outlives := &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{long.Leaf, shortCA.Cert}}}
	if _, _, err := Identity(outlives, now); err != nil {
		t.Fatalf("while the anchor is valid: %v", err)
	}

	for name, tt := range map[string]struct {
		cs  *tls.ConnectionState
		now time.Time
	}{
		"no connection state": {nil, now},
		"no verified chain":   {&tls.ConnectionState{}, now},
		"expired since":       {state(leaf("a@example.com")), now.Add(2 * time.Hour)},
		"no email SAN":        {state(leaf()), now},
		"two email SANs":      {state(leaf("a@example.com", "b@example.com")), now},
		// Unverified: a peer certificate the handshake did not chain to the anchor.
		"peer certificate only": {&tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf("a@example.com")}}, now},
		// An rfc822Name is IA5String, which admits spaces and control
		// characters; no policy identity can hold one, and the log must not.
		"a space in the email SAN":  {state(leaf("a b@example.com")), now},
		"a control character in it": {state(leaf("a\x01b@example.com")), now},
		"an email SAN with no @":    {state(leaf("alice")), now},
		"the anchor expired first":  {outlives, now.Add(2 * time.Hour)},
	} {
		if _, _, err := Identity(tt.cs, tt.now); !errors.Is(err, ErrUntrusted) {
			t.Errorf("%s: Identity = %v, want ErrUntrusted", name, err)
		}
	}
}

// The policy matches an identity exactly and accepts only the canonical form,
// so the principal Identity derives must be that form or no subject ever
// matches: a mixed-case SAN resolves to the subject written lower-case.
func TestAPrincipalMatchesItsPolicyIdentity(t *testing.T) {
	now := time.Now()
	ca, err := testpki.NewCA("test ca", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	c, err := ca.Issue(testpki.Leaf{CommonName: "x", Emails: []string{"Alice.Ops@Example.COM"}, Client: true,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	principal, _, err := Identity(&tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{c.Leaf, ca.Cert}}}, now)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(`
roles:
  - {name: r, privilege: admin, permit: ["**"]}
subjects:
  - {name: s, identity: ["user:alice.ops@example.com"], username: alice, token_ttl: 60s}
grants:
  - {subject: s, scope: all_devices, roles: [r]}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := policy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if name, ok := p.SubjectOf(principal); !ok || name != "s" {
		t.Fatalf("principal %q resolves to %q %v, want subject s", principal, name, ok)
	}
}
