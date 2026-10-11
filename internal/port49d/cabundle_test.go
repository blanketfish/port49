package port49d

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/testpki"
)

// The bundle GET /v1/config sends: sent when it holds the server
// certificate's CA, said by fingerprint; not sent, said, and marked refused
// when it does not, or cannot be read. The start goes on either way
// (decision 43 ruling 25).
func TestLoadCABundle(t *testing.T) {
	dir := t.TempDir()
	if err := testpki.WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, testpki.LabServerCert), filepath.Join(dir, testpki.LabServerKey))
	if err != nil {
		t.Fatal(err)
	}
	cur, err := os.ReadFile(filepath.Join(dir, testpki.LabCA))
	if err != nil {
		t.Fatal(err)
	}
	next, err := testpki.NewCA("port49 next CA", time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, body []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, body, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	var said []string
	say := func(format string, args ...any) { said = append(said, fmt.Sprintf(format, args...)) }

	both := write("both.pem", append(append([]byte{}, cur...), next.PEM()...))
	got, refused := loadCABundle(both, cert, say)
	certs, err := api.ParseCABundle(got)
	if err != nil || refused || len(certs) != 2 || !certs[1].Equal(next.Cert) || len(said) != 1 ||
		!strings.Contains(said[0], "sent to every client: "+api.CAFingerprints(certs)) {
		t.Fatalf("%v %v", err, said)
	}
	for name, c := range map[string]struct{ path, want string }{
		"the next CA alone": {write("next.pem", next.PEM()), "does not hold the CA of the server certificate"},
		"missing":           {filepath.Join(dir, "none.pem"), "no such file"},
		"a leaf":            {write("leaf.pem", mustRead(t, filepath.Join(dir, testpki.LabServerCert))), "is not a CA"},
	} {
		said = nil
		if got, refused := loadCABundle(c.path, cert, say); got != nil || !refused || len(said) != 1 ||
			!strings.Contains(said[0], c.want) ||
			!strings.Contains(said[0], "no CA bundle is sent, so clients keep the CAs they hold") {
			t.Errorf("%s: %q %v", name, got, said)
		}
	}
	if got, refused := loadCABundle("", cert, say); got != nil || refused {
		t.Fatal("no file named sends nothing, and refuses nothing")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
