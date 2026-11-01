// Package sottest serves NetBox and Nautobot to the connector's tests: a TLS
// server under a CA of its own, and a replay of a stack L30 recorded
// (replay.go).
package sottest

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/testpki"
)

// TLS serves h over TLS with a certificate for 127.0.0.1 from a CA made for
// it alone, and returns the server and a ca_file that trusts that CA and
// nothing else. httptest's own certificate is the same for every server, so
// it cannot show a CA file refusing a server it did not issue.
func TLS(t testing.TB, h http.Handler) (*httptest.Server, string) {
	t.Helper()
	now := time.Now()
	ca, err := testpki.NewCA("sottest CA", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.Issue(testpki.Leaf{CommonName: "sottest", IPs: testpki.Loopback(), NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, ca.PEM(), 0o644); err != nil {
		t.Fatal(err)
	}
	return srv, caFile
}
