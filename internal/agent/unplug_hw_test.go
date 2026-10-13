//go:build hwkey

package agent

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/hwkey"
	"github.com/rhwendt/port49/internal/hwkey/hwtest"
	"github.com/rhwendt/port49/internal/hwkey/tpm"
	"github.com/rhwendt/port49/internal/testpki"
)

// The unplug on a TPM: swtpm stopped is the key pulled and restarted (the same
// state directory) is the key put back. Held connection mints, a refresh and a
// reconnect say to insert the key and end nothing, and once the key is back a
// refresh succeeds with no mint and no reconnect in between.
func TestAUnpluggedTPMKeyNeverEndsTheSession(t *testing.T) {
	sim := hwtest.SWTPM(t)
	key, err := tpm.Generate(filepath.Join(t.TempDir(), "k.tpmkey"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = key.Close() })

	now := time.Now()
	ca, err := testpki.NewCA("agent hw test ca", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	srvCert, err := ca.Issue(testpki.Leaf{CommonName: "broker", IPs: testpki.Loopback(),
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(7),
		Subject: pkix.Name{CommonName: "alice"}, EmailAddresses: []string{"alice@example.com"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		ca.Cert, key.Public(), ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(&fakeBroker{})
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{srvCert}, ClientCAs: ca.Pool(),
		ClientAuth: tls.VerifyClientCertIfGiven, MinVersion: tls.VersionTLS13}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the failed reconnect's handshake error
	srv.StartTLS()
	t.Cleanup(srv.Close)

	a := New(Config{BrokerURL: srv.URL, BrokerCA: ca.Pool(), Cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}})
	ctx := context.Background()
	if _, err := a.Connect(ctx); err != nil {
		t.Fatal(err)
	}

	sim.Stop() // the unplug
	if _, err := a.Mint(ctx, "leaf1", false, 0); err != nil {
		t.Fatalf("mint on the held connection with the TPM gone: %v", err)
	}
	_, err = a.Refresh(ctx)
	var absent *KeyAbsentError
	if !errors.As(err, &absent) || absent.State != hwkey.Absent || !strings.Contains(err.Error(), "insert your key") {
		t.Fatalf("refresh with the TPM gone = %v", err)
	}
	srv.CloseClientConnections()
	a.client.CloseIdleConnections()
	absent = nil
	if _, err = a.Mint(ctx, "leaf1", false, 0); !errors.As(err, &absent) {
		t.Fatalf("mint needing a reconnect with the TPM gone = %v, want *KeyAbsentError", err)
	}
	select {
	case <-a.Done():
		t.Fatal("the session ended on an unplugged TPM")
	default:
	}

	sim.Restart() // the re-insertion: no mint, no reconnect, no signature since
	if _, err := a.Refresh(ctx); err != nil {
		t.Fatalf("refresh after the TPM came back: %v", err)
	}
}
