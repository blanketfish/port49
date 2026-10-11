package port49d

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/store/memory"
)

// stateDir is a broker state directory as port49 keeps one: 0700, whatever
// the umask leaves a t.TempDir.
func stateDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// init-issuer makes the CA once, 0600; run again it writes nothing; half a
// CA is refused. rotate-issuer stages and then promotes, the old CA kept
// trusted and its key gone (decision 43 ruling 14).
func TestInitAndRotateIssuer(t *testing.T) {
	dir, now := stateDir(t), time.Now()
	created, line, err := initIssuer(dir, now)
	if err != nil || !created || !strings.Contains(line, "created the issuing CA") {
		t.Fatalf("%v %q %v", created, line, err)
	}
	for _, name := range []string{issuer.CertFile, issuer.KeyFile} {
		if fi, err := os.Stat(filepath.Join(dir, name)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", name, fi, err)
		}
	}
	if created, line, err = initIssuer(dir, now); err != nil || created || !strings.Contains(line, "already there") {
		t.Fatalf("a second init: %v %q %v", created, line, err)
	}
	first, _ := issuer.Load(issuerFiles(dir), now)
	if line, err = rotateIssuer(dir, now); err != nil || !strings.Contains(line, "staged") {
		t.Fatalf("the stage: %q %v", line, err)
	}
	staged, _ := issuer.Load(issuerFiles(dir), now)
	if staged.Unavailable != nil || len(staged.Trusted) != 2 || !bytes.Equal(staged.Cert.Raw, first.Cert.Raw) {
		t.Fatalf("staged: %v %d", staged.Unavailable, len(staged.Trusted))
	}
	if line, err = rotateIssuer(dir, now); err != nil || !strings.Contains(line, "promoted the staged CA") {
		t.Fatalf("the promotion: %q %v", line, err)
	}
	after, _ := issuer.Load(issuerFiles(dir), now)
	if after.Unavailable != nil || len(after.Trusted) != 2 || bytes.Equal(after.Cert.Raw, first.Cert.Raw) ||
		!bytes.Equal(after.Trusted[1].Raw, first.Cert.Raw) {
		t.Fatalf("promoted: %v %d", after.Unavailable, len(after.Trusted))
	}
	for _, name := range []string{issuer.NextCertFile, issuer.NextKeyFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s is still there: %v", name, err)
		}
	}
	if err := os.Remove(filepath.Join(dir, issuer.KeyFile)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := initIssuer(dir, now); err == nil || !strings.Contains(err.Error(), "without the other") {
		t.Fatalf("half a CA: %v", err)
	}
}

// A promotion interrupted after the certificate and before the key is
// finished by running it again (decision 43 ruling 14).
func TestAnInterruptedPromotionFinishes(t *testing.T) {
	dir, now := stateDir(t), time.Now()
	if _, _, err := initIssuer(dir, now); err != nil {
		t.Fatal(err)
	}
	if _, err := rotateIssuer(dir, now); err != nil {
		t.Fatal(err)
	}
	cur, _ := os.ReadFile(filepath.Join(dir, issuer.CertFile))
	next, _ := os.ReadFile(filepath.Join(dir, issuer.NextCertFile))
	for name, body := range map[string][]byte{issuer.PreviousCertFile: cur, issuer.CertFile: next} {
		if err := writeOwnerOnly(filepath.Join(dir, name), body); err != nil {
			t.Fatal(err)
		}
	}
	if ca, _ := issuer.Load(issuerFiles(dir), now); ca.Unavailable == nil {
		t.Fatal("a certificate with the old key loaded as usable")
	}
	if _, err := rotateIssuer(dir, now); err != nil {
		t.Fatal(err)
	}
	if ca, _ := issuer.Load(issuerFiles(dir), now); ca.Unavailable != nil || len(ca.Trusted) != 2 ||
		!bytes.Equal(ca.Cert.Raw, mustCert(t, next)) {
		t.Fatalf("after the rerun: %v", ca.Unavailable)
	}
}

// The edges of a rotation (decision 43 ruling 14): another broker holds the
// staged certificate alone, trusts it, and cannot promote it; a staged file
// left there once the promotion is copied over is the current CA already,
// and is removed with nothing promoted; and a promotion is refused while an
// earlier rotation's previous CA is still there, until it is removed.
func TestRotateIssuerEdges(t *testing.T) {
	a, b, now := stateDir(t), stateDir(t), time.Now()
	if _, _, err := initIssuer(a, now); err != nil {
		t.Fatal(err)
	}
	copyToB := func(names ...string) {
		t.Helper()
		for _, n := range names {
			raw, err := os.ReadFile(filepath.Join(a, n))
			if err != nil {
				t.Fatal(err)
			}
			if err := writeOwnerOnly(filepath.Join(b, n), raw); err != nil {
				t.Fatal(err)
			}
		}
	}
	copyToB(issuer.CertFile, issuer.KeyFile)
	if line, err := rotateIssuer(a, now); err != nil || !strings.Contains(line, "copy "+issuer.NextCertFile+" alone") {
		t.Fatalf("the stage: %q %v", line, err)
	}
	copyToB(issuer.NextCertFile)
	if ca, _ := issuer.Load(issuerFiles(b), now); ca.Unavailable != nil || len(ca.Trusted) != 2 {
		t.Fatalf("the other broker, the staged certificate alone: %v, %d trusted", ca.Unavailable, len(ca.Trusted))
	}
	if _, err := rotateIssuer(b, now); err == nil || !strings.Contains(err.Error(), "the broker that staged it") {
		t.Fatalf("a promotion with no staged key: %v", err)
	}
	if line, err := rotateIssuer(a, now); err != nil || !strings.Contains(line, "promoted the staged CA") {
		t.Fatalf("the promotion: %q %v", line, err)
	}
	copyToB(issuer.CertFile, issuer.KeyFile, issuer.PreviousCertFile)
	before, _ := os.ReadFile(filepath.Join(b, issuer.CertFile))
	if line, err := rotateIssuer(b, now); err != nil || !strings.Contains(line, "nothing was promoted") ||
		!strings.Contains(line, "if this broker promoted it, copy") {
		t.Fatalf("a staged file left from the promotion: %q %v", line, err)
	}
	after, _ := os.ReadFile(filepath.Join(b, issuer.CertFile))
	if _, err := os.Stat(filepath.Join(b, issuer.NextCertFile)); !errors.Is(err, fs.ErrNotExist) ||
		!bytes.Equal(before, after) {
		t.Fatalf("the leftover is still there (%v), or the current CA changed", err)
	}
	if _, err := rotateIssuer(a, now); err != nil {
		t.Fatal(err)
	}
	if _, err := rotateIssuer(a, now); err == nil ||
		!strings.Contains(err.Error(), issuer.PreviousCertFile+" from an earlier rotation") {
		t.Fatalf("a promotion over the previous CA: %v", err)
	}
	if err := os.Remove(filepath.Join(a, issuer.PreviousCertFile)); err != nil {
		t.Fatal(err)
	}
	if line, err := rotateIssuer(a, now); err != nil || !strings.Contains(line, "promoted the staged CA") {
		t.Fatalf("the promotion once it is removed: %q %v", line, err)
	}
}

// mustCert is the DER of the one PEM certificate in b.
func mustCert(t *testing.T, b []byte) []byte {
	t.Helper()
	c, _ := issuer.Load(issuer.Mem(map[string][]byte{issuer.CertFile: b}), time.Now())
	if c.Cert == nil {
		t.Fatal("no certificate")
	}
	return c.Cert.Raw
}

// A broker configured to issue with no CA starts, says what to run, and sets
// its gauge to 0; once the CA is made, the next start issues (decision 43
// ruling 14; R4).
func TestABrokerWithNoIssuingCAStartsAndSaysSo(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	cfg := brokerConfig(t, minimalPolicy)
	cfg.Broker.ClientCAFile = ""
	cfg.Broker.StateDir = stateDir(t)
	cfg.Broker.Identity = oidcOnly(t, iss, t.TempDir())
	cfg.Broker.Identity.Issuance = &oidc.Issuance{CertificateLifetime: 8 * time.Hour}
	out := captureStderr(t)
	m := metrics.New(prometheus.NewRegistry())
	srv, b, err := buildBroker(cfg, "inventory_file x", memory.New(time.Now), seedMinter(),
		decision.NewJSONLines(io.Discard), m)
	if err != nil || srv == nil || b.Issuer == nil || b.Issuer.Unavailable == nil || b.CertificateLifetime != 8*time.Hour {
		t.Fatalf("%v, issuer %+v", err, b)
	}
	if !strings.Contains(out.String(), "issuance: issuing-ca.pem is missing") || !strings.Contains(out.String(), "init-issuer") {
		t.Fatalf("the start lines:\n%s", out.String())
	}
	if v := testutil.ToFloat64(m.IssuingCANotAfter); v != 0 {
		t.Fatalf("the gauge with no CA: %v", v)
	}
	if _, _, err := initIssuer(cfg.Broker.StateDir, time.Now()); err != nil {
		t.Fatal(err)
	}
	out = captureStderr(t)
	m = metrics.New(prometheus.NewRegistry())
	if _, b, err = buildBroker(cfg, "inventory_file x", memory.New(time.Now), seedMinter(),
		decision.NewJSONLines(io.Discard), m); err != nil || b.Issuer.Unavailable != nil ||
		!strings.Contains(out.String(), "issuance: issuing as ") {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if v := testutil.ToFloat64(m.IssuingCANotAfter); v != float64(b.Issuer.Cert.NotAfter.Unix()) {
		t.Fatalf("the gauge: %v", v)
	}
}

// The subcommand takes one flag, and says so.
func TestIssuerCmdUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := issuerCmd("port49d", "init-issuer", "/etc/port49/port49d.yaml", nil, []string{"extra"}, &out,
		&errb); code != 2 || !strings.Contains(errb.String(), "usage: port49d init-issuer [--config FILE]") {
		t.Fatalf("%d %q", code, errb.String())
	}
}
