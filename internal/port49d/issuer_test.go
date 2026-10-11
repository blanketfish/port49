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

	"github.com/rhwendt/port49/internal/config"
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

// issuerCmd refuses a config with no issuance, and with one acts in the
// state directory and exits 0.
func TestIssuerCmdRuns(t *testing.T) {
	dir := stateDir(t)
	cfg := config.Config{Broker: &config.BrokerConfig{StateDir: dir, Identity: &oidc.Config{}}}
	load := func(string) (config.Config, error) { return cfg, nil }
	var out, errb bytes.Buffer
	if code := issuerCmd("port49d", "init-issuer", "x.yaml", load, nil, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "configures no broker.identity.issuance") {
		t.Fatalf("no issuance: %d %q", code, errb.String())
	}
	if _, err := os.Stat(filepath.Join(dir, issuer.CertFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a CA was made with no issuance configured: %v", err)
	}
	cfg.Broker.Identity.Issuance = &oidc.Issuance{CertificateLifetime: time.Hour}
	out.Reset()
	errb.Reset()
	if code := issuerCmd("port49d", "init-issuer", "x.yaml", load, nil, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "created the issuing CA") || errb.Len() != 0 {
		t.Fatalf("init: %d %q %q", code, out.String(), errb.String())
	}
	if code := issuerCmd("port49d", "rotate-issuer", "x.yaml", load, nil, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "staged the next issuing CA") {
		t.Fatalf("rotate: %d %q %q", code, out.String(), errb.String())
	}
	bad := func(string) (config.Config, error) { return config.Config{}, errors.New("no such config") }
	if code := issuerCmd("port49d", "init-issuer", "x.yaml", bad, nil, &out, &errb); code != 1 {
		t.Fatalf("a config that does not load: %d", code)
	}
}

// A staged key that is not the staged certificate's (another broker's copied
// over this one's), or a staged certificate that does not parse, is refused
// before any write: the working CA, its key and the previous CA are as they
// were.
func TestRotateIssuerRefusesAStagedPairThatIsNotOne(t *testing.T) {
	a, b, now := stateDir(t), stateDir(t), time.Now()
	if _, _, err := initIssuer(a, now); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{issuer.CertFile, issuer.KeyFile} {
		raw, err := os.ReadFile(filepath.Join(a, n))
		if err != nil {
			t.Fatal(err)
		}
		if err := writeOwnerOnly(filepath.Join(b, n), raw); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{a, b} {
		if _, err := rotateIssuer(dir, now); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := func(dir string) map[string][]byte {
		m := map[string][]byte{}
		for _, n := range []string{issuer.CertFile, issuer.KeyFile, issuer.PreviousCertFile, issuer.NextCertFile,
			issuer.NextKeyFile} {
			m[n], _ = os.ReadFile(filepath.Join(dir, n))
		}
		return m
	}
	check := func(what string) {
		t.Helper()
		before := snapshot(b)
		if _, err := rotateIssuer(b, now); err == nil || !strings.Contains(err.Error(), "not a usable pair") {
			t.Fatalf("%s: %v", what, err)
		}
		for n, raw := range snapshot(b) {
			if !bytes.Equal(raw, before[n]) {
				t.Fatalf("%s: %s changed", what, n)
			}
		}
		if _, err := os.Stat(filepath.Join(b, issuer.PreviousCertFile)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s: a previous CA was written: %v", what, err)
		}
	}
	otherCert, err := os.ReadFile(filepath.Join(a, issuer.NextCertFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerOnly(filepath.Join(b, issuer.NextCertFile), otherCert); err != nil {
		t.Fatal(err)
	}
	check("another broker's certificate over this one's")
	if err := writeOwnerOnly(filepath.Join(b, issuer.NextCertFile), []byte("-----BEGIN CERTIFICATE-----\nAAAA\n")); err != nil {
		t.Fatal(err)
	}
	check("a corrupt staged certificate")
}

// A staged key with no staged certificate (a stage interrupted after the
// key) is refused and nothing is written; init-issuer refuses a key alone
// with the way out, a CA that is there and not usable without replacing it,
// and a key it finds already there is never overwritten.
func TestIssuerHalfStates(t *testing.T) {
	dir, now := stateDir(t), time.Now()
	if _, _, err := initIssuer(dir, now); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(dir, issuer.KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerOnly(filepath.Join(dir, issuer.NextKeyFile), key); err != nil {
		t.Fatal(err)
	}
	if _, err := rotateIssuer(dir, now); err == nil || !strings.Contains(err.Error(), issuer.NextKeyFile+" is in") ||
		!strings.Contains(err.Error(), "without "+issuer.NextCertFile) {
		t.Fatalf("a staged key with no certificate: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, issuer.PreviousCertFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("something was written: %v", err)
	}

	keyOnly := stateDir(t)
	if err := writeOwnerOnly(filepath.Join(keyOnly, issuer.KeyFile), key); err != nil {
		t.Fatal(err)
	}
	if _, _, err := initIssuer(keyOnly, now); err == nil || !strings.Contains(err.Error(), "if init-issuer was interrupted, remove "+issuer.KeyFile) {
		t.Fatalf("a key alone: %v", err)
	}
	if err := createOwnerOnly(filepath.Join(keyOnly, issuer.KeyFile), []byte("x")); err == nil {
		t.Fatal("createOwnerOnly overwrote a key that was there")
	}
	if got, _ := os.ReadFile(filepath.Join(keyOnly, issuer.KeyFile)); !bytes.Equal(got, key) {
		t.Fatal("the key was changed")
	}

	expired := stateDir(t)
	if _, _, err := initIssuer(expired, now.AddDate(-6, 0, 0)); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(expired, issuer.CertFile))
	if _, _, err := initIssuer(expired, now); err == nil || !strings.Contains(err.Error(), "not usable") ||
		!strings.Contains(err.Error(), "rotate-issuer") {
		t.Fatalf("an expired CA: %v", err)
	}
	if after, _ := os.ReadFile(filepath.Join(expired, issuer.CertFile)); !bytes.Equal(before, after) {
		t.Fatal("init replaced a CA that was there")
	}

	loose := stateDir(t)
	if _, _, err := initIssuer(loose, now); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(loose, issuer.KeyFile), 0o644); err != nil {
		t.Fatal(err)
	}
	before, _ = os.ReadFile(filepath.Join(loose, issuer.CertFile))
	if created, _, err := initIssuer(loose, now); err == nil || created {
		t.Fatalf("a key with a loose mode: %v", err)
	}
	if after, _ := os.ReadFile(filepath.Join(loose, issuer.CertFile)); !bytes.Equal(before, after) {
		t.Fatal("init replaced a CA that was there")
	}
}

// The gauge is the CA's end only while the CA can issue: a certificate whose
// key is gone leaves it 0, so an alert on 0 fires while sign-ins are refused.
func TestIssuingCAGaugeIsZeroWhileTheCAIsUnusable(t *testing.T) {
	cfg := config.Config{Broker: &config.BrokerConfig{StateDir: stateDir(t),
		Identity: &oidc.Config{Issuance: &oidc.Issuance{CertificateLifetime: time.Hour}}}}
	if _, _, err := initIssuer(cfg.Broker.StateDir, time.Now()); err != nil {
		t.Fatal(err)
	}
	say := func(string, ...any) {}
	m := metrics.New(prometheus.NewRegistry())
	if ca := openIssuer(cfg, m, say); ca.Unavailable != nil || testutil.ToFloat64(m.IssuingCANotAfter) == 0 {
		t.Fatalf("a usable CA: %v", ca.Unavailable)
	}
	if err := os.Remove(filepath.Join(cfg.Broker.StateDir, issuer.KeyFile)); err != nil {
		t.Fatal(err)
	}
	m = metrics.New(prometheus.NewRegistry())
	if ca := openIssuer(cfg, m, say); ca.Unavailable == nil || testutil.ToFloat64(m.IssuingCANotAfter) != 0 {
		t.Fatalf("a CA with no key: %v, gauge %v", ca.Unavailable, testutil.ToFloat64(m.IssuingCANotAfter))
	}
}
