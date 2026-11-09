//go:build linux

package port49d

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/config"
)

// fenceMode is the end of the fence's short mode refusal of a 0666 file: the
// value seen, the value wanted and the remedy (Task 1).
const fenceMode = ": mode -rw-rw-rw-, wants no group or other write - chmod go-w it"

// lineFrom is the line in said from prefix on. A line that ends on want was
// not cut, because the remedy is a refusal's last words.
func lineFrom(t *testing.T, said, prefix, want string) {
	t.Helper()
	for _, l := range strings.Split(said, "\n") {
		if i := strings.Index(l, prefix); i >= 0 {
			if !strings.HasSuffix(l, want) {
				t.Errorf("%d bytes, cut or worded otherwise, want it to end %q: %s", len(l[i:]), want, l[i:])
			}
			return
		}
	}
	t.Fatalf("no line with %q:\n%s", prefix, said)
}

// writeOpen writes p with mode 0666, whatever the umask.
func writeOpen(t *testing.T, p string) {
	t.Helper()
	if err := os.WriteFile(p, []byte("not a list"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
}

// port49d's in-process broker says a kept CRL the fence refuses at a
// 260-byte path with its cause, values and remedy, within the line's
// 300-byte cut (main.go:1285; #60).
func TestRunSaysAKeptCRLTheFenceRefusesWithinTheCut(t *testing.T) {
	out := captureStderr(t)
	b := brokerConfig(t, minimalPolicy).Broker
	statusPKI(t, b)
	dir := deepEnrollDir(t, 260, "crl-lab_ca.der")
	b.RevocationsFile = filepath.Join(dir, "revocations.json") // the in-process broker keeps its lists beside it
	if _, err := initRevocations(b.RevocationsFile, testInitConfig); err != nil {
		t.Fatal(err)
	}
	writeOpen(t, filepath.Join(dir, "crl-lab_ca.der"))
	b.CertificateStatus = &config.CertificateStatusConfig{CRLs: []config.CertificateStatusCRL{{Name: "lab_ca",
		URL: "http://127.0.0.1:1/lab.crl", IssuerFile: b.ClientCAFile}}}
	_, stop := startDaemon(t, writeRunConfig(t, b), out)
	defer stop()
	const said = "port49d: broker: certificate status: kept CRL lab_ca: the file …"
	waitFor(t, out, said)
	lineFrom(t, out.String(), said, fenceMode)
}

// The TLS listener says a kept CRL the fence refuses at a 260-byte path
// within its 300-byte cut (tlslistener.go:574; #60).
func TestTheTLSListenerSaysAKeptCRLTheFenceRefusesWithinTheCut(t *testing.T) {
	// the listener keeps its lists in state_dir/tls_listener (decision 50 ruling 8)
	dir := deepEnrollDir(t, 260-len("/crl-dev.der")-len("/tls_listener"), "state")
	if err := os.MkdirAll(filepath.Join(dir, "state", "tls_listener"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeOpen(t, filepath.Join(dir, "state", "tls_listener", "crl-dev.der"))
	r := newRotationIn(t, dir)
	lineFrom(t, r.sink.all(), "tls_listener: certificate status: kept CRL dev: the file …", fenceMode)
}

// A trust follow that finds the issuer_file refused by the fence, at a
// 260-byte path, says the refusal whole within its 400-byte cut. It names
// the config entry, then the fence's short form, never the path twice. That
// holds with no rotation (tlslistener.go:218) and after one
// (tlslistener.go:215) (#60).
func TestATrustFollowSaysAnIssuerFileTheFenceRefusesWithinTheCut(t *testing.T) {
	r := newRotationIn(t, deepEnrollDir(t, 260, "issuer.pem"))
	if len(r.issuer) != 260 {
		t.Fatalf("the issuer_file is %d bytes", len(r.issuer))
	}
	if err := os.Chmod(r.issuer, 0o666); err != nil {
		t.Fatal(err)
	}
	const key = "tls_listener.certificate_status.crls[0].issuer_file: the file …"
	r.l.reload("reload_interval")
	lineFrom(t, r.sink.all(), "the certificate status sources keep the issuers they had: "+key, fenceMode)
	if err := os.WriteFile(r.p.caFile, r.newCA.PEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	r.l.reload("reload_interval")
	r.l.reload("reload_interval")
	lineFrom(t, r.sink.all(), "declined status_unavailable until this is fixed: "+key, fenceMode)
}

// Every LoadPersisted loop in port49d says its errors through
// briefLine(err, 300), and the trust follow through briefLine(err, 400), so
// a fence refusal on a cut line keeps its cause, values and remedy (#60).
// It is brokerd.go's only test: no harness starts port49-broker with
// certificate_status on (ruling 10).
func TestEveryCutLineThatCarriesAFenceErrorIsBrief(t *testing.T) {
	const loop = "LoadPersisted() {"
	for file, want := range map[string]struct{ loads, follows int }{
		"main.go": {1, 0}, "brokerd.go": {1, 0}, "tlslistener.go": {1, 2},
	} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		src := string(raw)
		if n := strings.Count(src, loop); n != want.loads {
			t.Errorf("%s: %d LoadPersisted loops, want %d", file, n, want.loads)
		}
		for rest := src; strings.Contains(rest, loop); {
			rest = rest[strings.Index(rest, loop)+len(loop):]
			next := strings.SplitN(rest, "\n", 3) // the loop's first line
			if len(next) < 2 || !strings.Contains(next[1], "briefLine(err, 300)") {
				t.Errorf("%s: a LoadPersisted loop does not say its error through briefLine(err, 300): %q", file, next)
			}
		}
		if n := strings.Count(src, "briefLine(err, 400)"); n != want.follows {
			t.Errorf("%s: %d trust-follow lines through briefLine(err, 400), want %d", file, n, want.follows)
		}
	}
}
