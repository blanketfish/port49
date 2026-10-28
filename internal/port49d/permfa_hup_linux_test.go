//go:build linux

package port49d

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/testpki"
)

// waitLine waits up to 20s for out to hold want n times.
func waitLine(t *testing.T, out *syncBuffer, want string, n int) {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if strings.Count(out.String(), want) >= n {
			return
		}
	}
	t.Fatalf("waited 20s for %q x%d; have:\n%s", want, n, out.String())
}

// A running port49-broker re-reads attestation_roots_file at SIGHUP (spec
// §5.1.6, "add the root or intermediate to attestation_roots_file, then
// reload"): a replaced file is put in force and said so, and one it cannot
// use keeps the roots already in force and says so in one line.
func TestPort49BrokerReReadsItsAttestationRootsAtSIGHUP(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	iss := oidctest.NewIssuer(t)
	f := splitFleet(t)
	brokerWithIdentity(t, f, f.broker, iss, true)
	roots := filepath.Join(filepath.Dir(f.broker), "attestation-roots.pem")
	put := func(b []byte) {
		t.Helper()
		if err := os.WriteFile(roots, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ca := func(cn string) []byte {
		c, err := testpki.NewCA(cn, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		return c.PEM()
	}
	put(ca("first root"))
	raw, err := os.ReadFile(f.broker)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(string(raw), "  identity:\n",
		"  identity:\n    per_login_mfa: {hardware_key_touch: {attestation_roots_file: "+roots+"}}\n", 1)
	if body == string(raw) {
		t.Fatal("the broker config has no identity block to add per_login_mfa to")
	}
	if err := os.WriteFile(f.broker, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	runBrokerUntil(t, f.broker, &out, "port49-broker: listening on ", 1)
	const applied = "port49-broker: broker: SIGHUP: per_login_mfa hardware_key_touch verifies attestations against "
	const kept = "keeping the attestation roots already in force"
	hup := func() {
		t.Helper()
		if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
	}

	put(ca("second root"))
	hup()
	waitLine(t, &out, applied+roots, 1)

	put([]byte("not a certificate"))
	hup()
	waitLine(t, &out, kept, 1)
	if n := strings.Count(out.String(), kept); n != 1 {
		t.Fatalf("one bad file said %d lines, want one:\n%s", n, out.String())
	}
	if n := strings.Count(out.String(), applied+roots); n != 1 {
		t.Fatalf("a bad file was said to be applied (%d lines):\n%s", n, out.String())
	}
}
