//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/config"
)

// withAdminTouch moves the client_ca_file shorthand to broker.identity.humans
// beside the attestation roots, and the loader accepts the result; a config
// with no client_ca_file line, or two, is refused with the count.
func TestWithAdminTouchMovesTheClientCA(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PORT49_LAB_ENC_KEY", labEncKeyDefault)
	piv, roots := adminTouchRoots(t, dir)
	if piv == nil {
		t.Fatal("no attestation hierarchy")
	}
	if raw, err := os.ReadFile(roots); err != nil || !strings.Contains(string(raw), "BEGIN CERTIFICATE") {
		t.Fatalf("the roots file: %v", err)
	}
	in := "listen: \"127.0.0.1:0\"\nmetrics_listen: \"127.0.0.1:0\"\naccounting: {spool_path: " + filepath.Join(dir, "a.jsonl") + "}\ninventory_file: " + filepath.Join(dir, "inv.yaml") +
		"\nencryption:\n  current: {id: lab1, secret_ref: env:PORT49_LAB_ENC_KEY}\nbroker:\n  listen: \"127.0.0.1:0\"\n" +
		"  tls_cert_file: /c.pem\n  tls_key_file: /k.pem\n  client_ca_file: /ca.pem\n  policy_file: /p.yaml\n" +
		"  revocations_file: " + filepath.Join(dir, "r.json") + "\n  certificate_status: {disabled: true}\n"
	out, err := withAdminTouch(in, roots)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "\n  client_ca_file:") || !strings.Contains(out, "trust_anchor_file: /ca.pem") ||
		!strings.Contains(out, "attestation_roots_file: "+roots) {
		t.Fatalf("the shorthand was not moved:\n%s", out)
	}
	p := filepath.Join(dir, "port49d.yaml")
	if err := os.WriteFile(p, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("the loader refuses the result: %v\n%s", err, out)
	}
	if m := cfg.Broker.Identity.PerLoginMFA; m == nil || m.AttestationRootsFile != roots {
		t.Fatalf("per_login_mfa: %+v", m)
	}
	for name, bad := range map[string]string{"none": "broker:\n  listen: x\n", "two": in + "  client_ca_file: /b.pem\n"} {
		if _, err := withAdminTouch(bad, roots); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
