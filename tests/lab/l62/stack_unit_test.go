//go:build lab

package l62

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blanketfish/port49/internal/testpki"
)

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestL62UnitBrokerConfigNamesTheRealmAndIssuance(t *testing.T) {
	out, err := rewriteBrokerConfig(repoFile(t, "deploy/compose/config/port49-broker.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Broker struct {
			ClientCA string `yaml:"client_ca_file"`
			Identity struct {
				Issuance struct {
					Lifetime string `yaml:"certificate_lifetime"`
				} `yaml:"issuance"`
				Humans []map[string]any `yaml:"humans"`
			} `yaml:"identity"`
			Listen string `yaml:"listen"`
		} `yaml:"broker"`
	}
	if err := yaml.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatalf("the rewritten config is not YAML: %v", err)
	}
	b := cfg.Broker
	if b.ClientCA != "" {
		t.Errorf("client_ca_file is still set: %q", b.ClientCA)
	}
	if b.Identity.Issuance.Lifetime != "24h" {
		t.Errorf("certificate_lifetime = %q, want 24h", b.Identity.Issuance.Lifetime)
	}
	if b.Listen != ":8443" {
		t.Errorf("listen = %q: the compose port mapping reaches :8443", b.Listen)
	}
	if len(b.Identity.Humans) != 2 || b.Identity.Humans[0]["trust_anchor_file"] != "/etc/port49/broker/broker-ca.pem" ||
		b.Identity.Humans[1]["issuer"] != keycloakIssuer || b.Identity.Humans[1]["client_id"] != "port49-cli" ||
		b.Identity.Humans[1]["ca_file"] != "/etc/port49-oidc/idp-ca.pem" {
		t.Errorf("humans = %v", b.Identity.Humans)
	}
	// Everything else is the original's, byte for byte.
	if !strings.Contains(out, "stores:\n  directory:\n    backend: etcd") || !strings.Contains(out, "certificate_status: {disabled: true}") {
		t.Error("the rewrite lost the original's stores or certificate_status")
	}
}

func TestL62UnitBrokerConfigRefusesWhatItCannotFollow(t *testing.T) {
	for name, in := range map[string]string{
		"no anchor":     "broker:\n  listen: \":8443\"\n",
		"two anchors":   "broker:\n  client_ca_file: a\n  client_ca_file: b\n",
		"has identity":  "broker:\n  client_ca_file: a\n  identity:\n    humans: []\n",
		"empty":         "",
		"commented out": "broker:\n  # client_ca_file: a\n",
	} {
		if _, err := rewriteBrokerConfig(in); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// The realm and the policy must agree on who alice is, and the issuer must be
// the one the Keycloak overlay serves.
func TestL62UnitPolicyAndIssuerMatchTheLabRealm(t *testing.T) {
	realm := repoFile(t, "tests/lab/oidc/keycloak/realm.json")
	if !strings.Contains(realm, `"email": "alice@corp.example.com"`) || !strings.Contains(realm, "http://127.0.0.1:18749/callback") {
		t.Error("the realm no longer has alice@corp.example.com or the port49-cli redirect on 18749")
	}
	if !strings.Contains(policyYAML, "user:alice@corp.example.com") {
		t.Error("the policy does not name alice's email")
	}
	var p map[string]any
	if err := yaml.Unmarshal([]byte(policyYAML), &p); err != nil {
		t.Fatalf("policy is not YAML: %v", err)
	}
	overlay := repoFile(t, "tests/lab/compose/oidc.yaml")
	if !strings.Contains(overlay, "--hostname=https://"+keycloakHost+":"+keycloakPort) ||
		!strings.Contains(overlay, `"127.0.0.1:`+keycloakPort+`:`+keycloakPort+`"`) {
		t.Error("tests/lab/compose/oidc.yaml no longer serves Keycloak where this harness and the runbook expect it")
	}
}

func TestL62UnitOverlayPublishesTheBrokerOnItsOwnPort(t *testing.T) {
	var o struct {
		Services map[string]struct {
			Image string `yaml:"image"`
			Ports any    `yaml:"ports"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(composeOverlay), &o); err != nil {
		t.Fatal(err)
	}
	if got := o.Services["port49-broker"].Image; got != brokerImage {
		t.Errorf("broker image = %q", got)
	}
	if got := o.Services["setup"].Image; got != setupImage || o.Services["etcd-init"].Image != setupImage {
		t.Errorf("setup / etcd-init image = %q / %q", got, o.Services["etcd-init"].Image)
	}
	if !strings.Contains(composeOverlay, `ports: !override`) || !strings.Contains(composeOverlay, `"127.0.0.1:8449:8443"`) {
		t.Error("the overlay does not replace the broker's ports with 127.0.0.1:8449 alone")
	}
	if strings.Contains(composeOverlay, "9050") {
		t.Error("the overlay publishes the metrics port another lab's broker may hold")
	}
}

func TestL62UnitStateDir(t *testing.T) {
	if got := stateDir("", "/home/x/.cache"); got != "/home/x/.cache/port49-l62" {
		t.Errorf("default = %q", got)
	}
	if got := stateDir("/tmp/s", "/home/x/.cache"); got != "/tmp/s" {
		t.Errorf("override = %q", got)
	}
}

// madeState writes the files a kept state holds, certificates ending at end.
func madeState(t *testing.T, end time.Time) string {
	t.Helper()
	dir := t.TempDir()
	now := end.Add(-24 * time.Hour)
	ca, err := testpki.NewCA("test", now.Add(-time.Hour), end)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Issue(testpki.Leaf{CommonName: "x", NotBefore: now.Add(-time.Hour), NotAfter: end})
	if err != nil {
		t.Fatal(err)
	}
	cert, _, err := testpki.PEMs(leaf)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range stateFiles {
		body := []byte("x")
		for _, c := range stateCerts {
			if f == c {
				body = cert
			}
		}
		p := filepath.Join(dir, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestL62UnitReuseDecision(t *testing.T) {
	now := time.Now()
	good := madeState(t, now.Add(20*time.Hour))
	short := madeState(t, now.Add(2*time.Hour))
	partial := madeState(t, now.Add(20*time.Hour))
	if err := os.Remove(filepath.Join(partial, "local/oidc/admin.env")); err != nil {
		t.Fatal(err)
	}
	broken := madeState(t, now.Add(20*time.Hour))
	if err := os.WriteFile(filepath.Join(broken, "local/broker/broker.pem"), []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name  string
		dir   string
		fresh bool
		reuse bool
		why   string
	}{
		{"complete and long enough", good, false, true, "reusing the kept state"},
		{"fresh asked", good, true, false, "PORT49_L62_FRESH=1"},
		{"nothing there", filepath.Join(t.TempDir(), "none"), false, false, "no state yet"},
		{"ends too soon", short, false, false, "under 6h0m0s from now"},
		{"one file gone", partial, false, false, "no local/oidc/admin.env"},
		{"a certificate that does not parse", broken, false, false, "unreadable certificate (local/broker/broker.pem"},
	} {
		reuse, why := reuseDecision(readState(c.dir), now, c.fresh)
		if reuse != c.reuse || !strings.Contains(why, c.why) {
			t.Errorf("%s: reuse %v, %q; want %v, containing %q", c.name, reuse, why, c.reuse, c.why)
		}
	}
	// The earliest end governs, not the first file's.
	if s := readState(good); s.NotAfter.Sub(now) > 21*time.Hour || s.NotAfter.Sub(now) < 19*time.Hour {
		t.Errorf("NotAfter = %v, want about 20h from now", s.NotAfter)
	}
}

func TestL62UnitTheBrokerLogWithholdsWhatTheRunbookDoes(t *testing.T) {
	in := strings.Join([]string{
		`{"msg":"listening","addr":":8443"}`,
		`{"msg":"GET /authorize?state=abc&code_challenge=zzz"}`,
		`{"msg":"minted a Token for alice"}`,
		`{"msg":"bearer eyJhbGciOi"}`,
		`{"msg":"issuance: certificates of 24h"}`,
		`client SECRET rotated`,
		`password prompt shown`,
		``,
	}, "\n")
	var out bytes.Buffer
	kept, dropped, err := copyFiltered(strings.NewReader(in), &out)
	if err != nil {
		t.Fatal(err)
	}
	if kept != 2 || dropped != 5 {
		t.Errorf("kept %d, dropped %d; want 2 and 5", kept, dropped)
	}
	for _, bad := range []string{"state=", "Token", "eyJ", "SECRET", "password"} {
		if strings.Contains(out.String(), bad) {
			t.Errorf("the copy holds %q:\n%s", bad, out.String())
		}
	}
	if !strings.Contains(out.String(), "listening") || !strings.Contains(out.String(), "issuance: certificates of 24h") {
		t.Errorf("the copy lost an ordinary line:\n%s", out.String())
	}
}

func TestL62UnitIssuanceAvailable(t *testing.T) {
	for _, c := range []struct {
		body string
		want bool
		err  bool
	}{
		{`{"issuance":{"certificate_lifetime_seconds":86400}}`, true, false},
		{`{"issuance":{"certificate_lifetime_seconds":86400,"available":true}}`, true, false},
		{`{"issuance":{"available":false}}`, false, false},
		{`{}`, false, false},
		{`<html>`, false, true},
	} {
		got, err := issuanceAvailable([]byte(c.body))
		if got != c.want || (err != nil) != c.err {
			t.Errorf("%s: %v, %v; want %v, err %v", c.body, got, err, c.want, c.err)
		}
	}
}

func TestL62UnitHoldEndsOnEnterOrStop(t *testing.T) {
	stop := make(chan struct{})
	if got := holdUntil(strings.NewReader("\n"), stop); got != "enter" {
		t.Errorf("a line: %q", got)
	}
	// Input that ends with no line (a background run) must not stop the stack.
	done := make(chan string, 1)
	go func() { done <- holdUntil(strings.NewReader(""), stop) }()
	select {
	case got := <-done:
		t.Fatalf("end of input stopped the hold: %q", got)
	case <-time.After(100 * time.Millisecond):
	}
	close(stop)
	if got := <-done; got != "stop after end of input" {
		t.Errorf("after stop: %q", got)
	}
	// A terminal that never answers is stopped by the signal.
	pr, pw := io.Pipe()
	defer pw.Close()
	stop2 := make(chan struct{})
	go func() { time.Sleep(50 * time.Millisecond); close(stop2) }()
	if got := holdUntil(pr, stop2); got != "stop" {
		t.Errorf("signal: %q", got)
	}
}
