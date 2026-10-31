package userconfig

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// The client package ships packaging/client/config.yaml as /etc/port49/config.yaml (plan 12b,
// Task 8). A site's broker URL and CA are config management's job, so the file must set nothing:
// it loads as the zero File, and each of the keys is there only as a commented example.
func TestTheClientConffileSetsNothing(t *testing.T) {
	src := filepath.Join("..", "..", "packaging", "client", "config.yaml")
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	// Parsed from a private copy: parse walks the file's ancestors, and a checkout's own
	// directories say nothing about the installed file.
	dir := privateDir(t)
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	f, ok, err := parse(p, "system config", false)
	if err != nil || !ok {
		t.Fatalf("the conffile does not load: ok=%v err=%v", ok, err)
	}
	if f.Broker != "" || f.BrokerCA != "" || f.Cert != "" || f.Key != "" || f.Method != "" || f.BrokerCRL != "" ||
		f.TouchKey != "" || f.IssuedKeyStore != "" || f.IssuedKey != "" || f.OIDCIssuer != "" || f.OIDCCA != "" ||
		f.SignInName != "" || f.OIDCRedirectPort != 0 {
		t.Errorf("the conffile sets something: %+v", f)
	}
	for _, key := range []string{"broker", "broker_ca", "broker_crl", "touch_key", "key", "issued_key_store"} {
		if !regexp.MustCompile(`(?m)^# ` + key + `:`).Match(raw) {
			t.Errorf("the conffile does not carry %s as a commented line", key)
		}
		if regexp.MustCompile(`(?m)^` + key + `:`).Match(raw) {
			t.Errorf("the conffile sets %s", key)
		}
	}
}
