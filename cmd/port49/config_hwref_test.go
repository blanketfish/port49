package main

import (
	"flag"
	"io"
	"path/filepath"
	"testing"

	"github.com/rhwendt/port49/internal/userconfig"
)

// A pkcs11 key named on the command line without --cert is not a complete
// command line for the login: config.yaml still supplies cert: and, with the
// system file, touch_key. Only the agent child, which the login handed all of
// it (--broker-ca-fd), is complete without them.
func TestAPKCS11KeyWithNoCertStillReadsTheConfigFile(t *testing.T) {
	home := privateDir(t)
	t.Setenv("HOME", home)
	t.Setenv(userconfig.EnvConfig, "")
	cfg := filepath.Join(home, ".port49", "config.yaml")
	body := "cert: /somewhere/token-cert.pem\ntouch_key: pkcs11:object=touch\n"
	if err := userconfig.WritePrivate(cfg, []byte(body), "port49 config file"); err != nil {
		t.Fatal(err)
	}
	parse := func(extra ...string) (*sessionFlags, *flag.FlagSet) {
		var sf sessionFlags
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		sf.register(fs)
		args := append([]string{"--broker", "https://b.example:8443", "--broker-ca", "/ca.pem",
			"--broker-crl", "check", "--key", "pkcs11:object=sess", "--config", cfg}, extra...)
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		return &sf, fs
	}

	sf, fs := parse()
	if sf.complete() {
		t.Fatal("a login naming a pkcs11 key and no --cert counted as complete")
	}
	if err := sf.fill(fs); err != nil {
		t.Fatal(err)
	}
	if sf.cert != "/somewhere/token-cert.pem" || sf.touchKey != "pkcs11:object=touch" {
		t.Errorf("cert %q touch_key %q, want the config file's", sf.cert, sf.touchKey)
	}

	child, _ := parse("--broker-ca-fd", "3")
	if !child.complete() {
		t.Error("the agent child, handed everything, was not complete")
	}
}
