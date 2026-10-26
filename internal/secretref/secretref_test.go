package secretref

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// secretDir is a directory only its owner can write: t.TempDir is made under
// the process's umask, which may leave the group a write bit the fence refuses.
func secretDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestParse(t *testing.T) {
	for _, c := range []struct {
		in   string
		want Ref
	}{
		{"env:PORT49_PROD_V3", Ref{Scheme: SchemeEnv, Name: "PORT49_PROD_V3"}},
		{"file:/run/secrets/prod_v3", Ref{Scheme: SchemeFile, Name: "/run/secrets/prod_v3"}},
	} {
		got, err := Parse(c.in)
		if err != nil || got != c.want {
			t.Errorf("%q: %+v, %v", c.in, got, err)
		}
	}
	if got, _ := Parse("env:PORT49_PROD_V3"); got.String() != "env:PORT49_PROD_V3" {
		t.Errorf("String: %q", got.String())
	}
}

// A reference that does not parse is most likely the secret itself, pasted
// where its name goes: every refusal is the one fixed text, which quotes
// nothing of the input (decision 53 ruling 1).
func TestAnUnparsedRefIsNeverPrinted(t *testing.T) {
	for _, in := range []string{
		"hunter2-shared-key", "env:", "env:1BAD", "env:HAS SPACE", "file:relative/path", "file:/a/../b",
		"vault:port49/prod/v3", "vault:/run/vault/v3", "ldap:x", "",
		"file:/ok\x00/nul",
	} {
		_, err := Parse(in)
		if err == nil || err.Error() != errShape.Error() {
			t.Errorf("%q: %v, want the fixed refusal", in, err)
		}
	}
}

// The spec writes a reference unquoted inside a flow mapping; yaml.v3 must
// read it whole.
func TestARefDecodesUnquotedInAFlowMapping(t *testing.T) {
	var v struct {
		Ref string `yaml:"secret_ref"`
	}
	if err := yaml.Unmarshal([]byte(`{version: 3, secret_ref: file:/run/secrets/prod_v3}`), &v); err != nil ||
		v.Ref != "file:/run/secrets/prod_v3" {
		t.Fatalf("%q, %v", v.Ref, err)
	}
}

func TestResolveEnv(t *testing.T) {
	t.Setenv("T_SECRETREF_ENV", "shared-key")
	r := New()
	_, s, err := r.ResolveText("keys.k.current.secret_ref", "env:T_SECRETREF_ENV")
	if err != nil || string(s.Bytes()) != "shared-key" {
		t.Fatalf("got %d bytes, want 10; %v", len(s.Bytes()), err)
	}
	if _, _, err := r.ResolveText("keys.k.current.secret_ref", "env:T_SECRETREF_UNSET"); err == nil ||
		!strings.Contains(err.Error(), "keys.k.current.secret_ref env:T_SECRETREF_UNSET") ||
		!strings.Contains(err.Error(), "not set") {
		t.Fatalf("an unset variable: %v", err)
	}
}

// echo writes a newline; a key with one validates no device's packet. One
// trailing newline is dropped, LF or CRLF, and nothing else is touched.
func TestAFileSecretDropsOneTrailingNewline(t *testing.T) {
	r := New()
	dir := secretDir(t)
	for body, want := range map[string]string{
		"shared-key\n": "shared-key", "shared-key\r\n": "shared-key", "shared-key": "shared-key",
		"shared-key\n\n": "shared-key\n", " spaced \n": " spaced ",
	} {
		p := filepath.Join(dir, fmt.Sprintf("s%d", len(body)))
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, s, err := r.ResolveText("k", "file:"+p)
		if err != nil || string(s.Bytes()) != want {
			// lengths only: a failure message never prints a secret
			t.Errorf("a %d-byte body: got %d bytes, want %d; %v", len(body), len(s.Bytes()), len(want), err)
		}
	}
}

// A secret file is read through the fence: a mode the world can read is
// refused, naming the file and never its content; group-read is allowed,
// as fsGroup and an agent's perms give it (decision 53 ruling 1).
func TestAFileSecretTheWorldCanReadIsRefused(t *testing.T) {
	dir := secretDir(t)
	r := New()
	for mode, ok := range map[os.FileMode]bool{0o600: true, 0o640: true, 0o440: true, 0o644: false, 0o660: false,
		0o604: false} {
		p := filepath.Join(dir, fmt.Sprintf("s%o", mode))
		if err := os.WriteFile(p, []byte("hunter2-in-a-file"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		_, _, err := r.ResolveText("k", "file:"+p)
		if err != nil && strings.Contains(err.Error(), "hunter2") {
			t.Errorf("mode %o: the refusal carries the file's content", mode)
			continue
		}
		if (err == nil) != ok || (err != nil && !strings.Contains(err.Error(), "chmod 0440 or 0600")) {
			t.Errorf("mode %o: %v", mode, err)
		}
	}
}

// The allowance (decision 53 ruling 12): an env: reference by prefix, a
// file: one by directory, and its own shape.
func TestAllowance(t *testing.T) {
	a := Allowance{}.WithDefaults()
	for text, want := range map[string]bool{
		"env:PORT49_KEY_PROD_V3": true, "env:PORT49_ENC_V2": false, "env:PORT49_KEY": false,
		"file:/run/port49/keys/prod_v3": true, "file:/run/port49/keys/a/b": true, "file:/run/port49/keysx/k": false,
		"file:/run/port49/keys": false, "file:/etc/port49/tls-key.pem": false,
	} {
		ref, err := Parse(text)
		if err != nil || a.Allows(ref) != want {
			t.Errorf("%s: %v %v", text, a.Allows(ref), err)
		}
	}
	for _, bad := range []Allowance{{EnvPrefix: "P", FileDir: "/k"}, {EnvPrefix: "PORT49_", FileDir: "keys"},
		{EnvPrefix: "PORT 49", FileDir: "/k"}, {EnvPrefix: "PORT49_", FileDir: "/k/../x"}} {
		if bad.Check() == nil {
			t.Errorf("%+v passed", bad)
		}
	}
}

func TestAnEmptySecretIsRefused(t *testing.T) {
	t.Setenv("T_SECRETREF_EMPTY", "")
	p := filepath.Join(secretDir(t), "s")
	os.WriteFile(p, []byte("\n"), 0o600)
	r := New()
	for _, text := range []string{"env:T_SECRETREF_EMPTY", "file:" + p} {
		if _, _, err := r.ResolveText("k", text); err == nil || !strings.Contains(err.Error(), "empty") &&
			!strings.Contains(err.Error(), "not set") {
			t.Errorf("%s: %v", text, err)
		}
	}
}

// No resolve error, for any scheme, carries the secret it was reading or the
// value it found (Review Focus 1).
func TestNoResolveErrorCarriesTheSecret(t *testing.T) {
	r := New()
	p := filepath.Join(secretDir(t), "s")
	if err := os.WriteFile(p, []byte("hunter2-in-a-file"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.ResolveText("k", "file:"+p); err == nil {
		t.Fatal("a world-readable file was read")
	} else if strings.Contains(err.Error(), "hunter2") {
		t.Fatal("a refused file's content is in the refusal")
	}
	t.Setenv("T_SECRETREF_SHOWN", "hunter2-shown")
	_, s, _ := r.ResolveText("k", "env:T_SECRETREF_SHOWN")
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		if strings.Contains(fmt.Sprintf(verb, s), "hunter2") {
			t.Fatalf("a Secret printed its value under %s", verb)
		}
	}
	if b, _ := json.Marshal(struct{ S Secret }{s}); strings.Contains(string(b), "hunter2") {
		t.Fatal("a Secret printed its value as JSON")
	}
	if strings.Contains(fmt.Sprintf("%+v", r), "hunter2") {
		t.Fatal("the resolver printed a secret under the plus-v verb")
	}
}
