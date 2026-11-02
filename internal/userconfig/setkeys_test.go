package userconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	issuedRef = "pkcs11:token=YubiKey%20PIV%20%23%3Cserial%3E;id=%01?module-path=/usr/lib/x86_64-linux-gnu/libykcs11.so"
	touchRef  = "pkcs11:token=YubiKey%20PIV%20%23%3Cserial%3E;id=%02?module-path=/usr/lib/x86_64-linux-gnu/libykcs11.so"
)

func writeConf(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(privateDir(t), "config.yaml")
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSetKeysReplacesInPlace: an existing touch_key line is replaced where it
// stands; the lines before and after it, comments, odd indentation, a quoted
// value and blank lines included, are byte-identical.
func TestSetKeysReplacesInPlace(t *testing.T) {
	before := "# my port49 config\nbroker: \"https://broker.example.com:4433\"\ntouch_key: pkcs11:old\n\n   # indented comment\nbroker_ca:    /etc/ca.pem   # trailing\nmethod: x509\n"
	p := writeConf(t, before, 0o640)
	changed, err := SetKeys(p, issuedRef, touchRef)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	got, _ := os.ReadFile(p)
	lines := strings.Split(string(got), "\n")
	old := strings.Split(before, "\n")
	if !strings.HasPrefix(lines[2], "touch_key: ") || !strings.Contains(lines[2], "id=%02") {
		t.Fatalf("line 3 is %q", lines[2])
	}
	for i := range old[:len(old)-1] { // the last element is the empty tail after the final newline
		if i == 2 {
			continue
		}
		if i >= len(lines) || lines[i] != old[i] {
			t.Fatalf("line %d changed: %q -> %q", i+1, old[i], lines[i])
		}
	}
	if !strings.Contains(string(got), "issued_key: ") || !strings.HasSuffix(string(got), "\n") {
		t.Fatalf("issued_key was not appended: %q", got)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v, want the file's own 0640", fi.Mode().Perm())
	}
	f, ok, err := Load(p, WithoutCA())
	if err != nil || !ok || f.IssuedKey != issuedRef || f.TouchKey != touchRef {
		t.Fatalf("loaded %+v ok=%v err=%v", f, ok, err)
	}
}

func TestSetKeysChangesNothingWhenTheyMatch(t *testing.T) {
	p := writeConf(t, "broker: x\n", 0o600)
	if _, err := SetKeys(p, issuedRef, touchRef); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(p)
	changed, err := SetKeys(p, issuedRef, touchRef)
	after, _ := os.ReadFile(p)
	fi, _ := os.Stat(p)
	if err != nil || changed || string(before) != string(after) || !fi.ModTime().Equal(old) {
		t.Fatalf("changed=%v err=%v mtime=%v", changed, err, fi.ModTime())
	}
}

func TestSetKeysCreatesAMissingFile(t *testing.T) {
	p := filepath.Join(privateDir(t), "sub", "config.yaml")
	changed, err := SetKeys(p, issuedRef, touchRef)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

// A file the edit cannot leave loading is refused unwritten.
func TestSetKeysRefusesAFileItWouldBreak(t *testing.T) {
	body := "touch_key: |\n  pkcs11:multi\n  line\n"
	p := writeConf(t, body, 0o600)
	if _, err := SetKeys(p, issuedRef, touchRef); err == nil {
		t.Fatal("a block-scalar touch_key was edited in place")
	}
	got, _ := os.ReadFile(p)
	if string(got) != body {
		t.Fatalf("a refused edit wrote: %q", got)
	}
}
