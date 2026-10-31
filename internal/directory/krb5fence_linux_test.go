//go:build linux

package directory

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// krb5_conf names the KDCs the broker trusts, so it is read through the policy-file fence (decision 54
// ruling 16) as ca_file is: a directory others can write, a link out of its directory and a named pipe
// are each refused, within seconds, and the error names the field.
func TestKRB5ConfIsReadThroughTheFence(t *testing.T) {
	const conf = "[libdefaults]\n default_realm = CORP.EXAMPLE.COM\n"
	mk := func(mode os.FileMode) string {
		d := t.TempDir()
		if err := os.Chmod(d, mode); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(d, "krb5.conf")
		if err := os.WriteFile(p, []byte(conf), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if b, err := readKRB5Conf(mk(0o755)); err != nil || string(b) != conf {
		t.Fatalf("the control, a good file in a safe directory: %v", err)
	}
	link := filepath.Join(t.TempDir(), "krb5.conf")
	if err := os.Symlink(mk(0o777), link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(t.TempDir(), "krb5.conf")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{
		"a world-writable directory": mk(0o777),
		"a group-writable directory": mk(0o775),
		"a link out to such a place": link,
		"a named pipe":               fifo,
	} {
		done := make(chan error, 1)
		go func() { _, err := readKRB5Conf(p); done <- err }()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "krb5_conf") {
				t.Errorf("%s: want a refusal naming krb5_conf, got %v", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("%s: the read hung", name)
		}
	}
}
