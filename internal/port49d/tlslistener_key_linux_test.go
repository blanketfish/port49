//go:build linux

package port49d

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/fence"
)

// tls_listener.key_file is read under the secret-file rule (decision 54 ruling 16): a key others can
// read, a key linked in from outside its directory and a key another user owns are refused at the first
// load, and at a reload they are refused naming the key while the material in force stays.
func TestTheListenersKeyIsReadUnderTheSecretFileRule(t *testing.T) {
	good, err := os.ReadFile(writeDevicePKI(t).keyFile)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		spoil func(t *testing.T, key string)
		want  string
	}{
		"world-readable": {func(t *testing.T, key string) {
			if err := os.Chmod(key, 0o644); err != nil {
				t.Fatal(err)
			}
		}, "world-readable"},
		"linked from outside": {func(t *testing.T, key string) {
			out := filepath.Join(safeDir(t), "elsewhere.key")
			if err := os.WriteFile(out, good, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(key); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(out, key); err != nil {
				t.Fatal(err)
			}
		}, "outside"},
		"another user's": {func(t *testing.T, key string) {
			real := fence.FileOwner
			t.Cleanup(func() { fence.FileOwner = real })
			fence.FileOwner = func(fi fs.FileInfo) (uint32, bool) {
				if strings.HasPrefix(fi.Name(), "srv.key") {
					return uint32(os.Geteuid()) + 1, true
				}
				return real(fi)
			}
		}, "owned by uid"},
	} {
		t.Run(name, func(t *testing.T) {
			realOwner := fence.FileOwner
			t.Cleanup(func() { fence.FileOwner = realOwner })
			// at the first load
			p := writeDevicePKI(t)
			c.spoil(t, p.keyFile)
			if l, err := newTLSListener(p.listenerCfg(), nil, nil, false, nil, time.Now, func(string, ...any) {}); err == nil ||
				l != nil || !strings.Contains(err.Error(), "tls_listener.key_file") || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("the first load: %v %v", l, err)
			}
			fence.FileOwner = realOwner
			// at a reload, with the material in force kept
			p = writeDevicePKI(t)
			var said []string
			l, err := newTLSListener(p.listenerCfg(), nil, nil, false, nil, time.Now,
				func(f string, a ...any) { said = append(said, fmt.Sprintf(f, a...)) })
			if err != nil {
				t.Fatal(err)
			}
			before := l.Material()
			c.spoil(t, p.keyFile)
			l.reload("reload_interval")
			if l.Material() != before || l.Material() == nil {
				t.Fatal("the material in force changed")
			}
			if joined := strings.Join(said, "\n"); !strings.Contains(joined, "tls_listener.key_file") || !strings.Contains(joined, c.want) {
				t.Fatalf("the reload did not refuse the key: %q", joined)
			}
		})
	}
}
