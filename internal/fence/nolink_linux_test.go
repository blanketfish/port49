//go:build linux

package fence

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A named pipe in a state file's or a mirror's place is refused at once: both
// readers open non-blocking, so nothing waits on a writer.
func TestAFIFOIsRefusedByReadNoLinkAndReadSigned(t *testing.T) {
	path := filepath.Join(safeDir(t), "published.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, read := range map[string]func(string, int64, string) ([]byte, error){
		"ReadNoLink": ReadNoLink, "ReadSigned": ReadSigned} {
		if _, err := read(path, 1<<20, "bundle"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
