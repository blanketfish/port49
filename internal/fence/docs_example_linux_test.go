//go:build linux

package fence

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The troubleshooting page's example line for a store restored with the wrong
// owner is the fence's own Short, with uid 1000 seen and uid 999 wanted, not
// a line built by hand from the format (#60).
func TestTheTroubleshootingPageQuotesTheOwnerRefusalTheFenceSays(t *testing.T) {
	const path = "/var/lib/port49/enrollments.json"
	f := filepath.Join(t.TempDir(), "enrollments.json")
	if err := os.WriteFile(f, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(f)
	if err != nil {
		t.Fatal(err)
	}
	owner, euid := FileOwner, Geteuid
	t.Cleanup(func() { FileOwner, Geteuid = owner, euid })
	Geteuid = func() int { return 999 }
	FileOwner = func(fs.FileInfo) (uint32, bool) { return 1000, true }
	err = ownedByUsOrRoot(named("the file", path), fi)
	r, ok := err.(*Refusal)
	if !ok {
		t.Fatalf("no refusal: %v", err)
	}
	raw, err := os.ReadFile("../../docs/site/operate/troubleshooting/index.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "`"+r.Short()+"`") {
		t.Errorf("the troubleshooting page does not quote the fence's line %q", r.Short())
	}
}
