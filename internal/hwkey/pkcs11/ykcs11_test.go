//go:build hwkey && hwkey_dlopen

package pkcs11_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/hwkey/hwtest"
	"github.com/rhwendt/port49/internal/hwkey/pkcs11"
)

// threads is the process's thread count: the entries of /proc/self/task.
func threads(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Skipf("no /proc/self/task: %v", err)
	}
	return len(ents)
}

// Decision 42 ruling 13's "9c's first task measures it": libykcs11 under
// purego's fakecgo must initialize, list slots and finalize repeatedly
// without a crash, an error but CKR_OK, or a thread leak. It needs no token:
// with pcscd running and no card the slot list is empty.
func TestLibykcs11InitFinalizeUnderPurego(t *testing.T) {
	module := os.Getenv("PORT49_TEST_YKCS11_MODULE")
	if module == "" {
		matches, _ := filepath.Glob("/usr/lib/*/libykcs11.so*")
		if len(matches) > 0 {
			module = matches[0]
		}
	}
	if module == "" {
		hwtest.Missing(t, "libykcs11 is not installed (apt-get install ykcs11)")
	}
	if _, err := os.Stat(module); err != nil {
		hwtest.Missing(t, "libykcs11 module "+module+" is not there")
	}
	// The Go runtime adds a thread once, early (9 to 10, then steady), so a
	// strict "never grows" flaked. A leak in the module grows the count by one
	// or more per round, which over ten rounds is at least 9 from the first
	// round to the last: slack of two catches it and not the runtime (final
	// re-review N5).
	const rounds, slack = 10, 2
	// The last round leaves a finalized Module in the cache.
	t.Cleanup(pkcs11.ResetModules)
	before := threads(t)
	var afterFirst, afterLast int
	for i := 1; i <= rounds; i++ {
		pkcs11.ResetModules()
		m, err := pkcs11.Load(module)
		if err != nil {
			t.Fatalf("round %d: Load: %v", i, err)
		}
		slots, err := pkcs11.SlotList(m)
		if err != nil {
			if strings.Contains(err.Error(), "CKR_DEVICE_ERROR") {
				t.Fatalf("round %d: C_GetSlotList: %v\n"+
					"CKR_DEVICE_ERROR with no token usually means pcscd refused this process: polkit "+
					"(org.debian.pcsc-lite.access_pcsc) answers no to a session that is not an active local one. "+
					"`journalctl -u pcscd` says so. .github/workflows/hwkeys.yml has the CI-only rule and why it "+
					"must not be copied to a developer machine as written.", i, err)
			}
			t.Fatalf("round %d: C_GetSlotList: %v", i, err)
		}
		if rv := pkcs11.Finalize(m); rv != 0 {
			t.Fatalf("round %d: C_Finalize returned 0x%x, want CKR_OK", i, rv)
		}
		n := threads(t)
		t.Logf("round %d: %d slots with a token, %d threads", i, len(slots), n)
		if i == 1 {
			afterFirst = n
		}
		afterLast = n
	}
	t.Logf("threads before the first round %d, after it %d, after the last %d", before, afterFirst, afterLast)
	if afterLast-afterFirst > slack {
		t.Fatalf("the thread count grew across rounds: %d after the first, %d after the last", afterFirst, afterLast)
	}
}
