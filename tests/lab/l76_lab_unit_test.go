//go:build lab

package lab

import (
	"os"
	"strings"
	"testing"
)

// platformSessionAttributes is lab-tagged, so this test is too. SR Linux runs
// the checked-in reply: cell (b)'s probe b1 logged in with it.
func TestL76RunsTheSharedReply(t *testing.T) {
	if got, ok := platformSessionAttributes[l76PlatformName]; ok {
		t.Fatalf("platformSessionAttributes has an entry for %s: %q", l76PlatformName, got)
	}
	// derivedConfig swaps one line for cell (b)'s probes, so it must exist
	// exactly once in the shared lab policy.
	b, err := os.ReadFile("port49d-lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "\n  session_attributes: "); n != 1 {
		t.Errorf("port49d-lab.yaml has %d session_attributes lines, want 1", n)
	}
}
