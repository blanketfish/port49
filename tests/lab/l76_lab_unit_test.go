//go:build lab

package lab

import (
	"os"
	"strings"
	"testing"
)

// platformSessionAttributes is lab-tagged, so this test is too.
func TestL76StandingReplyIsPrivLvlAlone(t *testing.T) {
	if got := platformSessionAttributes[l76PlatformName]; got != `["priv-lvl=15"]` {
		t.Fatalf("platformSessionAttributes[%s] = %q", l76PlatformName, got)
	}
	// derivedConfig swaps this one line, so it must exist exactly once in the
	// shared lab policy, or the run would measure the wrong reply.
	b, err := os.ReadFile("port49d-lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "\n  session_attributes: "); n != 1 {
		t.Errorf("port49d-lab.yaml has %d session_attributes lines, want 1", n)
	}
}
