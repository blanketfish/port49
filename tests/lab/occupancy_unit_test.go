//go:build lab

package lab

import (
	"path/filepath"
	"strings"
	"testing"
)

// A second taker is refused while the first holds the lock, is told who
// holds it, and gets it once the first lets go.
func TestLabOccupyIsExclusive(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lab.lock")
	release, err := labOccupy(p, "first run")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := labOccupy(p, "second run"); err == nil || !strings.Contains(err.Error(), "first run") {
		t.Fatalf("a second taker got %v, want a refusal naming the holder", err)
	}
	release()
	again, err := labOccupy(p, "second run")
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	again()
}

// A run's lock outlives the test that took it: it is let go only by
// labRelease, which TestMain calls after teardown. Taking it twice in one
// process is a no-op, so every subtest of a run can ask.
func TestLabOccupyForRunHoldsUntilReleased(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lab.lock")
	if err := labOccupyForRun(p, "this run"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(labRelease)
	if err := labOccupyForRun(p, "this run again"); err != nil {
		t.Fatalf("a second take in the same run: %v", err)
	}
	if _, err := labOccupy(p, "another run"); err == nil || !strings.Contains(err.Error(), "this run") {
		t.Fatalf("another taker got %v, want a refusal naming this run", err)
	}
	labRelease()
	again, err := labOccupy(p, "another run")
	if err != nil {
		t.Fatalf("after labRelease: %v", err)
	}
	again()
}
