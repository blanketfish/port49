package config

import (
	"os"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/admission"
)

// TestCheckedInYAMLLoadsUnderStrictMode guards the configuration files this
// repository ships. The loaders refuse unknown keys, so a key that goes stale
// -- renamed in the schema, left behind in a lab file -- becomes a start-time
// failure, and without this test the thing that discovers it is a lab run on
// hardware. Paths are resolved from the repository root because
// port49d-lab.yaml names its inventory relative to it, as the daemon is run.
func TestCheckedInYAMLLoadsUnderStrictMode(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir("../.."); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(wd) })
	t.Setenv("PORT49_LAB_KEY", "labkey")
	t.Setenv("PORT49_LAB_ENC_KEY", strings.Repeat("k", 32))
	if _, err := Load("tests/lab/port49d-lab.yaml"); err != nil {
		t.Fatalf("tests/lab/port49d-lab.yaml: %v", err)
	}
	for _, p := range []string{
		"tests/lab/inventory-lab.yaml",
		"tests/lab/inventory-loopback.yaml",
		"internal/admission/testdata/inventory.yaml",
	} {
		if _, err := admission.LoadFile(p); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
}
