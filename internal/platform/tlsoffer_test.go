package platform

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The offer is cisco_nxos's alone, and each entry cites the note that
// measured it: the L80 re-measure, which names ruling 20 and its committed
// before-the-fix baseline. The pre-fix L80 note carries neither string, so
// an entry citing it, or a file that merely exists, does not pass.
func TestTLSServerSingleConnectIsMeasuredNXOSOnly(t *testing.T) {
	var names []string
	for _, v := range Sets() {
		set, _ := Set(v)
		for name := range set {
			if !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	for _, name := range append(names, "", "nokia_srlinux", "cisco_iosxr", "whitebox_nos") {
		if got, want := TLSServerSingleConnect(name), name == "cisco_nxos"; got != want {
			t.Errorf("TLSServerSingleConnect(%q) = %v, want %v", name, got, want)
		}
	}
	for name, note := range tlsServerSingleConnect {
		if !strings.HasPrefix(note, "tests/lab/results/") || !strings.HasSuffix(note, ".md") {
			t.Errorf("%s cites %q, not a tests/lab/results/ note", name, note)
			continue
		}
		raw, err := os.ReadFile(filepath.Join("..", "..", note))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		for _, want := range []string{"decision 50 ruling 20", "tests/lab/evidence/L80-" + name + "/baseline/"} {
			if !strings.Contains(string(raw), want) {
				t.Errorf("%s cites %s, which does not say %q: it is not the re-measured note", name, note, want)
			}
		}
	}
}
