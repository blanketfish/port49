//go:build lab

package lab

import (
	"os"
	"strings"
	"testing"
)

// L84 runs on a GitHub-hosted runner (.github/workflows/lab-hosted.yml), which has well under L66's 66 GiB
// free on /. Its disk floor is its own, below the hosted runner's free space, and TestL84 uses it at both
// guard sites. L66's floor is untouched for the lab host.
func TestL84DiskFloorFitsAHostedRunner(t *testing.T) {
	const hostedFreeMB = 14 * 1024
	if l84DiskFloorMB <= 0 || l84DiskFloorMB >= hostedFreeMB {
		t.Errorf("l84DiskFloorMB = %d, want above 0 and under a hosted runner's %d", l84DiskFloorMB, hostedFreeMB)
	}
	if l84DiskFloorMB == l66DiskFloorMB || l66DiskFloorMB != 67584 {
		t.Errorf("l84DiskFloorMB %d must differ from l66DiskFloorMB %d, and L66's stays 67584", l84DiskFloorMB, l66DiskFloorMB)
	}
	src, err := os.ReadFile("l84_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(src), "labGuardAt(l66StopSentinel, \"/\", l84DiskFloorMB)"); n != 2 {
		t.Errorf("l84_test.go guards with l84DiskFloorMB %d times, want 2 (TestL84 and the per-cell guard)", n)
	}
	if strings.Contains(string(src), "l66DiskFloorMB") {
		t.Error("l84_test.go still uses l66DiskFloorMB")
	}
}
