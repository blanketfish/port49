package workload

import (
	"strings"

	"github.com/blanketfish/port49/internal/printsafe"
)

// safeNames is device names the broker sent, as one line a terminal or a cron
// mail may show: each name is the broker's text, and untrusted.
func safeNames(devices []string) string {
	names := make([]string, len(devices))
	for i, d := range devices {
		names[i] = printsafe.Line(d, 128)
	}
	return strings.Join(names, ", ")
}
