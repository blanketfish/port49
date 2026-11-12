package port49d

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// The watch says a broker clock running ahead once per window, with the
// skew first seen in it, and again in the next window: a login storm does
// not fill the log, and a skew that persists is not forgotten.
func TestTheSkewWatchSaysOncePerWindow(t *testing.T) {
	var out bytes.Buffer
	now := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	w := newSkewWatch(&out, func() time.Time { return now }, "port49d")
	w.Ahead(8 * time.Second)
	w.Ahead(12 * time.Second)
	now = now.Add(skewWindow - time.Second)
	w.Ahead(9 * time.Second)
	if got := strings.Count(out.String(), "\n"); got != 1 {
		t.Fatalf("%d lines inside the window, want 1: %q", got, out.String())
	}
	if !strings.Contains(out.String(), "8s ahead") || !strings.Contains(out.String(), "NTP") {
		t.Fatalf("the line names the skew and the remedy: %q", out.String())
	}
	now = now.Add(2 * time.Second)
	w.Ahead(30 * time.Second)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[1], "30s ahead") {
		t.Fatalf("a line in the next window: %q", out.String())
	}
}
