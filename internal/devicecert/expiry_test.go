package devicecert

import (
	"crypto/x509"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

// cert is a certificate valid from issued for life, as Seen reads it.
func cert(issued time.Time, life time.Duration, serial int64) *x509.Certificate {
	return &x509.Certificate{NotBefore: issued, NotAfter: issued.Add(life), SerialNumber: big.NewInt(serial)}
}

func TestExpiryWarnsByFractionOfLifetime(t *testing.T) {
	var lines []string
	e := &Expiry{Fraction: 0.33, Say: func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }}
	now := time.Date(2026, 10, 16, 3, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	late := cert(now.Add(-70*day), 90*day, 0xbeef)  // 20 of 90 days left: past two thirds
	fresh := cert(now.Add(-10*day), 90*day, 1)      // 80 of 90 days left
	daily := cert(now.Add(-15*time.Hour), day, 2)   // 9 of 24h left, before its renewal at 16h
	stalled := cert(now.Add(-20*time.Hour), day, 3) // its renewal at 16h failed: 4 of 24h left
	e.Seen("leaf-07", late, now)
	e.Seen("leaf-07", late, now.Add(time.Hour))
	e.Seen("leaf-08", fresh, now)
	e.Seen("leaf-09", daily, now)
	if len(lines) != 1 || !strings.Contains(lines[0], "leaf-07") || !strings.Contains(lines[0], "beef") {
		t.Fatalf("a 90-day certificate in its last third warns, once; the rest do not: %q", lines)
	}
	e.Seen("leaf-10", stalled, now)
	if len(lines) != 2 || !strings.Contains(lines[1], "leaf-10") {
		t.Fatalf("a 24h certificate whose renewal failed warns: %q", lines)
	}
	e.Seen("leaf-07", late, now.Add(25*time.Hour))
	if len(lines) != 3 {
		t.Fatalf("a day later it is said again: %q", lines)
	}
	at := now.Add(25 * time.Hour)
	if f, ok := e.LeastLeft(at); !ok || f != LifetimeLeft(late, at) {
		t.Fatalf("least left: %v %v, want leaf-07's %v", f, ok, LifetimeLeft(late, at))
	}
	// At +50h leaf-07 was last seen 25h before and the rest 50h before: all
	// are outside the 24h window, so nothing counts.
	if _, ok := e.LeastLeft(now.Add(50 * time.Hour)); ok {
		t.Fatal("nothing was seen in the last 24h")
	}
	off := &Expiry{Say: func(string, ...any) { t.Fatal("expiry_warning_fraction 0 is off") }}
	off.Seen("leaf-07", late, now)
}
