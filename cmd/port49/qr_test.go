package main

import (
	"strings"
	"testing"
)

// The code is drawn two modules a character, with a four-module quiet zone,
// and the same input draws the same lines.
func TestQRTextIsSquareWithAQuietZone(t *testing.T) {
	uri := "otpauth://totp/port49:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	a, err := qrText(uri)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := qrText(uri)
	lines := strings.Split(strings.TrimRight(a, "\n"), "\n")
	w := len([]rune(lines[0]))
	if a != b || w < 29 || len(lines) != (w+1)/2 {
		t.Fatalf("width %d, %d lines", w, len(lines))
	}
	for _, l := range lines {
		if len([]rune(l)) != w {
			t.Fatal("ragged")
		}
	}
	// The quiet zone: the first two lines are light (spaces) in full.
	if strings.TrimSpace(lines[0]) != "" || strings.TrimSpace(lines[1]) != "" {
		t.Fatal("no quiet zone")
	}
}
