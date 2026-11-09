package printsafe

import (
	"strings"
	"testing"
)

func TestALineIsOneLineOfPrintableText(t *testing.T) {
	for _, c := range []struct {
		in    string
		limit int
		want  string
	}{
		{"leaf-01", 64, "leaf-01"},
		{"a\nforged: line", 64, "a?forged: line"},
		{"\x1b[31mred", 64, "?[31mred"},
		{"bidi‮override", 64, "bidi?override"},
		{"sep line para", 64, "sep?line?para"},
		{"bad\xffbyte", 64, "bad?byte"},
		{"abcdef", 4, "abcd…"},
		{"abcd", 4, "abcd"},
	} {
		if got := Line(c.in, c.limit); got != c.want {
			t.Errorf("Line(%q, %d) = %q, want %q", c.in, c.limit, got, c.want)
		}
	}
}

// Tail keeps the end: a path past the limit keeps its file name.
func TestTailKeepsTheEnd(t *testing.T) {
	if got := Tail("/a/b/enrollments.json", 64); got != "/a/b/enrollments.json" {
		t.Fatalf("short: %q", got)
	}
	got := Tail("/"+strings.Repeat("d", 200)+"/enrollments.json", 32)
	if !strings.HasPrefix(got, "…") || !strings.HasSuffix(got, "/enrollments.json") || len(got) > 32+len("…") {
		t.Fatalf("long: %q", got)
	}
	if got := Tail("x\x1b[2J/f", 64); strings.ContainsRune(got, '\x1b') {
		t.Fatalf("a control byte: %q", got)
	}
}
