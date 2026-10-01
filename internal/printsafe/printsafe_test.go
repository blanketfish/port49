package printsafe

import "testing"

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
