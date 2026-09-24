package policy

import "testing"

// Spec §5.5's table, row by row, plus the cases that make the comparator
// refuse rather than guess.
func TestCompareVersions(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		want int
		ok   bool
	}{
		{"21.4R2-S9", "21.4R3", -1, true},    // position 3: 2 < 3
		{"21.4R3-S5", "21.4R3", 1, true},     // a service release is newer, not a pre-release
		{"21.4R3-S4", "21.4R3-S5", -1, true}, // the §11 mitigation's boundary
		{"4.31.2F", "4.31.10F", -1, true},    // numeric, not lexical
		{"17.09.04a", "17.09.04", 1, true},   // the shorter is lower: the rebuild is newer
		{"4.31.5M", "4.31.2F", 1, true},      // decided at position 2; the letters never meet
		{"10.2(5a)", "10.2(5a)", 0, true},
		{"4.31.2f", "4.31.2F", 0, true}, // letters are upper-cased
		{"15.2(4)E10", "15.2(4)S10", 0, false},
		{"4.31.2F", "4.31.2M", 0, false}, // letters compare by equality only
		{"21.4X75-D40", "21.4R3-S5", 0, false},
		{"unknown", "21.4R3-S5", 0, false},
		{"", "21.4R3-S5", 0, false},
		{"21.4R3-S5", "21.4R3.5", 0, false}, // a letter run against a digit run
		{"99999999999999999999999.1", "99999999999999999999999.2", -1, true},
		{"007", "7", 0, true},
		{"-.-", "21.4R3-S5", 0, false},   // separators only: nothing to compare
		{"２１.4", "22.1", 0, false},       // a fullwidth digit is not read, nor dropped
		{"21.4R3+1", "21.4R3", 0, false}, // `+` is not a §5.5 separator
		{"21.4R3 ", "21.4R3", 0, false},  // nor is a space
		{"21.4", "21.4R3-S5", -1, true},  // a truncated version is ordered by the prefix rule, not refused
	} {
		got, ok := CompareVersions(tt.a, tt.b)
		if got != tt.want || ok != tt.ok {
			t.Errorf("CompareVersions(%q, %q) = %d %v, want %d %v", tt.a, tt.b, got, ok, tt.want, tt.ok)
		}
	}
}
