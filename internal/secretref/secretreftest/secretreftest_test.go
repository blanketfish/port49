package secretreftest

import "testing"

// A secret shorter than the prefixes Forms cuts is still spelled out whole.
func TestFormsTakeASecretShorterThanItsPrefixes(t *testing.T) {
	for _, secret := range []string{"", "a", "abc", "abcde"} {
		if got := Forms([]byte(secret)); len(got) == 0 {
			t.Errorf("%d-byte secret: no forms", len(secret))
		}
	}
}
