package lab

import (
	"errors"
	"strings"
	"testing"
)

const vcsSample = "bin/port49d: go1.26.0\n\tpath\tgithub.com/rhwendt/port49/cmd/port49d\n" +
	"\tbuild\tvcs=git\n\tbuild\tvcs.revision=0123456789abcdef0123456789abcdef01234567\n\tbuild\tvcs.modified=true\n"

func TestBuildVCSReadsRevisionAndModified(t *testing.T) {
	v, err := parseBuildVCS(vcsSample)
	if err != nil || v.Revision != "0123456789abcdef0123456789abcdef01234567" || !v.Modified {
		t.Fatalf("%+v %v", v, err)
	}
	if _, err := parseBuildVCS("bin/port49d: go1.26.0\n\tbuild\tvcs.modified=false\n"); err == nil {
		t.Fatal("no vcs.revision: a binary built with -buildvcs=false is refused")
	}
}

// Review I2: an arm's binary is checked, not taken on trust.
func TestL80ArmBinaryCheck(t *testing.T) {
	head := "1111111111111111111111111111111111111111"
	pre := "2222222222222222222222222222222222222222"
	hasFix := func(rev string) (bool, error) {
		switch rev {
		case head:
			return true, nil
		case pre:
			return false, nil
		}
		return false, errors.New("unknown revision")
	}
	for name, c := range map[string]struct {
		arm     string
		v       buildVCS
		invalid bool
	}{
		"fixed at HEAD, clean":        {"fixed", buildVCS{head, false}, false},
		"fixed at HEAD, modified":     {"fixed", buildVCS{head, true}, true},
		"fixed from an older build":   {"fixed", buildVCS{pre, false}, true},
		"baseline before the fix":     {"baseline", buildVCS{pre, false}, false},
		"baseline that holds the fix": {"baseline", buildVCS{head, false}, true},
		"baseline, unknown revision":  {"baseline", buildVCS{"3333333333333333333333333333333333333333", false}, true},
		"baseline, modified":          {"baseline", buildVCS{pre, true}, true},
	} {
		err := l80ArmCheck(c.arm, c.v, head, hasFix)
		if (err != nil) != c.invalid {
			t.Errorf("%s: %v, want invalid %v", name, err, c.invalid)
		}
		if err != nil && !strings.HasPrefix(err.Error(), "INVALID: ") {
			t.Errorf("%s: %v does not say INVALID", name, err)
		}
	}
}

// The qual run's offer comes from the binary's own revision: anything but
// the harness tree's clean HEAD is INVALID, since the table could differ.
func TestQualBinaryMatchesTheTree(t *testing.T) {
	head := "1111111111111111111111111111111111111111"
	if err := qualBinaryCheck(buildVCS{head, false}, head); err != nil {
		t.Fatal(err)
	}
	for _, v := range []buildVCS{{head, true}, {"2222222222222222222222222222222222222222", false}} {
		if err := qualBinaryCheck(v, head); err == nil || !strings.HasPrefix(err.Error(), "INVALID: ") {
			t.Errorf("%+v: %v", v, err)
		}
	}
}
