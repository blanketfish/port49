//go:build lab

package lab

import (
	"errors"
	"strings"
	"testing"
)

// TestLoginMeasured runs without a device: only an opened session, or the
// malformed deny's login refused by the device, is a measurement.
func TestLoginMeasured(t *testing.T) {
	rejected := errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain")
	timeout := errors.New(`none of ["> "] appeared on the SSH CLI as alice11 within 1m30s; what it said was:`)
	run := func(err error) junosRun {
		if err == nil {
			return junosRun{}
		}
		return junosRun{loginErr: oneLine(err.Error()), loginRefused: isAuthRejection(err)}
	}
	for _, c := range []struct {
		variant string
		err     error
		want    bool
	}{
		{"deny malformed", nil, true},
		{"deny malformed", rejected, true},
		{"deny malformed", timeout, false},
		{"narrow", nil, true},
		{"narrow", rejected, false},
		{"narrow", timeout, false},
	} {
		if got := loginMeasured(c.variant, run(c.err)); got != c.want {
			t.Errorf("loginMeasured(%q, %v) = %v, want %v", c.variant, c.err, got, c.want)
		}
	}
}

// TestJunosCfgVerdict: the deny reaches configuration mode only where the
// same class without it ran the statement and, under it, ran the sibling.
func TestJunosCfgVerdict(t *testing.T) {
	ran := "\n[edit]\nalice@srx1# "
	refused := "set system\n                  ^\nsyntax error.\n\n[edit]\nalice@srx1# "
	session := func(host, sibling string, auth string) junosRun {
		return junosRun{auth: auth, outs: map[string]string{
			"configure":                         "Entering configuration mode\n\n[edit]\nalice@srx1# ",
			"set system host-name " + junosHost: host,
			"set system services netconf ssh":   sibling,
		}}
	}
	listed := "Deny regular expression: (^set system host-name( .*)?$)"
	for _, c := range []struct {
		name          string
		control, deny junosRun
		want          string
	}{
		{"reached", session(ran, ran, ""), session(refused, ran, listed), "reached"},
		{"not reached", session(ran, ran, ""), session(ran, ran, listed), "not reached"},
		{"class cannot modify [system]", session(refused, refused, ""), session(refused, refused, listed), "not isolated"},
		{"deny refuses the sibling too", session(ran, ran, ""), session(refused, refused, listed), "not isolated"},
		{"deny not listed", session(ran, ran, ""), session(refused, ran, "Deny regular expression: none"), "not isolated"},
		{"no session", session(ran, ran, ""), junosRun{loginErr: "x"}, "not isolated"},
	} {
		if got := junosCfgVerdict(c.control, c.deny); !strings.HasPrefix(got, c.want+":") {
			t.Errorf("%s: junosCfgVerdict = %q, want %q", c.name, got, c.want)
		}
	}
}
