//go:build lab

package lab

import (
	"errors"
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
