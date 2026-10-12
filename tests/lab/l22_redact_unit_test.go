//go:build lab

package lab

import "testing"

// These run without a device: a capture's secrets are removed, and nothing
// else is. A secret word ending its line (Junos's `authentication-order
// password`) once took the next line's `set`, dropping a real statement from
// the L57 fixtures.
func TestRedactConfigCaptureStaysOnItsLine(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"set system authentication-order password\nset system tacplus-server 10.0.0.1 port 49\n",
			"set system authentication-order password\nset system tacplus-server 10.0.0.1 port 49\n"},
		{"set system tacplus-server 10.0.0.1 secret \"$9$abc\"\n",
			"set system tacplus-server 10.0.0.1 secret <removed>\n"},
		{"username admin password 7 0822455D0A16\n", "username admin password 7 <removed>\n"},
		{"snmp-server user u g auth sha 0x1234 priv aes-128 0x5678\n",
			"snmp-server user u g auth sha <removed> priv aes-128 <removed>\n"},
		{"snmp-server user u g auth sha\n0x1234\n", "snmp-server user u g auth sha\n0x1234\n"},
	} {
		if got := redactConfigCapture(c.in); got != c.want {
			t.Errorf("%q:\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}
