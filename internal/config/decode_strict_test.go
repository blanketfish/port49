package config

import (
	"strings"
	"testing"
)

// DecodeStrict and DecodeStrictBroker run the same checks as Load and LoadBroker, from one function,
// so a docs example is refused for what a real start refuses.
func TestDecodeStrictRefusesWhatLoadRefuses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		daemon string // a fragment of the daemon's refusal, "" if accepted
		broker string // the same under the broker's role
	}{
		{"empty tls_listener", "tls_listener:\n", "tls_listener is empty", "tls_listener"},
		{"admin_socket", "admin_socket: /run/x\n", "admin_socket", "admin_socket"},
		{"receipt_ttl", "receipt_ttl: 1h\n", "receipt_ttl was replaced", "receipt_ttl was replaced"},
		{"broker listen under the broker", "listen: \":49\"\n", "", "listen"},
		{"state_dir under the daemon", "broker:\n  state_dir: /x\n", "broker.state_dir is port49-broker.yaml's", ""},
		{"a second document", "listen: \":49\"\n---\nlisten: \":50\"\n", "one document", "one document"},
		{"an unknown key", "no_such_key: 1\n", "unknown field", "unknown field"},
	} {
		for _, role := range []struct {
			name string
			want string
			fn   func([]byte) error
		}{{"daemon", tc.daemon, DecodeStrict}, {"broker", tc.broker, DecodeStrictBroker}} {
			err := role.fn([]byte(tc.body))
			switch {
			case role.want == "" && err != nil:
				t.Errorf("%s under the %s role: refused: %v", tc.name, role.name, err)
			case role.want != "" && err == nil:
				t.Errorf("%s under the %s role: accepted", tc.name, role.name)
			case role.want != "" && !strings.Contains(err.Error(), role.want):
				t.Errorf("%s under the %s role: error %q lacks %q", tc.name, role.name, err, role.want)
			}
		}
	}
}
