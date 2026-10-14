package main

import (
	"errors"
	"testing"

	"github.com/rhwendt/port49/internal/workload"
)

// A broker certificate the CRL check refused stops the run as broker_refused,
// as Task 5's table codes the agent's own (Task 6 re-review N2); a certificate
// that does not verify stays agent_error, as the IdP proof's does.
func TestAStoppedRunCodesABrokerRefusal(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"crl refused", &workload.BrokerRefusedError{Err: errors.New("revoked")}, failBrokerRefused},
		{"tls", &workload.TLSError{Err: errors.New("unknown authority")}, failAgent},
	} {
		s := stopOf(tc.err, []string{"leaf1"}, nil)
		if s == nil || s.code != tc.want || len(s.left) != 1 {
			t.Errorf("%s: %+v, want %s with leaf1 left", tc.name, s, tc.want)
		}
	}
}
