//go:build lab

package lab

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestL73OpenRetriesOnlyAResetOrEOFHandshake(t *testing.T) {
	reset := errors.New("ssh: handshake failed: read tcp 172.100.100.1:39942->172.100.100.61:22: read: connection reset by peer")
	eof := errors.New("ssh: handshake failed: EOF")
	auth := errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain")

	var slept []time.Duration
	sleep := func(d time.Duration) { slept = append(slept, d) }
	calls := 0
	open := func(errs ...error) func() (*cliConn, error) {
		calls = 0
		return func() (*cliConn, error) {
			calls++
			if calls <= len(errs) {
				return nil, errs[calls-1]
			}
			return &cliConn{name: "ok"}, nil
		}
	}

	c, err := l73OpenRetrying(open(reset, eof), 6, 10*time.Second, sleep)
	if err != nil || c == nil || calls != 3 || len(slept) != 2 || slept[0] != 10*time.Second {
		t.Fatalf("reset then EOF then ok: %v calls %d slept %v", err, calls, slept)
	}

	slept = nil
	if _, err := l73OpenRetrying(open(auth), 6, 10*time.Second, sleep); err == nil || calls != 1 || len(slept) != 0 {
		t.Fatalf("an authentication error is never retried: %v calls %d slept %v", err, calls, slept)
	}

	// All six tries reset: every try's error is reported.
	slept = nil
	all := []error{reset, reset, reset, reset, reset, errors.New("ssh: handshake failed: read: connection reset by peer (sixth)")}
	_, err = l73OpenRetrying(open(all...), 6, 10*time.Second, sleep)
	if err == nil || calls != 6 || len(slept) != 5 || strings.Count(err.Error(), "try ") != 6 || !strings.Contains(err.Error(), "(sixth)") {
		t.Fatalf("%v calls %d slept %d", err, calls, len(slept))
	}
}
