package port49d

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/store"
)

// revoke without --offline is port49 revoke's, on the admin socket: said,
// exit 2.
func TestARevokeWithoutOfflineNamesTheSocket(t *testing.T) {
	var o, e bytes.Buffer
	if code := offlineRevoke([]string{"--principal", "user:alice@example.com"}, &o, &e); code != 2 ||
		!strings.Contains(e.String(), "port49 revoke --socket") {
		t.Fatalf("exit %d: %s", code, e.String())
	}
}

// The offline revocation names one principal or one certificate, and a
// config that does not load is exit 1, before anything opens the store.
func TestAnOfflineRevokeRefusesWhatItCannotRun(t *testing.T) {
	for _, c := range []struct {
		args []string
		code int
		says string
	}{
		{[]string{"--offline", "--config", "/nonexistent"}, 2, "name --principal, or --cert-issuer and --cert-serial"},
		{[]string{"--offline", "--config", "/nonexistent", "--principal", "user:a@example.com", "--cert-serial", "1"},
			2, "name --principal, or --cert-issuer and --cert-serial"},
		{[]string{"--offline", "--config", "/nonexistent", "extra"}, 2, "usage: port49-broker revoke --offline"},
		{[]string{"--offline", "--config", filepath.Join(t.TempDir(), "absent.yaml"), "--principal",
			"user:a@example.com"}, 1, "port49-broker: revoke (offline, no API): "},
	} {
		var o, e bytes.Buffer
		if code := offlineRevoke(c.args, &o, &e); code != c.code || !strings.Contains(e.String(), c.says) {
			t.Errorf("%q: exit %d: %s", c.args, code, e.String())
		}
	}
}

// A revocation or lift the store refused says the tool's own words: what
// may have landed, that the same command is safe again, and Ruling 13's
// fallback, never the broker's advice about a port49d that is not here
// (review M-4).
func TestAnOfflineFailureGivesTheToolsOwnAdvice(t *testing.T) {
	for _, lift := range []bool{false, true} {
		// Revoke's own error, as broker.Revoke words it on a failed write.
		s := offlineFailed(lift, fmt.Errorf("broker: the revocation could not be recorded, so nothing else was "+
			"revoked; this port49d denies what it names until a lift on this port49d or its restart (%w); cut "+
			"access another way: remove the principal's grants from broker.policy_file (live within two watch "+
			"intervals), or stop port49d", store.ErrUnavailable))
		if strings.Contains(s, "this port49d") || strings.Contains(s, "stop port49d") ||
			!strings.Contains(s, store.ErrUnavailable.Error()) || !strings.HasPrefix(s, offlineSay) ||
			!strings.Contains(s, "the same command is safe to run again") ||
			!strings.Contains(s, "as etcd's root under rv/") {
			t.Errorf("lift %v: %q", lift, s)
		}
	}
}
