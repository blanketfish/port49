package port49d

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
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
