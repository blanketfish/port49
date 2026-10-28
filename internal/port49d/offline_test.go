package port49d

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/store"
)

// revoke without --offline is port49 revoke's, through the broker API: said,
// exit 2, on both binaries.
func TestARevokeWithoutOfflineNamesTheAPI(t *testing.T) {
	var o, e bytes.Buffer
	if code := offlineRevoke([]string{"--principal", "user:alice@example.com"}, &o, &e); code != 2 ||
		!strings.Contains(e.String(), "use port49 revoke, which asks the broker API with a security key press") {
		t.Fatalf("exit %d: %s", code, e.String())
	}
	o.Reset()
	e.Reset()
	if code := offlineRevokeDaemon([]string{"--principal", "user:alice@example.com"}, &o, &e); code != 2 ||
		!strings.Contains(e.String(), "port49d revoke: this is the break-glass form") {
		t.Fatalf("port49d: exit %d: %s", code, e.String())
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
			"user:a@example.com"}, 1, "with no broker host, write the mark as etcd's root under rv/"},
	} {
		var o, e bytes.Buffer
		if code := offlineRevoke(c.args, &o, &e); code != c.code || !strings.Contains(e.String(), c.says) {
			t.Errorf("%q: exit %d: %s", c.args, code, e.String())
		}
	}
}

// A state directory another user owns is refused in the tool's words: run it
// as the owner, never chown the directory (R1-I-2).
func TestAnOfflineOwnerRefusalNeverAdvisesAChown(t *testing.T) {
	old := offlineOwnerName
	offlineOwnerName = func(uid uint32) string { return map[uint32]string{996: "port49-broker"}[uid] }
	s := offlineOwnerHint(&wrongOwnerError{what: "broker.state_dir /var/lib/port49", uid: 996, euid: 0}).Error()
	if strings.Contains(s, "chown it") || !strings.Contains(s, "run it as the user that owns broker.state_dir (uid 996)") ||
		!strings.Contains(s, "do not chown the directory") {
		t.Fatal(s)
	}
	// the exact line the operator pastes, as port49d's own refusal gives one
	if want := "e.g. sudo -u port49-broker port49-broker revoke --offline ..."; !strings.Contains(s, want) {
		t.Errorf("the refusal lacks %q: %s", want, s)
	}
	// an owner with no name on this host is said by its number, quoted for sudo
	offlineOwnerName = old
	if s := offlineOwnerHint(&wrongOwnerError{what: "x", uid: 4242, euid: 0}).Error(); !strings.Contains(s, "sudo -u '#4242' port49-broker revoke --offline ...") {
		t.Errorf("an unnamed owner: %s", s)
	}
}

// A revocation or lift the store refused says the tool's own words: what
// may have landed, that the same command is safe again, and Ruling 13's
// fallback, never the broker's advice about a port49d that is not here
// (review M-4).
func TestAnOfflineFailureGivesTheToolsOwnAdvice(t *testing.T) {
	for _, lift := range []bool{false, true} {
		// Revoke's own error, as broker.Revoke words it on a failed write.
		s := offlineFailed(lift, fmt.Errorf("broker: the revocation may not have been recorded: a copy already sent "+
			"can still land when the directory answers again, and then stands everywhere, even over a lift made "+
			"meanwhile. Until then this port49d denies what it names, until a lift on this port49d or its "+
			"restart; after the heal check `port49 revoke --list` (%w); cut access another way: remove the "+
			"principal's grants from broker.policy_file (live within two watch intervals), or stop port49d",
			store.ErrUnavailable))
		if strings.Contains(s, "this port49d") || strings.Contains(s, "stop port49d") ||
			!strings.Contains(s, store.ErrUnavailable.Error()) || !strings.HasPrefix(s, offlineSay) ||
			!strings.Contains(s, "the same command is safe to run again") ||
			!strings.Contains(s, "as etcd's root under rv/") {
			t.Errorf("lift %v: %q", lift, s)
		}
	}
}
