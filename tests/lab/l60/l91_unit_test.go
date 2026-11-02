package l60

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The L91 cells' verdicts, with no token and no terminal.

const l91StatusBefore = `roots: from broker 127.0.0.1:41000
module: /usr/lib/x86_64-linux-gnu/libykcs11.so.2 (found)
token: YubiKey PIV #<serial>
ok    session_slot
ok    touch_slot
ok    attestation_roots
ok    session_attested
ok    touch_attested
ok    touch_policy
ok    same_token
FAIL  config_issued_key: not set: run ` + "`port49 hwkey setup`" + `
FAIL  config_touch_key: not set: run ` + "`port49 hwkey setup`" + `
ok    issued_certificate: no certificate yet
ok    certificate_expiry: no certificate yet
ok    agent: no agent running
not ready: run ` + "`port49 hwkey setup`" + `
`

func TestL91VerdictAWantsExit1ConfigFailsAndSlotChecksPass(t *testing.T) {
	good := result{code: 1, stdout: l91StatusBefore}
	if v := l91VerdictA(good); !v.pass {
		t.Fatalf("%v", v)
	}
	for name, r := range map[string]result{
		"exit 0":              {code: 0, stdout: l91StatusBefore},
		"a slot check failed": {code: 1, stdout: strings.Replace(l91StatusBefore, "ok    touch_policy", "FAIL  touch_policy: x", 1)},
		"config check passed": {code: 1, stdout: strings.Replace(l91StatusBefore, "FAIL  config_issued_key", "ok    config_issued_key", 1)},
		"a PIN was asked":     {code: 1, stdout: l91StatusBefore, stderr: "PIN for the token:"},
		"a serial":            {code: 1, stdout: l91StatusBefore + "serial 12345678\n"},
		"a label with serial": {code: 1, stdout: l91StatusBefore + "YubiKey PIV #4242424\n"},
	} {
		if v := l91VerdictA(r); v.pass {
			t.Errorf("%s: passed", name)
		}
	}
}

func TestConfigOnlyTheKeysChanged(t *testing.T) {
	before := "# mine\nbroker: https://b\ntouch_key: old\n\ncert: c\n"
	cases := []struct {
		name, after string
		want        bool
	}{
		{"keys replaced and appended", "# mine\nbroker: https://b\ntouch_key: new\n\ncert: c\nissued_key: k\n", true},
		{"a line changed", "# mine\nbroker: https://other\ntouch_key: new\n\ncert: c\nissued_key: k\n", false},
		{"a line dropped", "# mine\ntouch_key: new\n\ncert: c\nissued_key: k\n", false},
		{"a line added", "# mine\nbroker: https://b\ntouch_key: new\n\ncert: c\nissued_key: k\nbroker_crl: off\n", false},
		{"unchanged", before, true},
	}
	for _, c := range cases {
		if got := configOnlyKeysChanged(before, c.after); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestL91VerdictBNeedsExit0KeysOnlyAndTheSameYkman(t *testing.T) {
	before, after := "broker: b\n", "broker: b\nissued_key: i\ntouch_key: t\n"
	if v := l91VerdictB(result{}, before, after, 1); !v.pass {
		t.Fatalf("%v", v)
	}
	if v := l91VerdictB(result{code: 1}, before, after, 1); v.pass {
		t.Error("exit 1 passed")
	}
	if v := l91VerdictB(result{}, before, "broker: other\n"+after[10:], 1); v.pass {
		t.Error("another line changed and passed")
	}
	if v := l91VerdictB(result{}, before, after, 0); v.pass {
		t.Error("ykman piv info differed and passed")
	}
}

func TestL91VerdictDNeedsTheAgentsTouchKey(t *testing.T) {
	ok := strings.Replace(l91StatusBefore, "ok    agent: no agent running", "ok    agent: touch_key: true", 1)
	ok = strings.ReplaceAll(ok, "FAIL  config_", "ok    config_")
	if v := l91VerdictD(result{code: 0, stdout: ok}); !v.pass {
		t.Fatalf("%v", v)
	}
	if v := l91VerdictD(result{code: 0, stdout: strings.Replace(ok, "touch_key: true", "touch_key: false", 1)}); v.pass {
		t.Error("touch_key false passed")
	}
	if v := l91VerdictD(result{code: 1, stdout: ok}); v.pass {
		t.Error("exit 1 passed")
	}
}

func TestL91VerdictEIsSnakeCaseAndHoldsNoSerialOrPIN(t *testing.T) {
	good := `{"token":"YubiKey PIV #<serial>","roots":"from broker b","ready":true,"checks":[{"name":"session_slot","ok":true,"why":""}]}` + "\n"
	if v := l91VerdictE(result{code: 0, stdout: good}); !v.pass {
		t.Fatalf("%v", v)
	}
	for name, out := range map[string]string{
		"camelCase":  strings.Replace(good, `"ready"`, `"isReady"`, 1),
		"a serial":   strings.Replace(good, "<serial>", "12345678", 1),
		"a PIN word": strings.Replace(good, `"why":""`, `"why":"enter the PIN"`, 1),
		"not JSON":   "roots: x\n" + good,
	} {
		if v := l91VerdictE(result{code: 0, stdout: out}); v.pass {
			t.Errorf("%s: passed", name)
		}
	}
}

func TestTheStopSentinelEndsTheRun(t *testing.T) {
	p := filepath.Join(t.TempDir(), "STOP")
	if stopRequested(p) {
		t.Fatal("no sentinel, and it stops")
	}
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !stopRequested(p) {
		t.Fatal("the sentinel is there, and it does not stop")
	}
}

// Every hwkey call is pinned to an agent socket: a cell that names none gets the
// run's own, where no agent runs, so it never reads Ryan's running agent (whose
// TPM session would take setup and status down their TPM branch).
func TestEveryHwkeyCallPinsItsAgentSocket(t *testing.T) {
	args := l91Args([]string{"status"}, nil, "", "/run/own/agent.sock")
	if _, sock := splitSock(args); sock != "/run/own/agent.sock" {
		t.Errorf("no pinned socket in %q", args)
	}
	args = l91Args([]string{"status", onSock("/run/cell-d.sock")}, nil, "/m/libykcs11.so", "/run/own/agent.sock")
	if rest, sock := splitSock(args); sock != "/run/cell-d.sock" || !strings.Contains(strings.Join(rest, " "), "--module /m/libykcs11.so") {
		t.Errorf("the cell's own socket or the module is lost: %q", args)
	}
}

// `ykman piv info` holds the token's serial: neither the runbook nor the harness has Ryan write
// it to a file (/tmp is shared). They compare it by sha256sum alone.
func TestNoYkmanOutputIsWrittenToAFile(t *testing.T) {
	book, err := os.ReadFile("../L91-runbook.md")
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]string{"the runbook": string(book), "the before step": l91StepBefore, "the after step": l91StepAfter} {
		for _, bad := range []string{"piv info >", "piv info |tee", "piv info | tee", "/tmp/l91", "cmp "} {
			if strings.Contains(s, bad) {
				t.Errorf("%s has %q: ykman output goes to sha256sum, never to a file", name, bad)
			}
		}
		if !strings.Contains(s, "ykman piv info | sha256sum") {
			t.Errorf("%s does not compare by `ykman piv info | sha256sum`", name)
		}
	}
}
