//go:build hwkey && hwkey_dlopen && linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/hwkey/hwtest"
	"github.com/rhwendt/port49/internal/hwkey/pkcs11"
)

// refWithPINSource is ref with a pin-source file holding pin.
func refWithPINSource(t *testing.T, ref, pin string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pin")
	if err := os.WriteFile(p, []byte(pin+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return ref + "&pin-source=file://" + p
}

// A pin-source key on a token that reports few PIN tries left: with a
// terminal `port49 login` asks the PIN there, instead of reading the file, and
// the typed success is what clears the token's flag; without one it refuses,
// sends no PIN, and says what a person does (final re-review N1). The file
// here holds a wrong PIN: were it read, the login would fail.
func TestLoginAsksATerminalWhenTheTokenReportsTriesLow(t *testing.T) {
	l := newLabBroker(t, time.Hour)
	ref := refWithPINSource(t, tokenWithTheLabKey(t, l), "000000")
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	t.Cleanup(pkcs11.PINTriesLow(false))

	// No terminal: refused, nothing sent, nothing asked.
	old := loginStdinIsTerminal
	t.Cleanup(func() { loginStdinIsTerminal = old })
	loginStdinIsTerminal = func() bool { return false }
	prompts, _ := pinPty(t, hwtest.SoftHSMUserPIN)
	logins := pkcs11.LoginCalls()
	var out, errb bytes.Buffer
	code := run(append([]string{"login"}, flagsWithKey(l, sock, ref, false)...), &out, &errb)
	if code == 0 || !strings.Contains(errb.String(), "will not spend one unattended") {
		t.Fatalf("no terminal: code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	if n := pkcs11.LoginCalls() - logins; n != 0 || prompts.Load() != 0 {
		t.Fatalf("no terminal: %d C_Login calls and %d prompts, want 0 and 0", n, prompts.Load())
	}
	if _, err := agent.NewClient(sock).Status(t.Context()); err == nil {
		t.Fatal("an agent started with no terminal")
	}

	// A terminal: the PIN is typed, once, and the file is not read.
	loginStdinIsTerminal = func() bool { return true }
	prompts, shown := pinPty(t, hwtest.SoftHSMUserPIN)
	logins = pkcs11.LoginCalls()
	out.Reset()
	errb.Reset()
	code = run(append([]string{"login"}, flagsWithKey(l, sock, ref, false)...), &out, &errb)
	if code != 0 || !strings.Contains(out.String(), "port49: logged in to "+l.url) {
		t.Fatalf("a terminal: code %d stdout %q stderr %q log %q", code, out.String(), errb.String(), agentLog(sock))
	}
	if n := pkcs11.LoginCalls() - logins; n != 1 || prompts.Load() != 1 {
		t.Fatalf("a terminal: %d C_Login calls and %d prompts, want 1 and 1", n, prompts.Load())
	}
	for name, s := range map[string]string{"stdout": out.String(), "stderr": errb.String(), "terminal": shown.String(),
		"agent log": agentLog(sock)} {
		if strings.Contains(s, hwtest.SoftHSMUserPIN) || strings.Contains(s, "000000") {
			t.Fatalf("%s holds a PIN: %q", name, s)
		}
	}
}
