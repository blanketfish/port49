//go:build lab

package lab

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// funcBody is the text of the Go function that starts with sig, up to the closing brace at column 0.
func funcBody(t *testing.T, src, sig string) string {
	t.Helper()
	i := strings.Index(src, sig)
	if i < 0 {
		t.Fatalf("%s is not in the file", sig)
	}
	j := strings.Index(src[i:], "\n}\n")
	if j < 0 {
		t.Fatalf("%s has no end", sig)
	}
	return src[i : i+j]
}

func readLab(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A command that never started is the harness's fault: l64RunGrace wraps the start error in errL64Start, which
// l64SSHFault reads as INVALID (#48).
func TestL64RunGraceMarksAStartFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _, _, err := l64RunGrace(ctx, time.Second, nil, "", "/nonexistent/port49-lab-binary")
	if !errors.Is(err, errL64Start) {
		t.Fatalf("a missing binary must read as errL64Start: %v", err)
	}
	if l64SSHFault(l64SSHRun{err: err}) == "" {
		t.Fatal("and that is a fault before the device")
	}
}

// portSSH must tell the running cell about a fault before the device: dropping the noteSSH call leaves every
// such run a FAIL.
func TestL64PortSSHReportsItsFault(t *testing.T) {
	body := funcBody(t, readLab(t, "l64_l65_test.go"), "func (e *l64Env) portSSH(")
	if !strings.Contains(body, "e.noteSSH(r)") {
		t.Error("portSSH does not call e.noteSSH(r): a run that never reached the device records FAIL")
	}
}

// Every setup failure of a cell measured nothing: it goes through setupFault (INVALID), never `return false,
// err.Error()` or a prerequisite string (FAIL). replaced() and the L65 cells are pinned here.
func TestL64SetupErrorsGoThroughSetupFault(t *testing.T) {
	src := readLab(t, "l64_l65_test.go")
	body := funcBody(t, src, "func (e *l64Env) replaced(")
	if n := strings.Count(body, "e.setupFault("); n < 3 {
		t.Errorf("replaced() calls setupFault %d times, want its 3 setup errors", n)
	}
	for _, bad := range []string{"return false, err.Error()", `return false, "no entry was filed`, `return false, "L65a recorded`, `return false, "L64a filed`} {
		if strings.Contains(src, bad) {
			t.Errorf("l64_l65_test.go still has %q: a setup error records FAIL, not INVALID", bad)
		}
	}
}

// No cell setup step may end the cell with a bare `return false,` whatever its spelling (err.Error(),
// fmt.Sprint(err), a string): that records FAIL for a cell that measured nothing. L64b's two are deliberate (its
// first sets e.invalid on the line above, its second sets e.reloadFailed); everything after the L64c cell, and
// replaced(), has none.
func TestNoCellEndsInABareFalseBeforeMeasuring(t *testing.T) {
	src := readLab(t, "l64_l65_test.go")
	from, mid, end := strings.Index(src, `e.cell("L64a"`), strings.Index(src, `e.replaced("L64c"`), strings.LastIndex(src, "l64WriteNotes(e, versions)\n}")
	if from < 0 || mid < from || end < mid {
		t.Fatal("the cell region markers moved: update this pin")
	}
	if n := strings.Count(src[from:mid], "return false,"); n != 2 {
		t.Errorf("L64a..L64b hold %d bare `return false,`, want the 2 deliberate ones in L64b", n)
	}
	if n := strings.Count(src[mid:end], "return false,"); n != 0 {
		t.Errorf("the cells after L64b hold %d bare `return false,`: a setup failure must go through e.setupFault", n)
	}
	if n := strings.Count(funcBody(t, src, "func (e *l64Env) replaced("), "return false,"); n != 0 {
		t.Errorf("replaced() holds %d bare `return false,`", n)
	}
}

// L44's AD CS bind names private copies (the file fence refuses in-tree paths): l44_test.go builds no external
// bind from the in-tree broker files.
func TestL44BuildsNoInTreeExternalBind(t *testing.T) {
	src := readLab(t, "l44_test.go")
	if strings.Contains(src, "brokerCertFile") || strings.Contains(src, "brokerKeyFile") {
		t.Error("l44_test.go names the in-tree brokerCertFile/brokerKeyFile: use winCerts.adcsBind")
	}
	if n := strings.Count(src, ".adcsBind(t)"); n != 3 {
		t.Errorf("l44_test.go calls adcsBind %d times, want 3 (l44Binds, l44OR1, l44Matrix)", n)
	}
}

// A broker outage while ssh runs (renew() when the token goes stale) ends port49 ssh with exit 255 after ssh's
// own output: it never measured the device, so it is INVALID too.
func TestL64SSHFaultBrokerOutageMidLogin(t *testing.T) {
	ssh := "debug1: Next authentication method: keyboard-interactive\n"
	for _, msg := range []string{
		"port49: ssh asked for the token 55s after it was minted, past its expires_at (2026-11-10T00:00:00Z), and a fresh mint failed: broker unreachable; the connection was not made\n",
		"port49: could not tell which process asked for the token (pid 4), so it was not sent and the login was refused\n",
	} {
		if l64SSHFault(l64SSHRun{exit: 255, stderr: ssh + msg}) == "" {
			t.Errorf("%q must be a fault before the device", msg)
		}
	}
	if l64SSHFault(l64SSHRun{exit: 255, stderr: ssh + "Host key verification failed.\n"}) != "" {
		t.Error("a refusal by ssh stays a measurement")
	}
}
