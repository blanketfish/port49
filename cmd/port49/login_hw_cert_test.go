//go:build hwkey && hwkey_dlopen && linux

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/clientkey"
	"github.com/rhwendt/port49/internal/hwkey/hwtest"
	"github.com/rhwendt/port49/internal/hwkey/pkcs11"
	"github.com/rhwendt/port49/internal/testpki"
)

// A token that holds the certificate itself needs no --cert: the login takes
// the certificate from the token, the real agent child (started with --cert
// "") does the same, and connects to the broker with it. The login also lets
// go of its own session on the token before the agent starts, so the process
// holds none while the agent logs in (decision 45 ruling 8).
func TestLoginWithTheCertificateOnTheTokenStartsTheAgent(t *testing.T) {
	l := newLabBroker(t, time.Hour)
	ref := tokenWithTheLabKey(t, l)
	raw, err := os.ReadFile(filepath.Join(l.dir, testpki.LabClientCert))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(raw)
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	u, err := pkcs11.ParseURI(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := pkcs11.StoreCertificate(u, cert, []byte(hwtest.SoftHSMUserPIN)); err != nil {
		t.Fatal(err)
	}

	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")

	// Every connection the broker takes comes from the agent child: the login
	// opens none. The sessions this process holds then are the count it must
	// have let go of.
	sessions := make(chan int, 64)
	hook := func() {
		select {
		case sessions <- pkcs11.OpenSessions():
		default:
		}
	}
	l.onAccept.Store(&hook)
	before := pkcs11.OpenSessions()

	prompts, shown := pinPty(t, hwtest.SoftHSMUserPIN)
	var out, errb bytes.Buffer
	code := run(append([]string{"login"}, flagsWithKey(l, sock, ref, true)...), &out, &errb)
	if code != 0 || !strings.Contains(out.String(), "port49: logged in to "+l.url) {
		t.Fatalf("code %d stdout %q stderr %q log %q", code, out.String(), errb.String(), agentLog(sock))
	}
	if prompts.Load() != 1 {
		t.Fatalf("the PIN was asked %d times", prompts.Load())
	}
	st, err := agent.NewClient(sock).Status(t.Context())
	if err != nil || st.KeyState != "present" || st.KeyRef != clientkey.CanonicalRef(ref) ||
		st.CertFingerprint != agent.CertFingerprint(tls.Certificate{Certificate: [][]byte{cert.Raw}}) {
		t.Fatalf("%+v %v", st, err)
	}
	if strings.Contains(shown.String(), hwtest.SoftHSMUserPIN) || strings.Contains(agentLog(sock), hwtest.SoftHSMUserPIN) {
		t.Fatal("the terminal or the agent log holds the PIN")
	}

	close(sessions)
	n := 0
	for held := range sessions {
		n++
		if held != before {
			t.Errorf("this process held %d session(s) on the token when the agent connected, want the %d it held before the login", held, before)
		}
	}
	if n == 0 {
		t.Fatal("the broker saw no connection from the agent")
	}
}
