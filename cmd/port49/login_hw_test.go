//go:build hwkey && hwkey_dlopen && linux

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/agent"
	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/clientkey"
	"github.com/blanketfish/port49/internal/hwkey"
	"github.com/blanketfish/port49/internal/hwkey/hwtest"
	"github.com/blanketfish/port49/internal/hwkey/pkcs11"
	"github.com/blanketfish/port49/internal/testpki"
)

// tokenWithTheLabKey is a SoftHSM token holding the lab client's key, so the
// lab certificate (client.pem) is the token key's own, and the reference that
// picks it.
func tokenWithTheLabKey(t *testing.T, l *labBroker) (ref string) {
	t.Helper()
	module, label := hwtest.SoftHSMBare(t)
	raw, err := os.ReadFile(filepath.Join(l.dir, testpki.LabClientKey))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(raw)
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	hwtest.SoftHSMImport(t, label, k.(*ecdsa.PrivateKey))
	return "pkcs11:token=" + label + ";id=%01?module-path=" + module
}

// flagsWithKey is l's flags with --key replaced by ref; noCert drops --cert,
// so the certificate would come from the token.
func flagsWithKey(t *testing.T, l *labBroker, sock, ref string, noCert bool) []string {
	in := l.flags(t, sock)
	var out []string
	for i := 0; i < len(in); i++ {
		switch {
		case in[i] == "--key":
			out = append(out, "--key", ref)
			i++
		case in[i] == "--cert" && noCert:
			i++
		default:
			out = append(out, in[i])
		}
	}
	return out
}

// pinPty makes the PIN prompt's terminal a pty, and types each of pins at the
// prompts it sees, one per prompt. prompts counts them; everything the prompt
// wrote is in the returned buffer once the login ends.
func pinPty(t *testing.T, pins ...string) (prompts *atomic.Int32, shown *lockedBuffer) {
	t.Helper()
	m, s := openPty(t)
	old := pinTerminal
	pinTerminal = func() (*os.File, error) { return os.OpenFile(s.Name(), os.O_RDWR|syscall.O_NOCTTY, 0) }
	t.Cleanup(func() { pinTerminal = old })
	prompts, shown = new(atomic.Int32), &lockedBuffer{}
	go func() {
		buf := make([]byte, 256)
		for {
			n, err := m.Read(buf)
			if n > 0 {
				_, _ = shown.Write(buf[:n])
				if strings.Contains(string(buf[:n]), "PIN for ") {
					i := int(prompts.Add(1)) - 1
					// A person types after the prompt is up and echo is off.
					time.Sleep(200 * time.Millisecond)
					if i < len(pins) {
						_, _ = io.WriteString(m, pins[i]+"\n")
					}
				}
			}
			if err != nil {
				return
			}
		}
	}()
	return prompts, shown
}

// A reference key in the login: the PIN is asked once on the terminal, the
// token sees one C_Login, the agent gets the PIN on a descriptor and starts,
// and a refresh follows. A wrong PIN exits 1 saying so, sends no second
// C_Login, starts nothing and prints no PIN.
func TestLoginAsksThePINOnceAndSaysTriesLeft(t *testing.T) {
	l := newLabBroker(t, time.Hour)
	ref := tokenWithTheLabKey(t, l)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")

	// A wrong PIN first.
	prompts, shown := pinPty(t, "000000")
	logins := pkcs11.LoginCalls()
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, flagsWithKey(t, l, sock, ref, false)...), &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "the token refused the PIN") {
		t.Fatalf("a wrong PIN: code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	if n := pkcs11.LoginCalls() - logins; n != 1 || prompts.Load() != 1 {
		t.Fatalf("a wrong PIN made %d C_Login calls and %d prompts, want 1 and 1", n, prompts.Load())
	}
	if _, err := agent.NewClient(sock).Status(t.Context()); err == nil {
		t.Fatal("an agent started on a refused PIN")
	}
	for name, s := range map[string]string{"stdout": out.String(), "stderr": errb.String(), "terminal": shown.String()} {
		if strings.Contains(s, "000000") || strings.Contains(s, hwtest.SoftHSMUserPIN) {
			t.Fatalf("%s holds a PIN: %q", name, s)
		}
	}

	// Then the right one.
	prompts, shown = pinPty(t, hwtest.SoftHSMUserPIN)
	out.Reset()
	errb.Reset()
	if code := run(append([]string{"login"}, flagsWithKey(t, l, sock, ref, false)...), &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "port49: logged in to "+l.url) || !strings.Contains(out.String(), "\nrefreshed at ") {
		t.Fatalf("code %d stdout %q stderr %q log %q", code, out.String(), errb.String(), agentLog(sock))
	}
	if prompts.Load() != 1 {
		t.Fatalf("the PIN was asked %d times", prompts.Load())
	}
	for name, s := range map[string]string{"stdout": out.String(), "stderr": errb.String(), "terminal": shown.String(),
		"agent log": agentLog(sock)} {
		if strings.Contains(s, hwtest.SoftHSMUserPIN) {
			t.Fatalf("%s holds the PIN: %q", name, s)
		}
	}
	st, err := agent.NewClient(sock).Status(t.Context())
	if err != nil || st.KeyState != "present" || st.KeyRef != clientkey.CanonicalRef(ref) {
		t.Fatalf("%+v %v", st, err)
	}
}

// heldAgent is an agent socket that answers as one logged in to l with the
// key at ref in the given state, recording what it was asked.
type heldAgent struct {
	mu      sync.Mutex
	state   string
	pins    int
	refresh int
}

func serveHeldAgent(t *testing.T, l *labBroker, sock, ref, fingerprint, state string) *heldAgent {
	t.Helper()
	h := &heldAgent{state: state}
	ln, err := agent.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		defer h.mu.Unlock()
		_ = json.NewEncoder(w).Encode(agent.Status{Broker: l.url, CertFingerprint: fingerprint,
			SessionEndsAt: "2099-01-01T00:00:00Z", KeyState: h.state, KeyRef: clientkey.CanonicalRef(ref)})
	})
	mux.HandleFunc("POST /unlock", func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.pins++
		h.state = hwkey.Present.String()
		h.mu.Unlock()
		_, _ = w.Write([]byte("{}"))
	})
	mux.HandleFunc("POST /refresh", func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.refresh++
		h.mu.Unlock()
		_ = json.NewEncoder(w).Encode(api.RefreshResponse{SessionEndsAt: "2099-01-01T00:00:00Z"})
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return h
}

// A login while the agent holds this login's key never opens the token
// (pre-flight I15): with the key reported absent it says to insert it and
// exits 1; reported locked it asks the PIN and calls Client.Unlock.
func TestLoginWithTheKeyOutReachesTheAgent(t *testing.T) {
	l := newLabBroker(t, time.Hour)
	ref := "pkcs11:token=held;id=%01?module-path=/nonexistent/module.so"
	fp, err := certFileFingerprint(filepath.Join(l.dir, testpki.LabClientCert))
	if err != nil {
		t.Fatal(err)
	}
	sock := privateSocket(t)
	h := serveHeldAgent(t, l, sock, ref, fp, "absent")
	opens, logins := pkcs11.OpenCalls(), pkcs11.LoginCalls()
	var out, errb bytes.Buffer
	code := run(append([]string{"login"}, flagsWithKey(t, l, sock, ref, false)...), &out, &errb)
	if code != 1 || !strings.Contains(errb.String(), "insert your key and run `port49 login` again; your session goes on until 2099-01-01T00:00:00Z") {
		t.Fatalf("absent: code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	if pkcs11.OpenCalls() != opens || pkcs11.LoginCalls() != logins {
		t.Fatal("the login opened the token though the agent held the key")
	}

	// Locked: the PIN is asked, Unlock called, the refresh follows. The
	// certificate comes from the token here, so the agent's key_ref decides.
	h.mu.Lock()
	h.state = "locked"
	h.mu.Unlock()
	prompts, _ := pinPty(t, hwtest.SoftHSMUserPIN)
	out.Reset()
	errb.Reset()
	code = run(append([]string{"login"}, flagsWithKey(t, l, sock, ref, true)...), &out, &errb)
	h.mu.Lock()
	defer h.mu.Unlock()
	if code != 0 || prompts.Load() != 1 || h.pins != 1 || h.refresh != 1 {
		t.Fatalf("locked: code %d prompts %d unlocks %d refreshes %d stdout %q stderr %q",
			code, prompts.Load(), h.pins, h.refresh, out.String(), errb.String())
	}
	if pkcs11.OpenCalls() != opens || pkcs11.LoginCalls() != logins {
		t.Fatal("the login opened the token though the agent held the key")
	}
}
