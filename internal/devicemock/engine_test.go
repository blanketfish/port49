package devicemock

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
)

func freshCredential(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 24)
	rand.Read(b)
	return []byte(hex.EncodeToString(b))
}

func playFake(t *testing.T, profile string, f *fake, scenario string, cred []byte) (Transcript, error) {
	t.Helper()
	p, err := Load("testdata/profiles/"+profile, root)
	if err != nil {
		t.Fatal(err)
	}
	return Play(t.Context(), p, scenario, Target{Addr: f.ln.Addr().String(), Transport: "tcp", Key: f.key, Scale: 1},
		Login{User: "q", Credential: cred, RemAddr: "198.51.100.4"})
}

func TestTokenLoginPlaysEveryStepOneConnectionEach(t *testing.T) {
	f := newFake(t, []byte("fresh-key"))
	f.authen = []uint8{wire.AuthenStatusPass}
	f.authorArgs = [][]byte{[]byte("local-user-name=p49-ro")}
	tr, err := playFake(t, "fixture_plain.yaml", f, "token_login", freshCredential(t))
	if err != nil {
		t.Fatal(err)
	}
	if tr.Outcome != "login_ok" || len(tr.Steps) != 3 || tr.Conns != 3 || f.conns.Load() != 3 {
		t.Fatalf("%s", tr)
	}
}

func TestAGatedViolationEndsThePlayBeforeAnyReaction(t *testing.T) {
	f := newFake(t, []byte("fresh-key"))
	f.authen = []uint8{wire.AuthenStatusPass}
	f.authorArgs = longArgs()
	tr, err := playFake(t, "fixture_junos.yaml", f, "token_login", freshCredential(t))
	if err != nil || len(tr.Gate) != 1 || tr.Outcome != "rejected_by_device" {
		t.Fatalf("the device would lock the user out; the play says so: %v\n%s", err, tr)
	}
}

func TestAnUnmeasuredViolationWarnsAndTheLoginStillSucceeds(t *testing.T) {
	f := newFake(t, []byte("fresh-key"))
	f.authen = []uint8{wire.AuthenStatusPass}
	f.authorArgs = longArgs()
	p, _ := Load("testdata/profiles/fixture_junos.yaml", root)
	p.Acceptance[0].Status = "unmeasured"
	tr, err := Play(t.Context(), p, "token_login", Target{Addr: f.ln.Addr().String(), Transport: "tcp", Key: f.key, Scale: 1},
		Login{User: "q", Credential: freshCredential(t)})
	if err != nil || len(tr.Gate) != 0 || len(tr.Warn) != 1 || tr.Outcome != "login_ok" {
		t.Fatalf("%v\n%s", err, tr)
	}
}

func TestTranscriptNeverHoldsTheCredential(t *testing.T) {
	f := newFake(t, []byte("distinctive-shared-key-77"))
	f.authen, f.echo = []uint8{wire.AuthenStatusFail}, true
	cred := freshCredential(t)
	tr, err := playFake(t, "fixture_plain.yaml", f, "token_login", cred)
	all := tr.String() + fmt.Sprint(err) + fmt.Sprintf("%+v %#v", tr, tr)
	if strings.Contains(all, string(cred)) {
		t.Fatal("the credential reached the transcript or its error")
	}
	if strings.Contains(all, string(f.key)) {
		t.Fatal("the key reached the transcript or its error")
	}
	if len(tr.Steps) == 0 || tr.Steps[0].ServerMsgLen == 0 {
		t.Fatal("the echoed server_msg is measured by its length")
	}
}

func TestNoSecretReachesAnErrorEither(t *testing.T) {
	f := newFake(t, []byte("distinctive-shared-key-78"))
	f.authen = []uint8{wire.AuthenStatusGetPass} // no reaction: the play errors
	f.echo = true
	cred := freshCredential(t)
	tr, err := playFake(t, "fixture_plain.yaml", f, "token_login", cred)
	if err == nil {
		t.Fatal("expected an error")
	}
	all := tr.String() + err.Error() + fmt.Sprintf("%+v", tr)
	if strings.Contains(all, string(cred)) || strings.Contains(all, string(f.key)) {
		t.Fatal("a secret reached an error or the transcript")
	}
}

func TestAnEventWithNoReactionIsAnError(t *testing.T) {
	f := newFake(t, []byte("fresh-key"))
	f.authen = []uint8{wire.AuthenStatusGetPass} // fixture_plain covers no GETPASS
	_, err := playFake(t, "fixture_plain.yaml", f, "token_login", freshCredential(t))
	if err == nil || !strings.Contains(err.Error(), "no reaction for authen_getpass") {
		t.Fatalf("%v", err)
	}
}

func TestAnASCIILoginSendsTheCredentialOnGetPass(t *testing.T) {
	f := newFake(t, []byte("fresh-key"))
	f.authen = []uint8{wire.AuthenStatusGetPass, wire.AuthenStatusPass}
	f.authorArgs = [][]byte{[]byte("local-user-name=p49-ro")}
	p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
	p.Stimulus.Steps[0].Fields.AuthenType, p.Stimulus.Steps[0].MinorVersion = "ascii", 0
	p.Reactions = append(p.Reactions, Reaction{Step: "login", On: "authen_getpass", Then: "send_credential", Status: "unmeasured"})
	tr, err := Play(t.Context(), p, "token_login", Target{Addr: f.ln.Addr().String(), Transport: "tcp", Key: f.key, Scale: 1},
		Login{User: "q", Credential: freshCredential(t)})
	if err != nil || tr.Outcome != "login_ok" || tr.Steps[0].Event != "authen_pass" {
		t.Fatalf("%v\n%s", err, tr)
	}
}

func TestSingleConnectionReusesOnlyWhenTheServerAgrees(t *testing.T) {
	for _, agree := range []bool{true, false} {
		f := newFake(t, []byte("fresh-key"))
		f.authen, f.singleConnect = []uint8{wire.AuthenStatusPass}, agree
		f.authorArgs = [][]byte{[]byte("local-user-name=p49-ro")}
		p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
		p.Reactions = append(p.Reactions, Reaction{Step: "*", On: "reply_single_connect", Then: "reuse_connection", Status: "unmeasured"})
		tr, err := Play(t.Context(), p, "single_connection", Target{Addr: f.ln.Addr().String(), Transport: "tcp", Key: f.key, Scale: 1},
			Login{User: "q", Credential: freshCredential(t)})
		if err != nil {
			t.Fatal(err)
		}
		if want := map[bool]int{true: 1, false: 3}[agree]; tr.Conns != want {
			t.Fatalf("server agrees %v: %d connections, want %d", agree, tr.Conns, want)
		}
	}
}

func TestWrongCredentialPlaysLoginAloneWithAFreshOne(t *testing.T) {
	f := newFake(t, []byte("fresh-key"))
	f.authen, f.echo = []uint8{wire.AuthenStatusFail}, true
	cred := freshCredential(t)
	tr, err := playFake(t, "fixture_plain.yaml", f, "wrong_credential", cred)
	if err != nil || tr.Outcome != "login_refused" || len(tr.Steps) != 1 {
		t.Fatalf("%v\n%s", err, tr)
	}
	if tr.Steps[0].ServerMsgLen != 48 { // the echoed random credential, 24 bytes hex
		t.Fatalf("the engine sends its own random credential, not the login's: %s", tr)
	}
}

func TestPlayRefusesATransportThatDisagreesWithTheScenario(t *testing.T) {
	f := newFake(t, []byte("fresh-key"))
	p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
	if _, err := Play(t.Context(), p, "tls_token_login", Target{Addr: f.ln.Addr().String(), Transport: "tcp"}, Login{}); err == nil {
		t.Fatal("a tls scenario over tcp is an error")
	}
}

func testCA(t *testing.T, name string) *testpki.CA {
	t.Helper()
	now := time.Now()
	ca, err := testpki.NewCA(name, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func issue(t *testing.T, ca *testpki.CA, client bool) tls.Certificate {
	t.Helper()
	now := time.Now()
	l := testpki.Leaf{CommonName: "leaf", Client: client, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	if !client {
		l.IPs = testpki.Loopback()
	}
	c, err := ca.Issue(l)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func tlsRefuser(t *testing.T, ca *testpki.CA) net.Listener {
	srvCert := issue(t, ca, false)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{srvCert},
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert,
		VerifyConnection: func(tls.ConnectionState) error { return x509.UnknownAuthorityError{} }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { c.(*tls.Conn).Handshake(); c.Read(make([]byte, 1)); c.Close() }()
		}
	}()
	return ln
}

// A real tls.Server that refuses the client's certificate in VerifyConnection,
// as port49's listener does: the client's Handshake returns nil (TLS 1.3), and
// the refusal reaches the first read as a *net.OpError "remote error", which
// handshakeEvent names; tls_unknown_ca plays its login and ends tls_refused.
func TestARefusedCertificateIsSeenOnTheLoginAsTLSRefused(t *testing.T) {
	ca, other := testCA(t, "trusted"), testCA(t, "untrusted")
	ln := tlsRefuser(t, ca)
	p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
	p.Transports = []string{"tls"}
	p.Stimulus.TLS = &TLSStimulus{ClientHello: nxosHello(), ServerIdentity: "chain_only"}
	tr, err := Play(t.Context(), p, "tls_unknown_ca", Target{Addr: ln.Addr().String(), Transport: "tls", Scale: 1,
		TLS: &TLSMaterial{Client: issue(t, other, true), ServerCAs: ca.Pool(), ServerIP: "127.0.0.1"}},
		Login{User: "q", Credential: freshCredential(t)})
	if err != nil || tr.Outcome != "handshake_refused" || tr.Steps[0].Event != "tls_refused" {
		t.Fatalf("%v\n%s", err, tr)
	}
}

// A server that accepts and never answers is a timeout, never a refusal.
func TestATimeoutOnTheUnknownCALoginIsAnErrorNotARefusal(t *testing.T) {
	ca := testCA(t, "trusted")
	srvCert := issue(t, ca, false)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{srvCert},
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { c.(*tls.Conn).Handshake(); time.Sleep(3 * time.Second); c.Close() }()
		}
	}()
	p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
	p.Transports = []string{"tls"}
	p.Stimulus.TLS = &TLSStimulus{ClientHello: nxosHello(), ServerIdentity: "chain_only"}
	ctx, cancel := contextWithTimeout(t, 500*time.Millisecond)
	defer cancel()
	tr, err := Play(ctx, p, "tls_unknown_ca", Target{Addr: ln.Addr().String(), Transport: "tls", Scale: 1,
		TLS: &TLSMaterial{Client: issue(t, ca, true), ServerCAs: ca.Pool(), ServerIP: "127.0.0.1"}},
		Login{User: "q", Credential: freshCredential(t)})
	if err == nil || tr.Outcome == "handshake_refused" || !strings.Contains(err.Error(), "handshake_timeout") {
		t.Fatalf("a timeout is an error, not tls_refused: %v\n%s", err, tr)
	}
}

// The names below are crypto/tls's own alert texts (alert.go).
func TestHandshakeEventNamesARemoteAlert(t *testing.T) {
	for text, want := range map[string]string{
		"tls: bad certificate":               "alert_bad_certificate",
		"tls: unknown certificate authority": "alert_unknown_ca",
		"tls: expired certificate":           "alert_certificate_expired",
		"tls: handshake failure":             "alert_handshake_failure",
		"tls: something new":                 "alert_other",
	} {
		err := &net.OpError{Op: "remote error", Err: errors.New(text)}
		if got := handshakeEvent(err); got != want {
			t.Errorf("%q: %s, want %s", text, got, want)
		}
	}
}

func contextWithTimeout(t *testing.T, d time.Duration) (ctx context.Context, cancel context.CancelFunc) {
	return context.WithTimeout(t.Context(), d)
}
