package devicemock

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
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
	f.authen = []uint8{wire.AuthenStatusFail}
	cred := freshCredential(t)
	tr, err := playFake(t, "fixture_plain.yaml", f, "wrong_credential", cred)
	if err != nil || tr.Outcome != "login_refused" || len(tr.Steps) != 1 {
		t.Fatalf("%v\n%s", err, tr)
	}
	got := f.seen()
	if len(got) != 1 || len(got[0].Data) == 0 {
		t.Fatalf("login alone, with a credential: %d requests", len(got))
	}
	if bytes.Equal(got[0].Data, cred) { // never print either value
		t.Fatalf("the engine sent the login's credential: both are %d bytes", len(cred))
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
	t.Helper()
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
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
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

func TestAGateOnAnEventNoReactionCoversStillReportsTheGate(t *testing.T) {
	f := newFake(t, []byte("fresh-key"))
	f.authen = []uint8{wire.AuthenStatusPass}
	f.authorArgs = longArgs()
	p, _ := Load("testdata/profiles/fixture_junos.yaml", root)
	p.Reactions = slices.DeleteFunc(p.Reactions, func(r Reaction) bool { return r.On == "author_pass_add" })
	tr, err := Play(t.Context(), p, "token_login", Target{Addr: f.ln.Addr().String(), Transport: "tcp", Key: f.key, Scale: 1},
		Login{User: "q", Credential: freshCredential(t)})
	if err != nil || len(tr.Gate) != 1 || tr.Outcome != "rejected_by_device" {
		t.Fatalf("the gate is reported before any reaction is looked up: %v\n%s", err, tr)
	}
}

func TestEveryRequestCarriesTheStepsShape(t *testing.T) {
	f := newFake(t, []byte("fresh-key"))
	f.authen = []uint8{wire.AuthenStatusPass}
	f.authorArgs = [][]byte{[]byte("local-user-name=p49-ro")}
	cred := freshCredential(t)
	tr, err := playFake(t, "fixture_plain.yaml", f, "token_login", cred)
	if err != nil || tr.Outcome != "login_ok" {
		t.Fatalf("%v\n%s", err, tr)
	}
	got := f.seen()
	if len(got) != 3 {
		t.Fatalf("%d requests", len(got))
	}
	login, author, acct := got[0], got[1], got[2]
	if login.MinorVersion != 1 || author.MinorVersion != 0 || acct.MinorVersion != 0 {
		t.Errorf("minor versions %d %d %d, want the steps' 1 0 0", login.MinorVersion, author.MinorVersion, acct.MinorVersion)
	}
	if !bytes.Equal(login.Data, cred) || login.AuthenType != wire.AuthenTypePAP {
		t.Errorf("a PAP login carries the credential as data (%v)", bytes.Equal(login.Data, cred))
	}
	if login.Flags&wire.FlagSingleConnect != 0 || acct.Flags&wire.FlagSingleConnect != 0 {
		t.Error("per_step without the flag: no single-connect request flag")
	}
	if acct.AcctFlags != wire.AcctFlagStart {
		t.Errorf("acct flags %#x, want start", acct.AcctFlags)
	}
	if len(author.Args) != 1 || !bytes.Equal(author.Args[0], []byte("service=junos-exec")) {
		t.Errorf("author args: %d, want the one service attribute", len(author.Args))
	}
	want := map[string]bool{"service=shell": false}
	for _, a := range acct.Args {
		s := string(a)
		switch {
		case strings.HasPrefix(s, "task_id="):
			if _, err := strconv.Atoi(strings.TrimPrefix(s, "task_id=")); err != nil {
				t.Errorf("task_id is not expanded (%d bytes)", len(s))
			}
		case strings.HasPrefix(s, "start_time="):
			if _, err := strconv.Atoi(strings.TrimPrefix(s, "start_time=")); err != nil {
				t.Errorf("start_time is not expanded (%d bytes)", len(s))
			}
		default:
			if _, ok := want[s]; ok {
				want[s] = true
			}
		}
		if strings.Contains(s, "{") || strings.Contains(s, string(cred)) {
			t.Errorf("an argument is unexpanded or holds the credential: %d bytes", len(s))
		}
	}
	if len(acct.Args) != 3 || !want["service=shell"] {
		t.Errorf("acct args: %d (service=shell present: %v), want 3", len(acct.Args), want["service=shell"])
	}
}

func TestASCIILoginSendsNoDataOnTheStartAndTheSingleConnectFlagWhenAsked(t *testing.T) {
	f := newFake(t, []byte("fresh-key"))
	f.authen = []uint8{wire.AuthenStatusFail}
	p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
	p.Stimulus.Steps[0].Fields.AuthenType = "ascii"
	p.Stimulus.Connections.SingleConnectFlag = true
	_, err := Play(t.Context(), p, "token_login", Target{Addr: f.ln.Addr().String(), Transport: "tcp", Key: f.key, Scale: 1},
		Login{User: "q", Credential: freshCredential(t)})
	if err != nil {
		t.Fatal(err)
	}
	got := f.seen()
	if len(got) != 1 || len(got[0].Data) != 0 || got[0].Flags&wire.FlagSingleConnect == 0 {
		t.Fatalf("ascii START has no data and the profile's flag is set: %d requests", len(got))
	}
}

func TestAReplyForAnotherSessionIsAnError(t *testing.T) {
	f := newFake(t, []byte("fresh-key"))
	f.authen, f.wrongSession = []uint8{wire.AuthenStatusPass}, true
	_, err := playFake(t, "fixture_plain.yaml", f, "token_login", freshCredential(t))
	if err == nil || !strings.Contains(err.Error(), "does not answer the request") {
		t.Fatalf("%v", err)
	}
}

func TestAClearReplyOverTCPIsRefused(t *testing.T) {
	f := newFake(t, []byte("fresh-key"))
	f.authen, f.clearReply = []uint8{wire.AuthenStatusPass}, true
	tr, err := playFake(t, "fixture_plain.yaml", f, "token_login", freshCredential(t))
	if err == nil || !strings.Contains(err.Error(), "unencrypted") {
		t.Fatalf("port 49 never answers in the clear: %v\n%s", err, tr)
	}
}

func tlsFakeProfile(t *testing.T) (*Profile, *testpki.CA, *fake) {
	t.Helper()
	ca := testCA(t, "trusted")
	f := newFakeTLS(t, issue(t, ca, false))
	p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
	p.Transports = []string{"tls"}
	p.Stimulus.TLS = &TLSStimulus{ClientHello: nxosHello(), ServerIdentity: "ip", FlightDelay: 5 * time.Second}
	return p, ca, f
}

// A device's measured flight delay holds on every TLS connection it makes,
// scaled by Target.Scale (decision 52 ruling 9).
func TestEveryTLSConnectionIsDelayedByTheScaledFlight(t *testing.T) {
	p, ca, f := tlsFakeProfile(t)
	f.authen = []uint8{wire.AuthenStatusPass}
	f.authorArgs = [][]byte{[]byte("local-user-name=p49-ro")}
	var mu sync.Mutex
	var slept []time.Duration
	tr, err := Play(t.Context(), p, "tls_token_login", Target{Addr: f.ln.Addr().String(), Transport: "tls", Scale: 0.1,
		Sleep: func(d time.Duration) { mu.Lock(); slept = append(slept, d); mu.Unlock() },
		TLS:   &TLSMaterial{Client: issue(t, ca, true), ServerCAs: ca.Pool(), ServerIP: "127.0.0.1"}},
		Login{User: "q", Credential: freshCredential(t)})
	if err != nil || tr.Outcome != "login_ok" || tr.Conns != 3 {
		t.Fatalf("%v\n%s", err, tr)
	}
	if len(slept) != 3 {
		t.Fatalf("%d delayed flights over %d connections", len(slept), tr.Conns)
	}
	for _, d := range slept {
		if d != 500*time.Millisecond {
			t.Errorf("delay %v, want 5s at scale 0.1", d)
		}
	}
}

func refusalProfile(t *testing.T) (*Profile, Target) {
	t.Helper()
	ca, other := testCA(t, "trusted"), testCA(t, "untrusted")
	ln := tlsRefuser(t, ca)
	p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
	p.Transports = []string{"tls"}
	p.Stimulus.TLS = &TLSStimulus{ClientHello: nxosHello(), ServerIdentity: "chain_only"}
	return p, Target{Addr: ln.Addr().String(), Transport: "tls", Scale: 1,
		TLS: &TLSMaterial{Client: issue(t, other, true), ServerCAs: ca.Pool(), ServerIP: "127.0.0.1"}}
}

// A refusal event the profile has a reaction for ends as that reaction says;
// with none, as the default handshake_refused.
func TestARefusalEventConsultsTheReactionTable(t *testing.T) {
	p, tgt := refusalProfile(t)
	p.Reactions = append(p.Reactions, Reaction{Step: "login", On: "alert_bad_certificate", Then: "failover_next_server",
		Outcome: "falls_to_local", Status: "unmeasured"})
	tr, err := Play(t.Context(), p, "tls_unknown_ca", tgt, Login{User: "q", Credential: freshCredential(t)})
	if err != nil || tr.Outcome != "falls_to_local" || tr.Steps[len(tr.Steps)-1].Event != "tls_refused" {
		t.Fatalf("%v\n%s", err, tr)
	}
	p2, tgt2 := refusalProfile(t)
	tr, err = Play(t.Context(), p2, "tls_unknown_ca", tgt2, Login{User: "q", Credential: freshCredential(t)})
	if err != nil || tr.Outcome != "handshake_refused" {
		t.Fatalf("no reaction: the default. %v\n%s", err, tr)
	}
}

func TestARefusalOnAnotherScenarioConsultsTheTableToo(t *testing.T) {
	p, tgt := refusalProfile(t)
	p.Reactions = append(p.Reactions, Reaction{Step: "login", On: "alert_bad_certificate", Then: "give_up",
		Outcome: "login_refused", Status: "unmeasured"})
	tr, err := Play(t.Context(), p, "tls_token_login", tgt, Login{User: "q", Credential: freshCredential(t)})
	if err != nil || tr.Outcome != "login_refused" {
		t.Fatalf("%v\n%s", err, tr)
	}
}

// resetter accepts and resets at once (SO_LINGER 0), before any alert: the
// other half of the race the alert-versus-reset ordering decides.
func resetter(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
			c.(*net.TCPConn).SetLinger(0)
			c.Close()
		}
	}()
	return ln.Addr().String()
}

// A profile that reacts on one alert gets that reaction when the reset wins.
func TestARefusalReactionHoldsWhateverArrivesFirst(t *testing.T) {
	p, tgt := refusalProfile(t)
	p.Reactions = append(p.Reactions, Reaction{Step: "login", On: "alert_bad_certificate", Then: "give_up",
		Outcome: "login_refused", Status: "unmeasured"})
	tgt.Addr = resetter(t)
	for _, sc := range []string{"tls_unknown_ca", "tls_token_login"} {
		tr, err := Play(t.Context(), p, sc, tgt, Login{User: "q", Credential: freshCredential(t)})
		if err != nil || tr.Outcome != "login_refused" {
			t.Fatalf("%s: %v\n%s", sc, err, tr)
		}
	}
}

func TestValidateRefusesRefusalReactionsThatDisagree(t *testing.T) {
	p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
	p.Reactions = append(p.Reactions,
		Reaction{Step: "login", On: "alert_unknown_ca", Then: "give_up", Outcome: "login_refused", Status: "unmeasured"},
		Reaction{Step: "login", On: "conn_reset", Then: "failover_local", Outcome: "falls_to_local", Status: "unmeasured"})
	err := p.Validate(root)
	if err == nil || !strings.Contains(err.Error(), "step login: refusal reactions disagree") {
		t.Fatalf("%v", err)
	}
	p.Reactions[len(p.Reactions)-1].Then, p.Reactions[len(p.Reactions)-1].Outcome = "give_up", "login_refused"
	if err := p.Validate(root); err != nil {
		t.Fatalf("agreeing reactions are fine: %v", err)
	}
}

// withCommandSteps is p with command_permitted and command_denied after
// authorize_session, as a per-command device's stimulus has them.
func withCommandSteps(p *Profile) {
	cmd := p.Stimulus.Steps[1]
	permitted, denied := cmd, cmd
	permitted.Name, denied.Name = "command_permitted", "command_denied"
	p.Stimulus.Steps = append(p.Stimulus.Steps[:2:2], append([]Step{permitted, denied}, p.Stimulus.Steps[2:]...)...)
}

// NX-OS 10.6(2)F sends no command authorization over per-request TLS (L73
// cell a): a profile that records it plays tls_token_login with no command
// step, never with steps the device never sent. token_login and
// tls_single_connection still play them.
func TestPerRequestTLSPlaysNoCommandStepWhereTheDeviceSendsNone(t *testing.T) {
	p, ca, f := tlsFakeProfile(t)
	withCommandSteps(p)
	all := []string{"login", "authorize_session", "command_permitted", "command_denied", "account_start"}
	if got := PlayedSteps(p, "tls_token_login"); !slices.Equal(got, all) {
		t.Fatalf("with no fact: %v", got)
	}
	p.DeviceFacts = []DeviceFact{{ID: "tls_per_request_no_command_authorization", Status: "measured"}}
	none := []string{"login", "authorize_session", "account_start"}
	if got := PlayedSteps(p, "tls_token_login"); !slices.Equal(got, none) {
		t.Fatalf("tls_token_login: %v, want %v", got, none)
	}
	for _, sc := range []string{"token_login", "tls_single_connection"} {
		if got := PlayedSteps(p, sc); !slices.Equal(got, all) {
			t.Fatalf("%s: %v, want %v", sc, got, all)
		}
	}
	f.authen = []uint8{wire.AuthenStatusPass}
	tr, err := Play(t.Context(), p, "tls_token_login", Target{Addr: f.ln.Addr().String(), Transport: "tls", Scale: 0,
		Sleep: func(time.Duration) {}, TLS: &TLSMaterial{Client: issue(t, ca, true), ServerCAs: ca.Pool(), ServerIP: "127.0.0.1"}},
		Login{User: "q", Credential: freshCredential(t)})
	if err != nil || tr.Outcome != "login_ok" {
		t.Fatalf("%v\n%s", err, tr)
	}
	var played []string
	for _, s := range tr.Steps {
		played = append(played, s.Step)
	}
	if !slices.Equal(played, none) || len(f.seen()) != 3 {
		t.Fatalf("played %v, the server saw %d requests\n%s", played, len(f.seen()), tr)
	}
}

// tls_single_connection is single_connection over TLS: every request carries
// the single-connect flag.
func TestTLSSingleConnectionSetsTheFlag(t *testing.T) {
	p, ca, f := tlsFakeProfile(t)
	p.Scenarios = append(p.Scenarios, "tls_single_connection")
	f.authen = []uint8{wire.AuthenStatusPass}
	tr, err := Play(t.Context(), p, "tls_single_connection", Target{Addr: f.ln.Addr().String(), Transport: "tls", Scale: 0,
		Sleep: func(time.Duration) {}, TLS: &TLSMaterial{Client: issue(t, ca, true), ServerCAs: ca.Pool(), ServerIP: "127.0.0.1"}},
		Login{User: "q", Credential: freshCredential(t)})
	if err != nil || tr.Outcome != "login_ok" {
		t.Fatalf("%v\n%s", err, tr)
	}
	for _, s := range f.seen() {
		if s.Flags&wire.FlagSingleConnect == 0 {
			t.Fatalf("a type %d request without the single-connect flag (flags %#x)", s.Type, s.Flags)
		}
	}
}
