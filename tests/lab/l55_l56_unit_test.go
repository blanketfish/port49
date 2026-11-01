//go:build lab

package lab

import (
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func TestL56AuthURLReadsPort49sLine(t *testing.T) {
	for line, want := range map[string]string{
		"  https://keycloak.port49.lab:18443/realms/port49-lab/protocol/openid-connect/auth?client_id=port49-cli&state=x": "https://keycloak.port49.lab:18443/realms/port49-lab/protocol/openid-connect/auth?client_id=port49-cli&state=x",
		"port49: open this address in a browser to sign in with your identity provider (keycloak.port49.lab:18443):":      "",
		"  http://127.0.0.1:18749/callback": "",
	} {
		if got, ok := l56AuthURL(line); got != want || ok != (want != "") {
			t.Errorf("%q: %q %v", line, got, ok)
		}
	}
}

func TestL56LoginFromReadsTheBrokersTime(t *testing.T) {
	at, ok := l56LoginFrom("port49 token: the session is over: your identity provider ended your sessions at " +
		"2026-10-10T03:00:00Z (back-channel logout); log in again from 2026-10-10T03:01:01Z\n")
	if !ok || !at.Equal(time.Date(2026, 10, 10, 3, 1, 1, 0, time.UTC)) {
		t.Fatalf("%v %v", at, ok)
	}
	if _, ok := l56LoginFrom("port49 token: no agent"); ok {
		t.Fatal("read a time from nothing")
	}
}

func TestL55AcceptedIsTheLoginForm(t *testing.T) {
	form := []byte(`<form id="kc-form-login" class="x" action="https://k/login-actions/authenticate?x=1" method="post">`)
	if !l55Accepted(200, form) || l55Accepted(400, []byte("Invalid parameter: redirect_uri")) || l55Accepted(200, []byte("<html/>")) {
		t.Fatal("misread")
	}
}

// The end to end's broker asks for the email scope its principal claim needs,
// and issues certificates.
func TestL56FilesAskForTheEmailScopeAndIssue(t *testing.T) {
	files := map[string]string{
		"port49-broker.yaml": "broker:\n  client_ca_file: /etc/port49/ca.pem\n  listen: x\n",
		"policy.yaml":        "subjects:\ngrants:\n",
	}
	if err := l56Files(files); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"        principal_claim: email\n        scopes: [openid, email]\n",
		"  identity:\n    issuance: {}\n"} {
		if !strings.Contains(files["port49-broker.yaml"], want) {
			t.Fatalf("no %q in %s", want, files["port49-broker.yaml"])
		}
	}
}

// A device token is the whole of `port49 token`'s stdout and nowhere else:
// not on its stderr, not on any other command's output, not with company on
// stdout.
func TestL56TokenAppearsOnlyAsPort49TokensStdout(t *testing.T) {
	kc := &keycloak{}
	c := &l56CLI{printed: []string{"state-0123456789"}}
	const tok = "device-token-0123456789"
	kc.know(tok)
	if err := c.tokenLeak(kc, tok, tok+"\n", ""); err != nil {
		t.Fatalf("the token alone on stdout: %v", err)
	}
	if c.tokenLeak(kc, tok, tok+"\n", "port49 token: "+tok) == nil {
		t.Error("the token on stderr not seen")
	}
	if c.tokenLeak(kc, tok, "note: "+tok+"\n", "") == nil {
		t.Error("the token with company on stdout not seen")
	}
	if c.leak(kc, "port49: extended to "+tok) == nil {
		t.Error("the token in another command's output not seen")
	}
}

func TestL56KeySecretsAreTheWholeKeyAndNeverPanic(t *testing.T) {
	der := make([]byte, 138)
	for i := range der {
		der[i] = byte(i)
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	got := l56KeySecrets(raw)
	if len(got) < 2 || got[0] != base64.StdEncoding.EncodeToString(der) {
		t.Fatalf("%q", got)
	}
	for _, s := range []string{"", "not a pem", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2}}))} {
		l56KeySecrets([]byte(s)) // must not panic
	}
	if len(l56KeySecrets([]byte("not a pem"))) != 0 {
		t.Fatal("secrets from nothing")
	}
}

// The leak check exempts what port49 prints by design and nothing else.
func TestL56LeakExemptsOnlyWhatPort49Prints(t *testing.T) {
	kc := &keycloak{}
	kc.know("state-0123456789", "verifier-0123456789")
	c := &l56CLI{printed: []string{"state-0123456789"}}
	if err := c.leak(kc, "  https://k/auth?state=state-0123456789"); err != nil {
		t.Fatalf("the printed state: %v", err)
	}
	for _, text := range []string{"verifier-0123456789", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"} {
		if c.leak(kc, "port49: "+text) == nil {
			t.Errorf("%q not seen", text)
		}
	}
}
