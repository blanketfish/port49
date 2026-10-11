//go:build lab

package lab

import (
	"strings"
	"testing"
	"time"
)

func TestL56AuthURLReadsPort49sLine(t *testing.T) {
	for line, want := range map[string]string{
		"  https://keycloak.port49.lab:18443/realms/port49-lab/protocol/openid-connect/auth?client_id=port49-cli&state=x": "https://keycloak.port49.lab:18443/realms/port49-lab/protocol/openid-connect/auth?client_id=port49-cli&state=x",
		"port49: open this address in a browser and sign in at https://keycloak.port49.lab:18443/realms/port49-lab:":      "",
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
