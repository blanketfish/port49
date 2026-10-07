//go:build lab

package lab

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/testpki"
)

const oidcE2EClaim = "A person who logs in at Keycloak mints a token from the broker with the ID token as a bearer " +
	"and logs in to the device with it; a logout at Keycloak reaches the broker by back-channel and the open " +
	"session's next command is denied credential_revoked; a new login after it works; a prompt=login refresh " +
	"answering the broker's challenge extends the open session from the fresh auth_time, while a plain SSO login " +
	"answering one is refused refresh_not_fresh; and a client-credentials token of the listed client mints for " +
	"the machine subject (plan 7h Task 16; policy engine spec §14)."

const (
	// oidcAlice is the realm's person, and the device username her subject names.
	oidcAlice         = "alice"
	oidcAlicePassword = "lab-only-alice-password"
	// oidcBrokerLogout is the URL Keycloak posts its logout tokens to on the
	// stack's network: the broker's certificate names port49-broker (testpki).
	oidcBrokerLogout = "https://port49-broker:8443/v1/logout"
)

// oidcE2EFiles gives the broker the identity block and the policy two OIDC
// subjects: alice by her verified email, and the lab service.
func oidcE2EFiles(files map[string]string) error {
	b := files["port49-broker.yaml"]
	i := strings.Index(b, "  client_ca_file:")
	if i < 0 {
		return fmt.Errorf("port49-broker.yaml has no client_ca_file to replace")
	}
	j := strings.Index(b[i:], "\n") + i + 1
	anchor := strings.TrimSpace(strings.TrimPrefix(b[i:j-1], "  client_ca_file:"))
	files["port49-broker.yaml"] = b[:i] + `  identity:
    humans:
      - {type: x509, trust_anchor_file: ` + anchor + `}
      - type: oidc
        issuer: https://keycloak.port49.lab:18443/realms/port49-lab
        client_id: port49-cli
        principal_claim: email
        principal_domains: [corp.example.com]
        ca_file: /etc/port49-oidc/idp-ca.pem
    machines:
      - type: oidc
        issuer: https://keycloak.port49.lab:18443/realms/port49-lab
        audience: "api://port49-svc"
        clients: [{client_id: port49-svc, sub: ` + kcServiceAccountID + `}]
        ca_file: /etc/port49-oidc/idp-ca.pem
` + b[j:]
	for _, add := range []struct{ key, entries string }{
		{"subjects:\n", `  - {name: oidc_alice, identity: ["user:alice@corp.example.com"], username: alice, token_ttl: 300s}
  - {name: oidc_svc, identity: ["app:port49-svc"], username: svc-backup, token_ttl: 300s}
`},
		{"grants:\n", `  - {subject: oidc_alice, scope: all_devices, roles: [network_admin], max_privilege: admin}
  - {subject: oidc_svc, scope: all_devices, roles: [network_admin], max_privilege: admin}
`},
	} {
		if !strings.Contains(files["policy.yaml"], add.key) {
			return fmt.Errorf("policy.yaml has no %q block to add to", strings.TrimSpace(add.key))
		}
		files["policy.yaml"] = strings.Replace(files["policy.yaml"], add.key, add.key+add.entries, 1)
	}
	return nil
}

// oidcE2EPKI writes what the overlay mounts, under dir (c.local/oidc): Keycloak's
// server certificate and key from ca, the broker's CA as its truststore (pki/),
// ca for the broker's ca_file (idp-ca.pem), and the admin password (admin.env,
// 0600, read by compose, never by the container's image layers).
//
// Keycloak reads its key as uid 1000 in the container, so pki/ is world-readable
// as the overlay mounts it; the stack's local directory is 0700 and the CA lives
// 48h for this one run, which is why that is deliberate (Task 15 review, M4).
func oidcE2EPKI(dir string, ca *testpki.CA, brokerCA []byte, now time.Time) error {
	pki := filepath.Join(dir, "pki")
	if err := os.MkdirAll(pki, 0o755); err != nil {
		return err
	}
	leaf, err := ca.Issue(testpki.Leaf{CommonName: kcHost, DNSNames: []string{kcHost}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(48 * time.Hour)})
	if err != nil {
		return err
	}
	cert, key, err := testpki.PEMs(leaf)
	if err != nil {
		return err
	}
	pass := make([]byte, 18)
	if _, err := rand.Read(pass); err != nil {
		return err
	}
	for _, f := range []struct {
		path string
		body []byte
		mode os.FileMode
	}{
		{filepath.Join(pki, "keycloak.pem"), cert, 0o644},
		{filepath.Join(pki, "keycloak-key.pem"), key, 0o644},
		{filepath.Join(pki, "broker-ca.pem"), brokerCA, 0o644},
		{filepath.Join(dir, "idp-ca.pem"), ca.PEM(), 0o644},
		{filepath.Join(dir, "admin.env"), []byte(fmt.Sprintf("KC_BOOTSTRAP_ADMIN_PASSWORD=%x\n", pass)), 0o600},
	} {
		if err := os.WriteFile(f.path, f.body, f.mode); err != nil {
			return err
		}
		if err := os.Chmod(f.path, f.mode); err != nil {
			return err
		}
	}
	return nil
}

func TestOIDCEndToEnd(t *testing.T) {
	sel, _, err := platformSelection()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range sel {
		if p.name != "arista_eos" {
			continue
		}
		p := p
		t.Run(p.name, func(t *testing.T) { oidcEndToEnd(t, labFor(t, p)) })
		return
	}
	t.Skip("PORT49_LAB_PLATFORMS does not select arista_eos")
}

// oidcEndToEnd is the claim measured on one device. A fault in the setup (the
// provider never answering, a login form that changed, the first mint refused,
// the device not opening) stops the test with t.Fatal before the note: it is
// INVALID, never a measured "no". A step that ran and did not do what the claim
// says is a failed cell, and the note records it.
func oidcEndToEnd(t *testing.T, l *lab) {
	var failed []string
	fail := func(format string, args ...any) { failed = append(failed, fmt.Sprintf(format, args...)) }
	var obs strings.Builder
	cell := func(step, what string) { fmt.Fprintf(&obs, "| %s | %s |\n", step, wideCell(what)) }
	complete := false
	var kc *keycloak

	now := time.Now()
	idpCA, err := testpki.NewCA("port49 lab oidc e2e CA", now.Add(-time.Hour), now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	c := l.startComposeWith(t, composeOptions{Overlay: "oidc.yaml", Files: oidcE2EFiles, Prepare: func(c *composeStack) error {
		brokerCA, err := os.ReadFile(filepath.Join(root, slicePKIDir, testpki.LabCA))
		if err != nil {
			return err
		}
		return oidcE2EPKI(filepath.Join(c.local, "oidc"), idpCA, brokerCA, time.Now())
	}})
	stop := l.capture(t, "oidc-e2e")
	defer stop()
	defer func() {
		if !complete {
			// Fatal before the measurement ended: nothing to record as a verdict.
			if len(failed) > 0 {
				t.Errorf("OIDC end to end, before it stopped: %s", strings.Join(failed, "; "))
			}
			return
		}
		note := "| step | observed |\n|---|---|\n" + obs.String()
		if len(failed) > 0 {
			note += "\n**Not as the claim says:**\n\n- " + strings.Join(failed, "\n- ") + "\n"
		}
		if err := oidcNoteLeak(note, kc.known()); err != nil {
			t.Errorf("the end-to-end note is not written: %v", err)
			return
		}
		l.result(t, "oidc-e2e", oidcE2EClaim, note)
		if len(failed) > 0 {
			t.Errorf("OIDC end to end: %s", strings.Join(failed, "; "))
		}
	}()

	kc = &keycloak{URL: "https://" + kcHost + ":" + kcPort + "/realms/" + kcRealm, ca: idpCA, HTTP: keycloakClient(idpCA)}
	kc.know(labSecrets...)
	kc.adminFromEnv(t, filepath.Join(c.local, "oidc", "admin.env"))
	kc.know(kc.admin)
	waitDiscovery(t, kc, 3*time.Minute)
	kc.SetLogoutURL(t, oidcBrokerLogout)
	br := oidcBroker{c: brokerClient(t), kc: kc, base: sliceBrokerURL}

	// ---- 1. Log in at Keycloak, mint with the ID token, log in to the device.
	// The first mint retries while the broker's key set has not yet fetched
	// Keycloak's keys (pre-flight I-9).
	first := kc.Login(t, oidcAlice, oidcAlicePassword, nil)
	tok, said := br.mintRetry(t, first.IDToken, l.p.node, 3*time.Minute)
	cell("1a. Keycloak login, POST /v1/tokens with the ID token as bearer", said)
	if tok == "" {
		t.Fatalf("INVALID: the first mint gave no token: %s", said)
	}
	sh, err := l.shell(oidcAlice, tok)
	if err != nil {
		t.Fatalf("INVALID: SSH as %s with the first token: %v", oidcAlice, err)
	}
	defer sh.Close()
	r := l.runPermitted(sh, "show version", 20*time.Second)
	cell("1b. SSH as alice with the token, `show version`", r.cell)
	if !r.permitted {
		// Every later step rests on this session; record it and stop.
		fail("the first command: %s", r.cell)
		complete = true
		return
	}

	// ---- 2. Log out at Keycloak; the broker hears it; the next command is denied.
	boff, doff := fileSize(c.brokerLog), l.mark()
	kc.EndSession(t, first.IDToken)
	recs := waitRecordsOf(c.brokerLog, boff, 30*time.Second, func(rs []map[string]any) bool {
		return revokeBySid(rs) != nil
	})
	rv := revokeBySid(recs)
	cell("2a. RP-initiated logout at Keycloak; the broker's revoke record", jsonCell(sub(rv, "revocation")))
	if rv == nil {
		fail("no revoke record by sid within 30s of the logout")
	}
	denied := l.runCmd(sh, "show version")
	_, verdict, reason := ctxIDOf(l.waitForRecords(doff, 30*time.Second, func(rs []map[string]any) bool {
		_, v, _ := ctxIDOf(rs, oidcAlice)
		return v == "deny"
	}), oidcAlice)
	cell("2b. the open session's next `show version`", fmt.Sprintf("%s; port49d: %s %s", denied.cell, verdict, reason))
	if denied.permitted || verdict != "deny" || reason != "credential_revoked" {
		fail("the session's command after the logout: %s; port49d %s %s", denied.cell, verdict, reason)
	}
	_, again := br.mint(t, first.IDToken, l.p.node)
	cell("2c. the ended session's ID token mints again", again)
	if !strings.Contains(again, "credential_revoked") {
		fail("the ended session's ID token minted again: %s", again)
	}

	// ---- 3. A new login after the logout works, and opens a live session
	// for the refresh to extend (pre-flight I-10).
	kc.HTTP = keycloakClient(idpCA) // a fresh browser
	second := kc.Login(t, oidcAlice, oidcAlicePassword, nil)
	tok2, said2 := br.mint(t, second.IDToken, l.p.node)
	cell("3a. a new Keycloak login, a new mint", said2)
	if tok2 == "" {
		t.Fatalf("INVALID: a login after the logout minted nothing: %s", said2)
	}
	sh2, err := l.shell(oidcAlice, tok2)
	if err != nil {
		t.Fatalf("INVALID: SSH as %s with the second token: %v", oidcAlice, err)
	}
	defer sh2.Close()
	r2 := l.runPermitted(sh2, "show version", 20*time.Second)
	cell("3b. SSH as alice with it, `show version`", r2.cell)
	if !r2.permitted {
		fail("the second session's first command: %s", r2.cell)
		complete = true
		return
	}

	// ---- 4b. A plain SSO login answering a challenge is not fresh: Keycloak
	// does not authenticate again without prompt=login, so its auth_time
	// predates the challenge by more than clock_skew (75s after step 3a) and
	// the broker refuses it (Ruling 15; pre-flight I-10).
	time.Sleep(75 * time.Second)
	stale := br.challenge(t, second.IDToken)
	sso := kc.Login(t, oidcAlice, oidcAlicePassword, url.Values{"nonce": {stale}})
	code, body := br.post("/v1/refresh", sso.IDToken, "{}")
	_, rsaid := refreshSaid(code, body, kc.known())
	cell("4b. a challenge, a plain SSO login with its nonce, `POST /v1/refresh`",
		fmt.Sprintf("password asked: %v; %s", sso.SawLoginForm, rsaid))
	if code != 401 || !strings.Contains(rsaid, "refresh_not_fresh") {
		fail("a refresh the provider did not re-authenticate: %s", rsaid)
	}

	// ---- 4. A prompt=login refresh answering the broker's challenge extends
	// the open session from the fresh auth_time.
	time.Sleep(11 * time.Second) // one challenge per principal per 10s
	nonce := br.challenge(t, second.IDToken)
	fresh := kc.Login(t, oidcAlice, oidcAlicePassword, url.Values{"prompt": {"login"}, "nonce": {nonce}})
	code, body = br.post("/v1/refresh", fresh.IDToken, "{}")
	refreshed, rsaid := refreshSaid(code, body, kc.known())
	cell("4. `POST /v1/refresh/challenge`, a prompt=login login with its nonce, `POST /v1/refresh`",
		fmt.Sprintf("password asked: %v; %s", fresh.SawLoginForm, rsaid))
	_, fc := claimsOf(fresh.IDToken)
	at, _ := fc["auth_time"].(float64)
	extended := 0
	for _, s := range refreshed.Sessions {
		if s.Outcome == "extended" && s.Device == l.p.node && s.Username == oidcAlice {
			extended++
		}
	}
	switch {
	case code != 200:
		fail("the OIDC refresh: %s", rsaid)
	case extended < 1:
		fail("the OIDC refresh extended no session: %s", rsaid)
	case refreshed.AuthTime != time.Unix(int64(at), 0).UTC().Format(time.RFC3339):
		fail("the refresh's auth_time %s is not the fresh token's %s", refreshed.AuthTime,
			time.Unix(int64(at), 0).UTC().Format(time.RFC3339))
	}
	after := l.runPermitted(sh2, "show version", 20*time.Second)
	cell("4a. the extended session's next `show version`", after.cell)
	if !after.permitted {
		fail("the extended session's next command: %s", after.cell)
	}

	// ---- 5. A machine mints with a client-credentials token of its listed
	// client, whose sub is the pinned service account (Ruling 21).
	svc := kc.ServiceToken(t)
	tok3, said3 := br.mint(t, svc, l.p.node)
	cell("5. client-credentials token, POST /v1/tokens", said3)
	if tok3 == "" || !strings.Contains(said3, "app:port49-svc") {
		fail("the machine's mint: %s", said3)
	}
	complete = true
}

// revokeBySid is the broker's revoke record for a back-channel logout by sid, or nil.
func revokeBySid(recs []map[string]any) map[string]any {
	var out map[string]any
	for _, rec := range recs {
		if str(rec, "event") == "revoke" && str(sub(rec, "revocation"), "by") == "sid" {
			out = rec
		}
	}
	return out
}

// jsonCell is v as one JSON line, for a table cell; "absent" for nil.
func jsonCell(v map[string]any) string {
	if v == nil {
		return "absent"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "unprintable"
	}
	return string(b)
}

// brokerClient trusts the compose stack's broker certificate.
func brokerClient(t *testing.T) *http.Client {
	t.Helper()
	pem, err := os.ReadFile(filepath.Join(root, slicePKIDir, testpki.LabCA))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}
}

// oidcBroker is the broker's HTTP API as the test calls it, with the bearer in
// the Authorization header alone and every answer said without its body: a mint
// answer holds the device token, a challenge holds its nonce, and a note, an
// evidence line or a failure message holds neither (Task 15 review).
type oidcBroker struct {
	c    *http.Client
	kc   *keycloak // its registry of values no message may hold
	base string
}

// post is one POST with bearer in the Authorization header, never in a URL. A
// transport failure is code 0 and the error without its URL.
func (b oidcBroker) post(path, bearer, body string) (int, string) {
	req, err := http.NewRequest("POST", b.base+path, strings.NewReader(body))
	if err != nil {
		return 0, errCause(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.c.Do(req)
	if err != nil {
		return 0, errCause(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(raw)
}

// mint mints one token for device with bearer, and says what it got without
// the token; the token is registered as a value no message may hold.
func (b oidcBroker) mint(t *testing.T, bearer, device string) (string, string) {
	t.Helper()
	code, body := b.post("/v1/tokens", bearer, `{"devices":["`+device+`"],"ttl_seconds":300}`)
	login, said := mintSaid(code, body, b.kc.known())
	b.kc.know(login)
	return login, said
}

// mintRetry is mint retried every 10s while the broker answers 503
// identity_provider_unavailable, up to within: the broker's first key fetches
// fail while Keycloak imports its realm (pre-flight I-9).
func (b oidcBroker) mintRetry(t *testing.T, bearer, device string, within time.Duration) (string, string) {
	t.Helper()
	return retryMint(func() (string, string) { return b.mint(t, bearer, device) }, within, 10*time.Second)
}

// challenge asks for a refresh challenge and returns its nonce, which is
// registered as a value no message may hold. A refusal is INVALID: the harness
// asked too soon (one per principal per 10s) or the bearer is not a person's.
func (b oidcBroker) challenge(t *testing.T, bearer string) string {
	t.Helper()
	code, body := b.post("/v1/refresh/challenge", bearer, "")
	var ch api.RefreshChallenge
	if code != 200 || json.Unmarshal([]byte(body), &ch) != nil || ch.Nonce == "" {
		t.Fatalf("INVALID: the refresh challenge: %s", brokerSaid(code, body, b.kc.known()))
	}
	b.kc.know(ch.Nonce)
	return ch.Nonce
}

// retryMint calls mint until it gives a token, answers anything but 503
// identity_provider_unavailable, or within passes; every apart.
func retryMint(mint func() (string, string), within, every time.Duration) (string, string) {
	deadline := time.Now().Add(within)
	for {
		tok, said := mint()
		if tok != "" || !strings.Contains(said, "identity_provider_unavailable") || time.Now().After(deadline) {
			return tok, said
		}
		time.Sleep(every)
	}
}

// scrubbed is text with each compact JWS and each registered secret replaced.
func scrubbed(text string, secrets []string) string {
	text = jwsShape.ReplaceAllString(text, "[jws]")
	for _, v := range secrets {
		if v != "" {
			text = strings.ReplaceAll(text, v, "[secret]")
		}
	}
	return text
}

// brokerSaid says what the broker answered without echoing a body that is not
// an error: its code and, for an error, its error code and detail, scrubbed.
func brokerSaid(code int, body string, secrets []string) string {
	if code == 0 {
		return "no answer: " + body
	}
	var e api.Error
	if json.Unmarshal([]byte(body), &e) == nil && e.Error != "" {
		return oneLineMax(scrubbed(fmt.Sprintf("%d %s: %s", code, e.Error, e.Detail), secrets), 300)
	}
	return fmt.Sprintf("%d (a %d-byte body that is no error)", code, len(body))
}

// mintSaid is the device token of a one-device mint answer, and a sentence
// saying what the broker decided that holds no token.
func mintSaid(code int, body string, secrets []string) (login, said string) {
	if code != 200 {
		return "", brokerSaid(code, body, secrets)
	}
	var resp api.MintResponse
	if json.Unmarshal([]byte(body), &resp) != nil || len(resp.Results) != 1 {
		return "", fmt.Sprintf("%d (a %d-byte body that is not one result)", code, len(body))
	}
	r := resp.Results[0]
	if r.Error != "" {
		return "", oneLineMax(scrubbed(fmt.Sprintf("200 %s: %s: %s", resp.Principal, r.Error, r.Detail), secrets), 300)
	}
	return r.Login, oneLineMax(scrubbed(fmt.Sprintf("200 %s: %s %s as %s", resp.Principal, r.Verdict, r.Reason, r.Username),
		secrets), 300)
}

// refreshSaid is a refresh answer decoded, and a sentence for a cell: the fresh
// auth_time and each session's outcome on a 200, the refusal otherwise.
func refreshSaid(code int, body string, secrets []string) (api.RefreshResponse, string) {
	var resp api.RefreshResponse
	if code != 200 {
		return resp, brokerSaid(code, body, secrets)
	}
	if json.Unmarshal([]byte(body), &resp) != nil {
		return resp, fmt.Sprintf("%d (a %d-byte body that is no refresh answer)", code, len(body))
	}
	var ss []string
	for _, s := range resp.Sessions {
		ss = append(ss, fmt.Sprintf("%s/%s %s", s.Device, s.Username, s.Outcome))
	}
	return resp, oneLineMax(scrubbed(fmt.Sprintf("200 auth_time %s; sessions: %s", resp.AuthTime, strings.Join(ss, ", ")),
		secrets), 300)
}
