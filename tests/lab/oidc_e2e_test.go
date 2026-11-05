//go:build lab

package lab

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/testpki"
)

const oidcE2EClaim = "A person who logs in at Keycloak exchanges the ID token for a certificate at POST /v1/certificate " +
	"(a person's ID token is no caller's credential, decision 56 ruling 4), mints a token from the broker with that " +
	"certificate and logs in to the device with it; a logout at Keycloak reaches the broker by back-channel and the " +
	"open session's next command is denied credential_revoked; a new login once clock_skew has passed works (an " +
	"immediate one is refused, for the sub record every Keycloak logout writes); and a client-credentials token of the " +
	"listed client mints for the machine subject (plan 7h Task 16; policy engine spec §14); Keycloak's admin sign-out " +
	"of a user holding two sessions sends one logout token naming one session and the subject, and the broker ends both " +
	"sessions (ruling 13, spec §5.1.4); and a burst of eight back-channel logouts, one per session ended back to back, " +
	"all reach the broker and all apply, none lost to a reused connection (plan 7h final review F1). The refresh of an " +
	"open session by a prompt=login ID token at POST /v1/refresh is retired with the bearer refresh; the certificate's " +
	"refresh is L56's."

const (
	// oidcAlice is the realm's person, and the device username her subject names.
	oidcAlice         = "alice"
	oidcAlicePassword = "lab-only-alice-password"
	// oidcBob and oidcCarol are the realm's other two people: bob holds exactly
	// the two sessions step 6 signs out, and carol the eight step 7 ends, each a
	// subject and a token key (device, username) no earlier step touched.
	oidcBob           = "bob"
	oidcBobPassword   = "lab-only-bob-password"
	oidcCarol         = "carol"
	oidcCarolPassword = "lab-only-carol-password"
	// oidcBrokerLogout is the URL Keycloak posts its logout tokens to on the
	// stack's network: the broker's certificate names port49-broker (testpki).
	oidcBrokerLogout = "https://port49-broker:8443/v1/logout"
)

// oidcE2EFiles gives the broker the identity block and the policy two OIDC
// subjects: alice, bob and carol by their verified emails, and the lab service.
// Mint alone touches no device, so bob and carol need no account on one.
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
  - {name: oidc_bob, identity: ["user:bob@corp.example.com"], username: bob, token_ttl: 300s}
  - {name: oidc_carol, identity: ["user:carol@corp.example.com"], username: carol, token_ttl: 300s}
  - {name: oidc_svc, identity: ["app:port49-svc"], username: svc-backup, token_ttl: 300s}
`},
		{"grants:\n", `  - {subject: oidc_alice, scope: all_devices, roles: [network_admin], max_privilege: admin}
  - {subject: oidc_bob, scope: all_devices, roles: [network_admin], max_privilege: admin}
  - {subject: oidc_carol, scope: all_devices, roles: [network_admin], max_privilege: admin}
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

// oidcE2EIssuingFiles is oidcE2EFiles with the broker issuing: a person's ID
// token is exchanged for a certificate, the one credential a person mints with.
func oidcE2EIssuingFiles(files map[string]string) error {
	if err := oidcE2EFiles(files); err != nil {
		return err
	}
	b := files["port49-broker.yaml"]
	if !strings.Contains(b, "  identity:\n") {
		return fmt.Errorf("port49-broker.yaml has no identity to add issuance to")
	}
	files["port49-broker.yaml"] = strings.Replace(b, "  identity:\n", "  identity:\n    issuance: {}\n", 1)
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
	for _, p := range rowsFor(sel, false) {
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
	c := l.startComposeWith(t, composeOptions{Overlay: "oidc.yaml", Files: oidcE2EIssuingFiles, Prepare: func(c *composeStack) error {
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

	// The broker issues, and has no issuing CA until one is made (as in L56):
	// make it and restart, before any person signs in.
	if out, err := c.run("run", "--rm", "--no-deps", "port49-broker", "init-issuer"); err != nil || !strings.Contains(out, "created the issuing CA") {
		t.Fatalf("INVALID: port49-broker init-issuer: %v: %s", err, oneLineMax(out, 300))
	}
	if _, err := c.restartBroker(); err != nil {
		t.Fatalf("INVALID: restarting the broker: %v", err)
	}

	// ---- 1. Log in at Keycloak with a nonce bound to a fresh key, exchange the
	// ID token for a certificate, mint with the certificate, log in to the
	// device. The exchange and the first mint retry while the broker's key set
	// has not yet fetched Keycloak's keys (pre-flight I-9), and while the
	// broker's start gate holds requests until its first takeover (decision 36).
	first, h1, exchanged := br.signIn(t, oidcAlice, oidcAlicePassword, 3*time.Minute)
	cell("1a. Keycloak login with a nonce bound to a fresh key, POST /v1/certificate with the ID token as bearer", exchanged)
	if h1 == nil {
		t.Fatalf("INVALID: the first exchange gave no certificate: %s", exchanged)
	}
	tok, said := retryMint(func() (string, string) { return br.mintAs(t, h1, l.p.node) }, 3*time.Minute, 10*time.Second)
	cell("1b. POST /v1/tokens by the issued certificate", said)
	if tok == "" {
		t.Fatalf("INVALID: the first mint gave no token: %s", said)
	}
	sh, err := l.shell(oidcAlice, tok)
	if err != nil {
		t.Fatalf("INVALID: SSH as %s with the first token: %v", oidcAlice, err)
	}
	defer sh.Close()
	r := l.runPermitted(sh, "show version", 20*time.Second)
	cell("1c. SSH as alice with the token, `show version`", r.cell)
	if !r.permitted {
		// Every later step rests on this session; record it and stop.
		fail("the first command: %s", r.cell)
		complete = true
		return
	}

	// ---- 2. Log out at Keycloak; the broker hears it; the next command is denied.
	boff, doff := fileSize(c.brokerLog), l.mark()
	kc.EndSession(t, first.IDToken)
	endedAt := time.Now() // at or after the logout token's iat
	recs := waitRecordsOf(c.brokerLog, boff, 30*time.Second, func(rs []map[string]any) bool {
		return revokeBySid(rs) != nil
	})
	rv := revokeBySid(recs)
	if rv == nil {
		// Keycloak's POST that never arrived is a setup fault (its truststore,
		// the port49-broker name, the network), not a logout that revokes
		// nothing: only a request the broker received, and refused or not
		// acted on, is a measurement (Task 16 review I1).
		errText, _ := os.ReadFile(c.brokerErr)
		metrics := ""
		if resp, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://127.0.0.1:9050/metrics"); err == nil {
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			resp.Body.Close()
			metrics = string(raw)
		}
		refusal, arrived := logoutArrival(string(errText), metrics)
		if !arrived {
			t.Fatalf("INVALID: no logout request reached the broker within 30s of the end-session logout: Keycloak's " +
				"truststore, the port49-broker name, or the stack's network; no note is written")
		}
		if refusal != "" {
			cell("2a. RP-initiated logout at Keycloak; the broker's answer", oneLineMax(scrubbed(refusal, kc.known()), 300))
		} else {
			cell("2a. RP-initiated logout at Keycloak; the broker's answer", "a logout request arrived and no revoke record by sid was written")
		}
		fail("no revoke record by sid within 30s of a logout the broker received")
	} else {
		cell("2a. RP-initiated logout at Keycloak; the broker's revoke record", jsonCell(sub(rv, "revocation")))
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
	_, again := br.mintAs(t, h1, l.p.node)
	cell("2c. the ended session's certificate mints again", again)
	if !saidRevoked(again) {
		fail("the ended session's certificate minted again: %s", again)
	}

	// ---- 3. A new login once clock_skew has passed works, and opens a live
	// session for the refresh to extend (pre-flight I-10). Every Keycloak
	// logout token carries sid and sub, so the broker also writes a sub record
	// (ruling 13 B) that refuses an ID token issued within clock_skew of the
	// logout: 3- records what an immediate re-login is told, then 3a waits it out.
	kc.HTTP = keycloakClient(idpCA) // a fresh browser
	_, hSoon, saidSoon := br.signIn(t, oidcAlice, oidcAlicePassword, 0)
	cell("3-. a new Keycloak login at once after the logout, POST /v1/certificate with its ID token", saidSoon)
	// A logged-out person is issued nothing: an exchange that gives a
	// certificate here is the failure, whatever the mint after it says.
	if hSoon != nil || !saidRevoked(saidSoon) {
		fail("a login at once after the logout was not refused credential_revoked at the exchange: %s", saidSoon)
	}
	time.Sleep(time.Until(loginAgainAt(endedAt)))
	kc.HTTP = keycloakClient(idpCA)
	_, h2, exchanged2 := br.signIn(t, oidcAlice, oidcAlicePassword, 0)
	if h2 == nil {
		t.Fatalf("INVALID: a login after the logout and clock_skew was given no certificate: %s", exchanged2)
	}
	tok2, said2 := br.mintAs(t, h2, l.p.node)
	cell("3a. a new Keycloak login after clock_skew, its exchange and a new mint", said2)
	if tok2 == "" {
		t.Fatalf("INVALID: a login after the logout and clock_skew minted nothing: %s", said2)
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

	// ---- 4. Retired. The refresh of an open session by a prompt=login ID token
	// at POST /v1/refresh (and its refusal of a plain SSO login, refresh_not_fresh)
	// went with the bearer refresh: a person's ID token is no caller's credential
	// (decision 56 ruling 4). The certificate's refresh, signed on the held
	// connection, is measured by L56.
	cell("4, 4b, 4a. a prompt=login ID token at POST /v1/refresh", "not measured: retired with the bearer refresh "+
		"(decision 56 ruling 4); the certificate's refresh is L56's")

	// ---- 5. A machine mints with a client-credentials token of its listed
	// client, whose sub is the pinned service account (Ruling 21).
	svc := kc.ServiceToken(t)
	tok3, said3 := br.mint(t, svc, l.p.node)
	cell("5. client-credentials token, POST /v1/tokens", said3)
	if tok3 == "" || !strings.Contains(said3, "app:port49-svc") {
		fail("the machine's mint: %s", said3)
	}

	// ---- 6. Admin sign-out of a user with two sessions: one token names one
	// sid and the sub; both sessions end (ruling 13 option B; L45 (b)). The user
	// is bob, who has no session or mark from any earlier step, so he holds
	// exactly the two sessions made here.
	bobID := kc.UserID(t, oidcBob)
	var pairIDs, pairSids []string
	var pairHolders []*oidcHolder
	for i := 1; i <= 2; i++ {
		kc.HTTP = keycloakClient(idpCA) // a fresh browser: a session of its own
		lg, h, ex := br.signIn(t, oidcBob, oidcBobPassword, 0)
		if h == nil {
			t.Fatalf("INVALID: session %d of 2 was given no certificate: %s", i, ex)
		}
		sid := sidOf(lg.IDToken)
		kc.know(sid)
		if sid == "" {
			t.Fatalf("INVALID: session %d of 2 has an ID token with no sid", i)
		}
		if tk, said := br.mintAs(t, h, l.p.node); tk == "" {
			t.Fatalf("%s", mintFault(fmt.Sprintf("session %d of 2", i), said))
		}
		pairIDs, pairSids, pairHolders = append(pairIDs, lg.IDToken), append(pairSids, sid), append(pairHolders, h)
	}
	if pairSids[0] == pairSids[1] {
		t.Fatalf("INVALID: the two logins share one sid")
	}
	bobSub := subOf(pairIDs[0])
	cell("6a. two fresh Keycloak logins as bob, a certificate for each and a mint with it", "both minted; two different sids")
	since := time.Now().UTC().Format(time.RFC3339)
	boff, errOff, mBefore := fileSize(c.brokerLog), fileSize(c.brokerErr), oidcBrokerMetrics()
	kc.LogoutUser(t, bobID)
	recs = waitRecordsOf(c.brokerLog, boff, 30*time.Second, func(rs []map[string]any) bool {
		_, _, ok := logoutRevokes(rs, oidcLogoutOrigin+kc.URL, bobSub)
		return ok
	})
	rsid, _, ok := logoutRevokes(recs, oidcLogoutOrigin+kc.URL, bobSub)
	if !ok {
		// As step 2: a request that never arrived is a setup fault; one that
		// arrived and wrote the wrong records is a failed cell.
		tail, _ := os.ReadFile(c.brokerErr)
		if int64(len(tail)) > errOff {
			tail = tail[errOff:]
		} else {
			tail = nil
		}
		refusal, _ := logoutArrival(string(tail), "")
		// Without a readable series before and after, a delta is cumulative or
		// negative: arrival then rests on the stderr refusal and the records alone.
		var answered float64
		if mAfter := oidcBrokerMetrics(); hasLogoutSeries(mBefore) && hasLogoutSeries(mAfter) {
			answered, _, _ = logoutCounts(mBefore, mAfter)
		}
		if refusal == "" && answered <= 0 {
			t.Fatalf("INVALID: no logout request reached the broker within 30s of the admin sign-out: Keycloak's " +
				"truststore, the port49-broker name, or the stack's network; no note is written")
		}
	}
	switch {
	case ok && sidLabel(rsid, pairSids) == 0:
		cell("6b. the broker's revoke records after admin sign-out", "a revoke by sid then by sub, but the sid is neither session's")
		fail("the revoke by sid names neither of the user's two sessions")
	case ok:
		cell("6b. the broker's revoke records after admin sign-out", fmt.Sprintf(
			"revoke by sid (session %d of 2), then revoke by sub (the user's); origin %s<issuer>", sidLabel(rsid, pairSids), oidcLogoutOrigin))
	default:
		cell("6b. the broker's revoke records after admin sign-out", fmt.Sprintf(
			"a logout request arrived, but no revoke by sid followed by a revoke by the user's sub with origin %s<issuer> "+
				"within 30s (%d revoke records)", oidcLogoutOrigin, len(reasonsOf(recs, "revoke"))))
		fail("the sign-out of a user holding two sessions left no revoke by sid then by sub within 30s")
	}
	for i, h := range pairHolders {
		tk, again := br.mintAs(t, h, l.p.node)
		cell(fmt.Sprintf("6c. session %d of 2's certificate mints again", i+1), again)
		if tk != "" || !saidRevoked(again) {
			fail("session %d of 2's certificate minted after the sign-out of its user: %s", i+1, again)
		}
	}
	// 6e recounts after 6c, so a late record is not missed; a count of 1 does
	// not also fail when 6b already failed for no records at all.
	sidRecs := countRevokes(recordsAt(c.brokerLog, boff), oidcLogoutOrigin+kc.URL, "sid")
	requests := "not measured"
	if mAfter := oidcBrokerMetrics(); hasLogoutSeries(mBefore) && hasLogoutSeries(mAfter) {
		tokens, _, _ := logoutCounts(mBefore, mAfter)
		requests = fmt.Sprintf("%.0f", tokens)
	}
	cell("6e. logout tokens Keycloak sent for the one sign-out", fmt.Sprintf("%s logout request(s) answered; %d revoke record(s) by sid", requests, sidRecs))
	if sidRecs != 1 && ok {
		fail("the sign-out sent %d logout token(s) naming a session, not one", sidRecs)
	}
	oidcDeliveryCell(c, kc, since, cell, fail, "6d")

	// ---- 7. A burst: eight sessions ended back to back. Keycloak's pooled client
	// reused a closed connection and never retried, so all but the first
	// logout was lost (7h final review F1; Connection: close on the listener).
	// Back to back, because a reused connection is what failed: eight requests
	// released at once each open a connection of their own and reuse none. The
	// user is carol: an empty token key (device, username), so the eight mints
	// fit token.candidate_cap, and a sub of her own that no earlier logout marked.
	const burst = 8
	var burstHolders []*oidcHolder
	var burstSids []string
	for i := 1; i <= burst; i++ {
		kc.HTTP = keycloakClient(idpCA)
		lg, h, ex := br.signIn(t, oidcCarol, oidcCarolPassword, 0)
		if h == nil {
			t.Fatalf("INVALID: burst session %d of %d was given no certificate: %s", i, burst, ex)
		}
		sid := sidOf(lg.IDToken)
		kc.know(sid)
		if sid == "" {
			t.Fatalf("INVALID: burst session %d of %d has an ID token with no sid", i, burst)
		}
		if tk, said := br.mintAs(t, h, l.p.node); tk == "" {
			t.Fatalf("%s", mintFault(fmt.Sprintf("burst session %d of %d", i, burst), said))
		}
		burstHolders, burstSids = append(burstHolders, h), append(burstSids, sid)
	}
	cell("7a. eight fresh Keycloak logins as carol, a certificate for each and a mint with it", "all eight minted")
	kc.HTTP = keycloakClient(idpCA)
	adminTok := kc.Admin(t)
	before := oidcBrokerMetrics()
	if !hasLogoutSeries(before) {
		// Steps 2 and 6 already logged out: the series exists unless the metrics
		// could not be read, and a delta against nothing counts steps 2 and 6 too.
		t.Fatalf("INVALID: the broker's metrics before the burst could not be read or hold no port49_oidc_logouts_total")
	}
	since = time.Now().UTC().Format(time.RFC3339)
	boff = fileSize(c.brokerLog)
	for i, sid := range burstSids {
		if err := kc.deleteSessionWith(adminTok, sid); err != nil {
			t.Fatalf("INVALID: ending burst session %d of %d: %v", i+1, burst, err)
		}
	}
	burstOrigin := oidcLogoutOrigin + kc.URL
	var missing []int
	var foreign int
	recs = waitRecordsOf(c.brokerLog, boff, 30*time.Second, func(rs []map[string]any) bool {
		missing, foreign = burstRevokes(rs, burstOrigin, burstSids)
		return len(missing) == 0
	})
	missing, foreign = burstRevokes(recs, burstOrigin, burstSids)
	if len(missing) == 0 && foreign == 0 {
		cell("7b. eight admin session ends back to back; the broker's revoke records by sid", fmt.Sprintf(
			"a revoke by sid for each of the eight burst sessions within 30s; origin %s<issuer>", oidcLogoutOrigin))
	} else {
		cell("7b. eight admin session ends back to back; the broker's revoke records by sid", fmt.Sprintf(
			"no revoke by sid within 30s for burst session(s) %v; %d record(s) by sid for no burst session", missing, foreign))
		fail("of %d back-to-back back-channel logouts, burst session(s) %v left no revoke record by sid and %d record(s) named another sid",
			burst, missing, foreign)
	}
	if after := oidcBrokerMetrics(); !hasLogoutSeries(after) {
		cell("7c. port49_oidc_logouts_total gained", "not measured: the metrics could not be read")
	} else {
		total, applied, nothing := logoutCounts(before, after)
		cell("7c. port49_oidc_logouts_total gained", fmt.Sprintf("%.0f logouts answered: %.0f applied, %.0f found nothing to end, "+
			"%.0f any other outcome (of %d ended)", total, applied, nothing, total-applied-nothing, burst))
		if !logoutAnswered(total, applied, nothing, burst) {
			fail("of %d back-to-back back-channel logouts, %.0f were answered and %.0f applied or found nothing to end", burst, total, applied+nothing)
		}
	}
	for i, h := range burstHolders {
		name := fmt.Sprintf("7d. burst session %d of %d's certificate mints again (refused by its session's logout)", i+1, burst)
		tk, again := br.mintAs(t, h, l.p.node)
		cell(name, again)
		if tk != "" || !saidRevoked(again) {
			fail("burst session %d of %d's certificate minted after its session ended: %s", i+1, burst, again)
		}
	}
	oidcDeliveryCell(c, kc, since, cell, fail, "7e")
	complete = true
}

// oidcLogoutOrigin prefixes a back-channel logout's revoke origin; the issuer follows.
const oidcLogoutOrigin = "backchannel_logout "

// subOf is the ID token's sub claim, empty when it has none.
func subOf(idToken string) string {
	_, c := claimsOf(idToken)
	s, _ := c["sub"].(string)
	return s
}

// sidOf is the ID token's sid claim, empty when it has none.
func sidOf(idToken string) string {
	_, c := claimsOf(idToken)
	s, _ := c["sid"].(string)
	return s
}

// logoutRevokes finds the revoke records one logout token wrote under ruling 13:
// the first by sid with origin, and a by sub with the same origin after it whose
// sub is subject (so a stray logout of another person cannot satisfy it).
func logoutRevokes(recs []map[string]any, origin, subject string) (bySid, bySub map[string]any, ok bool) {
	for _, rec := range recs {
		rv := sub(rec, "revocation")
		if str(rec, "event") != "revoke" || str(rv, "origin") != origin {
			continue
		}
		switch str(rv, "by") {
		case "sid":
			if bySid == nil {
				bySid = rec
			}
		case "sub":
			if bySid != nil && bySub == nil && subject != "" && str(rv, "sub") == subject {
				bySub = rec
			}
		}
	}
	return bySid, bySub, bySid != nil && bySub != nil
}

// burstRevokes matches the by-sid revoke records with origin against the sids a
// burst ended: the 1-based labels of the sids no record names, and how many
// distinct sids a record names that are not the burst's. Every logout writes its
// records whatever its outcome, so this is the per-session evidence.
func burstRevokes(recs []map[string]any, origin string, sids []string) (missing []int, foreign int) {
	named := map[string]bool{}
	for _, rec := range recs {
		rv := sub(rec, "revocation")
		if str(rec, "event") == "revoke" && str(rv, "origin") == origin && str(rv, "by") == "sid" {
			named[str(rv, "sid")] = true
		}
	}
	for i, s := range sids {
		if named[s] {
			delete(named, s)
		} else {
			missing = append(missing, i+1)
		}
	}
	return missing, len(named)
}

// countRevokes is how many revoke records with origin are by the given key.
func countRevokes(recs []map[string]any, origin, by string) int {
	n := 0
	for _, rec := range recs {
		rv := sub(rec, "revocation")
		if str(rec, "event") == "revoke" && str(rv, "origin") == origin && str(rv, "by") == by {
			n++
		}
	}
	return n
}

// loginAgainAt is the earliest time a person who logged out at at logs in again
// and is not refused by the sub record every Keycloak logout writes (ruling 13
// B): an ID token is refused until its iat passes the logout token's iat plus
// clock_skew. The extra 5s is 1s for iat's truncation to whole seconds and the
// rest margin. The e2e broker sets no clock_skew, so it is the default.
func loginAgainAt(at time.Time) time.Time {
	return at.Add(oidc.DefaultTiming.ClockSkew + 5*time.Second)
}

// mintFault is the INVALID message for a setup mint that gave no token; a
// refusal for the candidate cap says which knob it is.
func mintFault(what, said string) string {
	msg := fmt.Sprintf("INVALID: the mint of %s gave no token: %s", what, said)
	if strings.Contains(said, "candidate_cap_reached") {
		msg += " (the unspent tokens of this device and username reached token.candidate_cap, 8 by default)"
	}
	return msg
}

// sidLabel is the 1-based place in sids of the sid a revoke record names, 0 for none.
func sidLabel(rec map[string]any, sids []string) int {
	got := str(sub(rec, "revocation"), "sid")
	for i, s := range sids {
		if got != "" && got == s {
			return i + 1
		}
	}
	return 0
}

// oidcBrokerMetrics is the broker's metrics text, empty when it cannot be read.
func oidcBrokerMetrics() string {
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://127.0.0.1:9050/metrics")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return string(raw)
}

// logoutCounts is how many logouts the broker answered between two metrics
// texts, of any outcome, and how many of them applied and found nothing to end.
func logoutCounts(before, after string) (total, applied, nothing float64) {
	const name = "port49_oidc_logouts_total"
	return metricSum(after, name) - metricSum(before, name),
		metricOutcome(after, name, "applied") - metricOutcome(before, name, "applied"),
		metricOutcome(after, name, "nothing") - metricOutcome(before, name, "nothing")
}

// logoutAnswered is whether want logouts were all answered cleanly: applied, or
// nothing left to end (the first logout of a principal deletes every unspent
// token, so the later ones find none). An invalid, unavailable, store_error or
// partial outcome is the remainder and fails it.
func logoutAnswered(total, applied, nothing float64, want int) bool {
	return total == float64(want) && applied+nothing == float64(want)
}

// saidRevoked is whether a mint answer from brokerSaid or mintSaid carries the
// error code credential_revoked, and not merely a detail that mentions it. The
// code follows the status ("401 credential_revoked: ...") or, for one device's
// refusal in a 200, the principal ("200 user:a@b: credential_revoked: ...").
func saidRevoked(said string) bool {
	status, rest, ok := strings.Cut(said, " ")
	if !ok {
		return false
	}
	const code = "credential_revoked:"
	if strings.HasPrefix(rest, code) {
		return true
	}
	principal, rest, ok := strings.Cut(rest, ": ") // a 200's principal is kind:name
	return ok && status == "200" && strings.Contains(principal, ":") && strings.HasPrefix(rest, code)
}

// hasLogoutSeries is whether the metrics text holds a port49_oidc_logouts_total
// sample, which it does from the first logout the broker answers.
func hasLogoutSeries(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		if rest, ok := strings.CutPrefix(line, "port49_oidc_logouts_total"); ok && rest != "" && (rest[0] == '{' || rest[0] == ' ') {
			return true
		}
	}
	return false
}

// metricOutcome is metricSum of the samples labelled outcome="outcome".
func metricOutcome(text, name, outcome string) float64 {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, `outcome="`+outcome+`"`) {
			lines = append(lines, line)
		}
	}
	return metricSum(strings.Join(lines, "\n"), name)
}

// deliveryFailures is each line of Keycloak's log that says a back-channel
// logout failed: its own KC-SERVICES0057 ("Logout for client ... failed"), or a
// line about a backchannel logout or a logout for a client that says it failed.
// A line that only holds "logout" and "fail" (a failed-login counter) is not one.
func deliveryFailures(logs string) []string {
	var out []string
	for _, line := range strings.Split(logs, "\n") {
		low := strings.ToLower(line)
		if strings.Contains(low, "logout") && strings.Contains(low, "fail") &&
			(strings.Contains(low, "kc-services0057") || strings.Contains(low, "backchannel") || strings.Contains(low, "for client")) {
			out = append(out, line)
		}
	}
	return out
}

// deliveryCellText says how many delivery failure lines there are and the first,
// scrubbed: Keycloak's line can name a session id, and a note holding a
// registered value is refused whole.
func deliveryCellText(bad []string, secrets []string) string {
	return fmt.Sprintf("%d delivery failure line(s); first: %s", len(bad), oneLineMax(scrubbed(bad[0], secrets), 240))
}

// oidcDeliveryCell records the back-channel delivery failures in Keycloak's log
// since a time; a failure is a failed cell. A log that cannot be read is no cell
// of "none": it is said so.
func oidcDeliveryCell(c *composeStack, kc *keycloak, since string, cell func(step, what string), fail func(string, ...any), step string) {
	logs, err := c.run("logs", "--no-color", "--since", since, "keycloak")
	if err != nil {
		cell(step+". Keycloak's log in the window", "not measured: its log could not be read")
		return
	}
	bad := deliveryFailures(logs)
	if len(bad) == 0 {
		cell(step+". Keycloak's log in the window", "no back-channel delivery failure")
		return
	}
	cell(step+". Keycloak's log in the window", deliveryCellText(bad, kc.known()))
	fail("Keycloak logged %d back-channel delivery failure(s) in the window", len(bad))
}

// deleteSessionWith is the admin end of one session with a token already held,
// the error it returns without a URL; DeleteSession fatals, which a goroutine must not.
func (k *keycloak) deleteSessionWith(adminToken, sid string) error {
	req, err := http.NewRequest("DELETE", "https://"+kcHost+":"+kcPort+"/admin/realms/"+kcRealm+"/sessions/"+sid, nil)
	if err != nil {
		return errors.New(errCause(err))
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := k.HTTP.Do(req)
	if err != nil {
		return errors.New(errCause(err))
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("answered %s", resp.Status)
	}
	return nil
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
func brokerClient(t *testing.T) *http.Client { return brokerClientWith(t, nil) }

// brokerClientWith is brokerClient presenting cert when it is given.
func brokerClientWith(t *testing.T, cert *tls.Certificate) *http.Client {
	t.Helper()
	pem, err := os.ReadFile(filepath.Join(root, slicePKIDir, testpki.LabCA))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	tc := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	if cert != nil {
		tc.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}}
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
	return b.postWith(b.c, path, bearer, body)
}

// postWith is post by client c; with no bearer it sends no Authorization
// header, and c's certificate is the credential.
func (b oidcBroker) postWith(c *http.Client, path, bearer, body string) (int, string) {
	req, err := http.NewRequest("POST", b.base+path, strings.NewReader(body))
	if err != nil {
		return 0, errCause(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
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

// oidcHolder is a person's session at the broker: the client presenting the
// certificate the broker issued for the sign-in.
type oidcHolder struct{ client *http.Client }

// signIn logs user in at Keycloak with a nonce bound to a fresh key and
// exchanges the ID token for a certificate at POST /v1/certificate, retrying
// the exchange every 10s up to within while the broker is not ready. The
// holder is nil when the broker gave no certificate, and said is its answer.
func (b oidcBroker) signIn(t *testing.T, user, pass string, within time.Duration) (flowResult, *oidcHolder, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	nonce, err := api.IssuanceNonce(key.Public())
	if err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	b.kc.know(nonce)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	reqBody, _ := json.Marshal(api.IssueRequest{CSR: base64.RawURLEncoding.EncodeToString(der)})
	lg := b.kc.Login(t, user, pass, url.Values{"nonce": {nonce}})
	var cert *tls.Certificate
	_, said := retryMint(func() (string, string) {
		code, body := b.post("/v1/certificate", lg.IDToken, string(reqBody))
		if code != http.StatusOK {
			return "", brokerSaid(code, body, b.kc.known())
		}
		var out api.IssueResponse
		if json.Unmarshal([]byte(body), &out) != nil {
			return "", fmt.Sprintf("200 (a %d-byte body that is no certificate)", len(body))
		}
		block, _ := pem.Decode([]byte(out.Certificate))
		if block == nil {
			return "", "200 (a certificate that is not PEM)"
		}
		cert = &tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key}
		return "issued", fmt.Sprintf("200 %s: certificate issued", out.Principal)
	}, within, 10*time.Second)
	if cert == nil {
		return lg, nil, said
	}
	return lg, &oidcHolder{client: brokerClientWith(t, cert)}, said
}

// mintAs mints one token for device by h's certificate, and says what it got
// without the token, which is registered as a value no message may hold.
func (b oidcBroker) mintAs(t *testing.T, h *oidcHolder, device string) (string, string) {
	t.Helper()
	code, body := b.postWith(h.client, "/v1/tokens", "", `{"devices":["`+device+`"],"ttl_seconds":300}`)
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

// retryMint calls mint until it gives a token, answers anything but 503
// identity_provider_unavailable or store_unavailable or no answer at all (a
// restarted broker's published port resets connections until it listens), or
// within passes;
// every apart. store_unavailable is the broker's start gate, closed until
// its runner's first takeover is done (decision 36).
func retryMint(mint func() (string, string), within, every time.Duration) (string, string) {
	deadline := time.Now().Add(within)
	for {
		tok, said := mint()
		if tok != "" || !(strings.Contains(said, "identity_provider_unavailable") ||
			strings.Contains(said, "store_unavailable") || strings.HasPrefix(said, "no answer:")) || time.Now().After(deadline) {
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

// logoutArrival reads the broker's stderr and metrics text after a logout: the
// refusal line if the broker refused a logout request, and whether any logout
// request reached it at all (a refusal, or port49_oidc_logouts_total above 0).
func logoutArrival(brokerErr, metrics string) (refusal string, arrived bool) {
	for _, line := range strings.Split(brokerErr, "\n") {
		if strings.Contains(line, "a logout request was refused") {
			refusal = line
		}
	}
	return refusal, refusal != "" || metricSum(metrics, "port49_oidc_logouts_total") > 0
}

// metricSum is the sum of every sample of the labelled or unlabelled metric name.
func metricSum(text, name string) float64 {
	var sum float64
	for _, line := range strings.Split(text, "\n") {
		rest, ok := strings.CutPrefix(line, name)
		if !ok || rest == "" || (rest[0] != '{' && rest[0] != ' ') {
			continue
		}
		f := strings.Fields(rest[strings.LastIndexAny(rest, "} ")+1:])
		if len(f) == 0 {
			continue
		}
		if v, err := strconv.ParseFloat(f[0], 64); err == nil {
			sum += v
		}
	}
	return sum
}

// idTokenExpired says whether the ID token's exp is within margin of now.
func idTokenExpired(idToken string, now time.Time, margin time.Duration) bool {
	_, c := claimsOf(idToken)
	exp, ok := c["exp"].(float64)
	return ok && !now.Add(margin).Before(time.Unix(int64(exp), 0))
}
