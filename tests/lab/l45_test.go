//go:build lab

package lab

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

const l45Claim = "The back-channel logout token Keycloak sends to port49's /v1/logout when (a) the person logs " +
	"out at the end-session endpoint, (b) an administrator signs the user out of every session, and (c) an " +
	"administrator ends one session: its JWS header (alg, kid, typ); which of iss, aud, azp, iat, exp, jti, sub, " +
	"sid and events it carries, and that nonce is absent; whether its sid and its sub are the ID token's; one token " +
	"per session or per user; the request's content type; and what Keycloak does, and what its end-session " +
	"endpoint answers, when the answer is 503, 400, or the connection is refused (policy engine spec §15 L45; §13 " +
	"decision 39 rulings 12 and 13)."

func TestL45LogoutToken(t *testing.T) {
	k := startKeycloak(t)
	rcv := startReceiver(t, k)
	k.SetLogoutURL(t, rcv.URL)
	ev, evPath := oidcEvidence(t, k, "L45-keycloak")
	var obs strings.Builder
	obs.WriteString("| way | requests | content type | header | claims present | nonce | sid = ID token's | " +
		"sub = ID token's | exp − iat |\n|---|---|---|---|---|---|---|---|---|\n")
	sidOf := func(id string) string { _, c := claimsOf(id); s, _ := c["sid"].(string); return s }
	subOf := func(id string) string { _, c := claimsOf(id); s, _ := c["sub"].(string); return s }
	// row records each logout token against the ID token of the session it
	// ended: its sid, and its sub, which the sub path's owner record is
	// keyed by (pre-flight M-23).
	row := func(way string, idToken string, got []received) {
		for _, g := range got {
			var names []string
			for n := range g.Claims {
				names = append(names, n)
			}
			slices.Sort(names)
			_, nonce := g.Claims["nonce"]
			sid, _ := g.Claims["sid"].(string)
			sub, _ := g.Claims["sub"].(string)
			exp, _ := g.Claims["exp"].(float64)
			iat, _ := g.Claims["iat"].(float64)
			fmt.Fprintf(&obs, "| %s | %d | `%s` | alg %v kid %v typ %v | %s | %v | %v | %v | %vs |\n", way, len(got),
				g.ContentType, g.Header["alg"], g.Header["kid"] != nil, g.Header["typ"], strings.Join(names, ", "), nonce,
				sid != "" && sid == sidOf(idToken), sub != "" && sub == subOf(idToken), exp-iat)
			ev(way, map[string]any{"header": g.Header, "claims": g.Claims, "content_type": g.ContentType})
		}
	}

	// (a) RP-initiated logout.
	a := k.Login(t, "alice", "lab-only-alice-password", nil)
	n := len(rcv.Got())
	k.EndSession(t, a.IDToken)
	gotA := rcv.waitGot(n, 20*time.Second)[n:]
	// The precondition for every later count: Keycloak reached the receiver.
	// Without it, a "0 tokens, no retry" below is a setup fault (host-gateway,
	// the receiver's certificate, the logout URL), not a measurement.
	if len(gotA) == 0 {
		t.Fatalf("INVALID: the receiver got no request within 20s of an end-session logout: host.port49.lab, " +
			"the receiver's certificate, or the client's logout URL; no note is written")
	}
	mustBeLogoutTokens(t, k, gotA)
	row("(a) end-session endpoint", a.IDToken, gotA)

	// (b) an administrator signs alice out of every session (two open).
	b1 := k.Login(t, "alice", "lab-only-alice-password", nil)
	k.HTTP.Jar = nil // a second browser: a second session
	b2 := k.Login(t, "alice", "lab-only-alice-password", nil)
	n = len(rcv.Got())
	k.LogoutUser(t, k.UserID(t, "alice"))
	time.Sleep(5 * time.Second)
	got := rcv.waitGot(n+1, 20*time.Second)[n:]
	row("(b) admin: sign out user (2 sessions)", b1.IDToken, got)
	fmt.Fprintf(&obs, "\n(b) sent %d token(s) for 2 sessions; sids %v and %v.\n\n", len(got), sidOf(b1.IDToken), sidOf(b2.IDToken))

	// (c) an administrator ends one session.
	k.HTTP.Jar = nil
	c := k.Login(t, "alice", "lab-only-alice-password", nil)
	n = len(rcv.Got())
	k.DeleteSession(t, sidOf(c.IDToken))
	row("(c) admin: end one session", c.IDToken, rcv.waitGot(n, 20*time.Second)[n:])

	// (d) what Keycloak does with 503, 400, and a refused connection, and
	// what its end-session endpoint answers then: recorded, never fatal, since
	// that answer is part of what this row measures (pre-flight I-11).
	for _, answer := range []int{http.StatusServiceUnavailable, http.StatusBadRequest, 0} {
		k.HTTP.Jar = nil
		d := k.Login(t, "alice", "lab-only-alice-password", nil)
		n = len(rcv.Got())
		if answer == 0 {
			rcv.Stop()
		} else {
			rcv.Answer(answer)
		}
		code, err := k.EndSessionStatus(t, d.IDToken)
		time.Sleep(2 * time.Minute) // a retry within two minutes would land here
		got := rcv.Got()[n:]
		fmt.Fprintf(&obs, "- answered %s: %d request(s) in 2 minutes; the end-session endpoint answered %d (%v).\n",
			map[int]string{503: "503", 400: "400", 0: "nothing (connection refused)"}[answer], len(got), code, err)
		ev(fmt.Sprintf("(d) answer %d", answer), map[string]any{"requests": len(got), "end_session_status": code})
		if answer == 0 {
			break
		}
		rcv.Answer(200)
	}
	logs, _ := k.compose("logs", "--no-color", "--since", "10m", "keycloak").CombinedOutput()
	for _, line := range strings.Split(string(logs), "\n") {
		if strings.Contains(strings.ToLower(line), "logout") && strings.Contains(strings.ToLower(line), "fail") {
			fmt.Fprintf(&obs, "- Keycloak's log: `%s`\n", oneLineMax(line, 240))
		}
	}
	mustBeLogoutTokens(t, k, rcv.Got()) // a stray POST to the receiver is never a row
	writeOIDCResult(t, k, "L45", l45Claim, obs.String(), evPath)
}

// mustBeLogoutTokens stops the run, as INVALID, at a request that is not a
// logout token from this realm for port49-cli.
func mustBeLogoutTokens(t *testing.T, k *keycloak, got []received) {
	t.Helper()
	for i, g := range got {
		if err := checkLogoutToken(k.URL, g); err != nil {
			t.Fatalf("INVALID: request %d to the receiver is %v; no note is written", i, err)
		}
	}
}
