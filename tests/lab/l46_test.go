//go:build lab

package lab

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

const l46Claim = "On Keycloak, with an SSO session live: whether a plain second authorization request reuses it " +
	"(the control); whether one with prompt=login makes the person enter their password again; whether the new ID " +
	"token's auth_time is the new authentication's; whether it carries the request's nonce; whether its sid is the " +
	"old session's; what a refresh-token grant's ID token carries (auth_time, nonce, sid); max_age=0 against " +
	"prompt=login; the ID token's preferred_username for a user created as \"alice\"; and which of auth_time, sid, " +
	"nonce, scp, amr, idtyp, azp, client_id and sub a client-credentials access token carries beside a person's " +
	"access token (policy engine spec §15 L46; §5.6; §13 decision 39 rulings 15, 21 and 23)."

func TestL46FreshAuthentication(t *testing.T) {
	k := startKeycloak(t)
	ev, evPath := oidcEvidence(t, k, "L46-keycloak")
	var obs strings.Builder
	obs.WriteString("| step | password asked | auth_time | nonce | sid |\n|---|---|---|---|---|\n")
	at := func(id string) (float64, string, string) {
		_, c := claimsOf(id)
		a, _ := c["auth_time"].(float64)
		n, _ := c["nonce"].(string)
		s, _ := c["sid"].(string)
		return a, n, s
	}
	step := func(name string, r flowResult) (float64, string, string) {
		a, n, s := at(r.IDToken)
		fmt.Fprintf(&obs, "| %s | %v | %s | %q | %s |\n", name, r.SawLoginForm, time.Unix(int64(a), 0).UTC().Format(time.RFC3339), n, s)
		h, c := claimsOf(r.IDToken)
		ev(name, map[string]any{"header": h, "claims": c, "password_asked": r.SawLoginForm})
		return a, n, s
	}
	first := k.Login(t, "alice", "lab-only-alice-password", url.Values{"nonce": {"n-first"}})
	a1, _, s1 := step("1. first login, nonce n-first", first)
	time.Sleep(3 * time.Second)
	// 1b. The control (pre-flight I-7): a plain second login in the same
	// browser session reuses SSO, so no form is shown and auth_time stays.
	// Without it, step 2's "password asked" could be a cookie-jar fault, not
	// prompt=login, and Ruling 15's refresh_not_fresh would rest on nothing.
	reuse := k.Login(t, "alice", "lab-only-alice-password", url.Values{"nonce": {"n-reuse"}})
	ar, _, _ := step("1b. plain second login (control), nonce n-reuse", reuse)
	if reuse.SawLoginForm || ar != a1 {
		t.Fatalf("the control failed: a plain second login showed the form (%v) or moved auth_time (%v to %v): the "+
			"SSO session is not reused, so step 2 cannot show what prompt=login does; no note is written",
			reuse.SawLoginForm, a1, ar)
	}
	time.Sleep(3 * time.Second)
	again := k.Login(t, "alice", "lab-only-alice-password", url.Values{"prompt": {"login"}, "nonce": {"n-again"}})
	a2, n2, s2 := step("2. prompt=login, nonce n-again", again)
	time.Sleep(3 * time.Second)
	ref := k.Refresh(t, again.RefreshToken)
	a3, n3, s3 := step("3. refresh-token grant", ref)
	time.Sleep(3 * time.Second)
	maxAge := k.Login(t, "alice", "lab-only-alice-password", url.Values{"max_age": {"0"}, "nonce": {"n-maxage"}})
	a4, _, _ := step("4. max_age=0, nonce n-maxage", maxAge)
	fmt.Fprintf(&obs, "\n- prompt=login moved auth_time by %ds and asked for the password: %v; its nonce is the "+
		"request's: %v; its sid is the first login's: %v.\n", int(a2-a1), again.SawLoginForm, n2 == "n-again", s2 == s1)
	fmt.Fprintf(&obs, "- The refresh-token grant's auth_time is the last authentication's: %v (%ds after it); "+
		"its nonce: %q; its sid unchanged: %v.\n", a3 == a2, int(a3-a2), n3, s3 == s2)
	fmt.Fprintf(&obs, "- max_age=0 asked for the password: %v, and moved auth_time by %ds.\n", maxAge.SawLoginForm, int(a4-a2))
	// The row closes for Ruling 15 only if all three hold (Task 16 Step 5).
	fmt.Fprintf(&obs, "- **Ruling 15 may close on this run:** %v (the control held: true; prompt=login moved auth_time "+
		"forward: %v; the nonce was echoed: %v).\n", a2 > a1 && n2 == "n-again", a2 > a1, n2 == "n-again")

	// The principal claim (Ruling 23; pre-flight I-6) and the access tokens
	// (Ruling 21; pre-flight C-1): which session claims a client-credentials
	// token carries beside a person's, and the sub each names.
	_, ic := claimsOf(first.IDToken)
	fmt.Fprintf(&obs, "- The ID token's preferred_username for a user created as \"alice\": %q.\n", ic["preferred_username"])
	svc := k.ServiceToken(t)
	_, sc := claimsOf(svc)
	_, pc := claimsOf(again.AccessToken)
	ev("access tokens", map[string]any{"client_credentials": sc, "person": pc})
	obs.WriteString("\n| claim | client-credentials token | person's access token |\n|---|---|---|\n")
	var markers []string
	for _, name := range []string{"auth_time", "sid", "nonce", "scp", "amr", "idtyp", "azp", "client_id", "sub", "scope",
		"session_state", "aud"} {
		sv, sOK := sc[name]
		pv, pOK := pc[name]
		fmt.Fprintf(&obs, "| %s | %s | %s |\n", name, claimCell(sv, sOK), claimCell(pv, pOK))
		if sOK && slices.Contains([]string{"auth_time", "sid", "nonce", "scp", "amr"}, name) {
			markers = append(markers, name)
		}
	}
	fmt.Fprintf(&obs, "\n- Ruling 21's markers on the client-credentials token: %v (the ruling rests on none).\n", markers)
	fmt.Fprintf(&obs, "- The client-credentials token's sub is the service account's fixed id %s: %v.\n",
		kcServiceAccountID, sc["sub"] == kcServiceAccountID)
	writeOIDCResult(t, k, "L46", l46Claim, obs.String(), evPath)
	if sc["sub"] != kcServiceAccountID {
		t.Errorf("the service account's sub is %v, not realm.json's fixed id: Task 16's clients pin would refuse it; "+
			"fix the realm import, never the pin", sc["sub"])
	}
}

// claimCell is a claim's cell: its value when short, "present" when long, or
// "absent".
func claimCell(v any, ok bool) string {
	if !ok {
		return "absent"
	}
	if s := fmt.Sprint(v); len(s) <= 60 {
		return "`" + s + "`"
	}
	return "present"
}
