//go:build lab

package lab

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

const l61Claim = "Keycloak's `amr` and `acr` in an ID token for `idp_mfa`. With a realm flow of password and OTP, a " +
	"`prompt=login` sign-in with both: whether the ID token carries `amr`, and which values, with Keycloak's AMR " +
	"protocol mapper and with none; the control, a password-only sign-in, and its `amr`; whether `acr_values` changes " +
	"either (policy engine spec §15 L61; §13 decision 45 ruling 13, the default `amr: [mfa]`)."

const (
	l61Flow    = "p49-otp"
	l61Sub     = "p49-otp-mfa"
	l61User    = "alice-otp"
	l61Control = oidcAlice
)

// l61DefaultAMR is decision 45 ruling 13's default `amr`: the words a
// per_login_mfa idp_mfa proof is accepted on when the operator sets none.
var l61DefaultAMR = []string{"mfa"}

var otpFormAction = regexp.MustCompile(`<form[^>]*id="kc-otp-login-form"[^>]*action="([^"]+)"`)

// l61TOTP is RFC 6238's code (HMAC-SHA1, 6 digits, 30s) for key at step.
func l61TOTP(key []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", n%1000000)
}

// l61Words reads an ID token's claims into the two cells' words: amr (a list,
// or absent) and acr (a string, or absent). It never sees a token, only the
// decoded claims.
func l61Words(claims map[string]any) (amr []string, hasAMR bool, acr string, hasACR bool) {
	if list, ok := claims["amr"].([]any); ok {
		hasAMR = true
		for _, v := range list {
			if s, ok := v.(string); ok {
				amr = append(amr, s)
			}
		}
	} else if s, ok := claims["amr"].(string); ok {
		hasAMR, amr = true, []string{s}
	}
	acr, hasACR = claims["acr"].(string)
	return
}

// l61Cell is a cell's reading as the note says it.
func l61Cell(claims map[string]any) string {
	amr, hasAMR, acr, hasACR := l61Words(claims)
	a, c := "absent", "absent"
	if hasAMR {
		a = "[" + strings.Join(amr, " ") + "]"
	}
	if hasACR {
		c = fmt.Sprintf("%q", acr)
	}
	return fmt.Sprintf("amr %s; acr %s", a, c)
}

// l61Carries says whether amr holds any of words.
func l61Carries(claims map[string]any, words []string) bool {
	amr, _, _, _ := l61Words(claims)
	for _, w := range words {
		for _, a := range amr {
			if a == w {
				return true
			}
		}
	}
	return false
}

// l61Admin is one admin REST call that reports the status instead of failing.
func (k *keycloak) l61Admin(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "https://"+kcHost+":"+kcPort+"/admin/realms/"+kcRealm+path, rd)
	req.Header.Set("Authorization", "Bearer "+k.Admin(t))
	req.Header.Set("Content-Type", "application/json")
	resp, err := k.HTTP.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %s", method, path, errCause(err))
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func (k *keycloak) l61Must(t *testing.T, method, path string, body any) []byte {
	t.Helper()
	status, raw := k.l61Admin(t, method, path, body)
	if status/100 != 2 {
		t.Fatalf("INVALID: %s %s: %d %s; no note is written", method, path, status, oneLineMax(string(raw), 200))
	}
	return raw
}

// l61Executions is the flow's executions, in order, as the admin API lists them.
func (k *keycloak) l61Executions(t *testing.T, flow string) []map[string]any {
	t.Helper()
	var out []map[string]any
	if err := json.Unmarshal(k.l61Must(t, "GET", "/authentication/flows/"+flow+"/executions", nil), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// l61BuildFlow creates the flow p49-otp: a required sub-flow of the
// username-password form and the OTP form, both required, and returns the
// execution ids by provider (and the sub-flow's execution, under "subflow").
func (k *keycloak) l61BuildFlow(t *testing.T) (flowID string, ids map[string]string) {
	t.Helper()
	k.l61Must(t, "POST", "/authentication/flows", map[string]any{"alias": l61Flow, "providerId": "basic-flow",
		"topLevel": true, "builtIn": false})
	k.l61Must(t, "POST", "/authentication/flows/"+l61Flow+"/executions/flow", map[string]any{"alias": l61Sub,
		"type": "basic-flow", "provider": "registration-page-form"})
	for _, p := range []string{"auth-username-password-form", "auth-otp-form"} {
		k.l61Must(t, "POST", "/authentication/flows/"+l61Sub+"/executions/execution", map[string]any{"provider": p})
	}
	ids = map[string]string{}
	for _, e := range k.l61Executions(t, l61Flow) {
		e["requirement"] = "REQUIRED"
		k.l61Must(t, "PUT", "/authentication/flows/"+l61Flow+"/executions", e)
		if flow, _ := e["authenticationFlow"].(bool); flow {
			ids["subflow"] = e["id"].(string)
		} else {
			ids[e["providerId"].(string)] = e["id"].(string)
		}
	}
	var flows []map[string]any
	if err := json.Unmarshal(k.l61Must(t, "GET", "/authentication/flows", nil), &flows); err != nil {
		t.Fatal(err)
	}
	for _, f := range flows {
		if f["alias"] == l61Flow {
			return f["id"].(string), ids
		}
	}
	t.Fatal("INVALID: the flow just made is not listed; no note is written")
	return "", nil
}

// l61SetBrowserFlow binds port49-cli's browser flow to flowID, or to the
// realm's default when flowID is "".
func (k *keycloak) l61SetBrowserFlow(t *testing.T, flowID string) {
	t.Helper()
	c, _ := k.redirects(t)
	if flowID == "" {
		var flows []map[string]any
		if err := json.Unmarshal(k.l61Must(t, "GET", "/authentication/flows", nil), &flows); err != nil {
			t.Fatal(err)
		}
		for _, f := range flows {
			if f["alias"] == "browser" {
				flowID = f["id"].(string)
			}
		}
	}
	c["authenticationFlowBindingOverrides"] = map[string]any{"browser": flowID}
	k.l61Must(t, "PUT", "/clients/"+c["id"].(string), c)
}

// l61Reference sets an execution's AMR reference value, and says what the
// admin API answered.
func (k *keycloak) l61Reference(t *testing.T, execID, alias, word string) string {
	t.Helper()
	status, raw := k.l61Admin(t, "POST", "/authentication/executions/"+execID+"/config", map[string]any{
		"alias": alias, "config": map[string]string{"default.reference.value": word, "default.reference.maxAge": "3600"}})
	return fmt.Sprintf("%d %s", status, oneLineMax(string(raw), 120))
}

// l61AddMapper adds the AMR protocol mapper to port49-cli.
func (k *keycloak) l61AddMapper(t *testing.T) {
	t.Helper()
	c, _ := k.redirects(t)
	k.l61Must(t, "POST", "/clients/"+c["id"].(string)+"/protocol-mappers/models", map[string]any{
		"name": "amr", "protocol": "openid-connect", "protocolMapper": "oidc-amr-mapper",
		"config": map[string]string{"id.token.claim": "true", "access.token.claim": "false",
			"introspection.token.claim": "false"}})
}

// l61SignIn is a prompt=login sign-in as user in a fresh browser: the
// password form, then the OTP form when one is shown. It returns the code, its
// verifier, and whether an OTP form was shown. A TOTP code is never reused
// within its 30s step: Keycloak refuses one.
func (k *keycloak) l61SignIn(t *testing.T, user, pass string, seed []byte, last *int64, extra url.Values) (string, string, bool) {
	t.Helper()
	browser := k.l55Browser()
	verifier := randomSecret(t) + randomSecret(t)
	resp, err := browser.Get(k.l55Authorize(t, kcRedirect, verifier, extra))
	if err != nil {
		t.Fatalf("authorize: %s", errCause(err))
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := formAction.FindSubmatch(body)
	if resp.StatusCode != http.StatusOK || m == nil {
		t.Fatalf("INVALID: authorize answered %s with no login form; no note is written", resp.Status)
	}
	if resp, err = browser.PostForm(html.UnescapeString(string(m[1])), url.Values{"username": {user},
		"password": {pass}, "credentialId": {""}}); err != nil {
		t.Fatalf("login: %s", errCause(err))
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	asked := false
	if o := otpFormAction.FindSubmatch(body); resp.StatusCode == http.StatusOK && o != nil {
		asked = true
		step := time.Now().Unix() / 30
		if step <= *last {
			time.Sleep(time.Duration(30-time.Now().Unix()%30+1) * time.Second)
			step = time.Now().Unix() / 30
		}
		*last = step
		code := l61TOTP(seed, step)
		if resp, err = browser.PostForm(html.UnescapeString(string(o[1])), url.Values{"otp": {code},
			"selectedCredentialId": {""}}); err != nil {
			t.Fatalf("otp: %s", errCause(err))
		}
		resp.Body.Close()
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || err != nil || loc.Query().Get("code") == "" {
		t.Fatalf("INVALID: %s's sign-in gave no code (%s, redirect %s, otp form %v); no note is written", user,
			resp.Status, locShape(loc), asked)
	}
	k.know(loc.Query().Get("code"))
	return loc.Query().Get("code"), verifier, asked
}

func TestL61KeycloakAMR(t *testing.T) {
	k := startKeycloak(t)
	ev, evPath := oidcEvidence(t, k, "L61-keycloak")
	var obs strings.Builder
	obs.WriteString("| cell | observed |\n|---|---|\n")
	cell := func(step, what string) {
		fmt.Fprintf(&obs, "| %s | %s |\n", step, wideCell(what))
		ev(step, what)
	}

	// The OTP user. Its seed is made for this run, held here and never printed.
	seedText := randomSecret(t)[:20]
	seed := []byte(seedText)
	k.know(seedText)
	status, raw := k.l61Admin(t, "POST", "/users", map[string]any{"username": l61User, "enabled": true,
		"email": "alice-otp@corp.example.com", "emailVerified": true, "firstName": "Alice", "lastName": "Otp",
		"credentials": []map[string]any{
			{"type": "password", "value": oidcAlicePassword, "temporary": false},
			{"type": "otp", "secretData": `{"value":"` + seedText + `"}`,
				"credentialData": `{"subType":"totp","digits":6,"period":30,"algorithm":"HmacSHA1","counter":0}`}}})
	if status/100 != 2 {
		t.Fatalf("INVALID: the OTP user was not made: %d %s; no note is written", status, oneLineMax(string(raw), 200))
	}
	flowID, ids := k.l61BuildFlow(t)
	var last int64

	// (a) password and OTP, no AMR mapper.
	k.l61SetBrowserFlow(t, flowID)
	code, verifier, asked := k.l61SignIn(t, l61User, oidcAlicePassword, seed, &last, nil)
	if !asked {
		t.Fatal("INVALID: cell a was not asked for an OTP; the flow is not bound; no note is written")
	}
	a := k.l55IDClaims(t, code, verifier, "a")
	cell("a. password and OTP, no AMR mapper", l61Cell(a))

	// (b) the same, the mapper on the client and the references set.
	k.l61AddMapper(t)
	cfg := []string{
		"auth-username-password-form -> pwd: " + k.l61Reference(t, ids["auth-username-password-form"], "p49-ref-pwd", "pwd"),
		"auth-otp-form -> otp: " + k.l61Reference(t, ids["auth-otp-form"], "p49-ref-otp", "otp"),
		"sub-flow -> mfa: " + k.l61Reference(t, ids["subflow"], "p49-ref-mfa", "mfa"),
	}
	for _, c := range cfg {
		cell("config. reference value set on the execution", c)
	}
	code, verifier, asked = k.l61SignIn(t, l61User, oidcAlicePassword, seed, &last, nil)
	if !asked {
		t.Fatal("INVALID: cell b was not asked for an OTP; no note is written")
	}
	b := k.l55IDClaims(t, code, verifier, "b")
	cell("b. password and OTP, the AMR mapper, references pwd, otp and mfa", l61Cell(b))

	// (c) the control: password only, the realm's default flow, the mapper still on.
	k.l61SetBrowserFlow(t, "")
	code, verifier, asked = k.l61SignIn(t, l61Control, oidcAlicePassword, nil, &last, nil)
	if asked {
		t.Fatal("INVALID: the control was asked for an OTP; no note is written")
	}
	c := k.l55IDClaims(t, code, verifier, "c")
	cell("c. control: password only (alice, the default flow), the AMR mapper", l61Cell(c))

	// (d) (b) with acr_values=gold asked.
	k.l61SetBrowserFlow(t, flowID)
	code, verifier, asked = k.l61SignIn(t, l61User, oidcAlicePassword, seed, &last, url.Values{"acr_values": {"gold"}})
	if !asked {
		t.Fatal("INVALID: cell d was not asked for an OTP; no note is written")
	}
	d := k.l55IDClaims(t, code, verifier, "d")
	cell("d. (b) with acr_values=gold asked", l61Cell(d))

	// (e) the remedy a failed gate points to: the OTP execution's own reference
	// value set to the default word, so the mapper emits it.
	var otpConfig string
	for _, e := range k.l61Executions(t, l61Flow) {
		if e["id"] == ids["auth-otp-form"] {
			otpConfig, _ = e["authenticationConfig"].(string)
		}
	}
	if otpConfig == "" {
		t.Fatal("INVALID: the OTP execution has no config to change; no note is written")
	}
	k.l61Must(t, "PUT", "/authentication/config/"+otpConfig, map[string]any{"id": otpConfig, "alias": "p49-ref-otp",
		"config": map[string]string{"default.reference.value": l61DefaultAMR[0], "default.reference.maxAge": "3600"}})
	code, verifier, asked = k.l61SignIn(t, l61User, oidcAlicePassword, seed, &last, nil)
	if !asked {
		t.Fatal("INVALID: cell e was not asked for an OTP; no note is written")
	}
	e := k.l55IDClaims(t, code, verifier, "e")
	cell("e. (b) with the OTP execution's reference value set to "+l61DefaultAMR[0], l61Cell(e))

	m1 := l61Carries(b, l61DefaultAMR) && !l61Carries(c, l61DefaultAMR)
	cell("Gate M1. (b) carries one of "+fmt.Sprint(l61DefaultAMR)+" and (c) does not",
		fmt.Sprintf("%v (b carries: %v; c carries: %v)", m1, l61Carries(b, l61DefaultAMR), l61Carries(c, l61DefaultAMR)))
	preface := "The realm flow `" + l61Flow + "` (made through the admin API at run time) is a required sub-flow of " +
		"Keycloak's username-password form and its OTP form, bound to `port49-cli` as its browser flow; `" + l61User +
		"` holds a password and a TOTP credential whose seed is made per run and never written. Each sign-in is " +
		"`prompt=login` in a fresh browser. The AMR mapper is Keycloak's `oidc-amr-mapper`, added to the client; the " +
		"reference values are the executions' `default.reference.value` (cell config). Cell e is the remedy cell b " +
		"points to when the gate fails.\n\n"
	writeOIDCResult(t, k, "L61", l61Claim, preface+obs.String(), evPath)
}
