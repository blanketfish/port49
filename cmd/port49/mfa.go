package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/mfatouch"
	"github.com/rhwendt/port49/internal/oidcclient"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/userconfig"
)

// describeMFA is the sentence a per-login requirement is told in (decision 45
// ruling 17): who asks, what each level accepts, how long a proof is reused
// and where each part came from. Everything in it is the broker's text, made
// safe to print.
func describeMFA(req api.PerLoginMFA) string {
	who := "a device in your session"
	if req.Device != "" {
		who = printsafe.Line(req.Device, 128)
	}
	var levels []string
	for _, l := range req.Levels {
		levels = append(levels, fmt.Sprintf("%s accepts %s", printsafe.Line(l.Level, 128), methodList(l.Accept)))
	}
	if len(levels) == 0 {
		levels = []string{"accepts " + methodList(req.Accept)}
	}
	return fmt.Sprintf("%s asks for a second factor at each login: %s (%s)", who, strings.Join(levels, "; "),
		reuseText(req.ReuseForSeconds, req.ReuseFrom))
}

func methodList(methods []string) string {
	safe := make([]string, len(methods))
	for i, m := range methods {
		safe[i] = printsafe.Line(m, 64)
	}
	return strings.Join(safe, ", ")
}

// reuseText is "reuse 15m, from scope core", or "not reused" for a proof that
// covers one login.
func reuseText(seconds int, from string) string {
	text := "not reused"
	if seconds > 0 {
		d := (time.Duration(seconds) * time.Second).String()
		if strings.HasSuffix(d, "m0s") {
			d = strings.TrimSuffix(d, "0s") // 15m0s is 15m
		}
		if strings.HasSuffix(d, "h0m") {
			d = strings.TrimSuffix(d, "0m") // 1h0m is 1h
		}
		text = "reuse " + d
	}
	if from != "" {
		text += ", from " + printsafe.Line(from, 128)
	}
	return text
}

// proveFlags is the little of a session the proof needs when a command was
// not given it as flags: the broker and its CA, and the sign-in's provider,
// all from the config file.
func proveFlags(socket string) *sessionFlags {
	return &sessionFlags{socket: socket, configFile: userconfig.Path()}
}

// mintProved is the agent's Token, and for a device that asks for a second
// factor it proves the requirement (prove) and asks again, naming the
// challenge, once: a second requirement is the answer, never another
// challenge. The error is the agent's, as mintFailed says it.
func mintProved(ctx context.Context, sf *sessionFlags, req agent.TokenRequest, stderr io.Writer) (api.MintItem, error) {
	c := agent.NewClient(sf.socket)
	item, err := c.Token(ctx, req)
	var need *agent.MFARequiredError
	if !errors.As(err, &need) {
		return item, err
	}
	if err := prove(ctx, sf.socket, sf, need.Requirement, stderr); err != nil {
		return api.MintItem{}, &mfaUnprovedError{Requirement: need.Requirement, Err: err}
	}
	req.PerLoginMFAChallenge = need.Requirement.Challenge
	return c.Token(ctx, req)
}

// mfaUnprovedError is a requirement prove could not meet: Error is the
// proof's own words, as mintFailed always said them.
type mfaUnprovedError struct {
	Requirement api.PerLoginMFA
	Err         error
}

func (e *mfaUnprovedError) Error() string { return e.Err.Error() }
func (e *mfaUnprovedError) Unwrap() error { return e.Err }

// prove answers a requirement with the first factor it can: the agent's touch
// key when the agent holds a usable one and the broker verifies the touch, or
// else, at a terminal, a sign-in at the identity provider with the nonce the
// challenge fixes. A touch key that cannot prove is never tried: the agent's
// status says why, and that is said (pre-flight I6). Neither the challenge
// nor a signature nor an ID token is printed.
func prove(ctx context.Context, socket string, sf *sessionFlags, req api.PerLoginMFA, stderr io.Writer) error {
	fmt.Fprintf(stderr, "port49: %s\n", describeMFA(req))
	c := agent.NewClient(socket)
	st, err := c.Status(ctx)
	if err != nil {
		return err
	}
	methods := req.Methods
	if len(methods) == 0 {
		methods = req.Accept
	}
	touch, idp := slices.Contains(methods, "hardware_key_touch"), slices.Contains(methods, "idp_mfa")
	if touch && st.TouchKey {
		// The key's state is checked first, then the prompt (ruling 18): a key
		// that is out, locked or without attestations is never asked to blink.
		why := touchUnavailable(st.TouchKeyState)
		if why == "" {
			fmt.Fprintln(stderr, "port49: touch your key now")
			err := c.ProveTouch(ctx, req.Challenge)
			if !errors.Is(err, mfatouch.ErrNoAttestation) || !idp || !stdinIsTerminal() {
				return err
			}
			why = touchUnavailable("no_attestation") // the state changed under the prompt
		} else if !idp || !stdinIsTerminal() {
			// No fallback to take: the agent's own words (insert your key).
			return c.ProveTouch(ctx, req.Challenge)
		}
		fmt.Fprintf(stderr, "port49: %s; falling back to idp_mfa (a sign-in at your identity provider)\n", why)
		return proveBySignIn(ctx, sf, st, req, stderr)
	}
	if touch && st.TouchKeyUnusable != "" {
		fmt.Fprintf(stderr, "port49: %s\n", printsafe.Line(st.TouchKeyUnusable, 300))
	}
	switch {
	case idp && !stdinIsTerminal():
		return errors.New("this device asks for a sign-in at your identity provider and there is no terminal; run it at a terminal")
	case idp:
		return proveBySignIn(ctx, sf, st, req, stderr)
	case touch:
		return errors.New("this device accepts only hardware_key_touch, and the agent has no touch key it can use: " +
			"set touch_key to a key on your session key's token, and run `port49 login` again")
	}
	return fmt.Errorf("this broker verifies none of the methods this device accepts (%s)", methodList(req.Accept))
}

// proveBySignIn is the idp_mfa proof: a sign-in at the provider the broker
// lists, prompt=login, the broker's acr_values, and nonce = api.MFANonce of
// the challenge; its ID token goes to POST /v1/mfa as the bearer, once, with
// no client certificate.
func proveBySignIn(ctx context.Context, sf *sessionFlags, st agent.Status, req api.PerLoginMFA, stderr io.Writer) error {
	adoptAgentSession(sf, st)
	if err := sf.fill(flag.NewFlagSet("port49", flag.ContinueOnError)); err != nil {
		return err
	}
	pool, err := sf.brokerPool()
	if err != nil {
		return fmt.Errorf("the sign-in needs the broker's CA (the agent's session has none to give; broker_ca in %s): %w",
			sf.configFile, err)
	}
	verify, err := sf.verifyBroker(stderr)
	if err != nil {
		return err
	}
	conf, err := fetchBrokerConfig(ctx, sf.broker, pool, verify)
	if err != nil {
		return err
	}
	prov, err := pickProvider(conf, sf.issuer)
	if err != nil {
		return err
	}
	roots, err := sf.oidcRoots()
	if err != nil {
		return err
	}
	p := oidcclient.Provider{Issuer: prov.Issuer, ClientID: prov.ClientID, Scopes: prov.Scopes, Roots: roots}
	e, err := oidcclient.Discover(ctx, p)
	if err != nil {
		return err
	}
	ch, err := mfatouch.Challenge(req.Challenge)
	if err != nil {
		return err
	}
	acr := ""
	if conf.PerLoginMFA != nil {
		acr = conf.PerLoginMFA.ACRValues
	}
	tokens, err := signIn(ctx, p, e, api.MFANonce(ch), acr, sf.redirectPort, sf.noBrowser, stderr)
	if err != nil {
		return err
	}
	warnSkew(stderr, "port49", tokens)
	return postIdPProof(ctx, sf.broker, pool, verify, tokens.IDRaw, req.Challenge)
}

// postIdPProof is POST /v1/mfa with the sign-in's ID token the bearer, over
// TLS 1.3 to the broker's CA alone, with the broker CRL check on the
// connection and no redirect followed: the token goes to the broker named and
// nowhere else. A broker the check refuses is the check's own error, never
// "unreachable".
func postIdPProof(ctx context.Context, broker string, pool *x509.CertPool, verify func(tls.ConnectionState) error,
	idToken, challenge string) error {
	body, err := json.Marshal(api.MFAProofRequest{Challenge: challenge, Method: "idp_mfa"})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(broker, "/")+"/v1/mfa", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+idToken)
	req.Header.Set("Content-Type", "application/json")
	c := &http.Client{CheckRedirect: mfatouch.NoRedirect, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: pool, VerifyConnection: verify}}}
	resp, err := c.Do(req)
	if err != nil {
		if refused := refusedByCRL(err); refused != nil {
			return refused
		}
		return &agent.BrokerUnavailableError{Err: fmt.Errorf("the broker at %s is unreachable: %w", broker, err)}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	var e api.Error
	_ = json.Unmarshal(raw, &e)
	if e.Error == "" {
		return fmt.Errorf("the broker did not take your sign-in as the second factor: it answered %s", resp.Status)
	}
	return fmt.Errorf("the broker did not take your sign-in as the second factor: %s (%s)",
		printsafe.Line(e.Detail, 400), printsafe.Line(e.Error, 64))
}
