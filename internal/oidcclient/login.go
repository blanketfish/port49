package oidcclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/printsafe"
)

// SignInWait is how long a sign-in waits for the browser, and how old a
// sign-in's authentication may be when the broker exchanges it for a
// certificate (spec §13 decision 43 ruling 8).
const SignInWait = 5 * time.Minute

// ErrNoWayBack is a sign-in that cannot complete: no browser opened on this
// host, stdin is no terminal to paste the address into, and the port is an
// ephemeral one no ssh -L could have forwarded (decision 43 ruling 5). It is
// said at once, not after SignInWait.
var ErrNoWayBack = errors.New("no browser opened on this host and stdin is not a terminal to paste the address " +
	"into, so the sign-in's answer has no way back to port49")

// LoginOptions is one sign-in.
type LoginOptions struct {
	// Nonce is the request's nonce: the key binding a login sends
	// (api.IssuanceNonce; decision 43 ruling 3), or "" for one drawn here.
	Nonce string
	// Port is the loopback listener's; 0 is an ephemeral one (RFC 8252 §7.3).
	Port int
	// Browser opens the authorization URL; nil, or an error, means no
	// browser opened.
	Browser func(url string) error
	// Paste, when not nil, reads one address the browser ended on, from a
	// terminal and not echoed (decision 43 ruling 5).
	Paste func() (string, error)
	// Out is where the address and the waiting line go: stderr.
	Out io.Writer
	Now func() time.Time
}

// Login runs one sign-in (decision 43 rulings 1, 3–5): the authorization
// request with PKCE (S256) and prompt=login, its answer taken at a
// 127.0.0.1 listener or pasted, and the code exchanged. The authorization
// URL is printed to o.Out: it carries state, the nonce and the
// code_challenge, none a credential, since the code is bound to the
// verifier this call holds; but whoever holds its state can complete this
// sign-in with their own account, so the caller says whom it signed in as
// (ruling 20). With no way for the answer to come back, it is ErrNoWayBack
// at once.
func Login(ctx context.Context, p Provider, e Endpoints, o LoginOptions) (Tokens, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Out == nil {
		o.Out = io.Discard
	}
	verifier, state, nonce := opaque(), opaque(), o.Nonce
	if nonce == "" {
		nonce = opaque()
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(o.Port)))
	if err != nil {
		return Tokens{}, fmt.Errorf("listening on 127.0.0.1:%d for the sign-in's answer: %w", o.Port, err)
	}
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", ln.Addr().(*net.TCPAddr).Port)
	authURL, err := AuthorizationURL(p, e, redirect, state, nonce, challengeOf(verifier))
	if err != nil {
		ln.Close()
		return Tokens{}, err
	}
	w := &waiter{state: state, issuer: p.Issuer, requireIss: e.IssParameter, redirect: redirect,
		done: make(chan answer, 1)}
	srv := &http.Server{Handler: w, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	opened := o.Browser != nil && o.Browser(authURL) == nil
	switch {
	case opened:
		fmt.Fprintf(o.Out, "port49: sign in at %s in the browser that opened; if none did, open this address:\n  %s\n",
			p.Issuer, authURL)
	case o.Paste == nil && o.Port == 0:
		// No browser here, no terminal to paste into, and a port no ssh -L
		// can name in advance: nothing can bring the answer back.
		return Tokens{}, ErrNoWayBack
	default:
		fmt.Fprintf(o.Out, "port49: open this address in a browser and sign in at %s:\n  %s\n", p.Issuer, authURL)
	}
	switch {
	case o.Paste != nil:
		fmt.Fprintf(o.Out, "port49: waiting up to %s. If the browser ends on a page that cannot be reached (it runs on "+
			"another host), copy that page's address and paste it here (it is not shown), then press Enter:\n", SignInWait)
		go w.readPastes(o.Paste, o.Out)
	case !opened:
		fmt.Fprintf(o.Out, "port49: waiting up to %s for the browser to come back to %s; from another host, forward "+
			"that port first (ssh -L %d:127.0.0.1:%d)\n", SignInWait, redirect, o.Port, o.Port)
	}
	wait, cancel := context.WithTimeout(ctx, SignInWait)
	defer cancel()
	var a answer
	select {
	case a = <-w.done:
	case <-wait.Done():
		if ctx.Err() != nil {
			return Tokens{}, ctx.Err()
		}
		return Tokens{}, fmt.Errorf("no sign-in answer reached port49 within %s; run the command again", SignInWait)
	}
	if a.err != nil {
		return Tokens{}, a.err
	}
	return exchange(ctx, p, e, a.code, redirect, verifier, nonce, o.Now)
}

// answer is a sign-in's outcome: a code, or why there is none.
type answer struct {
	code string
	err  error
}

// waiter takes the provider's answer at /callback, or pasted. The first
// answer carrying this sign-in's state ends the wait; one carrying another
// state is refused and waited past, since anyone on the host can reach the
// port (decision 43 ruling 4).
type waiter struct {
	state, issuer, redirect string
	requireIss              bool
	once                    sync.Once
	done                    chan answer
}

func (w *waiter) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Referrer-Policy", "no-referrer")
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if r.Method != http.MethodGet || r.URL.Path != "/callback" {
		http.NotFound(rw, r)
		return
	}
	a, ours := w.judge(r.URL.Query())
	if !ours {
		rw.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(rw, "port49: this is not the sign-in port49 is waiting for; nothing was done.")
		return
	}
	w.deliver(a)
	if a.err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(rw, "port49: the sign-in failed; your terminal says why.")
		return
	}
	fmt.Fprintln(rw, "port49: signed in. You can close this tab and go back to your terminal.")
}

// deliver hands the first answer to Login; later ones are dropped.
func (w *waiter) deliver(a answer) { w.once.Do(func() { w.done <- a }) }

// judge reads one answer's query (RFC 6749 §4.1.2, RFC 9207 §2.4). ours is
// whether it carries this sign-in's state, and only then is it judged.
func (w *waiter) judge(q url.Values) (answer, bool) {
	if len(q["state"]) != 1 || q.Get("state") != w.state {
		return answer{}, false
	}
	switch iss, has := q.Get("iss"), q.Has("iss"); {
	case len(q["iss"]) > 1:
		return answer{err: fmt.Errorf("the sign-in's answer carries %d iss values where RFC 9207 allows one, "+
			"so it is refused", len(q["iss"]))}, true
	case has && iss != w.issuer:
		return answer{err: fmt.Errorf("the sign-in's answer names the issuer %q, not %s: it came from another "+
			"provider (RFC 9207), so it is refused", printsafe.Line(iss, 200), w.issuer)}, true
	case !has && w.requireIss:
		return answer{err: fmt.Errorf("the sign-in's answer carries no iss, which %s says it always sends (RFC 9207), "+
			"so it is refused", w.issuer)}, true
	}
	if e := q.Get("error"); e != "" {
		msg := fmt.Sprintf("%s refused the sign-in: %s", w.issuer, printsafe.Line(e, 64))
		if d := q.Get("error_description"); d != "" {
			msg += ": " + printsafe.Line(d, 200)
		}
		return answer{err: errors.New(msg)}, true
	}
	if len(q["code"]) != 1 || q.Get("code") == "" {
		return answer{err: errors.New("the sign-in's answer carries no code")}, true
	}
	return answer{code: q.Get("code")}, true
}

// readPastes reads pasted addresses until one is this sign-in's answer, or
// paste fails (the terminal closed). Nothing pasted is printed.
func (w *waiter) readPastes(paste func() (string, error), out io.Writer) {
	for {
		s, err := paste()
		if err != nil {
			return
		}
		a, why := w.pasted(s)
		if why != "" {
			fmt.Fprintf(out, "port49: %s; paste the address again:\n", why)
			continue
		}
		w.deliver(a)
		return
	}
}

// pasted is one pasted address as an answer, or why it is not one.
func (w *waiter) pasted(s string) (answer, string) {
	u, err := url.Parse(strings.TrimSpace(s))
	want, _ := url.Parse(w.redirect)
	if err != nil || u.Scheme != want.Scheme || u.Host != want.Host || u.Path != want.Path {
		return answer{}, "that is not the address the sign-in was sent back to (" + w.redirect + "?…)"
	}
	a, ours := w.judge(u.Query())
	if !ours {
		return answer{}, "that address answers another sign-in (its state is not this one's)"
	}
	return a, ""
}
