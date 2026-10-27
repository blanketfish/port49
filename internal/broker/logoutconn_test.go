package broker

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

// rawConn is a client that does not retry: one TLS connection, requests
// written by hand, as Apache HttpClient's pooled connection is in front of
// Keycloak's back-channel logout (final review F1).
type rawConn struct {
	t    *testing.T
	addr string
	cfg  *tls.Config
	conn *tls.Conn
	br   *bufio.Reader
}

func (c *rawConn) dial() {
	c.t.Helper()
	if c.conn != nil {
		_ = c.conn.Close()
	}
	conn, err := tls.Dial("tcp", c.addr, c.cfg)
	if err != nil {
		c.t.Fatal(err)
	}
	c.t.Cleanup(func() { _ = conn.Close() })
	c.conn, c.br = conn, bufio.NewReader(conn)
}

// do sends one request on the held connection, as it is, and reads the
// answer. A connection the broker closed under a request surfaces as err,
// the failure a client that pools and never retries would have.
func (c *rawConn) do(method, path, body string) (*http.Response, error) {
	c.t.Helper()
	_ = c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	req := method + " " + path + " HTTP/1.1\r\nHost: broker\r\n"
	if body != "" {
		req += "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n"
	}
	if _, err := io.WriteString(c.conn, req+"\r\n"+body); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(c.br, nil)
	if err != nil {
		return nil, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp, nil
}

// send is do for a client that honours Connection: close: when the answer
// says the connection is closing, the next request goes on a new one.
func (c *rawConn) send(method, path, body string) *http.Response {
	c.t.Helper()
	resp, err := c.do(method, path, body)
	if err != nil {
		c.t.Fatalf("%s %s on the held connection: %v", method, path, err)
	}
	if resp.Close {
		c.dial()
	}
	return resp
}

// A provider that pools its connections and never retries (Keycloak) sends a
// burst of logouts down one connection: every answer to a request with no
// certificate says Connection: close before the broker closes the idle
// socket, so the client opens the next one instead of writing into a
// connection that is gone (final review F1).
func TestABurstOfLogoutsOnOnePooledConnectionAreAllApplied(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	addr := strings.TrimPrefix(startServer(t, f), "https://")
	c := &rawConn{t: t, addr: addr, cfg: &tls.Config{RootCAs: f.ca.Pool(), MinVersion: tls.VersionTLS13}}
	c.dial()
	for _, jti := range []string{"j-burst-1", "j-burst-2", "j-burst-3"} {
		form := url.Values{"logout_token": {logoutFor(t, f, iss, "", jti)}}.Encode()
		resp := c.send("POST", "/v1/logout", form)
		if resp.StatusCode != 200 {
			t.Fatalf("logout %s: status %d", jti, resp.StatusCode)
		}
		if !resp.Close {
			t.Fatalf("logout %s: the answer to a request with no certificate must say Connection: close, "+
				"Close=%v", jti, resp.Close)
		}
		first, err := f.st.PutOnce(context.Background(), jtiKey(iss.URL, jti), nil, time.Hour)
		if err != nil || first {
			t.Fatalf("logout %s was not applied by the broker (jti not on record: first=%v err=%v)", jti, first, err)
		}
	}
	if contextRevokedAt(t, f, "leaf1").IsZero() {
		t.Fatal("the logouts did not end alice's context")
	}
}

// Every answer to a request without a client certificate announces the
// close, whatever the status; a connection with a certificate keeps
// keep-alive, its session being the connection (design §7).
func TestOnlyCertificateLessAnswersAnnounceTheClose(t *testing.T) {
	f, _, _ := oidcLoggedIn(t)
	addr := strings.TrimPrefix(startServer(t, f), "https://")
	none := &rawConn{t: t, addr: addr, cfg: &tls.Config{RootCAs: f.ca.Pool(), MinVersion: tls.VersionTLS13}}
	for _, r := range []struct{ method, path, body string }{
		{"GET", "/v1/config", ""},                // 200
		{"POST", "/v1/tokens", `{"devices":[]}`}, // 401
		{"POST", "/v1/logout", "logout_token=x"}, // 400
		{"GET", "/v1/nowhere", ""},               // 404 from the mux
		{"POST", "/v1/config", ""},               // 405 from the mux
	} {
		none.dial()
		resp, err := none.do(r.method, r.path, r.body)
		if err != nil {
			t.Fatalf("%s %s: %v", r.method, r.path, err)
		}
		if !resp.Close {
			t.Errorf("%s %s (status %d): no Connection: close on a certificate-less answer", r.method, r.path, resp.StatusCode)
		}
	}
	with := &rawConn{t: t, addr: addr, cfg: &tls.Config{Certificates: []tls.Certificate{f.alice}, RootCAs: f.ca.Pool(),
		MinVersion: tls.VersionTLS13}}
	with.dial()
	for i := 0; i < 2; i++ {
		resp, err := with.do("GET", "/v1/config", "")
		if err != nil || resp.StatusCode != 200 || resp.Close {
			t.Fatalf("request %d with a certificate on one connection: err %v, resp %+v", i+1, err, resp)
		}
	}
}

// stdLog captures the standard logger, where sayOnce lines land, for the
// rest of the test.
func stdLog(t *testing.T) *lockedBuffer {
	t.Helper()
	w, prev := &lockedBuffer{}, log.Writer()
	log.SetOutput(w)
	t.Cleanup(func() { log.SetOutput(prev) })
	return w
}

// A logout whose jti the store would not take is answered 503, and Keycloak
// sends it once and never again: the operator is told, with the by-hand
// recovery of a logout nothing of which was written (final review F2).
func TestALogoutWhosePutOnceFailedSaysSo(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	var said strings.Builder
	f.b.Say = func(format string, args ...any) { said.WriteString(fmt.Sprintf(format, args...) + "\n") }
	f.b.Store = hookStore{Store: f.st, before: map[string]func() error{
		"PutOnce": func() error { return store.ErrUnavailable }}}
	raw := logoutFor(t, f, iss, "s-sub-alice", "j-secret-jti")
	if w := f.postLogout(raw); w.Code != 503 {
		t.Fatalf("%s", lshown(w))
	}
	out := said.String()
	lift := f.b.Now().Add(f.b.Identity.Timing.MaxTokenAge + 2*f.b.Identity.Timing.ClockSkew).UTC().Format(time.RFC3339)
	if !strings.Contains(out, "the store did not answer") || !strings.Contains(out, "port49 revoke --principal") ||
		!strings.Contains(out, "--lift --principal ") || !strings.Contains(out, ") only after "+lift) ||
		!strings.Contains(out, `port49 revoke --sid "s-sub-alice" --sid-issuer `) {
		t.Fatalf("the PutOnce failure said:\n%s", out)
	}
	if strings.Contains(out, raw) || strings.Contains(out, "j-secret-jti") {
		t.Fatalf("the line carries the token or its jti:\n%s", out)
	}
}

// Keys the broker cannot use give a 503 Keycloak never retries: the line
// names the cause and where the refused logouts can be found.
func TestALogoutRefusedForUnavailableKeysSaysSo(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	logs := stdLog(t)
	// The keys went stale (past jwks_max_age) and cannot be fetched.
	f.advance(72 * time.Hour)
	raw := logoutFor(t, f, iss, "s-sub-alice", "j-secret-jti2")
	iss.Fail(503)
	for i := 0; i < 2; i++ { // the second is held back by the rate limit
		if w := f.postLogout(raw); w.Code != 503 {
			t.Fatalf("%s", lshown(w))
		}
	}
	out := logs.String()
	if n := strings.Count(out, "logout: "); n != 1 || !strings.Contains(out, iss.URL) ||
		!strings.Contains(out, "keys") || !strings.Contains(out, "KC-SERVICES0057") {
		t.Fatalf("the unavailable-keys line (want exactly one, naming the issuer and the provider's log):\n%s", out)
	}
	if strings.Contains(out, raw) || strings.Contains(out, "j-secret-jti2") {
		t.Fatalf("the line carries the token or its jti:\n%s", out)
	}
}

// The no-principal sub-logout line gives the runnable command, through the
// operator's agent (final review F5).
func TestASubLogoutWithNoPrincipalNamesTheRunnableRevoke(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	var said strings.Builder
	f.b.Say = func(format string, args ...any) { said.WriteString(fmt.Sprintf(format, args...) + "\n") }
	if w := f.postLogout(logoutFor(t, f, iss, "", "j-nobody")); w.Code != 200 {
		t.Fatalf("%s", lshown(w))
	}
	if out := said.String(); !strings.Contains(out, "no principal is on record") ||
		!strings.Contains(out, "`port49 revoke --principal <principal>` (api: revoke_others") {
		t.Fatalf("the line said:\n%s", out)
	}
}
