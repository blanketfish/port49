package broker

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
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
