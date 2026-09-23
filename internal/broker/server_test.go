package broker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/testpki"
)

func startServer(t *testing.T, f *fixture) string {
	t.Helper()
	return startServerLogging(t, f, nil)
}

// startServerLogging is startServer with the server's error log — where
// net/http reports a failed handshake — sent to errLog.
func startServerLogging(t *testing.T, f *fixture, errLog *log.Logger) string {
	t.Helper()
	now := f.b.Now()
	srvCert, err := f.ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	srv := f.b.Server("127.0.0.1:0", srvCert, f.ca.Pool())
	srv.ErrorLog = errLog
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return "https://" + ln.Addr().String()
}

func clientWith(f *fixture, certs ...tls.Certificate) *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: certs, RootCAs: f.ca.Pool(), MinVersion: tls.VersionTLS13}}}
}

// The agent's session is one connection (design §7): the broker stamps
// auth_time when it accepts the connection, and every mint on the connection
// carries it however long after — which is what makes session_expires the
// handshake plus max_session_age (plan 3, Decided 2).
func TestEveryMintOnAHeldConnectionCarriesItsHandshakeTime(t *testing.T) {
	f := newFixture(t, 8)
	url := startServer(t, f)
	c := clientWith(f, f.alice)
	var reused []bool
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		GotConn: func(i httptrace.GotConnInfo) { reused = append(reused, i.Reused) }})
	do := func(method, path, body string) {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, method, url+path, strings.NewReader(body))
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		// Read to EOF before closing, or the transport cannot reuse the
		// connection and every request is a new handshake.
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s %s: %s", method, path, resp.Status)
		}
	}
	handshake := f.b.Now()
	do("GET", "/v1/config", "")
	for i := 0; i < 2; i++ {
		f.advance(time.Hour)
		do("POST", "/v1/tokens", `{"devices":["leaf1"]}`)
		// Read each mint while it is live: the token TTL is a minute, and the
		// hour between mints is the point.
		toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"})
		if len(toks) != 1 || !toks[0].AuthTime.Equal(handshake) {
			t.Fatalf("mint %d, %d live token(s): auth_time must be the handshake's %v, an hour or two on: %+v",
				i+1, len(toks), handshake, toks)
		}
	}
	if len(reused) != 3 || reused[0] || !reused[1] || !reused[2] {
		t.Fatalf("three requests, one connection: reused %v", reused)
	}
}

// An untrusted certificate fails at the handshake, so `port49 login` fails
// there rather than at the first mint (plan 3, Decided 3), and nothing is
// minted or recorded as a mint.
func TestACertificateFromAnotherCAFailsTheHandshake(t *testing.T) {
	f := newFixture(t, 8)
	errs := &lockedBuffer{}
	url := startServerLogging(t, f, log.New(errs, "", 0))
	now := f.b.Now()
	other, err := testpki.NewCA("someone else's CA", now.Add(-time.Hour), now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	mallory, err := other.Issue(testpki.Leaf{CommonName: "m", Emails: []string{"alice@example.com"}, Client: true,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	// Presented whatever the broker's CA hint says, as the agent presents it
	// (Task 12): Go's default would send nothing for a certificate the hint
	// does not name, and the handshake would succeed with no identity.
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.ca.Pool(), MinVersion: tls.VersionTLS13,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &mallory, nil }}}}
	if resp, err := c.Get(url + "/v1/config"); err == nil {
		resp.Body.Close()
		t.Fatal("a certificate the anchor does not vouch for must fail the handshake")
	}
	if len(eventsOf(f.records(t), "mint")) != 0 {
		t.Fatalf("no mint was attempted: %v", f.records(t))
	}
	// What the operator reads when the anchor is the wrong one.
	errs.waitFor(t, "unknown authority")
}

// /v1/config needs no certificate; /v1/tokens does. Keep-alives are off: the
// broker closes a certificate-less connection as soon as it goes idle, and a
// pooled one would race that close.
func TestWithoutACertificateOnlyConfigAnswers(t *testing.T) {
	f := newFixture(t, 8)
	url := startServer(t, f)
	c := clientWith(f)
	c.Transport.(*http.Transport).DisableKeepAlives = true
	resp, err := c.Get(url + "/v1/config")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("config without a certificate: %v %v", resp, err)
	}
	resp.Body.Close()
	resp, err = c.Post(url+"/v1/tokens", "application/json", strings.NewReader(`{"devices":["leaf1"]}`))
	if err != nil || resp.StatusCode != 401 {
		t.Fatalf("a mint without a certificate: %v %v", resp, err)
	}
	resp.Body.Close()
}

// A connection that presented no certificate can reach /v1/config and nothing
// else, so it is closed the moment it goes idle rather than held for
// max_session_age. Held, anyone who can reach the listener could pile them up
// until port49d — which answers every device's AAA — runs out of file
// descriptors (pre-flight F1).
func TestACertificateLessConnectionIsClosedWhenIdle(t *testing.T) {
	f := newFixture(t, 8)
	url := startServer(t, f)
	conn, err := tls.Dial("tcp", strings.TrimPrefix(url, "https://"),
		&tls.Config{RootCAs: f.ca.Pool(), MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET /v1/config HTTP/1.1\r\nHost: broker\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("config without a certificate: %v %v", resp, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = br.ReadByte()
	var ne net.Error
	if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
		t.Fatalf("the broker must close an idle connection that presented no certificate; read: %v", err)
	}
}

// The listener holds at most n connections; the next waits in the kernel's
// backlog until one closes (pre-flight F1).
func TestLimitHoldsTheCap(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := Limit(raw, 1)
	defer ln.Close()
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", raw.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	first, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	second := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			second <- c
		}
	}()
	select {
	case c := <-second:
		c.Close()
		t.Fatal("a second connection was accepted past the cap")
	case <-time.After(200 * time.Millisecond):
	}
	first.Close()
	select {
	case c := <-second:
		c.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("closing a connection must free its slot")
	}
}

// With every slot held by an authenticated connection, which is never closed
// for idling before max_session_age, Shutdown must still return within its
// context. Serve waits in Accept for a slot; closing the listener has to wake
// it, or port49d hangs on SIGTERM and its accounting spool is never drained
// (final review, Important 1).
func TestShutdownReturnsWithEverySlotHeld(t *testing.T) {
	f := newFixture(t, 8)
	now := f.b.Now()
	srvCert, err := f.ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	srv := f.b.Server("127.0.0.1:0", srvCert, f.ca.Pool())
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	const slots = 2
	served := make(chan struct{})
	go func() { _ = srv.ServeTLS(Limit(raw, slots), "", ""); close(served) }()
	t.Cleanup(func() { _ = srv.Close() })
	for i := 0; i < slots; i++ {
		conn, err := tls.Dial("tcp", raw.Addr().String(), &tls.Config{Certificates: []tls.Certificate{f.alice},
			RootCAs: f.ca.Pool(), MinVersion: tls.VersionTLS13})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := io.WriteString(conn, "GET /v1/config HTTP/1.1\r\nHost: broker\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("config on held connection %d: %v %v", i, resp, err)
		}
		resp.Body.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	shut := make(chan error, 1)
	go func() { shut <- srv.Shutdown(ctx) }()
	select {
	case <-shut:
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown with a 500ms context was still blocked after 5s with every slot held")
	}
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Shutdown")
	}
}

// Closing a limited listener wakes an Accept waiting for a slot, with
// net.ErrClosed, which is how http.Server knows Serve is done.
func TestClosingALimitedListenerWakesAnAcceptWaitingForASlot(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := Limit(raw, 1)
	c, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	first, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	woke := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if c != nil {
			c.Close()
		}
		woke <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-woke:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept after Close: %v, want net.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not wake an Accept waiting for a slot")
	}
}

// One trust anchor, exactly: a bundle would silently widen who the email
// mapping trusts (design §7, weak mappings are issuer-pinned).
func TestLoadTLSTakesExactlyOneAnchor(t *testing.T) {
	dir := t.TempDir()
	if err := testpki.WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	p := func(n string) string { return filepath.Join(dir, n) }
	if _, _, err := LoadTLS(p(testpki.LabServerCert), p(testpki.LabServerKey), p(testpki.LabCA)); err != nil {
		t.Fatal(err)
	}
	two := filepath.Join(dir, "two.pem")
	a, _ := os.ReadFile(p(testpki.LabCA))
	other, _ := testpki.NewCA("second", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err := os.WriteFile(two, append(a, other.PEM()...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadTLS(p(testpki.LabServerCert), p(testpki.LabServerKey), two); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("two anchors: %v", err)
	}
	if _, _, err := LoadTLS(p(testpki.LabServerCert), p(testpki.LabServerKey), p(testpki.LabServerKey)); err == nil {
		t.Fatal("a file with no certificate is not an anchor")
	}
}

// Past max_session_age the held connection mints nothing and is closed, and
// the next request is a new handshake whose session starts then (spec §13,
// decision 17): the ceiling is enforced over the wire, not just in the handler.
func TestPastMaxSessionAgeTheNextRequestIsANewHandshake(t *testing.T) {
	f := newFixture(t, 8)
	url := startServer(t, f)
	c := clientWith(f, f.alice)
	var reused []bool
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		GotConn: func(i httptrace.GotConnInfo) { reused = append(reused, i.Reused) }})
	mint := func() int {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, "POST", url+"/v1/tokens", strings.NewReader(`{"devices":["leaf1"]}`))
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := mint(); code != 200 {
		t.Fatalf("first mint: %d", code)
	}
	f.advance(f.b.MaxSessionAge + time.Minute)
	if code := mint(); code != 401 {
		t.Fatalf("a mint past max_session_age on the held connection: %d", code)
	}
	again := f.b.Now()
	if code := mint(); code != 200 {
		t.Fatalf("a mint after reconnecting: %d", code)
	}
	if len(reused) != 3 || reused[0] || !reused[1] || reused[2] {
		t.Fatalf("the expired connection must be closed and the third request a new handshake: reused %v", reused)
	}
	toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"})
	if len(toks) != 1 || !toks[0].AuthTime.Equal(again) {
		t.Fatalf("the new handshake's session starts at %v: %+v", again, toks)
	}
}

// A reconnect is a full handshake that uses the key: no TLS session is
// resumed, so a ticket cannot stand in for the key (pre-flight F2).
func TestAReconnectIsNeverAResumedSession(t *testing.T) {
	f := newFixture(t, 8)
	url := startServer(t, f)
	cfg := &tls.Config{Certificates: []tls.Certificate{f.alice}, RootCAs: f.ca.Pool(), MinVersion: tls.VersionTLS13,
		ClientSessionCache: tls.NewLRUClientSessionCache(4)}
	for i := 0; i < 2; i++ {
		conn, err := tls.Dial("tcp", strings.TrimPrefix(url, "https://"), cfg)
		if err != nil {
			t.Fatal(err)
		}
		if conn.ConnectionState().DidResume {
			conn.Close()
			t.Fatalf("connection %d resumed a TLS session", i+1)
		}
		// A TLS 1.3 ticket arrives after the handshake; a request and its
		// response give the client the chance to read one.
		if _, err := io.WriteString(conn, "GET /v1/config HTTP/1.1\r\nHost: broker\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		conn.Close()
	}
}

// HTTP/2 is off, not merely out-preferred: a client that offers only h2 does
// not get it (pre-flight F13).
func TestHTTP2IsNeverNegotiated(t *testing.T) {
	f := newFixture(t, 8)
	url := startServer(t, f)
	conn, err := tls.Dial("tcp", strings.TrimPrefix(url, "https://"), &tls.Config{Certificates: []tls.Certificate{f.alice},
		RootCAs: f.ca.Pool(), MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}})
	if err == nil {
		defer conn.Close()
		if p := conn.ConnectionState().NegotiatedProtocol; p == "h2" {
			t.Fatal("the broker negotiated h2")
		}
	}
}

// An expired certificate fails the handshake, and the broker's log says so
// with the dates, which is what an operator reads when `port49 login` fails.
func TestAnExpiredCertificateFailsTheHandshakeAndTheLogSaysExpired(t *testing.T) {
	f := newFixture(t, 8)
	errs := &lockedBuffer{}
	url := startServerLogging(t, f, log.New(errs, "", 0))
	expired := f.client(t, "alice@example.com", f.now.Add(-time.Minute))
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.ca.Pool(), MinVersion: tls.VersionTLS13,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &expired, nil }}}}
	if resp, err := c.Get(url + "/v1/config"); err == nil {
		resp.Body.Close()
		t.Fatal("an expired certificate must fail the handshake")
	}
	errs.waitFor(t, "certificate has expired")
}

// lockedBuffer collects a server's error log, which its goroutines write.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// waitFor waits for want in the log: the server logs a failed handshake from
// its connection's goroutine, after the client has already seen the failure.
func (b *lockedBuffer) waitFor(t *testing.T, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		b.mu.Lock()
		got := b.buf.String()
		b.mu.Unlock()
		if strings.Contains(got, want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the broker's error log never said %q: %q", want, got)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A certificate-less connection stalled mid-request never goes idle, so the
// idle close cannot reach it: headers promising a body and then nothing would
// hold a slot of the cap for good, and MaxConns of them lock every operator
// out of the broker. ReadTimeout bounds the request (pre-flight F1).
func TestAStalledRequestWithoutACertificateIsClosed(t *testing.T) {
	defer func(d time.Duration) { readTimeout = d }(readTimeout)
	readTimeout = time.Second
	f := newFixture(t, 8)
	url := startServer(t, f)
	conn, err := tls.Dial("tcp", strings.TrimPrefix(url, "https://"),
		&tls.Config{RootCAs: f.ca.Pool(), MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "POST /v1/tokens HTTP/1.1\r\nHost: broker\r\n"+
		"Content-Type: application/json\r\nContent-Length: 200000\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.Copy(io.Discard, conn)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("the broker must close a connection whose request stalls")
	}
}

// A nil pool would mean the system roots — every public CA an anchor for the
// email mapping — and an empty one trusts nobody: Server refuses both.
func TestServerRefusesAMissingAnchor(t *testing.T) {
	f := newFixture(t, 8)
	for name, pool := range map[string]*x509.CertPool{"nil": nil, "empty": x509.NewCertPool()} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("a %s anchor pool must be refused", name)
				}
			}()
			f.b.Server("127.0.0.1:0", f.alice, pool)
		}()
	}
}
