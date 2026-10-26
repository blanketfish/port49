package sot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/egress"

	"github.com/rhwendt/port49/internal/sot/sottest"
)

const token = "0123456789abcdef0123456789abcdef01234567"

func TestASecretNeverPrints(t *testing.T) {
	s := struct{ Token Secret }{NewSecret("hunter2-token")}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		if out := fmt.Sprintf(verb, s); strings.Contains(out, "hunter2") {
			t.Fatalf("%s printed it: %s", verb, out)
		}
	}
	if b, _ := json.Marshal(s); strings.Contains(string(b), "hunter2") {
		t.Fatalf("JSON: %s", b)
	}
	if s.Token.Reveal() != "hunter2-token" || s.Token.Empty() || !NewSecret("").Empty() || !(Secret{}).Empty() {
		t.Fatal("Reveal or Empty")
	}
	// Reached through an unexported field, fmt prints a struct field by
	// field: the pointer keeps the value out (pre-flight M1).
	hidden := struct{ cfg struct{ token Secret } }{}
	hidden.cfg.token = NewSecret("hunter2-token")
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if out := fmt.Sprintf(verb, hidden); strings.Contains(out, "hunter2") {
			t.Fatalf("%s printed it through an unexported field: %s", verb, out)
		}
	}
}

// Decision 31: the source of truth is https, and its url carries nothing
// but where it is. An error never quotes what was pasted there.
func TestTheBaseIsStrictHTTPS(t *testing.T) {
	for raw, want := range map[string]string{
		"http://netbox.example.com":                      "must be https://",
		"netbox.example.com":                             "must be https://",
		"https://admin:" + token + "@netbox.example.com": "user information",
		"https://netbox.example.com/?token=" + token:     "a query or a fragment",
		"https://netbox.example.com/#" + token:           "a query or a fragment",
	} {
		err := CheckURL(raw)
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), token) {
			t.Errorf("%s: %v", raw, err)
		}
	}
	if err := CheckURL("https://netbox.example.com/netbox/"); err != nil {
		t.Fatal(err)
	}
}

func TestACAFileIsRequired(t *testing.T) {
	if _, err := newClient("https://netbox.example.com", "", NewSecret(token), "netbox"); err == nil ||
		!strings.Contains(err.Error(), "ca_file") {
		t.Fatalf("got %v", err)
	}
}

// L27: NetBox 4.x provisions v2 tokens, nbt_<key>.<token>, sent as Bearer; a
// v1 token, and every Nautobot token, is sent as Token.
func TestTheTokenSchemeFollowsTheToken(t *testing.T) {
	var got string
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.Write([]byte(`{}`))
	}))
	for _, c := range []struct{ product, token, want string }{
		{"netbox", "nbt_abcdefabcdef.0123456789", "Bearer nbt_abcdefabcdef.0123456789"},
		{"netbox", token, "Token " + token},
		{"nautobot", "nbt_looks_like_netbox", "Token nbt_looks_like_netbox"},
	} {
		cl, err := newClient(srv.URL, ca, NewSecret(c.token), c.product)
		if err != nil {
			t.Fatal(err)
		}
		var v map[string]any
		if err := cl.getJSON(context.Background(), cl.at("/api/status/", nil), &v); err != nil || got != c.want {
			t.Errorf("%s %s: sent %q, %v", c.product, c.token, got, err)
		}
	}
}

// Decision 31: no redirect is followed, so the token goes to the configured
// base alone.
func TestARedirectIsNotFollowed(t *testing.T) {
	elsewhere := 0
	other, _ := sottest.TLS(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere++ }))
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/api/status/", http.StatusFound)
	}))
	cl, err := newClient(srv.URL, ca, NewSecret(token), "netbox")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	err = cl.getJSON(context.Background(), cl.at("/api/status/", nil), &v)
	if err == nil || !strings.Contains(err.Error(), "a redirect, which is not followed") || elsewhere != 0 {
		t.Fatalf("%v; requests elsewhere: %d", err, elsewhere)
	}
}

// A refusal names the key that holds the token, and never prints it, even
// when the product echoes it.
func TestARefusedTokenIsNamedNeverPrinted(t *testing.T) {
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"detail": "Invalid token %s"}`, r.Header.Get("Authorization"))
	}))
	cl, _ := newClient(srv.URL, ca, NewSecret(token), "netbox")
	var v map[string]any
	err := cl.getJSON(context.Background(), cl.at("/api/status/", nil), &v)
	if err == nil || !strings.Contains(err.Error(), "answered HTTP 403: the token token_secret_ref names") ||
		strings.Contains(err.Error(), token) {
		t.Fatalf("%v", err)
	}
}

func TestAnAnswerPastTheBoundIsRefused(t *testing.T) {
	defer func(m int64) { maxResponse = m }(maxResponse)
	maxResponse = 1024
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"x": "` + strings.Repeat("a", 2048) + `"}`))
	}))
	cl, _ := newClient(srv.URL, ca, NewSecret(token), "netbox")
	var v map[string]any
	if err := cl.getJSON(context.Background(), cl.at("/api/status/", nil), &v); err == nil ||
		!strings.Contains(err.Error(), "more than 1024 bytes") {
		t.Fatalf("%v", err)
	}
}

func TestAServerTheCAFileDoesNotTrustIsRefused(t *testing.T) {
	srv, _ := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{}`)) }))
	_, otherCA := sottest.TLS(t, http.NotFoundHandler())
	cl, _ := newClient(srv.URL, otherCA, NewSecret(token), "netbox")
	var v map[string]any
	if err := cl.getJSON(context.Background(), cl.at("/api/status/", nil), &v); err == nil ||
		!strings.Contains(err.Error(), "certificate") {
		t.Fatalf("%v", err)
	}
}

// Pre-flight M2: a FIFO at ca_file is refused, not read until something
// writes to it.
func TestACAFileThatIsAFIFOIsRefused(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "ca.pem")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := newClient("https://netbox.example.com", fifo, NewSecret(token), "netbox")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "ca_file") {
			t.Fatalf("got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a FIFO blocked")
	}
}

// Pre-flight M3: a fetch reads at most maxFetch bytes over all its pages.
func TestABudgetBoundsAFetch(t *testing.T) {
	defer func(m int64) { maxFetch = m }(maxFetch)
	maxFetch = 100
	b := newBudget()
	if err := b.spend(60); err != nil {
		t.Fatal(err)
	}
	if err := b.spend(60); err == nil || !strings.Contains(err.Error(), "the most one sync reads") {
		t.Fatalf("got %v", err)
	}
}

func TestPrintableCutsAndNeutralises(t *testing.T) {
	if got := printable("a\x1b[2Jb\nc"); got != "a?[2Jb?c" {
		t.Fatalf("%q", got)
	}
	if got := printable(strings.Repeat("x", 300)); len(got) > maxPrinted+len("…") {
		t.Fatalf("%d bytes", len(got))
	}
}

// Decision 31 is the client's own: do sends the token to the base's origin
// alone, whoever built the URL.
func TestAForeignOriginIsRefused(t *testing.T) {
	elsewhere := 0
	other, _ := sottest.TLS(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere++ }))
	srv, ca := sottest.TLS(t, http.NotFoundHandler())
	cl, err := newClient(srv.URL, ca, NewSecret(token), "netbox")
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := url.Parse(other.URL + "/api/status/")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.do(context.Background(), http.MethodGet, foreign, nil, false); err == nil ||
		!strings.Contains(err.Error(), "is not on url") || elsewhere != 0 {
		t.Fatalf("%v; requests elsewhere: %d", err, elsewhere)
	}
}

// A transport error prints the path once and the cause whole: a long query
// a next named does not cut the cause away.
func TestATransportErrorKeepsItsCause(t *testing.T) {
	srv, _ := sottest.TLS(t, http.NotFoundHandler())
	_, otherCA := sottest.TLS(t, http.NotFoundHandler())
	cl, _ := newClient(srv.URL, otherCA, NewSecret(token), "netbox")
	var v map[string]any
	err := cl.getJSON(context.Background(), cl.at("/api/status/", url.Values{"q": {strings.Repeat("a", 500)}}), &v)
	if err == nil || !strings.HasPrefix(err.Error(), "GET /api/status/: ") || !strings.Contains(err.Error(), "certificate") ||
		strings.Contains(err.Error(), "aaaa") {
		t.Fatalf("%v", err)
	}
}

// An idle connection is closed before the source or a proxy closes it, and
// a rotated CA reaches the next dial.
func TestIdleConnectionsExpire(t *testing.T) {
	cl, err := newClient("https://netbox.example.com", writeCA(t), NewSecret(token), "netbox")
	if err != nil {
		t.Fatal(err)
	}
	if got := cl.http.Transport.(*http.Transport).IdleConnTimeout; got != 90*time.Second {
		t.Fatalf("IdleConnTimeout %v", got)
	}
}

func writeCA(t *testing.T) string {
	t.Helper()
	_, ca := sottest.TLS(t, http.NotFoundHandler())
	return ca
}

// connectProxy is an HTTP CONNECT proxy that counts its tunnels and keeps the
// Authorization header of each CONNECT it saw; with upstream it dials that
// address whatever host the CONNECT names.
func connectProxy(t *testing.T, upstream string) (*url.URL, *atomic.Int64, *atomic.Value) {
	t.Helper()
	var n atomic.Int64
	var auth atomic.Value
	auth.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		n.Add(1)
		if a := r.Header.Get("Authorization") + r.Header.Get("Proxy-Authorization"); a != "" {
			auth.Store("a credential header on CONNECT")
		}
		to := r.Host
		if upstream != "" {
			to = upstream // a name that is not the server's, to reach it under another host
		}
		up, err := net.Dial("tcp", to)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		down, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			up.Close()
			return
		}
		go func() { io.Copy(up, down); up.Close() }()
		io.Copy(down, up)
		down.Close()
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return u, &n, &auth
}

// Through an egress proxy the source is reached by CONNECT, its certificate
// still checked against ca_file, read at the dial (decision 53 ruling 7), and
// the token travels inside the tunnel only, never on the CONNECT.
func TestASourceIsReachedThroughTheProxy(t *testing.T) {
	pu, tunnels, connectAuth := connectProxy(t, "")
	was := proxy
	t.Cleanup(func() { proxy = was })
	proxy = http.ProxyURL(pu)
	var sawToken atomic.Bool
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawToken.Store(strings.HasSuffix(r.Header.Get("Authorization"), token))
		w.Write([]byte(`{}`))
	}))
	cl, err := newClient(srv.URL, ca, NewSecret(token), "netbox")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := cl.getJSON(context.Background(), cl.at("/api/status/", nil), &v); err != nil || tunnels.Load() != 1 {
		t.Fatalf("%v; tunnels %d", err, tunnels.Load())
	}
	if !sawToken.Load() {
		t.Fatal("the source did not get the token inside the tunnel")
	}
	if got := connectAuth.Load().(string); got != "" {
		t.Fatalf("the proxy saw %s", got)
	}
	// A CA that does not issue the source's certificate is refused through
	// the tunnel as it is directly.
	cl, _ = newClient(srv.URL, writeCA(t), NewSecret(token), "netbox")
	if err := cl.getJSON(context.Background(), cl.at("/api/status/", nil), &v); err == nil {
		t.Fatal("a source the CA file does not trust was read through the proxy")
	}
}

// A rotated CA reaches the next dial through the proxy as it does directly:
// the file is read at the handshake, not at the client's construction.
func TestARotatedCAReachesTheNextDialThroughTheProxy(t *testing.T) {
	pu, _, _ := connectProxy(t, "")
	was := proxy
	t.Cleanup(func() { proxy = was })
	proxy = http.ProxyURL(pu)
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) }))
	good, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	live := writeCA(t) // another source's CA: the file starts out wrong
	cl, err := newClient(srv.URL, live, NewSecret(token), "netbox")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := cl.getJSON(context.Background(), cl.at("/api/status/", nil), &v); err == nil {
		t.Fatal("read through the proxy under a CA that does not issue the certificate")
	}
	if err := os.WriteFile(live, good, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cl.getJSON(context.Background(), cl.at("/api/status/", nil), &v); err != nil {
		t.Fatalf("the rotated CA was not read at the next dial: %v", err)
	}
}

// An HTTPS_PROXY the transport would misread is refused, never dialled, and
// the error carries none of it.
func TestABadProxyEnvironmentRefusesTheFetchWithoutPrintingIt(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://svc:FAKE-pw#x@proxy.example.com:3128")
	srv, ca := sottest.TLS(t, http.NotFoundHandler())
	cl, err := newClient(srv.URL, ca, NewSecret(token), "netbox")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	err = cl.getJSON(context.Background(), cl.at("/api/status/", nil), &v)
	if !errors.Is(err, egress.ErrBadProxy) || strings.Contains(err.Error(), "FAKE-pw") {
		t.Fatalf("%v", err)
	}
}

// The source's name is checked through the tunnel as it is directly: the
// certificate of another host is refused even when its chain is trusted.
func TestAServerOfAnotherNameIsRefusedThroughTheProxy(t *testing.T) {
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) }))
	pu, _, _ := connectProxy(t, strings.TrimPrefix(srv.URL, "https://"))
	was := proxy
	t.Cleanup(func() { proxy = was })
	proxy = http.ProxyURL(pu)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	cl, err := newClient("https://netbox.example.com:"+port, ca, NewSecret(token), "netbox")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := cl.getJSON(context.Background(), cl.at("/api/status/", nil), &v); err == nil {
		t.Fatal("a certificate that does not name the source's host was accepted through the proxy")
	}
}

// With InsecureSkipVerify on, the CA read inside VerifyConnection is the only
// verification there is: a CA file that cannot be read at the handshake (cut
// short, swapped for a directory, gone mid-rotation) must refuse the fetch, in
// no case accept whatever certificate the server sent, and the source must
// never see the request, direct or through the proxy.
func TestAnUnreadableCAFileRefusesTheHandshake(t *testing.T) {
	breaks := map[string]func(t *testing.T, path string){
		"truncated": func(t *testing.T, path string) {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"a directory": func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"removed": func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		},
	}
	for _, via := range []string{"direct", "the proxy"} {
		for name, brk := range breaks {
			t.Run(via+"/"+name, func(t *testing.T) {
				if via == "the proxy" {
					pu, _, _ := connectProxy(t, "")
					was := proxy
					t.Cleanup(func() { proxy = was })
					proxy = http.ProxyURL(pu)
				}
				var reached atomic.Int64
				srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					reached.Add(1)
					w.Write([]byte(`{}`))
				}))
				good, err := os.ReadFile(ca)
				if err != nil {
					t.Fatal(err)
				}
				live := filepath.Join(t.TempDir(), "ca.pem")
				if err := os.WriteFile(live, good, 0o600); err != nil {
					t.Fatal(err)
				}
				cl, err := newClient(srv.URL, live, NewSecret(token), "netbox")
				if err != nil {
					t.Fatal(err)
				}
				brk(t, live)
				var v map[string]any
				if err := cl.getJSON(context.Background(), cl.at("/api/status/", nil), &v); err == nil || reached.Load() != 0 {
					t.Fatalf("a CA file that could not be read did not refuse the fetch: %v; source reached %d times",
						err, reached.Load())
				}
				// Sound, not vacuous: the same client reads once the file is whole again.
				os.RemoveAll(live)
				if err := os.WriteFile(live, good, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := cl.getJSON(context.Background(), cl.at("/api/status/", nil), &v); err != nil || reached.Load() != 1 {
					t.Fatalf("the restored CA was not read: %v; source reached %d times", err, reached.Load())
				}
			})
		}
	}
}

// A 407 comes from the egress proxy, not from the source: the operator is told
// whose credentials were refused, and never sees them.
//
// The hint follows the status code, not the proxy's wording of it: a proxy
// that answers "407 Unauthorized" gets the same text.
func TestAProxyThatRefusesItsCredentialsIsNamedNeverPrinted(t *testing.T) {
	for name, reason := range map[string]string{"standard phrase": "Proxy Authentication Required",
		"another phrase": "Unauthorized", "no phrase": ""} {
		t.Run(name, func(t *testing.T) { proxyRefusesCredentials(t, reason) })
	}
}

func proxyRefusesCredentials(t *testing.T, reason string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(io.Discard, io.LimitReader(c, 1)) // wait for the CONNECT
				time.Sleep(20 * time.Millisecond)
				fmt.Fprintf(c, "HTTP/1.1 407 %s\r\nProxy-Authenticate: Basic realm=\"egress\"\r\nContent-Length: 0\r\n\r\n", reason)
			}()
		}
	}()
	pu, _ := url.Parse("http://" + ln.Addr().String())
	pu.User = url.UserPassword("svc-FAKE", "FAKE-proxy-pw")
	was := proxy
	t.Cleanup(func() { proxy = was })
	proxy = http.ProxyURL(pu)
	var reached atomic.Int64
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	cl, err := newClient(srv.URL, ca, NewSecret(token), "netbox")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	err = cl.getJSON(context.Background(), cl.at("/api/status/", nil), &v)
	if err == nil || !strings.Contains(err.Error(), "the egress proxy refused HTTPS_PROXY's credentials; the token was not sent") {
		t.Fatalf("%v", err)
	}
	for _, leak := range []string{"svc-FAKE", "FAKE-proxy-pw", token, "Basic"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("the error carries a credential")
		}
	}
	if reached.Load() != 0 {
		t.Fatal("the source was reached")
	}
}
