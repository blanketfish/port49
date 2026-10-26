package sot

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

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
