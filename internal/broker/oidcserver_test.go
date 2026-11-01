package broker

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/testpki"
)

func TestConfigNamesTheHumanOIDCVerifiers(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	w := httptest.NewRecorder()
	f.b.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/config", nil))
	var c api.Config
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.Methods, ",") != "x509,oidc" || len(c.OIDC) != 1 || c.OIDC[0].Issuer != iss.URL ||
		c.OIDC[0].ClientID != testClientID || strings.Join(c.OIDC[0].Scopes, ",") != "openid" {
		t.Fatalf("config %+v: the machine verifier is not listed, the human one is", c)
	}
	if c.OIDC[0].Scopes == nil || strings.Contains(w.Body.String(), `"scopes":null`) {
		t.Fatalf("scopes is null: %s", w.Body)
	}
	if strings.Contains(w.Body.String(), "api://port49-svc") {
		t.Fatalf("a machine audience is advertised: %s", w.Body)
	}
}

// An OIDC-only broker requests no certificate and offers no x509; a broker
// with neither an anchor nor an OIDC verifier is refused.
func TestAnOIDCOnlyServer(t *testing.T) {
	f := newFixture(t, 8)
	now := f.b.Now()
	srvCert, err := f.ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.b.Server("127.0.0.1:0", srvCert, nil)
	if err == nil {
		t.Fatal("a broker with no anchor and no OIDC verifier was served")
	}
	if strings.Contains(err.Error(), "open :") || !strings.Contains(err.Error(), "anchor") {
		t.Fatalf("the refusal does not say what is missing: %v", err)
	}
	// A nil anchor is served only as NoX509 with Identity: either alone starts
	// a broker that then refuses everyone.
	f.b.NoX509 = true
	if _, err := f.b.Server("127.0.0.1:0", srvCert, nil); err == nil {
		t.Fatal("an OIDC-only broker with no OIDC verifier was served")
	}
	f.b.NoX509 = false
	iss := f.withOIDC(t)
	if _, err := f.b.Server("127.0.0.1:0", srvCert, nil); err == nil {
		t.Fatal("a broker that offers x509 was served with no anchor")
	}
	f.b.NoX509 = true
	// NoX509 with an anchor would still verify client certificates: refused
	// (pre-flight M-19).
	if _, err := f.b.Server("127.0.0.1:0", srvCert, f.ca.Pool()); err == nil {
		t.Fatal("an OIDC-only broker was served with an anchor")
	}
	srv, err := f.b.Server("127.0.0.1:0", srvCert, nil)
	if err != nil {
		t.Fatal(err)
	}
	if srv.TLSConfig.ClientAuth != tls.NoClientCert || srv.TLSConfig.ClientCAs != nil {
		t.Fatalf("an OIDC-only broker requests %v", srv.TLSConfig.ClientAuth)
	}
	w := httptest.NewRecorder()
	f.b.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/config", nil))
	if !strings.Contains(w.Body.String(), `"methods":["oidc"]`) {
		t.Fatalf("config %s", w.Body)
	}
	// A valid bearer mints on the same OIDC-only broker.
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, nil)); w.Code != 200 {
		t.Fatalf("a valid bearer on an OIDC-only broker: %s", shown(w))
	}
	// No bearer: the answer says what this broker takes, and the record is oidc's.
	w = f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, "")
	var e api.Error
	if w.Code != 401 || json.Unmarshal(w.Body.Bytes(), &e) != nil ||
		e.Error != "trust_domain_unresolved" || !strings.Contains(e.Detail, "OIDC ID token only") ||
		strings.Contains(e.Detail, "certificate") {
		t.Fatalf("no bearer on an OIDC-only broker: %s", shown(w))
	}
	recs := eventsOf(f.records(t), decision.EventMint)
	if len(recs) == 0 {
		t.Fatal("no mint record")
	}
	auth, _ := recs[len(recs)-1]["auth"].(map[string]any)
	if auth["method"] != "oidc" {
		t.Fatalf("the record's auth.method is %v", auth["method"])
	}
}

// A bearer over a real connection mints; the connection, which bound no
// principal, is closed once it goes idle and gives its source slot back.
func TestABearerMintsThroughTheListener(t *testing.T) {
	t.Run("x509 and oidc", func(t *testing.T) { bearerMintsThroughTheListener(t, false) })
	// A real OIDC-only server: no anchor, no certificate requested.
	t.Run("oidc only", func(t *testing.T) { bearerMintsThroughTheListener(t, true) })
}

func bearerMintsThroughTheListener(t *testing.T, noX509 bool) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	f.b.NoX509 = noX509
	addr, _ := serveThrough(t, f, ListenerLimits{MaxPendingPerSource: 1, MaxPerPrincipal: 4,
		HandshakeTimeout: 10 * time.Second}, nil)
	mint := func() int {
		c, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: f.ca.Pool(), MinVersion: tls.VersionTLS13})
		if err != nil {
			t.Fatal(err)
		}
		body := mintLeaf1
		req := "POST /v1/tokens HTTP/1.1\r\nHost: broker\r\nContent-Type: application/json\r\n" +
			"Authorization: Bearer " + f.idToken(t, iss, nil) + "\r\nContent-Length: " +
			strconv.Itoa(len(body)) + "\r\n\r\n" + body
		if _, err := io.WriteString(c, req); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(c)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		// The broker closes it once idle: the next read ends, it does not time out.
		_, err = br.ReadByte()
		var ne net.Error
		if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
			t.Fatalf("a bearer's connection was held after its request: %v", err)
		}
		// The close that ended the read gives the slot back just after it.
		pending := f.b.Metrics.BrokerConnections.WithLabelValues("pending")
		for deadline := time.Now().Add(2 * time.Second); testutil.ToFloat64(pending) != 0; {
			if time.Now().After(deadline) {
				t.Fatalf("%v connections still pending", testutil.ToFloat64(pending))
			}
			time.Sleep(10 * time.Millisecond)
		}
		return resp.StatusCode
	}
	// With one pending slot per source, the second mint gets its slot only if
	// the first connection's slot was given back when the broker closed it.
	for i := range 2 {
		if code := mint(); code != 200 {
			t.Fatalf("mint %d: %d", i+1, code)
		}
	}
}
