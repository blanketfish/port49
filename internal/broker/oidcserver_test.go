package broker

import (
	"bufio"
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

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/testpki"
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
	f.withOIDC(t)
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
}

// A bearer over a real connection mints; the connection, which bound no
// principal, is closed once it goes idle and gives its source slot back.
func TestABearerMintsThroughTheListener(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
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
