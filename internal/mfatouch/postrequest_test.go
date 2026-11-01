package mfatouch

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/blanketfish/port49/internal/broker/api"
)

// seen is what the test server received of one request.
type seen struct {
	method, uri, header, proof, body string
}

// exporterServer is a TLS server that records each request it is sent and
// tells the client both exporter values of the connection it arrived on,
// which a test then names as "the one signed over".
func exporterServer(t *testing.T) (*httptest.Server, func() []seen) {
	t.Helper()
	var mu sync.Mutex
	var got []seen
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/learn" {
			mu.Lock()
			got = append(got, seen{r.Method, r.URL.RequestURI(), r.Header.Get("X-Test"),
				r.Header.Get(api.AdminProofHeader), string(body)})
			mu.Unlock()
		}
		for name, label := range map[string]string{"X-Admin-Ekm": api.AdminExporterLabel, "X-Mfa-Ekm": api.MFAExporterLabel} {
			ekm, err := r.TLS.ExportKeyingMaterial(label, nil, 32)
			if err != nil {
				t.Error(err)
			}
			w.Header().Set(name, hex.EncodeToString(ekm))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []seen { mu.Lock(); defer mu.Unlock(); return append([]seen(nil), got...) }
}

func tlsState(c net.Conn) (tls.ConnectionState, bool) {
	tc, ok := c.(*tls.Conn)
	if !ok {
		return tls.ConnectionState{}, false
	}
	return tc.ConnectionState(), true
}

// PostRequest sends the caller's method, URL and headers under Post's
// connection rule: the body goes only on a connection whose exporter value
// is the one signed over, and an admin call's is the admin label's.
func TestPostRequestCarriesTheRequestOnlyOverTheConnectionSignedOver(t *testing.T) {
	srv, got := exporterServer(t)
	client := srv.Client()
	client.CheckRedirect = NoRedirect
	// learn reads the held connection's exporter values from a request of its
	// own. A cut request closes its connection, so a test learns again after.
	learn := func() (admin, mfa []byte) {
		resp, err := client.Get(srv.URL + "/learn")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		admin, _ = hex.DecodeString(resp.Header.Get("X-Admin-Ekm"))
		mfa, _ = hex.DecodeString(resp.Header.Get("X-Mfa-Ekm"))
		if len(admin) != 32 || len(mfa) != 32 {
			t.Fatal("the server did not tell the exporter values")
		}
		return admin, mfa
	}
	admin, mfa := learn()

	build := func(method string, proof bool) *http.Request {
		req, err := http.NewRequest(method, srv.URL+"/v1/tokens/revoke?x=1", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Test", "carried")
		if proof {
			req.Header.Set(api.AdminProofHeader, "fake-proof-header")
		}
		return req
	}

	// An admin call: its method, URL with query, headers and body arrive, on
	// the connection whose admin exporter value was signed over.
	resp, err := PostRequest(t.Context(), client.Do, build("POST", true), []byte(`{"a":1}`), admin, tlsState)
	if err != nil {
		t.Fatalf("the admin call: %v", err)
	}
	resp.Body.Close()
	if s := got(); len(s) != 1 || s[0] != (seen{"POST", "/v1/tokens/revoke?x=1", "carried", "fake-proof-header", `{"a":1}`}) {
		t.Fatalf("the server saw %+v", s)
	}

	// The per-login value is not an admin call's: nothing is sent.
	if _, err = PostRequest(t.Context(), client.Do, build("POST", true), []byte(`{"a":2}`), mfa, tlsState); !errors.Is(err, ErrConnectionChanged) {
		t.Fatalf("the wrong label's value: %v, want ErrConnectionChanged", err)
	}
	// Another connection's value: nothing is sent.
	other := append([]byte(nil), admin...)
	other[0] ^= 0xff
	if _, err = PostRequest(t.Context(), client.Do, build("POST", true), []byte(`{"a":3}`), other, tlsState); !errors.Is(err, ErrConnectionChanged) {
		t.Fatalf("another connection's value: %v, want ErrConnectionChanged", err)
	}
	// A request that is no admin call is held to the per-login value, and
	// its method is its own.
	_, mfa = learn()
	resp, err = PostRequest(t.Context(), client.Do, build("PUT", false), []byte(`{"a":4}`), mfa, tlsState)
	if err != nil {
		t.Fatalf("the per-login call: %v", err)
	}
	resp.Body.Close()
	// The headers of a cut request may reach the server, never its body.
	s := got()
	for _, x := range s[1 : len(s)-1] {
		if x.body != "" {
			t.Fatal("a body reached the server on a connection that was not signed over")
		}
	}
	if last := s[len(s)-1]; last.method != "PUT" || last.body != `{"a":4}` || last.proof != "" {
		t.Fatalf("the per-login call reached the server as %+v", last)
	}
}
