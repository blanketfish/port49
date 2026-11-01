package inventory

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/bundle"
	"github.com/blanketfish/port49/internal/testpki"
)

type apiRig struct {
	*syncRig
	srv                    *httptest.Server
	ca                     *testpki.CA
	reader, syncer, nobody *http.Client
}

func (rig *apiRig) client(t *testing.T, l testpki.Leaf) *http.Client {
	t.Helper()
	l.Client, l.NotBefore, l.NotAfter = true, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	cert, err := rig.ca.Issue(l)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: rig.ca.Pool(), Certificates: []tls.Certificate{cert}}}}
}

func uri(s string) *url.URL { u, _ := url.Parse(s); return u }

func newAPIRig(t *testing.T) *apiRig {
	t.Helper()
	return newAPIRigWith(t, []string{"spiffe://port49.test/port49d"}, []string{"user:alice@example.com"})
}

// newAPIRigWith is newAPIRig with its own readers and syncers.
func newAPIRigWith(t *testing.T, readers, syncers []string) *apiRig {
	t.Helper()
	rig := &apiRig{syncRig: newSyncRig(t, syncPolicy, devices(3))}
	ca, err := testpki.NewCA("inv test CA", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	rig.ca = ca
	srvCert, _ := ca.Issue(testpki.Leaf{CommonName: "inv", IPs: testpki.Loopback(), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour)})
	api := &API{Syncer: rig.s, Readers: readers, Syncers: syncers, Now: time.Now, Log: rig.out,
		Metrics: rig.s.Metrics}
	s, err := Server("127.0.0.1:0", srvCert, ca.Pool(), api.Handler(), log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	rig.srv = httptest.NewUnstartedServer(s.Handler)
	rig.srv.TLS = s.TLSConfig
	rig.srv.Config.ErrorLog = s.ErrorLog
	rig.srv.StartTLS()
	t.Cleanup(rig.srv.Close)
	rig.reader = rig.client(t, testpki.Leaf{CommonName: "d", URIs: []*url.URL{uri("spiffe://port49.test/port49d")}})
	rig.syncer = rig.client(t, testpki.Leaf{CommonName: "alice", Emails: []string{"Alice@Example.com"}})
	rig.nobody = rig.client(t, testpki.Leaf{CommonName: "x", URIs: []*url.URL{uri("spiffe://port49.test/other")}})
	return rig
}

func (rig *apiRig) do(t *testing.T, c *http.Client, method, path string, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, rig.srv.URL+path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp, body
}

func TestBeforeTheFirstSyncTheBundleIsNotThere(t *testing.T) {
	rig := newAPIRig(t)
	resp, body := rig.do(t, rig.reader, "GET", "/v1/bundle/version", nil)
	if resp.StatusCode != 503 || !strings.Contains(string(body), `"no_bundle"`) {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
}

// A bundle is served only once Save has kept it: a sync whose state_dir
// cannot be written serves nothing, not the bundle it could not keep.
func TestABundleNotKeptIsNotServed(t *testing.T) {
	rig := newAPIRig(t)
	blocker := filepath.Join(rig.dir, "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	rig.s.State.Dir = filepath.Join(blocker, "state")
	if res := rig.sync(t); res.Outcome != OutcomeFailed {
		t.Fatalf("%+v", res)
	}
	for _, path := range []string{"/v1/bundle", "/v1/bundle/version"} {
		resp, body := rig.do(t, rig.reader, "GET", path, nil)
		if resp.StatusCode != 503 || !strings.Contains(string(body), `"no_bundle"`) {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, body)
		}
	}
}

func TestAReaderReadsTheBundleWithAnETag(t *testing.T) {
	rig := newAPIRig(t)
	rig.sync(t)
	resp, body := rig.do(t, rig.reader, "GET", "/v1/bundle/version", nil)
	var v VersionInfo
	if resp.StatusCode != 200 || json.Unmarshal(body, &v) != nil || v.Sequence != 1 || v.ETag == "" {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	resp, body = rig.do(t, rig.reader, "GET", "/v1/bundle", nil)
	if resp.StatusCode != 200 || resp.Header.Get("ETag") != v.ETag || bundle.ETag(body) != v.ETag {
		t.Fatalf("%d %q %q", resp.StatusCode, resp.Header.Get("ETag"), v.ETag)
	}
	if _, _, err := bundle.Open(body, rig.pubs()); err != nil {
		t.Fatal(err)
	}
	resp, _ = rig.do(t, rig.reader, "GET", "/v1/bundle", map[string]string{"If-None-Match": v.ETag})
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("If-None-Match: %d", resp.StatusCode)
	}
}

// Design §17: reading a snapshot is not the right to trigger a sync.
func TestAReaderCannotSyncAndASyncerCan(t *testing.T) {
	rig := newAPIRig(t)
	if resp, _ := rig.do(t, rig.reader, "POST", "/v1/sync", nil); resp.StatusCode != 403 {
		t.Fatalf("reader: %d", resp.StatusCode)
	}
	resp, body := rig.do(t, rig.syncer, "POST", "/v1/sync", nil)
	var res Result
	if resp.StatusCode != 200 || json.Unmarshal(body, &res) != nil || res.Outcome != "published" {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if !strings.Contains(rig.out.String(), "port49-inventory: sync requested by user:alice@example.com") {
		t.Fatalf("the request is not said: %s", rig.out)
	}
}

// A sync the API runs is counted under the fixed trigger "api", whatever the
// request carries: a trigger is a metric label, and a request value would
// make it unbounded.
func TestAnAPISyncIsCountedUnderTheFixedTrigger(t *testing.T) {
	rig := newAPIRig(t)
	rig.do(t, rig.syncer, "POST", "/v1/sync?trigger=evil&source=a", map[string]string{"X-Trigger": "evil"})
	if n := testutil.CollectAndCount(rig.s.Metrics.Syncs); n != 1 ||
		testutil.ToFloat64(rig.s.Metrics.Syncs.WithLabelValues("api", OutcomePublished)) != 1 {
		t.Fatalf("%d series; api/published %v", n, testutil.ToFloat64(rig.s.Metrics.Syncs.WithLabelValues("api", OutcomePublished)))
	}
}

// A syncer may read too (design §17): the sync right includes the read right.
func TestASyncerMayRead(t *testing.T) {
	rig := newAPIRig(t)
	rig.sync(t)
	if resp, body := rig.do(t, rig.syncer, "GET", "/v1/bundle/version", nil); resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
}

// Identities match readers and syncers exactly: a case variant of an entry
// names someone else, and `*` or a glob is only text.
func TestAnIdentityMatchesExactly(t *testing.T) {
	for _, tc := range []struct {
		name     string
		readers  []string
		syncers  []string
		uris     []string
		emails   []string
		method   string
		path     string
		wantCode int
	}{
		{"a URI SAN differing in case", []string{"spiffe://port49.test/port49d"}, nil,
			[]string{"spiffe://port49.test/Port49d"}, nil, "GET", "/v1/bundle/version", 403},
		{"a URI SAN host differing in case", []string{"spiffe://port49.test/port49d"}, nil,
			[]string{"spiffe://PORT49.test/port49d"}, nil, "GET", "/v1/bundle/version", 403},
		{"an entry differing in case from the email", nil, []string{"user:Alice@example.com"},
			nil, []string{"alice@example.com"}, "POST", "/v1/sync", 403},
		{"a literal * reader", []string{"*"}, nil,
			[]string{"spiffe://port49.test/port49d"}, nil, "GET", "/v1/bundle/version", 403},
		{"a literal * syncer", nil, []string{"*"},
			nil, []string{"alice@example.com"}, "POST", "/v1/sync", 403},
		{"a glob reader", []string{"spiffe://port49.test/*"}, nil,
			[]string{"spiffe://port49.test/port49d"}, nil, "GET", "/v1/bundle/version", 403},
		{"a glob syncer", nil, []string{"user:*@example.com"},
			nil, []string{"alice@example.com"}, "POST", "/v1/sync", 403},
		{"the exact reader", []string{"spiffe://port49.test/port49d"}, nil,
			[]string{"spiffe://port49.test/port49d"}, nil, "GET", "/v1/bundle/version", 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newAPIRigWith(t, tc.readers, tc.syncers)
			var uris []*url.URL
			for _, u := range tc.uris {
				uris = append(uris, uri(u))
			}
			c := rig.client(t, testpki.Leaf{CommonName: "c", URIs: uris, Emails: tc.emails})
			if resp, body := rig.do(t, c, tc.method, tc.path, nil); resp.StatusCode != tc.wantCode {
				t.Fatalf("%d %s", resp.StatusCode, body)
			}
		})
	}
}

// A workload cannot take a person's rights: a URI SAN spelled as a person's
// identity names no one, for a sync or a read.
func TestAURISANCannotImpersonateAPerson(t *testing.T) {
	rig := newAPIRigWith(t, []string{"user:alice@example.com"}, []string{"user:alice@example.com"})
	forged := rig.client(t, testpki.Leaf{CommonName: "alice", URIs: []*url.URL{uri("user:alice@example.com")}})
	for _, m := range []struct{ method, path string }{{"POST", "/v1/sync"}, {"GET", "/v1/bundle/version"}} {
		if resp, body := rig.do(t, forged, m.method, m.path, nil); resp.StatusCode != 403 {
			t.Fatalf("%s %s: %d %s", m.method, m.path, resp.StatusCode, body)
		}
	}
	if rig.s.Current() != nil {
		t.Fatal("the forged caller ran a sync")
	}
}

// One URI SAN and one email SAN name the workload only: the email grants
// nothing, so the person's sync right does not come with it.
func TestAURISANAndAnEmailSANNameTheWorkloadOnly(t *testing.T) {
	rig := newAPIRigWith(t, []string{"spiffe://port49.test/port49d"}, []string{"user:alice@example.com"})
	both := rig.client(t, testpki.Leaf{CommonName: "d", URIs: []*url.URL{uri("spiffe://port49.test/port49d")},
		Emails: []string{"alice@example.com"}})
	if resp, body := rig.do(t, both, "POST", "/v1/sync", nil); resp.StatusCode != 403 {
		t.Fatalf("sync: %d %s", resp.StatusCode, body)
	}
	if resp, body := rig.do(t, both, "GET", "/v1/bundle/version", nil); resp.StatusCode != 503 {
		t.Fatalf("read: %d %s", resp.StatusCode, body)
	}
}

// A path that is not canonical is refused 400 before anyone is named, never
// redirected, counted, and said with a fixed label, never the path.
func TestANonCanonicalPathIsRefused(t *testing.T) {
	rig := newAPIRig(t)
	rig.sync(t)
	rig.out.Reset()
	paths := []string{"/v1//bundle", "/v1/x/../bundle", "/v1/./bundle", "/v1/%2e%2e/v1/bundle", "/v1/bundle/",
		"/v1/%2E/sync"}
	for _, p := range paths {
		for _, c := range []*http.Client{rig.reader, rig.nobody} {
			c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			if resp, body := rig.do(t, c, "GET", p, nil); resp.StatusCode != 400 || !strings.Contains(string(body), `"bad_path"`) {
				t.Fatalf("%s: %d %s", p, resp.StatusCode, body)
			}
		}
	}
	if resp, _ := rig.do(t, rig.syncer, "POST", "/v1/./sync", nil); resp.StatusCode != 400 || rig.s.Current().Doc.Sequence != 1 {
		t.Fatalf("POST /v1/./sync: %d", resp.StatusCode)
	}
	if n := testutil.ToFloat64(rig.s.Metrics.APIRefused.WithLabelValues("bad_path")); n != float64(2*len(paths)+1) {
		t.Fatalf("counted %v", n)
	}
	out := rig.out.String()
	if strings.Count(out, "port49-inventory: api: refused a path that is not canonical") != 1 || strings.Contains(out, "..") ||
		strings.Contains(out, "//") {
		t.Fatalf("%s", out)
	}
}

func TestACallerInNeitherListIsRefusedAndSaidOnce(t *testing.T) {
	rig := newAPIRig(t)
	for i := 0; i < 3; i++ {
		if resp, _ := rig.do(t, rig.nobody, "GET", "/v1/bundle/version", nil); resp.StatusCode != 403 {
			t.Fatalf("%d", resp.StatusCode)
		}
	}
	// Said once per reason and caller, whatever paths it cycles through
	// (pre-flight minor 3), and naming a fixed route, never the path it sent:
	// a decoded path is text the caller chose.
	rig.do(t, rig.nobody, "GET", "/v1/devices/10.0.0.1%0aport49-inventory:%20forged", nil)
	out := rig.out.String()
	if n := strings.Count(out, "port49-inventory: api: refused spiffe://port49.test/other"); n != 1 ||
		strings.Contains(out, "forged") || !strings.Contains(out, "(read)") {
		t.Fatalf("said %d times: %s", n, out)
	}
}

// The refusals remembered as said are bounded: past maxTold distinct
// callers, a refusal is still answered and counted, and not said.
func TestRefusalsSaidAreBounded(t *testing.T) {
	rig := newSyncRig(t, syncPolicy, devices(1))
	a := &API{Syncer: rig.s, Now: time.Now, Log: rig.out, Metrics: rig.s.Metrics}
	for i := 0; i < maxTold+10; i++ {
		w := httptest.NewRecorder()
		a.refuse(w, "forbidden", fmt.Sprintf("spiffe://port49.test/c%d", i), "read")
		if w.Code != 403 {
			t.Fatalf("%d", w.Code)
		}
	}
	if n := strings.Count(rig.out.String(), "api: refused"); n != maxTold || len(a.told) != maxTold {
		t.Fatalf("said %d, remembered %d; want %d", n, len(a.told), maxTold)
	}
}

// A certificate from another CA gets no answer: the anchor is one CA.
func TestACertificateFromAnotherCAGetsNoAnswer(t *testing.T) {
	rig := newAPIRig(t)
	other, err := testpki.NewCA("another CA", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := other.Issue(testpki.Leaf{CommonName: "d", URIs: []*url.URL{uri("spiffe://port49.test/port49d")},
		Client: true, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)})
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: rig.ca.Pool(), Certificates: []tls.Certificate{cert}}}}
	if _, err := c.Get(rig.srv.URL + "/v1/bundle/version"); err == nil {
		t.Fatal("answered a certificate from another CA")
	}
}

// Ambiguity fails closed: two URI SANs name no one.
func TestTwoURISANsAreRefused(t *testing.T) {
	rig := newAPIRig(t)
	two := rig.client(t, testpki.Leaf{CommonName: "d", URIs: []*url.URL{uri("spiffe://port49.test/port49d"),
		uri("spiffe://port49.test/other")}})
	if resp, _ := rig.do(t, two, "GET", "/v1/bundle/version", nil); resp.StatusCode != 403 {
		t.Fatalf("%d", resp.StatusCode)
	}
}

// Mutual TLS on every path: no certificate, no answer.
func TestNoClientCertificateGetsNoAnswer(t *testing.T) {
	rig := newAPIRig(t)
	bare := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: rig.ca.Pool()}}}
	for _, path := range []string{"/v1/bundle/version", "/v1/healthz", "/nowhere"} {
		if _, err := bare.Get(rig.srv.URL + path); err == nil {
			t.Fatalf("%s answered without a client certificate", path)
		}
	}
}

// The API has no health path: /healthz and /readyz are on metrics_listen.
func TestTheAPIHasNoHealthPath(t *testing.T) {
	rig := newAPIRig(t)
	rig.sync(t)
	for _, path := range []string{"/v1/healthz", "/healthz", "/readyz"} {
		if resp, _ := rig.do(t, rig.reader, "GET", path, nil); resp.StatusCode != 404 {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
	}
}

func TestADiffNamesWhatChangedSinceASequence(t *testing.T) {
	rig := newAPIRig(t)
	rig.sync(t)
	rig.src.inv = devices(4)
	rig.sync(t)
	resp, body := rig.do(t, rig.reader, "GET", "/v1/bundle/diff?from=1", nil)
	var d DiffResult
	if resp.StatusCode != 200 || json.Unmarshal(body, &d) != nil || d.From != 1 || d.To != 2 ||
		!strings.Contains(d.Summary, "+1 device(s)") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if resp, _ := rig.do(t, rig.reader, "GET", "/v1/bundle/diff?from=x", nil); resp.StatusCode != 400 {
		t.Fatalf("from=x: %d", resp.StatusCode)
	}
	if resp, _ := rig.do(t, rig.reader, "GET", "/v1/bundle/diff?from=99", nil); resp.StatusCode != 404 {
		t.Fatalf("from=99: %d", resp.StatusCode)
	}
}

// A diff that fails for any reason but a bundle not kept is a 500 with a
// fixed body; what failed is said in the log, not sent to the reader.
func TestADiffThatFailsIsNotNotKept(t *testing.T) {
	rig := newAPIRig(t)
	if resp, body := rig.do(t, rig.reader, "GET", "/v1/bundle/diff?from=1", nil); resp.StatusCode != 503 ||
		!strings.Contains(string(body), `"no_bundle"`) {
		t.Fatalf("before a bundle: %d %s", resp.StatusCode, body)
	}
	rig.sync(t)
	if err := os.Remove(rig.s.PolicyFile); err != nil {
		t.Fatal(err)
	}
	resp, body := rig.do(t, rig.reader, "GET", "/v1/bundle/diff?from=1", nil)
	if resp.StatusCode != 500 || strings.TrimSpace(string(body)) != `{"error":"internal"}` {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if !strings.Contains(rig.out.String(), "port49-inventory: api: diff from 1:") ||
		!strings.Contains(rig.out.String(), "policy.yaml") {
		t.Fatalf("the failure is not said: %s", rig.out)
	}
	// Said once per caller, not once per request.
	for i := 0; i < 3; i++ {
		rig.do(t, rig.reader, "GET", fmt.Sprintf("/v1/bundle/diff?from=%d", i+1), nil)
	}
	if n := strings.Count(rig.out.String(), "port49-inventory: api: diff from"); n != 1 {
		t.Fatalf("said %d times: %s", n, rig.out)
	}
}

// The diff and its To come from one bundle published.
func TestADiffNamesTheBundleItWasTakenAgainst(t *testing.T) {
	rig := newAPIRig(t)
	rig.sync(t)
	rig.src.inv = devices(4)
	rig.sync(t)
	rep, to, err := rig.s.Diff(1)
	if err != nil || to != 2 || !strings.Contains(rep.Summary(), "+1 device(s)") {
		t.Fatalf("%d %v %s", to, err, rep.Summary())
	}
	if _, _, err := rig.s.Diff(99); !errors.Is(err, ErrNotKept) {
		t.Fatalf("from 99: %v", err)
	}
}

// Server refuses a nil trust anchor: crypto/tls would verify a client
// against the system roots.
func TestServerRefusesANilAnchor(t *testing.T) {
	ca, err := testpki.NewCA("c", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := ca.Issue(testpki.Leaf{CommonName: "inv", IPs: testpki.Loopback(), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour)})
	if s, err := Server("127.0.0.1:0", cert, nil, http.NotFoundHandler(), log.New(io.Discard, "", 0)); err == nil || s != nil {
		t.Fatalf("served with a nil anchor: %v", err)
	}
}

// Server itself, on a real listener: HTTP/1.1 even to a client asking for
// h2, headers bounded, and the timeouts set.
func TestServerServesHTTP1WithBoundedHeaders(t *testing.T) {
	rig := newAPIRig(t)
	srvCert, _ := rig.ca.Issue(testpki.Leaf{CommonName: "inv", IPs: testpki.Loopback(),
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)})
	api := &API{Syncer: rig.s, Readers: []string{"spiffe://port49.test/port49d"}, Now: time.Now, Log: rig.out,
		Metrics: rig.s.Metrics}
	s, err := Server("127.0.0.1:0", srvCert, rig.ca.Pool(), api.Handler(), log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if s.ReadHeaderTimeout != 10*time.Second || s.ReadTimeout != 30*time.Second || s.WriteTimeout != 6*time.Minute ||
		s.IdleTimeout != 2*time.Minute || s.MaxHeaderBytes != 16<<10 {
		t.Fatalf("timeouts or header bound: %+v", s)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.ServeTLS(ln, "", "")
	t.Cleanup(func() { s.Close() })
	base := "https://" + ln.Addr().String()
	tr := rig.reader.Transport.(*http.Transport).Clone()
	tr.ForceAttemptHTTP2 = true
	tr.TLSClientConfig.NextProtos = []string{"h2", "http/1.1"}
	c := &http.Client{Timeout: 10 * time.Second, Transport: tr}
	resp, err := c.Get(base + "/v1/bundle/version")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.ProtoMajor != 1 || resp.TLS.NegotiatedProtocol == "h2" || resp.StatusCode != 503 {
		t.Fatalf("%s %q %d", resp.Proto, resp.TLS.NegotiatedProtocol, resp.StatusCode)
	}
	req, _ := http.NewRequest("GET", base+"/v1/bundle/version", nil)
	req.Header.Set("X-Big", strings.Repeat("a", 32<<10))
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("a 32 KiB header: %d", resp.StatusCode)
	}
	// OPTIONS * reaches the handler, not net/http's ungated 200, and is
	// refused there, for a caller in neither list too.
	for _, cl := range []*http.Client{c, rig.nobody} {
		req, _ = http.NewRequest("OPTIONS", base, nil)
		req.URL.Opaque = "*"
		resp, err = cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("OPTIONS *: %d", resp.StatusCode)
		}
	}
}

func TestADeviceIsDescribedByAnyOfItsAddresses(t *testing.T) {
	rig := newAPIRig(t)
	rig.sync(t)
	resp, body := rig.do(t, rig.reader, "GET", "/v1/devices/10.0.0.2", nil)
	var v DeviceView
	if resp.StatusCode != 200 || json.Unmarshal(body, &v) != nil || v.Name != "leaf-02" || v.Admission != "admitted" {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if resp, _ := rig.do(t, rig.reader, "GET", "/v1/devices/192.0.2.1", nil); resp.StatusCode != 404 {
		t.Fatalf("unknown: %d", resp.StatusCode)
	}
}

// Spec §12: inventory export --from reads a bundle from the history, with
// the read right.
func TestABundleFromTheHistoryIsServedToAReader(t *testing.T) {
	rig := newAPIRig(t)
	rig.sync(t)
	rig.src.inv = devices(4)
	rig.sync(t)
	resp, body := rig.do(t, rig.reader, "GET", "/v1/bundle?sequence=1", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if doc, inv, err := bundle.Open(body, rig.pubs()); err != nil || doc.Sequence != 1 || len(inv.Devices) != 3 {
		t.Fatalf("%v %v", doc.Sequence, err)
	}
	for path, code := range map[string]int{"/v1/bundle?sequence=2": 200, "/v1/bundle?sequence=99": 404,
		"/v1/bundle?sequence=x": 400, "/v1/bundle?sequence=0": 400, "/v1/bundle?sequence=1&x=2": 400} {
		if resp, body := rig.do(t, rig.reader, "GET", path, nil); resp.StatusCode != code {
			t.Errorf("%s: %d %s", path, resp.StatusCode, body)
		}
	}
	if resp, _ := rig.do(t, rig.nobody, "GET", "/v1/bundle?sequence=1", nil); resp.StatusCode != 403 {
		t.Fatalf("nobody: %d", resp.StatusCode)
	}
}

// The query is bounded: sequence alone, once, a positive int64. Nothing
// else widens what a reader may ask for, and before the first bundle a
// history read is no_bundle.
func TestTheBundleQueryTakesOnlyOneSequence(t *testing.T) {
	rig := newAPIRig(t)
	if resp, body := rig.do(t, rig.reader, "GET", "/v1/bundle?sequence=1", nil); resp.StatusCode != 503 ||
		!strings.Contains(string(body), "no_bundle") {
		t.Fatalf("before the first: %d %s", resp.StatusCode, body)
	}
	rig.sync(t)
	for _, path := range []string{"/v1/bundle?sequence=", "/v1/bundle?sequence=-1",
		"/v1/bundle?sequence=9223372036854775808", "/v1/bundle?sequence=1&sequence=1", "/v1/bundle?seq=1",
		"/v1/bundle?sequence=1.0", "/v1/bundle?sequence=0x1", "/v1/bundle?sequence=%2e%2e%2f1",
		"/v1/bundle?sequence=%2B1", "/v1/bundle?sequence=01"} {
		if resp, body := rig.do(t, rig.reader, "GET", path, nil); resp.StatusCode != 400 ||
			!strings.Contains(string(body), "not_a_sequence") {
			t.Errorf("%s: %d %s", path, resp.StatusCode, body)
		}
	}
	if resp, body := rig.do(t, rig.reader, "GET", "/v1/bundle?sequence=9223372036854775807", nil); resp.StatusCode != 404 {
		t.Errorf("max int64: %d %s", resp.StatusCode, body)
	}
}
