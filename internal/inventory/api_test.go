package inventory

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/testpki"
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
	s := Server("127.0.0.1:0", srvCert, ca.Pool(), api.Handler(), log.New(io.Discard, "", 0))
	rig.srv = httptest.NewUnstartedServer(s.Handler)
	rig.srv.TLS = s.TLSConfig
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
