package broker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/testpki"
)

// startServerWith is startServer with the listener wired as both daemons
// wire it (Broker.Wire; Task 8), then set's overrides. It returns the URL and
// what the listener said.
func startServerWith(t *testing.T, f *fixture, set func(l *Listener)) (string, *lockedBuffer) {
	t.Helper()
	said := &lockedBuffer{}
	now := f.b.Now()
	srvCert, err := f.ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := f.b.Server("127.0.0.1:0", srvCert, f.ca.Pool())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := NewListener(Limit(ln, MaxConns), srv.TLSConfig, DefaultListenerLimits, f.b.Metrics, f.b.Now,
		func(format string, args ...any) { fmt.Fprintf(said, format+"\n", args...) })
	f.b.Wire(l)
	if set != nil {
		set(l)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "https://" + ln.Addr().String(), said
}

func postMint(t *testing.T, c *http.Client, url string) (int, string) {
	t.Helper()
	resp, err := c.Post(url+"/v1/tokens", "application/json", strings.NewReader(mintLeaf1))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// Under a directory whose every call would fail, a workload binds and mints
// over a real handshake on a listener wired as both daemons wire it, and the
// resolver is never asked; alice, on the same listener, is mapped through it
// (decision 40 ruling 5; pre-flight I-4).
func TestAWorkloadBindsWithoutAskingTheDirectory(t *testing.T) {
	f, _, w := newWorkloadFixture(t)
	f.b.Directory = directory.ForTestsStaticResolver(f.st, nil, directory.ErrUnavailable)
	url, _ := startServerWith(t, f, nil)
	if code, body := postMint(t, clientWith(f, w), url); code != http.StatusOK || !strings.Contains(body, workloadID) {
		t.Fatalf("the workload: %d %s", code, body)
	}
	if n := f.b.Directory.Calls.Load(); n != 0 {
		t.Fatalf("the directory was asked %d times", n)
	}
	if code, body := postMint(t, clientWith(f, f.alice), url); code != http.StatusServiceUnavailable ||
		!strings.Contains(body, "directory_unavailable") {
		t.Fatalf("alice: %d %s", code, body)
	}
	if f.b.Directory.Calls.Load() == 0 {
		t.Fatal("alice was not mapped through the directory")
	}
}

// A workload certificate naming no principal completes its handshake and is
// answered identity_unmapped over HTTP, recorded and closed before it binds:
// never a TLS alert the client cannot read (decision 40 ruling 3).
func TestAnUnmappedWorkloadIsAnsweredNotAlerted(t *testing.T) {
	f, wca, _ := newWorkloadFixture(t)
	two := f.workloadCert(t, wca, workloadID, "spiffe://corp.example.com/host/other")
	var refused []decision.Reason
	url, _ := startServerWith(t, f, func(l *Listener) {
		l.Refused = func(_, _ string, _ store.Credential, r decision.Reason) { refused = append(refused, r) }
	})
	code, body := postMint(t, clientWith(f, two), url)
	if code != http.StatusUnauthorized || !strings.Contains(body, `"identity_unmapped"`) ||
		!strings.Contains(body, "carries 2 URI SANs") {
		t.Fatalf("%d %s", code, body)
	}
	if len(refused) != 1 || refused[0] != decision.IdentityUnmapped {
		t.Fatalf("recorded %v", refused)
	}
}

// A workload's held connections count against its principal, as a person's
// do (decision 32): the cap's eviction names the SPIFFE ID. The gauge alone
// would pass with every workload held under "" (pre-flight M-8).
func TestAWorkloadsHeldConnectionsAreItsPrincipals(t *testing.T) {
	f, _, w := newWorkloadFixture(t)
	url, said := startServerWith(t, f, nil)
	for range DefaultListenerLimits.MaxPerPrincipal + 1 {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{w},
			RootCAs: f.ca.Pool(), MinVersion: tls.VersionTLS13}}}
		if code, body := postMint(t, c, url); code != http.StatusOK {
			t.Fatalf("%d %s", code, body)
		}
	}
	// Only the workload holds connections here, so the held gauge is its.
	eventually(t, "the cap held", func() bool { return f.gauge("held") == float64(DefaultListenerLimits.MaxPerPrincipal) })
	// Nothing else in this test names the workload: the line is the eviction's.
	eventually(t, "the eviction named the workload", func() bool { return strings.Contains(said.String(), workloadID) })
}

// A listener given Map without Caller would map a workload's certificate
// through the directory as a person's: it serves nothing (pre-flight I-4).
func TestAListenerWithMapButNoCallerServesNothing(t *testing.T) {
	f, _, _ := newWorkloadFixture(t)
	f.b.Directory = directory.ForTestsStaticResolver(f.st, nil, directory.ErrUnavailable)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	l := NewListener(Limit(ln, MaxConns), &tls.Config{}, DefaultListenerLimits, f.b.Metrics, f.b.Now, nil)
	l.Map = f.b.BindMap
	if _, err := l.Accept(); !errors.Is(err, ErrUnwired) {
		t.Fatalf("got %v", err)
	}
}

// BindMap never maps a workload's chain, whoever calls it: identity_unmapped,
// and the directory is not asked (decision 40 ruling 5; pre-flight I-4).
func TestBindMapNeverMapsAWorkload(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.b.Directory = directory.ForTestsStaticResolver(f.st, nil, directory.ErrUnavailable)
	_, ref := f.b.BindMap(context.Background(), *chainState(w, wca), store.Credential{})
	if ref == nil || ref.Reason != decision.IdentityUnmapped || f.b.Directory.Calls.Load() != 0 {
		t.Fatalf("refusal %+v, directory calls %d", ref, f.b.Directory.Calls.Load())
	}
}

// BindMap fails closed on a chain ending at both anchors too: machineChain
// answers it an error, and the directory is not asked.
func TestBindMapRefusesAChainEndingAtBothAnchors(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.b.Directory = directory.ForTestsStaticResolver(f.st, nil, directory.ErrUnavailable)
	cs := &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{w.Leaf, wca.Cert}, {w.Leaf, f.ca.Cert}}}
	_, ref := f.b.BindMap(context.Background(), *cs, store.Credential{})
	if ref == nil || ref.Reason != decision.TrustDomainUnresolved || ref.Error != string(decision.TrustDomainUnresolved) || f.b.Directory.Calls.Load() != 0 ||
		!strings.Contains(ref.Detail, "chains to both") {
		t.Fatalf("refusal %+v, directory calls %d", ref, f.b.Directory.Calls.Load())
	}
}
