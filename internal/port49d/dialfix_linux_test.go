package port49d

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/store"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
	"github.com/rhwendt/port49/internal/testpki"
)

// silentEndpoint is a host:port that accepts TCP and never speaks: a member
// cut off from this process.
func silentEndpoint(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { <-done; c.Close() }()
		}
	}()
	t.Cleanup(func() { close(done); l.Close() })
	return l.Addr().String()
}

// endpointsAre rewrites the directory store's endpoint list in the file at
// path from the one member behind addr to list (each a host:port).
func endpointsAre(t *testing.T, path, addr string, list ...string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	old := "endpoints: [https://" + addr + "]"
	body := strings.Replace(string(raw), old, "endpoints: [https://"+strings.Join(list, ", https://")+"]", 1)
	if body == string(raw) {
		t.Fatalf("%s has no %q", path, old)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// L74 cell (f)'s shape: one directory member answers and another does not.
// The broker starts live: Open does not wait on the silent member
// (clientv3's RejectOldCluster would fail it, and send a healthy start to
// the snapshot), and no snapshot is served.
func TestABrokerWithOneSilentDirectoryMemberStartsLive(t *testing.T) {
	var out syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	var log syncBuffer
	stderr, stdout = &out, &log
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	endpointsAre(t, f.broker, f.dproxy.Addr(), f.dproxy.Addr(), silentEndpoint(t))
	start := time.Now()
	startBroker(t, f.broker, &out, 1)
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("the start took %v", d)
	}
	if strings.Contains(out.String(), "serving from") || strings.Contains(out.String(), "not answering") {
		t.Fatalf("a directory with a live member was treated as down:\n%s", out.String())
	}
}

// When the directory's only endpoint is silent, a broker with a young
// snapshot serves from it (R19) and does not exit.
func TestABrokerWhoseOnlyDirectoryEndpointIsSilentServesTheSnapshot(t *testing.T) {
	var out, log syncBuffer
	e, o, every := stderr, stdout, snapshotEvery
	t.Cleanup(func() { stderr, stdout, snapshotEvery = e, o, every })
	stderr, stdout, snapshotEvery = &out, &log, time.Second
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	_, stopB := startBroker(t, f.broker, &out, 1)
	_, stopD := runSplitDaemon(t, f.daemon, &out, 1)
	waitSnapshots(t, f.srv, 2)
	if err := stopD(); errors.Is(err, errDidNotStop) {
		t.Fatal(err)
	}
	if err := stopB(); errors.Is(err, errDidNotStop) {
		t.Fatal(err)
	}
	endpointsAre(t, f.broker, f.dproxy.Addr(), silentEndpoint(t))
	startBroker(t, f.broker, &out, 2)
	if want := "port49-broker: directory store: not answering; serving from"; !strings.Contains(out.String(), want) {
		t.Fatalf("no %q:\n%s", want, out.String())
	}
}

// L74 (d), (g), (i): a directory member going dark with quorum intact does
// not stop the directory answering. The running process's check, a read each
// directoryCheckEvery within call_timeout, never fails, so the process never
// says it is serving from the cache and refuses nothing.
func TestAFreshnessCheckSurvivesOneDarkDirectoryMember(t *testing.T) {
	c := etcdtest.StartCluster(t)
	var proxies []*etcdtest.Proxy
	var eps []string
	for _, e := range c.Endpoints {
		p := etcdtest.NewProxy(t, strings.TrimPrefix(e, "http://"))
		proxies, eps = append(proxies, p), append(eps, "http://"+p.Addr())
	}
	s, err := etcdstore.Open(etcdstore.Config{Endpoints: eps, Prefix: etcdtest.Prefix()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var h dirHandle
	h.set(s)
	every := directoryCheckEvery
	t.Cleanup(func() { directoryCheckEvery = every })
	directoryCheckEvery = 100 * time.Millisecond
	var out syncBuffer
	fresh := store.NewFreshness(time.Now)
	fresh.FeedUp(true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { keepFresh(ctx, &h, fresh, 500*time.Millisecond, &out, "port49-broker", false); close(done) }()
	time.Sleep(time.Second)
	proxies[2].Hang(true)
	time.Sleep(12 * time.Second)
	cancel()
	<-done
	if strings.Contains(out.String(), "not answering") {
		t.Fatalf("one dark member of three stopped the directory answering:\n%s", out.String())
	}
	if ok, why := fresh.Reachable(); !ok {
		t.Fatalf("the last check failed: %s", why)
	}
}

// A directory whose server this process's CA does not verify is a fault the
// operator fixes, never an outage: attempt's TLS probe names it, because
// Open no longer reports anything of the kind.
func TestAWrongCAIsAStoreFaultNotAnOutage(t *testing.T) {
	srv := etcdtest.Start(t, etcdtest.Options{TLS: true})
	now := time.Now()
	other, err := testpki.NewCA("other", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	id := writeIdentity(t, other, "port49-broker", now.Add(-time.Hour), now.Add(time.Hour), 0o600)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, other.PEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Role: config.RoleBroker}
	ref := storeRef{at: "stores.directory", dir: true, cfg: config.StoreConfig{Backend: "etcd", Etcd: &config.EtcdConfig{
		Endpoints: []string{srv.Endpoint}, CAFile: caFile, Prefix: "/port49/", Broker: &id, CallTimeout: 200 * time.Millisecond}}}
	_, err = attempt(context.Background(), cfg, ref, metrics.New(prometheus.NewRegistry()), io.Discard)
	var fault *storeFault
	if !errors.As(err, &fault) || errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a server this CA does not verify: %v", err)
	}
}

// probeTLS does not depend on endpoint order: a member whose certificate
// this CA does not verify is a fault of that member, so the start proceeds on
// the one that completes a handshake, whichever is listed first. Only when
// none does is it a storeFault (decision 35 and 51).
func TestProbeTLSIsIndependentOfEndpointOrder(t *testing.T) {
	good := etcdtest.Start(t, etcdtest.Options{TLS: true})
	bad := etcdtest.Start(t, etcdtest.Options{TLS: true}) // a CA of its own
	bad2 := etcdtest.Start(t, etcdtest.Options{TLS: true})
	tc := good.TLS(t, "port49-daemon")
	probe := func(eps ...string) error {
		return probeTLS(context.Background(), "stores.directory.etcd", eps, tc, time.Second)
	}
	for name, eps := range map[string][]string{
		"good first": {good.Endpoint, bad.Endpoint},
		"bad first":  {bad.Endpoint, good.Endpoint},
	} {
		if err := probe(eps...); err != nil {
			t.Errorf("%s: %v, want the start to proceed on the member that completes", name, err)
		}
	}
	var fault *storeFault
	for name, eps := range map[string][]string{
		"one bad":  {bad.Endpoint},
		"all bad":  {bad.Endpoint, bad2.Endpoint},
		"bad, bad": {bad2.Endpoint, bad.Endpoint},
	} {
		if err := probe(eps...); !errors.As(err, &fault) || errors.Is(err, store.ErrUnavailable) {
			t.Errorf("%s: %v, want a storeFault", name, err)
		}
	}
}

// A member that completes the handshake and then refuses this certificate
// (a TLS 1.3 server reads the client's certificate after the handshake, so
// the refusal arrives on the first read) is a fault of that member too: the
// start proceeds on a member that accepts it, and is a storeFault only
// when none does (dial fix round 3 review, M2).
func TestProbeTLSProceedsPastAMemberThatRefusesTheCertificate(t *testing.T) {
	good := etcdtest.Start(t, etcdtest.Options{TLS: true})
	refuser := etcdtest.Start(t, etcdtest.Options{TLS: true}) // a CA of its own
	tc := good.TLS(t, "port49-daemon")
	// Trust both servers, so the refuser's handshake completes and only its
	// refusal of good's client certificate is left to fail.
	tc.RootCAs = x509.NewCertPool()
	for _, s := range []*etcdtest.Server{good, refuser} {
		pem, err := os.ReadFile(filepath.Join(s.Dir, "ca.pem"))
		if err != nil {
			t.Fatal(err)
		}
		if !tc.RootCAs.AppendCertsFromPEM(pem) {
			t.Fatalf("no certificate in %s/ca.pem", s.Dir)
		}
	}
	probe := func(eps ...string) error {
		return probeTLS(context.Background(), "stores.directory.etcd", eps, tc, time.Second)
	}
	var fault *storeFault
	err := probe(refuser.Endpoint)
	if !errors.As(err, &fault) || !strings.Contains(err.Error(), "refused this certificate") {
		t.Fatalf("the refuser alone: %v, want its post-handshake refusal as a storeFault", err)
	}
	if err := probe(refuser.Endpoint, good.Endpoint); err != nil {
		t.Fatalf("the refuser first: %v, want the start to proceed on the member that accepts", err)
	}
}
