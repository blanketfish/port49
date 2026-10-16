package oidc_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
)

const k8sIssuer = "https://kubernetes.default.svc.cluster.local"

// clusterKeys is a key set reading iss's /jwks directly, configured with
// k8sIssuer, which nothing resolves; migrating are the other issuers on the
// same jwks.
func clusterKeys(t *testing.T, iss *oidctest.Issuer, c *clock, s *said, migrating ...string) *oidc.KeySet {
	t.Helper()
	return oidc.NewKeySet(oidc.KeySetConfig{Issuer: k8sIssuer, JWKS: iss.URL + "/jwks", Migrating: migrating,
		Client: oidc.NewClient(iss.Roots()), Refresh: time.Hour, MaxAge: 24 * time.Hour, Now: c.Now,
		M: metrics.New(prometheus.NewRegistry()), Say: s.Say})
}

// fetch fetches once and waits for the discovery read that follows it, which
// runs after Fetch returns (pre-flight I8).
func fetch(t *testing.T, ks *oidc.KeySet) {
	t.Helper()
	if err := ks.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	ks.WaitDiscoveryForTest()
}

// A discovery that agrees is silent, and so is its jwks_uri naming the
// issuer's host, as every self-managed cluster's does (pre-flight I7): the
// configured jwks is the API server's address, which discovery never names.
func TestAClusterKeySetReadsTheConfiguredJWKS(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	iss.Discovery(func(d map[string]any) { d["issuer"] = k8sIssuer; d["jwks_uri"] = k8sIssuer + "/openid/v1/jwks" })
	ks := clusterKeys(t, iss, c, s)
	fetch(t, ks)
	if keys, _, _ := ks.Status(); len(keys) != 1 {
		t.Fatalf("keys %v", keys)
	}
	if strings.Contains(s.all(), "discovery") || strings.Contains(s.all(), "jwks_uri") {
		t.Fatalf("a matching discovery is said: %s", s.all())
	}
}

// The keys come from jwks whatever discovery says: an unreachable discovery
// changes nothing, and is said once.
func TestAClusterKeySetNeedsNoDiscovery(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	iss.DiscoveryStatus(http.StatusForbidden)
	ks := clusterKeys(t, iss, c, s)
	for range 2 {
		fetch(t, ks)
	}
	if n := strings.Count(s.all(), "the cluster's discovery at "+iss.URL+"/.well-known/openid-configuration could not be read"); n != 1 {
		t.Fatalf("said %d times: %s", n, s.all())
	}
}

func TestAClusterKeySetSaysADifferentIssuer(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	iss.Discovery(func(d map[string]any) { d["issuer"] = "https://l69-a.port49.lab" })
	ks := clusterKeys(t, iss, c, s)
	fetch(t, ks)
	want := "names issuer https://l69-a.port49.lab: its tokens carry that iss, so each is refused until " +
		"broker.identity.machines[].issuer is https://l69-a.port49.lab"
	if !strings.Contains(s.all(), want) {
		t.Fatalf("said %s", s.all())
	}
}

// During an issuer migration (decision 49 ruling 4) discovery names the
// other configured issuer: no false alarm (pre-flight I7).
func TestAClusterKeySetIsQuietDuringAMigration(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	iss.Discovery(func(d map[string]any) { d["issuer"] = "https://new.port49.lab" })
	ks := clusterKeys(t, iss, c, s, "https://new.port49.lab")
	fetch(t, ks)
	if strings.Contains(s.all(), "names issuer") {
		t.Fatalf("said %s", s.all())
	}
}

// A discovery document with no issuer says so, not "names issuer :"
// (pre-flight M2).
func TestAClusterKeySetSaysNoIssuer(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	iss.Discovery(func(d map[string]any) { delete(d, "issuer") })
	ks := clusterKeys(t, iss, c, s)
	fetch(t, ks)
	if !strings.Contains(s.all(), "names no issuer") || strings.Contains(s.all(), "names issuer :") {
		t.Fatalf("said %s", s.all())
	}
}

// A stalled discovery holds no mint: the fetch's outcome is out before
// discovery is read (pre-flight I8).
func TestAStalledDiscoveryHoldsNoFetch(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	arrived, release := iss.HoldDiscovery()
	defer release()
	ks := clusterKeys(t, iss, c, s)
	done := make(chan error, 1)
	go func() { done <- ks.Fetch(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Fetch waited on a stalled discovery")
	}
	select { // the discovery was asked, and is what stalls: the test holds something
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("discovery was never read, so nothing was held")
	}
}

// A failed JWKS fetch is a failed fetch, counted, as for an OIDC issuer; a
// failed discovery is not.
func TestAClusterJWKSOutageKeepsTheHeldKeys(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	ks := clusterKeys(t, iss, c, s)
	if err := ks.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	iss.Fail(http.StatusServiceUnavailable)
	c.Add(2 * time.Hour)
	if err := ks.Fetch(context.Background()); err == nil {
		t.Fatal("a 503 JWKS fetch succeeded")
	}
	if k, err := ks.Key(context.Background(), "k1", oidc.RS256); err != nil || k.Kid != "k1" {
		t.Fatalf("the held key: %v %v", k, err)
	}
	s.await(t, "keys not refreshed since", 1)
}
