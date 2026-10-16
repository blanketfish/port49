package oidc_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
)

func cluster(ns ...string) oidc.VerifierConfig {
	return oidc.VerifierConfig{Domain: oidc.Machines, Kind: oidc.KindK8s, Cluster: "l69_a", Issuer: k8sIssuer, Audience: "port49",
		Namespaces: ns, Algorithms: []oidc.Alg{oidc.RS256}}
}

func k8sSet(t *testing.T, iss *oidctest.Issuer, c *clock, v oidc.VerifierConfig) *oidc.Set {
	t.Helper()
	m := metrics.New(prometheus.NewRegistry())
	v.JWKS = iss.URL + "/jwks"
	ks := oidc.NewKeySet(oidc.KeySetConfig{Issuer: v.Issuer, JWKS: v.JWKS, Client: oidc.NewClient(iss.Roots()),
		Refresh: time.Hour, MaxAge: 24 * time.Hour, Now: c.Now, M: m})
	return &oidc.Set{Timing: oidc.DefaultTiming, Now: c.Now, M: m, Verifiers: []*oidc.Verifier{{VerifierConfig: v, Keys: ks}}}
}

func TestAServiceAccountTokenVerifies(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := k8sSet(t, iss, c, cluster("netops"))
	a, err := set.Verify(context.Background(), iss.ServiceAccountToken(t, "k1", k8sIssuer, "port49", "netops", "oxidized", c.Now(), nil))
	if err != nil {
		t.Fatal(err)
	}
	if a.Domain != oidc.Machines || a.Principal != "system:serviceaccount:netops:oxidized" || !a.AuthTime.Equal(c.Now()) ||
		a.K8s == nil || a.K8s.Pod != "oxidized-7d9f" || a.K8s.PodUID == "" || a.K8s.ServiceAccountUID == "" ||
		a.K8s.Node != "l69-a-worker" || a.K8s.JTI == "" || a.K8s.Cluster != "l69_a" {
		t.Fatalf("assertion %+v %+v", a, a.K8s)
	}
	if cred := a.Credential(); cred.Method != "k8s" || cred.Iss != k8sIssuer || cred.Sub != a.Principal || cred.Sid != "" {
		t.Fatalf("credential %+v", cred)
	}
}

func TestK8sRefusals(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := k8sSet(t, iss, c, cluster("netops"))
	now := c.Now()
	bind := func(f func(m map[string]any)) map[string]any {
		m := map[string]any{"namespace": "netops",
			"serviceaccount": map[string]any{"name": "oxidized", "uid": "u1"},
			"pod":            map[string]any{"name": "p", "uid": "u2"}}
		f(m)
		return map[string]any{"kubernetes.io": m}
	}
	for name, tc := range map[string]struct {
		extra map[string]any
		kind  error
		want  string
	}{
		"two audiences":    {map[string]any{"aud": []string{"port49", "vault"}}, oidc.ErrInvalid, "its aud is not exactly [port49]"},
		"another audience": {map[string]any{"aud": "https://kubernetes.default.svc"}, oidc.ErrInvalid, "its aud is not exactly [port49]"},
		"no exp":           {map[string]any{"exp": nil}, oidc.ErrInvalid, "it has no exp"},
		"no iat":           {map[string]any{"iat": nil}, oidc.ErrInvalid, "it has no iat"},
		"old": {map[string]any{"iat": now.Add(-3 * time.Hour).Unix(), "exp": now.Add(time.Hour).Unix()}, oidc.ErrInvalid,
			"the kubelet refreshes a projected token at about 80% of its expirationSeconds, so keep expirationSeconds at or under 3600"},
		"ahead":           {map[string]any{"iat": now.Add(2 * time.Minute).Unix()}, oidc.ErrInvalid, "ahead of the broker's clock"},
		"a session claim": {map[string]any{"auth_time": now.Unix()}, oidc.ErrInvalid, "it carries auth_time"},
		"no binding":      {map[string]any{"kubernetes.io": nil}, oidc.ErrInvalid, "it carries no kubernetes.io claim"},
		"no pod":          {bind(func(m map[string]any) { delete(m, "pod") }), oidc.ErrInvalid, "it is not bound to a pod"},
		"secret-bound":    {bind(func(m map[string]any) { m["secret"] = map[string]any{"name": "s", "uid": "u"} }), oidc.ErrInvalid, "it is bound to a Secret"},
		"another account": {bind(func(m map[string]any) { m["serviceaccount"] = map[string]any{"name": "other", "uid": "u"} }), oidc.ErrInvalid, "does not name its sub's service account"},
		"another ns":      {bind(func(m map[string]any) { m["namespace"] = "backup" }), oidc.ErrInvalid, "does not name its sub's service account"},
		"no sa uid":       {bind(func(m map[string]any) { m["serviceaccount"] = map[string]any{"name": "oxidized"} }), oidc.ErrInvalid, "no serviceaccount uid"},
		"not a sa sub":    {map[string]any{"sub": "admin"}, oidc.ErrUnmapped, "its sub is not system:serviceaccount:<namespace>:<name>"},
		"unlisted ns": {map[string]any{"sub": "system:serviceaccount:kube-system:default", "kubernetes.io": map[string]any{"namespace": "kube-system",
			"serviceaccount": map[string]any{"name": "default", "uid": "u"}, "pod": map[string]any{"name": "p", "uid": "u"}}},
			oidc.ErrUnmapped, "its namespace kube-system is not one cluster l69_a (" + k8sIssuer + ") lists in namespaces"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := set.Verify(context.Background(), iss.ServiceAccountToken(t, "k1", k8sIssuer, "port49", "netops", "oxidized", now, tc.extra))
			if !errors.Is(err, tc.kind) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %v %q", err, tc.kind, tc.want)
			}
			if oidc.MethodOf(err) != "k8s" {
				t.Fatalf("method %q", oidc.MethodOf(err))
			}
		})
	}
}

// A typ of at+jwt is a provider's access token, never a cluster's.
func TestAK8sTokenTypIsJWTOrNone(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := k8sSet(t, iss, c, cluster("netops"))
	claims := map[string]any{"iss": k8sIssuer, "aud": []string{"port49"}, "sub": "system:serviceaccount:netops:oxidized",
		"iat": c.Now().Unix(), "exp": c.Now().Add(time.Minute).Unix(), "kubernetes.io": map[string]any{"namespace": "netops",
			"serviceaccount": map[string]any{"name": "oxidized", "uid": "u"}, "pod": map[string]any{"name": "p", "uid": "u"}}}
	for typ, ok := range map[string]bool{"JWT": true, "application/jwt": true, "at+jwt": false, "logout+jwt": false} {
		_, err := set.Verify(context.Background(), iss.TokenWith(t, "k1", map[string]any{"kid": "k1", "typ": typ}, claims))
		if (err == nil) != ok {
			t.Errorf("typ %s: %v", typ, err)
		}
	}
}

// Review Focus 1: the binding is read by exact name at every level.
func TestAK8sBindingIsReadByExactName(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := k8sSet(t, iss, c, cluster("netops"))
	now := c.Now()
	for name, body := range map[string]string{
		"Kubernetes.io": `"Kubernetes.io":{"namespace":"netops","serviceaccount":{"name":"oxidized","uid":"u"},"pod":{"name":"p","uid":"u"}}`,
		"Pod":           `"kubernetes.io":{"namespace":"netops","serviceaccount":{"name":"oxidized","uid":"u"},"Pod":{"name":"p","uid":"u"}}`,
		"Name":          `"kubernetes.io":{"namespace":"netops","serviceaccount":{"Name":"oxidized","uid":"u"},"pod":{"name":"p","uid":"u"}}`,
		// A second spelling beside the exact one is a token two readers read two ways.
		"Kubernetes.io beside": `"kubernetes.io":{"namespace":"netops","serviceaccount":{"name":"oxidized","uid":"u"},"pod":{"name":"p","uid":"u"}},"Kubernetes.io":{}`,
		"Pod beside":           `"kubernetes.io":{"namespace":"netops","serviceaccount":{"name":"oxidized","uid":"u"},"pod":{"name":"p","uid":"u"},"Pod":{"name":"q","uid":"v"}}`,
		"Name beside":          `"kubernetes.io":{"namespace":"netops","serviceaccount":{"name":"oxidized","Name":"x","uid":"u"},"pod":{"name":"p","uid":"u"}}`,
		"UID beside":           `"kubernetes.io":{"namespace":"netops","serviceaccount":{"name":"oxidized","uid":"u"},"pod":{"name":"p","uid":"u","UID":"v"}}`,
		"two pods":             `"kubernetes.io":{"namespace":"netops","serviceaccount":{"name":"oxidized","uid":"u"},"pod":{"name":"p","uid":"u"},"pod":{"name":"q","uid":"v"}}`,
	} {
		raw := iss.TokenRaw(t, "k1", fmt.Sprintf(`{"iss":%q,"aud":["port49"],"sub":"system:serviceaccount:netops:oxidized",`+
			`"iat":%d,"exp":%d,%s}`, k8sIssuer, now.Unix(), now.Add(time.Minute).Unix(), body))
		if _, err := set.Verify(context.Background(), raw); !errors.Is(err, oidc.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Review Focus 3: a cluster signing ES256 under the default RS256 pin.
func TestAK8sTokenUnderAnUnpinnedAlgorithmIsRefused(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	iss.AddKey(t, "e1", oidc.ES256)
	set := k8sSet(t, iss, c, cluster("netops"))
	_, err := set.Verify(context.Background(), iss.ServiceAccountToken(t, "e1", k8sIssuer, "port49", "netops", "oxidized", c.Now(), nil))
	if !errors.Is(err, oidc.ErrInvalid) || !strings.Contains(err.Error(), "its algorithm is not one") {
		t.Fatalf("%v", err)
	}
}

// Review Focus 5: a 253-byte name verifies whole.
func TestALongServiceAccountVerifies(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := k8sSet(t, iss, c, cluster("netops"))
	name := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	a, err := set.Verify(context.Background(), iss.ServiceAccountToken(t, "k1", k8sIssuer, "port49", "netops", name, c.Now(), nil))
	if err != nil || a.Principal != "system:serviceaccount:netops:"+name {
		t.Fatalf("%v %q", err, a.Principal)
	}
}

// On a broker whose verifiers are all k8s, a token from an unknown cluster
// is recorded k8s: oidc is a word its operator never configured (pre-flight M1).
func TestAnUnknownIssuerAtAClusterOnlySetIsK8s(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := k8sSet(t, iss, c, cluster("netops"))
	_, err := set.Verify(context.Background(), iss.ServiceAccountToken(t, "k1", "https://elsewhere.port49.lab", "port49", "netops", "oxidized", c.Now(), nil))
	if !errors.Is(err, oidc.ErrInvalid) || !strings.Contains(err.Error(), "no configured verifier accepts its issuer") ||
		oidc.MethodOf(err) != "k8s" {
		t.Fatalf("%v %q", err, oidc.MethodOf(err))
	}
}

// A refusal never quotes an unverified token, a cluster's either.
func TestAForgedClusterTokenIsNotQuoted(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := k8sSet(t, iss, c, cluster("netops"))
	forger := oidctest.NewIssuer(t)
	raw := forger.ServiceAccountToken(t, "k1", k8sIssuer, "port49", "netops", "marker-sa", c.Now(), nil)
	_, err := set.Verify(context.Background(), raw)
	if !errors.Is(err, oidc.ErrInvalid) || strings.Contains(err.Error(), "marker-sa") {
		t.Fatalf("%v", err)
	}
}
