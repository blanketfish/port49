package port49d

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// daemonMetrics is the newest port49d metrics address said on out.
func daemonMetrics(t *testing.T, out *syncBuffer) string {
	t.Helper()
	ms := regexp.MustCompile(`port49d: metrics on (127\.0\.0\.1:\d+)`).FindAllStringSubmatch(out.String(), -1)
	if len(ms) == 0 {
		t.Fatalf("no port49d metrics line:\n%s", out.String())
	}
	return ms[len(ms)-1][1]
}

// cachedFleet is splitFleet whose port49d keeps a context cache of ttl,
// with the health checks set by health ("" for the defaults).
func cachedFleet(t *testing.T, out *syncBuffer, ttl, health string) (*fleet, tacacsClient, string) {
	t.Helper()
	f := splitFleet(t)
	addUnderEtcd(t, f.daemon, "    context_cache: {ttl: "+ttl+"}\n"+health)
	api, _ := startBroker(t, f.broker, out, 1)
	tacacs := startSplitDaemon(t, f.daemon, out, 1)
	return f, tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}, api
}

// A session's commands are answered from the cache after the first
// (design §12): the counter says hits, and the start line says the
// cache's terms.
func TestASessionsCommandsAreAnsweredFromTheCache(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f, dev, api := cachedFleet(t, &out, "5s", "")
	waitFor(t, &out, "the context cache is on: a session's context is read from it for up to 5s")
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
	for i := 0; i < 3; i++ {
		if !dev.permits("alice", "show", "version") {
			t.Fatal("a command was refused")
		}
	}
	if v := metricAt(t, daemonMetrics(t, &out), `port49_context_cache_lookups_total{outcome="hit"}`); v < 2 {
		t.Fatalf("hits %v, want at least 2", v)
	}
}

// Review Focus 3: a context deleted by another process is denied at the
// next command, inside the TTL: the feed evicted it.
func TestAContextDeletedElsewhereIsNotAnsweredFromTheCache(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f, dev, api := cachedFleet(t, &out, "30s", "")
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
	if !dev.permits("alice", "show", "version") {
		t.Fatal("the first command was refused")
	}
	root := f.srv.Client(t, "root")
	if _, err := root.Delete(context.Background(), "/port49/v1/c/", clientv3.WithPrefix()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for dev.permits("alice", "show", "version") {
		if time.Now().After(deadline) {
			t.Fatal("a context deleted in the store was still answered 5s later, inside a 30s ttl")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if r := lastCommand(t, &log); r["reason"] != "context_missing" {
		t.Fatalf("denied %v, want context_missing", r["reason"])
	}
}

// Review Focus 3, revoked: a session revoked through the broker (the path
// through revokeown.go's SetRevokedAt, the whole revocation in decision 32's
// order) is denied credential_revoked inside the TTL, because the context's
// change reached the daemon's feed and evicted its entry, and the daemon's
// marks hold the principal besides (plan 7f, M-7). The control: the cached
// session is answered before.
func TestARevokedSessionIsDeniedInsideTheTTL(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	addUnderEtcd(t, f.daemon, "    context_cache: {ttl: 30s}\n")
	api, stopBroker := startBroker(t, f.broker, &out, 1)
	tacacs := startSplitDaemon(t, f.daemon, &out, 1)
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
	for i := 0; i < 2; i++ {
		if !dev.permits("alice", "configure") {
			t.Fatal("control: the cached session's command was refused before the revocation")
		}
	}
	if err := stopBroker(); err != nil {
		t.Fatal(err)
	}
	var rout, rerr bytes.Buffer
	if code := offlineRevoke([]string{"--offline", "--config", f.broker, "--principal", "user:alice@example.com"},
		&rout, &rerr); code != 0 {
		t.Fatalf("exit %d: %s", code, rerr.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	for dev.permits("alice", "configure") {
		if time.Now().After(deadline) {
			t.Fatal("a revoked session was still answered 5s later, inside a 30s ttl")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if r := lastCommand(t, &log); r["reason"] != "credential_revoked" {
		t.Fatalf("denied %v, want credential_revoked", r["reason"])
	}
}

// Through a store hang the cache answers past its TTL, counted stale and
// said once, until the listeners close (design §12; Ruling 5).
func TestAHungStoreServesTheCacheUntilTheListenersClose(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f, dev, api := cachedFleet(t, &out, "1s", "    health: {interval: 500ms, close_after: 8}\n")
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
	if !dev.permits("alice", "show", "version") {
		t.Fatal("the first command was refused")
	}
	time.Sleep(1200 * time.Millisecond) // past the ttl
	metrics := daemonMetrics(t, &out)
	f.proxy.Hang(true)
	if !dev.permits("alice", "show", "version") {
		t.Fatalf("a cached session's command was refused on a hung store; log %s", log.String())
	}
	if v := metricAt(t, metrics, `port49_context_cache_lookups_total{outcome="stale"}`); v < 1 {
		t.Fatalf("stale %v", v)
	}
	if n := strings.Count(out.String(), "serving cached login contexts past store.etcd.context_cache.ttl"); n != 1 {
		t.Fatalf("the stale line said %d times", n)
	}
	dev.permits("alice", "show", "version")
	if n := strings.Count(out.String(), "serving cached login contexts past"); n != 1 {
		t.Fatalf("the stale line said again in one run of stale serves: %d", n)
	}
	waitWithin(t, &out, "closing every listener so that devices use their local method", 15*time.Second)
}

// Review Focus 3: an entry the feed evicted is never served through an
// outage: the store is the only source, and it does not answer.
func TestAnEvictedContextIsNotServedThroughAnOutage(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f, dev, api := cachedFleet(t, &out, "30s", "    health: {interval: 500ms, close_after: 8}\n")
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
	dev.permits("alice", "show", "version")
	root := f.srv.Client(t, "root")
	if _, err := root.Delete(context.Background(), "/port49/v1/c/", clientv3.WithPrefix()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond) // the feed delivers the delete
	f.proxy.Hang(true)
	if dev.permits("alice", "show", "version") {
		t.Fatal("an evicted context was answered on a hung store")
	}
}

// No ttl, no cache: said at the start, and no lookup counted.
func TestNoCacheWithoutATTL(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	daemonCfg, _ := etcdSplit(t)
	startSplitDaemon(t, daemonCfg, &out, 1)
	waitFor(t, &out, "the context cache is off (store.etcd.context_cache.ttl is not set)")
}
