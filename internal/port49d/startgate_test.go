package port49d

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/tacacs/wire"
	"github.com/blanketfish/port49/internal/testpki"
)

// mintOnce is one POST /v1/tokens for alice on device, never tried again
// (mintWith retries the gate's 503): its status, the login token when one
// was minted, and the body otherwise. A token is never printed.
func mintOnce(t *testing.T, addr, pki, device string) (status int, login, body string) {
	t.Helper()
	resp := postMint(t, addr, pki, device, "", testpki.LabClientCert, testpki.LabClientKey)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, "", string(raw)
	}
	var out api.MintResponse
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Results) != 1 {
		t.Fatalf("a 200 mint answer that does not hold one result: %v", err)
	}
	return resp.StatusCode, out.Results[0].Login, ""
}

// holdKeyspace takes the runner's hold as another replica's runner would,
// so a port49-broker started after it serves the API with its runner
// waiting behind it. release lets it go: that broker's runner then takes
// the hold within a second and hold_ttl/3, and runs its takeover.
func holdKeyspace(t *testing.T, f *fleet) (release func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	holding, _ := openBrokerFor(t, ctx, f.broker, metrics.New(prometheus.NewRegistry()), io.Discard)
	cfg, _ := loadBroker(t, f.broker)
	_, release, err := holding.raw.Hold(ctx, cfg.Stores.Session.Etcd.HoldTTL,
		"port49-broker on replica-z (pid 1, since 2026-10-08T00:00:00Z)", func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	return release
}

// putJudged writes meta/judged as a runner's takeover would, naming bundle,
// marked in doubt when inDoubt.
func putJudged(t *testing.T, f *fleet, bundle string, inDoubt bool) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"bundle": bundle, "in_doubt": inDoubt,
		"written_at": time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	c := f.srv.Client(t, "root")
	if _, err := c.Put(context.Background(), "/port49/v1/meta/judged", string(body)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Put(context.Background(), "/port49/v1/meta/judged_bundle", bundle); err != nil {
		t.Fatal(err)
	}
}

// A first start mints nothing between "listening on" and its runner's
// takeover, which purges every unspent token: the mint answers 503
// store_unavailable, the gate's gauge reads 1 and the broker stays ready
// (decision 36, the mint gate at a start). Once the takeover is done a
// mint succeeds, and its token is not purged. This is L49's run set 3
// race (tests/lab/results/L49-oxidized-juniper_vjunos-router.md), held
// open here by another holder so the window is not a matter of timing;
// TestATakeoverPurgesOnlyAnUnjudgedBundle waits it out instead.
func TestAFirstStartMintsNothingBeforeItsTakeover(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	tacacs := startSplitDaemon(t, f.daemon, &out, 1)
	release := holdKeyspace(t, f)
	api, _ := startBroker(t, f.broker, &out, 1)
	metricsAt := brokerLine.FindAllStringSubmatch(out.String(), -1)[0][2]
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	status, early, body := mintOnce(t, api, f.pki, "leaf1")
	if status != http.StatusServiceUnavailable || !strings.Contains(body, `"store_unavailable"`) {
		t.Errorf("a mint between \"listening on\" and the first takeover: %s", reply(status, body))
	}
	if early == "" { // refused: the gate's gauge says so, and readiness does not
		waitBrokerMetricAt(t, metricsAt, "port49_broker_mint_gate_closed 1")
		if code := readyzAt(t, metricsAt); code != http.StatusOK {
			t.Errorf("/readyz %d while the start's gate is closed: a broker's readiness is never the store's", code)
		}
	}
	release()
	waitWithin(t, &out, "is not the one the last runner judged (none recorded); ", 20*time.Second)
	if early != "" && dev.login("alice", early) != wire.AuthenStatusPass {
		t.Error("the token minted before the takeover was purged under it (L49's run set 3)")
	}
	waitFor(t, &out, "port49-broker: policy: mints open: this replica's takeover is done")
	waitBrokerMetricAt(t, metricsAt, "port49_broker_mint_gate_closed 0")
	status, tok, body := mintOnce(t, api, f.pki, "leaf1")
	if status != http.StatusOK {
		t.Fatalf("a mint after the takeover: %s", reply(status, body))
	}
	if st := dev.login("alice", tok); st != wire.AuthenStatusPass {
		t.Fatalf("a token minted once the takeover was done: %d", st)
	}
}

// A rolling restart is never held: meta/judged already names the bundle
// the new replica serves, so its first mint after "listening on"
// succeeds while another runner holds, and survives that runner's stop.
func TestARollingRestartMintsAtOnce(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	tacacs := startSplitDaemon(t, f.daemon, &out, 1)
	_, stopA := startBroker(t, f.broker, &out, 1)
	waitFor(t, &out, "runner: recorded bundle ")
	apiB, _ := startBroker(t, f.copyBroker(t), &out, 2)
	status, tok, body := mintOnce(t, apiB, f.pki, "leaf1")
	if status != http.StatusOK {
		t.Fatalf("the first mint on a replica started under a runner that judged its bundle: %s",
			reply(status, body))
	}
	waitFor(t, &out, "port49-broker: policy: mints open: meta/judged names bundle "+f.bundle(t))
	if err := stopA(); err != nil {
		t.Fatal(err)
	}
	waitWithin(t, &out, "is the one the last runner judged; no unspent token purged", 30*time.Second)
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	if st := dev.login("alice", tok); st != wire.AuthenStatusPass {
		t.Fatalf("a token minted at once on a rolling restart: %d", st)
	}
}

// A replica whose runner waits behind another holder opens its gate when
// meta/judged names the bundle it serves, not in doubt: that runner's
// takeover is done (decision 36).
func TestAReplicaBehindAnotherRunnerOpensWhenItsBundleIsJudged(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	holdKeyspace(t, f)
	api, _ := startBroker(t, f.broker, &out, 1)
	metricsAt := brokerLine.FindAllStringSubmatch(out.String(), -1)[0][2]
	if status, _, body := mintOnce(t, api, f.pki, "leaf1"); status != http.StatusServiceUnavailable ||
		!strings.Contains(body, `"store_unavailable"`) {
		t.Errorf("a mint before any takeover judged the bundle: %s", reply(status, body))
	}
	waitBrokerMetricAt(t, metricsAt, "port49_broker_mint_gate_closed 1")
	putJudged(t, f, f.bundle(t), false) // the other runner's takeover, done
	waitFor(t, &out, "port49-broker: policy: mints open: meta/judged names bundle "+f.bundle(t))
	waitBrokerMetricAt(t, metricsAt, "port49_broker_mint_gate_closed 0")
	if status, _, body := mintOnce(t, api, f.pki, "leaf1"); status != http.StatusOK {
		t.Fatalf("a mint once meta/judged names the bundle: %s", reply(status, body))
	}
}

// meta/judged naming the bundle but in doubt is a takeover still to purge:
// the gate stays closed until one is done, here this replica's own, and
// the token minted after it is not purged.
func TestAJudgedBundleInDoubtHoldsMintsUntilATakeover(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	tacacs := startSplitDaemon(t, f.daemon, &out, 1)
	putJudged(t, f, f.bundle(t), true)
	release := holdKeyspace(t, f)
	api, _ := startBroker(t, f.broker, &out, 1)
	metricsAt := brokerLine.FindAllStringSubmatch(out.String(), -1)[0][2]
	for i := 0; i < 3; i++ { // past several of the gate's reads of meta/judged
		if status, _, body := mintOnce(t, api, f.pki, "leaf1"); status != http.StatusServiceUnavailable ||
			!strings.Contains(body, `"store_unavailable"`) {
			t.Fatalf("a mint with the bundle judged in doubt, before a takeover: %s", reply(status, body))
		}
		time.Sleep(time.Second)
	}
	waitBrokerMetricAt(t, metricsAt, "port49_broker_mint_gate_closed 1")
	release()
	waitWithin(t, &out, "is in doubt, a replica having served another since; ", 20*time.Second)
	waitFor(t, &out, "port49-broker: policy: mints open: this replica's takeover is done")
	status, tok, body := mintOnce(t, api, f.pki, "leaf1")
	if status != http.StatusOK {
		t.Fatalf("a mint after the takeover: %s", reply(status, body))
	}
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	if st := dev.login("alice", tok); st != wire.AuthenStatusPass {
		t.Fatalf("a token minted once the takeover was done: %d", st)
	}
}
