package port49d

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/store"
	etcdstore "github.com/blanketfish/port49/internal/store/etcd"
	"github.com/blanketfish/port49/internal/tacacs/wire"
)

// restoredFleet is a fleet whose etcd was restored from a snapshot taken
// before a token was redeemed, every process stopped across the restore, as
// the runbook says: the token is unspent in the store again. Nothing runs.
// The brokers and the daemon are started by the test, in the order it tests.
type restoredFleet struct {
	f        *fleet
	out, log *syncBuffer
	root     *clientv3.Client
	spent    string // redeemed after the snapshot
	recorded uint64 // the highest meta/witness the broker's state_dir held
	top      uint64 // the store's revision before the restore
}

// restoreAfterARedemption runs the fleet twice, with a snapshot between, and
// restores the snapshot. before runs against the store ahead of the snapshot.
func restoreAfterARedemption(t *testing.T, before func(f *fleet)) *restoredFleet {
	t.Helper()
	x := &restoredFleet{out: &syncBuffer{}, log: &syncBuffer{}}
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = x.out, x.log
	x.f = splitFleet(t)
	x.root = x.f.srv.Client(t, "root")
	_, stopD := runSplitDaemon(t, x.f.daemon, x.out, 1)
	api, stop := startBroker(t, x.f.broker, x.out, 1)
	waitFor(t, x.out, "runner: recorded bundle ")
	x.spent = mintOn(t, api, x.f.pki, "leaf1")
	waitUntil(t, "a witness", func() bool { return witnessAt(t, x.root) > 0 })
	if before != nil {
		before(x.f)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if err := stopD(); err != nil {
		t.Fatal(err)
	}
	snapshot := x.f.srv.Backup(t) // the token is unspent in it
	w0 := witnessAt(t, x.root)
	tacacs, stopD := runSplitDaemon(t, x.f.daemon, x.out, 2)
	_, stop = startBroker(t, x.f.broker, x.out, 2)
	waitForCount(t, x.out, "runner: took keyspace /port49/", 2)
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	if st := dev.login("alice", x.spent); st != wire.AuthenStatusPass {
		t.Fatalf("control: the token's first login: %d", st)
	}
	waitUntil(t, "the redemption's witness, recorded", func() bool { return witnessIn(t, x.f.stateDir(t)) > w0 })
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if err := stopD(); err != nil {
		t.Fatal(err)
	}
	x.recorded = witnessIn(t, x.f.stateDir(t))
	top, err := x.root.Get(context.Background(), "/port49/v1/meta/witness")
	if err != nil {
		t.Fatal(err)
	}
	x.top = uint64(top.Header.Revision)
	x.f.srv.Restore(t, snapshot)
	return x
}

// notServed fails the test if the daemon at addr logs spent in.
func (x *restoredFleet) notServed(t *testing.T, addr string) {
	t.Helper()
	dev := tacacsClient{t: t, addr: addr, key: []byte("run-test-secret")}
	if st := dev.login("alice", x.spent); st == wire.AuthenStatusPass {
		t.Fatal("a token redeemed after the snapshot logged in again after the restore")
	}
}

// A restored store is purged by whichever process looks first, so the token
// redeemed after the snapshot is never served again (decision 56; the
// pre-beta review's identity I2).
func TestARestoredTokenIsRefusedOrPurgedWhateverStartsFirst(t *testing.T) {
	t.Run("a broker first on an empty state_dir after a bumped restore", func(t *testing.T) {
		x := restoreAfterARedemption(t, nil)
		padPast(t, x.root, x.recorded) // --bump-revision: the witness will not read below the record
		if err := os.Remove(filepath.Join(x.f.stateDir(t), stateWitnessFile)); err != nil {
			t.Fatal(err)
		}
		before := len(x.out.String())
		api, _ := startBroker(t, x.f.broker, x.out, 3)
		waitWithinFrom(t, x.out, before, "every unspent token is purged", 30*time.Second)
		if !strings.Contains(x.out.String()[before:], "no witness record in broker.state_dir") {
			t.Fatalf("the purge did not say why:\n%s", x.out.String()[before:])
		}
		tacacs := startSplitDaemon(t, x.f.daemon, x.out, 3)
		x.notServed(t, tacacs)
		dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
		if st := dev.login("alice", mintOn(t, api, x.f.pki, "leaf1")); st != wire.AuthenStatusPass {
			t.Fatalf("control: a token minted after the purge: %d", st)
		}
	})
	t.Run("a broker first on an empty state_dir, and a port49d that has no restore record", func(t *testing.T) {
		x := restoreAfterARedemption(t, nil)
		padPast(t, x.root, x.recorded)
		if err := os.Remove(filepath.Join(x.f.stateDir(t), stateWitnessFile)); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(x.f.daemon)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(restoreRecordPath(cfg.Accounting.SpoolPath)); err != nil {
			t.Fatal(err)
		}
		before := len(x.out.String())
		startBroker(t, x.f.broker, x.out, 3)
		waitWithinFrom(t, x.out, before, "every unspent token is purged", 30*time.Second)
		x.notServed(t, startSplitDaemon(t, x.f.daemon, x.out, 3))
	})
	for _, empty := range []bool{false, true} {
		suffix := ""
		if empty {
			suffix = ", on an empty state_dir"
		}
		// emptied is the broker's state_dir after the runbook: kept, or a replaced pod's.
		emptied := func(t *testing.T, x *restoredFleet) {
			if !empty {
				return
			}
			if err := os.Remove(filepath.Join(x.f.stateDir(t), stateWitnessFile)); err != nil {
				t.Fatal(err)
			}
		}
		t.Run("a broker first while the new timeline climbs past the old high"+suffix, func(t *testing.T) {
			x := restoreAfterARedemption(t, nil)
			padPast(t, x.root, x.top) // writes on the restored timeline, past the revision the old one reached
			emptied(t, x)
			before := len(x.out.String())
			startBroker(t, x.f.broker, x.out, 3)
			waitWithinFrom(t, x.out, before, "every unspent token is purged", 30*time.Second)
			x.notServed(t, startSplitDaemon(t, x.f.daemon, x.out, 3))
		})
		t.Run("port49d first, then the broker"+suffix, func(t *testing.T) {
			x := restoreAfterARedemption(t, nil)
			padPast(t, x.root, x.recorded)
			emptied(t, x)
			tacacs := startSplitDaemon(t, x.f.daemon, x.out, 3)
			x.notServed(t, tacacs)
			before := len(x.out.String())
			startBroker(t, x.f.broker, x.out, 3)
			waitWithinFrom(t, x.out, before, "every unspent token is purged", 30*time.Second)
			x.notServed(t, tacacs)
		})
	}
}

// port49d restarted after the restore, on the same spool directory, still
// refuses the restored token before any broker starts: the floor's record
// survived the restart. On a spool directory with no record the gap is said,
// not claimed safe (identity I2).
func TestARestartedPort49dStillRefusesARestoredToken(t *testing.T) {
	x := restoreAfterARedemption(t, nil)
	padPast(t, x.root, x.recorded)
	tacacs, stop := runSplitDaemon(t, x.f.daemon, x.out, 3)
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	waitWithin(t, x.out, "port49d: store: the session store was restored from a snapshot: meta/witness is", 20*time.Second)
	refused := func(dev tacacsClient) {
		t.Helper()
		st := dev.login("alice", x.spent)
		for deadline := time.Now().Add(10 * time.Second); st == wire.AuthenStatusError && time.Now().Before(deadline); {
			time.Sleep(200 * time.Millisecond)
			st = dev.login("alice", x.spent)
		}
		if st != wire.AuthenStatusFail {
			t.Fatalf("the restored token, presented to port49d with no broker running: %d", st)
		}
		if r := records(t, x.log, "redeem"); r[len(r)-1]["reason"] != "token_spent" {
			t.Fatalf("the refusal: %v", r[len(r)-1])
		}
	}
	refused(dev)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	// A restart on the same config, so the same spool directory.
	tacacs, stop = runSplitDaemon(t, x.f.daemon, x.out, 4)
	defer stop()
	refused(tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")})
}

// The restore purge deletes the once-only records too: a sign-in challenge or
// proof written before the snapshot and replayed after the restore finds
// nothing (identity I5).
func TestTheRestorePurgeDeletesTheOnceRecords(t *testing.T) {
	const key = "restore-test/once"
	open := func(f *fleet) *etcdstore.Store {
		ctx := context.Background()
		bs, _ := openBrokerFor(t, ctx, f.broker, metrics.New(prometheus.NewRegistry()), io.Discard)
		return bs.raw
	}
	x := restoreAfterARedemption(t, func(f *fleet) {
		if ok, err := open(f).PutOnce(context.Background(), key, []byte("x"), time.Hour); err != nil || !ok {
			t.Fatalf("writing the once record: %v %v", ok, err)
		}
	})
	padPast(t, x.root, x.recorded)
	before := len(x.out.String())
	startBroker(t, x.f.broker, x.out, 3)
	waitWithinFrom(t, x.out, before, "once-only records (sign-in challenges, proofs, nonces) deleted", 30*time.Second)
	if _, err := open(x.f).TakeOnce(context.Background(), key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a once record written before the snapshot survived the restore purge: %v", err)
	}
}
