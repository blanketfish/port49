package port49d

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/daemon/admin"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
)

// copyDaemon writes another port49d's config: f.daemon's, with its own
// admin socket, accounting spool and metrics address.
func (f *fleet) copyDaemon(t *testing.T) string {
	t.Helper()
	return copyDaemon(t, f.daemon)
}

// closedWithin reports whether c was closed, by EOF or a reset, within d.
func closedWithin(c net.Conn, d time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(d))
	_, err := c.Read(make([]byte, 1))
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return false
	}
	return err != nil
}

// stopEveryBroker stops the one broker after it has run the keyspace and
// kept its witness, then waits until its hold is gone from etcd and each
// of the daemons' guards has completed two passes since (passes, from countPasses):
// the daemons then run on with a runner that held the keyspace and is dead,
// which is the 3am case (design §6), not one that never started.
func stopEveryBroker(t *testing.T, root *clientv3.Client, out *syncBuffer, stop func() error,
	passes func(t *testing.T, daemons, n int), daemons int) {
	t.Helper()
	waitWithin(t, out, "runner: took keyspace /port49/", 20*time.Second)
	waitUntil(t, "the runner's witness", func() bool { return witnessAt(t, root) > 0 })
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "meta/hold to empty", func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		resp, err := root.Get(ctx, "/port49/v1/meta/hold", clientv3.WithPrefix(), clientv3.WithCountOnly())
		return err == nil && resp.Count == 0
	})
	passes(t, daemons, 2) // two witness periods of each daemon's guard, with the runner dead
}

// lastOf is the last of recs, nil when there is none.
func lastOf(recs []map[string]any) map[string]any {
	if len(recs) == 0 {
		return nil
	}
	return recs[len(recs)-1]
}

// mintStatus is mintOn that returns the status and the body.
func mintStatus(t *testing.T, api, pki, device string) (int, string) {
	t.Helper()
	resp := postMint(t, api, pki, device, "", testpki.LabClientCert, testpki.LabClientKey)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

// askAdminAt asks the admin socket at p req.
func askAdminAt(t *testing.T, p string, req admin.Request) admin.Response {
	t.Helper()
	return askSocket(t, p, req)
}

// A login on one port49d is answered on another at its next command, as
// a device that opens a connection per transaction sends it to whichever
// server answers (Review Focus 1).
func TestALoginOnOneDaemonIsAnsweredOnAnother(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	f.judged(t)
	a := startSplitDaemon(t, f.daemon, &out, 1)
	b := startSplitDaemon(t, f.copyDaemon(t), &out, 2)
	api, _ := startBroker(t, f.broker, &out, 1)
	devA := tacacsClient{t: t, addr: a, key: []byte("run-test-secret")}
	devB := tacacsClient{t: t, addr: b, key: []byte("run-test-secret")}
	loginSession(t, devA, mintOn(t, api, f.pki, "leaf1"), &log)
	if !devB.permits("alice", "configure") {
		t.Fatalf("the other daemon did not answer the session's next command: %v", lastCommand(t, &log))
	}
}

// A revocation on one port49-broker closes the agent's held connection to
// the other, and both daemons deny the session's next command
// credential_revoked (Review Focus 3).
func TestARevocationOnOneBrokerReachesTheOther(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	f.judged(t)
	tacacs := startSplitDaemon(t, f.daemon, &out, 1)
	apiA, _ := startBroker(t, f.broker, &out, 1)
	cfgB := f.copyBroker(t) // its own API address and admin socket
	startBroker(t, cfgB, &out, 2)
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	loginSession(t, dev, mintOn(t, apiA, f.pki, "leaf1"), &log)
	principal := lastCommandPrincipal(t, &log)
	held := heldBrokerConn(t, f.pki, apiA) // alice's connection to A, one request answered, kept open
	resp := askAdminAt(t, adminSocketOf(t, cfgB), admin.Request{Op: "revoke", Principal: principal})
	if resp.Error != "" {
		t.Fatalf("the revocation on B: %+v", resp)
	}
	if !closedWithin(held, 5*time.Second) {
		t.Fatal("A kept alice's held connection after B revoked her")
	}
	if dev.permits("alice", "configure") {
		t.Fatal("the daemon permitted the session's next command after the revocation")
	}
	if r := lastCommand(t, &log); r["reason"] != "credential_revoked" {
		t.Fatalf("the denial: %v", r)
	}
	// Never the body: a mint that should have been refused answers with a token.
	if code, body := mintStatus(t, apiA, f.pki, "leaf1"); code != http.StatusUnauthorized ||
		!strings.Contains(body, "credential_revoked") {
		t.Fatalf("a mint on A after B's revocation: status %d, names credential_revoked: %v", code,
			strings.Contains(body, "credential_revoked"))
	}
}

// A context put back while a daemon was stopped, and another daemon ran,
// is denied by the stopped one when it starts: the runner's ledger record
// holds the later mark (Review Focus 2; Ruling 4). The put-back is bob's
// context over alice's at the username both log in as (pre-flight I14).
// bob is a second identity of alice's subject (sharedUsernamePolicy, as
// built in Task 10; spec §2), not a second subject, so the put-back is
// another principal at the same key: impersonation, so a denial cannot
// come from an unrelated fault. The controls: a daemon started with
// nothing put back permits alice's session, and the running daemon
// permits it before the put-back.
func TestAPutBackBeforeADaemonStartsIsDenied(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleetWith(t, sharedUsernamePolicy, []string{"bob@example.com"})
	root := f.srv.Client(t, "root")
	ctx := context.Background()
	a := startSplitDaemon(t, f.daemon, &out, 1)
	api, _ := startBroker(t, f.broker, &out, 1)
	devA := tacacsClient{t: t, addr: a, key: []byte("run-test-secret")}
	loginSession(t, devA, mintOnAs(t, api, f.pki, "leaf1", "bob@example.com"), &log)
	resp, err := root.Get(ctx, "/port49/v1/c/leaf1/alice")
	if err != nil || len(resp.Kvs) != 1 {
		t.Fatalf("bob's context: %v %v", resp, err)
	}
	bobs := resp.Kvs[0]
	s1 := waitForLedgerSeq(t, root, "/port49/v1/lw/leaf1/alice", 0)
	loginSession(t, devA, mintOn(t, api, f.pki, "leaf1"), &log) // alice's, later, at the key
	waitForLedgerSeq(t, root, "/port49/v1/lw/leaf1/alice", s1)  // the runner's record holds it
	if !devA.permits("alice", "configure") || lastCommandPrincipal(t, &log) != "user:alice@example.com" {
		t.Fatal("control: alice's session on the running daemon")
	}
	c := startSplitDaemon(t, f.copyDaemon(t), &out, 2) // started with nothing put back
	devC := tacacsClient{t: t, addr: c, key: []byte("run-test-secret")}
	if !devC.permits("alice", "configure") {
		t.Fatal("control: a daemon started with nothing put back denied alice's session")
	}
	if _, err := root.Put(ctx, string(bobs.Key), string(bobs.Value)); err != nil {
		t.Fatal(err)
	}
	b := startSplitDaemon(t, f.copyDaemon(t), &out, 3) // started after the put-back
	devB := tacacsClient{t: t, addr: b, key: []byte("run-test-secret")}
	if devB.permits("alice", "configure") {
		t.Fatalf("a daemon started after a put-back took bob's context as alice's key's: %v",
			lastCommandPrincipal(t, &log))
	}
	if devA.permits("alice", "configure") {
		t.Fatal("the running daemon took the put-back once its feed had passed it")
	}
}

// With every port49-broker stopped and no broker host to run the offline
// revocation on, a mark written as etcd's root reaches every port49d
// through its marks feed, and the session's next command is denied
// credential_revoked (Ruling 13's break-glass; pre-flight I4). A token
// already minted is refused at its login, credential_revoked: the brief
// said it would log in and be denied command by command, and the code,
// the safer of the two, does not let it in.
func TestARootWrittenMarkDeniesWithEveryBrokerStopped(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	passes := countPasses(t)
	root := f.srv.Client(t, "root")
	a := startSplitDaemon(t, f.daemon, &out, 1)
	b := startSplitDaemon(t, f.copyDaemon(t), &out, 2)
	api, stop := startBroker(t, f.broker, &out, 1)
	devA := tacacsClient{t: t, addr: a, key: []byte("run-test-secret")}
	devB := tacacsClient{t: t, addr: b, key: []byte("run-test-secret")}
	loginSession(t, devA, mintOn(t, api, f.pki, "leaf1"), &log)
	// After the takeover, whose purge takes every token minted before it.
	waitWithin(t, &out, "runner: took keyspace /port49/", 20*time.Second)
	spare := mintOn(t, api, f.pki, "leaf1")
	stopEveryBroker(t, root, &out, stop, passes, 2)
	if !devA.permits("alice", "configure") || !devB.permits("alice", "configure") {
		t.Fatal("control: the session runs on, on either daemon, with every broker stopped")
	}
	mark := fmt.Sprintf(`{"kind":"principal","key":"user:alice@example.com","at":%q,"origin":"etcdctl"}`,
		time.Now().UTC().Format(time.RFC3339))
	if _, err := root.Put(context.Background(), "/port49/v1/rv/principal/user:alice@example.com", mark); err != nil {
		t.Fatal(err)
	}
	for name, dev := range map[string]tacacsClient{"a": devA, "b": devB} {
		waitUntil(t, name+" to deny alice configure", func() bool { return !dev.permits("alice", "configure") })
		if r := lastCommand(t, &log); r["reason"] != "credential_revoked" {
			t.Fatalf("daemon %s's denial: %v", name, r)
		}
	}
	// A token minted before the mark is refused at its login, not let in to
	// be denied command by command.
	if st := devA.login("alice", spare); st == wire.AuthenStatusPass {
		t.Fatal("a token minted before the mark logged in after it")
	}
	if r := lastOf(records(t, &log, "redeem")); r == nil || r["reason"] != "credential_revoked" {
		t.Fatalf("the spare token's redemption: %v", r)
	}
}

// With every port49-broker stopped, an open session's next command is
// answered and a token minted before the stop logs in (design §6: the
// daemon never calls the broker).
func TestWithEveryBrokerStoppedOpenSessionsRunOn(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	passes := countPasses(t)
	root := f.srv.Client(t, "root")
	a := startSplitDaemon(t, f.daemon, &out, 1)
	api, stop := startBroker(t, f.broker, &out, 1)
	dev := tacacsClient{t: t, addr: a, key: []byte("run-test-secret")}
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
	// After the takeover, whose purge takes every token minted before it.
	waitWithin(t, &out, "runner: took keyspace /port49/", 20*time.Second)
	spare := mintOn(t, api, f.pki, "leaf1")
	stopEveryBroker(t, root, &out, stop, passes, 1)
	if !dev.permits("alice", "configure") {
		t.Fatalf("an open session's command with every broker stopped: %v", lastCommand(t, &log))
	}
	if st := dev.login("alice", spare); st != wire.AuthenStatusPass {
		t.Fatalf("a token minted before every broker stopped: %d; the last redeem: %v", st, lastOf(records(t, &log, "redeem")))
	}
}
