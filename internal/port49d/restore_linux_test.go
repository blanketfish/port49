//go:build linux

package port49d

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/daemon/admin"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
)

// An etcd restore under a running port49d that loses a mark this port49d
// made does not lift it: the marks feed's reload puts
// broker.revocations_file's marks back into the store first, and says so,
// so alice's next mint is refused credential_revoked without a restart
// (final review 7e-1 C-1). The positive control: a mark lifted on purpose
// with port49 revoke --lift stays lifted across the same compaction. And a
// mark the file never held, made on another broker process, that a
// restore loses is lifted by the reload and said by its key.
//
// The restore is what a member restart from a snapshot looks like to a
// watch: the mark's key deleted and compacted past while port49d's
// streams are held, then every stream dropped, so the watch resumes below
// the compaction mark and the delete is never delivered as a lift.
func TestARestoreUnderARunningPort49dKeepsTheFilesMarks(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	cfgPath, pkiDir, revocations, proxy, srv := etcdRunServer(t)
	root := srv.Client(t, "root")
	ctx := context.Background()
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	socket := regexp.MustCompile(`(?m)^admin_socket: (\S+)$`).FindSubmatch(raw)[1]

	_, brokerAddr, _ := startRun(t, cfgPath, &out, 1)
	if status, body, err := postAsAlice(pkiDir, brokerAddr); err != nil || status != http.StatusOK {
		t.Fatalf("control: alice's mint before the revocation: %s %v", reply(status, body), err)
	}
	const principal = "user:alice@example.com"
	key := "/port49/v1/rv/principal/" + url.PathEscape(principal)
	if r, err := ask(string(socket), admin.Request{Op: "revoke", Principal: principal}); err != nil || r.Error != "" {
		t.Fatalf("revoke: %+v %v", r, err)
	}
	waitInForce(t, &out, "principal", 1)
	waitMetric(t, &out, `port49_store_feed_up{feed="marks"} 1`)

	restore(t, proxy, root, key)
	waitFor(t, &out, "store: the marks feed's revision was compacted")
	waitFor(t, &out, "port49d: broker: 1 revocation(s) in broker.revocations_file "+revocations+
		" were missing from the store (an etcd restore?) and are put back; lift any lifted on purpose with "+
		"port49 revoke --lift")
	if resp, err := root.Get(ctx, key); err != nil || len(resp.Kvs) != 1 {
		t.Fatalf("the store does not hold the mark again: %v %v", resp, err)
	}
	status, body, err := postAsAlice(pkiDir, brokerAddr)
	if err != nil || status != http.StatusUnauthorized || !strings.Contains(body, `"credential_revoked"`) {
		t.Fatalf("alice's mint after the restore: %s %v; out %s", reply(status, body), err, out.String())
	}
	waitInForce(t, &out, "principal", 1)
	if n := strings.Count(out.String(), "port49d: broker listening on "); n != 1 {
		t.Fatalf("port49d started again (%d runs): a start puts the file back whatever the feed does", n)
	}

	// The positive control: lifted on purpose, the file drops it, and the
	// same restore puts nothing back.
	if r, err := ask(string(socket), admin.Request{Op: "revoke", Principal: principal, Lift: true}); err != nil ||
		r.Error != "" {
		t.Fatalf("lift: %+v %v", r, err)
	}
	waitInForce(t, &out, "principal", 0)
	restore(t, proxy, root, key)
	waitForCount(t, &out, "store: the marks feed's revision was compacted", 2)
	waitMetric(t, &out, `port49_store_feed_rescans_total{feed="marks"} 2`)
	if status, body, err := postAsAlice(pkiDir, brokerAddr); err != nil || status != http.StatusOK {
		t.Fatalf("a lift made on purpose was put back by the restore: %s %v; out %s", reply(status, body), err,
			out.String())
	}
	if resp, err := root.Get(ctx, key); err != nil || len(resp.Kvs) != 0 {
		t.Fatalf("the store holds the lifted mark again: %v %v", resp, err)
	}
	if n := strings.Count(out.String(), "were missing from the store"); n != 1 {
		t.Fatalf("the lifted mark was said put back: %s", out.String())
	}
	waitInForce(t, &out, "principal", 0)

	// A mark made on another broker process, never in this port49d's file,
	// that a restore loses is lifted here by the reload, and said.
	bob := "/port49/v1/rv/principal/" + url.PathEscape("user:bob@example.com")
	if _, err := root.Put(ctx, bob, `{"kind":"principal","key":"user:bob@example.com",`+
		`"at":"2026-10-03T03:00:00Z","origin":"test: another broker process"}`); err != nil {
		t.Fatal(err)
	}
	waitInForce(t, &out, "principal", 1)
	restore(t, proxy, root, bob)
	waitFor(t, &out, "port49d: broker: a reload of the marks found the revocation of user:bob@example.com "+
		"lifted: lifted on a broker process while the marks feed was down, or lost by an etcd restore; revoke "+
		"it again unless it was lifted on purpose")
	waitInForce(t, &out, "principal", 0)
}

// restore is an etcd restore as a running port49d's watches see it: with
// every stream through proxy held, the mark at key is deleted (when
// there) and the store compacted past it, then every stream is dropped.
func restore(t *testing.T, proxy *etcdtest.Proxy, root *clientv3.Client, key string) {
	t.Helper()
	ctx := context.Background()
	proxy.Hang(true)
	defer proxy.Drop()
	if _, err := root.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	// Two writes, so the compaction is above the revision after the last
	// one any watch delivered, the one it resumes from.
	var resp *clientv3.PutResponse
	for range 2 {
		var err error
		if resp, err = root.Put(ctx, "/restore-test/bump", "x"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := root.Compact(ctx, resp.Header.Revision); err != nil {
		t.Fatal(err)
	}
}
