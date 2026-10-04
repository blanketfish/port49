//go:build linux

package port49d

import (
	"context"
	"net/url"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
)

// An etcd restore under a running port49d with no broker lifts nothing
// there: the marks feed's reload finds alice's mark missing, keeps it in
// force, and names it (plan 7e, Ruling 5; final review 7e-1 C-1). The
// daemon's role cannot put it back; the runner does (Task 15b). The
// controls: a lift the watch delivers lifts it, before the restore and
// after it.
//
// The restore is what a member restart from a snapshot looks like to a
// watch: the mark's key deleted and compacted past while port49d's
// streams are held, then every stream dropped, so the watch resumes below
// the compaction mark and the delete is never delivered as a lift.
func TestARestoreUnderARunningDaemonKeepsItsMarks(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	daemonCfg, proxy, srv := etcdSplitServer(t)
	root := srv.Client(t, "root")
	ctx := context.Background()
	startSplitDaemon(t, daemonCfg, &out, 1)
	key := "/port49/v1/rv/principal/" + url.PathEscape("user:alice@example.com")
	bob := "/port49/v1/rv/principal/" + url.PathEscape("user:bob@example.com")
	mark := func(who string) string {
		return `{"kind":"principal","key":"user:` + who + `@example.com","at":"2026-10-03T03:00:00Z","origin":"test: a broker"}`
	}
	if _, err := root.Put(ctx, key, mark("alice")); err != nil {
		t.Fatal(err)
	}
	waitInForce(t, &out, "principal", 1)
	if _, err := root.Delete(ctx, key); err != nil { // the control: a watched lift
		t.Fatal(err)
	}
	waitInForce(t, &out, "principal", 0)

	if _, err := root.Put(ctx, key, mark("alice")); err != nil {
		t.Fatal(err)
	}
	waitInForce(t, &out, "principal", 1)
	waitMetric(t, &out, `port49_store_feed_up{feed="marks"} 1`)
	restore(t, proxy, root, key)
	waitFor(t, &out, "store: the marks feed's revision was compacted")
	waitFor(t, &out, "port49d: store: 1 revocation(s) this port49d enforces are missing from the store as its "+
		"marks feed reloads (an etcd restore, or lifted on port49-broker while the feed was down) and stay in "+
		"force here until a lift this feed delivers or a restart: principal user:alice@example.com")
	// A mark put after the restore arrives only once the reload is done and
	// the feed follows again: then both stand.
	if _, err := root.Put(ctx, bob, mark("bob")); err != nil {
		t.Fatal(err)
	}
	waitInForce(t, &out, "principal", 2)

	// Released by a revoke and a lift made again while the feed is up.
	if _, err := root.Put(ctx, key, mark("alice")); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	waitInForce(t, &out, "principal", 1)
}

// An etcd restore that outlasts hold_ttl takes port49d dark and starts a new
// run, which reads the restored marks. The marks are the process's (Ruling
// 11), so the new run keeps alice's mark the restore lost, names it, and
// enforces it (final review 7e-1 C-1; pre-flight 7e-2 P-1).
func TestARestoreAcrossAStoreGoneKeepsTheDaemonsMarks(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	daemonCfg, proxy, srv := etcdSplitServer(t)
	root := srv.Client(t, "root")
	ctx := context.Background()
	startSplitDaemon(t, daemonCfg, &out, 1)
	key := "/port49/v1/rv/principal/" + url.PathEscape("user:alice@example.com")
	if _, err := root.Put(ctx, key, `{"kind":"principal","key":"user:alice@example.com",`+
		`"at":"2026-10-03T03:00:00Z","origin":"test: a broker"}`); err != nil {
		t.Fatal(err)
	}
	waitInForce(t, &out, "principal", 1)
	proxy.Hang(true)
	waitWithin(t, &out, "closing every listener so that devices use their local method", 60*time.Second)
	if _, err := root.Delete(ctx, key); err != nil { // the restore, while this port49d is dark
		t.Fatal(err)
	}
	proxy.Drop()
	waitCountWithin(t, &out, "port49d: listening on ", 2, 90*time.Second)
	waitFor(t, &out, "port49d: store: 1 revocation(s) this port49d enforces are missing from the store "+
		"as it starts again after a store gone")
	waitInForce(t, &out, "principal", 1)
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
