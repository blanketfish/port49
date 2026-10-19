//go:build linux

package port49d

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/admin"
	"github.com/rhwendt/port49/internal/store"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
)

// With both stores hung at a call_timeout of 500ms, the status comes back over
// the socket, degraded and naming both stores, well inside the socket's own
// deadline: an operator in a partition gets lines, not EOF (R21). It asks over
// the admin socket through admin_linux_test.go's ask, so it is Linux's too.
func TestStoreStatusOverTheSocketWithBothStoresHung(t *testing.T) {
	d, sess := etcdtest.Start(t, etcdtest.Options{}), etcdtest.Start(t, etcdtest.Options{})
	dp := etcdtest.NewProxy(t, strings.TrimPrefix(d.Endpoint, "http://"))
	sp := etcdtest.NewProxy(t, strings.TrimPrefix(sess.Endpoint, "http://"))
	open := func(p *etcdtest.Proxy) *etcdstore.Store {
		s, err := etcdstore.Open(etcdstore.Config{Endpoints: []string{"http://" + p.Addr()}, Prefix: etcdtest.Prefix()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	h := &dirHandle{}
	h.set(open(dp))
	ses := open(sp)
	cfg := config.Config{}
	e := &config.EtcdConfig{CallTimeout: 500 * time.Millisecond}
	cfg.Stores.Directory = config.StoreConfig{Backend: config.BackendEtcd, Etcd: e}
	cfg.Stores.Session = config.StoreConfig{Backend: config.BackendEtcd, Etcd: e}
	st := newStoreStatus(cfg, h, ses, store.NewFreshness(time.Now))

	sock := filepath.Join(t.TempDir(), "p.sock")
	ln, err := admin.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go (&admin.Server{Now: time.Now, StoreStatus: st.answer}).Serve(ctx, ln)
	dp.Hang(true)
	sp.Hang(true)

	start := time.Now()
	r, err := ask(sock, admin.Request{Op: "store_status"})
	if err != nil || !r.Degraded || strings.Count(r.Text, "unreachable") != 2 ||
		!strings.Contains(r.Text, "directory ") || !strings.Contains(r.Text, "session ") {
		t.Fatalf("%+v %v after %v", r, err, time.Since(start))
	}
	if took := time.Since(start); took > 900*time.Millisecond {
		t.Fatalf("both stores hung took %v, one call_timeout of 500ms expected, the stores and their reads being at once", took)
	}
}
