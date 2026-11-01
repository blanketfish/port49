//go:build linux

package port49d

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/store"
	etcdstore "github.com/blanketfish/port49/internal/store/etcd"
	"github.com/blanketfish/port49/internal/store/etcd/etcdtest"
)

// With both stores hung at a call_timeout of 500ms, the status comes back on
// the metrics listener, a 503 naming both stores, well inside the handler's
// own bound: an operator in a partition gets lines, not EOF (R21).
func TestStoreStatusOnTheMetricsListenerWithBothStoresHung(t *testing.T) {
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

	sh := &statusHandler{}
	sh.set(st)
	srv := httptest.NewServer(sh)
	t.Cleanup(srv.Close)
	dp.Hang(true)
	sp.Hang(true)

	start := time.Now()
	code, text := storeStatusAt(t, strings.TrimPrefix(srv.URL, "http://"))
	if code != http.StatusServiceUnavailable || strings.Count(text, "unreachable") != 2 ||
		!strings.Contains(text, "directory ") || !strings.Contains(text, "session ") {
		t.Fatalf("%d %q after %v", code, text, time.Since(start))
	}
	if took := time.Since(start); took > 900*time.Millisecond {
		t.Fatalf("both stores hung took %v, one call_timeout of 500ms expected, the stores and their reads being at once", took)
	}
}
