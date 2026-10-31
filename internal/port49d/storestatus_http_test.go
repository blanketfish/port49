package port49d

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/store"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
)

// storeStatusAt is GET /store/status at addr: the status and the body.
func storeStatusAt(t *testing.T, addr string) (int, string) {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/store/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

// statusLines is every shape a line of the answer may take, the allowlist of
// spec §12: a role, its backend, the members answering of those listed,
// reachability, the directory cache's age, the names of the feeds down, the
// count of logouts pending, and on the next line a reason of outageCause's
// fixed words. A line of any other shape fails the test: the metrics listener
// has no authentication, so nothing else may appear.
var statusLines = []*regexp.Regexp{
	regexp.MustCompile(`^(directory|session) +(etcd|memory) +(\d+|\?)/(\d+|\?) members +(reachable|unreachable)` +
		`( +cache (none|[0-9.]+m?s|[0-9hms]+)( \(snapshot\))?)?` +
		`( +feeds down: [a-z_]+(, [a-z_]+)*)?( +\d+ logouts pending)?$`),
	regexp.MustCompile(`^(directory|session) +shares the directory store$`),
	regexp.MustCompile(`^directory +memory +in process$`),
	regexp.MustCompile(`^ {11}(not opened yet|permission denied|timed out|unreachable)$`),
	regexp.MustCompile(`^stores +not opened yet$`),
}

// checkStatusAllowlist fails when a line of text is outside the allowlist, and
// when text holds anything that names a member, a credential or a person.
func checkStatusAllowlist(t *testing.T, text string) {
	t.Helper()
	for i, l := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		ok := false
		for _, re := range statusLines {
			if re.MatchString(l) {
				ok = true
			}
		}
		if !ok {
			t.Errorf("line %d of the store status is outside the allowlist: %q", i+1, l)
		}
	}
	for _, bad := range []string{"https://", "http://", ":2379", "-----BEGIN", "user:", "app:", "spiffe://", "rv/", "127.0.0.1"} {
		if strings.Contains(text, bad) {
			t.Errorf("the store status holds %q", bad)
		}
	}
}

// openStatusStore opens an etcd store through the proxy p.
func openStatusStore(t *testing.T, p *etcdtest.Proxy) *etcdstore.Store {
	t.Helper()
	s, err := etcdstore.Open(etcdstore.Config{Endpoints: []string{"http://" + p.Addr()}, Prefix: etcdtest.Prefix()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// GET /store/status on the metrics listener answers the lines the admin
// socket did, a 503 with them when a store does not answer, a 429 to a second
// request while one runs, and nothing outside the allowlist (spec §12).
func TestStoreStatusOnTheMetricsListener(t *testing.T) {
	d, sess := etcdtest.Start(t, etcdtest.Options{}), etcdtest.Start(t, etcdtest.Options{})
	dp := etcdtest.NewProxy(t, strings.TrimPrefix(d.Endpoint, "http://"))
	sp := etcdtest.NewProxy(t, strings.TrimPrefix(sess.Endpoint, "http://"))
	h := &dirHandle{}
	h.set(openStatusStore(t, dp))
	cfg := config.Config{}
	e := &config.EtcdConfig{CallTimeout: 500 * time.Millisecond}
	cfg.Stores.Directory = config.StoreConfig{Backend: config.BackendEtcd, Etcd: e}
	cfg.Stores.Session = config.StoreConfig{Backend: config.BackendEtcd, Etcd: e}
	st := newStoreStatus(cfg, h, openStatusStore(t, sp), store.NewFreshness(time.Now))
	st.pending = func() int { return 2 }
	status := &statusHandler{}
	mux := http.NewServeMux()
	mux.Handle("GET /store/status", status)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "http://")

	// Before the stores are open the answer says so.
	code, text := storeStatusAt(t, addr)
	if code != http.StatusServiceUnavailable || !strings.Contains(text, "not opened yet") {
		t.Fatalf("before the stores are open: %d %q", code, text)
	}
	checkStatusAllowlist(t, text)

	status.set(st)
	code, text = storeStatusAt(t, addr)
	if code != http.StatusOK || !strings.Contains(text, "directory  etcd    1/1 members  reachable  cache ") ||
		!strings.Contains(text, "2 logouts pending") || !strings.Contains(text, "session    etcd    1/1 members  reachable") {
		t.Fatalf("both answering: %d %q", code, text)
	}
	checkStatusAllowlist(t, text)

	// The method is GET alone.
	if resp, err := http.Post(srv.URL+"/store/status", "text/plain", nil); err != nil || resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("a POST: %v %v", resp, err)
	}

	// A store that does not answer: a 503 with the lines, every reason a fixed word.
	dp.Hang(true)
	sp.Hang(true)
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	bodies := make(chan string, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, b := storeStatusAt(t, addr)
			codes <- c
			bodies <- b
		}()
		if i == 0 {
			time.Sleep(150 * time.Millisecond) // the first is in its reads when the second asks
		}
	}
	wg.Wait()
	close(codes)
	close(bodies)
	got := map[int]int{}
	for c := range codes {
		got[c]++
	}
	if got[http.StatusServiceUnavailable] != 1 || got[http.StatusTooManyRequests] != 1 {
		t.Fatalf("two at once answered %v, want one 503 with the lines and one 429", got)
	}
	for b := range bodies {
		if strings.Contains(b, "unreachable") {
			checkStatusAllowlist(t, b)
			if strings.Count(b, "unreachable") < 2 {
				t.Errorf("a cut store is not named: %q", b)
			}
		}
	}
}

// A reason is one of outageCause's fixed words, never an error's text: a
// directory handle with no store says "not opened yet", and nothing a peer
// sent is repeated.
func TestStoreStatusReasonsAreFixedWords(t *testing.T) {
	cfg := config.Config{}
	e := &config.EtcdConfig{CallTimeout: 200 * time.Millisecond}
	cfg.Stores.Directory = config.StoreConfig{Backend: config.BackendEtcd, Etcd: e}
	cfg.Stores.Session = config.StoreConfig{Backend: config.BackendEtcd, Etcd: e}
	cfg.Stores.Shared = true
	status := &statusHandler{}
	status.set(newStoreStatus(cfg, &dirHandle{}, nil, store.NewFreshness(time.Now)))
	srv := httptest.NewServer(status)
	t.Cleanup(srv.Close)
	code, text := storeStatusAt(t, strings.TrimPrefix(srv.URL, "http://"))
	if code != http.StatusServiceUnavailable || !strings.Contains(text, "?/? members  unreachable") ||
		!strings.Contains(text, "           not opened yet") {
		t.Fatalf("%d %q", code, text)
	}
	checkStatusAllowlist(t, text)
	for _, err := range []error{store.ErrRefused, errNoDirectory, store.ErrUnavailable} {
		switch w := outageCause(err); w {
		case "not opened yet", "permission denied", "timed out", "unreachable":
		default:
			t.Errorf("outageCause(%v) = %q, outside the fixed words", err, w)
		}
	}
}
