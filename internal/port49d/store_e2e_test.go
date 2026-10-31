package port49d

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/store/etcd"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
)

// rolesMember is a TLS etcd member with port49's roles in force, and a
// proxy to it the test can hang.
func rolesMember(t *testing.T) (*etcdtest.Server, *etcdtest.Proxy) {
	t.Helper()
	return rolesMemberOpts(t, etcdtest.Options{TLS: true})
}

// rolesMemberOpts is rolesMember on a member started with o.
func rolesMemberOpts(t *testing.T, o etcdtest.Options) (*etcdtest.Server, *etcdtest.Proxy) {
	t.Helper()
	srv := etcdtest.Start(t, o)
	var grants []etcdtest.Grant
	for _, g := range etcd.Roles("/port49/") {
		grants = append(grants, etcdtest.Grant{Role: g.Role, Key: g.Key, RangeEnd: g.RangeEnd, Write: g.Write})
	}
	srv.EnableAuth(t, grants, map[string][]string{"port49-daemon": {etcd.RoleDaemon}, "port49-broker": {etcd.RoleBroker}})
	return srv, etcdtest.NewProxy(t, strings.TrimPrefix(srv.Endpoint, "https://"))
}

// etcdSplit is a split daemon's port49d.yaml (plan 7e) on a TLS etcd
// member with the roles, through a proxy the test can hang: the
// run_test.go config with policy: in place of broker:, the daemon's
// identity alone.
func etcdSplit(t *testing.T) (daemonCfg string, proxy *etcdtest.Proxy) {
	t.Helper()
	daemonCfg, proxy, _ = etcdSplitServer(t)
	return daemonCfg, proxy
}

// etcdSplitServer is etcdSplit with the member, for a test that writes the
// store as its root.
func etcdSplitServer(t *testing.T) (daemonCfg string, proxy *etcdtest.Proxy, srv *etcdtest.Server) {
	t.Helper()
	return etcdSplitServerWith(t, minimalPolicy, nil)
}

// etcdSplitServerWith is etcdSplitServer on policyBody, with a lab client
// certificate for each of others (brokerConfigWith), for the broker Task
// 15 starts beside it.
func etcdSplitServerWith(t *testing.T, policyBody string, others []string) (daemonCfg string,
	proxy *etcdtest.Proxy, srv *etcdtest.Server) {
	t.Helper()
	return etcdSplitServerOpts(t, policyBody, others, etcdtest.Options{TLS: true})
}

// etcdSplitServerOpts is etcdSplitServerWith on a member started with o.
func etcdSplitServerOpts(t *testing.T, policyBody string, others []string, o etcdtest.Options) (daemonCfg string,
	proxy *etcdtest.Proxy, srv *etcdtest.Server) {
	t.Helper()
	srv, proxy = rolesMemberOpts(t, o)
	dc, dk := srv.ClientFiles(t, "port49-daemon")
	b := brokerConfigWith(t, policyBody, others).Broker
	daemonCfg = writeRunConfig(t, b)
	raw, err := os.ReadFile(daemonCfg)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	body = body[:strings.Index(body, "broker:\n")] + fmt.Sprintf("policy: {file: %s, watch_interval: 1s}\n"+
		"stores:\n  directory:\n    backend: etcd\n    packet_deadline: 1s\n    etcd:\n"+
		"      endpoints: [https://%s]\n      ca_file: %s\n      daemon: {cert_file: %s, key_file: %s}\n"+
		"      call_timeout: 200ms\n      hold_ttl: 10s\n      breaker: {failures: 3, open_for: 2s}\n"+
		"limits: {idle_timeout: 2m}\n", b.PolicyFile, proxy.Addr(),
		filepath.Join(srv.Dir, "ca.pem"), dc, dk)
	if err := os.WriteFile(daemonCfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return daemonCfg, proxy, srv
}

// waitCountWithin is waitForCount with a deadline of the test's choosing.
func waitCountWithin(t *testing.T, buf *syncBuffer, want string, n int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for strings.Count(buf.String(), want) < n {
		if time.Now().After(deadline) {
			t.Fatalf("waited %v for %q ×%d; have %q", d, want, n, buf.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// lastCommandPrincipal is the principal of the decision log's last
// authorize_command or redeem record: the one the session's records name.
func lastCommandPrincipal(t *testing.T, log *syncBuffer) string {
	t.Helper()
	recs := append(records(t, log, "redeem"), records(t, log, "authorize_command")...)
	for i := len(recs) - 1; i >= 0; i-- {
		if p, _ := recs[i]["principal"].(string); p != "" {
			return p
		}
	}
	t.Fatalf("no record names a principal; decision log %s", log.String())
	return ""
}

// loginSession logs alice in with tok and authorizes her exec session, as
// a device does before her first command: the session's level is raised
// to the context's ceiling there, not at the login.
func loginSession(t *testing.T, dev tacacsClient, tok string, log *syncBuffer) {
	t.Helper()
	if st := dev.login("alice", tok); st != wire.AuthenStatusPass {
		t.Fatalf("login: %d; log %s", st, log.String())
	}
	if r := dev.authorize("alice"); r.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("session authorization: %+v", r)
	}
}

// heldBrokerConn opens a connection to the broker as the lab client and
// asks /v1/config on it, leaving it open: an agent's held connection.
func heldBrokerConn(t *testing.T, pkiDir, addr string) *tls.Conn {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(filepath.Join(pkiDir, testpki.LabClientCert), filepath.Join(pkiDir, testpki.LabClientKey))
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(filepath.Join(pkiDir, testpki.LabCA))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	c, err := tls.Dial("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: roots,
		MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if _, err := io.WriteString(c, "GET /v1/config HTTP/1.1\r\nHost: broker\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("/v1/config on a held connection: %v %v", resp, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return c
}

// waitInForce waits up to 10s for the newest run's
// port49_revocations_in_force{by} to read n.
func waitInForce(t *testing.T, out *syncBuffer, by string, n int) {
	t.Helper()
	waitMetric(t, out, fmt.Sprintf(`port49_revocations_in_force{by="%s"} %d`, by, n))
}

// waitMetric waits up to 10s for the newest run's /metrics to hold line.
func waitMetric(t *testing.T, out *syncBuffer, line string) {
	t.Helper()
	ms := regexp.MustCompile(`port49d: metrics on (127\.0\.0\.1:\d+)`).FindAllStringSubmatch(out.String(), -1)
	if len(ms) == 0 {
		t.Fatalf("the metrics address is not said: %s", out.String())
	}
	want := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(line) + `$`)
	deadline := time.Now().Add(10 * time.Second)
	for {
		scraped, err := http.Get("http://" + ms[len(ms)-1][1] + "/metrics")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(scraped.Body)
		scraped.Body.Close()
		if want.Match(body) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("/metrics lacks %q:\n%s", line, body)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// waitForLedgerSeq polls the ledger record at key, as etcd's root, until
// its seq is above above or 10s pass, and returns it. The keeper writes
// within a second of a raise; a gauge read at 0 can be the round before
// (pre-flight I14).
func waitForLedgerSeq(t *testing.T, root *clientv3.Client, key string, above uint64) uint64 {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := root.Get(context.Background(), key); err == nil && len(resp.Kvs) == 1 {
			var r struct {
				Seq uint64 `json:"seq"`
			}
			if json.Unmarshal(resp.Kvs[0].Value, &r) == nil && r.Seq > above {
				return r.Seq
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the ledger record at %s never rose above %d", key, above)
	return 0
}

// addUnderEtcd inserts lines (each indented four spaces, newline-ended; the
// stores: nesting indents them two more) under the last etcd: block in the
// config at cfgPath: in a two-store file, the session store's.
func addUnderEtcd(t *testing.T, cfgPath, lines string) {
	t.Helper()
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	const etcdLine = "    etcd:\n"
	i := strings.LastIndex(string(raw), etcdLine)
	if i < 0 {
		t.Fatalf("%s has no etcd block under stores:", cfgPath)
	}
	var deeper strings.Builder
	for _, l := range strings.SplitAfter(lines, "\n") {
		if l != "" {
			deeper.WriteString("  " + l)
		}
	}
	at := i + len(etcdLine)
	body := string(raw)[:at] + deeper.String() + string(raw)[at:]
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
