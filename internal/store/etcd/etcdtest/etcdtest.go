// Package etcdtest runs real etcd members inside a test binary
// (go.etcd.io/etcd/server/v3/embed), so the store's tests and the lab need
// no docker and no cgo (plan 7d, Ruling 2): one shared plain member per
// package (Main), a member of a test's own with TLS and client-certificate
// authentication (Start), three members for quorum (StartCluster), and a
// TCP proxy that can stop answering (NewProxy). It is imported only by
// tests and the lab; no binary links the etcd server.
package etcdtest

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.etcd.io/etcd/client/pkg/v3/transport"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"
	"go.uber.org/zap"

	"github.com/rhwendt/port49/internal/testpki"
)

var shared struct {
	endpoint string
	client   *clientv3.Client
	n        atomic.Int64
}

// Main starts the package's shared member, runs its tests, and stops it.
// A package whose tests need etcd calls it from TestMain.
func Main(m *testing.M) int {
	dir, err := os.MkdirTemp("", "port49-etcd-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "etcdtest:", err)
		return 1
	}
	defer os.RemoveAll(dir)
	e, err := member(memberSpec{name: "shared", dir: dir})
	if err != nil {
		fmt.Fprintln(os.Stderr, "etcdtest:", err)
		return 1
	}
	defer e.Close()
	shared.endpoint = "http://" + e.Clients[0].Addr().String()
	shared.client, err = clientv3.New(clientv3.Config{Endpoints: []string{shared.endpoint},
		DialTimeout: 5 * time.Second, Logger: zap.NewNop()})
	if err != nil {
		fmt.Fprintln(os.Stderr, "etcdtest:", err)
		return 1
	}
	defer shared.client.Close()
	return m.Run()
}

// Endpoint is the shared member's client URL.
func Endpoint() string { return shared.endpoint }

// Client is a client of the shared member, shared by every test in the
// binary; never close it.
func Client(testing.TB) *clientv3.Client { return shared.client }

// Prefix is a key prefix no other caller in this binary has had, so each
// store a test builds starts on an empty keyspace.
func Prefix() string { return fmt.Sprintf("/storetest/%d/", shared.n.Add(1)) }

type memberSpec struct {
	name, dir      string
	client, peer   string // URLs; "" picks a loopback port
	cluster, token string // InitialCluster; "" is this member alone
	tls            *transport.TLSInfo
	stop           <-chan struct{} // closed: give up waiting to be ready
}

// errStopped is member's error when its spec's stop closed before it was
// ready: a cluster another member of which failed to start.
var errStopped = errors.New("stopped before ready")

func member(s memberSpec) (*embed.Etcd, error) {
	cfg := embed.NewConfig()
	cfg.Name, cfg.Dir = s.name, filepath.Join(s.dir, s.name)
	cfg.ZapLoggerBuilder = embed.NewZapLoggerBuilder(zap.NewNop())
	cfg.UnsafeNoFsync = true // a test member: durability is not what is measured
	scheme := "http"
	if s.tls != nil {
		scheme = "https"
		cfg.ClientTLSInfo = *s.tls
	}
	cu, err := url.Parse(or(s.client, scheme+"://127.0.0.1:0"))
	if err != nil {
		return nil, err
	}
	pu, err := url.Parse(or(s.peer, "http://127.0.0.1:0"))
	if err != nil {
		return nil, err
	}
	cfg.ListenClientUrls, cfg.AdvertiseClientUrls = []url.URL{*cu}, []url.URL{*cu}
	cfg.ListenPeerUrls, cfg.AdvertisePeerUrls = []url.URL{*pu}, []url.URL{*pu}
	cfg.InitialCluster = or(s.cluster, s.name+"="+pu.String())
	if s.token != "" {
		cfg.InitialClusterToken = s.token
	}
	e, err := embed.StartEtcd(cfg)
	if err != nil {
		return nil, err
	}
	select {
	case <-e.Server.ReadyNotify():
		return e, nil
	case <-s.stop:
		halt(e)
		return nil, errStopped
	case <-time.After(30 * time.Second):
		e.Close()
		return nil, fmt.Errorf("member %s not ready in 30s", s.name)
	}
}

// halt stops a member of a cluster that failed to start. HardStop first:
// Close alone has a leader hand off to a peer, and waits ReqTimeout (~7s)
// when that peer is gone.
func halt(e *embed.Etcd) {
	e.Server.HardStop()
	e.Close()
}

func or(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// Options is Start's: TLS turns on https with client-certificate
// authentication under a CA of the server's own.
type Options struct{ TLS bool }

// Server is one member of a test's own.
type Server struct {
	Endpoint string
	Dir      string // the PKI: ca.pem, and the client files ClientFiles writes
	ca       *testpki.CA
	e        *embed.Etcd
}

// Start runs a member for t alone, stopped at its cleanup.
func Start(t testing.TB, o Options) *Server {
	t.Helper()
	s := &Server{Dir: t.TempDir()}
	spec := memberSpec{name: "solo", dir: t.TempDir()}
	if o.TLS {
		now := time.Now()
		ca, err := testpki.NewCA("etcdtest CA", now.Add(-time.Hour), now.Add(24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		s.ca = ca
		srv, err := ca.Issue(testpki.Leaf{CommonName: "etcd", IPs: testpki.Loopback(), NoExtKeyUsage: true,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		certPEM, keyPEM, err := testpki.PEMs(srv)
		if err != nil {
			t.Fatal(err)
		}
		for name, body := range map[string][]byte{"ca.pem": ca.PEM(), "server.pem": certPEM, "server-key.pem": keyPEM} {
			if err := os.WriteFile(filepath.Join(s.Dir, name), body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		spec.tls = &transport.TLSInfo{CertFile: filepath.Join(s.Dir, "server.pem"),
			KeyFile: filepath.Join(s.Dir, "server-key.pem"), TrustedCAFile: filepath.Join(s.Dir, "ca.pem"),
			ClientCertAuth: true}
	}
	e, err := member(spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	s.e = e
	scheme := "http://"
	if o.TLS {
		scheme = "https://"
	}
	s.Endpoint = scheme + e.Clients[0].Addr().String()
	return s
}

// ClientFiles writes a client certificate for cn, from the server's CA,
// into Dir, and returns the certificate's and the key's paths.
func (s *Server) ClientFiles(t testing.TB, cn string) (cert, key string) {
	t.Helper()
	now := time.Now()
	c, err := s.ca.Issue(testpki.Leaf{CommonName: cn, Client: true, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := testpki.PEMs(c)
	if err != nil {
		t.Fatal(err)
	}
	cert, key = filepath.Join(s.Dir, cn+".pem"), filepath.Join(s.Dir, cn+"-key.pem")
	if err := os.WriteFile(cert, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// TLS is a client TLS config presenting a certificate for cn.
func (s *Server) TLS(t testing.TB, cn string) *tls.Config {
	t.Helper()
	cert, key := s.ClientFiles(t, cn)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{RootCAs: s.ca.Pool(), Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
}

// Client is a client of s as cn (cn is ignored without TLS), closed at t's
// cleanup.
func (s *Server) Client(t testing.TB, cn string) *clientv3.Client {
	t.Helper()
	cfg := clientv3.Config{Endpoints: []string{s.Endpoint}, DialTimeout: 5 * time.Second, Logger: zap.NewNop()}
	if strings.HasPrefix(s.Endpoint, "https://") {
		cfg.TLS = s.TLS(t, cn)
	}
	c, err := clientv3.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// Cluster is three members, for what a lost quorum looks like.
type Cluster struct {
	Endpoints []string
	members   []*embed.Etcd
	once      []sync.Once
}

// clusterRetryFor is how long StartCluster tries new ports for, swapped in
// a test.
var clusterRetryFor = 30 * time.Second

// StartCluster runs three members for t, stopped at its cleanup.
//
// Its members cannot listen on :0 as every other member here does: the
// initial cluster names each peer's address before any binds, so freePort
// picks them, and another process can take one in between. A member that
// finds its address in use stops the members that started, and the cluster
// is tried again on new ports, until clusterRetryFor has passed (pre-flight
// M29; plan 7e Task 2: one retry lost the race too, under load).
func StartCluster(t testing.TB) *Cluster {
	t.Helper()
	deadline := time.Now().Add(clusterRetryFor)
	for {
		c, err := startCluster(t)
		if err == nil {
			for i := range c.members {
				t.Cleanup(func() { c.Stop(i) })
			}
			return c
		}
		if !strings.Contains(err.Error(), "address already in use") || time.Now().After(deadline) {
			t.Fatal(err)
		}
		// A pause between attempts, so a loop that keeps losing does not
		// make a temp dir and three members every few milliseconds
		// (pre-flight M5).
		time.Sleep(50 * time.Millisecond)
	}
}

func startCluster(t testing.TB) (*Cluster, error) {
	names := []string{"m0", "m1", "m2"}
	var peers, clients, initial []string
	for _, n := range names {
		peers, clients = append(peers, "http://"+freePort(t)), append(clients, "http://"+freePort(t))
		initial = append(initial, n+"="+peers[len(peers)-1])
	}
	dir := t.TempDir()
	c := &Cluster{Endpoints: clients, members: make([]*embed.Etcd, 3), once: make([]sync.Once, 3)}
	type started struct {
		i int
		e *embed.Etcd
	}
	stop, results, errs := make(chan struct{}), make(chan started, 3), make(chan error, 3)
	for i, n := range names {
		go func(i int, n string) {
			e, err := member(memberSpec{name: n, dir: dir, client: clients[i], peer: peers[i],
				cluster: strings.Join(initial, ","), token: "port49-etcdtest", stop: stop})
			if err != nil {
				errs <- err
				return
			}
			results <- started{i, e}
		}(i, n)
	}
	for left := len(names); left > 0; left-- {
		select {
		case r := <-results:
			c.members[r.i] = r.e
		case err := <-errs:
			// The first failure stops the attempt at once. A member still
			// in etcd's bootstrap cannot be cut short (it asks each peer,
			// a taken port too, for up to a second), so the others are
			// halted in the background, and t's cleanup waits for them
			// before its temp dir goes (plan 7e Task 2: a failed attempt
			// cost ~10s waiting on them, a third of the retry deadline).
			close(stop)
			done := make(chan struct{})
			go func(left int) {
				defer close(done)
				for _, e := range c.members {
					if e != nil {
						halt(e)
					}
				}
				for ; left > 0; left-- {
					select {
					case r := <-results:
						halt(r.e)
					case <-errs:
					}
				}
			}(left - 1)
			t.Cleanup(func() { <-done })
			return nil, err
		}
	}
	return c, nil
}

// Stop stops member i; stopping two of three loses the quorum.
func (c *Cluster) Stop(i int) { c.once[i].Do(func() { c.members[i].Close() }) }

// freePort is a var so a test can hand StartCluster a port already taken.
var freePort = func(t testing.TB) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// Proxy forwards TCP to a target. Hang stops it forwarding, in both
// directions, without closing anything: what a partition looks like to a
// client, requests that never come back. Delay holds each chunk that long.
type Proxy struct {
	ln     net.Listener
	target string
	mu     sync.Mutex
	cond   *sync.Cond
	hung   bool
	delay  time.Duration
	conns  map[net.Conn]bool // every connection open through the proxy, both ends
	closed bool
}

// NewProxy listens on a loopback port, forwarding to target (host:port),
// until t's cleanup.
func NewProxy(t testing.TB, target string) *Proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{ln: ln, target: target, conns: map[net.Conn]bool{}}
	p.cond = sync.NewCond(&p.mu)
	t.Cleanup(p.close)
	go p.serve()
	return p
}

// Addr is the proxy's host:port.
func (p *Proxy) Addr() string { return p.ln.Addr().String() }

// Hang stops or resumes forwarding.
func (p *Proxy) Hang(on bool) {
	p.mu.Lock()
	p.hung = on
	p.mu.Unlock()
	p.cond.Broadcast()
}

// Delay holds every chunk d before forwarding it.
func (p *Proxy) Delay(d time.Duration) {
	p.mu.Lock()
	p.delay = d
	p.mu.Unlock()
}

// close stops the proxy: the listener, and every connection through it,
// so no pipe outlives the test waiting on its target.
func (p *Proxy) close() {
	p.mu.Lock()
	p.closed, p.hung = true, false
	for c := range p.conns {
		c.Close()
	}
	p.mu.Unlock()
	p.cond.Broadcast()
	p.ln.Close()
}

// track records c as open through the proxy, or closes it and reports
// false once the proxy is closed.
func (p *Proxy) track(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		c.Close()
		return false
	}
	p.conns[c] = true
	return true
}

func (p *Proxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		if !p.track(c) {
			return
		}
		go func() {
			u, err := net.Dial("tcp", p.target)
			if err != nil {
				c.Close()
				return
			}
			if !p.track(u) {
				c.Close()
				return
			}
			go p.pipe(u, c)
			p.pipe(c, u)
		}()
	}
}

func (p *Proxy) pipe(dst, src net.Conn) {
	defer func() {
		p.mu.Lock()
		delete(p.conns, dst)
		delete(p.conns, src)
		p.mu.Unlock()
		dst.Close()
		src.Close()
	}()
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			p.mu.Lock()
			for p.hung {
				p.cond.Wait()
			}
			d := p.delay
			p.mu.Unlock()
			time.Sleep(d)
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// EnableAuth turns on etcd's authentication on s as its root user (a
// client certificate whose CN is "root"), creating each role with its
// grants and each user (a certificate CN) with its roles. It is what an
// operator does with port49d store-roles' output (plan 7d).
func (s *Server) EnableAuth(t testing.TB, grants []Grant, users map[string][]string) {
	t.Helper()
	ctx := context.Background()
	root := s.Client(t, "root")
	must := func(_ any, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(root.UserAddWithOptions(ctx, "root", "", &clientv3.UserAddOptions{NoPassword: true}))
	must(root.UserGrantRole(ctx, "root", "root"))
	roles := map[string]bool{}
	for _, g := range grants {
		if !roles[g.Role] {
			must(root.RoleAdd(ctx, g.Role))
			roles[g.Role] = true
		}
		perm := clientv3.PermRead
		if g.Write {
			perm = clientv3.PermReadWrite
		}
		must(root.RoleGrantPermission(ctx, g.Role, g.Key, g.RangeEnd, clientv3.PermissionType(perm)))
	}
	for user, rs := range users {
		must(root.UserAddWithOptions(ctx, user, "", &clientv3.UserAddOptions{NoPassword: true}))
		for _, r := range rs {
			must(root.UserGrantRole(ctx, user, r))
		}
	}
	must(root.AuthEnable(ctx))
}

// Grant is one role permission: Key to RangeEnd ("" for the one key), read,
// or read and write.
type Grant struct {
	Role, Key, RangeEnd string
	Write               bool
}
