package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/daemon/acct"
	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/author"
	"github.com/rhwendt/port49/internal/daemon/limits"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/keyring"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// syncBuffer is the record sink. The spool forwards records from its own
// goroutine, so the buffer a test reads has to be locked on both sides.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuffer) contains(sub string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Contains(s.b.Bytes(), []byte(sub))
}

// waitFor polls until cond holds or the deadline passes, so a test never
// depends on how fast the spool's drain goroutine is scheduled.
func waitFor(t *testing.T, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// client is a minimal TACACS+ client built on the wire package.
type client struct {
	conn net.Conn
	key  []byte
	sid  uint32
	seq  uint8
}

func (c *client) send(t *testing.T, typ wire.Type, body []byte, flags uint8) {
	t.Helper()
	h := wire.Header{MajorVersion: 0xc, Type: typ, SeqNo: c.seq, Flags: flags, SessionID: c.sid, Length: uint32(len(body))}
	pkt := append(h.Encode(), wire.Obfuscate(h, c.key, body)...)
	if _, err := c.conn.Write(pkt); err != nil {
		t.Fatal(err)
	}
	c.seq += 2
}

func (c *client) recv(t *testing.T) (wire.Header, []byte) {
	t.Helper()
	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	hb := make([]byte, wire.HeaderLen)
	if _, err := io.ReadFull(c.conn, hb); err != nil {
		t.Fatal(err)
	}
	h, _ := wire.DecodeHeader(hb)
	body := make([]byte, h.Length)
	if _, err := io.ReadFull(c.conn, body); err != nil {
		t.Fatal(err)
	}
	return h, wire.Obfuscate(h, c.key, body)
}

// testServer is a running daemon plus the handles needed to shut it down in
// the daemon's own order. The spool has a context of its own, exactly as
// cmd/port49d does: sharing the server's would let the final drain decide the
// spool is empty while a connection is still inside a handler, and whatever
// that connection offers next would be left on disk.
type testServer struct {
	addr      string
	metrics   *metrics.Metrics
	cancel    context.CancelFunc
	stopSpool context.CancelFunc
	served    chan struct{}
	spoolDone chan struct{}
	once      sync.Once
}

// shutdown stops accepting and closes open connections, waits for Serve to
// return, and only then stops the spool and waits for its final drain.
// Waiting before the cancel would deadlock; stopping the spool before Serve
// returns would cut the drain short.
func (ts *testServer) shutdown() {
	ts.once.Do(func() {
		ts.cancel()
		<-ts.served
		ts.stopSpool()
		<-ts.spoolDone
	})
}

func newTestServer(t *testing.T, log *syncBuffer, st store.Store) *testServer {
	t.Helper()
	inv := admission.Inventory{
		Devices:   []admission.Device{{Name: "leaf-01", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}},
		KeyGroups: []admission.KeyGroup{{CIDR: netip.MustParsePrefix("127.0.0.0/8"), KeyRef: "prod_key"}},
	}
	trie, err := admission.Build(inv)
	if err != nil {
		t.Fatal(err)
	}
	m := metrics.New(prometheus.NewRegistry())
	em := decision.NewJSONLines(log)
	lim := limits.New(limits.Config{PerNASConnections: 2, IdleTimeout: time.Second,
		MalformedBackoffBase: time.Millisecond, MalformedBackoffMax: time.Millisecond, MalformedWindow: time.Minute,
		AuthFailureDelayBase: time.Millisecond, AuthFailureDelayMax: time.Millisecond, AuthFailureWindow: time.Minute}, time.Now)
	sp, err := acct.NewSpool(16, t.TempDir()+"/acct.jsonl", em, m)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	spoolCtx, stopSpool := context.WithCancel(context.Background())
	spoolDone := make(chan struct{})
	go func() { defer close(spoolDone); sp.Run(spoolCtx) }()
	var ids atomic.Int64
	d := Deps{Admission: trie,
		Keys:   map[string]keyring.Set{"prod_key": {Ref: "prod_key", Versions: []keyring.Version{{Number: 2, Secret: []byte("k2")}, {Number: 1, Secret: []byte("k1"), Retired: true}}}},
		Authen: authen.New(st, em, lim, m, time.Now, func() string { return "ctx" + strconv.FormatInt(ids.Add(1), 10) }, 30*time.Second, time.Hour),
		Author: author.New(st, &author.Lab{SessionAttributes: []string{"priv-lvl=15"}, DenyPrefixes: []string{"reload"}}, em, m, time.Now),
		Acct:   acct.New(st, sp, m, time.Now),
		Limits: lim, Metrics: m, Log: em, Now: time.Now, IdleTimeout: time.Second}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan struct{})
	go func() { defer close(served); Serve(ctx, ln, d) }()
	ts := &testServer{addr: ln.Addr().String(), metrics: m, cancel: cancel, stopSpool: stopSpool, served: served, spoolDone: spoolDone}
	t.Cleanup(ts.shutdown)
	return ts
}

func startServer(t *testing.T, log *syncBuffer) (addr string, st *memory.Store, m *metrics.Metrics) {
	t.Helper()
	st = memory.New(time.Now)
	if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{Secret: []byte("p49_e2e"), Kind: store.KindLogin, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	ts := newTestServer(t, log, st)
	return ts.addr, st, ts.metrics
}

func dial(t *testing.T, addr string, key []byte) *client {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &client{conn: conn, key: key, sid: 0xabcd1234, seq: 1}
}

func TestPAPLoginThenAuthorizeThenAccount(t *testing.T) {
	log := &syncBuffer{}
	addr, _, _ := startServer(t, log)

	c := dial(t, addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin,
		User: []byte("alice"), Port: []byte("vty0"), RemAddr: []byte("198.51.100.4"), Data: []byte("p49_e2e")}.Encode(), 0)
	h, body := c.recv(t)
	reply, err := wire.DecodeAuthenReply(body)
	if err != nil || reply.Status != wire.AuthenStatusPass || h.SeqNo != 2 {
		t.Fatalf("%+v %v seq=%d", reply, err, h.SeqNo)
	}

	c = dial(t, addr, []byte("k2"))
	c.send(t, wire.TypeAuthor, wire.AuthorRequest{AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 15, AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin,
		User: []byte("alice"), Port: []byte("vty0"), Args: [][]byte{[]byte("service=shell"), []byte("cmd=")}}.Encode(), 0)
	_, body = c.recv(t)
	ar, _ := wire.DecodeAuthorResponse(body)
	if ar.Status != wire.AuthorStatusPassAdd || len(ar.Args) != 1 || string(ar.Args[0]) != "priv-lvl=15" {
		t.Fatalf("%+v", ar)
	}

	c = dial(t, addr, []byte("k2"))
	c.send(t, wire.TypeAcct, wire.AcctRequest{Flags: wire.AcctFlagStop, AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 15, AuthenType: wire.AuthenTypeASCII,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Args: [][]byte{[]byte("task_id=1"), []byte("service=shell"), []byte("cmd=show"), []byte("cmd-arg=version"), []byte("cmd-arg=<cr>")}}.Encode(), 0)
	_, body = c.recv(t)
	if cr, _ := wire.DecodeAcctReply(body); cr.Status != wire.AcctStatusSuccess {
		t.Fatalf("%+v", cr)
	}
	if !waitFor(t, func() bool { return log.contains(`"event":"account"`) && log.contains(`"attribution":"resolved"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	if log.contains("p49_e2e") {
		t.Fatalf("the credential must never reach the log: %s", log.String())
	}
}

func TestRetiredKeyIdentifiesButIsRefused(t *testing.T) {
	log := &syncBuffer{}
	addr, _, _ := startServer(t, log)
	c := dial(t, addr, []byte("k1"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	c.conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a retired key must get no reply")
	}
	if !log.contains(`"diagnosis":"matches_retired"`) || log.contains("p49_e2e") {
		t.Fatalf("log: %s", log.String())
	}
}

func TestUnencryptedFlagIsRefusedBeforeBody(t *testing.T) {
	log := &syncBuffer{}
	addr, _, _ := startServer(t, log)
	c := dial(t, addr, nil)
	body := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("SECRET")}.Encode()
	h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 1, Flags: wire.FlagUnencrypted, SessionID: 1, Length: uint32(len(body))}
	c.conn.Write(append(h.Encode(), body...))
	c.conn.SetReadDeadline(time.Now().Add(time.Second))
	c.conn.Read(make([]byte, 1))
	if !log.contains(`"diagnosis":"unencrypted_refused"`) || log.contains("SECRET") {
		t.Fatalf("log: %s", log.String())
	}
}

func TestNotTACACSIsCountedAndBodyNeverLogged(t *testing.T) {
	log := &syncBuffer{}
	addr, _, m := startServer(t, log)
	c := dial(t, addr, nil)
	junk := make([]byte, 40)
	binary.BigEndian.PutUint32(junk[8:12], 4) // a plausible length but version 0x00
	copy(junk[12:], "GET / HTTP/1.1\r\n")
	c.conn.Write(junk)
	c.conn.SetReadDeadline(time.Now().Add(time.Second))
	c.conn.Read(make([]byte, 1))
	if !log.contains(`"diagnosis":"not_tacacs"`) || log.contains("HTTP") {
		t.Fatalf("log: %s", log.String())
	}
	if !waitFor(t, func() bool { return testutil.ToFloat64(m.ConnectionEvents.WithLabelValues("malformed_backoff")) >= 1 }) {
		t.Fatalf("malformed_backoff metric was not incremented: %v", testutil.ToFloat64(m.ConnectionEvents.WithLabelValues("malformed_backoff")))
	}
}

func TestUnadmittedSourceIsRecordedAndClosed(t *testing.T) {
	log := &syncBuffer{}
	addr, _, _ := startServer(t, log)
	// 127.0.0.2 is loopback but not in the inventory; if this host cannot
	// source from it there is nothing to test here.
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)}}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		t.Skipf("cannot source from 127.0.0.2 on this host: %v", err)
	}
	defer conn.Close()
	c := &client{conn: conn, key: []byte("k2"), sid: 7, seq: 1}
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("an unadmitted source must get no reply")
	}
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"unadmitted_source"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	if !log.contains(`"source":"127.0.0.2"`) {
		t.Fatalf("the record must name the source: %s", log.String())
	}
}

func TestPerNASCapRefusesThirdConnection(t *testing.T) {
	log := &syncBuffer{}
	addr, _, m := startServer(t, log)
	c1, c2 := dial(t, addr, []byte("k2")), dial(t, addr, []byte("k2"))
	time.Sleep(20 * time.Millisecond)
	c3 := dial(t, addr, []byte("k2"))
	c3.conn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := c3.conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("third connection must be closed")
	}
	var ne net.Error
	if errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		t.Fatalf("third connection was not refused, the read timed out instead: %v", err)
	}
	if got := testutil.ToFloat64(m.ConnectionEvents.WithLabelValues("refused_cap")); got < 1 {
		t.Fatalf("refused_cap metric was not incremented: %v", got)
	}
	// The two admitted connections still count toward Connections{open}; once
	// they close, the gauge must fall back to 0, not stay stuck above it.
	c1.conn.Close()
	c2.conn.Close()
	if !waitFor(t, func() bool { return testutil.ToFloat64(m.Connections.WithLabelValues("open")) == 0 }) {
		t.Fatalf("open connections gauge did not return to 0 after close: %v", testutil.ToFloat64(m.Connections.WithLabelValues("open")))
	}
}

func TestSingleConnectServesTwoExchanges(t *testing.T) {
	log := &syncBuffer{}
	addr, st, _ := startServer(t, log)
	if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{Secret: []byte("p49_second"), Kind: store.KindLogin, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	c := dial(t, addr, []byte("k2"))
	for i, tok := range []string{"p49_e2e", "p49_second"} {
		c.sid = uint32(100 + i)
		c.seq = 1
		c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin,
			User: []byte("alice"), Port: []byte("vty" + strconv.Itoa(i)), Data: []byte(tok)}.Encode(), wire.FlagSingleConnect)
		_, body := c.recv(t)
		if r, _ := wire.DecodeAuthenReply(body); r.Status != wire.AuthenStatusPass {
			t.Fatalf("exchange %d: %+v", i, r)
		}
	}
}

func TestASCIILoginRunsThreeRounds(t *testing.T) {
	log := &syncBuffer{}
	addr, _, _ := startServer(t, log)
	c := dial(t, addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypeASCII,
		Service: wire.AuthenServiceLogin, Port: []byte("vty0")}.Encode(), 0)
	_, body := c.recv(t)
	if r, _ := wire.DecodeAuthenReply(body); r.Status != wire.AuthenStatusGetUser {
		t.Fatalf("round 1: %+v", r)
	}
	c.send(t, wire.TypeAuthen, wire.AuthenContinue{UserMsg: []byte("alice")}.Encode(), 0)
	_, body = c.recv(t)
	if r, _ := wire.DecodeAuthenReply(body); r.Status != wire.AuthenStatusGetPass {
		t.Fatalf("round 2: %+v", r)
	}
	c.send(t, wire.TypeAuthen, wire.AuthenContinue{UserMsg: []byte("p49_e2e")}.Encode(), 0)
	_, body = c.recv(t)
	if r, _ := wire.DecodeAuthenReply(body); r.Status != wire.AuthenStatusPass {
		t.Fatalf("round 3: %+v", r)
	}
}

func TestContinueWithoutSessionClosesTheConnection(t *testing.T) {
	log := &syncBuffer{}
	addr, _, _ := startServer(t, log)
	c := dial(t, addr, []byte("k2"))
	c.seq = 3 // a CONTINUE for a session this connection never started
	c.send(t, wire.TypeAuthen, wire.AuthenContinue{UserMsg: []byte("alice")}.Encode(), 0)
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a CONTINUE with no live session must get no reply")
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the connection must be closed, not left open: %v", err)
	}
	assertProtocolErrorRecorded(t, log)
}

// assertProtocolErrorRecorded checks what an operator has to go on after a
// key-validated connection is closed without a reply. The counter carries no
// device label, by design, so the record is the only thing that names the
// source; and the cleartext at that point may hold a credential, so the
// record must carry header fields and no body hash at all (spec §10,
// "malformed after validation").
func assertProtocolErrorRecorded(t *testing.T, log *syncBuffer) {
	t.Helper()
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"malformed_after_validation"`) }) {
		t.Fatalf("a protocol-error close must leave one record naming the source: %s", log.String())
	}
	if !log.contains(`"source":"127.0.0.1"`) {
		t.Fatalf("the record must name the source: %s", log.String())
	}
	if log.contains("body_sha256") {
		t.Fatalf("a protocol-error record must carry header fields only: %s", log.String())
	}
}

// TestSeqNoWrapGetsNoReplyAndCloses uses an authorization request, not a
// CONTINUE: a CONTINUE at seq_no 255 has no live session either, so it takes
// the unknown-session path and passes whether or not the wrap guard exists.
// An authorization request validates, dispatches, and would be answered — at
// seq_no 255 + 1, which is 0 — so only the guard produces silence here.
func TestSeqNoWrapGetsNoReplyAndCloses(t *testing.T) {
	log := &syncBuffer{}
	addr, _, m := startServer(t, log)
	c := dial(t, addr, []byte("k2"))
	c.seq = 255 // RFC 8907: seq_no 255 has no valid successor; the session must restart
	c.send(t, wire.TypeAuthor, wire.AuthorRequest{AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 15,
		AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"),
		Args: [][]byte{[]byte("service=shell"), []byte("cmd=")}}.Encode(), 0)
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a request with seq_no 255 must get no reply; the wrap guard is missing")
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the connection must be closed, not left open: %v", err)
	}
	if !waitFor(t, func() bool { return testutil.ToFloat64(m.ConnectionEvents.WithLabelValues("malformed_backoff")) >= 1 }) {
		t.Fatalf("malformed_backoff metric was not incremented for a seq_no wrap")
	}
	assertProtocolErrorRecorded(t, log)
}

// TestLiveSessionCapClosesTheConnection covers maxLiveSessions: the device
// picks session_ids, so a single-connect connection that names new ones
// forever would grow the map without bound. The cap must close the connection
// and say so in the log, not silently.
func TestLiveSessionCapClosesTheConnection(t *testing.T) {
	log := &syncBuffer{}
	addr, _, _ := startServer(t, log)
	c := dial(t, addr, []byte("k2"))

	// An ASCII START with no username is answered GETUSER and leaves the
	// session live, which is exactly what fills the map.
	start := func(sid uint32) {
		c.sid, c.seq = sid, 1
		c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypeASCII,
			Service: wire.AuthenServiceLogin, Port: []byte("vty0")}.Encode(), wire.FlagSingleConnect)
	}
	for i := 0; i < maxLiveSessions; i++ {
		start(uint32(1000 + i))
		if _, body := c.recv(t); func() bool { r, _ := wire.DecodeAuthenReply(body); return r.Status != wire.AuthenStatusGetUser }() {
			t.Fatalf("session %d should have been accepted", i)
		}
	}

	start(uint32(1000 + maxLiveSessions))
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.conn.Read(make([]byte, 1)); err == nil {
		t.Fatalf("the session past the cap must get no reply")
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the connection must be closed, not left open: %v", err)
	}
	assertProtocolErrorRecorded(t, log)
}

// gateStore parks the first GetContext until the test releases it, which puts
// a connection inside Acct.Handle at a known point: the request has been
// accepted, and the record has not yet been offered to the spool.
type gateStore struct {
	store.Store
	enter   sync.Once
	opened  sync.Once
	entered chan struct{}
	release chan struct{}
}

func (g *gateStore) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	g.enter.Do(func() { close(g.entered) })
	<-g.release
	return g.Store.GetContext(ctx, k)
}

// open lets the parked handler run on. It is idempotent so a failing test can
// defer it: leaving a connection goroutine parked would deadlock the shutdown
// that t.Cleanup runs.
func (g *gateStore) open() { g.opened.Do(func() { close(g.release) }) }

// TestSpoolOutlivesServeSoShutdownDrainsEverything pins the shutdown order the
// daemon's comments promise. A connection is held inside Acct.Handle while the
// server is cancelled; the spool must still be running when that handler
// finally offers its record, or the record is acknowledged to the device and
// left on disk — invisible on an ephemeral volume, and making "accounting
// spool drained, exiting" a false statement.
func TestSpoolOutlivesServeSoShutdownDrainsEverything(t *testing.T) {
	log := &syncBuffer{}
	gate := &gateStore{Store: memory.New(time.Now), entered: make(chan struct{}), release: make(chan struct{})}
	defer gate.open()
	ts := newTestServer(t, log, gate)

	c := dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAcct, wire.AcctRequest{Flags: wire.AcctFlagStop, AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 15,
		AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"),
		Args: [][]byte{[]byte("task_id=shutdown-race"), []byte("service=shell")}}.Encode(), 0)

	<-gate.entered
	ts.cancel()

	// The spool must not stop here. Its own context is still live, so this wait
	// is an assertion, not a sleep: if Run returns now, the record offered
	// below never reaches the sink.
	select {
	case <-ts.spoolDone:
		t.Fatal("the spool stopped draining while a connection was still inside a handler")
	case <-time.After(200 * time.Millisecond):
	}

	gate.open()
	ts.shutdown()

	if !log.contains("shutdown-race") {
		t.Fatalf("a record offered during shutdown must still be drained: %s", log.String())
	}
}

func TestIdleConnectionIsClosed(t *testing.T) {
	log := &syncBuffer{}
	addr, _, _ := startServer(t, log) // IdleTimeout is 1s
	c := dial(t, addr, []byte("k2"))
	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.conn.Read(make([]byte, 1))
	if err == nil || n != 0 {
		t.Fatalf("an idle connection must be closed by the server, read %d bytes, err %v", n, err)
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the server did not close an idle connection: %v", err)
	}
}

func TestBodyReadTimeoutIsCountedAsIdleClosed(t *testing.T) {
	log := &syncBuffer{}
	addr, _, m := startServer(t, log) // IdleTimeout is 1s
	c := dial(t, addr, []byte("k2"))
	body := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin,
		User: []byte("alice"), Data: []byte("p49_e2e")}.Encode()
	h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 1, Flags: 0, SessionID: 1, Length: uint32(len(body))}
	// Send a valid, admitted header but never send the body: the read deadline
	// set before the header read still governs the body read, so this must
	// time out the same way an idle connection does, not hang or panic.
	if _, err := c.conn.Write(h.Encode()); err != nil {
		t.Fatal(err)
	}
	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a connection whose body never arrives must be closed")
	}
	if !waitFor(t, func() bool { return testutil.ToFloat64(m.ConnectionEvents.WithLabelValues("idle_closed")) >= 1 }) {
		t.Fatalf("idle_closed metric was not incremented for a body read timeout")
	}
}
