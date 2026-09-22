package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	stdlog "log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
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
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/token"
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

// records decodes every record written so far, one map per line. A test that
// has to join two records — a redeem to the authorization that found its
// context — needs the fields rather than a substring.
func (s *syncBuffer) records(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(s.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("record %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
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

// newTestServer starts a daemon against st. authz may be nil, which uses the
// lab authorizer every other test wants; a test passes its own only to reach
// a path the lab authorizer cannot produce.
func newTestServer(t *testing.T, log *syncBuffer, st store.Store, authz author.Authorizer) *testServer {
	t.Helper()
	if authz == nil {
		authz = &author.Lab{SessionAttributes: []string{"priv-lvl=15"}, DenyPrefixes: []string{"reload"}}
	}
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
		Keys: map[string]keyring.Set{"prod_key": {Ref: "prod_key", Versions: []keyring.Version{{Number: 2, Secret: []byte("k2")}, {Number: 1, Secret: []byte("k1"), Retired: true}}}},
		// The e2e credentials here are not token-shaped, so the tag check never
		// fires; the key only has to be non-nil and stable.
		Authen: authen.New(st, em, lim, m, time.Now, func() string { return "ctx" + strconv.FormatInt(ids.Add(1), 10) },
			15*time.Minute, 2*time.Hour, time.Hour, time.Hour,
			token.NewTagWindow(token.TagKey([]byte("server_test")))),
		Author: author.New(st, authz, em, m, time.Now, platform.Defaults(), time.Hour, 10*time.Minute, time.Hour),
		Acct:   acct.New(st, sp, m, time.Now, platform.SystemUsers()),
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
		store.Token{ID: "e2e", Secret: []byte("p49_e2e"), Kind: store.KindLogin, Principal: "user:alice@example.com", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	ts := newTestServer(t, log, st, nil)
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

	// priv_lvl=1 on the session authorization, matching the login START above
	// and what every device in the lab was measured sending: EOS asks
	// `priv_lvl=1 args=[service=shell cmd*]` and only raises to 15 once this
	// reply has granted `priv-lvl=15` (tests/lab/results/L1-arista_eos.md,
	// L3-arista_eos.md). It used to say 15 here, which the §5.3 privilege check
	// denies: the context holds the login START's 1 until this reply grants 15
	// and the handler records it. See TestTheDevicePrivLvlRaisedByOurOwnSessionReply
	// in internal/daemon/author for the whole sequence.
	c = dial(t, addr, []byte("k2"))
	c.send(t, wire.TypeAuthor, wire.AuthorRequest{AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 1, AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin,
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

// TestTwoUsersAuthenticateAtOnePortAndAuthorizeAtAnother drives the round trip
// the ruled key exists for, end to end through this package rather than
// against a pre-seeded context: vEOS reports port=ssh while it authenticates a
// login and port=vty<n> when it authorizes the shell that login opened
// (tests/lab/results/L1-arista_eos.md), and under the old (nas, port) key the
// authorization missed and the device killed the session. Two operators do it
// at once, because the other half of the ruling is that neither login may
// displace the other's context.
func TestTwoUsersAuthenticateAtOnePortAndAuthorizeAtAnother(t *testing.T) {
	log := &syncBuffer{}
	st := memory.New(time.Now)
	users := []struct{ name, secret, authenPort, authorPort string }{
		{"alice", "p49_alice_tok", "ssh", "vty4"},
		{"bob", "p49_bob_tok", "ssh", "vty5"},
	}
	for _, u := range users {
		if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: u.name},
			store.Token{ID: "t_" + u.name, Secret: []byte(u.secret), Kind: store.KindLogin, Principal: "user:" + u.name + "@example.com", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	ts := newTestServer(t, log, st, nil)

	// Both logins are in flight before either reply is read, so two sessions
	// are live on the daemon at the same time. The per-NAS connection cap is
	// 2, which is exactly what that costs.
	conns := make([]*client, len(users))
	for i, u := range users {
		conns[i] = dial(t, ts.addr, []byte("k2"))
		conns[i].send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1,
			AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte(u.name),
			Port: []byte(u.authenPort), RemAddr: []byte("172.100.100.1"), Data: []byte(u.secret)}.Encode(), 0)
	}
	for i, u := range users {
		_, body := conns[i].recv(t)
		reply, err := wire.DecodeAuthenReply(body)
		if err != nil || reply.Status != wire.AuthenStatusPass {
			t.Fatalf("%s: %+v %v", u.name, reply, err)
		}
		conns[i].conn.Close()
	}

	// The daemon closes a connection once its exchange is done; waiting for
	// the gauge keeps the authorizations from being refused on the cap.
	if !waitFor(t, func() bool { return testutil.ToFloat64(ts.metrics.Connections.WithLabelValues("open")) == 0 }) {
		t.Fatalf("open connections gauge: %v", testutil.ToFloat64(ts.metrics.Connections.WithLabelValues("open")))
	}

	// Each shell now authorizes from a different port than its login reported,
	// and from a port the other operator does not share.
	for i, u := range users {
		conns[i] = dial(t, ts.addr, []byte("k2"))
		conns[i].send(t, wire.TypeAuthor, wire.AuthorRequest{AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 1,
			AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin, User: []byte(u.name),
			Port: []byte(u.authorPort), RemAddr: []byte("172.100.100.1"),
			Args: [][]byte{[]byte("service=shell"), []byte("cmd=")}}.Encode(), 0)
	}
	for i, u := range users {
		_, body := conns[i].recv(t)
		ar, err := wire.DecodeAuthorResponse(body)
		if err != nil || ar.Status != wire.AuthorStatusPassAdd {
			t.Fatalf("%s authorized at %s: %+v %v", u.name, u.authorPort, ar, err)
		}
	}

	// Join each authorization to its own login through ctx_id. Asserting the
	// reason alone would pass if both users shared one context.
	redeemed := map[string]string{}   // username -> ctx_id written at authentication
	authorized := map[string]string{} // username -> ctx_id the authorization found
	for _, r := range log.records(t) {
		s, ok := r["session"].(map[string]any)
		if !ok {
			continue
		}
		user, _ := s["username"].(string)
		ctxID, _ := s["ctx_id"].(string)
		switch r["event"] {
		case "redeem":
			if r["reason"] != "token_redeemed" {
				t.Fatalf("%s: %v", user, r)
			}
			if s["replaced_ctx_id"] != nil {
				t.Fatalf("%s displaced a context that belonged to someone else: %v", user, s)
			}
			if s["port"] != "ssh" {
				t.Fatalf("%s authenticated at %v, not ssh: %v", user, s["port"], s)
			}
			redeemed[user] = ctxID
		case "authorize_session":
			if r["reason"] != "context_matched" {
				t.Fatalf("%s authorizing at %v: %v", user, s["port"], r)
			}
			authorized[user] = ctxID
		}
	}
	for _, u := range users {
		if redeemed[u.name] == "" || authorized[u.name] != redeemed[u.name] {
			t.Fatalf("%s authorized against ctx_id %q, its login wrote %q: %s",
				u.name, authorized[u.name], redeemed[u.name], log.String())
		}
	}
	if redeemed["alice"] == redeemed["bob"] {
		t.Fatalf("two operators on one device shared one context: %s", log.String())
	}
	for _, u := range users {
		if log.contains(u.secret) {
			t.Fatalf("the credential must never reach the log: %s", log.String())
		}
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
	// "the credential is not in the log" cannot tell "the body was never read"
	// from "the body was read and hashed". body_sha256 is the difference: the
	// refusal happens on the header alone, so there is nothing to hash.
	if log.contains("body_sha256") {
		t.Fatalf("an unencrypted packet must be refused before its body is read: %s", log.String())
	}
}

func TestNoKnownKeyIsRecordedAndRefused(t *testing.T) {
	log := &syncBuffer{}
	addr, _, m := startServer(t, log)
	// Neither the current key (k2) nor the retired one (k1): the body decodes
	// to noise under every version the keyring holds.
	c := dial(t, addr, []byte("a-key-this-daemon-has-never-held"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	c.conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a packet no key validates must get no reply")
	}
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"no_known_key_matches"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	// This is the rotation report's whole point: the record names the source
	// and the key_ref it was expected under, and never the body.
	if !log.contains(`"source":"127.0.0.1"`) || !log.contains(`"key_ref":"prod_key"`) {
		t.Fatalf("the record must name the source and the key_ref: %s", log.String())
	}
	if log.contains("p49_e2e") {
		t.Fatalf("the credential must never reach the log: %s", log.String())
	}
	if got := testutil.ToFloat64(m.Unvalidated.WithLabelValues("no_known_key_matches")); got < 1 {
		t.Fatalf("unvalidated_packets_total{no_known_key_matches} was not incremented: %v", got)
	}
}

// TestKeyChangeMidConnectionIsMalformedAfterValidation covers the rule that
// the first packet decides a connection's key version and every later packet
// is held to it: a device cannot walk the keyring packet by packet. The second
// packet here is obfuscated with a different key, so it de-obfuscates to noise
// under the pinned version and is refused -- with a body hash, because these
// are wire bytes, unlike the protocol-error closes.
func TestKeyChangeMidConnectionIsMalformedAfterValidation(t *testing.T) {
	log := &syncBuffer{}
	addr, _, m := startServer(t, log)
	c := dial(t, addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypeASCII,
		Service: wire.AuthenServiceLogin, Port: []byte("vty0")}.Encode(), wire.FlagSingleConnect)
	if _, body := c.recv(t); func() bool { r, _ := wire.DecodeAuthenReply(body); return r.Status != wire.AuthenStatusGetUser }() {
		t.Fatal("the first packet should have been accepted under k2")
	}

	c.key = []byte("k2-but-rotated-underneath-us")
	c.send(t, wire.TypeAuthen, wire.AuthenContinue{UserMsg: []byte("alice")}.Encode(), 0)
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a packet under a different key must get no reply")
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the connection must be closed, not left open: %v", err)
	}
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"malformed_after_validation"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	if !log.contains(`"body_sha256"`) {
		t.Fatalf("a body that arrived on the wire must be hashed in the record: %s", log.String())
	}
	if !log.contains(`"version":2`) {
		t.Fatalf("the record must name the version the connection was pinned to: %s", log.String())
	}
	if got := testutil.ToFloat64(m.Unvalidated.WithLabelValues("malformed_after_validation")); got < 1 {
		t.Fatalf("unvalidated_packets_total{malformed_after_validation} was not incremented: %v", got)
	}
}

// brokenStore fails one store call, so a test can drive the store_unavailable
// path end to end: a daemon that cannot reach its store must answer ERROR,
// never a PASS or a FAIL it cannot back up.
type brokenStore struct {
	store.Store
	err error
}

func (b *brokenStore) Candidates(context.Context, store.TokenKey) ([]store.Token, error) {
	return nil, b.err
}

func TestStoreErrorAnswersErrorEndToEnd(t *testing.T) {
	log := &syncBuffer{}
	st := &brokenStore{Store: memory.New(time.Now), err: errors.New("store: connection refused")}
	ts := newTestServer(t, log, st, nil)

	c := dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin,
		User: []byte("alice"), Port: []byte("vty0"), Data: []byte("p49_e2e")}.Encode(), 0)
	_, body := c.recv(t)
	reply, err := wire.DecodeAuthenReply(body)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Status != wire.AuthenStatusError {
		t.Fatalf("an unreachable store must answer ERROR, not %v", reply.Status)
	}
	if !waitFor(t, func() bool { return log.contains(`"reason":"store_unavailable"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	if got := testutil.ToFloat64(ts.metrics.Requests.WithLabelValues("authen", "error")); got < 1 {
		t.Fatalf("requests_total{authen,error} was not incremented: %v", got)
	}
	if got := testutil.ToFloat64(ts.metrics.StoreOps.WithLabelValues("candidates", "error")); got < 1 {
		t.Fatalf("store_operations_total{candidates,error} was not incremented: %v", got)
	}
	if log.contains("p49_e2e") {
		t.Fatalf("the credential must never reach the log: %s", log.String())
	}
}

// panicAuthorizer is the only way to reach the per-connection recover from
// outside the package: nothing in the daemon's own code is meant to panic.
type panicAuthorizer struct{}

func (panicAuthorizer) Session(context.Context, store.Context, []string) author.Decision {
	panic("port49 test: deliberate panic inside an authorizer")
}

func (panicAuthorizer) Command(context.Context, store.Context, []string, []string) author.Decision {
	panic("port49 test: deliberate panic inside an authorizer")
}

// TestPanicInOneConnectionDoesNotStopTheDaemon pins what the recover in Serve
// is for: one device's packet must never take service away from every other
// admitted device. The panicking connection closes, the event is counted, and
// the next connection is served normally.
func TestPanicInOneConnectionDoesNotStopTheDaemon(t *testing.T) {
	// Written from the panicking connection's goroutine, read from this one.
	panicLog := &syncBuffer{}
	stdlog.SetOutput(panicLog)
	t.Cleanup(func() { stdlog.SetOutput(os.Stderr) })

	log := &syncBuffer{}
	st := memory.New(time.Now)
	if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "e2e", Secret: []byte("p49_e2e"), Kind: store.KindLogin, Principal: "user:alice@example.com", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	ts := newTestServer(t, log, st, panicAuthorizer{})

	// A login first: authorization only reaches the authorizer once there is a
	// context for the line.
	c := dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin,
		User: []byte("alice"), Port: []byte("vty0"), Data: []byte("p49_e2e")}.Encode(), 0)
	if _, body := c.recv(t); func() bool { r, _ := wire.DecodeAuthenReply(body); return r.Status != wire.AuthenStatusPass }() {
		t.Fatal("the login should have passed")
	}
	c.conn.Close() // release the per-source connection slot before the next dial

	// Both levels are 1, as the lab measured them, so the request reaches the
	// authorizer at all: a §5.3 privilege denial would answer before it and the
	// panic under test would never be provoked.
	c = dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthor, wire.AuthorRequest{AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 1, AuthenType: wire.AuthenTypeASCII,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"),
		Args: [][]byte{[]byte("service=shell"), []byte("cmd=")}}.Encode(), 0)
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a panicking connection must be closed, not answered")
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the connection must be closed, not left open: %v", err)
	}
	if !waitFor(t, func() bool { return testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("panic")) >= 1 }) {
		t.Fatal("connection_events_total{panic} was not incremented")
	}
	c.conn.Close()

	// A panic counter without a stack says something broke and nothing about
	// where. The stack is port49's own frames -- no packet bytes.
	if !panicLog.contains("goroutine") || !panicLog.contains("server.go") {
		t.Fatalf("the panic log must carry a stack: %q", panicLog.String())
	}
	if panicLog.contains("p49_e2e") {
		t.Fatalf("the panic log must never carry a credential: %q", panicLog.String())
	}

	// The daemon is still serving: a fresh connection completes an exchange
	// that does not reach the authorizer.
	if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "bob"},
		store.Token{ID: "after", Secret: []byte("p49_after"), Kind: store.KindLogin, Principal: "user:bob@example.com", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	c = dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin,
		User: []byte("bob"), Port: []byte("vty1"), Data: []byte("p49_after")}.Encode(), 0)
	if _, body := c.recv(t); func() bool { r, _ := wire.DecodeAuthenReply(body); return r.Status != wire.AuthenStatusPass }() {
		t.Fatal("the daemon must keep serving after one connection panicked")
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
	// No sleep between the dials: Serve accepts in one goroutine and the
	// kernel's accept queue is FIFO, so c1 and c2 have taken their limiter
	// slots before Accept ever returns c3.
	c1, c2 := dial(t, addr, []byte("k2")), dial(t, addr, []byte("k2"))
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
		store.Token{ID: "second", Secret: []byte("p49_second"), Kind: store.KindLogin, Principal: "user:alice@example.com", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
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
	ts := newTestServer(t, log, gate, nil)

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

// flakyListener fails the first Accept and then behaves like the listener it
// wraps. EMFILE is the realistic cause and cannot be provoked directly from a
// test without exhausting the process's descriptors.
type flakyListener struct {
	net.Listener
	once sync.Once
}

func (f *flakyListener) Accept() (net.Conn, error) {
	failed := false
	f.once.Do(func() { failed = true })
	if failed {
		return nil, errors.New("accept: too many open files")
	}
	return f.Listener.Accept()
}

// TestAcceptErrorIsCountedAndTheListenerKeepsGoing covers the retry loop that
// used to be silent: while Accept is failing, no admitted device can connect
// at all, and an operator saw nothing -- no counter, no line. The loop must
// still recover on its own once the condition passes.
func TestAcceptErrorIsCountedAndTheListenerKeepsGoing(t *testing.T) {
	// The standard logger is written from Serve's goroutine and read from
	// this one, so the sink has to be locked on both sides.
	logged := &syncBuffer{}
	stdlog.SetOutput(logged)
	t.Cleanup(func() { stdlog.SetOutput(os.Stderr) })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := metrics.New(prometheus.NewRegistry())
	trie, err := admission.Build(admission.Inventory{})
	if err != nil {
		t.Fatal(err)
	}
	// Enough of Deps for the accept path and for one connection that sends
	// nothing: the handlers are never reached.
	d := Deps{Admission: trie, Metrics: m, Log: decision.NewJSONLines(&syncBuffer{}), Now: time.Now, IdleTimeout: time.Second,
		Limits: limits.New(limits.Config{PerNASConnections: 2, IdleTimeout: time.Second,
			MalformedBackoffBase: time.Millisecond, MalformedBackoffMax: time.Millisecond, MalformedWindow: time.Minute,
			AuthFailureDelayBase: time.Millisecond, AuthFailureDelayMax: time.Millisecond, AuthFailureWindow: time.Minute}, time.Now)}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() { defer close(served); Serve(ctx, &flakyListener{Listener: ln}, d) }()
	t.Cleanup(func() { cancel(); <-served })

	if !waitFor(t, func() bool { return testutil.ToFloat64(m.ConnectionEvents.WithLabelValues("accept_error")) >= 1 }) {
		t.Fatal("connection_events_total{accept_error} was not incremented")
	}
	// The counter moves before the line is written, so the line is waited
	// for too rather than read once.
	if !waitFor(t, func() bool { return logged.contains("accept failed") }) {
		t.Fatalf("an accept failure must say so: %q", logged.String())
	}
	// And the listener is still live: the transient error did not end Serve.
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("the listener must keep accepting after a transient error: %v", err)
	}
	conn.Close()
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
