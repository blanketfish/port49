package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/daemon/acct"
	"github.com/blanketfish/port49/internal/daemon/authen"
	"github.com/blanketfish/port49/internal/daemon/author"
	"github.com/blanketfish/port49/internal/daemon/limits"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/keyring"
	"github.com/blanketfish/port49/internal/platform"
	"github.com/blanketfish/port49/internal/policy"
	"github.com/blanketfish/port49/internal/secretref"
	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/memory"
	"github.com/blanketfish/port49/internal/tacacs/wire"
	"github.com/blanketfish/port49/internal/token"
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
// internal/port49d does: sharing the server's would let the final drain decide the
// spool is empty while a connection is still inside a handler, and whatever
// that connection offers next would be left on disk.
type testServer struct {
	addr      string
	metrics   *metrics.Metrics
	limits    *limits.Limiter
	spool     *acct.Spool
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

// slotFree waits until 127.0.0.1 has a per-NAS connection slot free. A
// connection's slot is released after its goroutine returns, which is after
// the reply has reached the client and after the server's close, so a client
// that dials again at once can still meet the cap: Accept refuses it, and the
// close of a socket holding its unread request is a reset. A test that dials
// one connection after another, more than the cap of 2, waits here first.
func (ts *testServer) slotFree(t *testing.T) {
	t.Helper()
	if !waitFor(t, func() bool {
		release, ok := ts.limits.Acquire(netip.MustParseAddr("127.0.0.1"))
		if ok {
			release()
		}
		return ok
	}) {
		t.Fatal("no per-NAS slot came free")
	}
}

// newTestServer starts a daemon against st. authz may be nil, which uses the
// lab authorizer every other test wants; a test passes its own only to reach
// a path the lab authorizer cannot produce.
func newTestServer(t *testing.T, log *syncBuffer, st store.Store, authz author.Authorizer) *testServer {
	t.Helper()
	return newTestServerWith(t, log, st, authz, nil)
}

// newTestServerWith is newTestServer with a last word on the Deps, for a test
// that needs one field the others do not.
func newTestServerWith(t *testing.T, log *syncBuffer, st store.Store, authz author.Authorizer, adjust func(*Deps)) *testServer {
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
		Keys: keysOf(map[string]keyring.Set{"prod_key": {Ref: "prod_key", Versions: []keyring.Version{{Number: 2, Secret: secretref.Of([]byte("k2"))}, {Number: 1, Secret: secretref.Of([]byte("k1")), Retired: true}}}}),
		// The e2e credentials here are not token-shaped, so the tag check never
		// fires; the key only has to be non-nil and stable.
		Authen: authen.New(st, em, lim, m, time.Now, func() string { return "ctx" + strconv.FormatInt(ids.Add(1), 10) },
			15*time.Minute, 2*time.Hour, time.Hour, time.Hour,
			token.NewTagWindow(token.TagKey([]byte("server_test")))),
		Author: author.New(st, authz, em, m, time.Now, platform.Defaults(), time.Hour, 10*time.Minute, time.Hour),
		Acct:   acct.New(st, sp, m, time.Now, platform.SystemUsers()),
		Limits: lim, Metrics: m, Log: em, Now: time.Now, IdleTimeout: time.Second}
	if adjust != nil {
		adjust(&d)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan struct{})
	go func() { defer close(served); Serve(ctx, ln, d) }()
	ts := &testServer{addr: ln.Addr().String(), metrics: m, limits: d.Limits, spool: sp, cancel: cancel, stopSpool: stopSpool, served: served, spoolDone: spoolDone}
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

// TestPAPLoginThenAuthorizeThenAccount drives the vEOS shape: the session
// authorization arrives at the login START's priv_lvl 1 (tests/lab/results/
// L1-arista_eos.md, L3-arista_eos.md).
func TestPAPLoginThenAuthorizeThenAccount(t *testing.T) {
	papLoginAuthorizeAccount(t, 1, 1)
}

// TestPAPSessionAuthorizationAboveTheLoginLevel is the same round trip with the
// shape SR Linux 26.7.2 sends: the login START at priv_lvl 0 and the session
// authorization at 1, above the 0 port49 holds (tests/lab/evidence/L76-nokia_srlinux/decisions.jsonl).
// Session authorization does not compare the request's level with the
// context's (spec §5.2).
func TestPAPSessionAuthorizationAboveTheLoginLevel(t *testing.T) {
	papLoginAuthorizeAccount(t, 0, 1)
}

func papLoginAuthorizeAccount(t *testing.T, startLvl, sessionLvl uint8) {
	t.Helper()
	log := &syncBuffer{}
	st := memory.New(time.Now)
	if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "e2e", Secret: []byte("p49_e2e"), Kind: store.KindLogin, Principal: "user:alice@example.com", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	ts := newTestServer(t, log, st, nil)
	addr := ts.addr

	c := dial(t, addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: startLvl, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin,
		User: []byte("alice"), Port: []byte("vty0"), RemAddr: []byte("198.51.100.4"), Data: []byte("p49_e2e")}.Encode(), 0)
	h, body := c.recv(t)
	reply, err := wire.DecodeAuthenReply(body)
	if err != nil || reply.Status != wire.AuthenStatusPass || h.SeqNo != 2 {
		t.Fatalf("%+v %v seq=%d", reply, err, h.SeqNo)
	}

	ts.slotFree(t)
	c = dial(t, addr, []byte("k2"))
	c.send(t, wire.TypeAuthor, wire.AuthorRequest{AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: sessionLvl, AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin,
		User: []byte("alice"), Port: []byte("vty0"), Args: [][]byte{[]byte("service=shell"), []byte("cmd=")}}.Encode(), 0)
	_, body = c.recv(t)
	ar, _ := wire.DecodeAuthorResponse(body)
	if ar.Status != wire.AuthorStatusPassAdd || len(ar.Args) != 1 || string(ar.Args[0]) != "priv-lvl=15" {
		t.Fatalf("%+v", ar)
	}

	// The device takes the level the reply granted, and its next command
	// arrives at 15: permitted because the context holds the reply's 15, which
	// policy granted, and not because the session request asked at 15.
	ts.slotFree(t)
	c = dial(t, addr, []byte("k2"))
	c.send(t, wire.TypeAuthor, wire.AuthorRequest{AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 15, AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin,
		User: []byte("alice"), Port: []byte("vty0"), Args: [][]byte{[]byte("service=shell"), []byte("cmd=show"), []byte("cmd-arg=version"), []byte("cmd-arg=<cr>")}}.Encode(), 0)
	_, body = c.recv(t)
	if cr, _ := wire.DecodeAuthorResponse(body); cr.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("a command at the level port49 granted must be permitted: %+v", cr)
	}
	// session.held_privilege is the context's level on arrival: the login
	// START's level on the session record whatever level it asked at, and the
	// reply's 15 on the command record.
	held := fmt.Sprintf(`"held_privilege":%d`, startLvl)
	if !log.contains(held+",") && !log.contains(held+"}") || !log.contains(`"held_privilege":15`) {
		t.Fatalf("held_privilege %d then 15 expected on the authorization records: %s", startLvl, log.String())
	}

	ts.slotFree(t)
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

func (panicAuthorizer) Session(context.Context, author.Request) author.Decision {
	panic("port49 test: deliberate panic inside an authorizer")
}

func (panicAuthorizer) Command(context.Context, author.Request) author.Decision {
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
	ts.slotFree(t)
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

// refusedAtAccept dials addr from d and asserts the connection is reset
// before anything is written on it, which is what a refusal at Accept looks
// like. On loopback that reset can reach the client before connect()
// returns, so the dial itself may fail with it (final review Minor 8). Nothing
// is sent, so nothing can be read or recorded.
func refusedAtAccept(t *testing.T, d *net.Dialer, addr string) {
	t.Helper()
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		if !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("want the connection refused at Accept with a reset, got %v", err)
		}
		return
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := conn.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("want the connection refused at Accept with a reset, got %d bytes, %v", n, err)
	}
}

// An unadmitted source is closed as a key miss is (L28 branch H; spec §15
// L31). It gets the record, a strike, and a reset at once, and is never held
// for the backoff. Its next connection is refused at Accept, before it
// writes: with single-connection on, IOS-XE and NX-OS wait out their 5 s
// timeout after a reset that follows their request.
func TestAnUnadmittedSourceIsResetAtOnceAndRefusedAtAccept(t *testing.T) {
	log := &syncBuffer{}
	ts := newTestServerWith(t, log, memory.New(time.Now), nil, func(d *Deps) { d.Limits = slowBackoff() })
	// 127.0.0.2 is loopback but not in the inventory.
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)}}
	conn, err := d.Dial("tcp", ts.addr)
	if err != nil {
		t.Skipf("cannot source from 127.0.0.2 on this host: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	c := &client{conn: conn, key: []byte("k2"), sid: 7, seq: 1}
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	began := time.Now()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("want a reset, got %v", err)
	}
	if held := time.Since(began); held > 500*time.Millisecond {
		t.Fatalf("the connection was held %s before the reset: an unadmitted source is not held for the backoff", held)
	}
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"unadmitted_source"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	refusedAtAccept(t, d, ts.addr)
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("held_refused")); n != 1 {
		t.Fatalf("held_refused = %v: the strike did not refuse the next connection at Accept", n)
	}
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("unadmitted_source")); n != 1 {
		t.Fatalf("unadmitted_source = %v", n)
	}
	if n := testutil.ToFloat64(ts.metrics.Unvalidated.WithLabelValues("unadmitted_source")); n != 1 {
		t.Fatalf("unvalidated{unadmitted_source} = %v: the connection refused at Accept left a record", n)
	}
}

// quarantinePolicy is a policy under which leaf-01 (arista_eos) is quarantined
// from adminUntil to opUntil: once the admin grant lapses, the custom level
// `unmapped` left has no rendering on arista_eos, and once the operator grant lapses too
// there is no composition to fail.
func quarantinePolicy(t *testing.T, loaded, adminUntil, opUntil time.Time) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(`
privilege_levels: [{name: readonly}, {name: operator}, {name: unmapped}, {name: admin}]
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: op, privilege: unmapped, permit: [show **]}
  - {name: adm, privilege: admin, permit: ["**"]}
subjects: [{name: s, identity: "user:alice@example.com", username: alice, token_ttl: 60s}]
grants:
  - {subject: s, scope: all_devices, roles: [op], expires: `+opUntil.Format(time.RFC3339)+`}
  - {subject: s, scope: all_devices, roles: [adm], expires: `+adminUntil.Format(time.RFC3339)+`}
`), policy.Env{Now: loaded, Devices: []admission.Device{{Name: "leaf-01", Platform: "arista_eos",
		Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// slowBackoff is a limiter whose malformed-packet delay is far longer than
// any quarantine test waits, so a connection held for it is seen as held.
func slowBackoff() *limits.Limiter {
	return limits.New(limits.Config{PerNASConnections: 2, IdleTimeout: time.Second,
		MalformedBackoffBase: 5 * time.Second, MalformedBackoffMax: 5 * time.Second, MalformedWindow: time.Minute,
		AuthFailureDelayBase: time.Millisecond, AuthFailureDelayMax: time.Millisecond, AuthFailureWindow: time.Minute}, time.Now)
}

// closedAtOnce asserts the server hung up on c without a reply and without
// holding the connection: a device waiting on a silent server costs ~5 s per
// command (tests/lab/results/L4-error-*.md), and this close costs what a
// refused connection does (tests/lab/results/quarantine-*.md).
func closedAtOnce(t *testing.T, c *client) {
	t.Helper()
	start := time.Now()
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	// The unread body makes the close a reset rather than a FIN; either is
	// the server gone, and a timeout is the connection held.
	n, err := c.conn.Read(make([]byte, 1))
	if n != 0 || !(errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET)) {
		t.Fatalf("want the connection closed without a reply, got %d bytes, %v", n, err)
	}
	if held := time.Since(start); held > 500*time.Millisecond {
		t.Fatalf("the connection was held %s before it was closed", held)
	}
}

// A quarantined device gets silence, not FAIL (spec §10; §13 decision 20):
// its connection is closed without a reply after one header, at once rather
// than after the limiter's delay, and the record names the device and says
// device_quarantined. The body, which carries the credential, is never read.
func TestAQuarantinedDeviceIsClosedWithoutAReply(t *testing.T) {
	log := &syncBuffer{}
	now := time.Now()
	pol := quarantinePolicy(t, now.Add(-time.Hour), now.Add(-time.Minute), now.Add(time.Hour))
	ts := newTestServerWith(t, log, memory.New(time.Now), nil, func(d *Deps) {
		d.Quarantined = pol.Quarantined
		d.Limits = slowBackoff()
	})
	c := dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	closedAtOnce(t, c)
	if !waitFor(t, func() bool { return log.contains(`"reason":"device_quarantined"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	if !log.contains(`"name":"leaf-01"`) || !log.contains(`"diagnosis":"device_quarantined"`) || log.contains("p49_e2e") {
		t.Fatalf("the record names the device, and never the credential: %s", log.String())
	}
	if n := testutil.ToFloat64(ts.metrics.Unvalidated.WithLabelValues("device_quarantined")); n != 1 {
		t.Fatalf("unvalidated{device_quarantined} = %v", n)
	}
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("malformed_backoff")); n != 0 {
		t.Fatalf("a quarantined device is not a malformed-packet strike: %v", n)
	}
}

// Quarantine is decided at the time of each packet, not once at start: a
// device is served until a grant's expiry quarantines it, then closed at once
// — on a new connection and on a single-connection session opened before the
// expiry — and served again once the quarantine's span ends.
func TestAQuarantineTakesEffectAtTheExpiryAndEndsWithIt(t *testing.T) {
	log := &syncBuffer{}
	loaded := time.Now()
	adminUntil, opUntil := loaded.Add(time.Hour), loaded.Add(2*time.Hour)
	pol := quarantinePolicy(t, loaded, adminUntil, opUntil)
	var clock atomic.Pointer[time.Time]
	clock.Store(&loaded)
	lim := slowBackoff()
	st := memory.New(time.Now)
	for _, id := range []string{"a", "b", "c"} {
		if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
			store.Token{ID: id, Secret: []byte("p49_" + id), Kind: store.KindLogin, Principal: "user:alice@example.com",
				ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	ts := newTestServerWith(t, log, st, nil, func(d *Deps) {
		d.Quarantined = pol.Quarantined
		d.Now = func() time.Time { return *clock.Load() }
		d.Limits = lim
	})
	login := func(c *client, sid uint32, tok string) {
		c.sid, c.seq = sid, 1
		c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
			Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: []byte(tok)}.Encode(),
			wire.FlagSingleConnect)
	}
	passes := func(c *client) {
		t.Helper()
		if _, body := c.recv(t); body == nil {
			t.Fatal("no reply")
		} else if r, _ := wire.DecodeAuthenReply(body); r.Status != wire.AuthenStatusPass {
			t.Fatalf("%+v", r)
		}
	}

	// Before the expiry: served, and the session stays open.
	held := dial(t, ts.addr, []byte("k2"))
	login(held, 1, "p49_a")
	passes(held)

	// After it: the open session's next packet is closed at once, and so is
	// a new connection.
	lapsed := adminUntil.Add(time.Second)
	clock.Store(&lapsed)
	login(held, 2, "p49_b")
	closedAtOnce(t, held)
	// A new connection inside the decline window that close opened is refused
	// at Accept, before it writes, and leaves no record (spec §15 L31).
	refusedAtAccept(t, &net.Dialer{}, ts.addr)
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("declined_refused")); n != 1 {
		t.Fatalf("declined_refused = %v", n)
	}
	if !waitFor(t, func() bool {
		return testutil.ToFloat64(ts.metrics.Unvalidated.WithLabelValues("device_quarantined")) == 1
	}) {
		t.Fatalf("unvalidated{device_quarantined} = %v", testutil.ToFloat64(ts.metrics.Unvalidated.WithLabelValues("device_quarantined")))
	}

	// Once the quarantine's span ends the device is served again. The
	// connections just closed hold the source's per-NAS slots until
	// each one's goroutine releases its slot, which it does just after the
	// socket closes (and after Connections{open} falls): a dial in that
	// window is refused at the cap, a test race and not the quarantine's
	// doing (final review Minor 8). Wait for a slot to come free first.
	if !waitFor(t, func() bool {
		release, ok := lim.Acquire(netip.MustParseAddr("127.0.0.1"))
		if ok {
			release()
		}
		return ok
	}) {
		t.Fatal("no per-NAS slot came free after both quarantined connections were closed")
	}
	ended := opUntil.Add(time.Second)
	clock.Store(&ended)
	again := dial(t, ts.addr, []byte("k2"))
	login(again, 4, "p49_c")
	passes(again)
	// The window was still open (5 s) and was dropped because the quarantine
	// ended, not because it expired.
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("declined_refused")); n != 1 {
		t.Fatalf("declined_refused = %v after the quarantine ended", n)
	}
	if lim.Declined(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("the window survived the end of the quarantine")
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

// Spec §5.7, §10: every record of a validated exchange names the key that
// validated it, which is what `port49 keys status` reads a rotation from.
func TestAValidatedExchangeNamesItsKey(t *testing.T) {
	log := &syncBuffer{}
	addr, _, _ := startServer(t, log)
	c := dial(t, addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), RemAddr: []byte("198.51.100.4"),
		Data: []byte("p49_e2e")}.Encode(), 0)
	c.recv(t)
	if !waitFor(t, func() bool { return log.contains(`"event":"redeem"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	if !log.contains(`"key_ref":"prod_key"`) || !log.contains(`"key_version":2`) {
		t.Fatalf("the redeem record does not name its key: %s", log.String())
	}
}

// A key one device holds is counted under single_device/any, never under a
// label that names it (ruling 4).
func TestAValidationOfASingleDeviceKeyIsNotLabelledByIt(t *testing.T) {
	log := &syncBuffer{}
	ts := newTestServerWith(t, log, memory.New(time.Now), nil, nil)
	ts.metrics.SetSingleDeviceKeyRefs(map[string]bool{"prod_key": true})
	c := dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	c.recv(t)
	if !waitFor(t, func() bool {
		return testutil.ToFloat64(ts.metrics.KeyValidations.WithLabelValues("single_device", "any", "validated")) == 1
	}) {
		t.Fatal("the validation was not counted under single_device/any")
	}
	if n := testutil.ToFloat64(ts.metrics.KeyValidations.WithLabelValues("prod_key", "2", "validated")); n != 0 {
		t.Fatalf("prod_key v2 validated %v times: the label names the key", n)
	}
}

// A device admission refuses — no key group admits it, two tie, or its
// key_ref is one port49d holds no key for — is closed after the header, at
// once, with nothing decrypted and no strike, and recorded apart from both
// the key report and noise (spec §10, admission_refused).
func TestARefusedDeviceIsClosedAtOnceAndNamed(t *testing.T) {
	log := &syncBuffer{}
	ts := newTestServerWith(t, log, memory.New(time.Now), nil, func(d *Deps) {
		dev := admission.Device{Name: "leaf-01", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
		trie, err := admission.NewTrie([]admission.Resolved{{Device: dev,
			Refused: "matches no key group, so no key admits it (spec §10)"}})
		if err != nil {
			t.Fatal(err)
		}
		d.Admission = trie
		d.Limits = slowBackoff()
	})
	c := dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	closedAtOnce(t, c)
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"admission_refused"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	if !log.contains(`"name":"leaf-01"`) || log.contains("p49_e2e") {
		t.Fatalf("the record names the device, and never the credential: %s", log.String())
	}
	if n := testutil.ToFloat64(ts.metrics.Unvalidated.WithLabelValues("admission_refused")); n != 1 {
		t.Fatalf("unvalidated{admission_refused} = %v", n)
	}
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("malformed_backoff")); n != 0 {
		t.Fatalf("a refused device is not a strike: %v", n)
	}
}

// "Admitted" is Refused == "", never a KeyRef or an index hit (Task 3 review
// M3): an entry that is refused and still carries a key_ref port49d holds —
// which admission never builds, since a refused entry fails closed — is
// closed all the same, and its packet is never tried under that key.
func TestARefusedEntryIsNeverValidatedUnderItsKey(t *testing.T) {
	log := &syncBuffer{}
	ts := newTestServerWith(t, log, memory.New(time.Now), nil, func(d *Deps) {
		dev := admission.Device{Name: "leaf-01", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
		trie, err := admission.NewTrie([]admission.Resolved{{Device: dev, KeyRef: "prod_key",
			Refused: "has transport \"udp\", which is not tcp or tls", Refusal: admission.RefusedTransport}})
		if err != nil {
			t.Fatal(err)
		}
		d.Admission = trie
		d.Limits = slowBackoff()
	})
	c := dial(t, ts.addr, []byte("k2")) // prod_key's current secret
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	closedAtOnce(t, c)
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"admission_refused"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	for _, diag := range []keyring.Diagnosis{keyring.DiagValidated, keyring.DiagMatchesRetired, keyring.DiagNoKnownKey,
		keyring.DiagUnadmittedSource} {
		if n := testutil.ToFloat64(ts.metrics.Unvalidated.WithLabelValues(string(diag))); n != 0 {
			t.Fatalf("unvalidated{%s} = %v: the packet was tried under a key", diag, n)
		}
	}
	if log.contains(`"event":"redeem"`) || log.contains(`"diagnosis":"validated"`) {
		t.Fatalf("a refused device's packet was validated: %s", log.String())
	}
}

// A refused device's first connection is recorded and reset at once, and its
// next connection is refused at Accept, before it writes, with no record and
// no strike (spec §10, "A declined source is refused at Accept"; §15 L31).
func TestARefusedDevicesNextConnectionIsRefusedAtAccept(t *testing.T) {
	log := &syncBuffer{}
	lim := slowBackoff()
	ts := newTestServerWith(t, log, memory.New(time.Now), nil, func(d *Deps) {
		trie, err := admission.NewTrie([]admission.Resolved{{Device: leaf01,
			Refused: "matches no key group, so no key admits it (spec §10)", Refusal: admission.RefusedNoGroup}})
		if err != nil {
			t.Fatal(err)
		}
		d.Admission = trie
		d.Limits = lim
	})
	c := dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.conn.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("want the refused device's connection reset, got %v", err)
	}
	refusedAtAccept(t, &net.Dialer{}, ts.addr)
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("declined_refused")); n != 1 {
		t.Fatalf("declined_refused = %v", n)
	}
	if n := testutil.ToFloat64(ts.metrics.Unvalidated.WithLabelValues("admission_refused")); n != 1 {
		t.Fatalf("unvalidated{admission_refused} = %v: one record, for the first connection only", n)
	}
	if lim.Holding(netip.MustParseAddr("127.0.0.1")) ||
		testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("held_refused")) != 0 {
		t.Fatal("a refused device took a strike")
	}
}

// The same for a quarantined device.
func TestAQuarantinedDevicesNextConnectionIsRefusedAtAccept(t *testing.T) {
	log := &syncBuffer{}
	now := time.Now()
	pol := quarantinePolicy(t, now.Add(-time.Hour), now.Add(-time.Minute), now.Add(time.Hour))
	lim := slowBackoff()
	ts := newTestServerWith(t, log, memory.New(time.Now), nil, func(d *Deps) {
		d.Quarantined = pol.Quarantined
		d.Limits = lim
	})
	c := dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.conn.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("want the quarantined device's connection reset, got %v", err)
	}
	refusedAtAccept(t, &net.Dialer{}, ts.addr)
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("declined_refused")); n != 1 {
		t.Fatalf("declined_refused = %v", n)
	}
	if n := testutil.ToFloat64(ts.metrics.Unvalidated.WithLabelValues("device_quarantined")); n != 1 {
		t.Fatalf("unvalidated{device_quarantined} = %v: one record, for the first connection only", n)
	}
	if lim.Holding(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("a quarantined device took a strike")
	}
}

// A reload that admits a refused device again serves its next connection at
// once, inside the window its refusal opened: the window never outlasts its
// reason.
func TestAReloadThatAdmitsARefusedDeviceServesItInsideTheWindow(t *testing.T) {
	log := &syncBuffer{}
	st := memory.New(time.Now)
	if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "e2e", Secret: []byte("p49_e2e"), Kind: store.KindLogin, Principal: "user:alice@example.com",
			ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	adm := &swapAdmitter{}
	adm.swap(t, admission.Resolved{Device: leaf01, Refused: "matches no key group, so no key admits it (spec §10)",
		Refusal: admission.RefusedNoGroup})
	lim := slowBackoff()
	ts := newTestServerWith(t, log, st, nil, func(d *Deps) {
		d.Admission = adm
		d.Limits = lim
	})
	start := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode()
	c := dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, start, 0)
	closedAtOnce(t, c)
	if !lim.Declined(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("the refusal opened no decline window")
	}
	adm.swap(t, admission.Resolved{Device: leaf01, KeyRef: "prod_key"})
	c = dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, start, 0)
	if _, body := c.recv(t); body == nil {
		t.Fatal("no reply")
	} else if r, _ := wire.DecodeAuthenReply(body); r.Status != wire.AuthenStatusPass {
		t.Fatalf("the admitted device was not served: %+v", r)
	}
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("declined_refused")); n != 0 {
		t.Fatalf("declined_refused = %v: an admitted device was refused at Accept", n)
	}
	if lim.Declined(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("the window survived the admission")
	}
}

// A connection accepted while its device was refused, whose packet arrives
// only after a reload admitted the device, is declined on its Accept-time
// snapshot and reopens a window. The next Accept asks again and serves the
// device: a stale connection can never refuse an admitted one.
func TestAStaleRefusedConnectionCannotRefuseTheAdmittedDevice(t *testing.T) {
	log := &syncBuffer{}
	st := memory.New(time.Now)
	for _, id := range []string{"a", "b"} {
		if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
			store.Token{ID: id, Secret: []byte("p49_" + id), Kind: store.KindLogin, Principal: "user:alice@example.com",
				ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	adm := &swapAdmitter{}
	adm.swap(t, admission.Resolved{Device: leaf01, Refused: "matches no key group, so no key admits it (spec §10)",
		Refusal: admission.RefusedNoGroup})
	lim := slowBackoff()
	ts := newTestServerWith(t, log, st, nil, func(d *Deps) {
		d.Admission = adm
		d.Limits = lim
	})
	login := func(c *client, tok string) {
		c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
			Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte(tok)}.Encode(), 0)
	}
	passes := func(c *client) {
		t.Helper()
		if _, body := c.recv(t); body == nil {
			t.Fatal("no reply")
		} else if r, _ := wire.DecodeAuthenReply(body); r.Status != wire.AuthenStatusPass {
			t.Fatalf("%+v", r)
		}
	}
	src := netip.MustParseAddr("127.0.0.1")

	// Accepted while refused, with nothing sent yet.
	stale := dial(t, ts.addr, []byte("k2"))
	if !waitFor(t, func() bool { return testutil.ToFloat64(ts.metrics.Connections.WithLabelValues("open")) == 1 }) {
		t.Fatal("the stale connection was never accepted")
	}
	adm.swap(t, admission.Resolved{Device: leaf01, KeyRef: "prod_key"})
	fresh := dial(t, ts.addr, []byte("k2"))
	login(fresh, "p49_a")
	passes(fresh)

	// The stale connection's packet is declined on its Accept-time snapshot,
	// and reopens a window. Its token is never read, so p49_b stays unspent.
	login(stale, "p49_b")
	closedAtOnce(t, stale)
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"admission_refused"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	if !lim.Declined(src) {
		t.Fatal("the stale connection's decline opened no window")
	}
	// Both earlier connections release their per-NAS slots just after their
	// sockets close; wait for one, as TestAQuarantineTakesEffectAtTheExpiryAndEndsWithIt does.
	if !waitFor(t, func() bool {
		release, ok := lim.Acquire(src)
		if ok {
			release()
		}
		return ok
	}) {
		t.Fatal("no per-NAS slot came free")
	}
	third := dial(t, ts.addr, []byte("k2"))
	login(third, "p49_b")
	passes(third)
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("declined_refused")); n != 0 {
		t.Fatalf("declined_refused = %v: the admitted device was refused at Accept", n)
	}
	if lim.Declined(src) {
		t.Fatal("the reopened window survived the admitted device's next Accept")
	}
}

// reloadAfterLookup is a swapAdmitter that runs a reload once, just after the
// first Lookup it answers once armed: a reload that lands between Accept's
// re-ask of admission and its Undecline.
type reloadAfterLookup struct {
	swapAdmitter
	reload atomic.Pointer[func()]
}

func (a *reloadAfterLookup) Lookup(addr netip.Addr) (admission.Resolved, bool) {
	r, ok := a.swapAdmitter.Lookup(addr)
	if f := a.reload.Swap(nil); f != nil {
		(*f)()
	}
	return r, ok
}

// Accept's Declined, re-ask and Undecline are not one atomic step (Task 4
// ruling 4). A reload that refuses the device again just after Accept asked
// and found it admitted fails closed: the connection is served on an
// admitted snapshot, but its first packet asks admission again, is declined
// with one record and nothing read, and reopens the window. That is one
// refusal more than an atomic check would give, and no credential is ever
// tried; the next connection is refused at Accept.
func TestAReloadBetweenAcceptsReAskAndUndeclineFailsClosed(t *testing.T) {
	log := &syncBuffer{}
	st := memory.New(time.Now)
	if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "e2e", Secret: []byte("p49_e2e"), Kind: store.KindLogin, Principal: "user:alice@example.com",
			ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	refused := admission.Resolved{Device: leaf01, Refused: "matches no key group, so no key admits it (spec §10)",
		Refusal: admission.RefusedNoGroup}
	adm := &reloadAfterLookup{}
	adm.swap(t, refused)
	lim := slowBackoff()
	ts := newTestServerWith(t, log, st, nil, func(d *Deps) {
		d.Admission = adm
		d.Limits = lim
	})
	src := netip.MustParseAddr("127.0.0.1")
	start := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode()
	c := dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, start, 0)
	closedAtOnce(t, c)
	if !lim.Declined(src) {
		t.Fatal("the refusal opened no decline window")
	}

	// A reload admits the device, and another refuses it again just after the
	// next Accept has asked.
	adm.swap(t, admission.Resolved{Device: leaf01, KeyRef: "prod_key"})
	again := func() { adm.swap(t, refused) }
	adm.reload.Store(&again)
	if !waitFor(t, func() bool {
		release, ok := lim.Acquire(src)
		if ok {
			release()
		}
		return ok
	}) {
		t.Fatal("no per-NAS slot came free")
	}
	c = dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, start, 0)
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := c.conn.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("want the connection reset with no reply, got %d bytes, %v", n, err)
	}
	if adm.reload.Load() != nil {
		t.Fatal("the reload never ran between Accept's re-ask and its Undecline")
	}
	if !waitFor(t, func() bool {
		return testutil.ToFloat64(ts.metrics.Unvalidated.WithLabelValues("admission_refused")) == 2
	}) {
		t.Fatalf("unvalidated{admission_refused} = %v", testutil.ToFloat64(ts.metrics.Unvalidated.WithLabelValues("admission_refused")))
	}
	// Declined by serve's own re-ask, on a connection Accept served.
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("admission_closed")); n != 1 {
		t.Fatalf("admission_closed = %v", n)
	}
	if log.contains(`"event":"redeem"`) || log.contains(`"diagnosis":"validated"`) || log.contains("p49_e2e") {
		t.Fatalf("the refused device's credential was tried: %s", log.String())
	}
	if toks, err := st.Candidates(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"}); err != nil ||
		len(toks) != 1 {
		t.Fatalf("the token was spent: %d left, %v", len(toks), err)
	}
	if !lim.Declined(src) {
		t.Fatal("the late decline reopened no window")
	}
	if !waitFor(t, func() bool {
		release, ok := lim.Acquire(src)
		if ok {
			release()
		}
		return ok
	}) {
		t.Fatal("no per-NAS slot came free")
	}
	refusedAtAccept(t, &net.Dialer{}, ts.addr)
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("declined_refused")); n != 1 {
		t.Fatalf("declined_refused = %v", n)
	}
	if lim.Holding(src) {
		t.Fatal("the late decline struck the source")
	}
}

// The same for a quarantine that starts just after Accept asked and found the
// device not quarantined: serve asks the quarantine again at the first
// packet, closes it silent with one record and nothing read, and reopens the
// window.
func TestAQuarantineBetweenAcceptsReAskAndUndeclineFailsClosed(t *testing.T) {
	log := &syncBuffer{}
	st := memory.New(time.Now)
	if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "e2e", Secret: []byte("p49_e2e"), Kind: store.KindLogin, Principal: "user:alice@example.com",
			ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	var quarantined, startAfterNextAsk atomic.Bool
	quarantined.Store(true)
	lim := slowBackoff()
	ts := newTestServerWith(t, log, st, nil, func(d *Deps) {
		d.Quarantined = func(string, time.Time) (string, bool) {
			q := quarantined.Load()
			if startAfterNextAsk.Swap(false) {
				quarantined.Store(true)
			}
			return "test", q
		}
		d.Limits = lim
	})
	src := netip.MustParseAddr("127.0.0.1")
	start := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode()
	c := dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, start, 0)
	closedAtOnce(t, c)
	if !lim.Declined(src) {
		t.Fatal("the quarantine opened no decline window")
	}

	// The quarantine ends, and another starts just after the next Accept has
	// asked.
	quarantined.Store(false)
	startAfterNextAsk.Store(true)
	if !waitFor(t, func() bool {
		release, ok := lim.Acquire(src)
		if ok {
			release()
		}
		return ok
	}) {
		t.Fatal("no per-NAS slot came free")
	}
	c = dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, start, 0)
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := c.conn.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("want the connection reset with no reply, got %d bytes, %v", n, err)
	}
	if startAfterNextAsk.Load() {
		t.Fatal("the quarantine never started between Accept's re-ask and its Undecline")
	}
	if !waitFor(t, func() bool {
		return testutil.ToFloat64(ts.metrics.Unvalidated.WithLabelValues("device_quarantined")) == 2
	}) {
		t.Fatalf("unvalidated{device_quarantined} = %v", testutil.ToFloat64(ts.metrics.Unvalidated.WithLabelValues("device_quarantined")))
	}
	if log.contains(`"event":"redeem"`) || log.contains(`"diagnosis":"validated"`) || log.contains("p49_e2e") {
		t.Fatalf("the quarantined device's credential was tried: %s", log.String())
	}
	if toks, err := st.Candidates(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"}); err != nil ||
		len(toks) != 1 {
		t.Fatalf("the token was spent: %d left, %v", len(toks), err)
	}
	if !lim.Declined(src) {
		t.Fatal("the late quarantine reopened no window")
	}
	if !waitFor(t, func() bool {
		release, ok := lim.Acquire(src)
		if ok {
			release()
		}
		return ok
	}) {
		t.Fatal("no per-NAS slot came free")
	}
	refusedAtAccept(t, &net.Dialer{}, ts.addr)
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("declined_refused")); n != 1 {
		t.Fatalf("declined_refused = %v", n)
	}
	if lim.Holding(src) {
		t.Fatal("the late quarantine struck the source")
	}
}

// A validated connection marks its device's key version, and an accept
// version past its date is refused as a retired one is.
func TestKeyVersionsAreMarkedAndADatePastRefuses(t *testing.T) {
	log := &syncBuffer{}
	var seen keyring.Seen
	ts := newTestServerWith(t, log, memory.New(time.Now), nil, func(d *Deps) {
		d.Keys = keysOf(map[string]keyring.Set{"prod_key": {Ref: "prod_key", Versions: []keyring.Version{
			{Number: 2, Secret: secretref.Of([]byte("k2"))}, {Number: 1, Secret: secretref.Of([]byte("k1")), RetireAt: time.Now().Add(-time.Hour)}}}})
		d.KeySeen = seen.Mark
	})
	c := dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	c.recv(t)
	if !waitFor(t, func() bool { return seen.Count("prod_key", 2) == 1 }) {
		t.Fatal("the validated version was not marked")
	}
	c = dial(t, ts.addr, []byte("k1"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"matches_retired"`) }) {
		t.Fatalf("a version past its date admitted: %s", log.String())
	}
}

// A single-connection opened under an accept version before its date does not
// outlive the date: the first packet after it is refused as a retired one is,
// with no reply, so a long-held connection never extends a key's life.
func TestAnOpenConnectionDoesNotOutliveItsVersionsDate(t *testing.T) {
	log := &syncBuffer{}
	at := time.Now().Add(time.Hour)
	var clock atomic.Int64
	clock.Store(at.Add(-time.Minute).UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()) }
	ts := newTestServerWith(t, log, memory.New(time.Now), nil, func(d *Deps) {
		d.Keys = keysOf(map[string]keyring.Set{"prod_key": {Ref: "prod_key", Versions: []keyring.Version{
			{Number: 2, Secret: secretref.Of([]byte("k2"))}, {Number: 1, Secret: secretref.Of([]byte("k1")), RetireAt: at}}}})
		d.Now = now
	})
	c := dial(t, ts.addr, []byte("k1"))
	start := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode()
	c.send(t, wire.TypeAuthen, start, wire.FlagSingleConnect)
	c.recv(t)
	clock.Store(at.UnixNano())
	c.sid, c.seq = c.sid+1, 1
	c.send(t, wire.TypeAuthen, start, wire.FlagSingleConnect)
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"matches_retired"`) }) {
		t.Fatalf("a connection outlived its version's date: %s", log.String())
	}
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := c.conn.Read(make([]byte, 1)); err == nil {
		t.Fatalf("a reply (%d bytes) under a version past its date", n)
	}
}

// No unvalidated packet is held: the server keeps no copy of a packet no key
// validates (its bytes are attacker-controlled and `port49d keys-diagnose`
// reads a capture instead, spec §10). The record and the metric stay, with the
// body's hash and never its bytes.
func TestNoUnvalidatedPacketIsHeld(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(Deps{}), reflect.TypeOf(conn{})} {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if f.Name == "Held" || strings.Contains(f.Type.String(), "Held") {
				t.Errorf("%s has a field %s %s: a packet no key validates is not kept", typ.Name(), f.Name, f.Type)
			}
		}
	}
	log := &syncBuffer{}
	addr, _, m := startServer(t, log)
	c := dial(t, addr, []byte("some-other-key"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"no_known_key_matches"`) }) {
		t.Fatalf("the unvalidated record was not written: %s", log.String())
	}
	if !log.contains(`"body_sha256":"`) || log.contains("p49_e2e") {
		t.Fatalf("the record must carry the body's hash and never its bytes: %s", log.String())
	}
	if got := testutil.ToFloat64(m.Unvalidated.WithLabelValues("no_known_key_matches")); got < 1 {
		t.Fatalf("unvalidated_packets_total{no_known_key_matches} = %v", got)
	}
}

// L28 branch H: a key miss from an admitted device is closed at once, and a
// source inside its backoff is refused at Accept rather than held silent,
// so a device missed in a rotation falls to its local method without
// waiting (tests/lab/results/L28-*.md).
func TestAKeyMissIsClosedAtOnceAndAHeldSourceRefusedAtAccept(t *testing.T) {
	log := &syncBuffer{}
	ts := newTestServerWith(t, log, memory.New(time.Now), nil, func(d *Deps) { d.Limits = slowBackoff() })
	c := dial(t, ts.addr, []byte("wrong"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	closedAtOnce(t, c)
	refusedAtAccept(t, &net.Dialer{}, ts.addr)
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("held_refused")); n != 1 {
		t.Fatalf("held_refused = %v", n)
	}
}

// L28 branch H on IOS-XE: the C8000V ignores a FIN from the server and waits
// out its own 5 s timeout, then falls to local only after it; a reset it
// acts on at once, as it does on a quarantine's close
// (tests/lab/results/L28-cisco_iosxe.md). So a key miss is closed with a
// reset, whose body port49d has read.
func TestAKeyMissIsClosedWithAReset(t *testing.T) {
	log := &syncBuffer{}
	ts := newTestServerWith(t, log, memory.New(time.Now), nil, func(d *Deps) { d.Limits = slowBackoff() })
	c := dial(t, ts.addr, []byte("wrong"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.conn.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("want the key miss closed with a reset, got %v", err)
	}
}

// A packet past its version's retire_after on an open connection is treated
// as a new connection's first packet would be (spec §10), and so closed as a
// first-packet miss is under L28 branch H: a matches_retired record, a
// strike, and a reset at once, never a silent hold for the backoff. How a
// device reacts to it is unmeasured.
func TestAPacketPastItsDateIsClosedWithAReset(t *testing.T) {
	log := &syncBuffer{}
	at := time.Now().Add(time.Hour)
	var clock atomic.Int64
	clock.Store(at.Add(-time.Minute).UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()) }
	ts := newTestServerWith(t, log, memory.New(time.Now), nil, func(d *Deps) {
		d.Keys = keysOf(map[string]keyring.Set{"prod_key": {Ref: "prod_key", Versions: []keyring.Version{
			{Number: 2, Secret: secretref.Of([]byte("k2"))}, {Number: 1, Secret: secretref.Of([]byte("k1")), RetireAt: at}}}})
		d.Now = now
		d.Limits = slowBackoff()
	})
	c := dial(t, ts.addr, []byte("k1"))
	start := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode()
	c.send(t, wire.TypeAuthen, start, wire.FlagSingleConnect)
	c.recv(t)
	clock.Store(at.UnixNano())
	c.sid, c.seq = c.sid+1, 1
	c.send(t, wire.TypeAuthen, start, wire.FlagSingleConnect)
	began := time.Now()
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.conn.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("want a reset, got %v", err)
	}
	if held := time.Since(began); held > 500*time.Millisecond {
		t.Fatalf("the connection was held %s before it was reset", held)
	}
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"matches_retired"`) }) {
		t.Fatalf("no matches_retired record: %s", log.String())
	}
	// The strike: the next connection from this source is refused at Accept,
	// with a reset. On loopback that reset can reach the client before
	// connect() returns, so the dial itself may fail with it: the same
	// refusal (final review Minor 8).
	if conn, err := net.Dial("tcp", ts.addr); err == nil {
		t.Cleanup(func() { conn.Close() })
		closedAtOnce(t, &client{conn: conn, key: []byte("k2"), sid: 0xabcd1234, seq: 1})
	} else if !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("want the struck source refused at Accept with a reset, got %v", err)
	}
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("held_refused")); n != 1 {
		t.Fatalf("held_refused = %v; the packet past its date was not struck", n)
	}
}

// L28 branch H: a source refused at Accept inside its backoff is reset, as a
// key miss is, so the C8000V falls to local at once rather than at its timeout
// (tests/lab/results/L28-fin-cisco_iosxe.md).
func TestAHeldSourceIsRefusedWithAReset(t *testing.T) {
	log := &syncBuffer{}
	ts := newTestServerWith(t, log, memory.New(time.Now), nil, func(d *Deps) { d.Limits = slowBackoff() })
	c := dial(t, ts.addr, []byte("wrong"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	closedAtOnce(t, c)
	refusedAtAccept(t, &net.Dialer{}, ts.addr)
}

// swapAdmitter is the policy in force's admission index as port49d gives it:
// a pointer a reload swaps while connections are open.
type swapAdmitter struct {
	p atomic.Pointer[admission.Trie]
}

func (a *swapAdmitter) Lookup(addr netip.Addr) (admission.Resolved, bool) {
	return a.p.Load().Lookup(addr)
}

func (a *swapAdmitter) swap(t *testing.T, rs ...admission.Resolved) {
	t.Helper()
	trie, err := admission.NewTrie(rs)
	if err != nil {
		t.Fatal(err)
	}
	a.p.Store(trie)
}

var (
	leaf01 = admission.Device{Name: "leaf-01", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	leaf02 = admission.Device{Name: "leaf-02", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.2")}}
)

// A reload that flips an open RFC 8907 connection's device to transport tls,
// key_ref kept, withdraws it: the transport clause stands on this listener.
func TestAReloadThatChangesTheTransportResetsItsOpenConnection(t *testing.T) {
	tlsDev := leaf01
	tlsDev.Transport = admission.TransportTLS
	c, ts, log := reloadBetweenPackets(t, func(a *swapAdmitter) {
		a.swap(t, admission.Resolved{Device: tlsDev, KeyRef: "prod_key"})
	})
	resetWithNoStrike(t, c, ts, log, "admission_withdrawn")
}

// A reload that adds an address leaves an open RFC 8907 connection alone: on
// 49 the key is the identity, not the address.
func TestAReloadThatAddsAnAddressKeepsItsOpenConnection(t *testing.T) {
	more := leaf01
	more.Addresses = append([]netip.Addr{}, leaf01.Addresses...)
	more.Addresses = append(more.Addresses, netip.MustParseAddr("192.0.2.77"))
	c, _, log := reloadBetweenPackets(t, func(a *swapAdmitter) {
		a.swap(t, admission.Resolved{Device: more, KeyRef: "prod_key"})
	})
	c.recv(t)
	if log.contains(`"diagnosis":"admission_withdrawn"`) {
		t.Fatalf("log: %s", log.String())
	}
}

// reloadBetweenPackets opens a single-connect connection as leaf-01 under
// prod_key, answers one exchange, lets reload swap the admission index, and
// sends a second packet on the same connection. It returns the client for
// the test to judge the second packet's fate.
func reloadBetweenPackets(t *testing.T, reload func(*swapAdmitter)) (*client, *testServer, *syncBuffer) {
	t.Helper()
	return reloadFrom(t, admission.Resolved{Device: leaf01, KeyRef: "prod_key"}, reload)
}

// reloadFrom is reloadBetweenPackets with the connection admitted as first.
func reloadFrom(t *testing.T, first admission.Resolved, reload func(*swapAdmitter)) (*client, *testServer, *syncBuffer) {
	t.Helper()
	log := &syncBuffer{}
	adm := &swapAdmitter{}
	adm.swap(t, first)
	ts := newTestServerWith(t, log, memory.New(time.Now), nil, func(d *Deps) {
		d.Admission = adm
		base := d.Keys
		d.Keys = func(ref string) keyring.Set {
			if ref == "new_key" {
				return keyring.Set{Ref: "new_key", Versions: []keyring.Version{{Number: 1, Secret: secretref.Of([]byte("n1"))}}}
			}
			return base(ref)
		}
		d.Limits = slowBackoff()
	})
	c := dial(t, ts.addr, []byte("k2"))
	start := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode()
	c.send(t, wire.TypeAuthen, start, wire.FlagSingleConnect)
	c.recv(t)
	reload(adm)
	c.sid, c.seq = c.sid+1, 1
	c.send(t, wire.TypeAuthen, start, wire.FlagSingleConnect)
	return c, ts, log
}

// resetWithNoStrike asserts the open connection was reset at once with no
// reply, one record naming why (device_unknown, diag) and the device it was
// admitted as, and no strike: the source is not struck. Its next connection
// may meet a decline window, which each caller asserts.
func resetWithNoStrike(t *testing.T, c *client, ts *testServer, log *syncBuffer, diag string) {
	t.Helper()
	began := time.Now()
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := c.conn.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("want a reset with no reply, got %d bytes, %v", n, err)
	}
	if held := time.Since(began); held > 500*time.Millisecond {
		t.Fatalf("the connection was held %s before it was reset", held)
	}
	want := `"diagnosis":"` + diag + `"`
	if !waitFor(t, func() bool { return log.contains(want) }) {
		t.Fatalf("no %s record: %s", diag, log.String())
	}
	var found int
	for _, r := range log.records(t) {
		u, _ := r["unvalidated"].(map[string]any)
		if u == nil || u["diagnosis"] != diag {
			continue
		}
		found++
		dev, _ := r["device"].(map[string]any)
		if r["reason"] != "device_unknown" || dev == nil || dev["name"] != "leaf-01" || u["key_ref"] != "prod_key" {
			t.Fatalf("the record does not name the device it was admitted as and why: %v", r)
		}
	}
	if found != 1 {
		t.Fatalf("%d %s records, want one", found, diag)
	}
	if log.contains("p49_e2e") {
		t.Fatalf("a credential reached the log: %s", log.String())
	}
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("admission_closed")); n != 1 {
		t.Fatalf("admission_closed = %v", n)
	}
	for _, ev := range []string{"malformed_backoff", "key_miss_closed", "unadmitted_source"} {
		if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues(ev)); n != 0 {
			t.Fatalf("%s = %v: a reload's close is not the device's fault", ev, n)
		}
	}
	if n := testutil.ToFloat64(ts.metrics.Unvalidated.WithLabelValues(diag)); n != 1 {
		t.Fatalf("unvalidated{%s} = %v", diag, n)
	}
}

// I1: a reload that refuses the device an open connection was admitted as
// ends that connection at its next packet — a busy single-connect connection
// has no end, so "complete against the snapshot it began with" had no bound
// (spec §10).
func TestAReloadThatRefusesTheDeviceResetsItsOpenConnection(t *testing.T) {
	c, ts, log := reloadBetweenPackets(t, func(a *swapAdmitter) {
		a.swap(t, admission.Resolved{Device: leaf01, Refused: "matches no key group, so no key admits it (spec §10)",
			Refusal: admission.RefusedNoGroup})
	})
	resetWithNoStrike(t, c, ts, log, "admission_refused")
	// The reset opens a decline window, not a strike: the next connection is
	// refused at Accept, before it writes (spec §15 L31), and counted as
	// declined, not held.
	refusedAtAccept(t, &net.Dialer{}, ts.addr)
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("declined_refused")); n != 1 {
		t.Fatalf("declined_refused = %v", n)
	}
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("held_refused")); n != 0 {
		t.Fatalf("held_refused = %v: the reload's close struck the source", n)
	}
}

func TestAReloadThatRemovesTheDeviceResetsItsOpenConnection(t *testing.T) {
	c, ts, log := reloadBetweenPackets(t, func(a *swapAdmitter) {
		a.swap(t, admission.Resolved{Device: leaf02, KeyRef: "prod_key"})
	})
	resetWithNoStrike(t, c, ts, log, "unadmitted_source")
	refusedAtAccept(t, &net.Dialer{}, ts.addr)
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("declined_refused")); n != 1 {
		t.Fatalf("declined_refused = %v", n)
	}
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("held_refused")); n != 0 {
		t.Fatalf("held_refused = %v: the reload's close struck the source", n)
	}
}

func TestAReloadThatRenamesTheDeviceResetsItsOpenConnection(t *testing.T) {
	c, ts, log := reloadBetweenPackets(t, func(a *swapAdmitter) {
		renamed := leaf01
		renamed.Name = "leaf-01-new"
		a.swap(t, admission.Resolved{Device: renamed, KeyRef: "prod_key"})
	})
	resetWithNoStrike(t, c, ts, log, "admission_withdrawn")
	c = dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	if _, body := c.recv(t); body == nil {
		t.Fatal("a renamed device's next connection got no reply")
	}
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("declined_refused")); n != 0 {
		t.Fatalf("declined_refused = %v: a still-admitted device was declined", n)
	}
}

// Moving a device off a key_ref is the answer to a suspected key compromise,
// so the old key must stop at once: the open connection gets no reply under
// it, and a new connection under it is a key miss, while the new key works.
func TestAReloadThatRekeysTheDeviceStopsTheOldKeyAtOnce(t *testing.T) {
	c, ts, log := reloadBetweenPackets(t, func(a *swapAdmitter) {
		a.swap(t, admission.Resolved{Device: leaf01, KeyRef: "new_key"})
	})
	resetWithNoStrike(t, c, ts, log, "admission_withdrawn")

	old := dial(t, ts.addr, []byte("k2"))
	old.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice")}.Encode(), 0)
	closedAtOnce(t, old)
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"no_known_key_matches"`) }) {
		t.Fatalf("the old key was not a miss after the swap: %s", log.String())
	}
	if n := testutil.ToFloat64(ts.metrics.KeyValidations.WithLabelValues("prod_key", "2", "validated")); n != 1 {
		t.Fatalf("prod_key v2 validated %v times; only the exchange before the swap may", n)
	}
}

// The new key works on a fresh connection once the device is moved to it.
func TestAReloadThatRekeysTheDeviceAdmitsTheNewKey(t *testing.T) {
	c, ts, _ := reloadBetweenPackets(t, func(a *swapAdmitter) {
		a.swap(t, admission.Resolved{Device: leaf01, KeyRef: "new_key"})
	})
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	c.conn.Read(make([]byte, 1))
	fresh := dial(t, ts.addr, []byte("n1"))
	fresh.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice")}.Encode(), 0)
	fresh.recv(t)
}

// A reload that changes another device leaves an open connection alone.
func TestAReloadOfAnotherDeviceLeavesTheConnectionOpen(t *testing.T) {
	c, ts, _ := reloadBetweenPackets(t, func(a *swapAdmitter) {
		a.swap(t, admission.Resolved{Device: leaf01, KeyRef: "prod_key"},
			admission.Resolved{Device: leaf02, KeyRef: "new_key"})
	})
	c.recv(t)
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("admission_closed")); n != 0 {
		t.Fatalf("admission_closed = %v", n)
	}
}

// R1: a reload that changes a device's platform ends its open connection, as
// one that re-keys it does: its session would otherwise be denied
// blob_platform_mismatch at every command for the connection's life, and its
// records redacted under a platform no longer in force.
func TestAReloadThatChangesThePlatformResetsItsOpenConnection(t *testing.T) {
	c, ts, log := reloadBetweenPackets(t, func(a *swapAdmitter) {
		moved := leaf01
		moved.Platform = "cisco_iosxe"
		a.swap(t, admission.Resolved{Device: moved, KeyRef: "prod_key"})
	})
	resetWithNoStrike(t, c, ts, log, "admission_withdrawn")
}

// A policy `based_on:` edit moves a variant's wire platform under the same
// name; the open connection read its wire facts from the old base.
func TestAReloadThatChangesTheWirePlatformResetsItsOpenConnection(t *testing.T) {
	variant := leaf01
	variant.Platform = "my_eos"
	c, ts, log := reloadFrom(t, admission.Resolved{Device: variant, KeyRef: "prod_key", WirePlatform: "arista_eos"},
		func(a *swapAdmitter) {
			a.swap(t, admission.Resolved{Device: variant, KeyRef: "prod_key", WirePlatform: "cisco_iosxe"})
		})
	resetWithNoStrike(t, c, ts, log, "admission_withdrawn")
}

// variantRedactor is port49d's redactorFor over a swappable variant table: a
// platform's built-in patterns are its wire platform's, so a variant deleted
// from the policy resolves to the default patterns alone.
type variantRedactor struct {
	bases atomic.Pointer[map[string]string]
}

func (v *variantRedactor) redact(name string) []platform.Redaction {
	if base, ok := (*v.bases.Load())[name]; ok {
		name = base
	}
	return platform.Redactions(name)
}

// R1's redaction half: a connection admitted as a `based_on: juniper_junos`
// variant, whose variant a reload deletes (the device now plain Junos), never
// has an accounting record written under the deleted name, whose patterns
// would be the default's alone: a secret Junos's patterns hide never reaches
// the log.
func TestAnOpenConnectionsRecordsAreNeverRedactedUnderADeletedVariant(t *testing.T) {
	const before, after = "Hx7qPw2Ls9Vb", "Zr4mKt8Nc1Qy"
	vr := &variantRedactor{}
	vr.bases.Store(&map[string]string{"my_junos": "juniper_junos"})
	variant := leaf01
	variant.Platform = "my_junos"
	log := &syncBuffer{}
	adm := &swapAdmitter{}
	adm.swap(t, admission.Resolved{Device: variant, KeyRef: "prod_key", WirePlatform: "juniper_junos"})
	ts := newTestServerWith(t, log, memory.New(time.Now), nil, func(d *Deps) {
		d.Admission = adm
		d.Limits = slowBackoff()
	})
	ts.spool.WithRedactor(vr.redact)
	account := func(secret string) []byte {
		return wire.AcctRequest{Flags: wire.AcctFlagStop, AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 15,
			AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin, User: []byte("alice"),
			Port: []byte("vty0"), Args: [][]byte{[]byte("service=shell"), []byte("cmd=set system login user bob " +
				"encrypted-password " + secret + " <cr>")}}.Encode()
	}
	c := dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAcct, account(before), wire.FlagSingleConnect)
	c.recv(t)
	if !waitFor(t, func() bool { return log.contains(`"event":"account"`) }) {
		t.Fatalf("no account record: %s", log.String())
	}
	if log.contains(before) {
		t.Fatalf("the variant's own record was not redacted as Junos: %s", log.String())
	}
	vr.bases.Store(&map[string]string{})
	junos := leaf01
	junos.Platform = "juniper_junos"
	adm.swap(t, admission.Resolved{Device: junos, KeyRef: "prod_key"})
	c.sid, c.seq = c.sid+1, 1
	c.send(t, wire.TypeAcct, account(after), wire.FlagSingleConnect)
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := c.conn.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("want a reset with no reply, got %d bytes, %v", n, err)
	}
	ts.shutdown()
	if log.contains(after) {
		t.Fatalf("a secret Junos's patterns hide reached the log under the deleted variant: %s", log.String())
	}
}

// hangingStore answers Candidates only when its context ends: a store
// that does not answer.
type hangingStore struct{ store.Store }

func (hangingStore) Candidates(ctx context.Context, _ store.TokenKey) ([]store.Token, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// A packet's store work ends at packet_deadline: the device hears
// ERROR then, never silence until its own timeout (spec §13, decision 35;
// L35 measures what each image does with it).
func TestAPacketsStoreWorkEndsAtItsDeadline(t *testing.T) {
	log := &syncBuffer{}
	ts := newTestServerWith(t, log, hangingStore{memory.New(time.Now)}, nil, func(d *Deps) {
		d.PacketDeadline = 200 * time.Millisecond
	})
	c := dial(t, ts.addr, []byte("k2"))
	start := time.Now()
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: []byte("p49_e2e")}.Encode(), 0)
	_, body := c.recv(t)
	took := time.Since(start)
	reply, err := wire.DecodeAuthenReply(body)
	if err != nil || reply.Status != wire.AuthenStatusError || took < 200*time.Millisecond || took > time.Second {
		t.Fatalf("status %v (%v) after %v", reply.Status, err, took)
	}
}

// The packet deadline bounds store work and never the brute-force delay:
// a FAIL behind a 50ms deadline still takes the whole 300ms delay
// (pre-flight I1; authen.Session.fail).
func TestThePacketDeadlineNeverShortensTheFailureDelay(t *testing.T) {
	log := &syncBuffer{}
	st := memory.New(time.Now)
	ts := newTestServerWith(t, log, st, nil, func(d *Deps) {
		d.PacketDeadline = 50 * time.Millisecond
		lim := limits.New(limits.Config{PerNASConnections: 2, IdleTimeout: time.Second,
			MalformedBackoffBase: time.Millisecond, MalformedBackoffMax: time.Millisecond, MalformedWindow: time.Minute,
			AuthFailureDelayBase: 300 * time.Millisecond, AuthFailureDelayMax: 300 * time.Millisecond,
			AuthFailureWindow: time.Minute}, time.Now)
		d.Limits = lim
		d.Authen = authen.New(st, d.Log, lim, d.Metrics, time.Now, func() string { return "ctx1" },
			15*time.Minute, 2*time.Hour, time.Hour, time.Hour, token.NewTagWindow(token.TagKey([]byte("server_test"))))
	})
	c := dial(t, ts.addr, []byte("k2"))
	start := time.Now()
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: []byte("not-a-token")}.Encode(), 0)
	_, body := c.recv(t)
	took := time.Since(start)
	reply, err := wire.DecodeAuthenReply(body)
	if err != nil || reply.Status != wire.AuthenStatusFail || took < 300*time.Millisecond {
		t.Fatalf("status %v (%v) after %v: the packet deadline cut the failure delay", reply.Status, err, took)
	}
}

// slowStore answers the two reads a wrong token's redemption makes, each
// after d: a store slow but inside every deadline.
type slowStore struct {
	store.Store
	d time.Duration
}

func (s slowStore) GetReceipt(ctx context.Context, rk store.ReceiptKey) (store.Receipt, error) {
	time.Sleep(s.d)
	return s.Store.GetReceipt(ctx, rk)
}

func (s slowStore) Candidates(ctx context.Context, k store.TokenKey) ([]store.Token, error) {
	time.Sleep(s.d)
	return s.Store.Candidates(ctx, k)
}

// The failure delay counts from the packet's arrival, so the store's time
// is inside it, not added to it: a wrong token behind a store spending
// 250ms and a 300ms delay is answered FAIL at about 300ms, never 550ms
// (re-check N1). That keeps a FAIL's worst case at max(packet_deadline,
// delay), inside Junos's 3s (L13), and the throttle whole.
func TestAFailArrivesAtItsDelay(t *testing.T) {
	log := &syncBuffer{}
	st := slowStore{Store: memory.New(time.Now), d: 125 * time.Millisecond}
	ts := newTestServerWith(t, log, st, nil, func(d *Deps) {
		d.PacketDeadline = 2 * time.Second
		lim := limits.New(limits.Config{PerNASConnections: 2, IdleTimeout: time.Second,
			MalformedBackoffBase: time.Millisecond, MalformedBackoffMax: time.Millisecond, MalformedWindow: time.Minute,
			AuthFailureDelayBase: 300 * time.Millisecond, AuthFailureDelayMax: 300 * time.Millisecond,
			AuthFailureWindow: time.Minute}, time.Now)
		d.Limits = lim
		d.Authen = authen.New(st, d.Log, lim, d.Metrics, time.Now, func() string { return "ctx1" },
			15*time.Minute, 2*time.Hour, time.Hour, time.Hour, token.NewTagWindow(token.TagKey([]byte("server_test"))))
	})
	c := dial(t, ts.addr, []byte("k2"))
	start := time.Now()
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: []byte("not-a-token")}.Encode(), 0)
	_, body := c.recv(t)
	took := time.Since(start)
	reply, err := wire.DecodeAuthenReply(body)
	if err != nil || reply.Status != wire.AuthenStatusFail || took < 300*time.Millisecond || took >= 500*time.Millisecond {
		t.Fatalf("status %v (%v) after %v: want FAIL at the 300ms delay, the 250ms of store inside it", reply.Status,
			err, took)
	}
}

// keysOf is a Deps.Keys over m.
func keysOf(m map[string]keyring.Set) func(string) keyring.Set {
	return func(ref string) keyring.Set { return m[ref] }
}

// expectShed dials addr and asserts the connection is reset at Accept. On
// loopback the server's accept-then-reset can reach the client before connect()
// returns, so the dial itself may fail with ECONNRESET: that is the shed, as
// in refusedAtAccept. Any other dial error fails, and a connection that is
// served (no reset on the dial or the read) fails.
func expectShed(t *testing.T, addr, what string) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		if !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("%s: dial: %v, want a reset at Accept", what, err)
		}
		return
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("%s: %v, want a reset at Accept", what, err)
	}
}

// roomyLimits is newTestServerWith's limiter with room for sixteen
// connections per source, so a test of the global cap meets the global cap.
func roomyLimits() *limits.Limiter {
	return limits.New(limits.Config{PerNASConnections: 16, IdleTimeout: time.Second,
		MalformedBackoffBase: time.Millisecond, MalformedBackoffMax: time.Millisecond, MalformedWindow: time.Minute,
		AuthFailureDelayBase: time.Millisecond, AuthFailureDelayMax: time.Millisecond, AuthFailureWindow: time.Minute}, time.Now)
}

// At the cap a new connection is accepted and reset at once, counted and
// said while the slot is still held, and the device can take its next server;
// when the slot frees, the next connection is served (design §11; decision
// 53 ruling 8; Review Focus 5).
func TestTheGlobalCapShedsAndSaysSo(t *testing.T) {
	var log syncBuffer
	var said syncBuffer
	defer func(w io.Writer) { stdlog.SetOutput(w) }(stdlog.Writer())
	stdlog.SetOutput(&said)
	st := memory.New(time.Now)
	slots := NewSlots(1, time.Now)
	ts := newTestServerWith(t, &log, st, nil, func(d *Deps) { d.Slots = slots })
	if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "e2e", Secret: []byte("p49_e2e"), Kind: store.KindLogin, Principal: "user:alice@example.com",
			ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	first := dial(t, ts.addr, []byte("k2")) // holds the one slot, idle
	if !waitFor(t, func() bool { return slots.InUse() == 1 }) {
		t.Fatal("the first connection holds no slot")
	}
	expectShed(t, ts.addr, "the second connection at the cap")
	// Counted and said while the first still holds its slot.
	if got := testutil.ToFloat64(ts.metrics.ConnectionsShed.WithLabelValues("global_cap")); got != 1 {
		t.Fatalf("port49_connections_shed_total{reason=global_cap} = %v with the cap held", got)
	}
	if !strings.Contains(said.String(), "shedding: all 1 TACACS+ connection slots") {
		t.Fatalf("no shedding line with the cap held:\n%s", said.String())
	}
	first.conn.Close()
	if !waitFor(t, func() bool { return slots.InUse() == 0 }) {
		t.Fatal("the slot was not freed")
	}
	third := dial(t, ts.addr, []byte("k2"))
	third.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	third.recv(t) // served once the slot frees
}

// A listener waiting in Accept holds no slot: with nothing connected the
// pool is empty, and with two listeners sharing a pool of 2, one connection
// on each is served and a third is shed (I1).
func TestIdleListenersHoldNoSlot(t *testing.T) {
	var log syncBuffer
	slots := NewSlots(2, time.Now)
	var deps Deps
	ts := newTestServerWith(t, &log, memory.New(time.Now), nil, func(d *Deps) {
		d.Slots = slots
		d.Limits = roomyLimits() // per-source room for three, so the global cap binds
		deps = *d
	})
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() { defer close(served); Serve(ctx, ln2, deps) }()
	t.Cleanup(func() { cancel(); <-served })
	time.Sleep(50 * time.Millisecond) // both loops are in Accept
	if n := slots.InUse(); n != 0 {
		t.Fatalf("%d slots held with nothing connected", n)
	}
	a := dial(t, ts.addr, []byte("k2"))
	b := dial(t, ln2.Addr().String(), []byte("k2"))
	if !waitFor(t, func() bool { return slots.InUse() == 2 }) {
		t.Fatalf("one connection on each listener: %d slots in use", slots.InUse())
	}
	expectShed(t, ln2.Addr().String(), "the third connection")
	a.conn.Close()
	b.conn.Close()
}

// No refusal at Accept leaves a slot behind: the per-source refusals take
// none, and a shed frees its per-source slot (Review Focus 5).
func TestEveryRefusalAtAcceptReleasesItsSlots(t *testing.T) {
	// refused_cap: a third connection past the per-NAS cap of 2.
	t.Run("refused_cap", func(t *testing.T) {
		var log syncBuffer
		slots := NewSlots(4, time.Now)
		ts := newTestServerWith(t, &log, memory.New(time.Now), nil, func(d *Deps) { d.Slots = slots })
		c1, c2 := dial(t, ts.addr, []byte("k2")), dial(t, ts.addr, []byte("k2"))
		c3 := dial(t, ts.addr, []byte("k2"))
		c3.conn.SetReadDeadline(time.Now().Add(time.Second))
		c3.conn.Read(make([]byte, 1))
		c1.conn.Close()
		c2.conn.Close()
		if !waitFor(t, func() bool { return slots.InUse() == 0 }) {
			t.Fatalf("%d slots still held with every connection closed", slots.InUse())
		}
		if got := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("refused_cap")); got < 1 {
			t.Fatalf("the refused_cap path was not taken: %v", got)
		}
	})
	// held_refused: a key miss, then a connection inside its backoff.
	t.Run("held_refused", func(t *testing.T) {
		var log syncBuffer
		slots := NewSlots(4, time.Now)
		ts := newTestServerWith(t, &log, memory.New(time.Now), nil, func(d *Deps) {
			d.Slots = slots
			d.Limits = slowBackoff()
		})
		miss := dial(t, ts.addr, []byte("not-the-key"))
		miss.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
			Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
		closedAtOnce(t, miss)
		refusedAtAccept(t, &net.Dialer{}, ts.addr)
		if !waitFor(t, func() bool { return slots.InUse() == 0 }) {
			t.Fatalf("%d slots still held with every connection closed", slots.InUse())
		}
		if got := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("held_refused")); got < 1 {
			t.Fatalf("the held_refused path was not taken: %v", got)
		}
	})
	// declined_refused: a source declined by admission, then refused at Accept.
	t.Run("declined_refused", func(t *testing.T) {
		var log syncBuffer
		slots := NewSlots(4, time.Now)
		refused := admission.Resolved{Device: leaf01, Refused: "matches no key group, so no key admits it (spec §10)",
			Refusal: admission.RefusedNoGroup}
		adm := &reloadAfterLookup{}
		adm.swap(t, refused)
		ts := newTestServerWith(t, &log, memory.New(time.Now), nil, func(d *Deps) {
			d.Admission = adm
			d.Limits = slowBackoff()
			d.Slots = slots
		})
		c := dial(t, ts.addr, []byte("k2"))
		c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
			Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
		closedAtOnce(t, c)
		ts.slotFree(t)
		refusedAtAccept(t, &net.Dialer{}, ts.addr)
		if !waitFor(t, func() bool { return slots.InUse() == 0 }) {
			t.Fatalf("%d slots still held with every connection closed", slots.InUse())
		}
		if got := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("declined_refused")); got < 1 {
			t.Fatalf("the declined_refused path was not taken: %v", got)
		}
	})
	// A shed frees its per-source slot: with one holder, a per-NAS slot is
	// free at once, and the holder closing frees the global one.
	t.Run("shed", func(t *testing.T) {
		var log syncBuffer
		slots := NewSlots(1, time.Now)
		ts := newTestServerWith(t, &log, memory.New(time.Now), nil, func(d *Deps) {
			d.Slots = slots
			d.Limits = limits.New(limits.Config{PerNASConnections: 2, IdleTimeout: time.Minute,
				MalformedBackoffBase: time.Millisecond, MalformedBackoffMax: time.Millisecond, MalformedWindow: time.Minute,
				AuthFailureDelayBase: time.Millisecond, AuthFailureDelayMax: time.Millisecond, AuthFailureWindow: time.Minute}, time.Now)
			d.IdleTimeout = time.Minute // the holder is still there when the shed is checked
		})
		holder := dial(t, ts.addr, []byte("k2"))
		if !waitFor(t, func() bool { return slots.InUse() == 1 }) {
			t.Fatal("the holder holds no slot")
		}
		expectShed(t, ts.addr, "the shed connection")
		// The per-NAS cap is 2 and the holder has one: the shed gave its slot
		// back before it was reset, so the other is free now, not at some
		// idle timeout.
		release, ok := ts.limits.Acquire(netip.MustParseAddr("127.0.0.1"))
		if !ok {
			t.Fatal("a shed connection kept its per-source slot")
		}
		release()
		holder.conn.Close()
		if !waitFor(t, func() bool { return slots.InUse() == 0 }) {
			t.Fatal("the holder's slot was not freed")
		}
	})
}

// Many connections dialled at once past a small cap: each is served or reset
// at Accept, the shed counter equals the resets the clients saw, and when
// every connection is closed no slot is left held (run under -race).
func TestTheGlobalCapUnderAFloodLeavesNoSlotHeld(t *testing.T) {
	var log syncBuffer
	defer func(w io.Writer) { stdlog.SetOutput(w) }(stdlog.Writer())
	stdlog.SetOutput(io.Discard)
	const cap, dials = 4, 200
	slots := NewSlots(cap, time.Now)
	ts := newTestServerWith(t, &log, memory.New(time.Now), nil, func(d *Deps) {
		d.Slots = slots
		d.Limits = limits.New(limits.Config{PerNASConnections: 1000, IdleTimeout: 300 * time.Millisecond,
			MalformedBackoffBase: time.Millisecond, MalformedBackoffMax: time.Millisecond, MalformedWindow: time.Minute,
			AuthFailureDelayBase: time.Millisecond, AuthFailureDelayMax: time.Millisecond, AuthFailureWindow: time.Minute}, time.Now)
		d.IdleTimeout = 300 * time.Millisecond
	})
	var resets, over atomic.Int64
	var wg sync.WaitGroup
	for range dials {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("tcp", ts.addr)
			if err != nil {
				if errors.Is(err, syscall.ECONNRESET) {
					resets.Add(1)
				}
				return
			}
			defer c.Close()
			if slots.InUse() > cap {
				over.Add(1)
			}
			c.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err := c.Read(make([]byte, 1)); errors.Is(err, syscall.ECONNRESET) {
				resets.Add(1)
			}
		}()
	}
	wg.Wait()
	if over.Load() != 0 {
		t.Fatalf("the pool held more than its cap %d times", over.Load())
	}
	if !waitFor(t, func() bool { return slots.InUse() == 0 }) {
		t.Fatalf("%d slots still held with every connection closed", slots.InUse())
	}
	shed := testutil.ToFloat64(ts.metrics.ConnectionsShed.WithLabelValues("global_cap"))
	if shed == 0 || int64(shed) != resets.Load() {
		t.Fatalf("shed counter %v, resets the clients saw %d", shed, resets.Load())
	}
}
