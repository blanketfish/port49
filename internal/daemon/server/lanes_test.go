package server

import (
	"context"
	"errors"
	"io"
	stdlog "log"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/daemon/authen"
	"github.com/blanketfish/port49/internal/daemon/author"
	"github.com/blanketfish/port49/internal/daemon/limits"
	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/memory"
	"github.com/blanketfish/port49/internal/tacacs/wire"
	"github.com/blanketfish/port49/internal/testpki"
	"github.com/blanketfish/port49/internal/token"
)

// laneDelay is the failure delay the tests in this file run under. It is
// longer than the test server's 1s idle timeout on purpose: a connection with
// a reply still owed is not idle (audit F2-1).
const laneDelay = 1500 * time.Millisecond

// newLaneServer is a test server whose every authentication failure waits
// laneDelay, with alice holding the login token p49_e2e.
func newLaneServer(t *testing.T, log *syncBuffer, st store.Store, authz author.Authorizer) *testServer {
	t.Helper()
	return newLaneServerWith(t, log, st, authz, laneDelay, time.Millisecond, nil)
}

// newLaneServerWith is newLaneServer with its failure delay and malformed
// backoff given, and its listener wrapped by wrap (nil wraps nothing).
func newLaneServerWith(t *testing.T, log *syncBuffer, st store.Store, authz author.Authorizer,
	delay, backoff time.Duration, wrap func(net.Listener) net.Listener) *testServer {
	t.Helper()
	if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "e2e", Secret: []byte("p49_e2e"), Kind: store.KindLogin, Principal: "user:alice@example.com",
			ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	return newTestServerOn(t, log, st, authz, func(d *Deps) {
		lim := limits.New(limits.Config{PerNASConnections: 2, IdleTimeout: time.Second,
			MalformedBackoffBase: backoff, MalformedBackoffMax: backoff, MalformedWindow: time.Minute,
			AuthFailureDelayBase: delay, AuthFailureDelayMax: delay, AuthFailureWindow: time.Minute}, time.Now)
		var ids atomic.Int64
		d.Limits = lim
		d.Authen = authen.New(st, d.Log, lim, d.Metrics, time.Now,
			func() string { return "ctx" + strconv.FormatInt(ids.Add(1), 10) },
			15*time.Minute, 2*time.Hour, time.Hour, time.Hour, token.NewTagWindow(token.TagKey([]byte("server_test"))))
	}, wrap)
}

// papStart sends one PAP login START as a new session sid on c, asking for
// single-connection.
func papStart(t *testing.T, c *client, sid uint32, user, secret string) {
	t.Helper()
	c.sid, c.seq = sid, 1
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte(user), Port: []byte("vty" + strconv.Itoa(int(sid%10))),
		Data: []byte(secret)}.Encode(), wire.FlagSingleConnect)
}

// authorize sends one authorization request for alice as session sid on c.
func authorize(t *testing.T, c *client, sid uint32, args ...string) {
	t.Helper()
	c.sid, c.seq = sid, 1
	var a [][]byte
	for _, s := range args {
		a = append(a, []byte(s))
	}
	c.send(t, wire.TypeAuthor, wire.AuthorRequest{AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 1,
		AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"),
		Args: a}.Encode(), wire.FlagSingleConnect)
}

// recvWithin reads one reply, failing the test if none arrives by within.
func recvWithin(t *testing.T, c *client, within time.Duration) (wire.Header, []byte) {
	t.Helper()
	c.conn.SetReadDeadline(time.Now().Add(within))
	hb := make([]byte, wire.HeaderLen)
	if _, err := io.ReadFull(c.conn, hb); err != nil {
		t.Fatalf("no reply within %v: %v", within, err)
	}
	h, _ := wire.DecodeHeader(hb)
	body := make([]byte, h.Length)
	if _, err := io.ReadFull(c.conn, body); err != nil {
		t.Fatalf("reply body: %v", err)
	}
	return h, wire.Obfuscate(h, c.key, body)
}

// The audit F2-1 scenario: on one single-connection connection, a session
// that fails waits out its failure delay, and a session behind it is answered
// at once, not after it. Before the fix the read loop slept the delay and the
// second session's PASS came after the first's FAIL.
func TestAFailingSessionDoesNotHoldAnotherOnASingleConnection(t *testing.T) {
	log := &syncBuffer{}
	st := memory.New(time.Now)
	ts := newLaneServer(t, log, st, nil)
	c := dial(t, ts.addr, []byte("k2"))

	start := time.Now()
	papStart(t, c, 1, "mallory", "p49_wrong")
	papStart(t, c, 2, "alice", "p49_e2e")

	h, body := recvWithin(t, c, 5*time.Second)
	first := time.Since(start)
	r, err := wire.DecodeAuthenReply(body)
	if err != nil || h.SessionID != 2 || r.Status != wire.AuthenStatusPass || first >= laneDelay/2 {
		t.Fatalf("first reply: session %d status %d (%v) after %v; want session 2's PASS well before the %v delay",
			h.SessionID, r.Status, err, first, laneDelay)
	}

	h, body = recvWithin(t, c, 5*time.Second)
	second := time.Since(start)
	r, err = wire.DecodeAuthenReply(body)
	if err != nil || h.SessionID != 1 || r.Status != wire.AuthenStatusFail || second < laneDelay-100*time.Millisecond {
		t.Fatalf("second reply: session %d status %d (%v) after %v; want session 1's FAIL at its %v delay",
			h.SessionID, r.Status, err, second, laneDelay)
	}

	// The delay outlasted the 1s idle timeout, and the connection was not
	// idle meanwhile: it owed a reply. It is still open and serving.
	if got := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("idle_closed")); got != 0 {
		t.Fatalf("idle_closed %v: a connection owing a reply was closed as idle", got)
	}
	if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "bob"},
		store.Token{ID: "third", Secret: []byte("p49_third"), Kind: store.KindLogin, Principal: "user:bob@example.com",
			ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	papStart(t, c, 3, "bob", "p49_third")
	if h, body := recvWithin(t, c, 5*time.Second); func() bool {
		r, _ := wire.DecodeAuthenReply(body)
		return h.SessionID != 3 || r.Status != wire.AuthenStatusPass
	}() {
		t.Fatal("the connection must still serve a session after the delayed FAIL")
	}
}

// Between a protocol error's drop and its close (the malformed backoff), a
// session finishing its failure delay writes nothing: over TLS the
// connection is by then the bare TCP beneath it, and a reply would go out
// in cleartext.
func TestNoReplyIsWrittenOnceAProtocolErrorDropsTheConnection(t *testing.T) {
	log := &syncBuffer{}
	ts := newLaneServerWith(t, log, memory.New(time.Now), nil, 300*time.Millisecond, time.Second, nil)
	c := dial(t, ts.addr, []byte("k2"))

	papStart(t, c, 1, "mallory", "p49_wrong") // FAIL due at 300ms, inside the 1s backoff
	inDelay(t, ts, 1)
	c.sid, c.seq = 2, 3 // a CONTINUE for a session this connection never started
	c.send(t, wire.TypeAuthen, wire.AuthenContinue{UserMsg: []byte("alice")}.Encode(), 0)

	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.conn.Read(make([]byte, 1))
	if n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read %d bytes, err %v: want the connection closed with nothing written after the drop", n, err)
	}
}

// smallSendBuffer shrinks every accepted socket's send buffer, so a peer that
// stops reading stalls port49d's writes after a few kilobytes.
type smallSendBuffer struct{ net.Listener }

func (l smallSendBuffer) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetWriteBuffer(4096)
	}
	return c, err
}

// A device that stops reading (a wedged control plane) while many sessions
// owe it replies costs one write timeout, not one per lane: the first
// write that fails drops the connection, so the lanes behind it write
// nothing more (a partial frame is already on the wire) and the close does
// not wait for them. Before, each of up to maxInFlight lanes took a fresh
// idle_timeout to fail its own write, and the per-NAS slot was held for all
// of them.
func TestAStalledPeerIsDroppedAfterOneWriteTimeout(t *testing.T) {
	log := &syncBuffer{}
	ts := newLaneServerWith(t, log, memory.New(time.Now), nil, laneDelay, time.Millisecond,
		func(l net.Listener) net.Listener { return smallSendBuffer{l} })
	open := ts.metrics.Connections.WithLabelValues("open")
	conn, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.(*net.TCPConn).SetReadBuffer(4096)

	// Authorizations with no login behind them: each is answered FAIL at
	// once, and none is ever read.
	body := wire.AuthorRequest{AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 1, AuthenType: wire.AuthenTypeASCII,
		Service: wire.AuthenServiceLogin, User: []byte("nobody"), Port: []byte("vty0"),
		Args: [][]byte{[]byte("service=shell"), []byte("cmd=")}}.Encode()
	start := time.Now()
	go func() {
		for i := range 5000 {
			h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthor, SeqNo: 1, Flags: wire.FlagSingleConnect,
				SessionID: uint32(1 + i), Length: uint32(len(body))}
			if _, err := conn.Write(append(h.Encode(), wire.Obfuscate(h, []byte("k2"), body)...)); err != nil {
				return // the server closed: the test reads that from the gauge
			}
		}
	}()
	if !waitFor(t, func() bool { return testutil.ToFloat64(open) == 1 }) {
		t.Fatal("the connection was never counted open")
	}
	// The server's write deadline is the test server's 1s idle_timeout.
	deadline := start.Add(4 * time.Second)
	for testutil.ToFloat64(open) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("still open %v after the peer stopped reading: each lane waited out its own write timeout",
				time.Since(start))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The failure delay counts from when the packet was read, not from when its
// lane began it. Two STARTs on one session_id, back to back, are the one shape
// in which a packet waits in its own session's lane (no device was seen to
// send it; port49 starts the session over): the second is read at once and
// begun when the first's FAIL is out, its delay by then already spent. Counted
// from the lane's start it would come a whole delay later.
func TestTheFailureDelayCountsFromTheRead(t *testing.T) {
	log := &syncBuffer{}
	ts := newLaneServer(t, log, memory.New(time.Now), nil)
	c := dial(t, ts.addr, []byte("k2"))

	start := time.Now()
	papStart(t, c, 7, "mallory", "p49_wrong")
	papStart(t, c, 7, "mallory", "p49_wrong_again")
	for i := range 2 {
		_, body := recvWithin(t, c, 5*time.Second)
		at := time.Since(start)
		if r, _ := wire.DecodeAuthenReply(body); r.Status != wire.AuthenStatusFail ||
			at < laneDelay-100*time.Millisecond || at > laneDelay+500*time.Millisecond {
			t.Fatalf("FAIL %d (status %d) after %v: want both at the one %v delay counted from their read",
				i+1, r.Status, at, laneDelay)
		}
	}
}

// inDelay waits until n sessions have entered their failure delay, so a
// test's next packet is known to arrive while they wait in it.
func inDelay(t *testing.T, ts *testServer, n float64) {
	t.Helper()
	if !waitFor(t, func() bool { return testutil.ToFloat64(ts.metrics.AuthFailures) >= n }) {
		t.Fatalf("fewer than %v sessions entered their failure delay", n)
	}
}

// Over TLS, a protocol error drops the connection by swapping c to the TCP
// connection beneath, under wmu, while another session's lane is in its
// failure delay. When that delay ends nothing is written: a reply there would
// be cleartext under the TLS stream, which the client reads as a bad record.
// The client sees the connection end, with no record at all.
func TestOverTLSADroppedConnectionGetsNoCleartextReply(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, func(d *Deps, _ *tlsFixture) {
		lim := limits.New(limits.Config{PerNASConnections: 2, IdleTimeout: time.Second,
			MalformedBackoffBase: time.Second, MalformedBackoffMax: time.Second, MalformedWindow: time.Minute,
			AuthFailureDelayBase: 300 * time.Millisecond, AuthFailureDelayMax: 300 * time.Millisecond,
			AuthFailureWindow: time.Minute}, time.Now)
		d.Limits = lim
		d.Authen = authen.New(memory.New(time.Now), d.Log, lim, d.Metrics, time.Now, func() string { return "ctx1" },
			15*time.Minute, 2*time.Hour, time.Hour, time.Hour, token.NewTagWindow(token.TagKey([]byte("server_test"))))
	})
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	c, err := f.dialTLS(t, &cert, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.sid, c.seq = 1, 1
	if err := c.send(wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("mallory"), Data: []byte("p49_wrong")}.Encode(),
		wire.FlagUnencrypted|wire.FlagSingleConnect); err != nil {
		t.Fatal(err)
	}
	inDelay(t, f.ts, 1) // its FAIL is due at 300ms, inside the 1s backoff
	c.sid, c.seq = 2, 3 // a CONTINUE for a session this connection never started
	if err := c.send(wire.TypeAuthen, wire.AuthenContinue{UserMsg: []byte("alice")}.Encode(), wire.FlagUnencrypted); err != nil {
		t.Fatal(err)
	}

	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = c.conn.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("read error %v: want the connection ended with no record after the drop", err)
	}
	assertProtocolErrorRecorded(t, log)
}

// login runs a passing PAP login for alice as session sid, so authorizations
// on vty0 find a context.
func login(t *testing.T, c *client, sid uint32) {
	t.Helper()
	c.sid, c.seq = sid, 1
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: []byte("p49_e2e")}.Encode(),
		wire.FlagSingleConnect)
	if _, body := recvWithin(t, c, 5*time.Second); func() bool {
		r, _ := wire.DecodeAuthenReply(body)
		return r.Status != wire.AuthenStatusPass
	}() {
		t.Fatal("the login should have passed")
	}
}

// The packets of one session are answered in the order they came, each
// against the state the one before it left: an ASCII login's START and both
// CONTINUEs, written back to back before any reply is read. Run out of order
// a CONTINUE would find no session, or the wrong phase; run at once, the
// three would share the session's state, which -race reports.
func TestPacketsOfOneSessionStayInOrder(t *testing.T) {
	log := &syncBuffer{}
	ts := newLaneServer(t, log, memory.New(time.Now), nil)
	c := dial(t, ts.addr, []byte("k2"))

	c.sid, c.seq = 20, 1
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypeASCII,
		Service: wire.AuthenServiceLogin, Port: []byte("vty0")}.Encode(), wire.FlagSingleConnect)
	c.send(t, wire.TypeAuthen, wire.AuthenContinue{UserMsg: []byte("alice")}.Encode(), 0)
	c.send(t, wire.TypeAuthen, wire.AuthenContinue{UserMsg: []byte("p49_e2e")}.Encode(), 0)

	for i, want := range []uint8{wire.AuthenStatusGetUser, wire.AuthenStatusGetPass, wire.AuthenStatusPass} {
		h, body := recvWithin(t, c, 5*time.Second)
		r, err := wire.DecodeAuthenReply(body)
		if err != nil || h.SessionID != 20 || h.SeqNo != uint8(2*i+2) || r.Status != want {
			t.Fatalf("round %d: session %d seq %d status %d (%v); want seq %d status %d",
				i+1, h.SessionID, h.SeqNo, r.Status, err, 2*i+2, want)
		}
	}
}

// Many sessions answered at once on one connection: every reply arrives
// whole, once, for the session that asked, at seq_no 2. A reply written in
// two pieces without the write lock would interleave with another.
func TestConcurrentRepliesAreNeverInterleaved(t *testing.T) {
	log := &syncBuffer{}
	ts := newLaneServer(t, log, memory.New(time.Now), nil)
	c := dial(t, ts.addr, []byte("k2"))
	login(t, c, 1)

	const n = maxInFlight
	for i := range n {
		authorize(t, c, uint32(100+i), "service=shell", "cmd=")
	}
	seen := map[uint32]bool{}
	for range n {
		h, body := recvWithin(t, c, 5*time.Second)
		r, err := wire.DecodeAuthorResponse(body)
		if err != nil || r.Status != wire.AuthorStatusPassAdd || h.SeqNo != 2 || h.SessionID < 100 ||
			h.SessionID >= 100+n || seen[h.SessionID] {
			t.Fatalf("reply for session %d seq %d status %d (%v): want one whole PASS_ADD per session",
				h.SessionID, h.SeqNo, r.Status, err)
		}
		seen[h.SessionID] = true
	}
}

// Past maxInFlight packets in flight, the connection stops reading: the next
// packet waits in the socket until a slot frees, and is then answered. The
// device sees that packet's reply late, never a close. The ones inside the
// bound run at once: maxInFlight FAILs arrive together at one delay, not one
// after another.
func TestTheInFlightBoundHoldsThePacketPastIt(t *testing.T) {
	log := &syncBuffer{}
	ts := newLaneServer(t, log, memory.New(time.Now), nil)
	c := dial(t, ts.addr, []byte("k2"))

	start := time.Now()
	for i := range maxInFlight {
		papStart(t, c, uint32(1+i), "mallory", "p49_wrong")
	}
	papStart(t, c, 999, "alice", "p49_e2e")

	fails := 0
	for range maxInFlight + 1 {
		h, body := recvWithin(t, c, 5*time.Second)
		at := time.Since(start)
		r, _ := wire.DecodeAuthenReply(body)
		switch {
		case h.SessionID == 999:
			if r.Status != wire.AuthenStatusPass || fails == 0 || at < laneDelay-100*time.Millisecond {
				t.Fatalf("the packet past the bound: status %d after %v with %d FAILs before it; want PASS after a slot freed",
					r.Status, at, fails)
			}
		case r.Status == wire.AuthenStatusFail:
			fails++
			if at > 2*laneDelay {
				t.Fatalf("FAIL %d after %v: the sessions inside the bound must run together", fails, at)
			}
		default:
			t.Fatalf("unexpected reply: session %d status %d", h.SessionID, r.Status)
		}
	}
	if fails != maxInFlight {
		t.Fatalf("%d FAILs, want %d", fails, maxInFlight)
	}
}

// A protocol error on one session closes the connection at once, though
// another session is in its failure delay, and that session's FAIL is never
// written after the close. The connection's goroutines still all end: the
// delayed session's at its delay, as the delay is cancelled only by shutdown.
func TestAProtocolErrorClosesAtOnceDespiteADelayedSession(t *testing.T) {
	log := &syncBuffer{}
	ts := newLaneServer(t, log, memory.New(time.Now), nil)
	c := dial(t, ts.addr, []byte("k2"))

	papStart(t, c, 1, "mallory", "p49_wrong")
	inDelay(t, ts, 1)
	start := time.Now()
	c.sid, c.seq = 2, 3 // a CONTINUE for a session this connection never started
	c.send(t, wire.TypeAuthen, wire.AuthenContinue{UserMsg: []byte("alice")}.Encode(), 0)

	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.conn.Read(make([]byte, 1))
	took := time.Since(start)
	if n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) || took >= laneDelay/2 {
		t.Fatalf("read %d bytes, err %v after %v: want the connection closed at once with no reply", n, err, took)
	}
	assertProtocolErrorRecorded(t, log)
	open := ts.metrics.Connections.WithLabelValues("open")
	if !waitFor(t, func() bool { return testutil.ToFloat64(open) == 0 }) {
		t.Fatal("the connection's goroutines did not end after its delayed session")
	}
}

// A device that hangs up while sessions are in their failure delay leaves
// nothing running once the connection is counted closed: serve waits for
// every session's work before it returns.
func TestAClosedConnectionLeavesNoSessionWorkRunning(t *testing.T) {
	log := &syncBuffer{}
	ts := newLaneServer(t, log, memory.New(time.Now), nil)
	open := ts.metrics.Connections.WithLabelValues("open")
	// The server's own goroutines start asynchronously: let them settle
	// before the count the test compares against.
	before := runtime.NumGoroutine()
	for range 20 {
		time.Sleep(10 * time.Millisecond)
		before = max(before, runtime.NumGoroutine())
	}

	c := dial(t, ts.addr, []byte("k2"))
	for i := range 4 {
		papStart(t, c, uint32(1+i), "mallory", "p49_wrong")
	}
	if !waitFor(t, func() bool { return testutil.ToFloat64(open) == 1 }) {
		t.Fatal("the connection was never counted open")
	}
	time.Sleep(100 * time.Millisecond) // every START read and in its delay
	c.conn.Close()

	deadline := time.Now().Add(laneDelay + 2*time.Second)
	for testutil.ToFloat64(open) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the connection was never counted closed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Counted closed: the sessions' goroutines are gone now, not at the end
	// of their delays. A short grace covers the shutdown watcher's exit.
	settled := false
	for range 20 {
		if runtime.NumGoroutine() <= before {
			settled = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !settled {
		t.Fatalf("%d goroutines after the close, %d before: session work outlived its connection",
			runtime.NumGoroutine(), before)
	}
}

// A shutdown during a session's failure delay ends the delay, as it did
// before, and Serve returns promptly.
func TestShutdownEndsADelayedSessionOnASingleConnection(t *testing.T) {
	log := &syncBuffer{}
	ts := newLaneServer(t, log, memory.New(time.Now), nil)
	c := dial(t, ts.addr, []byte("k2"))
	papStart(t, c, 1, "mallory", "p49_wrong")
	papStart(t, c, 2, "mallory", "p49_wrong")
	time.Sleep(100 * time.Millisecond)

	start := time.Now()
	ts.shutdown()
	if took := time.Since(start); took >= laneDelay/2 {
		t.Fatalf("shutdown took %v: the failure delay must end at shutdown", took)
	}
}

// A panic in one session's work on a single-connection connection is
// recovered as a connection's is: counted, logged with a stack, the
// connection closed, and the daemon serving.
func TestAPanicInASessionOnASingleConnectionDoesNotStopTheDaemon(t *testing.T) {
	panicLog := &syncBuffer{}
	stdlog.SetOutput(panicLog)
	t.Cleanup(func() { stdlog.SetOutput(os.Stderr) })

	log := &syncBuffer{}
	st := memory.New(time.Now)
	ts := newLaneServer(t, log, st, panicAuthorizer{})
	c := dial(t, ts.addr, []byte("k2"))
	login(t, c, 1)
	authorize(t, c, 2, "service=shell", "cmd=")

	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a panicking session's connection must be closed, not answered")
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the connection must be closed, not left open: %v", err)
	}
	if !waitFor(t, func() bool { return testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("panic")) >= 1 }) {
		t.Fatal("connection_events_total{panic} was not incremented")
	}
	if !panicLog.contains("goroutine") || panicLog.contains("p49_e2e") {
		t.Fatalf("the panic log must carry a stack and no credential: %q", panicLog.String())
	}
	c.conn.Close()

	if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "bob"},
		store.Token{ID: "after", Secret: []byte("p49_after"), Kind: store.KindLogin, Principal: "user:bob@example.com",
			ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	ts.slotFree(t)
	c = dial(t, ts.addr, []byte("k2"))
	papStart(t, c, 3, "bob", "p49_after")
	if _, body := recvWithin(t, c, 5*time.Second); func() bool {
		r, _ := wire.DecodeAuthenReply(body)
		return r.Status != wire.AuthenStatusPass
	}() {
		t.Fatal("the daemon must keep serving after a session panicked")
	}
}
