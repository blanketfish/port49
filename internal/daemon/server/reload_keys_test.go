package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/keyring"
	"github.com/rhwendt/port49/internal/secretref"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// liveSets is a key set in force that a test replaces under a connection, as a
// reload does.
type liveSets struct {
	mu sync.Mutex
	m  map[string]keyring.Set
}

func (l *liveSets) get(ref string) keyring.Set {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.m[ref]
}

func (l *liveSets) put(ref string, vs ...keyring.Version) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(vs) == 0 {
		delete(l.m, ref)
		return
	}
	l.m[ref] = keyring.Set{Ref: ref, Versions: vs}
}

func fakeVersion(n int, secret string, retired bool) keyring.Version {
	return keyring.Version{Number: n, Secret: secretref.Of([]byte(secret)), Retired: retired}
}

func putLogin(t *testing.T, st store.Store, secrets ...string) {
	t.Helper()
	for i, s := range secrets {
		if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
			store.Token{ID: "t" + strconv.Itoa(i), Secret: []byte(s), Kind: store.KindLogin,
				Principal: "user:alice@example.com", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
}

func loginStart(tok string) []byte {
	return wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte(tok)}.Encode()
}

// A reload that retires, or removes, the version an open connection validated
// under ends it at its next packet: matches_retired and a reset, with no
// strike, since the change is port49d's (spec §10; decision 53 ruling 4). A
// device already on the new version is served at once, and a reload that only
// adds a version changes nothing for the connection.
func TestAReloadThatWithdrawsTheVersionEndsItsConnectionWithoutAStrike(t *testing.T) {
	v3 := fakeVersion(3, "k3", false)
	for name, withdraw := range map[string]func(*liveSets){
		"retired": func(l *liveSets) { l.put("prod_key", v3, fakeVersion(2, "k2", true)) },
		"removed": func(l *liveSets) { l.put("prod_key", v3) },
		"the key_ref gone": func(l *liveSets) {
			l.put("prod_key")
		},
	} {
		t.Run(name, func(t *testing.T) {
			var log syncBuffer
			sets := &liveSets{m: map[string]keyring.Set{}}
			sets.put("prod_key", fakeVersion(2, "k2", false))
			st := memory.New(time.Now)
			putLogin(t, st, "p49_e2e", "p49_second", "p49_third", "p49_fourth")
			ts := newTestServerWith(t, &log, st, nil, func(d *Deps) { d.Keys = sets.get; d.Limits = slowBackoff() })
			c := dial(t, ts.addr, []byte("k2"))
			login := func(sid uint32, tok string) {
				c.sid, c.seq = sid, 1
				c.send(t, wire.TypeAuthen, loginStart(tok), wire.FlagSingleConnect)
				c.recv(t) // a reply: the connection still speaks version 2
			}
			login(100, "p49_e2e")
			sets.put("prod_key", v3, fakeVersion(2, "k2", false))
			login(101, "p49_second") // adding version 3 changed nothing for this connection
			withdraw(sets)
			c.sid, c.seq = 102, 1
			c.send(t, wire.TypeAuthen, loginStart("p49_third"), wire.FlagSingleConnect)
			closedAtOnce(t, c)
			if !waitFor(t, func() bool { return log.contains(`"diagnosis":"matches_retired"`) }) {
				t.Fatalf("no matches_retired record: %s", log.String())
			}
			if n := testutil.ToFloat64(ts.metrics.KeyValidations.WithLabelValues("prod_key", "2", "matches_retired")); name != "the key_ref gone" && n != 1 {
				t.Errorf("key_validations matches_retired = %v, want 1", n)
			}
			// No strike: the source is not held, nothing is counted as a key
			// miss, and a device re-provisioned with version 3 is served on its
			// next connection, not refused at Accept.
			if ts.limits.Holding(netip.MustParseAddr("127.0.0.1")) {
				t.Fatal("a reload's own withdrawal struck the device")
			}
			for _, ev := range []string{"key_miss_closed", "held_refused"} {
				if got := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues(ev)); got != 0 {
					t.Fatalf("%s = %v after a reload's withdrawal", ev, got)
				}
			}
			if name == "the key_ref gone" {
				sets.put("prod_key", v3)
			}
			c3 := dial(t, ts.addr, []byte("k3"))
			c3.sid, c3.seq = 103, 1
			c3.send(t, wire.TypeAuthen, loginStart("p49_fourth"), 0)
			c3.recv(t)
		})
	}
}

// Connections end as a reload withdraws their version while other packets
// flow, with no race and none left open: the live set is read at every
// packet. Run under -race.
func TestAReloadWithdrawingAVersionWhilePacketsFlow(t *testing.T) {
	var log syncBuffer
	sets := &liveSets{m: map[string]keyring.Set{}}
	sets.put("prod_key", fakeVersion(2, "k2", false))
	st := memory.New(time.Now)
	ts := newTestServerWith(t, &log, st, nil, func(d *Deps) { d.Keys = sets.get; d.Limits = slowBackoff() })
	const conns = 2 // the test server's per-NAS cap
	var wg sync.WaitGroup
	ended := make(chan error, conns)
	var served sync.WaitGroup // each connection has had three replies
	// retired is set once the retiring put has returned: a request written
	// after that is read by the server after it, so it must get no reply.
	var retired, lateReplies atomic.Int32
	served.Add(conns)
	for i := range conns {
		conn, err := net.Dial("tcp", ts.addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		wg.Add(1)
		go func(i int, conn net.Conn) {
			defer wg.Done()
			c := &client{conn: conn, key: []byte("k2"), sid: uint32(1000 + i), seq: 1}
			for n := 0; ; n++ {
				// A PAP login with a wrong credential: each is answered and its
				// session is over, so the connection can carry as many as it likes.
				afterPut := retired.Load() == 1
				body := loginStart("p49_wrong")
				h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 1, Flags: wire.FlagSingleConnect,
					SessionID: c.sid + uint32(n)<<16, Length: uint32(len(body))}
				if _, err := conn.Write(append(h.Encode(), wire.Obfuscate(h, c.key, body)...)); err != nil {
					ended <- nil
					return
				}
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				hb := make([]byte, wire.HeaderLen)
				if _, err := io.ReadFull(conn, hb); err != nil {
					if errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) {
						ended <- nil
					} else {
						ended <- err
					}
					return
				}
				if afterPut {
					lateReplies.Add(1)
				}
				rh, _ := wire.DecodeHeader(hb)
				if _, err := io.ReadFull(conn, make([]byte, rh.Length)); err != nil {
					ended <- err
					return
				}
				if n == 2 {
					served.Done()
				}
			}
		}(i, conn)
	}
	served.Wait()
	// Reloads that add and drop a version while the packets flow, then the
	// one that retires version 2.
	for range 20 {
		sets.put("prod_key", fakeVersion(3, "k3", false), fakeVersion(2, "k2", false))
		sets.put("prod_key", fakeVersion(2, "k2", false))
	}
	sets.put("prod_key", fakeVersion(3, "k3", false), fakeVersion(2, "k2", true))
	retired.Store(1)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("connections on a retired version were still open 10s after the reload")
	}
	for range conns {
		if err := <-ended; err != nil {
			t.Fatalf("a connection ended with %v, not a close", err)
		}
	}
	if n := lateReplies.Load(); n != 0 {
		t.Fatalf("%d replies came to requests sent after the retiring reload returned", n)
	}
	if ts.limits.Holding(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("a reload's own withdrawal struck the device")
	}
}

// A connection accepted before a reload, and idle until its first packet, is
// judged against the key set in force at that packet, never the one it was
// accepted with (Task 7 ruling): a version the reload withdrew is not
// validated under, the connection is reset with no strike and nothing is
// answered; a version it added validates at once; a wrong key is struck as
// ever.
func TestAFirstPacketIsJudgedAgainstTheSetInForceNow(t *testing.T) {
	v3 := fakeVersion(3, "k3", false)
	type want struct{ reset, strike bool }
	for name, c := range map[string]struct {
		reload func(*liveSets)
		key    string
		want   want
		// retired starts k2 listed retired: a key already withdrawn at Accept.
		retired bool
	}{
		"the version retired":    {func(l *liveSets) { l.put("prod_key", v3, fakeVersion(2, "k2", true)) }, "k2", want{true, false}, false},
		"the version removed":    {func(l *liveSets) { l.put("prod_key", v3) }, "k2", want{true, false}, false},
		"the key_ref removed":    {func(l *liveSets) { l.put("prod_key") }, "k2", want{true, false}, false},
		"a version added":        {func(l *liveSets) { l.put("prod_key", v3, fakeVersion(2, "k2", false)) }, "k3", want{false, false}, false},
		"a wrong key":            {func(l *liveSets) { l.put("prod_key", v3) }, "k-wrong", want{true, true}, false},
		"a wrong key, no reload": {func(l *liveSets) {}, "k-wrong", want{true, true}, false},
		"the old key, no reload": {func(l *liveSets) {}, "k2", want{false, false}, false},
		// A key retired before the connection was accepted is the leaked-key case: an
		// ordinary miss, struck, whatever else reloads (re-review 7, I1).
		"retired at Accept, no reload": {func(l *liveSets) {}, "k2", want{true, true}, true},
		"retired at Accept, an unrelated reload": {func(l *liveSets) { l.put("other_key", fakeVersion(1, "o1", false)) },
			"k2", want{true, true}, true},
	} {
		t.Run(name, func(t *testing.T) {
			var log syncBuffer
			sets := &liveSets{m: map[string]keyring.Set{}}
			if c.retired {
				sets.put("prod_key", v3, fakeVersion(2, "k2", true))
			} else {
				sets.put("prod_key", fakeVersion(2, "k2", false))
			}
			st := memory.New(time.Now)
			putLogin(t, st, "p49_first")
			ts := newTestServerWith(t, &log, st, nil, func(d *Deps) { d.Keys = sets.get; d.Limits = slowBackoff() })
			cl := dial(t, ts.addr, []byte(c.key))
			if !waitFor(t, func() bool { return testutil.ToFloat64(ts.metrics.Connections.WithLabelValues("open")) == 1 }) {
				t.Fatal("the connection was not accepted")
			}
			c.reload(sets)
			cl.send(t, wire.TypeAuthen, loginStart("p49_first"), wire.FlagSingleConnect)
			if !c.want.reset {
				cl.recv(t)
				return
			}
			closedAtOnce(t, cl)
			miss := func() float64 {
				return testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("key_miss_closed"))
			}
			if c.want.strike {
				if !waitFor(t, func() bool { return miss() == 1 && ts.limits.Holding(netip.MustParseAddr("127.0.0.1")) }) {
					t.Fatal("a wrong key was not struck")
				}
				return
			}
			if !waitFor(t, func() bool { return log.contains(`"diagnosis":"matches_retired"`) }) {
				t.Fatalf("no matches_retired record: %s", log.String())
			}
			if miss() != 0 || ts.limits.Holding(netip.MustParseAddr("127.0.0.1")) {
				t.Fatal("a reload's own withdrawal struck the device")
			}
		})
	}
}

// A first packet that misses after a reload removed the device's key_ref is
// counted under that key_ref, not under the empty name of the absent set
// (re-review 7, M2): one spelling for every key_validations series.
func TestAFirstPacketMissOnARemovedKeyRefIsCountedUnderItsName(t *testing.T) {
	var log syncBuffer
	sets := &liveSets{m: map[string]keyring.Set{}}
	sets.put("prod_key", fakeVersion(2, "k2", false))
	st := memory.New(time.Now)
	putLogin(t, st, "p49_first")
	ts := newTestServerWith(t, &log, st, nil, func(d *Deps) { d.Keys = sets.get; d.Limits = slowBackoff() })
	cl := dial(t, ts.addr, []byte("k-wrong"))
	if !waitFor(t, func() bool { return testutil.ToFloat64(ts.metrics.Connections.WithLabelValues("open")) == 1 }) {
		t.Fatal("the connection was not accepted")
	}
	sets.put("prod_key")
	cl.send(t, wire.TypeAuthen, loginStart("p49_first"), wire.FlagSingleConnect)
	closedAtOnce(t, cl)
	count := func(ref string) float64 {
		return testutil.ToFloat64(ts.metrics.KeyValidations.WithLabelValues(ref, "0", "no_known_key_matches"))
	}
	if !waitFor(t, func() bool { return count("prod_key") == 1 }) || count("") != 0 {
		t.Fatalf("under prod_key %v, under the empty name %v", count("prod_key"), count(""))
	}
}
