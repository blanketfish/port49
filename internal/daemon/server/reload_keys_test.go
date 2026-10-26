package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
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
			ts := newTestServerWith(t, &log, st, nil, func(d *Deps) { d.Keys = sets.get })
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
	ts := newTestServerWith(t, &log, st, nil, func(d *Deps) { d.Keys = sets.get })
	const conns = 2 // the test server's per-NAS cap
	var wg sync.WaitGroup
	ended := make(chan error, conns)
	var served sync.WaitGroup // each connection has had three replies
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
	if ts.limits.Holding(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("a reload's own withdrawal struck the device")
	}
}
