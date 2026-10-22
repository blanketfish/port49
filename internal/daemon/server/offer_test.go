package server

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/devicecert"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
)

// Spec §13 decision 50 ruling 20: on the RFC 9887 listener port49 offers
// single-connect to a platform whose built-in wire fact says its client
// pipelines (NX-OS 10.6(2)F writes the next request about 20 ms after an
// accounting record, without reading the reply; L80).

// nxos01TLS is leaf-01 as an NX-OS device on the TLS listener.
var nxos01TLS = admission.Device{Name: "leaf-01", Platform: "cisco_nxos", Transport: admission.TransportTLS,
	Addresses: []netip.Addr{loopback}}

// acctStop and showUsers are what NX-OS pipelines: the accounting record
// after a state-changing command, and the next command's authorization.
var (
	acctStop = wire.AcctRequest{Flags: wire.AcctFlagStop, AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 15,
		AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("pts/0"),
		Args: [][]byte{[]byte("task_id=1"), []byte("service=shell"), []byte("cmd=terminal length 0 <cr>")}}.Encode()
	showUsers = wire.AuthorRequest{AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 15, AuthenType: wire.AuthenTypeASCII,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("pts/0"),
		Args: [][]byte{[]byte("service=shell"), []byte("cmd=show"), []byte("cmd-arg=users"), []byte("cmd-arg=<cr>")}}.Encode()
)

// newOfferFixture is the TLS rig with leaf-01 admitted as dev.
func newOfferFixture(t *testing.T, log *syncBuffer, dev admission.Resolved, adjust func(*Deps, *tlsFixture)) (*tlsFixture, *tls.Certificate) {
	t.Helper()
	f := newTLSFixture(t, log, adjust)
	f.admit.swap(t, dev)
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	return f, &cert
}

// session sends one request as a new session with flags (the unencrypted
// flag is always added) and returns the reply header.
func (c *tlsClient) session(t *testing.T, sid uint32, typ wire.Type, body []byte, flags uint8) (wire.Header, error) {
	t.Helper()
	c.sid, c.seq = sid, 1
	if err := c.send(typ, body, wire.FlagUnencrypted|flags); err != nil {
		return wire.Header{}, err
	}
	h, _, err := c.recv()
	return h, err
}

// closedAfter wants c ended by the server: EOF, a reset, or a closed
// connection, never a reply and never a read that waits out its deadline.
func closedAfter(t *testing.T, c *tlsClient, what string) {
	t.Helper()
	c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _, err := c.recv()
	if err == nil {
		t.Fatalf("%s: the server answered or held the connection open", what)
	}
	var ne interface{ Timeout() bool }
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("%s: the server held the connection open: %v", what, err)
	}
}

// offered dials as leaf-01 and runs a login with no client flag: the first
// reply must carry the flag port49 offers.
func offered(t *testing.T, f *tlsFixture, cert *tls.Certificate, sid uint32) *tlsClient {
	t.Helper()
	cl, err := f.dialTLS(t, cert, nil)
	if err != nil {
		t.Fatal(err)
	}
	h, err := cl.session(t, sid, wire.TypeAuthen, aliceLogin, 0)
	if err != nil {
		t.Fatalf("the first exchange: %v", err)
	}
	if h.Flags&wire.FlagSingleConnect == 0 {
		t.Fatalf("the first reply to cisco_nxos has flags %#x: port49 did not offer single-connect", h.Flags)
	}
	return cl
}

// Test 1. A cisco_nxos device's first request carries no flag, and its
// first reply carries FlagSingleConnect. The accounting record and the
// command authorization NX-OS writes behind it, without reading the
// accounting reply, are both read and decided on the same connection.
func TestTLSOffersSingleConnectToNXOS(t *testing.T) {
	log := &syncBuffer{}
	f, cert := newOfferFixture(t, log, admission.Resolved{Device: nxos01TLS}, nil)
	cl := offered(t, f, cert, 0x100)
	// The pipeline: both requests written before either reply is read.
	cl.sid, cl.seq = 0x101, 1
	if err := cl.send(wire.TypeAcct, acctStop, wire.FlagUnencrypted); err != nil {
		t.Fatal(err)
	}
	cl.sid, cl.seq = 0x102, 1
	if err := cl.send(wire.TypeAuthor, showUsers, wire.FlagUnencrypted); err != nil {
		t.Fatal(err)
	}
	for _, want := range []wire.Type{wire.TypeAcct, wire.TypeAuthor} {
		h, _, err := cl.recv()
		if err != nil {
			t.Fatalf("the pipelined %d request was never answered: %v", want, err)
		}
		if h.Type != want {
			t.Fatalf("reply type %d, want %d", h.Type, want)
		}
	}
	if !waitFor(t, func() bool { return log.contains(`"event":"authorize_command"`) }) {
		t.Fatalf("the pipelined command was never decided: %s", log.String())
	}
}

// wirePlatformOf loads a policy whose platforms block is blocks, with leaf-01
// on the TLS listener as name, and returns its admission entry: the
// WirePlatform port49d's own index gives it.
func wirePlatformOf(t *testing.T, name, blocks string) admission.Resolved {
	t.Helper()
	dev := nxos01TLS
	dev.Platform = name
	p, err := policy.Parse([]byte(blocks+`
privilege_levels: [{name: readonly}, {name: operator}, {name: admin}]
scopes: [{name: all_devices, match: {}}]
roles: [{name: adm, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: "user:alice@example.com", username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [adm]}]
`), policy.Env{Now: time.Now(), Devices: []admission.Device{dev}})
	if err != nil {
		t.Fatal(err)
	}
	r, ok := p.Admission().Lookup(loopback)
	if !ok || r.Refused != "" {
		t.Fatalf("leaf-01 as %s is not admitted: %+v", name, r)
	}
	return r
}

// Test 2. Only the table's platforms are offered, across every platform the
// built-in sets ship (read from the sets, so a newly shipped one is
// covered). A `based_on: cisco_nxos` variant is offered through its wire
// platform, and a `replace: true` cisco_nxos block keeps its name and so the
// fact (Rm1). Every other platform's first reply has the flag clear, and its
// connection closes after one session.
func TestTLSOffersSingleConnectOnlyWhereMeasured(t *testing.T) {
	cases := map[string]admission.Resolved{}
	for _, v := range platform.Sets() {
		set, _ := platform.Set(v)
		for name := range set {
			dev := nxos01TLS
			dev.Platform = name
			cases[name] = admission.Resolved{Device: dev}
		}
	}
	if len(cases) < 4 {
		t.Fatalf("the built-in sets ship %d platforms", len(cases))
	}
	cases["variant of cisco_nxos"] = wirePlatformOf(t, "nexus_lab", "platforms:\n  nexus_lab: {based_on: cisco_nxos}\n")
	cases["replace: true cisco_nxos"] = wirePlatformOf(t, "cisco_nxos", `platforms:
  cisco_nxos:
    replace: true
    accepted_attributes: [priv-lvl]
    privilege_attributes: [priv-lvl, "shell:roles", cisco-av-pair]
    inert_attributes: []
    privilege:
      readonly: ["priv-lvl=1"]
      operator: ["priv-lvl=1"]
      admin: ["priv-lvl=15"]
`)
	cases["variant of arista_eos"] = wirePlatformOf(t, "eos_lab", "platforms:\n  eos_lab: {based_on: arista_eos}\n")
	if r := cases["variant of cisco_nxos"]; r.WirePlatform != "cisco_nxos" || r.Device.Platform != "nexus_lab" {
		t.Fatalf("the variant resolves as %+v", r)
	}
	for name, dev := range cases {
		t.Run(name, func(t *testing.T) {
			log := &syncBuffer{}
			f, cert := newOfferFixture(t, log, dev, nil)
			wp := dev.WirePlatform
			if wp == "" {
				wp = dev.Device.Platform
			}
			want := wp == "cisco_nxos"
			cl, err := f.dialTLS(t, cert, nil)
			if err != nil {
				t.Fatal(err)
			}
			h, err := cl.session(t, 0x100, wire.TypeAuthen, aliceLogin, 0)
			if err != nil {
				t.Fatal(err)
			}
			if got := h.Flags&wire.FlagSingleConnect != 0; got != want {
				t.Fatalf("first reply flags %#x: offered %v, want %v", h.Flags, got, want)
			}
			if !want {
				closedAfter(t, cl, "a platform port49 does not offer to, after one session")
				return
			}
			if _, err := cl.session(t, 0x101, wire.TypeAcct, acctStop, 0); err != nil {
				t.Fatalf("the offered connection did not serve a second session: %v", err)
			}
		})
	}
}

// Test 3. The RFC 8907 listener never offers: NX-OS opens a connection per
// request there (0 of 10 pipelined, arm E), so cisco_nxos with no client
// flag gets no flag and a close after one session.
func TestTCPListenerNeverOffersSingleConnect(t *testing.T) {
	log := &syncBuffer{}
	admit := &swapAdmitter{}
	nx := leaf01
	nx.Platform = "cisco_nxos"
	admit.swap(t, admission.Resolved{Device: nx, KeyRef: "prod_key"})
	ts := newTestServerWith(t, log, seededStore(t), nil, func(d *Deps) { d.Admission = admit })
	c := dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, aliceLogin, 0)
	h, _ := c.recv(t)
	if h.Flags&wire.FlagSingleConnect != 0 {
		t.Fatalf("the RFC 8907 listener offered single-connect: flags %#x", h.Flags)
	}
	c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := c.conn.Read(make([]byte, 1)); n != 0 || !(errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET)) {
		t.Fatalf("want a close after one session, got %d bytes, %v", n, err)
	}
}

// Test 4. An offered connection lives up to idle_timeout, so every packet on
// it is still judged against admission and the quarantine in force: a held
// connection never serves a packet a fresh one would be refused. (Setting
// s.single before the first packet is not observable: every path before it
// returns with no reply, Rm2. This targets caching the verdicts instead.)
func TestTLSOfferedConnectionStillChecksEveryPacket(t *testing.T) {
	aristaTLS := nxos01TLS
	aristaTLS.Platform = "arista_eos"
	for name, c := range map[string]struct {
		change   func(*testing.T, *tlsFixture, *atomic.Bool)
		diag     string
		declined bool
	}{
		"quarantined": {func(_ *testing.T, _ *tlsFixture, q *atomic.Bool) { q.Store(true) }, "device_quarantined", true},
		"removed by a reload": {func(t *testing.T, f *tlsFixture, _ *atomic.Bool) {
			f.admit.swap(t, admission.Resolved{Device: leaf02})
		}, "unadmitted_source", true},
		"re-platformed to arista_eos by a reload": {func(t *testing.T, f *tlsFixture, _ *atomic.Bool) {
			f.admit.swap(t, admission.Resolved{Device: aristaTLS})
		}, "admission_withdrawn", false},
		// Ruling 9's recheck: a certificate revoked, or anchors a reload
		// replaced, after the offer (review M2).
		"certificate revoked on the held connection": {func(_ *testing.T, f *tlsFixture, _ *atomic.Bool) {
			f.status.Store(int32(devicecert.StatusRevoked))
		}, "tls_refused", false},
		"anchors replaced by a reload on the held connection": {func(t *testing.T, f *tlsFixture, _ *atomic.Bool) {
			other, err := testpki.NewCA("Other", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			f.mat.Store(f.material(other, true))
		}, "tls_refused", false},
	} {
		t.Run(name, func(t *testing.T) {
			log := &syncBuffer{}
			var quar atomic.Bool
			f, cert := newOfferFixture(t, log, admission.Resolved{Device: nxos01TLS}, func(d *Deps, _ *tlsFixture) {
				d.Limits = slowBackoff()
				d.Quarantined = func(string, time.Time) (string, bool) { return "a grant expired", quar.Load() }
			})
			cl := offered(t, f, cert, 0x100)
			c.change(t, f, &quar)
			cl.sid, cl.seq = 0x101, 1
			if err := cl.send(wire.TypeAcct, acctStop, wire.FlagUnencrypted); err == nil {
				closedAfter(t, cl, "the packet after the change")
			}
			if !waitFor(t, func() bool { return log.contains(`"diagnosis":"` + c.diag + `"`) }) {
				t.Fatalf("no %s record: %s", c.diag, log.String())
			}
			if log.contains(`"event":"account"`) {
				t.Fatalf("the packet after the change was served: %s", log.String())
			}
			if got := f.ts.limits.Declined(loopback); got != c.declined {
				t.Fatalf("declined %v, want %v", got, c.declined)
			}
		})
	}
	t.Run("an unadmitted source gets no reply", func(t *testing.T) {
		log := &syncBuffer{}
		f, cert := newOfferFixture(t, log, admission.Resolved{Device: leaf02}, func(d *Deps, _ *tlsFixture) {
			d.Limits = slowBackoff()
		})
		cl, err := f.dialTLS(t, cert, nil)
		if err != nil {
			return // refused at Accept or at the handshake
		}
		if _, err := cl.session(t, 0x100, wire.TypeAuthen, aliceLogin, 0); err == nil {
			t.Fatal("an unadmitted source was answered")
		}
	})
}

// Test 5 (RI1). The measured form: an offered connection's replies 1, 2 and
// 3 all carry the flag, as a client-negotiated connection's do.
func TestTLSOfferedFlagEchoedOnEveryReply(t *testing.T) {
	log := &syncBuffer{}
	f, cert := newOfferFixture(t, log, admission.Resolved{Device: nxos01TLS}, nil)
	cl := offered(t, f, cert, 0x100)
	for i, x := range []struct {
		typ  wire.Type
		body []byte
	}{{wire.TypeAcct, acctStop}, {wire.TypeAuthor, showUsers}} {
		h, err := cl.session(t, uint32(0x101+i), x.typ, x.body, 0)
		if err != nil {
			t.Fatalf("reply %d: %v", i+2, err)
		}
		if h.Flags != wire.FlagUnencrypted|wire.FlagSingleConnect {
			t.Fatalf("reply %d flags %#x, want the flag echoed", i+2, h.Flags)
		}
	}
}

// Test 6. An offered connection closes at idle_timeout with no packet and
// counts idle_closed; one that gets a packet before it stays open.
func TestTLSOfferedConnectionClosesAtIdleTimeout(t *testing.T) {
	const idle = 600 * time.Millisecond
	log := &syncBuffer{}
	f, cert := newOfferFixture(t, log, admission.Resolved{Device: nxos01TLS}, func(d *Deps, _ *tlsFixture) {
		d.IdleTimeout = idle
	})
	busy := offered(t, f, cert, 0x100)
	quiet := offered(t, f, cert, 0x200)
	start := time.Now()
	time.Sleep(idle / 2)
	if _, err := busy.session(t, 0x101, wire.TypeAcct, acctStop, 0); err != nil {
		t.Fatalf("a packet inside idle_timeout was not served: %v", err)
	}
	closedAfter(t, quiet, "an offered connection past idle_timeout")
	if d := time.Since(start); d < idle-100*time.Millisecond {
		t.Fatalf("closed after %v, before idle_timeout %v", d, idle)
	}
	if !waitFor(t, func() bool {
		return testutil.ToFloat64(f.ts.metrics.ConnectionEvents.WithLabelValues("idle_closed")) >= 1
	}) {
		t.Fatal("the idle close was not counted idle_closed")
	}
	if _, err := busy.session(t, 0x102, wire.TypeAcct, acctStop, 0); err != nil {
		t.Fatalf("the busy connection was closed with the quiet one: %v", err)
	}
}

// asciiLogin runs an ASCII login whose START carries first and whose two
// CONTINUEs carry later, and returns the last reply's header.
func asciiLogin(t *testing.T, cl *tlsClient, first, later uint8) wire.Header {
	t.Helper()
	cl.sid, cl.seq = 0x100, 1
	if err := cl.send(wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypeASCII,
		Service: wire.AuthenServiceLogin, Port: []byte("vty0")}.Encode(), wire.FlagUnencrypted|first); err != nil {
		t.Fatal(err)
	}
	var h wire.Header
	for i, msg := range []string{"", "alice", "p49_e2e"} {
		if i > 0 {
			if err := cl.send(wire.TypeAuthen, wire.AuthenContinue{UserMsg: []byte(msg)}.Encode(),
				wire.FlagUnencrypted|later); err != nil {
				t.Fatal(err)
			}
		}
		var err error
		if h, _, err = cl.recv(); err != nil {
			t.Fatalf("round %d: %v", i+1, err)
		}
	}
	return h
}

// Test 7. RFC 8907 §4.3: "the client and server MUST ignore the flag after
// the second packet on a connection". A later packet's flag never changes
// the mode, in either direction.
func TestTLSClientFlagIgnoredAfterSecondPacket(t *testing.T) {
	arista := nxos01TLS
	arista.Platform = "arista_eos"
	t.Run("a flag set late does not open single-connect", func(t *testing.T) {
		log := &syncBuffer{}
		f, cert := newOfferFixture(t, log, admission.Resolved{Device: arista}, nil)
		cl, err := f.dialTLS(t, cert, nil)
		if err != nil {
			t.Fatal(err)
		}
		if h := asciiLogin(t, cl, 0, wire.FlagSingleConnect); h.Flags&wire.FlagSingleConnect != 0 {
			t.Fatalf("the last reply carries the flag: %#x", h.Flags)
		}
		closedAfter(t, cl, "a connection the first packet did not open in single-connect")
	})
	t.Run("a flag cleared late does not close single-connect", func(t *testing.T) {
		log := &syncBuffer{}
		f, cert := newOfferFixture(t, log, admission.Resolved{Device: arista}, nil)
		cl, err := f.dialTLS(t, cert, nil)
		if err != nil {
			t.Fatal(err)
		}
		if h := asciiLogin(t, cl, wire.FlagSingleConnect, 0); h.Flags&wire.FlagSingleConnect == 0 {
			t.Fatalf("the last reply lost the flag: %#x", h.Flags)
		}
		if _, err := cl.session(t, 0x101, wire.TypeAcct, acctStop, 0); err != nil {
			t.Fatalf("the single-connect connection closed after the session: %v", err)
		}
	})
}

// secondConnections is the ignore signal's count.
func secondConnections(f *tlsFixture) float64 {
	return testutil.ToFloat64(f.ts.metrics.ConnectionEvents.WithLabelValues("single_connect_second_connection"))
}

// served dials as leaf-01 and completes one exchange, so the server has
// certainly accepted the connection.
func served(t *testing.T, f *tlsFixture, cert *tls.Certificate, flags uint8) *tlsClient {
	t.Helper()
	cl, err := f.dialTLS(t, cert, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.session(t, 0x300, wire.TypeAcct, acctStop, flags); err != nil {
		t.Fatal(err)
	}
	return cl
}

// The offer is released before the socket closes, so a device that
// reconnects the moment it sees the close is never counted against its own
// closed connection (review M1).
func TestTLSOfferIsReleasedBeforeTheSocketCloses(t *testing.T) {
	off := newOffers()
	var deps *Deps
	f, cert := newOfferFixture(t, &syncBuffer{}, admission.Resolved{Device: nxos01TLS}, func(d *Deps, _ *tlsFixture) {
		d.offers = off
		deps = d
	})
	// A second Serve of the same Deps, on a listener whose connections say
	// at their close whether the source still had an offer open.
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	heldAtClose := make(chan bool, 4)
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() { defer close(served); Serve(ctx, closeProbe{raw, off, heldAtClose}, *deps) }()
	t.Cleanup(func() { cancel(); <-served })
	f.ts.addr = raw.Addr().String()
	cl := offered(t, f, cert, 0x100)
	cl.conn.Close()
	select {
	case held := <-heldAtClose:
		if held {
			t.Fatal("the socket closed while its offer was still counted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server never closed the connection")
	}
}

// closeProbe is a listener whose connections report, at their first Close,
// whether off still counts an offered connection from loopback.
type closeProbe struct {
	net.Listener
	off  *offers
	held chan bool
}

func (l closeProbe) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &probeConn{TCPConn: c.(*net.TCPConn), off: l.off, held: l.held}, nil
}

type probeConn struct {
	*net.TCPConn
	off  *offers
	held chan bool
	once sync.Once
}

func (c *probeConn) Close() error {
	c.once.Do(func() { c.held <- c.off.any(loopback) })
	return c.TCPConn.Close()
}

// Test 10 (RI3). A device port49 offered single-connect to that opens a
// second connection while its offered one is open is counted
// single_connect_second_connection; nothing else is.
func TestTLSCountsASecondConnectionFromAnOfferedDevice(t *testing.T) {
	arista := nxos01TLS
	arista.Platform = "arista_eos"
	type rig struct {
		f    *tlsFixture
		cert *tls.Certificate
		off  *offers
	}
	setup := func(t *testing.T, dev admission.Device) rig {
		off := newOffers()
		f, cert := newOfferFixture(t, &syncBuffer{}, admission.Resolved{Device: dev}, func(d *Deps, _ *tlsFixture) {
			d.Limits = slowBackoff()
			d.offers = off
		})
		return rig{f, cert, off}
	}
	t.Run("a second connection while the offered one is open", func(t *testing.T) {
		r := setup(t, nxos01TLS)
		offered(t, r.f, r.cert, 0x100)
		served(t, r.f, r.cert, 0)
		if n := secondConnections(r.f); n != 1 {
			t.Fatalf("single_connect_second_connection = %v, want 1", n)
		}
	})
	t.Run("a second connection after the offered one closed", func(t *testing.T) {
		r := setup(t, nxos01TLS)
		cl := offered(t, r.f, r.cert, 0x100)
		cl.conn.Close()
		if !waitFor(t, func() bool { return !r.off.any(loopback) }) {
			t.Fatal("the first connection's offer was never released")
		}
		served(t, r.f, r.cert, 0)
		if n := secondConnections(r.f); n != 0 {
			t.Fatalf("single_connect_second_connection = %v, want 0", n)
		}
	})
	t.Run("a connection still in its handshake is not offered", func(t *testing.T) {
		r := setup(t, nxos01TLS)
		if _, err := r.f.dialTLS(t, r.cert, nil); err != nil {
			t.Fatal(err)
		}
		served(t, r.f, r.cert, 0)
		if n := secondConnections(r.f); n != 0 {
			t.Fatalf("single_connect_second_connection = %v, want 0", n)
		}
	})
	t.Run("a client-negotiated connection is not offered", func(t *testing.T) {
		r := setup(t, nxos01TLS)
		served(t, r.f, r.cert, wire.FlagSingleConnect)
		served(t, r.f, r.cert, 0)
		if n := secondConnections(r.f); n != 0 {
			t.Fatalf("single_connect_second_connection = %v, want 0", n)
		}
	})
	t.Run("a non-table platform with two connections", func(t *testing.T) {
		r := setup(t, arista)
		served(t, r.f, r.cert, wire.FlagSingleConnect)
		served(t, r.f, r.cert, wire.FlagSingleConnect)
		if n := secondConnections(r.f); n != 0 {
			t.Fatalf("single_connect_second_connection = %v, want 0", n)
		}
	})
	t.Run("a connection refused at Accept inside a decline window", func(t *testing.T) {
		var quar atomic.Bool
		off := newOffers()
		f, cert := newOfferFixture(t, &syncBuffer{}, admission.Resolved{Device: nxos01TLS}, func(d *Deps, _ *tlsFixture) {
			d.Limits = slowBackoff()
			d.offers = off
			d.Quarantined = func(string, time.Time) (string, bool) { return "a grant expired", quar.Load() }
		})
		offered(t, f, cert, 0x100)
		quar.Store(true)
		f.ts.limits.Decline(loopback)
		acceptRefused(t, f.ts.addr)
		if !waitFor(t, func() bool {
			return testutil.ToFloat64(f.ts.metrics.ConnectionEvents.WithLabelValues("declined_refused")) == 1
		}) {
			t.Fatal("the second connection was not refused declined_refused")
		}
		if n := secondConnections(f); n != 0 {
			t.Fatalf("single_connect_second_connection = %v for a connection refused at Accept, want 0", n)
		}
	})
	t.Run("a source re-platformed off the table while its offered connection is open", func(t *testing.T) {
		r := setup(t, nxos01TLS)
		offered(t, r.f, r.cert, 0x100)
		r.f.admit.swap(t, admission.Resolved{Device: arista})
		served(t, r.f, r.cert, wire.FlagSingleConnect)
		if n := secondConnections(r.f); n != 0 {
			t.Fatalf("single_connect_second_connection = %v, want 0", n)
		}
	})
}

// countingConn counts the bytes a TLS client's raw socket reads.
type countingConn struct {
	net.Conn
	n atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	k, err := c.Conn.Read(p)
	c.n.Add(int64(k))
	return k, err
}

// A shutdown ends a held TLS connection with close_notify before its FIN,
// as an idle close does, not with a bare FIN (task 7 re-review N1). Over TLS
// 1.3 the alert is an encrypted record, so the device's raw socket reads
// bytes after the last reply; a bare FIN reads none.
func TestTLSShutdownSendsCloseNotifyOnAHeldConnection(t *testing.T) {
	var raw *countingConn
	old := tlsDial
	tlsDial = func(network, addr string) (net.Conn, error) {
		c, err := net.Dial(network, addr)
		if err != nil {
			return nil, err
		}
		raw = &countingConn{Conn: c}
		return raw, nil
	}
	t.Cleanup(func() { tlsDial = old })
	f, cert := newOfferFixture(t, &syncBuffer{}, admission.Resolved{Device: nxos01TLS}, nil)
	cl := offered(t, f, cert, 0x100)
	before := raw.n.Load()
	f.ts.shutdown()
	cl.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := cl.recv(); err == nil {
		t.Fatal("the connection was answered after shutdown")
	}
	if got := raw.n.Load() - before; got == 0 {
		t.Fatal("shutdown closed the held TLS connection with a bare FIN: no close_notify record arrived")
	}
}

// A store gone (Deps.Abort) still resets at once, with no close_notify
// first (L28: a device acts on a reset at once).
func TestTLSAbortResetsWithoutCloseNotify(t *testing.T) {
	var raw *countingConn
	old := tlsDial
	tlsDial = func(network, addr string) (net.Conn, error) {
		c, err := net.Dial(network, addr)
		if err != nil {
			return nil, err
		}
		raw = &countingConn{Conn: c}
		return raw, nil
	}
	t.Cleanup(func() { tlsDial = old })
	f, cert := newOfferFixture(t, &syncBuffer{}, admission.Resolved{Device: nxos01TLS}, func(d *Deps, _ *tlsFixture) {
		d.Abort = func() bool { return true }
	})
	cl := offered(t, f, cert, 0x100)
	before := raw.n.Load()
	f.ts.shutdown()
	cl.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _, err := cl.recv()
	if err == nil || raw.n.Load() != before {
		t.Fatalf("an abort sent %d bytes before closing (%v); want a bare reset", raw.n.Load()-before, err)
	}
}
