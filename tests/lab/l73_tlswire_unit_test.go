package lab

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
	"net"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/tests/lab/labpcap"
)

const (
	l73TDevice = "172.100.100.21"
	l73TServer = "172.100.100.1"
)

type l73FakeSeg struct {
	fromDevice bool
	flags      byte
	seq        uint32
	payload    []byte
	at         time.Time
}

// l73FakePcap writes segs as an Ethernet savefile between the device and the
// server, as tcpdump would.
func l73FakePcap(devPort, srvPort uint16, segs []l73FakeSeg) []byte {
	var b bytes.Buffer
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:], 2)
	binary.LittleEndian.PutUint16(hdr[6:], 4)
	binary.LittleEndian.PutUint32(hdr[16:], 262144)
	binary.LittleEndian.PutUint32(hdr[20:], uint32(labpcap.LinkEthernet))
	b.Write(hdr)
	for _, s := range segs {
		src, dst, sp, dp := l73TDevice, l73TServer, devPort, srvPort
		if !s.fromDevice {
			src, dst, sp, dp = l73TServer, l73TDevice, srvPort, devPort
		}
		pkt := make([]byte, 14+20+20+len(s.payload))
		binary.BigEndian.PutUint16(pkt[12:], 0x0800)
		ip := pkt[14:]
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(40+len(s.payload)))
		ip[8], ip[9] = 64, 6
		copy(ip[12:16], net.ParseIP(src).To4())
		copy(ip[16:20], net.ParseIP(dst).To4())
		tcp := ip[20:]
		binary.BigEndian.PutUint16(tcp[0:], sp)
		binary.BigEndian.PutUint16(tcp[2:], dp)
		binary.BigEndian.PutUint32(tcp[4:], s.seq)
		tcp[12] = 5 << 4
		tcp[13] = s.flags
		copy(tcp[20:], s.payload)
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:], uint32(s.at.Unix()))
		binary.LittleEndian.PutUint32(rec[4:], uint32(s.at.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(pkt)))
		binary.LittleEndian.PutUint32(rec[12:], uint32(len(pkt)))
		b.Write(rec)
		b.Write(pkt)
	}
	return b.Bytes()
}

const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
)

// l73Conversation is a whole connection: handshake, up in 1000-byte
// segments, down likewise, the device's FIN. reverse sends the device's
// segments last-first. Every segment appears twice, as -i any shows it.
func l73Conversation(up, down []byte, at time.Time, reverse bool) []l73FakeSeg {
	segs := []l73FakeSeg{{true, tcpSYN, 1000, nil, at}, {false, tcpSYN | tcpACK, 5000, nil, at}}
	var ups []l73FakeSeg
	seq := uint32(1001)
	for i := 0; i < len(up); i += 1000 {
		j := min(i+1000, len(up))
		ups = append(ups, l73FakeSeg{true, tcpACK | tcpPSH, seq, up[i:j], at})
		seq += uint32(j - i)
	}
	if reverse {
		for i, j := 0, len(ups)-1; i < j; i, j = i+1, j-1 {
			ups[i], ups[j] = ups[j], ups[i]
		}
	}
	segs = append(segs, ups...)
	sseq := uint32(5001)
	for i := 0; i < len(down); i += 1000 {
		j := min(i+1000, len(down))
		segs = append(segs, l73FakeSeg{false, tcpACK | tcpPSH, sseq, down[i:j], at})
		sseq += uint32(j - i)
	}
	segs = append(segs, l73FakeSeg{true, tcpFIN | tcpACK, seq, nil, at.Add(time.Second)})
	var twice []l73FakeSeg
	for _, s := range segs {
		twice = append(twice, s, s)
	}
	return twice
}

type l73Tee struct {
	net.Conn
	w *bytes.Buffer
}

func (c *l73Tee) Write(p []byte) (int, error) { c.w.Write(p); return c.Conn.Write(p) }

// l73RealHandshake runs crypto/tls over loopback TCP and returns the bytes
// each side wrote: real ClientHello and ServerHello bytes to parse.
func l73RealHandshake(t *testing.T, srv, cli *tls.Config) (up, down []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var downBuf bytes.Buffer
	done := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		s := tls.Server(&l73Tee{Conn: raw, w: &downBuf}, srv)
		if err := s.Handshake(); err != nil {
			raw.Close()
			done <- err
			return
		}
		_, err = s.Write([]byte("x"))
		s.Close()
		done <- err
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var upBuf bytes.Buffer
	c := tls.Client(&l73Tee{Conn: raw, w: &upBuf}, cli)
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 1)); err != nil { // takes the NewSessionTicket with it
		t.Fatal(err)
	}
	c.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return upBuf.Bytes(), downBuf.Bytes()
}

func l73TestConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	now := time.Now()
	ca, err := testpki.NewCA("L73 unit CA", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Issue(testpki.Leaf{DNSNames: []string{"tacacs.l73.example"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS13},
		&tls.Config{RootCAs: ca.Pool(), ServerName: "tacacs.l73.example", MinVersion: tls.VersionTLS13,
			ClientSessionCache: tls.NewLRUClientSessionCache(4)}
}

func TestL73ConnsReadsAFullHandshake(t *testing.T) {
	srv, cli := l73TestConfigs(t)
	up, down := l73RealHandshake(t, srv, cli)
	at := time.Unix(1_800_000_000, 0)
	conns, err := l73Conns(l73FakePcap(40001, 300, l73Conversation(up, down, at, false)), l73TDevice)
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) != 1 {
		t.Fatalf("%d connections, want 1: %+v", len(conns), conns)
	}
	c := conns[0]
	if c.Server != "172.100.100.1:300" || c.Answer != "syn-ack" || c.End != "device-fin" || c.Hello == nil || c.ServerHello == nil {
		t.Fatalf("%+v", c)
	}
	if !c.Hello.HasSNI || c.Hello.SNI != "tacacs.l73.example" || c.Hello.PSKIdentities != 0 {
		t.Errorf("hello %+v", c.Hello)
	}
	if c.ServerHello.Version != tls.VersionTLS13 || tls.CipherSuiteName(c.ServerHello.Suite) == "" || c.ServerHello.PSKSelected {
		t.Errorf("server hello %+v", c.ServerHello)
	}
	if c.Incomplete {
		t.Errorf("a whole connection reported incomplete")
	}
	if c.DeviceRecords == 0 || c.ServerRecords == 0 {
		t.Errorf("records %d %d", c.DeviceRecords, c.ServerRecords)
	}
}

// Go 1.26's ClientHello carries an X25519MLKEM768 share and spans segments;
// -i any shows each twice; the device's segments arrive last-first.
func TestL73ConnsReassemblesOutOfOrderDuplicates(t *testing.T) {
	srv, cli := l73TestConfigs(t)
	up, down := l73RealHandshake(t, srv, cli)
	if len(up) <= 1000 {
		t.Skip("this ClientHello fits one segment; nothing to reassemble")
	}
	conns, err := l73Conns(l73FakePcap(40002, 300, l73Conversation(up, down, time.Unix(1_800_000_000, 0), true)), l73TDevice)
	if err != nil || len(conns) != 1 || conns[0].Hello == nil || len(conns[0].Hello.Groups) == 0 {
		t.Fatalf("%+v %v", conns, err)
	}
}

// l73Stream is one direction in sequence order: an exact duplicate and a
// partial overlap add nothing, an out-of-order segment lands in place, and a
// gap ends the stream (what follows one was not captured).
func TestL73StreamDropsOverlapsAndStopsAtAGap(t *testing.T) {
	segs := []l73Seg{
		{seq: 1006, data: []byte("ghij")}, // out of order
		{seq: 1000, data: []byte("abcdef")},
		{seq: 1000, data: []byte("abcdef")}, // an exact duplicate
		{seq: 1004, data: []byte("efgh")},   // a partial overlap
		{seq: 1020, data: []byte("zz")},     // past a gap
	}
	if got := string(l73Stream(segs)); got != "abcdefghij" {
		t.Fatalf("got %q, want %q", got, "abcdefghij")
	}
}

// l73FieldTypes lists "Type.Field -> type" for every struct of rt's package
// reachable from rt through pointers, slices, arrays and maps (keys and
// values).
func l73FieldTypes(root reflect.Type) map[string]string {
	got := map[string]string{}
	pkg := root.PkgPath()
	seen := map[reflect.Type]bool{}
	var walk func(reflect.Type)
	walk = func(rt reflect.Type) {
		switch rt.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walk(rt.Elem())
			return
		case reflect.Map:
			walk(rt.Key())
			walk(rt.Elem())
			return
		}
		if rt.Kind() != reflect.Struct || rt.PkgPath() != pkg || seen[rt] {
			return
		}
		seen[rt] = true
		for i := range rt.NumField() {
			f := rt.Field(i)
			got[rt.Name()+"."+f.Name] = f.Type.String()
			walk(f.Type)
		}
	}
	walk(root)
	return got
}

// The walker reaches a byte string behind an array, a map's value or its key.
func TestL73FieldWalkerSeesThroughArraysAndMaps(t *testing.T) {
	type inArray struct{ B []byte }
	type inValue struct{ B []byte }
	type inKey struct{ K string }
	type probe struct {
		A [2]inArray
		M map[inKey][]*inValue
	}
	got := l73FieldTypes(reflect.TypeOf(probe{}))
	for _, name := range []string{"probe.A", "probe.M", "inArray.B", "inValue.B", "inKey.K"} {
		if _, ok := got[name]; !ok {
			t.Errorf("the walker missed %s: %v", name, got)
		}
	}
}

// The summary's types leave no room for session material. Every field is
// listed here with its type, and none is a byte string: a field that could
// carry a random, a legacy session id, a key share, a PSK identity, a
// binder or a ticket fails this test, and a new field fails it until it is
// reviewed and listed.
func TestL73SummaryTypesHaveNoRoomForSessionBytes(t *testing.T) {
	want := map[string]string{
		"l73Conn.Server": "string", "l73Conn.DevicePort": "uint16", "l73Conn.SYNAt": "time.Time",
		"l73Conn.Answer": "string", "l73Conn.Hello": "*lab.l73Hello", "l73Conn.ServerHello": "*lab.l73ServerHello",
		"l73Conn.Alerts": "[]lab.l73Alert", "l73Conn.DeviceRecords": "int", "l73Conn.ServerRecords": "int",
		"l73Conn.Plain": "[]lab.l73Plain", "l73Conn.Incomplete": "bool", "l73Conn.End": "string", "l73Conn.EndAt": "time.Time",
		"l73Conn.DevicePayloadBytes": "int", "l73Conn.ServerPayloadBytes": "int", "l73Conn.DeviceFINAt": "time.Time", "l73Conn.DeviceRSTAt": "time.Time",
		"l73Conn.ServerFlightAt": "time.Time", "l73Conn.DeviceReplyAt": "time.Time",
		"l73Hello.LegacyVersion": "uint16", "l73Hello.Versions": "[]uint16", "l73Hello.Suites": "[]uint16",
		"l73Hello.HasSNI": "bool", "l73Hello.SNI": "string", "l73Hello.Groups": "[]uint16",
		"l73Hello.SigAlgs": "[]uint16", "l73Hello.ALPN": "[]string", "l73Hello.PSKIdentities": "int",
		"l73Hello.PSKModes": "[]int", "l73Hello.EarlyData": "bool", "l73Hello.Extensions": "[]uint16",
		"l73ServerHello.Version": "uint16", "l73ServerHello.Suite": "uint16",
		"l73ServerHello.PSKSelected": "bool", "l73ServerHello.HelloRetry": "bool",
		"l73Alert.Level": "uint8", "l73Alert.Description": "uint8", "l73Alert.FromDevice": "bool",
		"l73Plain.Type": "uint8", "l73Plain.SeqNo": "uint8", "l73Plain.Flags": "uint8", "l73Plain.Length": "uint32",
		// compress_certificate's algorithm ids (RFC 8879): two-byte registry
		// codes the device offers, the same for every connection; no random,
		// key or secret can be carried in them (plan 11b, I3).
		"l73Hello.CompressCertAlgs": "[]uint16",
		// The 12-byte header's version octet (major<<4 | minor): one of four
		// values RFC 8907 defines; it carries no session byte (plan 11b, M4).
		"l73Plain.Version": "uint8",
	}
	got := l73FieldTypes(reflect.TypeOf(l73Conn{}))
	if !maps.Equal(got, want) {
		t.Fatalf("the summary's fields changed:\n got %v\nwant %v", got, want)
	}
}

// A resumption shows as a PSK identity offered and selected, and nothing of
// the identity, the binder, the randoms or the legacy session id reaches
// the summary.
func TestL73ResumptionSummaryHoldsNoSessionBytes(t *testing.T) {
	srv, cli := l73TestConfigs(t)
	l73RealHandshake(t, srv, cli)
	up, down := l73RealHandshake(t, srv, cli)
	conns, err := l73Conns(l73FakePcap(40003, 300, l73Conversation(up, down, time.Unix(1_800_000_000, 0), false)), l73TDevice)
	if err != nil || len(conns) != 1 {
		t.Fatalf("%+v %v", conns, err)
	}
	if conns[0].Hello.PSKIdentities != 1 || !conns[0].ServerHello.PSKSelected {
		t.Fatalf("not seen as a resumption: %+v %+v", conns[0].Hello, conns[0].ServerHello)
	}
	js, err := json.Marshal(conns)
	if err != nil {
		t.Fatal(err)
	}
	if hits := l73SummaryLeaks(string(js)); len(hits) > 0 {
		t.Fatalf("connection 0 summary holds %v", hits)
	}
	// record header 5, handshake header 4, legacy_version 2, random 32, then
	// the session id's length byte: none of the id or the random survives.
	sid := up[5+4+2+32+1 : 5+4+2+32+1+int(up[5+4+2+32])]
	random := up[5+4+2 : 5+4+2+32]
	for name, b := range map[string][]byte{"legacy session id": sid, "random": random} {
		if len(b) < 8 {
			t.Fatalf("the %s is %d bytes; the test cannot look for it", name, len(b))
		}
		if strings.Contains(strings.ToLower(string(js)), hex.EncodeToString(b[:8])) {
			t.Fatalf("connection 0 summary holds the %s", name)
		}
	}
}

// l73Shift moves a conversation's sequence numbers, as a second connection
// on the same ports would carry.
func l73Shift(segs []l73FakeSeg, by uint32) []l73FakeSeg {
	for i := range segs {
		segs[i].seq += by
	}
	return segs
}

// A device may reuse a source port: a SYN with a new sequence number on the
// same (port, server) pair is a second connection, and each hello is credited
// to its own.
func TestL73ConnsCountsAReusedSourcePortTwice(t *testing.T) {
	srv, cli := l73TestConfigs(t)
	up1, down1 := l73RealHandshake(t, srv, cli)
	up2, down2 := l73RealHandshake(t, srv, cli) // a resumption
	at := time.Unix(1_800_000_000, 0)
	segs := append(l73Conversation(up1, down1, at, false), l73Shift(l73Conversation(up2, down2, at.Add(5*time.Second), false), 100000)...)
	conns, err := l73Conns(l73FakePcap(40010, 300, segs), l73TDevice)
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) != 2 {
		t.Fatalf("%d connections, want 2", len(conns))
	}
	if conns[0].Hello == nil || conns[0].Hello.PSKIdentities != 0 || conns[0].ServerHello.PSKSelected {
		t.Errorf("first connection %+v", conns[0])
	}
	if conns[1].Hello == nil || conns[1].Hello.PSKIdentities != 1 || !conns[1].ServerHello.PSKSelected {
		t.Errorf("second connection %+v", conns[1])
	}
	if !conns[1].SYNAt.After(conns[0].SYNAt) {
		t.Errorf("not in capture order")
	}
}

func TestL73ConnsRefusedSYN(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	segs := []l73FakeSeg{{true, tcpSYN, 7, nil, at}, {false, tcpRST | tcpACK, 0, nil, at.Add(time.Millisecond)}}
	conns, err := l73Conns(l73FakePcap(40004, 6049, segs), l73TDevice)
	if err != nil || len(conns) != 1 || conns[0].Answer != "rst" || conns[0].End != "server-rst" || conns[0].Hello != nil {
		t.Fatalf("%+v %v", conns, err)
	}
	if p, ok := l73FirstPort(conns, l73TServer); !ok || p != 6049 {
		t.Fatalf("first port %d %v", p, ok)
	}
}

// Plain TACACS+ on 49 is summarized by its headers alone: the body (a
// password under the shared key) never reaches the summary.
func TestL73ConnsPlainTACACSHeadersOnly(t *testing.T) {
	body := []byte("SECRETBODY")
	hdr := []byte{0xc1, 1, 1, 0, 0, 0, 0, 7, 0, 0, 0, byte(len(body))}
	at := time.Unix(1_800_000_000, 0)
	segs := []l73FakeSeg{{true, tcpSYN, 1, nil, at}, {false, tcpSYN | tcpACK, 9, nil, at},
		{true, tcpACK | tcpPSH, 2, append(hdr, body...), at}}
	conns, err := l73Conns(l73FakePcap(40005, 49, segs), l73TDevice)
	if err != nil || len(conns) != 1 || len(conns[0].Plain) != 1 {
		t.Fatalf("%+v %v", conns, err)
	}
	if p := conns[0].Plain[0]; p.Version != 0xc1 || p.Type != 1 || p.SeqNo != 1 || p.Flags != 0 || p.Length != uint32(len(body)) {
		t.Fatalf("%+v", p)
	}
	js, _ := json.Marshal(conns)
	if strings.Contains(string(js), "SECRETBODY") {
		t.Fatal("the body reached the summary")
	}
}

func TestL73ConnsIgnoresSSHAndNETCONF(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	for _, port := range []uint16{22, 830} {
		conns, err := l73Conns(l73FakePcap(40006, port, []l73FakeSeg{{true, tcpSYN, 1, nil, at}}), l73TDevice)
		if err != nil || len(conns) != 0 {
			t.Fatalf("port %d: %+v %v", port, conns, err)
		}
	}
}

func TestL73FirstPortNeedsAConnection(t *testing.T) {
	if p, ok := l73FirstPort(nil, l73TServer); ok || p != 0 {
		t.Fatalf("%d %v", p, ok)
	}
	if got := l73Describe(nil, time.Now()); got != "the device opened no connection" {
		t.Fatal(got)
	}
}

func TestL73WindowAndDescribe(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	conns := []l73Conn{
		{Server: "172.100.100.1:300", SYNAt: t0.Add(time.Second), Answer: "syn-ack", End: "server-rst", EndAt: t0.Add(2 * time.Second)},
		{Server: "172.100.100.2:300", SYNAt: t0.Add(3 * time.Second), Answer: "rst", End: "server-rst", EndAt: t0.Add(3 * time.Second)},
	}
	if w := l73Window(conns, "172.100.100.1", t0, t0.Add(10*time.Second)); len(w) != 1 {
		t.Fatalf("%+v", w)
	}
	want := "+1.00s to 172.100.100.1:300: syn-ack, ended server-rst at +2.00s; +3.00s to 172.100.100.2:300: rst, ended server-rst at +3.00s"
	if got := l73Describe(conns, t0); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestL73SummaryLeaksFlagsLongRuns(t *testing.T) {
	if len(l73SummaryLeaks(`{"server":"172.100.100.1:300","syn_at":"2026-10-17T03:15:29.140123Z"}`)) != 0 {
		t.Fatal("an ordinary summary flagged")
	}
	if len(l73SummaryLeaks(`{"x":"`+strings.Repeat("ab", 16)+`"}`)) == 0 {
		t.Fatal("32 hex characters not flagged")
	}
	if len(l73SummaryLeaks(`{"x":"`+strings.Repeat("QUJD", 10)+`"}`)) == 0 {
		t.Fatal("40 base64 characters not flagged")
	}
}

// A segment lost from the start of the device's stream is an incomplete
// capture, never a stream that was not TLS.
func TestL73ConnsLostFirstSegmentIsIncomplete(t *testing.T) {
	srv, cli := l73TestConfigs(t)
	up, down := l73RealHandshake(t, srv, cli)
	if len(up) <= 1000 {
		t.Skip("this ClientHello fits one segment; there is no later segment to keep")
	}
	var kept []l73FakeSeg
	for _, s := range l73Conversation(up, down, time.Unix(1_800_000_000, 0), false) {
		if s.fromDevice && s.seq == 1001 && len(s.payload) > 0 {
			continue
		}
		kept = append(kept, s)
	}
	conns, err := l73Conns(l73FakePcap(40011, 300, kept), l73TDevice)
	if err != nil || len(conns) != 1 {
		t.Fatalf("%+v %v", conns, err)
	}
	if !conns[0].Incomplete || conns[0].Hello != nil {
		t.Fatalf("incomplete %v, hello %v", conns[0].Incomplete, conns[0].Hello)
	}
	if !strings.Contains(l73Describe(conns, time.Unix(1_800_000_000, 0)), "capture incomplete") {
		t.Fatal("the description does not say so")
	}
}

// l73HelloWith is a ClientHello body with one extension, by hand.
func l73HelloWith(typ uint16, data []byte) []byte {
	b := []byte{3, 3}
	b = append(b, make([]byte, 32)...)
	b = append(b, 0, 0, 2, 0x13, 0x01, 1, 0)
	ext := binary.BigEndian.AppendUint16(nil, typ)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(data)))
	ext = append(ext, data...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(ext)))
	return append(b, ext...)
}

// An extension cut inside its body is a parse error, not a hostname that was
// seen or an identity that was counted.
func TestL73ClientHelloCutInsideAnExtensionIsAnError(t *testing.T) {
	cases := map[string][]byte{
		"server_name cut after its type":  l73HelloWith(0, []byte{0, 4, 0, 0, 5, 'a'}),
		"pre_shared_key cut mid-identity": l73HelloWith(41, []byte{0, 3, 0, 8, 0xaa}),
		"alpn cut mid-name":               l73HelloWith(16, []byte{0, 3, 9, 'h', '2'}),
	}
	for name, b := range cases {
		if h, err := l73ParseClientHello(b); err == nil {
			t.Errorf("%s: parsed without error: has_sni %v, psk %d", name, h.HasSNI, h.PSKIdentities)
		}
	}
	if h, err := l73ParseClientHello(l73HelloWith(0, []byte{0, 6, 0, 0, 3, 'a', 'b', 'c'})); err != nil || h.SNI != "abc" {
		t.Errorf("a whole server_name: %+v %v", h, err)
	}
}

// compress_certificate (27) is kept as its algorithm ids: a one-byte length,
// then two-byte codes (RFC 8879). The ids are the device's offer, not session
// bytes.
func TestL73ClientHelloKeepsCompressCertificateAlgorithms(t *testing.T) {
	h, err := l73ParseClientHello(l73HelloWith(27, []byte{4, 0, 2, 0, 1}))
	if err != nil || !slices.Equal(h.CompressCertAlgs, []uint16{2, 1}) {
		t.Fatalf("%+v %v", h, err)
	}
	if _, err := l73ParseClientHello(l73HelloWith(27, []byte{4, 0, 2})); err == nil {
		t.Fatal("a compress_certificate list cut inside its length parsed without error")
	}
}

func TestL73DescribeNamesTheClientHelloAndAlerts(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	sni := "secret-name.example"
	conns := []l73Conn{{
		Server: "172.100.100.1:300", SYNAt: t0, Answer: "syn-ack", End: "server-rst", EndAt: t0.Add(time.Second),
		DeviceRecords: 2, ServerRecords: 1,
		Hello: &l73Hello{
			Versions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
			Suites:   []uint16{tls.TLS_AES_128_GCM_SHA256, 0x00ff},
			HasSNI:   true, SNI: sni,
			Groups:  []uint16{uint16(tls.X25519), 0x9999},
			SigAlgs: []uint16{uint16(tls.ECDSAWithP256AndSHA256), 0x0805, 0x9998},
			ALPN:    []string{"a"}, PSKIdentities: 1, EarlyData: true,
		},
		Alerts: []l73Alert{{Level: 2, Description: 40, FromDevice: true}, {Level: 2, Description: 48}},
	}}
	got := l73Describe(conns, t0)
	for _, want := range []string{"2 device TLS records", "1 server TLS records", "TLS 1.3", "TLS 1.2", "TLS_AES_128_GCM_SHA256",
		"0x00ff", "X25519", "0x9999", "ECDSAWithP256AndSHA256", "0x9998", "has_sni true", "alpn 1", "psk_identities 1", "early_data true",
		"alert from device level 2 description 40 (handshake_failure)", "alert from server level 2 description 48 (unknown_ca)"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
	if strings.Contains(got, sni) {
		t.Fatalf("the SNI value is printed: %s", got)
	}
	if hits := l73SummaryLeaks(got); len(hits) > 0 {
		t.Fatalf("%v: %s", hits, got)
	}
}

// A device that sends a few bytes and then closes first shows as such even
// when the server's RST is the connection's last event; only counts are kept.
func TestL73ConnsRecordsWhoClosedFirstAndHowMuchWasSent(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	segs := []l73FakeSeg{
		{true, tcpSYN, 1000, nil, at},
		{false, tcpSYN | tcpACK, 5000, nil, at},
		{true, tcpACK | tcpPSH, 1001, []byte("0123456789"), at.Add(10 * time.Millisecond)},
		{true, tcpFIN | tcpACK, 1011, nil, at.Add(20 * time.Millisecond)},
		{false, tcpACK | tcpPSH, 5001, []byte("abc"), at.Add(25 * time.Millisecond)},
		{false, tcpRST | tcpACK, 5004, nil, at.Add(30 * time.Millisecond)},
	}
	conns, err := l73Conns(l73FakePcap(40010, 300, segs), l73TDevice)
	if err != nil || len(conns) != 1 {
		t.Fatal(conns, err)
	}
	c := conns[0]
	if c.DevicePayloadBytes != 10 || c.ServerPayloadBytes != 3 || !c.DeviceFINAt.Equal(at.Add(20*time.Millisecond)) ||
		!c.DeviceRSTAt.IsZero() || c.End != "device-fin" {
		t.Fatalf("%+v", c)
	}
	got := l73Describe(conns, at)
	for _, want := range []string{"device sent 10 bytes", "server sent 3 bytes", "device fin at +0.02s"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
	if strings.Contains(got, "device rst") || strings.Contains(got, "0123456789") {
		t.Fatal(got)
	}
}

func TestL73DescribeShowsPlainHeaderFieldsOnly(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	conns := []l73Conn{{Server: "172.100.100.1:300", SYNAt: t0, Answer: "syn-ack", End: "server-rst", EndAt: t0,
		Plain: []l73Plain{{Type: 1, SeqNo: 1, Flags: 0x04, Length: 105}}}}
	got := l73Describe(conns, t0)
	if !strings.Contains(got, "1 plain TACACS+ header(s) (type 1 seq_no 1 flags 0x04)") {
		t.Fatal(got)
	}
}

// The gap between the server's first data and the device's next data is the
// device's own delay (a handshake that needs a longer timeout than the
// server's shows here); a connection whose device never answered says so.
func TestL73ConnsMeasuresTheDevicesDelayAfterTheServersFlight(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	segs := []l73FakeSeg{
		{true, tcpSYN, 1000, nil, at},
		{false, tcpSYN | tcpACK, 5000, nil, at},
		{true, tcpACK | tcpPSH, 1001, []byte("0123456789"), at.Add(time.Millisecond)},
		{false, tcpACK | tcpPSH, 5001, []byte("abc"), at.Add(2 * time.Millisecond)},
		{true, tcpACK, 1011, nil, at.Add(3 * time.Millisecond)}, // an ACK is not data
		{true, tcpACK | tcpPSH, 1011, []byte("0123"), at.Add(5002 * time.Millisecond)},
		{false, tcpFIN | tcpACK, 5004, nil, at.Add(5003 * time.Millisecond)},
	}
	var twice []l73FakeSeg
	for _, s := range segs {
		twice = append(twice, s, s)
	}
	conns, err := l73Conns(l73FakePcap(40011, 300, twice), l73TDevice)
	if err != nil || len(conns) != 1 {
		t.Fatal(conns, err)
	}
	c := conns[0]
	if !c.ServerFlightAt.Equal(at.Add(2*time.Millisecond)) || !c.DeviceReplyAt.Equal(at.Add(5002*time.Millisecond)) {
		t.Fatalf("%+v", c)
	}
	if got := l73Describe(conns, at); !strings.Contains(got, "device's next data 5.00s after the server's first data") {
		t.Errorf("missing the gap in %s", got)
	}

	silent := []l73FakeSeg{
		{true, tcpSYN, 1000, nil, at},
		{false, tcpSYN | tcpACK, 5000, nil, at},
		{true, tcpACK | tcpPSH, 1001, []byte("0123456789"), at.Add(time.Millisecond)},
		{false, tcpACK | tcpPSH, 5001, []byte("abc"), at.Add(2 * time.Millisecond)},
		{false, tcpFIN | tcpACK, 5004, nil, at.Add(5 * time.Second)},
	}
	conns, err = l73Conns(l73FakePcap(40012, 300, silent), l73TDevice)
	if err != nil || len(conns) != 1 || !conns[0].DeviceReplyAt.IsZero() {
		t.Fatal(conns, err)
	}
	if got := l73Describe(conns, at); !strings.Contains(got, "device sent no data after the server's first data") {
		t.Errorf("missing the silence in %s", got)
	}

	// A connection the server never sent data on has no gap to state.
	none := []l73FakeSeg{{true, tcpSYN, 1000, nil, at}, {false, tcpRST | tcpACK, 0, nil, at}}
	conns, _ = l73Conns(l73FakePcap(40013, 300, none), l73TDevice)
	if got := l73Describe(conns, at); strings.Contains(got, "server's first data") {
		t.Errorf("a gap stated with no server data: %s", got)
	}
}
