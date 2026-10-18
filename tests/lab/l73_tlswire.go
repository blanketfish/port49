package lab

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rhwendt/port49/tests/lab/labpcap"
)

// L73's captures are TLS. What is in the clear is the ClientHello, the
// ServerHello and any alert sent before the keys change; everything after is
// ciphertext. The committed evidence is a summary of each connection made
// from those, and its types have no field for session material: no random,
// no legacy session id, no key share, no PSK identity or binder. Counts and
// names stand for those. The raw capture stays in tests/lab/captures/
// (git-ignored).

// l73Hello is what a device's ClientHello says, minus every session byte.
type l73Hello struct {
	LegacyVersion uint16   `json:"legacy_version"`
	Versions      []uint16 `json:"supported_versions,omitempty"`
	Suites        []uint16 `json:"cipher_suites"`
	HasSNI        bool     `json:"has_sni"`
	SNI           string   `json:"sni,omitempty"`
	Groups        []uint16 `json:"supported_groups,omitempty"`
	SigAlgs       []uint16 `json:"signature_algorithms,omitempty"`
	ALPN          []string `json:"alpn,omitempty"`
	PSKIdentities int      `json:"psk_identities"`
	PSKModes      []int    `json:"psk_key_exchange_modes,omitempty"`
	EarlyData     bool     `json:"early_data"`
	Extensions    []uint16 `json:"extensions"`
}

// l73ServerHello is port49's answer: the version and suite it chose, and
// whether it accepted a PSK (a resumption).
type l73ServerHello struct {
	Version     uint16 `json:"selected_version"`
	Suite       uint16 `json:"cipher_suite"`
	PSKSelected bool   `json:"psk_selected"`
	HelloRetry  bool   `json:"hello_retry_request"`
}

// l73Alert is an alert sent in the clear (before the keys change).
type l73Alert struct {
	Level       uint8 `json:"level"`
	Description uint8 `json:"description"`
	FromDevice  bool  `json:"from_device"`
}

// l73Plain is one RFC 8907 header the device sent, without its body.
type l73Plain struct {
	Type   uint8  `json:"type"`
	SeqNo  uint8  `json:"seq_no"`
	Flags  uint8  `json:"flags"`
	Length uint32 `json:"length"`
}

// l73Conn is one TCP connection the device opened.
type l73Conn struct {
	Server        string          `json:"server"`
	DevicePort    uint16          `json:"device_port"`
	SYNAt         time.Time       `json:"syn_at"`
	Answer        string          `json:"answer"` // syn-ack, rst, none
	Hello         *l73Hello       `json:"client_hello,omitempty"`
	ServerHello   *l73ServerHello `json:"server_hello,omitempty"`
	Alerts        []l73Alert      `json:"plaintext_alerts,omitempty"`
	DeviceRecords int             `json:"device_tls_records"`
	ServerRecords int             `json:"server_tls_records"`
	// Byte counts and the device's first FIN and RST: a count, never the
	// bytes. End keeps only the last event; these say who closed first.
	DevicePayloadBytes int        `json:"device_payload_bytes"`
	ServerPayloadBytes int        `json:"server_payload_bytes"`
	DeviceFINAt        time.Time  `json:"device_fin_at,omitzero"`
	DeviceRSTAt        time.Time  `json:"device_rst_at,omitzero"`
	Plain              []l73Plain `json:"plain_tacacs_from_device,omitempty"`
	// Incomplete: the capture lacks bytes of this connection (a segment from
	// its start, or one in a gap), so a missing hello is not evidence the
	// device sent none.
	Incomplete bool      `json:"incomplete"`
	End        string    `json:"end"` // device-fin, server-fin, device-rst, server-rst, open
	EndAt      time.Time `json:"end_at"`
}

type l73Seg struct {
	seq  uint32
	data []byte
}

// l73Conns reads a savefile for every TCP connection the device opened,
// SSH (22) and NETCONF (830) aside, in the order their SYNs were captured.
// tcpdump -i any sees a segment on each interface it crosses; the second
// sighting is dropped.
func l73Conns(raw []byte, device string) ([]l73Conn, error) {
	f, err := labpcap.Parse(raw)
	if err != nil {
		return nil, err
	}
	type key struct {
		port   uint16
		server string
	}
	type state struct {
		c        *l73Conn
		up, down []l73Seg
		seen     map[[4]uint32]bool
		isn      uint32
		srvISN   uint32
		haveSrv  bool
	}
	// conns holds the latest connection on each (device port, server); a SYN
	// with a new sequence number on a used pair is a new connection, since the
	// device may reuse a source port.
	conns := map[key]*state{}
	var order []*state
	for i, r := range f.Records {
		fl, ok := labpcap.FlowOf(f.Link, f.Bytes(r))
		if !ok {
			continue
		}
		fromDevice := fl.Src.String() == device
		var k key
		var serverPort uint16
		switch {
		case fromDevice:
			k, serverPort = key{fl.SrcPort, net.JoinHostPort(fl.Dst.String(), strconv.Itoa(int(fl.DstPort)))}, fl.DstPort
		case fl.Dst.String() == device:
			k, serverPort = key{fl.DstPort, net.JoinHostPort(fl.Src.String(), strconv.Itoa(int(fl.SrcPort)))}, fl.SrcPort
		default:
			continue
		}
		if serverPort == 22 || serverPort == 830 {
			continue
		}
		st := conns[k]
		if fromDevice && fl.SYN() && (st == nil || st.isn != fl.Seq) {
			st = &state{c: &l73Conn{Server: k.server, DevicePort: k.port, SYNAt: f.TimeOf(i), Answer: "none", End: "open"},
				seen: map[[4]uint32]bool{}, isn: fl.Seq}
			conns[k] = st
			order = append(order, st)
		}
		if st == nil {
			continue // a connection is counted from its SYN
		}
		dir := uint32(0)
		if !fromDevice {
			dir = 1
		}
		id := [4]uint32{dir, fl.Seq, uint32(fl.PayloadLen), uint32(fl.Flags)}
		if st.seen[id] {
			continue
		}
		st.seen[id] = true
		const fin, syn, rst, ack = 0x01, 0x02, 0x04, 0x10
		if !fromDevice && fl.Flags&syn != 0 && fl.Flags&ack != 0 && !st.haveSrv {
			st.srvISN, st.haveSrv = fl.Seq, true
		}
		if !fromDevice && st.c.Answer == "none" {
			switch {
			case fl.Flags&syn != 0 && fl.Flags&ack != 0:
				st.c.Answer = "syn-ack"
			case fl.Flags&rst != 0:
				st.c.Answer = "rst"
			}
		}
		if fromDevice {
			st.c.DevicePayloadBytes += fl.PayloadLen
			if fl.Flags&fin != 0 && st.c.DeviceFINAt.IsZero() {
				st.c.DeviceFINAt = f.TimeOf(i)
			}
			if fl.Flags&rst != 0 && st.c.DeviceRSTAt.IsZero() {
				st.c.DeviceRSTAt = f.TimeOf(i)
			}
		} else {
			st.c.ServerPayloadBytes += fl.PayloadLen
		}
		if fl.Flags&(rst|fin) != 0 && st.c.End == "open" {
			who, kind := "device", "fin"
			if !fromDevice {
				who = "server"
			}
			if fl.Flags&rst != 0 {
				kind = "rst"
			}
			st.c.End, st.c.EndAt = who+"-"+kind, f.TimeOf(i)
		}
		if fl.PayloadLen > 0 {
			p := append([]byte(nil), f.Payload(r, fl)...)
			if fromDevice {
				st.up = append(st.up, l73Seg{fl.Seq, p})
			} else {
				st.down = append(st.down, l73Seg{fl.Seq, p})
			}
		}
	}
	out := make([]l73Conn, 0, len(order))
	for _, st := range order {
		c := st.c
		// Streams start at the SYN's sequence number + 1, so a lost first
		// segment shows as incomplete, never as a stream that is not TLS.
		up, upOK := l73StreamFrom(st.up, st.isn+1, true)
		var down []byte
		downOK := true
		if st.haveSrv {
			down, downOK = l73StreamFrom(st.down, st.srvISN+1, true)
		} else if len(st.down) > 0 {
			down, _ = l73StreamFrom(st.down, 0, false)
			downOK = false // data from a server whose SYN-ACK was not captured
		}
		c.Incomplete = !upOK || !downOK
		switch {
		case l73IsTLS(up):
			for _, r := range l73Records(up) {
				c.DeviceRecords++
				if r.typ == 21 && len(r.body) == 2 {
					c.Alerts = append(c.Alerts, l73Alert{r.body[0], r.body[1], true})
				}
			}
			for _, r := range l73Records(down) {
				c.ServerRecords++
				if r.typ == 21 && len(r.body) == 2 {
					c.Alerts = append(c.Alerts, l73Alert{r.body[0], r.body[1], false})
				}
			}
			if m, ok := l73FirstHandshake(up, 1); ok {
				h, err := l73ParseClientHello(m)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", c.Server, err)
				}
				c.Hello = h
			}
			if m, ok := l73FirstHandshake(down, 2); ok {
				s, err := l73ParseServerHello(m)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", c.Server, err)
				}
				c.ServerHello = s
			}
		case len(up) >= 12 && up[0]>>4 == 0xc:
			c.Plain = l73PlainHeaders(up)
		}
		out = append(out, *c)
	}
	return out, nil
}

// l73Stream is one direction's bytes in sequence order, overlaps dropped;
// it stops at the first gap, since what follows one was not captured.
func l73Stream(segs []l73Seg) []byte {
	out, _ := l73StreamFrom(segs, 0, false)
	return out
}

// l73StreamFrom is l73Stream anchored at base when anchored (otherwise at the
// lowest sequence number). complete is false when a gap cut the stream short:
// with an anchor, that includes a missing first segment.
func l73StreamFrom(segs []l73Seg, base uint32, anchored bool) (out []byte, complete bool) {
	if len(segs) == 0 {
		return nil, true
	}
	if !anchored {
		base = segs[0].seq
		for _, s := range segs {
			if int32(s.seq-base) < 0 {
				base = s.seq
			}
		}
	}
	sort.SliceStable(segs, func(i, j int) bool { return int32(segs[i].seq-base) < int32(segs[j].seq-base) })
	for _, s := range segs {
		off, data := int(int32(s.seq-base)), s.data
		if off < 0 {
			if -off >= len(data) {
				continue
			}
			data, off = data[-off:], 0
		}
		if off+len(data) <= len(out) {
			continue
		}
		if off > len(out) {
			return out, false
		}
		out = append(out, data[len(out)-off:]...)
	}
	return out, true
}

type l73Rec struct {
	typ  uint8
	body []byte
}

func l73IsTLS(b []byte) bool { return len(b) >= 3 && b[0] == 22 && b[1] == 3 }

func l73Records(b []byte) []l73Rec {
	var out []l73Rec
	for len(b) >= 5 {
		n := int(binary.BigEndian.Uint16(b[3:5]))
		if len(b) < 5+n {
			break
		}
		out = append(out, l73Rec{b[0], b[5 : 5+n]})
		b = b[5+n:]
	}
	return out
}

// l73FirstHandshake is the body of the first handshake message in the
// stream's leading handshake records, if it is of type want.
func l73FirstHandshake(stream []byte, want uint8) ([]byte, bool) {
	var hs []byte
	for _, r := range l73Records(stream) {
		if r.typ != 22 {
			break
		}
		hs = append(hs, r.body...)
		if len(hs) >= 4 {
			n := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
			if len(hs) >= 4+n {
				if hs[0] != want {
					return nil, false
				}
				return hs[4 : 4+n], true
			}
		}
	}
	return nil, false
}

type l73Reader struct {
	b   []byte
	bad bool
}

func (r *l73Reader) bytes(n int) []byte {
	if n < 0 || len(r.b) < n {
		r.bad, r.b = true, nil
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *l73Reader) u8() uint8 {
	b := r.bytes(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (r *l73Reader) u16() uint16 {
	b := r.bytes(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func (r *l73Reader) vec8() []byte  { return r.bytes(int(r.u8())) }
func (r *l73Reader) vec16() []byte { return r.bytes(int(r.u16())) }

func l73U16s(b []byte) []uint16 {
	var out []uint16
	for len(b) >= 2 {
		out = append(out, binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	return out
}

func l73ParseClientHello(b []byte) (*l73Hello, error) {
	r := &l73Reader{b: b}
	h := &l73Hello{LegacyVersion: r.u16()}
	r.bytes(32) // random: read past, never kept
	r.vec8()    // legacy_session_id: read past, never kept
	h.Suites = l73U16s(r.vec16())
	r.vec8() // compression methods
	exts := &l73Reader{b: r.vec16()}
	if r.bad {
		return nil, errors.New("a ClientHello shorter than its fields")
	}
	for len(exts.b) > 0 && !exts.bad {
		typ := exts.u16()
		data := &l73Reader{b: exts.vec16()}
		h.Extensions = append(h.Extensions, typ)
		switch typ {
		case 0: // server_name
			list := &l73Reader{b: data.vec16()}
			for len(list.b) > 0 && !list.bad {
				nt, name := list.u8(), list.vec16()
				if nt == 0 && !list.bad {
					h.HasSNI, h.SNI = true, string(name)
				}
			}
			data.bad = data.bad || list.bad
		case 10:
			h.Groups = l73U16s(data.vec16())
		case 13:
			h.SigAlgs = l73U16s(data.vec16())
		case 16:
			list := &l73Reader{b: data.vec16()}
			for len(list.b) > 0 && !list.bad {
				h.ALPN = append(h.ALPN, string(list.vec8()))
			}
			data.bad = data.bad || list.bad
		case 41: // pre_shared_key: counted, never copied
			ids := &l73Reader{b: data.vec16()}
			for len(ids.b) > 0 && !ids.bad {
				ids.vec16()
				ids.bytes(4)
				if !ids.bad {
					h.PSKIdentities++
				}
			}
			data.bad = data.bad || ids.bad
		case 42:
			h.EarlyData = true
		case 43:
			h.Versions = l73U16s(data.vec8())
		case 45:
			for _, m := range data.vec8() {
				h.PSKModes = append(h.PSKModes, int(m))
			}
		}
		if data.bad {
			return nil, errors.New("a ClientHello extension cut inside its body")
		}
	}
	if exts.bad {
		return nil, errors.New("a ClientHello extension shorter than its length")
	}
	return h, nil
}

// l73HRR is RFC 8446 §4.1.3's HelloRetryRequest random.
var l73HRR = []byte{0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C}

func l73ParseServerHello(b []byte) (*l73ServerHello, error) {
	r := &l73Reader{b: b}
	s := &l73ServerHello{Version: r.u16()}
	s.HelloRetry = bytes.Equal(r.bytes(32), l73HRR)
	r.vec8()
	s.Suite = r.u16()
	r.u8()
	if r.bad {
		return nil, errors.New("a ServerHello shorter than its fields")
	}
	if len(r.b) == 0 {
		return s, nil
	}
	exts := &l73Reader{b: r.vec16()}
	for len(exts.b) > 0 && !exts.bad {
		typ := exts.u16()
		data := &l73Reader{b: exts.vec16()}
		switch typ {
		case 43:
			s.Version = data.u16()
		case 41:
			s.PSKSelected = true
		}
		if data.bad {
			return nil, errors.New("a ServerHello extension cut inside its body")
		}
	}
	if exts.bad || r.bad {
		return nil, errors.New("a ServerHello extension shorter than its length")
	}
	return s, nil
}

func l73PlainHeaders(b []byte) []l73Plain {
	var out []l73Plain
	for len(b) >= 12 {
		n := binary.BigEndian.Uint32(b[8:12])
		out = append(out, l73Plain{Type: b[1], SeqNo: b[2], Flags: b[3], Length: n})
		if uint64(len(b)) < 12+uint64(n) {
			break
		}
		b = b[12+n:]
	}
	return out
}

var (
	l73LongHex = regexp.MustCompile(`[0-9A-Fa-f]{32,}`)
	l73LongB64 = regexp.MustCompile(`[A-Za-z0-9+/_=-]{40,}`)
)

// l73SummaryLeaks names what a summary holds that it must not: a long hex
// or base64 run, which is the shape a ticket, an identity, a random or a key
// takes once printed. A run is INVALID if it names anything.
func l73SummaryLeaks(s string) []string {
	var hits []string
	if l73LongHex.MatchString(s) {
		hits = append(hits, "a long hex run")
	}
	if l73LongB64.MatchString(s) {
		hits = append(hits, "a long base64 run")
	}
	return hits
}

func l73Host(server string) string {
	h, _, err := net.SplitHostPort(server)
	if err != nil {
		return server
	}
	return h
}

func l73PortOf(server string) uint16 {
	_, p, err := net.SplitHostPort(server)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return uint16(n)
}

// l73FirstPort is the port of the device's first connection to host; false
// when it opened none.
func l73FirstPort(conns []l73Conn, host string) (uint16, bool) {
	for _, c := range conns {
		if l73Host(c.Server) == host {
			return l73PortOf(c.Server), true
		}
	}
	return 0, false
}

// l73Window is the connections to host whose SYN falls in [from, to].
func l73Window(conns []l73Conn, host string, from, to time.Time) []l73Conn {
	var out []l73Conn
	for _, c := range conns {
		if l73Host(c.Server) == host && !c.SYNAt.Before(from) && !c.SYNAt.After(to) {
			out = append(out, c)
		}
	}
	return out
}

// l73Describe is conns as one line, times relative to from.
func l73Describe(conns []l73Conn, from time.Time) string {
	if len(conns) == 0 {
		return "the device opened no connection"
	}
	var parts []string
	for _, c := range conns {
		s := fmt.Sprintf("+%.2fs to %s: %s", c.SYNAt.Sub(from).Seconds(), c.Server, c.Answer)
		if c.ServerHello != nil {
			s += fmt.Sprintf(", %s %s", tls.VersionName(c.ServerHello.Version), tls.CipherSuiteName(c.ServerHello.Suite))
			if c.ServerHello.PSKSelected {
				s += " resumed"
			}
		}
		if c.DevicePayloadBytes > 0 {
			s += fmt.Sprintf(", device sent %d bytes", c.DevicePayloadBytes)
		}
		if c.ServerPayloadBytes > 0 {
			s += fmt.Sprintf(", server sent %d bytes", c.ServerPayloadBytes)
		}
		if !c.DeviceFINAt.IsZero() {
			s += fmt.Sprintf(", device fin at +%.2fs", c.DeviceFINAt.Sub(from).Seconds())
		}
		if !c.DeviceRSTAt.IsZero() {
			s += fmt.Sprintf(", device rst at +%.2fs", c.DeviceRSTAt.Sub(from).Seconds())
		}
		if c.DeviceRecords > 0 || c.ServerRecords > 0 {
			s += fmt.Sprintf(", %d device TLS records, %d server TLS records", c.DeviceRecords, c.ServerRecords)
		}
		if h := c.Hello; h != nil {
			s += ", client_hello (" + l73DescribeHello(h) + ")"
		}
		for _, a := range c.Alerts {
			who := "server"
			if a.FromDevice {
				who = "device"
			}
			s += fmt.Sprintf(", alert from %s level %d description %d (%s)", who, a.Level, a.Description, l73AlertName(a.Description))
		}
		if len(c.Plain) > 0 {
			s += fmt.Sprintf(", %d plain TACACS+ header(s)", len(c.Plain))
		}
		if c.Incomplete {
			s += ", capture incomplete"
		}
		s += ", ended " + c.End
		if !c.EndAt.IsZero() {
			s += fmt.Sprintf(" at +%.2fs", c.EndAt.Sub(from).Seconds())
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, "; ")
}

// l73DescribeHello names what the device offered: versions, suites, groups
// and signature algorithms (hex where Go has no name), whether it sent an SNI
// (never the name), the ALPN count, PSK identities and early data. It prints
// no key share, random or session ID.
func l73DescribeHello(h *l73Hello) string {
	name := func(v uint16, goName string, prefix string) string {
		if goName == "" || strings.HasPrefix(goName, prefix) {
			return fmt.Sprintf("0x%04x", v)
		}
		return goName
	}
	list := func(n int, f func(i int) string) string {
		var out []string
		for i := 0; i < n; i++ {
			out = append(out, f(i))
		}
		return "[" + strings.Join(out, " ") + "]"
	}
	versions := list(len(h.Versions), func(i int) string {
		v := h.Versions[i]
		if n := tls.VersionName(v); !strings.HasPrefix(n, "0x") {
			return n
		}
		return fmt.Sprintf("0x%04x", v)
	})
	suites := list(len(h.Suites), func(i int) string {
		v := h.Suites[i]
		if n := tls.CipherSuiteName(v); !strings.HasPrefix(n, "0x") {
			return n
		}
		return fmt.Sprintf("0x%04x", v)
	})
	groups := list(len(h.Groups), func(i int) string {
		v := h.Groups[i]
		return name(v, tls.CurveID(v).String(), "CurveID(")
	})
	sigs := list(len(h.SigAlgs), func(i int) string {
		v := h.SigAlgs[i]
		return name(v, tls.SignatureScheme(v).String(), "SignatureScheme(")
	})
	return fmt.Sprintf("versions %s; suites %s; groups %s; sig_algs %s; has_sni %v; alpn %d; psk_identities %d; early_data %v",
		versions, suites, groups, sigs, h.HasSNI, len(h.ALPN), h.PSKIdentities, h.EarlyData)
}

var l73AlertNames = map[uint8]string{
	0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 22: "record_overflow", 40: "handshake_failure",
	42: "bad_certificate", 43: "unsupported_certificate", 44: "certificate_revoked", 45: "certificate_expired",
	46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca", 49: "access_denied", 50: "decode_error",
	51: "decrypt_error", 70: "protocol_version", 71: "insufficient_security", 80: "internal_error",
	86: "inappropriate_fallback", 90: "user_canceled", 109: "missing_extension", 110: "unsupported_extension",
	112: "unrecognized_name", 115: "unknown_psk_identity", 116: "certificate_required", 120: "no_application_protocol",
}

func l73AlertName(d uint8) string {
	if n, ok := l73AlertNames[d]; ok {
		return n
	}
	return "unnamed"
}

// l73SettleTail is how long after a login returns its connections still
// count with it (an accounting stop may open late), and how long cells a and h
// let a capture run past their last login.
const l73SettleTail = 5 * time.Second

// l73Span is one login: when it began and when it returned.
type l73Span struct{ Start, End time.Time }

// l73LoginWindows gives each login the connections to host whose SYN falls in
// [Start, End+l73SettleTail). Every window has the same tail, so cell a's
// control and cell h's logins are counted alike. Logins must be at least
// l73SettleTail apart or their windows overlap.
func l73LoginWindows(conns []l73Conn, host string, spans []l73Span) [][]l73Conn {
	out := make([][]l73Conn, len(spans))
	for _, c := range conns {
		if l73Host(c.Server) != host {
			continue
		}
		for i, sp := range spans {
			if !c.SYNAt.Before(sp.Start) && c.SYNAt.Before(sp.End.Add(l73SettleTail)) {
				out[i] = append(out[i], c)
			}
		}
	}
	return out
}
