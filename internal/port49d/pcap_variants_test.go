package port49d

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// Synthetic captures, built here from headers and made-up bytes, one per way a
// real capture can differ: link type, byte order, timestamp precision, IP
// version, how the stream is cut into segments. A reader that fails any of
// them leaves an operator at 3am with "no whole TACACS+ packet" on a good
// capture.

type vcap struct {
	link  uint32
	order binary.ByteOrder
	magic uint32 // 0xa1b2c3d4 microseconds, 0xa1b23c4d nanoseconds
	v6    bool
	vlans []uint16 // outer tag first: 0x8100 or 0x88a8
	noSYN bool
}

type vseg struct {
	flags   byte
	seq     uint32
	payload []byte
}

var (
	vSrc4 = netip.MustParseAddr("10.20.4.9")
	vSrc6 = netip.MustParseAddr("fd00:20:4::9")
)

// vPacket is a TACACS+ packet whose body is made-up bytes: the reader never
// looks inside it, so it need not be a valid body.
func vPacket(bodyLen int) (pkt, body []byte) {
	body = bytes.Repeat([]byte{0x5a}, bodyLen)
	for i := range body {
		body[i] ^= byte(i * 7)
	}
	h := wire.Header{MajorVersion: wire.MajorVersion, Type: wire.TypeAuthen, SeqNo: 1, SessionID: 0x1234, Length: uint32(bodyLen)}
	return append(h.Encode(), body...), body
}

func (c vcap) build(segs []vseg) []byte {
	var out bytes.Buffer
	gh := make([]byte, 24)
	c.order.PutUint32(gh[0:], c.magic)
	c.order.PutUint16(gh[4:], 2)
	c.order.PutUint16(gh[6:], 4)
	c.order.PutUint32(gh[16:], 65535)
	c.order.PutUint32(gh[20:], c.link)
	out.Write(gh)
	src := vSrc4
	if c.v6 {
		src = vSrc6
	}
	for _, s := range segs {
		if c.noSYN && s.flags&0x02 != 0 {
			continue
		}
		tcp := make([]byte, 20)
		binary.BigEndian.PutUint16(tcp[0:], 40001)
		binary.BigEndian.PutUint16(tcp[2:], 49)
		binary.BigEndian.PutUint32(tcp[4:], s.seq)
		tcp[12], tcp[13] = 5<<4, s.flags
		tcp = append(tcp, s.payload...)
		var ip []byte
		var proto uint16
		if c.v6 {
			ip = make([]byte, 40)
			ip[0], ip[6], ip[7] = 0x60, 6, 64
			binary.BigEndian.PutUint16(ip[4:], uint16(len(tcp)))
			a := src.As16()
			copy(ip[8:], a[:])
			copy(ip[24:], []byte{0xfd, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
			proto = 0x86dd
		} else {
			ip = make([]byte, 20)
			ip[0], ip[8], ip[9] = 0x45, 64, 6
			binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcp)))
			a := src.As4()
			copy(ip[12:], a[:])
			copy(ip[16:], []byte{10, 1, 1, 1})
			proto = 0x0800
		}
		var rec []byte
		switch c.link {
		case linkEthernet:
			rec = vEthertypes(c.vlans, proto)
		case linkLinuxSLL:
			rec = make([]byte, 14)
			rec = binary.BigEndian.AppendUint16(rec, proto)
		case linkRaw:
			rec = nil
		}
		rec = append(append(rec, ip...), tcp...)
		rh := make([]byte, 16)
		c.order.PutUint32(rh[8:], uint32(len(rec)))
		c.order.PutUint32(rh[12:], uint32(len(rec)))
		out.Write(rh)
		out.Write(rec)
	}
	return out.Bytes()
}

// vEthertypes is an Ethernet header's 12 address bytes, then each VLAN tag
// (its TPID and a 2-byte tag control), then the ethertype of what follows.
func vEthertypes(tags []uint16, proto uint16) []byte {
	b := make([]byte, 12)
	for _, tpid := range tags {
		b = binary.BigEndian.AppendUint16(b, tpid)
		b = append(b, 0x00, 0x05)
	}
	return binary.BigEndian.AppendUint16(b, proto)
}

// vStream is a SYN and then pkt cut at the given offsets, in order.
func vStream(pkt []byte, cuts ...int) []vseg {
	segs := []vseg{{flags: 0x02, seq: 1000}}
	at := 0
	for _, end := range append(cuts, len(pkt)) {
		segs = append(segs, vseg{flags: 0x18, seq: uint32(1001 + at), payload: pkt[at:end]})
		at = end
	}
	return segs
}

func TestThePcapReaderReadsEveryVariant(t *testing.T) {
	pkt, body := vPacket(40)
	type kase struct {
		name  string
		cap   vcap
		segs  []vseg
		found bool
		errs  string // a substring of the error, "" for none
	}
	eth := vcap{link: linkEthernet, order: binary.LittleEndian, magic: 0xa1b2c3d4}
	with := func(c vcap, f func(*vcap)) vcap { f(&c); return c }
	two := vStream(pkt, 15)
	cases := []kase{
		{name: "ethernet, little-endian, microseconds", cap: eth, segs: two, found: true},
		{name: "ethernet, big-endian, microseconds", cap: with(eth, func(c *vcap) { c.order = binary.BigEndian }), segs: two, found: true},
		{name: "ethernet, little-endian, nanoseconds", cap: with(eth, func(c *vcap) { c.magic = 0xa1b23c4d }), segs: two, found: true},
		{name: "ethernet, big-endian, nanoseconds", cap: with(eth, func(c *vcap) { c.order, c.magic = binary.BigEndian, 0xa1b23c4d }), segs: two, found: true},
		{name: "ethernet, ipv6", cap: with(eth, func(c *vcap) { c.v6 = true }), segs: two, found: true},
		{name: "ethernet, vlan", cap: with(eth, func(c *vcap) { c.vlans = []uint16{0x8100} }), segs: two, found: true},
		{name: "ethernet, qinq", cap: with(eth, func(c *vcap) { c.vlans = []uint16{0x88a8, 0x8100} }), segs: two, found: true},
		{name: "ethernet, vlan, ipv6", cap: with(eth, func(c *vcap) { c.vlans, c.v6 = []uint16{0x8100}, true }), segs: two, found: true},
		{name: "linux cooked, ipv4", cap: with(eth, func(c *vcap) { c.link = linkLinuxSLL }), segs: two, found: true},
		{name: "linux cooked, ipv6, big-endian", cap: with(eth, func(c *vcap) { c.link, c.v6, c.order = linkLinuxSLL, true, binary.BigEndian }), segs: two, found: true},
		{name: "raw ip, ipv4", cap: with(eth, func(c *vcap) { c.link = linkRaw }), segs: two, found: true},
		{name: "raw ip, ipv6", cap: with(eth, func(c *vcap) { c.link, c.v6 = linkRaw, true }), segs: two, found: true},
		{name: "three segments", cap: eth, segs: vStream(pkt, 5, 30), found: true},
		{name: "a capture that began mid-connection", cap: with(eth, func(c *vcap) { c.noSYN = true }), segs: two, found: true},
		{name: "a retransmitted segment in between", cap: eth, segs: []vseg{
			{flags: 0x02, seq: 1000},
			{flags: 0x18, seq: 1001, payload: pkt[:15]},
			{flags: 0x18, seq: 1001, payload: pkt[:15]}, // the same bytes again
			{flags: 0x18, seq: 1001 + 15, payload: pkt[15:]},
		}, found: true},
		{name: "a segment that overlaps bytes already seen", cap: eth, segs: []vseg{
			{flags: 0x02, seq: 1000},
			{flags: 0x18, seq: 1001, payload: pkt[:15]},
			{flags: 0x18, seq: 1001 + 10, payload: pkt[10:30]},
			{flags: 0x18, seq: 1001 + 30, payload: pkt[30:]},
		}, found: true},
		{name: "a lost segment", cap: eth, segs: []vseg{
			{flags: 0x02, seq: 1000},
			{flags: 0x18, seq: 1001, payload: pkt[:15]},
			{flags: 0x18, seq: 1001 + 30, payload: pkt[30:]}, // bytes 15..30 never seen
		}},
		// Segments out of order: the stream is given up at the first gap, even
		// though everything that follows would complete it. Skipping the gap
		// instead of abandoning the flow would find a packet here.
		{name: "a gap filled later is still a lost segment", cap: eth, segs: []vseg{
			{flags: 0x02, seq: 1000},
			{flags: 0x18, seq: 1001, payload: pkt[:15]},
			{flags: 0x18, seq: 1001 + 30, payload: pkt[30:]},
			{flags: 0x18, seq: 1001 + 15, payload: pkt[15:30]},
			{flags: 0x18, seq: 1001 + 30, payload: pkt[30:]},
		}},
		{name: "a flow that sends more than a packet holds in one segment", cap: eth,
			segs: func() []vseg {
				p, _ := vPacket(10)
				return vStream(append(p, bytes.Repeat([]byte{1}, maxFlowBytes)...))
			}()},
		{name: "a record claiming more than the cap", cap: eth, segs: nil, errs: "damaged"},
	}
	for _, k := range cases {
		t.Run(k.name, func(t *testing.T) {
			raw := k.cap.build(k.segs)
			if k.errs != "" {
				rh := make([]byte, 16)
				k.cap.order.PutUint32(rh[8:], maxCaptureRecord+1)
				raw = append(raw, rh...)
			}
			src := vSrc4
			if k.cap.v6 {
				src = vSrc6
			}
			p, found, err := firstPacketFrom(bytes.NewReader(raw), func(a netip.Addr) bool { return a == src }, 49)
			if k.errs != "" {
				if err == nil || !strings.Contains(err.Error(), k.errs) {
					t.Fatalf("error %v, want one holding %q", err, k.errs)
				}
				return
			}
			if err != nil || found != k.found {
				t.Fatalf("found %v, error %v; want found %v", found, err, k.found)
			}
			if found && (p.hdr.SessionID != 0x1234 || !bytes.Equal(p.body, body)) {
				t.Fatalf("the packet read is not the packet sent (session %#x, %d body bytes)", p.hdr.SessionID, len(p.body))
			}
		})
	}
}
