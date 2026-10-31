package port49d

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// A reader for the classic pcap format (tcpdump -w), just enough for
// `port49d keys-diagnose`: the global header, the record headers, Ethernet
// (with VLAN tags), Linux cooked or raw IP, IPv4 or IPv6, and the TCP stream
// of one source to port 49. It decodes headers only. The bytes of a TACACS+
// body are handed to the key trial and are never printed, logged or decoded.

var (
	errPcapng = errors.New("this is a pcapng file; save the capture in the classic pcap format " +
		"(tcpdump -w FILE writes it; Wireshark's default is pcapng, so save as pcap)")
	errNotPcap = errors.New("this is not a pcap file; save the capture with tcpdump -w FILE")
)

// maxCaptureRecord bounds one record's captured length, so a corrupt length
// cannot ask for gigabytes.
const maxCaptureRecord = 1 << 18

// maxCaptureBytes bounds what one run reads of a capture.
const maxCaptureBytes = 1 << 30

// maxFlowBytes is the most of one flow's stream kept to find its first
// packet: a TACACS+ body of at most wire.MaxBodyLen follows a 12-byte header.
const maxFlowBytes = wire.HeaderLen + wire.MaxBodyLen

// Link types read (LINKTYPE_*).
const (
	linkEthernet = 1
	linkRaw      = 101
	linkLinuxSLL = 113
)

// capturedPacket is the first TACACS+ packet a source sent to port 49: its
// header, and its body as it was on the wire, obfuscated.
type capturedPacket struct {
	hdr  wire.Header
	body []byte
}

// flowKey names one direction of a TCP connection.
type flowKey struct {
	src, dst     netip.Addr
	sport, dport uint16
}

type flow struct {
	started bool
	next    uint32
	buf     []byte
	dead    bool
}

// firstPacketFrom reads the capture r and returns the first complete TACACS+
// packet, in capture order, that a source accepted by from sent to dport. found
// is false when there is none. A flow that starts mid-packet, loses a segment
// or sends something that is not a TACACS+ header is passed over.
func firstPacketFrom(r io.Reader, from func(netip.Addr) bool, dport uint16) (p capturedPacket, found bool, err error) {
	r = io.LimitReader(r, maxCaptureBytes)
	var gh [24]byte
	if _, err := io.ReadFull(r, gh[:]); err != nil {
		return p, false, errNotPcap
	}
	var order binary.ByteOrder
	switch binary.BigEndian.Uint32(gh[:4]) {
	case 0xa1b2c3d4, 0xa1b23c4d:
		order = binary.BigEndian
	case 0xd4c3b2a1, 0x4d3cb2a1:
		order = binary.LittleEndian
	case 0x0a0d0d0a:
		return p, false, errPcapng
	default:
		return p, false, errNotPcap
	}
	link := order.Uint32(gh[20:24])
	if link != linkEthernet && link != linkRaw && link != linkLinuxSLL {
		return p, false, fmt.Errorf("the capture's link type %d is not one this reads (Ethernet, Linux cooked, raw IP)", link)
	}
	flows := map[flowKey]*flow{}
	var rh [16]byte
	for {
		if _, err := io.ReadFull(r, rh[:]); err != nil {
			return p, false, nil // the end of the file, or of its last whole record
		}
		n := order.Uint32(rh[8:12])
		if n > maxCaptureRecord {
			return p, false, fmt.Errorf("a record of %d bytes: the capture is damaged", n)
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(r, data); err != nil {
			return p, false, nil
		}
		key, seq, flags, payload, ok := tcpOf(link, data)
		if !ok || key.dport != dport || !from(key.src) {
			continue
		}
		f := flows[key]
		if f == nil {
			f = &flow{}
			flows[key] = f
		}
		if f.dead {
			continue
		}
		if flags&0x02 != 0 { // SYN: the stream starts after it
			f.started, f.next, f.buf = true, seq+1, f.buf[:0]
			continue
		}
		if len(payload) == 0 {
			continue
		}
		if !f.started { // a capture that began mid-connection: the first data starts the stream
			f.started, f.next = true, seq
		}
		off := int32(f.next - seq)
		switch {
		case off < 0: // a segment was lost: the stream cannot be put together
			f.dead = true
			continue
		case int(off) >= len(payload): // a retransmission
			continue
		}
		payload = payload[off:]
		f.next += uint32(len(payload))
		f.buf = append(f.buf, payload...)
		if len(f.buf) > maxFlowBytes {
			f.dead = true
			continue
		}
		if len(f.buf) < wire.HeaderLen {
			continue
		}
		h, _ := wire.DecodeHeader(f.buf)
		if h.MajorVersion != wire.MajorVersion || h.Type < wire.TypeAuthen || h.Type > wire.TypeAcct ||
			h.Length > wire.MaxBodyLen {
			f.dead = true // not TACACS+ (or not at a packet boundary)
			continue
		}
		if len(f.buf) < wire.HeaderLen+int(h.Length) {
			continue
		}
		return capturedPacket{hdr: h, body: append([]byte(nil), f.buf[wire.HeaderLen:wire.HeaderLen+int(h.Length)]...)}, true, nil
	}
}

// tcpOf parses one record's link, IP and TCP headers. ok is false for anything
// that is not a whole, unfragmented TCP segment.
func tcpOf(link uint32, b []byte) (key flowKey, seq uint32, flags byte, payload []byte, ok bool) {
	var proto uint16
	switch link {
	case linkEthernet:
		if len(b) < 14 {
			return
		}
		proto, b = binary.BigEndian.Uint16(b[12:14]), b[14:]
		for proto == 0x8100 || proto == 0x88a8 { // VLAN tags
			if len(b) < 4 {
				return
			}
			proto, b = binary.BigEndian.Uint16(b[2:4]), b[4:]
		}
	case linkLinuxSLL:
		if len(b) < 16 {
			return
		}
		proto, b = binary.BigEndian.Uint16(b[14:16]), b[16:]
	case linkRaw:
		if len(b) < 1 {
			return
		}
		switch b[0] >> 4 {
		case 4:
			proto = 0x0800
		case 6:
			proto = 0x86dd
		}
	}
	var tcp []byte
	switch proto {
	case 0x0800:
		if len(b) < 20 || b[0]>>4 != 4 {
			return
		}
		ihl := int(b[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(b[2:4]))
		if ihl < 20 || len(b) < ihl || total < ihl || b[9] != 6 || binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
			return // not TCP, or a fragment
		}
		if total > len(b) {
			total = len(b)
		}
		key.src, key.dst = netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20]))
		tcp = b[ihl:total]
	case 0x86dd:
		if len(b) < 40 || b[0]>>4 != 6 || b[6] != 6 {
			return // not TCP directly after the IPv6 header
		}
		plen := int(binary.BigEndian.Uint16(b[4:6]))
		end := 40 + plen
		if end > len(b) {
			end = len(b)
		}
		key.src, key.dst = netip.AddrFrom16([16]byte(b[8:24])), netip.AddrFrom16([16]byte(b[24:40]))
		tcp = b[40:end]
	default:
		return
	}
	if len(tcp) < 20 {
		return
	}
	off := int(tcp[12]>>4) * 4
	if off < 20 || off > len(tcp) {
		return
	}
	key.sport, key.dport = binary.BigEndian.Uint16(tcp[0:2]), binary.BigEndian.Uint16(tcp[2:4])
	key.src, key.dst = key.src.Unmap(), key.dst.Unmap()
	return key, binary.BigEndian.Uint32(tcp[4:8]), tcp[13], tcp[off:], true
}
