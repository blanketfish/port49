// Package labpcap reads the packet captures the containerlab harness takes.
//
// It exists so that one parser serves three callers that used to need their
// own: the capture bookkeeping in `tests/lab/capture_test.go`, the header facts
// a results note quotes in `tests/lab/wire_pcap_test.go`, and the redactor in
// `tests/lab/cmd/redact-pcap`. The third is why the parsing had to leave the
// test files at all — a tool that rewrites credential bytes out of a capture
// has to agree, byte for byte, with the parser whose output the notes rest on,
// and two implementations of RFC 8907 framing would eventually disagree about
// where a password is.
//
// The reader handles only what this harness produces: a little-endian pcap
// written by `tcpdump -i any`, which on Linux is LINUX_SLL2. It reports what it
// cannot read rather than guessing.
package labpcap

import (
	"encoding/binary"
	"fmt"
	"net"
)

// FileHeaderLen is the 24-byte file header tcpdump writes when it opens a
// savefile. A file this size has captured nothing.
const FileHeaderLen = 24

// RecordHeaderLen is the per-packet header: two timestamp words, the captured
// length, and the original length.
const RecordHeaderLen = 16

// Link-layer types this package understands.
const (
	LinkEthernet  = 1
	LinkLinuxSLL  = 113
	LinkLinuxSLL2 = 276 // what `tcpdump -i any` produces on Linux
)

const (
	etherTypeIPv4 = 0x0800
	protoTCP      = 6

	// TCP flag bits this package reads.
	flagSYN = 0x02
	flagACK = 0x10
)

// Record locates one captured packet inside a File's bytes.
type Record struct {
	HeaderOff int // offset of the 16-byte record header
	DataOff   int // offset of the packet bytes
	InclLen   int // how many bytes were captured
	OrigLen   int // how long the packet was on the wire
}

// Truncated reports a packet the capture holds only part of. The harness
// captures with `-s 0`, so this should never be true; a rewriter must refuse to
// touch one, because the bytes it would compute a checksum over are not all
// there.
func (r Record) Truncated() bool { return r.OrigLen > r.InclLen }

// File is a parsed savefile. Raw is retained: every offset in a Record points
// into it, and the redactor rewrites bytes by those offsets.
type File struct {
	Raw     []byte
	Link    uint32
	Snaplen int
	Records []Record

	// TailBytes counts a trailing partial record. It is not corruption, it is
	// a snapshot: notes are written while tcpdump is still running, so a read
	// can land between a record header and its bytes.
	TailBytes int
}

// Bytes returns one record's captured packet.
func (f *File) Bytes(r Record) []byte { return f.Raw[r.DataOff : r.DataOff+r.InclLen] }

// Parse reads a savefile's bytes.
func Parse(raw []byte) (*File, error) {
	if len(raw) < FileHeaderLen {
		return nil, fmt.Errorf("%d bytes, shorter than a pcap file header", len(raw))
	}
	magic := binary.LittleEndian.Uint32(raw[0:4])
	if magic != 0xa1b2c3d4 && magic != 0xa1b23c4d {
		return nil, fmt.Errorf("unexpected pcap magic %#x; this parser reads only little-endian pcap", magic)
	}
	f := &File{
		Raw:     raw,
		Link:    binary.LittleEndian.Uint32(raw[20:24]),
		Snaplen: int(binary.LittleEndian.Uint32(raw[16:20])),
	}
	for off := FileHeaderLen; off+RecordHeaderLen <= len(raw); {
		inclLen := int(binary.LittleEndian.Uint32(raw[off+8 : off+12]))
		hdrOff := off
		off += RecordHeaderLen
		// snaplen bounds every record's inclLen by construction: tcpdump never
		// stores more of a packet than it captured. A larger value is corruption
		// in the middle of the file, not the truncated tail handled below, and a
		// results note must not quote a count taken from a corrupt capture.
		if f.Snaplen > 0 && inclLen > f.Snaplen {
			return nil, fmt.Errorf("record at offset %d claims %d bytes, more than the file's snaplen of %d; the capture is corrupt",
				hdrOff, inclLen, f.Snaplen)
		}
		if off+inclLen > len(raw) {
			f.TailBytes = len(raw) - hdrOff
			return f, nil
		}
		f.Records = append(f.Records, Record{
			HeaderOff: hdrOff, DataOff: off, InclLen: inclLen,
			OrigLen: int(binary.LittleEndian.Uint32(raw[hdrOff+12 : hdrOff+16])),
		})
		off += inclLen
	}
	// Fewer bytes left than a record header: the same snapshot case.
	end := FileHeaderLen
	if n := len(f.Records); n > 0 {
		end = f.Records[n-1].DataOff + f.Records[n-1].InclLen
	}
	f.TailBytes = len(raw) - end
	return f, nil
}

// linkHeaderLen returns the length of the link-layer header and the offset of
// the two bytes holding its protocol field.
func linkHeaderLen(link uint32) (hdr, protoOff int, ok bool) {
	switch link {
	case LinkLinuxSLL2:
		return 20, 0, true
	case LinkLinuxSLL:
		return 16, 14, true
	case LinkEthernet:
		return 14, 12, true
	}
	return 0, 0, false
}

// IPv4Of pulls the source and destination address out of one captured packet.
func IPv4Of(link uint32, b []byte) (src, dst net.IP, ok bool) {
	hdr, protoOff, ok := linkHeaderLen(link)
	if !ok || len(b) < hdr {
		return nil, nil, false
	}
	if binary.BigEndian.Uint16(b[protoOff:protoOff+2]) != etherTypeIPv4 || len(b) < hdr+20 {
		return nil, nil, false
	}
	ip := b[hdr:]
	if ip[0]>>4 != 4 {
		return nil, nil, false
	}
	return net.IP(ip[12:16]), net.IP(ip[16:20]), true
}

// Flow is everything the harness reads off one TCP packet, with the offsets a
// rewriter needs. Every offset is relative to the start of the captured packet.
type Flow struct {
	Src, Dst         net.IP
	SrcPort, DstPort uint16
	Seq              uint32
	Flags            byte

	IPOff      int
	TCPOff     int
	PayloadOff int
	PayloadLen int
}

// SYN reports a bare SYN, which opens a connection.
func (f Flow) SYN() bool { return f.Flags&flagSYN != 0 && f.Flags&flagACK == 0 }

// FlowOf pulls the addresses, ports, sequence number and payload bounds out of
// one captured packet.
func FlowOf(link uint32, b []byte) (Flow, bool) {
	src, dst, ok := IPv4Of(link, b)
	if !ok {
		return Flow{}, false
	}
	hdr, _, _ := linkHeaderLen(link)
	ip := b[hdr:]
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl+20 || ip[9] != protoTCP {
		return Flow{}, false
	}
	tcp := ip[ihl:]
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || dataOff > len(tcp) {
		return Flow{}, false
	}
	return Flow{
		Src: src, Dst: dst,
		SrcPort: binary.BigEndian.Uint16(tcp[0:2]),
		DstPort: binary.BigEndian.Uint16(tcp[2:4]),
		Seq:     binary.BigEndian.Uint32(tcp[4:8]),
		Flags:   tcp[13],

		IPOff:      hdr,
		TCPOff:     hdr + ihl,
		PayloadOff: hdr + ihl + dataOff,
		PayloadLen: len(tcp) - dataOff,
	}, true
}

// Payload returns one record's TCP payload.
func (f *File) Payload(r Record, fl Flow) []byte {
	return f.Raw[r.DataOff+fl.PayloadOff : r.DataOff+fl.PayloadOff+fl.PayloadLen]
}
