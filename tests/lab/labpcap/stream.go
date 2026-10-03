package labpcap

import (
	"fmt"
	"net"
	"time"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// Port is the TACACS+ port. A packet with neither endpoint on it is not this
// package's business, whatever else it is.
const Port = 49

// Segment is one TCP segment's payload, and where it came from.
//
// StreamOff is what makes a rewriter possible. `tcpdump -i any` sees a packet
// on the bridge *and* on the veth, so every segment appears twice, and the two
// copies carry identical bytes at identical stream offsets. A rewriter that
// patched the reassembled stream and then wrote back through one copy would
// leave the credential in the other. Patching by stream offset reaches both,
// because both claim the same range.
type Segment struct {
	Record     int // index into File.Records
	PayloadOff int // offset of the TCP payload within that record's packet bytes
	StreamOff  int // offset of the payload's first byte within the stream
	Length     int
}

// Stream is one direction of one TCP connection, reassembled by sequence
// number.
//
// The sequence number is not optional here, and the first lab run proved it: a
// reassembly that concatenated payloads in capture order produced a stream
// holding two copies of every TACACS+ packet, and a results note that reported
// eighteen requests where the device had sent nine.
//
// So: a segment whose sequence number is the one expected next is appended, a
// segment that repeats bytes already seen is dropped, and a segment that starts
// beyond the expected point is a gap. A gap stops the decode for that stream
// and is reported, rather than being silently spliced into a packet that never
// existed.
//
// A second thing the sequence number alone cannot do is tell two *connections*
// apart when they share a four-tuple, and these captures do that: during L3's
// relax phase port49d is stopped, so the device's connections are refused and
// it retries. A bare SYN therefore starts a new stream for that four-tuple.
// Duplicate SYNs — the `-i any` copies — carry the same sequence number as the
// stream they would start and are ignored.
type Stream struct {
	Key        string
	Conn       string
	SrcPort    uint16
	FromDevice bool
	Payload    []byte
	Segments   []Segment
	Gap        bool

	started bool
	baseSeq uint32
	synSeq  uint32
	hasSyn  bool
}

// add appends one TCP segment's payload, dropping duplicates and refusing to
// splice across a gap. It records the segment's provenance either way: a
// duplicate carries the same credential bytes as the copy that was kept, and
// has to be rewritten too.
func (s *Stream) add(seq uint32, rec, payloadOff int, payload []byte) {
	if !s.started {
		s.started, s.baseSeq = true, seq
	}
	off := int(int32(seq - s.baseSeq))
	s.Segments = append(s.Segments, Segment{
		Record: rec, PayloadOff: payloadOff, StreamOff: off, Length: len(payload),
	})
	if s.Gap {
		return
	}
	switch {
	case off == len(s.Payload):
		s.Payload = append(s.Payload, payload...)
	case off < len(s.Payload):
		// Starts before the point already reached: a duplicate, possibly
		// overlapping. Keep only the tail that is new.
		if skip := len(s.Payload) - off; skip < len(payload) {
			s.Payload = append(s.Payload, payload[skip:]...)
		}
	default:
		// Starts beyond it: a gap. Splicing here would build a packet that
		// never existed, so the decode for this stream stops instead.
		s.Gap = true
	}
}

// timeOf is the capture time of the earliest record holding the stream's
// byte at off.
func (s *Stream) timeOf(f *File, off int) time.Time {
	first := -1
	for _, g := range s.Segments {
		if off >= g.StreamOff && off < g.StreamOff+g.Length && (first < 0 || g.Record < first) {
			first = g.Record
		}
	}
	if first < 0 {
		return time.Time{}
	}
	return f.TimeOf(first)
}

// Decode is one capture's TACACS+ content: the streams it was reassembled
// from, and every packet framed out of them.
type Decode struct {
	File    *File
	Streams []*Stream
	Packets []Packet
	Gaps    []string
}

// Packet is one TACACS+ packet lifted out of a capture.
type Packet struct {
	Stream     int // index into Decode.Streams
	Conn       string
	SrcPort    uint16
	FromDevice bool
	Header     wire.Header

	// BodyOff is where the body starts within its stream; Body is the body
	// de-obfuscated with the shared key, or the bytes as they lie when the
	// header's unencrypted flag is set.
	BodyOff    int
	Body       []byte
	Obfuscated bool

	// At is when the capture took the record holding the packet's last
	// byte: when the whole packet had been sent. Of the copies of a
	// duplicated segment, the earliest counts.
	At time.Time
}

// Kind names the exchange, for a note or an error.
func (p Packet) Kind() string {
	switch p.Header.Type {
	case wire.TypeAuthen:
		return "AUTHEN"
	case wire.TypeAuthor:
		return "AUTHOR"
	case wire.TypeAcct:
		return "ACCT"
	}
	return fmt.Sprintf("type=%d", p.Header.Type)
}

// Decode reassembles every TCP stream with an endpoint on port 49 and frames
// the TACACS+ packets out of them, de-obfuscating each body with key.
//
// subnet, when non-nil, restricts the decode to packets to or from it, which is
// how a results note excludes the harness's own loopback liveness probes. Pass
// nil to decode everything: a tool that has to find every credential byte in
// the file cannot afford a filter.
func (f *File) Decode(key string, subnet *net.IPNet) (*Decode, error) {
	d := &Decode{File: f}
	live := map[string]*Stream{}
	for i, r := range f.Records {
		fl, ok := FlowOf(f.Link, f.Bytes(r))
		if !ok {
			continue
		}
		if !fl.SYN() && fl.PayloadLen == 0 {
			continue
		}
		if subnet != nil && !subnet.Contains(fl.Src) && !subnet.Contains(fl.Dst) {
			continue
		}
		if fl.DstPort != Port && fl.SrcPort != Port {
			continue
		}
		k := fmt.Sprintf("%s:%d>%s:%d", fl.Src, fl.SrcPort, fl.Dst, fl.DstPort)
		reverse := fmt.Sprintf("%s:%d>%s:%d", fl.Dst, fl.DstPort, fl.Src, fl.SrcPort)
		s := live[k]
		if s != nil && fl.SYN() && !(s.hasSyn && s.synSeq == fl.Seq) {
			// A new connection on a four-tuple this capture has already seen.
			// BOTH directions have to reset: the reply direction never carries
			// a bare SYN — the server answers SYN-ACK — so its stream would
			// otherwise run on across every reconnection and decode each
			// connection's replies on top of the last.
			delete(live, reverse)
			s = nil
		}
		if s == nil {
			fromDevice := fl.DstPort == Port
			shownPort := fl.SrcPort
			if !fromDevice {
				shownPort = fl.DstPort
			}
			s = &Stream{
				Key:        k,
				Conn:       fmt.Sprintf("%s:%d", fl.Src, fl.SrcPort),
				SrcPort:    shownPort,
				FromDevice: fromDevice,
			}
			live[k] = s
			d.Streams = append(d.Streams, s)
		}
		if fl.SYN() {
			s.hasSyn, s.synSeq = true, fl.Seq
		}
		if fl.PayloadLen > 0 {
			s.add(fl.Seq, i, fl.PayloadOff, f.Payload(r, fl))
		}
	}

	for idx, s := range d.Streams {
		if s.Gap {
			d.Gaps = append(d.Gaps, s.Key)
		}
		for i := 0; i+wire.HeaderLen <= len(s.Payload); {
			h, err := wire.DecodeHeader(s.Payload[i : i+wire.HeaderLen])
			if err != nil {
				break
			}
			end := i + wire.HeaderLen + int(h.Length)
			if h.Length > wire.MaxBodyLen || end > len(s.Payload) {
				break
			}
			body := s.Payload[i+wire.HeaderLen : end]
			p := Packet{
				Stream: idx, Conn: s.Conn, SrcPort: s.SrcPort, FromDevice: s.FromDevice,
				Header: h, BodyOff: i + wire.HeaderLen, At: s.timeOf(f, end-1),
			}
			if h.Flags&wire.FlagUnencrypted == 0 {
				p.Obfuscated = true
				p.Body = wire.Obfuscate(h, []byte(key), body)
			} else {
				p.Body = append([]byte(nil), body...)
			}
			d.Packets = append(d.Packets, p)
			i = end
		}
	}
	return d, nil
}
