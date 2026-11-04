package labpcap

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/blanketfish/port49/tests/lab/labcreds"
)

// Fill is the byte a redacted credential is overwritten with. One byte, the
// same length: the field keeps its length, the body keeps its length, the
// packet keeps its length, and every sequence number in the capture stays the
// number the device really sent.
const Fill = 'x'

// Options configures a redaction pass.
type Options struct {
	// Key is the TACACS+ shared secret the capture was taken under. A body is
	// de-obfuscated with it, its credential bytes overwritten, and the result
	// re-obfuscated under the same header — so the MD5 pad is unchanged and
	// Wireshark decodes the output with the same key.
	Key string

	// KeyFor, when non-nil, names the key a capture was taken under by its
	// base name, overriding Key for that file in RedactDir; "" keeps Key.
	// L28's rotation capture is the one taken under another key
	// (labcreds.CaptureKey).
	KeyFor func(name string) string

	// Secrets are the strings that must not survive. Verify fails if any of
	// them is found anywhere in the output.
	Secrets []string

	// Subnet, when non-nil, is the lab management subnet. A packet to or from
	// it that this pass would drop is an error rather than a drop: results
	// notes quote a device-packet count taken from the capture, and evidence
	// that holds fewer packets than the note claims is evidence of nothing.
	Subnet *net.IPNet

	// SkipFields is a test hook: a credential field whose name is in here is
	// left alone. It exists so a test can prove that a deliberately missed
	// field makes Verify fail — a verifier nobody has ever seen fail is not
	// known to work.
	SkipFields map[string]bool
}

// Stats is what one pass did, for an operator reading the command's output.
type Stats struct {
	RecordsIn      int
	RecordsKept    int
	Dropped        map[string]int // why a record was dropped -> how many
	Streams        int
	Packets        int
	FieldsRedacted int
	BytesRedacted  int
	RecordsPatched int

	// ChecksumsRecomputed counts patched records whose TCP checksum was
	// correct in the input and was made correct again. ChecksumsLeftStale
	// counts patched records whose checksum was already wrong in the input —
	// checksum offload writes the packet to the capture before the NIC fills
	// it in — and which are therefore left exactly as they were found.
	ChecksumsRecomputed int
	ChecksumsLeftStale  int
}

func (s Stats) String() string {
	var drops []string
	for k, n := range s.Dropped {
		drops = append(drops, fmt.Sprintf("%s=%d", k, n))
	}
	sort.Strings(drops)
	d := "none"
	if len(drops) > 0 {
		d = strings.Join(drops, " ")
	}
	return fmt.Sprintf("%d/%d records kept (dropped: %s), %d streams, %d TACACS+ packets, "+
		"%d credential fields (%d bytes) overwritten across %d records, %d checksums recomputed, %d left stale",
		s.RecordsKept, s.RecordsIn, d, s.Streams, s.Packets,
		s.FieldsRedacted, s.BytesRedacted, s.RecordsPatched, s.ChecksumsRecomputed, s.ChecksumsLeftStale)
}

// patch is one byte of one record, rewritten.
type patch struct {
	record int
	off    int // offset within the record's captured packet
	b      byte
}

// Redact returns a copy of a capture holding only its TACACS+ traffic, with
// every credential byte overwritten.
//
// What it guarantees, and what the verifier then re-checks from the output:
//
//   - Only TCP packets with an endpoint on port 49 survive. The harness
//     captures with `tcp port 49`, so in practice nothing is dropped; a packet
//     to or from Options.Subnet is never dropped, and the attempt is an error.
//   - Credential fields are overwritten with Fill, byte for byte. Lengths,
//     sequence numbers, timestamps and every other field are untouched.
//   - A patched packet's TCP checksum is recomputed if it was right to begin
//     with, and left alone if it was not.
func Redact(raw []byte, opt Options) ([]byte, Stats, error) {
	st := Stats{Dropped: map[string]int{}}
	f, err := Parse(raw)
	if err != nil {
		return nil, st, err
	}
	st.RecordsIn = len(f.Records)
	if f.TailBytes > 0 {
		// A short tail is a snapshot, not corruption, when a note is being
		// written mid-run. In a file being committed as evidence it means the
		// capture was never flushed, and the bytes past the last whole record
		// would be silently dropped here.
		return nil, st, fmt.Errorf("the capture ends with %d bytes of a partial record; it was never flushed", f.TailBytes)
	}

	d, err := f.Decode(opt.Key, nil)
	if err != nil {
		return nil, st, err
	}
	st.Streams, st.Packets = len(d.Streams), len(d.Packets)
	if len(d.Gaps) > 0 {
		// Bytes this tool never framed are bytes it cannot search for a
		// password. Refusing is the only safe answer.
		return nil, st, fmt.Errorf("%d stream(s) had a sequence gap (%s): part of this capture was never framed, "+
			"so it cannot be shown to hold no credential", len(d.Gaps), strings.Join(d.Gaps, ", "))
	}

	fields, err := d.Fields()
	if err != nil {
		return nil, st, err
	}

	// Credential bytes, in stream coordinates. The obfuscation is a XOR with a
	// pad derived from the header alone, so rewriting one plaintext byte
	// changes exactly one wire byte: new = wire ^ plain ^ Fill. The pad never
	// has to be recomputed, and the header it is derived from never changes.
	perStream := make([]map[int]byte, len(d.Streams))
	for _, fd := range fields {
		if !fd.Credential || fd.Len == 0 || opt.SkipFields[fd.Name] {
			continue
		}
		p := d.Packets[fd.Packet]
		if perStream[p.Stream] == nil {
			perStream[p.Stream] = map[int]byte{}
		}
		s := d.Streams[p.Stream]
		for k := 0; k < fd.Len; k++ {
			off := p.BodyOff + fd.Off + k
			b := byte(Fill)
			if p.Obfuscated {
				b = s.Payload[off] ^ p.Body[fd.Off+k] ^ Fill
			}
			perStream[p.Stream][off] = b
		}
		st.FieldsRedacted++
		st.BytesRedacted += fd.Len
	}

	// Stream coordinates back to file coordinates. Every segment that claims a
	// range is patched, including the duplicate copies `tcpdump -i any` writes
	// of every packet: they carry the same bytes and would otherwise keep the
	// password the reassembled copy just lost.
	byRecord := map[int][]patch{}
	for i, s := range d.Streams {
		pm := perStream[i]
		if len(pm) == 0 {
			continue
		}
		for _, seg := range s.Segments {
			for off, b := range pm {
				if off < seg.StreamOff || off >= seg.StreamOff+seg.Length {
					continue
				}
				byRecord[seg.Record] = append(byRecord[seg.Record],
					patch{record: seg.Record, off: seg.PayloadOff + (off - seg.StreamOff), b: b})
			}
		}
	}

	if err := checkTLSOpens(f); err != nil {
		return nil, st, err
	}

	out := make([]byte, 0, len(raw))
	out = append(out, raw[:FileHeaderLen]...)
	for i, r := range f.Records {
		pkt := f.Bytes(r)
		fl, ok := FlowOf(f.Link, pkt)
		switch {
		case !ok:
			st.Dropped["not_ipv4_tcp"]++
			if src, dst, isIP := IPv4Of(f.Link, pkt); isIP && opt.Subnet != nil &&
				(opt.Subnet.Contains(src) || opt.Subnet.Contains(dst)) {
				return nil, st, fmt.Errorf("record %d is to or from the lab subnet but is not parseable as TCP; "+
					"dropping it would make the evidence hold fewer device packets than the results note counts", i)
			}
			continue
		case fl.SrcPort != Port && fl.DstPort != Port && fl.SrcPort != TLSPort && fl.DstPort != TLSPort:
			st.Dropped["not_port_49"]++
			if opt.Subnet != nil && (opt.Subnet.Contains(fl.Src) || opt.Subnet.Contains(fl.Dst)) {
				return nil, st, fmt.Errorf("record %d is to or from the lab subnet on ports %d->%d, not TACACS+; "+
					"dropping it would make the evidence hold fewer device packets than the results note counts",
					i, fl.SrcPort, fl.DstPort)
			}
			continue
		}
		st.RecordsKept++

		body := pkt
		if ps := byRecord[i]; len(ps) > 0 {
			if r.Truncated() {
				return nil, st, fmt.Errorf("record %d holds %d of %d bytes and carries a credential: "+
					"a truncated packet cannot be rewritten safely", i, r.InclLen, r.OrigLen)
			}
			body = append([]byte(nil), pkt...)
			for _, p := range ps {
				body[p.off] = p.b
			}
			st.RecordsPatched++
			tcp := body[fl.TCPOff:]
			if checksumOK(fl.Src, fl.Dst, pkt[fl.TCPOff:]) {
				binary.BigEndian.PutUint16(tcp[16:18], 0)
				binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(fl.Src, fl.Dst, tcp))
				st.ChecksumsRecomputed++
			} else {
				// Checksum offload: the kernel handed tcpdump the packet before
				// the NIC filled the field in, so it was already wrong in the
				// input. Computing a correct one here would make the evidence
				// differ from the capture in a way that looks like a fix and
				// reads like a forgery.
				st.ChecksumsLeftStale++
			}
		}
		out = append(out, raw[r.HeaderOff:r.HeaderOff+RecordHeaderLen]...)
		out = append(out, body...)
	}
	return out, st, nil
}

// tcpChecksum computes the RFC 793 checksum over the IPv4 pseudo-header and the
// segment, which must already have its checksum field zeroed.
func tcpChecksum(src, dst net.IP, tcp []byte) uint16 {
	s4, d4 := src.To4(), dst.To4()
	sum := uint32(binary.BigEndian.Uint16(s4[0:2])) + uint32(binary.BigEndian.Uint16(s4[2:4])) +
		uint32(binary.BigEndian.Uint16(d4[0:2])) + uint32(binary.BigEndian.Uint16(d4[2:4])) +
		uint32(protoTCP) + uint32(len(tcp))
	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcp[i : i+2]))
	}
	if len(tcp)%2 == 1 {
		sum += uint32(tcp[len(tcp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// checksumOK reports whether a segment's checksum was right as captured.
func checksumOK(src, dst net.IP, tcp []byte) bool {
	if len(tcp) < 20 {
		return false
	}
	c := append([]byte(nil), tcp...)
	want := binary.BigEndian.Uint16(c[16:18])
	binary.BigEndian.PutUint16(c[16:18], 0)
	return tcpChecksum(src, dst, c) == want
}

// Verify re-reads a redaction pass's output and proves the two things a
// committed evidence file has to be: free of credentials, and otherwise the
// capture it came from.
//
// It parses `out` from scratch rather than trusting anything Redact returned.
// What it asserts:
//
//   - Every credential field of every packet is entirely Fill.
//   - No de-obfuscated body holds any string in opt.Secrets, in any field —
//     including the fields this package does not treat as credentials, which is
//     how an echoed token in an AV pair would be caught.
//   - No credential value from the *input* survives anywhere in the output,
//     decoded or raw.
//   - The output's raw bytes hold none of opt.Secrets.
//   - Record for record, the output is the input's TACACS+ records: same
//     count, same headers, same timestamps, same lengths, same sequence
//     numbers, and byte-identical packets apart from the credential bytes and,
//     where it was recomputed, the two-byte TCP checksum.
func Verify(raw, out []byte, opt Options) error {
	inF, err := Parse(raw)
	if err != nil {
		return fmt.Errorf("input: %w", err)
	}
	outF, err := Parse(out)
	if err != nil {
		return fmt.Errorf("output: %w", err)
	}
	if outF.Link != inF.Link || outF.Snaplen != inF.Snaplen {
		return fmt.Errorf("output link type/snaplen %d/%d does not match the input's %d/%d",
			outF.Link, outF.Snaplen, inF.Link, inF.Snaplen)
	}
	if outF.TailBytes > 0 {
		return fmt.Errorf("output ends with %d bytes of a partial record", outF.TailBytes)
	}

	inD, err := inF.Decode(opt.Key, nil)
	if err != nil {
		return fmt.Errorf("input: %w", err)
	}
	outD, err := outF.Decode(opt.Key, nil)
	if err != nil {
		return fmt.Errorf("output: %w", err)
	}
	if len(outD.Gaps) > 0 {
		return fmt.Errorf("output has %d stream(s) with a sequence gap (%s)", len(outD.Gaps), strings.Join(outD.Gaps, ", "))
	}
	if len(outD.Packets) != len(inD.Packets) {
		return fmt.Errorf("output holds %d TACACS+ packets, the input holds %d", len(outD.Packets), len(inD.Packets))
	}

	inFields, err := inD.Fields()
	if err != nil {
		return fmt.Errorf("input: %w", err)
	}
	outFields, err := outD.Fields()
	if err != nil {
		return fmt.Errorf("output: %w", err)
	}
	if len(outFields) != len(inFields) {
		return fmt.Errorf("output has %d body fields, the input has %d", len(outFields), len(inFields))
	}

	// Every credential the input carried, so the output can be searched for it
	// whether or not it is still in the field it came from. A value that is
	// already all Fill is skipped: it is what redaction writes, so it cannot
	// leak anything, and searching for it would fail every file in which an
	// operator typed such a password (a lab run's deliberate wrong one).
	var carried []string
	for _, fd := range inFields {
		if fd.Credential && fd.Len >= minCarriedLen {
			if v := fd.Bytes(inD.Packets[fd.Packet].Body); !labcreds.Redacted(v) {
				carried = append(carried, string(v))
			}
		}
	}

	for i, fd := range outFields {
		if inFields[i].Name != fd.Name || inFields[i].Packet != fd.Packet ||
			inFields[i].Off != fd.Off || inFields[i].Len != fd.Len {
			return fmt.Errorf("field %d of the output is %s @%d+%d, the input's is %s @%d+%d",
				i, fd.Name, fd.Off, fd.Len, inFields[i].Name, inFields[i].Off, inFields[i].Len)
		}
		b := fd.Bytes(outD.Packets[fd.Packet].Body)
		if fd.Credential && !labcreds.Redacted(b) {
			return fmt.Errorf("packet %d field %s survived redaction: %d bytes, not all %q",
				fd.Packet, fd.Name, fd.Len, string(rune(Fill)))
		}
		if hits := labcreds.Contains(b, opt.Secrets); len(hits) > 0 {
			return fmt.Errorf("packet %d field %s still holds %d lab credential string(s)", fd.Packet, fd.Name, len(hits))
		}
		if hits := labcreds.Contains(b, carried); len(hits) > 0 {
			return fmt.Errorf("packet %d field %s holds %d value(s) a credential field of the input carried",
				fd.Packet, fd.Name, len(hits))
		}
	}

	// The bodies whole, not only the fields: a length byte that pointed past a
	// field would leave credential bytes outside every Field above.
	for i, p := range outD.Packets {
		if hits := labcreds.Contains(p.Body, opt.Secrets); len(hits) > 0 {
			return fmt.Errorf("packet %d body still holds %d lab credential string(s)", i, len(hits))
		}
		if hits := labcreds.Contains(p.Body, carried); len(hits) > 0 {
			return fmt.Errorf("packet %d body holds %d value(s) a credential field of the input carried", i, len(hits))
		}
	}

	// And the file as it lies on disk, obfuscation and all. Nothing here should
	// ever fire — a plaintext credential in an obfuscated capture would mean
	// the key was wrong or the body was never obfuscated — which is why it is
	// cheap to check and worth checking.
	if hits := labcreds.Contains(out, opt.Secrets); len(hits) > 0 {
		return fmt.Errorf("the output file's raw bytes hold %d lab credential string(s) in the clear", len(hits))
	}
	if hits := labcreds.Contains(out, carried); len(hits) > 0 {
		return fmt.Errorf("the output file's raw bytes hold %d credential value(s) from the input in the clear", len(hits))
	}

	return verifyBytes(inF, outF, inD, opt)
}

// minCarriedLen is the shortest credential value worth searching the output
// for. Below it a "credential" is a byte or two that would match by accident —
// a one-character ASCII password field, or the trailing NUL some devices send.
const minCarriedLen = 8

// verifyBytes walks the two files record for record and proves the output is
// the input everywhere it is allowed to be.
func verifyBytes(inF, outF *File, inD *Decode, opt Options) error {
	// The positions the redactor was allowed to touch, re-derived from the
	// input rather than taken from the pass that wrote the output.
	allowed := map[int]map[int]bool{} // record -> offsets
	fields, err := inD.Fields()
	if err != nil {
		return err
	}
	for _, fd := range fields {
		if !fd.Credential || fd.Len == 0 {
			continue
		}
		p := inD.Packets[fd.Packet]
		s := inD.Streams[p.Stream]
		for _, seg := range s.Segments {
			for k := 0; k < fd.Len; k++ {
				off := p.BodyOff + fd.Off + k
				if off < seg.StreamOff || off >= seg.StreamOff+seg.Length {
					continue
				}
				if allowed[seg.Record] == nil {
					allowed[seg.Record] = map[int]bool{}
				}
				allowed[seg.Record][seg.PayloadOff+(off-seg.StreamOff)] = true
			}
		}
	}

	var kept []Record
	for _, r := range inF.Records {
		fl, ok := FlowOf(inF.Link, inF.Bytes(r))
		if !ok || (fl.SrcPort != Port && fl.DstPort != Port && fl.SrcPort != TLSPort && fl.DstPort != TLSPort) {
			continue
		}
		kept = append(kept, r)
	}
	if len(kept) != len(outF.Records) {
		return fmt.Errorf("output holds %d records, the input holds %d TACACS+ records", len(outF.Records), len(kept))
	}

	byOff := map[int]int{} // input record offset -> its index, to find its allowed set
	for i, r := range inF.Records {
		byOff[r.HeaderOff] = i
	}
	for i, or := range outF.Records {
		ir := kept[i]
		idx := byOff[ir.HeaderOff]
		if or.InclLen != ir.InclLen || or.OrigLen != ir.OrigLen {
			return fmt.Errorf("record %d: output is %d/%d bytes, input is %d/%d", i, or.InclLen, or.OrigLen, ir.InclLen, ir.OrigLen)
		}
		// The timestamp words, verbatim.
		if string(outF.Raw[or.HeaderOff:or.HeaderOff+RecordHeaderLen]) !=
			string(inF.Raw[ir.HeaderOff:ir.HeaderOff+RecordHeaderLen]) {
			return fmt.Errorf("record %d: the record header changed", i)
		}
		ip, op := inF.Bytes(ir), outF.Bytes(or)
		fl, ok := FlowOf(inF.Link, ip)
		if !ok {
			return fmt.Errorf("record %d: the input record no longer parses as TCP", i)
		}
		cksumLo, cksumHi := fl.TCPOff+16, fl.TCPOff+18
		for k := range ip {
			if ip[k] == op[k] {
				continue
			}
			if k >= cksumLo && k < cksumHi {
				continue // recomputed, and checked below
			}
			if allowed[idx][k] {
				continue
			}
			return fmt.Errorf("record %d: byte %d changed and is neither a credential byte nor the TCP checksum", i, k)
		}
		// A changed checksum has to be a correct one; an unchanged one has to
		// be as wrong as it was found.
		if string(ip[cksumLo:cksumHi]) != string(op[cksumLo:cksumHi]) {
			if !checksumOK(fl.Src, fl.Dst, op[fl.TCPOff:]) {
				return fmt.Errorf("record %d: the TCP checksum was rewritten and is still wrong", i)
			}
		}
	}
	return nil
}

// checkTLSOpens refuses a capture in which a connection to or from TLSPort carries data that does
// not open with a TLS handshake record in some direction. It names the connection, never bytes.
func checkTLSOpens(f *File) error {
	seen := map[string]bool{}
	for _, r := range f.Records {
		pkt := f.Bytes(r)
		fl, ok := FlowOf(f.Link, pkt)
		if !ok || (fl.SrcPort != TLSPort && fl.DstPort != TLSPort) || fl.PayloadLen == 0 {
			continue
		}
		k := fmt.Sprintf("%s:%d>%s:%d", fl.Src, fl.SrcPort, fl.Dst, fl.DstPort)
		if seen[k] {
			continue
		}
		seen[k] = true
		if fl.PayloadLen < 2 || pkt[fl.PayloadOff] != 0x16 || pkt[fl.PayloadOff+1] != 0x03 {
			return fmt.Errorf("the connection %s carries data on port %d that does not open with a TLS handshake record; "+
				"it may be plain TACACS+, which this tool would not redact there", k, TLSPort)
		}
	}
	return nil
}
