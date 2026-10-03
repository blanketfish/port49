package labpcap

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// A capture the tests can build a packet at a time.
//
// It is a real little-endian pcap of LINUX_SLL2 frames, which is what
// `tcpdump -i any` writes on this host, so the redactor under test is reading
// the same shape of file in a test as it reads in `make evidence`. The
// alternative — a fixture checked in — would be a capture nobody could edit to
// add the next case.

const (
	synthDevice = "172.100.100.11"
	synthServer = "172.100.100.1"
	synthKey    = labcreds.Key
)

type synth struct {
	buf []byte
	ts  uint32
}

func newSynth() *synth {
	b := make([]byte, FileHeaderLen)
	binary.LittleEndian.PutUint32(b[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(b[4:6], 2) // version major
	binary.LittleEndian.PutUint16(b[6:8], 4) // version minor
	binary.LittleEndian.PutUint32(b[16:20], 262144)
	binary.LittleEndian.PutUint32(b[20:24], LinkLinuxSLL2)
	return &synth{buf: b, ts: 1_758_000_000}
}

// segment appends one TCP segment. A valid checksum is written when valid is
// set, and a deliberately wrong one otherwise — which is what checksum offload
// leaves in a real capture off a veth.
func (s *synth) segment(src, dst string, sport, dport uint16, seq uint32, flags byte, payload []byte, valid bool) {
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 64240)
	copy(tcp[20:], payload)

	ip := make([]byte, 20)
	ip[0], ip[8], ip[9] = 0x45, 64, protoTCP
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(tcp)))
	copy(ip[12:16], net.ParseIP(src).To4())
	copy(ip[16:20], net.ParseIP(dst).To4())
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip))

	if valid {
		binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(net.ParseIP(src), net.ParseIP(dst), tcp))
	} else {
		binary.BigEndian.PutUint16(tcp[16:18], 0x1234)
	}

	sll := make([]byte, 20)
	binary.BigEndian.PutUint16(sll[0:2], etherTypeIPv4)
	pkt := append(append(sll, ip...), tcp...)

	hdr := make([]byte, RecordHeaderLen)
	s.ts++
	binary.LittleEndian.PutUint32(hdr[0:4], s.ts)
	binary.LittleEndian.PutUint32(hdr[4:8], 500)
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(pkt)))
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(len(pkt)))
	s.buf = append(s.buf, hdr...)
	s.buf = append(s.buf, pkt...)
}

func ipChecksum(h []byte) uint16 {
	sum := uint32(0)
	for i := 0; i+1 < len(h); i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(h[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// tacacs frames one TACACS+ packet, obfuscated the way a device would send it.
func tacacs(sessionID uint32, typ wire.Type, seqNo uint8, body []byte) []byte {
	h := wire.Header{
		MajorVersion: wire.MajorVersion, MinorVersion: 0, Type: typ,
		SeqNo: seqNo, SessionID: sessionID, Length: uint32(len(body)),
	}
	return append(h.Encode(), wire.Obfuscate(h, []byte(synthKey), body)...)
}

// exchange writes one TCP connection carrying the given TACACS+ packets, each
// on its own segment, alternating direction by sequence number: odd from the
// device, even from the server.
func (s *synth) exchange(port uint16, pkts [][]byte, fromDevice []bool, valid bool) {
	s.segment(synthDevice, synthServer, port, Port, 1000, flagSYN, nil, valid)
	s.segment(synthServer, synthDevice, Port, port, 2000, flagSYN|flagACK, nil, valid)
	dseq, sseq := uint32(1001), uint32(2001)
	for i, p := range pkts {
		if fromDevice[i] {
			s.segment(synthDevice, synthServer, port, Port, dseq, flagACK, p, valid)
			dseq += uint32(len(p))
		} else {
			s.segment(synthServer, synthDevice, Port, port, sseq, flagACK, p, valid)
			sseq += uint32(len(p))
		}
	}
	s.segment(synthDevice, synthServer, port, Port, dseq, flagACK|0x01, nil, valid)
}

// asciiLogin is the exchange an operator's SSH login produces: the password
// arrives in the CONTINUE's user_msg, which is the field the redactor exists
// for.
func asciiLogin(s *synth, port uint16, sid uint32, user, password string, valid bool) {
	start := wire.AuthenStart{
		Action: wire.AuthenActionLogin, PrivLvl: 15, AuthenType: wire.AuthenTypeASCII,
		Service: wire.AuthenServiceLogin, User: []byte(user), Port: []byte("ssh"),
		RemAddr: []byte("192.0.2.9"),
	}
	getpass := wire.AuthenReply{Status: wire.AuthenStatusGetPass, Flags: 0x01, ServerMsg: []byte("Password: ")}
	cont := wire.AuthenContinue{UserMsg: []byte(password)}
	pass := wire.AuthenReply{Status: wire.AuthenStatusPass, ServerMsg: []byte("port49: welcome")}
	s.exchange(port, [][]byte{
		tacacs(sid, wire.TypeAuthen, 1, start.Encode()),
		tacacs(sid, wire.TypeAuthen, 2, getpass.Encode()),
		tacacs(sid, wire.TypeAuthen, 3, cont.Encode()),
		tacacs(sid, wire.TypeAuthen, 4, pass.Encode()),
	}, []bool{true, false, true, false}, valid)
}

// papLogin puts the password in the START's data, which is where a PAP device
// and an eAPI request put it.
func papLogin(s *synth, port uint16, sid uint32, user, password string, valid bool) {
	start := wire.AuthenStart{
		Action: wire.AuthenActionLogin, PrivLvl: 1, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte(user), Port: []byte("command-api"),
		RemAddr: []byte(synthServer), Data: []byte(password),
	}
	pass := wire.AuthenReply{Status: wire.AuthenStatusPass}
	s.exchange(port, [][]byte{
		tacacs(sid, wire.TypeAuthen, 1, start.Encode()),
		tacacs(sid, wire.TypeAuthen, 2, pass.Encode()),
	}, []bool{true, false}, valid)
}

// authorization and accounting carry no password, and the scan over the real
// captures says so. They are here because the redactor must leave them
// byte-identical, which is only proved by feeding it some.
func authorization(s *synth, port uint16, sid uint32, user string, valid bool) {
	req := wire.AuthorRequest{
		AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 15, AuthenType: wire.AuthenTypeASCII,
		Service: wire.AuthenServiceLogin, User: []byte(user), Port: []byte("ssh"),
		RemAddr: []byte("192.0.2.9"),
		Args:    [][]byte{[]byte("service=shell"), []byte("cmd*"), []byte("priv-lvl=15")},
	}
	resp := wire.AuthorResponse{Status: 0x01, ServerMsg: []byte(""), Args: [][]byte{[]byte("priv-lvl=15")}}
	s.exchange(port, [][]byte{
		tacacs(sid, wire.TypeAuthor, 1, req.Encode()),
		tacacs(sid, wire.TypeAuthor, 2, resp.Encode()),
	}, []bool{true, false}, valid)
}

func accounting(s *synth, port uint16, sid uint32, user string, valid bool) {
	req := wire.AcctRequest{
		Flags: wire.AcctFlagStart, AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 15,
		AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin,
		User: []byte(user), Port: []byte("ssh"), RemAddr: []byte("192.0.2.9"),
		Args: [][]byte{[]byte("task_id=42"), []byte("start_time=1758000000")},
	}
	reply := wire.AcctReply{Status: 0x01}
	s.exchange(port, [][]byte{
		tacacs(sid, wire.TypeAcct, 1, req.Encode()),
		tacacs(sid, wire.TypeAcct, 2, reply.Encode()),
	}, []bool{true, false}, valid)
}

// fullRun is one of each exchange, which is what a lab capture holds.
func fullRun(t *testing.T, valid bool) []byte {
	t.Helper()
	s := newSynth()
	asciiLogin(s, 50001, 0x11111111, "alice01", synthToken, valid)
	papLogin(s, 50002, 0x22222222, "alice02", synthToken2, valid)
	authorization(s, 50003, 0x33333333, "alice01", valid)
	accounting(s, 50004, 0x44444444, "alice01", valid)
	return s.buf
}

// The two credentials the synthetic run puts on the wire. They are shaped like
// the seeded lab tokens — same prefix, same length — so a redactor that only
// worked on some other shape of string would fail here.
const (
	synthToken  = "p49_labtoken01"
	synthToken2 = "p49_labtoken02"
)

func synthOptions() Options {
	return Options{
		Key:     synthKey,
		Secrets: []string{synthToken, synthToken2, labcreds.BreakglassPassword, labcreds.TokenPrefix},
	}
}

// A packet's At is its capture time, read from the record header: a reply
// taken 42 seconds after its request is 42 seconds later, and the later
// duplicate copy of the request (the `-i any` second sighting) does not move
// the request's time.
func TestPacketAtIsTheCaptureTime(t *testing.T) {
	for _, nano := range []bool{false, true} {
		s := newSynth()
		if nano {
			binary.LittleEndian.PutUint32(s.buf[0:4], 0xa1b23c4d)
		}
		req := wire.AuthorRequest{AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 15,
			AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin, User: []byte("alice01"),
			Args: [][]byte{[]byte("service=shell"), []byte("cmd=show")}}
		resp := wire.AuthorResponse{Status: 0x01}
		reqPkt := tacacs(0x55555555, wire.TypeAuthor, 1, req.Encode())
		s.segment(synthDevice, synthServer, 50005, Port, 1000, flagSYN, nil, true)
		s.segment(synthServer, synthDevice, Port, 50005, 2000, flagSYN|flagACK, nil, true)
		s.segment(synthDevice, synthServer, 50005, Port, 1001, flagACK, reqPkt, true)
		s.segment(synthDevice, synthServer, 50005, Port, 1001, flagACK, reqPkt, true) // the duplicate copy
		s.ts += 40
		s.segment(synthServer, synthDevice, Port, 50005, 2001, flagACK, tacacs(0x55555555, wire.TypeAuthor, 2, resp.Encode()), true)

		f, err := Parse(s.buf)
		if err != nil {
			t.Fatal(err)
		}
		d, err := f.Decode(synthKey, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(d.Packets) != 2 {
			t.Fatalf("nano=%v: decoded %d packets, want 2", nano, len(d.Packets))
		}
		if got := d.Packets[1].At.Sub(d.Packets[0].At); got != 42*time.Second {
			t.Errorf("nano=%v: request to reply is %s, want 42s", nano, got)
		}
		frac := 500 * time.Microsecond
		if nano {
			frac = 500 * time.Nanosecond
		}
		if want := time.Unix(int64(newSynth().ts)+3, int64(frac)); !d.Packets[0].At.Equal(want) {
			t.Errorf("nano=%v: the request's At is %s, want %s", nano, d.Packets[0].At, want)
		}
	}
}
