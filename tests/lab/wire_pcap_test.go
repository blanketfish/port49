//go:build lab

package lab

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/tacacs/wire"
	"github.com/blanketfish/port49/tests/lab/labpcap"
)

// Header facts read back out of a capture.
//
// The decision log cannot answer these. A record carries a ctx_id and a
// session, not the TCP connection it arrived on, not the header `session_id`,
// not the single-connect flag, and not the fixed fields of the body — the
// authentication action, type and service, or the `authen_method` a device
// claims on an authorization request. Those are the fields an adapter is
// written against and the ones that say whether two exchanges can be joined up
// at all, which is the whole question behind the login-context key.
//
// This decodes them from the capture the test already takes, using the daemon's
// own wire package rather than a second implementation of RFC 8907. The bodies
// are obfuscated with the shared key, which the harness knows, so decoding them
// costs nothing but the key the lab publishes anyway.
//
// **No credential material leaves this file.** An AuthenStart's `data` carries
// the password on a PAP exchange and an AuthenContinue's `user_msg` carries it
// on an ASCII one; both are reported as a byte count and never as bytes. The
// username, `port` and `rem_addr` are reported in full, because those are the
// measurement.

// wirePacket is one TACACS+ packet lifted out of a capture, with the
// credential-free rendering a note prints.
//
// The framing — pcap records, TCP reassembly, RFC 8907 packet boundaries and
// the de-obfuscation — is labpcap's, shared with the redactor that writes
// tests/lab/evidence. Only the rendering is here.
type wirePacket struct {
	labpcap.Packet
	decoded   string // credential-free rendering of the body
	decodeErr error
}

// pcapTACACSPackets decodes every TACACS+ packet in a capture.
//
// The reassembly it rests on is labpcap's, and the two properties that make its
// counts trustworthy are documented there: duplicate segments (`tcpdump -i any`
// sees each one on the bridge and on the veth) are dropped, and a four-tuple
// reused by a reconnecting device starts a fresh stream rather than decoding
// the new connection's replies on top of the old one's.
func pcapTACACSPackets(path, key string) ([]wirePacket, []string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	f, err := labpcap.Parse(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	_, subnet, err := net.ParseCIDR(labSubnet)
	if err != nil {
		return nil, nil, err
	}
	// The subnet filter is what keeps the harness's own loopback liveness
	// probes out of a note's counts.
	d, err := f.Decode(key, subnet)
	if err != nil {
		return nil, nil, err
	}
	out := make([]wirePacket, 0, len(d.Packets))
	for _, p := range d.Packets {
		w := wirePacket{Packet: p}
		w.decoded, w.decodeErr = describeBody(p.Header, p.Body)
		out = append(out, w)
	}
	return out, d.Gaps, nil
}

// describeBody renders one packet's body without any credential material.
func describeBody(h wire.Header, body []byte) (string, error) {
	switch h.Type {
	case wire.TypeAuthen:
		switch {
		case h.SeqNo == 1:
			p, err := wire.DecodeAuthenStart(body)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("START action=%s authen_type=%s service=%s priv_lvl=%d user=%q port=%q rem_addr=%q data=%d bytes",
				authenActionName(p.Action), authenTypeName(p.AuthenType), authenServiceName(p.Service),
				p.PrivLvl, p.User, p.Port, p.RemAddr, len(p.Data)), nil
		case h.SeqNo%2 == 0:
			p, err := wire.DecodeAuthenReply(body)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("REPLY status=%s flags=%#02x server_msg=%q data=%d bytes",
				authenStatusName(p.Status), p.Flags, p.ServerMsg, len(p.Data)), nil
		default:
			p, err := wire.DecodeAuthenContinue(body)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("CONTINUE flags=%#02x user_msg=%d bytes data=%d bytes",
				p.Flags, len(p.UserMsg), len(p.Data)), nil
		}
	case wire.TypeAuthor:
		if h.SeqNo%2 == 1 {
			p, err := wire.DecodeAuthorRequest(body)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("REQUEST authen_method=%s authen_type=%s service=%s priv_lvl=%d user=%q port=%q rem_addr=%q args=[%s]",
				authenMethodName(p.AuthenMethod), authenTypeName(p.AuthenType), authenServiceName(p.Service),
				p.PrivLvl, p.User, p.Port, p.RemAddr, joinArgs(p.Args)), nil
		}
		p, err := wire.DecodeAuthorResponse(body)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("RESPONSE status=%#02x server_msg=%q args=[%s]", p.Status, p.ServerMsg, joinArgs(p.Args)), nil
	case wire.TypeAcct:
		if h.SeqNo%2 == 1 {
			p, err := wire.DecodeAcctRequest(body)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("REQUEST flags=%s authen_method=%s authen_type=%s service=%s priv_lvl=%d user=%q port=%q rem_addr=%q args=[%s]",
				acctFlagsName(p.Flags), authenMethodName(p.AuthenMethod), authenTypeName(p.AuthenType),
				authenServiceName(p.Service), p.PrivLvl, p.User, p.Port, p.RemAddr, joinArgs(p.Args)), nil
		}
		p, err := wire.DecodeAcctReply(body)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("REPLY status=%#02x server_msg=%q", p.Status, p.ServerMsg), nil
	}
	return "", fmt.Errorf("unknown packet type %d", h.Type)
}

// joinArgs renders authorization and accounting AV pairs. They never carry a
// credential: the protocol's password fields are in the authentication body,
// which is where the redaction above lives.
func joinArgs(args [][]byte) string {
	var out []string
	for _, a := range args {
		out = append(out, string(a))
	}
	return strings.Join(out, " ")
}

func authenActionName(a uint8) string {
	switch a {
	case wire.AuthenActionLogin:
		return "login(1)"
	case wire.AuthenActionChPass:
		return "chpass(2)"
	case wire.AuthenActionSendAuth:
		return "sendauth(4)"
	}
	return fmt.Sprintf("unknown(%d)", a)
}

func authenTypeName(t uint8) string {
	switch t {
	case 0:
		return "not-set(0)"
	case wire.AuthenTypeASCII:
		return "ascii(1)"
	case wire.AuthenTypePAP:
		return "pap(2)"
	case wire.AuthenTypeCHAP:
		return "chap(3)"
	case wire.AuthenTypeMSCHAP:
		return "mschap(5)"
	case wire.AuthenTypeMSCHAPv2:
		return "mschapv2(6)"
	}
	return fmt.Sprintf("unknown(%d)", t)
}

func authenServiceName(s uint8) string {
	switch s {
	case wire.AuthenServiceNone:
		return "none(0)"
	case wire.AuthenServiceLogin:
		return "login(1)"
	case wire.AuthenServiceEnable:
		return "enable(2)"
	case wire.AuthenServicePPP:
		return "ppp(3)"
	}
	return fmt.Sprintf("unknown(%d)", s)
}

func authenStatusName(s uint8) string {
	switch s {
	case wire.AuthenStatusPass:
		return "PASS(1)"
	case wire.AuthenStatusFail:
		return "FAIL(2)"
	case wire.AuthenStatusGetData:
		return "GETDATA(3)"
	case wire.AuthenStatusGetUser:
		return "GETUSER(4)"
	case wire.AuthenStatusGetPass:
		return "GETPASS(5)"
	case wire.AuthenStatusRestart:
		return "RESTART(6)"
	case wire.AuthenStatusError:
		return "ERROR(7)"
	}
	return fmt.Sprintf("status(%#02x)", s)
}

func authenMethodName(m uint8) string {
	switch m {
	case wire.AuthenMethodNotSet:
		return "not-set(0)"
	case wire.AuthenMethodNone:
		return "none(1)"
	case wire.AuthenMethodKRB5:
		return "krb5(2)"
	case wire.AuthenMethodLine:
		return "line(3)"
	case wire.AuthenMethodEnable:
		return "enable(4)"
	case wire.AuthenMethodLocal:
		return "local(5)"
	case wire.AuthenMethodTACACSPlus:
		return "tacacsplus(6)"
	case wire.AuthenMethodGuest:
		return "guest(8)"
	case wire.AuthenMethodRADIUS:
		return "radius(16)"
	}
	return fmt.Sprintf("unknown(%d)", m)
}

func acctFlagsName(f uint8) string {
	var parts []string
	if f&wire.AcctFlagStart != 0 {
		parts = append(parts, "start")
	}
	if f&wire.AcctFlagStop != 0 {
		parts = append(parts, "stop")
	}
	if f&wire.AcctFlagWatchdog != 0 {
		parts = append(parts, "watchdog")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%#02x", f)
	}
	return strings.Join(parts, "+")
}

// TestWirePcapSelfCheck decodes whatever captures this checkout already holds
// and asserts the two properties the reassembly exists to guarantee: no
// sequence gap, and no packet decoded twice.
//
// It deploys nothing and needs no device, and it is here because the bug it
// guards was invisible in the output. The first version of this parser
// concatenated payloads in capture order, `tcpdump -i any` handed it every
// segment twice, and the note it produced was perfectly well-formed and said
// the device had sent eighteen requests when it had sent nine. A count that is
// exactly double is not a count that looks wrong.
//
// Captures are git-ignored, so a fresh checkout has none and this skips. That
// is not the "a test that measured nothing must fail" rule bending: this
// measures a parser, not a device, and its input is a by-product of other runs
// rather than something it can produce for itself.
func TestWirePcapSelfCheck(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("repository root: %v", err)
	}
	files, _ := filepath.Glob(filepath.Join(root, "tests", "lab", "captures", "*.pcap"))
	key := os.Getenv("PORT49_LAB_KEY")
	if key == "" {
		key = labKeyDefault
	}

	decoded := 0
	for _, f := range files {
		pkts, gaps, err := pcapTACACSPackets(f, key)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
			continue
		}
		if len(gaps) > 0 {
			t.Errorf("%s: %d stream(s) had a sequence gap (%s); the decode stopped there and anything after it "+
				"is missing from every note that quotes this capture", filepath.Base(f), len(gaps), strings.Join(gaps, ", "))
		}
		seen := map[string]int{}
		for _, p := range pkts {
			decoded++
			// Keyed on the STREAM, not the connection string. A device that
			// retries an exchange opens a new connection and keeps the same
			// `session_id`, so port49 answers twice and both replies are real
			// packets — `L3-arista_eos.pcap` holds several. Keying on
			// `172.100.100.1:49`, which is every reply's source, called those
			// legitimate retries duplicates.
			seen[fmt.Sprintf("%d|%#08x|%d", p.Stream, p.Header.SessionID, p.Header.SeqNo)]++
		}
		for k, n := range seen {
			if n > 1 {
				t.Errorf("%s: stream|session|seq %s decoded %d times. Duplicate segments are reaching one "+
					"stream, so every count in every note from this capture is wrong by that factor",
					filepath.Base(f), k, n)
			}
		}
	}
	if !t.Failed() {
		t.Logf("decoded %d TACACS+ packets across %d capture file(s) with no gap and no duplicate", decoded, len(files))
	}
	if decoded == 0 {
		t.Skipf("no capture in tests/lab/captures holds a decodable TACACS+ packet (%d file(s) present); "+
			"captures are git-ignored, so a checkout that has not run the lab has nothing to check", len(files))
	}
}

// ---------------------------------------------------------------------------
// The note section
// ---------------------------------------------------------------------------

// tacacsHeaderFacts renders, for a results note, everything the decision log
// does not carry: one line per packet, then the four summary answers.
func (l *lab) tacacsHeaderFacts() string {
	key := os.Getenv("PORT49_LAB_KEY")
	if key == "" {
		key = labKeyDefault
	}
	pkts, gaps, err := pcapTACACSPackets(l.capAbs, key)
	if err != nil {
		return fmt.Sprintf("Not measured: the capture could not be decoded (%v).\n", err)
	}
	if len(pkts) == 0 {
		return "Not measured: the capture holds no TACACS+ packet this parser could decode. Either the device " +
			"never connected, or it used a key this harness does not hold.\n"
	}

	var b strings.Builder
	b.WriteString("Decoded from the capture with the daemon's own `internal/tacacs/wire` package and the lab " +
		"shared key. Passwords are never rendered: an AUTHEN START's `data` and a CONTINUE's `user_msg` are " +
		"reported as byte counts, which is where a PAP password and an ASCII one respectively live. " +
		"`tcpdump -i any` sees each segment twice, on the bridge and on the veth, so the streams are " +
		"reassembled by TCP sequence number and the duplicates dropped before anything below is counted.\n\n")
	if len(gaps) > 0 {
		fmt.Fprintf(&b, "**Incomplete:** %d stream(s) had a sequence gap and were decoded only as far as it "+
			"(%s). Everything after the gap on those streams is missing from this table.\n\n",
			len(gaps), strings.Join(gaps, ", "))
	}
	b.WriteString("| device connection | session_id | seq | single-connect | packet |\n|---|---|---|---|---|\n")
	for _, p := range pkts {
		sc := "clear"
		if p.Header.Flags&wire.FlagSingleConnect != 0 {
			sc = "**SET**"
		}
		dir := "→"
		if !p.FromDevice {
			dir = "←"
		}
		body := p.decoded
		if p.decodeErr != nil {
			body = "**undecodable**: " + p.decodeErr.Error()
		}
		fmt.Fprintf(&b, "| %s %s | `%#08x` | %d | %s | %s %s |\n",
			p.Conn, dir, p.Header.SessionID, p.Header.SeqNo, sc, p.Kind(),
			strings.ReplaceAll(body, "|", "\\|"))
	}

	// The four answers, computed rather than asserted.
	connSessions := map[string]map[uint32]bool{}
	sessionConns := map[uint32]map[string]bool{}
	exchangeConns := map[string]map[string]bool{} // exchange kind -> connections
	singleConnect := 0
	requests := 0
	for _, p := range pkts {
		if !p.FromDevice {
			continue
		}
		requests++
		if p.Header.Flags&wire.FlagSingleConnect != 0 {
			singleConnect++
		}
		if connSessions[p.Conn] == nil {
			connSessions[p.Conn] = map[uint32]bool{}
		}
		connSessions[p.Conn][p.Header.SessionID] = true
		if sessionConns[p.Header.SessionID] == nil {
			sessionConns[p.Header.SessionID] = map[string]bool{}
		}
		sessionConns[p.Header.SessionID][p.Conn] = true
		if exchangeConns[p.Kind()] == nil {
			exchangeConns[p.Kind()] = map[string]bool{}
		}
		exchangeConns[p.Kind()][p.Conn] = true
	}

	maxSessionsPerConn := 0
	for _, s := range connSessions {
		if len(s) > maxSessionsPerConn {
			maxSessionsPerConn = len(s)
		}
	}
	var kinds []string
	for k, conns := range exchangeConns {
		kinds = append(kinds, fmt.Sprintf("%s on %d connection(s)", k, len(conns)))
	}
	sort.Strings(kinds)

	fmt.Fprintf(&b, "\n- **TCP connections the device opened:** %d, carrying %d distinct `session_id`(s). "+
		"The busiest connection carried **%d** `session_id`(s).\n",
		len(connSessions), len(sessionConns), maxSessionsPerConn)
	if maxSessionsPerConn <= 1 && len(connSessions) > 1 {
		b.WriteString("  That is **one TCP connection per exchange**: the device tears the connection down and " +
			"opens another for the next one, so nothing at the transport layer joins two exchanges either.\n")
	} else if maxSessionsPerConn > 1 {
		b.WriteString("  So the device **multiplexes** several exchanges onto one connection.\n")
	}
	fmt.Fprintf(&b, "- **Single-connect flag:** set on %d of %d requests from the device.", singleConnect, requests)
	if singleConnect == 0 {
		b.WriteString(" The device never asks to hold the connection open, whatever it then does with it.")
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "- **Exchanges seen:** %s.\n", strings.Join(kinds, ", "))
	b.WriteString("- **What `session_id` can join:** a `session_id` that appears on exactly one connection and " +
		"under exactly one exchange links the packets *within* that exchange — a START and its CONTINUE, which " +
		"is what makes an ASCII login work at all — and links nothing across exchanges. Read the table: if the " +
		"authentication and the authorization for one login carry different `session_id`s, no field in the " +
		"header joins them, and the login-context key cannot be built out of one.\n")
	return b.String()
}
