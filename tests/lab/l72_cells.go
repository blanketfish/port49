package lab

import (
	"bufio"
	"bytes"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
)

// l72Result is one line of tacacs-tls-client's output.
type l72Result struct {
	Conn      int    `json:"conn"`
	Handshake string `json:"handshake"`
	Error     string `json:"error"`
	Resumed   bool   `json:"resumed"`
	Status    string `json:"status"`
	Flags     int    `json:"flags"`
	After     string `json:"after"`
	ClosedMS  int64  `json:"closed_ms"`
}

func parseL72Result(out []byte) ([]l72Result, error) {
	var rs []l72Result
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var r l72Result
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, err
		}
		rs = append(rs, r)
	}
	return rs, sc.Err()
}

// l72Cell is one register cell: its letter, what it measures, and its run.
// run is set in l72_test.go (build tag lab); here it is only named.
type l72Cell struct {
	id, claim string
}

// l72Cells are spec §15 L72's cells, in its order.
var l72Cells = []l72Cell{
	{"a", "a TLS 1.3 PAP login with a seed token passes; every reply has the unencrypted flag; the record has device.transport and device.cert_sha256 and no key_ref"},
	{"b", "a TLS 1.2-only client: the alert and version_refused"},
	{"c", "no client certificate: the alert and no_client_certificate"},
	{"d", "a leaf from another CA: the alert and unknown_ca"},
	{"e", "an expired leaf: the alert and certificate_expired"},
	{"f", "a leaf naming another device: the alert and identity_mismatch"},
	{"g", "a leaf the CRL lists: the handshake completes, then a reset (no alert), and certificate_revoked"},
	{"h", "a CRL source past nextUpdate and unreachable: the handshake completes, then a reset and status_unavailable; the next connection reset at Accept with no strike and no second record"},
	{"i", "a server name not in server_names: the alert and sni_mismatch; the next connection reset at Accept with no strike and no second record"},
	{"j", "tickets on: the second connection resumes; one ticket presented twice resumes once"},
	{"k", "openssl -early_data with a port49 session: whether early data is sent"},
	{"l", "a packet with the unencrypted flag clear: an ERROR with the flag, then the close"},
	{"m", "a tcp device's address and an address not in the inventory on the TLS listener: no TLS byte before the reset; the records"},
	{"n", "a tls device's address on the RFC 8907 listener: a reset after its header; transport_mismatch"},
	{"o", "a TCP connection that sends nothing: closed at handshake_timeout; handshake_timeout"},
}

// l72SecretMarkers are the substrings (matched case-insensitively) of the
// lines openssl s_client prints that carry TLS session secrets: the
// resumption PSK, the ticket and its identity, the master key, the session
// ids. None of them may reach a committed transcript.
var l72SecretMarkers = []string{"session-id", "psk", "master-key", "tls session ticket"}

// l72HexLine is a line of openssl's hex dump (`0000 - 7f 3a ...`).
var l72HexLine = regexp.MustCompile(`^\s*[0-9a-f]{4} - [0-9a-f]{2} `)

// l72HexTail is the wrapped last line of a hex dump, as it arrives when
// stderr interleaves with the dump: a short offset (or the end of one), the
// bytes, then the ASCII column (`6 de ad be ef   ......W0`).
var l72HexTail = regexp.MustCompile(`^\s*[0-9a-f]{1,4} (?:[0-9a-f]{2}[ -]){1,16} {2,}.*$`)

// l72HexBytes is two hex bytes in a row, anywhere in a line.
var l72HexBytes = regexp.MustCompile(`(?:\b[0-9a-f]{2}[ -]){2}`)

// l72DumpField is a `Key:` line, which ends a dump a marker opened.
var l72DumpField = regexp.MustCompile(`^\s*[a-z][a-z0-9 ./_-]*:(\s|$)`)

// l72FilterTranscript drops from an openssl s_client transcript every line
// that carries a session secret, and every hex dump line wherever it
// stands: s_client dumps only session and handshake bytes, and stderr
// lines interleaved into a dump would end any "after the ticket" state.
// Alert and "Early data" lines are untouched.
func l72FilterTranscript(s string) string {
	var out []string
	inDump := false // after a ticket or PSK marker: every line of hex bytes goes until the dump ends
	for _, line := range strings.Split(s, "\n") {
		low := strings.ToLower(line)
		marked := false
		for _, m := range l72SecretMarkers {
			if strings.Contains(low, m) {
				marked = true
			}
		}
		if marked {
			inDump = true
			continue
		}
		if inDump {
			switch {
			case strings.TrimSpace(low) == "" || l72DumpField.MatchString(low):
				inDump = false
			case l72HexBytes.MatchString(low):
				continue // a dump line, however it starts; stderr noise between them stays
			}
		}
		if l72HexLine.MatchString(low) || l72HexTail.MatchString(low) || strings.Contains(low, "<spaces/nuls>") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// l72TranscriptLeaks names what a transcript still carries of the above:
// the run is INVALID if it names anything.
func l72TranscriptLeaks(s string) []string {
	var hits []string
	low := strings.ToLower(s)
	for _, m := range l72SecretMarkers {
		if strings.Contains(low, m) {
			hits = append(hits, m)
		}
	}
	for _, line := range strings.Split(low, "\n") {
		if l72HexLine.MatchString(line) || l72HexTail.MatchString(line) {
			hits = append(hits, "a hex dump line")
			break
		}
	}
	return hits
}

// l72CredentialHash is a decision record's credential_sha256 value, or the
// seed record's token_sha256 (the same hash), quoted. l72CredentialHashes is
// the array form a mint record writes (`"token_sha256":["<hex>"]`): its
// whole bracket is the value.
var (
	l72CredentialHash   = regexp.MustCompile(`("(?:credential|token)_sha256"\s*:\s*")[0-9A-Fa-f]{64}(")`)
	l72CredentialHashes = regexp.MustCompile(`("(?:credential|token)_sha256"\s*:\s*\[)([^\]]*)(\])`)
	l72Hex64            = regexp.MustCompile(`[0-9A-Fa-f]{64}`)
)

// l72RedactCredentialHash replaces each credential_sha256 and token_sha256
// value in b, a string or an array of them, with "<redacted sha256>",
// keeping the field. The hash is of a single-use seed token and is no use to
// anyone, but evidence names the field and never holds a value (the earlier
// results notes do the same).
func l72RedactCredentialHash(b []byte) []byte {
	b = l72CredentialHash.ReplaceAll(b, []byte("${1}<redacted sha256>${2}"))
	return l72CredentialHashes.ReplaceAllFunc(b, func(m []byte) []byte {
		g := l72CredentialHashes.FindSubmatch(m)
		return append(append(append([]byte{}, g[1]...), l72Hex64.ReplaceAll(g[2], []byte("<redacted sha256>"))...), g[3]...)
	})
}

// l72HashValueLeaks names each *_sha256 key in s that still holds a 64-hex
// value (a string, or inside an array), except cert_sha256, a public
// certificate fingerprint. It is the gate behind the redaction: a shape the
// redaction misses is found here.
func l72HashValueLeaks(s string) []string {
	var out []string
	for _, m := range l72AnyHashValue.FindAllStringSubmatch(s, -1) {
		if m[1] != "cert" && !strings.HasSuffix(m[1], "_cert") && !slices.Contains(out, m[1]+"_sha256") {
			out = append(out, m[1]+"_sha256")
		}
	}
	return out
}

var l72AnyHashValue = regexp.MustCompile(`"([A-Za-z0-9_]+)_sha256"\s*:\s*(?:\[\s*)?(?:"[^"\]]*"\s*,\s*)*"[0-9A-Fa-f]{64}"`)
