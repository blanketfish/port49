package lab

import (
	"bufio"
	"bytes"
	"encoding/json"
	"regexp"
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
	{"i", "a server name not in server_names: the alert and sni_mismatch"},
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

// l72FilterTranscript drops from an openssl s_client transcript every line
// that carries a session secret, and every hex dump line wherever it
// stands: s_client dumps only session and handshake bytes, and stderr
// lines interleaved into a dump would end any "after the ticket" state.
// Alert and "Early data" lines are untouched.
func l72FilterTranscript(s string) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		low := strings.ToLower(line)
		if l72HexLine.MatchString(low) || strings.Contains(low, "<spaces/nuls>") {
			continue
		}
		drop := false
		for _, m := range l72SecretMarkers {
			if strings.Contains(low, m) {
				drop = true
			}
		}
		if !drop {
			out = append(out, line)
		}
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
		if l72HexLine.MatchString(line) {
			hits = append(hits, "a hex dump line")
			break
		}
	}
	return hits
}
