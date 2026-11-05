package labpcap

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/blanketfish/port49/tests/lab/labcreds"
)

// EvidenceReport is what AuditEvidence counted in one evidence file. Counts only: no field
// holds a byte or a string of the file.
type EvidenceReport struct {
	CredentialFields int // credential-carrying fields with at least one byte
	NotFill          int // of those, fields not entirely Fill
	TokenShaped      int // packet bodies holding a token-shaped string or the pre-minting token prefix
	HashShaped       int // authorization and accounting arguments shaped like a password hash
	Unaudited        int // streams not decodable as plain TACACS+: Unframed + TLS
	Unframed         int // port-49 streams with data that framed no TACACS+ packet
	TLS              int // directions of connections on TLSPort (RFC 9887), whose bytes TLS 1.3 hides
	TailBytes        int // bytes after a stream's last whole packet, filled or not
	Other            int // records that are not IPv4 TCP on port 49 or 300
}

// hashShape matches the password hashes and obfuscated secrets a device puts in a command:
// crypt prefixes, Junos $9$ and Arista $aes1$, "key 7" / "password 7" / "secret 7" with its hex,
// and a cleartext "secret 0 ".
var hashShape = regexp.MustCompile(`\$(?:1|5|6|9|aes1)\$|\b(?:key|password|secret) 7 [0-9A-Fa-f]{2,}|\bsecret 0 `)

// AuditEvidence checks one committed evidence file by its shape alone, with no capture and no
// secret list: every credential field is entirely Fill, no body holds a token-shaped string, and no
// authorization or accounting argument looks like a password hash. opt.Key de-obfuscates the
// bodies; opt.Secrets is not used. The error names field kinds and counts, never bytes. The
// report is returned even when the error is not nil.
func AuditEvidence(pcap []byte, opt Options) (EvidenceReport, error) {
	var r EvidenceReport
	f, err := Parse(pcap)
	if err != nil {
		return r, err
	}
	d, err := f.Decode(opt.Key, nil)
	if err != nil {
		return r, err
	}
	if len(d.Gaps) > 0 {
		return r, fmt.Errorf("%d stream(s) had a sequence gap: part of the file was never framed", len(d.Gaps))
	}
	r.Unframed, r.TLS, r.Other = unaudited(f, d)
	for _, tl := range d.Tails() {
		r.TailBytes += tl.Len
	}
	r.Unaudited = r.Unframed + r.TLS + r.Other
	// Port 300 is checked, not assumed: each direction must open with a TLS handshake record,
	// so plain TACACS+ there cannot hide behind an allowlisted file name.
	tlsErr := checkTLSOpens(f)
	fields, err := d.Fields()
	if err != nil {
		return r, err
	}
	kinds := map[string]int{}
	for _, fd := range fields {
		b := fd.Bytes(d.Packets[fd.Packet].Body)
		if fd.Credential && fd.Len > 0 {
			r.CredentialFields++
			if !labcreds.Redacted(b) {
				r.NotFill++
				kinds[fd.Name+" not all fill"]++
			}
		}
		if (strings.HasPrefix(fd.Name, "author_request.arg[") || strings.HasPrefix(fd.Name, "acct_request.arg[")) &&
			hashShape.Match(b) {
			r.HashShaped++
			kinds[fd.Name[:strings.Index(fd.Name, "[")]+" hash-shaped"]++
		}
	}
	for _, p := range d.Packets {
		if labcreds.TokenShaped(p.Body) != "" || bytes.Contains(p.Body, []byte(labcreds.TokenPrefix)) {
			r.TokenShaped++
			kinds[p.Kind()+" token-shaped"]++
		}
	}
	if len(kinds) == 0 {
		return r, tlsErr
	}
	var parts []string
	for k, n := range kinds {
		parts = append(parts, fmt.Sprintf("%s x%d", k, n))
	}
	sort.Strings(parts)
	err = fmt.Errorf("the evidence holds a credential: %s", strings.Join(parts, ", "))
	if tlsErr != nil {
		err = fmt.Errorf("%w; %v", err, tlsErr)
	}
	return r, err
}

// unaudited counts what AuditEvidence could not read as plain TACACS+:
//   - unframed: port-49 streams with bytes left after the last whole packet (or no packet at all)
//     that are not all Fill,
//   - tlsRuns: each direction of a connection on TLSPort (RFC 9887), which TLS 1.3 hides,
//   - other: records that are not IPv4 TCP on port 49 or 300, which Redact would have dropped.
func unaudited(f *File, d *Decode) (unframed, tlsRuns, other int) {
	// A tail that is entirely Fill is what the redactor writes over bytes it cannot frame, and
	// holds nothing; any other tail is unaudited.
	for _, tl := range d.Tails() {
		if !labcreds.Redacted(d.Streams[tl.Stream].Payload[tl.Off:]) {
			unframed++
		}
	}
	tls := map[string]bool{}
	for _, r := range f.Records {
		fl, ok := FlowOf(f.Link, f.Bytes(r))
		switch {
		case !ok || (fl.SrcPort != Port && fl.DstPort != Port && fl.SrcPort != TLSPort && fl.DstPort != TLSPort):
			other++
		case fl.PayloadLen > 0 && (fl.SrcPort == TLSPort || fl.DstPort == TLSPort):
			tls[fmt.Sprintf("%s:%d>%s:%d", fl.Src, fl.SrcPort, fl.Dst, fl.DstPort)] = true
		}
	}
	return unframed, len(tls), other
}
