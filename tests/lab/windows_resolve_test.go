//go:build lab

package lab

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
)

// The lab's Windows URIs name the DC as an operator's would, winDCHost, so
// port49's GSSAPI bind asks for ldap/<winDCHost>, an SPN the DC keeps itself.
// An SPN added to the DC's account for another name did not last: measured on
// the L44 DC, ldap/localhost left DC1$ within minutes, twice, with no 4742
// event naming who removed it. This process alone resolves winDCHost to the
// published ports on 127.0.0.1: winResolveDC answers that one name from a
// DNS server of its own and refuses every other, so nothing else this run
// looks up can reach a real resolver by way of it.

// winDNSAnswer is the reply to query, a message of one question (RFC 1035
// §4.1): winDCHost's A record is 127.0.0.1, its other types have none, and
// every other name does not exist. Written by hand, not with x/net's
// dnsmessage, so the lab adds no module requirement.
func winDNSAnswer(query []byte) ([]byte, error) {
	if len(query) < 12 || binary.BigEndian.Uint16(query[4:]) != 1 {
		return nil, errors.New("not a query of one question")
	}
	var labels []string
	i := 12
	for {
		if i >= len(query) {
			return nil, errors.New("question runs off the message")
		}
		n := int(query[i])
		if n == 0 {
			i++
			break
		}
		if n&0xc0 != 0 || i+1+n > len(query) {
			return nil, errors.New("question name is not plain labels")
		}
		labels = append(labels, string(query[i+1:i+1+n]))
		i += 1 + n
	}
	if i+4 > len(query) {
		return nil, errors.New("question has no type and class")
	}
	question, qtype := query[12:i+4], binary.BigEndian.Uint16(query[i:])
	ours := strings.EqualFold(strings.Join(labels, "."), winDCHost)
	rcode, answers := uint16(3), uint16(0) // NXDOMAIN
	if ours {
		rcode = 0
		if qtype == 1 { // A
			answers = 1
		}
	}
	out := make([]byte, 12, 12+len(question)+16)
	binary.BigEndian.PutUint16(out[0:], binary.BigEndian.Uint16(query[0:]))    // the query's ID
	binary.BigEndian.PutUint16(out[2:], 0x8400|uint16(query[2]&0x01)<<8|rcode) // QR, AA, the query's RD
	binary.BigEndian.PutUint16(out[4:], 1)
	binary.BigEndian.PutUint16(out[6:], answers)
	out = append(out, question...)
	if answers == 1 {
		// The name as a pointer to the question's, A, IN, TTL 60, 127.0.0.1.
		out = append(out, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1)
	}
	return out, nil
}

// winResolveDC makes this process's resolver answer from winDNSAnswer until
// the test ends. /etc/hosts still comes first, so localhost is unchanged.
func winResolveDC(t *testing.T) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if out, err := winDNSAnswer(buf[:n]); err == nil {
				_, _ = pc.WriteTo(out, from)
			}
		}
	}()
	was := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", pc.LocalAddr().String())
	}}
	t.Cleanup(func() {
		net.DefaultResolver = was
		_ = pc.Close()
	})
}
