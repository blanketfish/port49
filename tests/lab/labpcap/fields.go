package labpcap

import (
	"fmt"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// Field is one variable-length field of one packet body, located within that
// body.
//
// Every variable-length field of every RFC 8907 body is enumerated, not only
// the ones that hold a password. That is deliberate: the redactor rewrites the
// fields marked Credential, and the scan checks *all* of them for lab secrets.
// A token that turned up somewhere the protocol does not put passwords — an AV
// pair, a server message — would be found by the scan and would be a field this
// list has to start marking.
type Field struct {
	Packet int    // index into Decode.Packets
	Name   string // "authen_start.data", "author_request.arg[2]"
	Off    int    // offset within the packet body
	Len    int

	// Credential marks a field RFC 8907 uses to carry a secret. These are the
	// fields the redactor overwrites.
	Credential bool
}

// Bytes returns the field's bytes out of a de-obfuscated body.
func (f Field) Bytes(body []byte) []byte { return body[f.Off : f.Off+f.Len] }

// Fields enumerates every variable-length field of every packet in the decode.
//
// A body that does not decode is an error, not a skipped packet. The redactor
// would otherwise write out a packet it could not read, which is exactly the
// packet a credential could be hiding in.
func (d *Decode) Fields() ([]Field, error) {
	var out []Field
	add := func(i int, name string, off, n int, cred bool) {
		out = append(out, Field{Packet: i, Name: name, Off: off, Len: n, Credential: cred})
	}
	for i, p := range d.Packets {
		b := p.Body
		switch p.Header.Type {
		case wire.TypeAuthen:
			switch {
			case p.Header.SeqNo == 1:
				v, err := wire.DecodeAuthenStart(b)
				if err != nil {
					return nil, fmt.Errorf("packet %d (%s seq %d): authen START: %w", i, p.Conn, p.Header.SeqNo, err)
				}
				off := 8
				add(i, "authen_start.user", off, len(v.User), false)
				off += len(v.User)
				add(i, "authen_start.port", off, len(v.Port), false)
				off += len(v.Port)
				add(i, "authen_start.rem_addr", off, len(v.RemAddr), false)
				off += len(v.RemAddr)
				// A PAP password lives here, and so does a CHAP challenge and
				// response.
				add(i, "authen_start.data", off, len(v.Data), true)
			case p.Header.SeqNo%2 == 0:
				v, err := wire.DecodeAuthenReply(b)
				if err != nil {
					return nil, fmt.Errorf("packet %d (%s seq %d): authen REPLY: %w", i, p.Conn, p.Header.SeqNo, err)
				}
				add(i, "authen_reply.server_msg", 6, len(v.ServerMsg), false)
				// A server challenge lives here.
				add(i, "authen_reply.data", 6+len(v.ServerMsg), len(v.Data), true)
			default:
				v, err := wire.DecodeAuthenContinue(b)
				if err != nil {
					return nil, fmt.Errorf("packet %d (%s seq %d): authen CONTINUE: %w", i, p.Conn, p.Header.SeqNo, err)
				}
				// An ASCII password lives in user_msg.
				add(i, "authen_continue.user_msg", 5, len(v.UserMsg), true)
				add(i, "authen_continue.data", 5+len(v.UserMsg), len(v.Data), true)
			}
		case wire.TypeAuthor:
			if p.Header.SeqNo%2 == 1 {
				v, err := wire.DecodeAuthorRequest(b)
				if err != nil {
					return nil, fmt.Errorf("packet %d (%s seq %d): author REQUEST: %w", i, p.Conn, p.Header.SeqNo, err)
				}
				off := 8 + len(v.Args)
				add(i, "author_request.user", off, len(v.User), false)
				off += len(v.User)
				add(i, "author_request.port", off, len(v.Port), false)
				off += len(v.Port)
				add(i, "author_request.rem_addr", off, len(v.RemAddr), false)
				off += len(v.RemAddr)
				for n, a := range v.Args {
					add(i, fmt.Sprintf("author_request.arg[%d]", n), off, len(a), false)
					off += len(a)
				}
			} else {
				v, err := wire.DecodeAuthorResponse(b)
				if err != nil {
					return nil, fmt.Errorf("packet %d (%s seq %d): author RESPONSE: %w", i, p.Conn, p.Header.SeqNo, err)
				}
				off := 6 + len(v.Args)
				add(i, "author_response.server_msg", off, len(v.ServerMsg), false)
				off += len(v.ServerMsg)
				add(i, "author_response.data", off, len(v.Data), false)
				off += len(v.Data)
				for n, a := range v.Args {
					add(i, fmt.Sprintf("author_response.arg[%d]", n), off, len(a), false)
					off += len(a)
				}
			}
		case wire.TypeAcct:
			if p.Header.SeqNo%2 == 1 {
				v, err := wire.DecodeAcctRequest(b)
				if err != nil {
					return nil, fmt.Errorf("packet %d (%s seq %d): acct REQUEST: %w", i, p.Conn, p.Header.SeqNo, err)
				}
				off := 9 + len(v.Args)
				add(i, "acct_request.user", off, len(v.User), false)
				off += len(v.User)
				add(i, "acct_request.port", off, len(v.Port), false)
				off += len(v.Port)
				add(i, "acct_request.rem_addr", off, len(v.RemAddr), false)
				off += len(v.RemAddr)
				for n, a := range v.Args {
					add(i, fmt.Sprintf("acct_request.arg[%d]", n), off, len(a), false)
					off += len(a)
				}
			} else {
				v, err := wire.DecodeAcctReply(b)
				if err != nil {
					return nil, fmt.Errorf("packet %d (%s seq %d): acct REPLY: %w", i, p.Conn, p.Header.SeqNo, err)
				}
				add(i, "acct_reply.server_msg", 5, len(v.ServerMsg), false)
				add(i, "acct_reply.data", 5+len(v.ServerMsg), len(v.Data), false)
			}
		default:
			return nil, fmt.Errorf("packet %d (%s): unknown packet type %d", i, p.Conn, p.Header.Type)
		}
	}
	return out, nil
}
