package devicemock

import (
	"crypto/tls"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// fake is a test-only TACACS+ server: it answers each request type with a
// configured status and arguments.
type fake struct {
	ln                  net.Listener
	key                 []byte
	mu                  sync.Mutex
	authen              []uint8 // statuses in turn, e.g. {GetPass, Pass} for ASCII
	authorArgs          [][]byte
	echo, singleConnect bool
	clearReply          bool // reply with the unencrypted flag and a clear body
	wrongSession        bool // reply with a session id the request did not carry
	conns               atomic.Int32
	reqs                []seen // what the server received; test-only, never printed
}

// seen is one request as the server decoded it.
type seen struct {
	Type         wire.Type
	MinorVersion uint8
	Flags        uint8
	Data         []byte   // authen START data or CONTINUE user_msg
	AuthenType   uint8    // authen START / author / acct
	AcctFlags    uint8    // acct
	Args         [][]byte // author / acct
}

func (f *fake) record(s seen) {
	f.mu.Lock()
	f.reqs = append(f.reqs, s)
	f.mu.Unlock()
}

func (f *fake) seen() []seen {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]seen(nil), f.reqs...)
}

func newFake(t *testing.T, key []byte) *fake {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fake{ln: ln, key: key}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.conns.Add(1)
			go f.serve(c)
		}
	}()
	return f
}

// newFakeTLS is the fake behind a TLS listener that requires a client
// certificate, for the plays that run over RFC 9887.
func newFakeTLS(t *testing.T, server tls.Certificate) *fake {
	t.Helper()
	f := newFake(t, nil)
	f.ln.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{server},
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f.ln = ln
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.conns.Add(1)
			go f.serve(c)
		}
	}()
	return f
}

func (f *fake) nextAuthen() uint8 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.authen) == 0 {
		return wire.AuthenStatusError
	}
	s := f.authen[0]
	f.authen = f.authen[1:]
	return s
}

func (f *fake) serve(c net.Conn) {
	defer c.Close()
	for {
		var hb [wire.HeaderLen]byte
		if _, err := io.ReadFull(c, hb[:]); err != nil {
			return
		}
		h, err := wire.DecodeHeader(hb[:])
		if err != nil {
			return
		}
		raw := make([]byte, h.Length)
		if _, err := io.ReadFull(c, raw); err != nil {
			return
		}
		clear := h.Flags&wire.FlagUnencrypted != 0 // RFC 9887: TLS is the boundary
		body := raw
		if !clear {
			body = wire.Obfuscate(h, f.key, raw)
		}
		var reply []byte
		final := true
		rec := seen{Type: h.Type, MinorVersion: h.MinorVersion, Flags: h.Flags}
		switch h.Type {
		case wire.TypeAuthen:
			var echo []byte
			if h.SeqNo == 1 {
				if st, err := wire.DecodeAuthenStart(body); err == nil {
					echo, rec.AuthenType = st.Data, st.AuthenType
				}
			} else if ct, err := wire.DecodeAuthenContinue(body); err == nil {
				echo = ct.UserMsg
			}
			rec.Data = echo
			s := f.nextAuthen()
			r := wire.AuthenReply{Status: s}
			if f.echo {
				r.ServerMsg = echo
			}
			reply = r.Encode()
			final = s != wire.AuthenStatusGetPass && s != wire.AuthenStatusGetUser && s != wire.AuthenStatusGetData
		case wire.TypeAuthor:
			if r, err := wire.DecodeAuthorRequest(body); err == nil {
				rec.Args, rec.AuthenType = r.Args, r.AuthenType
			}
			reply = wire.AuthorResponse{Status: wire.AuthorStatusPassAdd, Args: f.authorArgs}.Encode()
		case wire.TypeAcct:
			if r, err := wire.DecodeAcctRequest(body); err == nil {
				rec.Args, rec.AcctFlags, rec.AuthenType = r.Args, r.Flags, r.AuthenType
			}
			reply = wire.AcctReply{Status: wire.AcctStatusSuccess}.Encode()
		default:
			return
		}
		f.record(rec)
		agreed := f.singleConnect && h.Flags&wire.FlagSingleConnect != 0
		rh := wire.Header{MajorVersion: h.MajorVersion, MinorVersion: h.MinorVersion, Type: h.Type,
			SeqNo: h.SeqNo + 1, SessionID: h.SessionID, Length: uint32(len(reply))}
		if agreed {
			rh.Flags |= wire.FlagSingleConnect
		}
		out := wire.Obfuscate(rh, f.key, reply)
		if f.clearReply || clear {
			rh.Flags |= wire.FlagUnencrypted
			out = reply
		}
		if f.wrongSession {
			rh.SessionID++
		}
		if _, err := c.Write(append(rh.Encode(), out...)); err != nil {
			return
		}
		if final && !agreed {
			return
		}
	}
}
