package devicemock

import (
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
	conns               atomic.Int32
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
		body := wire.Obfuscate(h, f.key, raw)
		var reply []byte
		final := true
		switch h.Type {
		case wire.TypeAuthen:
			var echo []byte
			if h.SeqNo == 1 {
				if st, err := wire.DecodeAuthenStart(body); err == nil {
					echo = st.Data
				}
			} else if ct, err := wire.DecodeAuthenContinue(body); err == nil {
				echo = ct.UserMsg
			}
			s := f.nextAuthen()
			r := wire.AuthenReply{Status: s}
			if f.echo {
				r.ServerMsg = echo
			}
			reply = r.Encode()
			final = s != wire.AuthenStatusGetPass && s != wire.AuthenStatusGetUser && s != wire.AuthenStatusGetData
		case wire.TypeAuthor:
			reply = wire.AuthorResponse{Status: wire.AuthorStatusPassAdd, Args: f.authorArgs}.Encode()
		case wire.TypeAcct:
			reply = wire.AcctReply{Status: wire.AcctStatusSuccess}.Encode()
		default:
			return
		}
		agreed := f.singleConnect && h.Flags&wire.FlagSingleConnect != 0
		rh := wire.Header{MajorVersion: h.MajorVersion, MinorVersion: h.MinorVersion, Type: h.Type,
			SeqNo: h.SeqNo + 1, SessionID: h.SessionID, Length: uint32(len(reply))}
		if agreed {
			rh.Flags |= wire.FlagSingleConnect
		}
		if _, err := c.Write(append(rh.Encode(), wire.Obfuscate(rh, f.key, reply)...)); err != nil {
			return
		}
		if final && !agreed {
			return
		}
	}
}
