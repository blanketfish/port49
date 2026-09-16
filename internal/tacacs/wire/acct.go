package wire

import "encoding/binary"

type AcctRequest struct {
	Flags, AuthenMethod, PrivLvl, AuthenType, Service uint8
	User, Port, RemAddr                               []byte
	Args                                              [][]byte
}

type AcctReply struct {
	Status          uint8
	ServerMsg, Data []byte
}

func DecodeAcctRequest(b []byte) (AcctRequest, error) {
	if len(b) < 9 {
		return AcctRequest{}, ErrShort
	}
	p := AcctRequest{Flags: b[0], AuthenMethod: b[1], PrivLvl: b[2], AuthenType: b[3], Service: b[4]}
	ul, pl, rl, cnt := int(b[5]), int(b[6]), int(b[7]), int(b[8])
	if len(b) < 9+cnt {
		return AcctRequest{}, ErrShort
	}
	lens := b[9 : 9+cnt]
	want := 9 + cnt + ul + pl + rl + argsTotal(lens)
	if len(b) < want {
		return AcctRequest{}, ErrShort
	}
	if len(b) != want {
		return AcctRequest{}, ErrLengthMismatch
	}
	if p.PrivLvl > 15 || p.Flags&^(AcctFlagStart|AcctFlagStop|AcctFlagWatchdog) != 0 {
		return AcctRequest{}, ErrBadEnum
	}
	off := 9 + cnt
	p.User = cut(b, &off, ul)
	p.Port = cut(b, &off, pl)
	p.RemAddr = cut(b, &off, rl)
	p.Args = make([][]byte, cnt)
	for i, l := range lens {
		p.Args[i] = cut(b, &off, int(l))
	}
	return p, nil
}

func (p AcctRequest) Encode() []byte {
	b := []byte{p.Flags, p.AuthenMethod, p.PrivLvl, p.AuthenType, p.Service,
		byte(len(p.User)), byte(len(p.Port)), byte(len(p.RemAddr)), byte(len(p.Args))}
	for _, a := range p.Args {
		b = append(b, byte(len(a)))
	}
	b = append(b, p.User...)
	b = append(b, p.Port...)
	b = append(b, p.RemAddr...)
	for _, a := range p.Args {
		b = append(b, a...)
	}
	return b
}

func DecodeAcctReply(b []byte) (AcctReply, error) {
	if len(b) < 5 {
		return AcctReply{}, ErrShort
	}
	sl, dl := int(binary.BigEndian.Uint16(b[0:2])), int(binary.BigEndian.Uint16(b[2:4]))
	p := AcctReply{Status: b[4]}
	if len(b) < 5+sl+dl {
		return AcctReply{}, ErrShort
	}
	if len(b) != 5+sl+dl {
		return AcctReply{}, ErrLengthMismatch
	}
	off := 5
	p.ServerMsg = cut(b, &off, sl)
	p.Data = cut(b, &off, dl)
	return p, nil
}

func (p AcctReply) Encode() []byte {
	b := make([]byte, 5, 5+len(p.ServerMsg)+len(p.Data))
	binary.BigEndian.PutUint16(b[0:2], uint16(len(p.ServerMsg)))
	binary.BigEndian.PutUint16(b[2:4], uint16(len(p.Data)))
	b[4] = p.Status
	b = append(b, p.ServerMsg...)
	b = append(b, p.Data...)
	return b
}
