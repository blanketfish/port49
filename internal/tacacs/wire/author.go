package wire

import "encoding/binary"

type AuthorRequest struct {
	AuthenMethod, PrivLvl, AuthenType, Service uint8
	User, Port, RemAddr                        []byte
	Args                                       [][]byte
}

type AuthorResponse struct {
	Status          uint8
	ServerMsg, Data []byte
	Args            [][]byte
}

// decodeArgs reads cnt one-octet lengths starting at *off, then the args
// themselves starting at argsOff. It is shared by author and acct requests.
func argsTotal(lens []byte) int {
	n := 0
	for _, l := range lens {
		n += int(l)
	}
	return n
}

func DecodeAuthorRequest(b []byte) (AuthorRequest, error) {
	if len(b) < 8 {
		return AuthorRequest{}, ErrShort
	}
	p := AuthorRequest{AuthenMethod: b[0], PrivLvl: b[1], AuthenType: b[2], Service: b[3]}
	ul, pl, rl, cnt := int(b[4]), int(b[5]), int(b[6]), int(b[7])
	if len(b) < 8+cnt {
		return AuthorRequest{}, ErrShort
	}
	lens := b[8 : 8+cnt]
	want := 8 + cnt + ul + pl + rl + argsTotal(lens)
	if len(b) < want {
		return AuthorRequest{}, ErrShort
	}
	if len(b) != want {
		return AuthorRequest{}, ErrLengthMismatch
	}
	if p.PrivLvl > 15 || (p.AuthenType != 0 && !validAuthenType(p.AuthenType)) {
		return AuthorRequest{}, ErrBadEnum
	}
	off := 8 + cnt
	p.User = cut(b, &off, ul)
	p.Port = cut(b, &off, pl)
	p.RemAddr = cut(b, &off, rl)
	p.Args = make([][]byte, cnt)
	for i, l := range lens {
		p.Args[i] = cut(b, &off, int(l))
	}
	return p, nil
}

func (p AuthorRequest) Encode() []byte {
	b := []byte{p.AuthenMethod, p.PrivLvl, p.AuthenType, p.Service,
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

func DecodeAuthorResponse(b []byte) (AuthorResponse, error) {
	if len(b) < 6 {
		return AuthorResponse{}, ErrShort
	}
	p := AuthorResponse{Status: b[0]}
	cnt := int(b[1])
	sl, dl := int(binary.BigEndian.Uint16(b[2:4])), int(binary.BigEndian.Uint16(b[4:6]))
	if len(b) < 6+cnt {
		return AuthorResponse{}, ErrShort
	}
	lens := b[6 : 6+cnt]
	want := 6 + cnt + sl + dl + argsTotal(lens)
	if len(b) < want {
		return AuthorResponse{}, ErrShort
	}
	if len(b) != want {
		return AuthorResponse{}, ErrLengthMismatch
	}
	off := 6 + cnt
	p.ServerMsg = cut(b, &off, sl)
	p.Data = cut(b, &off, dl)
	p.Args = make([][]byte, cnt)
	for i, l := range lens {
		p.Args[i] = cut(b, &off, int(l))
	}
	return p, nil
}

func (p AuthorResponse) Encode() []byte {
	b := make([]byte, 6)
	b[0], b[1] = p.Status, byte(len(p.Args))
	binary.BigEndian.PutUint16(b[2:4], uint16(len(p.ServerMsg)))
	binary.BigEndian.PutUint16(b[4:6], uint16(len(p.Data)))
	for _, a := range p.Args {
		b = append(b, byte(len(a)))
	}
	b = append(b, p.ServerMsg...)
	b = append(b, p.Data...)
	for _, a := range p.Args {
		b = append(b, a...)
	}
	return b
}
