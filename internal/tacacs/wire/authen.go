package wire

import "encoding/binary"

type AuthenStart struct {
	Action, PrivLvl, AuthenType, Service uint8
	User, Port, RemAddr, Data            []byte
}

type AuthenReply struct {
	Status, Flags   uint8
	ServerMsg, Data []byte
}

type AuthenContinue struct {
	Flags         uint8
	UserMsg, Data []byte
}

func validAuthenAction(a uint8) bool {
	return a == AuthenActionLogin || a == AuthenActionChPass || a == AuthenActionSendAuth
}

func validAuthenType(t uint8) bool {
	switch t {
	case AuthenTypeASCII, AuthenTypePAP, AuthenTypeCHAP, AuthenTypeMSCHAP, AuthenTypeMSCHAPv2:
		return true
	}
	return false
}

func DecodeAuthenStart(b []byte) (AuthenStart, error) {
	if len(b) < 8 {
		return AuthenStart{}, ErrShort
	}
	p := AuthenStart{Action: b[0], PrivLvl: b[1], AuthenType: b[2], Service: b[3]}
	ul, pl, rl, dl := int(b[4]), int(b[5]), int(b[6]), int(b[7])
	want := 8 + ul + pl + rl + dl
	if len(b) < want {
		return AuthenStart{}, ErrShort
	}
	if len(b) != want {
		return AuthenStart{}, ErrLengthMismatch
	}
	if !validAuthenAction(p.Action) || !validAuthenType(p.AuthenType) || p.PrivLvl > 15 || p.Service > 0x09 {
		return AuthenStart{}, ErrBadEnum
	}
	off := 8
	p.User = cut(b, &off, ul)
	p.Port = cut(b, &off, pl)
	p.RemAddr = cut(b, &off, rl)
	p.Data = cut(b, &off, dl)
	return p, nil
}

func (p AuthenStart) Encode() []byte {
	b := make([]byte, 8, 8+len(p.User)+len(p.Port)+len(p.RemAddr)+len(p.Data))
	b[0], b[1], b[2], b[3] = p.Action, p.PrivLvl, p.AuthenType, p.Service
	b[4], b[5], b[6], b[7] = byte(len(p.User)), byte(len(p.Port)), byte(len(p.RemAddr)), byte(len(p.Data))
	b = append(b, p.User...)
	b = append(b, p.Port...)
	b = append(b, p.RemAddr...)
	b = append(b, p.Data...)
	return b
}

func DecodeAuthenReply(b []byte) (AuthenReply, error) {
	if len(b) < 6 {
		return AuthenReply{}, ErrShort
	}
	p := AuthenReply{Status: b[0], Flags: b[1]}
	sl, dl := int(binary.BigEndian.Uint16(b[2:4])), int(binary.BigEndian.Uint16(b[4:6]))
	if len(b) < 6+sl+dl {
		return AuthenReply{}, ErrShort
	}
	if len(b) != 6+sl+dl {
		return AuthenReply{}, ErrLengthMismatch
	}
	off := 6
	p.ServerMsg = cut(b, &off, sl)
	p.Data = cut(b, &off, dl)
	return p, nil
}

func (p AuthenReply) Encode() []byte {
	b := make([]byte, 6, 6+len(p.ServerMsg)+len(p.Data))
	b[0], b[1] = p.Status, p.Flags
	binary.BigEndian.PutUint16(b[2:4], uint16(len(p.ServerMsg)))
	binary.BigEndian.PutUint16(b[4:6], uint16(len(p.Data)))
	b = append(b, p.ServerMsg...)
	b = append(b, p.Data...)
	return b
}

func DecodeAuthenContinue(b []byte) (AuthenContinue, error) {
	if len(b) < 5 {
		return AuthenContinue{}, ErrShort
	}
	ul, dl := int(binary.BigEndian.Uint16(b[0:2])), int(binary.BigEndian.Uint16(b[2:4]))
	p := AuthenContinue{Flags: b[4]}
	if len(b) < 5+ul+dl {
		return AuthenContinue{}, ErrShort
	}
	if len(b) != 5+ul+dl {
		return AuthenContinue{}, ErrLengthMismatch
	}
	off := 5
	p.UserMsg = cut(b, &off, ul)
	p.Data = cut(b, &off, dl)
	return p, nil
}

func (p AuthenContinue) Encode() []byte {
	b := make([]byte, 5, 5+len(p.UserMsg)+len(p.Data))
	binary.BigEndian.PutUint16(b[0:2], uint16(len(p.UserMsg)))
	binary.BigEndian.PutUint16(b[2:4], uint16(len(p.Data)))
	b[4] = p.Flags
	b = append(b, p.UserMsg...)
	b = append(b, p.Data...)
	return b
}

// cut returns a copy of the next n bytes and advances off. Callers have already
// checked the total length, so this cannot run past the buffer.
func cut(b []byte, off *int, n int) []byte {
	out := append([]byte(nil), b[*off:*off+n]...)
	*off += n
	return out
}
