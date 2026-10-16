package wire

import "encoding/binary"

// Header is the 12-byte cleartext RFC 8907 header.
type Header struct {
	MajorVersion uint8
	MinorVersion uint8
	Type         Type
	SeqNo        uint8
	Flags        uint8
	SessionID    uint32
	Length       uint32
}

// Version returns the version octet as carried on the wire and used in the pad.
func (h Header) Version() byte { return h.MajorVersion<<4 | h.MinorVersion&0x0f }

func DecodeHeader(b []byte) (Header, error) {
	if len(b) < HeaderLen {
		return Header{}, ErrShort
	}
	return Header{
		MajorVersion: b[0] >> 4,
		MinorVersion: b[0] & 0x0f,
		Type:         Type(b[1]),
		SeqNo:        b[2],
		Flags:        b[3],
		SessionID:    binary.BigEndian.Uint32(b[4:8]),
		Length:       binary.BigEndian.Uint32(b[8:12]),
	}, nil
}

func (h Header) Encode() []byte {
	b := make([]byte, HeaderLen)
	b[0] = h.Version()
	b[1] = byte(h.Type)
	b[2] = h.SeqNo
	b[3] = h.Flags
	binary.BigEndian.PutUint32(b[4:8], h.SessionID)
	binary.BigEndian.PutUint32(b[8:12], h.Length)
	return b
}

// Validate applies the spec §10 header checks to a packet received from a client.
// Order matters: the unencrypted check comes before anything that would read the body.
func (h Header) Validate() error {
	switch {
	case h.MajorVersion != MajorVersion:
		return ErrBadVersion
	case h.Type < TypeAuthen || h.Type > TypeAcct:
		return ErrBadType
	case h.SeqNo%2 == 0:
		return ErrSeqNotOdd
	case h.Flags&FlagUnencrypted != 0:
		return ErrUnencrypted
	case h.Length > MaxBodyLen:
		return ErrTooLong
	}
	return nil
}

// ValidateTLS is Validate for a packet on the RFC 9887 listener (spec §10;
// §13 decision 50 ruling 13): the same checks, but the unencrypted flag MUST
// be set, since TLS is the boundary and obfuscation never runs over it (RFC
// 9887 §4). Length comes before the flag, so a packet too long to be TACACS+
// is noise whatever its flag says.
func (h Header) ValidateTLS() error {
	switch {
	case h.MajorVersion != MajorVersion:
		return ErrBadVersion
	case h.Type < TypeAuthen || h.Type > TypeAcct:
		return ErrBadType
	case h.SeqNo%2 == 0:
		return ErrSeqNotOdd
	case h.Length > MaxBodyLen:
		return ErrTooLong
	case h.Flags&FlagUnencrypted == 0:
		return ErrObfuscatedOverTLS
	}
	return nil
}
