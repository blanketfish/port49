package wire

import (
	"crypto/md5"
	"encoding/binary"
)

// Pad returns n bytes of RFC 8907 §4.5 keystream for the header and key.
func Pad(h Header, key []byte, n int) []byte {
	out := make([]byte, 0, n+md5.Size)
	var sid [4]byte
	binary.BigEndian.PutUint32(sid[:], h.SessionID)
	var prev []byte
	for len(out) < n {
		m := md5.New()
		m.Write(sid[:])
		m.Write(key)
		m.Write([]byte{h.Version(), h.SeqNo})
		m.Write(prev)
		prev = m.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}

// Obfuscate XORs body with the pad. The operation is its own inverse. It never
// modifies its input.
func Obfuscate(h Header, key []byte, body []byte) []byte {
	pad := Pad(h, key, len(body))
	out := make([]byte, len(body))
	for i := range body {
		out[i] = body[i] ^ pad[i]
	}
	return out
}
