package wire

import "errors"

var (
	ErrShort       = errors.New("wire: buffer shorter than declared")
	ErrBadVersion  = errors.New("wire: major version is not 0xc")
	ErrBadType     = errors.New("wire: type not in {authen, author, acct}")
	ErrSeqNotOdd   = errors.New("wire: client seq_no must be odd")
	ErrTooLong     = errors.New("wire: body exceeds 4096-byte ceiling")
	ErrUnencrypted = errors.New("wire: unencrypted flag set; refused")
	// ErrObfuscatedOverTLS is a packet on the RFC 9887 listener whose
	// unencrypted flag is clear: RFC 9887 §4 requires the flag on every packet
	// over TLS, and an ERROR reply to one without it.
	ErrObfuscatedOverTLS = errors.New("wire: unencrypted flag clear over TLS; refused")
	ErrLengthMismatch    = errors.New("wire: field lengths do not sum to body length")
	ErrBadEnum           = errors.New("wire: enum value out of range")
	ErrTooManyArgs       = errors.New("wire: arg_cnt exceeds 255")
)
