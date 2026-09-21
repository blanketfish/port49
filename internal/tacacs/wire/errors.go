package wire

import "errors"

var (
	ErrShort          = errors.New("wire: buffer shorter than declared")
	ErrBadVersion     = errors.New("wire: major version is not 0xc")
	ErrBadType        = errors.New("wire: type not in {authen, author, acct}")
	ErrSeqNotOdd      = errors.New("wire: client seq_no must be odd")
	ErrTooLong        = errors.New("wire: body exceeds 4096-byte ceiling")
	ErrUnencrypted    = errors.New("wire: unencrypted flag set; refused")
	ErrLengthMismatch = errors.New("wire: field lengths do not sum to body length")
	ErrBadEnum        = errors.New("wire: enum value out of range")
	ErrTooManyArgs    = errors.New("wire: arg_cnt exceeds 255")
)
