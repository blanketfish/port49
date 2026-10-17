package wire

// ErrorReply is the reply RFC 9887 §4 requires to a packet whose unencrypted
// flag is clear on a TLS connection: the ERROR status of the request's type,
// with the unencrypted flag set, seq_no one past the request's. h has passed
// every ValidateTLS check but the flag, so its type is one of the three.
func ErrorReply(h Header) (Header, []byte) {
	var body []byte
	switch h.Type {
	case TypeAuthen:
		body = AuthenReply{Status: AuthenStatusError}.Encode()
	case TypeAuthor:
		body = AuthorResponse{Status: AuthorStatusError}.Encode()
	default:
		body = AcctReply{Status: AcctStatusError}.Encode()
	}
	return Header{MajorVersion: h.MajorVersion, MinorVersion: h.MinorVersion, Type: h.Type, SeqNo: h.SeqNo + 1,
		Flags: FlagUnencrypted, SessionID: h.SessionID, Length: uint32(len(body))}, body
}
