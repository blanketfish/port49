package pkcs11

// Token is one token a module shows in a slot, as Tokens lists it: what
// `port49 hwkey` needs to let a user pick one without the serial. Label is the
// raw label, which can carry the serial ("YubiKey PIV #<serial>"): it exists
// only to build the token= attribute of the URI that setup writes, and is never
// printed. MaskedLabel and MaskedSerial are what is printed.
type Token struct {
	Slot                      uint
	Label, MaskedLabel, Model string
	MaskedSerial              string
}
