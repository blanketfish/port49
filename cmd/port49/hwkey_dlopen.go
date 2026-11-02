//go:build hwkey_dlopen

package main

import (
	"github.com/blanketfish/port49/internal/hwkey"
	"github.com/blanketfish/port49/internal/hwkey/pkcs11"
)

// The client build: PKCS#11 modules are loaded at run time. openToken opens the
// key u names, with whatever PIN it is given; port49 hwkey gives it none, so
// the signer is Locked and nothing logs in.
var openToken = func(u pkcs11.URI, pin []byte) (hwkey.Key, error) {
	s, err := pkcs11.Open(u, pin)
	if err != nil {
		return nil, err
	}
	return s, nil
}

var listTokens = pkcs11.Tokens
