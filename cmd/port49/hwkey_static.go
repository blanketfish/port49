//go:build !hwkey_dlopen

package main

import (
	"errors"

	"github.com/blanketfish/port49/internal/hwkey"
	"github.com/blanketfish/port49/internal/hwkey/pkcs11"
)

// The static build has no PKCS#11 loader: port49 hwkey says so and exits 2.
var errNoPKCS11 = errors.New("this port49 was built without PKCS#11 support (the hwkey_dlopen build tag), so it cannot read a security key")

var openToken = func(pkcs11.URI, []byte) (hwkey.Key, error) { return nil, errNoPKCS11 }

var listTokens = func(string) ([]pkcs11.Token, error) { return nil, errNoPKCS11 }
