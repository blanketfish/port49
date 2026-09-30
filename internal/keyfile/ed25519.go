package keyfile

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

// LoadEd25519 reads the inventory service's signing key (spec §13, decision
// 30): one PKCS#8 "PRIVATE KEY" block holding an ed25519 key, read with
// readPrivate's checks. No error quotes the file.
func LoadEd25519(path string) (ed25519.PrivateKey, error) {
	raw, err := readPrivate(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(raw)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("keyfile: %s holds no PKCS#8 PRIVATE KEY block", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keyfile: %s: its PRIVATE KEY block does not parse", path)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("keyfile: %s holds a key that is not ed25519", path)
	}
	return priv, nil
}

// ParseEd25519Public reads one PKIX "PUBLIC KEY" block holding an ed25519
// key from raw, which the caller read: port49d's and port49-inventory's
// verify_key_files. A public key is no secret, but it is the trust root of
// the bundle's signature (spec §13, decision 30), so whoever could write it
// decides which inventories are accepted; its reader is the write fence
// (config.VerifyKeys), never a plain read. path names it in errors, which
// never quote raw.
func ParseEd25519Public(raw []byte, path string) (ed25519.PublicKey, error) {
	blk, _ := pem.Decode(raw)
	if blk == nil || blk.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("keyfile: %s holds no PUBLIC KEY block", path)
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keyfile: %s: its PUBLIC KEY block does not parse", path)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("keyfile: %s holds a key that is not ed25519", path)
	}
	return pub, nil
}

// EncodeEd25519 is priv as `port49 inventory keygen` writes it: the private
// key as PKCS#8, the public half as PKIX.
func EncodeEd25519(priv ed25519.PrivateKey) (privPEM, pubPEM []byte, err error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), nil
}

// Ed25519KeyID names a key in every line and in the sealed document: the
// first eight bytes of its public half's sha256, in hex. It says which key,
// and nothing that helps forge one.
func Ed25519KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(sum[:8])
}
