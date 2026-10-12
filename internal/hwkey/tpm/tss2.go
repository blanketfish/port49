package tpm

import (
	"encoding/asn1"
	"encoding/pem"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// The TSS2 private key file is the format of tpm2-tss-engine, tpm2-openssl
// and tpm2-pkcs11's export (the "ASN.1 Specification for TPM 2.0 Key Files"):
//
//	TPMKey ::= SEQUENCE {
//	  type        OBJECT IDENTIFIER,
//	  emptyAuth   [0] EXPLICIT BOOLEAN OPTIONAL,
//	  policy      [1] EXPLICIT SEQUENCE OF TPMPolicy OPTIONAL,
//	  secret      [2] EXPLICIT OCTET STRING OPTIONAL,
//	  authPolicy  [3] EXPLICIT SEQUENCE OF TPMAuthPolicy OPTIONAL,
//	  description [4] EXPLICIT UTF8String OPTIONAL,
//	  rsaParent   [5] EXPLICIT BOOLEAN OPTIONAL,
//	  parent      INTEGER,
//	  pubkey      OCTET STRING,
//	  privkey     OCTET STRING }
//
// port49 writes and reads the one shape it makes: a loadable key (not an
// importable one) under the owner-hierarchy SRK, with an empty auth and no
// policy. Anything else is refused by name rather than half-understood: a
// policy or a password would be skipped silently by a reader that ignored
// them, and the key would fail later with a TPM error nobody can read.

const pemTypeTSS2 = "TSS2 PRIVATE KEY"

// parentOwner is TPM_RH_OWNER: the key's parent is the SRK made from the
// standard template under the owner hierarchy.
const parentOwner = 0x40000001

var oidLoadableKey = asn1.ObjectIdentifier{2, 23, 133, 10, 1, 3}

func contextTag(n int) cbasn1.Tag { return cbasn1.Tag(n).ContextSpecific().Constructed() }

// EncodeTSS2 writes a loadable key under the SRK, with an empty auth, as a
// TSS2 PRIVATE KEY PEM file.
func EncodeTSS2(pub tpm2.TPM2BPublic, priv tpm2.TPM2BPrivate) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oidLoadableKey)
		b.AddASN1(contextTag(0), func(b *cryptobyte.Builder) { b.AddASN1Boolean(true) })
		b.AddASN1Int64(parentOwner)
		b.AddASN1OctetString(tpm2.Marshal(pub))
		b.AddASN1OctetString(tpm2.Marshal(priv))
	})
	der, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("tpm: encoding the key file: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeTSS2, Bytes: der}), nil
}

// DecodeTSS2 reads the key file EncodeTSS2 writes. A file of another shape is
// an error naming what is different.
func DecodeTSS2(pemBytes []byte) (tpm2.TPM2BPublic, tpm2.TPM2BPrivate, error) {
	var none2BPublic tpm2.TPM2BPublic
	var nonePrivate tpm2.TPM2BPrivate
	fail := func(format string, args ...any) (tpm2.TPM2BPublic, tpm2.TPM2BPrivate, error) {
		return none2BPublic, nonePrivate, fmt.Errorf("tpm: "+format, args...)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return fail("the key file is not PEM; expected a %q block", pemTypeTSS2)
	}
	if block.Type != pemTypeTSS2 {
		return fail("the key file is a %q block, not a %q", block.Type, pemTypeTSS2)
	}
	in := cryptobyte.String(block.Bytes)
	var seq cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !in.Empty() {
		return fail("the key file is not a TSS2 key (no SEQUENCE)")
	}
	var oid asn1.ObjectIdentifier
	if !seq.ReadASN1ObjectIdentifier(&oid) {
		return fail("the key file has no type OID")
	}
	if !oid.Equal(oidLoadableKey) {
		return fail("the key file's type %s is not a loadable key (%s); port49 reads loadable keys only", oid, oidLoadableKey)
	}

	// The optional elements are in tag order. emptyAuth must be true; the
	// policy, secret and authPolicy elements are refused; description is
	// free text; rsaParent must be absent or false.
	var elem cryptobyte.String
	var present bool
	if !seq.ReadOptionalASN1(&elem, &present, contextTag(0)) {
		return fail("the key file's emptyAuth element is malformed")
	}
	emptyAuth := false
	if present && (!elem.ReadASN1Boolean(&emptyAuth) || !elem.Empty()) {
		return fail("the key file's emptyAuth element is malformed")
	}
	for _, refused := range []struct {
		tag  int
		name string
	}{{1, "policy"}, {2, "secret"}, {3, "authPolicy"}} {
		if !seq.ReadOptionalASN1(&elem, &present, contextTag(refused.tag)) {
			return fail("the key file's %s element is malformed", refused.name)
		}
		if present {
			return fail("the key file has a %s element; port49 keys have none", refused.name)
		}
	}
	if !seq.ReadOptionalASN1(&elem, &present, contextTag(4)) {
		return fail("the key file's description element is malformed")
	}
	if !seq.ReadOptionalASN1(&elem, &present, contextTag(5)) {
		return fail("the key file's rsaParent element is malformed")
	}
	if present {
		rsaParent := false
		if !elem.ReadASN1Boolean(&rsaParent) || rsaParent {
			return fail("the key file's parent is an RSA SRK; port49 keys sit under the ECC SRK")
		}
	}
	if !emptyAuth {
		return fail("the key file needs a password (emptyAuth is not set); port49 keys have an empty auth")
	}

	var parent int64
	if !seq.ReadASN1Integer(&parent) {
		return fail("the key file has no parent")
	}
	if parent != parentOwner {
		return fail("the key file's parent %#x is not the owner-hierarchy SRK (%#x)", parent, parentOwner)
	}
	var pubBytes, privBytes cryptobyte.String
	if !seq.ReadASN1(&pubBytes, cbasn1.OCTET_STRING) || !seq.ReadASN1(&privBytes, cbasn1.OCTET_STRING) || !seq.Empty() {
		return fail("the key file's public and private blobs are malformed")
	}
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](pubBytes)
	if err != nil {
		return fail("the key file's public blob: %w", err)
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](privBytes)
	if err != nil {
		return fail("the key file's private blob: %w", err)
	}
	if _, err := pub.Contents(); err != nil {
		return fail("the key file's public blob: %w", err)
	}
	return *pub, *priv, nil
}
