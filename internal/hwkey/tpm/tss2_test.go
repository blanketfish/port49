package tpm

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func testBlobs() (tpm2.TPM2BPublic, tpm2.TPM2BPrivate) {
	return tpm2.New2B(keyTemplate()), tpm2.TPM2BPrivate{Buffer: []byte{1, 2, 3, 4, 5}}
}

// tss2File builds a key file by hand so a test can put in the elements
// EncodeTSS2 never writes. extra is called after emptyAuth and writes the
// optional elements in tag order.
func tss2File(t *testing.T, oid asn1.ObjectIdentifier, emptyAuth bool, extra func(*cryptobyte.Builder), parent int64) []byte {
	t.Helper()
	pub, priv := testBlobs()
	pubB, privB := tpm2.Marshal(pub), tpm2.Marshal(priv)
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		if emptyAuth {
			b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1Boolean(true)
			})
		}
		if extra != nil {
			extra(b)
		}
		b.AddASN1Int64(parent)
		b.AddASN1OctetString(pubB)
		b.AddASN1OctetString(privB)
	})
	der, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "TSS2 PRIVATE KEY", Bytes: der})
}

var oidLoadable = asn1.ObjectIdentifier{2, 23, 133, 10, 1, 3}

func TestTSS2RoundTrips(t *testing.T) {
	pub, priv := testBlobs()
	out, err := EncodeTSS2(pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	gotPub, gotPriv, err := DecodeTSS2(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tpm2.Marshal(gotPub), tpm2.Marshal(pub)) {
		t.Fatal("the public blob changed in a round trip")
	}
	if !bytes.Equal(gotPriv.Buffer, priv.Buffer) {
		t.Fatal("the private blob changed in a round trip")
	}
}

func TestTSS2FileShape(t *testing.T) {
	pub, priv := testBlobs()
	out, err := EncodeTSS2(pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(out)
	if block == nil || len(rest) != 0 || block.Type != "TSS2 PRIVATE KEY" {
		t.Fatalf("PEM block = %v, want one TSS2 PRIVATE KEY", block)
	}
	in := cryptobyte.String(block.Bytes)
	var seq cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) {
		t.Fatal("not a SEQUENCE")
	}
	var oid asn1.ObjectIdentifier
	if !seq.ReadASN1ObjectIdentifier(&oid) || oid.String() != "2.23.133.10.1.3" {
		t.Fatalf("OID = %v, want 2.23.133.10.1.3 (loadable key)", oid)
	}
	var auth, present = cryptobyte.String{}, false
	if !seq.ReadOptionalASN1(&auth, &present, cbasn1.Tag(0).ContextSpecific().Constructed()) || !present {
		t.Fatal("emptyAuth is missing")
	}
	var empty bool
	if !auth.ReadASN1Boolean(&empty) || !empty {
		t.Fatal("emptyAuth is not true")
	}
	var parent int64
	if !seq.ReadASN1Integer(&parent) || parent != 0x40000001 {
		t.Fatalf("parent = %#x, want 0x40000001", parent)
	}
}

func TestTSS2RefusesWhatItDoesNotKnow(t *testing.T) {
	tag := func(n int) cbasn1.Tag { return cbasn1.Tag(n).ContextSpecific().Constructed() }
	for _, c := range []struct {
		name  string
		file  []byte
		wants string
	}{
		{"another OID", tss2File(t, asn1.ObjectIdentifier{2, 23, 133, 10, 1, 4}, true, nil, 0x40000001), "2.23.133.10.1.4"},
		{"a policy", tss2File(t, oidLoadable, true, func(b *cryptobyte.Builder) {
			b.AddASN1(tag(1), func(b *cryptobyte.Builder) { b.AddASN1(cbasn1.SEQUENCE, func(*cryptobyte.Builder) {}) })
		}, 0x40000001), "policy"},
		{"a secret", tss2File(t, oidLoadable, true, func(b *cryptobyte.Builder) {
			b.AddASN1(tag(2), func(b *cryptobyte.Builder) { b.AddASN1OctetString([]byte{1}) })
		}, 0x40000001), "secret"},
		{"another parent", tss2File(t, oidLoadable, true, nil, 0x40000007), "0x40000007"},
		{"a password", tss2File(t, oidLoadable, false, nil, 0x40000001), "password"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := DecodeTSS2(c.file)
			if err == nil || !strings.Contains(err.Error(), c.wants) {
				t.Fatalf("DecodeTSS2 = %v, want a refusal naming %q", err, c.wants)
			}
		})
	}
	t.Run("not PEM", func(t *testing.T) {
		if _, _, err := DecodeTSS2([]byte("nope")); err == nil {
			t.Fatal("DecodeTSS2 accepted a non-PEM file")
		}
	})
	t.Run("another PEM type", func(t *testing.T) {
		file := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x30, 0}})
		if _, _, err := DecodeTSS2(file); err == nil || !strings.Contains(err.Error(), "PRIVATE KEY") {
			t.Fatalf("DecodeTSS2 = %v, want a refusal naming the PEM type", err)
		}
	})
}

// TestTheKeyIsFixedToTheTPM pins the template's attributes: a key that could
// leave the TPM is not a hardware key.
func TestTheKeyIsFixedToTheTPM(t *testing.T) {
	a := keyTemplate().ObjectAttributes
	if !a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin || !a.UserWithAuth || !a.SignEncrypt || a.Decrypt {
		t.Fatalf("template attributes %+v", a)
	}
}
