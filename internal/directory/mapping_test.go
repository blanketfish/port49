package directory

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

var (
	oidCN = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidDC = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
)

// issuingCA is a CA whose subject is rdns, written in DER as given (most
// significant first), so a DC= RDN reaches the leaf's RawIssuer as AD CS
// writes it and Go's pkix.Name cannot hide it (pre-flight I-1).
func issuingCA(t *testing.T, rdns pkix.RDNSequence) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := asn1.Marshal(rdns)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), RawSubject: raw, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return ca, key
}

// corpCA is CN=corp-DC01-CA,DC=corp,DC=com.
func corpCA(t *testing.T) (*x509.Certificate, crypto.Signer) {
	return issuingCA(t, pkix.RDNSequence{{{Type: oidDC, Value: "com"}}, {{Type: oidDC, Value: "corp"}},
		{{Type: oidCN, Value: "corp-DC01-CA"}}})
}

// issue is a client certificate from ca after mut edits its template,
// parsed back from DER: every mapping test reads what a real certificate
// carries, never a pkix.Name built in memory.
func issue(t *testing.T, ca *x509.Certificate, caKey crypto.Signer, mut func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(0x1200000000AC11), Subject: pkix.Name{CommonName: "Alice Smith"},
		EmailAddresses: []string{"alice@corp.example.com"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour)}
	if mut != nil {
		mut(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func leaf(t *testing.T, mut func(*x509.Certificate)) *x509.Certificate {
	ca, key := corpCA(t)
	return issue(t, ca, key, mut)
}

var pin = []string{"CN=corp-DC01-CA,DC=corp,DC=com"}

// A weak mapping refuses a certificate from an issuer it is not pinned to,
// before any search (design §7). The pin compares the issuer's DER RDNs,
// DC= included, case-folded: a pin naming the CN alone is another issuer.
func TestAWeakMappingRefusesAnUnpinnedIssuer(t *testing.T) {
	m := Mapping{Kind: MapSANEmail, Attribute: "mail", AllowWeak: true, Issuers: pin}
	if _, err := m.Lookup(leaf(t, nil), "(objectClass=person)"); err != nil {
		t.Fatal(err)
	}
	folded := Mapping{Kind: MapSANEmail, Attribute: "mail", AllowWeak: true, Issuers: []string{"cn=CORP-dc01-ca,dc=CORP,dc=com"}}
	if _, err := folded.Lookup(leaf(t, nil), "(objectClass=person)"); err != nil {
		t.Fatalf("a pin in another case: %v", err)
	}
	for _, issuers := range [][]string{{"CN=corp-DC01-CA"}, {"CN=corp-DC01-CA,DC=other,DC=com"}} {
		cnOnly := Mapping{Kind: MapSANEmail, Attribute: "mail", AllowWeak: true, Issuers: issuers}
		if _, err := cnOnly.Lookup(leaf(t, nil), "(objectClass=person)"); !errors.Is(err, ErrUnmapped) {
			t.Fatalf("pin %v matched CN=corp-DC01-CA,DC=corp,DC=com: %v", issuers, err)
		}
	}
	partner, partnerKey := issuingCA(t, pkix.RDNSequence{{{Type: oidCN, Value: "Partner CA"}}})
	other := issue(t, partner, partnerKey, nil)
	if _, err := m.Lookup(other, "(objectClass=person)"); !errors.Is(err, ErrUnmapped) ||
		!strings.Contains(err.Error(), "not one broker.directory.certificate_mapping.issuers pins") {
		t.Fatalf("%v", err)
	}
}

// A mapped value carrying filter metacharacters matches only its literal
// entry (Review Focus 1).
func TestAMappedValueIsEscapedInTheFilter(t *testing.T) {
	m := Mapping{Kind: MapCN, Attribute: "cn", AllowWeak: true, Issuers: pin}
	l, err := m.Lookup(leaf(t, func(c *x509.Certificate) { c.Subject.CommonName = `*)(uid=*` }), "(objectClass=person)")
	if err != nil {
		t.Fatal(err)
	}
	if l.Filter != `(&(objectClass=person)(cn=\2a\29\28uid=\2a))` {
		t.Fatalf("%s", l.Filter)
	}
	raw, _ := asn1.Marshal(pkix.RDNSequence{{{Type: oidCN, Value: "a\x00b"}}})
	nul := leaf(t, func(c *x509.Certificate) { c.RawSubject = raw })
	if _, err := m.Lookup(nul, "(objectClass=person)"); !errors.Is(err, ErrUnmapped) {
		t.Fatalf("a control character in a weak value: %v", err)
	}
}

// AD's altSecurityIdentities form: the issuer's DER RDNs most significant
// first, DC= included, serial bytes reversed, upper-case hex (KB5014754's
// own example has the DCs first).
func TestADIssuerSerial(t *testing.T) {
	got := ADIssuerSerial(leaf(t, nil))
	if got != "X509:<I>DC=com,DC=corp,CN=corp-DC01-CA<SR>11AC0000000012" {
		t.Fatalf("%s", got)
	}
	l, _ := Mapping{Kind: MapIssuerSerial, Attribute: "altSecurityIdentities"}.Lookup(leaf(t, nil), "(objectClass=person)")
	if !strings.HasPrefix(l.Filter, "(&(objectClass=person)(altSecurityIdentities=X509:<I>DC=com,DC=corp,CN=corp-DC01-CA<SR>") {
		t.Fatalf("%s", l.Filter)
	}
}

// subject_dn reads the subject's DER RDNs too, so a subject under DC=
// keeps them.
func TestASubjectDNKeepsItsDCs(t *testing.T) {
	m := Mapping{Kind: MapSubjectDN, Attribute: "distinguishedName", AllowWeak: true, Issuers: pin}
	raw, _ := asn1.Marshal(pkix.RDNSequence{{{Type: oidDC, Value: "com"}}, {{Type: oidDC, Value: "corp"}},
		{{Type: oidCN, Value: "Alice Smith"}}})
	l, err := m.Lookup(leaf(t, func(c *x509.Certificate) { c.RawSubject = raw }), "(objectClass=person)")
	if err != nil || l.Filter != "(&(objectClass=person)(distinguishedName=cn=Alice Smith,dc=corp,dc=com))" {
		t.Fatalf("%s %v", l.Filter, err)
	}
}

// The SID extension parsed, and objectSid escaped byte by byte (Review
// Focus 1): a binary attribute has no other safe form.
func TestAnObjectSidIsEscapedByteByByte(t *testing.T) {
	sid := "S-1-5-21-1004336348-1177238915-682003330-512"
	l, err := Mapping{Kind: MapSID, Attribute: "objectSid"}.Lookup(leaf(t, func(c *x509.Certificate) {
		c.ExtraExtensions = append(c.ExtraExtensions, sidExtension(t, sid))
	}), "(objectClass=person)")
	if err != nil {
		t.Fatal(err)
	}
	want := `(&(objectClass=person)(objectSid=\01\05\00\00\00\00\00\05\15\00\00\00\dc\f4\dc\3b\83\3d\2b\46\82\8b\a6\28\00\02\00\00))`
	if l.Filter != want {
		t.Fatalf("%s\nwant %s", l.Filter, want)
	}
	if b, _ := sidBytes(sid); func() string { s, _ := sidString(b); return s }() != sid {
		t.Fatal("sidString(sidBytes(x)) != x")
	}
	if _, err := (Mapping{Kind: MapSID, Attribute: "objectSid"}).Lookup(leaf(t, nil), "(objectClass=person)"); !errors.Is(err, ErrUnmapped) {
		t.Fatalf("no SID extension: %v", err)
	}
}

// The key a certificate searches with equals the key its entry answers to
// (pre-flight M-2): a SID re-canonicalized from its binary form, an
// issuer_serial upper-cased, as AD matches it.
func TestMapKeysAreCanonicalOnBothSides(t *testing.T) {
	sid := "S-1-5-21-1004336348-1177238915-682003330-512"
	c := leaf(t, func(c *x509.Certificate) { c.ExtraExtensions = append(c.ExtraExtensions, sidExtension(t, sid)) })
	b, _ := sidBytes(sid)
	sm := Mapping{Kind: MapSID, Attribute: "objectSid"}
	l, _ := sm.Lookup(c, "(objectClass=person)")
	if keys := sm.KeysOf(ldap.NewEntry("CN=Alice,DC=corp", map[string][]string{"objectSid": {string(b)}})); len(keys) != 1 || keys[0] != l.Key {
		t.Fatalf("sid: %v vs %s", keys, l.Key)
	}
	im := Mapping{Kind: MapIssuerSerial, Attribute: "altSecurityIdentities"}
	l, _ = im.Lookup(c, "(objectClass=person)")
	lower := strings.ToLower(ADIssuerSerial(c))
	if keys := im.KeysOf(ldap.NewEntry("CN=Alice,DC=corp", map[string][]string{"altSecurityIdentities": {lower}})); len(keys) != 1 || keys[0] != l.Key {
		t.Fatalf("issuer_serial: %v vs %s", keys, l.Key)
	}
}

// Zero or several email SANs is no mapping, never the first (design §7).
func TestSeveralSANsAreUnmapped(t *testing.T) {
	m := Mapping{Kind: MapSANEmail, Attribute: "mail", AllowWeak: true, Issuers: pin}
	for _, emails := range [][]string{nil, {"a@x", "b@x"}} {
		if _, err := m.Lookup(leaf(t, func(c *x509.Certificate) { c.EmailAddresses = emails }), "(objectClass=person)"); !errors.Is(err, ErrUnmapped) {
			t.Fatalf("%v: %v", emails, err)
		}
	}
}

// sidExtension builds szOID_NTDS_CA_SECURITY_EXT as AD CS writes it: a
// GeneralNames holding one otherName (1.3.6.1.4.1.311.25.2.1) whose value
// is the SID string as an OCTET STRING.
func sidExtension(t *testing.T, sid string) pkix.Extension {
	t.Helper()
	inner, _ := asn1.Marshal([]byte(sid))
	other, err := asn1.Marshal(struct {
		ID    asn1.ObjectIdentifier
		Value asn1.RawValue
	}{oidSIDValue, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}})
	if err != nil {
		t.Fatal(err)
	}
	other[0] = 0xa0 // [0] IMPLICIT, constructed: the GeneralName otherName choice
	names, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: other})
	return pkix.Extension{Id: oidSIDExtension, Value: names}
}

// upnOtherName is one UPN otherName whose [0] EXPLICIT value is inner (DER).
func upnOtherName(t *testing.T, inner []byte) []byte {
	t.Helper()
	other, err := asn1.Marshal(struct {
		ID    asn1.ObjectIdentifier
		Value asn1.RawValue
	}{oidUPN, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}})
	if err != nil {
		t.Fatal(err)
	}
	other[0] = 0xa0
	return other
}

// sanOf is a SAN extension holding the given otherNames.
func sanOf(otherNames ...[]byte) pkix.Extension {
	var body []byte
	for _, o := range otherNames {
		body = append(body, o...)
	}
	names, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
	return pkix.Extension{Id: oidSAN, Value: names}
}

// upnExtension is a SAN holding one UPN otherName (UTF8String).
func upnExtension(t *testing.T, upn string) pkix.Extension {
	t.Helper()
	inner, err := asn1.MarshalWithParams(upn, "utf8")
	if err != nil {
		t.Fatal(err)
	}
	return sanOf(upnOtherName(t, inner))
}

// onlyEscaped fails unless value, the part of f after "attr=", holds no
// filter metacharacter except as a \xx escape: the filter keeps its shape.
func onlyEscaped(t *testing.T, f, prefix string) {
	t.Helper()
	if !strings.HasPrefix(f, prefix) || !strings.HasSuffix(f, "))") {
		t.Fatalf("the filter lost its shape: %s", f)
	}
	v := strings.TrimSuffix(strings.TrimPrefix(f, prefix), "))")
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '*', '(', ')', 0:
			t.Fatalf("an unescaped %q in %s", v[i], f)
		case '\\':
			if i+2 >= len(v) {
				t.Fatalf("a bare backslash in %s", f)
			}
			i += 2
		}
	}
}

// Every kind that carries a certificate string escapes it: a value of
// filter metacharacters and NUL never widens the search (it either keeps its
// shape, escaped, or is refused as unmapped).
func TestEveryKindEscapesHostileValues(t *testing.T) {
	hostile := `a*)(uid=*)(|(cn=*\`
	base := "(&(objectClass=person)"
	t.Run("san_email", func(t *testing.T) {
		m := Mapping{Kind: MapSANEmail, Attribute: "mail", AllowWeak: true, Issuers: pin}
		l, err := m.Lookup(leaf(t, func(c *x509.Certificate) { c.EmailAddresses = []string{hostile} }), "(objectClass=person)")
		if err != nil {
			t.Fatal(err)
		}
		onlyEscaped(t, l.Filter, base+"(mail=")
		_, err = m.Lookup(leaf(t, func(c *x509.Certificate) { c.EmailAddresses = []string{"a\x00b@x"} }), "(objectClass=person)")
		if !errors.Is(err, ErrUnmapped) {
			t.Fatalf("NUL in an email SAN: %v", err)
		}
	})
	t.Run("san_upn", func(t *testing.T) {
		m := Mapping{Kind: MapSANUPN, Attribute: "userPrincipalName", AllowWeak: true, Issuers: pin}
		l, err := m.Lookup(leaf(t, func(c *x509.Certificate) { c.ExtraExtensions = append(c.ExtraExtensions, upnExtension(t, hostile)) }),
			"(objectClass=person)")
		if err != nil {
			t.Fatal(err)
		}
		onlyEscaped(t, l.Filter, base+"(userPrincipalName=")
		_, err = m.Lookup(leaf(t, func(c *x509.Certificate) { c.ExtraExtensions = append(c.ExtraExtensions, upnExtension(t, "a\x00b@x")) }),
			"(objectClass=person)")
		if !errors.Is(err, ErrUnmapped) {
			t.Fatalf("NUL in a UPN SAN: %v", err)
		}
		_, err = m.Lookup(leaf(t, func(c *x509.Certificate) {
			c.ExtraExtensions = append(c.ExtraExtensions, upnExtension(t, "a@x"))
			c.EmailAddresses = nil
		}), "(objectClass=person)")
		if err != nil {
			t.Fatalf("one UPN: %v", err)
		}
	})
	t.Run("cn", func(t *testing.T) {
		m := Mapping{Kind: MapCN, Attribute: "cn", AllowWeak: true, Issuers: pin}
		l, err := m.Lookup(leaf(t, func(c *x509.Certificate) { c.Subject.CommonName = hostile }), "(objectClass=person)")
		if err != nil {
			t.Fatal(err)
		}
		onlyEscaped(t, l.Filter, base+"(cn=")
	})
	t.Run("subject_dn", func(t *testing.T) {
		m := Mapping{Kind: MapSubjectDN, Attribute: "distinguishedName", AllowWeak: true, Issuers: pin}
		l, err := m.Lookup(leaf(t, func(c *x509.Certificate) { c.Subject.CommonName = hostile }), "(objectClass=person)")
		if err != nil {
			t.Fatal(err)
		}
		onlyEscaped(t, l.Filter, base+"(distinguishedName=")
	})
	t.Run("issuer_serial", func(t *testing.T) {
		ca, key := issuingCA(t, pkix.RDNSequence{{{Type: oidDC, Value: "com"}}, {{Type: oidCN, Value: hostile}}})
		m := Mapping{Kind: MapIssuerSerial, Attribute: "altSecurityIdentities"}
		l, err := m.Lookup(issue(t, ca, key, nil), "(objectClass=person)")
		if err != nil {
			t.Fatal(err)
		}
		onlyEscaped(t, l.Filter, base+"(altSecurityIdentities=")
	})
	t.Run("sid", func(t *testing.T) {
		m := Mapping{Kind: MapSID, Attribute: "objectSid"}
		for _, sid := range []string{hostile, "S-1-5-21-*", "S-1-5-21-1\x00"} {
			_, err := m.Lookup(leaf(t, func(c *x509.Certificate) { c.ExtraExtensions = append(c.ExtraExtensions, sidExtension(t, sid)) }),
				"(objectClass=person)")
			if !errors.Is(err, ErrUnmapped) {
				t.Fatalf("SID %q: %v", sid, err)
			}
		}
	})
}

// subject_dn keys are injective: a CN holding DN syntax never keys as the
// entry whose DN that syntax spells (review C-1; grace looks a principal up
// by this key).
func TestSubjectDNKeysAreInjective(t *testing.T) {
	m := Mapping{Kind: MapSubjectDN, Attribute: "distinguishedName", AllowWeak: true, Issuers: pin}
	subj := func(rdns ...[]pkix.AttributeTypeAndValue) string {
		seq := pkix.RDNSequence{{{Type: oidDC, Value: "com"}}, {{Type: oidDC, Value: "corp"}}}
		for _, r := range rdns {
			seq = append(seq, r)
		}
		raw, _ := asn1.Marshal(seq)
		l, err := m.Lookup(leaf(t, func(c *x509.Certificate) { c.RawSubject = raw }), "(objectClass=person)")
		if err != nil {
			t.Fatal(err)
		}
		return l.Key
	}
	ou := asn1.ObjectIdentifier{2, 5, 4, 11}
	comma := subj([]pkix.AttributeTypeAndValue{{Type: oidCN, Value: "alice,OU=admins"}})
	plus := subj([]pkix.AttributeTypeAndValue{{Type: oidCN, Value: "alice+OU=admins"}})
	multi := subj([]pkix.AttributeTypeAndValue{{Type: oidCN, Value: "alice"}, {Type: ou, Value: "admins"}})
	two := subj([]pkix.AttributeTypeAndValue{{Type: ou, Value: "admins"}}, []pkix.AttributeTypeAndValue{{Type: oidCN, Value: "alice"}})
	if comma == two || plus == two || multi == two || comma == plus || comma == multi || plus == multi {
		t.Fatal("distinct subjects share a key")
	}
	entryKey := func(dn string) string { return m.KeysOf(ldap.NewEntry(dn, nil))[0] }
	if entryKey("CN=alice,OU=admins,DC=corp,DC=com") != two {
		t.Fatal("the entry's key is not the certificate's for the same name")
	}
	if entryKey(`CN=alice\,OU=admins,DC=corp,DC=com`) != comma || entryKey("CN=alice+OU=admins,DC=corp,DC=com") != multi {
		t.Fatal("an escaped or multi-valued entry DN does not key as its certificate")
	}
	if entryKey(`CN=alice\,OU=admins,DC=corp,DC=com`) == entryKey("CN=alice,OU=admins,DC=corp,DC=com") {
		t.Fatal("an escaped comma keys as an RDN boundary")
	}
}

// A subject with two CNs is no cn mapping, never the last (review I-3).
func TestTwoCNsAreUnmapped(t *testing.T) {
	m := Mapping{Kind: MapCN, Attribute: "cn", AllowWeak: true, Issuers: pin}
	raw, _ := asn1.Marshal(pkix.RDNSequence{{{Type: oidCN, Value: "mallory"}}, {{Type: oidCN, Value: "alice"}}})
	if l, err := m.Lookup(leaf(t, func(c *x509.Certificate) { c.RawSubject = raw }), "(objectClass=person)"); !errors.Is(err, ErrUnmapped) {
		t.Fatalf("%s %v", l.Filter, err)
	}
	raw, _ = asn1.Marshal(pkix.RDNSequence{{{Type: oidCN, Value: "mallory"}, {Type: oidCN, Value: "alice"}}})
	if _, err := m.Lookup(leaf(t, func(c *x509.Certificate) { c.RawSubject = raw }), "(objectClass=person)"); !errors.Is(err, ErrUnmapped) {
		t.Fatalf("one RDN holding two CNs: %v", err)
	}
	raw, _ = asn1.Marshal(pkix.RDNSequence{{{Type: oidDC, Value: "com"}}})
	if _, err := m.Lookup(leaf(t, func(c *x509.Certificate) { c.RawSubject = raw }), "(objectClass=person)"); !errors.Is(err, ErrUnmapped) {
		t.Fatalf("no CN: %v", err)
	}
}

// A UPN otherName that does not parse counts, and fails closed (review I-4).
func TestAMalformedUPNOrSIDIsNeverSkipped(t *testing.T) {
	m := Mapping{Kind: MapSANUPN, Attribute: "userPrincipalName", AllowWeak: true, Issuers: pin}
	good, _ := asn1.MarshalWithParams("alice@x", "utf8")
	notString, _ := asn1.Marshal(7)
	trailing := append(append([]byte{}, good...), 0x05, 0x00)
	for name, inner := range map[string][]byte{"an INTEGER value": notString, "trailing bytes": trailing} {
		c := leaf(t, func(c *x509.Certificate) {
			c.EmailAddresses = nil
			c.ExtraExtensions = append(c.ExtraExtensions, sanOf(upnOtherName(t, good), upnOtherName(t, inner)))
		})
		if l, err := m.Lookup(c, "(objectClass=person)"); !errors.Is(err, ErrUnmapped) {
			t.Fatalf("%s: %s %v", name, l.Filter, err)
		}
		alone := leaf(t, func(c *x509.Certificate) {
			c.EmailAddresses = nil
			c.ExtraExtensions = append(c.ExtraExtensions, sanOf(upnOtherName(t, inner)))
		})
		if _, err := m.Lookup(alone, "(objectClass=person)"); !errors.Is(err, ErrUnmapped) {
			t.Fatalf("%s alone: %v", name, err)
		}
	}
	// two good UPNs: several
	c := leaf(t, func(c *x509.Certificate) {
		c.EmailAddresses = nil
		c.ExtraExtensions = append(c.ExtraExtensions, sanOf(upnOtherName(t, good), upnOtherName(t, good)))
	})
	if _, err := m.Lookup(c, "(objectClass=person)"); !errors.Is(err, ErrUnmapped) {
		t.Fatalf("two UPNs: %v", err)
	}
	// a SID extension with a sibling that is not an octet string
	sidM := Mapping{Kind: MapSID, Attribute: "objectSid"}
	one := sidExtension(t, "S-1-5-21-1")
	var names []asn1.RawValue
	asn1.Unmarshal(one.Value, &names)
	bad, _ := asn1.Marshal(struct {
		ID    asn1.ObjectIdentifier
		Value asn1.RawValue
	}{oidSIDValue, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: notString}})
	bad[0] = 0xa0
	body := append(append([]byte{}, names[0].FullBytes...), bad...)
	seq, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
	c = leaf(t, func(c *x509.Certificate) {
		c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: oidSIDExtension, Value: seq})
	})
	if _, err := sidM.Lookup(c, "(objectClass=person)"); !errors.Is(err, ErrUnmapped) {
		t.Fatalf("a malformed SID sibling: %v", err)
	}
}

// ValidPin names only attribute types a pin can match (review M-5).
func TestValidPin(t *testing.T) {
	for _, ok := range []string{"CN=a,DC=b", "2.5.4.3=a", "OID.2.5.4.3=a,DOMAINCOMPONENT=com"} {
		if !ValidPin(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"SERIALNUMBER=1,DC=b", "nonsense", "CN"} {
		if ValidPin(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
