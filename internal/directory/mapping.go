package directory

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"

	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/store"
)

var (
	ErrUnmapped      = errors.New("directory: identity_unmapped")
	ErrAmbiguous     = errors.New("directory: identity_ambiguous")
	ErrUsernameTaken = errors.New("directory: username_collision")
)

var (
	oidSIDExtension = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 25, 2}
	oidSIDValue     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 25, 2, 1}
	oidUPN          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	oidSAN          = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidCNType       = asn1.ObjectIdentifier{2, 5, 4, 3}
)

// Lookup is one certificate's search under the mapping.
type Lookup struct {
	Attribute, Filter string
	Key               string // store.MapKey of the value: what a bind in grace finds the principal by
}

func unmapped(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnmapped, fmt.Sprintf(format, args...))
}

// Lookup is the search the mapping makes for leaf (Ruling 1): the issuer
// pin first, for a weak kind or any kind given one; then the value,
// exactly one, escaped. A value the kind cannot find is ErrUnmapped.
func (m Mapping) Lookup(leaf *x509.Certificate, userFilter string) (Lookup, error) {
	if len(m.Issuers) > 0 && !pinned(leaf, m.Issuers) {
		return Lookup{}, unmapped("the certificate's issuer %q is not one broker.directory.certificate_mapping.issuers "+
			"pins", printsafe.Line(nameString(leaf.RawIssuer), 300))
	}
	var value string
	switch m.Kind {
	case MapIssuerSerial:
		value = ADIssuerSerial(leaf)
	case MapSID:
		sid, err := SIDOf(leaf)
		if err != nil {
			return Lookup{}, unmapped("%v", err)
		}
		b, err := sidBytes(sid)
		if err != nil {
			return Lookup{}, unmapped("the SID extension holds %v", err)
		}
		return Lookup{Attribute: m.Attribute, Filter: fmt.Sprintf("(&%s(%s=%s))", userFilter, m.Attribute, escapeBytes(b)),
			Key: store.MapKey(string(m.Kind), canonicalValue(m.Kind, sid))}, nil
	case MapSANUPN:
		upns, err := upnsOf(leaf)
		if err != nil {
			return Lookup{}, unmapped("%v", err)
		}
		if len(upns) != 1 {
			return Lookup{}, unmapped("the certificate carries %d UPN SANs; exactly one maps", len(upns))
		}
		value = upns[0]
	case MapSANEmail:
		if len(leaf.EmailAddresses) != 1 {
			return Lookup{}, unmapped("the certificate carries %d email SANs; exactly one maps", len(leaf.EmailAddresses))
		}
		value = leaf.EmailAddresses[0]
	case MapSubjectDN:
		value = nameString(leaf.RawSubject)
	case MapCN:
		cn, err := commonNameOf(leaf)
		if err != nil {
			return Lookup{}, unmapped("%v", err)
		}
		value = cn
	default:
		return Lookup{}, unmapped("mapping kind %q", m.Kind)
	}
	if value == "" || !printable(value) {
		return Lookup{}, unmapped("the certificate's %s value is empty or not printable (%d bytes)", m.Kind, len(value))
	}
	return Lookup{Attribute: m.Attribute, Filter: fmt.Sprintf("(&%s(%s=%s))", userFilter, m.Attribute,
		ldap.EscapeFilter(value)), Key: store.MapKey(string(m.Kind), canonicalValue(m.Kind, value))}, nil
}

// KeysOf is every mapping key entry e answers to under m: what pre-warm
// and every verification index (Ruling 20).
func (m Mapping) KeysOf(e *ldap.Entry) []string {
	var out []string
	switch m.Kind {
	case MapSID:
		for _, raw := range e.GetRawAttributeValues(m.Attribute) {
			if s, err := sidString(raw); err == nil {
				out = append(out, store.MapKey(string(m.Kind), canonicalValue(m.Kind, s)))
			}
		}
	case MapSubjectDN:
		out = append(out, store.MapKey(string(m.Kind), canonicalValue(m.Kind, e.DN)))
	default:
		for _, v := range e.GetAttributeValues(m.Attribute) {
			out = append(out, store.MapKey(string(m.Kind), canonicalValue(m.Kind, v)))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// canonicalValue is the form a key hashes, the same on the certificate's
// side and the entry's (pre-flight M-2): a DN as parsed RDNs lower-cased, a
// name lower-cased, an issuer_serial upper-cased (each of those matches
// case-insensitively in AD), a SID through its binary form and back.
func canonicalValue(k MappingKind, v string) string {
	switch k {
	case MapIssuerSerial:
		return strings.ToUpper(v)
	case MapSID:
		if b, err := sidBytes(v); err == nil {
			if s, err := sidString(b); err == nil {
				return s
			}
		}
		return v
	case MapSubjectDN:
		return canonicalDN(v)
	case MapSANUPN, MapSANEmail, MapCN:
		return strings.ToLower(v)
	}
	return v
}

// CanonicalDN is canonicalDN for the policy, which compares a group: given as
// a DN with the DNs a directory returned (plan 7g): one form on both sides.
func CanonicalDN(v string) string { return canonicalDN(v) }

// canonicalDN is a DN in the one form both sides key (review C-1, I-1): per
// RDN its attributes as type OID and lower-cased value, DN-escaped, sorted
// and joined with "+", the RDNs joined with ",". Escaping every DN
// metacharacter in a value keeps a comma, a plus or an equals sign in a value
// from spelling an RDN boundary, so two DNs never share a form. A DN that does
// not parse keys as itself behind a "?" no parsed form starts with.
func canonicalDN(v string) string {
	dn, err := ldap.ParseDN(v)
	if err != nil {
		return "?" + strings.ToLower(v)
	}
	rdns := make([]string, len(dn.RDNs))
	for i, rdn := range dn.RDNs {
		attrs := make([]string, len(rdn.Attributes))
		for j, a := range rdn.Attributes {
			attrs[j] = typeOID(a.Type) + "=" + escapeDNValue(strings.ToLower(a.Value))
		}
		slices.Sort(attrs)
		rdns[i] = strings.Join(attrs, "+")
	}
	return strings.Join(rdns, ",")
}

// typeOID is an attribute type, a short name or an OID, as its canonical
// lower-case short name when oidNames knows it, else its OID.
func typeOID(t string) string {
	t = strings.ToUpper(t)
	oid, ok := nameOIDs[t]
	if !ok {
		oid = strings.TrimPrefix(t, "OID.")
	}
	if n, ok := oidNames[oid]; ok {
		return strings.ToLower(n)
	}
	return strings.ToLower(oid)
}

// escapeDNValue backslash-escapes every character RFC 4514 reserves, and
// the NUL it writes as \00, anywhere in v.
func escapeDNValue(v string) string {
	var sb strings.Builder
	for _, r := range v {
		switch r {
		case 0:
			sb.WriteString(`\00`)
		case '\\', ',', '+', '"', '<', '>', ';', '=', '#':
			sb.WriteByte('\\')
			sb.WriteRune(r)
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// oidNames is each attribute type a mapping or a pin names, by OID, as AD
// and RFC 4514 write it. nameOIDs is the reverse, with the aliases a pin
// may use.
var (
	oidNames = map[string]string{"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "S", "2.5.4.10": "O",
		"2.5.4.11": "OU", "2.5.4.9": "STREET", "0.9.2342.19200300.100.1.25": "DC", "0.9.2342.19200300.100.1.1": "UID",
		"1.2.840.113549.1.9.1": "E"}
	nameOIDs = func() map[string]string {
		m := map[string]string{"ST": "2.5.4.8", "EMAILADDRESS": "1.2.840.113549.1.9.1", "DOMAINCOMPONENT": "0.9.2342.19200300.100.1.25"}
		for oid, n := range oidNames {
			m[n] = oid
		}
		return m
	}()
)

// rdnsOf parses raw, a certificate's RawIssuer or RawSubject, as its DER
// RDN sequence, most significant first. Go's pkix.Name drops DC= RDNs and
// Issuer.String() renders them as dotted OIDs (pre-flight I-1), so neither
// is used for a mapping or a pin.
func rdnsOf(raw []byte) (pkix.RDNSequence, error) {
	var seq pkix.RDNSequence
	rest, err := asn1.Unmarshal(raw, &seq)
	if err != nil || len(rest) > 0 {
		return nil, errors.New("a malformed name")
	}
	return seq, nil
}

func typeName(oid asn1.ObjectIdentifier) string {
	if t, ok := oidNames[oid.String()]; ok {
		return t
	}
	return "OID." + oid.String()
}

// nameString is raw as an RFC 4514 DN, least significant first, each type
// by its short name (DC kept) and each value escaped by go-ldap's
// DN.String, which lower-cases the types; "" when raw does not parse.
func nameString(raw []byte) string {
	seq, err := rdnsOf(raw)
	if err != nil {
		return ""
	}
	dn := &ldap.DN{}
	for i := len(seq) - 1; i >= 0; i-- {
		rdn := &ldap.RelativeDN{}
		for _, atv := range seq[i] {
			rdn.Attributes = append(rdn.Attributes, &ldap.AttributeTypeAndValue{Type: typeName(atv.Type), Value: fmt.Sprint(atv.Value)})
		}
		dn.RDNs = append(dn.RDNs, rdn)
	}
	return dn.String()
}

// rdnKeys is a name as the pin compares it: per RDN, most significant
// first, its (OID, case-folded value) pairs sorted.
func rdnKeys(seq pkix.RDNSequence) [][]string {
	out := make([][]string, len(seq))
	for i, rdn := range seq {
		for _, atv := range rdn {
			out[i] = append(out[i], atv.Type.String()+"="+strings.ToLower(fmt.Sprint(atv.Value)))
		}
		slices.Sort(out[i])
	}
	return out
}

// pinKeys is an RFC 4514 pin as rdnKeys, its RDNs reversed into DER order
// and each type through nameOIDs (or written as an OID); false for a type
// neither names, which then matches nothing.
func pinKeys(pin string) ([][]string, bool) {
	dn, err := ldap.ParseDN(pin)
	if err != nil {
		return nil, false
	}
	out := make([][]string, len(dn.RDNs))
	for i, rdn := range dn.RDNs {
		j := len(dn.RDNs) - 1 - i
		for _, a := range rdn.Attributes {
			t := strings.ToUpper(a.Type)
			oid, ok := nameOIDs[t]
			if !ok {
				oid = strings.TrimPrefix(t, "OID.")
				if strings.Trim(oid, "0123456789.") != "" || !strings.Contains(oid, ".") {
					return nil, false
				}
			}
			out[j] = append(out[j], oid+"="+strings.ToLower(a.Value))
		}
		slices.Sort(out[j])
	}
	return out, true
}

// ValidPin reports whether pin is an RFC 4514 DN whose every attribute type
// a pin can match (a short name nameOIDs knows, or an OID): a pin naming
// another type would never match and refuse every certificate (review M-5).
func ValidPin(pin string) bool {
	_, ok := pinKeys(pin)
	return ok
}

// pinned reports whether leaf's issuer, read from its DER, equals one of
// issuers (Ruling 1).
func pinned(leaf *x509.Certificate, issuers []string) bool {
	seq, err := rdnsOf(leaf.RawIssuer)
	if err != nil {
		return false
	}
	got := rdnKeys(seq)
	for _, iss := range issuers {
		if want, ok := pinKeys(iss); ok && slices.EqualFunc(got, want, slices.Equal[[]string]) {
			return true
		}
	}
	return false
}

func printable(s string) bool {
	return utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}

// ADIssuerSerial is AD's altSecurityIdentities strong form: X509:<I> the
// issuer's RDNs most significant first, read from RawIssuer so DC= is kept,
// <SR> the serial's bytes reversed in upper-case hex (KB5014754). L43's run
// checks it against Samba's form, and L44 measured Windows' quoting. "" when
// the issuer does not parse, which Lookup refuses.
func ADIssuerSerial(leaf *x509.Certificate) string {
	seq, err := rdnsOf(leaf.RawIssuer)
	if err != nil {
		return ""
	}
	var parts []string
	for _, rdn := range seq {
		for _, atv := range rdn {
			parts = append(parts, typeName(atv.Type)+"="+adQuote(fmt.Sprint(atv.Value)))
		}
	}
	b := leaf.SerialNumber.Bytes()
	r := make([]byte, len(b))
	for i := range b {
		r[i] = b[len(b)-1-i]
	}
	return "X509:<I>" + strings.Join(parts, ",") + "<SR>" + strings.ToUpper(hex.EncodeToString(r))
}

// adQuote is an RDN value as Windows' CertNameToStr writes it in
// altSecurityIdentities (L44): quoted when it is empty, starts or ends with
// white space, or holds , + = " \ < > # ; or a newline, an inner quote doubled.
func adQuote(v string) string {
	if v == "" || strings.ContainsAny(v, ",+=\"\\<>#;\n") || strings.TrimSpace(v) != v {
		return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
	}
	return v
}

// commonNameOf is the one CN in leaf's subject, read from its DER: several
// CNs, in one RDN or many, or a CN that is not a string is no mapping, never
// the last (design §7; Go's pkix.Name keeps only one).
func commonNameOf(leaf *x509.Certificate) (string, error) {
	seq, err := rdnsOf(leaf.RawSubject)
	if err != nil {
		return "", err
	}
	var cns []string
	for _, rdn := range seq {
		for _, atv := range rdn {
			if !atv.Type.Equal(oidCNType) {
				continue
			}
			v, ok := atv.Value.(string)
			if !ok {
				return "", errors.New("the certificate's CN is not a string")
			}
			cns = append(cns, v)
		}
	}
	if len(cns) != 1 {
		return "", fmt.Errorf("the certificate's subject carries %d CNs; exactly one maps", len(cns))
	}
	return cns[0], nil
}

// SIDOf is the SID string in leaf's szOID_NTDS_CA_SECURITY_EXT, exactly one.
func SIDOf(leaf *x509.Certificate) (string, error) {
	var found []string
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(oidSIDExtension) {
			continue
		}
		vals, err := otherNames(ext.Value, oidSIDValue)
		if err != nil {
			return "", fmt.Errorf("the SID extension is malformed: %w", err)
		}
		for _, v := range vals {
			var s []byte
			if rest, err := asn1.Unmarshal(v, &s); err != nil || len(rest) > 0 {
				return "", errors.New("the SID extension holds a value that is not one octet string")
			}
			found = append(found, string(s))
		}
	}
	if len(found) != 1 {
		return "", fmt.Errorf("the certificate carries %d SID extension values; exactly one maps", len(found))
	}
	return found[0], nil
}

// upnsOf is every UPN otherName in leaf's SAN; one that does not parse is an
// error, never skipped, so "several" cannot count as one.
func upnsOf(leaf *x509.Certificate) ([]string, error) {
	var out []string
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(oidSAN) {
			continue
		}
		vals, err := otherNames(ext.Value, oidUPN)
		if err != nil {
			return nil, fmt.Errorf("the SAN is malformed: %w", err)
		}
		for _, v := range vals {
			var s string
			if rest, err := asn1.UnmarshalWithParams(v, &s, "utf8"); err != nil || len(rest) > 0 {
				return nil, errors.New("the certificate carries a UPN SAN that is not one UTF8 string")
			}
			out = append(out, s)
		}
	}
	return out, nil
}

// otherNames is the inner value of every otherName of type id in a
// GeneralNames: each GeneralName [0] IMPLICIT OtherName {type-id, [0]
// EXPLICIT value}. An otherName that does not parse to that shape, of any
// type, is an error: it could be the second value of the one wanted.
func otherNames(der []byte, id asn1.ObjectIdentifier) ([][]byte, error) {
	var names []asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &names); err != nil || len(rest) > 0 {
		return nil, errors.New("not a GeneralNames")
	}
	var out [][]byte
	for _, n := range names {
		if n.Class != asn1.ClassContextSpecific || n.Tag != 0 {
			continue
		}
		var typeID asn1.ObjectIdentifier
		rest, err := asn1.Unmarshal(n.Bytes, &typeID)
		if err != nil {
			return nil, errors.New("an otherName with no type")
		}
		if !typeID.Equal(id) {
			continue
		}
		var val asn1.RawValue
		if rest, err = asn1.Unmarshal(rest, &val); err != nil || len(rest) > 0 ||
			val.Class != asn1.ClassContextSpecific || val.Tag != 0 || !val.IsCompound {
			return nil, errors.New("an otherName whose value is not [0] EXPLICIT")
		}
		out = append(out, val.Bytes)
	}
	return out, nil
}

// sidBytes is a SID string in objectSid's binary form: revision, count,
// the 48-bit authority big-endian, each sub-authority little-endian.
func sidBytes(sid string) ([]byte, error) {
	parts := strings.Split(sid, "-")
	if len(parts) < 3 || parts[0] != "S" || parts[1] != "1" || len(parts)-3 > 15 {
		return nil, fmt.Errorf("a malformed SID")
	}
	auth, err := strconv.ParseUint(parts[2], 10, 48)
	if err != nil {
		return nil, fmt.Errorf("a malformed SID")
	}
	b := []byte{1, byte(len(parts) - 3), 0, 0, 0, 0, 0, 0}
	for i := 0; i < 6; i++ {
		b[2+i] = byte(auth >> (8 * (5 - i)))
	}
	for _, p := range parts[3:] {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("a malformed SID")
		}
		b = binary.LittleEndian.AppendUint32(b, uint32(v))
	}
	return b, nil
}

func sidString(b []byte) (string, error) {
	if len(b) < 8 || b[0] != 1 || len(b) != 8+4*int(b[1]) {
		return "", fmt.Errorf("a malformed objectSid")
	}
	var auth uint64
	for i := 0; i < 6; i++ {
		auth = auth<<8 | uint64(b[2+i])
	}
	s := fmt.Sprintf("S-1-%d", auth)
	for i := 0; i < int(b[1]); i++ {
		s += fmt.Sprintf("-%d", binary.LittleEndian.Uint32(b[8+4*i:]))
	}
	return s, nil
}

func escapeBytes(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		fmt.Fprintf(&sb, `\%02x`, c)
	}
	return sb.String()
}
