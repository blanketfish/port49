package issuer

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The sign-in methods a certificate can be issued on.
const (
	MethodOIDC              = "oidc"
	MethodDirectoryPassword = "directory_password"
)

// entrySubjectPrefix starts a directory sign-in's sub.
const entrySubjectPrefix = "entry-sha256:"

// EntrySubject is a directory sign-in's sub: the entry's id hashed, so a
// DN-form id fits the URI (decision 47 D6).
func EntrySubject(entryID string) string {
	sum := sha256.Sum256([]byte(entryID))
	return entrySubjectPrefix + hex.EncodeToString(sum[:])
}

// SignIn is the sign-in a certificate was issued on (decision 43 rulings 9
// and 16; decision 47 D6): whom the provider or directory authenticated,
// when, and for OIDC the provider's session, which a back-channel logout
// names. Method "" is MethodOIDC.
type SignIn struct {
	Method    string
	Principal string
	Issuer    string
	Subject   string
	Sid       string
	AMR       []string
	ACR       string
	AuthTime  time.Time
	IssuedAt  time.Time
}

// signInScheme is the URI SAN's scheme. The URI is port49's own, read by the
// broker that issued it and by nothing else.
const signInScheme = "port49-sign-in"

// signInMembers are the URI's query members; amr alone may repeat.
var signInMembers = []string{"method", "iss", "sub", "sid", "auth_time", "iat", "amr", "acr"}

// URI is s as the certificate's one URI SAN (spec §13 decision 43 ruling 9,
// R1): port49-sign-in:v1?iss=…&sub=…&auth_time=…&iat=…, with sid, acr and
// each amr when present. The principal is the subject's CN.
func (s SignIn) URI() *url.URL {
	q := url.Values{"sub": {s.Subject}, "auth_time": {strconv.FormatInt(s.AuthTime.Unix(), 10)},
		"iat": {strconv.FormatInt(s.IssuedAt.Unix(), 10)}}
	if s.Issuer != "" {
		q.Set("iss", s.Issuer)
	}
	if s.Method == MethodDirectoryPassword {
		q.Set("method", s.Method)
	}
	if s.Sid != "" {
		q.Set("sid", s.Sid)
	}
	if s.ACR != "" {
		q.Set("acr", s.ACR)
	}
	for _, m := range s.AMR {
		q.Add("amr", m)
	}
	return &url.URL{Scheme: signInScheme, Opaque: "v1", RawQuery: q.Encode()}
}

// ReadSignIn reads the sign-in leaf was issued on: its subject's CN the
// principal, and its one URI SAN, port49-sign-in:v1, each member by its
// exact name and once (amr may repeat). Anything else is refused: this CA
// issues nothing else, so a leaf that differs is not one of its.
func ReadSignIn(leaf *x509.Certificate) (SignIn, error) {
	switch {
	case len(leaf.EmailAddresses) != 0 || len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0:
		return SignIn{}, errors.New("it carries an email, DNS or IP SAN, which port49 never issues")
	case len(leaf.URIs) != 1 || leaf.URIs[0].Scheme != signInScheme || leaf.URIs[0].Opaque != "v1":
		return SignIn{}, errors.New("it carries no port49-sign-in:v1 URI, or more than one URI")
	case leaf.URIs[0].Fragment != "" || leaf.URIs[0].User != nil:
		return SignIn{}, errors.New("its sign-in URI carries a fragment or user info")
	}
	q, err := url.ParseQuery(leaf.URIs[0].RawQuery)
	if err != nil {
		return SignIn{}, fmt.Errorf("its sign-in URI does not parse: %v", err)
	}
	for k, v := range q {
		switch {
		case !slices.Contains(signInMembers, k):
			return SignIn{}, fmt.Errorf("its sign-in URI has an unknown member %q", k)
		case k != "amr" && len(v) != 1:
			return SignIn{}, fmt.Errorf("its sign-in URI names %s twice", k)
		}
	}
	method := MethodOIDC
	if q.Has("method") {
		// Only a directory sign-in names its method; a 9b certificate has none.
		if method = q.Get("method"); method != MethodDirectoryPassword {
			return SignIn{}, fmt.Errorf("its sign-in names a method port49 does not issue (%q)", method)
		}
	}
	s := SignIn{Method: method, Principal: leaf.Subject.CommonName, Issuer: q.Get("iss"), Subject: q.Get("sub"), Sid: q.Get("sid"),
		ACR: q.Get("acr"), AMR: q["amr"]}
	at, errAt := strconv.ParseInt(q.Get("auth_time"), 10, 64)
	iat, errIat := strconv.ParseInt(q.Get("iat"), 10, 64)
	if errAt != nil || errIat != nil {
		return SignIn{}, errors.New("its sign-in's auth_time or iat is not a number")
	}
	s.AuthTime, s.IssuedAt = time.Unix(at, 0), time.Unix(iat, 0)
	if err := s.validate(); err != nil {
		return SignIn{}, err
	}
	return s, nil
}

// validate holds s to what ReadSignIn accepts, so that Issue never signs a
// sign-in its own reader would refuse on every later use.
func (s SignIn) validate() error {
	switch {
	case !printable(s.Principal) || !strings.HasPrefix(s.Principal, "user:") || !strings.Contains(s.Principal, "@"):
		return errors.New("its subject CN is not a principal (user: and an address)")
	}
	switch s.Method {
	case "", MethodOIDC:
		if CarriesIssuer(s.Issuer) != nil {
			return errors.New("its sign-in's iss is not an https URL")
		}
	case MethodDirectoryPassword:
		hexPart := strings.TrimPrefix(s.Subject, entrySubjectPrefix)
		switch {
		case s.Issuer != "":
			return errors.New("a directory sign-in carries no iss")
		case s.Sid != "" || s.ACR != "":
			return errors.New("a directory sign-in carries no sid or acr")
		case !strings.HasPrefix(s.Subject, entrySubjectPrefix) || len(hexPart) != 64 || !isLowerHex(hexPart):
			return errors.New("a directory sign-in's sub is not entry-sha256: and 64 hex digits")
		case len(s.AMR) == 0:
			return errors.New("a directory sign-in names no amr")
		}
	default:
		return errors.New("its sign-in names a method port49 does not issue")
	}
	switch {
	case !printable(s.Subject):
		return errors.New("its sign-in has no usable sub")
	case s.Sid != "" && !printable(s.Sid), s.ACR != "" && !printable(s.ACR),
		slices.ContainsFunc(s.AMR, func(m string) bool { return !printable(m) }):
		return errors.New("its sign-in's sid, amr or acr is not printable")
	}
	return nil
}

// CarriesIssuer is nil when an issued certificate can carry iss as the
// sign-in's issuer: an https URL of printable ASCII with no space, at most
// 1024 bytes. It is the rule validate applies, exposed so that config load
// can refuse an OIDC verifier whose issuer URL no certificate could carry.
func CarriesIssuer(iss string) error {
	if !printable(iss) || !strings.HasPrefix(iss, "https://") {
		return errors.New("it is not an https URL of printable ASCII (no space, at most 1024 bytes)")
	}
	return nil
}

// isLowerHex is true for a string of only 0-9 and a-f.
func isLowerHex(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return (r < '0' || r > '9') && (r < 'a' || r > 'f') }) < 0
}

// printable is 1 to 1024 bytes of printable ASCII, no space.
func printable(s string) bool {
	return s != "" && len(s) <= 1024 && strings.IndexFunc(s, func(r rune) bool { return r < 0x21 || r > 0x7e }) < 0
}
