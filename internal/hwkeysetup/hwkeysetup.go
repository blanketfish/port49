// Package hwkeysetup is what `port49 hwkey setup` and `port49 hwkey status`
// share (spec §13 decision 55 rulings 16 and 17): the checks of a user's
// security key for hardware_key_touch, the roots they run against, and the
// module they load. It is read-only on the token. Every check is the broker's
// own, pivattest.VerifyPair, and none repeats a step of it; every string it
// returns has passed serialmask.MaskSerial.
package hwkeysetup

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/blanketfish/port49/internal/agent"
	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/hwkey"
	"github.com/blanketfish/port49/internal/hwkey/pkcs11"
	"github.com/blanketfish/port49/internal/hwkey/serialmask"
	"github.com/blanketfish/port49/internal/mfatouch"
	"github.com/blanketfish/port49/internal/pivattest"
)

// SlotIDs maps a PIV slot to the CKA_ID libykcs11 gives its objects. 9a, 9c
// and 9e are measured (tests/lab/results/L60-ser8.md, the read-only-session
// table: 0x01, 0x02, 0x04, and f9 at 0x19), and the L91 capture of the same
// token lists the same IDs (a capture, not a lab measurement of hwkey). 9d is
// the PIV standard's and unmeasured, and no default uses it.
var SlotIDs = map[string]byte{"9a": 0x01, "9c": 0x02, "9d": 0x03, "9e": 0x04}

// SlotURI is the pkcs11: reference of the key in slot on the token labelled
// tokenLabel, through module, built by pkcs11's own encoder. It can carry the
// serial (the label does): print it only through serialmask.MaskSerial.
func SlotURI(module, tokenLabel, slot string) (string, error) {
	id, ok := SlotIDs[slot]
	if !ok {
		return "", fmt.Errorf("%q is not a PIV slot port49 knows (9a, 9c, 9d or 9e)", slot)
	}
	return pkcs11.URI{Token: tokenLabel, ID: []byte{id}, ModulePath: module}.String(), nil
}

// The closed set of check names.
const (
	CheckSessionSlot      = "session_slot"
	CheckTouchSlot        = "touch_slot"
	CheckAttestationRoots = "attestation_roots"
	CheckSessionAttested  = "session_attested"
	CheckTouchAttested    = "touch_attested"
	CheckTouchPolicy      = "touch_policy"
	CheckSameToken        = "same_token"

	// Status alone.
	CheckConfigIssuedKey   = "config_issued_key"
	CheckConfigTouchKey    = "config_touch_key"
	CheckIssuedCertificate = "issued_certificate"
	CheckCertificateExpiry = "certificate_expiry"
	CheckAgent             = "agent"
)

// CheckNames is every name a Check may carry.
var CheckNames = []string{
	CheckSessionSlot, CheckTouchSlot, CheckAttestationRoots, CheckSessionAttested, CheckTouchAttested,
	CheckTouchPolicy, CheckSameToken,
	CheckConfigIssuedKey, CheckConfigTouchKey, CheckIssuedCertificate, CheckCertificateExpiry, CheckAgent,
}

// Check is one finding. Why is a fixed sentence, never a serial, PIN or secret.
type Check struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
	Why  string `json:"why"`
}

// Report is what Inspect finds. Token is the token's label with the serial
// masked as <serial>; Roots is the roots line's text after "roots: ".
type Report struct {
	Token  string  `json:"token"`
	Roots  string  `json:"roots"`
	Checks []Check `json:"checks"`
	Ready  bool    `json:"ready"`
}

// Failed is the check named name, if it failed.
func (r Report) Failed(name string) bool {
	for _, c := range r.Checks {
		if c.Name == name && !c.OK {
			return true
		}
	}
	return false
}

// Append adds checks to the report (status's, beyond ruling 16's), masked, and
// recomputes Ready.
func (r *Report) Append(checks ...Check) {
	for _, c := range checks {
		c.Why = serialmask.MaskSerial(c.Why)
		r.Checks = append(r.Checks, c)
	}
	*r = finish(*r)
}

// Keys is what Inspect looks at: the keys opened in the session and touch
// slots (nil when the slot holds none, with the reason in SessionWhy or
// TouchWhy) and where the roots came from, for a message that names them.
type Keys struct {
	Session, Touch         hwkey.Key
	SessionWhy, TouchWhy   string
	SessionSlot, RootsFrom string
}

// Inspect runs the checks of ruling 16 on k against anchors (nil for none) at
// now. A check that cannot be made because an earlier one failed fails, saying
// so: nothing unverified counts as passed.
func Inspect(k Keys, anchors *pivattest.Anchors, now time.Time) Report {
	var r Report
	add := func(name string, ok bool, why string) {
		r.Checks = append(r.Checks, Check{Name: name, OK: ok, Why: serialmask.MaskSerial(why)})
	}
	slot := cmpOr(k.SessionSlot, "9a")
	add(CheckSessionSlot, k.Session != nil, ifNil(k.Session, cmpOr(k.SessionWhy, "slot "+slot+" holds no key libykcs11 lists")))
	add(CheckTouchSlot, k.Touch != nil, ifNil(k.Touch, cmpOr(k.TouchWhy, "slot 9c holds no key libykcs11 lists")))
	rootsOK := anchors != nil && anchors.Roots != nil
	add(CheckAttestationRoots, rootsOK, ifBool(!rootsOK, "no attestation roots"))

	notReached := func(why string) {
		for _, n := range []string{CheckSessionAttested, CheckTouchAttested, CheckTouchPolicy, CheckSameToken} {
			add(n, false, "not checked: "+why)
		}
	}
	switch {
	case k.Session == nil || k.Touch == nil:
		notReached("a key is missing")
		return finish(r)
	case !rootsOK:
		notReached("there are no roots")
		return finish(r)
	}

	certs := union(k.Session, k.Touch)
	chain, err := mfatouch.Chain(certs, k.Touch.Public(), k.Session.Public())
	if err != nil {
		// No device certificate on the tokens signs an attestation of both keys.
		own := func(key hwkey.Key) bool {
			_, err := mfatouch.Chain(union(key), key.Public(), key.Public())
			return err == nil
		}
		add(CheckSessionAttested, own(k.Session), ifBool(!own(k.Session), "the token holds no attestation certificate for this key"))
		add(CheckTouchAttested, own(k.Touch), ifBool(!own(k.Touch), "the token holds no attestation certificate for this key"))
		add(CheckTouchPolicy, false, "not checked: the two keys share no device certificate")
		add(CheckSameToken, false, "the two keys' attestations do not share one device certificate")
		return finish(r)
	}
	touchC, deviceC, sessionC, err := decode(chain)
	if err != nil {
		notReached("an attestation certificate does not parse")
		return finish(r)
	}
	_, _, why, verr := pivattest.VerifyPair(*anchors, deviceC, sessionC, touchC, now)
	detail := func() string {
		return "does not verify against the roots (" + cmpOr(k.RootsFrom, "the roots given") + "): " + short(verr)
	}
	switch why {
	case "touch_slot_chain":
		add(CheckSessionAttested, false, "not checked: the touch slot failed first, against the same roots")
		add(CheckTouchAttested, false, "the touch slot's attestation "+detail())
		add(CheckTouchPolicy, false, "not checked: the touch slot's attestation failed")
		add(CheckSameToken, false, "not checked: the touch slot's attestation failed")
		return finish(r)
	case "session_slot_chain":
		add(CheckSessionAttested, false, "the session slot's attestation "+detail())
		add(CheckTouchAttested, true, "")
		add(CheckTouchPolicy, false, "not checked: the session slot's attestation failed")
		add(CheckSameToken, false, "not checked: the session slot's attestation failed")
		return finish(r)
	}
	add(CheckSessionAttested, true, "")
	add(CheckTouchAttested, true, "")
	if why == "touch_policy" {
		add(CheckTouchPolicy, false, "the touch key must be made with touch policy always: "+short(verr))
	} else if why == "device_mismatch" {
		add(CheckTouchPolicy, false, "not checked: the keys are on different devices")
	} else {
		add(CheckTouchPolicy, true, "")
	}
	same, sameWhy := agent.SameToken(k.Session, k.Touch)
	switch {
	case why == "device_mismatch":
		add(CheckSameToken, false, "the touch key and the session key are not attested by the same device")
	case !same:
		add(CheckSameToken, false, sameWhy)
	default:
		add(CheckSameToken, true, "")
	}
	return finish(r)
}

func finish(r Report) Report {
	r.Ready = true
	for _, c := range r.Checks {
		r.Ready = r.Ready && c.OK
	}
	return r
}

// short is err's text on one line, bounded, and masked.
func short(err error) string {
	if err == nil {
		return ""
	}
	s := strings.Join(strings.Fields(err.Error()), " ")
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func ifNil(k hwkey.Key, why string) string {
	if k == nil {
		return why
	}
	return ""
}

func ifBool(b bool, s string) string {
	if b {
		return s
	}
	return ""
}

// certLister is a key whose token lists its certificate objects
// (pkcs11.Signer, hwfake.Key).
type certLister interface {
	Certificates() ([]*x509.Certificate, error)
}

// union is every certificate the keys' tokens list, once each.
func union(keys ...hwkey.Key) []*x509.Certificate {
	var out []*x509.Certificate
	for _, k := range keys {
		l, ok := k.(certLister)
		if !ok {
			continue
		}
		certs, err := l.Certificates()
		if err != nil {
			continue
		}
		for _, c := range certs {
			if !slices.ContainsFunc(out, func(o *x509.Certificate) bool { return o.Equal(c) }) {
				out = append(out, c)
			}
		}
	}
	return out
}

// decode is mfatouch.Chain's answer (touch, device, session) parsed.
func decode(chain []string) (touch, device, session *x509.Certificate, err error) {
	var cs [3]*x509.Certificate
	for i, s := range chain {
		der, derr := base64.RawURLEncoding.DecodeString(s)
		if derr != nil {
			return nil, nil, nil, derr
		}
		if cs[i], err = x509.ParseCertificate(der); err != nil {
			return nil, nil, nil, err
		}
	}
	return cs[0], cs[1], cs[2], nil
}

// Roots are the attestation roots a run checks against and where they came from.
type Roots struct {
	Anchors pivattest.Anchors
	// Source is "--roots <file>" or "from broker <host>".
	Source string
}

// The refusals LoadRoots returns, each exit 2.
var (
	ErrNoRoots           = errors.New("no attestation roots")
	ErrBrokerUnreachable = errors.New("broker unreachable")
	// ErrBrokerUntrusted is a broker whose certificate is not from the
	// configured broker CA: a trust failure, not an outage (pre-flight F21).
	ErrBrokerUntrusted = errors.New("broker certificate not trusted")
)

// rootsError carries the sentence a user reads and the sentinel it is.
type rootsError struct {
	sentinel error
	msg      string
}

func (e *rootsError) Error() string        { return e.msg }
func (e *rootsError) Is(target error) bool { return target == e.sentinel }

// LoadRoots reads the roots a run checks against. rootsFile first, for offline
// use; otherwise fetch, which is the broker's GET /v1/config over TLS to the
// configured broker CA. broker only names the host in a message.
func LoadRoots(ctx context.Context, rootsFile, broker string, fetch func(ctx context.Context) (api.Config, error)) (Roots, error) {
	if rootsFile != "" {
		b, err := os.ReadFile(rootsFile)
		if err != nil {
			return Roots{}, fmt.Errorf("reading --roots %s: %w", rootsFile, errors.Unwrap(err))
		}
		a, err := pivattest.ParseAnchors(b)
		if err != nil {
			return Roots{}, fmt.Errorf("--roots %s: %w", rootsFile, err)
		}
		return Roots{Anchors: a, Source: "--roots " + rootsFile}, nil
	}
	host := hostOf(broker)
	if broker == "" || fetch == nil {
		return Roots{}, &rootsError{ErrNoRoots, "no attestation roots: no broker is configured to fetch them from; " +
			"pass --roots FILE, or --broker URL"}
	}
	conf, err := fetch(ctx)
	if err != nil {
		var uae x509.UnknownAuthorityError
		var cv *tls.CertificateVerificationError
		if errors.Is(err, ErrBrokerUntrusted) || errors.As(err, &uae) || errors.As(err, &cv) {
			return Roots{}, &rootsError{ErrBrokerUntrusted, fmt.Sprintf("the broker %s did not present a certificate from the "+
				"configured broker CA, so the attestation roots were not fetched: check broker_ca, or pass --roots FILE", host)}
		}
		return Roots{}, &rootsError{ErrBrokerUnreachable, fmt.Sprintf("the broker %s is unreachable, so the attestation roots "+
			"could not be fetched: retry, or pass --roots FILE", host)}
	}
	if conf.HardwareKeyTouch == nil || conf.HardwareKeyTouch.AttestationRootsPEM == "" {
		return Roots{}, &rootsError{ErrNoRoots, fmt.Sprintf("no attestation roots: the broker %s serves none, so it does not "+
			"verify hardware_key_touch (broker.identity.per_login_mfa.hardware_key_touch.attestation_roots_file is not set); "+
			"pass --roots FILE", host)}
	}
	a, err := pivattest.ParseAnchors([]byte(conf.HardwareKeyTouch.AttestationRootsPEM))
	if err != nil {
		return Roots{}, fmt.Errorf("the roots the broker %s served do not parse: %w", host, err)
	}
	return Roots{Anchors: a, Source: "from broker " + host}, nil
}

func hostOf(broker string) string {
	if u, err := url.Parse(broker); err == nil && u.Host != "" {
		return u.Host
	}
	return broker
}

// ErrNoModule is no libykcs11 anywhere setup looks (exit 2).
var ErrNoModule = errors.New("no libykcs11 found; install yubico-piv-tool or pass --module")

// ModuleCandidates are the system paths a libykcs11 is probed at, in order,
// under root (a stand-in for "/" in tests). Each path is one a package
// installs; a path no package installs is not listed.
//
//   - Debian and Ubuntu, package ykcs11: /usr/lib/<multiarch>/libykcs11.so.2
//     and libykcs11.so (<multiarch> is x86_64-linux-gnu or aarch64-linux-gnu).
//     The L60 and L86 harnesses load /usr/lib/x86_64-linux-gnu/libykcs11.so
//     on the SER8.
//   - Fedora and RHEL, package yubico-piv-tool: /usr/lib64/libykcs11.so.2
//     and libykcs11.so.
//   - macOS, Intel Homebrew's yubico-piv-tool and Yubico's own installer:
//     /usr/local/lib/libykcs11.dylib. No Linux /usr/local/lib path: only a
//     source build puts one there.
//   - macOS, Apple-silicon Homebrew: /opt/homebrew/lib/libykcs11.dylib.
func ModuleCandidates(root, goos, goarch string) []string {
	var rel []string
	switch goos {
	case "linux":
		if multi := map[string]string{"amd64": "x86_64-linux-gnu", "arm64": "aarch64-linux-gnu"}[goarch]; multi != "" {
			rel = append(rel, "usr/lib/"+multi+"/libykcs11.so.2", "usr/lib/"+multi+"/libykcs11.so")
		}
		rel = append(rel, "usr/lib64/libykcs11.so.2", "usr/lib64/libykcs11.so")
	case "darwin":
		rel = append(rel, "usr/local/lib/libykcs11.dylib", "opt/homebrew/lib/libykcs11.dylib")
	}
	out := make([]string, len(rel))
	for i, p := range rel {
		out[i] = filepath.Join(root, "/", p)
	}
	return out
}

// FindModule is the first candidate that exists and passes check (the rule the
// agent applies to a module: userconfig.CheckOwned). A path that does not exist
// is passed over silently; one that exists and fails is skipped with one line
// to say. None is ErrNoModule.
func FindModule(root, goos, goarch string, check func(string) error, say func(string)) (string, error) {
	for _, p := range ModuleCandidates(root, goos, goarch) {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if err := check(p); err != nil {
			say(fmt.Sprintf("skipping %s: %v", p, err))
			continue
		}
		return p, nil
	}
	return "", ErrNoModule
}
