package bundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/keyfile"
)

// DocumentFormat names the document's shape; Open refuses any other.
const DocumentFormat = "port49-bundle/1"

// MaxDocument bounds a sealed document as inventory_file is bounded: a
// 10,000-device inventory is a few megabytes.
const MaxDocument = 64 << 20

// Document is what the inventory service publishes (spec §10, "One versioned
// bundle"; §13 decisions 29 and 30): the inventory in the canonical form the
// bundle's name hashes, the policy and platform set the service built it
// against — named, never carried — the device names each source gave, which
// the service's next sync bounds against, and its place in the service's
// sequence.
type Document struct {
	Format       string              `json:"format"`
	Sequence     int64               `json:"sequence"`
	PublishedAt  time.Time           `json:"published_at"`
	Bundle       string              `json:"bundle"`
	PolicySHA256 string              `json:"policy_sha256"`
	PlatformSet  string              `json:"platform_set"`
	Sources      map[string][]string `json:"sources"`
	Inventory    json.RawMessage     `json:"inventory"`
}

// NewDocument is the document for inv, published as seq at at.
func NewDocument(seq int64, at time.Time, policyRaw []byte, platformSet string, inv admission.Inventory,
	sources map[string][]string) Document {
	return Document{Format: DocumentFormat, Sequence: seq, PublishedAt: at.UTC(), Bundle: ID(policyRaw, inv),
		PolicySHA256: engine.HashOf(policyRaw), PlatformSet: platformSet, Sources: sources, Inventory: Canonical(inv)}
}

// envelope is a document as it travels and rests: its exact bytes, which key
// signed them, and the signature. Signing the bytes, not a re-encoding, means
// nothing is canonicalized twice.
type envelope struct {
	Document  []byte `json:"document"`
	KeyID     string `json:"key_id"`
	Signature []byte `json:"signature"`
}

// KeyIDOf is keyfile.Ed25519KeyID, the name a document gives its key.
func KeyIDOf(pub ed25519.PublicKey) string { return keyfile.Ed25519KeyID(pub) }

// Seal is d, signed by key.
func Seal(d Document, key ed25519.PrivateKey) ([]byte, error) {
	body, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{Document: body, KeyID: KeyIDOf(key.Public().(ed25519.PublicKey)),
		Signature: ed25519.Sign(key, body)})
}

// ETag is the HTTP entity tag of sealed bytes.
func ETag(raw []byte) string { return `"` + engine.HashOf(raw) + `"` }

var (
	keyIDShape = regexp.MustCompile(`^ed25519:[0-9a-f]{16}$`)
	hashShape  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// ErrUnknownKey is a document signed by a key no verify key names: a
// rotation port49d has not heard of yet, most likely. A signature that does
// not verify under a key it holds is not this: that is tampering or a
// foreign signer (pre-flight minor 4).
var ErrUnknownKey = errors.New("bundle")

// Open verifies raw against keys and reads it (spec §13, decision 30): the
// envelope, then the signature, and only then the document, strictly —
// an unknown field, another format or trailing bytes refuse it. A document
// that assigns a key (plan 6b owner decision 3), names a device with an
// unusable name or text (Decided 10), or does not validate as an inventory
// is refused. No error quotes the document: an envelope is read before
// anything vouches for it, and the rest is printed by position.
func Open(raw []byte, keys []ed25519.PublicKey) (Document, admission.Inventory, error) {
	if len(raw) > MaxDocument {
		return Document{}, admission.Inventory{}, fmt.Errorf("bundle: the document is larger than %d bytes", MaxDocument)
	}
	var e envelope
	if strict(raw, &e) != nil {
		return Document{}, admission.Inventory{}, errors.New("bundle: the sealed document does not parse")
	}
	if !keyIDShape.MatchString(e.KeyID) {
		return Document{}, admission.Inventory{}, errors.New("bundle: the sealed document names no key id of the form ed25519:<16 hex>")
	}
	var pub ed25519.PublicKey
	for _, k := range keys {
		// ed25519.Verify panics on a key of any other length.
		if len(k) == ed25519.PublicKeySize && KeyIDOf(k) == e.KeyID {
			pub = k
		}
	}
	if pub == nil {
		return Document{}, admission.Inventory{}, fmt.Errorf("%w: the document is signed by %s, which no verify key "+
			"holds", ErrUnknownKey, e.KeyID)
	}
	if !ed25519.Verify(pub, e.Document, e.Signature) {
		return Document{}, admission.Inventory{}, fmt.Errorf("bundle: the document's signature by %s does not verify", e.KeyID)
	}
	var d Document
	if strict(e.Document, &d) != nil {
		return Document{}, admission.Inventory{}, errors.New("bundle: the signed document does not parse as a port49 bundle")
	}
	if d.Format != DocumentFormat {
		return Document{}, admission.Inventory{}, fmt.Errorf("bundle: the document is not in format %s", DocumentFormat)
	}
	// The service writes the document as json.Marshal does. One spelled
	// otherwise — a duplicate key, a field name in another case — is not the
	// service's, and what was verified must be exactly what was read.
	if again, err := json.Marshal(d); err != nil || !bytes.Equal(again, e.Document) {
		return Document{}, admission.Inventory{}, errors.New("bundle: the signed document is not in the form port49 writes")
	}
	// Every field a line prints is checked for shape first (pre-flight
	// minor 9): the start line, the swap line and the mismatch line name them.
	if !hashShape.MatchString(d.Bundle) || !hashShape.MatchString(d.PolicySHA256) || !NameOK(d.PlatformSet) ||
		d.Sequence < 1 || d.PublishedAt.IsZero() {
		return Document{}, admission.Inventory{}, errors.New("bundle: the document's bundle, policy_sha256, " +
			"platform_set, sequence or published_at is not of the form port49 writes")
	}
	for name, devices := range d.Sources {
		if !NameOK(name) {
			return Document{}, admission.Inventory{}, errors.New("bundle: the document names a source that is not a name")
		}
		// The service's next sync bounds against these, and its lines name
		// them: DeviceProblem's name rule, as for the inventory.
		for _, dev := range devices {
			if !NameOK(dev) {
				return Document{}, admission.Inventory{}, errors.New("bundle: the document lists, under a source, a " +
					"device name that is not 1 to 255 bytes of printable ASCII without a space")
			}
		}
	}
	inv, err := inventoryOf(d.Inventory)
	if err != nil {
		return Document{}, admission.Inventory{}, err
	}
	return d, inv, nil
}

// UnverifiedSequence is the sequence raw's document states, read without
// verifying its signature. It is for a floor alone — the inventory service's
// check that it never saves below what it holds — where an unverified value
// can only refuse more; nothing else it says is to be believed.
func UnverifiedSequence(raw []byte) (int64, error) {
	var e envelope
	var d struct {
		Sequence int64 `json:"sequence"`
	}
	if len(raw) > MaxDocument || json.Unmarshal(raw, &e) != nil || json.Unmarshal(e.Document, &d) != nil {
		return 0, errors.New("bundle: the sealed document does not parse")
	}
	return d.Sequence, nil
}

// strict decodes one JSON value into v, refusing unknown fields and anything
// after it.
func strict(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

// inventoryOf reads the document's inventory back from its canonical form.
func inventoryOf(raw []byte) (admission.Inventory, error) {
	var c struct {
		Format    string        `json:"format"`
		Devices   []canonDevice `json:"devices"`
		KeyGroups []canonGroup  `json:"key_groups"`
	}
	if strict(raw, &c) != nil || c.Format != "port49-inventory/1" {
		return admission.Inventory{}, errors.New("bundle: the document's inventory does not parse")
	}
	if len(c.KeyGroups) > 0 {
		return admission.Inventory{}, errors.New("bundle: the document carries key_groups; key assignment is " +
			"reviewed policy, and nothing the inventory service sends assigns a key (spec §13, decision 30)")
	}
	var inv admission.Inventory
	for i, d := range c.Devices {
		label := fmt.Sprintf("#%d", i)
		if NameOK(d.Name) {
			label = d.Name
		}
		if d.KeyRef != "" {
			return admission.Inventory{}, fmt.Errorf("bundle: the document's device %s pins key_ref; key assignment "+
				"is reviewed policy, and nothing the inventory service sends assigns a key (spec §13, decision 30)", label)
		}
		dev := admission.Device{Name: d.Name, Platform: d.Platform, Transport: d.Transport}
		if dev.Transport == "" {
			dev.Transport = admission.TransportTCP
		}
		if len(d.Attributes) > 0 {
			dev.Attributes = d.Attributes
		}
		for j, s := range d.Addresses {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return admission.Inventory{}, fmt.Errorf("bundle: the document's device %s: addresses[%d] is not an "+
					"IP address", label, j)
			}
			dev.Addresses = append(dev.Addresses, a)
		}
		// The service's own rule (DeviceProblem): it leaves such a device out,
		// so one here was not published by it.
		if why := DeviceProblem(dev); why != "" {
			return admission.Inventory{}, fmt.Errorf("bundle: the document's device %s %s", label, why)
		}
		inv.Devices = append(inv.Devices, dev)
	}
	if err := admission.Validate(inv.Devices); err != nil {
		return admission.Inventory{}, fmt.Errorf("bundle: the document's inventory: %w", err)
	}
	// The service writes the canonical form; one that is not is not the
	// service's, whatever signed it.
	if !bytes.Equal(Canonical(inv), raw) {
		return admission.Inventory{}, errors.New("bundle: the document's inventory is not in canonical form")
	}
	return inv, nil
}

// DeviceProblem says why d cannot reach a record or a line safely, or "" when
// it can (Decided 10; pre-flight M2). It is the one rule: the service leaves
// out a device it names, and Open refuses a document carrying one, so
// whatever the service publishes, port49d opens. It never quotes the value.
func DeviceProblem(d admission.Device) string {
	switch {
	case !NameOK(d.Name):
		return "has a name that is not 1 to 255 bytes of printable ASCII without a space"
	case !NameOK(d.Platform):
		return "has a platform that is not 1 to 255 bytes of printable ASCII without a space"
	case d.Transport != "" && !NameOK(d.Transport):
		return "has a transport that is not 1 to 255 bytes of printable ASCII without a space"
	}
	for k, v := range d.Attributes {
		if !NameOK(k) || !TextOK(v) {
			return "has an attribute with a control character or an unusable key"
		}
	}
	for i, a := range d.Addresses {
		// A zone is free text, and netip keeps it through the canonical form.
		if a.Zone() != "" {
			return fmt.Sprintf("has a zoned address at addresses[%d]", i)
		}
	}
	return ""
}

// NameOK is a device name, platform or attribute key that can reach a record
// and a line as it is: 1 to 255 bytes of printable ASCII, no space — the
// broker's rule for a device name (pre-flight F11).
func NameOK(s string) bool {
	return s != "" && len(s) <= 255 && strings.IndexFunc(s, func(r rune) bool { return r < 0x21 || r > 0x7e }) < 0
}

// TextOK is an attribute value that can: valid UTF-8 of at most 255 bytes, every
// rune printable (a space included, no control character).
func TextOK(s string) bool {
	return len(s) <= 255 && utf8.ValidString(s) && strings.IndexFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }) < 0
}
