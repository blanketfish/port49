package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/engine"
)

const docPolicy = "scopes: [{name: all_devices, match: {}}]\n"

func docInventory() admission.Inventory {
	return admission.Inventory{Devices: []admission.Device{
		{Name: "leaf-02", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.3")},
			Attributes: map[string]string{"site": "dc1"}, Transport: admission.TransportTCP},
		{Name: "leaf-01", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.2"),
			netip.MustParseAddr("10.0.0.1")}, Transport: admission.TransportTCP},
	}}
}

func sealed(t *testing.T, inv admission.Inventory, key ed25519.PrivateKey) []byte {
	t.Helper()
	raw, err := Seal(NewDocument(7, time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC), []byte(docPolicy), "1.1.0", inv,
		map[string][]string{"lab_file": {"leaf-01", "leaf-02"}}), key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// sealBody signs bytes the test wrote itself, to hand Open a document the
// service would never write.
func sealBody(t *testing.T, body []byte, key ed25519.PrivateKey) []byte {
	t.Helper()
	raw, err := json.Marshal(envelope{Document: body, KeyID: keyIDOf(key), Signature: ed25519.Sign(key, body)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func keyIDOf(key ed25519.PrivateKey) string { return KeyIDOf(key.Public().(ed25519.PublicKey)) }

func TestASealedDocumentOpensWithItsKey(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	doc, inv, err := Open(sealed(t, docInventory(), key), []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	if doc.Sequence != 7 || doc.PlatformSet != "1.1.0" || doc.PolicySHA256 != engine.HashOf([]byte(docPolicy)) {
		t.Fatalf("doc %+v", doc)
	}
	// The name port49d computes from the same policy and the opened
	// inventory is the one the service wrote (spec §10).
	if doc.Bundle != ID([]byte(docPolicy), inv) || doc.Bundle != ID([]byte(docPolicy), docInventory()) {
		t.Fatalf("bundle %s", doc.Bundle)
	}
	if string(Canonical(inv)) != string(Canonical(docInventory())) {
		t.Fatal("the inventory did not round-trip")
	}
}

// A signing-key rotation: port49d holds both public keys for a while.
func TestADocumentOpensWithAnyVerifyKeyThatSignedIt(t *testing.T) {
	oldPub, _, _ := ed25519.GenerateKey(rand.Reader)
	newPub, newKey, _ := ed25519.GenerateKey(rand.Reader)
	raw := sealed(t, docInventory(), newKey)
	if _, _, err := Open(raw, []ed25519.PublicKey{oldPub}); err == nil ||
		!strings.Contains(err.Error(), "signed by "+KeyIDOf(newPub)+", which no verify key holds") {
		t.Fatalf("old key only: %v", err)
	}
	if _, _, err := Open(raw, []ed25519.PublicKey{oldPub, newPub}); err != nil {
		t.Fatal(err)
	}
}

func TestAnyChangeToTheSignedBytesIsRefused(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	var e envelope
	if err := json.Unmarshal(sealed(t, docInventory(), key), &e); err != nil {
		t.Fatal(err)
	}
	e.Document = []byte(strings.Replace(string(e.Document), "10.0.0.3", "10.66.0.1", 1))
	raw, _ := json.Marshal(e)
	if _, _, err := Open(raw, []ed25519.PublicKey{pub}); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("got %v", err)
	}
}

// Plan 6b owner decision 3: nothing the service sends assigns a key.
func TestADocumentThatAssignsAKeyIsRefused(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	pinned := docInventory()
	pinned.Devices[0].KeyRef = "lab_key"
	if _, _, err := Open(sealed(t, pinned, key), []ed25519.PublicKey{pub}); err == nil ||
		!strings.Contains(err.Error(), "pins key_ref") {
		t.Fatalf("pin: %v", err)
	}
	grouped := docInventory()
	grouped.KeyGroups = []admission.KeyGroup{{CIDR: netip.MustParsePrefix("10.0.0.0/8"), KeyRef: "lab_key"}}
	if _, _, err := Open(sealed(t, grouped, key), []ed25519.PublicKey{pub}); err == nil ||
		!strings.Contains(err.Error(), "carries key_groups") {
		t.Fatalf("groups: %v", err)
	}
}

// Decided 10: a name that could not reach a line safely is refused, and not
// printed.
func TestADocumentWithAnUnusableNameIsRefusedWithoutEchoingIt(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	for name, mutate := range map[string]func(*admission.Inventory){
		"name":      func(i *admission.Inventory) { i.Devices[0].Name = "leaf\nINJECTED" },
		"space":     func(i *admission.Inventory) { i.Devices[0].Name = "leaf INJECTED" },
		"attribute": func(i *admission.Inventory) { i.Devices[0].Attributes["site"] = "dc1\x1b[2JINJECTED" },
		"transport": func(i *admission.Inventory) { i.Devices[0].Transport = "tls INJECTED" },
		"zone":      func(i *admission.Inventory) { i.Devices[0].Addresses[0] = netip.MustParseAddr("fe80::1%INJECTED") },
	} {
		inv := docInventory()
		mutate(&inv)
		_, _, err := Open(sealed(t, inv, key), []ed25519.PublicKey{pub})
		if err == nil || strings.Contains(err.Error(), "INJECTED") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A device name a source lists is held to the inventory's name rule, and not
// printed.
func TestADocumentWithAnUnusableSourceDeviceNameIsRefusedWithoutEchoingIt(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	for _, bad := range []string{"leaf\nINJECTED", "leaf INJECTED", "leaf\x1b[2JINJECTED", ""} {
		raw, err := Seal(NewDocument(1, time.Now(), []byte(docPolicy), "1.1.0", docInventory(),
			map[string][]string{"lab_file": {"leaf-01", bad}}), key)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := Open(raw, []ed25519.PublicKey{pub}); err == nil || strings.Contains(err.Error(), "INJECTED") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// A field a line prints is checked for shape (pre-flight minor 9), and an
// unknown signer is told apart from a bad signature (minor 4).
func TestAPrintedFieldOfTheWrongShapeIsRefused(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	d := NewDocument(1, time.Now(), []byte(docPolicy), "1.1.0", docInventory(), nil)
	d.PolicySHA256 = "sha256:\nINJECTED"
	body, _ := json.Marshal(d)
	if _, _, err := Open(sealBody(t, body, key), []ed25519.PublicKey{pub}); err == nil ||
		strings.Contains(err.Error(), "INJECTED") {
		t.Fatalf("got %v", err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, _, err := Open(sealed(t, docInventory(), key), []ed25519.PublicKey{other}); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("an unknown signer: %v", err)
	}
}

func TestAnUnknownFieldOrFormatIsRefused(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	good, _ := json.Marshal(NewDocument(1, time.Now(), []byte(docPolicy), "1.1.0", docInventory(), nil))
	for name, body := range map[string]string{
		"unknown field": strings.Replace(string(good), `"format"`, `"grants":["everyone"],"format"`, 1),
		"other format":  strings.Replace(string(good), DocumentFormat, "port49-bundle/2", 1),
		"trailing":      string(good) + `{}`,
	} {
		if _, _, err := Open(sealBody(t, []byte(body), key), []ed25519.PublicKey{pub}); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
}

// An envelope is read before anything verifies it, so nothing in it is
// printed but a key id of the right shape.
func TestAGarbledEnvelopeIsRefusedWithoutEchoingIt(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	for _, raw := range []string{`SECRET not json`, `{"document":"eA==","key_id":"SECRET\n","signature":"eA=="}`,
		`{"document":"eA==","key_id":"ed25519:0011223344556677","signature":"eA==","SECRET":1}`} {
		if _, _, err := Open([]byte(raw), []ed25519.PublicKey{pub}); err == nil || strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%q: %v", raw, err)
		}
	}
}

func TestAnOversizedDocumentIsRefusedUnread(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, _, err := Open(make([]byte, MaxDocument+1), []ed25519.PublicKey{pub}); err == nil ||
		!strings.Contains(err.Error(), "larger than") {
		t.Fatalf("got %v", err)
	}
}

func TestAFlippedSignatureByteIsRefused(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	var e envelope
	if err := json.Unmarshal(sealed(t, docInventory(), key), &e); err != nil {
		t.Fatal(err)
	}
	e.Signature[0] ^= 1
	raw, _ := json.Marshal(e)
	if _, _, err := Open(raw, []ed25519.PublicKey{pub}); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("got %v", err)
	}
}

// Signed bytes that decode to a good document but are not spelled as the
// service writes them are refused: what was verified is what was read.
func TestASignedDocumentNotInTheServicesSpellingIsRefused(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	good, _ := json.Marshal(NewDocument(1, time.Now(), []byte(docPolicy), "1.1.0", docInventory(), nil))
	for name, body := range map[string]string{
		"duplicate key": strings.Replace(string(good), `"sequence":1`, `"sequence":99,"sequence":1`, 1),
		"case-varied":   strings.Replace(string(good), `"platform_set"`, `"PLATFORM_SET"`, 1),
	} {
		if body == string(good) {
			t.Fatalf("%s: the test's replacement did not apply", name)
		}
		if _, _, err := Open(sealBody(t, []byte(body), key), []ed25519.PublicKey{pub}); err == nil ||
			!strings.Contains(err.Error(), "not in the form port49 writes") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestANonCanonicalInventoryIsRefused(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	d := NewDocument(1, time.Now(), []byte(docPolicy), "1.1.0", docInventory(), nil)
	// Valid, and the default it spells, but not the canonical form.
	inv := strings.Replace(string(d.Inventory), `"addresses":["10.0.0.1","10.0.0.2"]}`,
		`"addresses":["10.0.0.1","10.0.0.2"],"transport":"tcp"}`, 1)
	if inv == string(d.Inventory) {
		t.Fatal("the test's replacement did not apply")
	}
	d.Inventory = json.RawMessage(inv)
	body, _ := json.Marshal(d)
	if _, _, err := Open(sealBody(t, body, key), []ed25519.PublicKey{pub}); err == nil ||
		!strings.Contains(err.Error(), "not in canonical form") {
		t.Fatalf("got %v", err)
	}
}

func TestAZeroPublishedAtIsRefused(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	d := NewDocument(1, time.Now(), []byte(docPolicy), "1.1.0", docInventory(), nil)
	d.PublishedAt = time.Time{}
	body, _ := json.Marshal(d)
	if _, _, err := Open(sealBody(t, body, key), []ed25519.PublicKey{pub}); err == nil ||
		!strings.Contains(err.Error(), "published_at") {
		t.Fatalf("got %v", err)
	}
}

// A verify key of the wrong length is passed over, never handed to Verify.
func TestAShortVerifyKeyIsSkipped(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	raw := sealed(t, docInventory(), key)
	short := ed25519.PublicKey(pub[:16])
	if _, _, err := Open(raw, []ed25519.PublicKey{short}); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("short only: %v", err)
	}
	if _, _, err := Open(raw, []ed25519.PublicKey{short, pub}); err != nil {
		t.Fatal(err)
	}
}
