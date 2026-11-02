package hwkeysetup

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/hwkey/serialmask"
	"github.com/blanketfish/port49/internal/pivattest"
)

// The L91 fixtures are the SER8 token's captured facts with the serial masked
// (tests/lab/l91fixture). They are a capture, not a lab measurement of hwkey:
// they close no L91 cell.
const l91Dir = "testdata/l91"

type l91Shape struct {
	Slots map[string]struct {
		Subject         string   `json:"subject"`
		Issuer          string   `json:"issuer"`
		ExtensionOIDs   []string `json:"extension_oids"`
		PINPolicy       string   `json:"pin_policy"`
		TouchPolicy     string   `json:"touch_policy"`
		FirmwareVersion string   `json:"firmware_version"`
		KeyAlgorithm    string   `json:"key_algorithm"`
		Curve           string   `json:"curve"`
	} `json:"slots"`
}

func loadShape(t *testing.T) l91Shape {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(l91Dir, "shape.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s l91Shape
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(l91Dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The masked label line, with <serial> replaced by the fake's 12345678, masks
// back to the same line.
func TestMaskSerialOnTheL91Label(t *testing.T) {
	var line string
	for _, l := range strings.Split(readFixture(t, "tokens.masked.txt"), "\n") {
		if strings.Contains(l, "token label") {
			line = l
		}
	}
	if !strings.Contains(line, "<serial>") {
		t.Fatalf("no masked label line in tokens.masked.txt: %q", line)
	}
	unmasked := strings.ReplaceAll(line, "<serial>", "12345678")
	if got := serialmask.MaskSerial(unmasked); got != line {
		t.Fatalf("masking the label gives %q, want %q", got, line)
	}
}

// The ID: of each certificate object, matched by its libykcs11 label, is the
// SlotIDs entry for 9a, 9c and 9e (and 9d if the listing shows it).
func TestSlotIDsMatchTheL91Objects(t *testing.T) {
	objs := readFixture(t, "objects.masked.txt")
	re := regexp.MustCompile(`(?m)^\s*label:\s+X\.509 Certificate for PIV Attestation (9[a-e])\s*\n(?:.*\n)*?\s*ID:\s+([0-9a-f]{2})\s*$`)
	got := map[string]string{}
	for _, m := range re.FindAllStringSubmatch(objs, -1) {
		got[m[1]] = m[2]
	}
	for slot, want := range map[string]string{"9a": "01", "9c": "02", "9e": "04"} {
		if got[slot] != want {
			t.Errorf("the capture lists %s at ID %q, want %q", slot, got[slot], want)
		}
		if id := SlotIDs[slot]; got[slot] != strings.ToLower(hexByte(id)) {
			t.Errorf("SlotIDs[%s] = %#x, the capture says %q", slot, id, got[slot])
		}
	}
	if id, ok := got["9d"]; ok && hexByte(SlotIDs["9d"]) != id {
		t.Errorf("SlotIDs[9d] = %#x, the capture says %q", SlotIDs["9d"], id)
	}
}

func hexByte(b byte) string {
	return strings.ToLower(string("0123456789abcdef"[b>>4]) + string("0123456789abcdef"[b&15]))
}

var maskedSerialRun = regexp.MustCompile(`<serial>`)

// testpki.NewPIV's device and slot certificates carry the extension OIDs, key
// algorithm, curve and DN form the real token's do.
func TestTestPKIMatchesTheL91Shape(t *testing.T) {
	shape := loadShape(t)
	now := time.Now()
	tok := newToken(t, now, pivattest.TouchAlways, fakeSerial)
	certs, _ := tok.session.Certificates()
	byName := map[string]*x509.Certificate{"f9": tok.piv.Device}
	for _, c := range certs {
		if c != tok.piv.Device && byName["9a"] == nil {
			byName["9a"] = c
		}
	}
	byName["9c"] = certs[2]
	dnForm := func(s string) *regexp.Regexp {
		return regexp.MustCompile("^" + strings.ReplaceAll(regexp.QuoteMeta(s), regexp.QuoteMeta("<serial>"), `\d+`) + "$")
	}
	for _, name := range []string{"9a", "9c", "f9"} {
		want, c := shape.Slots[name], byName[name]
		var oids []string
		for _, e := range c.Extensions {
			oids = append(oids, e.Id.String())
		}
		slices.Sort(oids)
		if !slices.Equal(oids, want.ExtensionOIDs) {
			t.Errorf("%s: extension OIDs %v, the token's %v", name, oids, want.ExtensionOIDs)
		}
		var alg, curve string
		switch k := c.PublicKey.(type) {
		case *ecdsa.PublicKey:
			alg, curve = "ECDSA", k.Curve.Params().Name
		case *rsa.PublicKey:
			alg = "RSA"
		}
		if alg != want.KeyAlgorithm || curve != want.Curve {
			t.Errorf("%s: key %s %s, the token's %s %s", name, alg, curve, want.KeyAlgorithm, want.Curve)
		}
		for what, pair := range map[string][2]string{"subject": {c.Subject.String(), want.Subject}, "issuer": {c.Issuer.String(), want.Issuer}} {
			form := pair[1]
			if name != "f9" && what == "subject" {
				form = strings.TrimSuffix(form, " "+name) + " 9a" // testpki names every slot 9a
				if name == "9c" {
					form = pair[1]
					pair[0] = strings.TrimSuffix(pair[0], " 9a") + " 9c"
				}
			}
			if !dnForm(form).MatchString(pair[0]) {
				t.Errorf("%s %s: %q does not have the token's form %q", name, what, pair[0], pair[1])
			}
		}
		if name != "f9" {
			pin, touch, err := pivattest.KeyPolicy(c)
			if err != nil || hexLit(pin) != want.PINPolicy || hexLit(touch) != want.TouchPolicy {
				t.Errorf("%s: policy %v %v err %v, the token's %s %s (see the next test)", name, hexLit(pin), hexLit(touch), err,
					want.PINPolicy, want.TouchPolicy)
			}
		}
	}
	_ = maskedSerialRun
}

func hexLit(b byte) string { return "0x" + hexByte(b) }

// The policy bytes the token's 9a and 9c report are the ones
// TestAGoodTokenIsReady builds: 9a PIN once and touch never, 9c PIN once and
// touch always. If the token differed, the fixture would follow the token.
func TestTheL91SlotPoliciesAreTheFixtures(t *testing.T) {
	shape := loadShape(t)
	for slot, want := range map[string][2]byte{"9a": {pivattest.PINOnce, pivattest.TouchNever}, "9c": {pivattest.PINOnce, pivattest.TouchAlways}} {
		got := shape.Slots[slot]
		if got.PINPolicy != hexLit(want[0]) || got.TouchPolicy != hexLit(want[1]) {
			t.Errorf("slot %s: the token reports PIN %s touch %s, the fixture builds PIN %s touch %s",
				slot, got.PINPolicy, got.TouchPolicy, hexLit(want[0]), hexLit(want[1]))
		}
	}
}
