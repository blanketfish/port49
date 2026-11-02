package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/pivattest"
	"github.com/blanketfish/port49/internal/testpki"
)

// plantedForms is the fake serial testpki.DeviceSerial (12345678) in the forms
// a raw listing writes it.
var plantedForms = []string{"12345678", "0012345678", "BC614E", "bc614e", "00BC614E", "00bc614e"}

const listingTemplate = `Available slots:
Slot 0 (0x0): Yubico YubiKey OTP+FIDO+CCID 00 00
  token label        : YubiKey PIV #12345678
  token manufacturer : Yubico (www.yubico.com)
  token model        : YubiKey YK5
  serial num         : 12345678
  hex serial         : 00BC614E and bc614e and 00bc614e and BC614E
  padded decimal     : 0012345678
  uri: pkcs11:model=YubiKey%%20YK5;serial=12345678;token=YubiKey%%20PIV%%20%%2312345678;id=%%01
  extra              : %s
`

// rawInputs writes testpki-made raw inputs with the fake serial planted in
// every form. extra is one more line planted into both listings.
func rawInputs(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	p, err := testpki.NewPIV(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pemOf := func(der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}) }
	for _, s := range []struct {
		name  string
		touch byte
	}{{"9a", pivattest.TouchNever}, {"9c", pivattest.TouchAlways}, {"9e", pivattest.TouchNever}} {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		c, err := p.Slot(&k.PublicKey, s.touch)
		if err != nil {
			t.Fatal(err)
		}
		write("attest-"+s.name+".pem", pemOf(c.Raw))
	}
	write("attest-f9.pem", pemOf(p.Device.Raw))
	listing := []byte(strings.Replace(listingTemplate, "%s", extra, 1))
	listing = bytes.ReplaceAll(listing, []byte("%%"), []byte("%"))
	write("tokens.txt", listing)
	write("objects.txt", listing)
	return dir
}

func TestNoSerialFormSurvivesMasking(t *testing.T) {
	raw, out := rawInputs(t, "none"), filepath.Join(t.TempDir(), "out")
	var stdout bytes.Buffer
	if err := run(raw, out, &stdout, Forms); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"tokens.masked.txt", "objects.masked.txt", "shape.json"} {
		b, err := os.ReadFile(filepath.Join(out, n))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range plantedForms {
			if strings.Contains(strings.ToLower(string(b)), strings.ToLower(f)) {
				t.Errorf("%s still holds a serial form", n)
			}
		}
	}
	b, _ := os.ReadFile(filepath.Join(out, "tokens.masked.txt"))
	if !strings.Contains(string(b), "YubiKey PIV #<serial>") {
		t.Errorf("the label form is not masked to <serial>: %q", b)
	}
	// Only names and byte counts are printed.
	for _, f := range plantedForms {
		if strings.Contains(strings.ToLower(stdout.String()), strings.ToLower(f)) {
			t.Errorf("stdout holds a serial form: %q", stdout.String())
		}
	}
}

func TestAMaskingMissRefusesToWrite(t *testing.T) {
	raw, out := rawInputs(t, "none"), filepath.Join(t.TempDir(), "out")
	// A mask list that leaves out the upper-case hex forms.
	short := func(s uint32) []string { return Forms(s)[:3] }
	err := run(raw, out, new(bytes.Buffer), short)
	if err == nil || !strings.Contains(err.Error(), "a serial form survived masking in ") {
		t.Fatalf("a form left out of the list did not refuse: %v", err)
	}
	for _, f := range plantedForms {
		if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(f)) {
			t.Fatalf("the refusal names a serial form: %v", err)
		}
	}
	if _, serr := os.Stat(out); serr == nil {
		ents, _ := os.ReadDir(out)
		if len(ents) != 0 {
			t.Fatalf("a refused run wrote %d files", len(ents))
		}
	}
}

func TestShapeKeepsNoDateOrKey(t *testing.T) {
	raw, out := rawInputs(t, "none"), filepath.Join(t.TempDir(), "out")
	if err := run(raw, out, new(bytes.Buffer), Forms); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(out, "shape.json"))
	if regexp.MustCompile(`\d{7,}`).Match(b) || regexp.MustCompile(`20\d\d-\d\d-\d\d`).Match(b) {
		t.Fatalf("shape.json holds a long digit run or a date: %s", b)
	}
	for _, k := range []string{`"9a"`, `"9c"`, `"9e"`, `"f9"`, `"extension_oids"`, `"validity_days"`, `"touch_policy"`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("shape.json lacks %s", k)
		}
	}
}

var (
	digitRun    = regexp.MustCompile(`[0-9]{7,}`)
	labelSerial = regexp.MustCompile(`#[0-9]+`)
	serialValue = regexp.MustCompile(`(?i)serial[^A-Za-z\n]{0,6}[0-9a-f]{4,}`)
)

// TestL91FixturesHoldNoSerial: nothing under the committed fixtures holds a
// run of 7 or more decimal digits, a # followed by digits in a token label, or
// a Serial field that is not <serial>.
func TestL91FixturesHoldNoSerial(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "internal", "hwkeysetup", "testdata", "l91")
	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) == 0 {
		t.Fatalf("the L91 fixtures are not committed under %s", dir)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		if digitRun.MatchString(s) {
			t.Errorf("%s holds a run of 7 or more digits", e.Name())
		}
		if labelSerial.MatchString(s) {
			t.Errorf("%s holds # followed by digits", e.Name())
		}
		if serialValue.MatchString(strings.ReplaceAll(s, "<serial>", "")) {
			t.Errorf("%s holds a Serial field that is not <serial>", e.Name())
		}
	}
}
