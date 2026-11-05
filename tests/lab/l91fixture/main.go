// Command l91fixture derives the L91 fixtures from the raw facts Ryan captured
// from the SER8's YubiKey (spec §15 L91; plan 12c Task 18, Step 1a), with the
// token's serial masked. The raw files hold the serial: this program holds it
// in memory only, writes nothing that carries it, and checks every output for
// every form of it before it writes a byte. It prints file names and byte
// counts and never a value read from a raw file.
//
//	go run ./tests/lab/l91fixture -raw ~/.cache/port49-l91-raw -out internal/hwkeysetup/testdata/l91
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/blanketfish/port49/internal/hwkey/serialmask"
)

var (
	oidSerial   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}
	oidPolicy   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8}
	oidFirmware = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 3}
)

// slotFiles are the raw attestation certificates, by the name shape.json keys them by.
var slotFiles = []struct{ name, file string }{
	{"9a", "attest-9a.pem"}, {"9c", "attest-9c.pem"}, {"9e", "attest-9e.pem"}, {"f9", "attest-f9.pem"},
}

// listings are the two pkcs11-tool listings, raw name to masked name.
var listings = []struct{ raw, masked string }{
	{"tokens.txt", "tokens.masked.txt"}, {"objects.txt", "objects.masked.txt"},
}

// slotShape is what shape.json keeps of one certificate: no certificate, public
// key, signature or date, because each of those identifies the token too.
type slotShape struct {
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	ExtensionOIDs      []string `json:"extension_oids"`
	PINPolicy          string   `json:"pin_policy,omitempty"`
	TouchPolicy        string   `json:"touch_policy,omitempty"`
	FirmwareVersion    string   `json:"firmware_version,omitempty"`
	KeyAlgorithm       string   `json:"key_algorithm"`
	Curve              string   `json:"curve,omitempty"`
	RSABits            int      `json:"rsa_bits,omitempty"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	// ValidityDays is days, never seconds: a long run of digits is what the
	// fixture check refuses as a possible serial.
	ValidityDays int `json:"validity_days"`
}

// Forms is the serial in every shape the raw files write it: decimal, and hex
// in either case, bare and zero-padded to 8 digits.
func Forms(serial uint32) []string {
	dec := fmt.Sprintf("%d", serial)
	return []string{
		fmt.Sprintf("%010d", serial), fmt.Sprintf("%08d", serial), dec,
		fmt.Sprintf("%08x", serial), fmt.Sprintf("%08X", serial),
		fmt.Sprintf("%x", serial), fmt.Sprintf("%X", serial),
	}
}

func main() {
	raw := flag.String("raw", "", "the directory holding the raw token facts")
	out := flag.String("out", "", "the directory the masked fixtures go to")
	flag.Parse()
	if *raw == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "l91fixture: -raw and -out are required")
		os.Exit(2)
	}
	if err := run(*raw, *out, os.Stdout, Forms); err != nil {
		fmt.Fprintln(os.Stderr, "l91fixture:", err)
		os.Exit(1)
	}
}

// run derives the three fixtures. maskForms is the list of serial forms the
// masking pass replaces; the check that follows always uses Forms, so a form
// left out of maskForms is caught and refuses the write.
func run(rawDir, outDir string, stdout io.Writer, maskForms func(uint32) []string) error {
	certs := map[string]*x509.Certificate{}
	for _, s := range slotFiles {
		b, err := os.ReadFile(filepath.Join(rawDir, s.file))
		if err != nil {
			return fmt.Errorf("reading %s: %w", s.file, errors.Unwrap(err))
		}
		blk, _ := pem.Decode(b)
		if blk == nil || blk.Type != "CERTIFICATE" {
			return fmt.Errorf("%s holds no certificate", s.file)
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return fmt.Errorf("%s does not parse", s.file)
		}
		certs[s.name] = c
	}
	serial, err := serialOf(certs["9a"])
	if err != nil {
		return err
	}
	forms := maskForms(serial)

	files := map[string][]byte{}
	for _, l := range listings {
		b, err := os.ReadFile(filepath.Join(rawDir, l.raw))
		if err != nil {
			return fmt.Errorf("reading %s: %w", l.raw, errors.Unwrap(err))
		}
		files[l.masked] = []byte(scrub(mask(string(b), forms)))
	}
	shapes := map[string]slotShape{}
	for _, s := range slotFiles {
		sh, err := shapeOf(certs[s.name])
		if err != nil {
			return fmt.Errorf("%s: %w", s.file, err)
		}
		sh.Subject, sh.Issuer = mask(sh.Subject, forms), mask(sh.Issuer, forms)
		shapes[s.name] = sh
	}
	var js bytes.Buffer
	enc := json.NewEncoder(&js)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // "<serial>" stays readable
	if err := enc.Encode(map[string]any{"slots": shapes}); err != nil {
		return err
	}
	files["shape.json"] = js.Bytes()

	// The check: nothing is written until every output is clear of every form.
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if survives(string(files[n]), Forms(serial)) {
			return fmt.Errorf("a serial form survived masking in %s", n)
		}
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(outDir, n), files[n], 0o644); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%s %d bytes\n", n, len(files[n]))
	}
	return nil
}

// serialOf reads the YubiKey serial extension of a slot attestation.
func serialOf(c *x509.Certificate) (uint32, error) {
	for _, e := range c.Extensions {
		if !e.Id.Equal(oidSerial) {
			continue
		}
		var n *big.Int
		if rest, err := asn1.Unmarshal(e.Value, &n); err != nil || len(rest) != 0 || n == nil ||
			!n.IsUint64() || n.Uint64() > 1<<32-1 {
			return 0, errors.New("the serial extension is not one 32-bit integer")
		}
		return uint32(n.Uint64()), nil
	}
	return 0, errors.New("attest-9a.pem carries no YubiKey serial extension")
}

func shapeOf(c *x509.Certificate) (slotShape, error) {
	sh := slotShape{Subject: c.Subject.String(), Issuer: c.Issuer.String(),
		KeyAlgorithm: c.PublicKeyAlgorithm.String(), SignatureAlgorithm: c.SignatureAlgorithm.String(),
		ValidityDays: int(c.NotAfter.Sub(c.NotBefore).Hours() / 24)}
	for _, e := range c.Extensions {
		sh.ExtensionOIDs = append(sh.ExtensionOIDs, e.Id.String())
		switch {
		case e.Id.Equal(oidPolicy) && len(e.Value) == 2:
			sh.PINPolicy, sh.TouchPolicy = fmt.Sprintf("%#02x", e.Value[0]), fmt.Sprintf("%#02x", e.Value[1])
		case e.Id.Equal(oidFirmware) && len(e.Value) == 3:
			sh.FirmwareVersion = fmt.Sprintf("%d.%d.%d", e.Value[0], e.Value[1], e.Value[2])
		}
	}
	sort.Strings(sh.ExtensionOIDs)
	switch k := c.PublicKey.(type) {
	case *ecdsa.PublicKey:
		sh.Curve = k.Curve.Params().Name
	case *rsa.PublicKey:
		sh.RSABits = k.N.BitLen()
	}
	return sh, nil
}

// mask replaces every form, and then the label form through serialmask.
func mask(s string, forms []string) string {
	for _, f := range forms {
		s = replaceFold(s, f, "<serial>")
	}
	return serialmask.MaskSerial(s)
}

// The listing lines whose values identify a certificate or a key rather than a
// slot's shape: a certificate's serial number and a public key's point. The
// fixtures keep that the line exists, not its value.
var (
	certSerialLine = regexp.MustCompile(`(?m)^(\s*serial:\s+)\S+$`)
	ecPointLine    = regexp.MustCompile(`(?m)^(\s*EC_POINT:\s+)\S+$`)
)

// scrub blanks the values of certificate-serial and public-key-point lines.
func scrub(s string) string {
	s = certSerialLine.ReplaceAllString(s, "${1}<serial>")
	return ecPointLine.ReplaceAllString(s, "${1}<point>")
}

// replaceFold replaces f, ignoring case, where it is not part of a longer run
// of digits (decimal or hex), so a timestamp that holds the digits is not cut.
func replaceFold(s, f, with string) string {
	var b strings.Builder
	low, lf := strings.ToLower(s), strings.ToLower(f)
	for i := 0; i < len(s); {
		j := strings.Index(low[i:], lf)
		if j < 0 {
			b.WriteString(s[i:])
			break
		}
		j += i
		end := j + len(f)
		if (j > 0 && isHex(low[j-1])) || (end < len(low) && isHex(low[end])) {
			b.WriteString(s[i : j+1])
			i = j + 1
			continue
		}
		b.WriteString(s[i:j])
		b.WriteString(with)
		i = end
	}
	return b.String()
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' }

// survives reports whether any form is in s at all, with no boundary rule: the
// check is stricter than the mask, so it errs toward refusing.
func survives(s string, forms []string) bool {
	low := strings.ToLower(s)
	for _, f := range forms {
		if strings.Contains(low, strings.ToLower(f)) {
			return true
		}
	}
	return false
}
