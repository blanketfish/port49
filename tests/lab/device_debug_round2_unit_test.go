package lab

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/blanketfish/port49/tests/lab/labcreds"
)

// The fix round after the step 4b security review (review-step4b.md). Every
// fixture is invented; failure messages name a platform and a case, never a
// sentinel.

var ddStripSepTest = regexp.MustCompile(`[\s:.,;-]`)

// ddKeepOrLeak is Keep's text, or "" when it failed closed: either way no
// secret may be in what came back.
func ddKeepOrLeak(f deviceDebugFilter, text string) string {
	k, err := f.Keep(text)
	if err != nil {
		return ""
	}
	return string(k)
}

// C1: a hex dump the old 8-byte and 16-digit rules missed is dropped, in
// whatever layout, with or without the word payload.
func TestDeviceDebugDropsHexDumpLayouts(t *testing.T) {
	for _, p := range ddPlatforms {
		for name, body := range map[string]string{
			"tail_row_7_bytes":   "6b 2d 31 78 aa bb cc",
			"tail_row_4_bytes":   "6b 2d 31 78",
			"chain_4_in_text":    "x 6b 2d 31 78 y",
			"chain_4_colon_text": "x 6b:2d:31:78 y",
			"two_byte_groups":    "0x0010: 6661 6b65 746f 6b2d 3178",
			"four_byte_groups":   "c001 0201 dead beef 0000 0005 6b2d 3178",
			"colon_separated":    "70:34:39:2d:7a:7a:7a",
			"one_digit_groups":   "c 0 1 2 1 de ad",
			"only_hex_tokens":    "6b 2d",
			"only_hex_one_group": "dead beef",
			"contiguous_8":       "frag 70343 92d7a7a7a",
			"contiguous_12":      "frag 7034392d7a7a",
			"hex_run_8":          "id 6b2d3178",
		} {
			if got := ddKeep(t, ddTestFilter(p), ddFacility[p]+body); got != "" {
				t.Errorf("%s: the hex layout %s was kept", p, name)
			}
		}
	}
}

// C1: a known secret spelled in spaced, coloned or odd-grouped hex never
// survives, whether the line is dropped or the capture fails closed.
func TestDeviceDebugSpacedHexOfAKnownSecretNeverSurvives(t *testing.T) {
	h := hex.EncodeToString([]byte(ddSentinelKey))
	pairs := func(sep string) string {
		var parts []string
		for i := 0; i < len(h); i += 2 {
			parts = append(parts, h[i:i+2])
		}
		return strings.Join(parts, sep)
	}
	threes := func() string {
		var parts []string
		for i := 0; i < len(h); i += 3 {
			parts = append(parts, h[i:min(i+3, len(h))])
		}
		return strings.Join(parts, " ")
	}
	for _, p := range ddPlatforms {
		for name, body := range map[string]string{
			"spaced":   "data " + pairs(" "),
			"coloned":  "data " + pairs(":"),
			"dashed":   "data " + pairs("-"),
			"threes":   "data " + threes(),
			"dotted":   "data " + pairs("."),
			"upper_sp": "data " + strings.ToUpper(pairs(" ")),
		} {
			got := ddKeepOrLeak(ddTestFilter(p), ddFacility[p]+body)
			for _, ln := range strings.Split(got, "\n") {
				if strings.Contains(strings.ToLower(ddStripSepTest.ReplaceAllString(ln, "")), h) {
					t.Errorf("%s: the %s hex of a known secret survived", p, name)
				}
			}
		}
	}
}

// I1: redaction must not unmask the rest of a long run.
func TestDeviceDebugRedactionDoesNotUnmaskALongRun(t *testing.T) {
	for _, p := range ddPlatforms {
		in := ddFacility[p] + "cookie=ABCDEFGHIJKLMNOPQRST" + ddSentinelToken + "uvwxyzghijklmnopqrst"
		got := ddKeep(t, ddTestFilter(p), in)
		if strings.Contains(got, "uvwxyzghijklmnopqrst") || strings.Contains(got, "ghijklmnopqrst") || strings.Contains(got, "ABCDEFGHIJKLMNOPQRST") {
			t.Errorf("%s: part of a 24+ run survived the secret redaction", p)
		}
	}
}

// I2: the whole $9$ value goes, including the part after a hyphen.
func TestDeviceDebugRedactsAHyphenatedJunosNine(t *testing.T) {
	for _, p := range ddPlatforms {
		got := ddKeep(t, ddTestFilter(p), ddFacility[p]+`set secret "$9$abcDEF-ghiJKLmn" end`)
		if strings.Contains(got, "ghiJKLmn") || strings.Contains(got, "abcDEF") {
			t.Errorf("%s: part of a $9$ value survived: %q", p, got)
		}
	}
}

// I3: one shape for the reversible types: any whitespace, an optional quoted
// value, key-string, and the whole value gone.
func TestDeviceDebugRedactsTheWholeValueOfAKeyShape(t *testing.T) {
	for _, p := range ddPlatforms {
		for name, c := range map[string]struct{ in, want string }{
			"nxos_quoted":    {`tacacs-server key 7 "fewhg123" end`, `tacacs-server key 7 <redacted> end`},
			"nxos_quoted_sp": {`tacacs-server key 7 "few hg 123" end`, `tacacs-server key 7 <redacted> end`},
			"tab":            {"tacacs-server key\t7\t08224A end", "tacacs-server key 7 <redacted> end"},
			"double_space":   {"tacacs-server key  7  08224A end", "tacacs-server key 7 <redacted> end"},
			"key_string":     {"key-string 7 08224A end", "key-string 7 <redacted> end"},
			"key_0_whole":    {"tacacs-server key 0 plainvalue end", "tacacs-server key 0 <redacted> end"},
			"pass_8_whole":   {"password 8 plainvaluetwo end", "password 8 <redacted> end"},
			"secret_9_whole": {`secret 9 "quoted value" end`, "secret 9 <redacted> end"},
		} {
			got := ddKeep(t, ddTestFilter(p), ddFacility[p]+c.in)
			if got != ddFacility[p]+c.want {
				t.Errorf("%s: %s: got %q", p, name, got)
			}
		}
	}
}

// I4: the XR process-less close line is only the measured shape; another
// daemon's "connection closed ... port" line is not kept.
func TestDeviceDebugXRDropsOtherDaemonsConnectionClosed(t *testing.T) {
	f := ddTestFilter("iosxr")
	const pre = "RP/0/RP0/CPU0:Oct 23 09:39:03.099 UTC: "
	for name, ln := range map[string]string{
		"sshd":          pre + "sshd[1]: Connection closed by user admin 10.0.0.1 port 22",
		"netconf":       pre + "netconf[77]: connection closed by 10.0.0.1 port 830",
		"no_process_by": pre + "connection closed by 10.0.0.1 port 22",
		"port_only":     pre + "listening on port 22",
		"closed_only":   pre + "connection closed",
	} {
		if got := ddKeep(t, f, ln); got != "" {
			t.Errorf("%s: kept an unmeasured line", name)
		}
	}
	if got := ddKeep(t, f, pre+"connection closed 5 172.100.100.1 port 49"); got == "" {
		t.Errorf("the measured close line was dropped")
	}
}

// I5: the debug evidence gate lets what the filter writes through and refuses
// what it should have redacted; the other evidence still refuses the words.
func TestDeviceDebugEvidenceGate(t *testing.T) {
	ok := []byte(ddFacility["eos"] + "tacacs-server key 7 <redacted>\n" + ddFacility["eos"] + "password prompt shown\n")
	if bad := qualGate(map[string][]byte{"tls_token_login-debug.txt": ok}, ddTestSecrets()); len(bad) != 0 {
		t.Errorf("a filter output was refused: %v", bad)
	}
	for name, body := range map[string]string{
		"type7":   ddFacility["eos"] + "password 7 08224A\n",
		"nine":    ddFacility["eos"] + "x $9$abcDEF-ghiJKLmn\n",
		"quoted":  ddFacility["eos"] + `key 7 "fewhg123"` + "\n",
		"payload": ddFacility["eos"] + "payload follows\n",
		"hexdump": ddFacility["eos"] + "6b 2d 31 78\n",
		"long":    ddFacility["eos"] + strings.Repeat("Qq", 14) + "\n",
		"secret":  ddFacility["eos"] + "see " + ddSentinelKey + "\n",
		"sha":     ddFacility["eos"] + `"x_sha256": 1` + "\n",
		"pem":     ddFacility["eos"] + "BEGIN CERTIFICATE\n",
	} {
		if bad := qualGate(map[string][]byte{"c-debug.txt": []byte(body)}, ddTestSecrets()); len(bad) == 0 {
			t.Errorf("%s: an unredacted line passed the debug gate", name)
		}
	}
	if bad := qualGate(map[string][]byte{"c-summary.txt": []byte("password prompt shown\n")}, nil); len(bad) == 0 {
		t.Errorf("the other evidence lost its forbidden words")
	}
}

// M1: base64 of a secret at the other two alignments.
func TestDeviceDebugRedactsShiftedBase64(t *testing.T) {
	for _, p := range ddPlatforms {
		for _, pre := range []string{"", "a:", "u:", "x", "ab:", "abc:"} {
			for _, post := range []string{"", "!", "?", "zz", "@@@"} {
				for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
					e := enc.EncodeToString([]byte(pre + ddSentinelPass + post))
					got := ddKeepOrLeak(ddTestFilter(p), ddFacility[p]+"auth "+e+" end")
					// the middle of the encoding is the same whatever the neighbours are
					if strings.Contains(got, e[4:len(e)-4]) {
						t.Errorf("%s: base64 of %q+secret+%q kept its middle", p, pre, post)
					}
				}
			}
		}
	}
}

// M3: the longest form wins at one position, whatever the order.
func TestDeviceDebugLongestFormWins(t *testing.T) {
	f := deviceDebugFilter{Platform: "eos", Secrets: func() []string { return []string{"tok-1", "tok-12", ddSentinelPass} }}
	if got := ddKeep(t, f, ddFacility["eos"]+"x tok-12 y"); got != ddFacility["eos"]+"x <redacted> y" {
		t.Errorf("a prefix secret left a residue: %q", got)
	}
	pad := base64.StdEncoding.EncodeToString([]byte(ddSentinelPass))
	if got := ddKeep(t, f, ddFacility["eos"]+"x "+pad+" y"); got != ddFacility["eos"]+"x <redacted> y" {
		t.Errorf("a padded base64 left a residue: %q", got)
	}
}

// M4: each rule pinned by a fixture of its own.
func TestDeviceDebugPinsTheRemainingRules(t *testing.T) {
	f := ddTestFilter("eos")
	pre := ddFacility["eos"]
	// the key word needs a word boundary
	if got := ddKeep(t, f, pre+"turnkey 7 xyz"); got != pre+"turnkey 7 xyz" {
		t.Errorf("a word that ends in key was redacted: %q", got)
	}
	// an ANSI escape or CR inside a secret does not hide it
	for name, in := range map[string]string{
		"ansi": pre + "x p49-\x1b[0mzzz y",
		"cr":   pre + "x p49-\rzzz y",
	} {
		if got := ddKeep(t, f, in); strings.Contains(got, "zzz") || strings.Contains(got, "p49") {
			t.Errorf("%s: a secret split by a control sequence survived: %q", name, got)
		}
	}
	// an empty secret redacts nothing
	e := deviceDebugFilter{Platform: "eos", Secrets: func() []string { return []string{"", ddSentinelKey} }}
	line := pre + "type 15 on port 49 at 05:00:11.000001"
	if got := ddKeep(t, e, line); got != line {
		t.Errorf("an empty secret changed a clean line: %q", got)
	}
	// a secret minted after the filter was built is redacted: Secrets is read at each Keep
	var have []string
	late := deviceDebugFilter{Platform: "eos", Secrets: func() []string { return have }}
	in := pre + "token " + ddSentinelToken + " seen"
	if got := ddKeep(t, late, in); !strings.Contains(got, ddSentinelToken) {
		t.Fatalf("test setup: the token should pass while unknown")
	}
	have = []string{ddSentinelToken}
	if got := ddKeep(t, late, in); strings.Contains(got, ddSentinelToken) {
		t.Errorf("a token minted later was not redacted")
	}
	// 8 spaced bytes with no payload word are dropped
	if got := ddKeep(t, f, pre+"x 1 2 3 4 5 6 7 8 y"); got != "" {
		t.Errorf("eight spaced bytes were kept")
	}
}

// M7: the TACACS+ key is a secret of every debug cell, with or without a device env.
func TestDeviceDebugSecretsNameTheKeyExplicitly(t *testing.T) {
	found := false
	for _, s := range ddKnownSecrets() {
		found = found || s == labcreds.Key
	}
	if !found {
		t.Errorf("ddKnownSecrets lacks the TACACS+ key")
	}
}

// Ordinary short numbers and words are not hex dumps.
func TestDeviceDebugKeepsOrdinaryShortNumbers(t *testing.T) {
	for _, p := range ddPlatforms {
		for _, body := range []string{
			"session id: 12, aaa type: 1, port 49 fd 7",
			"x 6b 2d 31 y",
			"server 172.100.100.1 port 49 socket 32 retry 3 ok",
			"Oct 23 2026 05:00:11.123456789 count 12",
		} {
			if got := ddKeep(t, ddTestFilter(p), ddFacility[p]+body); got != ddFacility[p]+body {
				t.Errorf("%s: an ordinary line was dropped or changed: %q", p, body)
			}
		}
	}
}

// M8: the alternation is compiled once per Keep, not once per line.
func TestDeviceDebugCompilesTheRedactionOncePerKeep(t *testing.T) {
	orig := ddRedactSecrets
	t.Cleanup(func() { ddRedactSecrets = orig })
	n := 0
	ddRedactSecrets = func(forms []string) func(string) string { n++; return orig(forms) }
	var lines []string
	for i := 0; i < 50; i++ {
		lines = append(lines, ddFacility["eos"]+"line "+strings.Repeat("x", i))
	}
	ddKeep(t, ddTestFilter("eos"), strings.Join(lines, "\n"))
	if n != 1 {
		t.Errorf("the redaction was compiled %d times for one capture", n)
	}
}

// M2: every platform widens its terminal before the debug is read, so a long
// line is not wrapped across two lines (a wrapped secret keeps a fragment).
func TestDeviceDebugEnableWidensTheTerminal(t *testing.T) {
	for _, p := range []string{"eos", "iosxr", "iosxe", "junos"} {
		found := false
		for _, c := range deviceDebugCmds[p].Enable {
			found = found || strings.Contains(c, "width") || strings.Contains(c, "screen-width")
		}
		if !found {
			t.Errorf("%s: Enable does not set a wide terminal", p)
		}
	}
}

// R1: a byte list with a 0x or \x prefix, or separated by commas or dashes, is a
// hex dump like the spaced one.
func TestDeviceDebugDropsPrefixedAndOtherSeparatorByteLists(t *testing.T) {
	layouts := map[string]string{
		"x_prefix":      "data: 0xc0 0x01 0x02 0x03 0x04",
		"x_prefix_four": "data: 0xc0 0x01 0x02 0x03",
		"comma":         "data: c0,01,02,03",
		"comma_space":   "data: c0, 01, 02, 03",
		"backslash_x":   `data: \xc0\x01\x02\x03`,
		"dash":          "data: c0-01-02-03",
	}
	known := ddSentinelKey // p49-zzz
	spell := func(sep, pre string) string {
		var parts []string
		for _, b := range []byte(known) {
			parts = append(parts, fmt.Sprintf("%s%02x", pre, b))
		}
		return strings.Join(parts, sep)
	}
	for name, body := range map[string]string{
		"known_x_prefix": "data: " + spell(" ", "0x"),
		"known_comma":    "data: " + spell(",", ""),
		"known_comma_x":  "data: " + spell(", ", "0x"),
		"known_bs_x":     "data: " + spell("", `\x`),
		"known_dash":     "data: " + spell("-", ""),
	} {
		layouts[name] = body
	}
	for _, p := range ddPlatforms {
		for name, body := range layouts {
			if got := ddKeepOrLeak(ddTestFilter(p), ddFacility[p]+body); got != "" {
				t.Errorf("%s: the byte list %s was kept", p, name)
			}
		}
	}
}

// R2: a line with a PEM marker or a _sha256 word goes, so the gate never has to
// refuse a whole run for one.
func TestDeviceDebugDropsEvidenceMarkerLines(t *testing.T) {
	for _, p := range ddPlatforms {
		for _, body := range []string{"tls: -----BEGIN CERTIFICATE-----", "cipher tls_aes_128_gcm_sha256 negotiated", "x TLS_AES_128_GCM_SHA256 y"} {
			got := ddKeep(t, ddTestFilter(p), ddFacility[p]+body)
			if got != "" {
				t.Errorf("%s: a marker line was kept", p)
			}
			if bad := qualDebugGate("x-debug.txt", []byte(got)); len(bad) > 0 {
				t.Errorf("%s: the gate refuses what Keep passed", p)
			}
		}
	}
}

// R3: the drops are counted by rule, numbers only.
func TestDeviceDebugCountsDropsByRule(t *testing.T) {
	var d ddDropCounts
	f := ddTestFilter("eos")
	f.Drops = &d
	in := strings.Join([]string{
		"unrelated line",
		ddFacility["eos"] + "payload is here",
		ddFacility["eos"] + "x c0 01 02 03 y",
		ddFacility["eos"] + "c0 01",
		ddFacility["eos"] + "tls_aes_128_gcm_sha256",
		ddFacility["eos"] + "kept line",
	}, "\n")
	if got := ddKeep(t, f, in); got != ddFacility["eos"]+"kept line" {
		t.Fatalf("kept %q", got)
	}
	want := ddDropCounts{Facility: 1, Payload: 1, HexView: 1, HexMessage: 1, Marker: 1}
	if d != want {
		t.Errorf("drops %s, want %s", d, want)
	}
	// the stripped-hex-of-a-secret drop is counted too
	f.Secrets = func() []string { return []string{"zq7"} }
	d = ddDropCounts{}
	ddKeep(t, f, ddFacility["eos"]+"v zq7 is 7a 71 37 end")
	if d.StrippedSecret+d.HexView != 1 {
		t.Errorf("a secret's spaced hex was not counted: %s", d)
	}
}

// R1: a short known secret (three bytes, too few for the hex-dump rule) written
// with 0x or \x prefixes is still found, by the separator-stripped check.
func TestDeviceDebugShortSecretInPrefixedHexNeverSurvives(t *testing.T) {
	for _, p := range ddPlatforms {
		for name, body := range map[string]string{
			"x_prefix":    "v 0x7a 0x71 0x37 end",
			"backslash_x": `v \x7a\x71\x37 end`,
			"comma":       "v 7a,71,37 end",
		} {
			if got := ddKeepOrLeak(ddTestFilter(p), ddFacility[p]+body); got != "" {
				t.Errorf("%s: %s kept the short secret's hex", p, name)
			}
		}
	}
}

// N1: the drop counts survive l80Filter, which drops lines that say payload or secret.
func TestDeviceDebugDropCountsSurviveTheSummaryFilter(t *testing.T) {
	line := "lines dropped by rule: " + (ddDropCounts{Facility: 1, Payload: 2, StrippedSecret: 3}).String()
	if got := l80Filter(line); got != line {
		t.Errorf("the drop-count line did not survive l80Filter: %q", got)
	}
}

// N2: a tail of two or three byte tokens in comma, dash or \x form is dropped too.
func TestDeviceDebugDropsShortByteListTails(t *testing.T) {
	for _, p := range ddPlatforms {
		for name, body := range map[string]string{
			"comma": "6b,2d,31", "dash": "6b-2d-31", "backslash_x": `\x6b\x2d\x31`, "x_prefix": "0x6b 0x2d", "comma_two": "6b,2d",
		} {
			if got := ddKeepOrLeak(ddTestFilter(p), ddFacility[p]+body); got != "" {
				t.Errorf("%s: the tail %s was kept", p, name)
			}
		}
	}
}

// N3: a known secret's hex in any punctuation layout, or with prefixes and no
// separator at all, is found by the stripped view.
func TestDeviceDebugKnownSecretHexInAnyPunctuationNeverSurvives(t *testing.T) {
	spell := func(sep, pre string) string {
		var parts []string
		for _, b := range []byte(ddSentinelShort) {
			parts = append(parts, fmt.Sprintf("%s%02x", pre, b))
		}
		return strings.Join(parts, sep)
	}
	for name, body := range map[string]string{
		"slash":       spell("/", ""),
		"pipe":        spell("|", ""),
		"underscore":  spell("_", ""),
		"brackets":    "[" + spell("][", "") + "]",
		"semicolon":   spell(";", ""),
		"dot":         spell(".", ""),
		"x_no_sep":    spell("", "0x"),
		"upper_x":     spell("", "0X"),
		"bs_x_no_sep": spell("", `\x`),
	} {
		for _, p := range ddPlatforms {
			if got := ddKeepOrLeak(ddTestFilter(p), ddFacility[p]+"v "+body+" end"); got != "" {
				t.Errorf("%s: the %s layout of a known secret survived", p, name)
			}
		}
	}
}

// A marker keeps two pieces of hex apart in the stripped view: they are not a secret.
func TestDeviceDebugMarkerDoesNotJoinHexInTheStrippedView(t *testing.T) {
	hf := ddHexForms([]string{ddSentinelShort})
	if ddLeaks("x 7a <redacted> 7137 y", nil, hf) {
		t.Errorf("two pieces either side of a marker joined into a known hex form")
	}
	if !ddLeaks("x 7a 71 37 y", nil, hf) {
		t.Errorf("a spaced known hex form was not found")
	}
}
