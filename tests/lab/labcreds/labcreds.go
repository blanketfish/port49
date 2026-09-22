// Package labcreds is the one place that knows what a lab credential looks
// like.
//
// The lab's shared secret, its breakglass account, and the tokens seeded in
// `tests/lab/port49d-lab.yaml` are all published: they are in the repository,
// in the device startup configs, and in this file. That is the point — anyone
// can decode a lab capture with them. It is also why the redactor has to know
// them exactly: `tests/lab/cmd/redact-pcap` proves that no credential survives
// into a committed evidence file by searching for these strings, and a verifier
// that searched for a stale copy of the password would pass while the real one
// sat in the file.
//
// So the harness constants in `tests/lab/harness_test.go` are defined from
// these, rather than beside them.
package labcreds

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/token"
)

const (
	// Key is the TACACS+ shared secret every lab device is configured with:
	// `tacacs-server host ... key`, `tplus-server ... secret`. Publishing it is
	// what makes a capture readable in Wireshark.
	Key = "labsecret"

	// BreakglassUser is the local account both startup configs define.
	BreakglassUser = "breakglass"

	// BreakglassPassword is that account's password, and the source of truth
	// for it. The EOS config carries it verbatim; the Junos config carries a
	// SHA-512 crypt hash of it under `encrypted-password`, because the
	// plain-text form does not produce a usable password on vSRX 21.4R3.15.
	// Regenerate that hash with `openssl passwd -6 -salt p49labsalt` over this
	// value if it changes.
	BreakglassPassword = "breakglass-only"

	// TokenPrefix is what every seeded lab token starts with. The redactor
	// treats it as a secret in its own right: a capture that still holds this
	// prefix after redaction is holding the start of a token, whether or not
	// the whole of one survived.
	TokenPrefix = "p49_"
)

// labConfig is the sliver of port49d-lab.yaml this package reads.
type labConfig struct {
	Lab struct {
		SeedTokens []struct {
			Secret string `yaml:"secret"`
		} `yaml:"seed_tokens"`
	} `yaml:"lab"`
}

// Secrets returns every credential string a lab run can put on the wire: the
// seeded token of every entry in port49d-lab.yaml, and the breakglass password.
//
// It is an error for the file to seed nothing. A verifier whose secret list
// came back empty would search a capture for nothing at all and report that it
// found nothing, which is the most convincing way to ship a token.
func Secrets(labYAMLPath string) ([]string, error) {
	raw, err := os.ReadFile(labYAMLPath)
	if err != nil {
		return nil, err
	}
	var c labConfig
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", labYAMLPath, err)
	}
	seen := map[string]bool{}
	var out []string
	for _, t := range c.Lab.SeedTokens {
		if t.Secret != "" && !seen[t.Secret] {
			seen[t.Secret] = true
			out = append(out, t.Secret)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s seeds no lab.seed_tokens[].secret; refusing to verify against an empty secret list", labYAMLPath)
	}
	for _, s := range []string{BreakglassPassword, TokenPrefix} {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out, nil
}

// TokenLen is how long a minted token is: the device tag plus the secret, in
// base62, with no separator and no prefix (design §8). It is taken from the
// minter's own constant so the shape rule below tracks the format rather than a
// copy of it.
const TokenLen = token.Len

func isBase62(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

// MinDistinct is how many different characters a TokenLen window must hold
// before it is called token-shaped. A minted token is 30 characters drawn
// uniformly from 62, which averages about 24 distinct and is never remotely
// near 12; what a lab capture legitimately carries in a long base62 run is
// repetitive by comparison — a redacted field is one character repeated, the
// deny prefix L2 types is 140 of them, and hostnames and ids reuse a small
// alphabet. 12 sits in the empty space between the two.
const MinDistinct = 12

// distinctBytes counts the different byte values in w.
func distinctBytes(w []byte) int {
	var seen [256]bool
	n := 0
	for _, c := range w {
		if !seen[c] {
			seen[c] = true
			n++
		}
	}
	return n
}

// TokenShaped returns the first token-shaped window in b, or "".
//
// It is the secret-list check stated as an invariant instead of as a lookup: a
// verifier that searches for the exact tokens of a run can only audit the
// machine and the moment that produced them, and the tokens live in /tmp. What
// a token LOOKS like does not expire, so this audits evidence committed by any
// run, including runs whose credentials are long gone.
//
// It slides a TokenLen window over every base62 run rather than asking for a
// run of exactly TokenLen, and that is a correctness requirement, not a
// refinement: a token is not delimited on the wire. NX-OS puts the PAP password
// straight after rem_addr in the AuthenStart body, so a real token arrives as
// the tail of `…100.1<token>` — a single run of 31 base62 bytes that an
// exact-length rule does not look at at all. `tests/lab/evidence/
// L8-cisco_nxos.pcap` packet 0 shows the redacted form of exactly that layout.
//
// What keeps it from crying wolf is the character count, not the run length: a
// window must hold at least MinDistinct different characters. That is what
// separates a random secret from the things that legitimately produce long
// base62 runs — 140 repeated 'A's, a redacted field of 30 'x's, or either of
// those with one stray character welded on.
func TokenShaped(b []byte) string {
	for i := 0; i < len(b); {
		if !isBase62(b[i]) {
			i++
			continue
		}
		j := i
		for j < len(b) && isBase62(b[j]) {
			j++
		}
		for k := i; k+TokenLen <= j; k++ {
			if w := b[k : k+TokenLen]; distinctBytes(w) >= MinDistinct {
				return string(w)
			}
		}
		i = j
	}
	return ""
}

// Redacted reports whether b is the redactor's output for a credential field:
// every byte overwritten with 'x'. An empty field is vacuously redacted, and is
// meant to be — a zero-length password field carries nothing.
func Redacted(b []byte) bool {
	for _, c := range b {
		if c != 'x' {
			return false
		}
	}
	return true
}

// Contains reports which of secrets appear in b, as a sorted-by-input list.
func Contains(b []byte, secrets []string) []string {
	var hits []string
	s := string(b)
	for _, sec := range secrets {
		if sec != "" && strings.Contains(s, sec) {
			hits = append(hits, sec)
		}
	}
	return hits
}
