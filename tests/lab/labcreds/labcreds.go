// Package labcreds is the one place that knows what a lab credential looks
// like.
//
// The lab's shared secret and its breakglass account are published: they are in
// the repository, in the device startup configs, and in this file. That is the
// point — anyone can decode a lab capture with them. It is also why the
// redactor has to know them exactly: `tests/lab/cmd/redact-pcap` proves that no
// credential survives into a committed evidence file by searching for these
// strings, and a verifier that searched for a stale copy of the password would
// pass while the real one sat in the file.
//
// The tokens are no longer among them. port49d mints every seeded pair at start
// and writes it to the file named by `lab.seed_token_file`, so nothing in this
// repository knows a token until a daemon has run — which is why Secrets reads
// that file rather than the config, and why a run's evidence can only be
// verified on the machine that produced it.
//
// So the harness constants in `tests/lab/harness_test.go` are defined from
// these, rather than beside them.
package labcreds

import (
	"bufio"
	"encoding/json"
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

	// TokenPrefix is what a lab token used to start with, back when the config
	// carried the secret and every one of them was written `p49_…`. A minted
	// token starts with the device tag instead (design §8), which differs per
	// device and per key, so this prefix no longer matches anything a daemon
	// puts on the wire and Secrets does NOT include it.
	//
	// It is kept because the redactor's own tests build synthetic captures with
	// it, where it is the prefix by construction. Adding it back to the live
	// secret list would be worse than dropping it: a prefix that cannot match
	// still reads as coverage.
	TokenPrefix = "p49_"

	// RotationKey is the second shared secret, published like Key: the one
	// L28 gives a device to carry it through a key rotation
	// (tests/lab/l28_test.go). PORT49_L28_NEW_KEY overrides it.
	RotationKey = "l28-rotated-lab-key"

	// RotationCapture begins the name of every capture taken after a device
	// was given RotationKey: its bodies are obfuscated under that key, not
	// Key, and redacted under it (CaptureKey).
	RotationCapture = "L28-rotation-"
)

// CaptureKey is the shared secret the capture named name (a base name,
// `L28-rotation-arista_eos.pcap`) was taken under, or "" for Key.
func CaptureKey(name string) string {
	if !strings.HasPrefix(name, RotationCapture) {
		return ""
	}
	if k := os.Getenv("PORT49_L28_NEW_KEY"); k != "" {
		return k
	}
	return RotationKey
}

// SeedToken is one line of the seed-token file port49d writes at start, named
// by `lab.seed_token_file`. Enable is empty unless the seed asked for an enable
// token beside the login one.
type SeedToken struct {
	NAS       string `json:"nas"`
	Username  string `json:"username"`
	Login     string `json:"login"`
	Enable    string `json:"enable"`
	ExpiresAt string `json:"expires_at"`
}

// SeedTokenFile returns the path port49d writes the minted pairs to, read out
// of the lab config's `lab.seed_token_file`. Callers resolve it this way rather
// than naming the path themselves, so the config stays the one place that says
// where the credentials of a run are.
func SeedTokenFile(labYAMLPath string) (string, error) {
	raw, err := os.ReadFile(labYAMLPath)
	if err != nil {
		return "", err
	}
	var c struct {
		Lab struct {
			SeedTokenFile string `yaml:"seed_token_file"`
		} `yaml:"lab"`
	}
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return "", fmt.Errorf("%s: %w", labYAMLPath, err)
	}
	if c.Lab.SeedTokenFile == "" {
		return "", fmt.Errorf("%s names no lab.seed_token_file, so nothing knows where the run's credentials went", labYAMLPath)
	}
	return c.Lab.SeedTokenFile, nil
}

// SeedTokens reads the seed-token file: one JSON object per line, written 0600
// by the daemon and truncated at every start.
func SeedTokens(seedTokenPath string) ([]SeedToken, error) {
	f, err := os.Open(seedTokenPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []SeedToken
	sc := bufio.NewScanner(f)
	// A minted pair is short, but the file is machine-written and a truncated
	// read would silently shorten the secret list, which is the one failure
	// this package exists to prevent.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var t SeedToken
		if err := json.Unmarshal([]byte(line), &t); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", seedTokenPath, n, err)
		}
		out = append(out, t)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", seedTokenPath, err)
	}
	return out, nil
}

// Secrets returns every credential string a lab run can put on the wire: each
// minted token in the seed-token file, login and enable alike, and the
// breakglass password.
//
// It reads the file the daemon wrote rather than the config, because the config
// no longer knows: a seed names who gets a token and port49d chooses the
// secret. That makes the file a required input — the captures and the token
// file come from the same run, and a run's evidence cannot be verified without
// the credentials that run used.
//
// It is an error for the file to hold no token. A verifier whose secret list
// came back empty would search a capture for nothing at all and report that it
// found nothing, which is the most convincing way to ship a token.
func Secrets(seedTokenPath string) ([]string, error) {
	tokens, err := SeedTokens(seedTokenPath)
	if err != nil {
		return nil, err
	}
	out, err := SecretsOf(tokens)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", seedTokenPath, err)
	}
	return out, nil
}

// SecretsOf is Secrets over pairs already read, and it exists for the run with
// a restart in it. The daemon truncates the seed-token file at every start, so
// the file at the end of a run names only the last daemon's tokens — while the
// captures hold every daemon's. A caller that watched each file as it was
// written passes the union here, and the exact-secret half of the verification
// covers the whole run rather than its last few minutes.
func SecretsOf(tokens []SeedToken) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, t := range tokens {
		for _, s := range []string{t.Login, t.Enable} {
			if s != "" && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("holds no minted token; refusing to verify against an empty secret list")
	}
	if !seen[BreakglassPassword] {
		out = append(out, BreakglassPassword)
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
