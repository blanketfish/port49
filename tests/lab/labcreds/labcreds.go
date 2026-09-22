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
