package labcreds

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"slices"
	"strings"
)

// SecretData is what RedactNote writes in place of a credential: the marker
// Junos itself prints for a hidden value, so a redacted note reads like the
// device's own `display secrets`-less output.
const SecretData = "/* SECRET-DATA */"

// passwordSums are the SHA-256 sums of the lab's published default passwords
// a results note must never carry: the break-glass account's, and the root
// password the vSRX and vJunos images boot with. The images' default is kept
// as a sum, not a string, so this file does not put it back into the
// repository that a4c4738 leaked it into (plan 5b final review C-1, I-4).
var passwordSums = func() map[string]bool {
	sum := sha256.Sum256([]byte(BreakglassPassword))
	return map[string]bool{
		hex.EncodeToString(sum[:]): true,
		// The vrnetlab Junos images' root password.
		"7676aaafb027c825bd9abab78b234070e702752f625b752e55e55b48e607e358": true,
	}
}()

// noteWord is one run of text a password could be, cut at what separates a
// configuration value from its surroundings: whitespace, quotes, markup, a
// statement's `;`, and Markdown's backtick.
var noteWord = regexp.MustCompile("[^\\s\"'<>;`,()]+")

// credentialKeys are the Junos statements whose value is a credential:
// a password hash or a plain-text password (tests/lab/results/L26c-*, a4c4738).
const credentialKeys = `encrypted-password|plain-text-password-value`

var (
	// hashed is a crypt(3) hash ($1$, $5$, $6$) or a Junos $8$ / $9$ secret,
	// which is reversible. Junos help text's "a $8$ or $9$ password" has a
	// space after each, and is not one.
	hashed = regexp.MustCompile(`\$[15689]\$[./0-9A-Za-z]+(?:\$[./0-9A-Za-z]*)*`)
	// xmlValue is `<encrypted-password>VALUE</encrypted-password>`.
	xmlValue = regexp.MustCompile(`(<(?:` + credentialKeys + `)>)([^<]*)(</)`)
	// statement is `encrypted-password "VALUE";`, the curly form.
	statement = regexp.MustCompile(`(\b(?:` + credentialKeys + `)[ \t]+)("[^"\n]*"|[^\s;"]+)([ \t]*;)`)
	// setLine is `set system login user x authentication encrypted-password
	// "VALUE"`, the display-set form.
	setLine = regexp.MustCompile(`(?m)(^[ \t]*set[ \t].*\b(?:` + credentialKeys + `)[ \t]+)("[^"\n]*"|\S+)([ \t]*)$`)
	// quotedSecret is a Junos `secret "VALUE"` (a TACACS+ or RADIUS key).
	quotedSecret = regexp.MustCompile(`(\bsecret[ \t]+)("[^"\n]*")()`)
)

// valued are the forms that carry a statement's value, each as three groups:
// what leads it, the value, and what follows.
var valued = []*regexp.Regexp{xmlValue, statement, setLine, quotedSecret}

// withheld reports whether v, a credential statement's value, is already a
// marker rather than the value: Junos's own `/* SECRET-DATA */`, the
// `«redacted»` ba4f7c8 wrote over L26c's, or a placeholder in angle brackets
// (`<value withheld>`, `"<hash>"`).
func withheld(v string) bool {
	v = strings.Trim(strings.TrimSpace(v), `"`)
	return v == "" || strings.HasPrefix(v, "/*") || strings.HasPrefix(v, "<") || v == "«redacted»"
}

// NoteLeaks returns the line numbers, from 1, of text that carry a credential:
// a Junos `encrypted-password` or `plain-text-password-value` value, a quoted
// `secret`, a `$1$`/`$5$`/`$6$`/`$8$`/`$9$` hash, or a published lab default
// password. It never returns what it matched, so a failure that reports it
// does not print the credential again.
func NoteLeaks(text string) []int {
	var out []int
	for i, line := range strings.Split(text, "\n") {
		if lineLeaks(line) {
			out = append(out, i+1)
		}
	}
	return out
}

func lineLeaks(line string) bool {
	if hashed.MatchString(line) {
		return true
	}
	for _, re := range valued {
		for _, m := range re.FindAllStringSubmatch(line, -1) {
			if !withheld(m[2]) {
				return true
			}
		}
	}
	return slices.ContainsFunc(noteWord.FindAllString(line, -1), isDefaultPassword)
}

func isDefaultPassword(w string) bool {
	sum := sha256.Sum256([]byte(w))
	return passwordSums[hex.EncodeToString(sum[:])]
}

// RedactNote is text with every credential NoteLeaks finds replaced by
// SecretData. The lab's notes writers pass everything they write through it:
// a note that copies a device's configuration, as L26c's break-glass `show
// configuration` does, would otherwise commit the root password and every
// account's hash (a4c4738).
func RedactNote(text string) string {
	for _, re := range valued {
		text = re.ReplaceAllStringFunc(text, func(m string) string {
			g := re.FindStringSubmatch(m)
			if withheld(g[2]) {
				return m
			}
			return g[1] + SecretData + g[3]
		})
	}
	text = hashed.ReplaceAllString(text, SecretData)
	return noteWord.ReplaceAllStringFunc(text, func(w string) string {
		if isDefaultPassword(w) {
			return SecretData
		}
		return w
	})
}
