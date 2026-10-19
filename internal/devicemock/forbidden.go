package devicemock

import (
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"
)

var (
	forbiddenKey   = regexp.MustCompile(`(?i)(^|_)(sha256|password|secret|token|key)$`)
	forbiddenValue = []struct {
		re   *regexp.Regexp
		what string
	}{
		{regexp.MustCompile(`[0-9a-fA-F]{40,}`), "long hex"},
		{regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----`), "a PEM BEGIN block"},
		{regexp.MustCompile(`[A-Za-z0-9+/]{44,}={0,2}`), "long base64"},
		{regexp.MustCompile(`(?i)\b(credential|token)_sha256=`), "a credential hash"},
	}
	// Keys the schema itself defines that match forbiddenKey's shape but
	// hold no secret.
	allowedKey = map[string]bool{"psk_key_exchange_modes": true}
)

// credentialShaped walks the document and names the first key or scalar that
// looks like credential material. It never prints the value.
func credentialShaped(n *yaml.Node, path string) error {
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for i, c := range n.Content {
			if err := credentialShaped(c, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i].Value
			if forbiddenKey.MatchString(k) && !allowedKey[k] {
				return fmt.Errorf("%s.%s: a key named like credential material", path, k)
			}
			if err := credentialShaped(n.Content[i+1], path+"."+k); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		for _, f := range forbiddenValue {
			if f.re.MatchString(n.Value) {
				return fmt.Errorf("%s: a value shaped like credential material (%s)", path, f.what)
			}
		}
	}
	return nil
}
