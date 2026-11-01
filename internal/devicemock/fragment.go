package devicemock

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/blanketfish/port49/internal/yamlfault"
	"gopkg.in/yaml.v3"
)

// MergeFragment puts fragment's top-level keys into base, replacing a key
// base already has: the one way the lab conformance config and the mock's
// config take the shared reply-shaping settings (decision 52 ruling 5).
func MergeFragment(base, fragment []byte) ([]byte, error) {
	var b, f yaml.Node
	if err := oneDocument(base, &b); err != nil {
		return nil, fmt.Errorf("devicemock: the base %w", err)
	}
	if err := oneDocument(fragment, &f); err != nil {
		return nil, fmt.Errorf("devicemock: the fragment %w", err)
	}
	if len(b.Content) == 0 || b.Content[0].Kind != yaml.MappingNode || len(f.Content) == 0 || f.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("devicemock: base and fragment must both be YAML mappings")
	}
	bm, fm := b.Content[0], f.Content[0]
	for i := 0; i+1 < len(fm.Content); i += 2 {
		replaced := false
		for j := 0; j+1 < len(bm.Content); j += 2 {
			if bm.Content[j].Value == fm.Content[i].Value {
				bm.Content[j+1] = fm.Content[i+1]
				replaced = true
			}
		}
		if !replaced {
			bm.Content = append(bm.Content, fm.Content[i], fm.Content[i+1])
		}
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&b); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// oneDocument decodes raw into n and refuses a second YAML document, which a
// single decode would drop (decision 53 ruling 6).
func oneDocument(raw []byte, n *yaml.Node) error {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(n); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return yamlfault.OneDocument(dec)
}
