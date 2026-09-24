package policy

import (
	"bytes"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Removal is what RemoveSubject took out of a policy file.
type Removal struct {
	Grants, Tests int
}

// RemoveSubject is `port49 grants remove --subject` (spec §12): the policy
// file with every grant row naming the subject deleted and then, because none
// remains, the subject block itself, so nothing is left behind to match. The
// file's tests naming the subject go too; left, they would name a subject
// that is no longer declared and the file would not load. So do tests naming
// one of its identities as `principal`, which would otherwise load and quietly
// turn into no_grants_matched denies. It edits the YAML
// tree rather than re-rendering the policy, so comments and the order of
// everything else survive; indentation is re-rendered at two spaces. The
// caller writes the result where a pull request will review it.
func RemoveSubject(raw []byte, subject string) ([]byte, Removal, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, Removal{}, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, Removal{}, errors.New("the policy file is not a YAML mapping")
	}
	top := doc.Content[0]
	ids := map[string]bool{}
	for i := 0; i+1 < len(top.Content); i += 2 {
		if top.Content[i].Value != "subjects" {
			continue
		}
		for _, item := range top.Content[i+1].Content {
			if item.Kind == yaml.MappingNode && field(item, "name") == subject {
				for _, id := range identities(item) {
					ids[id] = true
				}
			}
		}
	}
	var r Removal
	declared := false
	for i := 0; i+1 < len(top.Content); i += 2 {
		list := top.Content[i+1]
		if list.Kind != yaml.SequenceNode {
			continue
		}
		switch top.Content[i].Value {
		case "grants":
			r.Grants += filter(list, func(m *yaml.Node) bool { return field(m, "subject") == subject })
		case "tests":
			r.Tests += filter(list, func(m *yaml.Node) bool {
				return field(m, "subject") == subject || ids[field(m, "principal")]
			})
		case "subjects":
			declared = filter(list, func(m *yaml.Node) bool { return field(m, "name") == subject }) > 0
		}
	}
	if !declared {
		return nil, Removal{}, fmt.Errorf("subject %q is not declared", subject)
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, Removal{}, err
	}
	if err := enc.Close(); err != nil {
		return nil, Removal{}, err
	}
	return buf.Bytes(), r, nil
}

// filter drops every mapping in list that drop selects, and says how many.
func filter(list *yaml.Node, drop func(*yaml.Node) bool) int {
	kept := list.Content[:0]
	removed := 0
	for _, item := range list.Content {
		if item.Kind == yaml.MappingNode && drop(item) {
			removed++
			continue
		}
		kept = append(kept, item)
	}
	list.Content = kept
	return removed
}

// identities is a subject mapping's identity list, written as one string or
// as a sequence (spec §2, §11).
func identities(m *yaml.Node) []string {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value != "identity" {
			continue
		}
		v := m.Content[i+1]
		if v.Kind == yaml.ScalarNode {
			return []string{v.Value}
		}
		var out []string
		for _, c := range v.Content {
			out = append(out, c.Value)
		}
		return out
	}
	return nil
}

func field(m *yaml.Node, key string) string {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1].Value
		}
	}
	return ""
}
