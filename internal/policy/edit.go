package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

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
// turn into no_grants_matched denies. It reads the YAML tree only to find the
// removed items and cuts their lines from raw, so every other byte, comments,
// blank lines and alignment included, is the operator's and the pull request
// shows only the removal. A flow sequence or a second document cannot be cut
// that way and is refused. The caller writes the result where a pull request
// will review it.
func RemoveSubject(raw []byte, subject string) ([]byte, Removal, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var doc, next yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return nil, Removal{}, err
	}
	if err := dec.Decode(&next); err != io.EOF {
		return nil, Removal{}, errors.New("the policy file holds more than one YAML document")
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
	lines := bytes.SplitAfter(raw, []byte("\n"))
	cut := make([]bool, len(lines))
	var r Removal
	declared := false
	for i := 0; i+1 < len(top.Content); i += 2 {
		key, list := top.Content[i].Value, top.Content[i+1]
		var drop func(*yaml.Node) bool
		switch key {
		case "grants":
			drop = func(m *yaml.Node) bool { return field(m, "subject") == subject }
		case "tests":
			drop = func(m *yaml.Node) bool { return field(m, "subject") == subject || ids[field(m, "principal")] }
		case "subjects":
			drop = func(m *yaml.Node) bool { return field(m, "name") == subject }
		}
		if drop == nil || list.Kind != yaml.SequenceNode {
			continue
		}
		// The section ends before the next top-level key, or at the end of
		// the file.
		end := len(lines) + 1
		if i+2 < len(top.Content) {
			end = top.Content[i+2].Line
		}
		for j, item := range list.Content {
			if item.Kind != yaml.MappingNode || !drop(item) {
				continue
			}
			if list.Style&yaml.FlowStyle != 0 {
				return nil, Removal{}, fmt.Errorf("%s is a flow sequence: remove %s from it by hand", key, subject)
			}
			bound := end
			if j+1 < len(list.Content) {
				bound = itemStart(lines, list.Content[j+1])
			}
			cutItem(lines, cut, item, bound)
			switch key {
			case "grants":
				r.Grants++
			case "tests":
				r.Tests++
			case "subjects":
				declared = true
			}
		}
	}
	if !declared {
		return nil, Removal{}, fmt.Errorf("subject %q is not declared", subject)
	}
	var out bytes.Buffer
	for n, line := range lines {
		if !cut[n] {
			out.Write(line)
		}
	}
	// The cut is by line, so check it: what is left must parse, and hold
	// nothing that names the subject. A shape the cut does not model (a flow
	// mapping wrapped so its brace sits at the dash) is refused here rather
	// than left to the caller's load check.
	if stillNamed(out.Bytes(), subject, ids) {
		return nil, Removal{}, fmt.Errorf("the lines around %s could not be cut cleanly; remove it by hand", subject)
	}
	return out.Bytes(), r, nil
}

// stillNamed reports whether raw fails to parse as one mapping, or still has
// a subject, grant or test item RemoveSubject would have removed.
func stillNamed(raw []byte, subject string, ids map[string]bool) bool {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return true
	}
	if len(doc.Content) == 0 {
		return false
	}
	top := doc.Content[0]
	if top.Kind != yaml.MappingNode {
		return true
	}
	for i := 0; i+1 < len(top.Content); i += 2 {
		for _, m := range top.Content[i+1].Content {
			switch top.Content[i].Value {
			case "subjects":
				if field(m, "name") == subject {
					return true
				}
			case "grants":
				if field(m, "subject") == subject {
					return true
				}
			case "tests":
				if field(m, "subject") == subject || ids[field(m, "principal")] {
					return true
				}
			}
		}
	}
	return false
}

// itemStart is the 1-based line of a block sequence item's dash: the item's
// own line, or the line before when the dash stands alone.
func itemStart(lines [][]byte, item *yaml.Node) int {
	n := item.Line
	if n > 1 && !bytes.HasPrefix(bytes.TrimSpace(lines[n-1]), []byte("-")) &&
		string(bytes.TrimSpace(lines[n-2])) == "-" {
		n--
	}
	return n
}

// cutItem marks a block sequence item's lines, from its dash to its last line
// of content before bound (the next item's dash, or the next top-level key):
// continuation lines, a block scalar's blank lines and a trailing comment go
// with it, the comment lines and blank lines after it stay. The comment lines
// directly above the dash are the item's label (its head comment) and go too,
// or they would label the item that follows; one set off by a blank line
// stays. An item cut from between two blank lines takes the second, so no
// double gap is left.
func cutItem(lines [][]byte, cut []bool, item *yaml.Node, bound int) {
	first := itemStart(lines, item)
	dash := indent(lines[first-1])
	if item.HeadComment != "" {
		for k := strings.Count(item.HeadComment, "\n") + 1; k > 0 && first > 1 &&
			bytes.HasPrefix(bytes.TrimSpace(lines[first-2]), []byte("#")); k-- {
			first--
		}
	}
	last := lastLine(item)
	for n := last + 1; n < bound && n <= len(lines); n++ {
		text := bytes.TrimSpace(lines[n-1])
		if len(text) > 0 && text[0] != '#' && indent(lines[n-1]) > dash {
			last = n
		}
	}
	for n := first; n <= last; n++ {
		cut[n-1] = true
	}
	blank := func(n int) bool { return n >= 1 && n <= len(lines) && len(bytes.TrimSpace(lines[n-1])) == 0 }
	if blank(first-1) && !cut[first-2] && blank(last+1) && last+1 < len(lines) {
		cut[last] = true
	}
}

func indent(line []byte) int { return len(line) - len(bytes.TrimLeft(line, " ")) }

// lastLine is the last line any node under n starts on.
func lastLine(n *yaml.Node) int {
	last := n.Line
	for _, c := range n.Content {
		if l := lastLine(c); l > last {
			last = l
		}
	}
	return last
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
