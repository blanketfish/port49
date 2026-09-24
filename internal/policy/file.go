package policy

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// The policy file's schema (spec §11), snake_case throughout. Every key is
// declared: the decoder refuses one it does not know rather than ignoring it,
// because an ignored key is a policy that reads one way and runs another.
type file struct {
	PrivilegeLevels []fileLevel   `yaml:"privilege_levels"`
	Scopes          []fileScope   `yaml:"scopes"`
	Roles           []fileRole    `yaml:"roles"`
	Subjects        []fileSubject `yaml:"subjects"`
	Grants          []fileGrant   `yaml:"grants"`
	Tests           []fileTest    `yaml:"tests"`
	Acknowledge     []fileAck     `yaml:"acknowledge"`
}

// fileAck is one acknowledge: entry (spec §12): the author's written word for
// a removed or rewritten deny no test can flip.
type fileAck struct {
	Role   string `yaml:"role"`
	Rule   string `yaml:"rule"`
	Reason string `yaml:"reason"`
}

type fileLevel struct {
	Name   string `yaml:"name"`
	Parent string `yaml:"parent"`
}

type fileScope struct {
	Name          string                `yaml:"name"`
	Match         map[string]matchValue `yaml:"match"`
	OnMissing     string                `yaml:"on_missing"`
	SecurityLog   bool                  `yaml:"security_log"`
	AttachedRoles fileAttached          `yaml:"attached_roles"`
}

type fileAttached struct {
	Humans   []string `yaml:"humans"`
	Machines []string `yaml:"machines"`
}

type fileRole struct {
	Name       string              `yaml:"name"`
	Privilege  string              `yaml:"privilege"`
	Reason     string              `yaml:"reason"`
	Permit     []string            `yaml:"permit"`
	Deny       []string            `yaml:"deny"`
	Pipe       *filePipe           `yaml:"pipe"`
	Attributes map[string][]string `yaml:"attributes"`
}

type filePipe struct {
	Permit []string `yaml:"permit"`
}

type fileSubject struct {
	Name     string        `yaml:"name"`
	Group    string        `yaml:"group"`
	Identity stringList    `yaml:"identity"`
	Username string        `yaml:"username"`
	Enable   string        `yaml:"enable"`
	TokenTTL time.Duration `yaml:"token_ttl"`
	API      []string      `yaml:"api"`
}

type fileGrant struct {
	Subject      string              `yaml:"subject"`
	Scope        string              `yaml:"scope"`
	Roles        []string            `yaml:"roles"`
	MaxPrivilege string              `yaml:"max_privilege"`
	Expires      string              `yaml:"expires"`
	Attributes   map[string][]string `yaml:"attributes"`
}

type fileTest struct {
	Subject   string `yaml:"subject"`
	Principal string `yaml:"principal"`
	Device    string `yaml:"device"`
	Command   string `yaml:"command"`
	Expect    string `yaml:"expect"`
	Reason    string `yaml:"reason"`
	// Level and MaxPrivilege are a session test's assertions (spec §12,
	// "Policy tests"); MaxPrivilege `none` asserts no ceiling.
	Level        string `yaml:"level"`
	MaxPrivilege string `yaml:"max_privilege"`
	// PrivLvl is a number 0-15 or `none`; Enable is none, auto or token.
	PrivLvl string `yaml:"priv_lvl"`
	Enable  string `yaml:"enable"`
}

// stringList is a YAML scalar or a sequence of scalars: spec §11 writes one
// identity as a string and spec §2 writes several as a list.
type stringList []string

func (s *stringList) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*s = stringList{n.Value}
		return nil
	}
	var list []string
	if err := n.Decode(&list); err != nil {
		return err
	}
	*s = list
	return nil
}

// matchValue is one scope match term (spec §5.5): a scalar is equality, a
// sequence is any one of its values, and a mapping is a comparison — `lt`,
// `lte`, `gt`, `gte` against a version with the generic comparator, or `re`
// against an RE2 pattern. Several comparisons in one mapping must all hold.
type matchValue struct {
	Equal []string
	Cmp   map[string]string
}

func (m *matchValue) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		// A null would otherwise match the literal string "null".
		if n.ShortTag() == "!!null" {
			return fmt.Errorf("line %d: a match value is a string, a list or a comparison, not null", n.Line)
		}
		m.Equal = []string{n.Value}
	case yaml.SequenceNode:
		if err := n.Decode(&m.Equal); err != nil {
			return err
		}
		if len(m.Equal) == 0 {
			return fmt.Errorf("line %d: an empty list matches no device", n.Line)
		}
	case yaml.MappingNode:
		if err := n.Decode(&m.Cmp); err != nil {
			return err
		}
		if len(m.Cmp) == 0 {
			return fmt.Errorf("line %d: an empty comparison matches no device", n.Line)
		}
		for op := range m.Cmp {
			switch op {
			case "lt", "lte", "gt", "gte", "re":
			default:
				return fmt.Errorf("line %d: %q is not a comparison; use lt, lte, gt, gte or re", n.Line, op)
			}
		}
	default:
		return fmt.Errorf("line %d: a match value is a string, a list or a comparison", n.Line)
	}
	return nil
}
