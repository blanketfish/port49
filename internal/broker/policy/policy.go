// Package policy is the vertical slice's file-backed policy (design §19 step
// 3): literal-identity subjects, roles, and grants on the one scope
// `all_devices`. BORROWED AHEAD from plan 4, which replaces it with the policy
// engine. The file is a strict subset of spec §11's format, so a file that
// loads here means the same thing to plan 4; everything outside the subset —
// scopes, groups, `api:` rights, entity classes, regexes, custom privilege
// levels, grant expiry — is refused at load by name rather than ignored. An
// ignored `scopes:` block would be a policy that reads as scoped and is not.
//
// It is read once, when port49d starts. There is no reload, and a restart
// empties the in-process store (plan 3, Question 3).
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/blob"
	"github.com/rhwendt/port49/internal/token"
)

type fileRole struct {
	Name      string   `yaml:"name"`
	Privilege string   `yaml:"privilege"`
	Reason    string   `yaml:"reason"`
	Permit    []string `yaml:"permit"`
	Deny      []string `yaml:"deny"`
}

type fileSubject struct {
	Name     string   `yaml:"name"`
	Identity []string `yaml:"identity"`
	// Username is declared because the slice has no directory to derive a
	// human's from (spec §2). BORROWED AHEAD from plan 7, which derives it
	// through the certificate-to-directory mapping (design §7).
	Username string        `yaml:"username"`
	Enable   string        `yaml:"enable"`
	TokenTTL time.Duration `yaml:"token_ttl"`
}

type fileGrant struct {
	Subject      string   `yaml:"subject"`
	Scope        string   `yaml:"scope"`
	Roles        []string `yaml:"roles"`
	MaxPrivilege string   `yaml:"max_privilege"`
}

type file struct {
	Roles    []fileRole    `yaml:"roles"`
	Subjects []fileSubject `yaml:"subjects"`
	Grants   []fileGrant   `yaml:"grants"`
}

// Policy is a loaded, validated policy file.
type Policy struct {
	roles      map[string]fileRole
	subjects   map[string]fileSubject
	byIdentity map[string]string // identity → subject name
	grants     map[string][]fileGrant
}

// levels is the slice's privilege table: each abstract level (spec §6) to the
// priv-lvl number every platform is told. BORROWED AHEAD from plan 5, whose
// adapters map levels per platform. `operator` is absent on purpose: nothing
// in the lab has measured what it should be, and a level with no mapping is a
// load error (spec §6), not a guess.
var levels = map[string]uint8{"readonly": 1, "admin": 15}

// Design §8: device tokens live 30–900s.
const (
	minTokenTTL = 30 * time.Second
	maxTokenTTL = 900 * time.Second
)

// Load reads and validates the policy file at path.
func Load(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	var f file
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		// Each hint only where it is true: the unknown-key one on a type
		// error would send an operator looking for a key that is not there.
		switch msg := err.Error(); {
		case strings.Contains(msg, "not found in type"):
			return nil, fmt.Errorf("policy: %s: %w; the vertical slice reads roles, subjects and grants only, "+
				"and refuses every other key rather than ignoring it (plan 3)", path, err)
		case strings.Contains(msg, "time.Duration"):
			return nil, fmt.Errorf("policy: %s: %w; durations need a unit, e.g. 60s", path, err)
		default:
			return nil, fmt.Errorf("policy: %s: %w", path, err)
		}
	}
	// A second document would be ignored by a single Decode, and an ignored
	// `---` then `scopes:` is the unscoped-but-looks-scoped policy the package
	// comment refuses.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("policy: %s: the policy file must be one YAML document; remove the `---` "+
			"separator and everything after it, or merge it into the first document", path)
	}
	p, err := build(f)
	if err != nil {
		return nil, fmt.Errorf("policy: %s: %w", path, err)
	}
	// An empty policy fails closed, but a truncated file or the wrong one
	// would go unnoticed until the first refused mint.
	if len(p.subjects) == 0 {
		return nil, fmt.Errorf("policy: %s: declares no subjects, so nobody can mint; is this the right file?", path)
	}
	return p, nil
}

func build(f file) (*Policy, error) {
	p := &Policy{roles: map[string]fileRole{}, subjects: map[string]fileSubject{},
		byIdentity: map[string]string{}, grants: map[string][]fileGrant{}}
	for i, r := range f.Roles {
		if r.Name == "" {
			return nil, fmt.Errorf("roles[%d]: name is required", i)
		}
		if _, dup := p.roles[r.Name]; dup {
			return nil, fmt.Errorf("role %q is declared twice", r.Name)
		}
		if err := checkLevel(r.Privilege); err != nil {
			return nil, fmt.Errorf("role %q: privilege: %w", r.Name, err)
		}
		for _, rule := range append(append([]string(nil), r.Permit...), r.Deny...) {
			if err := blob.CheckRule(rule); err != nil {
				return nil, fmt.Errorf("role %q: %w", r.Name, err)
			}
		}
		p.roles[r.Name] = r
	}
	users := map[string]string{}
	for i, s := range f.Subjects {
		if s.Name == "" {
			return nil, fmt.Errorf("subjects[%d]: name is required", i)
		}
		if _, dup := p.subjects[s.Name]; dup {
			return nil, fmt.Errorf("subject %q is declared twice", s.Name)
		}
		if len(s.Identity) == 0 {
			return nil, fmt.Errorf("subject %q: identity is required: the vertical slice has no directory, so a "+
				"subject is a list of literal identities (spec §2)", s.Name)
		}
		for _, id := range s.Identity {
			if !strings.HasPrefix(id, "user:") || len(id) == len("user:") {
				return nil, fmt.Errorf("subject %q: identity %q: the vertical slice's one verifier is a human x509 "+
					"certificate, whose principal is `user:<email>` (spec §2); machine identities are plan 8's", s.Name, id)
			}
			if err := checkIdentity(id); err != nil {
				return nil, fmt.Errorf("subject %q: %w", s.Name, err)
			}
			if other, dup := p.byIdentity[id]; dup {
				if other == s.Name {
					return nil, fmt.Errorf("identity %q is listed twice in subject %q; list it once", id, s.Name)
				}
				return nil, fmt.Errorf("identity %q is listed by both subject %q and subject %q; a principal must "+
					"resolve to one subject", id, other, s.Name)
			}
			p.byIdentity[id] = s.Name
		}
		// The minter's own invariant (token.ErrUsernameNotCanonical), checked
		// at load so an operator learns about `Alice` from the file and not
		// from a refused mint.
		if !token.CanonicalUsername(s.Username) {
			return nil, fmt.Errorf("subject %q: username %q must be printable ASCII and already canonical — lower "+
				"case, no DOMAIN\\ prefix, no @suffix — because the daemon looks tokens up by the canonical form of "+
				"what the device sends (spec §2)", s.Name, s.Username)
		}
		if other, dup := users[s.Username]; dup {
			return nil, fmt.Errorf("subjects %q and %q both claim username %q; usernames must be unique across "+
				"subjects, or two principals share one (nas, username) context (spec §2)", other, s.Name, s.Username)
		}
		users[s.Username] = s.Name
		switch s.Enable {
		case "":
			s.Enable = "none"
		case "none", "token":
		case "auto":
			return nil, fmt.Errorf("subject %q: `enable: auto` is restricted (spec §5.6, \"Why enable: auto is "+
				"restricted\") and the vertical slice does not offer it; use token or none", s.Name)
		default:
			return nil, fmt.Errorf("subject %q: enable %q: it must be none or token", s.Name, s.Enable)
		}
		if s.TokenTTL < minTokenTTL || s.TokenTTL > maxTokenTTL {
			return nil, fmt.Errorf("subject %q: token_ttl must be between %s and %s (design §8); got %s",
				s.Name, minTokenTTL, maxTokenTTL, s.TokenTTL)
		}
		p.subjects[s.Name] = s
	}
	for i, g := range f.Grants {
		if _, ok := p.subjects[g.Subject]; !ok {
			return nil, fmt.Errorf("grants[%d]: subject %q is not declared", i, g.Subject)
		}
		if g.Scope != "all_devices" {
			return nil, fmt.Errorf("grants[%d]: scope %q: the vertical slice has one scope, all_devices; scopes "+
				"are the policy engine's (plan 4)", i, g.Scope)
		}
		if len(g.Roles) == 0 {
			return nil, fmt.Errorf("grants[%d]: a grant needs at least one role", i)
		}
		for _, r := range g.Roles {
			if _, ok := p.roles[r]; !ok {
				return nil, fmt.Errorf("grants[%d]: role %q is not declared", i, r)
			}
		}
		if err := checkLevel(g.MaxPrivilege); err != nil {
			return nil, fmt.Errorf("grants[%d]: max_privilege: %w", i, err)
		}
		p.grants[g.Subject] = append(p.grants[g.Subject], g)
	}
	// A subject whose roles land it above its own ceiling is told the roles'
	// level by the device while port49 clamps the context to the ceiling, so
	// every command it types is denied privilege_exceeded. Resolve composes
	// both as a max over all the subject's grants, so the check does too
	// (plan 3, pre-flight F17). An absent max_privilege is no ceiling only
	// when no grant of the subject sets one.
	for name, gs := range p.grants {
		var level, ceiling uint8
		for _, g := range gs {
			ceiling = max(ceiling, levels[g.MaxPrivilege])
			for _, r := range g.Roles {
				level = max(level, levels[p.roles[r].Privilege])
			}
		}
		if ceiling > 0 && level > ceiling {
			return nil, fmt.Errorf("subject %q: its roles land it at priv-lvl %d, above its grants' max_privilege "+
				"(%d): the device would be told %d while port49 holds the session at %d, and every command would "+
				"be denied privilege_exceeded; raise max_privilege or lower the role", name, level, ceiling, level, ceiling)
		}
	}
	return p, nil
}

// checkIdentity refuses a `user:` identity no principal can equal. The
// daemon's principal is `user:` plus the certificate's email lower-cased, and
// the lookup is exact, so `user:Alice@Example.com` would load and never match.
// It is refused rather than lower-cased so the file reads exactly as it matches.
func checkIdentity(id string) error {
	email := strings.TrimPrefix(id, "user:")
	unprintable := func(r rune) bool { return r < 0x21 || r > 0x7e }
	if strings.IndexFunc(email, unprintable) >= 0 || !strings.Contains(email, "@") {
		return fmt.Errorf("identity %q: an email must be printable ASCII with no spaces, and contain an @", id)
	}
	if lower := strings.ToLower(email); lower != email {
		return fmt.Errorf("identity %q must be lower-case, because certificate identities are compared "+
			"lower-case: write \"user:%s\"", id, lower)
	}
	return nil
}

// checkLevel accepts an empty level (the role or grant sets none) or one the
// slice's table maps.
func checkLevel(name string) error {
	if name == "" {
		return nil
	}
	if _, ok := levels[name]; ok {
		return nil
	}
	if name == "operator" {
		return errors.New("`operator` has no priv-lvl mapping in the vertical slice, and a level with no mapping " +
			"is a load error (spec §6); platform adapters map it (plan 5)")
	}
	return fmt.Errorf("%q is not a privilege level; the vertical slice knows readonly and admin", name)
}
