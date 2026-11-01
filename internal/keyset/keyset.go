// Package keyset is the device key sets of spec §10: versions, dates and
// secret references, never a secret (decision 53). Both port49d.yaml and the
// policy file carry them; neither reads a secret to check them.
package keyset

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/keyring"
	"github.com/blanketfish/port49/internal/secretref"
)

// Version is one version of a key: its number, where its secret is read from,
// and for an accept version the day it stops admitting.
type Version struct {
	Version   int    `yaml:"version"`
	SecretRef string `yaml:"secret_ref"`
	// RetireAfter is the last day, UTC, the version admits (spec §10):
	// accept versions only. RetireAt is it parsed, the first instant the
	// version is refused — midnight after that day. Zero is none.
	RetireAfter string    `yaml:"retire_after"`
	RetireAt    time.Time `yaml:"-"`
}

// Set is one key_ref's versions.
type Set struct {
	Current Version   `yaml:"current"`
	Accept  []Version `yaml:"accept"`
	Retired []Version `yaml:"retired"` // diagnosis only: identifies, never admits
}

// ErrBadRef is wrapped by the refusal of a secret_ref that secretref.Parse
// refuses. It may be the secret itself, so a caller that keeps the file in a
// shared repository adds its advice to rotate.
var ErrBadRef = errors.New("a secret_ref secretref refuses")

// badRef is what Parse said of a reference, worded as the refusal reads
// ("secret_ref is not a secret reference: ..."), and ErrBadRef to errors.Is.
type badRef struct{ err error }

func (b badRef) Error() string        { return "secret_ref " + b.err.Error() }
func (b badRef) Is(target error) bool { return target == ErrBadRef }
func (b badRef) Unwrap() error        { return b.err }

// Clone is a deep copy: the accept and retired lists are copied, so a caller
// that edits one does not edit the set it was cloned from.
func (s Set) Clone() Set {
	s.Accept, s.Retired = slices.Clone(s.Accept), slices.Clone(s.Retired)
	return s
}

// All is the set's versions: current, accept, then retired.
func (s Set) All() []Version {
	out := make([]Version, 0, 1+len(s.Accept)+len(s.Retired))
	out = append(out, s.Current)
	out = append(out, s.Accept...)
	return append(out, s.Retired...)
}

// Sorted names the sets' refs, sorted, so the start notices read the same
// every time.
func Sorted(sets map[string]Set) []string {
	out := make([]string, 0, len(sets))
	for ref := range sets {
		out = append(out, ref)
	}
	sort.Strings(out)
	return out
}

// Check validates sets without reading a secret: every version numbered from
// 1 and once, a secret_ref named and parseable, and retire_after a date on an
// accept version only. It returns the sets with RetireAt filled, a non-nil map
// for a non-nil input. raw is the file the sets came from, for the line of a
// key that is no name. Its errors carry no caller prefix.
func Check(sets map[string]Set, raw []byte) (map[string]Set, error) {
	if err := checkNames(sets, raw); err != nil {
		return nil, err
	}
	out := make(map[string]Set, len(sets))
	for _, ref := range Sorted(sets) {
		ks := sets[ref]
		seen := map[int]bool{}
		for _, v := range ks.All() {
			if v.Version < 1 {
				return nil, fmt.Errorf("key %s: every version number must be 1 or greater", ref)
			}
			if seen[v.Version] {
				return nil, fmt.Errorf("key %s: version %d appears twice", ref, v.Version)
			}
			seen[v.Version] = true
			if v.SecretRef == "" {
				return nil, fmt.Errorf("key %s version %d: secret_ref is required", ref, v.Version)
			}
			if _, err := secretref.Parse(v.SecretRef); err != nil {
				return nil, fmt.Errorf("key %s version %d: %w", ref, v.Version, badRef{err})
			}
		}
		if ks.Current.RetireAfter != "" {
			return nil, fmt.Errorf("key %s: current version %d has retire_after; current is what devices "+
				"are provisioned with, so retire it by making another version current (spec §10)", ref, ks.Current.Version)
		}
		for _, v := range ks.Retired {
			if v.RetireAfter != "" {
				return nil, fmt.Errorf("key %s: retired version %d has retire_after; a retired version is "+
					"refused already", ref, v.Version)
			}
		}
		accept := make([]Version, len(ks.Accept))
		for i, v := range ks.Accept {
			if v.RetireAfter != "" {
				day, err := time.Parse("2006-01-02", v.RetireAfter)
				if err != nil {
					return nil, fmt.Errorf("key %s version %d: retire_after is not a date (YYYY-MM-DD)",
						ref, v.Version)
				}
				v.RetireAt = day.AddDate(0, 0, 1) // admits through the named day, UTC
			}
			accept[i] = v
		}
		ks.Accept = accept
		out[ref] = ks.Clone()
	}
	return out, nil
}

// checkNames refuses a key under keys: that is not a key_ref name
// (admission.KeyRefShape), by its line in raw and never by the name: every
// report prints a key_ref, and one that is not a name is most likely a secret.
func checkNames(sets map[string]Set, raw []byte) error {
	bad := false
	for ref := range sets {
		if !admission.KeyRefShape.MatchString(ref) {
			bad = true
			break
		}
	}
	if !bad {
		return nil
	}
	line := 0
	var doc yaml.Node
	if yaml.Unmarshal(raw, &doc) == nil && len(doc.Content) == 1 {
		top := doc.Content[0]
		for i := 0; i+1 < len(top.Content); i += 2 {
			if top.Content[i].Value != "keys" {
				continue
			}
			for j, keys := 0, top.Content[i+1]; j+1 < len(keys.Content); j += 2 {
				if !admission.KeyRefShape.MatchString(keys.Content[j].Value) && (line == 0 || keys.Content[j].Line < line) {
					line = keys.Content[j].Line
				}
			}
		}
	}
	where := "a key under keys:"
	if line > 0 {
		where = fmt.Sprintf("a key under keys: on line %d", line)
	}
	return fmt.Errorf("%s is not a valid key_ref name (%s): it names the key, never holds it",
		where, admission.KeyRefShapeRule)
}

// Notices say, for each accept version, that it has no retire_after or that
// it has passed, in key then file order.
func Notices(sets map[string]Set, now time.Time) []string {
	var out []string
	for _, ref := range Sorted(sets) {
		for _, v := range sets[ref].Accept {
			switch {
			case v.RetireAt.IsZero():
				out = append(out, fmt.Sprintf("key %s version %d has no retire_after; an indefinitely "+
					"accepted version is what rotation exists to prevent (spec §10)", ref, v.Version))
			case !now.Before(v.RetireAt):
				out = append(out, fmt.Sprintf("key %s version %d: retire_after %s has passed, so it "+
					"identifies devices and admits none; move it to retired, or remove it", ref, v.Version, v.RetireAfter))
			}
		}
	}
	return out
}

// Keyring resolves every set to its secrets, ordered current, accept, retired.
// secret is called with each version's SecretRef exactly as the set holds it.
func Keyring(sets map[string]Set, secret func(secretRef string) []byte) map[string]keyring.Set {
	out := make(map[string]keyring.Set, len(sets))
	for ref, ks := range sets {
		set := keyring.Set{Ref: ref}
		set.Versions = append(set.Versions, keyring.Version{Number: ks.Current.Version, Secret: secretref.Of(secret(ks.Current.SecretRef))})
		for _, v := range ks.Accept {
			set.Versions = append(set.Versions, keyring.Version{Number: v.Version, Secret: secretref.Of(secret(v.SecretRef)), RetireAt: v.RetireAt})
		}
		for _, v := range ks.Retired {
			set.Versions = append(set.Versions, keyring.Version{Number: v.Version, Secret: secretref.Of(secret(v.SecretRef)), Retired: true})
		}
		out[ref] = set
	}
	return out
}
