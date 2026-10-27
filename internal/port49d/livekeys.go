package port49d

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/rhwendt/port49/internal/keyring"
	"github.com/rhwendt/port49/internal/keyset"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/secretref"
)

// liveKeys is the device keys in force (spec §10; decision 53 rulings 2, 3):
// the policy's key sets with each version's secret, built before every swap
// and put in force with it, so a reload that adds or retires a version
// reaches the next packet. Each reference is read once per process and held
// by its text: a version's secret never changes, so a build reads only the
// versions it has not seen. Nil holds no key: port49-broker's, which never
// answers a device.
//
// A resolved secret is held only as a secretref.Secret, which prints as
// <redacted> and, behind two pointers, even where fmt cannot call a method.
type liveKeys struct {
	res   *secretref.Resolver
	allow secretref.Allowance // key_secret_refs: where a reference may point
	mu    sync.Mutex
	held  map[string]secretref.Secret // reference text → secret
	// seen is every version's reference this process has had in force, by
	// key_ref and version: a version dropped and added back with another
	// reference is a re-key too. References only, never a secret.
	seen map[string]map[int]string
	in   atomic.Pointer[keyBuild]
}

// keyBuild is one policy's keys, ready to put in force: the keyring by
// key_ref, and each version's reference, by key_ref and version number.
type keyBuild struct {
	sets map[string]keyring.Set
	refs map[string]map[int]string
}

// keyUnreadError is a build refused because a secret could not be read: a
// file not rendered yet, an unset variable, a mode to fix. The reloader
// tries it again (decision 53 ruling 2); any other refusal is the policy's.
type keyUnreadError struct{ err error }

func (e *keyUnreadError) Error() string { return e.err.Error() }
func (e *keyUnreadError) Unwrap() error { return e.err }

func newLiveKeys(res *secretref.Resolver, allow secretref.Allowance) *liveKeys {
	if res == nil {
		// A Config built by hand, as tests build one, has no resolver:
		// env: and file: still read.
		res = secretref.New()
	}
	k := &liveKeys{res: res, allow: allow.WithDefaults(), held: map[string]secretref.Secret{}, seen: map[string]map[int]string{}}
	k.in.Store(&keyBuild{sets: map[string]keyring.Set{}, refs: map[string]map[int]string{}})
	return k
}

// build reads every reference pol names that is not held, and refuses a
// version whose reference differs from the one this process has had for it.
// It changes nothing in force; put does.
func (k *liveKeys) build(pol *policy.Policy) (keyBuild, error) {
	if k == nil {
		return keyBuild{}, nil
	}
	sets := pol.KeySets()
	k.mu.Lock()
	defer k.mu.Unlock()
	b := keyBuild{refs: map[string]map[int]string{}}
	fresh := map[string]secretref.Secret{}
	for _, ref := range keyset.Sorted(sets) {
		b.refs[ref] = map[int]string{}
		for _, v := range sets[ref].All() {
			at := fmt.Sprintf("keys.%s version %d secret_ref", ref, v.Version)
			r, err := secretref.Parse(v.SecretRef) // keyset.Check parsed it already
			if err != nil {
				return keyBuild{}, fmt.Errorf("%s %w", at, err)
			}
			text := v.SecretRef // a reference's one spelling (Task 4)
			if !k.allow.Allows(r) {
				// Before anything is read: a policy writer must not choose which of
				// the host's secrets becomes a device key (decision 53 ruling 12).
				// An env: name is not printed: a secret pasted where one goes parses as one.
				return keyBuild{}, fmt.Errorf("%s %s is outside key_secret_refs (%s): a policy names only the "+
					"secrets port49d.yaml allows it (decision 53 ruling 12)", at, r.ForRefusal(), k.allow)
			}
			if was, ok := k.seen[ref][v.Version]; ok && was != text {
				return keyBuild{}, fmt.Errorf("keys.%s version %d names secret_ref %s, but port49d has held %s for %s "+
					"version %d since it started; a version's reference never changes (spec §10), so add a new version "+
					"instead", ref, v.Version, text, was, ref, v.Version)
			}
			b.refs[ref][v.Version] = text
			if _, ok := k.held[text]; ok {
				continue
			}
			if _, ok := fresh[text]; ok {
				continue
			}
			s, err := k.res.Resolve(r, k.allow.FileDir)
			if err != nil {
				return keyBuild{}, &keyUnreadError{fmt.Errorf("%s %w", at, err)}
			}
			fresh[text] = s
		}
	}
	for text, s := range fresh {
		k.held[text] = s
	}
	b.sets = keyset.Keyring(sets, func(text string) []byte { return k.held[text].Bytes() })
	return b, nil
}

// put puts b in force and lets go of every secret no version in it names.
func (k *liveKeys) put(b keyBuild) {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	named := map[string]bool{}
	for ref, vs := range b.refs {
		if k.seen[ref] == nil {
			k.seen[ref] = map[int]string{}
		}
		for n, text := range vs {
			named[text] = true
			k.seen[ref][n] = text
		}
	}
	for text := range k.held {
		if !named[text] {
			delete(k.held, text)
		}
	}
	k.in.Store(&b)
}

// union is b with every key set in force that b does not define, the sets b
// defines taking its versions: the build a swap puts in force first, so the
// policy still in force finds the keys it names until the new one replaces it.
func (k *liveKeys) union(b keyBuild) keyBuild {
	if k == nil {
		return b
	}
	in := k.in.Load()
	u := keyBuild{sets: maps.Clone(b.sets), refs: maps.Clone(b.refs)}
	for ref, s := range in.sets {
		if _, ok := u.sets[ref]; !ok {
			u.sets[ref], u.refs[ref] = s, in.refs[ref]
		}
	}
	return u
}

// Set is the key set in force for ref; the zero Set for one none defines.
func (k *liveKeys) Set(ref string) keyring.Set { return k.in.Load().sets[ref] }

// All is every key set in force.
func (k *liveKeys) All() map[string]keyring.Set { return k.in.Load().sets }

// keyChanges is the line a swap says when it changes the key sets: each
// version added, retired (moved to retired) and removed, and what that does
// to open connections; "" when nothing changed.
func keyChanges(old, new map[string]keyset.Set) string {
	refs := map[string]bool{}
	for ref := range old {
		refs[ref] = true
	}
	for ref := range new {
		refs[ref] = true
	}
	const reset = " (connections on it reset at their next packet, with no strike)"
	var parts []string
	for _, ref := range slices.Sorted(maps.Keys(refs)) {
		was, now := versionStates(old[ref]), versionStates(new[ref])
		nums := map[int]bool{}
		for n := range was {
			nums[n] = true
		}
		for n := range now {
			nums[n] = true
		}
		ordered := make([]int, 0, len(nums))
		for n := range nums {
			ordered = append(ordered, n)
		}
		sort.Ints(ordered)
		for _, n := range ordered {
			w, wok := was[n]
			s, sok := now[n]
			switch {
			case !wok:
				parts = append(parts, fmt.Sprintf("%s: version %d added", ref, n))
			case !sok:
				parts = append(parts, fmt.Sprintf("%s: version %d removed%s", ref, n, reset))
			case s == "retired" && w != "retired":
				parts = append(parts, fmt.Sprintf("%s: version %d retired%s", ref, n, reset))
			}
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "keys: " + strings.Join(parts, "; ")
}

// versionStates is each version number in s with the list it is in.
func versionStates(s keyset.Set) map[int]string {
	out := map[int]string{}
	if s.Current.Version != 0 {
		out[s.Current.Version] = "current"
	}
	for _, v := range s.Accept {
		out[v.Version] = "accept"
	}
	for _, v := range s.Retired {
		out[v.Version] = "retired"
	}
	return out
}
