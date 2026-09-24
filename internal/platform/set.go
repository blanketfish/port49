package platform

import (
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/rhwendt/port49/platforms"
)

// DefaultSet is the platform set this build renders with: the one a policy
// that pins none gets (spec §8, "the platform set is pinned").
const DefaultSet = "1.0.0"

// sets is every built-in platform set, by version, parsed and validated once.
// An embedded file that does not load is a build defect, never an operator's
// error, so it panics at start rather than degrading; TestEmbeddedSetsLoad is
// what keeps that from reaching a binary.
var sets = mustLoadSets(platforms.FS)

func mustLoadSets(fsys fs.FS) map[string]map[string]Dialect {
	out, err := LoadSets(fsys)
	if err != nil {
		panic("platform: the built-in adapters do not load: " + err.Error())
	}
	if _, ok := out[DefaultSet]; !ok {
		panic("platform: no built-in set " + DefaultSet)
	}
	return out
}

// LoadSets reads every set in fsys: a directory per version, a file per
// platform named for it, each defining that platform alone. Each file is laid
// over the generic adapter, so a key it leaves out is what an unmodeled device
// gets (spec §8, "Unknown platforms"), and every adapter is validated as a
// user's would be ("User-editable, day one").
func LoadSets(fsys fs.FS) (map[string]map[string]Dialect, error) {
	dirs, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]Dialect{}
	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}
		version := dir.Name()
		if _, ok := parseVersion(version); !ok {
			return nil, fmt.Errorf("platform set %q: a set is named by its version, e.g. 1.0.0", version)
		}
		files, err := fs.ReadDir(fsys, version)
		if err != nil {
			return nil, err
		}
		set := map[string]Dialect{}
		for _, f := range files {
			if f.IsDir() || path.Ext(f.Name()) != ".yaml" {
				continue
			}
			raw, err := fs.ReadFile(fsys, path.Join(version, f.Name()))
			if err != nil {
				return nil, err
			}
			specs, err := ParseSpecs(raw)
			if err != nil {
				return nil, fmt.Errorf("%s/%s: %w", version, f.Name(), err)
			}
			want := strings.TrimSuffix(f.Name(), ".yaml")
			if _, ok := specs[want]; !ok || len(specs) != 1 {
				return nil, fmt.Errorf("%s/%s: the file defines %s and nothing else", version, f.Name(), want)
			}
			d := specs[want].Over(generic)
			if err := Validate(want, d); err != nil {
				return nil, fmt.Errorf("%s/%s: %w", version, f.Name(), err)
			}
			set[want] = d
		}
		out[version] = set
	}
	return out, nil
}

// Sets lists the built-in set versions, oldest first.
func Sets() []string {
	out := make([]string, 0, len(sets))
	for v := range sets {
		out = append(out, v)
	}
	slices.SortFunc(out, compareVersions)
	return out
}

// Set returns a built-in set by version, copied, and whether it exists.
func Set(version string) (map[string]Dialect, bool) {
	set, ok := sets[version]
	if !ok {
		return nil, false
	}
	out := make(map[string]Dialect, len(set))
	for name, d := range set {
		out[name] = d.clone()
	}
	return out, true
}

// parseVersion reads a set version: dotted non-negative integers.
func parseVersion(v string) ([]int, bool) {
	var out []int
	for _, part := range strings.Split(v, ".") {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || strconv.Itoa(n) != part {
			return nil, false
		}
		out = append(out, n)
	}
	return out, len(out) > 0
}

func compareVersions(a, b string) int {
	x, _ := parseVersion(a)
	y, _ := parseVersion(b)
	return slices.Compare(x, y)
}

// sortedKeys is a map's keys in order, so a map with several faults reports
// the same one on every load.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
