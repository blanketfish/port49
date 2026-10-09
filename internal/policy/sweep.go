package policy

import (
	"slices"
	"sort"
	"time"
)

// sweepIndex is what a sweep walks, built once per policy: every inventory
// name, sorted, and for each declared scope the positions in names of the
// devices it selects, ascending. A position orders as its name does.
type sweepIndex struct {
	names  []string
	scopes map[string][]int32
}

// SweepPage is one page of a mint by scope (design §17; spec §13 decision 42
// ruling 1): the devices scope selects on which m holds a grant unexpired at
// now, in the byte order of their names, after the name after, at most limit
// of them. next is the page's last name when more remain, "" at the end.
//
// A scope this policy does not declare, a declared one selecting no device m
// holds a grant on, and a page past the end are all an empty page: one
// answer, so a sweep tells a caller nothing about devices it holds no grant
// on, or about which scopes exist (ruling 2). Nor does its cost: see
// sweepPage.
func (p *Policy) SweepPage(m Member, scope, after string, limit int, now time.Time) (devices []string, next string) {
	devices, next, _ = p.sweepPage(m, scope, after, limit, now)
	return devices, next
}

// sweepPage is SweepPage, and how many devices it visited. It walks only the
// devices m holds an unexpired grant on, after after: the union of those
// grants' scopes, merged in name order from the index. The swept scope only
// filters that walk, and an undeclared one is walked as a scope selecting
// nothing. So the walk, and the time it takes, is set by m's own grants,
// never by which scopes exist or by how many inventory names lie in a range
// the caller chose (ruling 2; pre-flight I-1).
func (p *Policy) sweepPage(m Member, scope, after string, limit int, now time.Time) (devices []string, next string, visited int) {
	x := p.sweepIndex()
	start := sort.SearchStrings(x.names, after)
	if start < len(x.names) && x.names[start] == after {
		start++
	}
	// Each of m's unexpired grants' scopes, once, from start on.
	var lists [][]int32
	held := map[string]bool{}
	for _, sub := range p.subjectsOf(m) {
		for _, g := range p.grants {
			if g.Subject != sub.Name || held[g.Scope] || (!g.Expires.IsZero() && !now.IsZero() && !now.Before(g.Expires)) {
				continue
			}
			held[g.Scope] = true
			sel := x.scopes[g.Scope]
			from := sort.Search(len(sel), func(i int) bool { return sel[i] >= int32(start) })
			lists = append(lists, sel[from:])
		}
	}
	swept := x.scopes[scope] // nil for an undeclared scope
	for limit > 0 {
		// The lowest position at the head of any list, taken off each.
		lo := int32(-1)
		for _, l := range lists {
			if len(l) > 0 && (lo < 0 || l[0] < lo) {
				lo = l[0]
			}
		}
		if lo < 0 {
			break
		}
		for i, l := range lists {
			if len(l) > 0 && l[0] == lo {
				lists[i] = l[1:]
			}
		}
		visited++
		if _, ok := slices.BinarySearch(swept, lo); !ok {
			continue
		}
		if len(devices) == limit {
			return devices, devices[limit-1], visited
		}
		devices = append(devices, x.names[lo])
	}
	return devices, "", visited
}

// sweepIndex is the index, built by Parse and memoized: a Policy is one
// bundle, never changed once loaded. Every declared scope is indexed at
// once, so a sweep costs the same whichever scope it names.
func (p *Policy) sweepIndex() *sweepIndex {
	p.sweepOnce.Do(func() {
		x := &sweepIndex{names: make([]string, 0, len(p.devIndex)), scopes: make(map[string][]int32, len(p.scopes))}
		for name := range p.devIndex {
			x.names = append(x.names, name)
		}
		sort.Strings(x.names)
		for sname, s := range p.scopes {
			var sel []int32
			for i, name := range x.names {
				if s.Selects(p.devIndex[name]) {
					sel = append(sel, int32(i))
				}
			}
			x.scopes[sname] = sel
		}
		p.sweep = x
	})
	return p.sweep
}
