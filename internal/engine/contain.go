package engine

import "strings"

// Contains reports whether every command inner matches is matched by outer
// too, both read as a permit reads them: as received, never widened (spec §3,
// §4). It answers what it can decide from the terms and says false otherwise:
// a regex or class term holds another only where it is the same term, and a
// `*` is held only by `*` or `**`. So true is a proof and false may be a
// containment it could not see, the direction a session-only projection
// needs — a bit's reach it cannot prove held by a rule is never taken to be
// (spec §8, "The projection model").
func Contains(outer, inner string, classes map[string][]string) (bool, error) {
	o, err := compileRule(Permit, outer, "", classes, Normalize{PipeToken: "|"})
	if err != nil {
		return false, err
	}
	in, err := compileRule(Permit, inner, "", classes, Normalize{PipeToken: "|"})
	if err != nil {
		return false, err
	}
	return contains(o[0], in[0]), nil
}

func contains(outer, inner compiled) bool {
	of, orest := fixedLen(outer.terms)
	nf, nrest := fixedLen(inner.terms)
	switch {
	case nrest && !orest:
		// inner matches vectors of every length past nf; outer does not.
		return false
	case !orest && nf != of:
		return false
	case nf < of:
		// outer requires terms inner may leave out.
		return false
	}
	for i := 0; i < of; i++ {
		if !termHolds(outer.terms[i], inner.terms[i]) {
			return false
		}
	}
	return true
}

// termHolds reports whether every argument term n takes, outer term o takes
// too, read as received.
func termHolds(o, n cterm) bool {
	switch o.kind {
	case Any, Rest:
		return true
	case Word:
		return n.kind == Word && strings.EqualFold(o.word, n.word)
	}
	// o is a regex or a class.
	switch n.kind {
	case Word:
		return everyTaken(o.rd, n.word)
	case o.kind:
		return o.word == n.word
	}
	return false
}

// MayMeet reports whether some command may match both permit and deny, the
// deny read as the platform's dialect n widens it (compileRule): true where
// two patterns meet at one position and nobody can say cheaply whether they
// share a string.
func MayMeet(permit, deny string, classes map[string][]string, n Normalize) (bool, error) {
	pm, ds, err := compilePair(permit, deny, classes, n)
	if err != nil {
		return false, err
	}
	for _, d := range ds {
		if meets(pm, d, n.abbreviated()) {
			return true, nil
		}
	}
	return false, nil
}

// AlwaysDominates reports whether permit dominates deny on every command both
// match (spec §5.4): wherever they meet, the permit is at least as specific
// at every position and more at one, and nothing about it turns on two
// patterns meeting. Rules that never meet are dominated vacuously. A
// session-only projection emits a permit as a device allow only where this
// holds for every deny, since on the device a matching allow beats any
// matching deny (spec §8, L11).
func AlwaysDominates(permit, deny string, classes map[string][]string, n Normalize) (bool, error) {
	pm, ds, err := compilePair(permit, deny, classes, n)
	if err != nil {
		return false, err
	}
	abbrev := n.abbreviated()
	for _, d := range ds {
		if !meets(pm, d, abbrev) {
			continue
		}
		if ok, possible := overrides(pm, d, abbrev); !ok || possible {
			return false, nil
		}
	}
	return true, nil
}

func compilePair(permit, deny string, classes map[string][]string, n Normalize) (compiled, []compiled, error) {
	pm, err := compileRule(Permit, permit, "", classes, n)
	if err != nil {
		return compiled{}, nil, err
	}
	ds, err := compileRule(Deny, deny, "", classes, n)
	if err != nil {
		return compiled{}, nil, err
	}
	return pm[0], ds, nil
}
