package engine

import (
	"regexp"
	"regexp/syntax"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// A word does not stand for one argument. It takes every case-fold of itself
// (strings.EqualFold), and a deny takes it with whitespace on either side too
// (compiled.match). A pattern need not treat those alike: `(?-i)` takes `fxp0`
// and not `FXP0`, `\b` sees a boundary before `k` and none before the Kelvin
// sign that folds to it, and `^reboot\s$` takes `reboot ` and not `reboot`. So
// whether a pattern takes what a word stands for is read off the pattern's
// program, run over every argument the word stands for at once, and never
// off the one spelling the rule wrote.

// spaces are the runes strings.TrimSpace removes.
var spaces = func() []rune {
	var out []rune
	for r := rune(0); r <= 0x3000; r++ {
		if unicode.IsSpace(r) {
			out = append(out, r)
		}
	}
	return out
}()

// maxStates bounds the states one reading visits. Past it the reading gives
// the answer that fails closed: a pattern may take the word (someTaken) and
// is not shown to take all of it (everyTaken).
const maxStates = 1 << 14

// spelling is the set of arguments a word stands for, as a chain of nodes:
// node i has read i runes of the word, each any case-fold of the word's rune
// there, and where padded the first and last node also read whitespace.
type spelling struct {
	folds  [][]rune
	padded bool
}

func spellingOf(w string, padded bool) spelling {
	s := spelling{padded: padded}
	for _, r := range w {
		orbit := []rune{r}
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			orbit = append(orbit, f)
		}
		s.folds = append(s.folds, orbit)
	}
	return s
}

type move struct {
	r  rune // -1 is the argument's end
	to int
}

func (s spelling) moves(node int) []move {
	var out []move
	last := len(s.folds)
	if s.padded && (node == 0 || node == last) {
		for _, r := range spaces {
			out = append(out, move{r, node})
		}
	}
	if node < last {
		for _, r := range s.folds[node] {
			out = append(out, move{r, node + 1})
		}
	} else {
		out = append(out, move{-1, node})
	}
	return out
}

// progOf compiles a term's patterns, which compileTerm compiled, into one
// program taking what any of them takes. ok is false where it cannot.
func progOf(res []*regexp.Regexp) (prog *syntax.Prog, ok bool) {
	if len(res) == 0 {
		return nil, true
	}
	alts := make([]string, len(res))
	for i, re := range res {
		alts[i] = "(?:" + re.String() + ")"
	}
	re, err := syntax.Parse(strings.Join(alts, "|"), syntax.Perl)
	if err != nil {
		return nil, false
	}
	prog, err = syntax.Compile(re.Simplify())
	return prog, err == nil
}

// advance runs prog's threads one rune on. pcs are the instructions they wait
// at, not yet followed past empty-width assertions, which turn on the rune
// that comes next. It follows them, and one starting afresh since a pattern is
// not anchored unless it says so, between prev and next (-1 at either end):
// matched is whether one reaches a match there, and out is where the threads
// stand after reading next.
func advance(prog *syntax.Prog, pcs []uint32, prev, next rune) (out []uint32, matched bool) {
	ctx := syntax.EmptyOpContext(prev, next)
	seen := make([]bool, len(prog.Inst))
	stack := append(slices.Clone(pcs), uint32(prog.Start))
	for len(stack) > 0 {
		pc := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[pc] {
			continue
		}
		seen[pc] = true
		inst := &prog.Inst[pc]
		switch inst.Op {
		case syntax.InstAlt, syntax.InstAltMatch:
			stack = append(stack, inst.Out, inst.Arg)
		case syntax.InstCapture, syntax.InstNop:
			stack = append(stack, inst.Out)
		case syntax.InstEmptyWidth:
			if syntax.EmptyOp(inst.Arg)&^ctx == 0 {
				stack = append(stack, inst.Out)
			}
		case syntax.InstMatch:
			matched = true
		case syntax.InstRune, syntax.InstRune1:
			if next >= 0 && inst.MatchRune(next) {
				out = append(out, inst.Out)
			}
		case syntax.InstRuneAny:
			if next >= 0 {
				out = append(out, inst.Out)
			}
		case syntax.InstRuneAnyNotNL:
			if next >= 0 && next != '\n' {
				out = append(out, inst.Out)
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out), matched
}

type state struct {
	node int
	prev rune
	pcs  string
}

func stateOf(node int, prev rune, pcs []uint32) state {
	var b strings.Builder
	for _, pc := range pcs {
		b.WriteString(strconv.FormatUint(uint64(pc), 36) + ",")
	}
	return state{node, prev, b.String()}
}

// someTaken reports whether some argument w stands for, padded or not, is
// taken by one of res, in the (meet, possible) reading overlap gives: a
// reading past maxStates is a possible meet.
func someTaken(res []*regexp.Regexp, w string, padded bool) (meet, possible bool) {
	prog, ok := progOf(res)
	if !ok {
		return true, true
	}
	if prog == nil {
		return false, false
	}
	s := spellingOf(w, padded)
	type item struct {
		node int
		prev rune
		pcs  []uint32
	}
	seen := map[state]bool{}
	stack := []item{{0, -1, nil}}
	for len(stack) > 0 {
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, mv := range s.moves(it.node) {
			out, matched := advance(prog, it.pcs, it.prev, mv.r)
			if matched {
				return true, false
			}
			if mv.r < 0 {
				continue
			}
			k := stateOf(mv.to, mv.r, out)
			if seen[k] {
				continue
			}
			if len(seen) >= maxStates {
				return true, true
			}
			seen[k] = true
			stack = append(stack, item{mv.to, mv.r, out})
		}
	}
	return false, false
}

// everyTaken reports whether every case-fold of w is taken by one of res. A
// reading past maxStates is not a proof, and says false.
func everyTaken(res []*regexp.Regexp, w string) bool {
	prog, ok := progOf(res)
	if !ok || prog == nil {
		return false
	}
	s := spellingOf(w, false)
	memo := map[state]bool{}
	var all func(node int, prev rune, pcs []uint32) bool
	all = func(node int, prev rune, pcs []uint32) bool {
		k := stateOf(node, prev, pcs)
		if v, ok := memo[k]; ok {
			return v
		}
		if len(memo) >= maxStates {
			return false
		}
		v := true
		for _, mv := range s.moves(node) {
			out, matched := advance(prog, pcs, prev, mv.r)
			if matched {
				continue
			}
			if mv.r < 0 || !all(mv.to, mv.r, out) {
				v = false
				break
			}
		}
		memo[k] = v
		return v
	}
	return all(0, -1, nil)
}
