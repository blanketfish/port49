package engine

import (
	"encoding/binary"
	"regexp"
	"regexp/syntax"
	"slices"
	"sync"
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

// reader is a regex or class term's patterns read as one program, compiled
// once per term (compileRule) and asked many times, with the answers it has
// given. A Program is shared across goroutines, so it locks.
type reader struct {
	res  []*regexp.Regexp
	once sync.Once
	prog *syntax.Prog
	ok   bool
	// spaces holds one rune of each class of whitespace the program tells
	// apart: the same instructions take it, and it is `\n` or it is not,
	// which is all an empty-width assertion asks of whitespace. Reading one
	// of a class reads them all.
	spaces []rune

	mu    sync.Mutex
	some  map[query]answer
	every map[string]bool
}

type query struct {
	w                string
	padded, prefixes bool
}

type answer struct{ meet, possible bool }

// newReader is a term's reader, or nil for a term with no patterns, which
// takes nothing.
func newReader(res []*regexp.Regexp) *reader {
	if len(res) == 0 {
		return nil
	}
	return &reader{res: res}
}

// nameReader reads nameShape, the name a split `*` takes before an index.
var nameReader = newReader([]*regexp.Regexp{nameShape})

func (rd *reader) compile() {
	rd.once.Do(func() {
		rd.prog, rd.ok = progOf(rd.res)
		if !rd.ok {
			return
		}
		seen := map[string]bool{}
		for _, r := range spaces {
			sig := []byte{0}
			if r == '\n' {
				sig[0] = 1
			}
			for i := range rd.prog.Inst {
				if inst := &rd.prog.Inst[i]; readsRune(inst) {
					sig = append(sig, boolByte(takesRune(inst, r)))
				}
			}
			if !seen[string(sig)] {
				seen[string(sig)] = true
				rd.spaces = append(rd.spaces, r)
			}
		}
	})
}

func boolByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

// progOf compiles a term's patterns, which compileTerm compiled, into one
// program taking what any of them takes. Each pattern is parsed on its own,
// as regexp parsed it, and the trees are joined: pasted into one string, a
// `\Q` with no `\E` would quote the text after it. ok is false where it
// cannot, which regexp's own compile of the same patterns rules out.
func progOf(res []*regexp.Regexp) (prog *syntax.Prog, ok bool) {
	alt := &syntax.Regexp{Op: syntax.OpAlternate}
	for _, re := range res {
		tree, err := syntax.Parse(re.String(), syntax.Perl)
		if err != nil {
			return nil, false
		}
		alt.Sub = append(alt.Sub, tree)
	}
	tree := alt
	if len(alt.Sub) == 1 {
		tree = alt.Sub[0]
	}
	prog, err := syntax.Compile(tree.Simplify())
	return prog, err == nil
}

func readsRune(inst *syntax.Inst) bool {
	switch inst.Op {
	case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
		return true
	}
	return false
}

func takesRune(inst *syntax.Inst, r rune) bool {
	switch inst.Op {
	case syntax.InstRuneAny:
		return true
	case syntax.InstRuneAnyNotNL:
		return r != '\n'
	}
	return inst.MatchRune(r)
}

// spelling is the set of arguments a word stands for, as a chain of nodes:
// node i has read i runes of the word, each any case-fold of the word's rune
// there. Where padded, node 0 also reads leading whitespace and a node the
// argument may end at moves on to trail, which reads only whitespace. Where
// prefixes, the argument may end after any rune of the word, which reads
// every abbreviation in one walk.
type spelling struct {
	folds            [][]rune
	padded, prefixes bool
}

func spellingOf(w string, padded, prefixes bool) spelling {
	s := spelling{padded: padded, prefixes: prefixes}
	for _, r := range w {
		orbit := []rune{r}
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			orbit = append(orbit, f)
		}
		s.folds = append(s.folds, orbit)
	}
	return s
}

func (s spelling) trail() int { return len(s.folds) + 1 }

func (s spelling) ends(node int) bool {
	k := len(s.folds)
	return node == k || (s.prefixes && node >= 1 && node < k)
}

// move reads r, or ends the argument where r is -1, in context ctx.
type move struct {
	r   rune
	to  int
	ctx syntax.EmptyOp
}

// walk is one reading of a spelling by a reader's program, with scratch it
// reuses so a step allocates nothing.
type walk struct {
	rd    *reader
	s     spelling
	mark  []uint32 // per instruction, the closure that last reached it
	pass  uint32
	stack []uint32
	reach []uint32 // the rune instructions the last closure reached
	out   []uint32
	key   []byte
}

func newWalk(rd *reader, s spelling) *walk {
	return &walk{rd: rd, s: s, mark: make([]uint32, len(rd.prog.Inst))}
}

// moves lists what may follow node, after prev, grouped by context so a
// closure is computed once per context.
func (w *walk) moves(dst []move, node int, prev rune) []move {
	add := func(r rune, to int) {
		dst = append(dst, move{r, to, syntax.EmptyOpContext(prev, r)})
	}
	k, trail := len(w.s.folds), w.s.trail()
	switch {
	case node == trail:
		for _, r := range w.rd.spaces {
			add(r, trail)
		}
		add(-1, trail)
	default:
		if w.s.padded && node == 0 {
			for _, r := range w.rd.spaces {
				add(r, 0)
			}
		}
		if node < k {
			for _, r := range w.s.folds[node] {
				add(r, node+1)
			}
		}
		if w.s.ends(node) {
			add(-1, node)
			if w.s.padded && node > 0 {
				for _, r := range w.rd.spaces {
					add(r, trail)
				}
			}
		}
	}
	slices.SortStableFunc(dst, func(a, b move) int { return int(a.ctx) - int(b.ctx) })
	return dst
}

// closure follows the threads at pcs, and one starting afresh since a
// pattern is not anchored unless it says so, past every instruction that
// reads no rune, in context ctx. It reports whether one reaches a match and
// leaves the rune instructions reached in w.reach.
func (w *walk) closure(pcs []uint32, ctx syntax.EmptyOp) (matched bool) {
	prog := w.rd.prog
	w.pass++
	w.reach = w.reach[:0]
	w.stack = append(append(w.stack[:0], pcs...), uint32(prog.Start))
	for len(w.stack) > 0 {
		pc := w.stack[len(w.stack)-1]
		w.stack = w.stack[:len(w.stack)-1]
		if w.mark[pc] == w.pass {
			continue
		}
		w.mark[pc] = w.pass
		inst := &prog.Inst[pc]
		switch inst.Op {
		case syntax.InstAlt, syntax.InstAltMatch:
			w.stack = append(w.stack, inst.Out, inst.Arg)
		case syntax.InstCapture, syntax.InstNop:
			w.stack = append(w.stack, inst.Out)
		case syntax.InstEmptyWidth:
			if syntax.EmptyOp(inst.Arg)&^ctx == 0 {
				w.stack = append(w.stack, inst.Out)
			}
		case syntax.InstMatch:
			matched = true
		case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
			w.reach = append(w.reach, pc)
		}
	}
	return matched
}

// step is where the threads w.reach holds stand after reading r, in w.out.
func (w *walk) step(r rune) []uint32 {
	w.out = w.out[:0]
	for _, pc := range w.reach {
		if inst := &w.rd.prog.Inst[pc]; takesRune(inst, r) {
			w.out = append(w.out, inst.Out)
		}
	}
	slices.Sort(w.out)
	w.out = slices.Compact(w.out)
	return w.out
}

// keyOf encodes a state, the node, the rune before it and where the threads
// stand, into w.key.
func (w *walk) keyOf(node int, prev rune, pcs []uint32) []byte {
	w.key = binary.AppendUvarint(w.key[:0], uint64(node))
	w.key = binary.AppendVarint(w.key, int64(prev))
	for _, pc := range pcs {
		w.key = binary.AppendUvarint(w.key, uint64(pc))
	}
	return w.key
}

// someTaken reports whether some argument w stands for is taken by the
// reader's patterns: padded, with whitespace around it, and where prefixes,
// or any non-empty prefix of it. It answers in the (meet, possible) reading
// overlap gives: a reading past maxStates is a possible meet, and patterns it
// cannot compile are a certain one, so neither turns a meet the report must
// fail on into one it only prints.
func someTaken(rd *reader, w string, padded, prefixes bool) (meet, possible bool) {
	if rd == nil {
		return false, false
	}
	rd.compile()
	if !rd.ok {
		return true, false
	}
	q := query{w, padded, prefixes}
	rd.mu.Lock()
	a, ok := rd.some[q]
	rd.mu.Unlock()
	if !ok {
		a.meet, a.possible = newWalk(rd, spellingOf(w, padded, prefixes)).some()
		rd.mu.Lock()
		if rd.some == nil {
			rd.some = map[query]answer{}
		}
		rd.some[q] = a
		rd.mu.Unlock()
	}
	return a.meet, a.possible
}

func (w *walk) some() (meet, possible bool) {
	type item struct {
		node int
		prev rune
		pcs  []uint32
	}
	seen := map[string]struct{}{}
	stack := []item{{0, -1, nil}}
	var mv []move
	for len(stack) > 0 {
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		mv = w.moves(mv[:0], it.node, it.prev)
		for i, m := range mv {
			if (i == 0 || m.ctx != mv[i-1].ctx) && w.closure(it.pcs, m.ctx) {
				return true, false
			}
			if m.r < 0 {
				continue
			}
			out := w.step(m.r)
			k := w.keyOf(m.to, m.r, out)
			if _, ok := seen[string(k)]; ok {
				continue
			}
			if len(seen) >= maxStates {
				return true, true
			}
			seen[string(k)] = struct{}{}
			stack = append(stack, item{m.to, m.r, slices.Clone(out)})
		}
	}
	return false, false
}

// everyTaken reports whether every case-fold of w is taken by the reader's
// patterns. A reading past maxStates is not a proof, and says false.
func everyTaken(rd *reader, w string) bool {
	if rd == nil {
		return false
	}
	rd.compile()
	if !rd.ok {
		return false
	}
	rd.mu.Lock()
	v, ok := rd.every[w]
	rd.mu.Unlock()
	if !ok {
		v = newWalk(rd, spellingOf(w, false, false)).every()
		rd.mu.Lock()
		if rd.every == nil {
			rd.every = map[string]bool{}
		}
		rd.every[w] = v
		rd.mu.Unlock()
	}
	return v
}

func (w *walk) every() bool {
	memo := map[string]bool{}
	var all func(node int, prev rune, pcs []uint32) bool
	all = func(node int, prev rune, pcs []uint32) bool {
		k := string(w.keyOf(node, prev, pcs))
		if v, ok := memo[k]; ok {
			return v
		}
		if len(memo) >= maxStates {
			return false
		}
		// Every next step is read before any is followed: following one
		// reuses the walk's scratch.
		type next struct {
			to  int
			r   rune
			pcs []uint32
		}
		var nexts []next
		mv := w.moves(nil, node, prev)
		matched := false
		for i, m := range mv {
			if i == 0 || m.ctx != mv[i-1].ctx {
				matched = w.closure(pcs, m.ctx)
			}
			switch {
			case matched:
			case m.r < 0:
				memo[k] = false
				return false
			default:
				nexts = append(nexts, next{to: m.to, r: m.r, pcs: slices.Clone(w.step(m.r))})
			}
		}
		v := true
		for _, n := range nexts {
			if !all(n.to, n.r, n.pcs) {
				v = false
				break
			}
		}
		memo[k] = v
		return v
	}
	return all(0, -1, nil)
}
