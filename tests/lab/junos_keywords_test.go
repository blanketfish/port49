//go:build lab

package lab

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestL26JunosKeywords captures the Junos CLI keyword tree the projection
// proves rules against (spec §13 decision 27; §15 L26). Junos matches a
// deny-commands or allow-commands regex against a command's keywords only
// (tests/lab/results/L12-juniper_*.md), and port49 has no Junos grammar, so a
// rule reaches the wire only where this tree proves each of its words a
// keyword.
//
// A word is a keyword only on positive evidence (the lead's ruling on the
// amendment's pre-flight A1). The CLI must offer it by completion at that
// exact place (`<path> ?`), which alone is not enough, since Junos offers an
// argument's values there too (interface names, routing instances). And its
// RPC must show it a keyword: `<path> <word> | display xml rpc` either shows
// an RPC in which the word is an element's name and no element's text
// (`show interfaces terse` is `<terse/>`), or an RPC with no text at all
// where `<path>` alone was still asking for a `<command>` (`show route`), or
// is itself still asking for a `<command>` (`show chassis`); the last two only
// where `<path>`'s completion offered no `<argument>` placeholder, since after
// an argument a mandatory keyword could also be "expecting <command>"
// (re-pre-flight R-M1). Anything else is
// an argument: an RPC holding the word as text (`<interface-name>fxp0`), text
// that differs from the word, no RPC, an error naming anything but
// `<command>`, and a prompt that did not come back. The two images' trees are
// merged by intersection (Task 14), so a keyword must be proven on both.
//
// The walk runs no command that acts or streams (pre-flight A2). Before it
// walks, it proves on harmless commands that `| display xml rpc` shows the
// RPC without running the command: `show system uptime` and `show version`
// return their RPCs and none of their output. It then descends only under
// `show`: every other top-level word is a command name, proven by the
// top-level listing, and nothing under it is typed, so a word under one is
// unproven and counts as an argument. A prompt that does not come back within
// junosPer is interrupted with ^C and the word is an argument; if the prompt
// does not come back after that either, the session's state is unknown, and
// the test fails as not observed.
//
// The walk is bounded: the prefixes of junosKeywordSeeds first, then every
// path under `show` of up to junosKeywordBreadth words, to at most
// junosKeywordDepth words, junosKeywordNodes nodes and junosKeywordCommands
// commands. A path it did not reach proves nothing, so a rule under it fails
// closed. It logs progress every 100 commands, for the watchdog.
//
// It writes tests/lab/results/L26-keywords-<image>.yaml, the tree in the
// format platform.ParseKeywords reads, and the note. Task 14 merges the two
// images' files into platforms/keywords/1.1.0/juniper_junos.yaml.

const (
	junosKeywordBreadth  = 2
	junosKeywordDepth    = 4
	junosKeywordNodes    = 4000
	junosKeywordCommands = 20000
)

// junosKeywordWalked is the one top-level command the walk descends under:
// it only shows, and its RPC is shown without running it.
const junosKeywordWalked = "show"

// junosKeywordSeeds are show commands a policy denies or allows below the
// breadth: spec §11's example, the carve-out, and the operational commands
// the lab and the owner's fleet name. Their prefixes are walked first, in
// full, so the bounds never cut them off (pre-flight A-M1).
var junosKeywordSeeds = []string{
	"show chassis cluster status", "show chassis hardware", "show chassis routing-engine",
	"show configuration system", "show interfaces terse", "show interfaces extensive",
	"show route summary", "show system users", "show system uptime", "show system processes",
	"show cli authorization", "show bgp summary", "show bgp neighbor", "show ospf neighbor",
	"show security policies", "show security flow session", "show version",
}

// junosPlaceholder is an argument in a completion listing: `<name>`, but not
// `<[Enter]>`, which says the command is complete there.
var junosPlaceholder = regexp.MustCompile(`^<[^\[].*>$`)

var (
	junosRPCTag  = regexp.MustCompile(`<([A-Za-z][A-Za-z0-9_.-]*)[\s/>]`)
	junosRPCText = regexp.MustCompile(`>([^<>]+)<`)
	// junosRPCCommand is the CLI still asking for a <command>; its `: <word>`
	// form names a word the CLI rejected (review M1), and is captured apart.
	junosRPCCommand = regexp.MustCompile(`expecting <command>(:\s*\S+)?`)
)

type keywordWalk struct {
	c        *cliConn
	logf     func(format string, args ...any)
	prompt   string
	nodes    map[string]*keywordNode
	rpcs     map[string]rpcAnswer
	commands int
	values   []string // "<path> <word> (why)": offered, and not proven a keyword
}

type keywordNode struct {
	words    []string
	argument bool
}

// rpcAnswer is what `<cmd> | display xml rpc` showed.
type rpcAnswer struct {
	rpc          bool     // an RPC came back
	tags, values []string // its element names and texts
	command      bool     // the device is still asking for a <command>
	stalled      bool     // no prompt within junosPer, interrupted
}

func (w *keywordWalk) tick() {
	w.commands++
	if w.commands%100 == 0 {
		w.logf("keyword walk: %d commands, %d nodes", w.commands, len(w.nodes))
	}
}

// completion lists what the CLI offers after path: the words, and whether an
// argument placeholder is among them.
func (w *keywordWalk) completion(path string) ([]string, bool, error) {
	w.tick()
	send := "?"
	if path != "" {
		send = path + " ?"
	}
	prefix := strings.TrimSuffix(send, "?")
	from := len(w.c.out.String())
	if _, err := fmt.Fprint(w.c.in, send); err != nil {
		return nil, false, err
	}
	const none = "No valid completions"
	out, err := w.c.expectFrom(from, junosPer, w.prompt+prefix, none)
	if i := strings.Index(out, none); err == nil && i >= 0 && !strings.Contains(out, w.prompt+prefix) {
		_, err = w.c.expectFrom(from+i+len(none), junosPer, w.prompt)
		fmt.Fprint(w.c.in, "\x15")
		return nil, false, err
	}
	fmt.Fprint(w.c.in, "\x15")
	if err != nil {
		return nil, false, err
	}
	var words []string
	argument, listing := false, false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "Possible completions:") {
			listing = true
			continue
		}
		if !listing {
			continue
		}
		// Junos marks a configuration container `> ` and a multi-value
		// statement `+ ` (`show configuration ?`); each is an offered word,
		// and proves nothing until its RPC does.
		if strings.HasPrefix(line, "> ") || strings.HasPrefix(line, "+ ") {
			line = " " + line[2:]
		}
		if !strings.HasPrefix(line, " ") {
			continue
		}
		f := strings.Fields(line)
		if len(f) == 0 || f[0] == "|" || f[0] == "<[Enter]>" {
			continue
		}
		if junosPlaceholder.MatchString(f[0]) {
			argument = true
			continue
		}
		words = append(words, strings.ToLower(f[0]))
	}
	slices.Sort(words)
	return slices.Compact(words), argument, nil
}

// rpc is `<cmd> | display xml rpc`, remembered. A prompt that does not come
// back is interrupted; one that still does not come back is an error.
func (w *keywordWalk) rpc(cmd string) (rpcAnswer, error) {
	if a, ok := w.rpcs[cmd]; ok {
		return a, nil
	}
	w.tick()
	out, err := w.c.sendExpect(cmd+" | display xml rpc", junosPer, w.prompt)
	var a rpcAnswer
	if err != nil {
		fmt.Fprint(w.c.in, "\x03")
		if _, err := w.c.expectFrom(len(w.c.out.String()), junosPer, w.prompt); err != nil {
			return rpcAnswer{}, fmt.Errorf("%q did not return a prompt, even after ^C: %w", cmd, err)
		}
		a.stalled = true
	} else if i := strings.Index(out, "<rpc>"); i >= 0 {
		a.rpc = true
		// The RPC alone: Junos follows it with a <cli> block whose tags are
		// no part of the command.
		body := out[i:]
		if j := strings.Index(body, "</rpc>"); j >= 0 {
			body = body[:j]
		}
		for _, m := range junosRPCTag.FindAllStringSubmatch(body, -1) {
			a.tags = append(a.tags, strings.ToLower(m[1]))
		}
		for _, m := range junosRPCText.FindAllStringSubmatch(body, -1) {
			if t := strings.TrimSpace(m[1]); t != "" {
				a.values = append(a.values, strings.ToLower(t))
			}
		}
	} else {
		a.command = askingForCommand(out)
	}
	w.rpcs[cmd] = a
	return a, nil
}

// keyword reports whether word, offered after path, is proven a keyword
// there, and if not, why. placeholder is whether path's completion offered an
// `<argument>` placeholder, in which case only an RPC naming the word proves it.
func (w *keywordWalk) keyword(path, word string, placeholder bool) (bool, string, error) {
	a, err := w.rpc(path + " " + word)
	if err != nil {
		return false, "", err
	}
	switch {
	case a.stalled:
		return false, "no prompt within the deadline", nil
	case a.rpc && slices.Contains(a.values, word):
		return false, "the RPC holds it as text", nil
	case a.rpc && slices.Contains(a.tags, word):
		return true, "", nil
	case placeholder:
		return false, "an argument may be typed here, and no RPC names the word", nil
	case a.rpc && len(a.values) == 0:
		parent, err := w.rpc(path)
		if err != nil {
			return false, "", err
		}
		if parent.command {
			return true, "", nil
		}
		return false, "an RPC names it nowhere, and the path was not asking for a command", nil
	case a.rpc:
		return false, "the RPC holds text other than the word", nil
	case a.command:
		return true, "", nil
	}
	return false, "no RPC, and no <command> asked for", nil
}

// junosUnproven are the paths under which no word is proven a keyword,
// whatever its RPC shows (the lead's ruling of 2026-09-25). Under `show
// configuration` the RPC names each hierarchy level as an element
// (`<system/>`), which proves the word exists, not that deny-commands matches
// it as a keyword; until a lab run measures a deny naming one against a
// control, a deny naming a hierarchy is an argument deny and fails closed.
var junosUnproven = [][]string{{"show", "configuration"}}

const junosUnprovenWhy = "under `show configuration`: a hierarchy level, not proven a keyword to deny-commands"

// unproven reports whether path is at or under a junosUnproven path.
func unproven(path []string) bool {
	for _, u := range junosUnproven {
		if len(path) >= len(u) && slices.Equal(path[:len(u)], u) {
			return true
		}
	}
	return false
}

// unprovenSeeds names each seed the walk did not prove in full, with the
// first word not proven and why: offered and not proven (its reason), not
// offered by completion there, or its path not reached.
func (w *keywordWalk) unprovenSeeds() []string {
	var out []string
	for _, s := range junosKeywordSeeds {
		f := strings.Fields(s)
		for i := 1; i < len(f); i++ {
			p := strings.Join(f[:i], " ")
			n := w.nodes[p]
			if n == nil {
				out = append(out, fmt.Sprintf("`%s`: `%s` not reached", s, p))
				break
			}
			if slices.Contains(n.words, f[i]) {
				continue
			}
			why := "not offered by completion there"
			for _, v := range w.values {
				if rest, ok := strings.CutPrefix(v, p+" "+f[i]+" ("); ok {
					why = "offered, not proven: " + strings.TrimSuffix(rest, ")")
					break
				}
			}
			out = append(out, fmt.Sprintf("`%s`: `%s` after `%s`, %s", s, f[i], p, why))
			break
		}
	}
	return out
}

// askingForCommand reports whether the CLI's answer is still asking for a
// <command> after the words typed: "syntax error, expecting <command>." A
// "syntax error, expecting <command>: <word>" names the word the CLI
// rejected, and so proves no keyword (review M1): a false proof is the unsafe
// direction, a deny sent as keyword-only that the device never enforces.
func askingForCommand(out string) bool {
	ms := junosRPCCommand.FindAllStringSubmatch(out, -1)
	for _, m := range ms {
		if m[1] != "" {
			return false
		}
	}
	return len(ms) > 0
}

// seeded reports whether path is a prefix of a seed, word for word.
func seeded(path []string) bool {
	for _, s := range junosKeywordSeeds {
		f := strings.Fields(s)
		if len(f) >= len(path) && slices.Equal(f[:len(path)], path) {
			return true
		}
	}
	return false
}

// visit captures one node, and returns its keywords.
func (w *keywordWalk) visit(path []string) ([]string, error) {
	p := strings.Join(path, " ")
	if n, ok := w.nodes[p]; ok {
		return n.words, nil
	}
	words, argument, err := w.completion(p)
	if err != nil {
		return nil, fmt.Errorf("completion after %q: %w", p, err)
	}
	n := &keywordNode{argument: argument}
	for _, word := range words {
		if len(path) == 0 {
			// The top-level listing holds command names only.
			n.words = append(n.words, word)
			continue
		}
		if unproven(path) {
			n.argument = true
			w.values = append(w.values, fmt.Sprintf("%s %s (%s)", p, word, junosUnprovenWhy))
			continue
		}
		ok, why, err := w.keyword(p, word, argument)
		if err != nil {
			return nil, err
		}
		if ok {
			n.words = append(n.words, word)
			continue
		}
		n.argument = true
		w.values = append(w.values, fmt.Sprintf("%s %s (%s)", p, word, why))
	}
	w.nodes[p] = n
	return n.words, nil
}

func (w *keywordWalk) bounded() bool {
	return len(w.nodes) >= junosKeywordNodes || w.commands >= junosKeywordCommands
}

// walk captures the root, then every seed's prefixes, then the breadth under
// junosKeywordWalked, within the bounds.
func (w *keywordWalk) walk() error {
	if _, err := w.visit(nil); err != nil {
		return err
	}
	for _, s := range junosKeywordSeeds {
		f := strings.Fields(s)
		for i := 1; i < len(f) && i < junosKeywordDepth && !w.bounded(); i++ {
			words, err := w.visit(f[:i])
			if err != nil {
				return err
			}
			if !slices.Contains(words, f[i]) {
				break // not proven here: nothing under it is walked
			}
		}
	}
	queue := [][]string{{junosKeywordWalked}}
	for len(queue) > 0 && !w.bounded() {
		path := queue[0]
		queue = queue[1:]
		words, err := w.visit(path)
		if err != nil {
			return err
		}
		for _, word := range words {
			next := append(slices.Clone(path), word)
			if len(next) < junosKeywordDepth && (len(next) <= junosKeywordBreadth || seeded(next)) {
				queue = append(queue, next)
			}
		}
	}
	return nil
}

// proveInert shows that `| display xml rpc` returns a command's RPC and does
// not run it, on two harmless commands, before anything else is typed.
func (w *keywordWalk) proveInert() error {
	for _, c := range []struct{ cmd, rpc, output string }{
		{"show system uptime", "get-system-uptime-information", "System booted"},
		{"show version", "get-software-information", "Junos:"},
	} {
		w.tick()
		out, err := w.c.sendExpect(c.cmd+" | display xml rpc", junosPer, w.prompt)
		if err != nil {
			return fmt.Errorf("%s | display xml rpc: not observed: %w", c.cmd, err)
		}
		if !strings.Contains(out, "<rpc>") || !strings.Contains(out, c.rpc) || strings.Contains(out, c.output) {
			return fmt.Errorf("%s | display xml rpc did not show the RPC alone, so the pipe may run the command "+
				"and the walk does not start: %s", c.cmd, oneLine(out))
		}
	}
	return nil
}

// yaml is the tree as platform.ParseKeywords reads it.
func (w *keywordWalk) yaml(platformName string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "platform: %s\nnodes:\n", platformName)
	paths := make([]string, 0, len(w.nodes))
	for p := range w.nodes {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	for _, p := range paths {
		n := w.nodes[p]
		quoted := make([]string, len(n.words))
		for i, word := range n.words {
			quoted[i] = fmt.Sprintf("%q", word)
		}
		fmt.Fprintf(&b, "  %q: {words: [%s], argument: %v}\n", p, strings.Join(quoted, ", "), n.argument)
	}
	return b.String()
}

func TestL26JunosKeywords(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
			t.Skip("Junos only")
		}
		stop := l.capture(t, "L26")
		defer stop()
		c, err := l.junosCLI(breakglassUser, breakglassPassword)
		if err != nil {
			t.Fatalf("no break-glass CLI: %v", err)
		}
		defer c.Close()
		if err := junosPrepare(c); err != nil {
			t.Fatalf("set cli screen-length 0 not observed within %s: %v", junosPer, err)
		}
		w := &keywordWalk{c: c, logf: t.Logf, prompt: "@" + junosHost + "> ", nodes: map[string]*keywordNode{},
			rpcs: map[string]rpcAnswer{}}
		if err := w.proveInert(); err != nil {
			t.Fatal(err)
		}
		if err := w.walk(); err != nil {
			t.Fatalf("not observed; the walk stopped: %v", err)
		}
		for _, v := range w.values {
			t.Logf("not proven: %s", v)
		}
		// Keywords every image has: a capture without them misread the device.
		for _, want := range [][2]string{{"", "show"}, {"show", "interfaces"}, {"show", "version"},
			{"show interfaces", "terse"}, {"show", "system"}, {"show system", "uptime"}} {
			if n := w.nodes[want[0]]; n == nil || !slices.Contains(n.words, want[1]) {
				t.Errorf("%q is not proven a keyword after %q", want[1], want[0])
			}
		}
		file := filepath.Join(root, "tests", "lab", "results", "L26-keywords-"+l.p.name+".yaml")
		if err := os.WriteFile(file, []byte(w.yaml("juniper_junos")), 0o644); err != nil {
			t.Fatal(err)
		}
		bounded := "no"
		if w.bounded() {
			bounded = "yes: every path it did not reach proves nothing"
		}
		var b strings.Builder
		fmt.Fprintf(&b, "`| display xml rpc` showed the RPCs of `show system uptime` and `show version` and none of "+
			"their output, so it runs nothing. The walk then typed only under `show`: %d nodes, %d commands. "+
			"Stopped at a bound: %s.\n\n", len(w.nodes), w.commands, bounded)
		fmt.Fprintf(&b, "Bounds: the prefixes of %d seed commands first, then every path under `show` of up to %d "+
			"words, to %d words; at most %d nodes and %d commands.\n\n", len(junosKeywordSeeds), junosKeywordBreadth,
			junosKeywordDepth, junosKeywordNodes, junosKeywordCommands)
		fmt.Fprintf(&b, "Words offered by completion and not proven keywords (%d), the first 60: `%s`\n\n",
			len(w.values), strings.Join(w.values[:min(60, len(w.values))], "`, `"))
		fmt.Fprintf(&b, "Seeds not proven in full (%d of %d), each at the first word not proven:\n\n",
			len(w.unprovenSeeds()), len(junosKeywordSeeds))
		for _, u := range w.unprovenSeeds() {
			fmt.Fprintf(&b, "- %s\n", u)
		}
		b.WriteString("\n")
		b.WriteString("Nothing under `show configuration` is proven, whatever its RPC shows: the RPC names each " +
			"hierarchy level as an element, which proves the word exists, not that deny-commands matches it as a " +
			"keyword (the lead's ruling of 2026-09-25), so a deny naming one fails closed until a lab run measures it.\n\n")
		b.WriteString("What this does not show: an argument completion never lists, a hidden one, is invisible " +
			"here, so an exact allow may run with one (the stake is a read command under `show`); and the tree " +
			"holds for these two images only: another release or hardware family (MX, EX, QFX, SRX hardware) " +
			"may take an argument where this tree proves a keyword.\n\n")
		fmt.Fprintf(&b, "The tree: `tests/lab/results/L26-keywords-%s.yaml`.\n", l.p.name)
		l.result(t, "L26", "The Junos operational CLI keyword tree under `show`, each keyword proven by completion "+
			"and by its RPC, within the stated bounds: the keywords decision 27 proves a projected rule's words "+
			"against (spec §8; §15 L26).", b.String())
	})
}
