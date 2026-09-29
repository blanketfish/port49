//go:build lab

package lab

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	keywords "github.com/rhwendt/port49/internal/platform"
)

// TestL26bJunosKeywordDeny proves Junos keywords by what decision 27 is
// about: deny-commands enforcement (spec §15 L26; the controller's L26b
// brief). A word W after path P is proven a keyword on an image where a
// class whose deny-commands is the rendered deny naming `P W **` (a leading
// ` *`, words joined by ` +`, the tail `( .*)? *(\|.*)?`) refuses a runnable
// command `P W …` with the CLI's refusal, while a paired control, the same
// class with no deny, runs the same command with positive evidence that it
// ran. Junos matches deny-commands against keywords only
// (L12-juniper_*.md), so a refusal there is the matcher reading W as a
// keyword.
//
// The words: the five L26 left unproven after `show` (cli, host,
// ingress-replication, policy, task), `exit` and `save` at the root, `cli`
// after `set`, and every hierarchy after `show configuration` either image
// offers. A command head absent on an image (not in its listing, and the
// control's CLI calls it an unknown command, typed in full as a hidden command
// would be) is recorded absent there; a deny naming it is vacuous on that
// image, and it is never an allow. Anything else is unproven, which fails
// closed in projection. Unproven is a result, not a test failure (review L26b
// I-5): the test fails on a harness failure (a login that did not open, a read
// past junosPer) and on a regression, a word below that was proven and is not,
// or a `show configuration` hierarchy that no longer runs under a deny naming
// it.
//
// Evidence of a run is positive, and counts only where the window holds no
// refusal: a `Count: N lines` line from `| count` (a deny refuses the line as
// it is parsed, before any pipe; the redrawn line after a syntax error can
// count too, which the no-refusal rule excludes), `set cli screen-length 0`
// says "Screen length set to 0", and `exit` ends the SSH session
// (cliConn.done). No evidence is matched in a command's echo. Every read has
// junosPer.
//
// Before any token, the break-glass CLI lists the completions at the root,
// `set`, `show` and `show configuration`; the note records each listing's
// words and whether it offers an `<argument>` placeholder, apart from whether
// its words are proven. The test writes an overlay per image,
// tests/lab/results/L26b-keywords-<image>.yaml, in platform.ParseKeywords
// form: each node's words are those this run proves (with the parents L26
// proves, so every node's parent lists it), and its `argument` is what the
// node is once the overlay is laid over the image's L26 tree: true where
// completion offers a placeholder there or any word it offers is proven by
// neither. The note and the overlay's comment record that tree's sha256, and
// an overlay is only good against the tree that hashes to it.

// junosL26bClass is a class with every bit and no regex: the control, and
// under a deny each deny session.
var junosL26bClass = []string{
	"set system login class p49-l26b-all permissions all",
	"set system login user p49-l26b-all class p49-l26b-all",
}

var junosL26bDelete = []string{"delete system login user p49-l26b-all", "delete system login class p49-l26b-all"}

// l26bWord is one word to prove: at path, the runnable read-only command
// typed, and what its output holds where it ran.
type l26bWord struct {
	path, word, cmd string
	evidence        *regexp.Regexp
}

// junosL26bCount is `| count`'s answer, on a line of its own: the echo
// carries `| count`, never this.
var junosL26bCount = regexp.MustCompile(`(?m)^Count: \d+ lines`)

// junosL26bShowWords are L26's five unproven words after `show`, each with a
// command that runs on both images (the survey, tests/lab/logs, not
// committed): `show host` and `show ingress-replication` take an argument.
var junosL26bShowWords = []l26bWord{
	{path: "show", word: "cli", cmd: "show cli | count"},
	{path: "show", word: "host", cmd: "show host localhost | count"},
	{path: "show", word: "ingress-replication", cmd: "show ingress-replication mvpn | count"},
	{path: "show", word: "policy", cmd: "show policy | count"},
	{path: "show", word: "task", cmd: "show task memory | count"},
}

// junosL26bRootWords are the baseline's root and `set` words. `save` offers
// only `dhcp-security-snoop` on vJunos and nothing on vSRX; its file is in
// /var/tmp on a lab device the run destroys. Its evidence is `| count`'s, as
// the show words' is (review L26b I-1: what a save prints was never
// measured, and a guessed word matched the echo). `exit` is typed last.
var junosL26bRootWords = []l26bWord{
	{path: "set", word: "cli", cmd: "set cli screen-length 0", evidence: regexp.MustCompile(`(?m)^Screen length set to 0`)},
	{path: "", word: "save", cmd: "save dhcp-security-snoop /var/tmp/p49-l26b.snoop | count"},
}

// junosL26bMustProve are the words the first run proved on both images; one
// that is not proven is a regression, and fails the test.
var junosL26bMustProve = []string{"show cli", "show host", "show ingress-replication", "show policy", "show task",
	"set cli", "exit"}

// junosL26bSentinel is typed in every hierarchy deny session that does not
// name `system` (review L26b M-2): a hierarchy with a count well above zero,
// so each session carries a strong "ran under deny".
const junosL26bSentinel = "show configuration system | count"

// junosL26bHierarchies is every word either image's `show configuration ?`
// offers (vJunos 32, vSRX 25; the survey), probed on both, so a hierarchy one
// image lacks is recorded absent there.
var junosL26bHierarchies = []string{"access", "access-profile", "accounting-options", "applications", "apply-groups",
	"bridge-domains", "chassis", "class-of-service", "diameter", "dynamic-profiles", "event-options", "firewall",
	"forwarding-options", "groups", "interfaces", "jsrc", "jsrc-partition", "logical-systems", "multi-chassis",
	"multicast-snooping-options", "poe", "policy-options", "protocols", "routing-instances", "routing-options",
	"schedulers", "security", "services", "smtp", "snmp", "switch-options", "system", "unified-edge", "vlans",
	"virtual-chassis"}

// junosL26bRefusal are the CLI's answers to a command it will not take as
// typed; a deny refuses the line with one of them, and an absent head gets
// `unknown command` or `syntax error`.
var junosL26bRefusal = []string{"permission denied", "syntax error", "unknown command", "missing argument",
	"not allowed", "is ambiguous"}

// l26bCell is a command's outcome in one session: ran (its evidence, and no
// refusal), refused (a refusal, and no evidence), or not observed.
func l26bCell(out string, evidence *regexp.Regexp) string {
	if evidence == nil {
		evidence = junosL26bCount
	}
	refused := containsAny(strings.ToLower(out), junosL26bRefusal)
	switch {
	case evidence.MatchString(out) && !refused:
		return "ran"
	case refused && !evidence.MatchString(out):
		return "refused"
	}
	return "not observed"
}

// caretAt is the text the CLI's first caret points at in out: the caret's
// column, less the prompt that preceded the echoed line it sits under.
// promptLen is the length of the session's own prompt, which the window's
// first echo does not carry (it was printed before the window began); a
// retyped line within the window carries its prompt, `user@host> `.
func caretAt(out string, promptLen int) string {
	lines := strings.Split(strings.ReplaceAll(out, "\r", ""), "\n")
	for i := 1; i < len(lines); i++ {
		col := strings.Index(lines[i], "^")
		if col < 0 || strings.TrimSpace(lines[i]) != "^" {
			continue
		}
		echo := lines[i-1]
		off := col - promptLen
		if j := strings.Index(echo, "> "); j >= 0 && strings.Contains(echo[:j], "@") {
			off = col - (j + 2)
			echo = echo[j+2:]
		}
		if off < 0 || off > len(echo) {
			return ""
		}
		return echo[off:]
	}
	return ""
}

// l26bDenyCell is l26bCell for a deny session, with the refusal tied to the
// word under test (review L26b I-2): refused only where the CLI's first caret
// points at word, so a refusal of anything else, or one spilled from another
// command, is not observed.
func l26bDenyCell(out, word string, evidence *regexp.Regexp, promptLen int) string {
	c := l26bCell(out, evidence)
	if c == "refused" && !caretOn(caretAt(out, promptLen), word) {
		return "not observed"
	}
	return c
}

// caretOn reports whether the text from the caret on, at, begins with word
// whole: a caret under `clients` is not one under `cli` (parked item 167).
func caretOn(at, word string) bool {
	rest, ok := strings.CutPrefix(at, word)
	return ok && (rest == "" || strings.ContainsAny(rest[:1], " \t|"))
}

// l26bVerdict is a word's verdict on one image from its two cells, whether
// the image's completion offers it, and the control's output: proven where
// the control ran it and the deny refused it; absent where the image does not
// offer it and the control's CLI called the head an unknown command, typed in
// full as a hidden command would be; else unproven. Any other refusal is not
// absence: vSRX took the hidden `save dhcp-security-snoop` and refused only
// the argument after it (`syntax error, expecting <command>`).
func l26bVerdict(control, deny string, offered bool, controlOut string) string {
	switch {
	case control == "ran" && deny == "refused":
		return "proven"
	case !offered && control == "refused" && strings.Contains(strings.ToLower(controlOut), "unknown command"):
		return "absent"
	}
	return "unproven"
}

// l26bDeny is a deny-commands value naming `path (w1|w2|…) **` in the
// rendered shape, anchored.
func l26bDeny(path string, words []string) string {
	head := " *"
	for _, f := range strings.Fields(path) {
		head += f + " +"
	}
	alt := words[0]
	if len(words) > 1 {
		alt = "(" + strings.Join(words, "|") + ")"
	}
	return head + alt + `( .*)? *(\|.*)?`
}

// l26bChunks splits words into denies at path, each attribute within 255
// bytes.
func l26bChunks(path string, words []string) [][]string {
	var out [][]string
	var cur []string
	for _, w := range words {
		next := append(slices.Clone(cur), w)
		if len("deny-commands=^("+l26bDeny(path, next)+")$") > 255 && len(cur) > 0 {
			out = append(out, cur)
			next = []string{w}
		}
		cur = next
	}
	return append(out, cur)
}

// l26bUserKey keys the session's user in l26bSession's outputs, for the
// prompt's length: never a command.
const l26bUserKey = "\x00user"

// l26bSession is one token login under attrs, each command typed with
// junosPer, and then `exit` where exit is set: its cell is ran where the SSH
// session ended within junosPer (cliConn.done), refused where the prompt came
// back with a refusal, else not observed.
func (l *lab) l26bSession(t *testing.T, name, attrs string, cmds []string, exit bool) (map[string]string, string, string) {
	t.Helper()
	outs := map[string]string{}
	c, r, _ := l.junosLogin(t, name, attrs)
	outs[l26bUserKey] = r.user
	if c == nil {
		t.Errorf("%s: the session did not open, so nothing was measured: %s", name, r.loginErr)
		return outs, "not observed", r.auth
	}
	defer c.Close()
	for _, cmd := range cmds {
		out, err := l.junosProbe(c, junosProbe{cmd: cmd})
		outs[cmd] = out
		if err != nil {
			t.Errorf("%s: %q not observed within %s: %v", name, cmd, junosPer, err)
			return outs, "not observed", r.auth
		}
	}
	if !exit {
		return outs, "", r.auth
	}
	from := len(c.out.String())
	if err := c.send("exit"); err != nil {
		return outs, "not observed", r.auth
	}
	deadline := time.After(junosPer)
	for {
		select {
		case <-c.done:
			outs["exit"] = c.out.String()[from:]
			return outs, "ran", r.auth
		case <-deadline:
			outs["exit"] = c.out.String()[from:]
			t.Errorf("%s: `exit` neither ended the session nor returned a prompt within %s", name, junosPer)
			return outs, "not observed", r.auth
		case <-time.After(250 * time.Millisecond):
			out := c.out.String()[from:]
			if strings.Contains(out, junosOpPrompt) && containsAny(strings.ToLower(out), junosL26bRefusal) {
				junosSettle(c)
				out = c.out.String()[from:]
				outs["exit"] = out
				if !strings.HasPrefix(caretAt(out, len(r.user+"@"+junosHost+"> ")), "exit") {
					return outs, "not observed", r.auth
				}
				return outs, "refused", r.auth
			}
		}
	}
}

// l26bListing is the completion at each path over the break-glass CLI: the
// words offered and whether a placeholder is.
type l26bListing struct {
	words       []string
	placeholder bool
}

func TestL26bJunosKeywordDeny(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
			t.Skip("Junos only")
		}
		stop := l.capture(t, "L26b")
		defer stop()

		// The listings, over break-glass, before any token.
		listings := map[string]l26bListing{}
		func() {
			c, err := l.junosCLI(breakglassUser, breakglassPassword)
			if err != nil {
				t.Fatalf("no break-glass CLI: %v", err)
			}
			defer c.Close()
			if err := junosPrepare(c); err != nil {
				t.Fatalf("set cli screen-length 0 not observed within %s: %v", junosPer, err)
			}
			w := &keywordWalk{c: c, logf: t.Logf, prompt: "@" + junosHost + "> "}
			for _, p := range junosL26bPaths {
				words, ph, err := w.completion(p)
				if err != nil {
					t.Fatalf("completion after %q: not observed: %v", p, err)
				}
				listings[p] = l26bListing{words: words, placeholder: ph}
			}
		}()

		commit := l.junosConfigureAdmin(t, junosL26bClass)
		defer l.junosConfigureAdmin(t, junosL26bDelete)
		defer func() {
			if std, err := l.configPath(); err == nil {
				if err := l.restart(std); err != nil {
					t.Errorf("could not put port49d back on the lab config: %v", err)
				}
			}
		}()

		words := junosL26bWords()
		var cmds []string
		for _, w := range words {
			cmds = append(cmds, w.cmd)
		}

		const class = `"local-user-name=p49-l26b-all"`
		controlOuts, controlExit, controlAuth := l.l26bSession(t, "control", "["+class+"]", cmds, true)

		// The denies: the show words in one, the root and set words in
		// one, the hierarchies in as many as 255 bytes allow.
		type denySession struct {
			name, deny string
			words      []l26bWord
			exit       bool
			sentinel   bool
		}
		var sessions []denySession
		quote := func(re string) string { return strings.ReplaceAll(re, `\`, `\\`) }
		showNames := []string{}
		for _, w := range junosL26bShowWords {
			showNames = append(showNames, w.word)
		}
		sessions = append(sessions, denySession{name: "deny show words",
			deny: "^(" + l26bDeny("show", showNames) + ")$", words: junosL26bShowWords})
		sessions = append(sessions, denySession{name: "deny root and set words",
			deny: "^(" + l26bDeny("", []string{"exit"}) + "|" + l26bDeny("", []string{"save"}) + "|" +
				l26bDeny("set", []string{"cli"}) + ")$",
			words: junosL26bRootWords, exit: true})
		for i, chunk := range l26bChunks("show configuration", junosL26bHierarchies) {
			var ws []l26bWord
			for _, h := range chunk {
				ws = append(ws, l26bWord{path: "show configuration", word: h, cmd: "show configuration " + h + " | count"})
			}
			sessions = append(sessions, denySession{name: fmt.Sprintf("deny hierarchies %d", i+1),
				deny: "^(" + l26bDeny("show configuration", chunk) + ")$", words: ws,
				sentinel: !slices.Contains(chunk, "system")})
		}

		denyCells := map[string]string{} // "<path> <word>" → the deny's cell
		denyOuts := map[string]string{}
		denyOf := map[string]string{}
		var sessionNotes []string
		type sentinelRow struct{ session, cell, out string }
		var sentinels []sentinelRow
		for _, s := range sessions {
			if n := len("deny-commands=" + s.deny); n > 255 {
				t.Fatalf("%s: the deny is %d bytes, past the attribute's 255", s.name, n)
			}
			var sc []string
			for _, w := range s.words {
				sc = append(sc, w.cmd)
			}
			if s.sentinel {
				sc = append(sc, junosL26bSentinel)
			}
			outs, exitCell, auth := l.l26bSession(t, s.name, "["+class+`, "deny-commands=`+quote(s.deny)+`"]`, sc, s.exit)
			promptLen := len(outs[l26bUserKey] + "@" + junosHost + "> ")
			sessionNotes = append(sessionNotes, fmt.Sprintf("#### %s, user `%s`\n\n`deny-commands=%s`\n\n```\n%s\n```",
				s.name, outs[l26bUserKey], tableCell(s.deny), auth))
			for _, w := range s.words {
				key := strings.TrimSpace(w.path + " " + w.word)
				denyCells[key] = l26bDenyCell(outs[w.cmd], w.word, w.evidence, promptLen)
				denyOuts[key] = outs[w.cmd]
				denyOf[key] = s.name
			}
			if s.sentinel {
				out := outs[junosL26bSentinel]
				sentinels = append(sentinels, sentinelRow{s.name, l26bDenyCell(out, "system", nil, promptLen), out})
			}
			if s.exit {
				denyCells["exit"] = exitCell
				denyOuts["exit"] = outs["exit"]
				denyOf["exit"] = s.name
			}
		}

		// Verdicts, and the overlay.
		type row struct{ path, word, cmd, control, deny, verdict string }
		var rows []row
		proven := map[string][]string{}
		verdictOf := map[string]string{}
		add := func(path, word, cmd, cc, dc, controlOut string) {
			v := l26bVerdict(cc, dc, l26bOffered(listings, path, word), controlOut)
			if v == "proven" {
				proven[path] = append(proven[path], word)
			}
			verdictOf[strings.TrimSpace(path+" "+word)] = v
			rows = append(rows, row{path, word, cmd, cc, dc, v})
		}
		for _, w := range words {
			key := strings.TrimSpace(w.path + " " + w.word)
			add(w.path, w.word, w.cmd, l26bCell(controlOuts[w.cmd], w.evidence), denyCells[key], controlOuts[w.cmd])
		}
		add("", "exit", "exit", controlExit, denyCells["exit"], controlOuts["exit"])

		// Regressions (review L26b I-5): an unproven word is a result; a
		// word the first run proved that is not proven now, or a hierarchy
		// that no longer runs under a deny naming it, is news.
		for _, k := range junosL26bMustProve {
			if verdictOf[k] != "proven" {
				t.Errorf("%q: %s, where the first run proved it", k, verdictOf[k])
			}
		}
		notEnforced, offeredHier := 0, 0
		for _, r := range rows {
			if r.path != "show configuration" || !slices.Contains(listings[r.path].words, r.word) {
				continue
			}
			offeredHier++
			if r.control == "ran" && r.deny == "ran" {
				notEnforced++
			} else {
				t.Errorf("hierarchy %q: control %s, deny %s, where every offered hierarchy ran under its deny", r.word,
					r.control, r.deny)
			}
		}
		for _, s := range sentinels {
			if s.cell != "ran" {
				t.Errorf("%s: %q under the deny: %s, not ran", s.session, junosL26bSentinel, s.cell)
			}
		}

		treeFile := filepath.Join("tests", "lab", "results", "L26-keywords-"+l.p.name+".yaml")
		tree, err := os.ReadFile(filepath.Join(root, treeFile))
		if err != nil {
			t.Fatalf("the L26 tree: %v", err)
		}
		overlay, err := l26bOverlay(l.p.name, tree, listings, proven)
		if err != nil {
			t.Fatalf("the overlay: %v", err)
		}
		file := filepath.Join(root, "tests", "lab", "results", "L26b-keywords-"+l.p.name+".yaml")
		if err := os.WriteFile(file, overlay, 0o644); err != nil {
			t.Fatal(err)
		}

		var b strings.Builder
		fmt.Fprintf(&b, "The class was committed: %s.\n\n```\n%s\n```\n\n", commitWord(commit), strings.Join(junosL26bClass, "\n"))
		b.WriteString("A word is **proven** a keyword where the control (the class, no deny) ran the command with " +
			"positive evidence and no refusal in its window (a `Count: N lines` line from `| count`; `Screen length " +
			"set to 0`; for `exit`, the SSH session ending; never a match in the command's own echo), and the deny " +
			"session refused it with the CLI's refusal, its caret under the word; **absent** only where the image " +
			"does not offer the word and the control's CLI answered `unknown command`, typed in full as a hidden " +
			"command would be (a deny naming it is vacuous there, and it is never an allow); anything else is " +
			"**unproven**, and fails closed. Unproven is a result, not a test failure: the test fails on a harness " +
			"failure and on a regression of the words the first run proved.\n\n")
		b.WriteString("### Completion listings (break-glass)\n\n| path | placeholder offered | words offered | words |\n|---|---|---|---|\n")
		for _, p := range junosL26bPaths {
			q := make([]string, len(listings[p].words))
			for i, w := range listings[p].words {
				q[i] = "`" + w + "`"
			}
			fmt.Fprintf(&b, "| `%s` | %v | %d | %s |\n", p, listings[p].placeholder, len(listings[p].words), strings.Join(q, ", "))
		}
		b.WriteString("\n### Verdicts\n\n| path | word | command | control | deny | verdict | deny session |\n|---|---|---|---|---|---|---|\n")
		for _, r := range rows {
			fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | %s | %s | **%s** | %s |\n", r.path, r.word, tableCell(r.cmd), r.control,
				r.deny, r.verdict, denyOf[strings.TrimSpace(r.path+" "+r.word)])
		}
		b.WriteString("\n### Hierarchies\n\n")
		if notEnforced == offeredHier {
			fmt.Fprintf(&b, "**A deny naming a `show configuration` hierarchy is not enforced.** Every one of the %d "+
				"hierarchies this image offers ran under a deny naming it, as it did in the control; the same deny "+
				"shape refused the `show` words above. Each hierarchy word stays unproven.\n\n", offeredHier)
		} else {
			fmt.Fprintf(&b, "%d of the %d hierarchies this image offers ran under a deny naming them; the rest are "+
				"in the table above.\n\n", notEnforced, offeredHier)
		}
		fmt.Fprintf(&b, "Each hierarchy deny session that does not name `system` also typed `%s`, a hierarchy with "+
			"lines to count, under its deny:\n\n| deny session | deny |\n|---|---|\n", tableCell(junosL26bSentinel))
		for _, s := range sentinels {
			fmt.Fprintf(&b, "| %s | %s |\n", s.session, s.cell)
		}
		fmt.Fprintf(&b, "\n### The overlay\n\n`tests/lab/results/L26b-keywords-%s.yaml`, in platform.ParseKeywords form: "+
			"a node's words are those this run proves (and, for the parent chain, `set`, `show` and `configuration`, "+
			"which L26 proves); its `argument` is the node once the overlay is laid over this image's L26 tree: true "+
			"where a placeholder is offered there, or a word offered there is proven by neither. It was computed "+
			"against `%s`, sha256 `%s`, and holds only against the tree that hashes to that.\n\n```yaml\n%s```\n",
			l.p.name, filepath.ToSlash(treeFile), l26bTreeSum(tree), overlay)
		fmt.Fprintf(&b, "\n### Sessions\n\n#### control, user `%s`\n\n```\n%s\n```\n\n%s\n", controlOuts[l26bUserKey],
			controlAuth, strings.Join(sessionNotes, "\n\n"))
		b.WriteString("\n### Outputs\n")
		for _, r := range rows {
			key := strings.TrimSpace(r.path + " " + r.word)
			co := controlOuts[r.cmd]
			if r.word == "exit" && r.path == "" {
				co = controlOuts["exit"]
			}
			fmt.Fprintf(&b, "\n#### `%s`\n\ncontrol:\n\n```\n%s\n```\n\ndeny:\n\n```\n%s\n```\n", r.cmd,
				orEmpty([]string{co}, 0), orEmpty([]string{denyOuts[key]}, 0))
		}
		for _, s := range sentinels {
			fmt.Fprintf(&b, "\n#### sentinel, %s\n\ndeny:\n\n```\n%s\n```\n", s.session, orEmpty([]string{s.out}, 0))
		}
		l.result(t, "L26b", "Junos keywords proven by deny-commands enforcement against a paired control: L26's "+
			"unproven words after `show`, `exit`, `save` and `set cli`, and every `show configuration` hierarchy "+
			"(spec §15 L26; decision 27).", b.String())
	})
}

// junosL26bPaths are the paths whose completion the break-glass CLI lists.
var junosL26bPaths = []string{"", "set", "show", "show configuration"}

// junosL26bWords is every word, with the command it is proven by, in the
// order the control types them.
func junosL26bWords() []l26bWord {
	words := slices.Clone(junosL26bShowWords)
	words = append(words, junosL26bRootWords...)
	for _, h := range junosL26bHierarchies {
		words = append(words, l26bWord{path: "show configuration", word: h, cmd: "show configuration " + h + " | count"})
	}
	return words
}

// l26bOffered is whether the image's completion at path offers word. `exit`
// is a hidden command every image runs in full: never absent.
func l26bOffered(listings map[string]l26bListing, path, word string) bool {
	return (path == "" && word == "exit") || slices.Contains(listings[path].words, word)
}

// l26bTreeSum is the sha256 of an L26 tree file, in hex.
func l26bTreeSum(tree []byte) string {
	sum := sha256.Sum256(tree)
	return hex.EncodeToString(sum[:])
}

// l26bOverlay is the overlay for one image, checked by platform.ParseKeywords.
// argument is computed against tree, the image's L26 tree, whose sha256 the
// overlay's first line records: a node takes an argument where its completion
// offered a placeholder, or a word it offered is proven neither there nor
// here. A parent word the overlay adds must be one the tree proves (review
// L26b M-4).
func l26bOverlay(image string, tree []byte, listings map[string]l26bListing, proven map[string][]string) ([]byte, error) {
	_, base, err := keywords.ParseKeywords(tree)
	if err != nil {
		return nil, fmt.Errorf("the L26 tree: %w", err)
	}
	node := func(path string, parents ...string) (string, []string, bool, error) {
		for _, w := range parents {
			if !base.Keyword(strings.Fields(path), w) {
				return "", nil, false, fmt.Errorf("%q after %q: the L26 tree does not prove it", w, path)
			}
		}
		ws := slices.Clone(proven[path])
		ws = append(ws, parents...)
		slices.Sort(ws)
		ws = slices.Compact(ws)
		li := listings[path]
		arg := li.placeholder
		for _, w := range li.words {
			if !slices.Contains(ws, w) && !base.Keyword(strings.Fields(path), w) {
				arg = true
			}
		}
		return path, ws, arg, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# computed against tests/lab/results/L26-keywords-%s.yaml sha256 %s\nplatform: juniper_junos\nnodes:\n",
		image, l26bTreeSum(tree))
	for _, n := range [][]string{{"", "set", "show"}, {"set"}, {"show", "configuration"}, {"show configuration"}} {
		p, ws, arg, err := node(n[0], n[1:]...)
		if err != nil {
			return nil, err
		}
		q := make([]string, len(ws))
		for i, w := range ws {
			q[i] = fmt.Sprintf("%q", w)
		}
		fmt.Fprintf(&b, "  %q: {words: [%s], argument: %v}\n", p, strings.Join(q, ", "), arg)
	}
	out := []byte(b.String())
	if _, _, err := keywords.ParseKeywords(out); err != nil {
		return nil, fmt.Errorf("does not parse: %w", err)
	}
	return out, nil
}
