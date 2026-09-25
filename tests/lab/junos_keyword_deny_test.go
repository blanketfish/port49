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
// control's CLI calls it unknown, typed in full as a hidden command would be)
// is recorded absent there; a deny naming it is vacuous on that image, and it
// is never an allow. Anything else is not observed, and the word stays
// unproven, which fails closed.
//
// Evidence of a run is positive: `<command> | count` prints "Count: N
// lines" only where the CLI took the command and ran it (a deny refuses the
// line as it is parsed, before any pipe), `set cli screen-length 0` says
// "Screen length set to 0", and `exit` ends the SSH session (cliConn.done).
// Every read has junosPer.
//
// Before any token, the break-glass CLI lists the completions at the root,
// `set`, `show` and `show configuration`, so the note records whether each
// offers an `<argument>` placeholder apart from whether its words are proven.
// The test writes an overlay per image, tests/lab/results/L26b-keywords-
// <image>.yaml, in platform.ParseKeywords form: each node's words are those
// this run proves (with the parents L26 proves, so every node's parent lists
// it), and its `argument` is what the node is once the overlay is laid over
// the image's L26 tree: true where completion offers a placeholder there or
// any word it offers is proven by neither.

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

var junosL26bCount = regexp.MustCompile(`Count: \d+ lines`)

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
// /var/tmp on a lab device the run destroys. `exit` is typed last.
var junosL26bRootWords = []l26bWord{
	{path: "set", word: "cli", cmd: "set cli screen-length 0", evidence: regexp.MustCompile(`Screen length set to 0`)},
	{path: "", word: "save", cmd: "save dhcp-security-snoop /var/tmp/p49-l26b.snoop",
		evidence: regexp.MustCompile(`(?i)(saved|wrote|written|entries)`)},
}

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
	if c == "refused" && !strings.HasPrefix(caretAt(out, promptLen), word) {
		return "not observed"
	}
	return c
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
			for _, p := range []string{"", "set", "show", "show configuration"} {
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

		// Every word, the command it is proven by, in one list.
		words := slices.Clone(junosL26bShowWords)
		words = append(words, junosL26bRootWords...)
		for _, h := range junosL26bHierarchies {
			words = append(words, l26bWord{path: "show configuration", word: h, cmd: "show configuration " + h + " | count"})
		}
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
				deny: "^(" + l26bDeny("show configuration", chunk) + ")$", words: ws})
		}

		denyCells := map[string]string{} // "<path> <word>" → the deny's cell
		denyOuts := map[string]string{}
		denyOf := map[string]string{}
		var denyAuth []string
		for _, s := range sessions {
			if n := len("deny-commands=" + s.deny); n > 255 {
				t.Fatalf("%s: the deny is %d bytes, past the attribute's 255", s.name, n)
			}
			var sc []string
			for _, w := range s.words {
				sc = append(sc, w.cmd)
			}
			outs, exitCell, auth := l.l26bSession(t, s.name, "["+class+`, "deny-commands=`+quote(s.deny)+`"]`, sc, s.exit)
			promptLen := len(outs[l26bUserKey] + "@" + junosHost + "> ")
			denyAuth = append(denyAuth, fmt.Sprintf("%s: `deny-commands=%s`\n\n```\n%s\n```", s.name, tableCell(s.deny), auth))
			for _, w := range s.words {
				key := strings.TrimSpace(w.path + " " + w.word)
				denyCells[key] = l26bDenyCell(outs[w.cmd], w.word, w.evidence, promptLen)
				denyOuts[key] = outs[w.cmd]
				denyOf[key] = s.name
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
		add := func(path, word, cmd, cc, dc, controlOut string) {
			offered := slices.Contains(listings[path].words, word)
			if word == "exit" {
				offered = true // a hidden command every image runs in full; never absent
			}
			v := l26bVerdict(cc, dc, offered, controlOut)
			if v == "unproven" {
				t.Errorf("%q after %q: unproven (control %s, deny %s)", word, path, cc, dc)
			}
			if v == "proven" {
				proven[path] = append(proven[path], word)
			}
			rows = append(rows, row{path, word, cmd, cc, dc, v})
		}
		for _, w := range words {
			key := strings.TrimSpace(w.path + " " + w.word)
			add(w.path, w.word, w.cmd, l26bCell(controlOuts[w.cmd], w.evidence), denyCells[key], controlOuts[w.cmd])
		}
		add("", "exit", "exit", controlExit, denyCells["exit"], controlOuts["exit"])

		overlay, err := l26bOverlay(l.p.name, listings, proven)
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
			"positive evidence (`Count: N lines` from `| count`, which only a command the CLI took and ran prints; " +
			"`Screen length set to 0`; for `exit`, the SSH session ending) and the deny session refused it with the " +
			"CLI's refusal; **absent** where the image does not offer the word and the control's CLI refused it too, " +
			"typed in full as a hidden command would be (a deny naming it is vacuous there, and it is never an " +
			"allow); anything else is **unproven**, and fails closed.\n\n")
		b.WriteString("### Completion listings (break-glass)\n\n| path | placeholder offered | words offered |\n|---|---|---|\n")
		for _, p := range []string{"", "set", "show", "show configuration"} {
			fmt.Fprintf(&b, "| `%s` | %v | %d |\n", p, listings[p].placeholder, len(listings[p].words))
		}
		b.WriteString("\n### Verdicts\n\n| path | word | command | control | deny | verdict | deny session |\n|---|---|---|---|---|---|---|\n")
		for _, r := range rows {
			fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | %s | %s | **%s** | %s |\n", r.path, r.word, tableCell(r.cmd), r.control,
				r.deny, r.verdict, denyOf[strings.TrimSpace(r.path+" "+r.word)])
		}
		fmt.Fprintf(&b, "\n### The overlay\n\n`tests/lab/results/L26b-keywords-%s.yaml`, in platform.ParseKeywords form: "+
			"a node's words are those this run proves (and, for the parent chain, `set`, `show` and `configuration`, "+
			"which L26 proves); its `argument` is the node once the overlay is laid over this image's L26 tree: true "+
			"where a placeholder is offered there, or a word offered there is proven by neither.\n\n```yaml\n%s```\n",
			l.p.name, overlay)
		b.WriteString("\n### Sessions\n\ncontrol:\n\n```\n" + controlAuth + "\n```\n\n" + strings.Join(denyAuth, "\n\n") + "\n")
		b.WriteString("\n### Outputs\n")
		for _, r := range rows {
			key := strings.TrimSpace(r.path + " " + r.word)
			co := controlOuts[r.cmd]
			if r.word == "exit" && r.path == "" {
				co = controlOuts["exit"]
			}
			fmt.Fprintf(&b, "\n#### `%s`\n\ncontrol:\n\n```\n%s\n```\n\ndeny:\n\n```\n%s\n```\n", r.cmd,
				firstLines(orEmpty([]string{co}, 0), 12), firstLines(orEmpty([]string{denyOuts[key]}, 0), 12))
		}
		l.result(t, "L26b", "Junos keywords proven by deny-commands enforcement against a paired control: L26's "+
			"unproven words after `show`, `exit`, `save` and `set cli`, and every `show configuration` hierarchy "+
			"(spec §15 L26; decision 27).", b.String())
	})
}

// l26bOverlay is the overlay for one image, checked by platform.ParseKeywords.
// argument is computed against the image's committed L26 tree: a node takes
// an argument where its completion offered a placeholder, or a word it
// offered is proven neither there nor here.
func l26bOverlay(image string, listings map[string]l26bListing, proven map[string][]string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(root, "tests", "lab", "results", "L26-keywords-"+image+".yaml"))
	if err != nil {
		return nil, err
	}
	_, base, err := keywords.ParseKeywords(raw)
	if err != nil {
		return nil, fmt.Errorf("the L26 tree: %w", err)
	}
	node := func(path string, extra ...string) (string, []string, bool) {
		ws := slices.Clone(proven[path])
		ws = append(ws, extra...)
		slices.Sort(ws)
		ws = slices.Compact(ws)
		li := listings[path]
		arg := li.placeholder
		for _, w := range li.words {
			if !slices.Contains(ws, w) && !base.Keyword(strings.Fields(path), w) {
				arg = true
			}
		}
		return path, ws, arg
	}
	var b strings.Builder
	fmt.Fprintf(&b, "platform: juniper_junos\nnodes:\n")
	for _, n := range [][]string{{"", "set", "show"}, {"set"}, {"show", "configuration"}, {"show configuration"}} {
		p, ws, arg := node(n[0], n[1:]...)
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
