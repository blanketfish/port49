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

// These run without a device: the L26b classifiers and the denies it renders.

func TestL26bCell(t *testing.T) {
	screen := junosL26bRootWords[0].evidence
	for _, c := range []struct {
		out  string
		ev   *regexp.Regexp
		want string
	}{
		{"show cli | count \nCount: 9 lines\nalice01@srx1> ", nil, "ran"},
		{"show policy | count \nCount: 0 lines\n", nil, "ran"},
		{"show cli | count \n         ^\npermission denied.\n", nil, "refused"},
		{"show configuration vlans | count\n                   ^\nsyntax error.\n", nil, "refused"},
		{"save dhcp\n^\nunknown command.\n", nil, "refused"},
		{"set cli screen-length 0 \nScreen length set to 0\n", screen, "ran"},
		// Neither the evidence nor a refusal: not observed.
		{"show task memory | count \n", nil, "not observed"},
		{"", nil, "not observed"},
		// Both: not observed, never a run nor a refusal.
		{"Count: 1 lines\nsyntax error.", nil, "not observed"},
		// Evidence counts only at a line's start, never inside an echo.
		{"echo Count: 3 lines\n", nil, "not observed"},
		{"set cli Screen length set to 0\n", screen, "not observed"},
	} {
		if got := l26bCell(c.out, c.ev); got != c.want {
			t.Errorf("l26bCell(%q) = %q, want %q", c.out, got, c.want)
		}
	}
}

func TestL26bVerdict(t *testing.T) {
	unknown := "save\n              ^\nunknown command.\n"
	argument := "                                       ^\nsyntax error, expecting <command>.\n"
	for _, c := range []struct {
		control, deny string
		offered       bool
		out           string
		want          string
	}{
		{"ran", "refused", true, "", "proven"},
		{"ran", "refused", false, "", "proven"}, // a hidden word the control runs
		{"ran", "ran", true, "", "unproven"},
		{"ran", "not observed", true, "", "unproven"},
		{"not observed", "refused", true, "", "unproven"},
		{"refused", "refused", false, unknown, "absent"},
		{"refused", "not observed", false, unknown, "absent"},
		// A refusal of the argument after a hidden head is not absence.
		{"refused", "not observed", false, argument, "unproven"},
		{"refused", "refused", true, unknown, "unproven"}, // offered, and the control could not run it
		{"not observed", "refused", false, unknown, "unproven"},
	} {
		if got := l26bVerdict(c.control, c.deny, c.offered, c.out); got != c.want {
			t.Errorf("l26bVerdict(%q, %q, %v, %q) = %q, want %q", c.control, c.deny, c.offered, c.out, got, c.want)
		}
	}
}

func TestL26bDenies(t *testing.T) {
	if got, want := l26bDeny("show", []string{"cli", "host"}), ` *show +(cli|host)( .*)? *(\|.*)?`; got != want {
		t.Errorf("l26bDeny = %q, want %q", got, want)
	}
	if got, want := l26bDeny("", []string{"exit"}), ` *exit( .*)? *(\|.*)?`; got != want {
		t.Errorf("l26bDeny root = %q, want %q", got, want)
	}
	re := regexp.MustCompile("^(" + l26bDeny("show configuration", []string{"system", "interfaces"}) + ")$")
	for cmd, want := range map[string]bool{"show configuration system": true, "show configuration system | count": true,
		"  show  configuration interfaces ge-0/0/0": true, "show configuration": false, "show configuration systems": false} {
		if re.MatchString(cmd) != want {
			t.Errorf("%q: matched %v", cmd, !want)
		}
	}
	chunks := l26bChunks("show configuration", junosL26bHierarchies)
	var all []string
	for _, ch := range chunks {
		if n := len("deny-commands=^(" + l26bDeny("show configuration", ch) + ")$"); n > 255 {
			t.Errorf("a chunk is %d bytes", n)
		}
		all = append(all, ch...)
	}
	if !slices.Equal(all, junosL26bHierarchies) {
		t.Errorf("the chunks lose or reorder words: %v", all)
	}
	t.Logf("%d hierarchy denies: %s", len(chunks), strings.Repeat("·", len(chunks)))
}

// TestCommittedL26bVerdictsHold re-reads both committed L26b notes from
// committed files alone (review L26b I-4, M-3): the listings the note
// records decide `offered`; every row's control and deny cells are
// recomputed from its full recorded outputs, with each deny session's prompt
// from the user the note names (but the control's `exit`, which is the
// session ending: its output must hold no refusal); every verdict follows;
// the sentinels are recomputed; the L26 tree still hashes to what the note
// records; and the committed overlay is what l26bOverlay makes from the
// listings, the proven words and that tree.
func TestCommittedL26bVerdictsHold(t *testing.T) {
	block := regexp.MustCompile("(?s)\n#### `([^`\n]+)`\n\ncontrol:\n\n```\n(.*?)\n```\n\ndeny:\n\n```\n(.*?)\n```\n")
	sentinel := regexp.MustCompile("(?s)\n#### sentinel, ([^\n]+)\n\ndeny:\n\n```\n(.*?)\n```\n")
	userOf := regexp.MustCompile("(?m)^#### ([^\n`]+), user `([^`]+)`$")
	sumOf := regexp.MustCompile("against `(tests/lab/results/L26-keywords-[^`]+\\.yaml)`, sha256 `([0-9a-f]{64})`")
	for _, img := range []string{"juniper_vjunos-router", "juniper_vsrx"} {
		raw, err := os.ReadFile(filepath.Join("results", "L26b-"+img+".md"))
		if err != nil {
			t.Fatal(err)
		}
		note := string(raw)
		rowOf := func(first ...string) []string {
			prefix := "| " + strings.Join(first, " | ") + " |"
			for _, line := range strings.Split(note, "\n") {
				if strings.HasPrefix(line, prefix) {
					cells := strings.Split(strings.Trim(strings.ReplaceAll(line, `\|`, "\x00"), "| "), " | ")
					for i := range cells {
						cells[i] = strings.ReplaceAll(cells[i], "\x00", "|")
					}
					return cells
				}
			}
			return nil
		}

		listings := map[string]l26bListing{}
		for _, p := range junosL26bPaths {
			row := rowOf("`" + p + "`")
			if len(row) < 3 {
				t.Fatalf("%s: no listing row for %q", img, p)
			}
			var li l26bListing
			li.placeholder = row[1] == "true"
			if len(row) > 3 {
				for _, w := range strings.Split(row[3], ", ") {
					if w = strings.Trim(w, "`"); w != "" {
						li.words = append(li.words, w)
					}
				}
			}
			if n := fmt.Sprint(len(li.words)); n != row[2] {
				t.Errorf("%s: listing %q counts %s, lists %s words", img, p, row[2], n)
			}
			listings[p] = li
		}
		users := map[string]int{}
		for _, m := range userOf.FindAllStringSubmatch(note, -1) {
			users[m[1]] = len(m[2] + "@" + junosHost + "> ")
		}
		outs := map[string][2]string{}
		for _, m := range block.FindAllStringSubmatch(note, -1) {
			outs[m[1]] = [2]string{m[2], m[3]}
		}

		proven := map[string][]string{}
		check := func(w l26bWord, recompute bool) {
			row := rowOf("`"+w.path+"`", "`"+w.word+"`")
			o, ok := outs[w.cmd]
			if !ok || len(row) < 7 {
				t.Errorf("%s: no row or outputs for %q", img, w.cmd)
				return
			}
			promptLen, ok := users[row[6]]
			if !ok {
				t.Errorf("%s: %q: the note names no user for %q", img, w.cmd, row[6])
				return
			}
			cc, dc := row[3], l26bDenyCell(o[1], w.word, w.evidence, promptLen)
			if recompute {
				cc = l26bCell(o[0], w.evidence)
			} else if cc == "ran" && containsAny(strings.ToLower(o[0]), junosL26bRefusal) {
				t.Errorf("%s: the control's %q ran, and its output holds a refusal", img, w.cmd)
			}
			v := l26bVerdict(cc, dc, l26bOffered(listings, w.path, w.word), o[0])
			got := strings.Trim(row[5], "*")
			if cc != row[3] || dc != row[4] || v != got {
				t.Errorf("%s %q after %q: the note reads %s / %s / %s, the classifier now %s / %s / %s", img, w.word,
					w.path, row[3], row[4], got, cc, dc, v)
			}
			if got == "proven" {
				proven[w.path] = append(proven[w.path], w.word)
			}
		}
		for _, w := range junosL26bWords() {
			check(w, true)
		}
		check(l26bWord{path: "", word: "exit", cmd: "exit"}, false)

		sentinels := 0
		for _, m := range sentinel.FindAllStringSubmatch(note, -1) {
			sentinels++
			row := rowOf(m[1])
			if len(row) < 2 || row[1] != l26bDenyCell(m[2], "system", nil, users[m[1]]) {
				t.Errorf("%s: sentinel in %s: the note reads %v", img, m[1], row)
			}
		}
		if sentinels == 0 {
			t.Errorf("%s: no sentinels", img)
		}

		m := sumOf.FindStringSubmatch(note)
		if m == nil {
			t.Fatalf("%s: the note records no L26 tree sha256", img)
		}
		tree, err := os.ReadFile(filepath.Join("..", "..", m[1]))
		if err != nil {
			t.Fatal(err)
		}
		if got := l26bTreeSum(tree); got != m[2] && os.Getenv("PORT49_L26B_REPIN") == "" {
			t.Errorf("%s: %s hashes to %s, the overlay was computed against %s: rerun L26b", img, m[1], got, m[2])
		}
		want, err := l26bOverlay(img, tree, listings, proven)
		if err != nil {
			t.Fatal(err)
		}
		committed, err := os.ReadFile(filepath.Join("results", "L26b-keywords-"+img+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if os.Getenv("PORT49_L26B_REPIN") != "" && string(committed) != string(want) {
			committed, note = l26bRepin(t, img, m[2], committed, want, note)
		}
		if string(committed) != string(want) {
			t.Errorf("%s: the committed overlay is not what the note's listings and verdicts make:\n%s\nwant:\n%s", img,
				committed, want)
		}
		if !strings.Contains(note, "```yaml\n"+string(committed)+"```") {
			t.Errorf("%s: the note's overlay is not the committed one", img)
		}
	}
}

// l26bRepin re-pins an image's committed overlay, and its note, to the L26
// tree now committed, when PORT49_L26B_REPIN is set: an L26 rerun changes the
// tree's sha256, and the overlay the note's listings and verdicts make
// against the new tree, want, is written in its place. It is refused, and
// L26b rerun instead, unless want lists the same nodes, words and arguments
// as the committed overlay: the new tree offers the same words where the
// overlay reads it, so only the pinned sha256 changes. The note keeps the
// sha256 its run was computed against, now the earlier run's, in a sentence.
func l26bRepin(t *testing.T, img, was string, committed, want []byte, note string) ([]byte, string) {
	t.Helper()
	_, oldBody, _ := strings.Cut(string(committed), "\n")
	_, newBody, _ := strings.Cut(string(want), "\n")
	if oldBody != newBody {
		t.Fatalf("%s: against the new L26 tree the overlay's nodes change: rerun L26b\n%s\nwas:\n%s", img, want, committed)
	}
	now := strings.Fields(strings.SplitN(string(want), "\n", 2)[0])[5]
	lead := "and holds only against the tree that hashes to that."
	if !strings.Contains(note, lead) {
		t.Fatalf("%s: the note has no overlay paragraph to re-pin", img)
	}
	note = strings.Replace(note, "```yaml\n"+string(committed)+"```", "```yaml\n"+string(want)+"```", 1)
	note = strings.Replace(note, "sha256 `"+was+"`", "sha256 `"+now+"`", 1)
	note = strings.Replace(note, lead, lead+fmt.Sprintf(" This run computed it against an earlier L26 run of the image, "+
		"whose tree hashed to %s; an L26 rerun changed the tree, and the overlay was re-pinned to it from this run's "+
		"listings and verdicts, with its nodes, words and arguments unchanged.", was), 1)
	if err := os.WriteFile(filepath.Join("results", "L26b-keywords-"+img+".yaml"), want, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("results", "L26b-"+img+".md"), []byte(note), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("%s: re-pinned the overlay from %s to %s", img, was, now)
	return want, note
}

func TestCaretAt(t *testing.T) {
	// The first echo carries no prompt; the caret column counts it.
	first := "show cli\n                   ^\nsyntax error, expecting <command>.\nalice02@srx1> show cli   |\n"
	if got := caretAt(first, len("alice02@srx1> ")); !strings.HasPrefix(got, "cli") {
		t.Errorf("caretAt(first echo) = %q", got)
	}
	// A retyped line carries its own prompt.
	retyped := "garbage\nalice02@srx1> exit\n              ^\nunknown command.\n"
	if got := caretAt(retyped, 99); !strings.HasPrefix(got, "exit") {
		t.Errorf("caretAt(retyped) = %q", got)
	}
	if l26bDenyCell("show cli\n               ^\nsyntax error.\n", "cli", nil, len("alice02@srx1> ")) != "not observed" {
		t.Error("a refusal whose caret is not at the word is refused")
	}
	if l26bDenyCell(first, "cli", nil, len("alice02@srx1> ")) != "refused" {
		t.Error("a refusal at the word is not refused")
	}
	// A caret under a longer word that begins with it is not at the word.
	longer := "show clients\n                   ^\nsyntax error.\n"
	if l26bDenyCell(longer, "cli", nil, len("alice02@srx1> ")) != "not observed" {
		t.Error("a caret under clients is read as one under cli")
	}
	for at, want := range map[string]bool{"cli": true, "cli   |": true, "cli\t": true, "clients": false, "": false} {
		if caretOn(at, "cli") != want {
			t.Errorf("caretOn(%q, cli) = %v", at, !want)
		}
	}
}
