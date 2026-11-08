package docgen

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

const (
	// LabRegisterPage is the generated page that explains and anchors every lab register ID.
	LabRegisterPage = "docs/site/reference/lab-register.md"
	// labRegisterDocPath is that page relative to docs/site, as a link from a page names it.
	labRegisterDocPath = "reference/lab-register.md"
	// LabRegisterSiteURL is the page on the published site. A file that is also read on GitHub (a README the
	// site includes) links it by this URL, because a relative link works on only one of the two.
	LabRegisterSiteURL = "https://blanketfish.github.io/port49/reference/lab-register/"
)

// RegisterLinkFrom is the relative link target of the lab register page from page, a path relative to
// docs/site: "../../reference/lab-register.md" from admin/devices/x.md.
func RegisterLinkFrom(page string) string {
	var from []string
	if dir := path.Dir(page); dir != "." {
		from = strings.Split(dir, "/")
	}
	to := strings.Split(labRegisterDocPath, "/")
	for len(from) > 0 && len(to) > 1 && from[0] == to[0] {
		from, to = from[1:], to[1:]
	}
	return strings.Repeat("../", len(from)) + strings.Join(to, "/")
}

// LabSpan is one lab ID in a markdown text that is neither linked nor code.
type LabSpan struct {
	Start, End int
	ID         string
}

var (
	labIDWord  = regexp.MustCompile(`\bL[0-9]+[a-z]?\b`)
	fenceOpen  = regexp.MustCompile("^\\s*(```|~~~)")
	admonOpen  = regexp.MustCompile(`^\s*(!!!|\?\?\?\+?)\s`)
	fileExt    = regexp.MustCompile(`\.[A-Za-z][A-Za-z0-9]{0,4}$`)
	idSegment  = regexp.MustCompile(`^L[0-9]+[a-z]?(-[A-Za-z0-9_.-]*)?$`)
	refDef     = regexp.MustCompile(`^\s{0,3}\[[^\]]+\]:\s`)
	rawURL     = regexp.MustCompile(`^https?://[^\s<>]*`)
	htmlTag    = regexp.MustCompile(`^</?[A-Za-z][^>]*>|^<!--.*?-->`)
	autolinkRE = regexp.MustCompile(`^<[A-Za-z][A-Za-z0-9+.-]*:[^>\s]*>`)
)

// BareLabIDs lists the lab IDs in md that are not inside a link, a code span, a fenced block, front
// matter, an HTML comment or tag, an admonition's title line, or a path or file name. A heading that is
// only an ID is the register page's own anchor and is not one. It is the scanner both the rewriter and
// the lint use, so what one links the other accepts.
func BareLabIDs(md string) []LabSpan {
	var out []LabSpan
	off := 0
	if rest, ok := strings.CutPrefix(md, "---\n"); ok {
		if i := strings.Index(rest, "\n---\n"); i >= 0 {
			off = 4 + i + 5
		}
	}
	fence := ""
	inComment := false
	for off < len(md) {
		end := strings.IndexByte(md[off:], '\n')
		if end < 0 {
			end = len(md) - off
		}
		line := md[off : off+end]
		trim := strings.TrimSpace(line)
		switch {
		case fence != "":
			if strings.HasPrefix(trim, fence) {
				fence = ""
			}
		case fenceOpen.MatchString(line):
			fence = strings.TrimSpace(line)[:3]
		case inComment:
			inComment = !strings.Contains(line, "-->")
		case strings.HasPrefix(trim, "<!--") && !strings.Contains(trim, "-->"):
			inComment = true
		case refDef.MatchString(line):
		case admonOpen.MatchString(line):
			// only the quoted title is prose; Material renders inline markdown in it
			if q := strings.IndexByte(line, '"'); q >= 0 {
				out = append(out, scanLine(line[q:], off+q)...)
			}
		default:
			out = append(out, scanLine(line, off)...)
		}
		off += end + 1
	}
	return out
}

// scanLine finds the bare lab IDs of one line of prose.
func scanLine(line string, base int) []LabSpan {
	var out []LabSpan
	for i := 0; i < len(line); {
		c := line[i]
		switch {
		case c == '\\' && i+1 < len(line):
			i += 2
		case c == '`':
			i = skipCodeSpan(line, i)
		case c == '!' && i+1 < len(line) && line[i+1] == '[', c == '[':
			if j := skipLink(line, i); j > i {
				i = j
			} else {
				i++
			}
		case c == '<':
			if m := autolinkRE.FindString(line[i:]); m != "" {
				i += len(m)
			} else if m := htmlTag.FindString(line[i:]); m != "" {
				i += len(m)
			} else {
				i++
			}
		case c == 'h' && (i == 0 || !isWordByte(line[i-1])) && rawURL.MatchString(line[i:]):
			i += len(rawURL.FindString(line[i:]))
		case c == 'L' && (i == 0 || !isWordByte(line[i-1])):
			loc := labIDWord.FindStringIndex(line[i:])
			if loc == nil || loc[0] != 0 {
				i++
				continue
			}
			j := i + loc[1]
			if !partOfAName(line, i, j) {
				out = append(out, LabSpan{base + i, base + j, line[i:j]})
			}
			i = j
		default:
			i++
		}
	}
	return out
}

func isWordByte(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func isNameByte(b byte) bool { return isWordByte(b) || b == '.' || b == '-' || b == '/' }

// partOfAName reports whether the ID at [i,j) is part of a file name or a path ("L4-error-arista_eos.md",
// "L4.md", "tests/lab/results/L4-x.md") and not a mention. The word the ID sits in, up to the spaces and
// punctuation round it, is a name when it ends in a file extension or when a "/" joins it to a segment that
// is not itself an ID. So "L4/L13", "L26c-L27", "foo-L4" and the variant "L29-reload" are mentions.
func partOfAName(line string, i, j int) bool {
	s, e := i, j
	for s > 0 && isNameByte(line[s-1]) {
		s--
	}
	for e < len(line) && isNameByte(line[e]) {
		e++
	}
	tok := strings.TrimRight(line[s:e], ".")
	if fileExt.MatchString(tok) {
		return true
	}
	if strings.Contains(tok, "/") {
		for _, seg := range strings.Split(tok, "/") {
			if seg != "" && !idSegment.MatchString(seg) {
				return true
			}
		}
	}
	return false
}

// skipCodeSpan returns the index after the code span opening at i, or i+run when it never closes.
func skipCodeSpan(line string, i int) int {
	n := 0
	for i+n < len(line) && line[i+n] == '`' {
		n++
	}
	fence := strings.Repeat("`", n)
	for j := i + n; j < len(line); {
		k := strings.Index(line[j:], fence)
		if k < 0 {
			break
		}
		k += j
		e := k + n
		if e < len(line) && line[e] == '`' {
			for e < len(line) && line[e] == '`' {
				e++
			}
			j = e
			continue
		}
		return e
	}
	return i + n
}

// skipLink returns the index after the link or image that opens at i ("[text](url)" or "[text][ref]"), or i
// when what follows the bracket is not a link.
func skipLink(line string, i int) int {
	j := i
	if line[j] == '!' {
		j++
	}
	close := matchClose(line, j, '[', ']')
	if close < 0 || close+1 >= len(line) {
		return i
	}
	switch line[close+1] {
	case '(':
		if e := matchClose(line, close+1, '(', ')'); e >= 0 {
			return e + 1
		}
	case '[':
		if e := matchClose(line, close+1, '[', ']'); e >= 0 {
			return e + 1
		}
	}
	return i
}

// matchClose returns the index of the bracket that closes the one at i, skipping code spans and escapes.
func matchClose(line string, i int, open, close byte) int {
	depth := 0
	for j := i; j < len(line); j++ {
		switch line[j] {
		case '\\':
			j++
		case '`':
			j = skipCodeSpan(line, j) - 1
		case open:
			depth++
		case close:
			if depth--; depth == 0 {
				return j
			}
		}
	}
	return -1
}

// LinkLabIDs links every bare lab ID in md to its anchor on the register page: base is what precedes the
// "#l15" (a relative path to the page, the site URL, or "" on the register page itself). An ID the
// register does not hold is an error, so a link never points at a missing anchor. Linking text that is
// already linked changes nothing.
func LinkLabIDs(md string, reg map[string]LabRow, base string) (string, error) {
	spans := BareLabIDs(md)
	var unknown []string
	for _, s := range spans {
		if _, ok := reg[s.ID]; !ok {
			unknown = append(unknown, s.ID)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return "", fmt.Errorf("lab ID %s is not in spec section 15", strings.Join(dedupe(unknown), ", "))
	}
	var b strings.Builder
	last := 0
	for _, s := range spans {
		b.WriteString(md[last:s.Start])
		fmt.Fprintf(&b, "[%s](%s#%s)", s.ID, base, strings.ToLower(s.ID))
		last = s.End
	}
	b.WriteString(md[last:])
	return b.String(), nil
}
