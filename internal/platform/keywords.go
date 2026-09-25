package platform

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/platforms"
)

// MaxKeywordNodes and MaxKeywordBytes bound a keyword tree: the lab's capture
// stops at the node cap, and a file past either is refused, since the tree
// is embedded in both binaries and read at every policy load.
const (
	MaxKeywordNodes = 5000
	MaxKeywordBytes = 1 << 20
)

// Keywords is a projected platform's CLI keyword tree as the lab captured it
// on every image a set measures (spec §8; §15 L26): for each command path
// the capture reached, the words the CLI completes there that are keywords,
// and whether an argument may be typed there. Junos matches a deny-commands
// or allow-commands regex against a command's keywords only, never its
// arguments (tests/lab/results/L12-juniper_*.md), so the projection sends a
// rule only where this tree proves every word of it a keyword. A path the
// capture did not reach proves nothing: a word under it is not a keyword,
// and an argument may be typed there. It is the set's measurement, so no
// `platforms:` block can change it.
type Keywords struct {
	nodes map[string]KeywordNode
}

// KeywordNode is one captured command path: Words are the keywords the CLI
// completes after it, lower case and sorted, and Argument whether it takes an
// argument there, on any image.
type KeywordNode struct {
	Words    []string `yaml:"words"`
	Argument bool     `yaml:"argument"`
}

// keywordFile is the file as written. A node's keys are pointers so that
// one left out, or a null node, is told apart from one the capture wrote:
// an argument is proven absent only where the file says `argument: false`.
// A key a later capture adds is one more field here, required the same way.
type keywordFile struct {
	Platform string                      `yaml:"platform"`
	Nodes    map[string]*keywordFileNode `yaml:"nodes"`
}

type keywordFileNode struct {
	Words    []string `yaml:"words"`
	Argument *bool    `yaml:"argument"`
}

// ParseKeywords reads a keyword file: `platform:` and `nodes:`, keyed by
// command path, the root as "". Every word is a lower-case run of printable
// ASCII with no space, every node but the root is listed by its parent, and
// the file is within MaxKeywordBytes and MaxKeywordNodes.
func ParseKeywords(raw []byte) (string, *Keywords, error) {
	if len(raw) > MaxKeywordBytes {
		return "", nil, fmt.Errorf("keywords: %d bytes, past the bound of %d", len(raw), MaxKeywordBytes)
	}
	var f keywordFile
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return "", nil, fmt.Errorf("keywords: %w", err)
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return "", nil, errors.New("keywords: more than one document")
	}
	if f.Platform == "" {
		return "", nil, errors.New("keywords: no platform")
	}
	if len(f.Nodes) > MaxKeywordNodes {
		return "", nil, fmt.Errorf("keywords: %d nodes, past the bound of %d", len(f.Nodes), MaxKeywordNodes)
	}
	if _, ok := f.Nodes[""]; !ok {
		return "", nil, errors.New("keywords: no root node (\"\")")
	}
	nodes := make(map[string]KeywordNode, len(f.Nodes))
	for p, n := range f.Nodes {
		if n == nil || n.Argument == nil {
			return "", nil, fmt.Errorf("keywords: node %q: no argument: key; the capture writes one for every node", p)
		}
		nodes[p] = KeywordNode{Words: n.Words, Argument: *n.Argument}
		for _, w := range n.Words {
			if w == "" || w != strings.ToLower(w) || strings.IndexFunc(w, func(r rune) bool { return r <= ' ' || r > '~' }) >= 0 {
				return "", nil, fmt.Errorf("keywords: node %q: word %q is not a lower-case printable word", p, w)
			}
		}
		if !slices.IsSorted(n.Words) {
			return "", nil, fmt.Errorf("keywords: node %q: words are not sorted", p)
		}
		if p == "" {
			continue
		}
		i := strings.LastIndexByte(p, ' ')
		parent, last := "", p
		if i >= 0 {
			parent, last = p[:i], p[i+1:]
		}
		if pn, ok := f.Nodes[parent]; !ok || pn == nil || !slices.Contains(pn.Words, last) {
			return "", nil, fmt.Errorf("keywords: node %q: its parent %q does not list %q", p, parent, last)
		}
	}
	return f.Platform, &Keywords{nodes: nodes}, nil
}

// Keyword reports whether word is a keyword after path: the capture reached
// path and the CLI completes word there. Case is ignored, as port49 ignores
// it in a rule's word.
func (k *Keywords) Keyword(path []string, word string) bool {
	if k == nil {
		return false
	}
	n, ok := k.nodes[strings.ToLower(strings.Join(path, " "))]
	if !ok {
		return false
	}
	_, found := slices.BinarySearch(n.Words, strings.ToLower(word))
	return found
}

// TakesArgument reports whether an argument may be typed after path: true
// where the capture found one on any image, and true where it did not reach
// path, which proves nothing.
func (k *Keywords) TakesArgument(path []string) bool {
	if k == nil {
		return true
	}
	n, ok := k.nodes[strings.ToLower(strings.Join(path, " "))]
	return !ok || n.Argument
}

// Len is the number of captured nodes.
func (k *Keywords) Len() int {
	if k == nil {
		return 0
	}
	return len(k.nodes)
}

// KeywordsFor is set version's keyword tree for platform, from the embedded
// `platforms/keywords/<version>/<platform>.yaml`, or nil where the set ships
// none. A file that does not load is a build defect, and panics, as a set's
// adapter file does. Each file is read once: a tree is never written after
// ParseKeywords returns it, so every policy load shares it.
func KeywordsFor(version, platformName string) *Keywords {
	key := version + "/" + platformName
	if k, ok := shippedKeywords.Load(key); ok {
		return k.(*Keywords)
	}
	k, _ := shippedKeywords.LoadOrStore(key, keywordsIn(platforms.Keywords, version, platformName))
	return k.(*Keywords)
}

var shippedKeywords sync.Map // "<version>/<platform>" → *Keywords, nil where none ships

func keywordsIn(fsys fs.FS, version, platformName string) *Keywords {
	raw, err := fs.ReadFile(fsys, path.Join("keywords", version, platformName+".yaml"))
	if err != nil {
		return nil
	}
	name, k, err := ParseKeywords(raw)
	if err == nil && name != platformName {
		err = fmt.Errorf("keywords: the file names platform %q", name)
	}
	if err != nil {
		panic(fmt.Sprintf("platforms/keywords/%s/%s.yaml: %v", version, platformName, err))
	}
	return k
}

// MergeKeywords is what every capture proves: a node captured on each image,
// the keywords each completes there, and an argument where any image takes
// one. A keyword only one image has is not proven, and fails closed; a node
// whose last word is not a keyword of its merged parent is dropped with its
// subtree (none is, of trees ParseKeywords read, whose every node its parent
// lists on each image: the drop guards a tree built otherwise). The tree is evidence from every image or none: with no tree, a
// nil one among them, or no root every image holds, the merge is nil, which
// proves nothing, and MarshalKeywords writes it as a file ParseKeywords
// refuses, so it never ships.
func MergeKeywords(trees ...*Keywords) *Keywords {
	if len(trees) == 0 || slices.Contains(trees, nil) {
		return nil
	}
	merged := map[string]KeywordNode{}
	for p, n := range trees[0].nodeMap() {
		words, arg, ok := slices.Clone(n.Words), n.Argument, true
		for _, other := range trees[1:] {
			o, found := other.nodeMap()[p]
			if !found {
				ok = false
				break
			}
			words = slices.DeleteFunc(words, func(w string) bool { return !slices.Contains(o.Words, w) })
			arg = arg || o.Argument
		}
		if ok {
			merged[p] = KeywordNode{Words: words, Argument: arg}
		}
	}
	paths := make([]string, 0, len(merged))
	for p := range merged {
		paths = append(paths, p)
	}
	slices.SortFunc(paths, func(a, b string) int { return strings.Count(a, " ") - strings.Count(b, " ") })
	for _, p := range paths {
		if p == "" {
			continue
		}
		i := strings.LastIndexByte(p, ' ')
		parent, last := "", p
		if i >= 0 {
			parent, last = p[:i], p[i+1:]
		}
		if pn, ok := merged[parent]; !ok || !slices.Contains(pn.Words, last) {
			delete(merged, p)
		}
	}
	if _, ok := merged[""]; !ok {
		return nil
	}
	return &Keywords{nodes: merged}
}

// OverlayKeywords lays a lab overlay over the capture it was computed
// against: tests/lab/results/L26b-keywords-<image>.yaml over that image's
// L26-keywords file (spec §15 L26; decision 27). L26b proves a word a keyword
// by deny-commands enforcement against a paired control, so at each node the
// overlay lists, its words join the capture's and its argument replaces the
// capture's, and a node the capture lacks is added. The overlay's first line,
// `# computed against <file> sha256 <hex>`, names the capture: an overlay
// holds only against the tree that hashes to that, so any other is refused,
// and the overlay is recomputed rather than laid over a capture it did not
// read.
func OverlayKeywords(capture, overlay []byte) (*Keywords, error) {
	first, _, _ := strings.Cut(string(overlay), "\n")
	fields := strings.Fields(first)
	if len(fields) != 6 || fields[0] != "#" || fields[1] != "computed" || fields[2] != "against" ||
		fields[4] != "sha256" {
		return nil, errors.New("keywords overlay: the first line is not `# computed against <file> sha256 <hex>`")
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(capture)); got != fields[5] {
		return nil, fmt.Errorf("keywords overlay: computed against %s at sha256 %s, and this capture hashes to %s: "+
			"recompute the overlay against it", fields[3], fields[5], got)
	}
	name, base, err := ParseKeywords(capture)
	if err != nil {
		return nil, err
	}
	oname, over, err := ParseKeywords(overlay)
	if err != nil {
		return nil, fmt.Errorf("keywords overlay: %w", err)
	}
	if oname != name {
		return nil, fmt.Errorf("keywords overlay: names platform %q, and the capture %q", oname, name)
	}
	nodes := maps.Clone(base.nodes)
	for p, n := range over.nodes {
		words := slices.Concat(nodes[p].Words, n.Words)
		slices.Sort(words)
		nodes[p] = KeywordNode{Words: slices.Compact(words), Argument: n.Argument}
	}
	return &Keywords{nodes: nodes}, nil
}

func (k *Keywords) nodeMap() map[string]KeywordNode {
	if k == nil {
		return nil
	}
	return k.nodes
}

// MarshalKeywords writes k as ParseKeywords reads it, paths sorted, so a
// capture diffs line by line against the last one.
func MarshalKeywords(platformName string, k *Keywords) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "platform: %s\nnodes:\n", platformName)
	paths := make([]string, 0, k.Len())
	for p := range k.nodeMap() {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	for _, p := range paths {
		n := k.nodes[p]
		quoted := make([]string, len(n.Words))
		for i, w := range n.Words {
			quoted[i] = fmt.Sprintf("%q", w)
		}
		fmt.Fprintf(&b, "  %q: {words: [%s], argument: %v}\n", p, strings.Join(quoted, ", "), n.Argument)
	}
	return []byte(b.String())
}
