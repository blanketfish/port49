package projection

import (
	"errors"
	"fmt"
	"math/bits"
	"slices"
	"strings"

	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
)

// The shapes a reply takes (spec §8, "The projection model").
const (
	// ShapeCapability is bits for the broad reach, `deny-commands` for what
	// the bits reach and the grant denies, `allow-commands` for a permit
	// beneath such a deny: the common case.
	ShapeCapability = "capability"
	// ShapeNarrow is a grant narrower than every bit that reaches its
	// permits: `deny-commands` `.*` and one allow alternation of the permits,
	// under the smallest bits that reach them. It cannot carry a deny
	// beneath a permit.
	ShapeNarrow = "narrow"
	// ShapeFailClosed is the reply a composition gets when neither shape can
	// carry it faithfully (spec §13 decision 26): `deny-commands` `.*`, only
	// the allows the generator proves, and no bit that enters configuration
	// mode; no template. The subject is told less than port49 would permit,
	// every other subject on the device is unaffected, and `policy test` and
	// `policy diff` fail on it.
	ShapeFailClosed = "fail_closed"
)

// Why a composition got the fail-closed reply: Result.FailClosed.
const (
	FailRefusedShape      = "refused_shape"
	FailConfigurationMode = "configuration_mode"
	FailOverflow          = "overflow"
	FailUnwritable        = "unwritable"
	FailSecretRule        = "secret_rule"
	FailUnsound           = "unsound"
)

// JunosFacts are what the Junos images were measured doing with a command
// regex (spec §15, L9): tests/lab/results/L9-juniper_*.md.
var JunosFacts = Facts{CaseSensitive: true, DenyMatchesExpanded: false}

// FactsFor is what a projection's device was measured doing: the zero Facts,
// which fail closed, for a projection with no measurement.
func FactsFor(projection string) Facts {
	if projection == platform.ProjectionJunosRegex {
		return JunosFacts
	}
	return Facts{CaseSensitive: true}
}

// Input is one composition on one projected platform: the rules its roles
// compose to (the blob's), and its level's ceiling in bits.
type Input struct {
	Platform string
	Dialect  platform.Dialect
	// Level is the level the bits and template are the ceiling of, its parent
	// chain followed; empty where the composition has no level, which gets no
	// bits and no template.
	Level    string
	Bits     []string
	Template string
	Rules    []engine.Rule
	Classes  map[string][]string
	// Normalize is the platform's normalization, as the blob carries it.
	Normalize engine.Normalize
	// Secret reports whether a rule's text carries a value the platform's
	// redaction hides: the reply is logged whole, so such a rule is never
	// sent (spec §5.8).
	Secret func(rule string) bool
	Facts  Facts
}

// Result is the reply a composition renders to, and what CI reports of it
// (spec §8): the shape, the bits or template, the rules each regex carries,
// and what the device is narrower than port49 in.
type Result struct {
	Shape    string
	Bits     []string // sent as user-permissions, or carried by Template's class
	Template string   // sent as local-user-name
	// Attributes is the reply, in wire order: the bits or the template, then
	// deny-commands, then allow-commands.
	Attributes []string
	// Denies are sent in deny-commands; none outside ShapeCapability. One
	// whose Role is platform.BaselineBit is not the grant's: it holds a
	// command the baseline runs for every session and no permit holds.
	Denies []engine.Rule
	Allows []engine.Rule // sent in allow-commands
	// Omitted are denies the bits already refuse, sent as nothing: a measured
	// carve-out of a bit not sent holds each.
	Omitted []engine.Rule
	// Beyond are permits no reply sends: beyond the level's ceiling, or, in
	// the fail-closed reply, not proven. The device refuses what port49 would
	// permit there, never the reverse (spec §8, "never exceeding the level's
	// ceiling").
	Beyond []engine.Rule
	// ConfigurationDropped are the level's bits that enter configuration
	// mode, left out because the composition is not a grant of every command
	// with no deny and the rest proved sound without them (decision 26).
	ConfigurationDropped []string
	// FailClosed is why the reply is ShapeFailClosed, one of the Fail*
	// constants; empty otherwise. Refusal says it for the report.
	FailClosed string
	Refusal    *Refusal
	model      *model
}

// Refusal is why a composition cannot be told faithfully, named for `policy
// test` and `policy diff` (spec §8, "Refused shape"; "Generator constraints"
// 5). It never leaves the generator as an error: the composition gets the
// fail-closed reply (decision 26).
type Refusal struct {
	Category string
	Why      string
	// Attribute and Value are the reply attribute past RFC 8907's length,
	// where that is the refusal. Class is the login class that would carry
	// the value on the device instead, the workaround the report prints
	// beside it (spec §8, "CI MUST report when a grant crosses that line"),
	// and is set only for deny-commands: a class allow-commands runs for
	// every session in the class, past each subject's own denies (L11), so
	// an allow is never moved there.
	Attribute, Value, Class string
}

func (r *Refusal) Error() string { return r.Why }

func refuse(category, format string, args ...any) error {
	return &Refusal{Category: category, Why: fmt.Sprintf(format, args...)}
}

// Project renders one composition (spec §8; §13 decisions 22 and 26). It
// proves the reply sound before it returns it: every command the device would
// run under it is one port49 permits. A composition neither shape carries
// gets the fail-closed reply, which is proven the same way. The error is a
// defect only: a program that does not compile.
func Project(in Input) (Result, error) {
	g := newGenerator(in, in.Bits)
	res, err := g.render()
	var r *Refusal
	if err == nil {
		m, merr := g.model(res)
		if merr != nil {
			return Result{}, merr
		}
		res.model = m
		v, bad := m.unsound()
		if !bad {
			return res, nil
		}
		// The checks are a proof; this is its witness. A vector here is a
		// generator defect, and the subject gets the fail-closed reply.
		err = refuse(FailUnsound, "on %s the reply would let the device run %q, which port49 denies; this is a "+
			"projection defect", in.Platform, strings.Join(v, " "))
	}
	if !errors.As(err, &r) {
		return Result{}, err
	}
	return g.failClosed(r)
}

type generator struct {
	in              Input
	permits, denies []engine.Rule
	ceiling         []string
}

// newGenerator splits the rules, and adds a deny for each baseline reach rule
// no permit holds: the baseline runs it for every session, so without the
// deny the device would run what port49 refuses.
func newGenerator(in Input, ceiling []string) generator {
	g := generator{in: in, ceiling: in.Dialect.ExpandBits(ceiling)}
	for _, r := range in.Rules {
		if r.Verdict == engine.Permit {
			g.permits = append(g.permits, r)
		} else {
			g.denies = append(g.denies, r)
		}
	}
	for _, b := range in.Dialect.Bits[platform.BaselineBit] {
		held := func(q engine.Rule) bool { return g.contains(q.Rule, b) }
		if !slices.ContainsFunc(g.permits, held) && !slices.ContainsFunc(g.denies, held) {
			g.denies = append(g.denies, engine.Rule{Verdict: engine.Deny, Rule: b, Role: platform.BaselineBit})
		}
	}
	return g
}

func (g generator) contains(outer, inner string) bool {
	ok, err := engine.Contains(outer, inner, g.in.Classes)
	return err == nil && ok
}

func (g generator) mayMeet(permit, deny string) bool {
	ok, err := engine.MayMeet(permit, deny, g.in.Classes, g.in.Normalize)
	return err != nil || ok
}

func (g generator) dominates(permit, deny string) bool {
	ok, err := engine.AlwaysDominates(permit, deny, g.in.Classes, g.in.Normalize)
	return err == nil && ok
}

// render is the capability or narrow shape, and, under user_permissions,
// the same without the bits that enter configuration mode where those are
// what refused it (decision 26, for spec §13's decided item 6).
func (g generator) render() (Result, error) {
	for _, r := range g.in.Rules {
		if g.in.Secret != nil && g.in.Secret(r.Rule) {
			return Result{}, refuse(FailSecretRule, "role %q has a rule whose text carries a value redaction "+
				"hides, and %s's session reply is its rules, logged whole (spec §5.8): write the rule without it",
				r.Role, g.in.Platform)
		}
	}
	res, err := g.shape()
	var r *Refusal
	if !errors.As(err, &r) || r.Category != FailConfigurationMode ||
		g.in.Dialect.BitDelivery != platform.BitDeliveryUserPermissions {
		return res, err
	}
	lower := g.plain(g.ceiling)
	if len(lower) == len(g.ceiling) {
		return res, err
	}
	h := newGenerator(g.in, lower)
	res2, err2 := h.shape()
	if err2 != nil {
		return res, err
	}
	res2.ConfigurationDropped = slices.DeleteFunc(slices.Clone(g.ceiling), func(b string) bool {
		return slices.Contains(lower, b)
	})
	return res2, nil
}

func (g generator) shape() (Result, error) {
	res, err := g.capability()
	if errors.As(err, new(*narrowOnly)) {
		res, err = g.narrow()
	}
	if err != nil {
		return Result{}, err
	}
	if err := g.configuration(res); err != nil {
		return Result{}, err
	}
	if err := g.attributes(&res); err != nil {
		return Result{}, err
	}
	return res, nil
}

// narrowOnly is capability's answer where only the narrow shape can carry
// the grant.
type narrowOnly struct{ why string }

func (n *narrowOnly) Error() string { return n.why }

// declared is the level's ceiling bits as the adapter writes them, sorted:
// what a template's class carries, `all` unexpanded.
func (g generator) declared() []string {
	out := slices.Clone(g.in.Bits)
	slices.Sort(out)
	return slices.Compact(out)
}

// held is the bits s, `all` read as every bit, and the baseline where the
// adapter declares one: what a session sent s holds.
func (g generator) held(s []string) []string {
	out := g.in.Dialect.ExpandBits(s)
	if _, ok := g.in.Dialect.Bits[platform.BaselineBit]; ok {
		out = append(out, platform.BaselineBit)
	}
	return out
}

// reach is every reach rule of bits.
func (g generator) reach(bits []string) []string {
	var out []string
	for _, b := range bits {
		out = append(out, g.in.Dialect.Bits[b]...)
	}
	return out
}

// carves is every measured carve-out of a declared bit not in held: the
// commands a session without that bit is refused whatever else it holds.
func (g generator) carves(held []string) []string {
	var out []string
	for _, b := range sortedKeys(g.in.Dialect.CarveOuts) {
		if !slices.Contains(held, b) {
			out = append(out, g.in.Dialect.CarveOuts[b]...)
		}
	}
	return out
}

// entersConfiguration reports whether bit b's reach holds `configure`.
func (g generator) entersConfiguration(b string) bool {
	return slices.ContainsFunc(g.in.Dialect.Bits[b], func(r string) bool { return g.contains(r, "configure") })
}

// plain is bits without the ones that enter configuration mode.
func (g generator) plain(bits []string) []string {
	return slices.DeleteFunc(slices.Clone(bits), g.entersConfiguration)
}

// covered reports whether every command rule r matches is decided by a
// rule of the grant: held by one permit or one deny. Under bits reaching r,
// such a command is then permitted by port49, or refused on the device by
// the deny sent for it.
func (g generator) covered(r string) bool {
	for _, q := range slices.Concat(g.permits, g.denies) {
		if g.contains(q.Rule, r) {
			return true
		}
	}
	return false
}

// usable reports whether every command bit b reaches is covered.
func (g generator) usable(b string) bool {
	for _, r := range g.in.Dialect.Bits[b] {
		if !g.covered(r) {
			return false
		}
	}
	return true
}

// aligned reports whether every command bit b reaches is denied: the bit
// adds nothing, and is dropped rather than a deny sent against it.
func (g generator) aligned(b string) bool {
	for _, r := range g.in.Dialect.Bits[b] {
		if !slices.ContainsFunc(g.denies, func(d engine.Rule) bool { return g.contains(d.Rule, r) }) {
			return false
		}
	}
	return true
}

// within reports whether the level's ceiling bits reach every command
// permit p matches, no carve-out of a bit outside the ceiling meeting it: a
// permit beyond them is never sent, since on the device an allow runs
// whatever the bits say (spec §8, "never exceeding the level's ceiling").
func (g generator) within(p string) bool { return g.reaches(p, g.ceiling, false) }

// byBits reports whether the bits s run every command of p that port49 does
// not deny outright: some reach rule of s holds p, and each carve-out of a
// bit outside s that meets p is held by a deny, so what it carves port49
// refuses too.
func (g generator) byBits(p string, s []string) bool { return g.reaches(p, s, true) }

// reaches reports whether some reach rule of the bits s holds p and no
// carve-out of a bit outside s meets it; with denied, a carve-out a deny
// holds may.
func (g generator) reaches(p string, s []string, denied bool) bool {
	held := g.held(s)
	if !slices.ContainsFunc(g.reach(held), func(r string) bool { return g.contains(r, p) }) {
		return false
	}
	for _, c := range g.carves(held) {
		if g.mayMeet(p, c) &&
			!(denied && slices.ContainsFunc(g.denies, func(d engine.Rule) bool { return g.contains(d.Rule, c) })) {
			return false
		}
	}
	return true
}

// allowable is the deny sending p as an allow would void, if any: on the
// device a matching allow beats every deny, so p goes out only where it
// dominates each deny it meets (spec §5.4, §8). A baseline deny is none of
// port49's: it holds what the baseline runs and no rule decides, so an allow
// running only what p matches runs nothing port49 denies beneath it.
func (g generator) allowable(p string) (engine.Rule, bool) {
	for _, d := range g.denies {
		if d.Role == platform.BaselineBit {
			continue
		}
		if g.mayMeet(p, d.Rule) && !g.dominates(p, d.Rule) {
			return d, false
		}
	}
	return engine.Rule{}, true
}

// refusedShape is spec §8's refused shape, naming the grant's two rules and
// the platform.
func (g generator) refusedShape(p, d engine.Rule) error {
	return refuse(FailRefusedShape, "on %s, permit %q (role %q) needs an allow-commands the device would let "+
		"beat deny %q (role %q), which sits beneath it: Junos regex cannot write everything under a permit except "+
		"a deny (spec §8, \"Refused shape\")", g.in.Platform, p.Rule, p.Role, d.Rule, d.Role)
}

// capability is the capability shape, or narrowOnly where it cannot carry
// the grant.
func (g generator) capability() (Result, error) {
	d := g.in.Dialect
	var bits []string
	if d.BitDelivery == platform.BitDeliveryLocalUserName {
		// The template's class carries every bit of the level: each has to
		// be covered, or the class lets the device run what port49 denies.
		for _, b := range g.ceiling {
			if !g.usable(b) {
				return Result{}, &narrowOnly{fmt.Sprintf("the template's bit %s reaches commands no rule decides", b)}
			}
		}
		bits = g.declared()
	} else {
		for _, b := range g.ceiling {
			if g.usable(b) && !g.aligned(b) {
				bits = append(bits, b)
			}
		}
		// `all` holds every bit, so it is sent alone: the smallest set.
		if slices.Contains(bits, "all") {
			bits = []string{"all"}
		}
	}
	if len(bits) == 0 {
		// No bit's reach is decided by the grant whole and permitted in part:
		// the permits are narrower than every bit (spec §8, "Narrow shape").
		return Result{}, &narrowOnly{"no bit of the ceiling is the grant's whole"}
	}
	res := Result{Shape: ShapeCapability, Bits: bits, Template: g.in.Template}
	for _, p := range g.permits {
		// A permit the bits carry sends nothing; one that needs an allow is
		// sent only within the level's ceiling.
		covered := g.byBits(p.Rule, bits)
		under := slices.ContainsFunc(g.denies, func(dn engine.Rule) bool {
			return g.mayMeet(p.Rule, dn.Rule) && g.dominates(p.Rule, dn.Rule)
		})
		if covered && !under {
			continue
		}
		if !g.within(p.Rule) {
			res.Beyond = append(res.Beyond, p)
			continue
		}
		if dn, ok := g.allowable(p.Rule); !ok {
			return Result{}, g.refusedShape(p, dn)
		}
		res.Allows = append(res.Allows, p)
	}
	for _, dn := range g.denies {
		if g.omittable(dn, bits, res.Allows) {
			res.Omitted = append(res.Omitted, dn)
			continue
		}
		res.Denies = append(res.Denies, dn)
	}
	if len(res.Denies) > 0 && !g.in.Facts.DenyMatchesExpanded {
		return Result{}, &narrowOnly{"a deny narrower than every command is walked past by abbreviating it"}
	}
	return res, nil
}

// omittable reports whether the bits already refuse every command deny dn
// matches, so nothing is sent for it (spec §8, "drops the bit instead of
// emitting a regex"): a measured carve-out of a bit not sent holds dn, and no
// allow meets it. Only a carve-out licenses this: under the union, a bit not
// sent refuses nothing another bit reaches.
func (g generator) omittable(dn engine.Rule, bits []string, allows []engine.Rule) bool {
	for _, a := range allows {
		if g.mayMeet(a.Rule, dn.Rule) {
			return false
		}
	}
	return slices.ContainsFunc(g.carves(g.held(bits)), func(c string) bool { return g.contains(c, dn.Rule) })
}

// configuration refuses a reply that enters configuration mode for a grant
// that is not everything — a bit whose reach holds `configure`, or an allow
// that meets it: a statement typed there is governed by the class's
// configuration permissions, which no deny-commands or allow-commands
// reaches (spec §8; §15 L12), so port49 could deny a statement the device
// then runs. Only a grant that permits every command and denies none is
// carried faithfully there.
func (g generator) configuration(res Result) error {
	what := ""
	for _, b := range g.held(res.Bits) {
		if g.entersConfiguration(b) {
			what = "bit " + b
			break
		}
	}
	for _, a := range res.Allows {
		if what == "" && g.mayMeet(a.Rule, "configure **") {
			what = fmt.Sprintf("allow %q", a.Rule)
		}
	}
	if what == "" {
		return nil
	}
	everything := slices.ContainsFunc(g.permits, func(p engine.Rule) bool { return g.contains(p.Rule, "**") })
	if everything && len(g.denies) == 0 {
		return nil
	}
	grant := "permits less than every command"
	if len(g.denies) > 0 {
		grant = fmt.Sprintf("denies %q (role %q)", g.denies[0].Rule, g.denies[0].Role)
	}
	return refuse(FailConfigurationMode, "on %s the reply's %s enters configuration mode, where a statement is "+
		"governed by the class's configuration permissions and no command regex reaches it (spec §8, §15 L12), "+
		"and the composition %s: port49 would deny what the device runs there", g.in.Platform, what, grant)
}

// narrow is the narrow shape: every permit the ceiling reaches as one allow
// alternation over `deny-commands .*`, under the smallest set of ceiling bits
// that reach them — the template's, where the delivery is one.
func (g generator) narrow() (Result, error) {
	res := Result{Shape: ShapeNarrow, Template: g.in.Template}
	for _, p := range g.permits {
		if !g.within(p.Rule) {
			res.Beyond = append(res.Beyond, p)
			continue
		}
		if dn, ok := g.allowable(p.Rule); !ok {
			return Result{}, g.refusedShape(p, dn)
		}
		res.Allows = append(res.Allows, p)
	}
	if g.in.Dialect.BitDelivery == platform.BitDeliveryLocalUserName {
		res.Bits = g.declared()
		return res, nil
	}
	res.Bits = g.cover(g.ceiling, res.Allows)
	return res, nil
}

// maxCover bounds cover's exact search, in candidate subsets; past it the
// cover is greedy.
const maxCover = 1 << 16

// cover is the smallest set of the bits from that reach every allow: fewest
// bits, then fewest that enter configuration mode, then first in name order
// (I11: `all` reaches everything, and a narrow admin grant under it would
// be refused for entering configuration mode). Bits reaching the same
// allows are one candidate, the preferred of them.
func (g generator) cover(from []string, allows []engine.Rule) []string {
	if len(allows) == 0 {
		return nil
	}
	if len(allows) > 63 {
		allows = allows[:63] // more never fit in one attribute
	}
	type cand struct {
		bit    string
		mask   uint64
		config bool
	}
	var cands []cand
	full := uint64(1)<<len(allows) - 1
	for _, b := range from {
		var m uint64
		for i, p := range allows {
			if slices.ContainsFunc(g.in.Dialect.Bits[b], func(r string) bool { return g.contains(r, p.Rule) }) {
				m |= 1 << i
			}
		}
		if m == 0 {
			continue
		}
		c := cand{b, m, g.entersConfiguration(b)}
		if k := slices.IndexFunc(cands, func(o cand) bool { return o.mask == m }); k >= 0 {
			if o := cands[k]; o.config && !c.config || o.config == c.config && c.bit < o.bit {
				cands[k] = c
			}
			continue
		}
		cands = append(cands, c)
	}
	names := func(set uint64) []string {
		var out []string
		for i, c := range cands {
			if set&(1<<i) != 0 {
				out = append(out, c.bit)
			}
		}
		slices.Sort(out)
		return out
	}
	configs := func(set uint64) int {
		n := 0
		for i, c := range cands {
			if set&(1<<i) != 0 && c.config {
				n++
			}
		}
		return n
	}
	better := func(a, b uint64) bool {
		if na, nb := bits.OnesCount64(a), bits.OnesCount64(b); na != nb {
			return na < nb
		}
		if ca, cb := configs(a), configs(b); ca != cb {
			return ca < cb
		}
		return slices.Compare(names(a), names(b)) < 0
	}
	if len(cands) < 64 && uint64(1)<<len(cands) <= maxCover {
		best, found := uint64(0), false
		for set := uint64(1); set < uint64(1)<<len(cands); set++ {
			var m uint64
			for i, c := range cands {
				if set&(1<<i) != 0 {
					m |= c.mask
				}
			}
			if m == full && (!found || better(set, best)) {
				best, found = set, true
			}
		}
		if found {
			return names(best)
		}
		return nil // within() said some ceiling bit reaches each; unreachable
	}
	// Greedy: the candidate reaching the most allows not yet reached, one
	// that does not enter configuration mode first, then name order.
	var set, got uint64
	for got != full {
		pick := -1
		for i, c := range cands {
			if set&(1<<i) != 0 {
				continue
			}
			n := bits.OnesCount64(c.mask &^ got)
			if n == 0 {
				continue
			}
			if pick < 0 {
				pick = i
				continue
			}
			p := cands[pick]
			pn := bits.OnesCount64(p.mask &^ got)
			if n > pn || n == pn && (p.config && !c.config || p.config == c.config && c.bit < p.bit) {
				pick = i
			}
		}
		if pick < 0 {
			break
		}
		set |= 1 << pick
		got |= cands[pick].mask
	}
	return names(set)
}

// failClosed is the reply for a composition neither shape carries (spec §13
// decision 26): `deny-commands` `.*`, an allow for each permit that is
// within the level's ceiling bits that do not enter configuration mode,
// dominates every deny it meets, does not meet `configure`, and can be
// written; under user_permissions the smallest of those bits that reach the
// allows, and no template under local_user_name, so the session lands in the
// bitless p49-remote. Where the allows cannot be sent whole, none is.
func (g generator) failClosed(r *Refusal) (Result, error) {
	res := Result{Shape: ShapeFailClosed, FailClosed: r.Category, Refusal: r}
	h := newGenerator(g.in, g.plain(g.ceiling))
	for _, p := range h.permits {
		_, ok := h.allowable(p.Rule)
		secret := g.in.Secret != nil && g.in.Secret(p.Rule)
		_, werr := ruleERE(p.Rule, g.in.Classes, false, g.in.Facts)
		if secret || werr != nil || !ok || !h.within(p.Rule) || h.mayMeet(p.Rule, "configure **") {
			res.Beyond = append(res.Beyond, p)
			continue
		}
		res.Allows = append(res.Allows, p)
	}
	send := func() (Result, error) {
		out := res
		out.Attributes = nil
		if g.in.Dialect.BitDelivery == platform.BitDeliveryUserPermissions {
			out.Bits = h.cover(h.ceiling, out.Allows)
		}
		if len(out.Bits) > 0 {
			out.Attributes = append(out.Attributes, "user-permissions="+strings.Join(out.Bits, " "))
		}
		out.Attributes = append(out.Attributes, "deny-commands=^.*$")
		allow, err := h.alternation(out.Allows, false)
		if err != nil {
			return out, err
		}
		if allow != "" {
			out.Attributes = append(out.Attributes, "allow-commands=^"+allow+"$")
		}
		for _, a := range out.Attributes {
			if err := engine.CheckAttribute(a); err != nil {
				return out, err
			}
		}
		m, err := h.model(out)
		if err != nil {
			return Result{}, err
		}
		out.model = m
		if _, bad := m.unsound(); bad {
			return out, errors.New("unsound")
		}
		return out, nil
	}
	out, err := send()
	if err != nil && out.Shape != "" {
		// The allows cannot go out whole: none does, and the reply is
		// `deny-commands` `.*` alone.
		res.Beyond = append(res.Beyond, res.Allows...)
		res.Allows = nil
		out, err = send()
	}
	return out, err
}

// attributes renders res as the reply: each attribute once, mandatory, within
// RFC 8907's 255 bytes (spec §8, "Generator constraints").
func (g generator) attributes(res *Result) error {
	d := g.in.Dialect
	switch {
	case d.BitDelivery == platform.BitDeliveryLocalUserName && res.Template != "":
		res.Attributes = append(res.Attributes, "local-user-name="+res.Template)
	case d.BitDelivery == platform.BitDeliveryUserPermissions && len(res.Bits) > 0:
		res.Attributes = append(res.Attributes, "user-permissions="+strings.Join(res.Bits, " "))
	}
	deny, err := g.alternation(res.Denies, true)
	if err != nil {
		return err
	}
	if res.Shape == ShapeNarrow {
		deny = ".*"
	}
	if deny != "" {
		res.Attributes = append(res.Attributes, "deny-commands=^"+deny+"$")
	}
	allow, err := g.alternation(res.Allows, false)
	if err != nil {
		return err
	}
	if allow != "" {
		res.Attributes = append(res.Attributes, "allow-commands=^"+allow+"$")
	}
	for _, a := range res.Attributes {
		if err := engine.CheckAttribute(a); err != nil {
			i := strings.IndexByte(a, '=')
			r := &Refusal{Category: FailOverflow, Attribute: a[:i], Value: a[i+1:],
				Why: fmt.Sprintf("on %s the reply's %s is %d bytes, and RFC 8907 carries at most %d in one attribute; "+
					"a device sent part of a deny is sent none of it (spec §8, \"Generator constraints\")",
					g.in.Platform, engine.AttributeName(a), len(a), engine.MaxAttribute)}
			if r.Attribute == "deny-commands" {
				r.Class = res.Template
				if r.Class == "" {
					r.Class = platform.RemoteClass
				}
				r.Why += ": move the denies into the template's class on the device (port49 platform export " +
					"--classes), where they bind every subject at that template, or narrow the grant"
			} else {
				r.Why += ": narrow the grant; an allow is never moved into a class, where it would run for every " +
					"subject past their own denies"
			}
			return r
		}
	}
	return nil
}

// alternation is rules as one group, `(a|b)`, or one rule bare; empty for
// none.
func (g generator) alternation(rules []engine.Rule, deny bool) (string, error) {
	var alts []string
	for _, r := range rules {
		e, err := ruleERE(r.Rule, g.in.Classes, deny, g.in.Facts)
		if err != nil {
			return "", refuse(FailUnwritable, "on %s, %s %q (role %q) cannot be written as the device's regex: %v "+
				"(spec §8, §15 L9)", g.in.Platform, r.Verdict, r.Rule, r.Role, err)
		}
		if !slices.Contains(alts, e) {
			alts = append(alts, e)
		}
	}
	switch len(alts) {
	case 0:
		return "", nil
	case 1:
		return alts[0], nil
	}
	return "(" + strings.Join(alts, "|") + ")", nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
