package projection

import (
	"errors"
	"fmt"
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
	// FailArgumentDeny is a deny that meets a permit and names a word the
	// keyword tree does not prove a keyword: Junos never matches it
	// (decision 27).
	FailArgumentDeny = "argument_deny"
	// FailConfigurationDeny is a deny that meets a permit, names a
	// configuration statement, and is no operational command the keyword
	// tree proves: deny-commands never reaches configuration mode, and
	// deny-configuration is not measured (decision 27).
	FailConfigurationDeny = "configuration_deny"
)

// JunosFacts are what the Junos images were measured doing with a command
// regex (spec §15, L9). CaseSensitive is false: the CLI refuses a keyword
// typed in upper case itself (tests/lab/results/L9-juniper_*.md), so a deny
// spelled in lower case holds every spelling that runs. DenyMatchesExpanded
// is true for keywords, the only words a rule reaches the wire with (decision
// 27): on both images every abbreviation of a keyword deny, at several
// lengths and depths, piped and ambiguous, was refused or not run under the
// deny, the control ran every unambiguous one, and the rendered shape was
// enforced (tests/lab/results/L9-abbreviations-juniper_*.md). DenyBindsRPCs
// is false: a projected CLI session ran `xml-mode netconf need-trailer` and a
// native RPC past its wire deny, and `op url`, on both images, its RPC reach
// bounded by the bits alone (tests/lab/results/L26c-juniper_*.md).
var JunosFacts = Facts{CaseSensitive: false, DenyMatchesExpanded: true, DenyBindsRPCs: false}

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
	// Hidden is every value a redaction hides anywhere in the policy's rules:
	// a refusal or an unsent allow's why that quotes a rule's words prints
	// each redacted, since %q escapes a `"` or `\` in one past any writer's
	// pass (platform.QuoteShown; spec §5.8).
	Hidden []string
	Facts  Facts
	// Keywords is the platform's keyword tree, from the policy's pinned set
	// (platform.KeywordsFor): a rule reaches the wire only where it proves
	// the rule's words keywords. Nil proves nothing.
	Keywords *platform.Keywords
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
	// Unreached are allows sent under bits that do not reach them, carve-outs
	// counted: whether a Junos allow runs a command its bits do not reach is
	// unmeasured, so the device may refuse what port49 permits there, and CI
	// says so (Narrower).
	Unreached []engine.Rule
	// ConfigurationDropped are the level's bits that enter configuration
	// mode, left out because the composition is not a grant of every command
	// with no deny and the rest proved sound without them (decision 26).
	ConfigurationDropped []string
	// Unsent are permits whose allow the device would not match as port49
	// does, left off the wire: the device refuses what port49 permits there,
	// and `policy test` warns (projection_argument_allow; decision 27).
	Unsent []Unsent
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

// Unsent is a permit left off the wire, and why.
type Unsent struct {
	Rule engine.Rule
	Why  string
}

// Clone is r with every slice and the Refusal copied, so a caller may sort,
// filter or append to its copy without touching another's: a policy hands
// one composition's Result to every device it lands on. The model is shared;
// nothing writes it after Project returns.
func (r Result) Clone() Result {
	r.Bits, r.Attributes = slices.Clone(r.Bits), slices.Clone(r.Attributes)
	r.Denies, r.Allows, r.Omitted = slices.Clone(r.Denies), slices.Clone(r.Allows), slices.Clone(r.Omitted)
	r.Beyond, r.Unreached = slices.Clone(r.Beyond), slices.Clone(r.Unreached)
	r.ConfigurationDropped, r.Unsent = slices.Clone(r.ConfigurationDropped), slices.Clone(r.Unsent)
	if r.Refusal != nil {
		rf := *r.Refusal
		r.Refusal = &rf
	}
	return r
}

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
		err = refuse(FailUnsound, "on %s the reply would let the device run %s, which port49 denies; this is a "+
			"projection defect", in.Platform, platform.QuoteShown(in.Hidden, strings.Join(v, " ")))
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

// quote is text derived from a rule as a refusal or a why quotes it: each
// value a redaction hides redacted first (platform.QuoteShown).
func (g generator) quote(s string) string { return platform.QuoteShown(g.in.Hidden, s) }

// shown is text derived from a rule as a refusal prints it between
// backticks, each value a redaction hides redacted (platform.RedactValues).
func (g generator) shown(s string) string { return platform.RedactValues(g.in.Hidden, s) }

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
	// A deny that meets a permit is one port49 needs the device to enforce,
	// under an allow or under bits; one naming an argument never is (decision
	// 27). A deny no permit meets is port49's no_rule_matched either way.
	for _, d := range g.denies {
		if d.Role == platform.BaselineBit || g.denyProvable(d.Rule) {
			continue
		}
		if slices.ContainsFunc(g.permits, func(p engine.Rule) bool { return g.mayMeet(p.Rule, d.Rule) }) {
			return Result{}, g.denyRefusal(d)
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
		// Without those bits something else stops it: that is what the
		// operator has to change.
		var r2 *Refusal
		if errors.As(err2, &r2) && r2.Category != FailConfigurationMode {
			return Result{}, err2
		}
		return res, err
	}
	res2.ConfigurationDropped = slices.DeleteFunc(slices.Clone(g.ceiling), func(b string) bool {
		return slices.Contains(lower, b)
	})
	return res2, nil
}

// shape is the capability shape, or the narrow one where only it can carry
// the grant, or where the capability shape's deny-commands is past the
// budget: the narrow shape's `.*` holds every deny in four bytes.
func (g generator) shape() (Result, error) {
	res, err := g.capability()
	var no *narrowOnly
	if errors.As(err, &no) {
		n, nerr := g.finish(g.narrow())
		// Where the capability shape was ruled out by a refusal of its own,
		// and the narrow shape cannot carry the grant either, the report says
		// both: the narrow shape's first, the one the grant can change — unless
		// it is its bits entering configuration mode, which render recovers
		// from, and which is passed on as it is. Why a deny binds no RPC is
		// said once.
		var nr, cr *Refusal
		if nerr != nil && errors.As(no.refusal, &cr) && errors.As(nerr, &nr) && !g.recoverable(nr) {
			both := *nr
			why := cr.Why
			if strings.Contains(nr.Why, g.rpcWhy()) {
				why = strings.Replace(why, ": "+g.rpcWhy(), "", 1)
			}
			both.Why += "; and without `deny-commands .*`, " + why
			return Result{}, &both
		}
		// Nor does a narrow shape that carries the grant only by leaving off a
		// permit the capability shape carried, or that allows none of it:
		// that is the refusal too, not a quiet shortfall.
		if nerr == nil && no.refusal != nil && (len(n.Allows) == 0 && len(g.permits) > 0 ||
			slices.ContainsFunc(n.Beyond, func(p engine.Rule) bool { return !slices.Contains(no.beyond, p) })) {
			return Result{}, no.refusal
		}
		return n, nerr
	}
	res, err = g.finish(res, err)
	var r *Refusal
	if errors.As(err, &r) && r.Category == FailOverflow && r.Attribute == "deny-commands" {
		n, nerr := g.finish(g.narrow())
		if nerr == nil {
			return n, nil
		}
		// The narrow shape's bits entering configuration mode is what render
		// can recover from, by dropping them: say that, not the overflow.
		var nr *Refusal
		if errors.As(nerr, &nr) && g.recoverable(nr) {
			return Result{}, nerr
		}
	}
	return res, err
}

// recoverable reports whether render recovers from r by dropping the bits
// that enter configuration mode, which it does only under user_permissions:
// a template's class carries every bit of the level.
func (g generator) recoverable(r *Refusal) bool {
	return r.Category == FailConfigurationMode && g.in.Dialect.BitDelivery == platform.BitDeliveryUserPermissions
}

// finish guards a rendered shape and writes its attributes.
func (g generator) finish(res Result, err error) (Result, error) {
	if err != nil {
		return Result{}, err
	}
	if err := g.configuration(res); err != nil {
		return Result{}, err
	}
	if err := g.attributes(&res); err != nil {
		return Result{}, err
	}
	res.Unreached = g.unreached(res)
	return res, nil
}

// narrowOnly is capability's answer where only the narrow shape can carry
// the grant; refusal, where set, is why the capability shape cannot, for
// the report where the narrow shape cannot either.
type narrowOnly struct {
	why     string
	refusal error
	beyond  []engine.Rule // the capability shape's Beyond, where refusal is set
}

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

// entersConfiguration reports whether bit b's reach meets a command that
// enters configuration mode (configurationEntries), a variant such as
// `configure private` or `edit exclusive` included.
func (g generator) entersConfiguration(b string) bool {
	return slices.ContainsFunc(g.in.Dialect.Bits[b], g.meetsConfiguration)
}

// configurationEntries are the operational commands that enter configuration
// mode: `configure` and its variants (`configure private`, `exclusive`,
// `batch` begin with it), and `edit`, its alias (plan 5b pre-flight B-M1).
var configurationEntries = []string{"configure", "edit"}

// meetsConfiguration reports whether rule meets a command that enters
// configuration mode.
func (g generator) meetsConfiguration(rule string) bool {
	return slices.ContainsFunc(configurationEntries, func(e string) bool { return g.mayMeet(rule, e+" **") })
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
	return refuse(FailRefusedShape, "on %s, permit %s (role %q) needs an allow-commands the device would let "+
		"beat deny %s (role %q), which sits beneath it: Junos regex cannot write everything under a permit except "+
		"a deny (spec §8, \"Refused shape\")", g.in.Platform, g.quote(p.Rule), p.Role, g.quote(d.Rule), d.Role)
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
				return Result{}, &narrowOnly{why: fmt.Sprintf("the template's bit %s reaches commands no rule decides", b)}
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
		return Result{}, &narrowOnly{why: "no bit of the ceiling is the grant's whole"}
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
		if why := g.unsendableAllow(p.Rule); why != "" {
			res.Unsent = append(res.Unsent, Unsent{Rule: p, Why: why})
			continue
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
		return Result{}, &narrowOnly{why: "a deny narrower than every command is walked past by abbreviating it"}
	}
	for _, dn := range res.Denies {
		if !g.denyProvable(dn.Rule) {
			// A deny the device would not enforce, of a command no permit
			// meets: the narrow shape's `.*` holds it instead.
			return Result{}, &narrowOnly{why: "a deny under the bits names an argument"}
		}
	}
	if !g.in.Facts.DenyBindsRPCs {
		for _, dn := range res.Denies {
			if b, ok := g.beneath(dn.Rule, bits); ok {
				// The reply's own configuration refusal comes first where
				// render recovers from it by dropping those bits, which may
				// leave the deny beneath none.
				var cr *Refusal
				if err := g.configuration(res); errors.As(err, &cr) && g.recoverable(cr) {
					return Result{}, err
				}
				return Result{}, &narrowOnly{why: "a deny beneath a sent bit guards the CLI alone",
					refusal: g.rpcReach(dn, b), beyond: res.Beyond}
			}
		}
	}
	return res, nil
}

// beneath is the first bit a session sent bits holds whose reach meets rule,
// a sent bit before the baseline: a deny of rule is the only guard there.
func (g generator) beneath(rule string, bits []string) (string, bool) {
	held := g.held(bits)
	slices.SortFunc(held, func(a, b string) int {
		if (a == platform.BaselineBit) != (b == platform.BaselineBit) {
			if a == platform.BaselineBit {
				return 1
			}
			return -1
		}
		return strings.Compare(a, b)
	})
	for _, b := range held {
		if slices.ContainsFunc(g.in.Dialect.Bits[b], func(r string) bool { return g.mayMeet(rule, r) }) {
			return b, true
		}
	}
	return "", false
}

// rpcEntries are the operational commands a Junos CLI session reaches RPCs
// through, with its bits' whole reach and no wire deny applied
// (tests/lab/results/L26c-juniper_*.md): `xml-mode` (hidden, so no keyword
// tree lists it) and `op`, whose `url` runs a script.
var rpcEntries = []string{"xml-mode", "op"}

// opensRPC reports whether an allow of rule would run an RPC entry point.
func (g generator) opensRPC(rule string) bool {
	return slices.ContainsFunc(rpcEntries, func(e string) bool { return g.mayMeet(rule, e+" **") })
}

// rpcWhy is why a wire deny is no boundary on a device where it binds no RPC.
func (g generator) rpcWhy() string {
	return fmt.Sprintf("on %s a wire deny binds the CLI only: a CLI session reaches RPCs through `xml-mode` and "+
		"`op url` with its bits' whole reach, and no deny applies there (tests/lab/results/L26c-juniper_*.md; spec "+
		"§8), so the composition is CLI-only safe and port49 fails it closed", g.in.Platform)
}

// rpcReach is the refusal of a deny that is the only guard beneath bit b.
func (g generator) rpcReach(dn engine.Rule, b string) error {
	what := "bit " + b + ", which the reply sends"
	if b == platform.BaselineBit {
		what = "the baseline, which every session runs and no rule of the grant decides there"
	}
	return refuse(FailRefusedShape, "deny %s (role %q) is the only guard beneath %s: %s; permit what it reaches "+
		"whole, or narrow the grant so that no sent bit reaches the deny", g.quote(dn.Rule), dn.Role, what, g.rpcWhy())
}

// omittable reports whether the bits already refuse every command deny dn
// matches, so nothing is sent for it (spec §8, "drops the bit instead of
// emitting a regex"): a measured carve-out of a bit not sent holds dn, and no
// allow meets it. Only a carve-out licenses this: under the union, a bit not
// sent refuses nothing another bit reaches. Where a deny binds no RPC, only
// a carve-out measured over RPC does (rpcCarves).
//
// Contains reads dn as received, where port49 reads a deny wider. Where the
// platform neither abbreviates nor splits a name, the one widening is
// trimming each argument, which the carve-out, read as a deny, takes alike;
// anywhere else the deny is sent.
func (g generator) omittable(dn engine.Rule, bits []string, allows []engine.Rule) bool {
	if n := g.in.Normalize; !n.SessionOnly || n.SplitsInterfaceNames {
		return false
	}
	for _, a := range allows {
		if g.mayMeet(a.Rule, dn.Rule) {
			return false
		}
	}
	return slices.ContainsFunc(g.carves(g.held(bits)), func(c string) bool {
		return g.contains(c, dn.Rule) && (g.in.Facts.DenyBindsRPCs || slices.Contains(rpcCarves, c))
	})
}

// rpcCarves are the carve-outs measured holding over RPC too: `view` without
// `view-configuration` got an empty `<configuration>` from a projected CLI
// session's RPCs (tests/lab/results/L26c-juniper_*.md). Where a wire deny
// binds no RPC, a deny is left off the wire only through one of these: any
// other carve-out is measured on the CLI at most, so the deny is sent, and a
// deny beneath a sent bit fails closed.
var rpcCarves = []string{"show configuration **"}

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
		if what == "" && g.meetsConfiguration(a.Rule) {
			what = "allow " + g.quote(a.Rule)
		}
	}
	if what == "" {
		return nil
	}
	everything := slices.ContainsFunc(g.permits, func(p engine.Rule) bool { return g.contains(p.Rule, "**") })
	if everything && len(g.denies) == 0 {
		return nil
	}
	// A baseline deny is none the operator wrote: a grant with only those
	// permits less than every command.
	grant := "permits less than every command"
	if i := slices.IndexFunc(g.denies, func(d engine.Rule) bool { return d.Role != platform.BaselineBit }); i >= 0 {
		grant = fmt.Sprintf("denies %s (role %q)", g.quote(g.denies[i].Rule), g.denies[i].Role)
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
		if why := g.unsendableAllow(p.Rule); why != "" {
			res.Unsent = append(res.Unsent, Unsent{Rule: p, Why: why})
			continue
		}
		// `deny-commands .*` is the narrow shape's guard beneath its bits, and
		// it refuses the RPC entry points: an allow running one voids it.
		if !g.in.Facts.DenyBindsRPCs && g.opensRPC(p.Rule) {
			return Result{}, refuse(FailRefusedShape, "permit %s (role %q) needs an allow-commands that runs an RPC "+
				"entry point past the reply's `deny-commands .*`: %s; drop the permit, or narrow it past `op` and "+
				"`xml-mode`", g.quote(p.Rule), p.Role, g.rpcWhy())
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

// cover is the smallest set of the bits from under which every allow is a
// command the bits run too (reaches, carve-outs counted): fewest bits, then
// fewest that enter configuration mode, then first in name order (I11: `all`
// reaches everything, and a narrow admin grant under it would be refused for
// entering configuration mode). Whether a Junos allow runs a command its bits
// do not reach is unmeasured, so the bits are what prove it runs. An allow
// the baseline runs needs no bit. Where the search finds no smaller set, or
// the greedy one stalls, it is every bit of from, which within proved reaches
// each allow: never none.
func (g generator) cover(from []string, allows []engine.Rule) []string {
	// For each allow the baseline does not run: the bits whose reach holds
	// it, one of which the set must hold, and the bits whose carve-out meets
	// it, all of which it must hold.
	type need struct{ reachers, carvers []string }
	var needs []need
	for _, a := range allows {
		if g.reaches(a.Rule, nil, false) {
			continue
		}
		var n need
		for _, b := range sortedKeys(g.in.Dialect.Bits) {
			if slices.ContainsFunc(g.in.Dialect.Bits[b], func(r string) bool { return g.contains(r, a.Rule) }) {
				n.reachers = append(n.reachers, b)
			}
		}
		for _, b := range sortedKeys(g.in.Dialect.CarveOuts) {
			if slices.ContainsFunc(g.in.Dialect.CarveOuts[b], func(c string) bool { return g.mayMeet(a.Rule, c) }) {
				n.carvers = append(n.carvers, b)
			}
		}
		needs = append(needs, n)
	}
	if len(needs) == 0 {
		return nil
	}
	every := slices.Clone(from)
	slices.Sort(every)
	every = slices.Compact(every)
	// satisfied counts the allows the bits s run.
	satisfied := func(s []string) int {
		held := g.held(s)
		in := func(b string) bool { return slices.Contains(held, b) }
		k := 0
		for _, n := range needs {
			if slices.ContainsFunc(n.reachers, in) && !slices.ContainsFunc(n.carvers, func(b string) bool { return !in(b) }) {
				k++
			}
		}
		return k
	}
	// Only a bit that reaches or carves some allow, or `all`, which holds
	// every bit, can be in the smallest set.
	cands := slices.DeleteFunc(slices.Clone(every), func(b string) bool {
		return b != "all" && !slices.ContainsFunc(needs, func(n need) bool {
			return slices.Contains(n.reachers, b) || slices.Contains(n.carvers, b)
		})
	})
	configs := func(s []string) int {
		k := 0
		for _, b := range s {
			if g.entersConfiguration(b) {
				k++
			}
		}
		return k
	}
	better := func(a, b []string) bool {
		if len(a) != len(b) {
			return len(a) < len(b)
		}
		if ca, cb := configs(a), configs(b); ca != cb {
			return ca < cb
		}
		return slices.Compare(a, b) < 0
	}
	if len(cands) < 64 && uint64(1)<<len(cands) <= maxCover {
		var best []string
		for set := uint64(1); set < uint64(1)<<len(cands); set++ {
			var s []string
			for i, b := range cands {
				if set&(1<<i) != 0 {
					s = append(s, b)
				}
			}
			if (best == nil || better(s, best)) && satisfied(s) == len(needs) {
				best = s
			}
		}
		if best != nil {
			return best
		}
		return every
	}
	// Greedy: the bit that runs the most allows not yet run, one that does
	// not enter configuration mode first, then name order.
	var set []string
	for got := 0; got < len(needs); {
		pick, pn := "", got
		for _, b := range cands {
			if slices.Contains(set, b) {
				continue
			}
			n := satisfied(append(slices.Clone(set), b))
			if n <= got {
				continue
			}
			if pick == "" || n > pn || n == pn && g.entersConfiguration(pick) && !g.entersConfiguration(b) {
				pick, pn = b, n
			}
		}
		if pick == "" {
			return every
		}
		set = append(set, pick)
		got = pn
	}
	slices.Sort(set)
	return set
}

// unreached is the allows of res its bits do not run (Result.Unreached).
func (g generator) unreached(res Result) []engine.Rule {
	var out []engine.Rule
	for _, a := range res.Allows {
		if !g.reaches(a.Rule, res.Bits, false) {
			out = append(out, a)
		}
	}
	return out
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
		rpc := !g.in.Facts.DenyBindsRPCs && h.opensRPC(p.Rule)
		if secret || werr != nil || !ok || !h.within(p.Rule) || h.meetsConfiguration(p.Rule) || rpc {
			res.Beyond = append(res.Beyond, p)
			continue
		}
		if why := h.unsendableAllow(p.Rule); why != "" {
			res.Unsent = append(res.Unsent, Unsent{Rule: p, Why: why})
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
		out.Unreached = h.unreached(out)
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
			return "", refuse(FailUnwritable, "on %s, %s %s (role %q) cannot be written as the device's regex: %v "+
				"(spec §8, §15 L9)", g.in.Platform, r.Verdict, g.quote(r.Rule), r.Role, err)
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
