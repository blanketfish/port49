package directory

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/spiffe"
	"github.com/rhwendt/port49/internal/store"
)

type Source string

const (
	Fresh Source = "fresh"
	Grace Source = "grace"
)

// ErrNotUser is a principal the directory holds no entry for: a machine
// principal (spiffe://, system:serviceaccount:, app:). It is never a
// refusal, so nothing revokes on it (pre-flight I-10).
var ErrNotUser = errors.New("directory: not a user: principal")

// IsUser reports whether principal is one the directory resolves: a
// user: principal (design §7). Every other is policy.MemberOf alone.
func IsUser(principal string) bool { return strings.HasPrefix(principal, "user:") }

// IsWorkload reports whether principal is a workload certificate's: a SPIFFE
// ID, as the verifier gives it, lower-case scheme (decision 40 ruling 4). The
// broker sends one to the directory only under a workload mapping
// (decision 41 ruling 1).
func IsWorkload(principal string) bool { return strings.HasPrefix(principal, spiffe.Scheme) }

// Answer is a membership and where it came from.
type Answer struct {
	store.Membership
	Source Source
}

// Resolver is the broker's one door to the directory (plan 7g).
type Resolver struct {
	Cfg      Config
	Pool     *Pool
	Store    store.Store
	Now      func() time.Time
	M        *metrics.Metrics
	Say      func(format string, args ...any)
	Declared func() map[string]string
	// StoreTimeout bounds each store read and write the resolver makes
	// on its own budget (the grace read, a refusal); 10s when zero, as
	// the broker's holdTimeout.
	StoreTimeout time.Duration
	// PersonDial dials the connection a person's bind is made on; nil is
	// dialPerson (signin.go).
	PersonDial func(ctx context.Context, s Server) (PersonConn, error)
	// Calls counts the answers a ForTestsStaticResolver gave: nothing
	// else sets it.
	Calls atomic.Int64

	// static, when set, answers Map, Verify and Current (static.go).
	static func(principal string) (Answer, error)

	mu   sync.Mutex
	said map[string]time.Time
	// ambiguous is each shared group name's last sighting, by verify and
	// by pre-warm: the gauge counts those seen within ambiguousWindow.
	ambiguous map[string]time.Time
}

// ambiguousWindow is how long a shared group name counts as ambiguous
// after it was last seen: the hourly cadence of its log line.
const ambiguousWindow = time.Hour

// TTL is a membership record's lease: past grace, so a policy reload
// judges a context by the membership its principal last had (Ruling 10).
func (r *Resolver) TTL() time.Duration { return max(r.Cfg.Grace, 24*time.Hour) }

func (r *Resolver) storeCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	d := r.StoreTimeout
	if d == 0 {
		d = 10 * time.Second
	}
	return context.WithTimeout(context.WithoutCancel(ctx), d)
}

// lookup is one verification: how the entry is found, and what it must
// still be.
type lookup struct {
	find   func(Searcher) (*ldap.Entry, error)
	want   string // the principal the entry must still give; "" at a bind or a pre-warm
	mapKey string // the key a bind searched with: indexed on success, refused on a refusal
	say    string // what names the lookup in a line said once
	// workload is a workload certificate's lookup (decision 41): the entry is
	// read by workloadIdentityOf, its SPIFFE ID checked by workloadUnique, no
	// mapping key is indexed, and no declared username is checked here, since
	// the broker settles a workload's username against its own subject
	// (ruling 4).
	workload bool
}

// Map maps a client certificate to its membership at a bind (Ruling 4):
// from a server, written to the store; with no server answering, from the
// store by the certificate's mapping key within grace.
func (r *Resolver) Map(ctx context.Context, leaf *x509.Certificate) (Answer, error) {
	if r.static != nil {
		return r.answerStatic(staticKey(leaf))
	}
	l, err := r.Cfg.Mapping.Lookup(leaf, r.Cfg.UserFilter)
	if err != nil {
		r.count("unmapped")
		return Answer{}, err
	}
	a, err := r.verify(ctx, lookup{find: r.byFilter(l.Filter), mapKey: l.Key, say: l.Filter})
	if !errors.Is(err, ErrUnavailable) {
		return a, err
	}
	return r.grace(ctx, func(ctx context.Context) (store.Membership, error) {
		return r.Store.MembershipByKey(ctx, l.Key)
	}, err, "this certificate", true)
}

// Verify reads principal's entry and groups from a server, never from
// grace: the scheduled refresh and an explicit re-check (Ruling 12). The
// entry must be the one the principal is pinned to (verify's pin check).
func (r *Resolver) Verify(ctx context.Context, principal string) (Answer, error) {
	if !IsUser(principal) {
		return Answer{}, fmt.Errorf("%w: %s", ErrNotUser, printsafe.Line(principal, 200))
	}
	if r.static != nil {
		return r.answerStatic(principal)
	}
	v := strings.TrimPrefix(principal, "user:")
	filter := fmt.Sprintf("(&%s(%s=%s))", r.Cfg.UserFilter, r.Cfg.PrincipalAttribute, ldap.EscapeFilter(v))
	return r.verify(ctx, lookup{find: r.byFilter(filter), want: principal, say: filter})
}

// VerifyWorkload reads a workload's entry and groups from a server, never from
// grace (decision 41 ruling 2): the one entry whose workload attribute holds
// principal, under the workload user_filter. ErrNotUser without a workload
// mapping, or for a principal that is no SPIFFE ID.
func (r *Resolver) VerifyWorkload(ctx context.Context, principal string) (Answer, error) {
	if r.Cfg.Workload == nil || !IsWorkload(principal) {
		return Answer{}, fmt.Errorf("%w: %s is no workload under broker.identity.machines[].directory", ErrNotUser,
			printsafe.Line(principal, 300))
	}
	if r.static != nil {
		return r.answerStatic(principal)
	}
	w := r.Cfg.Workload
	filter := fmt.Sprintf("(&%s(%s=%s))", w.UserFilter, w.Attribute, ldap.EscapeFilter(principal))
	return r.verify(ctx, lookup{find: r.byWorkloadFilter(filter), want: principal, say: filter, workload: true})
}

// CurrentWorkload is the membership a workload's request uses: VerifyWorkload,
// else the store's within grace (decision 41 ruling 6).
func (r *Resolver) CurrentWorkload(ctx context.Context, principal string) (Answer, error) {
	if r.static != nil && r.Cfg.Workload != nil && IsWorkload(principal) {
		return r.answerStatic(principal)
	}
	a, err := r.VerifyWorkload(ctx, principal)
	if !errors.Is(err, ErrUnavailable) {
		return a, err
	}
	return r.grace(ctx, func(ctx context.Context) (store.Membership, error) {
		return r.Store.GetMembership(ctx, principal)
	}, err, principal, false)
}

// byWorkloadFilter finds the one entry filter matches under base_dn, reading
// the workload attributes.
func (r *Resolver) byWorkloadFilter(filter string) func(Searcher) (*ldap.Entry, error) {
	return func(s Searcher) (*ldap.Entry, error) { return r.Cfg.oneEntry(s, filter, r.Cfg.workloadAttrs()) }
}

// byWorkloadDN reads the entry at dn under the workload user_filter (pre-warm:
// a machine group's member).
func (r *Resolver) byWorkloadDN(dn string) func(Searcher) (*ldap.Entry, error) {
	return func(s Searcher) (*ldap.Entry, error) {
		res, err := s.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1,
			int(r.Cfg.QueryTimeout.Seconds()), false, r.Cfg.Workload.UserFilter, r.Cfg.workloadAttrs(), nil))
		switch {
		case ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject):
			return nil, fmt.Errorf("%w: no entry %s", ErrUnmapped, printsafe.Line(dn, 200))
		case err != nil:
			return nil, err
		case len(res.Entries) != 1:
			return nil, fmt.Errorf("%w: %s is not under the workload user_filter", ErrUnmapped, printsafe.Line(dn, 200))
		}
		return res.Entries[0], nil
	}
}

// byFilter finds the one entry filter matches under base_dn.
func (r *Resolver) byFilter(filter string) func(Searcher) (*ldap.Entry, error) {
	return func(s Searcher) (*ldap.Entry, error) { return r.Cfg.oneEntry(s, filter, r.Cfg.entryAttrs()) }
}

// byDN reads the entry at dn, if it is a user (pre-warm: a group's member).
func (r *Resolver) byDN(dn string) func(Searcher) (*ldap.Entry, error) {
	return func(s Searcher) (*ldap.Entry, error) {
		res, err := s.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1,
			int(r.Cfg.QueryTimeout.Seconds()), false, r.Cfg.UserFilter, r.Cfg.entryAttrs(), nil))
		switch {
		case ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject):
			return nil, fmt.Errorf("%w: no entry %s", ErrUnmapped, printsafe.Line(dn, 200))
		case err != nil:
			return nil, err
		case len(res.Entries) != 1:
			return nil, fmt.Errorf("%w: %s is not a user", ErrUnmapped, printsafe.Line(dn, 200))
		}
		return res.Entries[0], nil
	}
}

// Current is the membership a request uses: Verify, else the store's
// within grace (Ruling 10).
func (r *Resolver) Current(ctx context.Context, principal string) (Answer, error) {
	if r.static != nil && IsUser(principal) {
		return r.answerStatic(principal)
	}
	a, err := r.Verify(ctx, principal)
	if !errors.Is(err, ErrUnavailable) {
		return a, err
	}
	return r.grace(ctx, func(ctx context.Context) (store.Membership, error) {
		return r.Store.GetMembership(ctx, principal)
	}, err, principal, true)
}

// Stored is the membership the store holds, whatever its age, refused or
// not: what a policy refresh judges by (Ruling 12). false with none.
func (r *Resolver) Stored(ctx context.Context, principal string) (store.Membership, bool, error) {
	m, err := r.Store.GetMembership(ctx, principal)
	if errors.Is(err, store.ErrNotFound) {
		return store.Membership{}, false, nil
	}
	return m, err == nil, err
}

// verify finds the entry, derives its identity, checks that its principal
// and username are its alone and reads its groups, all in one pool call (one
// server, one connection); then checks the entry is the one the principal is
// pinned to, and writes the store. The pool call is bounded by query_timeout alone, never by the caller's
// shorter deadline (pre-flight I-8), so a slow DC reaches grace. A
// refusal (unmapped, ambiguous, collision) is written too (pre-flight
// C-1): by the principal asked for, by the principal the entry gave when
// it is that principal's own (its value or username held twice), and by
// the key a bind searched with.
func (r *Resolver) verify(ctx context.Context, q lookup) (Answer, error) {
	var id Identity
	var g Groups
	var keys []string
	refuse := ""
	srv, err := r.Pool.Do(context.WithoutCancel(ctx), func(s Searcher) error {
		// Pool.Do reruns this on the next server after a fault: nothing a
		// faulted server's partial answer set may reach what follows.
		id, g, keys, refuse = Identity{}, Groups{}, nil, ""
		e, err := q.find(s)
		if err != nil {
			return err
		}
		if q.workload {
			id, err = r.Cfg.workloadIdentityOf(e, q.want)
		} else if err = r.Cfg.notWorkload(e); err == nil {
			// A person's entry must not be a workload's (decision 41
			// ruling 4): a bind, a mint, the scheduled refresh and pre-warm
			// all read a person through here.
			id, err = r.Cfg.identityOf(e)
		}
		if err != nil {
			return err
		}
		if !q.workload && q.want != "" && id.Principal != q.want {
			return fmt.Errorf("%w: the entry now gives %s", ErrUnmapped, id.Principal)
		}
		unique := r.Cfg.principalUnique
		if q.workload {
			unique = r.Cfg.workloadUnique
		}
		if err := unique(s, id); err != nil {
			refuse = id.Principal
			return err
		}
		if err := r.Cfg.usernameUnique(s, id); err != nil {
			refuse = id.Principal
			return err
		}
		if !q.workload {
			keys = r.Cfg.Mapping.KeysOf(e)
		}
		g, err = r.Cfg.groupsOf(s, id.DN)
		return err
	})
	if err == nil {
		// The pin (Ruling 3; pre-flight C-2): a principal the store holds
		// for another entry is refused, at a bind as on a re-verification.
		// No refusal is written for the principal here at a bind: it is
		// another person's, and its record (with its pin) stands. The line
		// is said once an hour per principal, naming the way out.
		attr := r.Cfg.PrincipalAttribute
		if q.workload {
			attr = r.Cfg.Workload.Attribute
		}
		if err = r.pinned(ctx, id, attr); errors.Is(err, ErrUnmapped) {
			r.sayOnce("pin:"+id.Principal, time.Hour, "%s", printsafe.Line(err.Error(), 900))
		}
	}
	if err == nil && !q.workload {
		if who, ok := r.declared()[id.Username]; ok {
			refuse = id.Principal
			err = fmt.Errorf("%w: the directory derives username %q for %s, which subject %q declares",
				ErrUsernameTaken, id.Username, id.Principal, who)
		}
	}
	switch {
	case errors.Is(err, ErrUnavailable):
		r.sayOnce("unavailable", time.Hour, "directory: no server answered (%s); serving memberships verified within "+
			"%s (directory.grace)", printsafe.Line(err.Error(), 300), r.Cfg.Grace)
		return Answer{}, err
	case errors.Is(err, ErrAmbiguous):
		r.count("ambiguous")
		r.sayOnce("ambiguous:"+q.say, time.Hour, "directory: identity_ambiguous: %s; refusing it: two entries "+
			"matching one identity is an impersonation path (design §7)", printsafe.Line(err.Error(), 400))
		r.refuse(ctx, q, refuse, id)
		return Answer{}, err
	case errors.Is(err, ErrUsernameTaken):
		r.count("collision")
		r.refuse(ctx, q, refuse, id)
		return Answer{}, err
	case errors.Is(err, ErrUnmapped):
		r.count("unmapped")
		r.refuse(ctx, q, "", id)
		return Answer{}, err
	case err != nil:
		return Answer{}, err
	}
	if g.Truncated {
		r.M.DirectoryWalksTruncated.Inc()
		r.sayOnce("truncated:"+id.DN, time.Hour, "directory: %s's group walk reached max_depth (%d); the groups "+
			"found are used and the deeper ones are not", printsafe.Line(id.DN, 200), r.Cfg.MaxDepth)
	}
	if g.Loops > 0 {
		r.sayOnce("revisits:"+id.DN, time.Hour, "directory: %s's group walk had %d revisits (loops or diamonds); "+
			"each path ended at the revisit", printsafe.Line(id.DN, 200), g.Loops)
	}
	if len(g.Ambiguous) > 0 {
		r.noteAmbiguous(g.Ambiguous...)
		r.sayOnce("names:"+strings.Join(g.Ambiguous, ","), time.Hour, "directory: group name(s) %s are shared by "+
			"two or more groups under %s; a subject naming one matches no one (use its DN)",
			printsafe.Line(strings.Join(g.Ambiguous, ", "), 400), r.Cfg.GroupsBaseDN)
	}
	if len(g.Unfound) > 0 {
		r.sayOnce("unfound:"+strings.Join(g.Unfound, ","), time.Hour, "directory: group name(s) %s matched no group "+
			"under %s by %s when checked for uniqueness; a subject naming one matches no one until it does",
			printsafe.Line(strings.Join(g.Unfound, ", "), 400), r.Cfg.GroupsBaseDN, r.Cfg.GroupNameAttribute)
	}
	if q.mapKey != "" && !slices.Contains(keys, q.mapKey) {
		keys = append(keys, q.mapKey) // the key the bind searched with is indexed too (pre-flight M-2)
		slices.Sort(keys)
	}
	m := store.Membership{Principal: id.Principal, DN: id.DN, EntryID: id.EntryID, Username: id.Username,
		GroupDNs: g.DNs, GroupNames: g.Names, MapKeys: keys, VerifiedAt: r.Now(), Server: srv.Label(), Site: srv.Site}
	sctx, cancel := r.storeCtx(ctx)
	defer cancel()
	if err := r.Store.PutMembership(sctx, m, r.TTL()); err != nil {
		return Answer{}, err
	}
	r.count("fresh")
	return Answer{Membership: m, Source: Fresh}, nil
}

// pinned is ErrUnmapped when the store holds id.Principal pinned to
// another entry (Ruling 3): a principal_attribute value moved between
// entries never carries the principal with it. A refused record keeps its
// pin and is checked the same way.
func (r *Resolver) pinned(ctx context.Context, id Identity, attr string) error {
	sctx, cancel := r.storeCtx(ctx)
	defer cancel()
	m, err := r.Store.GetMembership(sctx, id.Principal)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return err
	case m.EntryID == "" || m.EntryID == id.EntryID:
		return nil
	}
	// The line names the way out (Ruling 3's escape): an entry deleted and
	// re-created reads exactly like another person's, and only the operator
	// can tell them apart.
	return fmt.Errorf("%w: %s is pinned to entry %s and is now claimed by %s (%s); a %s value moved "+
		"between entries never carries a principal with it (Ruling 3); if this is the same person's entry "+
		"re-created (a rehire, a restore), confirm that and run `port49 directory forget %s` "+
		"(it asks for a press of your security key)", ErrUnmapped, printsafe.Line(id.Principal, spiffe.MaxLen), printsafe.Line(m.EntryID, 120),
		printsafe.Line(id.DN, 200), printsafe.Line(id.EntryID, 120), attr, printsafe.Line(id.Principal, spiffe.MaxLen))
}

// unreadPin is the entry id of a refusal whose held pin could not be read:
// no entry's id is this, so every claimant of the principal is refused.
const unreadPin = "unread:"

// refuse stores the directory's "no" (pre-flight C-1) for q.want, for
// also (a principal the entry gave whose value or username another entry
// holds), and for q.mapKey, so grace never answers yes in an outage that
// follows. Each principal's refusal keeps the pin its record held, or the
// refused entry's own id when none was held, so a refusal never frees the
// principal for the next claimant. A failed write is said; the refusal
// itself stands either way.
func (r *Resolver) refuse(ctx context.Context, q lookup, also string, id Identity) {
	now := r.Now()
	sctx, cancel := r.storeCtx(ctx)
	defer cancel()
	ps := []string{q.want}
	if also != q.want {
		ps = append(ps, also)
	}
	for _, p := range ps {
		if p == "" {
			continue
		}
		pin := ""
		switch held, err := r.Store.GetMembership(sctx, p); {
		case err == nil:
			pin = held.EntryID
		case errors.Is(err, store.ErrNotFound):
			if p == id.Principal {
				pin = id.EntryID
			}
		default:
			// The pin the record held cannot be read, and a refusal with no pin
			// frees the principal for the next claimant. Hold it on a pin no
			// entry matches until an operator forgets it.
			pin = unreadPin
			r.sayOnce("unreadpin:"+p, time.Hour, "directory: %s: the pin it was held to could not be read (%v); "+
				"the principal is held refused to every entry; once the store is healthy, `port49 directory forget %s` "+
				"(it asks for a press of your security key) frees it", printsafe.Line(p, spiffe.MaxLen), err, printsafe.Line(p, spiffe.MaxLen))
		}
		if err := r.Store.PutMembership(sctx, store.Membership{Principal: p, EntryID: pin, Refused: true,
			VerifiedAt: now}, r.TTL()); err != nil {
			r.sayOnce("refuse:"+p, time.Hour, "directory: %s: storing the directory's refusal failed (%v); grace "+
				"may serve its older membership in an outage until the store takes the write", p, err)
		}
	}
	if q.mapKey != "" {
		if err := r.Store.RefuseMapKeys(sctx, []string{q.mapKey}, now, r.TTL()); err != nil {
			r.sayOnce("refusekey:"+q.mapKey, time.Hour, "directory: storing a certificate's refusal failed (%v)", err)
		}
	}
}

// grace answers from a stored membership verified within grace, read on
// its own budget, or ErrUnavailable saying why not. A refused record is
// never served (pre-flight C-1), and a declared username still collides
// (pre-flight M-11).
func (r *Resolver) grace(ctx context.Context, read func(context.Context) (store.Membership, error), cause error,
	who string, declared bool) (Answer, error) {
	sctx, cancel := r.storeCtx(ctx)
	defer cancel()
	m, gerr := read(sctx)
	switch {
	case errors.Is(gerr, store.ErrNotFound):
		r.count("unavailable")
		return Answer{}, fmt.Errorf("%w: no membership is stored for %s (%v)", ErrUnavailable, who, cause)
	case gerr != nil:
		return Answer{}, gerr
	case m.Refused:
		r.count("unavailable")
		return Answer{}, fmt.Errorf("%w: the directory refused %s at %s, before it stopped answering; grace never "+
			"overrules a refusal", ErrUnavailable, printsafe.Line(m.Principal, spiffe.MaxLen), m.VerifiedAt.UTC().Format(time.RFC3339))
	}
	age := r.Now().Sub(m.VerifiedAt)
	if r.Cfg.Grace == 0 || age > r.Cfg.Grace {
		r.count("unavailable")
		r.sayOnce("past:"+m.Principal, time.Hour, "directory: %s: no server answered and the membership stored was "+
			"verified %s ago, past directory.grace (%s); refused directory_unavailable", printsafe.Line(m.Principal, spiffe.MaxLen),
			age.Round(time.Minute), r.Cfg.Grace)
		return Answer{}, fmt.Errorf("%w: the membership stored for %s was verified %s ago, past directory.grace (%s)",
			ErrUnavailable, printsafe.Line(m.Principal, spiffe.MaxLen), age.Round(time.Minute), r.Cfg.Grace)
	}
	if subj, ok := r.declared()[m.Username]; declared && ok {
		r.count("collision")
		return Answer{}, fmt.Errorf("%w: the stored membership gives username %q for %s, which subject %q declares",
			ErrUsernameTaken, m.Username, m.Principal, subj)
	}
	r.count("grace")
	r.sayOnce("grace:"+m.Principal, time.Hour, "directory: %s minted from a membership verified %s ago (grace)",
		printsafe.Line(m.Principal, spiffe.MaxLen), age.Round(time.Minute))
	return Answer{Membership: m, Source: Grace}, nil
}

// DeclaredBy is the subject that declares username, and false when none
// does: the collision check Verify and grace apply (pre-flight M-11), for a
// pass that judges by a stored membership and asks no server.
func (r *Resolver) DeclaredBy(username string) (string, bool) {
	who, ok := r.declared()[username]
	return who, ok
}

func (r *Resolver) declared() map[string]string {
	if r.Declared == nil {
		return nil
	}
	return r.Declared()
}

func (r *Resolver) count(outcome string) { r.M.DirectoryLookups.WithLabelValues(outcome).Inc() }

// sayOnce says a line at most once per every, by key.
func (r *Resolver) sayOnce(key string, every time.Duration, format string, args ...any) {
	r.mu.Lock()
	if r.said == nil {
		r.said = map[string]time.Time{}
	}
	now := r.Now()
	if last, ok := r.said[key]; ok && now.Sub(last) < every {
		r.mu.Unlock()
		return
	}
	r.said[key] = now
	r.mu.Unlock()
	r.Say(format, args...)
}

// noteAmbiguous records names as shared by two or more groups, seen now,
// and hands the gauge its count on the first sighting.
func (r *Resolver) noteAmbiguous(names ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ambiguous == nil {
		r.ambiguous = map[string]time.Time{}
		r.M.SetDirectoryGroupNamesAmbiguous(r.ambiguousCount)
	}
	now := r.Now()
	for _, n := range names {
		r.ambiguous[n] = now
	}
}

// ambiguousCount is the names seen shared within ambiguousWindow, the
// older ones dropped. It is what a scrape reads, so the gauge falls back
// to 0 with no resolution to reset it.
func (r *Resolver) ambiguousCount() float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.Now()
	for n, seen := range r.ambiguous {
		if now.Sub(seen) >= ambiguousWindow {
			delete(r.ambiguous, n)
		}
	}
	return float64(len(r.ambiguous))
}
