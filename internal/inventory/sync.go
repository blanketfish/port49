package inventory

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/fence"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/policy"
)

// Outcomes of a sync.
const (
	OutcomePublished = "published"
	OutcomeUnchanged = "unchanged"
	OutcomeRefused   = "refused"
	OutcomeFailed    = "failed"
)

// Result is what one sync did: the API's answer to POST /v1/sync, and what
// the service says.
type Result struct {
	Outcome     string              `json:"outcome"`
	Sequence    int64               `json:"sequence"`
	Bundle      string              `json:"bundle,omitempty"`
	Summary     string              `json:"summary,omitempty"`
	Changes     []bundle.Change     `json:"changes,omitempty"`
	Quarantined []QuarantinedDevice `json:"quarantined,omitempty"`
	LeftOut     []string            `json:"left_out,omitempty"`
	Reason      string              `json:"reason,omitempty"`
}

// QuarantinedDevice is a device the service's policy quarantines in the
// bundle it published (spec §10): each port49d quarantines it again against
// its own policy (spec §13, decision 29).
type QuarantinedDevice struct {
	Device   string `json:"device"`
	Platform string `json:"platform"`
	Cause    string `json:"cause"`
}

// Syncer runs one sync at a time: every source, merged and validated, parsed
// against the service's policy, bounded against the bundle published, and,
// when it changed, published — sealed, kept in State, mirrored. A trigger
// that arrives during a sync waits for it and then runs its own.
type Syncer struct {
	Sources    []Source
	Bounds     map[string]int
	Default    int
	PolicyFile string
	Key        ed25519.PrivateKey
	// VerifyKeys are the further keys the service's own state and mirror
	// are read against: through a signing-key rotation, the old key's
	// (pre-flight M6). Its own key's public half is always among them.
	VerifyKeys []ed25519.PublicKey
	// Timeout bounds one sync (sync_timeout; pre-flight minor 10); zero is 5m.
	Timeout time.Duration
	State   State
	Metrics *Metrics
	Now     func() time.Time
	Log     io.Writer

	mu      sync.Mutex
	current atomic.Pointer[Published]
	// said is the last refusal or failure said, so each is said once.
	said string
	// mirrorMu guards the mirror's bookkeeping, never a read or write of it:
	// mirrorOut is closed when the read or write last started returns, nil
	// once it has; mirrorSaid is the last mirror fault said, so each is said
	// once. mirrorDeadline bounds one read or write; zero is 10s.
	mirrorMu       sync.Mutex
	mirrorOut      chan struct{}
	mirrorSaid     string
	mirrorDeadline time.Duration
	// leftOutSaid is the devices left out as last said, so an unchanged
	// sync says only those newly left out.
	leftOutSaid []string
	// fetched is each source's latest fetch, which a sync of another source
	// merges with (spec §10: each source on its own interval).
	fetched map[string]admission.Inventory
}

// maxPolicy bounds the service's read of its policy copy, as port49d bounds
// its own.
const maxPolicy = 1 << 20

// readPolicy reads the service's policy copy behind the write fence, as
// port49d reads its own (final review Minor 1): whoever can write it decides
// what the service's bound refuses.
func readPolicy(path string) ([]byte, error) { return fence.Read(path, maxPolicy, "policy file") }

// Current is the bundle published, or nil before the first.
func (s *Syncer) Current() *Published { return s.current.Load() }

// keys are every key the service reads its own state and mirror against.
func (s *Syncer) keys() []ed25519.PublicKey {
	return append([]ed25519.PublicKey{s.Key.Public().(ed25519.PublicKey)}, s.VerifyKeys...)
}

// Restore serves what the service last published, the newer of state_dir's
// copy and the mirror's, so a restart serves at once and continues the
// sequence (Decided 3). A state_dir copy that does not open, or a mirror copy
// that does not open while state_dir holds none, is an error, and the service
// does not start: passed over, it would start the sequence again at 1,
// unbounded, below the copy every port49d holds (review of Task 9, Important
// 1). Beside a good state_dir, a mirror that does not open is said and shows
// as mirror_behind. A copy that is not there at all is a fresh start.
//
// The mirror is read under its deadline (mirrorIO): one that hangs is passed
// over beside a good state_dir, as one that does not open is, and with
// state_dir empty stops the start, said, since it may hold the bundle every
// port49d holds (final review I3). ctx ending — a SIGTERM — ends the wait,
// and Restore returns ctx's error. It holds the sync lock, so it is safe
// beside a sync.
func (s *Syncer) Restore(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := s.keys()
	best, err := s.State.Latest(keys)
	if err != nil {
		// Open's and the fence's errors name the file and quote nothing in it.
		return fmt.Errorf("port49-inventory: state_dir %s holds a bundle the service cannot open: %s; the service "+
			"does not start below it: if a signing key was rotated, add the old key to verify_key_files; to start "+
			"fresh, move it aside", s.State.Dir, oneLine(err))
	}
	if s.State.MirrorDir != "" {
		// Behind until shown level, so a mirror that hangs shows at once.
		s.Metrics.MirrorBehind.Set(1)
		var m *Published
		err := s.mirrorIO(ctx, func() (err error) { m, err = s.State.Mirror(keys); return err })
		switch {
		case ctx.Err() != nil:
			return ctx.Err()
		case errors.Is(err, errMirrorHung) && best != nil:
			fmt.Fprintf(s.Log, "port49-inventory: %s; serving state_dir's bundle %d\n", oneLine(err),
				best.Doc.Sequence)
		case err != nil && best != nil:
			// state_dir holds a good bundle: the mirror is a copy of it, not
			// the floor. Said, and mirror() below keeps mirror_behind 1 while
			// it cannot be brought level; WriteMirror's floor keeps a newer one.
			fmt.Fprintf(s.Log, "port49-inventory: mirror_dir %s holds a copy the service cannot open: %s; serving "+
				"state_dir's bundle %d\n", s.State.MirrorDir, oneLine(err), best.Doc.Sequence)
		case errors.Is(err, errMirrorHung):
			return fmt.Errorf("port49-inventory: %s, and state_dir %s holds no bundle: the mirror may hold the "+
				"bundle every port49d holds, and the service does not start below it: mend the mount, or, to "+
				"start fresh, move its copy aside", oneLine(err), s.State.Dir)
		case err != nil:
			return fmt.Errorf("port49-inventory: mirror_dir %s holds a bundle the service cannot open: %s; the "+
				"service does not start below it: if a signing key was rotated, add the old key to "+
				"verify_key_files; to start fresh, move it aside", s.State.MirrorDir, oneLine(err))
		case m != nil && (best == nil || m.Doc.Sequence > best.Doc.Sequence):
			best = m
		}
	}
	if best == nil {
		// The mirror was read, and is empty: nothing is published for it to
		// be behind.
		s.Metrics.MirrorBehind.Set(0)
		fmt.Fprintln(s.Log, "port49-inventory: no bundle published yet; the first sync publishes bundle 1, bounded "+
			"by each port49d")
		return nil
	}
	s.publish(best)
	fmt.Fprintf(s.Log, "port49-inventory: serving bundle %d (%s), published %s\n", best.Doc.Sequence,
		best.Doc.Bundle, best.Doc.PublishedAt.Format(time.RFC3339))
	if _, err := s.reseal(); err != nil {
		// Serving the old key's bundle is safe while port49d still lists
		// that key; the next sync tries again.
		fmt.Fprintf(s.Log, "port49-inventory: %s; serving it as it is, and the next sync tries again\n", oneLine(err))
	}
	s.mirror(ctx) // a mirror behind the state is brought level at once (M7)
	return nil
}

// reseal re-seals the bundle published under the signing key when another
// key signed it — a rotation — as the next sequence, published now, the
// fleet unchanged (final review I1). Without it a stable fleet keeps the old
// key's signature in force, and dropping that key from port49d's
// verify_key_files leaves every restarting port49d with no copy it can open.
// port49d takes the result as the same devices under a new sequence, and
// persists it. It says what it did, and whether it did anything.
func (s *Syncer) reseal() (bool, error) {
	cur := s.current.Load()
	if cur == nil {
		return false, nil
	}
	own := s.Key.Public().(ed25519.PublicKey)
	if _, _, err := bundle.Open(cur.Raw, []ed25519.PublicKey{own}); !errors.Is(err, bundle.ErrUnknownKey) {
		return false, nil
	}
	doc := cur.Doc
	seq, err := s.nextSequence(cur)
	doc.Sequence = seq
	doc.PublishedAt = s.publishedAt(cur, s.Now()).UTC()
	var raw []byte
	if err == nil {
		raw, err = bundle.Seal(doc, s.Key)
	}
	if err == nil {
		err = s.State.Save(Published{Raw: raw, Doc: doc, Inv: cur.Inv})
	}
	if err != nil {
		return false, fmt.Errorf("bundle %d is signed by another key than the signing key %s, and its re-sealing "+
			"could not be kept: state_dir %s: %s", cur.Doc.Sequence, bundle.KeyIDOf(own), s.State.Dir, oneLine(err))
	}
	s.publish(&Published{Raw: raw, Doc: doc, Inv: cur.Inv})
	fmt.Fprintf(s.Log, "port49-inventory: bundle %d is signed by another key than the signing key %s; re-sealed as "+
		"bundle %d, the fleet unchanged; once every port49d's port49_inventory_bundle_sequence shows %d, the old "+
		"key can leave verify_key_files\n", cur.Doc.Sequence, bundle.KeyIDOf(own), doc.Sequence, doc.Sequence)
	return true, nil
}

func (s *Syncer) publish(p *Published) {
	s.current.Store(p)
	s.Metrics.Published.Set(float64(p.Doc.Sequence))
	s.Metrics.PublishedAt.Set(float64(p.Doc.PublishedAt.Unix()))
	s.Metrics.Devices.Set(float64(len(p.Inv.Devices)))
}

// Sync runs one sync for trigger, under Timeout, says what it did, and
// returns it. It fetches the sources named in only — every source when only
// is empty, and any source not fetched since start — and rebuilds the merged
// bundle from every source's latest fetch, so each source syncs on its own
// interval (spec §10). Whatever it found, the mirror is brought level with
// the bundle published (M7). A sync that fails once its caller's ctx is done
// — a shutdown — returns quietly: it is not said, counted or mirrored, and a
// sync that ran past Timeout while its caller waited is still a failure.
func (s *Syncer) Sync(ctx context.Context, trigger string, only ...string) Result {
	res, quiet := s.syncLocked(ctx, trigger, only)
	if !quiet {
		s.mirror(ctx)
	}
	return res
}

// syncLocked is Sync's sync, under the sync lock; quiet is a sync its
// caller's end cut short, which is neither said, counted nor mirrored.
func (s *Syncer) syncLocked(ctx context.Context, trigger string, only []string) (Result, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res := s.sync(bounded, ctx, only)
	if res.Outcome == OutcomeFailed && ctx.Err() != nil {
		return res, true
	}
	// A sync that did not publish leaves the bundle published as it was: if
	// a rotation left it under the old key, it is re-sealed now (I1).
	if res.Outcome != OutcomePublished {
		if resealed, err := s.reseal(); err != nil && res.Outcome == OutcomeUnchanged {
			res = Result{Outcome: OutcomeFailed, Sequence: res.Sequence, Bundle: res.Bundle, Reason: oneLine(err)}
		} else if err != nil {
			res.Reason += "; and " + oneLine(err) // the refusal or failure stays the sync's outcome
		} else if resealed {
			res.Sequence = s.current.Load().Doc.Sequence
		}
	}
	s.Metrics.Syncs.WithLabelValues(trigger, res.Outcome).Inc()
	s.Metrics.SyncRefused.Set(b2f(res.Outcome == OutcomeRefused))
	s.Metrics.SyncFailing.Set(b2f(res.Outcome == OutcomeFailed))
	if res.Outcome == OutcomePublished || res.Outcome == OutcomeUnchanged {
		s.Metrics.LastGood.Set(float64(s.Now().Unix()))
	}
	s.say(trigger, res)
	return res, false
}

// sync fetches under ctx, the bounded one; caller is Sync's own, whose end
// (a shutdown) is no source's error.
func (s *Syncer) sync(ctx, caller context.Context, only []string) Result {
	prev := s.current.Load()
	held := func(r Result) Result {
		if prev != nil {
			r.Sequence, r.Bundle = prev.Doc.Sequence, prev.Doc.Bundle
		}
		return r
	}
	policyRaw, err := readPolicy(s.PolicyFile)
	if err != nil {
		return held(Result{Outcome: OutcomeFailed, Reason: "policy_file " + s.PolicyFile + ": " + oneLine(err)})
	}
	var inv admission.Inventory
	sources := map[string][]string{}
	owner := map[string]string{}
	var leftOut []string
	type owned struct {
		src string
		d   admission.Device
	}
	var kept []owned
	if s.fetched == nil {
		s.fetched = map[string]admission.Inventory{}
	}
	for _, src := range s.Sources {
		got, cached := s.fetched[src.Name()]
		if !cached || len(only) == 0 || slices.Contains(only, src.Name()) {
			var err error
			if got, err = src.Fetch(ctx); err != nil {
				if caller.Err() == nil {
					s.Metrics.SourceErrors.WithLabelValues(src.Name()).Inc()
				}
				return held(Result{Outcome: OutcomeFailed, Reason: "source " + src.Name() + ": " + oneLine(err)})
			}
			// Kept only once fetched whole: a failed fetch leaves the last one.
			s.fetched[src.Name()] = got
		}
		for i, d := range got.Devices {
			// The one rule port49d's Open applies (pre-flight M2).
			if why := bundle.DeviceProblem(d); why != "" {
				leftOut = append(leftOut, fmt.Sprintf("source %s: device %s %s", src.Name(), deviceLabel(i, d.Name), why))
				continue
			}
			kept = append(kept, owned{src.Name(), d})
		}
	}
	// Counted once every source is read, before any refusal below.
	s.Metrics.LeftOut.Set(float64(len(leftOut)))
	for _, k := range kept {
		if o, dup := owner[k.d.Name]; dup {
			return held(Result{Outcome: OutcomeRefused, Reason: fmt.Sprintf("device %s is in both source %s and source %s; "+
				"a device name is one device", k.d.Name, o, k.src)})
		}
		owner[k.d.Name] = k.src
		inv.Devices = append(inv.Devices, k.d)
		sources[k.src] = append(sources[k.src], k.d.Name)
	}
	for _, names := range sources {
		slices.Sort(names)
	}
	if err := admission.Validate(inv.Devices); err != nil {
		return held(Result{Outcome: OutcomeRefused, Reason: oneLine(err)})
	}
	// The service knows no port49d's key names (Env.KeyRefs nil): key_refs are
	// each daemon's to check (spec §10).
	next, err := bundle.Parse(policyRaw, inv, policy.Env{})
	if err != nil {
		return held(Result{Outcome: OutcomeFailed, Reason: "policy_file " + s.PolicyFile + ": " + oneLine(err)})
	}
	var prevPol *policy.Policy
	if prev != nil {
		// The bundle published, judged under the policy the service holds
		// now: what the sources changed, not what the policy did.
		if prevPol, err = bundle.Parse(policyRaw, prev.Inv, policy.Env{}); err != nil {
			return held(Result{Outcome: OutcomeFailed, Reason: "the bundle published does not load under policy_file " +
				s.PolicyFile + ": " + oneLine(err)})
		}
	}
	present := map[string]bool{}
	for name := range owner {
		present[name] = true
	}
	if err := checkSafety(prev, prevPol, next, present, s.Bounds, s.Default, s.PolicyFile); err != nil {
		return held(Result{Outcome: OutcomeRefused, Reason: err.Error()})
	}
	now := s.Now()
	quarantined := quarantinedIn(next, now)
	if prev != nil && prev.Doc.Bundle == next.Bundle && maps.EqualFunc(prev.Doc.Sources, sources, slices.Equal[[]string]) {
		return held(Result{Outcome: OutcomeUnchanged, Quarantined: quarantined, LeftOut: leftOut})
	}
	seq, err := s.nextSequence(prev)
	if err != nil {
		return held(Result{Outcome: OutcomeFailed, Reason: "state_dir " + s.State.Dir + ": " + oneLine(err)})
	}
	doc := bundle.NewDocument(seq, s.publishedAt(prev, now), policyRaw, next.PlatformSet(), inv, sources)
	raw, err := bundle.Seal(doc, s.Key)
	if err != nil {
		return held(Result{Outcome: OutcomeFailed, Reason: "sealing bundle " + fmt.Sprint(seq) + ": " + oneLine(err)})
	}
	p := &Published{Raw: raw, Doc: doc, Inv: inv}
	// Kept before served: a bundle the service could not keep is not
	// published, so a restart never serves an older one after a newer.
	if err := s.State.Save(*p); err != nil {
		return held(Result{Outcome: OutcomeFailed, Reason: "state_dir " + s.State.Dir + ": " + oneLine(err)})
	}
	s.publish(p)
	if prevPol == nil {
		return Result{Outcome: OutcomePublished, Sequence: seq, Bundle: next.Bundle,
			Summary: fmt.Sprintf("first bundle: +%d device(s)", len(inv.Devices)), Quarantined: quarantined, LeftOut: leftOut}
	}
	rep := bundle.Diff(prevPol, next, now)
	return Result{Outcome: OutcomePublished, Sequence: seq, Bundle: next.Bundle, Summary: rep.Summary(), Changes: rep.Changes,
		Quarantined: quarantined, LeftOut: leftOut}
}

// nextSequence is the sequence the next bundle is published as: above the
// bundle in force, prev, and above every one state_dir keeps. They differ
// only after a Save that wrote published.json and then failed — a full
// disk — which leaves bundle N+1 there but not in force; publishing N+1
// again would be refused as not above it at every sync until a restart
// (final review Minor 2).
func (s *Syncer) nextSequence(prev *Published) (int64, error) {
	floor, err := s.State.floor()
	if err != nil {
		return 0, err
	}
	if prev != nil {
		floor = max(floor, prev.Doc.Sequence)
	}
	return floor + 1, nil
}

// publishedAt is when the next bundle is published: now, or, when this
// host's clock has stepped back to or before the bundle in force's
// published_at, a second after it, said. port49d refuses a document not
// later than the one it holds, so a stable fleet would otherwise leave every
// port49d refusing, and its snapshot ageing, until the fleet next changed
// (final review Minor 3).
func (s *Syncer) publishedAt(prev *Published, now time.Time) time.Time {
	if prev == nil || now.After(prev.Doc.PublishedAt) {
		return now
	}
	at := prev.Doc.PublishedAt.Add(time.Second)
	fmt.Fprintf(s.Log, "port49-inventory: this host's clock (%s) is not after bundle %d's published_at (%s); the "+
		"next bundle is published at %s so every port49d takes it as later: check this host's NTP\n",
		now.UTC().Format(time.RFC3339), prev.Doc.Sequence, prev.Doc.PublishedAt.Format(time.RFC3339),
		at.Format(time.RFC3339))
	return at
}

// mirror brings the mirror's copy level with the bundle published,
// whenever it differs — at Restore and after every sync, whatever the sync
// found — so a failed write is retried and a wiped volume refilled (spec
// §10: the store "holds the most recent bundle"; pre-flight M7). Reading it
// costs one bounded read, under mirrorIO's deadline, and never under the
// sync lock. port49_inventory_mirror_behind is 1 from before the read until
// the copy is shown level, so a mount that hangs shows at once (final review
// I3). A failure is said once per distinct fault and counted; one cut short
// by ctx — a shutdown — is neither.
func (s *Syncer) mirror(ctx context.Context) {
	cur := s.current.Load()
	if s.State.MirrorDir == "" || cur == nil {
		return
	}
	s.Metrics.MirrorBehind.Set(1)
	err := s.mirrorIO(ctx, func() error {
		if have, err := s.State.MirrorRaw(); err == nil && bytes.Equal(have, cur.Raw) {
			return nil
		}
		return s.State.WriteMirror(cur.Raw)
	})
	if ctx.Err() != nil {
		return
	}
	s.mirrorMu.Lock()
	defer s.mirrorMu.Unlock()
	if err == nil {
		s.Metrics.MirrorBehind.Set(0)
		s.mirrorSaid = ""
		return
	}
	s.Metrics.MirrorFailures.Inc()
	if msg := oneLine(err); msg != s.mirrorSaid {
		s.mirrorSaid = msg
		fmt.Fprintf(s.Log, "port49-inventory: mirror_dir %s: %s; the bundle is published from the API and "+
			"state_dir, and a port49d starting with neither the service nor its own copy waits for one\n",
			s.State.MirrorDir, msg)
	}
}

// errMirrorHung is a read or write of mirror_dir that did not return by
// its deadline, or one started while an earlier one is still out.
var errMirrorHung = errors.New("mirror_dir did not answer")

// mirrorIO runs op, a read or write of mirror_dir, in a goroutine and waits
// for it until the deadline (10s) or ctx ends, as port49d reads the mirror
// (pre-flight M4): a FUSE, NFS or object-store CSI mount that hangs blocks
// in the kernel, and O_NONBLOCK does not help on a regular file. One that
// does not return is abandoned, and no other is started while it is still
// out — each later call fails at once — so a hang costs one goroutine, not
// one per sync.
func (s *Syncer) mirrorIO(ctx context.Context, op func() error) error {
	s.mirrorMu.Lock()
	if s.mirrorOut != nil {
		select {
		case <-s.mirrorOut:
			s.mirrorOut = nil
		default:
			s.mirrorMu.Unlock()
			return fmt.Errorf("mirror_dir %s has not answered a read or write started earlier, which is abandoned: %w",
				s.State.MirrorDir, errMirrorHung)
		}
	}
	done := make(chan struct{})
	s.mirrorOut = done
	deadline := s.mirrorDeadline
	s.mirrorMu.Unlock()
	if deadline == 0 {
		deadline = 10 * time.Second
	}
	var err error
	go func() { err = op(); close(done) }()
	timer := time.NewTimer(deadline)
	defer timer.Stop()
	select {
	case <-done:
		s.mirrorMu.Lock()
		if s.mirrorOut == done {
			s.mirrorOut = nil
		}
		s.mirrorMu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return fmt.Errorf("mirror_dir %s did not answer in %s: %w", s.State.MirrorDir, deadline, errMirrorHung)
	}
}

// quarantinedIn is every device next quarantines now, its cause redacted by
// the policy's patterns (spec §5.8): a cause quotes rule text.
func quarantinedIn(next *policy.Policy, now time.Time) []QuarantinedDevice {
	var out []QuarantinedDevice
	for _, q := range next.Quarantines(now) {
		for _, e := range q.Entries {
			if e.Current(now) {
				out = append(out, QuarantinedDevice{Device: q.Device, Platform: q.Platform,
					Cause: platform.RedactQuoted(next.Redactions(), e.Cause)})
				break
			}
		}
	}
	return out
}

// say writes what a sync did: a publication in full, a refusal or failure
// once per distinct reason, and an unchanged sync only when it ends one.
func (s *Syncer) say(trigger string, res Result) {
	switch res.Outcome {
	case OutcomePublished:
		s.said = ""
		fmt.Fprintf(s.Log, "port49-inventory: sync (%s): published bundle %d (%s): %s; %d quarantined\n", trigger,
			res.Sequence, res.Bundle, res.Summary, len(res.Quarantined))
		for _, c := range res.Changes {
			if c.Security {
				fmt.Fprintf(s.Log, "port49-inventory: bundle %d: %s\n", res.Sequence, c.Line(""))
			}
		}
		for _, q := range res.Quarantined {
			fmt.Fprintf(s.Log, "port49-inventory: bundle %d: device %s (%s) is quarantined against the service's "+
				"policy: %s\n", res.Sequence, q.Device, q.Platform, q.Cause)
		}
		for _, l := range res.LeftOut {
			fmt.Fprintf(s.Log, "port49-inventory: bundle %d: left out: %s\n", res.Sequence, l)
		}
		s.leftOutSaid = res.LeftOut
	case OutcomeUnchanged:
		if s.said != "" {
			s.said = ""
			fmt.Fprintf(s.Log, "port49-inventory: sync (%s): the sources and the policy are as bundle %d has them "+
				"again\n", trigger, res.Sequence)
		}
		// A device left out that leaves the bundle as it was is said too,
		// once: the gauge alone would not name it.
		for _, l := range res.LeftOut {
			if !slices.Contains(s.leftOutSaid, l) {
				fmt.Fprintf(s.Log, "port49-inventory: bundle %d: left out: %s\n", res.Sequence, l)
			}
		}
		s.leftOutSaid = res.LeftOut
	default:
		if key := res.Outcome + "\x00" + res.Reason; key != s.said {
			s.said = key
			still := "no bundle is published yet"
			if res.Sequence > 0 {
				still = fmt.Sprintf("still publishing bundle %d", res.Sequence)
			}
			fmt.Fprintf(s.Log, "port49-inventory: sync (%s) %s; %s: %s\n", trigger, res.Outcome, still, res.Reason)
		}
	}
}

// ErrNoBundle is Diff's error before the first bundle is published.
var ErrNoBundle = errors.New("no bundle is published yet")

// Diff is what changed from bundle from to the bundle published, both judged
// under the policy the service holds now (spec §12, `inventory diff
// --service`), and that bundle's sequence: one snapshot, so a sync publishing
// meanwhile cannot put a later sequence beside an earlier diff. A bundle no
// longer kept is ErrNotKept.
func (s *Syncer) Diff(from int64) (bundle.Report, int64, error) {
	cur := s.current.Load()
	if cur == nil {
		return bundle.Report{}, 0, ErrNoBundle
	}
	old, err := s.State.At(from, s.keys())
	if err != nil {
		return bundle.Report{}, 0, err
	}
	raw, err := readPolicy(s.PolicyFile)
	if err != nil {
		return bundle.Report{}, 0, err
	}
	o, err := bundle.Parse(raw, old.Inv, policy.Env{})
	if err != nil {
		return bundle.Report{}, 0, err
	}
	n, err := bundle.Parse(raw, cur.Inv, policy.Env{})
	if err != nil {
		return bundle.Report{}, 0, err
	}
	return bundle.Diff(o, n, s.Now()), cur.Doc.Sequence, nil
}

// DeviceView is one device as GET /v1/devices/{address} shows it: a
// diagnostic, never on a hot path (spec §10).
type DeviceView struct {
	Name       string            `json:"name"`
	Platform   string            `json:"platform"`
	Addresses  []string          `json:"addresses"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Transport  string            `json:"transport"`
	Admission  string            `json:"admission"`
}

// Describe is the device the bundle published gives addr to, with its
// admission under the service's policy.
func (s *Syncer) Describe(addr netip.Addr) (DeviceView, bool) {
	cur := s.current.Load()
	if cur == nil {
		return DeviceView{}, false
	}
	for _, d := range cur.Inv.Devices {
		if !slices.Contains(d.Addresses, addr) {
			continue
		}
		v := DeviceView{Name: d.Name, Platform: d.Platform, Attributes: d.Attributes, Transport: d.Transport,
			Admission: "unknown: policy_file does not load"}
		for _, a := range d.Addresses {
			v.Addresses = append(v.Addresses, a.String())
		}
		if raw, err := readPolicy(s.PolicyFile); err == nil {
			if pol, err := bundle.Parse(raw, cur.Inv, policy.Env{}); err == nil {
				v.Admission = "admitted"
				if r, _ := pol.Admitted(d.Name); r.Refused != "" {
					v.Admission = "refused: " + r.Refused
				}
				if cause, q := pol.Quarantined(d.Name, s.Now()); q {
					v.Admission = "quarantined: " + platform.RedactQuoted(pol.Redactions(), cause)
				}
			}
		}
		return v, true
	}
	return DeviceView{}, false
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// oneLine is err's text on one line.
func oneLine(err error) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(err.Error(), "\n", "; ")), " ")
}
