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
	"github.com/rhwendt/port49/internal/config"
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
	// said is the last refusal or failure said, and mirrorSaid the last mirror
	// fault, so each is said once.
	said, mirrorSaid string
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

// Current is the bundle published, or nil before the first.
func (s *Syncer) Current() *Published { return s.current.Load() }

// keys are every key the service reads its own state and mirror against.
func (s *Syncer) keys() []ed25519.PublicKey {
	return append([]ed25519.PublicKey{s.Key.Public().(ed25519.PublicKey)}, s.VerifyKeys...)
}

// Restore serves what the service last published, the newer of state_dir's
// copy and the mirror's, so a restart serves at once and continues the
// sequence (Decided 3). A copy that is there but does not open or verify is
// an error, and the service does not start: passed over, with state_dir lost,
// it would start the sequence again at 1, unbounded, below the copy every
// port49d holds (review of Task 9, Important 1). A copy that is not there at
// all is a fresh start. It holds the sync lock, so it is safe beside a sync.
func (s *Syncer) Restore() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := s.keys()
	var best *Published
	for _, c := range []struct {
		what string
		get  func([]ed25519.PublicKey) (*Published, error)
	}{{"state_dir " + s.State.Dir, s.State.Latest}, {"mirror_dir " + s.State.MirrorDir, s.State.Mirror}} {
		p, err := c.get(keys)
		if err != nil {
			// Open's and the fence's errors name the file and quote nothing in it.
			return fmt.Errorf("port49-inventory: %s holds a bundle the service cannot open: %s; the service does "+
				"not start below it: if a signing key was rotated, add the old key to verify_key_files; to start "+
				"fresh, move it aside", c.what, oneLine(err))
		}
		if p != nil && (best == nil || p.Doc.Sequence > best.Doc.Sequence) {
			best = p
		}
	}
	if best == nil {
		fmt.Fprintln(s.Log, "port49-inventory: no bundle published yet; the first sync publishes bundle 1, bounded "+
			"by each port49d")
		return nil
	}
	s.publish(best)
	fmt.Fprintf(s.Log, "port49-inventory: serving bundle %d (%s), published %s\n", best.Doc.Sequence,
		best.Doc.Bundle, best.Doc.PublishedAt.Format(time.RFC3339))
	s.mirror(best.Raw) // a mirror behind the state is brought level at once (M7)
	return nil
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
// the bundle published (M7).
func (s *Syncer) Sync(ctx context.Context, trigger string, only ...string) Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res := s.sync(ctx, only)
	if cur := s.current.Load(); cur != nil {
		s.mirror(cur.Raw)
	}
	s.Metrics.Syncs.WithLabelValues(trigger, res.Outcome).Inc()
	s.Metrics.SyncRefused.Set(b2f(res.Outcome == OutcomeRefused))
	s.Metrics.SyncFailing.Set(b2f(res.Outcome == OutcomeFailed))
	if res.Outcome == OutcomePublished || res.Outcome == OutcomeUnchanged {
		s.Metrics.LastGood.Set(float64(s.Now().Unix()))
	}
	s.say(trigger, res)
	return res
}

func (s *Syncer) sync(ctx context.Context, only []string) Result {
	prev := s.current.Load()
	held := func(r Result) Result {
		if prev != nil {
			r.Sequence, r.Bundle = prev.Doc.Sequence, prev.Doc.Bundle
		}
		return r
	}
	policyRaw, err := config.ReadRegular(s.PolicyFile, maxPolicy)
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
				s.Metrics.SourceErrors.WithLabelValues(src.Name()).Inc()
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
	seq := int64(1)
	if prev != nil {
		seq = prev.Doc.Sequence + 1
	}
	doc := bundle.NewDocument(seq, now, policyRaw, next.PlatformSet(), inv, sources)
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

// mirror brings the mirror's copy level with raw, the bundle published,
// whenever it differs — at Restore and after every sync, whatever the sync
// found — so a failed write is retried and a wiped volume refilled (spec
// §10: the store "holds the most recent bundle"; pre-flight M7). Reading it
// costs one bounded read. A failure is said once per distinct fault and
// counted; port49_inventory_mirror_behind is 1 until the copy is level.
func (s *Syncer) mirror(raw []byte) {
	if s.State.MirrorDir == "" {
		return
	}
	if have, err := s.State.MirrorRaw(); err == nil && bytes.Equal(have, raw) {
		s.Metrics.MirrorBehind.Set(0)
		s.mirrorSaid = ""
		return
	}
	s.Metrics.MirrorBehind.Set(1)
	if err := s.State.WriteMirror(raw); err != nil {
		s.Metrics.MirrorFailures.Inc()
		if msg := oneLine(err); msg != s.mirrorSaid {
			s.mirrorSaid = msg
			fmt.Fprintf(s.Log, "port49-inventory: mirror_dir %s: %s; the bundle is published from the API and "+
				"state_dir, and a port49d starting with neither the service nor its own copy waits for one\n",
				s.State.MirrorDir, msg)
		}
		return
	}
	s.Metrics.MirrorBehind.Set(0)
	s.mirrorSaid = ""
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

// Diff is what changed from bundle from to the bundle published, both judged
// under the policy the service holds now (spec §12, `inventory diff
// --service`).
func (s *Syncer) Diff(from int64) (bundle.Report, error) {
	cur := s.current.Load()
	if cur == nil {
		return bundle.Report{}, errors.New("no bundle is published yet")
	}
	old, err := s.State.At(from, s.keys())
	if err != nil {
		return bundle.Report{}, err
	}
	raw, err := config.ReadRegular(s.PolicyFile, maxPolicy)
	if err != nil {
		return bundle.Report{}, err
	}
	o, err := bundle.Parse(raw, old.Inv, policy.Env{})
	if err != nil {
		return bundle.Report{}, err
	}
	n, err := bundle.Parse(raw, cur.Inv, policy.Env{})
	if err != nil {
		return bundle.Report{}, err
	}
	return bundle.Diff(o, n, s.Now()), nil
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
		if raw, err := config.ReadRegular(s.PolicyFile, maxPolicy); err == nil {
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
