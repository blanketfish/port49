package port49d

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/policy"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
)

// judgedReader reads meta/judged (etcd.Store).
type judgedReader interface {
	Judged(ctx context.Context) (etcdstore.JudgedRecord, bool, error)
}

// startRefusal is guardAtStart's refusal: the reload guard's error, the
// bundle last judged, and its policy, which the line redacts with.
type startRefusal struct {
	err    error
	bundle string
	old    *policy.Policy
}

func (s *startRefusal) Error() string { return s.err.Error() }
func (s *startRefusal) Unwrap() error { return s.err }

// guardAtStart is the reload guard run at a broker's start, against the
// policy meta/judged records (plan 7e, Ruling 17; 7c's carry): a rollout
// restarts every replica onto the file on disk, and a file a running
// broker refused would otherwise be carried into every context and its
// newly refused devices' tokens deleted. refused is the guard's error, a
// *startRefusal. When it cannot judge (no record, a record with no policy,
// a recorded policy that no longer compiles against the inventory in
// force), said names why and the start goes on: the guard is a typo guard,
// and a broker stranded by an inventory edit would cost every login. A
// record that could not be read is not one that is absent: refused is
// that error, and the start waits for an answer, failing closed.
//
// The recorded policy is compiled with compileBundle, which does not require
// a keys: block: the bundle last judged may predate the upgrade that put the
// keys in the policy, and the first start after it must still be judged
// (pre-flight M14). With no block declared, admit refuses no device for its
// key_ref, so the recorded policy admits what it admitted when it was judged,
// and a new file whose block omits a key a key group names counts those
// devices as removed.
func guardAtStart(ctx context.Context, cfg config.Config, judged judgedReader, pol *policy.Policy,
	now time.Time) (refused error, said string) {
	rec, ok, err := judged.Judged(ctx)
	switch {
	case err != nil:
		return fmt.Errorf("reading the bundle last judged: %w", err), ""
	case !ok:
		return nil, "no bundle has been judged on this keyspace; this start is not judged against one"
	case rec.Bundle == pol.Bundle:
		return nil, ""
	case rec.Policy == nil:
		return nil, fmt.Sprintf("the bundle last judged (%s) was recorded without its policy (over 1 MiB); "+
			"this start is not judged against it", rec.Bundle)
	}
	old, err := compileBundle(cfg, rec.Policy, pol.Inventory())
	if err != nil {
		return nil, fmt.Sprintf("the policy last judged (%s) does not compile against the inventory in force (%v); "+
			"this start is not judged against it", rec.Bundle, oneLine(err))
	}
	if err := bundle.CheckAdmission(old, pol, cfg.MaxRemovedPercent, now); err != nil {
		return &startRefusal{err: fmt.Errorf("%s: %w", policyKey(cfg), err), bundle: rec.Bundle, old: old}, ""
	}
	return nil, ""
}

// passGuardAtStart runs guardAtStart on the policy live holds, at
// port49-broker's start, once the store has answered and before anything
// that mints serves (Ruling 17; pre-flight I6). A refusal, or a record
// that could not be read, holds the start: the runner is not started, the
// API is not served and /readyz answers 503 (broker.ReadyStarting), with
// port49_policy_file_refused at 1 for a refusal. Meanwhile it reads
// broker.policy_file every policy_watch_interval, as a start compiles it
// (startPolicy), and runs the guard again; each refusal and each fault is
// said once per version. Once a version passes it is put in force in live,
// said as a start says it, and the start goes on. It returns ctx.Err() if
// ctx ends first.
func passGuardAtStart(ctx context.Context, cfg config.Config, judged judgedReader, live *policy.Live,
	inventoryFrom string, m *metrics.Metrics) error {
	pol, version := live.Load(), live.Load().Source
	var saidRefused, saidRead, saidFile string
	t := time.NewTicker(cfg.Policy.WatchInterval)
	defer t.Stop()
	for {
		if pol != nil {
			rctx, cancel := context.WithTimeout(ctx, 4*cfg.Stores.Session.Etcd.CallTimeout)
			refused, said := guardAtStart(rctx, cfg, judged, pol, time.Now())
			cancel()
			var sr *startRefusal
			switch {
			case ctx.Err() != nil:
				return ctx.Err()
			case refused == nil:
				if said != "" {
					fmt.Fprintf(stderr, "port49-broker: policy: %s\n", said)
				}
				if saidRefused != "" || saidFile != "" {
					m.PolicyFileRefused.Set(0)
				}
				if pol != live.Load() {
					live.Swap(pol)
					fmt.Fprintf(stderr, "port49-broker: policy: %s %s passes the guard at start (bundle %s); "+
						"starting\n", policyKey(cfg), cfg.Policy.File, pol.Bundle)
					now := time.Now()
					sayPolicy(procOf(cfg), pol, now)
					sayFailClosed(procOf(cfg), pol, now, m)
				}
				return nil
			case errors.As(refused, &sr):
				m.PolicyFileRefused.Set(1)
				if saidRefused != version {
					saidRefused = version
					// Flattened: refusalLine's reload tail says the file is not
					// what is serving, and nothing serves here yet.
					fmt.Fprintf(stderr, "port49-broker: policy file refused at start against the bundle last judged "+
						"(%s): %s; this replica stays not ready, mints nothing and takes no hold until %s is fixed\n",
						lineBundle(sr.bundle),
						brokerStartWording(redactedLine(sr.err, []*policy.Policy{sr.old, pol})),
						policyKey(cfg))
				}
			default:
				if line := oneLine(refused); line != saidRead {
					saidRead = line
					fmt.Fprintf(stderr, "port49-broker: policy: %s; this replica stays not ready, mints nothing and "+
						"takes no hold until it is read; trying again every %v\n", line, cfg.Policy.WatchInterval)
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
		raw, v, err := policyVersion(cfg.Policy.File)
		if v == version {
			continue
		}
		version, pol = v, nil
		if err == nil {
			pol, err = startPolicy(cfg, raw, inventoryFrom)
		} else {
			err = fmt.Errorf("%s %s: %w", policyKey(cfg), cfg.Policy.File, err)
		}
		if err != nil {
			m.PolicyFileRefused.Set(1)
			saidFile = version
			fmt.Fprintf(stderr, "port49-broker: policy: %s; this replica stays not ready until it is fixed\n",
				refusalLine("port49-broker", err, false, live.Load()))
		}
	}
}
