package port49d

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/printsafe"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
)

// heldCA is the issuing CA this broker's files hold, by fingerprint.
type heldCA struct{ current, previous string }

// heldIssuer reads cfg's broker's issuing CA for the record (decision 53
// ruling 10): ok is false with no issuance or no usable CA, which the start
// says already and which issues nothing to check.
func heldIssuer(cfg config.Config, now time.Time) (heldCA, bool) {
	if cfg.Broker == nil || cfg.Broker.Identity == nil || cfg.Broker.Identity.Issuance == nil {
		return heldCA{}, false
	}
	ca, _ := issuer.Load(issuerFiles(brokerStateDir(cfg)), now)
	if ca.Unavailable != nil || ca.Cert == nil {
		return heldCA{}, false
	}
	h := heldCA{current: issuer.Fingerprint(ca.Cert)}
	if ca.Previous != nil {
		h.previous = issuer.Fingerprint(ca.Previous)
	}
	return h, true
}

type issuerRecorder interface {
	IssuerRecord(context.Context) (etcdstore.IssuerRecord, uint64, error)
	PutIssuerRecord(context.Context, etcdstore.IssuerRecord, uint64) (bool, error)
}

// checkIssuerRecord holds this broker's CA to the store's record (decision 53
// ruling 10): it records one where there is none, follows a promotion its
// own files show, and refuses any other difference, saying what to copy. The
// record holds fingerprints alone; the key stays on each broker's disk.
func checkIssuerRecord(ctx context.Context, rec issuerRecorder, held heldCA, who string, out io.Writer) error {
	for range 3 {
		r, rev, err := rec.IssuerRecord(ctx)
		if err != nil {
			return err
		}
		next := etcdstore.IssuerRecord{Current: held.current, Previous: held.previous, WrittenBy: who}
		switch {
		case rev == 0:
			ok, err := rec.PutIssuerRecord(ctx, next, 0)
			if err != nil {
				return err
			}
			if !ok {
				continue // another broker recorded first: judge against it
			}
			fmt.Fprintf(out, "port49-broker: issuance: recorded the issuing CA %s in the store; every broker on it "+
				"must issue from it\n", held.current)
			return nil
		case r.Current == held.current:
			return nil
		case held.previous != "" && held.previous == r.Current:
			ok, err := rec.PutIssuerRecord(ctx, next, rev)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			fmt.Fprintf(out, "port49-broker: issuance: the store's issuing CA is now %s, promoted from %s on this "+
				"broker; copy the files rotate-issuer named to every other broker, then restart each\n",
				held.current, held.previous)
			return nil
		case r.Previous != "" && held.current == r.Previous:
			return fmt.Errorf("issuance: this broker's issuing CA (%s) is behind a promotion: the store records %s, "+
				"promoted from it by %s at %s. Copy %s, %s and %s from that broker into broker.state_dir, then "+
				"start", held.current, r.Current, printsafe.Line(r.WrittenBy, 120), r.WrittenAt.Format(time.RFC3339),
				issuer.CertFile, issuer.KeyFile, issuer.PreviousCertFile)
		default:
			return fmt.Errorf("issuance: this broker's issuing CA (%s) is not the one the store records (%s, by %s "+
				"at %s): every broker on one store issues from one CA. Copy %s and %s from a broker that holds it; "+
				"if every broker lost it, run `port49-broker forget-issuer` once, then init-issuer on one broker "+
				"and copy its files to the others", held.current, r.Current, printsafe.Line(r.WrittenBy, 120),
				r.WrittenAt.Format(time.RFC3339), issuer.CertFile, issuer.KeyFile)
		}
	}
	return errors.New("issuance: the store's issuing CA record kept changing under this start; start again")
}

// forgetIssuer is `port49-broker forget-issuer [--config FILE]`: it removes
// the store's issuing CA record, for when every broker lost the CA. The next
// broker start records its own.
func forgetIssuer(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49-broker forget-issuer", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfgPath := fs.String("config", "/etc/port49/port49-broker.yaml", "path to port49-broker.yaml")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: port49-broker forget-issuer [--config FILE]")
		return 2
	}
	cfg, err := config.LoadBroker(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "port49-broker:", err)
		return 1
	}
	ref := sessionRef(cfg)
	if !cfg.Stores.Shared {
		ref = directoryRef(cfg)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	s, err := attempt(ctx, cfg, ref, metrics.New(prometheus.NewRegistry()), stderr, false)
	if err != nil {
		fmt.Fprintln(stderr, "port49-broker: store:", err)
		return 1
	}
	defer s.Close()
	old, removed, err := s.DeleteIssuerRecord(ctx)
	switch {
	case err != nil:
		fmt.Fprintln(stderr, "port49-broker:", err)
		return 1
	case !removed:
		fmt.Fprintln(stdout, "port49-broker: no issuing CA record to remove")
	default:
		fmt.Fprintf(stdout, "port49-broker: removed the issuing CA record (%s, by %s at %s); the next broker start "+
			"records its own\n", old.Current, printsafe.Line(old.WrittenBy, 120), old.WrittenAt.Format(time.RFC3339))
	}
	return 0
}
