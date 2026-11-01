package port49d

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/issuer"
	"github.com/blanketfish/port49/internal/printsafe"
	etcdstore "github.com/blanketfish/port49/internal/store/etcd"
)

// heldCA is the issuing CA this broker's files hold, by fingerprint.
type heldCA struct{ current, previous string }

// loadedIssuer is the issuing CA read from the broker's files once, at the
// start: the record check and the issuer are made from this one read, so the
// CA that issues is the CA that was checked (decision 53 ruling 10).
type loadedIssuer struct {
	ca    *issuer.CA
	lines []string
}

// loadIssuer reads cfg's broker's issuing CA; nil with no issuance.
func loadIssuer(cfg config.Config, now time.Time) *loadedIssuer {
	if cfg.Broker == nil || cfg.Broker.Identity == nil || cfg.Broker.Identity.Issuance == nil {
		return nil
	}
	ca, lines := issuer.Load(issuerFiles(brokerStateDir(cfg)), now)
	return &loadedIssuer{ca: ca, lines: lines}
}

// held is the CA for the record: ok is false with no issuance or no usable
// CA, which the start says already and which issues nothing to check.
func (l *loadedIssuer) held() (heldCA, bool) {
	if l == nil || l.ca.Unavailable != nil || l.ca.Cert == nil {
		return heldCA{}, false
	}
	h := heldCA{current: issuer.Fingerprint(l.ca.Cert)}
	if l.ca.Previous != nil {
		h.previous = issuer.Fingerprint(l.ca.Previous)
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
		// Behind before promoted: files {f1, previous f2} against a record
		// {f2, previous f1} are the retired CA coming back, never a rotation.
		case r.Previous != "" && held.current == r.Previous:
			return fmt.Errorf("issuance: this broker's issuing CA (%s) is behind a promotion: the store records %s, "+
				"promoted from it by %s at %s. Copy %s, %s and %s from that broker into broker.state_dir, then "+
				"start", held.current, r.Current, printsafe.Line(r.WrittenBy, 120), r.WrittenAt.Format(time.RFC3339),
				issuer.CertFile, issuer.KeyFile, issuer.PreviousCertFile)
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

// forgetIssuer is `port49-broker forget-issuer --current sha256:HEX [--config
// FILE]`: it removes the store's issuing CA record, for when every broker lost
// the CA. Forgetting re-opens the store to any CA, so it names the CA it
// forgets: a record that holds another one is kept, and the delete is over the
// revision read, so a broker that recorded meanwhile keeps its record. The
// next broker start records its own.
func forgetIssuer(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49-broker forget-issuer", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfgPath := fs.String("config", "/etc/port49/port49-broker.yaml", "path to port49-broker.yaml")
	current := fs.String("current", "", "the fingerprint of the issuing CA to forget, sha256:<hex>")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *current == "" {
		fmt.Fprintln(stderr, "usage: port49-broker forget-issuer --current sha256:<hex> [--config FILE]  (the "+
			"issuing CA the store records, which a broker's start prints)")
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
	r, rev, err := s.IssuerRecord(ctx)
	switch {
	case err != nil:
		fmt.Fprintln(stderr, "port49-broker:", err)
		return 1
	case rev == 0:
		fmt.Fprintln(stdout, "port49-broker: no issuing CA record to remove")
		return 0
	case r.Current != strings.ToLower(*current):
		fmt.Fprintf(stderr, "port49-broker: the store's issuing CA is %s (by %s at %s), not the one named; nothing removed\n",
			r.Current, printsafe.Line(r.WrittenBy, 120), r.WrittenAt.Format(time.RFC3339))
		return 1
	}
	removed, err := s.DeleteIssuerRecord(ctx, rev)
	switch {
	case err != nil:
		fmt.Fprintln(stderr, "port49-broker:", err)
		return 1
	case !removed:
		fmt.Fprintln(stderr, "port49-broker: the record changed while it was read; nothing removed; run forget-issuer again")
		return 1
	}
	fmt.Fprintf(stdout, "port49-broker: removed the issuing CA record (%s, by %s at %s); the next broker start "+
		"records its own\n", r.Current, printsafe.Line(r.WrittenBy, 120), r.WrittenAt.Format(time.RFC3339))
	fmt.Fprintf(stderr, "port49-broker: forgot issuing CA %s; stop every broker on this store before starting one on "+
		"another CA\n", r.Current)
	return 0
}
