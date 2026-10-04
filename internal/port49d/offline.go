package port49d

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/admin"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/session"
	"github.com/rhwendt/port49/internal/store/crypt"
	"github.com/rhwendt/port49/internal/store/guard"
)

// offlineSay begins each line of port49-broker revoke --offline.
const offlineSay = "port49-broker: revoke (offline, no API): "

// offlineRevoke is `port49-broker revoke --offline` (plan 7e, Ruling 13;
// pre-flight I4): the break-glass revocation with every port49-broker
// down, when port49 revoke has no admin socket to ask. It runs the whole
// revocation, or a lift, through the store on the broker's identity, as
// the admin socket's would: the mark, the unspent tokens deleted, the live
// contexts marked revoked. port49d's marks feed brings the mark to every
// session, and the next port49-broker start loads it before it serves, so
// nothing mints for the principal after. It takes no hold, binds nothing
// and keeps no copy; the report goes to out as port49 revoke prints it,
// and the revoke record to log, port49-broker's decision log. Exit 0 on a
// whole report, 1 on an error or a partial one, 2 on a usage error.
func offlineRevoke(args []string, log, out io.Writer) int {
	fs := flag.NewFlagSet("port49-broker revoke", flag.ContinueOnError)
	fs.SetOutput(out)
	offline := fs.Bool("offline", false, "revoke through the store with every port49-broker down")
	cfgPath := fs.String("config", "/etc/port49/port49-broker.yaml", "path to port49-broker.yaml")
	principal := fs.String("principal", "", "the principal, as the log names it: user:alice@example.com")
	issuer := fs.String("cert-issuer", "", "the certificate's issuer, as the broker spells it (RFC 2253: CN=…,O=…)")
	serial := fs.String("cert-serial", "", "the certificate's serial, in hex")
	lift := fs.Bool("lift", false, "lift the revocation instead")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	switch byCert := *issuer != "" || *serial != ""; {
	case fs.NArg() != 0:
		fmt.Fprintln(out, "usage: port49-broker revoke --offline [--config FILE] (--principal P | --cert-issuer I "+
			"--cert-serial S) [--lift]")
		return 2
	case !*offline:
		fmt.Fprintln(out, "port49-broker revoke: without --offline, revoke on the running broker's admin socket: "+
			"port49 revoke --socket <its admin_socket>")
		return 2
	case (*principal != "") == byCert, byCert && (*issuer == "" || *serial == ""):
		fmt.Fprintln(out, "port49-broker revoke: name --principal, or --cert-issuer and --cert-serial; one of the two")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	brk, closeStore, err := offlineBroker(ctx, *cfgPath, log, out)
	if err != nil {
		fmt.Fprintf(out, "%s%v; nothing was revoked\n", offlineSay, err)
		return 1
	}
	defer closeStore()
	req := broker.RevokeRequest{Principal: *principal, Issuer: *issuer, Serial: *serial, Origin: "offline"}
	if *lift {
		rep, err := brk.Lift(ctx, req)
		if err != nil {
			fmt.Fprintf(out, "%s%v\n", offlineSay, err)
			return 1
		}
		// The copies of the marks hold it still (marksCopy): the next runner
		// puts it back, as it would a mark an etcd restore lost.
		fmt.Fprintf(out, "%s%s\nevery port49-broker's broker.state_dir/%s still holds it: the next runner puts it "+
			"back; once a port49-broker runs, lift it again with port49 revoke --lift\n", offlineSay,
			rep.LiftedText(), stateMarksFile)
		if rep.Partial() {
			return 1
		}
		return 0
	}
	rep, err := brk.Revoke(ctx, req)
	if err != nil {
		fmt.Fprintf(out, "%s%v\n", offlineSay, err)
		return 1
	}
	fmt.Fprintf(out, "%s%s\n", offlineSay, rep.Text())
	if rep.Partial() {
		return 1
	}
	return 0
}

// offlineBroker is the broker offlineRevoke runs on: port49-broker.yaml
// at cfgPath, the policy in force there, and one attempt at the store on
// the broker's identity, its roles checked (attempt; Ruling 10), under the
// broker's guard and sealing layer with a ledger of its own and no fence:
// nothing follows the store here, and it only writes marks and revokes. No
// listener and no minter. closeStore closes the store.
func offlineBroker(ctx context.Context, cfgPath string, log, out io.Writer) (*broker.Broker, func(), error) {
	cfg, err := config.LoadBroker(cfgPath)
	if err != nil {
		return nil, nil, err
	}
	keys, err := cfg.EncryptionKeys()
	if err != nil {
		return nil, nil, err
	}
	inventoryFrom := "inventory_file " + cfg.InventoryFile
	if svc := cfg.InventoryService; svc == nil {
		if cfg.Inventory, _, err = fencedInventory(cfg); err != nil {
			return nil, nil, err
		}
	} else if cfg.Inventory, inventoryFrom, err = persistedInventory(cfg); err != nil {
		// The report's reach is the policy's to read, not the mark's: every
		// context is reported as on a platform that never asks, which says
		// to close more by hand, never fewer.
		fmt.Fprintf(out, "%sthe inventory service's persisted copy (%v): the report names every live context as "+
			"one to close on the device\n", offlineSay, err)
		inventoryFrom = "no inventory"
	}
	pol, err := loadPolicy(cfg, inventoryFrom)
	if err != nil {
		return nil, nil, err
	}
	m := metrics.New(prometheus.NewRegistry())
	b, err := attempt(ctx, cfg, m, out)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, nil, errors.New("stopped")
		}
		return nil, nil, fmt.Errorf("store: %w", err)
	}
	gc := guardConfig(procOf(cfg), "broker", cfg.Store.Etcd, m, out, func(error) {})
	gc.StopAfter, gc.Unhealthy = 0, nil
	st := crypt.Wrap(guard.WrapRev(b, gc), keys, m.CryptOpenFailures, crypt.WithLedger(crypt.NewLedger()),
		crypt.OnUnopenable(unopenableSayer("port49-broker", keys, out, time.Now)))
	brk := &broker.Broker{Policy: policy.NewLive(pol), Store: st, Now: time.Now, Metrics: m,
		Log:            decision.NewJSONLinesWithFailureHook(log, m.DecisionLogWriteFailures.Inc),
		ContextIdleTTL: cfg.ContextIdleTTL, GraceWindow: cfg.Session.GraceWindow, RevokeTimeout: admin.OpTimeout,
		Proc: "port49-broker"}
	brk.Redact = redactorFor(brk.Policy)
	brk.Sessions = session.New(st, time.Now, cfg.ContextIdleTTL, cfg.Session.IndexTTL)
	brk.Say = func(format string, args ...any) { fmt.Fprintf(out, "port49-broker: "+format+"\n", args...) }
	return brk, func() { b.Close() }, nil
}

// persistedInventory is the inventory service's persisted copy, read and
// verified as a start reads it (readPersisted), with no service asked.
func persistedInventory(cfg config.Config) (admission.Inventory, string, error) {
	svc := cfg.InventoryService
	keys, err := config.VerifyKeys(svc.VerifyKeyFiles)
	if err != nil {
		return admission.Inventory{}, "", err
	}
	p, err := readPersisted(svc.StateDir, keys)
	switch {
	case err != nil:
		return admission.Inventory{}, "", err
	case p == nil:
		return admission.Inventory{}, "", fmt.Errorf("none in %s", svc.StateDir)
	}
	return p.Inv, fmt.Sprintf("the inventory service's bundle %d", p.Doc.Sequence), nil
}
