package port49d

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/admin"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/session"
	"github.com/rhwendt/port49/internal/store"
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
	run, err := offlineBroker(ctx, *cfgPath, log, out)
	if err != nil {
		fmt.Fprintf(out, "%s%v; nothing was revoked; with no broker host, write the mark as etcd's root under rv/, "+
			"which every port49d follows\n", offlineSay, err)
		return 1
	}
	defer run.close()
	brk := run.brk
	// Who ran it, as the admin socket's origin names its caller (spec §5.7).
	req := broker.RevokeRequest{Principal: *principal, Issuer: *issuer, Serial: *serial,
		Origin: fmt.Sprintf("offline uid %d", os.Getuid())}
	if *lift {
		rep, err := brk.Lift(ctx, req)
		if err != nil {
			fmt.Fprintln(out, offlineFailed(true, err))
			return 1
		}
		// This host's copy drops it. Every other host's holds it still
		// (marksCopy): its next runner puts it back, as it would a mark an
		// etcd restore lost.
		copied := "this host's broker.state_dir/" + stateMarksFile + " no longer holds it"
		if err := offlineCopy(run.stateDir, rep.Mark, true, out); err != nil {
			copied = fmt.Sprintf("this host's broker.state_dir/%s could not be updated (%v) and still holds it",
				stateMarksFile, err)
		}
		fmt.Fprintf(out, "%s%s\n%s; every other host's broker.state_dir/%s still holds it: its next runner puts it "+
			"back; once a port49-broker runs, lift it again with port49 revoke --lift\n", offlineSay,
			rep.LiftedText(), copied, stateMarksFile)
		if rep.Partial() {
			return 1
		}
		return 0
	}
	rep, err := brk.Revoke(ctx, req)
	if err != nil {
		fmt.Fprintln(out, offlineFailed(false, err))
		return 1
	}
	// No policy was read, so whether it names the principal is unknown, not no.
	rep.Unnamed = rep.Unnamed && !run.noPolicy
	// The mark also stands in this host's copy, which no broker has seen: an
	// etcd restore from before it would lose it, and the runbook's restart
	// after the restore would let the principal mint again (final review 7e-2
	// I-2).
	copied := fmt.Sprintf("the mark stands in this host's broker.state_dir/%s, which the next port49-broker started "+
		"here keeps in force and puts back; an etcd restore from before now loses this mark unless a port49-broker "+
		"has run since, so revoke again after such a restore, before any broker starts", stateMarksFile)
	if err := offlineCopy(run.stateDir, rep.Mark, false, out); err != nil {
		copied = fmt.Sprintf("the mark is NOT in this host's broker.state_dir/%s (%v): an etcd restore from before "+
			"now loses it unless another port49-broker's copy holds it, so revoke again after such a restore, before any "+
			"broker starts",
			stateMarksFile, err)
	}
	fmt.Fprintf(out, "%s%s\n%s%s\n", offlineSay, rep.Text(), offlineSay, copied)
	if rep.Partial() {
		return 1
	}
	return 0
}

// offlineCopy stands mark in this host's broker.state_dir/marks.json, or
// drops it when lifted, through the copy port49-broker keeps (openMarksCopy),
// after the same owner checks a start makes (ownStateDir): the copy is what a
// takeover puts back after an etcd restore, and no broker ran to write it.
// openMarksCopy's lines are the broker's start's, so they are taken and
// said in the tool's words (said). The error is why it was not written; a
// directory another user owns is never to be chowned, and the tool says to
// run it as the owner.
func offlineCopy(stateDir string, mark store.Revocation, lifted bool, out io.Writer) error {
	if err := ownStateDir(stateDir); err != nil {
		var wo *wrongOwnerError
		if errors.As(err, &wo) {
			return offlineOwnerHint(wo)
		}
		return err
	}
	path := filepath.Join(stateDir, stateMarksFile)
	_, statErr := os.Stat(path)
	var said bytes.Buffer
	c := openMarksCopy(path, &said)
	if statErr == nil && said.Len() > 0 {
		// A file that did not decode is moved aside by openMarksCopy, and one with
		// entries this port49 does not understand keeps them unchanged.
		fmt.Fprintf(out, "%sbroker.state_dir/%s did not read as written (moved aside as %s.bad-<time>, or entries "+
			"this port49 does not understand kept unchanged): the mark stands in a copy of what could be read; a "+
			"broker started here fills it from the store\n", offlineSay, stateMarksFile, stateMarksFile)
	}
	if lifted {
		c.Apply(store.MarkChange{Revocation: mark, Standing: false})
	} else {
		c.stand([]store.Revocation{mark})
	}
	return c.writeErr()
}

// offlineOwnerHint is the refusal of a state path another user owns, in the
// tool's words: run it as the owner, never chown the directory.
func offlineOwnerHint(wo *wrongOwnerError) error {
	return fmt.Errorf("%s is owned by uid %d and this runs as uid %d: run it as the user that owns "+
		"broker.state_dir (uid %d), and do not chown the directory", wo.what, wo.uid, wo.euid, wo.uid)
}

// offlineFailed is the line for a revocation (or a lift) that did not
// finish, in the tool's own words (Task 15b review M-4): the broker's
// errors advise on a port49d that denies what the mark names, and here
// nothing does. A request the broker refused as written, or a lift of no
// mark, is said as the broker says it. Otherwise the store's error is
// named, with what may have landed, that running the same command again
// is safe, and Ruling 13's fallback with no broker host.
func offlineFailed(lift bool, err error) string {
	if errors.Is(err, broker.ErrBadRevocation) || errors.Is(err, broker.ErrNotRevoked) {
		return fmt.Sprintf("%s%v; nothing was changed", offlineSay, err)
	}
	cause := err
	if u := errors.Unwrap(err); u != nil {
		cause = u
	}
	if lift {
		return fmt.Sprintf("%sthe lift did not finish (%v): the mark may still stand; the same command is safe to run "+
			"again; with no broker host, delete the mark as etcd's root under rv/", offlineSay, cause)
	}
	return fmt.Sprintf("%sthe revocation did not finish (%v): the mark may or may not have landed, and no token was "+
		"deleted and no context marked; the same command is safe to run again; with no broker host, write the "+
		"mark as etcd's root under rv/, which every port49d follows", offlineSay, cause)
}

// offlineRun is what offlineBroker builds: the broker, whether it runs on the
// empty policy (the real one did not load), this host's broker.state_dir, and
// the close of the store.
type offlineRun struct {
	brk      *broker.Broker
	noPolicy bool
	stateDir string
	close    func()
}

// offlineBroker is the broker offlineRevoke runs on: port49-broker.yaml
// at cfgPath, the policy in force there, and one attempt at the store on
// the broker's identity, its roles checked (attempt; Ruling 10), under the
// broker's guard and sealing layer with a ledger of its own and no fence:
// nothing follows the store here, and it only writes marks and revokes. No
// listener and no minter. closeStore closes the store.
//
// A policy or inventory that does not load does not stop it (final review
// 7e-2 I-1): that is when every broker crash-loops, and the policy decides
// nothing about access here. It reads the policy for two things only, the
// report's note that no subject names the principal and its list of live
// contexts to close on the device. So it goes on with a policy that names no
// subject and no device, says so once, and noPolicy is true.
func offlineBroker(ctx context.Context, cfgPath string, log, out io.Writer) (run offlineRun, err error) {
	cfg, err := config.LoadBroker(cfgPath)
	if err != nil {
		return offlineRun{}, err
	}
	keys, err := cfg.EncryptionKeys()
	if err != nil {
		return offlineRun{}, err
	}
	inventoryFrom := "inventory_file " + cfg.InventoryFile
	var pol *policy.Policy
	noPolicy := false
	if svc := cfg.InventoryService; svc == nil {
		if cfg.Inventory, _, err = fencedInventory(cfg); err != nil {
			pol, noPolicy = offlineNoPolicy(out, err), true
		}
	} else if cfg.Inventory, inventoryFrom, err = persistedInventory(cfg); err != nil {
		// The report's reach is the policy's to read, not the mark's: every
		// context is reported as on a platform that never asks, which says
		// to close more by hand, never fewer.
		fmt.Fprintf(out, "%sthe inventory service's persisted copy (%v): the report names every live context as "+
			"one to close on the device\n", offlineSay, err)
		inventoryFrom = "no inventory"
	}
	if pol == nil {
		if pol, err = loadPolicy(cfg, inventoryFrom); err != nil {
			pol, noPolicy = offlineNoPolicy(out, err), true
		}
	}
	run.noPolicy = noPolicy
	m := metrics.New(prometheus.NewRegistry())
	b, err := attempt(ctx, cfg, m, out)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return offlineRun{}, errors.New("stopped")
		}
		return offlineRun{}, fmt.Errorf("store: %w", err)
	}
	gc := guardConfig(procOf(cfg), "broker", cfg.Stores.SessionPath(), cfg.Stores.Session.Etcd, m, out, func(error) {})
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
	run.brk, run.stateDir, run.close = brk, cfg.Broker.StateDir, func() { b.Close() }
	return run, nil
}

// offlineNoPolicy is the policy offlineBroker goes on with when the policy
// or the inventory does not load: one subject no principal matches and no
// device, said once, with the cause. The report then lists every live context
// as one to close on the device.
func offlineNoPolicy(out io.Writer, cause error) *policy.Policy {
	fmt.Fprintf(out, "%sthe policy does not load (%v): the report names every live context as one to close on the "+
		"device, and cannot say whether the policy names the principal; the revocation does not depend on it\n",
		offlineSay, cause)
	pol, err := bundle.Parse([]byte(noPolicyBody), admission.Inventory{}, policy.Env{})
	if err != nil {
		panic("port49d: the offline revocation's empty policy does not compile: " + err.Error())
	}
	return pol
}

// noPolicyBody is the smallest policy that compiles: it names no subject
// any principal spells and holds no grant.
const noPolicyBody = `
scopes: [{name: none, match: {}}]
roles: [{name: none, privilege: readonly, permit: []}]
subjects: [{name: none, identity: ["app:offline-no-policy"], username: none, token_ttl: 60s}]
grants: [{subject: none, scope: none, roles: [none]}]
`

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
