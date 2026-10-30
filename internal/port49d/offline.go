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
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/session"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/crypt"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
	"github.com/rhwendt/port49/internal/store/guard"
	"github.com/rhwendt/port49/internal/store/placement"
)

// offlineSay begins each line of port49-broker revoke --offline.
const offlineSay = "port49-broker: revoke (offline, no API): "

// offlineFlags is what `revoke --offline` reads, on port49-broker and on port49d.
type offlineFlags struct {
	cfgPath, principal, issuer, serial string
	lift, list                         bool
}

// parseOffline reads the flags of `<proc> revoke`, and answers the exit code
// when the command is not to run: 2 for a usage error (said to out). proc is
// "port49-broker" or "port49d".
func parseOffline(proc, defCfg string, args []string, out io.Writer) (f offlineFlags, code int, stop bool) {
	fs := flag.NewFlagSet(proc+" revoke", flag.ContinueOnError)
	fs.SetOutput(out)
	offline := fs.Bool("offline", false, "revoke through the store with every "+proc+" down")
	fs.StringVar(&f.cfgPath, "config", defCfg, "path to "+proc+"'s yaml")
	fs.StringVar(&f.principal, "principal", "", "the principal, as the log names it: user:alice@example.com")
	fs.StringVar(&f.issuer, "cert-issuer", "", "the certificate's issuer, as the broker spells it (RFC 2253: CN=…,O=…)")
	fs.StringVar(&f.serial, "cert-serial", "", "the certificate's serial, in hex")
	fs.BoolVar(&f.lift, "lift", false, "lift the revocation instead")
	fs.BoolVar(&f.list, "list", false, "list the revocations in force, each with its origin")
	if err := fs.Parse(args); err != nil {
		return f, 2, true
	}
	byCert := f.issuer != "" || f.serial != ""
	named := f.principal != "" || byCert
	switch {
	case fs.NArg() != 0:
		fmt.Fprintln(out, "usage: "+proc+" revoke --offline [--config FILE] (--principal P | --cert-issuer I "+
			"--cert-serial S) [--lift] | --list")
		return f, 2, true
	case !*offline:
		fmt.Fprintln(out, proc+" revoke: this is the break-glass form for when every "+proc+" is down: add --offline. "+
			"With one running, use port49 revoke, which asks the broker API with a security key press")
		return f, 2, true
	case f.list && (named || f.lift):
		fmt.Fprintln(out, proc+" revoke: --list takes no principal, certificate or --lift")
		return f, 2, true
	case f.list:
		return f, 0, false
	case (f.principal != "") == byCert, byCert && (f.issuer == "" || f.serial == ""):
		fmt.Fprintln(out, proc+" revoke: name --principal, or --cert-issuer and --cert-serial; one of the two")
		return f, 2, true
	}
	return f, 0, false
}

// offlineRevoke is `port49-broker revoke --offline` (plan 7e, Ruling 13;
// pre-flight I4): the break-glass revocation with every port49-broker
// down, when the API has no broker to ask. It runs the whole
// revocation, or a lift, through the store on the broker's identity, as
// the API's would: the mark, the unspent tokens deleted, the live
// contexts marked revoked. port49d's marks feed brings the mark to every
// session, and the next port49-broker start loads it before it serves, so
// nothing mints for the principal after. It takes no hold, binds nothing
// and keeps no copy; the report goes to out as port49 revoke prints it,
// and the revoke record to log, port49-broker's decision log. With --list
// it prints the marks in force, each with its origin. A user who does not own
// broker.state_dir is refused before anything is written. Exit 0 on a
// whole report, 1 on an error, a refusal or a partial one, 2 on a usage error.
func offlineRevoke(args []string, log, out io.Writer) int {
	f, code, done := parseOffline("port49-broker", "/etc/port49/port49-broker.yaml", args, out)
	if done {
		return code
	}
	cfgPath, principal, issuer, serial, lift := &f.cfgPath, &f.principal, &f.issuer, &f.serial, &f.lift
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// A user who does not own broker.state_dir is refused before anything is opened or written: the
	// etcd client key is the owner's too, so opening it first would tell root to chown a key, the
	// opposite of the hint; and the copy this ends by writing is refused anyway, so a revoke that stands
	// in the store while the command says it could not finish is half a revoke at 3am. Only the owner is
	// knowable here; an I/O failure of the copy is not, and keeps its write-anyway rule (final review
	// 7e-2 I-2). --list writes nothing, so any user may run it and it keeps to the store alone.
	if !f.list {
		if cfg, err := config.LoadBroker(*cfgPath); err == nil {
			if err := ownStateDir(cfg.Broker.StateDir); err != nil {
				var wo *wrongOwnerError
				if errors.As(err, &wo) {
					what := "revoked"
					if *lift {
						what = "lifted"
					}
					fmt.Fprintf(out, "%snothing was %s: %v\n", offlineSay, what, offlineOwnerHint(wo))
					return 1
				}
			}
		}
	}
	run, err := offlineBroker(ctx, *cfgPath, log, out)
	if err != nil {
		fmt.Fprintf(out, "%s%v; nothing was revoked; with no broker host, write the mark as etcd's root under rv/, "+
			"which every port49d follows\n", offlineSay, err)
		return 1
	}
	defer run.close()
	brk := run.brk
	if f.list {
		return offlineList(ctx, brk.Store, offlineSay, out)
	}
	// Who ran it, as the API's origin names its caller (spec §5.7).
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

// offlineList prints the marks st holds, each with its origin and the lift
// that a landed-after-lift mark followed, as port49 revoke --list does. Exit
// 0, or 1 when the store did not answer.
func offlineList(ctx context.Context, st store.Store, say string, out io.Writer) int {
	rs, err := st.ListRevocations(ctx)
	if err != nil {
		fmt.Fprintf(out, "%sthe revocations in force could not be read (%v)\n", say, printsafe.Line(err.Error(), 300))
		return 1
	}
	fmt.Fprintln(out, broker.RevocationsText(rs, func(kind, key string) (store.Lift, error) {
		return st.GetLift(ctx, kind, key)
	}))
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

// offlineOwnerName is the name of the user with uid on this host, or "" when it has none.
// A variable so a test can say.
var offlineOwnerName = func(uid uint32) string {
	if u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		return u.Username
	}
	return ""
}

// offlineOwnerHint is the refusal of a state path another user owns, in the
// tool's words: run it as the owner, never chown the directory. An owner with a
// name gets the sudo -u line, as port49d's own refusal gives one; one with none
// gets its number, since sudo refuses a #uid without runas_allow_unknown_id.
func offlineOwnerHint(wo *wrongOwnerError) error {
	how := fmt.Sprintf("run it as uid %d, the owner of broker.state_dir", wo.uid)
	if who := offlineOwnerName(wo.uid); who != "" {
		how = fmt.Sprintf("e.g. sudo -u %s port49-broker revoke --offline ...", who)
	}
	return fmt.Errorf("%s is owned by uid %d and this runs as uid %d: run it as the user that owns "+
		"broker.state_dir (uid %d), %s, and do not chown the directory",
		wo.what, wo.uid, wo.euid, wo.uid, how)
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
	// cfg, keys and dir are what the enrollment commands add: the config the
	// run loaded, its sealing keys, and the directory store's raw handle (the
	// session store's own in a shared store).
	cfg  config.Config
	keys crypt.Keys
	dir  *etcdstore.Store
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
	b, err := attempt(ctx, cfg, sessionRef(cfg), m, out, false)
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
	closeAll := func() { b.Close() }
	run.cfg, run.keys, run.dir = cfg, keys, b
	if !cfg.Stores.Shared {
		d, err := attempt(ctx, cfg, directoryRef(cfg), m, out, false)
		if err != nil {
			b.Close()
			if errors.Is(err, context.Canceled) {
				return offlineRun{}, errors.New("stopped")
			}
			return offlineRun{}, fmt.Errorf("directory store: %w", err)
		}
		de := cfg.Stores.Directory.Etcd
		// No copy: the offline revocation follows no feed, so a mark is read
		// from the directory.
		st = placement.Wrap(placement.Config{Session: st, Directory: d, CallTimeout: de.CallTimeout,
			BulkTimeout: de.BulkTimeout})
		closeAll = func() { b.Close(); d.Close() }
		run.dir = d
	}
	brk := &broker.Broker{Policy: policy.NewLive(pol), Store: st, Now: time.Now, Metrics: m,
		Log:            decision.NewJSONLinesWithFailureHook(log, m.DecisionLogWriteFailures.Inc),
		ContextIdleTTL: cfg.ContextIdleTTL, GraceWindow: cfg.Session.GraceWindow, RevokeTimeout: revokeRunTimeout,
		Proc: "port49-broker"}
	brk.Redact = redactorFor(brk.Policy)
	brk.Sessions = session.New(st, time.Now, cfg.ContextIdleTTL, cfg.Session.IndexTTL)
	brk.Say = func(format string, args ...any) { fmt.Fprintf(out, "port49-broker: "+format+"\n", args...) }
	run.brk, run.stateDir, run.close = brk, cfg.Broker.StateDir, closeAll
	return run, nil
}

// offlineNoPolicy is the policy offlineBroker goes on with when the policy
// or the inventory does not load: one subject no principal matches and no
// device, said once, with the cause. The report then lists every live context
// as one to close on the device.
func offlineNoPolicy(out io.Writer, cause error) *policy.Policy {
	if cause == nil {
		return emptyOfflinePolicy()
	}
	fmt.Fprintf(out, "%sthe policy does not load (%v): the report names every live context as one to close on the "+
		"device, and cannot say whether the policy names the principal; the revocation does not depend on it\n",
		offlineSay, cause)
	return emptyOfflinePolicy()
}

// emptyOfflinePolicy is the policy that names no subject and no device.
func emptyOfflinePolicy() *policy.Policy {
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
