package port49d

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/session"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
)

// daemonOfflineSay begins each line of port49d revoke --offline.
const daemonOfflineSay = "port49d: revoke (offline, no API): "

// offlineRevokeDaemon is `port49d revoke --offline` (spec §12): the
// break-glass revocation for a port49d that runs its broker in process, on
// the memory store, whose marks live in broker.revocations_file. With port49d
// stopped, it loads the file, runs the whole revocation or lift on a broker
// of its own over the same code, and saves the file; the next start loads the
// mark before it serves. It refuses a port49d that answers on its metrics
// listener (the file is that process's to write), and a port49d with no
// broker: block, naming port49-broker revoke --offline. Exit codes are
// offlineRevoke's.
func offlineRevokeDaemon(args []string, log, out io.Writer) int {
	f, code, done := parseOffline("port49d", "/etc/port49/port49d.yaml", args, out)
	if done {
		return code
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	brk, file, release, err := offlineDaemon(ctx, f.cfgPath, log)
	if err != nil {
		fmt.Fprintf(out, "%s%v; nothing was changed\n", daemonOfflineSay, err)
		return 1
	}
	defer release() // held through the write: a port49d that starts meanwhile waits for it
	if f.list {
		return offlineList(ctx, brk.Store, daemonOfflineSay, out)
	}
	req := broker.RevokeRequest{Principal: f.principal, Issuer: f.issuer, Serial: f.serial,
		Origin: fmt.Sprintf("offline uid %d", os.Getuid())}
	if f.lift {
		rep, err := brk.Lift(ctx, req)
		if err != nil {
			fmt.Fprintln(out, strings.Replace(offlineFailed(true, err), offlineSay, daemonOfflineSay, 1))
			return 1
		}
		fmt.Fprintf(out, "%s%s\nbroker.revocations_file %s no longer holds it; start port49d\n", daemonOfflineSay,
			rep.LiftedText(), file)
		if rep.Partial() {
			return 1
		}
		return 0
	}
	rep, err := brk.Revoke(ctx, req)
	if err != nil {
		fmt.Fprintln(out, strings.Replace(offlineFailed(false, err), offlineSay, daemonOfflineSay, 1))
		return 1
	}
	// No policy was read, so whether it names the principal is unknown, not no.
	rep.Unnamed = false
	fmt.Fprintf(out, "%s%s\n%sthe mark stands in broker.revocations_file %s, which port49d loads before it "+
		"serves; start port49d\n", daemonOfflineSay, rep.Text(), daemonOfflineSay, file)
	if rep.Partial() {
		return 1
	}
	return 0
}

// offlineDaemon is the broker offlineRevokeDaemon runs on: the memory store
// loaded from broker.revocations_file at cfgPath's port49d.yaml, saved to it
// by every revocation or lift. It refuses a config with no broker: block, and
// a port49d that is running. file is the path of broker.revocations_file, and
// release gives up the lock on it, which the caller holds through its write.
func offlineDaemon(ctx context.Context, cfgPath string, log io.Writer) (*broker.Broker, string, func(), error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, "", nil, err
	}
	if cfg.Broker == nil {
		return nil, "", nil, errors.New("this port49d.yaml has no broker: block, so port49d holds no revocations; " +
			"revocations are port49-broker's: run port49-broker revoke --offline")
	}
	if err := daemonAnswering(ctx, cfg.MetricsListen); err != nil {
		return nil, "", nil, err
	}
	file := cfg.Broker.RevocationsFile
	if err := offlineOwner(file, cfgPath); err != nil {
		return nil, "", nil, err
	}
	// A port49d that answers nothing may still be starting, or be another
	// config's on the same file: the lock is what keeps it out of the file
	// between this load and this save.
	release, err := lockRevocations(file)
	switch {
	case errors.Is(err, errRevocationsLocked):
		return nil, "", nil, fmt.Errorf("broker.revocations_file %s is locked: a port49d is running or starting on it "+
			"(or another offline revoke is); stop it, or revoke through the API with port49 revoke", file)
	case err != nil:
		return nil, "", nil, fmt.Errorf("broker.revocations_file %s: %w", file, err)
	}
	st := memory.New(time.Now)
	marks := store.NewMarks()
	held, err := restoreRevocations(ctx, st, file)
	if err != nil {
		release()
		return nil, "", nil, fmt.Errorf("broker.revocations_file %s: %w", file, err)
	}
	for _, r := range held {
		marks.Set(r, true)
	}
	m := metrics.New(prometheus.NewRegistry())
	brk := &broker.Broker{Policy: policy.NewLive(offlineNoPolicy(io.Discard, nil)), Store: st, Now: time.Now, Metrics: m,
		Log:            decision.NewJSONLinesWithFailureHook(log, m.DecisionLogWriteFailures.Inc),
		ContextIdleTTL: cfg.ContextIdleTTL, GraceWindow: cfg.Session.GraceWindow, RevokeTimeout: revokeRunTimeout,
		Proc: "port49d", Marks: marks}
	brk.Persist = persister(st, file, held, marks, m)
	brk.Redact = redactorFor(brk.Policy)
	brk.Sessions = session.New(st, time.Now, cfg.ContextIdleTTL, cfg.Session.IndexTTL)
	brk.Say = func(format string, args ...any) {}
	return brk, file, release, nil
}

// daemonAnswering is nil when nothing answers /readyz on port49d's metrics
// listener, and otherwise the refusal: a running port49d owns its revocations
// file and its marks, so the revocation goes through it (the API), or after it
// is stopped. A listener on port 0 cannot be dialed and is not asked.
func daemonAnswering(ctx context.Context, listen string) error {
	return answeringOn(ctx, listen, "port49d", "broker.revocations_file")
}

// answeringOn is daemonAnswering for the process proc, which owns what.
func answeringOn(ctx context.Context, listen, proc, owns string) error {
	host, port, err := net.SplitHostPort(listen)
	if err != nil || port == "0" {
		return nil
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	addr := net.JoinHostPort(host, port)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/readyz", nil)
	if err != nil {
		return nil
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()
	return fmt.Errorf("something answers /readyz on %s, so %s is running and owns %s: "+
		"with it running, use port49 revoke, which asks the broker API with a security key press; to revoke "+
		"with it stopped, stop it first", addr, proc, owns)
}
