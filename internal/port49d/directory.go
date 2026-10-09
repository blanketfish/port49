package port49d

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
)

// openDirectoryHook is openDirectory, swapped in tests that need a resolver
// without a directory server.
var openDirectoryHook = openDirectory

// openDirectory builds the resolver from broker.directory: the bind's
// credentials read once, the pool over a dialer that binds each connection,
// the policy's declared usernames read live. It returns nil without a
// directory.
func openDirectory(cfg config.Config, st store.Store, live *policy.Live, m *metrics.Metrics,
	say func(string, ...any)) (*directory.Resolver, error) {
	if cfg.Broker == nil || cfg.Broker.Directory == nil {
		return nil, nil
	}
	d := cfg.Broker.Directory
	cr, err := directory.LoadCredentials(d.Bind, os.Getenv)
	if err != nil {
		// The error names the key (keytab_file, tls_cert_file, password_env,
		// the realm, the KDC), never the secret; the start stops on it, as
		// on a config refusal (pre-flight M-3).
		return nil, fmt.Errorf("config: %w", err)
	}
	dial, err := directory.NewDialer(*d, cr)
	if err != nil {
		return nil, err
	}
	pool := directory.NewPool(*d, dial, directory.RootDSE, time.Now, m, say)
	return &directory.Resolver{Cfg: *d, Pool: pool, Store: st, Now: time.Now, M: m, Say: say,
		// Read at each check, so a reload's declarations are the next
		// collision check's.
		Declared: func() map[string]string { return live.Load().DeclaredUsernames() }}, nil
}

// policyEnv is the policy's environment in this process: the key refs, and
// whether its broker resolves humans through a directory (Ruling 16), and
// workloads (decision 41 ruling 1).
func policyEnv(cfg config.Config) policy.Env {
	env := policy.Env{KeyRefs: cfg.KeyRefs()}
	switch {
	case cfg.Broker == nil:
	case cfg.Broker.Directory != nil:
		env.Directory, env.WorkloadDirectory = policy.DirectoryOn, policy.DirectoryOff
		if cfg.Broker.Directory.Workload != nil {
			env.WorkloadDirectory = policy.DirectoryOn
		}
	default:
		env.Directory, env.WorkloadDirectory = policy.DirectoryOff, policy.DirectoryOff
	}
	return env
}

// announceDirectory is the start's directory lines (What the operator sees).
// A server is named by its label, and a credential by the key that holds it,
// never by its value.
func announceDirectory(w io.Writer, proc string, cfg config.Config, pol *policy.Policy) {
	if cfg.Broker == nil {
		return
	}
	d := cfg.Broker.Directory
	machineGroups := func() {
		if d != nil && d.Workload != nil {
			return
		}
		if gs := pol.MachineGroupSubjects(); len(gs) > 0 {
			fmt.Fprintf(w, "%s: policy: %d machine_group subjects (%s) mint for no one: no "+
				"broker.identity.machines[].directory is configured\n", proc, len(gs), strings.Join(gs, ", "))
		}
	}
	if d == nil {
		if gs := pol.GroupSubjects(); len(gs) > 0 {
			fmt.Fprintf(w, "%s: policy: %d group subjects (%s) mint for no one: no broker.directory is configured\n",
				proc, len(gs), strings.Join(gs, ", "))
		}
		machineGroups()
		return
	}
	var servers []string
	for _, s := range d.Servers {
		servers = append(servers, fmt.Sprintf("%s site %s priority %d", s.Label(), cmp.Or(s.Site, "-"), s.Priority))
	}
	site := "none: servers rank by priority alone (set broker.directory.site or PORT49_SITE)"
	if d.Site != "" {
		site = d.Site + " (" + d.SiteFrom + ")"
	}
	fmt.Fprintf(w, "%s: directory: %d servers (%s); this broker's site is %s; bind %s as %s\n", proc,
		len(d.Servers), strings.Join(servers, ", "), site, d.Bind.Mechanism, bindWho(d.Bind))
	if d.Bind.Mechanism == "simple" {
		fmt.Fprintf(w, "%s: directory: bind simple as %s: the weakest of the three (design §10); its password is "+
			"read from %s\n", proc, d.Bind.BindDN, d.Bind.PasswordEnv)
	}
	strength := "weak, pinned to " + strings.Join(d.Mapping.Issuers, "; ")
	if d.Mapping.Kind.Strong() {
		strength = "strong"
	}
	fmt.Fprintf(w, "%s: directory: certificates map by %s (%s) through %s; principal from %s, username from %s; "+
		"nested groups %s under %s\n", proc, d.Mapping.Kind, strength, d.Mapping.Attribute, d.PrincipalAttribute,
		d.UsernameAttribute, d.Nested, d.GroupsBaseDN)
	fmt.Fprintf(w, "%s: directory: %s and %s must be writable only by directory administrators: two entries "+
		"holding one value are both refused (identity_ambiguous, username_collision) until it is fixed\n", proc,
		d.PrincipalAttribute, d.UsernameAttribute)
	fmt.Fprintf(w, "%s: directory: grace %s; pre-warm %s; the scheduled refresh every %s stamps refreshed_at "+
		"(session.staleness_ceiling denies a session past it)\n", proc, d.Grace, every(d.PrewarmInterval),
		cfg.Broker.RefreshInterval)
	machineGroups()
	if wm := d.Workload; wm != nil {
		// Ruling Q2's cost (pre-flight I-4): every workload of the verifier,
		// identity-only ones included, needs its entry, and an outage stops it.
		fmt.Fprintf(w, "%s: directory: workload certificates map by spiffe_id (weak, pinned to %s) through %s under "+
			"%s; every workload this verifier accepts must have exactly one entry holding its SPIFFE ID, or it is "+
			"refused identity_unmapped, and while the directory is down past grace it is refused "+
			"directory_unavailable; username from the identity subject listing the SPIFFE ID, else from %s; an entry "+
			"holding a SPIFFE ID in %s is never a person's; machine_group subjects match them, group subjects never\n",
			proc, strings.Join(wm.Issuers, "; "), wm.Attribute, wm.UserFilter, d.UsernameAttribute, wm.Attribute)
		warm := fmt.Sprintf("pre-warm %s keeps mapped workloads verified (machine_group members and each spiffe:// "+
			"identity a subject lists, up to prewarm.max_principals (%d) besides the people's)", every(d.PrewarmInterval),
			d.PrewarmMax)
		if d.PrewarmInterval == 0 {
			warm = "pre-warm is off, so a workload that has not minted within grace is refused in an outage"
		}
		// Two clocks (pre-flight M-1): grace bounds a mint; port49d's
		// staleness ceiling, counted from the last pass that reached the
		// directory, bounds a session. Their defaults coincide; they need not.
		fmt.Fprintf(w, "%s: directory: a mapped workload mints only while a server answers or its membership was "+
			"verified within grace (%s): past it its mints are refused directory_unavailable (port49 workload exits "+
			"75); its live device sessions go unstamped from the first scheduled refresh that cannot verify it, and "+
			"deny context_stale once port49d's session.staleness_ceiling has passed since the last one that did; %s\n",
			proc, d.Grace, warm)
		fmt.Fprintf(w, "%s: directory: %s must be writable only by directory administrators: whoever can write it on "+
			"an entry chooses which workload takes that entry's groups\n", proc, wm.Attribute)
	}
}

// bindWho is who the bind is, as the start says it: never a secret.
func bindWho(b directory.Bind) string {
	switch b.Mechanism {
	case "gssapi":
		return b.Principal
	case "simple":
		return b.BindDN
	}
	return "the certificate in " + b.TLSCertFile
}

func every(d time.Duration) string {
	if d == 0 {
		return "off"
	}
	return "every " + d.String()
}

// scheduled runs the scheduled refresh every interval until ctx ends, in
// every process that mints, with a directory or without: it is what stamps
// refreshed_at, so without it every context goes context_stale at
// session.staleness_ceiling. A pass that stops is said; the next runs on
// schedule.
func scheduled(ctx context.Context, brk *broker.Broker, interval time.Duration, say func(string, ...any)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		rep, err := brk.RefreshDirectory(ctx)
		switch {
		case ctx.Err() != nil:
			return
		case errors.Is(err, store.ErrConflict):
			// Every context was visited: only the busy ones are left.
			say("refresh: %d context(s) still changing keep their last stamp; the next pass runs in %s", rep.Failed,
				interval)
		case err != nil:
			say("refresh: the scheduled refresh stopped (%s so far): %v; the next runs in %s", summary(rep), err, interval)
		case rep.Updated+rep.Revoked+rep.Failed > 0:
			say("refresh: scheduled: %s", summary(rep))
		}
	}
}

// prewarmInterval is broker.directory.prewarm.interval, 0 (off) without a
// directory, so a caller never dereferences a nil directory (pre-flight
// M-13).
func prewarmInterval(cfg config.Config) time.Duration {
	if cfg.Broker == nil || cfg.Broker.Directory == nil {
		return 0
	}
	return cfg.Broker.Directory.PrewarmInterval
}

// prewarm runs pre-warm every interval, the first 30s after the start. A nil
// resolver or a zero interval returns at once.
func prewarm(ctx context.Context, r *directory.Resolver, live *policy.Live, interval time.Duration,
	say func(string, ...any)) {
	if r == nil || interval == 0 {
		return
	}
	wait := 30 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = interval
		pol := live.Load()
		rep, err := r.PrewarmAll(ctx, pol.GroupValues(), pol.MachineGroupValues(),
			slices.Collect(maps.Keys(pol.SPIFFEIdentities())))
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			say("directory: pre-warm stopped: %v; the next runs in %s", err, interval)
		default:
			capped := ""
			if rep.Capped {
				capped = fmt.Sprintf("; capped at prewarm.max_principals (%d)", r.Cfg.PrewarmMax)
			}
			say("directory: pre-warm: %d groups, %d principals verified, %d skipped%s", rep.Groups,
				rep.Principals, rep.Failed, capped)
		}
	}
}

// brokerLimits are the broker listener's limits: the config's, and with a
// directory the mapping's budget at bind, its query_timeout plus 1s.
func brokerLimits(cfg config.Config, brk *broker.Broker) broker.ListenerLimits {
	lim := broker.ListenerLimits{MaxPendingPerSource: cfg.Broker.MaxPendingConnsPerSource,
		MaxPerPrincipal:  cfg.Broker.MaxConnsPerPrincipal,
		HandshakeTimeout: broker.DefaultListenerLimits.HandshakeTimeout}
	if brk.Directory != nil {
		lim.MapTimeout = brk.Directory.Cfg.QueryTimeout + time.Second
	}
	return lim
}

// runPool runs the pool's health checks until ctx ends, on a process with a
// directory; the pool closes its connections as it returns. A resolver with
// no pool (a test's static one) has no checks to run.
func runPool(ctx context.Context, r *directory.Resolver) {
	if r != nil && r.Pool != nil {
		r.Pool.Run(ctx)
	}
}
