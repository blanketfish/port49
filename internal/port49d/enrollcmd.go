package port49d

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/crypt"
	"github.com/rhwendt/port49/internal/store/memory"
)

// enrollmentsCmd is `port49-broker|port49d init-enrollments|export-enrollments
// [--config FILE]` (spec §12): the enrollment store's two local operations,
// run beside the store with the process's own identity and keys. They are not
// on the API: init creates the store, and export reads sealed bytes that
// leave the host only if the operator carries them, so neither is a remote
// right. proc names the binary; op is the subcommand.
//
// init-enrollments prints what it did and exits 0, or 1 with the reason
// ("already there" names import and reset-second-factor --all). export-
// enrollments writes the sealed bytes to stdout and nothing else there, and is
// refused when stdout is a terminal, or writes to the new file --out names. Exit 2 is a usage error.
func enrollmentsCmd(proc, op string, args []string, stdout, stderr io.Writer) int {
	def, load := "/etc/port49/port49d.yaml", config.Load
	if proc == "port49-broker" {
		def, load = "/etc/port49/port49-broker.yaml", config.LoadBroker
	}
	fs := flag.NewFlagSet(proc+" "+op, flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", def, "path to "+proc+"'s yaml")
	outPath := fs.String("out", "", "export-enrollments: write the sealed export to this new file (created 0600, never replacing one) instead of stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "usage: %s %s [--config FILE]%s\n", proc, op, map[bool]string{true: " [--out FILE]"}[op == "export-enrollments"])
		return 2
	}
	if op != "export-enrollments" && *outPath != "" {
		fmt.Fprintf(stderr, "%s %s: --out is export-enrollments's\n", proc, op)
		return 2
	}
	if op == "export-enrollments" && *outPath == "" && stdoutIsTerminal(stdout) {
		fmt.Fprintf(stderr, "%s %s: the sealed export is binary: redirect it to a file or a pipe, "+
			"%s %s > enrollments.sealed\n", proc, op, proc, op)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	cfg, err := load(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "%s %s: %v\n", proc, op, err)
		return 1
	}
	keys, err := cfg.EncryptionKeys()
	if err != nil {
		fmt.Fprintf(stderr, "%s %s: %v\n", proc, op, err)
		return 1
	}
	// The decision log of init is the process's stdout, as revoke's is; the
	// export's stdout is the sealed bytes alone.
	logTo := stdout
	if op == "export-enrollments" {
		logTo = stderr
	}
	if *outPath != "" {
		return withOutFile(*outPath, stderr, func(w io.Writer) int {
			return runEnrollments(ctx, proc, op, cfg, keys, logTo, w, stderr)
		})
	}
	return runEnrollments(ctx, proc, op, cfg, keys, logTo, stdout, stderr)
}

// withOutFile runs the export into a new file at path: created 0600 with O_EXCL, so one that
// exists (a stale partial one included) is refused and never replaced, then synced and closed.
// Whatever fails, the partial file is removed, so a later run never finds one that looks whole.
// run's code is returned, or 1 for a failure of the file's own.
func withOutFile(path string, stderr io.Writer, run func(io.Writer) int) int {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			fmt.Fprintf(stderr, "--out %s exists: it is never replaced; remove it or name a new file\n", path)
		} else {
			fmt.Fprintf(stderr, "--out %s: %v\n", path, err)
		}
		return 1
	}
	code := run(f)
	if code == 0 {
		if err := f.Sync(); err != nil {
			fmt.Fprintf(stderr, "--out %s: syncing: %v\n", path, err)
			code = 1
		}
	}
	if err := f.Close(); err != nil && code == 0 {
		fmt.Fprintf(stderr, "--out %s: closing: %v\n", path, err)
		code = 1
	}
	if code != 0 {
		_ = os.Remove(path)
	}
	return code
}

// stdoutIsTerminal is whether w is a terminal; a variable so a test can say.
var stdoutIsTerminal = func(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// runEnrollments runs op on cfg's enrollment store. A port49-broker (or any
// config on etcd) opens the directory store on the process's identity; a
// port49d on the memory store opens the sealed file.
func runEnrollments(ctx context.Context, proc, op string, cfg config.Config, keys crypt.Keys,
	logTo, stdout, stderr io.Writer) int {
	say := proc + " " + op + ": "
	if cfg.Broker == nil || cfg.Broker.Identity == nil || cfg.Broker.Identity.PasswordSignIn == nil {
		fmt.Fprintln(stderr, say+"this config has no directory_password verifier (broker.identity), so it holds no "+
			"second factors")
		return 1
	}
	m := metrics.New(prometheus.NewRegistry())
	brk := &broker.Broker{Policy: nil, Now: time.Now, Metrics: m, Proc: proc,
		Log: decision.NewJSONLinesWithFailureHook(logTo, m.DecisionLogWriteFailures.Inc)}
	brk.Say = func(format string, args ...any) { fmt.Fprintf(stderr, proc+": "+format+"\n", args...) }
	var shared func() store.Enrollments
	closeAll := func() {}
	if cfg.Stores.Directory.Backend == config.BackendEtcd {
		run, err := openEnrollmentDirectory(ctx, cfg, m, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "%s%v\n", say, err)
			return 1
		}
		closeAll = run.close
		shared = func() store.Enrollments { return run.dir }
		brk.Store = memory.New(time.Now) // never read: the enrollment ops touch the enrollment store alone
	} else {
		brk.Store = memory.New(time.Now)
	}
	defer closeAll()
	setPasswordSignIn(cfg, brk)
	open, _ := enrollmentOpener(cfg, keys, m, shared, stderr)
	late := &lateEnrollments{open: open, now: time.Now}
	defer late.close()
	brk.Enrollments = late
	brk.EnrollmentFile = cfg.Broker.Directory.EnrollmentStore.File
	origin := fmt.Sprintf("offline uid %d", os.Getuid())
	switch op {
	case "init-enrollments":
		text, err := brk.InitEnrollments(ctx, origin)
		if err != nil {
			fmt.Fprintln(stderr, say+err.Error())
			return 1
		}
		fmt.Fprintln(stdout, text)
		return 0
	default:
		sealed, err := brk.ExportEnrollments(ctx)
		if err != nil {
			fmt.Fprintln(stderr, say+err.Error())
			return 1
		}
		if _, err := stdout.Write(sealed); err != nil {
			fmt.Fprintln(stderr, say+"writing the export: "+err.Error())
			return 1
		}
		return 0
	}
}

// openEnrollmentDirectory opens the directory store on the broker's identity
// for an enrollment command, as the offline revocation does and without its
// policy or its marks: the raw handle the enrollment records are read
// through, and its close.
func openEnrollmentDirectory(ctx context.Context, cfg config.Config, m *metrics.Metrics, out io.Writer) (offlineRun, error) {
	b, err := attempt(ctx, cfg, directoryRef(cfg), m, out, false)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return offlineRun{}, errors.New("stopped")
		}
		return offlineRun{}, fmt.Errorf("directory store: %w", err)
	}
	return offlineRun{dir: b, close: func() { b.Close() }}, nil
}
