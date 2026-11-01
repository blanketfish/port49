package port49d

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/daemon/metrics"
)

// init-enrollments creates the enrollment store once; a second run exits 1
// saying it is already there. export-enrollments writes the sealed bytes to a
// pipe and nothing else on stdout, bytes ImportEnrollments accepts on another
// store sealed under the same key; it refuses a terminal. The commands run
// beside the store with the process's own keys (spec §12).
func TestInitAndExportEnrollments(t *testing.T) {
	cfg, file := signInConfig(t, "127.0.0.1:0")
	ctx := context.Background()
	run := func(op string, stdout io.Writer) (int, string) {
		var stderr bytes.Buffer
		return runEnrollments(ctx, "port49d", op, cfg, signInTestKeys, io.Discard, stdout, &stderr), stderr.String()
	}

	// Nothing to export before the store is there.
	var sealed bytes.Buffer
	if code, say := run("export-enrollments", &sealed); code != 1 || sealed.Len() != 0 ||
		!strings.Contains(say, "the export failed") {
		t.Fatalf("export before init: exit %d, %d bytes: %s", code, sealed.Len(), say)
	}

	var out bytes.Buffer
	if code, say := run("init-enrollments", &out); code != 0 || !strings.Contains(out.String(), "created the enrollment store") {
		t.Fatalf("init: exit %d: %s %s", code, out.String(), say)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("init wrote no %s: %v", file, err)
	}
	out.Reset()
	if code, say := run("init-enrollments", &out); code != 1 || !strings.Contains(say, "already") || out.Len() != 0 {
		t.Fatalf("a second init: exit %d: %q %q", code, out.String(), say)
	}

	if code, say := run("export-enrollments", &sealed); code != 0 || sealed.Len() == 0 {
		t.Fatalf("export: exit %d, %d bytes: %s", code, sealed.Len(), say)
	}
	if bytes.Contains(sealed.Bytes(), []byte("example.com")) {
		t.Error("the export holds a name in the clear")
	}

	// Another store, sealed under the same key, accepts it.
	cfg2, _ := signInConfig(t, "127.0.0.1:0")
	m := metrics.New(prometheus.NewRegistry())
	b2 := builtSignInBroker(t, cfg2, m)
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	wirePasswordSignIn(cctx, cfg2, b2, signInTestKeys, m, nil, io.Discard)
	if text, err := b2.ImportEnrollments(ctx, sealed.Bytes(), true, "offline uid 1000"); err != nil || !strings.Contains(text, "imported") {
		t.Fatalf("import: %q %v", text, err)
	}
}

// export-enrollments to a terminal is refused before it opens anything, and
// the usage errors exit 2.
func TestExportEnrollmentsRefusesATerminal(t *testing.T) {
	was := stdoutIsTerminal
	t.Cleanup(func() { stdoutIsTerminal = was })
	stdoutIsTerminal = func(io.Writer) bool { return true }
	var out, say bytes.Buffer
	if code := enrollmentsCmd("port49d", "export-enrollments", []string{"--config", "/nonexistent"}, &out, &say); code != 2 ||
		!strings.Contains(say.String(), "redirect it to a file or a pipe") || out.Len() != 0 {
		t.Fatalf("exit %d: %q %q", code, out.String(), say.String())
	}
	stdoutIsTerminal = func(io.Writer) bool { return false }
	say.Reset()
	if code := enrollmentsCmd("port49-broker", "init-enrollments", []string{"extra"}, &out, &say); code != 2 ||
		!strings.Contains(say.String(), "usage: port49-broker init-enrollments [--config FILE]") {
		t.Fatalf("a stray argument: exit %d: %s", code, say.String())
	}
	say.Reset()
	if code := enrollmentsCmd("port49d", "init-enrollments", []string{"--config", "/nonexistent"}, &out, &say); code != 1 {
		t.Fatalf("a config that does not load: exit %d: %s", code, say.String())
	}
}

// A config with no directory_password verifier holds no second factors: both
// commands say so and exit 1.
func TestEnrollmentCommandsNeedAVerifier(t *testing.T) {
	cfg, _ := signInConfig(t, "127.0.0.1:0")
	cfg.Broker.Identity.PasswordSignIn = nil
	for _, op := range []string{"init-enrollments", "export-enrollments"} {
		var out, say bytes.Buffer
		if code := runEnrollments(context.Background(), "port49d", op, cfg, signInTestKeys, io.Discard, &out, &say); code != 1 ||
			!strings.Contains(say.String(), "no directory_password verifier") || out.Len() != 0 {
			t.Errorf("%s: exit %d: %q %q", op, code, out.String(), say.String())
		}
	}
}

// export-enrollments --out FILE writes the same sealed bytes as stdout, to a new file made 0600
// that never replaces one, and leaves no partial file when the export fails (spec §12).
func TestExportEnrollmentsOut(t *testing.T) {
	cfg, _ := signInConfig(t, "127.0.0.1:0")
	ctx := context.Background()
	var say bytes.Buffer
	if code := runEnrollments(ctx, "port49d", "init-enrollments", cfg, signInTestKeys, io.Discard, io.Discard, &say); code != 0 {
		t.Fatalf("init: %d %s", code, say.String())
	}
	// A sealed export is not deterministic (a fresh nonce each time), so the same run is teed: what
	// the file holds is what stdout would have.
	var viaStdout bytes.Buffer
	run := func(w io.Writer) int {
		viaStdout.Reset()
		return runEnrollments(ctx, "port49d", "export-enrollments", cfg, signInTestKeys, io.Discard,
			io.MultiWriter(w, &viaStdout), &say)
	}
	path := filepath.Join(t.TempDir(), "enrollments.new")

	say.Reset()
	if code := withOutFile(path, &say, run); code != 0 {
		t.Fatalf("--out: exit %d: %s", code, say.String())
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, viaStdout.Bytes()) {
		t.Fatalf("the file holds %d bytes (%v), stdout %d: they must be the same", len(got), err, viaStdout.Len())
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("the file is mode %v, want 0600", fi.Mode().Perm())
	}

	// An existing file is never replaced, whatever it holds.
	say.Reset()
	if code := withOutFile(path, &say, run); code != 1 || !strings.Contains(say.String(), "exists") {
		t.Errorf("an existing file: exit %d: %q", code, say.String())
	}
	if again, _ := os.ReadFile(path); !bytes.Equal(again, got) {
		t.Error("an existing --out file was changed")
	}

	// A failed export leaves no partial file, and the failure is the export's.
	failed := filepath.Join(t.TempDir(), "failed.new")
	say.Reset()
	if code := withOutFile(failed, &say, func(w io.Writer) int { _, _ = w.Write([]byte("partial")); return 1 }); code != 1 {
		t.Errorf("a failed export: exit %d", code)
	}
	if _, err := os.Stat(failed); err == nil {
		t.Error("a failed export left its partial file")
	}
	// A missing directory is an error, and --out is the export's alone.
	if code := withOutFile(filepath.Join(t.TempDir(), "no", "such", "x"), &say, run); code != 1 {
		t.Errorf("a missing directory: exit %d", code)
	}
	var out bytes.Buffer
	say.Reset()
	if code := enrollmentsCmd("port49d", "init-enrollments", []string{"--out", path}, &out, &say); code != 2 ||
		!strings.Contains(say.String(), "export-enrollments") {
		t.Errorf("--out on init-enrollments: exit %d: %q", code, say.String())
	}
}
