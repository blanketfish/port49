package port49d

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/author"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/token"
)

// seedConfig is the smallest config mintSeeds reads: where the pairs go, and
// who gets one.
func seedConfig(path string) config.Config {
	return config.Config{
		ContextIdleTTL: time.Hour,
		Session:        config.SessionConfig{MaxSessionAgeDefault: time.Hour},
		Lab: &config.LabConfig{
			SeedTokenFile: path,
			SeedTokens:    []config.SeedToken{{NAS: "leaf-01", Username: "alice"}},
		},
	}
}

func seedMinter() *token.Minter {
	return token.NewMinter(memory.New(time.Now), decision.NewJSONLines(io.Discard), rand.Reader,
		token.TagKey([]byte("seed-test-key")), time.Now, 8)
}

// A symlink at the seed-token path is refused, and nothing is written through
// it. The shipped lab config points this at /tmp, where anyone on the box can
// place one; followed, the credentials land wherever it points and the Chmod
// narrows a file whose owner can widen it again.
func TestSeedTokenFileRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "somewhere-else.jsonl")
	link := filepath.Join(dir, "tokens.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := mintSeeds(context.Background(), seedConfig(link), seedMinter()); err == nil {
		t.Fatal("a symlink at lab.seed_token_file must fail the start, before the listener opens")
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatalf("%s was created, so the credentials were written through the symlink after all", target)
	}
}

// A file already at the path keeps its own mode through O_CREATE, so the write
// has to narrow it. Without that, a seed file left at 0644 is filled with live
// credentials and left world-readable.
func TestSeedTokenFileIsNarrowedTo0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.jsonl")
	if err := os.WriteFile(path, []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	logins, enables, err := mintSeeds(context.Background(), seedConfig(path), seedMinter())
	if err != nil {
		t.Fatal(err)
	}
	// The seed did not ask for an enable token, so there is no pair: the count
	// the daemon prints has to say so rather than calling every seed a pair.
	if logins != 1 || enables != 0 {
		t.Fatalf("minted %d login(s) and %d enable(s), want 1 and 0", logins, enables)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("seed-token file mode is %v, not 0600", info.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 || string(b[:5]) == "stale" {
		t.Fatalf("the file was not truncated before the pairs were written: %q", b)
	}
}

func TestHandlersSeeTheStoreItselfWithoutAFaultFile(t *testing.T) {
	st := memory.New(time.Now)
	if got := labHandlerStore(st, author.LabFault{}); got != store.Store(st) {
		t.Fatalf("with no fault_file the handlers got %T, want the store itself", got)
	}
	got := labHandlerStore(st, author.LabFault{Path: filepath.Join(t.TempDir(), "fault")})
	if fs, ok := got.(*author.FaultStore); !ok || fs.Store != store.Store(st) {
		t.Fatalf("with a fault_file the handlers got %T, want *author.FaultStore over the store", got)
	}
}

// A lab: block makes the start say, on stderr, what it enables and that it
// must never be in production; no block says nothing (owner's ruling
// 2026-09-24; design §13).
func TestALabBlockIsAnnouncedAtStart(t *testing.T) {
	if got := labWarning(nil); got != "" {
		t.Fatalf("no lab block: %q", got)
	}
	got := labWarning(&config.LabConfig{SeedTokenFile: "/tmp/seeds.jsonl",
		SeedTokens: []config.SeedToken{{NAS: "leaf-01", Username: "alice"}, {NAS: "nx1", Username: "bob"}},
		FaultFile:  "/tmp/fault"})
	for _, want := range []string{"LAB MODE", "2 seed token(s) minted to /tmp/seeds.jsonl", "fault file /tmp/fault",
		"lab fallback authorizer", "must never be in production"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if strings.Count(got, "\n") != 1 || !strings.HasSuffix(got, "\n") {
		t.Errorf("one line: %q", got)
	}
	bare := labWarning(&config.LabConfig{})
	if strings.Contains(bare, "seed token") || strings.Contains(bare, "fault file") ||
		!strings.Contains(bare, "lab fallback authorizer") {
		t.Errorf("a bare lab block enables the fallback authorizer alone: %q", bare)
	}
}

// The start says what the configuration file itself carries that moved:
// `enable_username: principal` in port49d.yaml loads, and the start tells
// the operator the key lives in the policy file now (task 8 review minor 2).
func TestTheStartSaysAKeyMoved(t *testing.T) {
	var out bytes.Buffer
	announce(&out, &config.Config{Notices: []string{"platforms.cisco_iosxe.enable_username moved to the policy file"}})
	if out.String() != "port49d: platforms.cisco_iosxe.enable_username moved to the policy file\n" {
		t.Fatalf("%q", out.String())
	}
}
