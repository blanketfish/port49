//go:build lab

package lab

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Each L49 phase has its own compose directory, so phase B's stack does not
// remove phase A's logs (startComposeWith removes its directory).
func TestComposeDirNamesEachPhase(t *testing.T) {
	if got := composeDirName("arista_eos", ""); got != "compose-arista_eos" {
		t.Errorf("no phase: %q", got)
	}
	a, bc := composeDirName("arista_eos", "a"), composeDirName("arista_eos", "bc")
	if a != "compose-arista_eos-a" || bc != "compose-arista_eos-bc" {
		t.Errorf("phases: %q, %q", a, bc)
	}
}

const oxidizedStaleLog = `I, [2026-10-08T02:19:01.100 #1]  INFO -- : lib/oxidized/nodes.rb: Loaded 1 nodes
E, [2026-10-08T02:19:05.200 #8] ERROR -- : 172.100.100.11 raised Errno::ENOTTY with msg "Inappropriate ioctl for device"
E, [2026-10-08T02:19:05.300 #8] ERROR -- : 172.100.100.11 status no_connection, retries exhausted, creating crashfile
I, [2026-10-08T02:19:06.000 #8]  INFO -- : Configuration updated for nothing
`

func TestStaleRunExcerptKeepsClassAndMessage(t *testing.T) {
	got, err := staleRunExcerpt(oxidizedStaleLog, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Errno::ENOTTY", "Inappropriate ioctl for device", "creating crashfile"} {
		if !strings.Contains(got, want) {
			t.Errorf("excerpt lacks %q: %q", want, got)
		}
	}
	if strings.Contains(got, "Loaded 1 nodes") || strings.Contains(got, "Configuration updated") {
		t.Errorf("excerpt holds unrelated lines: %q", got)
	}
}

func TestStaleRunExcerptRefusesASecret(t *testing.T) {
	log := oxidizedStaleLog + `E, [x] ERROR -- : 172.100.100.11 raised Net::SSH::AuthenticationFailed with msg "tok-SECRET-1"` + "\n"
	if got, err := staleRunExcerpt(log, []string{"tok-SECRET-1"}); err == nil || strings.Contains(got, "tok-SECRET-1") {
		t.Errorf("a registered secret was quoted: %q, %v", got, err)
	}
	jws := `E, [x] ERROR -- : raised Errno::ENOTTY eyJhbGciOiJF.eyJzdWIiOiJ4.c2ln` + "\n"
	if got, err := staleRunExcerpt(jws, nil); err == nil || strings.Contains(got, "eyJ") {
		t.Errorf("a compact JWS was quoted: %q, %v", got, err)
	}
}

func TestStaleRunExcerptOfAQuietLogIsEmpty(t *testing.T) {
	got, err := staleRunExcerpt("I, [x]  INFO -- : all quiet\n", nil)
	if err != nil || got != "" {
		t.Errorf("got %q, %v", got, err)
	}
}

func TestCrashfilesListsOnlyFiles(t *testing.T) {
	dir := t.TempDir()
	if got := crashfiles(dir); len(got) != 0 {
		t.Errorf("no crash directory: %v", got)
	}
	// Oxidized's node crashfiles are ROOT/crashes/<ip> (node.rb, config.rb:48);
	// ROOT/crash is the single process-crash file (cli.rb), a different thing.
	if err := os.MkdirAll(filepath.Join(dir, "crashes", "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "crashes", "172.100.100.11"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := crashfiles(dir)
	if len(got) != 1 || got[0] != "172.100.100.11" {
		t.Errorf("got %v", got)
	}
	if processCrashed(dir) {
		t.Error("no process-crash file yet")
	}
	if err := os.WriteFile(filepath.Join(dir, "crash"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !processCrashed(dir) {
		t.Error("the process-crash file is missed")
	}
}

// The directory the harness reads crashfiles from must be Oxidized's ROOT in
// the container: OXIDIZED_HOME, else $HOME/.config/oxidized, and that path must
// be a host mount. The example config must not move the crash directory.
func TestOxidizedRootIsAHostMountOfTheOverlay(t *testing.T) {
	raw, err := os.ReadFile("compose/oxidized.yaml")
	if err != nil {
		t.Fatal(err)
	}
	got, err := oxidizedHostRoot(raw, "/L")
	if err != nil {
		t.Fatal(err)
	}
	if want := "/L/oxidized"; got != want {
		t.Errorf("host root %q, want %q (startOxidized's o.dir)", got, want)
	}
	cfg, err := os.ReadFile("../../examples/oxidized/config")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cfg), "\ncrash:") {
		t.Error("examples/oxidized/config sets crash:; the harness reads ROOT/crashes")
	}
	if _, err := oxidizedHostRoot([]byte("services:\n  oxidized:\n    environment:\n      HOME: /elsewhere\n    volumes:\n      - ${PORT49_COMPOSE_LOCAL}/oxidized:/oxhome/.config/oxidized\n"), "/L"); err == nil {
		t.Error("a mount that is not at ROOT was accepted")
	}
}

// A token that straddles the 220-character cut is caught: the whole line is
// checked before it is cut.
func TestStaleRunExcerptScrubsBeforeItCuts(t *testing.T) {
	secret := "tok-ABCDEFGHIJKLMNOP-0123456789"
	line := "E, [x] ERROR -- : raised Errno::ENOTTY msg " + strings.Repeat("p", 220-len("E, [x] ERROR -- : raised Errno::ENOTTY msg ")-8) + secret
	if len(line) <= 220 || strings.Index(line, secret) >= 220 || strings.Index(line, secret)+len(secret) <= 220 {
		t.Fatalf("fixture does not straddle the cut: %d", len(line))
	}
	got, err := staleRunExcerpt(line+"\n", []string{secret})
	if err == nil || got != "" {
		t.Errorf("a token across the cut survived: %q, %v", got, err)
	}
}

func TestCrashfilesSince(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "crashes")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	old, fresh := filepath.Join(dir, "172.100.100.11"), filepath.Join(dir, "172.100.100.12")
	for _, p := range []string{old, fresh} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	since := time.Now()
	if err := os.Chtimes(old, since.Add(-time.Hour), since.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(fresh, since, since); err != nil {
		t.Fatal(err)
	}
	got := crashfilesSince(root, since)
	if len(got) != 1 || got[0] != "172.100.100.12" {
		t.Errorf("got %v", got)
	}
	// a file that already existed and was overwritten by the run counts
	if err := os.Chtimes(old, since.Add(time.Second), since.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := crashfilesSince(root, since); len(got) != 2 {
		t.Errorf("an overwritten crashfile was missed: %v", got)
	}
}

func TestOxidizedDownWhy(t *testing.T) {
	if why := oxidizedDownWhy(false, nil); why != "" {
		t.Errorf("alive: %q", why)
	}
	if why := oxidizedDownWhy(true, nil); why != "" {
		t.Errorf("a process-crash file with the REST API answering is not down: %q", why)
	}
	if why := oxidizedDownWhy(true, errors.New("connection refused")); !strings.Contains(why, "process-crash file") {
		t.Errorf("crashed: %q", why)
	}
	if why := oxidizedDownWhy(false, errors.New("connection refused")); !strings.Contains(why, "REST") || strings.Contains(why, "process-crash file exists") {
		t.Errorf("gone without a crash file: %q", why)
	}
}

func TestScrubWrapperSaid(t *testing.T) {
	if got := scrubWrapperSaid("node leaf1 queued", []string{"s3cret-token-1"}); got != "node leaf1 queued" {
		t.Errorf("clean text changed: %q", got)
	}
	got := scrubWrapperSaid("login s3cret-token-1 failed", []string{"s3cret-token-1"})
	if strings.Contains(got, "s3cret") || !strings.Contains(got, "withheld") {
		t.Errorf("leak kept: %q", got)
	}
}

func TestOfferedMethods(t *testing.T) {
	m, ok := offeredMethods("x@172.100.100.11: Permission denied (publickey,keyboard-interactive).\n")
	if !ok || m != "publickey,keyboard-interactive" {
		t.Errorf("%q, %v", m, ok)
	}
	if _, ok := offeredMethods("ssh: connect to host 172.100.100.11 port 22: Connection refused\n"); ok {
		t.Error("a refused connection read as an answer")
	}
}

// Phase A's line states no device fact it did not measure.
func TestAuthMethodsLineStatesOnlyWhatWasMeasured(t *testing.T) {
	for _, plat := range []string{"arista_eos", "cisco_nxos", "juniper_vsrx"} {
		for _, ok := range []bool{true, false} {
			got := authMethodsLine(plat, "none password keyboard-interactive", ok)
			if !strings.Contains(got, "vars: auth_methods") || strings.Contains(got, "offers only") || strings.Contains(got, ".md:") {
				t.Errorf("%s/%v: %q", plat, ok, got)
			}
			if ok != strings.Contains(got, "none password keyboard-interactive") {
				t.Errorf("%s/%v: offered methods quoted only when read: %q", plat, ok, got)
			}
			if (plat == "arista_eos") != strings.Contains(got, "L4-error-arista_eos.md") {
				t.Errorf("%s: the EOS citation belongs to the EOS note alone: %q", plat, got)
			}
		}
	}
}

func TestJWSShapeCoversAFivePartJWE(t *testing.T) {
	jwe := "eyJhbGciOiJkaXIifQ..aXY.Y2lwaGVydGV4dA.dGFn"
	if got := jwsShape.ReplaceAllString("x="+jwe+" y", "<r>"); got != "x=<r> y" {
		t.Errorf("a JWE keeps parts: %q", got)
	}
}
