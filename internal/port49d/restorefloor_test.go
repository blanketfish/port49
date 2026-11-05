package port49d

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/policy"
	"github.com/blanketfish/port49/internal/store"
	etcdstore "github.com/blanketfish/port49/internal/store/etcd"
	"github.com/blanketfish/port49/internal/tacacs/wire"
)

// floorT is a restoreFloor with a fixed clock, a buffer for its lines and a
// record in a directory of its own.
type floorT struct {
	*restoreFloor
	t    *testing.T
	out  *bytes.Buffer
	now  time.Time
	path string
	m    *metrics.Metrics
}

const floorPrefix = "/p49/"

func floorAt(t *testing.T) *floorT {
	t.Helper()
	f := &floorT{t: t, out: &bytes.Buffer{}, now: time.Date(2026, 11, 5, 3, 0, 0, 0, time.UTC),
		path: filepath.Join(safeDir(t), "restore.json")}
	f.open()
	return f
}

// open builds a floor on f.path as a new process would, begun on a new run.
func (f *floorT) open() {
	f.restoreFloor = newRestoreFloor(f.out, func() time.Time { return f.now })
	f.attach(f.path, floorPrefix)
	f.m = metrics.New(prometheus.NewRegistry())
	f.begin(f.m)
}

// restart is the process ending after its last save, and a new one starting.
func (f *floorT) restart() {
	f.saveIfDirty()
	f.open()
}

// judge is one read as pass takes it: the record, then the read.
func (f *floorT) judge(r etcdstore.RestoreRead, err error) {
	f.restoreFloor.judge(f.record(), r, err)
}

func (f *floorT) read(witness, header uint64) {
	f.judge(etcdstore.RestoreRead{Witness: witness, Header: header}, nil)
}

func (f *floorT) restored(rev uint64, minted time.Time) bool {
	return f.Restored(store.Token{Revision: rev, MintedAt: minted}, f.now)
}

func (f *floorT) said(s string) int { return strings.Count(f.out.String(), s) }

const dropped = "the session store was restored from a snapshot"

// Probe (pre-beta stores): the right snapshot is restored after the wrong
// one, the right one carrying an old takeover's meta/purged above the first
// drop's header. No lift exists any more; the floor and the band hold.
func TestASecondRestoreCarryingAnOldPurgeRefusesItsTokens(t *testing.T) {
	f := floorAt(t)
	f.Saw(1000)
	f.read(1000, 1010)
	f.read(480, 500) // restore 1, no bump
	if f.floor != 500 || f.band != 1010 || !f.bandUntil.Equal(f.now.Add(policy.MaxTokenTTL+restoreSkew)) ||
		!f.bandUntil.Equal(f.now.Add(20*time.Minute)) {
		t.Fatalf("floor %d band %d until %v", f.floor, f.band, f.bandUntil)
	}
	f.read(985, 990) // restore 2: not a drop
	if f.said(dropped) != 1 {
		t.Fatalf("a second read inside the band was a drop: %q", f.out.String())
	}
	if !f.restored(970, f.now.Add(-2*time.Minute)) {
		t.Fatal("a token of the second snapshot, below the old high header, was served")
	}
	if f.restored(995, f.now.Add(restoreSkew+time.Second)) {
		t.Fatal("a token minted after the drop was refused")
	}
	if strings.Contains(f.out.String(), "purge") {
		t.Fatalf("the line mentions a purge: %q", f.out.String())
	}
}

// Probes (pre-beta identity): a second restore to a snapshot of the old
// timeline leaves the first drop's tokens refused.
func TestASecondOldTimelineRestoreKeepsTheFirstDropsTokensRefused(t *testing.T) {
	for _, name := range []string{"live", "expired"} {
		t.Run(name, func(t *testing.T) {
			f := floorAt(t)
			f.Saw(50)
			f.read(50, 55)
			f.read(10, 29) // restore 1
			f.read(45, 45) // restore 2
			if !f.restored(44, f.now.Add(-time.Hour)) {
				t.Fatalf("a token minted before restore 1 was served: floor %d band %d", f.floor, f.band)
			}
		})
	}
}

func TestAWitnessFollowedDuringTheReadIsNoDrop(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	ok := f.pass(context.Background(), time.Second, func(context.Context) (etcdstore.RestoreRead, error) {
		f.Saw(1100) // a put lands while the read is in flight
		return etcdstore.RestoreRead{Witness: 1000, Header: 1011}, nil
	})
	if !ok || f.floor != 0 || f.said(dropped) != 0 {
		t.Fatalf("a witness followed during the read was a drop: %q", f.out.String())
	}
}

func TestAPassTakesTheRecordBeforeItReads(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.pass(context.Background(), time.Second, func(context.Context) (etcdstore.RestoreRead, error) {
		f.Saw(1100)
		return etcdstore.RestoreRead{Witness: 1100, Header: 1101}, nil
	})
	if f.floor != 0 {
		t.Fatalf("a read that agrees with the follower was a drop: %q", f.out.String())
	}
}

func TestAFailedReadRefusesRedemptionsUntilOneAnswers(t *testing.T) {
	f := floorAt(t)
	if !f.Held() || testutil.ToFloat64(f.m.RedemptionRestoreUnjudged) != 1 {
		t.Fatal("a run is not held before its first read")
	}
	f.read(1000, 1010)
	if f.Held() || testutil.ToFloat64(f.m.RedemptionRestoreUnjudged) != 0 {
		t.Fatal("a read that answered left the floor held")
	}
	down := errors.Join(store.ErrUnavailable, errors.New("down"))
	f.judge(etcdstore.RestoreRead{}, down)
	f.judge(etcdstore.RestoreRead{}, down)
	if !f.Held() || testutil.ToFloat64(f.m.RedemptionRestoreUnjudged) != 1 || f.said("reading meta/witness") != 1 {
		t.Fatalf("a failed read: held %v, said %d times", f.Held(), f.said("reading meta/witness"))
	}
	if f.floor != 0 || f.said(dropped) != 0 {
		t.Fatal("a failed read judged a drop")
	}
	f.read(1000, 1012)
	if f.Held() || testutil.ToFloat64(f.m.RedemptionRestoreUnjudged) != 0 {
		t.Fatal("an answering read did not release the floor")
	}
}

func TestTheFloorsReadsAreCountedByOutcome(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.judge(etcdstore.RestoreRead{}, errors.New("down"))
	for outcome, want := range map[string]float64{"ok": 1, "error": 1} {
		if got := testutil.ToFloat64(f.m.StoreOps.WithLabelValues("restore_read", outcome)); got != want {
			t.Fatalf("restore_read %s = %v, want %v", outcome, got, want)
		}
	}
}

// A run judges the store before it serves: begin, then the synchronous pass;
// a drop found there is in force before pass returns.
func TestARunJudgesTheStoreBeforeItServes(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.restart()
	if !f.Held() {
		t.Fatal("a new run serves before its first read")
	}
	f.pass(context.Background(), time.Second, func(context.Context) (etcdstore.RestoreRead, error) {
		return etcdstore.RestoreRead{Witness: 480, Header: 500}, nil
	})
	if f.Held() || !f.restored(400, f.now) {
		t.Fatal("a drop found by the first pass was not in force when it returned")
	}
}

func TestAWitnessFollowedDuringAReadAfterADropIsNoSecondRestore(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.read(480, 500)
	f.pass(context.Background(), time.Second, func(context.Context) (etcdstore.RestoreRead, error) {
		f.Saw(600)
		return etcdstore.RestoreRead{Witness: 480, Header: 501}, nil
	})
	if f.said(dropped) != 1 || f.floor != 500 {
		t.Fatalf("a second drop: %q", f.out.String())
	}
}

func TestASecondRestoreIsToldOnTheFirstRead(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.read(480, 500)
	f.read(600, 610)
	f.read(300, 320) // below the first drop's witness
	if f.said(dropped) != 2 || f.floor != 320 {
		t.Fatalf("floor %d after a second restore, want 320 (replaced, not maxed): %q", f.floor, f.out.String())
	}
}

func TestASecondRestoreAboveTheFirstDropsBaselineIsInTheBand(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.read(480, 500)
	f.read(985, 990)
	if !f.restored(900, f.now.Add(-time.Minute)) || f.restored(1011, f.now.Add(-time.Minute)) {
		t.Fatal("the band does not cover the old timeline's revisions exactly")
	}
}

func TestARestoreAfterTheBandEndsIsStillTold(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.read(480, 500)
	f.now = f.now.Add(time.Hour)
	if f.restored(700, f.now.Add(-2*time.Hour)) {
		t.Fatal("the band outlasted its bound")
	}
	f.read(300, 320)
	if f.said(dropped) != 2 || f.floor != 320 {
		t.Fatalf("a restore after the band: %q", f.out.String())
	}
}

func TestAFreshMintIsNeverRestored(t *testing.T) {
	t.Run("bump", func(t *testing.T) {
		f := floorAt(t)
		f.read(1000, 1010)
		f.read(480, 5_000_000_000)
		if f.band != 0 {
			t.Fatalf("a bump armed a band: %d", f.band)
		}
		if f.restored(5_000_000_001, f.now) {
			t.Fatal("a token minted after a bumped restore was refused")
		}
	})
	t.Run("no bump", func(t *testing.T) {
		f := floorAt(t)
		f.read(1000, 1010)
		f.read(480, 500)
		if f.restored(600, f.now.Add(restoreSkew+time.Millisecond)) {
			t.Fatal("a token minted after the drop was refused inside the band")
		}
	})
	t.Run("no bump, the cost", func(t *testing.T) {
		f := floorAt(t)
		f.read(1000, 1010)
		f.read(480, 500)
		if !f.restored(600, f.now.Add(4*time.Minute)) {
			t.Fatal("a token inside the band and the skew was served")
		}
		if f.restored(1011, f.now) {
			t.Fatal("a token above the old high header was refused")
		}
	})
}

func TestAClockStepBackNeverRevivesARestoredToken(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.read(480, 500)
	for _, at := range []time.Time{f.now.Add(-time.Hour), f.now.Add(time.Hour)} {
		if !f.Restored(store.Token{Revision: 400, MintedAt: at}, at) {
			t.Fatalf("a restored token was served at %v", at)
		}
	}
}

func TestAQuietStoreRestoreRefusesATokenMintedAfterTheLastWitness(t *testing.T) {
	f := floorAt(t)
	f.read(480, 490) // the witness last written at 02:00
	f.read(100, 500) // the snapshot, taken at 03:00:00.4, after a token was minted at 03:00
	if !f.Restored(store.Token{Revision: 499, MintedAt: f.now.Add(-time.Second)}, f.now) {
		t.Fatalf("the token minted after the last witness was served: %q", f.out.String())
	}
}

func TestTheFloorIgnoresMintedAt(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.read(480, 500)
	for _, at := range []time.Time{{}, f.now.Add(time.Hour), f.now.Add(-time.Hour)} {
		if !f.restored(500, at) || !f.restored(1, at) {
			t.Fatalf("a token at or below the floor was served (minted %v)", at)
		}
	}
}

func TestTheDropLineSaysWhatIsRefusedAndTheRunbook(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.read(480, 500)
	line := f.out.String()
	for _, want := range []string{"token_spent", "a token minted after this read is served", "design §13", "--bump-revision",
		f.bandUntil.UTC().Format(time.RFC3339),
		"tokens minted since the restore and before this read are refused once too"} {
		if !strings.Contains(line, want) {
			t.Errorf("the line lacks %q: %q", want, line)
		}
	}
	if strings.Contains(line, "stop port49d") {
		t.Errorf("the line tells the operator to stop port49d: %q", line)
	}
	bumped := floorAt(t)
	bumped.read(1000, 1010)
	bumped.read(480, 5_000_000_000)
	if strings.Contains(bumped.out.String(), "--bump-revision") || !strings.Contains(bumped.out.String(), "token_spent") {
		t.Errorf("the bumped line: %q", bumped.out.String())
	}
}

func TestTheFloorSurvivesARestart(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.read(480, 500)
	f.restart()
	if !f.restored(400, f.now) {
		t.Fatal("a restart forgot the floor")
	}
	f.read(480, 501) // the same witness, a later header
	if f.said(dropped) != 1 {
		t.Fatalf("a restart made the same witness a new drop: %q", f.out.String())
	}
}

func TestARestartAfterARestoreTellsTheDrop(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.restart()
	f.read(480, 500)
	if f.said(dropped) != 1 || f.floor != 500 {
		t.Fatalf("a restore under a stopped port49d was not told: %q", f.out.String())
	}
}

func TestARecordOfAnotherPrefixIsNoRecord(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.saveIfDirty()
	other := &floorT{t: t, out: &bytes.Buffer{}, now: f.now, path: f.path}
	other.restoreFloor = newRestoreFloor(other.out, func() time.Time { return other.now })
	other.attach(f.path, "/other/")
	other.begin(metrics.New(prometheus.NewRegistry()))
	other.read(480, 500)
	if !strings.Contains(other.out.String(), "another prefix's") || other.said(dropped) != 0 {
		t.Fatalf("another prefix's record was used: %q", other.out.String())
	}
}

func TestAnUnreadableRecordMakesTheFirstReadADrop(t *testing.T) {
	f := &floorT{t: t, out: &bytes.Buffer{}, now: time.Date(2026, 11, 5, 3, 0, 0, 0, time.UTC),
		path: filepath.Join(safeDir(t), "restore.json")}
	if err := os.WriteFile(f.path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.open()
	if aside, _ := filepath.Glob(f.path + ".bad-*"); len(aside) != 1 {
		t.Fatalf("the unreadable record was not moved aside: %v", aside)
	}
	if !strings.Contains(f.out.String(), "every token in the store is refused") {
		t.Fatalf("the line: %q", f.out.String())
	}
	f.restart() // before the first read: still owed
	f.read(1000, 1010)
	if f.said(dropped) != 1 || !f.restored(1010, f.now) {
		t.Fatalf("the first read was not a drop: %q", f.out.String())
	}
	f.read(1000, 1011)
	if f.said(dropped) != 1 {
		t.Fatal("the second read was a drop too")
	}
}

func TestAnAbsentRecordIsSaidOnce(t *testing.T) {
	f := floorAt(t)
	f.attach(f.path, floorPrefix) // a later run's attach
	f.begin(f.m)
	if f.said("no restore record at") != 1 {
		t.Fatalf("said %d times: %q", f.said("no restore record at"), f.out.String())
	}
	f.read(480, 500)
	if f.said(dropped) != 0 {
		t.Fatal("with no record the first read was a drop")
	}
}

func TestTheHeaderFallingIsADrop(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.read(1000, 900)
	if f.said(dropped) != 1 || f.floor != 900 {
		t.Fatalf("a falling header was no drop: %q", f.out.String())
	}
}

func TestAWitnessThatMovesBelowAReadHeaderIsADrop(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.read(1005, 1012) // a live put cannot land at or below 1010
	if f.said(dropped) != 1 {
		t.Fatalf("a witness below the earlier header was no drop: %q", f.out.String())
	}
	g := floorAt(t)
	g.read(1000, 1010)
	g.read(1011, 1012)
	if g.said(dropped) != 0 {
		t.Fatalf("a live put was a drop: %q", g.out.String())
	}
}

func TestAFollowedWitnessBelowAReadHeaderIsADropAtTheNextPass(t *testing.T) {
	cases := []struct {
		name string
		saw  uint64
		read etcdstore.RestoreRead
		drop bool
	}{
		{"inside the header", 1005, etcdstore.RestoreRead{Witness: 1005, Header: 1012}, true},
		{"inside the header, the read shows the old witness", 1005, etcdstore.RestoreRead{Witness: 1000, Header: 1011}, true},
		{"above the header", 1011, etcdstore.RestoreRead{Witness: 1011, Header: 1012}, false},
		{"a late event", 998, etcdstore.RestoreRead{Witness: 1000, Header: 1012}, false},
		{"the same witness", 1000, etcdstore.RestoreRead{Witness: 1000, Header: 1012}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := floorAt(t)
			f.read(1000, 1010)
			f.Saw(c.saw)
			if f.said(dropped) != 0 {
				t.Fatal("Saw judged")
			}
			f.judge(c.read, nil)
			if got := f.said(dropped) == 1; got != c.drop {
				t.Fatalf("drop %v, want %v: %q", got, c.drop, f.out.String())
			}
		})
	}
}

func TestATokenWithNoRevisionIsRefusedUnderAFloor(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.read(480, 500)
	if !f.Restored(store.Token{}, f.now) {
		t.Fatal("a token with no revision was served under a floor")
	}
	g := floorAt(t)
	g.read(1000, 1010)
	if g.Restored(store.Token{}, g.now) {
		t.Fatal("a token was refused with no drop found")
	}
}

func TestARecordThatCannotBeSavedKeepsServingAndSaysSoOnce(t *testing.T) {
	f := floorAt(t)
	fail := true
	f.save = func(path string, body []byte) error {
		if fail {
			return errors.New("read-only file system")
		}
		return writeOwnerOnly(path, body)
	}
	f.read(1000, 1010)
	f.read(480, 500)
	f.saveIfDirty()
	f.saveIfDirty()
	if f.Held() || f.said("saving ") != 1 {
		t.Fatalf("held %v, said %d times: %q", f.Held(), f.said("saving "), f.out.String())
	}
	if !f.restored(400, f.now) {
		t.Fatal("a record that cannot be saved stopped the floor")
	}
	fail = false
	f.saveIfDirty()
	f.restart()
	if !f.restored(400, f.now) {
		t.Fatal("the save was not retried")
	}
}

func TestADropIsSavedAtOnce(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.read(480, 500) // judge saves a drop, no tick between
	body, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	var rec floorFile
	if err := json.Unmarshal(body, &rec); err != nil || rec.Floor != 500 || rec.Prefix != floorPrefix {
		t.Fatalf("the record after a drop: %+v %v", rec, err)
	}
}

func TestARunWhoseFirstReadFailsOpensHeldAndGauged(t *testing.T) {
	f := floorAt(t)
	f.pass(context.Background(), time.Second, func(context.Context) (etcdstore.RestoreRead, error) {
		return etcdstore.RestoreRead{}, errors.Join(store.ErrUnavailable, errors.New("down"))
	})
	if !f.Held() || testutil.ToFloat64(f.m.RedemptionRestoreUnjudged) != 1 {
		t.Fatal("a run whose first read failed is not held")
	}
}

func TestTheRestoreDetectedGaugeIsSetAgainInANewRun(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	if testutil.ToFloat64(f.m.StoreRestoreDetected) != 0 {
		t.Fatal("the gauge reads a restore that was not found")
	}
	f.read(480, 500)
	want := float64(f.now.Unix())
	if got := testutil.ToFloat64(f.m.StoreRestoreDetected); got != want {
		t.Fatalf("gauge %v, want %v", got, want)
	}
	f.m = metrics.New(prometheus.NewRegistry()) // the next run's registry
	f.begin(f.m)
	if got := testutil.ToFloat64(f.m.StoreRestoreDetected); got != want {
		t.Fatalf("a new run's registry reads %v, want %v", got, want)
	}
}

// The memory store has no revisions and no restore: a daemon on it builds no
// floor, and a minted token logs in (Review Focus 3).
func TestTheMemoryStoreHasNoFloor(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	b := brokerConfig(t, minimalPolicy).Broker
	pkiDir := filepath.Dir(b.TLSCertFile)
	cfgPath := writeRunConfig(t, b)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	})
	waitFor(t, &out, "port49d: broker listening on ")
	addrs := regexp.MustCompile(`listening on (127\.0\.0\.1:\d+)`).FindAllStringSubmatch(out.String(), -1)
	if len(addrs) != 2 {
		t.Fatalf("stderr: %q", out.String())
	}
	dev := tacacsClient{t: t, addr: addrs[0][1], key: []byte("run-test-secret")}
	if st := dev.login("alice", mint(t, addrs[1][1], pkiDir, "leaf1")); st != wire.AuthenStatusPass {
		t.Fatalf("login: status %d; decision log %s", st, log.String())
	}
	if strings.Contains(out.String(), "restore record") {
		t.Fatalf("a memory store kept a restore record: %q", out.String())
	}
}

// JSON that decodes but is no record fails closed, as a torn file does.
func TestARecordThatIsNoRecordIsUnreadable(t *testing.T) {
	for name, body := range map[string]string{"null": `null`, "empty object": `{}`,
		"a prefix alone": `{"prefix":"` + floorPrefix + `"}`} {
		t.Run(name, func(t *testing.T) {
			f := &floorT{t: t, out: &bytes.Buffer{}, now: time.Date(2026, 11, 5, 3, 0, 0, 0, time.UTC),
				path: filepath.Join(safeDir(t), "restore.json")}
			if err := os.WriteFile(f.path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			f.open()
			if aside, _ := filepath.Glob(f.path + ".bad-*"); len(aside) != 1 {
				t.Fatalf("not moved aside: %v", aside)
			}
			f.read(1000, 1010)
			if f.said(dropped) != 1 || !f.restored(1010, f.now) {
				t.Fatalf("the first read was not a drop: %q", f.out.String())
			}
		})
	}
}

// The gauge is the time of the last drop, kept in the record: a restart does
// not clear it.
func TestTheDetectedTimeSurvivesARestart(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.read(480, 500)
	want := float64(f.now.Unix())
	f.now = f.now.Add(time.Hour)
	f.restart()
	if got := testutil.ToFloat64(f.m.StoreRestoreDetected); got != want {
		t.Fatalf("after a restart the gauge reads %v, want %v", got, want)
	}
}

// A run whose config named another spool path or prefix opens that record.
func TestAReattachToAnotherPrefixOpensItsRecordAfresh(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.read(480, 500)
	f.attach(f.path, "/other/")
	if f.restored(400, f.now) || f.Restored(store.Token{Revision: 400}, f.now) {
		t.Fatal("another prefix's floor was kept")
	}
	f.attach(filepath.Join(safeDir(t), "restore.json"), floorPrefix)
	if f.restored(400, f.now) {
		t.Fatal("another path's floor was kept")
	}
}

// Ported from the Task 3 review's probes: sequences of restores, restarts and
// failed saves the floor must hold through.

func TestAWitnessRewrittenBeforeTheReadIsStillTold(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.Saw(501)
	f.read(501, 502) // a restored timeline's rewrite, below the header already read
	if !f.restored(900, f.now.Add(-time.Minute)) {
		t.Fatalf("served; floor %d", f.floor)
	}
}

func TestADoubleRestoreWithARestartBetweenKeepsBothFloors(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.read(480, 500)
	f.restart()
	f.read(985, 990)
	if !f.restored(970, f.now.Add(-2*time.Minute)) || !f.restored(450, f.now.Add(-2*time.Minute)) {
		t.Fatalf("served after a restart; floor %d band %d", f.floor, f.band)
	}
}

func TestADropWhoseSaveFailedIsToldAgainAfterARestart(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.saveIfDirty()
	f.save = func(string, []byte) error { return errors.New("disk full") }
	f.read(480, 500)
	f.restart() // the file still holds {1000, 1010}
	f.read(510, 520)
	if !f.restored(450, f.now.Add(-2*time.Minute)) {
		t.Fatalf("served; floor %d", f.floor)
	}
}

func TestTheBandEdgesAndItsSurvivalOfARestart(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.read(480, 500)
	from := f.now
	for _, c := range []struct {
		at, minted time.Duration
		want       bool
	}{
		{0, restoreSkew, true},
		{0, restoreSkew + time.Nanosecond, false},
		{20*time.Minute - time.Nanosecond, 0, true},
		{20 * time.Minute, 0, false},
		{-time.Hour, 0, true}, // a clock stepped back: still in the band
	} {
		tok := store.Token{Revision: 600, MintedAt: from.Add(c.minted)}
		if got := f.Restored(tok, from.Add(c.at)); got != c.want {
			t.Errorf("at +%v minted +%v: Restored %v, want %v", c.at, c.minted, got, c.want)
		}
	}
	f.restart()
	if !f.Restored(store.Token{Revision: 600, MintedAt: from}, from.Add(19*time.Minute)) {
		t.Errorf("the band did not survive a restart: band %d until %v", f.band, f.bandUntil)
	}
}

func TestAFollowedWitnessLostOnRestartIsStillADrop(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.Saw(1005)
	f.restart()
	f.read(1005, 1012)
	if !f.restored(900, f.now) {
		t.Fatalf("served; floor %d", f.floor)
	}
}

func TestTheWitnessGoneAfterARestoreIsADrop(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.read(0, 500)
	if !f.restored(400, f.now) {
		t.Fatalf("served; floor %d", f.floor)
	}
}

// A config change that moves only the spool path keeps the keyspace: the
// floor stays, and the record is written at the new path.
func TestAReattachToAnotherPathKeepsTheFloorAndMovesTheRecord(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.read(480, 500) // a drop, not yet saved
	moved := filepath.Join(safeDir(t), "restore.json")
	f.attach(moved, floorPrefix)
	if !f.restored(400, f.now) {
		t.Fatal("a path-only re-attach dropped the floor: the restored token was served")
	}
	f.saveIfDirty()
	f.path = moved
	f.restart()
	f.read(480, 500)
	if !f.restored(400, f.now) || f.said(dropped) != 1 {
		t.Fatalf("the record was not written at the new path: %q", f.out.String())
	}
}

// A re-attach that resets the state to an absent record must not leave the
// reset state dirty: saving it would write a record with no witness, which
// the next start reads as no record at all and takes as a drop.
func TestAReattachToAnAbsentRecordSavesNothing(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.read(480, 500)
	f.savedRev = 0 // the drop's save failed: the old record is dirty
	other := filepath.Join(safeDir(t), "restore.json")
	f.attach(other, "/other/")
	f.saveIfDirty()
	if _, err := os.Stat(other); err == nil {
		t.Fatal("a record with no witness and no header was saved")
	}
}

func TestAnEmptyStateIsNeverSaved(t *testing.T) {
	f := floorAt(t)
	f.rev++
	f.saveIfDirty()
	if _, err := os.Stat(f.path); err == nil {
		t.Fatal("a record with no witness and no header was saved")
	}
}
