package broker

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/crypt"
	"github.com/blanketfish/port49/internal/store/enrollfile"
	"github.com/blanketfish/port49/internal/store/memory"
)

const bobPrincipal = "user:bob@example.com"

// staleEnrollments reads the records in stale, and the mark when markStale,
// as ones that opened under the previous key; broken records do not open.
// onMark runs once, after the mark is read and before it is returned: the
// moment an operator can act between the pass's read and its write.
type staleEnrollments struct {
	store.Enrollments
	stale     map[string]bool
	broken    map[string]bool
	markStale bool
	onMark    func()
}

func (s *staleEnrollments) GetSecondFactor(ctx context.Context, p string) (store.SecondFactor, error) {
	f, err := s.Enrollments.GetSecondFactor(ctx, p)
	if s.broken[p] {
		// As crypt does: the revision comes back with the error.
		return store.SecondFactor{Principal: p, Rev: f.Rev},
			errors.New("crypt: opening second factor: crypt: sealed under an unknown key")
	}
	if err == nil && s.stale[p] {
		f.Stale = true
	}
	return f, err
}

func (s *staleEnrollments) GetEnrollmentMark(ctx context.Context) (store.EnrollmentMark, error) {
	m, err := s.Enrollments.GetEnrollmentMark(ctx)
	if err == nil && s.markStale {
		m.Stale = true
		if h := s.onMark; h != nil {
			s.onMark = nil
			h()
		}
	}
	return m, err
}

// shape is f as a failure says it: never its secret.
func shape(f store.SecondFactor) string {
	return fmt.Sprintf("{%s state %s, rev %d, until %s, a %d-byte secret}", f.Principal, f.State, f.Rev,
		f.Until.Format(time.RFC3339), len(f.Secret))
}

func revOf(t *testing.T, e store.Enrollments, p string) store.SecondFactor {
	t.Helper()
	f, err := e.GetSecondFactor(context.Background(), p)
	if err != nil {
		t.Fatal(p, err)
	}
	return f
}

// The re-seal pass rewrites a record that opened under the previous key,
// and leaves a current one (ruling 11). A record that will not open is
// counted and said once, naming reset-second-factor, and never deleted.
func TestTheReSealPassSealsStaleRecords(t *testing.T) {
	ctx := context.Background()
	f, _ := newSignInFixture(t)
	inner := f.b.Enrollments
	w := &staleEnrollments{Enrollments: inner, stale: map[string]bool{alicePrincipal: true},
		broken: map[string]bool{"user:carol@example.com": true}}
	f.b.Enrollments = w
	f.enrolled(t, alicePrincipal, "uuid:alice")
	f.enrolled(t, bobPrincipal, "uuid:bob")
	f.enrolled(t, "user:carol@example.com", "uuid:carol")
	aliceRev, bobRev := revOf(t, inner, alicePrincipal).Rev, revOf(t, inner, bobPrincipal).Rev
	n, err := f.b.ResealSecondFactors(ctx)
	if err != nil || n != 1 {
		t.Fatalf("sealed %d: %v", n, err)
	}
	if got := revOf(t, inner, alicePrincipal).Rev; got == aliceRev {
		t.Fatalf("the stale record was not rewritten (rev %d)", got)
	}
	if got := revOf(t, inner, bobPrincipal).Rev; got != bobRev {
		t.Fatalf("the current record was rewritten (rev %d, was %d)", got, bobRev)
	}
	if _, err := inner.GetSecondFactor(ctx, "user:carol@example.com"); err != nil {
		t.Fatalf("a record that will not open was deleted: %v", err)
	}
	if _, err := f.b.ResealSecondFactors(ctx); err != nil {
		t.Fatal(err)
	}
	logs := f.logs()
	if c := strings.Count(logs, "carol@example.com's second factor does not open"); c != 1 ||
		!strings.Contains(logs, "reset-second-factor user:carol@example.com") ||
		!strings.Contains(logs, "could not open 1 second factors") {
		t.Fatalf("said %d times:\n%s", c, logs)
	}
}

// A real key rotation: records and the mark written under k1 are read Stale
// under k2 with k1 previous, the pass seals them under k2, and then they are
// not Stale.
func TestTheReSealPassRetiresThePreviousKey(t *testing.T) {
	ctx := context.Background()
	f, _ := newSignInFixture(t)
	mem := memory.NewEnrollments(f.b.Now)
	k1 := testKeys("k1")
	old := crypt.WrapEnrollments(mem, k1, nil)
	if err := old.CreateEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: f.now}); err != nil {
		t.Fatal(err)
	}
	f.b.Enrollments = old
	f.enrolled(t, alicePrincipal, "uuid:alice")
	k2 := testKeys("k2")
	k2.Previous = &k1.Current
	f.b.Enrollments = crypt.WrapEnrollments(mem, k2, nil)
	if !revOf(t, f.b.Enrollments, alicePrincipal).Stale {
		t.Fatal("the record under the previous key is not stale")
	}
	if n, err := f.b.ResealSecondFactors(ctx); err != nil || n != 2 {
		t.Fatalf("sealed %d (the record and the mark): %v", n, err)
	}
	m, err := f.b.Enrollments.GetEnrollmentMark(ctx)
	if err != nil || m.Stale || revOf(t, f.b.Enrollments, alicePrincipal).Stale {
		t.Fatalf("still stale after the pass: %+v, %v", m, err)
	}
	if n, err := f.b.ResealSecondFactors(ctx); err != nil || n != 0 {
		t.Fatalf("a second pass sealed %d: %v", n, err)
	}
}

// A reopened record may hold the secret of an enrollment under way. The
// re-seal writes it back whole: not corrupt, and not an active factor.
func TestTheReSealPassKeepsAPendingSecretInAReopenedRecord(t *testing.T) {
	ctx := context.Background()
	f, _ := newSignInFixture(t)
	if err := f.b.Enrollments.SwapSecondFactor(ctx, store.SecondFactor{Principal: alicePrincipal,
		State: store.SecondFactorReopened, Until: f.now.Add(24 * time.Hour)}, 0); err != nil {
		t.Fatal(err)
	}
	enrollAlice(t, f)
	before := revOf(t, f.b.Enrollments, alicePrincipal)
	if before.State != store.SecondFactorReopened || len(before.Secret) == 0 {
		t.Fatalf("setup: %s", shape(before))
	}
	f.b.Enrollments = &staleEnrollments{Enrollments: f.b.Enrollments, stale: map[string]bool{alicePrincipal: true}}
	if n, err := f.b.ResealSecondFactors(ctx); err != nil || n != 1 {
		t.Fatalf("sealed %d: %v", n, err)
	}
	after := revOf(t, f.b.Enrollments, alicePrincipal)
	if after.Rev == before.Rev || after.State != store.SecondFactorReopened || !bytes.Equal(after.Secret, before.Secret) ||
		!after.Until.Equal(before.Until) || after.LastStep != 0 {
		t.Fatalf("the re-seal changed the record: %s, was %s", shape(after), shape(before))
	}
}

// An operator's reset --all between the pass's read of a stale mark and its
// write stands: the pass's swap is refused, which is not an error.
func TestTheReSealPassNeverRevertsAResetAll(t *testing.T) {
	ctx := context.Background()
	f, _ := newSignInFixture(t)
	w := &staleEnrollments{Enrollments: f.b.Enrollments, markStale: true}
	f.b.Enrollments = w
	w.onMark = func() {
		if _, err := f.b.ResetSecondFactor(ctx, "", true, "offline uid 0"); err != nil {
			t.Error(err)
		}
	}
	n, err := f.b.ResealSecondFactors(ctx)
	if err != nil || n != 0 {
		t.Fatalf("sealed %d: %v", n, err)
	}
	m, err := w.Enrollments.GetEnrollmentMark(ctx)
	if err != nil || !m.ReopenAllUntil.Equal(f.now.Add(f.b.PasswordSignIn.ReopenFor)) {
		t.Fatalf("the pass reverted the reset: %+v, %v", m, err)
	}
}

// Reset makes the record reopened for reopen_for with no secret, prints
// what it removed, and records second_factor_reset with the origin; a
// sign-in then enrolls (the lost phone at 3am).
func TestResetReopensEnrollment(t *testing.T) {
	ctx := context.Background()
	f, _ := newSignInFixture(t)
	secret := f.enrolled(t, alicePrincipal, "uuid:alice")
	text, err := f.b.ResetSecondFactor(ctx, "USER:Alice@Example.com", false, "offline uid 0")
	until := decision.FormatTime(f.now.Add(f.b.PasswordSignIn.ReopenFor))
	if err != nil || !strings.Contains(text, "enrolled "+decision.FormatTime(f.now.Add(-time.Hour))+" from 192.0.2.0/32") ||
		!strings.Contains(text, "they may enroll until "+until) {
		t.Fatalf("%q, %v", text, err)
	}
	got := revOf(t, f.b.Enrollments, alicePrincipal)
	if got.State != store.SecondFactorReopened || len(got.Secret) != 0 || !got.Until.Equal(f.now.Add(f.b.PasswordSignIn.ReopenFor)) {
		t.Fatalf("%s", shape(got))
	}
	recs := eventsOf(f.records(t), decision.EventSecondFactorReset)
	if len(recs) != 1 || recs[0]["principal"] != alicePrincipal {
		t.Fatalf("%v", recs)
	}
	body := recs[0]["second_factor_reset"].(map[string]any)
	if body["origin"] != "offline uid 0" || body["reopen_until"] != until || body["enrolled_from"] != "192.0.2.0/32" {
		t.Fatalf("%v", body)
	}
	if strings.Contains(f.logs(), base64.StdEncoding.EncodeToString(secret)) {
		t.Fatal("the old secret reached the log")
	}
	enrollAlice(t, f) // the sign-in enrolls: a 202, not a 403
}

// A reopened record holding an enrollment's secret is reset like any other:
// the secret goes, and the handle that held it no longer confirms.
func TestResetClearsAPendingSecretInAReopenedRecord(t *testing.T) {
	ctx := context.Background()
	f, _ := newSignInFixture(t)
	if err := f.b.Enrollments.SwapSecondFactor(ctx, store.SecondFactor{Principal: alicePrincipal,
		State: store.SecondFactorReopened, Until: f.now.Add(time.Hour)}, 0); err != nil {
		t.Fatal(err)
	}
	e, secret := enrollAlice(t, f)
	text, err := f.b.ResetSecondFactor(ctx, alicePrincipal, false, "offline uid 0")
	if err != nil || !strings.Contains(text, "unconfirmed enrollment") {
		t.Fatalf("%q, %v", text, err)
	}
	if got := revOf(t, f.b.Enrollments, alicePrincipal); got.State != store.SecondFactorReopened || len(got.Secret) != 0 {
		t.Fatalf("%s", shape(got))
	}
	w := f.confirm(t, api.ConfirmRequest{Handle: e.Handle, Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))})
	if w.Code != 401 {
		t.Fatalf("a reset enrollment confirmed: %s", shown(w))
	}
}

// A person with no record is reset all the same; a principal that is not a
// person's is refused; and a record that will not open is replaced at the
// revision the failed read gave back.
func TestResetOfNoRecordAnAppAndAnUnopenableRecord(t *testing.T) {
	ctx := context.Background()
	f, _ := newSignInFixture(t)
	if text, err := f.b.ResetSecondFactor(ctx, alicePrincipal, false, "o"); err != nil ||
		!strings.Contains(text, "had no second factor") {
		t.Fatalf("%q, %v", text, err)
	}
	if got := revOf(t, f.b.Enrollments, alicePrincipal); got.State != store.SecondFactorReopened {
		t.Fatalf("%s", shape(got))
	}
	if _, err := f.b.ResetSecondFactor(ctx, "app:ci", false, "o"); err == nil || !strings.Contains(err.Error(), "user: principal") {
		t.Fatalf("%v", err)
	}
	if _, err := f.b.ResetSecondFactor(ctx, "", false, "o"); err == nil {
		t.Fatal("an empty principal was reset")
	}
	if _, err := f.b.ResetSecondFactor(ctx, alicePrincipal, true, "o"); err == nil {
		t.Fatal("a principal and --all were both taken")
	}

	mem := memory.NewEnrollments(f.b.Now)
	k1 := testKeys("k1")
	one := crypt.WrapEnrollments(mem, k1, nil)
	if err := one.CreateEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: f.now}); err != nil {
		t.Fatal(err)
	}
	f.b.Enrollments = one
	f.enrolled(t, bobPrincipal, "uuid:bob")
	f.b.Enrollments = crypt.WrapEnrollments(mem, testKeys("k2"), nil) // k1 is gone: bob's record does not open
	if _, err := f.b.Enrollments.GetSecondFactor(ctx, bobPrincipal); err == nil {
		t.Fatal("setup: the record opened")
	}
	text, err := f.b.ResetSecondFactor(ctx, bobPrincipal, false, "o")
	if err != nil || !strings.Contains(text, "did not open") || !strings.Contains(text, "they may enroll until") {
		t.Fatalf("%q, %v", text, err)
	}
	if got := revOf(t, f.b.Enrollments, bobPrincipal); got.State != store.SecondFactorReopened {
		t.Fatalf("%s", shape(got))
	}
}

// lostFile is a lost enrollments file in a temporary directory: an enrollments
// file written under keys, with a body no key opens, and the broker over it.
func lostFile(t *testing.T, f *fixture) (path string, keys crypt.Keys) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, "enrollments.json")
	keys = testKeys("k1")
	file, err := enrollfile.Open(path, keys, f.b.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := crypt.WrapEnrollments(file, keys, nil).CreateEnrollmentMark(context.Background(),
		store.EnrollmentMark{CreatedAt: f.now}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"port49_enrollments":1,"key_id":"k1","sealed":"AAAAAAAA"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, keys
}

func overFile(t *testing.T, f *fixture, path string, keys crypt.Keys) {
	t.Helper()
	file, err := enrollfile.Open(path, keys, f.b.Now)
	if err != nil {
		t.Fatal(err)
	}
	f.b.Enrollments = crypt.WrapEnrollments(file, keys, nil)
	f.b.EnrollmentFile = path
}

// D7: lost → reset --all → the unreadable file sits beside the new one,
// the gauge reads 1, an enroll for an old entry answers 202, an active
// factor is untouched, and second_factor_reset {"all": true} is recorded.
func TestResetAllReplacesALostStoreAndOpensTheWindow(t *testing.T) {
	ctx := context.Background()
	f, _ := newSignInFixture(t)
	path, keys := lostFile(t, f)
	overFile(t, f, path, keys)
	tampered, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.b.CheckEnrollmentStore(ctx); err != nil || f.b.EnrollmentStoreLost() == "" ||
		testutil.ToFloat64(f.b.Metrics.DirectoryEnrollmentStoreOK) != 0 {
		t.Fatalf("setup: not lost: %v", err)
	}
	if _, err := f.b.ResetSecondFactor(ctx, alicePrincipal, false, "o"); err == nil ||
		!strings.Contains(err.Error(), "reset-second-factor --all") {
		t.Fatalf("a reset of one person on a lost store: %v", err)
	}
	text, err := f.b.ResetSecondFactor(ctx, "", true, "offline uid 0")
	until := decision.FormatTime(f.now.Add(f.b.PasswordSignIn.ReopenFor))
	kept, _ := filepath.Glob(path + ".unreadable-*")
	if err != nil || len(kept) != 1 || !strings.Contains(text, "every entry with no active second factor may enroll until "+until) ||
		!strings.Contains(text, "the unreadable store was kept at "+kept[0]) {
		t.Fatalf("%q, %v, %v", text, kept, err)
	}
	if got, err := os.ReadFile(kept[0]); err != nil || !bytes.Equal(got, tampered) {
		t.Fatalf("the unreadable file was not kept whole: %v", err)
	}
	if f.b.EnrollmentStoreLost() != "" || testutil.ToFloat64(f.b.Metrics.DirectoryEnrollmentStoreOK) != 1 {
		t.Fatal("the store is still lost")
	}
	recs := eventsOf(f.records(t), decision.EventSecondFactorReset)
	if len(recs) != 1 || recs[0]["principal"] != nil ||
		recs[0]["second_factor_reset"].(map[string]any)["all"] != true {
		t.Fatalf("%v", recs)
	}
	enrollAlice(t, f) // an old entry, no window but --all's: a 202
}

// I1, I2: on a backend with no file (etcd) a lost key makes the mark and every
// record it sealed unopenable. --all replaces the mark and every record that
// will not open with a reopened one, says how many, says nothing of an empty
// store or a kept file (there is neither), and leaves a factor that opens.
func TestResetAllAfterALostKeyOnEtcdReplacesWhatWillNotOpen(t *testing.T) {
	ctx := context.Background()
	f, _ := newSignInFixture(t)
	mem := memory.NewEnrollments(f.b.Now)
	f.b.Enrollments = crypt.WrapEnrollments(mem, testKeys("k1"), nil)
	f.b.EnrollmentFile = ""
	if err := f.b.Enrollments.CreateEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: f.now}); err != nil {
		t.Fatal(err)
	}
	f.enrolled(t, alicePrincipal, "uuid:alice")
	f.enrolled(t, bobPrincipal, "uuid:bob")
	f.b.Enrollments = crypt.WrapEnrollments(mem, testKeys("k2"), nil) // k1 is lost
	const carol = "user:carol@example.com"
	if err := f.b.Enrollments.SwapSecondFactor(ctx, store.SecondFactor{Principal: carol, State: store.SecondFactorActive,
		Secret: []byte("0123456789abcdef0123"), EntryID: "uuid:carol", EnrolledAt: f.now, EnrolledFrom: "192.0.2.0/32"}, 0); err != nil {
		t.Fatal(err)
	}
	if err := f.b.CheckEnrollmentStore(ctx); err != nil || f.b.EnrollmentStoreLost() == "" {
		t.Fatalf("setup: not lost: %v", err)
	}
	carolBefore := revOf(t, f.b.Enrollments, carol)

	var said []string
	f.b.Say = func(format string, args ...any) { said = append(said, fmt.Sprintf(format, args...)) }
	text, err := f.b.ResetSecondFactor(ctx, "", true, "offline uid 0")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(said, "\n"), "did not open and were replaced: 2") {
		t.Errorf("the log line lacks the count: %q", said)
	}
	for _, want := range []string{"the enrollment mark did not open and is replaced", "second factors that did not open and are replaced: 2",
		"keep working", "etcd snapshot"} {
		if !strings.Contains(text, want) {
			t.Errorf("the text lacks %q: %s", want, text)
		}
	}
	for _, not := range []string{"empty one", "kept beside", "kept at"} {
		if strings.Contains(text, not) {
			t.Errorf("the text says %q, which is false on etcd: %s", not, text)
		}
	}
	for _, p := range []string{alicePrincipal, bobPrincipal} {
		if got := revOf(t, f.b.Enrollments, p); got.State != store.SecondFactorReopened || len(got.Secret) != 0 {
			t.Errorf("%s", shape(got))
		}
	}
	if after := revOf(t, f.b.Enrollments, carol); after.State != store.SecondFactorActive || after.Rev != carolBefore.Rev {
		t.Fatalf("a factor that opens was touched: %s", shape(after))
	}
	if f.b.EnrollmentStoreLost() != "" {
		t.Fatal("the store is still lost")
	}
}

// --all also replaces a record that will not open under a mark that does.
func TestResetAllReplacesAnUnopenableRecordUnderAGoodMark(t *testing.T) {
	ctx := context.Background()
	f, _ := newSignInFixture(t)
	sealedStore(t, f, true)
	f.enrolled(t, alicePrincipal, "uuid:alice")
	f.b.Enrollments = &staleEnrollments{Enrollments: f.b.Enrollments, broken: map[string]bool{alicePrincipal: true}}
	text, err := f.b.ResetSecondFactor(ctx, "", true, "o")
	if err != nil || !strings.Contains(text, "second factors that did not open and are replaced: 1") {
		t.Fatalf("%q, %v", text, err)
	}
}

func TestResetAllDropsNoActiveFactor(t *testing.T) {
	ctx := context.Background()
	f, _ := newSignInFixture(t)
	secret := f.enrolled(t, alicePrincipal, "uuid:alice")
	before := revOf(t, f.b.Enrollments, alicePrincipal)
	created := f.now
	f.advance(time.Hour) // the mark's creation time is kept, not the reset's
	text, err := f.b.ResetSecondFactor(ctx, "", true, "o")
	if err != nil || strings.Contains(text, "unreadable") {
		t.Fatalf("%q, %v", text, err)
	}
	if after := revOf(t, f.b.Enrollments, alicePrincipal); after.State != store.SecondFactorActive ||
		!bytes.Equal(after.Secret, secret) || after.Rev != before.Rev {
		t.Fatalf("%s", shape(after))
	}
	m, err := f.b.Enrollments.GetEnrollmentMark(ctx)
	if err != nil || !m.CreatedAt.Equal(created) || !m.ReopenAllUntil.Equal(f.now.Add(f.b.PasswordSignIn.ReopenFor)) {
		t.Fatalf("%+v, %v", m, err)
	}
	if w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, secret, f.now),
		CSR: csrOf(t, newECKey(t))}); w.Code != 200 {
		t.Fatalf("the active factor no longer signs in: %s", shown(w))
	}
}

// D7, I15: init-enrollments on an empty store creates the mark, clears
// lost, sets the gauge 1, records second_factor_reset {"created": true}
// with no principal; a second run is refused and writes nothing; on a
// tampered file, or a store holding records with no mark, it is refused
// naming import and reset-second-factor --all.
func TestInitEnrollmentsCreatesTheStoreOnce(t *testing.T) {
	ctx := context.Background()
	f, _ := newSignInFixture(t)
	f.b.Enrollments = memory.NewEnrollments(f.b.Now)
	if err := f.b.CheckEnrollmentStore(ctx); err != nil || f.b.EnrollmentStoreLost() == "" ||
		testutil.ToFloat64(f.b.Metrics.DirectoryEnrollmentStoreOK) != 0 {
		t.Fatalf("setup: %v", err)
	}
	text, err := f.b.InitEnrollments(ctx, "offline uid 0")
	if err != nil || !strings.Contains(text, "created the enrollment store") {
		t.Fatalf("%q, %v", text, err)
	}
	if f.b.EnrollmentStoreLost() != "" || testutil.ToFloat64(f.b.Metrics.DirectoryEnrollmentStoreOK) != 1 {
		t.Fatal("the store is still lost")
	}
	// A broker already running is a different process: it follows at its recheck, and until then refuses.
	for _, want := range []string{"already running", EnrollmentRecheckEvery.String(), "enrollment_store_lost"} {
		if !strings.Contains(text, want) {
			t.Errorf("init-enrollments says %q, want it to say %q", text, want)
		}
	}
	recs := eventsOf(f.records(t), decision.EventSecondFactorReset)
	if len(recs) != 1 || recs[0]["principal"] != nil ||
		recs[0]["second_factor_reset"].(map[string]any)["created"] != true {
		t.Fatalf("%v", recs)
	}
	m1, _ := f.b.Enrollments.GetEnrollmentMark(ctx)
	_, err = f.b.InitEnrollments(ctx, "o")
	m2, _ := f.b.Enrollments.GetEnrollmentMark(ctx)
	if err == nil || !strings.Contains(err.Error(), "the enrollment store is already there") || m1.Rev != m2.Rev ||
		len(eventsOf(f.records(t), decision.EventSecondFactorReset)) != 1 {
		t.Fatalf("a second run: %v", err)
	}

	// A tampered file: refused, named, and left as it is.
	path, keys := lostFile(t, f)
	overFile(t, f, path, keys)
	before, _ := os.ReadFile(path)
	_, err = f.b.InitEnrollments(ctx, "o")
	after, _ := os.ReadFile(path)
	if err == nil || !strings.Contains(err.Error(), "port49 directory import") ||
		!strings.Contains(err.Error(), "reset-second-factor --all") || !bytes.Equal(before, after) {
		t.Fatalf("a tampered file: %v", err)
	}

	// Records with no mark.
	f.b.Enrollments = memory.NewEnrollments(f.b.Now)
	f.enrolled(t, alicePrincipal, "uuid:alice")
	if _, err := f.b.InitEnrollments(ctx, "o"); err == nil || !strings.Contains(err.Error(), "reset-second-factor --all") {
		t.Fatalf("records with no mark: %v", err)
	}
	if _, err := f.b.Enrollments.GetEnrollmentMark(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a mark was written beside the records: %v", err)
	}
}

// sealedStore is a fixture's enrollment store as a broker keeps it: sealed
// under keys, with its mark.
func sealedStore(t *testing.T, f *fixture, withMark bool) {
	t.Helper()
	f.b.Enrollments = crypt.WrapEnrollments(memory.NewEnrollments(f.b.Now), testKeys("k1"), nil)
	if withMark {
		if err := f.b.Enrollments.CreateEnrollmentMark(context.Background(), store.EnrollmentMark{CreatedAt: f.now}); err != nil {
			t.Fatal(err)
		}
	}
	_ = f.b.CheckEnrollmentStore(context.Background())
}

// D13: an export holds no secret or entry id in the clear; import into an
// empty store restores sign-in; import without replace over a later
// enrollment is refused naming --replace; with replace it replaces;
// enrollments_import is recorded.
func TestExportImport(t *testing.T) {
	ctx := context.Background()
	f, _ := newSignInFixture(t)
	sealedStore(t, f, true)
	secret := f.enrolled(t, alicePrincipal, "uuid:alice")
	exp, err := f.b.ExportEnrollments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Named, never printed: one of them is the secret.
	for name, clear := range map[string]string{"secret": base64.StdEncoding.EncodeToString(secret),
		"entry id": "uuid:alice", "principal": alicePrincipal, "source": "192.0.2.0"} {
		if bytes.Contains(exp, []byte(clear)) {
			t.Fatalf("the export holds the %s in the clear", name)
		}
	}

	g, _ := newSignInFixture(t)
	sealedStore(t, g, false) // a replacement broker: an empty store, no mark
	if g.b.EnrollmentStoreLost() == "" {
		t.Fatal("setup: the empty store is not lost")
	}
	text, err := g.b.ImportEnrollments(ctx, exp, false, "offline uid 0")
	if err != nil || !strings.HasPrefix(text, "imported 1 second factors exported at ") {
		t.Fatalf("%q, %v", text, err)
	}
	if g.b.EnrollmentStoreLost() != "" {
		t.Fatal("the import left the store lost")
	}
	if w := g.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, secret, g.now),
		CSR: csrOf(t, newECKey(t))}); w.Code != 200 {
		t.Fatalf("sign-in after the import: %s", shown(w))
	}
	imports := eventsOf(g.records(t), decision.EventEnrollmentsImport)
	if len(imports) != 1 {
		t.Fatalf("%v", imports)
	}
	if body := imports[0]["enrollments_import"].(map[string]any); body["origin"] != "offline uid 0" ||
		body["records"] != float64(1) || body["replaced"] != nil {
		t.Fatalf("%v", body)
	}

	// A person enrolled after the export is not undone without --replace.
	if err := g.b.Enrollments.SwapSecondFactor(ctx, store.SecondFactor{Principal: bobPrincipal,
		State: store.SecondFactorActive, EntryID: "uuid:bob", Secret: secret, EnrolledAt: g.now.Add(time.Hour)}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := g.b.ImportEnrollments(ctx, exp, false, "o"); err == nil || !strings.Contains(err.Error(), "--replace") {
		t.Fatalf("%v", err)
	}
	if _, err := g.b.Enrollments.GetSecondFactor(ctx, bobPrincipal); err != nil {
		t.Fatalf("the refused import changed the store: %v", err)
	}
	if text, err := g.b.ImportEnrollments(ctx, exp, true, "o"); err != nil || !strings.HasPrefix(text, "imported 1 ") {
		t.Fatalf("%q, %v", text, err)
	}
	if _, err := g.b.Enrollments.GetSecondFactor(ctx, bobPrincipal); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("--replace kept the later record: %v", err)
	}
	if body := eventsOf(g.records(t), decision.EventEnrollmentsImport)[1]["enrollments_import"].(map[string]any); body["replaced"] != true {
		t.Fatalf("%v", body)
	}

	// Something that is not an export names nothing of itself.
	if _, err := g.b.ImportEnrollments(ctx, []byte("not an export, sk-secret-text"), false, "o"); err == nil ||
		strings.Contains(err.Error(), "sk-secret-text") {
		t.Fatalf("%v", err)
	}
}

// Unlock clears the principal's count and records sign_in_unlock with the
// count it held; the next sign-in is judged.
func TestUnlockClearsTheCount(t *testing.T) {
	ctx := context.Background()
	f, _ := newSignInFixture(t)
	secret := f.enrolled(t, alicePrincipal, "uuid:alice")
	for range 5 {
		if _, _, err := f.b.Store.NoteSignInAttempt(ctx, alicePrincipalKey, f.b.PasswordSignIn.Window); err != nil {
			t.Fatal(err)
		}
	}
	req := api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))}
	if w := f.signIn(t, req); w.Code != 429 {
		t.Fatalf("setup: %s", shown(w))
	}
	// The throttled attempt was itself counted: six are held.
	text, err := f.b.UnlockSignIn(ctx, "User:Alice@example.com", "offline uid 0")
	if err != nil || text != "cleared 6 failed sign-ins for "+alicePrincipal+" here; every region's count starts again" {
		t.Fatalf("%q, %v", text, err)
	}
	recs := eventsOf(f.records(t), decision.EventSignInUnlock)
	if len(recs) != 1 || recs[0]["principal"] != alicePrincipal ||
		recs[0]["sign_in_unlock"].(map[string]any)["failures"] != float64(6) ||
		recs[0]["sign_in_unlock"].(map[string]any)["origin"] != "offline uid 0" {
		t.Fatalf("%v", recs)
	}
	if w := f.signIn(t, req); w.Code != 200 {
		t.Fatalf("after the unlock: %s", shown(w))
	}
	if _, err := f.b.UnlockSignIn(ctx, "", "o"); err == nil {
		t.Fatal("an empty principal was unlocked")
	}
}

// With no directory_password verifier every op says so and writes nothing.
func TestTheSignInOpsNeedTheVerifier(t *testing.T) {
	ctx := context.Background()
	f, _ := newSignInFixture(t)
	f.b.PasswordSignIn = nil
	if _, err := f.b.ResetSecondFactor(ctx, alicePrincipal, false, "o"); err == nil || !strings.Contains(err.Error(), "directory_password") {
		t.Fatalf("%v", err)
	}
	if _, err := f.b.UnlockSignIn(ctx, alicePrincipal, "o"); err == nil {
		t.Fatal("unlock")
	}
	if _, err := f.b.InitEnrollments(ctx, "o"); err == nil {
		t.Fatal("init")
	}
	if _, err := f.b.ExportEnrollments(ctx); err == nil {
		t.Fatal("export")
	}
	if _, err := f.b.ImportEnrollments(ctx, []byte("x"), false, "o"); err == nil {
		t.Fatal("import")
	}
}

// resealing is a store as the scheduled pass sees it: ResealPins tells
// each of unopened and answers rep, held, err.
type resealing struct {
	store.Store
	rep      store.PinReseal
	held     bool
	err      error
	unopened []string
}

func (r *resealing) ResealPins(_ context.Context, unopened func(string, error)) (store.PinReseal, bool, error) {
	for _, p := range r.unopened {
		unopened(p, errors.New("crypt: opening membership: crypt: sealed under an unknown key"))
	}
	return r.rep, r.held, r.err
}

// series fails the test unless each gauge has want series (0: absent).
func series(t *testing.T, want int, gs ...*prometheus.GaugeVec) {
	t.Helper()
	for _, g := range gs {
		if n := testutil.CollectAndCount(g); n != want {
			t.Fatalf("a pin gauge has %d series, want %d", n, want)
		}
	}
}

// The scheduled pass re-seals the directory's pins (decision 57): a pass
// that completes sets the three gauges and says what it did; one the store
// stops changes none; a store with no pins has none of them.
func TestTheScheduledPassReSealsPinsAndGaugesWhatIsLeft(t *testing.T) {
	ctx := context.Background()
	f, _ := newSignInFixture(t)
	m := f.b.Metrics
	gauges := []*prometheus.GaugeVec{m.DirectoryPinsSealedPrevious, m.DirectoryPinsUnopenable,
		m.DirectoryPinsResealLastComplete}
	if _, err := f.b.RefreshDirectory(ctx); err != nil {
		t.Fatal(err)
	}
	series(t, 0, gauges...) // a shared store: no ResealPins
	r := &resealing{Store: f.b.Store, held: false}
	f.b.Store = r
	if _, err := f.b.RefreshDirectory(ctx); err != nil {
		t.Fatal(err)
	}
	series(t, 0, gauges...) // a router with no directory of its own
	r.held, r.rep, r.unopened = true, store.PinReseal{Sealed: 3, Previous: 1, Unopened: 1},
		[]string{"user:carol@example.com"}
	if _, err := f.b.RefreshDirectory(ctx); err != nil {
		t.Fatal(err)
	}
	ended := f.b.Now().Unix()
	series(t, 1, gauges...)
	if p, u, at := testutil.ToFloat64(m.DirectoryPinsSealedPrevious), testutil.ToFloat64(m.DirectoryPinsUnopenable),
		testutil.ToFloat64(m.DirectoryPinsResealLastComplete); p != 1 || u != 1 || at != float64(ended) {
		t.Fatalf("after a complete pass: sealed_previous %v, unopenable %v, last_complete %v", p, u, at)
	}
	f.now = f.now.Add(time.Hour)
	r.rep, r.err, r.unopened = store.PinReseal{Sealed: 1}, fmt.Errorf("%w: cut", store.ErrUnavailable), nil
	if _, err := f.b.RefreshDirectory(ctx); err != nil {
		t.Fatal(err)
	}
	if p, u, at := testutil.ToFloat64(m.DirectoryPinsSealedPrevious), testutil.ToFloat64(m.DirectoryPinsUnopenable),
		testutil.ToFloat64(m.DirectoryPinsResealLastComplete); p != 1 || u != 1 || at != float64(ended) {
		t.Fatalf("a stopped pass moved the gauges: sealed_previous %v, unopenable %v, last_complete %v", p, u, at)
	}
	logs := f.logs()
	for _, want := range []string{
		"directory store: the re-seal sealed 3 pins under the current key; 1 are left under encryption.previous",
		"directory store: user:carol@example.com's pin does not open",
		"`port49 directory forget user:carol@example.com`",
		"directory store: 1 pins open under neither encryption key",
		"directory store: the re-seal of pins stopped",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("the log lacks %q:\n%s", want, logs)
		}
	}
	if strings.Contains(logs, "more are not named") {
		t.Errorf("one unopenable pin was said as more than the named ones:\n%s", logs)
	}
}

// A pass the store refuses or the context cancels, like one it cannot reach,
// leaves all three gauges as the last complete pass set them.
func TestAStoppedPinPassLeavesAllThreeGaugesWhatEverStoppedIt(t *testing.T) {
	for name, stop := range map[string]struct {
		err    error
		cancel bool
	}{
		"unavailable": {err: fmt.Errorf("%w: cut", store.ErrUnavailable)},
		"refused":     {err: fmt.Errorf("%w: no", store.ErrRefused)},
		"canceled":    {err: context.Canceled, cancel: true},
	} {
		t.Run(name, func(t *testing.T) {
			f, _ := newSignInFixture(t)
			m := f.b.Metrics
			r := &resealing{Store: f.b.Store, held: true, rep: store.PinReseal{Sealed: 3, Previous: 1, Unopened: 2}}
			f.b.Store = r
			f.b.pinPass(context.Background())
			ended := f.b.Now().Unix()
			f.now = f.now.Add(time.Hour)
			r.rep, r.err = store.PinReseal{Sealed: 9, Previous: 7, Unopened: 5}, stop.err
			ctx := context.Background()
			if stop.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			f.b.pinPass(ctx)
			if p, u, at := testutil.ToFloat64(m.DirectoryPinsSealedPrevious), testutil.ToFloat64(m.DirectoryPinsUnopenable),
				testutil.ToFloat64(m.DirectoryPinsResealLastComplete); p != 1 || u != 2 || at != float64(ended) {
				t.Fatalf("a stopped pass moved the gauges: sealed_previous %v, unopenable %v, last_complete %v", p, u, at)
			}
		})
	}
}

// Pre-flight S4: a lost key strands every pin, so a pass names at most 20
// and counts the rest.
func TestThePinPassNamesAtMostTwentyUnopenablePins(t *testing.T) {
	f, _ := newSignInFixture(t)
	var ps []string
	for i := range 21 {
		ps = append(ps, fmt.Sprintf("user:p%02d@example.com", i))
	}
	f.b.Store = &resealing{Store: f.b.Store, held: true, rep: store.PinReseal{Unopened: 21}, unopened: ps}
	if _, err := f.b.RefreshDirectory(context.Background()); err != nil {
		t.Fatal(err)
	}
	logs := f.logs()
	if !strings.Contains(logs, "user:p19@example.com's pin does not open") ||
		strings.Contains(logs, "user:p20@example.com's pin") ||
		!strings.Contains(logs, "21 pins open under neither encryption key") ||
		!strings.Contains(logs, "; 1 more are not named") {
		t.Fatalf("the lines for 21 unopenable pins:\n%s", logs)
	}
}

// The scheduled pass checks the store, and re-seals when it is well.
func TestTheScheduledPassChecksAndReSealsTheEnrollmentStore(t *testing.T) {
	ctx := context.Background()
	f, _ := newSignInFixture(t)
	inner := f.b.Enrollments
	f.b.Enrollments = &staleEnrollments{Enrollments: inner, stale: map[string]bool{alicePrincipal: true}}
	f.enrolled(t, alicePrincipal, "uuid:alice")
	rev := revOf(t, inner, alicePrincipal).Rev
	f.b.markEnrollmentStore("it was lost a moment ago")
	if _, err := f.b.RefreshDirectory(ctx); err != nil {
		t.Fatal(err)
	}
	if f.b.EnrollmentStoreLost() != "" || testutil.ToFloat64(f.b.Metrics.DirectoryEnrollmentStoreOK) != 1 {
		t.Fatal("the pass did not look at the store")
	}
	if revOf(t, inner, alicePrincipal).Rev == rev {
		t.Fatal("the pass did not re-seal")
	}
	// A lost store is not re-sealed.
	f.b.Enrollments = memory.NewEnrollments(f.b.Now)
	f.enrolled(t, alicePrincipal, "uuid:alice")
	f.b.Enrollments = &staleEnrollments{Enrollments: f.b.Enrollments, stale: map[string]bool{alicePrincipal: true}}
	rev = revOf(t, f.b.Enrollments, alicePrincipal).Rev
	if _, err := f.b.RefreshDirectory(ctx); err != nil {
		t.Fatal(err)
	}
	if f.b.EnrollmentStoreLost() == "" || revOf(t, f.b.Enrollments, alicePrincipal).Rev != rev {
		t.Fatal("the pass re-sealed a store with no mark")
	}
}
