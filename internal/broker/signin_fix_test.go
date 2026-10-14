package broker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/totp"
)

const alicePrincipalKey = "principal:" + alicePrincipal

// A 202 gives its own source attempt back, not the principal's: fifty people
// enrolling through one office address must not use up the office's count (I1).
func TestAnEnrollmentStartGivesItsSourceAttemptBack(t *testing.T) {
	f, _ := newSignInFixture(t)
	f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour)
	enrollAlice(t, f)
	if n := f.counted(t, aliceSource); n != 0 {
		t.Fatalf("the source's count holds %d after a 202", n)
	}
	if n := f.counted(t, alicePrincipalKey); n != 1 {
		t.Fatalf("the principal's count holds %d after a 202", n)
	}
}

// A reopened record keeps its window through a lapsed enrollment: the person
// signs in again inside the operator's 24h and enrolls (I2).
func TestALapsedEnrollmentKeepsTheReopenWindow(t *testing.T) {
	ctx := context.Background()
	f, _ := newSignInFixture(t)
	if err := f.b.Enrollments.SwapSecondFactor(ctx, store.SecondFactor{Principal: alicePrincipal,
		State: store.SecondFactorReopened, Until: f.now.Add(24 * time.Hour)}, 0); err != nil {
		t.Fatal(err)
	}
	e, _ := enrollAlice(t, f)
	f.advance(11 * time.Minute)
	if w := f.confirm(t, api.ConfirmRequest{Handle: e.Handle, Code: "123456", CSR: csrOf(t, newECKey(t))}); w.Code != 401 {
		t.Fatalf("a lapsed handle: %s", shown(w))
	}
	e, secret := enrollAlice(t, f) // the reopen is still there: a 202, not a 403
	if w := f.confirm(t, api.ConfirmRequest{Handle: e.Handle, Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))}); w.Code != 200 {
		t.Fatalf("the second enrollment: %s", shown(w))
	}
}

// flakyEnrollments fails its next GetSecondFactor with a store error.
type flakyEnrollments struct {
	store.Enrollments
	fail atomic.Bool
}

func (u *flakyEnrollments) GetSecondFactor(ctx context.Context, p string) (store.SecondFactor, error) {
	if u.fail.CompareAndSwap(true, false) {
		return store.SecondFactor{}, store.ErrUnavailable
	}
	return u.Enrollments.GetSecondFactor(ctx, p)
}

// A store fault after the handle is taken puts it back: the same handle
// confirms once the store answers (I3).
func TestAStoreFaultAfterTheHandleIsTakenKeepsIt(t *testing.T) {
	f, _ := newSignInFixture(t)
	f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour)
	e, secret := enrollAlice(t, f)
	flaky := &flakyEnrollments{Enrollments: f.b.Enrollments}
	f.b.Enrollments = flaky
	flaky.fail.Store(true)
	w := f.confirm(t, api.ConfirmRequest{Handle: e.Handle, Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))})
	if w.Code != 503 || apiError(w) != "store_unavailable" {
		t.Fatalf("%s", shown(w))
	}
	if w := f.confirm(t, api.ConfirmRequest{Handle: e.Handle, Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))}); w.Code != 200 {
		t.Fatalf("the blip spent the handle: %s", shown(w))
	}
}

// The confirm's refusals are recorded as enroll denies (I5).
func TestTheConfirmsRefusalsAreEnrollDenies(t *testing.T) {
	f, _ := newSignInFixture(t)
	f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour)
	e, secret := enrollAlice(t, f)
	f.confirm(t, api.ConfirmRequest{Handle: e.Handle, Code: wrongCode(t, secret, f.now), CSR: csrOf(t, newECKey(t))})
	f.confirm(t, api.ConfirmRequest{Handle: "no-such-handle", Code: "123456", CSR: csrOf(t, newECKey(t))})
	for i := range 5 {
		if _, _, err := f.b.Store.NoteSignInAttempt(context.Background(), alicePrincipalKey, f.b.PasswordSignIn.Window); err != nil {
			t.Fatal(i, err)
		}
	}
	f.confirm(t, api.ConfirmRequest{Handle: e.Handle, Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))})
	denies := eventsOf(f.records(t), decision.EventEnroll)
	var reasons []any
	for _, d := range denies {
		if d["verdict"] != "deny" {
			t.Fatalf("%v", d)
		}
		reasons = append(reasons, d["reason"])
	}
	if len(reasons) != 3 || reasons[0] != "sign_in_refused" || reasons[1] != "sign_in_refused" || reasons[2] != "sign_in_throttled" {
		t.Fatalf("%v", reasons)
	}
	if n := len(eventsOf(f.records(t), decision.EventIssue)); n != 0 {
		t.Fatalf("%d issue records for a confirm", n)
	}
}

// A broker fault judges nothing about the person: both counts are given back
// (I6; decision 47 D5).
func TestABrokerFaultGivesBackBothCounts(t *testing.T) {
	for name, tc := range map[string]struct {
		fault func(f *fixture, d *fakeDir)
		code  int
	}{
		"the search": {func(_ *fixture, d *fakeDir) { d.setDown(true) }, 503},
		"the bind":   {func(_ *fixture, d *fakeDir) { d.mu.Lock(); d.bindDown = true; d.mu.Unlock() }, 503},
		"the record": {func(f *fixture, _ *fakeDir) {
			f.b.Enrollments = &unreadableEnrollments{Enrollments: f.b.Enrollments}
		}, 503},
		"the CA": {func(f *fixture, _ *fakeDir) { f.b.Issuer.Unavailable = errors.New("no key") }, 503},
	} {
		f, dir := newSignInFixture(t)
		secret := f.enrolled(t, alicePrincipal, "uuid:alice")
		tc.fault(f, dir)
		w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, secret, f.now),
			CSR: csrOf(t, newECKey(t))})
		if w.Code != tc.code {
			t.Fatalf("%s: %s", name, shown(w))
		}
		if n := f.counted(t, aliceSource); n != 0 {
			t.Fatalf("%s: the source holds %d", name, n)
		}
		if n := f.counted(t, alicePrincipalKey); n != 0 {
			t.Fatalf("%s: the principal holds %d", name, n)
		}
	}
}

// midLostEnrollments reads the mark as lost, though it was well at the start.
type midLostEnrollments struct{ store.Enrollments }

func (midLostEnrollments) GetEnrollmentMark(context.Context) (store.EnrollmentMark, error) {
	return store.EnrollmentMark{}, fmt.Errorf("%w: test: the file does not unseal", store.ErrEnrollmentStoreLost)
}

// A lost store found in the middle of a request sets the lost state and the
// gauge, so the next sign-in is refused before it is counted (M1).
func TestALostStoreFoundMidRequestIsRemembered(t *testing.T) {
	f, dir := newSignInFixture(t)
	f.b.Enrollments = midLostEnrollments{f.b.Enrollments}
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", CSR: csrOf(t, newECKey(t))}) // a window is closed: the mark is read
	if w.Code != 503 || apiError(w) != "enrollment_store_lost" {
		t.Fatalf("%s", shown(w))
	}
	if f.b.EnrollmentStoreLost() == "" || testutil.ToFloat64(f.b.Metrics.DirectoryEnrollmentStoreOK) != 0 {
		t.Fatal("the lost state was not set")
	}
	f.counted(t, aliceSource)
	f.counted(t, alicePrincipalKey)
	if w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", CSR: csrOf(t, newECKey(t))}); w.Code != 503 ||
		f.counted(t, aliceSource) != 0 || dir.searchCount() != 1 {
		t.Fatalf("the second sign-in was counted or searched: %s", shown(w))
	}
}

// A principal no certificate carries is 401 sign_in_not_certifiable, recorded
// with 9b's reason, before the step is taken or anything is bound (M2).
func TestANotCertifiablePrincipalIsRefusedBeforeTheStep(t *testing.T) {
	f, dir := newSignInFixture(t)
	p := dir.people["alice"]
	p.entry.Principal = "user:a b@example.com" // a space: not carried in a certificate
	dir.people["alice"] = p
	secret := f.enrolled(t, p.entry.Principal, "uuid:alice")
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))})
	rec := f.lastIssue(t)
	got, _ := f.b.Enrollments.GetSecondFactor(context.Background(), p.entry.Principal)
	if w.Code != 401 || apiError(w) != "sign_in_not_certifiable" || rec["reason"] != "trust_domain_unresolved" ||
		dir.bindCount() != 0 || got.LastStep != 0 {
		t.Fatalf("%s %v step %d", shown(w), rec, got.LastStep)
	}
}

// A sign_in_refused record always says which check failed (concern 7).
func TestARefusedRecordAlwaysSaysWhich(t *testing.T) {
	f, dir := newSignInFixture(t)
	secret := f.enrolled(t, alicePrincipal, "uuid:alice")
	carol := dir.people["alice"]
	carol.entry.Principal, carol.entry.DN, carol.entry.EntryID = "user:c d@example.com", "uid=carol", "uuid:carol"
	dir.people["carol"] = carol
	f.enrolled(t, carol.entry.Principal, "uuid:carol")
	for _, req := range []api.SignInRequest{
		{Name: "carol", Password: "right", Code: "123456"}, // a principal no certificate carries
		{Name: "nobody", Password: "x", Code: "123456"},
		{Name: "alice", Password: "wrong", Code: codeAt(t, secret, f.now)},
		{Name: "alice", Password: "right", Code: "000000"},
		{Name: "al\x00ice", Password: "right", Code: "000000"},
	} {
		req.CSR = csrOf(t, newECKey(t))
		f.signIn(t, req)
		f.advance(time.Minute)
	}
	for _, rec := range eventsOf(f.records(t), decision.EventIssue) {
		if rec["reason"] == "sign_in_refused" && signInOf(rec)["failed"] == nil {
			t.Fatalf("a sign_in_refused record with no failed: %v", rec)
		}
	}
}

// The words are the spec's (decision 47 ruling 7).
func TestTheAnswersUseTheSpecsWords(t *testing.T) {
	f, dir := newSignInFixture(t)
	w := f.signIn(t, api.SignInRequest{Name: "nobody", Password: "x", Code: "123456", CSR: csrOf(t, newECKey(t))})
	if !strings.Contains(shown(w), "the broker did not accept that name, password and code; check each and run `port49 login` again") {
		t.Fatalf("%s", shown(w))
	}
	dir.setDown(true)
	w = f.signIn(t, api.SignInRequest{Name: "alice", Password: "x", Code: "123456", CSR: csrOf(t, newECKey(t))})
	if !strings.Contains(shown(w), "the directory did not answer, so no one can sign in with a password now; "+
		"anyone already signed in keeps working until their certificate ends") {
		t.Fatalf("%s", shown(w))
	}
}

// A clock a minute off says "1 minute", not "1 minutes".
func TestTheSkewIsSaidInTheSingular(t *testing.T) {
	f, _ := newSignInFixture(t)
	secret := f.enrolled(t, alicePrincipal, "uuid:alice")
	c, err := totp.Code(secret, f.now.Add(-60*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: c, CSR: csrOf(t, newECKey(t))})
	if !strings.Contains(shown(w), "about 1 minute off") || strings.Contains(shown(w), "1 minutes") {
		t.Fatalf("%s", shown(w))
	}
}

// A judged failure keeps both its counts: giving back is for broker faults
// alone (decision 47 D5).
func TestAJudgedFailureKeepsBothCounts(t *testing.T) {
	for name, tc := range map[string]struct {
		enrolled bool
		req      func(secret []byte, f *fixture) api.SignInRequest
		state    string
	}{
		"a wrong password": {true, func(s []byte, f *fixture) api.SignInRequest {
			return api.SignInRequest{Name: "alice", Password: "wrong", Code: codeAt(t, s, f.now)}
		}, ""},
		"a wrong code": {true, func(s []byte, f *fixture) api.SignInRequest {
			return api.SignInRequest{Name: "alice", Password: "right", Code: wrongCode(t, s, f.now)}
		}, ""},
		"a clock off": {true, func(s []byte, f *fixture) api.SignInRequest {
			return api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, s, f.now.Add(-90*time.Second))}
		}, ""},
		"the directory's state": {true, func(s []byte, f *fixture) api.SignInRequest {
			return api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, s, f.now)}
		}, "532"},
		"enrollment closed": {false, func(_ []byte, _ *fixture) api.SignInRequest {
			return api.SignInRequest{Name: "alice", Password: "right"}
		}, ""},
	} {
		f, dir := newSignInFixture(t)
		var secret []byte
		if tc.enrolled {
			secret = f.enrolled(t, alicePrincipal, "uuid:alice")
		}
		dir.state = tc.state
		req := tc.req(secret, f)
		req.CSR = csrOf(t, newECKey(t))
		if w := f.signIn(t, req); w.Code != 401 && w.Code != 403 {
			t.Fatalf("%s: %s", name, shown(w))
		}
		if n := f.counted(t, aliceSource); n != 1 {
			t.Fatalf("%s: the source holds %d", name, n)
		}
		if n := f.counted(t, alicePrincipalKey); n != 1 {
			t.Fatalf("%s: the principal holds %d", name, n)
		}
	}
}
