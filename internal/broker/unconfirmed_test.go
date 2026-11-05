package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
)

// A revocation whose write the store did not answer may still land, even over a lift made meanwhile
// (L79 k). The broker says so with its own code, never "nothing was revoked", which an operator at a
// regional cut would believe; a write the store refused wrote nothing and keeps saying so.
func TestAnUnrecordedRevocationIsUnconfirmedNotNothingRevoked(t *testing.T) {
	f := newMFAFixture(t, withAllAdminRights())
	f.b.Store = putRevocationUnavailable{f.b.Store}
	code, raw := f.adminCall(t, f.alice, f.alice.conn, revokePath, bobBody)
	a := decodeAdminAnswer(t, raw)
	if code != 503 || a.Error != "revocation_unconfirmed" {
		t.Fatalf("%d %s", code, raw)
	}
	for _, want := range []string{"may not have been recorded", "even over a lift made meanwhile", "port49 revoke --list"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("the answer lacks %q: %s", want, raw)
		}
	}
	for _, bad := range []string{"nothing was revoked", "nothing was done", "no quorum", "socket"} {
		if strings.Contains(string(raw), bad) {
			t.Errorf("the answer says %q: %s", bad, raw)
		}
	}
}

func TestARefusedRevocationStillSaysNothingWasRevoked(t *testing.T) {
	f := newMFAFixture(t, withAllAdminRights())
	f.b.Store = putRevocationRefused{f.b.Store}
	code, raw := f.adminCall(t, f.alice, f.alice.conn, revokePath, bobBody)
	if code != 503 || decodeAdminAnswer(t, raw).Error != "store_unavailable" || !strings.Contains(string(raw), "nothing was revoked") {
		t.Fatalf("%d %s", code, raw)
	}
}

type putRevocationRefused struct{ store.Store }

func (putRevocationRefused) PutRevocation(context.Context, store.Revocation) error {
	return fmt.Errorf("%w: a mark with no principal", store.ErrRefused)
}

// A lift the store did not answer may have gone through: the mark may or may not be gone.
func TestAnUnconfirmedLiftIsNotNothingLifted(t *testing.T) {
	f := newMFAFixture(t, withAllAdminRights())
	if _, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: bobKey, Origin: "test"}); err != nil {
		t.Fatal(err)
	}
	f.b.Store = deleteRevocationFails{f.b.Store, fmt.Errorf("%w: no quorum", store.ErrUnavailable)}
	code, raw := f.adminCall(t, f.alice, f.alice.conn, liftPath, bobBody)
	if code != 503 || decodeAdminAnswer(t, raw).Error != "revocation_unconfirmed" {
		t.Fatalf("%d %s", code, raw)
	}
	for _, want := range []string{"may not have been recorded", "port49 revoke --list"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("the answer lacks %q: %s", want, raw)
		}
	}
	for _, bad := range []string{"nothing was lifted", "nothing was done", "no quorum", "and stands"} {
		if strings.Contains(string(raw), bad) {
			t.Errorf("the answer says %q: %s", bad, raw)
		}
	}
}

func TestTheUnconfirmedErrorsAreTyped(t *testing.T) {
	f := newFixture(t, 8)
	st := f.b.Store
	f.b.Store = putRevocationUnavailable{st}
	if _, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alice}); !errors.Is(err, ErrUnrecorded) {
		t.Fatalf("an unanswered write: %v", err)
	}
	f.b.Store = putRevocationRefused{st}
	if _, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alice}); err == nil || errors.Is(err, ErrUnrecorded) {
		t.Fatalf("a refused write: %v", err)
	}
	f.b.Store = st
	if _, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alice}); err != nil {
		t.Fatal(err)
	}
	f.b.Store = deleteRevocationFails{st, fmt.Errorf("%w: no quorum", store.ErrUnavailable)}
	if _, err := f.b.Lift(context.Background(), RevokeRequest{Principal: alice}); !errors.Is(err, ErrLiftUnrecorded) {
		t.Fatalf("an unanswered delete: %v", err)
	}
}

// getRevocationFails fails the read of one key only: the caller's own authentication reads others.
type getRevocationFails struct {
	store.Store
	key string
	err error
}

func (s getRevocationFails) GetRevocation(ctx context.Context, kind, key string) (store.Revocation, error) {
	if key != s.key {
		return s.Store.GetRevocation(ctx, kind, key)
	}
	return store.Revocation{}, s.err
}

type putRevocationNotSent struct{ store.Store }

func (putRevocationNotSent) PutRevocation(context.Context, store.Revocation) error {
	return fmt.Errorf("%w: the pool's circuit is open (%w)", store.ErrUnavailable, store.ErrNotSent)
}

// A lift that cannot have reached the store, or that the store refused (a missing role never heals), is
// the definite answer: it could not be lifted, and the mark stands. Only a delete the store may have
// received and left unanswered is "may or may not be gone". The store's own words stay in the log.
func TestALiftThatWasRefusedOrNeverSentStands(t *testing.T) {
	for _, c := range []struct {
		name string
		wrap func(store.Store) store.Store
		leak string
	}{
		{"delete refused", func(s store.Store) store.Store {
			return deleteRevocationFails{s, fmt.Errorf("%w: role lacks delete on /p49/rev", store.ErrRefused)}
		}, "role lacks delete"},
		{"delete not sent", func(s store.Store) store.Store {
			return deleteRevocationFails{s, fmt.Errorf("%w: circuit open (%w)", store.ErrUnavailable, store.ErrNotSent)}
		}, "circuit open"},
		{"read fails", func(s store.Store) store.Store {
			return getRevocationFails{s, bobKey, fmt.Errorf("%w: no quorum on /p49/rev", store.ErrUnavailable)}
		}, "no quorum"},
	} {
		f := newMFAFixture(t, withAllAdminRights())
		if _, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: bobKey, Origin: "test"}); err != nil {
			t.Fatal(err)
		}
		f.b.Store = c.wrap(f.b.Store)
		code, raw := f.adminCall(t, f.alice, f.alice.conn, liftPath, bobBody)
		if code != 503 || decodeAdminAnswer(t, raw).Error != "store_unavailable" ||
			!strings.Contains(string(raw), "could not be lifted, and stands") {
			t.Errorf("%s: %d %s", c.name, code, raw)
		}
		for _, bad := range []string{"may or may not", "may not have been recorded", c.leak, "reading the revocation"} {
			if strings.Contains(string(raw), bad) {
				t.Errorf("%s: the answer says %q: %s", c.name, bad, raw)
			}
		}
	}
}

// A write the guard failed before anything was sent cannot land later, but this broker still denies what
// it names (revoke fails closed): the mark stays, the answer is store_unavailable and never says nothing
// was revoked. A write the store refused wrote nothing, and its pending mark goes.
func TestARevocationThatWasNeverSentKeepsDenyingHere(t *testing.T) {
	f := newMFAFixture(t, withAllAdminRights())
	f.b.Marks = store.NewMarks()
	f.b.Store = putRevocationNotSent{f.b.Store}
	code, raw := f.adminCall(t, f.alice, f.alice.conn, revokePath, bobBody)
	if code != 503 || decodeAdminAnswer(t, raw).Error != "store_unavailable" {
		t.Fatalf("%d %s", code, raw)
	}
	for _, want := range []string{"not recorded in the store", "will not land later", "denies what it names", "port49 revoke --list"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("the answer lacks %q: %s", want, raw)
		}
	}
	for _, bad := range []string{"nothing was revoked", "nothing was done", "circuit"} {
		if strings.Contains(string(raw), bad) {
			t.Errorf("the answer says %q: %s", bad, raw)
		}
	}
	if !f.b.Marks.Holds(store.RevocationPrincipal, bobKey) {
		t.Fatal("a revocation never sent dropped this broker's own deny")
	}
	if _, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alice}); errors.Is(err, ErrUnrecorded) || !errors.Is(err, ErrNotRecorded) {
		t.Fatalf("a write never sent: %v", err)
	}
}

func TestARefusedRevocationDropsItsPendingMark(t *testing.T) {
	f := newMFAFixture(t, withAllAdminRights())
	f.b.Marks = store.NewMarks()
	f.b.Store = putRevocationRefused{f.b.Store}
	f.adminCall(t, f.alice, f.alice.conn, revokePath, bobBody)
	if f.b.Marks.Holds(store.RevocationPrincipal, bobKey) {
		t.Fatal("a refused revocation left a mark here")
	}
}

// At 3am the operator checks what stands before trying again (a second try can stack another mark), and
// is not pointed at asking someone else to revoke their own principal.
func TestTheUnconfirmedAnswerSaysCheckBeforeTryingAgain(t *testing.T) {
	f := newMFAFixture(t, withAllAdminRights())
	f.b.Store = putRevocationUnavailable{f.b.Store}
	_, raw := f.adminCall(t, f.alice, f.alice.conn, revokePath, bobBody)
	s := string(raw)
	if strings.Contains(s, "ask an operator holding") {
		t.Errorf("the answer points a self-revoker at another operator: %s", s)
	}
	list, again := strings.Index(s, "port49 revoke --list"), strings.Index(s, "try again")
	if list < 0 || (again >= 0 && again < list) || !strings.Contains(s, "landed") {
		t.Errorf("the answer must say to check --list before any retry, and why: %s", s)
	}
}

// A write never sent cannot land late: when another writer's mark of the same key arrives, this broker
// must not log that its own write landed (Marks.FailedWrite). An unconfirmed write still can.
func TestANeverSentWriteIsNotRememberedAsFailed(t *testing.T) {
	for _, c := range []struct {
		name string
		wrap func(store.Store) store.Store
		want bool
	}{
		{"never sent", func(s store.Store) store.Store { return putRevocationNotSent{s} }, false},
		{"unconfirmed", func(s store.Store) store.Store { return putRevocationUnavailable{s} }, true},
	} {
		f := newFixture(t, 8)
		f.b.Marks = store.NewMarks()
		f.b.Store = c.wrap(f.st)
		if _, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alice}); err == nil {
			t.Fatalf("%s: the revoke succeeded", c.name)
		}
		if got := f.b.Marks.FailedWrite(store.RevocationPrincipal, alice, f.b.Now()); got != c.want {
			t.Errorf("%s: FailedWrite %v, want %v", c.name, got, c.want)
		}
	}
}

// A revocation the directory did not record still reaches this region's own session store: the token
// keys the principal holds are deleted and its live contexts marked revoked, and the answer says so
// (stores I1). Other regions learn of the mark at the heal.
func TestAnUnrecordedRevokeStillReachesThisRegionsSessionStore(t *testing.T) {
	f := newFixture(t, 8)
	ctx := context.Background()
	decodeMint(t, f.post(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, ""))
	f.liveContext(t, "leaf1", "alice", alice, certKey(f.alice))
	f.b.Store = putRevocationUnavailable{f.b.Store}
	_, err := f.b.Revoke(ctx, RevokeRequest{Principal: alice})
	if !errors.Is(err, ErrUnrecorded) {
		t.Fatalf("an unanswered write: %v", err)
	}
	if n := strings.Count(err.Error(), "port49 revoke --list"); n != 1 || strings.Contains(err.Error(), "at the heal") {
		t.Errorf("the --list check is said once, and no heal is promised: %d %v", n, err)
	}
	for _, want := range []string{"this region's session store: 1 token keys deleted and 1 contexts marked revoked",
		"other regions have not learned of it yet", "run `port49 revoke` now against a broker in a region that reaches the directory",
		"the copy sent may land too", "check `port49 revoke --list`"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error lacks %q: %v", want, err)
		}
	}
	if toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: "leaf1", Username: "alice"}); len(toks) != 0 {
		t.Errorf("%d unspent token(s) survived an unrecorded revoke", len(toks))
	}
	if c, gerr := f.st.GetContext(ctx, store.ContextKey{NAS: "leaf1", Username: "alice"}); gerr != nil || c.RevokedAt.IsZero() {
		t.Errorf("the live context was not marked revoked: %+v %v", c, gerr)
	}
}

func TestANotSentRevokeReachesTooAndSaysSo(t *testing.T) {
	f := newFixture(t, 8)
	ctx := context.Background()
	decodeMint(t, f.post(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, ""))
	f.liveContext(t, "leaf1", "alice", alice, certKey(f.alice))
	f.b.Store = putRevocationNotSent{f.b.Store}
	_, err := f.b.Revoke(ctx, RevokeRequest{Principal: alice})
	if !errors.Is(err, ErrNotRecorded) || !strings.Contains(err.Error(), "this region's session store: 1 token keys deleted and 1 contexts marked revoked") {
		t.Fatalf("a write never sent: %v", err)
	}
	// Nothing carries a write never sent to another region: the text says so and names the fix, and
	// does not promise a heal.
	for _, want := range []string{"other regions have not learned of it",
		"run `port49 revoke` now against a broker in a region that reaches the directory", "this one, if the directory answers it again"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error lacks %q: %v", want, err)
		}
	}
	for _, bad := range []string{"at the heal", "the copy sent may land"} {
		if strings.Contains(err.Error(), bad) {
			t.Errorf("the error says %q: %v", bad, err)
		}
	}
	if c, gerr := f.st.GetContext(ctx, store.ContextKey{NAS: "leaf1", Username: "alice"}); gerr != nil || c.RevokedAt.IsZero() {
		t.Errorf("the live context was not marked revoked: %+v %v", c, gerr)
	}
}

// With the reach done, port49-broker is no longer told to stop every port49d; the policy edit is the
// further cut. "Stop every port49d" is offered only when the reach itself failed.
func TestTheFallbackNoLongerSaysStopEveryPort49d(t *testing.T) {
	f := newFixture(t, 8)
	f.b.Proc = "port49-broker"
	ctx := context.Background()
	f.b.Store = putRevocationUnavailable{f.b.Store}
	_, err := f.b.Revoke(ctx, RevokeRequest{Principal: alice})
	if err == nil || strings.Contains(err.Error(), "stop every port49d") || !strings.Contains(err.Error(), "broker.policy_file") {
		t.Fatalf("the reach was done: %v", err)
	}
	// The reach itself failed: the process stop is offered again.
	f.b.Store = putRevocationFails{tokensByPrincipalFails{f.st}}
	_, err = f.b.Revoke(ctx, RevokeRequest{Principal: alice})
	if err == nil || !strings.Contains(err.Error(), "stop every port49d") ||
		!strings.Contains(err.Error(), "could not be reached") || strings.Contains(err.Error(), "only in part") {
		t.Fatalf("the reach failed: %v", err)
	}
}

// putRevocationHangs holds the write until the call's deadline, as a partitioned etcd does, and then
// answers unavailable.
type putRevocationHangs struct{ store.Store }

func (putRevocationHangs) PutRevocation(ctx context.Context, _ store.Revocation) error {
	<-ctx.Done()
	return fmt.Errorf("%w: %v", store.ErrUnavailable, ctx.Err())
}

// The answer an operator reads over HTTP carries the reach sentence, not only the error Revoke
// returned: what this region's session store was told and what to do about the other regions
// (stores I1; found in the lab, where the CLI printed the unanswered text without it).
func TestTheRevokeAnswerNamesTheReachAndWhatToDoAboutOtherRegions(t *testing.T) {
	for name, wrap := range map[string]func(store.Store) store.Store{
		"unavailable": func(s store.Store) store.Store { return putRevocationUnavailable{s} },
		"hangs":       func(s store.Store) store.Store { return putRevocationHangs{s} },
		"not sent":    func(s store.Store) store.Store { return putRevocationNotSent{s} },
	} {
		t.Run(name, func(t *testing.T) {
			f := newMFAFixture(t, withAllAdminRights())
			f.b.RevokeTimeout = 200 * time.Millisecond
			f.b.Store = wrap(f.b.Store)
			code, raw := f.adminCall(t, f.alice, f.alice.conn, revokePath, bobBody)
			if code != http.StatusServiceUnavailable {
				t.Fatalf("%d %s", code, raw)
			}
			for _, want := range []string{"this region's session store: ", " token keys deleted and ", " contexts marked revoked",
				"run `port49 revoke` now against a broker in a region that reaches the directory"} {
				if !strings.Contains(string(raw), want) {
					t.Errorf("the answer lacks %q: %s", want, raw)
				}
			}
		})
	}
}

// The exact detail an operator reads for each unrecorded branch, with the reach done and with it
// failed: `port49 revoke --list` is named once, and the reach says what to do now (3am text).
func TestTheUnrecordedRevokeAnswersAreExact(t *testing.T) {
	const body = "a copy already sent can still land when the directory answers again, and then stands everywhere, " +
		"even over a lift made meanwhile. Until then this port49d denies what it names, until a lift on this port49d " +
		"or its restart; "
	const reached = "this region's session store: 0 token keys deleted and 0 contexts marked revoked; "
	const sentTail = "other regions have not learned of it yet: run `port49 revoke` now against a broker in a region that " +
		"reaches the directory (the copy sent may land too); "
	const notSentTail = "other regions have not learned of it: run `port49 revoke` now against a broker in a region that " +
		"reaches the directory (this one, if the directory answers it again); "
	const notReached = "this region's session store could not be reached (index unreadable); "
	const closing = "check `port49 revoke --list` once the store answers, before trying again: if the mark is there it " +
		"landed and needs nothing; if it is absent and nobody lifted it, run it again; meanwhile an operator can remove " +
		"the principal's grants from broker.policy_file"
	const notSentWhat = "the revocation was not recorded in the store and will not land later, but this port49d denies what " +
		"it names until a lift on this port49d or its restart; run it again once the store answers; "
	for _, c := range []struct {
		name   string
		wrap   func(store.Store) store.Store
		reach  bool
		detail string
	}{
		{"unanswered, reached", func(s store.Store) store.Store { return putRevocationUnavailable{s} }, true,
			"the revocation may not have been recorded: " + body + reached + sentTail + closing},
		{"unanswered, reach failed", func(s store.Store) store.Store { return putRevocationUnavailable{s} }, false,
			"the revocation may not have been recorded: " + body + notReached + closing},
		{"never sent, reached", func(s store.Store) store.Store { return putRevocationNotSent{s} }, true,
			notSentWhat + reached + notSentTail + "check `port49 revoke --list` first"},
		{"never sent, reach failed", func(s store.Store) store.Store { return putRevocationNotSent{s} }, false,
			notSentWhat + notReached + "check `port49 revoke --list` first"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newMFAFixture(t, withAllAdminRights())
			f.b.Store = c.wrap(f.b.Store)
			if !c.reach {
				f.b.Store = putRevocationUnavailableIndex{f.b.Store}
			}
			code, raw := f.adminCall(t, f.alice, f.alice.conn, revokePath, bobBody)
			var a struct{ Detail string }
			if err := json.Unmarshal(raw, &a); err != nil || code != http.StatusServiceUnavailable {
				t.Fatalf("%d %s", code, raw)
			}
			if a.Detail != c.detail {
				t.Errorf("detail:\n got %q\nwant %q", a.Detail, c.detail)
			}
			if n := strings.Count(a.Detail, "port49 revoke --list"); n != 1 {
				t.Errorf("--list is named %d times", n)
			}
		})
	}
}

// putRevocationUnavailableIndex fails the principal's token index, which the reach reads first.
type putRevocationUnavailableIndex struct{ store.Store }

func (putRevocationUnavailableIndex) TokensByPrincipal(context.Context, string) ([]store.TokenKey, error) {
	return nil, errors.New("index unreadable")
}
