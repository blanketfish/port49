package broker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/store"
)

// port49 directory forget deletes the principal's membership, pin
// included, writes one directory_forget record naming the old entry and
// who asked, and says what it removed. A second forget finds nothing and
// writes nothing. It never asks the directory (Ruling 3's escape).
func TestForgetRemovesThePinAndIsRecorded(t *testing.T) {
	f := newFixture(t, 8)
	r := directory.ForTestsStaticResolver(f.st, nil, directory.ErrUnavailable)
	f.b.Directory = r
	ctx := context.Background()
	verified := f.b.Now().Add(-time.Hour)
	if err := f.st.PutMembership(ctx, store.Membership{Principal: alice, DN: "CN=Alice,OU=Staff,DC=corp",
		EntryID: "guid:0a1b", Refused: true, VerifiedAt: verified, GroupNames: nil}, time.Hour); err != nil {
		t.Fatal(err)
	}
	// Mixed case names the same principal: the broker spells it as the log does.
	text, err := f.b.Forget(ctx, "user:Alice@Example.COM", "admin_socket uid 0")
	if err != nil || !strings.Contains(text, "guid:0a1b") || !strings.Contains(text, "CN=Alice,OU=Staff,DC=corp") {
		t.Fatalf("%q %v", text, err)
	}
	if strings.Contains(text, "again") {
		t.Fatalf("a forget that ran says nothing of running it again: %q", text)
	}
	if _, err := f.st.GetMembership(ctx, alice); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the record outlived the forget: %v", err)
	}
	forgetsIn := func() []map[string]any {
		var out []map[string]any
		for _, rec := range f.records(t) {
			if rec["event"] == "directory_forget" {
				out = append(out, rec)
			}
		}
		return out
	}
	forgets := forgetsIn()
	if len(forgets) != 1 {
		t.Fatalf("%d directory_forget records, want 1", len(forgets))
	}
	body, _ := forgets[0]["forget"].(map[string]any)
	if forgets[0]["principal"] != alice || forgets[0]["verdict"] != nil || body["entry_id"] != "guid:0a1b" ||
		body["dn"] != "CN=Alice,OU=Staff,DC=corp" || body["refused"] != true || body["origin"] != "admin_socket uid 0" ||
		body["verified_at"] == "" {
		t.Fatalf("%v", forgets[0])
	}
	if _, has := forgets[0]["groups"]; has || strings.Contains(f.log.String(), "group") {
		t.Fatalf("a group reached the record: %v", forgets[0])
	}
	if text, err := f.b.Forget(ctx, alice, "admin_socket uid 0"); err != nil || !strings.Contains(text, "no membership is held") {
		t.Fatalf("a second forget: %q %v", text, err)
	}
	if n := len(forgetsIn()); n != 1 {
		t.Fatalf("%d directory_forget records after a forget of nothing, want the one", n)
	}
	if n := r.Calls.Load(); n != 0 {
		t.Fatalf("forget asked the directory %d times", n)
	}
}

// A verification begun before the forget cannot write the old pin back: the
// store's tombstone drops it, so one forget is enough (ruling PF7g-e).
func TestAForgetIsNotUndoneByAnEarlierVerification(t *testing.T) {
	f := newFixture(t, 8)
	f.b.Directory = directory.ForTestsStaticResolver(f.st, nil, nil)
	ctx := context.Background()
	verified := f.b.Now().Add(-time.Minute)
	m := store.Membership{Principal: alice, DN: "CN=Alice,DC=corp", EntryID: "guid:0a1b", VerifiedAt: verified}
	if err := f.st.PutMembership(ctx, m, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := f.b.Forget(ctx, alice, "admin_socket uid 0"); err != nil {
		t.Fatal(err)
	}
	if err := f.st.PutMembership(ctx, m, time.Hour); err != nil { // the verification in flight
		t.Fatal(err)
	}
	if _, err := f.st.GetMembership(ctx, alice); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the old pin was written back: %v", err)
	}
}

// A forget whose store write failed says to run it again, and says nothing
// of the store's text.
func TestAFailedForgetSaysToRunItAgain(t *testing.T) {
	f := newFixture(t, 8)
	f.b.Directory = directory.ForTestsStaticResolver(f.st, nil, nil)
	f.b.Store = failingMembership{f.b.Store}
	_, err := f.b.Forget(context.Background(), alice, "admin_socket uid 0")
	if err == nil || !strings.Contains(err.Error(), "run it again") || strings.Contains(err.Error(), "disk on fire") {
		t.Fatalf("%v", err)
	}
	if n := len(eventsOf(f.records(t), "directory_forget")); n != 0 {
		t.Fatalf("%d records for a forget that failed", n)
	}
}

type failingMembership struct{ store.Store }

func (failingMembership) DeleteMembership(context.Context, string) (store.Membership, error) {
	return store.Membership{}, errors.New("disk on fire")
}

// Forget refuses what holds no membership: no directory configured, and a
// principal that is not user: (pre-flight I-10's machine principals).
func TestForgetRefusesWhatHoldsNoMembership(t *testing.T) {
	f := newFixture(t, 8)
	if _, err := f.b.Forget(context.Background(), alice, "admin_socket uid 0"); err == nil ||
		!strings.Contains(err.Error(), "no broker.directory") {
		t.Fatalf("without a directory: %v", err)
	}
	f.b.Directory = directory.ForTestsStaticResolver(f.st, nil, nil)
	if _, err := f.b.Forget(context.Background(), "app:ci-runner", "admin_socket uid 0"); err == nil ||
		!strings.Contains(err.Error(), "neither a user: principal nor a workload's spiffe:// ID") {
		t.Fatalf("a machine principal: %v", err)
	}
}
