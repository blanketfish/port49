package broker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/store"
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
