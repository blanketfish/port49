package placement

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
)

var t0 = time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)

const alice = "user:alice@example.com"

func clock() time.Time { return t0 }

func wrapped(marks *store.Marks) (s store.Store, session, directory *memory.Store) {
	session, directory = memory.New(clock), memory.New(clock)
	return Wrap(Config{Session: session, Directory: directory, Marks: marks, CallTimeout: time.Second,
		BulkTimeout: time.Second}), session, directory
}

func TestTheMarksAreTheDirectorys(t *testing.T) {
	ctx := context.Background()
	s, session, directory := wrapped(store.NewMarks())
	r := store.Revocation{Kind: store.RevocationPrincipal, Key: alice, At: t0, Origin: "admin_socket uid 0"}
	if err := s.PutRevocation(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err := directory.GetRevocation(ctx, r.Kind, r.Key); err != nil {
		t.Fatalf("the directory lacks the mark: %v", err)
	}
	if _, err := session.GetRevocation(ctx, r.Kind, r.Key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the session store holds a mark: %v", err)
	}
	if rs, err := s.ListRevocations(ctx); err != nil || len(rs) != 1 {
		t.Fatalf("%v %v", rs, err)
	}
	if err := s.DeleteRevocation(ctx, r.Kind, r.Key, store.Lift{}); err != nil {
		t.Fatal(err)
	}
	if rs, _ := directory.ListRevocations(ctx); len(rs) != 0 {
		t.Fatalf("the lift left %v", rs)
	}
}

// A mark is read from the process's copy, never from the directory: a
// login and a mint in a cut region answer from it (R4, R17).
func TestAMarkIsReadFromTheProcesssCopy(t *testing.T) {
	ctx := context.Background()
	marks := store.NewMarks()
	s, _, directory := wrapped(marks)
	marks.Set(store.Revocation{Kind: store.RevocationCert, Key: "CN=CA|1f", At: t0, Origin: "crl corp"}, true)
	if r, err := s.GetRevocation(ctx, store.RevocationCert, "CN=CA|1f"); err != nil || r.Origin != "crl corp" ||
		!r.At.Equal(t0) {
		t.Fatalf("%+v %v", r, err)
	}
	if err := directory.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: alice, At: t0}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetRevocation(ctx, store.RevocationPrincipal, alice); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a mark the copy has not followed was read: %v", err)
	}
}

// With no copy (the offline revocation), a mark is read from the directory.
func TestWithNoCopyAMarkIsReadFromTheDirectory(t *testing.T) {
	ctx := context.Background()
	s, _, directory := wrapped(nil)
	if err := directory.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: alice, At: t0}); err != nil {
		t.Fatal(err)
	}
	if r, err := s.GetRevocation(ctx, store.RevocationPrincipal, alice); err != nil || !r.At.Equal(t0) {
		t.Fatalf("%+v %v", r, err)
	}
}

// A login carries a mark of the copy into its context and asks the
// session store to compare none: the session store holds no mark, and a
// compare there would refuse every login under one (decision 51).
func TestALoginCarriesACopiedMarkAndComparesNone(t *testing.T) {
	ctx := context.Background()
	marks := store.NewMarks()
	marks.Set(store.Revocation{Kind: store.RevocationPrincipal, Key: alice, At: t0}, true)
	s, _, _ := wrapped(marks)
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	login := store.Context{CtxID: "c1", Principal: alice, Username: "alice", AuthTime: t0.Add(-time.Hour),
		RefreshedAt: t0}
	res, err := store.JoinContext(ctx, s, k, login, t0.Add(-time.Minute), t0, time.Hour,
		store.LoginIndex{Principal: alice, TTL: time.Hour})
	if err != nil {
		t.Fatalf("the login: %v", err)
	}
	if !res.Context.RevokedAt.Equal(t0) {
		t.Fatalf("the context's RevokedAt is %v, want the mark's %v", res.Context.RevokedAt, t0)
	}
}

// hung is a directory that never answers.
type hung struct{}

func (hung) PutRevocation(ctx context.Context, _ store.Revocation) error {
	<-ctx.Done()
	return ctx.Err()
}
func (hung) GetRevocation(ctx context.Context, _, _ string) (store.Revocation, error) {
	<-ctx.Done()
	return store.Revocation{}, ctx.Err()
}
func (hung) DeleteRevocation(ctx context.Context, _, _ string, _ store.Lift) error {
	<-ctx.Done()
	return ctx.Err()
}
func (hung) ListRevocations(ctx context.Context) ([]store.Revocation, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (hung) GetLift(ctx context.Context, _, _ string) (store.Lift, error) {
	<-ctx.Done()
	return store.Lift{}, ctx.Err()
}

// Review Focus 5: a directory write in a cut region fails within the
// directory's call_timeout, as ErrUnavailable, never on the caller's
// minute-long deadline.
func TestADirectoryThatDoesNotAnswerIsBoundedByCallTimeout(t *testing.T) {
	s := Wrap(Config{Session: memory.New(clock), Directory: hung{}, Marks: store.NewMarks(),
		CallTimeout: 100 * time.Millisecond, BulkTimeout: 200 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	start := time.Now()
	err := s.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: alice, At: t0})
	if !errors.Is(err, store.ErrUnavailable) || time.Since(start) > 2*time.Second {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
	if _, err := s.ListRevocations(ctx); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("the list: %v", err)
	}
}

// A lift asks the directory itself when the copy has no mark (plan 11a, Task
// 9 ruling): the answer is the directory's, and a directory that does not
// answer is ErrUnavailable within the call timeout, never "absent".
func TestReadRevocationAsksTheDirectoryNotTheCopy(t *testing.T) {
	ctx := context.Background()
	s, _, directory := wrapped(store.NewMarks())
	r := store.Revocation{Kind: store.RevocationPrincipal, Key: alice, At: t0}
	if err := directory.PutRevocation(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetRevocation(ctx, r.Kind, r.Key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the copy has not followed the mark, so it is a miss: %v", err)
	}
	got, err := s.(interface {
		ReadRevocation(context.Context, string, string) (store.Revocation, error)
	}).ReadRevocation(ctx, r.Kind, r.Key)
	if err != nil || got.Key != alice {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestReadRevocationOfACutDirectoryIsUnavailableWithinTheCallTimeout(t *testing.T) {
	s := Wrap(Config{Session: memory.New(clock), Directory: hung{}, Marks: store.NewMarks(),
		CallTimeout: 100 * time.Millisecond})
	start := time.Now()
	_, err := s.(interface {
		ReadRevocation(context.Context, string, string) (store.Revocation, error)
	}).ReadRevocation(context.Background(), store.RevocationPrincipal, alice)
	if !errors.Is(err, store.ErrUnavailable) || time.Since(start) > 2*time.Second {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
}
