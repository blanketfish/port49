package port49d

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/crypt"
	"github.com/blanketfish/port49/internal/store/enrollfile"
)

type countingCloser struct{ closed int }

func (c *countingCloser) Close() error { c.closed++; return nil }

// closableEnrollments is an Enrollments whose Close counts.
type closableEnrollments struct {
	store.Enrollments
	closer *countingCloser
}

func (c *closableEnrollments) Close() error { return c.closer.Close() }

// lateEnrollments opens its backend on first use and tries again no oftener
// than every 30s while that fails: a failure is not retried before then, a
// success is cached and never reopened, a lost store passes through as lost
// and anything else is unavailable, and close closes what it owns.
func TestLateEnrollments(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	calls := 0
	fail := errors.New("dial tcp: connection refused")
	cl := &countingCloser{}
	l := &lateEnrollments{now: func() time.Time { return now }}
	l.open = func() (store.Enrollments, error) {
		calls++
		if fail != nil {
			return nil, fail
		}
		return &closableEnrollments{closer: cl}, nil
	}
	if _, err := l.get(); !errors.Is(err, store.ErrUnavailable) || errors.Is(err, store.ErrEnrollmentStoreLost) || calls != 1 {
		t.Fatalf("a first failure: %v after %d opens", err, calls)
	}
	now = now.Add(enrollmentRetryEvery - time.Second)
	if _, err := l.get(); !errors.Is(err, store.ErrUnavailable) || calls != 1 {
		t.Fatalf("before the retry: %v after %d opens", err, calls)
	}
	now = now.Add(2 * time.Second)
	if _, err := l.get(); !errors.Is(err, store.ErrUnavailable) || calls != 2 {
		t.Fatalf("at the retry: %v after %d opens", err, calls)
	}
	fail = nil
	now = now.Add(enrollmentRetryEvery)
	if in, err := l.get(); err != nil || in == nil || calls != 3 {
		t.Fatalf("the success: %v after %d opens", err, calls)
	}
	now = now.Add(time.Hour)
	if _, err := l.get(); err != nil || calls != 3 {
		t.Fatalf("a cached store was opened again: %v after %d opens", err, calls)
	}
	l.close()
	if cl.closed != 1 {
		t.Fatalf("close closed %d times", cl.closed)
	}

	lost := &lateEnrollments{now: func() time.Time { return now }, open: func() (store.Enrollments, error) {
		return nil, errors.Join(store.ErrEnrollmentStoreLost, errors.New("it cannot be read"))
	}}
	if _, err := lost.get(); !errors.Is(err, store.ErrEnrollmentStoreLost) || errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a lost store: %v", err)
	}
}

// A file lost because it could not be read is opened again after 30s: the
// operator who fixes its mode does not then run --all, which would set the
// good file aside.
func TestALostEnrollmentFileIsOpenedAgainOnceFixed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode 0000 file")
	}
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "enrollments.json")
	file, err := enrollfile.Open(path, signInTestKeys, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := crypt.WrapEnrollments(file, signInTestKeys, nil).CreateEnrollmentMark(ctx,
		store.EnrollmentMark{CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	l := &lateEnrollments{now: func() time.Time { return now },
		open: func() (store.Enrollments, error) { return openEnrollmentFile(path, signInTestKeys, nil) }}
	if _, err := l.GetEnrollmentMark(ctx); !errors.Is(err, store.ErrEnrollmentStoreLost) {
		t.Fatalf("an unreadable file: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	now = now.Add(enrollmentRetryEvery - time.Second)
	if _, err := l.GetEnrollmentMark(ctx); !errors.Is(err, store.ErrEnrollmentStoreLost) {
		t.Fatalf("before the retry: %v", err)
	}
	now = now.Add(2 * time.Second)
	if _, err := l.GetEnrollmentMark(ctx); err != nil {
		t.Fatalf("after the retry the fixed file is still lost: %v", err)
	}
}
