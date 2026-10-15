package port49d

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/crypt"
	"github.com/rhwendt/port49/internal/store/enrollfile"
)

// goodThenUnreadable is a real enrollments file holding a mark and one active
// second factor, sealed under signInTestKeys, its mode then taken away; the
// broker wired over it starts with the store lost. fix puts the mode back.
func goodThenUnreadable(t *testing.T) (b *broker.Broker, path string, exported []byte, fix func(), created time.Time,
	m *metrics.Metrics, enrolled func() store.SecondFactor) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode 0000 file")
	}
	ctx := context.Background()
	cfg, file := signInConfig(t, "127.0.0.1:0")
	created = time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	f, err := enrollfile.Open(file, signInTestKeys, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	w := crypt.WrapEnrollments(f, signInTestKeys, nil)
	if err := w.CreateEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: created}); err != nil {
		t.Fatal(err)
	}
	const alice = "user:alice@example.com"
	if err := w.SwapSecondFactor(ctx, store.SecondFactor{Principal: alice, State: store.SecondFactorActive,
		Secret: []byte("0123456789abcdef0123"), EntryID: "uuid:alice", EnrolledAt: created, EnrolledFrom: "192.0.2.0/32"}, 0); err != nil {
		t.Fatal(err)
	}
	if exported, err = w.Export(ctx); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0); err != nil {
		t.Fatal(err)
	}
	m = metrics.New(prometheus.NewRegistry())
	br := builtSignInBroker(t, cfg, m)
	var out syncBuffer
	wirePasswordSignIn(context.Background(), cfg, br, signInTestKeys, m, nil, &out)
	if br.EnrollmentStoreLost() == "" {
		t.Fatalf("setup: the unreadable file is not lost:\n%s", out.String())
	}
	fix = func() {
		if err := os.Chmod(file, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	enrolled = func() store.SecondFactor {
		f, err := br.Enrollments.GetSecondFactor(ctx, alice)
		if err != nil {
			t.Fatalf("alice's second factor: %v", err)
		}
		return f
	}
	return br, file, exported, fix, created, m, enrolled
}

// The operator fixes the mode and, with no 30s wait, runs the remedy the lost
// line names next: reset-second-factor --all must see the good file and keep
// it, not set it aside and make everyone enroll again.
func TestAllRightAfterFixingTheModeKeepsTheGoodFile(t *testing.T) {
	b, file, _, fix, created, _, enrolled := goodThenUnreadable(t)
	fix()
	if _, err := b.ResetSecondFactor(context.Background(), "", true, "admin_socket uid 0"); err != nil {
		t.Fatal(err)
	}
	if kept, _ := filepath.Glob(file + ".unreadable-*"); len(kept) != 0 {
		t.Fatalf("the good file was set aside: %v", kept)
	}
	if f := enrolled(); f.State != store.SecondFactorActive {
		t.Fatalf("alice's factor is %s", f.State)
	}
	if mk, err := b.Enrollments.GetEnrollmentMark(context.Background()); err != nil || !mk.CreatedAt.Equal(created) {
		t.Fatalf("the mark's creation time was not kept: %v, %v", mk.CreatedAt, err)
	}
}

// An import straight after the fix is the same: the good file is not set
// aside before it is replaced.
func TestAnImportRightAfterFixingTheModeKeepsTheGoodFile(t *testing.T) {
	b, file, exported, fix, _, _, enrolled := goodThenUnreadable(t)
	fix()
	if _, err := b.ImportEnrollments(context.Background(), exported, true, "admin_socket uid 0"); err != nil {
		t.Fatal(err)
	}
	if kept, _ := filepath.Glob(file + ".unreadable-*"); len(kept) != 0 {
		t.Fatalf("the good file was set aside: %v", kept)
	}
	if f := enrolled(); f.State != store.SecondFactorActive {
		t.Fatalf("alice's factor is %s", f.State)
	}
}
