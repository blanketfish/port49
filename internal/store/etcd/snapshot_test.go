package etcd

import (
	"context"
	"testing"
	"time"
)

// R19: a process's snapshot is one record under its writer, read back with
// every other writer's.
func TestDirectorySnapshotsRoundTrip(t *testing.T) {
	s := onShared(t, func() time.Time { return t0 })
	ctx := context.Background()
	if err := s.PutDirectorySnapshot(ctx, SnapshotMarks, "port49d@host-1", []byte("sealed-1"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.PutDirectorySnapshot(ctx, SnapshotMarks, "port49-broker@host-2", []byte("sealed-2"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.PutDirectorySnapshot(ctx, SnapshotBroker, "port49-broker@host-2", []byte("sealed-3"), time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := s.DirectorySnapshots(ctx, SnapshotMarks)
	if err != nil || len(got) != 2 || string(got["port49d@host-1"]) != "sealed-1" {
		t.Fatalf("%v %v", got, err)
	}
	if b, err := s.DirectorySnapshots(ctx, SnapshotBroker); err != nil || len(b) != 1 {
		t.Fatalf("the broker records: %v %v", b, err)
	}
}
