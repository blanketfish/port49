package etcd

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
)

// meta/issuer is written only over the revision read: two brokers recording
// at once never write one over the other.
func TestTheIssuerRecordIsCompareAndSwap(t *testing.T) {
	srv := etcdtest.Start(t, etcdtest.Options{})
	s, err := Open(Config{Endpoints: []string{srv.Endpoint}, Prefix: etcdtest.Prefix()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()
	if _, rev, err := s.IssuerRecord(ctx); err != nil || rev != 0 {
		t.Fatalf("an absent record: %d %v", rev, err)
	}
	if ok, err := s.PutIssuerRecord(ctx, IssuerRecord{Current: "sha256:a"}, 0); !ok || err != nil {
		t.Fatalf("create: %v %v", ok, err)
	}
	if ok, _ := s.PutIssuerRecord(ctx, IssuerRecord{Current: "sha256:b"}, 0); ok {
		t.Fatal("a second create over the first")
	}
	r, rev, _ := s.IssuerRecord(ctx)
	if r.Current != "sha256:a" || r.WrittenAt.IsZero() {
		t.Fatalf("the record: %+v", r)
	}
	if ok, _ := s.PutIssuerRecord(ctx, IssuerRecord{Current: "sha256:c", Previous: r.Current}, rev); !ok {
		t.Fatal("an update at its revision")
	}
	if ok, _ := s.PutIssuerRecord(ctx, IssuerRecord{Current: "sha256:d"}, rev); ok {
		t.Fatal("an update at a revision that has passed")
	}
	if old, ok, err := s.DeleteIssuerRecord(ctx); !ok || err != nil || old.Current != "sha256:c" {
		t.Fatalf("delete: %+v %v %v", old, ok, err)
	}
	if _, ok, err := s.DeleteIssuerRecord(ctx); ok || err != nil {
		t.Fatalf("delete of none: %v %v", ok, err)
	}
}

// Sixteen brokers recording at once: exactly one create lands, and the record
// holds the winner's fingerprint, never a mixture.
func TestOnlyOneCreateOfTheIssuerRecordLands(t *testing.T) {
	srv := etcdtest.Start(t, etcdtest.Options{})
	s, err := Open(Config{Endpoints: []string{srv.Endpoint}, Prefix: etcdtest.Prefix()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	var won atomic.Int32
	winner := make(chan string, 16)
	var wg sync.WaitGroup
	for _, fp := range []string{"sha256:01", "sha256:02", "sha256:03", "sha256:04", "sha256:05", "sha256:06", "sha256:07",
		"sha256:08", "sha256:09", "sha256:0a", "sha256:0b", "sha256:0c", "sha256:0d", "sha256:0e", "sha256:0f", "sha256:10"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, err := s.PutIssuerRecord(context.Background(), IssuerRecord{Current: fp}, 0); err == nil && ok {
				won.Add(1)
				winner <- fp
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatalf("%d creates landed", won.Load())
	}
	if r, _, _ := s.IssuerRecord(context.Background()); r.Current != <-winner {
		t.Fatalf("the record is %q, not the winner's", r.Current)
	}
}
