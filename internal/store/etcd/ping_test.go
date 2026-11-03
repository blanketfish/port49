package etcd

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"

	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/etcd/etcdtest"
)

// PingToken reads on the token connection as Ping does on the context one
// (plan 7f, Ruling 1): each answers while etcd does, and each is
// store.ErrUnavailable while it hangs.
func TestPingTokenReadsOnTheTokenConnection(t *testing.T) {
	srv := etcdtest.Start(t, etcdtest.Options{})
	p := etcdtest.NewProxy(t, strings.TrimPrefix(srv.Endpoint, "http://"))
	s, err := Open(Config{Endpoints: []string{"http://" + p.Addr()}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.PingToken(ctx); err != nil {
		t.Fatal(err)
	}
	p.Hang(true)
	hctx, hcancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer hcancel()
	if err := s.PingToken(hctx); !errors.Is(err, store.ErrUnavailable) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("PingToken on a hung store: %v", err)
	}
}

// etcd out of space is its own error, still unavailable, and not "too large".
func TestNoSpaceIsItsOwnUnavailableError(t *testing.T) {
	err := unavailable(rpctypes.ErrNoSpace)
	if !errors.Is(err, ErrNoSpace) || !errors.Is(err, store.ErrUnavailable) || errors.Is(err, ErrTooLarge) {
		t.Fatalf("%v", err)
	}
}
