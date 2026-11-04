package etcd

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestFastFailReasonNamesTheUnavailableAnswer(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{status.Error(codes.Unavailable, "etcdserver: no leader"), "no_leader"},
		{status.Error(codes.Unavailable, "etcdserver: leader changed"), "leader_changed"},
		{status.Error(codes.Unavailable, "last connection error: connection refused"), "no_connection"},
		{status.Error(codes.Unavailable, "error reading from server: EOF"), "no_connection"},
		{status.Error(codes.Unavailable, "something new"), "other"},
		{status.Error(codes.DeadlineExceeded, "late"), ""},
		{nil, ""},
		{errors.New("plain"), ""},
	} {
		if got := fastFailReason(c.err); got != c.want {
			t.Errorf("%v: %q, want %q", c.err, got, c.want)
		}
	}
}

// A call refused at once while its caller still waits is counted by reason,
// so a refusal that takes a millisecond names itself in
// port49_store_fast_fail_total (the leader_dark matrix saw 9 s of them). One
// that took the call's time, or whose caller had gone, is not one.
func TestACallRefusedAtOnceIsCountedByReason(t *testing.T) {
	var got []string
	ic := fastFails(func(r string) { got = append(got, r) })
	refuse := func(err error, took time.Duration) grpc.UnaryInvoker {
		return func(context.Context, string, any, any, *grpc.ClientConn, ...grpc.CallOption) error {
			time.Sleep(took)
			return err
		}
	}
	run := func(ctx context.Context, inv grpc.UnaryInvoker) {
		ic(ctx, "/etcdserverpb.KV/Range", nil, nil, nil, inv)
	}
	noLeader := status.Error(codes.Unavailable, "etcdserver: no leader")
	run(context.Background(), refuse(noLeader, 0))
	run(context.Background(), refuse(noLeader, 2*fastFailUnder)) // it took its time
	run(context.Background(), refuse(status.Error(codes.DeadlineExceeded, "late"), 0))
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	run(gone, refuse(noLeader, 0)) // the caller had given up
	if len(got) != 1 || got[0] != "no_leader" {
		t.Fatalf("counted %v, want [no_leader]", got)
	}
}
