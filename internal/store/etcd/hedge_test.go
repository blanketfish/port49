package etcd

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type fakeReply struct{ N int }

// failFirst is an invoker whose first copy fails at once as a connection
// keepalive just closed does (Unavailable), and whose later copies answer.
type failFirst struct {
	mu    sync.Mutex
	sends int
}

func (f *failFirst) invoke(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn,
	opts ...grpc.CallOption) error {
	f.mu.Lock()
	f.sends++
	n := f.sends
	f.mu.Unlock()
	if n == 1 {
		return status.Error(codes.Unavailable, "keepalive ping failed to receive ACK within timeout")
	}
	reply.(*fakeReply).N = n
	return nil
}

// An opted-in write whose copy fails outright is sent again at once, not at
// the quarter timer: the write a keepalive failure would otherwise lose.
func TestAnOptedInWriteIsSentAgainAtOnceOnUnavailable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f := &failFirst{}
	var reply fakeReply
	start := time.Now()
	err := hedgeReads(idempotent(ctx), "/etcdserverpb.KV/Txn", nil, &reply, nil, f.invoke)
	if err != nil || reply.N != 2 || f.sends != 2 {
		t.Fatalf("err %v, answered by send %d of %d, want send 2 of 2", err, reply.N, f.sends)
	}
	if took := time.Since(start); took >= 250*time.Millisecond {
		t.Fatalf("sent again after %v: at the quarter timer, not at once", took)
	}
}

// A read whose copy fails outright is not sent again by the hedge: clientv3
// already retries an Unavailable read on another connection, and a second
// layer of re-sends only multiplies the load on a cluster that has lost its
// leader (dial fix round 3 review, M1).
func TestAReadIsNotSentAgainAtOnceOnUnavailable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f := &failFirst{}
	var reply fakeReply
	err := hedgeReads(ctx, "/etcdserverpb.KV/Range", nil, &reply, nil, f.invoke)
	if status.Code(err) != codes.Unavailable || f.sends != 1 {
		t.Fatalf("err %v after %d send(s), want Unavailable after 1", err, f.sends)
	}
}

// setPeer writes p through every Peer option in opts, as grpc does when a
// call finishes.
func setPeer(opts []grpc.CallOption, p peer.Peer) {
	for _, o := range opts {
		if po, ok := o.(grpc.PeerCallOption); ok {
			*po.PeerAddr = p
		}
	}
}

// The caller's Peer is the winning copy's, and a losing copy that finishes
// after hedgeReads has returned never writes it: clientv3's retry
// interceptor reads it then (final review, C1).
func TestALosingCopyNeverWritesTheCallersPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	winner := peer.Peer{Addr: &net.TCPAddr{Port: 2}}
	release, lost := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	sends := 0
	invoke := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn,
		opts ...grpc.CallOption) error {
		mu.Lock()
		sends++
		n := sends
		mu.Unlock()
		if n == 1 { // the stalled copy: it finishes only once the caller has its answer
			<-release
			setPeer(opts, peer.Peer{Addr: &net.TCPAddr{Port: 1}})
			close(lost)
			return status.Error(codes.Canceled, "context canceled")
		}
		setPeer(opts, winner)
		reply.(*fakeReply).N = n
		return nil
	}
	var got peer.Peer
	var reply fakeReply
	if err := hedgeReads(ctx, "/etcdserverpb.KV/Range", nil, &reply, nil, invoke, grpc.Peer(&got)); err != nil {
		t.Fatal(err)
	}
	if got.Addr != winner.Addr {
		t.Fatalf("the caller's peer is %v, want the winner's %v", got.Addr, winner.Addr)
	}
	close(release)
	<-lost
	if got.Addr != winner.Addr {
		t.Fatalf("a losing copy wrote the caller's peer after the call returned: %v", got.Addr)
	}
}
