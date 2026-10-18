package etcd

import (
	"context"
	"reflect"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// hedged are the read-only calls a second copy of is harmless to send.
var hedged = map[string]bool{
	"/etcdserverpb.KV/Range":           true,
	"/etcdserverpb.Cluster/MemberList": true,
}

// hedgeReads is the client's interceptor for a member that goes dark with
// quorum intact. The client spreads calls round-robin over its connections;
// a connection whose link was dropped (not refused) stalls until keepalive
// fails it, about 7s, and every third call sent to it ran into its own
// deadline: a directory that still answers read as not answering (L74). A
// read still unanswered at a quarter and at half of its deadline is sent
// again, on the next connection round-robin picks, and the first answer wins.
// A call with no deadline, or any call that writes, goes through alone: a
// write sent twice could land twice.
func hedgeReads(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	dl, ok := ctx.Deadline()
	rv := reflect.ValueOf(reply)
	if !hedged[method] || !ok || rv.Kind() != reflect.Pointer || rv.Elem().Kind() != reflect.Struct {
		return invoker(ctx, method, req, reply, cc, opts...)
	}
	total := time.Until(dl)
	actx, cancel := context.WithCancel(ctx)
	defer cancel()
	type answer struct {
		err error
		msg any
	}
	answers := make(chan answer, 3)
	send := func() {
		msg := reflect.New(rv.Elem().Type()).Interface()
		go func() { answers <- answer{invoker(actx, method, req, msg, cc, opts...), msg} }()
	}
	send()
	inflight, hedges := 1, 0
	timer := time.NewTimer(total / 4)
	defer timer.Stop()
	var last error
	for {
		select {
		case a := <-answers:
			inflight--
			if a.err == nil {
				rv.Elem().Set(reflect.ValueOf(a.msg).Elem())
				return nil
			}
			last = a.err
			if inflight == 0 {
				return last
			}
		case <-timer.C:
			if hedges < 2 {
				hedges++
				inflight++
				send()
				timer.Reset(total / 4)
			}
		case <-ctx.Done():
			if last != nil {
				return last
			}
			return status.FromContextError(ctx.Err()).Err()
		}
	}
}
