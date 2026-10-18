package etcd

import (
	"context"
	"reflect"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// hedged are the read-only calls a second copy of is harmless to send.
var hedged = map[string]bool{
	"/etcdserverpb.KV/Range":           true,
	"/etcdserverpb.Cluster/MemberList": true,
}

// idempotentWrites are the write calls hedged only when the store method that
// makes them says a second copy is harmless (idempotent).
var idempotentWrites = map[string]bool{
	"/etcdserverpb.KV/Txn":         true,
	"/etcdserverpb.KV/DeleteRange": true,
}

// hedgeWrites switches the opt-in off, for a test that shows what it prevents.
var hedgeWrites = true

type idempotentKey struct{}

// idempotent marks ctx's writes as ones a store method has checked are
// harmless sent twice: a create-if-absent put (a second copy finds the key
// and changes nothing) or a delete of one key. Txn carries writes that are
// not, so the call's own method name never decides it.
func idempotent(ctx context.Context) context.Context {
	return context.WithValue(ctx, idempotentKey{}, true)
}

// hedgeReads is the client's interceptor for a member that goes dark with
// quorum intact. The client spreads calls round-robin over its connections;
// a connection whose link was dropped (not refused) stalls until keepalive
// fails it, 10s + 2s (grpc raises a keepalive Time below 10s to 10s), and every third call sent to it ran into its own
// deadline: a directory that still answers read as not answering (L74). A
// read still unanswered at a quarter and at half of its deadline is sent
// again, on the next connection round-robin picks, and the first answer wins.
// A call with no deadline goes through alone, and so does a write, unless its
// store method marked it idempotent.
func hedgeReads(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	dl, ok := ctx.Deadline()
	rv := reflect.ValueOf(reply)
	write := hedgeWrites && idempotentWrites[method] && ctx.Value(idempotentKey{}) != nil
	if !(hedged[method] || write) || !ok || rv.Kind() != reflect.Pointer || rv.Elem().Kind() != reflect.Struct {
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
				// A write's connection that failed outright (Unavailable, as
				// when keepalive closes the dark one) is no answer either: try
				// the next at once rather than waiting for a timer. clientv3
				// does not retry a write; it already retries a read on another
				// connection, so a read's failure goes back to it.
				if write && hedges < 2 && ctx.Err() == nil && status.Code(last) == codes.Unavailable {
					hedges++
					inflight++
					send()
					continue
				}
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
