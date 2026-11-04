package etcd

import (
	"context"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fastFailUnder is how quickly an Unavailable answer must come to count as
// refused at once: a member that was tried and did not answer takes the call's
// deadline, so one in a few milliseconds was never sent to a member that
// could answer.
const fastFailUnder = 20 * time.Millisecond

// fastFails is the interceptor under hedgeReads (so it sees each copy of a
// hedged call) that tells fn the reason of every call the client refused at
// once, while its caller still waited (port49_store_fast_fail_total). It
// records a count and a reason from a closed set, never the message.
func fastFails(fn func(reason string)) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		start := time.Now()
		err := invoker(ctx, method, req, reply, cc, opts...)
		if err != nil && fn != nil && ctx.Err() == nil && time.Since(start) < fastFailUnder {
			if r := fastFailReason(err); r != "" {
				fn(r)
			}
		}
		return err
	}
}

// fastFailReason names an Unavailable answer: no_leader and leader_changed
// are etcd's own, no_connection is the client having no connection that
// works (refused, reset, closing, or every one in backoff), other is any
// Unavailable else. "" for an error that is not Unavailable.
func fastFailReason(err error) string {
	if status.Code(err) != codes.Unavailable {
		return ""
	}
	m := status.Convert(err).Message()
	switch {
	case strings.Contains(m, "no leader"):
		return "no_leader"
	case strings.Contains(m, "leader changed"):
		return "leader_changed"
	case strings.Contains(m, "connection"), strings.Contains(m, "EOF"), strings.Contains(m, "transport"),
		strings.Contains(m, "TransientFailure"), strings.Contains(m, "refused"), strings.Contains(m, "reset"):
		return "no_connection"
	}
	return "other"
}
