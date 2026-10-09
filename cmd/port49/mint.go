package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
)

// mintFailed says, under cmd's prefix, why a mint through the agent gave no
// usable token, and reports whether it did. These are `port49 token`'s words,
// shared by `port49 devices trust` and `port49 ssh`.
func mintFailed(cmd, socket, device string, item api.MintItem, err error, stderr io.Writer) bool {
	var ie *agent.ItemError
	switch {
	case errors.As(err, &ie):
		// The broker could not decide this device. Whatever else the item
		// carries is not printed.
		fmt.Fprintf(stderr, "%s: %s: %s\n", cmd, device, unprefixed(ie))
	case errors.Is(err, agent.ErrNoAgent):
		fmt.Fprintf(stderr, "%s: no agent at %s; run `port49 login`\n", cmd, socket)
	case err != nil:
		// An ended session says to log in and why: an expired certificate
		// has to be renewed before a login will work. A revocation says
		// since when and who lifts it instead.
		fmt.Fprintf(stderr, "%s: %s\n", cmd, unprefixed(err))
	case item.Verdict != "permit":
		// The item's detail, when it has one, says what to do: a session
		// past its ceiling is told to refresh (pre-flight M12).
		detail := ""
		if item.Detail != "" {
			detail = ": " + item.Detail
		}
		fmt.Fprintf(stderr, "%s: %s: %s %s%s\n", cmd, device, item.Verdict, item.Reason, detail)
	case item.Login == "":
		// Printed, it would be an empty password to whatever reads stdout.
		fmt.Fprintf(stderr, "%s: %s: the broker answered permit with no token\n", cmd, device)
	default:
		return false
	}
	return true
}

// ceilingWarning is the broker's session.ceiling_warning as the agent holds
// it; zero when the agent does not say.
func ceilingWarning(socket string) time.Duration {
	st, err := agent.NewClient(socket).Status(context.Background())
	if err != nil || st.CeilingWarningSeconds <= 0 {
		return 0
	}
	return time.Duration(st.CeilingWarningSeconds) * time.Second
}

// warnNearCeiling says on stderr, and reports, that item's device session
// ends within warn: the warning a platform that does not show server_msg
// never gives (decision 33; spec §15 L34). On stderr, so --json's stdout stays
// one object (pre-flight M12).
func warnNearCeiling(stderr io.Writer, device string, item api.MintItem, warn time.Duration) bool {
	exp, err := time.Parse(time.RFC3339, item.SessionExpiresAt)
	if err != nil || warn <= 0 {
		return false
	}
	left := time.Until(exp)
	if left > warn {
		return false
	}
	fmt.Fprintf(stderr, "port49: your session on %s ends at %s (%s); run 'port49 refresh'\n", device,
		item.SessionExpiresAt, timeLeft(left))
	return true
}
