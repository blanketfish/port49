package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
)

// refreshCmd is `port49 refresh` (spec §12): it asks the agent to
// re-authenticate the session it holds and extend every live session the
// policy in force still grants.
func refreshCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 refresh", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", agent.SocketPath(), "the agent's socket")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	out, err := agent.NewClient(*socket).Refresh(context.Background())
	switch {
	case errors.Is(err, agent.ErrNoAgent):
		fmt.Fprintf(stderr, "port49 refresh: no agent at %s; run 'port49 login'\n", *socket)
		return 1
	case err != nil:
		fmt.Fprintln(stderr, "port49 refresh:", unprefixed(err))
		return 1
	}
	printRefresh(stdout, out)
	return 0
}

// printRefresh says what a refresh did, one line per device (pre-flight M6):
// extended to when, revoked by the policy, past the grace window (log in
// again there), not judged (try again), and whether the device's own
// session is out of reach.
func printRefresh(w io.Writer, r api.RefreshResponse) {
	fmt.Fprintf(w, "refreshed at %s; this login lasts until %s\n", r.AuthTime, r.SessionEndsAt)
	if len(r.Sessions) == 0 {
		fmt.Fprintln(w, "  no live device session to extend")
	}
	width := 0
	for _, s := range r.Sessions {
		width = max(width, len(s.Device)+len(s.Username)+3)
	}
	for _, s := range r.Sessions {
		var what string
		switch s.Outcome {
		case "extended":
			what = "extended with no ceiling"
			if s.SessionExpires != "" {
				what = "extended to " + s.SessionExpires
			}
		case "revoked":
			what = "revoked by the policy in force, not extended"
		case "past_grace":
			what = "past the grace window, not resumed: log in again there"
		default:
			what = "not extended this time (the policy could not be applied to it): run 'port49 refresh' again"
		}
		if s.Unreached {
			what += ", not reached: the device keeps its own session"
		}
		fmt.Fprintf(w, "  %-*s  %s\n", width, fmt.Sprintf("%s (%s)", s.Device, s.Username), what)
	}
}
