package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
)

// identityCmd is `port49 identity` (spec §12): what the broker resolves the
// agent's principal to (GET /v1/identity).
func identityCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 identity", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := agent.SocketPath()
	asJSON := fs.Bool("json", false, "print the broker's answer as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	id, err := agent.NewClient(socket).Identity(context.Background())
	switch {
	case errors.Is(err, agent.ErrNoAgent):
		fmt.Fprint(stderr, noAgentLine("port49 identity", socket))
		return 1
	case err != nil:
		fmt.Fprintln(stderr, "port49 identity:", unprefixed(err))
		return 1
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(id)
		return 0
	}
	printIdentity(stdout, id)
	return 0
}

// printIdentity says who the session is, one fact a line.
func printIdentity(w io.Writer, id api.Identity) {
	fmt.Fprintf(w, "principal  %s (%s %s)\n", id.Principal, id.Method, id.Fingerprint)
	subject := id.Subject
	if subject == "" {
		subject = "(none: no subject names this principal, so nothing is minted for it)"
	}
	fmt.Fprintf(w, "subject    %s\n", subject)
	if len(id.Groups) > 0 {
		fmt.Fprintf(w, "groups     %s\n", strings.Join(id.Groups, ", "))
	}
	if len(id.Grants) == 0 {
		fmt.Fprintln(w, "grants     (none)")
	}
	for i, g := range id.Grants {
		label := "grants    "
		if i > 0 {
			label = "          "
		}
		line := g.Scope + " [" + strings.Join(g.Roles, " ") + "]"
		if g.MaxPrivilege != "" {
			line += " max_privilege " + g.MaxPrivilege
		}
		if g.Expires != "" {
			line += " expires " + g.Expires
		}
		fmt.Fprintf(w, "%s %s\n", label, line)
	}
	rights := "(none: you act on your own tokens and sessions alone)"
	if len(id.API) > 0 {
		rights = strings.Join(id.API, ", ")
	}
	fmt.Fprintf(w, "api        %s\n", rights)
	fmt.Fprintf(w, "session    authenticated %s", id.AuthTime)
	if id.ConnectionEndsAt != "" {
		// max_session_age's end for this connection, not a device session's:
		// a role's ceiling on a device may end one sooner (pre-flight M16).
		fmt.Fprintf(w, "; this connection lasts until %s (a device's own session ceiling may end a session "+
			"sooner)", id.ConnectionEndsAt)
	}
	fmt.Fprintln(w)
}
