package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/printsafe"
)

// adminCall makes one admin call through your agent (spec §5.1.6) and returns
// the broker's 200 answer with exit code 0, or says why not on stderr and
// returns the exit code. The agent builds the touch prompt from the request
// and the command prints it as it arrives, before the key is waited on; a
// call the broker refuses before it asks, or the agent will not make, never
// prompts. unanswered is what to do about a call that was sent and not
// answered, which may have run. Every line says what to do next.
func adminCall(name string, req agent.AdminRequest, unanswered string, stderr io.Writer) (agent.AdminResponse, int) {
	touched := false
	resp, err := agent.NewClient(agent.SocketPath()).Admin(context.Background(), req, func(line string) {
		touched = true
		fmt.Fprintln(stderr, line)
	})
	if err != nil {
		return agent.AdminResponse{}, adminFailed(name, err, unanswered, stderr)
	}
	if resp.Status != 200 {
		return agent.AdminResponse{}, adminRefused(name, resp, touched, stderr)
	}
	return resp, 0
}

// adminFailed says why the agent could not make the call. Nothing was done
// unless the error is an *agent.UnansweredAdminError.
func adminFailed(name string, err error, unanswered string, stderr io.Writer) int {
	var unusable *agent.TouchUnusableError
	var refused *agent.AdminRefusedError
	var lost *agent.UnansweredAdminError
	switch {
	case errors.Is(err, agent.ErrNoAgent):
		fmt.Fprintf(stderr, "%s: no agent is running for you; run `port49 login`, then run this again\n", name)
	case errors.As(err, &unusable):
		// An unusable touch key is the key's reason; a missing one says its
		// own remedy. Nothing was sent either way.
		next := "; nothing was sent: fix that in your config, run `port49 login` again, then run this again"
		if strings.Contains(unusable.Detail, "port49 login") {
			next = "; nothing was sent"
		}
		fmt.Fprintf(stderr, "%s: admin operations need a press of your security key, and %s%s\n", name,
			printsafe.Line(unusable.Detail, 300), next)
	case errors.Is(err, agent.ErrConnectionChanged):
		fmt.Fprintf(stderr, "%s: the connection changed during the touch; nothing was sent: run it again\n", name)
	case errors.Is(err, agent.ErrTouchBusy):
		fmt.Fprintf(stderr, "%s: %s\n", name, safeLine(unprefixed(err)))
	case errors.Is(err, agent.ErrChallengeMismatch):
		fmt.Fprintf(stderr, "%s: %s\n", name, safeLine(unprefixed(err)))
	case errors.As(err, &refused):
		fmt.Fprintf(stderr, "%s: the agent will not send that: %s\n", name, safeLine(refused.Detail))
	case errors.As(err, &lost):
		if unanswered == "" {
			unanswered = "check the broker's decision log before trying again"
		}
		fmt.Fprintf(stderr, "%s: the broker did not answer (%v); %s\n", name, safeLine(lost.Err.Error()), unanswered)
	default:
		// The key's own words (no touch within 15s, locked, absent), a session
		// that is over, an unreachable broker: each says what to do.
		fmt.Fprintf(stderr, "%s: %s\n", name, safeLine(unprefixed(err)))
	}
	return 1
}

// adminRefused says what the broker's answer other than a 200 means. A
// refusal before the key was asked (touched false) did no touch and no work.
func adminRefused(name string, resp agent.AdminResponse, touched bool, stderr io.Writer) int {
	var e api.Error
	_ = json.Unmarshal(resp.Body, &e)
	detail := printsafe.Line(e.Detail, 600)
	switch {
	case resp.Status == 401 && e.Error == "admin_touch_refused":
		fmt.Fprintf(stderr, "%s: the broker refused the touch: %s; nothing was done: fix what that says (log in again "+
			"on your security key, or ask the broker's operator to check attestation_roots_file), then run it again\n",
			name, detail)
	case resp.Status == 401 && e.Error == "admin_touch_required":
		fmt.Fprintf(stderr, "%s: the broker asked for a touch again after yours; nothing was done: run it again\n", name)
	case resp.Status == 503 && e.Error == "admin_touch_unavailable":
		fmt.Fprintf(stderr, "%s: %s; no admin call can run on this broker until its operator sets "+
			"attestation_roots_file; ask them, then run this again\n", name, detail)
	case resp.Status == 403 && e.Error == "api_right_missing":
		fmt.Fprintf(stderr, "%s: refused: %s; no key press was asked: ask whoever owns the policy to add the right under "+
			"your subject's api:, then run this again\n", name, detail)
	case resp.Status == 409 && e.Error == "admin_operation_failed" && !touched:
		fmt.Fprintf(stderr, "%s: this broker cannot run that: %s; no key press was asked: set it up on the broker, or "+
			"run the command against one that has it\n", name, detail)
	case resp.Status == 409 && e.Error == "admin_operation_failed":
		fmt.Fprintf(stderr, "%s: the broker did not run it: %s\n", name, detail)
	case resp.Status == 404 && e.Error == "not_revoked":
		fmt.Fprintf(stderr, "%s: no such revocation is in force; check `port49 revoke --list` for what is\n", name)
	case resp.Status == 503 && e.Error == "revocation_busy":
		fmt.Fprintf(stderr, "%s: another revocation or lift is still running, so nothing was done; run it again in a "+
			"few seconds\n", name)
	case resp.Status == 413:
		fmt.Fprintf(stderr, "%s: the broker takes at most %d MiB; an export port49 wrote is smaller than that: check "+
			"the file is the export\n", name, api.MaxImportBytes>>20)
	case resp.Status == 400:
		fmt.Fprintf(stderr, "%s: the broker refused the request: %s; fix that and run it again\n", name, detail)
	case resp.Status == 503:
		fmt.Fprintf(stderr, "%s: the broker is unavailable just now (%s: %s); nothing was done: run it again shortly\n",
			name, safeLine(e.Error), detail)
	default:
		fmt.Fprintf(stderr, "%s: the broker answered %d %s: %s; nothing is known to have run: look at the broker's "+
			"log, then run it again\n", name, resp.Status, printsafe.Line(e.Error, 60), detail)
	}
	return 1
}

// printAdminResult prints a proved call's text, and exits 3 when a step did
// not finish and the call is to be run again.
func printAdminResult(name string, resp agent.AdminResponse, stdout, stderr io.Writer) int {
	var res api.AdminResult
	if err := json.Unmarshal(resp.Body, &res); err != nil || res.Text == "" {
		fmt.Fprintf(stderr, "%s: the broker's answer said nothing; it may have run: check the broker's decision log "+
			"before trying again\n", name)
		return 1
	}
	fmt.Fprintln(stdout, safeText(res.Text))
	if res.Partial {
		fmt.Fprintf(stderr, "%s: a step did not finish: run the same command again\n", name)
		return 3
	}
	return 0
}

// safeLine is a broker's or an agent's one line of text made safe for the
// terminal: the text crosses a network, so a hostile or broken broker must not
// put an escape sequence or a forged line in front of an operator.
func safeLine(s string) string { return printsafe.Line(s, 600) }

// safeText is a broker's multi-line text with each line made safe.
func safeText(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = printsafe.Line(l, 2000)
	}
	return strings.Join(lines, "\n")
}
