package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/brokercrl"
	"github.com/rhwendt/port49/internal/printsafe"
)

// tokenFailure is `port49 token --json`'s stdout on a failure (decision 46
// ruling 9): the broker's own item for a deny or an item it could not decide
// (no token in either), or a client code.
type tokenFailure struct {
	Device      string          `json:"device"`
	Verdict     string          `json:"verdict,omitempty"`
	Reason      string          `json:"reason,omitempty"`
	Error       string          `json:"error,omitempty"`
	Detail      string          `json:"detail,omitempty"`
	PerLoginMFA *mfaRequirement `json:"per_login_mfa,omitempty"`
}

// mfaRequirement is a requirement as printed: never its challenge.
type mfaRequirement struct {
	Accept          []string       `json:"accept"`
	ReuseForSeconds int            `json:"reuse_for_seconds"`
	ReuseFrom       string         `json:"reuse_from,omitempty"`
	Levels          []api.MFALevel `json:"levels,omitempty"`
}

// Client codes of `port49 token --json` (decision 46 ruling 9): the CLI's own,
// like the API's error codes, never §5.7 reason codes.
const (
	failNoAgent           = "no_agent"
	failAgentTooOld       = "agent_too_old"
	failSessionOver       = "session_over"
	failRevoked           = "credential_revoked"
	failRevocationRunning = "revocation_running"
	failMFARequired       = "per_login_mfa_required"
	failConnectionChanged = "connection_changed"
	failBrokerRefused     = "broker_refused"
	failBrokerUnavailable = "broker_unavailable"
	failNoToken           = "no_token"
	failAgent             = "agent_error"
)

// brokerStatusError is a broker answer the CLI made itself (an IdP proof's
// POST, a config fetch) that was not a 200. Its text is the message it always
// had; Status lets tokenFailureOf sort it as it sorts the agent's own proof
// paths: 503 an outage, under 500 a refusal, else a fault.
type brokerStatusError struct {
	Status int
	msg    string
}

func (e *brokerStatusError) Error() string { return e.msg }

func requirementOf(r api.PerLoginMFA) *mfaRequirement {
	return &mfaRequirement{Accept: r.Accept, ReuseForSeconds: r.ReuseForSeconds, ReuseFrom: r.ReuseFrom, Levels: r.Levels}
}

// tokenFailureOf is why a mint gave no usable token, as one JSON object. The
// session's own failures and the key's come before the requirement, so a
// revoked session or a touch that timed out inside a proof says so, not
// per_login_mfa_required (pre-flight M8).
func tokenFailureOf(device string, item api.MintItem, err error) tokenFailure {
	f := tokenFailure{Device: device}
	if err != nil {
		f.Detail = printsafe.Line(unprefixed(err), safeLimit)
	}
	var ie *agent.ItemError
	var need *agent.MFARequiredError
	var unproved *mfaUnprovedError
	var revoked *agent.RevokedError
	var running *agent.RevocationRunningError
	var refused *agent.BrokerRefusedError
	var crlRevoked *brokercrl.RevokedError
	var crlUnchecked *brokercrl.UncheckedError
	var down *agent.BrokerUnavailableError
	var answered *agent.APIError
	var downCLI *brokerDownError
	var status *brokerStatusError
	var fault *agent.BrokerFaultError
	switch {
	case err == nil && item.Verdict != "" && item.Verdict != "permit":
		f.Verdict, f.Reason = item.Verdict, item.Reason
		f.Detail = printsafe.Line(item.Detail, safeLimit)
	case err == nil:
		f.Error = failNoToken
	case errors.As(err, &ie):
		f.Error, f.Detail = ie.Code, printsafe.Line(ie.Detail, safeLimit)
	case agent.KeyCode(err) != "":
		f.Error = agent.KeyCode(err)
	case errors.Is(err, agent.ErrConnectionChanged):
		f.Error = failConnectionChanged
	case errors.As(err, &refused), errors.As(err, &crlRevoked), errors.As(err, &crlUnchecked):
		// The CRL check refused the broker's certificate, in the agent or in
		// an IdP proof the CLI posted itself.
		f.Error = failBrokerRefused
	case errors.As(err, &down), errors.As(err, &downCLI), errors.As(err, &status) && status.Status == http.StatusServiceUnavailable:
		f.Error = failBrokerUnavailable
	case errors.As(err, &status) && status.Status < 500:
		f.Error = failBrokerRefused
	case errors.As(err, &status), errors.As(err, &fault):
		f.Error = failAgent
	case errors.As(err, &revoked):
		f.Error = failRevoked
	case errors.As(err, &running):
		f.Error = failRevocationRunning
	case errors.Is(err, agent.ErrAgentTooOld):
		f.Error = failAgentTooOld
	case errors.Is(err, agent.ErrNoAgent):
		f.Error = failNoAgent
	case errors.Is(err, agent.ErrSessionOver):
		f.Error = failSessionOver
	case errors.As(err, &answered) && answered.Status < 500:
		// The broker refused a proof the CLI sent through the agent (a 4xx):
		// nothing for the person to prove again.
		f.Error = failBrokerRefused
	case errors.As(err, &answered):
		f.Error = failAgent // a broker fault; a 503 is an outage and is caught above
	case errors.As(err, &unproved):
		f.Error, f.PerLoginMFA = failMFARequired, requirementOf(unproved.Requirement)
	case errors.As(err, &need):
		f.Error, f.PerLoginMFA = failMFARequired, requirementOf(need.Requirement)
	default:
		f.Error = failAgent
	}
	return f
}

// mintFailed says, under cmd's prefix, why a mint through the agent gave no
// usable token, and reports whether it did. These are `port49 token`'s words,
// shared by `port49 ssh`.
func mintFailed(cmd, socket, device string, item api.MintItem, err error, stderr io.Writer) bool {
	var ie *agent.ItemError
	var need *agent.MFARequiredError
	switch {
	case errors.As(err, &need):
		// Still required after a proof, or the requirement of a re-mint: said,
		// never proved again in a loop.
		fmt.Fprintf(stderr, "%s: %s\n", cmd, describeMFA(need.Requirement))
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
