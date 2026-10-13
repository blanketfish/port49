package main

import (
	"cmp"

	"github.com/rhwendt/port49/internal/agent"
)

// touchUnavailable is why the agent's touch key cannot be touched now, from
// Status.TouchKeyState, or "" when it can (an agent that reports no state is
// taken at its TouchKey). The words are fixed, never the agent's.
func touchUnavailable(state string) string {
	switch state {
	case "absent":
		return "the touch key is not in the machine"
	case "locked":
		return "the touch key needs its PIN"
	case "no_attestation":
		return "your token shows no attestation certificates"
	}
	return ""
}

// adoptAgentSession points sf at the broker the agent's session is with, with
// the CA and CRL mode that session uses, so a proof posted outside the agent
// (the sign-in's) goes where the challenge came from and is checked as the
// session is. It must run before sf.fill: the config file then supplies the
// provider's side alone, never a different broker, and its broker_ca is
// unused when the agent gave the CA (a login made with flags has none in any
// file).
func adoptAgentSession(sf *sessionFlags, st agent.Status) {
	sf.broker, sf.verified = st.Broker, false
	if st.BrokerCAPEM != "" {
		sf.brokerCA, sf.brokerCAPEM = "the agent's session", []byte(st.BrokerCAPEM)
	}
	sf.brokerCRL = cmp.Or(st.BrokerCRL, sf.brokerCRL)
}
