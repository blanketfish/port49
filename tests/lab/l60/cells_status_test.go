package l60

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"
)

// statusCost times n GET /status calls on the agent at sock.
func (h *lab) statusCost(field, sock string, n int) {
	h.t.Helper()
	took := make([]time.Duration, 0, n)
	var last string
	for range n {
		start := time.Now()
		st, err := h.status(sock)
		took = append(took, time.Since(start))
		if err != nil {
			h.obs(field, "a call failed: "+err.Error())
			return
		}
		last = st.KeyState + "/" + st.TouchKeyState
	}
	h.obs(field, summarize(took)+" (key_state/touch_key_state "+last+")")
}

// summarize is n calls' min, median, p95, max and total.
func summarize(d []time.Duration) string {
	if len(d) == 0 {
		return "no calls"
	}
	s := slices.Clone(d)
	slices.Sort(s)
	var total time.Duration
	for _, x := range s {
		total += x
	}
	r := func(x time.Duration) string { return x.Round(10 * time.Microsecond).String() }
	return fmt.Sprintf("n=%d min=%s median=%s p95=%s max=%s total=%s", len(s), r(s[0]), r(s[len(s)/2]),
		r(s[(len(s)*95+99)/100-1]), r(s[len(s)-1]), r(total))
}

// The cost of GET /status, which reads the touch key's attestations on every
// call (agent.touchKeyState): N calls on a file-key agent (the control), on
// a slot 9a agent, and on a slot 9a agent with slot 9c as its touch key.
func TestL60StatusCost(t *testing.T) {
	gate(t, gateStatus, "times GET /status; you type your PIN twice")
	h := newLab(t, "status", true)
	h.needPKCS11()
	ca := h.needLabCA()
	b := h.startLabBroker(ca, nil)
	n := 50
	if v, err := strconv.Atoi(os.Getenv(envStatusN)); err == nil && v > 0 {
		n = v
	}
	h.obs("calls_per_agent", strconv.Itoa(n))

	h.step("1", "control: a file-key agent (no token)")
	cert, key := fileClient(t, ca)
	s0 := socketIn(t)
	h.mustOK(h.port49(runOpts{}, loginArgs(b, s0, key, cert, "")...), "the control login")
	h.statusCost("cost_file_key", s0, n)
	h.stopAgent(s0)

	s1 := socketIn(t)
	h.mustOK(h.typedLogin("2", "login_9a", loginArgs(b, s1, h.keyRef(slot9a, false), "", "")), "the slot 9a login")
	h.statusCost("cost_9a", s1, n)
	h.stopAgent(s1)

	s2 := socketIn(t)
	h.mustOK(h.typedLogin("3", "login_9a_touch_9c", loginArgs(b, s2, h.keyRef(slot9a, false), "", h.keyRef(slot9c, false))),
		"the slot 9a login with the touch key")
	h.obsStatus("status_9a_touch_9c", s2)
	h.statusCost("cost_9a_touch_9c", s2, n)
	h.stopAgent(s2)
}

// Cell (g), issued_key_store: pkcs11 on slot 9e, needs plan 9e, which is not
// built.
func TestL60G(t *testing.T) {
	t.Skip("L60 cell (g) (issued_key_store: pkcs11 on slot 9e: the certificate issued, nothing written to the token) " +
		"needs plan 9e, which is not built yet; it runs when plan 9e merges")
}
