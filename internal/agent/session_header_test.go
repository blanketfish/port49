package agent

import (
	"context"
	"encoding/base64"
	"testing"
	"time"
)

// The agent draws 32 random bytes at its start and sends them, base64url, as
// api.AgentSessionHeader on every broker request (decision 45 ruling 15): the
// connect, a mint, a refresh's challenge and its answer.
func TestEveryBrokerRequestCarriesTheAgentSession(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if _, err := r.a.Mint(ctx, "leaf1", false, time.Minute, ""); err != nil {
		t.Fatal(err)
	}
	_, _ = r.a.Refresh(ctx, "") // the fake broker's answer does not matter: both requests are sent
	r.fb.mu.Lock()
	seen := map[string][]string{}
	for p, v := range r.fb.sessions {
		seen[p] = append([]string(nil), v...)
	}
	r.fb.mu.Unlock()
	var first string
	for _, p := range []string{"/v1/config", "/v1/tokens", "/v1/refresh/challenge"} {
		if len(seen[p]) == 0 {
			t.Fatalf("%s was never asked", p)
		}
		for _, v := range seen[p] {
			if b, err := base64.RawURLEncoding.DecodeString(v); err != nil || len(b) != 32 {
				t.Fatalf("%s carried %d bytes of session, err %v", p, len(v), err)
			}
			if first == "" {
				first = v
			}
			if v != first {
				t.Fatalf("%s carried another session than the first request", p)
			}
		}
	}
	other := newRig(t)
	other.fb.mu.Lock()
	defer other.fb.mu.Unlock()
	if v := other.fb.sessions["/v1/config"]; len(v) == 0 || v[0] == first {
		t.Fatalf("a second agent shares the first's session")
	}
}
