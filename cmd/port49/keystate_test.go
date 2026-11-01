package main

import (
	"testing"

	"github.com/blanketfish/port49/internal/agent"
)

// The CLI and the agent share one word for a blocked key.
func TestBlockedKeyStateIsTheAgents(t *testing.T) {
	if agent.KeyStateBlocked != "blocked" {
		t.Fatalf("agent.KeyStateBlocked = %q", agent.KeyStateBlocked)
	}
}
