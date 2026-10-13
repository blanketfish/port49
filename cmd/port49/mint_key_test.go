package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/hwkey"
)

// A key that is out is said as the agent said it, without the "agent: "
// prefix, and the command fails.
func TestMintFailedSaysAnAbsentKeyAsTheAgentDid(t *testing.T) {
	err := &agent.KeyAbsentError{State: hwkey.Absent, SessionEnds: time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)}
	var stderr bytes.Buffer
	if !mintFailed("port49 token", "/s", "leaf1", api.MintItem{}, err, &stderr) {
		t.Fatal("mintFailed returned false for an absent key")
	}
	want := "port49 token: insert your key; your session goes on until 2026-10-13T09:00:00Z"
	if !strings.HasPrefix(stderr.String(), want) || strings.Contains(stderr.String(), "agent:") {
		t.Fatalf("stderr = %q, want it to start %q", stderr.String(), want)
	}
}
