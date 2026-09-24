package decision

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// An authorization record names the policy it was decided against and the
// rules that matched, in the shape spec §5.7 writes: the rule as its terms, the
// tuple it scored, and the role that carries it.
func TestAnAuthorizationRecordCarriesItsMatchedRules(t *testing.T) {
	var buf bytes.Buffer
	NewJSONLines(&buf).Emit(Record{TS: time.Unix(0, 0), Event: EventAuthorizeCommand, Verdict: VerdictDeny,
		Reason: NoPermitDominatesDeny, Policy: &Policy{Bundle: "sha256:b", Blob: "sha256:a",
			MatchedDeny:    &PolicyRule{Rule: []string{"*", "*", "/^tftp:/"}, Specificity: []int{1, 1, 2}, Role: "no_exfil"},
			MatchedPermits: []PolicyRule{{Rule: []string{"copy", "**"}, Specificity: []int{3, 0, 0}, Role: "net_operator"}}}})
	var raw struct {
		Policy map[string]any `json:"policy"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	p := raw.Policy
	deny, _ := p["matched_deny"].(map[string]any)
	rule, _ := deny["rule"].([]any)
	permits, _ := p["matched_permits"].([]any)
	if p["bundle"] != "sha256:b" || p["blob"] != "sha256:a" || deny["role"] != "no_exfil" ||
		len(rule) != 3 || len(permits) != 1 {
		t.Fatalf("policy block: %s", buf.String())
	}
	if _, ok := p["stage"]; ok {
		t.Fatalf("stage is omitted unless a pipeline stage was refused: %s", buf.String())
	}
	if BlobPlatformMismatch != "blob_platform_mismatch" {
		t.Fatalf("the §5.7 spelling is blob_platform_mismatch, got %q", BlobPlatformMismatch)
	}
}

// A permitted session record carries the attributes it returned, as sent,
// so replay can re-derive and compare them (spec §5.7).
func TestASessionRecordCarriesItsReply(t *testing.T) {
	var buf bytes.Buffer
	NewJSONLines(&buf).Emit(Record{TS: time.Unix(0, 0), Event: EventAuthorizeSession, Verdict: VerdictPermit,
		Reason: ContextMatched, Reply: &Reply{Attributes: []string{"priv-lvl=15", "home-directory*/home/alice"}}})
	var raw struct {
		Reply struct {
			Attributes []string `json:"attributes"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw.Reply.Attributes) != 2 || raw.Reply.Attributes[1] != "home-directory*/home/alice" {
		t.Fatalf("reply: %s", buf.String())
	}
}

// Write is Emit with the refusal returned, and a refusal is counted once
// whichever the caller used (the spool retries on Write; spec §5.8).
func TestWriteReturnsTheSinksRefusal(t *testing.T) {
	var failures int
	s := NewJSONLinesWithFailureHook(failingWriter{err: errors.New("no space left on device")}, func() { failures++ })
	if err := s.Write(Record{Event: EventAccount}); err == nil {
		t.Fatal("a refused write must return its error")
	}
	s.Emit(Record{Event: EventAccount})
	if failures != 2 {
		t.Fatalf("one count per refused record, got %d", failures)
	}
	var buf bytes.Buffer
	if err := NewJSONLines(&buf).Write(Record{Event: EventAccount}); err != nil || buf.Len() == 0 {
		t.Fatalf("a good write: %v %q", err, buf.String())
	}
}
