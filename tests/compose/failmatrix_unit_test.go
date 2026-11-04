//go:build compose && failmatrix

package compose

import "testing"

// circuitSummary prints the fields of a circuit-open line and nothing else,
// with "token" spelled "tkn".
func TestCircuitSummaryKeepsOnlyTheStructuredFields(t *testing.T) {
	line := `port49d-1  | 2026-11-04T01:45:01.044Z port49d: store: the daemon's token pool's circuit is open after 5 consecutive failures (store: unavailable: SECRET-LOOKING-TEXT; by call: PutToken 3, RedeemAndReceipt 2); each call on it fails at once`
	got, ok := circuitSummary(line)
	want := "2026-11-04T01:45:01.044Z daemon tkn pool open after 5 failures; by call: PutTkn 3, RedeemAndReceipt 2"
	if !ok || got != want {
		t.Fatalf("got %q %v, want %q", got, ok, want)
	}
	if _, ok := circuitSummary("port49d: listening on [::]:49"); ok {
		t.Fatal("a line that is no circuit line was summarized")
	}
}
