package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNewRegistersEveryMetric(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	// Touch one child of every vector so it appears in gathering.
	m.Requests.WithLabelValues("authen", "pass").Inc()
	m.Latency.WithLabelValues("authen").Observe(0.001)
	m.Decisions.WithLabelValues("authen", "pass", "accept").Inc()
	m.Unvalidated.WithLabelValues("no_key").Inc()
	m.KeyValidations.WithLabelValues("default", "1", "accept").Inc()
	m.Connections.WithLabelValues("open").Set(1)
	m.ConnectionEvents.WithLabelValues("refused_cap").Inc()
	m.AuthFailures.Inc()
	m.SpoolDepth.Set(10)
	m.SpoolDrops.WithLabelValues("offer_refused").Inc()
	m.SpoolQuarantines.Inc()
	m.StoreOps.WithLabelValues("put", "ok").Inc()
	m.DecisionLogWriteFailures.Inc()
	m.CryptOpenFailures.WithLabelValues("context").Inc()

	// Gather all metrics from registry.
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather failed: %v", err)
	}

	// Expected metric names from brief + ConnectionEvents.
	expectedMetrics := map[string]bool{
		"port49_requests_total":                    false,
		"port49_request_seconds":                   false,
		"port49_decisions_total":                   false,
		"port49_unvalidated_packets_total":         false,
		"port49_key_validations_total":             false,
		"port49_connections":                       false,
		"port49_connection_events_total":           false,
		"port49_authentication_failures_total":     false,
		"port49_accounting_spool_depth":            false,
		"port49_accounting_spool_drops_total":      false,
		"port49_store_operations_total":            false,
		"port49_decision_log_write_failures_total": false,
		"port49_crypt_open_failures_total":         false,
	}

	// Check that all expected metrics are present and all gathered metrics are snake_case.
	gatheredNames := make(map[string]bool)
	for _, fam := range families {
		gatheredNames[fam.GetName()] = true

		// Check metric name is lowercase snake_case.
		if !isLowercaseSnakeCase(fam.GetName()) {
			t.Errorf("metric name not lowercase snake_case: %s", fam.GetName())
		}

		// Check all label names are lowercase snake_case.
		for _, m := range fam.GetMetric() {
			for _, label := range m.GetLabel() {
				if !isLowercaseSnakeCase(label.GetName()) {
					t.Errorf("label name not lowercase snake_case: %s", label.GetName())
				}
			}
		}
	}

	// Verify all expected metrics were gathered.
	for name := range expectedMetrics {
		if !gatheredNames[name] {
			t.Errorf("expected metric not found: %s", name)
		}
	}
}

// A counter that is constructed but never registered increments happily in
// process and never appears on /metrics, so the one signal that names a key
// rotation problem is silently absent exactly when it is needed. Gather from
// the registry, not from the collector: collecting the vector directly would
// pass whether or not New registered it.
func TestCryptOpenFailuresReachesTheRegistry(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)
	m.CryptOpenFailures.WithLabelValues("token").Inc()

	n, err := testutil.GatherAndCount(reg, "port49_crypt_open_failures_total")
	if err != nil {
		t.Fatalf("GatherAndCount failed: %v", err)
	}
	if n != 1 {
		t.Fatalf("port49_crypt_open_failures_total series in the registry = %d, want 1", n)
	}
}

func isLowercaseSnakeCase(s string) bool {
	// Check for uppercase letters or hyphens.
	for _, c := range s {
		if c >= 'A' && c <= 'Z' {
			return false
		}
		if c == '-' {
			return false
		}
	}
	// Only lowercase, digits, and underscores allowed.
	return !strings.ContainsAny(s, " \t\n")
}
