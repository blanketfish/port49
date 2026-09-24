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
	m.Attributions.WithLabelValues("foreign").Inc()
	m.BrokerItemErrors.WithLabelValues("device_unconfigured").Inc()
	m.BlobCache.WithLabelValues("hit").Inc()
	m.CountQuarantined(func() int { return 1 })
	m.ContextRefreshes.WithLabelValues("updated").Inc()
	m.TokensSuperseded.Inc()
	m.PolicyReloads.WithLabelValues("applied").Inc()
	m.PolicyFileRefused.Set(0)
	m.PolicyRefreshPending.Set(0)

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
		"port49_accounting_attributions_total":     false,
		"port49_broker_item_errors_total":          false,
		"port49_blob_cache_lookups_total":          false,
		"port49_devices_quarantined":               false,
		"port49_context_refreshes_total":           false,
		"port49_tokens_superseded_total":           false,
		"port49_policy_reloads_total":              false,
		"port49_policy_file_refused":               false,
		"port49_policy_refresh_pending":            false,
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

// port49_devices_quarantined is counted when it is scraped, not set once at
// start: quarantine is time-scoped, so the count moves with the clock.
func TestDevicesQuarantinedIsCountedAtEachScrape(t *testing.T) {
	m := New(prometheus.NewRegistry())
	if n := testutil.ToFloat64(m.DevicesQuarantined); n != 0 {
		t.Fatalf("before any count is set: %v", n)
	}
	count := 1
	m.CountQuarantined(func() int { return count })
	if n := testutil.ToFloat64(m.DevicesQuarantined); n != 1 {
		t.Fatalf("got %v, want 1", n)
	}
	count = 3
	if n := testutil.ToFloat64(m.DevicesQuarantined); n != 3 {
		t.Fatalf("got %v, want 3 at the next scrape", n)
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
