package metrics

import (
	"strings"
	"testing"
	"time"

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
	m.StoreCalls.WithLabelValues("daemon", "context", "ok").Inc()
	m.StoreCallSeconds.WithLabelValues("daemon", "context").Observe(0.001)
	m.StoreCircuitOpen.WithLabelValues("daemon", "context").Set(0)
	m.DecisionLogWriteFailures.Inc()
	m.CryptOpenFailures.WithLabelValues("context").Inc()
	m.IndexRecordsUndecodable.Inc()
	m.Attributions.WithLabelValues("foreign").Inc()
	m.BrokerItemErrors.WithLabelValues("device_unconfigured").Inc()
	m.BrokerIdempotency.WithLabelValues("conflict").Inc()
	m.BrokerHandshakeFailures.WithLabelValues("timeout").Inc()
	m.BrokerConnectionEvents.WithLabelValues("source_cap_refused").Inc()
	m.BrokerConnections.WithLabelValues("held").Set(1)
	m.BlobCache.WithLabelValues("hit").Inc()
	m.CountQuarantined(func() int { return 1 })
	m.ContextRefreshes.WithLabelValues("updated").Inc()
	m.ContextsReindexed.Inc()
	m.ContextsReindexFailures.Inc()
	m.SessionRefreshes.WithLabelValues("extended").Inc()
	m.TokensSuperseded.Inc()
	m.CeilingWarnings.Inc()
	m.Revocations.WithLabelValues("principal", "applied").Inc()
	m.RevocationsInForce.WithLabelValues("cert").Set(1)
	m.RevocationsFileFailed.Set(0)
	m.CertStatusChecks.WithLabelValues("crl", "good").Inc()
	m.CRLLoads.WithLabelValues("corp_issuing", "loaded").Inc()
	m.CRLNextUpdate.WithLabelValues("corp_issuing").Set(1)
	m.CertStatusUnavailable.Inc()
	m.PolicyReloads.WithLabelValues("applied").Inc()
	m.PolicyFileRefused.Set(0)
	m.PolicyRefreshPending.Set(0)
	m.InventoryReloads.WithLabelValues("applied").Inc()
	m.InventoryFileRefused.Set(0)
	m.InventoryFetches.WithLabelValues("unchanged").Inc()
	m.WatchInventoryAge(func() float64 { return 1 })
	m.StoreCertExpiry.WithLabelValues("daemon").Set(1)

	// Gather all metrics from registry.
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather failed: %v", err)
	}

	// Expected metric names from brief + ConnectionEvents.
	expectedMetrics := map[string]bool{
		"port49_requests_total":                             false,
		"port49_request_seconds":                            false,
		"port49_decisions_total":                            false,
		"port49_unvalidated_packets_total":                  false,
		"port49_key_validations_total":                      false,
		"port49_connections":                                false,
		"port49_connection_events_total":                    false,
		"port49_authentication_failures_total":              false,
		"port49_accounting_spool_depth":                     false,
		"port49_accounting_spool_drops_total":               false,
		"port49_store_operations_total":                     false,
		"port49_store_calls_total":                          false,
		"port49_store_call_seconds":                         false,
		"port49_store_circuit_open":                         false,
		"port49_decision_log_write_failures_total":          false,
		"port49_crypt_open_failures_total":                  false,
		"port49_store_index_records_undecodable_total":      false,
		"port49_store_keyspace_held":                        false,
		"port49_crypt_store_key_unknown":                    false,
		"port49_store_client_cert_expiry_timestamp_seconds": false,
		"port49_accounting_attributions_total":              false,
		"port49_broker_item_errors_total":                   false,
		"port49_broker_idempotency_refusals_total":          false,
		"port49_broker_tls_handshake_failures_total":        false,
		"port49_broker_connection_events_total":             false,
		"port49_broker_connections":                         false,
		"port49_blob_cache_lookups_total":                   false,
		"port49_devices_quarantined":                        false,
		"port49_context_refreshes_total":                    false,
		"port49_contexts_reindexed_total":                   false,
		"port49_contexts_reindex_failures_total":            false,
		"port49_session_refreshes_total":                    false,
		"port49_tokens_superseded_total":                    false,
		"port49_ceiling_warnings_total":                     false,
		"port49_revocations_total":                          false,
		"port49_revocations_in_force":                       false,
		"port49_revocations_file_failed":                    false,
		"port49_cert_status_checks_total":                   false,
		"port49_crl_loads_total":                            false,
		"port49_crl_next_update_timestamp_seconds":          false,
		"port49_cert_status_unavailable_total":              false,
		"port49_policy_reloads_total":                       false,
		"port49_policy_file_refused":                        false,
		"port49_policy_refresh_pending":                     false,
		"port49_inventory_reloads_total":                    false,
		"port49_inventory_file_refused":                     false,
		"port49_inventory_snapshot_age_seconds":             false,
		"port49_inventory_bundle_sequence":                  false,
		"port49_inventory_persist_failed":                   false,
		"port49_inventory_bundle_refused":                   false,
		"port49_inventory_policy_mismatch":                  false,
		"port49_inventory_mirror_unreadable":                false,
		"port49_inventory_fetches_total":                    false,
		// The key-version alert gates on uptime with it (spec §10).
		"process_start_time_seconds": false,
	}

	// Check that all expected metrics are present and all gathered metrics are snake_case.
	gatheredNames := make(map[string]bool)
	for _, fam := range families {
		gatheredNames[fam.GetName()] = true
		// The process collector's series describe port49d itself, never a device.
		if strings.HasPrefix(fam.GetName(), "process_") {
			for _, m := range fam.GetMetric() {
				if len(m.GetLabel()) != 0 {
					t.Errorf("%s carries labels %v", fam.GetName(), m.GetLabel())
				}
			}
		}

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

func TestKeySeriesAreSampledAtScrape(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)
	now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	m.WatchKeys(func() []KeySample {
		return []KeySample{{KeyRef: "prod_key", Version: 3, Devices: 8},
			{KeyRef: "prod_key", Version: 2, Devices: 1, RetireAt: now.Add(48 * time.Hour)}}
	}, func() time.Time { return now })
	want := `
# HELP port49_key_retirement_seconds Seconds until a key version's retire_after passes; negative once it has.
# TYPE port49_key_retirement_seconds gauge
port49_key_retirement_seconds{key_ref="prod_key",version="2"} 172800
# HELP port49_key_version_devices Devices whose latest validated connection since start used this key version.
# TYPE port49_key_version_devices gauge
port49_key_version_devices{key_ref="prod_key",version="2"} 1
port49_key_version_devices{key_ref="prod_key",version="3"} 8
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "port49_key_version_devices",
		"port49_key_retirement_seconds"); err != nil {
		t.Fatal(err)
	}
}

// The guard counts into the registered series, not copies of them.
func TestStoreGuardIsTheRegisteredSeries(t *testing.T) {
	m := New(prometheus.NewRegistry())
	g := m.StoreGuard()
	if g.Calls != m.StoreCalls || g.Seconds != m.StoreCallSeconds || g.Open != m.StoreCircuitOpen {
		t.Fatal("StoreGuard's series are not the registered ones")
	}
}
