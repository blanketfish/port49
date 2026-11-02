package metrics

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/devicecert"
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
	m.CertStatusChecks.WithLabelValues("broker", "crl", "good").Inc()
	m.CRLLoads.WithLabelValues("broker", "corp_issuing", "loaded").Inc()
	m.CRLNextUpdate.WithLabelValues("broker", "corp_issuing").Set(1)
	m.CertStatusUnavailable.WithLabelValues("broker").Inc()
	m.PolicyReloads.WithLabelValues("applied").Inc()
	m.PolicyFileRefused.Set(0)
	m.StoreKeyspaceHeld.WithLabelValues().Set(1)
	m.StoreDirectoryReachable.WithLabelValues().Set(1)
	m.StoreDirectoryConfirmed.WithLabelValues().Set(1)
	m.DirectoryRefreshLastComplete.WithLabelValues().Set(1)
	m.SetPolicyFailClosed(0)
	m.PolicyRefreshPending.Set(0)
	if v := testutil.ToFloat64(m.PolicyBundleMatchesRunner); v != 1 {
		t.Fatalf("port49_policy_bundle_matches_runner starts at %v; nothing is known to differ", v)
	}
	m.BrokerMintGateClosed.Set(0)
	m.RedemptionRestoreGuarded.Set(0)
	m.RedemptionRestoreGuardUntil.Set(0)
	m.InventoryReloads.WithLabelValues("applied").Inc()
	m.InventoryFileRefused.Set(0)
	m.InventoryFetches.WithLabelValues("unchanged").Inc()
	m.WatchInventoryAge(func() float64 { return 1 })
	m.StoreCertExpiry.WithLabelValues("daemon").Set(1)
	m.StoreFeedUp.WithLabelValues("contexts").Set(1)
	m.StoreFeedRescans.WithLabelValues("contexts").Inc()
	m.LedgerPending.Set(0)
	m.LedgerBehind.Set(0)

	// Gather all metrics from registry.
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather failed: %v", err)
	}

	// Expected metric names from brief + ConnectionEvents.
	expectedMetrics := map[string]bool{
		"port49_requests_total":                                   false,
		"port49_request_seconds":                                  false,
		"port49_decisions_total":                                  false,
		"port49_unvalidated_packets_total":                        false,
		"port49_key_validations_total":                            false,
		"port49_connections":                                      false,
		"port49_connection_events_total":                          false,
		"port49_authentication_failures_total":                    false,
		"port49_accounting_spool_depth":                           false,
		"port49_accounting_spool_drops_total":                     false,
		"port49_store_operations_total":                           false,
		"port49_store_calls_total":                                false,
		"port49_store_call_seconds":                               false,
		"port49_store_circuit_open":                               false,
		"port49_decision_log_write_failures_total":                false,
		"port49_crypt_open_failures_total":                        false,
		"port49_store_index_records_undecodable_total":            false,
		"port49_store_keyspace_held":                              false,
		"port49_store_feed_up":                                    false,
		"port49_store_feed_rescans_total":                         false,
		"port49_store_fence_timeouts_total":                       false,
		"port49_ledger_pending":                                   false,
		"port49_ledger_behind":                                    false,
		"port49_crypt_store_key_unknown":                          false,
		"port49_store_client_cert_expiry_timestamp_seconds":       false,
		"port49_accounting_attributions_total":                    false,
		"port49_broker_item_errors_total":                         false,
		"port49_broker_idempotency_refusals_total":                false,
		"port49_broker_tls_handshake_failures_total":              false,
		"port49_broker_connection_events_total":                   false,
		"port49_broker_connections":                               false,
		"port49_blob_cache_lookups_total":                         false,
		"port49_devices_quarantined":                              false,
		"port49_devices_generic_platform":                         false,
		"port49_context_refreshes_total":                          false,
		"port49_contexts_reindexed_total":                         false,
		"port49_contexts_reindex_failures_total":                  false,
		"port49_session_refreshes_total":                          false,
		"port49_tokens_superseded_total":                          false,
		"port49_ceiling_warnings_total":                           false,
		"port49_revocations_total":                                false,
		"port49_revocations_in_force":                             false,
		"port49_revocations_file_failed":                          false,
		"port49_cert_status_checks_total":                         false,
		"port49_crl_loads_total":                                  false,
		"port49_crl_next_update_timestamp_seconds":                false,
		"port49_cert_status_unavailable_total":                    false,
		"port49_policy_reloads_total":                             false,
		"port49_policy_file_refused":                              false,
		"port49_policy_refresh_pending":                           false,
		"port49_policy_bundle_matches_runner":                     false,
		"port49_broker_mint_gate_closed":                          false,
		"port49_redemption_restore_guarded":                       false,
		"port49_redemption_restore_guard_until_timestamp_seconds": false,
		"port49_inventory_reloads_total":                          false,
		"port49_inventory_file_refused":                           false,
		"port49_inventory_snapshot_age_seconds":                   false,
		"port49_inventory_bundle_sequence":                        false,
		"port49_inventory_persist_failed":                         false,
		"port49_inventory_bundle_refused":                         false,
		"port49_inventory_policy_mismatch":                        false,
		"port49_inventory_mirror_unreadable":                      false,
		"port49_inventory_fetches_total":                          false,
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

func TestEverySignInOutcomeExistsAtZero(t *testing.T) {
	m := New(prometheus.NewRegistry())
	// Counted before any WithLabelValues, which would create the series.
	if n := testutil.CollectAndCount(m.SignIns); n != 9 {
		t.Fatalf("%d series; every outcome from the first scrape", n)
	}
	for _, o := range []string{"issued", "refused", "throttled", "enrollment_started", "enrolled",
		"enrollment_closed", "enrollment_store_lost", "directory_unavailable", "store_unavailable"} {
		if v := testutil.ToFloat64(m.SignIns.WithLabelValues(o)); v != 0 {
			t.Errorf("%s: %v", o, v)
		}
	}
}

// The gauge is not set at construction: it is absent without a
// directory_password verifier, and port49d sets it once the store is checked.
func TestTheEnrollmentStoreGaugeIsNotSetAtConstruction(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)
	if n, err := testutil.GatherAndCount(reg, "port49_directory_enrollment_store_ok"); err != nil || n != 0 {
		t.Fatalf("%d %v", n, err)
	}
	m.DirectoryEnrollmentStoreOK.WithLabelValues().Set(1)
	if v := testutil.ToFloat64(m.DirectoryEnrollmentStoreOK); v != 1 {
		t.Fatalf("%v", v)
	}
}

func TestTLSMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)
	for _, o := range append([]devicecert.Outcome{devicecert.OK, devicecert.Resumed}, devicecert.Outcomes...) {
		m.TLSHandshakes.WithLabelValues(string(o)).Inc()
	}
	m.WatchTLSLifetime(func() (float64, bool) { return 0.25, true }, func() float64 { return 0.5 })
	m.CountDevicesByTransport(func() map[string]int { return map[string]int{"tcp": 3, "tls": 2} })
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, mf := range mfs {
		for _, mm := range mf.GetMetric() {
			key := mf.GetName()
			for _, l := range mm.GetLabel() {
				key += "{" + l.GetName() + "=" + l.GetValue() + "}"
			}
			if g := mm.GetGauge(); g != nil {
				got[key] = g.GetValue()
			}
		}
	}
	if got["port49_tls_device_certificate_lifetime_left_ratio"] != 0.25 || got["port49_tls_server_certificate_lifetime_left_ratio"] != 0.5 ||
		got["port49_devices_by_transport{transport=tcp}"] != 3 || got["port49_devices_by_transport{transport=tls}"] != 2 {
		t.Fatalf("gauges: %v", got)
	}
	if n := testutil.CollectAndCount(m.TLSHandshakes); n != 14 {
		t.Fatalf("%d outcome series, want 14", n)
	}
}

func TestTLSLifetimeWithNoneSeenIsWhole(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)
	m.WatchTLSLifetime(func() (float64, bool) { return 0, false }, nil)
	if v := testutil.ToFloat64(m.TLSDeviceCertLifetime); v != 1 {
		t.Fatalf("none seen: %v, want 1 so a lifetime alarm never fires on nothing", v)
	}
	if v := testutil.ToFloat64(m.TLSServerCertLifetime); v != 1 {
		t.Fatalf("no listener: %v, want 1", v)
	}
}

func TestTLSHandshakeSeriesExistFromTheStart(t *testing.T) {
	m := New(prometheus.NewRegistry())
	if n := testutil.CollectAndCount(m.TLSHandshakes); n != 14 {
		t.Fatalf("%d outcome series before any handshake, want 14", n)
	}
}

func TestASingleDeviceKeyRefIsNotALabel(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)
	now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	m.SetSingleDeviceKeyRefs(map[string]bool{"r1_pin": true})
	if k, v := m.KeyLabels("r1_pin", 3); k != SingleDeviceKeyRef || v != AnyVersion {
		t.Fatalf("KeyLabels(r1_pin, 3) = (%q, %q)", k, v)
	}
	m.WatchKeys(func() []KeySample {
		return []KeySample{{KeyRef: "r1_pin", Version: 3, Devices: 1, RetireAt: now.Add(time.Hour)}}
	}, func() time.Time { return now })
	ref, ver := m.KeyLabels("r1_pin", 3)
	m.KeyValidations.WithLabelValues(ref, ver, "validated").Inc()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		for _, s := range mf.GetMetric() {
			for _, l := range s.GetLabel() {
				if strings.Contains(l.GetValue(), "r1_pin") {
					t.Fatalf("%s has a label naming the pin: %s", mf.GetName(), l.GetValue())
				}
			}
		}
	}
}

func TestTwoDevicesKeepTheirKeyRef(t *testing.T) {
	m := New(prometheus.NewRegistry())
	m.SetSingleDeviceKeyRefs(map[string]bool{"r1_pin": true})
	if k, v := m.KeyLabels("core", 2); k != "core" || v != "2" {
		t.Fatalf("KeyLabels(core, 2) = (%q, %q)", k, v)
	}
}

// A single-device key that no device presents does not count, and the least
// retirement among those that do is the one reported.
func TestTheSingleDeviceRetirementIsTheLeastPresented(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)
	now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	m.SetSingleDeviceKeyRefs(map[string]bool{"a_pin": true, "b_pin": true, "c_pin": true})
	m.WatchKeys(func() []KeySample {
		return []KeySample{
			{KeyRef: "a_pin", Version: 1, Devices: 1, RetireAt: now.Add(10 * 24 * time.Hour)},
			{KeyRef: "b_pin", Version: 1, Devices: 0, RetireAt: now.Add(24 * time.Hour)},
			{KeyRef: "c_pin", Version: 2, Devices: 1},
		}
	}, func() time.Time { return now })
	want := `
# HELP port49_key_retirement_seconds Seconds until a key version's retire_after passes; negative once it has.
# TYPE port49_key_retirement_seconds gauge
port49_key_retirement_seconds{key_ref="single_device",version="any"} 864000
# HELP port49_key_version_devices Devices whose latest validated connection since start used this key version.
# TYPE port49_key_version_devices gauge
port49_key_version_devices{key_ref="single_device",version="any"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "port49_key_version_devices",
		"port49_key_retirement_seconds"); err != nil {
		t.Fatal(err)
	}
}

// A series counted while two devices held the key names it once one does, so
// setting it single-device takes the series out.
func TestSettingAKeySingleDeviceDropsItsNamedSeries(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)
	m.KeyValidations.WithLabelValues("edge", "3", "validated").Inc()
	m.KeyValidations.WithLabelValues("core", "2", "validated").Inc()
	m.SetSingleDeviceKeyRefs(map[string]bool{"edge": true})
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var core bool
	for _, mf := range mfs {
		for _, s := range mf.GetMetric() {
			for _, l := range s.GetLabel() {
				if l.GetValue() == "edge" {
					t.Fatalf("%s still has a series labelled edge", mf.GetName())
				}
				core = core || l.GetValue() == "core"
			}
		}
	}
	if !core {
		t.Fatal("core's series was dropped with edge's")
	}
}

// A count that chose its labels under the old set lands before a new set's
// delete, never after it: the series must not come back under the key's name.
func TestACountRacingASetNeverRecreatesTheNamedSeries(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)
	done := make(chan struct{})
	m.afterKeyLabels = func() {
		go func() {
			m.SetSingleDeviceKeyRefs(map[string]bool{"edge": true})
			close(done)
		}()
		time.Sleep(50 * time.Millisecond) // the set has had every chance to run
	}
	m.CountKeyValidation("edge", 3, "validated")
	<-done
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		for _, s := range mf.GetMetric() {
			for _, l := range s.GetLabel() {
				if l.GetValue() == "edge" {
					t.Fatalf("%s has a series labelled edge", mf.GetName())
				}
			}
		}
	}
}

// port49_redemption_restore_guard_until_timestamp_seconds reaches the
// registry with no labels, and reads 0 until the guard sets it (plan 12c,
// Task 9a).
func TestRestoreGuardUntilReachesTheRegistryWithNoLabels(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)
	fams, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() != "port49_redemption_restore_guard_until_timestamp_seconds" {
			continue
		}
		if len(f.GetMetric()) != 1 || len(f.GetMetric()[0].GetLabel()) != 0 {
			t.Fatalf("want one series without labels: %v", f.GetMetric())
		}
		if v := testutil.ToFloat64(m.RedemptionRestoreGuardUntil); v != 0 {
			t.Fatalf("starts at %v, want 0", v)
		}
		return
	}
	t.Fatal("port49_redemption_restore_guard_until_timestamp_seconds is not registered")
}

// port49_issuing_ca_configured reaches the registry with no labels and reads
// 0 until a broker with issuance sets it (plan 12c, Task 5).
func TestIssuingCAConfiguredReachesTheRegistryAtZero(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)
	fams, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() != "port49_issuing_ca_configured" {
			continue
		}
		if len(f.GetMetric()) != 1 || len(f.GetMetric()[0].GetLabel()) != 0 {
			t.Fatalf("want one series without labels: %v", f.GetMetric())
		}
		if v := testutil.ToFloat64(m.IssuingCAConfigured); v != 0 {
			t.Fatalf("starts at %v, want 0", v)
		}
		return
	}
	t.Fatal("port49_issuing_ca_configured is not registered")
}

// The gauges an alert reads as "0 is a fault" exist only where the thing they watch does, so a
// process without it (the memory backend; no scheduled refresh) has no series to read 0 and page
// on (plan 12c, Task 5 fix 1, C1/I2). Each is created by the code that starts what it watches.
func TestEtcdOnlyGaugesHaveNoSeriesUntilSet(t *testing.T) {
	m := New(prometheus.NewRegistry())
	for name, c := range map[string]prometheus.Collector{
		"port49_store_directory_reachable":                         m.StoreDirectoryReachable,
		"port49_store_directory_confirmed_timestamp_seconds":       m.StoreDirectoryConfirmed,
		"port49_store_keyspace_held":                               m.StoreKeyspaceHeld,
		"port49_directory_refresh_last_complete_timestamp_seconds": m.DirectoryRefreshLastComplete,
	} {
		if n := testutil.CollectAndCount(c); n != 0 {
			t.Errorf("%s has %d series at construction, want none", name, n)
		}
	}
}

// port49_directory_password_configured is 0 until a broker with a directory_password verifier sets it.
func TestDirectoryPasswordConfiguredStartsAtZero(t *testing.T) {
	m := New(prometheus.NewRegistry())
	if v := testutil.ToFloat64(m.DirectoryPasswordConfigured); v != 0 {
		t.Fatalf("starts at %v, want 0", v)
	}
}
