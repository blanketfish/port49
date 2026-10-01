// Package metrics defines every daemon metric in one place (design §15). Labels
// are bounded by construction; device identity never appears here.
package metrics

import (
	"strconv"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

type Metrics struct {
	Requests       *prometheus.CounterVec   // port49_requests_total{exchange, outcome}
	Latency        *prometheus.HistogramVec // port49_request_seconds{exchange}
	Decisions      *prometheus.CounterVec   // port49_decisions_total{event, verdict, reason}
	Unvalidated    *prometheus.CounterVec   // port49_unvalidated_packets_total{diagnosis}
	KeyValidations *prometheus.CounterVec   // port49_key_validations_total{key_ref, version, outcome}
	Connections    *prometheus.GaugeVec     // port49_connections{state="open"}
	// port49_connection_events_total{event}. The full set of event values:
	// "refused_cap" (the per-source connection cap), "idle_closed" (the idle
	// timeout, which also fires on a stall partway through a packet),
	// "malformed_backoff" (a strike from an admitted source), "unadmitted_source"
	// (a strike from an address not in the inventory: recorded and reset at
	// once, L31), "key_miss_closed" (a first packet no accepted key validated,
	// or one past its version's retire_after: struck and reset at once, L28),
	// "held_refused" (a source inside the backoff its last strike earned,
	// reset at Accept, L28; the strike is a key miss, garbage, or an address
	// the inventory does not name, a removed device's retries included, so
	// the event that opened it says which: "key_miss_closed",
	// "malformed_backoff" or "unadmitted_source"),
	// "declined_refused" (a source inside the decline window a refused or
	// quarantined device, or a reload's refusal or removal, opened: reset at
	// Accept while still declined, no strike, L31),
	// "admission_closed" (an open connection whose device a reload refused,
	// removed, renamed, re-keyed or re-platformed: reset at its next packet,
	// no strike),
	// "panic" (a connection recovered from a panic), and "accept_error"
	// (Accept failed and the listener is being retried).
	ConnectionEvents *prometheus.CounterVec
	AuthFailures     prometheus.Counter // port49_authentication_failures_total
	SpoolDepth       prometheus.Gauge   // port49_accounting_spool_depth
	// port49_accounting_spool_drops_total{stage}. The stages are not the
	// same event and must not be alerted on together: "offer_refused" means
	// the record never became durable, so its device was answered ERROR and
	// will retry — nothing is lost. "drain_unparseable" means the record was
	// durable, its device was answered SUCCESS, and it is gone.
	// "drain_set_aside" means the decision log can never encode it, so it was
	// moved to <spool>.unencodable for an operator rather than hold every
	// record behind it.
	SpoolDrops *prometheus.CounterVec
	// port49_accounting_spool_quarantines_total: .draining files set aside for
	// an operator after three consecutive read failures. Not a record count —
	// the records are still in the quarantined file.
	SpoolQuarantines         prometheus.Counter
	StoreOps                 *prometheus.CounterVec
	DecisionLogWriteFailures prometheus.Counter // port49_decision_log_write_failures_total
	// port49_crypt_open_failures_total{record}. A record that will not open is a
	// key problem, not a missing record, and it is the one failure mode of the
	// rotation window that has no other symptom. Labels are the record kind only —
	// "token", "receipt", "context", "idempotency" — never a device or a user.
	CryptOpenFailures *prometheus.CounterVec
	// port49_accounting_attributions_total{attribution}: every accounting
	// record the spool accepted, by the attribution it was given — "resolved",
	// "unattributed", "system", "foreign" (spec §5.8). `foreign` is the one to
	// alert on: an exec record for a session port49 did not authenticate,
	// under a name it does, which is a local fallback, a console, or a
	// device-local account sharing a port49 username. The label is the
	// attribution only; the device and the user are on the log record.
	Attributions *prometheus.CounterVec
	// port49_broker_item_errors_total{error}: mint items the broker could not
	// decide, by the API error code on the item — "device_unconfigured" (an
	// inventory device with no platform), "broker_error" (a policy that
	// compiled to a blob the daemon would refuse), "attribute_too_long" (a
	// session attribute the principal's own values push past 255 bytes), or
	// "attribute_unsafe" (one they would fill with `=`, `*`, a control
	// character or invalid UTF-8). None is a decision, so none is in port49_decisions_total.
	// The label is the code only.
	BrokerItemErrors *prometheus.CounterVec
	// port49_broker_idempotency_refusals_total{outcome}: mint requests refused
	// whole at their Idempotency-Key (design §17; plan 7a): "conflict" (another
	// body under the key), "in_progress" (the same body still minting), and
	// "store_error" (the reservation could not be read or written).
	BrokerIdempotency *prometheus.CounterVec
	// port49_broker_tls_handshake_failures_total{reason}: handshakes the
	// broker's listener did not complete (spec §13 decision 32): reason is
	// untrusted_chain, identity_refused, server_cert_refused, timeout,
	// client_closed or protocol.
	BrokerHandshakeFailures *prometheus.CounterVec
	// port49_broker_connection_events_total{event}: source_cap_refused (reset
	// at accept, its source holding max_pending_conns_per_source),
	// principal_cap_evicted (a principal's oldest held connection closed for
	// its newest), revoked_closed (closed by a revocation), revoked_refused
	// (answered credential_revoked and closed at bind: its certificate or
	// principal is marked).
	BrokerConnectionEvents *prometheus.CounterVec
	// port49_broker_connections{state}: pending (not yet bound to a
	// principal: handshaking, or certificate-less) and held.
	BrokerConnections *prometheus.GaugeVec
	// port49_blob_cache_lookups_total{outcome}: the authorizer's per-replica
	// blob cache, "hit" or "miss" (spec §5.1.1). A miss is one store read,
	// counted again in port49_store_operations_total{op="get_blob"}; a hit
	// during a blob-read failure is a command still being answered.
	BlobCache *prometheus.CounterVec
	// port49_devices_quarantined: how many inventory devices the loaded policy
	// quarantines now (spec §10). Quarantine is time-scoped — a grant's expiry
	// can bring one on or end it — so the count is taken at each scrape, from
	// the function CountQuarantined sets; 0 until it is set. Each device is
	// named in port49d's start lines and on every record its connections
	// leave; the gauge is what an alert watches, and it names no device.
	DevicesQuarantined prometheus.GaugeFunc
	quarantined        atomic.Pointer[func() int]
	// port49_devices_admission_refused: how many inventory devices the bundle
	// in force refuses admission — no key group admits them, two tie on
	// them, or their key_ref is one port49d holds no key for (spec §10). Each
	// is named at start and at every reload; the gauge names none.
	DevicesAdmissionRefused prometheus.GaugeFunc
	admissionRefused        atomic.Pointer[func() int]
	// port49_context_refreshes_total{outcome}: live login contexts a policy
	// refresh visited, by what it did to each (spec §5.1.3) — "updated" (the
	// policy in force written into it), "unchanged", "revoked" (no grant left
	// on that device), "quarantined" (the device is quarantined; the context
	// is left as it was), or "failed" (a context that could not be opened, or
	// a policy in force that could not be resolved or compiled for it — both
	// revoked, failing closed — or a context still changing after every
	// compare-and-set attempt, left for the retry; the process log says which).
	// A context the refresh skipped — another principal's since, the lab's,
	// already revoked — is not counted. The label is the outcome only.
	ContextRefreshes *prometheus.CounterVec
	// port49_tokens_superseded_total: (device, username) keys whose unspent
	// tokens a policy change deleted, because the policy now in force would
	// not mint what they carry. Each is one operator's `port49 token` to run
	// again; none is a session ended.
	TokensSuperseded prometheus.Counter
	// port49_ceiling_warnings_total: permitted authorization replies that
	// carried the session ceiling warning in server_msg (spec §5.6; decision
	// 33). No labels.
	CeilingWarnings prometheus.Counter
	// port49_revocations_total{by, outcome}: revocations by principal or by
	// cert, applied, partial (the mark in force, a later step failed) or
	// lifted (spec §5.1.4).
	Revocations *prometheus.CounterVec
	// port49_revocations_in_force{by}: marks standing now.
	RevocationsInForce *prometheus.GaugeVec
	// port49_revocations_file_failed: 1 while the last write of
	// broker.revocations_file failed, so a restart would forget a mark.
	RevocationsFileFailed prometheus.Gauge
	// port49_policy_reloads_total{outcome}: attempts to put a changed policy
	// file in force (plan 4b) — "applied", "unchanged" (a SIGHUP with nothing
	// new), or "refused" (the file does not load; the policy in force keeps
	// serving). The watch counts a refused file once per distinct content,
	// however many times it reads it; each SIGHUP is an attempt of its own.
	PolicyReloads *prometheus.CounterVec
	// port49_policy_file_refused: 1 while the file on disk is one port49d
	// refused, or one that has changed at every read for six reads running
	// and so never loads, so the policy serving is not the one in the file;
	// 0 once a file loads or the file is put back. It is the alert: an edit
	// someone believes is live, and is not.
	PolicyFileRefused prometheus.Gauge
	// port49_policy_refresh_pending: 1 from a policy swap or a grant's
	// expiry until the settle pass 30s after it completes, and while a pass
	// the store stopped, or that left a context still changing, is owed a
	// retry. While it is 1 a live login context may still hold a policy no
	// longer in force — a withdrawn or expired grant included. It is the alert
	// beside port49_policy_file_refused: an edit that loaded, and has not yet
	// reached every live session.
	PolicyRefreshPending prometheus.Gauge
	// port49_inventory_reloads_total{outcome}: attempts to put a changed
	// inventory_file in force (plan 6a) — "applied", "unchanged" (the same
	// devices, respelled), or "refused" (it could not be read behind the
	// fence, did not parse, repeated a name or an address, was empty,
	// admitted no device, or took more than max_removed_percent out of
	// service; the bundle in force keeps serving). The watch counts a refused
	// file once per distinct content.
	InventoryReloads *prometheus.CounterVec
	// port49_inventory_file_refused: 1 while inventory_file on disk is one
	// port49d refused, or one that has changed at every read for six reads
	// running; 0 once a file loads or the file in force is put back.
	InventoryFileRefused prometheus.Gauge
	// port49_inventory_snapshot_age_seconds: how long since the inventory
	// snapshot in force was last confirmed or loaded (spec §10) — inventory_file
	// read and found in force, or the service confirming its document; a start
	// from a copy counts from its published_at. NaN while a cold start has no
	// snapshot yet, which a comparison never matches, so the staleness alert is
	// `port49_inventory_snapshot_age_seconds > N or
	// port49_inventory_snapshot_age_seconds != port49_inventory_snapshot_age_seconds`
	// (NaN is the one value not equal to itself). Staleness is an alarm, never
	// a fail-closed: the snapshot never expires.
	InventorySnapshotAge prometheus.GaugeFunc
	// port49_inventory_changes_total{kind}: security-relevant changes a bundle
	// swap made (spec §10) — "address_added" (an address on a device already
	// in inventory, which a mint hands to an SSH client), "scope_joined" and
	// "scope_left" (a scope with security_log: true), "key_ref_changed" (a
	// device moved onto another key), "admission_changed" (a device already
	// in inventory newly admitted) and "device_added" (a device added and
	// admitted). Each is an inventory_change record naming the device; the
	// label is the kind only.
	InventoryChanges *prometheus.CounterVec
	// port49_inventory_bundle_sequence: the inventory service's sequence of
	// the document in force; 0 with inventory_file.
	InventoryBundleSequence prometheus.Gauge
	// port49_inventory_persist_failed: 1 while the document in force could
	// not be written to inventory.service.state_dir, so a restart with the
	// service down would start from an older copy, or none.
	InventoryPersistFailed prometheus.Gauge
	// port49_inventory_bundle_refused: 1 while a document port49d was given
	// — a copy at cold start, or one the service sent — did not open or was
	// refused; the bundle in force keeps serving. The first document from the
	// service applied or confirmed in force clears it.
	InventoryBundleRefused prometheus.Gauge
	// port49_inventory_policy_mismatch: 1 while the inventory service built
	// the document in force against a policy other than the one in force.
	// The service's policy is never applied: its inventory is loaded against
	// port49d's own (spec §13, decision 29). A rollout holds it briefly.
	InventoryPolicyMismatch prometheus.Gauge
	// port49_inventory_mirror_unreadable: 1 when the start could not read
	// inventory.service.mirror_dir's copy — it did not answer within the
	// deadline, or the read failed — as against a copy it read and refused
	// (port49_inventory_bundle_refused). Only a start reads the mirror, so it
	// holds until the next start.
	InventoryMirrorUnreadable prometheus.Gauge
	// port49_inventory_fetches_total{outcome}: each time port49d asked the
	// inventory service — "unchanged" (the service confirmed the document in
	// force), "refused" (it confirmed a document port49d refused, which
	// port49_inventory_bundle_refused alarms), "received" (a document that
	// opened under the verify keys), "invalid" (a document that did not) and
	// "failed" (the service did not answer).
	InventoryFetches *prometheus.CounterVec
	inventoryAge     atomic.Pointer[func() float64]
	keys             atomic.Pointer[keyWatch]
}

// KeySample is one key version at a scrape: how many devices' latest
// validated connection used it, and when it retires (zero: never).
type KeySample struct {
	KeyRef   string
	Version  int
	Devices  int
	RetireAt time.Time
}

type keyWatch struct {
	sample func() []KeySample
	now    func() time.Time
}

// keyCollector reports port49_key_version_devices{key_ref,version} and
// port49_key_retirement_seconds{key_ref,version} at each scrape (spec §10:
// "alarm severity escalates as retire_after approaches while devices still
// present the version"). Labels are the key_ref and the version only; the
// devices are named by `port49 keys status`.
type keyCollector struct {
	m                *Metrics
	devices, retires *prometheus.Desc
}

func (k keyCollector) Describe(ch chan<- *prometheus.Desc) { ch <- k.devices; ch <- k.retires }

func (k keyCollector) Collect(ch chan<- prometheus.Metric) {
	w := k.m.keys.Load()
	if w == nil {
		return
	}
	now := w.now()
	for _, s := range w.sample() {
		v := strconv.Itoa(s.Version)
		ch <- prometheus.MustNewConstMetric(k.devices, prometheus.GaugeValue, float64(s.Devices), s.KeyRef, v)
		if !s.RetireAt.IsZero() {
			ch <- prometheus.MustNewConstMetric(k.retires, prometheus.GaugeValue, s.RetireAt.Sub(now).Seconds(), s.KeyRef, v)
		}
	}
}

// WatchKeys sets what the key series report at each scrape.
func (m *Metrics) WatchKeys(sample func() []KeySample, now func() time.Time) {
	m.keys.Store(&keyWatch{sample: sample, now: now})
}

// WatchInventoryAge sets what port49_inventory_snapshot_age_seconds reports.
func (m *Metrics) WatchInventoryAge(age func() float64) { m.inventoryAge.Store(&age) }

// CountQuarantined sets what port49_devices_quarantined reports at each scrape.
func (m *Metrics) CountQuarantined(count func() int) { m.quarantined.Store(&count) }

// CountAdmissionRefused sets what port49_devices_admission_refused reports.
func (m *Metrics) CountAdmissionRefused(count func() int) { m.admissionRefused.Store(&count) }

func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		Requests: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_requests_total",
			Help: "TACACS+ exchanges handled, by exchange type and outcome."}, []string{"exchange", "outcome"}),
		Latency: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "port49_request_seconds",
			Help: "Exchange handling latency.", Buckets: []float64{.0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1}}, []string{"exchange"}),
		Decisions: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_decisions_total",
			Help: "Decision records by event, verdict, and reason (same vocabulary as the log)."}, []string{"event", "verdict", "reason"}),
		Unvalidated: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_unvalidated_packets_total",
			Help: "Packets no accepted key validated, by diagnosis."}, []string{"diagnosis"}),
		KeyValidations: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_key_validations_total",
			Help: "Key trial outcomes by key_ref and version."}, []string{"key_ref", "version", "outcome"}),
		Connections: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "port49_connections",
			Help: "Connections by state."}, []string{"state"}),
		ConnectionEvents: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_connection_events_total",
			Help: "Connection lifecycle events by kind."}, []string{"event"}),
		AuthFailures: prometheus.NewCounter(prometheus.CounterOpts{Name: "port49_authentication_failures_total",
			Help: "Authentication failures from admitted devices."}),
		SpoolDepth: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_accounting_spool_depth",
			Help: "Accounting records waiting for the sink."}),
		SpoolDrops: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_accounting_spool_drops_total",
			Help: "Accounting records discarded by the spool, by the stage that discarded them."}, []string{"stage"}),
		SpoolQuarantines: prometheus.NewCounter(prometheus.CounterOpts{Name: "port49_accounting_spool_quarantines_total",
			Help: "Unreadable spool files renamed aside for an operator."}),
		StoreOps: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_store_operations_total",
			Help: "Store operations by op and outcome."}, []string{"op", "outcome"}),
		// A decision record the sink refused is a record that does not exist:
		// the device was still answered, so without this counter the log is
		// silently short and nothing says so (design §11). It counts refused
		// writes, not lost records: the accounting spool keeps a refused
		// record and writes it again once a second, each attempt counted, so
		// a climb with spool depth steady or rising is records held, not
		// records lost (acct.sinkRetryInterval).
		DecisionLogWriteFailures: prometheus.NewCounter(prometheus.CounterOpts{Name: "port49_decision_log_write_failures_total",
			Help: "Writes the decision log sink refused. A record the accounting spool retries counts once per attempt."}),
		CryptOpenFailures: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_crypt_open_failures_total",
			Help: "Stored records that would not decrypt, by record kind."}, []string{"record"}),
		Attributions: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_accounting_attributions_total",
			Help: "Accounting records accepted, by attribution."}, []string{"attribution"}),
		BrokerItemErrors: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_broker_item_errors_total",
			Help: "Mint items the broker could not decide, by API error code."}, []string{"error"}),
		BrokerIdempotency: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_broker_idempotency_refusals_total",
			Help: "Mint requests refused whole at their Idempotency-Key, by outcome."}, []string{"outcome"}),
		BrokerHandshakeFailures: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_broker_tls_handshake_failures_total",
			Help: "TLS handshakes the broker's listener did not complete, by reason."}, []string{"reason"}),
		BrokerConnectionEvents: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_broker_connection_events_total",
			Help: "Broker connections refused at accept or closed by the broker, by event."}, []string{"event"}),
		BrokerConnections: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "port49_broker_connections",
			Help: "Broker connections open now: pending (not yet bound to a principal) and held."}, []string{"state"}),
		BlobCache: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_blob_cache_lookups_total",
			Help: "Compiled-blob cache lookups by the authorizer, by outcome."}, []string{"outcome"}),
		ContextRefreshes: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_context_refreshes_total",
			Help: "Live login contexts a policy refresh visited, by outcome."}, []string{"outcome"}),
		TokensSuperseded: prometheus.NewCounter(prometheus.CounterOpts{Name: "port49_tokens_superseded_total",
			Help: "(device, username) keys whose unspent tokens a policy change deleted."}),
		CeilingWarnings: prometheus.NewCounter(prometheus.CounterOpts{Name: "port49_ceiling_warnings_total",
			Help: "Permitted authorization replies that carried the session ceiling warning."}),
		Revocations: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_revocations_total",
			Help: "Revocations by principal or certificate, by outcome."}, []string{"by", "outcome"}),
		RevocationsInForce: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "port49_revocations_in_force",
			Help: "Revocation marks in force now."}, []string{"by"}),
		RevocationsFileFailed: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_revocations_file_failed",
			Help: "1 while broker.revocations_file could not be written; a restart would forget a revocation."}),
		PolicyReloads: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_policy_reloads_total",
			Help: "Attempts to put a changed policy file in force, by outcome."}, []string{"outcome"}),
		PolicyFileRefused: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_policy_file_refused",
			Help: "1 while the policy file on disk is one port49d refused, or has not stopped changing, and an older policy is serving."}),
		PolicyRefreshPending: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_policy_refresh_pending",
			Help: "1 from a policy swap or grant expiry until its settle pass has carried it into every live login context."}),
		InventoryReloads: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_inventory_reloads_total",
			Help: "Attempts to put a changed inventory file in force, by outcome."}, []string{"outcome"}),
		InventoryFileRefused: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_file_refused",
			Help: "1 while the inventory file on disk is one port49d refused, or has not stopped changing."}),
		InventoryChanges: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_inventory_changes_total",
			Help: "Security-relevant changes a bundle swap made, by kind."}, []string{"kind"}),
		InventoryBundleSequence: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_bundle_sequence",
			Help: "The inventory service's sequence of the document in force; 0 with inventory_file."}),
		InventoryPersistFailed: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_persist_failed",
			Help: "1 while the document in force could not be written to inventory.service.state_dir."}),
		InventoryBundleRefused: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_bundle_refused",
			Help: "1 while a document port49d was given did not open or was refused; the bundle in force keeps serving."}),
		InventoryPolicyMismatch: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_policy_mismatch",
			Help: "1 while the inventory service built the document in force against a policy other than the one in force."}),
		InventoryMirrorUnreadable: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_mirror_unreadable",
			Help: "1 when the start could not read mirror_dir's copy: it hung past the deadline, or the read failed; " +
				"it holds until the next start."}),
		InventoryFetches: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_inventory_fetches_total",
			Help: "Asks of the inventory service, by outcome: unchanged, refused (the service confirmed a document " +
				"port49d refused), received, invalid or failed."},
			[]string{"outcome"}),
	}
	m.InventorySnapshotAge = prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "port49_inventory_snapshot_age_seconds",
		Help: "Seconds since the inventory snapshot in force was last confirmed or loaded; NaN while there is none, " +
			"so alert on port49_inventory_snapshot_age_seconds > N or " +
			"port49_inventory_snapshot_age_seconds != port49_inventory_snapshot_age_seconds."}, func() float64 {
		if age := m.inventoryAge.Load(); age != nil {
			return (*age)()
		}
		return 0
	})
	m.DevicesQuarantined = prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "port49_devices_quarantined",
		Help: "Inventory devices the loaded policy quarantines now."}, func() float64 {
		if count := m.quarantined.Load(); count != nil {
			return float64((*count)())
		}
		return 0
	})
	m.DevicesAdmissionRefused = prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "port49_devices_admission_refused",
		Help: "Inventory devices the bundle in force refuses admission."}, func() float64 {
		if count := m.admissionRefused.Load(); count != nil {
			return float64((*count)())
		}
		return 0
	})
	reg.MustRegister(m.Requests, m.Latency, m.Decisions, m.Unvalidated, m.KeyValidations,
		m.Connections, m.ConnectionEvents, m.AuthFailures, m.SpoolDepth, m.SpoolDrops, m.SpoolQuarantines,
		m.StoreOps, m.DecisionLogWriteFailures, m.CryptOpenFailures, m.Attributions, m.BrokerItemErrors, m.BrokerIdempotency,
		m.BrokerHandshakeFailures, m.BrokerConnectionEvents, m.BrokerConnections, m.BlobCache,
		m.DevicesQuarantined, m.DevicesAdmissionRefused, m.ContextRefreshes, m.TokensSuperseded, m.CeilingWarnings,
		m.Revocations, m.RevocationsInForce, m.RevocationsFileFailed, m.PolicyReloads, m.PolicyFileRefused,
		m.PolicyRefreshPending, m.InventoryReloads, m.InventoryFileRefused, m.InventorySnapshotAge,
		m.InventoryChanges, m.InventoryBundleSequence, m.InventoryPersistFailed, m.InventoryBundleRefused,
		m.InventoryPolicyMismatch, m.InventoryMirrorUnreadable, m.InventoryFetches)
	// process_start_time_seconds among them: an alert on
	// port49_key_version_devices gates on uptime, because the count starts
	// at 0 with every restart (spec §10). No labels.
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	reg.MustRegister(keyCollector{m: m,
		devices: prometheus.NewDesc("port49_key_version_devices",
			"Devices whose latest validated connection since start used this key version.", []string{"key_ref", "version"}, nil),
		retires: prometheus.NewDesc("port49_key_retirement_seconds",
			"Seconds until a key version's retire_after passes; negative once it has.", []string{"key_ref", "version"}, nil)})
	return m
}
