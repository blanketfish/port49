// Package metrics defines every daemon metric in one place (design §15). Labels
// are bounded by construction; device identity never appears here.
package metrics

import (
	"strconv"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/rhwendt/port49/internal/store/guard"
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
	SpoolQuarantines prometheus.Counter
	StoreOps         *prometheus.CounterVec
	// StoreCalls, StoreCallSeconds and StoreCircuitOpen are the guard's
	// (internal/store/guard; plan 7d): every store call by component
	// (daemon, broker), pool (token, context, bulk) and outcome (ok,
	// not_found, conflict, error, timeout, deadline, unavailable, refused,
	// canceled, saturated, circuit_open); how long they took; and whether
	// each pool's circuit is open, design §15's circuit-breaker state. The
	// gauge moves only when a call ends, so a pool no one calls keeps the
	// value of its last call, open included, and never goes dark on it:
	// harmless, since it serves no one (re-check R-M5).
	StoreCalls               *prometheus.CounterVec
	StoreCallSeconds         *prometheus.HistogramVec
	StoreCircuitOpen         *prometheus.GaugeVec
	DecisionLogWriteFailures prometheus.Counter // port49_decision_log_write_failures_total
	// port49_crypt_open_failures_total{record}. A record that will not open is a
	// key problem, not a missing record, and it is the one failure mode of the
	// rotation window that has no other symptom. Labels are the record kind only —
	// "token", "receipt", "context", "idempotency" — never a device or a user.
	CryptOpenFailures *prometheus.CounterVec
	// port49_store_index_records_undecodable_total: an etcd index record (x/)
	// that would not decode, each time a walk skipped it (the refresh's
	// active principals, the sweep), a lookup took its ref without reading
	// it (plan 7d Task 7), or the re-index scan, a login or an index write
	// met it, the last two writing it whole again (Task 7b). It also counts
	// a lookup or token-index entry whose key does not parse, each time a
	// lookup skipped it or the sweep deleted it (final review I-1). Only a
	// store writer makes either. No labels:
	// its key, which names a device, is in the log line beside it.
	IndexRecordsUndecodable prometheus.Counter
	// StoreKeyspaceHeld is 1 while this port49d holds its keyspace on etcd
	// (plan 7d): 0 while it waits for another or for the store, and alarmed
	// when port49d runs with it 0.
	StoreKeyspaceHeld prometheus.Gauge
	// StoreFeedUp is 1 while a feed's watch runs (plan 7e): feed is
	// "contexts" or "marks". 0 for longer than hold_ttl is an alarm: this
	// process's ledger or marks are not following the store.
	StoreFeedUp *prometheus.GaugeVec
	// StoreFeedRescans counts a feed's rescans after a compacted watch.
	StoreFeedRescans *prometheus.CounterVec
	// StoreFenceTimeouts counts context reads denied because this
	// process's context feed had not delivered the record's revision by the
	// read's deadline (the feed fence): with port49_store_feed_up 1 and
	// etcd answering, a rising count is a feed lagging, not a store down.
	StoreFenceTimeouts prometheus.Counter
	// StoreHealthChecks counts port49d's store health checks by outcome
	// (pass, fail; plan 7f), and StoreHealthFailures is the failed checks
	// in a row now: at store.etcd.health.close_after the listeners close.
	// The count is the process's (healthState): each run's registry is set
	// from it, and it reads at least close_after while the listeners are
	// closed after a store gone.
	StoreHealthChecks   *prometheus.CounterVec
	StoreHealthFailures prometheus.Gauge
	// ContextCacheLookups counts the context cache's reads by outcome
	// (hit, miss, stale; plan 7f): any increase of stale is a replica
	// answering from contexts the store did not confirm.
	ContextCacheLookups *prometheus.CounterVec
	ContextCacheEntries prometheus.Gauge
	// LedgerPending is how many context keys' marks the ledger record does
	// not yet hold (plan 7e, Ruling 4). Above 0 for a minute is an alarm:
	// a context put back at one would be taken after a restart.
	LedgerPending prometheus.Gauge
	// LedgerBehind is 1 while the ledger record's keeper runs with its
	// context feed down: the record does not follow other processes'
	// logins, whatever LedgerPending says (pre-flight I11).
	LedgerBehind prometheus.Gauge
	// CryptStoreKeyUnknown is 1 when port49d started on a store last written
	// under a current key its encryption window does not hold (plan 7d):
	// records sealed under it will not open.
	CryptStoreKeyUnknown prometheus.Gauge
	// StoreCertExpiry is each component's etcd client certificate's
	// NotAfter, in Unix seconds (plan 7d; pre-flight I9), as
	// port49_crl_next_update_timestamp_seconds is: an alert subtracts now.
	// Its one label is the component, daemon or broker.
	StoreCertExpiry *prometheus.GaugeVec
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
	// principal is marked, or its certificate is revoked at its CA),
	// status_unavailable_refused (answered 503 certificate_status_unavailable
	// and closed at bind: its certificate status could not be established).
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
	// is left as it was), or "failed" (a context that failed authentication,
	// or a policy in force that could not be resolved or compiled for it —
	// both revoked, failing closed — or a context sealed under a key this
	// port49d does not hold, left unrevoked, or a context still changing after every
	// compare-and-set attempt, left for the retry, or a principal whose
	// contexts could not be looked up, counted once and left for the next
	// pass; the process log says which).
	// A context the refresh skipped — another principal's since, the lab's,
	// already revoked — is not counted. The label is the outcome only.
	ContextRefreshes *prometheus.CounterVec
	// ContextsReindexed counts live contexts found missing from the index
	// and re-indexed, or revoked when they would not open (plan 7d;
	// re-check IA2). Any increase is an index record deleted or rewritten in
	// the store.
	ContextsReindexed prometheus.Counter
	// ContextsReindexFailures counts contexts the re-index could not
	// re-index or judge, each left for its next pass, one sealed under a key
	// this port49d does not hold among them; the process log names the
	// device and username (plan 7d; re-check I3; final review I-2). No labels.
	ContextsReindexFailures prometheus.Counter
	// port49_session_refreshes_total{outcome}: session refreshes (spec §5.6;
	// decision 33). Per context a refresh visited: "extended", "revoked" (the
	// policy in force withdrew it, or the context could not be judged and was
	// revoked failing closed), "past_grace" (deleted, its grace window
	// over) or "not_judged" (the policy did not just judge and keep it: a
	// quarantined device, a write that lost every race). Per refresh:
	// "refused" (no live challenge, a bad signature, a mark), "store_error"
	// or "too_soon" (paced, refresh_too_soon). The label is the outcome only.
	SessionRefreshes *prometheus.CounterVec
	// port49_tokens_superseded_total: (device, username) keys whose unspent
	// tokens a policy change deleted, because the policy now in force would
	// not mint what they carry. Each is one operator's `port49 token` to run
	// again; none is a session ended.
	TokensSuperseded prometheus.Counter
	// port49_ceiling_warnings_total: permitted authorization replies that
	// carried the session ceiling warning in server_msg (spec §5.6; decision
	// 33). No labels.
	CeilingWarnings prometheus.Counter
	// port49_revocations_total{by, outcome}: revocations by what they named,
	// principal or cert (a standing mark), self (a principal ending its own
	// sessions) or key (one (device, username) ended), and outcome: applied,
	// partial (a later step failed) or lifted (spec §5.1.4; decision 34).
	Revocations *prometheus.CounterVec
	// port49_revocations_in_force{by}: marks standing now.
	RevocationsInForce *prometheus.GaugeVec
	// port49_revocations_file_failed: 1 while the last write of
	// broker.revocations_file failed, so a restart would forget a mark.
	RevocationsFileFailed prometheus.Gauge
	// port49_cert_status_checks_total{source, result}: broker certificate
	// status checks of a chain, by the source that decided ("crl", "ocsp" or
	// "none") and the verdict ("good", "revoked" or "unknown") (spec §5.1.4).
	CertStatusChecks *prometheus.CounterVec
	// port49_crl_loads_total{crl, outcome}: loads of a configured CRL source
	// by its name: "loaded", "unchanged", "failed" (it could not be fetched)
	// or "refused" (it did not verify, is out of scope, or is older than the
	// list in force).
	CRLLoads *prometheus.CounterVec
	// port49_crl_next_update_timestamp_seconds{crl}: the Unix time the list
	// in force passes its next update, set after every load; alert on
	// time() - port49_crl_next_update_timestamp_seconds > 0.
	CRLNextUpdate *prometheus.GaugeVec
	// port49_cert_status_unavailable_total: checks whose status could not be
	// established. No labels.
	CertStatusUnavailable prometheus.Counter
	// WorkloadRenewalLate is port49_workload_certificates_renewal_late_total:
	// each workload certificate seen with under a quarter of its validity
	// left, once per 24h per certificate on each broker replica (plan 8;
	// decision 40 ruling 9). No label: a certificate is a workload's identity.
	WorkloadRenewalLate prometheus.Counter
	// port49_certificates_issued_total{outcome}: POST /v1/certificate by
	// outcome: issued, refused, unavailable (the issuing CA not usable)
	// (plan 9b; spec §13 decision 43 ruling 22). No principal.
	CertificatesIssued *prometheus.CounterVec
	// port49_issuing_ca_not_after_timestamp_seconds: the Unix time the
	// issuing CA in use expires; 0 when none is loaded. Where issuance is
	// configured, alert on 0, and on it within 90 days.
	IssuingCANotAfter prometheus.Gauge
	// port49_directory_queries_total{server, outcome}: directory queries by
	// server (host:port) and outcome: ok, fault (the server's), error (the
	// query's answer), refused (the dial or bind was refused, no fault).
	DirectoryQueries *prometheus.CounterVec
	// port49_directory_server_up{server}: 1 while the server's breaker is
	// closed.
	DirectoryServerUp *prometheus.GaugeVec
	// port49_directory_selected{server}: 1 for the server queries go to.
	DirectorySelected *prometheus.GaugeVec
	// port49_directory_site_crossings_total: selections that crossed sites,
	// consistency events (design §10). No labels.
	DirectorySiteCrossings prometheus.Counter
	// port49_directory_bind_holdoff_seconds: seconds left in the pool-wide
	// hold-off after a refused bind, 0 when clear. No labels.
	DirectoryBindHoldoff prometheus.GaugeFunc
	directoryBindHoldoff atomic.Pointer[func() float64]
	// port49_directory_walks_truncated_total: nested-group walks that ended
	// at max_depth or the node bound with groups unconfirmed, and so grant
	// none of them. No labels.
	DirectoryWalksTruncated prometheus.Counter
	// port49_directory_group_names_ambiguous: group names dropped from
	// matching because two groups share them, seen in the last hour. No
	// labels.
	DirectoryGroupNamesAmbiguous prometheus.GaugeFunc
	directoryGroupNamesAmbiguous atomic.Pointer[func() float64]
	// port49_directory_lookups_total{outcome}: directory resolutions by
	// outcome: fresh (a server answered), grace (the store's membership,
	// within directory.grace), unavailable (no server and no grace),
	// unmapped, ambiguous, collision (the directory's refusals).
	DirectoryLookups *prometheus.CounterVec
	// port49_directory_prewarm_principals: people and workloads together
	// that the last pre-warm pass verified and stored.
	DirectoryPrewarmPrincipals prometheus.Gauge
	// port49_directory_prewarm_last_success_timestamp_seconds: the Unix time
	// the last pre-warm pass finished, 0 before one has.
	DirectoryPrewarmLastSuccess prometheus.Gauge
	// port49_directory_refresh_last_complete_timestamp_seconds: the Unix
	// time of the last scheduled refresh that verified every principal, 0
	// before one has. No labels: no principal or device.
	DirectoryRefreshLastComplete prometheus.Gauge
	// port49_oidc_keys_last_success_timestamp_seconds{issuer}: the Unix
	// time the keys held were fetched: 0 from the key set's creation until
	// a fetch or a restore, and after a restore the kept set's fetched_at,
	// so a restart during an outage keeps the alert firing (plan 7h,
	// pre-flight I-4). Alert on time() - it > jwks_max_age / 2 or absent(it),
	// with a for: of a few minutes to pass a start's first fetch.
	OIDCKeysLastSuccess *prometheus.GaugeVec
	// port49_oidc_keys_fetch_failures_total{issuer}: discovery or JWKS
	// fetches that failed.
	OIDCKeysFetchFailures *prometheus.CounterVec
	// port49_oidc_tokens_total{issuer, outcome}: OIDC bearer tokens by the
	// configured issuer ("unknown" for any other) and outcome: accepted,
	// invalid, expired, unavailable, unmapped, logged_out (plan 7h).
	OIDCTokens *prometheus.CounterVec
	// port49_oidc_logouts_total{outcome}: back-channel logouts: applied,
	// nothing (a valid logout that reached no context or token), replayed,
	// invalid, unavailable (the provider's keys), store_error, partial
	// (plan 7h).
	OIDCLogouts *prometheus.CounterVec
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
	// port49_policy_bundle_matches_runner: 1 while this broker serves the
	// bundle the runner serves, or this port49d the bundle the runner last
	// judged (plan 7e, Ruling 8; pre-flight I3; re-check R5). 0 on a broker
	// is a replica whose policy file differs: its tokens and the contexts
	// they make carry another policy until it reloads. 0 on a port49d past
	// the runner's settle pass is a policy file that differs from the
	// brokers', for admission, quarantine and redaction. It starts at 1:
	// nothing is known to differ until a read says so.
	PolicyBundleMatchesRunner prometheus.Gauge
	// port49_broker_mint_gate_closed: 1 while this port49-broker waits to
	// mark meta/judged in doubt for a swap, minting nothing under the
	// swapped bundle meanwhile (Task 15a re-review 1, I-2; re-review 3,
	// I-4), and from its start until it has seen a takeover done for the
	// bundle it serves (decision 36, the mint gate at a start). A swap
	// holds it for a store round trip, a first start for hold_ttl/3 and
	// the takeover; 1 for longer than a minute is a store that does not
	// answer, or refuses, the broker's mark, or no runner that judges this
	// replica's bundle. Readiness never shows it (design §12): it is an
	// alarm.
	BrokerMintGateClosed prometheus.Gauge
	// port49_redemption_restore_guarded: 1 while this port49d refuses every
	// token redemption store_unavailable, having found meta/witness below
	// the highest it followed (an etcd restore; plan 7e, Task 15d), until
	// a broker runner's purge is done; 1 too from a run's start after a
	// store gone until its first read of the witness.
	RedemptionRestoreGuarded prometheus.Gauge
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

// SetDirectoryBindHoldoff sets what port49_directory_bind_holdoff_seconds reports.
func (m *Metrics) SetDirectoryBindHoldoff(remaining func() float64) {
	m.directoryBindHoldoff.Store(&remaining)
}

// SetDirectoryGroupNamesAmbiguous sets what port49_directory_group_names_ambiguous reports.
func (m *Metrics) SetDirectoryGroupNamesAmbiguous(count func() float64) {
	m.directoryGroupNamesAmbiguous.Store(&count)
}

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
		StoreCalls: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_store_calls_total",
			Help: "Store calls through the guard, by component, pool and outcome."}, []string{"component", "pool", "outcome"}),
		StoreCallSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "port49_store_call_seconds",
			Help:    "Store call latency through the guard, by component and pool.",
			Buckets: []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30}}, []string{"component", "pool"}),
		StoreCircuitOpen: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "port49_store_circuit_open",
			Help: "1 while a pool's circuit is open: its calls fail at once until a probe succeeds."}, []string{"component", "pool"}),
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
		IndexRecordsUndecodable: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "port49_store_index_records_undecodable_total",
			Help: "etcd index records that would not decode, or index entries whose key would not parse, each time one was skipped, taken unread, written over, or deleted."}),
		StoreKeyspaceHeld: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_store_keyspace_held",
			Help: "1 while this port49d holds its keyspace on etcd."}),
		StoreFeedUp: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "port49_store_feed_up",
			Help: "1 while a feed's watch on the store runs, by feed (contexts or marks)."}, []string{"feed"}),
		StoreFeedRescans: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_store_feed_rescans_total",
			Help: "Rescans of the store after a feed's watch was compacted, by feed."}, []string{"feed"}),
		StoreFenceTimeouts: prometheus.NewCounter(prometheus.CounterOpts{Name: "port49_store_fence_timeouts_total",
			Help: "Context reads and store health checks denied because this process's context feed had not delivered the record's revision by the deadline."}),
		StoreHealthChecks: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_store_health_checks_total",
			Help: "port49d's store health checks, by outcome (pass, fail)."}, []string{"outcome"}),
		StoreHealthFailures: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_store_health_failures",
			Help: "port49d's failed store health checks in a row; at store.etcd.health.close_after every listener closes."}),
		ContextCacheLookups: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_context_cache_lookups_total",
			Help: "The context cache's reads by outcome: hit, miss, stale (served past its ttl because the store failed)."},
			[]string{"outcome"}),
		ContextCacheEntries: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_context_cache_entries",
			Help: "Login contexts the context cache holds."}),
		LedgerPending: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_ledger_pending",
			Help: "Context keys whose mark the ledger record does not yet hold; above 0 for a minute, a context put back at one would be taken after a restart."}),
		LedgerBehind: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_ledger_behind",
			Help: "1 while the ledger record's keeper runs with its context feed down: the record does not follow other processes' logins, whatever port49_ledger_pending says."}),
		CryptStoreKeyUnknown: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_crypt_store_key_unknown",
			Help: "1 when port49d started on a store last written under a current key its encryption window does not hold."}),
		StoreCertExpiry: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "port49_store_client_cert_expiry_timestamp_seconds",
			Help: "When each component's etcd client certificate expires, in Unix seconds."}, []string{"component"}),
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
		ContextsReindexed: prometheus.NewCounter(prometheus.CounterOpts{Name: "port49_contexts_reindexed_total",
			Help: "Live login contexts found missing from the index and re-indexed, or revoked when they would not open."}),
		ContextsReindexFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "port49_contexts_reindex_failures_total",
			Help: "Live login contexts the re-index could not re-index or judge, each left for its next pass."}),
		SessionRefreshes: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_session_refreshes_total",
			Help: "Session refreshes: per context extended, revoked, past_grace or not_judged; per refresh refused, " +
				"store_error or too_soon."}, []string{"outcome"}),
		TokensSuperseded: prometheus.NewCounter(prometheus.CounterOpts{Name: "port49_tokens_superseded_total",
			Help: "(device, username) keys whose unspent tokens a policy change deleted."}),
		CeilingWarnings: prometheus.NewCounter(prometheus.CounterOpts{Name: "port49_ceiling_warnings_total",
			Help: "Permitted authorization replies that carried the session ceiling warning."}),
		Revocations: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_revocations_total",
			Help: "Revocations by what they named (principal, cert, self, key) and outcome."}, []string{"by", "outcome"}),
		RevocationsInForce: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "port49_revocations_in_force",
			Help: "Revocation marks in force now."}, []string{"by"}),
		RevocationsFileFailed: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_revocations_file_failed",
			Help: "1 while broker.revocations_file could not be written; a restart would forget a revocation."}),
		CertStatusChecks: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_cert_status_checks_total",
			Help: "Broker certificate status checks, by the source that decided and the result."}, []string{"source", "result"}),
		CRLLoads: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_crl_loads_total",
			Help: "Loads of a CRL source, by outcome: loaded, unchanged, failed or refused."}, []string{"crl", "outcome"}),
		CRLNextUpdate: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "port49_crl_next_update_timestamp_seconds",
			Help: "The Unix time the CRL in force passes its next update."}, []string{"crl"}),
		CertStatusUnavailable: prometheus.NewCounter(prometheus.CounterOpts{Name: "port49_cert_status_unavailable_total",
			Help: "Certificate status checks whose status could not be established."}),
		WorkloadRenewalLate: prometheus.NewCounter(prometheus.CounterOpts{Name: "port49_workload_certificates_renewal_late_total",
			Help: "Workload certificates presented with under a quarter of their validity left, once per certificate " +
				"per 24h on this replica; alert on its increase."}),
		CertificatesIssued: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_certificates_issued_total",
			Help: "Sign-ins exchanged for a port49-issued certificate, by outcome: issued, refused, unavailable."},
			[]string{"outcome"}),
		IssuingCANotAfter: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_issuing_ca_not_after_timestamp_seconds",
			Help: "The Unix time the issuing CA in use expires; 0 when none is loaded."}),
		DirectoryQueries: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_directory_queries_total",
			Help: "Directory queries by server (host:port) and outcome: ok, fault (the server's), error (the query's answer), refused (the server refused the dial or bind without a fault)."},
			[]string{"server", "outcome"}),
		DirectoryServerUp: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "port49_directory_server_up",
			Help: "1 while the directory server's breaker is closed."}, []string{"server"}),
		DirectorySelected: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "port49_directory_selected",
			Help: "1 for the directory server queries are sent to (sticky selection)."}, []string{"server"}),
		DirectorySiteCrossings: prometheus.NewCounter(prometheus.CounterOpts{Name: "port49_directory_site_crossings_total",
			Help: "Selections that crossed sites: consistency events, membership read there may lag replication (design §10)."}),
		DirectoryWalksTruncated: prometheus.NewCounter(prometheus.CounterOpts{Name: "port49_directory_walks_truncated_total",
			Help: "Nested-group walks that ended at max_depth or the node bound with groups unconfirmed; those groups are not granted."}),
		DirectoryLookups: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_directory_lookups_total",
			Help: "Directory resolutions by outcome: fresh, grace, unavailable, unmapped, ambiguous, collision."},
			[]string{"outcome"}),
		DirectoryPrewarmPrincipals: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_directory_prewarm_principals",
			Help: "People and workloads together that the last pre-warm pass verified and stored."}),
		DirectoryPrewarmLastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_directory_prewarm_last_success_timestamp_seconds",
			Help: "The Unix time the last pre-warm pass finished; 0 before one has."}),
		DirectoryRefreshLastComplete: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_directory_refresh_last_complete_timestamp_seconds",
			Help: "The Unix time of the last scheduled refresh that verified every principal; 0 before one has."}),
		OIDCKeysLastSuccess: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "port49_oidc_keys_last_success_timestamp_seconds",
			Help: "Unix time the OIDC issuer's held keys were fetched (restored included), 0 before any."}, []string{"issuer"}),
		OIDCKeysFetchFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "port49_oidc_keys_fetch_failures_total",
			Help: "OIDC discovery or JWKS fetches that failed, by configured issuer."}, []string{"issuer"}),
		OIDCTokens: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_oidc_tokens_total",
			Help: "OIDC bearer tokens by configured issuer and outcome: accepted, invalid, expired, unavailable, unmapped, logged_out."},
			[]string{"issuer", "outcome"}),
		OIDCLogouts: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_oidc_logouts_total",
			Help: "OIDC back-channel logouts by outcome: applied, nothing, replayed, invalid, unavailable, store_error, partial."},
			[]string{"outcome"}),
		PolicyReloads: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_policy_reloads_total",
			Help: "Attempts to put a changed policy file in force, by outcome."}, []string{"outcome"}),
		PolicyFileRefused: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_policy_file_refused",
			Help: "1 while the policy file on disk is one port49d refused, or has not stopped changing, and an older policy is serving."}),
		PolicyRefreshPending: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_policy_refresh_pending",
			Help: "1 from a policy swap or grant expiry until its settle pass has carried it into every live login context."}),
		PolicyBundleMatchesRunner: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_policy_bundle_matches_runner",
			Help: "1 while this broker serves the bundle the runner serves, or this port49d the bundle the runner " +
				"last judged; 0 on a broker is a replica whose policy file differs: its tokens and the contexts they " +
				"make carry another policy until it reloads; 0 on a port49d past the runner's settle pass is a " +
				"policy file that differs from the brokers', for admission, quarantine and redaction."}),
		BrokerMintGateClosed: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_broker_mint_gate_closed",
			Help: "1 while this broker waits to mark the bundle last judged in doubt for a swap, minting nothing " +
				"under the swapped bundle, and from its start until it has seen a takeover done for the bundle it " +
				"serves; 1 for longer than a minute is a store that does not answer, or refuses, the mark, or no " +
				"runner that judges this broker's bundle."}),
		RedemptionRestoreGuarded: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_redemption_restore_guarded",
			Help: "1 while this port49d refuses every token redemption, having found the store restored from a " +
				"snapshot, until a broker runner's purge is done."}),
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
	m.DirectoryBindHoldoff = prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "port49_directory_bind_holdoff_seconds",
		Help: "Seconds left in the hold-off after a directory server refused the broker's bind, during which no unbound server is dialled; 0 when clear."}, func() float64 {
		if remaining := m.directoryBindHoldoff.Load(); remaining != nil {
			return (*remaining)()
		}
		return 0
	})
	m.DirectoryGroupNamesAmbiguous = prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "port49_directory_group_names_ambiguous",
		Help: "Group names that match no one because two groups under groups_base_dn share them, seen in the last hour."}, func() float64 {
		if count := m.directoryGroupNamesAmbiguous.Load(); count != nil {
			return (*count)()
		}
		return 0
	})
	reg.MustRegister(m.Requests, m.Latency, m.Decisions, m.Unvalidated, m.KeyValidations,
		m.Connections, m.ConnectionEvents, m.AuthFailures, m.SpoolDepth, m.SpoolDrops, m.SpoolQuarantines,
		m.StoreOps, m.StoreCalls, m.StoreCallSeconds, m.StoreCircuitOpen, m.DecisionLogWriteFailures, m.CryptOpenFailures, m.IndexRecordsUndecodable, m.StoreKeyspaceHeld, m.StoreFeedUp, m.StoreFeedRescans, m.StoreFenceTimeouts, m.StoreHealthChecks, m.StoreHealthFailures, m.ContextCacheLookups, m.ContextCacheEntries, m.LedgerPending, m.LedgerBehind, m.CryptStoreKeyUnknown, m.StoreCertExpiry, m.Attributions, m.BrokerItemErrors, m.BrokerIdempotency,
		m.BrokerHandshakeFailures, m.BrokerConnectionEvents, m.BrokerConnections, m.BlobCache,
		m.DevicesQuarantined, m.DevicesAdmissionRefused, m.ContextRefreshes, m.ContextsReindexed,
		m.ContextsReindexFailures, m.SessionRefreshes, m.TokensSuperseded, m.CeilingWarnings,
		m.Revocations, m.RevocationsInForce, m.RevocationsFileFailed, m.CertStatusChecks, m.CRLLoads, m.CRLNextUpdate,
		m.CertStatusUnavailable, m.DirectoryQueries, m.DirectoryServerUp, m.DirectorySelected, m.DirectorySiteCrossings, m.DirectoryBindHoldoff, m.DirectoryWalksTruncated, m.DirectoryGroupNamesAmbiguous, m.DirectoryLookups, m.DirectoryPrewarmPrincipals, m.DirectoryPrewarmLastSuccess, m.DirectoryRefreshLastComplete, m.OIDCKeysLastSuccess, m.OIDCKeysFetchFailures, m.OIDCTokens, m.OIDCLogouts, m.PolicyReloads, m.PolicyFileRefused,
		m.PolicyRefreshPending, m.PolicyBundleMatchesRunner, m.BrokerMintGateClosed, m.RedemptionRestoreGuarded,
		m.InventoryReloads,
		m.InventoryFileRefused,
		m.InventorySnapshotAge,
		m.InventoryChanges, m.InventoryBundleSequence, m.InventoryPersistFailed, m.InventoryBundleRefused,
		m.InventoryPolicyMismatch, m.InventoryMirrorUnreadable, m.InventoryFetches, m.WorkloadRenewalLate,
		m.CertificatesIssued, m.IssuingCANotAfter)
	// Nothing is known to differ until a read says so: a process with no
	// runner to compare with (memory) reads 1.
	m.PolicyBundleMatchesRunner.Set(1)
	// Every issuance outcome exists at 0 from the first scrape.
	for _, o := range []string{"issued", "refused", "unavailable"} {
		m.CertificatesIssued.WithLabelValues(o)
	}
	// Both outcomes exist at 0 from the first scrape.
	m.StoreHealthChecks.WithLabelValues("pass")
	m.StoreHealthChecks.WithLabelValues("fail")
	for _, o := range []string{"hit", "miss", "stale"} {
		m.ContextCacheLookups.WithLabelValues(o)
	}
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

// StoreGuard is the guard's Metrics over these series.
func (m *Metrics) StoreGuard() guard.Metrics {
	return guard.Metrics{Calls: m.StoreCalls, Seconds: m.StoreCallSeconds, Open: m.StoreCircuitOpen}
}
