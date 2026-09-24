// Package metrics defines every daemon metric in one place (design §15). Labels
// are bounded by construction; device identity never appears here.
package metrics

import (
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
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
	// (a strike from an address not in the inventory), "panic" (a connection
	// recovered from a panic), and "accept_error" (Accept failed and the
	// listener is being retried).
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
	// "attribute_unsafe" (one they would fill with `=`, `*` or a control
	// character). None is a decision, so none is in port49_decisions_total.
	// The label is the code only.
	BrokerItemErrors *prometheus.CounterVec
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
}

// CountQuarantined sets what port49_devices_quarantined reports at each scrape.
func (m *Metrics) CountQuarantined(count func() int) { m.quarantined.Store(&count) }

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
		BlobCache: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_blob_cache_lookups_total",
			Help: "Compiled-blob cache lookups by the authorizer, by outcome."}, []string{"outcome"}),
	}
	m.DevicesQuarantined = prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "port49_devices_quarantined",
		Help: "Inventory devices the loaded policy quarantines now."}, func() float64 {
		if count := m.quarantined.Load(); count != nil {
			return float64((*count)())
		}
		return 0
	})
	reg.MustRegister(m.Requests, m.Latency, m.Decisions, m.Unvalidated, m.KeyValidations,
		m.Connections, m.ConnectionEvents, m.AuthFailures, m.SpoolDepth, m.SpoolDrops, m.SpoolQuarantines,
		m.StoreOps, m.DecisionLogWriteFailures, m.CryptOpenFailures, m.Attributions, m.BrokerItemErrors, m.BlobCache,
		m.DevicesQuarantined)
	return m
}
