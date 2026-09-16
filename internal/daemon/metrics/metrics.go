// Package metrics defines every daemon metric in one place (design §15). Labels
// are bounded by construction; device identity never appears here.
package metrics

import "github.com/prometheus/client_golang/prometheus"

type Metrics struct {
	Requests         *prometheus.CounterVec   // port49_requests_total{exchange, outcome}
	Latency          *prometheus.HistogramVec // port49_request_seconds{exchange}
	Decisions        *prometheus.CounterVec   // port49_decisions_total{event, verdict, reason}
	Unvalidated      *prometheus.CounterVec   // port49_unvalidated_packets_total{diagnosis}
	KeyValidations   *prometheus.CounterVec   // port49_key_validations_total{key_ref, version, outcome}
	Connections      *prometheus.GaugeVec     // port49_connections{state="open"}
	ConnectionEvents *prometheus.CounterVec   // port49_connection_events_total{event="refused_cap"|"idle_closed"|"malformed_backoff"}
	AuthFailures     prometheus.Counter       // port49_authentication_failures_total
	SpoolDepth       prometheus.Gauge         // port49_accounting_spool_depth
	SpoolDrops       prometheus.Counter       // port49_accounting_spool_drops_total
	StoreOps         *prometheus.CounterVec   // port49_store_operations_total{op, outcome}
}

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
		SpoolDrops: prometheus.NewCounter(prometheus.CounterOpts{Name: "port49_accounting_spool_drops_total",
			Help: "Accounting records discarded by the spool."}),
		StoreOps: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_store_operations_total",
			Help: "Store operations by op and outcome."}, []string{"op", "outcome"}),
	}
	reg.MustRegister(m.Requests, m.Latency, m.Decisions, m.Unvalidated, m.KeyValidations,
		m.Connections, m.ConnectionEvents, m.AuthFailures, m.SpoolDepth, m.SpoolDrops, m.StoreOps)
	return m
}
