package inventory

import "github.com/prometheus/client_golang/prometheus"

// Metrics is what the service exports on metrics_listen. No label names a
// device; source names are configuration, not device identity.
type Metrics struct {
	// Syncs counts syncs by trigger (startup, schedule, api, signal) and
	// outcome (published, unchanged, refused, failed).
	Syncs *prometheus.CounterVec
	// SyncRefused is 1 while the last sync was refused — over a bound,
	// empty, admitting none, a device in two sources — and the bundle
	// published is older than the sources: the alarm for a mistyped filter.
	SyncRefused prometheus.Gauge
	// SyncFailing is 1 while the last sync failed: a source, the policy
	// file or the state directory did not answer.
	SyncFailing  prometheus.Gauge
	SourceErrors *prometheus.CounterVec
	// LeftOut is how many devices the last sync left out for a name or text
	// that could not reach a line safely (Decided 10).
	LeftOut     prometheus.Gauge
	Published   prometheus.Gauge
	PublishedAt prometheus.Gauge
	Devices     prometheus.Gauge
	// LastGood is when a sync last ended published or unchanged: alert on
	// time() minus it, beside SyncRefused and SyncFailing.
	LastGood       prometheus.Gauge
	MirrorFailures prometheus.Counter
	// MirrorBehind is 1 while the mirror's copy differs from the bundle
	// published: a fresh pod with the service down would start from it.
	MirrorBehind prometheus.Gauge
	APIRefused   *prometheus.CounterVec
	// SourceHung is 1 while a source's fetch, abandoned past sync_timeout,
	// has not returned (spec §10): that source is not asked meanwhile.
	SourceHung *prometheus.GaugeVec
	// GenericDevices is how many devices the last good sync's bundle serves
	// with the generic adapter (spec §8, "Unknown platforms").
	GenericDevices prometheus.Gauge
	// Webhooks counts deliveries on webhook_listen, by source (configuration;
	// "" when the path names none) and outcome (accepted, duplicate, stale,
	// bad_signature, unsigned, too_large, bad_body, bad_content_type,
	// unknown_source, bad_path; tls_handshake, source "", from the server's
	// error log).
	Webhooks *prometheus.CounterVec
}

func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		Syncs: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_inventory_syncs_total",
			Help: "Syncs, by trigger and outcome."}, []string{"trigger", "outcome"}),
		SyncRefused: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_sync_refused",
			Help: "1 while the last sync was refused and an older bundle is published."}),
		SyncFailing: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_sync_failing",
			Help: "1 while the last sync failed: a source, the policy file or the state directory did not answer."}),
		SourceErrors: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_inventory_source_errors_total",
			Help: "Fetches a source did not answer, by source."}, []string{"source"}),
		LeftOut: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_devices_left_out",
			Help: "Devices the last sync left out: a name or text that cannot reach a line safely."}),
		Published: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_published_sequence",
			Help: "The sequence of the bundle published."}),
		PublishedAt: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_published_timestamp_seconds",
			Help: "When the bundle published was published."}),
		Devices: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_devices",
			Help: "Devices in the bundle published."}),
		LastGood: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_last_good_sync_timestamp_seconds",
			Help: "When a sync last ended published or unchanged."}),
		MirrorFailures: prometheus.NewCounter(prometheus.CounterOpts{Name: "port49_inventory_mirror_write_failures_total",
			Help: "Writes of the mirror's copy that failed."}),
		MirrorBehind: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_mirror_behind",
			Help: "1 while the mirror's copy differs from the bundle published."}),
		APIRefused: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_inventory_api_refused_total",
			Help: "API requests refused, by reason (untrusted, forbidden, bad_path)."}, []string{"reason"}),
	}
	m.SourceHung = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "port49_inventory_source_hung",
		Help: "1 while a source's fetch, abandoned past sync_timeout, has not returned."}, []string{"source"})
	m.GenericDevices = prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_generic_platform_devices",
		Help: "Devices in the last good sync whose platform has no adapter in the policy."})
	m.Webhooks = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_inventory_webhooks_total",
		Help: "Webhook deliveries, by source and outcome."}, []string{"source", "outcome"})
	reg.MustRegister(m.Syncs, m.SyncRefused, m.SyncFailing, m.SourceErrors, m.LeftOut, m.Published, m.PublishedAt,
		m.Devices, m.LastGood, m.MirrorFailures, m.MirrorBehind, m.APIRefused, m.SourceHung, m.GenericDevices,
		m.Webhooks)
	return m
}
