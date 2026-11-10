---
title: Monitoring
description: The metrics, alerts and logs that show whether port49 is healthy.
---

# Monitoring

port49 is watched through three things: Prometheus metrics, a shipped set of alert rules, and the
logs. When an alert has fired or a log line worries you, go to the
[3am index](troubleshooting/index.md); this page is what to set up before that.

## Scraping

Every process serves `/metrics` on its `metrics_listen` address. The defaults:

| Process | Port | `job` the alert rules expect |
|---|---|---|
| `port49d` | 9049 | `port49d` |
| `port49-broker` | 9050 | `port49-broker` |

The `job` name is not cosmetic. Three rules read Prometheus's own `up` series by it
(`up{job="port49d"}` and `up{job="port49-broker"}`): `port49_target_down`, `port49_target_absent` and
`port49_broker_target_absent`. Give the jobs these names, or edit the rules.

```yaml
scrape_configs:
  - job_name: port49d
    static_configs:
      - targets: ["<port49d-host>:9049"]
  - job_name: port49-broker
    static_configs:
      - targets: ["<broker-host>:9050"]
```

On Helm, `prometheusRule.enabled: true` renders the rules as a `PrometheusRule`, and a `PodMonitor` for
each workload with `job` set to `port49d` and `port49-broker`.

- It needs the Prometheus Operator's CRDs.
- `prometheusRule.labels` must be the labels your Prometheus selects on. The same labels go on the
  monitors.
- If your Prometheus selects PodMonitors on other labels, set them on the monitors yourself.

The metrics ports listen on every address of the host or pod and need no credential. Restrict them to
your Prometheus (and, on Kubernetes, the kubelet, whose probes use the same port). The chart renders no
NetworkPolicy.

`port49_target_absent` fires when Prometheus has no `up` series for `port49d` at all, which means no
port49d is being scraped. That rule is fleet-wide: use one Prometheus per port49 fleet, or add a
namespace matcher to the two absent rules.

No metric carries a device name or address. "Which device" is answered by the
[decision log](../reference/decision-log.md), not by a label.

## The alerts

`deploy/alerts/port49.rules.yaml` holds the rules. Load it with `rule_files:`, or take the Helm chart's
copy. There are two severities, and you route on the `severity` label:

- `page`: port49 is refusing devices or losing records now.
- `ticket`: it costs nothing yet, or a person fixes it in working hours.

Every alert carries a `runbook_url` that opens its section of the [alerts reference](../reference/alerts.md),
which gives its expression and why the threshold is what it is. The
[3am index](troubleshooting/index.md#an-alert-fired) gives a do and a don't for each family.

The rules assume the defaults of the settings they watch (`close_after`, `refresh_interval`,
`staleness_ceiling` and so on). If you change one, edit the matching rule; the reference lists them.

## The disk etcd and the spool need

etcd needs a disk with sustained WAL fsync p99 under 10 ms. Datacenter NVMe and cloud SSD volumes
qualify; a consumer QLC drive does not.

A drive that stalls pushes port49's store calls past the 500 ms call timeout in bursts. A store call
that times out is a token login answered `store_unavailable`.

Two alerts watch for it:

- `etcd_disk_slow` ([reference](../reference/alerts.md#etcd_disk_slow)) fires after 10 minutes when the
  p99 of `etcd_disk_wal_fsync_duration_seconds` is over 10 ms, or the p99 of
  `etcd_disk_backend_commit_duration_seconds` is over 25 ms. It reads etcd's own metrics, so scrape etcd.
- `port49_accounting_spool_disk_slow`
  ([reference](../reference/alerts.md#port49_accounting_spool_disk_slow)) fires after 10 minutes when the
  p99 of `port49_accounting_spool_sync_seconds` is over 10 ms. The 10 ms is port49's own threshold, not
  an etcd figure.

  It matters because port49d acknowledges an accounting record only after the record is synced to the
  spool. A slow disk under `accounting.spool_path` slows every accounting reply, and a device may see
  accounting fail.

The sizing defaults were measured on a cloud SSD volume that passed every load cell. The same run on a
consumer QLC drive failed. The figures and the gates applied to them are in
[`tests/lab/results/load-beehive-gates.md`](https://github.com/blanketfish/port49/blob/main/tests/lab/results/load-beehive-gates.md).
Put the session etcd and the accounting spool on disks that meet the 10 ms line before you rely on
either.

## Accounting is delivered at least once

port49d writes each accounting record to its spool and forwards it to the decision log. The log can
hold the same `account` record twice, in two ways:

- A crash between forwarding a record and removing it from the spool forwards that record again at
  the next start.
- A record the log refuses is offered again.

**Dedupe on `task_id` together with `device.nas`, `flags` and `record.raw`.** The log carries
`task_id` for exactly this, and on Junos it is the only per-record counter the device sends. It is not
unique alone: a device numbers its tasks within one login, so the next login starts again at 1. The
other three keys keep records apart that share a `task_id`. `record.raw` holds the arguments the device
sent, so a start, a stop and a watchdog update of one task stay distinct.

Never drop a record because its `task_id` was seen once before.

`port49_accounting_spool_drops_total` is different: it counts records port49d discarded, and the `stage`
label says where. Any rise pages ([port49_accounting_spool_drops](../reference/alerts.md#port49_accounting_spool_drops)).

## Shedding

port49d holds one pool of connection slots across both TACACS+ listeners, `limits.max_connections`.
Left unset, it is sized from the open-file limit at start.

When the pool is full, a new connection is reset at once. The device then moves to its next server
now, instead of waiting out its own timeout. That is meant, and it is never silent. port49d says so on
its log when shedding begins:

```text
port49d: shedding: all <N> TACACS+ connection slots (limits.max_connections) are in use; each new connection is reset at Accept and the device tries its next server
```

and, while it goes on, once a minute:

```text
port49d: still shedding: <N> connections reset at Accept in the last minute; <N> of <N> slots in use
```

Each shed adds one to `port49_connections_shed_total{reason="global_cap"}`. The page alert
[port49_global_cap_shedding](../reference/alerts.md#port49_global_cap_shedding) fires on any rise of it
over five minutes. Its warning, the ticket
[port49_connections_near_cap](../reference/alerts.md#port49_connections_near_cap), fires when a port49d
holds more than 80% of `port49_connections_max` open for ten minutes.

A shed device tries its next server, and with none left it falls to local authentication. Raise
`limits.max_connections` or add replicas before the near-cap ticket becomes the page.

The pool counts only accepted connections. The per-source limits are checked first, and they count in
`port49_connection_events_total`, not here.

## Logs

Process logs go to stderr (journald under systemd, `docker compose logs`, `kubectl logs`). They hold
operational lines, never a token, password, challenge or response. The decision log is separate and
structured: one record per decision, with the fields in the [reference](../reference/decision-log.md).

The log lines worth knowing at 3am are in the [3am index](troubleshooting/index.md#a-log-line-says).
