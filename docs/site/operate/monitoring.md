---
title: Monitoring
description: The metrics, alerts and logs that show whether port49 is healthy.
---

# Monitoring

port49 is watched through Prometheus metrics, a shipped set of alert rules, and the logs. When an alert has
fired or a log line worries you, go to the [3am index](troubleshooting/index.md); this page is what to set
up before that.

## Scraping

Every process serves `/metrics` on its `metrics_listen` address: `port49d` on 9049 and `port49-broker` on
9050. Three alert rules (`port49_target_down`, `port49_target_absent` and `port49_broker_target_absent`)
read Prometheus's own `up` series by job name (`up{job="port49d"}` and `up{job="port49-broker"}`), so name
the jobs that, or edit the rules:

```yaml
scrape_configs:
  - job_name: port49d
    static_configs:
      - targets: ["<port49d-host>:9049"]
  - job_name: port49-broker
    static_configs:
      - targets: ["<broker-host>:9050"]
```

On Helm, `prometheusRule.enabled: true` renders the rules as a `PrometheusRule` and a `PodMonitor` for each
workload with `job` set to `port49d` and `port49-broker`. It needs the Prometheus Operator's CRDs, and
`prometheusRule.labels` must be the labels your Prometheus selects on.

The metrics ports listen on every address of the host or pod and need no credential. Restrict them to your
Prometheus and, on Kubernetes, the kubelet, whose probes use the same port. The chart renders no
NetworkPolicy.

`port49_target_absent` is fleet-wide: it fires when no port49d is scraped at all, so use one Prometheus per
port49 fleet, or add a namespace matcher to the two absent rules. No metric carries a device name or
address: "which device" is answered by the [decision log](../reference/decision-log.md).

## The alerts

`deploy/alerts/port49.rules.yaml` holds the rules. Load it with `rule_files:`, or take the Helm chart's
copy. Route on the `severity` label: `page` means port49 is refusing devices or losing records now, and
`ticket` means it costs nothing yet. Every alert's `runbook_url` opens its section of the
[alerts reference](../reference/alerts.md), and the [3am index](troubleshooting/index.md#an-alert-fired)
gives a do and a don't for each family. The rules assume the defaults of the settings they watch
(`close_after`, `refresh_interval`, `staleness_ceiling` and so on): if you change one, edit the matching
rule.

## Disks

Two alerts watch the disks, each firing after 10 minutes over 10 ms at p99. `etcd_disk_slow`
([reference](../reference/alerts.md#etcd_disk_slow)) reads etcd's own metrics, so scrape etcd.
`port49_accounting_spool_disk_slow` ([reference](../reference/alerts.md#port49_accounting_spool_disk_slow))
watches the spool, because port49d acknowledges an accounting record only after it is synced. The sizing
and the measured gates are in [Requirements](../reference/requirements.md#etcd-disk) and in
[`load-beehive-gates.md`](https://github.com/blanketfish/port49/blob/main/tests/lab/results/load-beehive-gates.md).

## Accounting is delivered at least once

port49d writes each accounting record to its spool and forwards it to the decision log. The log can hold
the same `account` record twice: a crash between forwarding a record and removing it from the spool
forwards it again at the next start, and a record the log refuses is offered again.

**Dedupe on `task_id` together with `device.nas`, `flags` and `record.raw`.** `task_id` alone is not unique,
because a device numbers its tasks within one login and the next login starts again at 1 (on Junos it is
the only per-record counter the device sends). `record.raw` keeps a start, a stop and a watchdog update of
one task distinct. Never drop a record because its `task_id` was seen once before.

`port49_accounting_spool_drops_total` is different: it counts records port49d discarded, the `stage` label
says where, and any rise pages
([port49_accounting_spool_drops](../reference/alerts.md#port49_accounting_spool_drops)).

## Shedding

port49d holds one pool of connection slots across both TACACS+ listeners, `limits.max_connections`, sized
from the open-file limit at start when unset. When the pool is full a new connection is reset at once, so
the device moves to its next server now instead of waiting out its own timeout. That is meant, and never
silent. port49d logs when shedding begins:

```text
port49d: shedding: all <N> TACACS+ connection slots (limits.max_connections) are in use; each new connection is reset at Accept and the device tries its next server
```

and once a minute while it goes on:

```text
port49d: still shedding: <N> connections reset at Accept in the last minute; <N> of <N> slots in use
```

Each shed adds one to `port49_connections_shed_total{reason="global_cap"}`. The page alert is
[port49_global_cap_shedding](../reference/alerts.md#port49_global_cap_shedding), and its warning, the
ticket [port49_connections_near_cap](../reference/alerts.md#port49_connections_near_cap), fires when a
port49d holds more than 80% of `port49_connections_max` open for ten minutes. A shed device with no server
left falls to local authentication, so raise `limits.max_connections` or add replicas when the ticket
fires. The per-source limits are checked first and count in `port49_connection_events_total`, not here.

## Logs

Process logs go to stderr (journald under systemd, `docker compose logs`, `kubectl logs`) and never hold a
token, password, challenge or response. The decision log is separate and structured, one record per
decision, with the fields in the [reference](../reference/decision-log.md). The lines worth knowing at 3am
are in the [3am index](troubleshooting/index.md#a-log-line-says).
