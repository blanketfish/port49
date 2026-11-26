---
title: Requirements
description: What every port49 deployment needs from the network, etcd, disks and clocks.
---

# Requirements

Every deployment needs the five things below. The install pages for [systemd](../operate/systemd/install.md),
[containers](../operate/containers/install.md) and [Helm](../operate/helm/install.md) each have a step
that meets them.

## Device source address

port49d admits a device by the address it sees, so nothing in front of port 49 may rewrite the
device's source address. A NAT or a proxy in front of port 49 breaks admission.

- On a host, this is the default.
- In a container, a published port can change the address. See [Install with containers](../operate/containers/install.md).
- In Kubernetes, a `LoadBalancer` Service needs `externalTrafficPolicy: Local`, which is the chart's
  default. `Cluster` makes port49d see a pod-network or node address. The measurements are on
  [Install with Helm](../operate/helm/install.md).

## etcd

port49 runs on its own etcd cluster of three members, never another system's. It needs port49's two roles
(`port49d store-roles` prints them), compaction, a quota and backups.

A member must be etcd 3.4.24, 3.5.8 or 3.6 or later. port49d refuses an older one and says which. Its
start line names every member it checked, for example `etcd https://etcd-1.example.com:2379 3.6.15, ... at
or above the floor (3.4.24, 3.5.8 or 3.6)`. Every config names every member's URL, never a load
balancer or a VIP.

The memory store is one process and is for a trial only. See [Stores](../operate/stores.md).

## etcd disk

!!! info "WAL fsync p99 under 10 ms"
    etcd needs a disk with sustained WAL fsync p99 under 10 ms, which is etcd's own guidance. Datacenter
    NVMe and cloud SSD volumes qualify. A consumer QLC drive does not.

A drive that stalls pushes port49's store calls past the 500 ms call timeout in bursts, and a store call
that times out answers a token login `store_unavailable`. The `etcd_disk_slow` alert fires when the WAL
fsync p99 or the backend commit p99 stays over its bound for 10 minutes. It reads etcd's own metrics, so
scrape etcd.

On a GCE pd-ssd (400 GB, declared by the operator) the load run passed every cell with a WAL fsync mean
of 0.72 to 0.86 ms. A consumer QLC drive failed it. The figures and the gates are in
[`load-beehive-gates.md`](https://github.com/blanketfish/port49/blob/main/tests/lab/results/load-beehive-gates.md),
and the other `load-*` files in `tests/lab/results/` are the rest of the run.

port49d's accounting spool directory needs the same, under 10 ms. That figure is port49's alert
threshold, not etcd's. port49d acknowledges each accounting record only after an fsync, so a slow disk
caps accounting latency. The `port49_accounting_spool_disk_slow` alert watches it.

## broker.state_dir { #broker-state-dir }

`broker.state_dir` holds the revocation marks, the witness and the issuing CA. It must survive a
restart, so put it on a volume that is kept and back it up with the host. Each broker has its own.

## Clocks

Every broker host and every port49d host keeps its clock on NTP. In Kubernetes these are the nodes'
clocks, and in a container the host's. A subject's `token_ttl` may be 30 seconds, so the hosts must
disagree by far less than that.

The broker writes a token with its expiry, which is its own time of minting plus the TTL. port49d honours
the token only before that time on its own clock, and the store's leases only clean up later. On etcd,
the two clocks therefore decide a login together.

- A broker behind. A broker 20 seconds behind turns a 30-second token into a 10-second one. One 30
  seconds behind mints tokens that are dead on arrival, and every login with one fails
  `token_not_found`, the same as a typo. Nothing else points at the clock.
- A broker ahead. Each token lasts longer by the skew, until its lease reclaims it: at most `lease_grace`
  (5 minutes) plus two minutes past `token_ttl`. port49d says so (`clock: a token was minted ... ahead of
  this host's clock`), counts it in `port49_token_minted_ahead_total` and raises the
  `port49_token_clock_skew` ticket. Skew never admits a token minted for another device or one already
  spent. It widens an unspent token's window only up to that bound.
- A session ceiling follows the broker's own `auth_time` for a certificate login, and for OIDC the
  provider's, capped at the broker's now. Skew moves it by the skew. A broker behind makes a context look
  staler (`context_stale` sooner). One ahead cannot push a refresh time into the future.

The memory store is one process and has one clock.

port49 cannot see a broker that is behind, so alert on the hosts' own NTP sync. With node_exporter,
alert on `node_timex_sync_status == 0` and on `abs(node_timex_offset_seconds) > 1`.
