---
title: Install
description: Choosing between the systemd, container and Helm shapes of a port49 deployment, and what every shape needs.
---

# Install

port49 runs in three shapes. They are peers: each runs the same two processes, `port49d` and
`port49-broker`, on the same etcd, and nothing in port49 requires any one of them. Choose the one your
team already operates.

| Shape | You get | Page |
|---|---|---|
| systemd | the `port49-server` package (`.deb` or `.rpm`) with two units | [Install with systemd](systemd.md) |
| Containers | `port49d`, `port49-broker` and a three-member etcd under Compose | [Install with containers](container.md) |
| Helm | two StatefulSets and a PVC per replica | [Install with Helm](helm.md) |

The people who sign in need the [clients](clients.md), which are installed on their own machines and
not on the server.

## What every shape needs

Each shape page states these four again, in its own terms.

1. **The device's source address reaches `port49d` unrewritten.** `port49d` admits a device by the
   address it sees. A NAT or a proxy in front of port 49 breaks that. On a host this is the default. In
   a container, follow the network notes on the [container page](container.md). In Kubernetes a `LoadBalancer` Service needs
   `externalTrafficPolicy: Local` (the chart's default); the [Helm page](helm.md) has the measurement.
2. **etcd, with two processes.** `port49d` and `port49-broker` run apart, each with its own etcd
   identity. The memory store is one process and is for a trial only.
3. **`broker.state_dir` survives a restart.** It holds the revocation marks, the witness and the issuing
   CA. Put it on a volume that is kept, and back it up with the host.
4. **etcd is port49's own cluster, on a disk that keeps up.** etcd needs sustained WAL fsync p99
   under 10 ms. A slow disk pushes port49's store calls past their timeout in bursts, and the
   `etcd_disk_slow` alert fires after ten minutes of it.

## Install the binaries 0755

Install `port49` with mode `0755`, owned by root, with no setgid bit and no file capabilities. The
packages and the image already do. If you copy the binary by hand, do the same.

The reason is `port49 ssh`. It tells `ssh` to run `port49` itself as `SSH_ASKPASS`, by the path
`/proc/<pid>/exe`. A setgid or capability-bearing binary makes that path unexecutable for the `ssh`
process, and `ssh` then sends the device an empty password, so the login fails.

`port49d` needs no file capability to bind port 49. The systemd unit grants `CAP_NET_BIND_SERVICE` as an
ambient capability instead.

## First install: `port49d init-revocations`

A `port49d` that holds its broker in process (`broker.revocations_file` is set) never creates the
revocations file itself: a missing file, or one that does not load, refuses every start, so that a
lost file cannot silently forget every revoke. Run this once per install, before the first start:

```sh
port49d init-revocations --config /etc/port49/port49d.yaml
```

It refuses when a file is already there, so a second run changes nothing. It is a first-install step
and does not belong in a unit's `ExecStartPre=`. The shape pages cover the other one-time steps
(`port49-broker init-issuer`, and `init-enrollments` for directory password sign-in).
