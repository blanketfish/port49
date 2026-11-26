---
title: Install
description: The three ways to deploy port49, the parts of a deployment and what to check before the first command.
---

# Install

Each deployment runs the same two processes, `port49d` and `port49-broker`, on the same etcd. Choose the
one your team already operates.

| Deployment | You get | Guide |
|---|---|---|
| systemd | the `port49-server` package (`.deb` or `.rpm`) with two units | [Install with systemd](../systemd/install.md) |
| Containers | `port49d`, `port49-broker` and a three-member etcd under Compose | [Install with containers](../containers/install.md) |
| Helm | two StatefulSets and a PVC per replica | [Install with Helm](../helm/install.md) |

## The parts

| Part | What it is |
|---|---|
| Client | `port49` and its agent, on the person's machine |
| Broker | `port49-broker`, HTTPS on 8443 |
| `port49d` | the TACACS+ server, on 49 and optionally TLS on 300 |
| etcd | three members, port49's own |
| Device | unmodified |

## Before you start

- The device's source address reaches `port49d` unrewritten. On Kubernetes that means
  `externalTrafficPolicy: Local` on the `LoadBalancer` Service
  ([requirements](../../reference/requirements.md#device-source-address)).
- etcd has three members, at or above the version floor, on a disk that keeps up
  ([requirements](../../reference/requirements.md#etcd)).
- `broker.state_dir` is on a volume that survives a restart
  ([requirements](../../reference/requirements.md#broker-state-dir)).
- Every broker host and every `port49d` host keeps its clock on NTP
  ([requirements](../../reference/requirements.md#clocks)).

## First install

Run these once per etcd cluster, in this order. The Install guide for your deployment has each as a step.

1. `port49d store-roles` prints the `etcdctl` commands that create port49's two etcd roles. Run them as etcd's root.
2. `port49-broker init-issuer`, on one broker only, when the broker issues certificates.
3. `port49-broker init-enrollments`, only for directory password sign-in, before the broker's first start.

The people who sign in install the [client](../../use/install-client.md).
