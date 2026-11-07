---
title: When it will not start
description: The refusals port49d prints at start, what each means and how to fix it.
---

# When it will not start

port49d and port49-broker refuse to start rather than start wrong. Each refusal is one line that names
the file, the setting or the key; read it first. The sections below are for the three deployment shapes,
which are peers: each says where the line is and what to do.

The fastest check on any shape is the metrics port: `curl <host>:9049/readyz` for port49d and
`curl <host>:9050/readyz` for the broker. `serving` with a 200 means the process is up. Anything else
is a 503 with a line that says why (`starting`, `waiting for the store`, `draining`).

## systemd

--8<-- "deploy/systemd/README.md:will_not_start"

## Containers (compose)

--8<-- "deploy/compose/README.md:will_not_start"

## Kubernetes (Helm)

`kubectl logs --previous <pod>` holds the line of a pod in `CrashLoopBackOff`. The chart README's
table of what you see:

| You see | Look at | Cause and action |
|---|---|---|
| Pod `CrashLoopBackOff` | `kubectl logs --previous <pod>` | The config or a Secret is wrong; the log names the field or reference, never its value. |
| Pod `ContainerCreating` for minutes | `kubectl describe pod <pod>` (the Events) | A named Secret or ConfigMap is missing: a kubelet event, never a port49 line. |
| Pod `Pending` | `kubectl describe pod <pod>` | A named PVC is missing or unbound, or nothing can be scheduled. |
| port49d refuses to start naming etcd and a version | `kubectl logs --previous <pod>` | A member is below the floor (3.4.24, 3.5.8 or 3.6); upgrade etcd. Every member is listed and checked. |
| Not Ready, running | `curl :9049/readyz` through a port-forward | A store is unreachable; the body says which. |
| No pod is ever created; the StatefulSet's events say `violates PodSecurity` | `kubectl -n <ns> describe statefulset <name>` | The namespace enforces `restricted`. The data-dir init runs as root, so the namespace must be `baseline`: `kubectl label --overwrite ns <ns> pod-security.kubernetes.io/enforce=baseline`. |
| Pod `Init:Error` or `Init:CrashLoopBackOff` | `kubectl logs <pod> -c data-dir` and `-c data-dir-owner` | `data-dir-owner` naming a path: a file in the data directory belongs to another uid; run the `chown -R 65532:65532 ...` it prints. Naming a directory that may be mode 0000: `chmod u+rwx` it as root on the volume, then restart. `data-dir` saying the data directory is a symlink: someone replaced it; inspect and remove the link. |
| `kubectl get externalsecret` shows `SecretSyncedError` | `kubectl describe externalsecret <name>` | The external secrets operator cannot reach its store or a remote key. The Secret keeps its last data, so a new key version never appears and port49d names the missing `secret_ref`. |

### A broker refused "behind a promotion"

After a CA rotation, a broker that missed the copy refuses to start and the pod crash-loops with:

```text
issuance: this broker's issuing CA (<fingerprint>) is behind a promotion: the store records <fingerprint>, promoted from it by <broker> at <time>. Copy issuing-ca.pem, issuing-ca.key and issuing-ca-previous.pem from that broker into broker.state_dir, then start
```

The chart's `scripts/copy-issuer.sh` cannot fix it: it never overwrites a broker's CA, and this broker
holds the old one. Copy the three files by hand:

1. Find the broker the line names and this broker's PVC (`kubectl get pvc`; the chart's StatefulSet
   makes one per ordinal from the claim template `data`). The files live in `state/` inside it.
2. Start a throwaway debug pod that mounts that PVC. The claim is `ReadWriteOnce`, which one node can
   mount: if the debug pod cannot attach it because the crash-looping pod holds it, set the debug pod's
   `nodeName` to that pod's node.
3. Copy `issuing-ca.pem`, `issuing-ca.key` and `issuing-ca-previous.pem` from the broker the line names
   into the PVC's `state/` directory. Set the owner to 65532:65532 and the mode to 0600.
4. Delete the debug pod and let the broker start. Compare the `issuing as ... (sha256:<fingerprint>)`
   line on every broker; the fingerprints must be identical.

Do not run `init-issuer` on this broker (it would make a different CA), and do not run `forget-issuer`
(every certificate the old CA issued stops working). The
[key rotation page](../../admin/key-rotation.md#the-three-refusals) has the other two refusals.

## Which healthcheck to use where

Both `port49d` and `port49-broker` have a `healthcheck` subcommand, for an image with no shell and no
curl, and `port49-inventory healthcheck` takes the same flags. It asks the process's own
`metrics_listen`, and it exits 0 or 1.

| Command | Asks | Means |
|---|---|---|
| `port49d healthcheck` | `/healthz` | Liveness: the process runs and its metrics listener is bound. |
| `port49d healthcheck --ready` | `/readyz` | Readiness: the TACACS+ listener is serving. 503 while it waits for the store or drains. |

The broker's `/readyz` is its own: 503 `starting` until its API is up, then 200. The default and
`--ready` mean the same for it as for port49d.

**Use the default, `/healthz`, for anything that restarts a container or holds something back when it is
unhealthy:** Docker Swarm, an autoheal sidecar, a Nomad `check_restart`, an ECS container health check
that replaces the task, and a Compose `depends_on` with `condition: service_healthy`.

**Use `--ready` (`/readyz`) only to route or to display:** Compose's own `healthy` in
`docker compose ps`, a load balancer's member check.

The reason is the 3am case. When the store is down at start, port49d waits for it with its listener
closed, and `/readyz` answers `503 waiting for the store: the TACACS+ listener stays closed until etcd
answers`. That wait is the design: port49d comes back by itself when etcd does, and devices find TCP 49
refused and fall to their local method meanwhile. A supervisor that restarts on `--ready` turns that
wait into a restart loop. Each restart throws away what the process holds in memory, its cached
directory membership and pins, and serves from its stored snapshot only up to
`session.staleness_ceiling`. A store outage must never restart-loop port49d.

!!! warning "The shipped compose.yaml probes with `--ready`, and `docker stack deploy` acts on it"
    `compose.yaml` runs `healthcheck --ready` for port49d and the broker, which is right for
    `docker compose`: it only reports `healthy` and restarts nothing on it. **Docker Swarm
    (`docker stack deploy`) restarts a container that turns unhealthy.** Deployed to Swarm as shipped,
    port49d is restarted again and again for as long as the store is down. If you adapt the file to
    Swarm, remove `--ready` from both `healthcheck` lines so they probe `/healthz`.

Even `/healthz` has a gap. Between one run of port49d and the next after a store loss, `/healthz` and
`/readyz` are unbound for seconds. Give a liveness check a failure window of more than 30 seconds; the
chart uses `/healthz` every 10 seconds and six failures (60 seconds), and the shipped compose healthcheck
is 10 seconds and three retries, with a 30-second start period.

On Kubernetes the chart already does this: `/readyz` is the readiness probe, so a not-ready pod leaves
the Service, and `/healthz` is the liveness probe.
