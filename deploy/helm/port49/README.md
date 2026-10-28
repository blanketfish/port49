# port49 Helm chart

Runs port49d (TACACS+) and port49-broker as two StatefulSets, a PVC per replica. Kubernetes is one
supported shape among peers (systemd, containers); nothing in port49 requires it.

Status: the chart's render checks pass on a Go stand-in renderer. `helm lint`, `helm template` and the
schema refusals are unverified until helm runs (`make helm-test`), and the chart has not been installed
on a cluster (Task 11's kind smoke).

## Install

You supply, as Secrets created with `--from-file` (never `--from-literal`): the device keys, the
encryption key, etcd's CA and one etcd client identity per component, and the broker's TLS pair.

```sh
helm install port49 deploy/helm/port49 -n port49 \
  --set keys.existingSecret=port49-device-keys \
  --set encryption.existingSecret=port49-encryption \
  --set etcd.caSecret=port49-etcd-ca \
  --set etcd.port49d.existingSecret=port49-etcd-port49d \
  --set etcd.broker.existingSecret=port49-etcd-broker \
  --set broker.tls.existingSecret=port49-broker-tls \
  --set 'etcd.endpoints={https://etcd-0:2379,https://etcd-1:2379,https://etcd-2:2379}' \
  --set-file policy=policy.yaml --set-file inventory=inventory.yaml
```

The schema refuses an install with fewer than three etcd members, a repeated or non-https member, or
an empty Secret name. List every member: a client given one URL has no failover. port49 does not
create or run etcd for you; `examples/etcd/` is a three-member example, and its init Job is
unverified until Task 11's smoke.

Two server groups (for example a lab and production) are two releases in two namespaces with their
own Secrets and their own etcd; they share nothing.

## The four requirements

1. `etcd.endpoints`: every member, at least three.
2. `keys.existingSecret`: mounted whole at `/run/port49/keys`, in port49d's pod only. The volume mode
   is provisional on L82.
3. `encryption.existingSecret` and `encryption.id`: mounted in both pods.
4. `policy` and `inventory`, via `--set-file`. Without a policy port49d refuses to start.

## Secrets and rotation

Every secret is a mounted file, never an environment variable. Mounts are whole-volume and never
`subPath`, because the kubelet updates a whole mount in place and a `subPath` mount never sees the
update. Files are mode 0440; the pod sets `fsGroup: 65532` with `fsGroupChangePolicy: OnRootMismatch`
so the unprivileged user can read them and the state directories are not made group-writable at every
start.

fsGroup also makes a PVC's root group-writable, and port49's file fence refuses a group-writable
directory above a file it reads (the kept CRLs and the bundle live below the volume). So the
`data-dir` init container, which runs as root after the kubelet has set the volume up, removes the
group write bit from the volume root before the process starts, and no fenced file (policy,
inventory, device keys, the sealing key) lives on a PVC. Unverified against a real kubelet until the
kind smoke and L82.

`examples/external-secret.yaml` syncs the device keys from Vault with External Secrets: one Secret key
per key version (`core_v1`, `core_v2`), each from its own remote key. Adding a version is adding a
remote key and an entry; nothing is overwritten, so a rollback is still a file on disk. Vault Agent
and the Secrets Store CSI driver are unmeasured here (L83) and not documented as supported.

To rotate the encryption key, add the new key to the Secret, set `encryption.id` to a new id, and
upgrade; port49 reads old ids until nothing is sealed under them (see the operator guide).

## The issuing CA

Every broker must hold the same issuing CA. After the first install run, once:

```sh
deploy/helm/port49/scripts/copy-issuer.sh port49 port49
```

It runs `init-issuer` in a one-shot pod on broker-0's volume, copies the CA to each other broker's
volume with ownership and mode set, restarts the brokers, and prints each pod's "issuing ca" log
line so you can compare them. It never `exec`s into a broker. `forget-issuer` retires a CA.

## Admin calls

Admin commands (`port49 revoke`, `port49 directory ...`) are calls to the broker API and need a
security-key press from an admin whose key chains to `broker.attestationRootsConfigMap` (a ConfigMap
holding `attestation-roots.pem`). Without it every admin call is refused 503. Run them from a
workstation that can reach the `<release>-broker` Service.

Break-glass, when no broker is reachable: `scripts/revoke-offline.sh <ns> <release> -- --principal
<name> [--lift|--list]` scales the brokers to 0, runs `port49-broker revoke --offline` against
broker-0's volume, and scales back on every exit. `init-revocations` and `init-enrollments` are
one-off Jobs, run once per new deployment.

## At 3am

| You see | Look at | Cause and action |
|---|---|---|
| Pod `CrashLoopBackOff` | `kubectl logs --previous <pod>` | The config or a Secret is wrong; the log names the field or reference, never its value. |
| Pod `Pending` | `kubectl describe pod <pod>` | A named Secret or PVC is missing. |
| Not Ready, running | `curl :9049/readyz` through a port-forward | A store is unreachable; the body says which. |
| Admin call 503 | broker log | No attestation roots configured. |
| Brokers disagree on the CA | `copy-issuer.sh` output | Run it again; it is idempotent on the source. |

## Storage and scaling

Each replica has its own PVC (the accounting spool for port49d, the state directory for the broker).
Scaling down or deleting the release retains the PVCs; delete them yourself when you are sure.
`autoscaling.enabled` renders an HPA on the `port49_connections` Pods metric; it needs a metrics
adapter (for example prometheus-adapter) that you provide, and the StatefulSet then omits `replicas`.
A scale-down leaves the spool of the removed pod on its PVC, so drain or collect it before deleting.

## Network

`service.type` defaults to LoadBalancer with `externalTrafficPolicy: Local`. Whether the device's
source address is preserved on Kubernetes is unmeasured (L39 b, c): do not write source-based policy
on the strength of it. `tlsListener.enabled` adds port 300 and requires `tlsListener.existingSecret`.
The pod sets `net.ipv4.ip_unprivileged_port_start` to 0 so the non-root process can bind 49; clusters
that forbid that sysctl need a different arrangement (not offered here).

The image is distroless and non-root. The pods meet the Pod Security `baseline` level; the init
containers run as root with only the capabilities they need, so a namespace enforcing `restricted`
will refuse them.

`issuerDiscovery.enabled` (default off) binds `system:unauthenticated` to the issuer-discovery role
for the cluster, which is a cluster-wide change: enable it in one release per cluster, and see
`examples/kubernetes/issuer-discovery.yaml`.

## Backups

Two CronJob examples, one pattern (UNVERIFIED until the kind smoke): `examples/backup-cronjob.yaml`
(the etcd snapshot) and `examples/backup-enrollments-cronjob.yaml` (the sealed enrollment store,
`port49-broker export-enrollments --out FILE`). Neither the etcd nor the port49 image has a shell, so:

1. a `stale-check` init container fails the job when `<name>.new` is left from a run that did not
   finish (the failed pod stays, and `kubectl logs` names the file); remove it and the next run goes;
2. the writer init container (`etcdctl snapshot save`, or `export-enrollments --out`) creates
   `<name>.new` 0600 and never replaces a file;
3. an alpine `finish` container does `umask 077`, renames to a dated name and prunes after 14 days.

Nothing sealed is written to a log. The snapshot holds sealed data but is still sensitive; give its
PVC a restrictive access mode. Restore enrollments with `port49 directory import`.

## Multi-region

`examples/values-multi-region.yaml` gives the session store its own etcd per region with a 500 ms call
timeout; port49d starts without waiting for it.
