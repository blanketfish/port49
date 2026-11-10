# port49 Helm chart

Runs port49d (TACACS+) and port49-broker as two StatefulSets, a PVC per replica. Kubernetes is one
supported shape among peers (systemd, containers); nothing in port49 requires it.

Status: the chart's render checks run on a Go stand-in renderer (`make test`) and on real helm 3.22.0
(`make helm-test`, a CI job), and the kind smoke installs it on a cluster with port49's own etcd (green in CI,
run 41155086403).

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
create or run etcd for you; `examples/etcd/` is a three-member example, and the kind smoke runs it with
its init Job.

**etcd's disk.** etcd needs a disk with sustained WAL fsync p99 under 10 ms (etcd's own guidance;
datacenter NVMe or a cloud SSD volume). A drive that stalls pushes port49's store calls past the
500 ms call timeout in bursts. The `etcd_disk_slow` alert (`deploy/alerts`) fires when the WAL fsync
or backend commit p99 stays over its bound for 10 minutes. On a GCE pd-ssd (400 GB, declared by the operator) the load run passed every cell with a WAL fsync mean of 0.72 to 0.86 ms; a consumer QLC drive failed it (the notes are the `load-*` files in `tests/lab/results/`).
port49d's accounting spool directory needs the same, under 10 ms (port49's alert threshold, not etcd's figure): each accounting record is acked only after an fsync, so a slow-fsync disk caps accounting latency. The `port49_accounting_spool_disk_slow` alert watches it.

Two server groups (for example a lab and production) are two releases in two namespaces with their
own Secrets and their own etcd; they share nothing.

## The four requirements

1. `etcd.endpoints`: every member, at least three.
2. `keys.existingSecret`: mounted whole at `/run/port49/keys`, in port49d's pod only, mode 0440 under
   `fsGroup` (measured on kind: [L82](https://blanketfish.github.io/port49/latest/reference/lab-register/#l82)).
3. `encryption.existingSecret` and `encryption.id`: mounted in both pods.
4. `policy` and `inventory`, via `--set-file`. Without a policy port49d refuses to start.

## Secrets and rotation

Every secret is a mounted file, never an environment variable. Mounts are whole-volume and never
`subPath`, because the kubelet updates a whole mount in place and a `subPath` mount never sees the
update. Files are mode 0440; the pod sets `fsGroup: 65532` with `fsGroupChangePolicy: OnRootMismatch`
so the unprivileged user can read them and the state directories are not made group-writable at every
start.

A key is read under the secret-file rule, so two things are refused at the pod's start, each with a line
naming the file. A key directory that is group- or world-writable (outside a read-only Secret mount, which
is excused): `chmod 0755` or `0750` it. A group-readable key whose group is not the pod's (fsGroup 65532
is): a Secret volume's files are, and a file an injector or a CSI driver writes as `root:root` 0440 is not.
Never a looser rule. Two mechanisms were measured on kind ([L83](https://blanketfish.github.io/port49/latest/reference/lab-register/#l83), run 41155086403):

- **The Secrets Store CSI driver is not supported for device keys.** Its files are `0:0 0644` (the world
  bit: refused) and, with the provider's `filePermission: 0440`, `0:0 0440` (port49d, uid 65532, cannot read
  them). The driver chart (secrets-store-csi-driver 1.6.1) sets no `fsGroupPolicy` and the provider has no
  owner or group option, so `fsGroup` is not applied to the volume and no setting makes the file readable by
  65532 without a world bit. `filePermission: 0400` does not help: a `root:root` 0400 file is unreadable too.
- **The Vault Agent injector is offered for the encryption key only, never for device keys.** By default the
  agent is uid 100 and owns the rendered file (`100:65532 0440`); port49d refuses a key whose owner is neither
  itself nor root, because whoever owns a file can rewrite it. With
  `vault.hashicorp.com/agent-run-as-same-user: "true"` the file is port49d's own and port49d starts. But adding
  a version is a pod rollout, not a reload: the injector reads its annotations only when a pod is admitted, and
  each file is its own annotation. A device key must reach a running process with no restart (spec decision 54
  ruling 2), and the injector failed that cell ([L83](https://blanketfish.github.io/port49/latest/reference/lab-register/#l83) c), so device keys come from External Secrets or a Secret
  volume ([L82](https://blanketfish.github.io/port49/latest/reference/lab-register/#l82)). The encryption key changes rarely and a rollout is acceptable for it.

fsGroup also acts on a PVC's root, and two rules meet there. With `OnRootMismatch` the kubelet walks the
whole volume at a pod's start unless the root is group 65532, includes 0770 and has setgid (kubelet
`volume_linux.go`, `requiresPermissionChange`); its walk adds group write to everything it reaches.
port49's file fence refuses a group-writable directory above a file it reads, unless the directory is
sticky and root-owned. So the `data-dir` init container, as root before the process starts, sets the
volume root to `root:65532` mode 3770 (the kubelet then never walks it again, and the fence excuses
it), makes the data directory with an explicit `chmod 0700`, and repairs everything below it to
owner-only, so a walk that happens anyway (a restore, a driver that walks regardless) changes nothing
the process sees. No fenced file (policy, inventory, device keys, the sealing key) lives on a PVC. A
cluster that forbids root init containers needs a volume root provisioned 3770 root:65532 instead.
If `data-dir` fails the pod sits in `Init:` and `kubectl describe pod` says why; nothing starts
half-fenced.

The kind smoke checks this against a real kubelet (green in CI): its two-generation cell uses a
volume type the kubelet applies fsGroup to (a `local` volume or csi-hostpath, never kind's default
hostPath class, which never applies it): install, delete the pod, and check the broker starts again,
the root is `3770 root:65532` and `state/issuing-ca.key` is still 0600. Run first with the old 2755
root, with issuance on, it must leave `issuing-ca.key` unusable after the walk (the broker says so and
issues nothing; it does not crash-loop), which proves the cell detects it.

`examples/external-secret.yaml` syncs the device keys from Vault with External Secrets: one Secret key
per key version (`core_v1`, `core_v2`), each from its own remote key. Adding a version is adding a
remote key and an entry; nothing is overwritten, so a rollback is still a file on disk. The Vault Agent
injector (encryption key only) and the Secrets Store CSI driver (not supported) are covered above.

**Order matters.** Put the key file in place first, then add the policy line that names it. To remove a
key, take the policy line out first, then the file. The other order is a 3am outage: a policy line naming a
file that is not there makes port49d refuse its start (`lstat ...: no such file`), so on a restart it
crash-loops until you restore the key in the Secret or take the policy line out; the pod shows `CrashLoopBackOff` and `kubectl logs --previous` repeats the line.
The example's store is a namespaced `SecretStore`, usable only from the release's namespace. A
cluster-wide `ClusterSecretStore` without `conditions` can be used from every namespace: anyone who
can create an ExternalSecret anywhere could read the device keys through your Vault role.
`examples/external-secret-clusterstore.yaml` shows the option, with the namespace named.

### Rotating the `encryption:` key

One key everywhere, from one Secret, in three steps. The Secret holds each key as its own file, and the
chart's `encryption.key` and `encryption.previous.key` name them (`encryption.key` by default).

1. Add the new key to the Secret as a new file, `encryption-e2` (32 bytes, made as at install:
   `--from-file`, never a literal), keeping the old `encryption.key`. Then upgrade with the new key as
   `previous` while the old one stays current:
   `--set encryption.previous.id=e2 --set encryption.previous.key=encryption-e2`.
   Every pod now opens what either key sealed.
2. Swap: `--set encryption.id=e2 --set encryption.key=encryption-e2 --set encryption.previous.id=c1
   --set encryption.previous.key=encryption.key`. New records are sealed under `e2`.
3. Remove `encryption.previous` and the old file only after the scheduled directory pass (every
   `refresh_interval`) has re-sealed the second-factor records under `e2`. A record that opens under neither
   key is never "not enrolled": that sign-in is `503 store_unavailable`, and the broker's line names
   `port49 directory reset-second-factor`.

A pod whose keys lack the id the directory store currently holds refuses to start, naming the store and the
id. Never reuse an id; the chart refuses a `previous` with no file, the same id, or the same file as the
current key.

## The issuing CA

This section applies when issuance is on: a person signs in at your identity provider and the broker
issues a short-lived certificate. It is off by default, because it needs your provider: install with
`-f examples/values-issuance.yaml` (the provider, client and domain replaced) so that
`broker.identity.issuance` is set; `init-issuer` refuses a broker without it. A broker that takes
certificates and tokens only has no issuing CA and skips this section. The values replace the chart's
`humans` list: keep the `x509` entry in it if people still sign in with client certificates, or the
broker stops accepting them (its start line names the verifiers it loaded).

Every broker must hold the same issuing CA, or it refuses to start against the store's record of it.
After the first install run, once:

```sh
deploy/helm/port49/scripts/copy-issuer.sh port49 port49 --from 0
```

`--from` is required: it names the broker whose CA is the one to keep (`--to` names targets; the
default is every other broker). The script looks at every broker's volume first. If none holds a CA it
runs `init-issuer` in a one-shot pod on the source's volume; if the source holds none but another
broker does it refuses and names that broker (a second `init-issuer` would make a different CA). It
copies `issuing-ca.pem` and `issuing-ca.key` (and `issuing-ca-previous.pem` during a rotation) to each
target through a staging directory, with ownership and mode set, skips a target that already holds
the same CA, and **refuses, naming both certificate sha256s and both ordinals, a target that holds a
different one: it never overwrites a CA.** Then it restarts the brokers and prints each pod's "issuing
ca" log line so you can compare them. It never `exec`s into a broker, and its helper pods have
deadlines of minutes.

**broker-0's volume was lost** (or any broker's): copy from one that holds the CA, never run
`init-issuer`:

```sh
deploy/helm/port49/scripts/copy-issuer.sh port49 port49 --from 1 --to 0
```

Do not reach for `forget-issuer`. It removes the store's record of the CA so that a new one can be
made, and every certificate issued under the old CA stops working. It is for the case where every
broker lost the CA and no copy exists.

## Admin calls

Admin commands (`port49 revoke`, `port49 directory ...`) are calls to the broker API and need a
security-key press from an admin whose key chains to `broker.attestationRootsConfigMap` (a ConfigMap
holding `attestation-roots.pem`). Without it every admin call is refused 503. Run them from a
workstation that can reach the `<release>-broker` Service.

Break-glass, when no broker is reachable: `scripts/revoke-offline.sh <ns> <release> -- --principal
<name> [--lift|--list]` scales the brokers to 0, runs `port49-broker revoke --offline` against
broker-0's volume, and scales back on every exit. The chart is on etcd, which keeps the revocation
marks (with a copy in `broker.state_dir`), so it has no `init-revocations` step (that command is for a single-process trial on the memory
store). The etcd roles are applied once per cluster by `examples/etcd/etcd-init-job.yaml`, which applies
`port49d store-roles`' output as etcd's root and enables auth. Before it, run
`port49d store-roles --config port49d.yaml --broker-config port49-broker.yaml > roles.sh` (the broker's
config names the broker's own etcd certificate) and
`kubectl -n port49-etcd create configmap port49-etcd-roles --from-file=roles.sh`; the Job's header
comment has the details. `init-enrollments` is a one-off Job, run once per new deployment that uses directory password
sign-in: `examples/init-enrollments-job.yaml` is it (adapt its names to
your values, then `kubectl -n <ns> apply -f` it and `kubectl -n <ns> wait --for=condition=complete job/port49-init-enrollments
--timeout=300s`; the kind job `make kind-enrollments` applies that file with only the image and the release's ConfigMap name changed, in the namespace `-n` names). A broker already running when `init-enrollments` finishes
finds the new store within 30 seconds; until then its sign-ins answer `enrollment_store_lost`.

## At 3am

| You see | Look at | Cause and action |
|---|---|---|
| Pod `CrashLoopBackOff` | `kubectl logs --previous <pod>` | The config or a Secret is wrong; the log names the field or reference, never its value. |
| Pod `ContainerCreating` for minutes | `kubectl describe pod <pod>` (the Events) | A named Secret or ConfigMap is missing: a kubelet event, never a port49 line. |
| Pod `Pending` | `kubectl describe pod <pod>` | A named PVC is missing or unbound, or nothing can be scheduled. |
| port49d refuses to start naming etcd and a version | `kubectl logs --previous <pod>` | A member is below the floor; upgrade etcd. Every member is listed and checked. |
| Not Ready, running | `curl :9049/readyz` through a port-forward | A store is unreachable; the body says which. |
| Admin call 503 | broker log | No attestation roots configured. |
| Brokers disagree on the CA, or one refuses to start on it | the broker's "issuing ca" log line; `copy-issuer.sh` output | Copy from a broker that holds the CA the store records, onto one that holds none (a lost volume): `copy-issuer.sh <ns> <release> --from <ordinal> --to <ordinal>`. It never overwrites a CA: onto a broker that holds a different one, including one "behind a promotion" after a rotation, it refuses and names both, and the files are copied by hand with a debug pod on that broker's PVC (the docs' "When it will not start"). Never `init-issuer` again, and not `forget-issuer`. |
| Pod `Init:Error` or `Init:CrashLoopBackOff` | `kubectl logs <pod> -c data-dir` and `-c data-dir-owner` (`describe` shows only the exit code) | `data-dir-owner` naming a path: a file in the data directory belongs to another uid; run the `chown -R 65532:65532 ...` it prints. `data-dir-owner` saying a directory may be mode 0000: `chmod u+rwx` it (as root on the volume), then restart. `data-dir` saying the data directory is a symlink: someone replaced it; inspect and remove the link. Otherwise the root init that sets up the volume failed; its log names the command. Usually a PVC that cannot be chowned (a read-only or network volume that refuses chown), or a namespace policy that drops its capabilities. |
| No pod is ever created; the StatefulSet's events say `violates PodSecurity` | `kubectl -n <ns> describe statefulset <name>` | The namespace enforces `restricted`. The data-dir init runs as root (it makes the volume's root 3770 and the data directory 0700), so the namespace must be `baseline`: `kubectl label --overwrite ns <ns> pod-security.kubernetes.io/enforce=baseline`. |
| A backup Job failed | `kubectl logs job/<name> -c stale-check` | A `.new` file is left from a run that did not finish; the log names it. Neither backup image has a shell: remove it from a throwaway alpine pod that mounts the backups PVC (`kubectl run`, `rm /backup/<name>.new`), and the next run proceeds. |
| `kubectl get externalsecret` shows `SecretSyncedError` | `kubectl describe externalsecret <name>` | ESO cannot reach the store or a remote key. The Secret keeps its last data, so a new key version never appears and port49d names the missing `secret_ref`. |

## Storage and scaling

Each replica has its own PVC (the accounting spool for port49d, the state directory for the broker).
Scaling down or deleting the release retains the PVCs; delete them yourself when you are sure.
`autoscaling.enabled` renders an HPA on the `port49_connections` Pods metric; it needs a metrics
adapter (for example prometheus-adapter) that you provide, and the StatefulSet then omits `replicas`.
A scale-down leaves the spool of the removed pod on its PVC, so drain or collect it before deleting.

## Alerts and scraping

`prometheusRule.enabled: true` renders the alert rules as a `PrometheusRule` and a `PodMonitor` for each
workload's `metrics` port. The monitors set `job` to `port49d` and `port49-broker`, the two names the
`port49_target_down`, `port49_target_absent` and `port49_broker_target_absent` rules key on
(`deploy/alerts/README.md`). Both need the Prometheus Operator's CRDs, and `prometheusRule.labels` must be
the ones your Prometheus selects on. The same labels go on the monitors; if your Prometheus selects
PodMonitors on different labels from rules, set them on the monitors yourself.

The metrics ports (9049 for port49d, 9050 for the broker) listen on every pod address. Restrict them with
a NetworkPolicy that admits only your Prometheus (and the kubelet, for the probes on the same port); the
chart does not render one.

## Network

`service.type` defaults to LoadBalancer with `externalTrafficPolicy: Local`, and the device's source
address must reach port49d unrewritten, because port49d admits a device by that address. Measured on kind
(spec §15 [L39](https://blanketfish.github.io/port49/latest/reference/lab-register/#l39), 2026-11-04, kube-proxy in iptables mode, a device outside every node, a NodePort Service):

| Setting, and where the device dials | Result |
|---|---|
| `Cluster`, a node running the pod | fails: the source port49d sees is a pod-network address, not the device's |
| `Cluster`, a node not running the pod | fails: the source is that node's own address |
| `Local`, a node running the pod | works: port49d sees the device's own address |
| `Local`, a node not running the pod | the connection times out, and port49d logs nothing, since the connection never reaches it |
| host networking, the pod's node | works, but the chart does not offer it |

Keep `Local`; `Cluster` breaks device binding. Under `Local`, give devices the LoadBalancer address, not a
node's address: a pod that moves leaves its old node answering nothing, and the symptom is a device whose
logins time out while port49d's log shows no attempt from it. MetalLB in BGP mode advertises the address
only from nodes with a ready pod ([L85](https://blanketfish.github.io/port49/latest/reference/lab-register/#l85) measured that); a cloud load balancer is unmeasured.

Host networking passed in the lab, on a namespace relabelled `privileged`. The chart offers none: its namespace
runs at Pod Security `baseline`. Kubernetes also refuses a pod's `net.ipv4.ip_unprivileged_port_start`
sysctl on the host network, so a host-network pod needs that sysctl removed. Binding port 49 as the non-root
user then depends on the node's own value, which is 1024 on an ordinary host: set it to 0 there or give
the container a capability to bind. A kind node's value is inferred to be 0, not read.

The TLS listener's Service has the same policy; its port was not dialled. `tlsListener.enabled` adds port 300
and requires `tlsListener.existingSecret`.
The pod sets `net.ipv4.ip_unprivileged_port_start` to 0 so the non-root process can bind 49; clusters
that forbid that sysctl need a different arrangement (not offered here).

A terminating port49d pod keeps serving for `port49d.preStopSeconds` (default 15) before it closes its
listeners, so the route to it is withdrawn first. Without the wait, a login that a router or load
balancer still sent to the pod was refused: with MetalLB over BGP the route took 6.6 s to leave the
router after the listener closed ([L85](https://blanketfish.github.io/port49/latest/reference/lab-register/#l85) c, measured on kind), and the rolling-restart run without the
wait lost one login of 42 past its retry ([L85](https://blanketfish.github.io/port49/latest/reference/lab-register/#l85) d). It applies to every `service.type`, because the endpoint leaves the Service at the
pod's deletion in all of them. The image has no shell, so the wait is the kubelet's own `sleep`
action, which needs Kubernetes 1.30 or later; on an older cluster set `port49d.preStopSeconds: 0`.
`port49d.terminationGracePeriodSeconds` (default 60) must be at least the sleep plus 30, port49d's
longest drain; the chart refuses a smaller value. With the 15 s wait the rolling restart lost no login
(55 of 55 first time, [L85](https://blanketfish.github.io/port49/latest/reference/lab-register/#l85) d, run 41155086403).

### Anycast with MetalLB

`service.anycast.enabled: true` with `service.anycast.address` adds MetalLB's
`metallb.universe.tf/loadBalancerIPs` annotation to the TACACS+ Service. Nothing else changes, and
MetalLB, its address pool and its BGP peers stay yours. Lab [L85](https://blanketfish.github.io/port49/latest/reference/lab-register/#l85) measured this on kind with MetalLB 0.16.1
and an FRR 10.5.3 peer, and the chart refuses what it did not measure: `service.type` must be
`LoadBalancer`, `externalTrafficPolicy` must be `Local`, and `port49d.preStopSeconds` must be at least 15.
Measured: the device's own source address reaches port49d; exactly the nodes running a ready pod advertise
the address; after a pod's listener closes its route left FRR 6.6 s later, with 33 of 33 per-transaction
logins passing; a rolling restart lost no login. Single-connection sessions are not drained by this: two
of four were still open when the window ended, so under anycast prefer per-transaction sessions
(design section 13). tests/lab/results/L85-kind.md has the runs, including the two that led to the
`preStop` wait.

The image is distroless and non-root. The pods meet the Pod Security `baseline` level, and the
namespace needs no weaker one. The volume setup is two init containers. The first runs as root with
`CHOWN`, `FOWNER` and `FSETID` only, all in `baseline`'s list: it sets the volume's root and the data
directory's owner and mode (inodes, never a descent). The second runs as 65532 with every capability
dropped and does the recursive `chmod` inside the data directory, which it owns. A namespace
enforcing `restricted` refuses the root init; use `baseline`. If a file inside the data directory is
owned by another uid (a restore done as root), the second init stops with the path and the one
command to run, `chown -R 65532:65532 <data directory>`, instead of leaving the fence to refuse it
later.

`issuerDiscovery.enabled` (default off) binds `system:unauthenticated` to the issuer-discovery role
for the cluster, which is a cluster-wide change: enable it in one release per cluster, and see
`examples/kubernetes/issuer-discovery.yaml`.

## Backups

Two CronJobs, one pattern (the etcd snapshot job runs in the kind smoke, the enrollments job in its own kind job against a directory, `make kind-enrollments`): `examples/backup-cronjob.yaml` (the etcd
snapshot, which needs etcd's root certificate and is yours to adapt) and the chart's own, off by default:
`--set backup.enrollments.enabled=true --set backup.enrollments.claimName=<your PVC>` (the sealed
enrollment store, `port49-broker export-enrollments --out FILE`; it mounts what the broker does, from
the same template). It exports the enrollment store of a `directory_password` verifier, so the chart refuses
to render it unless `config.broker.broker.identity.humans` has one (otherwise the job would fail every night).
The kind smoke runs the etcd snapshot job only: it has no directory, and a directory refuses the smoke's
policy. The enrollments job reads the sealed enrollment store in etcd (not the directory; the directory is only what the verifier's config needs to load). `make kind-enrollments` runs it against an OpenLDAP pod: `init-enrollments` as the example Job, then the export twice (a dated, non-empty, 0600 file owned by 65532 each, and a log holding only the broker's certificate-validity warning), then once over a stale `enrollments.new` (the job fails and `stale-check`'s log names it). That run exported a freshly initialised store, the mark with no enrolled person: an export holding enrollments is unmeasured. Neither the etcd nor the port49 image has a shell, so:

1. a `stale-check` init container fails the job when `<name>.new` is left from a run that did not
   finish (the failed pod stays, and `kubectl logs` names the file); remove it and the next run goes;
2. the writer init container (`etcdctl snapshot save`, or `export-enrollments --out`) creates
   `<name>.new` 0600 and never replaces a file;
3. an alpine `finish` container does `umask 077`, renames to a dated name and prunes after 14 days.

Nothing sealed is written to a log. The snapshot holds sealed data but is still sensitive; give its
PVC a restrictive access mode. Restore enrollments with `port49 directory import`.

### Velero (file-system backup of the volumes)

`examples/velero/` is a Velero `Schedule` with the steps around it. **A Velero restore that includes
`port49-etcd` is a store restore**: it loses the revocations and lifts made since the backup
and brings back redeemed tokens, so follow the restore runbook,
[Restoring etcd from a snapshot](https://blanketfish.github.io/port49/latest/operate/backup-and-restore/#restoring-etcd-from-a-snapshot) (delete `v1/t/` and `meta/judged`/`meta/judged_bundle`
before the members serve clients, re-issue revocations with `scripts/revoke-offline.sh` (it runs `port49-broker revoke --offline`), lift again). Prefer
restoring etcd from the `etcdctl snapshot` CronJob with `--bump-revision`; a file-system copy of a live member
is crash-consistent at best and unmeasured under load ([L89](https://blanketfish.github.io/port49/latest/reference/lab-register/#l89) measured one restore on an idle cluster). Measured on kind (Velero 1.18.4 with
its node agent, an S3-compatible store in the cluster; `tests/lab/results/L89-kind.md`, 2026-11-04): after a
backup, deleting the namespace and a restore, both StatefulSets became ready with no fence refusal, the
issuing CA's fingerprint was unchanged, the owner, group and mode of `state/`, `issuing-ca.key` and the
spool directory were unchanged (65532:65532, 0700 and 0600), and a mint and a login succeeded. The
measurement used file-system backup because kind has no snapshot-capable CSI driver; CSI snapshots are
not measured here.

- **Restore with the pods running, never with the StatefulSets at 0 replicas.** Velero's file-system
  restore copies a volume through the pod that mounts it; restored at 0 replicas, the restore stayed
  `InProgress` past 8 minutes with every pod volume restore `New` and its pod absent ([L89](https://blanketfish.github.io/port49/latest/reference/lab-register/#l89) cell (c), run
  42053716808). `examples/velero/README.md` has the order (etcd held down while the pods run, then both
  StatefulSets scaled to 0) and the recovery from a restore at 0 replicas.
- **The backup holds the issuing CA's private key** (`state/issuing-ca.key`), each broker's state and the
  accounting spool. **The bucket alone also holds the namespaces' Secrets**, unencrypted by Velero: the
  TACACS+ keys, the store's encryption key, the etcd CA and client identities and the TLS key. The
  repository key protects only the volumes. Protect the bucket like the CA key: server-side encryption, and
  access limited to the backup's own credentials.
- **Set the repository key from your own Secret before installing Velero.** Velero's default repository
  password is a well-known static value, and Velero writes it into `velero-repo-credentials` itself when
  it finds no Secret (`examples/velero/README.md` has the order).
- **Velero skips a hostPath volume with only a warning, and the backup still reads Completed.** The first
  measured run backed up 4 of the namespace's 7 claims: etcd's volumes were hostPath (kind's default
  class), and the backup said "Volume data in pod port49/etcd-0 is a hostPath volume which is not
  supported for pod volume backup, skipping" (lab-kind run 41855911600). The restore then brought etcd back
  empty and port49d never became ready. Put etcd on volumes the node agent can read: list the volumes
  backed by hostPath (a claim and its path per line; no output means none), and move any that appear:

  <!-- l89:hostpath:begin -->
  ```sh
  kubectl get pv -o jsonpath='{range .items[*]}{.spec.claimRef.namespace}/{.spec.claimRef.name} {.spec.hostPath.path}{"\n"}{end}' \
    | grep -E '^(port49|port49-etcd)/' | awk 'NF == 2'
  ```
  <!-- l89:hostpath:end -->

  A claim that no pod mounts (a spool kept after a scale-down, say) is never copied: file-system backup
  reads a volume through the pod that mounts it. So after every backup check each claim in both namespaces
  by name, not by count. This prints every claim without a completed pod volume backup (it assumes
  StatefulSet claim names, `<volume>-<pod>`, as the chart and the etcd example use), and nothing is the pass:

  <!-- l89:claims:begin -->
  ```sh
  backup=<the backup's name>
  comm -23 \
    <(kubectl get pvc -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}' | grep -E '^(port49|port49-etcd)/' | sort) \
    <(kubectl -n velero get podvolumebackups -l velero.io/backup-name=$backup \
        -o jsonpath='{range .items[?(@.status.phase=="Completed")]}{.spec.pod.namespace}/{.spec.volume}-{.spec.pod.name}{"\n"}{end}' | sort)
  ```
  <!-- l89:claims:end -->

  [L89](https://blanketfish.github.io/port49/latest/reference/lab-register/#l89) runs these two commands verbatim, from this file, in CI after its backup (lab-kind run 41870212174): each printed nothing on a good backup, and with a claim no pod mounts the second printed exactly that claim.

  The backup's own warnings, which name a volume Velero skipped:

  ```sh
  velero backup describe <the backup's name> --details | grep -i -A6 warnings
  ```

## Multi-region

`examples/values-multi-region.yaml` gives the session store its own etcd per region with a 500 ms call
timeout; port49d starts without waiting for it.

## The smoke tests

`make kind-smoke` and `make kind-smoke-red` run the chart on a kind cluster, whose nodes are privileged
containers. The smokes run in CI (`.github/workflows/kind.yml`). Locally they refuse to start on a host with a TPM or a security key (`/dev/tpm0`, `/dev/tpmrm0`, a Yubico device on the USB bus); the
refusal is one line that names the device it found.
