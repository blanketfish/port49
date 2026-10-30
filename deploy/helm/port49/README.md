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

A key is read under the secret-file rule, so two things are refused at the pod's start, each with a line
naming the file. A key directory that is group- or world-writable (outside a read-only Secret mount, which
is excused): `chmod 0755` or `0750` it. A group-readable key whose group is not the pod's (fsGroup 65532
is): a Secret volume's files are, and a file a CSI driver or an injector writes as `root:root` 0440 is not;
the remedy is the driver's own setting, `filePermission: 0400` for the Secrets Store CSI provider, so the
group bit is gone, never a looser rule (L83 records which drivers need it).

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

Unverified against a real kubelet until Task 11's kind smoke. Its two-generation cell must use a
volume type the kubelet applies fsGroup to (a `local` volume or csi-hostpath, never kind's default
hostPath class, which never applies it): install, delete the pod, and check the broker starts again,
the root is `3770 root:65532` and `state/issuing-ca.key` is still 0600. Run first with the old 2755
root it must crash-loop on the `state_dir` refusal, which proves the cell detects it.

`examples/external-secret.yaml` syncs the device keys from Vault with External Secrets: one Secret key
per key version (`core_v1`, `core_v2`), each from its own remote key. Adding a version is adding a
remote key and an entry; nothing is overwritten, so a rollback is still a file on disk. Vault Agent
and the Secrets Store CSI driver are unmeasured here (L83) and not documented as supported.

**Order matters.** Put the key file in place first, then add the policy line that names it. To remove a
key, take the policy line out first, then the file. The other order is a 3am outage: a policy line naming a
file that is not there makes port49d refuse its start (`lstat ...: no such file`), so on a restart it
crash-loops until you restore the key in the Secret or take the policy line out; the pod shows `CrashLoopBackOff` and `kubectl logs --previous` repeats the line.
The example's store is a namespaced `SecretStore`, usable only from the release's namespace. A
cluster-wide `ClusterSecretStore` without `conditions` can be used from every namespace: anyone who
can create an ExternalSecret anywhere could read the device keys through your Vault role.
`examples/external-secret-clusterstore.yaml` shows the option, with the namespace named.

To rotate the encryption key, add the new key to the Secret, set `encryption.id` to a new id, and
upgrade; port49 reads old ids until nothing is sealed under them (see the operator guide).

## The issuing CA

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
broker-0's volume, and scales back on every exit. `init-revocations` and `init-enrollments` are
one-off Jobs, run once per new deployment.

## At 3am

| You see | Look at | Cause and action |
|---|---|---|
| Pod `CrashLoopBackOff` | `kubectl logs --previous <pod>` | The config or a Secret is wrong; the log names the field or reference, never its value. |
| Pod `Pending` | `kubectl describe pod <pod>` | A named Secret or PVC is missing. |
| Not Ready, running | `curl :9049/readyz` through a port-forward | A store is unreachable; the body says which. |
| Admin call 503 | broker log | No attestation roots configured. |
| Brokers disagree on the CA, or one refuses to start on it | the broker's "issuing ca" log line; `copy-issuer.sh` output | Copy from a broker that holds the CA the store records, onto the one that differs: `copy-issuer.sh <ns> <release> --from <ordinal> --to <ordinal>`. It refuses to overwrite a different CA and names both; never `init-issuer` again, and not `forget-issuer`. |
| Pod `Init:Error` or `Init:CrashLoopBackOff` | `kubectl logs <pod> -c data-dir` and `-c data-dir-owner` (`describe` shows only the exit code) | `data-dir-owner` naming a path: a file in the data directory belongs to another uid; run the `chown -R 65532:65532 ...` it prints. `data-dir-owner` saying a directory may be mode 0000: `chmod u+rwx` it (as root on the volume), then restart. `data-dir` saying the data directory is a symlink: someone replaced it; inspect and remove the link. Otherwise the root init that sets up the volume failed; its log names the command. Usually a PVC that cannot be chowned (a read-only or network volume that refuses chown), or a namespace policy that drops its capabilities. |
| No pod is ever created; the StatefulSet's events say `violates PodSecurity` | `kubectl -n <ns> describe statefulset <name>` | The namespace enforces `restricted`. The data-dir init runs as root (it makes the volume's root 3770 and the data directory 0700), so the namespace must be `baseline` (README, Install). |
| A backup Job failed | `kubectl logs job/<name> -c stale-check` | A `.new` file is left from a run that did not finish; the log names it. Neither backup image has a shell: remove it from a throwaway alpine pod that mounts the backups PVC (`kubectl run`, `rm /backup/<name>.new`), and the next run proceeds. |
| `kubectl get externalsecret` shows `SecretSyncedError` | `kubectl describe externalsecret <name>` | ESO cannot reach the store or a remote key. The Secret keeps its last data, so a new key version never appears and port49d names the missing `secret_ref`. |

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

Two CronJobs, one pattern (UNVERIFIED until the kind smoke): `examples/backup-cronjob.yaml` (the etcd
snapshot, which needs etcd's root certificate and is yours to adapt) and the chart's own, off by default:
`--set backup.enrollments.enabled=true --set backup.enrollments.claimName=<your PVC>` (the sealed
enrollment store, `port49-broker export-enrollments --out FILE`; it mounts what the broker does, from
the same template). Neither the etcd nor the port49 image has a shell, so:

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

## The smoke tests

`make kind-smoke` and `make kind-smoke-red` run the chart on a kind cluster, whose nodes are privileged
containers. The smokes run in CI (their workflow lands with plan 12b Task 13). Locally they refuse to start on a host with a TPM or a security key (`/dev/tpm0`, `/dev/tpmrm0`, a Yubico device on the USB bus); the
refusal is one line that names the device it found.
