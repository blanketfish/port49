# port49 Helm chart

The chart runs `port49d` and `port49-broker` as two StatefulSets, a PVC per replica, against an etcd you
supply.

<!-- --8<-- [start:install] -->
Run the commands from the repository root. You need a cluster, `kubectl` and `helm`, and a namespace for
the release (the examples use `port49`).

## 1. Create the Secrets

Create each Secret with `--from-file`, never `--from-literal`, so no secret reaches a shell history or a
process list:

```sh
kubectl -n port49 create secret generic port49-device-keys --from-file=core_v1=./core_v1
kubectl -n port49 create secret generic port49-encryption --from-file=encryption.key=./encryption.key
kubectl -n port49 create secret generic port49-etcd-ca --from-file=ca.crt=./etcd-ca.crt
kubectl -n port49 create secret generic port49-etcd-port49d --from-file=tls.crt=./port49d.crt --from-file=tls.key=./port49d.key
kubectl -n port49 create secret generic port49-etcd-broker --from-file=tls.crt=./broker-etcd.crt --from-file=tls.key=./broker-etcd.key
kubectl -n port49 create secret generic port49-broker-tls --from-file=tls.crt=./broker.crt --from-file=tls.key=./broker.key --from-file=ca.crt=./client-ca.crt
```

The device keys Secret holds one key per version, named `<ref>_v<N>` in the policy. The encryption key is 32
bytes, the same in both pods. To check, run `kubectl -n port49 get secret`. All six are listed.

To sync the device keys from Vault instead, use `examples/external-secret.yaml`: one Secret key per version
(`core_v1`, `core_v2`), each from its own remote key, so adding a version adds a remote key and an entry.

!!! warning "A ClusterSecretStore can be read from every namespace"
    The example's store is a namespaced `SecretStore`, usable only from the release's namespace. A
    cluster-wide `ClusterSecretStore` without `conditions` lets anyone who can create an ExternalSecret
    anywhere read the device keys through your Vault role. `examples/external-secret-clusterstore.yaml`
    shows the option, with the namespace named.

## 2. Bring up etcd

port49 does not create or run etcd. `examples/etcd/` is a three-member example (the kind smoke runs it with
its init Job). port49 needs three members, etcd 3.4.24, 3.5.8 or 3.6 or later, and its own cluster.

!!! info "etcd's disk"
    etcd needs sustained WAL fsync p99 under 10 ms. See
    [Requirements](https://blanketfish.github.io/port49/latest/reference/requirements/#etcd-disk).

To check, run `kubectl -n port49-etcd get pods`. All three members are `Ready`.

## 3. Apply port49's etcd roles

Make the roles script from your two configs. The broker's config names the broker's own etcd certificate:

```sh
port49d store-roles --config port49d.yaml --broker-config port49-broker.yaml > roles.sh
kubectl -n port49-etcd create configmap port49-etcd-roles --from-file=roles.sh
kubectl -n port49-etcd apply -f deploy/helm/port49/examples/etcd/etcd-init-job.yaml
```

The Job applies the output as etcd's root and enables auth. Its header comment says which Secrets it
needs. To check, run `kubectl -n port49-etcd wait --for=condition=complete job/etcd-init --timeout=300s`.
The Job completes.

## 4. Install the chart

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

Four values are required:

1. `etcd.endpoints`: every member, at least three. The schema refuses fewer, a repeated or non-https
   member, and an empty Secret name. A client given one URL has no failover.
2. `keys.existingSecret`: mounted whole at `/run/port49/keys`, in port49d's pod only, mode 0440 under
   `fsGroup` (measured on kind: [L82](https://blanketfish.github.io/port49/latest/reference/lab-register/#l82)).
3. `encryption.existingSecret` and `encryption.id`: mounted in both pods.
4. `policy` and `inventory`, with `--set-file`. Without a policy port49d refuses to start.

The release namespace must enforce Pod Security `baseline`. The volume setup is two init containers. The
first runs as root with `CHOWN`, `FOWNER` and `FSETID` only, all in `baseline`'s list. A namespace
enforcing `restricted` refuses it, so no pod is created. To label the namespace, run:

```sh
kubectl label --overwrite ns port49 pod-security.kubernetes.io/enforce=baseline
```

Then pick the sign-in backend.

=== "OIDC"

    Add `-f deploy/helm/port49/examples/values-issuance.yaml` to the install, with the issuer, client and
    domain replaced. The values replace the chart's `humans` list, so keep the `x509` entry in it if people
    also sign in with client certificates, or the broker stops accepting them.
    [OIDC sign-in](https://blanketfish.github.io/port49/latest/admin/sign-in/oidc/) has the block.

=== "Client certificate (x509)"

    The chart trusts `ca.crt` from `broker.tls.existingSecret` for client certificates and asks each
    certificate's own OCSP responder. If your CA has none, set `crls:` under
    `config.broker.broker.certificate_status` before the first sign-in.
    [Client certificates](https://blanketfish.github.io/port49/latest/admin/sign-in/x509/) has the block.

=== "Directory password"

    Set `broker.site` (the same for every replica of a release) and, for a Kerberos bind,
    `broker.directory.keytabSecret`: a Secret holding the keytab and `krb5.conf`, mounted at
    `/etc/port49/directory`. [Directory password](https://blanketfish.github.io/port49/latest/admin/sign-in/directory-password/)
    and [The directory](https://blanketfish.github.io/port49/latest/admin/directory/) have the blocks.

To check, run:

```sh
kubectl -n port49 get pods
kubectl -n port49 port-forward <release>-port49d-0 9049:9049 &
curl -fsS 127.0.0.1:9049/readyz
```

Every pod is `Ready` and `/readyz` prints `serving`. A schema refusal names the value at fault before
anything is created.

## 5. The issuing CA

Only when issuance is on (the OIDC and directory password tabs turn it on). It needs
`-f examples/values-issuance.yaml` first, so that `broker.identity.issuance` is set: `init-issuer` refuses a
broker without it. Every broker must hold the same issuing CA, or it refuses to start against the store's
record of it. After the first install run, once:

```sh
deploy/helm/port49/scripts/copy-issuer.sh port49 port49 --from 0
```

`--from` names the broker whose CA is the one to keep. If no broker holds a CA, the script makes one in a
one-shot pod. It copies the CA to each other broker, refuses to overwrite a different one (naming both
sha256s), restarts the brokers and prints each pod's `issuing as` log line.

To check, compare those lines. The `(sha256:...)` fingerprint is the same on every broker.

A broker whose volume was lost gets its CA from one that has it, never from `init-issuer`:

```sh
deploy/helm/port49/scripts/copy-issuer.sh port49 port49 --from 1 --to 0
```

!!! warning "Do not run forget-issuer"
    It removes the store's record of the CA, and every certificate issued under the old CA stops working.
    It is for the case where every broker lost the CA and no copy exists.

## 6. Create the enrollment store

Only for directory password sign-in. Adapt the names in `examples/init-enrollments-job.yaml` to your values,
then run:

```sh
kubectl -n port49 apply -f deploy/helm/port49/examples/init-enrollments-job.yaml
kubectl -n port49 wait --for=condition=complete job/port49-init-enrollments --timeout=300s
```

The Job completes. A broker that is already running finds the new store within 30 seconds, and until then
its sign-ins answer `enrollment_store_lost`.

## 7. Expose port 49

port49d admits a device by the address it sees, so the device's source address must reach it unrewritten.
`service.type` defaults to LoadBalancer with `externalTrafficPolicy: Local`. Measured on kind
([L39](https://blanketfish.github.io/port49/latest/reference/lab-register/#l39), kube-proxy in iptables
mode, a device outside every node, a NodePort Service):

| Setting, and where the device dials | Result |
|---|---|
| `Cluster`, a node running the pod | fails: the source port49d sees is a pod-network address |
| `Cluster`, a node not running the pod | fails: the source is that node's own address |
| `Local`, a node running the pod | works: port49d sees the device's own address |
| `Local`, a node not running the pod | times out, and port49d logs nothing |

Keep `Local`. Under `Local`, give devices the LoadBalancer address, not a node's address: a pod that moves
leaves its old node answering nothing. MetalLB in BGP mode advertises the address only from nodes with a
ready pod ([L85](https://blanketfish.github.io/port49/latest/reference/lab-register/#l85) measured that). For
an anycast address, set `service.anycast.enabled: true` and `service.anycast.address`. The chart then
requires `service.type: LoadBalancer`, `externalTrafficPolicy: Local` and `port49d.preStopSeconds` of at
least 15, and refuses anything else.

!!! warning "Unmeasured"
    A cloud load balancer has not been measured.

To check, run a TACACS+ login from a device. `port49d` logs the device's own address, and the decision log
holds a `redeem` record with `verdict: permit`.

## Optional steps

The details of each are under
[Chart options](https://github.com/blanketfish/port49/blob/main/deploy/helm/port49/README.md#chart-options)
in the chart README.

- Autoscaling: `autoscaling.enabled` renders an HPA.
- Alerts and scraping: `prometheusRule.enabled: true`.
- TACACS+ over TLS: `tlsListener.enabled`, with [TLS](https://blanketfish.github.io/port49/latest/operate/tls/).
- Several regions: [Stores](https://blanketfish.github.io/port49/latest/operate/stores/#several-regions).
- Backups: [Backup and restore](https://blanketfish.github.io/port49/latest/operate/backup-and-restore/) and
  [Back up with Velero](https://blanketfish.github.io/port49/latest/operate/helm/velero/).
- Issuer discovery: `issuerDiscovery.enabled`, a cluster-wide change.
<!-- --8<-- [end:install] -->

## Chart options

- **Autoscaling.** `autoscaling.enabled` renders an HPA on the `port49_connections` Pods metric. It needs a
  metrics adapter you provide. A scale-down leaves the removed pod's spool on its PVC, so drain it before
  deleting the PVC. Scaling down or deleting the release retains the PVCs.
- **Alerts and scraping.** `prometheusRule.enabled: true` renders the alert rules and a `PodMonitor` per
  workload that sets `job` to `port49d` and `port49-broker`. Both need the Prometheus Operator's CRDs, and
  `prometheusRule.labels` must be the ones your Prometheus selects on. The metrics ports (9049 and 9050)
  listen on every pod address: admit only your Prometheus and the kubelet with a NetworkPolicy. The chart
  renders none.
- **TACACS+ over TLS.** `tlsListener.enabled` adds port 300 and needs `tlsListener.existingSecret`.
- **Several regions.** `examples/values-multi-region.yaml` gives the session store its own etcd per region.
- **Issuer discovery.** `issuerDiscovery.enabled` (off) binds `system:unauthenticated` to the issuer-discovery
  role for the whole cluster. Enable it in one release per cluster. See
  `examples/kubernetes/issuer-discovery.yaml`.

## Key versions

**Order matters.** Put the key file in place first, then add the policy line that names it. To remove a
key, take the policy line out first, then the file. The other order is a 3am outage: a policy line naming a
file that is not there makes port49d refuse its start (`lstat ...: no such file`), so on a restart it
crash-loops until you restore the key in the Secret or take the policy line out; the pod shows `CrashLoopBackOff` and `kubectl logs --previous` repeats the line.

<!-- moved: docs/site/admin/key-rotation.md (Rotating the `encryption:` key) -->
Rotating the `encryption:` key: [Key rotation](https://blanketfish.github.io/port49/latest/admin/key-rotation/).

<!-- moved: docs/site/operate/secrets.md (Secrets and rotation) -->
Mounts, the secret-file rule and the secret agents that were measured: [Secrets](https://blanketfish.github.io/port49/latest/operate/secrets/).

<!-- moved: docs/site/operate/backup-and-restore.md (Backups, Velero) -->
Backup CronJobs and Velero: [Backup and restore](https://blanketfish.github.io/port49/latest/operate/backup-and-restore/).

## Velero checks

Velero skips a hostPath volume with only a warning, and the backup still reads Completed. List the volumes
backed by hostPath (a claim and its path per line; no output means none), and move any that appear:

<!-- l89:hostpath:begin -->
```sh
kubectl get pv -o jsonpath='{range .items[*]}{.spec.claimRef.namespace}/{.spec.claimRef.name} {.spec.hostPath.path}{"\n"}{end}' \
  | grep -E '^(port49|port49-etcd)/' | awk 'NF == 2'
```
<!-- l89:hostpath:end -->

After every backup, check each claim in both namespaces by name, not by count. This prints every claim
without a completed pod volume backup (it assumes StatefulSet claim names, `<volume>-<pod>`, as the chart
and the etcd example use), and nothing is the pass:

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

<!-- moved: docs/site/admin/revocation.md (Break-glass) -->
Break-glass revoke with no broker reachable: [Revoking access](https://blanketfish.github.io/port49/latest/admin/revocation/).

<!-- --8<-- [start:upgrade] -->
Read the [release notes](https://github.com/blanketfish/port49/releases) and
[Versions and upgrades](https://blanketfish.github.io/port49/latest/operate/versions/) first. They say whether
the release changes the roles, the values or the sealing key.

## 1. Upgrade the release

```sh
helm upgrade port49 deploy/helm/port49 -n port49 --reuse-values
```

Pass the same `-f` and `--set` flags as the install if you do not use `--reuse-values`. To check, run:

```sh
kubectl -n port49 rollout status statefulset/port49-port49d
kubectl -n port49 rollout status statefulset/port49-broker
```

Both rollouts complete and every pod is `Ready`.

## 2. Re-run the roles Job when the release notes say so

Make `roles.sh` again with `port49d store-roles`, replace the `port49-etcd-roles` ConfigMap, and run the
etcd roles Job as in the install. port49d does not apply roles for you. It refuses to start for some missing
grants and names `port49d store-roles` in the line, but it does not check every grant.

## 3. Keep a login from dropping during a rollout

A terminating port49d pod keeps serving for `port49d.preStopSeconds` (default 15) before it closes its
listeners, so the route to it is withdrawn first. Without the wait, a login that a router or load balancer
still sent to the pod was refused: with MetalLB over BGP the route left the router 6.6 s after the listener
closed ([L85](https://blanketfish.github.io/port49/latest/reference/lab-register/#l85) c, measured on kind),
and a rolling restart without the wait lost one login of 42 past its retry ([L85](https://blanketfish.github.io/port49/latest/reference/lab-register/#l85) d). With the 15 s wait it lost
none (55 of 55). The image has no shell, so the wait is the kubelet's own `sleep` action, which needs
Kubernetes 1.30 or later. On an older cluster set `port49d.preStopSeconds: 0`.

`port49d.terminationGracePeriodSeconds` (default 60) must be at least the sleep plus 30, port49d's longest
drain. The chart refuses a smaller value.

## 4. Two groups of servers

Two server groups, for example a lab and production, are two releases in two namespaces with their own
Secrets and their own etcd. They share nothing. Upgrade one release, check it, then the other.
<!-- --8<-- [end:upgrade] -->

<!-- --8<-- [start:troubleshoot] -->
`kubectl logs --previous <pod>` holds the line of a pod in `CrashLoopBackOff`. Each refusal names the file,
the field or the reference, never a value.

## What you see

| You see | Look at | Cause and action |
|---|---|---|
| Pod `CrashLoopBackOff` | `kubectl logs --previous <pod>` | The config or a Secret is wrong; the log names the field or reference, never its value. |
| Pod `ContainerCreating` for minutes | `kubectl describe pod <pod>` (the Events) | A named Secret or ConfigMap is missing: a kubelet event, never a port49 line. |
| Pod `Pending` | `kubectl describe pod <pod>` | A named PVC is missing or unbound, or nothing can be scheduled. |
| port49d refuses to start naming etcd and a version | `kubectl logs --previous <pod>` | A member is below the floor (3.4.24, 3.5.8 or 3.6); upgrade etcd. Every member is listed and checked. |
| Not Ready, running | `curl :9049/readyz` through a port-forward | Not serving yet: the body says why (`starting`, `waiting for the store`, `draining`). It does not name the store; `port49 store status` does. |
| Admin call 503 | the broker log | No attestation roots configured: set `broker.attestationRootsConfigMap`. |
| No pod is ever created; the StatefulSet's events say `violates PodSecurity` | `kubectl -n <ns> describe statefulset <name>` | The namespace enforces `restricted`. The data-dir init runs as root (it makes the volume's root 3770 and the data directory 0700), so the namespace must be `baseline`: `kubectl label --overwrite ns <ns> pod-security.kubernetes.io/enforce=baseline`. |
| Pod `Init:Error` or `Init:CrashLoopBackOff` | `kubectl logs <pod> -c data-dir` and `-c data-dir-owner` (`describe` shows only the exit code) | `data-dir-owner` naming a path: a file in the data directory belongs to another uid; run the `chown -R 65532:65532 ...` it prints. Naming a directory that may be mode 0000: `chmod u+rwx` it as root on the volume, then restart. `data-dir` saying the data directory is a symlink: someone replaced it; inspect and remove the link. Otherwise the root init failed and its log names the command: usually a PVC that refuses chown, or a namespace policy that drops its capabilities. |
| Brokers disagree on the CA, or one refuses to start on it | the broker's `issuing as` log line; `copy-issuer.sh` output | Copy from a broker that holds the CA the store records, onto one that holds none: `copy-issuer.sh <ns> <release> --from <ordinal> --to <ordinal>`. It never overwrites a CA: onto a broker that holds a different one, including one behind a promotion after a rotation, it refuses and names both, and you copy by hand (below). Never `init-issuer` again, and not `forget-issuer`. |
| A backup Job failed | `kubectl logs job/<name> -c stale-check` | A `.new` file is left from a run that did not finish; the log names it. Neither backup image has a shell: remove it from a throwaway alpine pod that mounts the backups PVC (`kubectl run`, `rm /backup/<name>.new`), and the next run proceeds. |
| `kubectl get externalsecret` shows `SecretSyncedError` | `kubectl describe externalsecret <name>` | The external secrets operator cannot reach its store or a remote key. The Secret keeps its last data, so a new key version never appears and port49d names the missing `secret_ref`. |

## A broker refused "behind a promotion"

After a CA rotation, a broker that missed the copy refuses to start and the pod crash-loops with:

```text
issuance: this broker's issuing CA (<fingerprint>) is behind a promotion: the store records <fingerprint>, promoted from it by <broker> at <time>. Copy issuing-ca.pem, issuing-ca.key and issuing-ca-previous.pem from that broker into broker.state_dir, then start
```

The chart's `scripts/copy-issuer.sh` cannot fix it: it never overwrites a broker's CA, and this broker
holds the old one. Copy the three files by hand:

1. Find the broker the line names, and the two PVCs. The chart's StatefulSet is `<release>-broker`. It
   makes one claim per ordinal, `data-<release>-broker-<ordinal>`, and the files live in `state/`
   inside it.
2. Start a throwaway debug pod for each PVC.
    - The claims are `ReadWriteOnce`, which only one node can mount. Set each debug pod's `nodeName` to
      the node of the broker pod that holds that claim, or the debug pod stays pending.
    - The port49 image has no shell, so use an image that has one, such as a throwaway alpine pod.
3. Read the three files off the source broker's claim, mounted `readOnly: true`.
   `kubectl exec ... -- tar c -C /s/state issuing-ca.pem issuing-ca.key issuing-ca-previous.pem`
   streams them. Write them into `state/` on the crash-looping broker's claim, with owner 65532:65532
   and mode 0600.
4. Delete the debug pods and let the broker start. Compare the `issuing as ... (sha256:<fingerprint>)`
   line on every broker; the fingerprints must be identical.

Two commands look like fixes and are not:

- Do not run `init-issuer` on this broker. It would make a different CA.
- Do not run `forget-issuer`. Every certificate the old CA issued would stop working.

The [key rotation page](https://blanketfish.github.io/port49/latest/admin/key-rotation/#the-three-refusals)
has the other two refusals. The words every refusal prints are in the
[3am index](https://blanketfish.github.io/port49/latest/operate/troubleshooting/).
<!-- --8<-- [end:troubleshoot] -->

## More

- [Install overview](https://blanketfish.github.io/port49/latest/operate/deploy/)
- [Admin access](https://blanketfish.github.io/port49/latest/admin/admin-access/)
- [Deployment design](https://blanketfish.github.io/port49/latest/contributing/deployment-design/): the
  volume root, the init containers and the smoke tests
