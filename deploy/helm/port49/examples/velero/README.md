# Velero, file-system backup of a release's volumes

Measured on kind (lab entry L89, `tests/lab/results/L89-kind.md`): the chart README's "Velero" section has the result. Velero skips a hostPath volume with only a warning: check every claim has a pod volume backup after each backup (chart README).

## What the backup holds

The backup holds `issuing-ca.key`, the issuing CA's private key, in each broker's `state/` directory,
the broker state, and the accounting spool of each port49d. Whoever reads the bucket and the repository
key can issue certificates your devices trust.

The bucket alone holds more. Velero encrypts only the volume data, under the repository key. It stores
the namespaces' Secrets as it reads them, unencrypted: the TACACS+ keys, the store's encryption key, the
etcd CA and client identities, and the TLS key. Read access to the bucket is enough to take them. The
repository key protects the volumes and nothing else. Protect the bucket like the CA key.

## Requirements (decision 55 ruling 10)

1. The repository key is yours, from a Secret, created BEFORE Velero is installed and before the first
   backup. Velero's default repository password is a well-known static value, and Velero writes that
   Secret itself when it starts and finds none. A repository made under the default key keeps it, so a
   backup made first is encrypted with a key everyone knows. Generate the key and create the Secret from
   a file, never from a value on the command line:

   ```sh
   umask 077
   head -c 32 /dev/urandom | base64 > repository-password
   kubectl create namespace velero
   kubectl -n velero create secret generic velero-repo-credentials --from-file=repository-password=./repository-password
   velero install ...
   ```

   Keep a copy outside the cluster: a restore into a new cluster needs it. If Velero already runs and
   has made no backup, delete the Secret Velero made, create yours, and restart the Velero deployment.
2. Apply `schedule.yaml` only after step 1.
3. The bucket must be encrypted at rest (server-side encryption in the object store).
4. Access to the bucket is limited to the backup's own credentials: no other principal, no public access,
   no credentials shared with another workload.

## Pinning the plugin

`velero install --plugins` cannot take an image by digest: Velero names the plugin's init container after
the reference, and a digest makes that name invalid. Give it the tag, then check the running pod's
`imageID` (`kubectl -n velero get pods -o jsonpath='{..initContainerStatuses[*].imageID}'`) against the
digest you reviewed, or mirror the plugin by tag into a registry you control.

## Restore

**A Velero restore that includes `port49-etcd` is a store restore** under design §13 (Deployment
requirements, "A restore rolls the marks back too"). It loses every revocation and lift made since the
backup, so a revoked principal or certificate is admitted again until it is re-issued, and it brings back
every token redeemed since, redeemable again while it has not expired. The backup also restores port49d's
`restore.json` and the brokers' `witness.json` with the store, so neither can tell the restore: the token
delete (design §13 step 3) is required, and it must land before port49d or a broker reaches the restored
store. So the restore is made in this order, with nothing reaching the store until the end.

Run step 2 in this directory (`deploy/helm/port49/examples/velero/`), which holds `restore-unspent.yaml`;
step 8 from the repository root. `<release>` is your Helm release name, `<backup>` the Velero backup,
`<brokers>` and `<port49d>` the `broker.replicas` and `port49d.replicas` you run, `<prefix>` the store
prefix (`/port49/` by default), and `<restore>` a name for the restore of `port49`, new each time you make
one (`port49-restore-1`, then `port49-restore-2`).

**Do not restore `port49` with its StatefulSets at 0 replicas** (a resource modifier setting
`/spec/replicas` to 0, as the `restore-scale-zero.yaml` of earlier versions of this page did). Velero's
file-system restore copies a volume through the pod that mounts it, and at 0 replicas there is none:
measured on kind in L89 cell (c), run 42053716808, the restore stayed `InProgress` past 8 minutes with
every pod volume restore at `New` and its pod absent. It does not finish. If you started one, see
"Recovering from a restore at 0 replicas" below.

So the pods run for the restore, and etcd is held down while they do, so none of them reaches the store.

**First, if a GitOps controller manages the release, suspend it for both namespaces.** These follow Argo
CD's and Flux's documented commands and are not measured in port49's lab (L89 runs no GitOps controller).
Argo CD with
auto-sync or self-heal, or Flux, puts back what this order takes away: it re-creates the
HorizontalPodAutoscaler that step 4 leaves out and reverts step 6's scale to 0, so brokers and port49d
start before etcd is back or before step 8 re-issues the revocations.
**Skipping this can admit a revoked principal** until step 8 runs.

For each Argo CD Application that manages `port49` or `port49-etcd`, first note its sync policy: copy
the `.spec.syncPolicy.automated` object of `argocd app get <app> -o json` as it is (its `prune`,
`selfHeal`, `allowEmpty` and `enabled`), so step 11 restores exactly that. Suspend the parent too when
the app is managed by another (app-of-apps, or generated by an ApplicationSet): the parent's next sync
turns the child's sync back on. For a parent Application, suspend it the same way, first. For an
ApplicationSet, first suspend the Application that syncs the ApplicationSet itself, if one does (or it
puts the ApplicationSet back as Git has it), then keep the ApplicationSet from overwriting the child's
sync policy: add `.spec.syncPolicy` to its `spec.ignoreApplicationDifferences`
(`- jqPathExpressions: [.spec.syncPolicy]`), and remove that again after step 11 (first,
check your Argo CD version supports `ignoreApplicationDifferences`). Then:

```sh
argocd app set <app> --sync-policy none
```

Under Flux, suspend every HelmRelease and every Kustomization that applies `port49` or `port49-etcd`
(the etcd example is plain manifests, reconciled by a Kustomization):

```sh
flux suspend helmrelease <name> -n <namespace>
flux suspend kustomization <name> -n <namespace>
```

Then:

```sh
kubectl delete namespace port49 port49-etcd
```

1. etcd alone. No port49d or broker exists yet, so nothing reaches the store.

<!-- l89:etcdrestore:begin -->
```sh
velero restore create --from-backup <backup> --include-namespaces port49-etcd --wait
kubectl -n port49-etcd wait --for=condition=Ready pod -l app.kubernetes.io/name=etcd --timeout=5m
```
<!-- l89:etcdrestore:end -->

2. The token delete (design §13 step 3), from a one-shot pod holding etcd's root client certificate (the
   Secret `port49-etcd-root`, as `etcd-init-job.yaml` uses it). Edit `PREFIX` in the file if your prefix is
   not `/port49/`.

<!-- l89:deletejob:begin -->
```sh
kubectl apply -f restore-unspent.yaml
state=
for i in $(seq 120); do
  state=$(kubectl -n port49-etcd get job/restore-unspent -o jsonpath='{.status.conditions[?(@.status=="True")].type}')
  case "$state" in *Complete*|*Failed*) break ;; esac
  sleep 2
done
kubectl -n port49-etcd logs job/restore-unspent --all-containers || true
case "$state" in
  *Complete*) kubectl -n port49-etcd delete job/restore-unspent ;;
  *) echo "restore-unspent did not complete ($state): read its log above, and do not go on to step 3" >&2; exit 1 ;;
esac
```
<!-- l89:deletejob:end -->

   This ends when the Job completes or fails, and prints its log either way. If it did not complete, do not
   go on: the log says why. Each delete is its own container (`unspent`, `judged`, `judged-bundle`), so
   `kubectl -n port49-etcd logs job/restore-unspent -c unspent` shows one, and
   `kubectl -n port49-etcd describe job/restore-unspent` has its pods. Delete the Job before applying it
   again. The deletes need a quorum of etcd, not every member: one member not yet answering after the
   restore is fine as long as the Job completes. `context deadline exceeded` from every container means
   no quorum: bring etcd's members back before trying again. The Job runs etcdctl from etcd's own image,
   so it needs no egress.

3. Hold etcd down: `kubectl -n port49-etcd scale statefulset/etcd --replicas=0`.
4. Restore `port49`, without the HorizontalPodAutoscaler (the chart's `autoscaling.enabled`): a pod it
   added while the pods run would have a claim with no backup, and step 5 would find a pod with no line.
   Step 11 brings it back. Its pods start, so the node agent can restore their volumes, and with etcd down they
   cannot reach the store. The lab cannot hold its etcd down apart from the release (one namespace), so
   L89 (d) runs this command with its etcd up.

<!-- l89:restore:begin -->
```sh
velero restore create <restore> --from-backup <backup> --include-namespaces port49 \
  --exclude-resources horizontalpodautoscalers.autoscaling --wait
```
<!-- l89:restore:end -->

5. Check that the volumes came back, by the restore's name. This prints the restore's phase, then one
   line per pod volume restore:

<!-- l89:volumes:begin -->
```sh
kubectl -n velero get restore <restore> -o jsonpath='{.status.phase}{"\n"}'
kubectl -n velero get podvolumerestores -l velero.io/restore-name=<restore> -o custom-columns=PHASE:.status.phase,POD:.spec.pod.name,VOLUME:.spec.volume
```
<!-- l89:volumes:end -->

   The phase must be `Completed`, and there must be a `Completed` line with volume `data` for every
   broker pod (`<release>-broker-0`, `-1`, ...) and every port49d pod (`<release>-port49d-0`, ...). A
   pod with no line did not have its volume restored. A line still `New` or `InProgress` is still copying: run the
   check again. **Never go on to step 7 while the restore or any of these lines is not `Completed`.** A
   broker that starts on an empty `state_dir` puts back none of the revocations the store restore lost.
   If one is missing or `Failed`, stop: no broker or port49d has reached the store, so start over from
   the first command with a new `<restore>`.
6. Scale both StatefulSets to 0, and wait until no port49 pod is left.

<!-- l89:scalezero:begin -->
```sh
kubectl -n port49 scale statefulset/<release>-broker statefulset/<release>-port49d --replicas=0
kubectl -n port49 wait --for=delete pod -l app.kubernetes.io/name=port49 --timeout=3m
```
<!-- l89:scalezero:end -->

7. Bring etcd back: `kubectl -n port49-etcd scale statefulset/etcd --replicas=3`, and wait for it as
   step 1 does.

Then, with no broker and no port49d running:

8. Re-issue the revocations made since the backup (design §13 step 4). The script leaves the brokers at the 0
   it finds. Run it from the repository root.

<!-- l89:revoke:begin -->
```sh
deploy/helm/port49/scripts/revoke-offline.sh port49 <release> -- --principal user:bob@example.com
```
<!-- l89:revoke:end -->

9. The brokers first, a broker whose `broker.state_dir` survived the restore first (the check in step 5
   showed every broker's volume restored, so any of them does); then port49d.

<!-- l89:scaleup:begin -->
```sh
kubectl -n port49 scale statefulset/<release>-broker --replicas=<brokers>
kubectl -n port49 rollout status statefulset/<release>-broker --timeout=10m
kubectl -n port49 scale statefulset/<release>-port49d --replicas=<port49d>
kubectl -n port49 rollout status statefulset/<release>-port49d --timeout=10m
```
<!-- l89:scaleup:end -->

10. Lift again what was lifted since (design §13 step 6).
11. Bring back what step 4 left out, and resume what you suspended first. With a GitOps controller,
    resuming it does both (unmeasured, as above). Under Argo CD, put back the `automated` object you
    noted, exactly, children first, then any parent and the Application that syncs an ApplicationSet:

```sh
argocd app patch <app> --type merge -p '{"spec":{"syncPolicy":{"automated":<noted JSON>}}}'
```

    Under Flux, resume each one you suspended:

```sh
flux resume helmrelease <name> -n <namespace>
flux resume kustomization <name> -n <namespace>
```

    Without one, upgrade the release to the chart version it runs, which re-creates the
    HorizontalPodAutoscaler and changes nothing else:

```sh
helm upgrade <release> <chart> --version <version> -n port49 --reuse-values
```

With the chart's `autoscaling.enabled`, the HPA is not restored (step 4) until step 11.

### Recovering from a restore at 0 replicas

A restore made with the StatefulSets at 0 replicas waits for pods that never start, and Velero restores
one at a time, so it holds up every restore after it. No broker or port49d ran, so nothing reached the
store. Restart Velero, delete that restore (`<restore>` here is its name), then start over from the first
command above with a new `<restore>`. Measured on kind in L89 cell (d), run 42058930263, on (c)'s hung
restore: after these commands the restore was gone and no restore was `New` or `InProgress`.

<!-- l89:recover:begin -->
```sh
kubectl -n velero rollout restart deployment/velero
kubectl -n velero rollout status deployment/velero --timeout=5m
velero restore delete <restore> --confirm
kubectl -n velero wait --for=delete restore/<restore> --timeout=5m
```
<!-- l89:recover:end -->

Prefer restoring etcd from the `etcdctl snapshot` CronJob (`backup-cronjob.yaml`) with `--bump-revision`,
as design §13 gives it, and use Velero for the other volumes. A file-system copy of a live etcd member is
crash-consistent at best, and the three members are copied at different moments; whether a busy member's
database survives that is unmeasured. L89 measured one restore on an idle cluster.

The data-directory init containers refuse a volume whose files are not owned by uid 65532 (see the
chart README), so what a restore does to ownership, group and mode matters. L89 (a) measured it on kind:
owner, group and mode of `state/`, `issuing-ca.key` and the spool directory were unchanged, and both
StatefulSets became ready with no fence refusal.
