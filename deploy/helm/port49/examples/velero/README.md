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
store. So the restore is made in this order, with nothing running against the store until the end.

Run steps 2 and 3 in this directory (`deploy/helm/port49/examples/velero/`), which holds `restore-token-delete.yaml` and
`restore-scale-zero.yaml`; step 4 from the repository root. `<release>` is your Helm release name, `<backup>` the Velero backup, `<brokers>` and `<port49d>` the
`broker.replicas` and `port49d.replicas` you run, and `<prefix>` the store prefix (`/port49/` by default).

```sh
kubectl delete namespace port49 port49-etcd

# 1. etcd alone. No port49d or broker exists yet, so nothing reaches the store.
velero restore create --from-backup <backup> --include-namespaces port49-etcd --wait
kubectl -n port49-etcd wait --for=condition=Ready pod -l app.kubernetes.io/name=etcd --timeout=5m

# 2. The token delete (design §13 step 3), from a one-shot pod holding etcd's root client
#    certificate (the Secret port49-etcd-root, as etcd-init-job.yaml uses it). Edit PREFIX in the file
#    if your prefix is not /port49/.
kubectl apply -f restore-token-delete.yaml
kubectl -n port49-etcd wait --for=condition=complete job/restore-token-delete --timeout=3m
kubectl -n port49-etcd logs job/restore-token-delete
kubectl -n port49-etcd delete job/restore-token-delete

# 3. Everything else, with both StatefulSets at 0 replicas, so no broker or port49d starts yet.
kubectl -n velero create configmap restore-scale-zero --from-file=restore-scale-zero.yaml
velero restore create --from-backup <backup> --include-namespaces port49 \
  --resource-modifier-configmap restore-scale-zero --wait
```

Then, with no broker and no port49d running:

```sh
# 4. Re-issue the revocations made since the backup (design §13 step 4). The script leaves the brokers
#    at the 0 it finds. Run it from deploy/helm/port49/scripts/ of the chart you installed.
deploy/helm/port49/scripts/revoke-offline.sh port49 <release> -- --principal user:bob@example.com

# 5. The brokers first, a broker whose broker.state_dir survived the restore first (the restore brings
#    every broker's volume back, so any of them does); then port49d.
kubectl -n port49 scale statefulset/<release>-broker --replicas=<brokers>
kubectl -n port49 rollout status statefulset/<release>-broker --timeout=10m
kubectl -n port49 scale statefulset/<release>-port49d --replicas=<port49d>
kubectl -n port49 rollout status statefulset/<release>-port49d --timeout=10m

# 6. Lift again what was lifted since (design §13 step 6).
```

With the chart's `autoscaling.enabled`, the HPA owns port49d's replica count and scales it up itself:
pause it (delete the HorizontalPodAutoscaler) until step 5.

Prefer restoring etcd from the `etcdctl snapshot` CronJob (`backup-cronjob.yaml`) with `--bump-revision`,
as design §13 gives it, and use Velero for the other volumes. A file-system copy of a live etcd member is
crash-consistent at best, and the three members are copied at different moments; whether a busy member's
database survives that is unmeasured. L89 measured one restore on an idle cluster.

The data-directory init containers refuse a volume whose files are not owned by uid 65532 (see the
chart README), so what a restore does to ownership, group and mode matters. L89 (a) measured it on kind:
owner, group and mode of `state/`, `issuing-ca.key` and the spool directory were unchanged, and both
StatefulSets became ready with no fence refusal.
