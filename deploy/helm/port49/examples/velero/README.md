# Velero, file-system backup of a release's volumes

UNVERIFIED until lab entry L89 closes (`tests/lab/results/L89-kind.md`). Read the note before relying on this.

## What the backup holds

The backup holds `issuing-ca.key`, the issuing CA's private key, in each broker's `state/` directory,
the broker state, and the accounting spool of each port49d. Treat the bucket as you treat the key: whoever
reads the bucket and the repository key can issue certificates your devices trust.

## Requirements (decision 55 ruling 10)

1. The repository key is yours, from a Secret, set before the first backup. Velero's default is well
   known and is used when the Secret is absent. Generate it and create the Secret from a file, never
   from a value on the command line:

   ```sh
   umask 077
   head -c 32 /dev/urandom | base64 > repository-password
   kubectl -n velero create secret generic velero-repo-credentials --from-file=repository-password=./repository-password
   ```

   Keep a copy outside the cluster: a restore into a new cluster needs it.
2. The bucket must be encrypted at rest (server-side encryption in the object store).
3. Access to the bucket is limited to the backup's own credentials: no other principal, no public access,
   no credentials shared with another workload.

## Restore

```sh
kubectl delete namespace port49
velero restore create --from-backup <backup> --wait
```

The data-directory init containers refuse a volume whose files are not owned by uid 65532 (see the
chart README), so what a restore does to ownership, group and mode matters: L89 (a) measures it, and the
note is the answer.
