# Velero, file-system backup of a release's volumes

UNVERIFIED until lab entry L89 closes (`tests/lab/results/L89-kind.md`). Read the note before relying on this.

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

## Restore

```sh
kubectl delete namespace port49
velero restore create --from-backup <backup> --wait
```

The data-directory init containers refuse a volume whose files are not owned by uid 65532 (see the
chart README), so what a restore does to ownership, group and mode matters: L89 (a) measures it, and the
note is the answer.
