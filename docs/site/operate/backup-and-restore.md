---
title: Backup and restore
description: What to back up, how to restore it, and what a restore does to live sessions.
---

# Backup and restore

Read the first section before you need it. A restore is the one routine operation that can admit a
person you revoked, so its steps run in a fixed order and each safety step has a check.

## What a restore does

A restore puts the store back to the moment of its snapshot. Two things follow, and the rest of this page
exists to undo them:

- **Revocations made since the snapshot are gone, and lifts made since are undone.** A revoked
  principal or certificate is admitted again until the revocation is put back.
- **Every single-use token redeemed since the snapshot is back, unspent.** Redeemable again until it
  expires (a token lives at most 15 minutes).

port49 defends against both on its own, and still asks you for steps, because some restores it cannot
see (below). Keep the order of the runbook: the token delete comes before anything reaches the store,
and the revocations are re-issued before any broker starts.

## What to back up

All three deployments ([systemd](systemd/install.md), [containers](containers/install.md),
[Helm](helm/install.md)) keep the same things. Only the paths differ.

| What | Why it is in the backup | systemd | Containers | Helm |
|---|---|---|---|---|
| The etcd data of every cluster: the directory store, and each region's session store | The revocation marks, second factors, pins and sessions. A snapshot holds the plaintext index (principal, device, username, certificate, `sid`): guard it as the store itself. | the hourly `port49-etcd-snapshot` timer, from an etcd host | each `etcd-N-data` volume | the `port49-etcd-snapshot` CronJob (`examples/backup-cronjob.yaml`) |
| `broker.state_dir` of **every** broker: `marks.json`, `witness.json`, and `issuing-ca.pem` and `issuing-ca.key` when the broker issues certificates | `marks.json` puts back the revocations a restore lost. `witness.json` is how a broker tells a restore. The CA is the private key your devices trust: whoever reads the backup can issue certificates. | `/var/lib/port49-broker` | the `broker-state` volume | one PVC per broker replica, `state/` inside it |
| port49d's accounting spool and `<accounting.spool_path>.restore.json` | `restore.json` is port49d's record of the restore witness, so a restart still knows the store was restored. | `/var/spool/port49d` | the `port49d-spool` volume | the port49d PVC (`/var/spool/port49d/data`) |
| On the memory store only: the directory holding `broker.revocations_file` | The broker runs inside port49d and keeps its state beside the revocations file: the marks, `enrollments.json` (the sealed enrollment store), the CRLs it verified, and `issuing-ca.pem` and `issuing-ca.key` (with `-next` or `-previous` copies during a CA rotation). Whoever reads the backup can issue certificates. On etcd the store keeps the marks and none of this applies. | the directory of `broker.revocations_file` | same | same |
| The enrollment store of a `directory_password` verifier | Second factors. On etcd it is sealed records in the directory store; on the memory store it is `enrollments.json`, above. | the daily `port49-enrollments-export` timer, on a broker host | no job is shipped: run `port49-broker export-enrollments --out FILE` from your scheduler | the chart's `backup.enrollments` CronJob (off by default) |

Each etcd cluster has its own snapshot: the directory's, and each region's session etcd. The configuration,
the policy and the secrets are not on this list: they are in your configuration management and your
secrets manager. Two cautions:

- **A backup is only restorable while every key that sealed its records is kept.** Every record inside an
  etcd snapshot, a Velero backup or an enrollments export stays sealed under the `encryption:` key that was
  current when it was written. An enrollments export keeps each record's own seal and seals only its
  envelope under the key current at export time. Keep every old key file, offline, as long as any backup holding its records
  is kept. [Key rotation](../admin/key-rotation.md#backups-and-exports-need-every-key-that-sealed-their-records)
  has the rule and what a missing key costs.
- **Back up `broker.state_dir` with the broker's host, not from a different moment.** A broker whose
  `state_dir` survived the restore is the one that puts back the revocations the store lost, so the runbook
  starts it first.

### The backup jobs

=== "systemd"

    `examples/port49-etcd-snapshot.{service,timer}` take an hourly snapshot into `/var/backups/port49` (0700
    root, `UMask=0077`) on an etcd host, since it needs etcd's root certificate. It needs
    `examples/tmpfiles-etcd.conf` for the directory, and keeps two weeks.
    `examples/port49-enrollments-export.{service,timer}` export the directory's sealed enrollment store
    daily from a broker host into a dated file in `/var/backups/port49-broker` (0700, the broker's). Run each
    once by hand before you rely on its timer.

=== "Containers"

    The stack ships no backup job. Snapshot each `etcd-N-data` volume with etcd's own tooling, and schedule
    `port49-broker export-enrollments --out FILE` if you use directory password sign-in.

=== "Helm"

    Two CronJobs follow one pattern. `examples/backup-cronjob.yaml` is the etcd snapshot, which needs etcd's
    root certificate and is yours to adapt. The chart's own is off by default:
    `--set backup.enrollments.enabled=true --set backup.enrollments.claimName=<your PVC>`. The chart
    refuses to render it unless `config.broker.broker.identity.humans` has a `directory_password`
    verifier. A failed run leaves `<name>.new`: remove it and the next run goes. The snapshot is sensitive, so
    give its PVC a restrictive access mode. For a Velero backup of the volumes, see
    [Restoring with Velero](#restoring-with-velero).

### The enrollments export

`port49-broker export-enrollments --out FILE` writes the sealed enrollment store to a new file (mode 0600,
never replacing one) and keeps 14 days. The store it reads is made once by `port49-broker init-enrollments`, in
each install guide.

To restore from an export, as an admin with a key press:

```sh
port49 directory import < enrollments-<date>.json
```

The import refuses when the store holds a second factor enrolled or reset after the export was taken,
because it would undo it. `--replace` replaces the store anyway. An export sealed under a key the broker
does not hold is refused, and the message tells you to set that key as `encryption.previous`.

!!! warning "Unmeasured"
    The Helm export has been run only against a freshly initialised store, which holds the creation mark
    and no enrolled person. An export that holds enrolled people has not been measured. The systemd timer
    has not been run on a real host: run it once by hand before you rely on it.

## The restore floor

An etcd restore can bring back a token that was redeemed after the snapshot. port49 refuses such a token
in three places, and the runbook adds a fourth, the delete.

!!! warning
    The delete is required in both cases where port49d cannot tell a restore: the restore also restored the
    spool directory or `broker.state_dir` (Velero, a volume snapshot), or port49d's spool directory is new or
    lost. A restored token is redeemed a second time with no line saying so.

??? info "How port49 refuses a restored token"
    1. **port49d's restore floor.** Every token records the store revision it was created at. port49d reads
       `meta/witness` once a second. When the witness or the store's revision is lower than its own record
       (`<accounting.spool_path>.restore.json`), the store was restored. The revision of that read becomes the
       floor: a token at or below it is refused `FAIL` with reason `token_spent`, once, and the user mints
       again. A token minted after the read is served. Each refusal adds one to
       `port49_redemption_restored_refused_total`.
    2. **The runner's purge.** The broker that holds the keyspace compares `meta/witness` with its own
       `broker.state_dir/witness.json`. A store below the record, or no record at all, makes it purge every
       unspent token and every once-only record (sign-in challenges, proofs, nonces).
    3. **The mint gate.** While a purge is owed, that broker mints nothing, so a token is not minted into a
       purge that would delete it.
    4. **The delete,** step 3 of the runbook, before any port49d or broker reaches the restored store.

    port49d tells a restore only from a record that is newer than the restored store. A broker with no
    `witness.json` (an empty or new `broker.state_dir`) purges once at its first takeover, which costs every
    user one new token and is expected on a cold start of a whole fleet on new volumes.

??? info "When port49 cannot tell"
    A new or lost spool has no `restore.json` and takes the restored witness as its first record. It logs
    `port49d: store: no restore record at <path>: a restore made before this port49d's first read of the store cannot be told; after a restore, delete the unspent tokens before this port49d reaches the store (step 3 of Restoring etcd from a snapshot)`.

The lines and metrics a restore leaves, and what to do about each, are in the
[3am index](troubleshooting/index.md#the-session-store-was-restored-from-a-snapshot).

### The revision bump and the 5-minute band

Restore an etcd snapshot with `--bump-revision`. It raises the restored store's revision by a billion
(eleven days of writes at a thousand a second), so etcd never reuses a revision for another write, and the
floor needs no band: nothing is refused but the old tokens. Measured on vEOS with etcd 3.6.15
([L35-restore-arista_eos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L35-restore-arista_eos.md)).

Without `--bump-revision` (a Velero restore cannot use it) the restored store climbs through the revisions
the old timeline already used, so port49d also refuses, for **5 minutes after its read**, every token
minted at a revision up to the old high mark, `token_spent`. Users see a failed login, and so does every
retry until the window ends. Tell them to mint a new token after the window. Break-glass is unaffected.

??? info "The band's log line and a token minted inside it"
    The log line names the time:
    `a token minted until <time> (5 minutes after this read) at a revision up to <N> is refused until <time>; restore with --bump-revision (step 2 of Restoring etcd from a snapshot) to end that`.
    A token minted inside the window keeps its mint time, so it stays refused until the band ends, 20
    minutes after the read, and pasting the same token again keeps failing.

## Restoring etcd from a snapshot

This is the runbook for a restore of etcd on any deployment. Do the steps in order. A step marked **Check**
is a stop: do not go on until the check passes.

1.  **Stop what could reach the restored store.**

    **On Helm, first suspend every GitOps controller** (Argo CD auto-sync or self-heal, Flux) that manages
    `port49` or `port49-etcd`, with the commands in the [Velero runbook](helm/velero.md) (the paragraph
    before its step 1). Resume it after step 6. A StatefulSet cannot serve loopback only (step 2), so on
    Helm the brokers held at 0 are the only guard. A controller that puts the replicas back lets a broker
    reach the restored store before the delete and before the revocations are re-issued, and **can admit a
    revoked principal**.

    **Stop every `port49-broker`** (systemd: `systemctl stop port49-broker` on every broker host;
    containers: stop the `port49-broker` service; Helm: scale the broker StatefulSet to 0).

    port49d may run on: it goes dark while the store is down. **Also stop every port49d** in any of these
    cases, because port49d may then not see the restore, and the delete below must land before it reaches
    the store:

    - the restore also restored the spool directory or `broker.state_dir`;
    - a port49d's spool is new;
    - you cannot serve the restored store on loopback only (a StatefulSet cannot).

2.  **Restore with `--bump-revision` and `--mark-compacted`** on each member, from the same snapshot:
    `etcdutl snapshot restore <snapshot> --data-dir <new dir> --bump-revision 1000000000 --mark-compacted`,
    with the member flags your cluster uses (`--name`, `--initial-cluster`,
    `--initial-advertise-peer-urls`).

    Start the members serving clients on **loopback only** (for example
    `--listen-client-urls https://127.0.0.1:2379 --advertise-client-urls https://127.0.0.1:2379`, the TLS
    flags unchanged, the peer URLs as they were so quorum forms). On systemd and containers, no port49d or
    broker can reach the restored store yet; on Helm only the stopped StatefulSets keep them off it.

    If the store was restored without `--bump-revision` anyway, also restart every port49d only after step
    5's first runner has said its put-back line. Two things go wrong otherwise:

    - a port49d restarted before then loads the restored marks, so it enforces none of the revocations the
      restore lost;
    - a port49d started after the restore seals below what a port49d that ran across it knows, so its
      logins are denied `store_unavailable` until that process writes at the key.

3.  **Delete the unspent tokens and the judged records,** on the loopback address, as etcd's root. Use your
    store prefix (`stores.session.etcd.prefix`, `/port49/` by default):

    ```sh
    etcdctl --endpoints https://127.0.0.1:2379 del --prefix /port49/v1/t/
    etcdctl --endpoints https://127.0.0.1:2379 del /port49/v1/meta/judged
    etcdctl --endpoints https://127.0.0.1:2379 del /port49/v1/meta/judged_bundle
    ```

    Add the `--cacert`, `--cert` and `--key` of etcd's root identity; in a container, run `etcdctl` in the
    member's own network namespace. **Check:** all three returned. Only then restart the members on their
    usual client URLs.

    On Helm the one-shot Job `restore-unspent` runs these three deletes from etcd's own image, as etcd's
    root; the Velero runbook uses it.

4.  **Re-issue the revocations no broker's `marks.json` holds,** while every broker is still stopped. These
    are:

    - those made while every broker was down, since no broker saw them;
    - if no broker's `state_dir` survived the restore, every revocation made since the snapshot.

    Run `port49-broker revoke --offline --principal <principal>` on a broker host as the broker's user
    (`sudo -u port49-broker`; as root it refuses and names the line). On Helm,
    `deploy/helm/port49/scripts/revoke-offline.sh` does the same from the repository root. It leaves the
    brokers at the 0 it finds.

5.  **Check `broker.policy_file` on every broker host** before any broker starts. Step 3 deleted
    `meta/judged`, so the reload guard at a broker's start has no judged bundle to check against. The first
    start says `no bundle has been judged on this keyspace; this start is not judged against one` and goes
    on, and a policy file the guard would have refused is not caught. Confirm each host holds the policy you
    mean to serve.

    **Start the brokers, first a broker whose `broker.state_dir` survived the restore.** The first runner
    puts back only the revocations its own `marks.json` holds that the store lacks, and names them. A
    broker on an empty or new `state_dir` that runs first puts back none of the revocations made since the
    snapshot: its line says `had no marks.json at this start`. If no broker's `state_dir` survived, step 4
    had to re-issue them all.

    The first runner also applies every mark to the restored contexts and purges the unspent tokens.
    **Check:** a runner printed `every unspent token is purged`. If none did, delete the restored tokens
    again as root (step 3). Then start any port49d you stopped.

6.  **Lift again,** with `port49 revoke --lift`, any revocation that was lifted since the snapshot and that
    the put-back line named.

7.  **Run `port49 directory forget` again** for every pin forgotten since the snapshot: a restore brings the
    old pin back ([Stores](stores.md)).

8.  If a replay fails `token_not_found` with the log line
    `etcd: superseded record "<prefix>v1/meta/superseded_all" does not decode`, delete that one key as
    etcd's root (`etcdctl del <prefix>v1/meta/superseded_all`); the next purge writes it again. That is
    availability, never an admission.

A restored snapshot also brings back every context it held. One that a revocation by principal or
certificate ended is denied again at once by the marks. One that a self or key revocation ended has no
mark and is live again until its idle TTL: revoke it again.

## Restoring with Velero

A Velero restore that includes `port49-etcd` is a store restore: it cannot use `--bump-revision`, so the band
applies and step 3's delete is required. The procedure, the bucket warning and the evidence are on
[Back up with Velero](helm/velero.md).
