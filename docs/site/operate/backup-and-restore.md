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

## What each shape must keep

All three shapes ([systemd](install/systemd.md), [container](install/container.md),
[Helm](install/helm.md)) keep the same things. Only the paths differ.

| What | Why it is in the backup | systemd | container (compose) | Helm |
|---|---|---|---|---|
| The etcd data of every cluster: the directory store, and each region's session store | The revocation marks, second factors, pins and sessions. A snapshot holds the plaintext index (principal, device, username, certificate, `sid`): guard it as the store itself. | the hourly `port49-etcd-snapshot` timer, from an etcd host | each `etcd-N-data` volume | the `port49-etcd-snapshot` CronJob (`examples/backup-cronjob.yaml`) |
| `broker.state_dir` of **every** broker: `marks.json`, `witness.json`, and `issuing-ca.pem` and `issuing-ca.key` when the broker issues certificates | `marks.json` is the copy that puts back revocations a restore lost. `witness.json` is how a broker tells a restore. The CA is the private key your devices trust: whoever reads the backup can issue certificates. | `/var/lib/port49-broker` | the `broker-state` volume | one PVC per broker replica, `state/` inside it |
| port49d's accounting spool and the file beside it, `<accounting.spool_path>.restore.json` | `restore.json` is port49d's record of the restore witness, so a restart still knows the store was restored. Two port49d with spools in one directory each keep their own. | `/var/spool/port49d` | the `port49d-spool` volume | the port49d PVC (`/var/spool/port49d/data`) |
| On the memory store only: the directory holding `broker.revocations_file` | The memory store runs the broker inside port49d, which refuses `broker.state_dir`; the broker keeps its state beside the revocations file. That directory holds the revocations file (the marks), `enrollments.json` (the sealed enrollment store) and the CRLs the broker verified. On etcd the store keeps the marks and none of this applies. | the directory of `broker.revocations_file` | same | same |
| The enrollment store of a `directory_password` verifier | Second factors. On etcd it is sealed records in the directory store; on the memory store it is the sealed file `enrollments.json`, in the directory above. | the daily `port49-enrollments-export` timer, on a broker host | no job is shipped: run `port49-broker export-enrollments --out FILE` from your scheduler | the chart's `backup.enrollments` CronJob (off by default) |

The configuration, the policy and the secrets are not on this list: they are in your configuration
management and your secrets manager. Two cautions:

- **A backup is only restorable while every key that sealed its records is kept.** Every record inside
  an etcd snapshot, a Velero backup or an enrollments export stays sealed under the `encryption:` key
  that was current when the record was written. Keep every old key file, offline, as long as any backup
  holding its records is kept. Velero also stores the encryption Secret in its bucket, so the bucket is
  as sensitive as the key. An enrollments export keeps each record's own seal and seals only its envelope
  under the key current at export time. [Key rotation](../admin/key-rotation.md#the-encryption-key) (the bullet "Backups and exports need every
  key that sealed their records") has the rule and what a missing key costs.
- **Back up `broker.state_dir` with the broker's host, not from a different moment.** A broker whose
  `state_dir` survived the restore is the one that puts back the revocations the store lost, so the runbook
  starts it first.

### The enrollments export

`port49-broker export-enrollments --out FILE` writes the sealed enrollment store to a new file (mode
0600, never replacing one). The unit and the CronJob run it on a schedule, keep 14 days, and write a
temporary file that is renamed, so a failed run changes nothing. On Helm a `stale-check` init container
fails the Job when a `.new` file is left from a run that did not finish; remove it, and the next run goes.

A new deployment that uses directory password sign-in runs `port49-broker init-enrollments` once,
before the first start (on Helm, `examples/init-enrollments-job.yaml`). It creates the store the export
reads, and a second run is refused (`the enrollment store is already there`). Until it has run,
sign-ins answer `enrollment_store_lost`.

To restore from an export, as an admin with a key press:

```sh
port49 directory import < enrollments-<date>.json
```

The import refuses when the store holds a second factor enrolled or reset after the export was taken,
because it would undo it. `--replace` replaces the store anyway. An export sealed under a key the broker
does not hold is refused, and the message tells you to set that key as `encryption.previous`.

!!! warning "Unmeasured"
    The Helm export has been run only against a freshly initialised store, which holds the creation
    mark and no enrolled person. An export that holds enrolled people has not been measured. The systemd
    timer has not been run on a real host: run it once by hand before you rely on it.

## The restore floor

An etcd restore can bring back a token that was redeemed after the snapshot. port49 refuses such a token
in three places, and the runbook adds a fourth, the delete, for the cases where the first two cannot
tell.

1. **port49d's restore floor.** Every token records the store revision it was created at. port49d
   reads `meta/witness` once a second. When the witness or the store's revision is lower than its own
   record (`<accounting.spool_path>.restore.json`), the store was restored. The revision of that read
   becomes the floor: a token at or below it is refused `FAIL` with reason `token_spent`, once, and
   the user mints again. A token minted after the read is served. Each refusal adds one to
   `port49_redemption_restored_refused_total`.
2. **The runner's purge.** The broker that holds the keyspace compares `meta/witness` with its own
   `broker.state_dir/witness.json`. A store below the record, or no record at all, makes it purge every
   unspent token and every once-only record (sign-in challenges, proofs, nonces).
3. **The mint gate.** While a purge is owed, that broker mints nothing, so a token is not minted into a
   purge that would delete it.
4. **The delete,** step 3 of the runbook, before any port49d or broker reaches the restored store.

### When port49 cannot tell

port49d tells a restore only from a record that is *newer* than the restored store. So it does not see
one when:

- the restore also restored the spool directory or `broker.state_dir` (Velero, a volume snapshot), so
  `restore.json` and `witness.json` came back with the store. They are newer than the store only when the
  store had writes in the backup window, which is usual on a busy store and not on an idle one;
- port49d's spool directory is new or was lost. It has no `restore.json` and takes the restored witness as
  its first record. It logs
  `port49d: store: no restore record at <path>: a restore made before this port49d's first read of the store cannot be told; after a restore, delete the unspent tokens before this port49d reaches the store (design §13 step 3)`.

Either way a restored token is redeemed a second time with no line saying so. **The delete is required
in both cases.** A broker with no `witness.json` (an empty or new `broker.state_dir`) purges once at its
first takeover, which costs every user one new token and is expected on a cold start of a whole fleet
on new volumes.

A record that cannot be read or decoded is moved aside (`<path>.bad-<time>`), and the first read is taken
as a restore: every token in the store is refused `token_spent` once.

### What you see

| You see | It means | You do |
|---|---|---|
| port49d's stderr: `port49d: store: the session store was restored from a snapshot: meta/witness is …` and the tail `Revocations and marks made after the snapshot are lost: follow the restore runbook (design §13)` | port49d found the restore and set its floor. The line names the floor revision. After a restore without `--bump-revision` it also names the band (below). | Follow the runbook from the revocations step if you have not. The line is a report, not a recovery. |
| `port49_store_restore_detected_timestamp_seconds` above 0, and the alert [port49_store_restore_detected](../reference/alerts.md#port49_store_restore_detected) (ticket, for a day after) | Same event, as a metric. | The same. |
| A user's login fails and `port49_redemption_restored_refused_total` rises | Their token is from before the restore. | They mint a new token (`port49 token`). Nothing else. |
| A broker's stderr: `port49-broker: runner: <why>; every unspent token is purged and must be minted again (port49 token): N purged; M once-only records (sign-in challenges, proofs, nonces) deleted` | The runner purged. `<why>` is `the store's meta/witness is … below the … this replica saw: the store was restored from a snapshot`, or `no witness record in broker.state_dir; …`. | Nothing. Every user mints again. |
| A broker's stderr: `port49-broker: runner: N revocation(s) in broker.state_dir/marks.json were missing from the store (an etcd restore, …) and are put back: <marks>; lift any that were lifted on purpose with port49 revoke --lift` | The runner put back the revocations its copy held. | Lift again, with `port49 revoke --lift`, any of them that were lifted on purpose before the snapshot. |
| A broker's stderr: `broker.state_dir had no marks.json at this start; a revocation a store restore lost is put back only if this copy saw it` | This broker had no copy, so it put back nothing. | If no broker's `state_dir` survived, re-issue every revocation made since the snapshot (step 4 of the runbook). |
| `port49_broker_mint_gate_closed` at 1 and `POST /v1/token` answering `503 store_unavailable` with `Retry-After: 5` | A broker owes the purge and mints nothing until it is done. | Wait. If it stays at 1 for more than a minute (ticket [port49_broker_mint_gate_closed](../reference/alerts.md#port49_broker_mint_gate_closed)), no runner is purging: check that one broker holds the keyspace, and read its stderr for a purge that failed. A purge cut short is made again by the next takeover. |
| `port49_redemption_restore_unjudged` at 1, and `port49d: store: reading meta/witness, to tell whether the store was restored: …; token redemptions are refused (store_unavailable) until a read answers; tried again every 1s` | port49d cannot read `meta/witness`, so it cannot tell whether the store was restored and refuses every token login. Page after 2 minutes: [port49_redemption_restore_unjudged](../reference/alerts.md#port49_redemption_restore_unjudged). | Fix the store, or the daemon role's read of `meta/witness`. A device whose authentication `ERROR` is final (IOS XE, and Junos under `tacplus` alone) refuses break-glass until the read answers or port49d is stopped; stopping port49d lets those devices fall to break-glass. Do not delete `restore.json` to clear it: without the record port49d cannot tell a restore. |

### The revision bump and the 5-minute band

Restore an etcd snapshot with `--bump-revision`. It raises the restored store's revision by a billion
(eleven days of writes at a thousand a second), so etcd never reuses a revision for another write. port49d
tells a restore from its witness whether or not `--bump-revision` was used, and with it the floor
needs no band: nothing is refused but the old tokens.

Measured on vEOS with etcd 3.6.15
([L35-restore-arista_eos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L35-restore-arista_eos.md)):
a snapshot at revision 338 of a store at 347 restored to 1000000338, its next write was 1000000339, and
a read at 347 was refused as compacted.

**Without `--bump-revision`** (a Velero restore cannot use it) the restored store climbs through the
revisions the old timeline already used. port49d then also refuses, for **5 minutes after its read**,
every token minted at a revision up to the old high mark, `token_spent`. The log line names the time:
`a token minted until <time> (5 minutes after this read) at a revision up to <N> is refused until <time>; restore with --bump-revision (design §13) to end that`.
Users see a failed login, and so does every retry until the window ends. A token minted inside the window
keeps its mint time, so it stays refused until the band ends, 20 minutes after the read, and pasting the
same token again keeps failing. Tell users to mint a new token after the window. Break-glass is unaffected.

## Restoring etcd from a snapshot

This is the runbook for a restore of etcd on any shape. Do the steps in order. A step marked **Check** is
a stop: do not go on until the check passes.

1. **On Helm, first suspend every GitOps controller** (Argo CD auto-sync or self-heal, Flux) that manages
   `port49` or `port49-etcd`, with the commands in the [Velero runbook](#restoring-with-velero) below
   (the paragraph before its step 1). Resume it after step 6. A StatefulSet cannot serve loopback
   only (step 2), so on Helm the brokers held at 0 are the only guard: a controller that puts the
   replicas back lets a broker reach the restored store before the delete and before the revocations are
   re-issued, and **can admit a revoked principal**. Then:
   **Stop every `port49-broker`** (systemd: `systemctl stop port49-broker` on every broker host;
   container: stop the `port49-broker` service; Helm: scale the broker StatefulSet to 0). port49d may run
   on: it goes dark while the store is down. **Also stop every port49d** when the restore also restored
   the spool directory or `broker.state_dir`, when a port49d's spool is new, or when you cannot serve
   the restored store on loopback only (a StatefulSet cannot): in those cases port49d may not see the
   restore, and the delete below must land before it reaches the store.
2. **Restore with `--bump-revision` and `--mark-compacted`** on each member, from the same snapshot:
   `etcdutl snapshot restore <snapshot> --data-dir <new dir> --bump-revision 1000000000 --mark-compacted`,
   with the member flags your cluster uses (`--name`, `--initial-cluster`,
   `--initial-advertise-peer-urls`). Start the members serving clients on **loopback only** (for example
   `--listen-client-urls https://127.0.0.1:2379 --advertise-client-urls https://127.0.0.1:2379`, the TLS
   flags unchanged, the peer URLs as they were so quorum forms). On systemd and compose, no port49d or
   broker can reach the restored store yet; on Helm only the stopped StatefulSets keep them off it. If the
   store was restored without `--bump-revision` anyway, also restart every port49d only after step 5's
   first runner has said its put-back line: a port49d restarted before it loads the restored marks and
   enforces none the restore lost, and one started after the restore seals below what a port49d that ran
   across it knows, so its logins are denied `store_unavailable` until that process writes at the key.
3. **Delete the unspent tokens and the judged records,** on the loopback address, as etcd's root. Use your
   store prefix (`stores.session.etcd.prefix`, `/port49/` by default):

   ```sh
   etcdctl --endpoints https://127.0.0.1:2379 del --prefix /port49/v1/t/
   etcdctl --endpoints https://127.0.0.1:2379 del /port49/v1/meta/judged
   etcdctl --endpoints https://127.0.0.1:2379 del /port49/v1/meta/judged_bundle
   ```

   (add the `--cacert`, `--cert` and `--key` of etcd's root identity; in a container, run `etcdctl` in
   the member's own network namespace). **Check:** all three returned. Only then restart the members on
   their usual client URLs. On Helm the one-shot Job `restore-unspent` runs these three deletes from
   etcd's own image, as etcd's root; the Velero runbook below uses it.
4. **Re-issue the revocations no broker's `marks.json` holds,** while every broker is still stopped:
   those made while every broker was down, since no broker saw them, and, if no broker's `state_dir`
   survived the restore, every revocation made since the snapshot. Run `port49-broker revoke --offline --principal <principal>` on a broker host as the broker's user
   (`sudo -u port49-broker`; as root it refuses and names the line). On Helm,
   `deploy/helm/port49/scripts/revoke-offline.sh` does the same from the repository root. It leaves the
   brokers at the 0 it finds.
5. **Check `broker.policy_file` on every broker host** before any broker starts. Step 3 deleted
   `meta/judged`, so the reload guard at a broker's start has no judged bundle to check against: the first
   start says `no bundle has been judged on this keyspace; this start is not judged against one` and goes
   on, and a policy file the guard would have refused is not caught. Confirm each host holds the policy
   you mean to serve.

   **Start the brokers, first a broker whose `broker.state_dir` survived the restore.** The first runner
   puts back only the revocations its own `marks.json` holds that the store lacks, and names them. A
   broker on an empty or new `state_dir` that runs first puts back none of the revocations made since
   the snapshot: its line says `had no marks.json at this start`. If no broker's `state_dir` survived, step
   4 had to re-issue them all. The first runner also applies every mark to the restored contexts and
   purges the unspent tokens. **Check:** a runner printed `every unspent token is purged`. If none did,
   delete the restored tokens again as root (step 3). Then start any port49d you stopped.
6. **Lift again,** with `port49 revoke --lift`, any revocation that was lifted since the snapshot and that
   the put-back line named.
7. **Run `port49 directory forget` again** for every pin forgotten since the snapshot: a restore brings
   the old pin back ([Stores](stores.md)).
8. If a replay fails `token_not_found` with the log line `etcd: superseded record "<prefix>v1/meta/superseded_all" does not decode`,
   delete that one key as etcd's root (`etcdctl del <prefix>v1/meta/superseded_all`); the next purge
   writes it again. That is availability, never an admission.

A restored snapshot also brings back every context it held. One that a revocation by principal or
certificate ended is denied again at once by the marks. One that a self or key revocation ended has no
mark and is live again until its idle TTL: revoke it again.

## Restoring with Velero

Prefer restoring etcd from an etcd snapshot (the CronJob's), as above, with `--bump-revision`, and use
Velero for the other volumes. **A Velero restore that includes `port49-etcd` is a store restore:** it cannot use
`--bump-revision`, so the 5-minute band applies, and the spool and `broker.state_dir` come back with the
store, so the delete of step 3 is **required**, not belt and braces. The runbook below is the repository's
own file, `deploy/helm/port49/examples/velero/README.md`, so it matches the chart you run. It restores
etcd alone first, runs the `restore-unspent` Job (the delete of step 3), holds etcd down, restores
`port49` with its pods running so Velero can copy their volumes, then holds both StatefulSets at 0 and
brings etcd back, so the revocations are re-issued before any broker or port49d reaches the store.

!!! warning "Unmeasured"
    The Argo CD and Flux suspend and resume commands in the runbook follow those tools' documented
    commands, and no GitOps controller has run the restore. Restoring `port49` while etcd is held down in
    its own namespace has not been measured either: the measurement ran against an etcd that shared the
    release's namespace and was never held at 0. A file-system copy of a live etcd member under load, and
    a CSI volume snapshot in place of file-system backup, are also unmeasured. Skipping the suspend step
    can admit a revoked principal until the revocations are re-issued.

What is measured is on kind, with Velero 1.18.4 and its node agent
([L89-kind.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L89-kind.md)): a backup of both
StatefulSets, a deleted namespace and a restore left both ready with no fence refusal, the issuing CA
unchanged, and a mint and a login working; a restore with the StatefulSets at 0 replicas hung; and the
restore order below, with the pods running and then scaled to 0, completed with `marks.json`, the CA and
the spool intact.

Everything from here to the end of the page is that README verbatim: what the backup holds, its
requirements, how to pin the plugin, then the restore.

--8<-- "deploy/helm/port49/examples/velero/README.md:5"
