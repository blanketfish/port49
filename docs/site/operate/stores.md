---
title: Stores
description: The directory and session stores port49 keeps state in, the single-site and multi-region recipes, and what each looks like when a store is down.
---

# Stores

port49 keeps its state in two stores. The part to read before you need it is
[a cut region at 3am](#a-cut-region-at-3am).

## The two roles

| Role | Config key | Holds |
|---|---|---|
| Directory | `stores.directory` | What every region must agree on: revocation marks, second factors, the enrollment mark, unlocks, directory membership pins and back-channel logouts. |
| Session | `stores.session` | Everything else: tokens, receipts, contexts, OIDC owner records, attempt counts, and each process's sealed snapshot of its directory cache. |

Each has a `backend`: `memory` (one process, lost when it stops) or `etcd`. The keys are in the
[`port49d` reference](../reference/config/port49d.md#stores).

Every process loads the revocation marks before it serves, so a cut region keeps serving.

## The memory store

The memory store is one process and is for a trial. There, `port49d` holds its broker in process and never
creates `broker.revocations_file` itself. A missing or unloadable file refuses every start, so a lost file
cannot silently forget a revoke. Run this once, before the first start:

```sh
port49d init-revocations --config /etc/port49/port49d.yaml
```

It refuses when the file exists, so a second run changes nothing. An etcd install sets no
`broker.revocations_file` and does not run it. A unit's `ExecStartPre=` must never run it.

## Single site

Leave `stores.session` out. The session store is then the directory store, one etcd and one keyspace:

```yaml
stores:
  directory:
    backend: etcd
    etcd:
      endpoints:
        - https://etcd-1.example.net:2379
        - https://etcd-2.example.net:2379
        - https://etcd-3.example.net:2379
      ca_file: /etc/port49/etcd-ca.pem
      daemon:
        cert_file: /etc/port49/etcd-daemon.pem
        key_file: /etc/port49/etcd-daemon-key.pem
```

A `stores.session` you do name must reach a different cluster, or the same one with the same keys in both
blocks. Two blocks that reach one cluster and prefix under different names are refused at start. The disk
and clock the etcd members need are in [Requirements](../reference/requirements.md).

## Several regions

Stretch one directory etcd across the regions, one member in each, and give each region a session etcd of
its own. Each region runs its own port49d and port49-broker.

```yaml
stores:
  directory:
    backend: etcd
    etcd:
      endpoints: [https://etcd-dir-a.example.net:2379, https://etcd-dir-b.example.net:2379, https://etcd-dir-c.example.net:2379]
      ca_file: /etc/port49/etcd-ca.pem
      daemon: {cert_file: /etc/port49/etcd-daemon.pem, key_file: /etc/port49/etcd-daemon-key.pem}
  session:
    backend: etcd
    etcd:
      endpoints: [https://etcd-sess-a.example.net:2379, https://etcd-sess-b.example.net:2379, https://etcd-sess-c.example.net:2379]
      ca_file: /etc/port49/etcd-ca.pem
      prefix: /port49/
      daemon: {cert_file: /etc/port49/etcd-daemon.pem, key_file: /etc/port49/etcd-daemon-key.pem}
```

List every member. The list is static: there is no member discovery, so a member replaced at a new address
needs a config change and a restart. With one endpoint, a reboot of that member sends the region's devices
to break-glass.

Never mix backends. A split starts on fresh stores: there is no migration from one store to two.

At start each process scans every live context, 500 to a page, under `bulk_timeout` (30 seconds). That
takes about contexts / 500 times the round trip to the session etcd, so keep it in the region.

## One set of encryption keys everywhere

Every region holds the same `encryption:` keys. The directory records in `meta/seal_keys` the key ids it
was last written under. On a directory store of its own (a split), a process whose keys lack the current id
exits 1, naming the store and the id. On a single shared store the start goes on and
`port49_crypt_store_key_unknown` is 1
([alert](../reference/alerts.md#port49_crypt_store_key_unknown)). The rotation steps, in every region and
in order, are on [Key rotation](../admin/key-rotation.md#the-encryption-key).

## A cut region at 3am

"Cut" means a region cannot reach the directory etcd. Its session store still answers.

| What happened | What you see | What to do |
|---|---|---|
| The link to the directory is cut | Devices notice nothing. The line `directory store: not answering (...): serving from the cache`. `port49_store_directory_reachable` is 0, and `port49 store status` prints `unreachable` and exits 3. Alerts [port49_store_directory_unreachable](../reference/alerts.md#port49_store_directory_unreachable), then [port49_store_directory_stale](../reference/alerts.md#port49_store_directory_stale). | Restore the link. The marks catch up on the heal. |
| Someone is revoked in region A while C is cut | A and B deny the next command. C does not: open sessions keep working, and earlier tokens still log in. | Remove the person's grants from the policy file C loads (live within two watch intervals), or stop C's port49d. |
| A lift made in A during a long cut | On the heal C's runner says `... in broker.state_dir/marks.json were missing from the store (...) and are put back`. | Lift it again in any region (`port49 revoke --lift`). |
| A password and TOTP sign-in in the cut region | 503 `store_unavailable`. | Use a certificate, OIDC or a hardware key, or break-glass. Password sign-in fails closed so that one code never signs in twice across regions. |
| `port49 revoke`, `port49 directory unlock`, `reset-second-factor`, `init-enrollments` or `import` in the cut region | It fails with "the directory store did not answer, so nothing changed". | Run it from a region that reaches the directory. |
| A restart during the cut | It serves from a snapshot, and `port49 store status` shows `cache <age> (snapshot)`. | Nothing, while the cut is shorter than `session.staleness_ceiling` (4 hours). |
| A restarted process is past the ceiling, or finds no snapshot younger than it | port49d closes its listeners (`past session.staleness_ceiling`, or `no snapshot in the session store is younger than session.staleness_ceiling`). port49-broker answers every mint and sign-in 503 `store_unavailable`. A cold start exits 1 after `start_timeout`. Processes that never restarted keep serving. | Restore the link, or raise `session.staleness_ceiling` and restart if you know the copy is current. |

??? info "How the snapshot and ceiling work"
    Every 60 seconds, while its copy is confirmed, each process writes a sealed snapshot of its directory
    cache to its session store. A process that restarts in a cut serves the union of the marks in every
    snapshot younger than the ceiling, never the newest alone, so a deleted or replayed snapshot cannot lift
    a mark. Only a successful load of the directory clears the ceiling and the `(snapshot)` tag. A key or
    cluster fault found at the heal ends the process with exit 1; the fix is in its `encryption:` or
    `stores:` block.

### When the session store is the one that is down

After `etcd.health.close_after` failed checks in a row (5 by default, one per `etcd.health.interval`, 1
second) port49d closes every listener, so devices use their local method. It reopens them after
`open_after` passes in a row (3). The alert is
[port49_store_health_failures_close](../reference/alerts.md#port49_store_health_failures_close).
port49-broker never closes anything: it answers 503 `store_unavailable`. `/readyz` does not report store
health, so alert on the metrics, not on `/readyz`. Some devices do not fall back to their local method
when the server answers an error: see [IOS XE and a down store](tls.md#ios-xe-and-a-down-store).

??? info "How the checks and circuits count"
    `port49_store_health_failures` counts the failed checks, and
    [port49_store_circuit_open](../reference/alerts.md#port49_store_circuit_open) says which pool's circuit
    opened. A token or context pool whose circuit stays open for `etcd.hold_ttl` (15 seconds) closes the
    listeners without waiting for the checks. A slow bulk scan opens a circuit and raises an alarm but
    closes nothing. A call whose deadline had passed on entry is counted as `outcome="deadline_on_entry"`
    on `port49_store_calls_total` and does not count toward a circuit, so a rising count of it does not
    mean the store is unhealthy.

## `port49 store status`

```sh
port49 store status --metrics 127.0.0.1:9049
```

It prints one line per role: the backend, the etcd members answering out of those listed, whether the store
is reachable, and the directory's cache age. Exit 0 means every store answers, 3 means one does not, and 1
means the listener does not answer.

??? info "Reading the output"
    ```text
    directory  etcd    3/3 members  reachable  cache 0.4s
    session    etcd    1/1 members  reachable
    directory  etcd    ?/? members  unreachable  cache 41.2s  1 logouts pending
               <why the store did not answer, on a line of its own>
    ```

    `feeds down:` lists a feed whose watch has stopped. A session store that is the directory store prints
    `shares the directory store`, and the memory backend prints `in process`.

## Forgetting a directory membership

A person's directory entry is pinned to the principal the first time it is verified. If the entry is
deleted and re-created, the principal is refused (`directory: user:... is pinned to entry ... and is now
claimed by ...`) until an operator forgets the pin, after confirming the new entry is the same person:

```sh
port49 directory forget <principal>
```

One forget reaches every region at its next verification. In a cut region it is refused
(`store_unavailable`): run it from a region that reaches the directory.

??? info "Forgets, restores and cut regions"
    A region cut off when you forget keeps refusing the re-created entry until the heal. A member already
    pinned is served from the cached pin meanwhile.

    An etcd restore from a backup older than a forget brings the old pin back, so run
    `port49 directory forget` again after the restore. port49d judges a restore from its own witness record,
    with or without etcd's `--bump-revision`, and says so in
    [port49_store_restore_detected](../reference/alerts.md#port49_store_restore_detected). The steps are on
    [backup and restore](backup-and-restore.md).

## Back-channel logouts

An identity provider's back-channel logout that reaches any region refuses that session's mints and
refreshes in every region. If the receiving region is cut from the directory, it applies the logout at
once and the provider still gets 200. The logout stays pending, counted by `port49_store_logouts_pending` and by
`port49 store status` (`N logouts pending`;
[alert](../reference/alerts.md#port49_store_logouts_pending)). On the heal the runner forwards it. To cut
the session off in the other regions before then, run `port49 revoke --principal <principal>` from a region
that reaches the directory.

??? info "Retries and a person who signs in again"
    A region that cannot finish reaching a logout says `not every step finished (...)` and retries after a
    wait that doubles from 1 to 64 seconds, refusing the person's mints meanwhile. Look for the first line of
    the run: it carries the `port49 revoke` remedy, and later lines say `still not reached after N tries`.
    A logout the broker can never reach is not retried; the next takeover of that keyspace tries once more.

    A logout that arrives late still ends logins made after it was sent, so a person who signed in again
    may be logged out again. That is deliberate: cutting logins off by time would fail open under clock
    skew.

## What the lab measured

The three-region runs are in
[L74](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L74-regions.md) and
[L75](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L75-regions.md). With one region
cut, its open session's command was permitted. A revocation made elsewhere reached it 11 seconds after the
heal, and a logout posted to it reached another region after 5.
