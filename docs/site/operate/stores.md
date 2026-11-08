---
title: Stores
description: The directory and session stores port49 keeps state in, the single-site and multi-region recipes, and what each looks like when a store is down.
---

# Stores

port49 keeps its state in two stores, each with a job. This page says what each holds, how to lay them
out for one site or several regions, and what you see and do when one is cut off. The part to read before
you need it is [a cut region at 3am](#a-cut-region-at-3am).

## The two roles

| Role | Config key | Holds |
|---|---|---|
| Directory | `stores.directory` | The records every region must agree on: revocation marks, second factors (including the TOTP step a code was last used at), the enrollment mark, unlocks, directory membership pins and back-channel logouts. Also the key window the directory was last written under. |
| Session | `stores.session` | Everything else: tokens, receipts, contexts, OIDC owner records, attempt counts, and the sealed snapshots each process keeps of its directory cache. |

Each has a `backend`: `memory` (the default, in one process, lost when it stops) or `etcd`. The
keys of both blocks are in the [`port49d` reference](../reference/config/port49d.md#stores); this page
does not repeat them.

Every process loads the revocation marks from the directory before it serves and follows them as they
change. A login, a mint and a command are all answered from that copy, so none of them waits on a
region far away. That is why a cut region keeps serving.

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

`etcd` in `port49d.yaml` needs a `policy:` block and no `broker:` block; `port49-broker.yaml` uses
`etcd` too. If you do name `stores.session`, it must reach a different cluster, or the same one with
the same keys in both blocks. Two blocks that reach one etcd cluster and one prefix under different names
(an IP address and a DNS name) are refused at start, and so are two blocks that name one store and set
`etcd.call_timeout` differently.

## Several regions

Stretch one directory etcd across the regions, one member in each, and give each region a session etcd
of its own. Each region runs its own port49d and port49-broker.

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
      endpoints: [https://etcd-sess-a.example.net:2379]
      ca_file: /etc/port49/etcd-ca.pem
      prefix: /port49/
      daemon: {cert_file: /etc/port49/etcd-daemon.pem, key_file: /etc/port49/etcd-daemon-key.pem}
```

Never mix backends: `memory` for one store and `etcd` for the other is refused, and so is a nest of
keyspaces on one cluster. The directory's `etcd` block takes `endpoints`, `ca_file`, `prefix`, `daemon`,
`broker`, `roles`, `call_timeout`, `bulk_timeout` and `start_timeout` only.

**A split starts on fresh stores.** There is no migration from one store to two. Stand the new stores up
empty, and let people sign in again and the brokers re-mint.

## One set of encryption keys everywhere

Every region holds the same `encryption:` keys. The directory records, in `meta/seal_keys`, the key ids
it was last written under, and every broker start writes it. A process whose keys do not include the
current id there refuses to start and exits 1, naming the directory store and the key id. That is the
rule for a directory store of its own (a split); on a single shared store the start goes on, says it, and
`port49_crypt_store_key_unknown` is 1 (alert
[port49_crypt_store_key_unknown](../reference/alerts.md#port49_crypt_store_key_unknown)). A running
runner on a split rechecks the directory every hour and says the same on stderr once; that recheck sets no
gauge.

Rotate in three steps. Finish a step in every region before you begin the next, and restart the
processes at each (`encryption` needs a restart):

1. Add the new key as `encryption.previous` everywhere. Nothing is sealed under it yet, but every region can now open what is.
2. Make the new key `encryption.current` and the old one `encryption.previous`, everywhere.
3. Remove the old key from `encryption.previous`, everywhere.

The ids must differ, because the id labels every record the key seals.

## A cut region at 3am

"Cut" means a region cannot reach the directory etcd. Its session store still answers. The table is
what you see, and what to do.

| What happened | What you see | What to do |
|---|---|---|
| A region's link to the directory is cut | Devices notice nothing: logins and commands are answered from the session store and the cached marks. The line `directory store: not answering (...): serving from the cache confirmed <age> ago; revocations, lifts, enrollments, unlocks and second-factor resets are refused until it answers`. `port49_store_directory_reachable` is 0 and `time() - port49_store_directory_confirmed_timestamp_seconds` climbs. `port49 store status` prints the directory `unreachable` and exits 3. Alerts [port49_store_directory_unreachable](../reference/alerts.md#port49_store_directory_unreachable), then [port49_store_directory_stale](../reference/alerts.md#port49_store_directory_stale). | Restore the link. On the heal the line `directory store: answering again; the cache was <age> old` appears and the marks catch up. |
| Someone is revoked in region A while region C is cut | A and B deny the person's next command. C does not: open sessions keep working, and tokens minted before the cut still log in. | To cut C off now without the directory, remove the person's grants from the policy file C's hosts load (live within two watch intervals), or stop C's port49d. On the heal, C's runner says `a revocation of <principal> made elsewhere reached N token key(s) and M context(s) here`. |
| A lift made in A during a long cut comes back when C heals | C's runner says `N revocation(s) in broker.state_dir/marks.json were missing from the store (...) and are put back`. | Lift it again in any region once the cut has healed (`port49 revoke --lift`). |
| A person signs in with a password and a TOTP code in the cut region | 503 `store_unavailable`, "the broker could not reach its store, so it signed no one in; try again shortly" (the first directory read of a sign-in, the person's unlock record, is what fails). The broker says `sign-in: the unlock store did not answer: ...`, at most once every 10 seconds. The log records an `issue` denial with reason `store_unavailable`. | Use a certificate, OIDC or a hardware key, or break-glass. Password sign-in returns when the cut heals. It fails closed so that one code never signs in twice across regions. |
| `port49 revoke`, `port49 directory unlock`, `reset-second-factor`, `init-enrollments` or `import` in the cut region | The command fails in about `stores.directory.etcd.call_timeout` with "the directory store did not answer, so nothing changed". A revocation says the record may not have been made and names the fallback. | Run it from a region that reaches the directory. |
| port49d or port49-broker restarts during the cut (a deploy, an OOM kill) | It serves from a snapshot, up to the ceiling (below). `port49 store status` shows `cache <age> (snapshot)`. | Nothing while the cut is shorter than the ceiling. |
| The cut outlasts the ceiling on a process that started from a snapshot | port49d: the line `directory store: the snapshot this run serves from is <age> old, past session.staleness_ceiling (4h0m0s): the listeners close until the directory answers`. port49-broker: every mint and sign-in is 503 `store_unavailable`. Processes that never restarted keep serving. | Restore the link. Or raise `session.staleness_ceiling` and restart, if you know the copy is current. |
| A process restarts in the cut and finds no snapshot younger than the ceiling (a new region, or every writer gone longer) | Its listeners stay closed; port49d says `no snapshot in the session store is younger than session.staleness_ceiling`. A cold start exits 1 after `start_timeout`. The region's other processes keep serving. | Wait for the heal, then start it again. |

### A restart during a cut: the snapshot and its ceiling

Every 60 seconds, while its copy is confirmed, each process writes a sealed snapshot of its directory
cache to its session store. A process that restarts while the directory does not answer serves the
union of the marks in every snapshot younger than `session.staleness_ceiling` (4 hours by default),
never the newest alone, so a deleted or replayed snapshot cannot lift a mark.

Only a load of the directory that succeeds clears the ceiling and the `(snapshot)` tag. At the ceiling
the process fails closed: port49d closes its listeners and port49-broker refuses every mint and sign-in.
A key or cluster fault found at the heal ends the process, exit 1, and its listeners do not reopen. The
fix is in the process's `encryption:` or `stores:` block, not in the directory.

### When the session store is the one that is down

A session store port49d cannot use is a different failure. port49d checks it every
`etcd.health.interval` (1 second by default) through its token and context pools, and after
`etcd.health.close_after` failed checks in a row (5 by default) it closes every listener, so that
devices use their local method. It opens them again after `open_after` passes in a row (3). The page
alert is [port49_store_health_failures_close](../reference/alerts.md#port49_store_health_failures_close);
`port49_store_health_failures` counts the failed checks, and
[port49_store_circuit_open](../reference/alerts.md#port49_store_circuit_open) says which pool's circuit
opened.

A token or context pool whose circuit stays open for `etcd.hold_ttl` (15 seconds by default) closes the
listeners too, without waiting for the checks.

port49-broker never closes anything: it keeps answering 503 `store_unavailable` while its store is
down, and `/readyz` says it is serving.

Two things stay true while this happens:

- **Only the token and context pools close the listeners.** A slow or refused bulk scan opens a circuit
  and raises an alarm, but it is not a store gone, and it does not close anything.
- **`/readyz` does not report store health.** It answers whether the process is serving, so a store
  outage does not take every replica out of a load balancer at once. Alert on the metrics above, not on
  `/readyz`.

A call whose caller's deadline had already passed when it reached the store is counted as
`outcome="deadline_on_entry"` on `port49_store_calls_total`, and it does not count toward opening a
circuit: the time was spent before the store was asked, so it says nothing about the store. A call that
the store was too slow to answer within its deadline still counts as a failure. A rising count of this
outcome is therefore not a sign that the store is unhealthy; the store alerts above are.

Some devices do not fall back to their local method when the server answers an error. See
[IOS XE and a down store](tls.md#ios-xe-and-a-down-store) before you rely on break-glass.

## `port49 store status`

Run it on a host that reaches the process's `metrics_listen`:

```sh
port49 store status --metrics 127.0.0.1:9049
```

It asks port49d or port49-broker what each store is. One line per role: the backend, how many of the
etcd members answer out of those listed, whether the store is reachable, and for the directory the age of
the cache. Examples:

```text
directory  etcd    3/3 members  reachable  cache 0.4s
session    etcd    1/1 members  reachable
```

```text
directory  etcd    ?/? members  unreachable  cache 41.2s  1 logouts pending
           <why the store did not answer, on a line of its own>
```

The indented second line is the reason, printed only when a store does not answer; it is not an error of
its own.

`cache <age> (snapshot)` means the process started from a snapshot, not a live load. `feeds down:` lists
a feed whose watch has stopped. A session store that is the directory store prints `shares the directory
store`, and the memory backend prints `in process`. The exit code is 0 when every store answers, 3 when
one does not (the lines are still printed), and 1 when the listener does not answer or another status is
already running. `--metrics` defaults to `127.0.0.1:9049`.

## Forgetting a directory membership

A person's directory entry (an LDAP entry, for example) is pinned to the principal the first time it is
verified. If an entry is deleted and re-created, the principal is refused, `directory: user:... is
pinned to entry ... and is now claimed by ...`, until an operator forgets the pin:

```sh
port49 directory forget <principal>
```

Confirm that the re-created entry is the same person first. One forget reaches every region: each reads
the pin forgotten at its next verification. In a cut region the forget is refused (`store_unavailable`);
run it from a region that reaches the directory. A region cut off when you forget keeps refusing the
re-created entry until the heal. While the directory is cut, a member who is already pinned is served
from the cached pin, and a first bind or a refusal's record fails closed.

An etcd restore from a backup older than a forget brings the old pin back. Run `port49 directory forget`
again once the restore is done. port49d judges a restore from its own witness record whether or not the
restore used etcd's `--bump-revision`, and says so in the alert
[port49_store_restore_detected](../reference/alerts.md#port49_store_restore_detected); the restore steps
are on [backup and restore](backup-and-restore.md).

A cut region says, at most once per principal per 10 minutes, `directory store: not answering: serving
<principal>'s cached directory membership (its pin as this region last read it); a forget made
elsewhere reaches this region when the directory answers`. The table that remembers who was told holds
65,536 principals. When it is full it drops entries older than the window, then the oldest, so a fleet
larger than that can see the line repeat for a principal.

## Back-channel logouts

An identity provider's back-channel logout that reaches any region refuses that session's mints and
refreshes in every region, once each region's logout feed delivers the record. Each region's runner says
`a logout made elsewhere (...) reached N token key(s) and M context(s) here`.

If the region that received the logout is cut from the directory:

- The provider still gets 200, and the region applies the logout at once.
- The logout is kept pending. `port49_store_logouts_pending` and `port49 store status`
  (`N logouts pending`) count it; the alert is
  [port49_store_logouts_pending](../reference/alerts.md#port49_store_logouts_pending).
- On the heal the runner forwards it, and the other regions refuse that session from then on.
- To cut the session off in the other regions before the heal, run `port49 revoke --principal <principal>`
  from a region that reaches the directory.

The runner does not repeat itself while this lasts. It says `N back-channel logout(s) pending until the
directory store answers` once for a run of forwarding passes that fail, and then says nothing more until a
pass forwards them. A logout it could not finish applying in its own region is tried again after a wait
that doubles from 1 second, and the log gives the `port49 revoke` remedy only with the first failure; the
lines after it read `still not reached after N tries … (the remedy was said with the first failure)`.
Look for the first line of the run, not the latest.

### A person who signs in again during a cut

A logout that reaches a region late still ends the logins made after the logout was sent. A person who
signs in again in a region that has not yet followed the logout may therefore be logged out again when
it arrives. This is deliberate: cutting logins off by time would fail open under clock skew between
regions.

## What the lab measured

The three-region runs are in the notes
[L74](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L74-regions.md) and
[L75](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L75-regions.md). With one region
cut: its open session's command was permitted, and `port49 store status` exited 3; a revocation in another
region reached the cut region's session 11 seconds after the heal; a logout posted to the cut region was
refused there at once, shown pending, and refused by another region 5 seconds after the heal. Password
sign-in in the cut region answered 503 `store_unavailable`.
