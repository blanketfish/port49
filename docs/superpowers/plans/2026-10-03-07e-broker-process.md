# Plan 7e: The Broker as Its Own Process — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the broker as `port49-broker`, its own process, and run `port49d` with no broker
inside it, any number of each on one etcd keyspace. Close every item the roadmap and plan 7d
hand to 7e.
- **Two binaries, two identities.**
  - `port49d` serves TACACS+ and holds only the daemon's etcd identity.
  - `port49-broker` serves the API and holds only the broker's.
  - Neither host holds the other's credential. The broker never holds a device's TACACS+ key.
  - The in-process broker stays for `store.backend: memory` alone: one process, for the lab and
    the tests.
- **Many replicas on one keyspace.**
  - No port49d holds the keyspace. Each one serves on its own, and devices list several.
  - The hold becomes the **runner's**: one port49-broker at a time runs the start, the sweep,
    the re-index and the context half of every policy refresh. Every replica serves the API.
- **A ledger that works across processes and across restarts.**
  - The write ID that plan 7d's Task 13b sealed into each context becomes a **sealed write
    sequence**, drawn from etcd's own revision counter. A reader admits a record at or above
    the highest it knows at the key, so another process's later login is admitted and an
    earlier record put back is denied.
  - Every process keeps that high-water mark current by following the store's context family
    (a watch).
  - **The feed fence.** A read admits a record only once this process's feed has delivered
    every change through the record's revision. A put-back cannot hide behind a feed that lags
    or has stopped: the read waits for the feed, up to `call_timeout`, and is otherwise
    `store_unavailable`. A dead feed therefore goes dark as a dead store does.
  - The runner records each key's mark in a **ledger record** that the daemon's role cannot
    write. A process that starts is therefore seeded with what the processes before it knew.
- **The marks across processes.** Each process loads the revocation marks at a revision and
  follows them from there. A mark made on one broker replica closes the held connections it
  names on every replica.
- **What the broker remembers is bounded and shared where it must be.**
  - `superseded` moves into the store, kept for the life of a replayable record.
  - `blobsSeen` stays per process and is bounded.
  - The decision-log records written under the policy hold are buffered and written after it
    is released.
- **`broker.revocations_file` is retired on etcd**, which persists the marks. It stays for the
  memory store.
  - Each broker replica keeps its own copy of the marks it followed, in
    `broker.state_dir/marks.json`. After an etcd restore, the runner puts back every mark the
    copy holds that the store lost.
  - Each also records the highest `meta/witness` it has seen, in `witness.json`. A runner that
    finds the store's witness below that record purges every unspent token, so a restore
    whose runbook step was forgotten fails closed.
  - With every broker down, `port49-broker revoke --offline` writes a revocation through the
    store, with no API.
- **Policy across replicas.**
  - Every replica records the bundle it serves.
  - A replica whose bundle differs from the runner's says so, and its reload or start has the
    runner judge every live context.
  - A start whose policy file the reload guard would refuse, against the bundle last judged,
    stays not ready.
- **Carries.** The flaky `TestStartClusterRetriesAPortTaken`; the encryption key-id charset
  refused at load.
- **Lab.**
  - A new register row, **L37**: the slice on the split deployment, on five images.
  - A new row, **L38**: IOS-XE's open session once port49 is unreachable, settling the L35
    discrepancy.
  - The open row **L36** (Junos re-authorization after a port49d restart on etcd), measured on
    both Junos images.

**Architecture:**
- **One package, two entry points.** port49d's code moves out of `package main` into
  `internal/port49d` (no behaviour change, Task 12).
  - `cmd/port49d` and the new `cmd/port49-broker` are each a ten-line shim over it.
  - `port49d` runs the daemon. On memory it can also run the in-process broker it runs today.
  - `port49-broker` runs the broker alone, on etcd.
- **Configuration.** `port49-broker.yaml` is port49d.yaml's schema, decoded strictly under the
  broker role (`config.LoadBroker`).
  - It names `key_refs` (names only) where port49d names `keys` (with their secrets). It names
    the broker's etcd identity and never the daemon's.
  - port49d.yaml on etcd names `policy:`, the file it admits from, and never a `broker:` block
    or the broker's identity.
- **The ledger.**
  - **The sequence.** A context's sealed write sequence is `max(compare revision, the highest
    store revision this client has seen, the key's high-water + 1)`. Each landed write is
    strictly above every earlier one at the key, and no store writer can forge it.
  - **What `crypt.Ledger` holds.** Per key, the high-water sequence, the revision it was read
    at, the revocation floor and the latest sealed ceiling. It also holds a **base**, the
    revision the start's scan read at. A key it has never seen admits only a record sealed at
    or above that.
  - **What feeds it.** Its own writes and reads; the context feed (`ScanContexts`, then
    `WatchContexts`); and, at the start, the ledger record (`lw/`). The feed and a later scan
    raise a mark the ledger holds. They make a new one only for a record sealed at or above the
    base.
  - **The fence (`crypt.Fence`, `crypt.Fenced`).** It records how far the feed has delivered.
    It sits under the guard and holds each context read until the feed has passed the record's
    revision, so the guard counts a feed that never gets there as a failed call.
- **The runner.**
  - **The hold.** It takes plan 7d's hold (`meta/hold`) as the broker. On taking it, it runs
    plan 7d's start: the seal keys, the re-index, the marks its copy holds and the store lost,
    the marks on the kept contexts, the purge (only when the bundle in force is not the one
    last judged), the carry, and `meta/judged` when nothing is owed. Then it runs the sweep,
    the ledger keeper, the context half of every refresh pass, and a full context pass whenever
    another replica's reload or start asks for one (`meta/refresh_owed`).
  - **Before the hold.** A replica whose policy file the reload guard refuses, against the
    policy `meta/judged` records, stays not ready: it does not mint and does not take the
    hold.
  - **Losing it.** It stops those duties, keeps serving the API, and tries to take the hold
    again.
- **port49d on etcd.**
  - **The start.** No hold. It waits for the store and checks the daemon's identity. It reads
    the seal keys (never writes them), loads the marks, and seeds the ledger. It starts both
    feeds, probes the store through its context pool, and binds.
  - **The policy.** It reloads the policy file live, for admission, quarantine and redaction.
    It refreshes nothing: carrying a policy into live contexts is the broker's.

**Tech Stack:**
- Go 1.26, module `github.com/rhwendt/port49`, no cgo.
- `go.etcd.io/etcd/client/v3` v3.6.15: watches (`Watch`, `WithRev`, `WithPrefix`,
  `WithPrevKV` is not used) and one-revision paged reads (`WithRev`). No new dependency.
- containerlab on beehive for Task 17, with the five images L35 used.

**Spec:**
- `docs/design/2026-08-23-policy-engine-spec.md`:
  - §5.1.3: the refresh, and who runs it.
  - §5.1.4: revocation; the revocations file on etcd.
  - §12: tooling (`port49-broker`, `store-roles`).
  - §13: decisions 32, 34 and 35 (amended), and the new 36.
  - §14: required test assertions.
  - §15: the register rules; L35; L36; the new L37 and L38.
- `docs/design/2026-08-21-port49-design.md`:
  - §6: components ("Broker and daemon are split so that a broker failure cannot end an active
    login").
  - §8: encryption at rest, the ledger.
  - §12: the failure matrix, its "Broker unavailable" row; the store interface.
  - §13: deployment ("One keyspace per port49d until plan 7e").
  - §15: every stated alarm needs a metric.
  - §17: internal interfaces.
  - §19: step 7.
- Roadmap `docs/superpowers/plans/README.md`:
  - "Plan 7", the 7e bullet (line 1583).
  - "Plan 4b": "Hands to plan 6", the decision-log emits and m10.
  - "Plan 7d — As built": "Carried, for later plans" (7e) and "Unassigned follow-ups".
- `.superpowers/sdd/2026-10-02-07d-shared-store/7d2-carries.md`: the 7e items.
- The merged plan 7d (`2026-10-02-07d-shared-store.md`), whose code this plan is written against.

**Prerequisite:** plan 7d merged (PR #25, merge `9282085`; `main` at `b508ba0`).

## The carries: what 7e takes, and what it leaves

Every 7e item the roadmap, plan 7d's "Carried, for later plans" and `7d2-carries.md` name, and
what happens to it.

| Carry | Taken? | Where, or why not |
|---|---|---|
| `cmd/port49-broker`; port49d serving TACACS+ with no broker inside (roadmap 7e) | **Taken** | Tasks 12–15; Rulings 1, 2 |
| port49d holding the broker's store credential (7d's "until plan 7e" in decision 35 and §12) | **Taken** | Ruling 1: port49d.yaml on etcd refuses `store.etcd.broker`, and port49-broker.yaml refuses `store.etcd.daemon` (Task 13) |
| One port49d per keyspace; the hold per broker process, the daemons holding none (7d carry) | **Taken** | Rulings 6, 11; Tasks 14, 15 |
| One refresh runner across broker replicas (roadmap; 7d carry) | **Taken** | Ruling 6; Task 15 |
| The listener's marks and the daemon's shared across replicas through a watch (7d carry) | **Taken** | Ruling 5; Task 9 (the feed), Tasks 14 and 15 (wired) |
| The ledger shared across replicas or replaced (7d carry, re-check IA1) | **Taken: replaced** by a sealed write sequence, a high-water per key, and a ledger record the daemon cannot write | Rulings 3, 4; Tasks 7, 8, 10 |
| `b.superseded`, `b.blobsSeen`, `quarantineRecorded` into the store, bounded (4b m10; 7d carry) | **Taken in part**: `superseded` into the store with a lifetime; `blobsSeen` bounded and kept per process; `quarantineRecorded` kept per runner | Ruling 9 says why the last two stay in memory; Tasks 4, 5 |
| The decision-log emits under a policy hold bounded (4b Task 4) | **Taken** | Ruling 10; Task 4 |
| `broker.revocations_file` retired if the backend persists (roadmap) | **Taken** on etcd; kept on memory | Ruling 12; Tasks 13, 15 |
| A lab run to settle IOS-XE's dark behaviour against `quarantine-cisco_iosxe.md` (7d carry) | **Taken** | New register row L38; Task 17 |
| Spec: config refuses an encryption key id outside the seal-key charset (7d Task 13 C2) | **Taken** | Ruling 15; Task 3 |
| `TestStartClusterRetriesAPortTaken` flaky: retry until a deadline (7d unassigned) | **Taken** | Task 2 |
| §15 L36, Junos re-authorization after a port49d restart on etcd (7d "Lab, unassigned") | **Taken** | Task 17 runs it with L37 on the two Junos images: the run restarts a port49d replica anyway |
| Lab hygiene: check beehive's free space before a run (7d unassigned) | **Taken** | Task 17 Step 0 |
| Ruling 17's residual (7d unassigned): replay by a stolen daemon store credential | **Narrowed, the rest left unassigned** | Ruling 4 closes the **context** put-back across a restart for every key the ledger record holds. Tokens put back, a receipt's sliding bound, the idle clock and the index stay. Closing them needs a revocation record the daemon's role cannot write for every kind, a spec change to decision 34, which is no part of "the broker as its own process" |
| 7c's M3: a `revoke` record for a mark that could not be written | **Left unassigned** | A §5.7 change, unrelated to the split; a store outage is loud since 7d |
| The bulk lift (7c) | **Left unassigned** | No operator has asked; unrelated to the split |
| Go-dark proper (N failures / M passes) and the warm context cache | **Left to 7f** | The roadmap's 7f. Ruling 11's probe is the interim for a daemon with no hold |
| The etcd deployment artifacts, two Deployments and the runner; timeouts sized under load; the store alarms | **Left to plan 12** | The roadmap's 12. Task 18's operator notes name what plan 12 must ship |
| Copying 7d's raw L35 captures to `main` | **The controller's merge chore**, not a task | Task 17 Step 0 checks the labpcap audit passes on the branch before the run |
| 7c: a reload guard at start, against the last bundle in force (roadmap, 7c's "7e" carries; 7c pre-flight I4) | **Taken** | Ruling 17; Task 15a. `meta/judged` records the policy judged, and a start the guard refuses stays not ready |
| 7c: `/healthz` and `/readyz` on the broker's own process | **Taken** | Task 15 Step 7, item 2 |
| 7c: the revocations file's init in the broker's deployment | **Taken: moot on etcd** | Ruling 12 retires the file on etcd. On memory, `port49d init-revocations` stays as it is, and plan 12 owns the deployment step |
| 7c: the per-caller self/key bound (`holdOwnRevoke`) and the revocation slot are per process, so with replicas a caller holds one per replica | **Left unassigned** | Each replica bounds its own callers, so a fleet of N replicas allows N at once. That is a rate bound, not a security boundary: every revocation is idempotent, and none is refused that one replica would answer. A shared bound would need one more store record per call. Named in Task 18's "Unassigned" |

## The split: two merges, one plan

As 7d was: **7e-1** (Tasks 1–10) and **7e-2** (Tasks 11–18), each its own branch and pull
request, each leaving `make test` green. Nothing is cut.

- **7e-1, `feature/broker-process`, off `main`** (this plan's commit is its first). The store
  and the ledger a fleet of processes shares. **port49d is still one process**: on etcd it still
  runs the in-process broker 7d built, and it is wired to everything 7e-1 builds, so 7e-1's
  pieces run end to end in plan 7d's tests before anything is split.
  - **Task 1:** the docs for what 7e-1 builds.
  - **Tasks 2–3:** two carried fixes.
  - **Task 4:** the decision-log emits under the policy hold.
  - **Task 5:** `superseded` in the store.
  - **Tasks 6–10:** the write sequence, the ledger, the feeds (8), the feed fence (8a) and the
    ledger record.
  - **What changes for an operator in 7e-1:**
    - a context sealed by 7d (form 3) no longer opens, so an etcd store's live sessions end at
      the upgrade, with one line naming it;
    - a context put back while port49d was stopped is denied after a restart, for every key the
      ledger record holds;
    - a context read waits for the context feed, so a feed that has stopped denies new
      sessions `store_unavailable`;
    - `port49d store-roles` is re-applied before the upgrade;
    - four new metrics.
  - No device-visible behaviour changes, so there is no lab.
- **7e-2, `feature/broker-split`, off `main` after 7e-1 merges.** The two processes.
  - **Task 11:** the docs for what 7e-2 builds, and L37 and L38 opened.
  - **Task 12:** the move into `internal/port49d`.
  - **Tasks 13–16:** the config, port49d without a broker, port49-broker (15), policy across
    replicas and the guard at start (15a), the marks copy and the offline revocation (15b), the
    restore witness (15c), and the fleet end to end.
  - **Task 17:** the lab, which gates the merge.
  - **Task 18:** the as-built docs.

**Why split.** Twenty-two tasks (eighteen, plus 8a, 15a, 15b and 15c) is well above 7d's
sixteen.
- **What each half risks is different.** 7e-1 is correctness against properties, with no new
  process. 7e-2 is operational, and L37 gates it.
- **A reviewer can reject one and approve the other.** The ledger change is the one most worth
  its own review.
- **7e-2 is written against 7e-1's interfaces**, which this plan fixes. If 7e-1's review changes
  one, the controller amends 7e-2's tasks before dispatching Task 11, and says so in the ledger.
  - **Done 2026-10-03, after PR #26 merged.** Tasks 11–18 now call 7e-1 as built: the roadmap's
    "Interfaces 7e-1 changed" and the final review's 7e-2 amendments
    (`.superpowers/sdd/2026-10-03-07e-broker-process/amend-7e2-report.md` maps each one).

## What this plan does not do

- **No go-dark proper and no warm context cache** (plan 7f). Plan 7d's coarse go-dark stays on
  port49d: a pool whose circuit stays open for `hold_ttl` closes every listener. Without a hold,
  an idle port49d would not notice a hung store until a device asked. So Ruling 11 adds a probe,
  one read every `hold_ttl`/6 through the context pool. 7f replaces both.
- **No directory, no OIDC** (7g, 7h). `port49-broker` serves exactly what the in-process broker
  serves today.
- **No change to what a device sees from one port49d.** L37 measures what the split adds: a
  second server, a broker that is down, and a revocation from another replica.
- **No Kubernetes manifests, systemd units or load numbers** (plan 12).
- **No new reason code.** Every refusal the split adds is an existing §5.7 reason, or a line and
  a metric.
- **No change to the agent.** It talks to the broker's URL, as before.
- **The residual it does not close** (Ruling 4, last bullet) stays unassigned, stated exactly.

## Rulings where the design and spec are silent

Each takes the option that denies more, and is written into the tasks named. Spec §13 records
them as decision 36: 7e-1's part in Task 1, 7e-2's in Task 11. The owner may override any of
them. The ones to read first are under "Worth reading before the merge".

1. **Two processes, two identities, any number of each.**
   - **port49d** holds the daemon's etcd identity and the devices' TACACS+ keys, and never the
     broker's identity.
   - **port49-broker** holds the broker's etcd identity, and never the daemon's or a device
     key.
   - **Why.** Plan 7d's role separation is real only once no host holds both credentials. Until
     now port49d held the broker's, whose role is the whole keyspace, marks included (decision
     35, "until plan 7e"). A stolen port49d host now yields the daemon's role alone, which
     cannot write a mark, `meta/`, the ledger record or `superseded`. A stolen broker host
     yields no device key.
   - **The in-process broker stays for `store.backend: memory`.** Its store is in the process, so
     there is nothing to separate: one process, for the lab and the tests.
   - **On etcd, a `broker:` block in port49d.yaml is refused at load**, with a line naming the
     move to `port49-broker.yaml`. That is a breaking change for a 7d deployment on etcd, and
     the safe direction (Ruling 2).
2. **`port49-broker.yaml`** is port49d.yaml's schema, read under the broker role
   (`config.LoadBroker`).
   - **Required:**
     - `broker:`, with `broker.state_dir`, a directory for the persisted CRLs, which replaces
       the revocations file's directory;
     - `store.backend: etcd`, with `store.etcd.broker`;
     - `encryption:`;
     - an inventory (`inventory_file` or `inventory.service`);
     - `key_refs:`, the names a policy may assign (the policy's key groups are checked against
       them, as `keys:` names are on port49d);
     - `admin_socket`.
   - **Refused,** each naming the key and why:
     - `listen` (the broker never speaks TACACS+);
     - `keys:` (device secrets never reach the broker);
     - `store.etcd.daemon`;
     - `accounting`, `limits`, `receipt_idle_ttl`, `receipt_max_age`, `platforms`;
     - `policy:` (the broker's policy is `broker.policy_file`);
     - `broker.revocations_file` (Ruling 12);
     - any `lab:` key but `seed_tokens` and `seed_token_file`.
   - **`metrics_listen`** defaults to `:9050`.
   - **port49d.yaml on etcd:**
     - requires `policy: {file, watch_interval}`, the file it admits from, quarantines by and
       redacts with;
     - refuses `broker:`, `store.etcd.broker` and `lab.seed_tokens`.
   - **One field for the policy.** `Config.Policy` names the policy file whichever block named
     it, so the code reads one field.
3. **The ledger across processes is a sealed write sequence and a high-water mark per key**
   (replacing 7d Task 13b's write ID).
   - **The sequence.** Every context seal (form 4) carries `seq = max(the revision the write
     compares on, Seen(), hw(key)+1)`.
     - `Seen()` is the highest store revision this process's client has been told of, by a
       read, a write or a watch.
     - `hw(key)` is the ledger's high-water at the key.
     - So each landed write at a key is sealed strictly above every earlier one. A write's
       compare revision is above the sequence of the record it replaces. A create after a
       delete reads at a revision past the delete, and `hw + 1` is above everything known.
   - **The rule.** A read admits a record whose sealed sequence is at or above the key's
     high-water, and raises the high-water to it.
     - **The feed fence comes first** (pre-flight C1). A record is judged only once this
       process's context feed has delivered every change through the record's mod revision.
       - A put-back is a store write, so it commits above the write it hides. Once the feed
         has passed the put-back's revision, it has delivered that later write and raised the
         high-water past the put-back.
       - A read whose record is newer than the feed asks the feed for its progress (etcd's
         `RequestProgress`) and waits, bounded by the guard's `call_timeout`.
       - A feed still behind at the bound is `store.ErrUnavailable`, and the guard counts it.
         A dead feed therefore opens the context pool's circuit and goes dark as a dead store
         does (Ruling 11's probe pings through the fence too).
       - No wait is needed for a record at the revision this process last knew at its key: its
         own write, or a record it already admitted.
       - A process with no feed (memory, the tests' two-layer fixtures) passes at once. Its
         ledger sees every write already.
       - **The etcd floor** (re-check R2). The fence rests on etcd never sending a progress
         notification ahead of an event it has not delivered. etcd fixed that ordering (#15220)
         in 3.4.24 and 3.5.8, and every 3.6 has it; port49 builds and tests against v3.6.15.
         Below that floor a notify can let a read through before the later write it hides
         arrives, so a downgraded etcd is a known risk. `TestAWatchAnswersAProgressRequest`
         pins the order.
     - **A key with no entry** admits a record at or above the ledger's **base**, the revision
       after the start's scan (Ruling 4). Any record that existed then was scanned.
       - **The feed and every later scan** (a compacted watch, a re-entry after a store gone)
         raise an entry that exists. They make one only for a record sealed at or above the
         base (`Ledger.ObserveFollowed`; pre-flight I1).
       - So a put-back at a key this process never saw is denied whether or not the feed has
         brought it. Made the key's entry, it would be admitted.
       - **A compacted watch seeds from the ledger record before it scans again** (re-check
         R1). A rescan sees each key's latest record, not the writes between. A put-back made
         while the watch was down hides the later login it replaced, so a scan alone raises
         nothing at the key, and the fence, once the scan has passed it, would admit the
         put-back. The ledger record (Ruling 4) holds that login's mark when the runner's feed
         saw it. So the rescan reads the record first, as a start does.
         - **The gap left:** the runner's own feed compacted in the same gap, or the login and
           its put-back both inside the keeper's lag (about a second). That is the restart
           residual of Ruling 4, met by a rescan instead of a restart.
       - **The one fail-closed race.** A login sealed by another process before this process's
         scan, and committed after it, is below the base. Its writer's `Seen()` predated the
         scan, and a put-back looks the same. It is denied on this process until the next
         write at its key, `store_unavailable` to that one session. That needs a login in
         flight across another process's start.
     - **Below the high-water** is denied `store_unavailable`, as 7d denies a record that is not
       the one last written (`crypt.ErrNotLastWritten`, kept).
     - **A read that raced a write** is read again (`stale`), up to twice, as 7d does: its
       revision is below the high-water's.
   - **What it fixes.** Another process's later login at a key is admitted, once this
     process's feed has passed it: its sequence is higher. An earlier record put back is
     denied, whether or not the feed has caught up, and whichever process wrote either: its
     sequence is lower. With a per-process ledger, the first would deny every other replica's
     logins (re-check IA1).
   - **Simpler than 7d's.** 7d's writes in flight, unknown outcomes and the two restore cases
     (Tasks 6b, 13b; 79812ef, 3159dbc) all fall out of the rule.
     - A write of unknown outcome that landed has the higher sequence. One that did not left
       the record the high-water names.
     - After a restore, with or without `--bump-revision`, this process's `Seen()` never goes
       back, so its next write seals above every earlier record. A record the restore brought
       back is below the high-water and is denied, as 7d measured (L35).
     - **Across processes, a restore needs the runbook** (pre-flight I12). A process started
       after a restore without `--bump-revision` has a low `Seen()`, and seals below the
       high-water a process that ran across the restore holds. Its logins are denied there
       until a process that ran across it writes at the key.
       - With `--bump-revision`, every revision after the restore is above every earlier one,
         so every process admits them.
       - So the runbook (design §13; Task 11) says to restore with `--bump-revision` and
         `--mark-compacted`, as etcd advises, or else to restart every port49d after the
         restore, once the first runner has put the lost marks back (a port49d restarted
         before that enforces none the restore lost; pre-flight 7e-2 P-2). The brokers are
         stopped across the restore and started after it.
       - `TestALoginAfterARestoreIsAdmitted` pins both outcomes with two processes.
   - **The revocation floor** (7d final review I-1) stays.
     - Each process also takes a floor from the feed: a change at a key whose plaintext
       `revoked_at` is set, at the high-water's sequence.
     - So a seal that failed on one replica is held on every replica that saw the plaintext
       mark land. The fence makes "saw" certain before a put-back that zeroes it is read.
   - **Memory.** An entry is kept while a record it saw could still be live: until the latest
     sealed ceiling it saw at the key, plus `session.grace_window`. A `never` context's entry is
     kept for good. Past that a record put back is past its sealed ceiling, which the
     authorizer denies anyway (`Ledger.Prune`, run with the sweep).
   - **Migration.** A form-3 record does not open. On etcd every live session ends at the
     upgrade: it is denied, replaced at the next login, and revoked by the refresh as tampered,
     as 13b did to form 2. Tokens are purged at a start that changes the bundle anyway. The
     memory store loses everything at the restart that installs it.
     - **What the operator reads** (pre-flight I10). An earlier form is
       `crypt.ErrEarlierForm`, and the line says so once per 10 minutes, not as tampering:
       `a context sealed by an earlier port49 (form 3) does not open: expected once after the
       7e upgrade; replaced at its user's next login`.
     - A record below the high-water says `is sealed below the newest write any port49
       process made there`. 7d's "is not the one this port49d last wrote there" is wrong under
       the new rule.
     - **Rolling back to 7d** ends sessions again: 7d does not open form 4.
4. **The ledger record, `lw/<nas>/<user>`, kept by the runner alone.**
   - **What it holds.** Per key, `{seq, revoked_at, until}`.
   - **Who writes it.** The runner, about once a second, from its own ledger. Every write
     raises and never lowers, by a compare on the record's revision. Its lease runs to `until`
     plus `lease_grace`, with none for a `never` context.
   - **Who reads it.** Every process seeds its ledger from it at start, before it scans `c/`,
     and again before each rescan after a compacted watch (re-check R1). A scanned record below
     its key's mark is a put-back, and is denied.
   - **What the daemon's role can do to it.** Read it, never write it. Without it, a port49d
     started after a put-back would take the record put back as the key's (7d's restart
     residual), and with many replicas restarting in turn, that would be every rollout.
   - **The residual it leaves:**
     - a key written within the keeper's lag (a second, and a store round trip) and put back
       inside it;
     - a key written while no runner ran, put back before a runner recorded it;
     - a key written while the runner's own context feed was down, since the record follows
       the runner's ledger, which only that feed raises for other processes' logins;
     - the same three for a process whose watch was compacted, which seeds its rescan from the
       record (Ruling 3, re-check R1).
   - **Saying it is behind** (pre-flight I11).
     - `port49_ledger_pending` is how many marks the runner's ledger owes the record.
     - `port49_ledger_behind` is 1 while the runner keeps the record and its context feed is
       down: pending then reads 0 while the record silently stops following other processes'
       logins.
     - Both are set to 0 when the runner's duties stop, so an ex-runner never shows a stale
       value.
     - The alarm (design §15) is: on the runner, `port49_ledger_pending` above 0 for a minute,
       or `port49_ledger_behind` at 1.
5. **The marks across processes.**
   - **Loading.** Every process loads the marks with the revision they were read at
     (`Revocations`) before it serves, then follows `rv/` from that revision
     (`WatchRevocations`).
   - **What follows them.** The daemon's `store.Marks`, and each broker replica's `Marks` and
     listener copy.
   - **A mark made on any replica:**
     - closes the held connections it names on every replica (`Broker.MarkChanged`);
     - is in every daemon's marks within the watch's latency.
   - **A lift** takes it out of each.
   - **A lagging marks feed only delays the in-memory copy.**
     - A revocation marks every context record it reaches (7a), and the mint path reads the
       store's marks itself.
     - A put-back that would hide a revocation (the plaintext `revoked_at` zeroed, or an
       earlier record) is the context feed's to catch. A read waits for that feed (Ruling 3,
       the fence).
     - 0cc5573's "a lagging feed opens nothing" claimed this without the fence. Without it, a
       put-back read before the context feed delivered the revocation was admitted (pre-flight
       C1).
   - **A compacted watch** loads the marks again and applies the difference. A mark the reload
     finds missing is applied as a lift, but is told as `Reloaded`. It may be a lift made in
     the gap, or a mark a restore lost. So each broker's copy (Ruling 12) keeps it, and only a
     lift the watch delivered as a delete removes one.
   - **A reconnect is not a reload** (final review 7e-1 I-1). Each watch asks for progress
     notifications, and each raises the revision a re-watch resumes from, so a reconnect within
     etcd's compaction retention never reloads. A reload means a real gap: a compaction past
     the last progress, or a restore.
   - **The hook before a reload** (`store.FollowMarks`'s `rescanned func() error`; final review
     7e-1 C-1, re-review 1 C-2). It runs before the reload reads the store. One that fails
     refuses the reload: the feed is down, said once per run of failures, and tried again in a
     second. A reload never runs on a put-back that failed.
   - **On port49d, a mark a reload finds missing stays in force** until a lift the watch
     delivers, or a restart, and is said with a count. This is the daemon's half of C-1.
     - The marks are the process's, as the ledger is (Ruling 11). A restore that outlasts
       `hold_ttl` takes port49d dark and ends the run before the feed can reload; the next run
       keeps the same way (`keepLost`, Task 14) before it loads the restored marks (pre-flight
       7e-2 P-1).
     - The daemon's role cannot write `rv/`, and on etcd the revocations file that 7e-1's
       `marksReloadHook` put back from is retired (Ruling 12). So port49d's hook
       (`daemonReloadHook`, Task 14) does not put back. It reads the store's marks and keeps
       every mark this port49d enforces that the store lacks (`store.Marks.Keep`), so the
       reload does not lift it.
     - The runbook keeps port49d running across a restore (design §13, step 1). Without the
       keep, a revoked principal with a token the snapshot still holds would log in on every
       daemon until step 4's runner put the lost marks back.
     - A lift made on a broker while this port49d's marks feed was down is kept too, which
       denies more. It ends at that port49d's restart, or at a revoke and lift made again while
       its feed is up. The line says so.
6. **The runner.** The keyspace hold of 7d's Ruling 11 is now the runner's: one port49-broker
   per keyspace at a time.
   - **On taking it,** with the API already serving:
     1. it records the seal keys (`meta/seal_keys`);
     2. re-indexes every kept context the index lost;
     3. puts back every mark its copy holds that the store lacks (Ruling 12), and says how many;
     4. applies every standing mark to the kept contexts;
     5. purges the unspent tokens, only by Ruling 7;
     6. carries the policy in force into every kept context;
     7. records `meta/judged` (Ruling 7) itself when the carry leaves no pass owed (pre-flight
        I2). Otherwise the reloader's settle records it, as below.
   - **Then it runs:**
     - the sweep and the re-index every `sweep_interval`;
     - the ledger keeper (Ruling 4);
     - the context half of every refresh pass, which records quarantines as before;
     - a full context pass whenever another replica asks for one in `meta/refresh_owed`
       (Ruling 8);
     - `meta/judged` (Ruling 7) whenever its `port49_policy_refresh_pending` reaches 0 and
       every replica serves the runner's bundle;
     - before every reload of its marks feed, the same put-back as step 3, in the feed's
       `rescanned` hook: a put-back that fails refuses the reload (Ruling 12; re-review 1 C-2);
     - the restore witness, read every second beside the keeper, and rewritten when the store
       has moved (Ruling 18).
   - **Every replica, runner or not:**
     - serves the API and the admin socket;
     - runs the token half of its own reload's passes (Ruling 8);
     - records the bundle it serves (`meta/bundles/`), and asks for a full pass after its own
       reload or start (Ruling 8);
     - runs certificate status and its revocation queue (a mark is idempotent);
     - follows the marks and the contexts, keeps its copy of the marks, and keeps in force
       through a reload every mark its copy holds that the store lacks (Ruling 12);
     - follows `meta/witness`, and keeps the highest it has seen in `witness.json` (Ruling 18).
   - **Losing the hold** (the key gone, the lease lapsed, or etcd not answering with half the
     lease or less left, as 7d's fence judges):
     - the runner's duties stop at once;
     - the replica keeps serving the API, whose store calls fail closed through the guard if
       the store is gone;
     - it tries to take the hold again every 5s.
   - **Why the API stays open.** A broker's readiness is never the store's health (design
     §12). Two runners for a moment, an old one paused past its fence, is safe: every context
     write is a compare-and-set and every mark is idempotent. It costs at most a duplicated
     `refresh` record.
   - **The waiting line** names the holder, as 7d's did, with "this replica serves the API".
     - When the holder is this replica's own last run (a hold lost while the lease lives on),
       the line is 7d's I-2 line (4001732), not "run by" itself (pre-flight M7): `keyspace
       … is still held by this replica's last run (…); waiting up to hold_ttl for its lease to
       expire`.
   - **The purge's moment** (pre-flight M8). A token minted on any replica between the
     takeover's `SupersedeAll` and its purge is deleted too. `port49 token` succeeded, and
     the login then fails `token_not_found`. That needs a mint within the purge's few store
     round trips of an unjudged takeover. It fails closed, and running `port49 token` again
     mints one that works. It is named in the operator notes rather than cut off by a mint
     time the store cannot read (the time is sealed).
7. **The token purge happens when the bundle changed hands unjudged**, not at every start.
   - **`meta/judged`** is the bundle in force, with its policy file's bytes (Ruling 17). It is
     written only when two things hold:
     - the runner's last pass left `port49_policy_refresh_pending` at 0, so every token minted
       under an earlier bundle was judged against it;
     - every replica's `meta/bundles/` record names the runner's bundle (Ruling 8), so no
       replica still mints under another.
   - **Who writes it** (pre-flight I2):
     - the takeover itself, once its purge (if any) and its carry complete with no pass owed;
     - the reloader's settle otherwise (`onSettled`).
     - Each says `runner: recorded bundle <bundle> as judged`. When a replica still serves
       another bundle, it says `runner: not recording bundle … as judged: <replica> serves
       bundle …` instead.
     - Without the takeover's own write, a first install, and every takeover after a purge,
       left it absent, so every later takeover purged again.
   - **At a takeover** a runner whose bundle in force differs (an edit made with no runner, or a
     runner that died before its settle pass) purges every unspent token. It writes
     `meta/superseded_all` with the instant, so an idempotent replay on any replica mints
     afresh. A `meta/judged` that does not decode is taken as absent: the takeover purges.
   - **Otherwise it purges nothing.** A rolling restart of the brokers does not make every
     operator run `port49 token` again.
   - **After an etcd restore,** `meta/judged` is the snapshot's, so a takeover would not purge.
     A token redeemed since the snapshot would be unspent again until its sealed expiry. 7d's
     start purged at every start and closed that.
     - So the restore runbook (design §13, Task 11) deletes `meta/judged` before any
       port49-broker starts: `etcdctl del <prefix>v1/meta/judged`.
     - The first takeover then purges every unspent token, as 7d's start did.
     - Found while revising for the pre-flight review, not by it. Named in the commit.
     - **If the delete is forgotten** (Ruling 18, re-check R6), a takeover, or a running
       runner, that reads `meta/witness` below the revision its replica recorded in
       `broker.state_dir/witness.json` takes `meta/judged` as absent and purges. A replica with
       no record cannot tell, and says so.
   - **Memory.** A start still purges as before; its store is empty anyway.
8. **The settle pass covers a replica that reloads late.**
   - **The delay** is `max(30s, 2 × policy_watch_interval + 5s)` after a swap.
   - **The priors.** The reloader keeps the priors it has had since the last settled pass until
     that settle pass completes, instead of resetting them after the first complete pass.
   - **What that catches.** A token another replica minted under the replaced policy before it
     reloaded is judged by the runner's settle pass, and by that replica's own token pass.
   - **What it does not catch, and what does** (pre-flight I3). Each replica reads its own
     `broker.policy_file`.
     - **Propagation skew** outlasts any settle window: a ConfigMap volume often lags 60s or
       more, and config management reaches hosts at different times. So a replica can mint
       under the withdrawn grant after the runner's settle pass, and a context redeemed from
       it carries the old blob. That replica's own reload runs only the token half, so no
       pass reaches that context. 0cc5573's "only a differing interval" was wrong.
     - **Every replica records the bundle it serves**, in `meta/bundles/<who>`. The record is
       leased for `hold_ttl`, renewed every third of it, and rewritten at every swap.
     - **`port49_policy_bundle_matches_runner`** is 1 while a replica's bundle is the one the
       runner's record names, 0 otherwise. It is 1 on the runner. A mismatch is said once per
       pair of bundles: `policy: this replica serves bundle X and the runner (<who>) serves
       bundle Y; set the same broker.policy_file content and broker.policy_watch_interval on
       every replica`.
     - **port49d's own policy can differ too** (re-check R5). It decides admission, quarantine
       and redaction there. The daemon's role cannot write `meta/`, so port49d records nothing.
       Instead it reads `meta/judged`'s bundle every `policy.watch_interval` and sets the same
       gauge, 1 while its bundle is the one last judged. A mismatch is said once per pair:
       `port49d: policy: this port49d serves bundle X and the bundle last judged by the runner
       is Y; set the same policy file on port49d (policy.file) as on every port49-broker
       (broker.policy_file)`.
       - Right after a rollout it reads 0 until the runner's settle pass records the new
         bundle, so its alarm waits `settleAfter(policy.watch_interval)` and one interval more.
       - With no record (a first install), it says nothing and reads 1: nothing is known to
         differ.
     - **A non-runner's swap, and its start, write `meta/refresh_owed`**. The runner reads it
       every `policy_watch_interval`. When its revision is newer than the last one handled, the
       runner runs a full context pass: `Refresh` with `priors = [the policy in force]`, whose
       context half judges every live context against that policy. Then it deletes the record
       on that revision.
     - **A replica that dies before it reloads** leaves its record to lapse. The runner, having
       seen another bundle in `meta/bundles/`, owes a full context pass at the last sighting
       plus `policy.MaxTokenTTL` (15m). By then every token that replica minted has expired
       or been redeemed, so the pass reaches every context it made.
     - While a replica serves another bundle, the runner writes no `meta/judged` (Ruling 7), so
       the next takeover purges.
   - **The residual.** A token minted on a skewed replica is redeemable until that replica's
     own token pass or its expiry, at most `token_ttl` (15m). Any context made from one is
     carried at the replica's reload, or at the last sighting plus 15m if the replica dies.
     The operator note still says to set the same file and interval everywhere.
9. **What the broker remembers.**
   - **`superseded` moves into the store** (`sp/<nas>/<user>`, broker role only). Every replica
     must answer an idempotent replay alike (design §17), and the key a revocation superseded
     on one replica is replayed on another.
     - Each entry is kept for `store.SupersededFor` (20m). That is past the longest
       `token_ttl` (15m), so past any record it could make a replay mint afresh for. That is m10's
       bound.
     - A replica also keeps its own entries in memory, pruned at the same age, so a store write
       that failed still covers that replica's replays.
   - **`blobsSeen` stays per process**, bounded at 4096 hashes, forgetting all at the bound.
     - Each process's decision log must stay replayable by itself (spec §5.7, Replay): a mint
       record names a blob its own stream carried.
     - A shared "seen" would leave a replica's stream naming blobs only another stream holds.
     - Forgetting costs a duplicate `blob` record per concurrent request. Since Task 4 drops
       `putBlob`'s `b.mu` serialisation, N mints of a new hash at once after a reload each
       buffer and write a blob record, a burst of up to N large duplicates (pre-flight M10).
       Replay reads a duplicate as one. Accepted: serialising them again would put a store
       write back under a lock every mint shares.
   - **`quarantineRecorded` stays the runner's.** Each complete pass already prunes it to the
     contexts it met (`refreshContexts`), so it is bounded by the live contexts. A takeover
     writes at most one more `refresh` record per quarantined context.
10. **The decision-log records a mint writes under the policy hold are buffered** (4b Task 4).
    - **How.** A request emits into a `decision.Buffer` while it holds the policy, and writes
      it to the log in order once the hold is released, before its response. A stalled log
      therefore never stalls a reload, and through it every mint.
    - **The blob record.** A blob is marked emitted once its buffered record has landed, so a
      concurrent request emits its own copy rather than naming a blob not yet written. A mint
      record always follows its blob record in each request's run of lines.
11. **port49d on etcd holds no hold, and probes the store.**
    - **The start:**
      1. waits for etcd and checks the daemon's identity;
      2. reads `meta/seal_keys`, warning as 7d does, and never writes it;
      3. loads the marks;
      4. seeds the ledger from `lw/` and a scan of `c/`, and sets the base;
      5. starts both feeds;
      6. binds.
    - **The probe.** One `Ping` every `hold_ttl`/6 through the context pool, so an idle
      port49d's circuit opens and it goes dark as 7d's fence made it. The two triggers are a
      token or context pool whose circuit stays open for `hold_ttl`, and a refused run.
      - The ping goes through the feed fence (Ruling 3): it answers only once the context feed
        has delivered through the revision the ping read at.
      - So a context feed that has stopped fails every probe, and the port49d goes dark,
        though the store answers. A device then uses another replica, or its local method,
        rather than a port49d that cannot tell a put-back from a login.
    - **A run after a store gone** keeps the ledger and the marks, which are the process's:
      `run` makes both, and the new run keeps every mark the store lacks before it loads
      (Ruling 5; Task 14, pre-flight 7e-2 P-1).
    - **Live sessions survive a restart,** as in 7d.
    - **The policy.** port49d reloads its policy file live, for admission, quarantine and
      redaction, and carries nothing into live contexts: that is the broker's (design §6).
      Broker down, a reload changes admission at once and live contexts at the next runner's
      pass.
12. **`broker.revocations_file` is retired on etcd, and each broker keeps a copy of the
    marks.** Changed by pre-flight I5 to the option that denies more.
    - **Why the file is not needed.** The store persists the marks, and since plan 7d every
      start has put the file's marks into it, so a 7d deployment's marks are all in etcd
      already. The file is operator-managed. Its copy below is not.
    - **What replaces it.**
      - `broker.state_dir` holds the persisted CRLs and `marks.json`.
      - The file, its marker and `port49d init-revocations` stay for the memory store.
    - **`marks.json`, one per replica.**
      - Each port49-broker writes the marks it follows to `broker.state_dir/marks.json`: owner
        only, written to a temporary file and renamed.
      - A mark the feed or a load brings is added.
      - A lift is removed only when the watch delivered it as a delete. A mark a reload found
        missing (`MarkChange.Reloaded`) stays in the copy: it may be a restore's loss.
      - A write that fails is said once per run of failures. The copy in memory stays whole.
    - **The put-back.** The runner's takeover, and the runner's marks feed before every reload,
      put back every mark in its copy that the store lacks (`PutRevocation`, idempotent). It
      says how many, and names each, its kind and key (`printsafe.Line`), up to 20, then `and
      N more` (re-check R4).
      - **Before the reload, never after it** (re-review 1 C-2). The feed's put-back is its
        `rescanned` hook (`runner.reloadHook`, Task 15b), one attempt bounded by
        `store.etcd.bulk_timeout`. A put-back that fails returns an error, so `FollowMarks`
        does not reload: the marks feed is down, `port49_store_feed_up{feed="marks"}` is 0, and
        it is tried again every second. A reload after a failed put-back would lift every lost
        mark from this replica's marks and listener.
      - **A replica that does not run** (or the runner during its takeover) puts nothing back.
        Its hook keeps in force (`Marks.Keep`) every mark it enforces that its copy holds and the
        store lacks, so its listener still refuses that principal at the agent's first request
        (decision 32) until the runner's put-back arrives or a lift this feed delivers. A read
        that fails refuses the reload (pre-flight 7e-2 P-3). The line: `store: N revocation(s)
        in broker.state_dir/marks.json are missing from the store as the marks feed reloads and
        stay in force on this replica until the runner puts them back or a lift this feed
        delivers: …`.
      - **What replaces port49d's hook.** 7e-1's `marksReloadHook` put back
        `broker.revocations_file`'s marks before port49d's reload. On etcd that file is retired
        and the daemon's role cannot write `rv/`. So port49d's hook keeps what the store lost
        in force, without putting it back (Ruling 5, `daemonReloadHook`), and the runner's
        copy is what puts it back. `marksReloadHook` is deleted (Task 14): on memory no marks
        feed runs.

      The line:
      `runner: 2 revocation(s) in broker.state_dir/marks.json were missing from the store (an
      etcd restore, or a lift made while this replica's watch was compacted away) and are put
      back: principal user:alice@example.com, principal user:carol@example.com; lift any that
      were lifted on purpose with port49 revoke --lift`.
      The takeover's next step applies them to the kept contexts. The operator lifts again what
      the line names and was lifted on purpose; `port49 revoke --list` shows every mark.
    - **Which way it errs.**
      - A mark lifted after the snapshot is absent from every copy that saw the lift, so the
        restored store's mark stands, as the restored snapshot says.
      - A copy that missed a lift (its replica down, or its watch compacted, at the time) puts
        the mark back. That denies more, and the line says how to lift it.
      - **Final review 7e-1 I-1 is what makes a missed lift rare.** Each watch resumes from its
        last progress notification, so a reconnect within etcd's compaction retention delivers
        the lift as a delete. Without it, every reconnect after a quiet hour was a reload, and
        a lift made during the break was put back.
      - A replica that was down during a lift puts that mark back at each of its takeovers,
        until the lift is made again while it is up: only a lift its watch delivers clears its
        copy (re-check R4). The operator notes say so.
    - **A restore.** The runbook (design §13) restores with every port49-broker stopped, deletes
      `meta/judged` (Ruling 7), and starts the brokers: the first runner puts the marks back and
      purges the unspent tokens. Nothing is re-applied from memory at 3am.
13. **The admin sockets, and revoking with every broker down.**
    - **port49-broker's** answers `revoke`, `lift` and `list`. A `keys diagnose` there is
      answered "port49-broker holds no device packets; keys diagnose is port49d's admin
      socket" (`admin.Server.DiagnoseElsewhere`).
    - **port49d's** answers `keys diagnose`. When it runs no broker, a `revoke` or a `list`
      there is answered "port49d runs no broker; revocation is port49-broker's admin socket (its
      `admin_socket`): run `port49 revoke --socket <that path>`". That is an error, so the
      client exits 1.
    - **With every port49-broker down** (pre-flight I4), there is a break-glass.
      - Ruling 13's socket refuses, Ruling 12 retired the file, and decision 32's fallback
        (remove the grants) reaches live contexts only through a runner (Ruling 11). Without a
        break-glass, an operator with a compromised user and a crash-looping broker could
        only stop every port49d.
      - **`port49-broker revoke --offline --config port49-broker.yaml (--principal P |
        --cert-issuer I --cert-serial S) [--lift]`** opens the store on the broker's identity,
        serves no API, takes no hold, and runs `broker.Revoke` (or `Lift`) on a broker built
        with no listener. That is 7a's whole ordering: the mark first, tokens, contexts twice.
        It prints the report as `port49 revoke` does, and exits 0, or 1 on any failure.
      - Every running port49d gets the mark through its marks feed, and denies the session's
        next command `credential_revoked`. A broker that later starts loads it.
      - **With no broker host at all,** the operator writes the mark as etcd's root:
        `etcdctl put <prefix>v1/rv/principal/<key> '{"kind":"principal","key":"<key>","at":"<RFC 3339
        now>","origin":"etcdctl"}'`. Every port49d denies at the next command. Tokens are not
        deleted, so a token already minted still logs in and each of its commands is denied.
        The next runner's takeover applies the mark to the kept contexts.
14. **`store-roles` reads both files:** `port49d store-roles --config port49d.yaml
    --broker-config port49-broker.yaml`.
    - **The daemon's role** gains read on `lw/`, and never touches `sp/`. `CheckIdentity`
      probes that the daemon is refused a write to `lw/` and any access to `sp/`.
    - **The output** gains one grant line, the daemon's read on `lw/`.
    - **On memory** it is refused, as it is today.
    - **How it reads them** (pre-flight I8). It reads both files through `config.StoreBlocks`,
      a role-free decoder of the `store:` block that checks its shape and no role's
      requirements.
      - A 7d port49d.yaml naming both identities therefore still works without
        `--broker-config`, with a line naming the move.
      - `config.Load` under the daemon's role still refuses that file. Only `store-roles`
        reads it role-free.
15. **An encryption key id is `[A-Za-z0-9._-]{1,64}`**, refused at load otherwise (7d Task 13
    C2). It is sealed into every record's header and named by every line about a record that
    will not open (`crypt.LineKeyID`). Today such an id prints as `?`.
16. **L37, L38 and L36 are measured by this plan**, on beehive.
    - **L37:** the slice on the split deployment, on all five images.
      - two port49d replicas and one port49-broker on one embedded etcd;
      - each device lists both replicas;
      - measured: a session's next command after its replica stops; a token minted before the
        broker stops; the open session with the broker stopped; a revocation made on the
        broker reaching a session on either replica; how long after a store hang a port49d with
        no hold closes its listeners.
    - **L38:** IOS-XE alone. An open session's `show privilege` and `show version`, once port49
      is unreachable after nothing, and after a `FAIL store_unavailable`.
    - **L36:** both Junos images, measured within the L37 run. A session's re-authorization
      (`authorization-time-interval` 15m) after its port49d replica restarts on etcd.
    - Nothing about them is asserted before its row closes.
17. **The reload guard runs at a broker's start too** (7c's carry; pre-flight I6).
    - **The hazard.** A broker rollout restarts every replica onto the file on disk, a file
      the reload guard refused included. A takeover would then carry it into every context and
      delete the tokens of every device it newly refuses. That is what the guard's own line
      warns of: "a restart would load it".
    - **What the start does.**
      - It loads the file, then reads `meta/judged`, which holds the bundle last judged and
        its policy's bytes (Ruling 7).
      - If the bundles differ, it compiles the recorded policy against the inventory in force
        and runs the guard (`bundle.CheckAdmission(recorded, file, max_removed_percent, now)`).
    - **A refusal** says the guard's line once:
      `port49-broker: policy file refused at start against the bundle last judged (<bundle>):
      <refusal>; this replica stays not ready, mints nothing and takes no hold until
      broker.policy_file is fixed`.
      - It sets `port49_policy_file_refused` to 1.
      - It keeps `/readyz` at 503, so the API answers nothing that mints.
      - It polls the file every `policy_watch_interval` until a version passes, then goes on
        with its start.
    - **When the guard cannot judge,** the start goes on, as a first install does:
      - no record;
      - a record whose policy does not compile against the inventory in force (an inventory
        edit in between);
      - a record written without its policy, because the policy was over 1 MiB.
      Each case says one line naming why. The guard is a typo guard, not a security boundary.
      A broker stranded at 3am by an inventory change would cost every login.
      - **After a restore** the runbook deletes `meta/judged` (Ruling 7), so the first start
        after it has no record and is not judged: a refused file is not caught then. The
        runbook's step 3 says so, and says to check the policy file on every broker host
        before the brokers start (re-check).
    - **port49d judges nothing at start.** Its policy decides admission alone: a device it
      newly refuses is answered by another replica or its local method. The destruction the
      guard prevents is the broker's carry and purge.
18. **The restore witness: a runner that finds the store older than a replica saw it purges**
    (pre-flight re-check R6, which replaces the owner's first backstop). After an etcd restore
    `meta/judged` is the snapshot's, so a takeover would not purge, and a token redeemed since
    the snapshot is redeemable again until its sealed expiry. The runbook's delete (Ruling 7)
    stays, but forgetting it now fails closed.
    - **Why not the first backstop.** It was a runner seeing a response header below its own
      `Seen()`, or its own beat gone back. It misses both cases the runbook makes: every broker
      is stopped, so no runner has a `Seen()` or a beat to compare with, and `--bump-revision`
      moves revisions up. Nothing inside one snapshot shows that it is a snapshot: detection
      needs a record outside etcd that survives the restore, and `broker.state_dir` (Ruling 12)
      is one.
    - **What it compares.** A restored key keeps its original `ModRevision`, with or without
      `--bump-revision` (measured: `crypt/ledger.go:74-79`; `L35-restore-arista_eos.md`). So the
      snapshot's copy of a key the runner rewrites whenever the store moves sits below the last
      copy any replica saw, whichever way the cluster's revision went.
    - **`meta/witness`** holds no secret: the runner's name and the time.
      - The runner reads it every second, beside the ledger keeper (`keepWitness`). It rewrites
        it when the read's header is past the witness's own `ModRevision`, so any write since
        the last witness brings a new one, at most one a second.
      - A quiet store writes nothing: the rewrite's own revision is the one the next pass
        compares with, so it never feeds itself.
      - The write compares the `ModRevision` it read, so two runners for a moment (Ruling 6)
        cannot write one over the other.
      - The runner takes its record before it reads the witness, never after: a record taken
        after could hold a witness another runner wrote meanwhile, and purge at a routine
        handover (final check, Minor 1).
    - **Every port49-broker follows it.** One watch on the key sits beside the marks feed
      (`etcd.Store.FollowWitness`). Each replica keeps the highest `ModRevision` it has seen, a
      runner's own write included, in `broker.state_dir/witness.json`, as `{"prefix":
      "<prefix>", "mod_revision": N}`.
      - The file is owner only, written to a temporary file and renamed, at most once a second.
      - It is keyed by prefix, not by cluster ID, since a restore may or may not keep the
        cluster ID. A file for another prefix is no record, and says so.
    - **At a takeover,** after reading `meta/judged`, the runner reads `meta/witness`. An absent
      witness is revision 0. Below the replica's record, the store has lost writes this replica
      saw: the runner takes `meta/judged` as absent and purges every unspent token, writing
      `meta/superseded_all` as an unjudged bundle does:
      `port49-broker: runner: the store's meta/witness is at revision 812, below the 1907 this
      replica saw: the store was restored from a snapshot; every unspent token is purged and must
      be minted again (port49 token): 14 purged`.
    - **While running,** a pass that reads the witness below the replica's record is a restore
      under a running runner: the operator who also skipped "stop every broker". The runner
      says the same line and purges at once. It then puts the marks back from its copy, as its
      marks feed's hook does before a reload (Ruling 12), since a watch at a revision the
      restored store has not reached may not reload on its own.
    - **The record follows the purge, never the other way.** Only once the purge is done does
      the runner take the store's witness as its record (`witnessRecord.Reset`). Until then
      every pass, and every replica's takeover, still sees the restore, so a purge cut short by
      a lost hold is made by the next runner.
    - **What it cannot tell.**
      - A replica with no `witness.json` (a new host, a lost `state_dir`) says
        `port49-broker: runner: no witness record in broker.state_dir; cannot tell whether the
        store was restored; going by meta/judged alone`. If every replica's `state_dir` is lost,
        the runbook's delete is the only cover.
      - **A broker whose `state_dir` was lost or is new, started first after a
        `--bump-revision` restore,** means the restore is never caught. It does not purge, and
        its first witness lands above every other replica's record, so no later takeover sees
        the restore either. Without the bump, its witness lands below them, and the next
        takeover by a replica with a record catches it. So after a restore, start a broker whose
        `state_dir` survived first (the runbook's step 4, the operator notes).
      - A snapshot taken within about one keeper interval (1s) after the last witness any
        surviving replica recorded, where the only writes lost came after that witness, is not
        caught. The file is saved at most once a second too, so a replica host that crashes
        within a second of a witness may have recorded the one before.
    - **Which way it errs.** Each errs toward a purge: users run `port49 token` again, and the
      line says why.
      - A witness deleted by hand, or a `state_dir` reused against a new empty keyspace under the
        same prefix, purges once.
      - After a restore without `--bump-revision`, a replica that did not run the purge keeps its
        record above the store's revisions until they climb past it. A takeover by that replica
        before then purges once more.
    - **The roles.** `meta/` is read-only to the daemon, so port49d can neither suppress nor
      forge the witness. The broker's existing `meta/` write covers it; no grant is new.

19. **port49d refuses a redemption while the store is older than it followed** (controller
    Ruling T15c-c, 2026-10-04, from Task 15c's review I-2 and re-review 1 §5; built by Task
    15d). A restore brings back every single-use token redeemed since the snapshot, unspent,
    and a port49d serving before the first runner's purge would redeem it again: a replay
    window 7d did not have, since 7d purged at a start before any listener bound. The
    runbook's token delete (design §13, step 3) closes it when followed; this fails closed
    when it is not.
    - **What port49d keeps.** The highest `meta/witness` ModRevision it has followed, for the
      process's life: a restore that outlasts `hold_ttl` ends a run, and the next must still
      know. It follows the witness and also reads it, with `meta/purged`, at once and every
      second (`witnessEvery`): a watch can wait across a restore without `--bump-revision` at
      a revision the store has not reached, and never tell.
    - **Guarded.** A read that shows the witness below that, or gone after one was seen,
      refuses every token redemption `store_unavailable` before any token is looked up, and
      nothing else: marks, live contexts' decisions, the admin socket and metrics go on. A
      run after a store gone refuses too until its first read, once a witness was followed.
      `port49_redemption_restore_guarded` is 1, and the line says what to do.
    - **Released only by a purge.** The runner writes `meta/purged` once a purge of every
      unspent token is done: at a takeover's purge, either branch, and `purgeRestored`.
      port49d leaves the guard on a `meta/purged` whose ModRevision is above the header of
      the read that found the drop, so a snapshot's own `meta/purged` never releases it. A
      plain witness write is no purge: a runner with no record writes them without purging.
      Any whole purge after the restore leaves no restored token, so a takeover's purge
      releases it as well as the witness's (Task 15d's report).
    - **A failed read** changes nothing, said once per run of failures.
    - **What it leaves.** A port49d started after the restore has followed nothing and cannot
      tell; one whose read has not yet come since the store returned (up to a second within a
      run) may redeem; and a runner's purge that lands before port49d's first read after the
      restore leaves it guarded until the next purge or its restart. The runbook's token
      delete covers all three.

### Open for Ryan

Nothing is open. OR-1 was closed by Ryan on 2026-10-03 ("use your best judgement"), and is now
a ruling:

**OR-1 (closed). `port49 revoke`'s default `--socket`.** It is `/run/port49/port49d.sock`, and
on etcd revocation now lives on port49-broker's socket. Ruling 13 makes port49d's socket say
which socket to use, so nothing is revoked silently in the wrong place. There is no
anti-escalation default either way.
- **Ruled: keep the default.** A memory-store install keeps working unchanged. On etcd,
  port49d's socket names the broker's socket, and the operator passes `--socket`.
- **Not taken:** probing both paths, where an operator could not tell which process answered.
- Task 18 records it under the rulings as made, not as open.

**Worth reading before the merge** (rulings, not open questions):
- **Ruling 1.** On etcd, port49d.yaml with a `broker:` block is refused. A 7d deployment on etcd
  must move its `broker:` block into `port49-broker.yaml` and start `port49-broker` beside
  port49d.
- **Ruling 3.** The upgrade from 7d to 7e on etcd ends every live session once (form 3 does not
  open). Users log in again. A context read now waits for the context feed: a port49d whose
  feed has stopped goes dark although etcd answers (pre-flight C1).
- **Ruling 7.** Unspent tokens survive a broker rollout now. They are purged only when the
  bundle in force changed with no runner to judge the tokens minted under it.
- **Ruling 11.** On etcd port49d no longer takes the keyspace. A second port49d serves beside the
  first, so 7d's "stop the old one first" advice is withdrawn in every deployment shape: a
  second systemd unit or container starts beside the first, and on Kubernetes the `Recreate`
  strategy is no longer needed. It moves to nothing: port49-broker's replicas share the
  runner's hold.
- **Ruling 12.** On etcd the revocations file is gone. Each broker keeps its own copy of the
  marks, and after a restore the runner puts back every mark the store lost. A copy that
  missed a lift puts that mark back too, and says so (pre-flight I5).
- **Ruling 13.** With every broker down, `port49-broker revoke --offline` revokes through the
  store; with no broker host, an `etcdctl put` as root does (pre-flight I4).
- **Ruling 17.** A broker whose policy file the reload guard refuses, against the bundle last
  judged, starts not ready and takes no hold (pre-flight I6).
- **Ruling 18.** A runner that finds `meta/witness` below what its replica recorded in
  `broker.state_dir/witness.json` (an etcd restore, at a takeover or under a running runner)
  purges every unspent token, whether or not the runbook's delete of `meta/judged` was done. A
  replica with no record cannot tell, and a snapshot within about a second of the last witness
  is not caught.
- **Ruling 19.** A port49d that finds `meta/witness` below what it followed refuses every token
  redemption `store_unavailable` until a runner's purge writes `meta/purged`
  (`port49_redemption_restore_guarded` 1 meanwhile). Logins with a token fail, sessions and
  revocations go on.

## What the operator sees

The owner's rule: trace a mechanism on a bad day first. Every line below is printed by a task
in this plan, and the tests named pin it.

- **Upgrading to 7e-1, on etcd** (one port49d, as in 7d).
  - Re-apply `port49d store-roles` first. Without the daemon's read on `lw/`, the start stops
    at the ledger record (pre-flight M17):

    ```
    port49d: store: the daemon's role cannot read lw/, the ledger record: apply port49d store-roles (plan 7e) as etcd's root, then start again
    ```
  - Every live session ends once, said once per 10 minutes on each node, never as tampering:

    ```
    port49d: crypt: a context sealed by an earlier port49 (form 3) does not open: expected once after the 7e upgrade; replaced at its user's next login
    ```
  - Rolling 7e-1 back to 7d ends every session again: 7d does not open form 4.
- **Install, on etcd.**
  - Run `port49d store-roles --config /etc/port49/port49d.yaml --broker-config
    /etc/port49/port49-broker.yaml` and apply its output once, as etcd's root (one grant more
    than 7d's: the daemon's read on `lw/`).
  - Start one or more `port49-broker --config /etc/port49/port49-broker.yaml`, then one or more
    `port49d`, in either order.
  - A 7d port49d.yaml with a `broker:` block on etcd stops with:

    ```
    port49d: config: store.backend: etcd runs the broker as its own process (plan 7e): move the broker: block,
    with store.etcd.broker, into port49-broker.yaml and start port49-broker; name the policy port49d admits from
    under policy: (file, watch_interval)
    ```

    A 7e-2 port49d refused on its config can be rolled back to the 7e-1 binary, which still
    reads the 7d file (pre-flight M17).
- **A port49-broker start:**

  ```
  port49-broker: store: the broker's etcd certificate (CN=port49-broker) is valid until 2027-10-01T00:00:00Z (362 days)
  port49-broker: 3 revocation(s) in force from the store
  port49-broker: ledger: 1204 context key(s) known (1190 from the ledger record); following the store from revision 88213
  port49-broker: listening on 0.0.0.0:8443, metrics on 0.0.0.0:9050
  port49-broker: runner: took keyspace /port49/ ("port49-broker on brk-a (pid 4121, since 2026-10-04T09:00:00Z)"): this replica runs the start, the sweep and the policy refresh
  port49-broker: runner: every revocation in broker.state_dir/marks.json is in the store
  port49-broker: runner: 3 standing revocation(s) applied to the live contexts the store kept (0 context(s) marked revoked)
  port49-broker: runner: the bundle in force (b3f9…) is the one the last runner judged; no unspent token purged
  port49-broker: runner: 1204 live context(s) carried onto the policy in force (bundle b3f9…)
  port49-broker: runner: recorded bundle b3f9… as judged
  ```

  A second replica says, instead of the runner's lines, and every 30s:

  ```
  port49-broker: runner: keyspace /port49/ is run by "port49-broker on brk-a (pid 4121, since 2026-10-04T09:00:00Z)"; this replica serves the API and takes over if that one stops
  ```

  A replica whose last run still holds the lease says 7d's own-hold line instead (`… is still
  held by this replica's last run (…); waiting up to hold_ttl for its lease to expire`).
- **A replica serving another policy** (its file not yet propagated):

  ```
  port49-broker: policy: this replica serves bundle 77c1… and the runner ("port49-broker on brk-a (pid 4121, since …)") serves bundle b3f9…; set the same broker.policy_file content and broker.policy_watch_interval on every replica
  ```

  `port49_policy_bundle_matches_runner` is 0 there. When it reloads, the runner says
  `runner: a full context pass owed by "port49-broker on brk-b (…)" (bundle b3f9…)`, and carries
  every live context.
- **A port49d serving another policy** than the bundle last judged (re-check R5):

  ```
  port49d: policy: this port49d serves bundle 77c1… and the bundle last judged by the runner is b3f9…; set the same policy file on port49d (policy.file) as on every port49-broker (broker.policy_file)
  ```

  `port49_policy_bundle_matches_runner` is 0 on that port49d. Right after a rollout it reads 0
  until the runner's settle pass, so its alarm waits longer than a broker's.
- **A start on a policy file the guard refuses:**

  ```
  port49-broker: policy file refused at start against the bundle last judged (b3f9…): <the guard's reason, as refusalLine words a refused reload>; this replica stays not ready, mints nothing and takes no hold until broker.policy_file is fixed
  ```

  `port49_policy_file_refused` is 1 and `/readyz` answers 503 until the file is fixed.
- **A port49d start on etcd:**

  ```
  port49d: store: the daemon's etcd certificate (CN=port49-daemon) is valid until … (362 days)
  port49d: store: 3 revocation(s) in force from the store
  port49d: ledger: 1204 context key(s) known (1190 from the ledger record); following the store from revision 88240
  port49d: listening on 0.0.0.0:49, metrics on 0.0.0.0:9049, 5120 devices admitted
  ```
- **The runner lost** (its host died, or etcd stopped answering it). Within `hold_ttl` and a
  third more, another replica says `runner: took keyspace …`. The old one, if it lives, says:

  ```
  port49-broker: runner: lost the keyspace's hold (its lock key is gone, or etcd stopped answering with half its lease or less left); the runner's duties stop; this replica keeps serving the API and tries to take the hold again every 5s
  ```

  Meanwhile no policy refresh carries an edit into live contexts. `port49_policy_refresh_pending`
  says so on the replica that reloaded it.
- **Every broker down.** Open sessions run on: no port49d asks a broker anything (design §6).
  - A token already minted still logs in.
  - `port49 token` fails with the broker unreachable.
  - A policy edit changes admission at once, and live contexts only when a runner returns.
  - Measured on five images by L37 (Task 17).
  - **To revoke now**, on any broker host:

    ```
    # port49-broker revoke --offline --config /etc/port49/port49-broker.yaml --principal user:alice@example.com
    port49-broker: revoke (offline, no API): principal user:alice@example.com marked; 2 unspent token(s) deleted; 1 live context(s) marked revoked
    ```

    With no broker host, write the mark as etcd's root (Ruling 13 gives the command). Every
    port49d denies alice's next command either way.
- **A revocation on any replica.** `port49 revoke --socket /run/port49/port49-broker.sock
  --principal user:alice@example.com` on brk-b:
  - closes alice's held connections on brk-a and brk-b;
  - denies her open sessions on every port49d at their next command.
  - Measured by L37.
- **A revocation sent to port49d's socket on etcd:**

  ```
  port49 revoke: port49d runs no broker; revocation is port49-broker's admin socket (its admin_socket in port49-broker.yaml): run port49 revoke --socket <that path>
  ```

  It exits 1.
- **A store that hangs.** Each port49d acts as 7d's did, without a hold.
  - Its probe and its devices' requests open the context pool's circuit, and `hold_ttl` later
    it closes every listener and says why.
  - L37 measures how long that takes with no hold.
  - The runner loses its hold as 7d's port49d did, and the other replicas cannot take it until
    etcd answers.
- **A feed that falls behind** (a compacted watch): `port49d: store: the context feed's revision
  was compacted; seeding from the ledger record and scanning the store again` once, and
  `port49_store_feed_rescans_total{feed}` counts it. `port49_store_feed_up{feed}` is 0 while a
  feed re-establishes, and context reads wait meanwhile.
- **A context feed that stops** while etcd answers. Every context read newer than the feed
  waits up to `call_timeout` and is `store_unavailable`, and the guard counts it. The probe
  fails the same way. On port49d the context pool's circuit opens, and `hold_ttl` later it
  closes every listener, as on a hung store (Rulings 3, 11). On a broker the API answers 503
  `store_unavailable` for what reads a context. The line is `port49d: store: the context feed
  stopped (…); trying again every second`, with `port49_store_feed_up{feed="contexts"}` 0.
- **After an etcd restore** (design §13's runbook):
  - restore with `--bump-revision` and `--mark-compacted` and every port49-broker stopped, the
    restored members serving clients on loopback only;
  - there, as etcd's root, `etcdctl del --prefix <prefix>v1/t/` (a restore brings back every
    token redeemed since the snapshot, and a port49d that reaches the store first redeems it
    again), then `etcdctl del <prefix>v1/meta/judged`; only then restart the members on their
    usual client URLs, so no port49d or broker reaches a restored token; and check the policy
    file on every broker host: the first start after the delete has no judged bundle to guard
    against;
  - start the brokers.
  The first runner names the marks it put back from its copy, and purges the unspent tokens.
  Without `--bump-revision`, restart every port49d once the first runner has put the marks back
  (before that, a restarted port49d enforces none the restore lost). Otherwise a login made on
  a process started after the restore is denied `store_unavailable` on the processes that ran
  across it, until one of those writes at its key.

  Each port49d that ran across the restore keeps the marks it lost in force until then (Ruling
  5), and says so once its marks feed reloads:

  ```
  port49d: store: 1 revocation(s) this port49d enforces are missing from the store as its marks feed reloads (an etcd restore, or lifted on port49-broker while the feed was down) and stay in force here (to release one lifted on purpose, revoke it again on port49-broker, then lift it with port49 revoke --lift, or restart this port49d): principal user:alice@example.com
  ```

  (Task 14 review I-2: a lift alone of a mark the store lacks is `ErrNotRevoked` on port49-broker
  and reaches no feed, so the line names the revoke-then-lift that does. It is said once for one
  set of kept marks, review M-1.)

  A runner whose put-back fails before its marks reload (its store circuit open through the
  restore) does not reload: `port49-broker: store: the marks feed stopped (runner: putting
  broker.state_dir/marks.json's marks back into the store before the marks reload: …; the
  marks are not reloaded until they are back); trying again every second`.
- **A restore with the runbook's delete forgotten** (Ruling 18), at the takeover, or under a
  running runner:

  ```
  port49-broker: runner: the store's meta/witness is at revision 812, below the 1907 this replica saw: the store was restored from a snapshot; every unspent token is purged and must be minted again (port49 token): 14 purged
  ```

  A replica with no `witness.json` says instead, once per takeover:

  ```
  port49-broker: runner: no witness record in broker.state_dir; cannot tell whether the store was restored; going by meta/judged alone
  ```
- **The ledger record lagging:** `port49_ledger_pending` on the runner is the number of keys
  whose high-water the record does not yet hold. Above 0 for a minute is an alarm: a put-back
  there would survive a restart. `port49_ledger_behind` is 1 on the runner while its context
  feed is down, when pending cannot see what it misses. Both read 0 on every other replica.
- **New metrics:** `port49_store_feed_up{feed}`, `port49_store_feed_rescans_total{feed}` (`feed`
  is `contexts` or `marks`), `port49_ledger_pending`, `port49_ledger_behind`,
  `port49_store_fence_timeouts_total` (7e-1); `port49_policy_bundle_matches_runner` (7e-2).
- **Changed meaning:** `port49_store_keyspace_held` is 1 on the runner and 0 on every other
  replica and on every port49d. Alert on its sum over the brokers being 0 for twice `hold_ttl`.

## Global Constraints

Copied verbatim from `CLAUDE.md`, "Code conventions":

- Go 1.26+ (etcd's floor, plan 7d), module `github.com/rhwendt/port49`, `gofmt` and `go vet` clean, no cgo.
- **snake_case everywhere it is data**: YAML keys, JSON log keys, config, metric names.
- Reason codes are the closed vocabulary of spec §5.7 (`internal/decision/reasons.go`).
  Never invent one; add to the spec table first.
- The log never contains a token, password, challenge, or response. Credentials appear only
  as `credential_sha256`. An unvalidated body is never logged.
- No device identity in metric labels.
- Verify before claiming done: run `make test && make vet` and report the real output.

Carried from plans 2–7d, and still binding:

- **Every claim about device behaviour cites a `tests/lab/results/` note or a register row.**
  Lab register rules 1–4 apply. This plan opens L37 and L38 (Task 11) and measures them with L36
  (Task 17). Until a row closes, no doc asserts what it measures.
- **Security first:** no privilege escalation, no impersonation, no secret in a log, fail closed.
  Where a task leaves a choice, take the one that denies more and say so in the commit.
- **Narrow setters only for live contexts** (7d). Nothing re-puts a context but `SwapLogin` and
  `PutContext` (seeding and tests).
- **7a's ordering holds for every revocation:** the mark first, tokens before contexts, contexts
  twice.
- **Every read is linearizable.** Never `clientv3.WithSerializable()`. A watch is not a read; it
  only raises a high-water or a mark, never admits a record.
- **etcd's client logs never reach stderr** (`zap.NewNop()`).
- **No metric label names a principal, device, key or endpoint.** The new label `feed` is the
  closed set `contexts`, `marks`.

New in this plan:

- **No host holds both etcd identities.** No code path in `port49d` on etcd opens the broker's,
  and no code path in `port49-broker` opens the daemon's or reads `keys:`.
- **Every context seal carries a write sequence, and every context read is judged against the
  high-water** (Ruling 3). A watch event or a ledger record only raises; neither ever lowers a
  high-water or removes a floor. A watch event or a later scan makes no entry for a record
  below the base.
- **No context read is judged before the feed has passed its revision** (Ruling 3, the fence).
  The wait is bounded by the guard's call deadline and fails closed as `store.ErrUnavailable`,
  counted by the guard. Nothing admits a record because the feed is late.
- **The daemon's role never writes `lw/`, `sp/`, `rv/` or `meta/`.** `etcd.Roles` and
  `CheckIdentity` say so, and a test grants one and is refused.
- **The code blocks are written against `b508ba0` (7e-1) and `a5e4fe8` (7e-2).** Where the
  compiler or a test says a block is wrong about the tree or about etcd's API, fix the block
  minimally, keep the behaviour the step's test asserts, and say so in the task's report and
  commit. Never weaken a test to make a
  block pass.
- **Every commit is preceded by `gofmt -w` on the Go files the task touched, then `make build &&
  make test && make vet`.** Report their real output.
- **Branches.** 7e-1 is on `feature/broker-process` and 7e-2 on `feature/broker-split`. Never
  commit code to `main`. Name every path in `git add`; never `git commit -a`.
- Commit messages end with:
  ```
  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
  ```

## Review Focus

The input classes the spec implies and no task's happy path exercises, most likely to bite
first. Each has its test in the task named.

1. **A login on one port49d replica, the next packet on another, before the second's feed has
   seen the write.** It is admitted once the second's feed delivers it, within the read's
   wait, and never denied as an unseen key. The record's sequence is above the second's base,
   and above any high-water it knows at the key. *Task 7,
   `TestAnotherProcesssWriteIsAdmittedWithNoFeedBetween`; Task 8a,
   `TestAnotherProcesssWriteIsAdmittedOnceTheFeedDeliversIt`; Task 16,
   `TestALoginOnOneDaemonIsAnsweredOnAnother`.*
2. **A record put back on one replica while another replica, or a port49d started later, reads
   it.** The running replicas deny it once their feed has passed the later write, and wait
   for the feed until then. A port49d started after the put-back denies it from the ledger
   record. *Task 8, `TestTheFeedRaisesTheHighWaterSoAPutBackIsDenied`; Task 10,
   `TestAStartSeededFromTheLedgerRecordDeniesAPutBack`; Task 16,
   `TestAPutBackBeforeADaemonStartsIsDenied`. Each put-back there is bob's context over
   alice's, and each has a positive control.*
3. **A revocation made on one broker replica, while the agent holds a connection to another.**
   The other closes it, and every port49d denies the session's next command. *Task 9,
   `TestAMarkFromTheFeedClosesThisReplicasHeldConnections`; Task 16,
   `TestARevocationOnOneBrokerReachesTheOther`.*
4. **The runner killed mid-pass, cut off from etcd, or paused past its fence.**
   - Another takes the hold within `hold_ttl` and a third: of a graceful stop, and of a runner
     whose lease is never released.
   - The takeover purges only when the bundle changed unjudged.
   - A cut-off runner says it lost the hold and does not run again while the other holds.
   - Two runners for a moment write nothing wrong.
   *Task 15, `TestARunnerThatStopsIsReplaced`, `TestARunnerCutOffIsReplacedAfterItsLease`,
   `TestATakeoverPurgesOnlyAnUnjudgedBundle`, `TestACleanTakeoverRecordsItsBundleAsJudged`;
   Task 10, `TestTheLedgerRecordRaceKeepsTheHigher` (two keepers at once).*
5. **A log sink that stalls during a mint.** A reload still swaps within a second, and the
   mint's records land in order once the sink drains. *Task 4,
   `TestAStalledLogNeverHoldsAReload`, `TestEveryMintRecordFollowsItsBlobRecord`.*
6. **An etcd restore, with and without `--bump-revision`, with two processes.**
   - With the bump, a login after it is admitted on every process, and a restored record is
     denied.
   - Without it, a process started after the restore has its login denied by one that ran
     across it, which is why the runbook says to bump or restart every process.
   *Task 7, `TestALoginAfterARestoreIsAdmitted`.*
7. **A watch whose revision was compacted.** The feed seeds from the ledger record, then scans
   again. It only raises, so nothing is admitted that the scan before would have denied; a
   record above the mark in the rescan raises it; the rescan is counted. A put-back made in
   the gap, over a later login only the record holds, is denied after the rescan (re-check
   R1). *Task 8, `TestACompactedFeedScansAgainAndOnlyRaises`,
   `TestACompactedRescanSeedsFromTheLedgerRecord`; Task 9,
   `TestACompactedMarkFeedReloadsTheDifference`.*
8. **The daemon given the broker's reach on `lw/` or `sp/`.** port49d refuses to start. *Task 10,
   `TestCheckIdentityRefusesADaemonThatCanWriteTheLedgerRecord`.*
9. **A port49d.yaml naming the broker's identity, or a port49-broker.yaml naming `keys:`.** Each
   is refused at load, naming the key. *Task 13, `TestTheDaemonsConfigNeverNamesTheBrokersIdentity`,
   `TestTheBrokersConfigNeverNamesADeviceKey`.*
10. **A context feed that lags or has stopped, while a store writer puts back an earlier
    record or a pre-revocation one** (pre-flight C1). The read is never admitted: it waits, and
    is `store_unavailable`; once the feed delivers, it is denied. A dead feed fails the
    probe. etcd delivers an event before any progress notify at or above its revision (the
    fence's floor, re-check R2). *Task 8a, `TestAPutBackIsDeniedWhileTheFeedLags`,
    `TestARevocationFromAnotherProcessHoldsWhileTheFeedIsDown`,
    `TestAPingFailsWhileTheFeedIsBehind`; Task 8, `TestAWatchAnswersAProgressRequest`.*
11. **A put-back at a key this process never saw, brought by the feed or a rescan** (pre-flight
    I1). It makes no entry and is denied. *Task 8, `TestAFedPutBackAtAnUnseenKeyIsDenied`.*
12. **An etcd restore that loses revocations** (pre-flight I5). The runner puts back every mark
    its copy holds and the store lacks; a mark lifted through the watch is not put back, nor is
    one lifted on another replica across a short watch break within the compaction retention
    (final review 7e-1 I-1). A put-back that fails before a marks reload refuses the reload, so
    the lost mark is never lifted (re-review 1 C-2). Each port49d keeps the mark in force until
    then. *Task 15b, `TestATakeoverPutsBackAMarkTheStoreLost`,
    `TestALiftAcrossAShortWatchBreakIsNotPutBack`,
    `TestTheRunnersReloadHookRefusesTheReloadOnAFailedPutBack`; Task 14,
    `TestARestoreUnderARunningDaemonKeepsItsMarks`,
    `TestTheDaemonsReloadHookKeepsWhatTheStoreLost`.*
13. **A compromised user with every broker down** (pre-flight I4). The offline revocation, or a
    mark written as etcd's root, denies the next command on every port49d. *Task 15b,
    `TestAnOfflineRevokeDeniesWithEveryBrokerStopped`; Task 16,
    `TestARootWrittenMarkDeniesWithEveryBrokerStopped`.*
14. **A replica serving another policy than the runner's** (pre-flight I3). It says so; its
    reload has the runner carry the context it made under the old policy; no `meta/judged` is
    written meanwhile. A port49d serving another policy than the bundle last judged says so
    too (re-check R5). *Task 15a, `TestALateReplicasContextIsCarriedWhenItReloads`,
    `TestADaemonServingAnotherBundleThanTheJudgedSaysSo`.*
15. **A start on a file the reload guard would refuse** (pre-flight I6). It stays not ready and
    takes no hold until the file is fixed. *Task 15a,
    `TestAStartRefusesAFileTheGuardRefusesAgainstTheJudgedBundle`.*
16. **An etcd restore without the runbook's delete of `meta/judged`** (Ruling 18, re-check R6).
    A takeover whose replica recorded a later `meta/witness` purges, with `--bump-revision`
    too, and a token redeemed after the snapshot stays spent. A replica that only followed the
    witness catches it as the runner does. A quiet store writes no witness. Does the record
    follow the purge, so a purge cut short is made by the next runner? *Task 15c,
    `TestARestoredWitnessIsCaught`, `TestATakeoverAfterARestorePurgesWithoutTheRunbook`,
    `TestAWitnessRecordFromAnotherReplicaCatchesTheRestore`, `TestAQuietStoreWritesNoWitness`.*

## Conflict scan: where tasks share a file or an interface

The pre-flight review's scan (`preflight-review.md`, "Conflict scan"), as this revision leaves
it. Only the pairs that changed or were marked ✗ are listed; every other pair stands as the
review found it.

| Pair | Shared | Now |
|---|---|---|
| T1 ↔ T11 | decision 36's closing citation | T11 Step 1 replaces it with 7e-2's sections (M12) ✓ |
| T7 ↔ T15 | `sweepLoop` | `sweepLoop(ctx, s, brk, ledger, every, out)` from Task 7; Task 15 calls it as is (M16) ✓ |
| T7 ↔ T8 ↔ T8a | `Ledger` | Task 8 adds `ObserveFollowed`; Task 8a adds `Fence`, `knownAt` and `Fenced`. Each later task names them ✓ |
| T8 ↔ T8a | `ContextFeed.WatchContexts(…, progress, asks)` | Task 8 fixes the signature and etcd's progress handling, passing a no-op and nil; Task 8a wires the fence. The crypt fixtures (`feedOf`, `answeringFeed`) implement the new signature ✓ |
| T8a ↔ T14, T15, T15b | `crypt.Fenced` under the guard | the daemon (T14) and the broker (T15) fence their raw stores; the offline revocation (T15b) does not, since nothing follows there ✓ |
| T9 ↔ T15b | `store.MarkChange` (`Reloaded`) | Task 9 tells each change as an event or a reload; Task 15b's copy keeps a mark a reload found missing ✓ |
| T9 files | `revoke.go` (`matchMark`) | now in Task 9's Files ✓ |
| T10 ↔ T15 | `KeepLedger`'s `report(pending, behind)` | 7e-1's port49d and 7e-2's runner both set `LedgerPending` and `LedgerBehind`; both are zeroed when duties stop (I11) ✓ |
| T13 ↔ T16 | `config.StoreBlocks` | it reads either file with no role, so a 7d file still yields both identities for `store-roles`, while `Load` refuses it (I8; was ✗) ✓ |
| T13 | `internal/config/broker_role_test.go` | new file; `broker_test.go` untouched (I7; was ✗) ✓ |
| T14 ↔ `store_test.go` | `openStores`, the hold tests | each test listed and moved in Task 14 Step 7, the hold tests to Task 15 (I9; was ✗) ✓ |
| T15 ↔ T15a | `recordJudged`, `PutJudged(ctx, bundle, policy)`, `JudgedRecord` | Task 15 writes the record with its policy; Task 15a's guard reads it and adds the every-replica condition ✓ |
| T15 ↔ T15b | the takeover's steps | Task 15b inserts `restoreMarks` after the re-index and before `ApplyMarksAtStart` ✓ |
| T15b ↔ T16 | `askAdminAt`, `adminSocketOf` | written in Task 15b, used in Task 16 ✓ |
| T10 ↔ T16 | `waitForLedgerSeq`, `sharedUsernamePolicy`, `brokerConfigWith`, `mintAs` | written in Task 10 (`cmd/port49d`), moved by Task 12, used in Task 16 ✓ |
| T17 ↔ every lab test | `tests/lab/topologies/*`, `tests/lab/configs/*` | not changed; `startSplit` pushes the second server and removes it (I13; was ✗) ✓ |

Revision 2 adds the re-check's rows (`preflight-review.md`, "Re-check"), and those its findings
create:

| Pair | Shared | Now |
|---|---|---|
| T8 ↔ T8a | `FollowContexts(ctx, feed, src, …)` | Task 8 adds `src store.LedgerSource` and `rescan`, which seeds from it before a compacted watch's scan (R1); Task 8a raises the fence after `rescan`. Every crypt fixture call passes `nil` or a `marksOf` ✓ |
| T8 ↔ T10, T14, T15 | `FollowContexts`'s `src` | Task 8's port49d passes `nil`; Task 10 passes the daemon's raw store, as `LoadLedger` does; Task 14 keeps it on the daemon and Task 15 passes the broker's ✓ |
| T8a ↔ T10 | `Fence.Up` → `port49_ledger_behind` | Task 8a produces it, Task 10's keeper reports it ✓ |
| T8a ↔ T15b | the offline revocation | unfenced: no feed is attached, so `Wait` returns at once ✓ |
| T9 ↔ T15b | `store.MarkChange` (`Reloaded`); the put-back line | the copy keeps a mark a reload found missing; `namedMarks` names each mark put back (R4) ✓ |
| T14 ↔ T15a | `stores.judged`, `keepDaemonBundle` | Task 14's daemon start; Task 15a adds the field in `openStores` and the goroutine in `runOnce`, joined before `sts.close` (R5) ✓ |
| T10 ↔ T15c | the keeper's pass | the witness rides the keeper's interval as `keepWitness`, a sibling duty in the runner: `crypt.KeepLedger` knows nothing of `meta/` and is unchanged ✓ |
| T15 ↔ T15c | `takeover`'s purge, `duties` | the witness check runs before the judged-bundle comparison (R6), and `purgeRestored` is the unjudged purge's two calls; `duties` gains `keepWitness` ✓ |
| T15a ↔ T15c | the takeover's judged check | the witness decides first; a `meta/judged` that matches is then not consulted for the purge, and `recordJudged` after the carry is unchanged ✓ |
| T9, T15b ↔ T15c | the marks feed, `marksReloaded` | `FollowWitness` is a second watch beside the marks feed, on its own goroutine; after a running purge `keepWitness` sends on `marksReloaded`, so the put-back is Task 15b's ✓ |
| T13, T15b ↔ T15c | `broker.state_dir` | `witness.json` beside `marks.json`, written the same way; `copyBroker` gives each copy a `state_dir` of its own ✓ |
| T2 ↔ T15c | `etcdtest.go` | Task 2 changes `StartCluster`; Task 15c adds `Server.Backup` and `Server.Restore` and keeps the spec `Start` used: additive ✓ |
| T11 ↔ T15a, T15c | design §13 runbook, decision 36, §14 | step 3 names the guard's blind start after the delete, and the witness if the step is forgotten; decision 36 and §14 name the witness and port49d's gauge ✓ |

The amendment to 7e-1 as built (final review 7e-1, its two re-reviews, and the roadmap's
"Interfaces 7e-1 changed") adds these:

| Pair | Shared | Now |
|---|---|---|
| 7e-1 ↔ T14, T15, T15b | `store.FollowMarks(ctx, feed, m, from, on, up, rescanned func() error, logf)` | every caller passes a hook that returns an error to refuse the reload: port49d `daemonReloadHook` (T14), Task 15's counter until T15b; then `reloadHook` (T15b) on every replica: the runner puts back, and a non-runner replica keeps what its copy holds (pre-flight 7e-2 P-3). `progress` is `WatchRevocations`'s, wired inside `FollowMarks`; no caller passes it ✓ |
| 7e-1 ↔ T14 | `store.Marks` | T14 adds `Keep`, used by port49d's hook and its start after a store gone (`keepLost`), and by every broker replica's hook (T15b; pre-flight 7e-2 P-3); `authMarks` is `run`'s, as the ledger is, and each `runOnce` sets `Count` before `openStores` (T14); `runBroker` sets it before its `LoadMarks` (T15) ✓ |
| T14 ↔ T15b | `namedMarks` | written in T14 (`daemon.go`) for the daemon's keep line, with its test; T15b's put-back line uses it ✓ |
| 7e-1 ↔ T14 | `marksReloadHook`, `putBackFileMarks` | `marksReloadHook` and its test are deleted in T14: on etcd the file is retired, and on memory no marks feed runs. `putBackFileMarks`, `withHeld` and `persister(st, path, held, enforced, m)` stay for memory, with the persister's tests; Task 18 names `putBackFileMarks` as called by tests alone ✓ |
| 7e-1 ↔ T14, T15 | `restore_linux_test.go`, `TestARestoreUnderARunningPort49dKeepsTheFilesMarks` | replaced: its daemon half by T14's `TestARestoreUnderARunningDaemonKeepsItsMarks`, its put-back half by T15b's runner tests; its file half is retired with the file ✓ |
| 7e-1 ↔ T15 | `unopenableSayer` | gains `prefix`: `port49d` or `port49-broker`, so each process's crypt lines carry its own name ✓ |
| 7e-1 ↔ T14, T15 | `openStores`'s M-3 and M-4 wiring | the split daemon keeps both; `runBroker` sets both feed series to 0 and `ledger.Fence().OnTimeout(m.StoreFenceTimeouts.Inc)` before its store wait ✓ |
| T15b ↔ T15c | `marksReloaded` | still `chan struct{}`, buffered one. On each receive `duties` runs `restoreMarks` and then applies every standing mark to the kept contexts. T15c's running purge sends on it, as before. The feed's hook sends on it too, but only after its own synchronous put-back has landed, so the reload never waits on `duties` ✓ |

The pre-flight of the amended 7e-2 (`preflight-7e2.md`, "Cross-task table") marked these ✗;
each now reads:

| Pair | Shared | Now |
|---|---|---|
| T11 ↔ T14, T15b, T15c | the runbook's no-bump restart | every port49d is restarted only after the first runner's put-back line (P-2; was ✗) ✓ |
| T13 ↔ T14 | hand-built test configs, the reload rig | `brokerConfigWith` sets `Policy`, and `newReloadRig` sets `Policy.WatchInterval`, in Task 13; both files are in its commit (P-8; was ✗) ✓ |
| Ruling 11 ↔ T14 | the marks across runs (`authMarks`) | `run`'s, as the ledger is; a run after a store gone keeps what the store lost before it loads (`keepLost`) (P-1; was ✗) ✓ |
| 7e-1 ↔ T14 | `Marks.Count` before the first load | `authMarks` is made in `run`, and each `runOnce` sets `Count` before `openStores` (P-1; was ✗) ✓ |
| T14 ↔ T15 | `newReloader(cfg, live, log, pass, m, now)` | `reload_test.go`'s caller is in Task 14's Files and commit (P-8; was ✗) ✓ |
| T14 ↔ T15 | `onSettled` | `func(pol *policy.Policy)` in both (P-10; was ✗) ✓ |
| T14 ↔ T15 | `checkSealKeys(…, write bool)` | T15 `true`, T14 `false`; `store_test.go`'s eight calls gain `, true` in Task 14 (P-8) ✓ |
| T14 ↔ T15, T15a, T15b, T15c, T16 | the daemon start helper | `startSplitDaemon` and `startSplitDaemonStop`; `certstatus_test.go`'s `startDaemon` stays (P-7; was ✗) ✓ |
| T14 ↔ T16 | the second daemon's config | `copyDaemon` gives each copy its own `admin_socket`, spool path and metrics address; `f.copyDaemon` is Task 15's (P-9; was ✗) ✓ |
| T14 ↔ T15b | `Marks.Keep` | port49d's, and every non-runner broker replica's through `r.marks` (P-3) ✓ |
| 7e-1 ↔ T14, T15, T15b | `FollowMarks`'s `rescanned` | a non-runner's hook keeps what its copy holds, and a failed read refuses the reload (P-3; was ✗) ✓ |
| T15 ↔ T15a | `recordJudged`'s every-replica condition | a replica's bundle record is deleted at its graceful stop, so Task 15's restart tests still see their "recorded bundle" lines; a replica that dies leaves its record to lapse by `ExpiresAt` (P-5; was ✗) ✓ |
| T15 ↔ T15a, T15c | `meta/` reads and writes | every KV call on `s.ctxKV`; `Judged` reads the key and tells an undecodable record itself (P-6; was ✗) ✓ |
| T15a internal | `Bundles` liveness | `BundleRecord.ExpiresAt` decides; the lease only reclaims (P-4; was ✗) ✓ |
| T15a ↔ T15a, T15b, T15c, T16 | `waitUntil`, `readyz` | `revocations_test.go`'s `waitUntil(t, what, cond)` at every call; the plan's `readyzAt(t, addr)` (P-7; was ✗) ✓ |
| T15 ↔ T15a, T15b, T15c, T16 | `copyBroker`, `mintOn`, `editPolicy` | defined in Task 15's helper list (P-9; was ✗) ✓ |
| T15 ↔ T15b | the runner's fields | `copy`, `marks`, `marksReloaded` (P-3) ✓ |
| T15 ↔ T15c | `retryCtx`, `sleepCtx`, `orNone` | defined under Task 15's `recordJudged` (P-9) ✓ |
| T16 ↔ 7e-1 | the held broker connection | 7e-1's `heldBrokerConn` (P-13; was ✗) ✓ |
| T17 ↔ README | the Junos re-authorization note | the 7d note in `README.md`, replaced in Task 17 Step 3's commit (P-11) ✓ |

## Running the lab (Task 17)

The lab host is beehive. The owner has standing consent for lab runs, and the lab is
single-occupant.
- **Instructions.** The controller writes
  `.superpowers/sdd/2026-10-03-07e-broker-process/lab-instructions.md` from 7d's, amended as
  below, before Task 17 dispatches. Task 17 Step 0 checks it.
- **Every run is from a detached worktree pinned to a commit:**
  `git worktree add --detach /home/rwendt/git/port49/.worktrees/lab-7e <sha>`, then `make build`
  there, which now builds `bin/port49-broker` too. Never build in the shared feature worktree
  during a run.
- **The pinned commit includes `tests/lab/split_test.go`.** Task 17 Step 1 commits it as
  `test(lab):` first.
- **One platform at a time:** `PORT49_LAB_PLATFORMS=eos`, then `nxos`, `iosxe`, `vjunos`,
  `vsrx`.
- **The shared topologies are not changed** (pre-flight I13).
  - The second TACACS+ server (`172.100.100.2`) is pushed onto each device by `startSplit`, at
    the start of each split test, and removed at its end (`t.Cleanup`).
  - Every other register test (L1–L36) therefore runs with one server listed, as it was
    measured.
  - Step 2 re-runs one L35 cell (`TestStoreOutageEndToEnd`'s hung-store cell, on EOS) after
    the split tests, and checks it matches `L35-arista_eos.md`.
- **An INVALID cell keeps its row open.** A cell recorded INVALID on a named image (as L35's
  Ruling T15-a recorded one) leaves that row open for that image. The row is not closed with an
  INVALID cell in it.
- **A stall watchdog** runs for the whole run (background, re-armed on every wake) on the test
  log, capture growth and results files, with a 25-minute stall threshold, except that L36's
  15-minute re-authorization wait raises it to 40 minutes on the Junos images. Match the test
  binary exactly: `pgrep -f "^/tmp/go-build[^ ]*/lab\.test"`.
- **After every platform:**
  - no `port49d` holds `172.100.100.1:49` or `172.100.100.2:49` (the second replica);
  - no `port49-broker` and no agent run (`pgrep -f 'port49 agent'`);
  - the topology is destroyed;
  - `ss -ltnp | grep -c lab.test` prints 0.
- **Before removing the pinned worktree,** copy the results and the raw captures
  (`tests/lab/captures/L37-*`, `L38-*`, `L36-*`) to the feature worktree, and run `make
  evidence` there. The labpcap and count-only audits must pass on the branch that commits them.

## File Structure

```
docs/design/2026-08-23-policy-engine-spec.md   MOD  d36 (7e-1 part), d35 amended (the ledger), §13's floor note, §14 (Task 1);
                                                    d36 (7e-2 part, its citation extended), d32, d34 and d35's "until plan 7e"
                                                    clauses amended, §5.1.3, §12, §14, L37 and L38 opened (Task 11); L36, L37,
                                                    L38 measured (Task 17)
docs/design/2026-08-21-port49-design.md        MOD  §8 the ledger, §12 store interface (Task 1); §6, §12 matrix, §13 (the
                                                    restore runbook), §15, §17, §19 (Task 11); device cells (Task 17)
internal/store/etcd/etcdtest/etcdtest.go       MOD  StartCluster retries until a deadline (Task 2); Server.Backup, Restore (Task 15c)
internal/store/etcd/etcdtest/etcdtest_test.go  MOD  (Tasks 2, 15c)
internal/config/config.go                      MOD  KeyIDShape (Task 3); Role, Policy, LoadBroker, key_refs, state_dir, the
                                                    refusals, StoreBlocks (Task 13)
internal/config/config_test.go                 MOD  (Tasks 3, 13)
internal/config/broker_role_test.go            NEW  (Task 13; broker_test.go exists and is left alone)
internal/decision/buffer.go, buffer_test.go    NEW  Buffer (Task 4)
internal/token/minter.go, minter_test.go       MOD  Request.Log (Task 4)
internal/broker/broker.go, broker_test.go      MOD  the buffered request, putBlob, bounded blobsSeen (Task 4); supersede in the store,
                                                    SupersededAll removed (Task 5); MarkChanged (Task 9)
internal/broker/refresh.go, refresh_test.go    MOD  supersede (Task 5); RefreshTokens (Task 15)
internal/broker/revoke.go, revokeown.go        MOD  supersede(ctx, …) (Task 5); matchMark (Task 9)
internal/store/store.go                        MOD  SupersedeTokens, SupersededAt, SupersedeAll, SupersededFor (Task 5); RevStore.Seen,
                                                    RevStore.Ping (Task 6); LedgerMark (Task 7); ContextChange, ContextFeed, ErrCompacted,
                                                    LedgerSource, LedgerSink (Task 8); MarkFeed, MarkChange (Task 9)
internal/store/marks.go, marks_test.go         MOD  Marks.All; LoadMarks, FollowMarks (Task 9); Marks.Keep (Task 14)
internal/store/memory/memory.go, _test.go      MOD  superseded (Task 5); Seen, Ping (Task 6)
internal/store/etcd/keys.go                    MOD  famSuperseded sp/ (Task 5); famLedger lw/ (Task 10)
internal/store/etcd/superseded.go              NEW  (Task 5)
internal/store/etcd/etcd.go, contexts.go       MOD  seenRev, Seen, every context response observed (Task 6)
internal/store/etcd/feed.go, feed_test.go      NEW  ScanContexts, WatchContexts with progress (Tasks 8, 8a); Revocations,
                                                    WatchRevocations (Task 9)
internal/store/etcd/ledger.go, ledger_test.go  NEW  LedgerMarks, PutLedgerMarks (Task 10)
internal/store/etcd/roles.go, roles_test.go    MOD  sp/ never, lw/ read for the daemon; probes (Task 10)
internal/store/etcd/meta.go, meta_test.go      MOD  Judged, PutJudged (Task 15); Bundles, PutBundle, RefreshOwed, PutRefreshOwed,
                                                    ClearRefreshOwed (Task 15a); WitnessRead, Witness, PutWitness,
                                                    FollowWitness (Task 15c)
internal/store/etcd/etcd_test.go               MOD  the restore test on the new ledger (Task 7)
internal/store/guard/guard.go, guard_test.go   MOD  the three new methods routed (Task 5); Seen, Ping (Task 6)
internal/store/crypt/crypt.go                  MOD  form 4, seq, the ledger on reads and writes, ErrEarlierForm, OnUnopenable's
                                                    why (Task 7); supersede pass-through (Task 5)
internal/store/crypt/ledger.go                 MOD  rewritten: high-water, base, floor, prune, dirty (Task 7); ObserveFollowed
                                                    (Task 8); the fence it owns (Task 8a)
internal/store/crypt/follow.go, follow_test.go NEW  LoadLedger, FollowContexts and its rescan seeded from the record (Task 8);
                                                    KeepLedger (Task 10)
internal/store/crypt/fence.go, fence_test.go   NEW  Fence, Fenced, ErrFeedBehind (Task 8a)
internal/store/crypt/crypt_test.go             MOD  the ledger's tests on the new rule (Task 7)
internal/store/storetest/superseded.go         NEW  SupersededIsTheLaterAndExpires (Task 5)
internal/store/storetest/storetest.go          MOD  Run lists it (Task 5)
internal/daemon/metrics/metrics.go, _test.go   MOD  store_feed_up, store_feed_rescans_total (Task 8); ledger_pending, ledger_behind
                                                    (Task 10); policy_bundle_matches_runner (Task 15a)
cmd/port49d/store.go, main.go                  MOD  the sayer's lines (Task 7); the feeds, the fence and the keeper wired, Seal
                                                    replaced by the base (Tasks 8–10)
cmd/port49d/store_test.go                      MOD  the sayer's lines (Task 7)
cmd/port49d/store_e2e_test.go                  MOD  the put-back test on the record (Task 10)
cmd/port49d/*.go → internal/port49d/*.go       MOV  package port49d (Task 12)
cmd/port49d/main.go                            NEW  the shim (Task 12)
cmd/port49-broker/main.go                      NEW  the shim (Task 15)
internal/port49d/daemon.go                     NEW  the daemon's start on etcd, the probe, daemonReloadHook, keepLost, namedMarks (Task 14)
internal/port49d/revocations.go, _test.go      MOD  marksReloadHook and its test deleted (Task 14)
internal/port49d/restore_linux_test.go         MOD  the file's restore test replaced by the split daemon's (Task 14)
internal/port49d/store.go                      MOD  unopenableSayer(prefix, …) (Task 15)
internal/port49d/store_test.go                 MOD  the hold tests moved to the runner, the rest to the split daemon (Task 14)
internal/port49d/brokerd.go, runner.go         NEW  runBroker, the runner (Task 15); revoke --offline (Task 15b); the witness
                                                    followed, keepWitness, the takeover's check, purgeRestored (Task 15c)
internal/port49d/policyskew.go, startguard.go  NEW  the bundle record and refresh_owed, port49d's gauge on meta/judged; the guard
                                                    at start (Task 15a)
internal/port49d/main.go, store.go             MOD  keepDaemonBundle wired, stores.judged (Task 15a)
internal/port49d/markscopy.go, offline.go      NEW  broker.state_dir/marks.json; the offline revocation (Task 15b)
internal/port49d/witness.go, witness_test.go   NEW  broker.state_dir/witness.json, restored (Task 15c)
internal/port49d/reload.go                     MOD  live, log, refresher (Task 14); the settle's priors, onSettled (Task 15);
                                                    onSwap, the full pass owed (Task 15a)
internal/port49d/storeroles.go                 MOD  --broker-config, StoreBlocks (Task 16)
internal/port49d/split_e2e_test.go             NEW  the fleet end to end (Task 16)
internal/daemon/admin/admin.go, admin_test.go  MOD  RevokeElsewhere (Task 14); DiagnoseElsewhere (Task 15)
Makefile                                       MOD  build port49-broker (Task 15)
tests/lab/split_test.go                        NEW  L37, L38, L36 (Task 17)
tests/lab/harness_test.go                      MOD  startSplit, the second server pushed and removed, the second replica's
                                                    address (Task 17)
tests/lab/results/L36-*, L37-*, L38-*.md       NEW  written by the run (Task 17)
docs/superpowers/plans/README.md               MOD  7e written (this commit); 7e-1 as built (Task 10 Step 7); 7e as built (Task 18)
```

The topologies under `tests/lab/topologies/` and the startup configs under `tests/lab/configs/`
are not changed (pre-flight I13; "Running the lab").

Twenty-two tasks in two merges:
- **7e-1 (Tasks 1–10, with 8a):** Task 1 is docs, first; Tasks 2–3 are carried fixes; Task 4 is
  the emits; Tasks 5–10 are the store and the ledger, 8a the feed fence.
- **7e-2 (Tasks 11–18, with 15a, 15b and 15c):** Task 11 is docs, first; Task 12 is a move with
  no behaviour change; Tasks 13–16 are the processes, 15a policy across replicas, 15b the marks
  copy and the offline revocation, and 15c the restore witness; Task 17 is the lab and gates
  the merge; Task 18 is the as-built docs.

---

# Part 7e-1: the store a fleet shares (`feature/broker-process`, off `main`)

### Task 1: The spec and the design say what 7e-1 builds

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`
- Modify: `docs/design/2026-08-21-port49-design.md`

**Interfaces:** none. 7e-1's tasks cite the text this one writes.

No code. Each edit names a one-line fragment to find, which does not wrap, and the text to put
after it or in its place.

**What this task writes, and what it leaves.** Only what 7e-1 builds: the write sequence, the
ledger record, the feeds and the feed fence, `superseded` in the store, the emits, and the
key-id charset. The two
processes, the runner, the config split, the sockets, the retired file, L37 and L38 are Task 11's,
the first commit of 7e-2. Nothing here asserts what a device does.

- [ ] **Step 1: Decision 36, 7e-1's part.** In spec §13, after decision 35's closing line
  `(§5.1.4, §5.6, §5.7, §12, §14, §15; design document §8, §12, §13, §15, §17)` and before
  `### Deferred, with reasons`, add:

  ```markdown
  **36. The broker is its own process, any number of each on one keyspace; the ledger is a
  sealed write sequence every process follows, and a ledger record the daemon cannot write.**
  *Plan 7e, 2026-10-03, rulings where the design was silent, each the option that denies more
  (the owner may override them).*

  - **A sealed write sequence replaces the write ID.** Every context seal (form 4) carries a
    sequence: the highest of the revision the write compares on, the highest store revision
    this process has been told of, and one above the highest sequence it knows at the key. Each
    write that lands at a key is therefore sealed above every earlier one, and no store writer
    can forge it. A context sealed in form 3 does not open: denied, replaced at the next login,
    and revoked by the refresh as tampered. On etcd every live session ends once, at the
    upgrade.
  - **The ledger is a high-water mark per key.** A read admits a record sealed at or above the
    highest sequence this process knows at its key, and raises it; below is denied
    `store_unavailable`, as decision 35's ledger denies a record not last written. A key it has
    no mark for admits a record sealed at or above the revision just past its start's scan of the
    contexts: anything at a key then was scanned. A login sealed by another process before that
    scan and committed after it is below it too, as a put-back is, and is denied on this process
    until the next write at its key. A read that raced a write is read again, up to twice. A
    write of unknown outcome needs nothing more: if it landed it is the higher, and if not, the
    record the mark names is still the store's.
  - **No record is judged before this process's context feed has passed it.** A read waits until
    the feed has delivered every change through the record's revision, asking the store for the
    feed's progress, for at most the store's call timeout; a feed still behind then is
    `store_unavailable`, counted as a store failure, so a feed that has stopped takes port49d dark
    as a store that has stopped does. A record at the revision this process last knew at its key
    needs no wait. A put-back is a store write, so it commits above the write it hides, and once
    the feed has passed it the later write has raised the mark. Another process's later login is
    therefore admitted, and an earlier record put back is denied, whichever process wrote either
    and however late the feed. This rests on etcd never sending a progress notification ahead of
    an event it has not delivered, which etcd 3.4.24, 3.5.8 and every 3.6 guarantee; an older
    etcd is a known risk.
  - **After an etcd restore** a process's next write seals above every record it knew, so its
    login is admitted and a restored record is denied. Restore with `--bump-revision`: without
    it, a process started after the restore seals below the mark a process that ran across it
    holds, and its logins are denied there until that process writes at the key, so restart
    every process.
  - **Every process follows the store's contexts.** After its start's scan it watches the context
    family from that revision. Each change raises the key's mark, never lowers it, and makes no
    mark for a record below the base. A plaintext `revoked_at` at the mark's sequence is the
    key's revocation floor, cleared only by a later sequence, so a revocation whose seal failed
    holds on every process that saw its mark land. A watch whose revision was compacted seeds from
    the ledger record, as a start does, then scans again, raising only: a scan sees each key's
    latest record, and a login a put-back hid while the watch was down is in the record alone.
    A mark is kept while a record it saw could be live: to the latest sealed
    ceiling seen at the key and `session.grace_window`, and for good for a `never` context.
  - **The ledger record.** The process that holds the keyspace writes each key's mark, its
    revocation floor and how long to keep it to `lw/<nas>/<user>`, about once a second, raising
    only, by a compare on the record's revision. The daemon's etcd role reads it and never writes
    it. Every start seeds its ledger from it before it scans, so a record put back while every
    process was stopped is denied at its key when the record holds a later mark there, and so is
    one put back while a process's watch was compacted. Left: a key written and put back within
    the record's lag, about a second, or while no process held the keyspace or its feed was
    down, and before one recorded it. `port49_ledger_pending` and
    `port49_ledger_behind` say when the record lags.
  - **An earlier form says so.** A context sealed in form 3 is named as sealed by an earlier
    port49, expected once after the upgrade, never as altered.
  - **The marks are followed too.** Every process loads the revocation marks with the revision
    they were read at, before it serves, and follows them from there. A mark that lands closes
    the held broker connections it names in this process; a lift removes it. A compacted watch
    loads them again and applies the difference.
  - **What the broker remembers.** When a refresh or a revocation deleted a key's unspent tokens is
    kept in the store (`sp/`, the broker's role alone) for 20 minutes, past any token's
    `token_ttl` (at most 15m): an idempotent replay on any broker process mints afresh after it.
    Which blobs a process has emitted into its decision log stays the process's, bounded at
    4096: each process's log stays replayable alone, and forgetting costs a repeated `blob`
    record. Which quarantined contexts the refresh recorded stays the refresh's, pruned at every
    complete pass.
  - **The records a mint writes while it holds the policy** are buffered and written once it lets
    go, in order, before its response: a log that stalls never stalls a reload. A blob counts as
    emitted once its record has landed.
  - **An encryption key id** is 1 to 64 of `A-Z a-z 0-9 . _ -`, refused at load otherwise: it is
    in every sealed record's header and every line about one that will not open.

  (§5.1.4, §5.6, §5.7, §14; design document §8, §12, §17)
  ```

- [ ] **Step 2: Decision 35's ledger, amended.** In decision 35, find the bullet that begins
  `- **The ledger.** port49d keeps, per context key, the write it last made there or first read`.
  At the end of that bullet's first paragraph (after `does not open, and is replaced the same
  way.`), add:

  ```markdown
  *Amended by decision 36 (plan 7e):* the write ID is a sealed write sequence, the ledger a
  high-water mark per key that every process follows, and the start's seal a base revision; a
  form-3 record does not open.
  ```

  In the same decision's "What store write access still yields" bullet, after `**Across a
  restart it is impersonation:**`, insert:

  ```markdown
  (narrowed by decision 36: a start denies a record below the mark the ledger record holds at
  its key)
  ```

- [ ] **Step 3: The floor across processes, in §13.** The floor is named once in the spec, in
  §13, decision 35's "What store write access still yields" bullet (pre-flight M2: §5.1.4 does
  not name it). Find the one line
  `    time and the floor, until a later write of this process lands at the key. The floor`
  and replace `until a later write of this process lands at the key.` on it with `until a
  later write lands at the key (with several processes on one store, each holds the floor of
  every revocation whose plaintext mark its context feed delivered, and reads nothing before
  that feed has passed it; decision 36).` Leave the rest of the bullet.

- [ ] **Step 4: §14's ledger assertions.** In §14, under "Shared store", replace the bullet that
  begins `- **The ledger**: another login's context written back at a key is denied` with:

  ```markdown
  - **The ledger**: another login's context written back at a key is denied, and so is an
    earlier version of the same context put back after a later write landed, whichever process
    made either. Another process's later write at a key is admitted once this process's feed
    has delivered it. A key with no mark admits only a record sealed past the start's scan, and
    a put-back the feed or a rescan brings at such a key is denied. A process started after a
    put-back denies it when the ledger record holds a later mark at the key. With
    `--bump-revision`, a login after an etcd restore is admitted on every process and a
    restored record is denied; without it, a login on a process started after the restore is
    denied on one that ran across it. A form-3 context does not open, and is named as an
    earlier form.
  - **The feed fence**: while this process's context feed lags or has stopped, a record put
    back over another process's later write, or over its revocation, is never admitted: the
    read waits and is `store_unavailable`, and once the feed delivers, it is denied. A ping
    through the fence fails while the feed is behind.
  - **The feeds**: a context change raises its key's mark and never lowers it; a plaintext
    revocation at the mark's sequence is a floor a put-back cannot clear; a compacted watch
    seeds from the ledger record and scans again, and a put-back made in the gap over a later
    login the record holds is denied after it. A progress notification never precedes an event
    at or below its revision. A mark landing on one process closes that process's held
    connections it names, and a lift removes it.
  - **The ledger record**: `port49_ledger_behind` is 1 while the keeper's context feed is down,
    and both ledger gauges are 0 once its duties stop.
  - **The emits**: a log sink that stalls during a mint never stalls a reload, and every mint
    record follows its blob record.
  ```

- [ ] **Step 5: Design §8, the ledger.** In design §8, replace the bullet that begins
  `- **The ledger.** port49d keeps the write it last made, or first read, at each key, named by`
  (through `sealed ledger denies a context at any key it has not seen, unless this process wrote
  it.`) with:

  ```markdown
  - **The ledger.** Each context seal carries a write sequence, sealed with it: above the
    revision the write compares on, above every store revision the writing process has seen,
    and above every sequence it knows at the key. Every process keeps the highest sequence it
    knows at each key, from its own writes, its reads and a watch on the store's contexts, and
    denies a context sealed below it: another login's record, or an earlier version of the same
    context, written back. It judges no record before its watch has delivered every change
    through the record's revision, so a watch that lags or has stopped cannot let a put-back
    through: the read waits, and fails as a store failure. A key it has no mark for admits only
    a record sealed past its start's scan. The process holding the keyspace keeps each key's
    mark in a ledger record the daemon's etcd role cannot write, and every start is seeded from
    it (policy engine spec §13, decision 36).
  ```

  In the paragraph after it (`- **What store write access still yields is replay**`), replace
  these two whole lines (pre-flight M2: each is quoted as it stands, indentation included):

  ```
    before the start's reads seal the ledger, the first record read at a key it has not seen
    is admitted, so another login's context put back while port49d was stopped is taken as
  ```

  with:

  ```
    a start admits the record at a key the ledger record holds no later mark for, so another
    login's context put back while every port49d was stopped, at such a key, is taken as
  ```

  The next line, `  that key's, until its sealed ceiling, …`, stays as it is.

- [ ] **Step 6: Design §12, the store interface.** In §12's record table, after the row that
  begins `| revocation mark |`, add:

  ```markdown
  | superseded | `(nas, username)`, and one for every key | broker, when a refresh or a revocation deletes a key's unspent tokens, or a start purges them all | broker, at an idempotent replay | 20 minutes | no |
  | ledger record | `(nas, username)` | the broker holding the keyspace, raising only (decision 36) | every process, at its start | the latest sealed ceiling seen at the key, none for `never` | no — a sequence and a time |
  ```

  After the paragraph that begins `**etcd (plan 7d).** Each record is one key under`, add:

  ```markdown
  **Following the store (plan 7e).** Every process scans the context family at one revision, then
  watches it from there, and does the same for the revocation marks: that is how a process learns
  of another's writes and marks without asking it (decision 36). A watch never admits a record;
  it only raises what a read must clear, and a context read waits until the watch has passed
  the record's revision (etcd's progress request), for at most the call timeout.
  ```

- [ ] **Step 7: Check the edits.** Run:

  ```bash
  grep -c '^\*\*36\. ' docs/design/2026-08-23-policy-engine-spec.md
  grep -n 'Amended by decision 36' docs/design/2026-08-23-policy-engine-spec.md
  grep -n 'No record is judged before this process' docs/design/2026-08-23-policy-engine-spec.md
  grep -n 'The feed fence\*\*: while' docs/design/2026-08-23-policy-engine-spec.md
  grep -n 'reads nothing before' docs/design/2026-08-23-policy-engine-spec.md
  grep -n 'Following the store (plan 7e)' docs/design/2026-08-21-port49-design.md
  grep -n '| ledger record |' docs/design/2026-08-21-port49-design.md
  grep -c "before the start's reads seal the ledger" docs/design/2026-08-21-port49-design.md
  ```

  Expected: `1`, then one line each, then `0`.

- [ ] **Step 8: Commit.**

  ```bash
  git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
  git commit -m "docs: decision 36 (7e-1): the sealed write sequence, the feeds, the ledger record

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 2: `StartCluster` retries a taken port until a deadline

**Files:**
- Modify: `internal/store/etcd/etcdtest/etcdtest.go:240-260` (`StartCluster`)
- Test: `internal/store/etcd/etcdtest/etcdtest_test.go:15-34`

**Interfaces:**
- Consumes: `freePort` (the package's swappable picker), `startCluster`.
- Produces: `StartCluster(t testing.TB) *Cluster`, the same signature, retrying "address already
  in use" until `clusterRetryFor` (30s) has passed. `var clusterRetryFor = 30 * time.Second`.

The flake (7d unassigned): `TestStartClusterRetriesAPortTaken` failed once under load because its
one retry hit a taken port again. The pick-then-bind race is the machine's, not the test's: any
retry can lose it. The fix is to retry until a deadline, and a test that makes two attempts
lose pins it.

- [ ] **Step 1: The failing test.** Replace `TestStartClusterRetriesAPortTaken` with:

  ```go
  // A port another process takes between the pick and the bind is the
  // machine's race, not the test's, and any retry can lose it too (7d's
  // flake: its one retry hit a taken port again). StartCluster tries again
  // until clusterRetryFor has passed: here the first two attempts each meet
  // a taken port, and the third starts.
  func TestStartClusterRetriesAPortTaken(t *testing.T) {
  	taken, err := net.Listen("tcp", "127.0.0.1:0")
  	if err != nil {
  		t.Fatal(err)
  	}
  	defer taken.Close()
  	pick, picks := freePort, 0
  	freePort = func(t testing.TB) string {
  		picks++
  		if picks == 1 || picks == 7 { // the first pick of the first two attempts
  			return taken.Addr().String()
  		}
  		return pick(t)
  	}
  	defer func() { freePort = pick }()
  	c := StartCluster(t)
  	if picks < 18 || picks%6 != 0 || len(c.Endpoints) != 3 {
  		t.Fatalf("%d ports picked, %d endpoints: the cluster was not tried a third time", picks, len(c.Endpoints))
  	}
  }

  // Past clusterRetryFor, StartCluster stops and fails the test, naming the
  // address: a port that never frees is not waited on forever.
  func TestStartClusterGivesUpAtItsDeadline(t *testing.T) {
  	taken, err := net.Listen("tcp", "127.0.0.1:0")
  	if err != nil {
  		t.Fatal(err)
  	}
  	defer taken.Close()
  	pick, retry := freePort, clusterRetryFor
  	freePort = func(t testing.TB) string { return taken.Addr().String() }
  	clusterRetryFor = 200 * time.Millisecond
  	defer func() { freePort, clusterRetryFor = pick, retry }()
  	ft := &fatalT{TB: t}
  	func() {
  		defer func() { recover() }()
  		StartCluster(ft)
  	}()
  	if !strings.Contains(ft.msg, "address already in use") {
  		t.Fatalf("StartCluster did not give up naming the taken port: %q", ft.msg)
  	}
  }

  // fatalT records Fatal's message and stops the call, without failing the
  // test that wraps it.
  type fatalT struct {
  	testing.TB
  	msg string
  }

  func (f *fatalT) Fatal(args ...any) { f.msg = fmt.Sprint(args...); panic(f) }
  func (f *fatalT) Fatalf(format string, args ...any) {
  	f.msg = fmt.Sprintf(format, args...)
  	panic(f)
  }
  ```

  Add `"fmt"`, `"strings"` and `"time"` to the test file's imports if absent.

- [ ] **Step 2: Run it to see it fail.**

  Run: `go test ./internal/store/etcd/etcdtest/ -run 'TestStartCluster' -count=1 -v`
  Expected: FAIL to compile: `clusterRetryFor` is undefined, so neither test runs (pre-flight
  M5). To see the retry test fail on its own first, declare `var clusterRetryFor = 30 *
  time.Second` alone, run again, and expect `TestStartClusterRetriesAPortTaken` to report `12
  ports picked`, one retry, before Step 3 writes the loop.

- [ ] **Step 3: Retry until the deadline.** In `etcdtest.go`, replace `StartCluster`'s body and
  add the variable:

  ```go
  // clusterRetryFor is how long StartCluster tries new ports for, swapped in
  // a test.
  var clusterRetryFor = 30 * time.Second

  // StartCluster runs three members for t, stopped at its cleanup.
  //
  // Its members cannot listen on :0 as every other member here does: the
  // initial cluster names each peer's address before any binds, so freePort
  // picks them, and another process can take one in between. A member that
  // finds its address in use stops the members that started, and the cluster
  // is tried again on new ports, until clusterRetryFor has passed (pre-flight
  // M29; plan 7e Task 2: one retry lost the race too, under load).
  func StartCluster(t testing.TB) *Cluster {
  	t.Helper()
  	deadline := time.Now().Add(clusterRetryFor)
  	for {
  		c, err := startCluster(t)
  		if err == nil {
  			for i := range c.members {
  				t.Cleanup(func() { c.Stop(i) })
  			}
  			return c
  		}
  		if !strings.Contains(err.Error(), "address already in use") || time.Now().After(deadline) {
  			t.Fatal(err)
  		}
  		// A pause between attempts, so a loop that keeps losing does not
  		// make a temp dir and three members every few milliseconds
  		// (pre-flight M5).
  		time.Sleep(50 * time.Millisecond)
  	}
  }
  ```

- [ ] **Step 4: Run it to see it pass, and the package.**

  Run: `go test ./internal/store/etcd/etcdtest/ -count=1 -v -run 'TestStartCluster'` then
  `go test ./internal/store/etcd/... -count=1`
  Expected: PASS.

- [ ] **Step 5: Commit.**

  ```bash
  gofmt -w internal/store/etcd/etcdtest/etcdtest.go internal/store/etcd/etcdtest/etcdtest_test.go
  make build && make test && make vet
  git add internal/store/etcd/etcdtest/etcdtest.go internal/store/etcd/etcdtest/etcdtest_test.go
  git commit -m "test(etcdtest): StartCluster retries a taken port until a deadline

  One retry could lose the pick-then-bind race again under load (7d's
  flake). Retry for 30s, and give up naming the port.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 3: An encryption key id outside the seal-key charset is refused at load

**Files:**
- Modify: `internal/config/config.go:945-952` (the encryption key loop in `Load`)
- Test: `internal/config/config_test.go`

**Interfaces:**
- Consumes: `crypt.LineKeyID` (the charset it prints by).
- Produces: `var config.KeyIDShape = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)`, and a refusal
  naming the block (`encryption.current` or `encryption.previous`), never echoing the id.

Ruling 15. Today an id outside the charset loads, and every line about a record sealed under it
prints `?`.

- [ ] **Step 1: The failing test.** Add to `internal/config/config_test.go`. It uses the
  file's own fixture (pre-flight M1):
  - `sample`, whose `encryption.current` is `{id: v2, secret_env: PORT49_ENC_V2}` and whose
    first `%s` is the inventory path;
  - `inv`, `write(t, name, body)` and `setKeyEnv(t)`, which sets `PORT49_ENC_V2` and the
    shared secrets.

  ```go
  // sampleWithKeyID is sample with encryption.current's id replaced by the
  // YAML scalar id, and the previous block added when prev is not empty.
  func sampleWithKeyID(t *testing.T, id, prev string) string {
  	t.Helper()
  	body := fmt.Sprintf(sample, write(t, "inv.yaml", inv))
  	if !strings.Contains(body, "id: v2,") {
  		t.Fatal("sample no longer names id v2: the test would replace nothing")
  	}
  	body = strings.Replace(body, "id: v2,", "id: "+id+",", 1)
  	if prev != "" {
  		body = strings.Replace(body, "encryption:\n", "encryption:\n  previous: "+prev+"\n", 1)
  	}
  	return body
  }

  // An encryption key id is sealed into every record's header and named by
  // every line about one that will not open, which prints only the key-id
  // charset (crypt.LineKeyID). One outside it is refused at load, naming the
  // block and never echoing the id (plan 7e, Ruling 15), whether or not the
  // block names a secret_env (pre-flight M6).
  func TestAnEncryptionKeyIDOutsideTheCharsetIsRefused(t *testing.T) {
  	for _, id := range []string{"has space", "semi;colon", "émoji", strings.Repeat("a", 65), "new\nline"} {
  		t.Run(fmt.Sprintf("%q", id), func(t *testing.T) {
  			setKeyEnv(t)
  			_, err := Load(write(t, "port49d.yaml", sampleWithKeyID(t, fmt.Sprintf("%q", id), "")))
  			if err == nil || !strings.Contains(err.Error(), "encryption.current: id must be 1 to 64 of") {
  				t.Fatalf("an id %q loaded, or the refusal does not say why: %v", id, err)
  			}
  			if strings.Contains(err.Error(), id) {
  				t.Fatalf("the refusal echoes the id: %v", err)
  			}
  			// A previous block naming the id and no secret_env took the
  			// branch that echoed it with %q before the shape was checked.
  			_, err = Load(write(t, "port49d.yaml", sampleWithKeyID(t, "v2", fmt.Sprintf("{id: %q}", id))))
  			if err == nil || !strings.Contains(err.Error(), "encryption.previous: id must be 1 to 64 of") ||
  				strings.Contains(err.Error(), id) {
  				t.Fatalf("a previous id %q with no secret_env: %v", id, err)
  			}
  		})
  	}
  	for _, id := range []string{"v2", "2026-10.key_A", strings.Repeat("a", 64)} {
  		setKeyEnv(t)
  		if _, err := Load(write(t, "port49d.yaml", sampleWithKeyID(t, id, ""))); err != nil {
  			t.Fatalf("an id %q in the charset was refused: %v", id, err)
  		}
  	}
  }
  ```

- [ ] **Step 2: Run it to see it fail.**

  Run: `go test ./internal/config/ -run TestAnEncryptionKeyIDOutsideTheCharsetIsRefused -count=1`
  Expected: FAIL. Each bad id loads.

- [ ] **Step 3: Refuse it.** In `config.go`, add beside `envName`:

  ```go
  // KeyIDShape is an encryption key id: what crypt seals into every record's
  // header and what every line about a record that will not open names
  // (crypt.LineKeyID prints anything else as "?"). Plan 7e, Ruling 15.
  var KeyIDShape = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
  ```

  In `Load`'s loop over `encryption.current` and `encryption.previous`, as the loop body's
  first statement, before the `if k.ref.SecretEnv == ""` branch whose refusal echoes the id
  with `%q` (pre-flight M6), add:

  ```go
  		if k.ref.ID != "" && !KeyIDShape.MatchString(k.ref.ID) {
  			// Not printed: whatever the operator wrote, a line must not carry
  			// it. Checked first, so no later refusal in this loop echoes an
  			// id outside the charset.
  			return Config{}, fmt.Errorf("config: %s: id must be 1 to 64 of A-Z a-z 0-9 . _ -: it is written "+
  				"into every record the key seals, and every line about a record that will not open names it", k.what)
  		}
  ```

  The `if k.ref.ID == ""` refusal below stays: an empty id is required, not misshapen.

- [ ] **Step 4: Run it to see it pass.**

  Run: `go test ./internal/config/ -count=1`
  Expected: PASS.

- [ ] **Step 5: Commit.**

  ```bash
  gofmt -w internal/config/config.go internal/config/config_test.go
  make build && make test && make vet
  git add internal/config/config.go internal/config/config_test.go
  git commit -m "fix(config): refuse an encryption key id outside the seal-key charset

  Every sealed record's header carries it and every line about a record
  that will not open names it; one outside [A-Za-z0-9._-]{1,64} printed as
  '?'. Refused at load, never echoed (plan 7e Ruling 15; 7d Task 13 C2).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 4: A mint's records are written after it lets go of the policy

**Files:**
- Create: `internal/decision/buffer.go`, `internal/decision/buffer_test.go`
- Modify: `internal/token/minter.go` (`Request`, where `Mint` emits its permit record)
- Modify: `internal/broker/broker.go:231-364` (`tokens`), `:625-773` (`mintOne`), `:810-829`
  (`putBlob`), `:902-905` (`emit`)
- Test: `internal/broker/broker_test.go`

**Interfaces:**
- Consumes: `decision.Emitter`, `decision.Sink`, `decision.Record`, `decision.EventBlob`;
  `policy.Live.Hold`, `policy.Live.Swap`.
- Produces:
  - `type decision.Buffer struct` with `func NewBuffer() *Buffer`, `func (b *Buffer) Emit(r Record)`,
    `func (b *Buffer) Len() int` and `func (b *Buffer) Flush(to Emitter, landed func(r Record, err error))`.
    `Flush` writes every buffered record to `to` in order, through `Write` when `to` is a `Sink`,
    and calls `landed` with each record and the error its write returned (nil from a plain
    `Emitter`). It leaves the buffer empty.
  - `token.Request.Log decision.Emitter`: where `Mint` emits its permit record; nil is the minter's
    own log, as today.
  - `const blobsSeenMax = 4096` in `broker`.

Ruling 10, and Ruling 9's `blobsSeen`.
- **Today.** `tokens` holds the policy (`Live.Hold`, a read lock) from its first resolution to its
  last token write. Every record written in between (the minter's permit, `mintOne`'s denies,
  `putBlob`'s blob) is a write to stdout under that lock, so a stalled log sink stalls
  `Live.Swap` and every mint behind it.
- **Now.** Those records go into a per-request `Buffer`. `tokens` flushes it once it has
  released the hold, before it writes the response.
- **Blob ordering.** `putBlob` marks a hash emitted only when its buffered blob record lands.
  A concurrent request that finds a hash not yet marked buffers its own blob record. Within one
  sink, every mint record still follows a blob record for its hash.

- [ ] **Step 1: The failing tests, the buffer.** Create `internal/decision/buffer_test.go`:

  ```go
  package decision

  import (
  	"errors"
  	"testing"
  )

  type recSink struct {
  	got  []Record
  	fail map[string]bool // by Event: Write refuses these
  }

  func (s *recSink) Emit(r Record) { _ = s.Write(r) }
  func (s *recSink) Write(r Record) error {
  	if s.fail[r.Event] {
  		return errors.New("refused")
  	}
  	s.got = append(s.got, r)
  	return nil
  }

  // A buffer writes what it was given in order, tells landed of each with
  // its write's error, and is empty after.
  func TestABufferFlushesInOrderAndSaysWhatLanded(t *testing.T) {
  	b := NewBuffer()
  	b.Emit(Record{Event: EventBlob})
  	b.Emit(Record{Event: EventMint})
  	b.Emit(Record{Event: "refused"})
  	sink := &recSink{fail: map[string]bool{"refused": true}}
  	var landed []string
  	b.Flush(sink, func(r Record, err error) {
  		if err == nil {
  			landed = append(landed, r.Event)
  		}
  	})
  	if len(sink.got) != 2 || sink.got[0].Event != EventBlob || sink.got[1].Event != EventMint {
  		t.Fatalf("written %+v", sink.got)
  	}
  	if len(landed) != 2 || b.Len() != 0 {
  		t.Fatalf("landed %v, left %d", landed, b.Len())
  	}
  }

  // A plain Emitter cannot refuse, so every record is said to have landed.
  func TestABufferFlushedToAnEmitterSaysEveryRecordLanded(t *testing.T) {
  	b := NewBuffer()
  	b.Emit(Record{Event: EventBlob})
  	n := 0
  	b.Flush(emitOnly{}, func(_ Record, err error) {
  		if err == nil {
  			n++
  		}
  	})
  	if n != 1 {
  		t.Fatalf("%d landed", n)
  	}
  }

  type emitOnly struct{}

  func (emitOnly) Emit(Record) {}
  ```

- [ ] **Step 2: The failing tests, the broker.** Add to `internal/broker/broker_test.go`. They use
  `fixture_test.go`'s fixture (pre-flight M1):
  - `newFixture(t, candidateCap)`, whose `f.b` is a `*Broker` on the memory store `f.st`;
  - `f.post(ctx, f.state(f.alice), body, key)`, which drives `tokens` through `f.b.Handler()`;
  - the minter's tag key, `token.TagKey([]byte("k"))`, as the fixture builds it.

  ```go
  // stallSink is a log whose Write blocks until release is closed, and says
  // when the first Write has begun.
  type stallSink struct {
  	began   chan struct{}
  	once    sync.Once
  	release chan struct{}
  	mu      sync.Mutex
  	got     []decision.Record
  }

  func newStallSink() *stallSink {
  	return &stallSink{began: make(chan struct{}), release: make(chan struct{})}
  }
  func (s *stallSink) Emit(r decision.Record) { _ = s.Write(r) }
  func (s *stallSink) Write(r decision.Record) error {
  	s.once.Do(func() { close(s.began) })
  	<-s.release
  	s.mu.Lock()
  	s.got = append(s.got, r)
  	s.mu.Unlock()
  	return nil
  }

  // A log sink that stalls during a mint never holds a reload: the mint
  // writes its records only once it has let go of the policy, so Swap
  // returns while the sink is still stalled, and once it drains the mint's
  // records land, in order (plan 7e Ruling 10; 4b Task 4).
  func TestAStalledLogNeverHoldsAReload(t *testing.T) {
  	sink := newStallSink()
  	f := newFixture(t, 8)
  	b := f.b
  	b.Log = sink
  	b.Minter = token.NewMinter(f.st, sink, rand.Reader, token.TagKey([]byte("k")), b.Now, 8)
  	done := make(chan *httptest.ResponseRecorder, 1)
  	go func() { done <- f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "") }()
  	select {
  	case <-sink.began:
  	case <-time.After(5 * time.Second):
  		t.Fatal("the mint never wrote a record")
  	}
  	swapped := make(chan struct{})
  	go func() { b.Policy.Swap(b.Policy.Load()); close(swapped) }()
  	select {
  	case <-swapped:
  	case <-time.After(time.Second):
  		t.Fatal("a stalled log held the reload: the mint still held the policy while it wrote")
  	}
  	close(sink.release)
  	if rr := <-done; rr.Code != http.StatusOK {
  		t.Fatalf("the mint: %d %s", rr.Code, rr.Body)
  	}
  	sink.mu.Lock()
  	defer sink.mu.Unlock()
  	if len(sink.got) < 2 || sink.got[0].Event != decision.EventBlob || sink.got[1].Event != decision.EventMint {
  		t.Fatalf("records %+v", sink.got)
  	}
  }

  // Two requests minting the same blob at once: each request's run of lines
  // carries a blob record before its mint record, unless the hash was marked
  // emitted, which happens only once a blob record has landed.
  //
  // A regression guard, not a failing-first test (pre-flight M4): today
  // putBlob writes the blob record under b.mu before any mint record, so it
  // passes before this task. It pins that buffering keeps the order.
  func TestEveryMintRecordFollowsItsBlobRecord(t *testing.T) {
  	var buf bytes.Buffer
  	f := newFixture(t, 8)
  	b := f.b
  	b.Log = decision.NewJSONLines(&lockedWriter{w: &buf})
  	b.Minter = token.NewMinter(f.st, b.Log, rand.Reader, token.TagKey([]byte("k")), b.Now, 8)
  	var wg sync.WaitGroup
  	for i := 0; i < 8; i++ {
  		wg.Add(1)
  		go func() {
  			defer wg.Done()
  			f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "")
  		}()
  	}
  	wg.Wait()
  	seen := map[string]bool{}
  	mints := 0
  	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
  		var r map[string]any
  		if err := json.Unmarshal([]byte(line), &r); err != nil {
  			t.Fatal(err)
  		}
  		switch r["event"] {
  		case decision.EventBlob:
  			seen[r["blob"].(map[string]any)["hash"].(string)] = true
  		case decision.EventMint:
  			mints++
  			h, _ := r["mint"].(map[string]any)["blob"].(string) // decision.Mint.BlobHash
  			if h == "" || !seen[h] {
  				t.Fatalf("a mint record names blob %q before any blob record for it:\n%s", h, buf.String())
  			}
  		}
  	}
  	if mints != 8 {
  		t.Fatalf("%d mint records, want 8:\n%s", mints, buf.String())
  	}
  }

  // blobsSeen forgets every hash once it holds blobsSeenMax, so a policy
  // rewritten on a schedule cannot grow it without bound (4b m10): the next
  // mint of a forgotten hash writes its blob record again, which replay reads
  // as a duplicate.
  func TestBlobsSeenIsBounded(t *testing.T) {
  	b := newFixture(t, 8).b
  	for i := 0; i < blobsSeenMax; i++ {
  		b.markBlob(fmt.Sprintf("h%d", i))
  	}
  	if b.blobSeen("h0") != true {
  		t.Fatal("a hash marked was not seen")
  	}
  	b.markBlob("one-more")
  	if b.blobSeen("h0") || !b.blobSeen("one-more") || len(b.blobsSeen) != 1 {
  		t.Fatalf("at the bound blobsSeen kept %d hashes", len(b.blobsSeen))
  	}
  }
  ```

  `lockedWriter` (an `io.Writer` with a mutex) is a test helper: add it to the file if no
  `_test.go` file in the package has one. A mint record names its blob at `mint.blob`
  (`decision.Mint.BlobHash`, `json:"blob"`), so no helper is needed to read it.

- [ ] **Step 3: Run them to see them fail.**

  Run: `go test ./internal/decision/ ./internal/broker/ -run 'Buffer|Stalled|FollowsItsBlob|BlobsSeenIsBounded' -count=1`
  Expected: FAIL. `NewBuffer`, `markBlob`, `blobSeen` and `blobsSeenMax` are undefined, and once
  they compile, the reload is held. `TestEveryMintRecordFollowsItsBlobRecord` passes once it
  compiles: it is the regression guard for Step 6.

- [ ] **Step 4: The buffer.** Create `internal/decision/buffer.go`:

  ```go
  package decision

  import "sync"

  // Buffer is an Emitter that keeps what it is given, for a caller that must
  // not write while it holds a lock others wait on (plan 7e, Ruling 10): a
  // mint holds the policy from its first resolution to its last token write,
  // and a log sink that stalls there would stall every reload. The caller
  // flushes it once it has let go. It is safe for concurrent use.
  type Buffer struct {
  	mu   sync.Mutex
  	recs []Record
  }

  // NewBuffer is an empty buffer.
  func NewBuffer() *Buffer { return &Buffer{} }

  // Emit keeps r.
  func (b *Buffer) Emit(r Record) {
  	b.mu.Lock()
  	b.recs = append(b.recs, r)
  	b.mu.Unlock()
  }

  // Len is how many records it holds.
  func (b *Buffer) Len() int {
  	b.mu.Lock()
  	defer b.mu.Unlock()
  	return len(b.recs)
  }

  // Flush writes every record it holds to to, in the order given, and tells
  // landed of each with its write's error: Write's when to is a Sink, nil
  // otherwise, since a plain Emitter cannot refuse. It leaves the buffer
  // empty. landed may be nil.
  func (b *Buffer) Flush(to Emitter, landed func(r Record, err error)) {
  	b.mu.Lock()
  	recs := b.recs
  	b.recs = nil
  	b.mu.Unlock()
  	sink, isSink := to.(Sink)
  	for _, r := range recs {
  		var err error
  		if isSink {
  			err = sink.Write(r)
  		} else {
  			to.Emit(r)
  		}
  		if landed != nil {
  			landed(r, err)
  		}
  	}
  }
  ```

- [ ] **Step 5: The minter emits where it is told.** In `internal/token/minter.go`, add to
  `Request`:

  ```go
  	// Log is where Mint writes its permit record; nil is the minter's own
  	// log. The broker passes a per-request decision.Buffer, flushed once
  	// the request lets go of the policy (plan 7e, Ruling 10).
  	Log decision.Emitter
  ```

  Where `Mint` emits the permit (`m.log.Emit(rec)`, or however the minter names its log), emit
  to `r.Log` when it is set:

  ```go
  	log := m.log
  	if r.Log != nil {
  		log = r.Log
  	}
  	log.Emit(rec)
  ```

  Add a minter test, `TestAMintWritesItsRecordWhereTheRequestSays`: a `Request.Log` buffer gets
  the permit record, and the minter's own log gets none.

- [ ] **Step 6: The broker buffers under the hold.** In `broker.go`:
  - Add `const blobsSeenMax = 4096`.
  - Add `markBlob(hash string)`: under `b.mu`, clear `b.blobsSeen` when it holds
    `blobsSeenMax`, then set the hash.
  - Add `blobSeen(hash string) bool`, under `b.mu`.
  - Add `emitTo(to decision.Emitter, r decision.Record)`: `to.Emit(r)`, then
    `b.Metrics.Decisions.WithLabelValues(...).Inc()` as `emit` does. Make `emit(r)` call
    `b.emitTo(b.Log, r)`.
  - In `tokens`:
    - create `buf := decision.NewBuffer()` before `b.Policy.Hold()`;
    - make `release` flush after it lets go: `hold(); buf.Flush(b.Log, b.blobLanded)`;
    - pass `buf` to `mintOne`, which passes it to every `deny` (as `b.emitTo(buf, …)`), to
      `putBlob`, and to the minter as `token.Request{…, Log: buf}`.
  - `revokedSince` and `writeInProgress` run after `release()`, so they keep `b.emit`.
  - Replace `putBlob` with:

  ```go
  // putBlob writes an encoded blob under its hash, and buffers its blob
  // record into out the first time this process writes it (spec §5.1.1;
  // §13, decision 19). out is the request's buffer, written to the log once
  // the request lets go of the policy (plan 7e, Ruling 10); a hash is marked
  // emitted only when its record lands (blobLanded), so a request that finds
  // a hash unmarked buffers a blob record of its own, and within one sink
  // every mint record follows one for its hash. Its store TTL is ttl
  // (blobTTL); PutBlob keeps the later expiry.
  func (b *Broker) putBlob(ctx context.Context, out decision.Emitter, hash string, body []byte, ttl time.Duration) error {
  	if err := b.Store.PutBlob(ctx, hash, body, ttl); err != nil {
  		return err
  	}
  	if !b.blobSeen(hash) {
  		out.Emit(decision.Record{TS: b.Now(), Event: decision.EventBlob, Blob: b.blobEvent(hash, body)})
  	}
  	return nil
  }

  // blobLanded is Buffer.Flush's landed for the request's buffer: a blob
  // record the sink took marks its hash emitted. One the sink refused is not
  // marked, so the next mint that writes the hash emits it again (roadmap,
  // plan 4).
  func (b *Broker) blobLanded(r decision.Record, err error) {
  	if err == nil && r.Event == decision.EventBlob && r.Blob != nil {
  		b.markBlob(r.Blob.Hash)
  	}
  }
  ```

  Update `blobsSeen`'s field comment: "which blob hashes this process has written into its
  decision log, bounded at blobsSeenMax and forgotten whole there: a forgotten hash is emitted
  again, which costs one duplicate record (plan 7e, Ruling 9). Per process, by design: each
  process's log stays replayable alone."

  Any other caller of `putBlob` (the refresh, `refreshContext`, writes blobs outside a mint and
  holds no policy): pass `b.Log`, and mark the hash when its `Emit` returns, through a
  one-record buffer flushed at once:

  ```go
  	one := decision.NewBuffer()
  	err := b.putBlob(ctx, one, hash, body, ttl)
  	one.Flush(b.Log, b.blobLanded)
  ```

- [ ] **Step 7: Run the tests to see them pass, then the packages.**

  Run: `go test ./internal/decision/ ./internal/token/ ./internal/broker/ -count=1`
  Expected: PASS.

- [ ] **Step 8: Commit.**

  ```bash
  gofmt -w internal/decision/buffer.go internal/decision/buffer_test.go internal/token/minter.go \
    internal/token/minter_test.go internal/broker/broker.go internal/broker/broker_test.go internal/broker/refresh.go
  make build && make test && make vet
  git add internal/decision/buffer.go internal/decision/buffer_test.go internal/token/minter.go \
    internal/token/minter_test.go internal/broker/broker.go internal/broker/broker_test.go internal/broker/refresh.go
  git commit -m "fix(broker): write a mint's records after it lets go of the policy

  A stalled decision-log sink held the policy's read lock through every
  record a mint wrote, and so held every reload and every mint behind it
  (4b Task 4). Records go to a per-request buffer flushed after release; a
  blob is marked emitted only when its record lands, and blobsSeen is
  bounded at 4096 (plan 7e Rulings 9, 10).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 5: When a key's tokens were superseded is kept in the store

**Files:**
- Modify: `internal/store/store.go` (the `Store` interface; `SupersededFor`)
- Modify: `internal/store/memory/memory.go`, `internal/store/memory/memory_test.go`
- Create: `internal/store/etcd/superseded.go`
- Modify: `internal/store/etcd/keys.go` (`famSuperseded`), `internal/store/etcd/roles.go`
  (`daemonNever`)
- Modify: `internal/store/crypt/crypt.go` (pass-through), `internal/store/guard/guard.go` (routing,
  methods)
- Create: `internal/store/storetest/superseded.go`; Modify: `internal/store/storetest/storetest.go`
  (`Run`)
- Modify: `internal/policy/load.go` (export `MaxTokenTTL`)
- Modify: `internal/broker/broker.go`, `revoke.go`, `revokeown.go`, `refresh.go`;
  `cmd/port49d/store.go` (`SupersededAll`)
- Test: `internal/broker/broker_test.go`, `internal/store/etcd/etcd_test.go` (the property through
  `Run`)

**Interfaces:**
- Consumes: `store.TokenKey`, `store.ErrUnavailable`.
- Produces:
  - On `store.Store`:
    - `SupersedeTokens(ctx context.Context, k TokenKey, at time.Time) error` keeps the later of
      `at` and what stands, for `SupersededFor`;
    - `SupersedeAll(ctx context.Context, at time.Time) error`: every key, the later;
    - `SupersededAt(ctx context.Context, k TokenKey) (time.Time, error)`: the later of `k`'s
      own and the all-keys instant, zero when neither stands or both have expired, never
      `ErrNotFound`.
  - `const store.SupersededFor = 20 * time.Minute`.
  - `const policy.MaxTokenTTL = 900 * time.Second` (was `maxTokenTTL`).
  - etcd families: `famSuperseded = "sp/"` (`sp/<nas>/<user>`), and the all-keys record at
    `meta/superseded_all`.
  - Broker:
    - `(*Broker).supersede(ctx context.Context, k store.TokenKey, at time.Time)` (was without
      `ctx`);
    - `(*Broker).supersededAt(ctx context.Context, k store.TokenKey) (time.Time, error)`;
    - the exported field `SupersededAll` is removed.
  - guard: all three in the token pool.

Ruling 9. An idempotent replay landing on another broker replica must mint afresh after a
refresh, a revocation, or a start's purge superseded its key, so the instant lives in the store.
- **Lifetime.** It is kept 20 minutes, past the longest `token_ttl` (15m), so past the life of
  any record whose replay it governs. That is 4b m10's bound.
- **The local copy.** Each replica also keeps its own entries in memory for the same time, so a
  store write that failed still covers that replica.
- **When the store is read.** A mint reads the store only when it holds a reservation (an
  `Idempotency-Key`): without one there is nothing to replay.

- [ ] **Step 1: The failing property.** Create `internal/store/storetest/superseded.go`:

  ```go
  package storetest

  import (
  	"context"
  	"sync"
  	"testing"
  	"time"

  	"github.com/rhwendt/port49/internal/store"
  )

  // SupersededIsTheLaterAndExpires: a key's superseded instant is the later
  // of every one written, the all-keys instant reaches every key, and both
  // are gone SupersededFor after they were written (plan 7e, Ruling 9). An
  // unknown key is zero, never ErrNotFound.
  func SupersededIsTheLaterAndExpires(t *testing.T, b Backend) {
  	ctx := context.Background()
  	var mu sync.Mutex
  	now := t0
  	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
  	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
  	s := b.New(t, clock)
  	k := store.TokenKey{NAS: "leaf-01", Username: "alice"}
  	other := store.TokenKey{NAS: "leaf-02", Username: "alice"}
  	if at, err := s.SupersededAt(ctx, k); err != nil || !at.IsZero() {
  		t.Fatalf("an unknown key: %v %v", at, err)
  	}
  	if err := s.SupersedeTokens(ctx, k, t0.Add(time.Minute)); err != nil {
  		t.Fatal(err)
  	}
  	if err := s.SupersedeTokens(ctx, k, t0); err != nil { // earlier: the later stands
  		t.Fatal(err)
  	}
  	if at, _ := s.SupersededAt(ctx, k); !at.Equal(t0.Add(time.Minute)) {
  		t.Fatalf("the later did not stand: %v", at)
  	}
  	if at, _ := s.SupersededAt(ctx, other); !at.IsZero() {
  		t.Fatalf("another key was superseded: %v", at)
  	}
  	if err := s.SupersedeAll(ctx, t0.Add(2*time.Minute)); err != nil {
  		t.Fatal(err)
  	}
  	for _, key := range []store.TokenKey{k, other} {
  		if at, _ := s.SupersededAt(ctx, key); !at.Equal(t0.Add(2 * time.Minute)) {
  			t.Fatalf("the all-keys instant did not reach %v: %v", key, at)
  		}
  	}
  	advance(store.SupersededFor + 3*time.Minute)
  	if at, err := s.SupersededAt(ctx, k); err != nil || !at.IsZero() {
  		t.Fatalf("past SupersededFor: %v %v", at, err)
  	}
  }
  ```

  In `storetest.go`'s `Run`, add `{"SupersededIsTheLaterAndExpires", SupersededIsTheLaterAndExpires}`
  to the last table.

- [ ] **Step 2: Run it to see it fail.**

  Run: `go test ./internal/store/... -run SupersededIsTheLaterAndExpires -count=1`
  Expected: FAIL to compile: `SupersededAt` is not a method of `store.Store`.

- [ ] **Step 3: The interface.** In `store.go`, after `ListRevocations` in `Store`, add:

  ```go
  	// SupersedeTokens records that k's unspent tokens were deleted at at, by
  	// a refresh or a revocation, keeping the later of at and what stands,
  	// for SupersededFor. An idempotent replay of a mint from before it, on
  	// any broker process, is minted afresh rather than answered with a token
  	// that no longer exists (plan 7e, Ruling 9).
  	SupersedeTokens(ctx context.Context, k TokenKey, at time.Time) error
  	// SupersedeAll is SupersedeTokens for every key at once: a start that
  	// purged every unspent token.
  	SupersedeAll(ctx context.Context, at time.Time) error
  	// SupersededAt is the later of k's own instant and the all-keys one;
  	// zero when neither stands or both are past SupersededFor. Never
  	// ErrNotFound.
  	SupersededAt(ctx context.Context, k TokenKey) (time.Time, error)
  ```

  and, near `CertKey`:

  ```go
  // SupersededFor is how long a superseded instant is kept: past the
  // longest token_ttl (policy.MaxTokenTTL, 15m) and so past the life of any
  // idempotency record whose replay it governs (plan 7e, Ruling 9; 4b m10).
  const SupersededFor = 20 * time.Minute
  ```

  In `internal/policy/load.go`, rename `maxTokenTTL` to `MaxTokenTTL` (exported, the same
  value, every use updated). Add to `internal/broker/broker_test.go`:

  ```go
  // SupersededFor outlives every idempotency record a replay could read.
  func TestSupersededOutlivesTheLongestToken(t *testing.T) {
  	if store.SupersededFor <= policy.MaxTokenTTL {
  		t.Fatalf("SupersededFor %v is not past the longest token_ttl %v", store.SupersededFor, policy.MaxTokenTTL)
  	}
  }
  ```

- [ ] **Step 4: Memory.** In `memory.go`, add to `Store`:
  - `superseded map[store.TokenKey]supersededEntry`;
  - `supersededAll supersededEntry`;
  - `type supersededEntry struct{ at, until time.Time }`.

  Then:

  ```go
  // SupersedeTokens keeps the later instant at k, for SupersededFor from now.
  func (s *Store) SupersedeTokens(_ context.Context, k store.TokenKey, at time.Time) error {
  	s.mu.Lock()
  	defer s.mu.Unlock()
  	if s.superseded == nil {
  		s.superseded = map[store.TokenKey]supersededEntry{}
  	}
  	s.superseded[k] = s.superseded[k].with(at, s.now())
  	return nil
  }

  // SupersedeAll keeps the later all-keys instant, for SupersededFor.
  func (s *Store) SupersedeAll(_ context.Context, at time.Time) error {
  	s.mu.Lock()
  	defer s.mu.Unlock()
  	s.supersededAll = s.supersededAll.with(at, s.now())
  	return nil
  }

  // with is e after at was written at now: the later of at and e's own
  // instant while e is live, kept for SupersededFor from now.
  func (e supersededEntry) with(at, now time.Time) supersededEntry {
  	if now.Before(e.until) && e.at.After(at) {
  		at = e.at
  	}
  	return supersededEntry{at: at, until: now.Add(store.SupersededFor)}
  }

  // SupersededAt is the later live instant of k's and every key's.
  func (s *Store) SupersededAt(_ context.Context, k store.TokenKey) (time.Time, error) {
  	s.mu.Lock()
  	defer s.mu.Unlock()
  	now := s.now()
  	var at time.Time
  	for _, e := range []supersededEntry{s.superseded[k], s.supersededAll} {
  		if now.Before(e.until) && e.at.After(at) {
  			at = e.at
  		}
  	}
  	return at, nil
  }
  ```

  The memory store's sweep drops entries past `until`: add that to the sweep the store already
  runs (`sweepLocked`, or whatever it is named), and a line in `memory_test.go` that a swept
  entry is gone from the map.

- [ ] **Step 5: etcd.** In `keys.go` add `famSuperseded = "sp/" // sp/<nas>/<user>: when its
  tokens were last superseded` and:

  ```go
  func (k keys) superseded(t store.TokenKey) string { return k.root + famSuperseded + esc(t.NAS, t.Username) }
  ```

  In `roles.go`, add `famSuperseded` to `daemonNever`. Create `internal/store/etcd/superseded.go`:

  ```go
  package etcd

  import (
  	"context"
  	"encoding/json"
  	"fmt"
  	"time"

  	clientv3 "go.etcd.io/etcd/client/v3"

  	"github.com/rhwendt/port49/internal/store"
  )

  // supersededRec is sp/<nas>/<user>, and meta/superseded_all for every key:
  // when tokens were last superseded there, and until when that is kept
  // (plan 7e, Ruling 9). The broker's role alone writes either, and alone
  // reads sp/; meta/superseded_all sits under meta/, which the daemon's
  // role reads, and tells it nothing it could use.
  type supersededRec struct {
  	At        time.Time `json:"at"`
  	ExpiresAt time.Time `json:"expires_at"`
  }

  func (r supersededRec) live(now time.Time) bool { return now.Before(r.ExpiresAt) }

  // SupersedeTokens keeps the later instant at k, by a compare on the
  // record's revision, on a lease past SupersededFor.
  func (s *Store) SupersedeTokens(ctx context.Context, k store.TokenKey, at time.Time) error {
  	return s.supersede(ctx, s.k.superseded(k), at)
  }

  // SupersedeAll is SupersedeTokens for every key.
  func (s *Store) SupersedeAll(ctx context.Context, at time.Time) error {
  	return s.supersede(ctx, s.k.meta("superseded_all"), at)
  }

  func (s *Store) supersede(ctx context.Context, key string, at time.Time) error {
  	now := s.now()
  	live := func(r supersededRec) bool { return r.live(now) }
  	return cas(ctx, s.tok, s.tokLeases, key, live, func(r *supersededRec, found bool) (bool, time.Time, bool, error) {
  		next := supersededRec{At: at, ExpiresAt: now.Add(store.SupersededFor)}
  		if found && r.At.After(at) {
  			next.At = r.At
  		}
  		*r = next
  		return true, next.ExpiresAt, false, nil
  	})
  }

  // SupersededAt reads k's record and the all-keys record in one
  // transaction, and is the later live instant of the two.
  func (s *Store) SupersededAt(ctx context.Context, k store.TokenKey) (time.Time, error) {
  	resp, err := s.tok.Txn(ctx).Then(clientv3.OpGet(s.k.superseded(k)),
  		clientv3.OpGet(s.k.meta("superseded_all"))).Commit()
  	if err != nil {
  		return time.Time{}, unavailable(err)
  	}
  	now := s.now()
  	var at time.Time
  	for _, r := range resp.Responses {
  		kvs := r.GetResponseRange().Kvs
  		if len(kvs) == 0 {
  			continue
  		}
  		var rec supersededRec
  		if json.Unmarshal(kvs[0].Value, &rec) != nil {
  			return time.Time{}, notDecoded(fmt.Sprintf("superseded record %q", kvs[0].Key))
  		}
  		if rec.live(now) && rec.At.After(at) {
  			at = rec.At
  		}
  	}
  	return at, nil
  }
  ```

  `cas` is commit.go's generic compare-and-set: it reads, lets `f` change the record, and writes
  on the revision read, retrying a lost race, with the lease `f`'s expiry names. An undecodable
  record is an error naming its key, never skipped, as decision 35 requires.

- [ ] **Step 6: crypt and guard.** In `crypt.go`, pass all three through, unsealed: they carry no
  credential. In `guard.go`:
  - add `"SupersedeTokens": Token, "SupersedeAll": Token, "SupersededAt": Token` to `pools`;
  - add the three methods through `g.do(ctx, Token, …)`;
  - the routing test, `TestEveryMethodIsRoutedToItsPool`, now finds them.

- [ ] **Step 7: The broker.** In `broker.go`:
  - drop the field `SupersededAll`;
  - keep `superseded` as the local copy, its entries pruned past `store.SupersededFor` in
    `supersede`;
  - replace `supersede` and the read in `mintOne`:

  ```go
  // supersede records that k's unspent tokens were deleted at at: in this
  // process, so its own replays mint afresh whatever the store says, and in
  // the store, so every broker process's do (plan 7e, Ruling 9). A store
  // write that fails is said, and this process's copy still covers its own
  // replays; another process may then answer one with a deleted token's
  // record, which redeems token_not_found.
  func (b *Broker) supersede(ctx context.Context, k store.TokenKey, at time.Time) {
  	b.mu.Lock()
  	if b.superseded == nil {
  		b.superseded = map[store.TokenKey]time.Time{}
  	}
  	if at.After(b.superseded[k]) {
  		b.superseded[k] = at
  	}
  	for key, t := range b.superseded {
  		if b.Now().Sub(t) > store.SupersededFor {
  			delete(b.superseded, key)
  		}
  	}
  	b.mu.Unlock()
  	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), holdTimeout)
  	defer cancel()
  	if err := b.Store.SupersedeTokens(sctx, k, at); err != nil {
  		b.logf("broker: recording that the tokens under %q on %q were superseded: %v; this process still "+
  			"mints a replay of them afresh", k.Username, k.NAS, err)
  	}
  }

  // supersededAt is the later of this process's instant for k and the
  // store's (every process's, and a start's purge).
  func (b *Broker) supersededAt(ctx context.Context, k store.TokenKey) (time.Time, error) {
  	b.mu.Lock()
  	local := b.superseded[k]
  	b.mu.Unlock()
  	at, err := b.Store.SupersededAt(ctx, k)
  	if err != nil {
  		return time.Time{}, err
  	}
  	if local.After(at) {
  		at = local
  	}
  	return at, nil
  }
  ```

  In `mintOne`, replace the `b.mu.Lock(); supersededAt := …; SupersededAll` lines with:

  ```go
  	var supersededAt time.Time
  	if hold != nil { // only a request under an Idempotency-Key can be replayed
  		var err error
  		if supersededAt, err = b.supersededAt(ctx, store.TokenKey{NAS: name, Username: res.Username}); err != nil {
  			return deny(decision.StoreUnavailable, dev.Platform), nil
  		}
  	}
  ```

  Every caller of `b.supersede(k, at)` passes its own `ctx`:
  - `broker.go:454` and `:597`, `revoke.go:258`, `revokeown.go:86, :178`, `refresh.go:419`;
  - the `revokedSince` path, whose `ctx` is already detached.

  In `cmd/port49d/store.go`'s `startOnPersistentStore`, replace `brk.SupersededAll = brk.Now()`
  with:

  ```go
  	if err := retry("recording the purge's instant", func() error { return st.SupersedeAll(ctx, brk.Now()) }); err != nil {
  		return refreshOwed{}, err
  	}
  ```

  placed before the purge, so a replay after any token is gone mints afresh.

- [ ] **Step 8: The broker's tests.** Add to `broker_test.go`:

  ```go
  // second is another *Broker on f's store, policy, log and sessions, with a
  // minter of its own: a second broker process on one keyspace. Built field
  // by field, since a Broker holds a mutex and is never copied.
  func second(f *fixture) *Broker {
  	return &Broker{Policy: f.b.Policy, Store: f.st, Log: f.b.Log, Now: f.b.Now,
  		Minter:  token.NewMinter(f.st, f.b.Log, rand.Reader, token.TagKey([]byte("k")), f.b.Now, 8),
  		Metrics: metrics.New(prometheus.NewRegistry()), MaxSessionAge: f.b.MaxSessionAge,
  		BatchMax: f.b.BatchMax, Sessions: f.b.Sessions, ContextIdleTTL: f.b.ContextIdleTTL}
  }

  // postTo is f.post through b's handler.
  func postTo(f *fixture, b *Broker, body, key string) *httptest.ResponseRecorder {
  	r := httptest.NewRequest("POST", "/v1/tokens", strings.NewReader(body))
  	r.TLS = f.state(f.alice)
  	if key != "" {
  		r.Header.Set("Idempotency-Key", key)
  	}
  	w := httptest.NewRecorder()
  	b.Handler().ServeHTTP(w, r)
  	return w
  }

  // A key superseded on one broker process makes an idempotent replay on
  // another mint afresh: the instant is in the store (plan 7e, Ruling 9).
  func TestASupersededKeyReplaysAfreshOnAnotherBroker(t *testing.T) {
  	f := newFixture(t, 8)
  	other := second(f)
  	body := `{"devices":["leaf1"]}`
  	first := postTo(f, f.b, body, "k1").Body.String()
  	f.b.supersede(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"}, f.b.Now())
  	f.advance(time.Second)
  	again := postTo(f, other, body, "k1").Body.String()
  	if again == first {
  		t.Fatal("another broker answered a superseded key's replay with the deleted token")
  	}
  }

  // A store that fails the read of the superseded instant refuses the item
  // store_unavailable rather than risk handing back a deleted token.
  func TestAnUnreadableSupersededInstantRefusesTheItem(t *testing.T) {
  	f := newFixture(t, 8)
  	f.b.Store = &failSuperseded{Store: f.st}
  	rr := f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "k2")
  	if !strings.Contains(rr.Body.String(), `"store_unavailable"`) {
  		t.Fatalf("%d %s", rr.Code, rr.Body)
  	}
  }

  type failSuperseded struct{ store.Store }

  func (f *failSuperseded) SupersededAt(context.Context, store.TokenKey) (time.Time, error) {
  	return time.Time{}, store.ErrUnavailable
  }
  ```

  Without Step 7, the first test fails: the second broker's in-memory `superseded` is empty, so
  it answers the replay from the idempotency record. If the fixture's policy gives alice no
  token on `leaf1` at `f.now`, use the device the file's existing idempotency tests mint on, and
  say so in the report.

- [ ] **Step 9: Run everything.**

  Run: `go test ./internal/store/... ./internal/broker/ ./internal/policy/ ./cmd/port49d/ -count=1`
  Expected: PASS. `SupersededIsTheLaterAndExpires` passes on memory, crypt, etcd and
  crypt-over-etcd.

- [ ] **Step 10: Commit.**

  ```bash
  gofmt -w internal/store internal/broker internal/policy/load.go cmd/port49d/store.go
  make build && make test && make vet
  git add internal/store/store.go internal/store/memory/memory.go internal/store/memory/memory_test.go \
    internal/store/etcd/superseded.go internal/store/etcd/keys.go internal/store/etcd/roles.go \
    internal/store/crypt/crypt.go internal/store/guard/guard.go internal/store/guard/guard_test.go \
    internal/store/storetest/superseded.go internal/store/storetest/storetest.go internal/policy/load.go \
    internal/broker/broker.go internal/broker/broker_test.go internal/broker/revoke.go internal/broker/revokeown.go \
    internal/broker/refresh.go cmd/port49d/store.go
  git commit -m "feat(store): keep when a key's tokens were superseded in the store

  An idempotent replay on another broker process must mint afresh after a
  refresh, a revocation or a start's purge (design §17). sp/ and
  meta/superseded_all, the broker's role alone, kept 20 minutes, past the
  longest token_ttl: 4b m10's bound (plan 7e Ruling 9).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 6: A store says the highest revision it has seen, and answers a ping

**Files:**
- Modify: `internal/store/store.go:895-902` (`RevStore`)
- Modify: `internal/store/memory/memory.go`, `internal/store/memory/memory_test.go`
- Modify: `internal/store/etcd/etcd.go` (`Store`, `Seen`, `saw`), `internal/store/etcd/contexts.go`
  (every context-pool response observed)
- Modify: `internal/store/guard/guard.go` (`Seen` passed through, `Ping` routed), `guard_test.go`
- Test: `internal/store/etcd/etcd_test.go`

**Interfaces:**
- Consumes: `clientv3.ResponseHeader.Revision`.
- Produces:
  - On `store.RevStore`:
    - `Seen() uint64`: the highest store revision this client has been told of, by any read,
      write or watch. It makes no call and never goes back.
    - `Ping(ctx context.Context) error`: one linearizable read, nil when the store answers.
  - `(*etcd.Store).saw(rev int64)`: an atomic max, called with every context-pool response's
    header revision and, from Task 8, every watch event's.
  - `(*memory.Store).Seen()` is its revision counter, and `Ping` is nil.
  - guard: `"Ping": Context` in `pools`. `Seen` reaches the inner store with no slot and no
    deadline.

Task 7's sequence reads `Seen()`, and Ruling 11's probe calls `Ping`. A create seals above
everything the reader of the empty key was told, because the etcd response that found the key
empty carries the store's current revision.

- [ ] **Step 1: The failing tests.** Add to `internal/store/etcd/etcd_test.go`:

  ```go
  // Seen is at least the store's revision when a read answered, the read of
  // a key that is not there included: a create sealed after it is above
  // every record ever at the key (plan 7e, Ruling 3).
  func TestSeenIsTheRevisionAReadOfAnAbsentKeyAnswered(t *testing.T) {
  	ctx := context.Background()
  	s := onShared(t, time.Now) // etcd_test.go's helper: the shared member, a fresh prefix
  	cli := etcdtest.Client(t)
  	resp, err := cli.Put(ctx, etcdtest.Prefix()+"elsewhere", "x")
  	if err != nil {
  		t.Fatal(err)
  	}
  	if _, err := s.GetContext(ctx, store.ContextKey{NAS: "leaf-01", Username: "nobody"}); !errors.Is(err, store.ErrNotFound) {
  		t.Fatal(err)
  	}
  	if got := s.Seen(); got < uint64(resp.Header.Revision) {
  		t.Fatalf("Seen %d, below the revision %d written before the read", got, resp.Header.Revision)
  	}
  }

  // Seen never goes back, whatever a later response says.
  func TestSeenNeverGoesBack(t *testing.T) {
  	s := onShared(t, time.Now)
  	s.saw(500)
  	s.saw(10)
  	if s.Seen() != 500 {
  		t.Fatalf("Seen %d", s.Seen())
  	}
  }
  ```

  Add to `internal/store/memory/memory_test.go`:

  ```go
  // The memory store's Seen is its revision counter, past every write.
  func TestMemorySeenIsItsCounter(t *testing.T) {
  	s := New(time.Now)
  	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
  	rev, err := s.PutContextRev(context.Background(), k, store.Context{CtxID: "c", Principal: "user:a", Username: "alice"}, time.Hour)
  	if err != nil || s.Seen() < rev || s.Ping(context.Background()) != nil {
  		t.Fatalf("Seen %d after a write at %d: %v", s.Seen(), rev, err)
  	}
  }
  ```

  In `guard_test.go` (pre-flight M15):
  - `TestEveryMethodIsRoutedToItsPool` iterates every `store.RevStore` method and calls each
    with a context. `Seen` has no pool ("Seen has no pool"), and a context passed to it would
    panic the reflective call. Exempt it by name at the top of the loop (`if m.Name == "Seen"
    { continue }`), with a comment that `Seen` makes no call.
  - Add `TestSeenPassesThroughWithNoSlot`. Build a guard whose context pool has one slot, held
    by a call parked inside the inner store. `Seen` through the guard still returns the
    inner's value at once, within 100ms, and counts nothing in `c.Metrics.Calls`. It fails
    against a `Seen` routed through `g.do`, which waits for the slot.
  - Add `TestPingIsTheContextPools`: `Ping` on an inner that fails counts one `context` pool
    failure, and none in `token` or `bulk`.

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/store/... -run 'Seen|Ping' -count=1`
  Expected: FAIL to compile: `Seen` is undefined.

- [ ] **Step 3: The interface.** In `store.go`, add to `RevStore`:

  ```go
  	// Seen is the highest store revision this client has been told of, by
  	// any read, write or watch; it makes no call and never goes back. A
  	// context write's sealed sequence is drawn above it (crypt; plan 7e,
  	// Ruling 3).
  	Seen() uint64
  	// Ping is one linearizable read: nil when the store answers. port49d's
  	// probe calls it through the guard (plan 7e, Ruling 11).
  	Ping(ctx context.Context) error
  ```

- [ ] **Step 4: Memory.**

  ```go
  // Seen is the store's revision counter: no write has a higher one.
  func (s *Store) Seen() uint64 {
  	s.mu.Lock()
  	defer s.mu.Unlock()
  	return s.revs
  }

  // Ping answers at once: the store is in the process.
  func (s *Store) Ping(context.Context) error { return nil }
  ```

- [ ] **Step 5: etcd.** In `etcd.go`, add to `Store` a field `seen atomic.Uint64` (named
  `seenRev` if `seen`, the read cache, is taken: it is, so `seenRev`) and:

  ```go
  // saw raises Seen to rev.
  func (s *Store) saw(rev int64) {
  	for {
  		cur := s.seenRev.Load()
  		if uint64(rev) <= cur || s.seenRev.CompareAndSwap(cur, uint64(rev)) {
  			return
  		}
  	}
  }

  // Seen is the highest store revision any of this store's responses or
  // watch events carried (store.RevStore).
  func (s *Store) Seen() uint64 { return s.seenRev.Load() }
  ```

  `Ping` exists (`Ping(ctx) error`). Make it `s.saw(resp.Header.Revision)` on success. In
  `contexts.go`, call `s.saw(resp.Header.Revision)` on every successful response of the context
  client:
  - `GetContext`, the not-found path included: move the call above the `len(resp.Kvs) == 0`
    check;
  - `readCtx`'s transaction;
  - `DeleteContextIf`'s read;
  - `mutate`'s read;
  - `commitRev`'s and `commit`'s responses (in `commit.go`, through a `*Store` method or by
    returning the header revision to the caller, whichever leaves `commit.go` shortest).

- [ ] **Step 6: guard.** In `guard.go`, add `"Ping": Context` to `pools`, and on the `RevStore`
  wrapper:

  ```go
  // Seen makes no call, so it takes no slot and no deadline (store.RevStore).
  func (g revGuarded) Seen() uint64 { return g.rev.Seen() }

  func (g revGuarded) Ping(ctx context.Context) error {
  	return g.do(ctx, Context, func(ctx context.Context) error { return g.rev.Ping(ctx) })
  }
  ```

  `revGuarded` (`guard.go:158`) is the wrapper `WrapRev` returns, a value type whose inner
  `RevStore` is `rev`. Every test double that
  implements `store.RevStore` without embedding one gains both methods: `grep -rn 'RevStore'
  internal cmd` names them.

- [ ] **Step 7: Run everything.**

  Run: `go test ./internal/store/... -count=1`
  Expected: PASS.

- [ ] **Step 8: Commit.**

  ```bash
  gofmt -w internal/store
  make build && make test && make vet
  git add internal/store/store.go internal/store/memory/memory.go internal/store/memory/memory_test.go \
    internal/store/etcd/etcd.go internal/store/etcd/contexts.go internal/store/etcd/commit.go \
    internal/store/etcd/etcd_test.go internal/store/guard/guard.go internal/store/guard/guard_test.go
  git commit -m "feat(store): Seen, the highest revision a store has been told of, and Ping

  A context write's sealed sequence is drawn above it (plan 7e Ruling 3),
  and port49d's probe pings through the context pool (Ruling 11). etcd
  observes every context-pool response's header, an absent key's read
  included.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

  List in `git add` any test double Step 6 touched.

---

### Task 7: The sealed write sequence, and a ledger every process can share a keyspace under

**Files:**
- Modify: `internal/store/crypt/ledger.go` (rewritten)
- Modify: `internal/store/crypt/crypt.go:199-239` (`contextSecret`, form 4), `:498-639` (seal,
  open, `sent`, the writes, `GetContext`), `:808-829` (the deletes)
- Modify: `internal/store/crypt/crypt.go:281-287` (`OnUnopenable` gains the reason)
- Modify: `internal/store/crypt/crypt_test.go` (the ledger's tests, listed below)
- Modify: `internal/broker/ledger_test.go`, `internal/store/etcd/etcd_test.go:284-357`
- Modify: `cmd/port49d/main.go:859`, `cmd/port49d/store.go:741` (`Seal` replaced),
  `cmd/port49d/store.go:243-290` (`unopenableSayer`'s lines), `:761` (`sweepLoop` takes the
  ledger)
- Modify: `cmd/port49d/store_test.go` (`TestUnopenableSayerSaysOncePerKeyPerTenMinutes`,
  `TestUnopenableSayerCallsANamelessRecordCorrupt`; two new sayer tests)

**Interfaces:**
- Consumes: `store.RevStore.Seen()` (Task 6).
- Produces (`crypt`):
  - `var ErrEarlierForm = errors.New("crypt: a context sealed by an earlier port49")`: a context
    that opens and is sealed in a form below `contextSealVersion` (pre-flight I10). Exported, so
    port49d's sayer tells it from tampering. A form above it is the plain mismatch error, as
    today.
  - `func OnUnopenable(f func(record, keyID string, why error)) Option`: `why` is the error the
    open returned (`ErrUnknownKey`, `ErrEarlierForm`, `ErrNotLastWritten`, or an authentication
    or decode failure).
  - `const contextSealVersion = 4`; `contextSecret.Seq uint64` (`json:"seq"`) in place of
    `WriteID`.
  - `func NewLedger() *Ledger`, unchanged.
  - `func (l *Ledger) SetBase(rev uint64)`, which replaces `Seal`: a key with no mark admits only
    a record sealed at or above the base. It only rises.
  - `func (l *Ledger) Base() uint64`.
  - `func (l *Ledger) SetKeep(d time.Duration)`: how long past the latest sealed ceiling seen at
    a key its mark is kept; at least `DefaultLedgerKeep` (24h).
  - `func (l *Ledger) Observe(k store.ContextKey, seq, rev uint64, plainRevokedAt, ceiling time.Time)`:
    a record known at `k`. It raises the mark to `seq` (and its revision to `rev`), never lowers
    it. A plaintext revocation at the mark's sequence is the floor. `ceiling` (zero: `never`)
    extends how long the mark is kept.
  - `func (l *Ledger) Seed(m store.LedgerMark)`: `Observe` from a ledger record. This task declares
    `store.LedgerMark` (Step 3); Task 10 writes the record.
  - `func (l *Ledger) Dirty() []store.LedgerMark`, `func (l *Ledger) Redirty(ms []store.LedgerMark)`
    and `func (l *Ledger) Pending() int` (Task 10's keeper).
  - `func (l *Ledger) Prune(now time.Time) int`: drops the marks past their keep; it returns how
    many.
  - `func (l *Ledger) Len() int`.
  - Unexported, for `crypt.go`:
    - `admits(k, seq) bool`, `next(k) uint64` and `stale(k, rev) bool`;
    - `floor(k) time.Time` and `revoked(k, at)`;
    - `wrote(k, seq, committed uint64, ceiling time.Time)`.
  - `ErrNotLastWritten`, kept: a record sealed below its key's mark.
  - `func openContextWith(keys Keys, k store.ContextKey, c store.Context) (store.Context, uint64, error)`,
    the open without a `wrapped`, for Task 8's feed.
- Produces (`cmd/port49d`): `func sweepLoop(ctx context.Context, s *etcdstore.Store, brk
  *broker.Broker, ledger *crypt.Ledger, every time.Duration, out io.Writer)` (pre-flight M16),
  which Task 15's runner calls as is.

Ruling 3. This is the change most worth its own review: read the ruling first.

**The rule, in full** (put it in `Ledger`'s comment):
- A write at `k` compared on `rev` seals `seq = max(rev, inner.Seen(), next(k))`. `next(k)` is
  the mark plus one, or the base for a key with no mark.
- A read admits a record whose sealed `seq` is at or above the key's mark, or at or above the
  base when the key has none, and then `Observe`s it.
- Below that, a record whose revision is below the mark's revision was served before the write
  that set the mark committed (`stale`), and is read again, up to twice. Anything else is
  `ErrNotLastWritten`.
- A write that lands `Observe`s its own `seq` at the revision it committed at.
- A write that fails needs nothing. A conflict wrote nothing. A deadline or an outage may have
  committed it, and if it did, the next read finds the higher sequence and admits it.
- Deletes forget nothing: a record put back after a delete is still below the mark.

**The tests, old and new.** 7d's ledger tests named a mechanism (writes in flight, unknown
outcomes, commit order, restore detection) that this rule removes. Each property they pinned is
kept as a property of the new rule:

| 7d test | Now |
|---|---|
| `TestTheLedgerDeniesAnotherLoginsContext` | kept: `Seal()` becomes `SetBase(inner.Seen()+1)` |
| `TestTheLedgerDeniesAnEarlierVersionOfTheSameContext` | kept, likewise |
| `TestTheLedgerAdmitsTheSameContextsWritesInFlightOrUnknown`, `TestTheLedgerAdmitsWritesInFlight`, `TestAReadSettlesEveryWriteWhoseOutcomeWasUnknown` | replaced by `TestAWriteInFlightOrOfUnknownOutcomeIsAdmittedWhicheverLanded` |
| `TestARevocationWhoseSealFailedIsNotUndoneByAPutBack` | kept |
| `TestTheRevocationFloorIsClearedOnlyByALaterWrite` | kept, as "only by a later sequence" |
| `TestAReadRacingAWriteOfTheSameContextReadsAgain` | kept on its `readHoldingStore`, which embeds `store.RevStore` and so gains `Seen` and `Ping`; its `l.Seal()` becomes `l.SetBase(h.Seen()+1)` (pre-flight M3) |
| `TestAContextOfFormTwoDoesNotOpen` | becomes `TestAContextOfFormThreeDoesNotOpen` (form 2 too) |
| `TestTheLedgerForgetsAKeyTheStoreNoLongerHolds` | replaced by `TestADeletedKeyKeepsItsMark` (stronger: a put-back after a delete is denied) and `TestTheLedgerPrunesAKeyPastItsKeep` |
| `TestASealedLedgerAdmitsNoUnseenKey` | becomes `TestARecordSealedBeforeTheBaseIsDeniedAtAnUnseenKey` |
| `TestTheLedgerOrdersWritesByTheStoresCommit`, `TestFirstLoginsRacingOnAnEmptyKey`, `TestTheLedgerPlacesAWriteThatEndsLate`, `TestTheLedgerDoesNotPlaceAWriteThatEndedAfterALaterOne`, `TestAWriteBegunBeforeTheLastEndedIsNotARestore`, `TestAReadSetsTheLastAtNoRevision` (`crypt_test.go:1529` at `b508ba0`), `TestAReplayReadBeforeALandedWriteEndsIsDeniedAfter` | `TestFirstLoginsRacingOnAnEmptyKey` kept on `twoLoginsEndOutOfOrder` and its `holdingStore`, whose `l.Seal()` (`:1401`) becomes `l.SetBase(inner.Seen()+1)`; the rest replaced by `TestTheStoresLastWriteIsAdmittedWhateverOrderWritesEnd` |
| `TestTheLedgerPlacesAWriteAfterTheStoresRevisionsWentBack`, `…WereBumped`, `TestALoginAfterARestoreIsTheLast` | replaced by `TestALoginAfterARestoreIsAdmitted` (both kinds of restore, one process and two), and `etcd_test.go`'s `TestALoginAfterAnEtcdRestoreIsTheLast` kept on the new API |
| — | new: `TestAnotherProcesssWriteIsAdmittedWithNoFeedBetween`, `TestAnEarlierRecordIsDeniedOnEveryProcessThatSawALater`, `TestTheSequenceIsAboveEverythingKnown`, `TestAnEarlierFormIsNamedAsOne` |
| `cmd/port49d`'s `TestUnopenableSayerSaysOncePerKeyPerTenMinutes`, `TestUnopenableSayerCallsANamelessRecordCorrupt` | kept, the sayer called with a `why`; new: `TestTheSayerNamesAnEarlierFormAsTheUpgrade`, `TestTheSayerNamesAPutBackAsBelowTheNewestWrite` |

- [ ] **Step 1: The failing tests.** In `crypt_test.go`, delete the tests the table replaces.
  Adapt the kept ones (`Seal()` → `SetBase(inner.Seen()+1)`; no other change to what they
  assert). Add:

  ```go
  // twoProcesses is one memory store with two sealing layers over it, each
  // with its own ledger, as two port49d processes on one etcd keyspace are;
  // each set its base when the store was empty.
  func twoProcesses(t *testing.T) (*memory.Store, store.Store, store.Store, *Ledger, *Ledger) {
  	t.Helper()
  	inner := memory.New(time.Now)
  	la, lb := NewLedger(), NewLedger()
  	la.SetBase(inner.Seen() + 1)
  	lb.SetBase(inner.Seen() + 1)
  	return inner, Wrap(inner, keys(), nil, WithLedger(la)), Wrap(inner, keys(), nil, WithLedger(lb)), la, lb
  }

  var ka = store.ContextKey{NAS: "leaf-01", Username: "netops"}

  func login(t *testing.T, s store.Store, ctxID, principal string) {
  	t.Helper()
  	cur, err := s.GetContext(context.Background(), ka)
  	var rev uint64
  	switch {
  	case err == nil:
  		rev = cur.Rev
  	case errors.Is(err, store.ErrNotFound):
  	default:
  		var u *store.UnreadableContextError
  		if !errors.As(err, &u) {
  			t.Fatal(err)
  		}
  		rev = u.Rev
  	}
  	if err := s.SwapLogin(context.Background(), ka, rev, store.Context{CtxID: ctxID, Principal: principal,
  		Username: "netops", BlobHash: "b-" + ctxID, PrivLvl: 1}, time.Hour, store.LoginWrite{}); err != nil {
  		t.Fatal(err)
  	}
  }

  // A login on one process is admitted on another: the record's sequence is
  // above the other's base, and above any mark it knows at the key (Review
  // Focus 1; Ruling 3). Neither ledger here follows a feed, so the fence
  // (Task 8a) passes at once; Task 8a's test covers the wait. A per-process
  // ledger, sealed, denied it (re-check IA1).
  func TestAnotherProcesssWriteIsAdmittedWithNoFeedBetween(t *testing.T) {
  	_, a, b, _, _ := twoProcesses(t)
  	login(t, a, "ctx-alice", "user:alice")
  	if c, err := b.GetContext(context.Background(), ka); err != nil || c.CtxID != "ctx-alice" {
  		t.Fatalf("the other process: %v %v", c.CtxID, err)
  	}
  	login(t, a, "ctx-bob", "user:bob") // a later login, again on a
  	if c, err := b.GetContext(context.Background(), ka); err != nil || c.CtxID != "ctx-bob" {
  		t.Fatalf("the other process, after a later login: %v %v", c.CtxID, err)
  	}
  }

  // Bob's context, written on a, read on b, and Alice's earlier one put
  // back by a store writer: b denies it, as a does, since both have seen a
  // later sequence at the key (Ruling 3).
  func TestAnEarlierRecordIsDeniedOnEveryProcessThatSawALater(t *testing.T) {
  	inner, a, b, _, _ := twoProcesses(t)
  	login(t, a, "ctx-alice", "user:alice")
  	saved, err := inner.GetContext(context.Background(), ka)
  	if err != nil {
  		t.Fatal(err)
  	}
  	login(t, b, "ctx-bob", "user:bob") // on b this time
  	if _, err := a.GetContext(context.Background(), ka); err != nil {
  		t.Fatal(err) // a reads bob's, raising its mark
  	}
  	if err := inner.PutContext(context.Background(), ka, saved, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	for name, s := range map[string]store.Store{"a": a, "b": b} {
  		_, err := s.GetContext(context.Background(), ka)
  		if !errors.Is(err, ErrNotLastWritten) {
  			t.Fatalf("process %s took alice's context put back over bob's: %v", name, err)
  		}
  	}
  }

  // A write in flight leaves the record before it admitted, and a write
  // whose outcome is unknown is admitted once read if it landed, and leaves
  // the record before it admitted if it did not (Ruling 3; 7d's three
  // in-flight and unknown-outcome tests).
  func TestAWriteInFlightOrOfUnknownOutcomeIsAdmittedWhicheverLanded(t *testing.T) {
  	for _, landed := range []bool{true, false} {
  		inner := &lossy{RevStore: memory.New(time.Now), commit: landed}
  		l := NewLedger()
  		l.SetBase(inner.Seen() + 1)
  		s := Wrap(inner, keys(), nil, WithLedger(l))
  		login(t, s, "ctx-1", "user:alice")
  		inner.lose = true // the next swap's reply is lost: ErrUnavailable, committed or not
  		cur, _ := s.GetContext(context.Background(), ka)
  		err := s.SwapContext(context.Background(), ka, cur.Rev, store.Context{CtxID: "ctx-1", Principal: "user:alice",
  			Username: "netops", BlobHash: "b-2", PrivLvl: 1}, time.Hour)
  		if !errors.Is(err, store.ErrUnavailable) {
  			t.Fatalf("landed=%v: %v", landed, err)
  		}
  		inner.lose = false
  		c, err := s.GetContext(context.Background(), ka)
  		want := map[bool]string{true: "b-2", false: "b-ctx-1"}[landed]
  		if err != nil || c.BlobHash != want {
  			t.Fatalf("landed=%v: read %q, %v; want %q", landed, c.BlobHash, err, want)
  		}
  	}
  }

  // lossy commits a SwapContextRev (or not) and reports ErrUnavailable while
  // lose is set.
  type lossy struct {
  	store.RevStore
  	lose, commit bool
  }

  func (l *lossy) SwapContextRev(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration) (uint64, error) {
  	if !l.lose {
  		return l.RevStore.SwapContextRev(ctx, k, rev, c, ttl)
  	}
  	if l.commit {
  		l.RevStore.SwapContextRev(ctx, k, rev, c, ttl)
  	}
  	return 0, store.ErrUnavailable
  }

  // Two writes at a key in either order of ending: whichever the store
  // holds is admitted, because it is the one whose compare-and-set landed
  // last, and a writer that read the other's record seals above it.
  func TestTheStoresLastWriteIsAdmittedWhateverOrderWritesEnd(t *testing.T) {
  	_, a, b, _, _ := twoProcesses(t)
  	login(t, a, "ctx-1", "user:alice")
  	login(t, b, "ctx-1", "user:alice") // b read a's, so seals above it
  	for name, s := range map[string]store.Store{"a": a, "b": b} {
  		if _, err := s.GetContext(context.Background(), ka); err != nil {
  			t.Fatalf("%s: the store's last write was denied: %v", name, err)
  		}
  	}
  }

  // After the store's revisions went back (a restore without
  // --bump-revision) or jumped (with it), a login seals above every record
  // this process knew, because Seen never goes back: it is admitted, and a
  // record the restore brought back, below the mark, is denied (Ruling 3;
  // L35's restore, measured).
  //
  // With two processes (pre-flight I12): q starts after the restore, so its
  // Seen is the restored store's. With the bump, q's login seals above
  // everything p knew, and p admits it. Without it, q seals below p's mark,
  // and p denies it until p writes at the key. The runbook (design §13)
  // says to bump, or to restart every process: the second half pins why.
  func TestALoginAfterARestoreIsAdmitted(t *testing.T) {
  	for _, bump := range []bool{false, true} {
  		inner := newRewinding(memory.New(time.Now))
  		l := NewLedger()
  		l.SetBase(inner.Seen() + 1)
  		p := Wrap(inner, keys(), nil, WithLedger(l))
  		login(t, p, "ctx-old", "user:alice")
  		old, _ := inner.RevStore.GetContext(context.Background(), ka)
  		for i := 0; i < 5; i++ { // p's mark well past the snapshot's revisions
  			login(t, p, fmt.Sprintf("ctx-new-%d", i), "user:alice")
  		}
  		inner.restore(old, bump) // the store now holds ctx-old, its revisions back or bumped
  		if _, err := p.GetContext(context.Background(), ka); !errors.Is(err, ErrNotLastWritten) {
  			t.Fatalf("bump=%v: a restored record below the mark was admitted: %v", bump, err)
  		}
  		// q: a process started after the restore, with a view of its own.
  		qv := inner.view()
  		lq := NewLedger()
  		lq.SetBase(qv.Seen() + 1)
  		q := Wrap(qv, keys(), nil, WithLedger(lq))
  		login(t, q, "ctx-on-q", "user:alice")
  		c, err := p.GetContext(context.Background(), ka)
  		switch {
  		case bump && (err != nil || c.CtxID != "ctx-on-q"):
  			t.Fatalf("with the bump, p did not admit q's login: %v %v", c.CtxID, err)
  		case !bump && !errors.Is(err, ErrNotLastWritten):
  			t.Fatalf("without the bump, p admitted a login sealed below its mark (%v %v): the runbook's "+
  				"restart is no longer needed, so say so in design §13", c.CtxID, err)
  		}
  		login(t, p, "ctx-after", "user:alice") // p's own write after the restore
  		for name, s := range map[string]store.Store{"p": p, "q": q} {
  			if c, err := s.GetContext(context.Background(), ka); err != nil || c.CtxID != "ctx-after" {
  				t.Fatalf("bump=%v, %s: the login after the restore: %v %v", bump, name, c.CtxID, err)
  			}
  		}
  	}
  }

  // rewinding is a store whose revisions can be put back to before a
  // record's, as a restore without --bump-revision does, or bumped by a
  // billion, as one with it does. Each view's Seen is its own and never goes
  // back, as an etcd client's is; the offset is the store's, shared by every
  // view.
  type rewinding struct {
  	store.RevStore
  	shared *rewindState
  	mu     sync.Mutex
  	seen   uint64
  }

  type rewindState struct {
  	mu     sync.Mutex
  	offset int64 // added to every revision the inner store reports
  }

  func newRewinding(inner store.RevStore) *rewinding {
  	return &rewinding{RevStore: inner, shared: &rewindState{}}
  }

  // view is another client of the same store, which has seen nothing yet:
  // a process started now.
  func (r *rewinding) view() *rewinding { return &rewinding{RevStore: r.RevStore, shared: r.shared} }

  func (r *rewinding) offset() int64 {
  	r.shared.mu.Lock()
  	defer r.shared.mu.Unlock()
  	return r.shared.offset
  }

  // out is an inner revision as the store reports it; in is the reverse.
  func (r *rewinding) out(rev uint64) uint64 {
  	if rev == 0 {
  		return 0
  	}
  	v := uint64(int64(rev) + r.offset())
  	r.mu.Lock()
  	r.seen = max(r.seen, v)
  	r.mu.Unlock()
  	return v
  }

  func (r *rewinding) in(rev uint64) uint64 {
  	if rev == 0 {
  		return 0
  	}
  	return uint64(int64(rev) - r.offset())
  }

  func (r *rewinding) Seen() uint64 {
  	r.out(r.RevStore.Seen())
  	r.mu.Lock()
  	defer r.mu.Unlock()
  	return r.seen
  }

  func (r *rewinding) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
  	c, err := r.RevStore.GetContext(ctx, k)
  	c.Rev, c.PolicyRev = r.out(c.Rev), r.out(c.PolicyRev)
  	return c, err
  }

  func (r *rewinding) SwapLoginRev(ctx context.Context, k store.ContextKey, rev uint64, c store.Context,
  	ttl time.Duration, w store.LoginWrite) (uint64, error) {
  	got, err := r.RevStore.SwapLoginRev(ctx, k, r.in(rev), c, ttl, w)
  	return r.out(got), err
  }

  // SwapContextRev, PutContextRev and RewriteContextRev are SwapLoginRev's
  // shape: in on the way down, out on the way up. Write them alike.

  // restore puts old back at ka as the store's, and moves the revisions the
  // store reports: back to just above 1 (no bump), below everything written
  // since, or up by a billion (bump).
  func (r *rewinding) restore(old store.Context, bump bool) {
  	cur := r.RevStore.Seen()
  	r.shared.mu.Lock()
  	if bump {
  		r.shared.offset = 1_000_000_000
  	} else {
  		r.shared.offset = 1 - int64(cur)
  	}
  	r.shared.mu.Unlock()
  	old.Rev, old.PolicyRev = 0, 0
  	r.RevStore.PutContext(context.Background(), ka, old, time.Hour)
  }

  // A record sealed before this process's base, at a key it has no mark
  // for, is a put-back: denied. One sealed after the base, by any process,
  // is admitted (7d's sealed ledger, on the new rule).
  func TestARecordSealedBeforeTheBaseIsDeniedAtAnUnseenKey(t *testing.T) {
  	inner, a, _, _, _ := twoProcesses(t)
  	login(t, a, "ctx-1", "user:alice")
  	saved, _ := inner.GetContext(context.Background(), ka)
  	if err := inner.DeleteContext(context.Background(), ka); err != nil {
  		t.Fatal(err)
  	}
  	late := NewLedger()
  	late.SetBase(inner.Seen() + 1) // a process started now, finding the key empty
  	c := Wrap(inner, keys(), nil, WithLedger(late))
  	if err := inner.PutContext(context.Background(), ka, saved, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	if _, err := c.GetContext(context.Background(), ka); !errors.Is(err, ErrNotLastWritten) {
  		t.Fatalf("a record sealed before the base was admitted at an unseen key: %v", err)
  	}
  	login(t, a, "ctx-2", "user:alice")
  	if _, err := c.GetContext(context.Background(), ka); err != nil {
  		t.Fatalf("a record sealed after the base was denied: %v", err)
  	}
  }

  // A delete forgets nothing: a record put back after one is still below the
  // key's mark (stronger than 7d's forget).
  func TestADeletedKeyKeepsItsMark(t *testing.T) {
  	inner, a, _, _, _ := twoProcesses(t)
  	login(t, a, "ctx-1", "user:alice")
  	saved, _ := inner.GetContext(context.Background(), ka)
  	login(t, a, "ctx-2", "user:bob")
  	if err := a.DeleteContext(context.Background(), ka); err != nil {
  		t.Fatal(err)
  	}
  	inner.PutContext(context.Background(), ka, saved, time.Hour)
  	if _, err := a.GetContext(context.Background(), ka); !errors.Is(err, ErrNotLastWritten) {
  		t.Fatalf("a put-back after a delete was admitted: %v", err)
  	}
  }

  // A mark is kept past the latest sealed ceiling seen at its key by the
  // ledger's keep, then pruned; a context with no ceiling (never) is kept.
  func TestTheLedgerPrunesAKeyPastItsKeep(t *testing.T) {
  	l := NewLedger()
  	now := time.Unix(2_000_000, 0)
  	l.Observe(ka, 10, 10, time.Time{}, now.Add(time.Hour))
  	never := store.ContextKey{NAS: "leaf-02", Username: "svc"}
  	l.Observe(never, 11, 11, time.Time{}, time.Time{})
  	if n := l.Prune(now.Add(time.Hour + DefaultLedgerKeep - time.Second)); n != 0 {
  		t.Fatalf("pruned %d before its keep", n)
  	}
  	if n := l.Prune(now.Add(time.Hour + DefaultLedgerKeep + time.Second)); n != 1 || l.Len() != 1 {
  		t.Fatalf("pruned %d, %d left: the never context's mark must stay", n, l.Len())
  	}
  }

  // The sequence a write seals is above the revision it compares on, above
  // everything the store has told this process, and above the key's mark:
  // each term wins once (pre-flight M4: the Seen term is exercised too).
  func TestTheSequenceIsAboveEverythingKnown(t *testing.T) {
  	inner := &seenAt{RevStore: memory.New(time.Now), seen: 10}
  	l := NewLedger()
  	l.Observe(ka, 1000, 1000, time.Time{}, time.Time{})
  	w := Wrap(inner, keys(), nil, WithLedger(l)).(*wrapped)
  	if got := w.seqFor(ka, 5); got != 1001 {
  		t.Fatalf("the mark's term: %d", got)
  	}
  	if got := w.seqFor(ka, 5000); got != 5000 {
  		t.Fatalf("the compare revision's term: %d", got)
  	}
  	inner.seen = 9000
  	if got := w.seqFor(ka, 5000); got != 9000 {
  		t.Fatalf("the Seen term: %d", got)
  	}
  }

  // seenAt is a store whose Seen is whatever the test sets.
  type seenAt struct {
  	store.RevStore
  	seen uint64
  }

  func (s *seenAt) Seen() uint64 { return s.seen }

  // A form-3 (7d) or form-2 context does not open: denied, and replaced at
  // the next login (Ruling 3, the migration).
  func TestAContextOfFormThreeDoesNotOpen(t *testing.T) {
  	for _, v := range []int{2, 3} {
  		inner := memory.New(time.Now)
  		l := NewLedger()
  		l.SetBase(inner.Seen() + 1)
  		s := Wrap(inner, keys(), nil, WithLedger(l))
  		body, _ := json.Marshal(map[string]any{"v": v, "write_id": "00", "ctx_id": "c-old", "principal": "user:alice",
  			"username": "netops"})
  		sealed, err := keys().SealBound(body, contextAAD(ka))
  		if err != nil {
  			t.Fatal(err)
  		}
  		if err := inner.PutContext(context.Background(), ka, store.Context{Sealed: sealed}, time.Hour); err != nil {
  			t.Fatal(err)
  		}
  		var u *store.UnreadableContextError
  		if _, err := s.GetContext(context.Background(), ka); !errors.As(err, &u) {
  			t.Fatalf("form %d opened: %v", v, err)
  		}
  		login(t, s, "ctx-new", "user:alice") // the next login replaces it
  		if c, err := s.GetContext(context.Background(), ka); err != nil || c.CtxID != "ctx-new" {
  			t.Fatalf("form %d: the login after it: %v %v", v, c.CtxID, err)
  		}
  	}
  }

  // An earlier form is ErrEarlierForm, both in the read's error and in what
  // OnUnopenable is told, so the operator's line names the upgrade rather
  // than tampering; a later form, and a put-back, are not it (pre-flight I10).
  func TestAnEarlierFormIsNamedAsOne(t *testing.T) {
  	for _, c := range []struct {
  		v       int
  		earlier bool
  	}{{3, true}, {2, true}, {5, false}} {
  		inner := memory.New(time.Now)
  		var told error
  		s := Wrap(inner, keys(), nil, OnUnopenable(func(_, _ string, why error) { told = why }))
  		body, _ := json.Marshal(map[string]any{"v": c.v, "ctx_id": "c-old", "principal": "user:alice",
  			"username": "netops"})
  		sealed, _ := keys().SealBound(body, contextAAD(ka))
  		inner.PutContext(context.Background(), ka, store.Context{Sealed: sealed}, time.Hour)
  		_, err := s.GetContext(context.Background(), ka)
  		if errors.Is(err, ErrEarlierForm) != c.earlier || errors.Is(told, ErrEarlierForm) != c.earlier {
  			t.Fatalf("form %d: read %v, told %v", c.v, err, told)
  		}
  	}
  	// A put-back is told as one, never as an earlier form.
  	inner := memory.New(time.Now)
  	l := NewLedger()
  	l.SetBase(inner.Seen() + 1)
  	var told error
  	s := Wrap(inner, keys(), nil, WithLedger(l), OnUnopenable(func(_, _ string, why error) { told = why }))
  	login(t, s, "ctx-alice", "user:alice")
  	saved, _ := inner.GetContext(context.Background(), ka)
  	login(t, s, "ctx-bob", "user:bob")
  	inner.PutContext(context.Background(), ka, saved, time.Hour)
  	s.GetContext(context.Background(), ka)
  	if !errors.Is(told, ErrNotLastWritten) || errors.Is(told, ErrEarlierForm) {
  		t.Fatalf("a put-back was told as %v", told)
  	}
  }
  ```

  In `internal/broker/ledger_test.go` and `etcd_test.go:284`, replace `l.Seal()` with
  `l.SetBase(<the store>.Seen()+1)`. Keep what they assert.

  In `cmd/port49d/store_test.go`, the two sayer tests call the sayer with a third argument,
  `nil` (an authentication failure), and assert as before. Add (pre-flight I10):

  ```go
  // An earlier form is the upgrade, said as the upgrade: never "altered or is
  // corrupt", which at 3am reads as an attack across the fleet.
  func TestTheSayerNamesAnEarlierFormAsTheUpgrade(t *testing.T) {
  	var out bytes.Buffer
  	keys := crypt.Keys{Current: crypt.Key{ID: "v2"}}
  	say := unopenableSayer(keys, &out, time.Now)
  	say("context", "v2", fmt.Errorf("crypt: opening context: %w", crypt.ErrEarlierForm))
  	got := out.String()
  	if !strings.Contains(got, "a context sealed by an earlier port49 (form 3) does not open: expected once "+
  		"after the 7e upgrade; replaced at its user's next login") || strings.Contains(got, "altered") {
  		t.Fatalf("%q", got)
  	}
  }

  // A record below the newest write is named as that, not as "the one this
  // port49d last wrote", which is no longer the rule (plan 7e, Ruling 3).
  func TestTheSayerNamesAPutBackAsBelowTheNewestWrite(t *testing.T) {
  	var out bytes.Buffer
  	keys := crypt.Keys{Current: crypt.Key{ID: "v2"}}
  	say := unopenableSayer(keys, &out, time.Now)
  	say("context", "v2", crypt.ErrNotLastWritten)
  	got := out.String()
  	if !strings.Contains(got, "is sealed below the newest write any port49 process made there") ||
  		strings.Contains(got, "last wrote") {
  		t.Fatalf("%q", got)
  	}
  }
  ```

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/store/crypt/ ./cmd/port49d/ -run 'Ledger|Process|Restore|Sequence|Form|Sayer|Earlier|Deleted|Prune|Racing|Revocation' -count=1`
  Expected: FAIL to compile (`SetBase`, `Observe`, `seqFor`, `ErrEarlierForm` undefined; the
  sayer takes two arguments). Once compiled against a stub,
  `TestAnotherProcesssWriteIsAdmittedWithNoFeedBetween` fails as 7d's sealed ledger would:
  process b denies a's login.

- [ ] **Step 3: The ledger.** Replace `internal/store/crypt/ledger.go` with:

  ```go
  package crypt

  import (
  	"errors"
  	"sync"
  	"time"

  	"github.com/rhwendt/port49/internal/store"
  )

  // ErrNotLastWritten is a context that opens at its key but is sealed below
  // the highest write sequence this process knows there: another login's
  // record, or an earlier version of the same context, written back by
  // whoever can write the store (plan 7d, Ruling 17; plan 7e, Ruling 3).
  // GetContext returns it inside an UnreadableContextError, so every handler
  // treats it as a record that will not open.
  var ErrNotLastWritten = errors.New("crypt: sealed below the newest write this port49d knows at its key")

  // DefaultLedgerKeep is how long past the latest sealed ceiling seen at a
  // key its mark is kept, at least: longer than any grace window a context
  // is kept past its ceiling, so a record put back is past its ceiling, and
  // denied by it, before its mark goes.
  const DefaultLedgerKeep = 24 * time.Hour

  // Ledger is, per context key, the highest write sequence this process
  // knows there (plan 7e, Ruling 3; decision 36). Every context seal carries
  // a sequence above the revision its write compares on, above every store
  // revision the writing process has seen (store.RevStore.Seen), and above
  // the key's mark here: so every write that lands at a key is sealed above
  // every earlier one, whichever process made it, and no store writer can
  // forge it.
  //
  // A read admits a record sealed at or above its key's mark, and raises the
  // mark; below it, the record is another login's, or an earlier version of
  // the same context, written back, and is denied (ErrNotLastWritten) —
  // unless it was served before the write that set the mark committed
  // (stale), when it is read again, up to twice. A key with no mark admits
  // a record sealed at or above the base: the revision just past the
  // start's scan of the contexts, which saw every record then at a key.
  //
  // The mark is fed by this process's own writes that land, its reads, the
  // store's context feed (FollowContexts) and, at a start, the ledger record
  // (LoadLedger, Seed). Each only raises. A write of unknown outcome needs
  // nothing: if it landed, its sequence is the higher and the next read
  // admits it; if not, the store holds the record the mark names. A delete
  // forgets nothing.
  //
  // A revocation whose plaintext mark landed and whose seal did not is the
  // key's revocation floor (final review 7d-2 I-1): GetContext takes the
  // latest of the sealed time, the plaintext time and the floor. The floor
  // is set by this process's own revocation (revoked), and by any record it
  // reads or the feed brings at the mark's sequence with a plaintext
  // revoked_at; only a later sequence clears it.
  //
  // A mark is kept until keep past the latest sealed ceiling seen at its
  // key; one that saw a context with no ceiling (max_session_age: never) is
  // kept for good (Prune).
  //
  // One Ledger is shared by every Wrap in a process (WithLedger). It is safe
  // for concurrent use.
  type Ledger struct {
  	mu    sync.Mutex
  	m     map[store.ContextKey]*ledgerEntry
  	base  uint64
  	keep  time.Duration
  	dirty map[store.ContextKey]bool
  }

  type ledgerEntry struct {
  	hw           uint64    // the highest sequence known at the key
  	rev          uint64    // the revision the record at hw was read or written at; zero when unknown
  	floor        time.Time // a revocation's plaintext time, held while hw <= floorSeq
  	floorSeq     uint64    // the sequence the floor's revocation landed on
  	floorPending bool      // a floor set before any sequence was known: the next one is its
  	ceiling      time.Time // the latest sealed ceiling seen at the key
  	never        bool      // a context with no ceiling was seen at the key
  }

  // NewLedger is an empty ledger with a base of zero and the default keep.
  func NewLedger() *Ledger {
  	return &Ledger{m: map[store.ContextKey]*ledgerEntry{}, keep: DefaultLedgerKeep,
  		dirty: map[store.ContextKey]bool{}}
  }

  // SetBase raises the base to rev: a key with no mark admits only a record
  // sealed at or above it. port49d sets it just past its start's scan.
  func (l *Ledger) SetBase(rev uint64) {
  	l.mu.Lock()
  	defer l.mu.Unlock()
  	if rev > l.base {
  		l.base = rev
  	}
  }

  // Base is the base.
  func (l *Ledger) Base() uint64 {
  	l.mu.Lock()
  	defer l.mu.Unlock()
  	return l.base
  }

  // SetKeep sets how long past the latest ceiling a mark is kept, never
  // below DefaultLedgerKeep.
  func (l *Ledger) SetKeep(d time.Duration) {
  	l.mu.Lock()
  	defer l.mu.Unlock()
  	l.keep = max(d, DefaultLedgerKeep)
  }

  func (l *Ledger) entry(k store.ContextKey) *ledgerEntry {
  	e := l.m[k]
  	if e == nil {
  		e = &ledgerEntry{}
  		l.m[k] = e
  	}
  	return e
  }

  // Observe is a record known at k: sealed at seq, read or written at rev,
  // with its plaintext revocation and its sealed ceiling (zero: never). It
  // raises k's mark and never lowers it.
  func (l *Ledger) Observe(k store.ContextKey, seq, rev uint64, plainRevokedAt, ceiling time.Time) {
  	l.mu.Lock()
  	defer l.mu.Unlock()
  	l.observe(k, seq, rev, plainRevokedAt, ceiling)
  }

  func (l *Ledger) observe(k store.ContextKey, seq, rev uint64, plainRevokedAt, ceiling time.Time) {
  	e := l.entry(k)
  	changed := false
  	switch {
  	case seq > e.hw:
  		e.hw, e.rev, changed = seq, rev, true
  		switch {
  		case e.floorPending:
  			e.floorSeq, e.floorPending = seq, false
  		case seq > e.floorSeq:
  			e.floor, e.floorSeq = time.Time{}, 0
  		}
  	case seq == e.hw && rev > e.rev:
  		e.rev = rev
  	}
  	if seq == e.hw && !plainRevokedAt.IsZero() && plainRevokedAt.After(e.floor) {
  		e.floor, e.floorSeq, changed = plainRevokedAt, seq, true
  	}
  	switch {
  	case ceiling.IsZero() && seq >= e.hw && !e.never:
  		e.never, changed = true, true
  	case ceiling.After(e.ceiling):
  		e.ceiling, changed = ceiling, true
  	}
  	if changed {
  		l.dirty[k] = true
  	}
  }

  // Seed is Observe from the ledger record (plan 7e, Ruling 4).
  func (l *Ledger) Seed(m store.LedgerMark) {
  	ceiling := time.Time{}
  	if !m.Until.IsZero() {
  		ceiling = m.Until.Add(-l.keepFor())
  	}
  	l.Observe(m.Key, m.Seq, 0, m.RevokedAt, ceiling)
  }

  func (l *Ledger) keepFor() time.Duration {
  	l.mu.Lock()
  	defer l.mu.Unlock()
  	return l.keep
  }

  // admits reports whether a record sealed at seq may be read at k.
  func (l *Ledger) admits(k store.ContextKey, seq uint64) bool {
  	l.mu.Lock()
  	defer l.mu.Unlock()
  	if e, ok := l.m[k]; ok && e.hw > 0 {
  		return seq >= e.hw
  	}
  	return seq >= l.base
  }

  // next is the least sequence a write at k may seal: above the mark, or
  // the base for a key with none.
  func (l *Ledger) next(k store.ContextKey) uint64 {
  	l.mu.Lock()
  	defer l.mu.Unlock()
  	if e, ok := l.m[k]; ok && e.hw > 0 {
  		return e.hw + 1
  	}
  	return max(l.base, 1)
  }

  // stale reports whether a record read at k at rev was served before the
  // write that set the mark committed.
  func (l *Ledger) stale(k store.ContextKey, rev uint64) bool {
  	l.mu.Lock()
  	defer l.mu.Unlock()
  	e, ok := l.m[k]
  	return ok && e.rev > 0 && rev < e.rev
  }

  // wrote is a write of this process's that landed at k: sealed at seq,
  // committed at committed (zero when the store did not say).
  func (l *Ledger) wrote(k store.ContextKey, seq, committed uint64, ceiling time.Time) {
  	l.Observe(k, seq, committed, time.Time{}, ceiling)
  }

  // revoked records at as k's revocation floor once this process's
  // revocation's plaintext mark has landed there.
  func (l *Ledger) revoked(k store.ContextKey, at time.Time) {
  	l.mu.Lock()
  	defer l.mu.Unlock()
  	e := l.entry(k)
  	if at.After(e.floor) {
  		e.floor = at
  	}
  	if e.hw == 0 {
  		e.floorPending = true
  	} else {
  		e.floorSeq = e.hw
  	}
  	l.dirty[k] = true
  }

  // floor is k's revocation floor, zero when it has none.
  func (l *Ledger) floor(k store.ContextKey) time.Time {
  	l.mu.Lock()
  	defer l.mu.Unlock()
  	if e, ok := l.m[k]; ok {
  		return e.floor
  	}
  	return time.Time{}
  }

  // Dirty is every mark raised since the last call, which it clears, for
  // the ledger record's keeper (Task 10).
  func (l *Ledger) Dirty() []store.LedgerMark {
  	l.mu.Lock()
  	defer l.mu.Unlock()
  	out := make([]store.LedgerMark, 0, len(l.dirty))
  	for k := range l.dirty {
  		e := l.m[k]
  		if e == nil {
  			continue
  		}
  		m := store.LedgerMark{Key: k, Seq: e.hw, RevokedAt: e.floor}
  		if !e.never && !e.ceiling.IsZero() {
  			m.Until = e.ceiling.Add(l.keep)
  		}
  		out = append(out, m)
  	}
  	clear(l.dirty)
  	return out
  }

  // Redirty marks ms owed again: the keeper's write of them failed.
  func (l *Ledger) Redirty(ms []store.LedgerMark) {
  	l.mu.Lock()
  	defer l.mu.Unlock()
  	for _, m := range ms {
  		l.dirty[m.Key] = true
  	}
  }

  // Pending is how many marks are owed to the ledger record.
  func (l *Ledger) Pending() int {
  	l.mu.Lock()
  	defer l.mu.Unlock()
  	return len(l.dirty)
  }

  // Prune drops every mark past its keep after the latest ceiling seen at
  // its key, and returns how many. A mark that saw a never context stays.
  func (l *Ledger) Prune(now time.Time) int {
  	l.mu.Lock()
  	defer l.mu.Unlock()
  	n := 0
  	for k, e := range l.m {
  		if !e.never && !e.ceiling.IsZero() && now.After(e.ceiling.Add(l.keep)) {
  			delete(l.m, k)
  			delete(l.dirty, k)
  			n++
  		}
  	}
  	return n
  }

  // Len is how many keys the ledger holds a mark for.
  func (l *Ledger) Len() int {
  	l.mu.Lock()
  	defer l.mu.Unlock()
  	return len(l.m)
  }
  ```

  Declare `store.LedgerMark` in `internal/store/store.go`
  already, with its comment, so this task compiles:

  ```go
  // LedgerMark is one key's entry in the ledger record (plan 7e, Ruling 4):
  // the highest write sequence known there, a revocation's plaintext time
  // held at it, and until when it is kept (zero: for good, a never
  // context's).
  type LedgerMark struct {
  	Key       ContextKey
  	Seq       uint64
  	RevokedAt time.Time
  	Until     time.Time
  }
  ```

- [ ] **Step 4: The seal.** In `crypt.go`:
  - `contextSealVersion = 4`; in `contextSecret`, `Seq uint64 \`json:"seq"\`` replaces
    `WriteID`, with this comment: "Seq is the write's sequence (Ledger): above every earlier
    write at the key, whichever process made it. Sealed, a store writer can neither forge it nor
    move it."
  - `sealContext(k, c, seq uint64) (store.Context, error)` seals `Seq: seq` and no longer draws
    a random ID.
  - `openContextWith(keys, k, c) (store.Context, uint64, error)` is today's `openContext` body
    over `keys`, returning `cs.Seq`. `(*wrapped).openContext` calls it with `w.keys`.
    - A form below 4 is `fmt.Errorf("%w (form %d, not %d)", ErrEarlierForm, cs.V,
      contextSealVersion)`, so `errors.Is(err, ErrEarlierForm)` holds through `openErr`'s
      wrap.
    - A form above 4 is the mismatch error it is today.
  - `OnUnopenable(f func(record, keyID string, why error))`. `openErr(record, sealed, err)`
    calls `w.onUnopenable(record, SealedKeyID(sealed), err)`. Every caller of `OnUnopenable` in
    the tree passes a three-argument function (`grep -rn OnUnopenable internal cmd`).
  - Add:

  ```go
  // seqFor is the sequence a write at k compared on rev seals (Ledger):
  // above the compare revision, everything the store has told this process,
  // and the key's mark.
  func (w *wrapped) seqFor(k store.ContextKey, rev uint64) uint64 {
  	return max(rev, w.inner.Seen(), w.ledger.next(k))
  }

  // sent sends one sealed write at k, sealed at seq, and tells the ledger
  // when it lands, with the revision it committed at. A write that fails
  // tells it nothing: a conflict wrote nothing, and one of unknown outcome
  // is admitted by the next read if it landed (Ledger).
  func (w *wrapped) sent(k store.ContextKey, seq uint64, ceiling time.Time, send func() (uint64, error)) error {
  	committed, err := send()
  	if err == nil {
  		w.ledger.wrote(k, seq, committed, ceiling)
  	}
  	return err
  }
  ```

  - In `PutContext`, `SwapContext`, `SwapLogin`, `RewriteContext` and `rewrite`: `seq :=
    w.seqFor(k, rev)` (rev 0 for `PutContext`), `sc, err := w.sealContext(k, c, seq)`, and
    `w.sent(k, seq, c.SessionExpires, …)`.
  - `GetContext`:

  ```go
  func (w *wrapped) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
  	for read := 0; ; read++ {
  		c, err := w.inner.GetContext(ctx, k)
  		if err != nil {
  			return store.Context{}, err
  		}
  		oc, seq, err := w.openContext(k, c)
  		if err != nil {
  			return store.Context{}, &store.UnreadableContextError{Rev: c.Rev,
  				RevokedAt: latest(c.RevokedAt, w.ledger.floor(k)), Err: w.openErr("context", c.Sealed, err)}
  		}
  		// The ledger (plan 7e, Ruling 3): a record sealed below the newest
  		// write this process knows at the key is another login's, or an
  		// earlier version of this one, written back, and is denied as one
  		// that does not open. One served before that write committed raced
  		// it, and is read again.
  		if w.ledger.admits(k, seq) {
  			w.ledger.Observe(k, seq, c.Rev, c.RevokedAt, oc.SessionExpires)
  			oc.RevokedAt = latest(oc.RevokedAt, w.ledger.floor(k))
  			return oc, nil
  		}
  		if read < staleReads && w.ledger.stale(k, c.Rev) {
  			continue
  		}
  		return store.Context{}, &store.UnreadableContextError{Rev: c.Rev,
  			RevokedAt: latest(c.RevokedAt, w.ledger.floor(k)), Err: w.openErr("context", c.Sealed, ErrNotLastWritten)}
  	}
  }
  ```

  - `DeleteContext` and `DeleteContextIf` pass through, with no ledger call.
  - Delete `mark`, `forget`, `begin`, `end`, `landed` and `ledgerWrite` with the old ledger.
  - `SetRevokedAt` keeps `w.ledger.revoked(k, at)`.

- [ ] **Step 5: port49d.** In `cmd/port49d/main.go` (the memory branch, `ledger.Seal()`), the
  memory store is new and empty. In `openStores`'s memory branch, build it as `mem :=
  memory.New(time.Now)` and set `ledger.SetBase(mem.Seen() + 1)` before wrapping it. Delete the
  `ledger.Seal()` in `main.go`.

  In `cmd/port49d/store.go`'s `startOnPersistentStore`, replace `ledger.Seal()` with nothing
  for now. Task 8 sets the base before the start's reads, from its scan. Until Task 8 lands,
  set `ledger.SetBase(e.Seen() + 1)` there, where `Seal` was, so 7d's
  `TestAStartSealsTheLedgerOnceItHasReadTheStore` still passes.

  Also call `ledger.SetKeep(max(cfg.Session.GraceWindow+time.Hour, crypt.DefaultLedgerKeep))`
  where the ledger is built (`run`). `Prune` runs in the sweep loop and, on memory, every 10
  minutes from `run` (a ticker joined with the run). The sweep loop's signature becomes
  (pre-flight M16):

  ```go
  func sweepLoop(ctx context.Context, s *etcdstore.Store, brk *broker.Broker, ledger *crypt.Ledger,
  	every time.Duration, out io.Writer)
  ```

  It calls `ledger.Prune(time.Now())` after each sweep. `runOnce`'s call becomes
  `sweepLoop(ctx, sts.etcd, brk, ledger, cfg.Store.Etcd.SweepInterval, stderr)`.

  **The sayer's lines** (`unopenableSayer` in `store.go`, pre-flight I10). It becomes `func(record,
  keyID string, why error)`. In its held-key branch:
  - `errors.Is(why, crypt.ErrEarlierForm)` prints `port49d: crypt: a %s sealed by an earlier
    port49 (form 3) does not open: expected once after the 7e upgrade; replaced at its user's
    next login`.
  - `errors.Is(why, crypt.ErrNotLastWritten)` prints `port49d: crypt: a %s under key id %q is
    sealed below the newest write any port49 process made there: it was put back, and is treated
    as unreadable`.
  - Anything else prints today's line without its "or is not the one this port49d last wrote
    there" clause: `port49d: crypt: a %s failed authentication under key id %q: it was altered or
    is corrupt, and is treated as unreadable`.
  - The memory key stays `(record, keyID)`, so each line is still once per 10 minutes. The
    earlier-form line is the one a fleet sees at the upgrade.

  The form-3 line names form 3 because 7d's form is 3. A form-2 record, which only a 7d store
  that never re-sealed can hold, prints the same line.

- [ ] **Step 6: Run everything.**

  Run: `go test ./internal/store/... ./internal/broker/ ./cmd/port49d/ -count=1` then `make
  test-race`
  Expected: PASS. 7d's e2e tests pass unchanged:
  - `TestAStartSealsTheLedgerOnceItHasReadTheStore`;
  - `TestAHungStoreGoesDarkAndServesAgainWhenItReturns`, the put-back in the dark denied;
  - the restore test.

- [ ] **Step 7: Commit.**

  ```bash
  gofmt -w internal/store/crypt internal/store/store.go internal/broker/ledger_test.go \
    internal/store/etcd/etcd_test.go cmd/port49d
  make build && make test && make vet && make test-race
  git add internal/store/crypt/ledger.go internal/store/crypt/crypt.go internal/store/crypt/crypt_test.go \
    internal/store/store.go internal/broker/ledger_test.go internal/store/etcd/etcd_test.go \
    cmd/port49d/main.go cmd/port49d/store.go cmd/port49d/store_test.go
  git commit -m "feat(crypt): a sealed write sequence and a high-water ledger per key

  A context seal (form 4) carries a sequence above its compare revision,
  every revision the store has told this process, and the key's mark; a
  read admits a record at or above the mark. Another process's later
  login is admitted and an earlier record put back is denied, whichever
  process wrote either: a per-process ledger would deny every other
  replica's logins (plan 7e Ruling 3; re-check IA1). Writes in flight,
  unknown outcomes and both kinds of restore fall out of the rule. A form-3
  context does not open: on etcd every live session ends once at the
  upgrade.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 8: Every process follows the store's contexts

**Files:**
- Modify: `internal/store/store.go` (`ContextChange`, `ContextFeed`, `ErrCompacted`,
  `LedgerSource`, `LedgerSink`)
- Create: `internal/store/etcd/feed.go`, `internal/store/etcd/feed_test.go`
- Create: `internal/store/crypt/follow.go`, `internal/store/crypt/follow_test.go`
- Modify: `internal/store/crypt/ledger.go` (`ObserveFollowed`)
- Modify: `internal/daemon/metrics/metrics.go`, `metrics_test.go` (`StoreFeedUp`,
  `StoreFeedRescans`)
- Modify: `cmd/port49d/store.go` (`openStores`, `stores`), `cmd/port49d/main.go`

**Interfaces:**
- Consumes: `crypt.Ledger` (Task 7), `(*etcd.Store).saw` (Task 6), `etcd.lastTwo`.
- Produces:
  - `store`:
    - `type ContextChange struct { Key ContextKey; Context Context; Deleted bool; Rev uint64 }`;
    - `type ContextFeed interface { ScanContexts(ctx context.Context, fn func(ContextKey, Context)) (uint64, error); WatchContexts(ctx context.Context, after uint64, fn func(ContextChange), progress func(rev uint64), asks <-chan struct{}) error }`.
      `progress` is told a revision through which every change has been delivered: the
      highest event's after each batch, and each progress notify's header revision. Each
      receive on `asks` requests one progress notify. A nil `asks` requests none. Task 8a
      wires both to the fence; this task passes a no-op and nil;
    - `var ErrCompacted = errors.New("store: the feed's revision was compacted")`;
    - `type LedgerSource interface { LedgerMarks(ctx context.Context) (uint64, []LedgerMark, error) }`;
    - `type LedgerSink interface { PutLedgerMarks(ctx context.Context, ms []LedgerMark) error }`.
  - `(*etcd.Store).ScanContexts` and `(*etcd.Store).WatchContexts`.
  - `crypt`:
    - `func (l *Ledger) ObserveFollowed(k store.ContextKey, seq, rev uint64, plainRevokedAt, ceiling time.Time)`:
      `Observe` for a record the feed or a later scan brought. It raises an entry the ledger
      holds, and makes one only for `seq >= l.Base()` (pre-flight I1);
    - `func LoadLedger(ctx context.Context, feed store.ContextFeed, src store.LedgerSource, keys Keys, l *Ledger) (rev uint64, known, recorded int, err error)`.
      Its scan makes entries (`Observe`) only on a ledger never loaded (`l.Base() == 0`). On a
      ledger already loaded, such as a re-entry after a store gone, it uses `ObserveFollowed`
      against the base before this load, then raises the base;
    - `func FollowContexts(ctx context.Context, feed store.ContextFeed, src store.LedgerSource, keys Keys, l *Ledger, from uint64, up func(bool), rescanned func(), logf func(string, ...any)) error`.
      Every change and every rescan goes through `ObserveFollowed`. A compacted watch's rescan
      seeds `l` from `src` first (`nil` reads none), as `LoadLedger` does (re-check R1);
    - `func rescan(ctx context.Context, feed store.ContextFeed, src store.LedgerSource, keys Keys, l *Ledger) (uint64, error)`
      and `func seedFrom(ctx context.Context, src store.LedgerSource, l *Ledger) (int, error)`,
      unexported.
  - metrics:
    - `Metrics.StoreFeedUp *prometheus.GaugeVec` (`port49_store_feed_up{feed}`);
    - `Metrics.StoreFeedRescans *prometheus.CounterVec` (`port49_store_feed_rescans_total{feed}`).
  - `stores` gains `follow func(ctx context.Context)`, run by `runOnce` and joined before
    `sts.close`.

Ruling 3's "every process follows the store's contexts":
- **The scan.** `ScanContexts` reads the context family at one revision, paged with `WithRev`
  pinned to the first page's, so the scan and the watch meet with no gap.
- **The watch.** `WatchContexts` watches from the next revision.
- **What the crypt side does with them.** It opens each record with the keys, raises its key's
  mark, and never admits anything: admission is `GetContext`'s alone.
- **No entry from below the base** (pre-flight I1).
  - Without `ObserveFollowed`, a store writer's put-back at a key absent from the record and
    from the start's scan was denied before the feed brought it, by the base. Once the feed
    brought it, `entry(k)` made `hw = seq_old`, and it was admitted.
  - Now the feed only raises entries that exist, and makes one only at or above the base.
  - The same holds for a compacted watch's rescan and a re-entry's scan.
- **A rescan seeds from the ledger record first** (re-check R1). The scan sees each key's latest
  record. A login another process made while this watch was down, and a put-back over it in the
  same gap, leave only the put-back to scan, so the scan raises nothing at the key. The ledger
  record holds the login's mark if the runner's feed saw it, so `rescan` reads it first. This
  task's port49d passes `nil`, since the record is Task 10's; Task 10 passes the daemon's store.

- [ ] **Step 1: The failing tests, the feed.** Create `internal/store/etcd/feed_test.go`:

  ```go
  package etcd

  import (
  	"context"
  	"errors"
  	"sync"
  	"testing"
  	"time"

  	"github.com/rhwendt/port49/internal/store"
  	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
  )

  // A scan reads every live context at one revision; a watch from it brings
  // every change after, a delete included, in revision order, with Seen
  // raised by each.
  func TestTheScanAndTheWatchMeetWithNoGap(t *testing.T) {
  	ctx := context.Background()
  	s := onShared(t, time.Now)
  	k1 := store.ContextKey{NAS: "leaf/01", Username: "al%ce"} // escaping
  	k2 := store.ContextKey{NAS: "leaf-02", Username: "bob"}
  	put := func(k store.ContextKey, id string) {
  		if err := s.PutContext(ctx, k, store.Context{CtxID: id, Principal: "user:x", Username: k.Username}, time.Hour); err != nil {
  			t.Fatal(err)
  		}
  	}
  	put(k1, "c1")
  	var got []store.ContextKey
  	rev, err := s.ScanContexts(ctx, func(k store.ContextKey, c store.Context) { got = append(got, k) })
  	if err != nil || len(got) != 1 || got[0] != k1 {
  		t.Fatalf("scan: %v %v", got, err)
  	}
  	put(k2, "c2")
  	if err := s.DeleteContext(ctx, k1); err != nil {
  		t.Fatal(err)
  	}
  	wctx, cancel := context.WithCancel(ctx)
  	var mu sync.Mutex
  	var changes []store.ContextChange
  	done := make(chan error, 1)
  	go func() {
  		done <- s.WatchContexts(wctx, rev, func(c store.ContextChange) {
  			mu.Lock()
  			changes = append(changes, c)
  			n := len(changes)
  			mu.Unlock()
  			if n == 2 {
  				cancel()
  			}
  		}, func(uint64) {}, nil)
  	}()
  	select {
  	case err := <-done:
  		if !errors.Is(err, context.Canceled) {
  			t.Fatal(err)
  		}
  	case <-time.After(10 * time.Second):
  		t.Fatal("the watch brought nothing")
  	}
  	if changes[0].Key != k2 || changes[0].Deleted || changes[1].Key != k1 || !changes[1].Deleted ||
  		changes[0].Rev >= changes[1].Rev || s.Seen() < changes[1].Rev {
  		t.Fatalf("changes %+v, Seen %d", changes, s.Seen())
  	}
  }

  // A watch from a compacted revision is store.ErrCompacted, never a silent
  // gap. On a member of its own: compacting the shared member would cut the
  // history every other test in the package reads with WithRev (pre-flight
  // M17).
  func TestAWatchFromACompactedRevisionSaysSo(t *testing.T) {
  	ctx := context.Background()
  	srv := etcdtest.Start(t, etcdtest.Options{})
  	s, err := Open(Config{Endpoints: []string{srv.Endpoint}, Prefix: "/port49/", Now: time.Now})
  	if err != nil {
  		t.Fatal(err)
  	}
  	t.Cleanup(func() { s.Close() })
  	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
  	s.PutContext(ctx, k, store.Context{CtxID: "c1", Principal: "user:x", Username: "alice"}, time.Hour)
  	rev, _ := s.ScanContexts(ctx, func(store.ContextKey, store.Context) {})
  	s.PutContext(ctx, k, store.Context{CtxID: "c2", Principal: "user:x", Username: "alice"}, time.Hour)
  	resp, err := s.ctx.Get(ctx, "compact-me")
  	if err != nil {
  		t.Fatal(err)
  	}
  	if _, err := s.ctx.Compact(ctx, resp.Header.Revision); err != nil {
  		t.Fatal(err)
  	}
  	err = s.WatchContexts(ctx, rev, func(store.ContextChange) {}, func(uint64) {}, nil)
  	if !errors.Is(err, store.ErrCompacted) {
  		t.Fatalf("%v", err)
  	}
  }

  // A progress request is answered: with no change to deliver, progress is
  // told a revision at least the store's, so a reader waiting on the feed is
  // let through an idle family (Task 8a's fence). And an event is delivered
  // before any progress at or above its revision, a request sent the moment
  // after the write included: the fence rests on that order, which etcd
  // fixed in #15220 (3.4.24, 3.5.8, every 3.6; re-check R2).
  func TestAWatchAnswersAProgressRequest(t *testing.T) {
  	ctx, cancel := context.WithCancel(context.Background())
  	defer cancel()
  	s := onShared(t, time.Now)
  	rev, _ := s.ScanContexts(ctx, func(store.ContextKey, store.Context) {})
  	other, err := s.ctx.Put(ctx, etcdtest.Prefix()+"elsewhere", "x") // a revision outside c/
  	if err != nil {
  		t.Fatal(err)
  	}
  	type told struct{ at, delivered uint64 }
  	var mu sync.Mutex
  	var delivered uint64 // the highest event fn has been given
  	var tolds []told     // each progress, with what had been delivered when it was told
  	asks := make(chan struct{}, 1)
  	got := make(chan uint64, 64)
  	go s.WatchContexts(ctx, rev, func(c store.ContextChange) {
  		mu.Lock()
  		delivered = max(delivered, c.Rev)
  		mu.Unlock()
  	}, func(r uint64) {
  		mu.Lock()
  		tolds = append(tolds, told{at: r, delivered: delivered})
  		mu.Unlock()
  		select {
  		case got <- r:
  		default:
  		}
  	}, asks)
  	ask := func() {
  		select {
  		case asks <- struct{}{}:
  		default:
  		}
  	}
  	waitPast := func(want uint64, why string) {
  		deadline := time.After(10 * time.Second)
  		for {
  			ask()
  			select {
  			case r := <-got:
  				if r >= want {
  					return
  				}
  			case <-time.After(100 * time.Millisecond):
  			case <-deadline:
  				t.Fatal(why)
  			}
  		}
  	}
  	waitPast(uint64(other.Header.Revision), "no progress past a revision outside the family was told")
  	put, err := s.PutContextRev(ctx, store.ContextKey{NAS: "leaf-01", Username: "alice"},
  		store.Context{CtxID: "c1", Principal: "user:x", Username: "alice"}, time.Hour)
  	if err != nil {
  		t.Fatal(err)
  	}
  	ask() // at once: an etcd without #15220 could answer it ahead of the event
  	waitPast(put, "the write was never followed")
  	mu.Lock()
  	defer mu.Unlock()
  	for _, x := range tolds {
  		if x.at >= put && x.delivered < put {
  			t.Fatalf("progress told %d before the event at %d was delivered (etcd #15220: needs 3.4.24, 3.5.8 or 3.6)",
  				x.at, put)
  		}
  	}
  }
  ```

  The order half can fail: with `WatchContexts` telling a batch's revision to `progress` before
  it calls `fn` for the batch's events, it does. On the pinned etcd (v3.6.15) it holds.

  A store opened by `Open` on a plain member is the one `roles_test.go`'s `openAs` opens,
  without TLS. If `Config` requires TLS at `b508ba0`, use `etcdtest.Start(t,
  etcdtest.Options{TLS: true})` and `openAs(t, srv, "root", "/port49/")`. Either way the member
  is the test's own.

- [ ] **Step 2: The failing tests, the crypt side.** Create `internal/store/crypt/follow_test.go`:

  ```go
  package crypt

  import (
  	"context"
  	"errors"
  	"sync"
  	"testing"
  	"time"

  	"github.com/rhwendt/port49/internal/store"
  	"github.com/rhwendt/port49/internal/store/memory"
  )

  // feedOf is a ContextFeed over a memory store for these tests: a scan of
  // what the test planted, and a watch that delivers what the test sends.
  type feedOf struct {
  	mu      sync.Mutex
  	scanned map[store.ContextKey]store.Context
  	rev     uint64
  	changes chan store.ContextChange
  	compact chan struct{}
  }

  func (f *feedOf) ScanContexts(_ context.Context, fn func(store.ContextKey, store.Context)) (uint64, error) {
  	f.mu.Lock()
  	defer f.mu.Unlock()
  	for k, c := range f.scanned {
  		fn(k, c)
  	}
  	return f.rev, nil
  }

  func (f *feedOf) WatchContexts(ctx context.Context, _ uint64, fn func(store.ContextChange),
  	progress func(uint64), _ <-chan struct{}) error {
  	for {
  		select {
  		case <-ctx.Done():
  			return ctx.Err()
  		case c := <-f.changes:
  			fn(c)
  			progress(c.Rev)
  		case <-f.compact:
  			return store.ErrCompacted
  		}
  	}
  }

  // setScanned replaces what the next scan finds, under the feed's lock: a
  // rescan runs on FollowContexts's goroutine (pre-flight M4, the race).
  func (f *feedOf) setScanned(m map[store.ContextKey]store.Context, rev uint64) {
  	f.mu.Lock()
  	defer f.mu.Unlock()
  	f.scanned, f.rev = m, rev
  }

  type marksOf []store.LedgerMark

  func (m marksOf) LedgerMarks(context.Context) (uint64, []store.LedgerMark, error) { return 1, m, nil }

  // A process's feed brings another process's later write: the mark rises,
  // so a record put back below it is denied even if this process never
  // read the later one (Review Focus 2; Ruling 3).
  func TestTheFeedRaisesTheHighWaterSoAPutBackIsDenied(t *testing.T) {
  	inner, a, _, _, lb := twoProcesses(t)
  	login(t, a, "ctx-alice", "user:alice")
  	saved, _ := inner.GetContext(context.Background(), ka)
  	b := Wrap(inner, keys(), nil, WithLedger(lb))
  	if _, err := b.GetContext(context.Background(), ka); err != nil {
  		t.Fatal(err) // b knows alice's
  	}
  	login(t, a, "ctx-bob", "user:bob")
  	later, _ := inner.GetContext(context.Background(), ka)
  	feed := &feedOf{changes: make(chan store.ContextChange, 1), compact: make(chan struct{})}
  	ctx, cancel := context.WithCancel(context.Background())
  	defer cancel()
  	go FollowContexts(ctx, feed, nil, keys(), lb, 0, func(bool) {}, func() {}, t.Logf)
  	feed.changes <- store.ContextChange{Key: ka, Context: later, Rev: later.Rev}
  	eventually(t, func() bool { return lb.next(ka) > 0 && !lb.admits(ka, seqOf(t, saved)) })
  	inner.PutContext(context.Background(), ka, saved, time.Hour)
  	if _, err := b.GetContext(context.Background(), ka); !errors.Is(err, ErrNotLastWritten) {
  		t.Fatalf("a put-back below a mark the feed raised was admitted: %v", err)
  	}
  }

  // A start's ledger: the record's marks first, then the scan; a scanned
  // record below its key's recorded mark is a put-back and raises nothing;
  // the base is just past the scan (Ruling 4).
  func TestLoadLedgerTakesTheRecordOverAPutBack(t *testing.T) {
  	inner, a, _, _, _ := twoProcesses(t)
  	login(t, a, "ctx-alice", "user:alice")
  	saved, _ := inner.GetContext(context.Background(), ka)
  	login(t, a, "ctx-bob", "user:bob")
  	later, _ := inner.GetContext(context.Background(), ka)
  	feed := &feedOf{scanned: map[store.ContextKey]store.Context{ka: saved}, rev: inner.Seen()}
  	l := NewLedger()
  	rev, known, recorded, err := LoadLedger(context.Background(), feed, marksOf{{Key: ka, Seq: seqOf(t, later)}}, keys(), l)
  	if err != nil || rev != feed.rev || known != 1 || recorded != 1 || l.Base() != rev+1 {
  		t.Fatalf("rev %d known %d recorded %d base %d: %v", rev, known, recorded, l.Base(), err)
  	}
  	if l.admits(ka, seqOf(t, saved)) {
  		t.Fatal("a scanned record below the recorded mark was admitted")
  	}
  }

  // A compacted watch scans again, counts the rescan, and goes on. The rescan
  // raises a mark below a record it finds, never lowers one above it, and
  // makes an entry only for a record at or above the base: nothing the
  // earlier scan would have denied is admitted (pre-flight M4: each half can
  // fail; I1).
  func TestACompactedFeedScansAgainAndOnlyRaises(t *testing.T) {
  	kb := store.ContextKey{NAS: "leaf-02", Username: "bob"}
  	kc := store.ContextKey{NAS: "leaf-03", Username: "carol"}
  	kd := store.ContextKey{NAS: "leaf-04", Username: "dave"}
  	l := NewLedger()
  	l.SetBase(150)
  	l.Observe(ka, 100, 100, time.Time{}, time.Time{})
  	l.Observe(kb, 10, 10, time.Time{}, time.Time{})
  	feed := &feedOf{changes: make(chan store.ContextChange), compact: make(chan struct{}, 1)}
  	feed.setScanned(map[store.ContextKey]store.Context{
  		ka: sealedAt(t, ka, 50),  // below ka's mark: must not lower it
  		kb: sealedAt(t, kb, 300), // above kb's mark: must raise it
  		kc: sealedAt(t, kc, 60),  // unseen, below the base: a put-back, no entry
  		kd: sealedAt(t, kd, 400), // unseen, above the base: an entry
  	}, 500)
  	feed.compact <- struct{}{}
  	var rescans atomic.Int32
  	ctx, cancel := context.WithCancel(context.Background())
  	go func() { eventually(t, func() bool { return rescans.Load() > 0 && l.next(kd) == 401 }); cancel() }()
  	FollowContexts(ctx, feed, nil, keys(), l, 150, func(bool) {}, func() { rescans.Add(1) }, t.Logf)
  	if l.next(ka) != 101 {
  		t.Fatalf("a rescan lowered the mark: next %d", l.next(ka))
  	}
  	if l.next(kb) != 301 {
  		t.Fatalf("a rescan did not raise the mark: next %d", l.next(kb))
  	}
  	if l.admits(kc, 60) {
  		t.Fatal("a rescan made an entry from a record below the base")
  	}
  }

  // A put-back at a key this process never saw, brought by the feed, makes
  // no entry: the read still judges it against the base, and denies it
  // (pre-flight I1). Before ObserveFollowed, the event made hw = its own
  // sequence and the read admitted it.
  func TestAFedPutBackAtAnUnseenKeyIsDenied(t *testing.T) {
  	inner, a, _, _, _ := twoProcesses(t)
  	login(t, a, "ctx-alice", "user:alice")
  	saved, _ := inner.GetContext(context.Background(), ka)
  	if err := inner.DeleteContext(context.Background(), ka); err != nil {
  		t.Fatal(err)
  	}
  	late := NewLedger()
  	late.SetBase(inner.Seen() + 1) // started after the delete: ka is not in its scan
  	c := Wrap(inner, keys(), nil, WithLedger(late))
  	if err := inner.PutContext(context.Background(), ka, saved, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	back, _ := inner.GetContext(context.Background(), ka)
  	feed := &feedOf{changes: make(chan store.ContextChange, 1), compact: make(chan struct{})}
  	ctx, cancel := context.WithCancel(context.Background())
  	defer cancel()
  	delivered := make(chan struct{})
  	go FollowContexts(ctx, &tapFeed{feedOf: feed, after: func() { close(delivered) }}, nil, keys(), late,
  		late.Base()-1, func(bool) {}, func() {}, t.Logf)
  	feed.changes <- store.ContextChange{Key: ka, Context: back, Rev: back.Rev}
  	<-delivered
  	if _, err := c.GetContext(context.Background(), ka); !errors.Is(err, ErrNotLastWritten) {
  		t.Fatalf("a put-back the feed brought at an unseen key was admitted: %v", err)
  	}
  }

  // A compacted watch seeds from the ledger record before it scans again
  // (re-check R1). b knows alice's record; while b's watch is down, a logs
  // bob in and a store writer puts alice's back over it. The rescan sees
  // only alice's, so without the seed it raises nothing, and alice's is
  // admitted at b's high-water. The record holds bob's mark, and it is
  // denied.
  func TestACompactedRescanSeedsFromTheLedgerRecord(t *testing.T) {
  	inner, a, _, _, lb := twoProcesses(t)
  	login(t, a, "ctx-alice", "user:alice")
  	alice, _ := inner.GetContext(context.Background(), ka)
  	b := Wrap(inner, keys(), nil, WithLedger(lb))
  	if _, err := b.GetContext(context.Background(), ka); err != nil {
  		t.Fatal(err) // b's high-water at ka is alice's
  	}
  	login(t, a, "ctx-bob", "user:bob") // in the gap: b's watch delivers nothing
  	bob, _ := inner.GetContext(context.Background(), ka)
  	if err := inner.PutContext(context.Background(), ka, alice, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	back, _ := inner.GetContext(context.Background(), ka)
  	feed := &feedOf{changes: make(chan store.ContextChange), compact: make(chan struct{}, 1)}
  	feed.setScanned(map[store.ContextKey]store.Context{ka: back}, inner.Seen())
  	feed.compact <- struct{}{}
  	ctx, cancel := context.WithCancel(context.Background())
  	defer cancel()
  	go FollowContexts(ctx, feed, marksOf{{Key: ka, Seq: seqOf(t, bob)}}, keys(), lb, 0,
  		func(bool) {}, func() {}, t.Logf)
  	eventually(t, func() bool { return lb.next(ka) > seqOf(t, bob) })
  	if _, err := b.GetContext(context.Background(), ka); !errors.Is(err, ErrNotLastWritten) {
  		t.Fatalf("a put-back over a later login only the ledger record held was admitted after a rescan: %v", err)
  	}
  }

  // tapFeed is feedOf that calls after once its first change is delivered.
  type tapFeed struct {
  	*feedOf
  	after func()
  	once  sync.Once
  }

  func (f *tapFeed) WatchContexts(ctx context.Context, from uint64, fn func(store.ContextChange),
  	progress func(uint64), asks <-chan struct{}) error {
  	return f.feedOf.WatchContexts(ctx, from, func(c store.ContextChange) { fn(c); f.once.Do(f.after) }, progress, asks)
  }
  ```

  `eventually`, `seqOf` (opens a sealed record with `keys()` and returns its sequence) and
  `sealedAt` (seals a context at a given sequence with the test keys) are test helpers. Write
  them in `follow_test.go`; add `"sync/atomic"` to its imports.

- [ ] **Step 3: Run them to see them fail.**

  Run: `go test ./internal/store/etcd/ ./internal/store/crypt/ -run 'Scan|Watch|Feed|LoadLedger|Compacted|UnseenKey' -count=1`
  Expected: FAIL to compile. With `ObserveFollowed` stubbed as `Observe`,
  `TestAFedPutBackAtAnUnseenKeyIsDenied` and the base half of
  `TestACompactedFeedScansAgainAndOnlyRaises` fail. With `rescan`'s `seedFrom` left out,
  `TestACompactedRescanSeedsFromTheLedgerRecord` fails waiting for the mark (`eventually`), and
  its read is admitted.

- [ ] **Step 4: The store's types.** In `store.go`:

  ```go
  // ContextChange is one change to the context family, as a feed brings it
  // (plan 7e, Ruling 3): the record as GetContext's backend returns it
  // (sealed under crypt), or Deleted, at revision Rev.
  type ContextChange struct {
  	Key     ContextKey
  	Context Context
  	Deleted bool
  	Rev     uint64
  }

  // ContextFeed is a backend's context family as a stream: a scan at one
  // revision, then every change after it. A watch never admits a record;
  // what follows it only raises what a read must clear.
  type ContextFeed interface {
  	// ScanContexts calls fn for every live context at one revision, which
  	// it returns.
  	ScanContexts(ctx context.Context, fn func(ContextKey, Context)) (uint64, error)
  	// WatchContexts calls fn for every change after `after`, in revision
  	// order, until ctx ends (ctx.Err()), the revision was compacted
  	// (ErrCompacted), or the watch fails (ErrUnavailable). progress is told
  	// a revision through which every change has been delivered: each
  	// batch's highest event once fn has had them all, and each progress
  	// notification's header revision. Each receive on asks requests one
  	// such notification from the store; a nil asks requests none (plan 7e,
  	// the feed fence).
  	WatchContexts(ctx context.Context, after uint64, fn func(ContextChange), progress func(rev uint64),
  		asks <-chan struct{}) error
  }

  // ErrCompacted is a feed asked for revisions the store no longer keeps: the
  // follower scans again.
  var ErrCompacted = errors.New("store: the feed's revision was compacted")

  // LedgerSource reads the ledger record at one revision (plan 7e, Ruling 4).
  type LedgerSource interface {
  	LedgerMarks(ctx context.Context) (uint64, []LedgerMark, error)
  }

  // LedgerSink raises the ledger record's marks, never lowering one.
  type LedgerSink interface {
  	PutLedgerMarks(ctx context.Context, ms []LedgerMark) error
  }
  ```

- [ ] **Step 5: etcd's feed.** Create `internal/store/etcd/feed.go`:

  ```go
  package etcd

  import (
  	"context"
  	"encoding/json"
  	"errors"
  	"fmt"

  	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
  	clientv3 "go.etcd.io/etcd/client/v3"

  	"github.com/rhwendt/port49/internal/store"
  )

  // contextKeyOf is the ContextKey of a c/ key, false for one that does not
  // parse.
  func (s *Store) contextKeyOf(key string) (store.ContextKey, bool) {
  	nas, user, ok := lastTwo(key)
  	return store.ContextKey{NAS: nas, Username: user}, ok && s.k.context(store.ContextKey{NAS: nas, Username: user}) == key
  }

  // ScanContexts calls fn for every live context at one revision, read a
  // page at a time on the context client, every page at the first page's
  // revision, and returns it (store.ContextFeed). A key that does not parse,
  // or a record that does not decode, is said by its key alone and skipped:
  // it raises nothing, and a read of it is unreadable anyway.
  func (s *Store) ScanContexts(ctx context.Context, fn func(store.ContextKey, store.Context)) (uint64, error) {
  	prefix := s.k.family(famContext)
  	end := clientv3.GetPrefixRangeEnd(prefix)
  	from, rev := prefix, int64(0)
  	now := s.now()
  	for {
  		opts := []clientv3.OpOption{clientv3.WithRange(end), clientv3.WithLimit(500)}
  		if rev > 0 {
  			opts = append(opts, clientv3.WithRev(rev))
  		}
  		resp, err := s.ctx.Get(ctx, from, opts...)
  		if errors.Is(err, rpctypes.ErrCompacted) {
  			return 0, store.ErrCompacted
  		}
  		if err != nil {
  			return 0, unavailable(err)
  		}
  		s.saw(resp.Header.Revision)
  		if rev == 0 {
  			rev = resp.Header.Revision
  		}
  		for _, kv := range resp.Kvs {
  			k, ok := s.contextKeyOf(string(kv.Key))
  			if !ok {
  				s.unparseable("context key", kv.Key, "skipped by the scan")
  				continue
  			}
  			var r ctxRec
  			if json.Unmarshal(kv.Value, &r) != nil {
  				s.logf("etcd: the context at %q does not decode; the scan skipped it", kv.Key)
  				continue
  			}
  			if r.ExpiresAt.After(now) {
  				fn(k, r.context(kv.ModRevision))
  			}
  		}
  		if !resp.More || len(resp.Kvs) == 0 {
  			return uint64(rev), nil
  		}
  		from = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
  	}
  }

  // WatchContexts calls fn for every change to the context family after
  // `after` (store.ContextFeed), on the context client, requiring a leader so
  // a member cut off from its quorum ends the watch rather than going quiet.
  // A request on asks is sent with RequestProgress on the watch's own
  // context, which names its stream: etcd answers it with a progress
  // notification once the stream's watchers are synced, and that header
  // revision is told to progress. An event batch tells progress its highest
  // event's revision, never the batch header's, which a catching-up watcher
  // may send ahead of what it has delivered.
  func (s *Store) WatchContexts(ctx context.Context, after uint64, fn func(store.ContextChange),
  	progress func(uint64), asks <-chan struct{}) error {
  	wctx, cancel := context.WithCancel(clientv3.WithRequireLeader(ctx))
  	defer cancel()
  	ch := s.ctx.Watch(wctx, s.k.family(famContext), clientv3.WithPrefix(), clientv3.WithRev(int64(after)+1))
  	for {
  		var resp clientv3.WatchResponse
  		var ok bool
  		select {
  		case <-asks: // nil: never ready
  			if err := s.ctx.RequestProgress(wctx); err != nil && ctx.Err() == nil {
  				s.logf("etcd: asking the context watch for its progress: %v", err)
  			}
  			continue
  		case resp, ok = <-ch:
  		}
  		if !ok {
  			break
  		}
  		if err := resp.Err(); err != nil {
  			if resp.CompactRevision > 0 || errors.Is(err, rpctypes.ErrCompacted) {
  				return store.ErrCompacted
  			}
  			return unavailable(err)
  		}
  		if resp.IsProgressNotify() {
  			s.saw(resp.Header.Revision)
  			progress(uint64(resp.Header.Revision))
  			continue
  		}
  		var top int64
  		for _, ev := range resp.Events {
  			top = max(top, ev.Kv.ModRevision)
  			s.saw(ev.Kv.ModRevision)
  			k, ok := s.contextKeyOf(string(ev.Kv.Key))
  			if !ok {
  				continue
  			}
  			c := store.ContextChange{Key: k, Rev: uint64(ev.Kv.ModRevision)}
  			if ev.Type == clientv3.EventTypeDelete {
  				c.Deleted = true
  				fn(c)
  				continue
  			}
  			var r ctxRec
  			if json.Unmarshal(ev.Kv.Value, &r) != nil {
  				s.logf("etcd: a change to the context at %q does not decode; the feed skipped it", ev.Kv.Key)
  				continue
  			}
  			c.Context = r.context(ev.Kv.ModRevision)
  			fn(c)
  		}
  		if top > 0 {
  			progress(uint64(top))
  		}
  	}
  	if ctx.Err() != nil {
  		return ctx.Err()
  	}
  	return fmt.Errorf("%w: the context watch ended", store.ErrUnavailable)
  }
  ```

  The `if !ok { break }` sits after the `select`, so it leaves the `for`; keep it there. A
  skipped undecodable event still counts toward `top`: its revision was delivered, and nothing
  at it can be admitted, since a read of it does not open.

  Check `s.unparseable`'s signature at `b508ba0` (`indexes.go:525`) and pass what it takes.

- [ ] **Step 6: The crypt side.** Create `internal/store/crypt/follow.go`:

  ```go
  package crypt

  import (
  	"context"
  	"errors"
  	"time"

  	"github.com/rhwendt/port49/internal/store"
  )

  // LoadLedger seeds l at a start (plan 7e, Rulings 3, 4): every mark the
  // ledger record holds (src; nil reads none), then every live context at one
  // revision, each opened with keys to read its sequence. A scanned record
  // below its key's recorded mark is a put-back and raises nothing; one that
  // will not open is skipped, since a read of it is unreadable anyway. It
  // sets the base just past the scan's revision and returns that revision,
  // how many keys l knows, and how many came from the record.
  //
  // A ledger loaded before (a re-entry after a store gone keeps it) is
  // scanned as the feed is followed: a record at a key it has no mark for
  // makes one only at or above the base it had, so a put-back made while the
  // store was away is not taken as its key's (pre-flight I1). Only then is
  // the base raised.
  func LoadLedger(ctx context.Context, feed store.ContextFeed, src store.LedgerSource, keys Keys,
  	l *Ledger) (rev uint64, known, recorded int, err error) {
  	if recorded, err = seedFrom(ctx, src, l); err != nil {
  		return 0, 0, 0, err
  	}
  	first := l.Base() == 0
  	rev, err = feed.ScanContexts(ctx, func(k store.ContextKey, c store.Context) { observe(l, keys, k, c, first) })
  	if err != nil {
  		return 0, 0, 0, err
  	}
  	l.SetBase(rev + 1)
  	return rev, l.Len(), recorded, nil
  }

  // observe raises k's mark from c, sealed, if it opens: making a mark for
  // any record at a first start's scan, and as ObserveFollowed otherwise.
  func observe(l *Ledger, keys Keys, k store.ContextKey, c store.Context, first bool) {
  	oc, seq, err := openContextWith(keys, k, c)
  	if err != nil {
  		return
  	}
  	if first {
  		l.Observe(k, seq, c.Rev, c.RevokedAt, oc.SessionExpires)
  		return
  	}
  	l.ObserveFollowed(k, seq, c.Rev, c.RevokedAt, oc.SessionExpires)
  }

  // seedFrom raises l from every mark the ledger record holds (src; nil reads
  // none), and returns how many it read.
  func seedFrom(ctx context.Context, src store.LedgerSource, l *Ledger) (int, error) {
  	if src == nil {
  		return 0, nil
  	}
  	_, ms, err := src.LedgerMarks(ctx)
  	if err != nil {
  		return 0, err
  	}
  	for _, m := range ms {
  		l.Seed(m)
  	}
  	return len(ms), nil
  }

  // rescan is a compacted watch's catch-up (re-check R1): the ledger
  // record's marks first, as a start seeds them, then every live context,
  // raising only. A scan sees each key's latest record, not the writes in
  // between: a later login a put-back hid while the watch was down is in
  // the record, when the runner's feed saw it, and nowhere in the scan.
  func rescan(ctx context.Context, feed store.ContextFeed, src store.LedgerSource, keys Keys,
  	l *Ledger) (uint64, error) {
  	if _, err := seedFrom(ctx, src, l); err != nil {
  		return 0, err
  	}
  	return feed.ScanContexts(ctx, func(k store.ContextKey, c store.Context) { observe(l, keys, k, c, false) })
  }

  // FollowContexts keeps l current from feed after `from` until ctx ends,
  // and returns ctx's error then (plan 7e, Ruling 3). Each change raises its
  // key's mark and never lowers one; a delete changes nothing. A compacted
  // watch seeds from src and scans again (rescan), raising only, tells
  // rescanned, and goes on from the scan's revision; a rescan that fails is
  // a watch that failed. A watch that fails is tried again every second. up
  // is told whether the watch is running
  // (port49_store_feed_up{feed="contexts"}), and logf says each rescan and
  // each failure once per run of them.
  func FollowContexts(ctx context.Context, feed store.ContextFeed, src store.LedgerSource, keys Keys,
  	l *Ledger, from uint64, up func(bool), rescanned func(), logf func(string, ...any)) error {
  	failing := false
  	for {
  		up(true)
  		err := feed.WatchContexts(ctx, from, func(c store.ContextChange) {
  			if c.Rev > from {
  				from = c.Rev
  			}
  			if !c.Deleted {
  				observe(l, keys, c.Key, c.Context, false)
  			}
  		}, func(uint64) {}, nil) // Task 8a: the fence's progress and asks
  		up(false)
  		if ctx.Err() != nil {
  			return ctx.Err()
  		}
  		if errors.Is(err, store.ErrCompacted) {
  			logf("store: the context feed's revision was compacted; seeding from the ledger record and scanning " +
  				"the store again")
  			rescanned()
  			if rev, serr := rescan(ctx, feed, src, keys, l); serr == nil {
  				from = rev
  				failing = false
  				continue
  			} else {
  				err = serr
  			}
  		}
  		if !failing {
  			logf("store: the context feed stopped (%v); trying again every second", err)
  			failing = true
  		}
  		select {
  		case <-ctx.Done():
  			return ctx.Err()
  		case <-time.After(time.Second):
  		}
  	}
  }
  ```

  In `ledger.go`, beside `Observe`:

  ```go
  // ObserveFollowed is Observe for a record the context feed, a rescan, or a
  // later start's scan brought (pre-flight I1): it raises a mark the ledger
  // holds, and makes one only for a record sealed at or above the base. A
  // record below the base at a key with no mark is what a put-back looks
  // like; made the key's mark, a read would admit it.
  func (l *Ledger) ObserveFollowed(k store.ContextKey, seq, rev uint64, plainRevokedAt, ceiling time.Time) {
  	l.mu.Lock()
  	defer l.mu.Unlock()
  	if e, ok := l.m[k]; (!ok || e.hw == 0) && seq < l.base {
  		return
  	}
  	l.observe(k, seq, rev, plainRevokedAt, ceiling)
  }
  ```

  An entry that holds only a floor (`hw == 0`, `revoked` before any sequence) counts as no
  mark here. The floor stays, and the record below the base makes no mark.

- [ ] **Step 7: The metrics.** In `metrics.go`, add, beside the store guard's series:

  ```go
  	// StoreFeedUp is 1 while a feed's watch runs (plan 7e): feed is
  	// "contexts" or "marks". 0 for longer than hold_ttl is an alarm: this
  	// process's ledger or marks are not following the store.
  	StoreFeedUp *prometheus.GaugeVec
  	// StoreFeedRescans counts a feed's rescans after a compacted watch.
  	StoreFeedRescans *prometheus.CounterVec
  ```

  Register `port49_store_feed_up{feed}` and `port49_store_feed_rescans_total{feed}`, and add
  both names to `TestNewRegistersEveryMetric`.

- [ ] **Step 8: port49d follows.** In `cmd/port49d/store.go`, `openStores`'s etcd branch, after
  `checkSealKeys` succeeds and before it returns, seed the ledger from the daemon's raw store and
  start nothing yet:

  ```go
  	rev, known, recorded, err := crypt.LoadLedger(ctx, d, nil, keys, ledger) // the record: Task 10
  	// (retry while unavailable, with the listeners closed, as checkSealKeys's loop does)
  	fmt.Fprintf(out, "port49d: ledger: %d context key(s) known (%d from the ledger record); following the store "+
  		"from revision %d\n", known, recorded, rev)
  ```

  Then return `stores{…, follow: func(ctx context.Context) { crypt.FollowContexts(ctx, d, nil,
  keys, ledger, rev, …) }}` (the record, `src`, is Task 10's) with:
  - `up` setting `m.StoreFeedUp.WithLabelValues("contexts")`;
  - `rescanned` incrementing `m.StoreFeedRescans.WithLabelValues("contexts")`;
  - `logf` printing `port49d: ` + the line.

  Put the retry around `LoadLedger` in the shape of the `checkSealKeys` loop beside it: an
  outage is said and tried every 5s, and a lost hold ends the start as a store gone.
  - In `runOnce`, start `sts.follow` on a goroutine **immediately after `openStores` returns**,
    before anything reads a context, the start's reads (`startOnPersistentStore`) included.
    Task 8a's fence holds every context read until the feed has delivered through the record's
    revision, so a feed started later would stall the start for a call timeout per read.
  - Join it before `sts.close`, as the sweep is (`sweepDone`).
  - Remove the interim `ledger.SetBase(e.Seen() + 1)` Task 7 put in `startOnPersistentStore`:
    the base is the scan's now, set before the start's reads.

- [ ] **Step 9: Run everything.**

  Run: `go test ./internal/store/... ./internal/daemon/metrics/ ./cmd/port49d/ -count=1`
  Expected: PASS. The port49d e2e tests pass. `TestAStartSealsTheLedgerOnceItHasReadTheStore`
  holds through the base. The log names the ledger line.

- [ ] **Step 10: Commit.**

  ```bash
  gofmt -w internal/store internal/daemon/metrics cmd/port49d
  make build && make test && make vet
  git add internal/store/store.go internal/store/etcd/feed.go internal/store/etcd/feed_test.go \
    internal/store/crypt/follow.go internal/store/crypt/follow_test.go internal/store/crypt/ledger.go \
    internal/daemon/metrics/metrics.go internal/daemon/metrics/metrics_test.go cmd/port49d/store.go \
    cmd/port49d/main.go
  git commit -m "feat(store): every process follows the store's contexts

  A scan at one revision, then a watch from it, raise each key's mark in
  the ledger and never lower one; a compacted watch seeds from the ledger
  record and scans again, since a scan alone misses a login a put-back
  hid in the gap (re-check R1). The feed and a later scan make no mark
  from a record below the base, so a put-back at a key this process never
  saw stays denied (pre-flight I1). The start's base is the scan's
  revision, before any read. The watch reports its progress, after the
  events it covers, and answers progress requests, for Task 8a's fence
  (re-check R2). port49_store_feed_up and port49_store_feed_rescans_total
  say whether it follows (plan 7e Ruling 3).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 8a: No context read is judged before the feed has passed it

**Files:**
- Create: `internal/store/crypt/fence.go`, `internal/store/crypt/fence_test.go`
- Modify: `internal/store/crypt/ledger.go` (the ledger owns a `*Fence`; `knownAt`),
  `internal/store/crypt/follow.go` (`LoadLedger` attaches the fence; `FollowContexts` moves it)
- Modify: `cmd/port49d/store.go` (`openStores`: each raw store fenced under its guard)

**Interfaces:**
- Consumes: `store.ContextFeed.WatchContexts`'s `progress` and `asks` (Task 8),
  `store.RevStore.Seen` and `Ping` (Task 6), `Ledger.ObserveFollowed` (Task 8).
- Produces (`crypt`):
  - `var ErrFeedBehind = fmt.Errorf("%w: this process's context feed has not delivered the record's revision", store.ErrUnavailable)`.
  - `type Fence struct` with:
    - `func (f *Fence) Attach(at uint64)`: a feed follows from `at`, and from now on a read
      waits for it;
    - `func (f *Fence) Followed(rev uint64)`: every change through `rev` is delivered. It only
      rises, and wakes every waiter;
    - `func (f *Fence) SetUp(up bool)` and `func (f *Fence) Up() bool`: whether the feed's
      watch runs (Task 10's `port49_ledger_behind`);
    - `func (f *Fence) At() uint64`;
    - `func (f *Fence) Asks() <-chan struct{}`: requests for a progress notification, buffered
      one;
    - `func (f *Fence) Wait(ctx context.Context, rev uint64) error`. It returns nil at once
      when no feed is attached or the feed is at or past `rev`. Otherwise it asks, and waits
      until it is, asking again after each wake that leaves it behind. When `ctx` ends first it
      returns `ErrFeedBehind`.
  - `func (l *Ledger) Fence() *Fence`, built by `NewLedger`.
  - `func (l *Ledger) knownAt(k store.ContextKey, rev uint64) bool`: `rev` is the revision of
    the record this process last knew at `k`, its own landed write or a record it admitted.
  - `func Fenced(inner store.RevStore, l *Ledger) store.RevStore`. `GetContext` waits on
    `l.Fence()` for the record's revision, unless `l.knownAt(k, c.Rev)`. `Ping` waits for
    `inner.Seen()` after the ping. Every other method passes through.

Ruling 3's fence (pre-flight C1, the plan's one Critical).
- **The hole.** In 7d one ledger per process saw every write that could legitimately land, so
  a put-back was always below it. Across processes, a process's high-water at a key rises only
  from its own writes, its reads and its feed. While the feed lagged or was down, a store
  writer could put back the record another process's rewrite or revocation replaced, and this
  process admitted it, for as long as the feed was down.
- **The fence.** A put-back is a store write, so it commits above the write it hides. Once the
  feed has delivered through the put-back's revision, it has delivered the later write and
  raised the high-water past the put-back. So a read waits for that.
- **Where it sits.** `Fenced` sits under the guard (`crypt.Wrap(guard.WrapRev(crypt.Fenced(raw,
  ledger), gc), …)`).
  - The wait runs inside the guard's call, bounded by `call_timeout`.
  - A feed that never arrives is the guard's `timeout` outcome, a counted failure. A dead feed
    opens the context pool's circuit like a dead store, and on port49d goes dark.
- **What needs no wait.**
  - A record at the revision this process last knew at its key: its own write (the login's
    next packet on the same process), or a record it admitted. The store holding that
    revision at the key holds that record, and nothing written after it.
  - Any read with no feed attached: memory, the tests' fixtures, the offline revocation.
  - A read after this process's own plaintext write (a touch, an annotation) waits for the
    feed to deliver it. That costs a watch's latency, typically milliseconds. L37's reply
    times measure it on the split.
- **7e-1 wires it** on port49d's daemon and broker layers. With one port49d, every legitimate
  write is its own and its reads seldom wait, but 7e-2 inherits it whole.

- [ ] **Step 1: The failing tests.** Create `internal/store/crypt/fence_test.go`:

  ```go
  package crypt

  import (
  	"context"
  	"errors"
  	"testing"
  	"time"

  	"github.com/prometheus/client_golang/prometheus"

  	"github.com/rhwendt/port49/internal/store"
  	"github.com/rhwendt/port49/internal/store/guard"
  	"github.com/rhwendt/port49/internal/store/memory"
  )

  // fencedPair is twoProcesses with b's layer fenced, its feed attached at
  // the store's revision and delivering nothing until the test says.
  func fencedPair(t *testing.T) (*memory.Store, store.Store, store.Store, *Ledger) {
  	t.Helper()
  	inner, a, _, _, lb := twoProcesses(t)
  	lb.Fence().Attach(inner.Seen())
  	return inner, a, Wrap(Fenced(inner, lb), keys(), nil, WithLedger(lb)), lb
  }

  // feedUpTo stands in for b's feed delivering every change through the
  // store's revision: each record at k is observed as FollowContexts would,
  // and the fence moves.
  func feedUpTo(t *testing.T, inner *memory.Store, l *Ledger, recs ...store.Context) {
  	t.Helper()
  	for _, c := range recs {
  		observe(l, keys(), ka, c, false)
  	}
  	l.Fence().Followed(inner.Seen())
  }

  func within(d time.Duration) (context.Context, context.CancelFunc) {
  	return context.WithTimeout(context.Background(), d)
  }

  // While b's feed lags, a store writer puts back alice's context over the
  // later login a made: b never admits it. It waits and is unavailable, and
  // once the feed delivers the later write, it is denied (pre-flight C1).
  // Without the fence b admitted it: alice's seq is b's high-water.
  func TestAPutBackIsDeniedWhileTheFeedLags(t *testing.T) {
  	inner, a, b, lb := fencedPair(t)
  	login(t, a, "ctx-alice", "user:alice")
  	alice, _ := inner.GetContext(context.Background(), ka)
  	feedUpTo(t, inner, lb, alice)
  	if c, err := b.GetContext(context.Background(), ka); err != nil || c.CtxID != "ctx-alice" {
  		t.Fatalf("b's read of alice's: %v %v", c.CtxID, err)
  	}
  	login(t, a, "ctx-bob", "user:bob") // the later write b's feed has not delivered
  	bob, _ := inner.GetContext(context.Background(), ka)
  	if err := inner.PutContext(context.Background(), ka, alice, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	ctx, cancel := within(150 * time.Millisecond)
  	defer cancel()
  	c, err := b.GetContext(ctx, ka)
  	if err == nil || !errors.Is(err, store.ErrUnavailable) || !errors.Is(err, ErrFeedBehind) {
  		t.Fatalf("with the feed behind, b read %q: %v", c.CtxID, err)
  	}
  	back, _ := inner.GetContext(context.Background(), ka)
  	feedUpTo(t, inner, lb, bob, back)
  	if _, err := b.GetContext(context.Background(), ka); !errors.Is(err, ErrNotLastWritten) {
  		t.Fatalf("once the feed delivered the later write: %v", err)
  	}
  }

  // a revokes alice: its plaintext mark lands and its seal does not (the
  // revocation floor's case). A store writer then puts back the record from
  // before, revoked_at zeroed. With b's feed down, b never answers it as
  // live; once the feed delivers the mark, the record put back is answered
  // revoked, from the floor (pre-flight C1).
  func TestARevocationFromAnotherProcessHoldsWhileTheFeedIsDown(t *testing.T) {
  	inner, a, b, lb := fencedPair(t)
  	login(t, a, "ctx-alice", "user:alice")
  	before, _ := inner.GetContext(context.Background(), ka)
  	feedUpTo(t, inner, lb, before)
  	if _, err := b.GetContext(context.Background(), ka); err != nil {
  		t.Fatal(err)
  	}
  	at := time.Now().UTC().Truncate(time.Second)
  	if err := inner.SetRevokedAt(context.Background(), ka, at); err != nil { // the plaintext mark alone
  		t.Fatal(err)
  	}
  	marked, _ := inner.GetContext(context.Background(), ka)
  	before.RevokedAt = time.Time{}
  	if err := inner.PutContext(context.Background(), ka, before, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	ctx, cancel := within(150 * time.Millisecond)
  	defer cancel()
  	if c, err := b.GetContext(ctx, ka); err == nil {
  		t.Fatalf("with the feed down, b answered the put-back, revoked_at %v", c.RevokedAt)
  	} else if !errors.Is(err, store.ErrUnavailable) {
  		t.Fatalf("with the feed down: %v", err)
  	}
  	back, _ := inner.GetContext(context.Background(), ka)
  	feedUpTo(t, inner, lb, marked, back)
  	c, err := b.GetContext(context.Background(), ka)
  	if err != nil || !c.RevokedAt.Equal(at) {
  		t.Fatalf("once the feed delivered the mark: revoked_at %v, %v", c.RevokedAt, err)
  	}
  }

  // A login on a, read on b before b's feed has delivered it, is admitted
  // once the feed does, within the read's wait (Review Focus 1).
  func TestAnotherProcesssWriteIsAdmittedOnceTheFeedDeliversIt(t *testing.T) {
  	inner, a, b, lb := fencedPair(t)
  	feed := &feedOf{changes: make(chan store.ContextChange, 1), compact: make(chan struct{})}
  	ctx, cancel := context.WithCancel(context.Background())
  	defer cancel()
  	go FollowContexts(ctx, feed, nil, keys(), lb, inner.Seen(), func(bool) {}, func() {}, t.Logf)
  	login(t, a, "ctx-alice", "user:alice")
  	alice, _ := inner.GetContext(context.Background(), ka)
  	go func() {
  		time.Sleep(50 * time.Millisecond)
  		feed.changes <- store.ContextChange{Key: ka, Context: alice, Rev: alice.Rev}
  	}()
  	rctx, rcancel := within(2 * time.Second)
  	defer rcancel()
  	if c, err := b.GetContext(rctx, ka); err != nil || c.CtxID != "ctx-alice" {
  		t.Fatalf("b's read once its feed delivered a's login: %v %v", c.CtxID, err)
  	}
  }

  // A read waiting on a feed with nothing to deliver asks it for its
  // progress, and the answer lets it through (an idle family; etcd's
  // RequestProgress).
  func TestAWaitingReadAsksTheFeedForItsProgress(t *testing.T) {
  	inner, a, b, lb := fencedPair(t)
  	login(t, a, "ctx-alice", "user:alice")
  	feed := &answeringFeed{now: inner.Seen}
  	ctx, cancel := context.WithCancel(context.Background())
  	defer cancel()
  	go FollowContexts(ctx, feed, nil, keys(), lb, inner.Seen(), func(bool) {}, func() {}, t.Logf)
  	rctx, rcancel := within(2 * time.Second)
  	defer rcancel()
  	if _, err := b.GetContext(rctx, ka); err != nil {
  		t.Fatalf("a read the feed's progress answer should let through: %v", err)
  	}
  	if feed.asked.Load() == 0 {
  		t.Fatal("the read never asked the feed")
  	}
  }

  // answeringFeed delivers no change, and answers every ask with progress
  // at the store's revision.
  type answeringFeed struct {
  	now   func() uint64
  	asked atomic.Int32
  }

  func (f *answeringFeed) ScanContexts(context.Context, func(store.ContextKey, store.Context)) (uint64, error) {
  	return f.now(), nil
  }

  func (f *answeringFeed) WatchContexts(ctx context.Context, _ uint64, _ func(store.ContextChange),
  	progress func(uint64), asks <-chan struct{}) error {
  	for {
  		select {
  		case <-ctx.Done():
  			return ctx.Err()
  		case <-asks:
  			f.asked.Add(1)
  			progress(f.now())
  		}
  	}
  }

  // A ping through the fence fails while the feed is behind the revision
  // the ping read at, so an idle port49d's probe takes it dark when its
  // feed has stopped (Ruling 11).
  func TestAPingFailsWhileTheFeedIsBehind(t *testing.T) {
  	inner, a, _, lb := fencedPair(t)
  	login(t, a, "ctx-alice", "user:alice") // the store moves past the fence
  	f := Fenced(inner, lb)
  	ctx, cancel := within(100 * time.Millisecond)
  	defer cancel()
  	if err := f.Ping(ctx); !errors.Is(err, ErrFeedBehind) {
  		t.Fatalf("a ping with the feed behind: %v", err)
  	}
  	lb.Fence().Followed(inner.Seen())
  	if err := f.Ping(context.Background()); err != nil {
  		t.Fatalf("a ping with the feed caught up: %v", err)
  	}
  }

  // Under the guard, a read the feed never lets through is the guard's
  // timeout, counted in the context pool: a dead feed opens the circuit as
  // a dead store does.
  func TestAFeedThatNeverArrivesIsCountedByTheGuard(t *testing.T) {
  	inner, a, _, lb := fencedPair(t)
  	login(t, a, "ctx-alice", "user:alice")
  	calls := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "calls"}, []string{"component", "pool", "outcome"})
  	g := guard.WrapRev(Fenced(inner, lb), guard.Config{Component: "daemon", CallTimeout: 100 * time.Millisecond,
  		BulkTimeout: time.Second, Now: time.Now, Metrics: guard.Metrics{Calls: calls}})
  	if _, err := g.GetContext(context.Background(), ka); !errors.Is(err, store.ErrUnavailable) {
  		t.Fatalf("%v", err)
  	}
  	if n := testutil.ToFloat64(calls.WithLabelValues("daemon", "context", "timeout")); n != 1 {
  		t.Fatalf("the guard counted %v timeouts", n)
  	}
  }
  ```

  Add `"sync/atomic"` and `"github.com/prometheus/client_golang/prometheus/testutil"` to the
  imports. Build `guard.Config` as `guard_test.go`'s `config` helper builds it if a field the
  guard needs (slots, breaker) has no usable zero value at `b508ba0`, and say so.

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/store/crypt/ -run 'Feed|Fence|Ping|Revocation' -count=1`
  Expected: FAIL to compile (`Fenced`, `Fence`, `ErrFeedBehind` undefined). With a `Fenced`
  that passes `GetContext` through, `TestAPutBackIsDeniedWhileTheFeedLags` admits alice's
  put-back and `TestARevocationFromAnotherProcessHoldsWhileTheFeedIsDown` answers it unrevoked.

- [ ] **Step 3: The fence.** Create `internal/store/crypt/fence.go`:

  ```go
  package crypt

  import (
  	"context"
  	"fmt"
  	"sync"

  	"github.com/rhwendt/port49/internal/store"
  )

  // ErrFeedBehind is a context read whose record this process's context feed
  // had not delivered by the read's deadline (plan 7e, pre-flight C1). It is
  // store.ErrUnavailable: the guard counts it, a handler denies
  // store_unavailable, and the refresh leaves the context for its next pass.
  var ErrFeedBehind = fmt.Errorf("%w: this process's context feed has not delivered the record's revision",
  	store.ErrUnavailable)

  // Fence is how far this process's context feed has delivered the store's
  // changes (plan 7e, Ruling 3). A read judges no record its feed has not
  // passed: a put-back commits above the write it hides, so once the feed has
  // passed the put-back it has raised the key's mark past it, and while it
  // has not, the read cannot tell a put-back from another process's login.
  // With no feed attached (memory, a fixture, the offline revocation) every
  // revision passes. It is safe for concurrent use.
  type Fence struct {
  	mu   sync.Mutex
  	on   bool
  	at   uint64
  	up   bool
  	wake chan struct{}
  	asks chan struct{}
  }

  func newFence() *Fence { return &Fence{wake: make(chan struct{}), asks: make(chan struct{}, 1)} }

  // Attach is a feed following the store from at: from now on a read waits
  // for it. It only raises.
  func (f *Fence) Attach(at uint64) {
  	f.mu.Lock()
  	defer f.mu.Unlock()
  	f.on = true
  	f.raise(at)
  }

  // Followed is every change through rev delivered. It only raises.
  func (f *Fence) Followed(rev uint64) {
  	f.mu.Lock()
  	defer f.mu.Unlock()
  	f.raise(rev)
  }

  func (f *Fence) raise(rev uint64) {
  	if rev > f.at {
  		f.at = rev
  		close(f.wake)
  		f.wake = make(chan struct{})
  	}
  }

  // SetUp records whether the feed's watch runs; Up reads it.
  func (f *Fence) SetUp(up bool) { f.mu.Lock(); f.up = up; f.mu.Unlock() }
  func (f *Fence) Up() bool      { f.mu.Lock(); defer f.mu.Unlock(); return f.up }

  // At is the revision the feed has delivered through.
  func (f *Fence) At() uint64 { f.mu.Lock(); defer f.mu.Unlock(); return f.at }

  // Asks is where a waiting read asks the feed for a progress notification.
  func (f *Fence) Asks() <-chan struct{} { return f.asks }

  // Wait returns once the feed has delivered every change through rev, or at
  // once with no feed attached. While it is behind, it asks the feed for its
  // progress, again after each wake that leaves it behind, and returns
  // ErrFeedBehind when ctx ends first. ctx carries the guard's call deadline.
  func (f *Fence) Wait(ctx context.Context, rev uint64) error {
  	for {
  		f.mu.Lock()
  		if !f.on || f.at >= rev {
  			f.mu.Unlock()
  			return nil
  		}
  		wake, at := f.wake, f.at
  		f.mu.Unlock()
  		select {
  		case f.asks <- struct{}{}:
  		default: // an ask is already pending
  		}
  		select {
  		case <-wake:
  		case <-ctx.Done():
  			return fmt.Errorf("%w (the feed at revision %d, the record at %d)", ErrFeedBehind, at, rev)
  		}
  	}
  }

  // Fenced is inner with each context read held until l's feed has passed
  // the record's revision (plan 7e, pre-flight C1). port49d puts it under the
  // guard, so the wait is bounded by call_timeout and a feed that never
  // arrives is a counted failure. A record at the revision l last knew at
  // its key needs no wait: the store holding that revision there holds that
  // record and nothing written after it. Ping waits for the revision the
  // ping itself read at, so a probe fails while the feed is behind.
  func Fenced(inner store.RevStore, l *Ledger) store.RevStore { return fenced{RevStore: inner, l: l} }

  type fenced struct {
  	store.RevStore
  	l *Ledger
  }

  func (f fenced) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
  	c, err := f.RevStore.GetContext(ctx, k)
  	if err != nil || f.l.knownAt(k, c.Rev) {
  		return c, err
  	}
  	if err := f.l.Fence().Wait(ctx, c.Rev); err != nil {
  		return store.Context{}, err
  	}
  	return c, nil
  }

  func (f fenced) Ping(ctx context.Context) error {
  	if err := f.RevStore.Ping(ctx); err != nil {
  		return err
  	}
  	return f.l.Fence().Wait(ctx, f.RevStore.Seen())
  }
  ```

  In `ledger.go`, add `fence *Fence` to `Ledger`, built in `NewLedger` as `newFence()`, and:

  ```go
  // Fence is this process's feed fence (Fenced).
  func (l *Ledger) Fence() *Fence { return l.fence }

  // knownAt reports whether rev is the revision of the record this process
  // last knew at k: a write of its own that landed, or a record it admitted.
  //
  // After an etcd restore without --bump-revision, revisions repeat, so a
  // put-back can land at a revision equal to a stale e.rev and skip the
  // feed's wait (re-check R3). The high-water still judges it, so this only
  // narrows the fence to the feed-lag case, and the runbook restarts every
  // process after such a restore, which clears it.
  func (l *Ledger) knownAt(k store.ContextKey, rev uint64) bool {
  	l.mu.Lock()
  	defer l.mu.Unlock()
  	e, ok := l.m[k]
  	return ok && rev > 0 && e.rev == rev
  }
  ```

  Add to `Ledger`'s comment one paragraph: "A read judges no record the context feed has not
  passed (Fence, Fenced): a put-back commits above the write it hides, so once the feed has
  passed it the mark is past it."

- [ ] **Step 4: The feed moves it.** In `follow.go`:
  - `LoadLedger`, after `l.SetBase(rev + 1)`: `l.Fence().Attach(rev)`. Say in its comment that
    from here every fenced read waits for `FollowContexts`, so the caller starts it at once.
  - `FollowContexts`:
    - pass `l.Fence().Followed` as `progress` and `l.Fence().Asks()` as `asks` to
      `WatchContexts`, replacing Task 8's no-op and nil;
    - call `l.Fence().Followed(rev)` after a successful `rescan` (the record's seed, then the
      scan), never before the seed: the fence opens only once the record's marks are in;
    - call `l.Fence().SetUp(true)` and `SetUp(false)` beside each `up(…)`.

- [ ] **Step 5: port49d fences its stores.** In `cmd/port49d/store.go`'s `openStores` etcd branch,
  wrap each component's raw store in the fence under its guard:

  ```go
  	daemon := crypt.Wrap(guard.WrapRev(crypt.Fenced(d, ledger), gc("daemon")), keys, m.CryptOpenFailures,
  		crypt.WithLedger(ledger), say)
  ```

  Do the same for the broker's (`crypt.Fenced(b, ledger)`, `gc("broker")`). The raw stores the
  sweep, the hold and the record use stay unfenced: they read no context for admission. Memory
  is not fenced.

- [ ] **Step 6: Run everything.**

  Run: `go test ./internal/store/... ./cmd/port49d/ -count=1` then `make test-race`
  Expected: PASS. 7d's e2e tests pass unchanged, through the fence:
  - `TestAHungStoreGoesDarkAndServesAgainWhenItReturns`;
  - `TestRunOnEtcdKeepsALoginAcrossARestart`;
  - `TestAStartAppliesAStandingMarkToAKeptContext`.

- [ ] **Step 7: Commit.**

  ```bash
  gofmt -w internal/store/crypt cmd/port49d
  make build && make test && make vet && make test-race
  git add internal/store/crypt/fence.go internal/store/crypt/fence_test.go internal/store/crypt/ledger.go \
    internal/store/crypt/follow.go cmd/port49d/store.go
  git commit -m "feat(crypt): judge no context the feed has not passed

  A process's high-water rises from its own writes, its reads and its
  feed; while the feed lagged or was down, a put-back over another
  process's rewrite or revocation was admitted (pre-flight C1). A read now
  waits, under the guard and within call_timeout, until the context feed
  has delivered through the record's revision, asking etcd for progress;
  a put-back commits above what it hides, so the feed has raised the mark
  past it by then. A feed that never arrives is a counted store failure,
  and a ping waits too, so a dead feed goes dark as a dead store does.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 9: Every process follows the revocation marks

**Files:**
- Modify: `internal/store/store.go` (`MarkFeed`), `internal/store/marks.go`,
  `internal/store/marks_test.go`
- Modify: `internal/store/etcd/feed.go`, `internal/store/etcd/feed_test.go`
- Modify: `internal/broker/broker.go` (`MarkChanged`), `internal/broker/revoke.go`
  (`matchMark`, factored out of `Revoke`; pre-flight's per-task table),
  `internal/broker/listen_test.go`
- Modify: `cmd/port49d/main.go` (the daemon's marks and the listener's from the feed)

**Interfaces:**
- Consumes: `store.Marks` (7d), `broker.ConnCloser` (7a).
- Produces:
  - `type store.MarkFeed interface { Revocations(ctx context.Context) (uint64, []Revocation, error); WatchRevocations(ctx context.Context, after uint64, fn func(r Revocation, lifted bool)) error }`.
  - `type store.MarkChange struct { Revocation; Standing, Reloaded bool }`: one change applied
    to a process's marks. `Reloaded` is a change a load found by difference, not an event the
    watch delivered. A mark a reload finds missing may be a lift made in a gap, or a mark an
    etcd restore lost, and Task 15b's copy of the marks keeps it (Ruling 12).
  - `func (m *Marks) All() []Revocation`: every mark in force, `Kind`, `Key` and `At`, sorted.
  - `func store.LoadMarks(ctx context.Context, feed MarkFeed, m *Marks, on func(MarkChange)) (uint64, error)`:
    every mark the store holds goes into `m`; every mark `m` holds that the store lacks is lifted
    from `m`; `on` is told of each change, every one `Reloaded`; it returns the revision read
    at.
  - `func store.FollowMarks(ctx context.Context, feed MarkFeed, m *Marks, from uint64, on func(MarkChange), up func(bool), rescanned func(), logf func(string, ...any)) error`.
    A watch event is told with `Reloaded` false. A reload after a compacted watch is told as
    `LoadMarks` tells it.
  - `(*etcd.Store).Revocations` and `(*etcd.Store).WatchRevocations`.
  - `func (b *Broker) MarkChanged(c store.MarkChange)`: the listener's copy, and, for a mark
    that stands, the held connections it names, closed.

Ruling 5. A mark made on one broker process reaches every other process's in-memory copy and
held connections through the feed. A lift does the same, removing the mark.

- [ ] **Step 1: The failing tests.** In `internal/store/marks_test.go`:

  ```go
  // markFeed serves a set of marks at rev 7, and a watch that delivers what
  // the test sends. The set is read on FollowMarks's goroutine at a reload,
  // so it is behind a lock (pre-flight M4, the race).
  type markFeed struct {
  	mu      sync.Mutex
  	marks   []Revocation
  	events  chan markEvent
  	compact chan struct{}
  }

  type markEvent struct {
  	r      Revocation
  	lifted bool
  }

  func (f *markFeed) setMarks(rs []Revocation) { f.mu.Lock(); f.marks = rs; f.mu.Unlock() }

  func (f *markFeed) Revocations(context.Context) (uint64, []Revocation, error) {
  	f.mu.Lock()
  	defer f.mu.Unlock()
  	return 7, append([]Revocation(nil), f.marks...), nil
  }

  // told renders a change for the assertions: key, standing, reloaded.
  func told(c MarkChange) string { return fmt.Sprintf("%s %v %v", c.Key, c.Standing, c.Reloaded) }
  func (f *markFeed) WatchRevocations(ctx context.Context, _ uint64, fn func(Revocation, bool)) error {
  	for {
  		select {
  		case <-ctx.Done():
  			return ctx.Err()
  		case e := <-f.events:
  			fn(e.r, e.lifted)
  		case <-f.compact:
  			return ErrCompacted
  		}
  	}
  }

  // LoadMarks puts every stored mark in, takes out one the store lacks, and
  // tells on of each change, each as Reloaded: a mark missing from a load
  // may be a restore's loss, not a lift (Ruling 12).
  func TestLoadMarksMakesTheCopyTheStores(t *testing.T) {
  	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0)}
  	gone := Revocation{Kind: RevocationPrincipal, Key: "user:bob@example.com", At: time.Unix(5, 0)}
  	m := NewMarks()
  	m.Set(gone, true)
  	var got []string
  	rev, err := LoadMarks(context.Background(), &markFeed{marks: []Revocation{alice}}, m,
  		func(c MarkChange) { got = append(got, told(c)) })
  	if err != nil || rev != 7 || !m.Holds(alice.Kind, alice.Key) || m.Holds(gone.Kind, gone.Key) {
  		t.Fatalf("rev %d: %v; marks %v", rev, err, m.All())
  	}
  	sort.Strings(got)
  	if fmt.Sprint(got) != "[user:alice@example.com true true user:bob@example.com false true]" {
  		t.Fatalf("told %v", got)
  	}
  }

  // FollowMarks applies each put and lift, told as events; a compacted
  // watch loads them again and applies the difference, telling on of it
  // alone, as reloaded.
  func TestACompactedMarkFeedReloadsTheDifference(t *testing.T) {
  	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0)}
  	carol := Revocation{Kind: RevocationPrincipal, Key: "user:carol@example.com", At: time.Unix(11, 0)}
  	dave := Revocation{Kind: RevocationPrincipal, Key: "user:dave@example.com", At: time.Unix(12, 0)}
  	f := &markFeed{events: make(chan markEvent, 1), compact: make(chan struct{}, 1)}
  	m := NewMarks()
  	var mu sync.Mutex
  	var got []string
  	on := func(c MarkChange) { mu.Lock(); got = append(got, told(c)); mu.Unlock() }
  	ctx, cancel := context.WithCancel(context.Background())
  	defer cancel()
  	go FollowMarks(ctx, f, m, 7, on, func(bool) {}, func() {}, t.Logf)
  	f.events <- markEvent{r: alice}
  	f.events <- markEvent{r: dave}
  	f.events <- markEvent{r: dave, lifted: true}
  	waitFor(t, func() bool { return m.Holds(alice.Kind, alice.Key) && !m.Holds(dave.Kind, dave.Key) })
  	f.setMarks([]Revocation{carol}) // alice lifted and carol marked while the watch was compacted away
  	f.compact <- struct{}{}
  	waitFor(t, func() bool { return m.Holds(carol.Kind, carol.Key) && !m.Holds(alice.Kind, alice.Key) })
  	mu.Lock()
  	defer mu.Unlock()
  	want := []string{
  		"user:alice@example.com true false", "user:dave@example.com true false",
  		"user:dave@example.com false false", // a lift the watch delivered: not reloaded
  	}
  	if len(got) != 5 || fmt.Sprint(got[:3]) != fmt.Sprint(want) {
  		t.Fatalf("told %v", got)
  	}
  	rest := append([]string(nil), got[3:]...)
  	sort.Strings(rest)
  	if fmt.Sprint(rest) != "[user:alice@example.com false true user:carol@example.com true true]" {
  		t.Fatalf("the reload told %v", rest)
  	}
  }
  ```

  `waitFor` is a polling helper with a 5s deadline. Add it to the test file.

  In `internal/broker/listen_test.go`, using the file's listener fixture that binds a held
  connection for a principal:

  ```go
  // A mark another broker process made, arriving through the feed, closes
  // this process's held connections it names and refuses the next bind
  // (Review Focus 3; Ruling 5).
  func TestAMarkFromTheFeedClosesThisReplicasHeldConnections(t *testing.T) {
  	b, l, conn := brokerWithHeldConn(t, "user:alice@example.com") // a Broker whose Conns is l, and alice's live connection
  	alice := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: time.Now()}
  	b.MarkChanged(store.MarkChange{Revocation: alice, Standing: true})
  	if !closedWithin(conn, 2*time.Second) {
  		t.Fatal("the held connection was not closed")
  	}
  	if !bindRefused(t, l, "user:alice@example.com") {
  		t.Fatal("a new bind was not refused credential_revoked")
  	}
  	b.MarkChanged(store.MarkChange{Revocation: store.Revocation{Kind: alice.Kind, Key: alice.Key}})
  	if bindRefused(t, l, "user:alice@example.com") {
  		t.Fatal("a lift from the feed did not reach the listener")
  	}
  }
  ```

  `brokerWithHeldConn`, `closedWithin` and `bindRefused` are built from `listen_test.go`'s
  existing helpers. Name them in the report.

  In `feed_test.go`, add `TestTheMarkFeedBringsPutsAndLifts`: `Revocations` returns a
  revision, then a `PutRevocation` and a `DeleteRevocation` arrive through
  `WatchRevocations` as `(r, false)` and `(r, true)`, the lift carrying the kind and key parsed
  from the etcd key.

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/store/ ./internal/store/etcd/ ./internal/broker/ -run 'Marks|MarkFeed|FromTheFeed' -count=1`
  Expected: FAIL to compile.

- [ ] **Step 3: The store side.** In `store.go`, add `MarkFeed` (as in Interfaces, with a
  comment that a lift carries only `Kind` and `Key`). In `marks.go`:

  ```go
  // All is every mark in force, sorted by kind and key.
  func (m *Marks) All() []Revocation {
  	if m == nil {
  		return nil
  	}
  	m.mu.RLock()
  	defer m.mu.RUnlock()
  	out := make([]Revocation, 0, len(m.m))
  	for k, at := range m.m {
  		out = append(out, Revocation{Kind: k[0], Key: k[1], At: at})
  	}
  	sort.Slice(out, func(i, j int) bool {
  		if out[i].Kind != out[j].Kind {
  			return out[i].Kind < out[j].Kind
  		}
  		return out[i].Key < out[j].Key
  	})
  	return out
  }

  // MarkChange is one change applied to a process's marks (plan 7e, Ruling
  // 5): a mark that now stands, or one lifted. Reloaded is a change a load
  // found by difference, not an event the watch delivered: a mark missing
  // from a load may be a lift made in a gap, or a mark an etcd restore lost
  // (Ruling 12).
  type MarkChange struct {
  	Revocation
  	Standing, Reloaded bool
  }

  // LoadMarks makes m the store's marks (plan 7e, Ruling 5): every mark feed
  // holds is put in, every mark m holds that feed lacks is lifted, and on is
  // told of each change, as Reloaded (nil tells nothing). It returns the
  // revision read at, which FollowMarks follows from.
  func LoadMarks(ctx context.Context, feed MarkFeed, m *Marks, on func(MarkChange)) (uint64, error) {
  	rev, rs, err := feed.Revocations(ctx)
  	if err != nil {
  		return 0, err
  	}
  	stored := map[[2]string]bool{}
  	for _, r := range rs {
  		stored[[2]string{r.Kind, r.Key}] = true
  		if !m.Holds(r.Kind, r.Key) {
  			m.Set(r, true)
  			if on != nil {
  				on(MarkChange{Revocation: r, Standing: true, Reloaded: true})
  			}
  		}
  	}
  	for _, r := range m.All() {
  		if !stored[[2]string{r.Kind, r.Key}] {
  			m.Set(r, false)
  			if on != nil {
  				on(MarkChange{Revocation: r, Reloaded: true})
  			}
  		}
  	}
  	return rev, nil
  }

  // FollowMarks keeps m current from feed after `from` until ctx ends, and
  // returns ctx's error then (plan 7e, Ruling 5). Each put and lift is
  // applied to m and told to on. A compacted watch loads the marks again
  // (LoadMarks), telling on only of the difference, and tells rescanned; a
  // watch that fails is tried again every second. up and logf are as
  // crypt.FollowContexts's.
  func FollowMarks(ctx context.Context, feed MarkFeed, m *Marks, from uint64, on func(MarkChange),
  	up func(bool), rescanned func(), logf func(string, ...any)) error {
  	failing := false
  	for {
  		up(true)
  		err := feed.WatchRevocations(ctx, from, func(r Revocation, lifted bool) {
  			if m.Holds(r.Kind, r.Key) == !lifted {
  				return
  			}
  			m.Set(r, !lifted)
  			if on != nil {
  				on(MarkChange{Revocation: r, Standing: !lifted})
  			}
  		})
  		up(false)
  		if ctx.Err() != nil {
  			return ctx.Err()
  		}
  		if errors.Is(err, ErrCompacted) {
  			logf("store: the marks feed's revision was compacted; loading the marks again")
  			rescanned()
  			if rev, lerr := LoadMarks(ctx, feed, m, on); lerr == nil {
  				from, failing = rev, false
  				continue
  			} else {
  				err = lerr
  			}
  		}
  		if !failing {
  			logf("store: the marks feed stopped (%v); trying again every second", err)
  			failing = true
  		}
  		select {
  		case <-ctx.Done():
  			return ctx.Err()
  		case <-time.After(time.Second):
  		}
  	}
  }
  ```

  The watch's `from` is not advanced per event here, because `WatchRevocations` delivers in
  order. On a reconnect after a failure, re-watching from `from` re-delivers events already
  applied, and applying them is idempotent (`Holds` check). Say so in the comment.

- [ ] **Step 4: etcd's marks feed.** In `feed.go`:
  - `Revocations` is `ListRevocations` read at one revision: page with `WithRev` pinned to the
    first page's, as `ScanContexts` does. Return the revision. A mark that does not decode is an
    error naming its key, as `ListRevocations`'s is.
  - `WatchRevocations` watches `famMark` from `after+1` on the token client, as
    `WatchContexts` does. A put decodes its `markRec`. A delete parses `(kind, key)` from the
    etcd key with `lastTwo`, and calls `fn(store.Revocation{Kind: kind, Key: key}, true)`.

- [ ] **Step 5: The broker.** In `broker.go`:

  ```go
  // MarkChanged is a mark made or lifted on a broker process, this one
  // included, as the marks feed brings it (plan 7e, Ruling 5): the
  // listener's copy follows, and a mark that stands closes this process's
  // held connections it names, as Revoke closes its own. The daemon's marks
  // (b.Marks) are the feed's own to keep (store.FollowMarks).
  func (b *Broker) MarkChanged(c store.MarkChange) {
  	if b.Conns == nil {
  		return
  	}
  	b.Conns.Revoked(c.Revocation, c.Standing)
  	if !c.Standing {
  		return
  	}
  	if n := b.Conns.CloseHeld(matchMark(c.Revocation)); n > 0 {
  		b.logf("broker: a revocation of %s made on a broker process closed %d held connection(s) here",
  			printsafe.Line(c.Key, 160), n)
  	}
  }
  ```

  The feed delivers this process's own marks too, after `Revoke` has closed their connections,
  so the line says "a broker process", never "another" (pre-flight M11). A mark this process
  made usually closes nothing here, since `Revoke` closed it first, and prints nothing.

  Factor `Revoke`'s match closure in `revoke.go` into `func matchMark(r store.Revocation)
  func(principal, certKey string) bool`, used by `Revoke` and here.

- [ ] **Step 6: port49d follows the marks.** In `cmd/port49d/main.go`, on etcd, after
  `startOnPersistentStore`:
  - replace filling `authMarks` from `marks` with `rev, err := store.LoadMarks(ctx, sts.etcd,
    authMarks, nil)`, retried while unavailable;
  - after the listener is built, put every mark in it (`bl.Revoked(r, true)` for `r` in
    `authMarks.All()`, replacing the loop over `marks`);
  - start `store.FollowMarks(ctx, sts.etcd, authMarks, rev, brk.MarkChanged, …)` on a goroutine
    joined as the context feed is, with `up` and `rescanned` on `StoreFeedUp` and
    `StoreFeedRescans` labelled `marks`.

  In `feed_test.go`, `TestTheMarkFeedBringsPutsAndLifts` runs on `onShared(t, time.Now)`.

  Before the listener exists, `brk.MarkChanged` finds `brk.Conns` nil and does nothing. The
  listener is filled from `authMarks.All()` once built, so no mark is missed between the two.

  Memory keeps its restore path.

- [ ] **Step 7: Run everything.**

  Run: `go test ./internal/store/... ./internal/broker/ ./cmd/port49d/ -count=1`
  Expected: PASS, and `TestAStartAppliesAStandingMarkToAKeptContext` unchanged.

- [ ] **Step 8: Commit.**

  ```bash
  gofmt -w internal/store internal/broker cmd/port49d
  make build && make test && make vet
  git add internal/store/store.go internal/store/marks.go internal/store/marks_test.go \
    internal/store/etcd/feed.go internal/store/etcd/feed_test.go internal/broker/broker.go \
    internal/broker/revoke.go internal/broker/listen_test.go cmd/port49d/main.go
  git commit -m "feat(store): every process follows the revocation marks

  The marks load at a revision and follow from it: a mark made on one
  broker process reaches every process's in-memory copy, and closes the
  held connections it names there; a lift removes it. A compacted watch
  reloads and applies the difference (plan 7e Ruling 5).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 10: The ledger record, kept by the holder, read by every start

**Files:**
- Modify: `internal/store/etcd/keys.go` (`famLedger`), `internal/store/etcd/roles.go`
  (`daemonReads`, the probes)
- Create: `internal/store/etcd/ledger.go`, `internal/store/etcd/ledger_test.go`
- Modify: `internal/store/etcd/roles_test.go`
- Modify: `internal/store/crypt/follow.go` (`KeepLedger`), `follow_test.go`
- Modify: `internal/daemon/metrics/metrics.go`, `metrics_test.go` (`LedgerPending`, `LedgerBehind`)
- Modify: `cmd/port49d/store.go` (the record into `LoadLedger`; the keeper; the refused-read
  line), `cmd/port49d/storeroles_test.go`, `cmd/port49d/store_e2e_test.go`,
  `cmd/port49d/broker_test.go` (`sharedUsernamePolicy`)
- Modify: `docs/superpowers/plans/README.md` (7e-1 as built, Step 7)

**Interfaces:**
- Consumes: `store.LedgerMark`, `store.LedgerSource`, `store.LedgerSink` (Tasks 7, 8);
  `crypt.Ledger.Dirty`, `Redirty`, `Pending` (Task 7); `crypt.Fence.Up` (Task 8a).
- Produces:
  - etcd: `famLedger = "lw/"` (`lw/<nas>/<user>`); `(*etcd.Store).LedgerMarks` and
    `(*etcd.Store).PutLedgerMarks`.
  - `func crypt.KeepLedger(ctx context.Context, l *Ledger, sink store.LedgerSink, every time.Duration, report func(pending int, behind bool), logf func(string, ...any))`.
    `behind` is `!l.Fence().Up()`: the context feed that raises the ledger for other
    processes' logins is down. When `ctx` ends, it reports `(0, false)` once, so a keeper that
    stops leaves no stale gauge (pre-flight I11).
  - `Metrics.LedgerPending prometheus.Gauge` (`port49_ledger_pending`) and
    `Metrics.LedgerBehind prometheus.Gauge` (`port49_ledger_behind`).
  - roles: `daemonReads` gains `famLedger`. `CheckIdentity` probes that the daemon is refused a
    write of `lw/`, and a read and a write of `sp/`. The broker is allowed all three.

Ruling 4. In 7e-1 the keyspace's holder is port49d itself, as in 7d, so port49d keeps the record
with the broker's identity. In 7e-2 the runner does.

- [ ] **Step 1: The failing tests.** In `internal/store/etcd/ledger_test.go`:

  ```go
  // The record raises and never lowers: a higher sequence replaces, a lower
  // one is ignored, a later floor at the same sequence is kept, and a never
  // context's mark has no lease (Ruling 4).
  func TestTheLedgerRecordOnlyRaises(t *testing.T) {
  	ctx := context.Background()
  	s := onShared(t, time.Now)
  	k := store.ContextKey{NAS: "leaf-01", Username: "netops"}
  	until := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
  	put := func(m store.LedgerMark) {
  		if err := s.PutLedgerMarks(ctx, []store.LedgerMark{m}); err != nil {
  			t.Fatal(err)
  		}
  	}
  	put(store.LedgerMark{Key: k, Seq: 100, Until: until})
  	put(store.LedgerMark{Key: k, Seq: 50, Until: until})              // lower: ignored
  	put(store.LedgerMark{Key: k, Seq: 100, RevokedAt: until.Add(-time.Hour), Until: until}) // a floor at the same sequence
  	rev, ms, err := s.LedgerMarks(ctx)
  	if err != nil || rev == 0 || len(ms) != 1 || ms[0].Seq != 100 || ms[0].RevokedAt.IsZero() {
  		t.Fatalf("rev %d marks %+v: %v", rev, ms, err)
  	}
  	put(store.LedgerMark{Key: k, Seq: 101}) // a never context: no lease
  	_, ms, _ = s.LedgerMarks(ctx)
  	if ms[0].Seq != 101 || !ms[0].Until.IsZero() || !ms[0].RevokedAt.IsZero() {
  		t.Fatalf("after a higher sequence: %+v", ms[0])
  	}
  }

  // Two keepers raising one key at once (a runner paused past its fence, and
  // the one that took over) both land, and the higher stands.
  func TestTheLedgerRecordRaceKeepsTheHigher(t *testing.T) {
  	ctx := context.Background()
  	s := onShared(t, time.Now)
  	k := store.ContextKey{NAS: "leaf-01", Username: "netops"}
  	var wg sync.WaitGroup
  	for _, run := range [][2]int{{1, 1}, {200, -1}} { // one counts up, one down
  		wg.Add(1)
  		go func(seq, step int) {
  			defer wg.Done()
  			for i := 0; i < 200; i, seq = i+1, seq+step {
  				if err := s.PutLedgerMarks(ctx, []store.LedgerMark{{Key: k, Seq: uint64(seq)}}); err != nil {
  					t.Error(err)
  					return
  				}
  			}
  		}(run[0], run[1])
  	}
  	wg.Wait()
  	if _, ms, err := s.LedgerMarks(ctx); err != nil || len(ms) != 1 || ms[0].Seq != 200 {
  		t.Fatalf("after the race: %+v %v", ms, err)
  	}
  }
  ```

  In `roles_test.go`, beside `TestCheckIdentityRefusesADaemonWithTheBrokersReach`:

  ```go
  // A daemon role granted a write on lw/, or any access to sp/, is refused at
  // the start: either would let a stolen daemon key lower the ledger record
  // or forge a replay's superseded instant (Review Focus 8; Rulings 4, 9).
  func TestCheckIdentityRefusesADaemonThatCanWriteTheLedgerRecord(t *testing.T) {
  	const prefix = "/port49/"
  	ledger, superseded := newKeys(prefix).family(famLedger), newKeys(prefix).family(famSuperseded)
  	srv := provisioned(t, prefix)
  	if err := openAs(t, srv, "port49-daemon", prefix).CheckIdentity(context.Background(), false); err != nil {
  		t.Fatalf("the daemon as itself, with its read on lw/: %v", err)
  	}
  	for _, extra := range []etcdtest.Grant{
  		{Role: RoleDaemon, Key: ledger, RangeEnd: clientv3.GetPrefixRangeEnd(ledger), Write: true},
  		{Role: RoleDaemon, Key: superseded, RangeEnd: clientv3.GetPrefixRangeEnd(superseded)},
  	} {
  		loose := provisionedWith(t, prefix, []etcdtest.Grant{extra}, nil)
  		if err := openAs(t, loose, "port49-daemon", prefix).CheckIdentity(context.Background(), false); !errors.Is(err, ErrNotSeparated) {
  			t.Fatalf("a daemon granted %+v passed: %v", extra, err)
  		}
  	}
  }
  ```

  `provisioned`, `provisionedWith` and `openAs` are `roles_test.go`'s own (pre-flight M1).

  In `crypt/follow_test.go`:

  ```go
  // The keeper writes what was raised, keeps what a failed write owed for the
  // next round, and reports what is owed; when it stops it reports 0, so an
  // ex-runner's gauge is never stale (pre-flight I11).
  func TestTheKeeperWritesRaisedMarksAndRetriesAFailure(t *testing.T) {
  	l := NewLedger()
  	l.Fence().SetUp(true)
  	l.Observe(ka, 10, 10, time.Time{}, time.Now().Add(time.Hour))
  	sink := &flakySink{fail: 1}
  	var reports []report
  	ctx, cancel := context.WithCancel(context.Background())
  	go func() { eventually(t, func() bool { return sink.landed() == 1 }); cancel() }()
  	KeepLedger(ctx, l, sink, 10*time.Millisecond, func(n int, behind bool) {
  		reports = append(reports, report{n, behind})
  	}, t.Logf)
  	if sink.calls() < 2 || l.Pending() != 0 || reports[0] != (report{1, false}) {
  		t.Fatalf("calls %d pending %d reports %v", sink.calls(), l.Pending(), reports)
  	}
  	if last := reports[len(reports)-1]; last != (report{0, false}) {
  		t.Fatalf("a keeper that stopped last reported %v", last)
  	}
  }

  // While the context feed is down, the keeper reports itself behind: its
  // pending count cannot see the logins other processes make (pre-flight
  // I11).
  func TestTheKeeperIsBehindWhileTheFeedIsDown(t *testing.T) {
  	l := NewLedger()
  	l.Fence().SetUp(false)
  	sink := &flakySink{}
  	var mu sync.Mutex
  	var reports []report
  	ctx, cancel := context.WithCancel(context.Background())
  	defer cancel()
  	go KeepLedger(ctx, l, sink, 10*time.Millisecond, func(n int, behind bool) {
  		mu.Lock()
  		reports = append(reports, report{n, behind})
  		mu.Unlock()
  	}, t.Logf)
  	eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(reports) > 0 && reports[len(reports)-1].behind })
  	l.Fence().SetUp(true)
  	eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return !reports[len(reports)-1].behind })
  }

  type report struct {
  	pending int
  	behind  bool
  }

  // flakySink fails its first fail calls with store.ErrUnavailable and
  // records what lands, under a lock: KeepLedger calls it on its own
  // goroutine (pre-flight M4, the race).
  type flakySink struct {
  	mu          sync.Mutex
  	fail, n, ok int
  }

  func (s *flakySink) PutLedgerMarks(context.Context, []store.LedgerMark) error {
  	s.mu.Lock()
  	defer s.mu.Unlock()
  	s.n++
  	if s.n <= s.fail {
  		return store.ErrUnavailable
  	}
  	s.ok++
  	return nil
  }

  func (s *flakySink) calls() int  { s.mu.Lock(); defer s.mu.Unlock(); return s.n }
  func (s *flakySink) landed() int { s.mu.Lock(); defer s.mu.Unlock(); return s.ok }
  ```

  In the first test, `reports` is appended on the keeper's goroutine, which is the test's own
  (`KeepLedger` runs in the foreground), so it needs no lock.

  In `cmd/port49d/store_e2e_test.go`, add the test and its helpers (pre-flight I14):

  ```go
  // A context put back while port49d was stopped, at a key the ledger record
  // holds a later mark for, is denied after the restart: the start seeds its
  // ledger from the record before it scans (Review Focus 2; Ruling 4). In
  // 7d this was the restart residual: the start took it as the key's.
  //
  // The put-back is bob's context over alice's at the username both log in
  // as: impersonation, so a denial here cannot come from some unrelated
  // fault. Two positive controls: alice's own session is permitted before
  // the stop, and after a restart with nothing put back.
  func TestAStartSeededFromTheLedgerRecordDeniesAPutBack(t *testing.T) {
  	var out, log syncBuffer
  	e, o := stderr, stdout
  	t.Cleanup(func() { stderr, stdout = e, o })
  	stderr, stdout = &out, &log
  	cfgPath, pkiDir, _, _, srv := etcdRunServerWith(t, sharedUsernamePolicy, []string{"bob@example.com"})
  	root := srv.Client(t, "root")
  	ctx := context.Background()
  	tacacs, brokerAddr, stop := startRun(t, cfgPath, &out, 1)
  	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
  	loginSession(t, dev, mintAs(t, brokerAddr, pkiDir, "leaf1", "bob@example.com"), &log)
  	resp, err := root.Get(ctx, "/port49/v1/c/leaf1/alice")
  	if err != nil || len(resp.Kvs) != 1 {
  		t.Fatalf("bob's context: %v %v", resp, err)
  	}
  	bobs := resp.Kvs[0]
  	s1 := waitForLedgerSeq(t, root, "/port49/v1/lw/leaf1/alice", 0)
  	loginSession(t, dev, mint(t, brokerAddr, pkiDir, "leaf1"), &log) // alice's, later, at the same key
  	waitForLedgerSeq(t, root, "/port49/v1/lw/leaf1/alice", s1)       // the record holds alice's
  	if !dev.permits("alice", "configure") || lastCommandPrincipal(t, &log) != "user:alice@example.com" {
  		t.Fatal("control: alice's own session was not permitted as alice before the stop")
  	}
  	if err := stop(); err != nil {
  		t.Fatal(err)
  	}
  	tacacs, brokerAddr, stop = startRun(t, cfgPath, &out, 2) // nothing put back
  	dev = tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
  	if !dev.permits("alice", "configure") {
  		t.Fatal("control: alice's session was not permitted after a restart with nothing put back")
  	}
  	if err := stop(); err != nil {
  		t.Fatal(err)
  	}
  	if _, err := root.Put(ctx, string(bobs.Key), string(bobs.Value)); err != nil {
  		t.Fatal(err)
  	}
  	tacacs, _, _ = startRun(t, cfgPath, &out, 3)
  	dev = tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
  	if dev.permits("alice", "configure") {
  		t.Fatalf("bob's context put back over alice's while port49d was stopped was taken as the key's: %v",
  			lastCommandPrincipal(t, &log))
  	}
  }

  // waitForLedgerSeq polls the ledger record at key, as etcd's root, until
  // its seq is above above or 10s pass, and returns it. The keeper writes
  // within a second of a raise; a gauge read at 0 can be the round before
  // (pre-flight I14).
  func waitForLedgerSeq(t *testing.T, root *clientv3.Client, key string, above uint64) uint64 {
  	t.Helper()
  	deadline := time.Now().Add(10 * time.Second)
  	for time.Now().Before(deadline) {
  		if resp, err := root.Get(context.Background(), key); err == nil && len(resp.Kvs) == 1 {
  			var r struct {
  				Seq uint64 `json:"seq"`
  			}
  			if json.Unmarshal(resp.Kvs[0].Value, &r) == nil && r.Seq > above {
  				return r.Seq
  			}
  		}
  		time.Sleep(50 * time.Millisecond)
  	}
  	t.Fatalf("the ledger record at %s never rose above %d", key, above)
  	return 0
  }
  ```

  The fixture's helpers, beside the ones they generalise (`broker_test.go`, `run_test.go`,
  `store_e2e_test.go`):
  - `sharedUsernamePolicy` is `minimalPolicy` with a second subject,
    `{name: b, identity: ["user:bob@example.com"], username: alice, token_ttl: 60s}`, granted
    the same scope and role. Bob and alice then log in to `leaf1` under one username, one
    context key.
  - `brokerConfigWith(t, policyBody, others)` is `brokerConfig` with
    `testpki.WriteLabWith(dir, "alice@example.com", others, time.Now())`, and `brokerConfig`
    becomes `brokerConfigWith(t, policyBody, nil)`.
  - `etcdRunServerWith(t, policyBody, others)` is `etcdRunServer` over `brokerConfigWith`, and
    `etcdRunServer` becomes `etcdRunServerWith(t, minimalPolicy, nil)`.
  - `mintAs(t, brokerAddr, pkiDir, device, email)` is `mintKeyed` with
    `testpki.LabClientFiles(email)`'s certificate and key in place of the lab client's.

  The key path assumes the default prefix (`/port49/`) and `esc`, which leaves `leaf1` and
  `alice` as they are.

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/store/etcd/ ./internal/store/crypt/ ./cmd/port49d/ -run 'LedgerRecord|Keeper|SeededFromTheLedgerRecord|CanWriteTheLedgerRecord' -count=1`
  Expected: FAIL to compile. Then `TestAStartSeededFromTheLedgerRecordDeniesAPutBack` fails at
  `waitForLedgerSeq`, since no keeper writes `lw/`. Once the keeper is wired and `LoadLedger`
  is passed no record, it fails at its last assertion: the restart admits bob's context.

- [ ] **Step 3: etcd's record.** In `keys.go`, add `famLedger = "lw/" // lw/<nas>/<user>: the
  ledger record (plan 7e)` and `func (k keys) ledgerOf(c store.ContextKey) string { return k.root
  + famLedger + esc(c.NAS, c.Username) }`. Create `internal/store/etcd/ledger.go`:

  ```go
  package etcd

  import (
  	"context"
  	"encoding/json"
  	"fmt"
  	"time"

  	clientv3 "go.etcd.io/etcd/client/v3"

  	"github.com/rhwendt/port49/internal/store"
  )

  // ledgerRec is lw/<nas>/<user> (plan 7e, Ruling 4): the highest write
  // sequence known at the key, a revocation floor held at it, and until when
  // the mark is kept (zero: for good). Only the broker's role writes it.
  type ledgerRec struct {
  	Seq       uint64    `json:"seq"`
  	RevokedAt time.Time `json:"revoked_at,omitempty"`
  	Until     time.Time `json:"until,omitempty"`
  }

  // raised is r with m applied: the higher sequence; at the same sequence
  // the later floor and the later keep (a zero keep, for good, wins). ok is
  // false when m raises nothing.
  func (r ledgerRec) raised(m store.LedgerMark) (ledgerRec, bool) {
  	switch {
  	case m.Seq > r.Seq:
  		return ledgerRec{Seq: m.Seq, RevokedAt: m.RevokedAt, Until: m.Until}, true
  	case m.Seq < r.Seq:
  		return r, false
  	}
  	out, ok := r, false
  	if m.RevokedAt.After(out.RevokedAt) {
  		out.RevokedAt, ok = m.RevokedAt, true
  	}
  	if !out.Until.IsZero() && (m.Until.IsZero() || m.Until.After(out.Until)) {
  		out.Until, ok = m.Until, true
  	}
  	return out, ok
  }

  // LedgerMarks is every mark the record holds, read at one revision a page
  // at a time (store.LedgerSource). A record that does not decode is an
  // error naming its key: skipped, a start would admit a put-back there.
  func (s *Store) LedgerMarks(ctx context.Context) (uint64, []store.LedgerMark, error) {
  	prefix := s.k.family(famLedger)
  	end := clientv3.GetPrefixRangeEnd(prefix)
  	from, rev := prefix, int64(0)
  	var out []store.LedgerMark
  	for {
  		opts := []clientv3.OpOption{clientv3.WithRange(end), clientv3.WithLimit(500)}
  		if rev > 0 {
  			opts = append(opts, clientv3.WithRev(rev))
  		}
  		resp, err := s.ctx.Get(ctx, from, opts...)
  		if err != nil {
  			return 0, nil, unavailable(err)
  		}
  		s.saw(resp.Header.Revision)
  		if rev == 0 {
  			rev = resp.Header.Revision
  		}
  		for _, kv := range resp.Kvs {
  			nas, user, ok := lastTwo(string(kv.Key))
  			var r ledgerRec
  			if !ok || json.Unmarshal(kv.Value, &r) != nil {
  				return 0, nil, notDecoded(fmt.Sprintf("ledger record %q", kv.Key))
  			}
  			out = append(out, store.LedgerMark{Key: store.ContextKey{NAS: nas, Username: user}, Seq: r.Seq,
  				RevokedAt: r.RevokedAt, Until: r.Until})
  		}
  		if !resp.More || len(resp.Kvs) == 0 {
  			return uint64(rev), out, nil
  		}
  		from = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
  	}
  }

  // PutLedgerMarks raises each key's record to its mark (store.LedgerSink),
  // never lowering one, by cas on the record's revision; a lost race reads
  // again. A mark is leased to its Until, and one with none has no lease.
  // It stops at the first error and returns it; the keeper owes the rest
  // again.
  func (s *Store) PutLedgerMarks(ctx context.Context, ms []store.LedgerMark) error {
  	for _, m := range ms {
  		live := func(ledgerRec) bool { return true }
  		err := cas(ctx, s.ctx, s.ctxLeases, s.k.ledgerOf(m.Key), live, func(r *ledgerRec, found bool) (bool, time.Time, bool, error) {
  			next, ok := r.raised(m)
  			if found && !ok {
  				return false, time.Time{}, false, nil
  			}
  			if !found {
  				next = ledgerRec{Seq: m.Seq, RevokedAt: m.RevokedAt, Until: m.Until}
  			}
  			*r = next
  			return true, next.Until, false, nil
  		})
  		if err != nil {
  			return err
  		}
  	}
  	return nil
  }
  ```

  One `cas` per key is two round trips. A keeper flushing every second writes only the keys
  raised since the last flush: logins and refreshes, not touches. Batch them into transactions
  of up to 64 keys if Task 16's fleet test shows the keeper falling behind, and say so in the
  report if it does.

- [ ] **Step 4: The roles.** In `roles.go`:
  - `daemonReads = []string{famMark, famMeta, famLedger}`;
  - `famSuperseded` is in `daemonNever` (Task 5);
  - in `CheckIdentity`'s probes, add writes to `famLedger` and `famSuperseded`, and a read of
    `famSuperseded`. The broker must be allowed all three, and the daemon refused all three;
  - `beyondDaemon` already refuses a write grant outside `daemonWrites`, which `lw/` is not
    among, and any grant on `daemonNever`;
  - update the role's comment: the daemon reads the ledger record and never writes it, and
    never touches the superseded record.

  In `cmd/port49d/storeroles_test.go`, the expected output gains `etcdctl role grant-permission
  port49_daemon read --prefix=true /port49/v1/lw/`.

- [ ] **Step 5: The keeper.** In `crypt/follow.go`:

  ```go
  // KeepLedger writes l's raised marks to sink every `every` until ctx ends
  // (plan 7e, Ruling 4): the keyspace's holder alone runs it. A write that
  // fails is said once per run of failures, and its marks are owed again.
  // report is told after each round how many marks are owed
  // (port49_ledger_pending), and whether the context feed is down
  // (port49_ledger_behind): then the ledger is not raised by other
  // processes' logins, and pending cannot show what the record misses. When
  // ctx ends it reports (0, false) once, so a runner whose duties stopped
  // shows no stale value (pre-flight I11).
  func KeepLedger(ctx context.Context, l *Ledger, sink store.LedgerSink, every time.Duration,
  	report func(pending int, behind bool), logf func(string, ...any)) {
  	t := time.NewTicker(every)
  	defer t.Stop()
  	defer report(0, false)
  	failing := false
  	for {
  		select {
  		case <-ctx.Done():
  			return
  		case <-t.C:
  		}
  		ms := l.Dirty()
  		if len(ms) > 0 {
  			wctx, cancel := context.WithTimeout(ctx, 10*every+5*time.Second)
  			err := sink.PutLedgerMarks(wctx, ms)
  			cancel()
  			switch {
  			case err != nil:
  				l.Redirty(ms)
  				if !failing {
  					logf("store: writing the ledger record failed (%v); %d mark(s) owed, tried again every %v; a "+
  						"context put back at those keys would be taken after a restart", err, len(ms), every)
  					failing = true
  				}
  			case failing:
  				logf("store: the ledger record is written again")
  				failing = false
  			}
  		}
  		report(l.Pending(), !l.Fence().Up())
  	}
  }
  ```

  In `metrics.go`, add:
  - `LedgerPending prometheus.Gauge` (`port49_ledger_pending`, "context keys whose mark the
    ledger record does not yet hold; above 0 for a minute, a context put back at one would be
    taken after a restart");
  - `LedgerBehind prometheus.Gauge` (`port49_ledger_behind`, "1 while the ledger record's
    keeper runs with its context feed down: the record does not follow other processes'
    logins, whatever port49_ledger_pending says").

  Add both to `TestNewRegistersEveryMetric`.

- [ ] **Step 6: port49d keeps it.** In `cmd/port49d/store.go`'s `openStores` (etcd):
  - `crypt.LoadLedger(ctx, d, d, keys, ledger)`: the daemon's identity reads `lw/`.
  - `crypt.FollowContexts(ctx, d, d, keys, ledger, rev, …)`, replacing Task 8's `nil`: a
    compacted watch's rescan seeds from the record too (re-check R1). A rescan whose read of
    `lw/` fails is a failed watch, tried again every second, with the fence shut meanwhile.
  - **A refused read** (pre-flight M17). Roles applied before 7e lack the daemon's read on
    `lw/`, and the read is `store.ErrRefused`. That is a store fault, not an outage: waiting
    does not mend it. It ends the start with:

    ```
    port49d: store: the daemon's role cannot read lw/, the ledger record: apply port49d store-roles (plan 7e) as etcd's root, then start again
    ```

    It is a `storeFault`, so a cold start exits 1 and a start after a store gone retries, as
    7d's identity faults do.
  - In the returned `stores`, a `keep func(ctx)` runs `crypt.KeepLedger(ctx, ledger, b,
    time.Second, func(n int, behind bool) { m.LedgerPending.Set(float64(n));
    m.LedgerBehind.Set(b2f(behind)) }, logf)`. `b` is the broker's raw store, which holds the
    hold in 7e-1. `b2f` is 1 for true.
  - `runOnce` runs and joins it as it does the feeds. The keeper's final `(0, false)` zeroes
    both gauges when the run ends.

  Add `TestARefusedLedgerRecordReadNamesStoreRoles` to `cmd/port49d/store_test.go`: on a TLS
  member whose daemon role has no read on `lw/` (7d's roles, `etcd.Roles` minus that grant),
  `openStores` fails with a `*storeFault` whose text holds `apply port49d store-roles (plan
  7e)`.

  On memory there is no record and no keeper.

- [ ] **Step 7: Run everything, then record 7e-1 as built.**

  Run: `make build && make test && make vet && make test-race`
  Expected: PASS.

  In `docs/superpowers/plans/README.md`, under "Plan 7d — As built", add a heading `### Plan 7e
  — As built`, with a paragraph "**7e-1** (`feature/broker-process`, base `b508ba0`)". List
  each task's commits (8a included) and what differs from this plan's text, as the 7d section
  does from its ledger. Name every interface 7e-1's review changed: the controller amends
  7e-2's tasks to match before dispatching Task 11. Add 7e-1's operator notes, the 7e-1 half of
  "Operator-facing notes" below, as amended by what was built.

- [ ] **Step 8: Commit.**

  ```bash
  gofmt -w internal/store internal/daemon/metrics cmd/port49d
  make build && make test && make vet
  git add internal/store/etcd/keys.go internal/store/etcd/roles.go internal/store/etcd/roles_test.go \
    internal/store/etcd/ledger.go internal/store/etcd/ledger_test.go internal/store/crypt/follow.go \
    internal/store/crypt/follow_test.go internal/daemon/metrics/metrics.go internal/daemon/metrics/metrics_test.go \
    cmd/port49d/store.go cmd/port49d/main.go cmd/port49d/storeroles_test.go cmd/port49d/store_e2e_test.go \
    cmd/port49d/store_test.go cmd/port49d/broker_test.go cmd/port49d/run_test.go docs/superpowers/plans/README.md
  git commit -m "feat(store): the ledger record, kept by the keyspace's holder

  lw/<nas>/<user> holds each key's highest write sequence, raised once a
  second and never lowered; the daemon's role reads it and cannot write
  it. A start seeds its ledger from it before it scans, so a context put
  back while port49d was stopped is denied at a key the record holds a
  later mark for: 7d's restart residual, closed but for the keeper's lag
  (plan 7e Ruling 4). port49_ledger_pending gauges what it owes, and
  port49_ledger_behind says when the keeper's feed is down; both read 0
  once the keeper stops (pre-flight I11). A daemon role without the read
  on lw/ is told to re-apply store-roles.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

**7e-1 ends here.** The controller runs the whole-branch review, merges, and only then
dispatches Task 11 on `feature/broker-split` off the new `main`.

---

# Part 7e-2: the two processes (`feature/broker-split`, off `main` after 7e-1)

### Task 11: The spec and the design say what 7e-2 builds, and L37 and L38 open

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`
- Modify: `docs/design/2026-08-21-port49-design.md`

**Interfaces:** none. 7e-2's tasks cite the text this one writes.

No code. As Task 1: a one-line fragment to find, and the text to put after it or in its place.
Nothing here asserts what a device does. The device cells it adds cite L37 or L38 as open.

- [ ] **Step 1: Decision 36, 7e-2's part.** At the end of decision 36's bullets, add the bullets
  below. Then replace its closing `(§5.1.4, §5.6, §5.7, §14; design document §8, §12, §17)`
  with `(§5.1.3, §5.1.4, §5.6, §5.7, §12, §14, §15; design document §6, §8, §12, §13, §15, §17,
  §19)` (pre-flight M12).

  ```markdown
  - **Two processes.** `port49-broker` serves the API and holds the broker's etcd identity alone;
    `port49d` serves TACACS+ and holds the daemon's identity and the device keys alone. Any
    number of each run on one keyspace. port49d holds no hold, and a second one serves beside the
    first. The in-process broker stays for `store.backend: memory` only; on etcd a `broker:`
    block in port49d.yaml is refused, naming the move. A stolen port49d host therefore holds the
    daemon's role alone, which cannot write a mark, `meta/`, the ledger record or the superseded
    record, and a stolen broker host holds no device key.
  - **The configuration.** `port49-broker.yaml` is port49d.yaml's schema under the broker's role:
    it requires `broker:` (with `broker.state_dir`, where the persisted CRLs are kept),
    `store.backend: etcd` with `store.etcd.broker`, `encryption:`, an inventory, `key_refs:` (the
    names a policy may assign, no secrets) and `admin_socket`; it refuses `listen`, `keys:`,
    `store.etcd.daemon`, `accounting`, `limits`, the receipt windows, `platforms`, `policy:`,
    `broker.revocations_file`, and any `lab:` key but the seed tokens. port49d.yaml on etcd
    requires `policy: {file, watch_interval}` and refuses `broker:`, `store.etcd.broker` and
    `lab.seed_tokens`.
  - **The runner.** The keyspace hold is the runner's: one port49-broker at a time. On taking it,
    it records the seal keys, re-indexes the contexts the index lost, puts back every revocation
    its copy of the marks holds and the store lacks, applies every standing mark to the kept
    contexts, purges the unspent tokens only as below, and carries the policy in force into every
    kept context; then it runs the sweep, the re-index, the ledger record's keeper, the context
    half of every refresh pass, and a full context pass whenever another replica asks for one.
    Every replica serves the API and the admin socket, runs the token half of its own reload's
    passes and certificate status, and follows the contexts and the marks. A runner that loses
    the hold stops those duties at once, keeps serving the API, and tries to take the hold again
    every 5s; a broker's readiness is never the store's.
  - **The purge at a takeover.** The runner records in `meta/judged` the bundle in force, with its
    policy, when a pass leaves `port49_policy_refresh_pending` at 0 and every broker process
    serves that bundle, and at a takeover whose carry leaves nothing owed. A runner taking the
    hold with another bundle in force (an edit made while none ran, a runner gone before its
    settle pass, or a replica serving another bundle) purges every unspent token and records the
    instant for every key; with the same, it purges none, so a rolling restart of the brokers
    keeps everyone's tokens. A token minted in the moment between that instant and the purge is
    purged too, and its login fails `token_not_found`. After an etcd restore, `meta/judged` is
    deleted before any broker starts, so the first takeover purges.
  - **The restore witness.** The runner rewrites `meta/witness` (its name and the time, no
    secret) at most once a second, whenever the store has moved past it. Every broker follows
    it and keeps the highest `ModRevision` it has seen in `broker.state_dir/witness.json`. A
    restored key keeps its `ModRevision`, with or without `--bump-revision`, so a runner that
    reads the witness below its replica's record, at a takeover or while it runs, knows the
    store was restored: it takes `meta/judged` as absent and purges every unspent token, so a
    token redeemed since the snapshot stays spent even when the runbook's delete was
    forgotten. It takes the store's witness as its record only once the purge is done. A
    replica with no record says it cannot tell, and goes by `meta/judged`; a snapshot taken
    within about a second of the last witness recorded is not caught.
  - **The settle pass** is 30s or two policy watch intervals and 5s after a swap, whichever is
    longer, and the policies since the last settled pass are kept until it completes, so a token
    another replica minted under the replaced policy before it reloaded is judged.
  - **Policy across replicas.** Every broker process records the bundle it serves, leased, and
    says when it is not the runner's (`port49_policy_bundle_matches_runner`). A replica that
    swaps, or starts, while it is not the runner asks the runner for a full context pass, which
    judges every live context against the policy in force; a replica that dies unreloaded is
    covered by a full pass the runner owes once its tokens have expired, `token_ttl` (at most
    15 minutes) after it last saw that replica's bundle. Until then the runner records no bundle
    as judged. Each port49d, whose role cannot write `meta/`, reads the bundle last judged and
    sets the same gauge, saying when its own policy differs.
  - **The reload guard at a start.** A broker process whose policy file the reload guard would
    refuse against the policy `meta/judged` records stays not ready, mints nothing and takes no
    hold until the file is fixed, so a restart cannot load a file a running broker refused.
  - **The daemon's start on etcd** waits for the store and checks its identity, reads (never
    writes) the seal-key record, loads the marks, seeds the ledger from the record and a scan, starts
    both feeds and binds. It reloads its policy file for admission, quarantine and redaction and
    carries nothing into live contexts. It probes the store every sixth of `hold_ttl` through its
    context pool and the feed fence, so an idle port49d goes dark as one under load does, on a
    store or a context feed that has stopped; a run after a store gone keeps the ledger and the
    marks.
  - **The revocations file is retired on etcd**, which persists the marks; it stays for the memory
    store, with `port49d init-revocations`. Each broker process keeps its own copy of the marks it
    followed, adding each mark and removing a mark only on a lift the watch delivered. The runner
    puts back any mark in its copy the store lacks, at a takeover and before its marks feed
    reloads, and says how many: an etcd restore's lost revocations are revoked again, and a lift
    a copy missed is revoked again too, which the line says how to lift. A put-back that fails
    refuses the reload, so the marks feed stays down and is tried again, rather than lifting
    what the restore lost.
  - **A mark a reload finds missing stays in force on port49d.** The daemon's role cannot put a
    mark back, so each port49d keeps every mark it enforces that its marks feed's reload finds
    missing, until a lift its feed delivers or its restart, and says how many and which. An
    etcd restore under a running port49d therefore lifts nothing there before the runner puts
    the marks back; a lift made on a broker while that port49d's feed was down is kept too,
    which denies more. This amends "a compacted watch loads them again and applies the
    difference" above for port49d alone.
  - **A reconnect is not a reload.** Both feeds ask etcd for progress notifications and resume a
    re-watch from the last change or progress delivered, so a reconnect within the compaction
    retention reloads nothing, and a lift made meanwhile arrives as a lift.
  - **The sockets.** port49-broker's admin socket answers `port49 revoke` (revoke, lift, list).
    port49d's answers `port49 keys diagnose`, and, with no broker in it, a revocation there is
    refused naming port49-broker's socket.
  - **Revoking with every broker down.** `port49-broker revoke --offline` revokes and lifts
    through the store on the broker's identity, with no API and no hold, in decision 32's order.
    With no broker host, a mark written as etcd's root under `rv/` is followed by every port49d,
    which denies the session's next command; tokens are deleted only by the next revocation that
    reaches them.
  ```

- [ ] **Step 2: Decisions 32, 34 and 35 amended.** At the end of decision 32's paragraph, before
  `(§5.1.4, §5.7, §12; design document §11, §12, §17)`, add `*Amended by decision 36 (plan 7e):*
  on etcd the store keeps the marks, each broker process a copy, and the file is retired; a lift
  is port49-broker's admin socket's, or its offline command's.` At the end of decision 34's "The
  revocations file" bullet, add `On etcd it is retired (decision 36).`

  Decision 35's three "until plan 7e" clauses (pre-flight M12). Each replacement quotes whole
  lines, as they stand:
  - **"What store write access still yields"** (spec line 6597). Replace the two lines

    ```
      That holds for the daemon's credential taken alone: until plan 7e port49d also holds the
      broker's, whose role is the whole keyspace, marks included, and under
    ```

    with

    ```
      That holds for the daemon's credential, which since plan 7e is all a port49d host holds
      (decision 36): the broker's, whose role is the whole keyspace, is port49-broker's, and under
    ```

    The next line, `` `store.etcd.roles: unenforced` the daemon's is too.``, stays.
  - **"The daemon's role cannot"** (spec line 6701). Replace the two lines

    ```
        taken alone: until plan 7e port49d also holds the broker's, whose role is the whole
        keyspace, marks included, and under `store.etcd.roles: unenforced` the daemon's is too.
    ```

    with

    ```
        alone, which since plan 7e is all a port49d host holds (decision 36); under
        `store.etcd.roles: unenforced` the daemon's is the whole keyspace too.
    ```
  - **"One port49d per keyspace"** (spec line 6716). Replace the line
    `- **One port49d per keyspace until plan 7e.**` with `- **One port49d per keyspace in plan
    7d.** *Amended by decision 36 (plan 7e):* any number of port49d serve a keyspace and hold
    nothing; the hold below is port49-broker's runner's.`

  Check the result reads as a sentence in each bullet before committing, and fix the joins
  minimally if a neighbouring line differs from what is quoted here.

- [ ] **Step 3: §5.1.3, who refreshes.** In §5.1.3, after the paragraph that says the refresh
  runs after every reload (search `#### Policy reload` and the first paragraph after it), add:

  ```markdown
  With several port49-broker processes on one store (plan 7e), the one holding the keyspace (the
  runner) carries each policy into the live contexts; every process deletes the unspent tokens
  its own policies minted that the policy in force would not give. port49d carries nothing: it
  reloads its policy for admission, quarantine and redaction alone. With every broker stopped, an
  edit changes admission at once and live contexts when a runner returns (§13, decision 36).
  ```

- [ ] **Step 4: §12, tooling.** In §12, where `port49d store-roles` is described (search
  `port49d store-roles`), replace its invocation with `port49d store-roles --config port49d.yaml
  --broker-config port49-broker.yaml` and add after the paragraph:

  ```markdown
  `port49-broker --config port49-broker.yaml` is the broker on etcd (plan 7e; decision 36). It
  takes no subcommand. `port49 revoke --socket <port49-broker's admin_socket>` revokes, lifts and
  lists on it.
  ```

- [ ] **Step 5: §14, the split.** Under "Shared store" in §14, add:

  ```markdown
  - **The split**: port49d.yaml on etcd naming the broker's identity, or a `broker:` block, is
    refused; port49-broker.yaml naming `keys:` or the daemon's identity is refused. A login on
    one port49d is answered on another. A revocation made on one port49-broker closes the held
    connections it names on another, and every port49d denies the session's next command. A
    runner that stops, or is cut off from etcd without releasing its lease, is replaced within
    `hold_ttl` and a third; a takeover purges only when the bundle in force is not the one last
    judged, and a clean takeover records its bundle as judged. With every broker stopped, an
    open session's next command is answered, and a revocation made offline, or as etcd's root,
    denies it.
  - **Across replicas**: a replica serving another bundle than the runner's says so, and its
    reload has the runner carry a context it made under the old policy. A start whose policy
    file the reload guard refuses against the judged bundle stays not ready and takes no hold. A
    mark in a broker's copy that the store lost is put back by the runner, named in its line,
    and a mark lifted through the watch is not. A port49d whose policy is not the bundle last
    judged says so.
  - **The restore witness**: an etcd restore with `meta/judged` left as the snapshot's still
    purges, at the takeover or under a running runner, when a broker's `witness.json` recorded
    a later `meta/witness` than the store holds, with `--bump-revision` too; a token redeemed
    after the snapshot stays spent.
  ```

- [ ] **Step 6: §15, L37 and L38.** After the L36 row, add:

  ```markdown
  | **L37** | On the split deployment (plan 7e; two port49d replicas and port49-broker on one etcd, each device listing both replicas as TACACS+ servers): whether a session opened through one replica has its next command answered by the other once the first stops; whether, with every broker stopped, an open session runs on and a token minted before the stop logs in; whether a revocation made on port49-broker denies the session's next command on either replica; and how long after its store hangs a port49d with no hold closes its listeners. | The failure model's "Broker unavailable" and store rows on the split deployment (design §12), and decision 36 | EOS, NX-OS, IOS-XE, vJunos-router, vSRX | open — added 2026-10-03 (plan 7e) |
  | **L38** | On IOS-XE, whether an open session's command runs under local authorization once port49 is unreachable, by the command (`show privilege`, `show version`) and by what port49 answered before it went away (nothing; a `FAIL store_unavailable`): `quarantine-cisco_iosxe.md` ran `show privilege` with port49d stopped, and `L35-cisco_iosxe.md` refused `show version` once port49d went dark on a hung store. | Design §12's IOS-XE cells for a store outage and an unreachable port49 | IOS-XE | open — added 2026-10-03 (plan 7e; plan 7d's carry) |
  ```

- [ ] **Step 7: Design §6, §12, §13, §15, §17, §19.**
  - **§6, Components.** After the table, add a paragraph: "**As built (plan 7e).** The broker
    is `port49-broker`, its own process, and the daemon `port49d`; any number of each run on one
    store, and one broker at a time, the runner, carries policy into live contexts (policy engine
    spec §13, decision 36). With the memory store both run in one `port49d`, for the lab and the
    tests."
  - **§12, the matrix.** In the "Broker unavailable" row, after `⚠ unaffected within the
    staleness ceiling; ✗ beyond it`, add `(on the split deployment, what each image does is
    policy engine spec §15 L37, open)`. In the "Store hangs" row, after `it closes every
    listener.`, add `On the split deployment port49d holds no hold: it closes them once a
    pool's circuit has stayed open for hold_ttl, which its probe brings on with no device
    traffic (L37, open).`
  - **§13.** Replace the bullet `- **One keyspace per port49d until plan 7e.** …` (through
    `…is not ready.`) with:

    ```markdown
    - **Any number of port49d and port49-broker per keyspace** (plan 7e). port49d holds nothing:
      run several, and replace them one at a time, whatever runs them (systemd units, containers,
      or a Kubernetes workload); a new one may start beside the old. port49-broker's replicas
      share the runner's hold: one runs the start, the sweep and the policy refresh, and another
      takes over within `hold_ttl` and a third when it stops. Set the same
      `broker.policy_watch_interval` on every replica.
      Each port49d needs its own `listen` address, which devices list as one more TACACS+
      server, and its own `admin_socket`, `metrics_listen` and `accounting.spool_path`: two on
      one host (two systemd units, or two containers on the host's network) differ in each, and
      every one must see the device's true source address (Source address visibility, above;
      policy engine spec §15 L39 measures the container and Kubernetes cases). Each
      port49-broker likewise needs its own `broker.listen`, `metrics_listen` (default `:9050`),
      `admin_socket` and `broker.state_dir`.
    - **`broker.state_dir` survives a restart** (plan 7e). It holds the replica's `marks.json`
      and `witness.json` (policy engine spec §13, decision 36). Under systemd it is a directory
      on the host; in a container, a named volume; on Kubernetes, a volume per replica that
      outlives the pod, never an empty directory. A broker that starts without it cannot tell
      that etcd was restored.
    - **The admin sockets are local.** `port49 revoke` speaks to port49-broker's
      `admin_socket` and `port49 keys diagnose` to port49d's, each a Unix socket on the process's
      own filesystem: run them on the host, or inside the container or pod, that runs the process.
    - **Keep every broker host's clock synchronised (NTP).** A replica whose clock runs behind
      another's can take a token that the other's revocation or refresh deleted, as superseded,
      for one minted after it, and answer an idempotent replay with that deleted token: its
      login then fails `token_not_found`. That costs availability, never an admission.
    - **Run etcd 3.5.8 or later** (3.4.24 on 3.4). The feed fence rests on etcd never sending a
      progress notification ahead of an event it has not delivered, which earlier releases do
      not keep (etcd #15220).
    ```

    In the "Backups" bullet, replace these two whole lines (pre-flight M2: quoted as they stand):

    ```
    - **Backups.** Back etcd up as a database holding the revocation marks. Until plan 7e retires
      it, `broker.revocations_file` is kept as well.
    ```

    with:

    ```
    - **Backups.** Back etcd up as a database holding the revocation marks. On etcd
      `broker.revocations_file` is retired (plan 7e): each port49-broker keeps its own copy of the
      marks it followed, in `broker.state_dir/marks.json`, and the runner puts back any the store
      lost. Beside it, `witness.json` records the latest restore witness that broker saw
      (decision 36). Back `broker.state_dir` up with the broker's host.
    ```

    Then replace the whole bullet that begins `  - **A restore rolls the marks back too.**` (its
    six lines, through `snapshot, since a mark in either the file or the store stands.`) with
    (pre-flight I5, I12; Ruling 7):

    ```
      - **A restore rolls the marks back too.** A mark added since the snapshot is gone from
        the store, and one lifted since is back. The runbook, on etcd since plan 7e:
        1. Stop every port49-broker. port49d may run on: it goes dark while the store is down,
           and reaches the store again only once step 3 reopens it.
        2. Restore with `--bump-revision` and `--mark-compacted` (below), and start the restored
           member or members serving clients on loopback only (for example `--listen-client-urls
           https://127.0.0.1:2379 --advertise-client-urls https://127.0.0.1:2379`, the TLS flags
           unchanged; the peer URLs stay as they are, so quorum forms). No port49d or broker can
           reach the restored store yet. Without `--bump-revision`, also restart every port49d, but
           only once step 4's first runner has said its put-back line: a process started after the
           restore seals below what one that ran across it knows, and their logins are denied there
           (`store_unavailable`) until that process writes at the key; and a port49d restarted
           before the put-back loads the restored marks, so it enforces none the restore lost until
           the runner puts them back.
        3. On the loopback address, as etcd's root, delete the unspent tokens and `meta/judged`:
           `etcdctl --endpoints https://127.0.0.1:2379 del --prefix <prefix>v1/t/`, then
           `etcdctl --endpoints https://127.0.0.1:2379 del <prefix>v1/meta/judged` (in a container
           or on Kubernetes, run `etcdctl` in the member's own network namespace). Only once both
           have landed, restart the member or members on their usual client URLs. Do not open them
           before: a restore brings back every single-use token redeemed since the snapshot,
           unspent, and a port49d that reaches the store before the token delete, one that ran
           across the restore too, redeems such a token a second time, and no line says so; the
           first runner's purge (step 4) comes minutes later. Where serving on loopback is not
           possible, stop every port49d in step 1 as well, and start them after both deletes once
           step 4's first runner has said its put-back line. With `meta/judged` gone the first
           runner purges too. With it gone, the reload guard at start has no judged bundle to
           check against: the first start after the restore says so and goes on, and a refused
           policy file is not caught then. Check `broker.policy_file` on every broker host before
           step 4. If the `meta/judged` delete is forgotten, a runner whose
           `broker.state_dir/witness.json` survived finds the restored `meta/witness` below its
           record and purges anyway (decision 36, the restore witness); one whose `state_dir` was
           lost or is new cannot, and a snapshot taken within about a second of the last witness
           (two, if a broker was killed rather than stopped) is not caught: the deletes are still
           the procedure. After a restore without `--bump-revision`, a later takeover by another
           broker may purge once more and say the store was restored; `--bump-revision` avoids it.
        4. Start the brokers, a broker whose `broker.state_dir` survived the restore first:
           one with no `witness.json` started first after a `--bump-revision` restore means a
           forgotten step 3 is never caught. The first runner puts back every mark its `marks.json` holds that
           the store lacks, and names them; it applies every mark to the restored contexts,
           and purges.
        5. Lift again, with `port49 revoke --lift`, any mark that was lifted since the snapshot
           and that the line says was put back.
    ```

    The bullet `  - **Restored under a running port49d**, …` stays: it describes one process,
    which is what L35 measured. At its end, after `Restore with port49d stopped (below) and this
    does not arise.`, add (final review 7e-1 C-1, as 7e-2 leaves it):

    ```
      Since plan 7e a mark the restore lost stays in force on every port49d that ran across it,
      until a lift its marks feed delivers or its restart, and each says how many and which: the
      daemon's role cannot put it back. The first runner puts it back from its `marks.json`
      (step 4 below). On the memory store nothing is restored, and `broker.revocations_file`
      stays.
    ```

    After the runbook's step 5, add a sixth step:

    ```
        6. A `meta/superseded_all` that does not decode (`etcd: superseded record
           "<prefix>v1/meta/superseded_all" does not decode`) fails every idempotent replay that
           reads it. Delete it as etcd's root (`etcdctl del <prefix>v1/meta/superseded_all`); the
           next purge writes it again. Until then a replay of a token the last purge deleted may
           be answered with that token, whose login fails `token_not_found`: availability, never
           an admission.
    ```
  - **§15.** In the store's exports list (`The store (plan 7d) exports:`), after
    `` - `port49_store_index_records_undecodable_total`. ``, add (Task 1 review m-1; final review
    7e-1 M-4):
    - `port49_store_feed_up{feed}` and `port49_store_feed_rescans_total{feed}`, `feed` being
      `contexts` or `marks` (plan 7e);
    - `port49_ledger_pending` and `port49_ledger_behind`, on the runner (plan 7e);
    - `port49_store_fence_timeouts_total` (plan 7e; the paragraph below the alarms says what it
      tells apart);
    - `port49_policy_bundle_matches_runner` (plan 7e).

    The list's last item then ends with `;` and the new last with `.`. In the alarms list, add:
    - `port49_store_feed_up{feed}` 0 for longer than `hold_ttl`;
    - any increase of `port49_store_feed_rescans_total`;
    - on the runner, `port49_ledger_pending` above 0 for a minute, or `port49_ledger_behind` at 1
      (pre-flight I11);
    - `port49_policy_bundle_matches_runner` 0 on a broker for longer than twice
      `broker.policy_watch_interval`, and on a port49d for longer than its settle delay
      (`max(30s, 2 × policy.watch_interval + 5s)`) and one `policy.watch_interval` more, since
      the bundle last judged moves only at the runner's settle pass;
    - the sum of `port49_store_keyspace_held` over port49-broker's replicas 0 for twice
      `hold_ttl`.
  - **§17, internal interfaces.** In the row `| daemon, broker → token store |`, add after `under
    port49's roles`: `; each process holds its own component's certificate alone (plan 7e)`.
  - **§19, step 7.** After `the API authorization model.` add ` Plan 7e splits the broker into its
    own process, \`port49-broker\`, and lets any number of each run on one store.`

- [ ] **Step 8: Check the edits.**

  ```bash
  grep -n '^| \*\*L37\*\*\|^| \*\*L38\*\*' docs/design/2026-08-23-policy-engine-spec.md
  grep -n 'The runner.\*\* The keyspace hold' docs/design/2026-08-23-policy-engine-spec.md
  grep -n 'Revoking with every broker down' docs/design/2026-08-23-policy-engine-spec.md
  grep -n 'Any number of port49d and port49-broker per keyspace' docs/design/2026-08-21-port49-design.md
  grep -n 'del <prefix>v1/meta/judged' docs/design/2026-08-21-port49-design.md
  grep -c 'until plan 7e\|Until plan 7e' docs/design/2026-08-21-port49-design.md docs/design/2026-08-23-policy-engine-spec.md
  grep -c 'The restore witness' docs/design/2026-08-23-policy-engine-spec.md
  grep -n 'the reload guard at start has no judged bundle' docs/design/2026-08-21-port49-design.md
  grep -n 'A mark a reload finds missing stays in force on port49d' docs/design/2026-08-23-policy-engine-spec.md
  grep -n 'etcd #15220' docs/design/2026-08-21-port49-design.md
  grep -c 'port49_store_fence_timeouts_total' docs/design/2026-08-21-port49-design.md
  grep -c 'Recreate' docs/design/2026-08-21-port49-design.md
  grep -n 'Under systemd it is a directory' docs/design/2026-08-21-port49-design.md
  ```

  Expected: two rows; then one line each; then `0` for each file; then `2` (decision 36 and
  §14); then one line (the runbook's step 3); then one line each; then `2` (the exports list
  and the fence paragraph); then `0` (7d's Kubernetes-only rollout advice is gone); then one
  line (`broker.state_dir` stated for systemd, containers and Kubernetes alike).

- [ ] **Step 9: Commit.**

  ```bash
  git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
  git commit -m "docs: decision 36 (7e-2): two processes, the runner, the retired file; open L37 and L38

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 12: port49d's code moves into `internal/port49d`

**Files:**
- Move: every `cmd/port49d/*.go` to `internal/port49d/*.go`, `package main` → `package port49d`
- Create: `cmd/port49d/main.go` (the shim)

**Interfaces:**
- Produces: `func port49d.Main(args []string) int`, today's `main` body with `os.Args[1:]` for
  `args` and its exit codes returned, never `os.Exit`ed.

A move, with no behaviour change. `cmd/port49-broker` (Task 15) needs port49d's start, store,
reloader, certificate status and revocations code, and Go cannot import a `main` package. Every
test moves with its code and keeps its package-internal access.

- [ ] **Step 1: Move.**

  ```bash
  mkdir -p internal/port49d
  git mv cmd/port49d/*.go internal/port49d/
  sed -i 's/^package main$/package port49d/' internal/port49d/*.go
  ```

- [ ] **Step 2: `Main`.** In `internal/port49d/main.go`, rename `func main()` to `func Main(args
  []string) int`.
  - Parse `args` with a `flag.NewFlagSet("port49d", flag.ContinueOnError)` in place of the
    global `flag`.
  - Read the subcommand from `args[0]`.
  - Return each `os.Exit` code instead.

  Update the package comment's first line to `// Package port49d is the TACACS+ daemon, and on
  memory its in-process broker (cmd/port49d).` Create `cmd/port49d/main.go`:

  ```go
  // Command port49d is the TACACS+ daemon (internal/port49d).
  package main

  import (
  	"os"

  	"github.com/rhwendt/port49/internal/port49d"
  )

  func main() { os.Exit(port49d.Main(os.Args[1:])) }
  ```

- [ ] **Step 3: Run everything.** Comments that name `cmd/port49d/<file>` in other packages
  (`internal/fence`, `internal/keyfile`, `internal/daemon/server`, `tests/lab/harness_test.go`)
  name `internal/port49d/<file>` now. Fix them.

  Run: `make build && make test && make vet && make test-race`
  Expected: PASS, with `internal/port49d` running exactly the tests `cmd/port49d` ran (compare
  `go test -list . ./internal/port49d/ | wc -l` with the count at `main`).

  `make test-race` covers `./internal/...`, so this move race-tests port49d's code under it for
  the first time (pre-flight M13; 7d ran `go test -race ./cmd/...` by hand). A race it reports
  is pre-existing: fix it here, in its own `fix(port49d):` commit before the move's, so it
  surfaces at the move and not in Task 15.

- [ ] **Step 4: Commit.**

  ```bash
  git add cmd/port49d internal/port49d internal/fence internal/keyfile internal/daemon/server tests/lab/harness_test.go
  git commit -m "refactor(port49d): move the daemon's code into internal/port49d

  No behaviour change: cmd/port49d is a shim over port49d.Main, so
  cmd/port49-broker can run the same start, store and reloader code
  (plan 7e).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 13: Two configurations, and neither holds the other's credential

**Files:**
- Modify: `internal/config/config.go` (`Role`, `PolicyConfig`, `Config.Policy`, `Config.Role`,
  `LoadBroker`, `key_refs`, `broker.state_dir`, `checkStore`, the refusals, `KeyRefs`,
  `StoreBlocks` in place of `StoreOf`)
- Create: `internal/config/broker_role_test.go`. `internal/config/broker_test.go` exists at
  `a5e4fe8`, with `loadWith`, `brokerBlock` and the 7a/7b broker-block tests, and is not
  touched (pre-flight I7).
- Modify: `internal/config/store_test.go` (`checkStore` takes the role; `StoreBlocks`),
  `internal/config/config_test.go`
- Modify: every reader of `cfg.Broker.PolicyFile` and `cfg.Broker.PolicyWatchInterval` in
  `internal/port49d` (`loadPolicy`, `parseBundle`, `reload.go`), which read `cfg.Policy` now
- Modify: `internal/port49d/broker_test.go` (`brokerConfigWith` sets `Policy:
  &config.PolicyConfig{File: pol}`), `internal/port49d/reload_test.go` (`newReloadRig` sets
  `rig.cfg.Policy.WatchInterval = time.Second` beside the broker's): both build
  `config.Config` by hand, and would leave `Policy` nil (pre-flight 7e-2 P-8)
- Modify: `internal/port49d/storeroles.go` (`StoreBlocks` for `StoreOf`, no other change: Task 16
  adds `--broker-config`)

**Interfaces:**
- Produces:
  - `type config.Role int` with `RoleDaemon` (the zero value) and `RoleBroker`; `Config.Role`.
  - `type config.PolicyConfig struct { File string; WatchInterval time.Duration }`;
    `Config.Policy *PolicyConfig`. It is set from `broker.policy_file` with an in-process broker,
    or from `policy:`; nil with neither.
  - `func config.LoadBroker(path string) (Config, error)`.
  - `BrokerConfig.StateDir string` (`yaml:"state_dir"`), required under the broker role,
    absolute, a directory that exists.
  - `fileConfig.KeyRefs []string` (`yaml:"key_refs"`). `Config.KeyRefs()` is `key_refs` under the
    broker role and `keys:`' names under the daemon's.
  - `fileConfig.Policy *policyYAML` (`yaml:"policy"`): `{file, watch_interval}`.
  - `func config.StoreBlocks(raw []byte) (StoreConfig, error)` (pre-flight I8). It replaces
    `StoreOf`: either file's `store:` block, decoded strictly and checked for shape alone, by
    `checkStoreShape`:
    - checked: endpoints, the CA, durations, no identity named `root`, each named identity's
      files;
    - not checked: any role's requirement. Either identity may be named or absent.
    `store-roles` (Task 16) reads both files through it, so a 7d port49d.yaml naming both
    identities still yields both, while `Load` under the daemon's role refuses that file.
  - `checkStore(s storeYAML, role Role, hasBroker, hasPolicy, hasAdminSocket bool)`: the role's
    requirements over `checkStoreShape`.

Rulings 1, 2, 12, 14.

- [ ] **Step 1: The failing tests.** Create `internal/config/broker_role_test.go`. Its fixtures are
  built from the package's own (pre-flight M1):
  - `config_test.go`'s `inv` (whose key group names `prod_key`), `write(t, name, body)`,
    `setKeyEnv(t)` (`PORT49_ENC_V2` and the shared secrets) and `sampleHead`;
  - `store_test.go`'s `storeFiles(t)`, which writes `ca.pem`, `d.pem`, `d-key.pem`, `b.pem`
    and `b-key.pem` at mode 0600;
  - `broker_test.go`'s `brokerBlock` const, which is read, never edited.
  Check each new name against `broker_test.go`'s (`loadWith`, `brokerBlock`, its test names)
  before committing.

  ```go
  package config

  import (
  	"os"
  	"path/filepath"
  	"strings"
  	"testing"
  )

  // brokerRoleYAML is a port49-broker.yaml that loads under the broker's
  // role; each test changes one key.
  func brokerRoleYAML(t *testing.T) string {
  	t.Helper()
  	dir := storeFiles(t)
  	state := filepath.Join(dir, "state")
  	if err := os.Mkdir(state, 0o700); err != nil {
  		t.Fatal(err)
  	}
  	return strings.Join([]string{
  		"inventory_file: " + write(t, "inv.yaml", inv),
  		"key_refs: [prod_key]",
  		"encryption:",
  		"  current: {id: v2, secret_env: PORT49_ENC_V2}",
  		"admin_socket: " + filepath.Join(dir, "broker.sock"),
  		"broker:",
  		"  listen: 127.0.0.1:0",
  		"  tls_cert_file: /etc/port49/broker.pem",
  		"  tls_key_file: /etc/port49/broker-key.pem",
  		"  client_ca_file: /etc/port49/clients-ca.pem",
  		"  policy_file: /etc/port49/policy.yaml",
  		"  state_dir: " + state,
  		"  certificate_status: {disabled: true}",
  		"store:",
  		"  backend: etcd",
  		"  etcd:",
  		"    endpoints: [https://etcd-0:2379]",
  		"    ca_file: " + filepath.Join(dir, "ca.pem"),
  		"    broker: {cert_file: " + filepath.Join(dir, "b.pem") + ", key_file: " + filepath.Join(dir, "b-key.pem") + "}",
  	}, "\n") + "\n"
  }

  func loadBrokerRole(t *testing.T, raw string) (Config, error) {
  	t.Helper()
  	setKeyEnv(t)
  	return LoadBroker(write(t, "port49-broker.yaml", raw))
  }

  // daemonRoleYAML is a port49d.yaml on etcd with no broker: the daemon's
  // identity alone, and the policy it admits from under policy:.
  func daemonRoleYAML(t *testing.T) string {
  	t.Helper()
  	dir := storeFiles(t)
  	return fmt.Sprintf(sampleHead, write(t, "inv.yaml", inv)) +
  		"encryption:\n  current: {id: v2, secret_env: PORT49_ENC_V2}\n" +
  		"policy: {file: /etc/port49/policy.yaml}\n" +
  		"admin_socket: " + filepath.Join(dir, "admin.sock") + "\n" +
  		"store:\n  backend: etcd\n  etcd:\n    endpoints: [https://etcd-0:2379]\n" +
  		"    ca_file: " + filepath.Join(dir, "ca.pem") + "\n" +
  		"    daemon: {cert_file: " + filepath.Join(dir, "d.pem") + ", key_file: " + filepath.Join(dir, "d-key.pem") + "}\n"
  }

  func loadDaemonRole(t *testing.T, raw string) (Config, error) {
  	t.Helper()
  	setKeyEnv(t)
  	return Load(write(t, "port49d.yaml", raw))
  }

  // A port49-broker.yaml loads under the broker's role: key_refs are its key
  // names, its policy is broker.policy_file, and metrics default to :9050.
  func TestABrokerConfigLoads(t *testing.T) {
  	c, err := loadBrokerRole(t, brokerRoleYAML(t))
  	if err != nil {
  		t.Fatal(err)
  	}
  	if c.Role != RoleBroker || len(c.KeyRefs()) != 1 || c.KeyRefs()[0] != "prod_key" || c.Policy == nil ||
  		c.MetricsListen != ":9050" || c.Broker.StateDir == "" {
  		t.Fatalf("%+v", c)
  	}
  }

  // The broker never holds a device key, nor the daemon's etcd identity, nor
  // speaks TACACS+ (Review Focus 9; Rulings 1, 2): each is refused naming
  // the key.
  func TestTheBrokersConfigNeverNamesADeviceKey(t *testing.T) {
  	for key, extra := range map[string]string{
  		"keys:":                   "keys: {prod_key: {current: {version: 3, secret_env: T_PROD_V3}}}\n",
  		"listen":                  "listen: :49\n",
  		"store.etcd.daemon":       "", // added under store.etcd below
  		"accounting":              "accounting: {spool_capacity: 10}\n",
  		"limits":                  "limits: {per_nas_connections: 4}\n",
  		"receipt_idle_ttl":        "receipt_idle_ttl: 5m\n",
  		"platforms":               "platforms: {arista_eos: {session_services: [shell]}}\n",
  		"policy:":                 "policy: {file: /etc/port49/policy.yaml}\n",
  		"broker.revocations_file": "",
  		"lab.fault_file":          "lab: {fault_file: /tmp/f}\n",
  	} {
  		raw := brokerRoleYAML(t) + extra
  		switch key {
  		case "store.etcd.daemon":
  			raw = strings.Replace(raw, "    broker: {", "    daemon: {cert_file: /x, key_file: /y}\n    broker: {", 1)
  		case "broker.revocations_file":
  			raw = strings.Replace(raw, "  state_dir:", "  revocations_file: /var/lib/port49/r.json\n  state_dir:", 1)
  		}
  		if _, err := loadBrokerRole(t, raw); err == nil || !strings.Contains(err.Error(), key) {
  			t.Errorf("port49-broker.yaml with %s loaded, or the refusal does not name it: %v", key, err)
  		}
  	}
  }

  // port49-broker.yaml requires each of these, naming it.
  func TestTheBrokersConfigRequiresItsKeys(t *testing.T) {
  	for _, cut := range []string{"key_refs:", "state_dir:", "admin_socket:", "backend: etcd", "    broker: {"} {
  		var lines []string
  		for _, l := range strings.Split(brokerRoleYAML(t), "\n") {
  			if !strings.Contains(l, cut) {
  				lines = append(lines, l)
  			}
  		}
  		if _, err := loadBrokerRole(t, strings.Join(lines, "\n")); err == nil {
  			t.Errorf("port49-broker.yaml without %q loaded", cut)
  		}
  	}
  }

  // port49d.yaml on etcd never names the broker's identity, never carries a
  // broker: block, and names the policy it admits from (Review Focus 9;
  // Rulings 1, 2).
  func TestTheDaemonsConfigNeverNamesTheBrokersIdentity(t *testing.T) {
  	base := daemonRoleYAML(t)
  	if c, err := loadDaemonRole(t, base); err != nil || c.Policy == nil || c.Broker != nil {
  		t.Fatalf("the split daemon's config: %+v %v", c, err)
  	}
  	withBrokerID := strings.Replace(base, "    daemon: {", "    broker: {cert_file: /x, key_file: /y}\n    daemon: {", 1)
  	if _, err := loadDaemonRole(t, withBrokerID); err == nil || !strings.Contains(err.Error(), "store.etcd.broker") {
  		t.Fatalf("a daemon config naming the broker's identity: %v", err)
  	}
  	withBlock := strings.Replace(base, "policy: {file: /etc/port49/policy.yaml}\n", brokerBlock, 1)
  	if _, err := loadDaemonRole(t, withBlock); err == nil || !strings.Contains(err.Error(), "port49-broker.yaml") {
  		t.Fatalf("a broker: block in port49d.yaml on etcd: %v", err)
  	}
  	noPolicy := strings.Replace(base, "policy: {file: /etc/port49/policy.yaml}\n", "", 1)
  	if _, err := loadDaemonRole(t, noPolicy); err == nil || !strings.Contains(err.Error(), "policy") {
  		t.Fatalf("port49d.yaml on etcd with no policy: %v", err)
  	}
  }

  // StoreBlocks reads either file's store: block whatever role would load
  // it (pre-flight I8): a 7d port49d.yaml naming both identities yields
  // both, as store-roles needs; Load under the daemon's role refuses the
  // same file. A block whose shape is wrong is refused by both.
  func TestStoreBlocksReadsEitherFileWithNoRole(t *testing.T) {
  	dir := storeFiles(t)
  	both := []byte(storeDoc(dir, ""))
  	sc, err := StoreBlocks(both)
  	if err != nil || sc.Etcd == nil || sc.Etcd.Daemon.CertFile == "" || sc.Etcd.Broker == nil {
  		t.Fatalf("a 7d file's two identities: %+v %v", sc, err)
  	}
  	if sc, err := StoreBlocks([]byte(brokerRoleYAML(t))); err != nil || sc.Etcd.Broker == nil ||
  		sc.Etcd.Daemon.CertFile != "" {
  		t.Fatalf("port49-broker.yaml: %+v %v", sc, err)
  	}
  	if sc, err := StoreBlocks([]byte(daemonRoleYAML(t))); err != nil || sc.Etcd.Broker != nil ||
  		sc.Etcd.Daemon.CertFile == "" {
  		t.Fatalf("port49d.yaml with no broker: %+v %v", sc, err)
  	}
  	misshapen := strings.Replace(storeDoc(dir, ""), "    endpoints: [https://etcd-0:2379]", "    endpoints: []", 1)
  	if _, err := StoreBlocks([]byte(misshapen)); err == nil || !strings.Contains(err.Error(), "endpoints") {
  		t.Fatalf("a store block with no endpoint was read: %v", err)
  	}
  }
  ```

  `TestAStoreIdentityNamedRootIsRefused` (`store_test.go:186`) keeps pinning the root refusal;
  run it through `StoreBlocks` as well as `Load`, since `checkStoreShape` now holds that check.

  Add `"fmt"` to the file's imports. `storeDoc(dir, startTimeout)` is `store_test.go`'s
  (`:139`), a 7d port49d.yaml naming both identities.

  Then add to `config_test.go`: `TestAnInProcessBrokerSetsThePolicy` (`Config.Policy` mirrors
  `broker.policy_file` and its interval on memory, through `loadWith(t, brokerBlock)`) and
  `TestPolicyIsRefusedBesideABrokerBlock` (`loadWith(t, brokerBlock+"policy: {file:
  /etc/port49/p.yaml}\n")` is refused naming `policy:`).

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/config/ -count=1`
  Expected: FAIL to compile (`LoadBroker`, `RoleBroker`, `Policy`, `StoreBlocks`).

- [ ] **Step 3: The role and the policy.** In `config.go`:

  ```go
  // Role is which process a configuration is for (plan 7e, Ruling 2):
  // port49d's, the zero value, or port49-broker's.
  type Role int

  const (
  	RoleDaemon Role = iota
  	RoleBroker
  )

  // PolicyConfig is the policy file a process admits from, quarantines by and
  // redacts with: broker.policy_file with a broker in the process, or policy:
  // in a port49d.yaml with none (plan 7e).
  type PolicyConfig struct {
  	File          string
  	WatchInterval time.Duration
  }

  // policyYAML is policy:, the policy a port49d with no broker admits from.
  type policyYAML struct {
  	File          string        `yaml:"file"`
  	WatchInterval time.Duration `yaml:"watch_interval"`
  }
  ```

  Add `Policy *policyYAML \`yaml:"policy"\`` and `KeyRefs []string \`yaml:"key_refs"\`` to
  `fileConfig`; `Role Role` and `Policy *PolicyConfig` to `Config` (unexported `keyRefs
  []string` for the broker's names); and `StateDir string \`yaml:"state_dir"\`` to
  `BrokerConfig`, documented "where port49-broker keeps the CRLs it verified, crl-<name>.der;
  required under the broker's role, which has no revocations file (plan 7e, Ruling 12)".

- [ ] **Step 4: `Load` and `LoadBroker`.** Rename `Load`'s body to `load(path string, role Role)
  (Config, error)`. `Load(path)` is `load(path, RoleDaemon)`, and `LoadBroker(path)` is
  `load(path, RoleBroker)`. In `load`, after the strict decode:

  ```go
  	if role == RoleBroker {
  		if err := brokerRefusals(f); err != nil {
  			return Config{}, err
  		}
  	}
  ```

  with:

  ```go
  // brokerRefusals refuses, by key, what a port49-broker.yaml must never name
  // (plan 7e, Rulings 1, 2): the broker never speaks TACACS+, never holds a
  // device key or the daemon's etcd identity, and on etcd keeps no
  // revocations file.
  func brokerRefusals(f fileConfig) error {
  	for _, c := range []struct {
  		key string
  		set bool
  		why string
  	}{
  		{"listen", f.Listen != "", "port49-broker never speaks TACACS+; that is port49d's"},
  		{"keys:", len(f.Keys) > 0, "device keys are port49d's alone; name the key references under key_refs"},
  		{"accounting", f.Accounting != (AccountingConfig{}), "accounting is port49d's"},
  		{"limits", f.Limits != (limitsYAML{}), "TACACS+ limits are port49d's"},
  		{"receipt_idle_ttl", f.ReceiptIdleTTL != 0, "receipts are port49d's"},
  		{"receipt_max_age", f.ReceiptMaxAge != 0, "receipts are port49d's"},
  		{"platforms", len(f.Platforms) > 0, "session services are port49d's"},
  		{"policy:", f.Policy != nil, "port49-broker's policy is broker.policy_file"},
  		{"broker.revocations_file", f.Broker != nil && f.Broker.RevocationsFile != "",
  			"on etcd the store keeps the marks (decision 36); remove it"},
  		{"store.etcd.daemon", f.Store.Etcd != nil && (f.Store.Etcd.Daemon != EtcdIdentity{}),
  			"the daemon's etcd identity is port49d's alone"},
  		{"lab.fault_file", f.Lab != nil && f.Lab.FaultFile != "", "the lab's fault switch is port49d's"},
  	} {
  		if c.set {
  			return fmt.Errorf("config: %s is not port49-broker.yaml's: %s (plan 7e)", c.key, c.why)
  		}
  	}
  	return nil
  }
  ```

  If `AccountingConfig` or `limitsYAML` is not comparable at `a5e4fe8`, compare field by field.
  `lab.session_attributes`, `command_attributes`, `deny_prefixes`, `deny_message_length` and
  `deny_session` join the list as `lab.<key>`.

  Continue in `load`:
  - **Defaults:** under `RoleBroker`, `MetricsListen` defaults to `:9050`, and the receipt and
    limit defaults are left unset.
  - **The key names:** under `RoleBroker`, require `key_refs`, each matching
    `admission.KeyRefShape`, with no duplicates. `Config.KeyRefs()` returns them sorted. Skip
    `checkKeySets` and the key secrets.
  - **The broker block:** under `RoleBroker`, require `broker:`, `admin_socket` and
    `broker.state_dir` (absolute, an existing directory). Skip the `revocations_file`
    requirement and `ownRevocationsFile`.
  - **The policy block:** `policy:` under `RoleDaemon` is refused beside a `broker:` block ("the
    in-process broker's policy is broker.policy_file"). Its `file` is required. Its
    `watch_interval` defaults to 5s and must be 1s to 5m, as `broker.policy_watch_interval`'s.
  - **`Config.Policy`:** `&PolicyConfig{b.PolicyFile, b.PolicyWatchInterval}` with a broker
    block, else from `policy:`. `Admission` stays nil whenever `Config.Policy` is set: the policy
    in force admits. The early return before the inventory read becomes `if c.Policy != nil`.
  - **`inventory.service`:** requires `Config.Policy`: "inventory.service needs a policy
    (broker.policy_file or policy.file)".
  - **The store:** `checkStore(f.Store, role, f.Broker != nil, f.Policy != nil, f.AdminSocket !=
    "")`. On etcd:
    - **under `RoleDaemon`:** a broker block is refused with Ruling 1's line (What the operator
      sees). `policy:` is required. `e.Broker` is refused ("store.etcd.broker: the broker's
      identity is port49-broker's alone; remove it from port49d.yaml (plan 7e)"). `e.Daemon` is
      required. `admin_socket` is required as before;
    - **under `RoleBroker`:** `e.Broker` is required and `e.Daemon` empty;
    - **the memory backend** under `RoleBroker` is refused ("port49-broker runs on etcd: with
      the memory store, run the broker in port49d").
  - **`lab.seed_tokens`** under `RoleDaemon` with `store.backend: etcd` is refused ("lab seed
    tokens are minted by port49-broker on etcd").

  **`StoreBlocks` replaces `StoreOf`** (pre-flight I8).
  - Split `checkStore` in two:
    - `checkStoreShape(s storeYAML) (StoreConfig, error)` holds every check that is not a
      role's: the endpoints, the CA file, durations and defaults, `roles`, each named
      identity's files, and no identity whose CN is `root`;
    - `checkStore(s, role, hasBroker, hasPolicy, hasAdminSocket)` calls it, then applies the
      role's requirements above.
  - `StoreBlocks(raw)` runs `staleSeedKeys`, the strict decode, and `checkStoreShape` alone,
    so either identity may be present or absent.
  - `storeroles.go`'s one call to `StoreOf` becomes `StoreBlocks`. Its output is unchanged on a
    7d file until Task 16.
  - In 0cc5573, `StoreOf` guessed a role from which identities were named. That refused a 7d
    file naming both under the daemon's role, which Task 16 had promised keeps working.

- [ ] **Step 5: One field for the policy.** Replace every read of `cfg.Broker.PolicyFile` and
  `cfg.Broker.PolicyWatchInterval` in `internal/port49d` with `cfg.Policy.File` and
  `cfg.Policy.WatchInterval`.
  - **Where:** `loadPolicy`, `parseBundle`, `quotesCut`'s callers, `newReloader`, `pollPolicy`,
    `refusalLine`'s callers.
  - **Keep the wording.** Every refusal line that says `broker.policy_file` keeps saying it when
    `cfg.Broker != nil`, and says `policy.file` otherwise, through `func policyKey(cfg
    config.Config) string`.
  - **The fence.** `fencedInventory`'s condition and `runOnce`'s `if cfg.Broker != nil &&
    cfg.InventoryService == nil` become `cfg.Policy != nil`.

  Run `go test ./internal/port49d/ -count=1`: unchanged behaviour on every existing test.

- [ ] **Step 6: Run everything.**

  Run: `make build && make test && make vet`
  Expected: PASS.

- [ ] **Step 7: Commit.**

  ```bash
  gofmt -w internal/config internal/port49d
  git add internal/config/config.go internal/config/broker_role_test.go internal/config/config_test.go \
    internal/config/store_test.go internal/port49d/main.go internal/port49d/reload.go internal/port49d/store.go \
    internal/port49d/storeroles.go internal/port49d/broker_test.go internal/port49d/reload_test.go
  git commit -m "feat(config): port49-broker.yaml, and port49d.yaml with no broker on etcd

  LoadBroker reads port49d.yaml's schema under the broker's role: key_refs
  in place of keys, broker.state_dir in place of the revocations file, the
  broker's etcd identity alone. port49d.yaml on etcd names policy: and
  refuses a broker: block and the broker's identity: no host holds both
  credentials, and the broker never holds a device key (plan 7e Rulings 1,
  2, 12).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 14: port49d on etcd with no broker inside

**Files:**
- Create: `internal/port49d/daemon.go`, `internal/port49d/daemon_test.go`
- Modify: `internal/port49d/main.go` (`runOnce` with `cfg.Policy` and no broker on etcd),
  `internal/port49d/store.go` (`openStores` under the daemon's role; `checkSealKeys(…, write
  bool)`; the probe), `internal/port49d/reload.go` (`reloader` over a `*policy.Live`, a log and
  an optional pass)
- Modify: `internal/daemon/admin/admin.go` (`Server.RevokeElsewhere`), `admin_test.go`
- Modify: `internal/store/marks.go` (`Marks.Keep`), `internal/store/marks_test.go`
- Modify: `internal/port49d/revocations.go` (delete `marksReloadHook`; one line more on
  `putBackFileMarks`'s comment), `internal/port49d/revocations_test.go` (delete
  `TestTheMarksReloadHookRefusesTheReloadOnAFailedPutBack` and `putsFail`, which only it uses)
- Modify: `internal/port49d/store_e2e_test.go` (the etcd fixture: a split daemon config)
- Modify: `internal/port49d/restore_linux_test.go` (7e-1's
  `TestARestoreUnderARunningPort49dKeepsTheFilesMarks` replaced by the split daemon's; `restore`
  kept)
- Modify: `internal/port49d/store_test.go` (its etcd tests on the split daemon, or moved to Task
  15; pre-flight I9); its eight `checkSealKeys` calls gain `, true`
- Modify: `internal/port49d/reload_test.go` (`newReloadRig` calls `newReloader(rig.cfg,
  b.Policy, b.Log, b.Refresh, rig.m, rig.clock)`; pre-flight 7e-2 P-8)

**Interfaces:**
- Consumes (as built in 7e-1; roadmap, "Interfaces 7e-1 changed"):
  - `config.Config.Policy` and `config.RoleDaemon` (Task 13);
  - `crypt.LoadLedger(ctx, feed, src, keys, l) (rev uint64, known, recorded int, err error)` and
    `crypt.FollowContexts(ctx, feed, src, keys, l, from, up func(bool), rescanned func(), logf)`;
  - `store.LoadMarks(ctx, feed, m, on) (uint64, error)` and `store.FollowMarks(ctx, feed, m,
    from, on func(store.MarkChange), up func(bool), rescanned func() error, logf)`. A
    `rescanned` that returns an error refuses the reload (re-review 1 C-2).
    `MarkFeed.WatchRevocations(ctx, after, fn func(r, lifted, rev), progress)` is called inside
    `FollowMarks`, which wires `progress` itself (final review 7e-1 I-1);
  - `store.Marks.Count(fn func(principal, cert int))`, set before the first `LoadMarks`, or
    `port49_revocations_in_force` reads 0;
  - `crypt.Fence.OnTimeout(fn)` and the feed series zeroed at the etcd branch's start (final
    review 7e-1 M-3, M-4), both in `openStores` already;
  - `store.RevStore.Ping` (Task 6).
- Produces:
  - `func (m *store.Marks) Keep(r store.Revocation)`: a mark in force stands through a load that
    lacks it, as a `Pend`ed one does, until a lift (`Set(r, false)`) or a load that holds it
    again. A mark not in force is not put in force.
  - `func daemonReloadHook(ctx context.Context, feed store.MarkFeed, enforced *store.Marks,
    rescans prometheus.Counter, bound time.Duration, out io.Writer) func() error`: port49d's
    `rescanned` on etcd (Ruling 5). It replaces 7e-1's `marksReloadHook`, which this task
    deletes. `putBackFileMarks`, `withHeld` and `persister(st, path, held, enforced, m)` stay:
    the file stays on memory, and the persister's two tests (`TestAPersistBeforeTheReload…`,
    `TestAPersistKeepsAMarkMadeSinceTheStart…`) use `putBackFileMarks` as their witness. Its
    comment gains: `Since plan 7e no marks feed calls it: on etcd the file is retired, and on
    memory no feed runs.`
  - `func keepLost(ctx context.Context, feed store.MarkFeed, enforced *store.Marks, bound
    time.Duration, when string, out io.Writer) error`: the keep, run by `daemonReloadHook` and
    by a run after a store gone before its `LoadMarks` (pre-flight 7e-2 P-1).
  - `authMarks` is made by `run`, beside the ledger, and passed to every `runOnce`.
  - `func namedMarks(ms []store.Revocation) string` (re-check R4): each mark's kind and key
    (`printsafe.Line`), comma-separated, at most 20, then `and N more`. Written here for the
    daemon's keep line; Task 15b's put-back line uses it.
  - `stores.probe func(ctx context.Context)`: one `Ping` every `hold_ttl`/6 through the
    daemon's guard, until `ctx` ends.
  - `reloader` fields:
    - `live *policy.Live`;
    - `log decision.Emitter`;
    - `pass func(ctx context.Context, priors []broker.Prior) (broker.RefreshReport, error)`, nil
      for none (port49d with no broker);
    - `onSettled func(pol *policy.Policy)`, nil for none (Task 15).

    `newReloader(cfg, live, log, pass, m, now)` replaces `newReloader(cfg, b, m, now)`, and an
    in-process broker passes `b.Policy, b.Log, b.Refresh`.
  - `admin.Server.RevokeElsewhere string`: when set and `Revoke` is nil, a revocation op is
    refused naming it.
  - `func checkSealKeys(ctx context.Context, s *etcdstore.Store, keys crypt.Keys, m *metrics.Metrics, out io.Writer, bound time.Duration, alarm *keyAlarm, write bool) error`.

Ruling 11.

- [ ] **Step 1: The failing tests.** Create `internal/port49d/daemon_test.go`. The fixture is a
  split daemon config on a TLS etcd member with the roles (`etcdSplit(t)`): the run_test.go
  config with `policy:` in place of `broker:` and the daemon's identity alone. Build it from
  `etcdRunServer` in `store_e2e_test.go`, which this task changes.

  ```go
  // A port49d on etcd with no broker starts with no hold, says the ledger
  // line and the marks, and a second one beside it serves too (Ruling 11):
  // 7d's "waits for the keyspace" is gone.
  func TestTwoDaemonsServeOneKeyspace(t *testing.T) {
  	var out syncBuffer
  	e := stderr
  	t.Cleanup(func() { stderr = e })
  	stderr = &out
  	daemonCfg, _ := etcdSplit(t)
  	startSplitDaemon(t, daemonCfg, &out, 1)
  	startSplitDaemon(t, copyDaemon(t, daemonCfg), &out, 2) // a second, its own addresses
  	if strings.Contains(out.String(), "is held by") {
  		t.Fatalf("a daemon waited for a hold:\n%s", out.String())
  	}
  	waitForCount(t, &out, "port49d: ledger: ", 2)
  }

  // An idle port49d whose store hangs goes dark on its probe alone: no
  // device asks, and it closes its listeners within hold_ttl of the
  // circuit opening, and listens again when the store returns (Ruling 11).
  func TestAnIdleDaemonGoesDarkOnItsProbe(t *testing.T) {
  	var out syncBuffer
  	e := stderr
  	t.Cleanup(func() { stderr = e })
  	stderr = &out
  	daemonCfg, proxy := etcdSplit(t)
  	startSplitDaemon(t, daemonCfg, &out, 1)
  	proxy.Hang(true)
  	waitWithin(t, &out, "closing every listener so that devices use their local method", 60*time.Second)
  	proxy.Hang(false)
  	waitCountWithin(t, &out, "port49d: listening on ", 2, 90*time.Second)
  }

  // A revocation sent to port49d's socket with no broker in it is refused,
  // naming port49-broker's socket (Ruling 13).
  func TestARevocationAtTheDaemonsSocketNamesTheBrokers(t *testing.T) {
  	srv := &admin.Server{Now: time.Now, RevokeElsewhere: "port49-broker's admin socket (its admin_socket in port49-broker.yaml)"}
  	resp := askAdmin(t, srv, admin.Request{Op: "revoke", Principal: "user:alice@example.com"})
  	if !strings.Contains(resp.Error, "port49 revoke --socket") || !strings.Contains(resp.Error, "port49-broker") {
  		t.Fatalf("%+v", resp)
  	}
  }

  // A policy edit reloads into a port49d with no broker: admission and
  // quarantine follow it, and no refresh runs (no line, no pending gauge).
  // On the memory store: the reload path needs no etcd.
  func TestADaemonWithNoBrokerReloadsItsPolicy(t *testing.T) {
  	var out syncBuffer
  	e := stderr
  	t.Cleanup(func() { stderr = e })
  	stderr = &out
  	cfgPath, policyPath := policyOnlyRun(t) // run_test.go's config, policy: {file, watch_interval: 1s} for broker:
  	tacacs := startSplitDaemon(t, cfgPath, &out, 1)
  	writePolicyFile(t, policyPath, quarantiningLeaf1) // reload_test.go's quarantine fixture
  	waitFor(t, &out, "is quarantined")
  	if answeredFrom(t, tacacs, leaf1Addr) {
  		t.Fatal("a quarantined device's connection was answered")
  	}
  	if strings.Contains(out.String(), "policy refresh") {
  		t.Fatalf("a daemon with no broker ran a refresh:\n%s", out.String())
  	}
  	if v := gauge(t, &out, "port49_policy_refresh_pending"); v != 0 {
  		t.Fatalf("port49_policy_refresh_pending %v", v)
  	}
  }
  ```

  `policyOnlyRun`, `writePolicyFile`, `quarantiningLeaf1`, `answeredFrom` and `leaf1Addr` are
  built from `run_test.go`'s and `reload_test.go`'s fixtures. `answeredFrom` dials from the
  device's loopback address, as the quarantine tests there do. Name each in the report.

  `startSplitDaemon`, `copyDaemon` and `askAdmin` are helpers; write them beside the test.
  `startSplitDaemon` (not `certstatus_test.go`'s `startDaemon`, which stays) is `startRun`
  waiting for `port49d: listening on` instead of `broker listening on`, and returns the TACACS+
  address. `copyDaemon(t, cfg) string` writes a copy of a daemon config with its own
  `admin_socket`, `accounting.spool_path` and `metrics_listen: 127.0.0.1:0` in a `safeDir` of
  its own: `admin.Listen` refuses a socket another port49d answers on.
  `TestTwoDaemonsServeOneKeyspace` uses `copyDaemon(t, daemonCfg)`.

  The daemon's half of final review 7e-1 C-1 (Ruling 5). Add to `daemon_test.go`, beside
  `namedMarks`' test, which moves here from 0cc5573's Task 15b:

  ```go
  // port49d's hook before a marks reload keeps every mark it enforces that
  // the store lacks, so the reload lifts none, and names them; one the store
  // holds is not said (plan 7e, Ruling 5). The daemon's role cannot put a
  // mark back. A read that fails refuses the reload (re-review 1 C-2). Each
  // call counts a rescan.
  func TestTheDaemonsReloadHookKeepsWhatTheStoreLost(t *testing.T) {
  	ctx := context.Background()
  	alice := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0).UTC()}
  	carol := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:carol@example.com", At: time.Unix(11, 0).UTC()}
  	enforced := store.NewMarks()
  	enforced.Set(alice, true)
  	enforced.Set(carol, true)
  	rescans := prometheus.NewCounter(prometheus.CounterOpts{Name: "rescans"})
  	var out bytes.Buffer

  	if err := daemonReloadHook(ctx, marksIn{err: store.ErrUnavailable}, enforced, rescans, time.Second, &out)(); err == nil ||
  		!strings.HasSuffix(err.Error(), "the marks are not reloaded until they are read") {
  		t.Fatalf("a read that failed: %v", err)
  	}
  	if out.Len() != 0 {
  		t.Fatalf("a failed read said %q", out.String())
  	}
  	feed := marksIn{rs: []store.Revocation{carol}} // the restore lost alice's
  	if err := daemonReloadHook(ctx, feed, enforced, rescans, time.Second, &out)(); err != nil {
  		t.Fatal(err)
  	}
  	if !strings.Contains(out.String(), "port49d: store: 1 revocation(s) this port49d enforces are missing from "+
  		"the store as its marks feed reloads") || !strings.HasSuffix(out.String(),
  		"and stay in force here (to release one lifted on purpose, revoke it again on port49-broker, then lift "+
  		"it with port49 revoke --lift, or restart this port49d): principal user:alice@example.com\n") {
  		t.Fatalf("said %q", out.String())
  	}
  	if _, err := store.LoadMarks(ctx, feed, enforced, nil); err != nil {
  		t.Fatal(err)
  	}
  	if !enforced.Holds(alice.Kind, alice.Key) || !enforced.Holds(carol.Kind, carol.Key) {
  		t.Fatalf("the reload lifted a kept mark: %+v", enforced.All())
  	}
  	if n := testutil.ToFloat64(rescans); n != 2 {
  		t.Fatalf("counted %v rescans, want 2", n)
  	}
  }

  // marksIn is a store.MarkFeed holding rs at revision 7, or failing with
  // err; its watch waits for ctx.
  type marksIn struct {
  	rs  []store.Revocation
  	err error
  }

  func (f marksIn) Revocations(context.Context) (uint64, []store.Revocation, error) { return 7, f.rs, f.err }

  func (f marksIn) WatchRevocations(ctx context.Context, _ uint64, _ func(store.Revocation, bool, uint64),
  	_ func(uint64)) error {
  	<-ctx.Done()
  	return ctx.Err()
  }

  // The put-back and keep lines name each mark, kind and key, up to 20, then
  // how many more, so the operator knows what to lift again (re-check R4). A
  // key is printed safe: a newline in it cannot forge a line.
  func TestRestoredMarksAreNamedUpToTwenty(t *testing.T) {
  	two := []store.Revocation{
  		{Kind: store.RevocationPrincipal, Key: "user:alice@example.com"},
  		{Kind: store.RevocationPrincipal, Key: "user:carol\nport49-broker: forged"},
  	}
  	if got := namedMarks(two); got != "principal user:alice@example.com, principal user:carol?port49-broker: forged" {
  		t.Fatalf("%q", got)
  	}
  	var many []store.Revocation
  	for i := range 23 {
  		many = append(many, store.Revocation{Kind: store.RevocationPrincipal, Key: fmt.Sprintf("user:u%02d", i)})
  	}
  	got := namedMarks(many)
  	if !strings.HasSuffix(got, "principal user:u19, and 3 more") || strings.Contains(got, "user:u20") {
  		t.Fatalf("%q", got)
  	}
  }
  ```

  In `internal/store/marks_test.go`:

  ```go
  // A kept mark (Keep) stands through a load that lacks it, and tells
  // nothing; a lift the watch delivers lifts it, and so does a later load
  // once a load has seen the store hold it again (plan 7e, Ruling 5). The
  // control: the same load lifts a mark not kept.
  func TestAKeptMarkStandsThroughAReloadUntilAWatchedLift(t *testing.T) {
  	ctx := context.Background()
  	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0).UTC()}
  	var changes []string
  	on := func(c MarkChange) { changes = append(changes, told(c)) }

  	unkept := NewMarks()
  	unkept.Set(alice, true)
  	if _, err := LoadMarks(ctx, &markFeed{}, unkept, nil); err != nil || unkept.Holds(alice.Kind, alice.Key) {
  		t.Fatalf("control: a load lacking an unkept mark: %v %v", unkept.All(), err)
  	}

  	m := NewMarks()
  	m.Keep(alice) // not in force: nothing
  	if m.Holds(alice.Kind, alice.Key) {
  		t.Fatal("Keep put a mark in force")
  	}
  	m.Set(alice, true)
  	m.Keep(alice)
  	if _, err := LoadMarks(ctx, &markFeed{}, m, on); err != nil || !m.Holds(alice.Kind, alice.Key) || len(changes) != 0 {
  		t.Fatalf("a load lacking a kept mark: %v %v %v", m.All(), changes, err)
  	}
  	back := &markFeed{}
  	back.setMarks([]Revocation{alice}) // the runner put it back
  	if _, err := LoadMarks(ctx, back, m, on); err != nil {
  		t.Fatal(err)
  	}
  	if _, err := LoadMarks(ctx, &markFeed{}, m, on); err != nil || m.Holds(alice.Kind, alice.Key) {
  		t.Fatalf("a mark the store held again was kept past its lift: %v %v", m.All(), err)
  	}
  	m.Set(alice, true)
  	m.Keep(alice)
  	m.Set(alice, false) // a lift the watch delivered
  	if _, err := LoadMarks(ctx, &markFeed{}, m, on); err != nil || m.Holds(alice.Kind, alice.Key) {
  		t.Fatalf("a watched lift: %v %v", m.All(), err)
  	}
  }
  ```

  In `restore_linux_test.go`, replace 7e-1's `TestARestoreUnderARunningPort49dKeepsTheFilesMarks`
  (its broker-block config is refused from Task 13, and the file it puts back from is retired
  on etcd) with the split daemon's, keeping `restore`:

  ```go
  // An etcd restore under a running port49d with no broker lifts nothing
  // there: the marks feed's reload finds alice's mark missing, keeps it in
  // force, and names it (plan 7e, Ruling 5; final review 7e-1 C-1). The
  // daemon's role cannot put it back; the runner does (Task 15b). The
  // controls: a lift the watch delivers lifts it, before the restore and
  // after it.
  func TestARestoreUnderARunningDaemonKeepsItsMarks(t *testing.T) {
  	var out syncBuffer
  	e := stderr
  	t.Cleanup(func() { stderr = e })
  	stderr = &out
  	daemonCfg, proxy, srv := etcdSplitServer(t)
  	root := srv.Client(t, "root")
  	ctx := context.Background()
  	startSplitDaemon(t, daemonCfg, &out, 1)
  	key := "/port49/v1/rv/principal/" + url.PathEscape("user:alice@example.com")
  	bob := "/port49/v1/rv/principal/" + url.PathEscape("user:bob@example.com")
  	mark := func(who string) string {
  		return `{"kind":"principal","key":"user:` + who + `@example.com","at":"2026-10-03T03:00:00Z","origin":"test: a broker"}`
  	}
  	if _, err := root.Put(ctx, key, mark("alice")); err != nil {
  		t.Fatal(err)
  	}
  	waitInForce(t, &out, "principal", 1)
  	if _, err := root.Delete(ctx, key); err != nil { // the control: a watched lift
  		t.Fatal(err)
  	}
  	waitInForce(t, &out, "principal", 0)

  	if _, err := root.Put(ctx, key, mark("alice")); err != nil {
  		t.Fatal(err)
  	}
  	waitInForce(t, &out, "principal", 1)
  	waitMetric(t, &out, `port49_store_feed_up{feed="marks"} 1`)
  	restore(t, proxy, root, key)
  	waitFor(t, &out, "store: the marks feed's revision was compacted")
  	waitFor(t, &out, "port49d: store: 1 revocation(s) this port49d enforces are missing from the store as its "+
  		"marks feed reloads (an etcd restore, or lifted on port49-broker while the feed was down) and stay in "+
  		"force here (to release one lifted on purpose, revoke it again on port49-broker, then lift it with "+
  		"port49 revoke --lift, or restart this port49d): principal user:alice@example.com")
  	// A mark put after the restore arrives only once the reload is done and
  	// the feed follows again: then both stand.
  	if _, err := root.Put(ctx, bob, mark("bob")); err != nil {
  		t.Fatal(err)
  	}
  	waitInForce(t, &out, "principal", 2)

  	// Released by a revoke and a lift made again while the feed is up.
  	if _, err := root.Put(ctx, key, mark("alice")); err != nil {
  		t.Fatal(err)
  	}
  	if _, err := root.Delete(ctx, key); err != nil {
  		t.Fatal(err)
  	}
  	waitInForce(t, &out, "principal", 1)
  }

  // An etcd restore that outlasts hold_ttl takes port49d dark and starts a new
  // run, which reads the restored marks. The marks are the process's (Ruling
  // 11), so the new run keeps alice's mark the restore lost, names it, and
  // enforces it (final review 7e-1 C-1; pre-flight 7e-2 P-1).
  func TestARestoreAcrossAStoreGoneKeepsTheDaemonsMarks(t *testing.T) {
  	var out syncBuffer
  	e := stderr
  	t.Cleanup(func() { stderr = e })
  	stderr = &out
  	daemonCfg, proxy, srv := etcdSplitServer(t)
  	root := srv.Client(t, "root")
  	ctx := context.Background()
  	startSplitDaemon(t, daemonCfg, &out, 1)
  	key := "/port49/v1/rv/principal/" + url.PathEscape("user:alice@example.com")
  	if _, err := root.Put(ctx, key, `{"kind":"principal","key":"user:alice@example.com",`+
  		`"at":"2026-10-03T03:00:00Z","origin":"test: a broker"}`); err != nil {
  		t.Fatal(err)
  	}
  	waitInForce(t, &out, "principal", 1)
  	proxy.Hang(true)
  	waitWithin(t, &out, "closing every listener so that devices use their local method", 60*time.Second)
  	if _, err := root.Delete(ctx, key); err != nil { // the restore, while this port49d is dark
  		t.Fatal(err)
  	}
  	proxy.Drop()
  	waitCountWithin(t, &out, "port49d: listening on ", 2, 90*time.Second)
  	waitFor(t, &out, "port49d: store: 1 revocation(s) this port49d enforces are missing from the store "+
  		"as it starts again after a store gone")
  	waitInForce(t, &out, "principal", 1)
  }
  ```

  `etcdSplitServer` is Step 7's. `waitInForce`, `waitMetric`, `waitFor`, `waitWithin`,
  `waitCountWithin` and `restore` are the package's own (7e-1).

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/port49d/ ./internal/daemon/admin/ ./internal/store/ -run 'TwoDaemons|IdleDaemon|DaemonsSocket|NoBrokerReloads|ReloadHookKeeps|NamedUpToTwenty|RestoreUnderARunningDaemon|RestoreAcrossAStoreGone|KeptMark' -count=1`
  Expected: FAIL. The split config does not start (port49d takes the hold as the broker, whose
  identity it no longer has), and `RevokeElsewhere`, `Marks.Keep`, `daemonReloadHook`,
  `namedMarks` and `etcdSplitServer` are undefined.

- [ ] **Step 3: The admin socket.** In `admin.go`, add to `Server`:

  ```go
  	// RevokeElsewhere names where revocation is answered when this process
  	// runs no broker (plan 7e, Ruling 13): port49d on etcd, beside
  	// port49-broker. Empty keeps the memory store's line.
  	RevokeElsewhere string
  ```

  In `answer`'s `"revoke", "revocations"` case, when `s.Revoke == nil`:

  ```go
  		if s.RevokeElsewhere != "" {
  			return Response{Error: "port49d runs no broker; revocation is " + s.RevokeElsewhere +
  				": run port49 revoke --socket <that path>"}
  		}
  ```

  Add `TestARevokeWithNoBrokerNamesWhereItIs` to `admin_test.go` (the same assertion as the
  daemon test above, at the package's level).

- [ ] **Step 4: The store under the daemon's role.** In `store.go`:
  - **`openStores`'s etcd branch, when `cfg.Broker == nil`** (the split daemon):
    - `attempt` opens the daemon's identity alone and runs the daemon's `CheckIdentity` (no
      broker store). Factor `attempt` into `openIdentity(ctx, cfg, m, out, name, id)` and use it
      for one identity or two;
    - no `Hold` and no `meta/holder`. `m.StoreKeyspaceHeld` stays 0;
    - `checkSealKeys(…, false)` reads the record and warns as today, and writes nothing (the
      daemon's role cannot);
    - keep 7e-1's wiring at the branch's start as it is: both feeds' `port49_store_feed_up`
      at 0 and their rescan series created (final review 7e-1 M-3), and
      `ledger.Fence().OnTimeout(m.StoreFenceTimeouts.Inc)` (M-4);
    - `crypt.LoadLedger(ctx, d, d, keys, ledger)`, retried while unavailable, then the ledger
      line, as 7e-1's `openStores` does;
    - `store.LoadMarks(ctx, d, authMarks, nil)`, retried while unavailable, then
      `port49d: store: N revocation(s) in force from the store`. This moves the load from
      `runOnce`'s `brk != nil` branch (`main.go:899-930` at `a5e4fe8`) into `openStores`, for the
      split daemon. **`authMarks` is the process's, as the ledger is (Ruling 11):** `run` makes it
      beside `crypt.NewLedger()` (`main.go:524`) and passes it to every `runOnce`, which passes it
      to `openStores`. `runOnce` sets `authMarks.Count(…)` to the run's metrics before it calls
      `openStores` (`main.go:718`), since metrics are per run; the last run's feeds are joined
      by then, so the new `Count` replaces the old one safely. Move `authMarks := store.NewMarks()`
      and its `Count` (`main.go:817-823`) up accordingly. **On a run after a store gone**
      (`again`), before this `LoadMarks`, run the same keep the reload hook runs (factor it out
      of `daemonReloadHook` as `keepLost(ctx, feed, enforced, bound, when, out) error`, with
      `when` "as its marks feed reloads" or "as it starts again after a store gone"), so a mark
      the store lost while this port49d was dark stays in force. A `keepLost` read that fails is
      retried as the load is. Keep the marks' revision as `markRev`;
    - return `stores` whose:
      - `follow` runs both feeds on two goroutines and returns once both have: the context feed
        as 7e-1's `follow` does (`crypt.FollowContexts(ctx, d, d, keys, ledger, rev, …)`), and
        the marks feed moved from `runOnce`'s goroutine (`main.go:1095-1112`):

        ```go
        store.FollowMarks(ctx, d, authMarks, markRev, nil,
        	func(up bool) { m.StoreFeedUp.WithLabelValues("marks").Set(b2f(up)) },
        	daemonReloadHook(ctx, d, authMarks, m.StoreFeedRescans.WithLabelValues("marks"), e.BulkTimeout, out),
        	func(format string, args ...any) { fmt.Fprintf(out, "port49d: "+format+"\n", args...) })
        ```

        `on` is nil: the split daemon has no broker listener to tell, and its marks are the
        feed's own. The keep on a reload is the hook's (Ruling 5);
      - `keep` is nil: the ledger record is the runner's (Task 15). `runOnce` runs `sts.keep`
        only when it is set;
      - `probe` pings through the daemon's guard (Step 5);
      - `broker` is nil;
      - `lost` is nil. A store gone comes from the guard alone, as 7d's second trigger.
  - **`checkSealKeys`** gains `write bool`. With `write` false it never calls `PutSealKeys`.
  - **`daemonReloadHook`, `namedMarks` and `Marks.Keep`.** In `daemon.go`, which Step 5
    creates with the probe (write both, and merge the import blocks):

    ```go
    // daemonReloadHook is port49d's rescanned for its marks feed on etcd with
    // no broker inside (store.FollowMarks; plan 7e, Ruling 5). The daemon's
    // role cannot write rv/, and broker.revocations_file is retired on etcd
    // (Ruling 12), so a mark an etcd restore lost cannot be put back here as
    // 7e-1's marksReloadHook put it back (final review 7e-1 C-1). Instead
    // every mark this port49d enforces that the store lacks is kept in force
    // through the reload (store.Marks.Keep), until a lift this feed delivers
    // or a restart, and named on out. A lift made on a broker while the feed
    // was down is kept too: that denies more, and the runner's copy puts back
    // what the restore lost. A read that fails refuses the reload (re-review 1
    // C-2). Each call counts a rescan.
    func daemonReloadHook(ctx context.Context, feed store.MarkFeed, enforced *store.Marks,
    	rescans prometheus.Counter, bound time.Duration, out io.Writer) func() error {
    	return func() error {
    		rescans.Inc()
    		return keepLost(ctx, feed, enforced, bound, "as its marks feed reloads", out)
    	}
    }

    // keepLost keeps in force every mark enforced holds that the store lacks,
    // and names them on out; when says at which load. The reload hook runs it,
    // and so does a run after a store gone before its LoadMarks: the marks are
    // the process's (Ruling 11), and an etcd restore that outlasts hold_ttl
    // ends the run before the feed can reload (pre-flight 7e-2 P-1). A read
    // that fails returns an error, and the caller loads nothing.
    func keepLost(ctx context.Context, feed store.MarkFeed, enforced *store.Marks, bound time.Duration,
    	when string, out io.Writer) error {
    	rctx, cancel := context.WithTimeout(ctx, bound)
    	_, rs, err := feed.Revocations(rctx)
    	cancel()
    	if err != nil {
    		return fmt.Errorf("reading the marks before the marks reload: %w; the marks are not reloaded "+
    			"until they are read", err)
    	}
    	stored := map[[2]string]bool{}
    	for _, r := range rs {
    		stored[[2]string{r.Kind, r.Key}] = true
    	}
    	var kept []store.Revocation
    	for _, r := range enforced.All() {
    		if !stored[[2]string{r.Kind, r.Key}] {
    			enforced.Keep(r)
    			kept = append(kept, r)
    		}
    	}
    	if len(kept) > 0 {
    		fmt.Fprintf(out, "port49d: store: %d revocation(s) this port49d enforces are missing from the store "+
    			"%s (an etcd restore, or lifted on port49-broker while the feed was down) and stay in force "+
    			"here (to release one lifted on purpose, revoke it again on port49-broker, then lift it with "+
    			"port49 revoke --lift, or restart this port49d): %s\n", len(kept), when, namedMarks(kept))
    	}
    	return nil
    }

    // namedMarks names each mark a put-back or keep line lists, its kind and
    // key, printed safe, at most 20, then how many more (re-check R4): the
    // operator lifts again what was lifted on purpose, and port49 revoke
    // --list shows the rest.
    func namedMarks(ms []store.Revocation) string {
    	const most = 20
    	var names []string
    	for i, m := range ms {
    		if i == most {
    			names = append(names, fmt.Sprintf("and %d more", len(ms)-most))
    			break
    		}
    		names = append(names, string(m.Kind)+" "+printsafe.Line(m.Key, 256))
    	}
    	return strings.Join(names, ", ")
    }
    ```

    `printsafe.Line` (`internal/printsafe/printsafe.go:15`) prints a control character as `?`,
    which is what the test expects of the newline. `daemon.go` imports `fmt`, `io`, `strings`,
    `time`, `prometheus`, `printsafe` and `store`; `daemon_test.go` imports `bytes`, `fmt`,
    `prometheus` and `prometheus/testutil` beside the rest.

    In `internal/store/marks.go`, after `Pend`:

    ```go
    // Keep has a mark in force stand through a load that lacks it, as an
    // unwritten one does (Pend), until a lift (Set false: the feed's, or this
    // process's) or a load that shows the store holds it again: port49d's on
    // etcd, whose role cannot put back a mark an etcd restore lost (plan 7e,
    // Ruling 5). A mark not in force is not put in force. On a broker it
    // marks a mark the copy holds and a reload found missing; a later put or
    // Put clears it as it clears a Pended one.
    func (m *Marks) Keep(r Revocation) {
    	if m == nil {
    		return
    	}
    	m.mu.Lock()
    	defer m.mu.Unlock()
    	k := [2]string{r.Kind, r.Key}
    	if _, ok := m.m[k]; ok {
    		m.unwritten[k] = true
    	}
    }
    ```

    `LoadMarks`' comment gains `or kept (Keep)` after `unless it is unwritten (Pend; Ruling
    T9-b)`.
  - **`revocations.go`.** Delete `marksReloadHook`; its one caller, `runOnce`'s marks goroutine,
    runs only with a broker on etcd, which Task 13 refuses. Add to `putBackFileMarks`' comment
    the line its interface names. In `revocations_test.go`, delete
    `TestTheMarksReloadHookRefusesTheReloadOnAFailedPutBack` and `putsFail`.

- [ ] **Step 5: The probe.** In `daemon.go`:

  ```go
  package port49d

  import (
  	"context"
  	"time"

  	"github.com/rhwendt/port49/internal/store"
  )

  // probe pings the store through the daemon's guard every every until ctx
  // ends (plan 7e, Ruling 11). With no hold, nothing else asks the store while
  // no device does, so a hung store would go unnoticed until the first
  // packet, which a device would hear as store_unavailable rather than as a
  // closed port. Each ping counts toward the context pool's circuit, which,
  // open for hold_ttl, ends the run as a store gone (guard.Config.StopAfter),
  // as 7d's fence did. Plan 7f replaces it with go-dark proper.
  func probe(ctx context.Context, s store.RevStore, every time.Duration) {
  	t := time.NewTicker(every)
  	defer t.Stop()
  	for {
  		select {
  		case <-ctx.Done():
  			return
  		case <-t.C:
  			pctx, cancel := context.WithTimeout(ctx, every)
  			s.Ping(pctx) // its outcome is the guard's to count
  			cancel()
  		}
  	}
  }
  ```

  In `openStores`, keep the daemon's guarded, fenced `RevStore` (`gd :=
  guard.WrapRev(crypt.Fenced(d, ledger), gc("daemon"))`, Task 8a). Wrap it with `crypt.Wrap(gd,
  …)` as 7e-1 does, and set `probe: func(ctx context.Context) { probe(ctx, gd, e.HoldTTL/6) }`.
  Each ping then waits for the context feed too, so a feed that has stopped fails the probe and
  takes an idle port49d dark (Ruling 11).

- [ ] **Step 6: `runOnce` with a policy and no broker.** In `main.go`, when `cfg.Broker == nil
  && cfg.Policy != nil`:
  - build the policy as the broker path does (`loadPolicy`, `sayPolicy`), into `live :=
    policy.NewLive(pol)`;
  - admission is `liveAdmission{live}`;
  - quarantine is `watchQuarantine(live, …)`;
  - the redactor is `redactorFor(live)`;
  - `assignedKeyRef` reads `live`;
  - the reloader is `newReloader(cfg, live, log, nil, m, time.Now)`, and with it the inventory
    file watch and the inventory service's fetcher, unchanged. `pass` is nil, so a swap runs no
    refresh and leaves `port49_policy_refresh_pending` alone;
  - the admin socket's server gets `RevokeElsewhere: "port49-broker's admin socket (its
    admin_socket in port49-broker.yaml)"` on etcd;
  - the daemon's handlers get `authMarks`, the process's (`run`'s), which `openStores` filled;
    on memory the file's marks are `Set` into it each run, as today;
  - run `sts.follow` and `sts.probe` on goroutines joined before `sts.close`, and `sts.keep` only
    when it is set;
  - skip `startOnPersistentStore`, the sweep, the keeper, the restore of the revocations file,
    the certificate status and the seeds: each is the broker's;
  - delete the etcd half of `runOnce`'s marks load (`if sts.persistent { … LoadMarks … }` in the
    `brk != nil` branch, `main.go:899-930` at `a5e4fe8`) and its marks goroutine
    (`main.go:1095-1112`): both moved into `openStores` (Step 4), and with a broker on etcd
    refused (Task 13) neither runs. On memory, the file's marks go into `authMarks` as today.

  `cfg.Broker != nil` (memory with the in-process broker) runs exactly as today. In
  `reload.go`, `reloader` reads `r.live` where it read `r.broker.Policy`, and `r.log` where it
  read `r.broker.Log`. `refresh` returns at once when `r.pass` is nil. `swap` sets
  `port49_policy_refresh_pending` only when `r.pass` is set.

- [ ] **Step 7: The e2e fixture.** In `store_e2e_test.go`, `etcdRun`, `etcdRunServer`,
  `etcdRunServerWith(t, policyBody, others)` (7e-1's, with a lab client certificate for each of
  `others`) and their callers run port49d on etcd with a broker block, which Task 13 now refuses.
  - Split them as they nest today:
    - `etcdSplitServerWith(t, policyBody, others) (daemonCfg string, proxy *etcdtest.Proxy, srv
      *etcdtest.Server)` is `etcdRunServerWith` writing the daemon's config alone: `policy:` in
      place of `broker:`, and `store.etcd.daemon` alone;
    - `etcdSplitServer(t)` is `etcdSplitServerWith(t, minimalPolicy, nil)`, and `etcdSplit(t)
      (daemonCfg string, proxy *etcdtest.Proxy)` drops the member;
    - from Task 15, `brokerSplit(t, srv) string` writes port49-broker's beside it.
  - Move each 7d e2e test (`TestRunOnEtcdKeepsALoginAcrossARestart`,
    `TestAStartAppliesAStandingMarkToAKeptContext`,
    `TestAStartSealsTheLedgerOnceItHasReadTheStore`, `TestAHungStoreGoesDarkAndServesAgainWhenItReturns`)
    to run a daemon and a broker in the same test process. That is Task 15's `startBroker`, so
    mark each `t.Skip("plan 7e Task 15: needs port49-broker")` here, and unskip it in Task 15.
  - Skip 7e-1's two e2e tests the same way (final review 7e-1, 7e-2 amendments): each needs a
    broker process beside the daemon, and runs in Task 15 on the split:
    - `TestAMarkFromAnotherBrokerProcessReachesThisOne` (`store_e2e_test.go:484` at
      `a5e4fe8`);
    - `TestAStartSeededFromTheLedgerRecordDeniesAPutBack` (`:623`). The runner writes the
      ledger record it reads. In Task 16 it becomes `TestAPutBackBeforeADaemonStartsIsDenied`'s
      single-daemon case, or stays beside it.
  - Delete `TestASecondPort49dWaitsForTheKeyspace`: Ruling 11 withdraws it, and
    `TestTwoDaemonsServeOneKeyspace` replaces it.
  - In `restore_linux_test.go`, 7e-1's `TestARestoreUnderARunningPort49dKeepsTheFilesMarks` is
    replaced by Step 1's `TestARestoreUnderARunningDaemonKeepsItsMarks`. Its file half is retired
    with the file on etcd (Ruling 12); its put-back half is the runner's, in Task 15b.

  **`store_test.go`'s etcd tests** (pre-flight I9). Each builds a port49d.yaml with a `broker:`
  block on etcd (`etcdRunServer`) and calls `openStores`, which Task 13 refuses and this task
  splits. Each is moved, by name (lines at `a5e4fe8`):

  | Test (`internal/port49d/store_test.go`) | Now |
  |---|---|
  | `TestOpenStoresSharesOneSayer` (`:492`) | on `etcdSplit`'s daemon config: the daemon's layer and the probe's share one sayer. Its broker half moves to Task 15 as `TestTheBrokersStoresShareOneSayer`, on `brokerSplit` |
  | `TestARaisedAlarmIsGaugedWhileTheStoreIsAway` (`:614`) | on `etcdSplit`'s daemon config, unchanged in what it asserts: the daemon reads the seal keys and raises the alarm too |
  | `TestAHoldStillOnThisPort49dsLastRunIsSaidAsIts` (`:719`) | moves to Task 15's `brokerd_test.go` as `TestAHoldStillOnThisReplicasLastRunIsSaidAsIts`: the hold is the runner's. Mark it skipped here, as the e2e tests are |
  | `TestTheRolesCheckRunsTheBrokersUnderUnenforced` (`:131`) | splits. The daemon's half stays: under `roles: unenforced` the daemon's check is skipped and said. The broker's half moves to Task 15 as `TestTheBrokersRolesCheckRunsUnderUnenforced`, on the broker's identity alone |
  | `TestAStartAfterAStoreGoneRetriesEveryError` (`:179`) | on `etcdSplit`'s daemon config, unchanged in what it asserts |
  | `TestTheStartsCarryDecidesHoldOrOpen` (`:218`) | the daemon has no hold, so its pure function's hold branch is the runner's: moved to Task 15 with the takeover, and skipped here |
  | `TestARefusedLedgerRecordReadNamesStoreRoles` (`:535`, 7e-1) | on `etcdSplitServer`'s daemon config, unchanged in what it asserts: the daemon's start reads `lw/` |
  | `TestOpenStoresFencesEachLayerUnderItsGuard` (`:565`, 7e-1) | keeps its daemon half on `etcdSplit`: the daemon's layer and the probe are fenced under the guard. Its broker half moves to Task 15 as `TestTheBrokersStoreIsFencedUnderItsGuard`, on `brokerSplit` |
  | `TestBothFeedsReadDownWhileTheStoreIsAway` (`:651`, 7e-1) | on `etcdSplit`'s daemon config, unchanged in what it asserts: the split daemon sets both feeds' series to 0 while it waits |

  Each test kept here passes in this task. Each skipped one is named in the report, and Task 15
  fails its review if one is left skipped. 7d's I-2 line ("still held by this port49d's last
  run") becomes the runner's (Task 15, pre-flight M7).

- [ ] **Step 8: Run everything.**

  Run: `make build && make test && make vet`
  Expected: PASS, with six e2e tests (7d's four and 7e-1's two) and the two hold tests of
  `store_test.go` skipped and named.

- [ ] **Step 9: Commit.**

  ```bash
  gofmt -w internal/port49d internal/daemon/admin internal/store
  git add internal/port49d/daemon.go internal/port49d/daemon_test.go internal/port49d/main.go \
    internal/port49d/store.go internal/port49d/reload.go internal/port49d/store_e2e_test.go \
    internal/port49d/store_test.go internal/port49d/restore_linux_test.go \
    internal/port49d/revocations.go internal/port49d/revocations_test.go internal/port49d/reload_test.go \
    internal/store/marks.go internal/store/marks_test.go \
    internal/daemon/admin/admin.go internal/daemon/admin/admin_test.go
  git commit -m "feat(port49d): serve TACACS+ on etcd with no broker inside

  With the daemon's identity alone: no hold, the seal keys read and never
  written, the marks and the ledger loaded and followed, a probe through
  the context pool so an idle port49d goes dark as 7d's fence made it, and
  the policy reloaded for admission with no refresh. A revocation at its
  socket names port49-broker's (plan 7e Rulings 11, 13). A mark a marks
  reload finds missing stays in force until a watched lift or a restart,
  since the daemon's role cannot put it back and the revocations file is
  retired on etcd (Ruling 5; final review 7e-1 C-1).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 15: `port49-broker`, its replicas, and one runner

**Files:**
- Create: `cmd/port49-broker/main.go`; `internal/port49d/brokerd.go`, `internal/port49d/runner.go`,
  `internal/port49d/brokerd_test.go`
- Modify: `internal/port49d/reload.go` (the settle's delay and priors; `onSettled`),
  `reload_test.go`
- Modify: `internal/broker/refresh.go` (`RefreshTokens`), `refresh_test.go`
- Modify: `internal/store/etcd/meta.go` (`Judged`, `PutJudged`), `meta_test.go`
- Modify: `internal/port49d/store.go` (`lineHolder`'s shape takes `port49-broker on …`;
  `startOnPersistentStore` becomes the runner's takeover; `unopenableSayer` takes the
  process's prefix)
- Modify: `internal/port49d/certstatus.go` (the state dir)
- Modify: `internal/port49d/store_e2e_test.go` (Task 14's skipped tests, on the split),
  `internal/port49d/store_test.go` (Task 14's skipped hold tests, moved here; the sayer tests
  call `unopenableSayer("port49d", …)`)
- Modify: `internal/daemon/admin/admin.go` (`Server.DiagnoseElsewhere`), `admin_test.go`
  (pre-flight M16)
- Modify: `Makefile` (`build`)

**Interfaces:**
- Consumes:
  - Tasks 13–14: `config.LoadBroker`, `Config.Policy`, `Config.KeyRefs()`,
    `BrokerConfig.StateDir`;
  - Task 14: `newReloader(cfg, live, log, pass, m, now)`;
  - 7e-1, as built (roadmap, "Interfaces 7e-1 changed"):
    - `crypt.LoadLedger(ctx, feed, src, keys, l)`, `crypt.FollowContexts(ctx, feed, src, keys,
      l, from, up, rescanned func(), logf)`, `crypt.Fenced`, `crypt.KeepLedger(ctx, l, sink,
      every, report, logf)` with the stop's last write, `crypt.Fence.OnTimeout(fn)`;
    - `store.LoadMarks(ctx, feed, m, on)`, `store.FollowMarks(ctx, feed, m, from, on, up,
      rescanned func() error, logf)`, whose `rescanned` refuses the reload by returning an
      error. `MarkFeed.WatchRevocations(ctx, after, fn func(r, lifted, rev), progress)` is
      called inside it;
    - `store.Marks.Count(fn func(principal, cert int))`, set before the first `Set` or
      `LoadMarks`;
    - `broker.Broker.Say`, through which `MarkChanged`'s lines go; nil sends them to the process
      log;
    - `store.LedgerSink.PutLedgerMarks(ctx, ms) (int, error)`, how many of `ms` landed, which
      the keeper uses on the runner;
    - `Broker.MarkChanged(store.MarkChange)`;
    - `startOnPersistentStore(ctx, brk, st, e, cfg, &marks, m)`, which no longer takes `ledger`:
      the base is set by `LoadLedger`, and `Ledger.Seal` is gone;
  - 7d: `etcd.Store.Hold`, `Broker.ApplyMarksAtStart`, `Broker.RefreshAtStart`,
    `Broker.ReindexContexts`, `etcd.Store.Unindexed`, `startLeftBy`;
  - Task 7: `sweepLoop(ctx, s, brk, ledger, every, out)`.
- Produces:
  - `func unopenableSayer(prefix string, keys crypt.Keys, out io.Writer, now func() time.Time)
    func(record, keyID string, why error)`: 7e-1's, keyed as before by (record, key id, kind),
    with every line starting `prefix + ": crypt: "` where 7e-1 hard-codes `port49d: crypt: `,
    and "this port49d does not hold" reading "this " + prefix + " does not hold". port49d passes
    `"port49d"` (its lines unchanged) and port49-broker `"port49-broker"`.
  - `func port49d.BrokerMain(args []string) int`, behind `cmd/port49-broker`.
  - `func runBroker(parent context.Context, cfgPath string) error`.
  - `type runner struct` with:
    - `func (r *runner) run(ctx context.Context)`: hold, takeover, duties, loss, again;
    - `func (r *runner) running() bool`.
  - `func (b *broker.Broker) RefreshTokens(ctx context.Context, priors []broker.Prior) (broker.RefreshReport, error)`.
  - `type etcd.JudgedRecord struct { Bundle string; Policy []byte }`;
    `func (s *etcd.Store) Judged(ctx context.Context) (JudgedRecord, bool, error)` and
    `func (s *etcd.Store) PutJudged(ctx context.Context, bundle string, policy []byte) error`, at
    `meta/judged`. `policy` is the bundle's policy file (`policy.Policy.Raw()`), for Task 15a's
    guard at start. Above `maxJudgedPolicy` (1 MiB) it is left out and the record says so
    (Ruling 17).
  - `func (r *runner) recordJudged(ctx context.Context, why string)`: the one place
    `meta/judged` is written, by the takeover with nothing owed and by `onSettled` (pre-flight
    I2). Task 15a adds its condition that every replica serves the bundle.
  - `admin.Server.DiagnoseElsewhere string`: when set and `Held` is nil, a `keys_diagnose` is
    refused naming it.
  - `const settleMin = 30 * time.Second`; `func settleAfter(interval time.Duration) time.Duration`
    is `max(settleMin, 2*interval+5*time.Second)`, which replaces the constant
    `settleAfterReload` at its uses.

Rulings 6, 7, 8, 9, 12, 13. The broker process is port49d's broker path, with no TACACS+
listener, on the broker's identity alone, and with the start steps moved behind the runner's
hold. Task 15a adds policy across replicas and the guard at start, and Task 15b the marks copy
and the offline revocation, each on this task's runner.

- [ ] **Step 1: The failing tests.** Create `internal/port49d/brokerd_test.go`. The fixture,
  `splitFleet(t)`, is one TLS etcd member with the roles, one `port49d.yaml` and one
  `port49-broker.yaml` (`brokerSplit`), and the helpers `startBroker(t, cfg, out, n) (apiAddr
  string, stop func() error)` and `startSplitDaemon`.

  ```go
  // The first port49-broker takes the runner's hold and runs the takeover;
  // a second serves the API and says who runs. When the runner stops, the
  // second takes over within hold_ttl and a third (Review Focus 4; Ruling 6).
  func TestARunnerThatStopsIsReplaced(t *testing.T) {
  	var out syncBuffer
  	e := stderr
  	t.Cleanup(func() { stderr = e })
  	stderr = &out
  	f := splitFleet(t) // hold_ttl 10s
  	_, stopA := startBroker(t, f.broker, &out, 1)
  	waitFor(t, &out, "runner: took keyspace /port49/")
  	apiB, _ := startBroker(t, f.copyBroker(t), &out, 2)
  	waitFor(t, &out, "this replica serves the API and takes over if that one stops")
  	mintOn(t, apiB, f.pki, "leaf1") // the second serves the API before it runs anything
  	start := time.Now()
  	if err := stopA(); err != nil {
  		t.Fatal(err)
  	}
  	waitCountWithin(t, &out, "runner: took keyspace /port49/", 2, 30*time.Second)
  	if d := time.Since(start); d > 10*time.Second+10*time.Second/3+5*time.Second {
  		t.Fatalf("the takeover took %v", d)
  	}
  }

  // A runner cut off from etcd, which neither releases its lease nor renews
  // it (a crash, a partition, or a pause past its fence), is replaced once
  // its lease lapses: within hold_ttl and a third. Back, it says it lost the
  // hold and waits behind the new runner; it runs nothing while that one
  // holds (Review Focus 4; pre-flight M9). A graceful stop releases the
  // lease at once, so TestARunnerThatStopsIsReplaced alone never reaches
  // this path.
  func TestARunnerCutOffIsReplacedAfterItsLease(t *testing.T) {
  	var out syncBuffer
  	e := stderr
  	t.Cleanup(func() { stderr = e })
  	stderr = &out
  	f := splitFleet(t) // hold_ttl 10s
  	cfgA, proxyA := f.copyBrokerVia(t) // A reaches etcd through a proxy of its own
  	startBroker(t, cfgA, &out, 1)
  	waitFor(t, &out, "runner: took keyspace /port49/")
  	startBroker(t, f.copyBroker(t), &out, 2)
  	waitFor(t, &out, "this replica serves the API and takes over if that one stops")
  	start := time.Now()
  	proxyA.Hang(true)
  	waitWithin(t, &out, "runner: lost the keyspace's hold", 15*time.Second)
  	waitCountWithin(t, &out, "runner: took keyspace /port49/", 2, 30*time.Second)
  	if d := time.Since(start); d > 10*time.Second+10*time.Second/3+5*time.Second {
  		t.Fatalf("the takeover after a lease never released took %v", d)
  	}
  	proxyA.Hang(false)
  	time.Sleep(10 * time.Second) // A tries again every 5s; B holds throughout
  	if n := strings.Count(out.String(), "runner: took keyspace /port49/"); n != 2 {
  		t.Fatalf("a runner cut off and back took the hold while another held it: %d takes", n)
  	}
  }

  // A clean takeover, with nothing owed after its carry, records its bundle
  // as judged itself: no reloader pass runs to do it (pre-flight I2). The
  // next takeover on the same bundle purges nothing.
  func TestACleanTakeoverRecordsItsBundleAsJudged(t *testing.T) {
  	var out syncBuffer
  	e := stderr
  	t.Cleanup(func() { stderr = e })
  	stderr = &out
  	f := splitFleet(t)
  	_, stop := startBroker(t, f.broker, &out, 1)
  	waitFor(t, &out, "runner: recorded bundle ")
  	resp, err := f.srv.Client(t, "root").Get(context.Background(), "/port49/v1/meta/judged")
  	if err != nil || len(resp.Kvs) != 1 || !strings.Contains(string(resp.Kvs[0].Value), `"bundle":"`+f.bundle(t)+`"`) {
  		t.Fatalf("meta/judged after a clean takeover: %v %v", resp, err)
  	}
  	if err := stop(); err != nil {
  		t.Fatal(err)
  	}
  	startBroker(t, f.broker, &out, 2)
  	waitFor(t, &out, "is the one the last runner judged; no unspent token purged")
  }

  // A takeover purges the unspent tokens only when the bundle in force is
  // not the one the last runner judged (Ruling 7): a broker restart on the
  // same policy keeps a minted token redeemable; an edit made with no
  // broker running purges it, and an idempotent replay mints afresh. Each
  // step waits on the judged line, never on a gauge already at 0 (pre-flight
  // I14).
  func TestATakeoverPurgesOnlyAnUnjudgedBundle(t *testing.T) {
  	var out, log syncBuffer
  	e, o := stderr, stdout
  	t.Cleanup(func() { stderr, stdout = e, o })
  	stderr, stdout = &out, &log
  	f := splitFleet(t)
  	tacacs := startSplitDaemon(t, f.daemon, &out, 1)
  	api, stop := startBroker(t, f.broker, &out, 1)
  	waitForCount(t, &out, "runner: recorded bundle ", 1)
  	kept := mintOn(t, api, f.pki, "leaf1")
  	stop()
  	api, stop = startBroker(t, f.broker, &out, 2)
  	waitFor(t, &out, "is the one the last runner judged; no unspent token purged")
  	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
  	if st := dev.login("alice", kept); st != wire.AuthenStatusPass {
  		t.Fatalf("control: a token minted before a broker restart on the same policy: %d", st)
  	}
  	spare := mintOn(t, api, f.pki, "leaf1")
  	stop()
  	f.editPolicy(t) // a grant's comment changed: another bundle
  	startBroker(t, f.broker, &out, 3)
  	waitFor(t, &out, "unspent token(s) purged")
  	if st := dev.login("alice", spare); st == wire.AuthenStatusPass {
  		t.Fatal("a token minted under a bundle no runner judged was not purged")
  	}
  	waitForCount(t, &out, "runner: recorded bundle ", 3) // the purge's takeover records the new bundle too
  }

  // A token another replica minted under the replaced policy before it
  // reloaded is judged by the runner's settle pass (Ruling 8). The settle's
  // delay is exact, not merely past a floor (pre-flight M4).
  func TestTheSettlePassJudgesALateReplicasTokens(t *testing.T) {
  	for interval, want := range map[time.Duration]time.Duration{
  		time.Second: 30 * time.Second, 5 * time.Second: 30 * time.Second,
  		20 * time.Second: 45 * time.Second, time.Minute: 125 * time.Second,
  	} {
  		if got := settleAfter(interval); got != want {
  			t.Fatalf("settleAfter(%v) = %v, want %v", interval, got, want)
  		}
  	}
  	rig := newReloadRig(t, minimalPolicy) // reload_test.go's fixture: a reloader on a memory broker
  	swapTo(t, rig, showOnly)               // the edit that withdraws alice's grant
  	tok := mintUnder(t, rig, minimalPolicy) // another replica, still on the old policy
  	runFirstPass(t, rig)
  	runSettlePass(t, rig)
  	if tokenStillRedeemable(t, rig, tok) {
  		t.Fatal("the settle pass kept a token minted under the replaced policy after the first pass")
  	}
  }
  ```

  Write the settle test's helpers on `reload_test.go`'s `newReloadRig(t, policyBody)`:
  - `swapTo(t, rig, body)` is `rig.write(t, body)` and then `rig.pollTwice()`;
  - the withdrawn grant is `reload_test.go`'s `showOnly`; the old policy is `minimalPolicy`;
  - `mintUnder(t, rig, body) string` mints through a second broker that `buildBroker` builds on
    `rig.st`, holding `body`;
  - `runFirstPass` and `runSettlePass` call the reloader's refresh with `rig.now` moved to each;
  - `tokenStillRedeemable(t, rig, tok) bool` looks the token up in `rig.st`.

  `splitFleet`'s further helpers:
  - `f.daemon`, `f.broker` and `f.pki` are the two configs and the lab PKI; `f.copyDaemon(t)` is
    Task 14's `copyDaemon(t, f.daemon)`;
  - `f.copyBroker(t) string` writes a copy of `f.broker` with its own `broker.listen` and
    `metrics_listen` (both `127.0.0.1:0`), its own `admin_socket`, its own `broker.state_dir` (a
    fresh `t.TempDir()`, mode 0700) and its own `broker.policy_file` (a copy of the policy, in a
    `safeDir`), so Tasks 15a, 15b, 15c and 16 each get the separate file they need;
  - `mintOn(t, api, pki, device) string` is `run_test.go`'s `mint`; `mintOnAs` is `mintAs`;
  - `f.editPolicy(t)` rewrites `f.broker`'s policy file with one comment line added, through
    `f.writePolicyOf` (Task 15a), so its bundle differs;
  - `f.copyBrokerVia(t) (string, *etcdtest.Proxy)` is `copyBroker` with the endpoint through
    an `etcdtest.NewProxy` of its own;
  - `f.bundle(t)` is the bundle the policy file loads into, read as `loadPolicy` reads it;
  - `f.srv` is the member, for a root client.
  `waitFor`, `waitForCount`, `waitWithin` and `waitCountWithin` are the package's own.

  Add to `refresh_test.go`: `TestRefreshTokensJudgesTokensAndNoContext`. It deletes a
  superseded token and leaves a context on the withdrawn grant untouched, and returns a report
  whose context counts are all 0.

  Add to `meta_test.go`: `TestJudgedIsReadBackAndAbsentIsNotFound`. It covers four cases:
  - a record written with its policy reads back both;
  - one whose policy is over `maxJudgedPolicy` reads back the bundle and no policy;
  - an absent record is `ok` false with no error;
  - a record that does not decode is `ok` false, with its key said.

  Add to `admin_test.go`: `TestAKeysDiagnoseWithNoPacketsNamesWhereItIs`. A `Server` with
  `DiagnoseElsewhere` set and `Held` nil answers `keys_diagnose` with an error naming
  port49d's admin socket.

  Unskip, and move into `brokerd_test.go` on `splitFleet`, the hold tests Task 14 skipped in
  `store_test.go` (pre-flight I9):
  - **`TestAHoldStillOnThisReplicasLastRunIsSaidAsIts`.** A runner whose hold was lost, and
    whose lease is live, says `is still held by this replica's last run`, never "is run by"
    itself. A holder that is another replica's is named as that one (pre-flight M7; 7d's
    4001732).
  - **`TestTheBrokersRolesCheckRunsUnderUnenforced`.** Under `roles: unenforced` the broker's
    check still refuses an identity that cannot do the broker's work.
  - **`TestTheBrokersStoresShareOneSayer`.** The broker's sealing layer and the runner's reads
    share one sayer, and its line starts `port49-broker: crypt: `, never `port49d:`
    (`unopenableSayer("port49-broker", …)`).
  - **`TestTheBrokersStoreIsFencedUnderItsGuard`.** The broker half of 7e-1's
    `TestOpenStoresFencesEachLayerUnderItsGuard`: the broker's layer is
    `guard.WrapRev(crypt.Fenced(b, ledger), …)`, so a context read waits for the broker's own
    feed under its guard.
  - **`TestTheStartsCarryDecidesHoldOrOpen`.** It is now the takeover's.

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/port49d/ ./internal/broker/ ./internal/store/etcd/ ./internal/daemon/admin/ -run 'Runner|Takeover|Settle|RefreshTokens|Judged|LastRun|Unenforced|Sayer|Carry|KeysDiagnose|FencedUnderItsGuard' -count=1`
  Expected: FAIL to compile. Once it compiles against a takeover that writes no `meta/judged`,
  `TestACleanTakeoverRecordsItsBundleAsJudged` fails waiting for its line.

- [ ] **Step 3: The broker's token half.** In `refresh.go`:

  ```go
  // RefreshTokens is Refresh's token half alone (plan 7e, Ruling 6): every
  // broker process runs it at its own reload, for the policies it minted
  // under, and the runner runs Refresh, whose context half is the runner's
  // alone. It deletes the unspent tokens priors minted that the policy in
  // force would not, at every grant expiry in their spans, and judges no
  // context. Like Refresh it runs again at once over an expiry the pass
  // crossed.
  func (b *Broker) RefreshTokens(ctx context.Context, priors []Prior) (RefreshReport, error) {
  	cur := b.Policy.Load()
  	var rep RefreshReport
  	for {
  		rep.At = b.Now()
  		if err := b.supersedeTokens(ctx, cur, rep.At, priors, &rep); err != nil {
  			return rep, fmt.Errorf("deleting superseded tokens: %w", err)
  		}
  		next, ok := cur.NextChange(rep.At)
  		if !ok || next.After(b.Now()) || b.Policy.Load() != cur {
  			return rep, nil
  		}
  		priors = []Prior{{Policy: cur, At: rep.At}}
  	}
  }
  ```

- [ ] **Step 4: The judged record.** In `meta.go`:

  ```go
  // maxJudgedPolicy is the most of a policy file meta/judged carries: under
  // etcd's request limit (1.5 MiB by default) with room for the record.
  const maxJudgedPolicy = 1 << 20

  type judgedRec struct {
  	Bundle    string    `json:"bundle"`
  	Policy    []byte    `json:"policy,omitempty"`
  	Omitted   bool      `json:"policy_omitted,omitempty"`
  	WrittenAt time.Time `json:"written_at"`
  }

  // JudgedRecord is meta/judged: the bundle a runner last judged every
  // unspent token against (plan 7e, Ruling 7), and its policy file, for the
  // reload guard at a start (Ruling 17). Policy is nil when the file was
  // over maxJudgedPolicy.
  type JudgedRecord struct {
  	Bundle string
  	Policy []byte
  }

  // Judged reads meta/judged; ok is false when none was recorded. A record
  // that does not decode is ok false too, said by its key alone: a takeover
  // then purges, which fails closed.
  func (s *Store) Judged(ctx context.Context) (JudgedRecord, bool, error) {
  	key := s.k.meta("judged")
  	resp, err := s.ctxKV.Get(ctx, key)
  	if err != nil {
  		return JudgedRecord{}, false, unavailable(err)
  	}
  	if len(resp.Kvs) == 0 {
  		return JudgedRecord{}, false, nil
  	}
  	var r judgedRec
  	if err := json.Unmarshal(resp.Kvs[0].Value, &r); err != nil {
  		s.logf("etcd: %s does not decode; the takeover purges the unspent tokens", key)
  		return JudgedRecord{}, false, nil
  	}
  	return JudgedRecord{Bundle: r.Bundle, Policy: r.Policy}, true, nil
  }

  // PutJudged records bundle as judged, with its policy file unless that is
  // over maxJudgedPolicy, as the broker.
  func (s *Store) PutJudged(ctx context.Context, bundle string, policy []byte) error {
  	r := judgedRec{Bundle: bundle, Policy: policy, WrittenAt: s.now().UTC()}
  	if len(policy) > maxJudgedPolicy {
  		r.Policy, r.Omitted = nil, true
  	}
  	body, err := json.Marshal(r)
  	if err != nil {
  		return err
  	}
  	_, err = s.ctxKV.Put(ctx, s.k.meta("judged"), string(body))
  	return unavailable(err)
  }
  ```

  Every KV call on the context client goes through `s.ctxKV`, so `Seen()` sees it (Ruling
  T6-a). `Judged` reads the key itself rather than through `getJSON`, whose decode error
  (`notDecoded`, `commit.go:134`) carries no sentinel to tell it from a failed read. The
  daemon's role reads `meta/`, so port49d can read the policy here. That is no wider than the
  policy file port49d already reads from disk, and the file names no secret (key groups name key
  references, never keys).

- [ ] **Step 5: The settle covers a late replica.** In `reload.go`:
  - add `settleMin` and `settleAfter`, and use `settleAfter(r.interval)` where `settleAfterReload`
    was;
  - in `refresh`, on a complete pass, reset `r.priors` to the policy in force **only when
    `r.settle` is zero after this pass**. While a settle pass is owed, keep the priors and close
    the newest's span at `rep.At`, so the settle pass judges every token minted under each of
    them since;
  - when a complete pass leaves `PolicyRefreshPending` at 0 and `r.onSettled` is set, call
    `r.onSettled(r.live.Load())`. `onSettled` is `func(pol *policy.Policy)` (Task 14), so the
    record can carry `pol.Raw()`.

  Update `refresh`'s comment. Every existing reload test passes: a pass with no settle owed
  resets as before.

- [ ] **Step 6: The runner.** Create `internal/port49d/runner.go`:

  ```go
  package port49d

  // runner is one port49-broker's part in the keyspace's one runner (plan
  // 7e, Ruling 6): it takes the hold (etcd.Store.Hold, as the broker),
  // runs the takeover, then the duties, until the hold is lost or ctx ends;
  // then it lets go and tries again every 5s. running is read by the
  // reloader to choose the whole refresh or its token half.
  type runner struct {
  	cfg     config.Config
  	brk     *broker.Broker
  	raw     *etcdstore.Store // the broker's own, outside the guard: the hold, the sweep, the record
  	st      store.Store      // the broker's sealed store
  	ledger  *crypt.Ledger
  	keys    crypt.Keys
  	m       *metrics.Metrics
  	alarm   *keyAlarm
  	who     string
  	held    string // the holder this process last held as, for the waiting line
  	rel     *reloader
  	on      atomic.Bool
  }

  func (r *runner) running() bool { return r.on.Load() }

  // run holds and runs until ctx ends.
  func (r *runner) run(ctx context.Context) {
  	e := r.cfg.Store.Etcd
  	for ctx.Err() == nil {
  		lost, release, err := r.raw.Hold(ctx, e.HoldTTL, r.who, func(holder string) {
  			if r.held != "" && holder == r.held {
  				// This replica's own last run, whose hold was lost and whose
  				// lease lives on: never "run by" itself (7d's I-2, 4001732;
  				// pre-flight M7).
  				fmt.Fprintf(stderr, "port49-broker: runner: keyspace %s is still held by this replica's last run "+
  					"(%s); waiting up to hold_ttl (%v) for its lease to expire\n", e.Prefix, lineHolder(holder),
  					e.HoldTTL)
  				return
  			}
  			fmt.Fprintf(stderr, "port49-broker: runner: keyspace %s is run by %s; this replica serves the API and "+
  				"takes over if that one stops\n", e.Prefix, lineHolder(holder))
  		})
  		if err != nil {
  			if ctx.Err() == nil {
  				fmt.Fprintf(stderr, "port49-broker: runner: taking keyspace %s: %v; trying again in 5s\n", e.Prefix, err)
  				sleepCtx(ctx, 5*time.Second)
  			}
  			continue
  		}
  		r.held = r.who
  		r.m.StoreKeyspaceHeld.Set(1)
  		fmt.Fprintf(stderr, "port49-broker: runner: took keyspace %s (%s): this replica runs the start, the sweep "+
  			"and the policy refresh\n", e.Prefix, lineHolder(r.who))
  		dctx, stop := context.WithCancel(ctx)
  		done := make(chan struct{})
  		go func() { defer close(done); r.duties(dctx) }()
  		select {
  		case <-ctx.Done():
  		case <-lost:
  			fmt.Fprintln(stderr, "port49-broker: runner: lost the keyspace's hold (its lock key is gone, or etcd "+
  				"stopped answering with half its lease or less left); the runner's duties stop; this replica keeps "+
  				"serving the API and tries to take the hold again every 5s")
  		}
  		stop()
  		<-done
  		r.on.Store(false)
  		r.m.StoreKeyspaceHeld.Set(0)
  		// The keeper reports (0, false) as it stops; set them here too, for
  		// a takeover that failed before the keeper started (pre-flight I11).
  		r.m.LedgerPending.Set(0)
  		r.m.LedgerBehind.Set(0)
  		release()
  		sleepCtx(ctx, 5*time.Second)
  	}
  }

  // duties is the takeover, then the sweep, the ledger record's keeper and
  // the refresh's context half, until ctx ends.
  func (r *runner) duties(ctx context.Context) {
  	if err := r.takeover(ctx); err != nil {
  		if ctx.Err() == nil {
  			fmt.Fprintf(stderr, "port49-broker: runner: the takeover stopped: %v; letting the hold go and trying "+
  				"again\n", err)
  		}
  		return
  	}
  	r.on.Store(true)
  	var wg sync.WaitGroup
  	wg.Add(2)
  	go func() { defer wg.Done(); sweepLoop(ctx, r.raw, r.brk, r.ledger, r.cfg.Store.Etcd.SweepInterval, stderr) }()
  	go func() {
  		defer wg.Done()
  		crypt.KeepLedger(ctx, r.ledger, r.raw, time.Second, func(n int, behind bool) {
  			r.m.LedgerPending.Set(float64(n))
  			r.m.LedgerBehind.Set(b2f(behind))
  		}, func(f string, a ...any) { fmt.Fprintf(stderr, "port49-broker: "+f+"\n", a...) })
  	}()
  	wg.Wait()
  }

  // recordJudged writes meta/judged for the policy in force, retried while
  // the store is unavailable and ctx lives, and says so (plan 7e, Ruling 7;
  // pre-flight I2). It is the only writer of the record: the takeover calls
  // it once its carry leaves nothing owed, and the reloader's onSettled
  // whenever a pass leaves nothing pending. Task 15a adds that every
  // replica must serve the bundle.
  func (r *runner) recordJudged(ctx context.Context, why string) {
  	pol := r.brk.Policy.Load()
  	if err := retryCtx(ctx, func() error { return r.raw.PutJudged(ctx, pol.Bundle, pol.Raw()) }); err != nil {
  		if ctx.Err() == nil {
  			fmt.Fprintf(stderr, "port49-broker: runner: recording bundle %s as judged: %v; the next takeover "+
  				"purges the unspent tokens\n", pol.Bundle, err)
  		}
  		return
  	}
  	fmt.Fprintf(stderr, "port49-broker: runner: recorded bundle %s as judged (%s)\n", pol.Bundle, why)
  }
  ```

  `retryCtx(ctx, f func() error) error` runs `f` until it returns nil, an error that is not
  `store.ErrUnavailable`, or ctx ends (ctx.Err()), waiting 5s between tries and saying each
  wait as `port49-broker: runner: <err>; trying again in 5s`. `sleepCtx(ctx, d)` waits d or for
  ctx. `orNone(bundle string, ok bool) string` is bundle, or `none recorded` when !ok. A
  failure fails toward purging at the next takeover, which denies more.

  `takeover(ctx) error` is 7e-1's `startOnPersistentStore(ctx, brk, st, e, cfg, &marks, m)` as
  built (`store.go:776` at `a5e4fe8`), renamed and moved here, with these changes:
  - its arguments are the runner's fields: `r.brk`, `r.st`, `r.raw` for `e` (the re-index's
    `Unindexed` scan on the broker's raw store, as 7e-1's ran it on the daemon's), `r.cfg` and
    `r.m`. `marks` is gone (below). It already takes no ledger: the base was set by
    `LoadLedger` in `runBroker`;
  - its lines say `port49-broker: runner: ` where 7e-1's say `port49d: store: ` or `port49d:
    broker: `, and "before serving" is dropped: the API already serves;
  - it runs `checkSealKeys(…, true)` first, with `r.raw` (7e-1 runs it in `openStores`, under
    the hold);
  - the revocations file's union is gone (7e-1's `inFile`, `extra` and its `brk.Persist`): the
    marks are the store's, listed by its `ListRevocations` step as now, and loaded by
    `store.LoadMarks` in `runBroker` before the API serves;
  - the purge, by Ruling 7, replaces the unconditional one:

  ```go
  	bundle := r.brk.Policy.Load().Bundle
  	var judged etcdstore.JudgedRecord
  	var ok bool
  	// Retried while unavailable, as every step is: an unavailable read taken
  	// as no record would purge when the store's state did not call for it.
  	if err := retryCtx(ctx, func() (e error) { judged, ok, e = r.raw.Judged(ctx); return }); err != nil {
  		return err
  	}
  	if ok && judged.Bundle == bundle {
  		fmt.Fprintf(stderr, "port49-broker: runner: the bundle in force (%s) is the one the last runner judged; no "+
  			"unspent token purged\n", bundle)
  	} else {
  		at := r.brk.Now()
  		// SupersedeAll first: a replay after any token is gone mints afresh (Task 5).
  		if err := retryCtx(ctx, func() error { return r.st.SupersedeAll(ctx, at) }); err != nil {
  			return err
  		}
  		var n int
  		if err := retryCtx(ctx, func() (e error) { n, e = r.st.PurgeTokens(ctx); return }); err != nil {
  			return err
  		}
  		fmt.Fprintf(stderr, "port49-broker: runner: the bundle in force (%s) is not the one the last runner judged "+
  			"(%s); %d unspent token(s) purged (run 'port49 token' again)\n", bundle, orNone(judged.Bundle, ok), n)
  	}
  ```

  - the carry's owed pass (`startLeftBy`) goes to `r.rel.startLeft(now)` through the reloader's
    own goroutine. Send it on a channel the reloader's `run` selects on (`r.rel.owed`), never by
    calling into the reloader from this goroutine;
  - **when the carry leaves no pass owed** (7d's `store.go:741-745`, where no reloader pass
    runs), the takeover calls `r.recordJudged(ctx, "the takeover's carry left nothing owed")`
    as its last step (pre-flight I2). Without it, a first install and every takeover after a
    purge left `meta/judged` absent, and every later takeover purged again;
  - `ledger.Seal()` is already gone (7e-1).

  `sweepLoop` takes the ledger since Task 7 (pre-flight M16), and prunes it after each sweep.
  The runner calls it as written above.

- [ ] **Step 7: `runBroker`.** Create `internal/port49d/brokerd.go`. Its body is `runOnce`'s
  broker path, in this order, each step as `runOnce` does it today unless said:
  1. `config.LoadBroker(cfgPath)`; `announce`.
  2. The metrics listener on `cfg.MetricsListen`, with `/healthz`, `/readyz` (the broker's
     readiness: `brk.SetReady`) and `/metrics`.
  3. The inventory: the fenced file, or the cold start from the service (`coldCopies`,
     `startCopy`), as `runOnce` does.
  4. The keys (`cfg.EncryptionKeys()`); the tag key from them, as today.
  5. The store, on the broker's identity alone, waited for as `openStores` waits:
     `start_timeout` on a cold start, no deadline after.
     - Before the wait, as 7e-1's `openStores` does: both feeds' `port49_store_feed_up` set to 0
       and their `port49_store_feed_rescans_total` series created (final review 7e-1 M-3), and
       `ledger.Fence().OnTimeout(m.StoreFenceTimeouts.Inc)` (M-4).
     - Its guard has `StopAfter: 0`. A broker never goes dark: the API answers 503
       `store_unavailable` from the guard, and readiness is never the store's (design §12).
     - It is wrapped as `crypt.Wrap(guard.WrapRev(crypt.Fenced(b, ledger), gc("broker")), keys, …,
       crypt.WithLedger(ledger), say)`, where `say` is
       `crypt.OnUnopenable(unopenableSayer("port49-broker", keys, stderr, time.Now))`, one for
       every layer: the broker's context reads wait for its feed as port49d's do (Task 8a). A
       broker whose feed is down answers 503 `store_unavailable` for what reads a context, and
       its refresh leaves those contexts pending. It never admits one.
  6. The ledger: `crypt.LoadLedger(ctx, b, b, keys, ledger)`, then `crypt.FollowContexts(ctx,
     b, b, keys, ledger, rev, up, rescanned, logf)` on its goroutine at once, its `up` setting
     `port49_store_feed_up{feed="contexts"}`, its `rescanned` counting
     `port49_store_feed_rescans_total{feed="contexts"}`, and its `logf` prefixed
     `port49-broker: `. The marks: `marks := store.NewMarks()`, then
     `marks.Count(func(principal, cert int) { … })` setting `port49_revocations_in_force` by
     kind as `runOnce` does (`main.go:820` at `a5e4fe8`), **before** `markRev, err =
     store.LoadMarks(ctx, b, marks, nil)`, or the gauge reads 0. Both loads are retried while
     unavailable.
  7. `buildBrokerAnchor` (the minter, the session manager, `brk.Marks = marks`, `Persist` nil).
     Set `brk.Say = func(format string, args ...any) { fmt.Fprintf(stderr, "port49-broker:
     "+format+"\n", args...) }`, so `MarkChanged`'s lines (a held connection closed, a lift a
     reload found) reach port49-broker's stderr (Ruling T9-c). Certificate status with
     `certStatusConfig(*cs, anchorCert, cfg.Broker.StateDir)`.
  8. The broker listener, every mark in `marks.All()` put in it, `brk.Conns = bl`. Only then
     start the marks feed, on its goroutine, joined at the drain: a change told before
     `brk.Conns` is set would reach no listener, and the listener was built from `marks.All()`
     at the load's revision, so nothing between is missed:

     ```go
     store.FollowMarks(ctx, b, marks, markRev, brk.MarkChanged,
     	func(up bool) { m.StoreFeedUp.WithLabelValues("marks").Set(b2f(up)) },
     	func() error { m.StoreFeedRescans.WithLabelValues("marks").Inc(); return nil },
     	func(format string, args ...any) { fmt.Fprintf(stderr, "port49-broker: "+format+"\n", args...) })
     ```

     `progress` is `WatchRevocations`'s, wired inside `FollowMarks` (final review 7e-1 I-1).
     The `rescanned` here only counts; Task 15b replaces it with `reloadHook`, which puts back
     on the runner, keeps what the copy holds on every other replica, and can refuse the
     reload.
  9. The admin socket: `admin.Server{Revoke: adminRevoke(brk), Revocations: adminRevocations(st),
     Now: time.Now, DiagnoseElsewhere: "port49d's admin socket"}`, with `Held` nil. In
     `admin.go`'s `keys_diagnose` case, when `s.Held == nil && s.DiagnoseElsewhere != ""`, the
     answer is `Response{Error: "port49-broker holds no device packets; keys diagnose is " +
     s.DiagnoseElsewhere}` (pre-flight M16).
  10. The lab's seeds, if any (`mintSeeds`), on every broker start.
  11. Serve. `port49-broker: listening on <api>, metrics on <metrics>`. `brk.SetReady(ReadyServing)`.
  12. The reloader: `newReloader(cfg, brk.Policy, brk.Log, pass, m, time.Now)`, where `pass`
      calls `brk.Refresh` while `rn.running()` and `brk.RefreshTokens` otherwise, and
      `onSettled` calls `rn.recordJudged(ctx, "a pass left nothing pending")` while running.
  13. The runner, `rn.run(ctx)`, on its goroutine.
  14. On a signal: drain as `runOnce` does. The runner lets go of the hold; the listener, the
      admin socket and the reloader stop. Every goroutine is joined.

  `BrokerMain(args)` parses `--config` (default `/etc/port49/port49-broker.yaml`), refuses any
  other subcommand or extra argument (exit 2), and runs `runBroker` under `signal.NotifyContext`,
  as `Main` runs `run`. SIGHUP is caught and reloads, as port49d's does. Task 15b adds the one
  subcommand, `revoke --offline`. Create `cmd/port49-broker/main.go`:

  ```go
  // Command port49-broker is port49's broker, its own process on etcd (plan
  // 7e; internal/port49d).
  package main

  import (
  	"os"

  	"github.com/rhwendt/port49/internal/port49d"
  )

  func main() { os.Exit(port49d.BrokerMain(os.Args[1:])) }
  ```

  In the `Makefile`'s `build`, add `go build -o bin/port49-broker ./cmd/port49-broker`.
  `holderShape` in `store.go` admits `port49-broker on …` beside `port49d on …`.

- [ ] **Step 8: The skipped e2e tests, on the split.** Unskip Task 14's four tests. Rewrite each
  to start `startSplitDaemon` and `startBroker` on `splitFleet`, keeping what it asserts:
  - **`TestRunOnEtcdKeepsALoginAcrossARestart`:** restart the daemon; then restart the broker and
    assert the token minted before is still redeemable (Ruling 7, the same bundle). The 7d
    assertion that it is purged now belongs to `TestATakeoverPurgesOnlyAnUnjudgedBundle`.
  - **`TestAStartAppliesAStandingMarkToAKeptContext`:** the mark is put into the store as etcd's
    root with every broker stopped, standing in for the file edit, which no longer exists. The
    runner's takeover then applies it: `(1 context(s) marked revoked)`.
  - **`TestAStartSealsTheLedgerOnceItHasReadTheStore`:** unchanged on the daemon.
  - **`TestAHungStoreGoesDarkAndServesAgainWhenItReturns`:** on the daemon, which goes dark on
    its guard and probe. The broker's runner loses its hold.

  And 7e-1's two, which Task 14 skipped:
  - **`TestAMarkFromAnotherBrokerProcessReachesThisOne`:** the mark is made on one
    port49-broker's admin socket (or written as etcd's root, as 7e-1's test stands in for
    another broker process), and reaches the other port49-broker's listener and marks, and the
    daemon's: the held connection closes, the `MarkChanged` line is on port49-broker's stderr
    through `brk.Say`, and the daemon's `port49_revocations_in_force` follows.
  - **`TestAStartSeededFromTheLedgerRecordDeniesAPutBack`:** the daemon is stopped, and the
    runner's keeper writes the record the restarted daemon is seeded from. bob is a second
    identity of alice's subject (`sharedUsernamePolicy`, as built in Task 10), so the put-back
    is another principal at the same key. Both positive controls stay.

- [ ] **Step 9: Run everything.**

  Run: `make build && make test && make vet && make test-race`
  Expected: PASS, with no test skipped for Task 15.

- [ ] **Step 10: Commit.**

  ```bash
  gofmt -w internal/port49d internal/broker internal/store/etcd cmd/port49-broker
  git add cmd/port49-broker/main.go internal/port49d/brokerd.go internal/port49d/runner.go \
    internal/port49d/brokerd_test.go internal/port49d/reload.go internal/port49d/reload_test.go \
    internal/port49d/store.go internal/port49d/store_test.go internal/port49d/certstatus.go \
    internal/port49d/store_e2e_test.go internal/broker/refresh.go internal/broker/refresh_test.go \
    internal/store/etcd/meta.go internal/store/etcd/meta_test.go internal/daemon/admin/admin.go \
    internal/daemon/admin/admin_test.go Makefile
  git commit -m "feat(port49-broker): the broker as its own process, with one runner per keyspace

  port49-broker serves the API on the broker's identity alone. Its
  replicas share the keyspace hold as the runner's: the runner records the
  seal keys, re-indexes, applies the marks, purges only a bundle no runner
  judged, carries the policy, records its bundle as judged when nothing is
  owed (pre-flight I2), sweeps, and keeps the ledger record; every replica
  runs its own reload's token half. A replica whose last run still holds
  the lease says so (7d's I-2). The settle pass keeps the replaced
  policies until it completes, so a late replica's tokens are judged (plan
  7e Rulings 6-9, 12, 13).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 15a: Policy across replicas, and the reload guard at a start

**Files:**
- Modify: `internal/store/etcd/meta.go` (`PutBundle`, `Bundles`, `Holder`, `PutRefreshOwed`,
  `RefreshOwed`, `ClearRefreshOwed`), `meta_test.go`
- Create: `internal/port49d/policyskew.go`, `internal/port49d/policyskew_test.go`
- Create: `internal/port49d/startguard.go`, `internal/port49d/startguard_test.go`
- Modify: `internal/port49d/reload.go` (`onSwap`; `fullPass`, the channel a full context pass
  is owed on), `internal/port49d/runner.go` (`recordJudged`'s condition; the owed passes),
  `internal/port49d/brokerd.go` (the guard at start; the bundle keeper)
- Modify: `internal/daemon/metrics/metrics.go`, `metrics_test.go` (`PolicyBundleMatchesRunner`)
- Modify: `internal/port49d/brokerd_test.go` (the fleet tests below)
- Modify: `internal/port49d/store.go` (`stores.judged`, the daemon's raw store),
  `internal/port49d/main.go` (port49d runs `keepDaemonBundle`; re-check R5)

**Interfaces:**
- Consumes: Task 15's runner, `recordJudged`, `etcd.JudgedRecord`; `bundle.CheckAdmission`;
  `parseBundle`, `refusalLine`; `policy.MaxTokenTTL` (Task 5).
- Produces (`etcd`):
  - `type BundleRecord struct { Who, Bundle string; At, ExpiresAt time.Time }`.
  - `func (s *Store) PutBundle(ctx context.Context, who, bundle string, ttl time.Duration) error`:
    `meta/bundles/<esc(who)>`, expiring at `now + ttl` (its lease is `cas`'s bucket past that;
    the expiry decides).
  - `func (s *Store) DeleteBundle(ctx context.Context, who string) error`: deletes this
    replica's record, at its graceful stop (pre-flight 7e-2 P-5).
  - `func (s *Store) Bundles(ctx context.Context) ([]BundleRecord, error)`: every record whose
    ExpiresAt is after now. A
    record that does not decode is an error naming its key.
  - `func (s *Store) Holder(ctx context.Context) (string, bool, error)`: `meta/holder`, the
    runner's `who`: `getJSON(ctx, s.ctxKV, s.k.meta("holder"), &h)`, as `Hold`'s wait already
    reads it (`meta.go:103`).
  - `func (s *Store) PutRefreshOwed(ctx context.Context, who, bundle string) error`,
    `func (s *Store) RefreshOwed(ctx context.Context) (rev uint64, rec BundleRecord, ok bool, err error)`
    and `func (s *Store) ClearRefreshOwed(ctx context.Context, rev uint64) error`. The clear is a
    delete on a compare of the record's mod revision, so an ask written during the pass stays.
- Produces (`port49d`):
  - `func keepBundle(ctx context.Context, raw bundleStore, who string, live *policy.Live, ttl time.Duration, swapped <-chan struct{}, m *metrics.Metrics, out io.Writer)`.
    Every `ttl/3`, and at once on each receive from `swapped`, it writes this replica's
    record. Each round it reads `Bundles` and `Holder`, sets
    `port49_policy_bundle_matches_runner`, and says a mismatch once per pair of bundles.
  - `func owedFullPassAt(lastMismatch time.Time) time.Time`: `lastMismatch.Add(policy.MaxTokenTTL)`.
  - `func keepDaemonBundle(ctx context.Context, judged judgedReader, live *policy.Live, every time.Duration, m *metrics.Metrics, out io.Writer)`
    (re-check R5): port49d's half. Every `every` it reads `meta/judged` and sets
    `port49_policy_bundle_matches_runner` to whether `live`'s bundle is the one judged; a
    mismatch is said once per pair. No record sets 1 and says nothing; a read that fails
    leaves the gauge as it was, as `keepBundle` does.
  - `stores.judged judgedReader`: the daemon's raw etcd store, nil on memory.
  - `reloader.onSwap func(pol *policy.Policy)`, called after every swap, on the reloader's
    goroutine.
  - `reloader.fullPass chan fullPassOwed`, which `run` selects on. A full context pass is
    `brk.Refresh(ctx, []broker.Prior{{Policy: cur, At: now}})`, said as `runner: a full
    context pass owed by <who> (bundle …): <report>`.
  - `func guardAtStart(ctx context.Context, cfg config.Config, judged judgedReader, pol *policy.Policy, now time.Time) (refused error, said string)`.
    `refused` is non-nil when `bundle.CheckAdmission` refuses `pol` against the recorded
    policy. `said` is the one line for a start the guard could not judge, and is empty when it
    judged. `judgedReader` is `interface{ Judged(context.Context) (etcdstore.JudgedRecord, bool, error) }`.
  - `Metrics.PolicyBundleMatchesRunner prometheus.Gauge` (`port49_policy_bundle_matches_runner`).

Ruling 8 as corrected (pre-flight I3) with port49d's gauge (re-check R5), and Ruling 17
(pre-flight I6, 7c's carry).

- [ ] **Step 1: The failing tests.** In `internal/store/etcd/meta_test.go`, on `onShared(t,
  time.Now)`:
  - `TestBundlesAreLeasedAndListed`: two `PutBundle`s list two records. One put with a 2s
    `ttl` is gone from `Bundles` within 5s. A `who` with spaces and parentheses round-trips. A
    `DeleteBundle` removes the record at once.
  - `TestRefreshOwedIsClearedOnlyAtItsRevision`: `PutRefreshOwed`, then `RefreshOwed` gives
    `rev1`. A second `PutRefreshOwed` gives `rev2`. `ClearRefreshOwed(rev1)` leaves the record;
    `ClearRefreshOwed(rev2)` deletes it.

  Create `internal/port49d/startguard_test.go`:

  ```go
  // judgedAt is a judgedReader holding one record, or none.
  type judgedAt struct {
  	rec etcdstore.JudgedRecord
  	ok  bool
  }

  func (j judgedAt) Judged(context.Context) (etcdstore.JudgedRecord, bool, error) { return j.rec, j.ok, nil }

  // A start whose policy file the reload guard would refuse against the
  // policy last judged is refused; one it cannot judge says why and goes on
  // (Ruling 17; pre-flight I6).
  func TestAStartRefusesAFileTheGuardRefusesAgainstTheJudgedBundle(t *testing.T) {
  	cfg := brokerConfig(t, minimalPolicy) // its inventory: leaf1
  	cfg.MaxRemovedPercent = 20
  	inv := cfg.Inventory
  	good, err := parseBundle(cfg, []byte(minimalPolicy), inv)
  	if err != nil {
  		t.Fatal(err)
  	}
  	none, err := parseBundle(cfg, []byte(admitsNothingPolicy), inv) // scopes match no device
  	if err != nil {
  		t.Fatal(err)
  	}
  	ctx, now := context.Background(), time.Now()
  	recorded := judgedAt{rec: etcdstore.JudgedRecord{Bundle: good.Bundle, Policy: good.Raw()}, ok: true}
  	if refused, said := guardAtStart(ctx, cfg, recorded, none, now); refused == nil || said != "" {
  		t.Fatalf("a file admitting no device, against a judged one admitting leaf1: %v %q", refused, said)
  	}
  	if refused, said := guardAtStart(ctx, cfg, recorded, good, now); refused != nil || said != "" {
  		t.Fatalf("the judged bundle itself: %v %q", refused, said)
  	}
  	for name, j := range map[string]judgedAt{
  		"no record":      {},
  		"no policy":      {rec: etcdstore.JudgedRecord{Bundle: "b-other"}, ok: true},
  		"does not parse": {rec: etcdstore.JudgedRecord{Bundle: "b-other", Policy: []byte("scopes: [")}, ok: true},
  	} {
  		if refused, said := guardAtStart(ctx, cfg, j, none, now); refused != nil || said == "" {
  			t.Fatalf("%s: the guard cannot judge, so the start goes on and says why: %v %q", name, refused, said)
  		}
  	}
  }
  ```

  `admitsNothingPolicy` is `minimalPolicy` with its scope matching a device name no inventory
  holds. If `CheckAdmission` refuses a policy admitting nothing whatever the bound
  (`admitsNone`), that is the refusal this test sees; keep it.

  Create `internal/port49d/policyskew_test.go`:

  ```go
  // A replica whose bundle is not the runner's gauges 0 and says so once per
  // pair; matching, it gauges 1 (pre-flight I3).
  func TestAReplicaServingAnotherBundleSaysSo(t *testing.T) {
  	var out syncBuffer
  	m := metrics.New(prometheus.NewRegistry())
  	st := &fakeBundles{holder: "runner-a", recs: []etcdstore.BundleRecord{{Who: "runner-a", Bundle: "b-new"}}}
  	live := policy.NewLive(policyWithBundle(t, "b-old"))
  	ctx, cancel := context.WithCancel(context.Background())
  	defer cancel()
  	go keepBundle(ctx, st, "replica-b", live, 300*time.Millisecond, nil, m, &out)
  	waitFor(t, &out, "this replica serves bundle b-old and the runner")
  	if v := testutil.ToFloat64(m.PolicyBundleMatchesRunner); v != 0 {
  		t.Fatalf("gauge %v with another bundle", v)
  	}
  	time.Sleep(time.Second) // several rounds: the line is said once
  	if n := strings.Count(out.String(), "this replica serves bundle b-old"); n != 1 {
  		t.Fatalf("said %d times", n)
  	}
  	st.set("runner-a", "b-old")
  	waitUntil(t, "the gauge to match the runner", func() bool { return testutil.ToFloat64(m.PolicyBundleMatchesRunner) == 1 })
  	if got := st.put("replica-b"); got != "b-old" {
  		t.Fatalf("the replica recorded %q", got)
  	}
  	cancel() // a graceful stop deletes the record (pre-flight 7e-2 P-5)
  	waitUntil(t, "the stopped replica's record is deleted", func() bool { return st.put("replica-b") == "" })
  }

  // A full pass is owed once every token a mismatched replica could have
  // minted has expired.
  func TestAFullPassIsOwedATokenLifeAfterTheLastMismatch(t *testing.T) {
  	at := time.Unix(1_000_000, 0)
  	if got := owedFullPassAt(at); !got.Equal(at.Add(policy.MaxTokenTTL)) {
  		t.Fatalf("%v", got)
  	}
  }

  // A port49d whose policy is not the bundle last judged gauges 0 and says
  // so once per pair; with no record it gauges 1 and says nothing; matching,
  // 1 (re-check R5). The daemon's role cannot write meta/, so it reads the
  // runner's judged record.
  func TestADaemonServingAnotherBundleThanTheJudgedSaysSo(t *testing.T) {
  	var out syncBuffer
  	m := metrics.New(prometheus.NewRegistry())
  	j := &judgedVar{}
  	live := policy.NewLive(policyWithBundle(t, "b-old"))
  	ctx, cancel := context.WithCancel(context.Background())
  	defer cancel()
  	m.PolicyBundleMatchesRunner.Set(0)
  	go keepDaemonBundle(ctx, j, live, 100*time.Millisecond, m, &out)
  	waitUntil(t, "the daemon's gauge to match the judged bundle", func() bool { return testutil.ToFloat64(m.PolicyBundleMatchesRunner) == 1 })
  	if out.String() != "" {
  		t.Fatalf("with no judged record: %q", out.String())
  	}
  	j.set(etcdstore.JudgedRecord{Bundle: "b-new"}, true)
  	waitFor(t, &out, "this port49d serves bundle b-old and the bundle last judged by the runner is b-new")
  	if v := testutil.ToFloat64(m.PolicyBundleMatchesRunner); v != 0 {
  		t.Fatalf("gauge %v with another bundle judged", v)
  	}
  	time.Sleep(500 * time.Millisecond) // several rounds: the line is said once
  	if n := strings.Count(out.String(), "this port49d serves bundle b-old"); n != 1 {
  		t.Fatalf("said %d times", n)
  	}
  	j.set(etcdstore.JudgedRecord{Bundle: "b-old"}, true)
  	waitUntil(t, "the daemon's gauge to match the judged bundle", func() bool { return testutil.ToFloat64(m.PolicyBundleMatchesRunner) == 1 })
  }

  // judgedVar is a judgedReader whose record the test changes.
  type judgedVar struct {
  	mu  sync.Mutex
  	rec etcdstore.JudgedRecord
  	ok  bool
  }

  func (j *judgedVar) Judged(context.Context) (etcdstore.JudgedRecord, bool, error) {
  	j.mu.Lock()
  	defer j.mu.Unlock()
  	return j.rec, j.ok, nil
  }

  func (j *judgedVar) set(rec etcdstore.JudgedRecord, ok bool) {
  	j.mu.Lock()
  	defer j.mu.Unlock()
  	j.rec, j.ok = rec, ok
  }
  ```

  `fakeBundles` implements `bundleStore` (`PutBundle`, `DeleteBundle`, `Bundles`, `Holder`) in
  memory under a lock, with `set(who, bundle)` and `put(who) string` (`""` once deleted).
  `policyWithBundle(t, bundle)` loads `minimalPolicy` into the named bundle. `waitUntil` is
  `revocations_test.go`'s (`what`, `cond`), which polls for 5s. `judgedAt`
  (`startguard_test.go`) is the fixed reader; `judgedVar` changes, and needs `"sync"` in the
  file's imports.

  In `brokerd_test.go`, on `splitFleet`:

  ```go
  // A replica that minted under a policy the runner had replaced, then
  // reloads, has the runner carry the context its token made: the runner
  // runs a full context pass on its ask. Meanwhile the runner records no
  // bundle as judged (pre-flight I3; Ruling 8 corrected).
  func TestALateReplicasContextIsCarriedWhenItReloads(t *testing.T) {
  	var out, log syncBuffer
  	e, o := stderr, stdout
  	t.Cleanup(func() { stderr, stdout = e, o })
  	stderr, stdout = &out, &log
  	f := splitFleet(t)
  	tacacs := startSplitDaemon(t, f.daemon, &out, 1)
  	startBroker(t, f.broker, &out, 1)
  	waitFor(t, &out, "runner: recorded bundle ")
  	cfgB := f.copyBroker(t) // a policy file of its own
  	apiB, _ := startBroker(t, cfgB, &out, 2)
  	f.writePolicyOf(t, f.broker, withdrawnConfigurePolicy) // A's file only: alice loses configure
  	waitFor(t, &out, "policy reloaded")
  	waitFor(t, &out, "this replica serves bundle ")
  	waitFor(t, &out, "runner: not recording bundle ")
  	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
  	loginSession(t, dev, mintOn(t, apiB, f.pki, "leaf1"), &log) // under B's old policy
  	if !dev.permits("alice", "configure") {
  		t.Fatal("control: the context B's token made should carry the old grant")
  	}
  	f.writePolicyOf(t, cfgB, withdrawnConfigurePolicy) // B catches up
  	waitFor(t, &out, "runner: a full context pass owed by ")
  	if dev.permits("alice", "configure") {
  		t.Fatal("the context a late replica's token made kept the withdrawn grant after it reloaded")
  	}
  	waitForCount(t, &out, "runner: recorded bundle ", 2)
  }

  // A start whose policy file the guard refuses against the bundle last
  // judged stays not ready and takes no hold, until the file is fixed
  // (Ruling 17; pre-flight I6).
  func TestAStartOnARefusedFileStaysNotReady(t *testing.T) {
  	var out syncBuffer
  	e := stderr
  	t.Cleanup(func() { stderr = e })
  	stderr = &out
  	f := splitFleet(t)
  	_, stop := startBrokerNoWait(t, f.broker, &out, 1)
  	waitFor(t, &out, "runner: recorded bundle ")
  	stop()
  	f.writePolicyOf(t, f.broker, admitsNothingPolicy)
  	startBrokerNoWait(t, f.broker, &out, 2)
  	waitFor(t, &out, "policy file refused at start against the bundle last judged")
  	if code := readyzAt(t, f.metricsOf(t, f.broker)); code != http.StatusServiceUnavailable {
  		t.Fatalf("/readyz %d while the file is refused", code)
  	}
  	if strings.Count(out.String(), "runner: took keyspace") != 1 {
  		t.Fatal("a broker on a refused file took the hold")
  	}
  	f.writePolicyOf(t, f.broker, minimalPolicy)
  	waitForCount(t, &out, "runner: took keyspace", 2)
  }
  ```

  The helpers, beside `splitFleet`'s:
  - `startBrokerNoWait` is `startBroker` that waits for the metrics line, not the API's;
  - `f.writePolicyOf(t, cfg, body)` rewrites the policy file the config names, behind the
    fence's owner and mode rules, as `reload_test.go`'s writes do;
  - `withdrawnConfigurePolicy` is `minimalPolicy` whose role permits `show **` alone;
  - `f.metricsOf(t, cfg)` is the config's metrics address;
  - `readyzAt(t, addr string) int` gets `/readyz` at addr and returns its status (not
    `service_e2e_test.go`'s `readyz`, which stays).

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/store/etcd/ ./internal/port49d/ -run 'Bundles|RefreshOwed|GuardRefuses|AnotherBundle|FullPassIsOwed|LateReplica|RefusedFile|DaemonServing' -count=1`
  Expected: FAIL to compile (`PutBundle`, `guardAtStart`, `keepBundle`, `owedFullPassAt`,
  `keepDaemonBundle` undefined). With `keepDaemonBundle` setting the gauge to 1 whatever was
  judged, `TestADaemonServingAnotherBundleThanTheJudgedSaysSo` fails.

- [ ] **Step 3: The records.** In `meta.go`, beside `Judged`:
  - `PutBundle` writes `bundleRec{Who, Bundle, At, ExpiresAt: now + ttl}` at
    `s.k.meta("bundles/") + esc(who)` with `cas` (`live` is `now.Before(r.ExpiresAt)`, as
    `supersededRec.live`; `f` writes always and names `ExpiresAt` as the lease's expiry).
  - `Bundles` reads the prefix in pages at one revision, as `LedgerMarks` does, and returns
    the records whose ExpiresAt is after now: a lease only reclaims (leases.go), so a lapsed
    record can remain up to a minute and lease_grace past its ttl, and is skipped by its own
    expiry, as every leased record is.
  - `DeleteBundle(ctx, who)` deletes this replica's record (P-5).
  - `Holder` reads `meta/holder` with `getJSON(ctx, s.ctxKV, s.k.meta("holder"), &h)`.
  - Every KV call on the context client goes through `s.ctxKV`, so `Seen()` sees it (Ruling
    T6-a): `PutBundle`'s `cas`, `Bundles`, `DeleteBundle`, `Holder` and the `*RefreshOwed`
    calls alike.
  - `PutRefreshOwed` puts `bundleRec` at `meta/refresh_owed`.
  - `RefreshOwed` returns its mod revision with it.
  - `ClearRefreshOwed(rev)` is a transaction: `If(ModRevision(key) == rev).Then(OpDelete(key))`.

- [ ] **Step 4: The replica's record and the gauge.** Create `policyskew.go`:

  ```go
  package port49d

  // bundleStore is what keepBundle reads and writes (etcd.Store).
  type bundleStore interface {
  	PutBundle(ctx context.Context, who, bundle string, ttl time.Duration) error
  	DeleteBundle(ctx context.Context, who string) error
  	Bundles(ctx context.Context) ([]etcdstore.BundleRecord, error)
  	Holder(ctx context.Context) (string, bool, error)
  }

  // keepBundle records the bundle this replica serves, leased for ttl and
  // renewed every third of it and at every swap, and gauges whether it is
  // the runner's (plan 7e, Ruling 8; pre-flight I3): each replica reads its
  // own broker.policy_file, and propagation can skew them past any settle
  // window. A mismatch is said once per pair of bundles. A store that does
  // not answer leaves the gauge as it was: the record lapses on its own.
  func keepBundle(ctx context.Context, raw bundleStore, who string, live *policy.Live, ttl time.Duration,
  	swapped <-chan struct{}, m *metrics.Metrics, out io.Writer) {
  	t := time.NewTicker(ttl / 3)
  	defer t.Stop()
  	said := ""
  	for {
  		mine := live.Load().Bundle
  		rctx, cancel := context.WithTimeout(ctx, ttl/3)
  		_ = raw.PutBundle(rctx, who, mine, ttl)
  		recs, err := raw.Bundles(rctx)
  		holder, held, herr := raw.Holder(rctx)
  		cancel()
  		if err == nil && herr == nil && held {
  			theirs, match := mine, true
  			for _, r := range recs {
  				if r.Who == holder {
  					theirs, match = r.Bundle, r.Bundle == mine
  				}
  			}
  			m.PolicyBundleMatchesRunner.Set(b2f(match))
  			if pair := mine + " " + theirs; !match && pair != said {
  				fmt.Fprintf(out, "port49-broker: policy: this replica serves bundle %s and the runner (%s) serves "+
  					"bundle %s; set the same broker.policy_file content and broker.policy_watch_interval on every "+
  					"replica\n", mine, lineHolder(holder), theirs)
  				said = pair
  			} else if match {
  				said = ""
  			}
  		}
  		select {
  		case <-ctx.Done():
  			// A replica that stops mints nothing more: its record goes with it,
  			// so a takeover right after a rollout judges the replicas that serve.
  			// One that dies leaves its record to lapse (ExpiresAt).
  			dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
  			_ = raw.DeleteBundle(dctx, who)
  			cancel()
  			return
  		case <-t.C:
  		case <-swapped:
  		}
  	}
  }

  // owedFullPassAt is when the runner owes a full context pass after it last
  // saw a replica serve another bundle: every token that replica could have
  // minted under it has expired by then, so the pass reaches every context
  // one of them made (pre-flight I3).
  func owedFullPassAt(lastMismatch time.Time) time.Time { return lastMismatch.Add(policy.MaxTokenTTL) }

  // keepDaemonBundle is port49d's half (re-check R5): its own policy file
  // decides admission, quarantine and redaction, and can differ from the
  // brokers'. Its role cannot write meta/, so it records nothing; it reads
  // the bundle the runner last judged (meta/judged) every every, gauges
  // whether its own is that one, and says a mismatch once per pair. Right
  // after a rollout the record lags until the runner's settle pass, so a 0
  // then is expected for that long. With no record nothing is known to
  // differ: it gauges 1 and says nothing. A store that does not answer
  // leaves the gauge as it was.
  func keepDaemonBundle(ctx context.Context, judged judgedReader, live *policy.Live, every time.Duration,
  	m *metrics.Metrics, out io.Writer) {
  	t := time.NewTicker(every)
  	defer t.Stop()
  	said := ""
  	for {
  		mine := live.Load().Bundle
  		rctx, cancel := context.WithTimeout(ctx, every)
  		rec, ok, err := judged.Judged(rctx)
  		cancel()
  		if err == nil {
  			match := !ok || rec.Bundle == mine
  			m.PolicyBundleMatchesRunner.Set(b2f(match))
  			if pair := mine + " " + rec.Bundle; !match && pair != said {
  				fmt.Fprintf(out, "port49d: policy: this port49d serves bundle %s and the bundle last judged by "+
  					"the runner is %s; set the same policy file on port49d (policy.file) as on every port49-broker "+
  					"(broker.policy_file)\n", mine, rec.Bundle)
  				said = pair
  			} else if match {
  				said = ""
  			}
  		}
  		select {
  		case <-ctx.Done():
  			return
  		case <-t.C:
  		}
  	}
  }
  ```

  The runner's own replica runs `keepBundle` too, so its record is the one the others compare
  with. On the runner the gauge is 1 by construction.

- [ ] **Step 5: The runner's owed passes and its judged condition.** In `runner.go`'s `duties`,
  add a third goroutine, `r.owed(ctx)`, which every `policy_watch_interval`:
  - reads `RefreshOwed`. When its revision is newer than the last one handled, it sends
    `fullPassOwed{who, bundle, rev}` on `r.rel.fullPass`;
  - reads `Bundles`. When any record's bundle differs from the runner's, it sets
    `lastMismatch = now`;
  - when `lastMismatch` is set and `now` is past `owedFullPassAt(lastMismatch)`, it sends a
    `fullPassOwed{who: "a replica that served another bundle"}` once, and clears
    `lastMismatch`.

  In `reload.go`'s `run`, a receive on `fullPass` runs the full context pass, says its line, and
  then, if `rev` is set, calls `ClearRefreshOwed(rev)`. A pass that fails is said and left owed:
  the record stays, and the next read sends it again.

  `recordJudged` reads `Bundles` first. When a record names another bundle, it says
  `port49-broker: runner: not recording bundle %s as judged: %s serves bundle %s` and writes
  nothing. That makes the next takeover purge, which denies more.

- [ ] **Step 6: Every replica asks.** In `brokerd.go`:
  - start `keepBundle(ctx, b, who, brk.Policy, e.HoldTTL, swapped, m, stderr)` on its
    goroutine, joined at the end;
  - the reloader's `onSwap` pokes `swapped` (non-blocking, buffered one), and, when
    `!rn.running()`, calls `PutRefreshOwed(ctx, who, pol.Bundle)`, retried as the takeover's
    steps are;
  - after the guard at start passes, a replica that is not yet the runner calls
    `PutRefreshOwed` once. A replica's start then makes the runner judge every live context
    against the policy in force, so a context made from an earlier life's token, under
    another bundle, is carried. A rolling restart of N replicas costs N full context passes:
    a full pass is what every takeover's carry already is.

  And port49d's half (re-check R5):
  - in `store.go`'s `openStores`, the daemon's etcd path sets `stores.judged = d`, the daemon's
    raw store (its role reads `meta/`). Memory leaves it nil;
  - in `main.go`'s `runOnce`, when `sts.judged != nil`, start `keepDaemonBundle(ctx,
    sts.judged, live, cfg.Policy.WatchInterval, m, stderr)` on a goroutine beside
    `sts.follow` and `sts.probe`, joined before `sts.close`. The read goes through no guard:
    it is a gauge, and a store gone is the probe's to judge.

- [ ] **Step 7: The guard at start.** Create `startguard.go`:

  ```go
  package port49d

  // judgedReader reads meta/judged (etcd.Store).
  type judgedReader interface {
  	Judged(ctx context.Context) (etcdstore.JudgedRecord, bool, error)
  }

  // guardAtStart is the reload guard run at a broker's start, against the
  // policy meta/judged records (plan 7e, Ruling 17; 7c's carry): a rollout
  // restarts every replica onto the file on disk, and a file a running
  // broker refused would otherwise be carried into every context and its
  // newly refused devices' tokens deleted. refused is the guard's error.
  // When it cannot judge (no record, a record with no policy, a recorded
  // policy that no longer compiles against the inventory in force), said
  // names why and the start goes on: the guard is a typo guard, and a broker
  // stranded by an inventory edit would cost every login.
  func guardAtStart(ctx context.Context, cfg config.Config, judged judgedReader, pol *policy.Policy,
  	now time.Time) (refused error, said string) {
  	rec, ok, err := judged.Judged(ctx)
  	switch {
  	case err != nil:
  		return nil, fmt.Sprintf("the bundle last judged could not be read (%v); this start is not judged against it", err)
  	case !ok:
  		return nil, "no bundle has been judged on this keyspace; this start is not judged against one"
  	case rec.Bundle == pol.Bundle:
  		return nil, ""
  	case rec.Policy == nil:
  		return nil, fmt.Sprintf("the bundle last judged (%s) was recorded without its policy (over 1 MiB); "+
  			"this start is not judged against it", rec.Bundle)
  	}
  	old, err := parseBundle(cfg, rec.Policy, pol.Inventory())
  	if err != nil {
  		return nil, fmt.Sprintf("the policy last judged (%s) does not compile against the inventory in force (%v); "+
  			"this start is not judged against it", rec.Bundle, oneLine(err))
  	}
  	if err := bundle.CheckAdmission(old, pol, cfg.MaxRemovedPercent, now); err != nil {
  		return fmt.Errorf("%s: %w", policyKey(cfg), err), ""
  	}
  	return nil, ""
  }
  ```

  In `runBroker`, between the store's open (step 5) and serving (step 11), on the store's
  first answer:
  - run `guardAtStart` with the policy loaded at step 3. A `said` line is printed once,
    prefixed `port49-broker: policy: `.
  - **On a refusal**, print `port49-broker: policy file refused at start against the bundle
    last judged (<bundle>): <refusalLine(refused, false, old, pol)>; this replica stays not
    ready, mints nothing and takes no hold until broker.policy_file is fixed`, and set
    `PolicyFileRefused` to 1.
  - Then poll the file every `policy_watch_interval`, by `policyVersion` and `parseBundle`,
    until a version passes. Keep `brk.SetReady` at its starting state meanwhile, so `/readyz`
    answers 503. Do not start the runner. Serve nothing that mints: the API listener is not
    started.
  - Once a version passes, set `PolicyFileRefused` to 0 and go on with the start on that
    policy.

  port49d's start does not run it (Ruling 17).

- [ ] **Step 8: The metric.** In `metrics.go`, add `PolicyBundleMatchesRunner prometheus.Gauge`
  (`port49_policy_bundle_matches_runner`, "1 while this broker serves the bundle the runner
  serves, or this port49d the bundle the runner last judged; 0 on a broker is a replica whose
  policy file differs: its tokens and the contexts they make carry another policy until it
  reloads; 0 on a port49d past the runner's settle pass is a policy file that differs from the
  brokers', for admission, quarantine and redaction"), and add it to
  `TestNewRegistersEveryMetric`.

- [ ] **Step 9: Run everything.**

  Run: `make build && make test && make vet && make test-race`
  Expected: PASS.

- [ ] **Step 10: Commit.**

  ```bash
  gofmt -w internal/port49d internal/store/etcd internal/daemon/metrics
  git add internal/store/etcd/meta.go internal/store/etcd/meta_test.go internal/port49d/policyskew.go \
    internal/port49d/policyskew_test.go internal/port49d/startguard.go internal/port49d/startguard_test.go \
    internal/port49d/reload.go internal/port49d/runner.go internal/port49d/brokerd.go \
    internal/port49d/brokerd_test.go internal/port49d/store.go internal/port49d/main.go \
    internal/daemon/metrics/metrics.go internal/daemon/metrics/metrics_test.go
  git commit -m "feat(port49-broker): policy skew across replicas, and the reload guard at a start

  Each replica reads its own policy file, and propagation can skew them
  past any settle window: a replica minting under a withdrawn grant made
  contexts no pass reached (pre-flight I3). Every replica now records the
  bundle it serves and gauges whether it is the runner's; its reload or
  start asks the runner for a full context pass; a replica that dies
  unreloaded is covered a token life later; and no bundle is recorded as
  judged while one differs. port49d, which cannot write meta/, gauges its
  own policy against the bundle last judged (re-check R5). A start whose
  policy file the reload guard refuses against the policy last judged
  stays not ready and takes no hold (7c's carry; pre-flight I6; plan 7e
  Rulings 8, 17).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 15b: The marks copy, and revoking with every broker down

**Files:**
- Create: `internal/port49d/markscopy.go`, `internal/port49d/markscopy_test.go`
- Create: `internal/port49d/offline.go`, `internal/port49d/offline_test.go`
- Modify: `internal/port49d/brokerd.go` (the copy fed by `FollowMarks`; the marks feed's
  `rescanned` is the runner's hook; `BrokerMain`'s `revoke` subcommand),
  `internal/port49d/runner.go` (`putBackMissing`, `restoreMarks` at the takeover, `reloadHook`
  before a marks reload)
- Modify: `internal/port49d/brokerd_test.go` (the fleet tests below), `internal/port49d/
  runner_test.go` (new: the hook's unit test)

**Interfaces:**
- Consumes: `store.MarkChange` (Task 9); `store.FollowMarks(…, rescanned func() error, …)` as
  built in 7e-1, whose failing hook refuses the reload (re-review 1 C-2); `BrokerConfig.StateDir`
  (Task 13); the runner and its marks feed (Task 15); `namedMarks` (Task 14); `broker.Revoke`,
  `broker.Lift`, `broker.RevokeRequest`; `etcdtest.Options.ProgressNotify` and
  `etcdtest.Proxy.Drop` (7e-1).
- Produces:
  - `type marksCopy struct` with:
    - `func openMarksCopy(path string, out io.Writer) *marksCopy`: reads `path`. An absent file
      is an empty copy. A file that does not decode is said, moved aside to
      `path + ".bad-" + time`, and replaced by an empty copy: the store still holds every mark;
    - `func (c *marksCopy) Apply(ch store.MarkChange)`. A mark that stands is added. A lift is
      removed only when `!ch.Reloaded`. The file is rewritten on each change, to a temporary
      file at mode 0600 and then renamed. A write that fails is said once per run of failures;
    - `func (c *marksCopy) Missing(stored []store.Revocation) []store.Revocation`;
    - `func (c *marksCopy) All() []store.Revocation`.
  - `func (r *runner) putBackMissing(ctx context.Context) ([]store.Revocation, error)`: one
    attempt to put back every mark the copy holds and the store lacks; it returns the ones that
    landed.
  - `func (r *runner) restoreMarks(ctx context.Context) error`: `putBackMissing` retried while
    unavailable, then says how many and which. The takeover's step, and `duties`' on each
    `marksReloaded`.
  - `func (r *runner) reloadHook(ctx context.Context, rescans prometheus.Counter) func() error`:
    the marks feed's `rescanned` on every replica. It counts a rescan; while this replica runs,
    it puts back what the store lost **before** the reload, once, bounded by
    `store.etcd.bulk_timeout`, and returns an error when that fails, so the reload is refused
    (re-review 1 C-2). On a replica that does not run, or runs its takeover still, it keeps in
    force (`Marks.Keep`) every mark it enforces that its copy holds and the store lacks, and
    names them; a read that fails refuses the reload (pre-flight 7e-2 P-3). It replaces port49d's
    7e-1 `marksReloadHook`, as Ruling 12 says.
  - `func offlineRevoke(args []string, stdout, stderr io.Writer) int`, behind `port49-broker
    revoke --offline`.

Ruling 12 as changed (pre-flight I5) and Ruling 13's break-glass (pre-flight I4).

- [ ] **Step 1: The failing tests.** Create `internal/port49d/markscopy_test.go`:

  ```go
  // The copy keeps every mark it was told stands, drops one only on a lift
  // the watch delivered, and keeps one a reload found missing: that may be a
  // restore's loss (Ruling 12; pre-flight I5). It survives a restart, owner
  // only.
  func TestTheCopyKeepsAMarkAReloadFoundMissing(t *testing.T) {
  	path := filepath.Join(t.TempDir(), "marks.json")
  	alice := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0).UTC()}
  	carol := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:carol@example.com", At: time.Unix(11, 0).UTC()}
  	var out bytes.Buffer
  	c := openMarksCopy(path, &out)
  	c.Apply(store.MarkChange{Revocation: alice, Standing: true})
  	c.Apply(store.MarkChange{Revocation: carol, Standing: true})
  	c.Apply(store.MarkChange{Revocation: store.Revocation{Kind: alice.Kind, Key: alice.Key}, Reloaded: true})
  	c.Apply(store.MarkChange{Revocation: store.Revocation{Kind: carol.Kind, Key: carol.Key}}) // a lift
  	again := openMarksCopy(path, &out)
  	if got := again.All(); len(got) != 1 || got[0].Key != alice.Key {
  		t.Fatalf("after a restart the copy holds %+v", got)
  	}
  	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
  		t.Fatalf("%v %v", fi, err)
  	}
  	if miss := again.Missing(nil); len(miss) != 1 || miss[0].Key != alice.Key {
  		t.Fatalf("missing from an empty store: %+v", miss)
  	}
  	if miss := again.Missing([]store.Revocation{alice}); len(miss) != 0 {
  		t.Fatalf("missing from a store holding it: %+v", miss)
  	}
  }

  // A copy that does not decode is moved aside and replaced, never fatal:
  // the store holds every mark.
  func TestACopyThatDoesNotDecodeIsMovedAside(t *testing.T) {
  	dir := t.TempDir()
  	path := filepath.Join(dir, "marks.json")
  	os.WriteFile(path, []byte("{"), 0o600)
  	var out bytes.Buffer
  	if c := openMarksCopy(path, &out); len(c.All()) != 0 || !strings.Contains(out.String(), "does not decode") {
  		t.Fatalf("%q", out.String())
  	}
  	if m, _ := filepath.Glob(path + ".bad-*"); len(m) != 1 {
  		t.Fatalf("not moved aside: %v", m)
  	}
  }
  ```

  In `brokerd_test.go`, on `splitFleet`:

  ```go
  // After a restore loses a revocation, the runner's takeover puts it back
  // from its copy and says so; a mark lifted through the watch is not put
  // back (Ruling 12; pre-flight I5).
  func TestATakeoverPutsBackAMarkTheStoreLost(t *testing.T) {
  	var out syncBuffer
  	e := stderr
  	t.Cleanup(func() { stderr = e })
  	stderr = &out
  	f := splitFleet(t)
  	root := f.srv.Client(t, "root")
  	_, stop := startBroker(t, f.broker, &out, 1)
  	waitFor(t, &out, "runner: recorded bundle ")
  	sock := adminSocketOf(t, f.broker)
  	for _, req := range []admin.Request{
  		{Op: "revoke", Principal: "user:alice@example.com"},
  		{Op: "revoke", Principal: "user:carol@example.com"},
  		{Op: "revoke", Principal: "user:carol@example.com", Lift: true},
  	} {
  		if resp := askAdminAt(t, sock, req); resp.Error != "" {
  			t.Fatalf("%+v: %+v", req, resp)
  		}
  	}
  	waitUntil(t, "the copy to hold alice and not carol", func() bool { return copyHolds(t, f.stateDir(t), "user:alice@example.com", "user:carol@example.com") == "10" })
  	if err := stop(); err != nil {
  		t.Fatal(err)
  	}
  	if _, err := root.Delete(context.Background(), "/port49/v1/rv/principal/user:alice@example.com"); err != nil {
  		t.Fatal(err) // what a restore from before the revocation leaves
  	}
  	startBroker(t, f.broker, &out, 2)
  	waitFor(t, &out, "1 revocation(s) in broker.state_dir/marks.json were missing from the store")
  	waitFor(t, &out, "are put back: principal user:alice@example.com; lift any") // named (re-check R4)
  	resp, err := root.Get(context.Background(), "/port49/v1/rv/principal/", clientv3.WithPrefix())
  	if err != nil || len(resp.Kvs) != 1 || !strings.Contains(string(resp.Kvs[0].Key), "alice") {
  		t.Fatalf("the store's marks after the takeover: %v %v", resp, err)
  	}
  }

  // A lift made on another replica while the runner's marks watch is broken
  // for a moment, within the compaction retention, reaches the runner's copy
  // as a lift when its watch resumes from its last progress notification,
  // and is never put back: no reload runs (final review 7e-1 I-1). Resumed
  // from its last change instead, the watch would be compacted and reload,
  // and the runner's hook would put alice back. The negative control of
  // TestATakeoverPutsBackAMarkTheStoreLost.
  func TestALiftAcrossAShortWatchBreakIsNotPutBack(t *testing.T) {
  	var out syncBuffer
  	e := stderr
  	t.Cleanup(func() { stderr = e })
  	stderr = &out
  	f := splitFleetProgress(t, 200*time.Millisecond)
  	root := f.srv.Client(t, "root")
  	ctx := context.Background()
  	cfgA, proxyA := f.copyBrokerVia(t)
  	startBroker(t, cfgA, &out, 1)
  	waitFor(t, &out, "runner: recorded bundle ") // A runs
  	cfgB := f.copyBroker(t)
  	startBroker(t, cfgB, &out, 2)
  	waitFor(t, &out, "this replica serves the API and takes over if that one stops")
  	const alice = "user:alice@example.com"
  	if resp := askAdminAt(t, adminSocketOf(t, cfgB), admin.Request{Op: "revoke", Principal: alice}); resp.Error != "" {
  		t.Fatalf("revoke on B: %+v", resp)
  	}
  	waitUntil(t, "A's copy to hold alice", func() bool { return copyHolds(t, f.stateDirOf(t, cfgA), alice) == "1" })
  	// Writes elsewhere move the store past alice's mark, A's marks watch is
  	// told a progress at or above them, and the store is compacted there:
  	// above A's last change, at or below its last progress.
  	var top int64
  	for range 3 {
  		resp, err := root.Put(ctx, "/restore-test/bump", "x")
  		if err != nil {
  			t.Fatal(err)
  		}
  		top = resp.Header.Revision
  	}
  	time.Sleep(time.Second) // five progress intervals
  	if _, err := root.Compact(ctx, top); err != nil {
  		t.Fatal(err)
  	}
  	proxyA.Hang(true)
  	if resp := askAdminAt(t, adminSocketOf(t, cfgB), admin.Request{Op: "revoke", Principal: alice, Lift: true}); resp.Error != "" {
  		t.Fatalf("lift on B: %+v", resp)
  	}
  	proxyA.Drop() // A's streams end, and it reconnects
  	waitUntil(t, "A's copy to drop alice", func() bool { return copyHolds(t, f.stateDirOf(t, cfgA), alice) == "0" })
  	if s := out.String(); strings.Contains(s, "the marks feed's revision was compacted") ||
  		strings.Contains(s, "were missing from the store") {
  		t.Fatalf("a short break reloaded or put back:\n%s", s)
  	}
  	if resp, err := root.Get(ctx, "/port49/v1/rv/principal/"+url.PathEscape(alice)); err != nil || len(resp.Kvs) != 0 {
  		t.Fatalf("the lift was put back: %v %v", resp, err)
  	}
  }

  // With every port49-broker stopped, the offline revocation reaches a live
  // session on port49d at its next command, and deletes a token minted
  // before (Ruling 13; pre-flight I4).
  func TestAnOfflineRevokeDeniesWithEveryBrokerStopped(t *testing.T) {
  	var out, log syncBuffer
  	e, o := stderr, stdout
  	t.Cleanup(func() { stderr, stdout = e, o })
  	stderr, stdout = &out, &log
  	f := splitFleet(t)
  	tacacs := startSplitDaemon(t, f.daemon, &out, 1)
  	api, stop := startBroker(t, f.broker, &out, 1)
  	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
  	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
  	spare := mintOn(t, api, f.pki, "leaf1")
  	if err := stop(); err != nil {
  		t.Fatal(err)
  	}
  	if !dev.permits("alice", "configure") {
  		t.Fatal("control: the session runs on with every broker stopped")
  	}
  	var rout, rerr bytes.Buffer
  	if code := offlineRevoke([]string{"--offline", "--config", f.broker, "--principal", "user:alice@example.com"},
  		&rout, &rerr); code != 0 {
  		t.Fatalf("exit %d: %s", code, rerr.String())
  	}
  	waitUntil(t, "the device to deny alice configure", func() bool { return !dev.permits("alice", "configure") })
  	if r := lastCommand(t, &log); r["reason"] != "credential_revoked" {
  		t.Fatalf("the denial: %v", r)
  	}
  	if st := dev.login("alice", spare); st == wire.AuthenStatusPass {
  		t.Fatal("a token minted before the offline revocation still logged in")
  	}
  }

  // revoke without --offline is port49 revoke's, on the admin socket: said,
  // exit 2.
  func TestARevokeWithoutOfflineNamesTheSocket(t *testing.T) {
  	var o, e bytes.Buffer
  	if code := offlineRevoke([]string{"--principal", "user:alice@example.com"}, &o, &e); code != 2 ||
  		!strings.Contains(e.String(), "port49 revoke --socket") {
  		t.Fatalf("exit %d: %s", code, e.String())
  	}
  }
  ```

  `TestARevokeWithoutOfflineNamesTheSocket` goes in `offline_test.go`, beside its code; the three
  fleet tests go in `brokerd_test.go`.

  Create `internal/port49d/runner_test.go`, the C-2 case for the runner. A fleet test cannot fail
  one store call of the broker's while the reload's read succeeds (re-review 2 §3), so the
  put-back that fails once is a unit test of the hook under `store.FollowMarks`:

  ```go
  // The runner's hook before a marks reload puts back what its copy holds
  // and the store lost; a put-back that fails returns an error, so
  // FollowMarks reloads nothing and the lost mark is never lifted, and the
  // next compacted round puts it back, then reloads (re-review 1 C-2). A
  // replica that does not run puts nothing back and keeps alice, whom its
  // copy holds; its reload lifts bob, whom its copy lacks (pre-flight 7e-2
  // P-3). Each call counts a rescan.
  func TestTheRunnersReloadHookRefusesTheReloadOnAFailedPutBack(t *testing.T) {
  	alice := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0).UTC()}
  	var out syncBuffer
  	e := stderr
  	t.Cleanup(func() { stderr = e })
  	stderr = &out
  	rescans := prometheus.NewCounter(prometheus.CounterOpts{Name: "rescans"})
  	bob := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:bob@example.com", At: time.Unix(11, 0).UTC()}
  	// newRunner's copy holds alice; its marks hold alice and bob, whom the
  	// copy lacks.
  	newRunner := func(st store.Store, running bool) *runner {
  		c := openMarksCopy(filepath.Join(t.TempDir(), "marks.json"), &out)
  		c.Apply(store.MarkChange{Revocation: alice, Standing: true})
  		marks := store.NewMarks()
  		marks.Set(alice, true)
  		marks.Set(bob, true)
  		r := &runner{cfg: config.Config{Store: config.StoreConfig{Etcd: &config.EtcdConfig{BulkTimeout: time.Second}}},
  			st: st, copy: c, marks: marks, marksReloaded: make(chan struct{}, 1)}
  		r.on.Store(running)
  		return r
  	}
  	// follow runs FollowMarks over st's marks into r.marks, compacted
  	// rounds times, and records each key a reload lifted.
  	follow := func(r *runner, st store.Store, rounds int32) *sync.Map {
  		var lifted sync.Map
  		feed := &storeFeed{st: st}
  		feed.compacted.Store(rounds)
  		ctx, cancel := context.WithCancel(context.Background())
  		done := make(chan struct{})
  		go func() {
  			defer close(done)
  			store.FollowMarks(ctx, feed, r.marks, 1, func(c store.MarkChange) {
  				if !c.Standing {
  					lifted.Store(c.Key, true)
  				}
  			}, func(bool) {}, r.reloadHook(ctx, rescans), func(string, ...any) {})
  		}()
  		t.Cleanup(func() { cancel(); <-done })
  		return &lifted
  	}

  	idle := memory.New(time.Now)
  	rIdle := newRunner(idle, false)
  	liftedIdle := follow(rIdle, idle, 1)
  	waitUntil(t, "the idle replica's reload lifts bob", func() bool { _, ok := liftedIdle.Load(bob.Key); return ok })
  	if _, ok := liftedIdle.Load(alice.Key); ok || !rIdle.marks.Holds(alice.Kind, alice.Key) {
  		t.Fatal("an idle replica's reload lifted a mark its copy holds and the store lost")
  	}

  	st := &putsFailOnce{Store: memory.New(time.Now)}
  	r := newRunner(st, true)
  	lifted := follow(r, st, 2)
  	waitUntil(t, "the runner puts alice back", func() bool {
  		_, err := st.GetRevocation(context.Background(), alice.Kind, alice.Key)
  		return err == nil
  	})
  	waitFor(t, &out, "port49-broker: runner: 1 revocation(s) in broker.state_dir/marks.json were missing from the "+
  		"store")
  	if _, ok := lifted.Load(alice.Key); ok || !r.marks.Holds(alice.Kind, alice.Key) {
  		t.Fatal("a reload after a failed put-back lifted the mark the store lost")
  	}
  	waitUntil(t, "three rescans", func() bool { return testutil.ToFloat64(rescans) == 3 })
  }

  // putsFailOnce is a store whose first PutRevocation fails unavailable, as
  // the broker's guarded store does with its Token circuit open through a
  // restore (re-review 1 C-2).
  type putsFailOnce struct {
  	store.Store
  	failed atomic.Bool
  }

  func (p *putsFailOnce) PutRevocation(ctx context.Context, r store.Revocation) error {
  	if p.failed.CompareAndSwap(false, true) {
  		return store.ErrUnavailable
  	}
  	return p.Store.PutRevocation(ctx, r)
  }

  // storeFeed is a store.MarkFeed over st's marks, at revision 1, whose
  // first compacted watches return store.ErrCompacted; later ones wait for
  // ctx.
  type storeFeed struct {
  	st        store.Store
  	compacted atomic.Int32
  }

  func (f *storeFeed) Revocations(ctx context.Context) (uint64, []store.Revocation, error) {
  	rs, err := f.st.ListRevocations(ctx)
  	return 1, rs, err
  }

  func (f *storeFeed) WatchRevocations(ctx context.Context, _ uint64, _ func(store.Revocation, bool, uint64),
  	_ func(uint64)) error {
  	if f.compacted.Add(-1) >= 0 {
  		return store.ErrCompacted
  	}
  	<-ctx.Done()
  	return ctx.Err()
  }
  ```

  The hook's `return nil` on a failed put-back makes the first round reload and lift alice, which
  `lifted` catches; a hook that put back after the reload would too. An idle replica's hook that
  only counted (0cc5573's, and 670bb7a's) lifts alice there, which the control catches.

  The helpers:
  - `f.stateDirOf(t, cfg)` reads a broker config's `broker.state_dir`, and `f.stateDir(t)` is
    `f.stateDirOf(t, f.broker)`. `f.copyBroker(t)` (Task 15) gives each copy a
    `broker.state_dir` of its own. Task 15c uses them;
  - `copyHolds(t, dir, keys...)` reads `marks.json` and returns a `1` or `0` per key, in order;
  - `splitFleetProgress(t, every)` is `splitFleet` on a member started with
    `etcdtest.Options{TLS: true, ProgressNotify: every}` (7e-1). Factor the member's start out of
    Task 14's `etcdSplitServerWith` into `etcdSplitServerOpts(t, policyBody, others, o
    etcdtest.Options)`, which `etcdSplitServerWith` calls with `etcdtest.Options{TLS: true}`;
  - `adminSocketOf` and `askAdminAt` were Task 16's in 0cc5573. Write them here, and Task 16
    uses them.

  `runner_test.go` imports `context`, `path/filepath`, `sync`, `sync/atomic`, `testing`, `time`,
  `prometheus`, `prometheus/testutil`, `config`, `store` and `store/memory`.

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/port49d/ -run 'Copy|PutsBackAMark|OfflineRevoke|WithoutOffline|ShortWatchBreak|RunnersReloadHook' -count=1`
  Expected: FAIL to compile (`openMarksCopy`, `offlineRevoke`, `reloadHook`, `splitFleetProgress`
  undefined).

- [ ] **Step 3: The copy.** Create `markscopy.go` as its interface says. The file is `{"marks":
  [{"kind": …, "key": …, "at": …}]}`, written sorted by kind and key, through a temporary file in
  the same directory at mode 0600, then `os.Rename`. Its comment states which way it errs: a
  mark the store lost is put back, and so is a mark whose lift this copy missed. Both deny
  more, and the takeover's line says how to lift.

- [ ] **Step 4: Wired.** In `brokerd.go`:
  - open the copy at `filepath.Join(cfg.Broker.StateDir, "marks.json")` before the marks load;
  - pass `on: func(c store.MarkChange) { copy.Apply(c); brk.MarkChanged(c) }` to both
    `LoadMarks` and `FollowMarks`.
    - At the start's `LoadMarks`, before the listener exists, `brk.MarkChanged` does nothing
      (`b.Conns` is nil, as Task 9 built it), and the listener is then built from
      `marks.All()`, so nothing is lost.
    - That is safe only because the marks feed starts after `brk.Conns = bl` (Task 15 Step 7,
      item 8). A feed started before it would tell a change no listener hears and that
      `marks.All()` was read too early to hold. Keep that order, and say so in a comment at the
      `FollowMarks` call;
  - give the runner the copy (`r.copy`), the replica's `store.Marks` (`r.marks = marks`), and
    a `marksReloaded chan struct{}` buffered one;
  - replace Task 15's counting `rescanned` with `rn.reloadHook(ctx,
    m.StoreFeedRescans.WithLabelValues("marks"))`. The hook runs on the marks feed's goroutine,
    before the reload, and only the runner puts back; every other replica keeps what its copy
    holds and the store lacks (pre-flight 7e-2 P-3).

  In `runner.go`:

  ```go
  // putBackMissing puts back, once, every mark this replica's copy holds
  // that the store lacks, and returns the ones that landed (plan 7e, Ruling
  // 12; pre-flight I5): an etcd restore's lost revocations, or a lift this
  // copy missed. Both deny more, and the line says how to lift.
  func (r *runner) putBackMissing(ctx context.Context) ([]store.Revocation, error) {
  	stored, err := r.st.ListRevocations(ctx)
  	if err != nil {
  		return nil, err
  	}
  	missing := r.copy.Missing(stored)
  	for i, m := range missing {
  		if err := r.st.PutRevocation(ctx, m); err != nil {
  			return missing[:i], err
  		}
  	}
  	return missing, nil
  }

  // restoreMarks is putBackMissing retried while the store is unavailable
  // and ctx lives, said either way: the takeover's step, before it applies
  // every mark to the kept contexts, and duties' on each marksReloaded. The
  // marks feed brings what it put back to every process.
  func (r *runner) restoreMarks(ctx context.Context) error {
  	var put []store.Revocation
  	if err := retryCtx(ctx, func() error {
  		p, err := r.putBackMissing(ctx)
  		put = append(put, p...)
  		return err
  	}); err != nil {
  		return err
  	}
  	if len(put) == 0 {
  		fmt.Fprintln(stderr, "port49-broker: runner: every revocation in broker.state_dir/marks.json is in the store")
  		return nil
  	}
  	sayPutBack(put)
  	return nil
  }

  // reloadHook is the marks feed's rescanned on every replica (store.
  // FollowMarks; plan 7e, Ruling 12). It counts a rescan. While this replica
  // runs, it puts back every mark its copy holds that the store lacks, once
  // and bounded, before the reload reads the store: a reload first would
  // lift each lost mark from this replica's marks and listener. A put-back
  // that fails returns an error, so the reload is refused and the marks
  // feed is down until a put-back lands, tried again every second
  // (re-review 1 C-2). What it put back is applied to the kept contexts by
  // duties (marksReloaded). A replica that does not run, or runs its
  // takeover still, puts nothing back: it keeps in force (store.Marks.Keep)
  // every mark it enforces that its copy holds and the store lacks, so its
  // listener refuses that principal until the runner's put-back arrives or
  // a lift this feed delivers; a read that fails refuses the reload.
  func (r *runner) reloadHook(ctx context.Context, rescans prometheus.Counter) func() error {
  	return func() error {
  		rescans.Inc()
  		pctx, cancel := context.WithTimeout(ctx, r.cfg.Store.Etcd.BulkTimeout)
  		defer cancel()
  		if !r.running() {
  			stored, err := r.st.ListRevocations(pctx)
  			if err != nil {
  				return fmt.Errorf("runner: reading the marks before the marks reload: %w; the marks are not "+
  					"reloaded until they are read", err)
  			}
  			var kept []store.Revocation
  			for _, m := range r.copy.Missing(stored) {
  				if r.marks.Holds(m.Kind, m.Key) {
  					r.marks.Keep(m)
  					kept = append(kept, m)
  				}
  			}
  			if len(kept) > 0 {
  				fmt.Fprintf(stderr, "port49-broker: store: %d revocation(s) in broker.state_dir/marks.json are "+
  					"missing from the store as the marks feed reloads and stay in force on this replica until the "+
  					"runner puts them back or a lift this feed delivers: %s\n", len(kept), namedMarks(kept))
  			}
  			return nil
  		}
  		put, err := r.putBackMissing(pctx)
  		if len(put) > 0 {
  			sayPutBack(put)
  			select {
  			case r.marksReloaded <- struct{}{}:
  			default:
  			}
  		}
  		if err != nil {
  			return fmt.Errorf("runner: putting broker.state_dir/marks.json's marks back into the store before the "+
  				"marks reload: %w; the marks are not reloaded until they are back", err)
  		}
  		return nil
  	}
  }

  // sayPutBack is the put-back line, naming each mark (re-check R4).
  func sayPutBack(put []store.Revocation) {
  	fmt.Fprintf(stderr, "port49-broker: runner: %d revocation(s) in broker.state_dir/marks.json were missing from the "+
  		"store (an etcd restore, or a lift made while this replica's watch was compacted away) and are put back: %s; "+
  		"lift any that were lifted on purpose with port49 revoke --lift\n", len(put), namedMarks(put))
  }
  ```

  `namedMarks` is Task 14's (`daemon.go`). Add `"github.com/prometheus/client_golang/prometheus"`
  to `runner.go`'s imports if it lacks it.

  - **The takeover** calls `restoreMarks` after the re-index and before `ApplyMarksAtStart`,
    and lists the store's marks after it, so the marks it put back are applied with the rest.
  - **`duties`** runs one more goroutine: on each receive from `r.marksReloaded`, it calls
    `restoreMarks`, then lists the store's marks and applies every one through
    `ApplyMarksAtStart`, saying `port49-broker: runner: N standing revocation(s) applied to the
    live contexts after a put-back (M context(s) marked revoked)`. After the hook's put-back,
    `restoreMarks` finds nothing missing and says so; after Task 15c's running purge it is the
    put-back itself.
  - **With I-1, the hook's put-back runs only after a real gap:** a compaction past the
    watch's last progress, or a restore. A reconnect within the retention resumes without a
    reload, so a lift made on another replica during a short break arrives as a lift and is
    never put back (`TestALiftAcrossAShortWatchBreakIsNotPutBack`).

- [ ] **Step 5: The offline revocation.** Create `offline.go`:
  - `offlineRevoke(args, stdout, stderr)` parses `--offline` (required), `--config` (default
    `/etc/port49/port49-broker.yaml`), `--principal`, `--cert-issuer`, `--cert-serial` and
    `--lift`. Without `--offline` it says `port49-broker revoke: without --offline, revoke on
    the running broker's admin socket: port49 revoke --socket <its admin_socket>` and exits 2.
  - It loads the config with `config.LoadBroker`, and opens the broker's identity with
    `openIdentity` (Task 14), running the broker's `CheckIdentity`. It takes no hold and binds
    nothing.
  - It builds the sealing layer as `crypt.Wrap(guard.WrapRev(b, gc("broker")), keys, …,
    crypt.WithLedger(crypt.NewLedger()))`, with no fence: nothing follows here, and the tool
    only writes marks and revokes.
  - It builds a `*broker.Broker` with `Store`, `Sessions` (`session.New(st, time.Now, …)` as
    `buildBrokerAnchor` builds it), `Now`, `Log` (a decision-log sink on `stdout`, as
    port49-broker's), and `Metrics` (a private registry). No listener, no minter.
  - It calls `brk.Revoke` (or `brk.Lift`) with `RevokeRequest{Principal, Issuer, Serial, Origin:
    "offline"}`, and prints the report to `stderr` as `adminRevoke` words it, prefixed
    `port49-broker: revoke (offline, no API): `.
  - It exits 0 on a full report, and 1 on an error or a report with `Err` set, as `port49
    revoke` does.

  `BrokerMain` routes `args[0] == "revoke"` to `offlineRevoke(args[1:], stdout, stderr)`. Any
  other subcommand stays exit 2.

- [ ] **Step 6: Run everything.**

  Run: `make build && make test && make vet && make test-race`
  Expected: PASS.

- [ ] **Step 7: Commit.**

  ```bash
  gofmt -w internal/port49d
  git add internal/port49d/markscopy.go internal/port49d/markscopy_test.go internal/port49d/offline.go \
    internal/port49d/offline_test.go internal/port49d/brokerd.go internal/port49d/runner.go \
    internal/port49d/runner_test.go internal/port49d/brokerd_test.go
  git commit -m "feat(port49-broker): a copy of the marks per replica, and revoking with every broker down

  With the revocations file retired, an etcd restore silently lifted every
  revocation made since the snapshot (pre-flight I5). Each broker keeps
  the marks it followed in broker.state_dir/marks.json, dropping one only
  on a lift the watch delivered, and the runner puts back any the store
  lacks, at a takeover and before a marks reload, naming each (re-check
  R4). A put-back that fails refuses the reload, so a lost mark is never
  lifted (final review 7e-1 C-2). With every broker down there was no
  revocation path (pre-flight I4): port49-broker revoke --offline runs
  the whole revocation through the store on the broker's identity, with
  no API and no hold (plan 7e Rulings 12, 13).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 15c: The restore witness: a runner that finds the store older than a replica saw it purges

**Files:**
- Create: `internal/port49d/witness.go`, `internal/port49d/witness_test.go`
- Modify: `internal/store/etcd/etcdtest/etcdtest.go` (`Server` keeps its member's spec;
  `Server.Backup`, `Server.Restore`, `copyDir`), `etcdtest_test.go`
- Modify: `internal/store/etcd/meta.go` (`WitnessRead`, `Witness`, `PutWitness`,
  `FollowWitness`), `meta_test.go`
- Modify: `internal/port49d/runner.go` (`witnessEvery`, `keepWitness`, `witnessPass`,
  `purgeRestored`; the takeover's check; `duties`), `internal/port49d/brokerd.go` (the record
  opened, kept and followed), `internal/port49d/markscopy.go` (`writeOwnerOnly`, if Task 15b
  wrote its write inline), `internal/port49d/brokerd_test.go`

**Interfaces:**
- Consumes: Task 15's runner, its takeover's purge, `duties` and `retryCtx`; Task 15b's
  `marksReloaded`, `restoreMarks` and the copy's temporary-file write; Task 13's
  `BrokerConfig.StateDir`.
- Produces:
  - `func (s *etcdtest.Server) Backup(t testing.TB) string` and
    `func (s *etcdtest.Server) Restore(t testing.TB, from string)`.
  - `type etcd.WitnessRead struct { ModRevision, Header uint64 }`;
    `func (s *etcd.Store) Witness(ctx context.Context) (WitnessRead, error)`;
    `func (s *etcd.Store) PutWitness(ctx context.Context, who string, over uint64) (uint64, error)`;
    `func (s *etcd.Store) FollowWitness(ctx context.Context, saw func(uint64))`; all at
    `meta/witness`.
  - `type witnessRecord struct` with `func openWitness(path, prefix string, out io.Writer)
    *witnessRecord`, `Saw(rev uint64)`, `Recorded() (uint64, bool)`, `Reset(rev uint64)` and
    `keep(ctx context.Context)`.
  - `func restored(read etcdstore.WitnessRead, recorded uint64, haveRecord bool) (bool, string)`;
    `func readWitness(ctx context.Context, w *witnessRecord, read func(context.Context)
    (etcdstore.WitnessRead, error)) (etcdstore.WitnessRead, bool, string, error)`, which takes
    the record before the read.
  - `const witnessEvery = time.Second`; `func (r *runner) keepWitness(ctx context.Context)`;
    `func (r *runner) witnessPass(ctx context.Context) error`;
    `func (r *runner) purgeRestored(ctx context.Context, why string, read etcdstore.WitnessRead) error`;
    the field `runner.witness *witnessRecord`.

Ruling 18, pre-flight re-check R6, which replaced the owner's first backstop (a header below
`Seen()`): that one missed both cases the runbook makes, every broker stopped and
`--bump-revision`. The runbook's delete of `meta/judged` (Ruling 7) stays; this task makes
forgetting it fail closed.
- **The record lives outside etcd.** Nothing inside one snapshot shows that it is a snapshot.
  `broker.state_dir` survives the restore, and every replica keeps one.
- **It compares `ModRevision`, never the header.** A restored key keeps its own, with or without
  `--bump-revision`, while the bump moves the header up.
- **What it leaves** (Ruling 18): a replica with no `witness.json` says so and goes by
  `meta/judged` alone; a snapshot taken within about one keeper interval (1s) after the last
  witness a surviving replica recorded is not caught. The runbook's delete covers both.
- **The two fleet tests split the cases.** The takeover test pads the restored store's revisions
  past the record before anything starts, which is what `--bump-revision` does to the witness;
  the other-replica test restores with no pad.

- [ ] **Step 1: The failing tests.** Create `internal/port49d/witness_test.go`:

  ```go
  // The decision reads the witness's ModRevision alone: a restored key
  // keeps it, with or without --bump-revision, while the read's header
  // rises under the bump (Ruling 18; re-check R6).
  func TestARestoredWitnessIsCaught(t *testing.T) {
  	for name, c := range map[string]struct {
  		read     etcdstore.WitnessRead
  		recorded uint64
  		have     bool
  		want     bool
  		says     string
  	}{
  		"below, no bump":              {etcdstore.WitnessRead{ModRevision: 812, Header: 900}, 1907, true, true, "is at revision 812, below the 1907 this replica saw"},
  		"below, the header far above": {etcdstore.WitnessRead{ModRevision: 812, Header: 1_000_812}, 1907, true, true, "is at revision 812, below the 1907 this replica saw"},
  		"equal":                       {etcdstore.WitnessRead{ModRevision: 1907, Header: 1950}, 1907, true, false, ""},
  		"above, another runner's":     {etcdstore.WitnessRead{ModRevision: 2001, Header: 2001}, 1907, true, false, ""},
  		"absent, with a record":       {etcdstore.WitnessRead{Header: 1_000_000}, 1907, true, true, "is absent, below the 1907 this replica saw"},
  		"no record":                   {etcdstore.WitnessRead{ModRevision: 812, Header: 900}, 0, false, false, "no witness record in broker.state_dir"},
  	} {
  		got, why := restored(c.read, c.recorded, c.have)
  		if got != c.want || !strings.Contains(why, c.says) || (c.says == "" && why != "") {
  			t.Errorf("%s: %v %q", name, got, why)
  		}
  	}
  }

  // The record keeps the highest it is told, is lowered only by Reset,
  // survives a restart owner only, and is no record for another prefix.
  func TestTheWitnessRecordKeepsTheHighest(t *testing.T) {
  	path := filepath.Join(t.TempDir(), "witness.json")
  	var out bytes.Buffer
  	w := openWitness(path, "/port49/", &out)
  	if _, have := w.Recorded(); have {
  		t.Fatal("a record with no file")
  	}
  	w.Saw(1907)
  	w.Saw(812) // a restore's, followed
  	if got, have := w.Recorded(); got != 1907 || !have {
  		t.Fatalf("%d %v", got, have)
  	}
  	ctx, cancel := context.WithCancel(context.Background())
  	done := make(chan struct{})
  	go func() { defer close(done); w.keep(ctx) }()
  	cancel()
  	<-done // keep saves as it stops
  	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
  		t.Fatalf("%v %v", fi, err)
  	}
  	if got, have := openWitness(path, "/port49/", &out).Recorded(); got != 1907 || !have {
  		t.Fatalf("after a restart: %d %v", got, have)
  	}
  	if _, have := openWitness(path, "/other/", &out).Recorded(); have || !strings.Contains(out.String(), "another prefix's") {
  		t.Fatalf("a record for another prefix: %v %q", have, out.String())
  	}
  	w.Reset(812)
  	if got, _ := w.Recorded(); got != 812 {
  		t.Fatalf("after Reset: %d", got)
  	}
  }

  // A witness another runner writes while this one reads, followed into the
  // record before the read answers, is no restore: the record is taken
  // before the read (final check, Minor 1).
  func TestAWitnessWrittenDuringTheReadIsNoRestore(t *testing.T) {
  	w := openWitness(filepath.Join(t.TempDir(), "witness.json"), "/port49/", io.Discard)
  	w.Saw(1907)
  	_, gone, why, err := readWitness(context.Background(), w, func(context.Context) (etcdstore.WitnessRead, error) {
  		w.Saw(2001) // another runner's witness, followed while the read was in flight
  		return etcdstore.WitnessRead{ModRevision: 1907, Header: 1950}, nil
  	})
  	if err != nil || gone || why != "" {
  		t.Fatalf("a witness written during the read: %v %q %v", gone, why, err)
  	}
  }

  // A pass rewrites the witness only when the store has moved past it: two
  // passes with nothing written between them leave it where it was, so the
  // rewrite never feeds itself. A write elsewhere brings one more, and the
  // replica records the witness it wrote (Ruling 18; re-check R6). On a
  // member of the test's own: the shared one moves under every test.
  func TestAQuietStoreWritesNoWitness(t *testing.T) {
  	ctx := context.Background()
  	srv := etcdtest.Start(t, etcdtest.Options{})
  	s, err := etcdstore.Open(etcdstore.Config{Endpoints: []string{srv.Endpoint}, Prefix: "/port49/", Now: time.Now})
  	if err != nil {
  		t.Fatal(err)
  	}
  	t.Cleanup(func() { s.Close() })
  	r := &runner{raw: s, who: "port49-broker on test",
  		witness: openWitness(filepath.Join(t.TempDir(), "witness.json"), "/port49/", io.Discard)}
  	at := func() uint64 {
  		t.Helper()
  		w, err := s.Witness(ctx)
  		if err != nil {
  			t.Fatal(err)
  		}
  		return w.ModRevision
  	}
  	pass := func() {
  		t.Helper()
  		if err := r.witnessPass(ctx); err != nil {
  			t.Fatal(err)
  		}
  	}
  	pass() // none yet: the store has moved past an absent witness
  	first := at()
  	if first == 0 {
  		t.Fatal("no witness after a pass on a store with none")
  	}
  	pass()
  	pass()
  	if got := at(); got != first {
  		t.Fatalf("a quiet store's witness moved from %d to %d", first, got)
  	}
  	if rec, _ := r.witness.Recorded(); rec != first {
  		t.Fatalf("the replica recorded %d, not its own witness at %d", rec, first)
  	}
  	if _, err := srv.Client(t, "root").Put(ctx, "/port49/v1/elsewhere", "x"); err != nil {
  		t.Fatal(err)
  	}
  	pass()
  	if got := at(); got <= first {
  		t.Fatalf("a write elsewhere brought no witness: %d after %d", got, first)
  	}
  }
  ```

  In `internal/store/etcd/meta_test.go`:

  ```go
  // A witness lands only over the revision it was given, so two runners
  // for a moment cannot write one over the other, and a read says both
  // its revision and the store's (Ruling 18).
  func TestAWitnessLandsOnlyOverTheOneRead(t *testing.T) {
  	ctx := context.Background()
  	s := onShared(t, time.Now)
  	if w, err := s.Witness(ctx); err != nil || w.ModRevision != 0 || w.Header == 0 {
  		t.Fatalf("no witness yet: %+v %v", w, err)
  	}
  	first, err := s.PutWitness(ctx, "runner-a", 0)
  	if err != nil || first == 0 {
  		t.Fatalf("the first witness: %d %v", first, err)
  	}
  	if got, err := s.PutWitness(ctx, "runner-b", 0); err != nil || got != 0 {
  		t.Fatalf("a witness over an absent one that is there now: %d %v", got, err)
  	}
  	if w, err := s.Witness(ctx); err != nil || w.ModRevision != first || w.Header < first {
  		t.Fatalf("the witness read back: %+v %v", w, err)
  	}
  	if got, err := s.PutWitness(ctx, "runner-a", first); err != nil || got <= first {
  		t.Fatalf("a witness over the one read: %d %v", got, err)
  	}
  }
  ```

  In `internal/store/etcd/etcdtest/etcdtest_test.go`:

  ```go
  // Restore puts a Backup's data back under clients still connected: a key
  // written since is gone, and the revision is the backup's again (Ruling
  // 18's fleet tests stand on it).
  func TestARestoreTakesTheStoreBack(t *testing.T) {
  	ctx := context.Background()
  	srv := Start(t, Options{})
  	cli := srv.Client(t, "root")
  	if _, err := cli.Put(ctx, "before", "x"); err != nil {
  		t.Fatal(err)
  	}
  	backup := srv.Backup(t)
  	at, err := cli.Get(ctx, "before")
  	if err != nil {
  		t.Fatal(err)
  	}
  	for range 5 {
  		if _, err := cli.Put(ctx, "after", "y"); err != nil {
  			t.Fatal(err)
  		}
  	}
  	srv.Restore(t, backup)
  	resp, err := cli.Get(ctx, "after")
  	if err != nil || len(resp.Kvs) != 0 || resp.Header.Revision != at.Header.Revision {
  		t.Fatalf("after a restore: %v at revision %d, the backup's %d: %v", resp.Kvs, resp.Header.Revision,
  			at.Header.Revision, err)
  	}
  }
  ```

  In `internal/port49d/brokerd_test.go`, on `splitFleet`:

  ```go
  // An etcd restore with every process stopped, as the runbook says, but its
  // delete of meta/judged forgotten: the takeover finds meta/witness below
  // what this replica recorded and purges, so a token redeemed after the
  // snapshot stays spent. The revisions are padded past the record before
  // anything starts, as --bump-revision moves them (Ruling 18; re-check R6).
  func TestATakeoverAfterARestorePurgesWithoutTheRunbook(t *testing.T) {
  	var out, log syncBuffer
  	e, o := stderr, stdout
  	t.Cleanup(func() { stderr, stdout = e, o })
  	stderr, stdout = &out, &log
  	f := splitFleet(t)
  	root := f.srv.Client(t, "root")
  	tacacs, stopD := startSplitDaemonStop(t, f.daemon, &out, 1)
  	api, stop := startBroker(t, f.broker, &out, 1)
  	waitFor(t, &out, "runner: recorded bundle ")
  	spent := mintOn(t, api, f.pki, "leaf1")
  	snapshot := f.srv.Backup(t) // the token is unspent in it, and meta/judged names the bundle
  	w0 := witnessAt(t, root)   // the snapshot's witness is at or below it
  	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
  	// Backup restarted the member: port49d may be dark until it re-enters,
  	// and a dark port49d answers without redeeming, so try again.
  	if st := loginWithin(t, dev, "alice", spent, 10*time.Second); st != wire.AuthenStatusPass {
  		t.Fatalf("control: the token's first login: %d", st)
  	}
  	waitUntil(t, "the redemption's witness, recorded", func() bool { return witnessIn(t, f.stateDir(t)) > w0 }) // the redemption's witness, recorded
  	if err := stop(); err != nil {
  		t.Fatal(err)
  	}
  	if err := stopD(); err != nil {
  		t.Fatal(err)
  	}
  	recorded := witnessIn(t, f.stateDir(t)) // saved as the broker stopped
  	f.srv.Restore(t, snapshot)              // meta/judged left as the snapshot's
  	padPast(t, root, recorded)              // as --bump-revision moves revisions up
  	dev.addr = startSplitDaemon(t, f.daemon, &out, 2)
  	api, _ = startBroker(t, f.broker, &out, 2)
  	waitFor(t, &out, fmt.Sprintf("below the %d this replica saw: the store was restored from a snapshot; every "+
  		"unspent token is purged", recorded))
  	if st := dev.login("alice", spent); st == wire.AuthenStatusPass {
  		t.Fatal("a token redeemed after the snapshot logged in again after the restore")
  	}
  	if st := dev.login("alice", mintOn(t, api, f.pki, "leaf1")); st != wire.AuthenStatusPass {
  		t.Fatalf("control: a token minted after the takeover: %d", st)
  	}
  }

  // A replica that never ran, and only followed the witness, catches the
  // restore at its takeover as the runner would have: the record is every
  // replica's, not the runner's alone (Ruling 18; re-check R6).
  func TestAWitnessRecordFromAnotherReplicaCatchesTheRestore(t *testing.T) {
  	var out syncBuffer
  	e := stderr
  	t.Cleanup(func() { stderr = e })
  	stderr = &out
  	f := splitFleet(t)
  	root := f.srv.Client(t, "root")
  	apiA, stopA := startBroker(t, f.broker, &out, 1)
  	waitFor(t, &out, "runner: recorded bundle ")
  	cfgB := f.copyBroker(t) // a broker.state_dir of its own
  	_, stopB := startBroker(t, cfgB, &out, 2)
  	waitFor(t, &out, "this replica serves the API and takes over if that one stops")
  	snapshot := f.srv.Backup(t)
  	w0 := witnessAt(t, root)
  	mintWithin(t, apiA, f.pki, "leaf1", 10*time.Second) // after the member's restart; brings a witness
  	waitUntil(t, "B's copy of the witness to rise", func() bool { return witnessIn(t, f.stateDirOf(t, cfgB)) > w0 })
  	// The follower path, proved: A held throughout, so B's record came only
  	// from following. Had A's hold lapsed across Backup's restart, B would
  	// have run and recorded its own writes (final check, Minor 3).
  	if n := strings.Count(out.String(), "runner: took keyspace /port49/"); n != 1 {
  		t.Fatalf("the hold changed hands across the backup: %d takes; the follower path is not what was tested", n)
  	}
  	if err := stopB(); err != nil { // B first, so it never takes the hold
  		t.Fatal(err)
  	}
  	if err := stopA(); err != nil {
  		t.Fatal(err)
  	}
  	recorded := witnessIn(t, f.stateDirOf(t, cfgB))
  	f.srv.Restore(t, snapshot)
  	startBroker(t, cfgB, &out, 3)
  	waitFor(t, &out, fmt.Sprintf("below the %d this replica saw: the store was restored from a snapshot", recorded))
  }
  ```

  The helpers, beside `splitFleet`'s:
  - `startSplitDaemonStop(t, cfg, out, n) (addr string, stop func() error)` is
    `startSplitDaemon` returning its stop, as `startBroker` does; `startSplitDaemon` calls it and
    drops the stop;
  - `f.copyBroker(t)` is Task 15's (a `broker.state_dir` of its own); `f.stateDirOf(t, cfg)` and
    `f.stateDir(t)` are Task 15b's;
  - `witnessAt(t, root) uint64` is `/port49/v1/meta/witness`'s `ModRevision` read as etcd's root,
    0 when absent, tried again for 10s while the member restarts under the client;
  - `witnessIn(t, dir) uint64` is `dir/witness.json`'s `mod_revision`, 0 when there is none;
  - `padPast(t, root, rev)` puts `/pad/<n>` as etcd's root until a put's header revision is past
    `rev`, tried again for 10s while the member restarts;
  - `loginWithin(t, dev, user, token, d) uint8` tries `dev.login` until it passes or `d` runs out,
    and returns the last status: a port49d still dark after the member's restart answers without
    redeeming the token;
  - `mintWithin(t, api, pki, device, d) string` is `mintOn` tried again while the API answers 503
    `store_unavailable`, until `d` runs out.

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/store/etcd/... ./internal/port49d/ -run 'RestoreTakesTheStoreBack|WitnessLandsOnly|RestoredWitnessIsCaught|WitnessRecord|WrittenDuringTheRead|QuietStoreWritesNoWitness|AfterARestorePurges' -count=1`
  Expected: FAIL to compile (`Backup`, `Restore`, `WitnessRead`, `PutWitness`, `openWitness`,
  `restored`, `witnessPass` undefined). Each can fail once it compiles. Run these mutations, and
  put each back:
  - `restored` compares `read.Header` with the record: `TestARestoredWitnessIsCaught`'s "the
    header far above" row fails, and so does the takeover test, whose revisions are padded;
  - the takeover's witness check removed, going by `meta/judged` alone: the takeover test's spent
    token logs in again (re-check R6's mutation);
  - the record fed only by the runner's own writes (`FollowWitness` not wired):
    `TestAWitnessRecordFromAnotherReplicaCatchesTheRestore`'s replica has no record, says so, and
    its wait fails;
  - `witnessPass` rewriting the witness on every pass: `TestAQuietStoreWritesNoWitness` fails;
  - `Saw` taking any revision, lower too: `TestTheWitnessRecordKeepsTheHighest` fails;
  - `readWitness` taking the record after the read: `TestAWitnessWrittenDuringTheReadIsNoRestore`
    fails.

- [ ] **Step 3: The member restored.** In `etcdtest.go`:
  - add to `Server` a field `spec memberSpec`. In `Start`, once `member(spec)` returns and the
    scheme is known, keep `s.spec = spec` with the addresses the start bound, so a restart
    listens where every client dials: `s.spec.client = scheme + e.Clients[0].Addr().String()`,
    `s.spec.peer = "http://" + e.Peers[0].Addr().String()`, and `s.spec.cluster = spec.name +
    "=" + s.spec.peer`;
  - replace `t.Cleanup(e.Close)` with `t.Cleanup(func() { s.e.Close() })`, since a restore
    replaces `s.e`;
  - and add:

  ```go
  // Backup stops the member, copies its data directory, and starts it again
  // on the same addresses, and returns the copy: a cold copy is what an etcd
  // snapshot restores a member of its own to (plan 7e, Ruling 18).
  func (s *Server) Backup(t testing.TB) string {
  	t.Helper()
  	dst := t.TempDir()
  	s.restart(t, func(dir string) error { return copyDir(dst, dir) })
  	return dst
  }

  // Restore stops the member, puts a Backup's copy in place of its data, and
  // starts it again on the same addresses, under every client still
  // connected: an etcd restore without --bump-revision, whose revisions go
  // back to the backup's. A test pads them past a mark to stand for the bump.
  func (s *Server) Restore(t testing.TB, from string) {
  	t.Helper()
  	s.restart(t, func(dir string) error {
  		if err := os.RemoveAll(dir); err != nil {
  			return err
  		}
  		return copyDir(dir, from)
  	})
  }

  func (s *Server) restart(t testing.TB, between func(dir string) error) {
  	t.Helper()
  	s.e.Close()
  	if err := between(filepath.Join(s.spec.dir, s.spec.name)); err != nil {
  		t.Fatal(err)
  	}
  	e, err := member(s.spec)
  	if err != nil {
  		t.Fatal(err)
  	}
  	s.e = e
  }

  // copyDir copies a member's data directory owner only, as etcd requires of
  // it.
  func copyDir(dst, src string) error {
  	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
  		if err != nil {
  			return err
  		}
  		rel, err := filepath.Rel(src, p)
  		if err != nil {
  			return err
  		}
  		to := filepath.Join(dst, rel)
  		if d.IsDir() {
  			return os.MkdirAll(to, 0o700)
  		}
  		body, err := os.ReadFile(p)
  		if err != nil {
  			return err
  		}
  		return os.WriteFile(to, body, 0o600)
  	})
  }
  ```

  Add `"io/fs"` to the imports. A member started on a data directory it already holds ignores
  the initial cluster but checks its own entry, which `s.spec.cluster` keeps.

- [ ] **Step 4: The witness in the store.** In `meta.go`, beside `Judged`:

  ```go
  // WitnessRead is meta/witness as one read found it (plan 7e, Ruling 18):
  // the key's ModRevision, 0 when it is absent, and the revision etcd
  // answered the read at. A restored key keeps its ModRevision, with or
  // without --bump-revision; the header rises under the bump.
  type WitnessRead struct {
  	ModRevision uint64
  	Header      uint64
  }

  // Witness reads meta/witness, as the broker.
  func (s *Store) Witness(ctx context.Context) (WitnessRead, error) {
  	resp, err := s.ctxKV.Get(ctx, s.k.meta("witness"))
  	if err != nil {
  		return WitnessRead{}, unavailable(err)
  	}
  	w := WitnessRead{Header: uint64(resp.Header.Revision)}
  	if len(resp.Kvs) > 0 {
  		w.ModRevision = uint64(resp.Kvs[0].ModRevision)
  	}
  	return w, nil
  }

  // PutWitness rewrites meta/witness, as the broker, if it is still at the
  // ModRevision over (0: absent), and returns the revision it landed at, 0
  // when another write got there first: two runners for a moment never
  // write one over the other. It holds no secret: the runner's name and the
  // time.
  func (s *Store) PutWitness(ctx context.Context, who string, over uint64) (uint64, error) {
  	key := s.k.meta("witness")
  	body, err := json.Marshal(struct {
  		Who string    `json:"who"`
  		At  time.Time `json:"at"`
  	}{who, s.now().UTC()})
  	if err != nil {
  		return 0, err
  	}
  	resp, err := s.ctxKV.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(key), "=", int64(over))).
  		Then(clientv3.OpPut(key, string(body))).Commit()
  	if err != nil {
  		return 0, unavailable(err)
  	}
  	if !resp.Succeeded {
  		return 0, nil
  	}
  	return uint64(resp.Header.Revision), nil
  }

  // FollowWitness tells saw the ModRevision of meta/witness as it reads and
  // watches it, until ctx ends (plan 7e, Ruling 18): one read, then a watch
  // from the read's revision, and a read again a second after the watch
  // ends (a compaction, or etcd gone). A lower revision than before, a
  // restore's, is told too: saw keeps the highest.
  func (s *Store) FollowWitness(ctx context.Context, saw func(uint64)) {
  	key := s.k.meta("witness")
  	for {
  		if resp, err := s.ctxKV.Get(ctx, key); err == nil {
  			if len(resp.Kvs) > 0 {
  				saw(uint64(resp.Kvs[0].ModRevision))
  			}
  			wctx, cancel := context.WithCancel(clientv3.WithRequireLeader(ctx))
  			for wr := range s.ctx.Watch(wctx, key, clientv3.WithRev(resp.Header.Revision+1)) {
  				if wr.Err() != nil {
  					break
  				}
  				for _, ev := range wr.Events {
  					if ev.Type == clientv3.EventTypePut {
  						saw(uint64(ev.Kv.ModRevision))
  					}
  				}
  			}
  			cancel()
  		}
  		select {
  		case <-ctx.Done():
  			return
  		case <-time.After(time.Second):
  		}
  	}
  }
  ```

  Every KV call on the context client goes through `s.ctxKV`, so `Seen()` sees it (Ruling
  T6-a); `FollowWitness`'s `Watch` stays on `s.ctx`, as `WatchContexts`' does.

  The key is `meta/`, which the broker's role writes and the daemon's only reads, so port49d
  can neither suppress nor forge it; `store-roles` is unchanged. `keys.go` needs nothing:
  `meta(name)` takes any name.

- [ ] **Step 5: The record.** Create `internal/port49d/witness.go`:

  ```go
  package port49d

  // witnessRecord is this replica's record of the restore witness (plan 7e,
  // Ruling 18; re-check R6): the highest ModRevision of meta/witness it has
  // seen, followed or written, kept in broker.state_dir/witness.json so it
  // outlives an etcd restore. A store whose witness is below it lost writes
  // this replica saw. The file is keyed by prefix, not by cluster ID, which
  // a restore may or may not keep. Which way it errs: a record lost or old
  // only weakens the check; one the store never reached (a witness deleted
  // by hand, a state_dir reused against a new keyspace) purges once.
  type witnessRecord struct {
  	path, prefix string
  	out          io.Writer
  	mu           sync.Mutex
  	high         uint64
  	have         bool
  	saved        bool // high is in the file
  	failing      bool // the last save failed: said once per run of failures
  }

  type witnessFile struct {
  	Prefix      string `json:"prefix"`
  	ModRevision uint64 `json:"mod_revision"`
  }

  // openWitness reads path. An absent file is no record. A file that cannot
  // be read, does not decode, or is another prefix's is no record either,
  // and says so; the next save replaces it.
  func openWitness(path, prefix string, out io.Writer) *witnessRecord {
  	w := &witnessRecord{path: path, prefix: prefix, out: out, saved: true}
  	body, err := os.ReadFile(path)
  	if errors.Is(err, fs.ErrNotExist) {
  		return w
  	}
  	var f witnessFile
  	switch {
  	case err != nil:
  		fmt.Fprintf(out, "port49-broker: reading %s: %v; no witness record\n", path, err)
  	case json.Unmarshal(body, &f) != nil:
  		fmt.Fprintf(out, "port49-broker: %s does not decode; no witness record\n", path)
  	case f.Prefix != prefix:
  		fmt.Fprintf(out, "port49-broker: %s is another prefix's (%s), not %s's; no witness record\n", path,
  			printsafe.Line(f.Prefix, 256), prefix)
  	default:
  		w.high, w.have = f.ModRevision, true
  	}
  	return w
  }

  // Saw raises the record to rev and never lowers it: a lower witness is a
  // restore's, which the runner judges.
  func (w *witnessRecord) Saw(rev uint64) {
  	w.mu.Lock()
  	defer w.mu.Unlock()
  	if !w.have || rev > w.high {
  		w.high, w.have, w.saved = rev, true, false
  	}
  }

  // Recorded is the record, and whether there is one.
  func (w *witnessRecord) Recorded() (uint64, bool) {
  	w.mu.Lock()
  	defer w.mu.Unlock()
  	return w.high, w.have
  }

  // Reset takes rev as the record, lower or not. The runner calls it once
  // its purge after a restore is done, and only then (Ruling 18).
  func (w *witnessRecord) Reset(rev uint64) {
  	w.mu.Lock()
  	defer w.mu.Unlock()
  	w.high, w.have, w.saved = rev, true, false
  }

  // keep saves the record, when it changed, once a second and as ctx ends.
  func (w *witnessRecord) keep(ctx context.Context) {
  	t := time.NewTicker(time.Second)
  	defer t.Stop()
  	for {
  		select {
  		case <-ctx.Done():
  			w.save()
  			return
  		case <-t.C:
  			w.save()
  		}
  	}
  }

  // save writes the record owner only, through a temporary file renamed
  // into place, as the marks copy is written.
  func (w *witnessRecord) save() {
  	w.mu.Lock()
  	if w.saved || !w.have {
  		w.mu.Unlock()
  		return
  	}
  	high := w.high
  	w.mu.Unlock()
  	body, err := json.Marshal(witnessFile{Prefix: w.prefix, ModRevision: high})
  	if err == nil {
  		err = writeOwnerOnly(w.path, body)
  	}
  	w.mu.Lock()
  	defer w.mu.Unlock()
  	if err != nil {
  		if !w.failing {
  			fmt.Fprintf(w.out, "port49-broker: saving %s: %v; the record is kept in memory and saved again each "+
  				"second\n", w.path, err)
  		}
  		w.failing = true
  		return
  	}
  	w.failing = false
  	w.saved = w.high == high
  }

  // restored judges a read of meta/witness against this replica's record
  // (plan 7e, Ruling 18; re-check R6). Only the key's ModRevision counts: a
  // restored key keeps its own, with or without --bump-revision, while the
  // read's header rises under the bump. why is said when it is not "".
  func restored(read etcdstore.WitnessRead, recorded uint64, haveRecord bool) (bool, string) {
  	if !haveRecord {
  		return false, "no witness record in broker.state_dir; cannot tell whether the store was restored"
  	}
  	if read.ModRevision >= recorded {
  		return false, ""
  	}
  	at := fmt.Sprintf("at revision %d", read.ModRevision)
  	if read.ModRevision == 0 {
  		at = "absent"
  	}
  	return true, fmt.Sprintf("the store's meta/witness is %s, below the %d this replica saw: the store was "+
  		"restored from a snapshot", at, recorded)
  }

  // readWitness takes the replica's record, then reads meta/witness, and
  // judges the read against it (Ruling 18). The record is taken first: a
  // linearizable read sees every witness the record held unless the store
  // went back, while a record taken after the read may hold a witness
  // another runner wrote meanwhile (two runners for a moment, Ruling 6),
  // which would purge at a routine handover (final check, Minor 1).
  func readWitness(ctx context.Context, w *witnessRecord,
  	read func(context.Context) (etcdstore.WitnessRead, error)) (etcdstore.WitnessRead, bool, string, error) {
  	rec, have := w.Recorded()
  	got, err := read(ctx)
  	if err != nil {
  		return got, false, "", err
  	}
  	gone, why := restored(got, rec, have)
  	return got, gone, why, nil
  }
  ```

  Its imports: `context`, `encoding/json`, `errors`, `fmt`, `io`, `io/fs`, `os`, `sync`, `time`,
  `internal/printsafe` and `etcdstore`. `witness_test.go`'s: `bytes`, `context`, `io`, `os`,
  `path/filepath`, `strings`, `testing`, `time`, `etcdtest` and `etcdstore`.

  `writeOwnerOnly(path string, body []byte) error` is the marks copy's write (Task 15b, Step 3):
  a temporary file in the same directory at mode 0600, then `os.Rename`. If Task 15b wrote it
  inline, move it into this function in `markscopy.go` and call it from both.

- [ ] **Step 6: The runner.** In `runner.go`, add the field `witness *witnessRecord` to `runner`,
  and:

  ```go
  // witnessEvery is how often the runner reads meta/witness (Ruling 18): the
  // ledger keeper's interval, and about the most of a snapshot's lead over
  // the last witness that the check cannot see.
  const witnessEvery = time.Second

  // keepWitness is the runner's half of the restore witness (plan 7e,
  // Ruling 18), beside the ledger's keeper, until ctx ends. A pass the
  // store does not answer is tried at the next: an outage is the hold's
  // fence's to judge.
  func (r *runner) keepWitness(ctx context.Context) {
  	t := time.NewTicker(witnessEvery)
  	defer t.Stop()
  	for {
  		if err := r.witnessPass(ctx); err != nil && ctx.Err() == nil && !errors.Is(err, store.ErrUnavailable) {
  			fmt.Fprintf(stderr, "port49-broker: runner: the restore witness: %v; trying again in %v\n", err,
  				witnessEvery)
  		}
  		select {
  		case <-ctx.Done():
  			return
  		case <-t.C:
  		}
  	}
  }

  // witnessPass is one pass of keepWitness. It reads meta/witness first:
  // below the replica's record, the store was restored under a running
  // runner, and it purges, then has the marks put back (Ruling 12), since a
  // watch at a revision the restored store has not reached may not reload.
  // Otherwise it rewrites the witness when the read's header is past the
  // witness's own revision. A quiet store writes nothing: the rewrite's
  // revision is the one the next pass compares with.
  func (r *runner) witnessPass(ctx context.Context) error {
  	rctx, cancel := context.WithTimeout(ctx, witnessEvery)
  	read, gone, why, err := readWitness(rctx, r.witness, r.raw.Witness)
  	cancel()
  	if err != nil {
  		return err
  	}
  	if gone {
  		if err := r.purgeRestored(ctx, why, read); err != nil {
  			return err
  		}
  		select {
  		case r.marksReloaded <- struct{}{}:
  		default:
  		}
  		return nil
  	}
  	if read.Header <= read.ModRevision {
  		return nil
  	}
  	wctx, cancel := context.WithTimeout(ctx, witnessEvery)
  	defer cancel()
  	landed, err := r.raw.PutWitness(wctx, r.who, read.ModRevision)
  	if landed > 0 {
  		r.witness.Saw(landed)
  	}
  	return err
  }

  // purgeRestored purges every unspent token after the witness caught a
  // restore (plan 7e, Ruling 18), as an unjudged takeover does: SupersedeAll
  // first, so a replay mints afresh. It takes the store's witness as the
  // replica's record only once the purge is done: until then every pass,
  // and every replica's takeover, still sees the restore, so a purge cut
  // short by a lost hold is made by the next runner.
  func (r *runner) purgeRestored(ctx context.Context, why string, read etcdstore.WitnessRead) error {
  	at := r.brk.Now()
  	if err := retryCtx(ctx, func() error { return r.st.SupersedeAll(ctx, at) }); err != nil {
  		return err
  	}
  	var n int
  	if err := retryCtx(ctx, func() (e error) { n, e = r.st.PurgeTokens(ctx); return }); err != nil {
  		return err
  	}
  	r.witness.Reset(read.ModRevision)
  	fmt.Fprintf(stderr, "port49-broker: runner: %s; every unspent token is purged and must be minted again "+
  		"(port49 token): %d purged\n", why, n)
  	return nil
  }
  ```

  In `takeover`, replace Task 15's purge block (from `bundle := r.brk.Policy.Load().Bundle`
  through the purge's line) with the witness first, then the judged bundle:

  ```go
  	bundle := r.brk.Policy.Load().Bundle
  	var judged etcdstore.JudgedRecord
  	var ok bool
  	if err := retryCtx(ctx, func() (e error) { judged, ok, e = r.raw.Judged(ctx); return }); err != nil {
  		return err
  	}
  	var read etcdstore.WitnessRead
  	var gone bool
  	var why string
  	if err := retryCtx(ctx, func() (e error) {
  		read, gone, why, e = readWitness(ctx, r.witness, r.raw.Witness)
  		return
  	}); err != nil {
  		return err
  	}
  	if !gone && why != "" {
  		fmt.Fprintf(stderr, "port49-broker: runner: %s; going by meta/judged alone\n", why)
  	}
  	switch {
  	case gone: // meta/judged is the snapshot's: taken as absent
  		if err := r.purgeRestored(ctx, why, read); err != nil {
  			return err
  		}
  	case ok && judged.Bundle == bundle:
  		fmt.Fprintf(stderr, "port49-broker: runner: the bundle in force (%s) is the one the last runner judged; no "+
  			"unspent token purged\n", bundle)
  	default:
  		at := r.brk.Now()
  		// SupersedeAll first: a replay after any token is gone mints afresh (Task 5).
  		if err := retryCtx(ctx, func() error { return r.st.SupersedeAll(ctx, at) }); err != nil {
  			return err
  		}
  		var n int
  		if err := retryCtx(ctx, func() (e error) { n, e = r.st.PurgeTokens(ctx); return }); err != nil {
  			return err
  		}
  		fmt.Fprintf(stderr, "port49-broker: runner: the bundle in force (%s) is not the one the last runner judged "+
  			"(%s); %d unspent token(s) purged (run 'port49 token' again)\n", bundle, orNone(judged.Bundle, ok), n)
  	}
  ```

  `marksReloaded` is Task 15b's `chan struct{}`, buffered one; the send never blocks. Add
  `"errors"` to `runner.go`'s imports if it lacks it.

  The takeover's later steps are unchanged: the carry, and `recordJudged` when it leaves nothing
  owed. In `duties`, run `r.keepWitness(ctx)` on one more goroutine beside the keeper, joined
  with the rest.

- [ ] **Step 7: Wired.** In `brokerd.go`, beside the marks copy, before the runner starts:

  ```go
  	wit := openWitness(filepath.Join(cfg.Broker.StateDir, "witness.json"), cfg.Store.Etcd.Prefix, stderr)
  	wg.Add(2)
  	go func() { defer wg.Done(); wit.keep(ctx) }()
  	go func() { defer wg.Done(); b.FollowWitness(ctx, wit.Saw) }()
  ```

  and give the runner `witness: wit`. Use `runBroker`'s own wait group, whichever name it has:
  both are joined on the drain, and `keep` saves once more as it stops.

- [ ] **Step 8: Run everything.**

  Run: `make build && make test && make vet && make test-race`
  Expected: PASS.

- [ ] **Step 9: Commit.**

  ```bash
  gofmt -w internal/store/etcd internal/port49d
  git add internal/store/etcd/etcdtest/etcdtest.go internal/store/etcd/etcdtest/etcdtest_test.go \
    internal/store/etcd/meta.go internal/store/etcd/meta_test.go internal/port49d/witness.go \
    internal/port49d/witness_test.go internal/port49d/runner.go internal/port49d/brokerd.go \
    internal/port49d/markscopy.go internal/port49d/brokerd_test.go
  git commit -m "feat(port49-broker): a restore witness, so a forgotten runbook step fails closed

  After an etcd restore meta/judged is the snapshot's, so a takeover
  purged nothing and a token redeemed since the snapshot was redeemable
  again, unless the runbook's delete was done. The runner now rewrites
  meta/witness whenever the store has moved, and every broker keeps the
  highest ModRevision it has seen in broker.state_dir/witness.json. A
  restored key keeps its ModRevision under --bump-revision too, so a
  takeover or a running runner that reads the witness below its record
  purges every unspent token and names both revisions (plan 7e Ruling 18,
  pre-flight re-check R6).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 15d: port49d refuses a redemption while the store is older than it followed

Added by controller Ruling T15c-c (2026-10-04); Ruling 19.

**Files:**
- Create: `internal/port49d/restoreguard.go`, `internal/port49d/restoreguard_test.go`
- Modify: `internal/store/etcd/meta.go` (`PutPurged`, `RestoreRead`), `meta_test.go`
- Modify: `internal/port49d/runner.go` (`markPurged`, after every whole purge),
  `internal/port49d/main.go` (the guard is `run`'s, begun and kept by each `runOnce`, asked by
  the authentication handler), `internal/daemon/authen/authen.go` (`WithRedeemGuard`),
  `internal/daemon/metrics/metrics.go` (`port49_redemption_restore_guarded`), `metrics_test.go`,
  `internal/port49d/brokerd_test.go`, `internal/port49d/witness_test.go` (the mode-0000 case
  skipped as root)

**Interfaces:**
- Consumes: Task 15c's `meta/witness`, `FollowWitness`, `witnessEvery` and `purgeRestored`; the
  takeover's purge.
- Produces:
  - `func (s *etcd.Store) PutPurged(ctx context.Context, who string) (uint64, error)` at
    `meta/purged`; `type etcd.RestoreRead struct { Witness, Purged, Header uint64 }` and
    `func (s *etcd.Store) RestoreRead(ctx context.Context) (RestoreRead, error)`, one
    transaction.
  - `type restoreGuard struct` with `newRestoreGuard(out io.Writer)`, `begin(gauge)`,
    `Allows() bool`, `Saw(rev uint64)`, `judge(etcdstore.RestoreRead, error)` and
    `keep(ctx, *etcdstore.Store)`.
  - `func (h *authen.Handler) WithRedeemGuard(func() bool) *authen.Handler`.

- [ ] **Step 1: The failing tests.** `TestTheRestoreGuardEntersOnADropAndLeavesOnlyOnAPurge`
  (enter on a drop and on a witness gone after one was seen; stay on a failed read, said once,
  on a plain witness write, a followed witness and a purge from before the drop; leave on a
  purge after it; the gauge 1 then 0), `TestARunAfterAStoreGoneRedeemsOnlyOnceTheStoreIsJudged`,
  `TestARestoreReadSaysTheWitnessAndThePurge`, and the fleet test
  `TestPort49dRefusesARestoredTokenUntilTheRunnerPurges`: port49d runs across a restore from a
  backup taken before a token's redemption, with neither of the runbook's deletes and the
  revisions padded past the pre-restore ones; the replay is refused `store_unavailable` with no
  candidate lookup and the gauge at 1, until the runner's purge; then the gauge is 0 and a token
  minted after the purge logs in.
- [ ] **Step 2: Mutations**, each caught: the drop compared by header; the witness gone after
  one was seen ignored; leaving on a plain witness write; leaving on a purge from before the
  drop; the timer re-read removed; a run that starts checked; the guard not asked at redemption.
- [ ] **Step 3: Build** what the interfaces name. The guard is asked before the candidates
  lookup, so a receipt's replay, an `auto` escalation and every other path are untouched.
- [ ] **Step 4: Run** `make test && make vet && make test-race`, and `go test -race ./cmd/...`.
- [ ] **Step 5: Commit** `feat(port49d): refuse a redemption while the store is older than it
  followed`.

---

### Task 16: The fleet end to end, and `store-roles` for two files

**Files:**
- Create: `internal/port49d/split_e2e_test.go`
- Modify: `internal/port49d/storeroles.go`, `storeroles_test.go`

**Interfaces:**
- Consumes: everything Tasks 12–15 produce.
- Produces: `port49d store-roles --config FILE --broker-config FILE`.

The properties no single task's tests reach: two of each process, and a store writer between
them.

- [ ] **Step 1: The failing tests.** Create `internal/port49d/split_e2e_test.go` on Task 15's
  `splitFleet`:

  ```go
  // A login on one port49d is answered on another at its next command, as
  // a device that opens a connection per transaction sends it to whichever
  // server answers (Review Focus 1).
  func TestALoginOnOneDaemonIsAnsweredOnAnother(t *testing.T) {
  	var out, log syncBuffer
  	e, o := stderr, stdout
  	t.Cleanup(func() { stderr, stdout = e, o })
  	stderr, stdout = &out, &log
  	f := splitFleet(t)
  	a := startSplitDaemon(t, f.daemon, &out, 1)
  	b := startSplitDaemon(t, f.copyDaemon(t), &out, 2)
  	api, _ := startBroker(t, f.broker, &out, 1)
  	devA := tacacsClient{t: t, addr: a, key: []byte("run-test-secret")}
  	devB := tacacsClient{t: t, addr: b, key: []byte("run-test-secret")}
  	loginSession(t, devA, mintOn(t, api, f.pki, "leaf1"), &log)
  	if !devB.permits("alice", "configure") {
  		t.Fatalf("the other daemon did not answer the session's next command: %v", lastCommand(t, &log))
  	}
  }

  // A revocation on one port49-broker closes the agent's held connection to
  // the other, and both daemons deny the session's next command
  // credential_revoked (Review Focus 3).
  func TestARevocationOnOneBrokerReachesTheOther(t *testing.T) {
  	var out, log syncBuffer
  	e, o := stderr, stdout
  	t.Cleanup(func() { stderr, stdout = e, o })
  	stderr, stdout = &out, &log
  	f := splitFleet(t)
  	tacacs := startSplitDaemon(t, f.daemon, &out, 1)
  	apiA, _ := startBroker(t, f.broker, &out, 1)
  	cfgB := f.copyBroker(t) // its own API address and admin socket
  	startBroker(t, cfgB, &out, 2)
  	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
  	loginSession(t, dev, mintOn(t, apiA, f.pki, "leaf1"), &log)
  	principal := lastCommandPrincipal(t, &log)
  	held := heldBrokerConn(t, f.pki, apiA) // alice's connection to A, one request answered, kept open
  	resp := askAdminAt(t, adminSocketOf(t, cfgB), admin.Request{Op: "revoke", Principal: principal})
  	if resp.Error != "" {
  		t.Fatalf("the revocation on B: %+v", resp)
  	}
  	if !closedWithin(held, 5*time.Second) {
  		t.Fatal("A kept alice's held connection after B revoked her")
  	}
  	if dev.permits("alice", "configure") {
  		t.Fatal("the daemon permitted the session's next command after the revocation")
  	}
  	if r := lastCommand(t, &log); r["reason"] != "credential_revoked" {
  		t.Fatalf("the denial: %v", r)
  	}
  	if code, body := mintStatus(t, apiA, f.pki, "leaf1"); code != http.StatusUnauthorized ||
  		!strings.Contains(body, "credential_revoked") {
  		t.Fatalf("a mint on A after B's revocation: %d %s", code, body)
  	}
  }

  // A context put back while a daemon was stopped, and another daemon ran,
  // is denied by the stopped one when it starts: the runner's ledger record
  // holds the later mark (Review Focus 2; Ruling 4). The put-back is bob's
  // context over alice's at the username both log in as (pre-flight I14).
  // bob is a second identity of alice's subject (sharedUsernamePolicy, as
  // built in Task 10; spec §2), not a second subject, so the put-back is
  // another principal at the same key: impersonation, so a denial cannot
  // come from an unrelated fault. The controls: a daemon started with
  // nothing put back permits alice's session, and the running daemon
  // permits it before the put-back.
  func TestAPutBackBeforeADaemonStartsIsDenied(t *testing.T) {
  	var out, log syncBuffer
  	e, o := stderr, stdout
  	t.Cleanup(func() { stderr, stdout = e, o })
  	stderr, stdout = &out, &log
  	f := splitFleetWith(t, sharedUsernamePolicy, []string{"bob@example.com"})
  	root := f.srv.Client(t, "root")
  	ctx := context.Background()
  	a := startSplitDaemon(t, f.daemon, &out, 1)
  	api, _ := startBroker(t, f.broker, &out, 1)
  	devA := tacacsClient{t: t, addr: a, key: []byte("run-test-secret")}
  	loginSession(t, devA, mintOnAs(t, api, f.pki, "leaf1", "bob@example.com"), &log)
  	resp, err := root.Get(ctx, "/port49/v1/c/leaf1/alice")
  	if err != nil || len(resp.Kvs) != 1 {
  		t.Fatalf("bob's context: %v %v", resp, err)
  	}
  	bobs := resp.Kvs[0]
  	s1 := waitForLedgerSeq(t, root, "/port49/v1/lw/leaf1/alice", 0)
  	loginSession(t, devA, mintOn(t, api, f.pki, "leaf1"), &log) // alice's, later, at the key
  	waitForLedgerSeq(t, root, "/port49/v1/lw/leaf1/alice", s1)   // the runner's record holds it
  	if !devA.permits("alice", "configure") || lastCommandPrincipal(t, &log) != "user:alice@example.com" {
  		t.Fatal("control: alice's session on the running daemon")
  	}
  	c := startSplitDaemon(t, f.copyDaemon(t), &out, 2) // started with nothing put back
  	devC := tacacsClient{t: t, addr: c, key: []byte("run-test-secret")}
  	if !devC.permits("alice", "configure") {
  		t.Fatal("control: a daemon started with nothing put back denied alice's session")
  	}
  	if _, err := root.Put(ctx, string(bobs.Key), string(bobs.Value)); err != nil {
  		t.Fatal(err)
  	}
  	b := startSplitDaemon(t, f.copyDaemon(t), &out, 3) // started after the put-back
  	devB := tacacsClient{t: t, addr: b, key: []byte("run-test-secret")}
  	if devB.permits("alice", "configure") {
  		t.Fatalf("a daemon started after a put-back took bob's context as alice's key's: %v",
  			lastCommandPrincipal(t, &log))
  	}
  	if devA.permits("alice", "configure") {
  		t.Fatal("the running daemon took the put-back once its feed had passed it")
  	}
  }

  // With every port49-broker stopped and no broker host to run the offline
  // revocation on, a mark written as etcd's root reaches every port49d
  // through its marks feed, and the session's next command is denied
  // credential_revoked (Ruling 13's break-glass; pre-flight I4). A token
  // already minted still logs in, and its commands are denied.
  func TestARootWrittenMarkDeniesWithEveryBrokerStopped(t *testing.T) {
  	var out, log syncBuffer
  	e, o := stderr, stdout
  	t.Cleanup(func() { stderr, stdout = e, o })
  	stderr, stdout = &out, &log
  	f := splitFleet(t)
  	root := f.srv.Client(t, "root")
  	a := startSplitDaemon(t, f.daemon, &out, 1)
  	b := startSplitDaemon(t, f.copyDaemon(t), &out, 2)
  	api, stop := startBroker(t, f.broker, &out, 1)
  	devA := tacacsClient{t: t, addr: a, key: []byte("run-test-secret")}
  	devB := tacacsClient{t: t, addr: b, key: []byte("run-test-secret")}
  	loginSession(t, devA, mintOn(t, api, f.pki, "leaf1"), &log)
  	if err := stop(); err != nil {
  		t.Fatal(err)
  	}
  	if !devA.permits("alice", "configure") || !devB.permits("alice", "configure") {
  		t.Fatal("control: the session runs on, on either daemon, with every broker stopped")
  	}
  	mark := fmt.Sprintf(`{"kind":"principal","key":"user:alice@example.com","at":%q,"origin":"etcdctl"}`,
  		time.Now().UTC().Format(time.RFC3339))
  	if _, err := root.Put(context.Background(), "/port49/v1/rv/principal/user:alice@example.com", mark); err != nil {
  		t.Fatal(err)
  	}
  	for name, dev := range map[string]tacacsClient{"a": devA, "b": devB} {
  		waitUntil(t, name + " to deny alice configure", func() bool { return !dev.permits("alice", "configure") })
  		if r := lastCommand(t, &log); r["reason"] != "credential_revoked" {
  			t.Fatalf("daemon %s's denial: %v", name, r)
  		}
  	}
  }

  // With every port49-broker stopped, an open session's next command is
  // answered and a token minted before the stop logs in (design §6: the
  // daemon never calls the broker).
  func TestWithEveryBrokerStoppedOpenSessionsRunOn(t *testing.T) {
  	var out, log syncBuffer
  	e, o := stderr, stdout
  	t.Cleanup(func() { stderr, stdout = e, o })
  	stderr, stdout = &out, &log
  	f := splitFleet(t)
  	a := startSplitDaemon(t, f.daemon, &out, 1)
  	api, stop := startBroker(t, f.broker, &out, 1)
  	dev := tacacsClient{t: t, addr: a, key: []byte("run-test-secret")}
  	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
  	spare := mintOn(t, api, f.pki, "leaf1")
  	if err := stop(); err != nil {
  		t.Fatal(err)
  	}
  	if !dev.permits("alice", "configure") {
  		t.Fatalf("an open session's command with every broker stopped: %v", lastCommand(t, &log))
  	}
  	if st := dev.login("alice", spare); st != wire.AuthenStatusPass {
  		t.Fatalf("a token minted before every broker stopped: %d", st)
  	}
  }
  ```

  The helpers beside Task 15's and 15b's:
  - `heldBrokerConn` is 7e-1's (`store_e2e_test.go`), moved by Task 12;
  - `closedWithin` is a read that returns EOF or a reset within the bound;
  - `askAdminAt` and `adminSocketOf` are Task 15b's;
  - `mintStatus` is `mintOn` that returns the status and body;
  - `splitFleetWith(t, policyBody, others)` is `splitFleet` over Task 10's `brokerConfigWith`,
    so the lab pki holds a client certificate for each of `others`, and `splitFleet` becomes
    `splitFleetWith(t, minimalPolicy, nil)`;
  - `mintOnAs(t, api, pki, device, email)` is `mintOn` with `email`'s certificate, as Task 10's
    `mintAs`;
  - `waitForLedgerSeq`, `sharedUsernamePolicy` and `lastCommandPrincipal` came over in Task
    12's move;
  - `waitUntil` is `revocations_test.go`'s.

  No test here waits on a gauge already at its target (pre-flight I14).

  In `storeroles_test.go`:

  ```go
  // store-roles reads the daemon's CN from port49d.yaml and the broker's from
  // port49-broker.yaml (Ruling 14); either alone is refused, naming the other.
  func TestStoreRolesReadsBothFiles(t *testing.T) {
  	f := splitFleet(t)
  	var out, errb bytes.Buffer
  	if code := storeRolesCmd([]string{"--config", f.daemon, "--broker-config", f.broker}, &out, &errb); code != 0 {
  		t.Fatalf("exit %d: %s", code, errb.String())
  	}
  	if !strings.Contains(out.String(), "etcdctl role grant-permission port49_daemon read --prefix=true /port49/v1/lw/") ||
  		!strings.Contains(out.String(), "etcdctl user add port49-broker --no-password") {
  		t.Fatalf("%s", out.String())
  	}
  	errb.Reset()
  	if code := storeRolesCmd([]string{"--config", f.daemon}, &out, &errb); code != 1 ||
  		!strings.Contains(errb.String(), "--broker-config") {
  		t.Fatalf("one file: exit %d, %s", code, errb.String())
  	}
  }

  // A 7d port49d.yaml naming both identities still yields both roles with
  // no --broker-config, and says to move the broker's identity (pre-flight
  // I8: StoreBlocks reads it with no role; Load would refuse it).
  func TestStoreRolesStillReadsA7dFile(t *testing.T) {
  	f := splitFleet(t)
  	old := f.sevenDFile(t) // port49d.yaml as 7d wrote it: a broker: block and both identities
  	var out, errb bytes.Buffer
  	if code := storeRolesCmd([]string{"--config", old}, &out, &errb); code != 0 {
  		t.Fatalf("exit %d: %s", code, errb.String())
  	}
  	if !strings.Contains(out.String(), "etcdctl user add port49-broker --no-password") ||
  		!strings.Contains(errb.String(), "port49-broker.yaml") {
  		t.Fatalf("out %s; err %s", out.String(), errb.String())
  	}
  	if _, err := config.Load(old); err == nil {
  		t.Fatal("control: Load under the daemon's role must refuse the 7d file on etcd")
  	}
  }
  ```

  `f.sevenDFile(t)` writes the fleet's daemon config with the broker's `broker:` block and
  `store.etcd.broker` added back, as `etcdRunServer` wrote it in 7d.

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/port49d/ -run 'OneDaemonIsAnswered|OneBrokerReaches|BeforeADaemonStarts|EveryBrokerStopped|RootWrittenMark|ReadsBothFiles|A7dFile' -count=1`
  Expected: the e2e tests PASS where Tasks 12–15b hold, and FAIL to show any gap. Each failure
  is a defect in an earlier task, fixed in its own `fix(…)` commit with this test as its
  witness. That these pass first is said in the report: they are the fleet's integration
  witnesses, not failing-first tests. `TestStoreRolesReadsBothFiles` and
  `TestStoreRolesStillReadsA7dFile` FAIL: `--broker-config` is undefined.

- [ ] **Step 3: `store-roles`.** In `storeroles.go`:
  - add `--broker-config` (default `/etc/port49/port49-broker.yaml`);
  - read the daemon's identity from `--config`'s `store.etcd.daemon`, and the broker's from
    `--broker-config`'s `store.etcd.broker`, each through `config.StoreBlocks` (Task 13), which
    checks shape and no role (pre-flight I8);
  - refuse a mismatch of `store.etcd.prefix` between the two ("the two files name different
    keyspaces");
  - a `--config` that still names `store.etcd.broker` (a 7d file) keeps working without
    `--broker-config`, said with a line naming the move (Ruling 1). `StoreBlocks` reads both of
    its identities; `config.Load` would refuse that file, and `store-roles` never calls it. A
    file with neither is refused naming `--broker-config`;
  - the header line says `(plan 7e)`, and the four "until plan 7e" comment lines become "the
    daemon's credential cannot write a mark, meta/, the ledger record or the superseded record;
    port49d holds it alone (plan 7e)".

  The usage line becomes `usage: port49d store-roles [--config FILE] [--broker-config FILE]`.

- [ ] **Step 4: Run everything.**

  Run: `make build && make test && make vet && make test-race`
  Expected: PASS.

- [ ] **Step 5: Commit.**

  ```bash
  gofmt -w internal/port49d
  git add internal/port49d/split_e2e_test.go internal/port49d/storeroles.go internal/port49d/storeroles_test.go \
    internal/port49d/brokerd_test.go
  git commit -m "test(port49d): the fleet end to end; store-roles reads both files

  Two daemons and two brokers on one keyspace: a login answered on the
  other daemon, a revocation on one broker closing the other's held
  connection, bob's context put back over alice's denied by a daemon
  started after it, sessions running on with every broker stopped, and a
  mark written as etcd's root denying them. store-roles takes the broker's
  identity from port49-broker.yaml, and still reads a 7d file whole
  (plan 7e Rulings 13, 14).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 17: (lab, on beehive) L37, L38 and L36 on the split deployment

**Files:**
- Create: `tests/lab/split_test.go`
- Modify: `tests/lab/harness_test.go` (`startSplit`, the second replica, the broker's process,
  `addSecondServer` and `removeSecondServer`), `tests/lab/store_test.go` (`storeLab` on the
  split's two configs)
- Not modified: the topologies (`tests/lab/topologies/*.clab.yml`) and the startup configs
  (`tests/lab/configs/*`). The second TACACS+ server is pushed by `startSplit` and removed at
  the test's end (pre-flight I13)
- Create (by the run): `tests/lab/results/L37-*.md`, `L38-cisco_iosxe.md`, `L36-*.md`;
  `tests/lab/evidence/L3[678]-*.pcap`
- Modify (closing): `docs/design/2026-08-23-policy-engine-spec.md` §15 (L36, L37, L38),
  `docs/design/2026-08-21-port49-design.md` §12 (the cells Task 11 left open)

**Interfaces:**
- Consumes:
  - `bin/port49d` and `bin/port49-broker` built at the pinned commit;
  - the lab harness's `lab`, `labShell`, `revokeOutcome`, `storeOutcome`, `replyTimes` and
    `l.result`;
  - etcdtest's TLS member, proxy and roles, as L35's `storeLab`.
- Produces: the three rows measured, and the notes.

Ruling 16. Read "Running the lab" first. **No claim enters a doc before its row's notes exist**
(CLAUDE.md rule 1). A result that contradicts a doc is the doc's to fix (rule 4).

- [ ] **Step 0: Before dispatch.** The controller checks:
  - `lab-instructions.md` for 7e exists and names this task's tests, platforms, captures and
    the 40-minute watchdog on the Junos images;
  - beehive's root filesystem has 20 GiB free (`df -h /`; 7d's Task 15 died at ENOSPC);
  - `make evidence` passes on the feature branch (7d's L35 captures are on `main`);
  - the five images are present (`image_check_test.go`);
  - `TestStoreOutageEndToEnd` and `TestStoreSnapshotRestore` start on the split (a dry run on
    one image). Task 16 left `storeLab` returning both store blocks, and left both tests on a
    single port49d config that carries `slice/broker.yaml`'s `broker:` block and the lab seeds,
    which `config.Load` refuses on etcd ("lab seed tokens are minted by port49-broker"). Step 1
    moves the seeds, the broker block and `store.etcd.broker` into the port49-broker file.

- [ ] **Step 1: The harness, committed first.**
  - **`startSplit(cfg splitCfg)`.** It starts, from the pinned `bin/`:
    - `port49-broker --config tests/lab/port49-broker-lab.yaml`, which mints the lab seeds;
    - port49d A on `172.100.100.1:49`;
    - port49d B on `172.100.100.2:49`.

    All three share one embedded etcd member, through L35's proxy, with the daemon's and the
    broker's identities. Each process gets its own log and stderr file under
    `tests/lab/logs/`. `stopDaemon(which)`, `stopBroker()` and `startBroker()` each wait on the
    process's exit, as `stopDaemon` does today.
  - **The second address.** `startSplit` adds the bridge's second host address and removes it
    in `t.Cleanup`.
  - **The second server, pushed and removed** (pre-flight I13).
    - `addSecondServer(t, l)` pushes the configuration that lists `172.100.100.2` after
      `172.100.100.1`, in one group, in the platform's own syntax, through `labShell`'s config
      path.
    - `removeSecondServer` pushes the inverse. `startSplit` registers it in `t.Cleanup`, so a
      failed test still removes it.
    - Neither touches the startup configs or the topologies. Every other register test (L1–L36)
      therefore runs with the one server it was measured with: on `ERROR`, a timeout or a
      refused connection a device tries the next server, and a listed server with nothing
      behind it would change L4's and L35's timings and fallbacks.
    - Every pushed line was measured working on its image in an earlier row; cite which in a
      comment. Where one was not, Step 2's first cell is its own check.

  Create `tests/lab/split_test.go` with `//go:build lab` and three tests:
  - **`TestSplitEndToEnd`, L37 on every image, one cell per row of this table, in order.** Each
    cell records the device's output and each request's reply time from the capture
    (`replyTimes`):

    | Cell | Done | Measured |
    |---|---|---|
    | 1 | Mint through `port49-broker` (the lab agent), log in through A (stop B first, start it after), run `show version` | the baseline: permit, `ctx_id` |
    | 2 | Stop A; the session's next command | answered by B? permit from the same `ctx_id`? the device's delay before it tried B |
    | 3 | Start A; stop the broker; the session's next command; then a login with a token minted before the stop | permit; the token logs in |
    | 4 | Start the broker; `port49 revoke --principal` on its socket; the session's next command on A, then (A stopped) on B | `credential_revoked` on each, or the session's own reaction on Junos (decision 21) |
    | 5 | Lift; hang the store; time to each daemon closing its listeners; break-glass once both are closed | seconds to dark with no hold; break-glass logs in |

    Each cell's result is a row in `L37-<platform>.md`.
  - **`TestIOSXEOpenSessionUnreachable`, L38, IOS-XE only.** Four cells:
    `{show privilege, show version}` × `{the daemons stopped with nothing before, the daemons
    stopped after a FAIL store_unavailable on the session's last command}`. For the second
    column, hang the store, run one command (FAIL), then stop both daemons with the store still
    hung. Each cell: the command's output, and whether the device sent anything (the capture). A
    `show privilege` after `show version` in the same cell, and the reverse order in a fresh
    session, tell an order effect from a command effect.
  - **`TestJunosReauthorizationAfterRestart`, L36, vJunos-router and vSRX.** Set
    `authorization-time-interval 15` on the device. Log in through A and keep the session.
    Restart A, with B stopped so the device asks A. Wait 16 minutes, watching the capture for
    the re-authorization request. Record its reply and the session's reaction. Then revoke the
    principal and wait for the next re-authorization: does a denial end the session, or not?

  Commit before the run:

  ```bash
  git add tests/lab/split_test.go tests/lab/harness_test.go tests/lab/store_test.go
  git commit -m "test(lab): L37, L38 and L36 on the split deployment

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

- [ ] **Step 2: The run.** From the pinned worktree, one platform at a time, as "Running the
  lab" says:

  ```bash
  PORT49_LAB_PLATFORMS=eos go test -tags lab ./tests/lab/ -run 'TestSplitEndToEnd' -count=1 -v -timeout 120m
  PORT49_LAB_PLATFORMS=nxos  …  -run 'TestSplitEndToEnd'
  PORT49_LAB_PLATFORMS=iosxe …  -run 'TestSplitEndToEnd|TestIOSXEOpenSessionUnreachable'
  PORT49_LAB_PLATFORMS=vjunos … -run 'TestSplitEndToEnd|TestJunosReauthorizationAfterRestart'
  PORT49_LAB_PLATFORMS=vsrx  …  -run 'TestSplitEndToEnd|TestJunosReauthorizationAfterRestart'
  ```

  After the split tests on EOS, re-run one L35 cell with the second server removed, and check
  it matches `L35-arista_eos.md` within its recorded spread (pre-flight I13):

  ```bash
  PORT49_LAB_PLATFORMS=eos go test -tags lab ./tests/lab/ -run 'TestStoreOutageEndToEnd' -count=1 -v -timeout 60m
  ```

  A mismatch means `removeSecondServer` left something behind: fix the harness, and re-run.
  This one is a check, not a new measurement. Its note is a line in `L37-arista_eos.md`.

  **Cell outcomes:**
  - A cell whose precondition failed (the device never tried B, the store did not hang) is
    re-run up to three times, then recorded INVALID, as L35's Ruling T15-a. **A row with an
    INVALID cell on a named image stays open for that image**: it is not closed, and the note
    says what would make the cell valid.
  - A cell that shows port49 wrong (B denies a session A wrote, a revocation that does not
    reach B, a daemon that does not go dark) is a defect. Fix it on the branch, with a unit
    test, in a `fix(…)` commit, and re-run every image from a worktree pinned to the fix
    (CLAUDE.md rule 4).
  - A device that does not try the second server is a device fact, not a defect: record it.
  - **A context read that times out across a re-watch** (a `store_unavailable` naming `context
    feed has not delivered`, or `port49_store_fence_timeouts_total` rising, in the seconds after
    a daemon's feed resumes: cells 2–5 restart and hang things) reopens Task 8a's parked R-1:
    the fence's `askAgain` may reach etcd before the new watch registers, so that read falls
    back to the full `call_timeout` wait. It fails closed, but it is a defect if a device sees
    it. Record the cell and the daemon's log, and revisit R-1 as a defect above (the 8a
    re-review's note in the SDD ledger, `progress.md`).

- [ ] **Step 3: Close the rows.** Close each row only when every platform it names has a note
  with no INVALID cell.
  - **L37:** five images. **L38:** IOS-XE. **L36:** both Junos images.
  - **The notes.** Each has the date, the image versions and digests, the run command at the
    pinned commit, a capture pointer, the credentials statement, and the observation table with
    each reply time.
  - **The rows.** Edit each Status to `closed — measured <date>; tests/lab/results/…`, with a
    per-image summary as L35's has.
  - **Design §12.** Replace the "(L37, open)" and "(policy engine spec §15 L37, open)" clauses
    Task 11 wrote with what was measured, citing the notes.
  - **The IOS-XE cells** of the store rows: replace L35's "unlike `quarantine-cisco_iosxe.md`"
    clause with L38's answer.
  - **L36's answer** replaces the 7d operator note (`README.md`, "Junos re-authorization on
    etcd is unmeasured") and is stated in Task 18's notes.

  Copy the captures back and run `make evidence` before removing the pinned worktree. Commit:

  ```bash
  git add tests/lab/results/L36-*.md tests/lab/results/L37-*.md tests/lab/results/L38-cisco_iosxe.md \
    tests/lab/evidence/L36-* tests/lab/evidence/L37-* tests/lab/evidence/L38-* \
    docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md \
    docs/superpowers/plans/README.md
  git commit -m "docs: close lab register entries L36, L37 and L38

  <one line per row: what was measured, on which images; any doc corrected
  by a result, named, per CLAUDE.md rule 4>

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 18: Plan 7e as built

**Files:**
- Modify: `docs/superpowers/plans/README.md` (the status line; the 7e bullet; "Plan 7e — As
  built")
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`, `docs/design/2026-08-21-port49-design.md`
  (any drift a task report names that its own task did not fix)

**Interfaces:** none.

- [ ] **Step 1: As built.** In the README's "Plan 7e — As built" (Task 10 started it with 7e-1),
  add **7e-2**. It covers:
  - every task's commits;
  - what differs from this plan's text;
  - the rulings as made, against Rulings 1–18 and OR-1. OR-1 is no longer open: Ryan closed it
    on 2026-10-03 ("use your best judgement"). Record it as made: `port49 revoke` keeps port49d's
    socket as its default, and on etcd port49d's socket names the broker's. Nothing is left
    under "Open for Ryan";
  - the deployment consequences 7e-2 adds, stated alike for each of plan 12's three shapes
    (systemd, containers, Kubernetes; roadmap "Deployment shapes", L39), never for Kubernetes
    alone: where `broker.state_dir` lives, where each admin socket is reached, and that port49d
    replicas replace one at a time with a new one beside the old;
  - the lab table, one row per image, from the notes: cells 1–5 of L37, L38's four cells, and
    L36;
  - the operator notes below, as amended by what was built;
  - "Carried, for later plans", and the unassigned follow-ups, with the residual Ruling 4 leaves
    named exactly, and the per-replica self/key bound and revocation slot (7c's carry, left
    unassigned in the carries table). Also unassigned: `putBackFileMarks` and `withHeld`, kept
    for the memory store's file, which no marks feed calls since Task 14; remove them if the
    file never returns to etcd.
- [ ] **Step 2: The status line.** In the README's status paragraph, after the 7d-2 sentence, add
  `**7e written 2026-10-03** (…), **executed** …, **merged** … (PR #…)`. The 7e bullet under
  "Plan 7" gains `**As built:** "Plan 7e — As built", below.`
- [ ] **Step 3: Drift.** Fix every doc drift a task report names that its own task left. Check
  that no line in the spec or design still says "until plan 7e" (`grep -n 'until plan 7e'
  docs/design/*.md` prints nothing). Check that the carries Task 11 wrote stand in the design
  as built: §15's exports list names the four 7e-1 gauges and
  `port49_store_fence_timeouts_total`; §13 cites etcd #15220, asks for NTP on the broker hosts,
  and gives the recovery for a `meta/superseded_all` that does not decode. If a task changed
  what they say, fix them here.
- [ ] **Step 4: Commit.**

  ```bash
  git add docs/superpowers/plans/README.md docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
  git commit -m "docs: plan 7e as built

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

## Operator-facing notes (for the pull request bodies)

**7e-1's:**
- **Re-apply `port49d store-roles` before upgrading.** It prints one more grant: the daemon's
  read on `lw/`. Without it the start stops with `the daemon's role cannot read lw/, the ledger
  record: apply port49d store-roles (plan 7e)`. port49d's start check also refuses a daemon role
  that can write `lw/` or touch `sp/`.
- **Upgrading from 7d on etcd ends every live session once.** A session record 7d sealed does
  not open under 7e. It is denied `store_unavailable`, replaced at the user's next login, and
  revoked by the next refresh pass. Users log in again.
  - Each node says it once per 10 minutes as the upgrade, never as tampering: `a context sealed
    by an earlier port49 (form 3) does not open: expected once after the 7e upgrade`.
  - Rolling back to 7d ends sessions again: 7d does not open 7e's records.
  - The memory store loses everything at a restart, as before.
- **A context put back in etcd while port49d was stopped is now denied after the restart,** for
  every key the new ledger record (`lw/`) holds a later write for. In 7d the start took it as
  that key's.
- **A context read waits for port49d's watch on the store** (the feed fence).
  - Normally that is milliseconds, on a command after a write.
  - If the watch stops while etcd answers, new sessions are denied `store_unavailable`, and
    `port49_store_feed_up{feed="contexts"}` is 0. The line says `the context feed stopped`.
  - A watch that falls past a compaction reads the ledger record again, then the store, and
    says so once.
  - **Run etcd 3.5.8 or later** (3.4.24 on 3.4). The wait rests on an ordering older etcd
    releases do not keep (etcd #15220); the tests run v3.6.15.
- **After an etcd restore under a running port49d**, with or without `--bump-revision`, the
  next login is admitted, and a session written since the snapshot is denied until its next
  login, as 7d measured.
  - A mark the restore lost is put back from `broker.revocations_file` before the marks feed
    reloads, and said (`… were missing from the store (an etcd restore?) and are put back`). A
    put-back that fails reloads nothing: the marks feed is down until it lands (final review
    C-1, C-2). A mark not in this port49d's file that the reload lifts is said by its key.
  - A port49d restarted soon after a lift made on another port49d may put that mark back: lift
    it again. 7e-2 retires the file on etcd, and this note with it.
- **Each feed says each stop and each return**, and a reconnect within the compaction retention
  resumes without a reload (final review I-1, I-2).
- **The upgrade** also logs, per live context, `broker: refresh: the context for … will not open
  (crypt: a context sealed by an earlier port49 (form 3, not 4)); revoking it`, beside the
  once-per-10-minutes line. Both are expected, once.
- **Rolling back to 7d** prints 7d's `a context failed authentication under key id "…" …: it was
  altered or is corrupt` once per 10 minutes per key id, and 7d's start refresh revokes every 7e
  context as tampered, one line each. That is the rollback, not an attack.
- **A revocation at a key with no ledger mark** (each form-3 context at the upgrade) leaves an
  `lw/` key with no lease until the key's next login. One never logged into again stays, at most
  one per (device, username).
- **`port49 refresh` and `port49 token`** say the broker's `credential_revoked` reason instead of
  `no agent at …`, and an ending agent waits up to 5s for its in-flight calls (f6e5a26).
- **`port49_revocations_in_force`** counts the marks this process enforces, following the store's
  marks feed.
- **A stalled decision-log sink no longer holds a policy reload**, nor the mints behind it. A
  mint's records are written once it has let go of the policy.
- **New config refusal:** an `encryption` key `id` outside `A-Z a-z 0-9 . _ -` (1 to 64) is
  refused at load.
- **New metrics:**
  - `port49_store_feed_up{feed}` (`contexts`, `marks`): 0 for longer than `hold_ttl` is an alarm;
    both read 0 from when a run on etcd begins waiting for the store;
  - `port49_store_feed_rescans_total{feed}`: alert on any increase;
  - `port49_ledger_pending`: above 0 for a minute is an alarm;
  - `port49_ledger_behind`: 1 is an alarm. The record keeper's watch is down, and pending cannot
    show what the record misses;
  - `port49_store_fence_timeouts_total`: context reads denied because the context feed had not
    delivered in time. Rising with `feed_up` 1 and etcd answering, the feed lags; it is not the
    store.

The roadmap's "7e-1's operator notes, as built" (`README.md`) is the full text these summarise.

**7e-2's:**
- **New binary: `port49-broker`.** On etcd the broker runs as its own process, from
  `port49-broker.yaml`, beside `port49d`. Any number of each run on one keyspace.
  - **Migration from 7d on etcd.** port49d.yaml with a `broker:` block is refused. Move the
    block, with `store.etcd.broker`, into `port49-broker.yaml`. There:
    - add `key_refs:` (the names of your `keys:`, no secrets) and `broker.state_dir`;
    - remove `broker.revocations_file`;
    - keep `encryption:`, the inventory and `admin_socket`.

    In port49d.yaml, add `policy: {file: <the same policy file>, watch_interval: 5s}` and
    remove `store.etcd.broker`. The marks are already in etcd: every 7d start put the file's
    there.
  - **Run** `port49d store-roles --config port49d.yaml --broker-config port49-broker.yaml` and
    apply its output. On the 7d file alone it still works, and says to move the broker's
    identity.
  - **Rolling back:** a 7e-2 port49d refused on its config can be rolled back to the 7e-1
    binary, which still reads the 7d file.
  - **Set the same `broker.policy_file` content and `broker.policy_watch_interval` on every
    broker replica.** A replica serving another bundle says so, and
    `port49_policy_bundle_matches_runner` is 0 there. When it catches up, the runner carries
    every live context.
  - **Alert on `port49_broker_mint_gate_closed == 1` for longer than a minute.** A broker that
    swaps its policy marks the bundle last judged in doubt before it mints under the new one
    (Task 15a). Until the mark lands its mints answer 503 `store_unavailable`, while `/readyz`
    stays 200 (design §12: a store fault is an alarm, never readiness). A swap holds the gauge
    at 1 for one store round trip; a minute is a store that does not answer, or refuses, the
    broker's write to `meta/judged`.
  - **Keep `broker.state_dir` across restarts, and back it up** with each broker. It holds that
    replica's copy of the marks (`marks.json`) and its record of the restore witness
    (`witness.json`). Under systemd it is a directory on the host; in a container, a named
    volume; on Kubernetes, a volume per replica that outlives the pod, never an empty
    directory. A `witness.json` restored from an older backup only weakens the check; it never
    purges wrongly.
  - **`broker.state_dir` must be the directory itself, owned by the user port49-broker runs
    as (or root), and writable by no group or other user** (0700 or 0750). A start refuses
    anything else and says why: a group-writable directory, one owned by another uid, a
    `marks.json` or `witness.json` owned by another uid or not a regular file, and a symbolic
    link (point `broker.state_dir` at its target). systemd's `StateDirectory=` and a
    container's 0700 volume pass as they are. On Kubernetes an `emptyDir` (0777) is refused,
    and so is a volume the kubelet makes group-writable for `fsGroup`. Under the default
    `fsGroupChangePolicy: Always` the kubelet does that at every mount, to every directory in
    the volume, so even a 0700 subdirectory turns group-writable and the next start is refused.
    The recipe, on a StatefulSet's volume per replica mounted at `/var/lib/port49-broker`:
    - the pod's `securityContext` sets `runAsUser: <uid>` and either no `fsGroup`, or
      `fsGroup` with `fsGroupChangePolicy: OnRootMismatch` (the kubelet then leaves the volume
      alone once its root matches);
    - an initContainer running as root makes the subdirectory:
      `install -d -m 0700 -o <uid> -g <uid> /var/lib/port49-broker/state`;
    - `broker.state_dir: /var/lib/port49-broker/state`.
  - **Keep every broker host's clock synchronised (NTP).** A replica whose clock runs behind can
    answer an idempotent replay with a token another replica's revocation or refresh deleted:
    its login fails `token_not_found`. Availability only, never an admission.
- **port49d no longer takes the keyspace.**
  - **A second port49d serves beside the first.** List several on each device, and replace them
    one at a time, a new one starting beside the old: a second systemd unit or container, or on
    Kubernetes a rolling update. 7d's advice to stop the old one first (`strategy: Recreate`) is
    withdrawn. Two on one host need their own listen address, admin_socket, metrics_listen and
    spool path, and each must see the device's true source address (design §13; L39).
  - **A login in flight while another port49d or port49-broker starts** can be denied
    `store_unavailable` once on the process that started: it was sealed below that process's
    fresh base. The user's next login is admitted.
  - **`port49_store_keyspace_held`** is 1 on the port49-broker running the start, the sweep and
    the policy refresh, and 0 elsewhere. Alert on its sum over the brokers being 0 for twice
    `hold_ttl`.
- **A broker rollout keeps everyone's tokens.** Unspent tokens are purged only when the runner
  that takes over finds a policy in force that no runner judged: an edit made while every broker
  was stopped, or while a replica served another policy.
  - A token minted in the moment of such a purge is purged too: its login fails
    `token_not_found`, and `port49 token` again works.
  - **A policy edit's settle pass deletes more than the edit's first pass.** At
    max(30s, 2 × `broker.policy_watch_interval` + 5s) after a replica swaps in an edit, the
    runner judges the tokens again, so one a slower replica minted under the replaced policy is
    deleted (Ruling 8). It deletes every unspent token minted since the first pass for each
    (principal, device) whose answer the edit changed, including tokens minted under the new
    policy: such a login fails `token_not_found`, and `port49 token` again works. Availability
    only, never an admission.
- **A broker restart on a policy file the reload guard refuses** stays not ready (`/readyz` 503)
  and takes no hold until the file is fixed. It says the guard's reason, and
  `port49_policy_file_refused` is 1.
- **Revocation lives on port49-broker's admin socket:** `port49 revoke --socket <its
  admin_socket>`. `port49 revoke`'s default stays port49d's socket (OR-1); on etcd a revocation
  sent there says which socket to use, and exits 1. port49d's socket answers `keys diagnose`. A
  `keys diagnose` sent to port49-broker's says to use port49d's. Each socket is local to its
  process: run `port49 revoke` on the broker's host, or inside its container or pod
  (`docker exec`, `kubectl exec`).
- **With every broker down, revoke offline:** `port49-broker revoke --offline --config
  /etc/port49/port49-broker.yaml --principal <p>` on a broker host. It runs the whole
  revocation through etcd, with no API.
  - With no broker host, write the mark as etcd's root (`etcdctl put
    <prefix>v1/rv/principal/<p> '{"kind":"principal","key":"<p>","at":"<now>","origin":"etcdctl"}'`).
  - Either way every port49d denies the session's next command.
- **On etcd the revocations file is retired.** etcd holds the marks, and each broker keeps a
  copy in `broker.state_dir/marks.json`. After an etcd restore:
  - stop every broker;
  - restore with `--bump-revision` and `--mark-compacted`, the restored members serving clients
    on loopback only; without them, restart every port49d too, once the first runner has said
    which marks it put back, never before;
  - there, as etcd's root, `etcdctl del --prefix <prefix>v1/t/` (a restore brings back every
    token redeemed since the snapshot, and a port49d that reaches the store first redeems it
    again), then `etcdctl del <prefix>v1/meta/judged`; only then restart the members on their
    usual client URLs;
  - start the brokers, one whose `broker.state_dir` survived the restore first.
  The first runner puts back the marks the restore lost, says how many, and purges the unspent
  tokens. Lift again anything it put back that was lifted on purpose.
  - **Meanwhile each port49d that ran across the restore keeps the marks it lost in force**, and
    names them: `port49d: store: N revocation(s) this port49d enforces are missing from the
    store as its marks feed reloads (…) and stay in force here (to release one lifted on purpose,
    revoke it again on port49-broker, then lift it with port49 revoke --lift, or restart this
    port49d): …`; a port49d dark through the restore says `… as it starts again after a
    store gone …` instead. The daemon cannot put a mark back; the runner does. A lift made on a
    broker while that port49d's marks feed was down is kept there too: restart that port49d
    (after the runner's put-back line), or revoke and lift again while its feed is up.
  - **Each port49-broker that is not the runner keeps the marks its copy holds**, and names
    them (`… are missing from the store as the marks feed reloads and stay in force on this
    replica until the runner puts them back …`), so its listener refuses those principals
    until the put-back arrives.
  - **A runner whose put-back fails before its marks reload** (its store circuit open through
    the restore) does not reload: its marks feed is down, `port49_store_feed_up{feed="marks"}`
    0, `… the marks are not reloaded until they are back`, tried again every second. While it
    is down, mints and refreshes still read the store's marks, and a revoked principal's
    contexts and tokens are revoked in the store, so logins are still refused; held connections
    on that replica are not closed by a mark made elsewhere, and lifts made elsewhere do not
    reach it until it follows the store again (final review 7e-1, re-review 2 M-12).
  - 7e-1's notes about `broker.revocations_file`'s put-back and a restarted port49d putting back
    another's lift no longer apply on etcd: the file is retired.
  - **A `meta/superseded_all` that does not decode** fails idempotent replays: delete it as
    etcd's root (`etcdctl del <prefix>v1/meta/superseded_all`), and the next purge writes it
    again.
- **With every broker stopped,** open sessions run on, a token already minted logs in, and a
  policy edit changes admission at once and live sessions when a broker returns. What each image
  does: L37.
- **A port49d with no traffic** still goes dark on a hung store, or a stopped watch: it probes
  the store every `hold_ttl`/6, through the feed fence. L37 measures how long that takes.
- **port49d's policy file is checked against the brokers'.** A port49d whose policy is not the
  bundle the runner last judged says so, and `port49_policy_bundle_matches_runner` is 0 there.
  Right after a rollout that is expected until the runner's settle pass.
- **A forgotten `etcdctl del` still purges** (the restore witness). Each broker records the
  latest `meta/witness` it saw in `broker.state_dir/witness.json`. A runner that finds the store's
  witness below that record says `the store was restored from a snapshot`, naming both
  revisions, and purges every unspent token, at a takeover or while it runs. A replica with no
  `witness.json` says it cannot tell; one whose `witness.json` cannot be read moves it aside and
  purges once. A snapshot taken within about a second of the last witness (two, if a broker was
  killed rather than stopped) is not caught. After a restore without `--bump-revision`, a later
  takeover by another broker may purge once more and say the store was restored;
  `--bump-revision` avoids it. The witness purges at the first takeover, not before: a port49d
  serving meanwhile redeems a token spent since the snapshot again, which only the runbook's
  `etcdctl del --prefix <prefix>v1/t/`, made while the restored members serve clients on
  loopback only, closes. The runbook above stays the procedure.
- **A port49d that ran across a restore refuses token logins until the runner purges** (Ruling
  19). It says `port49d: store: meta/witness is at revision N, below the M this port49d
  followed: the store was restored from a snapshot, …; every token redemption is refused
  (store_unavailable) until a broker runner's purge is done`, and
  `port49_redemption_restore_guarded` is 1. Sessions already open, revocations and the admin
  socket go on. Start the brokers: once a runner's purge is done, port49d says `the broker
  runner's purge after the restore is done; token redemptions are served again`, and users mint
  again. A port49d still guarded after a runner has purged (one that read the store only after
  the purge) is released by the next purge or by restarting it. A port49d started after the
  restore cannot tell: the runbook's token delete is what covers it.
  - **Alarm:** `port49_redemption_restore_guarded` 1 for longer than it takes to start the
    brokers.
  - **After a restore, start a broker whose `state_dir` survived first.** A broker whose
    `state_dir` was lost or is new, started first after a `--bump-revision` restore, means a
    forgotten `etcdctl del` is never caught.
- **After the runbook's delete of `meta/judged`,** the first broker start has no judged bundle
  for the reload guard, and says so: check the policy file on every broker host before
  starting them.
- **The marks put back are named** in the runner's line, up to 20. A broker that was down
  during a lift puts that mark back at each of its takeovers until the lift is made again
  while it is up. A brief watch break (a leader change, a member restart) puts nothing back:
  each watch resumes from its last progress notification, so only a gap past etcd's compaction
  retention, or a restore, reloads.
- **New alarms:** `port49_policy_bundle_matches_runner` 0 on a broker for twice
  `broker.policy_watch_interval`, and on a port49d for its settle delay and one
  `policy.watch_interval` more; `port49_ledger_behind` 1 on the runner.
- **What each device does** when one port49d replica stops, when every broker stops, and on a
  revocation from the broker: L37, per image. IOS-XE's open session once port49 is unreachable:
  L38. A Junos session's re-authorization after a port49d restart: L36.

## Self-review against the spec

Checked against the roadmap's 7e bullet, 7d's carries, and decisions 32–35:
- **The roadmap's 7e bullet.**
  - `cmd/port49-broker`: Task 15.
  - `port49d` with no broker inside: Tasks 13–14.
  - `b.superseded` into the store and bounded: Task 5.
  - `b.blobsSeen` bounded and kept per process, with the reason: Ruling 9, Task 4.
  - The emits under the hold bounded: Task 4.
  - One refresh runner: Task 15.
  - The file retired: Rulings 12, 13; Tasks 13, 15.
  - The lab on the split: Task 17.
- **7d's "Carried, for later plans", the 7e items.** Each is in the carries table with its task.
  - The marks shared: Task 9.
  - The ledger shared or replaced: Tasks 7, 8, 10.
  - More than one port49d per keyspace: Task 14.
  - The IOS-XE run: Task 17, L38.
- **`7d2-carries.md`'s 7e items.** The IOS-XE run (L38), the key-id charset (Task 3) and the
  flaky test (Task 2) are taken.
- **Decision 35's three "until plan 7e" clauses** (the broker's credential in port49d, one
  port49d per keyspace, the hold): Rulings 1, 11. Task 11 Step 2 amends each (pre-flight M12),
  and Task 11 Step 8 and Task 18 Step 3 check that no "until plan 7e" is left.
- **The 7c carries for 7e:** `/healthz` and `/readyz` (Task 15), the reload guard at start
  (Task 15a), the file's init (moot on etcd), and the per-replica bound (left unassigned, with
  its reason).
- **Spec §14:** Task 1 Step 4 and Task 11 Step 5 add the assertions, and each names its test.
- **Review Focus:** each of the sixteen lines names its test and task.
- **The pre-flight review** (`.superpowers/sdd/2026-10-03-07e-broker-process/preflight-review.md`):
  - C1 → Task 8a;
  - I1 → Task 8;
  - I2 → Task 15;
  - I3, I6 → Task 15a;
  - I4, I5 → Task 15b, with the root path in Task 16;
  - I7, I8 → Task 13;
  - I9 → Tasks 14 and 15;
  - I10 → Task 7;
  - I11 → Task 10, with the runner's reset in Task 15;
  - I12 → Task 7's test, Task 11's runbook;
  - I13 → Task 17;
  - I14 → Tasks 10, 15 and 16.
  The Minors are in the tasks they name. Revision 1 of the writer's report maps each one.
- **The re-check** (`preflight-review.md`, "Re-check"):
  - R1 → Task 8 (`rescan`, `seedFrom`), with the record wired in Tasks 10 and 15, and Ruling 3's
    gap;
  - R2 → Task 8's `TestAWatchAnswersAProgressRequest`, and Ruling 3's etcd floor;
  - R3 → Task 8a's `knownAt` comment;
  - R4 → `namedMarks` (Task 14, used by Task 15b's put-back line), and Ruling 12;
  - R5 → Task 15a's `keepDaemonBundle`;
  - the restore backstop, then R6, which replaced it → Ruling 18, Task 15c;
  - the guard after the runbook's delete → Ruling 17, Task 11's runbook step 3.
  Revision 2 of the writer's report maps each one.
- **The final review of 7e-1** (`final-review-7e1.md`, "7e-2 amendments" and its re-reviews),
  applied before Task 11 is dispatched:
  - C-1, C-2 → Rulings 5 and 12; Task 14 (`daemonReloadHook`, `Marks.Keep`), Task 15b
    (`reloadHook`, refusing the reload on a failed put-back);
  - I-1 → Rulings 5 and 12, Task 15b's negative control;
  - I-3 → every 7e-2 call on the as-built signatures (Tasks 14, 15, 15b), and the fixtures
    Task 14 Step 7 splits;
  - I-4 → the 7e-1 operator notes above;
  - M-4 → Task 11's §15 exports list; M-5 was fixed in 7e-1 (design §12), so Task 11 leaves it;
  - the ledger's carries (Task 1 m-1, m-3; Task 5 m1, m4; Task 8 M6; Task 10's floor-only
    keys; Task 9's `WatchRevocations` and listener order; Task 8a's R-1; OR-1; the deployment
    shapes) → Tasks 11, 14, 15, 15b, 17, 18 and the operator notes.
  `amend-7e2-report.md` maps each one.
- **The pre-flight of 7e-2 as amended** (`preflight-7e2.md`, P-1 to P-13):
  - P-1 → Rulings 5 and 11; Task 14 (`authMarks` is `run`'s, `keepLost` at a run after a store
    gone, `TestARestoreAcrossAStoreGoneKeepsTheDaemonsMarks`);
  - P-2 → Task 11's runbook step 2, "What the operator sees", the 7e-2 operator notes;
  - P-3 → Rulings 6 and 12; Task 15b's `reloadHook` on a non-runner replica, and its control;
  - P-4, P-5 → Task 15a (`BundleRecord.ExpiresAt`, `DeleteBundle`);
  - P-6 → Tasks 15, 15a and 15c on `s.ctxKV`;
  - P-7, P-9, P-13 → the test helpers, named and defined once;
  - P-8 → Tasks 13 and 14's Files and commits;
  - P-10, P-11, P-12 → Task 14's Produces, the anchors, Task 11's §13 and the operator notes.
  The "Pre-flight fixes" table in `amend-7e2-report.md` maps each one.
- **Placeholders.** None in the unit and e2e tests. The lab tests (Task 17) are specified cell by
  cell, as 7d's Task 15 was, since they are written against the harness at the pinned commit.
  Three of `rewinding`'s methods are "SwapLoginRev's shape", written beside it. Test helpers built
  from a file's existing fixtures are named after the real helper they build on (pre-flight
  M1). A helper still to be written is named with what it is built from.
- **Type consistency.** These names are used alike in every task that consumes them, as 7e-1
  built them (roadmap, "Interfaces 7e-1 changed"):
  - `Ledger.SetBase`, `Base`, `Observe`, `ObserveFollowed`, `Seed`, `Dirty`, `Redirty`,
    `Pending`, `Prune`, `Fence`;
  - `crypt.Fence` (`Attach`, `Followed`, `SetUp`, `Up`, `At`, `Asks`, `Wait`, `OnTimeout(fn)`,
    told each `ErrFeedBehind` for `port49_store_fence_timeouts_total`), `crypt.Fenced`,
    `crypt.ErrFeedBehind`, `crypt.ErrEarlierForm`;
  - `store.LedgerMark{Key, Seq, RevokedAt, FloorSeq, Until}`, `ContextFeed` (with `progress`
    and `asks`), `MarkFeed` (`Revocations(ctx) (uint64, []Revocation, error)`;
    `WatchRevocations(ctx, after, fn func(r Revocation, lifted bool, rev uint64), progress
    func(rev uint64))`), `MarkChange`, `LedgerSource`, `LedgerSink`
    (`PutLedgerMarks(ctx, ms) (int, error)`, how many landed);
  - `crypt.LoadLedger`, `FollowContexts`, `KeepLedger(ctx, l, sink, every, report(pending,
    behind), logf)`;
  - `store.LoadMarks(ctx, feed, m, on)`, `FollowMarks(ctx, feed, m, from, on func(MarkChange),
    up func(bool), rescanned func() error, logf)`: a `rescanned` that returns an error refuses
    the reload. Its callers: `daemonReloadHook` (port49d, Task 14), the counting hook (Task 15),
    `runner.reloadHook` (Task 15b, on every replica);
  - `store.Marks.Count(fn func(principal, cert int))`, set before the first `Set` or
    `LoadMarks`; `Marks.Pend`, `Marks.Unrecorded` (the broker's); `Marks.Keep` (Task 14:
    port49d's hook and `keepLost`, and a non-runner replica's `reloadHook`, through `r.marks`);
  - `Broker.MarkChanged(store.MarkChange)`, `Broker.Say`, `RefreshTokens`;
  - port49d's `startOnPersistentStore(ctx, brk, st, e, cfg, &marks, m)` (7e-1, which Task 15
    renames `takeover`), `restoreRevocations(ctx, st, path)`, `persister(st, path, held,
    enforced, m)`, `putBackFileMarks(ctx, st, path, enforced)` (memory's file, tests only since
    Task 14), and `unopenableSayer(prefix, keys, out, now)` (Task 15);
  - `daemonReloadHook(ctx, feed, enforced, rescans, bound, out)`, `keepLost(ctx, feed, enforced,
    bound, when, out) error`, `namedMarks` (Task 14); `authMarks` is `run`'s (Task 14);
    `putBackMissing`, `restoreMarks`, `reloadHook(ctx, rescans)`, `sayPutBack`,
    `marksReloaded chan struct{}` (Task 15b);
  - the fixtures `etcdSplitServerWith(t, policyBody, others)`, `etcdSplitServer`, `etcdSplit`
    (Task 14), `etcdSplitServerOpts`, `splitFleetProgress` (Task 15b), and 7e-1's
    `sharedUsernamePolicy` (bob a second identity of alice's subject), `mintAs`,
    `waitForLedgerSeq`, `restore`, `etcdtest.Proxy.Drop`, `etcdtest.Options.ProgressNotify`;
  - the test helpers the pre-flight of 7e-2 settled: `startSplitDaemon`, `startSplitDaemonStop`,
    `copyDaemon(t, cfg)` (Task 14); `f.copyDaemon`, `f.copyBroker`, `mintOn`, `f.editPolicy`,
    `retryCtx`, `sleepCtx`, `orNone` (Task 15); `readyzAt(t, addr)` (Task 15a); and the
    package's own `waitUntil(t, what, cond)`, `startDaemon`, `readyz(t, out)` and
    `heldBrokerConn(t, pkiDir, addr)`, which stay;
  - the runner's fields `copy`, `marks` (the replica's `store.Marks`) and `marksReloaded`
    (Task 15b);
  - `etcd.Store.Seen`, `Judged` (`JudgedRecord`), `PutJudged(ctx, bundle, policy)`,
    `PutBundle`, `DeleteBundle`, `Bundles` (`BundleRecord.ExpiresAt`), `Holder`, `PutRefreshOwed`,
    `RefreshOwed`, `ClearRefreshOwed`, each on `s.ctxKV` (Ruling T6-a);
  - `config.LoadBroker`, `Config.Policy`, `RoleBroker`, `StoreBlocks`;
  - `sweepLoop(ctx, s, brk, ledger, every, out)`, `recordJudged`, `guardAtStart`, `keepBundle`,
    `offlineRevoke`;
  - `FollowContexts(ctx, feed, src, keys, l, from, up, rescanned, logf)`, `rescan`, `seedFrom`;
  - `etcd.WitnessRead`, `Store.Witness`, `PutWitness`, `FollowWitness`;
    `etcdtest.Server.Backup`, `Restore`;
  - `keepDaemonBundle`, `stores.judged`, `witnessRecord` (`openWitness`, `Saw`,
    `Recorded`, `Reset`, `keep`), `restored`, `readWitness`, `keepWitness`, `witnessPass`,
    `purgeRestored`.

