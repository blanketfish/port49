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
    `WatchContexts`); and, at the start, the ledger record (`lw/`).
- **The runner.**
  - **The hold.** It takes plan 7d's hold (`meta/hold`) as the broker. On taking it, it runs
    plan 7d's start: the seal keys, the re-index, the marks on the kept contexts, the purge
    (only when the bundle in force is not the one last judged), and the carry. Then it runs
    the sweep, the ledger keeper and the context half of every refresh pass.
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
  - **Tasks 6–10:** the write sequence, the ledger, the feeds and the ledger record.
  - **What changes for an operator in 7e-1:**
    - a context sealed by 7d (form 3) no longer opens, so an etcd store's live sessions end at
      the upgrade;
    - a context put back while port49d was stopped is denied after a restart, for every key the
      ledger record holds;
    - two new metrics.
  - No device-visible behaviour changes, so there is no lab.
- **7e-2, `feature/broker-split`, off `main` after 7e-1 merges.** The two processes.
  - **Task 11:** the docs for what 7e-2 builds, and L37 and L38 opened.
  - **Task 12:** the move into `internal/port49d`.
  - **Tasks 13–16:** the config, port49d without a broker, port49-broker, and the fleet end to
    end.
  - **Task 17:** the lab, which gates the merge.
  - **Task 18:** the as-built docs.

**Why split.** Eighteen tasks is above 7d's sixteen.
- **What each half risks is different.** 7e-1 is correctness against properties, with no new
  process. 7e-2 is operational, and L37 gates it.
- **A reviewer can reject one and approve the other.** The ledger change is the one most worth
  its own review.
- **7e-2 is written against 7e-1's interfaces**, which this plan fixes. If 7e-1's review changes
  one, the controller amends 7e-2's tasks before dispatching Task 11, and says so in the ledger.

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
     - **A key with no entry** admits a record at or above the ledger's **base**, the revision
       after the start's scan (Ruling 4). Any record that existed then was scanned, and
       anything sealed since is above it.
     - **Below the high-water** is denied `store_unavailable`, as 7d denies a record that is not
       the one last written (`crypt.ErrNotLastWritten`, kept).
     - **A read that raced a write** is read again (`stale`), up to twice, as 7d does: its
       revision is below the high-water's.
   - **What it fixes.** Another process's later login at a key is admitted: its sequence is
     higher. An earlier record put back is denied: its sequence is lower. With a per-process
     ledger, the first would deny every other replica's logins (re-check IA1).
   - **Simpler than 7d's.** 7d's writes in flight, unknown outcomes and the two restore cases
     (Tasks 6b, 13b; 79812ef, 3159dbc) all fall out of the rule.
     - A write of unknown outcome that landed has the higher sequence. One that did not left
       the record the high-water names.
     - After a restore, with or without `--bump-revision`, `Seen()` never goes back, so a write
       after it seals above every earlier record. A record the restore brought back is below
       the high-water and is denied, as 7d measured (L35).
   - **The revocation floor** (7d final review I-1) stays.
     - Each process also takes a floor from the feed: a change at a key whose plaintext
       `revoked_at` is set, at the high-water's sequence.
     - So a seal that failed on one replica is held on every replica that saw the plaintext
       mark land.
   - **Memory.** An entry is kept while a record it saw could still be live: until the latest
     sealed ceiling it saw at the key, plus `session.grace_window`. A `never` context's entry is
     kept for good. Past that a record put back is past its sealed ceiling, which the
     authorizer denies anyway (`Ledger.Prune`, run with the sweep).
   - **Migration.** A form-3 record does not open. On etcd every live session ends at the
     upgrade: it is denied, replaced at the next login, and revoked by the refresh as tampered,
     as 13b did to form 2. Tokens are purged at a start that changes the bundle anyway. The
     memory store loses everything at the restart that installs it.
4. **The ledger record, `lw/<nas>/<user>`, kept by the runner alone.**
   - **What it holds.** Per key, `{seq, revoked_at, until}`.
   - **Who writes it.** The runner, about once a second, from its own ledger. Every write
     raises and never lowers, by a compare on the record's revision. Its lease runs to `until`
     plus `lease_grace`, with none for a `never` context.
   - **Who reads it.** Every process seeds its ledger from it at start, before it scans `c/`. A
     scanned record below its key's mark is a put-back, and is denied.
   - **What the daemon's role can do to it.** Read it, never write it. Without it, a port49d
     started after a put-back would take the record put back as the key's (7d's restart
     residual), and with many replicas restarting in turn, that would be every rollout.
   - **The residual it leaves:**
     - a key written within the keeper's lag (a second, and a store round trip) and put back
       inside it;
     - a key written while no runner ran, put back before a runner recorded it.
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
   - **A lagging feed opens nothing.** A revocation marks every context record it reaches (7a),
     and the mint path reads the store's marks itself. A lagging feed only delays the
     in-memory copy, which is defence against a put-back.
   - **A compacted watch** loads the marks again and applies the difference.
6. **The runner.** The keyspace hold of 7d's Ruling 11 is now the runner's: one port49-broker
   per keyspace at a time.
   - **On taking it,** with the API already serving:
     1. it records the seal keys (`meta/seal_keys`);
     2. re-indexes every kept context the index lost;
     3. applies every standing mark to the kept contexts;
     4. purges the unspent tokens, only by Ruling 7;
     5. carries the policy in force into every kept context.
   - **Then it runs:**
     - the sweep and the re-index every `sweep_interval`;
     - the ledger keeper (Ruling 4);
     - the context half of every refresh pass, which records quarantines as before;
     - `meta/judged` (Ruling 7) whenever its `port49_policy_refresh_pending` reaches 0.
   - **Every replica, runner or not:**
     - serves the API and the admin socket;
     - runs the token half of its own reload's passes (Ruling 8);
     - runs certificate status and its revocation queue (a mark is idempotent);
     - follows the marks and the contexts.
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
7. **The token purge happens when the bundle changed hands unjudged**, not at every start.
   - **`meta/judged`** is the bundle in force when the runner's last pass left
     `port49_policy_refresh_pending` at 0, so every token minted under an earlier bundle was
     judged against it.
   - **At a takeover** a runner whose bundle in force differs (an edit made with no runner, or a
     runner that died before its settle pass) purges every unspent token. It writes
     `meta/superseded_all` with the instant, so an idempotent replay on any replica mints
     afresh.
   - **Otherwise it purges nothing.** A rolling restart of the brokers does not make every
     operator run `port49 token` again.
   - **Memory.** A start still purges as before; its store is empty anyway.
8. **The settle pass covers a replica that reloads late.**
   - **The delay** is `max(30s, 2 × policy_watch_interval + 5s)` after a swap.
   - **The priors.** The reloader keeps the priors it has had since the last settled pass until
     that settle pass completes, instead of resetting them after the first complete pass.
   - **What that catches.** A token another replica minted under the replaced policy before it
     reloaded is judged by the runner's settle pass, and by that replica's own token pass.
   - **The residual.** A replica that reloads later than the settle pass, which only a
     `policy_watch_interval` differing between replicas can cause. Task 13 refuses nothing for
     it; the operator note says to set the same interval everywhere.
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
     - Forgetting costs one duplicate `blob` record.
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
    - **A run after a store gone** keeps the ledger and the marks, which are the process's.
    - **Live sessions survive a restart,** as in 7d.
    - **The policy.** port49d reloads its policy file live, for admission, quarantine and
      redaction, and carries nothing into live contexts: that is the broker's (design §6).
      Broker down, a reload changes admission at once and live contexts at the next runner's
      pass.
12. **`broker.revocations_file` is retired on etcd.**
    - **Why it is not needed.** The store persists the marks, and since plan 7d every start
      has put the file's marks into it, so a 7d deployment's marks are all in etcd already.
    - **What replaces it.** `broker.state_dir` holds the persisted CRLs. The file, its marker
      and `port49d init-revocations` stay for the memory store.
    - **A restore.** A restored etcd snapshot rolls the marks back, and the operator re-applies
      revocations made since the snapshot. The file no longer puts them back; the runbook
      changes (Task 18).
13. **The admin sockets.**
    - **port49-broker's** answers `revoke`, `lift` and `list`.
    - **port49d's** answers `keys diagnose`. When it runs no broker, a `revoke` or a `list`
      there is answered "port49d runs no broker; revocation is port49-broker's admin socket (its
      `admin_socket`): run `port49 revoke --socket <that path>`". That is an error, so the
      client exits 1.
14. **`store-roles` reads both files:** `port49d store-roles --config port49d.yaml
    --broker-config port49-broker.yaml`.
    - **The daemon's role** gains read on `lw/`, and never touches `sp/`. `CheckIdentity`
      probes that the daemon is refused a write to `lw/` and any access to `sp/`.
    - **The output** gains one grant line, the daemon's read on `lw/`.
    - **On memory** it is refused, as it is today.
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

### Open for Ryan

**OR-1. `port49 revoke`'s default `--socket`.** It is `/run/port49/port49d.sock`, and on etcd
revocation now lives on port49-broker's socket. Ruling 13 makes port49d's socket say which
socket to use, so nothing is revoked silently in the wrong place. There is no anti-escalation
default either way.
- **Recommended: keep the default.** A memory-store install keeps working unchanged, and an
  etcd install passes `--socket`, which the line names.
- **The alternative** probes both paths, and an operator could not tell which process answered.
- **The plan proceeds on the recommendation.**

**Worth reading before the merge** (rulings, not open questions):
- **Ruling 1.** On etcd, port49d.yaml with a `broker:` block is refused. A 7d deployment on etcd
  must move its `broker:` block into `port49-broker.yaml` and start `port49-broker` beside
  port49d.
- **Ruling 3.** The upgrade from 7d to 7e on etcd ends every live session once (form 3 does not
  open). Users log in again.
- **Ruling 7.** Unspent tokens survive a broker rollout now. They are purged only when the
  bundle in force changed with no runner to judge the tokens minted under it.
- **Ruling 11.** On etcd port49d no longer takes the keyspace. A second port49d serves beside the
  first, and Kubernetes' `strategy: Recreate` advice is withdrawn for port49d. It moves to
  nothing: port49-broker's replicas share the runner's hold.
- **Ruling 12.** On etcd the revocations file is gone. Back etcd up, and after a restore re-apply
  the revocations made since the snapshot.

## What the operator sees

The owner's rule: trace a mechanism on a bad day first. Every line below is printed by a task
in this plan, and the tests named pin it.

- **Install, on etcd.**
  - Run `port49d store-roles --config /etc/port49/port49d.yaml --broker-config
    /etc/port49/port49-broker.yaml` and apply its output once, as etcd's root (one grant more than 7d's: the daemon's read on `lw/`).
  - Start one or more `port49-broker --config /etc/port49/port49-broker.yaml`, then one or more
    `port49d`, in either order.
  - A 7d port49d.yaml with a `broker:` block on etcd stops with:

    ```
    port49d: config: store.backend: etcd runs the broker as its own process (plan 7e): move the broker: block,
    with store.etcd.broker, into port49-broker.yaml and start port49-broker; name the policy port49d admits from
    under policy: (file, watch_interval)
    ```
- **A port49-broker start:**

  ```
  port49-broker: store: the broker's etcd certificate (CN=port49-broker) is valid until 2027-10-01T00:00:00Z (362 days)
  port49-broker: 3 revocation(s) in force from the store
  port49-broker: ledger: 1204 context key(s) known (1190 from the ledger record); following the store from revision 88213
  port49-broker: listening on 0.0.0.0:8443, metrics on 0.0.0.0:9050
  port49-broker: runner: took keyspace /port49/ ("port49-broker on brk-a (pid 4121, since 2026-10-04T09:00:00Z)"): this replica runs the start, the sweep and the policy refresh
  port49-broker: runner: 3 standing revocation(s) applied to the live contexts the store kept (0 context(s) marked revoked)
  port49-broker: runner: the bundle in force (b3f9…) is the one the last runner judged; no unspent token purged
  port49-broker: runner: 1204 live context(s) carried onto the policy in force (bundle b3f9…)
  ```

  A second replica says, instead of the runner's lines, and every 30s:

  ```
  port49-broker: runner: keyspace /port49/ is run by "port49-broker on brk-a (pid 4121, since 2026-10-04T09:00:00Z)"; this replica serves the API and takes over if that one stops
  ```
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
  was compacted; scanning the store again` once, and `port49_store_feed_rescans_total{feed}`
  counts it. `port49_store_feed_up{feed}` is 0 while a feed re-establishes.
- **The ledger record lagging:** `port49_ledger_pending` on the runner is the number of keys
  whose high-water the record does not yet hold. Above 0 for a minute is an alarm: a put-back
  there would survive a restart.
- **New metrics:** `port49_store_feed_up{feed}`, `port49_store_feed_rescans_total{feed}` (`feed`
  is `contexts` or `marks`), and `port49_ledger_pending`.
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
  high-water or removes a floor.
- **The daemon's role never writes `lw/`, `sp/`, `rv/` or `meta/`.** `etcd.Roles` and
  `CheckIdentity` say so, and a test grants one and is refused.
- **The code blocks are written against `b508ba0`.** Where the compiler or a test says a block is
  wrong about the tree or about etcd's API, fix the block minimally, keep the behaviour the
  step's test asserts, and say so in the task's report and commit. Never weaken a test to make a
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
   seen the write.** It is admitted, never denied as an unseen key. The record's sequence is
   above the second's base, and above any high-water it knows at the key. *Task 7,
   `TestAnotherProcesssWriteIsAdmittedBeforeItsFeedArrives`; Task 16,
   `TestALoginOnOneDaemonIsAnsweredOnAnother`.*
2. **A record put back on one replica while another replica, or a port49d started later, reads
   it.** The running replicas deny it once their feed has passed the later write. A port49d
   started after the put-back denies it from the ledger record. *Task 8,
   `TestTheFeedRaisesTheHighWaterSoAPutBackIsDenied`; Task 10,
   `TestAStartSeededFromTheLedgerRecordDeniesAPutBack`; Task 16,
   `TestAPutBackBeforeADaemonStartsIsDenied`.*
3. **A revocation made on one broker replica, while the agent holds a connection to another.**
   The other closes it, and every port49d denies the session's next command. *Task 9,
   `TestAMarkFromTheFeedClosesThisReplicasHeldConnections`; Task 16,
   `TestARevocationOnOneBrokerReachesTheOther`.*
4. **The runner killed mid-pass, and a runner paused past its fence.** Another takes the hold
   within `hold_ttl` and a third. It purges only when the bundle changed unjudged, and two
   runners for a moment write nothing wrong. *Task 15, `TestARunnerThatStopsIsReplaced`,
   `TestATakeoverPurgesOnlyAnUnjudgedBundle`.*
5. **A log sink that stalls during a mint.** A reload still swaps within a second, and the
   mint's records land in order once the sink drains. *Task 4,
   `TestAStalledLogNeverHoldsAReload`, `TestEveryMintRecordFollowsItsBlobRecord`.*
6. **An etcd restore under running processes, with and without `--bump-revision`.** A login
   after it is admitted on every replica, and a restored record is denied. *Task 7,
   `TestALoginAfterARestoreIsAdmitted`.*
7. **A watch whose revision was compacted.** The feed scans again. It only raises, so nothing
   is admitted that the scan before would have denied, and the rescan is counted. *Task 8,
   `TestACompactedFeedScansAgainAndOnlyRaises`; Task 9, `TestACompactedMarkFeedReloadsTheDifference`.*
8. **The daemon given the broker's reach on `lw/` or `sp/`.** port49d refuses to start. *Task 10,
   `TestCheckIdentityRefusesADaemonThatCanWriteTheLedgerRecord`.*
9. **A port49d.yaml naming the broker's identity, or a port49-broker.yaml naming `keys:`.** Each
   is refused at load, naming the key. *Task 13, `TestTheDaemonsConfigNeverNamesTheBrokersIdentity`,
   `TestTheBrokersConfigNeverNamesADeviceKey`.*

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
docs/design/2026-08-23-policy-engine-spec.md   MOD  d36 (7e-1 part), d35 amended (the ledger), §5.1.4 (Task 1); d36 (7e-2 part),
                                                    d32 and d34 amended (the file, the sockets), §5.1.3, §12, §14, L37 and L38
                                                    opened (Task 11); L36, L37, L38 measured (Task 17)
docs/design/2026-08-21-port49-design.md        MOD  §8 the ledger, §12 store interface (Task 1); §6, §12 matrix, §13, §15, §17,
                                                    §19 (Task 11); device cells (Task 17)
internal/store/etcd/etcdtest/etcdtest.go       MOD  StartCluster retries until a deadline (Task 2)
internal/store/etcd/etcdtest/etcdtest_test.go  MOD  (Task 2)
internal/config/config.go                      MOD  KeyIDShape (Task 3); Role, Policy, LoadBroker, key_refs, state_dir, the
                                                    refusals (Task 13)
internal/config/config_test.go                 MOD  (Task 3)
internal/config/broker_test.go                 NEW  (Task 13)
internal/decision/buffer.go, buffer_test.go    NEW  Buffer (Task 4)
internal/token/minter.go, minter_test.go       MOD  Request.Log (Task 4)
internal/broker/broker.go, broker_test.go      MOD  the buffered request, putBlob, bounded blobsSeen (Task 4); supersede in the store,
                                                    SupersededAll removed (Task 5); MarkChanged (Task 9)
internal/broker/refresh.go, refresh_test.go    MOD  supersede (Task 5); RefreshTokens (Task 15)
internal/broker/revoke.go, revokeown.go        MOD  supersede(ctx, …) (Task 5)
internal/store/store.go                        MOD  SupersedeTokens, SupersededAt, SupersedeAll, SupersededFor (Task 5); RevStore.Seen,
                                                    RevStore.Ping (Task 6); LedgerMark (Task 7); ContextChange, ContextFeed, ErrCompacted,
                                                    LedgerSource, LedgerSink (Task 8); MarkFeed (Task 9)
internal/store/marks.go, marks_test.go         MOD  Marks.All; LoadMarks, FollowMarks (Task 9)
internal/store/memory/memory.go, _test.go      MOD  superseded (Task 5); Seen, Ping (Task 6)
internal/store/etcd/keys.go                    MOD  famSuperseded sp/ (Task 5); famLedger lw/ (Task 10)
internal/store/etcd/superseded.go              NEW  (Task 5)
internal/store/etcd/etcd.go, contexts.go       MOD  seen, Seen, every context response observed (Task 6)
internal/store/etcd/feed.go, feed_test.go      NEW  ScanContexts, WatchContexts (Task 8); Revocations, WatchRevocations (Task 9)
internal/store/etcd/ledger.go, ledger_test.go  NEW  LedgerMarks, PutLedgerMarks (Task 10)
internal/store/etcd/roles.go, roles_test.go    MOD  sp/ never, lw/ read for the daemon; probes (Task 10)
internal/store/etcd/meta.go, meta_test.go      MOD  Judged, PutJudged, SupersededAll's record (Task 15)
internal/store/etcd/etcd_test.go               MOD  the restore test on the new ledger (Task 7)
internal/store/guard/guard.go, guard_test.go   MOD  the three new methods routed (Task 5); Seen, Ping (Task 6)
internal/store/crypt/crypt.go                  MOD  form 4, seq, the ledger on reads and writes (Task 7); supersede pass-through (Task 5)
internal/store/crypt/ledger.go                 MOD  rewritten: high-water, base, floor, prune, dirty (Task 7)
internal/store/crypt/follow.go, follow_test.go NEW  LoadLedger, FollowContexts (Task 8); KeepLedger (Task 10)
internal/store/crypt/crypt_test.go             MOD  the ledger's tests on the new rule (Task 7)
internal/store/storetest/superseded.go         NEW  SupersededIsTheLaterAndExpires (Task 5)
internal/store/storetest/storetest.go          MOD  Run lists it (Task 5)
internal/daemon/metrics/metrics.go, _test.go   MOD  store_feed_up, store_feed_rescans_total, ledger_pending (Tasks 8, 10)
cmd/port49d/store.go, main.go                  MOD  the feeds and the keeper wired, Seal replaced by the base (Tasks 8–10)
cmd/port49d/store_e2e_test.go                  MOD  the put-back test on the record (Task 10)
cmd/port49d/*.go → internal/port49d/*.go       MOV  package port49d (Task 12)
cmd/port49d/main.go                            NEW  the shim (Task 12)
cmd/port49-broker/main.go                      NEW  the shim (Task 15)
internal/port49d/daemon.go                     NEW  the daemon's start on etcd, the probe (Task 14)
internal/port49d/brokerd.go, runner.go         NEW  runBroker, the runner (Task 15)
internal/port49d/reload.go                     MOD  live, log, refresher; the settle's priors (Tasks 14, 15)
internal/port49d/storeroles.go                 MOD  --broker-config (Task 16)
internal/port49d/split_e2e_test.go             NEW  the fleet end to end (Task 16)
internal/daemon/admin/admin.go                 MOD  NoBroker's answer (Task 14)
Makefile                                       MOD  build port49-broker (Task 15)
tests/lab/split_test.go                        NEW  L37, L38, L36 (Task 17)
tests/lab/harness_test.go                      MOD  startSplit, the second replica's address (Task 17)
tests/lab/topologies/*                         MOD  a second TACACS+ server on each device (Task 17)
tests/lab/results/L36-*, L37-*, L38-*.md       NEW  written by the run (Task 17)
docs/superpowers/plans/README.md               MOD  7e written (this commit); 7e-1 as built (Task 10 Step 7); 7e as built (Task 18)
```

Eighteen tasks in two merges:
- **7e-1:** Task 1 is docs, first; Tasks 2–3 are carried fixes; Task 4 is the emits; Tasks 5–10
  are the store and the ledger.
- **7e-2:** Task 11 is docs, first; Task 12 is a move with no behaviour change; Tasks 13–16 are
  the processes; Task 17 is the lab and gates the merge; Task 18 is the as-built docs.

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
ledger record, the feeds, `superseded` in the store, the emits, and the key-id charset. The two
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
    contexts: anything at a key then was scanned, and anything sealed since is above it. A read
    that raced a write is read again, up to twice. Another process's later login is therefore
    admitted, and an earlier record put back is denied, whichever process wrote either. A write of
    unknown outcome needs nothing more: if it landed it is the higher, and if not, the record the
    mark names is still the store's. After an etcd restore, with or without `--bump-revision`, a
    write seals above every earlier record, so a login is admitted and a restored record is
    denied.
  - **Every process follows the store's contexts.** After its start's scan it watches the context
    family from that revision. Each change raises the key's mark, never lowers it. A plaintext
    `revoked_at` at the mark's sequence is the key's revocation floor, cleared only by a later
    sequence, so a revocation whose seal failed holds on every process that saw its mark land. A
    watch whose revision was compacted scans again, raising only. A mark is kept while a record it
    saw could be live: to the latest sealed ceiling seen at the key and `session.grace_window`,
    and for good for a `never` context.
  - **The ledger record.** The process that holds the keyspace writes each key's mark, its
    revocation floor and how long to keep it to `lw/<nas>/<user>`, about once a second, raising
    only, by a compare on the record's revision. The daemon's etcd role reads it and never writes
    it. Every start seeds its ledger from it before it scans, so a record put back while every
    process was stopped is denied at its key when the record holds a later mark there. Left: a
    key written and put back within the record's lag, about a second, or while no process held
    the keyspace and before one recorded it.
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

- [ ] **Step 3: §5.1.4's residual window.** In §5.1.4, find the paragraph that names the
  revocation floor (search `revocation floor`). After it, add:

  ```markdown
  With several port49d processes on one store (plan 7e), each holds the floor of every
  revocation whose plaintext mark it saw land, through the store's context feed, not only of the
  revocations it made (§13, decision 36).
  ```

- [ ] **Step 4: §14's ledger assertions.** In §14, under "Shared store", replace the bullet that
  begins `- **The ledger**: another login's context written back at a key is denied` with:

  ```markdown
  - **The ledger**: another login's context written back at a key is denied, and so is an
    earlier version of the same context put back after a later write landed, whichever process
    made either. Another process's later write at a key is admitted, before and after this
    process's feed has seen it. A key with no mark admits only a record sealed past the start's
    scan. A process started after a put-back denies it when the ledger record holds a later mark
    at the key. A login after an etcd restore, with or without `--bump-revision`, is admitted,
    and a restored record is denied. A form-3 context does not open.
  - **The feeds**: a context change raises its key's mark and never lowers it; a plaintext
    revocation at the mark's sequence is a floor a put-back cannot clear; a compacted watch
    scans again. A mark landing on one process closes that process's held connections it names,
    and a lift removes it.
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
    context, written back. A key it has no mark for admits only a record sealed past its start's
    scan. The process holding the keyspace keeps each key's mark in a ledger record the daemon's
    etcd role cannot write, and every start is seeded from it (policy engine spec §13, decision
    36).
  ```

  In the paragraph after it (`- **What store write access still yields is replay**`), replace
  `before the start's reads seal the ledger, the first record read at a key it has not seen is
  admitted, so another login's context put back while port49d was stopped is taken as that key's`
  with `a start admits the record at a key the ledger record holds no later mark for, so another
  login's context put back while every port49d was stopped, at such a key, is taken as that
  key's`. Leave the rest of the sentence.

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
  it only raises what a read must clear.
  ```

- [ ] **Step 7: Check the edits.** Run:

  ```bash
  grep -c '^\*\*36\. ' docs/design/2026-08-23-policy-engine-spec.md
  grep -n 'Amended by decision 36' docs/design/2026-08-23-policy-engine-spec.md
  grep -n 'whichever process' docs/design/2026-08-23-policy-engine-spec.md
  grep -n 'Following the store (plan 7e)' docs/design/2026-08-21-port49-design.md
  grep -n '| ledger record |' docs/design/2026-08-21-port49-design.md
  ```

  Expected: `1`, then one line each.

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
  Expected: FAIL. `TestStartClusterRetriesAPortTaken` reports `12 ports picked` (one retry), and
  `TestStartClusterGivesUpAtItsDeadline` fails to compile on `clusterRetryFor`.

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

- [ ] **Step 1: The failing test.** Add to `internal/config/config_test.go` (the helpers
  `writeConfig`, `baseYAML` and `setEnv` are the file's own; use whatever the file names its
  fixture builder and environment setter, and say so in the report):

  ```go
  // An encryption key id is sealed into every record's header and named by
  // every line about one that will not open, which prints only the key-id
  // charset (crypt.LineKeyID). One outside it is refused at load, naming the
  // block and never echoing the id (plan 7e, Ruling 15).
  func TestAnEncryptionKeyIDOutsideTheCharsetIsRefused(t *testing.T) {
  	for _, id := range []string{"has space", "semi;colon", "émoji", strings.Repeat("a", 65), "new\nline"} {
  		t.Run(fmt.Sprintf("%q", id), func(t *testing.T) {
  			setEnv(t, "PORT49_ENC_V1", strings.Repeat("k", 32))
  			raw := strings.Replace(baseYAML, "id: v1", fmt.Sprintf("id: %q", id), 1)
  			_, err := Load(writeConfig(t, raw))
  			if err == nil || !strings.Contains(err.Error(), "encryption.current: id must be 1 to 64 of") {
  				t.Fatalf("an id %q loaded, or the refusal does not say why: %v", id, err)
  			}
  			if strings.Contains(err.Error(), id) {
  				t.Fatalf("the refusal echoes the id: %v", err)
  			}
  		})
  	}
  	for _, id := range []string{"v1", "2026-10.key_A", strings.Repeat("a", 64)} {
  		setEnv(t, "PORT49_ENC_V1", strings.Repeat("k", 32))
  		raw := strings.Replace(baseYAML, "id: v1", "id: "+id, 1)
  		if _, err := Load(writeConfig(t, raw)); err != nil {
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

  In `Load`'s loop over `encryption.current` and `encryption.previous`, after the `if k.ref.ID
  == ""` refusal, add:

  ```go
  		if !KeyIDShape.MatchString(k.ref.ID) {
  			// Not printed: whatever the operator wrote, a line must not carry it.
  			return Config{}, fmt.Errorf("config: %s: id must be 1 to 64 of A-Z a-z 0-9 . _ -: it is written "+
  				"into every record the key seals, and every line about a record that will not open names it", k.what)
  		}
  ```

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

- [ ] **Step 2: The failing tests, the broker.** Add to `internal/broker/broker_test.go`. Use the
  file's own fixture (`newTestBroker` or whatever builds a `*Broker` with a policy, a minter and a
  memory store, and `mintRequest` or the helper that drives `tokens` over `httptest`), and name
  them in the report:

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
  	b := newTestBroker(t)
  	b.Log = sink
  	b.Minter = token.NewMinter(b.Store, sink, rand.Reader, testTagKey, b.Now, 8)
  	done := make(chan *httptest.ResponseRecorder, 1)
  	go func() { done <- mintRequest(t, b, "leaf1") }()
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
  func TestEveryMintRecordFollowsItsBlobRecord(t *testing.T) {
  	var buf bytes.Buffer
  	b := newTestBroker(t)
  	b.Log = decision.NewJSONLines(&lockedWriter{w: &buf})
  	b.Minter = token.NewMinter(b.Store, b.Log, rand.Reader, testTagKey, b.Now, 8)
  	var wg sync.WaitGroup
  	for i := 0; i < 8; i++ {
  		wg.Add(1)
  		go func() { defer wg.Done(); mintRequest(t, b, "leaf1") }()
  	}
  	wg.Wait()
  	seen := map[string]bool{}
  	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
  		var r map[string]any
  		if err := json.Unmarshal([]byte(line), &r); err != nil {
  			t.Fatal(err)
  		}
  		switch r["event"] {
  		case decision.EventBlob:
  			seen[r["blob"].(map[string]any)["hash"].(string)] = true
  		case decision.EventMint:
  			if pol, _ := r["policy"].(map[string]any); pol != nil {
  				for _, h := range blobHashesOf(r) {
  					if !seen[h] {
  						t.Fatalf("a mint record names blob %s before any blob record for it:\n%s", h, buf.String())
  					}
  				}
  			}
  		}
  	}
  }

  // blobsSeen forgets every hash once it holds blobsSeenMax, so a policy
  // rewritten on a schedule cannot grow it without bound (4b m10): the next
  // mint of a forgotten hash writes its blob record again, which replay reads
  // as a duplicate.
  func TestBlobsSeenIsBounded(t *testing.T) {
  	b := newTestBroker(t)
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

  `lockedWriter` (an `io.Writer` with a mutex) and `blobHashesOf` (the blob hashes a mint record
  names, from its `mint.blobs` or `policy` field, as the decision log's schema writes them) are
  test helpers. Add them to the file if it has none, and say which field the schema uses.

- [ ] **Step 3: Run them to see them fail.**

  Run: `go test ./internal/decision/ ./internal/broker/ -run 'Buffer|Stalled|FollowsItsBlob|BlobsSeenIsBounded' -count=1`
  Expected: FAIL. `NewBuffer`, `markBlob`, `blobSeen` and `blobsSeenMax` are undefined, and once
  they compile, the reload is held.

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
  // (plan 7e, Ruling 9). The broker's role alone writes or reads it.
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
  // A key superseded on one broker process makes an idempotent replay on
  // another mint afresh: the instant is in the store (plan 7e, Ruling 9).
  func TestASupersededKeyReplaysAfreshOnAnotherBroker(t *testing.T) {
  	a, b := twoBrokersOneStore(t) // two *Broker on one memory store, each with its own minter
  	first := mintKeyedOn(t, a, "leaf1", "k1")
  	a.supersede(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"}, a.Now())
  	again := mintKeyedOn(t, b, "leaf1", "k1")
  	if again == first {
  		t.Fatal("another broker answered a superseded key's replay with the deleted token")
  	}
  }

  // A store that fails the read of the superseded instant refuses the item
  // store_unavailable rather than risk handing back a deleted token.
  func TestAnUnreadableSupersededInstantRefusesTheItem(t *testing.T) {
  	b := newTestBroker(t)
  	b.Store = &failSuperseded{Store: b.Store}
  	rr := mintKeyedRequest(t, b, "leaf1", "k2")
  	if !strings.Contains(rr.Body.String(), `"store_unavailable"`) {
  		t.Fatalf("%d %s", rr.Code, rr.Body)
  	}
  }

  type failSuperseded struct{ store.Store }

  func (f *failSuperseded) SupersededAt(context.Context, store.TokenKey) (time.Time, error) {
  	return time.Time{}, store.ErrUnavailable
  }
  ```

  `twoBrokersOneStore`, `mintKeyedOn` and `mintKeyedRequest` are built from the file's existing
  fixture. Name them in the report.

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
  	s := newEtcdStore(t) // the file's helper: a store on the shared member with a fresh prefix
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
  	s := newEtcdStore(t)
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

  In `guard_test.go`, the routing test's method list reads `store.RevStore`'s methods. Add
  `TestSeenPassesThroughAndPingIsTheContextPools`: `Seen` through the guard returns the inner's
  value, and `Ping` on an inner that fails counts one `context` pool failure.

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
  func (g *guardedRev) Seen() uint64 { return g.inner.Seen() }

  func (g *guardedRev) Ping(ctx context.Context) error {
  	return g.do(ctx, Context, func(ctx context.Context) error { return g.inner.Ping(ctx) })
  }
  ```

  (Use the `RevStore` wrapper's real type and field names at `b508ba0`.) Every test double that
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
- Modify: `internal/store/crypt/crypt_test.go` (the ledger's tests, listed below)
- Modify: `internal/broker/ledger_test.go`, `internal/store/etcd/etcd_test.go:284-357`
- Modify: `cmd/port49d/main.go:859`, `cmd/port49d/store.go:741` (`Seal` replaced)

**Interfaces:**
- Consumes: `store.RevStore.Seen()` (Task 6).
- Produces (`crypt`):
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
| `TestAReadRacingAWriteOfTheSameContextReadsAgain` | kept |
| `TestAContextOfFormTwoDoesNotOpen` | becomes `TestAContextOfFormThreeDoesNotOpen` (form 2 too) |
| `TestTheLedgerForgetsAKeyTheStoreNoLongerHolds` | replaced by `TestADeletedKeyKeepsItsMark` (stronger: a put-back after a delete is denied) and `TestTheLedgerPrunesAKeyPastItsKeep` |
| `TestASealedLedgerAdmitsNoUnseenKey` | becomes `TestARecordSealedBeforeTheBaseIsDeniedAtAnUnseenKey` |
| `TestTheLedgerOrdersWritesByTheStoresCommit`, `TestFirstLoginsRacingOnAnEmptyKey`, `TestTheLedgerPlacesAWriteThatEndsLate`, `TestTheLedgerDoesNotPlaceAWriteThatEndedAfterALaterOne`, `TestAWriteBegunBeforeTheLastEndedIsNotARestore`, `TestAReadSetsTheLastAtNoRevision`, `TestAReplayReadBeforeALandedWriteEndsIsDeniedAfter` | `TestFirstLoginsRacingOnAnEmptyKey` kept; the rest replaced by `TestTheStoresLastWriteIsAdmittedWhateverOrderWritesEnd` |
| `TestTheLedgerPlacesAWriteAfterTheStoresRevisionsWentBack`, `…WereBumped`, `TestALoginAfterARestoreIsTheLast` | replaced by `TestALoginAfterARestoreIsAdmitted` (both kinds of restore), and `etcd_test.go`'s `TestALoginAfterAnEtcdRestoreIsTheLast` kept on the new API |
| — | new: `TestAnotherProcesssWriteIsAdmittedBeforeItsFeedArrives`, `TestAnEarlierRecordIsDeniedOnEveryProcessThatSawALater`, `TestTheSequenceIsAboveEverythingKnown` |

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

  // A login on one process is admitted on another at once: the record's
  // sequence is above the other's base, and above any mark it knows at the
  // key, with no feed between them (Review Focus 1; Ruling 3). A
  // per-process ledger, sealed, denied it (re-check IA1).
  func TestAnotherProcesssWriteIsAdmittedBeforeItsFeedArrives(t *testing.T) {
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
  func TestALoginAfterARestoreIsAdmitted(t *testing.T) {
  	for _, bump := range []bool{false, true} {
  		inner := &rewinding{RevStore: memory.New(time.Now)}
  		l := NewLedger()
  		l.SetBase(inner.Seen() + 1)
  		s := Wrap(inner, keys(), nil, WithLedger(l))
  		login(t, s, "ctx-old", "user:alice")
  		old, _ := inner.RevStore.GetContext(context.Background(), ka)
  		login(t, s, "ctx-new", "user:alice")
  		inner.restore(old, bump) // the store now holds ctx-old, its revisions back or bumped
  		if _, err := s.GetContext(context.Background(), ka); !errors.Is(err, ErrNotLastWritten) {
  			t.Fatalf("bump=%v: a restored record below the mark was admitted: %v", bump, err)
  		}
  		login(t, s, "ctx-after", "user:alice")
  		if c, err := s.GetContext(context.Background(), ka); err != nil || c.CtxID != "ctx-after" {
  			t.Fatalf("bump=%v: the login after the restore: %v %v", bump, c.CtxID, err)
  		}
  	}
  }

  // rewinding is a store whose revisions can be put back to before a
  // record's, as a restore without --bump-revision does, or bumped by a
  // billion, as one with it does. Seen is the wrapper's and never goes back,
  // as etcd's client's is.
  type rewinding struct {
  	store.RevStore
  	mu     sync.Mutex
  	offset int64 // added to every revision the inner store reports
  	seen   uint64
  }

  // out is an inner revision as the store reports it; in is the reverse.
  func (r *rewinding) out(rev uint64) uint64 {
  	r.mu.Lock()
  	defer r.mu.Unlock()
  	if rev == 0 {
  		return 0
  	}
  	v := uint64(int64(rev) + r.offset)
  	r.seen = max(r.seen, v)
  	return v
  }

  func (r *rewinding) in(rev uint64) uint64 {
  	r.mu.Lock()
  	defer r.mu.Unlock()
  	if rev == 0 {
  		return 0
  	}
  	return uint64(int64(rev) - r.offset)
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
  	r.mu.Lock()
  	if bump {
  		r.offset = 1_000_000_000
  	} else {
  		r.offset = 1 - int64(cur)
  	}
  	r.mu.Unlock()
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
  // everything the store has told this process, and above the key's mark.
  func TestTheSequenceIsAboveEverythingKnown(t *testing.T) {
  	inner := memory.New(time.Now)
  	l := NewLedger()
  	l.Observe(ka, 1000, 1000, time.Time{}, time.Time{})
  	w := Wrap(inner, keys(), nil, WithLedger(l)).(*wrapped)
  	if got := w.seqFor(ka, 5); got != 1001 {
  		t.Fatalf("below the mark: %d", got)
  	}
  	if got := w.seqFor(ka, 5000); got != 5000 {
  		t.Fatalf("below the compare revision: %d", got)
  	}
  }

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
  ```

  In `internal/broker/ledger_test.go` and `etcd_test.go:284`, replace `l.Seal()` with
  `l.SetBase(<the store>.Seen()+1)`. Keep what they assert.

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/store/crypt/ -count=1`
  Expected: FAIL to compile (`SetBase`, `Observe`, `seqFor` undefined). Once compiled against a
  stub, `TestAnotherProcesssWriteIsAdmittedBeforeItsFeedArrives` fails as 7d's sealed ledger
  would: process b denies a's login.

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
    over `keys`, returning `cs.Seq`. A form other than 4 is the error it is today.
    `(*wrapped).openContext` calls it with `w.keys`.
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
  where the ledger is built (`run`). `Prune` runs in the sweep loop: add
  `ledger.Prune(time.Now())` after each sweep in `sweepLoop` (pass the ledger), and on memory
  every 10 minutes from `run` (a ticker joined with the run).

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
    cmd/port49d/main.go cmd/port49d/store.go
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
- Modify: `internal/daemon/metrics/metrics.go`, `metrics_test.go` (`StoreFeedUp`,
  `StoreFeedRescans`)
- Modify: `cmd/port49d/store.go` (`openStores`, `stores`), `cmd/port49d/main.go`

**Interfaces:**
- Consumes: `crypt.Ledger` (Task 7), `(*etcd.Store).saw` (Task 6), `etcd.lastTwo`.
- Produces:
  - `store`:
    - `type ContextChange struct { Key ContextKey; Context Context; Deleted bool; Rev uint64 }`;
    - `type ContextFeed interface { ScanContexts(ctx context.Context, fn func(ContextKey, Context)) (uint64, error); WatchContexts(ctx context.Context, after uint64, fn func(ContextChange)) error }`;
    - `var ErrCompacted = errors.New("store: the feed's revision was compacted")`;
    - `type LedgerSource interface { LedgerMarks(ctx context.Context) (uint64, []LedgerMark, error) }`;
    - `type LedgerSink interface { PutLedgerMarks(ctx context.Context, ms []LedgerMark) error }`.
  - `(*etcd.Store).ScanContexts` and `(*etcd.Store).WatchContexts`.
  - `crypt`:
    - `func LoadLedger(ctx context.Context, feed store.ContextFeed, src store.LedgerSource, keys Keys, l *Ledger) (rev uint64, known, recorded int, err error)`;
    - `func FollowContexts(ctx context.Context, feed store.ContextFeed, keys Keys, l *Ledger, from uint64, up func(bool), rescanned func(), logf func(string, ...any)) error`.
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
  	s := newEtcdStore(t)
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
  			mu.Unlock()
  			if len(changes) == 2 {
  				cancel()
  			}
  		})
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
  // gap.
  func TestAWatchFromACompactedRevisionSaysSo(t *testing.T) {
  	ctx := context.Background()
  	s := newEtcdStore(t)
  	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
  	s.PutContext(ctx, k, store.Context{CtxID: "c1", Principal: "user:x", Username: "alice"}, time.Hour)
  	rev, _ := s.ScanContexts(ctx, func(store.ContextKey, store.Context) {})
  	s.PutContext(ctx, k, store.Context{CtxID: "c2", Principal: "user:x", Username: "alice"}, time.Hour)
  	resp, _ := etcdtest.Client(t).Get(ctx, "compact-me")
  	if _, err := etcdtest.Client(t).Compact(ctx, resp.Header.Revision); err != nil {
  		t.Fatal(err)
  	}
  	err := s.WatchContexts(ctx, rev, func(store.ContextChange) {})
  	if !errors.Is(err, store.ErrCompacted) {
  		t.Fatalf("%v", err)
  	}
  }
  ```

  The shared member is compacted by `TestAWatchFromACompactedRevisionSaysSo`, which every other
  test in the package shares. Run it on a member of its own (`etcdtest.Start(t,
  etcdtest.Options{})`) if a test after it reads history. Note which in the report.

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

  func (f *feedOf) WatchContexts(ctx context.Context, _ uint64, fn func(store.ContextChange)) error {
  	for {
  		select {
  		case <-ctx.Done():
  			return ctx.Err()
  		case c := <-f.changes:
  			fn(c)
  		case <-f.compact:
  			return store.ErrCompacted
  		}
  	}
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
  	go FollowContexts(ctx, feed, keys(), lb, 0, func(bool) {}, func() {}, t.Logf)
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

  // A compacted watch scans again, raising only, counts the rescan, and goes
  // on; nothing the earlier scan would have denied is admitted.
  func TestACompactedFeedScansAgainAndOnlyRaises(t *testing.T) {
  	l := NewLedger()
  	l.Observe(ka, 100, 100, time.Time{}, time.Time{})
  	low := sealedAt(t, ka, 50) // a record sealed at sequence 50
  	feed := &feedOf{scanned: map[store.ContextKey]store.Context{ka: low}, rev: 200,
  		changes: make(chan store.ContextChange), compact: make(chan struct{}, 1)}
  	feed.compact <- struct{}{}
  	rescans := 0
  	ctx, cancel := context.WithCancel(context.Background())
  	go func() { eventually(t, func() bool { return rescans > 0 }); cancel() }()
  	FollowContexts(ctx, feed, keys(), l, 150, func(bool) {}, func() { rescans++ }, t.Logf)
  	if l.next(ka) != 101 {
  		t.Fatalf("a rescan lowered the mark: next %d", l.next(ka))
  	}
  }
  ```

  `eventually`, `seqOf` (opens a sealed record with `keys()` and returns its sequence) and
  `sealedAt` (seals a context at a given sequence with the test keys) are test helpers. Write
  them in `follow_test.go`.

- [ ] **Step 3: Run them to see them fail.**

  Run: `go test ./internal/store/etcd/ ./internal/store/crypt/ -run 'Scan|Watch|Feed|LoadLedger' -count=1`
  Expected: FAIL to compile.

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
  	// (ErrCompacted), or the watch fails (ErrUnavailable).
  	WatchContexts(ctx context.Context, after uint64, fn func(ContextChange)) error
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
  func (s *Store) WatchContexts(ctx context.Context, after uint64, fn func(store.ContextChange)) error {
  	wctx, cancel := context.WithCancel(clientv3.WithRequireLeader(ctx))
  	defer cancel()
  	ch := s.ctx.Watch(wctx, s.k.family(famContext), clientv3.WithPrefix(), clientv3.WithRev(int64(after)+1))
  	for resp := range ch {
  		if err := resp.Err(); err != nil {
  			if resp.CompactRevision > 0 || errors.Is(err, rpctypes.ErrCompacted) {
  				return store.ErrCompacted
  			}
  			return unavailable(err)
  		}
  		for _, ev := range resp.Events {
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
  	}
  	if ctx.Err() != nil {
  		return ctx.Err()
  	}
  	return fmt.Errorf("%w: the context watch ended", store.ErrUnavailable)
  }
  ```

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
  func LoadLedger(ctx context.Context, feed store.ContextFeed, src store.LedgerSource, keys Keys,
  	l *Ledger) (rev uint64, known, recorded int, err error) {
  	if src != nil {
  		_, ms, err := src.LedgerMarks(ctx)
  		if err != nil {
  			return 0, 0, 0, err
  		}
  		for _, m := range ms {
  			l.Seed(m)
  		}
  		recorded = len(ms)
  	}
  	rev, err = feed.ScanContexts(ctx, func(k store.ContextKey, c store.Context) { observe(l, keys, k, c) })
  	if err != nil {
  		return 0, 0, 0, err
  	}
  	l.SetBase(rev + 1)
  	return rev, l.Len(), recorded, nil
  }

  // observe raises k's mark from c, sealed, if it opens.
  func observe(l *Ledger, keys Keys, k store.ContextKey, c store.Context) {
  	oc, seq, err := openContextWith(keys, k, c)
  	if err != nil {
  		return
  	}
  	l.Observe(k, seq, c.Rev, c.RevokedAt, oc.SessionExpires)
  }

  // FollowContexts keeps l current from feed after `from` until ctx ends,
  // and returns ctx's error then (plan 7e, Ruling 3). Each change raises its
  // key's mark and never lowers one; a delete changes nothing. A compacted
  // watch scans again, raising only, tells rescanned, and goes on from the
  // scan's revision; a watch that fails is tried again every second. up is
  // told whether the watch is running (port49_store_feed_up{feed="contexts"}),
  // and logf says each rescan and each failure once per run of them.
  func FollowContexts(ctx context.Context, feed store.ContextFeed, keys Keys, l *Ledger, from uint64,
  	up func(bool), rescanned func(), logf func(string, ...any)) error {
  	failing := false
  	for {
  		up(true)
  		err := feed.WatchContexts(ctx, from, func(c store.ContextChange) {
  			if c.Rev > from {
  				from = c.Rev
  			}
  			if !c.Deleted {
  				observe(l, keys, c.Key, c.Context)
  			}
  		})
  		up(false)
  		if ctx.Err() != nil {
  			return ctx.Err()
  		}
  		if errors.Is(err, store.ErrCompacted) {
  			logf("store: the context feed's revision was compacted; scanning the store again")
  			rescanned()
  			if rev, serr := feed.ScanContexts(ctx, func(k store.ContextKey, c store.Context) { observe(l, keys, k, c) }); serr == nil {
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

  Then return `stores{…, follow: func(ctx context.Context) { crypt.FollowContexts(ctx, d, keys,
  ledger, rev, …) }}` with:
  - `up` setting `m.StoreFeedUp.WithLabelValues("contexts")`;
  - `rescanned` incrementing `m.StoreFeedRescans.WithLabelValues("contexts")`;
  - `logf` printing `port49d: ` + the line.

  Put the retry around `LoadLedger` in the shape of the `checkSealKeys` loop beside it: an
  outage is said and tried every 5s, and a lost hold ends the start as a store gone. In
  `runOnce`, after `openStores`, run `sts.follow` on a goroutine joined before `sts.close`, as
  the sweep is (`sweepDone`). Remove the interim `ledger.SetBase(e.Seen() + 1)` Task 7 put in
  `startOnPersistentStore`: the base is the scan's now, set before the start's reads.

- [ ] **Step 9: Run everything.**

  Run: `go test ./internal/store/... ./internal/daemon/metrics/ ./cmd/port49d/ -count=1`
  Expected: PASS. The port49d e2e tests pass. `TestAStartSealsTheLedgerOnceItHasReadTheStore`
  holds through the base. The log names the ledger line.

- [ ] **Step 10: Commit.**

  ```bash
  gofmt -w internal/store internal/daemon/metrics cmd/port49d
  make build && make test && make vet
  git add internal/store/store.go internal/store/etcd/feed.go internal/store/etcd/feed_test.go \
    internal/store/crypt/follow.go internal/store/crypt/follow_test.go internal/daemon/metrics/metrics.go \
    internal/daemon/metrics/metrics_test.go cmd/port49d/store.go cmd/port49d/main.go
  git commit -m "feat(store): every process follows the store's contexts

  A scan at one revision, then a watch from it, raise each key's mark in
  the ledger and never lower one; a compacted watch scans again. The
  start's base is the scan's revision, before any read. port49_store_feed_up
  and port49_store_feed_rescans_total say whether it follows (plan 7e
  Ruling 3).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 9: Every process follows the revocation marks

**Files:**
- Modify: `internal/store/store.go` (`MarkFeed`), `internal/store/marks.go`,
  `internal/store/marks_test.go`
- Modify: `internal/store/etcd/feed.go`, `internal/store/etcd/feed_test.go`
- Modify: `internal/broker/broker.go` (`MarkChanged`), `internal/broker/listen_test.go`
- Modify: `cmd/port49d/main.go` (the daemon's marks and the listener's from the feed)

**Interfaces:**
- Consumes: `store.Marks` (7d), `broker.ConnCloser` (7a).
- Produces:
  - `type store.MarkFeed interface { Revocations(ctx context.Context) (uint64, []Revocation, error); WatchRevocations(ctx context.Context, after uint64, fn func(r Revocation, lifted bool)) error }`.
  - `func (m *Marks) All() []Revocation`: every mark in force, `Kind`, `Key` and `At`, sorted.
  - `func store.LoadMarks(ctx context.Context, feed MarkFeed, m *Marks, on func(r Revocation, standing bool)) (uint64, error)`:
    every mark the store holds goes into `m`; every mark `m` holds that the store lacks is lifted
    from `m`; `on` is told of each change; it returns the revision read at.
  - `func store.FollowMarks(ctx context.Context, feed MarkFeed, m *Marks, from uint64, on func(Revocation, bool), up func(bool), rescanned func(), logf func(string, ...any)) error`.
  - `(*etcd.Store).Revocations` and `(*etcd.Store).WatchRevocations`.
  - `func (b *Broker) MarkChanged(r store.Revocation, standing bool)`: the listener's copy, and,
    for a mark that stands, the held connections it names, closed.

Ruling 5. A mark made on one broker process reaches every other process's in-memory copy and
held connections through the feed. A lift does the same, removing the mark.

- [ ] **Step 1: The failing tests.** In `internal/store/marks_test.go`:

  ```go
  // markFeed serves a fixed set of marks at rev 7, and a watch that delivers
  // what the test sends.
  type markFeed struct {
  	marks   []Revocation
  	events  chan markEvent
  	compact chan struct{}
  }

  type markEvent struct {
  	r      Revocation
  	lifted bool
  }

  func (f *markFeed) Revocations(context.Context) (uint64, []Revocation, error) { return 7, f.marks, nil }
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
  // tells on of each change.
  func TestLoadMarksMakesTheCopyTheStores(t *testing.T) {
  	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0)}
  	gone := Revocation{Kind: RevocationPrincipal, Key: "user:bob@example.com", At: time.Unix(5, 0)}
  	m := NewMarks()
  	m.Set(gone, true)
  	var told []string
  	rev, err := LoadMarks(context.Background(), &markFeed{marks: []Revocation{alice}}, m,
  		func(r Revocation, on bool) { told = append(told, fmt.Sprintf("%s %v", r.Key, on)) })
  	if err != nil || rev != 7 || !m.Holds(alice.Kind, alice.Key) || m.Holds(gone.Kind, gone.Key) {
  		t.Fatalf("rev %d: %v; marks %v", rev, err, m.All())
  	}
  	sort.Strings(told)
  	if fmt.Sprint(told) != "[user:alice@example.com true user:bob@example.com false]" {
  		t.Fatalf("told %v", told)
  	}
  }

  // FollowMarks applies each put and lift; a compacted watch loads them again
  // and applies the difference, telling on of it alone.
  func TestACompactedMarkFeedReloadsTheDifference(t *testing.T) {
  	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0)}
  	carol := Revocation{Kind: RevocationPrincipal, Key: "user:carol@example.com", At: time.Unix(11, 0)}
  	f := &markFeed{events: make(chan markEvent, 1), compact: make(chan struct{}, 1)}
  	m := NewMarks()
  	var mu sync.Mutex
  	var told []string
  	on := func(r Revocation, s bool) { mu.Lock(); told = append(told, fmt.Sprintf("%s %v", r.Key, s)); mu.Unlock() }
  	ctx, cancel := context.WithCancel(context.Background())
  	defer cancel()
  	go FollowMarks(ctx, f, m, 7, on, func(bool) {}, func() {}, t.Logf)
  	f.events <- markEvent{r: alice}
  	waitFor(t, func() bool { return m.Holds(alice.Kind, alice.Key) })
  	f.marks = []Revocation{carol} // alice lifted and carol marked while the watch was compacted away
  	f.compact <- struct{}{}
  	waitFor(t, func() bool { return m.Holds(carol.Kind, carol.Key) && !m.Holds(alice.Kind, alice.Key) })
  	mu.Lock()
  	defer mu.Unlock()
  	if len(told) != 3 {
  		t.Fatalf("told %v", told)
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
  	b.MarkChanged(store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: time.Now()}, true)
  	if !closedWithin(conn, 2*time.Second) {
  		t.Fatal("the held connection was not closed")
  	}
  	if !bindRefused(t, l, "user:alice@example.com") {
  		t.Fatal("a new bind was not refused credential_revoked")
  	}
  	b.MarkChanged(store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com"}, false)
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

  // LoadMarks makes m the store's marks (plan 7e, Ruling 5): every mark feed
  // holds is put in, every mark m holds that feed lacks is lifted, and on is
  // told of each change (nil tells nothing). It returns the revision read
  // at, which FollowMarks follows from.
  func LoadMarks(ctx context.Context, feed MarkFeed, m *Marks, on func(r Revocation, standing bool)) (uint64, error) {
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
  				on(r, true)
  			}
  		}
  	}
  	for _, r := range m.All() {
  		if !stored[[2]string{r.Kind, r.Key}] {
  			m.Set(r, false)
  			if on != nil {
  				on(r, false)
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
  func FollowMarks(ctx context.Context, feed MarkFeed, m *Marks, from uint64, on func(Revocation, bool),
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
  				on(r, !lifted)
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
  // MarkChanged is a mark another broker process made or lifted, as the
  // marks feed brings it (plan 7e, Ruling 5): the listener's copy follows,
  // and a mark that stands closes this process's held connections it names,
  // as Revoke closes its own. The daemon's marks (b.Marks) are the feed's
  // own to keep (store.FollowMarks).
  func (b *Broker) MarkChanged(r store.Revocation, standing bool) {
  	if b.Conns == nil {
  		return
  	}
  	b.Conns.Revoked(r, standing)
  	if !standing {
  		return
  	}
  	n := b.Conns.CloseHeld(func(principal, certKey string) bool {
  		if r.Kind == store.RevocationPrincipal {
  			return principal == r.Key
  		}
  		return certKey == r.Key
  	})
  	if n > 0 {
  		b.logf("broker: a revocation of %s made on another broker process closed %d held connection(s) here",
  			printsafe.Line(r.Key, 160), n)
  	}
  }
  ```

  Factor the match closure into `func matchMark(r store.Revocation) func(principal, certKey
  string) bool`, used by `Revoke` and here.

- [ ] **Step 6: port49d follows the marks.** In `cmd/port49d/main.go`, on etcd, after
  `startOnPersistentStore`:
  - replace filling `authMarks` from `marks` with `rev, err := store.LoadMarks(ctx, sts.etcd,
    authMarks, nil)`, retried while unavailable;
  - after the listener is built, put every mark in it (`bl.Revoked(r, true)` for `r` in
    `authMarks.All()`, replacing the loop over `marks`);
  - start `store.FollowMarks(ctx, sts.etcd, authMarks, rev, brk.MarkChanged, …)` on a goroutine
    joined as the context feed is, with `up` and `rescanned` on `StoreFeedUp` and
    `StoreFeedRescans` labelled `marks`.

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
- Modify: `internal/daemon/metrics/metrics.go`, `metrics_test.go` (`LedgerPending`)
- Modify: `cmd/port49d/store.go` (the record into `LoadLedger`; the keeper), `cmd/port49d/storeroles_test.go`,
  `cmd/port49d/store_e2e_test.go`
- Modify: `docs/superpowers/plans/README.md` (7e-1 as built, Step 7)

**Interfaces:**
- Consumes: `store.LedgerMark`, `store.LedgerSource`, `store.LedgerSink` (Tasks 7, 8);
  `crypt.Ledger.Dirty`, `Redirty`, `Pending` (Task 7).
- Produces:
  - etcd: `famLedger = "lw/"` (`lw/<nas>/<user>`); `(*etcd.Store).LedgerMarks` and
    `(*etcd.Store).PutLedgerMarks`.
  - `func crypt.KeepLedger(ctx context.Context, l *Ledger, sink store.LedgerSink, every time.Duration, pending func(int), logf func(string, ...any))`.
  - `Metrics.LedgerPending prometheus.Gauge` (`port49_ledger_pending`).
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
  	s := newEtcdStore(t)
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
  	s := newEtcdStore(t)
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
  	for _, extra := range []etcdtest.Grant{
  		{Role: RoleDaemon, Key: "/port49/v1/lw/", RangeEnd: clientv3.GetPrefixRangeEnd("/port49/v1/lw/"), Write: true},
  		{Role: RoleDaemon, Key: "/port49/v1/sp/", RangeEnd: clientv3.GetPrefixRangeEnd("/port49/v1/sp/")},
  	} {
  		d := daemonWithGrant(t, extra) // the file's fixture: a TLS member, port49's roles plus extra, the daemon's store
  		if err := d.CheckIdentity(context.Background(), false); !errors.Is(err, ErrNotSeparated) {
  			t.Fatalf("a daemon granted %+v passed: %v", extra, err)
  		}
  	}
  }
  ```

  In `crypt/follow_test.go`:

  ```go
  // The keeper writes what was raised, keeps what a failed write owed for the
  // next round, and gauges what is owed.
  func TestTheKeeperWritesRaisedMarksAndRetriesAFailure(t *testing.T) {
  	l := NewLedger()
  	l.Observe(ka, 10, 10, time.Time{}, time.Now().Add(time.Hour))
  	sink := &flakySink{fail: 1}
  	var owed []int
  	ctx, cancel := context.WithCancel(context.Background())
  	go func() { eventually(t, func() bool { return sink.landed() == 1 }); cancel() }()
  	KeepLedger(ctx, l, sink, 10*time.Millisecond, func(n int) { owed = append(owed, n) }, t.Logf)
  	if sink.calls < 2 || l.Pending() != 0 || owed[0] != 1 {
  		t.Fatalf("calls %d pending %d owed %v", sink.calls, l.Pending(), owed)
  	}
  }
  ```

  `flakySink` fails its first `fail` calls with `store.ErrUnavailable` and records what lands.
  Write it in the test file.

  In `cmd/port49d/store_e2e_test.go`, add:

  ```go
  // A context put back while port49d was stopped, at a key the ledger record
  // holds a later mark for, is denied after the restart: the start seeds its
  // ledger from the record before it scans (Review Focus 2; Ruling 4). In
  // 7d this was the restart residual: the start took it as the key's.
  func TestAStartSeededFromTheLedgerRecordDeniesAPutBack(t *testing.T) {
  	var out, log syncBuffer
  	e, o := stderr, stdout
  	t.Cleanup(func() { stderr, stdout = e, o })
  	stderr, stdout = &out, &log
  	cfgPath, pkiDir, _, _, srv := etcdRunServer(t)
  	root := srv.Client(t, "root")
  	ctx := context.Background()
  	tacacs, brokerAddr, stop := startRun(t, cfgPath, &out, 1)
  	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
  	loginSession(t, dev, mint(t, brokerAddr, pkiDir, "leaf1"), &log)
  	resp, err := root.Get(ctx, "/port49/v1/c/", clientv3.WithPrefix())
  	if err != nil || len(resp.Kvs) != 1 {
  		t.Fatalf("the context: %v %v", resp, err)
  	}
  	saved := resp.Kvs[0]
  	loginSession(t, dev, mint(t, brokerAddr, pkiDir, "leaf1"), &log) // a later login at the key
  	waitForGauge(t, &out, "port49_ledger_pending", 0)                // the record holds it
  	if err := stop(); err != nil {
  		t.Fatal(err)
  	}
  	if _, err := root.Put(ctx, string(saved.Key), string(saved.Value)); err != nil {
  		t.Fatal(err)
  	}
  	tacacs, _, _ = startRun(t, cfgPath, &out, 2)
  	dev = tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
  	if dev.permits("alice", "configure") {
  		t.Fatal("a context put back while port49d was stopped was taken as the key's after the restart")
  	}
  }
  ```

  `waitForGauge` scrapes the run's metrics address, as `gauge` in `service_e2e_test.go` does,
  until the series reads the value or 10s pass.

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/store/etcd/ ./internal/store/crypt/ ./cmd/port49d/ -run 'LedgerRecord|Keeper|SeededFromTheLedgerRecord|CanWriteTheLedgerRecord' -count=1`
  Expected: FAIL to compile, then `TestAStartSeededFromTheLedgerRecordDeniesAPutBack` FAILs: the
  restart admits the put-back.

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
  // pending is told how many marks are owed after each round
  // (port49_ledger_pending).
  func KeepLedger(ctx context.Context, l *Ledger, sink store.LedgerSink, every time.Duration, pending func(int),
  	logf func(string, ...any)) {
  	t := time.NewTicker(every)
  	defer t.Stop()
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
  		pending(l.Pending())
  	}
  }
  ```

  In `metrics.go`, add `LedgerPending prometheus.Gauge` (`port49_ledger_pending`, "context keys
  whose mark the ledger record does not yet hold; above 0 for a minute, a context put back at
  one would be taken after a restart"). Add it to `TestNewRegistersEveryMetric`.

- [ ] **Step 6: port49d keeps it.** In `cmd/port49d/store.go`'s `openStores` (etcd):
  - `crypt.LoadLedger(ctx, d, d, keys, ledger)`: the daemon's identity reads `lw/`;
  - in the returned `stores`, a `keep func(ctx)` that runs `crypt.KeepLedger(ctx, ledger, b,
    time.Second, func(n int) { m.LedgerPending.Set(float64(n)) }, logf)`. `b` is the broker's
    raw store, which holds the hold in 7e-1;
  - `runOnce` runs and joins it as it does the feeds.

  On memory there is no record and no keeper.

- [ ] **Step 7: Run everything, then record 7e-1 as built.**

  Run: `make build && make test && make vet && make test-race`
  Expected: PASS.

  In `docs/superpowers/plans/README.md`, under "Plan 7d — As built", add a heading `### Plan 7e
  — As built`, with a paragraph "**7e-1** (`feature/broker-process`, base `b508ba0`)". List
  each task's commits and what differs from this plan's text, as the 7d section does from its
  ledger. Name every interface 7e-1's review changed: the controller amends 7e-2's tasks to
  match before dispatching Task 11.

- [ ] **Step 8: Commit.**

  ```bash
  gofmt -w internal/store internal/daemon/metrics cmd/port49d
  make build && make test && make vet
  git add internal/store/etcd/keys.go internal/store/etcd/roles.go internal/store/etcd/roles_test.go \
    internal/store/etcd/ledger.go internal/store/etcd/ledger_test.go internal/store/crypt/follow.go \
    internal/store/crypt/follow_test.go internal/daemon/metrics/metrics.go internal/daemon/metrics/metrics_test.go \
    cmd/port49d/store.go cmd/port49d/main.go cmd/port49d/storeroles_test.go cmd/port49d/store_e2e_test.go \
    docs/superpowers/plans/README.md
  git commit -m "feat(store): the ledger record, kept by the keyspace's holder

  lw/<nas>/<user> holds each key's highest write sequence, raised once a
  second and never lowered; the daemon's role reads it and cannot write
  it. A start seeds its ledger from it before it scans, so a context put
  back while port49d was stopped is denied at a key the record holds a
  later mark for: 7d's restart residual, closed but for the keeper's lag
  (plan 7e Ruling 4). port49_ledger_pending gauges what it owes.

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

- [ ] **Step 1: Decision 36, 7e-2's part.** At the end of decision 36's bullets (before its
  closing `(§5.1.4, §5.6, §5.7, §14; design document §8, §12, §17)`), add:

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
    it records the seal keys, re-indexes the contexts the index lost, applies every standing mark
    to the kept contexts, purges the unspent tokens only as below, and carries the policy in force
    into every kept context; then it runs the sweep, the re-index, the ledger record's keeper and
    the context half of every refresh pass. Every replica serves the API and the admin socket,
    runs the token half of its own reload's passes and certificate status, and follows the
    contexts and the marks. A runner that loses the hold stops those duties at once, keeps serving
    the API, and tries to take the hold again every 5s; a broker's readiness is never the store's.
  - **The purge at a takeover.** The runner records in `meta/judged` the bundle in force whenever a
    pass leaves `port49_policy_refresh_pending` at 0. A runner taking the hold with another bundle
    in force (an edit made while none ran, or a runner gone before its settle pass) purges every
    unspent token and records the instant for every key; with the same, it purges none, so a
    rolling restart of the brokers keeps everyone's tokens.
  - **The settle pass** is 30s or two policy watch intervals and 5s after a swap, whichever is
    longer, and the policies since the last settled pass are kept until it completes, so a token
    another replica minted under the replaced policy before it reloaded is judged.
  - **The daemon's start on etcd** waits for the store and checks its identity, reads (never
    writes) the seal-key record, loads the marks, seeds the ledger from the record and a scan, starts
    both feeds and binds. It reloads its policy file for admission, quarantine and redaction and
    carries nothing into live contexts. It probes the store every sixth of `hold_ttl` through its
    context pool, so an idle port49d goes dark as one under load does; a run after a store gone
    keeps the ledger and the marks.
  - **The revocations file is retired on etcd**, which persists the marks; it stays for the memory
    store, with `port49d init-revocations`. After an etcd restore, revocations made since the
    snapshot are re-applied by hand.
  - **The sockets.** port49-broker's admin socket answers `port49 revoke` (revoke, lift, list).
    port49d's answers `port49 keys diagnose`, and, with no broker in it, a revocation there is
    refused naming port49-broker's socket.
  ```

- [ ] **Step 2: Decisions 32 and 34 amended.** At the end of decision 32's paragraph, before
  `(§5.1.4, §5.7, §12; design document §11, §12, §17)`, add `*Amended by decision 36 (plan 7e):*
  on etcd the store keeps the marks and the file is retired; a lift is port49-broker's admin
  socket's.` At the end of decision 34's "The revocations file" bullet, add `On etcd it is retired
  (decision 36).`

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
    runner that stops is replaced within `hold_ttl` and a third; a takeover purges only when the
    bundle in force is not the one last judged. With every broker stopped, an open session's next
    command is answered.
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
    - **Any number of port49d and port49-broker per keyspace** (plan 7e). port49d holds nothing;
      run it as a Deployment of several, with a rolling update. port49-broker's replicas share the
      runner's hold: one runs the start, the sweep and the policy refresh, and another takes over
      within `hold_ttl` and a third when it stops. Set the same `broker.policy_watch_interval` on
      every replica.
    ```

    In the "Backups" bullet, replace `Until plan 7e retires it, broker.revocations_file is kept as
    well.` with `On etcd broker.revocations_file is retired (plan 7e): after a restore, revoke again
    what was revoked since the snapshot.` In "Restore with port49d stopped", replace `its start
    puts the revocations file's marks back into the store,` with `the runner's start`.
  - **§15.** In the alarms list, add: `port49_store_feed_up{feed}` 0 for longer than `hold_ttl`;
    any increase of `port49_store_feed_rescans_total`; `port49_ledger_pending` above 0 for a
    minute; the sum of `port49_store_keyspace_held` over port49-broker's replicas 0 for twice
    `hold_ttl`.
  - **§17, internal interfaces.** In the row `| daemon, broker → token store |`, add after `under
    port49's roles`: `; each process holds its own component's certificate alone (plan 7e)`.
  - **§19, step 7.** After `the API authorization model.` add ` Plan 7e splits the broker into its
    own process, \`port49-broker\`, and lets any number of each run on one store.`

- [ ] **Step 8: Check the edits.**

  ```bash
  grep -n '^| \*\*L37\*\*\|^| \*\*L38\*\*' docs/design/2026-08-23-policy-engine-spec.md
  grep -n 'The runner.\*\* The keyspace hold' docs/design/2026-08-23-policy-engine-spec.md
  grep -n 'Any number of port49d and port49-broker per keyspace' docs/design/2026-08-21-port49-design.md
  grep -c 'One keyspace per port49d until plan 7e' docs/design/2026-08-21-port49-design.md
  ```

  Expected: two rows; one line; one line; `0`.

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

  Run: `make build && make test && make vet`
  Expected: PASS, with `internal/port49d` running exactly the tests `cmd/port49d` ran (compare
  `go test -list . ./internal/port49d/ | wc -l` with the count at `main`).

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
  `LoadBroker`, `key_refs`, `broker.state_dir`, `checkStore`, the refusals, `KeyRefs`)
- Create: `internal/config/broker_test.go`
- Modify: `internal/config/store_test.go`, `internal/config/config_test.go`
- Modify: every reader of `cfg.Broker.PolicyFile` and `cfg.Broker.PolicyWatchInterval` in
  `internal/port49d` (`loadPolicy`, `parseBundle`, `reload.go`), which read `cfg.Policy` now

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
  - `config.StoreOf(raw)` reads either file's `store:` block (Task 16 uses it on both).

Rulings 1, 2, 12.

- [ ] **Step 1: The failing tests.** Create `internal/config/broker_test.go`. Its fixtures are
  built as `config_test.go`'s are: a temp file with a base YAML, and `t.Setenv` for the
  encryption key. Write them as helpers here:

  ```go
  package config

  import (
  	"os"
  	"path/filepath"
  	"strings"
  	"testing"
  )

  // brokerYAML is a port49-broker.yaml that loads; each test changes one key.
  func brokerYAML(t *testing.T) string {
  	t.Helper()
  	dir := t.TempDir()
  	pki := writeEtcdIdentity(t, dir, "port49-broker") // writes ca.pem, cert and 0600 key; store_test.go's helper
  	state := filepath.Join(dir, "state")
  	if err := os.Mkdir(state, 0o700); err != nil {
  		t.Fatal(err)
  	}
  	return strings.Join([]string{
  		"inventory_file: " + writeInventory(t, dir),
  		"key_refs: [core]",
  		"encryption: {current: {id: v1, secret_env: PORT49_ENC_V1}}",
  		"admin_socket: " + filepath.Join(dir, "broker.sock"),
  		"broker:",
  		"  listen: 127.0.0.1:0",
  		"  tls_cert_file: " + pki.cert, "  tls_key_file: " + pki.key, "  client_ca_file: " + pki.ca,
  		"  policy_file: " + writePolicy(t, dir),
  		"  state_dir: " + state,
  		"  certificate_status: {disabled: true}",
  		"store:",
  		"  backend: etcd",
  		"  etcd:",
  		"    endpoints: [https://127.0.0.1:2379]",
  		"    ca_file: " + pki.ca,
  		"    broker: {cert_file: " + pki.cert + ", key_file: " + pki.key + "}",
  	}, "\n") + "\n"
  }

  func loadBrokerYAML(t *testing.T, raw string) (Config, error) {
  	t.Helper()
  	t.Setenv("PORT49_ENC_V1", strings.Repeat("k", 32))
  	p := filepath.Join(t.TempDir(), "port49-broker.yaml")
  	if err := os.WriteFile(p, []byte(raw), 0o600); err != nil {
  		t.Fatal(err)
  	}
  	return LoadBroker(p)
  }

  // A port49-broker.yaml loads under the broker's role: key_refs are its key
  // names, its policy is broker.policy_file, and metrics default to :9050.
  func TestABrokerConfigLoads(t *testing.T) {
  	c, err := loadBrokerYAML(t, brokerYAML(t))
  	if err != nil {
  		t.Fatal(err)
  	}
  	if c.Role != RoleBroker || len(c.KeyRefs()) != 1 || c.KeyRefs()[0] != "core" || c.Policy == nil ||
  		c.MetricsListen != ":9050" || c.Broker.StateDir == "" {
  		t.Fatalf("%+v", c)
  	}
  }

  // The broker never holds a device key, nor the daemon's etcd identity, nor
  // speaks TACACS+ (Review Focus 9; Rulings 1, 2): each is refused naming
  // the key.
  func TestTheBrokersConfigNeverNamesADeviceKey(t *testing.T) {
  	for key, extra := range map[string]string{
  		"keys:":                   "keys: {core: {accept: [{version: 1, secret_env: PORT49_LAB_KEY}]}}\n",
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
  		raw := brokerYAML(t) + extra
  		switch key {
  		case "store.etcd.daemon":
  			raw = strings.Replace(raw, "    broker: {", "    daemon: {cert_file: /x, key_file: /y}\n    broker: {", 1)
  		case "broker.revocations_file":
  			raw = strings.Replace(raw, "  state_dir:", "  revocations_file: /var/lib/port49/r.json\n  state_dir:", 1)
  		}
  		if _, err := loadBrokerYAML(t, raw); err == nil || !strings.Contains(err.Error(), key) {
  			t.Errorf("port49-broker.yaml with %s loaded, or the refusal does not name it: %v", key, err)
  		}
  	}
  }

  // port49-broker.yaml requires each of these, naming it.
  func TestTheBrokersConfigRequiresItsKeys(t *testing.T) {
  	for _, cut := range []string{"key_refs:", "state_dir:", "admin_socket:", "backend: etcd", "    broker: {"} {
  		var lines []string
  		for _, l := range strings.Split(brokerYAML(t), "\n") {
  			if !strings.Contains(l, cut) {
  				lines = append(lines, l)
  			}
  		}
  		if _, err := loadBrokerYAML(t, strings.Join(lines, "\n")); err == nil {
  			t.Errorf("port49-broker.yaml without %q loaded", cut)
  		}
  	}
  }

  // port49d.yaml on etcd never names the broker's identity, never carries a
  // broker: block, and names the policy it admits from (Review Focus 9;
  // Rulings 1, 2).
  func TestTheDaemonsConfigNeverNamesTheBrokersIdentity(t *testing.T) {
  	base := daemonEtcdYAML(t) // store_test.go's etcd fixture, with the broker identity and block removed and policy: added
  	if c, err := loadYAML(t, base); err != nil || c.Policy == nil || c.Broker != nil {
  		t.Fatalf("the split daemon's config: %+v %v", c, err)
  	}
  	withBrokerID := strings.Replace(base, "    daemon: {", "    broker: {cert_file: /x, key_file: /y}\n    daemon: {", 1)
  	if _, err := loadYAML(t, withBrokerID); err == nil || !strings.Contains(err.Error(), "store.etcd.broker") {
  		t.Fatalf("a daemon config naming the broker's identity: %v", err)
  	}
  	withBlock := base + brokerBlockYAML(t)
  	if _, err := loadYAML(t, withBlock); err == nil || !strings.Contains(err.Error(), "port49-broker.yaml") {
  		t.Fatalf("a broker: block in port49d.yaml on etcd: %v", err)
  	}
  	noPolicy := strings.Replace(base, "policy:", "unused_policy_marker:", 1)
  	if _, err := loadYAML(t, noPolicy); err == nil {
  		t.Fatal("port49d.yaml on etcd with no policy: loaded")
  	}
  }
  ```

  `writeEtcdIdentity`, `writeInventory`, `writePolicy`, `daemonEtcdYAML`, `brokerBlockYAML` and
  `loadYAML` are built from `store_test.go`'s and `config_test.go`'s fixtures. Name them in the
  report.
  - `writeInventory` writes an inventory with no key groups.
  - `writePolicy` writes a policy whose key group assigns `core`, behind the fence's owner and
    mode rules.

  Then add to `config_test.go`: `TestAnInProcessBrokerSetsThePolicy` (`Config.Policy` mirrors
  `broker.policy_file` and its interval on memory) and `TestPolicyIsRefusedBesideABrokerBlock`.

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/config/ -count=1`
  Expected: FAIL to compile (`LoadBroker`, `RoleBroker`, `Policy`).

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

  If `AccountingConfig` or `limitsYAML` is not comparable at `b508ba0`, compare field by field.
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

  `StoreOf(raw)` decodes either file. It cannot know the role from the bytes, so it calls
  `checkStore` with the role whose identity the block names: the broker's if `store.etcd.broker`
  is set and `store.etcd.daemon` is not, else the daemon's.

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
  git add internal/config/config.go internal/config/broker_test.go internal/config/config_test.go \
    internal/config/store_test.go internal/port49d/main.go internal/port49d/reload.go internal/port49d/store.go
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
- Modify: `internal/port49d/store_e2e_test.go` (the etcd fixture: a split daemon config)

**Interfaces:**
- Consumes:
  - `config.Config.Policy` and `config.RoleDaemon` (Task 13);
  - `crypt.LoadLedger`, `crypt.FollowContexts` and `store.LoadMarks`, `store.FollowMarks`
    (7e-1);
  - `store.RevStore.Ping` (Task 6).
- Produces:
  - `type daemonStart struct { ledgerRev, marksRev uint64 }`, returned by `openStores` for the
    daemon's role.
  - `stores.probe func(ctx context.Context)`: one `Ping` every `hold_ttl`/6 through the
    daemon's guard, until `ctx` ends.
  - `reloader` fields:
    - `live *policy.Live`;
    - `log decision.Emitter`;
    - `pass func(ctx context.Context, priors []broker.Prior) (broker.RefreshReport, error)`, nil
      for none (port49d with no broker);
    - `onSettled func(bundle string)`, nil for none (Task 15).

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
  	startDaemon(t, daemonCfg, &out, 1)
  	startDaemon(t, copyWithListen(t, daemonCfg, "127.0.0.1:0"), &out, 2) // a second, its own addresses
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
  	startDaemon(t, daemonCfg, &out, 1)
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
  	tacacs := startDaemon(t, cfgPath, &out, 1)
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

  `startDaemon`, `copyWithListen` and `askAdmin` are helpers. Write them beside the test.
  `startDaemon` is `startRun` waiting for `port49d: listening on` instead of `broker listening
  on`.

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/port49d/ ./internal/daemon/admin/ -run 'TwoDaemons|IdleDaemon|DaemonsSocket|NoBrokerReloads' -count=1`
  Expected: FAIL. The split config does not start (port49d takes the hold as the broker, whose
  identity it no longer has), and `RevokeElsewhere` is undefined.

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
    - `crypt.LoadLedger(ctx, d, d, keys, ledger)`, retried while unavailable, then the ledger
      line;
    - `store.LoadMarks(ctx, d, authMarks, nil)`, retried while unavailable, then
      `port49d: store: N revocation(s) in force from the store`. Pass `authMarks` into
      `openStores`;
    - return `stores` whose:
      - `follow` runs both feeds;
      - `probe` pings through the daemon's guard (Step 5);
      - `broker` is nil;
      - `lost` is nil. A store gone comes from the guard alone, as 7d's second trigger.
  - **`checkSealKeys`** gains `write bool`. With `write` false it never calls `PutSealKeys`.

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

  In `openStores`, keep the daemon's guarded `RevStore` (`gd := guard.WrapRev(d, gc("daemon"))`),
  wrap it with `crypt.Wrap(gd, …)` as today, and set `probe: func(ctx context.Context) { probe(ctx,
  gd, e.HoldTTL/6) }`.

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
  - the daemon's handlers get `authMarks`, which `openStores` filled;
  - run `sts.follow` and `sts.probe` on goroutines joined before `sts.close`;
  - skip `startOnPersistentStore`, the sweep, the keeper, the restore of the revocations file,
    the certificate status and the seeds: each is the broker's.

  `cfg.Broker != nil` (memory with the in-process broker) runs exactly as today. In
  `reload.go`, `reloader` reads `r.live` where it read `r.broker.Policy`, and `r.log` where it
  read `r.broker.Log`. `refresh` returns at once when `r.pass` is nil. `swap` sets
  `port49_policy_refresh_pending` only when `r.pass` is set.

- [ ] **Step 7: The e2e fixture.** In `store_e2e_test.go`, `etcdRunServer` and its callers run
  port49d on etcd with a broker block, which Task 13 now refuses.
  - Split it into `etcdSplit(t) (daemonCfg string, proxy *etcdtest.Proxy)` for the daemon, and,
    from Task 15, `brokerSplit(t, srv) string` for port49-broker.
  - Move each 7d e2e test (`TestRunOnEtcdKeepsALoginAcrossARestart`,
    `TestAStartAppliesAStandingMarkToAKeptContext`,
    `TestAStartSealsTheLedgerOnceItHasReadTheStore`, `TestAHungStoreGoesDarkAndServesAgainWhenItReturns`)
    to run a daemon and a broker in the same test process. That is Task 15's `startBroker`, so
    mark each `t.Skip("plan 7e Task 15: needs port49-broker")` here, and unskip it in Task 15.
  - Delete `TestASecondPort49dWaitsForTheKeyspace`: Ruling 11 withdraws it, and
    `TestTwoDaemonsServeOneKeyspace` replaces it.

  Each skipped test stays in the file, named in the report, and Task 15 fails its review if one
  is left skipped.

- [ ] **Step 8: Run everything.**

  Run: `make build && make test && make vet`
  Expected: PASS, with the four 7d e2e tests skipped and named.

- [ ] **Step 9: Commit.**

  ```bash
  gofmt -w internal/port49d internal/daemon/admin
  git add internal/port49d/daemon.go internal/port49d/daemon_test.go internal/port49d/main.go \
    internal/port49d/store.go internal/port49d/reload.go internal/port49d/store_e2e_test.go \
    internal/daemon/admin/admin.go internal/daemon/admin/admin_test.go
  git commit -m "feat(port49d): serve TACACS+ on etcd with no broker inside

  With the daemon's identity alone: no hold, the seal keys read and never
  written, the marks and the ledger loaded and followed, a probe through
  the context pool so an idle port49d goes dark as 7d's fence made it, and
  the policy reloaded for admission with no refresh. A revocation at its
  socket names port49-broker's (plan 7e Rulings 11, 13).

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
  `startOnPersistentStore` becomes the runner's takeover)
- Modify: `internal/port49d/certstatus.go` (the state dir)
- Modify: `internal/port49d/store_e2e_test.go` (Task 14's skipped tests, on the split)
- Modify: `Makefile` (`build`)

**Interfaces:**
- Consumes:
  - Tasks 13–14: `config.LoadBroker`, `Config.Policy`, `Config.KeyRefs()`,
    `BrokerConfig.StateDir`;
  - Task 14: `newReloader(cfg, live, log, pass, m, now)`;
  - 7e-1: `crypt.LoadLedger`, `crypt.FollowContexts`, `crypt.KeepLedger`, `store.LoadMarks`,
    `store.FollowMarks`, `Broker.MarkChanged`;
  - 7d: `etcd.Store.Hold`, `Broker.ApplyMarksAtStart`, `Broker.RefreshAtStart`,
    `Broker.ReindexContexts`, `etcd.Store.Unindexed`, `sweepLoop`, `startLeftBy`.
- Produces:
  - `func port49d.BrokerMain(args []string) int`, behind `cmd/port49-broker`.
  - `func runBroker(parent context.Context, cfgPath string) error`.
  - `type runner struct` with:
    - `func (r *runner) run(ctx context.Context)`: hold, takeover, duties, loss, again;
    - `func (r *runner) running() bool`.
  - `func (b *broker.Broker) RefreshTokens(ctx context.Context, priors []broker.Prior) (broker.RefreshReport, error)`.
  - `func (s *etcd.Store) Judged(ctx context.Context) (string, bool, error)` and
    `func (s *etcd.Store) PutJudged(ctx context.Context, bundle string) error`, at `meta/judged`.
  - `const settleMin = 30 * time.Second`; `func settleAfter(interval time.Duration) time.Duration`
    is `max(settleMin, 2*interval+5*time.Second)`, which replaces the constant
    `settleAfterReload` at its uses.

Rulings 6, 7, 8, 9, 12, 13. The broker process is port49d's broker path, with no TACACS+
listener, on the broker's identity alone, and with the start steps moved behind the runner's
hold.

- [ ] **Step 1: The failing tests.** Create `internal/port49d/brokerd_test.go`. The fixture,
  `splitFleet(t)`, is one TLS etcd member with the roles, one `port49d.yaml` and one
  `port49-broker.yaml` (`brokerSplit`), and the helpers `startBroker(t, cfg, out, n) (apiAddr
  string, stop func() error)` and `startDaemon`.

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

  // A takeover purges the unspent tokens only when the bundle in force is
  // not the one the last runner judged (Ruling 7): a broker restart on the
  // same policy keeps a minted token redeemable; an edit made with no
  // broker running purges it, and an idempotent replay mints afresh.
  func TestATakeoverPurgesOnlyAnUnjudgedBundle(t *testing.T) {
  	var out, log syncBuffer
  	e, o := stderr, stdout
  	t.Cleanup(func() { stderr, stdout = e, o })
  	stderr, stdout = &out, &log
  	f := splitFleet(t)
  	tacacs := startDaemon(t, f.daemon, &out, 1)
  	api, stop := startBroker(t, f.broker, &out, 1)
  	waitFor(t, &out, "runner: took keyspace")
  	waitForGauge(t, &out, "port49_policy_refresh_pending", 0) // judged
  	kept := mintOn(t, api, f.pki, "leaf1")
  	stop()
  	api, stop = startBroker(t, f.broker, &out, 2)
  	waitFor(t, &out, "is the one the last runner judged; no unspent token purged")
  	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
  	if st := dev.login("alice", kept); st != wire.AuthenStatusPass {
  		t.Fatalf("a token minted before a broker restart on the same policy: %d", st)
  	}
  	spare := mintOn(t, api, f.pki, "leaf1")
  	stop()
  	f.editPolicy(t) // a grant's comment changed: another bundle
  	startBroker(t, f.broker, &out, 3)
  	waitFor(t, &out, "unspent token(s) purged")
  	if st := dev.login("alice", spare); st == wire.AuthenStatusPass {
  		t.Fatal("a token minted under a bundle no runner judged was not purged")
  	}
  }

  // A token another replica minted under the replaced policy before it
  // reloaded is judged by the runner's settle pass (Ruling 8).
  func TestTheSettlePassJudgesALateReplicasTokens(t *testing.T) {
  	r := newReloaderForTest(t) // reload_test.go's fixture: a runner reloader on a memory broker
  	if got := settleAfter(r.interval); got < 2*r.interval {
  		t.Fatalf("settle %v is not past two watch intervals %v", got, r.interval)
  	}
  	r.swapTo(t, withdrawnGrantPolicy) // the edit that withdraws alice's grant
  	tok := mintUnder(t, r, oldPolicy)  // another replica, still on the old policy
  	r.runFirstPass(t)
  	r.runSettlePass(t)
  	if tokenStillRedeemable(t, r, tok) {
  		t.Fatal("the settle pass kept a token minted under the replaced policy after the first pass")
  	}
  }
  ```

  Write the third test's helpers from `reload_test.go`'s fixture:
  - `mintUnder` mints through a second `*broker.Broker` on the same store, holding the old
    policy;
  - `runFirstPass` and `runSettlePass` call `r.refresh` with the clock moved to each.

  Add to `refresh_test.go`: `TestRefreshTokensJudgesTokensAndNoContext`. It deletes a
  superseded token and leaves a context on the withdrawn grant untouched, and returns a report
  whose context counts are all 0.

  Add to `meta_test.go`: `TestJudgedIsReadBackAndAbsentIsNotFound`.

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/port49d/ ./internal/broker/ ./internal/store/etcd/ -run 'Runner|Takeover|Settle|RefreshTokens|Judged' -count=1`
  Expected: FAIL to compile.

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
  type judgedRec struct {
  	Bundle    string    `json:"bundle"`
  	WrittenAt time.Time `json:"written_at"`
  }

  // Judged is the bundle the last runner's pass left
  // port49_policy_refresh_pending at 0 under (plan 7e, Ruling 7); ok is
  // false when none was recorded. A record that does not decode is ok false
  // too, said by its key alone: a takeover then purges, which fails closed.
  func (s *Store) Judged(ctx context.Context) (bundle string, ok bool, err error) {
  	var r judgedRec
  	_, found, err := getJSON(ctx, s.ctx, s.k.meta("judged"), &r)
  	if errors.Is(err, errNotDecoded) { // whatever getJSON's undecodable error is at b508ba0
  		s.logf("etcd: %s does not decode; the takeover purges the unspent tokens", s.k.meta("judged"))
  		return "", false, nil
  	}
  	if err != nil || !found {
  		return "", false, err
  	}
  	return r.Bundle, true, nil
  }

  // PutJudged records bundle as judged, as the broker.
  func (s *Store) PutJudged(ctx context.Context, bundle string) error {
  	body, err := json.Marshal(judgedRec{Bundle: bundle, WrittenAt: s.now().UTC()})
  	if err != nil {
  		return err
  	}
  	_, err = s.ctx.Put(ctx, s.k.meta("judged"), string(body))
  	return unavailable(err)
  }
  ```

  Check `getJSON`'s error for a record that does not decode at `b508ba0`, and match it.

- [ ] **Step 5: The settle covers a late replica.** In `reload.go`:
  - add `settleMin` and `settleAfter`, and use `settleAfter(r.interval)` where `settleAfterReload`
    was;
  - in `refresh`, on a complete pass, reset `r.priors` to the policy in force **only when
    `r.settle` is zero after this pass**. While a settle pass is owed, keep the priors and close
    the newest's span at `rep.At`, so the settle pass judges every token minted under each of
    them since;
  - when a complete pass leaves `PolicyRefreshPending` at 0 and `r.onSettled` is set, call
    `r.onSettled(r.live.Load().Bundle)`.

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
  		crypt.KeepLedger(ctx, r.ledger, r.raw, time.Second, func(n int) { r.m.LedgerPending.Set(float64(n)) },
  			func(f string, a ...any) { fmt.Fprintf(stderr, "port49-broker: "+f+"\n", a...) })
  	}()
  	wg.Wait()
  }
  ```

  `takeover(ctx) error` is 7d's `startOnPersistentStore`, renamed and moved here, with these
  changes:
  - it runs `checkSealKeys(…, true)` first;
  - the revocations file's union is gone: the marks are the store's, read by `store.LoadMarks`
    in `runBroker` before the API serves;
  - the purge, by Ruling 7, replaces the unconditional one:

  ```go
  	bundle := r.brk.Policy.Load().Bundle
  	judged, ok, err := r.raw.Judged(ctx) // retried while unavailable, as every step is
  	if ok && judged == bundle {
  		fmt.Fprintf(stderr, "port49-broker: runner: the bundle in force (%s) is the one the last runner judged; no "+
  			"unspent token purged\n", bundle)
  	} else {
  		at := r.brk.Now()
  		// SupersedeAll first: a replay after any token is gone mints afresh (Task 5).
  		// … retry(st.SupersedeAll(ctx, at)), then n, err := st.PurgeTokens(ctx) …
  		fmt.Fprintf(stderr, "port49-broker: runner: the bundle in force (%s) is not the one the last runner judged "+
  			"(%s); %d unspent token(s) purged (run 'port49 token' again)\n", bundle, orNone(judged, ok), n)
  	}
  ```

  - the carry's owed pass (`startLeftBy`) goes to `r.rel.startLeft(now)` through the reloader's
    own goroutine. Send it on a channel the reloader's `run` selects on (`r.rel.owed`), never by
    calling into the reloader from this goroutine;
  - `ledger.Seal()` is gone (7e-1).

  `sweepLoop` gains the ledger argument, and prunes it after each sweep (Task 7 Step 5 added the
  prune).

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
     - Its guard has `StopAfter: 0`. A broker never goes dark: the API answers 503
       `store_unavailable` from the guard, and readiness is never the store's (design §12).
     - It is wrapped as `crypt.Wrap(guard.WrapRev(b, gc("broker")), keys, …,
       crypt.WithLedger(ledger))`.
  6. The ledger: `crypt.LoadLedger(ctx, b, b, keys, ledger)`, then `crypt.FollowContexts`. The
     marks: `store.LoadMarks(ctx, b, marks, nil)`. Both are retried while unavailable.
  7. `buildBrokerAnchor` (the minter, the session manager, `brk.Marks = marks`, `Persist` nil).
     Certificate status with `certStatusConfig(*cs, anchorCert, cfg.Broker.StateDir)`.
  8. The broker listener, every mark in `marks.All()` put in it, `brk.Conns = bl`. Then
     `store.FollowMarks(ctx, b, marks, rev, brk.MarkChanged, …)`.
  9. The admin socket: `admin.Server{Revoke: adminRevoke(brk), Revocations: adminRevocations(st),
     Now: time.Now}`, with `Held` nil. A `keys_diagnose` there is answered `port49-broker holds no
     device packets; keys diagnose is port49d's admin socket`.
  10. The lab's seeds, if any (`mintSeeds`), on every broker start.
  11. Serve. `port49-broker: listening on <api>, metrics on <metrics>`. `brk.SetReady(ReadyServing)`.
  12. The reloader: `newReloader(cfg, brk.Policy, brk.Log, pass, m, time.Now)`, where `pass`
      calls `brk.Refresh` while `rn.running()` and `brk.RefreshTokens` otherwise, and
      `onSettled` calls `rn.raw.PutJudged` while running.
  13. The runner, `rn.run(ctx)`, on its goroutine.
  14. On a signal: drain as `runOnce` does. The runner lets go of the hold; the listener, the
      admin socket and the reloader stop. Every goroutine is joined.

  `BrokerMain(args)` parses `--config` (default `/etc/port49/port49-broker.yaml`), refuses any
  subcommand or extra argument (exit 2), and runs `runBroker` under `signal.NotifyContext`, as
  `Main` runs `run`. SIGHUP is caught and reloads, as port49d's does. Create
  `cmd/port49-broker/main.go`:

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
  to start `startDaemon` and `startBroker` on `splitFleet`, keeping what it asserts:
  - **`TestRunOnEtcdKeepsALoginAcrossARestart`:** restart the daemon; then restart the broker and
    assert the token minted before is still redeemable (Ruling 7, the same bundle). The 7d
    assertion that it is purged now belongs to `TestATakeoverPurgesOnlyAnUnjudgedBundle`.
  - **`TestAStartAppliesAStandingMarkToAKeptContext`:** the mark is put into the store as etcd's
    root with every broker stopped, standing in for the file edit, which no longer exists. The
    runner's takeover then applies it: `(1 context(s) marked revoked)`.
  - **`TestAStartSealsTheLedgerOnceItHasReadTheStore`:** unchanged on the daemon.
  - **`TestAHungStoreGoesDarkAndServesAgainWhenItReturns`:** on the daemon, which goes dark on
    its guard and probe. The broker's runner loses its hold.

- [ ] **Step 9: Run everything.**

  Run: `make build && make test && make vet && make test-race`
  Expected: PASS, with no test skipped for Task 15.

- [ ] **Step 10: Commit.**

  ```bash
  gofmt -w internal/port49d internal/broker internal/store/etcd cmd/port49-broker
  git add cmd/port49-broker/main.go internal/port49d/brokerd.go internal/port49d/runner.go \
    internal/port49d/brokerd_test.go internal/port49d/reload.go internal/port49d/reload_test.go \
    internal/port49d/store.go internal/port49d/certstatus.go internal/port49d/store_e2e_test.go \
    internal/broker/refresh.go internal/broker/refresh_test.go internal/store/etcd/meta.go \
    internal/store/etcd/meta_test.go Makefile
  git commit -m "feat(port49-broker): the broker as its own process, with one runner per keyspace

  port49-broker serves the API on the broker's identity alone. Its
  replicas share the keyspace hold as the runner's: the runner records the
  seal keys, re-indexes, applies the marks, purges only a bundle no runner
  judged, carries the policy, sweeps, and keeps the ledger record; every
  replica runs its own reload's token half. The settle pass keeps the
  replaced policies until it completes, so a late replica's tokens are
  judged (plan 7e Rulings 6-9, 12, 13).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

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
  	a := startDaemon(t, f.daemon, &out, 1)
  	b := startDaemon(t, f.copyDaemon(t), &out, 2)
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
  	tacacs := startDaemon(t, f.daemon, &out, 1)
  	apiA, _ := startBroker(t, f.broker, &out, 1)
  	cfgB := f.copyBroker(t) // its own API address and admin socket
  	startBroker(t, cfgB, &out, 2)
  	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
  	loginSession(t, dev, mintOn(t, apiA, f.pki, "leaf1"), &log)
  	principal := lastCommandPrincipal(t, &log)
  	held := heldConnTo(t, apiA, f.pki) // alice's connection to A, one request answered, kept open
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
  // holds the later mark (Review Focus 2; Ruling 4).
  func TestAPutBackBeforeADaemonStartsIsDenied(t *testing.T) {
  	var out, log syncBuffer
  	e, o := stderr, stdout
  	t.Cleanup(func() { stderr, stdout = e, o })
  	stderr, stdout = &out, &log
  	f := splitFleet(t)
  	root := f.srv.Client(t, "root")
  	ctx := context.Background()
  	a := startDaemon(t, f.daemon, &out, 1)
  	api, _ := startBroker(t, f.broker, &out, 1)
  	devA := tacacsClient{t: t, addr: a, key: []byte("run-test-secret")}
  	loginSession(t, devA, mintOn(t, api, f.pki, "leaf1"), &log)
  	resp, err := root.Get(ctx, "/port49/v1/c/", clientv3.WithPrefix())
  	if err != nil || len(resp.Kvs) != 1 {
  		t.Fatalf("the context: %v %v", resp, err)
  	}
  	saved := resp.Kvs[0]
  	loginSession(t, devA, mintOn(t, api, f.pki, "leaf1"), &log) // a later login at the key
  	waitForGauge(t, &out, "port49_ledger_pending", 0)            // the runner's record holds it
  	if _, err := root.Put(ctx, string(saved.Key), string(saved.Value)); err != nil {
  		t.Fatal(err)
  	}
  	b := startDaemon(t, f.copyDaemon(t), &out, 2) // started after the put-back
  	devB := tacacsClient{t: t, addr: b, key: []byte("run-test-secret")}
  	if devB.permits("alice", "configure") {
  		t.Fatal("a daemon started after a put-back took it as the key's")
  	}
  	if devA.permits("alice", "configure") {
  		t.Fatal("the running daemon took the put-back its feed had passed")
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
  	a := startDaemon(t, f.daemon, &out, 1)
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

  The helpers beside Task 15's:
  - `heldConnTo` is a `tls.Dial` with alice's client certificate that sends one `GET
    /v1/identity` and keeps the connection, as `listen_test.go`'s held-connection tests do;
  - `closedWithin` is a read that returns EOF or a reset within the bound;
  - `askAdminAt` speaks the admin protocol on a socket, as `admin_linux_test.go` does
    (`internal/port49d` cannot import `cmd/port49`);
  - `adminSocketOf` reads a config's `admin_socket`;
  - `mintStatus` is `mintOn` that returns the status and body.

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
  ```

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/port49d/ -run 'OneDaemonIsAnswered|OneBrokerReaches|BeforeADaemonStarts|EveryBrokerStopped|ReadsBothFiles' -count=1`
  Expected: the e2e tests PASS where Tasks 12–15 hold, and FAIL to show any gap. Each failure is
  a defect in an earlier task, fixed in its own `fix(…)` commit with this test as its witness.
  `TestStoreRolesReadsBothFiles` FAILs: `--broker-config` is undefined.

- [ ] **Step 3: `store-roles`.** In `storeroles.go`:
  - add `--broker-config` (default `/etc/port49/port49-broker.yaml`);
  - read the daemon's identity from `--config`'s `store.etcd.daemon`, and the broker's from
    `--broker-config`'s `store.etcd.broker`, each through `config.StoreOf`;
  - refuse a mismatch of `store.etcd.prefix` between the two ("the two files name different
    keyspaces");
  - a `--config` that still names `store.etcd.broker` (a 7d file) keeps working without
    `--broker-config`, said with a line naming the move (Ruling 1). A file with neither is
    refused naming `--broker-config`;
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
  git add internal/port49d/split_e2e_test.go internal/port49d/storeroles.go internal/port49d/storeroles_test.go
  git commit -m "test(port49d): the fleet end to end; store-roles reads both files

  Two daemons and two brokers on one keyspace: a login answered on the
  other daemon, a revocation on one broker closing the other's held
  connection, a put-back denied by a daemon started after it, and sessions
  running on with every broker stopped. store-roles takes the broker's
  identity from port49-broker.yaml (plan 7e Ruling 14).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 17: (lab, on beehive) L37, L38 and L36 on the split deployment

**Files:**
- Create: `tests/lab/split_test.go`
- Modify: `tests/lab/harness_test.go` (`startSplit`, the second replica, the broker's process),
  `tests/lab/store_test.go` (`storeLab` on the split's two configs)
- Modify: the five topologies' device configs under `tests/lab/` (a second TACACS+ server,
  `172.100.100.2`, in the same server group as `172.100.100.1`) and the bridge's second host
  address
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
  - the five images are present (`image_check_test.go`).

- [ ] **Step 1: The harness, committed first.**
  - **`startSplit(cfg splitCfg)`.** It starts, from the pinned `bin/`:
    - `port49-broker --config tests/lab/port49-broker-lab.yaml`, which mints the lab seeds;
    - port49d A on `172.100.100.1:49`;
    - port49d B on `172.100.100.2:49`.

    All three share one embedded etcd member, through L35's proxy, with the daemon's and the
    broker's identities. Each process gets its own log and stderr file under
    `tests/lab/logs/`. `stopDaemon(which)`, `stopBroker()` and `startBroker()` each wait on the
    process's exit, as `stopDaemon` does today.
  - **The second address.** The bridge's second host address is added at `bringUp` and removed
    at `down`.
  - **The device configs.** Each topology's config lists both servers in one group, in the
    platform's own syntax, A first. Every line was measured working on its image in an earlier
    row; cite which in a comment, and where one was not, Step 2's first cell is its own check.

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
  git add tests/lab/split_test.go tests/lab/harness_test.go tests/lab/store_test.go tests/lab/topologies
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

  **Cell outcomes:**
  - A cell whose precondition failed (the device never tried B, the store did not hang) is
    re-run up to three times, then recorded INVALID, as L35's Ruling T15-a.
  - A cell that shows port49 wrong (B denies a session A wrote, a revocation that does not
    reach B, a daemon that does not go dark) is a defect. Fix it on the branch, with a unit
    test, in a `fix(…)` commit, and re-run every image from a worktree pinned to the fix
    (CLAUDE.md rule 4).
  - A device that does not try the second server is a device fact, not a defect: record it.

- [ ] **Step 3: Close the rows.** Close each row only when every platform it names has a note.
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
  - **L36's answer** replaces the operator note "Junos re-authorization on etcd is unmeasured"
    in Task 18's notes.

  Copy the captures back and run `make evidence` before removing the pinned worktree. Commit:

  ```bash
  git add tests/lab/results/L36-*.md tests/lab/results/L37-*.md tests/lab/results/L38-cisco_iosxe.md \
    tests/lab/evidence/L36-* tests/lab/evidence/L37-* tests/lab/evidence/L38-* \
    docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
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
  - the rulings as made, against Rulings 1–16 and OR-1;
  - the lab table, one row per image, from the notes: cells 1–5 of L37, L38's four cells, and
    L36;
  - the operator notes below, as amended by what was built;
  - "Carried, for later plans", and the unassigned follow-ups, with the residual Ruling 4 leaves
    named exactly.
- [ ] **Step 2: The status line.** In the README's status paragraph, after the 7d-2 sentence, add
  `**7e written 2026-10-03** (…), **executed** …, **merged** … (PR #…)`. The 7e bullet under
  "Plan 7" gains `**As built:** "Plan 7e — As built", below.`
- [ ] **Step 3: Drift.** Fix every doc drift a task report names that its own task left. Check
  that no line in the spec or design still says "until plan 7e" (`grep -n 'until plan 7e'
  docs/design/*.md` prints nothing).
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
- **Upgrading from 7d on etcd ends every live session once.** A session record 7d sealed does
  not open under 7e: it is denied `store_unavailable`, replaced at the user's next login, and
  revoked by the next refresh pass. Users log in again. The memory store loses everything at a
  restart, as before.
- **A context put back in etcd while port49d was stopped is now denied after the restart,** for
  every key the new ledger record (`lw/`) holds a later write for. In 7d the start took it as
  that key's.
- **After an etcd restore under a running port49d**, with or without `--bump-revision`, the
  next login is admitted, and a session written since the snapshot is denied until its next
  login, as 7d measured.
- **A stalled decision-log sink no longer holds a policy reload**, nor the mints behind it. A
  mint's records are written once it has let go of the policy.
- **New config refusal:** an `encryption` key `id` outside `A-Z a-z 0-9 . _ -` (1 to 64) is
  refused at load.
- **New metrics:**
  - `port49_store_feed_up{feed}` (`contexts`, `marks`): 0 for longer than `hold_ttl` is an alarm;
  - `port49_store_feed_rescans_total{feed}`: alert on any increase;
  - `port49_ledger_pending`: above 0 for a minute is an alarm.
- **`port49d store-roles`** prints one more grant: the daemon's read on `lw/`. Re-apply it before
  starting 7e-1; port49d's start check refuses a daemon role that can write `lw/` or touch `sp/`.

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
    apply its output.
  - **Set the same `broker.policy_watch_interval` on every broker replica.**
- **port49d no longer takes the keyspace.**
  - **A second port49d serves beside the first.** List several on each device, and use a rolling
    update. 7d's `strategy: Recreate` advice is withdrawn.
  - **`port49_store_keyspace_held`** is 1 on the port49-broker running the start, the sweep and
    the policy refresh, and 0 elsewhere. Alert on its sum over the brokers being 0 for twice
    `hold_ttl`.
- **A broker rollout keeps everyone's tokens.** Unspent tokens are purged only when the runner
  that takes over finds a policy in force that no runner judged: an edit made while every broker
  was stopped.
- **Revocation lives on port49-broker's admin socket:** `port49 revoke --socket <its
  admin_socket>`. port49d's socket answers `keys diagnose`, and a revocation sent there says
  which socket to use.
- **On etcd the revocations file is retired.** etcd holds the marks. After an etcd restore,
  revoke again what you revoked since the snapshot.
- **With every broker stopped,** open sessions run on, a token already minted logs in, and a
  policy edit changes admission at once and live sessions when a broker returns. What each image
  does: L37.
- **A port49d with no traffic** still goes dark on a hung store: it probes the store every
  `hold_ttl`/6. L37 measures how long that takes.
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
  port49d per keyspace, the hold): Rulings 1, 11; Task 18 Step 3 checks no "until plan 7e" is
  left.
- **Spec §14:** Task 1 Step 4 and Task 11 Step 5 add the assertions, and each names its test.
- **Review Focus:** each of the nine lines names its test and task.
- **Placeholders.** None in the unit and e2e tests. The lab tests (Task 17) are specified cell by
  cell, as 7d's Task 15 was, since they are written against the harness at the pinned commit.
  Three of `rewinding`'s methods are "SwapLoginRev's shape", written beside it. Test helpers built
  from a file's existing fixtures are named, and each task's report names what it built them
  from.
- **Type consistency.** These names are used alike in every task that consumes them:
  - `Ledger.SetBase`, `Observe`, `Seed`, `Dirty`, `Redirty`, `Pending`, `Prune`;
  - `store.LedgerMark`, `ContextFeed`, `MarkFeed`, `LedgerSource`, `LedgerSink`;
  - `crypt.LoadLedger`, `FollowContexts`, `KeepLedger`;
  - `store.LoadMarks`, `FollowMarks`;
  - `Broker.MarkChanged`, `RefreshTokens`;
  - `etcd.Store.Seen`, `Judged`, `PutJudged`;
  - `config.LoadBroker`, `Config.Policy`, `RoleBroker`.

