# Plan 7d: The Shared Store (etcd) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put port49's store on etcd, the backend the owner chose for D1 on 2026-10-02, and close
every item the roadmap and plans 4b, 7a and 7c hand to 7d.
- **The backend.** `internal/store/etcd` implements every `store.Store` method with its
  atomicity, and every `storetest` property runs against it. That includes the ones only the
  memory store's own tests held until now, 7a's, and 7c's `DeleteTokenRemovesOne` and
  `DeleteTokenRacesRedeem` with the expired-put case.
- **One step for a login.** The context write, its index bookkeeping, and a check that no
  revocation mark has appeared for the login's principal or certificate land in one atomic
  operation (`store.SwapLogin`). That closes four holes:
  - PR #7's third follow-up (a replace, its unindex and its index made one operation);
  - 4b's unindexed context, invisible to the refresh and to revocation;
  - 7a's residual window, where a redemption racing a revocation writes its context after the
    second pass;
  - and makes 7c's self-revocation compare-and-set on `SetContextPolicy` a property of every
    backend.
- **A store that does not answer is a store that is down.** Every store call has a hard
  timeout, every TACACS+ packet's store work has its own deadline, and each of two pools has a
  circuit breaker. Token and context operations use separate connections and in-flight slots
  (design §12).
- **Store-native mutual TLS per component** (design §17). The daemon and the broker each
  authenticate to etcd with their own client certificate, under roles port49 prints
  (`port49d store-roles`). port49d refuses to start when its roles are not in force.
- **port49d on etcd.**
  - **One port49d per keyspace** until plan 7e. A second one waits with its listeners closed,
    and one that loses its hold stops.
  - **A start** puts the revocations file's marks into the store and purges unspent tokens.
    It then carries the policy in force into every live context the store kept, before
    TACACS+ binds.
  - **Live sessions survive a restart.**
- **The `crypt_open_failures_total{record="token"}` alarm.** A record that will not open is named
  by its key id on stderr. A start whose store was last sealed under a key this configuration
  lacks says so.
- **The agent's single connection.** A `port49 token` queued behind a slow revocation is told
  that the revocation is still running, never that the broker is unreachable.
- **Lab.** A new register row, L35: what each image does when port49d's store hangs, when
  port49d stops on losing it, and when it comes back. It is opened and closed on beehive.

**Architecture:**
- **One backend, two clients per component.** `etcd.Open` dials etcd twice, a token pool and a
  context pool, each its own gRPC connection.
  - **Records.** Each record is one key holding JSON with snake_case keys. Every compare-and-set
    is a transaction on the key's `mod_revision`.
  - **Expiry is logical.** A record carries its own expiry, read against port49d's clock. etcd
    leases only reclaim keys, in one-minute buckets, at least `lease_grace` after the expiry.
  - **Revisions.** `Rev` is the context key's `mod_revision`. `PolicyRev` is drawn from the same
    counter through a `policy_moved` flag the next non-policy write resolves.
  - **Indexes.** A ref's index record (`x/<nas>/<user>`) is authoritative. The lookup entries
    under a principal, a sid or a certificate only find candidates, are filtered against it, and
    are cleaned by a sweep.
- **The guard.** `internal/store/guard` wraps any `store.Store`.
  - **Pools.** It routes each method to the `token` or the `context` pool, with an in-flight cap
    and a breaker each.
  - **Deadlines.** It bounds each call by `call_timeout`.
  - **Errors.** It counts a backend's `store.ErrUnavailable`, and its own deadline, as failures,
    and never counts a caller that gave up. Above it, the sealing layer is unchanged:
    `crypt.Wrap(guard.Wrap(etcd store))`.
- **The login.** `store.JoinContext` reads the revocation marks for the login's principal and
  certificate before it decides. It hands the backend one `SwapLogin` carrying:
  - the context;
  - the index change (clear, drop, add);
  - and the marks as read.

  The backend writes all of it only while the context, the ref's index record and the marks are
  as read.
- **port49d.** `cmd/port49d/store.go` builds the daemon's and the broker's stores, takes the
  keyspace hold, waits for etcd with every listener closed, checks the roles, and runs the
  index sweep. The broker gains `RefreshAtStart` and `SupersededAll`. The agent serialises its
  exchanges and knows when a revocation holds the wire.

**Tech Stack:**
- Go: the module's `go` line moves from 1.22 to **1.26**, because every current etcd release's
  `go.mod` says `go 1.26` (Owner decision OD-1).
- `go.etcd.io/etcd/client/v3` **v3.6.15**, with `concurrency` and `api/v3/v3rpc/rpctypes`, in
  the binary.
- `go.etcd.io/etcd/server/v3/embed` **v3.6.15**, in tests only: `internal/store/etcd/etcdtest`
  is imported by `_test.go` files and the lab, never by a binary.
- `go.uber.org/zap`, only for `zap.NewNop()`, to keep the client's JSON logs off port49d's
  stderr.
- All pure Go, with no cgo. Measured before this plan was written: an embedded member was ready
  in 0.92 s under `CGO_ENABLED=0`. A three-member embedded cluster, with two members stopped,
  timed out linearizable reads and writes at the deadline and still served serializable reads.
  A client-certificate CN was etcd's user, and a role's prefix permission was enforced, a
  transaction comparing a key outside it included.
- containerlab on beehive for Task 15.

**Spec:**
- `docs/design/2026-08-23-policy-engine-spec.md`:
  - §5.1.4: revocation, the residual window.
  - §5.6: the login and the join.
  - §5.7: `store_unavailable`.
  - §12: tooling.
  - §13: decisions 15, 21, 24 (amended), 32, 34, and the new 35.
  - §14: required test assertions.
  - §15: the register rules; L4; the new L35.
- `docs/design/2026-08-21-port49-design.md`:
  - §8: encryption at rest.
  - §12: the failure model; Consequences ("Hard timeouts", "Circuit breaker", "Connection pool
    separation", go-dark); the store interface.
  - §13: token store topology.
  - §15: every stated alarm needs a metric.
  - §17: internal interfaces, "daemon, broker → token store".
  - §19: steps 2 and 7.
- Roadmap `docs/superpowers/plans/README.md`:
  - "Plan 7", the 7d bullet, and "Decision D1".
  - "Plan 4b": "Hands to plan 6", the four remote-store items.
  - "Plan 2": "Owed by plan 3 or plan 7", the `crypt_open_failures_total{record="token"}` alarm.
  - "Plan 3": PR #7's third follow-up.
  - "Plan 7a — As built", "Carried" (7d).
  - "Plan 7c — As built", "Carried" (7d).
- The merged plans 7a (`2026-10-01-07a-revocation-and-broker-limits.md`) and 7c
  (`2026-10-02-07c-api-and-authorization.md`).

**Prerequisite:** plan 7c merged (PR #22, merge `c485e03`; `main` at `9cefbba`).

## The split: two merges, one plan

This plan is **7d-1** (Tasks 1–8) and **7d-2** (Tasks 9–16). Each is its own branch and pull
request, and each leaves `make test` green. Nothing is cut; the split is only where the review
gate falls.

- **7d-1, `feature/shared-store-backend`, off `main`.** The spec, the `storetest` suite lifted,
  the interface changes and their callers (the login's one step), and the etcd backend passing
  every property.
  - **What port49d does.** It still runs on the memory store. The one behaviour that changes on
    it is the login (Task 4): an index failure now refuses the login, and a login whose
    principal or certificate is marked writes its context revoked.
  - **No device behaviour changes, so no lab.**
- **7d-2, `feature/shared-store-port49d`, off `main` after 7d-1 merges.** The guard, the
  identities and roles, the config, port49d on etcd, the crypt alarm, the agent, the lab, and the
  as-built docs. Everything an operator meets at 3am lands here, behind its own review.

**Why split.**
- **Size.** Sixteen tasks is above 7c's fourteen, and the backend alone is four.
- **What each half risks.** 7d-1 is correctness against properties, with no operational surface.
  7d-2 is operational behaviour, gated by L35. A reviewer can reject one and approve the other.
- **Fewer surprises for 7d-2.** 7d-2 is written against 7d-1's interfaces, which this plan
  fixes. The project rule ("write plan N+1 after plan N merges") is kept, because this is one
  plan: 7d-2's tasks consume exactly the names 7d-1's tasks produce, as any later task does.
- **If 7d-1's review changes an interface,** the controller amends 7d-2's tasks before
  dispatching Task 9, and says so in the ledger.

## What this plan does not do

- **No second port49d on one keyspace, and no broker process.** Plan 7e builds the broker as its
  own process, one refresh runner across replicas, the listener's marks shared across replicas,
  and `b.superseded`/`b.blobsSeen` in the store. Until then a second port49d against the same
  keyspace waits (Ruling 11).
- **No go-dark proper and no warm context cache** (plan 7f). The one form of go-dark 7d builds is
  coarse: a port49d that loses its hold on the store stops, so devices find the connection
  refused (Ruling 11).
- **`broker.revocations_file` stays** (Ruling 13). Its retirement is 7e's.
- **No Valkey, Redis, PostgreSQL or DynamoDB backend.** The interface stays pluggable.
- **The decision-log emits under a policy hold** (4b Task 4) stay 7e's, as the roadmap has them.
- **No bulk lift.** It stays on the unassigned list (7c).
- **Spec, unassigned: a `revoke` record for a mark that could not be written** (7c final review
  M3). It is untouched. A store outage is now loud on stderr and in metrics (Task 9), which
  narrows what M3 costs.

## Rulings where the design and spec are silent

Each takes the option that denies more, is written into the tasks named, and is recorded in spec
§13 as decision 35 by Task 1. The ones the owner should read first are under "Decisions for
Ryan".

1. **etcd v3.6.15, and Go 1.26.** D1 is the owner's (2026-10-02). v3.6 is the current stable
   series, and every release since v3.5.21 says `go 1.26` in its `go.mod`, so the module's `go`
   line follows (OD-1). The client is linked into `port49d`; the server (`embed`) only into test
   binaries.
2. **Tests get etcd in process, never from docker.** `etcdtest` starts real etcd members from
   `go.etcd.io/etcd/server/v3/embed` inside the test binary.
   - **What it starts.** One shared member per package (`etcdtest.Main`), with a fresh key prefix
     per store, so each property gets an empty keyspace without a restart. A member of a test's
     own with TLS, client-certificate authentication and roles (`Start`). Three members for
     quorum loss (`StartCluster`). An in-process TCP proxy that can stop answering (`NewProxy`).
   - **Why.** `make test` stays runnable on a laptop with no docker, under `CGO_ENABLED=0`. It
     exercises the real server (Raft, MVCC, RBAC), not a fake. The lab uses the same members, so
     beehive needs no etcd image.
   - **The cost.** A larger module graph and about a second per started member.
3. **Expiry is the record's, read against port49d's clock.**
   - **The lease.** Each record holds its own expiry, as the memory store's do, and a read past
     it is `ErrNotFound`. etcd leases only reclaim keys: a record is put on the lease of the
     one-minute bucket that ends at least `lease_grace` (5 m) after its expiry. So a lease never
     reclaims a record before it is dead to port49d, and skew between port49d and etcd costs
     nothing, since a lease's TTL is a duration.
   - **The expired put (7c M-2).** It is accepted: the record is put on the shortest lease and
     never read as live. `DeleteTokenRemovesOne` therefore runs on a fixed clock against etcd as
     it does against memory, and needs no clock-advancing constructor.
   - **What never expires.** Revocation marks carry no lease. Lookup entries carry none either:
     they live while their ref's index record lists them, and the sweep removes them after.
4. **Every read is linearizable.** None is serializable. A member cut off from the quorum answers
   nothing, never a stale context, an unrevoked one included. Measured before this plan: with
   two of three members stopped, a linearizable read timed out and a serializable one answered.
5. **Compare-and-set on `mod_revision`, everywhere.**
   - **The narrow setters.** Each is a read, a change, and a transaction that writes only if the
     key's `mod_revision` (and, for contexts, the ref's index record's) is what was read. It reads
     again on a lost race, until the call's deadline.
   - **The revisions.** `Rev` is the context key's `mod_revision`. `PolicyRev` comes from the same
     counter: a policy-relevant write sets `policy_moved`, and the next write that is not one
     stores the `mod_revision` it read as `policy_rev`. So `PolicyRev` moves only on what the
     refresh decides, and never repeats.
   - **`DeleteToken`** keeps the token index's entries, as 7c ruled. The etcd backend never
     prunes them, so it cannot hide a second live token under the key.
6. **The ref's index record is authoritative.**
   - **The record.** `x/<nas>/<user>` holds every principal, sid and certificate the ref is
     indexed under, each with its own expiry, and an extension restamps them all.
   - **Lookup entries.** `ip/<principal>/<ref>`, `is/<sid>/<ref>` and `ic/<cert>/<ref>` exist so a
     revocation can find refs without a scan. A lookup answers only the refs whose index record
     still lists that key, live.
   - **The invariant.** A lookup entry is written in the same transaction that lists its key, and
     deleted only once the key is unlisted (`Sweep`, Task 7), so a revocation never misses a ref
     the index record holds.
   - **Escaping.** Keys escape every part, so `user:al` never matches `user:alice`.
7. **The login is one step** (`store.SwapLogin`).
   - **What it carries.** The context write, the index change the join decided (clear the ref,
     drop a sid or certificate, add the login's), and the revocation marks the login read for
     its principal and certificate. The step lands only while the context, the ref's index
     record and those marks are as read; otherwise `ErrConflict`, and `JoinContext` reads and
     decides again. A mark that stands, for a token not minted after it, is carried into the
     context as its revocation.
   - **What it closes.** PR #7's third follow-up; 4b's unindexed context; 7a's residual window
     for a revocation by principal or certificate. Decision 32 writes the mark first, so any
     login after it sees it, and one before it is reached by the second pass.
   - **What it leaves.** A self or key revocation leaves no mark, so its residual window of one
     round trip stays, as 7c's §5.1.4 text says.
   - **What changes for the operator.** A login whose index cannot be written is now refused
     ERROR `store_unavailable`, where it was a PASS with `index_error`: a context that no
     revocation can reach is never written.
8. **The guard.**
   - **Pools.** Methods are pooled by the table in Task 9. The authorization path, every context
     record and blob read, is the `context` pool. Mints, redemptions, receipts, idempotency and
     marks are the `token` pool.
   - **Deadlines and slots.** Each call has `call_timeout` (500 ms). A call waits for an
     in-flight slot only within that deadline, then is refused: a queue is worse than a refusal
     (design §12).
   - **The breaker.** After `breaker.failures` (5) consecutive failures the pool's circuit opens
     for `open_for` (5 s), then lets one call probe. A probe that fails opens it again.
   - **What counts as a failure.** The backend's `store.ErrUnavailable`, or the guard's own
     deadline. Never `ErrNotFound`, `ErrConflict` or a refusal by etcd's roles, and never a
     caller that gave up.
   - **Saying it.** A circuit that opens or closes is one line on stderr and a gauge.
9. **Every TACACS+ packet's store work has a deadline,** `store.packet_deadline` (2 s; 100 ms to
   4 s, and at least `call_timeout`). It serves two ends:
   - **The device.** It hears port49's FAIL or ERROR before its own TACACS+ timeout, which L4
     measured at 5 s a command on the Cisco and Arista images, so a hung store reads as
     `store_unavailable`, never as a silent server (L35 measures it).
   - **The refresh.** A redemption's write lands well inside 4b's 30 s settle pass (4b final
     review m3).

   4b's other remote-store item, a deadline on each refresh call, is the guard's `call_timeout`.
10. **Each component has its own identity on etcd** (design §17).
    - **The certificates.** `store.etcd.daemon` and `store.etcd.broker` name a client
      certificate each. etcd authenticates the CN as its user, and `port49d store-roles` prints
      the `etcdctl` commands that create the two roles and grant them.
    - **The daemon's role cannot** read or write idempotency records, write the token indexes,
      or write revocation marks. A compromised daemon credential cannot lift a revocation or hide
      a token from one.
    - **The start check.** port49d probes: its daemon identity must be refused a read of the
      idempotency records, and its broker identity must be allowed one. It refuses to start
      otherwise, unless `store.etcd.roles: unenforced` is set, which it says at every start, as
      `certificate_status.disabled` is said.
    - **Transport.** Endpoints are `https` only. A key file readable by group or other is
      refused.
11. **One port49d per keyspace until 7e.**
    - **The hold.** port49d holds `meta/hold` on an etcd session lease of `hold_ttl` (15 s), and
      writes who holds it.
    - **A second port49d** waits, with every listener closed, naming the holder every 30 s.
    - **Losing the hold.** A port49d whose lease lapses has lost the store for longer than
      `hold_ttl`. It stops, and the reason is the last line it prints: devices then find the
      connection refused and use their local method, as the owner ruled for a store outage
      (2026-09-24). Its service manager restarts it, and it waits for the store. Plan 7f
      replaces the stop with closing and reopening the listener.
12. **A start on etcd.**
    - **The store.** port49d waits up to `start_timeout` (30 s) for etcd, with every listener
      closed, and exits 1 past it, naming the endpoints.
    - **Then, in order:** it takes the hold; checks the roles; restores the revocations file's
      marks into the store (a mark in either stands); and purges every unspent token. A restart
      purged them on the memory store too, and no policy port49d loaded judged them.
    - **Replays.** Every key is marked superseded at the start instant (`Broker.SupersededAll`),
      so an idempotent replay re-mints rather than handing back a deleted token.
    - **The policy in force.** port49d carries it into every live context the store kept
      (`Broker.RefreshAtStart`) before TACACS+ binds, retrying every 5 s while the store errs, its
      listeners still closed.
    - **Then it serves.** Live sessions continue across the restart.
13. **`broker.revocations_file` stays in 7d.** With etcd, the store and the file are a union at
    start. A mark lifted while its save failed comes back at the next start, which fails closed,
    and the start line counts the marks that came only from the file. Retiring the file is 7e's.
14. **The crypt alarm.**
    - **The line.** A record that will not open is said once per `(record, key id)` per 10
      minutes, naming the key id (the sealed header's, never a secret) and what to do. This is
      beside `port49_crypt_open_failures_total{record}`, unchanged.
    - **The seal record.** On etcd, port49d records its current and previous key ids in
      `meta/seal_keys` at each start. A start whose recorded current key is outside its own window
      warns, sets `port49_crypt_store_key_unknown` to 1, and still starts. Records it cannot open
      already fail closed, and refusing to start would turn a key-config mistake into a
      fleet-wide AAA outage.
15. **The agent's single connection.**
    - **One exchange at a time.** The agent sends one exchange at a time on its held connection
      (a one-slot "wire" semaphore), and knows when a revocation holds it.
    - **Behind a revocation.** A mint, identity or explain arriving then waits within its own 30
      s. If the revocation still holds the wire, it fails with `ErrRevocationRunning`, and
      `port49 token` says the revocation is still running and nothing was minted.
    - **Not built.** No second connection (a design change, 7c's final review), and no HTTP/2.
16. **L35 is opened and closed by this plan,** on vEOS, the N9Kv, the C8000V and vJunos-router.
    - **The store.** An embedded etcd with TLS and roles in the lab test process, behind an
      in-process proxy that can hang it.
    - **What it measures.** What a device sees when the store hangs, when port49d stops on losing
      its hold, and after the store returns and port49d restarts. Nothing in the design is
      asserted about it before the row closes.

## Decisions for Ryan

**OD-1. The module's Go floor rises from 1.22 to 1.26.**
- **Why.** Every etcd release from v3.5.21 on, v3.6.15 included, declares `go 1.26` in its
  `go.mod`, so depending on it raises port49's `go` line. `CLAUDE.md`'s "Go 1.22+" becomes "Go
  1.26+".
- **Recommended default: accept** (D1 implies it). Task 1 edits `CLAUDE.md` and Task 5 the
  `go.mod`.
- **The alternative** pins an older etcd with known fixes missing, and is not recommended.
- **The plan proceeds on the default.**

**Worth reading before the merge** (rulings, not open questions):
- **Ruling 11.** Until 7e, one port49d per keyspace, so etcd gives persistence and the
  foundation, not yet HA. A Kubernetes rollout must use `Recreate`: a surge pod waits for the
  hold and is not ready.
- **Ruling 12.** A port49d restart purges every unspent token, as it always did on the memory
  store. Operators run `port49 token` again after a restart. Their sessions survive.
- **Ruling 7.** A login whose index write fails is now refused (ERROR), not admitted unrevocable.
- **Ruling 11's stop.** When etcd is gone for longer than `hold_ttl`, port49d exits and devices fall
  to local: break-glass works. That is the owner's go-dark ruling in its coarse form, ahead of
  7f.

## What the operator sees

The owner's rule is to trace a mechanism on a bad day first. Every line below is printed by a
task in this plan, and the tests named pin it.

- **Install.** `port49d store-roles --config /etc/port49/port49d.yaml` prints the `etcdctl`
  commands, run once as etcd's root:

  ```
  # port49 roles for keyspace /port49/ (plan 7d). Run as etcd's root user, once.
  etcdctl role add port49_daemon
  etcdctl role grant-permission port49_daemon readwrite --prefix=true /port49/v1/t/
  …
  etcdctl role grant-permission port49_daemon read --prefix=true /port49/v1/rv/
  etcdctl role add port49_broker
  etcdctl role grant-permission port49_broker readwrite --prefix=true /port49/v1/
  etcdctl user add port49-daemon --no-password
  etcdctl user grant-role port49-daemon port49_daemon
  etcdctl user add port49-broker --no-password
  etcdctl user grant-role port49-broker port49_broker
  # then, if auth is not enabled yet: etcdctl user add root --no-password &&
  #   etcdctl user grant-role root root && etcdctl auth enable
  ```

  The user names are the CNs of the certificates the config names.
- **The roles were not applied, or auth is off.** port49d refuses:

  ```
  port49d: store.etcd: the daemon's identity (CN=port49-daemon) can read the broker's idempotency
  records under /port49/v1/id/: etcd's roles for port49 are not in force (auth disabled, or that
  user holds the broker's or root's role); run 'port49d store-roles --config …' and apply its
  output as etcd's root, or set store.etcd.roles: unenforced to run without them
  ```

  With `roles: unenforced` it starts, and says `port49d: store.etcd.roles: unenforced: the daemon
  and the broker are not separated on etcd; a stolen daemon key can lift revocations` at every
  start.
- **3am: etcd is down when port49d starts.** Nothing listens. Devices find TACACS+ refused and use
  their local method, so break-glass works (L4). Every 5 s port49d prints `port49d: store: etcd
  at https://etcd-0:2379, … not answering (context deadline exceeded); the listeners stay closed;
  waiting up to 30s`. Then `port49d: store: etcd at … did not answer within store.etcd.start_timeout
  (30s); not starting`, exit 1. systemd restarts it, and it waits again.
- **3am: etcd loses quorum, or is cut off from port49d, while port49d runs.**
  1. **The first commands** (up to `breaker.failures` per pool) wait out `call_timeout` and are
     answered FAIL `store_unavailable` within `store.packet_deadline`. L35 measures that a
     device prints L4-error's refusal there and never stalls as on a silent server. Logins are
     answered ERROR.
  2. **The circuit opens.** `port49d: store: the daemon's context pool's circuit is open after 5
     consecutive failures (store: unavailable: context deadline exceeded); each call on it fails
     at once until a probe in 5s succeeds; devices see store_unavailable, and break-glass is
     refused (L4); port49d stops if the store is gone for store.etcd.hold_ttl`. From then
     on, refusals are immediate. `port49_store_circuit_open{component,pool}` is 1.
  3. **Within `hold_ttl`, port49d stops:** `port49d: store: lost this port49d's hold on keyspace
     /port49/ (no answer from etcd for 15s); stopping so that devices use their local method;
     the service manager restarts port49d, which waits for etcd`. Devices find TACACS+ refused.
     Open sessions' commands fall to local authorization, measured with port49d stopped
     (`tests/lab/results/quarantine-*.md`), and break-glass logs in.
  4. **When etcd returns,** the restarted port49d takes the hold, says `port49d: store: purged 3
     unspent token(s) from before this start (run 'port49 token' again)`, and `port49d: store: 41
     live context(s) carried onto the policy in force (bundle sha256:…) before serving`. Then it
     listens. An open session's next command is answered from its context again (L35).
- **3am: etcd is slow, not down.** Calls over `call_timeout` fail as above. One that answers
  inside it is served. A sustained slowdown trips the circuit, and recovers with the probe.
- **A second port49d on the same keyspace** (a surge pod, a copy-pasted config): `port49d: store:
  keyspace /port49/ is held by port49d on core-aaa-1 (pid 4121, since 2026-10-02T03:00:00Z);
  waiting, with the listeners closed: one port49d per keyspace until plan 7e`, every 30 s.
- **A planned restart.** The memory store lost every session at a restart; etcd keeps them.
  Tokens are purged, and `port49 token` minted before the restart is refused `token_not_found`.
  A `port49 token` retried with the same idempotency key mints afresh.
- **A key rotation done wrong across a restart** (previous dropped while records it sealed
  live): `port49d: crypt: the store was last written by a port49d whose current key is "enc2",
  which this configuration does not hold (current "enc3", no previous); records sealed under
  enc2 will not open: live sessions on them end at their next command, and their tokens fail;
  set encryption.previous to enc2 until they expire`. `port49_crypt_store_key_unknown` is 1.
  While running, each unopenable record says `port49d: crypt: a token is sealed under key id
  "enc2", which this port49d does not hold (current "enc3", no previous)`, once per 10 minutes
  per key id.
- **A `port49 token` behind a slow `port49 revoke --mine`:** `port49 token: your revocation sent
  at 03:12:09 is still running on the broker; nothing was minted; run port49 token again once
  port49 revoke reports`. Exit 1. Before this plan it said `the broker … is unreachable`.
- **A revocation during an etcd outage** is still refused `503 store_unavailable` and revokes
  nothing (7c). It fails at once while the circuit is open, rather than after a timeout.

## Global Constraints

Copied verbatim from `CLAUDE.md`, "Code conventions", with OD-1 applied:

- Go 1.26+, module `github.com/rhwendt/port49`, `gofmt` and `go vet` clean, no cgo.
- **snake_case everywhere it is data**: YAML keys, JSON log keys, config, metric names.
- Reason codes are the closed vocabulary of spec §5.7 (`internal/decision/reasons.go`).
  Never invent one; add to the spec table first.
- The log never contains a token, password, challenge, or response. Credentials appear only
  as `credential_sha256`. An unvalidated body is never logged.
- No device identity in metric labels.
- Verify before claiming done: run `make test && make vet` and report the real output.

Carried from plans 2–7c, and still binding:

- **Every claim about device behaviour cites a `tests/lab/results/` note or a register row.** Lab
  register rules 1–4 apply. This plan opens L35 (Task 1) and closes it (Task 15). Until it
  closes, no doc asserts what a device does when the store hangs.
- **Security first:** no privilege escalation, no impersonation, no secret in a log, fail closed.
  Where a task leaves a choice, take the one that denies more and say so in the commit.
- **Narrow setters only for live contexts.** Nothing re-puts a context except `SwapLogin` (the
  login) and `PutContext` (seeding and tests).
- **7a's ordering holds for every revocation:** the mark first, tokens before contexts, contexts
  twice.
- **No reason code is added.** A timeout, an open circuit and a refused role are all
  `store_unavailable` on every event (spec §5.7).

New in this plan:

- **Store records are JSON with snake_case keys.** The etcd backend never marshals a `store` type
  whose fields lack tags; it converts to its own `*Rec` types (Task 5).
- **No metric label names a principal, device, key or endpoint.** The new labels are closed sets:
  `component` (`daemon`, `broker`), `pool` (`token`, `context`), and `outcome`.
- **Every read is linearizable.** Never `clientv3.WithSerializable()` (Ruling 4).
- **etcd's client logs never reach stderr.** Each client is built with `zap.NewNop()`, and port49d
  prints its own lines.
- **The code blocks are written against `9cefbba`.** Where the compiler or a test says a block is
  wrong about the tree or about etcd's API, fix the block minimally, keep the behaviour the step's
  test asserts, and say so in the task's report and commit. Never weaken a test to make a block
  pass.
- **Every commit is preceded by `gofmt -w` on the Go files the task touched, then `make build &&
  make test && make vet`.** Report their real output.
- **Branches.** 7d-1 is on `feature/shared-store-backend` and 7d-2 on
  `feature/shared-store-port49d`. Never commit code to `main`. Name every path in `git add`;
  never `git commit -a` (7a's 9e257ae).
- Commit messages end with:
  ```
  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
  ```

## Review Focus

The input classes the spec implies and no task's happy path exercises, most likely to bite first.
Each has its test in the task named.

1. **A store that hangs, rather than refuses, in the middle of a login.** The redeem committed,
   and the `SwapLogin` never answers. Whatever happens, the device hears ERROR
   `store_unavailable` within `store.packet_deadline`, never silence. No context is written
   half-indexed, and the device's retransmission replays the receipt.
   *Task 12, `TestAHungStoreAnswersWithinThePacketDeadline`.*
2. **A lease etcd no longer knows.** The cached bucket's lease expired while port49d was paused,
   or an operator revoked it. The next put retries once on a fresh lease and lands, and no record
   is written without one. *Task 5, `TestAPutOnALostLeaseTakesAFreshOne`.*
3. **Keys that look alike.** A principal that is the start of another (`user:al`, `user:alice`),
   and a device name, sid or certificate key holding `/` or `%`. Each lookup is exact on every
   backend. *Task 7, `storetest.IndexKeysAreExact`.*
4. **Two port49d against one keyspace, and a port49d whose hold lapses.** The second never binds
   TACACS+ while the first holds. The first, cut off past `hold_ttl`, stops and says why.
   *Task 12, `TestHoldIsOnePerKeyspaceAndLapses`, `TestASecondPort49dWaitsForTheKeyspace`,
   `TestAHungStoreAnswersWithinThePacketDeadline`.*
5. **A mark that lands between a login's read of the marks and its write.** The write conflicts,
   is decided again, and writes the context revoked. Neither a PASS nor an unrevoked context.
   *Task 3, `storetest.JoinHonoursAStandingMark`.*
6. **A daemon certificate that holds the broker's role, or etcd with auth off.** port49d refuses
   to start, naming the identity and the fix. *Task 11, `TestCheckIdentityRefusesADaemonWithTheBrokersReach`.*
7. **A guard whose caller gives up.** A device's connection drops mid-call. The breaker does not
   count it, and the slot is given back. *Task 9, `TestACallerThatGivesUpIsNotAFailure`.*

## Running the lab (Task 15)

The lab host is beehive. The owner has given standing consent for lab runs; the lab is
single-occupant.

**Every run is made from a detached worktree pinned to a commit:** `git worktree add --detach
../port49-lab-7d <sha>`, then `make build` there. Run one platform at a time:
`PORT49_LAB_PLATFORMS=eos`, then `nxos`, `iosxe`, `vjunos`.

**A stall watchdog runs for the whole run** (background, re-armed on every wake). Its signals are
the test log, capture growth and results files, with a 25-minute stall threshold. Match the test
binary exactly: `pgrep -f "^/tmp/go-build[^ ]*/lab\.test"`.

**After every platform,** confirm that no `port49d` holds `172.100.100.1:49`, that no agent is
running (`pgrep -f 'port49 agent'`), and that the topology is destroyed. The embedded etcd dies
with the test process: confirm with `ss -ltnp | grep -c lab.test`, which must print 0.

**Before removing the worktree,** copy the raw captures from its `tests/lab/captures/` to the main
checkout's `tests/lab/captures/`, then run `make evidence` there. Otherwise main's labpcap audit
fails.

## File Structure

```
docs/design/2026-08-23-policy-engine-spec.md   MOD  d35; d24 amended; §5.1.4, §5.7, §12, §14; L35 (Task 1); L35 closed (Task 15)
docs/design/2026-08-21-port49-design.md        MOD  §12 matrix, Consequences, interface; §13; §15; §17; §19 (Task 1)
CLAUDE.md                                      MOD  Go 1.26+ (Task 1, OD-1)
internal/store/storetest/storetest.go          MOD  Backend, Run; JoinContext's new argument (Task 2, 3)
internal/store/storetest/lifted.go             NEW  the memory store's properties, for every backend (Task 2)
internal/store/storetest/login.go              NEW  SwapLoginIsOneStep, LoginsRaceToOneIndex, JoinHonoursAStandingMark,
                                                    PurgeTakesEveryToken, SelfRevocationBindsToTheRead (Task 3); IndexKeysAreExact (Task 7)
internal/store/memory/memory_test.go           MOD  lifted tests removed; Run (Task 2)
internal/store/crypt/crypt_test.go             MOD  Run through the sealing layer (Task 2)
internal/store/store.go                        MOD  ErrUnavailable, BlankCertKey, CheckRevocation, MarkRead, LoginWrite,
                                                    SwapLogin, PurgeTokens (Task 3)
internal/store/join.go                         MOD  LoginIndex; JoinContext reads marks and writes through SwapLogin (Task 3)
internal/store/memory/memory.go                MOD  SwapLogin, PurgeTokens, *Locked index helpers (Task 3)
internal/store/crypt/crypt.go                  MOD  SwapLogin, PurgeTokens (Task 3); OnUnopenable, SealedKeyID (Task 13)
internal/daemon/authen/authen.go               MOD  the join with its index; no separate index calls (Task 4)
internal/daemon/authen/authen_test.go          MOD  noStore; tests of the one step (Task 4)
go.mod, go.sum                                 MOD  go 1.26; etcd client, embed (Task 5)
internal/store/etcd/etcd.go                    NEW  Config, Open, Store, Close, Ping, unavailable (Task 5); two clients (Task 11)
internal/store/etcd/keys.go                    NEW  the key schema (Task 5)
internal/store/etcd/records.go                 NEW  snake_case records and conversions (Task 5)
internal/store/etcd/leases.go                  NEW  lease buckets (Task 5)
internal/store/etcd/commit.go                  NEW  commit, cas (Task 5)
internal/store/etcd/tokens.go                  NEW  tokens, receipts, token index, PurgeTokens (Task 5)
internal/store/etcd/marks.go                   NEW  revocation marks (Task 5)
internal/store/etcd/contexts.go                NEW  contexts, blobs, the index record's writes, SwapLogin (Task 6)
internal/store/etcd/indexes.go                 NEW  lookups, active principals, Sweep (Task 7)
internal/store/etcd/idempotency.go             NEW  reservation (Task 8)
internal/store/etcd/notbuilt.go                NEW→DEL  methods later tasks build (Tasks 5–8)
internal/store/etcd/etcd_test.go               NEW  TestMain; storetest on etcd; the planting store; backend-only tests (Tasks 5–8)
internal/store/etcd/etcdtest/etcdtest.go       NEW  Main, Prefix, Client, Start, EnableAuth, StartCluster, NewProxy (Task 5)
internal/store/etcd/roles.go, roles_test.go    NEW  Roles, CheckIdentity (Task 11)
internal/store/etcd/meta.go, meta_test.go      NEW  Hold (Task 12); SealKeys (Task 13)
internal/store/guard/guard.go                  NEW  Wrap, pools, breaker (Task 9)
internal/store/guard/guard_test.go             NEW  (Task 9)
internal/daemon/metrics/metrics.go             MOD  store_calls_total, store_circuit_open, store_call_seconds,
                                                    store_keyspace_held, crypt_store_key_unknown (Tasks 9, 12, 13)
internal/config/config.go                      MOD  StoreConfig, EtcdConfig, StoreOf; checks (Task 10)
internal/config/store_test.go                  NEW  (Task 10)
internal/daemon/server/server.go, conn.go      MOD  Deps.PacketDeadline (Task 10)
cmd/port49d/store.go                           NEW  openStores, the hold, the start wait, sweepLoop (Task 12); the crypt line, seal keys (Task 13)
cmd/port49d/storeroles.go, storeroles_test.go  NEW  port49d store-roles (Task 11)
cmd/port49d/main.go                            MOD  deps.PacketDeadline (Task 10); store-roles dispatch (Task 11);
                                                    openStores, purge, RefreshAtStart, hold loss (Task 12)
cmd/port49d/store_e2e_test.go                  NEW  (Task 12)
cmd/port49d/store_test.go                      NEW  (Task 13)
internal/broker/broker.go, refresh.go          MOD  SupersededAll; RefreshAtStart (Task 12)
internal/agent/agent.go, socket.go             MOD  the wire slot; RevocationRunningError; 503 revocation_running (Task 14)
tests/lab/store_test.go                        NEW  L35 (Task 15)
tests/lab/results/L35-*.md                     NEW  written by the run (Task 15)
docs/superpowers/plans/README.md               MOD  plan 7d as built (Task 16)
```

Sixteen tasks in two merges:
- **7d-1:**
  - **Task 1** is docs, and comes first: every later task cites the text it writes.
  - **Tasks 2–4** are the store's contract and its one behaviour change (the login).
  - **Tasks 5–8** are the etcd backend.
- **7d-2:**
  - **Tasks 9–14** are code: the guard, the config, the identities, port49d on etcd, the crypt
    alarm, the agent.
  - **Task 15** is the lab, and gates the merge.
  - **Task 16** is docs: plan 7d as built.

---

# Part 7d-1: the backend (`feature/shared-store-backend`, off `main`)

### Task 1: The spec and the design say what plan 7d builds

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`
- Modify: `docs/design/2026-08-21-port49-design.md`
- Modify: `CLAUDE.md` (OD-1)

**Interfaces:** none. Every later task cites the text this one writes.

No code. Each edit names a phrase to find and the text to put after it or in its place: the files
wrap their lines, so search for a phrase rather than a whole sentence. Nothing here asserts what
a device does when the store hangs. That is L35, which this task opens and Task 15 closes.

- [ ] **Step 1: Decision 35.** In spec §13, after decision 34's closing line `(§2, §5.1.3, §5.1.4,
  §5.7, §12, §14; design document §12, §17)` and before `### Deferred, with reasons`, add:

  ```markdown
  **35. The shared store is etcd, every read is linearizable, a login lands with its index and
  its revocation check in one step, and a store that does not answer is a store that is down.**
  *Plan 7d, 2026-10-02: D1 answered by the owner (etcd); the rest rulings where the design was
  silent, each the option that denies more.*

  - **Backend.** etcd v3.6. Every acknowledged write survives a leader failover (Raft), so a
    redeemed token never comes back and a revocation mark is never lost. Every read is
    linearizable: a member cut off from the quorum answers nothing, never a stale context. The
    interface stays pluggable; a backend whose replication is asynchronous (Valkey, Redis) is
    acceptable only with its replay window stated (design document §13).
  - **Expiry.** Each record carries its own expiry and is read against port49d's clock; etcd's
    leases only reclaim, at least `store.etcd.lease_grace` (5m) later. A revocation mark carries
    no lease, and never expires.
  - **The login is one step.** A login's context write, its index entries, and a check that no
    revocation mark stands for its principal or its certificate that was not there when it
    read, are one transaction. A mark that stands, for a token not minted after it, is written
    into the context as its revocation, and the login is refused `credential_revoked`. So a
    context is never live and unindexed, and a redemption racing a revocation by principal or
    certificate writes its context revoked or is reached by the revocation's second pass. A
    login whose index cannot be written is refused ERROR `store_unavailable` (it was a PASS with
    `index_error`). A self or key revocation leaves no mark, so its window of one round trip
    stays (§5.1.4).
  - **Hard timeouts and a circuit per pool.**
    - **Per call.** Every store call has its own deadline (`store.etcd.call_timeout`, 500ms).
    - **Per packet.** Every TACACS+ packet's store work has one too (`store.packet_deadline`,
      2s, at most 4s), so a device hears `store_unavailable` before its own timeout, and a
      redemption's write lands inside the policy refresh's 30s settle pass.
    - **The circuit.** After `breaker.failures` (5) consecutive failures, a pool's circuit opens
      for `breaker.open_for` (5s) and then lets one call probe.
    - **No queue.** A call that cannot get an in-flight slot within its deadline is refused,
      never queued.
    - **Pools.** Token and context operations use separate connections and slots (design
      document §12).
  - **Identity.** Each component authenticates to etcd by its own client certificate, its CN
    etcd's user, under the roles `port49d store-roles` prints. The daemon's role cannot read
    idempotency records, write the token indexes, or write revocation marks. port49d refuses to
    start when its daemon identity can read the broker's records, unless `store.etcd.roles:
    unenforced`, said at every start.
  - **One port49d per keyspace until plan 7e.**
    - **The hold.** port49d holds the keyspace on an etcd lease of `store.etcd.hold_ttl` (15s).
      A second port49d waits for it, its listeners closed.
    - **Losing it.** A port49d that loses its hold stops, so devices find the connection refused
      and use their local method: the owner's go-dark ruling of 2026-09-24 in its coarse form,
      which plan 7f refines.
  - **A start on etcd.** port49d waits for the store with every listener closed (up to
    `store.etcd.start_timeout`, 30s, then exits 1), and then:
    1. puts the revocations file's marks into the store (a mark in either stands);
    2. deletes every unspent token, as a restart always did, and marks every key superseded, so
       an idempotent replay mints again;
    3. carries the policy in force into every live context the store kept;
    4. binds TACACS+.

    Live contexts survive a restart (what a device then sees: §15 L35).
  - **Keys.** A record sealed under a key outside the window is said by its key id. A start
    whose store was last sealed under a current key this window lacks warns
    (`port49_crypt_store_key_unknown`), and never refuses: those records fail closed already.

  (§5.1.4, §5.6, §5.7, §12, §14, §15; design document §8, §12, §13, §15, §17)
  ```

- [ ] **Step 2: Decision 24, amended for etcd.** In decision 24 replace `A restart ends every live
  context and every unspent token, so without a live reload` with `A restart ends every live
  context and every unspent token on the memory store (on etcd, plan 7d, it ends every unspent
  token and keeps the contexts; decision 35), so without a live reload`.

- [ ] **Step 3: §5.1.4, the residual window.** Replace

  ```markdown
  A redemption that
  removed its token before the delete and writes its context after the second pass is a window of one
  store round trip, which the shared store (plan 7d) closes atomically.
  ```

  (find `which the shared store (plan 7d) closes atomically`) with

  ```markdown
  A redemption that
  removed its token before the delete and writes its context after the second pass writes it
  revoked: a login's context write checks, in the same atomic step, that no mark stands for its
  principal or its certificate (plan 7d; §13, decision 35), and the mark is written before
  anything else. A self or key revocation leaves no mark, so for those the window of one store
  round trip stays.
  ```

- [ ] **Step 4: §5.7, `store_unavailable`.** In the `store_unavailable` row replace `port49d will
  do this itself by closing its TACACS+ listener while the store is unhealthy (owner's ruling
  2026-09-24; arrives with the remote store, plan 7).` with:

  ```markdown
  port49d will do this itself by closing its TACACS+ listener while the store is unhealthy
  (owner's ruling 2026-09-24; plan 7f). On etcd (plan 7d) it already stops when it has lost its
  hold on the store for `store.etcd.hold_ttl`, and before then a store that does not answer, or a
  pool's open circuit, is answered within `store.packet_deadline`, never left for the device to
  time out (what each image does then: §15 L35).
  ```

- [ ] **Step 5: §12, `port49d store-roles`.** After the `port49d init-revocations` paragraph
  (ending `init-revocations is running or has just run; nothing written); 2 on usage.`) add:

  ```markdown
  **`port49d store-roles [--config <port49d.yaml>]`** prints the `etcdctl` commands that create
  port49's two etcd roles and grant them, for the keyspace `store.etcd.prefix` names (plan 7d;
  §13, decision 35): `port49_daemon`, read-write on the token, receipt, context, index and blob
  records and read-only on revocation marks, and `port49_broker`, read-write on the whole
  keyspace; then a user per component, named by the CN of the certificate `store.etcd.daemon` and
  `store.etcd.broker` name, granted its role. It reads the config and those certificates, holds
  no etcd credential, changes nothing, and exits 0, or 1 naming what it could not read; 2 on usage.
  The output is run once, by etcd's root user.
  ```

- [ ] **Step 6: §14, the store's assertions.** Before `---` and `## 15. Lab register`, after the
  `**Scoping**` list, add:

  ```markdown
  **Shared store** (plan 7d; §13, decision 35)

  - **Every backend, every property**: each `storetest` property passes against the memory
    store, the sealing layer over it, the etcd backend, and the sealing layer over etcd.
  - **The login is one step**: a login replacing another principal's context leaves it indexed
    under the new login's keys alone, whatever lands concurrently; a revocation mark that appears
    between a login's read and its write makes the write conflict and land revoked.
  - **Quorum lost**: with two of three etcd members stopped, a store call fails with
    `store.ErrUnavailable` within its deadline, never answers from a stale member.
  - **A restart on etcd**: a live context's next authorization is answered from it, an unspent
    token from before the restart is `token_not_found`, and a second port49d against the
    keyspace binds no listener.
  ```

- [ ] **Step 7: L35, opened.** In the §15 table, after the L34 row, add:

  ```markdown
  | **L35** | What a device does when port49d's store hangs rather than refuses — etcd cut off from port49d, or past its quorum: whether port49d's `FAIL` (a command) and `ERROR` (a login) reach it before its own TACACS+ timeout, so it acts as on L4's store outage (`tests/lab/results/L4-error-*.md`) and never as on a silent server; what it does once port49d stops on losing its hold on the store; and, after the store returns and port49d restarts, whether an open session's next command is answered from its context. | `store.packet_deadline`'s default and bound, and the store rows of the failure model (§13, decision 35; design document §12) | EOS, NX-OS, IOS-XE, Junos | open — plan 7d Task 15 |
  ```

- [ ] **Step 8: The design's failure matrix.** In design §12's table:
  - In the **Token store unavailable** row replace `port49d will do this itself by closing its
    TACACS+ listener while the store is unhealthy (owner's ruling 2026-09-24; arrives with the
    remote store, plan 7). Continuing active logins from a replica's warm context cache through a
    store outage arrives with the remote store (plan 7)` with `port49d will do this itself by
    closing its TACACS+ listener while the store is unhealthy (owner's ruling 2026-09-24; plan
    7f); on etcd it stops once it has lost its hold on the store (the rows below). Continuing
    active logins from a replica's warm context cache through a store outage is plan 7f's`.
  - After that row add three rows:

  ```markdown
  | **Store hangs or loses quorum** (etcd cut off from port49d, two of three members down; plan 7d) | ✓ `port49 login` touches no store | ✗ ERROR `store_unavailable` within `store.packet_deadline`; once a pool's circuit opens, at once | ✗ FAIL `store_unavailable` within `store.packet_deadline` (what each image does then: policy engine spec §15 L35), then, `store.etcd.hold_ttl` after the store stopped answering, port49d stops and the device falls to its local method as with port49d stopped; when etcd returns and port49d restarts, the session's next command is answered from its context | ✗ |
  | **Store unreachable at start** (plan 7d) | ✓ | ✗ → device-local break-glass: nothing listens while port49d waits `store.etcd.start_timeout`, then exits 1 for its supervisor to restart | ✗ local authorization, as with port49d stopped | ✗ |
  | **port49d restarted on etcd** (plan 7d) | ✓ | ✓ a token minted before the restart is `token_not_found` (purged); `port49 token` again | ✓ answered from the context the store kept, carried onto the policy in force before TACACS+ binds | ⚠ tokens not yet spent are refused; an idempotent retry mints again |
  ```

- [ ] **Step 9: The design's Consequences.** In design §12 "Consequences":
  - After the **Connection pool separation** bullet (ending `so mint pressure cannot starve
    authorization.`) add:

    ```markdown
    - **As built on etcd (plan 7d; policy engine spec §13, decision 35).** Each store call has
      `store.etcd.call_timeout` (500ms), and each TACACS+ packet's store work
      `store.packet_deadline` (2s). The token and context pools are each their own etcd
      connection with their own in-flight cap (`store.etcd.max_in_flight`) and circuit
      (`store.etcd.breaker`: open after 5 consecutive failures, for 5s, then one probe). A call
      that cannot get a slot within its deadline is refused. A failure is a timeout or an etcd
      error that is not a refusal by the roles; a caller that gave up is none. The warm context
      cache stays plan 7f's.
    ```
  - In the readiness paragraph replace `It arrives with the remote store (plan 7).` with `It is
    plan 7f's; on etcd, plan 7d already stops port49d when it loses its hold on the store, so
    devices find the connection refused (policy engine spec §13, decision 35).`

- [ ] **Step 10: The design's store interface.** In design §12 "Store interface":
  - After the requirement paragraph (ending `separation is by *operation* per identity, not by
    key prefix.`) add:

    ```markdown
    **A login's context write is one atomic operation with its index entries and its revocation
    check** (plan 7d): the context, the index change its join decided (clear the ref, drop a sid
    or certificate, add the login's), and the revocation marks the login read for its principal
    and its certificate land together, only while the context, the ref's index record and those
    marks are as read. A context is therefore never live and unindexed, and a redemption racing
    a revocation by principal or certificate writes its context revoked.
    ```
  - After the paragraph ending `so the daemon can be integration-tested as a single binary with
    no external services.` add:

    ```markdown
    **etcd (plan 7d).** Each record is one key under `store.etcd.prefix` + `v1/`, its value JSON
    with snake_case keys, and every compare-and-set a transaction on the key's `mod_revision`;
    the context's `Rev` is that revision, and `PolicyRev` comes from the same counter. Expiry is
    the record's, read against port49d's clock; a lease (one per minute bucket) reclaims a key at
    least `lease_grace` after it, and a revocation mark carries none. A ref's index record
    (`x/<nas>/<user>`) is authoritative; the lookup entries under a principal, a sid or a
    certificate find candidates, are filtered against it, and are removed by a sweep once
    unlisted. Every read is linearizable. Leases are never kept alive: a record's lease is
    chosen at each write.
    ```

- [ ] **Step 11: The design's deployment requirements.** In design §13, after the paragraph ending
  `a cross-region read alone can consume the entire budget.` add:

  ```markdown
  **etcd (plan 7d).** Three or five members in the region the devices are in, with:
  - **Client authentication.** `--client-cert-auth` and auth enabled, and a root user, which
    port49d never holds. port49's two roles and users are created from `port49d store-roles`'s
    output.
  - **Compaction.** `--auto-compaction-mode=periodic` with `--auto-compaction-retention=1h`,
    since every login and touch writes a revision, and a defragmentation schedule.
  - **Quota.** `--quota-backend-bytes` sized above the live record set (records are a few
    hundred bytes; a blob a few kilobytes).
  - **One keyspace per port49d until plan 7e.** A Kubernetes rollout must therefore stop the old
    pod first (`Recreate`), because a surge pod waits for the keyspace and is not ready.
  - **Backups.** Back etcd up as a database holding the revocation marks: until plan 7e retires
    it, `broker.revocations_file` is kept as well.
  ```

- [ ] **Step 12: The design's observability.** In design §15, after the paragraph beginning `The
  broker exports:` add:

  ```markdown
  The store (plan 7d) exports `port49_store_calls_total{component,pool,outcome}`,
  `port49_store_call_seconds{component,pool}`, `port49_store_circuit_open{component,pool}` (the
  circuit-breaker state the paragraph above requires), `port49_store_keyspace_held`, and
  `port49_crypt_store_key_unknown`. Alert on a circuit open, on the hold not held while port49d
  runs, on `port49_crypt_store_key_unknown` at 1, and on any increase of
  `port49_crypt_open_failures_total{record="token"}`: a token that will not open is dropped from
  its candidates with no error, so that counter is the only witness that a rotation retired a key
  while tokens it sealed were live (plan 2).
  ```

- [ ] **Step 13: The design's internal interfaces.** In design §17's table, replace the cell
  `store-native auth over TLS` with `store-native auth over TLS: on etcd, a client certificate per
  component, its CN etcd's user, under port49's roles (\`port49d store-roles\`; policy engine spec
  §13, decision 35)`. In the paragraph `The token store is the one place where a password may still
  exist`, append: `On etcd it is none: each component's client certificate is its identity.`

- [ ] **Step 14: The design's sequencing.** In §19 step 2 replace `a store two processes can reach
  is owed before the broker becomes a process of its own (step 7).` with `a store two processes
  can reach is owed before the broker becomes a process of its own (step 7), and is built by plan
  7d on etcd.`

- [ ] **Step 15: `CLAUDE.md` (OD-1).** Replace `Go 1.22+, module` with `Go 1.26+ (etcd's floor,
  plan 7d), module`.

- [ ] **Step 16: Check, then commit.**

  Run: `grep -c 'decision 35' docs/design/2026-08-23-policy-engine-spec.md` — expect at least 6.
  Run: `grep -n '| \*\*L35\*\*' docs/design/2026-08-23-policy-engine-spec.md` — expect one line,
  status `open`. Run `make test` (docs only; it must stay green, the labpcap audit included).

  ```bash
  git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md CLAUDE.md
  git commit -m "docs: the shared store is etcd, and a login is one step (decision 35, L35 opened)

  Spec §13 decision 35 records D1 (etcd, the owner's) and plan 7d's
  rulings; decision 24 says what a restart keeps on etcd; §5.1.4 closes
  the residual window for marked revocations; §5.7 and design §12 say
  what a hung store answers; §12 gains port49d store-roles; §14 its
  assertions; §15 opens L35. CLAUDE.md's Go floor is 1.26 (OD-1).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 2: Every property the memory store holds is a `storetest` property

**Files:**
- Modify: `internal/store/storetest/storetest.go`
- Create: `internal/store/storetest/lifted.go`
- Modify: `internal/store/memory/memory_test.go`
- Modify: `internal/store/crypt/crypt_test.go`
- Modify: `internal/store/join_test.go`

**Interfaces:**
- Consumes: the existing properties, as they are.
- Produces:
  - `type storetest.Backend struct { New func(t *testing.T, clock func() time.Time) store.Store }`
  - `func storetest.Run(t *testing.T, b Backend)`. It runs every property, each as a subtest
    named after it. Later tasks add to it.
  - `func storetest.Rw(rk store.ReceiptKey, r store.Receipt, principal string) store.ReceiptWrite`,
    which the memory store's own tests used as `rw`.
  - One exported property per lifted test, `func X(t *testing.T, b Backend)`, named in Step 2's
    table.

**Why:** 7d's backend must hold every property the memory store holds. Twenty-eight of those live
only in `memory_test.go`, where they test the memory store and nothing else. Lifted, they run on
every backend, including the sealing layer over memory (which nothing tested them through) and,
from Task 5, etcd.

- [ ] **Step 1: The runner.** Append to `internal/store/storetest/storetest.go`:

  ```go
  // Backend is a store.Store implementation the properties run against. New
  // returns a fresh, empty store whose clock is clock; a property moves time
  // by changing what clock returns. A store that is also a Planter gets
  // IdempotencyReservesOnce's holderless case.
  type Backend struct {
  	New func(t *testing.T, clock func() time.Time) store.Store
  }

  // t0 is the instant the fixed-clock properties run at: far from the wall
  // clock on purpose, so a backend that reads time.Now where it should read
  // its clock fails.
  var t0 = time.Unix(1_000_000, 0).UTC()

  // Run runs every property against b, each as its own subtest.
  func Run(t *testing.T, b Backend) {
  	fixed := func(t *testing.T) func() store.Store {
  		return func() store.Store { return b.New(t, func() time.Time { return t0 }) }
  	}
  	for _, p := range []struct {
  		name string
  		run  func(*testing.T)
  	}{
  		{"JoinRacesRevocation", func(t *testing.T) { JoinRacesRevocation(t, fixed(t), t0) }},
  		{"PolicyRevision", func(t *testing.T) { PolicyRevision(t, fixed(t), t0) }},
  		{"RevocationIsMonotonic", func(t *testing.T) { RevocationIsMonotonic(t, fixed(t), t0) }},
  		{"IdempotencyReservesOnce", func(t *testing.T) { IdempotencyReservesOnce(t, fixed(t), t0) }},
  		{"IdempotencyLeaseExpires", func(t *testing.T) {
  			IdempotencyLeaseExpires(t, func() (store.Store, func(time.Duration)) {
  				var mu sync.Mutex
  				now := t0
  				s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
  				return s, func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
  			}, t0)
  		}},
  		{"TokenIndex", func(t *testing.T) { TokenIndex(t, fixed(t), t0) }},
  		{"DeleteTokenRemovesOne", func(t *testing.T) { DeleteTokenRemovesOne(t, fixed(t), t0) }},
  		{"DeleteTokenRacesRedeem", func(t *testing.T) { DeleteTokenRacesRedeem(t, fixed(t), t0) }},
  		{"RevocationMarks", func(t *testing.T) { RevocationMarks(t, fixed(t), t0) }},
  		{"CeilingShortensOnly", func(t *testing.T) { CeilingShortensOnly(t, fixed(t), t0) }},
  		{"RefreshSetsTheCeiling", func(t *testing.T) { RefreshSetsTheCeiling(t, fixed(t), t0) }},
  		{"RefreshStopsAtGrace", func(t *testing.T) { RefreshStopsAtGrace(t, fixed(t), t0) }},
  		{"WritesBindToTheRevision", func(t *testing.T) { WritesBindToTheRevision(t, fixed(t), t0) }},
  	} {
  		t.Run(p.name, p.run)
  	}
  	for _, p := range lifted {
  		p := p
  		t.Run(p.name, func(t *testing.T) { p.run(t, b) })
  	}
  }
  ```

  Add `"sync"` to the imports if it is not there (it is, for the races).

- [ ] **Step 2: Lift the tests.** Create `internal/store/storetest/lifted.go`. It holds the
  `lifted` table and, for each row below, the memory test's body as an exported function `func
  <Property>(t *testing.T, b Backend)`. Move each body **verbatim**, with these substitutions and
  no others:
  - `New(func() time.Time { return now })` becomes `b.New(t, func() time.Time { return now })`.
    Any other `New(clock)` becomes `b.New(t, clock)`.
  - `New(time.Now)` becomes `b.New(t, func() time.Time { return t0 })`, and each `time.Now()`
    read in that test becomes `t0`. A fixed clock in place of the wall clock changes nothing the
    test asserts. It makes the test mean the same thing on a backend whose expiry is its clock's.
  - `rw(` becomes `Rw(`. Move the helper too, as `func Rw(rk store.ReceiptKey, r store.Receipt,
    principal string) store.ReceiptWrite`, with its body unchanged.
  - A comment that names the memory store's internals ("the map", "the lock") is reworded to say
    the store. The assertion stays as it is.

  | memory test (`internal/store/memory/memory_test.go`) | property |
  |---|---|
  | `TestTokenLifecycle` | `TokenLifecycle` |
  | `TestRedeemIsAtomicUnderRace` | `RedeemIsAtomic` |
  | `TestContextTTL` | `ContextExpires` |
  | `TestSecretsAreNotAliased` | `SecretsAreNotAliased` |
  | `TestDeleteContext` | `DeleteContextRemovesIt` |
  | `TestRedeemByID` | `RedeemByID` |
  | `TestReceiptRetainedPastItsSlidingBound` | `ReceiptRetainedPastItsSlidingBound` |
  | `TestFailReceiptMarksTheReceiptAndNothingElse` | `FailReceiptMarksOnly` |
  | `TestDeleteReceiptsByPrincipal` | `DeleteReceiptsByPrincipal` |
  | `TestTouchContextExtendsWithoutClobbering` | `TouchExtendsWithoutClobbering` |
  | `TestAnnotateContextKeepsARacingRevocation` | `AnnotateKeepsARacingRevocation` |
  | `TestSetRevokedAtMarksOneFieldAndDoesNotExtend` | `SetRevokedAtMarksOneField` |
  | `TestRefreshContextMovesTheWindowAndKeepsTheRest` | `RefreshMovesTheWindow` |
  | `TestExtendingAContextCarriesItsIndexEntries` | `ExtendingCarriesIndexEntries` |
  | `TestExtendingNeverShortensOrCreatesAnIndexEntry` | `ExtendingNeverShortensOrCreates` |
  | `TestExtendingFollowsARotatedSid` | `ExtendingFollowsARotatedSid` |
  | `TestRefreshContextWithoutCeilingLeavesNoCeiling` | `RefreshWithoutCeiling` |
  | `TestAnnotateContextSetRules` | `AnnotateSetRules` |
  | `TestAnnotateContextDoesNotEditAReadersSlice` | `AnnotateDoesNotEditAReadersSlice` |
  | `TestBlobBump` | `BlobBump` |
  | `TestIndexes` | `Indexes` |
  | `TestIdempotency` | `Idempotency` |
  | `TestSwapContextIsACompareAndSet` | `SwapIsACompareAndSet` |
  | `TestEveryContextWriteMovesTheRevision` | `EveryWriteMovesTheRevision` |
  | `TestExtendingCarriesEveryJoinedLoginsSidAndCert` | `ExtendingCarriesEveryJoinedCredential` |
  | `TestSetPrivilegeIsRaiseOnlyAndClamped` | `SetPrivilegeIsRaiseOnly` |
  | `TestAnEmptySidOrCertificateIsNeverIndexed` | `BlankKeysAreNeverIndexed` |
  | `TestUnindexRefClearsEveryKeyRecordedForTheRef` | `UnindexRefClearsEveryKey` |
  | `TestSetContextPolicyWritesItsListOnlyIfTheRecordIsTheOneRead` | `SetContextPolicyBindsToTheRead` |
  | `TestATokenIndexEntryExpiresWithItsLongestToken` | `TokenIndexExpiresWithItsLongestToken` |
  | `TestARevocationMarkNeverExpires` | `RevocationMarkNeverExpires` |

  The table in the file:

  ```go
  // lifted are the properties the memory store's own tests held until plan
  // 7d, each now run against every backend (Run).
  var lifted = []struct {
  	name string
  	run  func(*testing.T, Backend)
  }{
  	{"TokenLifecycle", TokenLifecycle},
  	{"RedeemIsAtomic", RedeemIsAtomic},
  	// … one row per line of the table above, in its order.
  }
  ```

  Write every row out; there are thirty-one. These four memory tests stay where they are, because
  they read the memory store's internals and test it alone: `TestSweepDropsExpiredKeys`,
  `TestCompactionZeroesTheTail`, `TestRedeemZeroesTheSpentToken` and
  `TestSetPrivilegeWritesTheLevelAndNothingElse`. Its `planting` type stays too.

- [ ] **Step 3: The memory store runs them through `Run`.** In `memory_test.go`, delete the moved
  tests, the `rw` helper (replace its remaining callers with `storetest.Rw`), and every
  single-property caller (`TestPolicyRevisionOnTheMemoryStore` through `TestWritesBindToTheRevision`,
  lines 1369–1466 at `9cefbba`). Add:

  ```go
  // Every storetest property, against the memory store; a planting store, so
  // IdempotencyReservesOnce plants its holderless record.
  func TestTheMemoryStoreHoldsEveryProperty(t *testing.T) {
  	storetest.Run(t, storetest.Backend{New: func(_ *testing.T, clock func() time.Time) store.Store {
  		return planting{New(clock)}
  	}})
  }
  ```

  In `internal/store/join_test.go`, delete `TestJoinRacesRevocationOnTheMemoryStore` (line 430):
  `Run` holds it now.

- [ ] **Step 4: The sealing layer runs them too.** In `crypt_test.go`, delete the single-property
  callers (`TestPolicyRevisionThroughTheSealingLayer` through
  `TestWritesBindToTheRevisionThroughTheSealingLayer`), and add:

  ```go
  // Every storetest property through the sealing layer over memory: what the
  // layer passes through, it must not change.
  func TestTheSealingLayerHoldsEveryProperty(t *testing.T) {
  	storetest.Run(t, storetest.Backend{New: func(_ *testing.T, clock func() time.Time) store.Store {
  		return Wrap(memory.New(clock), testKeys(t), nil)
  	}})
  }
  ```

  Use the key helper the file already has. If its name differs from `testKeys`, use that name.
  This is the first time the lifted properties run through the sealing layer. A property that
  fails here is a finding: report it with the failure, fix the layer if the layer is wrong, and
  never skip the property.

- [ ] **Step 5: Run.**

  Run: `go test ./internal/store/... -count=1`
  Expected: PASS, including `TestTheMemoryStoreHoldsEveryProperty/<each>` and
  `TestTheSealingLayerHoldsEveryProperty/<each>`. Count the subtests: `go test
  ./internal/store/memory/ -run TestTheMemoryStoreHoldsEveryProperty -v -count=1 | grep -c '^    ---
  PASS'` must be 44 (13 + 31).

- [ ] **Step 6: Commit.**

  ```bash
  gofmt -w internal/store/storetest internal/store/memory internal/store/crypt internal/store/join_test.go
  make build && make test && make vet
  git add internal/store/storetest/storetest.go internal/store/storetest/lifted.go \
    internal/store/memory/memory_test.go internal/store/crypt/crypt_test.go internal/store/join_test.go
  git commit -m "test(store): every property the memory store holds is a storetest property

  Thirty-one memory-only tests move into storetest, verbatim but for the
  store they are given; storetest.Run runs every property, and the memory
  store and the sealing layer each run it whole. Plan 7d's etcd backend
  runs the same suite.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 3: The store contract plan 7d needs: one step for a login, and a purge

**Files:**
- Modify: `internal/store/store.go`
- Modify: `internal/store/join.go`
- Modify: `internal/store/memory/memory.go`
- Modify: `internal/store/crypt/crypt.go`
- Create: `internal/store/storetest/login.go`
- Modify: `internal/store/storetest/storetest.go` (`Run`; `JoinContext`'s new argument)
- Modify: `internal/store/storetest/lifted.go` (`JoinContext`'s new argument, where called)
- Modify: `internal/daemon/authen/authen_test.go` (`noStore` gains the two methods, so the tree
  builds)
- Test: `internal/store/join_test.go`

**Interfaces:**
- Consumes: `store.JoinContext`, `store.Joinable`, `store.Join`, `store.CarryRevocation`.
- Produces:
  - `var store.ErrUnavailable = errors.New("store: unavailable")`
  - `func store.BlankCertKey(certKey string) bool`
  - `var store.ErrIncompleteMark` and `func store.CheckRevocation(r Revocation) error`
  - `type store.MarkRead struct { Kind, Key string; At time.Time }`
  - `type store.LoginWrite struct { ClearRef bool; DropSid, DropCertKey string; Principal, Sid, CertKey string; IndexTTL time.Duration; Marks []MarkRead }`
  - `Store.SwapLogin(ctx context.Context, k ContextKey, rev uint64, c Context, ttl time.Duration, w LoginWrite) error`
  - `Store.PurgeTokens(ctx context.Context) (int, error)`
  - `type store.LoginIndex struct { Principal, Sid, CertKey string; TTL time.Duration }`
  - `func store.JoinContext(ctx context.Context, s Store, k ContextKey, login Context, mintedAt, now time.Time, ttl time.Duration, ix LoginIndex) (JoinResult, error)`
  - storetest: `SwapLoginIsOneStep`, `LoginsRaceToOneIndex`, `JoinHonoursAStandingMark`,
    `PurgeTakesEveryToken`, `SelfRevocationBindsToTheRead`, each `func(t *testing.T, b Backend)`
    and in `Run`.

- [ ] **Step 1: The failing properties.** Create `internal/store/storetest/login.go`:

  ```go
  package storetest

  import (
  	"context"
  	"errors"
  	"fmt"
  	"sync"
  	"testing"
  	"time"

  	"github.com/rhwendt/port49/internal/store"
  )

  // loginOf is a login's context and the index it writes, for principal on
  // ref under sid and the certificate (issuer "CN=Corp CA", serial).
  func loginOf(principal, sid, serial string, now time.Time) (store.Context, store.LoginIndex) {
  	c := store.Context{CtxID: "ctx_" + sid, Principal: principal, Username: "svc", PrivLvl: 1,
  		AuthTime: now, RefreshedAt: now, Credential: store.Credential{Method: "cert", Issuer: "CN=Corp CA",
  			Serial: serial, Sid: sid}}
  	return c, store.LoginIndex{Principal: principal, Sid: sid, CertKey: store.CertKey("CN=Corp CA", serial),
  		TTL: time.Hour}
  }

  func refsOf(t *testing.T, s store.Store, f func(context.Context, string) ([]store.ContextRef, error), key string) int {
  	t.Helper()
  	refs, err := f(context.Background(), key)
  	if err != nil {
  		t.Fatal(err)
  	}
  	return len(refs)
  }

  // SwapLoginIsOneStep is plan 7d's login: JoinContext writes the context
  // and its index in one SwapLogin. A first login is found under its
  // principal, sid and certificate; another principal's replace leaves the
  // ref under the new login's keys alone; the same principal's second
  // window keeps the first window's keys; and a write whose context moved
  // since the read writes nothing, index included.
  func SwapLoginIsOneStep(t *testing.T, b Backend) {
  	now := t0
  	s := b.New(t, func() time.Time { return now })
  	ctx := context.Background()
  	k := store.ContextKey{NAS: "leaf-01", Username: "svc"}
  	const alice, bob = "spiffe://example.com/alice", "spiffe://example.com/bob"

  	c, ix := loginOf(alice, "sid-a1", "0a", now)
  	if _, err := store.JoinContext(ctx, s, k, c, now, now, time.Hour, ix); err != nil {
  		t.Fatal(err)
  	}
  	for _, q := range []struct {
  		f   func(context.Context, string) ([]store.ContextRef, error)
  		key string
  	}{{s.ContextsByPrincipal, alice}, {s.ContextsBySid, "sid-a1"}, {s.ContextsByCert, ix.CertKey}} {
  		if refsOf(t, s, q.f, q.key) != 1 {
  			t.Fatalf("a first login is not found under %q", q.key)
  		}
  	}
  	c2, ix2 := loginOf(alice, "sid-a2", "0a", now)
  	if out, err := store.JoinContext(ctx, s, k, c2, now, now, time.Hour, ix2); err != nil || !out.Joined {
  		t.Fatalf("the second window: %+v %v", out, err)
  	}
  	if refsOf(t, s, s.ContextsBySid, "sid-a1") != 1 || refsOf(t, s, s.ContextsBySid, "sid-a2") != 1 {
  		t.Fatal("a join must keep the first window's sid and add its own")
  	}
  	cb, ixb := loginOf(bob, "sid-b1", "0b", now)
  	if out, err := store.JoinContext(ctx, s, k, cb, now, now, time.Hour, ixb); err != nil || out.Replaced == "" {
  		t.Fatalf("bob's replace: %+v %v", out, err)
  	}
  	for key, f := range map[string]func(context.Context, string) ([]store.ContextRef, error){
  		alice: s.ContextsByPrincipal, "sid-a1": s.ContextsBySid, "sid-a2": s.ContextsBySid, ix.CertKey: s.ContextsByCert,
  	} {
  		if refsOf(t, s, f, key) != 0 {
  			t.Fatalf("after bob's replace, alice's %q still reaches bob's context", key)
  		}
  	}
  	if refsOf(t, s, s.ContextsByPrincipal, bob) != 1 || refsOf(t, s, s.ContextsBySid, "sid-b1") != 1 {
  		t.Fatal("bob's replace is not indexed under bob")
  	}

  	// A swap against a revision that moved writes nothing: not the context,
  	// not the index.
  	read, err := s.GetContext(ctx, k)
  	if err != nil {
  		t.Fatal(err)
  	}
  	if err := s.TouchContext(ctx, k, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	cc, _ := loginOf("spiffe://example.com/carol", "sid-c1", "0c", now)
  	err = s.SwapLogin(ctx, k, read.Rev, cc, time.Hour, store.LoginWrite{ClearRef: true,
  		Principal: "spiffe://example.com/carol", Sid: "sid-c1", IndexTTL: time.Hour})
  	if !errors.Is(err, store.ErrConflict) {
  		t.Fatalf("a stale SwapLogin: %v, want ErrConflict", err)
  	}
  	if refsOf(t, s, s.ContextsBySid, "sid-c1") != 0 || refsOf(t, s, s.ContextsByPrincipal, bob) != 1 {
  		t.Fatal("a refused SwapLogin changed the index")
  	}
  }

  // LoginsRaceToOneIndex is PR #7's third follow-up made a property: logins
  // under one username on one device, racing, leave the ref indexed under
  // the keys of the principal whose context stands, all of them, and under
  // no other's. Each round races alice's two windows and bob's login over
  // carol's context.
  func LoginsRaceToOneIndex(t *testing.T, b Backend) {
  	const rounds = 100
  	k := store.ContextKey{NAS: "leaf-01", Username: "svc"}
  	const alice, bob, carol = "spiffe://example.com/alice", "spiffe://example.com/bob", "spiffe://example.com/carol"
  	for round := 0; round < rounds; round++ {
  		s := b.New(t, func() time.Time { return t0 })
  		ctx := context.Background()
  		c0, ix0 := loginOf(carol, "sid-c", "0c", t0)
  		if _, err := store.JoinContext(ctx, s, k, c0, t0, t0, time.Hour, ix0); err != nil {
  			t.Fatal(err)
  		}
  		start := make(chan struct{})
  		var wg sync.WaitGroup
  		errs := make(chan error, 3)
  		for _, l := range []struct{ p, sid, serial string }{{alice, "sid-a1", "0a"}, {alice, "sid-a2", "0a"}, {bob, "sid-b", "0b"}} {
  			c, ix := loginOf(l.p, l.sid, l.serial, t0)
  			wg.Add(1)
  			go func() {
  				defer wg.Done()
  				<-start
  				_, err := store.JoinContext(ctx, s, k, c, t0, t0, time.Hour, ix)
  				errs <- err
  			}()
  		}
  		close(start)
  		wg.Wait()
  		close(errs)
  		for err := range errs {
  			if err != nil {
  				t.Fatalf("round %d: %v", round, err)
  			}
  		}
  		got, err := s.GetContext(ctx, k)
  		if err != nil {
  			t.Fatal(err)
  		}
  		mine := map[string][]string{alice: {"sid-a1", "sid-a2"}, bob: {"sid-b"}}
  		for p, sids := range mine {
  			want := 0
  			if p == got.Principal {
  				want = 1
  			}
  			if n := refsOf(t, s, s.ContextsByPrincipal, p); n != want {
  				t.Fatalf("round %d: %s's context stands, and %s is indexed %d times", round, got.Principal, p, n)
  			}
  			for _, sid := range sids {
  				// The standing principal's own sids: each that joined is
  				// indexed; the other principal's: none is.
  				if n := refsOf(t, s, s.ContextsBySid, sid); p != got.Principal && n != 0 {
  					t.Fatalf("round %d: %s's context stands, and %s's sid %s reaches it", round, got.Principal, p, sid)
  				}
  			}
  		}
  		if refsOf(t, s, s.ContextsByPrincipal, carol) != 0 || refsOf(t, s, s.ContextsBySid, "sid-c") != 0 {
  			t.Fatalf("round %d: carol's keys outlived the replace", round)
  		}
  		if got.Principal == alice && refsOf(t, s, s.ContextsBySid, got.Credential.Sid) != 1 {
  			t.Fatalf("round %d: alice's standing context is not under its own last sid", round)
  		}
  	}
  }

  // markingStore puts a mark the first time JoinContext reads that none
  // stands, so the mark lands between the login's read and its write.
  type markingStore struct {
  	store.Store
  	mark store.Revocation
  	once sync.Once
  }

  func (m *markingStore) GetRevocation(ctx context.Context, kind, key string) (store.Revocation, error) {
  	r, err := m.Store.GetRevocation(ctx, kind, key)
  	if errors.Is(err, store.ErrNotFound) && kind == m.mark.Kind && key == m.mark.Key {
  		m.once.Do(func() {
  			if perr := m.Store.PutRevocation(ctx, m.mark); perr != nil {
  				panic(perr)
  			}
  		})
  	}
  	return r, err
  }

  // JoinHonoursAStandingMark is 7a's residual window closed (spec §5.1.4;
  // decision 35): a login whose principal or certificate is marked writes
  // its context revoked at the mark, unless its token was minted after it;
  // and a mark that lands between the login's read of the marks and its
  // write makes the write conflict, so it is decided again and lands
  // revoked.
  func JoinHonoursAStandingMark(t *testing.T, b Backend) {
  	ctx := context.Background()
  	k := store.ContextKey{NAS: "leaf-01", Username: "svc"}
  	const alice = "spiffe://example.com/alice"
  	at := t0.Add(-time.Minute)
  	for _, kind := range []string{store.RevocationPrincipal, store.RevocationCert} {
  		key := alice
  		if kind == store.RevocationCert {
  			key = store.CertKey("CN=Corp CA", "0a")
  		}
  		mark := store.Revocation{Kind: kind, Key: key, At: at, Origin: "storetest"}

  		// Standing before the login.
  		s := b.New(t, func() time.Time { return t0 })
  		if err := s.PutRevocation(ctx, mark); err != nil {
  			t.Fatal(err)
  		}
  		c, ix := loginOf(alice, "sid-a1", "0a", t0)
  		out, err := store.JoinContext(ctx, s, k, c, at.Add(-time.Second), t0, time.Hour, ix)
  		if err != nil || !out.Context.RevokedAt.Equal(at) {
  			t.Fatalf("%s: a login under a standing mark wrote %+v %v", kind, out.Context, err)
  		}
  		// A token minted after the mark is a credential verified again
  		// (decision 15): it is not carried.
  		s = b.New(t, func() time.Time { return t0 })
  		if err := s.PutRevocation(ctx, mark); err != nil {
  			t.Fatal(err)
  		}
  		if out, err := store.JoinContext(ctx, s, k, c, at.Add(time.Second), t0, time.Hour, ix); err != nil ||
  			!out.Context.RevokedAt.IsZero() {
  			t.Fatalf("%s: a token minted after the mark: %+v %v", kind, out.Context, err)
  		}

  		// Landing between the read and the write.
  		inner := b.New(t, func() time.Time { return t0 })
  		s = &markingStore{Store: inner, mark: mark}
  		out, err = store.JoinContext(ctx, s, k, c, at.Add(-time.Second), t0, time.Hour, ix)
  		if err != nil {
  			t.Fatalf("%s: %v", kind, err)
  		}
  		got, err := inner.GetContext(ctx, k)
  		if err != nil || !got.RevokedAt.Equal(at) || !out.Context.RevokedAt.Equal(at) {
  			t.Fatalf("%s: a mark landing mid-login: stored %+v (%v), reported %v", kind, got.RevokedAt, err,
  				out.Context.RevokedAt)
  		}
  		// And the context is still indexed, so the revocation's second pass
  		// would find it too.
  		if refsOf(t, inner, inner.ContextsByPrincipal, alice) != 1 {
  			t.Fatalf("%s: the revoked login is not indexed", kind)
  		}
  	}
  }

  // PurgeTakesEveryToken is a start on a store that persists (plan 7d):
  // every token goes, live or expired, under every key, and the count is the
  // live ones; receipts, contexts and marks stay.
  func PurgeTakesEveryToken(t *testing.T, b Backend) {
  	ctx := context.Background()
  	s := b.New(t, func() time.Time { return t0 })
  	for i, k := range []store.TokenKey{{NAS: "leaf-01", Username: "a"}, {NAS: "leaf-02", Username: "a"},
  		{NAS: "leaf-03", Username: "b"}} {
  		exp := t0.Add(time.Minute)
  		if i == 2 {
  			exp = t0 // expired already
  		}
  		if _, err := s.PutToken(ctx, k, store.Token{ID: fmt.Sprint("t", i), Secret: []byte("s"), Kind: store.KindLogin,
  			ExpiresAt: exp}); err != nil {
  			t.Fatal(err)
  		}
  	}
  	ck := store.ContextKey{NAS: "leaf-01", Username: "a"}
  	if err := s.PutContext(ctx, ck, store.Context{CtxID: "c", Principal: "p", Username: "a"}, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	if err := s.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: "p", At: t0}); err != nil {
  		t.Fatal(err)
  	}
  	n, err := s.PurgeTokens(ctx)
  	if err != nil || n != 2 {
  		t.Fatalf("PurgeTokens = %d, %v; want the 2 live tokens", n, err)
  	}
  	for _, k := range []store.TokenKey{{NAS: "leaf-01", Username: "a"}, {NAS: "leaf-02", Username: "a"}} {
  		if got, _ := s.Candidates(ctx, k); len(got) != 0 {
  			t.Fatalf("a token under %v survived the purge", k)
  		}
  	}
  	if _, err := s.GetContext(ctx, ck); err != nil {
  		t.Fatalf("the purge took a context: %v", err)
  	}
  	if _, err := s.GetRevocation(ctx, store.RevocationPrincipal, "p"); err != nil {
  		t.Fatalf("the purge took a mark: %v", err)
  	}
  	if n, err := s.PurgeTokens(ctx); err != nil || n != 0 {
  		t.Fatalf("a second purge: %d %v", n, err)
  	}
  }

  // SelfRevocationBindsToTheRead is 7c's self-revocation on any backend
  // (decision 34): a revoking SetContextPolicy against the policy revision a
  // read returned conflicts once another principal's login has replaced the
  // context, and the replacing context stays unrevoked.
  func SelfRevocationBindsToTheRead(t *testing.T, b Backend) {
  	ctx := context.Background()
  	s := b.New(t, func() time.Time { return t0 })
  	k := store.ContextKey{NAS: "leaf-01", Username: "svc"}
  	ca, ixa := loginOf("spiffe://example.com/alice", "sid-a", "0a", t0)
  	if _, err := store.JoinContext(ctx, s, k, ca, t0, t0, time.Hour, ixa); err != nil {
  		t.Fatal(err)
  	}
  	read, err := s.GetContext(ctx, k)
  	if err != nil {
  		t.Fatal(err)
  	}
  	cb, ixb := loginOf("spiffe://example.com/bob", "sid-b", "0b", t0)
  	if _, err := store.JoinContext(ctx, s, k, cb, t0, t0, time.Hour, ixb); err != nil {
  		t.Fatal(err)
  	}
  	err = s.SetContextPolicy(ctx, k, read.PolicyRev, store.ContextPolicy{RevokedAt: t0})
  	if !errors.Is(err, store.ErrConflict) {
  		t.Fatalf("alice's revoke after bob's replace: %v, want ErrConflict", err)
  	}
  	if got, err := s.GetContext(ctx, k); err != nil || got.Principal != "spiffe://example.com/bob" ||
  		!got.RevokedAt.IsZero() {
  		t.Fatalf("bob's context: %+v %v", got, err)
  	}
  }
  ```

  Add the five to `Run`, after the `lifted` loop:

  ```go
  	for _, p := range []struct {
  		name string
  		run  func(*testing.T, Backend)
  	}{
  		{"SwapLoginIsOneStep", SwapLoginIsOneStep},
  		{"LoginsRaceToOneIndex", LoginsRaceToOneIndex},
  		{"JoinHonoursAStandingMark", JoinHonoursAStandingMark},
  		{"PurgeTakesEveryToken", PurgeTakesEveryToken},
  		{"SelfRevocationBindsToTheRead", SelfRevocationBindsToTheRead},
  	} {
  		p := p
  		t.Run(p.name, func(t *testing.T) { p.run(t, b) })
  	}
  ```

  Run: `go test ./internal/store/... -count=1`
  Expected: FAIL to build: `store.LoginIndex`, `Store.SwapLogin`, `store.LoginWrite` and
  `Store.PurgeTokens` are undefined.

- [ ] **Step 2: The contract.** In `internal/store/store.go`:

  After `ErrPastGrace` add:

  ```go
  // ErrUnavailable is a store that did not answer, or answered with an
  // error that is not about the record: a network backend that timed out,
  // lost its quorum, or is unreachable. The guard (internal/store/guard)
  // counts it toward a pool's circuit, and every handler answers it
  // store_unavailable, as any error that is not ErrNotFound (spec §5.7).
  var ErrUnavailable = errors.New("store: unavailable")
  ```

  Add to the `Store` interface, after `SwapContext`:

  ```go
  	// SwapLogin is SwapContext with a login's index bookkeeping and its
  	// revocation check in the same atomic step (plan 7d; spec §13, decision
  	// 35). It writes c only if the record at k is still the one the caller
  	// read (rev, as SwapContext reads it) and each mark in w.Marks is still
  	// as the caller read it: present at that At, or absent for a zero At.
  	// Otherwise ErrConflict, and nothing — context or index — is written.
  	// On success, after the context is written and its existing index
  	// entries extended as SwapContext extends them, the ref is unindexed
  	// wholly when w.ClearRef (UnindexRef), then from w.DropSid and
  	// w.DropCertKey (UnindexContext, no principal), then indexed under
  	// w.Principal, w.Sid and w.CertKey for w.IndexTTL (IndexContext), each
  	// empty or blank key skipped.
  	SwapLogin(ctx context.Context, k ContextKey, rev uint64, c Context, ttl time.Duration, w LoginWrite) error
  ```

  and after `DeleteToken`:

  ```go
  	// PurgeTokens deletes every token record, live or expired, under every
  	// key, and reports how many were live. It is a start on a store that
  	// persists (plan 7d): no policy this port49d loaded minted them, so none
  	// is redeemable after it, as none was after a restart of the memory
  	// store. The token indexes stay; an entry that outlives its token costs
  	// a revocation one DeleteTokens on an empty key (IndexToken).
  	PurgeTokens(ctx context.Context) (int, error)
  ```

  After the `ContextRef` type add:

  ```go
  // MarkRead is a revocation mark as a login read it: At is the mark's, or
  // zero when none stood (plan 7d).
  type MarkRead struct {
  	Kind, Key string
  	At        time.Time
  }

  // LoginWrite is what a login's SwapLogin carries beside the context: the
  // index change its join decided, and the marks it read (spec §13,
  // decision 35). The zero value changes no index and checks no mark,
  // which is SwapContext.
  type LoginWrite struct {
  	// ClearRef unindexes the ref from every key it was indexed under: a
  	// replace by another principal, or of a record that would not open.
  	ClearRef bool
  	// DropSid and DropCertKey are a same-principal replace's displaced
  	// credential, unindexed where this login does not share it.
  	DropSid, DropCertKey string
  	// Principal, Sid and CertKey index the ref for IndexTTL.
  	Principal, Sid, CertKey string
  	IndexTTL                time.Duration
  	// Marks must still be as read for the write to land.
  	Marks []MarkRead
  }
  ```

  After `CertKey` add the two helpers the memory store had to itself, which the etcd backend
  needs too:

  ```go
  // BlankCertKey reports whether certKey is CertKey of an empty issuer or an
  // empty serial, or is not a CertKey at all (no "|"). It names no
  // certificate: every OIDC login's credential has neither, so "|" would be
  // one index entry holding every OIDC operator's context on the fleet, and
  // a revocation by it would revoke them all. Every backend treats it as ""
  // — never indexed, never marked (ruling P8).
  func BlankCertKey(certKey string) bool {
  	return !strings.Contains(certKey, "|") || strings.HasPrefix(certKey, "|") || strings.HasSuffix(certKey, "|")
  }

  // ErrIncompleteMark refuses a revocation mark that could match nothing: it
  // would be reported as in force and revoke nothing.
  var ErrIncompleteMark = errors.New("store: a revocation mark must name a principal, or a certificate by issuer and serial")

  // CheckRevocation is PutRevocation's refusal, shared by every backend: a
  // kind that is neither RevocationPrincipal nor RevocationCert, an empty
  // key, or a certificate key that is blank (BlankCertKey).
  func CheckRevocation(r Revocation) error {
  	switch {
  	case r.Kind == RevocationPrincipal && r.Key != "":
  		return nil
  	case r.Kind == RevocationCert && !BlankCertKey(r.Key):
  		return nil
  	}
  	return ErrIncompleteMark
  }
  ```

  Add `"strings"` to the imports.

- [ ] **Step 3: The join reads the marks and writes once.** In `internal/store/join.go`, add after
  `JoinResult`:

  ```go
  // LoginIndex is what a login indexes its context under (IndexContext's
  // arguments): its principal, sid and certificate key, for TTL. JoinContext
  // decides what the displaced record's keys lose, and SwapLogin writes it
  // with the context (plan 7d).
  type LoginIndex struct {
  	Principal, Sid, CertKey string
  	TTL                     time.Duration
  }
  ```

  Replace `JoinContext` whole with:

  ```go
  // JoinContext writes a login's context at k: a join into the live context
  // when Joinable says it may, the login itself otherwise (spec §5.6), with
  // its index and its revocation check in the same step (SwapLogin; plan 7d).
  // It reads the marks for the login's principal and certificate, then the
  // context, decides, and swaps on what it read, retrying from the read when
  // the swap is refused, so a write that lands in between — SetRevokedAt, or
  // a mark, above all — is merged rather than erased, and two concurrent
  // logins both land in one context instead of one overwriting the other.
  //
  // login is the context this login would create on its own, CtxID
  // included. A mark that stands for login's principal or certificate is
  // carried into the context as its revocation by CarryRevocation's rule: a
  // token minted after the mark is the credential verified again (decision
  // 15). A replace of the same principal's context past its ceiling carries
  // the revocation by the same rule a join does.
  //
  // The index change is the one the login path made in three calls before
  // plan 7d: another principal's replace, or an unreadable one, clears every
  // key the ref was indexed under; the same principal's replace drops only
  // the displaced sid and certificate this login does not share; a join
  // keeps what is there. Then the login's own keys are added.
  //
  // A record the sealing layer cannot open (UnreadableContextError) cannot
  // be merged, and is replaced by the login: refusing it would lock the
  // operator out until the idle TTL reclaims a record nothing can use. The
  // replace is a swap on the plaintext revision the error carries, and it
  // keeps the plaintext RevokedAt by the same minted-after rule whoever the
  // principal was, because the principal is sealed. Any other store error is
  // returned as it is.
  func JoinContext(ctx context.Context, s Store, k ContextKey, login Context, mintedAt, now time.Time, ttl time.Duration,
  	ix LoginIndex) (JoinResult, error) {
  	for attempt := 0; attempt < MaxJoinAttempts; attempt++ {
  		marks, standing, err := readMarks(ctx, s, login)
  		if err != nil {
  			return JoinResult{}, err
  		}
  		mine := login
  		mine.RevokedAt = later(mine.RevokedAt, CarryRevocation(standing, mintedAt))
  		live, err := s.GetContext(ctx, k)
  		var res JoinResult
  		var rev uint64
  		w := LoginWrite{Principal: ix.Principal, Sid: ix.Sid, CertKey: ix.CertKey, IndexTTL: ix.TTL, Marks: marks}
  		var unreadable *UnreadableContextError
  		switch {
  		case errors.Is(err, ErrNotFound):
  			res.Context = mine
  		case errors.As(err, &unreadable):
  			res = JoinResult{Context: mine, ReplacedUnreadable: true}
  			res.Context.RevokedAt = later(mine.RevokedAt, CarryRevocation(unreadable.RevokedAt, mintedAt))
  			rev = unreadable.Rev
  			w.ClearRef = true
  		case err != nil:
  			return JoinResult{}, err
  		case Joinable(live, mine, now):
  			res = JoinResult{Context: Join(live, mine, mintedAt), Joined: true}
  			res.Context.RevokedAt = later(res.Context.RevokedAt, mine.RevokedAt)
  			if live.PrivLvl > res.Context.PrivLvl {
  				res.ClampedFrom = live.PrivLvl
  			}
  			rev = live.Rev
  		default:
  			res = JoinResult{Context: mine, Replaced: live.CtxID, Prior: live}
  			rev = live.Rev
  			if live.Principal == mine.Principal {
  				res.Context.RevokedAt = later(mine.RevokedAt, CarryRevocation(live.RevokedAt, mintedAt))
  				w.DropSid, w.DropCertKey = displaced(live.Credential, mine.Credential)
  			} else {
  				w.ClearRef = true
  			}
  		}
  		switch err := s.SwapLogin(ctx, k, rev, res.Context, ttl, w); {
  		case err == nil:
  			return res, nil
  		case !errors.Is(err, ErrConflict):
  			return JoinResult{}, err
  		}
  	}
  	return JoinResult{}, fmt.Errorf("store: context still changing after %d attempts: %w", MaxJoinAttempts, ErrConflict)
  }

  // readMarks reads the marks for the login's principal and certificate, as
  // SwapLogin will compare them, and the latest At among those standing.
  func readMarks(ctx context.Context, s Store, login Context) ([]MarkRead, time.Time, error) {
  	keys := [][2]string{{RevocationPrincipal, login.Principal}}
  	if ck := CertKey(login.Credential.Issuer, login.Credential.Serial); !BlankCertKey(ck) {
  		keys = append(keys, [2]string{RevocationCert, ck})
  	}
  	var out []MarkRead
  	var standing time.Time
  	for _, kk := range keys {
  		if kk[1] == "" {
  			continue
  		}
  		r, err := s.GetRevocation(ctx, kk[0], kk[1])
  		switch {
  		case errors.Is(err, ErrNotFound):
  			out = append(out, MarkRead{Kind: kk[0], Key: kk[1]})
  		case err != nil:
  			return nil, time.Time{}, err
  		default:
  			out = append(out, MarkRead{Kind: kk[0], Key: kk[1], At: r.At})
  			standing = later(standing, r.At)
  		}
  	}
  	return out, standing, nil
  }

  // displaced is what a same-principal replace unindexes: the displaced
  // login's sid and certificate, each only where this login does not share
  // it. A key both hold is one this login indexes anyway, and dropping it
  // first would leave a moment in which a revocation by it finds nothing —
  // which, in one step, it no longer can; the rule is kept so the index ends
  // where it did before plan 7d.
  func displaced(prior, login Credential) (sid, certKey string) {
  	if prior.Sid != login.Sid {
  		sid = prior.Sid
  	}
  	if ck := CertKey(prior.Issuer, prior.Serial); ck != CertKey(login.Issuer, login.Serial) {
  		certKey = ck
  	}
  	return sid, certKey
  }
  ```

  The comment's argument is authen's, moved here with the code. Task 4 removes it from authen.

- [ ] **Step 4: The memory store.** In `internal/store/memory/memory.go`:

  1. Replace `blankCertKey`'s body with `return store.BlankCertKey(certKey)`, keeping its comment
     (now `// blankCertKey is store.BlankCertKey.`). Replace `errIncompleteMark` and
     `PutRevocation`'s switch with:

     ```go
     // PutRevocation writes r unless a mark for its key already stands.
     func (s *Store) PutRevocation(_ context.Context, r store.Revocation) error {
     	if err := store.CheckRevocation(r); err != nil {
     		return err
     	}
     	s.mu.Lock()
     	defer s.mu.Unlock()
     	k := [2]string{r.Kind, r.Key}
     	if _, ok := s.revocations[k]; !ok {
     		s.revocations[k] = r
     	}
     	s.wroteLocked()
     	return nil
     }
     ```

  2. Split the bodies of `IndexContext`, `UnindexContext` and `UnindexRef` below their
     `s.mu.Lock(); defer s.mu.Unlock()` into `indexLocked(principal, sid, certKey string, ref
     store.ContextRef, ttl time.Duration)`, `unindexLocked(principal, sid, certKey string, ref
     store.ContextRef)` and `unindexRefLocked(ref store.ContextRef)`. Each public method locks and
     calls its helper. Move the comments with the code.

  3. Replace `SwapContext` with:

     ```go
     // SwapContext is SwapLogin with no index change and no mark to check.
     func (s *Store) SwapContext(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration) error {
     	return s.SwapLogin(ctx, k, rev, c, ttl, store.LoginWrite{})
     }

     // SwapLogin writes c only if the record at k still carries revision rev
     // (for rev zero, only if there is no live record) and every mark in
     // w.Marks is still as read; then the index change, all under the one
     // lock, which is what makes the three one step (store.Store).
     func (s *Store) SwapLogin(_ context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration,
     	w store.LoginWrite) error {
     	s.mu.Lock()
     	defer s.mu.Unlock()
     	now := s.now()
     	e, ok := s.contexts[k]
     	live := ok && e.exp.After(now)
     	if live && e.rev != rev || !live && rev != 0 {
     		return store.ErrConflict
     	}
     	for _, m := range w.Marks {
     		cur, ok := s.revocations[[2]string{m.Kind, m.Key}]
     		if ok == m.At.IsZero() || ok && !cur.At.Equal(m.At) {
     			return store.ErrConflict
     		}
     	}
     	s.writeContextLocked(k, c, now, ttl)
     	ref := store.ContextRef{NAS: k.NAS, Username: k.Username}
     	if w.ClearRef {
     		s.unindexRefLocked(ref)
     	}
     	if w.DropSid != "" || w.DropCertKey != "" {
     		s.unindexLocked("", w.DropSid, w.DropCertKey, ref)
     	}
     	if w.Principal != "" || w.Sid != "" || w.CertKey != "" {
     		s.indexLocked(w.Principal, w.Sid, w.CertKey, ref, w.IndexTTL)
     	}
     	return nil
     }
     ```

     `ok == m.At.IsZero()` is the mismatch: a mark there that was read as absent, or one absent
     that was read as standing.

  4. After `DeleteToken` add:

     ```go
     // PurgeTokens drops every token, clearing each set's entries so no
     // secret stays reachable from a backing array (clearTail), and counts
     // the live ones.
     func (s *Store) PurgeTokens(context.Context) (int, error) {
     	s.mu.Lock()
     	defer s.mu.Unlock()
     	now := s.now()
     	n := 0
     	for k, set := range s.tokens {
     		for _, t := range set {
     			if t.ExpiresAt.After(now) {
     				n++
     			}
     		}
     		clearTail(set, 0)
     		delete(s.tokens, k)
     	}
     	return n, nil
     }
     ```

- [ ] **Step 5: The sealing layer.** In `internal/store/crypt/crypt.go`, after `SwapContext` add:

  ```go
  // SwapLogin seals as SwapContext does, and passes the index change and the
  // marks through: both are plaintext, as the indexes and the marks are (the
  // package comment), so the inner store compares and writes them under the
  // same step as the sealed context.
  func (w *wrapped) SwapLogin(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration,
  	lw store.LoginWrite) error {
  	sc, err := w.sealContext(c)
  	if err != nil {
  		return err
  	}
  	return w.inner.SwapLogin(ctx, k, rev, sc, ttl, lw)
  }
  ```

  and after `DeleteToken`:

  ```go
  // PurgeTokens reads nothing sealed: the backend deletes by key.
  func (w *wrapped) PurgeTokens(ctx context.Context) (int, error) { return w.inner.PurgeTokens(ctx) }
  ```

- [ ] **Step 6: Every `JoinContext` caller in the store packages passes a `LoginIndex`.** In
  `storetest.go` (`JoinRacesRevocation`, `PolicyRevision`, `RevocationIsMonotonic`), in
  `lifted.go`, and in `internal/store/join_test.go`, append `, store.LoginIndex{}` to every
  `store.JoinContext(` call. The zero value indexes nothing, which is what each did. In
  `internal/daemon/authen/authen_test.go`, give `noStore` the two methods:

  ```go
  func (noStore) SwapLogin(context.Context, store.ContextKey, uint64, store.Context, time.Duration, store.LoginWrite) error {
  	return errors.New("store down")
  }

  func (noStore) PurgeTokens(context.Context) (int, error) { return 0, errors.New("store down") }
  ```

  Match what `noStore`'s other methods return (read them first). If they return a named error,
  return that. `authen.go`'s own call is Task 4's. Until then it passes `store.LoginIndex{}` and
  keeps its three index calls, so this task changes no behaviour: in `authen.go` append `,
  store.LoginIndex{}` to the one `store.JoinContext(` call.

- [ ] **Step 7: Run.**

  Run: `go test ./internal/store/... ./internal/daemon/... -count=1`
  Expected: PASS, with `TestTheMemoryStoreHoldsEveryProperty/{SwapLoginIsOneStep,
  LoginsRaceToOneIndex, JoinHonoursAStandingMark, PurgeTakesEveryToken,
  SelfRevocationBindsToTheRead}` and the same five under `TestTheSealingLayerHoldsEveryProperty`.

  Mutation check (do it, report it, revert it): in memory's `SwapLogin`, move the mark loop
  after `s.writeContextLocked`. `JoinHonoursAStandingMark` must fail ("a mark landing
  mid-login"). Then drop `w.ClearRef`'s branch: `SwapLoginIsOneStep` and `LoginsRaceToOneIndex`
  must fail.

- [ ] **Step 8: Commit.**

  ```bash
  gofmt -w internal/store internal/daemon/authen/authen_test.go internal/daemon/authen/authen.go
  make build && make test && make vet
  git add internal/store/store.go internal/store/join.go internal/store/join_test.go \
    internal/store/memory/memory.go internal/store/crypt/crypt.go internal/store/storetest/storetest.go \
    internal/store/storetest/lifted.go internal/store/storetest/login.go \
    internal/daemon/authen/authen.go internal/daemon/authen/authen_test.go
  git commit -m "feat(store): a login's context, index and mark check are one step; PurgeTokens

  SwapLogin writes a login's context, its index change and a check that
  no revocation mark appeared since the login read, in one atomic step;
  JoinContext reads the marks first and carries a standing one into the
  context. PurgeTokens deletes every token for a start on a persistent
  store. BlankCertKey and CheckRevocation move into the store package so
  every backend refuses the same keys. New storetest properties pin each.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 4: The login path writes its context once

**Files:**
- Modify: `internal/daemon/authen/authen.go:570-650` (the join and the index calls after it)
- Modify: `internal/daemon/authen/authen_test.go`

**Interfaces:**
- Consumes: `store.JoinContext(…, store.LoginIndex)` (Task 3).
- Produces: nothing new. A login whose context cannot be written with its index is ERROR
  `store_unavailable`. One whose principal or certificate is marked is refused
  `credential_revoked`, by the existing refusal after the join.

- [ ] **Step 1: The failing tests.** In `authen_test.go`:

  1. Replace `indexFailsStore` and `TestAnUnindexedContextSaysSoOnTheRecord` with:

     ```go
     // swapLoginFails answers everything normally but never writes a login:
     // a store that is up for reads and refuses the one step that writes the
     // context with its index.
     type swapLoginFails struct{ *memory.Store }

     func (swapLoginFails) SwapLogin(context.Context, store.ContextKey, uint64, store.Context, time.Duration,
     	store.LoginWrite) error {
     	return errors.New("store unavailable")
     }

     // A login whose context and index cannot be written together is refused
     // ERROR store_unavailable, never admitted with a context no revocation
     // can reach (plan 7d; decision 35). Before plan 7d it was a PASS with
     // index_error.
     func TestALoginThatCannotBeIndexedIsRefused(t *testing.T) {
     	f := setupStore(t, func(st *memory.Store) store.Store { return swapLoginFails{st} })
     	reply := f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
     		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
     		Port: []byte("vty0"), Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")})
     	if reply.Status != wire.AuthenStatusError {
     		t.Fatalf("status %d, want ERROR", reply.Status)
     	}
     	rec := f.records(t)[0]
     	if rec["reason"] != "store_unavailable" || rec["index_error"] != nil {
     		t.Fatalf("record: %v", rec)
     	}
     	if refs, _ := f.st.ContextsByPrincipal(context.Background(), "user:alice@example.com"); len(refs) != 0 {
     		t.Fatalf("an unindexed login left refs: %v", refs)
     	}
     	if _, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: f.peer.NAS, Username: "alice"}); !errors.Is(err, store.ErrNotFound) {
     		t.Fatalf("an unindexed login left a context: %v", err)
     	}
     }
     ```

     Use the reply shape `Start` returns in this file's other tests. If it is not `.Status`, read
     the status the way they do. If `f.st` or `f.peer.NAS` are named otherwise in `setupStore`'s
     fixture, use those names.

  2. Add:

     ```go
     // A login by a principal a standing mark names is refused
     // credential_revoked, and the context it wrote is revoked at the mark:
     // the redemption that raced a revocation (spec §5.1.4; decision 35).
     func TestALoginUnderAStandingMarkIsRefused(t *testing.T) {
     	f := setupStore(t, func(st *memory.Store) store.Store { return st })
     	at := f.now.Add(-time.Second)
     	if err := f.st.PutRevocation(context.Background(), store.Revocation{Kind: store.RevocationPrincipal,
     		Key: "user:alice@example.com", At: at, Origin: "test"}); err != nil {
     		t.Fatal(err)
     	}
     	f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
     		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
     		Port: []byte("vty0"), Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")})
     	rec := f.records(t)[0]
     	if rec["reason"] != "credential_revoked" {
     		t.Fatalf("record: %v", rec)
     	}
     	c, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: f.peer.NAS, Username: "alice"})
     	if err != nil || !c.RevokedAt.Equal(at) {
     		t.Fatalf("context %+v %v", c, err)
     	}
     }
     ```

     The fixture's token must have been minted before `at`. The seeded token's `MintedAt` is
     `f.now` or earlier: read `setupStore`. If it is `f.now`, set `at := f.now.Add(time.Second)`,
     so the token predates the mark.

  3. `certReachStore` (above `TestAReplaceKeepsTheKeysItShares`) wraps `SwapContext`,
     `UnindexContext` and `IndexContext` to check the certificate's reach between the calls.
     There is one call now. Replace the three wrappers with one:

     ```go
     func (c *certReachStore) SwapLogin(ctx context.Context, k store.ContextKey, rev uint64, v store.Context,
     	ttl time.Duration, w store.LoginWrite) error {
     	err := c.Store.SwapLogin(ctx, k, rev, v, ttl, w)
     	c.check(ctx, "swap_login")
     	return err
     }
     ```

     Leave the test's assertion as it is: it asserts no moment without reach, and there is now
     one moment to check.

  4. Tests that read `store_operations_total{op="unindex_ref"|"unindex_context"|"index_context"}`
     (grep the file) now read `{op="join_context"}` for the same outcome. A test that asserted
     an index call's own failure path is the first test above, and is deleted with
     `indexFailsStore`.

  Run: `go test ./internal/daemon/authen/ -count=1`
  Expected: `TestALoginThatCannotBeIndexedIsRefused` FAILS: the swap writes no index (Task 3
  passes `LoginIndex{}`), the separate `IndexContext` call that follows succeeds, and the login
  is a PASS. Since Task 3, `JoinContext` already reads the marks from the login's own principal
  and credential, so `TestALoginUnderAStandingMarkIsRefused` may already pass. That is expected:
  it pins the behaviour from here on. Report what each did.

- [ ] **Step 2: The join carries its index.** In `authen.go`, replace from `out, err :=
  store.JoinContext(` through the `if err != nil { rec.IndexError = "context not indexed; …" }`
  block (the comments between included; they moved to `store.JoinContext` in Task 3) with:

  ```go
  	// Join, or write fresh, with the index and the revocation check in one
  	// step (spec §5.6; §13, decision 35): a context is never live and
  	// unindexed, and a mark that stands for this principal or certificate,
  	// on a token minted before it, is written into the context, which the
  	// check below then refuses. store.JoinContext says how the displaced
  	// record's keys are unindexed.
  	out, err := store.JoinContext(ctx, s.h.store, ck, login, winner.MintedAt, s.h.now(), s.h.contextTTL,
  		store.LoginIndex{Principal: winner.Principal, Sid: winner.Credential.Sid,
  			CertKey: store.CertKey(winner.Credential.Issuer, winner.Credential.Serial), TTL: s.h.indexTTL})
  	s.h.metrics.StoreOps.WithLabelValues("join_context", storeOutcome(err)).Inc()
  	if err != nil {
  		// The token is already redeemed, but without a context and its index
  		// a later authorization has nothing to check against, and a
  		// revocation nothing to reach: ERROR, not a PASS we can't back up.
  		return s.storeError(rec)
  	}
  	rec.Session.ReplacedCtxID = out.Replaced
  	rec.Session.ReplacedUnreadable = out.ReplacedUnreadable
  	if out.ClampedFrom != 0 {
  		rec.Session.PrivilegeClamped = &decision.PrivilegeClamp{From: out.ClampedFrom, To: out.Context.PrivLvl}
  	}
  ```

  In the `FailReceipt` block below it, replace

  ```go
  			lost := "receipt not marked failed; a retransmission after the revocation is lifted will replay PASS"
  			if rec.IndexError != "" {
  				lost = rec.IndexError + "; " + lost
  			}
  			rec.IndexError = lost
  ```

  with `rec.IndexError = "receipt not marked failed; a retransmission after the revocation is
  lifted will replay PASS"`. Delete the comment line `// After the index bookkeeping, not before:
  the context exists and is revoked, and a revocation of this credential must still reach it.` and
  its continuation: there is no separate bookkeeping now, and the context is indexed by the join.
  The local `ref` the switch used is gone. If nothing else uses it, the compiler says so; remove
  it.

  Run: `go test ./internal/daemon/authen/ -count=1`
  Expected: PASS.

- [ ] **Step 3: The whole tree.**

  Run: `make test`
  Expected: PASS. Tests elsewhere that counted `index_context` or `unindex_ref` ops (`grep -rn
  'index_context\|unindex_ref\|unindex_context' --include='*_test.go' cmd internal`) move to
  `join_context` as in Step 1.4. Report each one changed.

- [ ] **Step 4: Commit.**

  ```bash
  gofmt -w internal/daemon/authen
  make build && make test && make vet
  git add internal/daemon/authen/authen.go internal/daemon/authen/authen_test.go
  git commit -m "fix(authen): a login writes its context and index in one step, under the marks

  The login path's join, unindex and index were three store calls; a
  failure between them left a context no revocation could reach, admitted
  with index_error, and a revocation mark landing between the redemption
  and the write was missed (7a's residual window). JoinContext now writes
  all of it through SwapLogin and carries a standing mark into the
  context. A login that cannot be indexed is ERROR store_unavailable
  (plan 7d; decision 35; PR #7's third follow-up; 4b pre-flight N4).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 5: The etcd backend's foundation, its tokens and its marks

**Files:**
- Modify: `go.mod`, `go.sum`
- Create: `internal/store/etcd/etcdtest/etcdtest.go`
- Create: `internal/store/etcd/etcd.go`, `keys.go`, `records.go`, `leases.go`, `commit.go`,
  `tokens.go`, `marks.go`, `notbuilt.go`
- Test: `internal/store/etcd/etcd_test.go`

**Interfaces:**
- Consumes: `store.Store` and its types; `store.BlankCertKey`, `store.CheckRevocation`,
  `store.ErrUnavailable` (Task 3); every `storetest` property (Tasks 2–3).
- Produces:
  - `type etcd.Config struct { Endpoints []string; TLS *tls.Config; Prefix string; Now func() time.Time; LeaseGrace, DialTimeout time.Duration }`
  - `func etcd.Open(c Config) (*Store, error)`, `func (s *Store) Close() error`,
    `func (s *Store) Ping(ctx context.Context) error`
  - `var etcd.ErrRefused` (etcd refused this identity: a role, not an outage)
  - `func newStore(tok, ctx *clientv3.Client, c Config) *Store` (unexported; tests build stores
    on a shared client)
  - `type keys struct{…}` with the methods below; `type leases struct{…}` with `For`, `Reset`;
    `func (s *Store) commit(…)`, `func cas[R any](…)`; every token, receipt, token-index and mark
    method of `store.Store`.
  - etcdtest: `func Main(m *testing.M) int`, `func Endpoint() string`, `func Prefix() string`,
    `func Client(t testing.TB) *clientv3.Client`, `type Server`, `func Start(t testing.TB, o Options) *Server`,
    `type Cluster`, `func StartCluster(t testing.TB) *Cluster`, `(*Cluster).Stop(i int)`,
    `type Proxy`, `func NewProxy(t testing.TB, target string) *Proxy`, `(*Proxy).Addr()`,
    `(*Proxy).Hang(bool)`, `(*Proxy).Delay(time.Duration)`.

**Gotchas, measured before this plan:**
- `clientv3.New` with a `DialTimeout` blocks until it connects or the timeout passes.
- A transaction comparing a key outside the caller's role is refused whole, so the daemon's role
  must be able to read the marks it compares (Task 11).
- An etcd server certificate under client-certificate authentication is given no extended key
  usage (testpki's `NoExtKeyUsage`), which RFC 5280 reads as any purpose, because etcd's gateway
  dials itself with it.
- A `Value` compare on a missing key is false. A `ModRevision` compare on one is against 0.
- `errors.Is(err, rpctypes.ErrPermissionDenied)` works on the client's errors.

- [ ] **Step 1: The dependency.**

  ```bash
  go get go.etcd.io/etcd/client/v3@v3.6.15 go.etcd.io/etcd/server/v3@v3.6.15 go.etcd.io/etcd/api/v3@v3.6.15 \
    go.etcd.io/etcd/client/pkg/v3@v3.6.15 go.uber.org/zap
  go mod tidy
  ```

  `go.mod`'s `go` line becomes `go 1.26` (OD-1). Check that `go build ./cmd/...` does not link
  the server: `go list -deps ./cmd/port49d | grep -c 'etcd/server'` must print 0 once Task 12
  imports the client. Today it prints 0 because nothing imports either.

- [ ] **Step 2: `etcdtest`.** Create `internal/store/etcd/etcdtest/etcdtest.go`:

  ```go
  // Package etcdtest runs real etcd members inside a test binary
  // (go.etcd.io/etcd/server/v3/embed), so the store's tests and the lab need
  // no docker and no cgo (plan 7d, Ruling 2): one shared plain member per
  // package (Main), a member of a test's own with TLS and client-certificate
  // authentication (Start), three members for quorum (StartCluster), and a
  // TCP proxy that can stop answering (NewProxy). It is imported only by
  // tests and the lab; no binary links the etcd server.
  package etcdtest

  import (
  	"context"
  	"crypto/tls"
  	"fmt"
  	"net"
  	"net/url"
  	"os"
  	"path/filepath"
  	"strings"
  	"sync"
  	"sync/atomic"
  	"testing"
  	"time"

  	"go.etcd.io/etcd/client/pkg/v3/transport"
  	clientv3 "go.etcd.io/etcd/client/v3"
  	"go.etcd.io/etcd/server/v3/embed"
  	"go.uber.org/zap"

  	"github.com/rhwendt/port49/internal/testpki"
  )

  var shared struct {
  	endpoint string
  	client   *clientv3.Client
  	n        atomic.Int64
  }

  // Main starts the package's shared member, runs its tests, and stops it.
  // A package whose tests need etcd calls it from TestMain.
  func Main(m *testing.M) int {
  	dir, err := os.MkdirTemp("", "port49-etcd-")
  	if err != nil {
  		fmt.Fprintln(os.Stderr, "etcdtest:", err)
  		return 1
  	}
  	defer os.RemoveAll(dir)
  	e, err := member(memberSpec{name: "shared", dir: dir})
  	if err != nil {
  		fmt.Fprintln(os.Stderr, "etcdtest:", err)
  		return 1
  	}
  	defer e.Close()
  	shared.endpoint = "http://" + e.Clients[0].Addr().String()
  	shared.client, err = clientv3.New(clientv3.Config{Endpoints: []string{shared.endpoint},
  		DialTimeout: 5 * time.Second, Logger: zap.NewNop()})
  	if err != nil {
  		fmt.Fprintln(os.Stderr, "etcdtest:", err)
  		return 1
  	}
  	defer shared.client.Close()
  	return m.Run()
  }

  // Endpoint is the shared member's client URL.
  func Endpoint() string { return shared.endpoint }

  // Client is a client of the shared member, shared by every test in the
  // binary; never close it.
  func Client(testing.TB) *clientv3.Client { return shared.client }

  // Prefix is a key prefix no other caller in this binary has had, so each
  // store a test builds starts on an empty keyspace.
  func Prefix() string { return fmt.Sprintf("/storetest/%d/", shared.n.Add(1)) }

  type memberSpec struct {
  	name, dir      string
  	client, peer   string // URLs; "" picks a loopback port
  	cluster, token string // InitialCluster; "" is this member alone
  	tls            *transport.TLSInfo
  }

  func member(s memberSpec) (*embed.Etcd, error) {
  	cfg := embed.NewConfig()
  	cfg.Name, cfg.Dir = s.name, filepath.Join(s.dir, s.name)
  	cfg.ZapLoggerBuilder = embed.NewZapLoggerBuilder(zap.NewNop())
  	cfg.UnsafeNoFsync = true // a test member: durability is not what is measured
  	scheme := "http"
  	if s.tls != nil {
  		scheme = "https"
  		cfg.ClientTLSInfo = *s.tls
  	}
  	cu, err := url.Parse(or(s.client, scheme+"://127.0.0.1:0"))
  	if err != nil {
  		return nil, err
  	}
  	pu, err := url.Parse(or(s.peer, "http://127.0.0.1:0"))
  	if err != nil {
  		return nil, err
  	}
  	cfg.ListenClientUrls, cfg.AdvertiseClientUrls = []url.URL{*cu}, []url.URL{*cu}
  	cfg.ListenPeerUrls, cfg.AdvertisePeerUrls = []url.URL{*pu}, []url.URL{*pu}
  	cfg.InitialCluster = or(s.cluster, s.name+"="+pu.String())
  	if s.token != "" {
  		cfg.InitialClusterToken = s.token
  	}
  	e, err := embed.StartEtcd(cfg)
  	if err != nil {
  		return nil, err
  	}
  	select {
  	case <-e.Server.ReadyNotify():
  		return e, nil
  	case <-time.After(30 * time.Second):
  		e.Close()
  		return nil, fmt.Errorf("member %s not ready in 30s", s.name)
  	}
  }

  func or(s, d string) string {
  	if s == "" {
  		return d
  	}
  	return s
  }

  // Options is Start's: TLS turns on https with client-certificate
  // authentication under a CA of the server's own.
  type Options struct{ TLS bool }

  // Server is one member of a test's own.
  type Server struct {
  	Endpoint string
  	Dir      string // the PKI: ca.pem, and the client files ClientFiles writes
  	ca       *testpki.CA
  	e        *embed.Etcd
  }

  // Start runs a member for t alone, stopped at its cleanup.
  func Start(t testing.TB, o Options) *Server {
  	t.Helper()
  	s := &Server{Dir: t.TempDir()}
  	spec := memberSpec{name: "solo", dir: t.TempDir()}
  	if o.TLS {
  		now := time.Now()
  		ca, err := testpki.NewCA("etcdtest CA", now.Add(-time.Hour), now.Add(24*time.Hour))
  		if err != nil {
  			t.Fatal(err)
  		}
  		s.ca = ca
  		srv, err := ca.Issue(testpki.Leaf{CommonName: "etcd", IPs: testpki.Loopback(), NoExtKeyUsage: true,
  			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
  		if err != nil {
  			t.Fatal(err)
  		}
  		certPEM, keyPEM, err := testpki.PEMs(srv)
  		if err != nil {
  			t.Fatal(err)
  		}
  		for name, body := range map[string][]byte{"ca.pem": ca.PEM(), "server.pem": certPEM, "server-key.pem": keyPEM} {
  			if err := os.WriteFile(filepath.Join(s.Dir, name), body, 0o600); err != nil {
  				t.Fatal(err)
  			}
  		}
  		spec.tls = &transport.TLSInfo{CertFile: filepath.Join(s.Dir, "server.pem"),
  			KeyFile: filepath.Join(s.Dir, "server-key.pem"), TrustedCAFile: filepath.Join(s.Dir, "ca.pem"),
  			ClientCertAuth: true}
  	}
  	e, err := member(spec)
  	if err != nil {
  		t.Fatal(err)
  	}
  	t.Cleanup(e.Close)
  	s.e = e
  	scheme := "http://"
  	if o.TLS {
  		scheme = "https://"
  	}
  	s.Endpoint = scheme + e.Clients[0].Addr().String()
  	return s
  }

  // ClientFiles writes a client certificate for cn, from the server's CA,
  // into Dir, and returns the certificate's and the key's paths.
  func (s *Server) ClientFiles(t testing.TB, cn string) (cert, key string) {
  	t.Helper()
  	now := time.Now()
  	c, err := s.ca.Issue(testpki.Leaf{CommonName: cn, Client: true, NotBefore: now.Add(-time.Hour),
  		NotAfter: now.Add(24 * time.Hour)})
  	if err != nil {
  		t.Fatal(err)
  	}
  	certPEM, keyPEM, err := testpki.PEMs(c)
  	if err != nil {
  		t.Fatal(err)
  	}
  	cert, key = filepath.Join(s.Dir, cn+".pem"), filepath.Join(s.Dir, cn+"-key.pem")
  	if err := os.WriteFile(cert, certPEM, 0o600); err != nil {
  		t.Fatal(err)
  	}
  	if err := os.WriteFile(key, keyPEM, 0o600); err != nil {
  		t.Fatal(err)
  	}
  	return cert, key
  }

  // TLS is a client TLS config presenting a certificate for cn.
  func (s *Server) TLS(t testing.TB, cn string) *tls.Config {
  	t.Helper()
  	cert, key := s.ClientFiles(t, cn)
  	pair, err := tls.LoadX509KeyPair(cert, key)
  	if err != nil {
  		t.Fatal(err)
  	}
  	return &tls.Config{RootCAs: s.ca.Pool(), Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
  }

  // Client is a client of s as cn (cn is ignored without TLS), closed at t's
  // cleanup.
  func (s *Server) Client(t testing.TB, cn string) *clientv3.Client {
  	t.Helper()
  	cfg := clientv3.Config{Endpoints: []string{s.Endpoint}, DialTimeout: 5 * time.Second, Logger: zap.NewNop()}
  	if strings.HasPrefix(s.Endpoint, "https://") {
  		cfg.TLS = s.TLS(t, cn)
  	}
  	c, err := clientv3.New(cfg)
  	if err != nil {
  		t.Fatal(err)
  	}
  	t.Cleanup(func() { c.Close() })
  	return c
  }

  // Cluster is three members, for what a lost quorum looks like.
  type Cluster struct {
  	Endpoints []string
  	members   []*embed.Etcd
  	once      []sync.Once
  }

  // StartCluster runs three members for t, stopped at its cleanup.
  func StartCluster(t testing.TB) *Cluster {
  	t.Helper()
  	names := []string{"m0", "m1", "m2"}
  	var peers, clients, initial []string
  	for _, n := range names {
  		peers, clients = append(peers, "http://"+freePort(t)), append(clients, "http://"+freePort(t))
  		initial = append(initial, n+"="+peers[len(peers)-1])
  	}
  	dir := t.TempDir()
  	c := &Cluster{Endpoints: clients, members: make([]*embed.Etcd, 3), once: make([]sync.Once, 3)}
  	errs := make(chan error, 3)
  	for i, n := range names {
  		go func(i int, n string) {
  			e, err := member(memberSpec{name: n, dir: dir, client: clients[i], peer: peers[i],
  				cluster: strings.Join(initial, ","), token: "port49-etcdtest"})
  			c.members[i] = e
  			errs <- err
  		}(i, n)
  	}
  	for range names {
  		if err := <-errs; err != nil {
  			t.Fatal(err)
  		}
  	}
  	for i := range names {
  		t.Cleanup(func() { c.Stop(i) })
  	}
  	return c
  }

  // Stop stops member i; stopping two of three loses the quorum.
  func (c *Cluster) Stop(i int) { c.once[i].Do(func() { c.members[i].Close() }) }

  func freePort(t testing.TB) string {
  	t.Helper()
  	l, err := net.Listen("tcp", "127.0.0.1:0")
  	if err != nil {
  		t.Fatal(err)
  	}
  	defer l.Close()
  	return l.Addr().String()
  }

  // Proxy forwards TCP to a target. Hang stops it forwarding, in both
  // directions, without closing anything: what a partition looks like to a
  // client, requests that never come back. Delay holds each chunk that long.
  type Proxy struct {
  	ln     net.Listener
  	target string
  	mu     sync.Mutex
  	cond   *sync.Cond
  	hung   bool
  	delay  time.Duration
  }

  // NewProxy listens on a loopback port, forwarding to target (host:port),
  // until t's cleanup.
  func NewProxy(t testing.TB, target string) *Proxy {
  	t.Helper()
  	ln, err := net.Listen("tcp", "127.0.0.1:0")
  	if err != nil {
  		t.Fatal(err)
  	}
  	p := &Proxy{ln: ln, target: target}
  	p.cond = sync.NewCond(&p.mu)
  	t.Cleanup(func() { p.Hang(false); ln.Close() })
  	go p.serve()
  	return p
  }

  // Addr is the proxy's host:port.
  func (p *Proxy) Addr() string { return p.ln.Addr().String() }

  // Hang stops or resumes forwarding.
  func (p *Proxy) Hang(on bool) {
  	p.mu.Lock()
  	p.hung = on
  	p.mu.Unlock()
  	p.cond.Broadcast()
  }

  // Delay holds every chunk d before forwarding it.
  func (p *Proxy) Delay(d time.Duration) {
  	p.mu.Lock()
  	p.delay = d
  	p.mu.Unlock()
  }

  func (p *Proxy) serve() {
  	for {
  		c, err := p.ln.Accept()
  		if err != nil {
  			return
  		}
  		go func() {
  			u, err := net.Dial("tcp", p.target)
  			if err != nil {
  				c.Close()
  				return
  			}
  			go p.pipe(u, c)
  			p.pipe(c, u)
  		}()
  	}
  }

  func (p *Proxy) pipe(dst, src net.Conn) {
  	defer dst.Close()
  	defer src.Close()
  	buf := make([]byte, 32<<10)
  	for {
  		n, err := src.Read(buf)
  		if n > 0 {
  			p.mu.Lock()
  			for p.hung {
  				p.cond.Wait()
  			}
  			d := p.delay
  			p.mu.Unlock()
  			time.Sleep(d)
  			if _, werr := dst.Write(buf[:n]); werr != nil {
  				return
  			}
  		}
  		if err != nil {
  			return
  		}
  	}
  }

  // EnableAuth turns on etcd's authentication on s as its root user (a
  // client certificate whose CN is "root"), creating each role with its
  // grants and each user (a certificate CN) with its roles. It is what an
  // operator does with port49d store-roles' output (plan 7d).
  func (s *Server) EnableAuth(t testing.TB, grants []Grant, users map[string][]string) {
  	t.Helper()
  	ctx := context.Background()
  	root := s.Client(t, "root")
  	must := func(_ any, err error) {
  		t.Helper()
  		if err != nil {
  			t.Fatal(err)
  		}
  	}
  	must(root.UserAddWithOptions(ctx, "root", "", &clientv3.UserAddOptions{NoPassword: true}))
  	must(root.UserGrantRole(ctx, "root", "root"))
  	roles := map[string]bool{}
  	for _, g := range grants {
  		if !roles[g.Role] {
  			must(root.RoleAdd(ctx, g.Role))
  			roles[g.Role] = true
  		}
  		perm := clientv3.PermRead
  		if g.Write {
  			perm = clientv3.PermReadWrite
  		}
  		must(root.RoleGrantPermission(ctx, g.Role, g.Key, g.RangeEnd, clientv3.PermissionType(perm)))
  	}
  	for user, rs := range users {
  		must(root.UserAddWithOptions(ctx, user, "", &clientv3.UserAddOptions{NoPassword: true}))
  		for _, r := range rs {
  			must(root.UserGrantRole(ctx, user, r))
  		}
  	}
  	must(root.AuthEnable(ctx))
  }

  // Grant is one role permission: Key to RangeEnd ("" for the one key), read,
  // or read and write.
  type Grant struct {
  	Role, Key, RangeEnd string
  	Write               bool
  }
  ```

  `EnableAuth` and `Grant` are used from Task 11 on. They are here so `etcdtest` is one file.

- [ ] **Step 3: The failing test.** Create `internal/store/etcd/etcd_test.go`:

  ```go
  package etcd

  import (
  	"context"
  	"errors"
  	"os"
  	"testing"
  	"time"

  	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
  	clientv3 "go.etcd.io/etcd/client/v3"

  	"github.com/rhwendt/port49/internal/store"
  	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
  	"github.com/rhwendt/port49/internal/store/storetest"
  )

  func TestMain(m *testing.M) { os.Exit(etcdtest.Main(m)) }

  // onShared is a store on the shared member's client, under a prefix of its
  // own, whose clock is clock.
  func onShared(t *testing.T, clock func() time.Time) *Store {
  	cli := etcdtest.Client(t)
  	return newStore(cli, cli, Config{Prefix: etcdtest.Prefix(), Now: clock})
  }

  var backend = storetest.Backend{New: func(t *testing.T, clock func() time.Time) store.Store {
  	return onShared(t, clock)
  }}

  // run runs the named properties against etcd. Task 8 replaces every call
  // with storetest.Run.
  func run(t *testing.T, props map[string]func(*testing.T)) {
  	for name, p := range props {
  		t.Run(name, p)
  	}
  }

  var t0 = time.Unix(1_000_000, 0).UTC()

  func fixed(t *testing.T) func() store.Store {
  	return func() store.Store { return onShared(t, func() time.Time { return t0 }) }
  }

  // The token family: tokens, receipts, the token index, the delete by ID
  // and its race, and the marks (plan 7d Task 5).
  func TestTokensOnEtcd(t *testing.T) {
  	run(t, map[string]func(*testing.T){
  		"TokenLifecycle":                     func(t *testing.T) { storetest.TokenLifecycle(t, backend) },
  		"RedeemIsAtomic":                     func(t *testing.T) { storetest.RedeemIsAtomic(t, backend) },
  		"SecretsAreNotAliased":               func(t *testing.T) { storetest.SecretsAreNotAliased(t, backend) },
  		"RedeemByID":                         func(t *testing.T) { storetest.RedeemByID(t, backend) },
  		"ReceiptRetainedPastItsSlidingBound": func(t *testing.T) { storetest.ReceiptRetainedPastItsSlidingBound(t, backend) },
  		"FailReceiptMarksOnly":               func(t *testing.T) { storetest.FailReceiptMarksOnly(t, backend) },
  		"DeleteReceiptsByPrincipal":          func(t *testing.T) { storetest.DeleteReceiptsByPrincipal(t, backend) },
  		"TokenIndexExpiresWithItsLongestToken": func(t *testing.T) {
  			storetest.TokenIndexExpiresWithItsLongestToken(t, backend)
  		},
  		"TokenIndex":                 func(t *testing.T) { storetest.TokenIndex(t, fixed(t), t0) },
  		"DeleteTokenRemovesOne":      func(t *testing.T) { storetest.DeleteTokenRemovesOne(t, fixed(t), t0) },
  		"DeleteTokenRacesRedeem":     func(t *testing.T) { storetest.DeleteTokenRacesRedeem(t, fixed(t), t0) },
  		"RevocationMarks":            func(t *testing.T) { storetest.RevocationMarks(t, fixed(t), t0) },
  		"RevocationMarkNeverExpires": func(t *testing.T) { storetest.RevocationMarkNeverExpires(t, backend) },
  	})
  }

  // A lease etcd no longer knows (expired while port49d was paused, or
  // revoked by an operator) costs the next put one retry on a fresh lease;
  // the record lands, on a lease (Review Focus 2).
  func TestAPutOnALostLeaseTakesAFreshOne(t *testing.T) {
  	ctx := context.Background()
  	s := onShared(t, func() time.Time { return t0 })
  	k := store.TokenKey{NAS: "leaf-01", Username: "svc"}
  	if _, err := s.PutToken(ctx, k, store.Token{ID: "a", Secret: []byte("x"), Kind: store.KindLogin,
  		ExpiresAt: t0.Add(time.Minute)}); err != nil {
  		t.Fatal(err)
  	}
  	resp, err := s.tok.Get(ctx, s.k.token(k, "a"))
  	if err != nil || len(resp.Kvs) != 1 || resp.Kvs[0].Lease == 0 {
  		t.Fatalf("the token has no lease: %v %v", resp, err)
  	}
  	if _, err := s.tok.Revoke(ctx, clientv3.LeaseID(resp.Kvs[0].Lease)); err != nil {
  		t.Fatal(err)
  	}
  	if _, err := s.PutToken(ctx, k, store.Token{ID: "b", Secret: []byte("y"), Kind: store.KindLogin,
  		ExpiresAt: t0.Add(time.Minute)}); err != nil {
  		t.Fatalf("a put after its cached lease was revoked: %v", err)
  	}
  	resp, err = s.tok.Get(ctx, s.k.token(k, "b"))
  	if err != nil || len(resp.Kvs) != 1 || resp.Kvs[0].Lease == 0 {
  		t.Fatalf("the second token: %v %v", resp, err)
  	}
  }

  // A record is never on a lease shorter than its life plus the grace: an
  // expiry an hour out on port49d's clock is a lease of at least an hour and
  // five minutes on etcd's, whatever the two clocks read.
  func TestALeaseOutlivesItsRecord(t *testing.T) {
  	ctx := context.Background()
  	s := onShared(t, func() time.Time { return t0 })
  	k := store.TokenKey{NAS: "leaf-01", Username: "svc"}
  	if _, err := s.PutToken(ctx, k, store.Token{ID: "a", Secret: []byte("x"), Kind: store.KindLogin,
  		ExpiresAt: t0.Add(time.Hour)}); err != nil {
  		t.Fatal(err)
  	}
  	resp, _ := s.tok.Get(ctx, s.k.token(k, "a"))
  	ttl, err := s.tok.TimeToLive(ctx, clientv3.LeaseID(resp.Kvs[0].Lease))
  	if err != nil || time.Duration(ttl.TTL)*time.Second < time.Hour+5*time.Minute {
  		t.Fatalf("lease TTL %ds: %v", ttl.TTL, err)
  	}
  	// A token already expired is put on the shortest lease and never read.
  	if _, err := s.PutToken(ctx, k, store.Token{ID: "old", Secret: []byte("z"), Kind: store.KindLogin,
  		ExpiresAt: t0}); err != nil {
  		t.Fatalf("an expired put (7c M-2): %v", err)
  	}
  	if got, _ := s.Candidates(ctx, k); len(got) != 1 || got[0].ID != "a" {
  		t.Fatalf("candidates: %v", got)
  	}
  }

  // An outage is store.ErrUnavailable; a refusal by etcd's roles is not
  // (it is a configuration error, never a reason to trip a circuit).
  func TestUnavailableClassifies(t *testing.T) {
  	if err := unavailable(context.DeadlineExceeded); !errors.Is(err, store.ErrUnavailable) {
  		t.Fatalf("a deadline: %v", err)
  	}
  	if err := unavailable(rpctypes.ErrPermissionDenied); errors.Is(err, store.ErrUnavailable) || !errors.Is(err, ErrRefused) {
  		t.Fatalf("a refusal: %v", err)
  	}
  	if err := unavailable(context.Canceled); !errors.Is(err, context.Canceled) || errors.Is(err, store.ErrUnavailable) {
  		t.Fatalf("a caller that gave up: %v", err)
  	}
  }
  ```

  Run: `go test ./internal/store/etcd/ -count=1`
  Expected: FAIL to build (`newStore`, `Store`, `Config`, `unavailable`, `ErrRefused` undefined).

- [ ] **Step 4: The store and its keys.** Create `internal/store/etcd/etcd.go`:

  ```go
  // Package etcd is store.Store on etcd v3 (plan 7d; spec §13, decision 35).
  //
  // Each record is one key under Config.Prefix + "v1/", its value JSON with
  // snake_case keys (records.go), and every compare-and-set a transaction on
  // the key's mod_revision (commit.go). Expiry is the record's own, read
  // against Config.Now; leases only reclaim, at least LeaseGrace after it
  // (leases.go). Every read is linearizable: a member cut off from its
  // quorum answers nothing, never a stale record. A context's Rev is its
  // key's mod_revision, and its PolicyRev comes from the same counter
  // (records.go, ctxRec).
  package etcd

  import (
  	"context"
  	"crypto/tls"
  	"errors"
  	"fmt"
  	"time"

  	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
  	clientv3 "go.etcd.io/etcd/client/v3"
  	"go.uber.org/zap"

  	"github.com/rhwendt/port49/internal/store"
  )

  // Config is one component's view of etcd.
  type Config struct {
  	Endpoints []string
  	// TLS is the component's client certificate and the CA that signs
  	// etcd's. Nil dials in the clear, which only tests do: port49d refuses
  	// an endpoint that is not https.
  	TLS *tls.Config
  	// Prefix is the keyspace; "/port49/" when empty. Records live under
  	// Prefix + "v1/".
  	Prefix string
  	// Now is the clock every expiry is read against; time.Now when nil.
  	Now func() time.Time
  	// LeaseGrace is how long past its expiry a record's lease outlives it;
  	// 5m when zero.
  	LeaseGrace time.Duration
  	// DialTimeout bounds Open's connect; 5s when zero.
  	DialTimeout time.Duration
  }

  // Store is store.Store on etcd.
  type Store struct {
  	k   keys
  	now func() time.Time
  	// tok and ctx are the token and context pools (design §12): mint
  	// pressure on one cannot take the other's connection. They are one
  	// client until plan 7d Task 11 dials two.
  	tok, ctx             *clientv3.Client
  	tokLeases, ctxLeases *leases
  	owned                []*clientv3.Client // closed by Close
  }

  // ErrRefused is etcd refusing this identity an operation: a role that
  // does not grant it, or authentication that failed. It is configuration,
  // not an outage: never store.ErrUnavailable, so it trips no circuit.
  var ErrRefused = errors.New("etcd: refused this identity")

  // Open dials etcd and returns the store. It fails, wrapping
  // store.ErrUnavailable, when no endpoint answers within DialTimeout.
  func Open(c Config) (*Store, error) {
  	c = c.withDefaults()
  	cli, err := dial(c)
  	if err != nil {
  		return nil, err
  	}
  	s := newStore(cli, cli, c)
  	s.owned = []*clientv3.Client{cli}
  	return s, nil
  }

  func (c Config) withDefaults() Config {
  	if c.Prefix == "" {
  		c.Prefix = "/port49/"
  	}
  	if c.Now == nil {
  		c.Now = time.Now
  	}
  	if c.LeaseGrace == 0 {
  		c.LeaseGrace = 5 * time.Minute
  	}
  	if c.DialTimeout == 0 {
  		c.DialTimeout = 5 * time.Second
  	}
  	return c
  }

  func dial(c Config) (*clientv3.Client, error) {
  	if len(c.Endpoints) == 0 {
  		return nil, errors.New("etcd: no endpoints")
  	}
  	cli, err := clientv3.New(clientv3.Config{Endpoints: c.Endpoints, TLS: c.TLS, DialTimeout: c.DialTimeout,
  		// The client's own JSON lines would land in port49d's stderr, which
  		// is the operator's; port49d says what matters itself.
  		Logger:               zap.NewNop(),
  		DialKeepAliveTime:    5 * time.Second,
  		DialKeepAliveTimeout: 2 * time.Second,
  		RejectOldCluster:     true,
  	})
  	if err != nil {
  		return nil, fmt.Errorf("%w: etcd at %v: %v", store.ErrUnavailable, c.Endpoints, err)
  	}
  	return cli, nil
  }

  // newStore is a store on clients the caller owns: tests build many on one.
  func newStore(tok, ctx *clientv3.Client, c Config) *Store {
  	c = c.withDefaults()
  	s := &Store{k: newKeys(c.Prefix), now: c.Now, tok: tok, ctx: ctx}
  	s.tokLeases = newLeases(tok, c.Now, c.LeaseGrace)
  	s.ctxLeases = s.tokLeases
  	if ctx != tok {
  		s.ctxLeases = newLeases(ctx, c.Now, c.LeaseGrace)
  	}
  	return s
  }

  // Close closes the clients Open dialed.
  func (s *Store) Close() error {
  	var first error
  	for _, c := range s.owned {
  		if err := c.Close(); err != nil && first == nil {
  			first = err
  		}
  	}
  	return first
  }

  // Ping is one linearizable read on the context pool: nil when etcd's
  // quorum answers.
  func (s *Store) Ping(ctx context.Context) error {
  	_, err := s.ctx.Get(ctx, s.k.meta("ping"))
  	return unavailable(err)
  }

  // unavailable classifies an etcd error for the layers above: a caller that
  // gave up is its own error; a refusal of this identity is ErrRefused; any
  // other — a deadline, no leader, no quorum, a dropped connection — is
  // store.ErrUnavailable.
  func unavailable(err error) error {
  	switch {
  	case err == nil:
  		return nil
  	case errors.Is(err, context.Canceled):
  		return err
  	case errors.Is(err, rpctypes.ErrPermissionDenied), errors.Is(err, rpctypes.ErrAuthFailed),
  		errors.Is(err, rpctypes.ErrUserEmpty), errors.Is(err, rpctypes.ErrInvalidAuthToken):
  		return fmt.Errorf("%w: %v", ErrRefused, err)
  	}
  	return fmt.Errorf("%w: %v", store.ErrUnavailable, err)
  }
  ```

  Create `internal/store/etcd/keys.go`:

  ```go
  package etcd

  import (
  	"encoding/hex"
  	"net/url"
  	"strings"

  	"github.com/rhwendt/port49/internal/store"
  )

  // keys builds every key under one keyspace. Each part is escaped
  // (url.PathEscape), so a "/" in a device name, username, principal, sid or
  // certificate key cannot split it, and every family that is scanned by
  // prefix ends its scanned parts with "/", so "user:al" never matches
  // "user:alice" (Review Focus 3).
  type keys struct{ root string }

  func newKeys(prefix string) keys {
  	if !strings.HasSuffix(prefix, "/") {
  		prefix += "/"
  	}
  	return keys{root: prefix + "v1/"}
  }

  func esc(parts ...string) string {
  	out := make([]string, len(parts))
  	for i, p := range parts {
  		out[i] = url.PathEscape(p)
  	}
  	return strings.Join(out, "/")
  }

  // The families. Each comment is the key's shape after the root.
  const (
  	famToken       = "t/"  // t/<nas>/<user>/<id>: a token
  	famReceipt     = "r/"  // r/<nas>/<user>/<kind>/<sha256 hex>: a receipt
  	famReceiptBy   = "rp/" // rp/<principal>/<nas>/<user>/<kind>/<sha256 hex>: its revocation index
  	famContext     = "c/"  // c/<nas>/<user>: a login context
  	famIndexed     = "x/"  // x/<nas>/<user>: the ref's index record, authoritative
  	famByPrincipal = "ip/" // ip/<principal>/<nas>/<user>: a lookup entry
  	famBySid       = "is/" // is/<sid>/<nas>/<user>
  	famByCert      = "ic/" // ic/<cert key>/<nas>/<user>
  	famBlob        = "b/"  // b/<hash>
  	famTokByPrin   = "tp/" // tp/<principal>/<nas>/<user>: the token index
  	famTokByCert   = "tc/" // tc/<cert key>/<nas>/<user>
  	famIdem        = "id/" // id/<principal>/<key>: an idempotency record
  	famMark        = "rv/" // rv/<kind>/<key>: a revocation mark
  	famMeta        = "meta/"
  )

  func (k keys) family(f string) string { return k.root + f }

  func (k keys) tokens(t store.TokenKey) string           { return k.root + famToken + esc(t.NAS, t.Username) + "/" }
  func (k keys) token(t store.TokenKey, id string) string { return k.tokens(t) + esc(id) }

  func receiptTail(r store.ReceiptKey) string {
  	return esc(r.NAS, r.Username, r.Kind, hex.EncodeToString(r.CredentialSHA256[:]))
  }
  func (k keys) receipt(r store.ReceiptKey) string { return k.root + famReceipt + receiptTail(r) }
  func (k keys) receiptsBy(principal string) string {
  	return k.root + famReceiptBy + esc(principal) + "/"
  }
  func (k keys) receiptBy(principal string, r store.ReceiptKey) string {
  	return k.receiptsBy(principal) + receiptTail(r)
  }

  func (k keys) context(c store.ContextKey) string { return k.root + famContext + esc(c.NAS, c.Username) }
  func (k keys) indexed(r store.ContextRef) string { return k.root + famIndexed + esc(r.NAS, r.Username) }
  func (k keys) lookups(fam, key string) string    { return k.root + fam + esc(key) + "/" }
  func (k keys) lookup(fam, key string, r store.ContextRef) string {
  	return k.lookups(fam, key) + esc(r.NAS, r.Username)
  }

  func (k keys) blob(hash string) string { return k.root + famBlob + esc(hash) }

  func (k keys) tokenIndex(fam, key string) string { return k.root + fam + esc(key) + "/" }
  func (k keys) tokenIndexed(fam, key string, t store.TokenKey) string {
  	return k.tokenIndex(fam, key) + esc(t.NAS, t.Username)
  }

  func (k keys) idem(principal, key string) string { return k.root + famIdem + esc(principal, key) }
  func (k keys) mark(kind, key string) string      { return k.root + famMark + esc(kind, key) }
  func (k keys) meta(name string) string           { return k.root + famMeta + name }

  // lastTwo unescapes the last two parts of key: the (NAS, Username) every
  // lookup entry and token-index entry ends in.
  func lastTwo(key string) (string, string, bool) {
  	i := strings.LastIndexByte(key, '/')
  	if i <= 0 {
  		return "", "", false
  	}
  	j := strings.LastIndexByte(key[:i], '/')
  	if j < 0 {
  		return "", "", false
  	}
  	a, err1 := url.PathUnescape(key[j+1 : i])
  	b, err2 := url.PathUnescape(key[i+1:])
  	return a, b, err1 == nil && err2 == nil
  }
  ```

  `famMeta` and `meta` are used by `Ping` now, and by Tasks 12–13.

- [ ] **Step 5: The records.** Create `internal/store/etcd/records.go`:

  ```go
  package etcd

  import (
  	"encoding/hex"
  	"time"

  	"github.com/rhwendt/port49/internal/store"
  )

  // The records as stored: JSON with snake_case keys (spec: data is
  // snake_case). A store type is never marshalled itself — its fields carry
  // no tags — but converted to one of these and back. Each record holds its
  // own expiry; the revisions are etcd's.

  // credRec is store.Credential with tags: the same fields in the same
  // order, so each converts to the other directly.
  type credRec struct {
  	Method      string   `json:"method,omitempty"`
  	Fingerprint string   `json:"fingerprint,omitempty"`
  	Issuer      string   `json:"issuer,omitempty"`
  	Serial      string   `json:"serial,omitempty"`
  	Subject     string   `json:"subject,omitempty"`
  	Iss         string   `json:"iss,omitempty"`
  	Sub         string   `json:"sub,omitempty"`
  	Sid         string   `json:"sid,omitempty"`
  	ACR         string   `json:"acr,omitempty"`
  	AMR         []string `json:"amr,omitempty"`
  }

  type tokenRec struct {
  	ID            string        `json:"id"`
  	Secret        []byte        `json:"secret,omitempty"`
  	Kind          string        `json:"kind"`
  	ExpiresAt     time.Time     `json:"expires_at"`
  	Principal     string        `json:"principal,omitempty"`
  	Username      string        `json:"username,omitempty"`
  	BlobHash      string        `json:"blob_hash,omitempty"`
  	MaxSessionAge time.Duration `json:"max_session_age"`
  	Enable        string        `json:"enable,omitempty"`
  	MaxPrivilege  uint8         `json:"max_privilege"`
  	Credential    credRec       `json:"credential"`
  	AuthTime      time.Time     `json:"auth_time"`
  	MintedAt      time.Time     `json:"minted_at"`
  	Sealed        []byte        `json:"sealed,omitempty"`
  }

  func tokenRecOf(t store.Token) tokenRec {
  	return tokenRec{ID: t.ID, Secret: t.Secret, Kind: t.Kind, ExpiresAt: t.ExpiresAt, Principal: t.Principal,
  		Username: t.Username, BlobHash: t.BlobHash, MaxSessionAge: t.MaxSessionAge, Enable: t.Enable,
  		MaxPrivilege: t.MaxPrivilege, Credential: credRec(t.Credential), AuthTime: t.AuthTime, MintedAt: t.MintedAt,
  		Sealed: t.Sealed}
  }

  func (r tokenRec) token() store.Token {
  	return store.Token{ID: r.ID, Secret: r.Secret, Kind: r.Kind, ExpiresAt: r.ExpiresAt, Principal: r.Principal,
  		Username: r.Username, BlobHash: r.BlobHash, MaxSessionAge: r.MaxSessionAge, Enable: r.Enable,
  		MaxPrivilege: r.MaxPrivilege, Credential: store.Credential(r.Credential), AuthTime: r.AuthTime,
  		MintedAt: r.MintedAt, Sealed: r.Sealed}
  }

  type receiptRec struct {
  	CredentialSHA256 string    `json:"credential_sha256,omitempty"` // hex; zero when sealed
  	Status           uint8     `json:"status"`
  	CtxID            string    `json:"ctx_id,omitempty"`
  	FirstRedeemedAt  time.Time `json:"first_redeemed_at"`
  	IdleExpiresAt    time.Time `json:"idle_expires_at"`
  	RetainUntil      time.Time `json:"retain_until"`
  	Failed           bool      `json:"failed"`
  	Sealed           []byte    `json:"sealed,omitempty"`
  }

  func receiptRecOf(r store.Receipt) receiptRec {
  	out := receiptRec{Status: r.Status, CtxID: r.CtxID, FirstRedeemedAt: r.FirstRedeemedAt,
  		IdleExpiresAt: r.IdleExpiresAt, RetainUntil: r.RetainUntil, Failed: r.Failed, Sealed: r.Sealed}
  	if r.CredentialSHA256 != ([32]byte{}) {
  		out.CredentialSHA256 = hex.EncodeToString(r.CredentialSHA256[:])
  	}
  	return out
  }

  func (r receiptRec) receipt() store.Receipt {
  	out := store.Receipt{Status: r.Status, CtxID: r.CtxID, FirstRedeemedAt: r.FirstRedeemedAt,
  		IdleExpiresAt: r.IdleExpiresAt, RetainUntil: r.RetainUntil, Failed: r.Failed, Sealed: r.Sealed}
  	if b, err := hex.DecodeString(r.CredentialSHA256); err == nil && len(b) == 32 {
  		copy(out.CredentialSHA256[:], b)
  	}
  	return out
  }

  // expiryRec is an index entry's whole value: when it stops naming its key.
  type expiryRec struct {
  	ExpiresAt time.Time `json:"expires_at"`
  }

  type markRec struct {
  	Kind   string    `json:"kind"`
  	Key    string    `json:"key"`
  	At     time.Time `json:"at"`
  	Origin string    `json:"origin,omitempty"`
  }

  func markRecOf(r store.Revocation) markRec {
  	return markRec{Kind: r.Kind, Key: r.Key, At: r.At, Origin: r.Origin}
  }

  func (r markRec) revocation() store.Revocation {
  	return store.Revocation{Kind: r.Kind, Key: r.Key, At: r.At, Origin: r.Origin}
  }
  ```

  Task 6 adds `ctxRec`, `blobRec` and `idxRec` to this file; Task 8 adds `idemRec`.

- [ ] **Step 6: Leases.** Create `internal/store/etcd/leases.go`:

  ```go
  package etcd

  import (
  	"context"
  	"math"
  	"sync"
  	"time"

  	clientv3 "go.etcd.io/etcd/client/v3"
  )

  // leaseBucket is the width of one lease's expiry bucket: every record
  // dying in the same minute shares a lease, so leases are granted at most
  // one a minute of expiries, not one a record (design D1's cost).
  const leaseBucket = time.Minute

  // leases hands out the lease a record is put on. A lease only reclaims:
  // the record's own expiry, read against now, decides whether it is live
  // (plan 7d, Ruling 3). So a lease is always the bucket ending at least
  // grace after the record's expiry, and its TTL is a duration on etcd's
  // clock, which skew between port49d and etcd cannot shorten.
  type leases struct {
  	cli   *clientv3.Client
  	now   func() time.Time
  	grace time.Duration
  	mu    sync.Mutex
  	// held is, by bucket end (unix seconds of now's clock), the lease
  	// granted for it and until when it lives on the wall clock.
  	held map[int64]heldLease
  }

  type heldLease struct {
  	id    clientv3.LeaseID
  	until time.Time
  }

  func newLeases(cli *clientv3.Client, now func() time.Time, grace time.Duration) *leases {
  	return &leases{cli: cli, now: now, grace: grace, held: map[int64]heldLease{}}
  }

  // For returns a lease that lives at least until exp plus grace, measured
  // from now on now's clock. An expiry already past gets the shortest such
  // lease: the record is never read as live, and is reclaimed soon (7c M-2).
  func (l *leases) For(ctx context.Context, exp time.Time) (clientv3.LeaseID, error) {
  	now := l.now()
  	end := exp.Add(l.grace).Truncate(leaseBucket).Add(leaseBucket)
  	need := end.Sub(now)
  	if need < l.grace {
  		need = l.grace
  	}
  	wallNeed := time.Now().Add(need)
  	l.mu.Lock()
  	if h, ok := l.held[end.Unix()]; ok && !h.until.Before(wallNeed) {
  		l.mu.Unlock()
  		return h.id, nil
  	}
  	l.mu.Unlock()
  	// A bucket's worth more, so records of the same bucket put later still
  	// fit on it.
  	ttl := int64(math.Ceil((need + leaseBucket).Seconds()))
  	resp, err := l.cli.Grant(ctx, ttl)
  	if err != nil {
  		return 0, err
  	}
  	l.mu.Lock()
  	defer l.mu.Unlock()
  	wall := time.Now()
  	l.held[end.Unix()] = heldLease{id: resp.ID, until: wall.Add(time.Duration(resp.TTL) * time.Second)}
  	for b, h := range l.held {
  		if h.until.Before(wall) {
  			delete(l.held, b)
  		}
  	}
  	return resp.ID, nil
  }

  // Reset forgets every lease, after etcd said it no longer knows one.
  func (l *leases) Reset() {
  	l.mu.Lock()
  	l.held = map[int64]heldLease{}
  	l.mu.Unlock()
  }
  ```

- [ ] **Step 7: Commit and compare-and-set.** Create `internal/store/etcd/commit.go`:

  ```go
  package etcd

  import (
  	"context"
  	"encoding/json"
  	"errors"
  	"fmt"
  	"time"

  	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
  	clientv3 "go.etcd.io/etcd/client/v3"
  )

  // put is one write of a transaction, its lease chosen at commit: a zero
  // exp is no lease (a mark, a lookup entry, the index record's own rule
  // aside), and keep keeps the key's own lease (a receipt's flag).
  type put struct {
  	key  string
  	val  []byte
  	exp  time.Time
  	keep bool
  }

  // del is one delete of a transaction; prefix deletes the range.
  type del struct {
  	key    string
  	prefix bool
  }

  // commit runs one transaction on cli: if every cmp holds, every put and
  // del. It reports whether the cmps held. A lease etcd no longer knows (one
  // that expired while port49d was paused, or an operator revoked) costs one
  // retry on fresh leases (Review Focus 2).
  func commit(ctx context.Context, cli *clientv3.Client, ls *leases, cmps []clientv3.Cmp, puts []put, dels ...del) (bool, error) {
  	for attempt := 0; ; attempt++ {
  		ops := make([]clientv3.Op, 0, len(puts)+len(dels))
  		for _, p := range puts {
  			switch {
  			case p.keep:
  				ops = append(ops, clientv3.OpPut(p.key, string(p.val), clientv3.WithIgnoreLease()))
  			case p.exp.IsZero():
  				ops = append(ops, clientv3.OpPut(p.key, string(p.val)))
  			default:
  				id, err := ls.For(ctx, p.exp)
  				if err != nil {
  					return false, unavailable(err)
  				}
  				ops = append(ops, clientv3.OpPut(p.key, string(p.val), clientv3.WithLease(id)))
  			}
  		}
  		for _, d := range dels {
  			if d.prefix {
  				ops = append(ops, clientv3.OpDelete(d.key, clientv3.WithPrefix()))
  			} else {
  				ops = append(ops, clientv3.OpDelete(d.key))
  			}
  		}
  		resp, err := cli.Txn(ctx).If(cmps...).Then(ops...).Commit()
  		if errors.Is(err, rpctypes.ErrLeaseNotFound) && attempt == 0 {
  			ls.Reset()
  			continue
  		}
  		if err != nil {
  			return false, unavailable(err)
  		}
  		return resp.Succeeded, nil
  	}
  }

  // unchanged is the compare that key's mod_revision is still mod; 0 means
  // the key is still absent.
  func unchanged(key string, mod int64) clientv3.Cmp {
  	return clientv3.Compare(clientv3.ModRevision(key), "=", mod)
  }

  // cas reads key's record, lets f change it, and writes it back only if
  // nobody wrote key since the read, reading again on a lost race until one
  // write lands or ctx ends. live decides whether a record is present to f:
  // one past its expiry is handed over as absent, but its revision is still
  // compared. f returns write false to write nothing (its answer stands),
  // the expiry the write's lease follows (zero for none), keep to keep the
  // key's own lease, or an error to stop.
  func cas[R any](ctx context.Context, cli *clientv3.Client, ls *leases, key string, live func(R) bool,
  	f func(r *R, found bool) (write bool, exp time.Time, keep bool, err error)) error {
  	for {
  		resp, err := cli.Get(ctx, key)
  		if err != nil {
  			return unavailable(err)
  		}
  		var r R
  		var mod int64
  		found := false
  		if len(resp.Kvs) == 1 {
  			if err := json.Unmarshal(resp.Kvs[0].Value, &r); err != nil {
  				return fmt.Errorf("etcd: %s does not decode: %w", key, err)
  			}
  			mod, found = resp.Kvs[0].ModRevision, live(r)
  			if !found {
  				var zero R
  				r = zero
  			}
  		}
  		write, exp, keep, err := f(&r, found)
  		if err != nil || !write {
  			return err
  		}
  		body, err := json.Marshal(r)
  		if err != nil {
  			return err
  		}
  		ok, err := commit(ctx, cli, ls, []clientv3.Cmp{unchanged(key, mod)}, []put{{key: key, val: body, exp: exp, keep: keep}})
  		if err != nil || ok {
  			return err
  		}
  	}
  }

  // getJSON reads key into v; false when it is absent.
  func getJSON(ctx context.Context, cli *clientv3.Client, key string, v any) (mod int64, ok bool, err error) {
  	resp, err := cli.Get(ctx, key)
  	if err != nil {
  		return 0, false, unavailable(err)
  	}
  	if len(resp.Kvs) == 0 {
  		return 0, false, nil
  	}
  	if err := json.Unmarshal(resp.Kvs[0].Value, v); err != nil {
  		return 0, false, fmt.Errorf("etcd: %s does not decode: %w", key, err)
  	}
  	return resp.Kvs[0].ModRevision, true, nil
  }

  // chunked calls f on ops in transactions of at most maxTxnOps: etcd's
  // default --max-txn-ops is 128.
  func chunked(ctx context.Context, cli *clientv3.Client, ops []clientv3.Op, f func(*clientv3.TxnResponse)) error {
  	for len(ops) > 0 {
  		n := min(len(ops), maxTxnOps)
  		resp, err := cli.Txn(ctx).Then(ops[:n]...).Commit()
  		if err != nil {
  			return unavailable(err)
  		}
  		if f != nil {
  			f(resp)
  		}
  		ops = ops[n:]
  	}
  	return nil
  }

  const maxTxnOps = 64
  ```

- [ ] **Step 8: Tokens, receipts, the token index.** Create `internal/store/etcd/tokens.go`:

  ```go
  package etcd

  import (
  	"bytes"
  	"context"
  	"encoding/json"
  	"sort"
  	"time"

  	"go.etcd.io/etcd/api/v3/mvccpb"
  	clientv3 "go.etcd.io/etcd/client/v3"

  	"github.com/rhwendt/port49/internal/store"
  )

  // Every token is its own key under its (nas, username), so a put, a
  // redeem and a delete by ID each touch one key and never rewrite another
  // token's: DeleteTokenRacesRedeem cannot lose a concurrent put.

  // liveTokens decodes the tokens in kvs that are live at now, each with its
  // own copy of its secret.
  func liveTokens(kvs []*mvccpb.KeyValue, now time.Time) []store.Token {
  	var out []store.Token
  	for _, kv := range kvs {
  		var r tokenRec
  		if json.Unmarshal(kv.Value, &r) != nil || !r.ExpiresAt.After(now) {
  			continue
  		}
  		t := r.token()
  		t.Secret = bytes.Clone(t.Secret)
  		out = append(out, t)
  	}
  	return out
  }

  // PutToken writes t and counts the live tokens under k, in one
  // transaction, as the memory store counts them after its append.
  func (s *Store) PutToken(ctx context.Context, k store.TokenKey, t store.Token) (int, error) {
  	body, err := json.Marshal(tokenRecOf(t))
  	if err != nil {
  		return 0, err
  	}
  	for attempt := 0; ; attempt++ {
  		id, err := s.tokLeases.For(ctx, t.ExpiresAt)
  		if err != nil {
  			return 0, unavailable(err)
  		}
  		resp, err := s.tok.Txn(ctx).Then(
  			clientv3.OpPut(s.k.token(k, t.ID), string(body), clientv3.WithLease(id)),
  			clientv3.OpGet(s.k.tokens(k), clientv3.WithPrefix()),
  		).Commit()
  		if isLeaseLost(err) && attempt == 0 {
  			s.tokLeases.Reset()
  			continue
  		}
  		if err != nil {
  			return 0, unavailable(err)
  		}
  		return len(liveTokens(resp.Responses[1].GetResponseRange().Kvs, s.now())), nil
  	}
  }

  // Candidates is every live token under k.
  func (s *Store) Candidates(ctx context.Context, k store.TokenKey) ([]store.Token, error) {
  	resp, err := s.tok.Get(ctx, s.k.tokens(k), clientv3.WithPrefix())
  	if err != nil {
  		return nil, unavailable(err)
  	}
  	return liveTokens(resp.Kvs, s.now()), nil
  }

  // liveToken reads one token key: its revision, or found false when it is
  // absent or past its expiry.
  func (s *Store) liveToken(ctx context.Context, k store.TokenKey, id string) (mod int64, found bool, err error) {
  	var r tokenRec
  	mod, ok, err := getJSON(ctx, s.tok, s.k.token(k, id), &r)
  	if err != nil || !ok {
  		return 0, false, err
  	}
  	return mod, r.ExpiresAt.After(s.now()), nil
  }

  // RedeemAndReceipt deletes the token and writes the receipt and its index
  // entry in one transaction that holds only while the token is the one
  // read: of two racing redeemers, exactly one's compare holds (design §12).
  func (s *Store) RedeemAndReceipt(ctx context.Context, k store.TokenKey, tokenID string, w store.ReceiptWrite) error {
  	mod, live, err := s.liveToken(ctx, k, tokenID)
  	if err != nil {
  		return err
  	}
  	if !live {
  		return store.ErrNotFound
  	}
  	body, err := json.Marshal(receiptRecOf(w.Receipt))
  	if err != nil {
  		return err
  	}
  	puts := []put{{key: s.k.receipt(w.Key), val: body, exp: w.Receipt.RetainUntil}}
  	if w.Principal != "" {
  		idx, err := json.Marshal(expiryRec{ExpiresAt: s.now().Add(w.IndexTTL)})
  		if err != nil {
  			return err
  		}
  		puts = append(puts, put{key: s.k.receiptBy(w.Principal, w.Key), val: idx, exp: s.now().Add(w.IndexTTL)})
  	}
  	tk := s.k.token(k, tokenID)
  	ok, err := commit(ctx, s.tok, s.tokLeases, []clientv3.Cmp{unchanged(tk, mod)}, puts, del{key: tk})
  	if err != nil {
  		return err
  	}
  	if !ok {
  		return store.ErrNotFound // another redeemer, or a delete, took it
  	}
  	return nil
  }

  // DeleteTokens drops every token under k, spent or not.
  func (s *Store) DeleteTokens(ctx context.Context, k store.TokenKey) error {
  	_, err := s.tok.Delete(ctx, s.k.tokens(k), clientv3.WithPrefix())
  	return unavailable(err)
  }

  // DeleteToken removes the live token with this ID under k, and only while
  // it is the one read; nothing else. The token index is left as it is (7c
  // ruling): it is by key, and pruning it could hide a second live token.
  func (s *Store) DeleteToken(ctx context.Context, k store.TokenKey, id string) error {
  	mod, live, err := s.liveToken(ctx, k, id)
  	if err != nil {
  		return err
  	}
  	if !live {
  		return store.ErrNotFound
  	}
  	tk := s.k.token(k, id)
  	ok, err := commit(ctx, s.tok, s.tokLeases, []clientv3.Cmp{unchanged(tk, mod)}, nil, del{key: tk})
  	if err != nil {
  		return err
  	}
  	if !ok {
  		return store.ErrNotFound
  	}
  	return nil
  }

  // PurgeTokens deletes the whole token family in one request, after
  // counting its live tokens.
  func (s *Store) PurgeTokens(ctx context.Context) (int, error) {
  	prefix := s.k.family(famToken)
  	resp, err := s.tok.Txn(ctx).Then(
  		clientv3.OpGet(prefix, clientv3.WithPrefix()),
  		clientv3.OpDelete(prefix, clientv3.WithPrefix()),
  	).Commit()
  	if err != nil {
  		return 0, unavailable(err)
  	}
  	return len(liveTokens(resp.Responses[0].GetResponseRange().Kvs, s.now())), nil
  }

  func (s *Store) liveReceipt(r receiptRec) bool { return r.RetainUntil.After(s.now()) }

  // GetReceipt is the receipt until its RetainUntil (store.Receipt).
  func (s *Store) GetReceipt(ctx context.Context, rk store.ReceiptKey) (store.Receipt, error) {
  	var r receiptRec
  	_, ok, err := getJSON(ctx, s.tok, s.k.receipt(rk), &r)
  	if err != nil {
  		return store.Receipt{}, err
  	}
  	if !ok || !s.liveReceipt(r) {
  		return store.Receipt{}, store.ErrNotFound
  	}
  	return r.receipt(), nil
  }

  // ExtendReceipt moves IdleExpiresAt and nothing else, on the receipt's own
  // lease: RetainUntil does not move, so neither does the lease.
  func (s *Store) ExtendReceipt(ctx context.Context, rk store.ReceiptKey, idleExpiresAt time.Time) error {
  	return cas(ctx, s.tok, s.tokLeases, s.k.receipt(rk), s.liveReceipt,
  		func(r *receiptRec, found bool) (bool, time.Time, bool, error) {
  			if !found {
  				return false, time.Time{}, false, store.ErrNotFound
  			}
  			r.IdleExpiresAt = idleExpiresAt
  			return true, time.Time{}, true, nil
  		})
  }

  // FailReceipt sets Failed and nothing else.
  func (s *Store) FailReceipt(ctx context.Context, rk store.ReceiptKey) error {
  	return cas(ctx, s.tok, s.tokLeases, s.k.receipt(rk), s.liveReceipt,
  		func(r *receiptRec, found bool) (bool, time.Time, bool, error) {
  			if !found {
  				return false, time.Time{}, false, store.ErrNotFound
  			}
  			r.Failed = true
  			return true, time.Time{}, true, nil
  		})
  }

  // DeleteReceiptsByPrincipal deletes every receipt the principal's index
  // names, and the index, and counts the receipts that were live. A receipt
  // written after the read is not deleted, as one written after the memory
  // store's lock is not: revocation's ordering reaches it (7a).
  func (s *Store) DeleteReceiptsByPrincipal(ctx context.Context, principal string) (int, error) {
  	prefix := s.k.receiptsBy(principal)
  	resp, err := s.tok.Get(ctx, prefix, clientv3.WithPrefix(), clientv3.WithKeysOnly())
  	if err != nil {
  		return 0, unavailable(err)
  	}
  	var gets, dels []clientv3.Op
  	for _, kv := range resp.Kvs {
  		rk := s.k.root + famReceipt + string(kv.Key[len(prefix):])
  		gets = append(gets, clientv3.OpGet(rk))
  		dels = append(dels, clientv3.OpDelete(rk))
  	}
  	n := 0
  	if err := chunked(ctx, s.tok, gets, func(r *clientv3.TxnResponse) {
  		for _, op := range r.Responses {
  			for _, kv := range op.GetResponseRange().Kvs {
  				var rec receiptRec
  				if json.Unmarshal(kv.Value, &rec) == nil && s.liveReceipt(rec) {
  					n++
  				}
  			}
  		}
  	}); err != nil {
  		return 0, err
  	}
  	if err := chunked(ctx, s.tok, dels, nil); err != nil {
  		return 0, err
  	}
  	if _, err := s.tok.Delete(ctx, prefix, clientv3.WithPrefix()); err != nil {
  		return 0, unavailable(err)
  	}
  	return n, nil
  }

  // IndexToken records k under principal and certKey, keeping the later
  // expiry where one is recorded; an empty or blank key is skipped
  // (store.BlankCertKey).
  func (s *Store) IndexToken(ctx context.Context, principal, certKey string, k store.TokenKey, ttl time.Duration) error {
  	exp := s.now().Add(ttl)
  	for _, ix := range []struct{ fam, key string }{{famTokByPrin, principal}, {famTokByCert, certKey}} {
  		if ix.key == "" || ix.fam == famTokByCert && store.BlankCertKey(ix.key) {
  			continue
  		}
  		err := cas(ctx, s.tok, s.tokLeases, s.k.tokenIndexed(ix.fam, ix.key, k),
  			func(r expiryRec) bool { return true },
  			func(r *expiryRec, found bool) (bool, time.Time, bool, error) {
  				if found && !exp.After(r.ExpiresAt) {
  					return false, time.Time{}, false, nil
  				}
  				r.ExpiresAt = exp
  				return true, exp, false, nil
  			})
  		if err != nil {
  			return err
  		}
  	}
  	return nil
  }

  func (s *Store) tokenKeys(ctx context.Context, fam, key string) ([]store.TokenKey, error) {
  	if key == "" {
  		return nil, nil
  	}
  	resp, err := s.tok.Get(ctx, s.k.tokenIndex(fam, key), clientv3.WithPrefix())
  	if err != nil {
  		return nil, unavailable(err)
  	}
  	now := s.now()
  	var out []store.TokenKey
  	for _, kv := range resp.Kvs {
  		var r expiryRec
  		nas, user, ok := lastTwo(string(kv.Key))
  		if !ok || json.Unmarshal(kv.Value, &r) != nil || !r.ExpiresAt.After(now) {
  			continue
  		}
  		out = append(out, store.TokenKey{NAS: nas, Username: user})
  	}
  	sort.Slice(out, func(i, j int) bool {
  		if out[i].NAS != out[j].NAS {
  			return out[i].NAS < out[j].NAS
  		}
  		return out[i].Username < out[j].Username
  	})
  	return out, nil
  }

  func (s *Store) TokensByPrincipal(ctx context.Context, principal string) ([]store.TokenKey, error) {
  	return s.tokenKeys(ctx, famTokByPrin, principal)
  }

  func (s *Store) TokensByCert(ctx context.Context, certKey string) ([]store.TokenKey, error) {
  	if store.BlankCertKey(certKey) {
  		return nil, nil
  	}
  	return s.tokenKeys(ctx, famTokByCert, certKey)
  }

  ```

  Then add to `commit.go`, and use it in `commit` in place of the `errors.Is` it spells out:

  ```go
  // isLeaseLost is etcd saying a lease the put named is gone: one that
  // expired while port49d was paused, or that an operator revoked.
  func isLeaseLost(err error) bool { return errors.Is(err, rpctypes.ErrLeaseNotFound) }
  ```

- [ ] **Step 9: The marks.** Create `internal/store/etcd/marks.go`:

  ```go
  package etcd

  import (
  	"context"
  	"encoding/json"
  	"sort"

  	clientv3 "go.etcd.io/etcd/client/v3"

  	"github.com/rhwendt/port49/internal/store"
  )

  // A mark carries no lease: it never expires, and only DeleteRevocation
  // lifts it (spec §13, decision 32).

  // PutRevocation writes r unless a mark for its key already stands: the
  // put is conditional on the key's absence, so a repeat never moves the
  // first's time or origin.
  func (s *Store) PutRevocation(ctx context.Context, r store.Revocation) error {
  	if err := store.CheckRevocation(r); err != nil {
  		return err
  	}
  	body, err := json.Marshal(markRecOf(r))
  	if err != nil {
  		return err
  	}
  	key := s.k.mark(r.Kind, r.Key)
  	_, err = commit(ctx, s.tok, s.tokLeases,
  		[]clientv3.Cmp{clientv3.Compare(clientv3.CreateRevision(key), "=", 0)}, []put{{key: key, val: body}})
  	return err
  }

  func (s *Store) GetRevocation(ctx context.Context, kind, key string) (store.Revocation, error) {
  	var r markRec
  	_, ok, err := getJSON(ctx, s.tok, s.k.mark(kind, key), &r)
  	if err != nil {
  		return store.Revocation{}, err
  	}
  	if !ok {
  		return store.Revocation{}, store.ErrNotFound
  	}
  	return r.revocation(), nil
  }

  func (s *Store) DeleteRevocation(ctx context.Context, kind, key string) error {
  	_, err := s.tok.Delete(ctx, s.k.mark(kind, key))
  	return unavailable(err)
  }

  // ListRevocations is every mark, sorted by (Kind, Key) as stored, not as
  // escaped.
  func (s *Store) ListRevocations(ctx context.Context) ([]store.Revocation, error) {
  	resp, err := s.tok.Get(ctx, s.k.family(famMark), clientv3.WithPrefix())
  	if err != nil {
  		return nil, unavailable(err)
  	}
  	out := make([]store.Revocation, 0, len(resp.Kvs))
  	for _, kv := range resp.Kvs {
  		var r markRec
  		if err := json.Unmarshal(kv.Value, &r); err != nil {
  			continue
  		}
  		out = append(out, r.revocation())
  	}
  	sort.Slice(out, func(i, j int) bool {
  		if out[i].Kind != out[j].Kind {
  			return out[i].Kind < out[j].Kind
  		}
  		return out[i].Key < out[j].Key
  	})
  	return out, nil
  }
  ```

  A mark that does not decode is skipped. It cannot be listed as a mark, and the next task that
  reads it by key reports the decode error. Leaving it out of the list is the listing's choice,
  not the mint's: `GetRevocation` still fails closed, with an error.

- [ ] **Step 10: The rest, not yet built.** Create `internal/store/etcd/notbuilt.go` with every
  other `store.Store` method returning `errNotBuilt`:

  ```go
  package etcd

  import (
  	"context"
  	"errors"
  	"time"

  	"github.com/rhwendt/port49/internal/store"
  )

  // errNotBuilt is a method plan 7d builds in a later task. No production
  // path reaches this package before Task 12, and this file is gone by
  // Task 8.
  var errNotBuilt = errors.New("etcd: not built yet (plan 7d)")

  func (s *Store) PutContext(context.Context, store.ContextKey, store.Context, time.Duration) error {
  	return errNotBuilt
  }
  // … one function per remaining method of store.Store: GetContext,
  // SwapContext, SwapLogin, TouchContext, SetPrivilege, AnnotateContext,
  // RefreshContext, SetRevokedAt, SetContextPolicy, DeleteContext,
  // DeleteContextIf, PutBlob, GetBlob, BumpBlob, IndexContext,
  // UnindexContext, UnindexRef, ContextsByPrincipal, ContextsBySid,
  // ContextsByCert, ReindexSid, ActivePrincipals, ReserveIdempotency,
  // CompleteIdempotency, ReleaseIdempotency — each with store.Store's
  // signature, returning zero values and errNotBuilt.

  var _ store.Store = (*Store)(nil)
  ```

  Write every function out. The comment lists them so none is missed, and the compiler checks the
  set through the last line.

- [ ] **Step 11: Run.**

  Run: `go test ./internal/store/etcd/... -count=1`
  Expected: PASS: `TestTokensOnEtcd/<13 properties>`, `TestAPutOnALostLeaseTakesAFreshOne`,
  `TestALeaseOutlivesItsRecord`, `TestUnavailableClassifies`. Note the package's wall time in the
  report. A token property over the shared member should take seconds, not minutes.

  Mutation checks (do them, report them, revert them):
  1. In `RedeemAndReceipt`, drop the `unchanged(tk, mod)` compare. `RedeemIsAtomic` and
     `DeleteTokenRacesRedeem` must fail.
  2. In `leases.For`, use `need := exp.Sub(now)`, with no grace. `TestALeaseOutlivesItsRecord`
     must fail.

- [ ] **Step 12: Commit.**

  ```bash
  gofmt -w internal/store/etcd
  make build && make test && make vet
  git add go.mod go.sum internal/store/etcd
  git commit -m "feat(store/etcd): the etcd backend's foundation, tokens and marks

  internal/store/etcd: one key per record under the keyspace's v1/, JSON
  with snake_case keys, every compare-and-set a transaction on the key's
  mod_revision, expiry read against port49d's clock with leases only
  reclaiming. Tokens, receipts, the token index, PurgeTokens and the marks
  pass their storetest properties against a real etcd member embedded in
  the test binary (etcdtest; no docker, no cgo). go 1.26 (OD-1).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 6: Contexts, blobs, and the login's one step on etcd

**Files:**
- Modify: `internal/store/etcd/records.go` (`ctxRec`, `blobRec`, `idxRec`)
- Create: `internal/store/etcd/contexts.go`
- Modify: `internal/store/etcd/notbuilt.go` (remove what this task builds)
- Test: `internal/store/etcd/etcd_test.go`

**Interfaces:**
- Consumes: Task 5's `commit`, `cas`, `getJSON`, `unchanged`, `put`, `del`, `leases.For`, `keys`.
- Produces:
  - `type ctxRec`, `func ctxRecOf(store.Context) ctxRec`,
    `func (ctxRec) context(mod int64) store.Context`
  - `type idxRec struct { Principals, Sids, Certs []idxEntry }`, `type idxEntry struct { Key string; ExpiresAt time.Time }`,
    with `add(fam, key string, exp time.Time)`, `drop(fam, key string)`, `restamp(exp time.Time)`,
    `lists(fam, key string, now time.Time) bool`, `maxExp() time.Time`, `empty() bool`
  - `type ctxSnap`, `func (s *Store) readCtx(ctx, k, marks ...[2]string) (ctxSnap, error)`,
    `func (s *Store) commitCtx(ctx, k, snap, rec *ctxRec, idx *idxRec, added []string) (bool, error)`
  - The `store.Store` methods: GetContext, PutContext, SwapContext, SwapLogin, TouchContext,
    SetPrivilege, AnnotateContext, RefreshContext, SetRevokedAt, SetContextPolicy, DeleteContext,
    DeleteContextIf, PutBlob, GetBlob, BumpBlob, IndexContext, UnindexContext, UnindexRef,
    ReindexSid.

- [ ] **Step 1: The failing test.** Append to `etcd_test.go`:

  ```go
  // The context family: every context property, the revisions, the narrow
  // setters, the join with its marks, the blobs (plan 7d Task 6). The index
  // properties that read lookups are Task 7's.
  func TestContextsOnEtcd(t *testing.T) {
  	run(t, map[string]func(*testing.T){
  		"JoinRacesRevocation":           func(t *testing.T) { storetest.JoinRacesRevocation(t, fixed(t), t0) },
  		"PolicyRevision":                func(t *testing.T) { storetest.PolicyRevision(t, fixed(t), t0) },
  		"RevocationIsMonotonic":         func(t *testing.T) { storetest.RevocationIsMonotonic(t, fixed(t), t0) },
  		"CeilingShortensOnly":           func(t *testing.T) { storetest.CeilingShortensOnly(t, fixed(t), t0) },
  		"RefreshSetsTheCeiling":         func(t *testing.T) { storetest.RefreshSetsTheCeiling(t, fixed(t), t0) },
  		"RefreshStopsAtGrace":           func(t *testing.T) { storetest.RefreshStopsAtGrace(t, fixed(t), t0) },
  		"WritesBindToTheRevision":       func(t *testing.T) { storetest.WritesBindToTheRevision(t, fixed(t), t0) },
  		"ContextExpires":                func(t *testing.T) { storetest.ContextExpires(t, backend) },
  		"DeleteContextRemovesIt":        func(t *testing.T) { storetest.DeleteContextRemovesIt(t, backend) },
  		"TouchExtendsWithoutClobbering": func(t *testing.T) { storetest.TouchExtendsWithoutClobbering(t, backend) },
  		"AnnotateKeepsARacingRevocation": func(t *testing.T) {
  			storetest.AnnotateKeepsARacingRevocation(t, backend)
  		},
  		"SetRevokedAtMarksOneField": func(t *testing.T) { storetest.SetRevokedAtMarksOneField(t, backend) },
  		"RefreshMovesTheWindow":     func(t *testing.T) { storetest.RefreshMovesTheWindow(t, backend) },
  		"RefreshWithoutCeiling":     func(t *testing.T) { storetest.RefreshWithoutCeiling(t, backend) },
  		"AnnotateSetRules":          func(t *testing.T) { storetest.AnnotateSetRules(t, backend) },
  		"AnnotateDoesNotEditAReadersSlice": func(t *testing.T) {
  			storetest.AnnotateDoesNotEditAReadersSlice(t, backend)
  		},
  		"BlobBump":                       func(t *testing.T) { storetest.BlobBump(t, backend) },
  		"SwapIsACompareAndSet":           func(t *testing.T) { storetest.SwapIsACompareAndSet(t, backend) },
  		"EveryWriteMovesTheRevision":     func(t *testing.T) { storetest.EveryWriteMovesTheRevision(t, backend) },
  		"SetPrivilegeIsRaiseOnly":        func(t *testing.T) { storetest.SetPrivilegeIsRaiseOnly(t, backend) },
  		"SetContextPolicyBindsToTheRead": func(t *testing.T) { storetest.SetContextPolicyBindsToTheRead(t, backend) },
  		"SelfRevocationBindsToTheRead":   func(t *testing.T) { storetest.SelfRevocationBindsToTheRead(t, backend) },
  		"PurgeTakesEveryToken":           func(t *testing.T) { storetest.PurgeTakesEveryToken(t, backend) },
  	})
  }

  // PolicyRev comes from etcd's revision counter through policy_moved: a
  // policy write takes the write's own revision, and the next write that is
  // not one keeps it (Ruling 5).
  func TestPolicyRevIsTheLastPolicyWritesRevision(t *testing.T) {
  	ctx := context.Background()
  	s := onShared(t, func() time.Time { return t0 })
  	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
  	if err := s.PutContext(ctx, k, store.Context{CtxID: "c", Principal: "p", Username: "alice", BlobHash: "b"},
  		time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	put, _ := s.GetContext(ctx, k)
  	if put.PolicyRev != put.Rev {
  		t.Fatalf("a whole write moves both revisions to its own: %d %d", put.Rev, put.PolicyRev)
  	}
  	if err := s.TouchContext(ctx, k, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	touched, _ := s.GetContext(ctx, k)
  	if touched.Rev == put.Rev || touched.PolicyRev != put.PolicyRev {
  		t.Fatalf("a touch: %d/%d -> %d/%d", put.Rev, put.PolicyRev, touched.Rev, touched.PolicyRev)
  	}
  	if err := s.SetRevokedAt(ctx, k, t0); err != nil {
  		t.Fatal(err)
  	}
  	revoked, _ := s.GetContext(ctx, k)
  	if revoked.PolicyRev != revoked.Rev || revoked.PolicyRev == touched.PolicyRev {
  		t.Fatalf("a revocation takes its own revision: %d/%d", revoked.Rev, revoked.PolicyRev)
  	}
  }
  ```

  Run: `go test ./internal/store/etcd/ -run TestContextsOnEtcd -count=1`
  Expected: FAIL: every subtest hits `errNotBuilt`.

- [ ] **Step 2: The records.** Append to `records.go`:

  ```go
  // ctxRec is a login context as stored. PolicyRev is store.Context's
  // PolicyRev drawn from etcd's revision counter: a write that moves what a
  // policy refresh decides sets PolicyMoved, and the context's PolicyRev is
  // then the key's mod_revision, the revision of that very write; the next
  // write that does not move it stores the mod_revision it read as
  // policy_rev and clears the flag. So PolicyRev moves exactly on the writes
  // memory moves it on, and never repeats a value (store.Context.PolicyRev).
  type ctxRec struct {
  	CtxID                 string    `json:"ctx_id,omitempty"`
  	Principal             string    `json:"principal,omitempty"`
  	Username              string    `json:"username,omitempty"`
  	Port                  string    `json:"port,omitempty"`
  	RemAddr               string    `json:"rem_addr,omitempty"`
  	PrivLvl               uint8     `json:"priv_lvl"`
  	BlobHash              string    `json:"blob_hash,omitempty"`
  	Credential            credRec   `json:"credential"`
  	AuthTime              time.Time `json:"auth_time"`
  	SessionExpires        time.Time `json:"session_expires"`
  	RefreshedAt           time.Time `json:"refreshed_at"`
  	RevokedAt             time.Time `json:"revoked_at"`
  	LastTouchedAt         time.Time `json:"last_touched_at"`
  	SessionDiscriminators []string  `json:"session_discriminators,omitempty"`
  	AccountingState       string    `json:"accounting_state,omitempty"`
  	Enable                string    `json:"enable,omitempty"`
  	MaxPrivilege          uint8     `json:"max_privilege"`
  	CreatedAt             time.Time `json:"created_at"`
  	Sealed                []byte    `json:"sealed,omitempty"`

  	ExpiresAt   time.Time `json:"expires_at"`
  	PolicyRev   int64     `json:"policy_rev"`
  	PolicyMoved bool      `json:"policy_moved"`
  }

  func ctxRecOf(c store.Context) ctxRec {
  	return ctxRec{CtxID: c.CtxID, Principal: c.Principal, Username: c.Username, Port: c.Port, RemAddr: c.RemAddr,
  		PrivLvl: c.PrivLvl, BlobHash: c.BlobHash, Credential: credRec(c.Credential), AuthTime: c.AuthTime,
  		SessionExpires: c.SessionExpires, RefreshedAt: c.RefreshedAt, RevokedAt: c.RevokedAt,
  		LastTouchedAt: c.LastTouchedAt, SessionDiscriminators: append([]string(nil), c.SessionDiscriminators...),
  		AccountingState: c.AccountingState, Enable: c.Enable, MaxPrivilege: c.MaxPrivilege, CreatedAt: c.CreatedAt,
  		Sealed: c.Sealed}
  }

  func (r ctxRec) context(mod int64) store.Context {
  	return store.Context{CtxID: r.CtxID, Principal: r.Principal, Username: r.Username, Port: r.Port,
  		RemAddr: r.RemAddr, PrivLvl: r.PrivLvl, BlobHash: r.BlobHash, Credential: store.Credential(r.Credential),
  		AuthTime: r.AuthTime, SessionExpires: r.SessionExpires, RefreshedAt: r.RefreshedAt, RevokedAt: r.RevokedAt,
  		LastTouchedAt: r.LastTouchedAt, SessionDiscriminators: append([]string(nil), r.SessionDiscriminators...),
  		AccountingState: r.AccountingState, Enable: r.Enable, MaxPrivilege: r.MaxPrivilege, CreatedAt: r.CreatedAt,
  		Sealed: r.Sealed, Rev: uint64(mod), PolicyRev: uint64(r.policyRev(mod))}
  }

  func (r ctxRec) policyRev(mod int64) int64 {
  	if r.PolicyMoved {
  		return mod
  	}
  	return r.PolicyRev
  }

  type blobRec struct {
  	Body      []byte    `json:"body"`
  	ExpiresAt time.Time `json:"expires_at"`
  }

  // idxRec is a ref's index record, x/<nas>/<user>: every principal, sid and
  // certificate key the ref answers under, each with its own expiry. It is
  // authoritative: a lookup entry answers only while this lists its key
  // live (Ruling 6).
  type idxRec struct {
  	Principals []idxEntry `json:"principals,omitempty"`
  	Sids       []idxEntry `json:"sids,omitempty"`
  	Certs      []idxEntry `json:"certs,omitempty"`
  }

  type idxEntry struct {
  	Key       string    `json:"key"`
  	ExpiresAt time.Time `json:"expires_at"`
  }

  func (x *idxRec) list(fam string) *[]idxEntry {
  	switch fam {
  	case famByPrincipal:
  		return &x.Principals
  	case famBySid:
  		return &x.Sids
  	}
  	return &x.Certs
  }

  // add lists key under fam until exp, as the memory store's addRef does:
  // an entry already there takes exp, whatever it held.
  func (x *idxRec) add(fam, key string, exp time.Time) {
  	l := x.list(fam)
  	for i := range *l {
  		if (*l)[i].Key == key {
  			(*l)[i].ExpiresAt = exp
  			return
  		}
  	}
  	*l = append(*l, idxEntry{Key: key, ExpiresAt: exp})
  }

  func (x *idxRec) drop(fam, key string) {
  	l := x.list(fam)
  	out := (*l)[:0]
  	for _, e := range *l {
  		if e.Key != key {
  			out = append(out, e)
  		}
  	}
  	*l = out
  }

  // restamp pushes every entry out to exp, never shortening one: an
  // extension of the context carries its index entries (design §12).
  func (x *idxRec) restamp(exp time.Time) {
  	for _, l := range []*[]idxEntry{&x.Principals, &x.Sids, &x.Certs} {
  		for i := range *l {
  			if exp.After((*l)[i].ExpiresAt) {
  				(*l)[i].ExpiresAt = exp
  			}
  		}
  	}
  }

  // lists reports whether key is listed under fam, live at now.
  func (x idxRec) lists(fam, key string, now time.Time) bool {
  	for _, e := range *x.list(fam) {
  		if e.Key == key {
  			return e.ExpiresAt.After(now)
  		}
  	}
  	return false
  }

  func (x idxRec) maxExp() time.Time {
  	var m time.Time
  	for _, l := range [][]idxEntry{x.Principals, x.Sids, x.Certs} {
  		for _, e := range l {
  			if e.ExpiresAt.After(m) {
  				m = e.ExpiresAt
  			}
  		}
  	}
  	return m
  }

  func (x idxRec) empty() bool { return len(x.Principals)+len(x.Sids)+len(x.Certs) == 0 }
  ```

  `list` takes a pointer receiver for its own mutation, and `lists` calls it on a copy. That is
  fine, because `lists` only reads.

- [ ] **Step 3: Contexts.** Create `internal/store/etcd/contexts.go`:

  ```go
  package etcd

  import (
  	"bytes"
  	"context"
  	"encoding/json"
  	"errors"
  	"fmt"
  	"time"

  	clientv3 "go.etcd.io/etcd/client/v3"

  	"github.com/rhwendt/port49/internal/store"
  )

  // ctxSnap is one consistent read of a context, its ref's index record,
  // and any marks a login compares: one transaction of gets, so all are as
  // of one revision.
  type ctxSnap struct {
  	rec    ctxRec
  	found  bool // present and not past its expiry
  	mod    int64
  	idx    idxRec
  	idxMod int64
  	marks  map[[2]string]markSnap
  }

  type markSnap struct {
  	at  time.Time // zero: absent
  	mod int64
  }

  func refOf(k store.ContextKey) store.ContextRef { return store.ContextRef{NAS: k.NAS, Username: k.Username} }

  func (s *Store) readCtx(ctx context.Context, k store.ContextKey, marks ...[2]string) (ctxSnap, error) {
  	ops := []clientv3.Op{clientv3.OpGet(s.k.context(k)), clientv3.OpGet(s.k.indexed(refOf(k)))}
  	for _, m := range marks {
  		ops = append(ops, clientv3.OpGet(s.k.mark(m[0], m[1])))
  	}
  	resp, err := s.ctx.Txn(ctx).Then(ops...).Commit()
  	if err != nil {
  		return ctxSnap{}, unavailable(err)
  	}
  	var snap ctxSnap
  	if kvs := resp.Responses[0].GetResponseRange().Kvs; len(kvs) == 1 {
  		if err := json.Unmarshal(kvs[0].Value, &snap.rec); err != nil {
  			return ctxSnap{}, fmt.Errorf("etcd: context %v does not decode: %w", k, err)
  		}
  		snap.mod, snap.found = kvs[0].ModRevision, snap.rec.ExpiresAt.After(s.now())
  	}
  	if kvs := resp.Responses[1].GetResponseRange().Kvs; len(kvs) == 1 {
  		if err := json.Unmarshal(kvs[0].Value, &snap.idx); err != nil {
  			return ctxSnap{}, fmt.Errorf("etcd: index record of %v does not decode: %w", k, err)
  		}
  		snap.idxMod = kvs[0].ModRevision
  	}
  	snap.marks = map[[2]string]markSnap{}
  	for i, m := range marks {
  		var ms markSnap
  		if kvs := resp.Responses[2+i].GetResponseRange().Kvs; len(kvs) == 1 {
  			var r markRec
  			if err := json.Unmarshal(kvs[0].Value, &r); err != nil {
  				return ctxSnap{}, fmt.Errorf("etcd: mark %v does not decode: %w", m, err)
  			}
  			ms = markSnap{at: r.At, mod: kvs[0].ModRevision}
  		}
  		snap.marks[m] = ms
  	}
  	return snap, nil
  }

  // commitCtx writes rec at k (nil: no context write) and idx as the ref's
  // index record (nil: unchanged; empty: deleted), putting a lookup entry for
  // each key in added, only while the context, the index record and every
  // mark snap read are as read. A context's lease follows its expiry; the
  // index record's, its latest entry's.
  func (s *Store) commitCtx(ctx context.Context, k store.ContextKey, snap ctxSnap, rec *ctxRec, idx *idxRec,
  	added []string) (bool, error) {
  	ck, xk := s.k.context(k), s.k.indexed(refOf(k))
  	cmps := []clientv3.Cmp{unchanged(ck, snap.mod), unchanged(xk, snap.idxMod)}
  	for m, ms := range snap.marks {
  		cmps = append(cmps, unchanged(s.k.mark(m[0], m[1]), ms.mod))
  	}
  	var puts []put
  	var dels []del
  	if rec != nil {
  		body, err := json.Marshal(rec)
  		if err != nil {
  			return false, err
  		}
  		puts = append(puts, put{key: ck, val: body, exp: rec.ExpiresAt})
  	}
  	if idx != nil {
  		if idx.empty() {
  			dels = append(dels, del{key: xk})
  		} else {
  			body, err := json.Marshal(idx)
  			if err != nil {
  				return false, err
  			}
  			puts = append(puts, put{key: xk, val: body, exp: idx.maxExp()})
  		}
  	}
  	for _, key := range added {
  		puts = append(puts, put{key: key, val: []byte("{}")}) // no lease: the index record decides (Ruling 6)
  	}
  	return commit(ctx, s.ctx, s.ctxLeases, cmps, puts, dels...)
  }

  // GetContext reads the context alone: its revisions are its key's.
  func (s *Store) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
  	var r ctxRec
  	mod, ok, err := getJSON(ctx, s.ctx, s.k.context(k), &r)
  	if err != nil {
  		return store.Context{}, err
  	}
  	if !ok || !r.ExpiresAt.After(s.now()) {
  		return store.Context{}, store.ErrNotFound
  	}
  	return r.context(mod), nil
  }

  // whole is c as a whole-record write at now for ttl: stamped, and moving
  // both revisions (a join, a replace and a seeding put all do).
  func whole(c store.Context, now time.Time, ttl time.Duration) ctxRec {
  	r := ctxRecOf(c)
  	r.LastTouchedAt, r.ExpiresAt, r.PolicyMoved = now, now.Add(ttl), true
  	return r
  }

  // PutContext writes c unconditionally, extending the ref's index entries
  // with it (store.Store; no production path calls it).
  func (s *Store) PutContext(ctx context.Context, k store.ContextKey, c store.Context, ttl time.Duration) error {
  	for {
  		snap, err := s.readCtx(ctx, k)
  		if err != nil {
  			return err
  		}
  		r := whole(c, s.now(), ttl)
  		var idx *idxRec
  		if snap.idxMod != 0 {
  			x := snap.idx
  			x.restamp(r.ExpiresAt)
  			idx = &x
  		}
  		if ok, err := s.commitCtx(ctx, k, snap, &r, idx, nil); err != nil || ok {
  			return err
  		}
  	}
  }

  // SwapContext is SwapLogin with no index change and no mark.
  func (s *Store) SwapContext(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration) error {
  	return s.SwapLogin(ctx, k, rev, c, ttl, store.LoginWrite{})
  }

  // SwapLogin is the login's one step (store.Store; plan 7d Ruling 7): the
  // context, the ref's index change and the mark check in one transaction
  // that holds only while the context, the index record and each mark are
  // as read. A lost race on the index record alone (an IndexContext between
  // the read and the write) reads again here; anything that moves the
  // context or a mark is ErrConflict, for JoinContext to decide again.
  func (s *Store) SwapLogin(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration,
  	w store.LoginWrite) error {
  	marks := make([][2]string, 0, len(w.Marks))
  	for _, m := range w.Marks {
  		marks = append(marks, [2]string{m.Kind, m.Key})
  	}
  	ref := refOf(k)
  	for {
  		snap, err := s.readCtx(ctx, k, marks...)
  		if err != nil {
  			return err
  		}
  		if snap.found && uint64(snap.mod) != rev || !snap.found && rev != 0 {
  			return store.ErrConflict
  		}
  		for _, m := range w.Marks {
  			if !snap.marks[[2]string{m.Kind, m.Key}].at.Equal(m.At) {
  				return store.ErrConflict
  			}
  		}
  		now := s.now()
  		r := whole(c, now, ttl)
  		x := snap.idx
  		touched := snap.idxMod != 0
  		x.restamp(r.ExpiresAt)
  		if w.ClearRef {
  			x = idxRec{}
  		}
  		if w.DropSid != "" {
  			x.drop(famBySid, w.DropSid)
  		}
  		if w.DropCertKey != "" && !store.BlankCertKey(w.DropCertKey) {
  			x.drop(famByCert, w.DropCertKey)
  		}
  		added := s.addKeys(&x, ref, w.Principal, w.Sid, w.CertKey, now.Add(w.IndexTTL))
  		var idx *idxRec
  		if touched || len(added) > 0 {
  			idx = &x
  		}
  		if ok, err := s.commitCtx(ctx, k, snap, &r, idx, added); err != nil || ok {
  			return err
  		}
  	}
  }

  // addKeys lists ref under each non-empty key until exp (a blank
  // certificate key is no key: store.BlankCertKey) and returns the lookup
  // entries to put with it.
  func (s *Store) addKeys(x *idxRec, ref store.ContextRef, principal, sid, certKey string, exp time.Time) []string {
  	if store.BlankCertKey(certKey) {
  		certKey = ""
  	}
  	var added []string
  	for _, a := range []struct{ fam, key string }{{famByPrincipal, principal}, {famBySid, sid}, {famByCert, certKey}} {
  		if a.key == "" {
  			continue
  		}
  		x.add(a.fam, a.key, exp)
  		added = append(added, s.k.lookup(a.fam, a.key, ref))
  	}
  	return added
  }

  // mutate is every narrow setter's read-change-write: f changes the live
  // record, returning extend to carry the ref's index entries out to the
  // record's new expiry; the write lands only if neither moved since the
  // read, else it reads again. Before f runs, a PolicyMoved left by the last
  // write is resolved into policy_rev, so r.PolicyRev is the context's
  // PolicyRev and f marks its own policy write by setting PolicyMoved.
  func (s *Store) mutate(ctx context.Context, k store.ContextKey,
  	f func(r *ctxRec, rev int64, now time.Time) (extend bool, err error)) error {
  	for {
  		snap, err := s.readCtx(ctx, k)
  		if err != nil {
  			return err
  		}
  		if !snap.found {
  			return store.ErrNotFound
  		}
  		r := snap.rec
  		if r.PolicyMoved {
  			r.PolicyRev, r.PolicyMoved = snap.mod, false
  		}
  		extend, err := f(&r, snap.mod, s.now())
  		if err != nil {
  			return err
  		}
  		var idx *idxRec
  		if extend && snap.idxMod != 0 {
  			x := snap.idx
  			x.restamp(r.ExpiresAt)
  			idx = &x
  		}
  		if ok, err := s.commitCtx(ctx, k, snap, &r, idx, nil); err != nil || ok {
  			return err
  		}
  	}
  }

  // TouchContext writes the expiry and LastTouchedAt, and nothing else
  // (store.Store).
  func (s *Store) TouchContext(ctx context.Context, k store.ContextKey, ttl time.Duration) error {
  	return s.mutate(ctx, k, func(r *ctxRec, _ int64, now time.Time) (bool, error) {
  		r.ExpiresAt, r.LastTouchedAt = now.Add(ttl), now
  		return true, nil
  	})
  }

  // SetPrivilege raises the level, clamped to the ceiling; a level that
  // moved is a policy write (memory's SetPrivilege).
  func (s *Store) SetPrivilege(ctx context.Context, k store.ContextKey, level uint8) error {
  	return s.mutate(ctx, k, func(r *ctxRec, _ int64, _ time.Time) (bool, error) {
  		held := r.PrivLvl
  		if level > r.PrivLvl {
  			r.PrivLvl = level
  		}
  		if r.MaxPrivilege > 0 && r.PrivLvl > r.MaxPrivilege {
  			r.PrivLvl = r.MaxPrivilege
  		}
  		r.PolicyMoved = r.PrivLvl != held
  		return false, nil
  	})
  }

  // AnnotateContext adds a discriminator and sets the state; neither the
  // expiry nor LastTouchedAt moves (spec §5.8).
  func (s *Store) AnnotateContext(ctx context.Context, k store.ContextKey, discHash, state string) error {
  	return s.mutate(ctx, k, func(r *ctxRec, _ int64, _ time.Time) (bool, error) {
  		if discHash != "" {
  			r.SessionDiscriminators = addDiscriminator(r.SessionDiscriminators, discHash)
  		}
  		if state != "" {
  			r.AccountingState = state
  		}
  		return false, nil
  	})
  }

  // addDiscriminator is the memory store's, copied: a set capped at
  // store.MaxSessionDiscriminators, oldest evicted, never edited in place.
  func addDiscriminator(set []string, h string) []string {
  	for _, existing := range set {
  		if existing == h {
  			return set
  		}
  	}
  	out := make([]string, 0, store.MaxSessionDiscriminators)
  	if len(set) >= store.MaxSessionDiscriminators {
  		set = set[len(set)-store.MaxSessionDiscriminators+1:]
  	}
  	out = append(out, set...)
  	return append(out, h)
  }

  // RefreshContext is the memory store's RefreshContext, with its two
  // refusals made against the record this write will compare.
  func (s *Store) RefreshContext(ctx context.Context, k store.ContextKey, rf store.ContextRefresh, ttl time.Duration) error {
  	return s.mutate(ctx, k, func(r *ctxRec, rev int64, now time.Time) (bool, error) {
  		if rf.ExpectRev != 0 && uint64(rev) != rf.ExpectRev {
  			return false, store.ErrConflict
  		}
  		if !rf.GraceCutoff.IsZero() && !r.SessionExpires.IsZero() && r.SessionExpires.Before(rf.GraceCutoff) {
  			return false, store.ErrPastGrace
  		}
  		hasCeiling := !r.SessionExpires.IsZero() && !r.AuthTime.IsZero()
  		switch {
  		case rf.SessionAge != nil && *rf.SessionAge == 0:
  			r.SessionExpires = time.Time{}
  		case rf.SessionAge != nil:
  			r.SessionExpires = rf.AuthTime.Add(*rf.SessionAge)
  		case hasCeiling:
  			r.SessionExpires = rf.AuthTime.Add(r.SessionExpires.Sub(r.AuthTime))
  		}
  		r.AuthTime, r.RefreshedAt = rf.AuthTime, rf.RefreshedAt
  		if rf.BlobHash != "" && rf.BlobHash != r.BlobHash {
  			r.BlobHash, r.PolicyMoved = rf.BlobHash, true
  		}
  		r.ExpiresAt, r.LastTouchedAt = now.Add(ttl), now
  		return true, nil
  	})
  }

  // SetRevokedAt keeps the later mark; it moves neither the expiry nor
  // LastTouchedAt.
  func (s *Store) SetRevokedAt(ctx context.Context, k store.ContextKey, at time.Time) error {
  	return s.mutate(ctx, k, func(r *ctxRec, _ int64, _ time.Time) (bool, error) {
  		if at.After(r.RevokedAt) {
  			r.RevokedAt = at
  		}
  		r.PolicyMoved = true
  		return false, nil
  	})
  }

  // SetContextPolicy is the memory store's, its compare on the policy
  // revision made against the record this write compares.
  func (s *Store) SetContextPolicy(ctx context.Context, k store.ContextKey, policyRev uint64, p store.ContextPolicy) error {
  	if p.RevokedAt.IsZero() && p.BlobHash == "" {
  		return errors.New("store: a policy write that does not revoke must name a blob hash")
  	}
  	return s.mutate(ctx, k, func(r *ctxRec, _ int64, _ time.Time) (bool, error) {
  		if uint64(r.PolicyRev) != policyRev {
  			return false, store.ErrConflict
  		}
  		if !p.RevokedAt.IsZero() {
  			if p.RevokedAt.After(r.RevokedAt) {
  				r.RevokedAt = p.RevokedAt
  			}
  		} else {
  			r.BlobHash, r.MaxPrivilege, r.Enable = p.BlobHash, p.MaxPrivilege, p.Enable
  			if r.MaxPrivilege > 0 && r.PrivLvl > r.MaxPrivilege {
  				r.PrivLvl = r.MaxPrivilege
  			}
  			if p.MaxSessionAge > 0 {
  				if ceiling := r.AuthTime.Add(p.MaxSessionAge); r.SessionExpires.IsZero() || ceiling.Before(r.SessionExpires) {
  					r.SessionExpires = ceiling
  				}
  			}
  		}
  		r.PolicyMoved = true
  		return false, nil
  	})
  }

  // DeleteContext deletes the context alone, as the memory store's does.
  func (s *Store) DeleteContext(ctx context.Context, k store.ContextKey) error {
  	_, err := s.ctx.Delete(ctx, s.k.context(k))
  	return unavailable(err)
  }

  // DeleteContextIf deletes the context only while its Rev is rev.
  func (s *Store) DeleteContextIf(ctx context.Context, k store.ContextKey, rev uint64) error {
  	ck := s.k.context(k)
  	for {
  		var r ctxRec
  		mod, ok, err := getJSON(ctx, s.ctx, ck, &r)
  		if err != nil {
  			return err
  		}
  		if !ok || !r.ExpiresAt.After(s.now()) {
  			return store.ErrNotFound
  		}
  		if uint64(mod) != rev {
  			return store.ErrConflict
  		}
  		if done, err := commit(ctx, s.ctx, s.ctxLeases, []clientv3.Cmp{unchanged(ck, mod)}, nil, del{key: ck}); err != nil || done {
  			return err
  		}
  	}
  }

  // PutBlob writes body, keeping the later of the existing and the new
  // expiry.
  func (s *Store) PutBlob(ctx context.Context, hash string, body []byte, ttl time.Duration) error {
  	exp := s.now().Add(ttl)
  	return cas(ctx, s.tok, s.tokLeases, s.k.blob(hash), func(b blobRec) bool { return b.ExpiresAt.After(s.now()) },
  		func(b *blobRec, found bool) (bool, time.Time, bool, error) {
  			if found && b.ExpiresAt.After(exp) {
  				exp = b.ExpiresAt
  			}
  			b.Body, b.ExpiresAt = bytes.Clone(body), exp
  			return true, exp, false, nil
  		})
  }

  // GetBlob is the blob's body until its expiry.
  func (s *Store) GetBlob(ctx context.Context, hash string) ([]byte, error) {
  	var b blobRec
  	_, ok, err := getJSON(ctx, s.ctx, s.k.blob(hash), &b)
  	if err != nil {
  		return nil, err
  	}
  	if !ok || !b.ExpiresAt.After(s.now()) {
  		return nil, store.ErrNotFound
  	}
  	return b.Body, nil
  }

  // BumpBlob extends a live blob to at least now+ttl, never shortening it.
  func (s *Store) BumpBlob(ctx context.Context, hash string, ttl time.Duration) error {
  	return cas(ctx, s.ctx, s.ctxLeases, s.k.blob(hash), func(b blobRec) bool { return b.ExpiresAt.After(s.now()) },
  		func(b *blobRec, found bool) (bool, time.Time, bool, error) {
  			if !found {
  				return false, time.Time{}, false, store.ErrNotFound
  			}
  			exp := s.now().Add(ttl)
  			if !exp.After(b.ExpiresAt) {
  				return false, time.Time{}, false, nil
  			}
  			b.ExpiresAt = exp
  			return true, exp, false, nil
  		})
  }

  // indexOp is a write to the ref's index record alone: f changes it and
  // returns the lookup entries to put with it.
  func (s *Store) indexOp(ctx context.Context, ref store.ContextRef, f func(x *idxRec, now time.Time) []string) error {
  	k := store.ContextKey{NAS: ref.NAS, Username: ref.Username}
  	for {
  		snap, err := s.readCtx(ctx, k)
  		if err != nil {
  			return err
  		}
  		x := snap.idx
  		added := f(&x, s.now())
  		if snap.idxMod == 0 && x.empty() {
  			return nil
  		}
  		// Only the index record is compared: an index write and the
  		// context's own land in either order, as the memory store's
  		// separate calls do.
  		if ok, err := s.commitIndex(ctx, k, snap, &x, added); err != nil || ok {
  			return err
  		}
  	}
  }

  // commitIndex is commitCtx comparing the index record alone.
  func (s *Store) commitIndex(ctx context.Context, k store.ContextKey, snap ctxSnap, idx *idxRec, added []string) (bool, error) {
  	xk := s.k.indexed(refOf(k))
  	var puts []put
  	var dels []del
  	if idx.empty() {
  		dels = append(dels, del{key: xk})
  	} else {
  		body, err := json.Marshal(idx)
  		if err != nil {
  			return false, err
  		}
  		puts = append(puts, put{key: xk, val: body, exp: idx.maxExp()})
  	}
  	for _, key := range added {
  		puts = append(puts, put{key: key, val: []byte("{}")})
  	}
  	return commit(ctx, s.ctx, s.ctxLeases, []clientv3.Cmp{unchanged(xk, snap.idxMod)}, puts, dels...)
  }

  // IndexContext lists ref under each non-empty key for ttl.
  func (s *Store) IndexContext(ctx context.Context, principal, sid, certKey string, ref store.ContextRef, ttl time.Duration) error {
  	return s.indexOp(ctx, ref, func(x *idxRec, now time.Time) []string {
  		return s.addKeys(x, ref, principal, sid, certKey, now.Add(ttl))
  	})
  }

  // UnindexContext unlists ref from each key named; a blank certificate key
  // was never listed.
  func (s *Store) UnindexContext(ctx context.Context, principal, sid, certKey string, ref store.ContextRef) error {
  	return s.indexOp(ctx, ref, func(x *idxRec, _ time.Time) []string {
  		if principal != "" {
  			x.drop(famByPrincipal, principal)
  		}
  		if sid != "" {
  			x.drop(famBySid, sid)
  		}
  		if certKey != "" && !store.BlankCertKey(certKey) {
  			x.drop(famByCert, certKey)
  		}
  		return nil
  	})
  }

  // UnindexRef unlists ref from every key: its index record goes. The lookup
  // entries it leaves name a record that lists nothing, so they answer
  // nothing, and the sweep removes them (Ruling 6).
  func (s *Store) UnindexRef(ctx context.Context, ref store.ContextRef) error {
  	_, err := s.ctx.Delete(ctx, s.k.indexed(ref))
  	return unavailable(err)
  }

  // ReindexSid moves ref from oldSid to newSid for ttl.
  func (s *Store) ReindexSid(ctx context.Context, oldSid, newSid string, ref store.ContextRef, ttl time.Duration) error {
  	return s.indexOp(ctx, ref, func(x *idxRec, now time.Time) []string {
  		if oldSid != "" {
  			x.drop(famBySid, oldSid)
  		}
  		if newSid == "" {
  			return nil
  		}
  		x.add(famBySid, newSid, now.Add(ttl))
  		return []string{s.k.lookup(famBySid, newSid, ref)}
  	})
  }
  ```

  `PutBlob` is a
  mint's write, so it is on the token pool. `GetBlob` and `BumpBlob` are the daemon's
  authorization path, so they are on the context pool (Task 9's table).

- [ ] **Step 4: Remove what this task built from `notbuilt.go`.** Delete each method this task
  defines from `notbuilt.go`, keeping only `ContextsByPrincipal`, `ContextsBySid`,
  `ContextsByCert`, `ActivePrincipals`, `ReserveIdempotency`, `CompleteIdempotency` and
  `ReleaseIdempotency`.

- [ ] **Step 5: Run.**

  Run: `go test ./internal/store/etcd/ -count=1`
  Expected: PASS: `TestTokensOnEtcd`, `TestContextsOnEtcd/<23>`, and
  `TestPolicyRevIsTheLastPolicyWritesRevision`.

  Mutation checks (do them, report them, revert them):
  1. In `mutate`, drop the `PolicyMoved` resolution. `PolicyRevision` must fail, because a touch
     would then move `PolicyRev`.
  2. In `SwapLogin`, skip the mark comparison. This task cannot see that (no lookup readers yet).
     Note it for Task 7, whose `JoinHonoursAStandingMark` catches it.
  3. In `SetRevokedAt`, write `r.RevokedAt = at` unconditionally. `RevocationIsMonotonic` must
     fail.

- [ ] **Step 6: Commit.**

  ```bash
  gofmt -w internal/store/etcd
  make build && make test && make vet
  git add internal/store/etcd/records.go internal/store/etcd/contexts.go internal/store/etcd/notbuilt.go \
    internal/store/etcd/etcd_test.go
  git commit -m "feat(store/etcd): contexts, blobs and the login's one step on etcd

  Each context is one key whose mod_revision is its Rev; PolicyRev comes
  from the same counter through policy_moved. Every narrow setter is a
  read and a transaction comparing the context and its ref's index record;
  SwapLogin writes the context, the index change and the lookup entries,
  comparing the marks the login read. Every context property passes on a
  real etcd member.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 7: The indexes on etcd: lookups, active principals, and the sweep

**Files:**
- Create: `internal/store/etcd/indexes.go`
- Modify: `internal/store/etcd/notbuilt.go`
- Modify: `internal/store/storetest/login.go` (`IndexKeysAreExact`), `storetest.go` (`Run`)
- Test: `internal/store/etcd/etcd_test.go`

**Interfaces:**
- Consumes: Task 6's `idxRec`, `readCtx`, `keys.lookups`, `keys.indexed`, `lastTwo`.
- Produces:
  - `ContextsByPrincipal`, `ContextsBySid`, `ContextsByCert`, `ActivePrincipals` on `*etcd.Store`.
  - `func (s *Store) Sweep(ctx context.Context) (pruned, removed int, err error)`, which port49d
    calls every `sweep_interval` (Task 12).
  - `func storetest.IndexKeysAreExact(t *testing.T, b Backend)`, added to `Run`.

- [ ] **Step 1: The failing tests.** Append to `internal/store/storetest/login.go`:

  ```go
  // IndexKeysAreExact: a lookup by principal, sid or certificate finds the
  // refs indexed under exactly that key, whatever the keys hold: one that is
  // the start of another ("user:al", "user:alice"), and a device name, sid or
  // certificate key with "/" or "%" in it (plan 7d, Review Focus 3).
  func IndexKeysAreExact(t *testing.T, b Backend) {
  	ctx := context.Background()
  	s := b.New(t, func() time.Time { return t0 })
  	refs := []struct {
  		ref            store.ContextRef
  		principal, sid string
  		cert           string
  	}{
  		{store.ContextRef{NAS: "leaf-01", Username: "al"}, "user:al", "s/1", store.CertKey("CN=A/O=B", "01")},
  		{store.ContextRef{NAS: "leaf-01", Username: "alice"}, "user:alice", "s/10", store.CertKey("CN=A/O=B", "010")},
  		{store.ContextRef{NAS: "rack/1%2Fleaf", Username: "al"}, "user:al%2F", "s%2F1", store.CertKey("CN=A", "01")},
  	}
  	for _, r := range refs {
  		if err := s.PutContext(ctx, store.ContextKey{NAS: r.ref.NAS, Username: r.ref.Username},
  			store.Context{CtxID: "c", Principal: r.principal, Username: r.ref.Username}, time.Hour); err != nil {
  			t.Fatal(err)
  		}
  		if err := s.IndexContext(ctx, r.principal, r.sid, r.cert, r.ref, time.Hour); err != nil {
  			t.Fatal(err)
  		}
  	}
  	for _, r := range refs {
  		for _, q := range []struct {
  			f   func(context.Context, string) ([]store.ContextRef, error)
  			key string
  		}{{s.ContextsByPrincipal, r.principal}, {s.ContextsBySid, r.sid}, {s.ContextsByCert, r.cert}} {
  			got, err := q.f(ctx, q.key)
  			if err != nil || len(got) != 1 || got[0] != r.ref {
  				t.Fatalf("lookup %q: %v %v, want only %v", q.key, got, err, r.ref)
  			}
  		}
  	}
  	if ps, err := s.ActivePrincipals(ctx); err != nil || len(ps) != 3 {
  		t.Fatalf("active principals: %v %v", ps, err)
  	}
  }
  ```

  Add `{"IndexKeysAreExact", IndexKeysAreExact}` to `Run`'s second table.

  Append to `internal/store/etcd/etcd_test.go`:

  ```go
  // The index family: lookups, extension, the login's one step read back
  // through them, active principals (plan 7d Task 7).
  func TestIndexesOnEtcd(t *testing.T) {
  	run(t, map[string]func(*testing.T){
  		"Indexes":                         func(t *testing.T) { storetest.Indexes(t, backend) },
  		"ExtendingCarriesIndexEntries":    func(t *testing.T) { storetest.ExtendingCarriesIndexEntries(t, backend) },
  		"ExtendingNeverShortensOrCreates": func(t *testing.T) { storetest.ExtendingNeverShortensOrCreates(t, backend) },
  		"ExtendingFollowsARotatedSid":     func(t *testing.T) { storetest.ExtendingFollowsARotatedSid(t, backend) },
  		"ExtendingCarriesEveryJoinedCredential": func(t *testing.T) {
  			storetest.ExtendingCarriesEveryJoinedCredential(t, backend)
  		},
  		"BlankKeysAreNeverIndexed": func(t *testing.T) { storetest.BlankKeysAreNeverIndexed(t, backend) },
  		"UnindexRefClearsEveryKey": func(t *testing.T) { storetest.UnindexRefClearsEveryKey(t, backend) },
  		"SwapLoginIsOneStep":       func(t *testing.T) { storetest.SwapLoginIsOneStep(t, backend) },
  		"LoginsRaceToOneIndex":     func(t *testing.T) { storetest.LoginsRaceToOneIndex(t, backend) },
  		"JoinHonoursAStandingMark": func(t *testing.T) { storetest.JoinHonoursAStandingMark(t, backend) },
  		"IndexKeysAreExact":        func(t *testing.T) { storetest.IndexKeysAreExact(t, backend) },
  	})
  }

  // The sweep prunes an index record's expired entries and removes the
  // lookup entries no record lists; it never removes one a record lists,
  // so a revocation never misses a ref the index holds (Ruling 6).
  func TestTheSweepRemovesOnlyWhatNothingLists(t *testing.T) {
  	ctx := context.Background()
  	now := t0
  	s := onShared(t, func() time.Time { return now })
  	keep := store.ContextRef{NAS: "leaf-01", Username: "keep"}
  	gone := store.ContextRef{NAS: "leaf-01", Username: "gone"}
  	for _, r := range []store.ContextRef{keep, gone} {
  		if err := s.IndexContext(ctx, "user:a", "sid-"+r.Username, "", r, time.Hour); err != nil {
  			t.Fatal(err)
  		}
  	}
  	if err := s.UnindexRef(ctx, gone); err != nil {
  		t.Fatal(err)
  	}
  	if err := s.IndexContext(ctx, "", "short", "", keep, time.Minute); err != nil {
  		t.Fatal(err)
  	}
  	now = now.Add(2 * time.Minute) // "short" has expired; the hour has not
  	pruned, removed, err := s.Sweep(ctx)
  	if err != nil || pruned != 1 || removed != 3 { // gone's principal and sid, keep's "short"
  		t.Fatalf("Sweep = %d pruned, %d removed, %v", pruned, removed, err)
  	}
  	if refs, _ := s.ContextsByPrincipal(ctx, "user:a"); len(refs) != 1 || refs[0] != keep {
  		t.Fatalf("after the sweep: %v", refs)
  	}
  	resp, err := s.ctx.Get(ctx, s.k.lookups(famByPrincipal, "user:a"), clientv3.WithPrefix(), clientv3.WithCountOnly())
  	if err != nil || resp.Count != 1 {
  		t.Fatalf("lookup entries left under user:a: %v %v", resp, err)
  	}
  }
  ```

  Run: `go test ./internal/store/etcd/ -run 'TestIndexesOnEtcd|TestTheSweep' -count=1`
  Expected: FAIL: the readers return `errNotBuilt`, and `Sweep` is undefined.

- [ ] **Step 2: The readers and the sweep.** Create `internal/store/etcd/indexes.go`:

  ```go
  package etcd

  import (
  	"context"
  	"encoding/json"
  	"net/url"
  	"sort"
  	"strings"

  	clientv3 "go.etcd.io/etcd/client/v3"

  	"github.com/rhwendt/port49/internal/store"
  )

  // refsUnder reads the lookup entries under fam/key and keeps each ref whose
  // index record lists key live (Ruling 6), sorted as the memory store
  // sorts them.
  func (s *Store) refsUnder(ctx context.Context, fam, key string) ([]store.ContextRef, error) {
  	if key == "" {
  		return nil, nil
  	}
  	resp, err := s.ctx.Get(ctx, s.k.lookups(fam, key), clientv3.WithPrefix(), clientv3.WithKeysOnly())
  	if err != nil {
  		return nil, unavailable(err)
  	}
  	var refs []store.ContextRef
  	var gets []clientv3.Op
  	for _, kv := range resp.Kvs {
  		nas, user, ok := lastTwo(string(kv.Key))
  		if !ok {
  			continue
  		}
  		r := store.ContextRef{NAS: nas, Username: user}
  		refs = append(refs, r)
  		gets = append(gets, clientv3.OpGet(s.k.indexed(r)))
  	}
  	now := s.now()
  	var out []store.ContextRef
  	i := 0
  	if err := chunked(ctx, s.ctx, gets, func(t *clientv3.TxnResponse) {
  		for _, op := range t.Responses {
  			r := refs[i]
  			i++
  			for _, kv := range op.GetResponseRange().Kvs {
  				var x idxRec
  				if json.Unmarshal(kv.Value, &x) == nil && x.lists(fam, key, now) {
  					out = append(out, r)
  				}
  			}
  		}
  	}); err != nil {
  		return nil, err
  	}
  	sort.Slice(out, func(i, j int) bool {
  		return out[i].NAS+"\x00"+out[i].Username < out[j].NAS+"\x00"+out[j].Username
  	})
  	return out, nil
  }

  func (s *Store) ContextsByPrincipal(ctx context.Context, principal string) ([]store.ContextRef, error) {
  	return s.refsUnder(ctx, famByPrincipal, principal)
  }

  func (s *Store) ContextsBySid(ctx context.Context, sid string) ([]store.ContextRef, error) {
  	return s.refsUnder(ctx, famBySid, sid)
  }

  func (s *Store) ContextsByCert(ctx context.Context, certKey string) ([]store.ContextRef, error) {
  	if store.BlankCertKey(certKey) {
  		return nil, nil
  	}
  	return s.refsUnder(ctx, famByCert, certKey)
  }

  // eachIndexed calls f on every index record, a page at a time.
  func (s *Store) eachIndexed(ctx context.Context, f func(key string, mod int64, x idxRec)) error {
  	prefix := s.k.family(famIndexed)
  	end := clientv3.GetPrefixRangeEnd(prefix)
  	from := prefix
  	for {
  		resp, err := s.ctx.Get(ctx, from, clientv3.WithRange(end), clientv3.WithLimit(500))
  		if err != nil {
  			return unavailable(err)
  		}
  		for _, kv := range resp.Kvs {
  			var x idxRec
  			if json.Unmarshal(kv.Value, &x) == nil {
  				f(string(kv.Key), kv.ModRevision, x)
  			}
  		}
  		if !resp.More || len(resp.Kvs) == 0 {
  			return nil
  		}
  		from = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
  	}
  }

  // ActivePrincipals is every principal some index record lists live,
  // sorted: one pass over the index records, no lookup entry read.
  func (s *Store) ActivePrincipals(ctx context.Context) ([]string, error) {
  	now := s.now()
  	set := map[string]bool{}
  	if err := s.eachIndexed(ctx, func(_ string, _ int64, x idxRec) {
  		for _, e := range x.Principals {
  			if e.ExpiresAt.After(now) {
  				set[e.Key] = true
  			}
  		}
  	}); err != nil {
  		return nil, err
  	}
  	out := make([]string, 0, len(set))
  	for p := range set {
  		out = append(out, p)
  	}
  	sort.Strings(out)
  	return out, nil
  }

  // Sweep is the index's reclamation, which leases cannot do for it (Ruling
  // 6). It runs in two passes:
  //
  //  1. Every index record drops its expired entries, and is deleted when
  //     none is left.
  //  2. Every lookup entry whose index record no longer lists its key at
  //     all is deleted.
  //
  // Each change is compare-and-set against what was read, so a login
  // listing a key between the read and the delete keeps its lookup entry.
  // A lookup entry whose key is listed but expired is left for pass 1 of
  // the next sweep: deleted any earlier, a restamp could list a key whose
  // lookup is gone. pruned counts entries dropped, removed lookup entries
  // deleted.
  func (s *Store) Sweep(ctx context.Context) (pruned, removed int, err error) {
  	now := s.now()
  	type prune struct {
  		key string
  		mod int64
  		x   idxRec
  	}
  	var prunes []prune
  	if err := s.eachIndexed(ctx, func(key string, mod int64, x idxRec) {
  		before := len(x.Principals) + len(x.Sids) + len(x.Certs)
  		keepLive := func(l []idxEntry) []idxEntry {
  			var out []idxEntry
  			for _, e := range l {
  				if e.ExpiresAt.After(now) {
  					out = append(out, e)
  				}
  			}
  			return out
  		}
  		x.Principals, x.Sids, x.Certs = keepLive(x.Principals), keepLive(x.Sids), keepLive(x.Certs)
  		if n := before - (len(x.Principals) + len(x.Sids) + len(x.Certs)); n > 0 {
  			pruned += n
  			prunes = append(prunes, prune{key: key, mod: mod, x: x})
  		}
  	}); err != nil {
  		return 0, 0, err
  	}
  	for _, p := range prunes {
  		var puts []put
  		var dels []del
  		if p.x.empty() {
  			dels = append(dels, del{key: p.key})
  		} else {
  			body, err := json.Marshal(p.x)
  			if err != nil {
  				return pruned, removed, err
  			}
  			puts = append(puts, put{key: p.key, val: body, exp: p.x.maxExp()})
  		}
  		if _, err := commit(ctx, s.ctx, s.ctxLeases, []clientv3.Cmp{unchanged(p.key, p.mod)}, puts, dels...); err != nil {
  			return pruned, removed, err
  		}
  	}
  	for _, fam := range []string{famByPrincipal, famBySid, famByCert} {
  		n, err := s.sweepLookups(ctx, fam)
  		removed += n
  		if err != nil {
  			return pruned, removed, err
  		}
  	}
  	return pruned, removed, nil
  }

  // sweepLookups deletes fam's lookup entries whose index record does not
  // list their key, each only while the entry and the record are as read.
  func (s *Store) sweepLookups(ctx context.Context, fam string) (int, error) {
  	prefix := s.k.family(fam)
  	end := clientv3.GetPrefixRangeEnd(prefix)
  	from := prefix
  	removed := 0
  	for {
  		resp, err := s.ctx.Get(ctx, from, clientv3.WithRange(end), clientv3.WithLimit(500), clientv3.WithKeysOnly())
  		if err != nil {
  			return removed, unavailable(err)
  		}
  		for _, kv := range resp.Kvs {
  			key := string(kv.Key)
  			lookupKey, ref, ok := s.parseLookup(fam, key)
  			if !ok {
  				continue
  			}
  			xk := s.k.indexed(ref)
  			var x idxRec
  			xmod, found, err := getJSON(ctx, s.ctx, xk, &x)
  			if err != nil {
  				return removed, err
  			}
  			if found && listed(x, fam, lookupKey) {
  				continue
  			}
  			done, err := commit(ctx, s.ctx, s.ctxLeases,
  				[]clientv3.Cmp{unchanged(key, kv.ModRevision), unchanged(xk, xmod)}, nil, del{key: key})
  			if err != nil {
  				return removed, err
  			}
  			if done {
  				removed++
  			}
  		}
  		if !resp.More || len(resp.Kvs) == 0 {
  			return removed, nil
  		}
  		from = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
  	}
  }

  // listed reports whether x lists key under fam at all, live or not.
  func listed(x idxRec, fam, key string) bool {
  	for _, e := range *x.list(fam) {
  		if e.Key == key {
  			return true
  		}
  	}
  	return false
  }

  // parseLookup splits a lookup entry's key into the indexed key and the
  // ref.
  func (s *Store) parseLookup(fam, key string) (string, store.ContextRef, bool) {
  	rest := strings.TrimPrefix(key, s.k.family(fam))
  	i := strings.IndexByte(rest, '/')
  	if i < 0 {
  		return "", store.ContextRef{}, false
  	}
  	indexed, err := url.PathUnescape(rest[:i])
  	nas, user, ok := lastTwo(key)
  	if err != nil || !ok {
  		return "", store.ContextRef{}, false
  	}
  	return indexed, store.ContextRef{NAS: nas, Username: user}, true
  }
  ```

  `listed` calls `x.list` on a copy, which only reads.

  Remove `ContextsByPrincipal`, `ContextsBySid`, `ContextsByCert` and `ActivePrincipals` from
  `notbuilt.go`.

- [ ] **Step 3: Run.**

  Run: `go test ./internal/store/... -count=1`
  Expected: PASS: `TestIndexesOnEtcd/<11>`, `TestTheSweepRemovesOnlyWhatNothingLists`, and
  `IndexKeysAreExact` on memory and through the sealing layer (from `Run`).

  Mutation checks (do them, report them, revert them):
  1. In `SwapLogin` (Task 6), skip the mark comparison. `JoinHonoursAStandingMark` must fail.
  2. In `refsUnder`, drop the `x.lists(fam, key, now)` filter, keeping every lookup entry.
     `SwapLoginIsOneStep` and `UnindexRefClearsEveryKey` must fail.
  3. In `keys.lookups`, drop the trailing `"/"`. `IndexKeysAreExact` must fail.

- [ ] **Step 4: Commit.**

  ```bash
  gofmt -w internal/store
  make build && make test && make vet
  git add internal/store/etcd/indexes.go internal/store/etcd/notbuilt.go \
    internal/store/etcd/etcd_test.go internal/store/storetest/login.go internal/store/storetest/storetest.go
  git commit -m "feat(store/etcd): index lookups, active principals and the sweep

  A lookup by principal, sid or certificate answers only the refs whose
  index record lists that key live; the sweep prunes expired entries and
  removes lookup entries nothing lists, compare-and-set, so it never
  removes one a login just listed. IndexKeysAreExact pins keys that are
  prefixes of each other or hold / and %, on every backend.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 8: Idempotency on etcd, and every property against etcd and the sealing layer over it

**Files:**
- Create: `internal/store/etcd/idempotency.go`
- Modify: `internal/store/etcd/records.go` (`idemRec`)
- Delete: `internal/store/etcd/notbuilt.go`
- Modify: `internal/store/etcd/etcd_test.go`

**Interfaces:**
- Consumes: Task 5's `cas`, `getJSON`, `commit`.
- Produces: `ReserveIdempotency`, `CompleteIdempotency` and `ReleaseIdempotency` on
  `*etcd.Store`. The package now satisfies `store.Store` with no stub, and `storetest.Run` runs
  whole against it.

- [ ] **Step 1: The failing tests.** In `etcd_test.go`, replace `TestTokensOnEtcd`,
  `TestContextsOnEtcd`, `TestIndexesOnEtcd`, `run`, and `fixed` (keep `t0`, `onShared`,
  `backend`) with:

  ```go
  // planting is a store with a way to write an idempotency record whole,
  // as an older port49's or a corrupted one would sit there, which no
  // store.Store method can (storetest.Planter).
  type planting struct{ *Store }

  func (p planting) PlantIdempotency(ctx context.Context, principal, key string, rec store.Idempotency) error {
  	body, err := json.Marshal(idemRecOf(rec))
  	if err != nil {
  		return err
  	}
  	_, err = p.ctx.Put(ctx, p.k.idem(principal, key), string(body))
  	return err
  }

  // Every storetest property against etcd (plan 7d).
  func TestTheEtcdStoreHoldsEveryProperty(t *testing.T) {
  	storetest.Run(t, storetest.Backend{New: func(t *testing.T, clock func() time.Time) store.Store {
  		return planting{onShared(t, clock)}
  	}})
  }

  // And through the sealing layer over etcd, which is what port49d runs.
  func TestTheSealingLayerOverEtcdHoldsEveryProperty(t *testing.T) {
  	keys := crypt.Keys{Current: crypt.Key{ID: "k1", Bytes: [32]byte{1}}}
  	storetest.Run(t, storetest.Backend{New: func(t *testing.T, clock func() time.Time) store.Store {
  		return crypt.Wrap(onShared(t, clock), keys, nil)
  	}})
  }

  // With two of three members stopped, a write and a read each fail within
  // their deadline as store.ErrUnavailable: never a stale answer (Ruling 4;
  // spec §14, "Quorum lost").
  func TestALostQuorumIsUnavailableNeverStale(t *testing.T) {
  	c := etcdtest.StartCluster(t)
  	s, err := Open(Config{Endpoints: c.Endpoints, Prefix: etcdtest.Prefix(), Now: func() time.Time { return t0 }})
  	if err != nil {
  		t.Fatal(err)
  	}
  	defer s.Close()
  	ctx := context.Background()
  	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
  	if err := s.PutContext(ctx, k, store.Context{CtxID: "c", Principal: "p", Username: "alice"}, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	c.Stop(1)
  	c.Stop(2)
  	for name, call := range map[string]func(context.Context) error{
  		"read":  func(ctx context.Context) error { _, err := s.GetContext(ctx, k); return err },
  		"write": func(ctx context.Context) error { return s.SetRevokedAt(ctx, k, t0) },
  	} {
  		cctx, cancel := context.WithTimeout(ctx, time.Second)
  		start := time.Now()
  		err := call(cctx)
  		cancel()
  		if !errors.Is(err, store.ErrUnavailable) || time.Since(start) > 3*time.Second {
  			t.Fatalf("%s without quorum: %v after %v", name, err, time.Since(start))
  		}
  	}
  }
  ```

  Add imports `encoding/json` and `github.com/rhwendt/port49/internal/store/crypt`.

  Run: `go test ./internal/store/etcd/ -count=1`
  Expected: FAIL: the idempotency properties hit `errNotBuilt`, and `idemRecOf` is undefined.

  `SetRevokedAt` without quorum loops in `mutate` until the context's deadline: each read fails
  with `ErrUnavailable` and returns at once. If the test shows it spinning (many reads before
  the deadline), that is right, since every read fails immediately. Report the elapsed time.

- [ ] **Step 2: The record.** Append to `records.go`:

  ```go
  type idemRec struct {
  	BodyHash  string    `json:"body_hash"`
  	Response  []byte    `json:"response,omitempty"` // empty once sealed: the sealing layer seals it
  	ExpiresAt time.Time `json:"expires_at"`
  	Sealed    []byte    `json:"sealed,omitempty"`
  	Holder    string    `json:"holder,omitempty"`
  	Pending   bool      `json:"pending"`
  }

  func idemRecOf(r store.Idempotency) idemRec {
  	return idemRec{BodyHash: r.BodyHash, Response: r.Response, ExpiresAt: r.ExpiresAt, Sealed: r.Sealed,
  		Holder: r.Holder, Pending: r.Pending}
  }

  func (r idemRec) idempotency() store.Idempotency {
  	return store.Idempotency{BodyHash: r.BodyHash, Response: r.Response, ExpiresAt: r.ExpiresAt, Sealed: r.Sealed,
  		Holder: r.Holder, Pending: r.Pending}
  }
  ```

- [ ] **Step 3: The reservation.** Create `internal/store/etcd/idempotency.go`:

  ```go
  package etcd

  import (
  	"context"
  	"errors"
  	"time"

  	clientv3 "go.etcd.io/etcd/client/v3"

  	"github.com/rhwendt/port49/internal/store"
  )

  // errNoHolder refuses a record without a holder: the empty holder is one
  // any request can name (the memory store's).
  var errNoHolder = errors.New("store: an idempotency record must name its holder")

  func (s *Store) liveIdem(r idemRec) bool { return r.ExpiresAt.After(s.now()) }

  // ReserveIdempotency is design §17's put-if-absent: a live record is
  // returned untouched, and only its absence is written, compare-and-set on
  // the key, so of racing reservations exactly one lands.
  func (s *Store) ReserveIdempotency(ctx context.Context, principal, key string, rec store.Idempotency) (store.Idempotency, bool, error) {
  	if rec.Holder == "" {
  		return store.Idempotency{}, false, errNoHolder
  	}
  	var cur store.Idempotency
  	won := false
  	err := cas(ctx, s.tok, s.tokLeases, s.k.idem(principal, key), s.liveIdem,
  		func(r *idemRec, found bool) (bool, time.Time, bool, error) {
  			if found {
  				cur, won = r.idempotency(), false
  				return false, time.Time{}, false, nil
  			}
  			*r = idemRecOf(rec)
  			won = true
  			return true, rec.ExpiresAt, false, nil
  		})
  	if err != nil || won {
  		return store.Idempotency{}, won, err
  	}
  	return cur, false, nil
  }

  // CompleteIdempotency replaces the live record only while its holder is
  // expect.
  func (s *Store) CompleteIdempotency(ctx context.Context, principal, key, expect string, rec store.Idempotency) error {
  	if rec.Holder == "" {
  		return errNoHolder
  	}
  	if expect == "" {
  		return store.ErrConflict
  	}
  	return cas(ctx, s.tok, s.tokLeases, s.k.idem(principal, key), s.liveIdem,
  		func(r *idemRec, found bool) (bool, time.Time, bool, error) {
  			if !found || r.Holder != expect {
  				return false, time.Time{}, false, store.ErrConflict
  			}
  			*r = idemRecOf(rec)
  			return true, rec.ExpiresAt, false, nil
  		})
  }

  // ReleaseIdempotency deletes holder's own pending reservation and nothing
  // else, compare-and-set on the record read.
  func (s *Store) ReleaseIdempotency(ctx context.Context, principal, key, holder string) error {
  	k := s.k.idem(principal, key)
  	for {
  		var r idemRec
  		mod, ok, err := getJSON(ctx, s.tok, k, &r)
  		if err != nil {
  			return err
  		}
  		if !ok || !s.liveIdem(r) || !r.Pending || r.Holder != holder {
  			return nil
  		}
  		if done, err := commit(ctx, s.tok, s.tokLeases, []clientv3.Cmp{unchanged(k, mod)}, nil, del{key: k}); err != nil || done {
  			return err
  		}
  	}
  }
  ```

  Delete `internal/store/etcd/notbuilt.go`. Move its `var _ store.Store = (*Store)(nil)` into
  `etcd.go`.

- [ ] **Step 4: Run.**

  Run: `go test ./internal/store/... -count=1`
  Expected: PASS: `TestTheEtcdStoreHoldsEveryProperty/<every property>`,
  `TestTheSealingLayerOverEtcdHoldsEveryProperty/<every property>`,
  `TestALostQuorumIsUnavailableNeverStale`, and Tasks 5–7's backend tests. Count the subtests of
  each: they must equal the memory store's.

  ```bash
  go test ./internal/store/memory/ -run 'TestTheMemoryStoreHoldsEveryProperty$' -v -count=1 | grep -c '^    --- PASS'
  go test ./internal/store/etcd/ -run 'TestTheEtcdStoreHoldsEveryProperty$' -v -count=1 | grep -c '^    --- PASS'
  ```

  The two numbers must be equal. Report them and the package's wall time.

  Run it under the race detector once: `go test -race ./internal/store/etcd/ -count=1`. Report the
  result. A race is a finding.

- [ ] **Step 5: Commit.** This is the last commit of 7d-1. The controller then runs the final
  review of 7d-1 and opens its pull request.

  ```bash
  gofmt -w internal/store/etcd
  make build && make test && make vet
  git add internal/store/etcd/idempotency.go internal/store/etcd/records.go internal/store/etcd/etcd.go \
    internal/store/etcd/etcd_test.go
  git rm internal/store/etcd/notbuilt.go
  git commit -m "feat(store/etcd): idempotency, and every storetest property on etcd

  The reservation is put-if-absent and its completion and release a
  compare-and-set on the holder. storetest.Run passes whole against etcd
  and against the sealing layer over it, and a lost quorum is
  store.ErrUnavailable within the deadline, never a stale answer.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

# Part 7d-2: port49d on etcd (`feature/shared-store-port49d`, off `main` after 7d-1 merges)

### Task 9: The guard: a hard timeout on every call, a circuit per pool, and slots

**Files:**
- Create: `internal/store/guard/guard.go`
- Test: `internal/store/guard/guard_test.go`
- Modify: `internal/daemon/metrics/metrics.go`

**Interfaces:**
- Consumes: `store.Store`, `store.ErrUnavailable`, `store.ErrNotFound`, `store.ErrConflict`,
  `store.ErrPastGrace`; `etcd.Open` and `etcdtest.StartCluster` (7d-1) in one test.
- Produces:
  - `type guard.Pool string`; `const guard.Token, guard.Context Pool`
  - `type guard.Config struct { Component string; CallTimeout time.Duration; MaxInFlight map[Pool]int; Failures int; OpenFor time.Duration; Now func() time.Time; Say func(string); Metrics Metrics }`
  - `type guard.Metrics struct { Calls *prometheus.CounterVec; Seconds *prometheus.HistogramVec; Open *prometheus.GaugeVec }`
  - `func guard.Wrap(inner store.Store, c Config) store.Store`
  - `func guard.PoolOf(method string) Pool`, the routing table, for the tests and the docs.
  - metrics: `Metrics.StoreCalls` (`port49_store_calls_total{component,pool,outcome}`),
    `Metrics.StoreCallSeconds` (`port49_store_call_seconds{component,pool}`),
    `Metrics.StoreCircuitOpen` (`port49_store_circuit_open{component,pool}`).

**The routing table** (Ruling 8). The `context` pool is the authorization path, and the records
it reads and writes:
- **Context pool:** `GetContext`, `PutContext`, `SwapContext`, `SwapLogin`, `TouchContext`,
  `SetPrivilege`, `AnnotateContext`, `RefreshContext`, `SetRevokedAt`, `SetContextPolicy`,
  `DeleteContext`, `DeleteContextIf`, `GetBlob`, `BumpBlob`, `IndexContext`, `UnindexContext`,
  `UnindexRef`, `ContextsByPrincipal`, `ContextsBySid`, `ContextsByCert`, `ReindexSid`,
  `ActivePrincipals`.
- **Token pool:** everything else: `PutToken`, `Candidates`, `RedeemAndReceipt`, `DeleteTokens`,
  `DeleteToken`, `PurgeTokens`, `GetReceipt`, `ExtendReceipt`, `FailReceipt`,
  `DeleteReceiptsByPrincipal`, `PutBlob`, `IndexToken`, `TokensByPrincipal`, `TokensByCert`,
  `ReserveIdempotency`, `CompleteIdempotency`, `ReleaseIdempotency`, `PutRevocation`,
  `GetRevocation`, `DeleteRevocation`, `ListRevocations`.

This is the etcd backend's own split: each method there uses the client of the same name (7d-1).

- [ ] **Step 1: The failing tests.** Create `internal/store/guard/guard_test.go`:

  ```go
  package guard

  import (
  	"context"
  	"errors"
  	"os"
  	"strings"
  	"sync"
  	"testing"
  	"time"

  	"github.com/prometheus/client_golang/prometheus"
  	"github.com/prometheus/client_golang/prometheus/testutil"

  	"github.com/rhwendt/port49/internal/store"
  	"github.com/rhwendt/port49/internal/store/etcd"
  	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
  	"github.com/rhwendt/port49/internal/store/memory"
  	"github.com/rhwendt/port49/internal/store/storetest"
  )

  func TestMain(m *testing.M) { os.Exit(etcdtest.Main(m)) }

  func testMetrics() Metrics {
  	return Metrics{
  		Calls:   prometheus.NewCounterVec(prometheus.CounterOpts{Name: "c"}, []string{"component", "pool", "outcome"}),
  		Seconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "s"}, []string{"component", "pool"}),
  		Open:    prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "o"}, []string{"component", "pool"}),
  	}
  }

  // stuck is a store whose GetContext and PutToken do what the test says:
  // block until their context ends, or fail with err.
  type stuck struct {
  	store.Store
  	mu    sync.Mutex
  	err   error
  	block bool
  	calls int
  }

  func (s *stuck) do(ctx context.Context) error {
  	s.mu.Lock()
  	s.calls++
  	block, err := s.block, s.err
  	s.mu.Unlock()
  	if block {
  		<-ctx.Done()
  		return ctx.Err()
  	}
  	return err
  }

  func (s *stuck) GetContext(ctx context.Context, _ store.ContextKey) (store.Context, error) {
  	return store.Context{}, s.do(ctx)
  }

  func (s *stuck) PutToken(ctx context.Context, _ store.TokenKey, _ store.Token) (int, error) {
  	return 0, s.do(ctx)
  }

  func (s *stuck) set(block bool, err error) {
  	s.mu.Lock()
  	s.block, s.err = block, err
  	s.mu.Unlock()
  }

  func config(said *[]string) Config {
  	var mu sync.Mutex
  	return Config{Component: "daemon", CallTimeout: 50 * time.Millisecond, MaxInFlight: map[Pool]int{Token: 2, Context: 2},
  		Failures: 3, OpenFor: 100 * time.Millisecond, Now: time.Now, Metrics: testMetrics(),
  		Say: func(l string) { mu.Lock(); *said = append(*said, l); mu.Unlock() }}
  }

  var k = store.ContextKey{NAS: "leaf-01", Username: "alice"}

  // A call the store does not answer within call_timeout is
  // store.ErrUnavailable at the deadline, never later (Ruling 8).
  func TestACallPastItsTimeoutIsUnavailable(t *testing.T) {
  	var said []string
  	inner := &stuck{block: true}
  	g := Wrap(inner, config(&said))
  	start := time.Now()
  	_, err := g.GetContext(context.Background(), k)
  	if !errors.Is(err, store.ErrUnavailable) || time.Since(start) > 500*time.Millisecond {
  		t.Fatalf("%v after %v", err, time.Since(start))
  	}
  }

  // After Failures consecutive failures a pool's circuit opens: calls fail
  // at once without reaching the store, the line says so, and the gauge is
  // 1; after OpenFor one probe goes through, and its success closes it.
  func TestTheCircuitOpensAfterFailuresAndProbes(t *testing.T) {
  	var said []string
  	inner := &stuck{err: store.ErrUnavailable}
  	c := config(&said)
  	g := Wrap(inner, c)
  	for i := 0; i < 3; i++ {
  		g.GetContext(context.Background(), k)
  	}
  	before := inner.calls
  	start := time.Now()
  	if _, err := g.GetContext(context.Background(), k); !errors.Is(err, store.ErrUnavailable) || inner.calls != before ||
  		time.Since(start) > 10*time.Millisecond {
  		t.Fatalf("an open circuit reached the store or waited: %v, %d calls, %v", err, inner.calls-before, time.Since(start))
  	}
  	if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "context")); v != 1 {
  		t.Fatalf("circuit gauge %v", v)
  	}
  	if len(said) != 1 || !strings.Contains(said[0], "context pool's circuit is open after 3 consecutive failures") {
  		t.Fatalf("said %q", said)
  	}
  	// The token pool is its own: still closed.
  	if _, err := g.PutToken(context.Background(), store.TokenKey{}, store.Token{}); !errors.Is(err, store.ErrUnavailable) ||
  		inner.calls != before+1 {
  		t.Fatalf("the token pool should have reached the store: %v", err)
  	}
  	time.Sleep(110 * time.Millisecond)
  	inner.set(false, nil)
  	if _, err := g.GetContext(context.Background(), k); err != nil {
  		t.Fatalf("the probe: %v", err)
  	}
  	if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "context")); v != 0 || len(said) != 2 ||
  		!strings.Contains(said[1], "closed") {
  		t.Fatalf("after a good probe: gauge %v, said %q", v, said)
  	}
  }

  // A failed probe opens the circuit again for OpenFor.
  func TestAFailedProbeOpensItAgain(t *testing.T) {
  	var said []string
  	inner := &stuck{err: store.ErrUnavailable}
  	g := Wrap(inner, config(&said))
  	for i := 0; i < 3; i++ {
  		g.GetContext(context.Background(), k)
  	}
  	time.Sleep(110 * time.Millisecond)
  	g.GetContext(context.Background(), k) // the probe, failing
  	before := inner.calls
  	g.GetContext(context.Background(), k)
  	if inner.calls != before {
  		t.Fatal("a failed probe left the circuit closed")
  	}
  }

  // Not found, a conflict and past-grace are answers, never failures: a
  // thousand of them never open the circuit.
  func TestAnswersNeverTripIt(t *testing.T) {
  	var said []string
  	for _, err := range []error{store.ErrNotFound, store.ErrConflict, store.ErrPastGrace} {
  		inner := &stuck{err: err}
  		g := Wrap(inner, config(&said))
  		for i := 0; i < 1000; i++ {
  			g.GetContext(context.Background(), k)
  		}
  		if inner.calls != 1000 {
  			t.Fatalf("%v opened the circuit", err)
  		}
  	}
  }

  // A caller that gives up — a device's connection dropping mid-call — is
  // not the store failing: the circuit does not count it, and its slot is
  // given back (Review Focus 7).
  func TestACallerThatGivesUpIsNotAFailure(t *testing.T) {
  	var said []string
  	inner := &stuck{block: true}
  	c := config(&said)
  	c.CallTimeout = time.Hour
  	c.Failures = 1
  	g := Wrap(inner, c)
  	for i := 0; i < 5; i++ {
  		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
  		_, err := g.GetContext(ctx, k)
  		cancel()
  		if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, store.ErrUnavailable) {
  			t.Fatalf("a caller's own deadline: %v", err)
  		}
  	}
  	if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "context")); v != 0 || inner.calls != 5 {
  		t.Fatalf("the caller's give-ups opened the circuit (%v) or held slots (%d calls)", v, inner.calls)
  	}
  }

  // A pool's slots are its own: with every context slot held by a call the
  // store does not answer, a further context call is refused at its
  // deadline and a token call is served.
  func TestPoolsAreSeparate(t *testing.T) {
  	var said []string
  	inner := &stuck{block: true}
  	c := config(&said)
  	c.CallTimeout, c.Failures = 300*time.Millisecond, 100
  	g := Wrap(inner, c)
  	var wg sync.WaitGroup
  	for i := 0; i < 2; i++ {
  		wg.Add(1)
  		go func() { defer wg.Done(); g.GetContext(context.Background(), k) }()
  	}
  	time.Sleep(50 * time.Millisecond)
  	inner.set(false, nil) // new calls are answered at once; the two held stay held
  	if _, err := g.GetContext(context.Background(), k); !errors.Is(err, store.ErrUnavailable) {
  		t.Fatalf("a third context call with both slots held: %v", err)
  	}
  	if _, err := g.PutToken(context.Background(), store.TokenKey{}, store.Token{}); err != nil {
  		t.Fatalf("a token call while the context pool is full: %v", err)
  	}
  	wg.Wait()
  }

  // The guard passes every method through unchanged: every storetest
  // property holds through it.
  func TestTheGuardHoldsEveryProperty(t *testing.T) {
  	storetest.Run(t, storetest.Backend{New: func(t *testing.T, clock func() time.Time) store.Store {
  		var said []string
  		c := config(&said)
  		c.CallTimeout, c.MaxInFlight = 5*time.Second, map[Pool]int{Token: 64, Context: 64}
  		return Wrap(memory.New(clock), c)
  	}})
  }

  // On a real etcd losing its quorum, the circuit opens and calls then fail
  // at once (spec §14, "Quorum lost").
  func TestAGuardedEtcdLosingQuorumOpensItsCircuit(t *testing.T) {
  	cl := etcdtest.StartCluster(t)
  	s, err := etcd.Open(etcd.Config{Endpoints: cl.Endpoints, Prefix: etcdtest.Prefix()})
  	if err != nil {
  		t.Fatal(err)
  	}
  	defer s.Close()
  	var said []string
  	c := config(&said)
  	c.CallTimeout = 200 * time.Millisecond
  	g := Wrap(s, c)
  	cl.Stop(1)
  	cl.Stop(2)
  	for i := 0; i < 3; i++ {
  		g.GetContext(context.Background(), k)
  	}
  	start := time.Now()
  	if _, err := g.GetContext(context.Background(), k); !errors.Is(err, store.ErrUnavailable) || time.Since(start) > 20*time.Millisecond {
  		t.Fatalf("an open circuit on a lost quorum: %v after %v", err, time.Since(start))
  	}
  }

  // Every store.Store method is routed, and only to the two pools.
  func TestEveryMethodHasAPool(t *testing.T) {
  	st := reflect.TypeOf((*store.Store)(nil)).Elem()
  	for i := 0; i < st.NumMethod(); i++ {
  		if p := PoolOf(st.Method(i).Name); p != Token && p != Context {
  			t.Errorf("%s has no pool", st.Method(i).Name)
  		}
  	}
  }
  ```

  Add `"reflect"` to the imports.

  Run: `go test ./internal/store/guard/ -count=1`
  Expected: FAIL to build (`Wrap`, `Config`, `Pool`, `PoolOf` undefined).

- [ ] **Step 2: The guard.** Create `internal/store/guard/guard.go`:

  ```go
  // Package guard is design §12's mitigations for a store that is slow or
  // gone, around any store.Store (plan 7d; spec §13, decision 35): a hard
  // timeout on every call, a circuit breaker per pool that stops calling a
  // store that keeps failing and probes it, and two pools of in-flight
  // slots, so mint pressure cannot starve authorization. A call that cannot
  // get a slot within its deadline is refused: a queue is worse than a
  // refusal. It sits under the sealing layer, so a record that will not
  // decrypt is never counted as the store failing.
  package guard

  import (
  	"context"
  	"errors"
  	"fmt"
  	"sync"
  	"time"

  	"github.com/prometheus/client_golang/prometheus"

  	"github.com/rhwendt/port49/internal/store"
  )

  // Pool is one of the two.
  type Pool string

  const (
  	Token   Pool = "token"
  	Context Pool = "context"
  )

  var contextMethods = map[string]bool{
  	"GetContext": true, "PutContext": true, "SwapContext": true, "SwapLogin": true, "TouchContext": true,
  	"SetPrivilege": true, "AnnotateContext": true, "RefreshContext": true, "SetRevokedAt": true,
  	"SetContextPolicy": true, "DeleteContext": true, "DeleteContextIf": true, "GetBlob": true, "BumpBlob": true,
  	"IndexContext": true, "UnindexContext": true, "UnindexRef": true, "ContextsByPrincipal": true,
  	"ContextsBySid": true, "ContextsByCert": true, "ReindexSid": true, "ActivePrincipals": true,
  }

  // PoolOf is the pool method runs in: the context pool for the
  // authorization path's records, the token pool for everything else.
  func PoolOf(method string) Pool {
  	if contextMethods[method] {
  		return Context
  	}
  	return Token
  }

  // Config is one component's guard.
  type Config struct {
  	Component   string // "daemon" or "broker": the metrics' label and the lines' subject
  	CallTimeout time.Duration
  	MaxInFlight map[Pool]int
  	Failures    int           // consecutive failures that open a pool's circuit
  	OpenFor     time.Duration // how long it stays open before a probe
  	Now         func() time.Time
  	Say         func(line string) // told when a circuit opens or closes; nil says nothing
  	Metrics     Metrics
  }

  // Metrics are the guard's series; nil fields count nothing.
  type Metrics struct {
  	Calls   *prometheus.CounterVec   // component, pool, outcome
  	Seconds *prometheus.HistogramVec // component, pool
  	Open    *prometheus.GaugeVec     // component, pool
  }

  type pool struct {
  	name  Pool
  	slots chan struct{}
  	mu    sync.Mutex
  	fails int
  	open  bool
  	until time.Time
  	probe bool
  }

  type guarded struct {
  	inner store.Store
  	c     Config
  	pools map[Pool]*pool
  }

  // Wrap guards inner.
  func Wrap(inner store.Store, c Config) store.Store {
  	if c.Now == nil {
  		c.Now = time.Now
  	}
  	g := &guarded{inner: inner, c: c, pools: map[Pool]*pool{}}
  	for _, p := range []Pool{Token, Context} {
  		n := c.MaxInFlight[p]
  		if n <= 0 {
  			n = 64
  		}
  		g.pools[p] = &pool{name: p, slots: make(chan struct{}, n)}
  		if c.Metrics.Open != nil {
  			c.Metrics.Open.WithLabelValues(c.Component, string(p)).Set(0)
  		}
  	}
  	return g
  }

  // enter decides whether a call may go: always while closed; while open,
  // only one probe once OpenFor has passed.
  func (p *pool) enter(now time.Time) (probe, ok bool) {
  	p.mu.Lock()
  	defer p.mu.Unlock()
  	switch {
  	case !p.open:
  		return false, true
  	case now.Before(p.until) || p.probe:
  		return false, false
  	}
  	p.probe = true
  	return true, true
  }

  // leave records how a call ended, and reports whether the circuit
  // changed and how it now stands. A call not counted (a caller that gave
  // up, a slot never got) changes nothing but the probe it held.
  func (p *pool) leave(now time.Time, probe, counted, failed bool, threshold int, openFor time.Duration) (changed, open bool) {
  	p.mu.Lock()
  	defer p.mu.Unlock()
  	if probe {
  		p.probe = false
  	}
  	switch {
  	case !counted:
  		return false, p.open
  	case failed:
  		p.fails++
  		if probe || !p.open && p.fails >= threshold {
  			was := p.open
  			p.open, p.until = true, now.Add(openFor)
  			return !was, true
  		}
  		return false, p.open
  	}
  	p.fails = 0
  	if p.open {
  		p.open = false
  		return true, false
  	}
  	return false, false
  }

  // do runs one call in pool p.
  func (g *guarded) do(ctx context.Context, p Pool, f func(context.Context) error) error {
  	pl := g.pools[p]
  	probe, ok := pl.enter(g.c.Now())
  	if !ok {
  		g.count(p, "circuit_open")
  		return fmt.Errorf("%w: the %s pool's circuit is open", store.ErrUnavailable, p)
  	}
  	cctx, cancel := context.WithTimeout(ctx, g.c.CallTimeout)
  	defer cancel()
  	select {
  	case pl.slots <- struct{}{}:
  	case <-cctx.Done():
  		pl.leave(g.c.Now(), probe, false, false, g.c.Failures, g.c.OpenFor)
  		if ctx.Err() != nil {
  			g.count(p, "canceled")
  			return ctx.Err()
  		}
  		g.count(p, "saturated")
  		return fmt.Errorf("%w: every %s slot was busy for %v", store.ErrUnavailable, p, g.c.CallTimeout)
  	}
  	start := time.Now()
  	err := f(cctx)
  	<-pl.slots
  	if g.c.Metrics.Seconds != nil {
  		g.c.Metrics.Seconds.WithLabelValues(g.c.Component, string(p)).Observe(time.Since(start).Seconds())
  	}
  	outcome, counted, failed := classify(ctx, cctx, err)
  	if outcome == "timeout" {
  		err = fmt.Errorf("%w: no answer in %v", store.ErrUnavailable, g.c.CallTimeout)
  	}
  	g.count(p, outcome)
  	if changed, open := pl.leave(g.c.Now(), probe, counted, failed, g.c.Failures, g.c.OpenFor); changed {
  		g.changed(p, open, err)
  	}
  	return err
  }

  // classify names how a call ended; counted is whether it says anything
  // about the store, failed whether it failed.
  func classify(caller, call context.Context, err error) (outcome string, counted, failed bool) {
  	switch {
  	case err == nil:
  		return "ok", true, false
  	case caller.Err() != nil:
  		return "canceled", false, false
  	case errors.Is(err, store.ErrNotFound):
  		return "not_found", true, false
  	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrPastGrace):
  		return "conflict", true, false
  	case call.Err() != nil:
  		return "timeout", true, true
  	case errors.Is(err, store.ErrUnavailable):
  		return "unavailable", true, true
  	}
  	return "error", true, false
  }

  func (g *guarded) count(p Pool, outcome string) {
  	if g.c.Metrics.Calls != nil {
  		g.c.Metrics.Calls.WithLabelValues(g.c.Component, string(p), outcome).Inc()
  	}
  }

  func (g *guarded) changed(p Pool, open bool, cause error) {
  	v := 0.0
  	if open {
  		v = 1
  	}
  	if g.c.Metrics.Open != nil {
  		g.c.Metrics.Open.WithLabelValues(g.c.Component, string(p)).Set(v)
  	}
  	if g.c.Say == nil {
  		return
  	}
  	if open {
  		g.c.Say(fmt.Sprintf("port49d: store: the %s's %s pool's circuit is open after %d consecutive failures (%v); "+
  			"each call on it fails at once until a probe in %v succeeds; devices see store_unavailable, and "+
  			"break-glass is refused (L4); port49d stops if the store is gone for store.etcd.hold_ttl",
  			g.c.Component, p, g.c.Failures, cause, g.c.OpenFor))
  		return
  	}
  	g.c.Say(fmt.Sprintf("port49d: store: the %s's %s pool's circuit is closed: a probe was answered", g.c.Component, p))
  }
  ```

  Then one method per `store.Store` method, each three lines, in the interface's order. For
  example:

  ```go
  func (g *guarded) PutToken(ctx context.Context, k store.TokenKey, t store.Token) (n int, err error) {
  	err = g.do(ctx, Token, func(ctx context.Context) (e error) { n, e = g.inner.PutToken(ctx, k, t); return })
  	return
  }

  func (g *guarded) GetContext(ctx context.Context, k store.ContextKey) (c store.Context, err error) {
  	err = g.do(ctx, Context, func(ctx context.Context) (e error) { c, e = g.inner.GetContext(ctx, k); return })
  	return
  }

  func (g *guarded) SwapLogin(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration,
  	w store.LoginWrite) error {
  	return g.do(ctx, Context, func(ctx context.Context) error { return g.inner.SwapLogin(ctx, k, rev, c, ttl, w) })
  }
  ```

  Write all forty-three. Each one's pool is the routing table's (`PoolOf(name)`), written as the
  constant. `TestEveryMethodHasAPool` pins the table, and `TestTheGuardHoldsEveryProperty` pins
  the pass-through. End the file with `var _ store.Store = (*guarded)(nil)`.

  A circuit-open error from the guard is store.ErrUnavailable, so every handler already answers
  it `store_unavailable` (spec §5.7). No reason code is added.

- [ ] **Step 3: The metrics.** In `internal/daemon/metrics/metrics.go`, beside `StoreOps`:

  ```go
  	// StoreCalls, StoreCallSeconds and StoreCircuitOpen are the guard's
  	// (internal/store/guard; plan 7d): every store call by component
  	// (daemon, broker), pool (token, context) and outcome (ok, not_found,
  	// conflict, timeout, unavailable, circuit_open, saturated, canceled,
  	// error); how long they took; and whether each pool's circuit is open,
  	// design §15's circuit-breaker state.
  	StoreCalls       *prometheus.CounterVec
  	StoreCallSeconds *prometheus.HistogramVec
  	StoreCircuitOpen *prometheus.GaugeVec
  ```

  constructed in `New` as:

  ```go
  		StoreCalls: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_store_calls_total",
  			Help: "Store calls through the guard, by component, pool and outcome."}, []string{"component", "pool", "outcome"}),
  		StoreCallSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "port49_store_call_seconds",
  			Help:    "Store call latency through the guard, by component and pool.",
  			Buckets: []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5}}, []string{"component", "pool"}),
  		StoreCircuitOpen: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "port49_store_circuit_open",
  			Help: "1 while a pool's circuit is open: its calls fail at once until a probe succeeds."}, []string{"component", "pool"}),
  ```

  Add the three to the registration list. Add a method:

  ```go
  // StoreGuard is the guard's Metrics over these series.
  func (m *Metrics) StoreGuard() guard.Metrics {
  	return guard.Metrics{Calls: m.StoreCalls, Seconds: m.StoreCallSeconds, Open: m.StoreCircuitOpen}
  }
  ```

  If `internal/store/guard` importing nothing of `metrics` and `metrics` importing `guard` forms a
  cycle anywhere, the compiler says so. Then build `guard.Metrics` in `cmd/port49d` instead, and
  say so.

- [ ] **Step 4: Run.**

  Run: `go test ./internal/store/guard/ ./internal/daemon/metrics/ -count=1`
  Expected: PASS: every test above, `TestTheGuardHoldsEveryProperty/<every property>` included.

  Mutation checks (do them, report them, revert them):
  1. In `classify`, move the `caller.Err()` case below `call.Err()`.
     `TestACallerThatGivesUpIsNotAFailure` must fail.
  2. In `do`, wait for a slot on `ctx` rather than `cctx`. `TestPoolsAreSeparate` must hang past
     its deadline, so give that run `-timeout 30s`.

- [ ] **Step 5: Commit.**

  ```bash
  gofmt -w internal/store/guard internal/daemon/metrics
  make build && make test && make vet
  git add internal/store/guard internal/daemon/metrics/metrics.go
  git commit -m "feat(store/guard): a hard timeout, a circuit per pool, and slots

  Every store call has its own deadline; after five consecutive failures
  a pool's circuit opens for five seconds and then lets one probe through;
  token and context calls have their own slots, and one that cannot get
  a slot within its deadline is refused. A caller that gave up is never
  the store failing. Design §12's hard timeouts, circuit breaker and pool
  separation (plan 7d; decision 35).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 10: `store:` in port49d.yaml, and every packet's deadline

**Files:**
- Modify: `internal/config/config.go`
- Create: `internal/config/store_test.go`
- Modify: `internal/daemon/server/server.go` (`Deps.PacketDeadline`), `conn.go` (`dispatch`)
- Test: `internal/daemon/server/server_test.go`
- Modify: `cmd/port49d/main.go` (`deps.PacketDeadline`)

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `type config.StoreConfig struct { Backend string; PacketDeadline time.Duration; Etcd *EtcdConfig }`
  - `type config.EtcdConfig struct { Endpoints []string; CAFile, Prefix string; Daemon EtcdIdentity; Broker *EtcdIdentity; Roles string; CallTimeout time.Duration; Breaker EtcdBreaker; MaxInFlight EtcdInFlight; LeaseGrace, StartTimeout, HoldTTL, SweepInterval time.Duration }`
  - `type config.EtcdIdentity struct { CertFile, KeyFile string }`, `type config.EtcdBreaker struct { Failures int; OpenFor time.Duration }`, `type config.EtcdInFlight struct { Token, Context int }`
  - `config.Config.Store StoreConfig`
  - `func config.StoreOf(raw []byte) (StoreConfig, error)` (for `port49d store-roles`, Task 11)
  - `const config.BackendMemory = "memory"`, `config.BackendEtcd = "etcd"`, `config.RolesUnenforced = "unenforced"`
  - `server.Deps.PacketDeadline time.Duration`

The schema, with every default:

```yaml
store:
  backend: etcd                 # memory (default) or etcd
  packet_deadline: 2s           # 100ms to 4s, and at least store.etcd.call_timeout
  etcd:
    endpoints: [https://etcd-0:2379, https://etcd-1:2379, https://etcd-2:2379]   # https only
    ca_file: /etc/port49/etcd-ca.pem
    prefix: /port49/            # the keyspace; must start with /
    daemon: {cert_file: /etc/port49/etcd-daemon.pem, key_file: /etc/port49/etcd-daemon-key.pem}
    broker: {cert_file: /etc/port49/etcd-broker.pem, key_file: /etc/port49/etcd-broker-key.pem}
    roles: enforced             # enforced (default) or unenforced
    call_timeout: 500ms         # 10ms to 5s
    breaker: {failures: 5, open_for: 5s}         # 1 to 100; 1s to 5m
    max_in_flight: {token: 64, context: 128}     # 1 to 4096 each
    lease_grace: 5m             # 1m to 1h
    start_timeout: 30s          # 5s to 10m
    hold_ttl: 15s               # 5s to 60s
    sweep_interval: 10m         # 1m to 24h
```

**Rulings in this task:**
- `store.backend: etcd` requires a `broker:` block. Until 7e the one port49d on a keyspace is its
  broker too, so a broker-less port49d on etcd would have no policy to carry live contexts onto at
  a start (Ruling 12).
- Key files readable by group or other are refused.
- `store.etcd` beside `backend: memory` is refused, so a config that names etcd and runs on memory
  fails loudly.

- [ ] **Step 1: The failing tests.** Create `internal/config/store_test.go`:

  ```go
  package config

  import (
  	"os"
  	"path/filepath"
  	"strings"
  	"testing"
  	"time"
  )

  // storeFiles writes a CA and two identities' files, mode 0600, and
  // returns the dir.
  func storeFiles(t *testing.T) string {
  	t.Helper()
  	dir := t.TempDir()
  	for _, f := range []string{"ca.pem", "d.pem", "d-key.pem", "b.pem", "b-key.pem"} {
  		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
  			t.Fatal(err)
  		}
  	}
  	return dir
  }

  func etcdYAML(dir string) storeYAML {
  	return storeYAML{Backend: "etcd", Etcd: &EtcdConfig{
  		Endpoints: []string{"https://etcd-0:2379"}, CAFile: filepath.Join(dir, "ca.pem"),
  		Daemon: EtcdIdentity{CertFile: filepath.Join(dir, "d.pem"), KeyFile: filepath.Join(dir, "d-key.pem")},
  		Broker: &EtcdIdentity{CertFile: filepath.Join(dir, "b.pem"), KeyFile: filepath.Join(dir, "b-key.pem")}}}
  }

  func TestTheStoreDefaultsToMemoryWithAPacketDeadline(t *testing.T) {
  	s, err := checkStore(storeYAML{}, true)
  	if err != nil || s.Backend != BackendMemory || s.PacketDeadline != 2*time.Second || s.Etcd != nil {
  		t.Fatalf("%+v %v", s, err)
  	}
  }

  func TestEtcdTakesItsDefaults(t *testing.T) {
  	s, err := checkStore(etcdYAML(storeFiles(t)), true)
  	if err != nil {
  		t.Fatal(err)
  	}
  	e := s.Etcd
  	if e.Prefix != "/port49/" || e.Roles != "enforced" || e.CallTimeout != 500*time.Millisecond ||
  		e.Breaker.Failures != 5 || e.Breaker.OpenFor != 5*time.Second || e.MaxInFlight.Token != 64 ||
  		e.MaxInFlight.Context != 128 || e.LeaseGrace != 5*time.Minute || e.StartTimeout != 30*time.Second ||
  		e.HoldTTL != 15*time.Second || e.SweepInterval != 10*time.Minute {
  		t.Fatalf("%+v", e)
  	}
  }

  func TestTheStoreRefusesWhatWouldRunUnsafely(t *testing.T) {
  	dir := storeFiles(t)
  	if err := os.WriteFile(filepath.Join(dir, "loose-key.pem"), []byte("x"), 0o644); err != nil {
  		t.Fatal(err)
  	}
  	for _, c := range []struct {
  		name   string
  		edit   func(*storeYAML)
  		broker bool
  		want   string
  	}{
  		{"unknown backend", func(s *storeYAML) { s.Backend = "redis" }, true, `store.backend "redis": must be memory or etcd`},
  		{"etcd with no block", func(s *storeYAML) { s.Etcd = nil }, true, "store.etcd is missing"},
  		{"a block on memory", func(s *storeYAML) { s.Backend = "memory" }, true, "store.etcd is set but store.backend is memory"},
  		{"plain http", func(s *storeYAML) { s.Etcd.Endpoints = []string{"http://etcd-0:2379"} }, true, "must be https://"},
  		{"no endpoints", func(s *storeYAML) { s.Etcd.Endpoints = nil }, true, "store.etcd.endpoints is empty"},
  		{"a loose key", func(s *storeYAML) { s.Etcd.Daemon.KeyFile = filepath.Join(dir, "loose-key.pem") }, true,
  			"readable by group or other"},
  		{"no broker identity", func(s *storeYAML) { s.Etcd.Broker = nil }, true, "store.etcd.broker is missing"},
  		{"etcd with no broker", func(s *storeYAML) {}, false, "store.backend etcd needs a broker: block"},
  		{"roles misspelt", func(s *storeYAML) { s.Etcd.Roles = "off" }, true, `store.etcd.roles "off"`},
  		{"a deadline past 4s", func(s *storeYAML) { s.PacketDeadline = 5 * time.Second }, true, "store.packet_deadline"},
  		{"a deadline under the call's", func(s *storeYAML) {
  			s.PacketDeadline, s.Etcd.CallTimeout = 200*time.Millisecond, time.Second
  		}, true, "at least store.etcd.call_timeout"},
  		{"a prefix not absolute", func(s *storeYAML) { s.Etcd.Prefix = "port49/" }, true, "store.etcd.prefix"},
  		{"a hold too short", func(s *storeYAML) { s.Etcd.HoldTTL = time.Second }, true, "store.etcd.hold_ttl"},
  	} {
  		y := etcdYAML(dir)
  		c.edit(&y)
  		if _, err := checkStore(y, c.broker); err == nil || !strings.Contains(err.Error(), c.want) {
  			t.Errorf("%s: %v, want %q", c.name, err, c.want)
  		}
  	}
  }
  ```

  In `internal/daemon/server/server_test.go`, add:

  ```go
  // hangingStore answers Candidates only when its context ends: a store
  // that does not answer.
  type hangingStore struct{ store.Store }

  func (hangingStore) Candidates(ctx context.Context, _ store.TokenKey) ([]store.Token, error) {
  	<-ctx.Done()
  	return nil, ctx.Err()
  }

  // A packet's store work ends at store.packet_deadline: the device hears
  // ERROR then, never silence until its own timeout (spec §13, decision 35;
  // L35 measures what each image does with it).
  func TestAPacketsStoreWorkEndsAtItsDeadline(t *testing.T) {
  	log := &syncBuffer{}
  	ts := newTestServerWith(t, log, hangingStore{memory.New(time.Now)}, nil, func(d *Deps) {
  		d.PacketDeadline = 200 * time.Millisecond
  	})
  	c := dial(t, ts.addr, []byte("k2"))
  	start := time.Now()
  	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
  		Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: []byte("p49_e2e")}.Encode(), 0)
  	_, body := c.recv(t)
  	took := time.Since(start)
  	reply, err := wire.DecodeAuthenReply(body)
  	if err != nil || reply.Status != wire.AuthenStatusError || took < 200*time.Millisecond || took > time.Second {
  		t.Fatalf("status %v (%v) after %v", reply.Status, err, took)
  	}
  }
  ```

  Run: `go test ./internal/config/ ./internal/daemon/server/ -count=1`
  Expected: FAIL to build (`storeYAML`, `checkStore`, `EtcdConfig`, `Deps.PacketDeadline` undefined).

- [ ] **Step 2: The config.** In `internal/config/config.go`:

  1. After `CertificateStatusOCSP`, add the types from Interfaces with their YAML tags, snake_case
     as the schema above shows, and their comments: each field's meaning and bounds, as the schema
     says. `StoreConfig` has no YAML tags. It is the resolved form, built from:

     ```go
     type storeYAML struct {
     	Backend        string        `yaml:"backend"`
     	PacketDeadline time.Duration `yaml:"packet_deadline"`
     	Etcd           *EtcdConfig   `yaml:"etcd"`
     }

     const (
     	BackendMemory   = "memory"
     	BackendEtcd     = "etcd"
     	RolesEnforced   = "enforced"
     	RolesUnenforced = "unenforced"
     )
     ```

  2. Add `Store storeYAML \`yaml:"store"\`` to `fileConfig` and `Store StoreConfig` to `Config`.
     In `Load`, after the broker block is checked and before the encryption keys are read, add:

     ```go
     	if c.Store, err = checkStore(f.Store, f.Broker != nil); err != nil {
     		return Config{}, err
     	}
     ```

     Match the local names `Load` uses (`f`, `c`, `err`). Read the function first.

  3. Add:

     ```go
     // checkStore resolves `store:` (plan 7d; spec §13, decision 35): the
     // backend, the packet deadline, and on etcd every key's default and
     // bound. It refuses what would run unsafely: an endpoint that is not
     // https, a key file group or other can read, an identity missing, or etcd
     // with no broker, since until plan 7e the one port49d on a keyspace is its
     // broker too.
     func checkStore(s storeYAML, hasBroker bool) (StoreConfig, error) {
     	out := StoreConfig{Backend: or(s.Backend, BackendMemory), PacketDeadline: orD(s.PacketDeadline, 2*time.Second)}
     	if out.PacketDeadline < 100*time.Millisecond || out.PacketDeadline > 4*time.Second {
     		return StoreConfig{}, fmt.Errorf("store.packet_deadline %v: must be 100ms to 4s, so a device hears port49's "+
     			"answer before its own TACACS+ timeout", out.PacketDeadline)
     	}
     	switch out.Backend {
     	case BackendMemory:
     		if s.Etcd != nil {
     			return StoreConfig{}, errors.New("store.etcd is set but store.backend is memory: say store.backend: etcd, " +
     				"or remove store.etcd")
     		}
     		return out, nil
     	case BackendEtcd:
     	default:
     		return StoreConfig{}, fmt.Errorf("store.backend %q: must be memory or etcd", s.Backend)
     	}
     	if s.Etcd == nil {
     		return StoreConfig{}, errors.New("store.backend is etcd and store.etcd is missing")
     	}
     	if !hasBroker {
     		return StoreConfig{}, errors.New("store.backend etcd needs a broker: block: until plan 7e the one port49d " +
     			"on a keyspace is its broker too")
     	}
     	e := *s.Etcd
     	if len(e.Endpoints) == 0 {
     		return StoreConfig{}, errors.New("store.etcd.endpoints is empty")
     	}
     	for i, ep := range e.Endpoints {
     		u, err := url.Parse(ep)
     		if err != nil || u.Scheme != "https" || u.Host == "" {
     			return StoreConfig{}, fmt.Errorf("store.etcd.endpoints[%d] %q: must be https://host:port: port49d "+
     				"authenticates to etcd by client certificate (decision 35)", i, ep)
     		}
     	}
     	e.Prefix = or(e.Prefix, "/port49/")
     	if !strings.HasPrefix(e.Prefix, "/") {
     		return StoreConfig{}, fmt.Errorf("store.etcd.prefix %q: must start with /", e.Prefix)
     	}
     	if !strings.HasSuffix(e.Prefix, "/") {
     		e.Prefix += "/"
     	}
     	if e.Broker == nil {
     		return StoreConfig{}, errors.New("store.etcd.broker is missing: the broker authenticates to etcd as " +
     			"itself (decision 35)")
     	}
     	if err := readableFile("store.etcd.ca_file", e.CAFile); err != nil {
     		return StoreConfig{}, err
     	}
     	for _, id := range []struct {
     		name string
     		id   EtcdIdentity
     	}{{"store.etcd.daemon", e.Daemon}, {"store.etcd.broker", *e.Broker}} {
     		if err := readableFile(id.name+".cert_file", id.id.CertFile); err != nil {
     			return StoreConfig{}, err
     		}
     		if err := privateFile(id.name+".key_file", id.id.KeyFile); err != nil {
     			return StoreConfig{}, err
     		}
     	}
     	switch e.Roles = or(e.Roles, RolesEnforced); e.Roles {
     	case RolesEnforced, RolesUnenforced:
     	default:
     		return StoreConfig{}, fmt.Errorf("store.etcd.roles %q: must be enforced or unenforced", e.Roles)
     	}
     	for _, d := range []struct {
     		name     string
     		v        *time.Duration
     		def      time.Duration
     		min, max time.Duration
     	}{
     		{"store.etcd.call_timeout", &e.CallTimeout, 500 * time.Millisecond, 10 * time.Millisecond, 5 * time.Second},
     		{"store.etcd.breaker.open_for", &e.Breaker.OpenFor, 5 * time.Second, time.Second, 5 * time.Minute},
     		{"store.etcd.lease_grace", &e.LeaseGrace, 5 * time.Minute, time.Minute, time.Hour},
     		{"store.etcd.start_timeout", &e.StartTimeout, 30 * time.Second, 5 * time.Second, 10 * time.Minute},
     		{"store.etcd.hold_ttl", &e.HoldTTL, 15 * time.Second, 5 * time.Second, time.Minute},
     		{"store.etcd.sweep_interval", &e.SweepInterval, 10 * time.Minute, time.Minute, 24 * time.Hour},
     	} {
     		*d.v = orD(*d.v, d.def)
     		if *d.v < d.min || *d.v > d.max {
     			return StoreConfig{}, fmt.Errorf("%s %v: must be %v to %v", d.name, *d.v, d.min, d.max)
     		}
     	}
     	for _, n := range []struct {
     		name          string
     		v             *int
     		def, min, max int
     	}{
     		{"store.etcd.breaker.failures", &e.Breaker.Failures, 5, 1, 100},
     		{"store.etcd.max_in_flight.token", &e.MaxInFlight.Token, 64, 1, 4096},
     		{"store.etcd.max_in_flight.context", &e.MaxInFlight.Context, 128, 1, 4096},
     	} {
     		*n.v = orI(*n.v, n.def)
     		if *n.v < n.min || *n.v > n.max {
     			return StoreConfig{}, fmt.Errorf("%s %d: must be %d to %d", n.name, *n.v, n.min, n.max)
     		}
     	}
     	if out.PacketDeadline < e.CallTimeout {
     		return StoreConfig{}, fmt.Errorf("store.packet_deadline %v: must be at least store.etcd.call_timeout (%v)",
     			out.PacketDeadline, e.CallTimeout)
     	}
     	out.Etcd = &e
     	return out, nil
     }

     // readableFile refuses a path that is empty or not a regular file.
     func readableFile(name, path string) error {
     	if path == "" {
     		return fmt.Errorf("%s is missing", name)
     	}
     	fi, err := os.Stat(path)
     	if err != nil {
     		return fmt.Errorf("%s %s: %w", name, path, err)
     	}
     	if !fi.Mode().IsRegular() {
     		return fmt.Errorf("%s %s: not a regular file", name, path)
     	}
     	return nil
     }

     // privateFile is readableFile for a private key: group or other able to
     // read it is refused.
     func privateFile(name, path string) error {
     	if err := readableFile(name, path); err != nil {
     		return err
     	}
     	fi, _ := os.Stat(path)
     	if fi.Mode().Perm()&0o077 != 0 {
     		return fmt.Errorf("%s %s: readable by group or other (mode %04o): chmod 600 it", name, path, fi.Mode().Perm())
     	}
     	return nil
     }

     // StoreOf is `store:` from port49d.yaml's bytes, checked as Load checks
     // it, for `port49d store-roles`, which reads nothing else (plan 7d).
     func StoreOf(raw []byte) (StoreConfig, error) {
     	var f fileConfig
     	dec := yaml.NewDecoder(bytes.NewReader(raw))
     	dec.KnownFields(true)
     	if err := dec.Decode(&f); err != nil && err != io.EOF {
     		return StoreConfig{}, fmt.Errorf("config: %w; check the key spelling against the port49d.yaml schema", decodeFault(err))
     	}
     	return checkStore(f.Store, f.Broker != nil)
     }
     ```

     Add `net/url` to the imports, and `strings` if it is not there.

- [ ] **Step 3: The packet deadline.** In `internal/daemon/server/server.go`, add to `Deps`, beside
  `IdleTimeout`:

  ```go
  	// PacketDeadline bounds the store work of one packet (store.packet_deadline;
  	// plan 7d): past it every store call returns, the handler answers
  	// store_unavailable, and the device hears that before its own timeout.
  	// Zero is none.
  	PacketDeadline time.Duration
  ```

  In `conn.go`'s `dispatch`, as its first lines:

  ```go
  	if s.d.PacketDeadline > 0 {
  		var cancel context.CancelFunc
  		ctx, cancel = context.WithTimeout(ctx, s.d.PacketDeadline)
  		defer cancel()
  	}
  ```

  In `cmd/port49d/main.go`, where `deps := server.Deps{…}` is built, add `PacketDeadline:
  cfg.Store.PacketDeadline,`.

- [ ] **Step 4: Run.**

  Run: `go test ./internal/config/ ./internal/daemon/server/ ./cmd/port49d/ -count=1`
  Expected: PASS. Existing configs carry no `store:`, so they take the memory default and its 2 s
  deadline. That changes no existing test, since none waits 2 s on a store.

- [ ] **Step 5: Commit.**

  ```bash
  gofmt -w internal/config internal/daemon/server cmd/port49d
  make build && make test && make vet
  git add internal/config/config.go internal/config/store_test.go internal/daemon/server/server.go \
    internal/daemon/server/conn.go internal/daemon/server/server_test.go cmd/port49d/main.go
  git commit -m "feat(config): store: in port49d.yaml, and every packet's store deadline

  store.backend is memory (default) or etcd; store.packet_deadline (2s, at
  most 4s) bounds every TACACS+ packet's store work, so a device hears
  store_unavailable before its own timeout and a redemption's write lands
  inside the refresh's 30s settle pass (4b m3). store.etcd refuses plain
  http, a key file others can read, a missing identity, and etcd with no
  broker (plan 7d; decision 35).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 11: Each component its own identity on etcd, its roles, and `port49d store-roles`

**Files:**
- Modify: `internal/store/etcd/etcd.go` (`Open` dials two clients)
- Create: `internal/store/etcd/roles.go`
- Test: `internal/store/etcd/roles_test.go`
- Create: `cmd/port49d/storeroles.go`
- Test: `cmd/port49d/storeroles_test.go`
- Modify: `cmd/port49d/main.go` (the subcommand's dispatch)

**Interfaces:**
- Consumes: `config.StoreOf` (Task 10); `etcdtest.Start`, `(*Server).EnableAuth`,
  `(*Server).TLS`, `etcdtest.Grant` (Task 5).
- Produces:
  - `const etcd.RoleDaemon = "port49_daemon"`, `etcd.RoleBroker = "port49_broker"`
  - `type etcd.Grant struct { Role, Key, RangeEnd string; Write bool }`; `func etcd.Roles(prefix string) []Grant`
  - `var etcd.ErrNotSeparated`; `func (s *Store) CheckIdentity(ctx context.Context, broker bool) error`
  - `func storeRolesCmd(args []string, stdout, stderr io.Writer) int` in `cmd/port49d`

- [ ] **Step 1: The failing tests.** Create `internal/store/etcd/roles_test.go`:

  ```go
  package etcd

  import (
  	"context"
  	"errors"
  	"testing"
  	"time"

  	"github.com/rhwendt/port49/internal/store"
  	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
  )

  // provisioned is a TLS member with auth on and port49's roles applied
  // for prefix: users port49-daemon and port49-broker.
  func provisioned(t *testing.T, prefix string) *etcdtest.Server {
  	srv := etcdtest.Start(t, etcdtest.Options{TLS: true})
  	var grants []etcdtest.Grant
  	for _, g := range Roles(prefix) {
  		grants = append(grants, etcdtest.Grant{Role: g.Role, Key: g.Key, RangeEnd: g.RangeEnd, Write: g.Write})
  	}
  	srv.EnableAuth(t, grants, map[string][]string{"port49-daemon": {RoleDaemon}, "port49-broker": {RoleBroker}})
  	return srv
  }

  func openAs(t *testing.T, srv *etcdtest.Server, cn, prefix string) *Store {
  	s, err := Open(Config{Endpoints: []string{srv.Endpoint}, TLS: srv.TLS(t, cn), Prefix: prefix,
  		Now: func() time.Time { return t0 }})
  	if err != nil {
  		t.Fatal(err)
  	}
  	t.Cleanup(func() { s.Close() })
  	return s
  }

  // Under port49's roles, each component does its own work and the daemon
  // cannot do the broker's: it redeems, writes contexts and reads marks; it
  // cannot write a mark, read an idempotency record or write the token
  // index (Ruling 10).
  func TestTheRolesSeparateTheComponents(t *testing.T) {
  	const prefix = "/port49/"
  	srv := provisioned(t, prefix)
  	ctx := context.Background()
  	d, b := openAs(t, srv, "port49-daemon", prefix), openAs(t, srv, "port49-broker", prefix)

  	k := store.TokenKey{NAS: "leaf-01", Username: "alice"}
  	if err := b.IndexToken(ctx, "user:alice", "", k, time.Minute); err != nil {
  		t.Fatalf("the broker indexes a token: %v", err)
  	}
  	if _, err := b.PutToken(ctx, k, store.Token{ID: "t", Secret: []byte("s"), Kind: store.KindLogin,
  		ExpiresAt: t0.Add(time.Minute)}); err != nil {
  		t.Fatalf("the broker mints: %v", err)
  	}
  	if err := b.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: "user:bob", At: t0}); err != nil {
  		t.Fatalf("the broker marks: %v", err)
  	}
  	w := store.ReceiptWrite{Key: store.ReceiptKey{NAS: "leaf-01", Username: "alice", Kind: store.KindLogin},
  		Receipt: store.Receipt{RetainUntil: t0.Add(time.Hour)}, Principal: "user:alice", IndexTTL: time.Hour}
  	if err := d.RedeemAndReceipt(ctx, k, "t", w); err != nil {
  		t.Fatalf("the daemon redeems: %v", err)
  	}
  	login := store.Context{CtxID: "c", Principal: "user:alice", Username: "alice", AuthTime: t0, RefreshedAt: t0}
  	if _, err := store.JoinContext(ctx, d, store.ContextKey{NAS: "leaf-01", Username: "alice"}, login, t0, t0,
  		time.Hour, store.LoginIndex{Principal: "user:alice", TTL: time.Hour}); err != nil {
  		t.Fatalf("the daemon writes a login, comparing the marks: %v", err)
  	}
  	for name, err := range map[string]error{
  		"write a mark":              d.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: "user:x", At: t0}),
  		"lift a mark":               d.DeleteRevocation(ctx, store.RevocationPrincipal, "user:bob"),
  		"write the token index":     d.IndexToken(ctx, "user:alice", "", k, time.Minute),
  		"reserve an idempotency key": func() error { _, _, err := d.ReserveIdempotency(ctx, "user:alice", "k",
  			store.Idempotency{Holder: "h", Pending: true, ExpiresAt: t0.Add(time.Minute)}); return err }(),
  	} {
  		if !errors.Is(err, ErrRefused) {
  			t.Errorf("the daemon could %s: %v", name, err)
  		}
  	}
  }

  // CheckIdentity is port49d's start check: the daemon refused the broker's
  // records and the broker allowed them pass; a daemon holding the broker's
  // role, and etcd with auth off, fail with ErrNotSeparated (Review Focus 6).
  func TestCheckIdentityRefusesADaemonWithTheBrokersReach(t *testing.T) {
  	const prefix = "/port49/"
  	srv := provisioned(t, prefix)
  	ctx := context.Background()
  	if err := openAs(t, srv, "port49-daemon", prefix).CheckIdentity(ctx, false); err != nil {
  		t.Fatalf("the daemon as itself: %v", err)
  	}
  	if err := openAs(t, srv, "port49-broker", prefix).CheckIdentity(ctx, true); err != nil {
  		t.Fatalf("the broker as itself: %v", err)
  	}
  	if err := openAs(t, srv, "port49-broker", prefix).CheckIdentity(ctx, false); !errors.Is(err, ErrNotSeparated) {
  		t.Fatalf("the broker's certificate as the daemon: %v", err)
  	}
  	open := etcdtest.Start(t, etcdtest.Options{TLS: true}) // auth never enabled
  	if err := openAs(t, open, "port49-daemon", prefix).CheckIdentity(ctx, false); !errors.Is(err, ErrNotSeparated) {
  		t.Fatalf("etcd with auth off: %v", err)
  	}
  }

  // Open dials two clients, the token pool and the context pool: one
  // connection each (design §12).
  func TestOpenDialsAPoolEach(t *testing.T) {
  	s, err := Open(Config{Endpoints: []string{etcdtest.Endpoint()}, Prefix: etcdtest.Prefix()})
  	if err != nil {
  		t.Fatal(err)
  	}
  	defer s.Close()
  	if s.tok == s.ctx || len(s.owned) != 2 || s.tokLeases == s.ctxLeases {
  		t.Fatal("Open shares one client between the pools")
  	}
  }
  ```

  Create `cmd/port49d/storeroles_test.go`:

  ```go
  package main

  import (
  	"bytes"
  	"os"
  	"path/filepath"
  	"strings"
  	"testing"
  	"time"

  	"github.com/rhwendt/port49/internal/testpki"
  )

  // port49d store-roles prints the etcdctl commands for the keyspace and
  // the two certificates' CNs, and touches nothing (spec §12).
  func TestStoreRolesPrintsTheCommands(t *testing.T) {
  	dir := t.TempDir()
  	now := time.Now()
  	ca, err := testpki.NewCA("ca", now.Add(-time.Hour), now.Add(time.Hour))
  	if err != nil {
  		t.Fatal(err)
  	}
  	write := func(name string, body []byte) string {
  		p := filepath.Join(dir, name)
  		if err := os.WriteFile(p, body, 0o600); err != nil {
  			t.Fatal(err)
  		}
  		return p
  	}
  	ids := map[string][2]string{}
  	for _, cn := range []string{"port49-daemon", "port49-broker"} {
  		c, err := ca.Issue(testpki.Leaf{CommonName: cn, Client: true, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
  		if err != nil {
  			t.Fatal(err)
  		}
  		cp, kp, _ := testpki.PEMs(c)
  		ids[cn] = [2]string{write(cn+".pem", cp), write(cn+"-key.pem", kp)}
  	}
  	cfg := writeStoreRolesConfig(t, dir, write("ca.pem", ca.PEM()), ids["port49-daemon"], ids["port49-broker"])
  	var out, errb bytes.Buffer
  	if code := storeRolesCmd([]string{"--config", cfg}, &out, &errb); code != 0 {
  		t.Fatalf("exit %d: %s", code, errb.String())
  	}
  	for _, want := range []string{
  		"etcdctl role add port49_daemon",
  		"etcdctl role grant-permission port49_daemon readwrite --prefix=true /port49/v1/t/",
  		"etcdctl role grant-permission port49_daemon read --prefix=true /port49/v1/rv/",
  		"etcdctl role grant-permission port49_broker readwrite --prefix=true /port49/v1/",
  		"etcdctl user add port49-daemon --no-password",
  		"etcdctl user grant-role port49-daemon port49_daemon",
  		"etcdctl user grant-role port49-broker port49_broker",
  	} {
  		if !strings.Contains(out.String(), want) {
  			t.Errorf("missing %q in:\n%s", want, out.String())
  		}
  	}
  	if strings.Contains(out.String(), "port49_daemon readwrite --prefix=true /port49/v1/id/") {
  		t.Error("the daemon is granted the idempotency records")
  	}
  }
  ```

  `writeStoreRolesConfig` writes a minimal valid `port49d.yaml` with a `broker:` block and the
  `store:` block naming those files. Build it from the helper `run_test.go`'s `writeRunConfig`
  uses (`brokerConfig(t, minimalPolicy)`), appending:

  ```go
  func writeStoreRolesConfig(t *testing.T, dir, ca string, d, b [2]string) string {
  	t.Helper()
  	base := writeRunConfig(t, brokerConfig(t, minimalPolicy).Broker)
  	raw, err := os.ReadFile(base)
  	if err != nil {
  		t.Fatal(err)
  	}
  	raw = append(raw, []byte("\nstore:\n  backend: etcd\n  etcd:\n    endpoints: [https://127.0.0.1:2379]\n"+
  		"    ca_file: "+ca+"\n    daemon: {cert_file: "+d[0]+", key_file: "+d[1]+"}\n"+
  		"    broker: {cert_file: "+b[0]+", key_file: "+b[1]+"}\n")...)
  	p := filepath.Join(dir, "port49d.yaml")
  	if err := os.WriteFile(p, raw, 0o600); err != nil {
  		t.Fatal(err)
  	}
  	return p
  }
  ```

  Run: `go test ./internal/store/etcd/ ./cmd/port49d/ -run 'Roles|Identity|APoolEach|StoreRoles' -count=1`
  Expected: FAIL to build.

- [ ] **Step 2: Two clients.** In `etcd.go`'s `Open`, replace the single dial with:

  ```go
  	tok, err := dial(c)
  	if err != nil {
  		return nil, err
  	}
  	ctxCli, err := dial(c)
  	if err != nil {
  		tok.Close()
  		return nil, err
  	}
  	s := newStore(tok, ctxCli, c)
  	s.owned = []*clientv3.Client{tok, ctxCli}
  	return s, nil
  ```

  Update the `Store` comment: the pools are two clients.

- [ ] **Step 3: The roles.** Create `internal/store/etcd/roles.go`:

  ```go
  package etcd

  import (
  	"context"
  	"errors"
  	"fmt"

  	clientv3 "go.etcd.io/etcd/client/v3"
  )

  // The roles port49 runs under on etcd (plan 7d, Ruling 10; spec §13,
  // decision 35). The daemon reads and writes what a login, an
  // authorization and accounting touch, and reads the marks a login
  // compares; it cannot write a mark, read or write an idempotency record
  // (which holds minted tokens), or write the token index. The broker holds
  // the keyspace.
  const (
  	RoleDaemon = "port49_daemon"
  	RoleBroker = "port49_broker"
  )

  // Grant is one role permission over [Key, RangeEnd).
  type Grant struct {
  	Role, Key, RangeEnd string
  	Write               bool
  }

  // Roles is every grant the two roles need for prefix's keyspace.
  func Roles(prefix string) []Grant {
  	k := newKeys(prefix)
  	var out []Grant
  	for _, fam := range []string{famToken, famReceipt, famReceiptBy, famContext, famIndexed, famByPrincipal,
  		famBySid, famByCert, famBlob, famMeta} {
  		p := k.family(fam)
  		out = append(out, Grant{Role: RoleDaemon, Key: p, RangeEnd: clientv3.GetPrefixRangeEnd(p), Write: true})
  	}
  	marks := k.family(famMark)
  	out = append(out, Grant{Role: RoleDaemon, Key: marks, RangeEnd: clientv3.GetPrefixRangeEnd(marks)})
  	out = append(out, Grant{Role: RoleBroker, Key: k.root, RangeEnd: clientv3.GetPrefixRangeEnd(k.root), Write: true})
  	return out
  }

  // ErrNotSeparated is the daemon's identity able to read what only the
  // broker's may: etcd's roles for port49 are not in force.
  var ErrNotSeparated = errors.New("etcd: the daemon's identity can read the broker's records")

  // CheckIdentity is port49d's start check that the roles are in force.
  // Both identities must read the contexts; the broker's must read the
  // idempotency records, and the daemon's must be refused them.
  func (s *Store) CheckIdentity(ctx context.Context, broker bool) error {
  	probe := func(fam string) error {
  		_, err := s.tok.Get(ctx, s.k.family(fam), clientv3.WithPrefix(), clientv3.WithLimit(1), clientv3.WithKeysOnly())
  		return unavailable(err)
  	}
  	if err := probe(famContext); err != nil {
  		return fmt.Errorf("reading %s: %w", s.k.family(famContext), err)
  	}
  	err := probe(famIdem)
  	switch {
  	case broker && err != nil:
  		return fmt.Errorf("reading %s: %w", s.k.family(famIdem), err)
  	case !broker && err == nil:
  		return fmt.Errorf("%w under %s", ErrNotSeparated, s.k.family(famIdem))
  	case !broker && !errors.Is(err, ErrRefused):
  		return err
  	}
  	return nil
  }
  ```

- [ ] **Step 4: `port49d store-roles`.** Create `cmd/port49d/storeroles.go`:

  ```go
  package main

  import (
  	"crypto/x509"
  	"encoding/pem"
  	"flag"
  	"fmt"
  	"io"
  	"os"

  	"github.com/rhwendt/port49/internal/config"
  	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
  )

  // storeRolesCmd is `port49d store-roles [--config FILE]` (spec §12; plan
  // 7d): it prints the etcdctl commands that create port49's two roles for
  // store.etcd.prefix and a user per component named by its certificate's
  // CN. It holds no etcd credential and changes nothing; etcd's root runs
  // the output, once.
  func storeRolesCmd(args []string, stdout, stderr io.Writer) int {
  	fs := flag.NewFlagSet("store-roles", flag.ContinueOnError)
  	fs.SetOutput(stderr)
  	cfgPath := fs.String("config", "/etc/port49/port49d.yaml", "path to port49d.yaml")
  	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
  		fmt.Fprintln(stderr, "usage: port49d store-roles [--config FILE]")
  		return 2
  	}
  	raw, err := config.ReadRegular(*cfgPath, config.MaxConfigSize)
  	if err != nil {
  		fmt.Fprintln(stderr, "port49d store-roles:", err)
  		return 1
  	}
  	sc, err := config.StoreOf(raw)
  	if err != nil {
  		fmt.Fprintln(stderr, "port49d store-roles:", err)
  		return 1
  	}
  	if sc.Etcd == nil {
  		fmt.Fprintln(stderr, "port49d store-roles: store.backend is not etcd; there are no roles to make")
  		return 1
  	}
  	users := map[string]string{}
  	for role, path := range map[string]string{etcdstore.RoleDaemon: sc.Etcd.Daemon.CertFile,
  		etcdstore.RoleBroker: sc.Etcd.Broker.CertFile} {
  		cn, err := commonName(path)
  		if err != nil {
  			fmt.Fprintf(stderr, "port49d store-roles: %s: %v\n", path, err)
  			return 1
  		}
  		users[role] = cn
  	}
  	if users[etcdstore.RoleDaemon] == users[etcdstore.RoleBroker] {
  		fmt.Fprintf(stderr, "port49d store-roles: store.etcd.daemon and store.etcd.broker are both CN %q: each "+
  			"component needs its own certificate (decision 35)\n", users[etcdstore.RoleDaemon])
  		return 1
  	}
  	fmt.Fprintf(stdout, "# port49 roles for keyspace %s (plan 7d). Run as etcd's root user, once.\n", sc.Etcd.Prefix)
  	made := map[string]bool{}
  	for _, g := range etcdstore.Roles(sc.Etcd.Prefix) {
  		if !made[g.Role] {
  			fmt.Fprintf(stdout, "etcdctl role add %s\n", g.Role)
  			made[g.Role] = true
  		}
  		perm := "read"
  		if g.Write {
  			perm = "readwrite"
  		}
  		fmt.Fprintf(stdout, "etcdctl role grant-permission %s %s --prefix=true %s\n", g.Role, perm, g.Key)
  	}
  	for _, role := range []string{etcdstore.RoleDaemon, etcdstore.RoleBroker} {
  		fmt.Fprintf(stdout, "etcdctl user add %s --no-password\n", users[role])
  		fmt.Fprintf(stdout, "etcdctl user grant-role %s %s\n", users[role], role)
  	}
  	fmt.Fprintln(stdout, "# then, if auth is not enabled yet: etcdctl user add root --no-password &&")
  	fmt.Fprintln(stdout, "#   etcdctl user grant-role root root && etcdctl auth enable")
  	return 0
  }

  // commonName is the subject CN of the first certificate in a PEM file:
  // the user etcd authenticates it as.
  func commonName(path string) (string, error) {
  	raw, err := os.ReadFile(path)
  	if err != nil {
  		return "", err
  	}
  	b, _ := pem.Decode(raw)
  	if b == nil || b.Type != "CERTIFICATE" {
  		return "", fmt.Errorf("no certificate")
  	}
  	c, err := x509.ParseCertificate(b.Bytes)
  	if err != nil {
  		return "", err
  	}
  	if c.Subject.CommonName == "" {
  		return "", fmt.Errorf("the certificate has no CN, which etcd needs as the user name")
  	}
  	return c.Subject.CommonName, nil
  }
  ```

  In `main.go`'s `main`, beside the `init-revocations` dispatch:

  ```go
  	if len(os.Args) > 1 && os.Args[1] == "store-roles" {
  		os.Exit(storeRolesCmd(os.Args[2:], os.Stdout, os.Stderr))
  	}
  ```

  Extend the usage line to name it: `port49d [--config FILE], port49d init-revocations
  [--config FILE], or port49d store-roles [--config FILE] (a subcommand comes first)`.

  `etcdctl role grant-permission --prefix=true` takes the key and grants its prefix range, which
  is what `Roles`' `RangeEnd` says. The printed form drops the range end because `--prefix`
  implies it.

- [ ] **Step 5: Run.**

  Run: `go test ./internal/store/etcd/ ./cmd/port49d/ -count=1`
  Expected: PASS. The roles tests start two TLS members each, a few seconds in all. If a daemon
  write the test expects to be refused succeeds, the roles are wrong, so fix `Roles`. If one it
  expects to work is refused, a family is missing from the daemon's grants. Name which in the
  report.

- [ ] **Step 6: Commit.**

  ```bash
  gofmt -w internal/store/etcd cmd/port49d
  make build && make test && make vet
  git add internal/store/etcd/etcd.go internal/store/etcd/roles.go internal/store/etcd/roles_test.go \
    cmd/port49d/storeroles.go cmd/port49d/storeroles_test.go cmd/port49d/main.go
  git commit -m "feat(store/etcd): a pool each, an identity each, and port49d store-roles

  Open dials the token and context pools as two connections. The daemon
  and the broker each authenticate by their own certificate under
  port49_daemon and port49_broker: the daemon cannot write or lift a mark,
  touch an idempotency record, or write the token index. CheckIdentity is
  the start check; port49d store-roles prints the etcdctl commands (design
  §17; decision 35).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 12: port49d runs on etcd: the hold, the start, the purge, and live sessions across a restart

**Files:**
- Create: `internal/store/etcd/meta.go` (`Hold`)
- Test: `internal/store/etcd/meta_test.go`
- Create: `cmd/port49d/store.go`
- Modify: `cmd/port49d/main.go`
- Modify: `internal/broker/broker.go` (`SupersededAll`), `internal/broker/refresh.go` (`RefreshAtStart`)
- Test: `internal/broker/refresh_test.go`, `cmd/port49d/store_e2e_test.go`
- Modify: `internal/daemon/metrics/metrics.go` (`StoreKeyspaceHeld`)

**Interfaces:**
- Consumes: everything from Tasks 5–11.
- Produces:
  - `func (s *etcd.Store) Hold(ctx context.Context, ttl time.Duration, who string, waiting func(holder string)) (lost <-chan struct{}, release func(), err error)`
  - `type stores struct { daemon, broker store.Store; etcd *etcdstore.Store; persistent bool; lost <-chan struct{}; close func() }`,
    `func openStores(ctx context.Context, cfg config.Config, keys crypt.Keys, m *metrics.Metrics, out io.Writer) (stores, error)`,
    `func sweepLoop(ctx context.Context, s *etcdstore.Store, every time.Duration, out io.Writer)` in
    `cmd/port49d`
  - `Broker.SupersededAll time.Time`; `func (b *Broker) RefreshAtStart(ctx context.Context) (RefreshReport, error)`
  - `Metrics.StoreKeyspaceHeld` (`port49_store_keyspace_held`)

- [ ] **Step 1: The hold's failing test.** Create `internal/store/etcd/meta_test.go`:

  ```go
  package etcd

  import (
  	"context"
  	"strings"
  	"testing"
  	"time"

  	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
  )

  // One port49d per keyspace: a second Hold waits, saying who holds it,
  // until the first lets go; and a hold whose store stops answering is lost
  // within its TTL (Ruling 11; Review Focus 4).
  func TestHoldIsOnePerKeyspaceAndLapses(t *testing.T) {
  	srv := etcdtest.Start(t, etcdtest.Options{})
  	proxy := etcdtest.NewProxy(t, strings.TrimPrefix(srv.Endpoint, "http://"))
  	prefix := etcdtest.Prefix()
  	open := func(ep string) *Store {
  		s, err := Open(Config{Endpoints: []string{ep}, Prefix: prefix})
  		if err != nil {
  			t.Fatal(err)
  		}
  		t.Cleanup(func() { s.Close() })
  		return s
  	}
  	first, second := open("http://"+proxy.Addr()), open(srv.Endpoint)
  	ctx := context.Background()
  	lost, release, err := first.Hold(ctx, 5*time.Second, "port49d one", func(string) {})
  	if err != nil {
  		t.Fatal(err)
  	}
  	waited := make(chan string, 4)
  	got := make(chan error, 1)
  	go func() {
  		_, rel, err := second.Hold(ctx, 5*time.Second, "port49d two", func(h string) { waited <- h })
  		if err == nil {
  			defer rel()
  		}
  		got <- err
  	}()
  	select {
  	case h := <-waited:
  		if h != "port49d one" {
  			t.Fatalf("waiting on %q", h)
  		}
  	case err := <-got:
  		t.Fatalf("the second took a held keyspace: %v", err)
  	case <-time.After(10 * time.Second):
  		t.Fatal("the second never said it was waiting")
  	}
  	proxy.Hang(true) // the first's store stops answering
  	select {
  	case <-lost:
  	case <-time.After(15 * time.Second):
  		t.Fatal("the first's hold did not lapse")
  	}
  	if err := <-got; err != nil {
  		t.Fatalf("the second, once the first lapsed: %v", err)
  	}
  	proxy.Hang(false)
  	release()
  }
  ```

  Run: `go test ./internal/store/etcd/ -run TestHold -count=1`
  Expected: FAIL to build (`Hold` undefined).

- [ ] **Step 2: The hold.** Create `internal/store/etcd/meta.go`:

  ```go
  package etcd

  import (
  	"context"
  	"encoding/json"
  	"errors"
  	"time"

  	clientv3 "go.etcd.io/etcd/client/v3"
  	"go.etcd.io/etcd/client/v3/concurrency"
  )

  type holderRec struct {
  	Who string `json:"who"`
  }

  // Hold takes the keyspace for one port49d (plan 7d, Ruling 11): a lock
  // under meta/hold on an etcd session lease of ttl, with who written
  // beside it under meta/holder. While another holds it, Hold waits,
  // telling waiting the holder's who every 30s, until ctx ends. lost is
  // closed when the lease lapses, which is the store not answering for ttl;
  // release lets go.
  func (s *Store) Hold(ctx context.Context, ttl time.Duration, who string, waiting func(holder string)) (<-chan struct{}, func(), error) {
  	sess, err := concurrency.NewSession(s.ctx, concurrency.WithTTL(int(ttl/time.Second)), concurrency.WithContext(ctx))
  	if err != nil {
  		return nil, nil, unavailable(err)
  	}
  	mu := concurrency.NewMutex(sess, s.k.meta("hold"))
  	var said time.Time
  	for {
  		err := mu.TryLock(ctx)
  		if err == nil {
  			break
  		}
  		if !errors.Is(err, concurrency.ErrLocked) {
  			sess.Close()
  			return nil, nil, unavailable(err)
  		}
  		if time.Since(said) >= 30*time.Second {
  			var h holderRec
  			if _, _, err := getJSON(ctx, s.ctx, s.k.meta("holder"), &h); err == nil {
  				waiting(h.Who)
  			}
  			said = time.Now()
  		}
  		select {
  		case <-ctx.Done():
  			sess.Close()
  			return nil, nil, ctx.Err()
  		case <-time.After(time.Second):
  		}
  	}
  	body, err := json.Marshal(holderRec{Who: who})
  	if err != nil {
  		sess.Close()
  		return nil, nil, err
  	}
  	if _, err := s.ctx.Put(ctx, s.k.meta("holder"), string(body), clientv3.WithLease(sess.Lease())); err != nil {
  		sess.Close()
  		return nil, nil, unavailable(err)
  	}
  	return sess.Done(), func() {
  		uctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
  		defer cancel()
  		mu.Unlock(uctx)
  		sess.Close()
  	}, nil
  }
  ```

  `concurrency.WithContext(ctx)` ties the session's keepalive to ctx. Check the option's name in
  v3.6.15's `concurrency` package. If it differs, use what the package offers, as Global
  Constraints allow. A session whose lease the client cannot keep alive for its TTL closes
  `Done()`, which is the lapse.

  Run: `go test ./internal/store/etcd/ -run TestHold -count=1` — PASS.

- [ ] **Step 3: The broker's start refresh, failing first.** In `internal/broker/refresh_test.go`,
  add:

  ```go
  // RefreshAtStart carries the policy in force into a context a persistent
  // store kept across a restart, whatever bundle it was written under: a
  // narrowing reaches it before TACACS+ binds, and a context whose device
  // the inventory no longer names is revoked (plan 7d, Ruling 12).
  func TestRefreshAtStartCarriesThePolicyIntoKeptContexts(t *testing.T) {
  	f := newFixtureWithPolicy(t, 8, sharedPolicy)
  	ctx := context.Background()
  	f.liveContext(t, "leaf1", "alice", alicePrincipal, "")
  	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
  	before, err := f.st.GetContext(ctx, k)
  	if err != nil {
  		t.Fatal(err)
  	}
  	// The kept context names a blob the policy in force would not write.
  	if err := f.st.SetContextPolicy(ctx, k, before.PolicyRev, store.ContextPolicy{BlobHash: "sha256:from-before",
  		MaxPrivilege: before.MaxPrivilege, Enable: before.Enable}); err != nil {
  		t.Fatal(err)
  	}
  	rep, err := f.b.RefreshAtStart(ctx)
  	if err != nil {
  		t.Fatal(err)
  	}
  	got, err := f.st.GetContext(ctx, k)
  	if err != nil || got.BlobHash == "sha256:from-before" {
  		t.Fatalf("the kept context was not carried onto the policy in force: %+v %v (report %+v)", got, err, rep)
  	}
  }
  ```

  The fixture names (`newFixtureWithPolicy`, `liveContext`, `sharedPolicy`, `alicePrincipal`,
  `f.st`, `f.b`) are 7c's `revokeown_test.go`'s. `liveContext`'s fifth argument is a sid. Read
  its signature first.

  In `internal/broker/broker.go`, add to `Broker` beside `superseded`'s comment block:

  ```go
  	// SupersededAll is when port49d started on a store that persists (plan
  	// 7d): every unspent token was purged then, so every key is superseded
  	// at least then, and an idempotent replay of a mint from before is
  	// minted again, never answered with a token that no longer exists.
  	// Zero on the memory store.
  	SupersededAll time.Time
  ```

  In `mintOne`, replace `supersededAt := b.superseded[store.TokenKey{NAS: name, Username:
  res.Username}]` with:

  ```go
  	supersededAt := b.superseded[store.TokenKey{NAS: name, Username: res.Username}]
  	if b.SupersededAll.After(supersededAt) {
  		supersededAt = b.SupersededAll
  	}
  ```

  In `refresh.go`, after `Refresh`, add:

  ```go
  // RefreshAtStart carries the policy in force into every live context a
  // persistent store kept across a restart (plan 7d; spec §13, decision
  // 35). No policy those contexts were written under is one this port49d
  // loaded, so none is the same source, and every context is judged against
  // the policy in force; the tokens are already purged, so nothing is
  // superseded here. port49d runs it before TACACS+ binds, and again while
  // it returns an error.
  func (b *Broker) RefreshAtStart(ctx context.Context) (RefreshReport, error) {
  	var rep RefreshReport
  	rep.At = b.Now()
  	err := b.refreshContexts(ctx, b.Policy.Load(), nil, rep.At, &rep, false)
  	return rep, err
  }
  ```

  Run: `go test ./internal/broker/ -run TestRefreshAtStart -count=1` — PASS. A test that mints
  with `SupersededAll` set and replays is added in Step 6's end-to-end test, where it is
  observable.

- [ ] **Step 4: The metric.** In `metrics.go`, add:

  ```go
  	// StoreKeyspaceHeld is 1 while this port49d holds its keyspace on etcd
  	// (plan 7d): 0 while it waits for another, and alarmed when port49d runs
  	// with it 0.
  	StoreKeyspaceHeld prometheus.Gauge
  ```

  with `prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_store_keyspace_held", Help: "1 while
  this port49d holds its keyspace on etcd."})`, registered.

- [ ] **Step 5: `openStores`.** Create `cmd/port49d/store.go`:

  ```go
  package main

  import (
  	"context"
  	"crypto/tls"
  	"crypto/x509"
  	"errors"
  	"fmt"
  	"io"
  	"os"
  	"strings"
  	"time"

  	"github.com/rhwendt/port49/internal/config"
  	"github.com/rhwendt/port49/internal/daemon/metrics"
  	"github.com/rhwendt/port49/internal/store"
  	"github.com/rhwendt/port49/internal/store/crypt"
  	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
  	"github.com/rhwendt/port49/internal/store/guard"
  	"github.com/rhwendt/port49/internal/store/memory"
  )

  // stores is what port49d's components read and write through (plan 7d):
  // on etcd the daemon's and the broker's, each its own identity, guard and
  // sealing layer; on memory one store for both.
  type stores struct {
  	daemon, broker store.Store
  	// etcd is the daemon's backend: the hold, the sweep and the seal
  	// keys go through it. Nil on memory.
  	etcd       *etcdstore.Store
  	persistent bool
  	// lost is closed when this port49d loses its hold on the keyspace;
  	// nil on memory, where nothing is lost.
  	lost  <-chan struct{}
  	close func()
  }

  // errHoldLost ends run: the store has not answered for hold_ttl, and
  // another port49d may hold the keyspace now (Ruling 11).
  var errHoldLost = errors.New("store: lost this port49d's hold on its keyspace")

  // openStores builds the stores cfg names. On etcd it waits for the store
  // with every listener still closed (none is bound yet), up to
  // start_timeout; checks the roles; and takes the hold, waiting for
  // another port49d to let go. It says each on out.
  func openStores(ctx context.Context, cfg config.Config, keys crypt.Keys, m *metrics.Metrics, out io.Writer) (stores, error) {
  	if cfg.Store.Backend != config.BackendEtcd {
  		st := crypt.Wrap(memory.New(time.Now), keys, m.CryptOpenFailures)
  		return stores{daemon: st, broker: st, close: func() {}}, nil
  	}
  	e := cfg.Store.Etcd
  	pool, err := caPool(e.CAFile)
  	if err != nil {
  		return stores{}, fmt.Errorf("store.etcd.ca_file: %w", err)
  	}
  	open := func(name string, id config.EtcdIdentity) (*etcdstore.Store, error) {
  		pair, err := tls.LoadX509KeyPair(id.CertFile, id.KeyFile)
  		if err != nil {
  			return nil, fmt.Errorf("store.etcd.%s: %w", name, err)
  		}
  		return etcdstore.Open(etcdstore.Config{Endpoints: e.Endpoints, Prefix: e.Prefix, LeaseGrace: e.LeaseGrace,
  			TLS: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}})
  	}
  	deadline := time.Now().Add(e.StartTimeout)
  	var d *etcdstore.Store
  	for {
  		d, err = open("daemon", e.Daemon)
  		if err == nil {
  			pctx, cancel := context.WithTimeout(ctx, e.CallTimeout*4)
  			err = d.Ping(pctx)
  			cancel()
  			if err == nil {
  				break
  			}
  			d.Close()
  		}
  		if !errors.Is(err, store.ErrUnavailable) {
  			return stores{}, fmt.Errorf("store: etcd at %s: %w", strings.Join(e.Endpoints, ", "), err)
  		}
  		if time.Now().After(deadline) {
  			return stores{}, fmt.Errorf("store: etcd at %s did not answer within store.etcd.start_timeout (%v); not "+
  				"starting", strings.Join(e.Endpoints, ", "), e.StartTimeout)
  		}
  		fmt.Fprintf(out, "port49d: store: etcd at %s not answering (%v); the listeners stay closed; waiting up to %v\n",
  			strings.Join(e.Endpoints, ", "), err, e.StartTimeout)
  		select {
  		case <-ctx.Done():
  			return stores{}, ctx.Err()
  		case <-time.After(5 * time.Second):
  		}
  	}
  	b, err := open("broker", *e.Broker)
  	if err != nil {
  		d.Close()
  		return stores{}, err
  	}
  	closeAll := func() { b.Close(); d.Close() }
  	if e.Roles == config.RolesUnenforced {
  		fmt.Fprintln(out, "port49d: store.etcd.roles: unenforced: the daemon and the broker are not separated on etcd; "+
  			"a stolen daemon key can lift revocations")
  	} else if err := checkRoles(ctx, d, b, e); err != nil {
  		closeAll()
  		return stores{}, err
  	}
  	host, _ := os.Hostname()
  	who := fmt.Sprintf("port49d on %s (pid %d, since %s)", host, os.Getpid(), time.Now().UTC().Format(time.RFC3339))
  	m.StoreKeyspaceHeld.Set(0)
  	lost, release, err := d.Hold(ctx, e.HoldTTL, who, func(holder string) {
  		fmt.Fprintf(out, "port49d: store: keyspace %s is held by %s; waiting, with the listeners closed: one port49d "+
  			"per keyspace until plan 7e\n", e.Prefix, holder)
  	})
  	if err != nil {
  		closeAll()
  		return stores{}, fmt.Errorf("store: taking keyspace %s: %w", e.Prefix, err)
  	}
  	m.StoreKeyspaceHeld.Set(1)
  	gc := func(component string) guard.Config {
  		return guard.Config{Component: component, CallTimeout: e.CallTimeout,
  			MaxInFlight: map[guard.Pool]int{guard.Token: e.MaxInFlight.Token, guard.Context: e.MaxInFlight.Context},
  			Failures:    e.Breaker.Failures, OpenFor: e.Breaker.OpenFor, Metrics: m.StoreGuard(),
  			Say:         func(l string) { fmt.Fprintln(out, l) }}
  	}
  	return stores{
  		daemon:     crypt.Wrap(guard.Wrap(d, gc("daemon")), keys, m.CryptOpenFailures),
  		broker:     crypt.Wrap(guard.Wrap(b, gc("broker")), keys, m.CryptOpenFailures),
  		etcd:       d,
  		persistent: true,
  		lost:       lost,
  		close:      func() { release(); m.StoreKeyspaceHeld.Set(0); closeAll() },
  	}, nil
  }

  // checkRoles is Ruling 10's start check, its refusal naming the identity
  // and the fix.
  func checkRoles(ctx context.Context, d, b *etcdstore.Store, e *config.EtcdConfig) error {
  	cctx, cancel := context.WithTimeout(ctx, 4*e.CallTimeout)
  	defer cancel()
  	if err := d.CheckIdentity(cctx, false); err != nil {
  		cn, _ := commonName(e.Daemon.CertFile)
  		if errors.Is(err, etcdstore.ErrNotSeparated) {
  			return fmt.Errorf("store.etcd: the daemon's identity (CN=%s) can read the broker's idempotency records "+
  				"under %sv1/id/: etcd's roles for port49 are not in force (auth disabled, or that user holds the "+
  				"broker's or root's role); run 'port49d store-roles --config …' and apply its output as etcd's root, "+
  				"or set store.etcd.roles: unenforced to run without them", cn, e.Prefix)
  		}
  		return fmt.Errorf("store.etcd: the daemon's identity (CN=%s): %w", cn, err)
  	}
  	if err := b.CheckIdentity(cctx, true); err != nil {
  		cn, _ := commonName(e.Broker.CertFile)
  		return fmt.Errorf("store.etcd: the broker's identity (CN=%s): %w; apply 'port49d store-roles' output", cn, err)
  	}
  	return nil
  }

  func caPool(path string) (*x509.CertPool, error) {
  	raw, err := os.ReadFile(path)
  	if err != nil {
  		return nil, err
  	}
  	p := x509.NewCertPool()
  	if !p.AppendCertsFromPEM(raw) {
  		return nil, errors.New("no certificate in it")
  	}
  	return p, nil
  }

  // sweepLoop runs the index sweep every interval (Ruling 6), saying only a
  // failure.
  func sweepLoop(ctx context.Context, s *etcdstore.Store, every time.Duration, out io.Writer) {
  	t := time.NewTicker(every)
  	defer t.Stop()
  	for {
  		select {
  		case <-ctx.Done():
  			return
  		case <-t.C:
  		}
  		sctx, cancel := context.WithTimeout(ctx, every/2)
  		if _, _, err := s.Sweep(sctx); err != nil && ctx.Err() == nil {
  			fmt.Fprintf(out, "port49d: store: the index sweep did not finish (%v); it runs again in %v\n", err, every)
  		}
  		cancel()
  	}
  }
  ```

- [ ] **Step 6: The end-to-end tests, failing.** Create `cmd/port49d/store_e2e_test.go`:

  ```go
  package main

  import (
  	"context"
  	"fmt"
  	"os"
  	"path/filepath"
  	"regexp"
  	"strings"
  	"testing"
  	"time"

  	"github.com/rhwendt/port49/internal/store/etcd"
  	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
  	"github.com/rhwendt/port49/internal/tacacs/wire"
  )

  // etcdRun is a port49d config on a TLS etcd member with port49's roles,
  // through a proxy the test can hang: the run_test.go config with a store:
  // block appended.
  func etcdRun(t *testing.T) (cfgPath, pkiDir string, proxy *etcdtest.Proxy) {
  	t.Helper()
  	srv := etcdtest.Start(t, etcdtest.Options{TLS: true})
  	var grants []etcdtest.Grant
  	for _, g := range etcd.Roles("/port49/") {
  		grants = append(grants, etcdtest.Grant{Role: g.Role, Key: g.Key, RangeEnd: g.RangeEnd, Write: g.Write})
  	}
  	srv.EnableAuth(t, grants, map[string][]string{"port49-daemon": {etcd.RoleDaemon}, "port49-broker": {etcd.RoleBroker}})
  	proxy = etcdtest.NewProxy(t, strings.TrimPrefix(srv.Endpoint, "https://"))
  	dc, dk := srv.ClientFiles(t, "port49-daemon")
  	bc, bk := srv.ClientFiles(t, "port49-broker")
  	b := brokerConfig(t, minimalPolicy).Broker
  	cfgPath = writeRunConfig(t, b)
  	raw, err := os.ReadFile(cfgPath)
  	if err != nil {
  		t.Fatal(err)
  	}
  	raw = append(raw, []byte(fmt.Sprintf("\nstore:\n  backend: etcd\n  packet_deadline: 1s\n  etcd:\n"+
  		"    endpoints: [https://%s]\n    ca_file: %s\n    daemon: {cert_file: %s, key_file: %s}\n"+
  		"    broker: {cert_file: %s, key_file: %s}\n    call_timeout: 200ms\n    hold_ttl: 5s\n"+
  		"    breaker: {failures: 3, open_for: 2s}\n",
  		proxy.Addr(), filepath.Join(srv.Dir, "ca.pem"), dc, dk, bc, bk))...)
  	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
  		t.Fatal(err)
  	}
  	return cfgPath, filepath.Dir(b.TLSCertFile), proxy
  }

  // startRun runs port49d on cfgPath until the test ends or stop is called,
  // and returns its TACACS+ and broker addresses.
  func startRun(t *testing.T, cfgPath string, out *syncBuffer) (tacacs, brokerAddr string, stop func() error) {
  	t.Helper()
  	ctx, cancel := context.WithCancel(context.Background())
  	done := make(chan error, 1)
  	go func() { done <- run(ctx, cfgPath) }()
  	stop = func() error {
  		cancel()
  		select {
  		case err := <-done:
  			return err
  		case <-time.After(15 * time.Second):
  			return fmt.Errorf("port49d did not stop")
  		}
  	}
  	t.Cleanup(func() { stop() })
  	waitFor(t, out, "port49d: broker listening on ")
  	addrs := regexp.MustCompile(`listening on (127\.0\.0\.1:\d+)`).FindAllStringSubmatch(out.String(), -1)
  	return addrs[len(addrs)-2][1], addrs[len(addrs)-1][1], stop
  }

  // A live session survives a port49d restart on etcd; a token minted
  // before it does not (Ruling 12; spec §14, "A restart on etcd").
  func TestRunOnEtcdKeepsALoginAcrossARestart(t *testing.T) {
  	var out, log syncBuffer
  	e, o := stderr, stdout
  	t.Cleanup(func() { stderr, stdout = e, o })
  	stderr, stdout = &out, &log
  	cfgPath, pkiDir, _ := etcdRun(t)

  	tacacs, brokerAddr, stop := startRun(t, cfgPath, &out)
  	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
  	if st := dev.login("alice", mint(t, brokerAddr, pkiDir, "leaf1")); st != wire.AuthenStatusPass {
  		t.Fatalf("login: %d; log %s", st, log.String())
  	}
  	spare := mint(t, brokerAddr, pkiDir, "leaf1")
  	if !dev.permits("alice", "configure") {
  		t.Fatal("before the restart")
  	}
  	if err := stop(); err != nil {
  		t.Fatal(err)
  	}

  	tacacs, _, _ = startRun(t, cfgPath, &out)
  	waitFor(t, &out, "unspent token(s) from before this start")
  	waitFor(t, &out, "live context(s) carried onto the policy in force")
  	dev = tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
  	if !dev.permits("alice", "configure") {
  		t.Fatalf("after the restart the session's next command was not answered from its context; log %s", log.String())
  	}
  	if st := dev.login("alice", spare); st == wire.AuthenStatusPass {
  		t.Fatal("a token minted before the restart logged in")
  	}
  }

  // A second port49d on the keyspace binds no listener while the first
  // holds it (Review Focus 4).
  func TestASecondPort49dWaitsForTheKeyspace(t *testing.T) {
  	var out, log syncBuffer
  	e, o := stderr, stdout
  	t.Cleanup(func() { stderr, stdout = e, o })
  	stderr, stdout = &out, &log
  	cfgPath, _, _ := etcdRun(t)
  	startRun(t, cfgPath, &out)
  	n := strings.Count(out.String(), "listening on ")

  	// The same file: a copy-pasted config is the case. The second waits for
  	// the keyspace before it binds anything or touches the revocations file.
  	ctx, cancel := context.WithCancel(context.Background())
  	defer cancel()
  	go run(ctx, cfgPath)
  	waitFor(t, &out, "is held by port49d on")
  	time.Sleep(2 * time.Second)
  	if got := strings.Count(out.String(), "listening on "); got != n {
  		t.Fatalf("the second port49d bound a listener while the first held the keyspace:\n%s", out.String())
  	}
  }

  // A store that hangs in the middle of a login: the device hears ERROR
  // within store.packet_deadline, never silence (Review Focus 1). Then the
  // hold lapses and port49d stops, saying why (Review Focus 4).
  func TestAHungStoreAnswersWithinThePacketDeadline(t *testing.T) {
  	var out, log syncBuffer
  	e, o := stderr, stdout
  	t.Cleanup(func() { stderr, stdout = e, o })
  	stderr, stdout = &out, &log
  	cfgPath, pkiDir, proxy := etcdRun(t)
  	ctx, cancel := context.WithCancel(context.Background())
  	defer cancel()
  	done := make(chan error, 1)
  	go func() { done <- run(ctx, cfgPath) }()
  	waitFor(t, &out, "port49d: broker listening on ")
  	addrs := regexp.MustCompile(`listening on (127\.0\.0\.1:\d+)`).FindAllStringSubmatch(out.String(), -1)
  	tok := mint(t, addrs[1][1], pkiDir, "leaf1")
  	dev := tacacsClient{t: t, addr: addrs[0][1], key: []byte("run-test-secret")}

  	proxy.Hang(true)
  	start := time.Now()
  	st := dev.login("alice", tok)
  	if took := time.Since(start); st != wire.AuthenStatusError || took > 1500*time.Millisecond {
  		t.Fatalf("a login on a hung store: status %d after %v", st, took)
  	}
  	select {
  	case err := <-done:
  		if err == nil || !strings.Contains(err.Error(), "lost this port49d's hold") {
  			t.Fatalf("port49d stopped with %v", err)
  		}
  	case <-time.After(20 * time.Second):
  		t.Fatal("port49d did not stop after its hold lapsed")
  	}
  	if !strings.Contains(out.String(), "stopping so that devices use their local method") {
  		t.Fatalf("stderr: %s", out.String())
  	}
  }

  ```

  Add `TestMain` to `cmd/port49d` only if the package has none: `func TestMain(m *testing.M) {
  os.Exit(etcdtest.Main(m)) }`, in a new `cmd/port49d/main_etcd_test.go`. If the package already
  has a `TestMain`, call `etcdtest.Main` from it instead. These tests start their own members,
  so the shared one is only needed if another test uses `etcdtest.Endpoint()`. If none does, skip
  `TestMain`. If you create `main_etcd_test.go`, name it in Step 8's `git add`.

  The run-test helpers' exact names (`brokerConfig`, `minimalPolicy`, `writeRunConfig`, `mint`,
  `tacacsClient`, `waitFor`, `syncBuffer`, the `stderr`/`stdout` package vars) are
  `run_test.go`'s. Read it first and use them as they are. `writeRunConfig` listens on
  `127.0.0.1:0` for TACACS+, the broker and metrics, so a second run of the same file binds other
  ports. Read the file and confirm it. If it names fixed ports, give the second run a copy with
  `:0`.

  Run: `go test ./cmd/port49d/ -run 'OnEtcd|SecondPort49d|HungStore' -count=1`
  Expected: FAIL. port49d runs on memory regardless of `store:`, so the restart loses the session
  and the second port49d binds.

- [ ] **Step 7: `run` on the stores.** In `cmd/port49d/main.go`'s `run`:
  1. Make the context cancellable with a cause, right after `cfg, err := config.Load(cfgPath)`
     succeeds:

     ```go
     	parent, cancelRun := context.WithCancelCause(parent)
     	defer cancelRun(nil)
     ```

     `run` derives `ctx, cancel := context.WithCancel(parent)` a few lines further on
     (`main.go:524` at `9cefbba`), so the hold's loss cancels everything `run` started.
  2. Replace `st := crypt.Wrap(memory.New(time.Now), keys, m.CryptOpenFailures)` with:

     ```go
     	// The stores (plan 7d): on etcd, waited for with every listener still
     	// closed, the roles checked, the keyspace held; on memory, one store.
     	sts, err := openStores(ctx, cfg, keys, m, stderr)
     	if err != nil {
     		return err
     	}
     	defer sts.close()
     	if sts.lost != nil {
     		go func() {
     			select {
     			case <-sts.lost:
     				fmt.Fprintf(stderr, "port49d: store: lost this port49d's hold on keyspace %s (no answer from etcd "+
     					"for %v); stopping so that devices use their local method; the service manager restarts "+
     					"port49d, which waits for etcd\n", cfg.Store.Etcd.Prefix, cfg.Store.Etcd.HoldTTL)
     				cancelRun(errHoldLost)
     			case <-ctx.Done():
     			}
     		}()
     		go sweepLoop(ctx, sts.etcd, cfg.Store.Etcd.SweepInterval, stderr)
     	}
     	st := sts.broker
     ```

     `openStores` is called after the metrics listener is up, where `st` was built, so the
     metrics show `port49_store_keyspace_held` 0 while port49d waits. The TACACS+ and broker
     listeners bind later in `run`, so nothing listens while it waits.
  3. The daemon's handlers read the daemon's store. Replace `authz := &author.Engine{Store: st,
     Metrics: m}` with `authz := &author.Engine{Store: sts.daemon, Metrics: m}`, and
     `handlerStore := labHandlerStore(st, fault)` with `handlerStore := labHandlerStore(sts.daemon,
     fault)`. The minter, the session manager, the broker, the lab seeds and the revocations stay
     on `st`, the broker's.
  4. After the revocations are restored (the block ending `fmt.Fprintf(stderr, "port49d: broker:
     %d revocation(s) in force from %s\n", …)`), add:

     ```go
     	if sts.persistent {
     		if err := startOnPersistentStore(ctx, brk, st, cfg, &marks); err != nil {
     			stopSpool()
     			<-spoolDone
     			return err
     		}
     	}
     ```

     and, in `store.go`:

     ```go
     // startOnPersistentStore is a start on etcd after the marks are restored
     // (Ruling 12; Ruling 13): the store's marks the file lacked are put in
     // force and saved to it, every unspent token is purged and every key
     // superseded, and the policy in force is carried into every live context
     // the store kept, retried every 5s while the store errs. Nothing listens
     // until it returns.
     func startOnPersistentStore(ctx context.Context, brk *broker.Broker, st store.Store, cfg config.Config,
     	marks *[]store.Revocation) error {
     	all, err := st.ListRevocations(ctx)
     	if err != nil {
     		return fmt.Errorf("store: listing the revocations in force: %w", err)
     	}
     	if extra := len(all) - len(*marks); extra > 0 {
     		fmt.Fprintf(stderr, "port49d: broker: %d revocation(s) in force from the store that %s lacked; saving them "+
     			"to it\n", extra, cfg.Broker.RevocationsFile)
     		if err := brk.Persist(ctx); err != nil {
     			fmt.Fprintf(stderr, "port49d: broker: saving them: %v; port49_revocations_file_failed is 1\n", err)
     		}
     	}
     	*marks = all
     	brk.SupersededAll = brk.Now()
     	n, err := st.PurgeTokens(ctx)
     	if err != nil {
     		return fmt.Errorf("store: purging the tokens from before this start: %w", err)
     	}
     	fmt.Fprintf(stderr, "port49d: store: purged %d unspent token(s) from before this start (run 'port49 token' "+
     		"again)\n", n)
     	for {
     		rep, err := brk.RefreshAtStart(ctx)
     		if err == nil {
     			fmt.Fprintf(stderr, "port49d: store: %d live context(s) carried onto the policy in force (bundle %s) "+
     				"before serving\n", rep.Contexts(), brk.Policy.Load().Bundle)
     			return nil
     		}
     		fmt.Fprintf(stderr, "port49d: store: carrying the policy in force into the live contexts: %v; the "+
     			"listeners stay closed; trying again in 5s\n", err)
     		select {
     		case <-ctx.Done():
     			return ctx.Err()
     		case <-time.After(5 * time.Second):
     		}
     	}
     }
     ```

     Add to `refresh.go`:

     ```go
     // Contexts is how many live contexts the pass judged.
     func (r RefreshReport) Contexts() int {
     	return r.Updated + r.Unchanged + r.Revoked + r.Quarantined + r.Failed
     }
     ```

     The `stderr` used here is the package variable `run`'s helpers already write to.
  5. At the end of `run`, where it returns, return the cause when the hold was lost:

     ```go
     	if c := context.Cause(parent); errors.Is(c, errHoldLost) {
     		return c
     	}
     ```

     Place it before `run`'s final `return nil` (or the equivalent). `main` prints it as
     `port49d: store: lost this port49d's hold on its keyspace` and exits 1. The line before it
     says why.

  Run: `go test ./cmd/port49d/ -count=1`
  Expected: PASS: the three end-to-end tests, and every existing test (memory, unchanged). The
  `memory` import moves to `store.go`; drop it from `main.go` if the compiler says it is unused.

- [ ] **Step 8: Commit.**

  ```bash
  gofmt -w cmd/port49d internal/store/etcd internal/broker internal/daemon/metrics
  make build && make test && make vet
  git add internal/store/etcd/meta.go internal/store/etcd/meta_test.go cmd/port49d/store.go \
    cmd/port49d/store_e2e_test.go cmd/port49d/main.go internal/broker/broker.go internal/broker/refresh.go \
    internal/broker/refresh_test.go internal/daemon/metrics/metrics.go
  git commit -m "feat(port49d): run on etcd: one per keyspace, sessions across a restart

  With store.backend etcd, port49d waits for etcd with its listeners
  closed, checks its roles, holds the keyspace (a second port49d waits),
  restores the marks as a union with the store's, purges unspent tokens
  and supersedes every key, carries the policy in force into every kept
  context, and only then binds TACACS+. A port49d that loses its hold
  stops, so devices use their local method. The daemon's handlers read
  through the daemon's identity, the broker through its own (plan 7d;
  decision 35).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 13: The crypt alarm: a record that will not open names its key, and a start says when the store's key is not held

**Files:**
- Modify: `internal/store/crypt/crypt.go`
- Test: `internal/store/crypt/crypt_test.go`
- Modify: `internal/store/etcd/meta.go` (`SealKeys`, `PutSealKeys`)
- Test: `internal/store/etcd/meta_test.go`
- Modify: `cmd/port49d/store.go` (`unopenableSayer`, `checkSealKeys`), `cmd/port49d/main.go`
- Test: `cmd/port49d/store_test.go`
- Modify: `internal/daemon/metrics/metrics.go` (`CryptStoreKeyUnknown`)

**Interfaces:**
- Consumes: `crypt.Wrap`, `crypt.Keys`; Task 12's `openStores` and `Hold`.
- Produces:
  - `type crypt.Option func(*wrapped)`; `func crypt.OnUnopenable(f func(record, keyID string)) Option`;
    `func crypt.Wrap(inner store.Store, k Keys, openFailures *prometheus.CounterVec, opts ...Option) store.Store`
    (variadic, so every existing caller compiles unchanged)
  - `func crypt.SealedKeyID(sealed []byte) string`
  - `type etcd.SealKeys struct { Current, Previous string; WrittenAt time.Time }`;
    `func (s *Store) SealKeys(ctx context.Context) (SealKeys, bool, error)`;
    `func (s *Store) PutSealKeys(ctx context.Context, k SealKeys) error`
  - `func unopenableSayer(keys crypt.Keys, out io.Writer, now func() time.Time) func(record, keyID string)`;
    `func checkSealKeys(ctx context.Context, s *etcdstore.Store, keys crypt.Keys, m *metrics.Metrics, out io.Writer) error`
  - `Metrics.CryptStoreKeyUnknown` (`port49_crypt_store_key_unknown`)

**Why:** `Candidates` drops a token it cannot open with no error, so before this task the counter
was the only witness that a rotation retired a key while tokens it sealed were live (plan 2). On
a shared, persistent store the same happens across a restart. This task gives the counter a line
an operator can act on, and the start a check.

- [ ] **Step 1: The failing tests.** Append to `internal/store/crypt/crypt_test.go`:

  ```go
  // A record that will not open is told to OnUnopenable with its kind and
  // the key id its header names, beside the counter; a token among
  // candidates is dropped as before (plan 7d; the plan 2 alarm).
  func TestAnUnopenableRecordNamesItsKey(t *testing.T) {
  	now := time.Unix(1000, 0)
  	inner := memory.New(func() time.Time { return now })
  	old := Keys{Current: Key{ID: "enc2", Bytes: [32]byte{2}}}
  	cur := Keys{Current: Key{ID: "enc3", Bytes: [32]byte{3}}}
  	k := store.TokenKey{NAS: "leaf-01", Username: "alice"}
  	if _, err := Wrap(inner, old, nil).PutToken(context.Background(), k, store.Token{ID: "t", Secret: []byte("s"),
  		ExpiresAt: now.Add(time.Minute)}); err != nil {
  		t.Fatal(err)
  	}
  	var told [][2]string
  	s := Wrap(inner, cur, nil, OnUnopenable(func(record, keyID string) { told = append(told, [2]string{record, keyID}) }))
  	if got, err := s.Candidates(context.Background(), k); err != nil || len(got) != 0 {
  		t.Fatalf("%v %v", got, err)
  	}
  	if len(told) != 1 || told[0] != [2]string{"token", "enc2"} {
  		t.Fatalf("told %v", told)
  	}
  	if SealedKeyID(nil) != "" || SealedKeyID([]byte{9, 'a'}) != "" {
  		t.Fatal("a short or empty record names no key")
  	}
  }
  ```

  Append to `internal/store/etcd/meta_test.go`:

  ```go
  func TestSealKeysRoundTrip(t *testing.T) {
  	ctx := context.Background()
  	s, err := Open(Config{Endpoints: []string{etcdtest.Endpoint()}, Prefix: etcdtest.Prefix()})
  	if err != nil {
  		t.Fatal(err)
  	}
  	defer s.Close()
  	if _, ok, err := s.SealKeys(ctx); ok || err != nil {
  		t.Fatalf("a new keyspace has seal keys: %v %v", ok, err)
  	}
  	want := SealKeys{Current: "enc3", Previous: "enc2", WrittenAt: t0}
  	if err := s.PutSealKeys(ctx, want); err != nil {
  		t.Fatal(err)
  	}
  	if got, ok, err := s.SealKeys(ctx); !ok || err != nil || got.Current != "enc3" || got.Previous != "enc2" {
  		t.Fatalf("%+v %v %v", got, ok, err)
  	}
  }
  ```

  Create `cmd/port49d/store_test.go`:

  ```go
  package main

  import (
  	"bytes"
  	"context"
  	"strings"
  	"testing"
  	"time"

  	"github.com/prometheus/client_golang/prometheus"
  	"github.com/prometheus/client_golang/prometheus/testutil"

  	"github.com/rhwendt/port49/internal/daemon/metrics"
  	"github.com/rhwendt/port49/internal/store/crypt"
  	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
  	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
  )

  // A start whose store was last written under a current key this
  // configuration does not hold warns and sets the gauge; one that holds it
  // as previous does not (Ruling 14). Either way it records its own.
  func TestCheckSealKeysWarnsAboutAKeyNotHeld(t *testing.T) {
  	srv := etcdtest.Start(t, etcdtest.Options{})
  	s, err := etcdstore.Open(etcdstore.Config{Endpoints: []string{srv.Endpoint}})
  	if err != nil {
  		t.Fatal(err)
  	}
  	defer s.Close()
  	ctx := context.Background()
  	if err := s.PutSealKeys(ctx, etcdstore.SealKeys{Current: "enc2"}); err != nil {
  		t.Fatal(err)
  	}
  	m := metrics.New(prometheus.NewRegistry())
  	var out bytes.Buffer
  	rotated := crypt.Keys{Current: crypt.Key{ID: "enc3"}}
  	if err := checkSealKeys(ctx, s, rotated, m, &out); err != nil {
  		t.Fatal(err)
  	}
  	if !strings.Contains(out.String(), `whose current key is "enc2", which this configuration does not hold`) ||
  		testutil.ToFloat64(m.CryptStoreKeyUnknown) != 1 {
  		t.Fatalf("said %q, gauge %v", out.String(), testutil.ToFloat64(m.CryptStoreKeyUnknown))
  	}
  	out.Reset()
  	kept := crypt.Keys{Current: crypt.Key{ID: "enc4"}, Previous: &crypt.Key{ID: "enc3"}}
  	if err := checkSealKeys(ctx, s, kept, m, &out); err != nil || out.Len() != 0 ||
  		testutil.ToFloat64(m.CryptStoreKeyUnknown) != 0 {
  		t.Fatalf("a window holding the store's key: said %q, %v", out.String(), err)
  	}
  }

  // The unopenable line names the key and what to do, once per record kind
  // and key id per ten minutes.
  func TestUnopenableSayerSaysOncePerKeyPerTenMinutes(t *testing.T) {
  	now := time.Unix(1000, 0)
  	var out bytes.Buffer
  	say := unopenableSayer(crypt.Keys{Current: crypt.Key{ID: "enc3"}}, &out, func() time.Time { return now })
  	say("token", "enc2")
  	say("token", "enc2")
  	if strings.Count(out.String(), "\n") != 1 || !strings.Contains(out.String(),
  		`a token is sealed under key id "enc2", which this port49d does not hold (current "enc3", no previous)`) {
  		t.Fatalf("said %q", out.String())
  	}
  	say("context", "enc2")
  	now = now.Add(11 * time.Minute)
  	say("token", "enc2")
  	if strings.Count(out.String(), "\n") != 3 {
  		t.Fatalf("said %q", out.String())
  	}
  	say("token", "enc3")
  	if !strings.Contains(out.String(), `failed authentication under key id "enc3"`) {
  		t.Fatalf("a record under a held key that will not open: %q", out.String())
  	}
  }
  ```

  Run: `go test ./internal/store/crypt/ ./internal/store/etcd/ ./cmd/port49d/ -run 'Unopenable|SealKeys' -count=1`
  Expected: FAIL to build.

- [ ] **Step 2: The sealing layer.** In `internal/store/crypt/crypt.go`:

  ```go
  // Option configures Wrap.
  type Option func(*wrapped)

  // OnUnopenable is told the kind and the key id of every record that will
  // not open, beside crypt_open_failures_total. The key id is the sealed
  // record's own header, never a secret: it is how an operator learns which
  // key a rotation retired too early (plan 2's alarm; plan 7d).
  func OnUnopenable(f func(record, keyID string)) Option { return func(w *wrapped) { w.onUnopenable = f } }

  // SealedKeyID is the key id a sealed record's header names, or "" when it
  // is too short to name one.
  func SealedKeyID(sealed []byte) string {
  	if len(sealed) < 1 || len(sealed) < 1+int(sealed[0]) {
  		return ""
  	}
  	return string(sealed[1 : 1+int(sealed[0])])
  }
  ```

  Add `onUnopenable func(record, keyID string)` to `wrapped`. Make `Wrap` variadic and apply
  each option. Give `openErr` the record's sealed bytes: `func (w *wrapped) openErr(record string,
  sealed []byte, err error) error`, calling `w.onUnopenable(record, SealedKeyID(sealed))` when it
  is set, after the counter. Pass the sealed bytes at each of its four callers: `t.Sealed` in
  `Candidates`, `r.Sealed` in `GetReceipt`, `c.Sealed` in `GetContext`, `cur.Sealed` in
  `ReserveIdempotency`.

- [ ] **Step 3: The seal keys on etcd.** Append to `internal/store/etcd/meta.go`:

  ```go
  // SealKeys is the encryption key window the last port49d on this keyspace
  // started with: ids only, never key material (plan 7d, Ruling 14).
  type SealKeys struct {
  	Current   string    `json:"current"`
  	Previous  string    `json:"previous,omitempty"`
  	WrittenAt time.Time `json:"written_at"`
  }

  func (s *Store) SealKeys(ctx context.Context) (SealKeys, bool, error) {
  	var k SealKeys
  	_, ok, err := getJSON(ctx, s.ctx, s.k.meta("seal_keys"), &k)
  	return k, ok, err
  }

  func (s *Store) PutSealKeys(ctx context.Context, k SealKeys) error {
  	body, err := json.Marshal(k)
  	if err != nil {
  		return err
  	}
  	_, err = s.ctx.Put(ctx, s.k.meta("seal_keys"), string(body))
  	return unavailable(err)
  }
  ```

- [ ] **Step 4: port49d says it.** In `cmd/port49d/store.go` add:

  ```go
  // unopenableSayer is crypt.OnUnopenable's line (Ruling 14): which record,
  // which key id, and what to do, once per (record, key id) per 10 minutes,
  // so a fleet of logins under a retired key is one line, not one per login.
  func unopenableSayer(keys crypt.Keys, out io.Writer, now func() time.Time) func(record, keyID string) {
  	var mu sync.Mutex
  	said := map[[2]string]time.Time{}
  	window := fmt.Sprintf("current %q, no previous", keys.Current.ID)
  	if keys.Previous != nil {
  		window = fmt.Sprintf("current %q, previous %q", keys.Current.ID, keys.Previous.ID)
  	}
  	return func(record, keyID string) {
  		mu.Lock()
  		defer mu.Unlock()
  		k := [2]string{record, keyID}
  		if t, ok := said[k]; ok && now().Sub(t) < 10*time.Minute {
  			return
  		}
  		said[k] = now()
  		held := keyID == keys.Current.ID || keys.Previous != nil && keyID == keys.Previous.ID
  		if held {
  			fmt.Fprintf(out, "port49d: crypt: a %s failed authentication under key id %q: it was altered or is "+
  				"corrupt, and is treated as unreadable\n", record, keyID)
  			return
  		}
  		fmt.Fprintf(out, "port49d: crypt: a %s is sealed under key id %q, which this port49d does not hold (%s): a "+
  			"rotation retired that key while records it sealed were live; set encryption.previous to %q until they "+
  			"expire\n", record, keyID, window, keyID)
  	}
  }

  // checkSealKeys is the start's key check on etcd (Ruling 14): a store last
  // written under a current key this window lacks is said, and gauged, and
  // never refuses the start; then this window is recorded.
  func checkSealKeys(ctx context.Context, s *etcdstore.Store, keys crypt.Keys, m *metrics.Metrics, out io.Writer) error {
  	last, ok, err := s.SealKeys(ctx)
  	if err != nil {
  		return fmt.Errorf("store: reading the last start's key ids: %w", err)
  	}
  	held := !ok || last.Current == keys.Current.ID || keys.Previous != nil && last.Current == keys.Previous.ID
  	m.CryptStoreKeyUnknown.Set(0)
  	if !held {
  		m.CryptStoreKeyUnknown.Set(1)
  		window := fmt.Sprintf("current %q, no previous", keys.Current.ID)
  		if keys.Previous != nil {
  			window = fmt.Sprintf("current %q, previous %q", keys.Current.ID, keys.Previous.ID)
  		}
  		fmt.Fprintf(out, "port49d: crypt: the store was last written by a port49d whose current key is %q, which "+
  			"this configuration does not hold (%s); records sealed under %s will not open: live sessions on them "+
  			"end at their next command, and their tokens fail; set encryption.previous to %s until they expire\n",
  			last.Current, window, last.Current, last.Current)
  	}
  	cur := etcdstore.SealKeys{Current: keys.Current.ID, WrittenAt: time.Now().UTC()}
  	if keys.Previous != nil {
  		cur.Previous = keys.Previous.ID
  	}
  	return s.PutSealKeys(ctx, cur)
  }
  ```

  Add `"sync"` to the imports. In `openStores`:
  - Pass `crypt.OnUnopenable(unopenableSayer(keys, out, time.Now))` to every `crypt.Wrap`: the
    memory one and the two on etcd.
  - After the hold is taken and before the stores are returned, call `checkSealKeys(ctx, d, keys,
    m, out)`. On error, release, close and return it.

  Add to `metrics.go`:

  ```go
  	// CryptStoreKeyUnknown is 1 when port49d started on a store last written
  	// under a current key its encryption window does not hold (plan 7d):
  	// records sealed under it will not open.
  	CryptStoreKeyUnknown prometheus.Gauge
  ```

  named `port49_crypt_store_key_unknown`, registered.

- [ ] **Step 5: Run.**

  Run: `go test ./internal/store/... ./cmd/port49d/ -count=1`
  Expected: PASS.

- [ ] **Step 6: Commit.**

  ```bash
  gofmt -w internal/store/crypt internal/store/etcd cmd/port49d internal/daemon/metrics
  make build && make test && make vet
  git add internal/store/crypt/crypt.go internal/store/crypt/crypt_test.go internal/store/etcd/meta.go \
    internal/store/etcd/meta_test.go cmd/port49d/store.go cmd/port49d/store_test.go internal/daemon/metrics/metrics.go
  git commit -m "feat(crypt): a record that will not open names its key; a start checks the store's

  crypt_open_failures_total{record=\"token\"} becomes an alarm an operator
  can act on: each unopenable record is said once per key id per ten
  minutes, naming the key and the fix. On etcd a start records its key
  window and warns, with port49_crypt_store_key_unknown, when the store
  was last written under a current key it does not hold (plan 2's alarm;
  plan 7d).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 14: The agent's one connection: a mint behind a revocation says so

**Files:**
- Modify: `internal/agent/agent.go`
- Modify: `internal/agent/socket.go` (`Client.Mint`'s 503)
- Test: `internal/agent/agent_test.go`

**Interfaces:**
- Consumes: the agent's `exchange`, `doOn`, `Revoke`, `Handler`; the test rig (`newRig`,
  `fakeBroker.revokeDelay`, `fakeBroker.answers`, `fakeBroker.addrs`, `socketFor`).
- Produces:
  - `type agent.RevocationRunningError struct { Since time.Time; Detail string }`
  - `var wireWait = 30 * time.Second` (package variable; tests shorten it)
  - The agent's socket answers a mint behind a running revocation `503 revocation_running`, and
    `Client.Mint` returns `*RevocationRunningError`.

- [ ] **Step 1: The failing test.** Append to `internal/agent/agent_test.go`:

  ```go
  // A mint behind a revocation that holds the agent's one connection waits
  // its own budget, then says the revocation is still running and nothing
  // was minted, never that the broker is unreachable; it sends nothing
  // (plan 7d, Ruling 15; 7c final review).
  func TestAMintBehindARunningRevocationSaysSo(t *testing.T) {
  	defer func(d time.Duration) { wireWait = d }(wireWait)
  	wireWait = 200 * time.Millisecond
  	r := newRig(t)
  	r.fb.mu.Lock()
  	r.fb.answers = map[string]refusal{"/v1/tokens/revoke": {status: 200}}
  	r.fb.revokeDelay = 2 * time.Second
  	r.fb.mu.Unlock()
  	revoked := make(chan error, 1)
  	go func() {
  		_, err := r.a.Revoke(context.Background(), api.RevokeRequest{Mine: true})
  		revoked <- err
  	}()
  	time.Sleep(100 * time.Millisecond) // the revocation holds the wire
  	start := time.Now()
  	_, err := socketFor(t, r.a).Mint(context.Background(), "leaf1", false, 0)
  	var running *RevocationRunningError
  	if !errors.As(err, &running) || time.Since(start) > time.Second {
  		t.Fatalf("a mint behind a revocation: %v after %v", err, time.Since(start))
  	}
  	if !strings.Contains(err.Error(), "is still running on the broker; nothing was minted") ||
  		strings.Contains(err.Error(), "unreachable") {
  		t.Fatalf("said %q", err.Error())
  	}
  	r.fb.mu.Lock()
  	mints := len(r.fb.addrs["/v1/tokens"])
  	r.fb.mu.Unlock()
  	if mints != 0 {
  		t.Fatalf("the mint was sent behind the revocation: %d", mints)
  	}
  	if err := <-revoked; err != nil {
  		t.Fatal(err)
  	}
  	if _, err := r.a.Mint(context.Background(), "leaf1", false, 0); err != nil {
  		t.Fatalf("a mint after the revocation: %v", err)
  	}
  }
  ```

  Use `socketFor(t, r.a)`'s client exactly as the 7c tests in this file do. If its `Mint`
  signature differs from `Mint(ctx, device, enable, ttl)`, follow the file's own call. If
  `fakeBroker.addrs` keys mints under another path, use that path.

  Run: `go test ./internal/agent/ -run TestAMintBehindARunningRevocationSaysSo -count=1`
  Expected: FAIL: the mint waits for the connection and either succeeds after the revocation or,
  with a longer delay, fails "unreachable".

- [ ] **Step 2: The wire.** In `internal/agent/agent.go`:

  1. Add to `Agent`, after `revokeClient`:

     ```go
     	// wire is the held connection's one slot (plan 7d, Ruling 15): one
     	// exchange at a time, which the transport did already, now with the
     	// agent knowing what holds it. revoking is when a revocation took it,
     	// in Unix nanoseconds; 0 when none holds it.
     	wire     chan struct{}
     	revoking atomic.Int64
     ```

     and `wire: make(chan struct{}, 1)` in `New`'s literal.

  2. Add:

     ```go
     // wireWait bounds how long a call that is not a revocation waits for
     // the held connection: the budget it had before plan 7d, when it
     // queued in the transport under the client's 30s timeout.
     var wireWait = 30 * time.Second

     // RevocationRunningError is a call that waited wireWait for the held
     // connection while a revocation the operator sent held it: nothing was
     // sent, and the revocation is still the broker's to answer.
     type RevocationRunningError struct {
     	Since  time.Time
     	Detail string // set when it came back through the agent's socket
     }

     func (e *RevocationRunningError) Error() string {
     	if e.Detail != "" {
     		return e.Detail
     	}
     	return fmt.Sprintf("your revocation sent at %s is still running on the broker; nothing was minted; run "+
     		"port49 token again once port49 revoke reports", e.Since.Local().Format("15:04:05"))
     }

     // takeWire waits for the held connection. A revocation waits as long as
     // its ctx lets it and marks the wire as its own; any other call waits
     // wireWait, and if a revocation still holds it then, says so.
     func (a *Agent) takeWire(ctx context.Context, revocation bool) error {
     	wait := ctx
     	if !revocation {
     		var cancel context.CancelFunc
     		wait, cancel = context.WithTimeout(ctx, wireWait)
     		defer cancel()
     	}
     	select {
     	case a.wire <- struct{}{}:
     	case <-wait.Done():
     		if since := a.revoking.Load(); since != 0 && ctx.Err() == nil {
     			return &RevocationRunningError{Since: time.Unix(0, since)}
     		}
     		if ctx.Err() != nil {
     			return ctx.Err()
     		}
     		return fmt.Errorf("agent: the connection to the broker at %s was busy for %v", a.broker, wireWait)
     	}
     	if revocation {
     		a.revoking.Store(a.now().UnixNano())
     	}
     	return nil
     }

     func (a *Agent) giveWire(revocation bool) {
     	if revocation {
     		a.revoking.Store(0)
     	}
     	<-a.wire
     }
     ```

  3. In `exchange`, after the session checks and before the request body is built:

     ```go
     	revocation := unanswered != nil // only Revoke passes one
     	if err := a.takeWire(ctx, revocation); err != nil {
     		return err
     	}
     	defer a.giveWire(revocation)
     ```

  4. Every other send on the held connection takes the wire too: the refresh's challenge and
     its refresh (the two `a.doOn(` calls outside `exchange`; grep `a.doOn(` and
     `a.client.Do(`), each with `takeWire(ctx, false)`/`giveWire(false)` around its send. If
     `Connect` sends on the connection, it takes the wire as well.

  5. In `Handler`'s `POST /token`, before `case err != nil:`, add:

     ```go
     		case errors.As(err, new(*RevocationRunningError)):
     			// Not the broker failing: the operator's own revocation is still
     			// running, and nothing was minted.
     			writeJSON(w, http.StatusServiceUnavailable, api.Error{Error: "revocation_running", Detail: err.Error()})
     ```

  In `socket.go`'s `Client.Mint`, before `default:`:

  ```go
  	case http.StatusServiceUnavailable:
  		var e api.Error
  		_ = json.NewDecoder(resp.Body).Decode(&e)
  		if e.Error == "revocation_running" {
  			return api.MintItem{}, &RevocationRunningError{Detail: e.Detail}
  		}
  		return api.MintItem{}, fmt.Errorf("agent: %s: %s", e.Error, e.Detail)
  ```

  `port49 token` prints a mint error as `port49 token: <err>`, so it prints the operator line from
  "What the operator sees". Check `cmd/port49/main.go`'s `tokenCmd`. If it prefixes or wraps the
  error, make sure the line still reads as written, and add a case to `cmd/port49/main_test.go`
  only if it does not.

  Run: `go test ./internal/agent/ ./cmd/port49/ -count=1`
  Expected: PASS: the new test and every existing agent test, 7c's
  `TestAnUnansweredRevocationIsSentOnceAndMayBeInForce` included. Its revocations run one at a
  time on the wire, as they did on the transport.

- [ ] **Step 3: Commit.**

  ```bash
  gofmt -w internal/agent cmd/port49
  make build && make test && make vet
  git add internal/agent/agent.go internal/agent/socket.go internal/agent/agent_test.go
  git commit -m "fix(agent): a port49 token behind a running revocation says so

  The agent sends one exchange at a time on its held connection and knows
  when a revocation holds it. A mint arriving behind one waits its own 30s
  and then says the revocation is still running and nothing was minted,
  never that the broker is unreachable, which a remote store made likely
  (7c final review; plan 7d, Ruling 15).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 15: (lab, on beehive) L35: a hung store, a stop, a return, on four images

**Files:**
- Create: `tests/lab/store_test.go`
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§15, L35 closed; the cells the run
  measures)
- Created by the run: `tests/lab/results/L35-<platform>.md`,
  `tests/lab/evidence/L35-<platform>.pcap` (through `l.capture` and `make evidence`)

**Interfaces:**
- Consumes:
  - **The lab harness:** `eachPlatform`, `l.derivedConfig`, `l.stopDaemon`, `l.startDaemonWith`,
    `l.awaitTACACS`, `l.configPath`, `l.capture`, `l.mark`, `l.shell`, `l.loginWithin`,
    `l.waitForRecords`, `l.recordsSince`, `l.result`, `l.errLogSize`, `l.errLinesSince`.
  - **7a's and 7c's helpers:** `revokeAgent`, `revokeOutcome`, `redeemReason`, `l29Mint`,
    `l29Cell`, `sha`, `summarize`, `platformSessionAttributes`, `slicePKIDir`, `sliceEmail`,
    `sliceUser`, `breakglassUser`, `breakglassPassword`.
  - **The store:** `etcdtest.Start`, `(*Server).EnableAuth`, `(*Server).ClientFiles`,
    `etcdtest.NewProxy`, `etcd.Roles`, `etcd.RoleDaemon`, `etcd.RoleBroker` (Tasks 5, 11).
- Produces: `func TestStoreOutageEndToEnd(t *testing.T)`, and its notes.

**What it measures** (L35, opened by Task 1). The store is a real etcd member, with TLS and
port49's roles, inside the lab test process. port49d reaches it through an in-process proxy the
test hangs (Ruling 16), with `hold_ttl: 60s` so the window before port49d stops is long enough to
measure in. On each image:

1. **Baseline on etcd.** alice logs in with a token, and `show version` runs.
2. **A restart.** port49d stops and starts on the same store.
   - **Non-Junos:** the open session's next command runs, answered from its context. The record
     is `authorize_command permit context_matched` with the session's `ctx_id` from before the
     restart.
   - **Junos:** the session runs on, as it does with port49d stopped.
   - **Every image:** a token minted before the restart is refused `token_not_found`, and port49d
     says it purged it.
3. **The store hangs.** The proxy stops forwarding.
   - **Non-Junos:** the open session's next command is refused. The test measures how long the
     device took, which must be under its 5 s TACACS+ timeout (L4), what it printed, and the
     record (`authorize_command deny store_unavailable`).
   - **Every image:** a new token login is refused, timed, recorded `redeem error
     store_unavailable`. Break-glass is tried: logged in or not, a command or not, recorded as
     measured and compared with `tests/lab/results/L4-error-<platform>.md`.
4. **port49d stops.** Within `hold_ttl` + 30 s, port49d's stderr says it lost its hold and it
   exits. Then the open session's next command runs or does not, under local authorization
   (compared with `quarantine-<platform>.md`), and break-glass logs in, timed.
5. **The store returns.** The proxy resumes and port49d is started again, as its supervisor
   would. Its stderr says purged and carried.
   - **Non-Junos:** the open session's next command runs, answered from its context with the
     same `ctx_id`.

- [ ] **Step 1: The test.** Create `tests/lab/store_test.go`:

  ```go
  //go:build lab

  package lab

  import (
  	"fmt"
  	"os"
  	"path/filepath"
  	"strings"
  	"testing"
  	"time"

  	"github.com/rhwendt/port49/internal/store/etcd"
  	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
  	"github.com/rhwendt/port49/internal/testpki"
  )

  const storeClaim = "When port49d's store hangs (etcd cut off from port49d), port49d answers a command FAIL " +
  	"store_unavailable and a login ERROR store_unavailable within store.packet_deadline (2s), before the " +
  	"device's own TACACS+ timeout, and the device acts as on L4's store outage, never as on a silent server; " +
  	"once port49d stops on losing its hold on the store (store.etcd.hold_ttl), the device acts as with port49d " +
  	"stopped and break-glass logs in; and after the store returns and port49d restarts, an open session's next " +
  	"command is answered from the context the store kept (plan 7d; spec §13 decision 35)."

  // storeLab is the lab's etcd: a TLS member with port49's roles, behind a
  // proxy the test hangs, and the store: block that points port49d at it.
  func storeLab(t *testing.T) (block string, proxy *etcdtest.Proxy) {
  	t.Helper()
  	srv := etcdtest.Start(t, etcdtest.Options{TLS: true})
  	var grants []etcdtest.Grant
  	for _, g := range etcd.Roles("/port49/") {
  		grants = append(grants, etcdtest.Grant{Role: g.Role, Key: g.Key, RangeEnd: g.RangeEnd, Write: g.Write})
  	}
  	srv.EnableAuth(t, grants, map[string][]string{"port49-daemon": {etcd.RoleDaemon}, "port49-broker": {etcd.RoleBroker}})
  	proxy = etcdtest.NewProxy(t, strings.TrimPrefix(srv.Endpoint, "https://"))
  	dc, dk := srv.ClientFiles(t, "port49-daemon")
  	bc, bk := srv.ClientFiles(t, "port49-broker")
  	block = fmt.Sprintf("\nstore:\n  backend: etcd\n  etcd:\n    endpoints: [https://%s]\n    ca_file: %s\n"+
  		"    daemon: {cert_file: %s, key_file: %s}\n    broker: {cert_file: %s, key_file: %s}\n    hold_ttl: 60s\n",
  		proxy.Addr(), filepath.Join(srv.Dir, "ca.pem"), dc, dk, bc, bk)
  	return block, proxy
  }

  // ctxIDOf is the ctx_id of the last authorize_command record for user
  // since off, and its verdict and reason.
  func ctxIDOf(recs []map[string]any, user string) (ctxID, verdict, reason string) {
  	for _, r := range recs {
  		if r["event"] != "authorize_command" {
  			continue
  		}
  		if s, _ := r["session"].(map[string]any); s != nil && s["username"] == user {
  			ctxID, _ = s["ctx_id"].(string)
  			verdict, _ = r["verdict"].(string)
  			reason, _ = r["reason"].(string)
  		}
  	}
  	return ctxID, verdict, reason
  }

  func TestStoreOutageEndToEnd(t *testing.T) {
  	eachPlatform(t, func(t *testing.T, l *lab) {
  		var failed []string
  		fail := func(format string, args ...any) { failed = append(failed, fmt.Sprintf(format, args...)) }
  		sessionOnly := strings.HasPrefix(l.p.name, "juniper_")
  		var obs strings.Builder
  		row := func(step, what string) { fmt.Fprintf(&obs, "| %s | %s |\n", step, l29Cell(what)) }
  		obs.WriteString("| step | observed |\n|---|---|\n")

  		pki := filepath.Join(root, slicePKIDir)
  		if err := testpki.WriteLab(pki, sliceEmail, time.Now()); err != nil {
  			t.Fatal(err)
  		}
  		brokerYAML, err := os.ReadFile(filepath.Join(root, "tests", "lab", "slice", "broker.yaml"))
  		if err != nil {
  			t.Fatal(err)
  		}
  		block, proxy := storeLab(t)
  		cfg, err := l.derivedConfig("store", platformSessionAttributes[l.p.name], string(brokerYAML)+block)
  		if err != nil {
  			t.Fatal(err)
  		}
  		if err := l.stopDaemon(); err != nil {
  			t.Fatal(err)
  		}
  		start := func(what string) {
  			t.Helper()
  			if err := l.startDaemonWith(cfg, true); err != nil {
  				t.Fatalf("port49d would not start on etcd (%s): %v", what, err)
  			}
  			if err := l.awaitTACACS(); err != nil {
  				t.Fatal(err)
  			}
  		}
  		start("first")
  		defer func() {
  			proxy.Hang(false)
  			l.stopDaemon()
  			std, err := l.configPath()
  			if err != nil {
  				t.Fatalf("derive this platform's daemon config: %v", err)
  			}
  			if err := l.startDaemonWith(std, true); err != nil {
  				t.Fatalf("could not put port49d back on the lab config: %v", err)
  			}
  		}()
  		stop := l.capture(t, "L35")
  		defer stop()

  		// 1. Baseline.
  		off := l.mark()
  		sock, _, stopAgent := revokeAgent(t)
  		defer stopAgent()
  		_, tok1 := l29Mint(sock, l.p.node)
  		_, spare := l29Mint(sock, l.p.node)
  		if tok1 == "" || spare == "" {
  			t.Fatal("the agent minted no token on etcd")
  		}
  		sh, err := l.shell(sliceUser, tok1)
  		if err != nil {
  			t.Fatalf("SSH login on etcd: %v\nrecords:%s", err, summarize(l.recordsSince(off)))
  		}
  		defer sh.Close()
  		before := revokeOutcome(l.p.name, sh, "show version", fail, "baseline")
  		row("1. baseline, `show version`", before)
  		ctxBefore, _, _ := ctxIDOf(l.recordsSince(off), sliceUser)

  		// 2. A restart on the same store.
  		errOff := l.errLogSize()
  		if err := l.stopDaemon(); err != nil {
  			t.Fatal(err)
  		}
  		start("restart")
  		row("2. port49d's start lines", strings.Join(append(l.errLinesSince(errOff, "purged"),
  			l.errLinesSince(errOff, "carried onto the policy in force")...), " / "))
  		off = l.mark()
  		after := revokeOutcome(l.p.name, sh, "show version", fail, "after the restart")
  		ctxAfter, verdict, reason := ctxIDOf(l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
  			id, _, _ := ctxIDOf(rs, sliceUser)
  			return id != "" || sessionOnly
  		}), sliceUser)
  		row("2. after the restart, the open session's `show version`",
  			fmt.Sprintf("%s; record %s %s, ctx_id %s (before: %s)", after, verdict, reason, ctxAfter, ctxBefore))
  		if !strings.HasPrefix(after, "printed its output") {
  			fail("the open session's next command did not run after the restart: %s", after)
  		}
  		if !sessionOnly && (ctxAfter != ctxBefore || verdict != "permit") {
  			fail("the next command was not answered from the kept context: %s %s %s/%s", verdict, reason, ctxAfter, ctxBefore)
  		}
  		if _, err := l.loginWithin(sliceUser, spare, 60*time.Second, "show version"); err == nil {
  			fail("a token minted before the restart logged in")
  		}
  		recs := l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool { return redeemReason(rs, sha(spare)) != "" })
  		row("2. a token minted before the restart", "refused "+redeemReason(recs, sha(spare)))
  		if redeemReason(recs, sha(spare)) != "token_not_found" {
  			fail("the pre-restart token was refused %q, not token_not_found", redeemReason(recs, sha(spare)))
  		}

  		// 3. The store hangs.
  		_, tok3 := l29Mint(sock, l.p.node)
  		proxy.Hang(true)
  		hungAt := time.Now()
  		off = l.mark()
  		if !sessionOnly {
  			hung := revokeOutcome(l.p.name, sh, "show version", fail, "with the store hung")
  			row("3. store hung, the open session's `show version`", hung)
  			if !strings.HasPrefix(hung, "refused") {
  				fail("with the store hung the next command was not refused: %s", hung)
  			}
  		}
  		t0 := time.Now()
  		_, lerr := l.loginWithin(sliceUser, tok3, 60*time.Second, "show version")
  		row("3. store hung, a token login", fmt.Sprintf("%v after %s", lerr, time.Since(t0).Round(10*time.Millisecond)))
  		if lerr == nil {
  			fail("a token login succeeded with the store hung")
  		}
  		t0 = time.Now()
  		_, berr := l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version")
  		row("3. store hung, break-glass and `show version`",
  			fmt.Sprintf("%v after %s (compare tests/lab/results/L4-error-%s.md)", berr, time.Since(t0).Round(10*time.Millisecond), l.p.name))
  		recs = l.waitForRecords(off, 20*time.Second, func([]map[string]any) bool { return true })
  		row("3. records", summarize(recs))

  		// 4. port49d stops on losing its hold.
  		for time.Since(hungAt) < 90*time.Second && len(l.errLinesSince(errOff, "lost this port49d's hold")) == 0 {
  			time.Sleep(time.Second)
  		}
  		lost := l.errLinesSince(errOff, "lost this port49d's hold")
  		row("4. port49d's line", fmt.Sprintf("%s (%s after the hang)", strings.Join(lost, " / "),
  			time.Since(hungAt).Round(time.Second)))
  		if len(lost) == 0 {
  			fail("port49d did not stop within 90s of the hang")
  		}
  		time.Sleep(5 * time.Second) // the process exits after its line
  		stopped := revokeOutcome(l.p.name, sh, "show version", func(string, ...any) {}, "with port49d stopped")
  		row("4. port49d stopped, the open session's `show version`",
  			stopped+" (compare tests/lab/results/quarantine-"+l.p.name+".md)")
  		t0 = time.Now()
  		_, berr = l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version")
  		row("4. port49d stopped, break-glass and `show version`", fmt.Sprintf("%v after %s", berr, time.Since(t0).Round(10*time.Millisecond)))
  		if berr != nil {
  			fail("break-glass did not log in with port49d stopped: %v", berr)
  		}

  		// 5. The store returns; port49d is started again.
  		proxy.Hang(false)
  		errOff = l.errLogSize()
  		l.stopDaemon() // the harness's record of the exited process
  		start("after the outage")
  		row("5. port49d's start lines", strings.Join(append(l.errLinesSince(errOff, "purged"),
  			l.errLinesSince(errOff, "carried onto the policy in force")...), " / "))
  		off = l.mark()
  		back := revokeOutcome(l.p.name, sh, "show version", fail, "after the store returned")
  		ctxBack, verdict, reason := ctxIDOf(l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
  			id, _, _ := ctxIDOf(rs, sliceUser)
  			return id != "" || sessionOnly
  		}), sliceUser)
  		row("5. store back, the open session's `show version`",
  			fmt.Sprintf("%s; record %s %s, ctx_id %s", back, verdict, reason, ctxBack))
  		if !sessionOnly && (ctxBack != ctxBefore || verdict != "permit") {
  			fail("after the store returned the next command was not answered from the kept context: %s %s %s",
  				verdict, reason, ctxBack)
  		}

  		note := obs.String()
  		if len(failed) > 0 {
  			note += "\n**Failed:**\n\n- " + strings.Join(failed, "\n- ") + "\n"
  		}
  		l.result(t, "L35", storeClaim, note)
  		if len(failed) > 0 {
  			t.Fatalf("L35 on %s: %s", l.p.name, strings.Join(failed, "; "))
  		}
  	})
  }
  ```

  Read each consumed helper before relying on it. `l.result`'s note format is 7c's. The harness's
  `stopDaemon` must treat a port49d that exited on its own as stopped. Read `harness_test.go:1331`.
  If it errors on an exited process, change it to return nil for one, in this commit, and say
  so. The four-platform run is a plain `go test -tags lab`, as Running the lab says.

  Run: `go vet -tags lab ./tests/lab/` — clean. Then, on beehive, from a worktree pinned to the
  commit, one platform at a time:

  ```bash
  PORT49_LAB_PLATFORMS=eos go test -tags lab ./tests/lab/ -run TestStoreOutageEndToEnd -count=1 -timeout 60m -v
  ```

  then `nxos`, `iosxe`, `vjunos`, under the watchdog.

- [ ] **Step 2: Read the notes, then close L35.** Read each `tests/lab/results/L35-<platform>.md`.
  For each image, the row closes with:
  - its version;
  - the time from the hang to the device's refusal, against L4's 5 s;
  - what it printed;
  - what break-glass did while the store hung and once port49d stopped;
  - the stop's delay;
  - whether the session came back on its context.

  - **If a device timed out before port49d's answer arrived** (a refusal later than 5 s, or the
    device's own timeout text): `store.packet_deadline`'s default is wrong for that image. Lower
    the default in `config.go`, and the bound if needed. Say so in decision 35 and in the
    commit, and rerun that image.
  - **If a note contradicts a doc,** the doc is wrong (rule 4). Fix the doc and cite the note.

  Close the row only if all four images measured. Rule 5: a row with one open platform stays
  open.

  Edit L35's status cell to `closed — measured <date>; tests/lab/results/L35-arista_eos.md,
  L35-cisco_nxos.md, L35-cisco_iosxe.md, L35-juniper_vjunos-router.md`, followed by the
  per-image summary. Then:

  ```bash
  cp ../port49-lab-7d/tests/lab/captures/L35-* tests/lab/captures/   # from the worktree, before removing it
  make evidence
  git add tests/lab/store_test.go tests/lab/results/L35-*.md tests/lab/evidence/L35-*.pcap \
    docs/design/2026-08-23-policy-engine-spec.md
  git commit -m "docs: close lab register entry L35 (the store hangs, port49d stops, the session returns)

  <one line per image: refusal time, what it printed, break-glass, the
  stop's delay, the session's return>

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

  If the harness changed (`harness_test.go`), add it to the `git add`, by path. Commit the test
  first in its own `test(lab):` commit if it changed after review, as 7c's lab commits did.

---

### Task 16: Plan 7d as built

**Files:**
- Modify: `docs/superpowers/plans/README.md`
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`, `docs/design/2026-08-21-port49-design.md`,
  only where a task's as-built drift needs it

- [ ] **Step 1: The roadmap.**
  - **"Plan 7d — As built".** After "Plan 7c — As built", add it in 7c's form: task by task,
    what differs from this plan's text, with commits; the rulings as made; L35 per image; the
    operator notes (the section below, amended by what was built); "Carried, for later plans";
    and "Unassigned follow-ups".
  - **The status line.** Change it to say 7d-1 and 7d-2 executed and merged, with their PRs.
  - **What to carry:**
    - **7e:** `b.superseded`, `b.blobsSeen` and `quarantineRecorded` into the store; more than
      one port49d per keyspace (the hold becomes per broker process, and the daemons hold none);
      the listener's marks shared across replicas through a watch on the marks family;
      `broker.revocations_file` retired; one refresh runner.
    - **7f:** go-dark proper, replacing Ruling 11's stop with the listener's close and reopen;
      the warm context cache.
    - **12:** the etcd deployment artifacts (members, compaction, quota, the roles applied from
      `port49d store-roles`), `call_timeout` and `packet_deadline` sized against load, and the
      store alarms.
- [ ] **Step 2: Docs drift.** If any task's report says a block was changed against this plan's
  text in a way a doc states (a default, a line, a bound), fix the doc and cite the commit.
- [ ] **Step 3: Commit.**

  ```bash
  make test
  git add docs/superpowers/plans/README.md docs/design/2026-08-23-policy-engine-spec.md \
    docs/design/2026-08-21-port49-design.md
  git commit -m "docs: plan 7d as built

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

## Operator-facing notes (for the pull request bodies)

**7d-1** (no deployment change; port49d still runs on memory):

- **A login whose index cannot be written is refused.** Before, port49d admitted it and wrote
  `index_error: context not indexed …` on the redeem record. Now the device gets ERROR, the
  record is `redeem error store_unavailable`, and no context is written. A revocation can always
  reach a context that exists.
- **A login by a principal or certificate under a standing mark is refused `credential_revoked`,**
  even when it redeemed a token in the instant before the revocation deleted it.
- `port49_store_operations_total{op}` no longer counts `index_context`, `unindex_context` or
  `unindex_ref` on the login path. Those are now part of `join_context`.

**7d-2:**

- **New: `store:` in `port49d.yaml`.** `backend: memory` stays the default.
  - **Turning on etcd.** Set `backend: etcd` with `store.etcd` (endpoints `https` only, `ca_file`,
    and a client certificate each for `daemon` and `broker`, CN = etcd user). Run `port49d
    store-roles --config …` and apply its output once as etcd's root.
  - **Knobs and defaults:** `call_timeout` 500ms, `packet_deadline` 2s, `breaker` 5 failures
    and 5s open, `max_in_flight` 64 token and 128 context, `lease_grace` 5m, `start_timeout`
    30s, `hold_ttl` 15s, `sweep_interval` 10m.
- **etcd itself.** Run three or five members in the devices' region, with client-certificate
  auth and auth enabled, `--auto-compaction-mode=periodic --auto-compaction-retention=1h`,
  defragmentation, and a quota above the live records. Back etcd up as you would the revocations
  file.
- **One port49d per keyspace until plan 7e.** A second one waits and is not ready. On
  Kubernetes use `strategy: Recreate`.
- **What a restart does now.**
  - Live sessions survive: the next command after the restart is answered from the kept
    context, carried onto the policy in force first (L35).
  - Unspent tokens are purged (`port49d: store: purged N unspent token(s) …`), so run `port49
    token` again. A retried `port49 token` with the same idempotency key mints afresh.
- **What an etcd outage does.**
  - **At start:** nothing listens. Devices use their local method, break-glass works, and
    port49d waits up to `start_timeout`, then exits 1.
  - **While running:** commands are refused `store_unavailable` within `packet_deadline`, at once
    after the circuit opens (`port49_store_circuit_open` 1), and break-glass is refused (L4).
    After `hold_ttl` port49d stops, saying `lost this port49d's hold …`, and devices fall to local
    (break-glass works). The supervisor restarts it, it waits for etcd, then serves, and sessions
    resume on their contexts. L35 has the per-image detail.
- **New metrics:**
  - `port49_store_calls_total{component,pool,outcome}`, `port49_store_call_seconds{component,pool}`,
    `port49_store_circuit_open{component,pool}`;
  - `port49_store_keyspace_held`, `port49_crypt_store_key_unknown`.

  Alert on a circuit open, on `port49_store_keyspace_held` 0 while port49d runs, on
  `port49_crypt_store_key_unknown` 1, and on any `increase(port49_crypt_open_failures_total{record="token"}[10m])`.
- **Key rotation across a restart.** Keep `encryption.previous` until the old key's records
  expire. A start that finds the store last written under a key it does not hold says so and sets
  `port49_crypt_store_key_unknown` to 1. A record that will not open is named by its key id on
  stderr, once per 10 minutes.
- **`port49 token` behind a slow `port49 revoke`** now says `your revocation sent at … is still
  running on the broker; nothing was minted; run port49 token again once port49 revoke reports`
  (exit 1), not `the broker … is unreachable`.
- **New command: `port49d store-roles [--config FILE]`.**

## Self-review against the spec

**Coverage.** Each item the roadmap and the carries name, and the task that builds it:

- **The 7d bullet:**
  - **"the backend D1 chooses, implementing every store method with its atomicity and passing
    every storetest property, 7a's included"** — Tasks 5–8. `TestTheEtcdStoreHoldsEveryProperty`
    runs `storetest.Run`, which holds 7a's (`IdempotencyReservesOnce`, `IdempotencyLeaseExpires`,
    `TokenIndex`, `RevocationMarks`), 7c's, and the lifted thirty-one (Task 2).
  - **"store-native mutual-TLS authentication per component"** — Task 11 (identities and roles),
    Task 12 (two stores in port49d).
  - **"a hard timeout and a circuit breaker on every store call, and pool separation"** — Task 9
    (guard); Task 11 (two connections).
  - **"plan 4b's remote-store items":**
    - a deadline on each refresh and per-packet store call: Task 9 (`call_timeout`) and Task 10
      (`packet_deadline`);
    - the settle pass's redeem-to-write: Task 10, `packet_deadline` ≤ 4 s ≪ 30 s;
    - unindexed contexts invisible to the refresh: Tasks 3–4 (`SwapLogin`).
  - **"PR #7's third follow-up"** — Tasks 3–4; `LoginsRaceToOneIndex`.
  - **"the crypt_open_failures_total{record="token"} alarm"** — Task 13; the design §15 alert,
    Task 1.
- **7a's carry:**
  - **"IdempotencyReservesOnce, TokenIndex, RevocationMarks for the chosen backend"** — Task 8.
  - **"whether broker.revocations_file stays"** — Ruling 13, Task 12.
  - **"the revocation's residual window … closed atomically"** — Tasks 3–4;
    `JoinHonoursAStandingMark`; §5.1.4 (Task 1).
- **7c's carry:**
  - **"DeleteTokenRemovesOne and DeleteTokenRacesRedeem on the etcd backend; its M-2 case"** —
    Task 5 (Ruling 3: the expired put is accepted; no clock-advancing constructor needed).
  - **"DeleteToken's index semantics"** — Ruling 5; Task 5 (`DeleteToken` never prunes).
  - **"the self-revocation's compare-and-set on the backend's SetContextPolicy"** —
    `SelfRevocationBindsToTheRead` (Task 3), run on etcd from Task 6.
  - **"the agent's single held connection"** — Task 14.
- **Design §12 "Store health MUST NOT be wired into the readiness probe":** unchanged. The
  metrics `/readyz` and the broker's `/readyz` read nothing of the store. The hold's stop is a
  process exit, which is go-dark's owner-ruled form, not a readiness signal.
- **Device behaviour:** L35, opened in Task 1 and closed in Task 15.

**Placeholders.** Three places name a helper to read rather than reprinting its code, because
the code is in the tree and the plan must not drift from it:
- Task 2's verbatim move, with its substitution rules;
- the run-test helpers in Task 12;
- the lab helpers in Task 15.

Every new function is written out. The guard's forty-three pass-throughs are shown by pattern
with three examples, and pinned by `TestEveryMethodHasAPool` and `TestTheGuardHoldsEveryProperty`.
`notbuilt.go` lists every stub by name and is pinned by the interface assertion.

**Types.** These names are the same in every task that uses them:
- `store.LoginWrite`, `store.MarkRead`, `store.LoginIndex`, `store.SwapLogin`,
  `store.PurgeTokens`, `store.ErrUnavailable`, `store.BlankCertKey`, `store.CheckRevocation`;
- `etcd.Config`, `etcd.Open`, `etcd.Roles`, `etcd.Grant`, `etcd.RoleDaemon`, `etcd.RoleBroker`,
  `(*etcd.Store).CheckIdentity`, `Hold`, `Sweep`, `SealKeys`, `PutSealKeys`;
- `guard.Wrap`, `guard.Config`, `guard.Metrics`, `guard.PoolOf`;
- `config.StoreConfig`, `config.EtcdConfig`, `config.StoreOf`;
- `Broker.SupersededAll`, `Broker.RefreshAtStart`, `RefreshReport.Contexts`;
- `agent.RevocationRunningError`, `wireWait`.

`etcdtest.Grant` and `etcd.Grant` are deliberately two types, so `etcdtest` never imports
`etcd`, which would be a cycle with `etcd`'s internal tests. Every caller converts.

**Review Focus.** Each line's test is in the task it names.

**Reason codes.** None added. A timeout, an open circuit, a saturated pool and a refused role
are all `store_unavailable`.
