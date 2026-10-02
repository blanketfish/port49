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
- **No field a login or an authorization trusts is written in the clear.** The sealing layer
  seals, each bound to the record's own key:
  - the whole context record (privilege, ceiling, policy, clocks and revocation, beside the
    identity it sealed already);
  - every field of a token a login copies into its context (privilege ceiling, policy blob,
    enable mechanism, session age, the clocks, the kind and the expiry);
  - and a receipt, its first redemption included.

  The daemon also reads the standing revocation marks on every request, and keeps an
  in-process ledger of the `ctx_id` it last wrote at each key. So a stolen daemon store
  credential cannot forge a token or a context, raise a privilege, lift a revocation by
  principal or certificate, move a record to another device, or, while port49d runs, put
  another login's context back. What it can still do is replay, stated exactly in Ruling 17.
- **A store that does not answer is a store that is down.**
  - **Deadlines.** Every store call has a hard timeout, and every TACACS+ packet's store work
    has its own deadline, which never shortens the brute-force delay.
  - **Pools.** Three pools each have their own slots and circuit breaker: token, context
    (design §12), and bulk, for the scans.
  - **Going dark.** A port49d whose store has been gone for `hold_ttl` closes every listener and
    waits for it again, in-process, as at a start.
- **Store-native mutual TLS per component** (design §17).
  - **Identities.** The daemon and the broker each authenticate to etcd with their own client
    certificate, under roles port49 prints (`port49d store-roles`).
  - **The start check.** port49d refuses to start when its roles are not in force.
  - **Certificates.** An expired or wrong certificate is named, never read as "etcd not
    answering".
- **port49d on etcd.**
  - **One port49d per keyspace** until plan 7e, behind a hold that is a fence. A second one
    waits with its listeners closed.
  - **A start** puts the revocations file's marks into the store and applies every standing
    mark to the live contexts the store kept. It purges unspent tokens, then carries the policy
    in force into every kept context, all before TACACS+ binds.
  - **Live sessions survive a restart.**
- **The `crypt_open_failures_total{record="token"}` alarm.** A record that will not open is named
  by its key id on stderr. A start whose store was last sealed under a key this configuration
  lacks says so.
- **The agent's single connection.** Every request the agent sends on its held connection waits
  its turn. One queued behind a slow revocation is told that the revocation is still running,
  never that the broker is unreachable.
- **Lab.** A new register row, L35. It measures what each image does when port49d's store hangs,
  when port49d closes its listeners on losing the store, and when the store comes back. It is
  opened and closed on beehive, on five images.

**Architecture:**
- **One backend, two clients per component.** `etcd.Open` builds two etcd clients, a token pool
  and a context pool, each its own gRPC connection.
  - **Records.** Each record is one key holding JSON with snake_case keys. Every compare-and-set
    is a transaction on the key's `mod_revision`.
  - **Expiry is logical.** A record carries its own expiry, read against port49d's clock. etcd
    leases only reclaim keys, in one-minute buckets, at least `lease_grace` after the expiry.
  - **Revisions.** `Rev` is the context key's `mod_revision`. `PolicyRev` is drawn from the same
    counter through a `policy_moved` flag the next non-policy write resolves.
  - **Indexes.** A ref's index record (`x/<nas>/<user>`) is authoritative. The lookup entries
    under a principal, a sid or a certificate only find candidates. They are filtered against
    the index record and cleaned by a sweep.
- **The seal.** `crypt.Wrap` seals a context whole, a token's trusted fields and a receipt,
  each with its record's key as the cipher's additional data.
  - **The ledger.** `crypt.Ledger` holds the `ctx_id` this process last wrote, or first read, at
    each context key. A record that opens at a key under another `ctx_id` is denied.
  - **Narrow setters.** A setter that changes a sealed field reads, opens, applies the store's
    rule (`store.Apply*`), seals and rewrites. It rewrites on the revision it read, through a
    new backend primitive, `RewriteContext`.
  - **Revocation.** `revoked_at` is also written in the clear, so a revocation needs no key.
  - **The marks.** The daemon keeps the standing marks in memory (`store.Marks`), with the
    store as their authority.
- **The guard.** `internal/store/guard` wraps any `store.Store`.
  - **Pools.** It routes each method to the `token`, `context` or `bulk` pool, each with an
    in-flight cap, a deadline and a breaker.
  - **Errors.** It counts a backend's `store.ErrUnavailable`, its own deadline and a caller's
    deadline as failures. It never counts a caller that went away or a refusal by the store's
    roles.
  - **Going dark.** It reports a token or context pool that has stayed failed, or stayed
    refused, for `hold_ttl`. The bulk pool's circuit alarms and never takes port49d dark.
  - **The stack.** Above it, the sealing layer: `crypt.Wrap(guard.Wrap(etcd store))`.
- **The login.** `store.JoinContext` reads the revocation marks for the login's principal and
  certificate before it decides. It hands the backend one `SwapLogin` carrying:
  - the context;
  - the index change (clear, drop, add);
  - and the marks as read.

  The backend writes all of it only while the context, the ref's index record and the marks are
  as read.
- **port49d.** `cmd/port49d/store.go` builds the daemon's and the broker's stores.
  - **The start wait.** It waits for etcd with every listener closed. Each attempt loads and
    checks the certificates, probes TLS, pings, and checks the roles.
  - **The hold.** It takes the keyspace hold, as the broker, and runs the index sweep.
  - **Going dark.** `run` loops: a store gone ends one run and starts the next, so once it has
    served port49d never exits for an outage. A start after a store gone retries any error.
  - **The broker** gains `ApplyMarksAtStart`, `RefreshAtStart`, `ReindexContexts` and
    `SupersededAll`.
  - **The agent** serialises every send on its held connection and knows when a revocation
    holds it.

**Tech Stack:**
- Go: the module's `go` line moves from 1.22 to **1.26**, because every current etcd release's
  `go.mod` says `go 1.26` (Owner decision OD-1).
- `go.etcd.io/etcd/client/v3` **v3.6.15**, with `concurrency` and `api/v3/v3rpc/rpctypes`, in
  the binary.
- `go.etcd.io/etcd/server/v3/embed` **v3.6.15**, in tests only: `internal/store/etcd/etcdtest`
  is imported by `_test.go` files and the lab, never by a binary.
- `go.uber.org/zap`, only for `zap.NewNop()`, to keep the client's JSON logs off port49d's
  stderr.
- All pure Go, with no cgo. Measured before this plan was written:
  - An embedded member was ready in 0.92 s under `CGO_ENABLED=0`.
  - A three-member embedded cluster with two members stopped timed out linearizable reads and
    writes at the deadline, and still served serializable reads.
  - A client-certificate CN was etcd's user. A role's prefix permission was enforced, even on a
    transaction that only compared a key outside it.
  - The pre-flight review compiled every etcd identifier this plan uses against v3.6.15 with
    `CGO_ENABLED=0`.
- containerlab on beehive for Task 15.

**Spec:**
- `docs/design/2026-08-23-policy-engine-spec.md`:
  - §5.1.4: revocation, the residual window.
  - §5.6: the login and the join (rewritten for the one step, Task 1).
  - §5.7: `store_unavailable`.
  - §12: tooling.
  - §13: decisions 15, 21, 24 (amended), 32, 34, and the new 35.
  - §14: required test assertions.
  - §15: the register rules; L4; L13; the new L35.
- `docs/design/2026-08-21-port49-design.md`:
  - §8: encryption at rest (the whole-record seal; the index as the exception).
  - §12: the failure model; Consequences ("Hard timeouts", "Circuit breaker", "Connection pool
    separation", go-dark); the store interface.
  - §13: token store topology.
  - §15: every stated alarm needs a metric.
  - §17: internal interfaces, "daemon, broker → token store"; the API's Errors.
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

## Pre-flight resolution

The pre-flight review (`.superpowers/sdd/2026-10-02-07d-shared-store/preflight-review.md`, on
`cd71242`) found 1 Critical, 19 Important and 49 Minor. The controller ruled on its §5 questions
on 2026-10-02 (the "Rulings on §5" in that directory's `progress.md`), each the option that denies
more; the owner may override any. One row per finding, saying what was done and where. **No
finding is skipped.** M29 is applied in part, with the reason in its row.

| # | Done | Where |
|---|---|---|
| C1 | A start applies every standing mark to the kept contexts before it carries the policy, with the listeners closed, retried while the store errs (`Broker.ApplyMarksAtStart`, 7a's two context passes per mark). The authorizer's marks (I12) close it at runtime as well. The CRL queue's first drain, after bind, is noted as a window. | Ruling 12; Task 12 Steps 3, 7; broker test and e2e; spec §14 and d35's start order (Task 8b) |
| I1 | `packet_deadline` is 100 ms to 2 s, citing L13. The failure delay sleeps on the server's context, which dispatch stashes, never on the packet's. A server test pins it. (The worst-case FAIL this row first stated, the two summed, is gone: Re-check 1's N1.) | Ruling 9; Task 10 Steps 1, 3; d35 (Task 8b) |
| I2 | Task 1 keeps only what 7d-1 builds. Everything else is in Task 8b, the first commit of 7d-2. | Task 1; Task 8b |
| I3 | §5.6 is rewritten: there are five ways, the unindex is one step with the write, and an ERROR may follow a committed write, so a retransmission replays or is `token_spent`. Review Focus 1 says the same. | Task 1 Step 3; Review Focus 1 |
| I4 | The failure matrix states port49d's side only, and every device cell cites L35 as open. Task 15 fills them in. | Task 8b Step 7; Task 15 Step 3 |
| I5 | As ruled: design §8 names the plaintext index as the exception, and the operator notes say to protect etcd snapshots like the store. | Ruling 18; Task 1 Step 6; Task 8b Step 9; operator notes |
| I6 | `alwaysConflicts`, `capturingStore` and `certReachStore` each override `SwapLogin`, and are named in `git add`. | Task 3 Steps 6–8 |
| I7 | `crypt_test.go:474`'s call gains `LoginIndex{}`, and the file is in `git add`. | Task 3 Steps 6, 8 |
| I8 | `TestALoginIsIndexedByItsOwnWrite` (an `IndexContext` that fails) fails before Task 4 and passes after. `swapLoginFails` is the second test. | Task 4 Step 1 |
| I9 | Each attempt loads the identities and checks their validity windows and the CA's. A named error says "expired", never "not answering", and so does a TLS handshake probe. Each start says the days to expiry, and `port49_store_client_cert_expiry_timestamp_seconds{component}` records it (named after `port49_crl_next_update_timestamp_seconds`). The gotcha and `Open`'s comment are corrected. | Task 5 gotchas, Step 4; Task 12 Step 5 (`identity`, `probeTLS`); metric |
| I10 | The guard reports a pool whose circuit stayed open, or whose every call was refused, for `hold_ttl`, and the run then goes dark (I19). It gains the outcomes `refused` and `deadline`, the caller's deadline counted as a failure. The slow-store line of "What the operator sees" (plan:398 at `cd71242`) is corrected. Guard tests for a slow store and for refusals, and the hung-store e2e, pin it. | Ruling 8; Task 9; Task 12 Step 6; "What the operator sees" |
| I11 | `stuck` blocks on a channel the test closes, and ignores ctx. The test releases it after the asserts, then waits. Mutation 2 is restated. | Task 9 Step 1, Step 4 |
| I12 | As ruled: the whole context record is sealed with the context key as AAD. The daemon reads the standing marks on every request (authorizer, enable gate, receipt replay). Tests cover a zeroed `revoked_at`, a raised privilege, a swapped blob, a removed ceiling, a transplanted record, and a replay under a mark. The per-command cost is one in-memory lookup. Migration: memory is wiped by the restart that installs 7d-1, and etcd has no contexts before 7d. The residual (a replay of an unmarked revocation) is stated and carried. | Ruling 17; new Task 4b; Task 6 (`RewriteContext` on etcd); d35 and design §8 (Task 1) |
| I13 | Store keys load through `keyfile.LoadX509KeyPair` in `openStores`. Config checks presence only. | Task 10 Step 2; Task 12 Step 5 |
| I14 | A third pool, `bulk` (`ActivePrincipals`, `DeleteReceiptsByPrincipal`, `ListRevocations`, `PurgeTokens`), has its own `bulk_timeout` (30 s), slots and circuit, apart from the hot pools'. The backend pages them. `PurgeTokens` reads and deletes a page at a time. | Ruling 8; Task 5 Step 8–9; Task 9; Task 10 |
| I15 | The hold is the broker's, and the daemon's role is read-only on `meta/`. The holder reads its lock key every ttl/6 and counts the hold lost when the key is gone or on another lease, or when etcd stops answering in time (the ⅔-ttl rule first written here is replaced by Re-check 1's R-I4). The waiting line says to stop the holder and never delete `meta/hold`. A test deletes the key. | Ruling 11; Task 11 (roles); Task 12 Steps 1–2 |
| I16 | As ruled: `store.backend: etcd` requires `admin_socket` at config load. | Ruling 13; Task 10 |
| I17 | The L35 test times each request from the capture (labpcap gains a packet time). It asserts no store-gone line by the end of step 3, or marks the cell invalid. It asserts the `store_unavailable` reasons, and commits itself in a `test(lab):` commit before the run. | Task 15 |
| I18 | Every send on the held connection takes the wire: `Connect` (agent.go:217), `Mint`'s `post` (:376), both of `refreshOnce`'s (:706, :757) under one hold, and `exchange` (:476). | Ruling 15; Task 14 |
| I19 | As ruled: losing the hold, or a pool failing for `hold_ttl`, ends one run, and `run` starts the next in-process. The listeners are closed, `/readyz` is 503 "waiting for the store", there is no deadline, and SIGHUP is caught across runs. `start_timeout: 0` waits forever on a cold start. | Rulings 11, 12; Task 10; Task 12 Step 7 |
| M1 | The checks name the sections a phrase must appear in, not a count. | Task 1 Step 8; Task 8b Step 13 |
| M2 | Every anchor is a one-line fragment that does not wrap. | Tasks 1, 8b |
| M3 | Design §19 step 2: both the "last not built" phrase and the closing clause are rewritten. | Task 8b Step 12 |
| M4 | `503 revocation_running` is added to design §17's Errors, as an agent-socket code. | Task 8b Step 11 |
| M5 | §12's `store-roles` paragraph lists the daemon's families exactly (no `tp/`, `tc/`, `id/`, and read-only `rv/` and `meta/`), with the Ruling 17 and 7e caveats. | Task 8b Step 4 |
| M6 | The L35 platform cell names vJunos-router and vSRX. | Task 8b Step 6 |
| M7 | Task 16 qualifies spec:8278–8283 ("a restart loses Junos contexts") as the memory backend's, citing L35. | Task 16 Step 2 |
| M8 | Task 8 Step 6 records 7d-1 as built before 7d-2. Task 16 adds an "As built" pointer on the 7d bullet and carries the decision-log emits under a hold and m10's `b.superseded` bound to 7e. | Task 8 Step 6; Task 16 |
| M9 | The mutation is "delete the mark loop". | Task 3 Step 7 |
| M10 | `CheckRevocation` refuses a zero `At`, so the file loader does too, through `PutRevocation`. `RevocationMarks` gains the case. | Task 3 Step 2 |
| M11 | Two more allowed substitutions: `storetest.Peek(` → `Peek(`, and `sweepEvery` → `1024`. | Task 2 Step 2 |
| M12 | "Thirty-one". | Task 2 |
| M13 | Only the storetest callers are deleted, and the six crypt-only tests are named and kept. The helper is `keys()`. | Task 2 Step 4 |
| M14 | The task and its commit say what changes on memory. | Task 3 Steps 6, 8 |
| M15 | The `unindex_ref` assertions become "the displaced principal's refs are 0". | Task 4 Step 1.4 |
| M16 | `reply, _ :=`. | Task 4 Step 1 |
| M17 | `DeleteReceiptsByPrincipal` deletes exactly the entries it read, a page at a time. | Task 5 Step 8 |
| M18 | An undecodable entry or record is an error naming its key, in `refsUnder`, `tokenKeys`, `eachIndexed`, `ListRevocations` and the sweep. A test pins it. | Tasks 5, 7 |
| M19 | `etcd.ErrTooLarge` (gRPC `ResourceExhausted`, `ErrRequestTooLarge`) is neither unavailable nor counted. | Task 5 Step 4; Task 9 `classify` |
| M20 | Every write of an index record prunes its expired entries. It is not a cap, which would cost revocation its reach. | Task 6 (`idxRec.prune`) |
| M21 | `go mod tidy` moves to Step 11. | Task 5 Steps 1, 11 |
| M22 | Lease times strip the monotonic clock, and a cached lease is reused only within a bucket of its grant. | Task 5 Step 6 |
| M23 | `mutate`'s comment and Task 8's note say it returns at the first read error. `PurgeTakesEveryToken` first runs in Task 6, and the commit says so. | Tasks 5, 6, 8 |
| M24 | `TestScannedKeysEndWithASlash` pins the schema directly. Task 7's mutation 3 points at it. | Task 5 Step 3; Task 7 Step 3 |
| M25 | `sweepLookups` reads a page's index records in batched transactions. | Task 7 Step 2 |
| M26 | `classify` reads the caller's context before the error, and Mutation 1 pins it. Under I10 a caller's *deadline* is counted (`deadline`) and a caller that went away is not (`canceled`). | Task 9 |
| M27 | Every `git add` names files. | Tasks 5, 9 |
| M28 | Restoring an etcd snapshot revives contexts a `revoke --mine` ended (no mark). The operator notes say so. | Operator notes |
| M29 | **In part.** Every member listens on `:0` with a `t.TempDir()` data dir, and the cost is noted. `StartCluster`'s peers cannot use `:0`, because the initial cluster must name them before they bind, so it retries once on "address already in use" instead. | Task 5 Step 2 |
| M30 | `PoolOf` has no default. A test drives every method through the guard and checks its pool's counter. | Task 9 |
| M31 | The new metric names are added to `TestNewRegistersEveryMetric`. | Tasks 9, 12, 13 |
| M32 | `CheckIdentity` probes writes with a never-true transaction, and a test grants the daemon a mark write. | Task 11 |
| M33 | The role check is part of each start-wait attempt: an outage waits, and a misconfiguration is named. | Task 12 Step 5 |
| M34 | `store-roles` refuses a CN or prefix outside `[A-Za-z0-9._@/-]`, with a test. | Task 11 Step 4 |
| M35 | `StoreOf` runs `staleSeedKeys`, and `main`'s comment names the subcommands. | Task 10 Step 2; Task 11 Step 4 |
| M36 | The guard's tests have no `TestMain`. The cluster test starts its own. | Task 9 |
| M37 | The restart e2e counts lines (`waitForCount`) and reads the newest addresses. | Task 12 Step 6 |
| M38 | `TestHold…`'s receive has a timeout. The second-port49d test cancels and waits for its run in Cleanup before `stderr` is restored. | Task 12 Steps 1, 6 |
| M39 | A store gone prints its own line, not "signal received". A signal during the waits returns nil, as `coldCopies` does. `run` returns the cause on every path. | Task 12 Step 7 |
| M40 | Task 13's file list drops `main.go`. | Task 13 |
| M41 | The union is a set difference on (kind, key). `countRevocations` covers the union. A store error in `restoreRevocations` on etcd is retried, not reported as a corrupt file. | Task 12 Step 7 |
| M42 | The test calls `Client.Token(ctx, TokenRequest{…})`, and the plan says `RevocationRunningError`. | Task 14 |
| M43 | Identity, explain and refresh behind a revocation are 503 `revocation_running` on the socket, rebuilt by the client. | Task 14 |
| M44 | One sayer is shared by every `Wrap`, its memory is bounded (64), and `SealedKeyID` keeps to the key-id charset. | Task 13 |
| M45 | `lab-instructions.md` is rewritten for 7d (done with this amendment), and Task 15 Step 0 checks it. | Task 15 |
| M46 | The seal-key line says this start ends those sessions, and what to do before the next start. | Task 13 Step 4 |
| M47 | `SupersededAll` across a host move with clock skew, and a dead process's pending reservation (≤ 1 min), are in the operator notes. | Operator notes |
| M48 | The lab cites CLAUDE.md rule 3. A lowered default is its own `fix(config):` commit, stays ≥ `call_timeout`, and re-runs every image. | Task 15 Step 2 |
| M49 | On a lost hold, `release` skips `Unlock` and orphans the session. vSRX is added to L35. | Task 12 Step 2; Task 15 |

### Re-check 1

The scoped re-check (the same file, "Re-check 1", on `2913dc7`) found 1 Critical, 7 Important
and 16 Minor. The controller ruled IA1 yes (an in-process ref→`CtxID` ledger) and every other
finding "apply the reviewer's fix" (`progress.md`, the Re-check 1 block). One row per finding.
**None is skipped.**

| # | Done | Where |
|---|---|---|
| CA1 | A token's `kind`, `expires_at`, `blob_hash`, `max_session_age`, `enable`, `max_privilege`, `auth_time` and `minted_at` are sealed in `tokenSecret` beside the secret and identity, with additional data = key id + token key + token ID. A token whose plaintext expiry differs from its sealed one is dropped as unopenable. A receipt is sealed with its whole receipt key (device, username, kind, credential hash) as additional data, and its `first_redeemed_at`, which anchors the cap, is sealed too. Every record family the daemon can write is audited in Ruling 17's table: sealed, or why it is safe. Ruling 17, decision 35, design §8, Ruling 10 and §12's store-roles text say what a stolen daemon credential yields. Tests tamper each sealed token field, transplant a token (another key, another ID) and a receipt (another kind), and replay a deleted token. | Ruling 17; Task 4b Steps 1, 4; Task 1 Steps 1, 6; Task 8b Step 4 |
| IA1 | `crypt.Ledger`: per context key, the `ctx_id` of the last write that landed (or the first read, so a start's reads seed it), plus writes in flight or of unknown outcome. A record that opens under any other `ctx_id` is `UnreadableContextError` wrapping `crypt.ErrNotLastWritten`. One ledger per process, shared by the daemon's and the broker's `Wrap` (`crypt.WithLedger`). The residual, impersonation by a record put back while port49d was stopped, is in Ruling 17, d35 and design §8, and carried. | Ruling 17; Task 4b Steps 1, 4; Task 12 Step 5; Task 13 Step 2; Task 16 |
| IA2 | New Task 7b. `(*etcd.Store).Unindexed` pages the `c/` family keys-only and names each ref whose `x/` record is gone or lists no live principal. `Broker.ReindexContexts` re-indexes each (`session.Manager.Reindex`), judges it against the policy in force, revokes one that will not open, and counts `port49_contexts_reindexed_total`. port49d runs it at start, before the marks are applied, and after every sweep. The residual (a sid revocation, and the refresh, miss it until the next sweep; the marks deny throughout) is stated. | Ruling 6; Ruling 17; Task 7b; Task 12 Steps 5, 7 |
| N1 | `dispatch` stashes the packet's arrival with the server's context, and `fail` sleeps until arrival + the delay, so store time is inside the delay, not added to it. The worst case is max(`packet_deadline`, delay), 2 s at the defaults; the throttle is unchanged. The residual is dropped. Test: a store spending 250 ms behind a 300 ms delay answers in under 500 ms. | Ruling 9; Task 10 Steps 1, 3; Task 8b Step 1 |
| R-I2 | `run`'s loop, once `again` is set, retries every error but a parent cancel, every 5 s, the listeners closed, and says it. `runLoop` is factored out and tested with a fake run. | Ruling 11; Task 12 Step 7 |
| R-I3 | `ApplyMarksAtStart` skips `UnreadableContextError` and `ErrNotFound` (the plaintext mark landed; unreadable is denied anyway); any other error but `ErrUnavailable` is said, not returned. A test with one unreadable context under a certificate mark. | Ruling 12; Task 12 Step 3 |
| R-I4 | The fence reads the lock key and the lease's remaining TTL (`TimeToLive`) every `hold_ttl`/6. Its estimate of the lease's expiry is the send time plus that TTL; it counts the hold lost once half of `hold_ttl` or less is left with no newer answer, at least `hold_ttl`/6 before etcd can expire the lease. The test's ordering assertion now has that margin. The window before going dark shrinks to at least `hold_ttl`/6 (10 s at the lab's 60 s), so L35's step 3 takes each measurement on a hang of its own. | Ruling 11; Task 12 Steps 1, 2; Task 15 |
| R-I5 | Only the token and context pools go dark; the bulk pool's circuit alarms (line and gauge). A refused run needs at least `breaker.failures` refusals with no gap longer than `open_for`; a longer gap starts a new run. Tests for both. | Ruling 8; Task 9 Steps 1, 2 |
| MA1 | "never past its sealed ceiling, if it has one; under `max_session_age: never`, indefinitely". | Ruling 17; Task 1 Step 1; Task 4b Step 4 |
| MA2 | crypt `SetRevokedAt`'s seal retries until the caller's deadline (64 attempts with none), and its error says the revocation is in force and the seal pending. | Task 4b Step 4 |
| MA3 | The etcd `GetContext` remembers the plaintext bookkeeping of the version it read (bounded); `RewriteContext` with no ttl on that revision commits without reading again. A setter's rewrite is two RPCs. A test reads, moves the record, and rewrites the stale version. | Task 6 Step 4b |
| MA4 | `TestARevocationOfAnUnopenableContextNeedsNoKey` is labelled a regression guard: it passes before 4b. | Task 4b Step 1 |
| MA5 | `TestTheSealCoversWhatAuthorizationTrusts` gains a flipped sealed byte and a same-key older ciphertext (the ledger's two cases: another login's, denied; the same `ctx_id`'s, admitted, the residual). The "no ceiling" case writes a plaintext ceiling the seal ignores. | Task 4b Step 1 |
| R-M0 | `server.Deps.Abort`: when it reports true at shutdown (a store gone), each held connection is reset (linger 0), as L28 measured the fast fall to local. The hung-store e2e holds one connection across the hang and reads a reset. | Task 12 Steps 6, 7 |
| R-M1 | The mark-at-start e2e asserts `(1 context(s) marked revoked)`. Mutation 1 now fails it. | Task 12 Steps 6, 7 |
| R-M2 | On a store gone the broker listener `bl` is closed before the line, and `brokerSrv.Close()` follows a `Shutdown` that times out. | Task 12 Step 7 |
| R-M3 | Said in `run`'s comment and the operator notes: between runs `/healthz` and `/readyz` are unbound for the drain and the config load (seconds), and counters restart; a liveness probe's failure window should exceed 30 s. Binding once in `run` would hold a metrics address across a config change. | Task 12 Step 7; operator notes |
| R-M4 | Ruling 12: "Steps 3 to 7 retry" (the reindex, the marks, the purge, the refresh). | Ruling 12 |
| R-M5 | Noted beside the gauge: an idle pool with an open circuit never evaluates going dark, which is harmless. | Task 9 Step 3 |
| R-M6 | 8b's deployment text keeps `Restart=on-failure` for a cold-start failure or a crash. | Task 8b Step 9; operator notes |
| m1 | `Mint` takes the wire per send and gives it back across its 409 Retry-After sleep. A test sends a revocation during that sleep. | Task 14 Steps 1, 2 |
| m2 | "Running the lab" names the pinned worktree `.worktrees/lab-7d` and copies captures back to the feature worktree, as `lab-instructions.md` does. | Running the lab |
| m3 | "It never exits for an outage" becomes "once it has served". | Rulings 11; Decisions; Task 8b Step 1 |
| m4 | §5.7's text names every call refused for `hold_ttl` among the go-dark causes. | Task 8b Step 3 |

## The split: two merges, one plan

This plan is **7d-1** (Tasks 1–8, with 4b and 7b) and **7d-2** (Tasks 8b–16). Each is its own branch
and pull request, and each leaves `make test` green. Nothing is cut; the split is only where the
review gate falls.

- **7d-1, `feature/shared-store-backend`, off `main`.** What 7d-1 lands:
  - the docs for what 7d-1 builds, and nothing more (Task 1);
  - the `storetest` suite lifted (Task 2);
  - the interface changes and their callers: the login's one step (Tasks 3–4);
  - the whole-record seal, the token's and the receipt's seal, the ledger and the standing
    marks (Task 4b);
  - the etcd backend, passing every property (Tasks 5–8), and the unindexed-context finder
    with the broker's re-index (Task 7b).
  - **What port49d does.** It still runs on the memory store, and the etcd client is linked
    by nothing until Task 12. Three things change on it:
    - an index failure now refuses the login, and a login whose principal or certificate is
      marked writes its context revoked (Tasks 3–4);
    - a context is sealed whole, a token and a receipt are sealed bound to their keys, a
      context opening under a `ctx_id` this process did not write there is denied, and a
      revocation is read from the marks as well as the record (Task 4b).

    Each fails closed. `ReindexContexts` is built and tested, and called by nothing until Task
    12.
  - **No device behaviour changes, so no lab.** The restart that installs 7d-1 wipes the memory
    store, so no token, receipt or context sealed the old way survives it.
- **7d-2, `feature/shared-store-port49d`, off `main` after 7d-1 merges.**
  - **What 7d-2 lands:**
    - the docs for what it builds (Task 8b, its first commit);
    - the guard, the config, the identities and roles, and port49d on etcd;
    - the crypt alarm and the agent;
    - the lab, and the as-built docs.
  - **Everything an operator meets at 3am lands here,** behind its own review.

**Why split.**
- **Size.** Nineteen tasks is above 7c's fourteen, and the backend alone is five.
- **What each half risks.** 7d-1 is correctness against properties, with no operational surface.
  7d-2 is operational behaviour, gated by L35. A reviewer can reject one and approve the other.
- **Docs follow the code.** Each half's docs land with its code. If 7d-2 slips, main says
  nothing about a `store-roles` command or a circuit metric that does not exist (pre-flight I2).
- **Fewer surprises for 7d-2.** 7d-2 is written against 7d-1's interfaces, which this plan
  fixes. The project rule ("write plan N+1 after plan N merges") is kept, because this is one
  plan: 7d-2's tasks consume exactly the names 7d-1's tasks produce, as any later task does.
- **If 7d-1's review changes an interface,** the controller amends 7d-2's tasks before
  dispatching Task 8b, and says so in the ledger (Task 8 Step 6).

## What this plan does not do

- **No second port49d on one keyspace, and no broker process.** Plan 7e builds:
  - the broker as its own process;
  - one refresh runner across replicas;
  - the listener's marks, and the daemon's (`store.Marks`), shared across replicas;
  - the ledger (`crypt.Ledger`) across replicas: per process, it would deny another replica's
    logins, so 7e shares it or replaces it (a sealed write sequence);
  - `b.superseded` and `b.blobsSeen` in the store.

  Until then a second port49d against the same keyspace waits (Ruling 11).
- **No go-dark proper and no warm context cache** (plan 7f). The one form of go-dark 7d builds
  is coarse:
  - a port49d whose hold on the store lapses, or whose store has failed for `hold_ttl`, closes
    every listener, so devices find the connection refused;
  - it then waits, in-process, until the store answers and it can start again (Ruling 11).

  7f adds the N-failures/M-passes listener control and the cache.
- **`broker.revocations_file` stays** (Ruling 13). Its retirement is 7e's.
- **No Valkey, Redis, PostgreSQL or DynamoDB backend.** The interface stays pluggable.
- **The decision-log emits under a policy hold** (4b Task 4) stay 7e's, as the roadmap has them.
- **No bulk lift.** It stays on the unassigned list (7c).
- **Spec, unassigned: a `revoke` record for a mark that could not be written** (7c final review
  M3). It is untouched. A store outage is now loud on stderr and in metrics (Task 9), which
  narrows what M3 costs.
- **Spec, unassigned, new: replay by a stolen daemon store credential** (Ruling 17's
  residual, listed there exactly). Within a running port49d it is an earlier version of the
  context a key holds now (the same `ctx_id`), which undoes a self or key revocation (no mark;
  decision 34) or a policy narrowing until the next refresh. Across a restart it is
  impersonation: a context of another login put back while port49d was stopped is taken as the
  key's at the start. Closing it needs a revocation record the daemon's role cannot write for
  every kind (a spec change to decision 34) and a sealed freshness counter checked across
  restarts. Task 16 carries it.

## Rulings where the design and spec are silent

Each takes the option that denies more, is written into the tasks named, and is recorded in spec
§13 as decision 35: 7d-1's part by Task 1, 7d-2's by Task 8b. Rulings 6–13 and 17–18 include
the controller's rulings of 2026-10-02 on the pre-flight review's questions (I1, I5, I12, I16,
I19) and on its re-check (CA1, IA1, IA2, N1, R-I2 to R-I5). The owner may override any of them. The ones the owner should read first are under
"Decisions for Ryan".

1. **etcd v3.6.15, and Go 1.26.** D1 is the owner's (2026-10-02). v3.6 is the current stable
   series, and every release since v3.5.21 says `go 1.26` in its `go.mod`, so the module's `go`
   line follows (OD-1). The client is linked into `port49d`; the server (`embed`) only into test
   binaries.
2. **Tests get etcd in process, never from docker.** `etcdtest` starts real etcd members from
   `go.etcd.io/etcd/server/v3/embed` inside the test binary.
   - **What it starts.**
     - One shared member per package (`etcdtest.Main`), with a fresh key prefix per store, so
       each property gets an empty keyspace without a restart.
     - A member of a test's own, with TLS, client-certificate authentication and roles
       (`Start`).
     - Three members, for quorum loss (`StartCluster`).
     - An in-process TCP proxy that can stop answering (`NewProxy`).
   - **Why.** `make test` stays runnable on a laptop with no docker, under `CGO_ENABLED=0`. It
     exercises the real server (Raft, MVCC, RBAC), not a fake. The lab uses the same members, so
     beehive needs no etcd image.
   - **The cost.** A larger module graph, about a second per started member, and 20–40 s more
     `make test`.
3. **Expiry is the record's, read against port49d's clock.**
   - **The lease.** Each record holds its own expiry, as the memory store's do, and a read past
     it is `ErrNotFound`. etcd leases only reclaim keys: a record is put on the lease of the
     one-minute bucket that ends at least `lease_grace` (5 m) after its expiry.
     - So a lease never reclaims a record before it is dead to port49d.
     - Skew between port49d and etcd costs nothing, since a lease's TTL is a duration.
     - A cached lease is judged on the wall clock without its monotonic reading, and reused only
       within one bucket of its grant, so a suspended host costs a grant, never a short lease
       (pre-flight M22).
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
     again on a lost race, until the call's deadline, and returns at once on a read that fails.
   - **The revisions.** `Rev` is the context key's `mod_revision`. `PolicyRev` comes from the same
     counter: a policy-relevant write sets `policy_moved`, and the next write that is not one
     stores the `mod_revision` it read as `policy_rev`. So `PolicyRev` moves only on what the
     refresh decides, and never repeats.
   - **`DeleteToken`** keeps the token index's entries, as 7c ruled. The etcd backend never
     prunes them, so it cannot hide a second live token under the key.
6. **The ref's index record is authoritative.**
   - **The record.** `x/<nas>/<user>` holds every principal, sid and certificate the ref is
     indexed under, each with its own expiry, and an extension restamps them all. Every write of
     the record drops its expired entries (pre-flight M20). That is not a cap: a live entry is
     never dropped to bound it.
   - **Lookup entries.** `ip/<principal>/<ref>`, `is/<sid>/<ref>` and `ic/<cert>/<ref>` exist so a
     revocation can find refs without a scan. A lookup answers only the refs whose index record
     still lists that key, live.
   - **The invariant.** A lookup entry is written in the same transaction that lists its key, and
     deleted only once the key is unlisted (`Sweep`, Task 7), so a revocation never misses a ref
     the index record holds.
   - **Escaping.** Keys escape every part, so `user:al` never matches `user:alice`.
   - **Undecodable records.** A lookup entry or record that does not decode is an error naming
     its key, never skipped: skipped, a revocation would miss a live context (pre-flight M18).
   - **A context the index lost** (re-check IA2). A login writes a context and its index record
     in one step, and every extension carries both, so a live context with no live principal
     in its `x/` record has had that record deleted in the store. The refresh walks the index,
     so it would never judge that context again, and `revoke --mine` and a revocation by sid
     would miss it. So `(*etcd.Store).Unindexed` pages the `c/` family keys-only (the daemon's
     role reads it) and names each such ref. `Broker.ReindexContexts` then:
     - re-indexes it under its own principal, sid and certificate;
     - judges it against the policy in force at once;
     - revokes one that will not open, since nothing can index it;
     - counts `port49_contexts_reindexed_total` and says how many.

     port49d runs it at start, before the marks are applied, and after every sweep (Task 12).
     Until then a revocation by principal or certificate still denies it through the marks.
7. **The login is one step** (`store.SwapLogin`).
   - **What it carries.** It carries:
     - the context write;
     - the index change the join decided (clear the ref, drop a sid or certificate, add the
       login's);
     - and the revocation marks the login read for its principal and certificate.

     The step lands only while the context, the ref's index record and those marks are as read;
     otherwise `ErrConflict`, and `JoinContext` reads and decides again. A mark that stands, for
     a token not minted after it, is carried into the context as its revocation.
   - **What it closes.** PR #7's third follow-up; 4b's unindexed context; 7a's residual window
     for a revocation by principal or certificate. Decision 32 writes the mark first, so any
     login after it sees it, and one before it is reached by the second pass.
   - **What it leaves.** A self or key revocation leaves no mark, so its residual window of one
     round trip stays, as 7c's §5.1.4 text says.
   - **An ERROR after the spend** (pre-flight I3). A `SwapLogin` whose answer is lost to a
     deadline may still have committed. Its context is then indexed, so revocable, and the
     device's retransmission replays the receipt. If it did not commit, the retransmission is
     `token_spent`. Either way no context is live and unindexed. Spec §5.6 says this (Task 1).
   - **What changes for the operator.** A login whose index cannot be written is now refused
     ERROR `store_unavailable`, where it was a PASS with `index_error`: a context that no
     revocation can reach is never written.
8. **The guard.**
   - **Pools.** Methods are pooled by the table in Task 9.
     - **`context`:** the authorization path, every context record and blob read.
     - **`token`:** mints, redemptions, receipts, idempotency and marks.
     - **`bulk`:** the four scans, `ActivePrincipals`, `DeleteReceiptsByPrincipal`,
       `ListRevocations` and `PurgeTokens` (pre-flight I14). A slow scan over a large keyspace
       times out and trips its own circuit, never the context pool that holds `SetRevokedAt`.
       The backend pages each scan.
   - **Deadlines and slots.**
     - `token` and `context` calls each have `call_timeout` (500 ms).
     - `bulk` calls have `bulk_timeout` (30 s).
     - A call waits for an in-flight slot only within its deadline, then is refused: a queue is
       worse than a refusal (design §12).
   - **The breaker.** After `breaker.failures` (5) consecutive failures, a pool's circuit opens
     for `open_for` (5 s), then lets one call probe. A probe that fails opens it again.
   - **What counts as a failure.** Any of:
     - the backend's `store.ErrUnavailable`;
     - the guard's own deadline;
     - a caller's deadline that struck mid-call, outcome `deadline`: on the daemon, a packet's
       `store.packet_deadline`. A store slow enough that each call is under `call_timeout` but a
       packet's sum is over its deadline therefore still opens the circuit (pre-flight I10).

     Never a failure: `ErrNotFound`, `ErrConflict`, `ErrPastGrace`, `ErrTooLarge`, a refusal by
     etcd's roles (outcome `refused`), or a caller that went away (`canceled`).
   - **Going dark.** A token or context pool whose circuit has stayed open for
     `store.etcd.hold_ttl`, or whose every call in that time was refused (a role revoked at
     runtime), is reported once. port49d then ends the run as on a lost hold (Ruling 11).
     - **A refused run** is at least `breaker.failures` refusals with no gap between two longer
       than `breaker.open_for`. A refusal after a longer gap starts a new run, so two refused
       calls an hour apart are not "refused for `hold_ttl`" (re-check R-I5).
     - **The bulk pool never takes port49d dark** (re-check R-I5). A slow scan at scale is not
       a store gone while the token and context pools answer. Its circuit alarms instead: the
       line, and `port49_store_circuit_open{pool="bulk"}`.
   - **Saying it.** A circuit that opens or closes is one line on stderr and a gauge.
9. **Every TACACS+ packet's store work has a deadline,** `store.packet_deadline` (2 s; 100 ms to
   **2 s**, and at least `call_timeout`).
   - **The bound** is L13's: the Junos images time out a reply at about 3 s
     (`tests/lab/results/L13-*.md`), which is why `auth_failure_delay_max` defaults to 2 s
     (pre-flight I1). A reply later than that reads, on vJunos with `password` in its
     authentication order (L4), as a dead server, and the device falls through to its local
     password.
   - **The device.** It hears port49's FAIL or ERROR before its own TACACS+ timeout, so a hung
     store reads as `store_unavailable`, never as a silent server. L35 measures it.
   - **The refresh.** A redemption's write lands well inside 4b's 30 s settle pass (4b final
     review m3).
   - **The failure delay.** The deadline never shortens it. The delay sleeps on the server's
     context, which dispatch keeps beside the packet's, so `packet_deadline: 100ms` does not
     turn a 2 s brute-force delay into 100 ms.
   - **The delay counts from the packet's arrival** (re-check N1). dispatch stashes the
     arrival with the server's context, and a FAIL sleeps until arrival plus the delay. The
     store work is inside the delay, not added to it, so a FAIL's worst case is
     max(`packet_deadline`, delay): 2 s at the defaults, under Junos's 3 s. The throttle is
     unchanged: each failure still costs its sender the whole delay from its send.
   - **4b's other remote-store item,** a deadline on each refresh call, is the guard's
     `call_timeout`.
10. **Each component has its own identity on etcd** (design §17).
    - **The certificates.** `store.etcd.daemon` and `store.etcd.broker` name a client
      certificate each. etcd authenticates the CN as its user, and `port49d store-roles` prints
      the `etcdctl` commands that create the two roles and grant them.
    - **The daemon's role cannot** read or write idempotency records, write the token indexes,
      write revocation marks, or write `meta/` (the keyspace hold and the seal-key record). With
      the seals, the ledger and the marks (Ruling 17), a compromised daemon credential cannot:
      - forge a token, a receipt or a context, or raise a privilege past what port49 wrote;
      - lift a revocation by principal or certificate;
      - hide a token from one;
      - take the keyspace.

      What it can still do, record family by record family, is Ruling 17's table.
    - **The start check.** port49d probes that its daemon identity is refused, and its broker
      identity allowed, a read of the idempotency records and a write of each family only the
      broker may write (a transaction whose compare never holds, so it writes nothing). It
      refuses to start otherwise, unless `store.etcd.roles: unenforced` is set, which it says at
      every start, as `certificate_status.disabled` is said.
    - **Transport.** Endpoints are `https` only. Key files load through `internal/keyfile`, which
      refuses a symlink, a group- or other-readable mode, a foreign owner and an oversize file
      (pre-flight I13). Each start checks every certificate's validity window, and the CA's, and
      probes the TLS handshake. An expired or wrong certificate is named for what it is, never
      read as "etcd not answering" (pre-flight I9).
11. **One port49d per keyspace until 7e.**
    - **The hold.** port49d holds `meta/hold` on an etcd session lease of `hold_ttl` (15 s), as
      the broker identity, and writes who holds it.
    - **A fence** (pre-flight I15; re-check R-I4). Deleting the lock key does not end a
      session, so every `hold_ttl`/6 the holder reads the key and the lease's remaining TTL. Its
      estimate of when the lease expires is the read's send time plus that TTL, which is never
      later than etcd's. It counts the hold lost when:
      - the key is gone or on another lease (deleted by hand, or the lease reclaimed);
      - the lease has expired, or the session ends;
      - or, with no newer answer, the estimate has `hold_ttl`/2 or less left. Checks are at most
        `hold_ttl`/3 apart, so that is at least `hold_ttl`/6 before etcd can expire the lease
        and let a second port49d take the keyspace (2.5 s at 15 s).

      A process paused past that is the residual: its next read finds the key gone.
    - **A second port49d** waits, with every listener closed, naming the holder every 30 s and
      saying to stop that port49d to move the keyspace, never to delete `meta/hold`.
    - **Losing the store.** The hold is lost, or a pool has failed or been refused for `hold_ttl`
      (Ruling 8). port49d then:
      1. closes every listener and says why;
      2. drains, as at shutdown;
      3. starts again in-process: it waits for the store with the listeners closed and
         `/readyz` 503, with no deadline, then runs the start (Ruling 12) and serves.

      Devices find the connection refused meanwhile and use their local method, as the owner
      ruled for a store outage (2026-09-24). No service manager is needed to come back from an
      outage (pre-flight I19; the controller's ruling). Plan 7f replaces this with go-dark
      proper.
    - **A start after a store gone retries every error** (re-check R-I2), not only a store
      fault: a policy file caught half-written during the outage, the broker's role refused on
      `meta/`, anything but port49d being stopped. It says the error every 5 s with the
      listeners closed. So once port49d has served, it never exits for an outage. A cold start
      still exits 1 on a fault or at `start_timeout`, for a supervisor's `Restart=on-failure`.
12. **A start on etcd.**
    - **The store.** port49d waits for etcd with every listener closed. Each attempt:
      1. loads the identities (keyfile) and checks their validity windows and the CA's;
      2. probes the TLS handshake, then opens, pings, and checks the roles (M33).

      An outage is retried every 5 s; a cold start gives up at `start_timeout` (30 s; 0 is
      forever) and exits 1, naming the endpoints.
    - **A configuration fault** (an expired or wrong certificate, a CA that does not verify,
      roles not in force) is named at once. A cold start exits 1 on it. A start after a store
      gone says it every 5 s and retries, re-reading the files, so a renewed certificate or
      applied roles are picked up without a restart.
    - **Then, in order,** with the listeners still closed:
      1. it takes the hold;
      2. checks the seal-key record;
      3. restores the revocations file's marks into the store (a mark in either stands);
      4. re-indexes every kept context the index lost (Ruling 6; re-check IA2);
      5. **applies every standing mark to the contexts the store kept**, through 7a's two
         context passes (pre-flight C1);
      6. purges every unspent token (a restart purged them on the memory store too, and no
         policy port49d loaded judged them);
      7. carries the policy in force into every kept context (`Broker.RefreshAtStart`).

      Steps 3 to 7 retry every 5 s while the store errs (re-check R-M4).
    - **A kept context that will not open does not stop a start** (re-check R-I3). Applying a
      certificate mark reads each context it reaches. One sealed under a key this window lacks
      is still marked, since a revocation needs no key, and is denied as unreadable anyway; so
      it is skipped, never fatal. Any other error but an outage is said and skipped too: the
      daemon's marks deny that context on every request regardless.
    - **Replays.** Every key is marked superseded at the start instant (`Broker.SupersededAll`),
      so an idempotent replay re-mints rather than handing back a deleted token.
    - **The marks, at runtime too.** The daemon's in-memory marks (Ruling 17) are loaded before
      any listener binds, so a context step 5 could not reach is denied anyway.
    - **The ledger is seeded before any listener binds.** Steps 4, 5 and 7 read every kept
      context through the sealing layer, so the ledger (Ruling 17) holds each key's `ctx_id`
      before the first device connects.
    - **One window.** A certificate a kept CRL newly names is marked by the certificate-status
      queue's first drain, which starts after the listeners open (`crl.go:184-196`). Until that
      drain, seconds after bind, its kept contexts answer. A revoked certificate is still
      refused at mint and at refresh throughout (decision 33).
    - **Then it serves.** Live sessions continue across the restart.
13. **`broker.revocations_file` stays in 7d, and etcd requires `admin_socket`.**
    - **The union.** With etcd, the store and the file are a union at start. A mark lifted
      while its save failed comes back at the next start, which fails closed. The start line
      counts the marks that came only from the store, as a set difference on (kind, key).
    - **The lift path.** On etcd, stopping port49d and editing the file no longer lifts a mark,
      because the store's copy comes back. So `store.backend: etcd` requires `admin_socket` at
      config load, where `port49 revoke --lift` runs (pre-flight I16; the controller's ruling).
    - Retiring the file is 7e's.
14. **The crypt alarm.**
    - **The line.** A record that will not open is said once per `(record, key id)` per 10
      minutes, naming the key id and what to do.
      - The key id is the sealed header's, never a secret, and only within the key-id charset,
        since the header is the record's.
      - One sayer serves every sealing layer, and its memory is bounded.
      - This is beside `port49_crypt_open_failures_total{record}`, unchanged.
    - **The seal record.** On etcd, port49d records its current and previous key ids in
      `meta/seal_keys` at each start, as the broker. A start whose recorded current key is
      outside its own window:
      - warns, and sets `port49_crypt_store_key_unknown` to 1;
      - says this start ends the sessions it cannot read, and what to set before the next start;
      - still starts.

      Records it cannot open already fail closed, and refusing to start would turn a key-config
      mistake into a fleet-wide AAA outage.
15. **The agent's single connection.**
    - **One exchange at a time.** Every send on the held connection takes a one-slot "wire"
      semaphore, and the agent knows when a revocation holds it. The sends that take it
      (pre-flight I18):
      - `Connect`;
      - `Mint`, per `post`, given back across a `409`'s Retry-After wait (re-check m1);
      - `Refresh`'s challenge and answer, under one hold since they share a connection;
      - every `exchange` (identity, explain, revoke).
    - **Behind a revocation.** A call arriving then waits within its own 30 s. If the
      revocation still holds the wire, it fails with `*RevocationRunningError`. The socket
      answers it `503 revocation_running` on `/token`, `/refresh`, `/identity` and `/explain`,
      and `port49 token` says the revocation is still running and nothing was minted.
    - **Not built.** No second connection (a design change, 7c's final review), and no HTTP/2.
16. **L35 is opened and closed by this plan,** on vEOS, the N9Kv, the C8000V, vJunos-router and
    vSRX. vSRX is the owner's production platform, and L34 measured it (pre-flight M49).
    - **The store.** An embedded etcd with TLS and roles in the lab test process, behind an
      in-process proxy that can hang it.
    - **What it measures:**
      - what a device sees when the store hangs, each request's latency taken from the capture
        (pre-flight I17);
      - what it sees when port49d closes its listeners on losing the store;
      - what it sees after the store returns and port49d serves again.

      Nothing in the design is asserted about it before the row closes.
17. **No field a login or an authorization trusts is written in the clear; the daemon reads the
    standing marks and keeps a ledger** (pre-flight I12; re-check CA1, IA1; the controller's
    rulings: a stolen daemon store credential must not un-revoke a context, raise its
    privilege, or pass for another login).
    - **The context, sealed whole.**
      - **What is sealed.** Every field the authorizer trusts, under the encryption key: the
        identity and credential, as before, and now `priv_lvl`, `blob_hash`, `max_privilege`,
        `enable`, `auth_time`, `session_expires`, `refreshed_at`, `created_at` and
        `revoked_at`.
      - **Bound to its key.** The cipher's additional data is the key id and the context key
        (device and username), so a record moved to another key will not open.
      - **What stays in the clear.** The plaintext copies are blank, except `revoked_at`, which
        is also kept in the clear so a revocation needs no key; a read takes the later of the
        two. Also plaintext, and trusted by nothing: the revisions, the idle clock
        (`last_touched_at`) and accounting's annotations.
    - **The token, sealed with its key** (re-check CA1). A login copies a token's fields into
      its context (authen.go:705-724), and the context seal then seals them faithfully, so the
      token is where they must be sealed first.
      - **What is sealed** in `tokenSecret`, beside the secret, principal, username and
        credential: `kind`, `expires_at`, `blob_hash`, `max_session_age`, `enable`,
        `max_privilege`, `auth_time` and `minted_at`. A redemption reads `kind` and the ceiling
        (`auth_time` plus `max_session_age`). A login copies the policy fields into its
        context. The join compares `minted_at` with a revocation (`CarryRevocation`), so a
        forged later one would leave a self or key revocation behind.
      - **Bound to its key.** The additional data is the key id, the token key (device,
        username) and the token ID. A token moved to another key or ID does not open.
      - **What stays in the clear.** The `id` (the handle the backend deletes by), and a copy of
        `expires_at`, which the backend expires by. A token whose plaintext expiry differs from
        its sealed one is dropped as one that will not open. The layer writes them equal, so a
        difference is a store write, and an extended plaintext expiry would otherwise be
        redeemable past the sealed one.
    - **The receipt, sealed with its key** (re-check CA1). The additional data is the key id and
      the whole receipt key (device, username, kind, credential hash). So a login receipt copied
      to the enable key does not open; copied, it would replay an escalation with no enable
      token. `first_redeemed_at`, which anchors the cap, is sealed too. Its plaintext copy stays
      for the backend and is not read.
    - **The setters.**
      - **Sealed fields.** `SetPrivilege`, `RefreshContext` and `SetContextPolicy` become
        read-open-apply-reseal-rewrite in the sealing layer: on the revision read, through
        `Store.RewriteContext`, with the rules shared as `store.Apply*`.
      - **`SetRevokedAt`** writes the plaintext mark first, keyless and in force at once, then
        seals it in, retrying a lost race until the caller's deadline. If the seal still has
        not landed, its error says the revocation is in force and the seal pending (re-check
        MA2).
      - **The rest.** `TouchContext` and `AnnotateContext` stay pass-through, so the
        per-command path costs no extra store call.
    - **The marks.** `store.Marks` is the daemon's in-memory copy, with the store as authority.
      - port49d loads it at start, before any listener binds.
      - The broker adds a mark once its write lands, and removes one once its lift does.
      - The authorizer, the enable gate and a receipt's replay deny a context whose principal or
        certificate a mark names, whatever the record says.
      - **The cost per command:** one read lock and at most two map lookups, and no store call.
        Its memory is the number of marks in force, as the listener's copy is.
    - **The ledger** (re-check IA1; the controller's ruling: yes). Without it, Bob could save
      Alice's sealed context for leaf-01/netops and, after his own login there, write it back.
      It opens, since it is bound to that key, and his session authorizes as Alice. The refresh
      does not help, because it judges Alice, who is still entitled.
      - **What it holds.** `crypt.Ledger` holds, per context key, the `ctx_id` of the last
        sealed write that landed there, or of the first record this process read there.
      - **A mismatch is denied.** A record that opens at a key under any other `ctx_id` is
        `UnreadableContextError` wrapping `crypt.ErrNotLastWritten`, and is counted as
        `crypt_open_failures_total{record="context"}`. The authorizer answers it
        `store_unavailable`, a login replaces it, and the refresh revokes it.
      - **Writes in flight.** A write in flight is admitted. So is one whose outcome is unknown
        (a deadline; spec §5.6) until a later write lands. A conflict or a not-found wrote
        nothing.
      - **One per process.** One ledger is shared by every `Wrap` (`crypt.WithLedger`), so the
        broker's reads and the daemon's agree. A start's reads (the re-index, the marks, the
        refresh) seed it before any listener binds.
      - **The cost.** One mutex and a map lookup per context read or write, and no store call.
        Its memory is one entry per key this process has read or written, kept while it runs:
        about 150 bytes each, 15 MB at 100,000 keys.
      - **A race.** A read racing a login's replace at the same key can return the replaced
        record after the replace landed. That one request is denied `store_unavailable`, which
        fails closed; before the ledger it authorized as the replaced context.
    - **Every family the daemon's role can write, and what a writer gains** (re-check CA1).
      This is everything a stolen daemon store credential yields. The broker's role holds the
      whole keyspace until plan 7e splits it out.

      | Family | In the clear | What a store write gains |
      |---|---|---|
      | `t/` tokens | `id`; a copy of `expires_at` | **Nothing forged:** every trusted field is sealed and bound. **Replay:** a token port49 minted for the same key and ID, deleted since (redeemed, or by a self or key revocation), can be put back and redeemed by a holder of its secret until its sealed expiry (the TTL it was minted with). An extended plaintext expiry drops it. |
      | `r/` receipts | `idle_expires_at`, `retain_until`, `failed`, a copy of `first_redeemed_at` | **`idle_expires_at`** stretches the replay window to the sealed cap (`first_redeemed_at` plus `receipt_max_age`), never past it. **`failed`**, zeroed, replays PASS only onto the live context with the receipt's `ctx_id`, whose own revocation and the marks are read again, the marks for the receipt's own sealed principal and certificate too, and only for a login that context's sealed witness (`Logins`) names and the index still reaches under that credential: what that principal's later token already granted. Every replay needs the credential. |
      | `rp/` receipt index | all | **Deleted:** a revocation by principal misses those receipts, and each replay still reads the live context and the marks, so it is denied. **Added:** a revocation deletes more, which is a denial. |
      | `c/` contexts | `revoked_at` (a read takes the later), the revisions, `last_touched_at`, accounting's annotations | **Nothing forged or moved.** **Replay in a running port49d** (the ledger): an earlier version of the context the key holds now, which has the same `ctx_id`, so the same principal and login. It undoes a self or key revocation of that context, or a policy narrowing, until the next refresh judges it. **Replay across a restart:** a context of any login port49 sealed for that key, put back while port49d was stopped, or before the start read it, is taken as the key's at the start; once the start seals the ledger, one put back at a key it has not seen is denied, and the ledger is kept across a start after a store gone. That is impersonation, until that record's sealed ceiling (if it has one) or the key's next login; a principal or certificate mark still denies it. **The idle clock:** a context can be kept alive past its idle TTL, to its sealed ceiling if it has one, and indefinitely under `max_session_age: never` (re-check MA1). The refresh still judges it, and every revocation reaches it. **Accounting's annotations:** clearing a context's session discriminators suppresses the `foreign` attribution of its accounting records (re-check 2 M-B2). |
      | `x/` index records; `ip/`, `is/`, `ic/` lookups | all | **Deleted, or rewritten to name another principal or another sid, or a lookup entry deleted:** the context is hidden from the refresh, `revoke --mine` and a revocation by sid until the re-index finds it, at the start and after each sweep (`sweep_interval`, 10 m; Ruling 6), by comparing the keys listed, each with its lookup entry in place, against the context's own sealed principal, sid and certificate. A revocation by sid in that window never reaches it; one by principal or certificate does, through the marks. **Added:** a revocation reaches a context it should not, which is a denial. |
      | `b/` blobs | all (no identity) | **Nothing:** a blob is checked against its sealed hash (`engine.Decode`), so an altered body is refused, which is a denial. |
      | `rv/` marks, `meta/` | read-only for the daemon | Nothing, under the daemon's role (Task 11), which is what makes "cannot lift a revocation by principal or certificate" true. Before that role a daemon credential holds the whole keyspace, marks included. |
      | `tp/`, `tc/` token indexes; `id/` idempotency | no access | Nothing. |

      Deleting a record, or making a write conflict, is a denial, never a grant. Task 16 carries
      the replay cells as an unassigned follow-up.
    - **Migration.** A token, receipt or context sealed before 7d-1 fails to open under the new
      additional data: a token is dropped, a receipt or context is denied, and a context is
      replaced at the next login. None survives in practice. The restart that installs 7d-1
      wipes the memory store, and etcd holds no record before 7d.
18. **The index stays plaintext, and an etcd snapshot holds it** (pre-flight I5; the controller's
    ruling). Revocation must not depend on the encryption key or its rotation window (the
    owner's ruling of 2026-09-21; crypt's package comment). So the index keys revocation reads
    stay plaintext: principal, device, username, certificate and sid. On a persistent store,
    every snapshot holds them. Design §8 names the index as the exception to "a store dump
    should not enumerate who was logged into which device", and the operator notes say to
    protect etcd's snapshots and backups as the store itself.

## Decisions for Ryan

**OD-1. The module's Go floor rises from 1.22 to 1.26.**
- **Why.** Every etcd release from v3.5.21 on, v3.6.15 included, declares `go 1.26` in its
  `go.mod`, so depending on it raises port49's `go` line. `CLAUDE.md`'s "Go 1.22+" becomes "Go
  1.26+".
- **Recommended default: accept** (D1 implies it). Task 1 edits `CLAUDE.md` and Task 5 the
  `go.mod`. The controller accepted it on 2026-10-02.
- **The alternative** pins an older etcd with known fixes missing, and is not recommended.
- **The plan proceeds on the default.**

**Worth reading before the merge** (rulings, not open questions; the controller's rulings of
2026-10-02 are marked, and the owner may override them):
- **Ruling 11.** Until 7e, one port49d per keyspace, so etcd gives persistence and the
  foundation, not yet HA. A Kubernetes rollout must use `Recreate`: a surge pod waits for the
  hold and is not ready.
- **Ruling 11's go-dark (controller, I19, R-I2).** When etcd is gone for `hold_ttl`, port49d
  closes every listener and waits in-process for the store, retrying any start error after
  that. Once it has served it never exits for an outage, and break-glass works meanwhile
  (L4). Keep `Restart=on-failure` for a cold-start failure or a crash.
- **Ruling 12.** A port49d restart purges every unspent token, as it always did on the memory
  store, so operators run `port49 token` again after a restart. Their sessions survive.
- **Ruling 7.** A login whose index write fails is now refused (ERROR), not admitted unrevocable.
- **Ruling 9 (controller, I1, N1).** `packet_deadline` is at most 2 s, and the failure delay
  is never cut by it. The delay counts from the packet's arrival, so a FAIL arrives within 2 s
  at the defaults, under Junos's 3 s.
- **Ruling 13 (controller, I16).** etcd requires `admin_socket`.
- **Ruling 17 (controller, I12, CA1, IA1).** The context, the token's trusted fields and the
  receipt are sealed, each bound to its key. The daemon reads the marks and keeps a ledger of
  the `ctx_id` it last wrote at each key. Ruling 17's table is what a stolen daemon credential
  still yields: replay, which across a restart is impersonation by a context put back while
  port49d was stopped.

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
  etcdctl role grant-permission port49_daemon read --prefix=true /port49/v1/meta/
  etcdctl role add port49_broker
  etcdctl role grant-permission port49_broker readwrite --prefix=true /port49/v1/
  etcdctl user add port49-daemon --no-password
  etcdctl user grant-role port49-daemon port49_daemon
  etcdctl user add port49-broker --no-password
  etcdctl user grant-role port49-broker port49_broker
  # then, if auth is not enabled yet: etcdctl user add root --no-password &&
  #   etcdctl user grant-role root root && etcdctl auth enable
  ```

  The user names are the CNs of the certificates the config names. A CN or prefix holding
  anything a shell would read is refused, and nothing is printed.
- **A config on etcd with no `admin_socket`** is refused at load: `config: store.backend etcd
  needs admin_socket: on etcd a mark is kept in the store as well as broker.revocations_file, so
  editing the file no longer lifts one; a lift is 'port49 revoke --lift' on the admin socket
  (decision 35)`.
- **The roles were not applied, or auth is off.** port49d refuses:

  ```
  port49d: store.etcd: the daemon's identity (CN=port49-daemon) has the broker's reach: it was
  allowed reading /port49/v1/id/: etcd's roles for port49 are not in force (auth disabled, or
  that user holds the broker's or root's role); run 'port49d store-roles --config …' and apply
  its output as etcd's root, or set store.etcd.roles: unenforced to run without them
  ```

  With `roles: unenforced` it starts, and says `port49d: store.etcd.roles: unenforced: the daemon
  and the broker are not separated on etcd; a stolen daemon key can lift revocations` at every
  start.
- **Every start says each certificate's expiry:** `port49d: store: the daemon's etcd certificate
  (CN=port49-daemon) is valid until 2027-01-01T00:00:00Z (91 days)`, and
  `port49_store_client_cert_expiry_timestamp_seconds{component}` carries it for an alert.
- **An expired certificate:** `port49d: store.etcd.daemon: certificate
  /etc/port49/etcd-daemon.pem (CN=port49-daemon) expired at 2026-10-01T00:00:00Z; renew it`.
  - **On a cold start,** port49d exits 1 at once.
  - **After a store gone,** the same line comes every 5 s, the listeners stay closed, and the
    renewed file is picked up without a restart.

  A CA that does not verify etcd's certificate, or a handshake etcd refuses, is named the same
  way. None reads as "not answering".
- **3am: etcd is down when port49d starts.**
  - Nothing listens, and `/readyz` says `waiting for the store`. Devices find TACACS+ refused
    and use their local method, so break-glass works (L4).
  - Every 5 s port49d prints `port49d: store: etcd at https://etcd-0:2379, … not answering
    (context deadline exceeded); the listeners stay closed; waiting up to 30s`.
  - Then `port49d: store: etcd at … did not answer within store.etcd.start_timeout (30s); not
    starting`, exit 1.
  - With `start_timeout: 0` it waits for as long as it takes.
- **3am: etcd loses quorum, or is cut off from port49d, while port49d runs.**
  1. **The first commands** wait out `call_timeout` and are answered FAIL `store_unavailable`
     within `store.packet_deadline` (up to `breaker.failures` per pool). Logins are answered
     ERROR. L35 measures what each image does with that answer.
  2. **The circuit opens.** `port49d: store: the daemon's context pool's circuit is open after 5
     consecutive failures (store: unavailable: context deadline exceeded); each call on it fails
     at once until a probe in 5s succeeds; devices see store_unavailable, and break-glass is
     refused (L4); port49d closes its listeners if the store is gone for store.etcd.hold_ttl`.
     From then on, refusals are immediate. `port49_store_circuit_open{component,pool}` is 1.
  3. **Within `hold_ttl`, port49d closes every listener:** `port49d: store: lost this port49d's
     hold on keyspace /port49/ (its lock key is gone, or etcd stopped answering with half its
     lease or less left); closing every listener so that devices use their local method`.
     Held TACACS+ connections are reset, not closed with a FIN (L28's fast fall to local).
     - Then: `port49d: store: …; every listener is closed; waiting for the store again, as at a
       start`.
     - Devices find TACACS+ refused. Open sessions' commands fall to local authorization,
       measured with port49d stopped (`tests/lab/results/quarantine-*.md`; L35 measures this
       case), and break-glass logs in.
     - `/readyz` is 503 and `port49_store_keyspace_held` is 0. The metrics listener is
       unbound for the drain and the next run's config load (seconds), then up again with its
       counters restarted (re-check R-M3).
  4. **When etcd returns,** the same process takes the hold and says `port49d: store: purged 3
     unspent token(s) from before this start (run 'port49 token' again)` and `port49d: store: 41
     live context(s) carried onto the policy in force (bundle sha256:…) before serving`. Then it
     listens. Whether an open session's next command is answered from its context again is
     L35's.
  5. **If that start fails for another reason** (a policy file caught half-written, the
     broker's role refused on `meta/`): `port49d: starting again after a store gone: …; the
     listeners stay closed; trying again in 5s`, until it succeeds or port49d is stopped.
- **3am: etcd is slow, not down.** A call over `call_timeout` fails as above. So does a packet
  whose store work runs past `packet_deadline` mid-call (outcome `deadline`), even if each call
  is under `call_timeout`. Enough of them open the circuit, and a token or context circuit that
  stays open through `hold_ttl` closes the listeners as in 3. A store that answers inside both
  is served, and a wrong token's FAIL still arrives at the failure delay, the store's time
  inside it.
- **3am: the scans are slow at scale** (a refresh's `ActivePrincipals`, a start's purge). The
  bulk pool's circuit opens: `port49d: store: the broker's bulk pool's circuit is open after 5
  consecutive failures (…); the scans (the refresh, a revocation by principal, a start's
  purge) fail until a probe in 5s succeeds; logins and commands are unaffected`, and
  `port49_store_circuit_open{pool="bulk"}` is 1. port49d keeps serving.
- **3am: the daemon's etcd role is revoked or changed at runtime.** Every call is refused
  (`port49_store_calls_total{outcome="refused"}`). After `hold_ttl`: `port49d: store: every call
  on the daemon's context pool has been refused by the store for 15s (its role no longer grants
  it); closing every listener so that devices use their local method`. The restart's role check then names what is wrong, every 5 s, until
  the roles are fixed.
- **A second port49d on the same keyspace** (a surge pod, a copy-pasted config): `port49d: store:
  keyspace /port49/ is held by port49d on core-aaa-1 (pid 4121, since 2026-10-02T03:00:00Z);
  waiting, with the listeners closed: one port49d per keyspace until plan 7e; stop that port49d
  to move the keyspace, and never delete meta/hold`, every 30 s.
- **Someone deletes `meta/hold`** (or `etcdctl del --prefix`): the holder sees its key gone
  within `hold_ttl`/6 and closes its listeners, so two port49d never serve one keyspace.
- **A planned restart.** The memory store lost every session at a restart; etcd keeps them.
  - Tokens are purged, and a `port49 token` minted before the restart is refused
    `token_not_found`.
  - A `port49 token` retried with the same idempotency key mints afresh.
- **A restart after a revocation the contexts never saw** (a mark added to the file with port49d
  stopped, or a revocation cut short by an outage): `port49d: store: 1 standing revocation(s)
  applied to the live contexts the store kept (2 context(s) marked revoked) before serving`. The
  session's next command is denied `credential_revoked`.
- **A context record edited in etcd** (a stolen daemon key): the record fails authentication.
  `port49d: crypt: a context failed authentication under key id "enc3", or is not the one this
  port49d last wrote there: it was altered or is corrupt, and is treated as unreadable`, and
  the session is denied `store_unavailable`. A token edited the same way is dropped and the
  login is `token_not_found`; `crypt_open_failures_total{record}` counts each.
- **Another login's context written back in etcd** (the ledger): the same line, and the
  session is denied `store_unavailable` until its next login, which replaces the record.
- **An index record deleted in etcd:** at the next sweep, `broker: 1 live context(s) were
  missing from the index (an index record deleted in the store?); re-indexed and judged
  against the policy in force`, and `port49_contexts_reindexed_total` rises. Alert on any
  increase.
- **A key rotation done wrong across a restart** (previous dropped while records it sealed
  live): `port49d: crypt: the store was last written by a port49d whose current key is "enc2",
  which this configuration does not hold (current "enc3", no previous); the live sessions sealed
  under enc2 cannot be read, and this start ends them before it serves (their operators log in
  again); if enc2 was retired by mistake, stop port49d now and set encryption.previous to enc2
  before it starts`.
  - `port49_crypt_store_key_unknown` is 1.
  - While running, each unopenable record says `port49d: crypt: a token is sealed under key id
    "enc2", which this port49d does not hold (current "enc3", no previous)`, once per 10 minutes
    per key id.
- **A `port49 token` behind a slow `port49 revoke --mine`:** `port49 token: your revocation sent
  at 03:12:09 is still running on the broker; nothing was minted; run port49 token again once
  port49 revoke reports`. Exit 1. Before this plan it said `the broker … is unreachable`. A `port49 refresh`,
  identity or explain behind it says the same, naming its own command.
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
  register rules 1–4 apply. This plan opens L35 (Task 8b) and closes it (Task 15). Until it
  closes, no doc asserts what a device does when the store hangs.
- **Security first:** no privilege escalation, no impersonation, no secret in a log, fail closed.
  Where a task leaves a choice, take the one that denies more and say so in the commit.
- **Narrow setters only for live contexts.** Nothing re-puts a context except `SwapLogin` (the
  login) and `PutContext` (seeding and tests). The sealing layer's narrow setters rewrite through
  `RewriteContext`, on the revision they read.
- **7a's ordering holds for every revocation:** the mark first, tokens before contexts, contexts
  twice.
- **No reason code is added.** A timeout, an open circuit, a refused role and a record that fails
  authentication are all `store_unavailable` on every event (spec §5.7).

New in this plan:

- **No field a login or the authorizer trusts is written in the clear** (Ruling 17). Context,
  token and receipt are each sealed with their record's key as additional data. `revoked_at` is
  written both ways, and a read takes the later; a token's `expires_at` is written both ways,
  and a token whose two differ is dropped.
- **Every sealed context write goes through the ledger** (`w.sent`), and every context read is
  checked against it (Ruling 17; re-check IA1).
- **Store records are JSON with snake_case keys.** The etcd backend never marshals a `store` type
  whose fields lack tags; it converts to its own `*Rec` types (Task 5).
- **No metric label names a principal, device, key or endpoint.** The new labels are closed sets:
  `component` (`daemon`, `broker`), `pool` (`token`, `context`, `bulk`), and `outcome`.
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
   and the `SwapLogin` never answers. The device hears ERROR `store_unavailable` within
   `store.packet_deadline`, never silence. No context is written half-indexed: the step commits
   whole or not at all. If it committed before the deadline struck, the context is indexed and
   the device's retransmission replays the receipt; if it did not, the retransmission is
   `token_spent` (pre-flight I3).
   *Task 12, `TestAHungStoreGoesDarkAndServesAgainWhenItReturns`.*
2. **A lease etcd no longer knows.** The cached bucket's lease expired while port49d was paused,
   or an operator revoked it. The next put retries once on a fresh lease and lands, and no record
   is written without one. *Task 5, `TestAPutOnALostLeaseTakesAFreshOne`.*
3. **Keys that look alike.** A principal that is the start of another (`user:al`, `user:alice`),
   and a device name, sid or certificate key holding `/` or `%`. Each lookup is exact on every
   backend, and the schema ends every scanned part with `/`. *Task 5,
   `TestScannedKeysEndWithASlash`; Task 7, `storetest.IndexKeysAreExact`.*
4. **Two port49d against one keyspace, a port49d whose hold lapses, and a deleted hold key.** The
   second never binds TACACS+ while the first holds. The first, cut off until its estimate of
   the lease has half of `hold_ttl` or less left, or finding its key gone, closes its listeners
   and says why, at least `hold_ttl`/6 before the second can take the keyspace. *Task 12,
   `TestHoldIsOnePerKeyspaceAndLapses`, `TestTheHoldIsLostWhenItsKeyIsDeleted`,
   `TestASecondPort49dWaitsForTheKeyspace`.*
5. **A mark that lands between a login's read of the marks and its write.** The write conflicts,
   is decided again, and writes the context revoked. Neither a PASS nor an unrevoked context.
   *Task 3, `storetest.JoinHonoursAStandingMark`.*
6. **A daemon certificate that holds the broker's role, a role that grants one write too many, or
   etcd with auth off.** port49d refuses to start, naming the identity and the fix. *Task 11,
   `TestCheckIdentityRefusesADaemonWithTheBrokersReach`.*
7. **A guard whose caller goes away, and one whose caller's deadline strikes.** A device's
   connection dropping mid-call is not counted, and its slot is given back. A packet deadline
   striking mid-call is counted. *Task 9, `TestACallerThatGoesAwayIsNotAFailure`,
   `TestASlowStoreGoesDark`.*
8. **A context, token or receipt record edited in the store.** A zeroed `revoked_at`, a raised
   privilege, a swapped blob, a removed ceiling, a flipped sealed byte, a record moved to
   another key, a record put back from before its revocation under a standing mark, another
   login's context written back, every trusted token field raised, a token moved to another
   key or ID or its expiry extended, and a login receipt copied to the enable key. None
   reaches a permit. *Task 4b, `TestTheSealCoversWhatAuthorizationTrusts`,
   `TestTheTokensTrustedFieldsAreSealed`, `TestAReceiptIsBoundToItsKey`,
   `TestTheLedgerDeniesAnotherLoginsContext`, `TestAStandingMarkDeniesAnUnrevokedContext`.*
9. **A start after a revocation the kept contexts never saw** (pre-flight C1). *Task 12,
   `TestApplyMarksAtStartRevokesAKeptContext`, `TestAStartAppliesAStandingMarkToAKeptContext`.*
10. **A store slow but alive, or refusing every call.** The circuit opens, stays open, and the run
    goes dark; a role refused for `hold_ttl` does the same. Two refusals far apart, and a bulk
    circuit open for `hold_ttl`, do not. *Task 9, `TestASlowStoreGoesDark`,
    `TestRefusalsGoDark`, `TestTheBulkPoolNeverGoesDark`.*
11. **A FAIL behind a short packet deadline, and one behind a slow store.** The brute-force
    delay is served whole, and the store's time is inside it, not added. *Task 10,
    `TestThePacketDeadlineNeverShortensTheFailureDelay`, `TestAFailArrivesAtItsDelay`.*
12. **An index record deleted in the store.** The context is found, re-indexed, judged, and
    reached by a revocation again. *Task 7b, `TestUnindexedFindsAContextItsIndexLost`,
    `TestReindexContextsRestoresRevocationsReach`.*
13. **A start after a store gone that fails for another reason, and a kept context that will not
    open under a certificate mark.** Neither ends port49d. *Task 12,
    `TestAStartAfterAStoreGoneRetriesEveryError`,
    `TestApplyMarksAtStartSkipsAnUnreadableContext`.*

## Running the lab (Task 15)

The lab host is beehive. The owner has given standing consent for lab runs; the lab is
single-occupant. The controller rewrote `.superpowers/sdd/2026-10-02-07d-shared-store/lab-instructions.md`
for 7d with this amendment (pre-flight M45). Task 15 Step 0 checks it before dispatch.

**Every run is made from a detached worktree pinned to a commit:** `git worktree add --detach
/home/rwendt/git/port49/.worktrees/lab-7d <sha>`, then `make build` there, never in the shared
feature worktree. The commit includes `tests/lab/store_test.go`
(Task 15 Step 1 commits it first). Run one platform at a time: `PORT49_LAB_PLATFORMS=eos`, then
`nxos`, `iosxe`, `vjunos`, `vsrx`.

**A stall watchdog runs for the whole run** (background, re-armed on every wake). Its signals are
the test log, capture growth and results files, with a 25-minute stall threshold. Match the test
binary exactly: `pgrep -f "^/tmp/go-build[^ ]*/lab\.test"`.

**After every platform,** confirm that no `port49d` holds `172.100.100.1:49`, that no agent is
running (`pgrep -f 'port49 agent'`), and that the topology is destroyed. The embedded etcd dies
with the test process: confirm with `ss -ltnp | grep -c lab.test`, which must print 0.

**Before removing the pinned worktree,** copy the results and the raw captures from its
`tests/lab/captures/L35-*` to the feature worktree (the one on 7d-2's branch), then run `make evidence` there: the labpcap and count-only
audits must pass on the branch that commits them (re-check m2; `lab-instructions.md` says the
same).

## File Structure

```
docs/design/2026-08-23-policy-engine-spec.md   MOD  d35 (7d-1 part), §5.1.4, §5.6, §14 (Task 1); d35 (7d-2 part), d24, §5.7,
                                                    §12, §14, L35 opened (Task 8b); L35 closed (Task 15)
docs/design/2026-08-21-port49-design.md        MOD  §8, §12 store interface (Task 1); §12 matrix, Consequences; §13; §15;
                                                    §17; §19 (Task 8b)
CLAUDE.md                                      MOD  Go 1.26+ (Task 1, OD-1)
internal/store/storetest/storetest.go          MOD  Backend, Run; JoinContext's new argument; RevocationMarks' zero At (Tasks 2, 3)
internal/store/storetest/lifted.go             NEW  the memory store's properties, for every backend (Task 2)
internal/store/storetest/login.go              NEW  SwapLoginIsOneStep, LoginsRaceToOneIndex, JoinHonoursAStandingMark,
                                                    PurgeTakesEveryToken, SelfRevocationBindsToTheRead (Task 3); IndexKeysAreExact (Task 7)
internal/store/storetest/rewrite.go            NEW  RewriteBindsToTheRevision (Task 4b)
internal/store/memory/memory_test.go           MOD  lifted tests removed; Run (Task 2)
internal/store/crypt/crypt_test.go             MOD  Run through the sealing layer (Task 2); the seal's tests (Task 4b)
internal/store/store.go                        MOD  ErrUnavailable, ErrRefused, BlankCertKey, CheckRevocation, MarkRead, LoginWrite,
                                                    SwapLogin, PurgeTokens (Task 3); RewriteContext (Task 4b)
internal/store/apply.go                        NEW  ApplyPrivilege, ApplyRefresh, ApplyRevokedAt, ApplyContextPolicy (Task 4b)
internal/store/marks.go, marks_test.go         NEW  Marks (Task 4b)
internal/store/join.go                         MOD  LoginIndex; JoinContext reads marks and writes through SwapLogin (Task 3)
internal/store/join_test.go                    MOD  LoginIndex{}; alwaysConflicts.SwapLogin (Task 3)
internal/store/memory/memory.go                MOD  SwapLogin, PurgeTokens, *Locked index helpers (Task 3); RewriteContext, Apply* (Task 4b)
internal/store/crypt/crypt.go                  MOD  SwapLogin, PurgeTokens (Task 3); the whole-record seal, rewrite, the token's
                                                    and the receipt's seal, Option, WithLedger (Task 4b); OnUnopenable,
                                                    SealedKeyID (Task 13)
internal/store/crypt/ledger.go                 NEW  Ledger, NewLedger, ErrNotLastWritten (Task 4b)
internal/daemon/authen/authen.go               MOD  the join with its index; no separate index calls (Task 4); WithMarks (Task 4b)
internal/daemon/authen/authen_test.go          MOD  noStore; the fakes; tests of the one step (Tasks 3, 4); marks (Task 4b)
internal/daemon/author/author.go, _test.go     MOD  WithMarks; the mark check (Task 4b)
internal/broker/broker.go, revoke.go           MOD  Marks set on revoke and lift (Task 4b); SupersededAll, ApplyMarksAtStart (Task 12)
internal/broker/reindex.go, reindex_test.go    NEW  ReindexContexts (Task 7b)
internal/session/session.go, session_test.go   MOD  Manager.Reindex (Task 7b)
go.mod, go.sum                                 MOD  go 1.26; etcd client, embed (Task 5)
internal/store/etcd/etcd.go                    NEW  Config, Open, Store, Close, Ping, unavailable, ErrTooLarge (Task 5); two clients (Task 11)
internal/store/etcd/keys.go                    NEW  the key schema (Task 5)
internal/store/etcd/records.go                 NEW  snake_case records and conversions (Task 5)
internal/store/etcd/leases.go                  NEW  lease buckets (Task 5)
internal/store/etcd/commit.go                  NEW  commit, cas (Task 5)
internal/store/etcd/tokens.go                  NEW  tokens, receipts, token index, PurgeTokens (Task 5)
internal/store/etcd/marks.go                   NEW  revocation marks (Task 5)
internal/store/etcd/contexts.go                NEW  contexts, blobs, the index record's writes, SwapLogin, RewriteContext, the read's
                                                    bookkeeping cache (Task 6)
internal/store/etcd/indexes.go                 NEW  lookups, active principals, Sweep (Task 7); Unindexed (Task 7b)
internal/store/etcd/idempotency.go             NEW  reservation (Task 8)
internal/store/etcd/notbuilt.go                NEW→DEL  methods later tasks build (Tasks 5–8)
internal/store/etcd/etcd_test.go               NEW  TestMain; storetest on etcd; the planting store; backend-only tests (Tasks 5–8)
internal/store/etcd/etcdtest/etcdtest.go       NEW  Main, Prefix, Client, Start, EnableAuth, StartCluster, NewProxy (Task 5)
internal/store/etcd/roles.go, roles_test.go    NEW  Roles, CheckIdentity (Task 11)
internal/store/etcd/meta.go, meta_test.go      NEW  Hold and its fence (Task 12); SealKeys (Task 13)
internal/store/guard/guard.go                  NEW  Wrap, three pools, breaker, StopAfter (Task 9)
internal/store/guard/guard_test.go             NEW  (Task 9)
internal/daemon/metrics/metrics.go, _test.go   MOD  contexts_reindexed_total (Task 7b);
                                                    store_calls_total, store_circuit_open, store_call_seconds (Task 9);
                                                    store_keyspace_held, store_client_cert_expiry_timestamp_seconds (Task 12);
                                                    crypt_store_key_unknown (Task 13)
internal/config/config.go                      MOD  StoreConfig, EtcdConfig, StoreOf; checks (Task 10)
internal/config/store_test.go                  NEW  (Task 10)
internal/daemon/server/server.go, conn.go      MOD  Deps.PacketDeadline; the delay's context and the arrival (Task 10);
                                                    Deps.Abort, a reset on a store gone (Task 12)
internal/daemon/authen/authen.go               MOD  DelayContext, WithDelayContext; fail sleeps until arrival + delay (Task 10)
cmd/port49d/store.go                           NEW  openStores, identity, probeTLS, the start wait, storeGone, startOnPersistentStore,
                                                    sweepLoop (Task 12); the crypt line, seal keys (Task 13)
cmd/port49d/storeroles.go, storeroles_test.go  NEW  port49d store-roles (Task 11)
cmd/port49d/main.go                            MOD  deps.PacketDeadline (Task 10); store-roles dispatch (Task 11);
                                                    run's loop (runLoop), runOnce on the stores, marks, the ledger (Tasks 4b, 12)
cmd/port49d/store_e2e_test.go                  NEW  (Task 12)
cmd/port49d/store_test.go                      NEW  identity, probeTLS (Task 12); the crypt line, seal keys (Task 13)
internal/broker/refresh.go, refresh_test.go    MOD  RefreshAtStart, RefreshReport.Contexts; ApplyMarksAtStart's test (Task 12)
internal/agent/agent.go, socket.go, _test.go   MOD  the wire slot at every send; RevocationRunningError; 503 revocation_running (Task 14)
tests/lab/labpcap/stream.go                    MOD  Packet.At, a packet's capture time (Task 15)
tests/lab/store_test.go                        NEW  L35 (Task 15)
tests/lab/results/L35-*.md                     NEW  written by the run (Task 15)
docs/superpowers/plans/README.md               MOD  plan 7d-1 as built (Task 8 Step 6); plan 7d as built (Task 16)
```

Nineteen tasks in two merges:
- **7d-1:**
  - **Task 1** is docs, and comes first: 7d-1's tasks cite the text it writes.
  - **Tasks 2–4** are the store's contract and its one behaviour change (the login).
  - **Task 4b** is the seals, the ledger and the marks.
  - **Tasks 5–8** are the etcd backend; **Task 7b** finds and re-indexes a context its index
    lost.
- **7d-2:**
  - **Task 8b** is docs, and comes first: 7d-2's tasks cite the text it writes.
  - **Tasks 9–14** are code: the guard, the config, the identities, port49d on etcd, the crypt
    alarm, the agent.
  - **Task 15** is the lab, and gates the merge.
  - **Task 16** is docs: plan 7d as built.

---

# Part 7d-1: the backend (`feature/shared-store-backend`, off `main`)

### Task 1: The spec and the design say what 7d-1 builds

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`
- Modify: `docs/design/2026-08-21-port49-design.md`
- Modify: `CLAUDE.md` (OD-1)

**Interfaces:** none. 7d-1's tasks cite the text this one writes.

No code. Each edit names a one-line fragment to find (none wraps across a line break, pre-flight
M2) and the text to put after it or in its place. The files wrap their lines, so search for the
fragment rather than a whole sentence.

**What this task writes, and what it leaves** (pre-flight I2): only what 7d-1 builds. That is:
- decision 35's backend, expiry, one-step login, seal and marks, and the index exception;
- §5.1.4, §5.6, §14's store-contract assertions, design §8 and §12's store interface;
- `CLAUDE.md`.

Everything about port49d on etcd, and L35, is Task 8b's, the first commit of 7d-2:
- the guard, the hold, the start, the config keys, the metrics;
- `store-roles`;
- decision 24's amendment;
- the failure matrix.

Nothing here asserts what a device does.

- [ ] **Step 1: Decision 35, 7d-1's part.** In spec §13, after decision 34's closing line
  `(§2, §5.1.3, §5.1.4, §5.7, §12, §14; design document §12, §17)` (spec:6437) and before
  `### Deferred, with reasons`, add:

  ```markdown
  **35. The shared store is etcd, every read is linearizable, a login lands with its index and
  its revocation check in one step, and no field a login or an authorization trusts is written in
  the clear.**
  *Plan 7d, 2026-10-02: D1 answered by the owner (etcd); the rest rulings where the design was
  silent, each the option that denies more, and the controller's rulings on plan 7d's pre-flight
  review (the owner may override them).*

  - **Backend.** etcd v3.6. Every acknowledged write survives a leader failover (Raft), so a
    redeemed token never comes back and a revocation mark is never lost. Every read is
    linearizable: a member cut off from the quorum answers nothing, never a stale context. The
    interface stays pluggable; a backend whose replication is asynchronous (Valkey, Redis) is
    acceptable only with its replay window stated (design document §13).
  - **Expiry.** Each record carries its own expiry and is read against port49d's clock; etcd's
    leases only reclaim, at least `store.etcd.lease_grace` (5m) later. A revocation mark carries
    no lease, and never expires. A record that does not decode is an error naming its key, never
    skipped: a revocation that skipped one would miss a live context.
  - **The login is one step.** A login's context write, its index entries, and a check that no
    revocation mark stands for its principal or its certificate that was not there when it
    read, are one transaction.
    - **A standing mark.** A mark that stands, for a token not minted after it, is written into
      the context as its revocation, and the login is refused `credential_revoked`.
    - **What that closes.** A context is never live and unindexed. A redemption racing a
      revocation by principal or certificate writes its context revoked, or is reached by the
      revocation's second pass.
    - **An index that cannot be written.** The login is refused ERROR `store_unavailable` (it
      was a PASS with `index_error`). An ERROR whose write may have committed is §5.6's.
    - **What it leaves.** A self or key revocation leaves no mark, so its window of one round
      trip stays (§5.1.4).
  - **The context is sealed whole, bound to its key.**
    - **What is sealed.** Every field the authorizer trusts is sealed with the identity: the
      privilege, the ceiling, the policy blob, the enable mechanism, the maximum privilege, the
      clocks, and the revocation.
    - **Bound to its key.** The cipher's additional data is the context's key, so a record moved
      to another device or username will not open.
    - **The revocation in the clear.** `revoked_at` is kept in the clear as well, so revoking
      needs no key; a read takes the later of the two.
    - **The setters.** A narrow setter on a sealed field reads, opens, applies its rule, seals
      and rewrites on the revision it read. The idle clock and accounting's annotations stay
      plaintext and authorize nothing.
    - **The token and the receipt.** A token's secret, identity and every field a login trusts
      (its kind, expiry, policy blob, session age, enable mechanism, maximum privilege and
      clocks) are sealed, bound to the token's key and ID; a copy of the expiry stays in the
      clear for the store, and a token whose two expiries differ is dropped. A receipt is
      sealed, its first redemption included, bound to its whole key, kind and credential hash
      among it.
    - **Migration.** A token, receipt or context sealed before this does not open: a token is
      dropped, a context is denied and replaced at the next login. The memory store loses every
      record at the restart that installs it, and etcd holds none before plan 7d.
  - **The ledger.** port49d keeps, per context key, the `ctx_id` it last wrote there or first
    read there. A context that opens at a key under another `ctx_id` (another login's record
    written back) is denied `store_unavailable`, replaced by the next login and revoked by the
    refresh. A start reads every kept context before any listener binds.
  - **The standing marks are read on every request.** The daemon holds the marks in memory, with
    the store as the authority.
    - **Kept current.** They are loaded at start before any listener binds; a mark is added once
      its write lands and removed once its lift does.
    - **What they deny.** An authorization, an `enable` and a receipt's replay are denied
      `credential_revoked` for a context whose principal or certificate a mark names, whatever
      the record says.
    - **The cost** per request is one in-memory lookup.
  - **What store write access still yields.** A stolen daemon store credential cannot forge or
    move a token, receipt or context, raise a privilege past what port49 wrote, or lift a
    revocation by principal or certificate. Deleting a record, or making a write conflict, is
    a denial. What it can do is replay:
    - **a context** port49 sealed earlier for the same key. While port49d runs, the ledger
      admits only an earlier version of the context the key holds now (the same `ctx_id`, so
      the same principal), which undoes a self or key revocation of it (no mark; decision 34)
      or a policy narrowing until the next refresh judges it. **Across a restart it is
      impersonation:** another login's context put back while port49d was stopped is taken as
      that key's at the start, until its sealed ceiling, if it has one, or the key's next login.
      A principal or certificate mark still denies it;
    - **a token** port49 minted for the same key and ID, deleted since, which a holder of its
      secret can redeem until its sealed expiry;
    - **a receipt's sliding bound**, up to its sealed cap, or its refusal flag, which replays
      PASS only onto the live context that receipt's own principal holds unrevoked;
    - **the idle clock**: a context kept alive past its idle TTL, to its sealed ceiling if it
      has one, and indefinitely under `max_session_age: never`;
    - **the index**: a context whose index record is deleted is hidden from the refresh and
      from a revocation by sid or `--mine` until the broker finds and re-indexes it; a
      revocation by principal or certificate still denies it through the marks.

    That residual is carried, unassigned.
  - **The index is plaintext.** The keys revocation reads (principal, device, username,
    certificate, sid) stay plaintext, because revocation must not depend on the encryption key
    (owner's ruling 2026-09-21). On a persistent store every snapshot holds them, and is
    protected as the store is (design document §8).

  (§5.1.4, §5.6, §14; design document §8, §12)
  ```

  Task 8b inserts 7d-2's bullets before that last line and widens it.

- [ ] **Step 2: §5.1.4, the residual window.** Replace

  ```markdown
  A redemption that
  removed its token before the delete and writes its context after the second pass is a window of one
  store round trip, which the shared store (plan 7d) closes atomically.
  ```

  (find `which the shared store (plan 7d) closes atomically`, spec:886) with

  ```markdown
  A redemption that
  removed its token before the delete and writes its context after the second pass writes it
  revoked: a login's context write checks, in the same atomic step, that no mark stands for its
  principal or its certificate (plan 7d; §13, decision 35), and the mark is written before
  anything else. The daemon also reads the standing marks on every authorization, so a context a
  revocation by principal or certificate never reached is denied anyway. A self or key
  revocation leaves no mark, so for those the window of one store round trip stays.
  ```

- [ ] **Step 3: §5.6, the login is one step** (pre-flight I3). Three edits in §5.6:
  1. Replace `There are four ways to get there.` (spec:1415) with `There are five ways to get
     there.` In the same paragraph:
     - replace `merged by the join: each has` (spec:1418) with `merged by the join; and a
       revocation mark standing for the login's principal or certificate, on a token minted
       before it, read in the same step as the write (plan 7d; §13, decision 35): each has`;
     - and drop the `and` that ends spec:1417 (after `` `revoked_at`; ``), so the list keeps
       one `and`.
  2. Replace `**A replace unindexes what it displaced, before the new login is indexed**`
     with `**A replace unindexes what it displaced, in the same step that writes the new
     login's context and index**`.
  3. Replace the paragraph that begins `The unindex and the index are not one operation with
     the context write` and ends `that also needs the
     uniqueness MUST broken.` (find `The unindex and the index are not one operation`) with:

     ```markdown
     The context write, the unindex and the index are one atomic step (plan 7d; §13, decision
     35): it lands only while the context, the ref's index record and the marks the login read
     are as read, and otherwise reads and decides again. So no window leaves a joined login's
     `sid` unindexed, and no replace leaves the survivor under the loser's keys.
     ```
  4. Replace `A store port49 cannot reach fails the login `store_unavailable`, refused before the token is
     spent.` (find `refused before the token is`) with:

     ```markdown
     A store port49 cannot reach fails the login `store_unavailable`: before the token is spent
     when the redemption fails, and after it when the step that writes the context fails. A
     context and its index that cannot be written together are never written apart, so a login
     is never admitted with a context no revocation can reach. An ERROR whose write timed out
     may still have committed: the context is then indexed, so revocable, and a retransmission
     replays the receipt; if it did not commit, the retransmission is `token_spent`.
     ```

- [ ] **Step 4: §14, the store's contract.** Before `---` and `## 15. Lab register`, after the
  `**Scoping**` list (spec:6919), add:

  ```markdown
  **Shared store** (plan 7d; §13, decision 35)

  - **Every backend, every property**: each `storetest` property passes against the memory
    store, the sealing layer over it, the etcd backend, and the sealing layer over etcd.
  - **The login is one step**: a login replacing another principal's context leaves it indexed
    under the new login's keys alone, whatever lands concurrently; a revocation mark that appears
    between a login's read and its write makes the write conflict and land revoked.
  - **Quorum lost**: with two of three etcd members stopped, a store call fails with
    `store.ErrUnavailable` within its deadline, never answers from a stale member.
  - **The seal**: a context record whose `revoked_at` is zeroed, privilege raised, blob swapped
    or ceiling removed in the store reads back as port49 wrote it, and one moved to another key
    does not open. A token whose trusted fields are raised in the store reads back as minted,
    one moved to another key or ID or whose expiry is extended is dropped, and a login receipt
    copied to the enable key does not open.
  - **The ledger**: another login's context written back at a key is denied; an earlier
    version of the same context is not (the residual).
  - **The index lost**: a context whose index record is deleted is found, re-indexed and judged
    against the policy in force, and a revocation by principal reaches it again.
  - **The marks**: a context a standing mark names is denied `credential_revoked` at
    authorization, at `enable` and at a receipt's replay, whatever its record says; a lifted
    mark denies nothing.
  ```

- [ ] **Step 5: The design's store interface.** In design §12 "Store interface":
  - After the requirement paragraph whose last line holds `separation is by *operation* per
    identity, not by key` (design:1248), add:

    ```markdown
    **A login's context write is one atomic operation with its index entries and its revocation
    check** (plan 7d): the context, the index change its join decided (clear the ref, drop a sid
    or certificate, add the login's), and the revocation marks the login read for its principal
    and its certificate land together, only while the context, the ref's index record and those
    marks are as read. A context is therefore never live and unindexed, and a redemption racing
    a revocation by principal or certificate writes its context revoked. A narrow setter on a
    field the sealing layer seals is a rewrite on the revision read (`RewriteContext`, §8).
    ```
  - After the paragraph ending `daemon can be integration-tested as a single binary with no
    external services.` (find `integration-tested as a single binary`, design:1272) add:

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

- [ ] **Step 6: The design's encryption at rest** (§8; pre-flight I5, I12).
  - Replace `A store compromise alone yields
    nothing usable; an attacker needs the store *and* a daemon's or the broker's key.` (find
    `A store compromise alone yields`, design:484) with `A store compromise alone yields no
    credential and no session port49 did not write; an attacker needs the store *and* a daemon's
    or the broker's key. Store write access still yields replay (below).`
  - After the paragraph ending `older.` that begins `This keeps the store from becoming a
    credential vault.` (it ends `accept two keys for one TTL window, then retire the`), add:

    ```markdown
    **The context is sealed whole, bound to its key** (plan 7d; policy engine spec §13,
    decision 35).
    - **What is sealed.** Every field the authorizer trusts is sealed with the identity: the
      privilege, the ceiling, the policy blob, the enable mechanism, the clocks and the
      revocation.
    - **Bound to its key.** The record's key (device and username) is the cipher's additional
      data. A store write therefore cannot raise a privilege, lift a revocation, or move a
      record to another device or username.
    - **The revocation in the clear.** `revoked_at` is also kept in the clear, so a revocation
      needs no key; a read takes the later of the two.
    - **The token and the receipt.** A token's every field a login trusts (kind, expiry, policy
      blob, session age, enable mechanism, maximum privilege, clocks) is sealed with its secret,
      bound to the token's key and ID. A receipt is sealed bound to its whole key. A store write
      therefore cannot raise what a login copies into its context, nor make a login receipt
      answer an enable.
    - **The marks.** The daemon also reads the standing revocation marks on every request.
    - **The ledger.** port49d keeps the `ctx_id` it last wrote, or first read, at each key, and
      denies a context that opens there under another: another login's record written back.
    - **What store write access still yields is replay** (policy engine spec §13, decision 35,
      lists it whole). While port49d runs, an earlier version of the context a key holds now
      can be put back, which undoes a revocation that leaves no mark (a self or key revocation)
      or a policy narrowing until the next refresh. **Across a restart it is impersonation:**
      another login's context put back while port49d was stopped is taken as that key's, until
      its sealed ceiling, if it has one, or the key's next login. A deleted token can be put
      back for a holder of its secret until its sealed expiry. The idle clock and the
      accounting annotations stay plaintext, so a context can be kept alive to its sealed
      ceiling, if it has one, and indefinitely under `max_session_age: never`.

    **The index is the exception to the dump rule above.** The keys revocation reads stay
    plaintext: the principal, device, username, certificate and `sid`. Revocation must not
    depend on the encryption key or its rotation window (owner's ruling 2026-09-21). On a
    persistent store (etcd, plan 7d) every snapshot and backup holds them, so protect those as
    the store itself.
    ```

- [ ] **Step 7: `CLAUDE.md` (OD-1).** Replace `Go 1.22+, module` with `Go 1.26+ (etcd's floor,
  plan 7d), module`.

- [ ] **Step 8: Check, then commit.**

  Run, and expect each (pre-flight M1):
  - `grep -n 'decision 35' docs/design/2026-08-23-policy-engine-spec.md`: at least one line in
    each of §5.1.4 (near spec:886), §5.6 (near spec:1415–1480) and §14 (near spec:6919).
  - `grep -n '^\*\*35\. ' docs/design/2026-08-23-policy-engine-spec.md`: one line.
  - `grep -c 'decision 35' docs/design/2026-08-21-port49-design.md`: at least 1, in §8.
  - `grep -n 'There are five ways' docs/design/2026-08-23-policy-engine-spec.md`: one line.
  - `grep -n 'The unindex and the index are not one operation' docs/design/2026-08-23-policy-engine-spec.md`:
    none.
  - `grep -n 'store-roles\|packet_deadline\|L35' docs/design/*.md`: none (Task 8b's).

  Run `make test` (docs only; it must stay green, the labpcap audit included).

  ```bash
  git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md CLAUDE.md
  git commit -m "docs: the shared store is etcd, a login is one step, the context is sealed whole (decision 35)

  Spec §13 decision 35 records D1 (etcd, the owner's) and what plan
  7d-1 builds: the backend, logical expiry, the login's one step, the
  whole-record seal bound to its key, the token's and the receipt's
  seals, the ledger, the standing marks read on every request, the
  plaintext index as the exception, and exactly what a stolen daemon
  store credential still yields (replay; impersonation across a
  restart). §5.1.4 closes the
  residual window for marked revocations; §5.6 says the login is one
  step and what an ERROR after the spend means; §14 its assertions.
  Design §8 and §12 follow. CLAUDE.md's Go floor is 1.26 (OD-1).
  port49d on etcd, and L35, are plan 7d-2's (Task 8b).

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

**Why:** 7d's backend must hold every property the memory store holds. Thirty-one of those live
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
  - `storetest.Peek(` becomes `Peek(`: the body now lives in package `storetest` (pre-flight M11;
    `TestIdempotency`, memory_test.go:995, 998).
  - `sweepEvery` becomes the literal `1024`, its value at `9cefbba` (memory.go:193): the constant
    is the memory store's and unexported (`TestARevocationMarkNeverExpires`, memory_test.go:1439).
    The loop still runs past one memory sweep, and on another backend it is 1024 writes.

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

- [ ] **Step 4: The sealing layer runs them too.** In `crypt_test.go`, delete only the callers of
  storetest properties between `TestPolicyRevisionThroughTheSealingLayer` (:331) and
  `TestWritesBindToTheRevisionThroughTheSealingLayer` (:587): the `…ThroughTheSealingLayer`
  functions whose whole body is one `storetest.X(…)` call. The six crypt-only tests in that range
  stay, untouched: `TestAPendingReservationReadsBackWithoutOpening` (:372),
  `TestACompletedReservationIsSealed` (:392), `TestARenewedHoldIsNotSealed` (:422),
  `TestAContextUnderARetiredKeyIsReplacedCarryingItsRevocation` (:451),
  `TestUnindexRefPassesThrough` (:485) and `TestSetContextPolicyThroughTheSealingLayer` (:505)
  (pre-flight M13). Add:

  ```go
  // Every storetest property through the sealing layer over memory: what the
  // layer passes through, it must not change.
  func TestTheSealingLayerHoldsEveryProperty(t *testing.T) {
  	storetest.Run(t, storetest.Backend{New: func(_ *testing.T, clock func() time.Time) store.Store {
  		return Wrap(memory.New(clock), keys(), nil)
  	}})
  }
  ```

  `keys()` is the file's key helper (crypt_test.go:18). This is the first time the lifted properties run through the sealing layer. A property that
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
- Modify: `internal/daemon/authen/authen.go` (`, store.LoginIndex{}` on its one `JoinContext` call)
- Modify: `internal/daemon/authen/authen_test.go` (`noStore` gains the two methods, so the tree
  builds; `capturingStore` and `certReachStore` override `SwapLogin`)
- Modify: `internal/store/crypt/crypt_test.go` (its 7-argument `JoinContext` call, :474)
- Test: `internal/store/join_test.go` (`alwaysConflicts` overrides `SwapLogin`)

**Interfaces:**
- Consumes: `store.JoinContext`, `store.Joinable`, `store.Join`, `store.CarryRevocation`.
- Produces:
  - `var store.ErrUnavailable = errors.New("store: unavailable")`
  - `var store.ErrRefused = errors.New("store: refused this identity")` (a backend's refusal by
    its access control: the etcd roles; the guard tells it from an outage, Task 9)
  - `func store.BlankCertKey(certKey string) bool`
  - `var store.ErrIncompleteMark` and `func store.CheckRevocation(r Revocation) error`, which also
    refuses a zero `At` (pre-flight M10)
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

  // ErrRefused is a backend refusing this identity an operation by its own
  // access control: an etcd role that does not grant it, or authentication
  // that failed. It is configuration, not an outage: never ErrUnavailable,
  // so it opens no circuit, and the guard (internal/store/guard) stops
  // port49d's service when every call is refused for store.etcd.hold_ttl
  // (plan 7d; pre-flight I10). Handlers answer it store_unavailable.
  var ErrRefused = errors.New("store: refused this identity")
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
  var ErrIncompleteMark = errors.New("store: a revocation mark must name a principal, or a certificate by issuer and serial, and when it was made")

  // CheckRevocation is PutRevocation's refusal, shared by every backend: a
  // kind that is neither RevocationPrincipal nor RevocationCert, an empty
  // key, a certificate key that is blank (BlankCertKey), or a zero At. A
  // zero At is how a login reads "no mark stands" (MarkRead), so a mark
  // written with one would be compared as absent: the memory store would
  // refuse every login under it ErrConflict and etcd would land them
  // unrevoked (pre-flight M10). The revocations file reaches every backend
  // through PutRevocation, so a file mark with no time is refused at start.
  func CheckRevocation(r Revocation) error {
  	if r.At.IsZero() {
  		return ErrIncompleteMark
  	}
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

  In `storetest.go`'s `RevocationMarks`, add one refused case beside the incomplete marks it
  already refuses: a principal mark with a zero `At` is `ErrIncompleteMark`. Then grep every
  `PutRevocation(` in `_test.go` files (`grep -rn 'PutRevocation(' --include='*_test.go' cmd
  internal tests`) and give any mark written without an `At` one. That adds a field a real mark
  always has; it weakens nothing. Name each in the report.

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

- [ ] **Step 6: Every `JoinContext` caller passes a `LoginIndex`, and every fake that intercepts
  the login's write intercepts `SwapLogin`.** In `storetest.go` (`JoinRacesRevocation`,
  `PolicyRevision`, `RevocationIsMonotonic`), in `lifted.go`, in `internal/store/join_test.go`,
  and in `internal/store/crypt/crypt_test.go` (the call in
  `TestAContextUnderARetiredKeyIsReplacedCarryingItsRevocation`, :474), append
  `, store.LoginIndex{}` to every `store.JoinContext(` call. The zero value indexes nothing,
  which is what each did (pre-flight I7).

  Three test fakes embed `*memory.Store` and override `SwapContext` to watch or refuse the
  login's write. `JoinContext` now writes through `SwapLogin`, which they would inherit from the
  memory store unwatched (pre-flight I6). Give each a `SwapLogin` doing what its `SwapContext`
  does, and keep the `SwapContext` override, since other paths still call it:
  - `alwaysConflicts` (`internal/store/join_test.go:252`): `SwapLogin` returns
    `store.ErrConflict` and counts the swap, as its `SwapContext` does, so
    `TestJoinContextGivesUpAfterMaxJoinAttempts` still sees `MaxJoinAttempts` swaps.
  - `capturingStore` (`internal/daemon/authen/authen_test.go:941`): `SwapLogin` captures the
    context it is given, as its `SwapContext` does, then calls the embedded `SwapLogin`, so
    `TestTheHandlerStampsTheContextClocksItself` reads what the handler wrote.
  - `certReachStore` (`authen_test.go:1876`): Task 4 Step 1.3 replaces its wrappers with one
    `SwapLogin`. Until then add the `SwapLogin` wrapper that step shows, so its `swap_context`
    check is not vacuous in between.

  Read each fake first and mirror its own `SwapContext` body. Never loosen an assertion to make
  one pass: a fake that cannot see the write is the defect. In
  `internal/daemon/authen/authen_test.go`, give `noStore` the two methods:

  ```go
  func (noStore) SwapLogin(context.Context, store.ContextKey, uint64, store.Context, time.Duration, store.LoginWrite) error {
  	return errors.New("store down")
  }

  func (noStore) PurgeTokens(context.Context) (int, error) { return 0, errors.New("store down") }
  ```

  Match what `noStore`'s other methods return (read them first). If they return a named error,
  return that. `authen.go`'s own call is Task 4's. Until then it passes `store.LoginIndex{}` and
  keeps its three index calls: in `authen.go` append `, store.LoginIndex{}` to the one
  `store.JoinContext(` call.

  **This task changes behaviour, and says so in its commit** (pre-flight M14). From here
  `JoinContext` reads the marks, so on the memory store:
  - a login whose principal or certificate a standing mark names, on a token minted before it,
    writes its context revoked and is refused `credential_revoked` by authen's existing check;
  - a `GetRevocation` that errs fails the login, ERROR `store_unavailable`.

- [ ] **Step 7: Run.**

  Run: `go test ./internal/store/... ./internal/daemon/... -count=1`
  Expected: PASS, with `TestTheMemoryStoreHoldsEveryProperty/{SwapLoginIsOneStep,
  LoginsRaceToOneIndex, JoinHonoursAStandingMark, PurgeTakesEveryToken,
  SelfRevocationBindsToTheRead}` and the same five under `TestTheSealingLayerHoldsEveryProperty`.

  Mutation check (do it, report it, revert it): in memory's `SwapLogin`, delete the mark loop.
  `JoinHonoursAStandingMark` must fail ("a mark landing mid-login"). Moving the loop after
  `s.writeContextLocked` is not a mutation this property sees: the retry reads the mark and
  lands revoked anyway (pre-flight M9). Then drop `w.ClearRef`'s branch: `SwapLoginIsOneStep`
  and `LoginsRaceToOneIndex` must fail.

  Also run `go test ./internal/store/ -run TestJoinContextGivesUpAfterMaxJoinAttempts -count=1
  -v` and `go test ./internal/daemon/authen/ -run 'TestTheHandlerStampsTheContextClocksItself|
  TestAReplaceKeepsTheKeysItShares' -count=1 -v`, and report that each still asserts what it did
  (I6): the swap count, the captured context, the reach check.

- [ ] **Step 8: Commit.**

  ```bash
  gofmt -w internal/store internal/daemon/authen/authen_test.go internal/daemon/authen/authen.go
  make build && make test && make vet
  git add internal/store/store.go internal/store/join.go internal/store/join_test.go \
    internal/store/memory/memory.go internal/store/crypt/crypt.go internal/store/crypt/crypt_test.go \
    internal/store/storetest/storetest.go internal/store/storetest/lifted.go internal/store/storetest/login.go \
    internal/daemon/authen/authen.go internal/daemon/authen/authen_test.go
  git commit -m "feat(store): a login's context, index and mark check are one step; PurgeTokens

  SwapLogin writes a login's context, its index change and a check that
  no revocation mark appeared since the login read, in one atomic step;
  JoinContext reads the marks first and carries a standing one into the
  context. PurgeTokens deletes every token for a start on a persistent
  store. BlankCertKey and CheckRevocation move into the store package so
  every backend refuses the same keys, a mark with no time included. New
  storetest properties pin each.

  Behaviour changes on the memory store: a login under a standing mark,
  on a token minted before it, is refused credential_revoked with its
  context written revoked, and a mark read that errs is ERROR
  store_unavailable.

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

  1. Keep `indexFailsStore` (its `IndexContext` fails). Replace
     `TestAnUnindexedContextSaysSoOnTheRecord`, which pins the PASS-with-`index_error` this task
     removes, with the test that fails until the login stops calling `IndexContext` (pre-flight
     I8):

     ```go
     // A login is indexed by its own write (SwapLogin), never by a separate
     // IndexContext call: with IndexContext failing, the login still PASSes,
     // its context is found under its principal, and the record carries no
     // index_error (plan 7d; decision 35; PR #7's third follow-up).
     func TestALoginIsIndexedByItsOwnWrite(t *testing.T) {
     	f := setupStore(t, func(st *memory.Store) store.Store { return indexFailsStore{st} })
     	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
     		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
     		Port: []byte("vty0"), Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")})
     	if reply.Status != wire.AuthenStatusPass {
     		t.Fatalf("status %d, want PASS", reply.Status)
     	}
     	if rec := f.records(t)[0]; rec["index_error"] != nil {
     		t.Fatalf("record: %v", rec)
     	}
     	if refs, _ := f.st.ContextsByPrincipal(context.Background(), "user:alice@example.com"); len(refs) != 1 {
     		t.Fatalf("the login's own write indexed %d refs, want 1", len(refs))
     	}
     }

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
     	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
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

     `Start` returns `(wire.AuthenReply, bool)` (pre-flight M16). If `f.st`, `f.peer.NAS` or
     `indexFailsStore`'s shape are named otherwise in the file, use those names.

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
     (grep the file; authen_test.go:1806, 1854, 2234 at `9cefbba`) assert what those calls did,
     not that a counter moved, so moving the counter to `join_context` would lose their meaning
     (pre-flight M15). Replace each `unindex_ref ok == 1` assertion with the effect it stood for:
     the displaced principal's refs are 0 (`f.st.ContextsByPrincipal(ctx, <old principal>)`), and
     the new login's are 1. An `index_context` assertion becomes the new principal's refs being 1.
     Keep any counter assertion only as `join_context` `ok`, beside the effect.

  Run: `go test ./internal/daemon/authen/ -count=1`
  Expected: `TestALoginIsIndexedByItsOwnWrite` FAILS: the swap writes no index (Task 3 passes
  `LoginIndex{}`), the separate `IndexContext` fails, and the login is a PASS with
  `index_error` and no ref. `TestALoginThatCannotBeIndexedIsRefused` already passes, since Task
  3's `JoinContext` calls `SwapLogin`, and so may `TestALoginUnderAStandingMarkIsRefused`, since
  it reads the marks. Both are expected: they pin the behaviour from here on. Report what each
  did.

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

### Task 4b: The context is sealed whole, the token and the receipt are sealed to their keys, a ledger denies another login's context, and the daemon reads the standing marks

**Files:**
- Modify: `internal/store/store.go` (`RewriteContext` in `Store`)
- Create: `internal/store/apply.go` (`ApplyPrivilege`, `ApplyRefresh`, `ApplyRevokedAt`,
  `CheckContextPolicy`, `ApplyContextPolicy`)
- Create: `internal/store/marks.go`, `internal/store/marks_test.go` (`Marks`)
- Modify: `internal/store/memory/memory.go` (`RewriteContext`; the four setters call `Apply*`)
- Modify: `internal/store/crypt/crypt.go` (the whole-record seal; the rewrite; the token's and
  the receipt's seal; `Option`, `WithLedger`)
- Create: `internal/store/crypt/ledger.go` (`Ledger`, `NewLedger`, `ErrNotLastWritten`)
- Modify: `internal/store/crypt/crypt_test.go`
- Create: `internal/store/storetest/rewrite.go` (`RewriteBindsToTheRevision`); modify
  `storetest.go` (`Run`)
- Modify: `internal/daemon/author/author.go`, `author_test.go` (`WithMarks`, the check)
- Modify: `internal/daemon/authen/authen.go`, `authen_test.go` (`WithMarks`, the enable gate and
  the replay; `noStore.RewriteContext`)
- Modify: `internal/broker/broker.go` (`Marks`), `internal/broker/revoke.go` (`Revoke`, `Lift`)
- Test: `internal/broker/revoke_test.go`
- Modify: `cmd/port49d/main.go` (one `Marks`, loaded after the restore, given to the broker,
  authen and author)

**Interfaces:**
- Consumes: Task 3's `store.Store`; `crypt.Keys`; `author.New`, `authen.New`; `Broker.Revoke`,
  `Broker.Lift`.
- Produces:
  - `Store.RewriteContext(ctx context.Context, k ContextKey, rev uint64, c Context, ttl time.Duration, policyMoved bool) error`
  - `func store.ApplyPrivilege(c *Context, level uint8) (moved bool)`,
    `func store.ApplyRefresh(c *Context, r ContextRefresh) (moved bool, err error)`,
    `func store.ApplyRevokedAt(c *Context, at time.Time)`,
    `func store.CheckContextPolicy(p ContextPolicy) error`,
    `func store.ApplyContextPolicy(c *Context, p ContextPolicy)`
  - `type store.Marks`; `func store.NewMarks() *Marks`; `(*Marks).Set(r Revocation, on bool)`;
    `(*Marks).RevokedAt(c Context) time.Time`; `(*Marks).Len() int` (each nil-safe)
  - `func (k crypt.Keys) SealBound(plaintext, bound []byte) ([]byte, error)`,
    `func (k crypt.Keys) OpenBound(sealed, bound []byte) ([]byte, error)`
  - `type crypt.Option func(*wrapped)`; `func crypt.WithLedger(l *Ledger) Option`;
    `func crypt.Wrap(inner store.Store, k Keys, openFailures *prometheus.CounterVec, opts ...Option) store.Store`
    (variadic, so every existing caller compiles unchanged; Task 13 adds `OnUnopenable`)
  - `type crypt.Ledger`; `func crypt.NewLedger() *Ledger`; `var crypt.ErrNotLastWritten`
  - `func (h *author.Handler) WithMarks(m *store.Marks) *author.Handler`,
    `func (h *authen.Handler) WithMarks(m *store.Marks) *authen.Handler`
  - `Broker.Marks *store.Marks`
  - storetest: `RewriteBindsToTheRevision(t *testing.T, b Backend)`, in `Run`.

**Why:** Ruling 17, the controller's rulings on pre-flight I12 and on re-check CA1 and IA1.
- **The gap.** Until now the sealing layer sealed the identity alone. `revoked_at`, the
  privilege, the blob hash and the ceiling were plaintext, and the AEAD's additional data was
  the key id. A stolen daemon store credential could therefore zero a revocation, raise a
  privilege, swap a blob or transplant a record, and the authorizer trusted `RevokedAt` alone.
- **The token's gap** (re-check CA1). A token's `max_privilege`, `blob_hash`, `enable`,
  `max_session_age`, `auth_time`, `minted_at`, `kind` and `expires_at` were plaintext too, and
  the daemon's role writes `t/`.
  - **The scenario.** Mallory holds a valid `port49 token` and the stolen daemon credential.
    She edits her own `t/` record: `max_privilege` to 15, `enable` to `auto`,
    `max_session_age` to 0, and `blob_hash` to another principal's wider blob, which already
    sits in `b/` and which `engine.Decode` checks only against the hash. She logs in.
    `loginContext` (authen.go:705-724) copies those fields, and the context seal then seals a
    level-15 context with no ceiling faithfully.
  - **A second path.** A forged later `minted_at` makes `CarryRevocation` (authen.go:494)
    leave a self or key revocation behind at the join.
  - **The receipt.** It was sealed under the key id alone, so a login receipt copied to the
    enable key would replay an escalation with no enable token.
- **The impersonation gap** (re-check IA1). A record sealed for a key opens at that key
  whoever it was written for. Bob saves Alice's sealed context for leaf-01/netops, logs in
  there, and writes Alice's record back: his session authorizes as Alice, and the refresh
  judges Alice, who is still entitled.
- **The fix.** This task:
  - seals what a login and an authorization trust, each record bound to its key;
  - keeps a ledger of the `ctx_id` this process last wrote at each key, and denies another;
  - makes the daemon read the standing marks.
- **Why it is 7d-1's.** It closes the gap on every backend, memory included, and the etcd
  backend (Task 6) implements `RewriteContext` against it.
- **The per-command cost** is unchanged in store calls: `GetContext` opens one sealed blob, as
  it did, and `TouchContext` stays a pass-through. The mark check is one read lock and at most
  two map lookups, and the ledger's one mutex and one map lookup. `SetPrivilege` (once per
  session start) and the broker's refresh and revocation gain one read each (on etcd, Task 6's
  cache keeps a rewrite at two RPCs; re-check MA3). A token or receipt opens one sealed blob,
  as it did.

- [ ] **Step 1: The failing tests.**

  Create `internal/store/storetest/rewrite.go`:

  ```go
  package storetest

  import (
  	"context"
  	"errors"
  	"testing"
  	"time"

  	"github.com/rhwendt/port49/internal/store"
  )

  // RewriteBindsToTheRevision is RewriteContext (plan 7d; Ruling 17): it
  // writes the record's fields only on the revision read, keeps the expiry
  // and LastTouchedAt unless given a ttl, moves PolicyRev only when told,
  // and writes nothing on a stale revision or an absent record.
  func RewriteBindsToTheRevision(t *testing.T, b Backend) {
  	ctx := context.Background()
  	now := t0
  	s := b.New(t, func() time.Time { return now })
  	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
  	if err := s.RewriteContext(ctx, k, 1, store.Context{CtxID: "x"}, 0, false); !errors.Is(err, store.ErrNotFound) {
  		t.Fatalf("a rewrite of no record: %v", err)
  	}
  	if err := s.PutContext(ctx, k, store.Context{CtxID: "c", Principal: "p", Username: "alice", PrivLvl: 1},
  		time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	read, _ := s.GetContext(ctx, k)
  	now = now.Add(time.Minute)
  	next := read
  	next.PrivLvl = 7
  	if err := s.RewriteContext(ctx, k, read.Rev, next, 0, false); err != nil {
  		t.Fatal(err)
  	}
  	got, _ := s.GetContext(ctx, k)
  	if got.PrivLvl != 7 || got.Rev == read.Rev || got.PolicyRev != read.PolicyRev || !got.LastTouchedAt.Equal(read.LastTouchedAt) {
  		t.Fatalf("a rewrite with no ttl, not a policy write: %+v (read %+v)", got, read)
  	}
  	// The expiry did not move: an hour from the put, not from now.
  	now = t0.Add(time.Hour + time.Second)
  	if _, err := s.GetContext(ctx, k); !errors.Is(err, store.ErrNotFound) {
  		t.Fatalf("a rewrite with no ttl extended the record: %v", err)
  	}
  	k2 := store.ContextKey{NAS: "leaf-02", Username: "alice"}
  	if err := s.PutContext(ctx, k2, store.Context{CtxID: "c", Principal: "p", Username: "alice"}, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	read, _ = s.GetContext(ctx, k2)
  	now = now.Add(time.Minute)
  	if err := s.RewriteContext(ctx, k2, read.Rev, read, 2*time.Hour, true); err != nil {
  		t.Fatal(err)
  	}
  	got, _ = s.GetContext(ctx, k2)
  	if got.PolicyRev == read.PolicyRev || !got.LastTouchedAt.Equal(now) {
  		t.Fatalf("a rewrite with a ttl, a policy write: %+v (read %+v)", got, read)
  	}
  	now = now.Add(90 * time.Minute) // past the put's hour, inside the rewrite's two
  	if _, err := s.GetContext(ctx, k2); err != nil {
  		t.Fatalf("a rewrite with a ttl did not extend the record: %v", err)
  	}
  	stale := read
  	stale.PrivLvl = 15
  	if err := s.RewriteContext(ctx, k2, read.Rev, stale, 0, false); !errors.Is(err, store.ErrConflict) {
  		t.Fatalf("a rewrite on a stale revision: %v", err)
  	}
  	if got, _ := s.GetContext(ctx, k2); got.PrivLvl == 15 {
  		t.Fatal("a refused rewrite wrote")
  	}
  }
  ```

  Add `{"RewriteBindsToTheRevision", RewriteBindsToTheRevision}` to `Run`'s second table.

  Create `internal/store/marks_test.go`:

  ```go
  package store

  import (
  	"testing"
  	"time"
  )

  // Marks is the daemon's copy of the standing marks (plan 7d; Ruling 17):
  // a context its principal or certificate names stands revoked at the
  // later of its own mark and the record's; a lifted mark names nothing; a
  // blank certificate key names no certificate; nil names nothing.
  func TestMarksNameAContextByPrincipalOrCertificate(t *testing.T) {
  	at := time.Unix(1_000_000, 0).UTC()
  	m := NewMarks()
  	alice := Context{Principal: "user:alice@example.com", Credential: Credential{Issuer: "CN=Corp CA", Serial: "0a"}}
  	if !m.RevokedAt(alice).IsZero() {
  		t.Fatal("no mark, revoked")
  	}
  	m.Set(Revocation{Kind: RevocationPrincipal, Key: alice.Principal, At: at}, true)
  	if !m.RevokedAt(alice).Equal(at) {
  		t.Fatal("a principal's mark")
  	}
  	m.Set(Revocation{Kind: RevocationPrincipal, Key: alice.Principal, At: at.Add(time.Hour)}, true)
  	if !m.RevokedAt(alice).Equal(at) {
  		t.Fatal("a repeated mark moved the first one's time")
  	}
  	m.Set(Revocation{Kind: RevocationPrincipal, Key: alice.Principal}, false)
  	if !m.RevokedAt(alice).IsZero() || m.Len() != 0 {
  		t.Fatal("a lifted mark")
  	}
  	m.Set(Revocation{Kind: RevocationCert, Key: CertKey("CN=Corp CA", "0a"), At: at}, true)
  	if !m.RevokedAt(alice).Equal(at) {
  		t.Fatal("a certificate's mark")
  	}
  	oidc := Context{Principal: "user:bob@example.com"}
  	m.Set(Revocation{Kind: RevocationCert, Key: "|", At: at}, true)
  	if !m.RevokedAt(oidc).IsZero() {
  		t.Fatal("a blank certificate key named an OIDC login")
  	}
  	later := alice
  	later.RevokedAt = at.Add(time.Minute)
  	if !m.RevokedAt(later).Equal(later.RevokedAt) {
  		t.Fatal("the record's own later revocation")
  	}
  	var none *Marks
  	if !none.RevokedAt(alice).IsZero() {
  		t.Fatal("a nil Marks named a mark")
  	}
  }
  ```

  Append to `internal/store/crypt/crypt_test.go`:

  ```go
  // The sealing layer seals every field the authorizer trusts, bound to the
  // record's key (plan 7d; Ruling 17; pre-flight I12). A store write that
  // zeroes revoked_at, raises the privilege, swaps the blob or removes the
  // ceiling changes nothing the layer returns, and a record moved to another
  // (nas, username) does not open.
  func TestTheSealCoversWhatAuthorizationTrusts(t *testing.T) {
  	ctx := context.Background()
  	now := time.Unix(1_000_000, 0).UTC()
  	inner := memory.New(func() time.Time { return now })
  	s := Wrap(inner, keys(), nil)
  	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
  	if err := s.PutContext(ctx, k, store.Context{CtxID: "c1", Principal: "user:alice@example.com", Username: "alice",
  		PrivLvl: 1, MaxPrivilege: 1, BlobHash: "sha256:narrow", Enable: "none", AuthTime: now, RefreshedAt: now,
  		SessionExpires: now.Add(time.Hour)}, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	if err := s.SetRevokedAt(ctx, k, now); err != nil {
  		t.Fatal(err)
  	}
  	raw, err := inner.GetContext(ctx, k)
  	if err != nil {
  		t.Fatal(err)
  	}
  	// What the backend holds names none of it in the clear, the revocation
  	// aside, which is written both ways.
  	if raw.PrivLvl != 0 || raw.MaxPrivilege != 0 || raw.BlobHash != "" || raw.Enable != "" ||
  		!raw.SessionExpires.IsZero() || !raw.AuthTime.IsZero() || !raw.RevokedAt.Equal(now) {
  		t.Fatalf("the backend holds a trusted field in the clear: %+v", raw)
  	}
  	// Each edit writes a plaintext value the seal must outrank: a field
  	// already blank in the clear, set blank, would test nothing (re-check
  	// MA5).
  	for name, edit := range map[string]func(*store.Context){
  		"a zeroed revoked_at": func(r *store.Context) { r.RevokedAt = time.Time{} },
  		"a raised privilege":  func(r *store.Context) { r.PrivLvl, r.MaxPrivilege = 15, 15 },
  		"a swapped blob":      func(r *store.Context) { r.BlobHash = "sha256:wide" },
  		"a later ceiling": func(r *store.Context) {
  			r.SessionExpires, r.AuthTime = now.Add(100*time.Hour), now.Add(99*time.Hour)
  		},
  	} {
  		r := raw
  		edit(&r)
  		if err := inner.PutContext(ctx, k, r, time.Hour); err != nil {
  			t.Fatal(err)
  		}
  		got, err := s.GetContext(ctx, k)
  		if err != nil || !got.RevokedAt.Equal(now) || got.PrivLvl != 1 || got.MaxPrivilege != 1 ||
  			got.BlobHash != "sha256:narrow" || !got.SessionExpires.Equal(now.Add(time.Hour)) {
  			t.Fatalf("%s reached the reader: %+v %v", name, got, err)
  		}
  	}
  	// Moved to another key, the record does not open: unreadable, never
  	// another device's session.
  	other := store.ContextKey{NAS: "leaf-02", Username: "alice"}
  	if err := inner.PutContext(ctx, other, raw, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	var u *store.UnreadableContextError
  	if _, err := s.GetContext(ctx, other); !errors.As(err, &u) {
  		t.Fatalf("a transplanted record opened: %v", err)
  	}
  	// One sealed byte flipped: the record does not open (re-check MA5).
  	flipped := raw
  	flipped.Sealed = append([]byte(nil), raw.Sealed...)
  	flipped.Sealed[len(flipped.Sealed)-1] ^= 1
  	if err := inner.PutContext(ctx, k, flipped, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	if _, err := s.GetContext(ctx, k); !errors.As(err, &u) {
  		t.Fatalf("a record with a flipped sealed byte opened: %v", err)
  	}
  }

  // A revocation needs no key: on a record the layer cannot open, the
  // plaintext mark still lands, and a read of it is the unreadable error
  // carrying that mark (plan 7d; Ruling 17). A regression guard, not a
  // failing test: it passes before this task too, since SetRevokedAt was
  // already a plaintext pass-through (re-check MA4).
  func TestARevocationOfAnUnopenableContextNeedsNoKey(t *testing.T) {
  	ctx := context.Background()
  	now := time.Unix(1_000_000, 0).UTC()
  	inner := memory.New(func() time.Time { return now })
  	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
  	old := Wrap(inner, Keys{Current: Key{ID: "gone", Bytes: [32]byte{9}}}, nil)
  	if err := old.PutContext(ctx, k, store.Context{CtxID: "c", Principal: "p", Username: "alice"}, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	s := Wrap(inner, keys(), nil)
  	if err := s.SetRevokedAt(ctx, k, now); err != nil {
  		t.Fatalf("a keyless revocation: %v", err)
  	}
  	var u *store.UnreadableContextError
  	if _, err := s.GetContext(ctx, k); !errors.As(err, &u) || !u.RevokedAt.Equal(now) {
  		t.Fatalf("the unopenable record: %v", err)
  	}
  }

  // A token's every field a redemption or a login trusts is sealed, bound to
  // its key and ID (plan 7d; Ruling 17; re-check CA1). A store write that
  // changes one reads back as minted, and the login copies what this layer
  // returns (authen.go:705-724), so its context carries the minted value. A
  // token moved to another key or ID, or whose plaintext expiry moved, is
  // dropped and counted. A deleted token put back opens: the replay Ruling 17
  // states, bounded by its sealed expiry.
  func TestTheTokensTrustedFieldsAreSealed(t *testing.T) {
  	ctx := context.Background()
  	now := time.Unix(1_000_000, 0).UTC()
  	inner := memory.New(func() time.Time { return now })
  	failures := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "t"}, []string{"record"})
  	s := Wrap(inner, keys(), failures)
  	k := store.TokenKey{NAS: "leaf-01", Username: "alice"}
  	minted := store.Token{ID: "t1", Secret: []byte("p49_secret"), Kind: store.KindLogin, ExpiresAt: now.Add(time.Minute),
  		Principal: "user:alice@example.com", Username: "alice", BlobHash: "sha256:narrow", MaxSessionAge: time.Hour,
  		Enable: "token", MaxPrivilege: 1, AuthTime: now, MintedAt: now}
  	if _, err := s.PutToken(ctx, k, minted); err != nil {
  		t.Fatal(err)
  	}
  	raws, err := inner.Candidates(ctx, k)
  	if err != nil || len(raws) != 1 {
  		t.Fatalf("%v %v", raws, err)
  	}
  	raw := raws[0]
  	if raw.Kind != "" || raw.BlobHash != "" || raw.MaxSessionAge != 0 || raw.Enable != "" || raw.MaxPrivilege != 0 ||
  		!raw.AuthTime.IsZero() || !raw.MintedAt.IsZero() || !raw.ExpiresAt.Equal(minted.ExpiresAt) {
  		t.Fatalf("the backend holds a trusted token field in the clear: %+v", raw)
  	}
  	putRaw := func(k store.TokenKey, r store.Token) {
  		t.Helper()
  		if err := inner.DeleteTokens(ctx, k); err != nil {
  			t.Fatal(err)
  		}
  		if _, err := inner.PutToken(ctx, k, r); err != nil {
  			t.Fatal(err)
  		}
  	}
  	asMinted := func(got store.Token) bool {
  		return got.Kind == minted.Kind && got.BlobHash == minted.BlobHash && got.MaxSessionAge == minted.MaxSessionAge &&
  			got.Enable == minted.Enable && got.MaxPrivilege == minted.MaxPrivilege && got.AuthTime.Equal(minted.AuthTime) &&
  			got.MintedAt.Equal(minted.MintedAt) && got.ExpiresAt.Equal(minted.ExpiresAt) &&
  			got.Principal == minted.Principal && string(got.Secret) == string(minted.Secret)
  	}
  	for name, edit := range map[string]func(*store.Token){
  		"a raised privilege":   func(r *store.Token) { r.MaxPrivilege = 15 },
  		"enable auto":          func(r *store.Token) { r.Enable = "auto" },
  		"a longer session age": func(r *store.Token) { r.MaxSessionAge = 1000 * time.Hour },
  		"another blob":         func(r *store.Token) { r.BlobHash = "sha256:wide" },
  		"a later auth time":    func(r *store.Token) { r.AuthTime = now.Add(time.Hour) },
  		"a later mint":         func(r *store.Token) { r.MintedAt = now.Add(time.Hour) },
  		"the enable kind":      func(r *store.Token) { r.Kind = store.KindEnable },
  	} {
  		r := raw
  		edit(&r)
  		putRaw(k, r)
  		got, err := s.Candidates(ctx, k)
  		if err != nil || len(got) != 1 || !asMinted(got[0]) {
  			t.Fatalf("%s reached the reader: %+v %v", name, got, err)
  		}
  	}
  	// Dropped and counted: an extended plaintext expiry, another key,
  	// another ID.
  	dropped := func(what string, k store.TokenKey) {
  		t.Helper()
  		before := testutil.ToFloat64(failures.WithLabelValues("token"))
  		if got, err := s.Candidates(ctx, k); err != nil || len(got) != 0 {
  			t.Fatalf("%s opened: %+v %v", what, got, err)
  		}
  		if testutil.ToFloat64(failures.WithLabelValues("token")) != before+1 {
  			t.Fatalf("%s was not counted", what)
  		}
  	}
  	later := raw
  	later.ExpiresAt = now.Add(time.Hour)
  	putRaw(k, later)
  	dropped("an extended plaintext expiry", k)
  	other := store.TokenKey{NAS: "leaf-02", Username: "alice"}
  	putRaw(other, raw)
  	dropped("a token moved to another key", other)
  	renamed := raw
  	renamed.ID = "t2"
  	putRaw(k, renamed)
  	dropped("a token moved to another ID", k)
  	// The replay: a deleted token put back opens, until its sealed expiry.
  	putRaw(k, raw)
  	if got, err := s.Candidates(ctx, k); err != nil || len(got) != 1 || !asMinted(got[0]) {
  		t.Fatalf("a token put back as it was: %+v %v (the residual, Ruling 17)", got, err)
  	}
  }

  // A receipt is sealed bound to its whole key (re-check CA1): a login
  // receipt copied to the enable key does not open, so it can never replay
  // an escalation; and the cap's anchor is the sealed first redemption,
  // whatever the plaintext copy says.
  func TestAReceiptIsBoundToItsKey(t *testing.T) {
  	ctx := context.Background()
  	now := time.Unix(1_000_000, 0).UTC()
  	inner := memory.New(func() time.Time { return now })
  	s := Wrap(inner, keys(), nil)
  	tk := store.TokenKey{NAS: "leaf-01", Username: "alice"}
  	spend := func(id string) {
  		t.Helper()
  		if _, err := inner.PutToken(ctx, tk, store.Token{ID: id, ExpiresAt: now.Add(time.Minute)}); err != nil {
  			t.Fatal(err)
  		}
  	}
  	var h [32]byte
  	copy(h[:], "hash")
  	login := store.ReceiptKey{NAS: "leaf-01", Username: "alice", Kind: store.KindLogin, CredentialSHA256: h}
  	spend("t1")
  	if err := s.RedeemAndReceipt(ctx, tk, "t1", store.ReceiptWrite{Key: login, Principal: "user:alice@example.com",
  		IndexTTL: time.Hour, Receipt: store.Receipt{CredentialSHA256: h, Status: 1, CtxID: "ctx1", FirstRedeemedAt: now,
  			IdleExpiresAt: now.Add(time.Minute), RetainUntil: now.Add(time.Hour)}}); err != nil {
  		t.Fatal(err)
  	}
  	raw, err := inner.GetReceipt(ctx, login)
  	if err != nil {
  		t.Fatal(err)
  	}
  	enable := login
  	enable.Kind = store.KindEnable
  	spend("t2")
  	if err := inner.RedeemAndReceipt(ctx, tk, "t2", store.ReceiptWrite{Key: enable, Principal: "user:alice@example.com",
  		IndexTTL: time.Hour, Receipt: raw}); err != nil {
  		t.Fatal(err)
  	}
  	if _, err := s.GetReceipt(ctx, enable); err == nil || errors.Is(err, store.ErrNotFound) {
  		t.Fatalf("a login receipt copied to the enable key opened: %v", err)
  	}
  	moved := raw
  	moved.FirstRedeemedAt = now.Add(time.Hour)
  	spend("t3")
  	if err := inner.RedeemAndReceipt(ctx, tk, "t3", store.ReceiptWrite{Key: login, Principal: "user:alice@example.com",
  		IndexTTL: time.Hour, Receipt: moved}); err != nil {
  		t.Fatal(err)
  	}
  	if got, err := s.GetReceipt(ctx, login); err != nil || !got.FirstRedeemedAt.Equal(now) {
  		t.Fatalf("the cap's anchor came from the clear: %+v %v", got, err)
  	}
  }

  // The ledger (re-check IA1; the controller's ruling): another login's
  // context written back at a key is denied ErrNotLastWritten, through
  // either Wrap sharing the ledger. An earlier version of the same context
  // opens, which is the residual Ruling 17 states. A fresh process takes the
  // first record it reads as the key's, the restart residual, and denies
  // another after it.
  func TestTheLedgerDeniesAnotherLoginsContext(t *testing.T) {
  	ctx := context.Background()
  	now := time.Unix(1_000_000, 0).UTC()
  	inner := memory.New(func() time.Time { return now })
  	l := NewLedger()
  	daemon := Wrap(inner, keys(), nil, WithLedger(l))
  	broker := Wrap(inner, keys(), nil, WithLedger(l))
  	k := store.ContextKey{NAS: "leaf-01", Username: "netops"}
  	if err := daemon.PutContext(ctx, k, store.Context{CtxID: "alice-1", Principal: "user:alice@example.com",
  		Username: "netops", PrivLvl: 15}, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	alice, _ := inner.GetContext(ctx, k)
  	if err := daemon.PutContext(ctx, k, store.Context{CtxID: "bob-1", Principal: "user:bob@example.com",
  		Username: "netops", PrivLvl: 1}, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	bob, _ := inner.GetContext(ctx, k)
  	if err := broker.SetPrivilege(ctx, k, 5); err != nil {
  		t.Fatal(err)
  	}
  	if err := inner.PutContext(ctx, k, alice, time.Hour); err != nil { // Alice's, written back
  		t.Fatal(err)
  	}
  	var u *store.UnreadableContextError
  	for name, s := range map[string]store.Store{"daemon": daemon, "broker": broker} {
  		if _, err := s.GetContext(ctx, k); !errors.As(err, &u) || !errors.Is(err, ErrNotLastWritten) {
  			t.Fatalf("%s read another login's context written back: %v", name, err)
  		}
  	}
  	if err := inner.PutContext(ctx, k, bob, time.Hour); err != nil { // Bob's own, before the raise
  		t.Fatal(err)
  	}
  	if got, err := daemon.GetContext(ctx, k); err != nil || got.CtxID != "bob-1" || got.PrivLvl != 1 {
  		t.Fatalf("an earlier version of the same context: %+v %v (the residual)", got, err)
  	}
  	fresh := Wrap(inner, keys(), nil) // a restart: its own, empty ledger
  	if err := inner.PutContext(ctx, k, alice, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	if got, err := fresh.GetContext(ctx, k); err != nil || got.CtxID != "alice-1" {
  		t.Fatalf("a fresh process's first read: %+v %v (the restart residual)", got, err)
  	}
  	if err := inner.PutContext(ctx, k, bob, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	if _, err := fresh.GetContext(ctx, k); !errors.Is(err, ErrNotLastWritten) {
  		t.Fatalf("after its first read, a fresh process read another login's: %v", err)
  	}
  }

  // A write in flight is admitted beside the last one, a write that landed
  // replaces it, one refused admits nothing, and one whose outcome is
  // unknown stays admitted until a later write lands (re-check IA1).
  func TestTheLedgerAdmitsWritesInFlight(t *testing.T) {
  	l := NewLedger()
  	k := store.ContextKey{NAS: "leaf-01", Username: "netops"}
  	if !l.admits(k, "a") {
  		t.Fatal("a first read is the key's")
  	}
  	l.begin(k, "b")
  	if !l.admits(k, "a") || !l.admits(k, "b") || l.admits(k, "x") {
  		t.Fatal("a write in flight")
  	}
  	l.end(k, "b", nil)
  	if l.admits(k, "a") || !l.admits(k, "b") {
  		t.Fatal("a write that landed")
  	}
  	l.begin(k, "c")
  	l.end(k, "c", store.ErrConflict)
  	if l.admits(k, "c") {
  		t.Fatal("a conflict wrote nothing")
  	}
  	l.begin(k, "d")
  	l.end(k, "d", store.ErrUnavailable)
  	if !l.admits(k, "d") || !l.admits(k, "b") {
  		t.Fatal("a write whose outcome is unknown may have landed")
  	}
  	l.begin(k, "e")
  	l.end(k, "e", nil)
  	if l.admits(k, "d") || l.admits(k, "b") || !l.admits(k, "e") {
  		t.Fatal("a later write landed")
  	}
  }
  ```

  `crypt_test.go` already imports `prometheus` and `testutil` (`TestTokenUnderRetiredKeyIsDroppedNotReturned`).
  The memory store's `RedeemAndReceipt` overwrites the receipt at its key (memory.go:372), which
  is how the test writes the moved copy back under the login key.

  In `internal/daemon/author/author_test.go`, add:

  ```go
  // A standing mark denies a context whatever its record says (plan 7d;
  // Ruling 17; pre-flight C1, I12): an unrevoked record under a mark for its
  // principal or its certificate (a record put back from before the
  // revocation, or one a revocation never reached) is denied
  // credential_revoked, and a lifted mark denies nothing.
  func TestAStandingMarkDeniesAnUnrevokedContext(t *testing.T) {
  	h, st, log := setup(t)
  	marks := store.NewMarks()
  	h.WithMarks(marks)
  	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
  	st.PutContext(context.Background(), k, store.Context{CtxID: "c", Principal: "user:alice@example.com",
  		Username: "alice", PrivLvl: 15, RefreshedAt: time.Now(),
  		Credential: store.Credential{Issuer: "CN=Corp CA", Serial: "0a"}}, time.Hour)
  	for _, mark := range []store.Revocation{
  		{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: time.Now().Add(-time.Minute)},
  		{Kind: store.RevocationCert, Key: store.CertKey("CN=Corp CA", "0a"), At: time.Now().Add(-time.Minute)},
  	} {
  		marks.Set(mark, true)
  		resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show"))
  		if resp.Status != wire.AuthorStatusFail || lastRecord(t, log)["reason"] != "credential_revoked" {
  			t.Fatalf("%s mark: %+v %v", mark.Kind, resp, lastRecord(t, log))
  		}
  		marks.Set(mark, false)
  	}
  	resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show"))
  	if resp.Status == wire.AuthorStatusFail && lastRecord(t, log)["reason"] == "credential_revoked" {
  		t.Fatalf("a lifted mark still denied: %v", lastRecord(t, log))
  	}
  }
  ```

  In `internal/daemon/authen/authen_test.go`, add a test that an `enable` on a context whose
  principal a standing mark names is FAIL `credential_revoked`, and one that a retransmitted
  login (a receipt replay) onto such a context is refused `credential_revoked`. Build both from
  the file's existing enable and replay tests (grep `TestEnable` and `receipt_replayed`), with
  `f.h.WithMarks(marks)` and the mark set after the login. Name them
  `TestAnEnableUnderAStandingMarkIsRefused` and `TestAReplayUnderAStandingMarkIsRefused`. Give
  `noStore` a `RewriteContext` returning what its other methods return.

  In `internal/broker/revoke_test.go` (or the file holding `Revoke`'s tests), add:

  ```go
  // The daemon's marks follow the broker's (plan 7d; Ruling 17): a
  // revocation puts its mark in force once it is written, and a lift takes
  // it out once the store's is gone.
  func TestRevokeAndLiftKeepTheDaemonsMarks(t *testing.T) {
  	f := newFixtureWithPolicy(t, 8, sharedPolicy)
  	f.b.Marks = store.NewMarks()
  	ctx := context.Background()
  	alice := store.Context{Principal: alicePrincipal}
  	if _, err := f.b.Revoke(ctx, RevokeRequest{Principal: alicePrincipal, Origin: "t"}); err != nil {
  		t.Fatal(err)
  	}
  	if f.b.Marks.RevokedAt(alice).IsZero() {
  		t.Fatal("a revocation left the daemon's marks without it")
  	}
  	if _, err := f.b.Lift(ctx, RevokeRequest{Principal: alicePrincipal}); err != nil {
  		t.Fatal(err)
  	}
  	if !f.b.Marks.RevokedAt(alice).IsZero() {
  		t.Fatal("a lift left the mark in the daemon's marks")
  	}
  }
  ```

  If the fixture needs a session manager for `Revoke` (it refuses without `b.Sessions`), use the
  one 7a's revoke tests set up; read them first.

  Run: `go test ./internal/store/... ./internal/daemon/... ./internal/broker/ -count=1`
  Expected: FAIL to build: `RewriteContext`, `NewMarks`, `WithMarks`, `Broker.Marks`,
  `NewLedger`, `WithLedger` and `ErrNotLastWritten` are undefined.

- [ ] **Step 2: The contract and the rules.** In `internal/store/store.go`, add to the `Store`
  interface, after `SwapLogin`:

  ```go
  	// RewriteContext writes c's fields over the live record at k only while
  	// its Rev is rev: ErrNotFound when no record is live, ErrConflict when
  	// Rev has moved, and nothing written either way (plan 7d; spec §13,
  	// decision 35). Rev moves; PolicyRev moves to the new revision only when
  	// policyMoved. A zero ttl leaves the expiry and LastTouchedAt as the
  	// record has them; a non-zero ttl extends both, and the ref's index
  	// entries, as TouchContext does. It is the sealing layer's narrow
  	// setter: the layer reads the record, opens it, applies the setter's
  	// rule (ApplyPrivilege, ApplyRefresh, ApplyRevokedAt,
  	// ApplyContextPolicy), seals it again and rewrites it on the revision it
  	// read, so no field the authorizer trusts is written in the clear by a
  	// setter that cannot read it.
  	RewriteContext(ctx context.Context, k ContextKey, rev uint64, c Context, ttl time.Duration, policyMoved bool) error
  ```

  Create `internal/store/apply.go`, moving each body out of the memory store's setter verbatim
  (memory.go:577–789 at `9cefbba`), the record now a `*Context`:

  ```go
  package store

  import (
  	"errors"
  	"time"
  )

  // The narrow setters' rules, one definition for every backend and for
  // the sealing layer, which applies them to a record it has opened (plan
  // 7d; Ruling 17). Each changes c and nothing else; the store's own
  // bookkeeping (the revisions, the expiry) is the caller's.

  // ApplyPrivilege is SetPrivilege's rule: raise-only, then clamped to the
  // ceiling (spec §5.3). moved reports a level that changed, which is a
  // write to what the refresh decides (Context.PolicyRev).
  func ApplyPrivilege(c *Context, level uint8) (moved bool) {
  	held := c.PrivLvl
  	if level > c.PrivLvl {
  		c.PrivLvl = level
  	}
  	if ceiling, ok := c.PrivilegeCeiling(); ok && c.PrivLvl > ceiling {
  		c.PrivLvl = ceiling
  	}
  	return c.PrivLvl != held
  }

  // ApplyRefresh is RefreshContext's rule, ExpectRev aside (the caller
  // compares it with the revision it read): ErrPastGrace, writing nothing,
  // for a ceiling before r.GraceCutoff; else the window, AuthTime,
  // RefreshedAt and BlobHash. moved reports a blob hash that changed.
  // RevokedAt is not on the list: a refresh is a directory re-resolution,
  // not a credential re-verification.
  func ApplyRefresh(c *Context, r ContextRefresh) (moved bool, err error) {
  	if !r.GraceCutoff.IsZero() && !c.SessionExpires.IsZero() && c.SessionExpires.Before(r.GraceCutoff) {
  		return false, ErrPastGrace
  	}
  	switch {
  	case r.SessionAge != nil && *r.SessionAge == 0:
  		c.SessionExpires = time.Time{}
  	case r.SessionAge != nil:
  		c.SessionExpires = r.AuthTime.Add(*r.SessionAge)
  	case c.HasCeiling():
  		c.SessionExpires = r.AuthTime.Add(c.SessionExpires.Sub(c.AuthTime))
  	}
  	c.AuthTime, c.RefreshedAt = r.AuthTime, r.RefreshedAt
  	moved = r.BlobHash != "" && r.BlobHash != c.BlobHash
  	if r.BlobHash != "" {
  		c.BlobHash = r.BlobHash
  	}
  	return moved, nil
  }

  // ApplyRevokedAt is SetRevokedAt's rule: the later mark stands, or a
  // token minted between the two would lift the revocation at a join.
  func ApplyRevokedAt(c *Context, at time.Time) {
  	if at.After(c.RevokedAt) {
  		c.RevokedAt = at
  	}
  }

  // CheckContextPolicy refuses a policy write that neither revokes nor
  // names a blob: a live context pointing at no blob is a corrupt record.
  func CheckContextPolicy(p ContextPolicy) error {
  	if p.RevokedAt.IsZero() && p.BlobHash == "" {
  		return errors.New("store: a policy write that does not revoke must name a blob hash")
  	}
  	return nil
  }

  // ApplyContextPolicy is SetContextPolicy's rule, the policy revision's
  // compare aside (the caller's): a revocation keeps the later mark; any
  // other write replaces the blob, ceiling and enable, lowers a held level
  // above the new ceiling, and only ever moves the session ceiling earlier
  // (decision 33).
  func ApplyContextPolicy(c *Context, p ContextPolicy) {
  	if !p.RevokedAt.IsZero() {
  		ApplyRevokedAt(c, p.RevokedAt)
  		return
  	}
  	c.BlobHash, c.MaxPrivilege, c.Enable = p.BlobHash, p.MaxPrivilege, p.Enable
  	if ceiling, ok := c.PrivilegeCeiling(); ok && c.PrivLvl > ceiling {
  		c.PrivLvl = ceiling
  	}
  	if p.MaxSessionAge > 0 {
  		if ceiling := c.AuthTime.Add(p.MaxSessionAge); c.SessionExpires.IsZero() || ceiling.Before(c.SessionExpires) {
  			c.SessionExpires = ceiling
  		}
  	}
  }
  ```

  Keep the memory setters' comments where they explain the store's side (the lock, the
  revisions), and move the ones that explain a rule onto its `Apply` function.

  Create `internal/store/marks.go`:

  ```go
  package store

  import (
  	"sync"
  	"time"
  )

  // Marks is the daemon's copy of the standing revocation marks (plan 7d;
  // spec §13, decision 35). The store is the authority: port49d loads every
  // mark from it at start, before any listener binds, and the broker adds a
  // mark once its write has landed and removes one once its lift has. The
  // authorizer, the enable gate and a receipt's replay read it on every
  // request, so a context its principal or certificate names is denied
  // whatever the record says: a record put back from before the revocation,
  // or a context a revocation never reached (a start that kept it). It has
  // no minted-after exception, unlike CarryRevocation: a mint reads the
  // marks first and after its last write and deletes what it wrote if one
  // appeared (decision 32), so no live token was minted after a standing
  // mark. A nil *Marks names nothing. It is safe for concurrent use.
  type Marks struct {
  	mu sync.RWMutex
  	m  map[[2]string]time.Time
  }

  func NewMarks() *Marks { return &Marks{m: map[[2]string]time.Time{}} }

  // Set puts r in force, or lifts it when on is false. A mark already in
  // force keeps its first time, as PutRevocation keeps it.
  func (m *Marks) Set(r Revocation, on bool) {
  	if m == nil {
  		return
  	}
  	m.mu.Lock()
  	defer m.mu.Unlock()
  	k := [2]string{r.Kind, r.Key}
  	if !on {
  		delete(m.m, k)
  		return
  	}
  	if _, ok := m.m[k]; !ok {
  		m.m[k] = r.At
  	}
  }

  // RevokedAt is when c stands revoked: the later of its own RevokedAt and
  // a mark standing for its principal or its certificate (CertKey of its
  // credential; a blank key names no certificate). Zero when neither.
  func (m *Marks) RevokedAt(c Context) time.Time {
  	at := c.RevokedAt
  	if m == nil {
  		return at
  	}
  	m.mu.RLock()
  	defer m.mu.RUnlock()
  	if t, ok := m.m[[2]string{RevocationPrincipal, c.Principal}]; ok && c.Principal != "" {
  		at = later(at, t)
  	}
  	if ck := CertKey(c.Credential.Issuer, c.Credential.Serial); !BlankCertKey(ck) {
  		if t, ok := m.m[[2]string{RevocationCert, ck}]; ok {
  			at = later(at, t)
  		}
  	}
  	return at
  }

  // Len is how many marks stand.
  func (m *Marks) Len() int {
  	if m == nil {
  		return 0
  	}
  	m.mu.RLock()
  	defer m.mu.RUnlock()
  	return len(m.m)
  }
  ```

  `later` is join.go's.

- [ ] **Step 3: The memory store.** In `internal/store/memory/memory.go`:
  - `SetPrivilege`, `RefreshContext`, `SetRevokedAt` and `SetContextPolicy` keep their locking,
    their not-found and revision checks, and their revision bookkeeping, and call the rule:
    - `moved := store.ApplyPrivilege(&e.c, level)`;
    - `moved, err := store.ApplyRefresh(&e.c, r)`, after the `ExpectRev` check, returning `err`
      before anything is written;
    - `store.ApplyRevokedAt(&e.c, at)`;
    - `store.CheckContextPolicy(p)` first, then the policy-revision compare, then
      `store.ApplyContextPolicy(&e.c, p)`.
  - Add:

    ```go
    // RewriteContext writes c over the live record at k only while its
    // revision is rev, under the one lock (store.Store): the sealing
    // layer's narrow setter.
    func (s *Store) RewriteContext(_ context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration,
    	policyMoved bool) error {
    	s.mu.Lock()
    	defer s.mu.Unlock()
    	now := s.now()
    	e, ok := s.contexts[k]
    	if !ok || !e.exp.After(now) {
    		delete(s.contexts, k)
    		return store.ErrNotFound
    	}
    	if e.rev != rev {
    		return store.ErrConflict
    	}
    	c.Rev, c.PolicyRev = 0, 0 // the entry holds the revisions
    	c.LastTouchedAt = e.c.LastTouchedAt
    	if ttl > 0 {
    		e.exp, c.LastTouchedAt = now.Add(ttl), now
    	}
    	e.c = c
    	e.rev = s.nextRevLocked()
    	if policyMoved {
    		e.policyRev = e.rev
    	}
    	s.contexts[k] = e
    	if ttl > 0 {
    		s.extendIndexesLocked(store.ContextRef{NAS: k.NAS, Username: k.Username}, e.exp)
    	}
    	return nil
    }
    ```

- [ ] **Step 4: The sealing layer.** In `internal/store/crypt/crypt.go`:

  1. **Additional data beyond the key id.** Change `seal(key, plaintext)` to `seal(key Key,
     plaintext, bound []byte)`. The AEAD's additional data becomes `append([]byte(key.ID),
     bound...)`; with `bound` nil it is the key id alone, exactly as before, so every record
     sealed today still opens. Give `Open` the same `bound` through an unexported `open(sealed,
     bound)`, and add:

     ```go
     // SealBound is Seal with bound appended to the additional data, so the
     // record opens only where it was sealed for: OpenBound with the same
     // bound (plan 7d). Seal is SealBound with none.
     func (k Keys) SealBound(plaintext, bound []byte) ([]byte, error) { return seal(k.Current, plaintext, bound) }

     // OpenBound is Open for a record SealBound sealed with bound.
     func (k Keys) OpenBound(sealed, bound []byte) ([]byte, error) { return k.open(sealed, bound) }
     ```

  2. **The context, sealed whole.** Replace `contextSecret` and `sealContext`, and add
     `contextAAD` and `openContext`:

     ```go
     // contextSealVersion is the form of contextSecret below: 2 is plan 7d's
     // whole record. A context in any other form does not open, and is
     // replaced at its next login (store.UnreadableContextError).
     const contextSealVersion = 2

     // contextSecret is everything of a context the authorizer trusts,
     // sealed whole (plan 7d; Ruling 17): the identity and credential, as
     // before, and the privilege, the ceiling, the policy, the clocks and
     // the revocation. Only the store's bookkeeping stays outside it: the
     // revisions, the idle clock (LastTouchedAt), and accounting's
     // annotations, which authorize nothing. RevokedAt is also written in
     // the clear (sealContext).
     type contextSecret struct {
     	V              int              `json:"v"`
     	CtxID          string           `json:"ctx_id"`
     	Principal      string           `json:"principal"`
     	Username       string           `json:"username"`
     	Port           string           `json:"port"`
     	RemAddr        string           `json:"rem_addr"`
     	Credential     store.Credential `json:"credential"`
     	PrivLvl        uint8            `json:"priv_lvl"`
     	BlobHash       string           `json:"blob_hash"`
     	MaxPrivilege   uint8            `json:"max_privilege"`
     	Enable         string           `json:"enable"`
     	AuthTime       time.Time        `json:"auth_time"`
     	SessionExpires time.Time        `json:"session_expires"`
     	RefreshedAt    time.Time        `json:"refreshed_at"`
     	RevokedAt      time.Time        `json:"revoked_at"`
     	CreatedAt      time.Time        `json:"created_at"`
     }

     // contextAAD binds a sealed context to the key it is stored at: the
     // record kind, the NAS and the username, each length-prefixed, so no two
     // keys share an encoding. A record copied to another (nas, username)
     // fails authentication there (pre-flight I12).
     func contextAAD(k store.ContextKey) []byte {
     	return []byte(fmt.Sprintf("|context|%d:%s|%d:%s", len(k.NAS), k.NAS, len(k.Username), k.Username))
     }

     // sealContext seals c's trusted fields for k. What the backend holds
     // beside the sealed bytes is the bookkeeping and RevokedAt: the
     // revocation stays in the clear too, so a revocation needs no key
     // (SetRevokedAt), and a read takes the later of the two (openContext).
     func (w *wrapped) sealContext(k store.ContextKey, c store.Context) (store.Context, error) {
     	b, err := json.Marshal(contextSecret{V: contextSealVersion, CtxID: c.CtxID, Principal: c.Principal,
     		Username: c.Username, Port: c.Port, RemAddr: c.RemAddr, Credential: c.Credential, PrivLvl: c.PrivLvl,
     		BlobHash: c.BlobHash, MaxPrivilege: c.MaxPrivilege, Enable: c.Enable, AuthTime: c.AuthTime,
     		SessionExpires: c.SessionExpires, RefreshedAt: c.RefreshedAt, RevokedAt: c.RevokedAt, CreatedAt: c.CreatedAt})
     	if err != nil {
     		return store.Context{}, err
     	}
     	s, err := w.keys.SealBound(b, contextAAD(k))
     	if err != nil {
     		return store.Context{}, err
     	}
     	return store.Context{RevokedAt: c.RevokedAt, LastTouchedAt: c.LastTouchedAt,
     		SessionDiscriminators: c.SessionDiscriminators, AccountingState: c.AccountingState,
     		Rev: c.Rev, PolicyRev: c.PolicyRev, Sealed: s}, nil
     }

     // openContext is sealContext reversed for the record read at k. Every
     // trusted field is the sealed one; RevokedAt is the later of the sealed
     // and the plaintext, so a keyless revocation is in force at once and a
     // store write that zeroes the plaintext lifts nothing.
     func (w *wrapped) openContext(k store.ContextKey, c store.Context) (store.Context, error) {
     	b, err := w.keys.OpenBound(c.Sealed, contextAAD(k))
     	if err != nil {
     		return store.Context{}, err
     	}
     	var cs contextSecret
     	if err := json.Unmarshal(b, &cs); err != nil {
     		return store.Context{}, err
     	}
     	if cs.V != contextSealVersion {
     		return store.Context{}, fmt.Errorf("crypt: a context sealed in form %d, not %d", cs.V, contextSealVersion)
     	}
     	revoked := cs.RevokedAt
     	if c.RevokedAt.After(revoked) {
     		revoked = c.RevokedAt
     	}
     	return store.Context{CtxID: cs.CtxID, Principal: cs.Principal, Username: cs.Username, Port: cs.Port,
     		RemAddr: cs.RemAddr, Credential: cs.Credential, PrivLvl: cs.PrivLvl, BlobHash: cs.BlobHash,
     		MaxPrivilege: cs.MaxPrivilege, Enable: cs.Enable, AuthTime: cs.AuthTime, SessionExpires: cs.SessionExpires,
     		RefreshedAt: cs.RefreshedAt, RevokedAt: revoked, CreatedAt: cs.CreatedAt, LastTouchedAt: c.LastTouchedAt,
     		SessionDiscriminators: c.SessionDiscriminators, AccountingState: c.AccountingState,
     		Rev: c.Rev, PolicyRev: c.PolicyRev}, nil
     }
     ```

     `PutContext`, `SwapContext` and `SwapLogin` call `w.sealContext(k, c)`, and send through
     `w.sent` (item 5 below), so the ledger is told. `GetContext` calls `w.openContext(k, c)`
     and, on its error, returns the `UnreadableContextError` it returns today, carrying the
     plaintext `Rev` and `RevokedAt`. A record that opens (`oc, err := w.openContext(k, c)`)
     is then checked against the ledger before it is returned:

     ```go
     	// The ledger (re-check IA1): a record sealed for this key that is not
     	// the one this process last wrote here, or first read here, is another
     	// login's written back. It opens, since it is bound to this key, and so
     	// it is denied as one that does not.
     	if !w.ledger.admits(k, oc.CtxID) {
     		return store.Context{}, &store.UnreadableContextError{Rev: c.Rev, RevokedAt: c.RevokedAt,
     			Err: w.openErr("context", ErrNotLastWritten)}
     	}
     ```

  2b. **The token and the receipt, bound to their keys** (re-check CA1). Replace
     `tokenSecret`, `receiptSecret`, `sealToken` and `openToken`, and add the two additional
     data functions:

     ```go
     // tokenSecret is everything of a token a redemption or a login trusts,
     // sealed (plan 7d; Ruling 17; re-check CA1): the secret and identity, as
     // before, and the kind, the expiry, the policy, the ceiling and the
     // clocks, which the login copies into its context (authen.go:705-724)
     // and the join compares with a revocation (MintedAt). Left in the clear
     // they would let a store write raise a login's privilege, widen its
     // blob, drop its ceiling or outlive a self revocation. ExpiresAt is also
     // written in the clear, for the backend's expiry (openToken).
     type tokenSecret struct {
     	Secret        []byte           `json:"secret"`
     	Principal     string           `json:"principal"`
     	Username      string           `json:"username"`
     	Credential    store.Credential `json:"credential"`
     	Kind          string           `json:"kind"`
     	ExpiresAt     time.Time        `json:"expires_at"`
     	BlobHash      string           `json:"blob_hash"`
     	MaxSessionAge time.Duration    `json:"max_session_age"`
     	Enable        string           `json:"enable"`
     	MaxPrivilege  uint8            `json:"max_privilege"`
     	AuthTime      time.Time        `json:"auth_time"`
     	MintedAt      time.Time        `json:"minted_at"`
     }

     // receiptSecret is a receipt's sealed part. FirstRedeemedAt anchors the
     // cap, so it is sealed too; the plaintext copy stays for the backend and
     // is never read back (re-check CA1).
     type receiptSecret struct {
     	CredentialSHA256 [32]byte  `json:"credential_sha256"`
     	Status           uint8     `json:"status"`
     	CtxID            string    `json:"ctx_id"`
     	FirstRedeemedAt  time.Time `json:"first_redeemed_at"`
     }

     // tokenAAD binds a sealed token to its key and its ID, each
     // length-prefixed: a token copied to another (nas, username) or given
     // another ID does not open (re-check CA1).
     func tokenAAD(k store.TokenKey, id string) []byte {
     	return []byte(fmt.Sprintf("|token|%d:%s|%d:%s|%d:%s", len(k.NAS), k.NAS, len(k.Username), k.Username,
     		len(id), id))
     }

     // receiptAAD binds a sealed receipt to its whole key: a login receipt
     // copied to the enable key would otherwise replay an escalation with no
     // enable token (re-check CA1).
     func receiptAAD(rk store.ReceiptKey) []byte {
     	return []byte(fmt.Sprintf("|receipt|%d:%s|%d:%s|%d:%s|%x", len(rk.NAS), rk.NAS, len(rk.Username), rk.Username,
     		len(rk.Kind), rk.Kind, rk.CredentialSHA256))
     }

     // errExpiryMoved is a token whose plaintext expiry is not the one sealed
     // with it. sealToken writes them equal, so a store write moved it, and an
     // extended one would be redeemable past the sealed one: it is dropped as
     // a token that will not open.
     var errExpiryMoved = errors.New("crypt: a token's plaintext expiry differs from its sealed one")

     func (w *wrapped) sealToken(k store.TokenKey, t store.Token) (store.Token, error) {
     	b, err := json.Marshal(tokenSecret{Secret: t.Secret, Principal: t.Principal, Username: t.Username,
     		Credential: t.Credential, Kind: t.Kind, ExpiresAt: t.ExpiresAt, BlobHash: t.BlobHash,
     		MaxSessionAge: t.MaxSessionAge, Enable: t.Enable, MaxPrivilege: t.MaxPrivilege, AuthTime: t.AuthTime,
     		MintedAt: t.MintedAt})
     	if err != nil {
     		return store.Token{}, err
     	}
     	s, err := w.keys.SealBound(b, tokenAAD(k, t.ID))
     	if err != nil {
     		return store.Token{}, err
     	}
     	return store.Token{ID: t.ID, ExpiresAt: t.ExpiresAt, Sealed: s}, nil
     }

     func (w *wrapped) openToken(k store.TokenKey, t store.Token) (store.Token, error) {
     	b, err := w.keys.OpenBound(t.Sealed, tokenAAD(k, t.ID))
     	if err != nil {
     		return store.Token{}, err
     	}
     	var ts tokenSecret
     	if err := json.Unmarshal(b, &ts); err != nil {
     		return store.Token{}, err
     	}
     	if !ts.ExpiresAt.Equal(t.ExpiresAt) {
     		return store.Token{}, errExpiryMoved
     	}
     	return store.Token{ID: t.ID, Secret: ts.Secret, Kind: ts.Kind, ExpiresAt: ts.ExpiresAt, Principal: ts.Principal,
     		Username: ts.Username, BlobHash: ts.BlobHash, MaxSessionAge: ts.MaxSessionAge, Enable: ts.Enable,
     		MaxPrivilege: ts.MaxPrivilege, Credential: ts.Credential, AuthTime: ts.AuthTime, MintedAt: ts.MintedAt}, nil
     }
     ```

     - `PutToken` calls `w.sealToken(k, t)`, and `Candidates` `w.openToken(k, t)`; a token
       either drops is counted through `openErr("token", …)`, as one under a retired key is.
     - `RedeemAndReceipt` seals the four fields of `receiptSecret` with
       `w.keys.SealBound(…, receiptAAD(wr.Key))`, and blanks the three it blanked; it leaves the
       plaintext `FirstRedeemedAt` as it is.
     - `GetReceipt` opens with `w.keys.OpenBound(r.Sealed, receiptAAD(rk))`, and sets
       `FirstRedeemedAt` from the sealed copy.
     - Idempotency responses keep the key id alone as additional data. The daemon's role has no
       access to `id/` (Ruling 10), so only the broker's credential, which holds the whole
       keyspace, could move one.

  2c. **The ledger.** Create `internal/store/crypt/ledger.go`:

     ```go
     package crypt

     import (
     	"errors"
     	"sync"

     	"github.com/rhwendt/port49/internal/store"
     )

     // ErrNotLastWritten is a context that opens at its key but is not the
     // one this process last wrote there, or first read there: another
     // login's record, written back by whoever can write the store (plan 7d;
     // Ruling 17; re-check IA1). GetContext returns it inside an
     // UnreadableContextError, so every handler treats it as a record that
     // will not open.
     var ErrNotLastWritten = errors.New("crypt: not the context this port49d last wrote at its key")

     // Ledger is, per context key, the ctx_id this process last wrote there,
     // or first read there (plan 7d; Ruling 17; re-check IA1). A sealed
     // context is bound to its key, not to the login that wrote it, so
     // without the ledger a record of Alice's saved from leaf-01/netops and
     // written back over Bob's there would authorize Bob's session as Alice.
     //
     // A write is told before it is sent (begin) and when it ends (end): in
     // flight it is admitted beside the last, landed it replaces the last,
     // refused (ErrConflict, ErrNotFound) it wrote nothing, and with any other
     // error it may have committed (spec §5.6), so it stays admitted until a
     // later write lands. A key with no entry takes the first record read
     // there, so a start's reads seed it before any listener binds; a record
     // put back while the process was stopped is the residual.
     //
     // A read racing a login's replace can return the replaced record after
     // the replace landed; that one request is denied, which fails closed.
     // It holds one entry per key this process has read or written, kept
     // while it runs. One Ledger is shared by every Wrap in a process
     // (WithLedger). It is safe for concurrent use.
     type Ledger struct {
     	mu sync.Mutex
     	m  map[store.ContextKey]*ledgerEntry
     }

     type ledgerEntry struct {
     	last     string          // the last write that landed, or the first read
     	known    bool            // last is set: false for a key whose first write is in flight
     	inFlight map[string]int  // writes sent and not yet ended, by ctx_id
     	unknown  map[string]bool // writes that ended with neither a landing nor a refusal
     }

     func NewLedger() *Ledger { return &Ledger{m: map[store.ContextKey]*ledgerEntry{}} }

     func (l *Ledger) entry(k store.ContextKey) *ledgerEntry {
     	e := l.m[k]
     	if e == nil {
     		e = &ledgerEntry{inFlight: map[string]int{}, unknown: map[string]bool{}}
     		l.m[k] = e
     	}
     	return e
     }

     // admits reports whether a record holding id may be read at k.
     func (l *Ledger) admits(k store.ContextKey, id string) bool {
     	l.mu.Lock()
     	defer l.mu.Unlock()
     	e, ok := l.m[k]
     	if !ok {
     		e = l.entry(k)
     		e.last, e.known = id, true
     		return true
     	}
     	return (e.known && id == e.last) || e.inFlight[id] > 0 || e.unknown[id]
     }

     func (l *Ledger) begin(k store.ContextKey, id string) {
     	l.mu.Lock()
     	defer l.mu.Unlock()
     	l.entry(k).inFlight[id]++
     }

     func (l *Ledger) end(k store.ContextKey, id string, err error) {
     	l.mu.Lock()
     	defer l.mu.Unlock()
     	e := l.entry(k)
     	if e.inFlight[id]--; e.inFlight[id] <= 0 {
     		delete(e.inFlight, id)
     	}
     	switch {
     	case err == nil:
     		e.last, e.known = id, true
     		clear(e.unknown)
     	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrNotFound):
     	default:
     		e.unknown[id] = true
     	}
     }
     ```

     A delete leaves the entry as it is: the record it removed is past its sealed ceiling and
     grace (author.go, sessionrefresh.go), which deny it if it is put back. A key whose first
     write is still in flight (`known` false) admits only that write: a record no one in this
     process wrote or read cannot have appeared there by any other path. An empty `ctx_id` (a
     test's seed) is an id like any other.

     In `crypt.go`, add the option and give `wrapped` the ledger:

     ```go
     // Option configures Wrap.
     type Option func(*wrapped)

     // WithLedger shares l with every other Wrap given it, so the daemon's and
     // the broker's layers in one process agree on what each key last held
     // (re-check IA1). Without it each Wrap keeps its own.
     func WithLedger(l *Ledger) Option { return func(w *wrapped) { w.ledger = l } }
     ```

     Add `ledger *Ledger` to `wrapped`. Make `Wrap` variadic, set `ledger: NewLedger()` in its
     literal, then apply each option. Add `sent`, which every sealed context write goes through:

     ```go
     // sent sends one sealed write of the context id at k, telling the ledger
     // before and after (re-check IA1).
     func (w *wrapped) sent(k store.ContextKey, id string, send func() error) error {
     	w.ledger.begin(k, id)
     	err := send()
     	w.ledger.end(k, id, err)
     	return err
     }
     ```

     For example, `PutContext` becomes `return w.sent(k, c.CtxID, func() error { return
     w.inner.PutContext(ctx, k, sc, ttl) })`. `SwapContext`, `SwapLogin`, `RewriteContext` and
     `rewrite`'s write do the same.

  3. **The rewrite, and the setters on sealed fields.** Add, and replace the four pass-throughs:

     ```go
     // rewrite is a narrow setter on a field the seal covers (plan 7d; Ruling
     // 17): read the record, open it, apply the setter's rule, seal it again,
     // and rewrite it on the revision read (store.RewriteContext), reading
     // again on a lost race up to attempts times. apply may refuse
     // (ErrConflict, ErrPastGrace), and then nothing is written. A record
     // this layer cannot open, or the ledger does not admit, is GetContext's
     // UnreadableContextError.
     func (w *wrapped) rewrite(ctx context.Context, k store.ContextKey, ttl time.Duration, attempts int,
     	apply func(c *store.Context) (policyMoved bool, err error)) error {
     	for attempt := 0; attempt < attempts; attempt++ {
     		c, err := w.GetContext(ctx, k)
     		if err != nil {
     			return err
     		}
     		rev := c.Rev
     		moved, err := apply(&c)
     		if err != nil {
     			return err
     		}
     		sc, err := w.sealContext(k, c)
     		if err != nil {
     			return err
     		}
     		switch err := w.sent(k, c.CtxID, func() error { return w.inner.RewriteContext(ctx, k, rev, sc, ttl, moved) }); {
     		case err == nil:
     			return nil
     		case !errors.Is(err, store.ErrConflict):
     			return err
     		}
     		if err := ctx.Err(); err != nil {
     			return err
     		}
     	}
     	return fmt.Errorf("crypt: context still changing after %d attempts: %w", attempts, store.ErrConflict)
     }

     // SetPrivilege is a rewrite: the level is sealed (plan 7d).
     func (w *wrapped) SetPrivilege(ctx context.Context, k store.ContextKey, level uint8) error {
     	return w.rewrite(ctx, k, 0, store.MaxJoinAttempts, func(c *store.Context) (bool, error) {
     		return store.ApplyPrivilege(c, level), nil
     	})
     }

     // RefreshContext is a rewrite that extends the record, as the inner
     // store's does; ExpectRev is compared with the revision each attempt
     // reads.
     func (w *wrapped) RefreshContext(ctx context.Context, k store.ContextKey, r store.ContextRefresh, ttl time.Duration) error {
     	return w.rewrite(ctx, k, ttl, store.MaxJoinAttempts, func(c *store.Context) (bool, error) {
     		if r.ExpectRev != 0 && c.Rev != r.ExpectRev {
     			return false, store.ErrConflict
     		}
     		return store.ApplyRefresh(c, r)
     	})
     }

     // SetRevokedAt writes the plaintext mark first: it needs no key, lands
     // whatever the record holds, and is in force at once, since a read takes
     // the later of the two. Then it seals the mark into the record, so a
     // store write cannot take it back (plan 7d). The seal's write is not a
     // second policy write: the plaintext one already moved PolicyRev. A
     // record this layer cannot open keeps the plaintext mark alone, and is
     // denied as unreadable anyway; a record gone since is nothing to seal.
     //
     // A busy session can win the seal's race many times, so it retries until
     // the caller's deadline, and sealAttempts times when the caller set none.
     // The revocation is in force from the first write either way, so an error
     // after it says so, and that only the seal is pending (re-check MA2).
     func (w *wrapped) SetRevokedAt(ctx context.Context, k store.ContextKey, at time.Time) error {
     	if err := w.inner.SetRevokedAt(ctx, k, at); err != nil {
     		return err
     	}
     	attempts := sealAttempts
     	if _, ok := ctx.Deadline(); ok {
     		attempts = math.MaxInt
     	}
     	err := w.rewrite(ctx, k, 0, attempts, func(c *store.Context) (bool, error) {
     		store.ApplyRevokedAt(c, at)
     		return false, nil
     	})
     	var u *store.UnreadableContextError
     	switch {
     	case err == nil, errors.As(err, &u), errors.Is(err, store.ErrNotFound):
     		return nil
     	}
     	return fmt.Errorf("crypt: revoked (the plaintext mark is in force); sealing it into the record is pending: %w", err)
     }

     // sealAttempts bounds SetRevokedAt's seal when its caller set no
     // deadline: 64 lost races in a row is a store that never holds still.
     const sealAttempts = 64

     // SetContextPolicy is a rewrite compared on the policy revision each
     // attempt reads. A revoking write on a record this layer cannot open
     // still lands, through the inner store's plaintext compare and mark:
     // revocation needs no key.
     func (w *wrapped) SetContextPolicy(ctx context.Context, k store.ContextKey, policyRev uint64, p store.ContextPolicy) error {
     	if err := store.CheckContextPolicy(p); err != nil {
     		return err
     	}
     	err := w.rewrite(ctx, k, 0, store.MaxJoinAttempts, func(c *store.Context) (bool, error) {
     		if c.PolicyRev != policyRev {
     			return false, store.ErrConflict
     		}
     		store.ApplyContextPolicy(c, p)
     		return true, nil
     	})
     	var u *store.UnreadableContextError
     	if !p.RevokedAt.IsZero() && errors.As(err, &u) {
     		return w.inner.SetContextPolicy(ctx, k, policyRev, store.ContextPolicy{RevokedAt: p.RevokedAt})
     	}
     	return err
     }

     // RewriteContext seals c for k and passes the write through, telling
     // the ledger.
     func (w *wrapped) RewriteContext(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration,
     	policyMoved bool) error {
     	sc, err := w.sealContext(k, c)
     	if err != nil {
     		return err
     	}
     	return w.sent(k, c.CtxID, func() error { return w.inner.RewriteContext(ctx, k, rev, sc, ttl, policyMoved) })
     }
     ```

     Add `"math"` to the imports. `TouchContext` and `AnnotateContext` stay pass-throughs: they
     write the idle clock and accounting's annotations, which the seal does not cover and
     nothing authorizes on. Rewrite the comments on the old pass-throughs, and the package
     comment, to say what is sealed now (the context whole, the token's trusted fields, the
     receipt, each bound to its key), what the ledger denies, and why the idle clock is not
     sealed: a context kept alive past its idle TTL is still bounded by its sealed ceiling, if
     it has one, and under `max_session_age: never` by nothing but the refresh and revocation
     (re-check MA1).
  4. Existing crypt tests that assert a now-sealed field sits in the clear in the inner record,
     or that a now-rewritten setter is a single pass-through, encode the old design. Change each
     to assert the new one, and name each in the report and the commit. This is the ruling's
     change, not a weakened test.
     - `TestWrappedStoreHoldsNoPlaintext` asserts `raw[0].Kind` and `raw[0].BlobHash` stay in
       the clear ("keying fields must stay plaintext"). They are sealed now: assert the `ID`
       and `ExpiresAt` alone are in the clear and the rest blank.
     - `TestAContextUnderARetiredKeyIsReplacedCarryingItsRevocation` builds its unopenable
       record its own way: make it build one through a `Wrap` under the retired key, as
       `TestARevocationOfAnUnopenableContextNeedsNoKey` above does.
     - A test anywhere (crypt, authen, author, broker) that writes a context straight to the
       inner store, at a key the sealing layer has already read or written, now meets the
       ledger. Write through the layer, or give that phase its own `Wrap`, and name each.

- [ ] **Step 5: The daemon reads the marks.**
  - `internal/daemon/author/author.go`: add `marks *store.Marks` to `Handler`, and
    `WithMarks(m *store.Marks) *Handler`, which sets it and returns `h`. Replace `if
    !c.RevokedAt.IsZero() {` (author.go:258) with:

    ```go
    	// The record's own revocation, or a standing mark for its principal
    	// or certificate, whatever the record says (plan 7d; Ruling 17): a
    	// record put back from before its revocation, or a context a
    	// revocation never reached, is still denied.
    	if !h.marks.RevokedAt(c).IsZero() {
    ```
  - `internal/daemon/authen/authen.go`: the same field and `WithMarks` on `Handler`. In the
    enable gate replace `if !c.RevokedAt.IsZero() {` (authen.go:296) with `if
    !s.h.marks.RevokedAt(c).IsZero() {`. In the receipt replay (authen.go:351), replace `case
    !live.RevokedAt.IsZero():` with `case !s.h.marks.RevokedAt(live).IsZero():`, and pass
    `s.h.marks.RevokedAt(live)` to `s.revoked` in place of `live.RevokedAt`.
  - `internal/broker/broker.go`: add to `Broker`, beside `Conns`:

    ```go
    	// Marks is the daemon's copy of the standing marks (store.Marks): a
    	// revocation puts its mark in it once the store holds the mark, and a
    	// lift takes it out once the store's is gone. Nil keeps none.
    	Marks *store.Marks
    ```

    In `revoke.go`'s `Revoke`, after `rep.Mark` is settled (after the `GetRevocation` that keeps
    an earlier mark), add `b.Marks.Set(rep.Mark, true)`. In `Lift`, after `DeleteRevocation`
    succeeds, add `b.Marks.Set(cur, false)`.
  - `cmd/port49d/main.go`: before the broker block, `authMarks := store.NewMarks()`. After the
    revocations are restored (the block ending `… revocation(s) in force from %s\n`), add `for
    _, r := range marks { authMarks.Set(r, true) }` and, inside `if brk != nil`, `brk.Marks =
    authMarks`. Give `authen.New(…)` `.WithMarks(authMarks)` and `author.New(…)…`
    `.WithMarks(authMarks)` in `deps`. With no broker there are no marks, and the set stays
    empty.
  - The ledger needs nothing in `main.go` on 7d-1: the one `crypt.Wrap` there serves the daemon
    and the broker, and keeps its own ledger. Task 12 shares one across the two `Wrap`s etcd
    needs.

- [ ] **Step 6: Run.**

  Run: `go test ./internal/store/... ./internal/daemon/... ./internal/broker/ ./cmd/port49d/ -count=1`
  Expected: PASS, including:
  - `TestTheMemoryStoreHoldsEveryProperty/RewriteBindsToTheRevision` and
    `TestTheSealingLayerHoldsEveryProperty/<every property>`. The sealing layer's narrow
    setters now run the shared rules, and every property pins that they mean what memory's do;
    every property's contexts pass the ledger.
  - `TestTheSealCoversWhatAuthorizationTrusts`, `TestARevocationOfAnUnopenableContextNeedsNoKey`,
    `TestTheTokensTrustedFieldsAreSealed`, `TestAReceiptIsBoundToItsKey`,
    `TestTheLedgerDeniesAnotherLoginsContext`, `TestTheLedgerAdmitsWritesInFlight`,
    `TestMarksNameAContextByPrincipalOrCertificate`, `TestAStandingMarkDeniesAnUnrevokedContext`,
    the two authen tests and `TestRevokeAndLiftKeepTheDaemonsMarks`.
  - Every existing authen test that redeems a token, through whatever store its fixture uses:
    the token's fields now come from the seal.

  Mutation checks (do them, report them, revert them):
  1. In `openContext`, take the plaintext `RevokedAt` instead of the later of the two.
     `TestTheSealCoversWhatAuthorizationTrusts` must fail ("a zeroed revoked_at").
  2. In `contextAAD`, return `nil`. The transplant case must fail.
  3. In `crypt.SetPrivilege`, pass through to the inner store instead of rewriting.
     `SetPrivilegeIsRaiseOnly` through the sealing layer must fail.
  4. In `author.go`, read `c.RevokedAt` instead of `h.marks.RevokedAt(c)`.
     `TestAStandingMarkDeniesAnUnrevokedContext` must fail.
  5. In `openToken`, take `MaxPrivilege` from the plaintext record `t` instead of `ts`.
     `TestTheTokensTrustedFieldsAreSealed` must fail ("a raised privilege").
  6. In `openToken`, drop the expiry comparison. `TestTheTokensTrustedFieldsAreSealed` must fail
     ("an extended plaintext expiry").
  7. In `receiptAAD`, leave out `rk.Kind`. `TestAReceiptIsBoundToItsKey` must fail.
  8. In `GetContext`, skip the ledger check. `TestTheLedgerDeniesAnotherLoginsContext` must
     fail.
  9. In `Ledger.end`, treat an unknown outcome as a refusal. `TestTheLedgerAdmitsWritesInFlight`
     must fail.

- [ ] **Step 7: Commit.**

  ```bash
  gofmt -w internal/store internal/daemon/author internal/daemon/authen internal/broker cmd/port49d
  make build && make test && make vet
  git add internal/store/store.go internal/store/apply.go internal/store/marks.go internal/store/marks_test.go \
    internal/store/memory/memory.go internal/store/crypt/crypt.go internal/store/crypt/ledger.go \
    internal/store/crypt/crypt_test.go \
    internal/store/storetest/rewrite.go internal/store/storetest/storetest.go \
    internal/daemon/author/author.go internal/daemon/author/author_test.go \
    internal/daemon/authen/authen.go internal/daemon/authen/authen_test.go \
    internal/broker/broker.go internal/broker/revoke.go internal/broker/revoke_test.go cmd/port49d/main.go
  git commit -m "feat(store): seal what a login and an authorization trust, a ledger, and the marks

  Every field the authorizer trusts is now sealed with the identity,
  under the context key as additional data, so a store write cannot
  zero a revocation, raise a privilege, swap a blob or move a record to
  another key; revoked_at is kept in the clear too, so revoking needs no
  key, and a read takes the later. A token's kind, expiry, policy blob,
  session age, enable mechanism, maximum privilege and clocks are sealed
  with its secret, bound to its key and ID, so a login copies only what
  the broker minted; a token whose plaintext expiry moved is dropped. A
  receipt is bound to its whole key, so a login receipt cannot answer an
  enable. A ledger of the ctx_id this process last wrote at each key
  denies another login's context written back. A narrow setter on a
  sealed field is a read, the shared rule (store.Apply*), a reseal and a
  RewriteContext on the revision read. The daemon holds the standing
  marks in memory, the store their authority, and the authorizer, the
  enable gate and a receipt's replay deny any context they name (plan
  7d, Ruling 17; the controller's rulings on pre-flight I12 and re-check
  CA1, IA1). A record sealed the old way does not open.

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
  `store.ErrUnavailable`, `store.ErrRefused` (Task 3); `Store.RewriteContext` (Task 4b); every
  `storetest` property (Tasks 2–4b).
- Produces:
  - `type etcd.Config struct { Endpoints []string; TLS *tls.Config; Prefix string; Now func() time.Time; LeaseGrace, DialTimeout time.Duration }`
  - `func etcd.Open(c Config) (*Store, error)`, `func (s *Store) Close() error`,
    `func (s *Store) Ping(ctx context.Context) error`
  - `var etcd.ErrRefused = store.ErrRefused` (etcd refused this identity: a role, not an outage),
    `var etcd.ErrTooLarge` (a request etcd will not take for its size: neither)
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

**Gotchas, measured** (before this plan, and by the pre-flight review on v3.6.15):
- `clientv3.New` does not block and does not fail on an unreachable endpoint: it returns in
  about 0.1 ms either way, and the first call then fails at its deadline. An expired or wrong
  client certificate looks the same: `New` returns a client, and a `Get` fails `context deadline
  exceeded`, which `unavailable` classifies `store.ErrUnavailable` (pre-flight I9). So `Open`
  says nothing about reachability, and port49d checks a certificate's validity and the TLS
  handshake itself, before it calls `Open` (Task 12, `identity` and `probeTLS`).
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
  ```

  Do not run `go mod tidy` yet: nothing imports these until Steps 2–10, and tidy would drop them
  (pre-flight M21). Step 11 runs it. `go.mod`'s `go` line becomes `go 1.26` (OD-1). Check that `go build ./cmd/...` does not link
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

  Every member listens on `127.0.0.1:0` and keeps its data in a `t.TempDir()` (or `Main`'s own
  temporary directory), except `StartCluster`'s, whose initial cluster must name its peers'
  addresses before they bind. `freePort` can therefore hand out a port another process takes
  first. If a `StartCluster` member fails with "address already in use", stop the members that
  started and try once more with new ports, and say so in a comment (pre-flight M29). These
  tests add about 20–40 s to `make test` (four full `storetest.Run` passes and the clusters);
  note the measured figure in the Task 8 report.

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
  	// A request etcd will not take for its size is neither an outage nor a
  	// refusal: it says nothing about the store's health (pre-flight M19).
  	if err := unavailable(rpctypes.ErrRequestTooLarge); !errors.Is(err, ErrTooLarge) || errors.Is(err, store.ErrUnavailable) {
  		t.Fatalf("a request too large: %v", err)
  	}
  }

  // Every family scanned by prefix ends its scanned part with "/", so one
  // key that is the start of another never lists the other's entries: the
  // key schema itself, pinned apart from any lookup's filtering (pre-flight
  // M24; Review Focus 3).
  func TestScannedKeysEndWithASlash(t *testing.T) {
  	k := newKeys("/p/")
  	ref := store.ContextRef{NAS: "leaf-01", Username: "alice"}
  	tk := store.TokenKey{NAS: "leaf-01", Username: "alice"}
  	rk := store.ReceiptKey{NAS: "leaf-01", Username: "alice", Kind: store.KindLogin}
  	for _, pair := range [][2]string{
  		{k.lookups(famByPrincipal, "user:al"), k.lookup(famByPrincipal, "user:alice", ref)},
  		{k.tokenIndex(famTokByPrin, "user:al"), k.tokenIndexed(famTokByPrin, "user:alice", tk)},
  		{k.receiptsBy("user:al"), k.receiptBy("user:alice", rk)},
  		{k.tokens(store.TokenKey{NAS: "leaf-0", Username: "alice"}), k.token(tk, "t")},
  	} {
  		if !strings.HasSuffix(pair[0], "/") || strings.HasPrefix(pair[1], pair[0]) {
  			t.Errorf("%q scans %q", pair[0], pair[1])
  		}
  	}
  }
  ```

  Add `"strings"` to the test's imports.

  Run: `go test ./internal/store/etcd/ -count=1`
  Expected: FAIL to build (`newStore`, `Store`, `Config`, `unavailable`, `ErrRefused`,
  `ErrTooLarge`, `newKeys` undefined).

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
  	"google.golang.org/grpc/codes"
  	"google.golang.org/grpc/status"

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
  // does not grant it, or authentication that failed. It is store.ErrRefused,
  // so the guard, which imports no backend, tells it from an outage: it trips
  // no circuit (Task 9).
  var ErrRefused = store.ErrRefused

  // ErrTooLarge is a request etcd will not take for its size (its
  // --max-request-bytes, 1.5 MiB by default, or gRPC's 2 MiB message
  // limit). It is a fault in the request, not in the store: never
  // store.ErrUnavailable, so it trips no circuit (pre-flight M19).
  var ErrTooLarge = errors.New("etcd: request too large")

  // Open builds the store's clients. It never waits for etcd: clientv3.New
  // returns at once whether or not an endpoint answers, and an expired
  // certificate or a wrong CA fails only the first call, as a deadline
  // (pre-flight I9). A caller that must know etcd answers calls Ping; one
  // that must know why it does not checks the certificates and the TLS
  // handshake first (port49d does, Task 12). It fails only on a
  // configuration clientv3 refuses outright.
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
  		// Not ErrUnavailable: New does not dial, so this is a configuration
  		// it will not take (an endpoint it cannot parse, a TLS config it
  		// refuses), and waiting would not change it.
  		return nil, fmt.Errorf("etcd at %v: %w", c.Endpoints, err)
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
  // gave up is its own error; a refusal of this identity is ErrRefused; a
  // request too large is ErrTooLarge; any other — a deadline, no leader, no
  // quorum, a dropped connection — is store.ErrUnavailable. The guard reads
  // the caller's own context before this error (Task 9), so a deadline is
  // told apart there, not here.
  func unavailable(err error) error {
  	switch {
  	case err == nil:
  		return nil
  	case errors.Is(err, context.Canceled):
  		return err
  	case errors.Is(err, rpctypes.ErrPermissionDenied), errors.Is(err, rpctypes.ErrAuthFailed),
  		errors.Is(err, rpctypes.ErrUserEmpty), errors.Is(err, rpctypes.ErrInvalidAuthToken):
  		return fmt.Errorf("%w: %v", ErrRefused, err)
  	case errors.Is(err, rpctypes.ErrRequestTooLarge), status.Code(err) == codes.ResourceExhausted:
  		return fmt.Errorf("%w: %v", ErrTooLarge, err)
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
  	id      clientv3.LeaseID
  	granted time.Time // wall clock, no monotonic reading
  	until   time.Time // wall clock, no monotonic reading
  }

  func newLeases(cli *clientv3.Client, now func() time.Time, grace time.Duration) *leases {
  	return &leases{cli: cli, now: now, grace: grace, held: map[int64]heldLease{}}
  }

  // wall is the wall clock with its monotonic reading stripped. The
  // monotonic clock stops while the host is suspended and etcd's lease
  // clock does not, so a lease judged by it would look alive past its
  // death on etcd, and a reused one could reclaim a record early: a tp/
  // entry gone before its token, which a `port49 revoke --mine` then
  // misses (pre-flight M22).
  func wall() time.Time { return time.Now().Round(0) }

  // For returns a lease that lives at least until exp plus grace, measured
  // from now on now's clock. An expiry already past gets the shortest such
  // lease: the record is never read as live, and is reclaimed soon (7c M-2).
  // A cached lease is reused only within one bucket of its grant, judged by
  // the wall clock: past that it is granted afresh, so a suspend costs a
  // grant, never a short lease.
  func (l *leases) For(ctx context.Context, exp time.Time) (clientv3.LeaseID, error) {
  	now := l.now()
  	end := exp.Add(l.grace).Truncate(leaseBucket).Add(leaseBucket)
  	need := end.Sub(now)
  	if need < l.grace {
  		need = l.grace
  	}
  	w := wall()
  	l.mu.Lock()
  	if h, ok := l.held[end.Unix()]; ok && !h.until.Before(w.Add(need)) && w.Sub(h.granted) < leaseBucket {
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
  	w = wall()
  	l.held[end.Unix()] = heldLease{id: resp.ID, granted: w, until: w.Add(time.Duration(resp.TTL) * time.Second)}
  	for b, h := range l.held {
  		if h.until.Before(w) || w.Sub(h.granted) >= leaseBucket {
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
  	"fmt"
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

  // purgePage bounds one read of PurgeTokens: a page of sealed tokens is a
  // few hundred kilobytes, well inside etcd's 1.5 MiB request and gRPC's
  // 2 MiB message (pre-flight I14).
  const purgePage = 256

  // PurgeTokens deletes the token family a page at a time: it reads a page
  // of tokens, counts its live ones, and deletes exactly that page's key
  // range, until none is left. It runs at a start, before any listener
  // binds and with the keyspace held (Task 12), so nothing mints between
  // the pages; a token put mid-purge would be purged by a later page or
  // left, never half-deleted. A large t/ costs pages, never a request etcd
  // refuses.
  func (s *Store) PurgeTokens(ctx context.Context) (int, error) {
  	prefix := s.k.family(famToken)
  	end := clientv3.GetPrefixRangeEnd(prefix)
  	n := 0
  	for {
  		resp, err := s.tok.Get(ctx, prefix, clientv3.WithRange(end), clientv3.WithLimit(purgePage))
  		if err != nil {
  			return n, unavailable(err)
  		}
  		if len(resp.Kvs) == 0 {
  			return n, nil
  		}
  		n += len(liveTokens(resp.Kvs, s.now()))
  		last := string(resp.Kvs[len(resp.Kvs)-1].Key)
  		if _, err := s.tok.Delete(ctx, string(resp.Kvs[0].Key), clientv3.WithRange(last+"\x00")); err != nil {
  			return n, unavailable(err)
  		}
  	}
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
  // names, and those index entries, and counts the receipts that were live.
  // It reads the index a page at a time and deletes exactly the entries it
  // read, never the prefix: a receipt written after the read keeps its
  // entry, so a later revocation still finds it (pre-flight M17). A receipt
  // written after the read is not deleted, as one written after the memory
  // store's lock is not: revocation's ordering reaches it (7a).
  func (s *Store) DeleteReceiptsByPrincipal(ctx context.Context, principal string) (int, error) {
  	prefix := s.k.receiptsBy(principal)
  	end := clientv3.GetPrefixRangeEnd(prefix)
  	from, n := prefix, 0
  	for {
  		resp, err := s.tok.Get(ctx, from, clientv3.WithRange(end), clientv3.WithLimit(500), clientv3.WithKeysOnly())
  		if err != nil {
  			return n, unavailable(err)
  		}
  		var gets, dels []clientv3.Op
  		for _, kv := range resp.Kvs {
  			rk := s.k.root + famReceipt + string(kv.Key[len(prefix):])
  			gets = append(gets, clientv3.OpGet(rk))
  			dels = append(dels, clientv3.OpDelete(rk), clientv3.OpDelete(string(kv.Key)))
  		}
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
  			return n, err
  		}
  		if err := chunked(ctx, s.tok, dels, nil); err != nil {
  			return n, err
  		}
  		if !resp.More || len(resp.Kvs) == 0 {
  			return n, nil
  		}
  		from = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
  	}
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
  		// An entry that does not decode is an error, never skipped: a
  		// revocation that skipped it would miss that key's tokens, which
  		// is revocation failing open (pre-flight M18).
  		var r expiryRec
  		nas, user, ok := lastTwo(string(kv.Key))
  		if !ok {
  			return nil, fmt.Errorf("etcd: token index entry %q does not parse", kv.Key)
  		}
  		if err := json.Unmarshal(kv.Value, &r); err != nil {
  			return nil, fmt.Errorf("etcd: token index entry %q does not decode: %w", kv.Key, err)
  		}
  		if !r.ExpiresAt.After(now) {
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
  	"fmt"
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
  // escaped, read a page at a time (pre-flight I14).
  func (s *Store) ListRevocations(ctx context.Context) ([]store.Revocation, error) {
  	prefix := s.k.family(famMark)
  	end := clientv3.GetPrefixRangeEnd(prefix)
  	from := prefix
  	var out []store.Revocation
  	for {
  		resp, err := s.tok.Get(ctx, from, clientv3.WithRange(end), clientv3.WithLimit(500))
  		if err != nil {
  			return nil, unavailable(err)
  		}
  		for _, kv := range resp.Kvs {
  			var r markRec
  			if err := json.Unmarshal(kv.Value, &r); err != nil {
  				return nil, fmt.Errorf("etcd: mark %q does not decode: %w", kv.Key, err)
  			}
  			out = append(out, r.revocation())
  		}
  		if !resp.More || len(resp.Kvs) == 0 {
  			break
  		}
  		from = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
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

  A mark that does not decode fails the listing, naming its key (pre-flight M18). Skipped, it
  would be dropped from `broker.revocations_file` by the next save and from a start's marks: a
  revocation lost in silence. The error is loud and the operator repairs or deletes the key; the
  mark itself still fails closed at `GetRevocation`.

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
  // SwapContext, SwapLogin, RewriteContext, TouchContext, SetPrivilege, AnnotateContext,
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

  Run `go mod tidy` now that the package imports what Step 1 fetched, then check that the
  `require` block still names the etcd modules and zap.

  Run: `go test ./internal/store/etcd/... -count=1`
  Expected: PASS: `TestTokensOnEtcd/<13 properties>`, `TestAPutOnALostLeaseTakesAFreshOne`,
  `TestALeaseOutlivesItsRecord`, `TestUnavailableClassifies`, `TestScannedKeysEndWithASlash`.
  `PurgeTakesEveryToken` writes a context, so it first runs in Task 6 (pre-flight M23). Note the
  package's wall time in the report. A token property over the shared member should take seconds,
  not minutes.

  Mutation checks (do them, report them, revert them):
  1. In `RedeemAndReceipt`, drop the `unchanged(tk, mod)` compare. `RedeemIsAtomic` and
     `DeleteTokenRacesRedeem` must fail.
  2. In `leases.For`, use `need := exp.Sub(now)`, with no grace. `TestALeaseOutlivesItsRecord`
     must fail.
  3. In `keys.lookups`, drop the trailing `"/"`. `TestScannedKeysEndWithASlash` must fail
     (pre-flight M24).

- [ ] **Step 12: Commit.**

  ```bash
  gofmt -w internal/store/etcd
  make build && make test && make vet
  git add go.mod go.sum internal/store/etcd/etcdtest/etcdtest.go internal/store/etcd/etcd.go \
    internal/store/etcd/keys.go internal/store/etcd/records.go internal/store/etcd/leases.go \
    internal/store/etcd/commit.go internal/store/etcd/tokens.go internal/store/etcd/marks.go \
    internal/store/etcd/notbuilt.go internal/store/etcd/etcd_test.go
  git commit -m "feat(store/etcd): the etcd backend's foundation, tokens and marks

  internal/store/etcd: one key per record under the keyspace's v1/, JSON
  with snake_case keys, every compare-and-set a transaction on the key's
  mod_revision, expiry read against port49d's clock with leases only
  reclaiming. Tokens, receipts, the token index and the marks pass their
  storetest properties against a real etcd member embedded in the test
  binary (etcdtest; no docker, no cgo); PurgeTokens pages, and its
  property runs from Task 6. go 1.26 (OD-1).

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
- Consumes: Task 5's `commit`, `cas`, `getJSON`, `unchanged`, `put`, `del`, `leases.For`, `keys`;
  Task 4b's `store.Apply*`, `store.CheckContextPolicy` and `Store.RewriteContext`.
- Produces:
  - `type ctxRec`, `func ctxRecOf(store.Context) ctxRec`,
    `func (ctxRec) context(mod int64) store.Context`
  - `type idxRec struct { Principals, Sids, Certs []idxEntry }`, `type idxEntry struct { Key string; ExpiresAt time.Time }`,
    with `add(fam, key string, exp time.Time)`, `drop(fam, key string)`, `restamp(exp time.Time)`,
    `lists(fam, key string, now time.Time) bool`, `maxExp() time.Time`, `empty() bool`
  - `type ctxSnap`, `func (s *Store) readCtx(ctx, k, marks ...[2]string) (ctxSnap, error)`,
    `func (s *Store) commitCtx(ctx, k, snap, rec *ctxRec, idx *idxRec, added []string) (bool, error)`
  - `func (x *idxRec) prune(now time.Time)`: every write of an index record drops its expired
    entries (pre-flight M20)
  - The `store.Store` methods: GetContext, PutContext, SwapContext, SwapLogin, RewriteContext,
    TouchContext, SetPrivilege, AnnotateContext, RefreshContext, SetRevokedAt, SetContextPolicy,
    DeleteContext, DeleteContextIf, PutBlob, GetBlob, BumpBlob, IndexContext, UnindexContext,
    UnindexRef, ReindexSid.

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
  		"RewriteBindsToTheRevision":      func(t *testing.T) { storetest.RewriteBindsToTheRevision(t, backend) },
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

  // prune drops every entry expired at now. Every write of the record calls
  // it, so the record holds the keys still live and no more: a joined
  // context that sees a login per window stays as large as its live logins,
  // not its history (pre-flight M20). An expired entry answers no lookup
  // already (lists), so dropping it changes no answer. It is not a cap: a
  // live entry is never dropped to bound the record, since that would cost
  // a revocation its reach (the memory store's indexKeys says why).
  func (x *idxRec) prune(now time.Time) {
  	for _, l := range []*[]idxEntry{&x.Principals, &x.Sids, &x.Certs} {
  		out := (*l)[:0]
  		for _, e := range *l {
  			if e.ExpiresAt.After(now) {
  				out = append(out, e)
  			}
  		}
  		*l = out
  	}
  }
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
  			x.prune(s.now())
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
  		x.prune(now)
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

  // RewriteContext writes c's fields over the record at k only while its
  // mod_revision is rev (store.Store; Task 4b): the sealing layer's narrow
  // setter. No live record is ErrNotFound; one written since is ErrConflict,
  // for the caller to read again. The expiry and LastTouchedAt stay the
  // record's own unless ttl is set, which extends both and the ref's index
  // entries as TouchContext does; PolicyRev moves to this write's revision
  // only when policyMoved.
  func (s *Store) RewriteContext(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration,
  	policyMoved bool) error {
  	snap, err := s.readCtx(ctx, k)
  	if err != nil {
  		return err
  	}
  	if !snap.found {
  		return store.ErrNotFound
  	}
  	if uint64(snap.mod) != rev {
  		return store.ErrConflict
  	}
  	r := ctxRecOf(c)
  	r.ExpiresAt, r.LastTouchedAt = snap.rec.ExpiresAt, snap.rec.LastTouchedAt
  	r.PolicyRev, r.PolicyMoved = snap.rec.policyRev(snap.mod), policyMoved
  	var idx *idxRec
  	if ttl > 0 {
  		now := s.now()
  		r.ExpiresAt, r.LastTouchedAt = now.Add(ttl), now
  		if snap.idxMod != 0 {
  			x := snap.idx
  			x.prune(now)
  			x.restamp(r.ExpiresAt)
  			idx = &x
  		}
  	}
  	ok, err := s.commitCtx(ctx, k, snap, &r, idx, nil)
  	if err != nil {
  		return err
  	}
  	if !ok {
  		return store.ErrConflict // the context or its index record moved since the read
  	}
  	return nil
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
  // read, else it reads again. A read that fails returns at once, with the
  // read's error: only a lost race loops, and that is bounded by the
  // caller's deadline (pre-flight M23). Before f runs, a PolicyMoved left by
  // the last write is resolved into policy_rev, so r.PolicyRev is the
  // context's PolicyRev and f marks its own policy write by setting
  // PolicyMoved.
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
  			x.prune(s.now())
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

  // applyTo runs one of the store's rules (store.Apply*, Task 4b) on the
  // record as a store.Context and keeps what the rule changed: the rules are
  // one definition for every backend and the sealing layer. The record's
  // bookkeeping (its expiry and its policy revision) is mutate's, and stays.
  func applyTo(r *ctxRec, rev int64, f func(c *store.Context) (bool, error)) (bool, error) {
  	c := r.context(rev)
  	moved, err := f(&c)
  	if err != nil {
  		return false, err
  	}
  	next := ctxRecOf(c)
  	next.ExpiresAt, next.PolicyRev, next.PolicyMoved = r.ExpiresAt, r.PolicyRev, r.PolicyMoved
  	*r = next
  	return moved, nil
  }

  // SetPrivilege is store.ApplyPrivilege's rule; a level that moved is a
  // policy write.
  func (s *Store) SetPrivilege(ctx context.Context, k store.ContextKey, level uint8) error {
  	return s.mutate(ctx, k, func(r *ctxRec, rev int64, _ time.Time) (bool, error) {
  		moved, _ := applyTo(r, rev, func(c *store.Context) (bool, error) { return store.ApplyPrivilege(c, level), nil })
  		r.PolicyMoved = moved
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

  // RefreshContext is store.ApplyRefresh's rule, ExpectRev compared with the
  // revision this write will compare, and the record extended.
  func (s *Store) RefreshContext(ctx context.Context, k store.ContextKey, rf store.ContextRefresh, ttl time.Duration) error {
  	return s.mutate(ctx, k, func(r *ctxRec, rev int64, now time.Time) (bool, error) {
  		if rf.ExpectRev != 0 && uint64(rev) != rf.ExpectRev {
  			return false, store.ErrConflict
  		}
  		moved, err := applyTo(r, rev, func(c *store.Context) (bool, error) { return store.ApplyRefresh(c, rf) })
  		if err != nil {
  			return false, err
  		}
  		r.PolicyMoved = moved
  		r.ExpiresAt, r.LastTouchedAt = now.Add(ttl), now
  		return true, nil
  	})
  }

  // SetRevokedAt is store.ApplyRevokedAt's rule, a policy write; it moves
  // neither the expiry nor LastTouchedAt.
  func (s *Store) SetRevokedAt(ctx context.Context, k store.ContextKey, at time.Time) error {
  	return s.mutate(ctx, k, func(r *ctxRec, rev int64, _ time.Time) (bool, error) {
  		applyTo(r, rev, func(c *store.Context) (bool, error) { store.ApplyRevokedAt(c, at); return true, nil })
  		r.PolicyMoved = true
  		return false, nil
  	})
  }

  // SetContextPolicy is store.ApplyContextPolicy's rule, compared on the
  // policy revision of the record this write compares.
  func (s *Store) SetContextPolicy(ctx context.Context, k store.ContextKey, policyRev uint64, p store.ContextPolicy) error {
  	if err := store.CheckContextPolicy(p); err != nil {
  		return err
  	}
  	return s.mutate(ctx, k, func(r *ctxRec, rev int64, _ time.Time) (bool, error) {
  		if uint64(r.PolicyRev) != policyRev {
  			return false, store.ErrConflict
  		}
  		applyTo(r, rev, func(c *store.Context) (bool, error) { store.ApplyContextPolicy(c, p); return true, nil })
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
  		x.prune(s.now())
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

- [ ] **Step 4b: A rewrite after a read is one transaction** (re-check MA3). The sealing
  layer's setter reads the record (`GetContext`), then rewrites it on that revision
  (`RewriteContext`), which read it again: three RPCs on the refresh path and at a session's
  first `SetPrivilege`. The second read only recovers the plaintext bookkeeping the first one
  had. So `GetContext` keeps it, and `RewriteContext` with no ttl on that revision commits
  without reading. In `contexts.go` add:

  ```go
  // seenCache is the plaintext bookkeeping of the last version GetContext
  // read at each context key: its mod_revision and its record. RewriteContext
  // takes it instead of reading again when it is asked to rewrite exactly
  // that version with no ttl, so the sealing layer's narrow setter is two
  // RPCs, its read and its transaction (re-check MA3). The transaction still
  // compares the key's mod_revision, so a stale entry is a conflict, never a
  // lost write. It holds at most seenMax entries and forgets them all past
  // that: the cost of forgetting is one read.
  type seenCache struct {
  	mu sync.Mutex
  	m  map[string]seenRec
  }

  type seenRec struct {
  	mod int64
  	rec ctxRec
  }

  const seenMax = 4096

  func (c *seenCache) put(key string, mod int64, r ctxRec) {
  	c.mu.Lock()
  	defer c.mu.Unlock()
  	if c.m == nil || len(c.m) >= seenMax {
  		c.m = map[string]seenRec{}
  	}
  	c.m[key] = seenRec{mod: mod, rec: r}
  }

  // take is the entry for key at mod, removed either way.
  func (c *seenCache) take(key string, mod int64) (ctxRec, bool) {
  	c.mu.Lock()
  	defer c.mu.Unlock()
  	e, ok := c.m[key]
  	delete(c.m, key)
  	return e.rec, ok && e.mod == mod
  }
  ```

  - Add `seen seenCache` to `Store` (its zero value is ready), and `"sync"` to the imports.
  - In `GetContext`, after the expiry check, `s.seen.put(s.k.context(k), mod, r)`.
  - At the top of `RewriteContext`, before `readCtx`:

    ```go
    	if r0, ok := s.seen.take(s.k.context(k), int64(rev)); ok && ttl == 0 {
    		if !r0.ExpiresAt.After(s.now()) {
    			return store.ErrNotFound
    		}
    		r := ctxRecOf(c)
    		r.ExpiresAt, r.LastTouchedAt = r0.ExpiresAt, r0.LastTouchedAt
    		r.PolicyRev, r.PolicyMoved = r0.policyRev(int64(rev)), policyMoved
    		body, err := json.Marshal(r)
    		if err != nil {
    			return err
    		}
    		ck := s.k.context(k)
    		ok, err := commit(ctx, s.ctx, s.ctxLeases, []clientv3.Cmp{unchanged(ck, int64(rev))},
    			[]put{{key: ck, val: body, exp: r.ExpiresAt}})
    		switch {
    		case err != nil:
    			return err
    		case !ok:
    			return store.ErrConflict // moved, or gone, since the read: the caller reads again
    		}
    		return nil
    	}
    ```

    A rewrite with a ttl still reads, since it restamps the index record and compares it. A
    rewrite with no ttl touches no index record, so comparing the context key alone is the
    whole precondition.
  - Append to `etcd_test.go`:

    ```go
    // A rewrite on the revision a read saw commits without reading again,
    // and is still refused once the record has moved since that read
    // (re-check MA3).
    func TestARewriteAfterAReadComparesTheRevision(t *testing.T) {
    	ctx := context.Background()
    	s := onShared(t, func() time.Time { return t0 })
    	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
    	if err := s.PutContext(ctx, k, store.Context{CtxID: "c", Principal: "p", Username: "alice", PrivLvl: 1},
    		time.Hour); err != nil {
    		t.Fatal(err)
    	}
    	read, err := s.GetContext(ctx, k)
    	if err != nil {
    		t.Fatal(err)
    	}
    	if err := s.TouchContext(ctx, k, time.Hour); err != nil { // the record moves after the read
    		t.Fatal(err)
    	}
    	stale := read
    	stale.PrivLvl = 15
    	if err := s.RewriteContext(ctx, k, read.Rev, stale, 0, false); !errors.Is(err, store.ErrConflict) {
    		t.Fatalf("a rewrite of a version read and since moved: %v", err)
    	}
    	read, _ = s.GetContext(ctx, k)
    	next := read
    	next.PrivLvl = 7
    	if err := s.RewriteContext(ctx, k, read.Rev, next, 0, false); err != nil {
    		t.Fatal(err)
    	}
    	if got, _ := s.GetContext(ctx, k); got.PrivLvl != 7 || !got.LastTouchedAt.Equal(read.LastTouchedAt) {
    		t.Fatalf("a rewrite after a read: %+v", got)
    	}
    }
    ```

- [ ] **Step 5: Run.**

  Run: `go test ./internal/store/etcd/ -count=1`
  Expected: PASS: `TestTokensOnEtcd`, `TestContextsOnEtcd/<24>`,
  `TestPolicyRevIsTheLastPolicyWritesRevision` and `TestARewriteAfterAReadComparesTheRevision`.

  Mutation checks (do them, report them, revert them):
  1. In `mutate`, drop the `PolicyMoved` resolution. `PolicyRevision` must fail, because a touch
     would then move `PolicyRev`.
  4. In `RewriteContext`, drop the `snap.mod != rev` refusal. `RewriteBindsToTheRevision` must
     fail.
  5. In `RewriteContext`'s cached path, commit with no compare.
     `TestARewriteAfterAReadComparesTheRevision` must fail (re-check MA3).
  2. In `SwapLogin`, skip the mark comparison. This task cannot see that (no lookup readers yet).
     Note it for Task 7, whose `JoinHonoursAStandingMark` catches it.
  3. In `SetRevokedAt`, replace the `applyTo` call with `r.RevokedAt = at`, unconditionally.
     `RevocationIsMonotonic` must fail.

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
  comparing the marks the login read; RewriteContext is the sealing
  layer's narrow setter, one transaction after the read it follows
  (re-check MA3). Every write of an index record drops its expired
  entries. Every context property passes on a real etcd member.

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

  // A record a lookup or a walk cannot decode is an error, never a ref left
  // out: a revocation that skipped it would miss a live context (pre-flight
  // M18).
  func TestAnUndecodableIndexRecordIsAnError(t *testing.T) {
  	ctx := context.Background()
  	s := onShared(t, func() time.Time { return t0 })
  	ref := store.ContextRef{NAS: "leaf-01", Username: "alice"}
  	if err := s.IndexContext(ctx, "user:a", "", "", ref, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	if _, err := s.ctx.Put(ctx, s.k.indexed(ref), "not json"); err != nil {
  		t.Fatal(err)
  	}
  	if refs, err := s.ContextsByPrincipal(ctx, "user:a"); err == nil {
  		t.Fatalf("a lookup over an undecodable record answered %v", refs)
  	}
  	if ps, err := s.ActivePrincipals(ctx); err == nil {
  		t.Fatalf("a walk over an undecodable record answered %v", ps)
  	}
  }
  ```

  Run: `go test ./internal/store/etcd/ -run 'TestIndexesOnEtcd|TestTheSweep|TestAnUndecodable' -count=1`
  Expected: FAIL: the readers return `errNotBuilt`, and `Sweep` is undefined.

- [ ] **Step 2: The readers and the sweep.** Create `internal/store/etcd/indexes.go`:

  ```go
  package etcd

  import (
  	"context"
  	"encoding/json"
  	"fmt"
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
  		// An entry that does not parse, or a record that does not decode,
  		// is an error, never skipped: a revocation that skipped it would
  		// miss a context, which is revocation failing open (pre-flight M18).
  		nas, user, ok := lastTwo(string(kv.Key))
  		if !ok {
  			return nil, fmt.Errorf("etcd: lookup entry %q does not parse", kv.Key)
  		}
  		r := store.ContextRef{NAS: nas, Username: user}
  		refs = append(refs, r)
  		gets = append(gets, clientv3.OpGet(s.k.indexed(r)))
  	}
  	now := s.now()
  	var out []store.ContextRef
  	var bad error
  	i := 0
  	if err := chunked(ctx, s.ctx, gets, func(t *clientv3.TxnResponse) {
  		for _, op := range t.Responses {
  			r := refs[i]
  			i++
  			for _, kv := range op.GetResponseRange().Kvs {
  				var x idxRec
  				if err := json.Unmarshal(kv.Value, &x); err != nil {
  					if bad == nil {
  						bad = fmt.Errorf("etcd: index record %q does not decode: %w", kv.Key, err)
  					}
  					continue
  				}
  				if x.lists(fam, key, now) {
  					out = append(out, r)
  				}
  			}
  		}
  	}); err != nil {
  		return nil, err
  	}
  	if bad != nil {
  		return nil, bad
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

  // eachIndexed calls f on every index record, a page at a time. A record
  // that does not decode fails the walk, naming its key (pre-flight M18):
  // ActivePrincipals skipping it would leave its principal unrefreshed.
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
  			if err := json.Unmarshal(kv.Value, &x); err != nil {
  				return fmt.Errorf("etcd: index record %q does not decode: %w", kv.Key, err)
  			}
  			f(string(kv.Key), kv.ModRevision, x)
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
  // The index records a page names are read together, in transactions of
  // gets (chunked), not one linearizable read per entry (pre-flight M25).
  func (s *Store) sweepLookups(ctx context.Context, fam string) (int, error) {
  	prefix := s.k.family(fam)
  	end := clientv3.GetPrefixRangeEnd(prefix)
  	from := prefix
  	removed := 0
  	type entry struct {
  		key, lookupKey, xk string
  		mod                int64
  	}
  	type rec struct {
  		x     idxRec
  		mod   int64
  		found bool
  	}
  	for {
  		resp, err := s.ctx.Get(ctx, from, clientv3.WithRange(end), clientv3.WithLimit(500), clientv3.WithKeysOnly())
  		if err != nil {
  			return removed, unavailable(err)
  		}
  		var entries []entry
  		var xks []string
  		seen := map[string]bool{}
  		for _, kv := range resp.Kvs {
  			lookupKey, ref, ok := s.parseLookup(fam, string(kv.Key))
  			if !ok {
  				continue // not a lookup entry this sweep wrote; left alone
  			}
  			e := entry{key: string(kv.Key), lookupKey: lookupKey, xk: s.k.indexed(ref), mod: kv.ModRevision}
  			entries = append(entries, e)
  			if !seen[e.xk] {
  				seen[e.xk] = true
  				xks = append(xks, e.xk)
  			}
  		}
  		gets := make([]clientv3.Op, len(xks))
  		for i, xk := range xks {
  			gets[i] = clientv3.OpGet(xk)
  		}
  		recs := map[string]rec{}
  		var bad error
  		i := 0
  		if err := chunked(ctx, s.ctx, gets, func(t *clientv3.TxnResponse) {
  			for _, op := range t.Responses {
  				xk := xks[i]
  				i++
  				var r rec
  				for _, kv := range op.GetResponseRange().Kvs {
  					if err := json.Unmarshal(kv.Value, &r.x); err != nil && bad == nil {
  						bad = fmt.Errorf("etcd: index record %q does not decode: %w", kv.Key, err)
  					}
  					r.mod, r.found = kv.ModRevision, true
  				}
  				recs[xk] = r
  			}
  		}); err != nil {
  			return removed, err
  		}
  		if bad != nil {
  			return removed, bad // never delete against a record it could not read
  		}
  		for _, e := range entries {
  			r := recs[e.xk]
  			if r.found && listed(r.x, fam, e.lookupKey) {
  				continue
  			}
  			done, err := commit(ctx, s.ctx, s.ctxLeases,
  				[]clientv3.Cmp{unchanged(e.key, e.mod), unchanged(e.xk, r.mod)}, nil, del{key: e.key})
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
  Expected: PASS: `TestIndexesOnEtcd/<11>`, `TestTheSweepRemovesOnlyWhatNothingLists`,
  `TestAnUndecodableIndexRecordIsAnError`, and
  `IndexKeysAreExact` on memory and through the sealing layer (from `Run`).

  Mutation checks (do them, report them, revert them):
  1. In `SwapLogin` (Task 6), skip the mark comparison. `JoinHonoursAStandingMark` must fail.
  2. In `refsUnder`, drop the `x.lists(fam, key, now)` filter, keeping every lookup entry.
     `SwapLoginIsOneStep` and `UnindexRefClearsEveryKey` must fail.
  3. In `keys.lookups`, drop the trailing `"/"`. `TestScannedKeysEndWithASlash` (Task 5) must
     fail. `IndexKeysAreExact` may fail too, but only through `lastTwo` misparsing a key, since
     the `x/` filter masks a prefix collision; the direct test is the one that pins the schema
     (pre-flight M24).
  4. In `refsUnder`, skip a record that does not decode instead of returning its error.
     `TestAnUndecodableIndexRecordIsAnError` must fail (pre-flight M18).

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

### Task 7b: A context its index lost is found, re-indexed and judged

**Files:**
- Modify: `internal/store/etcd/indexes.go` (`Unindexed`)
- Test: `internal/store/etcd/etcd_test.go`
- Modify: `internal/session/session.go` (`Manager.Reindex`)
- Create: `internal/broker/reindex.go`, `internal/broker/reindex_test.go` (`ReindexContexts`)
- Modify: `internal/daemon/metrics/metrics.go`, `metrics_test.go` (`ContextsReindexed`)

**Interfaces:**
- Consumes: Task 7's `idxRec`, `lastTwo`, `chunked`, `keys.family`, `keys.indexed`;
  `Broker.refreshContext`; `session.Manager`.
- Produces:
  - `func (s *etcd.Store) Unindexed(ctx context.Context) ([]store.ContextRef, error)`
  - `func (m *session.Manager) Reindex(ctx context.Context, ref store.ContextRef, c store.Context) error`
  - `func (b *Broker) ReindexContexts(ctx context.Context, refs []store.ContextRef) (int, error)`
  - `Metrics.ContextsReindexed` (`port49_contexts_reindexed_total`)

**Why:** Ruling 6, re-check IA2.
- **The gap.** The refresh walks the index (`refreshContexts`, refresh.go:337, through
  `ActivePrincipals`), and so do `revoke --mine` and a revocation by sid. On etcd the index is
  the `x/` family, and the daemon's role writes it.
- **The scenario.** With a context's `x/` record deleted:
  - a grant removed, or a narrowing, never reaches that context;
  - `revoke --mine` misses it;
  - Touch keeps it alive, so under `max_session_age: never` that lasts indefinitely.

  Only a principal or certificate mark (the daemon's `Marks`) still catches it.
- **The fix.** A login writes a context and its index record in one step, and every extension
  carries both, so a live context whose `x/` record is gone, or lists no live principal, was
  hidden by a store write. `Unindexed` finds each such context. `ReindexContexts` then
  re-indexes it, judges it, or revokes it if it will not open.
- **Who calls it.** port49d runs it at start and after every sweep (Task 12), so 7d-1 builds
  and tests it and calls it from nothing yet. The memory store has no outside writer, and needs
  no finder.

- [ ] **Step 1: The failing tests.** Append to `internal/store/etcd/etcd_test.go`:

  ```go
  // A live context whose index record is gone, or lists no live principal,
  // is named; one indexed is not (re-check IA2).
  func TestUnindexedFindsAContextItsIndexLost(t *testing.T) {
  	ctx := context.Background()
  	now := t0
  	s := onShared(t, func() time.Time { return now })
  	kept := store.ContextRef{NAS: "leaf-01", Username: "kept"}
  	lost := store.ContextRef{NAS: "leaf-01", Username: "lost"}
  	stale := store.ContextRef{NAS: "rack/1%2Fleaf", Username: "stale"}
  	for _, r := range []store.ContextRef{kept, lost, stale} {
  		if err := s.PutContext(ctx, store.ContextKey{NAS: r.NAS, Username: r.Username},
  			store.Context{CtxID: "c", Principal: "user:a", Username: r.Username}, 2*time.Hour); err != nil {
  			t.Fatal(err)
  		}
  	}
  	if err := s.IndexContext(ctx, "user:a", "", "", kept, 2*time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	if err := s.IndexContext(ctx, "user:a", "", "", lost, 2*time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	if err := s.IndexContext(ctx, "user:a", "sid-1", "", stale, time.Minute); err != nil {
  		t.Fatal(err)
  	}
  	if _, err := s.ctx.Delete(ctx, s.k.indexed(lost)); err != nil { // a store write hides it
  		t.Fatal(err)
  	}
  	now = now.Add(2 * time.Minute) // stale's entries have expired; its context has not
  	got, err := s.Unindexed(ctx)
  	if err != nil {
  		t.Fatal(err)
  	}
  	if len(got) != 2 || !slices.Contains(got, lost) || !slices.Contains(got, stale) {
  		t.Fatalf("Unindexed = %v, want %v and %v", got, lost, stale)
  	}
  }
  ```

  Add `"slices"` to the file's imports if it is not there.

  Create `internal/broker/reindex_test.go`:

  ```go
  package broker

  import (
  	"context"
  	"errors"
  	"testing"

  	"github.com/prometheus/client_golang/prometheus/testutil"

  	"github.com/rhwendt/port49/internal/store"
  )

  // unreadableAt is a store whose context at k will not open, as one sealed
  // under a key this window lacks reads through the sealing layer.
  type unreadableAt struct {
  	store.Store
  	k store.ContextKey
  }

  func (u unreadableAt) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
  	if k == u.k {
  		return store.Context{}, &store.UnreadableContextError{Err: errors.New("test: will not open")}
  	}
  	return u.Store.GetContext(ctx, k)
  }

  // A context whose index was lost is re-indexed, so a revocation by
  // principal reaches it again, and judged against the policy in force at
  // once (plan 7d; re-check IA2).
  func TestReindexContextsRestoresRevocationsReach(t *testing.T) {
  	f := newFixtureWithPolicy(t, 8, sharedPolicy)
  	ctx := context.Background()
  	f.liveContext(t, "leaf1", "alice", alicePrincipal, "")
  	ref := store.ContextRef{NAS: "leaf1", Username: "alice"}
  	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
  	before, err := f.st.GetContext(ctx, k)
  	if err != nil {
  		t.Fatal(err)
  	}
  	if err := f.st.SetContextPolicy(ctx, k, before.PolicyRev, store.ContextPolicy{BlobHash: "sha256:from-before",
  		MaxPrivilege: before.MaxPrivilege, Enable: before.Enable}); err != nil {
  		t.Fatal(err)
  	}
  	if err := f.st.UnindexRef(ctx, ref); err != nil { // what a deleted x/ record leaves
  		t.Fatal(err)
  	}
  	if refs, _ := f.st.ContextsByPrincipal(ctx, alicePrincipal); len(refs) != 0 {
  		t.Fatalf("the index still names it: %v", refs)
  	}
  	n, err := f.b.ReindexContexts(ctx, []store.ContextRef{ref})
  	if err != nil || n != 1 {
  		t.Fatalf("ReindexContexts = %d, %v", n, err)
  	}
  	if refs, _ := f.st.ContextsByPrincipal(ctx, alicePrincipal); len(refs) != 1 || refs[0] != ref {
  		t.Fatalf("not re-indexed: %v", refs)
  	}
  	if got, _ := f.st.GetContext(ctx, k); got.BlobHash == "sha256:from-before" {
  		t.Fatal("re-indexed but not judged against the policy in force")
  	}
  	if v := testutil.ToFloat64(f.b.Metrics.ContextsReindexed); v != 1 {
  		t.Fatalf("port49_contexts_reindexed_total = %v", v)
  	}
  	if refs, err := f.b.Sessions.RevokeByPrincipal(ctx, alicePrincipal); err != nil || len(refs) != 1 {
  		t.Fatalf("a revocation by principal after the re-index: %v %v", refs, err)
  	}
  }

  // One that will not open cannot be indexed, and no refresh would visit
  // it: it is revoked, which needs no key.
  func TestReindexContextsRevokesOneThatWillNotOpen(t *testing.T) {
  	f := newFixtureWithPolicy(t, 8, sharedPolicy)
  	ctx := context.Background()
  	f.liveContext(t, "leaf1", "alice", alicePrincipal, "")
  	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
  	f.b.Store = unreadableAt{Store: f.st, k: k}
  	if n, err := f.b.ReindexContexts(ctx, []store.ContextRef{{NAS: "leaf1", Username: "alice"}}); err != nil || n != 1 {
  		t.Fatalf("ReindexContexts = %d, %v", n, err)
  	}
  	if got, _ := f.st.GetContext(ctx, k); got.RevokedAt.IsZero() {
  		t.Fatal("an unindexed context that will not open was left unrevoked")
  	}
  }
  ```

  The fixture names are 7c's (`internal/broker/fixture_test.go`), as in Task 12. If the fixture
  leaves `f.b.Sessions` nil, set it as 7a's revoke tests do, over `f.st`.

  Run: `go test ./internal/store/etcd/ ./internal/broker/ -run 'Unindexed|ReindexContexts' -count=1`
  Expected: FAIL to build (`Unindexed`, `ReindexContexts`, `ContextsReindexed` undefined).

- [ ] **Step 2: The finder.** Append to `internal/store/etcd/indexes.go`:

  ```go
  // Unindexed is the ref of every context whose index record is gone, or
  // lists no live principal (plan 7d; Ruling 6; re-check IA2). A login
  // writes a context and its index record in one step and every extension
  // carries both, so each is a record hidden by a store write: from the
  // refresh, which walks the index, and from a revocation by sid or by
  // --mine. It pages the context family keys-only and reads each page's
  // index records in batched transactions, as the sweep does. A context
  // past its expiry and not yet reclaimed may be named; ReindexContexts
  // reads it and finds nothing. An index record that does not decode is an
  // error naming its key (pre-flight M18).
  func (s *Store) Unindexed(ctx context.Context) ([]store.ContextRef, error) {
  	prefix := s.k.family(famContext)
  	end := clientv3.GetPrefixRangeEnd(prefix)
  	from := prefix
  	now := s.now()
  	var out []store.ContextRef
  	for {
  		resp, err := s.ctx.Get(ctx, from, clientv3.WithRange(end), clientv3.WithLimit(500), clientv3.WithKeysOnly())
  		if err != nil {
  			return out, unavailable(err)
  		}
  		refs := make([]store.ContextRef, 0, len(resp.Kvs))
  		gets := make([]clientv3.Op, 0, len(resp.Kvs))
  		for _, kv := range resp.Kvs {
  			nas, user, ok := lastTwo(string(kv.Key))
  			if !ok {
  				return out, fmt.Errorf("etcd: context key %q does not parse", kv.Key)
  			}
  			ref := store.ContextRef{NAS: nas, Username: user}
  			refs = append(refs, ref)
  			gets = append(gets, clientv3.OpGet(s.k.indexed(ref)))
  		}
  		i := 0
  		var bad error
  		if err := chunked(ctx, s.ctx, gets, func(t *clientv3.TxnResponse) {
  			for _, op := range t.Responses {
  				ref := refs[i]
  				i++
  				kvs := op.GetResponseRange().Kvs
  				if len(kvs) == 0 {
  					out = append(out, ref)
  					continue
  				}
  				var x idxRec
  				if err := json.Unmarshal(kvs[0].Value, &x); err != nil {
  					if bad == nil {
  						bad = fmt.Errorf("etcd: index record %q does not decode: %w", kvs[0].Key, err)
  					}
  					continue
  				}
  				live := false
  				for _, e := range x.Principals {
  					live = live || e.ExpiresAt.After(now)
  				}
  				if !live {
  					out = append(out, ref)
  				}
  			}
  		}); err != nil {
  			return out, err
  		}
  		if bad != nil {
  			return out, bad
  		}
  		if !resp.More {
  			return out, nil
  		}
  		from = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
  	}
  }
  ```

- [ ] **Step 3: The re-index.**
  - In `internal/session/session.go`, after `RevokeByCert`:

    ```go
    // Reindex indexes ref again under c's principal, sid and certificate,
    // for the index TTL: a context whose index record was deleted in the
    // store (plan 7d; re-check IA2). Revocation and the refresh read the
    // index, so a context left out of it is reached by neither.
    func (m *Manager) Reindex(ctx context.Context, ref store.ContextRef, c store.Context) error {
    	return m.store.IndexContext(ctx, c.Principal, c.Credential.Sid,
    		store.CertKey(c.Credential.Issuer, c.Credential.Serial), ref, m.indexTTL)
    }
    ```
  - Create `internal/broker/reindex.go`:

    ```go
    package broker

    import (
    	"context"
    	"errors"

    	"github.com/rhwendt/port49/internal/store"
    )

    // ReindexContexts is what port49d does with the contexts
    // (*etcd.Store).Unindexed names (plan 7d; Ruling 6; re-check IA2):
    // each one that opens is indexed again under its own principal, sid and
    // certificate, and judged at once against the policy in force, since a
    // refresh that ran while it was hidden never reached it. One that will
    // not open cannot be indexed, and no refresh would visit it, so it is
    // revoked, which needs no key. One gone since the scan is skipped. Each
    // is counted (port49_contexts_reindexed_total), and the total said: any
    // is an index record deleted in the store. It returns how many it found,
    // and its first store error, for the caller to run it again.
    func (b *Broker) ReindexContexts(ctx context.Context, refs []store.ContextRef) (int, error) {
    	if b.Sessions == nil {
    		return 0, errors.New("broker: revocation is not wired (no session manager); the unindexed contexts were not re-indexed")
    	}
    	var rep RefreshReport
    	rep.At = b.Now()
    	cur := b.Policy.Load()
    	n := 0
    	defer func() {
    		if n > 0 {
    			b.logf("broker: %d live context(s) were missing from the index (an index record deleted in the store?); "+
    				"re-indexed and judged against the policy in force, or revoked when they would not open", n)
    		}
    	}()
    	for _, ref := range refs {
    		k := store.ContextKey{NAS: ref.NAS, Username: ref.Username}
    		c, err := b.Store.GetContext(ctx, k)
    		var unreadable *store.UnreadableContextError
    		switch {
    		case errors.Is(err, store.ErrNotFound):
    			continue
    		case errors.As(err, &unreadable):
    			if err := b.Store.SetRevokedAt(ctx, k, rep.At); err != nil && !errors.Is(err, store.ErrNotFound) {
    				return n, err
    			}
    		case err != nil:
    			return n, err
    		default:
    			if err := b.Sessions.Reindex(ctx, ref, c); err != nil {
    				return n, err
    			}
    			if _, err := b.refreshContext(ctx, cur, nil, rep.At, c.Principal, ref, &rep, map[string]bool{},
    				false); err != nil && !errors.Is(err, store.ErrConflict) {
    				return n, err
    			}
    		}
    		n++
    		b.Metrics.ContextsReindexed.Inc()
    	}
    	return n, nil
    }
    ```

    A conflict in the judging leaves that context for the next policy refresh: it is indexed
    now, so the refresh reaches it.
  - In `internal/daemon/metrics/metrics.go`, add:

    ```go
    	// ContextsReindexed counts live contexts found missing from the index
    	// and re-indexed, or revoked when they would not open (plan 7d;
    	// re-check IA2). Any increase is an index record deleted in the store.
    	ContextsReindexed prometheus.Counter
    ```

    named `port49_contexts_reindexed_total`, registered, and named in
    `TestNewRegistersEveryMetric` with one sample (pre-flight M31).

- [ ] **Step 4: Run.**

  Run: `go test ./internal/store/etcd/ ./internal/session/ ./internal/broker/ ./internal/daemon/metrics/ -count=1`
  Expected: PASS: `TestUnindexedFindsAContextItsIndexLost`,
  `TestReindexContextsRestoresRevocationsReach`, `TestReindexContextsRevokesOneThatWillNotOpen`,
  and every existing test.

  Mutation checks (do them, report them, revert them):
  1. In `Unindexed`, count any principal entry as live, expired or not.
     `TestUnindexedFindsAContextItsIndexLost` must fail (`stale`).
  2. In `ReindexContexts`, skip the `refreshContext` call.
     `TestReindexContextsRestoresRevocationsReach` must fail ("not judged").

- [ ] **Step 5: Commit.**

  ```bash
  gofmt -w internal/store/etcd internal/session internal/broker internal/daemon/metrics
  make build && make test && make vet
  git add internal/store/etcd/indexes.go internal/store/etcd/etcd_test.go internal/session/session.go \
    internal/broker/reindex.go internal/broker/reindex_test.go internal/daemon/metrics/metrics.go \
    internal/daemon/metrics/metrics_test.go
  git commit -m "feat(store): find a context its index lost, and re-index and judge it

  A login writes a context and its index record in one step, so a live
  context whose x/ record is gone was hidden by a store write: from the
  refresh, which walks the index, and from a revocation by sid or --mine.
  etcd's Unindexed pages the context family keys-only and names each one;
  the broker's ReindexContexts indexes it again under its own principal,
  sid and certificate, judges it against the policy in force, revokes
  one that will not open, and counts port49_contexts_reindexed_total.
  port49d calls it from 7d-2 (plan 7d; Ruling 6; re-check IA2).

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

  `SetRevokedAt` without quorum returns from `mutate` at its first read's error: the read waits
  out the 1 s deadline, fails `ErrUnavailable`, and `mutate` returns it (pre-flight M23). Report
  the elapsed time; it is about the deadline, never a spin.

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

- [ ] **Step 6: 7d-1 as built** (on `main`, docs only, after 7d-1's pull request merges; pre-flight
  M8). The controller, or the agent it names, writes it before Task 8b is dispatched, so 7d-2's
  tasks are written against the ledger this plan's split relies on.
  - In `docs/superpowers/plans/README.md`, change the status line to say 7d-1 is executed and
    merged, with its pull request and merge commit, and 7d-2 next.
  - After "Plan 7c — As built", add "Plan 7d-1 — As built" in 7c's form: Tasks 1–8 (with 4b and
    7b) task by task, what differs from this plan's text, with commits; and any interface that
    changed.
  - If 7d-1's review changed an interface 7d-2 consumes, amend 7d-2's tasks in this plan in the
    same commit and say so (the split's rule above).

  ```bash
  git add docs/superpowers/plans/README.md docs/superpowers/plans/2026-10-02-07d-shared-store.md
  git commit -m "docs: plan 7d-1 merged (PR #<n>)

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

# Part 7d-2: port49d on etcd (`feature/shared-store-port49d`, off `main` after 7d-1 merges)

### Task 8b: The spec and the design say what 7d-2 builds

The first commit on `feature/shared-store-port49d`, before Task 9 (pre-flight I2).

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`
- Modify: `docs/design/2026-08-21-port49-design.md`

**Interfaces:** none. Tasks 9–16 cite the text this one writes.

No code. As in Task 1, each edit names a one-line fragment to find and the text to put after it
or in its place. **Nothing here asserts what a device does when the store hangs** (pre-flight
I4): that is L35, which this task opens and Task 15 closes. Where a cell would say what a device
does, it says what port49d does and cites L35 as open.

- [ ] **Step 1: Decision 35, 7d-2's part.** In decision 35 (Task 1), before its last line `(§5.1.4,
  §5.6, §14; design document §8, §12)`, add:

  ```markdown
  - **Hard timeouts and a circuit per pool.**
    - **Per call.** Every store call has its own deadline: `store.etcd.call_timeout` (500ms) on
      the token and context pools, and `store.etcd.bulk_timeout` (30s) on the bulk pool, which
      holds the four scans (`ActivePrincipals`, `DeleteReceiptsByPrincipal`, `ListRevocations`,
      `PurgeTokens`). A slow scan therefore trips no hot-path circuit, and the backend pages
      each scan.
    - **Per packet.** Every TACACS+ packet's store work has one too (`store.packet_deadline`,
      2s, 100ms to 2s, at least `call_timeout`). The bound is §15 L13's: the Junos images time
      out a reply at about 3s. So a device hears `store_unavailable` before its own timeout, and
      a redemption's write lands inside the policy refresh's 30s settle pass.
    - **The failure delay.** The packet deadline never shortens the authentication failure
      delay, which sleeps on the server's context. The delay counts from the packet's
      arrival, so the store's time is inside it: a FAIL arrives at max(`packet_deadline`,
      delay), 2s at the defaults, and every failure still costs its sender the whole delay.
    - **The circuit.** After `breaker.failures` (5) consecutive failures, a pool's circuit opens
      for `breaker.open_for` (5s) and then lets one call probe. A failure is any of:
      - a timeout;
      - a caller's deadline that struck mid-call;
      - an etcd error that is not a refusal by the roles.

      A caller that went away is none.
    - **No queue.** A call that cannot get an in-flight slot within its deadline is refused,
      never queued.
    - **Pools.** Token, context and bulk operations use separate slots and circuits; token and
      context operations use separate connections (design document §12).
  - **A store gone is a store that is down.** port49d closes every listener when:
    - it loses its hold on the keyspace;
    - the token or the context pool's circuit stays open for `store.etcd.hold_ttl`;
    - or every call on one of those pools is refused for that long (a role revoked at runtime):
      at least `breaker.failures` refusals, none more than `breaker.open_for` after the last.

    The bulk pool's circuit is alarmed, never a store gone: a slow scan while logins and
    commands are answered does not close the listeners. Held TACACS+ connections are reset.
    Devices then find the connection refused and use their local method: the owner's go-dark
    ruling of 2026-09-24 in its coarse form, which plan 7f refines. port49d then waits
    in-process for the store, `/readyz` 503, with no deadline, and starts again as below,
    retrying any error that start meets. Once it has served, it never exits for an outage.
  - **Identity.** Each component authenticates to etcd by its own client certificate, its CN
    etcd's user, under the roles `port49d store-roles` prints.
    - **The daemon's role cannot** read idempotency records, write the token indexes, write
      revocation marks, or write `meta/` (the keyspace hold and the seal-key record).
    - **The start check.** port49d refuses to start when its daemon identity can do any of
      those, probing reads and never-true writes, unless `store.etcd.roles: unenforced`, said at
      every start.
    - **Keys and certificates.** Key files load as the broker's key does (owner-only, no
      symlink). Every certificate's validity window, and the CA's, is checked at each start and
      named when it fails: never read as etcd not answering.
  - **One port49d per keyspace until plan 7e.**
    - **The hold.** port49d holds the keyspace on an etcd lease of `store.etcd.hold_ttl` (15s),
      as the broker. A second port49d waits for it, its listeners closed.
    - **A fence.** Every sixth of `hold_ttl` the holder reads its lock key and its lease's
      remaining TTL. It counts the hold lost when the key is gone or on another lease, the lease
      has expired, or, with etcd not answering, its estimate of the lease (each answer's send
      time plus its TTL) has half of `hold_ttl` or less left: at least a sixth of `hold_ttl`
      before etcd can expire the lease and let another take the keyspace.
  - **A start on etcd.** port49d waits for the store with every listener closed (up to
    `store.etcd.start_timeout`, 30s, then exits 1; `0` waits forever; after a store gone, no
    deadline), and then, retrying while the store errs:
    1. takes the hold;
    2. puts the revocations file's marks into the store (a mark in either stands);
    3. re-indexes every live context whose index record was deleted in the store, as it does
       after every index sweep;
    4. applies every standing mark to the live contexts the store kept, by the revocation's two
       context passes, so a revocation a restart or an outage cut short reaches them before any
       listener opens. A kept context that will not open is still marked, and never stops the
       start;
    5. deletes every unspent token, as a restart always did, and marks every key superseded,
       so an idempotent replay mints again;
    6. carries the policy in force into every live context the store kept;
    7. binds TACACS+.

    Live contexts survive a restart (what a device then sees: §15 L35). `store.backend: etcd`
    requires `admin_socket`, because editing `broker.revocations_file` with port49d stopped no
    longer lifts a mark the store also holds. A certificate a kept CRL newly names is marked by
    the certificate-status queue's first drain, which runs once the listeners are open.
  - **Keys.** A record sealed under a key outside the window is said by its key id. A start
    whose store was last sealed under a current key this window lacks warns
    (`port49_crypt_store_key_unknown`), says that start ends the sessions it cannot read, and
    never refuses: those records fail closed already.
  ```

  Then widen that last line to `(§5.1.4, §5.6, §5.7, §12, §14, §15; design document §8, §12,
  §13, §15, §17)`.

- [ ] **Step 2: Decision 24, amended for etcd.** In decision 24 replace `context and every
  unspent token, so without a live reload` (spec:6159) with `context and every unspent token on
  the memory store (on etcd, plan 7d, it ends every unspent token and keeps the contexts; decision
  35), so without a live reload`.

- [ ] **Step 3: §5.7, `store_unavailable`.** In the `store_unavailable` row replace `port49d will
  do this itself by closing its TACACS+ listener while the store is unhealthy (owner's ruling
  2026-09-24; arrives with the remote store, plan 7).` (find `arrives with the remote store,
  plan 7). The log line`) with:

  ```markdown
  port49d will do this itself by closing its TACACS+ listener while the store is unhealthy
  (owner's ruling 2026-09-24; plan 7f). On etcd (plan 7d) it already closes every listener once
  its hold on the store is lost, or the token or context pool's circuit has stayed open, or every
  call on one has been refused, for `store.etcd.hold_ttl`, and opens them again when the store
  returns. Before then a store that does not answer, or a pool's open circuit, is answered
  within `store.packet_deadline`, never left for the device to time out (what each image does
  then: §15 L35).
  ```

- [ ] **Step 4: §12, `port49d store-roles`** (pre-flight M5). After the `port49d
  init-revocations` paragraph (find `init-revocations is running or has just run; nothing
  written); 2 on usage.`, spec:5713) add:

  ```markdown
  **`port49d store-roles [--config <port49d.yaml>]`** prints the `etcdctl` commands that create
  port49's two etcd roles and grant them, for the keyspace `store.etcd.prefix` names (plan 7d;
  §13, decision 35).
  - **`port49_daemon`.** Read-write on the token, receipt, receipt-index, context, index-record,
    lookup and blob families (`t/`, `r/`, `rp/`, `c/`, `x/`, `ip/`, `is/`, `ic/`, `b/`), and
    read-only on the revocation marks (`rv/`) and the keyspace's `meta/`. Nothing on the token
    indexes (`tp/`, `tc/`) or the idempotency records (`id/`).
  - **`port49_broker`.** Read-write on the whole keyspace.
  - **The users.** A user per component, named by the CN of the certificate `store.etcd.daemon`
    and `store.etcd.broker` name, granted its role.
  - **What a stolen daemon key yields under these roles:** decision 35's residual, replay of
    records it cannot forge. While port49d runs that is an earlier version of a key's own
    context, a deleted token for a holder of its secret, or a receipt's sliding bound; across a
    restart, another login's context put back while port49d was stopped (impersonation). It can
    also hide a context from the index until the next sweep re-indexes it, and deny by deleting.
    The broker's role holds the whole keyspace until plan 7e splits the broker out.
  - **The command itself.** It reads the config and those certificates, holds no etcd
    credential, and changes nothing. It refuses a CN or prefix holding a character outside
    `[A-Za-z0-9._@/-]`, printing nothing. It exits 0, 1 naming what it could not read or
    refused, or 2 on usage.

  The output is run once, by etcd's root user.
  ```

- [ ] **Step 5: §14, port49d on etcd.** At the end of Task 1's `**Shared store**` list, add:

  ```markdown
  - **A restart on etcd**: a live context's next authorization is answered from it, an unspent
    token from before the restart is `token_not_found`, and a second port49d against the
    keyspace binds no listener.
  - **A mark at start**: a context the store kept, whose principal a mark added with port49d
    stopped names, is revoked before any listener binds, and its next command is denied
    `credential_revoked`.
  - **A store gone**: with the store hung past `store.etcd.hold_ttl`, port49d closes every
    listener, resets every held connection, and says why; when the store returns, the same
    process listens again. A start after a store gone that fails for any other reason is
    tried again, never an exit.
  - **The failure delay**: a FAIL behind a `store.packet_deadline` shorter than the delay takes
    the whole delay, and a FAIL behind a slow store arrives at the delay, its store time
    inside it.
  - **The bulk pool**: its circuit open for `store.etcd.hold_ttl` closes no listener.
  ```

- [ ] **Step 6: L35, opened** (pre-flight M6). In the §15 table, after the L34 row, add:

  ```markdown
  | **L35** | What a device does when port49d's store hangs rather than refuses (etcd cut off from port49d, or past its quorum): each request's time from the device's send to port49d's reply, against the device's own TACACS+ timeout (§15 L4, L13); what it shows for `FAIL` (a command) and `ERROR` (a login) `store_unavailable`, against L4's store outage (`tests/lab/results/L4-error-*.md`); whether break-glass logs in while the store hangs; what it does once port49d closes its listeners on losing the store; and, once the store returns and port49d listens again, whether an open session's next command is answered from its context. | `store.packet_deadline`'s default and bound, and the store rows of the failure model (§13, decision 35; design document §12) | EOS, NX-OS, IOS-XE, vJunos-router, vSRX | open — plan 7d Task 15 |
  ```

- [ ] **Step 7: The design's failure matrix** (pre-flight I4). In design §12's table:
  - In the **Token store unavailable** row replace `port49d will do this itself by closing its
    TACACS+ listener while the store is unhealthy (owner's ruling 2026-09-24; arrives with the
    remote store, plan 7). Continuing active logins from a replica's warm context cache through a
    store outage arrives with the remote store (plan 7)` (find `arrives with the remote store,
    plan 7). Continuing`) with `port49d will do this itself by closing its TACACS+ listener
    while the store is unhealthy (owner's ruling 2026-09-24; plan 7f); on etcd it closes it once
    the store has been gone for store.etcd.hold_ttl (the rows below). Continuing active logins
    from a replica's warm context cache through a store outage is plan 7f's`.
  - After that row add three rows, each stating port49d's side alone:

  ```markdown
  | **Store hangs or loses quorum** (etcd cut off from port49d, two of three members down; plan 7d) | ✓ `port49 login` touches no store | ✗ port49d answers ERROR `store_unavailable` within `store.packet_deadline`, and at once while a pool's circuit is open; once the store has been gone for `store.etcd.hold_ttl` it closes every listener (what each image does throughout: policy engine spec §15 L35, open) | ✗ port49d answers FAIL `store_unavailable` within `store.packet_deadline`, then closes every listener as in the cell before (what each image does, and whether an open session runs on under local authorization: L35, open) | ✗ |
  | **Store unreachable at start, or after a store gone** (plan 7d) | ✓ | ✗ nothing listens while port49d waits (`store.etcd.start_timeout` on a cold start, then exit 1; with no deadline after a store gone), as with port49d stopped | ✗ nothing listens, as with port49d stopped (`tests/lab/results/quarantine-*.md`) | ✗ |
  | **port49d restarted on etcd, or listening again after a store gone** (plan 7d) | ✓ | ✓ a token minted before is `token_not_found` (purged); `port49 token` again | port49d answers the session's next command from the context the store kept, revoked first by any standing mark and carried onto the policy in force before TACACS+ binds (what each image does: L35, open) | ⚠ tokens not yet spent are refused; an idempotent retry mints again |
  ```

- [ ] **Step 8: The design's Consequences.** In design §12 "Consequences":
  - After the **Connection pool separation** bullet, whose second line is `mint pressure cannot
    starve authorization.` (find `mint pressure cannot starve authorization.`), add:

    ```markdown
    - **As built on etcd (plan 7d; policy engine spec §13, decision 35).**
      - **Deadlines.** Each store call has `store.etcd.call_timeout` (500ms); the four scans
        `store.etcd.bulk_timeout` (30s); each TACACS+ packet's store work
        `store.packet_deadline` (2s, at most 2s, never cutting the failure delay).
      - **Pools.** The token and context pools are each their own etcd connection. Each of the
        three pools (token, context, bulk) has its own in-flight cap
        (`store.etcd.max_in_flight`) and circuit (`store.etcd.breaker`: open after 5
        consecutive failures, for 5s, then one probe). A call that cannot get a slot within its
        deadline is refused.
      - **What counts.** A failure is a timeout, a caller's deadline that struck mid-call, or an
        etcd error that is not a refusal by the roles; a caller that went away is none.
      - **Going dark.** The token or context pool's circuit open, or every call on it refused,
        for `store.etcd.hold_ttl` closes the listeners as a lost hold does. The bulk pool's
        circuit is alarmed, never a reason to close them.
      - The warm context cache stays plan 7f's.
    ```
  - In the readiness paragraph replace `It arrives with the remote store (plan 7).`
    (design:1181) with `It is plan 7f's; on etcd, plan 7d already closes every listener once the
    store has been gone for store.etcd.hold_ttl, so devices find the connection refused, and
    opens them again when it returns (policy engine spec §13, decision 35).`

- [ ] **Step 9: The design's deployment requirements** (pre-flight I5). In design §13, after the
  paragraph ending `a cross-region read alone can consume the entire budget.` (find
  `cross-region read alone can consume`, design:1300) add:

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
  - **No restart policy is needed for an outage, but keep `Restart=on-failure`.** port49d
    closes its listeners and waits for the store in-process, and once it has served it retries
    every start error after an outage. A supervisor is still what restarts it after a crash, or
    after a cold start that exits 1 (a configuration fault, or `start_timeout`).
  - **Backups.** Back etcd up as a database holding the revocation marks. Until plan 7e retires
    it, `broker.revocations_file` is kept as well.
    - **Protect every snapshot as the store itself.** It holds the plaintext index (§8):
      principal, device, username, certificate and `sid`.
    - **A restored snapshot** brings back every context it held. One a revocation by principal
      or certificate ended is denied again at once by the marks. One a self or key revocation
      ended (no mark) is live again until its idle TTL; revoke it again after a restore.
  ```

- [ ] **Step 10: The design's observability.** In design §15, after the paragraph beginning `The
  broker exports:` (design:1435) add:

  ```markdown
  The store (plan 7d) exports:
  - `port49_store_calls_total{component,pool,outcome}`;
  - `port49_store_call_seconds{component,pool}`;
  - `port49_store_circuit_open{component,pool}`, the circuit-breaker state the paragraph above
    requires;
  - `port49_store_keyspace_held`;
  - `port49_store_client_cert_expiry_timestamp_seconds{component}`;
  - `port49_crypt_store_key_unknown`;
  - `port49_contexts_reindexed_total`.

  Alert on any of:
  - a circuit open;
  - any increase of `port49_contexts_reindexed_total`: an index record deleted in the store;
  - the hold not held while port49d runs;
  - a store client certificate within 30 days of expiry;
  - `port49_crypt_store_key_unknown` at 1;
  - any increase of `port49_crypt_open_failures_total{record="token"}`: a token that will not
    open is dropped from its candidates with no error, so that counter is the only witness that
    a rotation retired a key while tokens it sealed were live (plan 2).
  ```

- [ ] **Step 11: The design's internal interfaces and the API's errors** (pre-flight M4).
  - In design §17's table, replace the cell `store-native auth over TLS` (design:1659) with
    `store-native auth over TLS: on etcd, a client certificate per component, its CN etcd's
    user, under port49's roles (\`port49d store-roles\`; policy engine spec §13, decision 35)`.
  - In the paragraph `The token store is the one place where a password may still exist`
    (design:1685), append: `On etcd it is none: each component's client certificate is its
    identity.`
  - In the **Errors** block (design:1513–1522), after the `503  certificate_status_unavailable`
    line, add:

    ```
    503  revocation_running               the agent's socket, not the broker: a `port49 token`, refresh, identity or explain waited 30 s for the agent's one connection while the operator's own revocation held it; nothing was sent (plan 7d)
    ```

- [ ] **Step 12: The design's sequencing** (pre-flight M3). In §19 step 2 (design:1771–1775):
  - Replace `in-memory store of step 1 is in-process) — **the last not built**: plan 2 shipped
    the sealing` (find `**the last not built**`) with `in-memory store of step 1 is in-process)
    — **the last built**: plan 2 shipped the sealing`.
  - Replace `is owed before the broker becomes a process of its own (step 7).` (find `is owed
    before the broker becomes a process`) with `was owed before the broker becomes a process of
    its own (step 7), and is built by plan 7d on etcd.`

- [ ] **Step 13: Check, then commit.**

  Run, and expect each (pre-flight M1):
  - `grep -n '| \*\*L35\*\*' docs/design/2026-08-23-policy-engine-spec.md`: one line, status
    `open`, platforms ending `vJunos-router, vSRX`.
  - `grep -n 'decision 35' docs/design/2026-08-23-policy-engine-spec.md`: lines in §5.7, §12,
    §14 and decision 24, beside Task 1's.
  - `grep -n 'store-roles' docs/design/2026-08-23-policy-engine-spec.md`: §12 and decision 35.
  - `grep -n 'the last not built\|arrives with the remote store' docs/design/2026-08-21-port49-design.md`:
    none.
  - `grep -n 'revocation_running' docs/design/2026-08-21-port49-design.md`: one line.
  - No cell of the three new matrix rows says what a device does without citing L35.

  Run `make test`.

  ```bash
  git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
  git commit -m "docs: port49d on etcd, and L35 opened (decision 35, plan 7d-2)

  Decision 35 gains plan 7d-2's rulings: hard timeouts and three pools,
  the packet deadline at most 2s and never cutting the failure delay, a
  store gone closing every listener and waiting in-process, identities
  and roles, the hold as a fence, the start's order with every standing
  mark applied to the kept contexts, admin_socket required on etcd, and
  the seal-key warning. Decision 24, §5.7, §12 (store-roles), §14 and the
  design's failure matrix, Consequences, deployment, observability,
  interfaces, Errors and §19 follow. Every device cell cites L35, opened
  here on five images.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 9: The guard: a hard timeout on every call, three pools with a circuit each, and going dark

**Files:**
- Create: `internal/store/guard/guard.go`
- Test: `internal/store/guard/guard_test.go`
- Modify: `internal/daemon/metrics/metrics.go`, `internal/daemon/metrics/metrics_test.go`

**Interfaces:**
- Consumes: `store.Store`, `store.ErrUnavailable`, `store.ErrRefused`, `store.ErrNotFound`,
  `store.ErrConflict`, `store.ErrPastGrace`; `etcd.Open` and `etcdtest.StartCluster` (7d-1) in
  one test.
- Produces:
  - `type guard.Pool string`; `const guard.Token, guard.Context, guard.Bulk Pool`
  - `type guard.Config struct { Component string; CallTimeout, BulkTimeout time.Duration; MaxInFlight map[Pool]int; Failures int; OpenFor, StopAfter time.Duration; Unhealthy func(why string); Now func() time.Time; Say func(string); Metrics Metrics }`
  - `type guard.Metrics struct { Calls *prometheus.CounterVec; Seconds *prometheus.HistogramVec; Open *prometheus.GaugeVec }`
  - `func guard.Wrap(inner store.Store, c Config) store.Store`
  - `func guard.PoolOf(method string) Pool`, the routing table, for the tests and the docs: ""
    for a name it does not hold (pre-flight M30).
  - metrics: `Metrics.StoreCalls` (`port49_store_calls_total{component,pool,outcome}`),
    `Metrics.StoreCallSeconds` (`port49_store_call_seconds{component,pool}`),
    `Metrics.StoreCircuitOpen` (`port49_store_circuit_open{component,pool}`), and
    `func (m *Metrics) StoreGuard() guard.Metrics`.

**The routing table** (Ruling 8). Three pools:
- **Context pool** (the authorization path, and the records it reads and writes): `GetContext`,
  `PutContext`, `SwapContext`, `SwapLogin`, `RewriteContext`, `TouchContext`, `SetPrivilege`,
  `AnnotateContext`, `RefreshContext`, `SetRevokedAt`, `SetContextPolicy`, `DeleteContext`,
  `DeleteContextIf`, `GetBlob`, `BumpBlob`, `IndexContext`, `UnindexContext`, `UnindexRef`,
  `ContextsByPrincipal`, `ContextsBySid`, `ContextsByCert`, `ReindexSid`.
- **Bulk pool** (the scans, pre-flight I14): `ActivePrincipals`, `DeleteReceiptsByPrincipal`,
  `ListRevocations`, `PurgeTokens`.
- **Token pool:** `PutToken`, `Candidates`, `RedeemAndReceipt`, `DeleteTokens`, `DeleteToken`,
  `GetReceipt`, `ExtendReceipt`, `FailReceipt`, `PutBlob`, `IndexToken`, `TokensByPrincipal`,
  `TokensByCert`, `ReserveIdempotency`, `CompleteIdempotency`, `ReleaseIdempotency`,
  `PutRevocation`, `GetRevocation`, `DeleteRevocation`.

That is all forty-four methods: the forty-one at `9cefbba`, with `SwapLogin`, `PurgeTokens` and
`RewriteContext`. The token and context pools are the etcd backend's own split: each method
there uses the client of the same name (7d-1). The bulk pool has its own slots, deadline and
circuit, and shares the backend's connections.

- [ ] **Step 1: The failing tests.** Create `internal/store/guard/guard_test.go`. It has no
  `TestMain`: the one test that needs etcd starts its own cluster (pre-flight M36).

  ```go
  package guard

  import (
  	"context"
  	"errors"
  	"reflect"
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

  func testMetrics() Metrics {
  	return Metrics{
  		Calls:   prometheus.NewCounterVec(prometheus.CounterOpts{Name: "c"}, []string{"component", "pool", "outcome"}),
  		Seconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "s"}, []string{"component", "pool"}),
  		Open:    prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "o"}, []string{"component", "pool"}),
  	}
  }

  // stuck is a store whose GetContext, PutToken and ActivePrincipals answer
  // as the test says: with err, after delay or at their context's end,
  // whichever is first; and GetContext alone, while hold is set, only once
  // hold is closed, whatever its context says (pre-flight I11): a call the
  // guard's deadline cannot end, which holds its slot.
  type stuck struct {
  	store.Store
  	mu    sync.Mutex
  	err   error
  	delay time.Duration
  	hold  chan struct{}
  	calls int
  }

  func (s *stuck) do(ctx context.Context, holdable bool) error {
  	s.mu.Lock()
  	s.calls++
  	err, delay, hold := s.err, s.delay, s.hold
  	s.mu.Unlock()
  	if holdable && hold != nil {
  		<-hold
  		return err
  	}
  	if delay > 0 {
  		select {
  		case <-time.After(delay):
  		case <-ctx.Done():
  			return ctx.Err()
  		}
  	}
  	return err
  }

  func (s *stuck) GetContext(ctx context.Context, _ store.ContextKey) (store.Context, error) {
  	return store.Context{}, s.do(ctx, true)
  }

  func (s *stuck) PutToken(ctx context.Context, _ store.TokenKey, _ store.Token) (int, error) {
  	return 0, s.do(ctx, false)
  }

  func (s *stuck) ActivePrincipals(ctx context.Context) ([]string, error) { return nil, s.do(ctx, false) }

  func (s *stuck) set(err error, delay time.Duration) {
  	s.mu.Lock()
  	s.err, s.delay = err, delay
  	s.mu.Unlock()
  }

  func (s *stuck) count() int {
  	s.mu.Lock()
  	defer s.mu.Unlock()
  	return s.calls
  }

  func eventually(t *testing.T, what string, cond func() bool) {
  	t.Helper()
  	deadline := time.Now().Add(5 * time.Second)
  	for !cond() {
  		if time.Now().After(deadline) {
  			t.Fatalf("timed out waiting for %s", what)
  		}
  		time.Sleep(5 * time.Millisecond)
  	}
  }

  type told struct {
  	mu    sync.Mutex
  	lines []string
  }

  func (t *told) add(l string) { t.mu.Lock(); t.lines = append(t.lines, l); t.mu.Unlock() }
  func (t *told) all() []string {
  	t.mu.Lock()
  	defer t.mu.Unlock()
  	return append([]string(nil), t.lines...)
  }

  func config(said, gone *told) Config {
  	return Config{Component: "daemon", CallTimeout: 50 * time.Millisecond, BulkTimeout: time.Second,
  		MaxInFlight: map[Pool]int{Token: 2, Context: 2, Bulk: 1}, Failures: 3, OpenFor: 100 * time.Millisecond,
  		StopAfter: time.Hour, Unhealthy: gone.add, Now: time.Now, Metrics: testMetrics(), Say: said.add}
  }

  var k = store.ContextKey{NAS: "leaf-01", Username: "alice"}

  // A call the store does not answer within call_timeout is
  // store.ErrUnavailable at the deadline, never later (Ruling 8).
  func TestACallPastItsTimeoutIsUnavailable(t *testing.T) {
  	var said, gone told
  	g := Wrap(&stuck{delay: time.Hour}, config(&said, &gone))
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
  	var said, gone told
  	inner := &stuck{err: store.ErrUnavailable}
  	c := config(&said, &gone)
  	g := Wrap(inner, c)
  	for i := 0; i < 3; i++ {
  		g.GetContext(context.Background(), k)
  	}
  	before := inner.count()
  	start := time.Now()
  	if _, err := g.GetContext(context.Background(), k); !errors.Is(err, store.ErrUnavailable) || inner.count() != before ||
  		time.Since(start) > 10*time.Millisecond {
  		t.Fatalf("an open circuit reached the store or waited: %v, %d calls, %v", err, inner.count()-before, time.Since(start))
  	}
  	if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "context")); v != 1 {
  		t.Fatalf("circuit gauge %v", v)
  	}
  	if l := said.all(); len(l) != 1 || !strings.Contains(l[0], "context pool's circuit is open after 3 consecutive failures") {
  		t.Fatalf("said %q", l)
  	}
  	// The token pool is its own: still closed.
  	if _, err := g.PutToken(context.Background(), store.TokenKey{}, store.Token{}); !errors.Is(err, store.ErrUnavailable) ||
  		inner.count() != before+1 {
  		t.Fatalf("the token pool should have reached the store: %v", err)
  	}
  	time.Sleep(110 * time.Millisecond)
  	inner.set(nil, 0)
  	if _, err := g.GetContext(context.Background(), k); err != nil {
  		t.Fatalf("the probe: %v", err)
  	}
  	if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "context")); v != 0 || len(said.all()) != 2 ||
  		!strings.Contains(said.all()[1], "closed") {
  		t.Fatalf("after a good probe: gauge %v, said %q", v, said.all())
  	}
  }

  // A failed probe opens the circuit again for OpenFor.
  func TestAFailedProbeOpensItAgain(t *testing.T) {
  	var said, gone told
  	inner := &stuck{err: store.ErrUnavailable}
  	g := Wrap(inner, config(&said, &gone))
  	for i := 0; i < 3; i++ {
  		g.GetContext(context.Background(), k)
  	}
  	time.Sleep(110 * time.Millisecond)
  	g.GetContext(context.Background(), k) // the probe, failing
  	before := inner.count()
  	g.GetContext(context.Background(), k)
  	if inner.count() != before {
  		t.Fatal("a failed probe left the circuit closed")
  	}
  }

  // Not found, a conflict, past-grace and a refusal are answers, never
  // failures: a thousand of them never open the circuit.
  func TestAnswersNeverTripIt(t *testing.T) {
  	var said, gone told
  	for _, err := range []error{store.ErrNotFound, store.ErrConflict, store.ErrPastGrace, store.ErrRefused} {
  		inner := &stuck{err: err}
  		g := Wrap(inner, config(&said, &gone))
  		for i := 0; i < 1000; i++ {
  			g.GetContext(context.Background(), k)
  		}
  		if inner.count() != 1000 {
  			t.Fatalf("%v opened the circuit", err)
  		}
  	}
  }

  // A caller that goes away (a device's connection dropping mid-call) is
  // not the store failing: the circuit does not count it, and its slot is
  // given back (Review Focus 7).
  func TestACallerThatGoesAwayIsNotAFailure(t *testing.T) {
  	var said, gone told
  	inner := &stuck{delay: time.Hour}
  	c := config(&said, &gone)
  	c.CallTimeout, c.Failures = time.Hour, 1
  	g := Wrap(inner, c)
  	for i := 0; i < 5; i++ {
  		ctx, cancel := context.WithCancel(context.Background())
  		time.AfterFunc(10*time.Millisecond, cancel)
  		_, err := g.GetContext(ctx, k)
  		if !errors.Is(err, context.Canceled) || errors.Is(err, store.ErrUnavailable) {
  			t.Fatalf("a caller that went away: %v", err)
  		}
  	}
  	if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "context")); v != 0 || inner.count() != 5 {
  		t.Fatalf("the caller's going away opened the circuit (%v) or held slots (%d calls)", v, inner.count())
  	}
  }

  // A caller's deadline that strikes mid-call (a packet's
  // store.packet_deadline, on the daemon) is the store too slow for it: it
  // is counted, as outcome deadline, and enough of them open the circuit
  // even though no call reached call_timeout (pre-flight I10).
  func TestACallersDeadlineIsAFailure(t *testing.T) {
  	var said, gone told
  	inner := &stuck{delay: time.Hour}
  	c := config(&said, &gone)
  	c.CallTimeout = time.Hour
  	g := Wrap(inner, c)
  	for i := 0; i < 3; i++ {
  		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
  		g.GetContext(ctx, k)
  		cancel()
  	}
  	if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "context")); v != 1 {
  		t.Fatalf("three callers' deadlines left the circuit closed (%v)", v)
  	}
  	if n := testutil.ToFloat64(c.Metrics.Calls.WithLabelValues("daemon", "context", "deadline")); n != 3 {
  		t.Fatalf("deadline outcomes: %v", n)
  	}
  }

  // A store slow but alive: every call is cut by its caller's deadline, the
  // circuit opens, every probe fails as slowly, and once the circuit has
  // stayed open for StopAfter the guard says so, once (Ruling 8; Ruling 11;
  // pre-flight I10).
  func TestASlowStoreGoesDark(t *testing.T) {
  	var said, gone told
  	inner := &stuck{delay: 40 * time.Millisecond}
  	c := config(&said, &gone)
  	c.Failures, c.OpenFor, c.StopAfter = 2, 50*time.Millisecond, 300*time.Millisecond
  	g := Wrap(inner, c)
  	deadline := time.Now().Add(3 * time.Second)
  	for len(gone.all()) == 0 && time.Now().Before(deadline) {
  		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
  		g.GetContext(ctx, k)
  		cancel()
  		time.Sleep(10 * time.Millisecond)
  	}
  	time.Sleep(100 * time.Millisecond) // more calls must not say it again
  	g.GetContext(context.Background(), k)
  	if l := gone.all(); len(l) != 1 || !strings.Contains(l[0], "context pool's circuit has been open for") {
  		t.Fatalf("told %q", l)
  	}
  }

  // A store that refuses every call (the daemon's role revoked at runtime)
  // never opens a circuit, but once a steady run of refusals has lasted
  // StopAfter the guard says so. An answer in between starts the count
  // again (pre-flight I10). So does a gap longer than OpenFor: two refusals
  // far apart are not a store refusing (re-check R-I5).
  func TestRefusalsGoDark(t *testing.T) {
  	var said, gone told
  	c := config(&said, &gone) // Failures 3, OpenFor 100ms
  	c.StopAfter = 200 * time.Millisecond
  	sparse := Wrap(&stuck{err: store.ErrRefused}, c)
  	sparse.GetContext(context.Background(), k)
  	time.Sleep(250 * time.Millisecond)
  	sparse.GetContext(context.Background(), k)
  	if l := gone.all(); len(l) != 0 {
  		t.Fatalf("two refusals with a gap past OpenFor went dark: %q", l)
  	}
  	inner := &stuck{err: store.ErrRefused}
  	g := Wrap(inner, c)
  	steady := func(d time.Duration) {
  		for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
  			g.GetContext(context.Background(), k)
  		}
  	}
  	steady(150 * time.Millisecond)
  	inner.set(nil, 0)
  	g.GetContext(context.Background(), k) // an answer: the count starts again
  	inner.set(store.ErrRefused, 0)
  	steady(150 * time.Millisecond)
  	if l := gone.all(); len(l) != 0 {
  		t.Fatalf("an answer did not restart the count: %q", l)
  	}
  	steady(100 * time.Millisecond)
  	if l := gone.all(); len(l) != 1 || !strings.Contains(l[0], "refused") {
  		t.Fatalf("told %q", l)
  	}
  	if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "context")); v != 0 {
  		t.Fatal("refusals opened the circuit")
  	}
  }

  // The bulk pool's circuit, open for StopAfter, is said and gauged and
  // never takes port49d dark: a slow scan is not a store gone while the
  // hot pools answer (re-check R-I5).
  func TestTheBulkPoolNeverGoesDark(t *testing.T) {
  	var said, gone told
  	c := config(&said, &gone)
  	c.StopAfter = 100 * time.Millisecond
  	g := Wrap(&stuck{err: store.ErrUnavailable}, c)
  	for end := time.Now().Add(400 * time.Millisecond); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
  		g.ActivePrincipals(context.Background())
  	}
  	if l := gone.all(); len(l) != 0 {
  		t.Fatalf("the bulk pool took port49d dark: %q", l)
  	}
  	if testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "bulk")) != 1 ||
  		len(said.all()) == 0 || !strings.Contains(said.all()[0], "bulk pool's circuit is open") {
  		t.Fatalf("the bulk circuit was not alarmed: said %q", said.all())
  	}
  }

  // A pool's slots are its own: with every context slot held by a call the
  // store does not answer, a further context call is refused at its
  // deadline without reaching the store, and a token call and a bulk call
  // are served (pre-flight I11, I14).
  func TestPoolsAreSeparate(t *testing.T) {
  	var said, gone told
  	inner := &stuck{hold: make(chan struct{})}
  	c := config(&said, &gone)
  	c.CallTimeout, c.Failures = 300*time.Millisecond, 100
  	g := Wrap(inner, c)
  	var wg sync.WaitGroup
  	for i := 0; i < 2; i++ {
  		wg.Add(1)
  		go func() { defer wg.Done(); g.GetContext(context.Background(), k) }()
  	}
  	eventually(t, "both context slots held", func() bool { return inner.count() == 2 })
  	start := time.Now()
  	if _, err := g.GetContext(context.Background(), k); !errors.Is(err, store.ErrUnavailable) ||
  		time.Since(start) < 250*time.Millisecond || inner.count() != 2 {
  		t.Fatalf("a third context call with both slots held: %v after %v, %d calls", err, time.Since(start), inner.count())
  	}
  	if _, err := g.PutToken(context.Background(), store.TokenKey{}, store.Token{}); err != nil {
  		t.Fatalf("a token call while the context pool is full: %v", err)
  	}
  	if _, err := g.ActivePrincipals(context.Background()); err != nil {
  		t.Fatalf("a bulk call while the context pool is full: %v", err)
  	}
  	close(inner.hold)
  	wg.Wait()
  }

  // A bulk call has its own deadline and circuit: a scan that fails opens
  // the bulk pool's, never the context pool's (pre-flight I14).
  func TestABulkFailureLeavesTheHotPoolsClosed(t *testing.T) {
  	var said, gone told
  	inner := &stuck{err: store.ErrUnavailable}
  	c := config(&said, &gone)
  	g := Wrap(inner, c)
  	for i := 0; i < 3; i++ {
  		g.ActivePrincipals(context.Background())
  	}
  	if testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "bulk")) != 1 ||
  		testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "context")) != 0 {
  		t.Fatal("a bulk failure reached the context pool's circuit, or not the bulk pool's")
  	}
  }

  // The guard passes every method through unchanged: every storetest
  // property holds through it.
  func TestTheGuardHoldsEveryProperty(t *testing.T) {
  	storetest.Run(t, storetest.Backend{New: func(t *testing.T, clock func() time.Time) store.Store {
  		var said, gone told
  		c := config(&said, &gone)
  		c.CallTimeout, c.BulkTimeout = 5*time.Second, 5*time.Second
  		c.MaxInFlight = map[Pool]int{Token: 64, Context: 64, Bulk: 8}
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
  	var said, gone told
  	c := config(&said, &gone)
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

  // Every store.Store method has a pool, and each guarded method runs in
  // the pool PoolOf names: driven through the guard over the memory store
  // with zero arguments, each moves exactly that pool's call counter
  // (pre-flight M30).
  func TestEveryMethodIsRoutedToItsPool(t *testing.T) {
  	var said, gone told
  	c := config(&said, &gone)
  	c.CallTimeout, c.BulkTimeout = 5*time.Second, 5*time.Second
  	g := reflect.ValueOf(Wrap(memory.New(time.Now), c))
  	st := reflect.TypeOf((*store.Store)(nil)).Elem()
  	for i := 0; i < st.NumMethod(); i++ {
  		m := st.Method(i)
  		p := PoolOf(m.Name)
  		if p != Token && p != Context && p != Bulk {
  			t.Errorf("%s has no pool", m.Name)
  			continue
  		}
  		before := poolCalls(c.Metrics.Calls, p)
  		args := []reflect.Value{reflect.ValueOf(context.Background())}
  		for j := 1; j < m.Type.NumIn(); j++ {
  			args = append(args, reflect.Zero(m.Type.In(j)))
  		}
  		g.MethodByName(m.Name).Call(args)
  		if got := poolCalls(c.Metrics.Calls, p); got != before+1 {
  			t.Errorf("%s ran %v calls in the %s pool, want 1", m.Name, got-before, p)
  		}
  	}
  }

  func poolCalls(c *prometheus.CounterVec, p Pool) float64 {
  	n := 0.0
  	for _, o := range outcomes {
  		n += testutil.ToFloat64(c.WithLabelValues("daemon", string(p), o))
  	}
  	return n
  }
  ```

  Run: `go test ./internal/store/guard/ -count=1`
  Expected: FAIL to build (`Wrap`, `Config`, `Pool`, `PoolOf`, `outcomes` undefined).

- [ ] **Step 2: The guard.** Create `internal/store/guard/guard.go`:

  ```go
  // Package guard is design §12's mitigations for a store that is slow or
  // gone, around any store.Store (plan 7d; spec §13, decision 35):
  //   - a hard timeout on every call;
  //   - a circuit breaker per pool, which stops calling a store that keeps
  //     failing and probes it;
  //   - three pools of in-flight slots (token, context and bulk), so mint
  //     pressure cannot starve authorization and a slow scan cannot open
  //     the circuit that holds a revocation's writes. A call that cannot get
  //     a slot within its deadline is refused: a queue is worse than a
  //     refusal.
  //
  // It reports a token or context pool that has stayed failed, or stayed
  // refused, for StopAfter, and port49d goes dark on that (Ruling 11); the
  // bulk pool's circuit is said and gauged, never reported. It sits under the
  // sealing layer, so a record that will not decrypt is never counted as
  // the store failing.
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

  // Pool is one of the three.
  type Pool string

  const (
  	Token   Pool = "token"
  	Context Pool = "context"
  	Bulk    Pool = "bulk"
  )

  var pools = map[string]Pool{
  	"GetContext": Context, "PutContext": Context, "SwapContext": Context, "SwapLogin": Context,
  	"RewriteContext": Context, "TouchContext": Context, "SetPrivilege": Context, "AnnotateContext": Context,
  	"RefreshContext": Context, "SetRevokedAt": Context, "SetContextPolicy": Context, "DeleteContext": Context,
  	"DeleteContextIf": Context, "GetBlob": Context, "BumpBlob": Context, "IndexContext": Context,
  	"UnindexContext": Context, "UnindexRef": Context, "ContextsByPrincipal": Context, "ContextsBySid": Context,
  	"ContextsByCert": Context, "ReindexSid": Context,

  	"ActivePrincipals": Bulk, "DeleteReceiptsByPrincipal": Bulk, "ListRevocations": Bulk, "PurgeTokens": Bulk,

  	"PutToken": Token, "Candidates": Token, "RedeemAndReceipt": Token, "DeleteTokens": Token, "DeleteToken": Token,
  	"GetReceipt": Token, "ExtendReceipt": Token, "FailReceipt": Token, "PutBlob": Token, "IndexToken": Token,
  	"TokensByPrincipal": Token, "TokensByCert": Token, "ReserveIdempotency": Token, "CompleteIdempotency": Token,
  	"ReleaseIdempotency": Token, "PutRevocation": Token, "GetRevocation": Token, "DeleteRevocation": Token,
  }

  // PoolOf is the pool method runs in, and "" for a name the table does not
  // hold: there is no default, so a method added to store.Store without a
  // row fails TestEveryMethodIsRoutedToItsPool.
  func PoolOf(method string) Pool { return pools[method] }

  // Config is one component's guard.
  type Config struct {
  	Component   string        // "daemon" or "broker": the metrics' label and the lines' subject
  	CallTimeout time.Duration // the token and context pools' deadline per call
  	BulkTimeout time.Duration // the bulk pool's
  	MaxInFlight map[Pool]int
  	Failures    int           // consecutive failures that open a pool's circuit
  	OpenFor     time.Duration // how long it stays open before a probe
  	// StopAfter is how long a token or context pool's circuit may stay
  	// open, or its calls be refused in a steady run, before Unhealthy is
  	// told, once (store.etcd.hold_ttl); zero never tells it. The bulk pool
  	// never tells it (re-check R-I5).
  	StopAfter time.Duration
  	Unhealthy func(why string)
  	Now       func() time.Time
  	Say       func(line string) // told when a circuit opens or closes; nil says nothing
  	Metrics   Metrics
  }

  // Metrics are the guard's series; nil fields count nothing.
  type Metrics struct {
  	Calls   *prometheus.CounterVec   // component, pool, outcome
  	Seconds *prometheus.HistogramVec // component, pool
  	Open    *prometheus.GaugeVec     // component, pool
  }

  // outcomes is every value of the outcome label: whether each is counted
  // toward the breaker, and whether it is a failure there.
  var outcomes = []string{"ok", "not_found", "conflict", "error", "timeout", "deadline", "unavailable", "refused",
  	"canceled", "saturated", "circuit_open"}

  type pool struct {
  	name    Pool
  	slots   chan struct{}
  	timeout time.Duration
  	mu      sync.Mutex
  	fails   int
  	open    bool
  	until   time.Time
  	probe   bool
  	cause   error
  	// openedAt is when the circuit last opened from closed; a failed probe
  	// opens it again without moving it. refusedSince is the first refusal
  	// of the current run, lastRefused its latest, and refused its count: a
  	// run ends at an answer, or at a refusal more than OpenFor after the
  	// one before it, which starts the next (re-check R-I5). told is whether
  	// Unhealthy has been told about this run of either.
  	openedAt, refusedSince, lastRefused time.Time
  	refused                             int
  	told                                bool
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
  	for _, p := range []Pool{Token, Context, Bulk} {
  		n := c.MaxInFlight[p]
  		if n <= 0 {
  			n = 64
  		}
  		timeout := c.CallTimeout
  		if p == Bulk {
  			timeout = c.BulkTimeout
  		}
  		g.pools[p] = &pool{name: p, slots: make(chan struct{}, n), timeout: timeout}
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

  // leave records how a call ended, and reports whether the circuit changed
  // and how it now stands. A call not counted (a caller that went away, a
  // refusal, a slot never got) changes nothing but the probe it held; a
  // refusal also starts or continues the refused run, and an answer ends it.
  func (p *pool) leave(now time.Time, probe bool, outcome string, cause error, threshold int, openFor time.Duration) (changed, open bool) {
  	p.mu.Lock()
  	defer p.mu.Unlock()
  	if probe {
  		p.probe = false
  	}
  	switch outcome {
  	case "refused":
  		if p.refusedSince.IsZero() || now.Sub(p.lastRefused) > openFor {
  			p.refusedSince, p.refused, p.told = now, 0, false
  		}
  		p.lastRefused = now
  		p.refused++
  		return false, p.open
  	case "canceled", "saturated":
  		return false, p.open
  	case "timeout", "deadline", "unavailable":
  		p.fails++
  		p.cause = cause
  		if probe || !p.open && p.fails >= threshold {
  			was := p.open
  			p.open, p.until = true, now.Add(openFor)
  			if !was {
  				p.openedAt = now
  			}
  			return !was, true
  		}
  		return false, p.open
  	}
  	// An answer: ok, not_found, conflict, error.
  	p.fails, p.refusedSince, p.refused, p.told = 0, time.Time{}, 0, false
  	if p.open {
  		p.open = false
  		return true, false
  	}
  	return false, false
  }

  // gone reports, once per run, a pool whose circuit has stayed open, or
  // whose every call has been refused, for stopAfter: a refused run of at
  // least minRefused calls, none more than OpenFor apart (leave). whose
  // names the pool ("the daemon's context pool").
  func (p *pool) gone(now time.Time, stopAfter time.Duration, minRefused int, whose string) (why string, tell bool) {
  	p.mu.Lock()
  	defer p.mu.Unlock()
  	if stopAfter <= 0 || p.told {
  		return "", false
  	}
  	switch {
  	case p.open && now.Sub(p.openedAt) >= stopAfter:
  		p.told = true
  		return fmt.Sprintf("%s's circuit has been open for %v (%v)", whose, stopAfter, p.cause), true
  	case !p.refusedSince.IsZero() && p.refused >= minRefused && now.Sub(p.refusedSince) >= stopAfter:
  		p.told = true
  		return fmt.Sprintf("every call on %s has been refused by the store for %v (its role no longer grants it)",
  			whose, stopAfter), true
  	}
  	return "", false
  }

  // do runs one call in pool p.
  func (g *guarded) do(ctx context.Context, p Pool, f func(context.Context) error) error {
  	pl := g.pools[p]
  	defer g.watch(pl)
  	probe, ok := pl.enter(g.c.Now())
  	if !ok {
  		g.count(p, "circuit_open")
  		return fmt.Errorf("%w: the %s pool's circuit is open", store.ErrUnavailable, p)
  	}
  	cctx, cancel := context.WithTimeout(ctx, pl.timeout)
  	defer cancel()
  	select {
  	case pl.slots <- struct{}{}:
  	case <-cctx.Done():
  		pl.leave(g.c.Now(), probe, "saturated", nil, g.c.Failures, g.c.OpenFor)
  		if ctx.Err() != nil {
  			g.count(p, "canceled")
  			return ctx.Err()
  		}
  		g.count(p, "saturated")
  		return fmt.Errorf("%w: every %s slot was busy for %v", store.ErrUnavailable, p, pl.timeout)
  	}
  	start := time.Now()
  	err := f(cctx)
  	<-pl.slots
  	if g.c.Metrics.Seconds != nil {
  		g.c.Metrics.Seconds.WithLabelValues(g.c.Component, string(p)).Observe(time.Since(start).Seconds())
  	}
  	outcome := classify(ctx, cctx, err)
  	if outcome == "timeout" {
  		err = fmt.Errorf("%w: no answer in %v", store.ErrUnavailable, pl.timeout)
  	}
  	g.count(p, outcome)
  	if changed, open := pl.leave(g.c.Now(), probe, outcome, err, g.c.Failures, g.c.OpenFor); changed {
  		g.changed(p, open, err)
  	}
  	return err
  }

  // classify names how a call ended. The caller's own context is read
  // before the error, because a backend maps a caller's expired deadline to
  // store.ErrUnavailable like any other (pre-flight M26): a caller that went
  // away is canceled, never counted; a caller whose deadline struck mid-call
  // is deadline, a failure, since the store was too slow for it (a packet's
  // store.packet_deadline on the daemon; pre-flight I10). A store answer is
  // read first of all: it is an answer whatever the caller's context did
  // after it.
  func classify(caller, call context.Context, err error) string {
  	switch {
  	case err == nil:
  		return "ok"
  	case errors.Is(err, store.ErrNotFound):
  		return "not_found"
  	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrPastGrace):
  		return "conflict"
  	case errors.Is(err, store.ErrRefused):
  		return "refused"
  	case errors.Is(caller.Err(), context.Canceled):
  		return "canceled"
  	case errors.Is(caller.Err(), context.DeadlineExceeded):
  		return "deadline"
  	case call.Err() != nil:
  		return "timeout"
  	case errors.Is(err, store.ErrUnavailable):
  		return "unavailable"
  	}
  	return "error" // an answer the store gave that is none of the above: a record that does not decode, a request too large
  }

  func (g *guarded) count(p Pool, outcome string) {
  	if g.c.Metrics.Calls != nil {
  		g.c.Metrics.Calls.WithLabelValues(g.c.Component, string(p), outcome).Inc()
  	}
  }

  // watch tells Unhealthy, outside every lock, when pl has gone dark. The
  // bulk pool never does (re-check R-I5): a scan slow at scale, or a
  // refused one, while the token and context pools answer, is not a store
  // gone, and closing every listener on it would undo the pools' separation
  // (pre-flight I14). Its circuit is said and gauged (changed), and that is
  // the alarm. A pool with no calls never reaches watch, so an idle pool
  // whose circuit is open is never told: harmless, since an idle pool
  // serves no one (re-check R-M5).
  func (g *guarded) watch(pl *pool) {
  	if pl.name == Bulk {
  		return
  	}
  	whose := fmt.Sprintf("the %s's %s pool", g.c.Component, pl.name)
  	if why, tell := pl.gone(g.c.Now(), g.c.StopAfter, g.c.Failures, whose); tell && g.c.Unhealthy != nil {
  		g.c.Unhealthy(why)
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
  	if open && p == Bulk {
  		g.c.Say(fmt.Sprintf("port49d: store: the %s's bulk pool's circuit is open after %d consecutive failures (%v); "+
  			"the scans (the refresh, a revocation by principal, a start's purge) fail until a probe in %v succeeds; "+
  			"logins and commands are unaffected", g.c.Component, g.c.Failures, cause, g.c.OpenFor))
  		return
  	}
  	if open {
  		g.c.Say(fmt.Sprintf("port49d: store: the %s's %s pool's circuit is open after %d consecutive failures (%v); "+
  			"each call on it fails at once until a probe in %v succeeds; devices see store_unavailable, and "+
  			"break-glass is refused (L4); port49d closes its listeners if the store is gone for store.etcd.hold_ttl",
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

  func (g *guarded) ActivePrincipals(ctx context.Context) (ps []string, err error) {
  	err = g.do(ctx, Bulk, func(ctx context.Context) (e error) { ps, e = g.inner.ActivePrincipals(ctx); return })
  	return
  }
  ```

  Write all forty-four. Each one's pool is the routing table's (`PoolOf(name)`), written as the
  constant. `TestEveryMethodIsRoutedToItsPool` pins every one, and
  `TestTheGuardHoldsEveryProperty` pins the pass-through. End the file with `var _ store.Store =
  (*guarded)(nil)`.

  A circuit-open error from the guard is `store.ErrUnavailable`, so every handler already
  answers it `store_unavailable` (spec §5.7). So is a refusal: every handler answers any error
  but `ErrNotFound` that way. No reason code is added.

- [ ] **Step 3: The metrics.** In `internal/daemon/metrics/metrics.go`, beside `StoreOps`:

  ```go
  	// StoreCalls, StoreCallSeconds and StoreCircuitOpen are the guard's
  	// (internal/store/guard; plan 7d): every store call by component
  	// (daemon, broker), pool (token, context, bulk) and outcome (ok,
  	// not_found, conflict, error, timeout, deadline, unavailable, refused,
  	// canceled, saturated, circuit_open); how long they took; and whether
  	// each pool's circuit is open, design §15's circuit-breaker state. The
  	// gauge moves only when a call ends, so a pool no one calls keeps the
  	// value of its last call, open included, and never goes dark on it:
  	// harmless, since it serves no one (re-check R-M5).
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
  			Buckets: []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30}}, []string{"component", "pool"}),
  		StoreCircuitOpen: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "port49_store_circuit_open",
  			Help: "1 while a pool's circuit is open: its calls fail at once until a probe succeeds."}, []string{"component", "pool"}),
  ```

  Add the three to the registration list, and their names to `TestNewRegistersEveryMetric`
  (metrics_test.go:12–110), with one sample each so the gatherer reports them (pre-flight M31).
  Add a method:

  ```go
  // StoreGuard is the guard's Metrics over these series.
  func (m *Metrics) StoreGuard() guard.Metrics {
  	return guard.Metrics{Calls: m.StoreCalls, Seconds: m.StoreCallSeconds, Open: m.StoreCircuitOpen}
  }
  ```

  `internal/store/guard` imports nothing of `metrics`, so `metrics` importing `guard` is no
  cycle. If the compiler finds one, build `guard.Metrics` in `cmd/port49d` instead, and say so.

- [ ] **Step 4: Run.**

  Run: `go test ./internal/store/guard/ ./internal/daemon/metrics/ -count=1`
  Expected: PASS: every test above, `TestTheGuardHoldsEveryProperty/<every property>` included.

  Mutation checks (do them, report them, revert them):
  1. In `classify`, move the `caller.Err()` cases below `call.Err()`.
     `TestACallerThatGoesAwayIsNotAFailure` must fail: the cancelled call is then a `timeout`,
     counted, and opens the circuit.
  2. In `do`, wait for a slot on `ctx` rather than `cctx`. `TestPoolsAreSeparate`'s third call
     then waits for a slot that is held until the test closes `hold`, after its asserts: the test
     hangs. Give that run `-timeout 30s`, and report the timeout (pre-flight I11).
  3. In `leave`, treat `deadline` as not counted. `TestACallersDeadlineIsAFailure` and
     `TestASlowStoreGoesDark` must fail.
  4. In `PoolOf`'s table, move `ListRevocations` to `Token` and leave its method on `Bulk`.
     `TestEveryMethodIsRoutedToItsPool` must fail.
  5. In `watch`, drop the `Bulk` return. `TestTheBulkPoolNeverGoesDark` must fail.
  6. In `leave`, drop the gap check (`now.Sub(p.lastRefused) > openFor`).
     `TestRefusalsGoDark` must fail ("two refusals with a gap").

- [ ] **Step 5: Commit.**

  ```bash
  gofmt -w internal/store/guard internal/daemon/metrics
  make build && make test && make vet
  git add internal/store/guard/guard.go internal/store/guard/guard_test.go \
    internal/daemon/metrics/metrics.go internal/daemon/metrics/metrics_test.go
  git commit -m "feat(store/guard): a hard timeout, three pools with a circuit each, and going dark

  Every store call has its own deadline; after five consecutive failures
  a pool's circuit opens for five seconds and then lets one probe
  through; token, context and bulk calls have their own slots, and one
  that cannot get a slot within its deadline is refused. A caller that
  went away is never the store failing; a caller's deadline that struck
  mid-call is. A token or context pool whose circuit stays open, or whose
  calls are refused in a steady run, for hold_ttl is reported, and
  port49d goes dark on it; the bulk pool's circuit is alarmed instead.
  Design §12's hard timeouts, circuit breaker and pool separation (plan
  7d; decision 35; pre-flight I10, I11, I14; re-check R-I5).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 10: `store:` in port49d.yaml, and every packet's deadline

**Files:**
- Modify: `internal/config/config.go`
- Create: `internal/config/store_test.go`
- Modify: `internal/daemon/server/server.go` (`Deps.PacketDeadline`), `conn.go` (`dispatch`)
- Modify: `internal/daemon/authen/authen.go` (`WithDelayContext`, `DelayContext`; `fail`)
- Test: `internal/daemon/server/server_test.go`
- Modify: `cmd/port49d/main.go` (`deps.PacketDeadline`)

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `type config.StoreConfig struct { Backend string; PacketDeadline time.Duration; Etcd *EtcdConfig }`
  - `type config.EtcdConfig struct { Endpoints []string; CAFile, Prefix string; Daemon EtcdIdentity; Broker *EtcdIdentity; Roles string; CallTimeout, BulkTimeout time.Duration; Breaker EtcdBreaker; MaxInFlight EtcdInFlight; LeaseGrace, HoldTTL, SweepInterval time.Duration; StartTimeoutSet *time.Duration; StartTimeout time.Duration }`
    (`StartTimeoutSet` is the YAML key `start_timeout`; `StartTimeout`, untagged, is its resolved
    value, 0 for "wait forever")
  - `type config.EtcdIdentity struct { CertFile, KeyFile string }`, `type config.EtcdBreaker struct { Failures int; OpenFor time.Duration }`, `type config.EtcdInFlight struct { Token, Context, Bulk int }`
  - `config.Config.Store StoreConfig`
  - `func config.StoreOf(raw []byte) (StoreConfig, error)` (for `port49d store-roles`, Task 11)
  - `const config.BackendMemory = "memory"`, `config.BackendEtcd = "etcd"`, `config.RolesEnforced`, `config.RolesUnenforced = "unenforced"`
  - `server.Deps.PacketDeadline time.Duration`
  - `func authen.WithDelayContext(ctx, delay context.Context, arrived time.Time) context.Context`,
    `func authen.DelayContext(ctx context.Context) (context.Context, time.Time)`

The schema, with every default:

```yaml
store:
  backend: etcd                 # memory (default) or etcd; etcd requires admin_socket (Ruling 13)
  packet_deadline: 2s           # 100ms to 2s (L13), and at least store.etcd.call_timeout
  etcd:
    endpoints: [https://etcd-0:2379, https://etcd-1:2379, https://etcd-2:2379]   # https only
    ca_file: /etc/port49/etcd-ca.pem
    prefix: /port49/            # the keyspace; must start with /
    daemon: {cert_file: /etc/port49/etcd-daemon.pem, key_file: /etc/port49/etcd-daemon-key.pem}
    broker: {cert_file: /etc/port49/etcd-broker.pem, key_file: /etc/port49/etcd-broker-key.pem}
    roles: enforced             # enforced (default) or unenforced
    call_timeout: 500ms         # 10ms to 5s: the token and context pools
    bulk_timeout: 30s           # 1s to 5m: the bulk pool's scans
    breaker: {failures: 5, open_for: 5s}               # 1 to 100; 1s to 5m
    max_in_flight: {token: 64, context: 128, bulk: 4}  # 1 to 4096 each
    lease_grace: 5m             # 1m to 1h
    start_timeout: 30s          # 0 (wait forever), or 5s to 10m
    hold_ttl: 15s               # 5s to 60s
    sweep_interval: 10m         # 1m to 24h
```

**Rulings in this task:**
- `store.backend: etcd` requires a `broker:` block. Until 7e the one port49d on a keyspace is its
  broker too, so a broker-less port49d on etcd would have no policy to carry live contexts onto at
  a start (Ruling 12).
- `store.backend: etcd` requires `admin_socket`. On etcd a mark is kept in the store as well as the
  file, so stopping port49d and editing the file no longer lifts one (Ruling 13; pre-flight I16).
- Key files must be named and exist. Their mode, owner and symlink are `internal/keyfile`'s to
  refuse when port49d loads them (Task 12): one check, at the read, with no window between
  check and use (pre-flight I13).
- `store.etcd` beside `backend: memory` is refused, so a config that names etcd and runs on memory
  fails loudly.
- `packet_deadline` is at most 2 s: L13 measured the Junos images timing out a reply at about 3 s
  (pre-flight I1).

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
  	s, err := checkStore(storeYAML{}, true, false)
  	if err != nil || s.Backend != BackendMemory || s.PacketDeadline != 2*time.Second || s.Etcd != nil {
  		t.Fatalf("%+v %v", s, err)
  	}
  }

  func TestEtcdTakesItsDefaults(t *testing.T) {
  	s, err := checkStore(etcdYAML(storeFiles(t)), true, true)
  	if err != nil {
  		t.Fatal(err)
  	}
  	e := s.Etcd
  	if e.Prefix != "/port49/" || e.Roles != "enforced" || e.CallTimeout != 500*time.Millisecond ||
  		e.BulkTimeout != 30*time.Second || e.Breaker.Failures != 5 || e.Breaker.OpenFor != 5*time.Second ||
  		e.MaxInFlight.Token != 64 || e.MaxInFlight.Context != 128 || e.MaxInFlight.Bulk != 4 ||
  		e.LeaseGrace != 5*time.Minute || e.StartTimeout != 30*time.Second || e.HoldTTL != 15*time.Second ||
  		e.SweepInterval != 10*time.Minute {
  		t.Fatalf("%+v", e)
  	}
  }

  // A start_timeout of 0 is "wait forever", not "take the default"
  // (pre-flight I19): the YAML field is a pointer, so an absent key and a
  // 0 are told apart.
  func TestAStartTimeoutOfZeroWaitsForever(t *testing.T) {
  	y := etcdYAML(storeFiles(t))
  	zero := time.Duration(0)
  	y.Etcd.StartTimeoutSet = &zero
  	s, err := checkStore(y, true, true)
  	if err != nil || s.Etcd.StartTimeout != 0 {
  		t.Fatalf("%+v %v", s.Etcd, err)
  	}
  }

  func TestTheStoreRefusesWhatWouldRunUnsafely(t *testing.T) {
  	dir := storeFiles(t)
  	for _, c := range []struct {
  		name          string
  		edit          func(*storeYAML)
  		broker, admin bool
  		want          string
  	}{
  		{"unknown backend", func(s *storeYAML) { s.Backend = "redis" }, true, true, `store.backend "redis": must be memory or etcd`},
  		{"etcd with no block", func(s *storeYAML) { s.Etcd = nil }, true, true, "store.etcd is missing"},
  		{"a block on memory", func(s *storeYAML) { s.Backend = "memory" }, true, true, "store.etcd is set but store.backend is memory"},
  		{"plain http", func(s *storeYAML) { s.Etcd.Endpoints = []string{"http://etcd-0:2379"} }, true, true, "must be https://"},
  		{"no endpoints", func(s *storeYAML) { s.Etcd.Endpoints = nil }, true, true, "store.etcd.endpoints is empty"},
  		{"a key file missing", func(s *storeYAML) { s.Etcd.Daemon.KeyFile = filepath.Join(dir, "nope.pem") }, true, true,
  			"store.etcd.daemon.key_file"},
  		{"no broker identity", func(s *storeYAML) { s.Etcd.Broker = nil }, true, true, "store.etcd.broker is missing"},
  		{"etcd with no broker", func(s *storeYAML) {}, false, true, "store.backend etcd needs a broker: block"},
  		{"etcd with no admin socket", func(s *storeYAML) {}, true, false, "store.backend etcd needs admin_socket"},
  		{"roles misspelt", func(s *storeYAML) { s.Etcd.Roles = "off" }, true, true, `store.etcd.roles "off"`},
  		{"a deadline past 2s", func(s *storeYAML) { s.PacketDeadline = 2500 * time.Millisecond }, true, true,
  			"store.packet_deadline"},
  		{"a deadline under the call's", func(s *storeYAML) {
  			s.PacketDeadline, s.Etcd.CallTimeout = 200*time.Millisecond, time.Second
  		}, true, true, "at least store.etcd.call_timeout"},
  		{"a prefix not absolute", func(s *storeYAML) { s.Etcd.Prefix = "port49/" }, true, true, "store.etcd.prefix"},
  		{"a hold too short", func(s *storeYAML) { s.Etcd.HoldTTL = time.Second }, true, true, "store.etcd.hold_ttl"},
  		{"a start timeout too short", func(s *storeYAML) { d := time.Second; s.Etcd.StartTimeoutSet = &d }, true, true,
  			"store.etcd.start_timeout"},
  	} {
  		y := etcdYAML(dir)
  		c.edit(&y)
  		if _, err := checkStore(y, c.broker, c.admin); err == nil || !strings.Contains(err.Error(), c.want) {
  			t.Errorf("%s: %v, want %q", c.name, err, c.want)
  		}
  	}
  }
  ```

  `EtcdConfig.StartTimeout` takes Load's default when the key is absent, and `0` when it says 0,
  which a plain `time.Duration` cannot tell apart. So the YAML field is a pointer
  (`StartTimeoutSet *time.Duration \`yaml:"start_timeout"\``), and the resolved
  `StartTimeout` is tagged `yaml:"-"`, so no key decodes into it. Name them as the file's other optional durations are named, if it
  has a convention (grep `\*time.Duration`); the test follows the names.

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

  // The packet deadline bounds store work and never the brute-force delay:
  // a FAIL behind a 50ms deadline still takes the whole 300ms delay
  // (pre-flight I1; authen.Session.fail).
  func TestThePacketDeadlineNeverShortensTheFailureDelay(t *testing.T) {
  	log := &syncBuffer{}
  	st := memory.New(time.Now)
  	ts := newTestServerWith(t, log, st, nil, func(d *Deps) {
  		d.PacketDeadline = 50 * time.Millisecond
  		lim := limits.New(limits.Config{PerNASConnections: 2, IdleTimeout: time.Second,
  			MalformedBackoffBase: time.Millisecond, MalformedBackoffMax: time.Millisecond, MalformedWindow: time.Minute,
  			AuthFailureDelayBase: 300 * time.Millisecond, AuthFailureDelayMax: 300 * time.Millisecond,
  			AuthFailureWindow: time.Minute}, time.Now)
  		d.Limits = lim
  		d.Authen = authen.New(st, d.Log, lim, d.Metrics, time.Now, func() string { return "ctx1" },
  			15*time.Minute, 2*time.Hour, time.Hour, time.Hour, token.NewTagWindow(token.TagKey([]byte("server_test"))))
  	})
  	c := dial(t, ts.addr, []byte("k2"))
  	start := time.Now()
  	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
  		Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: []byte("not-a-token")}.Encode(), 0)
  	_, body := c.recv(t)
  	took := time.Since(start)
  	reply, err := wire.DecodeAuthenReply(body)
  	if err != nil || reply.Status != wire.AuthenStatusFail || took < 300*time.Millisecond {
  		t.Fatalf("status %v (%v) after %v: the packet deadline cut the failure delay", reply.Status, err, took)
  	}
  }

  // slowStore answers the two reads a wrong token's redemption makes, each
  // after d: a store slow but inside every deadline.
  type slowStore struct {
  	store.Store
  	d time.Duration
  }

  func (s slowStore) GetReceipt(ctx context.Context, rk store.ReceiptKey) (store.Receipt, error) {
  	time.Sleep(s.d)
  	return s.Store.GetReceipt(ctx, rk)
  }

  func (s slowStore) Candidates(ctx context.Context, k store.TokenKey) ([]store.Token, error) {
  	time.Sleep(s.d)
  	return s.Store.Candidates(ctx, k)
  }

  // The failure delay counts from the packet's arrival, so the store's time
  // is inside it, not added to it: a wrong token behind a store spending
  // 250ms and a 300ms delay is answered FAIL at about 300ms, never 550ms
  // (re-check N1). That keeps a FAIL's worst case at max(packet_deadline,
  // delay), inside Junos's 3s (L13), and the throttle whole.
  func TestAFailArrivesAtItsDelay(t *testing.T) {
  	log := &syncBuffer{}
  	st := slowStore{Store: memory.New(time.Now), d: 125 * time.Millisecond}
  	ts := newTestServerWith(t, log, st, nil, func(d *Deps) {
  		d.PacketDeadline = 2 * time.Second
  		lim := limits.New(limits.Config{PerNASConnections: 2, IdleTimeout: time.Second,
  			MalformedBackoffBase: time.Millisecond, MalformedBackoffMax: time.Millisecond, MalformedWindow: time.Minute,
  			AuthFailureDelayBase: 300 * time.Millisecond, AuthFailureDelayMax: 300 * time.Millisecond,
  			AuthFailureWindow: time.Minute}, time.Now)
  		d.Limits = lim
  		d.Authen = authen.New(st, d.Log, lim, d.Metrics, time.Now, func() string { return "ctx1" },
  			15*time.Minute, 2*time.Hour, time.Hour, time.Hour, token.NewTagWindow(token.TagKey([]byte("server_test"))))
  	})
  	c := dial(t, ts.addr, []byte("k2"))
  	start := time.Now()
  	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
  		Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: []byte("not-a-token")}.Encode(), 0)
  	_, body := c.recv(t)
  	took := time.Since(start)
  	reply, err := wire.DecodeAuthenReply(body)
  	if err != nil || reply.Status != wire.AuthenStatusFail || took < 300*time.Millisecond || took >= 500*time.Millisecond {
  		t.Fatalf("status %v (%v) after %v: want FAIL at the 300ms delay, the 250ms of store inside it", reply.Status,
  			err, took)
  	}
  }
  ```

  Read `newTestServerWith` (server_test.go:171) first: `d.Log` and `d.Metrics` are the fixture's
  emitter and metrics, and `authen.New`'s arguments are the fixture's own, with the limiter
  swapped.

  Run: `go test ./internal/config/ ./internal/daemon/server/ -count=1`
  Expected: FAIL to build (`storeYAML`, `checkStore`, `EtcdConfig`, `Deps.PacketDeadline`
  undefined).

- [ ] **Step 2: The config.** In `internal/config/config.go`:

  1. After `CertificateStatusOCSP`, add the types from Interfaces with their YAML tags,
     snake_case as the schema above shows, and their comments: each field's meaning and bounds,
     as the schema says. `StoreConfig` has no YAML tags. It is the resolved form, built from:

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
     	if c.Store, err = checkStore(f.Store, f.Broker != nil, f.AdminSocket != ""); err != nil {
     		return Config{}, err
     	}
     ```

     Match the local names `Load` uses (`f`, `c`, `err`). Read the function first.

  3. Add:

     ```go
     // checkStore resolves `store:` (plan 7d; spec §13, decision 35): the
     // backend, the packet deadline, and on etcd every key's default and
     // bound. It refuses what would run unsafely:
     //   - an endpoint that is not https;
     //   - an identity missing, or a file it names absent;
     //   - etcd with no broker (until plan 7e the one port49d on a keyspace
     //     is its broker too);
     //   - etcd with no admin_socket (there is no other way to lift a mark;
     //     Ruling 13).
     // A key file's mode, owner and symlink are refused where it is read,
     // by internal/keyfile (Task 12).
     func checkStore(s storeYAML, hasBroker, hasAdminSocket bool) (StoreConfig, error) {
     	out := StoreConfig{Backend: or(s.Backend, BackendMemory), PacketDeadline: orD(s.PacketDeadline, 2*time.Second)}
     	if out.PacketDeadline < 100*time.Millisecond || out.PacketDeadline > 2*time.Second {
     		return StoreConfig{}, fmt.Errorf("store.packet_deadline %v: must be 100ms to 2s, so a device hears port49's "+
     			"answer before its own TACACS+ timeout, which is about 3s on Junos (spec §15, L13)", out.PacketDeadline)
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
     	if !hasAdminSocket {
     		return StoreConfig{}, errors.New("store.backend etcd needs admin_socket: on etcd a mark is kept in the store " +
     			"as well as broker.revocations_file, so editing the file no longer lifts one; a lift is " +
     			"'port49 revoke --lift' on the admin socket (decision 35)")
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
     		for _, f := range [][2]string{{".cert_file", id.id.CertFile}, {".key_file", id.id.KeyFile}} {
     			if err := readableFile(id.name+f[0], f[1]); err != nil {
     				return StoreConfig{}, err
     			}
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
     		{"store.etcd.bulk_timeout", &e.BulkTimeout, 30 * time.Second, time.Second, 5 * time.Minute},
     		{"store.etcd.breaker.open_for", &e.Breaker.OpenFor, 5 * time.Second, time.Second, 5 * time.Minute},
     		{"store.etcd.lease_grace", &e.LeaseGrace, 5 * time.Minute, time.Minute, time.Hour},
     		{"store.etcd.hold_ttl", &e.HoldTTL, 15 * time.Second, 5 * time.Second, time.Minute},
     		{"store.etcd.sweep_interval", &e.SweepInterval, 10 * time.Minute, time.Minute, 24 * time.Hour},
     	} {
     		*d.v = orD(*d.v, d.def)
     		if *d.v < d.min || *d.v > d.max {
     			return StoreConfig{}, fmt.Errorf("%s %v: must be %v to %v", d.name, *d.v, d.min, d.max)
     		}
     	}
     	// start_timeout: absent is 30s; 0 is wait forever (pre-flight I19).
     	e.StartTimeout = 30 * time.Second
     	if e.StartTimeoutSet != nil {
     		e.StartTimeout = *e.StartTimeoutSet
     	}
     	if e.StartTimeout != 0 && (e.StartTimeout < 5*time.Second || e.StartTimeout > 10*time.Minute) {
     		return StoreConfig{}, fmt.Errorf("store.etcd.start_timeout %v: must be 0 (wait for as long as it takes), "+
     			"or 5s to 10m", e.StartTimeout)
     	}
     	for _, n := range []struct {
     		name          string
     		v             *int
     		def, min, max int
     	}{
     		{"store.etcd.breaker.failures", &e.Breaker.Failures, 5, 1, 100},
     		{"store.etcd.max_in_flight.token", &e.MaxInFlight.Token, 64, 1, 4096},
     		{"store.etcd.max_in_flight.context", &e.MaxInFlight.Context, 128, 1, 4096},
     		{"store.etcd.max_in_flight.bulk", &e.MaxInFlight.Bulk, 4, 1, 4096},
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

     // readableFile refuses a path that is empty or not a regular file. A
     // private key's mode and owner are keyfile's, at the read (Task 12).
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

     // StoreOf is `store:` from port49d.yaml's bytes, checked as Load checks
     // it (the stale seed keys first, as Load refuses them), for `port49d
     // store-roles`, which reads nothing else (plan 7d; pre-flight M35).
     func StoreOf(raw []byte) (StoreConfig, error) {
     	if err := staleSeedKeys(raw); err != nil {
     		return StoreConfig{}, err
     	}
     	var f fileConfig
     	dec := yaml.NewDecoder(bytes.NewReader(raw))
     	dec.KnownFields(true)
     	if err := dec.Decode(&f); err != nil && err != io.EOF {
     		return StoreConfig{}, fmt.Errorf("config: %w; check the key spelling against the port49d.yaml schema", decodeFault(err))
     	}
     	return checkStore(f.Store, f.Broker != nil, f.AdminSocket != "")
     }
     ```

     Add `net/url` to the imports, and `strings` if it is not there.

- [ ] **Step 3: The packet deadline, and the delay that outlives it.**
  - In `internal/daemon/authen/authen.go`, add:

    ```go
    type delayKey struct{}

    type delayFrom struct {
    	ctx     context.Context
    	arrived time.Time
    }

    // WithDelayContext is ctx carrying delay, the context a failure delay
    // may be ended by, and arrived, when the packet arrived. delay is the
    // server's context, never the packet's: a packet's store.packet_deadline
    // bounds its store work and must not cut the brute-force delay (plan 7d;
    // pre-flight I1). The delay counts from arrived, so the store work it
    // waited on is inside it, not added to it (re-check N1).
    func WithDelayContext(ctx, delay context.Context, arrived time.Time) context.Context {
    	return context.WithValue(ctx, delayKey{}, delayFrom{ctx: delay, arrived: arrived})
    }

    // DelayContext is the context and arrival WithDelayContext put on ctx,
    // or ctx itself and the zero time.
    func DelayContext(ctx context.Context) (context.Context, time.Time) {
    	if d, ok := ctx.Value(delayKey{}).(delayFrom); ok {
    		return d.ctx, d.arrived
    	}
    	return ctx, time.Time{}
    }
    ```

    In `Session.fail` (authen.go:878), replace the timer and its `select` with:

    ```go
    	// The delay counts from the packet's arrival, and sleeps on the
    	// server's context (DelayContext): the store's time is inside it, not
    	// added to it, and a packet deadline does not shorten it (plan 7d;
    	// pre-flight I1; re-check N1). A FAIL therefore arrives at the later of
    	// the store's answer and arrival plus the delay, and each failure still
    	// costs its sender the whole delay from its send. With no arrival (a
    	// caller other than the server) it counts from now, as before.
    	dctx, arrived := DelayContext(ctx)
    	if !arrived.IsZero() {
    		delay -= time.Since(arrived)
    	}
    	if delay > 0 {
    		timer := time.NewTimer(delay)
    		select {
    		case <-timer.C:
    		case <-dctx.Done():
    			timer.Stop()
    		}
    	}
    ```

    The arrival is real time, not the handler's clock, because the sleep is real time.
  - In `internal/daemon/server/server.go`, add to `Deps`, beside `IdleTimeout`:

    ```go
    	// PacketDeadline bounds the store work of one packet (store.packet_deadline;
    	// plan 7d): past it every store call returns, the handler answers
    	// store_unavailable, and the device hears that before its own timeout.
    	// It never shortens the authentication failure delay. Zero is none.
    	PacketDeadline time.Duration
    ```
  - In `conn.go`'s `dispatch`, as its first lines:

    ```go
    	// The failure delay keeps the server's context and counts from now,
    	// the packet's arrival (authen.DelayContext): the deadline is for the
    	// store, never the brute-force delay (re-check N1).
    	delay, arrived := ctx, time.Now()
    	if s.d.PacketDeadline > 0 {
    		var cancel context.CancelFunc
    		ctx, cancel = context.WithTimeout(ctx, s.d.PacketDeadline)
    		defer cancel()
    	}
    	ctx = authen.WithDelayContext(ctx, delay, arrived)
    ```
  - In `cmd/port49d/main.go`, where `deps := server.Deps{…}` is built, add `PacketDeadline:
    cfg.Store.PacketDeadline,`.

- [ ] **Step 4: Run.**

  Run: `go test ./internal/config/ ./internal/daemon/... ./cmd/port49d/ -count=1`
  Expected: PASS. Existing configs carry no `store:`, so they take the memory default and its 2 s
  deadline. That changes no existing test, since none waits 2 s on a store, and no failure delay
  is cut by it.

  Mutation checks (do them, report them, revert them):
  1. In `fail`, sleep on `ctx.Done()` again. `TestThePacketDeadlineNeverShortensTheFailureDelay`
     must fail.
  2. In `fail`, drop the `delay -= time.Since(arrived)`. `TestAFailArrivesAtItsDelay` must
     fail (about 550ms).

- [ ] **Step 5: Commit.**

  ```bash
  gofmt -w internal/config internal/daemon/server internal/daemon/authen cmd/port49d
  make build && make test && make vet
  git add internal/config/config.go internal/config/store_test.go internal/daemon/server/server.go \
    internal/daemon/server/conn.go internal/daemon/server/server_test.go internal/daemon/authen/authen.go \
    cmd/port49d/main.go
  git commit -m "feat(config): store: in port49d.yaml, and every packet's store deadline

  store.backend is memory (default) or etcd; store.packet_deadline (2s,
  at most 2s, L13's Junos timeout) bounds every TACACS+ packet's store
  work, so a device hears store_unavailable before its own timeout and a
  redemption's write lands inside the refresh's 30s settle pass (4b m3).
  The failure delay sleeps on the server's context, is never cut by it,
  and counts from the packet's arrival, so a slow store's time is inside
  it and a FAIL arrives within max(packet_deadline, delay). store.etcd
  refuses plain http, a missing identity, etcd with no broker and etcd
  with no admin_socket; start_timeout 0 waits forever (plan 7d; decision
  35; pre-flight I1, I13, I16, I19; re-check N1).

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

  	clientv3 "go.etcd.io/etcd/client/v3"

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
  		"write meta/":               func() error { _, err := d.ctx.Put(ctx, d.k.meta("hold"), "x"); return unavailable(err) }(),
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
  	// A daemon role that reads no idempotency record but may write a mark
  	// is not separated either: the write probe catches it (pre-flight M32).
  	loose := etcdtest.Start(t, etcdtest.Options{TLS: true})
  	var grants []etcdtest.Grant
  	for _, g := range Roles(prefix) {
  		grants = append(grants, etcdtest.Grant{Role: g.Role, Key: g.Key, RangeEnd: g.RangeEnd, Write: g.Write})
  	}
  	marks := newKeys(prefix).family(famMark)
  	grants = append(grants, etcdtest.Grant{Role: RoleDaemon, Key: marks, RangeEnd: clientv3.GetPrefixRangeEnd(marks), Write: true})
  	loose.EnableAuth(t, grants, map[string][]string{"port49-daemon": {RoleDaemon}, "port49-broker": {RoleBroker}})
  	if err := openAs(t, loose, "port49-daemon", prefix).CheckIdentity(ctx, false); !errors.Is(err, ErrNotSeparated) {
  		t.Fatalf("a daemon that may write a mark: %v", err)
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
  		"etcdctl role grant-permission port49_daemon read --prefix=true /port49/v1/meta/",
  		"etcdctl role grant-permission port49_broker readwrite --prefix=true /port49/v1/",
  		"etcdctl user add port49-daemon --no-password",
  		"etcdctl user grant-role port49-daemon port49_daemon",
  		"etcdctl user grant-role port49-broker port49_broker",
  	} {
  		if !strings.Contains(out.String(), want) {
  			t.Errorf("missing %q in:\n%s", want, out.String())
  		}
  	}
  	for _, never := range []string{"/port49/v1/id/", "/port49/v1/meta/", "/port49/v1/rv/", "/port49/v1/tp/", "/port49/v1/tc/"} {
  		if strings.Contains(out.String(), "port49_daemon readwrite --prefix=true "+never) {
  			t.Errorf("the daemon is granted write on %s", never)
  		}
  	}
  }

  // A CN or prefix holding anything a shell would read is refused, never
  // printed into commands etcd's root runs (pre-flight M34).
  func TestStoreRolesRefusesAShellUnsafeName(t *testing.T) {
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
  	for _, cn := range []string{"port49-daemon; rm -rf /", "port49-broker"} {
  		c, err := ca.Issue(testpki.Leaf{CommonName: cn, Client: true, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
  		if err != nil {
  			t.Fatal(err)
  		}
  		cp, kp, _ := testpki.PEMs(c)
  		name := strings.NewReplacer(" ", "_", ";", "_", "/", "_").Replace(cn)
  		ids[cn] = [2]string{write(name+".pem", cp), write(name+"-key.pem", kp)}
  	}
  	cfg := writeStoreRolesConfig(t, dir, write("ca.pem", ca.PEM()), ids["port49-daemon; rm -rf /"], ids["port49-broker"])
  	var out, errb bytes.Buffer
  	if code := storeRolesCmd([]string{"--config", cfg}, &out, &errb); code != 1 || out.Len() != 0 ||
  		!strings.Contains(errb.String(), "A-Za-z0-9") {
  		t.Fatalf("exit %d, stdout %q, stderr %q", code, out.String(), errb.String())
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
  		"    broker: {cert_file: "+b[0]+", key_file: "+b[1]+"}\n"+
  		"admin_socket: "+filepath.Join(dir, "admin.sock")+"\n")...) // etcd needs one (Task 10, I16)
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
  // compares and the keyspace's meta records; it cannot write a mark, read
  // or write an idempotency record (which holds minted tokens), write the
  // token index, or write meta/ — so a stolen daemon key cannot delete the
  // keyspace hold (pre-flight I15) or the seal-key record. The broker holds
  // the keyspace. What a stolen daemon key can still do to a token, a
  // receipt or a context is bounded by the seals, the ledger and the marks,
  // record family by record family (Ruling 17's table).
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
  		famBySid, famByCert, famBlob} {
  		p := k.family(fam)
  		out = append(out, Grant{Role: RoleDaemon, Key: p, RangeEnd: clientv3.GetPrefixRangeEnd(p), Write: true})
  	}
  	for _, fam := range []string{famMark, famMeta} {
  		p := k.family(fam)
  		out = append(out, Grant{Role: RoleDaemon, Key: p, RangeEnd: clientv3.GetPrefixRangeEnd(p)})
  	}
  	out = append(out, Grant{Role: RoleBroker, Key: k.root, RangeEnd: clientv3.GetPrefixRangeEnd(k.root), Write: true})
  	return out
  }

  // ErrNotSeparated is the daemon's identity able to do what only the
  // broker's may: etcd's roles for port49 are not in force.
  var ErrNotSeparated = errors.New("etcd: the daemon's identity has the broker's reach")

  // CheckIdentity is port49d's start check that the roles are in force.
  // Both identities must read the contexts. The broker's must be allowed,
  // and the daemon's refused, each of: reading the idempotency records, and
  // writing a mark, the token index, an idempotency record and meta/. A
  // write is probed by a transaction whose compare can never hold, so it
  // writes nothing; etcd checks the permissions of both branches before it
  // evaluates the compare, so a missing grant is still refused (pre-flight
  // M32).
  func (s *Store) CheckIdentity(ctx context.Context, broker bool) error {
  	read := func(fam string) error {
  		_, err := s.tok.Get(ctx, s.k.family(fam), clientv3.WithPrefix(), clientv3.WithLimit(1), clientv3.WithKeysOnly())
  		return unavailable(err)
  	}
  	write := func(fam string) error {
  		key := s.k.family(fam) + "_probe"
  		_, err := s.tok.Txn(ctx).If(clientv3.Compare(clientv3.CreateRevision(key), "<", 0)).
  			Then(clientv3.OpPut(key, "")).Commit()
  		return unavailable(err)
  	}
  	if err := read(famContext); err != nil {
  		return fmt.Errorf("reading %s: %w", s.k.family(famContext), err)
  	}
  	probes := []struct {
  		what string
  		do   func() error
  	}{
  		{"reading " + s.k.family(famIdem), func() error { return read(famIdem) }},
  		{"writing " + s.k.family(famIdem), func() error { return write(famIdem) }},
  		{"writing " + s.k.family(famMark), func() error { return write(famMark) }},
  		{"writing " + s.k.family(famTokByPrin), func() error { return write(famTokByPrin) }},
  		{"writing " + s.k.family(famTokByCert), func() error { return write(famTokByCert) }},
  		{"writing " + s.k.family(famMeta), func() error { return write(famMeta) }},
  	}
  	for _, p := range probes {
  		err := p.do()
  		switch {
  		case broker && err != nil:
  			return fmt.Errorf("%s: %w", p.what, err)
  		case !broker && err == nil:
  			return fmt.Errorf("%w: it was allowed %s", ErrNotSeparated, p.what)
  		case !broker && !errors.Is(err, ErrRefused):
  			return fmt.Errorf("%s: %w", p.what, err) // an outage: the start waits
  		}
  	}
  	return nil
  }
  ```

  Check against v3.6.15 that a refused `Then` branch fails a transaction whose compare is false.
  The reviewer measured that etcd checks both branches' permissions; if the implementer measures
  otherwise, probe a write with a real `Put` of `<family>_probe` followed by a `Delete`, and say
  so in the report.

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
  	"strings"

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
  	// The output is run by etcd's root in a shell: a name that holds
  	// anything a shell reads is refused, never quoted into it (pre-flight
  	// M34).
  	for what, v := range map[string]string{"the daemon certificate's CN": users[etcdstore.RoleDaemon],
  		"the broker certificate's CN": users[etcdstore.RoleBroker], "store.etcd.prefix": sc.Etcd.Prefix} {
  		if !shellSafe(v) {
  			fmt.Fprintf(stderr, "port49d store-roles: %s %q holds a character outside [A-Za-z0-9._@/-]; "+
  				"nothing printed\n", what, v)
  			return 1
  		}
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

  // shellSafe reports whether s is non-empty and every byte of it is one of
  // [A-Za-z0-9._@/-], which a POSIX shell passes as one word unread.
  func shellSafe(s string) bool {
  	if s == "" {
  		return false
  	}
  	for _, r := range s {
  		switch {
  		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune("._@/-", r):
  		default:
  			return false
  		}
  	}
  	return true
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
  [--config FILE], or port49d store-roles [--config FILE] (a subcommand comes first)`. `main`'s
  comment "The one subcommand, before the daemon's flags" becomes "The subcommands, before the
  daemon's flags: each reads port49d.yaml and starts nothing" (pre-flight M35).

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
  touch an idempotency record, write the token index, or write meta/.
  CheckIdentity is the start check, probing the reads and the writes;
  port49d store-roles prints the etcdctl commands, refusing a name a
  shell would read (design §17; decision 35).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 12: port49d runs on etcd: the hold, the start, the marks at start, going dark, and live sessions across a restart

**Files:**
- Create: `internal/store/etcd/meta.go` (`Hold` and its fence)
- Test: `internal/store/etcd/meta_test.go`
- Create: `cmd/port49d/store.go`
- Test: `cmd/port49d/store_test.go` (`identity`, `probeTLS`)
- Modify: `cmd/port49d/main.go`
- Modify: `internal/broker/broker.go` (`SupersededAll`), `internal/broker/refresh.go`
  (`ApplyMarksAtStart`, `RefreshAtStart`, `RefreshReport.Contexts`)
- Test: `internal/broker/refresh_test.go`, `cmd/port49d/store_e2e_test.go`
- Modify: `internal/daemon/server/server.go` (`Deps.Abort`: a reset on a store gone)
- Modify: `internal/daemon/metrics/metrics.go`, `metrics_test.go` (`StoreKeyspaceHeld`,
  `StoreCertExpiry`)

**Interfaces:**
- Consumes: everything from Tasks 4b–11, `crypt.NewLedger` and `crypt.WithLedger` (4b),
  `(*etcd.Store).Unindexed` and `Broker.ReindexContexts` (7b); `internal/keyfile.LoadX509KeyPair`.
- Produces:
  - `func (s *etcd.Store) Hold(ctx context.Context, ttl time.Duration, who string, waiting func(holder string)) (lost <-chan struct{}, release func(), err error)`
  - In `cmd/port49d`:
    - `type stores struct { daemon, broker store.Store; etcd *etcdstore.Store; persistent bool; lost <-chan struct{}; close func() }`;
    - `func openStores(ctx context.Context, cfg config.Config, keys crypt.Keys, m *metrics.Metrics, out io.Writer, rd *readiness, again bool, gone func(error)) (stores, error)`;
    - `type storeGone struct{ why string }`, `type storeFault struct{ err error }`;
    - `func identity(name string, id config.EtcdIdentity, pool *x509.CertPool, now time.Time) (*tls.Config, *x509.Certificate, error)`;
    - `func probeTLS(ctx context.Context, endpoints []string, tc *tls.Config, timeout time.Duration) error`;
    - `func startOnPersistentStore(ctx context.Context, brk *broker.Broker, st store.Store, e *etcdstore.Store, cfg config.Config, marks *[]store.Revocation, m *metrics.Metrics) error`;
    - `func sweepLoop(ctx context.Context, s *etcdstore.Store, brk *broker.Broker, every time.Duration, out io.Writer)`;
    - `func runOnce(parent context.Context, cfgPath string, hup <-chan os.Signal, again bool) (err error)`;
      `func runLoop(parent context.Context, once func(again bool) error, every time.Duration) error`;
      `run` calls `runLoop` over `runOnce`.
  - `server.Deps.Abort func() bool`
  - `Broker.SupersededAll time.Time`; `func (b *Broker) ApplyMarksAtStart(ctx context.Context, marks []store.Revocation) (int, error)`;
    `func (b *Broker) RefreshAtStart(ctx context.Context) (RefreshReport, error)`; `func (r RefreshReport) Contexts() int`
  - `Metrics.StoreKeyspaceHeld` (`port49_store_keyspace_held`), `Metrics.StoreCertExpiry`
    (`port49_store_client_cert_expiry_timestamp_seconds{component}`)

- [ ] **Step 1: The hold's failing tests.** Create `internal/store/etcd/meta_test.go`:

  ```go
  package etcd

  import (
  	"context"
  	"errors"
  	"strings"
  	"testing"
  	"time"

  	clientv3 "go.etcd.io/etcd/client/v3"

  	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
  )

  // One port49d per keyspace: a second Hold waits, saying who holds it,
  // until the first lets go; and a hold whose store stops answering is lost
  // at least a sixth of its TTL before etcd can expire the lease and the
  // second take it (Ruling 11; pre-flight I15; re-check R-I4; Review Focus
  // 4). That margin, 0.83s at a 5s TTL, plus etcd's own lease-expiry
  // granularity, is what keeps the ordering assertion below from racing.
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
  	ctx, cancel := context.WithCancel(context.Background())
  	defer cancel()
  	lost, release, err := first.Hold(ctx, 5*time.Second, "port49d one", func(string) {})
  	if err != nil {
  		t.Fatal(err)
  	}
  	waited := make(chan string, 4)
  	got := make(chan error, 1)
  	tookAt := make(chan time.Time, 1)
  	go func() {
  		_, rel, err := second.Hold(ctx, 5*time.Second, "port49d two", func(h string) { waited <- h })
  		tookAt <- time.Now()
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
  	var lostAt time.Time
  	select {
  	case <-lost:
  		lostAt = time.Now()
  	case <-time.After(15 * time.Second):
  		t.Fatal("the first's hold did not lapse")
  	}
  	select { // pre-flight M38: never an unbounded receive
  	case err := <-got:
  		if err != nil {
  			t.Fatalf("the second, once the first lapsed: %v", err)
  		}
  	case <-time.After(20 * time.Second):
  		t.Fatal("the second never took the keyspace")
  	}
  	if took := <-tookAt; took.Before(lostAt) {
  		t.Fatalf("the second took the keyspace at %v, before the first knew it had lost it at %v", took, lostAt)
  	}
  	proxy.Hang(false)
  	release()
  }

  // A hold whose lock key is deleted (an operator "unsticking" it, or
  // etcdctl del --prefix) is lost at the next read, never left serving
  // beside another (pre-flight I15).
  func TestTheHoldIsLostWhenItsKeyIsDeleted(t *testing.T) {
  	s := onShared(t, func() time.Time { return t0 })
  	ctx := context.Background()
  	lost, release, err := s.Hold(ctx, 6*time.Second, "port49d one", func(string) {})
  	if err != nil {
  		t.Fatal(err)
  	}
  	defer release()
  	if _, err := s.ctx.Delete(ctx, s.k.meta("hold"), clientv3.WithPrefix()); err != nil {
  		t.Fatal(err)
  	}
  	select {
  	case <-lost:
  	case <-time.After(5 * time.Second):
  		t.Fatal("a hold whose key was deleted was not lost")
  	}
  }

  // A slow but healthy store keeps the hold: each fence read answers late,
  // inside its ttl/6 deadline, and the lease's keepalives land, so the
  // TTL each read reports is above ttl/2 at its send (8b re-review R-M2).
  // Judged when the read returns instead, a read slower than
  // floor(2*ttl/3) - ttl/2 (0.5s at 5s) would drop the hold.
  func TestASlowAnsweredReadKeepsTheHold(t *testing.T) {
  	srv := etcdtest.Start(t, etcdtest.Options{})
  	proxy := etcdtest.NewProxy(t, strings.TrimPrefix(srv.Endpoint, "http://"))
  	s, err := Open(Config{Endpoints: []string{"http://" + proxy.Addr()}, Prefix: etcdtest.Prefix()})
  	if err != nil {
  		t.Fatal(err)
  	}
  	defer s.Close()
  	ctx, cancel := context.WithCancel(context.Background())
  	defer cancel()
  	lost, release, err := s.Hold(ctx, 5*time.Second, "port49d one", func(string) {})
  	if err != nil {
  		t.Fatal(err)
  	}
  	defer release()
  	// Each fence read (a Get and a TimeToLive) then answers in about 0.6s:
  	// over the 0.5s that judging at the return would allow, under the
  	// read's 0.83s deadline.
  	proxy.Delay(150 * time.Millisecond)
  	select {
  	case <-lost:
  		t.Fatal("a slow but healthy store lost the hold")
  	case <-time.After(15 * time.Second):
  	}
  }

  // The daemon's identity cannot take the hold: meta/ is the broker's to
  // write (Ruling 10; pre-flight I15).
  func TestTheDaemonCannotTakeTheHold(t *testing.T) {
  	const prefix = "/port49/"
  	srv := provisioned(t, prefix)
  	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
  	defer cancel()
  	if _, _, err := openAs(t, srv, "port49-daemon", prefix).Hold(ctx, 5*time.Second, "x", func(string) {}); !errors.Is(err, ErrRefused) {
  		t.Fatalf("the daemon took the hold: %v", err)
  	}
  	lost, release, err := openAs(t, srv, "port49-broker", prefix).Hold(ctx, 5*time.Second, "x", func(string) {})
  	if err != nil {
  		t.Fatalf("the broker could not take the hold: %v", err)
  	}
  	_ = lost
  	release()
  }
  ```

  Run: `go test ./internal/store/etcd/ -run 'TestHold|TestTheHold|TestASlowAnsweredReadKeepsTheHold|TestTheDaemonCannotTakeTheHold' -count=1`
  Expected: FAIL to build (`Hold` undefined).

  In `TestASlowAnsweredReadKeepsTheHold`, measure the fence's read time once under the delay and
  tune `Delay` until each read answers between 0.5s and 0.8s. Report the value you used.

- [ ] **Step 2: The hold and its fence.** Create `internal/store/etcd/meta.go`:

  ```go
  package etcd

  import (
  	"context"
  	"encoding/json"
  	"errors"
  	"sync"
  	"time"

  	clientv3 "go.etcd.io/etcd/client/v3"
  	"go.etcd.io/etcd/client/v3/concurrency"
  )

  type holderRec struct {
  	Who string `json:"who"`
  }

  // Hold takes the keyspace for one port49d (plan 7d, Ruling 11): a lock
  // under meta/hold on an etcd session lease of ttl, with who written
  // beside it under meta/holder. port49d takes it as the broker: the
  // daemon's role cannot write meta/. While another holds it, Hold waits,
  // telling waiting the holder's who every 30s, until ctx ends.
  //
  // lost is closed when the hold is gone (pre-flight I15; re-check R-I4):
  // the lock key deleted or on another lease, the lease expired, the
  // session ended, or etcd not answering with half of ttl or less left on
  // the lease as last reported. That is before etcd can expire the lease
  // and let another port49d take the keyspace. The session's
  // keepalive is its own, not ctx's, so a shutdown is not a loss. release
  // lets go: it unlocks and revokes the lease, unless the hold was lost,
  // when it does neither, since the store may not answer and the lease is
  // gone or going (pre-flight M49).
  func (s *Store) Hold(ctx context.Context, ttl time.Duration, who string, waiting func(holder string)) (<-chan struct{}, func(), error) {
  	sctx, scancel := context.WithCancel(context.Background())
  	sess, err := concurrency.NewSession(s.ctx, concurrency.WithTTL(int(ttl/time.Second)), concurrency.WithContext(sctx))
  	if err != nil {
  		scancel()
  		return nil, nil, unavailable(err)
  	}
  	quit := func() { sess.Close(); scancel() }
  	mu := concurrency.NewMutex(sess, s.k.meta("hold"))
  	var said time.Time
  	for {
  		err := mu.TryLock(ctx)
  		if err == nil {
  			break
  		}
  		if !errors.Is(err, concurrency.ErrLocked) {
  			quit()
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
  			quit()
  			return nil, nil, ctx.Err()
  		case <-time.After(time.Second):
  		}
  	}
  	body, err := json.Marshal(holderRec{Who: who})
  	if err != nil {
  		quit()
  		return nil, nil, err
  	}
  	if _, err := s.ctx.Put(ctx, s.k.meta("holder"), string(body), clientv3.WithLease(sess.Lease())); err != nil {
  		quit()
  		return nil, nil, unavailable(err)
  	}
  	lost := make(chan struct{})
  	var once sync.Once
  	lose := func() { once.Do(func() { close(lost) }) }
  	fctx, stop := context.WithCancel(context.Background())
  	go s.fence(fctx, sess, mu.Key(), ttl, lose)
  	return lost, func() {
  		stop()
  		select {
  		case <-lost:
  			sess.Orphan()
  		default:
  			uctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
  			mu.Unlock(uctx)
  			cancel()
  			sess.Close()
  		}
  		scancel()
  	}, nil
  }

  // fence is the hold's watch (pre-flight I15; re-check R-I4). Every sixth
  // of ttl it reads the lock key, linearizably, and the lease's remaining
  // TTL. A key gone, or on a lease not this session's, is a hold lost at
  // once: an operator deleted it, or the lease was reclaimed. A lease
  // expired, or the session ending, is one too.
  //
  // expires is when the lease expires at the latest by the last answer:
  // its send time plus the TTL it reported, which etcd counted after the
  // send, so never later than etcd's own. An answered read is judged at
  // its send time: the hold is lost when the TTL it reported is half of ttl
  // or less (the keepalives stalled while reads answer; re-check 2 M-B7),
  // never by how long the read took, so a slow but healthy read keeps it
  // (8b re-review R-M2). With the reads not answering, it is lost once
  // expires has half of ttl or less left. Reads are at
  // most ttl/3 apart (a tick, then a read up to ttl/6 long), so the loss
  // comes at least ttl/6 before etcd can expire the lease and a second
  // port49d take the keyspace. Stamping at the send, and reading the TTL
  // rather than counting from the last answer, is what keeps that margin:
  // the lease's last keepalive can be up to ttl/3 older than the last
  // answered read. A process paused past that is the residual: its next
  // read finds the key gone.
  func (s *Store) fence(ctx context.Context, sess *concurrency.Session, key string, ttl time.Duration, lose func()) {
  	every := ttl / 6
  	// The lock was just taken on this lease, which the session keeps alive
  	// every ttl/3: at least two thirds of ttl is left.
  	expires := time.Now().Add(2 * ttl / 3)
  	t := time.NewTicker(every)
  	defer t.Stop()
  	for {
  		select {
  		case <-ctx.Done():
  			return
  		case <-sess.Done():
  			lose()
  			return
  		case <-t.C:
  		}
  		sent := time.Now()
  		rctx, cancel := context.WithTimeout(ctx, every)
  		resp, err := s.ctx.Get(rctx, key)
  		var left *clientv3.LeaseTimeToLiveResponse
  		if err == nil {
  			left, err = s.ctx.TimeToLive(rctx, sess.Lease())
  		}
  		cancel()
  		switch {
  		case ctx.Err() != nil:
  			return
  		case err == nil && (len(resp.Kvs) == 0 || clientv3.LeaseID(resp.Kvs[0].Lease) != sess.Lease() || left.TTL <= 0):
  			lose()
  			return
  		case err == nil && time.Duration(left.TTL)*time.Second <= ttl/2:
  			lose()
  			return
  		case err == nil:
  			expires = sent.Add(time.Duration(left.TTL) * time.Second)
  		case time.Until(expires) <= ttl/2:
  			lose()
  			return
  		}
  	}
  }
  ```

  `TimeToLive`'s `TTL` is whole seconds, rounded down, which only moves the estimate earlier.
  At the smallest `hold_ttl` (5 s) a healthy lease reports at least 3 s, above the 2.5 s line,
  however long the read took to answer, since an answered read is judged at its send.

  Check `concurrency.WithContext` and `Session.Orphan` in v3.6.15's `concurrency` package (the
  pre-flight review compiled `WithContext`). If a name differs, use what the package offers, as
  Global Constraints allow.

  Run: `go test ./internal/store/etcd/ -run 'TestHold|TestTheHold|TestASlowAnsweredReadKeepsTheHold|TestTheDaemonCannotTakeTheHold' -count=1` — PASS.

  Mutation checks (do them, report them, revert them):
  1. In `fence`, drop the key-gone case. `TestTheHoldIsLostWhenItsKeyIsDeleted` must fail.
  2. In `fence`, declare the loss at `time.Until(expires) <= 0` instead of `ttl/2`.
     `TestHoldIsOnePerKeyspaceAndLapses` must fail, or report that it raced; report which.
  3. In `fence`, judge an answered read when it returns (set `expires`, then check
     `time.Until(expires) <= ttl/2` after every read). `TestASlowAnsweredReadKeepsTheHold` must
     fail.

- [ ] **Step 3: The broker's start, failing first.** In `internal/broker/refresh_test.go`, add:

  ```go
  // RefreshAtStart carries the policy in force into a context a persistent
  // store kept across a restart, whatever bundle it was written under: a
  // narrowing reaches it before TACACS+ binds (plan 7d, Ruling 12).
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

  // A start applies every standing mark to the contexts a persistent store
  // kept, before any listener binds: a mark added to the revocations file
  // with port49d stopped, or a revocation whose passes an outage cut short,
  // reaches the session it was meant for (plan 7d; pre-flight C1).
  func TestApplyMarksAtStartRevokesAKeptContext(t *testing.T) {
  	f := newFixtureWithPolicy(t, 8, sharedPolicy)
  	ctx := context.Background()
  	f.liveContext(t, "leaf1", "alice", alicePrincipal, store.CertKey("CN=Corp CA", "0a"))
  	f.liveContext(t, "leaf2", "alice", alicePrincipal, store.CertKey("CN=Corp CA", "0b"))
  	n, err := f.b.ApplyMarksAtStart(ctx, []store.Revocation{
  		{Kind: store.RevocationCert, Key: store.CertKey("CN=Corp CA", "0b"), At: f.now},
  	})
  	if err != nil || n != 1 {
  		t.Fatalf("ApplyMarksAtStart = %d, %v; want the one context the certificate reaches", n, err)
  	}
  	one, _ := f.st.GetContext(ctx, store.ContextKey{NAS: "leaf1", Username: "alice"})
  	two, _ := f.st.GetContext(ctx, store.ContextKey{NAS: "leaf2", Username: "alice"})
  	if !one.RevokedAt.IsZero() || two.RevokedAt.IsZero() {
  		t.Fatalf("leaf1 revoked %v (want no), leaf2 revoked %v (want yes)", one.RevokedAt, two.RevokedAt)
  	}
  	if n, err := f.b.ApplyMarksAtStart(ctx, []store.Revocation{
  		{Kind: store.RevocationPrincipal, Key: alicePrincipal, At: f.now},
  	}); err != nil || n != 2 {
  		t.Fatalf("by principal: %d %v", n, err)
  	}
  }

  // A kept context that will not open (sealed under a key this window
  // lacks) under a certificate mark is still marked, since a revocation
  // needs no key, and never fails the start: it is denied as unreadable
  // anyway (re-check R-I3).
  func TestApplyMarksAtStartSkipsAnUnreadableContext(t *testing.T) {
  	f := newFixtureWithPolicy(t, 8, sharedPolicy)
  	ctx := context.Background()
  	f.liveContext(t, "leaf1", "alice", alicePrincipal, store.CertKey("CN=Corp CA", "0a"))
  	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
  	f.b.Sessions = session.New(unreadableAt{Store: f.st, k: k}, f.b.Now, time.Hour, time.Hour)
  	n, err := f.b.ApplyMarksAtStart(ctx, []store.Revocation{
  		{Kind: store.RevocationCert, Key: store.CertKey("CN=Corp CA", "0a"), At: f.now},
  	})
  	if err != nil || n != 1 {
  		t.Fatalf("ApplyMarksAtStart = %d, %v; want the unreadable context marked and no error", n, err)
  	}
  	if got, _ := f.st.GetContext(ctx, k); got.RevokedAt.IsZero() {
  		t.Fatal("the unreadable context was not marked")
  	}
  }
  ```

  `unreadableAt` is Task 7b's (`reindex_test.go`, the same package). Build the session manager
  as 7a's revoke tests do if `session.New`'s arguments there differ.

  The fixture names (`newFixtureWithPolicy`, `liveContext`, `sharedPolicy`, `alicePrincipal`,
  `f.st`, `f.b`, `f.now`) are 7c's (`internal/broker/fixture_test.go`). `liveContext`'s fifth
  argument is a certificate key (fixture_test.go:161), and it indexes the context under it. If
  the fixture leaves `f.b.Sessions` nil, set it as 7a's revoke tests do.

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

  // ApplyMarksAtStart runs 7a's two context passes for every standing mark
  // (plan 7d; pre-flight C1). On the memory store a restart lost every
  // context, so a mark never had a kept context to miss. On a store that
  // persists, a start keeps contexts a revocation never reached: a mark
  // added to broker.revocations_file with port49d stopped, or a revocation
  // whose passes an outage cut short. It touches no token (the start purges
  // them) and no connection (none is held yet). It reports how many
  // contexts it marked, and its first outage, for the caller to run it
  // again; a mark it could not apply is still denied by the daemon's marks.
  //
  // Only an outage is returned (re-check R-I3). A context that will not
  // open, sealed under a key this window lacks, is still marked (session.mark
  // marks what it cannot read, since a revocation needs no key), and is
  // denied as unreadable anyway; returned, it would fail every start until
  // that context's TTL ran out. Any other error is said and skipped for the
  // same reason: the daemon's marks deny that context on every request.
  func (b *Broker) ApplyMarksAtStart(ctx context.Context, marks []store.Revocation) (int, error) {
  	if b.Sessions == nil {
  		return 0, errors.New("broker: revocation is not wired (no session manager); the standing marks were not applied")
  	}
  	reached := map[store.ContextRef]bool{}
  	var first error
  	var kind string
  	note := func(err error) {
  		var unreadable *store.UnreadableContextError
  		switch {
  		case err == nil, errors.Is(err, store.ErrNotFound), errors.As(err, &unreadable):
  		case errors.Is(err, store.ErrUnavailable):
  			if first == nil {
  				first = err
  			}
  		default:
  			b.logf("broker: a standing %s revocation was not applied to every kept context (%v); the daemon's marks "+
  				"deny those contexts on every request regardless", kind, err)
  		}
  	}
  	for _, r := range marks {
  		kind = r.Kind
  		for pass := 0; pass < 2; pass++ {
  			var refs []store.ContextRef
  			var err error
  			switch r.Kind {
  			case store.RevocationPrincipal:
  				refs, err = b.Sessions.RevokeByPrincipal(ctx, r.Key)
  			case store.RevocationCert:
  				i := strings.LastIndexByte(r.Key, '|')
  				if i < 0 {
  					continue // CheckRevocation refused such a key; nothing names it
  				}
  				refs, err = b.Sessions.RevokeByCert(ctx, r.Key[:i], r.Key[i+1:])
  			}
  			note(err)
  			for _, ref := range refs {
  				reached[ref] = true
  			}
  		}
  	}
  	return len(reached), first
  }
  ```

  Add `"errors"` and `"strings"` to `refresh.go`'s imports if absent.

  The log line names the mark's kind, never its key: a certificate key or a principal is an
  identity, and the line needs only to say a mark was not applied. Add `"github.com/rhwendt/port49/internal/session"`
  and `"time"` to `refresh_test.go`'s imports if absent.

  Run: `go test ./internal/broker/ -run 'TestRefreshAtStart|TestApplyMarksAtStart' -count=1` —
  PASS.

  Mutation check (do it, report it, revert it): in `note`, return an `UnreadableContextError`
  as `first`. `TestApplyMarksAtStartSkipsAnUnreadableContext` must fail. A test that mints with `SupersededAll` set and replays is added in Step 6's end-to-end
  test, where it is observable.

- [ ] **Step 4: The metrics.** In `metrics.go`, add:

  ```go
  	// StoreKeyspaceHeld is 1 while this port49d holds its keyspace on etcd
  	// (plan 7d): 0 while it waits for another or for the store, and alarmed
  	// when port49d runs with it 0.
  	StoreKeyspaceHeld prometheus.Gauge
  	// StoreCertExpiry is each component's etcd client certificate's
  	// NotAfter, in Unix seconds (plan 7d; pre-flight I9), as
  	// port49_crl_next_update_timestamp_seconds is: an alert subtracts now.
  	StoreCertExpiry *prometheus.GaugeVec
  ```

  with `prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_store_keyspace_held", Help: "1 while
  this port49d holds its keyspace on etcd."})` and
  `prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "port49_store_client_cert_expiry_timestamp_seconds",
  Help: "When each component's etcd client certificate expires, in Unix seconds."},
  []string{"component"})`, registered, and both named in `TestNewRegistersEveryMetric`.

- [ ] **Step 5: `openStores`, the identities, and the start's order.** Create `cmd/port49d/store.go`:

  ```go
  package main

  import (
  	"context"
  	"crypto/tls"
  	"crypto/x509"
  	"encoding/pem"
  	"errors"
  	"fmt"
  	"io"
  	"net/url"
  	"os"
  	"strings"
  	"time"

  	"github.com/rhwendt/port49/internal/broker"
  	"github.com/rhwendt/port49/internal/config"
  	"github.com/rhwendt/port49/internal/daemon/metrics"
  	"github.com/rhwendt/port49/internal/keyfile"
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
  	// etcd is the daemon's backend, for the sweep. Nil on memory.
  	etcd       *etcdstore.Store
  	persistent bool
  	// lost is closed when this port49d loses its hold on the keyspace;
  	// nil on memory, where nothing is lost.
  	lost  <-chan struct{}
  	close func()
  }

  // storeGone ends one run of port49d on etcd (Ruling 11; pre-flight I10,
  // I19): the hold was lost, or a pool's store has failed or refused every
  // call for hold_ttl. run then starts the next, which waits for the store
  // with every listener closed, as at a start.
  type storeGone struct{ why string }

  func (g *storeGone) Error() string { return "store: " + g.why }

  // storeFault is a store configuration port49d cannot start on: an expired
  // or wrong certificate, a CA that does not verify, a key file keyfile
  // refuses, roles not in force. Waiting does not mend it, unlike
  // store.ErrUnavailable. A cold start exits on it; a start after a store
  // gone says it and tries again, re-reading the files, so a renewed
  // certificate or applied roles are picked up (Ruling 12; pre-flight I9,
  // M33).
  type storeFault struct{ err error }

  func (f *storeFault) Error() string { return f.err.Error() }
  func (f *storeFault) Unwrap() error { return f.err }

  // readyStore is /readyz while port49d waits for the store.
  const readyStore = "waiting for the store: the TACACS+ listener stays closed until etcd answers (plan 7d)"

  // openStores builds the stores cfg names. On etcd it waits for the store
  // with every listener still closed (none is bound yet): up to
  // start_timeout on a cold start (0 is for as long as it takes), and with
  // no deadline when again says this run follows a store gone. Then it
  // takes the hold, waiting for another port49d to let go. gone is how the
  // guard ends the run. It says each step on out.
  func openStores(ctx context.Context, cfg config.Config, keys crypt.Keys, m *metrics.Metrics, out io.Writer,
  	rd *readiness, again bool, gone func(error)) (stores, error) {
  	if cfg.Store.Backend != config.BackendEtcd {
  		st := crypt.Wrap(memory.New(time.Now), keys, m.CryptOpenFailures)
  		return stores{daemon: st, broker: st, close: func() {}}, nil
  	}
  	e := cfg.Store.Etcd
  	rd.set(readyStore)
  	eps := strings.Join(e.Endpoints, ", ")
  	var deadline time.Time
  	if !again && e.StartTimeout > 0 {
  		deadline = time.Now().Add(e.StartTimeout)
  	}
  	var d, b *etcdstore.Store
  	for {
  		var err error
  		d, b, err = attempt(ctx, cfg, m, out)
  		if err == nil {
  			break
  		}
  		if ctx.Err() != nil {
  			return stores{}, ctx.Err()
  		}
  		var fault *storeFault
  		switch {
  		case errors.As(err, &fault) && !again:
  			return stores{}, err // the operator's to fix; named, exit 1
  		case errors.As(err, &fault):
  			fmt.Fprintf(out, "port49d: %v; the listeners stay closed; trying again in 5s\n", err)
  		case !deadline.IsZero() && time.Now().After(deadline):
  			return stores{}, fmt.Errorf("store: etcd at %s did not answer within store.etcd.start_timeout (%v); not "+
  				"starting", eps, e.StartTimeout)
  		default:
  			wait := "until it answers"
  			if !deadline.IsZero() {
  				wait = fmt.Sprintf("up to %v", e.StartTimeout)
  			}
  			fmt.Fprintf(out, "port49d: store: etcd at %s not answering (%v); the listeners stay closed; waiting %s\n",
  				eps, err, wait)
  		}
  		select {
  		case <-ctx.Done():
  			return stores{}, ctx.Err()
  		case <-time.After(5 * time.Second):
  		}
  	}
  	closeAll := func() { b.Close(); d.Close() }
  	if e.Roles == config.RolesUnenforced {
  		fmt.Fprintln(out, "port49d: store.etcd.roles: unenforced: the daemon and the broker are not separated on etcd; "+
  			"a stolen daemon key can lift revocations")
  	}
  	host, _ := os.Hostname()
  	who := fmt.Sprintf("port49d on %s (pid %d, since %s)", host, os.Getpid(), time.Now().UTC().Format(time.RFC3339))
  	m.StoreKeyspaceHeld.Set(0)
  	var lost <-chan struct{}
  	var release func()
  	for {
  		var err error
  		lost, release, err = b.Hold(ctx, e.HoldTTL, who, func(holder string) {
  			fmt.Fprintf(out, "port49d: store: keyspace %s is held by %s; waiting, with the listeners closed: one "+
  				"port49d per keyspace until plan 7e; stop that port49d to move the keyspace, and never delete "+
  				"meta/hold\n", e.Prefix, holder)
  		})
  		if err == nil {
  			break
  		}
  		if ctx.Err() != nil || !errors.Is(err, store.ErrUnavailable) {
  			closeAll()
  			if ctx.Err() != nil {
  				return stores{}, ctx.Err()
  			}
  			return stores{}, fmt.Errorf("store: taking keyspace %s: %w", e.Prefix, err)
  		}
  		fmt.Fprintf(out, "port49d: store: taking keyspace %s: %v; the listeners stay closed; trying again in 5s\n",
  			e.Prefix, err)
  		select {
  		case <-ctx.Done():
  			closeAll()
  			return stores{}, ctx.Err()
  		case <-time.After(5 * time.Second):
  		}
  	}
  	m.StoreKeyspaceHeld.Set(1)
  	gc := func(component string) guard.Config {
  		return guard.Config{Component: component, CallTimeout: e.CallTimeout, BulkTimeout: e.BulkTimeout,
  			MaxInFlight: map[guard.Pool]int{guard.Token: e.MaxInFlight.Token, guard.Context: e.MaxInFlight.Context,
  				guard.Bulk: e.MaxInFlight.Bulk},
  			Failures: e.Breaker.Failures, OpenFor: e.Breaker.OpenFor, Metrics: m.StoreGuard(),
  			StopAfter: e.HoldTTL, Unhealthy: func(why string) { gone(&storeGone{why: why}) },
  			Say:       func(l string) { fmt.Fprintln(out, l) }}
  	}
  	// One ledger for both layers (re-check IA1): the broker's reads at
  	// start seed it for the daemon's, and either denies another login's
  	// context written back.
  	ledger := crypt.WithLedger(crypt.NewLedger())
  	return stores{
  		daemon:     crypt.Wrap(guard.Wrap(d, gc("daemon")), keys, m.CryptOpenFailures, ledger),
  		broker:     crypt.Wrap(guard.Wrap(b, gc("broker")), keys, m.CryptOpenFailures, ledger),
  		etcd:       d,
  		persistent: true,
  		lost:       lost,
  		close:      func() { release(); m.StoreKeyspaceHeld.Set(0); closeAll() },
  	}, nil
  }

  // attempt is one try at the store, as a start-wait loop runs it
  // (pre-flight I9, I13, M33):
  //   1. load each identity through keyfile, and check its validity and the
  //      CA's;
  //   2. probe the TLS handshake;
  //   3. open both stores, ping, and check the roles.
  // An outage is store.ErrUnavailable; a configuration fault is a
  // *storeFault naming what is wrong. Each start says each certificate's
  // expiry, once it succeeds.
  func attempt(ctx context.Context, cfg config.Config, m *metrics.Metrics, out io.Writer) (d, b *etcdstore.Store, err error) {
  	e := cfg.Store.Etcd
  	now := time.Now()
  	pool, cas, err := caCerts(e.CAFile)
  	if err != nil {
  		return nil, nil, &storeFault{fmt.Errorf("store.etcd.ca_file %s: %w", e.CAFile, err)}
  	}
  	for _, ca := range cas {
  		if now.After(ca.NotAfter) || now.Before(ca.NotBefore) {
  			return nil, nil, &storeFault{fmt.Errorf("store.etcd.ca_file %s: CA %s is valid only from %s to %s; "+
  				"replace it", e.CAFile, ca.Subject, ca.NotBefore.UTC().Format(time.RFC3339), ca.NotAfter.UTC().Format(time.RFC3339))}
  		}
  	}
  	leaves := map[string]*x509.Certificate{}
  	open := func(name string, id config.EtcdIdentity) (*etcdstore.Store, error) {
  		tc, leaf, err := identity(name, id, pool, now)
  		if err != nil {
  			return nil, err
  		}
  		if err := probeTLS(ctx, e.Endpoints, tc, 4*e.CallTimeout); err != nil {
  			return nil, err
  		}
  		s, err := etcdstore.Open(etcdstore.Config{Endpoints: e.Endpoints, Prefix: e.Prefix, LeaseGrace: e.LeaseGrace, TLS: tc})
  		if err != nil {
  			return nil, &storeFault{fmt.Errorf("store.etcd.%s: %w", name, err)}
  		}
  		leaves[name] = leaf
  		return s, nil
  	}
  	if d, err = open("daemon", e.Daemon); err != nil {
  		return nil, nil, err
  	}
  	if b, err = open("broker", *e.Broker); err != nil {
  		d.Close()
  		return nil, nil, err
  	}
  	pctx, cancel := context.WithTimeout(ctx, 4*e.CallTimeout)
  	err = d.Ping(pctx)
  	cancel()
  	if err == nil && e.Roles != config.RolesUnenforced {
  		err = checkRoles(ctx, d, b, e)
  	}
  	if err != nil {
  		b.Close()
  		d.Close()
  		if errors.Is(err, store.ErrUnavailable) {
  			return nil, nil, err
  		}
  		return nil, nil, &storeFault{err}
  	}
  	for _, name := range []string{"daemon", "broker"} {
  		leaf := leaves[name]
  		m.StoreCertExpiry.WithLabelValues(name).Set(float64(leaf.NotAfter.Unix()))
  		fmt.Fprintf(out, "port49d: store: the %s's etcd certificate (CN=%s) is valid until %s (%d days)\n", name,
  			leaf.Subject.CommonName, leaf.NotAfter.UTC().Format(time.RFC3339), int(leaf.NotAfter.Sub(now).Hours()/24))
  	}
  	return d, b, nil
  }

  // identity loads one component's client certificate through keyfile,
  // which refuses a symlink, a mode group or other can read, a foreign
  // owner and an oversize file, all at the read (pre-flight I13). It then
  // checks the leaf's validity window against now (I9). An expired or
  // not-yet-valid certificate is a storeFault naming the file, the CN and
  // the instant, never "not answering".
  func identity(name string, id config.EtcdIdentity, pool *x509.CertPool, now time.Time) (*tls.Config, *x509.Certificate, error) {
  	pair, err := keyfile.LoadX509KeyPair(id.CertFile, id.KeyFile)
  	if err != nil {
  		return nil, nil, &storeFault{fmt.Errorf("store.etcd.%s: %w", name, err)}
  	}
  	leaf, err := x509.ParseCertificate(pair.Certificate[0])
  	if err != nil {
  		return nil, nil, &storeFault{fmt.Errorf("store.etcd.%s: certificate %s: %w", name, id.CertFile, err)}
  	}
  	switch {
  	case now.After(leaf.NotAfter):
  		return nil, nil, &storeFault{fmt.Errorf("store.etcd.%s: certificate %s (CN=%s) expired at %s; renew it", name,
  			id.CertFile, leaf.Subject.CommonName, leaf.NotAfter.UTC().Format(time.RFC3339))}
  	case now.Before(leaf.NotBefore):
  		return nil, nil, &storeFault{fmt.Errorf("store.etcd.%s: certificate %s (CN=%s) is not valid until %s; check "+
  			"this host's clock", name, id.CertFile, leaf.Subject.CommonName, leaf.NotBefore.UTC().Format(time.RFC3339))}
  	}
  	return &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, leaf, nil
  }

  // probeTLS completes a TLS handshake with each endpoint in turn as the
  // component, then reads once, briefly (pre-flight I9). Under TLS 1.3 etcd
  // refuses a client certificate after the handshake, with an alert on the
  // first read, and clientv3 would report that only as a deadline. So:
  //   - a certificate the server refuses, or a server certificate this CA
  //     does not verify, is a storeFault naming it;
  //   - an endpoint that does not answer is store.ErrUnavailable;
  //   - one endpoint that completes is enough.
  func probeTLS(ctx context.Context, endpoints []string, tc *tls.Config, timeout time.Duration) error {
  	var last error
  	for _, ep := range endpoints {
  		u, err := url.Parse(ep)
  		if err != nil {
  			return &storeFault{fmt.Errorf("store.etcd.endpoints %q: %w", ep, err)}
  		}
  		dctx, cancel := context.WithTimeout(ctx, timeout)
  		conn, err := (&tls.Dialer{Config: tc}).DialContext(dctx, "tcp", u.Host)
  		cancel()
  		if err != nil {
  			if tlsFault(err) {
  				return &storeFault{fmt.Errorf("etcd at %s: the TLS handshake failed: %w", ep, err)}
  			}
  			last = err
  			continue
  		}
  		conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
  		_, rerr := conn.Read(make([]byte, 1))
  		conn.Close()
  		if rerr != nil && tlsFault(rerr) {
  			return &storeFault{fmt.Errorf("etcd at %s refused this certificate: %w", ep, rerr)}
  		}
  		return nil
  	}
  	return fmt.Errorf("%w: %v", store.ErrUnavailable, last)
  }

  // tlsFault is an error about the certificates, not the network: an alert
  // the server sent (crypto/tls spells it "remote error: tls: …"; its type
  // is unexported, as the agent's certificateAlerts says), or a chain this
  // side would not verify.
  func tlsFault(err error) bool {
  	var verr *tls.CertificateVerificationError
  	var uerr x509.UnknownAuthorityError
  	var herr x509.HostnameError
  	return errors.As(err, &verr) || errors.As(err, &uerr) || errors.As(err, &herr) ||
  		strings.Contains(err.Error(), "remote error: tls:")
  }

  // checkRoles is Ruling 10's start check, its refusal naming the identity
  // and the fix.
  func checkRoles(ctx context.Context, d, b *etcdstore.Store, e *config.EtcdConfig) error {
  	cctx, cancel := context.WithTimeout(ctx, 4*e.CallTimeout)
  	defer cancel()
  	if err := d.CheckIdentity(cctx, false); err != nil {
  		cn, _ := commonName(e.Daemon.CertFile)
  		if errors.Is(err, etcdstore.ErrNotSeparated) {
  			return fmt.Errorf("store.etcd: the daemon's identity (CN=%s) %v: etcd's roles for port49 are not in force "+
  				"(auth disabled, or that user holds the broker's or root's role); run 'port49d store-roles --config …' "+
  				"and apply its output as etcd's root, or set store.etcd.roles: unenforced to run without them", cn,
  				strings.TrimPrefix(err.Error(), "etcd: the daemon's identity "))
  		}
  		return fmt.Errorf("store.etcd: the daemon's identity (CN=%s): %w", cn, err)
  	}
  	if err := b.CheckIdentity(cctx, true); err != nil {
  		cn, _ := commonName(e.Broker.CertFile)
  		return fmt.Errorf("store.etcd: the broker's identity (CN=%s): %w; apply 'port49d store-roles' output", cn, err)
  	}
  	return nil
  }

  // caCerts is the CA file's certificates, and a pool of them.
  func caCerts(path string) (*x509.CertPool, []*x509.Certificate, error) {
  	raw, err := os.ReadFile(path)
  	if err != nil {
  		return nil, nil, err
  	}
  	pool := x509.NewCertPool()
  	var out []*x509.Certificate
  	for {
  		var blk *pem.Block
  		blk, raw = pem.Decode(raw)
  		if blk == nil {
  			break
  		}
  		if blk.Type != "CERTIFICATE" {
  			continue
  		}
  		c, err := x509.ParseCertificate(blk.Bytes)
  		if err != nil {
  			return nil, nil, err
  		}
  		pool.AddCert(c)
  		out = append(out, c)
  	}
  	if len(out) == 0 {
  		return nil, nil, errors.New("no certificate in it")
  	}
  	return pool, out, nil
  }

  // startOnPersistentStore is a start on etcd after the file's marks are
  // restored (Ruling 12; Ruling 13; pre-flight C1, M41; re-check IA2). With
  // the listeners still closed, it:
  //   1. puts the store's marks the file lacked in force and saves them to
  //      it, counted as a set difference on (kind, key);
  //   2. re-indexes every kept context the index lost (e.Unindexed, then
  //      ReindexContexts), so the passes below reach it;
  //   3. applies every standing mark to the live contexts the store kept,
  //      by 7a's two context passes;
  //   4. purges every unspent token and supersedes every key;
  //   5. carries the policy in force into every live context the store
  //      kept.
  // Each step that reads the store retries every 5s while it errs. marks
  // ends as every mark in force, which the caller puts in the daemon's
  // marks and the listener's. Steps 2, 3 and 5 read every kept context
  // through the sealing layer, which seeds the ledger before any listener
  // binds.
  func startOnPersistentStore(ctx context.Context, brk *broker.Broker, st store.Store, e *etcdstore.Store,
  	cfg config.Config, marks *[]store.Revocation, m *metrics.Metrics) error {
  	retry := func(what string, f func() error) error {
  		for {
  			err := f()
  			if err == nil {
  				return nil
  			}
  			if !errors.Is(err, store.ErrUnavailable) {
  				return fmt.Errorf("store: %s: %w", what, err)
  			}
  			fmt.Fprintf(stderr, "port49d: store: %s: %v; the listeners stay closed; trying again in 5s\n", what, err)
  			select {
  			case <-ctx.Done():
  				return ctx.Err()
  			case <-time.After(5 * time.Second):
  			}
  		}
  	}
  	var all []store.Revocation
  	if err := retry("listing the revocations in force", func() (err error) {
  		all, err = st.ListRevocations(ctx)
  		return err
  	}); err != nil {
  		return err
  	}
  	inFile := map[[2]string]bool{}
  	for _, r := range *marks {
  		inFile[[2]string{r.Kind, r.Key}] = true
  	}
  	extra := 0
  	for _, r := range all {
  		if !inFile[[2]string{r.Kind, r.Key}] {
  			extra++
  		}
  	}
  	if extra > 0 {
  		fmt.Fprintf(stderr, "port49d: broker: %d revocation(s) in force from the store that %s lacked; saving them "+
  			"to it\n", extra, cfg.Broker.RevocationsFile)
  		if err := brk.Persist(ctx); err != nil {
  			fmt.Fprintf(stderr, "port49d: broker: saving them: %v; port49_revocations_file_failed is 1\n", err)
  		}
  	}
  	*marks = all
  	countRevocations(all, m)
  	if err := retry("re-indexing the kept contexts the index lost", func() error {
  		// e is the daemon's raw store, outside the guard, as the sweep's is:
  		// the scan gets the bulk pool's deadline here.
  		uctx, cancel := context.WithTimeout(ctx, cfg.Store.Etcd.BulkTimeout)
  		refs, err := e.Unindexed(uctx)
  		cancel()
  		if err != nil {
  			return err
  		}
  		_, err = brk.ReindexContexts(ctx, refs)
  		return err
  	}); err != nil {
  		return err
  	}
  	var marked int
  	if err := retry("applying the standing revocations to the live contexts", func() (err error) {
  		marked, err = brk.ApplyMarksAtStart(ctx, all)
  		return err
  	}); err != nil {
  		return err
  	}
  	if len(all) > 0 {
  		fmt.Fprintf(stderr, "port49d: store: %d standing revocation(s) applied to the live contexts the store kept "+
  			"(%d context(s) marked revoked) before serving\n", len(all), marked)
  	}
  	brk.SupersededAll = brk.Now()
  	var n int
  	if err := retry("purging the tokens from before this start", func() (err error) {
  		n, err = st.PurgeTokens(ctx)
  		return err
  	}); err != nil {
  		return err
  	}
  	fmt.Fprintf(stderr, "port49d: store: purged %d unspent token(s) from before this start (run 'port49 token' "+
  		"again)\n", n)
  	var rep broker.RefreshReport
  	if err := retry("carrying the policy in force into the live contexts", func() (err error) {
  		rep, err = brk.RefreshAtStart(ctx)
  		return err
  	}); err != nil {
  		return err
  	}
  	fmt.Fprintf(stderr, "port49d: store: %d live context(s) carried onto the policy in force (bundle %s) "+
  		"before serving\n", rep.Contexts(), brk.Policy.Load().Bundle)
  	return nil
  }

  // sweepLoop runs the index sweep every interval (Ruling 6), then finds
  // the contexts the index lost and has the broker re-index and judge them
  // (re-check IA2), saying only a failure. ReindexContexts says what it
  // found.
  func sweepLoop(ctx context.Context, s *etcdstore.Store, brk *broker.Broker, every time.Duration, out io.Writer) {
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
  		refs, err := s.Unindexed(sctx)
  		if err == nil {
  			_, err = brk.ReindexContexts(sctx, refs)
  		}
  		if err != nil && ctx.Err() == nil {
  			fmt.Fprintf(out, "port49d: store: finding the contexts the index lost did not finish (%v); it runs again "+
  				"in %v\n", err, every)
  		}
  		cancel()
  	}
  }
  ```

  `ApplyMarksAtStart` returns only an outage (re-check R-I3), which `retry` waits out. A mark it
  could not apply for any other reason is said by the broker, and still denied at every request
  by the daemon's marks, loaded from `all` right after this returns. `Unindexed` runs on the
  daemon's etcd store, which bypasses the guard as the sweep does; its scan is bounded by the
  sweep's `every/2` context in the loop, and by `bulk_timeout` at start. A deadline there is
  `store.ErrUnavailable` (`unavailable`), which `retry` waits out.

  Add to `refresh.go`:

  ```go
  // Contexts is how many live contexts the pass judged.
  func (r RefreshReport) Contexts() int {
  	return r.Updated + r.Unchanged + r.Revoked + r.Quarantined + r.Failed
  }
  ```

  Create `cmd/port49d/store_test.go`:

  ```go
  package main

  import (
  	"context"
  	"errors"
  	"os"
  	"path/filepath"
  	"strings"
  	"testing"
  	"time"

  	"github.com/rhwendt/port49/internal/config"
  	"github.com/rhwendt/port49/internal/store"
  	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
  	"github.com/rhwendt/port49/internal/testpki"
  )

  // writeIdentity issues a client certificate for cn, valid from nb to na,
  // and writes it and its key, the key at mode.
  func writeIdentity(t *testing.T, ca *testpki.CA, cn string, nb, na time.Time, mode os.FileMode) config.EtcdIdentity {
  	t.Helper()
  	dir := t.TempDir()
  	c, err := ca.Issue(testpki.Leaf{CommonName: cn, Client: true, NotBefore: nb, NotAfter: na})
  	if err != nil {
  		t.Fatal(err)
  	}
  	cp, kp, err := testpki.PEMs(c)
  	if err != nil {
  		t.Fatal(err)
  	}
  	id := config.EtcdIdentity{CertFile: filepath.Join(dir, "c.pem"), KeyFile: filepath.Join(dir, "k.pem")}
  	if err := os.WriteFile(id.CertFile, cp, 0o600); err != nil {
  		t.Fatal(err)
  	}
  	if err := os.WriteFile(id.KeyFile, kp, mode); err != nil {
  		t.Fatal(err)
  	}
  	return id
  }

  // An expired store certificate is named for what it is, and a key file
  // others can read is refused at the read (pre-flight I9, I13): neither is
  // ever "not answering".
  func TestAStoreIdentityIsCheckedWhereItIsRead(t *testing.T) {
  	now := time.Now()
  	ca, err := testpki.NewCA("ca", now.Add(-48*time.Hour), now.Add(48*time.Hour))
  	if err != nil {
  		t.Fatal(err)
  	}
  	expired := writeIdentity(t, ca, "port49-daemon", now.Add(-48*time.Hour), now.Add(-time.Hour), 0o600)
  	_, _, err = identity("daemon", expired, ca.Pool(), now)
  	var fault *storeFault
  	if !errors.As(err, &fault) || !strings.Contains(err.Error(), "expired at") || errors.Is(err, store.ErrUnavailable) {
  		t.Fatalf("an expired certificate: %v", err)
  	}
  	loose := writeIdentity(t, ca, "port49-daemon", now.Add(-time.Hour), now.Add(time.Hour), 0o644)
  	if _, _, err := identity("daemon", loose, ca.Pool(), now); !errors.As(err, &fault) || !strings.Contains(err.Error(), "chmod 600") {
  		t.Fatalf("a key others can read: %v", err)
  	}
  	good := writeIdentity(t, ca, "port49-daemon", now.Add(-time.Hour), now.Add(time.Hour), 0o600)
  	if _, leaf, err := identity("daemon", good, ca.Pool(), now); err != nil || leaf.Subject.CommonName != "port49-daemon" {
  		t.Fatalf("a good identity: %v", err)
  	}
  }

  // A certificate etcd refuses, and a server this CA does not verify, are
  // named by the probe; a port nothing answers on is an outage (pre-flight
  // I9).
  func TestProbeTLSTellsAFaultFromAnOutage(t *testing.T) {
  	srv := etcdtest.Start(t, etcdtest.Options{TLS: true})
  	ctx := context.Background()
  	good := srv.TLS(t, "port49-daemon")
  	if err := probeTLS(ctx, []string{srv.Endpoint}, good, time.Second); err != nil {
  		t.Fatalf("a good identity: %v", err)
  	}
  	now := time.Now()
  	other, err := testpki.NewCA("other", now.Add(-time.Hour), now.Add(time.Hour))
  	if err != nil {
  		t.Fatal(err)
  	}
  	stranger := writeIdentity(t, other, "port49-daemon", now.Add(-time.Hour), now.Add(time.Hour), 0o600)
  	tc, _, err := identity("daemon", stranger, good.RootCAs, now)
  	if err != nil {
  		t.Fatal(err)
  	}
  	var fault *storeFault
  	if err := probeTLS(ctx, []string{srv.Endpoint}, tc, time.Second); !errors.As(err, &fault) {
  		t.Fatalf("a client certificate etcd does not trust: %v", err)
  	}
  	wrongCA := good.Clone()
  	wrongCA.RootCAs = other.Pool()
  	if err := probeTLS(ctx, []string{srv.Endpoint}, wrongCA, time.Second); !errors.As(err, &fault) {
  		t.Fatalf("a server this CA does not verify: %v", err)
  	}
  	if err := probeTLS(ctx, []string{"https://127.0.0.1:1"}, good, time.Second); !errors.Is(err, store.ErrUnavailable) {
  		t.Fatalf("nothing listening: %v", err)
  	}
  }
  ```

- [ ] **Step 6: The end-to-end tests, failing.** Create `cmd/port49d/store_e2e_test.go`:

  ```go
  package main

  import (
  	"context"
  	"errors"
  	"fmt"
  	"net"
  	"os"
  	"path/filepath"
  	"regexp"
  	"strings"
  	"syscall"
  	"testing"
  	"time"

  	"github.com/rhwendt/port49/internal/store"
  	"github.com/rhwendt/port49/internal/store/etcd"
  	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
  	"github.com/rhwendt/port49/internal/tacacs/wire"
  )

  // etcdRun is a port49d config on a TLS etcd member with port49's roles,
  // through a proxy the test can hang: the run_test.go config with a store:
  // block and an admin_socket appended (etcd requires one, Ruling 13).
  func etcdRun(t *testing.T) (cfgPath, pkiDir, revocations string, proxy *etcdtest.Proxy) {
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
  		"    breaker: {failures: 3, open_for: 2s}\nadmin_socket: %s\n",
  		proxy.Addr(), filepath.Join(srv.Dir, "ca.pem"), dc, dk, bc, bk, filepath.Join(t.TempDir(), "a.sock")))...)
  	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
  		t.Fatal(err)
  	}
  	return cfgPath, filepath.Dir(b.TLSCertFile), b.RevocationsFile, proxy
  }

  // startRun runs port49d on cfgPath until the test ends or stop is called,
  // and returns the TACACS+ and broker addresses of its nth run in out: it
  // waits for the nth "broker listening" line, never an earlier run's
  // (pre-flight M37), and reads the newest addresses.
  func startRun(t *testing.T, cfgPath string, out *syncBuffer, n int) (tacacs, brokerAddr string, stop func() error) {
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
  	waitForCount(t, out, "port49d: broker listening on ", n)
  	tacacs, brokerAddr = newestAddrs(t, out)
  	return tacacs, brokerAddr, stop
  }

  // newestAddrs is the last run's TACACS+ and broker addresses: each run
  // says "listening on <tacacs>" and then "broker listening on <broker>".
  func newestAddrs(t *testing.T, out *syncBuffer) (string, string) {
  	t.Helper()
  	addrs := regexp.MustCompile(`listening on (127\.0\.0\.1:\d+)`).FindAllStringSubmatch(out.String(), -1)
  	if len(addrs) < 2 {
  		t.Fatalf("no listening lines: %s", out.String())
  	}
  	return addrs[len(addrs)-2][1], addrs[len(addrs)-1][1]
  }

  // waitWithin is waitForCount with a deadline of the test's choosing.
  func waitWithin(t *testing.T, buf *syncBuffer, want string, n int, d time.Duration) {
  	t.Helper()
  	deadline := time.Now().Add(d)
  	for strings.Count(buf.String(), want) < n {
  		if time.Now().After(deadline) {
  			t.Fatalf("waited %v for %q ×%d; have %q", d, want, n, buf.String())
  		}
  		time.Sleep(50 * time.Millisecond)
  	}
  }

  // A live session survives a port49d restart on etcd; a token minted
  // before it does not (Ruling 12; spec §14, "A restart on etcd").
  func TestRunOnEtcdKeepsALoginAcrossARestart(t *testing.T) {
  	var out, log syncBuffer
  	e, o := stderr, stdout
  	t.Cleanup(func() { stderr, stdout = e, o })
  	stderr, stdout = &out, &log
  	cfgPath, pkiDir, _, _ := etcdRun(t)

  	tacacs, brokerAddr, stop := startRun(t, cfgPath, &out, 1)
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

  	tacacs, _, _ = startRun(t, cfgPath, &out, 2)
  	waitForCount(t, &out, "unspent token(s) from before this start", 2)
  	waitForCount(t, &out, "live context(s) carried onto the policy in force", 2)
  	dev = tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
  	if !dev.permits("alice", "configure") {
  		t.Fatalf("after the restart the session's next command was not answered from its context; log %s", log.String())
  	}
  	if st := dev.login("alice", spare); st == wire.AuthenStatusPass {
  		t.Fatal("a token minted before the restart logged in")
  	}
  }

  // A mark added to broker.revocations_file with port49d stopped reaches the
  // live context the store kept, before any listener binds (pre-flight C1;
  // spec §14, "A mark at start").
  func TestAStartAppliesAStandingMarkToAKeptContext(t *testing.T) {
  	var out, log syncBuffer
  	e, o := stderr, stdout
  	t.Cleanup(func() { stderr, stdout = e, o })
  	stderr, stdout = &out, &log
  	cfgPath, pkiDir, revocations, _ := etcdRun(t)

  	tacacs, brokerAddr, stop := startRun(t, cfgPath, &out, 1)
  	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
  	if st := dev.login("alice", mint(t, brokerAddr, pkiDir, "leaf1")); st != wire.AuthenStatusPass {
  		t.Fatalf("login: %d", st)
  	}
  	principal := lastCommandPrincipal(t, &log) // the principal the session's records name
  	if err := stop(); err != nil {
  		t.Fatal(err)
  	}
  	if err := saveRevocations(revocations, []store.Revocation{{Kind: store.RevocationPrincipal, Key: principal,
  		At: time.Now().UTC(), Origin: "test: the file edited with port49d stopped"}}); err != nil {
  		t.Fatal(err)
  	}

  	tacacs, _, _ = startRun(t, cfgPath, &out, 2)
  	// The start itself marked it, not only the daemon's marks at request
  	// time (re-check R-M1): without ApplyMarksAtStart this line is absent.
  	waitForCount(t, &out, "standing revocation(s) applied to the live contexts the store kept "+
  		"(1 context(s) marked revoked)", 1)
  	dev = tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
  	if dev.permits("alice", "configure") {
  		t.Fatal("a kept context under a standing mark was permitted")
  	}
  	if r := lastCommand(t, &log); r["reason"] != "credential_revoked" {
  		t.Fatalf("the denial: %v", r)
  	}
  }

  // A second port49d on the keyspace binds no listener while the first
  // holds it (Review Focus 4).
  func TestASecondPort49dWaitsForTheKeyspace(t *testing.T) {
  	var out, log syncBuffer
  	e, o := stderr, stdout
  	t.Cleanup(func() { stderr, stdout = e, o }) // runs last: after the second run has stopped
  	stderr, stdout = &out, &log
  	cfgPath, _, _, _ := etcdRun(t)
  	startRun(t, cfgPath, &out, 1)
  	n := strings.Count(out.String(), "listening on ")

  	// The same file: a copy-pasted config is the case. The second waits for
  	// the keyspace before it binds anything or touches the revocations file.
  	ctx, cancel := context.WithCancel(context.Background())
  	done := make(chan error, 1)
  	go func() { done <- run(ctx, cfgPath) }()
  	t.Cleanup(func() { // pre-flight M38: the run ends before stderr is restored
  		cancel()
  		select {
  		case <-done:
  		case <-time.After(15 * time.Second):
  			t.Error("the second port49d did not stop")
  		}
  	})
  	waitFor(t, &out, "is held by port49d on")
  	time.Sleep(2 * time.Second)
  	if got := strings.Count(out.String(), "listening on "); got != n {
  		t.Fatalf("the second port49d bound a listener while the first held the keyspace:\n%s", out.String())
  	}
  }

  // A store that hangs in the middle of a login: the device hears ERROR
  // within store.packet_deadline, never silence (Review Focus 1). Then the
  // store has been gone long enough, and port49d closes every listener and
  // says why, without exiting; when the store returns, the same process
  // listens again, and the session's next command is answered from its
  // context (Ruling 11; pre-flight I19; Review Focus 4).
  func TestAHungStoreGoesDarkAndServesAgainWhenItReturns(t *testing.T) {
  	var out, log syncBuffer
  	e, o := stderr, stdout
  	t.Cleanup(func() { stderr, stdout = e, o })
  	stderr, stdout = &out, &log
  	cfgPath, pkiDir, _, proxy := etcdRun(t)
  	ctx, cancel := context.WithCancel(context.Background())
  	done := make(chan error, 1)
  	go func() { done <- run(ctx, cfgPath) }()
  	t.Cleanup(func() {
  		cancel()
  		select {
  		case <-done:
  		case <-time.After(15 * time.Second):
  			t.Error("port49d did not stop")
  		}
  	})
  	waitForCount(t, &out, "port49d: broker listening on ", 1)
  	tacacs, brokerAddr := newestAddrs(t, &out)
  	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
  	if st := dev.login("alice", mint(t, brokerAddr, pkiDir, "leaf1")); st != wire.AuthenStatusPass {
  		t.Fatalf("login: %d", st)
  	}
  	tok := mint(t, brokerAddr, pkiDir, "leaf1")
  	// A connection a device holds open across the hang (re-check R-M0).
  	held, err := net.DialTimeout("tcp", tacacs, time.Second)
  	if err != nil {
  		t.Fatal(err)
  	}
  	defer held.Close()

  	proxy.Hang(true)
  	start := time.Now()
  	if st := dev.login("alice", tok); st != wire.AuthenStatusError || time.Since(start) > 1500*time.Millisecond {
  		t.Fatalf("a login on a hung store: status %d after %v", st, time.Since(start))
  	}
  	waitWithin(t, &out, "closing every listener so that devices use their local method", 1, 20*time.Second)
  	// Reset, not closed with a FIN: L28 measured the fast fall to local on
  	// a reset.
  	held.SetReadDeadline(time.Now().Add(5 * time.Second))
  	if _, err := held.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
  		t.Fatalf("a held connection on a store gone: %v, want a reset", err)
  	}
  	waitWithin(t, &out, "waiting for the store again, as at a start", 1, 20*time.Second)
  	select {
  	case err := <-done:
  		t.Fatalf("port49d exited on a store gone: %v", err)
  	default:
  	}
  	if c, err := net.DialTimeout("tcp", tacacs, time.Second); err == nil {
  		c.Close()
  		t.Fatal("TACACS+ still listens with the store gone")
  	}

  	proxy.Hang(false)
  	waitWithin(t, &out, "port49d: broker listening on ", 2, 60*time.Second)
  	tacacs, _ = newestAddrs(t, &out)
  	dev = tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
  	if !dev.permits("alice", "configure") {
  		t.Fatalf("after the store returned the session's next command was not answered from its context; log %s",
  			log.String())
  	}
  }
  ```

  `lastCommandPrincipal` reads the `principal` of the last `authorize_command` or `redeem` record
  in the log (`records`, run_test.go:165). Add it beside `lastCommand` if no helper gives it.

  The held connection must outlive the hang. Read `writeRunConfig`'s idle timeout for TACACS+
  connections; if it is under 30 s, raise it in `etcdRun`'s config, or the connection is closed
  idle, with a FIN, before the store gone.

  There is no `TestMain` to add: these tests start their own members, and no test in the package
  uses `etcdtest.Endpoint()`.

  The run-test helpers are `run_test.go`'s: `brokerConfig`, `minimalPolicy`, `writeRunConfig`,
  `mint`, `tacacsClient`, `waitFor`, `waitForCount`, `lastCommand`, `syncBuffer`, and the
  `stderr`/`stdout` package vars. Read the file first and use them as they are.
  - `writeRunConfig` listens on `127.0.0.1:0` for TACACS+, the broker and metrics, so a second
    run of the same file binds other ports. Read the file and confirm it; if it names fixed
    ports, give the second run a copy with `:0`.
  - `brokerConfig(…).Broker.RevocationsFile` is the file the run restores from.

  Run: `go test ./cmd/port49d/ -run 'OnEtcd|StandingMark|SecondPort49d|HungStore|StoreIdentity|ProbeTLS' -count=1`
  Expected: FAIL. port49d runs on memory regardless of `store:`, so the restart loses the
  session, the second port49d binds, and a hung store is never reached.

- [ ] **Step 7: `run` is a loop, and each run is on the stores.** In `cmd/port49d/main.go`:
  1. **The loop** (pre-flight I19). Rename `run` to `runOnce(parent context.Context, cfgPath
     string, hup <-chan os.Signal, again bool) (err error)`, and move its first lines (the SIGHUP
     channel, `signal.Notify`, `signal.Stop`) into a new `run`:

     ```go
     // run is port49d from config load to exit (plan 7d): it runs runOnce
     // until a run ends for a reason other than a store gone. A store gone
     // closes every listener and drains, as a shutdown does. The next run
     // then waits for the store with the listeners closed and no deadline,
     // and starts again in-process: devices find TACACS+ refused meanwhile
     // and use their local method, and no service manager is needed to
     // bring port49d back (Ruling 11; pre-flight I19). SIGHUP is caught
     // here, once, so a HUP between two runs never takes its default
     // action, which ends the process.
     //
     // Each run builds its own metrics registry and binds its own metrics
     // listener, so between runs /healthz and /readyz are unbound for the
     // drain and the next run's config load (seconds), and the counters
     // restart (re-check R-M3). A liveness probe's failure window should be
     // over 30s. Binding them once here would hold a metrics address across a
     // config change, so it is said instead.
     func run(parent context.Context, cfgPath string) error {
     	hup := make(chan os.Signal, 1)
     	signal.Notify(hup, syscall.SIGHUP)
     	defer signal.Stop(hup)
     	return runLoop(parent, func(again bool) error { return runOnce(parent, cfgPath, hup, again) }, 5*time.Second)
     }

     // runLoop runs once until a run ends for a reason other than a store
     // gone, or, once a store gone has happened, until parent ends (re-check
     // R-I2). A start after a store gone repeats the whole start: config,
     // inventory, policy, the revocations file, the hold, the marks. Any of
     // those can fail for a reason that is not the store, such as a policy
     // file caught half-written during the outage, or the broker's role
     // refused on meta/. Since I19 nothing restarts port49d after an outage
     // but this loop, so every such error is said and tried again every
     // `every`, the listeners closed, never an exit. A cold start still
     // returns its error, for exit 1 and a supervisor.
     func runLoop(parent context.Context, once func(again bool) error, every time.Duration) error {
     	again := false
     	for {
     		err := once(again)
     		if parent.Err() != nil {
     			return err
     		}
     		var gone *storeGone
     		switch {
     		case errors.As(err, &gone):
     			fmt.Fprintf(stderr, "port49d: %v; every listener is closed; waiting for the store again, as at a start\n", gone)
     			again = true
     			continue
     		case err == nil, !again:
     			return err
     		}
     		fmt.Fprintf(stderr, "port49d: starting again after a store gone: %v; the listeners stay closed; trying "+
     			"again in %v\n", err, every)
     		select {
     		case <-parent.Done():
     			return nil
     		case <-time.After(every):
     		}
     	}
     }
     ```

     Add to `cmd/port49d/store_test.go`:

     ```go
     // After a store gone, a start that fails for any other reason is said
     // and tried again, never an exit; a cold start's error is returned
     // (re-check R-I2).
     func TestAStartAfterAStoreGoneRetriesEveryError(t *testing.T) {
     	var out syncBuffer
     	e := stderr
     	t.Cleanup(func() { stderr = e })
     	stderr = &out
     	ctx, cancel := context.WithCancel(context.Background())
     	defer cancel()
     	var calls []bool
     	once := func(again bool) error {
     		calls = append(calls, again)
     		switch len(calls) {
     		case 1:
     			return &storeGone{why: "test: the store went"}
     		case 2, 3:
     			return errors.New("test: the policy file is half-written")
     		}
     		cancel()
     		return nil
     	}
     	if err := runLoop(ctx, once, time.Millisecond); err != nil {
     		t.Fatalf("runLoop = %v", err)
     	}
     	if len(calls) != 4 || calls[0] || !calls[1] || !calls[3] {
     		t.Fatalf("runs %v; want a cold start, then three after the store gone", calls)
     	}
     	if strings.Count(out.String(), "starting again after a store gone: test: the policy file is half-written") != 2 {
     		t.Fatalf("said %q", out.String())
     	}
     	cold := errors.New("test: a bad config")
     	if err := runLoop(context.Background(), func(bool) error { return cold }, time.Millisecond); err != cold {
     		t.Fatalf("a cold start's error: %v", err)
     	}
     }
     ```

     `syncBuffer` and `stderr` are run_test.go's; merge `"errors"` and `"strings"` into the file's
     imports.
  2. **The cause** (pre-flight M39). Right after `cfg, err := config.Load(cfgPath)` succeeds in
     `runOnce`:

     ```go
     	parent, cancelRun := context.WithCancelCause(parent)
     	defer cancelRun(nil)
     	// Whatever path a run ends by, a store gone is what it returns, so
     	// run starts the next.
     	defer func() {
     		var gone *storeGone
     		if c := context.Cause(parent); errors.As(c, &gone) {
     			err = gone
     		}
     	}()
     ```

     `runOnce` derives `ctx, cancel := context.WithCancel(parent)` a few lines further on
     (`main.go:524` at `9cefbba`), so a store gone cancels everything the run started.
  3. **The stores.** Replace `st := crypt.Wrap(memory.New(time.Now), keys, m.CryptOpenFailures)`
     with:

     ```go
     	// The stores (plan 7d): on etcd, waited for with every listener still
     	// closed, the identities and roles checked, the keyspace held; on
     	// memory, one store.
     	sts, err := openStores(ctx, cfg, keys, m, stderr, rd, again, func(e error) { cancelRun(e) })
     	if err != nil {
     		if ctx.Err() != nil {
     			return nil // stopped while waiting for the store: nothing was served, as coldCopies says
     		}
     		return err
     	}
     	defer sts.close()
     	if sts.lost != nil {
     		go func() {
     			select {
     			case <-sts.lost:
     				cancelRun(&storeGone{why: fmt.Sprintf("lost this port49d's hold on keyspace %s (its lock key is "+
     					"gone, or etcd stopped answering with half its lease or less left)", cfg.Store.Etcd.Prefix)})
     			case <-ctx.Done():
     			}
     		}()
     	}
     	st := sts.broker
     ```

     The sweep starts in item 6, once the broker it hands the unindexed contexts to exists.

     `openStores` is called after the metrics listener is up, where `st` was built, so the
     metrics show `port49_store_keyspace_held` 0 and `/readyz` says `readyStore` while port49d
     waits. The TACACS+ and broker listeners bind later in `runOnce`, so nothing listens while it
     waits.
  4. **The daemon's handlers read the daemon's store.** Replace `authz := &author.Engine{Store:
     st, Metrics: m}` with `authz := &author.Engine{Store: sts.daemon, Metrics: m}`, and
     `handlerStore := labHandlerStore(st, fault)` with `handlerStore :=
     labHandlerStore(sts.daemon, fault)`. The minter, the session manager, the broker, the lab
     seeds and the revocations stay on `st`, the broker's.
  5. **The revocations, retried on etcd** (pre-flight M41). Make the `restoreRevocations` call a
     loop: on a `store.ErrUnavailable` with `sts.persistent`, say `port49d: broker: putting %s's
     marks into the store: %v; the listeners stay closed; trying again in 5s` and try again after
     5 s (or return nil on `ctx`'s end). Any other error stays as it is today, a file that does
     not load.
  6. **The start's order.** After the revocations are restored (the block ending
     `fmt.Fprintf(stderr, "port49d: broker: %d revocation(s) in force from %s\n", …)`), and
     before Task 4b's `authMarks` loop, add:

     ```go
     	if sts.persistent {
     		if err := startOnPersistentStore(ctx, brk, st, sts.etcd, cfg, &marks, m); err != nil {
     			stopSpool()
     			<-spoolDone
     			if ctx.Err() != nil {
     				return nil
     			}
     			return err
     		}
     		go sweepLoop(ctx, sts.etcd, brk, cfg.Store.Etcd.SweepInterval, stderr)
     	}
     ```

     Move Task 4b's `for _, r := range marks { authMarks.Set(r, true) }` after it, so the
     daemon's marks are the union. The listener's `bl.Revoked` loop already reads `marks`, later.
     (`store.backend: etcd` requires a broker, Task 10, so `brk` is set here.)
  7. **The line a store gone ends a run with, and the listeners it closes** (re-check R-M0,
     R-M2). In the final `select`'s `case <-ctx.Done():`, replace `fmt.Fprintln(stderr,
     "port49d: signal received, draining")` with:

     ```go
     		var gone *storeGone
     		if errors.As(context.Cause(parent), &gone) {
     			// Close the broker's listener first, so the line is true when it
     			// is said; TACACS+'s is closing with ctx, its held connections
     			// reset (Deps.Abort).
     			if bl != nil {
     				bl.Close()
     			}
     			fmt.Fprintf(stderr, "port49d: %v; closing every listener so that devices use their local method\n", gone)
     		} else {
     			fmt.Fprintln(stderr, "port49d: signal received, draining")
     		}
     ```

     After it, where the broker server is shut down, close what `Shutdown` left at its timeout
     (the agent's held connections):

     ```go
     	if brokerSrv != nil {
     		shutdownCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
     		if err := brokerSrv.Shutdown(shutdownCtx); err != nil {
     			brokerSrv.Close()
     		}
     		done()
     	}
     ```

     `bl` is `broker.NewListener`'s; if its type has no `Close`, close `bln` under it. In the
     `deps := server.Deps{…}` literal, add `Abort: func() bool { var g *storeGone; return
     errors.As(context.Cause(parent), &g) }`.

     In `internal/daemon/server/server.go`, add to `Deps`, beside `PacketDeadline`:

     ```go
     	// Abort reports, when the server's context ends, whether it ended for
     	// a store gone (plan 7d; re-check R-M0): held connections are then
     	// reset (linger 0), not closed with a FIN, since a reset is what L28
     	// measured devices falling to their local method on at once. Nil is a
     	// shutdown, closed as before.
     	Abort func() bool
     ```

     and in `Serve`'s per-connection goroutine, in `case <-ctx.Done():`, before `c.Close()`:

     ```go
     				if d.Abort != nil && d.Abort() {
     					if tc, ok := c.(*net.TCPConn); ok {
     						_ = tc.SetLinger(0)
     					}
     				}
     ```

     conn.go:179 sets linger 0 the same way; follow its form if the accepted connection is
     wrapped.
  8. **Readiness.** Add `readyStore` to the fixed lines' block beside `readyWaiting` (it is
     declared in `store.go`; move it here if the block reads better whole).

  Run: `go test ./cmd/port49d/ ./internal/daemon/server/ -count=1`
  Expected: PASS: the end-to-end tests, the identity and probe tests,
  `TestAStartAfterAStoreGoneRetriesEveryError`, and every existing test (memory, unchanged). The `memory` import moves to `store.go`; drop it from `main.go` if the
  compiler says it is unused. Existing tests call `run`, which is now the loop. On memory no run
  ends with a store gone, so each behaves as before.

  Mutation checks (do them, report them, revert them):
  1. In `startOnPersistentStore`, drop the `ApplyMarksAtStart` step.
     `TestAStartAppliesAStandingMarkToAKeptContext` must fail: the start's line no longer says
     `(1 context(s) marked revoked)` (re-check R-M1). The session is still denied at runtime by
     the daemon's marks, which the test's last assertion shows.
  2. In `runLoop`, return on a `storeGone` instead of looping.
     `TestAHungStoreGoesDarkAndServesAgainWhenItReturns` must fail ("port49d exited on a store
     gone").
  3. In `runLoop`, return any error once `again` is set. `TestAStartAfterAStoreGoneRetriesEveryError`
     must fail (re-check R-I2).
  4. In `server.go`, drop the `SetLinger(0)`. The hung-store e2e must fail ("want a reset").

- [ ] **Step 8: Commit.**

  ```bash
  gofmt -w cmd/port49d internal/store/etcd internal/broker internal/daemon/metrics internal/daemon/server
  make build && make test && make vet
  git add internal/store/etcd/meta.go internal/store/etcd/meta_test.go cmd/port49d/store.go \
    cmd/port49d/store_test.go cmd/port49d/store_e2e_test.go cmd/port49d/main.go internal/broker/broker.go \
    internal/broker/refresh.go internal/broker/refresh_test.go internal/daemon/metrics/metrics.go \
    internal/daemon/metrics/metrics_test.go internal/daemon/server/server.go
  git commit -m "feat(port49d): run on etcd: one per keyspace, every mark at start, going dark in-process

  With store.backend etcd, port49d waits for etcd with its listeners
  closed, checking each certificate's validity, the TLS handshake and its
  roles, and naming a fault rather than calling it an outage. It holds the
  keyspace as the broker, behind a fence read from the lease's own TTL (a
  second port49d waits), puts the file's marks into the store, re-indexes
  any kept context the index lost, applies every standing mark to the
  contexts the store kept (one that will not open never stops it), purges
  unspent tokens and supersedes every key, carries the policy in force
  into every kept context, and only then binds TACACS+. A lost hold, or a
  token or context pool failed or refused for hold_ttl, closes every
  listener and resets every held connection; port49d then waits
  in-process, retries any start error, and serves again when the store
  returns. The daemon's and the broker's sealing layers share one ledger;
  the daemon's handlers read through the daemon's identity, the broker
  through its own (plan 7d; decision 35; pre-flight C1, I9, I13, I15,
  I19; re-check IA1, IA2, R-I2, R-I3, R-I4, R-M0 to R-M3).

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
- Modify: `cmd/port49d/store.go` (`unopenableSayer`, `checkSealKeys`; `openStores` passes the one
  sayer to every `Wrap`)
- Test: `cmd/port49d/store_test.go` (created by Task 12; this task appends)
- Modify: `internal/daemon/metrics/metrics.go`, `metrics_test.go` (`CryptStoreKeyUnknown`)

**Interfaces:**
- Consumes: `crypt.Wrap`, `crypt.Keys`, `crypt.Option` (Task 4b; `Wrap` is variadic since
  then); Task 12's `openStores` and `Hold`.
- Produces:
  - `func crypt.OnUnopenable(f func(record, keyID string)) Option`
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
  	// A header is the record's, so anyone who can write the store writes
  	// it: what it names is echoed only within the key-id charset
  	// (pre-flight M44).
  	if got := SealedKeyID(append([]byte{5}, "a\nb;c"...)); got != "?" {
  		t.Fatalf("a header outside the key-id charset named %q", got)
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

  Append to `cmd/port49d/store_test.go` (Task 12 created it; merge these imports into its own):

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
  		!strings.Contains(out.String(), "this start ends them before it serves") ||
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
  // OnUnopenable is told the kind and the key id of every record that will
  // not open, beside crypt_open_failures_total. The key id is the sealed
  // record's own header, never a secret: it is how an operator learns which
  // key a rotation retired too early (plan 2's alarm; plan 7d).
  func OnUnopenable(f func(record, keyID string)) Option { return func(w *wrapped) { w.onUnopenable = f } }

  // SealedKeyID is the key id a sealed record's header names, "" when it is
  // too short to name one, and "?" when it names one outside the key-id
  // charset ([A-Za-z0-9._-], at most 64 bytes): the header is the record's,
  // so whoever can write the store writes it, and a line must not echo up to
  // 255 bytes of it (pre-flight M44).
  func SealedKeyID(sealed []byte) string {
  	if len(sealed) < 1 || len(sealed) < 1+int(sealed[0]) {
  		return ""
  	}
  	id := sealed[1 : 1+int(sealed[0])]
  	if len(id) > 64 {
  		return "?"
  	}
  	for _, b := range id {
  		switch {
  		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9', b == '.', b == '_', b == '-':
  		default:
  			return "?"
  		}
  	}
  	return string(id)
  }
  ```

  Check the charset against what `config` accepts for `encryption.current`'s id; if config allows
  more, use config's rule and say so.

  Add `onUnopenable func(record, keyID string)` to `wrapped`; `Wrap` already applies each option
  (Task 4b). Give `openErr` the record's sealed bytes: `func (w *wrapped) openErr(record string,
  sealed []byte, err error) error`, calling `w.onUnopenable(record, SealedKeyID(sealed))` when it
  is set, after the counter. Pass the sealed bytes at each of its callers: `t.Sealed` in
  `Candidates`, `r.Sealed` in `GetReceipt`, `c.Sealed` in `GetContext` (both the open failure
  and the ledger's `ErrNotLastWritten`), `cur.Sealed` in `ReserveIdempotency`, and any other
  Task 4b added (grep `openErr(`).

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
  // openStores builds one and hands it to every Wrap, so the daemon's and
  // the broker's layers share its memory and say a key once, not twice. It
  // remembers at most sayerMax pairs, and forgets them all past it: a key id
  // is the record's header, which whoever writes the store chooses, so the
  // memory is bounded and the cost of forgetting is one repeated line
  // (pre-flight M44).
  func unopenableSayer(keys crypt.Keys, out io.Writer, now func() time.Time) func(record, keyID string) {
  	const sayerMax = 64
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
  		if len(said) >= sayerMax {
  			clear(said)
  		}
  		said[k] = now()
  		held := keyID == keys.Current.ID || keys.Previous != nil && keyID == keys.Previous.ID
  		if held {
  			// A held key's record that will not open was altered: its bytes
  			// fail authentication, or it opens but is not the context this
  			// port49d last wrote at its key (the ledger; re-check IA1).
  			fmt.Fprintf(out, "port49d: crypt: a %s failed authentication under key id %q, or is not the one this "+
  				"port49d last wrote there: it was altered or is corrupt, and is treated as unreadable\n", record, keyID)
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
  		// Said before the start carries the policy into the kept contexts,
  		// which revokes every one it cannot open (refresh.go); so it says
  		// that, and what to do before the next start, not "set it now"
  		// as if this start could still save them (pre-flight M46). Tokens
  		// are purged at every start on etcd, so none is named.
  		fmt.Fprintf(out, "port49d: crypt: the store was last written by a port49d whose current key is %q, which "+
  			"this configuration does not hold (%s); the live sessions sealed under %s cannot be read, and this "+
  			"start ends them before it serves (their operators log in again); if %s was retired by mistake, "+
  			"stop port49d now and set encryption.previous to %s before it starts\n",
  			last.Current, window, last.Current, last.Current, last.Current)
  	}
  	cur := etcdstore.SealKeys{Current: keys.Current.ID, WrittenAt: time.Now().UTC()}
  	if keys.Previous != nil {
  		cur.Previous = keys.Previous.ID
  	}
  	return s.PutSealKeys(ctx, cur)
  }
  ```

  Add `"sync"` to the imports. In `openStores`:
  - Build one `say := crypt.OnUnopenable(unopenableSayer(keys, out, time.Now))` and pass it to
    every `crypt.Wrap`: the memory one, and the daemon's and the broker's on etcd (pre-flight
    M44).
  - After the hold is taken and before the stores are returned, call `checkSealKeys(ctx, b, keys,
    m, out)` on the broker's store: `meta/` is the broker's to write (Task 11). On
    `store.ErrUnavailable` it says so and tries again every 5 s, the listeners still closed, as
    the hold's loop above does. Any other error releases the hold, closes the stores, and is
    returned.


  Add to `metrics.go`:

  ```go
  	// CryptStoreKeyUnknown is 1 when port49d started on a store last written
  	// under a current key its encryption window does not hold (plan 7d):
  	// records sealed under it will not open.
  	CryptStoreKeyUnknown prometheus.Gauge
  ```

  named `port49_crypt_store_key_unknown`, registered, and named in `TestNewRegistersEveryMetric`
  (pre-flight M31).

- [ ] **Step 5: Run.**

  Run: `go test ./internal/store/... ./cmd/port49d/ -count=1`
  Expected: PASS.

- [ ] **Step 6: Commit.**

  ```bash
  gofmt -w internal/store/crypt internal/store/etcd cmd/port49d internal/daemon/metrics
  make build && make test && make vet
  git add internal/store/crypt/crypt.go internal/store/crypt/crypt_test.go internal/store/etcd/meta.go \
    internal/store/etcd/meta_test.go cmd/port49d/store.go cmd/port49d/store_test.go \
    internal/daemon/metrics/metrics.go internal/daemon/metrics/metrics_test.go
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

### Task 14: The agent's one connection: every send takes its turn, and a call behind a revocation says so

**Files:**
- Modify: `internal/agent/agent.go`
- Modify: `internal/agent/socket.go` (`Client.Token`'s and `roundTrip`'s 503)
- Test: `internal/agent/agent_test.go`

**Interfaces:**
- Consumes: the agent's `Connect` (agent.go:209), `Mint` and `post` (:295, :368), `exchange`
  (:444), `Refresh` and `refreshOnce` (:673, :698), `doOn` (:897), `Handler` and `answer`
  (:998, :1099); the test rig (`newRig`, `fakeBroker.revokeDelay`, `fakeBroker.answers`,
  `fakeBroker.addrs`, `socketFor`, which returns a `*Client`).
- Produces:
  - `type agent.RevocationRunningError struct { Since time.Time; Undone, Again, Detail string }`
  - `var wireWait = 30 * time.Second` (package variable; tests shorten it)
  - The agent's socket answers `503 revocation_running` on `/token`, `/refresh`, `/identity` and
    `/explain` behind a running revocation. `Client.Token`, `Client.Refresh` and `roundTrip`
    return `*RevocationRunningError` for it (pre-flight M42, M43).

**Every send on the held connection** (pre-flight I18). At `9cefbba` the agent sends on the
connection from four places, each taking the wire as below:
- **`Connect`** (agent.go:217, `a.do`): around its send and its body read.
- **`Mint`**, through `post` (:376, `a.do`): around each `post` and its answer's read, given
  back across each `409` Retry-After sleep (re-check m1), so a revocation never queues behind a
  mint that is only waiting. The final answer's body is read before the wire is given back.
- **`refreshOnce`** (:706 and :757, `a.do`): once, around both sends. The challenge and its
  answer share a connection (the answer is signed over that connection's exporter value), so
  nothing may run between them.
- **`exchange`** (:476, `a.doOn`): identity, explain and revoke. A revocation is the exchange
  with `unanswered` set.

`do` and `doOn` themselves take nothing, so a send reached by any other path is a compile-time
search away: Step 2 ends with that grep.

- [ ] **Step 1: The failing tests.** Append to `internal/agent/agent_test.go`:

  ```go
  // revokeHolding starts a revocation the fake broker answers only after
  // delay, and returns once it holds the agent's connection.
  func revokeHolding(t *testing.T, r *rig, delay time.Duration) <-chan error {
  	t.Helper()
  	r.fb.mu.Lock()
  	r.fb.answers = map[string]refusal{"/v1/tokens/revoke": {status: 200}}
  	r.fb.revokeDelay = delay
  	r.fb.mu.Unlock()
  	revoked := make(chan error, 1)
  	go func() {
  		_, err := r.a.Revoke(context.Background(), api.RevokeRequest{Mine: true})
  		revoked <- err
  	}()
  	deadline := time.Now().Add(5 * time.Second)
  	for r.a.revoking.Load() == 0 {
  		if time.Now().After(deadline) {
  			t.Fatal("the revocation never took the wire")
  		}
  		time.Sleep(5 * time.Millisecond)
  	}
  	return revoked
  }

  // A mint behind a revocation that holds the agent's one connection waits
  // its own budget, then says the revocation is still running and nothing
  // was minted, never that the broker is unreachable; it sends nothing
  // (plan 7d, Ruling 15; 7c final review).
  func TestAMintBehindARunningRevocationSaysSo(t *testing.T) {
  	defer func(d time.Duration) { wireWait = d }(wireWait)
  	wireWait = 200 * time.Millisecond
  	r := newRig(t)
  	revoked := revokeHolding(t, r, 2*time.Second)
  	start := time.Now()
  	_, err := socketFor(t, r.a).Token(context.Background(), TokenRequest{Device: "leaf1"})
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

  // A refresh, an identity and an explain behind a running revocation say
  // the same, through the socket, never as the broker failing (pre-flight
  // I18, M43).
  func TestEveryCallBehindARunningRevocationSaysSo(t *testing.T) {
  	defer func(d time.Duration) { wireWait = d }(wireWait)
  	wireWait = 200 * time.Millisecond
  	r := newRig(t)
  	revoked := revokeHolding(t, r, 2*time.Second)
  	c := socketFor(t, r.a)
  	for name, call := range map[string]func() error{
  		"refresh":  func() error { _, err := c.Refresh(context.Background()); return err },
  		"identity": func() error { _, err := c.Identity(context.Background()); return err },
  		"explain": func() error {
  			_, err := c.Explain(context.Background(), api.ExplainRequest{Device: "leaf1", Command: "show version"})
  			return err
  		},
  	} {
  		var running *RevocationRunningError
  		if err := call(); !errors.As(err, &running) || !strings.Contains(err.Error(), "is still running on the broker") {
  			t.Errorf("%s behind a revocation: %v", name, err)
  		}
  	}
  	r.fb.mu.Lock()
  	sent := len(r.fb.addrs["/v1/refresh/challenge"]) + len(r.fb.addrs["/v1/identity"]) + len(r.fb.addrs["/v1/explain"])
  	r.fb.mu.Unlock()
  	if sent != 0 {
  		t.Fatalf("%d call(s) were sent behind the revocation", sent)
  	}
  	if err := <-revoked; err != nil {
  		t.Fatal(err)
  	}
  }

  // A mint waiting out a 409's Retry-After holds no turn on the connection:
  // a revocation sent meanwhile goes at once, not after the mint's sleep
  // (re-check m1).
  func TestARevocationIsNotQueuedBehindAMintsWait(t *testing.T) {
  	r := newRig(t)
  	r.fb.mu.Lock()
  	r.fb.inProgress = 1 // one 409 idempotency_in_progress, Retry-After: 1
  	r.fb.answers = map[string]refusal{"/v1/tokens/revoke": {status: 200}}
  	r.fb.mu.Unlock()
  	minted := make(chan error, 1)
  	go func() {
  		_, err := r.a.Mint(context.Background(), "leaf1", false, 0)
  		minted <- err
  	}()
  	deadline := time.Now().Add(5 * time.Second)
  	for {
  		r.fb.mu.Lock()
  		n := len(r.fb.keys)
  		r.fb.mu.Unlock()
  		if n == 1 {
  			break
  		}
  		if time.Now().After(deadline) {
  			t.Fatal("the mint was never answered 409")
  		}
  		time.Sleep(5 * time.Millisecond)
  	}
  	start := time.Now()
  	if _, err := r.a.Revoke(context.Background(), api.RevokeRequest{Mine: true}); err != nil {
  		t.Fatal(err)
  	}
  	if took := time.Since(start); took > 500*time.Millisecond {
  		t.Fatalf("the revocation waited %v behind a mint's Retry-After sleep", took)
  	}
  	if err := <-minted; err != nil {
  		t.Fatalf("the mint after its wait: %v", err)
  	}
  }
  ```

  The rig's `inProgress` answers that many mints `409` with `Retry-After: 1`
  (agent_test.go:204-229), and the agent sleeps `min(1s, inProgressDelayMax)`, so the revocation
  must land well inside that second.

  Use `socketFor(t, r.a)`'s client exactly as the 7c tests in this file do; its mint is
  `Client.Token(ctx, TokenRequest{…})` (socket.go:141; pre-flight M42). If `fakeBroker.addrs`
  keys a path otherwise, or `api.ExplainRequest`'s fields are named otherwise, follow the file.
  If the rig's refresh needs a challenge answer configured, configure none: nothing may reach
  the broker.

  Run: `go test ./internal/agent/ -run 'BehindARunningRevocation|NotQueuedBehindAMintsWait' -count=1`
  Expected: FAIL to build (`RevocationRunningError`, `wireWait`, `revoking` undefined). Once
  they exist, the tests fail: each call waits on the transport, and succeeds after the
  revocation or fails "unreachable".

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
     // sent, and the revocation is still the broker's to answer. Undone and
     // Again name what was not done and the command to run again; Detail is
     // the whole line, when it came back through the agent's socket.
     type RevocationRunningError struct {
     	Since         time.Time
     	Undone, Again string
     	Detail        string
     }

     func (e *RevocationRunningError) Error() string {
     	if e.Detail != "" {
     		return e.Detail
     	}
     	return fmt.Sprintf("your revocation sent at %s is still running on the broker; nothing was %s; run %s "+
     		"again once port49 revoke reports", e.Since.Local().Format("15:04:05"), e.Undone, e.Again)
     }

     // takeWire waits for the held connection. A revocation waits as long as
     // its ctx lets it and marks the wire as its own; any other call waits
     // wireWait, and if a revocation still holds it then, says so, naming
     // what it did not do (undone) and the command to run again (again).
     func (a *Agent) takeWire(ctx context.Context, revocation bool, undone, again string) error {
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
     			return &RevocationRunningError{Since: time.Unix(0, since), Undone: undone, Again: again}
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

  3. Take it at each of the four places:
     - `Connect`, after the request is built and before `a.do(req)`:
       ```go
       	if err := a.takeWire(ctx, false, "connected", "port49 login"); err != nil {
       		return api.Config{}, err
       	}
       	defer a.giveWire(false)
       ```
     - `Mint`, per send (re-check m1). Its loop becomes:
       ```go
       	var resp *http.Response
       	for wait := 0; ; wait++ {
       		if err := a.takeWire(ctx, false, "minted", "port49 token"); err != nil {
       			return api.MintItem{}, err
       		}
       		if resp, err = a.post(ctx, body, key); err != nil {
       			a.giveWire(false)
       			return api.MintItem{}, err
       		}
       		if resp.StatusCode != http.StatusConflict {
       			break // the wire is held through this answer's read, and given back below
       		}
       		var e api.Error
       		_ = json.NewDecoder(resp.Body).Decode(&e)
       		drain(resp.Body)
       		// Given back across the wait: a revocation sent now goes at once,
       		// never behind a mint that is only sleeping.
       		a.giveWire(false)
       		if e.Error != "idempotency_in_progress" || wait >= inProgressRetries {
       			return api.MintItem{}, fmt.Errorf("agent: the broker answered %s: %s %s", resp.Status, e.Error, e.Detail)
       		}
       		select {
       		case <-ctx.Done():
       			return api.MintItem{}, ctx.Err()
       		case <-time.After(retryAfter(resp.Header)):
       		}
       	}
       	defer a.giveWire(false)
       	defer drain(resp.Body)
       ```
       keeping the loop's comments as they are. The two defers run body first, wire second, so
       the final answer is read whole before another call may send.
     - `refreshOnce`, as its first lines, so the challenge and its answer are one turn:
       ```go
       	if err := a.takeWire(ctx, false, "refreshed", "port49 refresh"); err != nil {
       		return api.RefreshResponse{}, false, err
       	}
       	defer a.giveWire(false)
       ```
     - `exchange`, after the session checks and before the body is built:
       ```go
       	revocation := unanswered != nil // only Revoke passes one, and it never gets the error
       	if err := a.takeWire(ctx, revocation, "asked", "port49 "+strings.TrimPrefix(path, "/v1/")); err != nil {
       		return err
       	}
       	defer a.giveWire(revocation)
       ```
       `path` is `exchange`'s own parameter (`/v1/identity` → `port49 identity`, `/v1/explain`
       → `port49 explain`).
  4. Then check that no other send exists: `grep -n 'a\.do(\|a\.doOn(\|a\.client\.Do(\|a\.revokeClient\.Do('
     internal/agent/agent.go` must print only the four sites above, the definitions of `do` and
     `doOn`, and the `c.Do` inside `doOn`. Name each line in the report. A send this grep finds
     elsewhere takes the wire too, in this commit.

  5. In `Handler`, behind every route that calls a send:
     - `POST /token`, before `case err != nil:`:
       ```go
       		case errors.As(err, new(*RevocationRunningError)):
       			// Not the broker failing: the operator's own revocation is still
       			// running, and nothing was minted.
       			writeJSON(w, http.StatusServiceUnavailable, api.Error{Error: "revocation_running", Detail: err.Error()})
       ```
     - `POST /refresh`: the same case, before its `case err != nil:`.
     - `answer` (identity, explain, revoke), before `case errors.As(err, &refused):`:
       ```go
       	case errors.As(err, new(*RevocationRunningError)):
       		writeJSON(w, http.StatusServiceUnavailable, api.Error{Error: "revocation_running", Detail: err.Error()})
       ```
       A revocation itself never gets one (it waits as long as its ctx lets it).

  In `socket.go`:
  - `Client.Token`, before `default:`:
    ```go
    	case http.StatusServiceUnavailable:
    		var e api.Error
    		_ = json.NewDecoder(resp.Body).Decode(&e)
    		if e.Error == "revocation_running" {
    			return api.MintItem{}, &RevocationRunningError{Detail: e.Detail}
    		}
    		return api.MintItem{}, fmt.Errorf("agent: %s: %s", e.Error, e.Detail)
    ```
  - `Client.Refresh`: the same case, returning `api.RefreshResponse{}`.
  - `roundTrip`, before `case e.Error != "":`:
    ```go
    	case resp.StatusCode == http.StatusServiceUnavailable && e.Error == "revocation_running":
    		return &RevocationRunningError{Detail: e.Detail}
    ```

  `port49 token` prints a mint error as `port49 token: <err>`, so it prints the operator line from
  "What the operator sees". Check `cmd/port49/main.go`'s `tokenCmd`, and the `refresh`,
  `identity` and `explain` commands. If one prefixes or wraps the error, make sure the line still
  reads as written, and add a case to `cmd/port49/main_test.go` only if it does not.

  Run: `go test ./internal/agent/ ./cmd/port49/ -count=1`
  Expected: PASS: the three new tests and every existing agent test, 7c's
  `TestAnUnansweredRevocationIsSentOnceAndMayBeInForce` included. Its revocations run one at a
  time on the wire, as they did on the transport. `TestARevocationIsNotQueuedBehindAMintsWait`
  passes before this task too (the transport holds nothing across a sleep); it guards the wire
  against holding a turn across one.

  Mutation checks (do them, report them, revert them):
  1. Drop the wire from `refreshOnce`. `TestEveryCallBehindARunningRevocationSaysSo`'s refresh
     case must fail.
  2. In `Mint`, take the wire once before the loop and give it back by a defer, as the plan
     first had it. `TestARevocationIsNotQueuedBehindAMintsWait` must fail (re-check m1).

- [ ] **Step 3: Commit.**

  ```bash
  gofmt -w internal/agent cmd/port49
  make build && make test && make vet
  git add internal/agent/agent.go internal/agent/socket.go internal/agent/agent_test.go
  git commit -m "fix(agent): every send takes its turn on the held connection; a call behind a revocation says so

  The agent's four sends on its held connection (Connect, each of Mint's
  posts, the refresh's challenge and answer as one turn, and every
  exchange) each take a one-slot wire, and the agent knows when a
  revocation holds it; a mint gives it back across a 409's wait.
  A mint, refresh, identity or explain arriving behind one waits its own
  30s and then says the revocation is still running and nothing was
  done, never that the broker is unreachable, which a remote store made
  likely (7c final review; plan 7d, Ruling 15; pre-flight I18, M43).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 15: (lab, on beehive) L35: a hung store, the listeners closed, the store back, on five images

**Files:**
- Create: `tests/lab/store_test.go`
- Modify: `tests/lab/labpcap/pcap.go`, `stream.go` (`File.TimeOf`, `Packet.At`), and their test
  (`synth_test.go`)
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§15, L35 closed; the cells the run
  measures), `docs/design/2026-08-21-port49-design.md` (the matrix's device cells, from the notes)
- Created by the run: `tests/lab/results/L35-<platform>.md`,
  `tests/lab/evidence/L35-<platform>.pcap` (through `l.capture` and `make evidence`)

**Interfaces:**
- Consumes:
  - **The lab harness:** `eachPlatform`, `l.derivedConfig`, `l.stopDaemon`, `l.startDaemonWith`,
    `l.awaitTACACS`, `l.configPath`, `l.capture`, `l.mark`, `l.shell`, `l.loginWithin`,
    `l.waitForRecords`, `l.recordsSince`, `l.result`, `l.errLogSize`, `l.errLinesSince`,
    `pcapTACACSPackets`, `labKeyDefault`.
  - **7a's and 7c's helpers:** `revokeAgent`, `revokeOutcome`, `redeemReason`, `l29Mint`,
    `l29Cell`, `sha`, `summarize`, `platformSessionAttributes`, `slicePKIDir`, `sliceEmail`,
    `sliceUser`, `breakglassUser`, `breakglassPassword`.
  - **The store:** `etcdtest.Start`, `(*Server).EnableAuth`, `(*Server).ClientFiles`,
    `etcdtest.NewProxy`, `etcd.Roles`, `etcd.RoleDaemon`, `etcd.RoleBroker` (Tasks 5, 11).
- Produces: `func TestStoreOutageEndToEnd(t *testing.T)`, its notes, and `labpcap`'s packet times.

**What it measures** (L35, opened by Task 8b). The store is a real etcd member, with TLS and
port49's roles, inside the lab test process. port49d reaches it through an in-process proxy the
test hangs (Ruling 16), with `hold_ttl: 60s`. The window before port49d closes its listeners is
at least a sixth of that, 10 s, and usually 20 to 50 s (re-check R-I4), so step 3 takes each
measurement on a hang of its own, the store returned between them. On each image:

1. **Baseline on etcd.** alice logs in with a token, and `show version` runs.
2. **A restart.** port49d stops and starts on the same store.
   - **Non-Junos:** the open session's next command runs, answered from its context. The record
     is `authorize_command permit context_matched` with the session's `ctx_id` from before the
     restart.
   - **Junos (vJunos-router, vSRX):** the session runs on, as it does with port49d stopped.
   - **Every image:** a token minted before the restart is refused `token_not_found`, and port49d
     says it purged it.
3. **The store hangs.** The proxy stops forwarding. Each request's time from the device's send to
   port49d's reply is taken from the capture, against the device's own timeout (L4, L13), never
   from the test's clock (pre-flight I17).
   - **Non-Junos:** the open session's next command is refused. Recorded: its request-to-reply
     time, what the device printed, and the record, which must be `authorize_command deny
     store_unavailable`.
   - **Every image:** a new token login is refused. Recorded: its request-to-reply times and the
     record, which must be `redeem error store_unavailable`.
   - **Break-glass** is tried and recorded as measured: logged in or not, a command or not,
     compared with `tests/lab/results/L4-error-<platform>.md`.
   - **Valid only before the listeners close.** Each of step 3's hangs ends before port49d says
     it is closing its listeners. Otherwise that cell measured port49d dark, not a hung store,
     and is marked invalid in the note.
4. **port49d closes its listeners.** On a fresh hang, within `hold_ttl` + 30 s, port49d's stderr says
   it is closing every listener, and that it waits for the store. It does not exit.
   - The open session's next command runs or does not, under local authorization. It is
     compared with `quarantine-<platform>.md` where one exists; vSRX has none, and the cell says
     so.
   - Break-glass logs in, timed.
5. **The store returns.** The proxy resumes, and the same port49d process listens again on its
   own. Its stderr says purged and carried.
   - **Non-Junos:** the open session's next command runs, answered from its context with the
     same `ctx_id`.

- [ ] **Step 0: The lab instructions** (pre-flight M45). Before dispatching this task, the
  controller confirms that `.superpowers/sdd/2026-10-02-07d-shared-store/lab-instructions.md` is
  7d's. It must:
  - name this task and the five images;
  - say to close L35 in spec §15 (CLAUDE.md lab rule 3) only once every image has measured;
  - say a lowered `packet_deadline` default is its own `fix(config):` commit.

  This amendment rewrote it; check it has not drifted.

- [ ] **Step 1: The capture's clock, and the test.**

  1. **`labpcap`'s packet times.** A pcap record header holds the capture time
     (`ts_sec`, then `ts_usec`, or `ts_nsec` for a nanosecond savefile, in the byte order the
     magic number gave). Read `pcap.go` and `stream.go` first, then add:
     - `func (f *File) TimeOf(rec int) time.Time`;
     - `At time.Time` on `Packet`: the capture time of the record holding the packet's last
       byte. A stream's `Segments` map stream offsets to records; the earliest copy of a
       duplicated segment is the one that counts.

     Add a case to `synth_test.go` that synthesizes two records a known interval apart and
     asserts the packets' `At` differ by it.
  2. **The test.** Create `tests/lab/store_test.go`:

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
  	"github.com/rhwendt/port49/internal/tacacs/wire"
  	"github.com/rhwendt/port49/internal/testpki"
  )

  const storeClaim = "When port49d's store hangs (etcd cut off from port49d), port49d answers a command FAIL " +
  	"store_unavailable and a login ERROR store_unavailable within store.packet_deadline (2s), before the " +
  	"device's own TACACS+ timeout, and the device acts as on L4's store outage, never as on a silent server; " +
  	"once port49d closes its listeners on losing the store (store.etcd.hold_ttl), the device acts as with " +
  	"port49d stopped and break-glass logs in; and once the store returns and port49d listens again, an open " +
  	"session's next command is answered from the context the store kept (plan 7d; spec §13 decision 35)."

  // storeLab is the lab's etcd: a TLS member with port49's roles, behind a
  // proxy the test hangs, and the store: block (with the admin_socket etcd
  // requires) that points port49d at it.
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

  // reasonsOf is every (event, verdict, reason) among recs, for asserting
  // what a hung store answered.
  func reasonsOf(recs []map[string]any, event string) []string {
  	var out []string
  	for _, r := range recs {
  		if r["event"] == event {
  			out = append(out, fmt.Sprintf("%v %v", r["verdict"], r["reason"]))
  		}
  	}
  	return out
  }

  // replyTimes is, for every request the device sent at or after from,
  // the time from its send to port49d's reply, as the capture saw them:
  // the reply is the next packet on the reverse stream with the request's
  // session_id and its seq_no plus one. A request with no reply is listed
  // as unanswered.
  func replyTimes(path, key string, from time.Time) []string {
  	pkts, _, err := pcapTACACSPackets(path, key)
  	if err != nil {
  		return []string{"capture unreadable: " + err.Error()}
  	}
  	var out []string
  	for i, p := range pkts {
  		if !p.FromDevice || p.At.Before(from) {
  			continue
  		}
  		answered := false
  		for _, q := range pkts[i+1:] {
  			if !q.FromDevice && q.Conn == p.Conn && q.Header.SessionID == p.Header.SessionID &&
  				q.Header.SeqNo == p.Header.SeqNo+1 {
  				out = append(out, fmt.Sprintf("%s %s", wire.TypeName(p.Header.Type), q.At.Sub(p.At).Round(time.Millisecond)))
  				answered = true
  				break
  			}
  		}
  		if !answered {
  			out = append(out, fmt.Sprintf("%s unanswered", wire.TypeName(p.Header.Type)))
  		}
  	}
  	return out
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
  		block += "admin_socket: " + filepath.Join(t.TempDir(), "admin.sock") + "\n" // etcd requires one (Ruling 13)
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
  		capPath := filepath.Join(root, "tests", "lab", "captures", "L35-"+l.p.name+".pcap")

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

  		// 3. The store hangs. Every time below that a device sees is the
  		// capture's, request to reply (pre-flight I17). Each measurement
  		// gets its own hang, the store back between them: the fence counts
  		// the hold lost as soon as a sixth of hold_ttl after a hang begins
  		// (10s at 60s; re-check R-I4), and a login or a break-glass login
  		// can take most of that on its own.
  		_, tok3 := l29Mint(sock, l.p.node)
  		off = l.mark()
  		firstHang := time.Now()
  		var berr error
  		hang := func(what string, measure func()) {
  			errOff = l.errLogSize()
  			proxy.Hang(true)
  			measure()
  			proxy.Hang(false)
  			// Valid only if port49d had not gone dark yet: otherwise the cell
  			// measured port49d with its listeners closed (pre-flight I17).
  			if dark := l.errLinesSince(errOff, "closing every listener"); len(dark) > 0 {
  				row("3. validity", "INVALID: port49d closed its listeners before "+what+" ended ("+dark[0]+")")
  				fail("step 3 (%s) overran the window before port49d closed its listeners; its cell is invalid", what)
  			}
  			// The circuits' probes, and the fence's next answered read.
  			time.Sleep(15 * time.Second)
  		}
  		if !sessionOnly {
  			hang("the open session's command", func() {
  				hung := revokeOutcome(l.p.name, sh, "show version", fail, "with the store hung")
  				row("3. store hung, the open session's `show version`", hung)
  				if !strings.HasPrefix(hung, "refused") {
  					fail("with the store hung the next command was not refused: %s", hung)
  				}
  			})
  		}
  		hang("the token login", func() {
  			_, lerr := l.loginWithin(sliceUser, tok3, 60*time.Second, "show version")
  			row("3. store hung, a token login", fmt.Sprint(lerr))
  			if lerr == nil {
  				fail("a token login succeeded with the store hung")
  			}
  		})
  		hang("break-glass", func() {
  			_, berr = l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version")
  			row("3. store hung, break-glass and `show version`",
  				fmt.Sprintf("%v (compare tests/lab/results/L4-error-%s.md)", berr, l.p.name))
  		})
  		recs = l.waitForRecords(off, 20*time.Second, func([]map[string]any) bool { return true })
  		row("3. records", summarize(recs))
  		cmds, redeems := reasonsOf(recs, "authorize_command"), reasonsOf(recs, "redeem")
  		if !sessionOnly && !contains(cmds, "deny store_unavailable") {
  			fail("no command was answered deny store_unavailable with the store hung: %v", cmds)
  		}
  		if !contains(redeems, "error store_unavailable") {
  			fail("no login was answered error store_unavailable with the store hung: %v", redeems)
  		}
  		l.flushCapture(t)
  		row("3. request-to-reply, from the capture", strings.Join(replyTimes(capPath, labKeyDefault, firstHang), "; "))

  		// 4. port49d closes its listeners on losing the store, and stays up.
  		errOff = l.errLogSize()
  		proxy.Hang(true)
  		hungAt := time.Now()
  		for time.Since(hungAt) < 90*time.Second && len(l.errLinesSince(errOff, "closing every listener")) == 0 {
  			time.Sleep(time.Second)
  		}
  		dark := l.errLinesSince(errOff, "closing every listener")
  		row("4. port49d's line", fmt.Sprintf("%s (%s after the hang)", strings.Join(dark, " / "),
  			time.Since(hungAt).Round(time.Second)))
  		if len(dark) == 0 {
  			fail("port49d did not close its listeners within 90s of the hang")
  		}
  		time.Sleep(5 * time.Second) // the drain
  		if len(l.errLinesSince(errOff, "waiting for the store again")) == 0 {
  			fail("port49d did not say it waits for the store")
  		}
  		quarantine := "compare tests/lab/results/quarantine-" + l.p.name + ".md"
  		if _, err := os.Stat(filepath.Join(root, "tests", "lab", "results", "quarantine-"+l.p.name+".md")); err != nil {
  			quarantine = "no quarantine note for this image"
  		}
  		stopped := revokeOutcome(l.p.name, sh, "show version", func(string, ...any) {}, "with the listeners closed")
  		row("4. listeners closed, the open session's `show version`", stopped+" ("+quarantine+")")
  		_, berr = l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version")
  		row("4. listeners closed, break-glass and `show version`", fmt.Sprint(berr))
  		if berr != nil {
  			fail("break-glass did not log in with port49d's listeners closed: %v", berr)
  		}

  		// 5. The store returns; the same port49d listens again, unprompted.
  		errOff = l.errLogSize()
  		proxy.Hang(false)
  		for i := 0; i < 120 && len(l.errLinesSince(errOff, "listening on")) == 0; i++ {
  			time.Sleep(time.Second)
  		}
  		if err := l.awaitTACACS(); err != nil {
  			t.Fatalf("port49d did not listen again after the store returned: %v", err)
  		}
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

  func contains(list []string, s string) bool {
  	for _, x := range list {
  		if x == s {
  			return true
  		}
  	}
  	return false
  }
  ```

  Read each consumed helper before relying on it:
  - `l.result`'s note format is 7c's.
  - `l.flushCapture` (capture_test.go:130) makes the capture's bytes so far readable.
  - `wire.TypeName` stands for however the wire package names a packet type; use what it has, or
    `fmt.Sprint(p.Header.Type)`.
  - `pcapTACACSPackets` decodes with the lab's key (`labKeyDefault`, harness_test.go:130).
  - If a helper is named otherwise, use its name and say so.

  The harness's `stopDaemon` already treats a port49d that exited on its own as stopped
  (`harness_test.go:1337-1343`). A store gone no longer exits, and the test relies on that.

  Run: `go vet -tags lab ./tests/lab/` (clean) and `go test ./tests/lab/labpcap/ -count=1`
  (PASS). Then commit the test, so the pinned worktree runs it (pre-flight I17):

  ```bash
  gofmt -w tests/lab/store_test.go tests/lab/labpcap
  git add tests/lab/store_test.go tests/lab/labpcap/pcap.go tests/lab/labpcap/stream.go tests/lab/labpcap/synth_test.go
  git commit -m "test(lab): L35, a hung store, the listeners closed, the store back

  Five images; each request's time taken from the capture (labpcap
  gains a packet's capture time); step 3 marked invalid if port49d went
  dark before it ended (plan 7d Task 15).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

  Then, on beehive, from a worktree pinned to that commit, one platform at a time:

  ```bash
  PORT49_LAB_PLATFORMS=eos go test -tags lab ./tests/lab/ -run TestStoreOutageEndToEnd -count=1 -timeout 60m -v
  ```

  then `nxos`, `iosxe`, `vjunos`, `vsrx`, under the watchdog.

- [ ] **Step 2: Read the notes, then close L35.** Read each `tests/lab/results/L35-<platform>.md`.
  For each image, the row closes with:
  - its version;
  - each request-to-reply time with the store hung, against the device's timeout (L4, L13);
  - what it printed;
  - what break-glass did while the store hung and once the listeners closed;
  - the delay to the listeners closing;
  - whether the session came back on its context.

  Then:
  - **If a device timed out before port49d's answer arrived** (a reply later than the device's
    timeout in the capture, or the device's own timeout text), `store.packet_deadline`'s default
    is wrong for that image. Lowering it is code (pre-flight M48):
    - its own `fix(config):` commit on the branch, before this one;
    - the default stays at least `call_timeout`;
    - decision 35 says so;
    - and every image is re-run, not only that one, since the default is fleet-wide.
  - **If a note contradicts a doc,** the doc is wrong (CLAUDE.md lab rule 4). Fix the doc and cite
    the note.
  - **Step 3 invalid.** If a note marks step 3 invalid, re-run that image. A cell measured with
    the listeners closed is not a hung-store cell.

  Close the row only if all five images measured (CLAUDE.md lab rule 3: a row with one platform
  open stays open).

  Edit L35's status cell to `closed — measured <date>; tests/lab/results/L35-arista_eos.md,
  L35-cisco_nxos.md, L35-cisco_iosxe.md, L35-juniper_vjunos-router.md, L35-juniper_vsrx.md`,
  followed by the per-image summary. Fill the device cells of design §12's three store rows
  (Task 8b) from the notes, each citing its note. Then:

  ```bash
  cp ../port49-lab-7d/tests/lab/captures/L35-* tests/lab/captures/   # from the worktree, before removing it
  make evidence
  git add tests/lab/results/L35-*.md tests/lab/evidence/L35-*.pcap \
    docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
  git commit -m "docs: close lab register entry L35 (the store hangs, the listeners close, the session returns)

  <one line per image: request-to-reply times, what it printed,
  break-glass, the delay to the listeners closing, the session's return>

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

  If the harness changed (`harness_test.go`), add it to the `git add`, by path. If the test changed
  after Step 1's commit, commit it first in its own `test(lab):` commit, as 7c's lab commits did.

---

### Task 16: Plan 7d as built

**Files:**
- Modify: `docs/superpowers/plans/README.md`
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`, `docs/design/2026-08-21-port49-design.md`,
  where a task's as-built drift needs it, and the restart note below

- [ ] **Step 1: The roadmap** (pre-flight M8).
  - **"Plan 7d — As built".** After "Plan 7d-1 — As built" (Task 8 Step 6), add 7d-2's in 7c's
    form:
    - task by task, what differs from this plan's text, with commits;
    - the rulings as made;
    - L35 per image;
    - the operator notes (the section below, amended by what was built);
    - "Carried, for later plans", and "Unassigned follow-ups".
  - **The 7d bullet** (README:1547): add `**As built:** see "Plan 7d — As built"`, as 7c's bullet
    has.
  - **The status line.** Change it to say 7d-1 and 7d-2 executed and merged, with their PRs.
  - **What to carry:**
    - **7e:**
      - `b.superseded`, `b.blobsSeen` and `quarantineRecorded` into the store, and m10's bound on
        `b.superseded`;
      - more than one port49d per keyspace (the hold becomes per broker process, and the daemons
        hold none);
      - the listener's marks and the daemon's (`store.Marks`) shared across replicas, through a
        watch on the marks family;
      - the ledger (`crypt.Ledger`) shared across replicas or replaced, since per process it
        would deny another replica's logins (re-check IA1);
      - `broker.revocations_file` retired;
      - one refresh runner;
      - the decision-log emits under a policy hold (4b Task 4).
    - **7f:**
      - go-dark proper, replacing Ruling 11's coarse close-and-wait with the N-failures/M-passes
        listener control;
      - the warm context cache.
    - **12:**
      - the etcd deployment artifacts (members, compaction, quota, the roles applied from `port49d
        store-roles`);
      - `call_timeout`, `bulk_timeout` and `packet_deadline` sized against load;
      - the store alarms, a client certificate's expiry among them.
  - **Unassigned follow-ups:**
    - 7c's M3 (a `revoke` record for a mark that could not be written), unchanged;
    - the bulk lift (7c), unchanged;
    - **new, Ruling 17's residual** (its table, exactly): with a stolen daemon store credential,
      - **across a restart, impersonation:** another login's context put back while port49d
        was stopped is taken as that key's at the start, until its sealed ceiling, if it has
        one, or the key's next login;
      - **while port49d runs:** an earlier version of a key's own context put back, undoing a
        revocation that leaves no mark (self or key) or a policy narrowing until the next
        refresh;
      - a deleted token put back for a holder of its secret, until its sealed expiry;
      - a receipt's sliding bound stretched to its sealed cap;
      - a context kept alive past its idle TTL, to its sealed ceiling if it has one, and
        indefinitely under `max_session_age: never`;
      - a context hidden from the index until the next sweep re-indexes it, during which a
        revocation by sid does not reach it.

      Closing it needs a revocation record the daemon's role cannot write for every kind (a
      spec change to decision 34), and a sealed freshness counter checked across restarts (a
      write sequence the broker's role keeps per key, which 7e's shared ledger could become).
- [ ] **Step 2: Docs drift.**
  - **The restart note** (pre-flight M7). In spec §15, the Junos `authorization-time-interval`
    note says a port49d restart denies every live Junos session's next re-authorization, because
    the context store is in memory (find `A port49d restart denies every live Junos session`,
    spec:8278).
    - Qualify it as the memory backend's: `**On the memory store, a port49d restart denies every
      live Junos session's next re-authorization.**`.
    - Add a sentence: `On etcd (plan 7d) the store keeps the contexts across a restart, and
      whether a Junos session's next re-authorization is then answered from its context is §15
      L35's (tests/lab/results/L35-juniper_vjunos-router.md, L35-juniper_vsrx.md).`
  - **Each task's drift.** If any task's report says a block was changed against this plan's
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
- **A session whose principal or certificate a mark names is denied on its next command,**
  `credential_revoked`, whatever its stored context says.
- **The context is sealed whole.** A context record's privilege, policy, ceiling, clocks and
  revocation are now sealed with its identity, bound to its key. No setting changes.
  - The restart that installs 7d-1 ends every live session, as every restart on memory does:
    operators log in again.
  - A store dump shows only `revoked_at`, the revisions, the idle clock and accounting's
    annotations in the clear.
- **A token's policy and clocks, and a receipt, are sealed too.** A token's kind, expiry,
  policy blob, session age, enable mechanism, maximum privilege and clocks are sealed with its
  secret, bound to its device, username and ID; a receipt is bound to its device, username,
  kind and credential. A token or receipt edited in the store does not open: the token is
  dropped (`token_not_found`), and `port49_crypt_open_failures_total{record}` counts it.
- **A context written back over another login's is denied.** port49d remembers the `ctx_id`
  it last wrote at each device and username; a different one there is `store_unavailable`,
  counted as `port49_crypt_open_failures_total{record="context"}`, until the next login.
- `port49_store_operations_total{op}` no longer counts `index_context`, `unindex_context` or
  `unindex_ref` on the login path. Those are now part of `join_context`.

**7d-2:**

- **New: `store:` in `port49d.yaml`.** `backend: memory` stays the default.
  - **Turning on etcd.** Set `backend: etcd` with `store.etcd`:
    - endpoints `https` only, and `ca_file`;
    - a client certificate each for `daemon` and `broker` (CN = etcd user), the key files owned
      by port49d's user, mode 0600, and not symlinks.

    `admin_socket` must be set too. Run `port49d store-roles --config …` and apply its output
    once as etcd's root.
  - **Knobs and defaults:**
    - `call_timeout` 500ms, `bulk_timeout` 30s;
    - `packet_deadline` 2s (at most 2s: Junos times out at about 3s, L13);
    - `breaker` 5 failures and 5s open;
    - `max_in_flight` 64 token, 128 context, 4 bulk;
    - `lease_grace` 5m, `start_timeout` 30s (`0` waits forever), `hold_ttl` 15s, `sweep_interval`
      10m.
- **etcd itself.** Run three or five members in the devices' region, with:
  - client-certificate auth and auth enabled;
  - `--auto-compaction-mode=periodic --auto-compaction-retention=1h`, and defragmentation;
  - a quota above the live records.
- **Who may write etcd.** The daemon's client certificate can write tokens, receipts, contexts
  and the index. With it alone, a thief can replay records port49 sealed, never forge them:
  while port49d runs, an earlier version of a session's own context; across a port49d
  restart, another login's context put back while port49d was stopped (impersonation until
  that session's ceiling or its device's next login). Protect the daemon's key like the
  encryption key. After a suspected theft, have etcd stop trusting that certificate (a new
  CN, granted the daemon's role, and the old user deleted) before port49d next restarts.
- **Backups.**
  - **Back etcd up** as you would the revocations file.
  - **Protect every snapshot as the store itself.** It holds who is logged into which device
    (the plaintext index; design §8).
  - **A restored snapshot** brings back the contexts it held. One ended by a principal or
    certificate revocation is denied again at once, by the marks. One ended by `port49 revoke
    --mine`, or by `(device, username)`, is live again until its idle TTL: revoke it again after
    a restore.
  - **A restore rolls the marks back too:** a revocation added since the snapshot is gone from
    etcd, and one lifted since is back. Restore with port49d stopped. Its start puts the
    revocations file's marks back into etcd, applies every mark to the restored sessions, and
    purges every unspent token, so a token redeemed since the snapshot cannot be redeemed
    again. Then `port49 revoke --lift` again any revocation lifted since the snapshot.
  - **Restore with `etcdutl snapshot restore --bump-revision 1000000000 --mark-compacted`**
    (both in etcdutl v3.6.15). A billion is far above the writes since any snapshot worth
    restoring, so etcd never reuses a revision port49 has seen for another write.
- **One port49d per keyspace until plan 7e.** A second one waits and is not ready. On
  Kubernetes use `strategy: Recreate`. Never delete `meta/hold` by hand: stop the port49d that
  holds it.
- **What a restart does now.**
  - Live sessions survive. Every standing revocation is applied to them first, so a mark added
    to the file with port49d stopped takes effect before it serves. Each is then carried onto the
    policy in force, and the next command is answered from the kept context (L35).
  - Unspent tokens are purged (`port49d: store: purged N unspent token(s) …`), so run `port49
    token` again. A retried `port49 token` with the same idempotency key mints afresh.
    - **The replay's caveat.** That relies on this port49d's clock. If port49d moves to a host
      whose clock is behind the old one's, a replay inside the skew can still be answered from
      before.
    - **A pending reservation.** One a stopped port49d left blocks its key for up to a minute.
  - **On etcd, editing `broker.revocations_file` with port49d stopped no longer lifts a mark:**
    the store's copy comes back. Lift with `port49 revoke --lift` on the admin socket.
- **What an etcd outage does.**
  - **At start:** nothing listens, and `/readyz` says `waiting for the store`. Devices use their
    local method, and break-glass works. port49d waits up to `start_timeout`, then exits 1; with
    `0` it waits for as long as it takes.
  - **While running:**
    - Commands are refused `store_unavailable` within `packet_deadline`, and at once after the
      circuit opens (`port49_store_circuit_open` 1). Break-glass is refused (L4).
    - After `hold_ttl`, port49d closes every listener, resets every held TACACS+ connection,
      says why, and devices fall to local, so break-glass works. It does not exit.
    - It waits for etcd itself, then serves again, and sessions resume on their contexts. If
      that start fails for another reason (a policy file caught half-written), it says so and
      tries again every 5 s; it does not exit. L35 has the per-image detail.
    - **Keep `Restart=on-failure` anyway.** It is still what restarts port49d after a crash, or
      after a cold start that exits 1 (a configuration fault, or `start_timeout`).
    - **Metrics between runs.** `/healthz`, `/readyz` and `/metrics` are unbound for the drain
      and the next config load (seconds), and the counters restart. Give a Kubernetes
      liveness probe a failure window over 30 s.
  - **A store slow but up** does the same once its token or context calls keep missing their
    deadlines. So does etcd refusing every such call (a role removed): a steady run of
    refusals, not two an hour apart.
  - **Slow scans** (the refresh's, a large purge) open only the bulk pool's circuit
    (`port49_store_circuit_open{pool="bulk"}` 1, and a line saying logins and commands are
    unaffected). port49d keeps serving. Alert on it, and size `bulk_timeout`.
  - **A wrong token's FAIL** arrives at the failure delay even with a slow store: the store's
    time is inside the delay, so at most 2 s at the defaults.
- **Certificates.**
  - Each start prints each client certificate's expiry, and
    `port49_store_client_cert_expiry_timestamp_seconds{component}` carries it.
  - An expired or untrusted certificate is named, never reported as etcd not answering.
  - After an outage, a renewed certificate file is picked up without a restart.
- **New metrics:**
  - `port49_store_calls_total{component,pool,outcome}`, `port49_store_call_seconds{component,pool}`,
    `port49_store_circuit_open{component,pool}` (pools `token`, `context`, `bulk`; outcomes include
    `deadline` and `refused`);
  - `port49_store_keyspace_held`, `port49_store_client_cert_expiry_timestamp_seconds{component}`,
    `port49_crypt_store_key_unknown`, `port49_contexts_reindexed_total`.

  Alert on any of:
  - a circuit open;
  - any increase of `port49_contexts_reindexed_total`: an index record was deleted in etcd, and
    the context it hid has been re-indexed (each sweep, `sweep_interval`);
  - any increase of `port49_crypt_open_failures_total{record="context"}` with the key held: a
    record altered in etcd, or another login's written back;
  - `port49_store_keyspace_held` 0 while port49d runs;
  - a client certificate within 30 days of expiry;
  - `port49_crypt_store_key_unknown` 1;
  - any `increase(port49_crypt_open_failures_total{record="token"}[10m])`.
- **Key rotation across a restart.** Keep `encryption.previous` until the old key's records
  expire. A start that finds the store last written under a key it does not hold says so, and
  sets `port49_crypt_store_key_unknown` to 1. A record that will not open is named by its key id
  on stderr, once per 10 minutes.
- **A wrong `PORT49_ENC_V1` never revokes.** Sessions sealed under a key port49d does not hold
  are denied `store_unavailable`, and the re-index and the refresh say each by device and
  username, count it (`port49_contexts_reindex_failures_total`, the refresh's `failed`) and
  leave it; `port49_policy_refresh_pending` stays 1. Fix the key and restart, and those
  sessions answer again. A record that fails authentication, or is another login's written
  back, is tampered and is still revoked.
- **A session record that does not decode** (a `c/` value garbled in etcd) is unreadable, as
  one that will not open is: the next login on that device and username replaces it, and the
  refresh and the re-index delete it at the revision they read, since nothing can revoke or
  use it. It is said by its key alone, never its value.
- **A `port49 token`, refresh, identity or explain behind a slow `port49 revoke`** now says `your
  revocation sent at … is still running on the broker; nothing was minted; run port49 token again
  once port49 revoke reports` (exit 1), not `the broker … is unreachable`.
- **New command: `port49d store-roles [--config FILE]`.**

## Self-review against the spec

**Coverage.** Each item the roadmap and the carries name, and the task that builds it:

- **The 7d bullet:**
  - **"the backend D1 chooses, implementing every store method with its atomicity and passing
    every storetest property, 7a's included"** — Tasks 5–8. `TestTheEtcdStoreHoldsEveryProperty`
    runs `storetest.Run`, which holds 7a's (`IdempotencyReservesOnce`, `IdempotencyLeaseExpires`,
    `TokenIndex`, `RevocationMarks`), 7c's, the lifted thirty-one (Task 2), and 7d's own.
  - **"store-native mutual-TLS authentication per component"** — Task 11 (identities and roles),
    Task 12 (two stores in port49d; certificates checked and named).
  - **"a hard timeout and a circuit breaker on every store call, and pool separation"** — Task 9
    (guard, three pools); Task 11 (two connections).
  - **"plan 4b's remote-store items":**
    - a deadline on each refresh and per-packet store call: Task 9 (`call_timeout`,
      `bulk_timeout`) and Task 10 (`packet_deadline`);
    - the settle pass's redeem-to-write: Task 10, `packet_deadline` ≤ 2 s ≪ 30 s;
    - unindexed contexts invisible to the refresh: Tasks 3–4 (`SwapLogin`).
  - **"PR #7's third follow-up"** — Tasks 3–4; `LoginsRaceToOneIndex`.
  - **"the crypt_open_failures_total{record="token"} alarm"** — Task 13; the design §15 alert,
    Task 8b.
- **7a's carry:**
  - **"IdempotencyReservesOnce, TokenIndex, RevocationMarks for the chosen backend"** — Task 8.
  - **"whether broker.revocations_file stays"** — Ruling 13, Tasks 10 and 12.
  - **"the revocation's residual window … closed atomically"** — Tasks 3–4;
    `JoinHonoursAStandingMark`; §5.1.4 (Task 1); and the daemon's marks (Task 4b).
- **7c's carry:**
  - **"DeleteTokenRemovesOne and DeleteTokenRacesRedeem on the etcd backend; its M-2 case"** —
    Task 5 (Ruling 3: the expired put is accepted; no clock-advancing constructor needed).
  - **"DeleteToken's index semantics"** — Ruling 5; Task 5 (`DeleteToken` never prunes).
  - **"the self-revocation's compare-and-set on the backend's SetContextPolicy"** —
    `SelfRevocationBindsToTheRead` (Task 3), run on etcd from Task 6, and through the sealing
    layer's rewrite (Task 4b).
  - **"the agent's single held connection"** — Task 14, every send.
- **The pre-flight review** — every finding, in "Pre-flight resolution": C1 (Task 12), I12 (Task
  4b), I19 (Task 12), and the rest where the table says.
- **Its re-check** — every finding, in that section's "Re-check 1" table: CA1 and IA1 (Task 4b),
  IA2 (new Task 7b, wired in Task 12), N1 (Task 10), R-I2 to R-I4 (Task 12), R-I5 (Task 9), and
  each Minor where its row says.
- **Design §12 "Store health MUST NOT be wired into the readiness probe":** kept.
  - The metrics `/readyz` and the broker's `/readyz` read nothing of the store's health.
  - A store gone ends a run: the listeners close and `/readyz` says the TACACS+ listener is
    closed while port49d waits. That is serving or not, the line §12 allows, not the store's
    health, and it is the owner's go-dark ruling in its coarse form.
- **Device behaviour:** L35, opened in Task 8b and closed in Task 15.

**Placeholders.** Five places name a helper to read rather than reprinting its code, because the
code is in the tree and the plan must not drift from it:
- Task 2's verbatim move, with its substitution rules;
- Task 4b's two authen tests, built from the file's enable and replay tests;
- the run-test helpers in Task 12;
- the lab helpers in Task 15, and `labpcap`'s record reading.

Every new function is written out. The guard's forty-four pass-throughs are shown by pattern with
three examples, and pinned by `TestEveryMethodIsRoutedToItsPool` and
`TestTheGuardHoldsEveryProperty`. `notbuilt.go` lists every stub by name and is pinned by the
interface assertion.

**Types.** These names are the same in every task that uses them:
- `store.LoginWrite`, `store.MarkRead`, `store.LoginIndex`, `store.SwapLogin`,
  `store.PurgeTokens`, `store.RewriteContext`, `store.ErrUnavailable`, `store.ErrRefused`,
  `store.BlankCertKey`, `store.CheckRevocation`;
- `store.Apply*`, `store.CheckContextPolicy`, `store.Marks`, `store.NewMarks`;
- `crypt.Keys.SealBound`, `crypt.Keys.OpenBound`, `crypt.Option`, `crypt.WithLedger`,
  `crypt.Ledger`, `crypt.NewLedger`, `crypt.ErrNotLastWritten` (Task 4b), `crypt.OnUnopenable`,
  `crypt.SealedKeyID` (Task 13);
- `etcd.Config`, `etcd.Open`, `etcd.ErrRefused`, `etcd.ErrTooLarge`, `etcd.Roles`, `etcd.Grant`,
  `etcd.RoleDaemon`, `etcd.RoleBroker`, `(*etcd.Store).CheckIdentity`, `Hold`, `Sweep`,
  `Unindexed`, `SealKeys`, `PutSealKeys`;
- `session.Manager.Reindex`, `Metrics.ContextsReindexed`;
- `guard.Wrap`, `guard.Config`, `guard.Metrics`, `guard.PoolOf`, `guard.Token`,
  `guard.Context`, `guard.Bulk`;
- `config.StoreConfig`, `config.EtcdConfig`, `config.StoreOf`;
- `authen.WithDelayContext` (with the arrival), `authen.DelayContext` (returning it),
  `(*authen.Handler).WithMarks`, `(*author.Handler).WithMarks`, `server.Deps.Abort`;
- `Broker.SupersededAll`, `Broker.Marks`, `Broker.ApplyMarksAtStart`, `Broker.RefreshAtStart`,
  `Broker.ReindexContexts`, `RefreshReport.Contexts`;
- `storeGone`, `storeFault`, `openStores`, `identity`, `probeTLS`, `startOnPersistentStore` (with
  the daemon's etcd store), `sweepLoop` (with the broker), `runOnce`, `runLoop`;
- `agent.RevocationRunningError`, `wireWait`.

`etcdtest.Grant` and `etcd.Grant` are deliberately two types, so `etcdtest` never imports
`etcd`, which would be a cycle with `etcd`'s internal tests. Every caller converts.

**Review Focus.** Each line's test is in the task it names.

**Reason codes.** None added. A timeout, an open circuit, a saturated pool, a refused role, a
record that fails authentication and a context the ledger does not admit are all
`store_unavailable`; a token that will not open is dropped, so its login is `token_not_found`;
a standing mark is `credential_revoked`, as a revoked context already was.

**Logs.** No line names a token, secret, credential or ledger entry. The new lines name a key
id, a mark's kind (never its key), a count, or a keyspace prefix.

**The split, re-verified.**
- **7d-1 is independently mergeable and safe.**
  - The binary stays on the memory store, and no binary links the etcd client or server until
    Task 12. `ReindexContexts` and `Unindexed` are built and tested, and called by nothing
    until Task 12.
  - Every behaviour it changes fails closed: the login refused on an index failure or under a
    mark; a context denied under a mark or by the ledger; a context, token and receipt sealed
    to their keys, with the old forms unreadable and so dropped or denied and replaced.
  - Its docs say only what it builds (Task 1), and `make test` stays green at every commit.
  - On memory no outside writer exists, so CA1 and IA1 were not exploitable before 7d-2; they
    are closed in 7d-1 all the same, so its docs claim nothing it does not hold.
- **7d-2 consumes exactly the names 7d-1 produces.** Those are `RewriteContext`, `Marks`,
  `ErrRefused`, `SwapLogin`, `PurgeTokens`, `crypt.Option`, `crypt.WithLedger`,
  `crypt.NewLedger`, `Broker.ReindexContexts`, and the etcd backend's `Open`, `Config`, `Ping`,
  `Sweep`, `Unindexed` and `ErrTooLarge`. Task 8 Step 6 amends 7d-2 if 7d-1's review moved any.
