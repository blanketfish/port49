# Plan 7f: The Container Shape, Go-Dark Proper and the Warm Context Cache — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship port49 as a container image and a compose deployment that CI proves end to end;
then make port49d close its TACACS+ listener on store health checks (N failures, M passes),
close the idle go-dark gap 7e left, and answer an active login's commands from a per-replica
context cache that is served past its TTL through an outage and alarmed.

- **The container shape (Task 1, Ryan 2026-10-03, pulled forward from plan 12).**
  - One minimal image, `gcr.io/distroless/static-debian12:nonroot`, holding the four static
    binaries (`port49d`, `port49-broker`, `port49`, `port49-inventory`), run as uid 65532.
  - `deploy/compose/compose.yaml`: port49d, port49-broker, three etcd members with client-cert
    auth and port49's roles, and a named volume per broker for `broker.state_dir`.
  - A CI smoke test (`make compose-smoke`, `.github/workflows/compose.yml`): `compose up`, a
    device login, the stack recreated with its volumes kept, the same session's next command
    answered and the broker's state kept.
  - L39's Docker half measured on the lab (Task 2).
  - Not prescriptive: nothing in port49 needs Docker. The smoke test sits behind a build tag
    and a make target of its own. systemd and Kubernetes stay plan 12's peers.
- **Go-dark proper (the owner's ruling of 2026-09-24).**
  - port49d checks the store every `store.etcd.health.interval` (1s). It closes every listener
    after `close_after` (5) consecutive failed checks, and listens again only after `open_after`
    (3) consecutive passes.
  - A check is a linearizable read on each of the daemon's two etcd connections. The context
    one goes through the feed fence.
  - The check runs whether or not a device asks, so an idle port49d goes dark as fast as a
    loaded one. That is 7e's idle gap (about 2 minutes at `hold_ttl` 60s), closed: dark within
    `close_after` × `interval` + `call_timeout` (5.5s at the defaults).
  - Ruling 11's probe is removed.
- **The warm context cache (design §12).**
  - A per-replica read-through cache of login contexts for command and session authorization.
  - It is off until `store.etcd.context_cache.ttl` is set, because the design says the TTL "MUST
    be explicit configuration".
  - Every change the context feed brings evicts its key, so a revocation reaches a cached
    session at the feed's speed, not the TTL's.
  - Through an outage it serves an entry past its TTL, alarmed and said, until the listeners
    close.
  - Blobs have been cached compiled, by hash, since plan 4 (`author.Engine`), and need nothing
    new.
- **Lab.**
  - L39 (a): Docker with a published port, with the userland proxy on and off (Task 2).
  - A new row, **L41**: what each of the five images does when port49d closes its listener
    mid-session on its health checks, beside port49d stopped, and how long after the store
    returns the device asks it again (Task 9).
  - From Task 2 on, the lab runs the split deployment on the compose stack (roadmap: "From then
    on every plan's lab runs on it").

**Architecture:**
- **The image** is built by a multi-stage `Dockerfile` at the repository root.
  - Target `port49`: the four binaries, `CGO_ENABLED=0`, and the directories each process
    writes, created `0700` and owned by 65532. A named volume first mounted on one is created
    from it with that ownership and mode, so `broker.state_dir` passes port49-broker's check on
    every mount. That is why no `fsGroup`-like step is needed.
  - Target `setup`: alpine, `etcdctl` from the etcd image, and `port49d` for `store-roles`. It
    runs two one-shot services:
    - `setup` copies the configuration and the PKI into one volume per component, each owned
      as port49's readers require;
    - `etcd-init` applies `port49d store-roles`'s output as etcd's root and enables auth, once.
- **Each component sees its own secrets alone.**
  - port49d's volume holds the daemon's etcd key, and its env file holds the devices' TACACS+
    key.
  - The broker's volume holds the broker's etcd key and TLS key, and its env file holds no
    device key.
  - etcd's root key is in a volume only `etcd-init` mounts.
  - This keeps plan 7e's Ruling 1 (no host holds both identities) true inside one compose
    project.
- **Go-dark keeps the run restart.**
  - `health.watch` replaces the probe. After `close_after` failures it ends the run as a store
    gone (`storeGone`), and every listener closes as it does today (held connections reset,
    `/readyz` 503).
  - The next run waits for the store as today, re-reading the files (7d Ruling 12: a renewed
    certificate or roles applied are picked up). Then `health.passes` holds the TACACS+ bind
    until `open_after` consecutive checks pass.
  - A cold start is not gated: its start has just read the store.
  - The guard's `StopAfter` (`hold_ttl`) stays as a backstop for a pool that fails while the
    checks pass.
- **The cache** is `crypt.Cached`, layered over the daemon's sealed store and handed only to the
  authorization handler.
  - **A hit** is an entry younger than the TTL, with the context feed up, and the ledger still
    knowing the cached record's revision as the latest at its key.
  - **Eviction:**
    - every write through it evicts its key;
    - the ledger tells it of every change the feed brings (`Ledger.changed`, deletes and
      unopenable records included);
    - a compacted rescan clears it;
    - a generation counter keeps a read that raced an eviction from being cached.
  - **Through an outage** (`store.ErrUnavailable`), it serves an entry the ledger still knows,
    within the context's own idle TTL, counts it `stale` and says it once.
  - **Lifetime:** it lives as long as a run, so a run after a store gone starts empty.

**Tech Stack:**
- Go 1.26, module `github.com/blanketfish/port49`, no cgo.
- `go.etcd.io/etcd/client/v3` v3.6.15; the compose stack runs `gcr.io/etcd-development/etcd:v3.6.15`,
  the server module's own version in `go.mod`.
- Docker Engine with Compose v2.24.4 or later (`!override` in the lab's overlay), BuildKit.
- GitHub Actions (`ubuntu-24.04`), the repository's first workflow.
- containerlab on beehive for Tasks 2 and 9, with the five images L37 used.

**Spec:**
- `docs/design/2026-08-23-policy-engine-spec.md`:
  - §13: decisions 35 (a store gone) and 36 (the daemon's start, the probe), amended; the new
    37.
  - §15: the register rules; L35, L37, L38 (read for what is measured); L39 (a); the new L41.
- `docs/design/2026-08-21-port49-design.md`:
  - §12: the failure matrix's store rows; "Consequences": the hard timeouts, the circuit
    breaker, the **per-replica read-through cache** paragraph, "As built on etcd", and "Store
    health MUST NOT be wired into the readiness probe" with the owner's ruling.
  - §13: deployment (source address visibility; `broker.state_dir` survives a restart).
  - §15: every stated alarm needs a metric.
  - §19: step 7.
- Roadmap `docs/superpowers/plans/README.md`:
  - "Plan 7", the 7f bullet;
  - "Plan 12", "Deployment shapes (Ryan, 2026-10-03)";
  - "Plan 7e — As built": "Carried, for later plans" (7f), the deployment table, and "An idle
    port49d goes dark late".
- The merged plan 7e (`2026-10-03-07e-broker-process.md`), whose code this plan is written against.

**Prerequisite:** plan 7e merged (PR #27, merge `6438e26`; `main` at `ef4b200`).

## The carries: what 7f takes, and what it leaves

| Carry | Taken? | Where, or why not |
|---|---|---|
| The container shape: image, compose, CI smoke test with a restart that keeps `broker.state_dir` (roadmap 7f Task 1; 7e "Carried" 7f) | **Taken** | Task 1 |
| L39's Docker half (roadmap 7f) | **Taken**: (a) measured with the userland proxy on and off; (b) and (c) stay plan 12's, so the row stays open | Task 2 |
| "From then on every plan's lab runs on it" (roadmap 7f) | **Taken** for new rows: the compose lab mode (Task 2) runs L39 and L41. The host-process harness stays for re-checks of rows closed on it (L35–L38) | Tasks 2, 9 |
| Go-dark proper: N failures close, M passes reopen (owner's ruling 2026-09-24; 7d and 7e carries) | **Taken** | Rulings 1–3; Tasks 4–6 |
| The idle go-dark gap: about 2 minutes at `hold_ttl` 60s, IOS-XE locked out including break-glass (7e L37; "a probe that re-pings at `breaker.open_for` after one failure is the mitigation to weigh") | **Taken: closed**, not just bounded. The check runs on its own clock, so idle and loaded are the same: dark within 5.5s at the defaults. The re-ping mitigation is not taken, because the check makes it moot. Break-glass behaviour is unchanged: port49d answers nothing new to anyone | Ruling 4; Tasks 5, 6; L41 measures it (Task 9) |
| The per-replica read-through cache of contexts and blobs, TTL in seconds, served past its TTL through an outage and alarmed (design §12; plan 6a "Carried") | **Taken**: contexts in Tasks 7–8. Blobs: **already built** (`author.Engine`'s compiled cache by hash since plan 4, which serves through an outage); nothing new | Rulings 5, 6 |
| Lab: what each image does when port49d closes its listener mid-session, beside port49d stopped (roadmap 7f) | **Taken**: new row L41 | Tasks 3, 9 |
| A plan that changes a config changes the compose file in the same plan (roadmap 7f) | **Taken** | Task 8 Step 6 |
| `R-1` (7e Task 8a): `askAgain` may reach etcd before the new watch registers | **Left** | Parked by 7e for Task 17 "if L37 sees it"; L37 did not. Not a go-dark item |
| L40 (Junos re-authorization more than once) | **Left unassigned** | A Junos timer row, not this plan's subject |
| The restore guard's IOS-XE lockout (a guarded port49d never goes dark; 7e notes) | **Left, named** | The guard refuses redemptions while the store *answers*; going dark on it would turn a restore into an outage for every token user. The alarm stands (`port49_redemption_restore_guarded`). Listed in "What this plan does not do" |
| Plan 12's systemd and Kubernetes shapes, load numbers, the store alarms' rules | **Left to plan 12** | The roadmap's 12. This plan's compose install page is a README, and plan 13 finishes it |

## What this plan does not do

- **No change to what port49 answers.** A device is answered as before; only *when* port49d
  closes and reopens its listener changes. No new reason code, and nothing new is permitted to
  break-glass or to anyone.
- **No in-process listener toggle.** A store gone still ends the run and the next waits as at a
  start (Ruling 2; OR-2 asks Ryan).
- **No cache for logins, enables, accounting or token redemption.** Token redemption is the
  single-use authority and MUST NOT be cached (design §12). A login's join needs the latest
  record. Only `author.Handler` reads through the cache.
- **No go-dark on the restore guard.** See the carries table.
- **No Kubernetes manifests, no systemd units, no Helm** (plan 12). Nothing makes Docker or
  Kubernetes required.
- **No second port49d or broker replica in the compose example.** Each needs its own service
  and volume. The README says how, and says never to use `deploy.replicas` or `--scale`, which
  would share one `broker.state_dir` volume.
- **No `make test` in CI.** The labpcap audit in `make test` needs captures that live only on
  the lab machine. The workflow runs the compose smoke test alone, and saying so is part of
  Task 1.

## Rulings where the design and spec are silent

Each takes the option that denies more, and is written into the tasks named. Spec §13 records
them as decision 37 (Task 3). Ryan may override any of them. OR-1 and OR-2 below are the two
that need his call.

1. **What a health check is.**
   - **The reads.** One check is a linearizable read of `meta/ping` on each of the daemon's two
     etcd connections, made at once and bounded together by `store.etcd.call_timeout`:
     - `Ping` on the context connection, through the feed fence (`crypt.Fenced`), so a context
       feed that has stopped fails the check;
     - the new `PingToken` on the token connection, so a store that answers one pool and not
       the other fails it.
   - **What fails it.** Any error: a timeout, no leader, a refusal by the roles (a role revoked
     at runtime is a store gone, as decision 35 says), a TLS failure.
   - **Below the guard.** It runs under the guard, so it takes no in-flight slot, trips no
     circuit and is not refused by an open one. Its count is exactly the store's answers.
   - **Its own clock.** It runs every `interval` whether or not a device asks.
   - **Close.** `close_after` consecutive failures end the run as a store gone. A pass resets
     the count.
   - **Reopen.** A run after a store gone binds TACACS+ only after `open_after` consecutive
     passes; a failure resets that count. A cold start is not gated.
   - **The backstop.** The guard's `StopAfter` (`hold_ttl`) stays. A pool whose own calls fail
     while the checks pass still ends the run, as decision 35 says.
2. **Close-and-wait stays: a store gone ends the run, and the next run waits as at a start.**
   - **Why.**
     - It is the path L35 and L37 measured.
     - It re-reads the files at each attempt, so a renewed etcd certificate or roles applied
       during an outage are picked up with no restart (7d Ruling 12). An in-process toggle
       would keep the old client, and a certificate that expired and was renewed would leave
       port49d dark until someone restarted it.
     - It rebuilds the context cache empty.
   - **Cost.**
     - The metrics registry is per run, so counters restart at each dark (7d's known cost,
       re-check R-M3).
     - Listening again takes the start's wait (an attempt every 5s) plus `open_after` ×
       `interval`.
   - The roadmap's 7e carry says the N/M control "replaces Ruling 11's coarse close-and-wait".
     This ruling replaces the *trigger* (the probe and `hold_ttl`) and adds the M gate, but
     keeps the wait. OR-2 asks Ryan.
3. **`store.etcd.health`: `interval` 1s (200ms to 10s, at least `call_timeout`), `close_after` 5
   (2 to 60), `open_after` 3 (1 to 60).**
   - **What the defaults give.**
     - Dark within 5.5s of the store stopping: `close_after` × `interval` + `call_timeout`.
     - Listening again within about 5s + the start + 3s of its return.
   - **The tested reason.** Two conditions, each with quorum healthy, and each must not close
     the listeners. Task 5 asserts the longest run of failed checks at the default interval
     stays below 5 under both:
     - a three-member cluster's killed leader (a refused connection and one election);
     - one member hung with its TCP connection alive (defragmenting, wedged or partitioned),
       through an `etcdtest.Proxy` in front of its client endpoint. clientv3 balances reads
       round-robin, so each check has a good chance to land a read on that member, and every
       replica sees the same member. Both pings set `clientv3.WithRequireLeader`, so a
       leaderless member answers `ErrGRPCNoLeader` at once and clientv3 retries the next
       endpoint, instead of the read blocking until the caller's deadline.

     If either test finds a run of 5 or more, the default is not raised quietly: the measured
     run goes to Ryan with OR-1.
   - The trade is OR-1's.
4. **The idle gap is closed, and break-glass is unchanged.**
   - **What changes.** Going dark on the check's own clock makes idle and loaded the same.
     IOS-XE's lockout of break-glass on a store fault (its authentication `ERROR` is final, L4,
     L35) shrinks from about 2 minutes to at most 5.5s.
   - **What does not.** Nothing port49 answers to a break-glass account changes. port49 never
     answers anything that would let a local account in, and the escape is still the closed
     port.
   - **The anti-escalation cost, stated.** A shorter dark time means a shorter store fault
     closes the listener. Once it is closed, an open session's commands fall to local
     authorization on vEOS, the N9Kv and Junos, and IOS-XE refuses them (L35, L38), as the
     design already accepts. That trade is OR-1's.
5. **The context cache.**
   - **Configuration.**
     - Off unless `store.etcd.context_cache.ttl` is set (100ms to 60s: "seconds, not minutes").
       The design says the TTL "MUST be explicit configuration", so port49 never picks one.
     - `max_entries` defaults to 65536 (1 to 1,048,576). Past it the cache is cleared, as the
       blob cache is (`blobCacheMax`).
   - **Who reads through it.** `author.Handler` alone: command and session authorization. Never
     a login, an enable, accounting or a redemption.
   - **A hit needs all three of:**
     - the entry younger than the TTL;
     - the context feed up (`Fence().Up()`);
     - `Ledger.knownAt(k, entry.Rev)`: no later record at the key is known to this process.
   - **Eviction:**
     - every write through it evicts its key, after the write;
     - every change the context feed brings evicts its key, delete and unopenable included
       (`Ledger.changed`);
     - a compacted rescan clears it (`Ledger.rescanned`);
     - a generation counter keeps a read that raced any eviction from being cached;
     - `ErrNotFound` evicts.
   - **Through an outage.** A read that fails `store.ErrUnavailable` (a timeout, an open
     circuit), and is not a fence timeout, is answered from an entry when both hold:
     - the ledger still knows the entry's revision as the latest;
     - the context's own idle TTL from its `LastTouchedAt` has not passed.

     It is counted `stale`, and said once per run of stale serves. It ends when a read lands,
     or when the listeners close (the run, and the cache, end). Never on `ErrNotFound`, never
     on an unreadable record (a put-back), and never on a fence timeout: `crypt.Fenced` waits
     only when the store's record carries a different revision than the ledger's, so a read
     that failed in the fence wait means etcd *answered* with a later record than the cached
     one, which may be a `SetRevokedAt`. That is not an outage, so the cached entry is
     evicted and the read is denied (`crypt.ErrFeedBehind`, kept through the guard's timeout
     wrap, Task 7).
   - **What revocation does during it.** "Revocation does not function during it, and that is
     documented rather than discovered" (design §12). The window is bounded by go-dark, 5.5s at
     the defaults.
   - **The fence case.** A feed that is behind while etcd answers is not an outage and is
     never served stale (above). The health check waits on the fence too, so a feed behind by
     more than `call_timeout` for `close_after` checks closes the listeners; an operator who
     sees dark with etcd healthy looks at `port49_store_fence_timeouts_total`.
   - **What bounds a hit.** The TTL, not `Up()`. `FollowContexts` sets `Fence().SetUp(true)`
     before `WatchContexts` has established the watch (`follow.go:137-138`), and a watch hung
     on a dead connection reads up. The `Up()` condition is a cheap guard, and the
     revocation window on a hit is the TTL, which the operator chose.
   - **Lifetime.** Per run. A run after a store gone starts empty.
6. **Blobs: no change.** `author.Engine` caches the compiled program by hash with no invalidation
   (spec §5.1.1). A blob is immutable and named by its hash, so it is served through an outage
   already.
7. **`store.etcd.health` and `store.etcd.context_cache` are port49d's.** port49-broker.yaml
   refuses each, naming it, because the broker never goes dark and serves no device (7e's rule
   for a key a broker has no use for).
8. **The container shape.**
   - **The image.**
     - `gcr.io/distroless/static-debian12:nonroot`, uid and gid 65532, no shell.
     - `ENTRYPOINT port49d`; compose sets the broker's entrypoint.
     - The writable directories `/var/lib/port49-broker`, `/var/spool/port49d` and `/run/port49`
       are created 0700 and owned by 65532.
     - `port49` is in the image, so `docker compose exec port49-broker port49 revoke …` works
       (7e's deployment table).
   - **The stack.** Three etcd members with peer and client certificate auth. `setup` and
     `etcd-init` are one-shot and idempotent. Volumes:
     - one `/etc/port49` volume per component;
     - etcd's PKI, and etcd's root;
     - a data volume per member;
     - `broker-state`;
     - `port49d-spool` (an accounting spool on an ephemeral layer is lost at a recreate,
       design §13).
   - **Secrets.**
     - Private keys are copied `0600` and owned by 65532; public files `0644` root; directories
       `0755` root. That passes `keyfile` and the write fence (a file and its directory owned
       by the process's user or root, never group- or world-writable).
     - The encryption and TACACS+ secrets come from per-component env files, never inline.
   - **The network.** A fixed subnet (`172.30.49.0/24`, `PORT49_COMPOSE_SUBNET` to change). The
     example's inventory names the gateway, `172.30.49.1`, which is the source a
     host-published connection presents (what L39 measures for a device off-host).
   - **Certificate status.** The example's `broker.certificate_status` is `{disabled: true}`,
     because a trial PKI publishes no CRL. The file says a real deployment names its CRL there.
9. **The lab on the compose stack.**
   - New register rows from 7f on run on it (`l.startCompose`).
   - port49d is published on the clab bridge's `172.100.100.1:49`. Its stdout and stderr are
     followed into `l.logPath` and `l.errPath`, so every existing reader works unchanged.
   - A store hang is `docker compose pause` of the three members: a frozen process, so its
     connections hang rather than refuse, as `etcdtest.Proxy.Hang` does.
   - Rows closed on the host harness are re-checked there.

### Open for Ryan

Execution proceeds on each recommendation unless Ryan rules otherwise. Task 10 records the
answer.

**OR-1. The health defaults: `interval` 1s, `close_after` 5, `open_after` 3.**
- **For shorter.** A shorter dark time is a shorter IOS-XE break-glass lockout: today about 2
  minutes, 5.5s at these values.
- **For longer.** Each store fault that lasts longer than `close_after` × `interval` closes
  the listener. Then every device falls to its local method: token users cannot log in, and
  open sessions' commands run under local authorization (vEOS, N9Kv, Junos) or are refused
  (IOS-XE).
- **Recommended:** 1s / 5 / 3, which Task 5 tests against a killed etcd leader (no close on an
  election).
- **Not taken:**
  - 1s / 3, which would close on some elections;
  - 2s / 5 (about 10.5s of lockout).

**OR-2. Keep close-and-wait, or toggle the listener in-process.**
- **The question.** The roadmap's 7e carry reads "the N-failures/M-passes listener control
  replaces Ruling 11's coarse close-and-wait".
- **Recommended:** keep the wait and replace its trigger (Ruling 2). It preserves 7d Ruling 12:
  a certificate renewed, or roles applied, while dark are picked up with no restart. It reuses
  the restart path L35 and L37 measured.
- **The alternative,** an in-process toggle, would:
  - reopen a few seconds sooner;
  - keep the metrics' counters;
  - leave a port49d whose etcd certificate expired dark until restarted, unless the etcd
    client re-read its certificate on each handshake, which is new code.

**Worth reading before the merge** (rulings, not open questions):
- **Ruling 4.** Break-glass is unchanged, and the IOS-XE lockout window shrinks to 5.5s at the
  defaults. Below that, nothing is closed.
- **Ruling 5.** The cache is off until `store.etcd.context_cache.ttl` is set. With it on,
  revocation does not reach a cached session while the store is down, until the listeners
  close.
- **Ruling 8.** The compose example's certificate status is disabled, and its etcd root key
  stays in a volume no port49 process mounts.

## What the operator sees

Every line below is printed by a task in this plan, and the tests named pin it.

- **A port49d start on etcd** says, after the ledger and marks lines (Task 6, Task 8):

  ```
  port49d: store: health checked every 1s; every listener closes after 5 consecutive failed checks and opens again after 3 passes (store.etcd.health)
  port49d: store: the context cache is off (store.etcd.context_cache.ttl is not set)
  ```

  or, with the cache on:

  ```
  port49d: store: the context cache is on: a session's context is read from it for up to 2s, at most 65536 entries; a revocation reaches it through the context feed, and through a store outage it is served past 2s until the listeners close
  ```
- **The store hangs** (Task 6). Within 5.5s at the defaults, idle or not:

  ```
  port49d: store: 5 consecutive store health checks failed over 4.5s (the last: the context pool: store: unavailable: context deadline exceeded); closing every listener so that devices use their local method
  port49d: store: 5 consecutive store health checks failed over 4.5s (…); every listener is closed; waiting for the store again, as at a start
  ```

  Then the 7d wait (`store: etcd at … not answering …; the listeners stay closed; waiting until
  it answers`). `/readyz` is 503 throughout.
- **The store returns** (Task 6):

  ```
  port49d: store: the store answers; the listeners open again after 3 consecutive health checks pass (store.etcd.health.open_after)
  port49d: store: 3 consecutive health checks passed
  port49d: listening on 0.0.0.0:49, metrics on 0.0.0.0:9049, 5 devices admitted
  ```

  A store that flaps during that wait says, once per run of failures:

  ```
  port49d: store: a health check failed while the listeners wait to open (…); counting 3 passes again
  ```
- **With the cache on and the store failing** (Task 8), once per run of stale serves:

  ```
  port49d: store: the store does not answer context reads (…); serving cached login contexts past store.etcd.context_cache.ttl (2s) until it does or the listeners close; a revocation made meanwhile does not reach them
  port49d: store: context reads are answered by the store again; the context cache serves within its ttl
  ```
- **New config refusals** (Task 4):
  - `store.etcd.health.interval 100ms: must be 200ms to 10s`;
  - `store.etcd.health.interval 300ms: must be at least store.etcd.call_timeout (500ms), which bounds each check`;
  - `store.etcd.health.close_after 1: must be 2 to 60`;
  - `store.etcd.health.open_after 61: must be 1 to 60` (an absent or 0 value takes the default);
  - `store.etcd.context_cache.ttl 2m0s: must be 100ms to 1m0s ("seconds, not minutes": design §12)`;
  - `store.etcd.context_cache.max_entries 0: must be 1 to 1048576`;
  - in port49-broker.yaml, `store.etcd.health is port49d's: port49-broker never closes a
    listener on the store (design §12); remove it` and the same for `context_cache`.
- **New metrics** (Tasks 6, 8). No label names a device.
  - `port49_store_health_checks_total{outcome}` (`pass`, `fail`);
  - `port49_store_health_failures`, the failed checks in a row now. The count is held by the
    process (`healthState`, Task 5), not the run: each run's new registry is set from it, and
    while a run waits for the store it reads at least `close_after`, so the alert "above 0 for
    three intervals" does not resolve at the close and holds through the outage;
  - `port49_context_cache_lookups_total{outcome}` (`hit`, `miss`, `stale`), where any increase
    of `stale` is the alarm the design asks for;
  - `port49_context_cache_entries`.
- **The container shape** (Task 1): `deploy/compose/README.md`.
  - **Trial:** `go run ./tests/compose/cmd/compose-pki`, then `docker compose -f
    deploy/compose/compose.yaml up -d --build`.
  - **Revoke:** `docker compose exec port49-broker port49 revoke --socket
    /run/port49/port49-broker.sock --principal user:bob@example.com`.
  - **Replicas:** never `--scale`.
  - A broker whose `state_dir` is a bind mount, or a volume filled by hand, owned by root
    still starts, because root is an accepted owner (`statedir_linux.go:72`) and 0755 passes
    (`statedir_linux.go:61`, `internal/config/config.go:1181`). The first `marks.json` or
    witness write then fails, as the 65532 process cannot write the directory. Only a bind mount or a pre-filled volume can hit it: a fresh named volume copies
    65532/0700 from the image. The README gives the fix (`chown 65532:65532` and `chmod 0700`).

## Global Constraints

- Go 1.26+, module `github.com/blanketfish/port49`, `gofmt` and `go vet` clean, no cgo.
- snake_case everywhere it is data: YAML keys, JSON log keys, config, metric names.
- Reason codes are spec §5.7's closed vocabulary (`internal/decision/reasons.go`). This plan adds
  none.
- The log never contains a token, password, challenge or response. Credentials appear only as
  `credential_sha256`. An unvalidated body is never logged. The smoke test prints `docker
  compose logs` itself on failure (Task 1, Step 11), which holds the decision log and stderr
  and neither of those.
- No device identity in metric labels.
- Verify with `make test && make vet` and report the real output. Task 1 adds `make
  compose-smoke`, and Tasks 1 and 2 add `go vet -tags compose ./tests/compose/...` to `make vet`.
- **Deployment is not prescriptive.** Nothing in `go test ./...`, `make test` or a binary needs
  Docker. The compose test is behind `//go:build compose`.
- **The image runs as uid 65532, never root.** The only root container is the one-shot `setup`
  and `etcd-init`, which never run port49.
- **No host holds both etcd identities** (7e Ruling 1). Inside one compose project: port49d's
  container mounts only the daemon's key, and the broker's only the broker's. The device key is
  in port49d's env file only.
- The lab register rules (CLAUDE.md 1–4). L39 stays open after Task 2: (b) and (c) are plan 12's.
- Conventional Commits; commit messages end with
  `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>` and
  `Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc`.

## Review Focus

The five conditions no task's tests exercise by accident and most likely to bite a person, with
the test that pins each:

1. **A store that answers one connection and not the other** (the token client's connection
   dead, the context client's fine). The operator expects port49d to go dark, because logins
   fail. Pinned by Task 5's `TestACheckFailsWhenEitherPoolFails`.
2. **A store that flaps around the thresholds** (answers for one check in three). The operator
   expects no rebind until `open_after` checks pass in a row, and no close on failures a pass
   interleaves. Pinned by Task 5's `TestWatchNeedsTheFailuresInARow`, `TestPassesNeedsThePassesInARow`,
   and Task 6's `TestAFlappingStoreDoesNotOpenTheListeners`.
3. **A context deleted or revoked elsewhere while it is cached.** The operator expects it never
   served, fresh or stale. Pinned by Task 7's `TestAFeedChangeEvictsTheKey`,
   `TestAReadThatRacedAnEvictionIsNotCached`, `TestASupersededEntryIsNeverServedStale`,
   `TestAFenceTimeoutIsNeverServedStale`, and Task 8's
   `TestAContextDeletedElsewhereIsNotAnsweredFromTheCache`, `TestARevokedSessionIsDeniedInsideTheTTL`
   and `TestAnEvictedContextIsNotServedThroughAnOutage`.
4. **The stack recreated (`docker compose down`, then `up`) with its volumes kept.** The
   operator expects the broker to accept its kept `state_dir`, the session to continue, and a
   token minted before to redeem. Pinned by Task 1's `TestComposeSmoke`.
5. **SIGTERM while port49d waits for its passes.** The operator expects it to stop at once, not
   after the store returns. Pinned by Task 6's `TestAStopWhileWaitingForPassesEndsTheRun`.

## Conflict scan: where tasks share a file or an interface

- `internal/port49d/store.go`: Task 6 (the `health` field replacing `probe`) and Task 8 (the
  `author` field and the cache). Task 8 builds on Task 6's struct.
- `internal/port49d/main.go`: Task 6 (the pass gate before the bind, the watch after it) and
  Task 8 (`authorStore`).
- `internal/config/config.go`: Task 4 alone.
- `internal/daemon/metrics/metrics.go`: Task 6 (health) and Task 8 (cache).
- `internal/store/crypt/ledger.go`, `follow.go`: Task 7 alone.
- `deploy/compose/config/port49d.yaml`: Task 1 writes it, and Task 8 adds `context_cache`.
- `tests/lab/harness_test.go` is not edited. Task 2's compose mode is a new file, and Task 9's
  bound is new beside `darkBound`, which L37's closed test keeps.
- Spec §15: Task 2 edits L39's Status, Task 3 adds L41, Task 9 closes L41.

## Running the lab (Tasks 2 and 9)

- On beehive, from a pinned worktree of the branch at the commit under test (7e's practice).
  Copy raw captures to `main`'s `tests/lab/captures/` before removing the worktree (memory:
  the labpcap audit).
- Run a background stall watchdog during each run, and re-arm it on wake (memory).
- Before a run: `df -h` on beehive (7d hygiene), and `docker compose version` ≥ v2.24.4.
- Each run builds the image from the worktree (`docker compose build`), so the lab measures the
  commit.
- Task 2's proxy-off half changes `/etc/docker/daemon.json` and restarts Docker: run it last,
  and restore the file after.

## File Structure

**Create:**
- `Dockerfile`: the image (target `port49`) and the setup image (target `setup`).
- `.dockerignore`: keeps captures, logs, `bin/`, `.git` and `deploy/compose/local/` out of the
  context.
- `deploy/compose/compose.yaml`: the stack.
- `deploy/compose/config/port49d.yaml`, `port49-broker.yaml`, `policy.yaml`, `inventory.yaml`:
  the example's configuration, in-container paths.
- `deploy/compose/setup.sh`: copies config and PKI into the component volumes and stages
  `store-roles`.
- `deploy/compose/etcd-init.sh`: applies the roles and enables auth, once.
- `deploy/compose/README.md`: the trial, the files, revoking, replicas, `state_dir`, source
  addresses.
- `internal/testpki/compose.go` (+ `compose_test.go`): `WriteCompose(dir, email, now)`.
- `tests/compose/cmd/compose-pki/main.go`: writes `deploy/compose/local/` for a trial.
- `tests/compose/smoke_test.go`: `//go:build compose`, the smoke test.
- `tests/compose/client_test.go`: `//go:build compose`, the smallest TACACS+ client and a mint.
- `.github/workflows/compose.yml`: CI.
- `tests/lab/compose_test.go`: `//go:build lab`, `l.startCompose` and `composeStack`.
- `tests/lab/compose_unit_test.go`: the compose mode's pure helpers (`composeLabFiles`,
  `proxyModeOf`, `healthDarkBound`).
- `tests/lab/l39_test.go`: L39 (a).
- `tests/lab/l41_test.go`: L41.
- `internal/port49d/health.go` (+ `health_test.go`): the check, `watch`, `passes`.
- `internal/store/crypt/cache.go` (+ `cache_test.go`): `Cached`, `CacheConfig`.
- `internal/port49d/contextcache.go` (+ `contextcache_test.go`): `staleSayer`, the cache's
  wiring and its e2e tests.

**Modify:**
- `Makefile`: `image`, `compose-smoke`, the vet line.
- `.gitignore`: `/deploy/compose/local/`.
- `internal/config/config.go` (+ `store_test.go`): `EtcdHealth`, `EtcdContextCache`, their
  checks, the broker's refusals.
- `internal/store/etcd/etcd.go` (+ a test): `PingToken`; `Ping` and `PingToken` both set
  `clientv3.WithRequireLeader`.
- `internal/store/guard/guard.go` (+ `guard_test.go`): a guarded timeout keeps the inner error
  wrapped, so `crypt.ErrFeedBehind` survives it (Task 7).
- `internal/port49d/store_test.go`: `sts.probe` replaced by `sts.health` in the two tests that
  used it (Task 6).
- `internal/store/etcd/etcdtest/etcdtest.go`: `Cluster.Kill`, `Cluster.Leader`.
- `internal/port49d/store.go`: `stores.health` replaces `stores.probe`; `stores.author`.
- `internal/port49d/daemon.go`: `probe` removed.
- `internal/port49d/main.go`: the pass gate, the watch, the author's store.
- `internal/port49d/daemon_test.go`, `brokerd_test.go`, `store_e2e_test.go`: the idle-dark
  test rewritten, the hang tests checked, the health keys in the test configs.
- `internal/daemon/metrics/metrics.go`: four series.
- `internal/store/crypt/ledger.go`, `follow.go` (+ `follow_test.go`): `changed`, `rescanned`,
  `attach`.
- `docs/design/2026-08-23-policy-engine-spec.md`: decisions 35, 36 amended, 37; L39 Status;
  L41.
- `docs/design/2026-08-21-port49-design.md`: §12, §13, §15.
- `tests/lab/README.md`: the compose mode.
- `docs/superpowers/plans/README.md`: Task 10.

---

### Task 1: The container shape: one image, one compose stack, a CI smoke test

**Files:**
- Create: `Dockerfile`, `.dockerignore`, `deploy/compose/compose.yaml`,
  `deploy/compose/config/{port49d,port49-broker,policy,inventory}.yaml`,
  `deploy/compose/setup.sh`, `deploy/compose/etcd-init.sh`, `deploy/compose/README.md`,
  `internal/testpki/compose.go`, `internal/testpki/compose_test.go`,
  `tests/compose/cmd/compose-pki/main.go`, `tests/compose/smoke_test.go`,
  `tests/compose/client_test.go`, `.github/workflows/compose.yml`
- Modify: `Makefile`, `.gitignore`

**Interfaces:**
- Consumes: `testpki.NewCA`, `(*CA).Issue(Leaf)`, `testpki.PEMs`, `testpki.WriteLab`,
  `testpki.LabCA`/`LabServerCert`/`LabServerKey`/`LabClientCert`/`LabClientKey`;
  `api.MintResponse` (`internal/broker/api`); `wire.Header`, `wire.Obfuscate`,
  `wire.AuthenStart`, `wire.DecodeAuthenReply`, `wire.AuthorRequest`,
  `wire.DecodeAuthorResponse`; `port49d store-roles --config --broker-config` (prints etcdctl
  lines).
- Produces:
  - `testpki.WriteCompose(dir, email string, now time.Time) error`, which writes:
    - `etcd/{ca,etcd-1,etcd-2,etcd-3,root,port49d,port49-broker}.pem` and each leaf's
      `-key.pem`;
    - `broker/` (`WriteLab`'s files for email);
    - `port49d.env` (`PORT49_TACACS_KEY`, `PORT49_ENC_KEY`) and `port49-broker.env`
      (`PORT49_ENC_KEY`).
  - The compose stack:
    - services `setup`, `etcd-1`, `etcd-2`, `etcd-3`, `etcd-init`, `port49-broker`, `port49d`;
    - volumes `port49d-etc`, `broker-etc`, `etcd-pki`, `etcd-root`, `etcd-1-data`,
      `etcd-2-data`, `etcd-3-data`, `broker-state`, `port49d-spool`;
    - env inputs `PORT49_COMPOSE_LOCAL` (default `./local`), `PORT49_COMPOSE_CONFIG` (default
      `./config`), `PORT49_COMPOSE_SUBNET` (default `172.30.49.0/24`), `PORT49_TACACS_PUBLISH`
      (default `127.0.0.1:49`), `PORT49_BROKER_PUBLISH` (default `127.0.0.1:8443`).
  - Image tags `port49:dev` and `port49-setup:dev`. Task 2's lab mode uses all of the above.

- [ ] **Step 1: The compose PKI's failing test**

`internal/testpki/compose_test.go`:

```go
package testpki

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// WriteCompose writes every file deploy/compose reads from local/: etcd's
// CA and members (any-purpose, for peer and client), a client per etcd
// user, the broker's lab PKI, and an env file per component, the device
// key in port49d's alone (plan 7f, Ruling 8).
func TestWriteComposeWritesTheStacksFiles(t *testing.T) {
	dir := t.TempDir()
	if err := WriteCompose(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"etcd/ca.pem", "etcd/etcd-1.pem", "etcd/etcd-1-key.pem", "etcd/etcd-3.pem",
		"etcd/root.pem", "etcd/root-key.pem", "etcd/port49d.pem", "etcd/port49d-key.pem",
		"etcd/port49-broker.pem", "etcd/port49-broker-key.pem", "broker/" + LabCA, "broker/" + LabServerCert,
		"broker/" + LabServerKey, "broker/" + LabClientCert, "broker/" + LabClientKey, "port49d.env",
		"port49-broker.env"} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if strings.HasSuffix(f, "-key.pem") || strings.HasSuffix(f, ".env") {
			if fi.Mode().Perm() != 0o600 {
				t.Errorf("%s is %v, want 0600", f, fi.Mode().Perm())
			}
		}
	}
	cn := func(f string) string {
		raw, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := pem.Decode(raw)
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return c.Subject.CommonName
	}
	// etcd's user is the CN: the two components' differ, and neither is root.
	if cn("etcd/port49d.pem") != "port49d" || cn("etcd/port49-broker.pem") != "port49-broker" || cn("etcd/root.pem") != "root" {
		t.Fatalf("CNs %q %q %q", cn("etcd/port49d.pem"), cn("etcd/port49-broker.pem"), cn("etcd/root.pem"))
	}
	broker, err := os.ReadFile(filepath.Join(dir, "port49-broker.env"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(broker), "PORT49_TACACS_KEY") {
		t.Fatal("the broker's env file holds the device key")
	}
	daemon, _ := os.ReadFile(filepath.Join(dir, "port49d.env"))
	if !strings.Contains(string(daemon), "PORT49_TACACS_KEY=") || !strings.Contains(string(daemon), "PORT49_ENC_KEY=") {
		t.Fatalf("port49d.env: %d bytes, missing a key", len(daemon))
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/testpki/ -run TestWriteComposeWritesTheStacksFiles -count=1`
Expected: FAIL, `undefined: WriteCompose`.

- [ ] **Step 3: `WriteCompose`**

`internal/testpki/compose.go`:

```go
package testpki

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// WriteCompose writes deploy/compose's local/ directory into dir (plan 7f,
// Task 1): etcd's CA, a certificate for each of its three members (no
// extended key usage, so it serves a peer's and a client's side), a client
// certificate per etcd user (root, port49d, port49-broker), the broker's
// lab PKI under broker/ for email, and the two env files. Valid 24h, as
// WriteLab's. Nothing it writes protects anything real: a trial and the
// tests use it, never a deployment.
func WriteCompose(dir, email string, now time.Time) error {
	for _, d := range []string{dir, filepath.Join(dir, "etcd")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	if err := WriteLab(filepath.Join(dir, "broker"), email, now); err != nil {
		return err
	}
	from, until := now.Add(-time.Hour), now.Add(24*time.Hour)
	ca, err := NewCA("port49 compose etcd CA", from, until)
	if err != nil {
		return err
	}
	files := map[string][]byte{"etcd/ca.pem": ca.PEM()}
	issue := func(name string, l Leaf) error {
		l.NotBefore, l.NotAfter = from, until
		c, err := ca.Issue(l)
		if err != nil {
			return err
		}
		cert, key, err := PEMs(c)
		if err != nil {
			return err
		}
		files["etcd/"+name+".pem"], files["etcd/"+name+"-key.pem"] = cert, key
		return nil
	}
	for _, m := range []string{"etcd-1", "etcd-2", "etcd-3"} {
		if err := issue(m, Leaf{CommonName: m, DNSNames: []string{m, "localhost"}, IPs: Loopback(),
			NoExtKeyUsage: true}); err != nil {
			return err
		}
	}
	for _, u := range []string{"root", "port49d", "port49-broker"} {
		if err := issue(u, Leaf{CommonName: u, Client: true}); err != nil {
			return err
		}
	}
	tacacs, err := secret(24)
	if err != nil {
		return err
	}
	enc, err := secret(32) // encryption keys are 32 bytes (config.key32)
	if err != nil {
		return err
	}
	files["port49d.env"] = []byte(fmt.Sprintf("PORT49_TACACS_KEY=%s\nPORT49_ENC_KEY=%s\n", tacacs, enc))
	files["port49-broker.env"] = []byte(fmt.Sprintf("PORT49_ENC_KEY=%s\n", enc))
	for name, body := range files {
		if err := writeFresh(filepath.Join(dir, name), body); err != nil {
			return fmt.Errorf("testpki: %s: %w", name, err)
		}
	}
	return nil
}

// secret is n random characters from [A-Za-z0-9]: safe in an env file
// unquoted, and n bytes long.
func secret(n int) (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, n)
	for i := range out {
		v, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		out[i] = alphabet[v.Int64()]
	}
	return string(out), nil
}
```

`writeFresh` (testpki.go:283) writes 0600. If it refuses an existing file, `WriteCompose` into
a directory written before must still work for the trial: check `writeFresh`'s contract first.
If it refuses, remove `dir/etcd`, `dir/*.env` and `dir/broker` before writing, and say so in
the doc comment.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/testpki/ -count=1`
Expected: PASS.

- [ ] **Step 5: The trial's PKI command**

`tests/compose/cmd/compose-pki/main.go`:

```go
// Command compose-pki writes deploy/compose/local/ for a trial of the
// compose stack (plan 7f, Task 1): etcd's CA, members and users, the
// broker's PKI with a client certificate for -email, and the two env
// files. It protects nothing real, is valid 24h, and the directory is
// git-ignored. A deployment brings its own PKI (deploy/compose/README.md).
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/blanketfish/port49/internal/testpki"
)

func main() {
	out := flag.String("out", "deploy/compose/local", "directory to write into")
	email := flag.String("email", "alice@example.com", "the client certificate's email SAN")
	flag.Parse()
	if err := testpki.WriteCompose(*out, *email, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "compose-pki:", err)
		os.Exit(1)
	}
	fmt.Printf("compose-pki: wrote %s (valid 24h)\n", *out)
}
```

- [ ] **Step 6: The Dockerfile and `.dockerignore`**

`Dockerfile`:

```dockerfile
# syntax=docker/dockerfile:1.7
#
# port49's container image (plan 7f, Task 1): one peer shape beside systemd
# and Kubernetes; nothing in port49 requires it (roadmap, "Deployment
# shapes").
#
#   target port49: the four static binaries on distroless, as uid 65532
#   target setup:  the compose stack's one-shot setup and etcd-init (root,
#                  alpine, etcdctl); never runs port49 itself

FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/ \
      ./cmd/port49d ./cmd/port49-broker ./cmd/port49 ./cmd/port49-inventory

FROM gcr.io/etcd-development/etcd:v3.6.15 AS etcd

FROM gcr.io/distroless/static-debian12:nonroot AS port49
COPY --from=build /out/port49d /out/port49-broker /out/port49 /out/port49-inventory /usr/local/bin/
# Each directory a process writes, 0700 and owned by the user it runs as. A
# named volume first mounted on one is created from it, ownership and mode
# included, so broker.state_dir passes port49-broker's check (writable by
# no group or other user; plan 7e, Ruling T15-b) on its first mount and on
# every one after; no fsGroup-like step is needed.
COPY --from=build --chown=65532:65532 --chmod=0700 /out/empty/ /var/lib/port49-broker/
COPY --from=build --chown=65532:65532 --chmod=0700 /out/empty/ /var/spool/port49d/
COPY --from=build --chown=65532:65532 --chmod=0700 /out/empty/ /run/port49/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/port49d"]

FROM alpine:3.22 AS setup
COPY --from=etcd /usr/local/bin/etcdctl /usr/local/bin/etcdctl
COPY --from=build /out/port49d /usr/local/bin/port49d
COPY deploy/compose/setup.sh deploy/compose/etcd-init.sh /usr/local/bin/
ENTRYPOINT ["/bin/sh"]
```

Add `RUN mkdir -p /out/empty` to the `build` stage after the `go build`. If the `--chmod` on a
directory copy is not honoured by the BuildKit in use, Step 13's mode assertion fails. Do not
loosen the assertion: switch to a `scratch`-staged tree built with `install -d -m 0700 -o 65532
-g 65532` in the build stage, copied with `COPY --from=build --chown=65532:65532`. Then check
the mode again.

`.dockerignore`:

```
.git
bin/
tests/lab/captures/
tests/lab/logs/
tests/lab/evidence/
deploy/compose/local/
*.test
*.out
```

- [ ] **Step 7: The compose stack**

`deploy/compose/compose.yaml`:

```yaml
# port49 on etcd as containers (plan 7f, Task 1): port49d, port49-broker
# and a three-member etcd with client-certificate auth. One peer shape
# beside systemd and Kubernetes (roadmap, "Deployment shapes"). Read
# README.md beside this file first.
#
# Inputs (environment, each with a default):
#   PORT49_COMPOSE_LOCAL   the PKI and the env files (default ./local; a trial
#                          writes it with `go run ./tests/compose/cmd/compose-pki`)
#   PORT49_COMPOSE_CONFIG  the four YAML files (default ./config)
#   PORT49_COMPOSE_SUBNET  the stack's network (default 172.30.49.0/24)
#   PORT49_TACACS_PUBLISH  host address:port for TACACS+ (default 127.0.0.1:49)
#   PORT49_BROKER_PUBLISH  host address:port for the broker's API (default 127.0.0.1:8443)

name: port49

x-etcd: &etcd
  image: gcr.io/etcd-development/etcd:v3.6.15
  user: "65532:65532"
  restart: unless-stopped
  networks: [port49]
  depends_on:
    setup: {condition: service_completed_successfully}
  # The settings the three members share. A YAML merge (<<) cannot splice a
  # list into a member's command:, but it does merge this map, and etcd reads
  # each ETCD_* variable as the flag of the same name; each member's command:
  # carries only what differs per member.
  environment:
    ETCD_INITIAL_CLUSTER: etcd-1=https://etcd-1:2380,etcd-2=https://etcd-2:2380,etcd-3=https://etcd-3:2380
    ETCD_INITIAL_CLUSTER_STATE: new
    ETCD_INITIAL_CLUSTER_TOKEN: port49-compose
    ETCD_DATA_DIR: /var/lib/etcd
    ETCD_LISTEN_CLIENT_URLS: https://0.0.0.0:2379
    ETCD_LISTEN_PEER_URLS: https://0.0.0.0:2380
    ETCD_CLIENT_CERT_AUTH: "true"
    ETCD_TRUSTED_CA_FILE: /etc/etcd-pki/ca.pem
    ETCD_PEER_CLIENT_CERT_AUTH: "true"
    ETCD_PEER_TRUSTED_CA_FILE: /etc/etcd-pki/ca.pem
    # design §13: periodic compaction, since every login and touch writes a revision
    ETCD_AUTO_COMPACTION_MODE: periodic
    ETCD_AUTO_COMPACTION_RETENTION: 1h

services:
  # One-shot, as root: copies the configuration and the PKI into one volume
  # per component, owned as port49's readers require, and stages store-roles'
  # output for etcd-init. Idempotent: it runs at every `up`.
  setup:
    image: port49-setup:dev
    build: {context: ../.., target: setup}
    command: [/usr/local/bin/setup.sh]
    network_mode: none
    volumes:
      - ${PORT49_COMPOSE_CONFIG:-./config}:/src/config:ro
      - ${PORT49_COMPOSE_LOCAL:-./local}:/src/local:ro
      - port49d-etc:/vol/port49d-etc
      - broker-etc:/vol/broker-etc
      - etcd-pki:/vol/etcd-pki
      - etcd-root:/vol/etcd-root
      - etcd-1-data:/vol/etcd-1-data
      - etcd-2-data:/vol/etcd-2-data
      - etcd-3-data:/vol/etcd-3-data

  etcd-1:
    <<: *etcd
    command: [/usr/local/bin/etcd, --name=etcd-1, --advertise-client-urls=https://etcd-1:2379,
      --initial-advertise-peer-urls=https://etcd-1:2380, --cert-file=/etc/etcd-pki/etcd-1.pem,
      --key-file=/etc/etcd-pki/etcd-1-key.pem, --peer-cert-file=/etc/etcd-pki/etcd-1.pem,
      --peer-key-file=/etc/etcd-pki/etcd-1-key.pem]
    volumes: [etcd-pki:/etc/etcd-pki:ro, etcd-1-data:/var/lib/etcd]
  etcd-2:
    <<: *etcd
    command: [/usr/local/bin/etcd, --name=etcd-2, --advertise-client-urls=https://etcd-2:2379,
      --initial-advertise-peer-urls=https://etcd-2:2380, --cert-file=/etc/etcd-pki/etcd-2.pem,
      --key-file=/etc/etcd-pki/etcd-2-key.pem, --peer-cert-file=/etc/etcd-pki/etcd-2.pem,
      --peer-key-file=/etc/etcd-pki/etcd-2-key.pem]
    volumes: [etcd-pki:/etc/etcd-pki:ro, etcd-2-data:/var/lib/etcd]
  etcd-3:
    <<: *etcd
    command: [/usr/local/bin/etcd, --name=etcd-3, --advertise-client-urls=https://etcd-3:2379,
      --initial-advertise-peer-urls=https://etcd-3:2380, --cert-file=/etc/etcd-pki/etcd-3.pem,
      --key-file=/etc/etcd-pki/etcd-3-key.pem, --peer-cert-file=/etc/etcd-pki/etcd-3.pem,
      --peer-key-file=/etc/etcd-pki/etcd-3-key.pem]
    volumes: [etcd-pki:/etc/etcd-pki:ro, etcd-3-data:/var/lib/etcd]

  # One-shot, as etcd's root: applies port49d store-roles' output and
  # enables auth, once; a later `up` finds auth enabled and changes nothing.
  etcd-init:
    image: port49-setup:dev
    # built here as well as at setup, so no `up` ever tries to pull the tag
    build: {context: ../.., target: setup}
    command: [/usr/local/bin/etcd-init.sh]
    networks: [port49]
    volumes: [etcd-root:/etcd-root:ro]
    depends_on:
      etcd-1: {condition: service_started}
      etcd-2: {condition: service_started}
      etcd-3: {condition: service_started}

  port49-broker:
    image: port49:dev
    build: {context: ../.., target: port49}
    entrypoint: [/usr/local/bin/port49-broker]
    restart: unless-stopped
    networks: [port49]
    env_file: [{path: "${PORT49_COMPOSE_LOCAL:-./local}/port49-broker.env"}]
    ports:
      - ${PORT49_BROKER_PUBLISH:-127.0.0.1:8443}:8443
      - 127.0.0.1:9050:9050
    volumes:
      - broker-etc:/etc/port49:ro
      # broker.state_dir: one named volume per broker, never shared, never
      # an anonymous volume (plan 7e, Rulings 12 and 18). A second broker is
      # a second service with a volume of its own; never --scale.
      - broker-state:/var/lib/port49-broker
    depends_on:
      etcd-init: {condition: service_completed_successfully}

  port49d:
    image: port49:dev
    # built here as well as at port49-broker, so no `up` ever tries to pull the tag
    build: {context: ../.., target: port49}
    restart: unless-stopped
    networks: [port49]
    # Non-root binds 49: Docker sets this in each container's network
    # namespace already; it is stated so a runtime that does not is caught.
    sysctls: {net.ipv4.ip_unprivileged_port_start: 0}
    env_file: [{path: "${PORT49_COMPOSE_LOCAL:-./local}/port49d.env"}]
    ports:
      # port49d must see the device's true source address (design §13);
      # what a published port does to it is policy engine spec §15 L39 (a).
      - ${PORT49_TACACS_PUBLISH:-127.0.0.1:49}:49
      - 127.0.0.1:9049:9049
    volumes:
      - port49d-etc:/etc/port49:ro
      # the accounting spool: on an ephemeral layer a record acknowledged to
      # a device is lost at a recreate
      - port49d-spool:/var/spool/port49d
    depends_on:
      etcd-init: {condition: service_completed_successfully}

networks:
  port49:
    ipam:
      config: [{subnet: "${PORT49_COMPOSE_SUBNET:-172.30.49.0/24}"}]

volumes:
  port49d-etc: {}
  broker-etc: {}
  etcd-pki: {}
  etcd-root: {}
  etcd-1-data: {}
  etcd-2-data: {}
  etcd-3-data: {}
  broker-state: {}
  port49d-spool: {}
```

`port49d.yaml` and `port49-broker.yaml` are read at each container's default path
(`/etc/port49/port49d.yaml`, `/etc/port49/port49-broker.yaml`; `internal/port49d/main.go:75`,
`brokerd.go:52`), so neither service names `--config`.

- [ ] **Step 8: The example's configuration**

`deploy/compose/config/port49d.yaml`:

```yaml
# port49d in the compose stack (plan 7f, Task 1). Paths are inside the
# container: setup.sh copies this file and the files it names into the
# port49d-etc volume, mounted read-only at /etc/port49.
listen: ":49"
metrics_listen: ":9049"
inventory_file: /etc/port49/inventory.yaml
policy: {file: /etc/port49/policy.yaml, watch_interval: 5s}
keys:
  k:
    current: {version: 1, secret_env: PORT49_TACACS_KEY}
encryption:
  current: {id: c1, secret_env: PORT49_ENC_KEY}
admin_socket: /run/port49/port49d.sock
accounting:
  spool_path: /var/spool/port49d/acct.jsonl
store:
  backend: etcd
  etcd:
    endpoints: [https://etcd-1:2379, https://etcd-2:2379, https://etcd-3:2379]
    ca_file: /etc/port49/etcd/ca.pem
    daemon: {cert_file: /etc/port49/etcd/port49d.pem, key_file: /etc/port49/etcd/port49d-key.pem}
```

`deploy/compose/config/port49-broker.yaml`:

```yaml
# port49-broker in the compose stack (plan 7f, Task 1); paths inside the
# container (broker-etc, mounted read-only at /etc/port49).
metrics_listen: ":9050"
inventory_file: /etc/port49/inventory.yaml
key_refs: [k]
encryption:
  current: {id: c1, secret_env: PORT49_ENC_KEY}
admin_socket: /run/port49/port49-broker.sock
broker:
  listen: ":8443"
  tls_cert_file: /etc/port49/broker/broker.pem
  tls_key_file: /etc/port49/broker/broker-key.pem
  client_ca_file: /etc/port49/broker/broker-ca.pem
  policy_file: /etc/port49/policy.yaml
  # the broker-state volume; 0700 and owned by uid 65532 from the image
  state_dir: /var/lib/port49-broker
  # A trial PKI publishes no CRL. A deployment names its CRL (or OCSP) here
  # and leaves on_unavailable at refuse (spec §5.1.4).
  certificate_status: {disabled: true}
store:
  backend: etcd
  etcd:
    endpoints: [https://etcd-1:2379, https://etcd-2:2379, https://etcd-3:2379]
    ca_file: /etc/port49/etcd/ca.pem
    broker: {cert_file: /etc/port49/etcd/port49-broker.pem, key_file: /etc/port49/etcd/port49-broker-key.pem}
```

`deploy/compose/config/policy.yaml`:

```yaml
# The trial's policy: alice and bob, each an admin everywhere. A token_ttl
# of 15m outlasts the smoke test's waits (up to 3m + 3m + 120s) between
# minting a token and redeeming it after the recreate. The key
# group admits the stack's own network, whose gateway (172.30.49.1) is the
# source a host-published connection presents (inventory.yaml).
scopes: [{name: all_devices, match: {}}]
roles: [{name: network_admin, privilege: admin, permit: ["**"]}]
subjects:
  - {name: alice, identity: ["user:alice@example.com"], username: alice, token_ttl: 15m}
  - {name: bob, identity: ["user:bob@example.com"], username: bob, token_ttl: 15m}
grants:
  - {subject: alice, scope: all_devices, roles: [network_admin]}
  - {subject: bob, scope: all_devices, roles: [network_admin]}
key_groups: [{match: {cidr: 172.30.49.0/24}, key_ref: k}]
```

`deploy/compose/config/inventory.yaml`:

```yaml
# The trial's one device: whatever connects through the published port
# from this host, which the stack's network presents as its gateway. A
# deployment lists its devices by the addresses port49d sees (design §13).
devices:
  - {name: smoke1, platform: arista_eos, addresses: [172.30.49.1]}
```

- [ ] **Step 9: `setup.sh` and `etcd-init.sh`**

`deploy/compose/setup.sh`:

```sh
#!/bin/sh
# The compose stack's setup (plan 7f, Task 1), as root, at every `up`.
# Each component's volume gets its own files and nothing else (plan 7e,
# Ruling 1: no host holds both etcd identities):
#   - public files 0644 and directories 0755, owned by root;
#   - a private key 0600, owned by uid 65532, which every port49 process and
#     etcd runs as (keyfile: owner-only; the write fence: a file and its
#     directory owned by the process's user or root, never group- or
#     world-writable);
#   - etcd's root key 0600 root, in a volume only etcd-init mounts.
# It also runs port49d store-roles on a staged copy of both components'
# files and leaves the output for etcd-init.
set -eu
C=/src/config L=/src/local U=65532
pub() { install -o 0 -g 0 -m 0644 "$1" "$2"; }
key() { install -o "$U" -g "$U" -m 0600 "$1" "$2"; }
dir() { install -d -o 0 -g 0 -m 0755 "$@"; }

dir /vol/port49d-etc/etcd
pub "$C/port49d.yaml" /vol/port49d-etc/port49d.yaml
pub "$C/policy.yaml" /vol/port49d-etc/policy.yaml
pub "$C/inventory.yaml" /vol/port49d-etc/inventory.yaml
pub "$L/etcd/ca.pem" /vol/port49d-etc/etcd/ca.pem
pub "$L/etcd/port49d.pem" /vol/port49d-etc/etcd/port49d.pem
key "$L/etcd/port49d-key.pem" /vol/port49d-etc/etcd/port49d-key.pem

dir /vol/broker-etc/etcd /vol/broker-etc/broker
pub "$C/port49-broker.yaml" /vol/broker-etc/port49-broker.yaml
pub "$C/policy.yaml" /vol/broker-etc/policy.yaml
pub "$C/inventory.yaml" /vol/broker-etc/inventory.yaml
pub "$L/etcd/ca.pem" /vol/broker-etc/etcd/ca.pem
pub "$L/etcd/port49-broker.pem" /vol/broker-etc/etcd/port49-broker.pem
key "$L/etcd/port49-broker-key.pem" /vol/broker-etc/etcd/port49-broker-key.pem
pub "$L/broker/broker-ca.pem" /vol/broker-etc/broker/broker-ca.pem
pub "$L/broker/broker.pem" /vol/broker-etc/broker/broker.pem
key "$L/broker/broker-key.pem" /vol/broker-etc/broker/broker-key.pem

dir /vol/etcd-pki
pub "$L/etcd/ca.pem" /vol/etcd-pki/ca.pem
for m in etcd-1 etcd-2 etcd-3; do
  pub "$L/etcd/$m.pem" "/vol/etcd-pki/$m.pem"
  key "$L/etcd/$m-key.pem" "/vol/etcd-pki/$m-key.pem"
  chown "$U:$U" "/vol/$m-data"
  chmod 0700 "/vol/$m-data"
done

install -d -o 0 -g 0 -m 0700 /vol/etcd-root
pub "$L/etcd/ca.pem" /vol/etcd-root/ca.pem
pub "$L/etcd/root.pem" /vol/etcd-root/root.pem
install -o 0 -g 0 -m 0600 "$L/etcd/root-key.pem" /vol/etcd-root/root-key.pem

# store-roles reads both store: blocks and the files they name, at the
# paths each container sees them: stage both here, in this container alone.
# The staged copy holds both components' etcd private keys and the exited
# container keeps its filesystem layer, so it is removed on every exit
# (Ruling 1 holds inside the project). Nothing after setup needs it: etcd-init
# reads roles.sh from the etcd-root volume.
trap 'rm -rf /etc/port49' EXIT
dir /etc/port49/etcd
cp /vol/port49d-etc/port49d.yaml /vol/broker-etc/port49-broker.yaml /etc/port49/
cp /vol/port49d-etc/etcd/* /vol/broker-etc/etcd/* /etc/port49/etcd/
port49d store-roles --config /etc/port49/port49d.yaml --broker-config /etc/port49/port49-broker.yaml \
  > /vol/etcd-root/roles.sh
echo "setup: the component volumes are written; store-roles staged for etcd-init"
```

`deploy/compose/etcd-init.sh`:

```sh
#!/bin/sh
# Applies port49's etcd roles and enables auth, once (plan 7f, Task 1), as
# etcd's root. A later run finds auth enabled and changes nothing: roles
# changed by a port49 upgrade are re-applied by hand from store-roles'
# output (plan 7e's notes), never silently here.
set -eu
export ETCDCTL_ENDPOINTS=https://etcd-1:2379,https://etcd-2:2379,https://etcd-3:2379
export ETCDCTL_CACERT=/etcd-root/ca.pem ETCDCTL_CERT=/etcd-root/root.pem ETCDCTL_KEY=/etcd-root/root-key.pem
i=0
until etcdctl endpoint health >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -ge 120 ]; then
    echo "etcd-init: the three members did not all answer in 120s" >&2
    etcdctl endpoint health >&2 || true
    exit 1
  fi
  sleep 1
done
if etcdctl auth status 2>/dev/null | grep -q 'Authentication Status: true'; then
  echo "etcd-init: auth is already enabled; the roles stand as applied"
  exit 0
fi
# Each line of roles.sh is one etcdctl command. A run that stopped partway
# (an etcd restart, a killed container) left some of them applied, and `role
# add` and `user add` fail on a name that exists: tolerate exactly that, so
# the next `up` finishes the job instead of failing under `set -e`.
apply() {
  if out=$("$@" 2>&1); then
    return 0
  fi
  case "$out" in
    *"already exists"*) return 0 ;;
  esac
  echo "etcd-init: $* failed: $out" >&2
  exit 1
}
while IFS= read -r line; do
  case "$line" in
    "" | "#"*) continue ;;
  esac
  # shellcheck disable=SC2086 # one etcdctl command per line, split on spaces
  apply $line
done < /etcd-root/roles.sh
apply etcdctl user add root --no-password
apply etcdctl user grant-role root root
etcdctl auth enable
echo "etcd-init: port49's roles applied and auth enabled"
```

Mark both executable (`git update-index --chmod=+x` on commit).

Before relying on `etcd-init.sh`'s line loop, run `port49d store-roles` on the example's two
files and read its output: the loop assumes one `etcdctl …` command per line with no quoted
space inside an argument. If a line is quoted or wrapped, run it with `sh -c "$line"` in
`apply` instead, and keep the "already exists" tolerance.

- [ ] **Step 10: The smoke test's client and mint**

`tests/compose/client_test.go`:

```go
//go:build compose

package compose

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/tacacs/wire"
	"github.com/blanketfish/port49/internal/testpki"
)

// device is the smallest TACACS+ client that logs in and asks for
// authorization, one exchange per connection, as port49d's own tests'
// tacacsClient (internal/port49d/run_test.go), which this package cannot
// import.
type device struct {
	t    *testing.T
	addr string
	key  []byte
}

func (d device) exchange(typ wire.Type, body []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", d.addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	h := wire.Header{MajorVersion: 0xc, Type: typ, SeqNo: 1, SessionID: 0x5eed, Length: uint32(len(body))}
	if _, err := conn.Write(append(h.Encode(), wire.Obfuscate(h, d.key, body)...)); err != nil {
		return nil, err
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	hb := make([]byte, wire.HeaderLen)
	if _, err := io.ReadFull(conn, hb); err != nil {
		return nil, err
	}
	rh, _ := wire.DecodeHeader(hb)
	rb := make([]byte, rh.Length)
	if _, err := io.ReadFull(conn, rb); err != nil {
		return nil, err
	}
	return wire.Obfuscate(rh, d.key, rb), nil
}

// login is a PAP login; it fails the test on a connection that was not
// answered: port49d resets a source it does not admit (design §12).
func (d device) login(user, password string) uint8 {
	d.t.Helper()
	b, err := d.exchange(wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte(user), Port: []byte("ssh"),
		RemAddr: []byte("198.51.100.4"), Data: []byte(password)}.Encode())
	if err != nil {
		d.t.Fatalf("login: %v (a reset is port49d not admitting the source it saw: the inventory names "+
			"172.30.49.1, the stack's gateway; read `docker compose logs port49d`)", err)
	}
	r, err := wire.DecodeAuthenReply(b)
	if err != nil {
		d.t.Fatal(err)
	}
	return r.Status
}

// permits asks for user's session (no words) or a command at 15.
func (d device) permits(user string, words ...string) bool {
	d.t.Helper()
	priv := uint8(15)
	args := [][]byte{[]byte("service=shell")}
	if len(words) == 0 {
		args, priv = append(args, []byte("cmd=")), 1
	} else {
		args = append(args, []byte("cmd="+words[0]))
		for _, w := range words[1:] {
			args = append(args, []byte("cmd-arg="+w))
		}
		args = append(args, []byte("cmd-arg=<cr>"))
	}
	b, err := d.exchange(wire.TypeAuthor, wire.AuthorRequest{AuthenMethod: wire.AuthenMethodTACACSPlus,
		PrivLvl: priv, AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin, User: []byte(user),
		Port: []byte("vty1"), Args: args}.Encode())
	if err != nil {
		d.t.Fatalf("authorize: %v", err)
	}
	r, err := wire.DecodeAuthorResponse(b)
	if err != nil {
		d.t.Fatal(err)
	}
	return r.Status == wire.AuthorStatusPassAdd || r.Status == wire.AuthorStatusPassRepl
}

// mint asks the broker at addr for a token on device with the client
// certificate WriteCompose cut for alice. The answer carries a token and
// is never printed.
func mint(t *testing.T, local, addr, device string) string {
	t.Helper()
	pki := filepath.Join(local, "broker")
	cert, err := tls.LoadX509KeyPair(filepath.Join(pki, testpki.LabClientCert), filepath.Join(pki, testpki.LabClientKey))
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(filepath.Join(pki, testpki.LabCA))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{cert}, RootCAs: roots, MinVersion: tls.VersionTLS13}}}
	resp, err := c.Post("https://"+addr+"/v1/tokens", "application/json",
		bytes.NewReader([]byte(`{"devices":["`+device+`"]}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out api.MintResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("mint: status %d, the body does not decode", resp.StatusCode)
	}
	if len(out.Results) != 1 || out.Results[0].Login == "" {
		// MintItem.String withholds tokens (internal/broker/api/api.go:57), so
		// %v names the refusal and prints no credential.
		t.Fatalf("mint: status %d, %d result(s): %v", resp.StatusCode, len(out.Results), out.Results)
	}
	return out.Results[0].Login
}
```

- [ ] **Step 11: The smoke test**

`tests/compose/smoke_test.go`:

```go
//go:build compose

// Package compose is the container shape's smoke test (plan 7f, Task 1):
// deploy/compose brought up on a fresh PKI, a device login through it, the
// stack recreated with its volumes kept, and then the same session's next
// command answered, a token minted before redeemed, and the broker's
// broker.state_dir accepted as it was left. `make compose-smoke` runs it;
// `go test ./...` never builds it.
package compose

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/tacacs/wire"
	"github.com/blanketfish/port49/internal/testpki"
)

const project = "port49smoke"

// stack runs docker compose on deploy/compose/compose.yaml as project,
// with local as PORT49_COMPOSE_LOCAL.
type stack struct {
	t           *testing.T
	file, local string
}

func (s stack) run(args ...string) string {
	s.t.Helper()
	out, err := s.try(args...)
	if err != nil {
		s.t.Fatalf("docker compose %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func (s stack) try(args ...string) (string, error) {
	cmd := exec.Command("docker", append([]string{"compose", "-p", project, "-f", s.file}, args...)...)
	cmd.Env = append(os.Environ(), "PORT49_COMPOSE_LOCAL="+s.local)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ready waits up to 3 minutes for /readyz at addr to answer 200.
func ready(t *testing.T, s stack, addr string) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Minute); ; time.Sleep(time.Second) {
		resp, err := http.Get("http://" + addr + "/readyz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s/readyz not 200 in 3m (%v)\n%s", addr, err, s.run("logs", "--no-color"))
		}
	}
}

// envValue is name's value in the env file at path.
func envValue(t *testing.T, path, name string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), name+"="); ok {
			return v
		}
	}
	t.Fatalf("%s names no %s", path, name)
	return ""
}

// waitMarks waits up to 30s for marks.json to exist and be non-empty in the
// broker-state volume, looked at from a throwaway container on the image
// the volume was made from.
func waitMarks(t *testing.T) {
	t.Helper()
	var out []byte
	var err error
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		out, err = exec.Command("docker", "run", "--rm", "-v", project+"_broker-state:/s", "--entrypoint", "test",
			"port49-setup:dev", "-s", "/s/marks.json").CombinedOutput()
		if err == nil {
			return
		}
	}
	t.Fatalf("broker.state_dir/marks.json was not written in 30s after the revoke: %v\n%s", err, out)
}

func TestComposeSmoke(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	local := t.TempDir()
	if err := testpki.WriteCompose(local, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	s := stack{t: t, file: filepath.Join(root, "deploy", "compose", "compose.yaml"), local: local}
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := s.try("logs", "--no-color")
			t.Logf("docker compose logs:\n%s", out)
		}
		s.try("down", "-v", "--remove-orphans")
	})
	s.run("up", "-d", "--build")
	ready(t, s, "127.0.0.1:9050")
	ready(t, s, "127.0.0.1:9049")

	dev := device{t: t, addr: "127.0.0.1:49", key: []byte(envValue(t, filepath.Join(local, "port49d.env"), "PORT49_TACACS_KEY"))}
	if st := dev.login("alice", mint(t, local, "127.0.0.1:8443", "smoke1")); st != wire.AuthenStatusPass {
		t.Fatalf("a device login through the stack: status %d", st)
	}
	if !dev.permits("alice") || !dev.permits("alice", "show", "version") {
		t.Fatal("the session's authorization was refused")
	}
	later := mint(t, local, "127.0.0.1:8443", "smoke1") // redeemed after the recreate

	// A revocation writes the broker's copy of the marks into
	// broker.state_dir (marks.json), which the recreate must keep.
	s.run("exec", "-T", "port49-broker", "port49", "revoke", "--socket", "/run/port49/port49-broker.sock",
		"--principal", "user:bob@example.com") // s.run fails the test on a non-zero exit
	first := s.run("logs", "--no-color", "port49-broker")
	if !strings.Contains(first, "broker.state_dir/marks.json is absent") {
		t.Fatalf("a first start did not say its copy starts from the store:\n%s", first)
	}

	// The broker writes its copy from the store's watch, after `port49
	// revoke` has returned (internal/port49d/markscopy.go:303-311): wait for
	// marks.json before the recreate, or a fast `down` makes "is absent" flaky.
	waitMarks(t)

	// Recreate every container; the named volumes stay.
	s.run("down")
	s.run("up", "-d")
	ready(t, s, "127.0.0.1:9050")
	ready(t, s, "127.0.0.1:9049")

	second := s.run("logs", "--no-color", "port49-broker")
	if strings.Contains(second, "is absent") || strings.Contains(second, "cannot tell whether the store was restored") {
		t.Fatalf("the recreated broker did not find its broker.state_dir as it was left:\n%s", second)
	}
	if !dev.permits("alice", "show", "version") {
		t.Fatal("the session's next command after the recreate was refused: its context did not survive in etcd")
	}
	if st := dev.login("alice", later); st != wire.AuthenStatusPass {
		t.Fatalf("a token minted before the recreate: status %d", st)
	}
	// The volume as the image made it, and as the broker left it.
	st, err := exec.Command("docker", "run", "--rm", "-v", project+"_broker-state:/s", "--entrypoint", "stat",
		"port49-setup:dev", "-c", "%u %g %a", "/s", "/s/marks.json").CombinedOutput()
	if err != nil {
		t.Fatalf("stat the broker-state volume: %v\n%s", err, st)
	}
	lines := strings.Split(strings.TrimSpace(string(st)), "\n")
	if len(lines) != 2 || lines[0] != "65532 65532 700" || !strings.HasPrefix(lines[1], "65532 ") {
		t.Fatalf("broker-state: %q, want the directory 65532 65532 700 and marks.json owned by 65532", lines)
	}
	fmt.Fprintln(os.Stderr, "compose smoke: login, recreate, session kept, token redeemed, state_dir kept")
}
```

The "absent" and "cannot tell" substrings are 7e's lines (`internal/port49d/markscopy.go:96`,
`witness.go:74`). Grep both before running. If a line's wording has changed, use the current
words and keep the meaning: the second run must say neither.

- [ ] **Step 12: Make targets, the vet line, `.gitignore`, CI**

`Makefile`:
- Add `image compose-smoke` to `.PHONY`.
- Add the targets:

```make
# The container image (plan 7f, Task 1): one peer shape, never required.
image:
	docker build --target port49 -t port49:dev .

# The compose stack end to end: up, a device login, the stack recreated
# with its volumes kept, the session and the broker's state_dir kept. Needs
# Docker with Compose v2.24.4+; behind the `compose` tag so `go test ./...`
# never needs Docker.
compose-smoke:
	go test -tags compose ./tests/compose/ -count=1 -v -timeout 20m
```

- In `vet`, after `go vet ./...`, add `go vet -tags compose ./tests/compose/...`.

`.gitignore`, under `# Lab`:

```
# deploy/compose's trial PKI and env files (go run ./tests/compose/cmd/compose-pki)
/deploy/compose/local/
```

`.github/workflows/compose.yml`:

```yaml
# The container shape's smoke test (plan 7f, Task 1). The repository's
# only workflow: `make test` needs the lab's captures, which live on the
# lab machine alone (the labpcap audit), so it is run there and by hand.
name: compose
on:
  push: {branches: [main]}
  pull_request:
permissions: {contents: read}
jobs:
  smoke:
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: {go-version-file: go.mod}
      - run: docker compose version
      - run: make compose-smoke
```

The test prints `docker compose logs` itself on failure (`t.Cleanup`). Those logs are the
decision log and stderr, which never hold a credential (Global Constraints).

- [ ] **Step 13: Run the smoke test**

Run: `make compose-smoke` (needs Docker. If this machine's user cannot reach the Docker socket,
run it on beehive or in CI, and report where it ran).
Expected: PASS, ending `compose smoke: login, recreate, session kept, token redeemed, state_dir kept`.

If it fails, read the logs it prints. The likely causes, each a real fix and never a loosened
assertion:
- `setup.sh`'s ownership;
- the image's directory mode (Step 6's fallback);
- the source address port49d saw (the inventory's gateway);
- an etcd flag.

- [ ] **Step 14: `deploy/compose/README.md`**

Write the operator's page. It is short, and every fact in it is checked by Step 13 or cited:
- **What it is:** one peer shape; nothing requires it.
- **Trial:** the two commands; then mint with the trial's client certificate, or `port49 login
  --broker https://127.0.0.1:8443 --cert local/broker/client.pem --key
  local/broker/client-key.pem --broker-ca local/broker/broker-ca.pem`.
- **The files:** what each volume holds, and why the secrets are split (7e Ruling 1).
- **A deployment:**
  - bring your own PKI under `PORT49_COMPOSE_LOCAL` in the same layout;
  - list devices by the address port49d sees (design §13; L39 (a) once Task 2 measures it);
  - re-apply `store-roles` by hand after an upgrade that changes it.
- **Revoking:** `docker compose exec port49-broker port49 revoke --socket
  /run/port49/port49-broker.sock …`; with every broker down, `docker compose run --rm
  --entrypoint port49-broker port49-broker revoke --offline --principal …` (7e Ruling 13: as
  the broker's user, which the image is).
- **`broker.state_dir`:**
  - one named volume per broker; never `--scale`, never `deploy.replicas`, never an
    anonymous volume;
  - a bind mount, or a volume filled by hand, owned by root is not refused at start (root is
    an accepted owner), but the first `marks.json` or witness write fails, as the 65532
    process cannot write it; a fresh named volume copies 65532/0700 from the image and never
    hits this. The fix is `docker run --rm -v <volume>:/s alpine:3.22 sh -c 'chown
    65532:65532 /s && chmod 0700 /s'`.
- **Backups:** each etcd data volume and `broker-state` (design §13's runbook).
- **What it does not do yet:** plan 12's install page, compaction quota sizing, alarms.

- [ ] **Step 15: Commit**

```bash
git add Dockerfile .dockerignore deploy/compose internal/testpki/compose.go internal/testpki/compose_test.go \
  tests/compose .github/workflows/compose.yml Makefile .gitignore
git update-index --chmod=+x deploy/compose/setup.sh deploy/compose/etcd-init.sh
git commit -m "feat(deploy): the container image, a compose stack on etcd, and its CI smoke test

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 2: (lab, on beehive) The lab on the compose stack, and L39 (a)

**Files:**
- Create: `tests/lab/compose/lab.yaml` (the compose overlay), `tests/lab/compose_test.go`,
  `tests/lab/compose_unit_test.go`, `tests/lab/l39_test.go`
- Modify: `tests/lab/README.md`, `docs/design/2026-08-23-policy-engine-spec.md` (L39's Status),
  `docs/design/2026-08-21-port49-design.md` (§13's source-address sentence for containers)
- Results: `tests/lab/results/L39-docker-proxy-on-arista_eos.md`,
  `L39-docker-proxy-off-arista_eos.md`, and their evidence

**Interfaces:**
- Consumes:
  - Task 1's stack and its env inputs;
  - the harness: `eachPlatform`, `(*lab).capture`, `l.result`, `l.mark`,
    `l.waitForRecords`, `l.errLogSize`, `l.errLinesSince`, `l.loginWithin`, `l.shell`,
    `l.awaitTACACS`;
  - `revokeAgent`, `l29Mint`, `redeemReason`, `sha`, `splitDaemonYAML`, `splitBrokerYAML`,
    `l.derivedConfig`, `platformSessionAttributes`;
  - the constants `sliceEmail`, `sliceUser`, `slicePKIDir`, `tacacsAddr`, `labKeyDefault`.
- Produces:
  - `func (l *lab) startCompose(t *testing.T) *composeStack`, stopped at cleanup, with
    `composeStack` exposing:

    ```go
    func (c *composeStack) HangStore() error     // docker compose pause etcd-1 etcd-2 etcd-3
    func (c *composeStack) ReleaseStore() error  // docker compose unpause …
    func (c *composeStack) StopDaemon() error    // docker compose stop port49d
    func (c *composeStack) StartDaemon() error   // docker compose start port49d, l.logPath/errPath followed again
    func (c *composeStack) Revoke(args ...string) (string, bool) // port49 revoke on the broker's socket, in its container
    func (c *composeStack) ProxyMode() (string, error)           // "on" or "off"
    ```

  - `const composeGateway = "172.30.49.1"`;
  - `func proxyModeOf(ps string) string`;
  - `func composeLabFiles(base, brokerSlice, policy, inventory string) (map[string]string, error)`:
    pure, reads no file. `base` arrives already derived for the platform (`startCompose` calls
    `l.derivedConfig(…, platformSessionAttributes[platform], …)` first, as `prepareSplit`
    does), so the platform is not applied inside it. `brokerSlice` is
    `tests/lab/slice/broker.yaml`'s text, and `policy` and `inventory` are
    `tests/lab/slice/policy.yaml`'s and `tests/lab/inventory-lab.yaml`'s, as `splitBrokerYAML`
    takes `sliceBroker`. The unit test reads the four files relative to the package, as
    `split_unit_test.go:28` does, because `root` is set only by `initGlobal`
    (`harness_test.go:368-374`) and is empty under `make lab-unit`.

- [ ] **Step 1: The compose mode's unit tests**

`tests/lab/compose_unit_test.go` (`//go:build lab`). Its `Test` names are picked up by `make
lab-unit`:

```go
// The lab's compose files name in-container paths and the lab's keys by
// environment, with the device key in port49d's env alone, and an extra
// device at the stack's gateway so a rewritten source is recorded, not
// refused (L39).
func TestComposeLabFilesNameTheContainersPaths(t *testing.T) {
	// Relative to the package: `root` is empty under `make lab-unit`.
	read := func(name string) string {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	files, err := composeLabFiles(read("port49d-lab.yaml"), read(filepath.Join("slice", "broker.yaml")),
		read(filepath.Join("slice", "policy.yaml")), read("inventory-lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// The slice's broker listens on its container's loopback (127.0.0.1:8449);
	// published through 127.0.0.1:8449:8443 that is unreachable, so the
	// compose broker listens on every address of its container, on 8443.
	if b := files["port49-broker.yaml"]; !strings.Contains(b, `listen: ":8443"`) || strings.Contains(b, "127.0.0.1:8449") {
		t.Errorf("port49-broker.yaml does not listen on :8443 in its container:\n%s", b)
	}
	d := files["port49d.yaml"]
	for _, want := range []string{`listen: ":49"`, "/etc/port49/policy.yaml", "/etc/port49/inventory.yaml",
		"https://etcd-1:2379", "/etc/port49/etcd/port49d-key.pem", "/run/port49/port49d.sock"} {
		if !strings.Contains(d, want) {
			t.Errorf("port49d.yaml lacks %q:\n%s", want, d)
		}
	}
	if strings.Contains(files["port49-broker.yaml"], "PORT49_LAB_KEY") {
		t.Errorf("port49-broker.yaml names the device key's secret:\n%s", files["port49-broker.yaml"])
	}
	if !strings.Contains(files["inventory.yaml"], composeGateway) {
		t.Errorf("inventory.yaml lists no device at the gateway %s", composeGateway)
	}
	if strings.Contains(files["port49-broker.env"], "PORT49_LAB_KEY") || !strings.Contains(files["port49d.env"], "PORT49_LAB_KEY=") {
		t.Errorf("the device key is not port49d's alone")
	}
}

// The userland proxy's mode is read from the processes serving the
// published port: a docker-proxy for 172.100.100.1:49 is "on".
func TestProxyModeReadsTheProcessList(t *testing.T) {
	on := "1234 /usr/bin/docker-proxy -proto tcp -host-ip 172.100.100.1 -host-port 49 -container-ip 172.30.49.5 -container-port 49\n"
	if proxyModeOf(on) != "on" || proxyModeOf("1 /sbin/init\n") != "off" {
		t.Fatal(proxyModeOf(on), proxyModeOf("1 /sbin/init\n"))
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test -tags lab ./tests/lab/ -run 'TestComposeLabFilesNameTheContainersPaths|TestProxyModeReadsTheProcessList' -count=1`
Expected: FAIL, undefined `composeLabFiles`, `proxyModeOf`, `composeGateway`.

- [ ] **Step 3: The overlay and the compose mode**

`tests/lab/compose/lab.yaml`:

```yaml
# The lab's overlay on deploy/compose (plan 7f, Task 2): port49d on the
# clab bridge's gateway, where every topology's devices send TACACS+, and
# the broker on the slice's URL (sliceBrokerURL). Compose v2.24.4+ (!override).
services:
  port49d:
    ports: !override
      - "172.100.100.1:49:49"
      - "127.0.0.1:9049:9049"
  port49-broker:
    ports: !override
      - "127.0.0.1:8449:8443"
      - "127.0.0.1:9050:9050"
```

`tests/lab/compose_test.go` (`//go:build lab`) holds:

- **`composeGateway = "172.30.49.1"`**, and `composeProject = "port49lab"`.
- **`composeLabFiles(base, brokerSlice, policy, inventory)`** returns the four YAML files and
  two env files a run writes:
  - `port49d.yaml`: `splitDaemonYAML(base, splitNode{Listen: ":49", Metrics: ":9049", Admin:
    "/run/port49/port49d.sock", Spool: "/var/spool/port49d/acct.jsonl"}, "/etc/port49/policy.yaml",
    "/etc/port49/inventory.yaml", composeStoreBlock("daemon"))`, where `base` is
    `l.derivedConfig("compose-base", platformSessionAttributes[platform], …)`'s body, as
    `prepareSplit` derives it (harness_test.go:2607).
  - `port49-broker.yaml`: `splitBrokerYAML(base, brokerSlice, splitBrokerOpts{Policy:
    "/etc/port49/policy.yaml", Inventory: "/etc/port49/inventory.yaml", State:
    "/var/lib/port49-broker", Metrics: ":9050", Admin: "/run/port49/port49-broker.sock", Store:
    composeStoreBlock("broker"), PKI: "/etc/port49/broker"})`, then its `broker:` block's
    `listen:` rewritten to `":8443"`. `splitBrokerYAML` passes the slice's `listen:
    "127.0.0.1:8449"` (`tests/lab/slice/broker.yaml:6`) through unchanged, and inside the
    container that loopback address cannot be reached through the published
    `127.0.0.1:8449:8443`, so every `revokeAgent` and `port49 login` would fail before L39 or
    L41 measured anything. `composeLabFiles` fails if the string it rewrites is not there,
    rather than shipping a config that listens on loopback.
  - `policy.yaml`: the `policy` argument.
  - `inventory.yaml`: the `inventory` argument with one device appended, `{name:
    l39_gateway, platform: arista_eos, addresses: [172.30.49.1]}`, inside the `devices:` list,
    and a key group for `172.30.49.0/24` → `lab_key`.
  - `port49d.env`: `PORT49_LAB_KEY=<labKeyDefault>` and `PORT49_LAB_ENC_KEY=<the harness's
    value>`.
  - `port49-broker.env`: `PORT49_LAB_ENC_KEY` alone.

  The two `splitBrokerYAML` file names must match what Task 1's `setup.sh` copies:
  `/etc/port49/broker/broker.pem`, `broker-key.pem` and `broker-ca.pem`. If `splitBrokerYAML`
  takes the PKI's file names from `testpki.Lab*`, they already match.
- **`composeStoreBlock(component string) string`** writes the store: block Task 1's configs
  name for that component, with the three in-container endpoints, plus `hold_ttl: 60s` (the
  lab's, as `storeLab`).
- **`(*lab) startCompose(t)`** does, in order:
  1. Stops the standing host port49d, as `prepareSplit` does. t.Cleanup puts it back.
  2. Writes `tests/lab/logs/compose-<platform>/{config,local}`:
     - `testpki.WriteCompose(local, sliceEmail, now)`;
     - then overwrites `local/broker` with `testpki.WriteLab(local/broker, sliceEmail, now)`,
       so the agent's `slicePKIDir` copy matches. Copy the same files into `slicePKIDir`, which
       `revokeAgent` reads;
     - then the files from `composeLabFiles`.
  3. Runs `docker compose -p port49lab -f deploy/compose/compose.yaml -f tests/lab/compose/lab.yaml
     up -d --build`, with `PORT49_COMPOSE_LOCAL` and `PORT49_COMPOSE_CONFIG` set to those
     directories.
  4. Starts two followers:
     - `docker logs -f --since 0s port49lab-port49d-1`, stdout appended to `l.logPath` and
       stderr to `l.errPath`;
     - the same for the broker into `tests/lab/logs/compose-<platform>/broker.{log,err}`.
  5. Waits for the broker's `127.0.0.1:9050/readyz` and port49d's `127.0.0.1:9049/readyz` to
     answer 200 (up to 3 minutes), as Task 1's smoke test does, and then for
     `l.awaitTACACS()`. That call returns nil on every platform except IOS-XE
     (`adapters_test.go:344-348`), so on its own it proves nothing about port49d on the other
     four.
  6. At cleanup: `down -v`, then the followers stopped.
- **`StartDaemon`** starts a fresh follower with `--since <the stop's time>`, so no line is
  doubled in `l.errPath`.
- **`Revoke(args...)`** is `docker compose exec -T port49-broker port49 revoke --socket
  /run/port49/port49-broker.sock args...`. It returns the output and whether it exited 0, as
  `revokeCLI` does.
- **`ProxyMode()`** runs `ps -eo pid,args` and returns `proxyModeOf` of it.
- **`proxyModeOf(ps)`** is `"on"` when a line holds `docker-proxy` and `-host-ip 172.100.100.1
  -host-port 49`, and `"off"` otherwise.

Every helper writes what it ran into `tests/lab/logs/compose-<platform>/compose.log`. A failed
`up` fails the test with that log's tail, never with a bare exit code.

- [ ] **Step 4: Run the unit tests to verify they pass**

Run: `make lab-unit`
Expected: PASS, including the two new tests.

- [ ] **Step 5: The L39 test**

`tests/lab/l39_test.go` (`//go:build lab`):

```go
package lab

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const l39Claim = "On the compose deployment (plan 7f; deploy/compose), with port49d's TACACS+ port published on " +
	"the clab bridge's address (172.100.100.1:49), port49d sees the device's own address as the TCP source, so " +
	"the device-binding check passes for the known device: the redeem record's device.nas is the device's " +
	"management address, not the compose network's gateway (" + composeGateway + ", listed as l39_gateway so a " +
	"rewritten source is recorded rather than refused). Measured with Docker's userland proxy as the run found it " +
	"(policy engine spec §15 L39 (a); design §13)."

// TestL39DockerSourceAddress measures L39 (a) in the mode Docker runs in
// now: run it once with the userland proxy on (Docker's default) and once
// with "userland-proxy": false in /etc/docker/daemon.json (Task 2 Step 7).
// One platform is enough (the observation is the server's): run it with
// PORT49_LAB_PLATFORMS=eos.
func TestL39DockerSourceAddress(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		c := l.startCompose(t)
		mode, err := c.ProxyMode()
		if err != nil {
			t.Fatal(err)
		}
		entry := "L39-docker-proxy-" + mode
		stop := l.capture(t, entry)
		defer stop()
		off := l.mark()
		sock, _, stopAgent := revokeAgent(t)
		defer stopAgent()
		said, tok := l29Mint(sock, l.p.node)
		if tok == "" {
			t.Fatalf("the agent minted no token through the compose broker: %s", said)
		}
		_, lerr := l.loginWithin(sliceUser, tok, 90*time.Second, "show version")
		recs := l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool { return redeemReason(rs, sha(tok)) != "" })
		nas, name := "", ""
		for _, r := range sliceRecords(recs, "redeem", "") {
			if str(sub(r, "auth"), "credential_sha256") == sha(tok) {
				nas, name = str(sub(r, "device"), "nas"), str(sub(r, "device"), "name")
			}
		}
		var obs strings.Builder
		obs.WriteString("| cell | observed |\n|---|---|\n")
		fmt.Fprintf(&obs, "| Docker's userland proxy | %s (a docker-proxy process %s 172.100.100.1:49) |\n", mode,
			map[string]string{"on": "serves", "off": "does not serve"}[mode])
		fmt.Fprintf(&obs, "| the redeem record's device | nas %q, name %q (the device's address: %s) |\n", nas, name, l.p.addr)
		fmt.Fprintf(&obs, "| the login | err %v; redeem %q |\n", lerr, redeemReason(recs, sha(tok)))
		note := obs.String()
		failed := nas != l.p.addr || lerr != nil
		if failed && nas == "" && len(recs) == 0 {
			// No record at all is "the connection never reached port49d", not a
			// rewritten source: Docker's bridge isolation can drop traffic
			// DNAT'd from the clab network to the compose network (Step 5a).
			note += "\n**No connection reached port49d:** no record of any kind, so this says nothing about the " +
				"source address. Step 5a's reachability check decides which it is.\n"
		} else if failed {
			note += fmt.Sprintf("\n**Not as the claim says:** port49d saw %q, not the device's %s.\n", nas, l.p.addr)
		}
		l.result(t, entry, l39Claim, note)
		if failed {
			t.Fatalf("L39 (a), proxy %s: port49d saw %q, want %s; login err %v", mode, nas, l.p.addr, lerr)
		}
	})
}
```

`sliceRecords`, `str` and `sub` are the harness's record readers (`redeemReason` uses them,
`revoke_test.go`). `l.p.addr` is the device's management address. Check the field name in
`harness_test.go`'s platform table and use it.

- [ ] **Step 5a: Can the device reach the published port at all?**

containerlab's management network is a Docker bridge, and Docker's `DOCKER-ISOLATION-STAGE-1/2`
chains can drop traffic DNAT'd from `172.100.100.0/24` to the compose subnet. Before L39 or L41
is read, make one device-side TCP connect to `172.100.100.1:49` with the stack up (a throwaway
test, or by hand through `l.shell` on the device), and check that port49d's log or stderr shows
that connection (a record, or the line for a source it does not admit).
- **A connection is seen.** Go on to Step 6. The L39 note then tells a rewritten source apart
  from this case (see the test above).
- **Nothing is seen.** Stop. The compose deployment is not reachable from the clab network
  through its published port, so L39 would record `nas ""` and L41 could not run. The fallback
  is to attach port49d to the clab management network as an external network in the lab
  overlay. That changes what the lab measures against what the compose file ships, so it is
  Ryan's call: take it to Ryan with this check's output and do not add it unasked.

- [ ] **Step 6: Run it with the proxy on (Docker's default)**

On beehive, with the watchdog armed:

Run: `PORT49_LAB_PLATFORMS=eos go test -tags lab ./tests/lab/ -run TestL39DockerSourceAddress -count=1 -v -timeout 60m`
Expected: PASS, with `results/L39-docker-proxy-on-arista_eos.md` written. If it fails, the note
records what port49d saw. That is a measurement, not a defect: the row then records it, and
design §13's container sentence (Step 9) says the source is rewritten.

- [ ] **Step 7: Run it with the proxy off, then restore Docker**

As root on beehive, with consent standing for lab runs:
1. Back up `/etc/docker/daemon.json`.
2. Set `"userland-proxy": false` in it.
3. `systemctl restart docker`. This stops every container on beehive, including the clab
   topology and the compose stack. Run it between tests, with nothing else using beehive, and
   treat the next step as a cold start: the harness redeploys both (`startCompose`'s `up -d
   --build`, and the platform's topology deploy, which takes the platform's boot time, several
   minutes for vEOS).
4. Run Step 6's command again. Expected: `results/L39-docker-proxy-off-arista_eos.md`.
5. Restore the file and `systemctl restart docker`.
6. Check `docker info` answers, and that `ps -eo args | grep docker-proxy` shows the proxy back
   once a port is published.

If root is not available, this half is not measured: the row says "(a) proxy on measured; proxy
off open". Never claim the off half.

- [ ] **Step 8: Evidence**

Run: `make evidence`, then check `tests/lab/evidence/L39-docker-proxy-*.pcap` exist and the
notes point at them.

- [ ] **Step 9: Docs: L39's Status, design §13**

Spec §15, L39's Status cell. Replace `open — added 2026-10-03 (deployment shapes, Ryan). L37 and
L38 are plan 7e's` with:

`open — (a) measured <date>, on vEOS-lab 4.31.2F through deploy/compose (plan 7f):
tests/lab/results/L39-docker-proxy-on-arista_eos.md, L39-docker-proxy-off-arista_eos.md. <what
port49d saw, per mode, in one sentence each>. (b) and (c), Kubernetes, are plan 12's.`

Write the sentence from the notes, never ahead of them.

Design §13, the bullet ending `policy engine spec §15 L39 measures the container and Kubernetes
cases)`: add, from the notes, what a published port does to the source address with the proxy on
and off. Cite both notes.

CLAUDE.md rule 4: if a note contradicts the roadmap's "Under Docker, the userland proxy and port
publishing can rewrite it", fix that sentence too, and say so in the commit message.

- [ ] **Step 10: `tests/lab/README.md`**

Add a section, "The compose mode (plan 7f)", covering:
- `l.startCompose`, and what it publishes where;
- its files (`tests/lab/logs/compose-<platform>/`);
- the store hang (`docker compose pause`);
- Docker Compose ≥ v2.24.4;
- that new register rows run on it, and closed rows' re-checks stay on the host harness.

- [ ] **Step 11: Commit**

```bash
git add tests/lab/compose tests/lab/compose_test.go tests/lab/compose_unit_test.go tests/lab/l39_test.go \
  tests/lab/README.md tests/lab/results/L39-* tests/lab/evidence/L39-* docs/design
git commit -m "test(lab): the lab on the compose stack, and L39 (a) measured through it

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 3: The spec and the design say what 7f builds, and L41 opens

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`, `docs/design/2026-08-21-port49-design.md`

**Interfaces:** none (docs). Tasks 4–9 build what this records.

- [ ] **Step 1: Decision 37**

In spec §13, after decision 36 and before `### Deferred, with reasons`, add:

```markdown
**37. port49d goes dark on store health checks, N in a row; a replica answers commands from a
context cache it is told to keep; and port49 ships a container shape.** *Plan 7f, 2026-10-05.*

- **Health checks.** On etcd, port49d checks the store every `store.etcd.health.interval`
  (default 1s, 200ms to 10s, at least `store.etcd.call_timeout`).
  - **What a check is.** A linearizable read on each of its two etcd connections, made at once
    and bounded together by `call_timeout`. The context connection's read waits for the
    context feed (the feed fence).
  - **What fails it.** Any error, a refusal by the roles included.
  - **Where it runs.** Under the guard: it takes no slot and trips no circuit. It runs whether
    or not a device asks.
- **Closing.** `close_after` consecutive failures (default 5, 2 to 60) are a store gone (decision
  35): every listener closes and held connections are reset. Idle or loaded, port49d is dark
  within `close_after` × `interval` + `call_timeout` of the store stopping (5.5s at the
  defaults, derived from them; §15 L41 measures it). This replaces decision 36's probe. The
  guard's `hold_ttl` rule stays as the backstop.
  - **What the defaults were tested against.** Two conditions with quorum healthy, neither of
    which may close the listeners: a killed leader's election, and one member hung with its
    TCP connection alive (a defragmenting, wedged or partitioned member). Both pings carry
    `WithRequireLeader`, so a member with no leader answers at once and the client retries
    another endpoint, instead of the check waiting out `call_timeout`.
  - **Feed lag is a trigger.** The context connection's read waits for the context feed, so a
    feed more than `call_timeout` behind (a mass refresh burst, for example) fails the check,
    and `close_after` of them close every replica. The same reads are denied
    `store_unavailable` then. An operator who sees dark with etcd healthy looks at
    `port49_store_fence_timeouts_total`.
- **Reopening.** A run after a store gone waits for the store as at a start, re-reading its
  files. It binds TACACS+ only after `open_after` consecutive checks pass (default 3, 1 to 60);
  a failure starts the count again. A cold start is not gated.
- **Break-glass.** Nothing port49 answers changes. On IOS-XE, whose authentication `ERROR` is
  final (§15 L4, L35), break-glass is refused until port49d is dark, now at most
  `close_after` × `interval` + `call_timeout`.
- **The context cache (design §12).** It is off unless `store.etcd.context_cache.ttl` is set
  (100ms to 60s), with `max_entries` (default 65536). Only command and session authorization
  read through it: never a login, an enable, accounting or a token redemption.
  - **A hit:** the entry younger than the TTL, the context feed up, and no later record known
    at the key. What bounds a hit is the TTL, not the feed's `Up()`: `FollowContexts` marks the
    feed up before its watch is established, and a watch hung on a dead connection reads up.
  - **Eviction:**
    - a write through it evicts the key;
    - every change the context feed brings evicts its key, a delete included;
    - a compacted rescan clears it.

    So a revocation reaches a cached session at the feed's speed.
  - **Through an outage.** A read the store fails to answer (a timeout, an open circuit) is
    answered from the entry the ledger still knows, within the context's idle TTL, counted
    `stale` and said once. Never on a fence timeout: that is the store answering with a later
    record than the cached one, which may be a revocation, so the read is denied. A
    revocation made during a true outage does not reach a cached session, until a read lands
    or the listeners close. The cache lives for one run.
  - **Blobs** were already cached compiled by hash (§5.1.1).
- **Who sets it.** Both `store.etcd.health` and `store.etcd.context_cache` are port49d's;
  port49-broker.yaml refuses them.
- **The container shape.**
  - **The image.** One image of the four static binaries, run as uid 65532.
  - **The stack.** A compose stack (`deploy/compose`) of port49d, port49-broker and three etcd
    members with client-certificate auth and port49's roles. It has one configuration volume
    per component (no container holds both etcd identities, and the device key is in port49d's
    alone), and a named volume per broker for `broker.state_dir`, created 0700 and owned by
    the broker's user from the image.
  - **The test.** A CI smoke test brings it up, logs a device in, recreates it with its volumes
    kept, and finds the session, a token minted before, and `broker.state_dir` kept.
  - **Not required.** It is one shape beside systemd and Kubernetes. Nothing requires it.
  - **Source addresses.** What a published port does to a device's source address is §15 L39
    (a).
```

- [ ] **Step 2: Decisions 35 and 36 amended**

The quoted spans below can wrap across lines in the spec file. Match on the sentence's
beginning and end, never on a quote that spans a line break.

Decision 35, the bullet `- **A store gone is a store that is down.** port49d closes every
listener when:`. Add a first sub-bullet before `it loses its hold on the keyspace;`:

`its store health checks fail `store.etcd.health.close_after` times in a row (decision 37);`

In the same bullet, replace the sentence beginning `the owner's go-dark ruling of 2026-09-24
in its coarse form` (it ends `port49d then waits`) with `the owner's go-dark ruling of
2026-09-24, refined by decision 37. port49d then waits`. After `retrying any error that start meets.`, add `It binds
TACACS+ again only after `store.etcd.health.open_after` checks pass in a row (decision 37).`

Decision 36, the bullet `- **The daemon's start on etcd** …`. Replace the sentence beginning
`It probes the store` (it wraps across lines in the spec), from there through `(about 2
minutes: `L37-*.md`; plan 7f carries the gap), on a store or a context feed that has stopped;`
with:

`It checks the store's health every `store.etcd.health.interval` (decision 37), which replaced
plan 7e's probe: under 7e's probe an idle port49d went dark about 2 minutes into a hang at
`hold_ttl` 60s (`L37-*.md`); under the checks, within `close_after` × `interval` +
`call_timeout`, idle or not (§15 L41), on a store or a context feed that has stopped;`

- [ ] **Step 3: L41 opened**

After L40's row in §15, add:

```markdown
| **L41** | On the compose deployment (decision 37), what a device does when port49d closes its TACACS+ listener mid-session on its store health checks, beside port49d stopped: how long after the store hangs an idle port49d closes it (against `close_after` × `interval` + `call_timeout`); an open session's next command once it is closed, and with port49d stopped; break-glass once it is closed; once the store returns, how long until port49d listens again (after `open_after` passes) and until the device asks it again; and whether the session's next command port49d is asked is answered from the context the store kept. | Decision 37's defaults and design §12's store rows (the go-dark timing and what follows it) | EOS, NX-OS, IOS-XE, vJunos-router, vSRX | open — added 2026-10-05 (plan 7f) |
```

- [ ] **Step 4: Design §12**

- **The "Token store unavailable" row.** Replace from `port49d will do this itself by closing its
  TACACS+ listener while the store is unhealthy (owner's ruling 2026-09-24; plan 7f);` through
  `Continuing active logins from a replica's warm context cache through a store outage is plan
  7f's` with:

  `port49d does this itself (owner's ruling 2026-09-24; policy engine spec §13 decision 37): it
  checks the store every `store.etcd.health.interval` (1s) and closes its TACACS+ listener after
  `close_after` (5) failed checks in a row, idle or under load, within `close_after` ×
  `interval` + `call_timeout` of the store stopping (5.5s at the defaults, derived from them;
  policy engine spec §15 L41 measures it). Until it does, IOS-XE refuses a break-glass login too (L35), and after it,
  break-glass logs in. Before plan 7f it closed it once it lost its hold, 12–25s into a hang at
  `hold_ttl` 60s (L35), and on the split deployment 1m43s–2m0s in (L37). With
  `store.etcd.context_cache.ttl` set, a replica that holds a login's context answers its
  commands from that cache until the listener closes (Consequences, below)`
- **The "Store hangs or loses quorum" row, its second cell.** Replace from `On the split
  deployment port49d holds no hold: it closes them once a pool's circuit has stayed open for
  `hold_ttl`,` through `(plan 7f's gap).` with:

  `On the split deployment port49d holds no hold: its store health checks close them after
  `close_after` failures in a row, within `close_after` × `interval` + `call_timeout` (decision
  37; L41), idle or not, and a pool's circuit open for `hold_ttl` still does too. Before plan 7f
  an idle port49d took 1m43s–2m0s at `hold_ttl` 60s (L37), because its probe needed five failed
  pings a sixth of `hold_ttl` apart.`
- **"Consequences".** In the bullet `- **Per-replica read-through cache for login contexts**`,
  after the sentence beginning `Token redemption MUST NOT be cached` (it wraps across lines at
  design 1220–1221 and ends `the single-use authority.`), add:

  `As built (plan 7f; policy engine spec §13 decision 37): off unless
  `store.etcd.context_cache.ttl` is set; for command and session authorization only; every
  change the context feed brings evicts its key, so a revocation reaches a cached session at the
  feed's speed, not the TTL's; through an outage an entry is served past its TTL, counted
  `port49_context_cache_lookups_total{outcome="stale"}` and said, until the listener closes,
  which go-dark bounds to `close_after` × `interval` + `call_timeout`. A read the store
  answered with a later record (a context feed behind `call_timeout`) is never served stale.`
- **"As built on etcd".** Replace the bullet `- The warm context cache stays plan 7f's.` with:

  `- **Health checks** (plan 7f): every `store.etcd.health.interval`, a read on each pool's
  connection under the guard; `close_after` failures in a row are a store gone, and a run
  after one binds again after `open_after` passes (decision 37). The context cache is above.`
- **The paragraph beginning `**Store health MUST NOT be wired into the readiness probe.**`.**
  (Its quoted spans wrap in the design file: match each on its first words.) Replace `after N consecutive failed checks, reopening after M passes —` with `after
  `store.etcd.health.close_after` consecutive failed checks, reopening after `open_after`
  passes (plan 7f, decision 37) —`. Replace `It is plan 7f's; on etcd, plan 7d already closes
  every listener once the store has been gone for store.etcd.hold_ttl,` with `On etcd, plan 7d
  first closed every listener once the store had been gone for store.etcd.hold_ttl, and plan 7f
  closes it on the health checks,`.

- [ ] **Step 5: Design §15**

In "The store (plan 7d) exports:", after the `port49_broker_mint_gate_closed` bullet, add:

```markdown
- `port49_store_health_checks_total{outcome}` (`pass`, `fail`) and `port49_store_health_failures`,
  the failed checks in a row now, on port49d (plan 7f);
- `port49_context_cache_lookups_total{outcome}` (`hit`, `miss`, `stale`) and
  `port49_context_cache_entries`, on port49d with the cache on (plan 7f).
```

In "Alert on any of:", add:

```markdown
- `port49_store_health_failures` above 0 for longer than three `store.etcd.health.interval`s: the
  store is failing port49d's checks, and the listeners close at `close_after`. The gauge is
  held by the process, not the run: it carries across the run restart a go-dark causes, and
  reads at least `close_after` while the next run waits for the store, so the alert does not
  resolve at the close and stays raised through the whole outage;
- any increase of `port49_context_cache_lookups_total{outcome="stale"}`: a replica is answering
  commands from contexts the store did not confirm, and revocation does not reach them until the
  store answers or the listeners close. The registry restarts with each run after a store gone,
  so the line `serving cached login contexts past store.etcd.context_cache.ttl` is the durable
  witness.
```

- [ ] **Step 6: Check, then commit**

Run: `grep -n "plan 7f's\|7f carries\|plan 7f carries" docs/design/*.md`
Expected: no line that still says something is plan 7f's future work, except under "Deferred".

```bash
git add docs/design
git commit -m "docs: decision 37 (go-dark on health checks, the context cache, the container shape), L41 opened

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 4: `store.etcd.health` and `store.etcd.context_cache`

**Files:**
- Modify: `internal/config/config.go:326-381` (`EtcdConfig`), `:1859-1917` (`checkStoreShape`),
  `:1926-` (`checkStore`)
- Test: `internal/config/store_test.go`

**Interfaces:**
- Consumes: `checkStoreShape(s storeYAML) (StoreConfig, error)`, `checkStore(s storeYAML, role Role,
  hasBroker, hasPolicy, hasAdminSocket bool)`, `etcdYAML(dir)`, `storeFiles(t)`.
- Produces:

```go
type EtcdHealth struct {
	Interval   time.Duration `yaml:"interval"`
	CloseAfter int           `yaml:"close_after"`
	OpenAfter  int           `yaml:"open_after"`
}
type EtcdContextCache struct {
	TTL        time.Duration `yaml:"ttl"`
	MaxEntries int           `yaml:"max_entries"`
}
// in EtcdConfig:
HealthSet       *EtcdHealth       `yaml:"health"`
Health          EtcdHealth        `yaml:"-"` // resolved: always set on etcd
ContextCacheSet *EtcdContextCache `yaml:"context_cache"`
ContextCache    EtcdContextCache  `yaml:"-"` // resolved: TTL 0 is off
```

- [ ] **Step 1: The failing tests**

Append to `internal/config/store_test.go`:

```go
// store.etcd.health takes its defaults, and the cache is off until its
// ttl is set (plan 7f, Rulings 3, 5): the design asks for the TTL as
// explicit configuration, so port49 never picks one.
func TestHealthDefaultsAndTheCacheIsOffUntilSet(t *testing.T) {
	s, err := checkStoreShape(etcdYAML(storeFiles(t)))
	if err != nil {
		t.Fatal(err)
	}
	if h := s.Etcd.Health; h.Interval != time.Second || h.CloseAfter != 5 || h.OpenAfter != 3 {
		t.Fatalf("health %+v", h)
	}
	if c := s.Etcd.ContextCache; c.TTL != 0 || c.MaxEntries != 65536 {
		t.Fatalf("context_cache %+v", c)
	}
	y := etcdYAML(storeFiles(t))
	y.Etcd.ContextCacheSet = &EtcdContextCache{TTL: 2 * time.Second}
	y.Etcd.HealthSet = &EtcdHealth{Interval: 500 * time.Millisecond, CloseAfter: 3}
	s, err = checkStoreShape(y)
	if err != nil {
		t.Fatal(err)
	}
	if s.Etcd.ContextCache.TTL != 2*time.Second || s.Etcd.ContextCache.MaxEntries != 65536 ||
		s.Etcd.Health.Interval != 500*time.Millisecond || s.Etcd.Health.CloseAfter != 3 || s.Etcd.Health.OpenAfter != 3 {
		t.Fatalf("%+v %+v", s.Etcd.Health, s.Etcd.ContextCache)
	}
}

func TestHealthAndCacheBounds(t *testing.T) {
	dir := storeFiles(t)
	for _, c := range []struct {
		name string
		edit func(*storeYAML)
		want string
	}{
		{"an interval too short", func(s *storeYAML) { s.Etcd.HealthSet = &EtcdHealth{Interval: 100 * time.Millisecond} },
			"store.etcd.health.interval 100ms: must be 200ms to 10s"},
		{"an interval below the call timeout", func(s *storeYAML) {
			s.Etcd.CallTimeout = time.Second
			s.Etcd.HealthSet = &EtcdHealth{Interval: 500 * time.Millisecond}
		}, "must be at least store.etcd.call_timeout (1s), which bounds each check"},
		{"close after one", func(s *storeYAML) { s.Etcd.HealthSet = &EtcdHealth{CloseAfter: 1} },
			"store.etcd.health.close_after 1: must be 2 to 60"},
		{"open after too many", func(s *storeYAML) { s.Etcd.HealthSet = &EtcdHealth{OpenAfter: 61} },
			"store.etcd.health.open_after 61: must be 1 to 60"},
		{"a cache ttl of minutes", func(s *storeYAML) { s.Etcd.ContextCacheSet = &EtcdContextCache{TTL: 2 * time.Minute} },
			`store.etcd.context_cache.ttl 2m0s: must be 100ms to 1m0s ("seconds, not minutes": design §12)`},
		{"a cache with no ttl", func(s *storeYAML) { s.Etcd.ContextCacheSet = &EtcdContextCache{MaxEntries: 10} },
			"store.etcd.context_cache.ttl is not set: the cache's ttl is explicit configuration (design §12)"},
		{"a cache too large", func(s *storeYAML) {
			s.Etcd.ContextCacheSet = &EtcdContextCache{TTL: time.Second, MaxEntries: 1 << 21}
		}, "store.etcd.context_cache.max_entries 2097152: must be 1 to 1048576"},
	} {
		y := etcdYAML(dir)
		c.edit(&y)
		if _, err := checkStoreShape(y); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

// Both blocks are port49d's: the broker never closes a listener on the
// store and serves no device (Ruling 7).
func TestTheBrokerRefusesTheDaemonsStoreBlocks(t *testing.T) {
	dir := storeFiles(t)
	for _, c := range []struct {
		edit func(*storeYAML)
		want string
	}{
		{func(s *storeYAML) { s.Etcd.HealthSet = &EtcdHealth{} }, "store.etcd.health is port49d's"},
		{func(s *storeYAML) { s.Etcd.ContextCacheSet = &EtcdContextCache{TTL: time.Second} }, "store.etcd.context_cache is port49d's"},
	} {
		y := etcdYAML(dir)
		y.Etcd.Daemon = EtcdIdentity{}
		c.edit(&y)
		if _, err := checkStore(y, RoleBroker, true, false, true); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v, want %q", err, c.want)
		}
	}
}
```

A `context_cache:` block with no `ttl` is refused rather than read as "off". An operator who
wrote the block meant a cache; silently off would be discovered, not documented.

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/config/ -run 'TestHealthDefaults|TestHealthAndCacheBounds|TestTheBrokerRefusesTheDaemonsStoreBlocks' -count=1`
Expected: FAIL, undefined `EtcdHealth`, `EtcdContextCache`.

- [ ] **Step 3: The types and the checks**

In `internal/config/config.go`, add the two types after `EtcdInFlight`:

```go
// EtcdHealth is store.etcd.health (plan 7f; spec §13, decision 37):
// port49d checks the store every Interval (default 1s, 200ms to 10s, at
// least call_timeout, which bounds each check), closes every listener after
// CloseAfter consecutive failed checks (default 5, 2 to 60), and, in a run
// after that, listens again after OpenAfter consecutive passes (default 3,
// 1 to 60). port49d's alone.
type EtcdHealth struct {
	Interval   time.Duration `yaml:"interval"`
	CloseAfter int           `yaml:"close_after"`
	OpenAfter  int           `yaml:"open_after"`
}

// EtcdContextCache is store.etcd.context_cache (plan 7f; design §12):
// command and session authorization read a context from it for up to TTL
// (100ms to 60s; "seconds, not minutes"), at most MaxEntries (default
// 65536, 1 to 1048576). Absent, there is no cache: its TTL is a term in
// revocation latency, which the design makes explicit configuration, so a
// block with no ttl is refused. port49d's alone.
type EtcdContextCache struct {
	TTL        time.Duration `yaml:"ttl"`
	MaxEntries int           `yaml:"max_entries"`
}
```

In `EtcdConfig`, after `StartTimeout`:

```go
	// HealthSet is the health key, a pointer so port49-broker.yaml can
	// refuse it present (Ruling 7); Health is its resolved value, set on
	// every etcd store.
	HealthSet *EtcdHealth `yaml:"health"`
	Health    EtcdHealth  `yaml:"-"`
	// ContextCacheSet is the context_cache key, absent for no cache;
	// ContextCache is its resolved value, TTL 0 when off.
	ContextCacheSet *EtcdContextCache `yaml:"context_cache"`
	ContextCache    EtcdContextCache  `yaml:"-"`
```

In `checkStoreShape`, after the `start_timeout` check and before the integer loop:

```go
	// health: each value its default when absent (plan 7f, Ruling 3).
	if e.HealthSet != nil {
		e.Health = *e.HealthSet
	}
	e.Health.Interval = orD(e.Health.Interval, time.Second)
	if e.Health.Interval < 200*time.Millisecond || e.Health.Interval > 10*time.Second {
		return StoreConfig{}, fmt.Errorf("store.etcd.health.interval %v: must be 200ms to 10s", e.Health.Interval)
	}
	// context_cache: absent is no cache; present, its ttl is required
	// (Ruling 5).
	if c := e.ContextCacheSet; c != nil {
		if c.TTL == 0 {
			return StoreConfig{}, errors.New("store.etcd.context_cache.ttl is not set: the cache's ttl is explicit " +
				"configuration (design §12); set it, or remove store.etcd.context_cache for no cache")
		}
		if c.TTL < 100*time.Millisecond || c.TTL > time.Minute {
			return StoreConfig{}, fmt.Errorf("store.etcd.context_cache.ttl %v: must be 100ms to 1m0s (\"seconds, not "+
				"minutes\": design §12)", c.TTL)
		}
		e.ContextCache = *c
	}
```

Extend the integer loop with:

```go
		{"store.etcd.health.close_after", &e.Health.CloseAfter, 5, 2, 60},
		{"store.etcd.health.open_after", &e.Health.OpenAfter, 3, 1, 60},
		{"store.etcd.context_cache.max_entries", &e.ContextCache.MaxEntries, 65536, 1, 1 << 20},
```

After the loop, beside the `packet_deadline` check:

```go
	if e.Health.Interval < e.CallTimeout {
		return StoreConfig{}, fmt.Errorf("store.etcd.health.interval %v: must be at least store.etcd.call_timeout "+
			"(%v), which bounds each check", e.Health.Interval, e.CallTimeout)
	}
```

The interval comparison runs after `call_timeout` is resolved, which the duration loop has
already done.

In `checkStore`, in `case RoleBroker:` after the daemon-identity refusal:

```go
		if s.Etcd.HealthSet != nil {
			return StoreConfig{}, errors.New("store.etcd.health is port49d's: port49-broker never closes a listener " +
				"on the store (design §12); remove it from port49-broker.yaml")
		}
		if s.Etcd.ContextCacheSet != nil {
			return StoreConfig{}, errors.New("store.etcd.context_cache is port49d's: port49-broker serves no device; " +
				"remove it from port49-broker.yaml")
		}
```

`s` is the `storeYAML`, whose `Etcd` is the unresolved `*EtcdConfig`, so the `Set` pointers are
as written.

- [ ] **Step 4: Run them to verify they pass, then the package**

Run: `go test ./internal/config/ -count=1`
Expected: PASS. A test that compares a whole resolved `EtcdConfig` will now see `Health` set:
update its expectation, and say which in the commit.

- [ ] **Step 5: Commit**

```bash
git add internal/config
git commit -m "feat(config): store.etcd.health and store.etcd.context_cache, port49d's alone

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 5: The health check: `PingToken`, `watch`, `passes`, and a killed leader

**Files:**
- Modify: `internal/store/etcd/etcd.go:202-207` (beside `Ping`), `internal/store/etcd/etcdtest/etcdtest.go:435` (beside `Stop`)
- Create: `internal/port49d/health.go`, `internal/port49d/health_test.go`
- Test: `internal/store/etcd/ping_test.go` (new)

**Interfaces:**
- Consumes: `metrics.Metrics` (Step 3 adds the two health series, which Task 6 also reads);
  `storeGone{why}`; `etcdtest.StartCluster`; `etcdstore.Open`.
- Produces:

```go
func (s *Store) PingToken(ctx context.Context) error // etcd
func (c *Cluster) Kill(i int)                        // etcdtest
func (c *Cluster) Leader(t testing.TB) int           // etcdtest
type health struct {
	every, timeout        time.Duration
	closeAfter, openAfter int
	check                 func(context.Context) error
	m                     *metrics.Metrics
	state                 *healthState // the process's: outlives this run
	out                   io.Writer
}
// healthState is the failed checks in a row, kept by the process across runs
// (as the alarm, the ledger and the marks are), so the gauge does not drop to 0
// in a run's new registry while the store is still away.
type healthState struct {
	mu      sync.Mutex
	failing int
	m       *metrics.Metrics // the current run's registry, set by bind
}
func (s *healthState) bind(m *metrics.Metrics) // a run's new registry reads the count at once
func (s *healthState) set(n int)               // count and gauge
func (s *healthState) atLeast(n int)           // raises, never lowers
func (s *healthState) count() int
func storeCheck(ctxPool interface{ Ping(context.Context) error }, tokPool interface{ PingToken(context.Context) error }) func(context.Context) error
func (h *health) watch(ctx context.Context, gone func(error))
func (h *health) passes(ctx context.Context) error
```

- [ ] **Step 1: The failing tests**

`internal/store/etcd/ping_test.go`:

```go
package etcd

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/etcd/etcdtest"
)

// PingToken reads on the token connection as Ping does on the context one
// (plan 7f, Ruling 1): each answers while etcd does, and each is
// store.ErrUnavailable while it hangs.
func TestPingTokenReadsOnTheTokenConnection(t *testing.T) {
	srv := etcdtest.Start(t, etcdtest.Options{})
	p := etcdtest.NewProxy(t, strings.TrimPrefix(srv.Endpoint, "http://"))
	s, err := Open(Config{Endpoints: []string{"http://" + p.Addr()}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.PingToken(ctx); err != nil {
		t.Fatal(err)
	}
	p.Hang(true)
	hctx, hcancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer hcancel()
	if err := s.PingToken(hctx); !errors.Is(err, store.ErrUnavailable) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("PingToken on a hung store: %v", err)
	}
}
```

`internal/port49d/health_test.go`:

```go
package port49d

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/daemon/metrics"
	etcdstore "github.com/blanketfish/port49/internal/store/etcd"
	"github.com/blanketfish/port49/internal/store/etcd/etcdtest"
)

// scripted is a check that answers from a script, one entry per call,
// the last entry repeated.
type scripted struct {
	mu    sync.Mutex
	steps []error
	calls int
}

func (s *scripted) check(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := min(s.calls, len(s.steps)-1)
	s.calls++
	return s.steps[i]
}

func testHealth(check func(context.Context) error) *health {
	h := &health{every: 5 * time.Millisecond, timeout: 50 * time.Millisecond, closeAfter: 3, openAfter: 2,
		check: check, m: metrics.New(prometheus.NewRegistry()), state: &healthState{}, out: io.Discard}
	h.state.bind(h.m)
	return h
}

var errCheck = errors.New("no answer")

// close_after failures in a row are a store gone, told once; a pass
// between them starts the count again (Ruling 1; Review Focus 2).
func TestWatchNeedsTheFailuresInARow(t *testing.T) {
	s := &scripted{steps: []error{errCheck, errCheck, nil, errCheck, errCheck, errCheck, nil}}
	h := testHealth(s.check)
	var told atomic.Int32
	var why error
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h.watch(ctx, func(e error) { told.Add(1); why = e })
	if told.Load() != 1 {
		t.Fatalf("told %d times", told.Load())
	}
	var g *storeGone
	if !errors.As(why, &g) || s.calls != 6 {
		t.Fatalf("gone %v after %d checks, want a storeGone after the sixth", why, s.calls)
	}
	if got := testutil.ToFloat64(h.m.StoreHealthChecks.WithLabelValues("fail")); got != 5 {
		t.Fatalf("failed checks counted %v, want 5", got)
	}
	// The close leaves the gauge at close_after, not 0: the process keeps it.
	if got := testutil.ToFloat64(h.m.StoreHealthFailures); got != 3 {
		t.Fatalf("port49_store_health_failures after the close = %v, want 3", got)
	}
}

// The failure count is the process's, not the run's: a run after a store gone
// builds a new registry, whose gauge reads what the last run left, and the
// passes hold it at close_after until the listeners open (plan 7f, I-1; the
// shape of TestARaisedAlarmIsGaugedWhileTheStoreIsAway). Without this the
// "above 0 for three intervals" alert resolves at the close, with the store
// still down.
func TestTheFailureCountSurvivesTheRunsRegistry(t *testing.T) {
	st := &healthState{}
	first := metrics.New(prometheus.NewRegistry())
	st.bind(first)
	st.set(3) // the watch's close_after-th failure
	next := metrics.New(prometheus.NewRegistry())
	st.bind(next)
	if got := testutil.ToFloat64(next.StoreHealthFailures); got != 3 {
		t.Fatalf("the next run's gauge reads %v, want 3 (the count the last run left)", got)
	}
	st.atLeast(2) // never lowers
	if st.count() != 3 {
		t.Fatalf("atLeast lowered the count to %d", st.count())
	}
	// passes: the gauge reads at least close_after through failures and a pass
	// between them, and 0 only once the listeners may open.
	s := &scripted{steps: []error{errCheck, nil, errCheck, nil, nil}}
	h := &health{every: 5 * time.Millisecond, timeout: 50 * time.Millisecond, closeAfter: 3, openAfter: 2,
		check: s.check, m: next, state: st, out: io.Discard}
	lowest := 1 << 30
	done := make(chan error, 1)
	go func() { done <- h.passes(context.Background()) }()
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			if lowest < 3 {
				t.Fatalf("the gauge read %d while the listeners were still closed, under close_after 3", lowest)
			}
			if got := testutil.ToFloat64(next.StoreHealthFailures); got != 0 {
				t.Fatalf("after open_after passes the gauge reads %v, want 0", got)
			}
			return
		default:
			lowest = min(lowest, int(testutil.ToFloat64(next.StoreHealthFailures)))
			time.Sleep(time.Millisecond)
		}
	}
}

// passes returns once open_after checks pass in a row; a failure starts
// the count again (Review Focus 2).
func TestPassesNeedsThePassesInARow(t *testing.T) {
	s := &scripted{steps: []error{nil, errCheck, nil, errCheck, nil, nil}}
	h := testHealth(s.check)
	if err := h.passes(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.calls != 6 {
		t.Fatalf("passes returned after %d checks, want 6", s.calls)
	}
}

// A check that never returns is a failure at the timeout, not a hang
// of the watch.
func TestAHungCheckFailsAtItsTimeout(t *testing.T) {
	h := testHealth(func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() })
	start := time.Now()
	gone := make(chan struct{})
	go h.watch(context.Background(), func(error) { close(gone) })
	select {
	case <-gone:
	case <-time.After(5 * time.Second):
		t.Fatal("a hung check never went dark")
	}
	if d := time.Since(start); d < 3*h.timeout {
		t.Fatalf("dark after %v, under three timeouts", d)
	}
}

// passes ends with ctx (Review Focus 5's unit).
func TestPassesEndsWithItsContext(t *testing.T) {
	h := testHealth(func(context.Context) error { return errCheck })
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	if err := h.passes(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
}

// Either connection failing fails the check (Review Focus 1).
func TestACheckFailsWhenEitherPoolFails(t *testing.T) {
	for _, c := range []struct {
		name     string
		ctx, tok error
	}{{"the context pool", errCheck, nil}, {"the token pool", nil, errCheck}} {
		check := storeCheck(pinger{c.ctx}, tokPinger{c.tok})
		if err := check(context.Background()); err == nil {
			t.Errorf("%s failing passed the check", c.name)
		}
	}
	if err := storeCheck(pinger{}, tokPinger{})(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// pinger and tokPinger are structs: Go allows no methods on a named
// interface type such as `type pinger error`.
type pinger struct{ err error }

func (p pinger) Ping(context.Context) error { return p.err }

type tokPinger struct{ err error }

func (p tokPinger) PingToken(context.Context) error { return p.err }

// A killed etcd leader does not fail close_after checks in a row at the
// default interval (Ruling 3, the default's tested reason): an election
// must not close the listeners. If this fails, the run it found goes to
// Ryan with OR-1; the default is not raised quietly.
func TestAKilledLeaderDoesNotFailFiveChecksInARow(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the default interval for 15s")
	}
	c := etcdtest.StartCluster(t)
	d, err := etcdstore.Open(etcdstore.Config{Endpoints: c.Endpoints})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	check := storeCheck(d, d)
	for i := 0; i < 3; i++ { // both connections up before the kill
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if err := check(ctx); err != nil {
			t.Fatalf("before the kill: %v", err)
		}
		cancel()
	}
	c.Kill(c.Leader(t))
	run, worst := 0, 0
	for end := time.Now().Add(15 * time.Second); time.Now().Before(end); time.Sleep(time.Second) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		err := check(ctx)
		cancel()
		if err != nil {
			run++
		} else {
			run = 0
		}
		worst = max(worst, run)
	}
	t.Logf("the longest run of failed checks after the leader was killed: %d", worst)
	if worst >= 5 {
		t.Fatalf("%d failed checks in a row after a leader was killed: the default close_after (5) would close the "+
			"listeners on an election; report to Ryan (OR-1), do not raise the default", worst)
	}
}

// A hung minority member, with quorum healthy, does not fail close_after
// checks in a row either (Ruling 3, the default's second tested reason; the
// commoner bad day than a crashed leader): one member wedged, defragmenting
// or partitioned with its TCP connection alive. clientv3 balances reads
// round-robin and each check reads on two clients, so many checks land a read
// on that member; every replica sees the same member, so a long run would take
// the whole fleet dark while etcd has quorum. A proxy in front of one
// member's client endpoint holds its bytes. The test measures: a run of 5 or
// more is the finding (report it to Ryan with OR-1, do not raise the default
// and do not rerun it into passing).
func TestAHungMinorityMemberDoesNotFailFiveChecksInARow(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the default interval for 20s")
	}
	c := etcdtest.StartCluster(t)
	p := etcdtest.NewProxy(t, strings.TrimPrefix(c.Endpoints[0], "http://"))
	d, err := etcdstore.Open(etcdstore.Config{Endpoints: []string{"http://" + p.Addr(), c.Endpoints[1], c.Endpoints[2]}})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	check := storeCheck(d, d)
	for i := 0; i < 3; i++ { // both connections up before the hang
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if err := check(ctx); err != nil {
			t.Fatalf("before the hang: %v", err)
		}
		cancel()
	}
	p.Hang(true)
	run, worst, failed, total := 0, 0, 0, 0
	for end := time.Now().Add(20 * time.Second); time.Now().Before(end); time.Sleep(time.Second) { // the default interval, and call_timeout
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		err := check(ctx)
		cancel()
		total++
		if err != nil {
			run++
			failed++
		} else {
			run = 0
		}
		worst = max(worst, run)
	}
	t.Logf("with one member hung: %d of %d checks failed, the longest run %d", failed, total, worst)
	if worst >= 5 {
		t.Fatalf("%d failed checks in a row with one member hung and quorum healthy: the default close_after (5) "+
			"would take every replica dark with etcd up; report to Ryan (OR-1), do not raise the default", worst)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/store/etcd/ -run TestPingToken -count=1 && go test ./internal/port49d/ -run 'TestWatch|TestPasses|TestTheFailureCount|TestAHungCheck|TestACheckFails|TestAKilledLeader|TestAHungMinority' -count=1`
Expected: FAIL, undefined `PingToken`, `health`, `healthState`, `storeCheck`, `Kill`, `Leader`.

- [ ] **Step 3: `PingToken`, `Kill`, `Leader`, the two series, `health.go`**

`internal/store/etcd/etcd.go`: both pings require a leader, so a member that has lost its
leader (isolated, or mid-election) answers `ErrGRPCNoLeader` at once instead of the read
blocking to the caller's deadline. In v3.6.15 the server's unary interceptor returns it
(`server/etcdserver/api/v3rpc/interceptor.go:67-70`), it is `codes.Unavailable`
(`api/v3rpc/rpctypes/error.go:77`), and clientv3 retries a Range on the next endpoint
(`client/v3/retry.go:54-74`): an isolated member costs a retry, not a failed check. Only the
watches set it today (`feed.go:90,226`, `meta.go:547`). Change `Ping`:

```go
// Ping is one linearizable read on the context pool: nil when etcd's
// quorum answers. It requires a leader (plan 7f, Ruling 3): a member that
// has none fails at once and the client retries another, so one isolated
// member does not cost a check its whole timeout.
func (s *Store) Ping(ctx context.Context) error {
	_, err := s.ctxKV.Get(clientv3.WithRequireLeader(ctx), s.k.meta("ping"))
	return unavailable(err)
}
```

and add, after it:

```go
// PingToken is Ping on the token pool's connection (plan 7f, Ruling 1):
// port49d's health check reads on both, so a store that answers one and
// not the other is not healthy. It requires a leader as Ping does. Its
// response does not raise Seen: no context is read on this connection.
func (s *Store) PingToken(ctx context.Context) error {
	_, err := s.tok.Get(clientv3.WithRequireLeader(ctx), s.k.meta("ping"))
	return unavailable(err)
}
```

`etcdtest.go`, after `Stop`:

```go
// Kill stops member i at once, as a crash does: Stop's Close hands the
// leadership to a peer first, which an election test must not have.
func (c *Cluster) Kill(i int) { c.once[i].Do(func() { halt(c.members[i]) }) }

// Leader is the index of the member that leads now.
func (c *Cluster) Leader(t testing.TB) int {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		for i, m := range c.members {
			if m.Server.Leader() == m.Server.MemberID() {
				return i
			}
		}
	}
	t.Fatal("no member leads")
	return -1
}
```

If `MemberID` is not the v3.6.15 method name, use the one `etcdserver.EtcdServer` has (`ID()` in
earlier releases).

`internal/daemon/metrics/metrics.go`:
- Two fields, beside `StoreFenceTimeouts`:

```go
	// StoreHealthChecks counts port49d's store health checks by outcome
	// (pass, fail; plan 7f), and StoreHealthFailures is the failed checks
	// in a row now: at store.etcd.health.close_after the listeners close.
	// The count is the process's (healthState): each run's registry is set
	// from it, and it reads at least close_after while the listeners are
	// closed after a store gone.
	StoreHealthChecks   *prometheus.CounterVec
	StoreHealthFailures prometheus.Gauge
```

- Their construction in `New`:

```go
		StoreHealthChecks: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_store_health_checks_total",
			Help: "port49d's store health checks, by outcome (pass, fail)."}, []string{"outcome"}),
		StoreHealthFailures: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_store_health_failures",
			Help: "port49d's failed store health checks in a row; at store.etcd.health.close_after every listener closes."}),
```

- Both added to the `MustRegister` list (line ~579).
- After construction, `m.StoreHealthChecks.WithLabelValues("pass")` and `("fail")`, so both
  series exist at 0 from the first scrape.

`internal/port49d/health.go`:

```go
package port49d

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/blanketfish/port49/internal/daemon/metrics"
)

// health is port49d's store health check on etcd (plan 7f; spec §13,
// decision 37), which replaced plan 7e's probe. It checks every `every`
// on its own clock, whether or not a device asks, so an idle port49d goes
// dark as fast as a loaded one: within closeAfter × every + timeout of
// the store stopping. Each check is bounded by timeout (call_timeout).
type health struct {
	every, timeout        time.Duration
	closeAfter, openAfter int
	check                 func(context.Context) error
	m                     *metrics.Metrics
	state                 *healthState
	out                   io.Writer
}

// healthState is the failed checks in a row, owned by `run` beside the alarm,
// the ledger and the marks, so it outlives a run (plan 7f, I-1). The
// registry is per run (main.go: metrics.New(reg)), and a gauge set only by
// the run that ended would read 0 in the next run's, resolving the alert
// "above 0 for three intervals" at the close, while the store is still down
// and port49d waits for it. The rule: while the listeners are closed the
// gauge never reads below close_after. A run binds its registry to it with
// bind, and `passes` holds it until the listeners may open.
type healthState struct {
	mu      sync.Mutex
	failing int
	m       *metrics.Metrics // the current run's registry
}

// bind points the state at a run's new registry and gauges the count in it
// at once, before the run first waits for the store.
func (s *healthState) bind(m *metrics.Metrics) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m = m
	m.StoreHealthFailures.Set(float64(s.failing))
}

// set records n failed checks in a row, and gauges it.
func (s *healthState) set(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failing = n
	if s.m != nil {
		s.m.StoreHealthFailures.Set(float64(n))
	}
}

// atLeast raises the count to n and never lowers it.
func (s *healthState) atLeast(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n > s.failing {
		s.failing = n
		if s.m != nil {
			s.m.StoreHealthFailures.Set(float64(n))
		}
	}
}

// count is the failed checks in a row now.
func (s *healthState) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failing
}

// storeCheck is one health check (Ruling 1): a linearizable read on each
// of the daemon's two etcd connections, made at once. ctxPool is the
// daemon's store fenced on its ledger, so a context feed that has stopped
// fails the check as a store does; tokPool reads on the token connection,
// so a store that answers one pool and not the other fails it. It runs
// under the guard: no slot, no circuit, nothing the guard refuses.
func storeCheck(ctxPool interface{ Ping(context.Context) error },
	tokPool interface{ PingToken(context.Context) error }) func(context.Context) error {
	return func(ctx context.Context) error {
		var wg sync.WaitGroup
		var ce, te error
		wg.Add(2)
		go func() { defer wg.Done(); ce = ctxPool.Ping(ctx) }()
		go func() { defer wg.Done(); te = tokPool.PingToken(ctx) }()
		wg.Wait()
		switch {
		case ce != nil:
			return fmt.Errorf("the context pool: %w", ce)
		case te != nil:
			return fmt.Errorf("the token pool: %w", te)
		}
		return nil
	}
}

// once is one check within h.timeout, counted.
func (h *health) once(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	err := h.check(cctx)
	outcome := "pass"
	if err != nil {
		outcome = "fail"
	}
	h.m.StoreHealthChecks.WithLabelValues(outcome).Inc()
	return err
}

// watch checks every h.every until ctx ends, and tells gone once, a
// storeGone, when closeAfter checks have failed in a row; a pass starts
// the count again. A check that ctx's end cut short is not a failure.
func (h *health) watch(ctx context.Context, gone func(error)) {
	t := time.NewTicker(h.every)
	defer t.Stop()
	fails, first := 0, time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		err := h.once(ctx)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			fails = 0
			h.state.set(0)
			continue
		}
		if fails == 0 {
			first = time.Now()
		}
		fails++
		h.state.set(fails) // at the close it stays: the next run's gauge reads it
		if fails >= h.closeAfter {
			gone(&storeGone{why: fmt.Sprintf("%d consecutive store health checks failed over %v (the last: %v)",
				fails, time.Since(first).Round(100*time.Millisecond), err)})
			return
		}
	}
}

// passes checks every h.every until openAfter checks have passed in a
// row, and returns nil then, or ctx's error. A failure starts the count
// again and is said once per run of failures. Throughout, the failure
// gauge reads at least closeAfter (the listeners are closed and the store
// is not yet trusted): failed checks count on from closeAfter, and it is
// set to 0 only on the way out, when the listeners are about to open.
func (h *health) passes(ctx context.Context) error {
	t := time.NewTicker(h.every)
	defer t.Stop()
	h.state.atLeast(h.closeAfter)
	ok, failing, fails := 0, false, 0
	for ok < h.openAfter {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
		err := h.once(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil {
			ok, failing, fails = ok+1, false, 0
			h.state.set(h.closeAfter)
			continue
		}
		ok = 0
		fails++
		h.state.set(h.closeAfter + fails)
		if !failing {
			fmt.Fprintf(h.out, "port49d: store: a health check failed while the listeners wait to open (%v); "+
				"counting %d passes again\n", err, h.openAfter)
			failing = true
		}
	}
	h.state.set(0)
	return nil
}
```

In `TestWatchNeedsTheFailuresInARow` the script's sixth call is the third failure in a row, so
`watch` returns after it. That pins `fails >= closeAfter` and the reset on a pass.

- [ ] **Step 4: Run them to verify they pass**

Run: `go test ./internal/store/etcd/ -run TestPingToken -count=1 -v && go test ./internal/port49d/ -run 'TestWatch|TestPasses|TestTheFailureCount|TestAHungCheck|TestACheckFails|TestAKilledLeader|TestAHungMinority' -count=1 -v`
Expected: PASS. Record both logged worst runs in the commit message. If
`TestAKilledLeaderDoesNotFailFiveChecksInARow` or
`TestAHungMinorityMemberDoesNotFailFiveChecksInARow` fails (a worst run of 5 or more), stop and
report to the controller with the run it found (OR-1), for Ryan. Do not change the default, and
do not rerun the test until it passes.

- [ ] **Step 5: Commit**

```bash
git add internal/store/etcd internal/port49d/health.go internal/port49d/health_test.go internal/daemon/metrics
git commit -m "feat(port49d): the store health check, N failures and M passes in a row

The longest run of failed checks at 1s: <n> after a killed leader
(TestAKilledLeaderDoesNotFailFiveChecksInARow), <n> with one member hung
(TestAHungMinorityMemberDoesNotFailFiveChecksInARow). Both pings require a leader.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 6: port49d goes dark on its health checks and listens again after its passes

**Files:**
- Modify:
  - `internal/port49d/store.go` (the `stores` struct's `probe` becomes `health`; `openDaemon`
    builds it and says the start line);
  - `internal/port49d/daemon.go` (`probe` removed);
  - `internal/port49d/main.go` (`runOnce`: the pass gate before `net.Listen("tcp", cfg.Listen)`,
    the watch after `rd.serving()`; the probe block removed).
  - `internal/port49d/main.go` also: `run` owns a `healthState` beside `alarm` and `authMarks`
    and passes it to `runOnce`, which binds it to each run's registry.
- Test:
  - `internal/port49d/daemon_test.go` (`TestAnIdleDaemonGoesDarkOnItsProbe` rewritten);
  - `internal/port49d/store_test.go` (the two places that use `sts.probe`: the split daemon's
    stores assertion near line 531, and the probe round in
    `TestOpenStoresFencesEachLayerUnderItsGuard`, near lines 690-708);
  - `internal/port49d/store_e2e_test.go` (a helper);
  - every test that hangs the store: `grep -n "Hang(true)" internal/port49d/*_test.go`.

**Interfaces:**
- Consumes: Task 5's `health`, `healthState`, `storeCheck`, `PingToken`; Task 4's
  `cfg.Store.Etcd.Health`; `crypt.Fenced(d, ledger)`; `cancelRun`, `again`, `rd`, `mln`,
  `stopSpool`, `spoolDone` in `runOnce`.
- Produces: `stores.health *health` (nil on memory); `run`'s `healthState`, passed to `runOnce`
  as a new last parameter `hs *healthState` and bound to each run's registry; the lines in "What
  the operator sees"; `addUnderEtcd(t, cfgPath, lines string)` for tests.

- [ ] **Step 1: The failing tests**

In `internal/port49d/store_e2e_test.go`, add:

```go
// addUnderEtcd inserts lines (each indented four spaces, newline-ended)
// under store.etcd in the config at cfgPath.
func addUnderEtcd(t *testing.T, cfgPath, lines string) {
	t.Helper()
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(string(raw), "  etcd:\n", "  etcd:\n"+lines, 1)
	if body == string(raw) {
		t.Fatalf("%s has no store.etcd block", cfgPath)
	}
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
```

In `internal/port49d/daemon_test.go`, replace `TestAnIdleDaemonGoesDarkOnItsProbe` with:

```go
// An idle port49d whose store hangs goes dark on its health checks alone:
// no device asks, and it closes its listeners within close_after × interval
// + call_timeout (plan 7f, Ruling 4: 7e's idle gap closed), not hold_ttl
// later. In the dark a held connection is reset (L28: the fast fall to
// local), TACACS+ takes none, and /readyz is 503. When the store returns
// it listens again only after open_after checks pass in a row.
func TestAnIdleDaemonGoesDarkOnItsHealthChecks(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	daemonCfg, proxy := etcdSplit(t)
	addUnderEtcd(t, daemonCfg, "    health: {interval: 200ms, close_after: 3, open_after: 2}\n")
	tacacs := startSplitDaemon(t, daemonCfg, &out, 1)
	waitFor(t, &out, "every listener closes after 3 consecutive failed checks and opens again after 2 passes")
	held, err := net.DialTimeout("tcp", tacacs, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	proxy.Hang(true)
	hungAt := time.Now()
	waitWithin(t, &out, "closing every listener so that devices use their local method", 10*time.Second)
	// 3 × 200ms + 200ms, with 2s for the process; hold_ttl is 10s here, so
	// a close this early is the checks', not the guard's.
	if d := time.Since(hungAt); d > 2800*time.Millisecond {
		t.Fatalf("dark %v after the hang, past close_after × interval + call_timeout + 2s", d)
	}
	if !strings.Contains(out.String(), "3 consecutive store health checks failed") {
		t.Fatalf("the close does not name the checks:\n%s", out.String())
	}
	held.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := held.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("a held connection on a store gone: %v, want a reset", err)
	}
	waitWithin(t, &out, "waiting for the store again, as at a start", 20*time.Second)
	if c, err := net.DialTimeout("tcp", tacacs, time.Second); err == nil {
		c.Close()
		t.Fatal("TACACS+ still listens with the store gone")
	}
	waitCountWithin(t, &out, "port49d: metrics on ", 2, 20*time.Second)
	ms := regexp.MustCompile(`port49d: metrics on (127\.0\.0\.1:\d+)`).FindAllStringSubmatch(out.String(), -1)
	resp, err := http.Get("http://" + ms[len(ms)-1][1] + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/readyz while waiting for the store: %d, want 503", resp.StatusCode)
	}
	// The alarm holds through the wait (plan 7f, I-1): the new run's registry
	// reads the count the last run left, at least close_after, before the
	// store returns, so "above 0 for three intervals" does not resolve at the
	// close with the store still down.
	if v := scrapeGauge(t, ms[len(ms)-1][1], "port49_store_health_failures"); v < 3 {
		t.Fatalf("port49_store_health_failures = %v while the store is away, want at least close_after (3)", v)
	}
	proxy.Hang(false)
	waitCountWithin(t, &out, "port49d: listening on ", 2, 60*time.Second)
	s := out.String()
	passed := strings.Index(s, "2 consecutive health checks passed")
	second := strings.LastIndex(s, "port49d: listening on ")
	if passed < 0 || passed > second {
		t.Fatalf("listening again before the passes were said:\n%s", s)
	}
	// And 0 once open_after passes have passed and the listeners are open.
	if v := scrapeGauge(t, ms[len(ms)-1][1], "port49_store_health_failures"); v != 0 {
		t.Fatalf("port49_store_health_failures = %v with the listeners open again, want 0", v)
	}
}

// scrapeGauge is the value of the unlabelled series name in the /metrics
// of the daemon at addr.
func scrapeGauge(t *testing.T, addr, name string) float64 {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + ` (\S+)$`).FindSubmatch(body)
	if m == nil {
		t.Fatalf("/metrics at %s has no %s", addr, name)
	}
	v, err := strconv.ParseFloat(string(m[1]), 64)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// A store that answers for one check in two never opens the listeners: a
// failure starts open_after's count again (Review Focus 2). Once it
// answers steadily, they open.
func TestAFlappingStoreDoesNotOpenTheListeners(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	daemonCfg, proxy := etcdSplit(t)
	addUnderEtcd(t, daemonCfg, "    health: {interval: 200ms, close_after: 3, open_after: 4}\n")
	startSplitDaemon(t, daemonCfg, &out, 1)
	proxy.Hang(true)
	waitWithin(t, &out, "waiting for the store again, as at a start", 15*time.Second)
	stop := make(chan struct{})
	flapped := make(chan struct{})
	go func() {
		defer close(flapped)
		// Asymmetric windows: hung 700ms, open 300ms. Proxy.Hang(false)
		// releases the bytes it held (etcdtest.go:481-486), so with equal
		// windows a check that started in the last 100ms of a hang could pass
		// on the release. With a 700ms hang a whole check pair is held, and
		// open_after (4) passes at 200ms intervals cannot fit in a 300ms window.
		for hung := true; ; hung = !hung {
			proxy.Hang(hung)
			d := 300 * time.Millisecond
			if hung {
				d = 700 * time.Millisecond
			}
			select {
			case <-stop:
				proxy.Hang(false)
				return
			case <-time.After(d):
			}
		}
	}()
	waitWithin(t, &out, "a health check failed while the listeners wait to open", 30*time.Second)
	time.Sleep(3 * time.Second)
	if strings.Count(out.String(), "port49d: listening on ") != 1 {
		t.Fatalf("the listeners opened on a flapping store:\n%s", out.String())
	}
	close(stop)
	<-flapped
	waitCountWithin(t, &out, "port49d: listening on ", 2, 60*time.Second)
}

// SIGTERM while port49d waits for its passes ends it at once (Review
// Focus 5).
func TestAStopWhileWaitingForPassesEndsTheRun(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	daemonCfg, proxy := etcdSplit(t)
	addUnderEtcd(t, daemonCfg, "    health: {interval: 200ms, close_after: 2, open_after: 60}\n")
	_, stop := runSplitDaemon(t, daemonCfg, &out, 1)
	proxy.Hang(true)
	waitWithin(t, &out, "waiting for the store again, as at a start", 15*time.Second)
	proxy.Hang(false)
	waitWithin(t, &out, "the listeners open again after 60 consecutive health checks pass", 30*time.Second)
	start := time.Now()
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("a stop while waiting for passes took %v", d)
	}
}
```

`daemon_test.go` needs `io` and `strconv` for `scrapeGauge`; add them to its imports if absent.

In `internal/port49d/store_test.go`, which still uses `sts.probe` and would stop the package
compiling once Step 3 deletes it:

- The split daemon's stores assertion (near line 531). Replace

```go
	if sts.broker != nil || sts.probe == nil {
		t.Fatalf("the split daemon's stores: broker %v, probe %v", sts.broker != nil, sts.probe != nil)
	}
```

  with

```go
	if sts.broker != nil || sts.health == nil {
		t.Fatalf("the split daemon's stores: broker %v, health %v", sts.broker != nil, sts.health != nil)
	}
```

- `TestOpenStoresFencesEachLayerUnderItsGuard` (near lines 690-708), the only test that pins
  "the check is fenced". In its doc comment replace "The probe pings through the same guard and
  fence, so with the feed stopped its pings time out too (plan 7e, Ruling 11)." with "The health
  check waits on the same fence, below the guard (plan 7f, Ruling 1), so with the feed stopped it
  fails too, and the guard does not count it." Then replace everything from the `// One probe
  round` comment through the end of the test with:

```go
	// The health check (plan 7f, Ruling 1) waits for the feed too, below the
	// guard: with the feed not running and another ledger's write past the
	// base, it fails at its call_timeout deadline, wrapping ErrFeedBehind, and
	// counts a fence timeout; the guard's context counter does not move,
	// because the check takes no slot and trips no circuit.
	guarded := testutil.ToFloat64(m.StoreCalls.WithLabelValues("daemon", "context", "timeout"))
	cctx, stopCheck := context.WithTimeout(ctx, cfg.Store.Etcd.CallTimeout)
	defer stopCheck()
	if err := sts.health.check(cctx); !errors.Is(err, crypt.ErrFeedBehind) {
		t.Fatalf("the health check with the feed stopped: %v, want an error wrapping crypt.ErrFeedBehind", err)
	}
	if n := testutil.ToFloat64(m.StoreFenceTimeouts); n != 2 {
		t.Fatalf("port49_store_fence_timeouts_total = %v after the check, want 2", n)
	}
	if n := testutil.ToFloat64(m.StoreCalls.WithLabelValues("daemon", "context", "timeout")); n != guarded {
		t.Fatalf("the guard counted the health check: context timeouts %v, were %v", n, guarded)
	}
}
```

  (Check the field the call timeout is read from against Task 4's resolved `EtcdConfig`.)

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/port49d/ -run 'TestAnIdleDaemonGoesDarkOnItsHealthChecks|TestAFlappingStoreDoesNotOpenTheListeners|TestAStopWhileWaitingForPassesEndsTheRun|TestOpenStoresFencesEachLayerUnderItsGuard' -count=1`
Expected: FAIL. No start line names the checks, dark comes at `hold_ttl`, not within 2.8s, and
`store_test.go` does not compile against `sts.health`.

- [ ] **Step 3: Wire it**

`internal/port49d/store.go`, in `stores`, replace the `probe` field and its comment with:

```go
	// health is the store health check (plan 7f; decision 37): runOnce
	// waits on its passes before binding TACACS+ in a run after a store
	// gone, and runs its watch from the bind, which ends the run on
	// close_after failures in a row. Nil on memory.
	health *health
```

In `openDaemon`:
- Replace `gd := guard.WrapRev(crypt.Fenced(d, ledger), guardConfig(procOf(cfg), "daemon", e, m,
  out, gone))` with:

```go
	fd := crypt.Fenced(d, ledger)
	gd := guard.WrapRev(fd, guardConfig(procOf(cfg), "daemon", e, m, out, gone))
	h := e.Health
	fmt.Fprintf(out, "port49d: store: health checked every %v; every listener closes after %d consecutive failed "+
		"checks and opens again after %d passes (store.etcd.health)\n", h.Interval, h.CloseAfter, h.OpenAfter)
```

- Update the comment above it: the probe's sentence becomes "the health check reads the fenced
  store under the guard (storeCheck)".
- In the returned `stores`, replace `probe: …` with:

```go
		health: &health{every: h.Interval, timeout: e.CallTimeout, closeAfter: h.CloseAfter, openAfter: h.OpenAfter,
			check: storeCheck(fd, d), m: m, state: &healthState{}, out: out},
```

The `state` here is a private one, so a test that calls `openStores` directly has one. `runOnce`
replaces it with the process's (below), before `passes` or `watch` run.

`internal/port49d/daemon.go`: delete `probe` and its comment.

`internal/port49d/main.go`:
- In `run`, beside `ledger, alarm := …` and `authMarks`:

```go
	// The failed-check count is the process's too: the registry is per run, so
	// a gauge set only by the run that ended reads 0 in the next one's, and the
	// alert "above 0 for three intervals" would resolve at the close while the
	// store is still down (plan 7f, I-1; the shape of the key alarm's gauge).
	hs := &healthState{}
```

  and pass it: `runOnce(parent, cfgPath, hup, again, ledger, alarm, authMarks, restored, hs)`.
- In `runOnce`'s signature, add a last parameter `hs *healthState`. Immediately after `m :=
  metrics.New(reg)` (line ~652), add:

```go
	// This run's new registry reads the count the last run left, and a run
	// after a store gone holds it at close_after for as long as it waits for
	// the store (openStores' retry), so the alert holds through the whole
	// outage and resolves only when the listeners open again (passes sets 0).
	hs.bind(m)
	if again && cfg.Store.Backend == "etcd" {
		hs.atLeast(cfg.Store.Etcd.Health.CloseAfter)
	}
```

  (Check how `cfg.Store`'s backend and `Etcd` field are spelled, and guard as the neighbouring
  code does for the memory backend.)
- Immediately after `sts, err := openStores(…)` returns without error, add `if sts.health != nil
  { sts.health.state = hs }`, before any use of `sts.health`.

`internal/port49d/main.go`, in `runOnce`:
- Delete the `if sts.probe != nil { … }` block.
- Immediately before `ln, err := net.Listen("tcp", cfg.Listen)`, add:

```go
	// After a store gone, TACACS+ binds only once open_after health checks
	// pass in a row (plan 7f; decision 37): the start's own reads are not
	// enough to say a store that just returned will stay. A cold start is
	// not gated. A stop meanwhile ends the run at once.
	if sts.health != nil && again {
		fmt.Fprintf(stderr, "port49d: store: the store answers; the listeners open again after %d consecutive "+
			"health checks pass (store.etcd.health.open_after)\n", sts.health.openAfter)
		if err := sts.health.passes(ctx); err != nil {
			mln.Close()
			stopSpool()
			<-spoolDone
			return nil
		}
		fmt.Fprintf(stderr, "port49d: store: %d consecutive health checks passed\n", sts.health.openAfter)
	}
```

- Immediately after `rd.serving()`, add:

```go
	if sts.health != nil {
		// From the bind on, close_after failures in a row end the run as a
		// store gone, idle or not (plan 7f, Ruling 4); joined before
		// sts.close, as the feeds are.
		hctx, stopHealth := context.WithCancel(ctx)
		healthDone := make(chan struct{})
		go func() { defer close(healthDone); sts.health.watch(hctx, func(e error) { cancelRun(e) }) }()
		defer func() { stopHealth(); <-healthDone }()
	}
```

Check `runOnce`'s other early returns before the bind (broker listener, admin socket) for the
same `mln`, `stopSpool` and `<-spoolDone` unwind, and mirror the one at `net.Listen`'s error
exactly.

- [ ] **Step 4: Run the three tests to verify they pass**

Run: `go test ./internal/port49d/ -run 'TestAnIdleDaemonGoesDarkOnItsHealthChecks|TestAFlappingStoreDoesNotOpenTheListeners|TestAStopWhileWaitingForPassesEndsTheRun|TestOpenStoresFencesEachLayerUnderItsGuard' -count=1 -v`
Expected: PASS.

- [ ] **Step 5: Every test that hangs the store**

Run: `grep -n "Hang(true)" internal/port49d/*_test.go` and `grep -n "\.probe\|probe(" internal/port49d/*_test.go`
(the second must find nothing but comments by now: `store_test.go`'s two uses were rewritten in
Step 1).

For each one, read what it expects between the hang and its first assertion:
- **One that asserts a reply on a hung store before the close** (an `ERROR` login, a `FAIL`
  command, within `packet_deadline`) now has the health checks closing at 5.5s. If its
  assertion lands later than that, add `addUnderEtcd(t, cfg, "    health: {close_after:
  60}\n")` to that test alone, with a comment: "the checks would close the listeners first; this
  test measures the guard's reply".
- **One that expects the close at `hold_ttl`** (`TestAHungStoreGoesDarkAndServesAgainWhenItReturns`,
  brokerd_test.go:900) still passes with an earlier close. Keep it, and update its comment to say
  the checks close first.
- **One that expects `listening on` again soon after unhang** now also waits for 3 passes at 1s.
  Raise its wait if it is under 10s.

Name each test changed in the commit message.

- [ ] **Step 6: The package, race, vet**

Run: `go test ./internal/port49d/ -count=1 && go test -race ./internal/port49d/ -count=1 && make vet`
Expected: PASS, and `make vet` silent.

- [ ] **Step 7: Commit**

```bash
git add internal/port49d
git commit -m "feat(port49d): go dark on close_after failed health checks and listen again after open_after passes

The probe is gone: an idle port49d goes dark within close_after × interval + call_timeout.
Tests adjusted for the earlier close: <names>.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 7: The context cache, evicted by the ledger's feed

**Files:**
- Create: `internal/store/crypt/cache.go`, `internal/store/crypt/cache_test.go`
- Modify:
  - `internal/store/crypt/ledger.go` (the `Ledger` struct, `attach`, `changed`, `rescanned`);
  - `internal/store/crypt/follow.go` (`FollowContexts` tells the ledger each change and each
    rescan);
  - `internal/store/guard/guard.go:323-325` (a guarded timeout keeps the inner error, so the
    cache can tell a fence timeout from an outage).
- Test: `internal/store/crypt/follow_test.go` (one test), `internal/store/guard/guard_test.go`
  (one test)

**Interfaces:**
- Consumes:
  - `Ledger.knownAt(k, rev) bool` (ledger.go:123), `Ledger.Fence().Up()`,
    `Ledger.Observe(k, seq, rev, revokedAt, ceiling)`;
  - `FollowContexts`'s watch callback (follow.go: `func(c store.ContextChange)`) and its rescan
    branch;
  - the test fixtures `ka`, `keys()`, `feedOf`, `eventually`, `sealedAt`.
- Produces:

```go
type CacheConfig struct {
	TTL     time.Duration
	Max     int
	IdleTTL time.Duration
	Now     func() time.Time
	Lookups *prometheus.CounterVec // outcome: hit, miss, stale; nil counts nothing
	Entries prometheus.Gauge       // nil gauges nothing
	Stale   func(err error)        // told at each stale serve; nil tells no one
	Fresh   func()                 // told at each read the store answered; nil tells no one
}
func Cached(inner store.Store, l *Ledger, cfg CacheConfig) store.Store
func (l *Ledger) changed(k store.ContextKey)
func (l *Ledger) rescanned()
```

- [ ] **Step 1: The failing tests**

`internal/store/crypt/cache_test.go`:

```go
package crypt

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/memory"
)

// backing is the store under a cache in these tests: a memory store
// whose GetContext answers what the test says, counting reads.
type backing struct {
	store.Store
	mu    sync.Mutex
	c     store.Context
	err   error
	reads int
	hook  func() // run inside each read, before it answers
}

func (b *backing) GetContext(_ context.Context, _ store.ContextKey) (store.Context, error) {
	b.mu.Lock()
	b.reads++
	c, err, hook := b.c, b.err, b.hook
	b.mu.Unlock()
	if hook != nil {
		hook()
	}
	return c, err
}

func (b *backing) set(c store.Context, err error) { b.mu.Lock(); b.c, b.err = c, err; b.mu.Unlock() }
func (b *backing) count() int                      { b.mu.Lock(); defer b.mu.Unlock(); return b.reads }

// cacheRig is a cache over a backing whose context at ka the ledger knows
// at revision 7, with the feed up and a clock the test moves.
func cacheRig(t *testing.T) (*backing, store.Store, *Ledger, *time.Time, *prometheus.CounterVec) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	b := &backing{Store: memory.New(time.Now), c: store.Context{CtxID: "c1", Username: "alice", Rev: 7, LastTouchedAt: now}}
	l := NewLedger()
	l.Observe(ka, 7, 7, time.Time{}, time.Time{})
	l.Fence().SetUp(true)
	lookups := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "t"}, []string{"outcome"})
	c := Cached(b, l, CacheConfig{TTL: 2 * time.Second, Max: 4, IdleTTL: time.Hour,
		Now: func() time.Time { return now }, Lookups: lookups})
	return b, c, l, &now, lookups
}

func get(t *testing.T, c store.Store) (store.Context, error) {
	t.Helper()
	return c.GetContext(context.Background(), ka)
}

func TestACachedContextIsServedWithoutAStoreRead(t *testing.T) {
	b, c, _, _, lookups := cacheRig(t)
	for i := 0; i < 3; i++ {
		if got, err := get(t, c); err != nil || got.CtxID != "c1" {
			t.Fatalf("%v %v", got, err)
		}
	}
	if b.count() != 1 || testutil.ToFloat64(lookups.WithLabelValues("hit")) != 2 {
		t.Fatalf("reads %d, hits %v", b.count(), testutil.ToFloat64(lookups.WithLabelValues("hit")))
	}
}

func TestAnEntryPastItsTTLIsReadAgain(t *testing.T) {
	b, c, _, now, _ := cacheRig(t)
	get(t, c)
	*now = now.Add(2 * time.Second)
	get(t, c)
	if b.count() != 2 {
		t.Fatalf("reads %d, want 2", b.count())
	}
}

func TestAWriteAtTheKeyEvictsIt(t *testing.T) {
	b, c, _, _, _ := cacheRig(t)
	get(t, c)
	if err := c.TouchContext(context.Background(), ka, time.Hour); err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	get(t, c)
	if b.count() != 2 {
		t.Fatalf("reads %d: a write did not evict", b.count())
	}
}

// Review Focus 3: every change the feed brings evicts, a delete included.
func TestAFeedChangeEvictsTheKey(t *testing.T) {
	b, c, l, _, _ := cacheRig(t)
	get(t, c)
	l.changed(ka)
	get(t, c)
	if b.count() != 2 {
		t.Fatalf("reads %d: a feed change did not evict", b.count())
	}
}

func TestARescanClearsTheCache(t *testing.T) {
	b, c, l, _, _ := cacheRig(t)
	get(t, c)
	l.rescanned()
	get(t, c)
	if b.count() != 2 {
		t.Fatalf("reads %d: a rescan did not clear", b.count())
	}
}

// A later record the ledger knows (this process's own write, or one the
// feed raised) makes the entry no hit, before any eviction lands.
func TestALaterRecordTheLedgerKnowsIsReadNotServed(t *testing.T) {
	b, c, l, _, _ := cacheRig(t)
	get(t, c)
	l.Observe(ka, 9, 9, time.Time{}, time.Time{})
	get(t, c)
	if b.count() != 2 {
		t.Fatalf("reads %d: a superseded entry was a hit", b.count())
	}
}

func TestNoHitWhileTheFeedIsDown(t *testing.T) {
	b, c, l, _, _ := cacheRig(t)
	get(t, c)
	l.Fence().SetUp(false)
	get(t, c)
	if b.count() != 2 {
		t.Fatalf("reads %d: a hit with the feed down", b.count())
	}
}

// Review Focus 3: a read that raced an eviction is not cached, so the
// change it raced is not hidden behind it.
func TestAReadThatRacedAnEvictionIsNotCached(t *testing.T) {
	b, c, l, _, _ := cacheRig(t)
	b.hook = func() { l.changed(ka) } // the change lands while the read is in flight
	get(t, c)
	b.hook = nil
	get(t, c)
	if b.count() != 2 {
		t.Fatalf("reads %d: a read that raced an eviction was cached", b.count())
	}
}

// Through an outage an entry past its TTL is served, counted and told
// (design §12).
func TestAnOutageServesTheEntryPastItsTTL(t *testing.T) {
	b, c, _, now, lookups := cacheRig(t)
	get(t, c)
	*now = now.Add(5 * time.Second)
	b.set(store.Context{}, store.ErrUnavailable)
	got, err := get(t, c)
	if err != nil || got.CtxID != "c1" || testutil.ToFloat64(lookups.WithLabelValues("stale")) != 1 {
		t.Fatalf("%v %v stale %v", got, err, testutil.ToFloat64(lookups.WithLabelValues("stale")))
	}
}

// Review Focus 3: never stale once a later record is known, nor past the
// context's own idle TTL, nor on not found.
func TestASupersededEntryIsNeverServedStale(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(b *backing, l *Ledger, now *time.Time)
		want error
	}{
		{"a later record known", func(b *backing, l *Ledger, _ *time.Time) {
			l.Observe(ka, 9, 9, time.Time{}, time.Time{})
			b.set(store.Context{}, store.ErrUnavailable)
		}, store.ErrUnavailable},
		{"past its idle TTL", func(b *backing, _ *Ledger, now *time.Time) {
			*now = now.Add(2 * time.Hour)
			b.set(store.Context{}, store.ErrUnavailable)
		}, store.ErrUnavailable},
		{"not found", func(b *backing, _ *Ledger, now *time.Time) {
			*now = now.Add(5 * time.Second)
			b.set(store.Context{}, store.ErrNotFound)
		}, store.ErrNotFound},
	} {
		b, cc, l, now, _ := cacheRig(t)
		get(t, cc)
		c.edit(b, l, now)
		if _, err := get(t, cc); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}

// A fence timeout is never served stale (plan 7f, I-2). crypt.Fenced waits
// only when the store's record carries a different revision than the
// ledger's, so a read that failed in the fence wait means etcd answered with
// a later record than the cached one, possibly a revocation (SetRevokedAt):
// that is not an outage. The guard keeps the fence's error inside its own
// ErrUnavailable, and the cache refuses to serve on it, and evicts the entry.
func TestAFenceTimeoutIsNeverServedStale(t *testing.T) {
	b, c, _, now, lookups := cacheRig(t)
	get(t, c)
	*now = now.Add(5 * time.Second) // past the TTL, within the idle TTL
	b.set(store.Context{}, fmt.Errorf("%w: no answer (%w)", store.ErrUnavailable, ErrFeedBehind))
	got, err := get(t, c)
	if err == nil || got.CtxID != "" {
		t.Fatalf("a fence timeout served %q, %v", got.CtxID, err)
	}
	if !errors.Is(err, store.ErrUnavailable) || !errors.Is(err, ErrFeedBehind) {
		t.Fatalf("the error lost its meaning: %v", err)
	}
	if n := testutil.ToFloat64(lookups.WithLabelValues("stale")); n != 0 {
		t.Fatalf("stale serves counted: %v", n)
	}
	if n := len(c.(*cache).m); n != 0 {
		t.Fatalf("%d entries: the superseded one was kept", n)
	}
}

// A hit hands out a copy: the entry's SessionDiscriminators slice is shared
// with no caller (store.Context is returned by value, its slice is not).
func TestAHitIsACopy(t *testing.T) {
	b, c, _, _, _ := cacheRig(t)
	b.c.SessionDiscriminators = []string{"d1", "d2"}
	first, _ := get(t, c)
	first.SessionDiscriminators[0] = "edited"
	second, _ := get(t, c) // a hit
	if second.SessionDiscriminators[0] != "d1" {
		t.Fatalf("a caller's edit reached the cached entry: %v", second.SessionDiscriminators)
	}
}

func TestTheCacheIsBounded(t *testing.T) {
	b, c, l, _, _ := cacheRig(t)
	for i := 0; i < 6; i++ {
		k := store.ContextKey{NAS: "leaf", Username: string(rune('a' + i))}
		l.Observe(k, 7, 7, time.Time{}, time.Time{})
		c.GetContext(context.Background(), k)
	}
	if n := len(c.(*cache).m); n > 4 {
		t.Fatalf("%d entries, Max 4", n)
	}
	_ = b
}
```

In `follow_test.go`, add:

```go
// FollowContexts tells the ledger each change, a delete and a record that
// does not open included, so a cache evicts them (plan 7f, Ruling 5).
func TestTheFeedTellsTheLedgerEveryChange(t *testing.T) {
	l := NewLedger()
	var mu sync.Mutex
	var told []store.ContextKey
	l.attach(evicterFunc{evict: func(k store.ContextKey) { mu.Lock(); told = append(told, k); mu.Unlock() }})
	feed := &feedOf{changes: make(chan store.ContextChange, 3), compact: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go FollowContexts(ctx, feed, nil, keys(), l, 0, func(bool) {}, func() {}, t.Logf)
	kb := store.ContextKey{NAS: "leaf-02", Username: "bob"}
	feed.changes <- store.ContextChange{Key: ka, Context: sealedAt(t, ka, 10), Rev: 10}
	feed.changes <- store.ContextChange{Key: kb, Deleted: true, Rev: 11}
	feed.changes <- store.ContextChange{Key: ka, Context: store.Context{CtxID: "garbage"}, Rev: 12}
	eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(told) == 3 })
}

// evicterFunc is an evicter from funcs, for tests.
type evicterFunc struct {
	evict func(store.ContextKey)
	clear func()
}

func (e evicterFunc) evictKey(k store.ContextKey) {
	if e.evict != nil {
		e.evict(k)
	}
}
func (e evicterFunc) clearAll() {
	if e.clear != nil {
		e.clear()
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/store/crypt/ -run 'Cache|Cached|TestAWriteAtTheKey|TestAFeedChange|TestARescan|TestALaterRecord|TestNoHit|TestARead|TestAnOutage|TestASuperseded|TestAFenceTimeout|TestAHitIsACopy|TestTheFeedTellsTheLedger' -count=1 && go test ./internal/store/guard/ -run TestAGuardedTimeoutKeepsTheInnerError -count=1`
Expected: FAIL, undefined `Cached`, `CacheConfig`, `l.changed`, `l.attach`, and the guard's
timeout error not wrapping the inner one.

The guard's test, in `internal/store/guard/guard_test.go` beside
`TestACallPastItsTimeoutIsUnavailable` (add `fmt` to its imports):

```go
// feedBehind is a store whose GetContext waits for its context to end and
// then says why, as crypt.Fenced does when its feed has not arrived.
type feedBehind struct {
	store.Store
	why error
}

func (f feedBehind) GetContext(ctx context.Context, _ store.ContextKey) (store.Context, error) {
	<-ctx.Done()
	return store.Context{}, fmt.Errorf("%w: the feed is behind", f.why)
}

// A guarded timeout is store.ErrUnavailable and still wraps what the inner call
// said (plan 7f, I-2): the context cache reads crypt.ErrFeedBehind through it
// to tell a fence timeout, where etcd answered, from an outage. It is still
// counted a timeout.
func TestAGuardedTimeoutKeepsTheInnerError(t *testing.T) {
	var said, gone told
	errInner := errors.New("inner")
	c := config(&said, &gone)
	g := Wrap(feedBehind{why: errInner}, c)
	_, err := g.GetContext(context.Background(), k)
	if !errors.Is(err, store.ErrUnavailable) || !errors.Is(err, errInner) {
		t.Fatalf("a guarded timeout: %v, want ErrUnavailable wrapping the inner error", err)
	}
	if n := testutil.ToFloat64(c.Metrics.Calls.WithLabelValues("daemon", "context", "timeout")); n != 1 {
		t.Fatalf("timeout outcomes: %v, want 1", n)
	}
}
```

Before changing the guard, `grep -rn "no answer in" internal/store/guard/*_test.go internal/port49d/*_test.go`:
any test that matches the full message text keeps matching (the new text only appends
` (…)`), and one that compares the error with `==` or its exact string needs the suffix.

- [ ] **Step 3: The ledger's hooks and the feed's calls**

`internal/store/crypt/ledger.go`:
- In `Ledger`, add:

```go
	// ev is what each change the context feed brings is told, a context
	// cache (Cached; plan 7f), or nil. Its own lock. Lock order: the cache
	// takes l.mu (knownAt) under its own lock, so the ledger never calls
	// the cache (changed, rescanned) with l.mu held; FollowContexts calls
	// them outside it.
	evMu sync.Mutex
	ev   evicter
```

- Then:

```go
// evicter is a context cache, told by the ledger of every key the feed
// changes and of every rescan (plan 7f, Ruling 5).
type evicter interface {
	evictKey(k store.ContextKey)
	clearAll()
}

// attach makes e the cache this ledger tells; a later attach replaces it
// (a run after a store gone builds a new cache on the process's ledger).
func (l *Ledger) attach(e evicter) { l.evMu.Lock(); l.ev = e; l.evMu.Unlock() }

// changed tells the cache k changed in the store: a write, a delete, or a
// record this process cannot open, whatever it raised here.
func (l *Ledger) changed(k store.ContextKey) {
	l.evMu.Lock()
	e := l.ev
	l.evMu.Unlock()
	if e != nil {
		e.evictKey(k)
	}
}

// rescanned tells the cache a compacted watch scanned the store again:
// changes between are not delivered one by one, so every entry goes.
func (l *Ledger) rescanned() {
	l.evMu.Lock()
	e := l.ev
	l.evMu.Unlock()
	if e != nil {
		e.clearAll()
	}
}
```

`internal/store/crypt/follow.go`, in `FollowContexts`:
- In the watch callback, make `l.changed(c.Key)` its first statement, before `again()`:

```go
		err := feed.WatchContexts(ctx, from, func(c store.ContextChange) {
			// Every change, a delete and one that will not open included,
			// evicts its key from a context cache before anything else
			// (plan 7f, Ruling 5).
			l.changed(c.Key)
			again()
```

- In the rescan branch, call `l.rescanned()` right after `rescanned()`, before the scan:

```go
			rescanned()
			l.rescanned()
```

Clearing before the scan is safe: the cache's generation moves, so a read in flight during the
scan is not cached either.

`internal/store/guard/guard.go:323-325`, in `call`. The guard replaces a timed-out call's error
with its own, which drops `crypt.ErrFeedBehind` (`fence.go:134`), the one error that says etcd
answered with a record the ledger has not caught up to. Keep the inner error inside it:

```go
	if outcome == "timeout" {
		// The inner error stays wrapped: the context cache tells a fence
		// timeout (crypt.ErrFeedBehind: the store answered with a later
		// record) from an outage by it (plan 7f, I-2). classify has already
		// run, so what is counted is unchanged.
		err = fmt.Errorf("%w: no answer in %v (%w)", store.ErrUnavailable, pl.timeout, err)
	}
```

- [ ] **Step 4: `cache.go`**

```go
package crypt

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/store"
)

// CacheConfig is a context cache's bounds and its witnesses (plan 7f;
// design §12; spec §13, decision 37).
type CacheConfig struct {
	TTL     time.Duration          // a hit is an entry younger than this
	Max     int                    // past it the cache is cleared
	IdleTTL time.Duration          // the context's own idle TTL: no stale serve past LastTouchedAt + it
	Now     func() time.Time       // time.Now when nil
	Lookups *prometheus.CounterVec // outcome: hit, miss, stale; nil counts nothing
	Entries prometheus.Gauge       // nil gauges nothing
	Stale   func(err error)        // told at each stale serve, with the store's error; nil tells no one
	Fresh   func()                 // told at each read the store answered; nil tells no one
}

// Cached is inner, port49d's sealed daemon store, with GetContext answered
// from a per-replica read-through cache (design §12), for command and
// session authorization alone: a login, an enable, accounting and a token
// redemption never read through it.
//
// A hit is an entry younger than TTL, read while the context feed is up,
// whose revision the ledger still knows as the latest at its key. An
// entry is evicted by a write through this cache, by every change the
// feed brings (Ledger.changed), by a rescan (Ledger.rescanned) and by not
// found; a read that raced any eviction is not cached (gen).
//
// A read that fails store.ErrUnavailable is answered from an entry the
// ledger still knows, within the context's idle TTL: counted stale and
// told. Revocation does not reach it then (design §12: documented, not
// discovered), until a read lands or port49d's listeners close. Never when
// the failure is ErrFeedBehind: Fenced waits only for a record whose
// revision differs from the ledger's, so a fence timeout means etcd
// answered with a later record than the entry, perhaps a revocation. That
// is not an outage: the entry is evicted and the read denied.
//
// A hit hands out a copy, so a caller that edits the SessionDiscriminators
// slice cannot corrupt the entry.
func Cached(inner store.Store, l *Ledger, cfg CacheConfig) store.Store {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	c := &cache{Store: inner, l: l, cfg: cfg, m: map[store.ContextKey]cacheEntry{}}
	l.attach(c)
	return c
}

type cacheEntry struct {
	c  store.Context
	at time.Time
}

type cache struct {
	store.Store
	l   *Ledger
	cfg CacheConfig
	mu  sync.Mutex
	m   map[store.ContextKey]cacheEntry
	gen uint64 // moved by every eviction; a read is cached only if it did not move meanwhile
}

func (c *cache) count(outcome string) {
	if c.cfg.Lookups != nil {
		c.cfg.Lookups.WithLabelValues(outcome).Inc()
	}
}

func (c *cache) gauge() { // under c.mu
	if c.cfg.Entries != nil {
		c.cfg.Entries.Set(float64(len(c.m)))
	}
}

func (c *cache) evictKey(k store.ContextKey) {
	c.mu.Lock()
	delete(c.m, k)
	c.gen++
	c.gauge()
	c.mu.Unlock()
}

func (c *cache) clearAll() {
	c.mu.Lock()
	clear(c.m)
	c.gen++
	c.gauge()
	c.mu.Unlock()
}

func (c *cache) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	now := c.cfg.Now()
	c.mu.Lock()
	e, ok := c.m[k]
	gen := c.gen
	c.mu.Unlock()
	if ok && now.Sub(e.at) < c.cfg.TTL && c.l.Fence().Up() && c.l.knownAt(k, e.c.Rev) {
		c.count("hit")
		return cloned(e.c), nil
	}
	got, err := c.Store.GetContext(ctx, k)
	if err == nil {
		c.count("miss")
		c.mu.Lock()
		if c.gen == gen && c.l.knownAt(k, got.Rev) {
			if len(c.m) >= c.cfg.Max {
				clear(c.m)
			}
			c.m[k] = cacheEntry{c: cloned(got), at: now}
			c.gauge()
		}
		c.mu.Unlock()
		if c.cfg.Fresh != nil {
			c.cfg.Fresh()
		}
		return got, nil
	}
	// A fence timeout is the store answering with a later record than the
	// entry (plan 7f, I-2): not an outage, so never stale, and the entry is
	// superseded.
	behind := errors.Is(err, ErrFeedBehind)
	if ok && errors.Is(err, store.ErrUnavailable) && !behind && c.l.knownAt(k, e.c.Rev) && c.withinIdle(e.c, now) {
		c.count("stale")
		if c.cfg.Stale != nil {
			c.cfg.Stale(err)
		}
		return cloned(e.c), nil
	}
	c.count("miss")
	if !errors.Is(err, store.ErrUnavailable) || behind {
		c.evictKey(k) // not found, a record that will not open, or one the feed is behind: never served again
	}
	return got, err
}

// cloned is ct with its SessionDiscriminators slice copied: store.Context is
// handed out by value, but that slice is shared with whoever holds the other
// copy.
func cloned(ct store.Context) store.Context {
	ct.SessionDiscriminators = slices.Clone(ct.SessionDiscriminators)
	return ct
}

// withinIdle reports whether the context's own idle TTL, from its last
// touch, has not passed: the store would have reclaimed it then.
func (c *cache) withinIdle(ct store.Context, now time.Time) bool {
	from := ct.LastTouchedAt
	if from.IsZero() {
		from = ct.CreatedAt
	}
	return now.Before(from.Add(c.cfg.IdleTTL))
}

// Every write at a key evicts it once the write returns, whatever it
// returned: the next read is the store's.

func (c *cache) PutContext(ctx context.Context, k store.ContextKey, ct store.Context, ttl time.Duration) error {
	defer c.evictKey(k)
	return c.Store.PutContext(ctx, k, ct, ttl)
}

func (c *cache) SwapContext(ctx context.Context, k store.ContextKey, rev uint64, ct store.Context, ttl time.Duration) error {
	defer c.evictKey(k)
	return c.Store.SwapContext(ctx, k, rev, ct, ttl)
}

func (c *cache) SwapLogin(ctx context.Context, k store.ContextKey, rev uint64, ct store.Context, ttl time.Duration, w store.LoginWrite) error {
	defer c.evictKey(k)
	return c.Store.SwapLogin(ctx, k, rev, ct, ttl, w)
}

func (c *cache) RewriteContext(ctx context.Context, k store.ContextKey, rev uint64, ct store.Context, ttl time.Duration, policyMoved bool) error {
	defer c.evictKey(k)
	return c.Store.RewriteContext(ctx, k, rev, ct, ttl, policyMoved)
}

func (c *cache) TouchContext(ctx context.Context, k store.ContextKey, ttl time.Duration) error {
	defer c.evictKey(k)
	return c.Store.TouchContext(ctx, k, ttl)
}

func (c *cache) SetPrivilege(ctx context.Context, k store.ContextKey, level uint8) error {
	defer c.evictKey(k)
	return c.Store.SetPrivilege(ctx, k, level)
}

func (c *cache) AnnotateContext(ctx context.Context, k store.ContextKey, discHash string, state string) error {
	defer c.evictKey(k)
	return c.Store.AnnotateContext(ctx, k, discHash, state)
}

func (c *cache) RefreshContext(ctx context.Context, k store.ContextKey, r store.ContextRefresh, ttl time.Duration) error {
	defer c.evictKey(k)
	return c.Store.RefreshContext(ctx, k, r, ttl)
}

func (c *cache) SetRevokedAt(ctx context.Context, k store.ContextKey, at time.Time) error {
	defer c.evictKey(k)
	return c.Store.SetRevokedAt(ctx, k, at)
}

func (c *cache) SetContextPolicy(ctx context.Context, k store.ContextKey, policyRev uint64, p store.ContextPolicy) error {
	defer c.evictKey(k)
	return c.Store.SetContextPolicy(ctx, k, policyRev, p)
}

func (c *cache) DeleteContext(ctx context.Context, k store.ContextKey) error {
	defer c.evictKey(k)
	return c.Store.DeleteContext(ctx, k)
}

func (c *cache) DeleteContextIf(ctx context.Context, k store.ContextKey, rev uint64) error {
	defer c.evictKey(k)
	return c.Store.DeleteContextIf(ctx, k, rev)
}

var _ store.Store = (*cache)(nil)
```

Before writing these, check every context-writing method's signature against `store.Store` in
`internal/store/store.go`, and against `guard.go`'s wrappers (which list them all). A method the
interface has that writes a context and is missing here would be served from a stale entry
after its own write: add it.

- [ ] **Step 5: Run them to verify they pass, then the package with race**

Run: `go test ./internal/store/crypt/ -count=1 && go test -race ./internal/store/crypt/ -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/store/crypt
git commit -m "feat(crypt): a per-replica context cache, evicted by every change the feed brings

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 8: port49d's authorization reads through the cache, served stale through an outage and said

**Files:**
- Create: `internal/port49d/contextcache.go`, `internal/port49d/contextcache_test.go`
- Modify:
  - `internal/port49d/store.go` (`stores.author`; `openDaemon` builds the cache and says the
    start line; the memory branch sets `author`);
  - `internal/port49d/main.go` (`Author: author.New(labHandlerStore(sts.author, fault), …)`);
  - `internal/daemon/metrics/metrics.go` (two series);
  - `deploy/compose/config/port49d.yaml`.

**Interfaces:**
- Consumes: Task 7's `crypt.Cached`, `crypt.CacheConfig`; Task 4's
  `cfg.Store.Etcd.ContextCache`; `cfg.ContextIdleTTL`; `labHandlerStore`; `splitFleet`,
  `startSplitDaemon`, `startBroker`, `mintOn`, `loginSession`, `metricAt`, `waitWithin`,
  `waitCountWithin`, `addUnderEtcd`.
- Produces:
  - `stores.author store.Store`;
  - `metrics.Metrics.ContextCacheLookups *prometheus.CounterVec` and `ContextCacheEntries
    prometheus.Gauge`;
  - `type staleSayer`.

- [ ] **Step 1: The failing tests**

`internal/port49d/contextcache_test.go`:

```go
package port49d

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// daemonMetrics is the newest port49d metrics address said on out.
func daemonMetrics(t *testing.T, out *syncBuffer) string {
	t.Helper()
	ms := regexp.MustCompile(`port49d: metrics on (127\.0\.0\.1:\d+)`).FindAllStringSubmatch(out.String(), -1)
	if len(ms) == 0 {
		t.Fatalf("no port49d metrics line:\n%s", out.String())
	}
	return ms[len(ms)-1][1]
}

// cachedFleet is splitFleet whose port49d keeps a context cache of ttl,
// with the health checks set by health ("" for the defaults).
func cachedFleet(t *testing.T, out *syncBuffer, ttl, health string) (*fleet, tacacsClient, string) {
	t.Helper()
	f := splitFleet(t)
	addUnderEtcd(t, f.daemon, "    context_cache: {ttl: "+ttl+"}\n"+health)
	api, _ := startBroker(t, f.broker, out, 1)
	tacacs := startSplitDaemon(t, f.daemon, out, 1)
	return f, tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}, api
}

// A session's commands are answered from the cache after the first
// (design §12): the counter says hits, and the start line says the
// cache's terms.
func TestASessionsCommandsAreAnsweredFromTheCache(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f, dev, api := cachedFleet(t, &out, "5s", "")
	waitFor(t, &out, "the context cache is on: a session's context is read from it for up to 5s")
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
	for i := 0; i < 3; i++ {
		if !dev.permits("alice", "show", "version") {
			t.Fatal("a command was refused")
		}
	}
	if v := metricAt(t, daemonMetrics(t, &out), `port49_context_cache_lookups_total{outcome="hit"}`); v < 2 {
		t.Fatalf("hits %v, want at least 2", v)
	}
}

// Review Focus 3: a context deleted by another process is denied at the
// next command, inside the TTL: the feed evicted it.
func TestAContextDeletedElsewhereIsNotAnsweredFromTheCache(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f, dev, api := cachedFleet(t, &out, "30s", "")
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
	if !dev.permits("alice", "show", "version") {
		t.Fatal("the first command was refused")
	}
	root := f.srv.Client(t, "root")
	if _, err := root.Delete(context.Background(), "/port49/v1/c/", clientv3.WithPrefix()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for dev.permits("alice", "show", "version") {
		if time.Now().After(deadline) {
			t.Fatal("a context deleted in the store was still answered 5s later, inside a 30s ttl")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if r := lastCommand(t, &log); r["reason"] != "context_missing" {
		t.Fatalf("denied %v, want context_missing", r["reason"])
	}
}

// Review Focus 3, revoked: a session revoked through the broker (the path
// through revokeown.go's SetRevokedAt, the whole revocation in decision 32's
// order) is denied credential_revoked inside the TTL, because the context's
// change reached the daemon's feed and evicted its entry, and the daemon's
// marks hold the principal besides (plan 7f, M-7). The control: the cached
// session is answered before.
func TestARevokedSessionIsDeniedInsideTheTTL(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	addUnderEtcd(t, f.daemon, "    context_cache: {ttl: 30s}\n")
	api, stopBroker := startBroker(t, f.broker, &out, 1)
	tacacs := startSplitDaemon(t, f.daemon, &out, 1)
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
	for i := 0; i < 2; i++ {
		if !dev.permits("alice", "configure") {
			t.Fatal("control: the cached session's command was refused before the revocation")
		}
	}
	if err := stopBroker(); err != nil {
		t.Fatal(err)
	}
	var rout, rerr bytes.Buffer
	if code := offlineRevoke([]string{"--offline", "--config", f.broker, "--principal", "user:alice@example.com"},
		&rout, &rerr); code != 0 {
		t.Fatalf("exit %d: %s", code, rerr.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	for dev.permits("alice", "configure") {
		if time.Now().After(deadline) {
			t.Fatal("a revoked session was still answered 5s later, inside a 30s ttl")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if r := lastCommand(t, &log); r["reason"] != "credential_revoked" {
		t.Fatalf("denied %v, want credential_revoked", r["reason"])
	}
}

// Through a store hang the cache answers past its TTL, counted stale and
// said once, until the listeners close (design §12; Ruling 5).
func TestAHungStoreServesTheCacheUntilTheListenersClose(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f, dev, api := cachedFleet(t, &out, "1s", "    health: {interval: 500ms, close_after: 8}\n")
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
	if !dev.permits("alice", "show", "version") {
		t.Fatal("the first command was refused")
	}
	time.Sleep(1200 * time.Millisecond) // past the ttl
	metrics := daemonMetrics(t, &out)
	f.proxy.Hang(true)
	if !dev.permits("alice", "show", "version") {
		t.Fatalf("a cached session's command was refused on a hung store; log %s", log.String())
	}
	if v := metricAt(t, metrics, `port49_context_cache_lookups_total{outcome="stale"}`); v < 1 {
		t.Fatalf("stale %v", v)
	}
	if n := strings.Count(out.String(), "serving cached login contexts past store.etcd.context_cache.ttl"); n != 1 {
		t.Fatalf("the stale line said %d times", n)
	}
	dev.permits("alice", "show", "version")
	if n := strings.Count(out.String(), "serving cached login contexts past"); n != 1 {
		t.Fatalf("the stale line said again in one run of stale serves: %d", n)
	}
	waitWithin(t, &out, "closing every listener so that devices use their local method", 15*time.Second)
}

// Review Focus 3: an entry the feed evicted is never served through an
// outage: the store is the only source, and it does not answer.
func TestAnEvictedContextIsNotServedThroughAnOutage(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f, dev, api := cachedFleet(t, &out, "30s", "    health: {interval: 500ms, close_after: 8}\n")
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
	dev.permits("alice", "show", "version")
	root := f.srv.Client(t, "root")
	if _, err := root.Delete(context.Background(), "/port49/v1/c/", clientv3.WithPrefix()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond) // the feed delivers the delete
	f.proxy.Hang(true)
	if dev.permits("alice", "show", "version") {
		t.Fatal("an evicted context was answered on a hung store")
	}
}

// No ttl, no cache: said at the start, and no lookup counted.
func TestNoCacheWithoutATTL(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	daemonCfg, _ := etcdSplit(t)
	startSplitDaemon(t, daemonCfg, &out, 1)
	waitFor(t, &out, "the context cache is off (store.etcd.context_cache.ttl is not set)")
}
```

`f.proxy` is the proxy both the broker and port49d reach etcd through, so the broker's mint
must come before the hang. It does in each test. `lastCommand` is `run_test.go`'s.

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/port49d/ -run 'TestASessionsCommandsAreAnsweredFromTheCache|TestAContextDeletedElsewhere|TestARevokedSessionIsDenied|TestAHungStoreServesTheCache|TestAnEvictedContext|TestNoCacheWithoutATTL' -count=1`
Expected: FAIL. There is no cache line, and `context_cache` is unknown to the wiring (Task 4
accepted it; nothing reads it).

- [ ] **Step 3: The metrics, the sayer, the wiring**

`internal/daemon/metrics/metrics.go`:
- Fields beside the health ones:

```go
	// ContextCacheLookups counts the context cache's reads by outcome
	// (hit, miss, stale; plan 7f): any increase of stale is a replica
	// answering from contexts the store did not confirm.
	ContextCacheLookups *prometheus.CounterVec
	ContextCacheEntries prometheus.Gauge
```

- Their construction:

```go
		ContextCacheLookups: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_context_cache_lookups_total",
			Help: "The context cache's reads by outcome: hit, miss, stale (served past its ttl because the store failed)."},
			[]string{"outcome"}),
		ContextCacheEntries: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_context_cache_entries",
			Help: "Login contexts the context cache holds."}),
```

- Both registered. Precreate `hit`, `miss` and `stale` at 0.

`internal/port49d/contextcache.go`:

```go
package port49d

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// staleSayer says, once per run of them, that the context cache is
// answering past its ttl because the store fails, and once that the
// store answers again (plan 7f, Ruling 5): the line is the durable
// witness, since the metrics registry restarts with each run after a
// store gone, and a stale run ends in one.
type staleSayer struct {
	mu  sync.Mutex
	on  bool
	out io.Writer
	ttl time.Duration
}

func (s *staleSayer) serve(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.on {
		return
	}
	s.on = true
	fmt.Fprintf(s.out, "port49d: store: the store does not answer context reads (%v); serving cached login contexts "+
		"past store.etcd.context_cache.ttl (%v) until it does or the listeners close; a revocation made meanwhile "+
		"does not reach them\n", err, s.ttl)
}

func (s *staleSayer) fresh() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.on {
		return
	}
	s.on = false
	fmt.Fprintln(s.out, "port49d: store: context reads are answered by the store again; the context cache serves "+
		"within its ttl")
}
```

`internal/port49d/store.go`:
- In `stores`, add:

```go
	// author is what command and session authorization read through: the
	// daemon's store, behind a context cache when
	// store.etcd.context_cache.ttl is set (plan 7f; design §12).
	author store.Store
```

- In the memory branch of `openStores`: `return stores{daemon: st, broker: st, author: st, close: func() {}}, nil`.
- In `openDaemon`, build the daemon's store into a variable, then the cache:

```go
	daemon := crypt.Wrap(gd, keys, m.CryptOpenFailures, crypt.WithLedger(ledger), say)
	authorStore := daemon
	if cc := e.ContextCache; cc.TTL > 0 {
		ss := &staleSayer{out: out, ttl: cc.TTL}
		authorStore = crypt.Cached(daemon, ledger, crypt.CacheConfig{TTL: cc.TTL, Max: cc.MaxEntries,
			IdleTTL: cfg.ContextIdleTTL, Lookups: m.ContextCacheLookups, Entries: m.ContextCacheEntries,
			Stale: ss.serve, Fresh: ss.fresh})
		fmt.Fprintf(out, "port49d: store: the context cache is on: a session's context is read from it for up to %v, "+
			"at most %d entries; a revocation reaches it through the context feed, and through a store outage it is "+
			"served past %v until the listeners close\n", cc.TTL, cc.MaxEntries, cc.TTL)
	} else {
		fmt.Fprintln(out, "port49d: store: the context cache is off (store.etcd.context_cache.ttl is not set)")
	}
```

- Use `daemon:` and `author: authorStore` in the returned `stores`.

`internal/port49d/main.go`, in `runOnce`, at the `Author:` field of `server.Deps`, replace
`author.New(handlerStore, …` with `author.New(labHandlerStore(sts.author, fault), …`. Leave
`Authen` and `Acct` on `handlerStore`, with a one-line comment: "the context cache is
authorization's alone (plan 7f, Ruling 5): a login's join reads the store".

- [ ] **Step 4: Run them to verify they pass, then the package and race**

Run: `go test ./internal/port49d/ -run 'TestASessionsCommandsAreAnsweredFromTheCache|TestAContextDeletedElsewhere|TestARevokedSessionIsDenied|TestAHungStoreServesTheCache|TestAnEvictedContext|TestNoCacheWithoutATTL' -count=1 -v && go test ./internal/port49d/ -count=1 && go test -race ./internal/port49d/ ./internal/store/... -count=1`
Expected: PASS.

- [ ] **Step 5: The whole suite**

Run: `make test && make vet`
Expected: PASS; report the real tail of each.

- [ ] **Step 6: The compose example names the new keys**

In `deploy/compose/config/port49d.yaml`, under `store.etcd`, add:

```yaml
    # Go-dark (decision 37): the defaults, said so an operator sees them.
    health: {interval: 1s, close_after: 5, open_after: 3}
    # The context cache (design §12): its ttl is a term in revocation
    # latency, so it is never on unless set. Through a store outage a cached
    # session's commands are answered past it until the listeners close.
    # Off here: port49 never picks a ttl, and a trial that copies this file
    # should not inherit a revocation gap through outages it did not choose.
    # context_cache: {ttl: 2s}
```

The example ships with `context_cache` commented out, comment kept: the cache is off in the
trial and in the smoke test, as in any deployment that has not chosen a ttl (Ruling 5).

Run `make compose-smoke` (Task 1's caveat on where), and expect PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/port49d internal/daemon/metrics deploy/compose/config/port49d.yaml
git commit -m "feat(port49d): authorization reads through the context cache, served stale through an outage and said

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 9: (lab, on beehive) L41 on five images, on the compose stack

**Files:**
- Create: `tests/lab/l41_test.go`
- Modify: `tests/lab/compose_unit_test.go` (the bound's test), `tests/lab/compose_test.go` (the
  health and cache keys in the lab's port49d.yaml)
- Results: `tests/lab/results/L41-{arista_eos,cisco_nxos,cisco_iosxe,juniper_vjunos-router,juniper_vsrx}.md`,
  evidence
- Modify (docs): spec §15 L41's Status; design §12's cells, with the measured numbers

**Interfaces:**
- Consumes:
  - Task 2's `composeStack` (`HangStore`, `ReleaseStore`, `StopDaemon`, `StartDaemon`,
    `Revoke`);
  - the harness's `storeOutcome`, `shellCell`, `ctxIDOf`, `hasCtx`, `replyTimesFrom`,
    `splitAttempts`, `renderAttempts`, `labKeyDefault`, `breakglassUser`,
    `breakglassPassword`, `wideCell`, `firstOut`.
- Produces: `healthDarkBound(interval, callTimeout time.Duration, closeAfter int) time.Duration`.

- [ ] **Step 1: The bound's failing unit test**

In `tests/lab/compose_unit_test.go`:

```go
// The dark bound under the health checks (decision 37): close_after ×
// interval + call_timeout, with 5s for the 250ms poll and the process.
func TestHealthDarkBound(t *testing.T) {
	if got, want := healthDarkBound(time.Second, 500*time.Millisecond, 5), 10500*time.Millisecond; got != want {
		t.Fatalf("healthDarkBound = %s, want %s", got, want)
	}
}
```

Run: `make lab-unit`
Expected: FAIL, undefined `healthDarkBound`.

- [ ] **Step 2: The bound, and the lab's keys**

In `tests/lab/compose_test.go`:

```go
// The lab's health checks, which every compose run's port49d.yaml names
// (decision 37): the defaults, said. The context cache is off in the lab:
// L41 measures nothing about it, and a cache would answer cell 3's command
// from memory and play a part in what the closed listener is measured doing.
const (
	labHealthInterval = time.Second
	labCloseAfter     = 5
	labOpenAfter      = 3
)

// healthDarkBound is the longest an idle port49d on a hung store takes to
// close its listeners under its health checks (decision 37): closeAfter
// checks interval apart, the last bounded by callTimeout; 5s is slack for
// the 250ms poll and the process.
func healthDarkBound(interval, callTimeout time.Duration, closeAfter int) time.Duration {
	return time.Duration(closeAfter)*interval + callTimeout + 5*time.Second
}
```

`composeStoreBlock("daemon")` adds `health: {interval: 1s, close_after: 5, open_after: 3}` under
`etcd:`, and no `context_cache:`: the cache is off for L41. Extend
`TestComposeLabFilesNameTheContainersPaths` to assert `health:` is in `port49d.yaml` and absent
from `port49-broker.yaml`, and that `context_cache` is in neither.

Run: `make lab-unit`
Expected: PASS.

- [ ] **Step 3: The L41 test**

`tests/lab/l41_test.go`:

```go
//go:build lab

package lab

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const l41Claim = "On the compose deployment (plan 7f; port49d, port49-broker and three etcd members as containers), an " +
	"idle port49d whose store hangs closes its TACACS+ listener within close_after × interval + call_timeout " +
	"(5.5s at the defaults; the bound allows 5s more for the poll), and break-glass then logs in; an open " +
	"session's next command once it is closed is recorded beside the same command with port49d stopped; once the " +
	"store returns, port49d says its open_after passes before it listens again, and the session's next command " +
	"the device sends it is answered from the context the store kept (policy engine spec §13 decision 37)."

func TestL41GoDarkMidSession(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		var failed []string
		fail := func(format string, args ...any) { failed = append(failed, fmt.Sprintf(format, args...)) }
		sessionOnly := strings.HasPrefix(l.p.name, "juniper_")
		var obs strings.Builder
		wide := func(cell, what string) { fmt.Fprintf(&obs, "| %s | %s |\n", cell, wideCell(what)) }
		obs.WriteString("| cell | observed |\n|---|---|\n")

		c := l.startCompose(t)
		stop := l.capture(t, "L41")
		defer stop()
		capPath := filepath.Join(root, "tests", "lab", "captures", "L41-"+l.p.name+".pcap")
		times := func(from, to time.Time) string {
			l.flushCapture(t)
			as, err := splitAttempts(capPath, l.p.addr, from, to)
			conns := renderAttempts(as)
			if err != nil {
				conns = "capture unreadable: " + err.Error()
			}
			return strings.Join(replyTimesFrom(capPath, labKeyDefault, from, to, true), "; ") + " | connections: " + conns
		}
		// waitLine is how long after `from` the line s appears on port49d's
		// stderr past off, or 0 if it does not within `within` of from. Each
		// call measures from the moment its caller names, never from its own
		// start: a second wait that begins after the first returned would
		// otherwise read near 0 for a line that was already there.
		waitLine := func(off int64, s string, within time.Duration, from time.Time) time.Duration {
			for time.Since(from) < within {
				if len(l.errLinesSince(off, s)) > 0 {
					return time.Since(from)
				}
				time.Sleep(250 * time.Millisecond)
			}
			return 0
		}

		// 1. The baseline: a login, `show version` permitted, its ctx_id.
		off := l.mark()
		sock, _, stopAgent := revokeAgent(t)
		defer stopAgent()
		said, tok := l29Mint(sock, l.p.node)
		if tok == "" {
			t.Fatalf("the agent minted no token through the compose broker: %s", said)
		}
		sh, err := l.shell(sliceUser, tok)
		if err != nil {
			t.Fatalf("SSH login: %v", err)
		}
		defer sh.Close()
		from := time.Now()
		before := storeOutcome(l.p.name, sh, "show version", fail, "baseline")
		ctx1, v1, r1 := ctxIDOf(l.waitForRecords(off, 30*time.Second, hasCtx(sessionOnly)), sliceUser)
		wide("1. login through the compose port49d, `show version`", fmt.Sprintf("%s; record %s %s, ctx_id %s | %s",
			before, v1, r1, ctx1, times(from, time.Now())))

		// 2. The store hangs; no device asks. When port49d closes.
		errOff := l.errLogSize()
		if err := c.HangStore(); err != nil {
			t.Fatal(err)
		}
		hungAt := time.Now()
		dark := waitLine(errOff, "closing every listener so that devices use their local method", 60*time.Second, hungAt)
		bound := healthDarkBound(labHealthInterval, labCallTimeout, labCloseAfter)
		wide("2. the store hangs (the three members paused), no device asking: port49d closes its listener",
			fmt.Sprintf("%s after the hang (bound %s); the line: %s", dark.Round(100*time.Millisecond), bound,
				firstOf(l.errLinesSince(errOff, "consecutive store health checks failed"))))
		if dark == 0 || dark > bound {
			fail("port49d closed its listener %s after the hang, bound %s", dark, bound)
		}

		// 3. The open session's next command, the listener closed.
		time.Sleep(3 * time.Second) // the drain
		from = time.Now()
		out3 := shellCell(l, sh, "show version")
		wide("3. listener closed: the open session's `show version`", out3+" | "+times(from, time.Now()))

		// 4. Break-glass, the listener closed.
		from = time.Now()
		outs, berr := l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version")
		wide("4. listener closed: break-glass and `show version`", fmt.Sprintf("login err %v in %s; printed %s | %s",
			berr, time.Since(from).Round(100*time.Millisecond), firstOut(outs), times(from, time.Now())))
		if berr != nil {
			fail("break-glass did not log in with the listener closed: %v", berr)
		}

		// 5. The store returns: the passes, then the listener.
		errOff = l.errLogSize()
		if err := c.ReleaseStore(); err != nil {
			t.Fatal(err)
		}
		releaseAt := time.Now() // both times below are measured from the release
		passed := waitLine(errOff, fmt.Sprintf("%d consecutive health checks passed", labOpenAfter), 120*time.Second, releaseAt)
		listening := waitLine(errOff, "listening on", 120*time.Second, releaseAt)
		if err := l.awaitTACACS(); err != nil {
			fail("TACACS+ did not answer again: %v", err)
		}
		wide("5. the store returns: the passes said, then listening", fmt.Sprintf("passes said %s, listening %s after the release",
			passed.Round(100*time.Millisecond), listening.Round(100*time.Millisecond)))
		if passed == 0 || listening == 0 {
			fail("after the store returned: passes said %s, listening %s", passed, listening)
		}

		// 6. When the device asks port49d again: the open session's
		// `show version` every 5s, up to 5 minutes, until port49d records
		// it (Junos: no command is sent, decision 21; a fresh login is
		// measured instead).
		off = l.mark()
		back := time.Now()
		var asked time.Duration
		var ctx6, v6, r6 string
		neverAsked := false // a device that does not ask again within 5 minutes: recorded, the row stays open for it
		if sessionOnly {
			said, tok2 := l29Mint(sock, l.p.node)
			if tok2 == "" {
				t.Fatalf("no token after the return: %s", said)
			}
			_, lerr := l.loginWithin(sliceUser, tok2, 90*time.Second, "show version")
			asked = time.Since(back)
			wide("6. Junos: a fresh login after the return (an open session's command sends no TACACS+)",
				fmt.Sprintf("err %v, %s after listening | %s", lerr, asked.Round(100*time.Millisecond), times(back, time.Now())))
			if lerr != nil {
				fail("a fresh login after the store returned: %v", lerr)
			}
		} else {
			for time.Since(back) < 5*time.Minute {
				shellCell(l, sh, "show version")
				ctx6, v6, r6 = ctxIDOf(l.recordsSince(off), sliceUser)
				if ctx6 != "" {
					asked = time.Since(back)
					break
				}
				time.Sleep(5 * time.Second)
			}
			wide("6. the open session's `show version` until port49d is asked again", fmt.Sprintf(
				"asked %s after listening; record %s %s, ctx_id %s (before: %s) | %s", asked.Round(100*time.Millisecond),
				v6, r6, ctx6, ctx1, times(back, time.Now())))
			switch {
			case ctx6 == "":
				// What the device did, not a defect of port49d: no command
				// reached it in 5 minutes. Recorded, and the row stays open
				// for this platform (CLAUDE.md, register rule 3).
				neverAsked = true
			case v6 != "permit" || ctx6 != ctx1:
				fail("after the return the session was not answered from its kept context: %s %s %s/%s", v6, r6, ctx6, ctx1)
			}
		}

		// 7. Beside port49d stopped: the same command, and break-glass.
		if err := c.StopDaemon(); err != nil {
			t.Fatal(err)
		}
		from = time.Now()
		out7 := shellCell(l, sh, "show version")
		wide("7. port49d stopped: the open session's `show version`", out7+" | "+times(from, time.Now()))
		from = time.Now()
		outs7, berr7 := l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version")
		wide("7. port49d stopped: break-glass", fmt.Sprintf("login err %v in %s; printed %s",
			berr7, time.Since(from).Round(100*time.Millisecond), firstOut(outs7)))
		if err := c.StartDaemon(); err != nil {
			t.Fatal(err)
		}
		wide("3 beside 7", fmt.Sprintf("closed on its checks: %s; stopped: %s", firstLine(out3), firstLine(out7)))

		note := obs.String()
		if neverAsked {
			note += "\n**Cell 6 is not measured on this platform:** the device did not ask port49d again within 5 " +
				"minutes of its listening. That is what the device did, recorded; L41 stays open for " + l.p.name + ".\n"
		}
		if len(failed) > 0 {
			note += "\n**Not as the claim says:**\n\n- " + strings.Join(failed, "\n- ") + "\n"
		}
		l.result(t, "L41", l41Claim, note)
		if len(failed) > 0 {
			t.Fatalf("L41 on %s: %s", l.p.name, strings.Join(failed, "; "))
		}
	})
}

// firstOf is the first of lines, or "none".
func firstOf(lines []string) string {
	if len(lines) == 0 {
		return "none"
	}
	return lines[0]
}
```

`labCallTimeout` is the harness's 500ms. Check that `firstLine`, `firstOut` and `wideCell` exist
under those names (split_test.go uses them). Cells 3 and 7 assert nothing: what the device does
there is a device fact, recorded.

- [ ] **Step 4: Run it, one platform first**

On beehive, with the watchdog armed:

Run: `PORT49_LAB_PLATFORMS=eos go test -tags lab ./tests/lab/ -run TestL41GoDarkMidSession -count=1 -v -timeout 120m`
Expected: PASS, with `results/L41-arista_eos.md` written. Read the note before going on.

- [ ] **Step 5: The other four**

Run, once per platform (`make lab` would run every test, so use Step 4's form):
`PORT49_LAB_PLATFORMS=<nxos|iosxe|vjunos|vsrx> go test -tags lab ./tests/lab/ -run TestL41GoDarkMidSession -count=1 -v -timeout 120m`
Expected: PASS on each. A device that never asks port49d again within 5 minutes does not fail
the test: cell 6 is recorded as what the device did, the note says "Cell 6 is not measured on
this platform", and the row stays open for that platform. A row with any platform unmeasured
stays open.

- [ ] **Step 6: Evidence, close, design numbers**

Run: `make evidence`, and check each note points at its evidence.

If all five passed, and no note says "Cell 6 is not measured", edit L41's Status in spec §15 to:

`closed — measured <date>; tests/lab/results/L41-arista_eos.md, L41-cisco_nxos.md,
L41-cisco_iosxe.md, L41-juniper_vjunos-router.md, L41-juniper_vsrx.md (run at <sha> from a
pinned worktree)`

followed by the observation per image, from the notes alone:
- dark time;
- cell 3 beside cell 7;
- break-glass;
- the time to listening;
- the time until asked again.

In design §12, replace each "derived from them; policy engine spec §15 L41 measures it" that
Task 3 wrote ahead of the measurement with the measured range, citing the notes (the same for
decision 37's "derived from the defaults; §15 L41 measures it"). If a note contradicts Task 3's text,
fix the text and say so in the commit (CLAUDE.md rule 4).

- [ ] **Step 7: Commit**

```bash
git add tests/lab/l41_test.go tests/lab/compose_test.go tests/lab/compose_unit_test.go tests/lab/results/L41-* \
  tests/lab/evidence/L41-* docs/design
git commit -m "docs: close lab register entries L41 (go-dark on health checks, five images, on compose)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

If L41 stays open on any image, the message is `test(lab): L41 measured on <images>; open on
<images>`, and the row stays open.

---

### Task 10: Plan 7f as built

**Files:**
- Modify: `docs/superpowers/plans/README.md`

- [ ] **Step 1: The roadmap**

In the roadmap:
- Add `### Plan 7f — As built` after "Plan 7e — As built", in 7e's shape:
  - task by task, what differs from this plan's text, with commit SHAs;
  - the rulings as made, against Rulings 1–9, and Ryan's answers to OR-1 and OR-2;
  - the operator notes below, as built;
  - "Carried, for later plans": at least plan 12's systemd and Kubernetes shapes and L39 (b),
    (c); and the restore guard's IOS-XE lockout, unassigned.
- Update the status line's 7f entry to "executed … merged … PR #…" once it is.
- In "Plan 12", "Deployment shapes", note that the container shape and its CI test exist (7f),
  and that plan 12 finishes its install page.

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/plans/README.md
git commit -m "docs: plan 7f as built

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

## Operator-facing notes (for the pull request body)

- **New: a container image and a compose stack** (`deploy/compose`, `Dockerfile`).
  - One peer shape beside systemd and Kubernetes. Nothing requires it.
  - The image runs as uid 65532 and holds `port49d`, `port49-broker`, `port49` and
    `port49-inventory`.
  - The stack runs three etcd members with client-certificate auth and port49's roles, and one
    configuration volume per component (no container holds both etcd identities, and the
    device key is port49d's alone).
  - `broker.state_dir` is a named volume per broker, 0700 and owned by 65532 from the image.
    Never `--scale` the broker.
  - CI brings it up, logs a device in, recreates it, and checks the session, a token minted
    before, and `broker.state_dir` were kept.
- **port49d goes dark on store health checks** (`store.etcd.health`: `interval` 1s,
  `close_after` 5, `open_after` 3).
  - Idle or loaded, every listener closes within `close_after` × `interval` + `call_timeout`
    (5.5s at the defaults) of the store stopping. It was about 2 minutes for an idle port49d at
    `hold_ttl` 60s.
  - IOS-XE's break-glass lockout on a store fault shrinks to that window; nothing port49
    answers changes.
  - After the store returns, port49d listens again only after `open_after` checks pass in a
    row, and says so.
- **The context cache** (`store.etcd.context_cache.ttl`, off unless set).
  - Command and session authorization read a session's context from it for up to the TTL. A
    revocation reaches it through the context feed.
  - Through a store outage it is served past its TTL until the listeners close, counted
    `port49_context_cache_lookups_total{outcome="stale"}` and said once:
    `serving cached login contexts past store.etcd.context_cache.ttl`.
  - Alert on any increase of that series.
- **New metrics:**
  - `port49_store_health_checks_total{outcome}`;
  - `port49_store_health_failures`, where above 0 for three intervals is the alarm;
  - `port49_context_cache_lookups_total{outcome}`;
  - `port49_context_cache_entries`.
- **New config refusals:**
  - the health and cache bounds;
  - a `context_cache:` block with no `ttl`;
  - either block in `port49-broker.yaml`.
- **Removed:** Ruling 11's probe, along with its two-minute idle go-dark.
- **Lab:**
  - L39 (a): what a published port does to a device's source address, with Docker's userland
    proxy on and off;
  - L41: what each image does when port49d closes its listener on its checks, beside port49d
    stopped, and how soon it asks again.

## Self-review against the spec

- **Design §12's cache paragraph:**
  - TTL "seconds, not minutes": the bounds of 100ms to 60s. "MUST be explicit configuration":
    off until set, and a block with no `ttl` refused.
  - "Serves the cache past its TTL, alarming": counted `stale`, said, and alerted on.
  - "Token redemption MUST NOT be cached": only `author.Handler` reads through it.
  - "Revocation does not function during it… documented": Ruling 5, the stale line, design
    §12's new sentence.
- **Design §12's ruling** "after N consecutive failed checks, reopening after M passes": Tasks 5
  and 6. "Store health MUST NOT be wired into the readiness probe": unchanged. `/readyz` is 503
  only while nothing listens, which decision 35 already allows.
- **Decision 35's refused-run rule:** the check counts a refusal as a failure, and the guard's
  `StopAfter` stays.
- **The roadmap's 7f text:**
  - Task 1: image, compose, volume per broker, CI smoke test with a restart keeping state.
  - L39's Docker half: Task 2.
  - Go-dark N/M: Tasks 4–6.
  - The cache: Tasks 7–8.
  - The lab row: L41, Task 9.
  - The carries, including the idle gap: the table above.
- **Deployment not prescriptive:** the compose test is tagged and has its own target, and no
  binary or `make test` needs Docker.
- **Placeholders:** the lab notes' sentences and the SHAs are written from the runs, as each
  step says.
- **Type consistency:** `health{every, timeout, closeAfter, openAfter, check, m, state, out}`,
  `healthState{failing, m}` with `bind`/`set`/`atLeast`/`count`, `storeCheck`, `passes`,
  `watch`, `runOnce(…, restored, hs)`, `composeLabFiles(base, brokerSlice, policy, inventory)`, `crypt.Cached`, `CacheConfig{TTL, Max, IdleTTL, Now, Lookups, Entries, Stale, Fresh}`,
  `Ledger.changed`/`rescanned`/`attach`, `evicter{evictKey, clearAll}`, `stores.health`, `stores.author`,
  `EtcdHealth{Interval, CloseAfter, OpenAfter}`, `EtcdContextCache{TTL, MaxEntries}`, `HealthSet`, `ContextCacheSet`
  are spelled the same in every task.
