# Directory and session stores: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** port49 runs on two stores named by function: `stores.directory` (enrollments,
revocations, unlocks, second-factor resets, the TOTP used step, back-channel logouts, directory
membership's pins), which every process watches and serves from a local cache, and
`stores.session` (tokens, login contexts, receipts, attempt counts, membership freshness). port49
fixes which record lives where; the operator chooses the topology. A region cut off from the
directory keeps verifying from its cache, across a restart too, and refuses directory writes
(design §13; roadmap "Plan 11a").

**Architecture:** The session store is today's store, with every piece of its machinery unchanged:
the hold, the ledger, the feeds, the guard, the restore guard and go-dark. The directory store is a
second keyspace, or in a single site the same one. It holds these families, and no others (R11):

| Family | What | Ruling |
|---|---|---|
| `rv/` | revocation marks | R11 |
| `sf/` | second factors, which carry the TOTP used step | R11 |
| `meta/enrollments` | the enrollment mark | R11 |
| `ul/` | unlocks (new) | R15 |
| `mb/`, `mk/` | directory membership's pin record and map-key index | R13 |
| `lo/` | back-channel logout records | R26 |
| `meta/seal_keys`, `meta/ping` | the key window the directory was last written under; the ping | R27, R21 |

Each process also keeps sealed snapshot records of its directory cache in its session store (`ds/`), so a
process restarted during a cut serves from it (R19).

Every process loads the marks from the directory and follows them into its `store.Marks`, as
`store.LoadMarks` and `store.FollowMarks` do today, and every authorization already reads that copy.
A new router, `internal/store/placement`, sends the revocation methods of `store.Store` to the
directory and answers `GetRevocation` from the copy, so a login and a mint never wait on another
region. The enrollment handle (`store.Enrollments`, plan 9e) opens on the directory store and is
read and written there directly: a password sign-in's TOTP step is a compare-and-set on the one
record, and fails closed when the directory does not answer.

In a split, each region's runner applies a mark it follows to its own session store
(`Broker.ReachMark`). `port49 store status` asks a process's admin socket what each store is and
how fresh its copy is.

**Tech Stack:** Go 1.26 (module `github.com/rhwendt/port49`), no new module; `go.etcd.io/etcd/client/v3`
(already a dependency: `MemberList`, `Status`); `internal/config`, `internal/store`
(`store.go`, `marks.go`, a new `fresh.go`), `internal/store/{placement (new),etcd,memory,enrollfile,crypt,guard,storetest}`,
`internal/broker`, `internal/port49d`, `internal/daemon/{admin,metrics}`, `cmd/port49`; the lab on
the SER8 (beehive): build tag `lab`, `ip netns`, `tc netem`, `iptables`, etcd v3.6.15 release
binaries (`PORT49_LAB_ETCD_BIN`).

**Spec:** `docs/design/2026-08-23-policy-engine-spec.md`:
- §5.7, the `sign_in_unlock` record (:2326);
- §12, `port49d store-roles` (:6405);
- §13 decisions 32 (marks), 35 (the etcd store), 36 (following the store), 47 (directory password
  and TOTP; D7, D12, D13 and ruling 5), and 50, the last (:10125);
- §15, the register's rules (:11063) and its last row, L73 (:11168).

Design `docs/design/2026-08-21-port49-design.md` §12 "Store interface" (:1491) and §13 "Token store
topology" and "etcd (plan 7d)" (:1573). The roadmap's "Plan 11a" section
(`docs/superpowers/plans/README.md`), and the items plans 9e and 10 carried to 11a (the roadmap's "Plan
9e — As built" and "Plan 10 — As built", "Carried forward").

## Global Constraints

- Go 1.26+, `gofmt` and `go vet` clean, no cgo, no new module. Per task: the targeted `go test`
  named in its steps. Before the final review the controller runs `make test && make vet` and
  reports the real output.
- Data is snake_case. The new config keys are `stores`, `stores.directory` and `stores.session`.
  Each takes today's store shape: `backend`, `packet_deadline`, and `etcd` with its keys. The new
  etcd families are `ul/` (directory) and `ds/` (session: the directory snapshots). The admin op is
  `store_status`, and its answer field is `degraded`. The metrics are
  `port49_store_directory_reachable`, `port49_store_directory_confirmed_timestamp_seconds` and
  `port49_store_logouts_pending`.
- **Pre-beta rule (Ryan, 2026-10-17):** the top-level `store:` key and
  `broker.directory.enrollment_store` are removed outright. There is no alias, no deprecation line
  and no shim. A file that still names either is refused as any unknown key is. Every config, test
  fixture, lab harness, example and doc that uses them is updated. Historical records keep their
  text: `docs/superpowers/plans/20*`, `docs/design/*-findings.md` and `tests/lab/results/`.
- Reason codes are spec §5.7's closed vocabulary (`internal/decision/reasons.go`). This plan adds
  none (Ruling R18). A cut directory reaches a password sign-in as `store_unavailable`, the answer
  it already gives. §12's warning codes are policy-tooling codes; this plan adds none.
- The log never contains a token, password, TOTP code, TOTP secret, challenge or response.
  Credentials appear only as `credential_sha256`. Test failure messages print no secret: a test
  that holds a TOTP secret or code never formats it into `t.Fatalf`.
- No device identity in a metric label. The three new metrics carry no label.
- **Deployment is not prescriptive** (Ryan, 2026-10-03): systemd, containers and Kubernetes are
  peers. Kubernetes is never required. The recipes name a shape only as an example.
- The lab register is the source of truth. This plan opens L74 and L75 (Task 1) and closes them
  from the lab runs (Task 15). A claim about multi-region behaviour cites the row until it
  closes. If a result contradicts a doc, the doc is wrong: fix it, cite the note, and say so in
  the commit.
- **Lab runs:**
  - Single occupant. Check the STOP sentinel `/tmp/port49-STOP-LAB` before every cell
    (`labGuardAt`), and run a background stall watchdog, re-armed on every wake.
  - Run from a detached worktree under `.worktrees/` (never `/tmp`), pinned at the commit.
  - The harness pins `issued_key_store: file` in every `$HOME/.port49/config.yaml` it writes.
  - An INVALID run writes no note.
  - The harness never prints a token, a password, a TOTP secret or a TOTP code. Each is held in
    memory and registered with the note's leak check (`labcreds.Contains`, and `l67Secrets` for
    the TOTP secrets and codes).
  - Never read `/tmp/port49-lab-tokens.jsonl` or any credential or env file. Never run `ykman`,
    `pkcs11-tool` or `tpm2_*`.
- Commits: Conventional Commits, one per step that says Commit, on
  `feature/directory-and-session-stores`. Each message ends with exactly:
  `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. Never add a `Claude-Session:` line
  or a claude.ai URL, in a commit, a PR body, an issue or a comment.

## Rulings

Format: **Ruling**: what — why — cost if wrong. R1 to R10 are Ryan's (2026-10-17) and binding.
R11 onwards are the planner's, made security-first where the spec is silent, except R13 (Ryan,
2026-10-17) and R26 (the team lead, 2026-10-17, under standing autonomy). The pre-flight's fixes
(2026-10-17) amended R13, R19 and R25 and added R27 to R29 on the team lead's rulings; R30 ledgers
the one pre-flight item not taken. The re-review's N1 to N5 (2026-10-17, the team lead's rulings)
amended R19, R23 and R13's restore note. Task 1 records all of them as spec §13 decision 51. Ryan may
override any of the planner's.

**Ryan's, binding:**

- **R1. Two built-in store roles, named by function**: `stores.directory` and `stores.session`.
  Each takes today's store shape (`backend: memory | etcd`, `packet_deadline`, `etcd:` with
  endpoints, CA, prefix, identities and bounds). — The function names say what a store holds, not
  where it runs. — If wrong, it is a rename.
- **R2. port49 fixes the data placement; the operator never configures it.**
  - Directory: enrollments, revocations, unlocks, second-factor resets, the TOTP used-step record,
    and policy.
  - Session: tokens, login contexts, receipts and attempt counts.
  - Every other key space is placed by the same principle: R11 to R15.
  — A placement an operator could change is one a 3am operator could get wrong. — The cost is
  named per family in R11 to R15.
  - Note (planner, on the pre-flight's I7): port49 keeps no policy record in any store; the
    policy is a file every host loads. R12 says what that means for "policy" here, and where a
    runner's judgement of it lives.
- **R3. The operator chooses the topology.**
  - A single site omits `stores.session`, or points it at the same store.
  - A multi-region deployment stretches the directory etcd with one member per region, and runs
    one session etcd per cluster.
  The docs give both recipes (Task 1; the operator notes). — This was Ryan's shape at work.
- **R4. Each process watches the directory store and serves reads from a local cache.** A process
  cut off from the directory keeps verifying from its cache. Directory writes fail closed:
  enrollments, revocations, lifts, unlocks and resets. The TOTP and staleness rulings are R16 and
  R17.
- **R5. The old top-level `store:` and `broker.directory.enrollment_store` are removed outright**,
  with no warning, alias or shim (pre-beta). The enrollment store is the directory store.
- **R6. `port49 store status`** prints, per role, the backend, the member count, reachability and
  the cache age, and says when the session store shares the directory store. How it reaches the
  process is R21.
- **R7. The roadmap entry** says directory and session in place of global and regional, and "roles
  and data placement are built in; topology is the operator's". Its status line names this plan.
  The planner made that edit beside this plan.
- **R8. Lab:** three simulated regions with netem latency and one cut region, measuring the cache,
  the fail-closed edges and the cross-region replay of a TOTP code. This is L74 and L75, opened by
  Task 1, with a harness in Task 14 and the runs in Task 15.
- **R9.** A new reason code goes into spec §5.7 first, and a new warning into §12 first. This plan
  needs neither (R18). snake_case data. No secrets in logs or test messages. No device identity in
  metric labels.
- **R10. Deployment is not prescriptive.** systemd, containers and Kubernetes are peers.

**The planner's:**

- **R11. The directory families are exactly these, and every other family is session:**
  - `rv/` (marks), `sf/` (second factors, which carry the used step), `meta/enrollments` (the
    enrollment mark) and `ul/` (unlocks, new; R15);
  - `mb/` and `mk/` (directory membership's pin record and map-key index; R13);
  - `lo/` (back-channel logout records; R26);
  - `meta/seal_keys` (the key window the directory was last written under; R27) and `meta/ping`.
  - Why: these are the records R2 names, and the ones R13 and R26 add. Each is written rarely, by
    an operator, a person enrolling, a first bind or an identity provider, and each must agree
    everywhere.
  - Cost if wrong: a family placed in session that needed to agree everywhere leaves a region
    acting on its own copy. R12 to R15 name each such case, and its fail-closed side.
- **R12. Policy: port49 keeps no policy in any store.**
  - The policy is a file every host loads (design §13, "The policy file is a privilege").
  - What the store keeps is one runner's judgement of that file over its own session store's
    contexts: `meta/judged`, `meta/judged_bundle`, `meta/bundles/` and `meta/refresh_owed`. The
    runner holding that store's hold writes them. They stay with the session store.
  - Policy agreement across regions is the deployment's: one file and one pipeline to every host.
  - Why: in the directory, three regional runners would write one record, and their
    compare-and-sets (`PutJudgedSince` compares `meta/bundles/` in the same transaction) cannot
    span two clusters.
  - Cost if wrong: no check catches two regions on different policy files.
    `port49_policy_bundle_matches_runner` compares a region's processes with that region's runner
    alone. Plan 12 may add a cross-region check if a deployment shows the need.
- **R13. Directory membership (plan 7g) is split by write rate (Ryan, 2026-10-17, replacing the
  planner's all-session ruling).**
  - The directory store holds the rare, authoritative part: the pin record (`mb/` there: the entry
    id, the map keys, `refused`, the forget's tombstone) and the `mk/` index.
  - The session store holds the per-mint freshness record: `verified_at`, the groups, DN and
    username, with a copy of the pin.
  - A verification writes the directory only when the directory's own pin differs: a first bind,
    a re-pin after a forget, a changed map key, or a refusal. It compares against the directory's
    pin, never the session copy, so a re-verify of the same entry after a forget pins it again.
    A read takes the pin from the directory, so one `port49 directory forget` frees the principal
    in every region.
  - **A directory pin has no lease (amended on the pre-flight's C1, the team lead's ruling).** It
    lives until a forget or a re-pin replaces it, and so does its `mk/` index. A forget is an
    explicit tombstone, kept with no lease either. A directory read tells three answers apart:
    - pinned;
    - forgotten (`store.ErrForgotten`, which is an `ErrNotFound`): the principal is free;
    - absent: never pinned. Absent while this region's session copy holds a pin means the
      directory lost it (a restore from an older backup). The router puts it back from the copy
      and serves the copy's pin, never "unpinned".
  - **A changed pin hides this region's freshness (I2).** When the directory's pin names another
    entry than this region's session record, the read answers the pin alone: no groups and no
    verification time, so grace serves nothing and the next verification is pinned to the new
    entry.
  - **A cache fill never outlives a change (I3).** Each principal's cache entry carries a
    generation that every feed change and every write bumps. A fill read before a change is
    dropped, and the next read goes to the directory again.
  - With the directory cut: a first bind, a refusal's record and a forget fail closed
    (`store_unavailable`). A pinned member's refresh keeps working from the cached pin and the
    regional freshness record, and the broker says it served the cached pin. Task 8a.
  - Why: no per-region operator toil for a forget, and no cross-region write on the hot path. A
    pin with a lease would lapse after `max(directory.grace, 24h)` for every active principal,
    since a refresh never rewrites it, and then any entry could take the principal: the
    moved-entry attack plan 7g Ruling 3 closes.
  - Cost if wrong:
    - A membership read is served from the broker's watched pin cache (R4), as a mark is. Only a
      miss reads the directory, bounded: a principal's first verification in this process, or the
      first after its pin changed. The cache's age is the directory cache's (R17).
    - In a cut region, a forget made elsewhere is not seen until the heal. The cut region keeps
      refusing the re-created entry meanwhile, which fails closed.
    - The directory's `mb/` holds one record per principal ever pinned, and `mk/` one per map key
      ever pinned, until a forget. A key no live record lists answers nothing.
- **R14. Every other family is session.** That covers:
  - the OIDC owner records (`oo/`); the logout records are the directory's (R26);
  - once-only records (`on/`): a logout token's jti, refresh and MFA challenges, enrollment
    handles, refresh pacing;
  - kept per-login MFA proofs (`mp/`);
  - sign-in attempt counts (`sa/`);
  - idempotency, superseded, the token and context indexes, blobs and the ledger;
  - the directory snapshots (`ds/`, R19);
  - every `meta/` key except `enrollments`. `meta/seal_keys` and `meta/ping` are in both stores:
    each store's own.

  - Why: each is written on the hot path, or belongs to one region's flow (a challenge one broker
    issues and takes; an enrollment handle confirmed where it was issued).
  - Cost if wrong:
    - An enrollment is confirmed in the region that started it.
    - A kept MFA proof is reused only in its own region. Elsewhere the person proves again, which
      fails closed.
- **R15. Unlocks are directory records; attempt counts are session.**
  - `port49 directory unlock` writes `ul/<principal>`, the unlock's time. Every unlock advances
    the record: one at or before the time standing is recorded a nanosecond after it, so a region
    whose clock runs slow still starts every region's count again (the pre-flight's minor 12).
  - A password sign-in reads that time from the directory before it counts, and counts the
    principal's failures under `principal:<principal>@<unlock time, Unix nanoseconds>`
    (`principal:<principal>` when no unlock stands). An unlock therefore starts every region's
    count again at once, and the old keys lapse with their window.
  - The unlock also clears its own region's old count, and its `sign_in_unlock` record's `failures`
    is that count.
  - Why: an unlock that cleared one region's count would leave the person locked out in the region
    they are in, at 3am, with nothing saying why.
  - Cost if wrong: one directory read per password sign-in, which already needs the directory for
    its code (R16). The record's `failures` counts the answering region's attempts alone.
- **R16. TOTP fails closed.**
  - A password sign-in reads and writes the directory store directly, never a cache. The used step
    is compared-and-set on the one record before the password is tried (decision 47 ruling 5).
  - A broker that cannot reach the directory refuses every password sign-in with 503
    `store_unavailable`, the answer a store fault already gets, and mints nothing.
  - Why: a cached or regional used-step record would let one observed code sign in once per region.
    Stopping that replay is the point of the step. Certificates, OIDC, hardware keys and
    break-glass keep working in a cut region.
  - Cost if wrong: a person whose only way in is a directory password cannot get a new certificate
    in a cut region until the cut heals. A certificate and tokens already issued keep working until
    they expire.
- **R17. A stale cache has no cut-off, and says how old it is.**
  - A process that has loaded the marks once serves from them for as long as the directory does not
    answer.
  - What the operator sees:
    - a line when the directory stops answering and another when it answers again;
    - `port49_store_directory_reachable`;
    - `port49_store_directory_confirmed_timestamp_seconds`, the last time a directory read answered
      while the marks feed ran;
    - the `cache` age in `port49 store status`.
  - Writes made elsewhere during a cut: a revocation, lift, reset or unlock made in another region
    does not reach the cut region until the cut heals. Then the marks feed delivers it, reloading if
    the revision was compacted, and the region's runner applies each new mark to its session store
    (R20).
  - A lift made elsewhere during a cut longer than the directory's compaction is put back by the cut
    region's runner, from its `marks.json`. The runner cannot tell that lift from a mark a restore
    lost (plan 7e Ruling 12). It names the mark on its line, and the remedy is to lift it again once
    the cut heals (L74 cell i).
  - The same put-back follows a port49-broker restarted after a lift made elsewhere while it was
    down (plan 7e's `keepCopied`): its `marks.json` still holds the mark, the directory does not, and
    the runner cannot tell a lift from a loss. Its line names the mark, and the remedy is the same
    (the pre-flight's minor 13).
  - A process restarted during a cut serves from its snapshot, and that copy has a ceiling (R19).
    A process that never restarted keeps this ruling's no cut-off.
  - Why: a deadline would turn a WAN cut into a regional outage, which is what the split exists to
    avoid (R4). The operator sees the age instead.
  - Cost if wrong: a principal revoked elsewhere keeps access in a cut region for the length of the
    cut. The docs say so, and the 3am table says how to cut access locally.
- **R18. No new reason code, warning or record event.**
  - Devices see nothing of a cut directory, since verification is local.
  - A password sign-in gets `store_unavailable`.
  - An operator's write gets the admin socket's error, which names the directory store.
  - The `sign_in_unlock` record keeps its fields. Its `failures` is the answering region's count,
    and spec §5.7 says so.
  - Why: every edge already has an answer that means the same thing.
- **R19. A process with no cache does not serve; a process restarted during a cut serves from its
  snapshot (amended on the pre-flight's I5 and I9, the team lead's ruling: a node must not go dark
  because it restarted during a cut).**
  - **The snapshot.** In a split, every port49d and every port49-broker replica writes its directory
    cache to its own session store every 60s while that cache is confirmed, sealed with the
    process's keys (`crypt.Keys.SealBound`, bound to the record's key), each with the directory
    revision and the confirmed time, and a lease of the ceiling below. Task 10a.
    - `ds/m/<proc>@<host>`, the marks record, which every process writes and port49d reads.
    - `ds/b/port49-broker@<host>`, a broker's logout records and cached pins: the daemon's role
      has no grant on it, so `mb/` and `lo/` stay out of its reach (the re-review's N4).
    - The daemon's role writes `ds/m/port49d@` alone: a stolen daemon credential can neither delete
      nor replay a broker's record (N1).
  - **A start with the directory not answering** tries the directory once. When it does not answer,
    the process serves the **union** of the marks of every marks record that opens and is younger
    than the ceiling, never the newest alone (N1): a deleted or replayed record lifts nothing
    another record holds. A broker also takes the union of every broker record's logouts and the
    newest one's pins, and needs at least one broker record. Its age is the newest record's.
  - **The heal.** Once the directory opens, each follow loads it afresh (from 0), which reconciles
    every add and lift, then watches (N5).
  - **The ceiling.** `session.staleness_ceiling` (4h by default; 4h when it is off), counted from
    the snapshot's confirmed time. A process serving from a snapshot that reaches it fails closed:
    port49d closes its listeners and waits for the directory, port49-broker refuses every mint and
    sign-in with 503 `store_unavailable`. The line says so beforehand, at start, with the time
    left. Only the heal's load of the marks lifts both (N5): a directory that answers a read while
    the load fails keeps the ceiling.
  - **A check that fails at the heal** (R27's keys, R28's cluster) ends the process, exit 1, with
    the check's message: never a store gone, which would reopen the listeners on the held marks
    and flap (N2).
  - **No snapshot younger than the ceiling** (a new install, a new region, or every writer gone for
    longer): the process waits with its listeners closed, as before, up to the directory's
    `etcd.start_timeout` on a cold start.
  - A port49d run after a session-store outage (a "store gone") already holds its marks, so it does
    not wait for the directory. It serves from its cache and follows the directory once it answers.
  - Not snapshotted: unlocks and second-factor resets. No process caches them: a password sign-in
    reads and writes the directory directly and fails closed in a cut (R16), so a copy would serve
    nothing.
  - Why: a deploy or an OOM kill during a WAN cut must not take a region dark; a process with no
    marks at all would serve every revoked principal, so it still does not serve.
  - Cost if wrong:
    - A process restarted during a cut serves a copy as old as its snapshot (up to 60s older than
      the cache it replaced), and stops at the ceiling while its unrestarted siblings keep serving
      (R17).
    - Each process writes one sealed record a minute to its session store, a few kilobytes per
      thousand marks.
    - A session store lost during a cut takes the snapshots with it, and a restarted process then
      stays dark until the heal.
- **R20. In a split, each region's runner applies a mark it follows to its own session store.**
  - It does what Revoke does after its mark: deletes the principal's or certificate's unspent tokens
    through the index, supersedes their keys, and marks the live contexts revoked in two passes
    (`Broker.ReachMark`, extracted from Revoke).
  - It says one line per mark.
  - In a shared store the broker that made the mark has already done this.
  - Why: the marks already deny every request (`store.Marks`), and a login carries a cached mark
    into its context. Deleting the tokens closes the mint that raced the feed.
  - Cost if wrong: in that region, tokens of a principal revoked elsewhere live until the feed
    delivers the mark and the runner runs. Each is denied at its login by the cache meanwhile.
- **R21. `port49 store status [--socket PATH]` asks the process's admin socket**, op
  `store_status`, as `port49 keys diagnose` does.
  - Reachability and cache age are the answering process's own view.
  - Default socket: `/run/port49/port49d.sock`. port49-broker answers the same op on its own
    socket.
  - Exit codes: 0 when every store answers, 3 when one does not, 1 on a socket error.
  - Members: "listed" is etcd's member list. "answering" counts a `Status` call to each member's
    first client URL that answers within the store's `etcd.call_timeout`.
  - Why: cache age exists only inside a process, and the admin socket is how the CLI already asks
    a process about itself.
  - Cost if wrong: a member whose advertised client URL this process cannot reach counts as not
    answering. The line is the process's view, not etcd's.
- **R22. Config rules.**
  - `stores` absent means one memory store. `stores.session` absent means the session store is the
    directory store: a single site.
  - Two blocks naming the same keyspace are one store. Same keyspace means the same backend, the
    same prefix (compared with one trailing `/`) and the same endpoint hosts (compared
    case-insensitively). The two blocks must then agree on every key the directory takes:
    `endpoints`, `ca_file`, `prefix`, `daemon`, `broker`, `roles`, `call_timeout`, `bulk_timeout`,
    `start_timeout`. The session block's other keys apply.
  - A directory store of its own takes those nine keys alone. A session-store key set under it is
    refused, naming where the key goes. Those keys are `packet_deadline`, `etcd.health`,
    `etcd.context_cache`, `etcd.hold_ttl`, `etcd.sweep_interval`, `etcd.lease_grace`,
    `etcd.breaker` and `etcd.max_in_flight`.
  - Two blocks with an endpoint host in common and nesting prefixes that are not one store are
    refused: a broker's role over one prefix would reach the other.
  - Memory and etcd together are refused. Memory means one process holding everything; etcd means
    port49-broker beside port49d.
  - The session-store relations (`packet_deadline` at least `call_timeout`, and
    `health.interval` at least `call_timeout`) bind the store that serves sessions alone. A
    cross-region directory may set a `call_timeout` above `packet_deadline`.
  - Cost if wrong: a site that wants in-process sessions beside a shared etcd directory runs a
    session etcd instead.
- **R23. Least privilege on the directory keyspace.**
  - The daemon reads `rv/`, `meta/ping` and `meta/seal_keys` (R27), and nothing else.
    port49-broker's role covers the whole keyspace (`etcd.RolesFor(prefix, ScopeDirectory)`).
  - On the session keyspace the daemon's grants are today's, minus the marks, plus read of
    `ds/m/` (every marks snapshot record) and write of `ds/m/port49d@` (its own), and nothing of a
    broker's `ds/b/` (R19; N1, N4).
  - `port49d store-roles` prints one section per store, each run against its own cluster.
  - port49d's start check (`CheckIdentityAt`) holds each identity to its own store's roles.
- **R24. The Kubernetes verifier's kept keys (carried from plan 10): each region's
  port49-broker.yaml lists its own region's clusters.**
  - Configs already differ per region (the session store), so this adds no step. The staleness
    alert then still means a cluster that broker serves.
  - Cost if wrong: a workload whose region's broker is down cannot fail over to another region's
    broker unless that broker lists its cluster too. If it does, that broker alerts on the cluster
    it cannot reach.
- **R25. No migration from one store to two (amended on the pre-flight's C1, the team lead's
  ruling).** port49 is pre-beta: a split starts on fresh stores, a new directory etcd and a new
  session etcd per region, and nothing is carried from a single store. No old etcd becomes either
  store. The operator notes say so.
  - Why: no deployment exists to carry, and a carried single store would start the directory with
    no pins (`mb/` was session-side), which R13's re-pin from a session copy would have to rebuild
    region by region.
  - Cost if wrong: a site that ran a single store before beta re-enrolls its password users, or
    carries its enrollments with `port49 directory export` and `import`, which work across the
    change as across any two stores.
- **R26. Back-channel logout records are directory records (Q1; ruled by the team lead 2026-10-17
  under standing autonomy, the security-stronger option; Ryan may overrule).**
  - A logout received in any region ends the session everywhere: its `lo/` record is written to the
    directory store.
  - Every port49-broker loads the logout records before it serves and follows them into a local
    copy (`store.LogoutSet`). A mint's and a refresh's check reads the copy and never waits on the
    directory (R4).
  - Each region's runner reaches a logout it follows in its own session store
    (`Broker.ReachLogout`): the owners' tokens, the contexts by `sid`, or by owner for a `sub`. The
    owner records (`oo/`, written at every mint) and the logout token's `jti` stay session.
  - With the directory cut, a logout is accepted, never lost (the team lead's amendment, 2026-10-17:
    Keycloak 26 does not retry a 503, L45). The broker answers 200 and applies it in-region at once:
    it writes the record to its session store, where this region's checks read it, and reaches the
    owners' tokens and sessions as today. That session record is the pending copy. A runner duty
    forwards each pending record to the directory once the directory answers, then deletes it.
    The broker says so in a line, and `port49_store_logouts_pending` (no labels) and
    `port49 store status` (`N logouts pending`) show the count. Other regions get the logout on the
    heal. Sessions keep being checked against the cached set and the pending records. Tasks 8b, 8c
    and 9.
  - Why: a logout is a revocation by the identity provider, and it must agree everywhere, as the
    marks do (R2).
  - Cost if wrong:
    - During a cut, a logout received in the cut region reaches the other regions only on the heal;
      until then those regions mint for that session. A logout made elsewhere reaches the cut
      region only on the heal.
    - A pending record lives in the session store: if that store is lost before the heal, the
      logout is lost with it. The pending gauge and line say so beforehand.
    - A session-store outage as well as a directory cut answers 503, as a store fault does today,
      and Keycloak does not retry it.
    - One more watched family per broker, and one forwarding duty per runner.

- **R27. Every region holds the same encryption keys, and a process whose keys cannot open the
  directory does not start (the pre-flight's I1, the team lead's ruling).**
  - The directory's sealed records (`sf/`, `mb/`) are sealed with the writing broker's
    `encryption:` keys, and every region reads and re-seals them. So every port49d and
    port49-broker in every region holds one `encryption:` key set.
  - The directory keeps its own `meta/seal_keys`: the key window (ids only, never key material)
    the last port49-broker to start against it held; every port49-broker start writes its own. A
    port49d or port49-broker whose window does not hold that record's current id cannot open what
    that broker seals, and refuses to start, exit 1, naming the directory store, its endpoints and
    prefix, and the key id it lacks. A record that does not decode is said and
    written over, as the session store's is (plan 7d Ruling 14). Task 9a.
  - The session store's check stays a warning (plan 7d Ruling 14: a refused start would hand
    whoever can write that store a lockout). The directory's refuses: only port49-broker's
    identity can write its `meta/`, and a region whose keys cannot open the directory refuses
    every password sign-in and every pin read anyway.
  - Rotation, in the docs: first give every region the new key as `encryption.previous`, then
    make it `encryption.current` everywhere (the old one now `previous`), then retire the old one
    once the re-seal line says nothing is left under it. Every process can open every record at
    every step.
  - A running process whose window loses the record's current key (a region rotated out of
    order) says so once an hour from the runner's scheduled pass.
  - Cost if wrong: a region given a new key out of order cannot restart until it holds the key
    the directory names, which is the failure the check exists to show at start rather than at a
    sign-in.
- **R28. One etcd cluster named two ways is one store (the pre-flight's minor 11).** R22 compares
  blocks by text. At open, a split also compares the two stores' etcd cluster ids (each
  response's header) and prefixes. The same cluster, with the same prefix or one holding the
  other, is refused at start, exit 1: "stores.directory (prefix …) and stores.session (prefix …)
  reach one etcd cluster (id …), and one prefix holds the other: they are one keyspace named two
  ways; omit stores.session …". Task 9a.
  - Why: two names for one keyspace would run the split's machinery on one store: the logout
    forwarding duty would take every directory logout record for a pending one and delete it.
  - Cost if wrong: one more read at each start.
- **R29. A runner taking over during a cut runs every duty that needs only its session store
  (the pre-flight's I5 and I4, the team lead's ruling).**
  - In a split the takeover lists the standing marks from the process's followed copy, never the
    directory, and applies them to the kept contexts as today. It also reaches every standing
    logout in the copy (`Broker.ReachLogout`).
  - The put-back of `marks.json`'s marks needs the directory: in a split it runs as its own duty,
    tried every 5s until the directory answers, then applied to the kept contexts.
  - The scheduled refresh, the sweep, the ledger keeper, the witness keeper, the reach of followed
    marks and logouts and the pending-logout forwarding all run; the last waits for the directory
    by itself. The re-seal of second factors waits by itself too (it says so once an hour).
  - A load of the logouts (at start, or a reload after a compaction) tells the runner each record
    it did not hold before, as a watch's put does, so a logout made elsewhere during a long cut is
    reached here on the heal.
  - A replica that does not run leaves a followed mark or logout to the runner, which follows the
    same feed; a takeover reaches every standing one. A runner whose queue is full says each drop.
  - Why: a takeover that waits on the directory stops the scheduled refresh, and every session in
    the region reaches `context_stale` at the ceiling: a regional outage from a WAN cut (R4).
  - Cost if wrong: a takeover during a cut applies the marks as of the copy, so one made elsewhere
    since the cut reaches the contexts on the heal (R17).
- **R30. Pre-flight items not taken (ledgered, with the reason).**
  - **Minor 16: set `FeedUp(true)` on the watch's first progress or event, not as it begins.**
    Not taken. The window is one watch establishment: on a live link it is milliseconds, and on a
    cut one the watch, which requires a leader, fails and `FeedUp(false)` follows. A ping that
    lands in it confirms the copy at most one check interval (1s) early. The fix changes decision
    36's `port49_store_feed_up` gauge for every feed. Cost if wrong: the confirmed time reads up to
    a second fresh after a watch restart. Its snapshot remainder (the re-review's N5) is fixed
    narrowly in R19: only the heal's load of the marks clears a snapshot's ceiling; the gauge is
    untouched.
  - **I4, in part: "say every drop".** Taken for the runner, whose full queue says each drop. Not
    for a replica that does not run: it drops every followed mark and logout by design, since the
    runner follows the same feed and a takeover reaches every standing one (R29); a line per mark
    on every such replica would be noise with nothing to act on. Cost if wrong: none lost; a
    replica's log does not show what it left to the runner.

## Questions for Ryan

- **Q1. Back-channel logout across regions: closed.** Ruled by the team lead on 2026-10-17 under
  standing autonomy, as the security-stronger option; Ryan may overrule. The ruling is R26 (Tasks
  8b and 8c).

## The operator at 3am

What each case looks like, and what fixes it. "Line" is stderr. "Record" is the decision log.

| Case | What the operator sees | Fix |
|---|---|---|
| A region's link to the directory etcd is cut | **Devices:** nothing; logins and commands are answered from the session store and the cached marks. **Lines** (port49d and port49-broker): `directory store: not answering (...): serving from the cache confirmed <age> ago; revocations, lifts, enrollments, unlocks and second-factor resets are refused until it answers`. **Metrics:** `port49_store_directory_reachable` 0; `time() - port49_store_directory_confirmed_timestamp_seconds` rising. `port49 store status` prints `directory  etcd    ?/? members  unreachable  cache 41.2s` (a cut-off member cannot list the cluster) and exits 3 | Restore the link. On heal the line `directory store: answering again; the cache was <age> old` appears, and the marks feed catches up |
| An operator revokes someone in region A while region C is cut | **A and B:** the next command is denied (marks feed, L74 b). **C:** the person's open sessions keep working; their tokens minted before the cut still log in | To cut C now, without the directory: remove the person's grants from the policy file C's hosts load (live within two watch intervals), or stop C's port49d. On heal, C's runner says `a revocation of <principal> made elsewhere reached N token key(s) and M context(s) here` |
| A lift made in A during a long cut comes back after C heals; or one made while a broker was down comes back when it starts | C's runner (or the started broker's): `N revocation(s) in broker.state_dir/marks.json were missing from the store (...) and are put back: <kind key>; lift any that were lifted on purpose with port49 revoke --lift` (plan 7e's put-back; R17) | Lift it again in any region once the cut has healed (L74 i) |
| A person signs in with a password and TOTP code in a cut region | **Person:** 503 `store_unavailable`, "the broker could not reach the directory store". **Record:** `issue` deny `store_unavailable` | Use a certificate, OIDC or a hardware key, or break-glass. Password sign-in returns when the cut heals |
| `port49 revoke`, `port49 directory unlock`, `reset-second-factor`, `init-enrollments` or `import` in a cut region | The command fails in about `stores.directory.etcd.call_timeout` with "the directory store did not answer, so nothing changed". A revocation instead says "could not be recorded" and names the fallback | Run it from a region that reaches the directory |
| port49d or port49-broker restarted during a directory cut (a deploy, an OOM kill) | It serves the union of its region's snapshot records: `directory store: not answering; serving from 3 snapshot(s), the newest port49-broker@host-b's, confirmed <age> ago: M revocation(s) in their union; served until it is 4h0m0s old (session.staleness_ceiling), then <port49d: the listeners close / port49-broker: mints and sign-ins are refused>`. `port49 store status` shows `cache <age> (snapshot)` (R19) | None while the cut is shorter than the ceiling. On heal each process loads the directory afresh; the ceiling and `(snapshot)` clear only when that load succeeds |
| The heal after a snapshot start finds the directory under a key this region lacks, or one cluster named twice | The process ends, exit 1, with the check's message (`crypt: the directory store (…) was last written by a process whose current key is "k2", which this configuration does not hold …`); its listeners do not reopen (R19, N2) | Give the region the key (or fix `stores:`), then start it |
| The directory etcd is restored from a backup older than a `port49 directory forget` | The forgotten principal's pin is back in the directory: a region whose session copy still names the old entry also puts it back if it was absent (R13). The re-created entry is refused again, `directory: user:… is pinned to entry … and is now claimed by …` (fail closed) | Run `port49 directory forget` again from any region once the restore is done |
| The cut outlasts the ceiling for a process started from a snapshot | **port49d:** `directory store: the snapshot this run serves from is <age> old, past session.staleness_ceiling (4h0m0s): the listeners close until the directory answers`, then the store-gone line `…; closing every listener so that devices use their local method`. **port49-broker:** every mint and sign-in 503 `store_unavailable`; the line names the ceiling. Processes that never restarted keep serving (R17) | Restore the link. Or, to serve longer from a copy known to be current, raise `session.staleness_ceiling` and restart: it also bounds contexts' `refreshed_at` |
| A process restarted during a cut finds no snapshot younger than the ceiling (a new region, or every writer gone longer) | Its listeners stay closed: `directory store at etcd …, prefix …: not answering (…); no snapshot in the session store is younger than session.staleness_ceiling (4h0m0s)`, then today's wait line (`… the listeners stay closed; waiting up to 30s`); a cold start exits 1 after `start_timeout`. Its region's other processes keep serving | Wait for the cut to heal, then start it again |
| A region's `encryption:` keys differ from the directory's | The process does not start: `port49-broker: crypt: the directory store (etcd https://..., prefix /port49/) was last written by a process whose current key is "k2", which this configuration does not hold (current "k1"); every region holds the same encryption keys (decision 51); add "k2" to encryption, then start again`, exit 1. A running runner says the same once an hour (R27) | Copy `encryption:` from a region that starts; rotate by the three steps in the operator notes |
| `stores.session` reaches the directory's etcd cluster and prefix under another name (an IP and a DNS name) | Start refuses: `stores.directory (prefix /port49/) and stores.session (prefix /port49/) reach one etcd cluster (id 8e9e05c52164694d), and one prefix holds the other: they are one keyspace named two ways; omit stores.session for a single site, …`, exit 1 (R28) | Omit `stores.session` |
| `port49 directory forget` for a re-created entry, run in region A | Every region reads the pin forgotten at its next verification; a region cut off at the time keeps refusing the re-created entry until the heal. In a cut region the forget itself is refused (`store_unavailable`), and a pinned member's mint says `directory store: not answering: serving <principal>'s cached directory membership` | Run it from a region that reaches the directory |
| The identity provider's back-channel logout arrives at region A | Every region's broker refuses that session's mints and refreshes once its logouts feed delivers the record; each region's runner says `a logout made elsewhere (...) reached N token key(s) and M context(s) here`. If A is cut from the directory: the provider gets 200; A applies the logout at once and says it is pending; `port49_store_logouts_pending` and `port49 store status` (`N logouts pending`) count it; on the heal A's runner says it forwarded N, and the other regions refuse from then on | None. To cut the session off in the other regions before the heal: `port49 revoke --principal <principal>` from a region that reaches the directory |
| Someone locked out of password sign-in in region B is unlocked from region A | B's next sign-in is judged afresh (R15) | None |
| `stores.session` points at the same keyspace as `stores.directory` but sets a timeout differently | Load refuses: `stores.directory and stores.session name one store (...) and set etcd.call_timeout differently` | Omit `stores.session` for a single site, or make the blocks agree |
| A config still says `store:` (or `broker.directory.enrollment_store`) | Load refuses: `config: line N: an unknown field; check the key spelling against the port49d.yaml schema` (the strict decoder does not echo the key) | Rename the block to `stores:` with a `directory:` block under it (single site); delete `enrollment_store` (the directory store holds the enrollments) |

## Review Focus

- **A region cut mid-session while a revocation is made elsewhere.** A person expects the open
  session in the cut region to keep working until the cut heals, and its next command to be denied
  shortly after. Task 10's `TestADaemonCutFromItsDirectoryServesFromItsCache` and
  `TestAMarkMadeDuringACutReachesTheDaemonOnHeal` pin both.
- **A port49d started during a directory cut, and one run again after a session outage.** A person
  expects the first to stay dark, since it has no cache, and the second to serve from the marks it
  already holds. Task 10's `TestAColdStartWithTheDirectoryCutStaysDark` and
  `TestARunAfterAStoreGoneServesThroughADirectoryCut` pin both.
- **A process restarted during a cut, and one whose snapshot outlives the ceiling.** A person
  expects the first to serve from its region's snapshot at once, and the second to fail closed at
  the ceiling, saying so. Task 10a's `TestARestartDuringACutServesFromTheSnapshot` and
  `TestASnapshotPastTheCeilingFailsClosed` pin both, and
  `TestATakeoverDuringACutRunsTheSessionDuties` pins the runner's half (R29).
- **A pin through a forget, a re-pin and a day.** A person expects a pinned principal to stay
  pinned however long it is idle, a forget in one region to free it everywhere, and a re-pin to
  another entry never to serve the old entry's groups. Task 8a's `TestAPinOutlivesItsTTL`,
  `TestOneForgetReachesEveryRegion` and `TestARePinHidesTheOldEntrysFreshness` pin them.
- **Two regions racing one TOTP code.** A person expects exactly one sign-in to pass, whichever
  region answers first. Task 5's `TestOneCodeSignsInOnceAcrossRegions` pins it with two brokers on
  their own session stores sharing one directory.
- **`stores.session` naming the directory's keyspace, written slightly differently** (a trailing
  `/` on the prefix, an endpoint host in another case). A person expects one store, not a "split"
  onto one keyspace, which would duplicate a runner's work and lose the atomic login check. Task
  2's `TestTheSameKeyspaceTwiceIsOneStore` pins it.
- **A directory write in a cut region.** A person expects it to fail promptly (about
  `call_timeout`), naming the directory store, not to hang the admin socket for 60s. Task 6's
  `TestADirectoryThatDoesNotAnswerIsBoundedByCallTimeout` pins the bound, and Task 9's
  `TestARevocationWithTheDirectoryCutFailsPromptly` pins it end to end.

---

## File map

| File | Responsibility | Task |
|---|---|---|
| `docs/design/2026-08-23-policy-engine-spec.md`, `docs/design/2026-08-21-port49-design.md` | decision 51, L74 and L75, §12, the key names, the recipes | 1 |
| `internal/config/config.go`, `internal/config/stores.go` (new), `internal/config/directory.go`, `internal/directory/config.go` | `stores:`; `store:` and `enrollment_store` removed | 2 |
| every fixture naming `store:` (Task 2 lists them) | the new block | 2 |
| `internal/store/marks.go`, `internal/store/fresh.go` (new) | a mark's origin; the cache's freshness | 3 |
| `internal/store/store.go`, `internal/store/enrollments.go`, `internal/store/{memory,enrollfile,etcd,crypt,guard,storetest}/…`, `internal/port49d/signin.go` | unlock records (`ul/`) | 4 |
| `internal/broker/signin.go`, `internal/broker/signin_admin.go` | the unlock's attempt key; unlock writes the directory | 5 |
| `internal/store/placement/placement.go` (new) | the router | 6 |
| `internal/store/etcd/roles.go`, `internal/store/etcd/members.go` (new), `internal/store/etcd/keys.go` | scopes, roles per store, `Members` | 7 |
| `internal/broker/revoke.go` | `ReachMark` | 8 |
| `internal/store/placement/placement.go` (`Members`), `internal/store/store.go` (`NoExpiry`, `ErrForgotten`), `internal/store/{etcd,memory}/membership…`, `internal/store/storetest`, `internal/store/etcd/{roles,feed}.go` | membership's pin in the directory, with no lease | 8a |
| `internal/store/logouts.go` (new), `internal/store/etcd/oidc.go`, `internal/store/placement/placement.go` | logout records in the directory, followed | 8b |
| `internal/broker/logout.go`, `internal/store/store.go` (`ParseOIDCKey`) | `ReachLogout` | 8c |
| `internal/port49d/brokerd.go`, `internal/port49d/storeref.go` (new), `internal/port49d/store.go`, `internal/port49d/runner.go`, `internal/port49d/offline.go`, `internal/port49d/signin.go` | port49-broker on two stores | 9 |
| `internal/port49d/dirkeys.go` (new), `internal/port49d/brokerd.go`, `internal/port49d/store.go`, `internal/port49d/runner.go` | the directory's key check; one cluster named twice | 9a |
| `internal/port49d/store.go`, `internal/port49d/fresh.go` (new), `internal/port49d/main.go`, `internal/daemon/metrics/metrics.go`, `internal/store/marks.go` (`FollowMarks` from 0) | port49d on two stores | 10 |
| `internal/store/snapshot.go` (new), `internal/store/fresh.go`, `internal/store/etcd/{keys,snapshot}.go`, `internal/store/placement/placement.go`, `internal/port49d/{snapshot.go (new),store.go,brokerd.go,runner.go}` | the directory snapshot; a runner during a cut | 10a |
| `internal/port49d/storeroles.go` | roles per store | 11 |
| `internal/port49d/storestatus.go` (new), `internal/daemon/admin/admin.go`, `cmd/port49/store.go` (new), `cmd/port49/main.go` | `port49 store status` | 12 |
| `deploy/compose/config/*.yaml`, `deploy/compose/README.md`, `deploy/compose/etcd-init.sh` | the compose example on `stores:` | 13 |
| `tests/lab/regions_test.go` (new), `tests/lab/l74_test.go` (new), `tests/lab/l74_unit_test.go` (new), `tests/lab/README.md` | the three-region harness | 14 |
| `tests/lab/results/L74-regions.md`, `tests/lab/results/L75-regions.md`, spec §15 | the runs | 15 |
| `docs/superpowers/plans/README.md` | the roadmap's record and the carries | 16 |

---

### Task 1: The spec and the design first

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§5.7 `sign_in_unlock` :2326; §12
  `port49d store-roles` :6405; §13 after decision 50, before the `---` that precedes "## 14"; §15
  after the L73 row; every old key name)
- Modify: `docs/design/2026-08-21-port49-design.md` (§12 "Store interface" :1491; §13 "Token store
  topology" and "etcd (plan 7d)" :1573; every old key name)

**Interfaces:**
- Consumes: the Rulings above.
- Produces: decision 51 (cited by every later task as "decision 51 ruling R<n>"), L74 and L75
  (open), and the docs' key names, which Task 13's gate checks.

- [ ] **Step 1: Decision 51**

Insert after decision 50's last paragraph (the one that begins "Two SHOULDs are not built"),
before the `---` that precedes "## 14":

```markdown
**51. Two stores named by function: the directory and the session; placement built in, topology
the operator's.** *Plan 11a, 2026-10-17.* Rulings R1–R10 and R13 are Ryan's (2026-10-17), R26
the team lead's under standing autonomy, and the pre-flight's amendments (R13's unleased pin, R19's
snapshot, R25, R27–R29) the team lead's rulings; the rest are the planner's, made security-first
where this document was silent. The plan
(`docs/superpowers/plans/2026-10-17-11a-directory-and-session-stores.md`) gives each ruling's
reason and cost.

- **The two stores (R1, R2, R11).** `stores.directory` and `stores.session`, each today's store
  shape (`backend: memory | etcd`, `packet_deadline`, `etcd:`). The directory holds exactly `rv/`
  (the revocation marks), `sf/` (second factors, which carry the TOTP used step),
  `meta/enrollments` (the enrollment mark), `ul/` (unlocks), `mb/` and `mk/` (directory
  membership's pin record and map-key index), `lo/` (back-channel logout records), and its own
  `meta/seal_keys` and `meta/ping`. The session store holds every other family, the directory
  snapshots (`ds/`) among them. port49 fixes the placement; no key moves a family.
- **No policy in any store (R12).** The policy is a file every host loads. A runner's judgement of
  it (`meta/judged`, `meta/judged_bundle`, `meta/bundles/`, `meta/refresh_owed`) is about its own
  session store's contexts and stays with them. Cross-region agreement is the deployment's.
- **Directory membership is split by write rate (R13).** The directory store holds its pin record
  (`mb/` there: entry id, map keys, refusal, the forget's tombstone) and the `mk/` index, with no
  lease: a pin lives until a forget or a re-pin replaces it, and a tombstone until a re-pin. The
  session store holds the per-mint freshness record (`verified_at`, groups) with a copy of the pin.
  A verification writes the directory only when the directory's pin differs (a first bind, a
  re-pin, a refusal); a read takes the pin from the process's watched copy of the directory, so one
  `port49 directory forget` reaches every region. A forgotten pin frees the principal; an absent
  one that this region's copy holds is put back from the copy, never read as unpinned; a pin to
  another entry than this region's record answers no groups, so grace serves nothing. With the
  directory cut a first bind, a refusal's record and a forget fail closed (`store_unavailable`),
  and a pinned member's refresh is served from the cached pin, said.
- **Back-channel logouts are directory records (R26).** A logout received in any region refuses,
  everywhere, every mint and refresh it names: each port49-broker loads the logout records before it
  serves, follows them, and checks a mint against its copy; each region's runner reaches a logout it
  follows in its own sessions. With the directory cut, a logout is accepted (200), applied in-region
  at once, and kept pending in the session store. The runner forwards it to the directory on the
  heal, so nothing is lost; the count is `port49_store_logouts_pending` and `port49 store status`'s
  `N logouts pending`.
- **Session-side, by the same principle (R14).** OIDC owner records, once-only records (a logout's
  `jti` among them), kept MFA proofs, attempt counts, idempotency, superseded, the indexes, blobs,
  the ledger and every `meta/` key but `enrollments`.
- **Topology is the operator's (R3, R22).** Single site: `stores.session` omitted (the session store
  is the directory store) or naming the same keyspace, whose two blocks must then agree on the
  directory's keys. Several regions: the directory etcd stretched one member per region, a session
  etcd per region. A directory of its own takes `endpoints`, `ca_file`, `prefix`, `daemon`,
  `broker`, `roles`, `call_timeout`, `bulk_timeout` and `start_timeout` alone. Memory and etcd are
  never mixed; nesting keyspaces on one cluster are refused.
- **The cache (R4, R17, R19).** Every process loads the marks from the directory before it serves,
  follows them (decision 36's feed), and answers every read of a mark from that copy: the
  authorizer as before, and now a login's revocation check and a mint's. A process cut off from the
  directory serves from its copy with no cut-off, and says how old it is: a line at each change,
  `port49_store_directory_reachable`, `port49_store_directory_confirmed_timestamp_seconds`, and
  `port49 store status`. A revocation, lift, reset or unlock made elsewhere during a cut does not
  reach the cut process until the cut heals.
- **The snapshot (R19).** In a split every process writes its directory cache to its session store
  every 60s while the cache is confirmed, sealed: a marks record (`ds/m/<proc>@<host>`) from every
  process, and a broker record of logouts and pins (`ds/b/…`) that the daemon's role cannot read.
  The daemon writes its own marks record alone. A process started while the directory does not
  answer serves the union of the marks of every record younger than `session.staleness_ceiling`
  (4h by default, and when off), never the newest alone, so no deleted or replayed record lifts a
  mark. Once the directory answers it loads it afresh, and only that load lifts the ceiling; at
  the ceiling it fails closed: port49d closes its listeners and port49-broker refuses every mint
  and sign-in `store_unavailable`. A key or cluster fault found at the heal ends the process,
  exit 1. A process with no such
  snapshot does not serve: port49d keeps its listeners closed and port49-broker serves nothing, up
  to `start_timeout` on a cold start; a port49d run after a session-store outage, which holds its
  marks, serves from them. Unlocks and second-factor resets are not snapshotted: no process
  caches them, and a password sign-in fails closed in a cut regardless.
- **Keys (R27, R28).** Every region holds one `encryption:` key set. The directory keeps its own
  `meta/seal_keys` (ids only), which every port49-broker start writes; a process whose window lacks
  its current id refuses to start, naming the directory store and the key id. Rotation is three steps: the new key as `previous` everywhere,
  then `current` everywhere, then the old retired. Two store blocks reaching one etcd cluster id at
  one prefix are refused at start.
- **A runner during a cut (R29).** A takeover in a split lists the marks from the process's copy
  and reaches every standing logout there; the put-back of `marks.json` and the forwarding of
  pending logouts each wait for the directory by themselves; every session-store duty runs.
- **Fail closed (R4, R16, R18).** Directory writes are refused when the directory does not answer:
  revocations and lifts, enrollments, unlocks, second-factor resets, init-enrollments and imports.
  A password sign-in reads and writes the directory directly and takes the used step by
  compare-and-set on the one record, so a cut region refuses it `store_unavailable` and one code
  never signs in twice across regions. No reason code is added.
- **A login's mark check across two stores (R4).** Decision 35 made a login's context write one
  atomic step with the marks it read. With the marks in another etcd that cannot hold: a split
  login reads the marks from the process's copy, carries a standing one into the context
  (CarryRevocation), and compares none in the session store's transaction. What closes the gap the
  atomic check closed: every request is denied by the process's marks whatever the context says
  (decision 35), and each region's runner applies a mark it follows to its own session store,
  tokens deleted and contexts marked (R20). A shared store keeps decision 35's atomic check.
- **Unlocks (R15).** `port49 directory unlock` writes `ul/<principal>`; a password sign-in counts
  failures under `principal:<p>@<unlock unix nanos>`, so an unlock starts every region's count at
  once. The `sign_in_unlock` record's `failures` is the answering region's count.
- **Roles (R23).** On a directory of its own the daemon reads `rv/`, `meta/ping` and
  `meta/seal_keys` alone and the broker holds the keyspace; on a session store of its own the
  daemon's grants are a shared store's but `rv/`, with `ds/m/` read and `ds/m/port49d@` written,
  and nothing of `ds/b/`. `port49d
  store-roles` prints a section per store; the directory's section is run once, against the
  directory cluster, not once per region.
- **`port49 store status` (R6, R21).** Asks the process's admin socket (`store_status`): per role,
  the backend, `<answering>/<listed> members`, reachability, and the directory's cache age;
  "shares the directory store" for a shared session store. Exit 3 when a store does not answer.
- **Kubernetes verifiers (R24).** Each region's broker lists its own region's clusters.
- **Removed (R5, R25).** The top-level `store:` key and `broker.directory.enrollment_store`, with no
  alias. Decision 47 D12's separate enrollment handle is superseded: the enrollment store is the
  directory store. No migration: pre-beta, a split starts on fresh stores.
- **Lab.** L74 (three regions: the cache, the cut, the fail-closed edges) and L75 (the TOTP used
  step and the unlock across regions). Until each closes, every claim about multi-region timing
  cites it as unmeasured.
```

- [ ] **Step 2: L74 and L75, open**

Insert after the L73 row of §15's table:

```markdown
| **L74** | port49 across three simulated regions on one host: three network namespaces joined by a bridge, `tc netem` adding 20ms each way on each region's link (40ms round trip region to region); a directory etcd of three members, one per region; a session etcd, a port49-broker and a port49d in each region; a TACACS+ client on the host. (a) A login and a command answered in each region, and their reply times beside the directory's round trip. (b) A revocation made in region 1: the time until the next command of a session in region 2 and in region 3 is denied. (c) Region 3 cut from the other regions (iptables in its namespace), and so from the directory's quorum: an open session's command, and a login with a token minted before the cut, each answered; `port49 store status` in region 3, and its exit code; `port49_store_directory_reachable` and `port49_store_directory_confirmed_timestamp_seconds`. (d) During the cut, a revocation in region 1: region 3's session is still permitted. (e) During the cut, `port49 revoke` and `port49 revoke --lift` on region 3's broker: each refused, and how long each took. (f) During the cut, port49d and port49-broker restarted in region 3: each serves from region 3's directory snapshot (a session's command permitted, a token minted and logged in), and `port49 store status` says `(snapshot)`; then, with region 3's `ds/` records deleted, port49d restarted again: its listeners closed until the heal. (g) The heal: the time until region 3's session from (d) is denied, and region 3's runner line naming the revocation. (h) With auth on, the members `port49 store status` prints: whether a non-root identity's member list and per-member status answer. (i) A lift in region 1 during a cut longer than a compaction (forced with `etcdctl compact`), and whether region 3's runner puts the mark back on the heal. | §13 decision 51 (the cache, fail closed, a process with no cache, the runner's reach, `port49 store status`) | port49 on the lab host, three simulated regions | open |
| **L75** | The TOTP used step and the unlock across three port49-broker processes on the lab host, each with a session etcd of its own and L74's directory etcd shared, and L67's OpenLDAP. (a) One person signs in with a code at broker 1; the same code, within its step, is presented at broker 2: refused. (b) The same code sent to brokers 1 and 2 at once, once per step for twenty steps: how many of each pair pass (expected one). (c) A person locked out by failures at broker 2 is unlocked at broker 1: broker 2's next sign-in is judged. (d) The attempt counts are per broker: how many failures each takes before it refuses, and the total across three (the roadmap's accepted 3×5). (e) Broker 3 cut from the directory (its link held by a proxy that stops forwarding): a password sign-in answers 503 `store_unavailable`; `port49 directory unlock` and `port49 directory reset-second-factor` are refused; how long each took. (f) Directory membership across brokers (decision 51, R13): carol's certificate mint at broker 2 pins her in the directory (the pin record's revision); `port49 directory forget` at broker 1, and broker 2's next mint pins her again (the revision moves); with broker 3 cut, a forget at broker 3 refused, carol's mint at broker 3 served from the cached pin with its line said, and bob's first mint at broker 3 refused. (g) A back-channel logout across brokers (decision 51, R26), with an in-process OIDC provider the harness runs (Keycloak's own sending, and that it does not retry a 503, are L45's): carol's ID token minted at broker 2; its session's logout token posted to broker 1; the time until broker 2 refuses that ID token (`credential_revoked`), and broker 2's runner line; with broker 3 cut, a logout posted to broker 3: answered 200, broker 3 refuses the ID token at once, `port49 store status` at broker 3 says `1 logouts pending` and exits 3, broker 1 still mints for it; after the heal, broker 3's runner forwards it and broker 1 refuses, and the time from the heal to broker 1's first refusal. These cells run on L75's host brokers, since membership needs the directory (LDAP), which the namespaces cannot reach. | §13 decision 51 (unlocks, TOTP fail-closed, membership's pin); decision 47 ruling 5 | port49 on the lab host, three brokers, OpenLDAP 2.6 | open |
```

- [ ] **Step 3: §5.7 and §12**

In §5.7, in the paragraph naming the nineteenth record (`sign_in_unlock`, :2326), after
`{"principal": ..., "sign_in_unlock": {"failures": N, "origin": ...}}`, insert: "`failures` is the
count the answering broker's session store held; with a session store per region every region's
count starts again at the unlock, which is a directory record (decision 51)."

In §12, replace the `port49d store-roles` paragraph's first two sentences (from
"**`port49d store-roles --config port49d.yaml --broker-config port49-broker.yaml`** prints the" through
"two files naming different `store.etcd.prefix` are refused.") with:

```markdown
**`port49d store-roles --config port49d.yaml --broker-config port49-broker.yaml`** prints the
`etcdctl` commands that create port49's two etcd roles and grant them, for each store's keyspace
(plan 7d; §13, decisions 35 and 51). Each flag defaults to its file under `/etc/port49/`. With one
store (`stores.session` omitted, or naming the directory's keyspace) it prints one section, the
grants below. With a directory of its own it prints two sections, each to run as that cluster's
root: the directory's, where `port49_daemon` reads `rv/` and `meta/ping` alone and `port49_broker`
holds the keyspace; and the session's, the grants below without `rv/`. Two files naming a store
at different keyspaces are refused.
```

After the `port49_broker` bullet of that paragraph, add:

```markdown
**`port49 store status [--socket PATH]`** asks a process's admin socket (port49d's by default,
`/run/port49/port49d.sock`; port49-broker answers on its own) what each store is, as that process
sees it (decision 51):

    directory  etcd    3/3 members  reachable  cache 0.4s
    session    etcd    1/1 members  reachable

A session store that is the directory store prints `session    shares the directory store`; the
memory store prints `directory  memory  in process`. Members are `<answering>/<listed>`: etcd's
member list, and each member's status read at its first client URL within `etcd.call_timeout`. The
cache is the time since the process last confirmed its copy of the directory (a directory read
answered while its marks feed ran); `cache none` before the first, and `(snapshot)` after it while
the process serves from a snapshot it started from (R19). A store that does not answer
prints `unreachable`, the reason on the next line, and the command exits 3; 0 when both answer, 1
when the socket does not.
```

- [ ] **Step 4: Design §12 and §13**

In design §12, after the store-plan table and before "**Requirement:**", insert:

```markdown
**Placement (plan 11a; policy engine spec §13, decision 51).** The records live in two stores
named by function. The **directory store** holds the revocation marks, the second factors (with
the TOTP used step), the enrollment mark, the unlocks, the back-channel logout records, and a
directory membership's pin record and mapping-key index: written rarely, by an operator, a person enrolling or a first bind, and agreed
everywhere. A membership's per-mint freshness (`verified_at`, the groups) stays in the session
store. Every process loads the marks before it serves, follows
them, and answers a read of a mark from its copy. The **session store** holds every other record
in the table. port49 fixes the placement; the topology is the operator's (§13). A login's mark
check is one atomic step with its context write only where the two stores are one; across two, a
login carries the marks of its process's copy, and every request is denied by that copy.
```

Replace §13's "**Token store topology.**" paragraph and its three-row table with:

```markdown
**Store topology (plan 11a; policy engine spec §13, decision 51).** port49 has two stores, the
directory store (`stores.directory`) and the session store (`stores.session`), and decides which
record lives in which (§12, "Placement"). Where they run is the operator's:

| Shape | `stores.directory` | `stores.session` |
|---|---|---|
| Single site | one etcd of three or five members in the site (memory: one process holds both) | omitted: the session store is the directory store |
| Several regions | one etcd stretched across the regions, one member per region (an odd count, three or five) | one etcd per region or cluster, in that region |

A region cut off from the directory keeps verifying devices from its session store and its copy of
the marks, and refuses every directory write, password sign-in included (its TOTP step is a
directory write); revocations made elsewhere reach it when the cut heals (decision 51). Size the
directory's `etcd.call_timeout` to its cross-region round trip: the session store's
`packet_deadline` does not bound it. A session store shared by several regions is possible (point
each region's `stores.session` at one etcd) and carries the latency the next paragraph describes.
Any shape runs under systemd, in containers, or on Kubernetes; none is required.
```

In the next paragraph ("**A global store does not confine cross-region latency to redemption.**"),
replace "A global store" with "A session store shared across regions".

In "**etcd (plan 7d).**", after its first sentence ("Three or five members in the region the
devices are in, with:"), add: "With a directory store of its own, the directory etcd is stretched
across the regions, one member per region, and each region's session etcd is three or five members
in that region; `port49d store-roles` prints each cluster's roles."

In "**Backups.**", after its first sentence, add: "With a directory store of its own, back up both
clusters: a restore of the directory etcd is the marks' and enrollments' restore (steps 4 to 6 below,
and `port49 directory import`), and a restore of a session etcd is the tokens' (steps 1 to 3 and 7);
each region's runner puts back the marks its `marks.json` holds that the directory lacks."

- [ ] **Step 5: The key names**

In both files, rename every config key the plan removes, by this table, in the living text: every
section but spec §13's decisions 1 to 50 and §15's closed rows. Those are records and keep their
text (Global Constraints). Where a key could belong to either store, write the session store's
name and, the first time in a section, add "(or `stores.directory.…` when `stores.session` is
omitted)".

Never rename the reason code `enrollment_store_lost` (§5.7's closed vocabulary) or the metric
`port49_directory_enrollment_store_ok`: neither is a config key.

| Old | New |
|---|---|
| `store:`, `store.backend` | `stores:`; `stores.directory.backend` / `stores.session.backend` |
| `store.packet_deadline` | `stores.session.packet_deadline` |
| `store.etcd.health…`, `store.etcd.context_cache…`, `store.etcd.hold_ttl`, `store.etcd.sweep_interval`, `store.etcd.lease_grace`, `store.etcd.breaker…`, `store.etcd.max_in_flight…` | `stores.session.etcd.…` |
| `store.etcd.endpoints`, `.ca_file`, `.prefix`, `.daemon`, `.broker`, `.roles`, `.call_timeout`, `.bulk_timeout`, `.start_timeout` | `stores.session.etcd.…` where the text is about the session store's traffic; `stores.directory.etcd.…` where it is about the marks or enrollments |
| `broker.directory.enrollment_store` (and `…enrollment_store.etcd…`) | `stores.directory` |

Leave decision 47's D12 as written, and append to it, after its last sentence:

```markdown
*(Superseded by decision 51, R5: `broker.directory.enrollment_store` is removed; the enrollment
store is the directory store, `stores.directory`.)*
```

Append to decision 51, after its last bullet:

```markdown
Decisions before this one name the store keys as they were. `store.…` is now `stores.session.…`,
or `stores.directory.…` for the marks and the enrollments, by the plan's key table (Task 1, Step 5).
```

Then check. `OLDKEYS` is the pattern Tasks 2 and 13 use as well: an old key, anchored so that
`enrollment_store_lost`, `port49_directory_enrollment_store_ok`, `stores.…` and a message ending
`store:\n%s` never match.

```bash
export OLDKEYS='(^|[^a-z_.])store\.(etcd|backend|packet_deadline)([^a-z_]|$)|(^|[^a-z_])enrollment_store([^a-z_]|$)|^[[:space:]]*store:[[:space:]]*$|(^|"|\\n)store:(\\n|[[:space:]]*$)'
python3 - "$OLDKEYS" <<'EOF'
import re, sys
pat = re.compile(sys.argv[1].replace("[[:space:]]", r"\s"))
for path in ["docs/design/2026-08-21-port49-design.md", "docs/design/2026-08-23-policy-engine-spec.md"]:
    record = False
    for n, line in enumerate(open(path), 1):
        if path.endswith("spec.md"):
            # §13's decisions before 51 and §15's closed rows are records: they keep their text.
            d = re.match(r"^\*\*(\d+)\. ", line)
            if d:
                record = int(d.group(1)) < 51
            elif line.startswith("## "):
                record = False
            if line.startswith("- **Removed (R5, R25).**"):
                continue
            if line.startswith("| **L") and "| closed" in line:
                continue
        if not record and pat.search(line):
            print(f"{path}:{n}: {line.rstrip()}")
EOF
```

Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
git commit -m "docs: decision 51, the directory and session stores, and L74 and L75 opened

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 2: `stores:` in the config; `store:` and `enrollment_store` removed

**Files:**
- Create: `internal/config/stores.go`
- Modify: `internal/config/config.go` (`fileConfig.Store` :538; `Config.Store` :622; `load`'s `checkStore` call :1012;
  `brokerRefusals` :1487; the `enrollment_store` refusal :1396–1404; `checkStoreShape` :2029;
  `checkStore` :2189; `StoreBlocks` :2314, moved to `stores.go` as `StoresBlocks`)
- Modify: `internal/config/directory.go` (remove `enrollmentStoreYAML`, `enrollmentEtcdYAML`,
  `directoryYAML.EnrollmentStore`, `checkEnrollmentStore`, `EnrollmentEtcdOf`; rewrite
  `resolveEnrollmentStore`)
- Modify: `internal/directory/config.go:61-78` (`EnrollmentStore` loses `Etcd`; `EnrollmentEtcd` removed)
- Modify: `internal/port49d/*.go` (every `cfg.Store.` and `r.cfg.Store.`), `internal/port49d/signin.go`
  (`wireSignIn`: no enrollment etcd of its own; `openEnrollmentEtcd` and `closingEnrollments` removed),
  `internal/port49d/storeroles.go` (reads `StoresBlocks`), `internal/port49d/store.go` and
  `internal/port49d/brokerd.go` (a split refused until Tasks 9 and 10)
- Modify: `deploy/compose/config/port49d.yaml`, `deploy/compose/config/port49-broker.yaml`
- Modify (fixtures): every file `git grep -lnE "$OLDKEYS" -- '*.go' '*.yaml'`
  lists, with `OLDKEYS` as Task 1 Step 5 exports it. Today that is `internal/config/{store_test,broker_role_test,directory_test,identity_test}.go`,
  `internal/port49d/{brokerd_test,store_e2e_test,storeroles_test,signin_test,signin_late_test,signin_recheck_test}.go`,
  `cmd/port49/{signin_test,signin_login_linux_test}.go`,
  `tests/lab/{compose_test,store_test,split_unit_test,l67_test,directory_e2e_unit_test}.go`,
  `tests/lab/l62/stack_unit_test.go`, `tests/compose/smoke_test.go`, and `tests/lab/harness_test.go`
  (the split's store blocks, `storeLab`).
- Test: `internal/config/stores_test.go` (new), `internal/config/store_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `type config.StoresConfig struct { Directory, Session StoreConfig; Shared bool }` and
    `func (StoresConfig) SessionPath() string` ("stores.session", or "stores.directory" when
    `stores.session` was omitted).
  - `Config.Stores StoresConfig` in place of `Config.Store`; `cfg.Stores.Session` is what every
    `cfg.Store` read before.
  - `func config.StoresBlocks(raw []byte) (StoresConfig, error)` in place of `StoreBlocks`.
  - `checkStoreShape(at string, s storeYAML, session bool)` and
    `checkStore(at string, s storeYAML, session bool, role Role, hasBroker, hasPolicy, hasAdminSocket bool)`:
    every message names the block it read through `at`.
  - `directory.EnrollmentStore{Backend, File string}`: the directory store's backend, and on memory
    the sealed file.

- [ ] **Step 1: Write the failing tests**

Create `internal/config/stores_test.go`:

```go
package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// storesDoc is a file holding stores: with body under it.
func storesDoc(body string) []byte { return []byte("stores:\n" + body) }

// etcdBlock is one store's block at indent: etcd at endpoint under prefix,
// with dir's files (storeFiles) and the daemon's identity, and each of
// extra as a line under etcd:.
func etcdBlock(dir, indent, endpoint, prefix string, extra ...string) string {
	s := indent + "backend: etcd\n" + indent + "etcd:\n" +
		indent + "  endpoints: [" + endpoint + "]\n" +
		indent + "  ca_file: " + filepath.Join(dir, "ca.pem") + "\n" +
		indent + "  prefix: " + prefix + "\n" +
		indent + "  daemon: {cert_file: " + filepath.Join(dir, "d.pem") + ", key_file: " +
		filepath.Join(dir, "d-key.pem") + "}\n"
	for _, e := range extra {
		s += indent + "  " + e + "\n"
	}
	return s
}

func TestNoStoresIsOneMemoryStore(t *testing.T) {
	s, err := StoresBlocks([]byte("admin_socket: /run/port49/port49d.sock\n"))
	if err != nil || !s.Shared || s.Directory.Backend != BackendMemory || s.Session.Backend != BackendMemory ||
		s.SessionPath() != "stores.directory" {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestAnOmittedSessionSharesTheDirectory(t *testing.T) {
	dir := storeFiles(t)
	s, err := StoresBlocks(storesDoc("  directory:\n" +
		etcdBlock(dir, "    ", "https://etcd-0:2379", "/port49/", "hold_ttl: 20s")))
	if err != nil || !s.Shared || s.Session.Etcd == nil || s.Session.Etcd.HoldTTL != 20*time.Second ||
		s.Directory.Etcd.Prefix != "/port49/" || s.SessionPath() != "stores.directory" {
		t.Fatalf("%+v %v", s, err)
	}
}

// A directory of its own may wait on a far region: its call_timeout is not
// bound by the session store's packet_deadline (ruling R22).
func TestTwoStoresResolveApart(t *testing.T) {
	dir := storeFiles(t)
	s, err := StoresBlocks(storesDoc(
		"  directory:\n" + etcdBlock(dir, "    ", "https://dir-0:2379", "/port49/", "call_timeout: 3s") +
			"  session:\n" + etcdBlock(dir, "    ", "https://sess-0:2379", "/port49/", "hold_ttl: 20s")))
	if err != nil || s.Shared || s.Directory.Etcd.Endpoints[0] != "https://dir-0:2379" ||
		s.Directory.Etcd.CallTimeout != 3*time.Second || s.Session.Etcd.HoldTTL != 20*time.Second ||
		s.SessionPath() != "stores.session" {
		t.Fatalf("%+v %v", s, err)
	}
}

// Review Focus 4: two blocks naming one keyspace are one store, however the
// prefix's trailing slash and the host's case are written.
func TestTheSameKeyspaceTwiceIsOneStore(t *testing.T) {
	dir := storeFiles(t)
	s, err := StoresBlocks(storesDoc(
		"  directory:\n" + etcdBlock(dir, "    ", "https://ETCD-0:2379", "/port49") +
			"  session:\n" + etcdBlock(dir, "    ", "https://etcd-0:2379", "/port49/", "hold_ttl: 20s")))
	if err != nil || !s.Shared || s.Directory.Etcd.HoldTTL != 20*time.Second || s.SessionPath() != "stores.session" {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestOneStoreNamedTwiceMustAgree(t *testing.T) {
	dir := storeFiles(t)
	_, err := StoresBlocks(storesDoc(
		"  directory:\n" + etcdBlock(dir, "    ", "https://etcd-0:2379", "/port49/", "call_timeout: 1s") +
			"  session:\n" + etcdBlock(dir, "    ", "https://etcd-0:2379", "/port49/")))
	if err == nil || !strings.Contains(err.Error(), "name one store") ||
		!strings.Contains(err.Error(), "set etcd.call_timeout differently") {
		t.Fatalf("%v", err)
	}
}

func TestNestedKeyspacesOnOneClusterAreRefused(t *testing.T) {
	dir := storeFiles(t)
	_, err := StoresBlocks(storesDoc(
		"  directory:\n" + etcdBlock(dir, "    ", "https://etcd-0:2379", "/port49/") +
			"  session:\n" + etcdBlock(dir, "    ", "https://etcd-0:2379", "/port49/session/")))
	if err == nil || !strings.Contains(err.Error(), "would reach both") {
		t.Fatalf("%v", err)
	}
}

func TestPrefixesApartOnOneClusterAreTwoStores(t *testing.T) {
	dir := storeFiles(t)
	s, err := StoresBlocks(storesDoc(
		"  directory:\n" + etcdBlock(dir, "    ", "https://etcd-0:2379", "/port49-directory/") +
			"  session:\n" + etcdBlock(dir, "    ", "https://etcd-0:2379", "/port49/")))
	if err != nil || s.Shared {
		t.Fatalf("%+v %v", s, err)
	}
}

// The pre-flight's minor 10: a session block alone names what is missing.
func TestASessionStoreAloneNeedsADirectory(t *testing.T) {
	dir := storeFiles(t)
	_, err := StoresBlocks(storesDoc("  session:\n" + etcdBlock(dir, "    ", "https://etcd-0:2379", "/port49/")))
	if err == nil || !strings.Contains(err.Error(), "stores.directory is required") {
		t.Fatalf("%v", err)
	}
}

func TestMemoryAndEtcdAreNeverMixed(t *testing.T) {
	dir := storeFiles(t)
	_, err := StoresBlocks(storesDoc("  directory: {backend: memory}\n  session:\n" +
		etcdBlock(dir, "    ", "https://etcd-0:2379", "/port49/")))
	if err == nil || !strings.Contains(err.Error(), "both memory") {
		t.Fatalf("%v", err)
	}
}

func TestADirectoryOfItsOwnRefusesTheSessionStoresKeys(t *testing.T) {
	dir := storeFiles(t)
	for _, k := range []string{"hold_ttl: 20s", "health: {interval: 2s}", "context_cache: {ttl: 2s}",
		"sweep_interval: 5m", "lease_grace: 2m", "breaker: {failures: 3}", "max_in_flight: {token: 8}"} {
		key := strings.SplitN(k, ":", 2)[0]
		_, err := StoresBlocks(storesDoc(
			"  directory:\n" + etcdBlock(dir, "    ", "https://dir-0:2379", "/port49/", k) +
				"  session:\n" + etcdBlock(dir, "    ", "https://sess-0:2379", "/port49/")))
		if err == nil || !strings.Contains(err.Error(), "stores.directory.etcd."+key+": a session store's key") {
			t.Errorf("%s: %v", key, err)
		}
	}
	_, err := StoresBlocks(storesDoc(
		"  directory:\n    packet_deadline: 1s\n" + etcdBlock(dir, "    ", "https://dir-0:2379", "/port49/") +
			"  session:\n" + etcdBlock(dir, "    ", "https://sess-0:2379", "/port49/")))
	if err == nil || !strings.Contains(err.Error(), "stores.directory.packet_deadline: a session store's key") {
		t.Errorf("packet_deadline: %v", err)
	}
}

// R5: the old blocks are unknown keys, refused as any is, with no alias.
func TestTheOldBlocksAreUnknownKeys(t *testing.T) {
	if _, err := StoresBlocks([]byte("store:\n  backend: memory\n")); err == nil ||
		!strings.Contains(err.Error(), "unknown field") {
		t.Errorf("store: %v", err)
	}
	if _, err := StoresBlocks([]byte("broker:\n  directory:\n    enrollment_store: {backend: memory}\n")); err == nil ||
		!strings.Contains(err.Error(), "unknown field") {
		t.Errorf("enrollment_store: %v", err)
	}
}

func TestStoreMessagesNameTheirBlock(t *testing.T) {
	dir := storeFiles(t)
	_, err := StoresBlocks(storesDoc(
		"  directory:\n" + etcdBlock(dir, "    ", "https://dir-0:2379", "/port49/") +
			"  session:\n" + etcdBlock(dir, "    ", "https://sess-0:2379", "/port49/", "call_timeout: 9s")))
	if err == nil || !strings.Contains(err.Error(), "stores.session.etcd.call_timeout 9s") {
		t.Fatalf("%v", err)
	}
}
```

In `internal/config/store_test.go`, update the calls to the new signatures, and each expected message
to the block the call names:
- `checkStoreShape(y)` becomes `checkStoreShape("stores.directory", y, true)`.
- `checkStore(y, role, …)` becomes `checkStore("stores.directory", y, true, role, …)`.
- In each `want`, a key that began `store.` now begins `stores.directory.`.
- `StoreBlocks` becomes `StoresBlocks`, and `s.Etcd` becomes `s.Directory.Etcd`.
- `storeDoc` writes `stores:\n  directory:\n    backend: etcd\n    etcd:\n` with every line under it
  indented two spaces deeper.
- `TestAStoreRefusalIsAConfigError` reads `StoresBlocks([]byte("stores: {directory: {backend: redis}}\n"))`
  and expects the prefix `config: stores.directory.backend "redis"`.
- `TestHealthAndCacheDecodeFromYAML` reads `c.Stores.Session.Etcd`.

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/config/ -run 'Stores|Store|OneStore|Keyspace|Memory|OldBlocks|Messages' -count=1`
Expected: FAIL to compile (`undefined: StoresBlocks`).

- [ ] **Step 3: Write `internal/config/stores.go`**

```go
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"
)

// storesYAML mirrors the stores block (plan 11a; spec §13 decision 51).
type storesYAML struct {
	Directory *storeYAML `yaml:"directory"`
	Session   *storeYAML `yaml:"session"`
}

// StoresConfig is stores:, resolved (plan 11a; spec §13 decision 51).
// Directory holds the revocation marks, the second factors, the enrollment
// mark, the unlocks, the logout records and membership's pins (R11);
// Session holds every other record. Shared is a single
// site: stores.session omitted, or naming the directory's keyspace, so one
// store holds both and Session equals Directory.
type StoresConfig struct {
	Directory StoreConfig
	Session   StoreConfig
	Shared    bool
	// sessionNamed is whether stores.session was written: SessionPath's.
	sessionNamed bool
}

// SessionPath is the config path the session store's keys are written
// under: stores.session, or stores.directory when stores.session was
// omitted. A line naming a session-store key builds it from this.
func (s StoresConfig) SessionPath() string {
	if !s.sessionNamed {
		return "stores.directory"
	}
	return "stores.session"
}

// storeCheck resolves one store block: at is its path, and session is
// whether it serves sessions, which binds packet_deadline and
// health.interval to its call_timeout (ruling R22).
type storeCheck func(at string, s storeYAML, session bool) (StoreConfig, error)

// checkStores resolves stores: (ruling R22): the directory store, memory
// when absent; the session store, the directory's when absent or naming
// its keyspace. check resolves each block.
func checkStores(y storesYAML, check storeCheck) (StoresConfig, error) {
	var dirY storeYAML
	if y.Directory != nil {
		dirY = *y.Directory
	}
	if y.Session == nil {
		d, err := check("stores.directory", dirY, true)
		if err != nil {
			return StoresConfig{}, err
		}
		return StoresConfig{Directory: d, Session: d, Shared: true}, nil
	}
	if y.Directory == nil {
		return StoresConfig{}, errors.New("stores.directory is required: it holds the marks, the enrollments and " +
			"the logouts; for a single site, name the one store under stores.directory and omit stores.session")
	}
	only := sessionOnly(dirY) // read before check fills in the defaults
	sess, err := check("stores.session", *y.Session, true)
	if err != nil {
		return StoresConfig{}, err
	}
	dir, err := check("stores.directory", dirY, false)
	if err != nil {
		return StoresConfig{}, err
	}
	switch {
	case dir.Backend != sess.Backend:
		return StoresConfig{}, fmt.Errorf("stores.directory.backend %s and stores.session.backend %s: the two "+
			"stores are both memory (one process holds everything) or both etcd (port49-broker beside port49d)",
			dir.Backend, sess.Backend)
	case dir.Backend == BackendMemory:
		return StoresConfig{Directory: sess, Session: sess, Shared: true, sessionNamed: true}, nil
	}
	same, overlap := relate(dir.Etcd, sess.Etcd)
	switch {
	case same && only != "":
		return StoresConfig{}, fmt.Errorf("stores.directory.%s: stores.directory and stores.session name one "+
			"store (the same endpoints and prefix), and %s is the session store's key: set it under "+
			"stores.session alone", only, only)
	case same:
		if k := disagree(dir.Etcd, sess.Etcd); k != "" {
			return StoresConfig{}, fmt.Errorf("stores.directory and stores.session name one store (the same "+
				"endpoints and prefix) and set %s differently: omit stores.session for a single site, or give "+
				"both the same %s", k, k)
		}
		return StoresConfig{Directory: sess, Session: sess, Shared: true, sessionNamed: true}, nil
	case overlap:
		return StoresConfig{}, fmt.Errorf("stores.directory (prefix %s) and stores.session (prefix %s) share an "+
			"endpoint and one prefix holds the other: the broker's etcd role covers every key under its prefix, "+
			"so it would reach both; give each a prefix of its own, or name one store", dir.Etcd.Prefix,
			sess.Etcd.Prefix)
	case only != "":
		return StoresConfig{}, fmt.Errorf("stores.directory.%s: a session store's key; stores.session names a "+
			"store of its own, so set it under stores.session", only)
	}
	return StoresConfig{Directory: dir, Session: sess, sessionNamed: true}, nil
}

// sessionOnly names the first key y sets that a directory store of its
// own does not take (ruling R22), "" when none: what the session store's
// traffic, its hold and its go-dark need.
func sessionOnly(y storeYAML) string {
	switch {
	case y.PacketDeadline != 0:
		return "packet_deadline"
	case y.Etcd == nil:
		return ""
	case y.Etcd.HealthSet != nil:
		return "etcd.health"
	case y.Etcd.ContextCacheSet != nil:
		return "etcd.context_cache"
	case y.Etcd.HoldTTL != 0:
		return "etcd.hold_ttl"
	case y.Etcd.SweepInterval != 0:
		return "etcd.sweep_interval"
	case y.Etcd.LeaseGrace != 0:
		return "etcd.lease_grace"
	case y.Etcd.Breaker != (EtcdBreaker{}):
		return "etcd.breaker"
	case y.Etcd.MaxInFlight != (EtcdInFlight{}):
		return "etcd.max_in_flight"
	}
	return ""
}

// relate says whether two resolved etcd blocks name one keyspace (same:
// the same prefix, compared with one trailing "/", and the same endpoint
// hosts, compared case-insensitively) or reach into each other (overlap: a
// host in common and one prefix under the other).
func relate(a, b *EtcdConfig) (same, overlap bool) {
	ha, hb := hostsOf(a.Endpoints), hostsOf(b.Endpoints)
	common := false
	for h := range ha {
		common = common || hb[h]
	}
	pa, pb := slashed(a.Prefix), slashed(b.Prefix)
	nested := strings.HasPrefix(pa, pb) || strings.HasPrefix(pb, pa)
	return common && pa == pb && maps.Equal(ha, hb), common && nested
}

func hostsOf(endpoints []string) map[string]bool {
	out := map[string]bool{}
	for _, ep := range endpoints {
		if u, err := url.Parse(ep); err == nil && u.Host != "" {
			out[strings.ToLower(u.Host)] = true
		}
	}
	return out
}

func slashed(p string) string {
	if strings.HasSuffix(p, "/") {
		return p
	}
	return p + "/"
}

// disagree names the first key, of those a directory takes, that two
// blocks naming one store set differently; "" when none does.
func disagree(d, s *EtcdConfig) string {
	brokerOf := func(e *EtcdConfig) EtcdIdentity {
		if e.Broker == nil {
			return EtcdIdentity{}
		}
		return *e.Broker
	}
	switch {
	case d.CAFile != s.CAFile:
		return "etcd.ca_file"
	case d.Daemon != s.Daemon:
		return "etcd.daemon"
	case brokerOf(d) != brokerOf(s):
		return "etcd.broker"
	case d.Roles != s.Roles:
		return "etcd.roles"
	case d.CallTimeout != s.CallTimeout:
		return "etcd.call_timeout"
	case d.BulkTimeout != s.BulkTimeout:
		return "etcd.bulk_timeout"
	case d.StartTimeout != s.StartTimeout:
		return "etcd.start_timeout"
	}
	return ""
}

// sessionBackend is the session store's backend as written: the session
// block's, else the directory block's, else memory.
func (y storesYAML) sessionBackend() string {
	switch {
	case y.Session != nil && y.Session.Backend != "":
		return y.Session.Backend
	case y.Directory != nil && y.Directory.Backend != "":
		return y.Directory.Backend
	}
	return BackendMemory
}

// StoresBlocks is stores: from either file's bytes, port49d.yaml's or
// port49-broker.yaml's, decoded as strictly as Load (the stale seed keys
// first, as Load refuses them) and checked for its shape alone: either
// identity may be named or absent (plan 7e, pre-flight I8). It is for
// `port49d store-roles`, which reads nothing else.
func StoresBlocks(raw []byte) (StoresConfig, error) {
	if err := staleSeedKeys(raw); err != nil {
		return StoresConfig{}, err
	}
	var f fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return StoresConfig{}, fmt.Errorf("config: %w; check the key spelling against the port49d.yaml schema",
			decodeFault(err))
	}
	s, err := checkStores(f.Stores, checkStoreShape)
	if err != nil {
		return StoresConfig{}, fmt.Errorf("config: %w", err)
	}
	return s, nil
}
```

- [ ] **Step 4: Rewire `config.go` and `directory.go`**

In `internal/config/config.go`:
1. In `fileConfig`, replace `Store storeYAML \`yaml:"store"\`` with
   `Stores storesYAML \`yaml:"stores"\``.
2. In `Config`, replace the `Store StoreConfig` field and its comment with:
   ```go
   	// Stores is where records live (plan 11a; spec §13 decision 51): the
   	// directory store and the session store, one store when Shared.
   	Stores StoresConfig
   ```
3. Give `checkStoreShape` the signature `checkStoreShape(at string, s storeYAML, session bool) (StoreConfig, error)`.
   Build every message from `at`: each literal that begins a key with `store.` becomes `at + "."` and
   the rest. For example, `"store.etcd.endpoints is empty"` becomes `at + ".etcd.endpoints is empty"`,
   and the bounds table's names become `at + ".etcd.call_timeout"` and so on. Run the final check
   `PacketDeadline < e.CallTimeout` only when `session` is true.
4. Give `checkStore` the signature `checkStore(at string, s storeYAML, session bool, role Role, hasBroker, hasPolicy, hasAdminSocket bool)`.
   It calls `checkStoreShape(at, s, session)`, builds every message from `at` as in item 3, and runs
   the daemon's `e.Health.Interval < e.CallTimeout` check only when `session` is true.
5. In `Load`, replace the `checkStore` call and the `resolveEnrollmentStore` block with:
   ```go
   	if c.Stores, err = checkStores(f.Stores, func(at string, s storeYAML, session bool) (StoreConfig, error) {
   		return checkStore(at, s, session, role, f.Broker != nil, f.Policy != nil, f.AdminSocket != "")
   	}); err != nil {
   		return Config{}, fmt.Errorf("config: %w", err)
   	}
   	if c.Broker != nil {
   		resolveEnrollmentStore(c.Broker, c.Stores.Directory)
   	}
   ```
   In the lab seed check that follows it, `c.Store.Backend` becomes `c.Stores.Session.Backend`.
   In the `policy.file` branch above it, `or(f.Store.Backend, BackendMemory)` becomes
   `f.Stores.sessionBackend()`.
6. In `brokerRefusals`, replace the `store.etcd.daemon` row with two rows:
   ```go
   		{"stores.directory.etcd.daemon", f.Stores.Directory != nil && f.Stores.Directory.Etcd != nil &&
   			(f.Stores.Directory.Etcd.Daemon != EtcdIdentity{}), "the daemon's etcd identity is port49d's alone"},
   		{"stores.session.etcd.daemon", f.Stores.Session != nil && f.Stores.Session.Etcd != nil &&
   			(f.Stores.Session.Etcd.Daemon != EtcdIdentity{}), "the daemon's etcd identity is port49d's alone"},
   ```
7. Delete the `case id.PasswordSignIn == nil && b.DirectorySet != nil && b.DirectorySet.EnrollmentStore != nil:`
   refusal (:1402–1404). The key it guarded is gone.
8. Delete `StoreBlocks`. `StoresBlocks` replaces it.
9. Elsewhere in the file, every `c.Store` read becomes `c.Stores.Session`.

In `internal/config/directory.go`:
1. Delete `enrollmentStoreYAML`, `enrollmentEtcdYAML`, the `EnrollmentStore` field of `directoryYAML`,
   the `if es := y.EnrollmentStore` block in `checkDirectory`, `checkEnrollmentStore` and
   `EnrollmentEtcdOf`.
2. Replace `resolveEnrollmentStore` with:
   ```go
   // resolveEnrollmentStore puts a directory_password verifier's enrollments
   // in the directory store (plan 9e, D12; plan 11a, R5): its backend, and on
   // memory the sealed file in the broker's state directory (D7). It does
   // nothing without a directory_password verifier.
   func resolveEnrollmentStore(b *BrokerConfig, d StoreConfig) {
   	if b.Directory == nil || b.Identity == nil || b.Identity.PasswordSignIn == nil {
   		return
   	}
   	es := &b.Directory.EnrollmentStore
   	es.Backend = d.Backend
   	if es.Backend == BackendMemory {
   		es.File = filepath.Join(BrokerStateDir(b), "enrollments.json")
   	}
   }
   ```
3. In `config.go`, the two path labels that named the old key (`others` in the broker's check,
   :1783, and `namedPath` in the certificate-status check, :1870) read
   `"stores.directory's enrollment file"` (the pre-flight's minor 18).
4. In `internal/config/compose_identity_test.go` (:48), `f.Rest["store"]` becomes
   `f.Rest["stores"]`, and the assertion walks `stores.directory`: the identity block must sit under
   neither (the pre-flight's minor 17; the old key would make the check vacuous).
5. Drop any import (`slices`, `url`) that is now unused; `go vet` names them.

In `internal/directory/config.go`, replace `EnrollmentStore` and delete `EnrollmentEtcd`:

```go
// EnrollmentStore is where a directory_password verifier keeps its
// enrollments (plan 9e, D12; plan 11a): the directory store, Backend
// "memory" (the sealed file in the broker's state dir) or "etcd".
type EnrollmentStore struct {
	Backend string
	File    string // memory: <BrokerStateDir>/enrollments.json
}
```

- [ ] **Step 5: Follow the rename through port49d**

1. In `internal/port49d`, replace each read of the old field with the session store's:
   ```bash
   grep -rl 'cfg\.Store\.' internal/port49d cmd | xargs perl -pi -e 's/\b(r\.)?cfg\.Store\./$1cfg.Stores.Session./g'
   ```
   Then `go vet ./internal/port49d/ ./cmd/...` names any `cfg.Store` the pattern missed. Fix those by
   hand. A test that builds a `config.Config` by hand for an etcd store, and so now sets
   `cfg.Stores.Session`, also sets `cfg.Stores.Directory` to the same value and `cfg.Stores.Shared = true`,
   as `Load` resolves a single site (for example the "the global etcd" case of
   `TestAnEnrollmentEtcdThatDoesNotAnswerNeverStopsTheStart`, whose handle is now the directory's).
2. Where a port49d line names a session-store key, build it from
   `cfg.Stores.SessionPath() + ".etcd.…"`, so a single site's line names `stores.directory`.
   The guard's lines name the store too (the pre-flight's minor 19): `guard.Config` gains
   `Store string`, the noun each line leads with after the process (`"store"` when empty), and
   `HoldTTLKey string`, the key its "closes its listeners if the store is gone for …" names
   (guard.go:430, today the literal `store.etcd.hold_ttl`). `guardConfig` (store.go:371) takes the
   block's path after `component` (`cfg.Stores.SessionPath()` at each caller) and sets
   `HoldTTLKey: at + ".etcd.hold_ttl"`; the enrollment guard in
   `wireSignIn` sets `Store: "directory store"` when `!cfg.Stores.Shared`, so its circuit line at
   3am reads as the directory's, not the session store's. Find
   them with `grep -rn '"store\.etcd\.\|store\.etcd\.[a-z_]*' internal/port49d/*.go | grep -v _test`
   (for example `store.etcd.context_cache.ttl is not set` and `store.etcd.health`).
3. In `internal/port49d/signin.go`'s `wireSignIn`:
   - Delete the `case es.Etcd != nil:` branch, `openEnrollmentEtcd` and `closingEnrollments`.
   - The shared case reads `case es.Backend == config.BackendEtcd && shared != nil:`, and its `where`
     is `"stores.directory etcd " + strings.Join(cfg.Stores.Directory.Etcd.Endpoints, ", ")`.
   - Its guard config uses `cfg.Stores.Directory.Etcd` in place of `cfg.Store.Etcd`.
4. In `internal/port49d/storeroles.go`:
   - `storeBlocksOf` returns `config.StoresBlocks(raw)`, and every `dsc.Etcd` / `bsc.Etcd` becomes
     `.Directory.Etcd`.
   - Delete `enrollmentEtcdOf` and the enrollment section, which depended on the removed key.
   - A file whose stores are not `Shared` is refused with
     `port49d store-roles: stores.session names a store of its own; this build prints one store's roles`
     (Task 11 replaces this).
5. The split is refused until Tasks 9 and 10 open the directory store. In `openStores`
   (`internal/port49d/store.go`), at the top of its etcd branch, and in `openBroker`
   (`internal/port49d/brokerd.go`), as their first statements:
   ```go
   	if !cfg.Stores.Shared {
   		return stores{}, &storeFault{errors.New("stores.session names a store of its own, and this build " +
   			"serves one store: omit stores.session")}
   	}
   ```
   (`brokerStores{}` in `openBroker`).

- [ ] **Step 6: The fixtures and the compose example**

Rewrite every store block the grep in **Files** lists as a `stores.directory` block. Every line of
the old block moves two spaces deeper under `directory:`:

```yaml
stores:
  directory:
    backend: etcd
    packet_deadline: 1s
    etcd:
      endpoints: [...]
```

1. A fixture that set `broker.directory.enrollment_store`:
   - If it tested the key itself (its refusals, a memory store beside etcd, an endpoint shared with
     `store.etcd`), delete the test: R5 removes the key, and `TestTheOldBlocksAreUnknownKeys` pins
     the refusal.
   - If it tested an enrollment store on an etcd of its own (`openEnrollmentEtcd` in
     `internal/port49d/signin*_test.go`), delete the test. Task 9's
     `TestPasswordSignInUsesTheDirectoryStore` replaces it.
2. Helpers that edit a written config re-indent by the new depth:
   - `addUnderEtcd` in `internal/port49d/store_e2e_test.go` indents each line it is given two more
     spaces, so its callers stay as written. It inserts under the **last** `    etcd:\n` in the file
     (`strings.LastIndex`): in a two-store fixture that is the session store's, which Task 9's
     `withDirectory` writes after the directory's.
   - `brokerVia`'s `extra` lines are indented six spaces.
3. `deploy/compose/config/port49d.yaml` and `port49-broker.yaml` move their `store:` block under
   `stores:\n  directory:` the same way.

Then:

Run (`OLDKEYS` as Task 1 Step 5 exports it): `git grep -nE "$OLDKEYS" -- '*.go' '*.yaml' ':!docs'`
Expected: no output. `enrollment_store_lost`, the `port49_directory_enrollment_store_ok` metric and
messages such as `"…a flapping store:\n%s"` do not match, and are never renamed.

- [ ] **Step 7: Run the tests**

Run: `go build ./... && go vet ./... && go test ./internal/config/ ./internal/directory/ ./internal/port49d/ ./cmd/... -count=1`
Expected: PASS. A test that fails on a message is updated to the new path, and only that. A test that
fails for any other reason is a fixture the sweep missed.

Run: `go test -tags lab -run 'Unit' ./tests/lab/... -count=1 && go vet -tags lab ./tests/lab/...`
Expected: PASS (the lab's unit tests and its fixtures compile).

- [ ] **Step 8: Commit**

```bash
git add -A internal/config internal/directory internal/port49d cmd tests deploy/compose/config
git commit -m "feat!: stores: replaces store: and broker.directory.enrollment_store

The directory and session stores (decision 51). stores.session omitted is a
single site. The old keys are refused as unknown, with no alias (pre-beta).

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 3: A mark's origin, the directory cache's freshness, and a feed that loads first

**Files:**
- Modify: `internal/store/marks.go` (`Marks` :24, `NewMarks` :39, `Set` :46, `Put` :189, `All` :256, `FollowMarks` :336)
- Create: `internal/store/fresh.go`
- Test: `internal/store/marks_test.go`, `internal/store/fresh_test.go` (new)

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `func (m *Marks) Get(kind, key string) (Revocation, bool)`: the mark in force, `Origin`
    included.
  - `All` now carries each mark's `Origin`.
  - `FollowMarks` with `from == 0` loads before it watches, retrying every second.
  - `type store.Freshness`, `func store.NewFreshness(now func() time.Time) *Freshness`,
    `(*Freshness).Tell(onConfirm func(time.Time), onReach func(bool))` (a run's metrics, told the
    state at once), `(*Freshness).FeedUp(bool)`, `(*Freshness).Checked(err error) Transition`,
    `(*Freshness).Age() (time.Duration, bool)`, `(*Freshness).Reachable() (bool, string)`.
  - `type store.Transition int`, with the constants `Steady`, `Stopped` and `Resumed`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/store/marks_test.go`:

```go
// Get answers the mark in force with its origin, as the store holds it:
// the router's GetRevocation reads it (plan 11a).
func TestMarksGetCarriesTheOrigin(t *testing.T) {
	m := NewMarks()
	at := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	m.Set(Revocation{Kind: RevocationCert, Key: "CN=CA|1f", At: at, Origin: "crl corp"}, true)
	got, ok := m.Get(RevocationCert, "CN=CA|1f")
	if !ok || !got.At.Equal(at) || got.Origin != "crl corp" {
		t.Fatalf("%+v %v", got, ok)
	}
	if all := m.All(); len(all) != 1 || all[0].Origin != "crl corp" {
		t.Fatalf("All: %+v", all)
	}
	m.Set(Revocation{Kind: RevocationCert, Key: "CN=CA|1f"}, false)
	if _, ok := m.Get(RevocationCert, "CN=CA|1f"); ok {
		t.Fatal("a lifted mark is still got")
	}
	var none *Marks
	if _, ok := none.Get(RevocationPrincipal, "user:a"); ok {
		t.Fatal("a nil Marks names a mark")
	}
}

// flakyFeed fails its first loads, then holds marks; its watch waits.
type flakyFeed struct {
	mu    sync.Mutex
	fails int
	marks []Revocation
	loads int
}

func (f *flakyFeed) Revocations(context.Context) (uint64, []Revocation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loads++
	if f.fails > 0 {
		f.fails--
		return 0, nil, ErrUnavailable
	}
	return 7, f.marks, nil
}

func (f *flakyFeed) WatchRevocations(ctx context.Context, _ uint64, _ func(Revocation, bool, uint64),
	_ func(uint64)) error {
	<-ctx.Done()
	return ctx.Err()
}

// A feed never read (from 0) loads first, trying again each second while
// the store does not answer, and keeps what the process held meanwhile:
// a port49d run after a store gone with the directory cut (plan 11a, R19).
func TestFollowMarksFromZeroLoadsFirst(t *testing.T) {
	m := NewMarks()
	held := Revocation{Kind: RevocationPrincipal, Key: "user:held", At: time.Unix(1, 0)}
	m.Set(held, true)
	m.Keep(held)
	f := &flakyFeed{fails: 1, marks: []Revocation{{Kind: RevocationPrincipal, Key: "user:new", At: time.Unix(2, 0)}}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	rescans := 0
	go func() {
		done <- FollowMarks(ctx, f, m, 0, nil, func(bool) {}, func() error { rescans++; return nil },
			func(string, ...any) {})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !m.Holds(RevocationPrincipal, "user:new") {
		if time.Now().After(deadline) {
			t.Fatal("the marks were never loaded")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !m.Holds(RevocationPrincipal, "user:held") {
		t.Fatal("a kept mark was lifted by the first load")
	}
	cancel()
	<-done
	if f.loads < 2 || rescans < 1 {
		t.Fatalf("loads %d, rescans %d: want a retried load after its hook", f.loads, rescans)
	}
}
```

Create `internal/store/fresh_test.go`:

```go
package store

import (
	"errors"
	"testing"
	"time"
)

func TestFreshnessConfirmsOnlyWhileTheFeedRuns(t *testing.T) {
	now := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	var confirmed []time.Time
	var reach []bool
	f := NewFreshness(func() time.Time { return now })
	f.Tell(func(at time.Time) { confirmed = append(confirmed, at) }, func(r bool) { reach = append(reach, r) })
	if _, ok := f.Age(); ok {
		t.Fatal("a copy never confirmed has an age")
	}
	if tr := f.Checked(nil); tr != Steady {
		t.Fatalf("a first answer: %v", tr)
	}
	if _, ok := f.Age(); ok {
		t.Fatal("confirmed with the feed down")
	}
	f.FeedUp(true)
	f.Checked(nil)
	now = now.Add(2 * time.Second)
	if age, ok := f.Age(); !ok || age != 2*time.Second {
		t.Fatalf("age %v %v", age, ok)
	}
	if tr := f.Checked(errors.New("store: unavailable: deadline")); tr != Stopped {
		t.Fatalf("a failed read: %v", tr)
	}
	if ok, why := f.Reachable(); ok || why != "store: unavailable: deadline" {
		t.Fatalf("%v %q", ok, why)
	}
	if tr := f.Checked(errors.New("again")); tr != Steady {
		t.Fatalf("a second failure: %v", tr)
	}
	now = now.Add(time.Second)
	if tr := f.Checked(nil); tr != Resumed {
		t.Fatalf("the answer after a stop: %v", tr)
	}
	// Reachability is told when first known (true), at the stop (false) and
	// at the resume (true); a confirmation only while the feed ran.
	if len(confirmed) != 2 || !confirmed[1].Equal(now) || len(reach) != 3 || !reach[0] || reach[1] || !reach[2] {
		t.Fatalf("confirmed %v, reach %v", confirmed, reach)
	}
}

// A first read that fails is a stop: the line says the directory is not
// answering from the start.
func TestFreshnessFirstFailureIsAStop(t *testing.T) {
	f := NewFreshness(time.Now)
	if tr := f.Checked(errors.New("no")); tr != Stopped {
		t.Fatalf("%v", tr)
	}
}

// Tell tells a run's metrics the state at once: a port49d run after a store
// gone keeps the process's copy, and its new registry must not read absent
// or zero (plan 11a, R19).
func TestFreshnessTellsANewRunAtOnce(t *testing.T) {
	now := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	f := NewFreshness(func() time.Time { return now })
	f.FeedUp(true)
	f.Checked(nil)
	var at time.Time
	var reach []bool
	f.Tell(func(t time.Time) { at = t }, func(r bool) { reach = append(reach, r) })
	if !at.Equal(now) || len(reach) != 1 || !reach[0] {
		t.Fatalf("told %v %v", at, reach)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/store/ -run 'MarksGet|FollowMarksFromZero|Freshness' -count=1 -race`
Expected: FAIL to compile (`m.Get undefined`, `undefined: NewFreshness`).

- [ ] **Step 3: Implement**

In `internal/store/marks.go`:
1. Add a field beside `m`:
   ```go
   	// origin is each mark's Origin, as its put carried it (plan 11a): Get
   	// answers a mark whole, and revokedError names a CA's.
   	origin map[[2]string]string
   ```
   and add `origin: map[[2]string]string{}` to `NewMarks`.
2. In `Set`: on a lift, `delete(m.origin, k)` beside `delete(m.m, k)`. On a new mark, set
   `m.origin[k] = r.Origin` beside `m.m[k] = r.At`.
3. In `Put`: after `m.m[k] = r.At`, add `if r.Origin != "" { m.origin[k] = r.Origin }`.
4. In `All`: build each entry as `Revocation{Kind: k[0], Key: k[1], At: at, Origin: m.origin[k]}`.
5. Add `Get`:
   ```go
   // Get is the mark in force for (kind, key), with the origin its put
   // carried, and whether one stands. The placement router's GetRevocation
   // reads it (plan 11a; decision 51), so a login's and a mint's check never
   // waits on the directory store. A nil *Marks names nothing.
   func (m *Marks) Get(kind, key string) (Revocation, bool) {
   	if m == nil {
   		return Revocation{}, false
   	}
   	m.mu.RLock()
   	defer m.mu.RUnlock()
   	k := [2]string{kind, key}
   	at, ok := m.m[k]
   	if !ok {
   		return Revocation{}, false
   	}
   	return Revocation{Kind: kind, Key: key, At: at, Origin: m.origin[k]}, true
   }
   ```
6. In `FollowMarks`, before the `for {` loop, add the load that a never-read feed needs. Add one
   sentence to the function comment: "A from of 0 is a feed never read: it loads first, as after a
   compaction, trying again every second (plan 11a)."
   ```go
   	for from == 0 {
   		err := rescanned()
   		if err == nil {
   			var rev uint64
   			if rev, err = LoadMarks(ctx, feed, m, on); err == nil {
   				from = max(rev, 1)
   				break
   			}
   		}
   		up(false)
   		if !failing {
   			logf("store: the marks feed cannot load the marks (%v); trying again every second", err)
   			failing = true
   		}
   		select {
   		case <-ctx.Done():
   			return ctx.Err()
   		case <-time.After(time.Second):
   		}
   	}
   ```

Create `internal/store/fresh.go`:

```go
package store

import (
	"sync"
	"time"
)

// Freshness is how current a process's copy of the directory store is
// (plan 11a; spec §13 decision 51): whether its marks feed runs, and the
// last time a read of the directory answered while it did. A watch that
// runs and a store that answers a linearizable read leave the copy at most
// one check and one delivery behind. It is safe for concurrent use.
type Freshness struct {
	mu        sync.Mutex
	now       func() time.Time
	feedUp    bool
	confirmed time.Time
	checked   bool
	reachable bool
	why       string
	onConfirm func(time.Time)
	onReach   func(bool)
}

// Transition is what a check changed: nothing, the directory stopped
// answering, or it answered again after it had stopped.
type Transition int

const (
	Steady Transition = iota
	Stopped
	Resumed
)

// NewFreshness is a copy never confirmed, telling nothing until Tell.
func NewFreshness(now func() time.Time) *Freshness { return &Freshness{now: now} }

// Tell has onConfirm told each confirmation's time, and onReach each
// check's reachability when it changes or is first known (nil tells
// nothing): a run's metrics. Each is told what is known now, at once.
func (f *Freshness) Tell(onConfirm func(time.Time), onReach func(bool)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onConfirm, f.onReach = onConfirm, onReach
	if onConfirm != nil && !f.confirmed.IsZero() {
		onConfirm(f.confirmed)
	}
	if onReach != nil && f.checked {
		onReach(f.reachable)
	}
}

// FeedUp is the marks feed's up hook (FollowMarks).
func (f *Freshness) FeedUp(up bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.feedUp = up
}

// Checked is a directory read's answer: nil confirms the copy while the
// feed runs. It returns Stopped when the directory stops answering (a
// first check that fails included), Resumed when it answers after a stop,
// and Steady otherwise.
func (f *Freshness) Checked(err error) Transition {
	f.mu.Lock()
	defer f.mu.Unlock()
	was, first := f.reachable, !f.checked
	f.checked, f.reachable = true, err == nil
	f.why = ""
	if err != nil {
		f.why = err.Error()
	}
	if err == nil && f.feedUp {
		f.confirmed = f.now()
		if f.onConfirm != nil {
			f.onConfirm(f.confirmed)
		}
	}
	if (first || was != f.reachable) && f.onReach != nil {
		f.onReach(f.reachable)
	}
	switch {
	case !f.reachable && (first || was):
		return Stopped
	case f.reachable && !first && !was:
		return Resumed
	}
	return Steady
}

// Age is how long since the copy was last confirmed, and false before
// the first confirmation.
func (f *Freshness) Age() (time.Duration, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.confirmed.IsZero() {
		return 0, false
	}
	return f.now().Sub(f.confirmed), true
}

// Reachable is whether the last read answered, and its error's text when
// it did not.
func (f *Freshness) Reachable() (bool, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reachable, f.why
}
```

- [ ] **Step 4: Run them to verify they pass**

Run: `go test ./internal/store/ -count=1`
Expected: PASS, the existing marks tests included.

- [ ] **Step 5: Commit**

```bash
git add internal/store/marks.go internal/store/marks_test.go internal/store/fresh.go internal/store/fresh_test.go
git commit -m "feat: a mark's origin in the process's copy, the directory cache's freshness, and a feed that loads first

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Unlock records in the directory store

**Files:**
- Modify: `internal/store/store.go` (`Enrollments` :1124; new `ErrBadUnlock`)
- Modify: `internal/store/enrollments.go` (`EnrollmentBody` gains `Unlocks`)
- Modify: `internal/store/memory/enrollments.go`, `internal/store/enrollfile/enrollfile.go`,
  `internal/store/etcd/keys.go`, `internal/store/etcd/signin.go`, `internal/store/etcd/roles.go`
  (`daemonNever`, `CheckIdentity`'s probes), `internal/store/crypt/enrollments.go`,
  `internal/store/guard/guard.go` (`guardedEnrollments`), `internal/port49d/signin.go` (`lateEnrollments`)
- Modify: `internal/store/storetest/enrollments.go` (a property)
- Test: `internal/store/etcd/roles_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - on `store.Enrollments`:
    `GetUnlock(ctx context.Context, principal string) (time.Time, error)` (`ErrNotFound` when none)
    and `PutUnlock(ctx context.Context, principal string, at time.Time) error`, which always
    advances the record (`at`, or a nanosecond after the time standing when `at` is not later) and
    refuses an empty principal (`ErrNoPrincipal`) or a zero time (`ErrBadUnlock`);
  - `var store.ErrBadUnlock`;
  - the etcd family `ul/<principal>`, the broker's alone.

- [ ] **Step 1: Write the failing tests**

In `internal/store/storetest/enrollments.go`, add
`{"UnlockAlwaysAdvances", UnlockAlwaysAdvances},` to `RunEnrollments`'s list, and append:

```go
// UnlockAlwaysAdvances: none is ErrNotFound; a put reads back; a put at or
// before the time standing (a slower clock in another region) is recorded a
// nanosecond after it, so every unlock starts the count again; an empty
// principal or a zero time is refused; one principal's unlock is not
// another's (plan 11a, R15).
func UnlockAlwaysAdvances(t *testing.T, b EnrollmentsBackend) {
	ctx := context.Background()
	e := b.New(t, func() time.Time { return t0 })
	const p = "user:alice@example.com"
	if _, err := e.GetUnlock(ctx, p); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a new store holds an unlock: %v", err)
	}
	if err := e.PutUnlock(ctx, p, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := e.PutUnlock(ctx, p, t0); err != nil {
		t.Fatal(err)
	}
	if got, err := e.GetUnlock(ctx, p); err != nil || !got.Equal(t0.Add(time.Hour+time.Nanosecond)) {
		t.Fatalf("%v %v, want a nanosecond after the standing unlock", got, err)
	}
	if err := e.PutUnlock(ctx, "", t0); !errors.Is(err, store.ErrNoPrincipal) {
		t.Fatalf("an empty principal: %v", err)
	}
	if err := e.PutUnlock(ctx, p, time.Time{}); !errors.Is(err, store.ErrBadUnlock) {
		t.Fatalf("a zero time: %v", err)
	}
	if _, err := e.GetUnlock(ctx, "user:bob@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another principal: %v", err)
	}
}
```

Append to `internal/store/etcd/roles_test.go`:

```go
// An unlock is the broker's: the daemon's role neither reads nor writes
// ul/ (plan 11a, R23).
func TestTheDaemonCannotReachAnUnlock(t *testing.T) {
	const prefix = "/port49/"
	srv := provisioned(t, prefix)
	ctx := context.Background()
	d, b := openAs(t, srv, "port49-daemon", prefix), openAs(t, srv, "port49-broker", prefix)
	if err := b.PutUnlock(ctx, "user:alice@example.com", t0); err != nil {
		t.Fatalf("the broker unlocks: %v", err)
	}
	if _, err := d.GetUnlock(ctx, "user:alice@example.com"); !errors.Is(err, ErrRefused) {
		t.Fatalf("the daemon read an unlock: %v", err)
	}
	if err := d.PutUnlock(ctx, "user:alice@example.com", t0.Add(time.Hour)); !errors.Is(err, ErrRefused) {
		t.Fatalf("the daemon wrote an unlock: %v", err)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/store/... -run 'Unlock' -count=1`
Expected: FAIL to compile (`e.GetUnlock undefined`).

- [ ] **Step 3: Implement**

In `internal/store/store.go`, add to `Enrollments`, after `SecondFactorPrincipals`:

```go
	// GetUnlock is when an operator last cleared principal's failed
	// sign-ins (port49 directory unlock; plan 11a, R15), or ErrNotFound. A
	// principal and a time: no secret, kept in the clear.
	GetUnlock(ctx context.Context, principal string) (time.Time, error)
	// PutUnlock records an unlock of principal at at, or a nanosecond after
	// the unlock standing when at is not later: every unlock advances the
	// record, whatever the writer's clock (plan 11a, R15). An empty principal
	// is ErrNoPrincipal and a zero at ErrBadUnlock.
	PutUnlock(ctx context.Context, principal string, at time.Time) error
```

and beside `ErrNoPrincipal`:

```go
// ErrBadUnlock is an unlock written with no time.
var ErrBadUnlock = errors.New("store: an unlock needs its time")
```

In `internal/store/enrollments.go`, add to `EnrollmentBody`:

```go
	// Unlocks is each principal's latest unlock (plan 11a, R15), in the file
	// alone: an export carries none, since an unlock outlives no attempt
	// window worth restoring.
	Unlocks map[string]time.Time `json:"unlocks,omitempty"`
```

In `internal/store/memory/enrollments.go`, add `unlocks map[string]time.Time` to `enrollments`, set
it to `map[string]time.Time{}` in `NewEnrollments`, and add:

```go
func (e *enrollments) GetUnlock(_ context.Context, principal string) (time.Time, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	at, ok := e.unlocks[principal]
	if !ok {
		return time.Time{}, store.ErrNotFound
	}
	return at, nil
}

func (e *enrollments) PutUnlock(_ context.Context, principal string, at time.Time) error {
	switch {
	case principal == "":
		return store.ErrNoPrincipal
	case at.IsZero():
		return store.ErrBadUnlock
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if cur, ok := e.unlocks[principal]; ok && !at.After(cur) {
		at = cur.Add(time.Nanosecond)
	}
	e.unlocks[principal] = at
	return nil
}
```

In `internal/store/enrollfile/enrollfile.go`:
1. Add `unlocks map[string]time.Time` to `File`.
2. `load(b)` sets `f.unlocks = b.Unlocks`, or an empty map when it is nil.
3. `body(mark, records)` becomes `body(mark, records, unlocks)` and sets `Unlocks: unlocks`. Every
   caller passes `f.unlocks`.
4. `Export` seals a body built with a nil `unlocks`, so an export carries none.
5. Add the two methods. Each writes the file before it changes memory, as `SwapSecondFactor` does:
   ```go
   func (f *File) GetUnlock(_ context.Context, principal string) (time.Time, error) {
   	f.mu.Lock()
   	defer f.mu.Unlock()
   	if err := f.lostErr(); err != nil {
   		return time.Time{}, err
   	}
   	at, ok := f.unlocks[principal]
   	if !ok {
   		return time.Time{}, store.ErrNotFound
   	}
   	return at, nil
   }

   // PutUnlock writes the file with the unlock in place and, only once it
   // is written, in memory: a write that fails changes nothing.
   func (f *File) PutUnlock(_ context.Context, principal string, at time.Time) error {
   	switch {
   	case principal == "":
   		return store.ErrNoPrincipal
   	case at.IsZero():
   		return store.ErrBadUnlock
   	}
   	f.mu.Lock()
   	defer f.mu.Unlock()
   	if err := f.lostErr(); err != nil {
   		return err
   	}
   	if cur, ok := f.unlocks[principal]; ok && !at.After(cur) {
   		at = cur.Add(time.Nanosecond)
   	}
   	next := make(map[string]time.Time, len(f.unlocks)+1)
   	for p, t := range f.unlocks {
   		next[p] = t
   	}
   	next[principal] = at.UTC()
   	if err := f.write(body(f.mark, f.records, next)); err != nil {
   		return fmt.Errorf("enrollfile: writing %s: %w", f.path, err)
   	}
   	f.unlocks, f.present = next, true
   	return nil
   }
   ```

In `internal/store/etcd/keys.go`:
1. Add the family after `famSignInAttempts`:
   ```go
   	famUnlock         = "ul/" // ul/<principal>: a person's latest unlock (plan 11a), the broker's alone
   ```
2. Add the key function beside `signInAttempts`:
   ```go
   func (k keys) unlock(principal string) string { return k.root + famUnlock + esc(principal) }
   ```

In `internal/store/etcd/signin.go`:

```go
// unlockRec is ul/<principal> (plan 11a, R15): when an operator last
// cleared the person's failed sign-ins.
type unlockRec struct {
	At time.Time `json:"at"`
}

func (s *Store) GetUnlock(ctx context.Context, principal string) (time.Time, error) {
	var r unlockRec
	_, ok, err := getJSONAs(ctx, s.tok, s.k.unlock(principal), "unlock", &r)
	switch {
	case err != nil:
		return time.Time{}, err
	case !ok:
		return time.Time{}, store.ErrNotFound
	}
	return r.At, nil
}

// PutUnlock advances the unlock by a compare on the key's revision (its
// absence for none), reading again when another write came between: at, or
// a nanosecond after the standing one when at is not later. No lease: an
// unlock is a few bytes per person ever unlocked.
func (s *Store) PutUnlock(ctx context.Context, principal string, at time.Time) error {
	switch {
	case principal == "":
		return store.ErrNoPrincipal
	case at.IsZero():
		return store.ErrBadUnlock
	}
	key := s.k.unlock(principal)
	for {
		var r unlockRec
		mod, ok, err := getJSONAs(ctx, s.tok, key, "unlock", &r)
		if err != nil {
			return err
		}
		next := at
		if ok && !at.After(r.At) {
			next = r.At.Add(time.Nanosecond)
		}
		body, err := json.Marshal(unlockRec{At: next.UTC()})
		if err != nil {
			return err
		}
		cmp := unchanged(key, mod)
		if !ok {
			cmp = clientv3.Compare(clientv3.CreateRevision(key), "=", 0)
		}
		resp, err := s.tok.Txn(ctx).If(cmp).Then(clientv3.OpPut(key, string(body))).Commit()
		if err != nil {
			return unavailable(err)
		}
		if resp.Succeeded {
			return nil
		}
	}
}
```

`getJSONAs` returns the key's mod revision as an `int64`. If its type differs, convert it as
`GetSecondFactor` does for `SwapSecondFactor`'s `unchanged(key, int64(rev))`.

In `internal/store/etcd/roles.go`:
1. Add `famUnlock` to `daemonNever`.
2. Add two rows to `CheckIdentity`'s probes, after the `famSignInAttempts` pair:
   ```go
   		{"reading " + s.k.family(famUnlock), func() error { return read(famUnlock) }},
   		{"writing " + s.k.family(famUnlock), func() error { return write(famUnlock) }},
   ```

The pass-throughs, beside each wrapper's `GetEnrollmentMark`:
- `internal/store/crypt/enrollments.go`: `GetUnlock` and `PutUnlock` call `e.inner`'s. An unlock is
  not sealed.
- `internal/store/guard/guard.go`: in the `Token` pool, as `GetEnrollmentMark` is:
  ```go
  func (e *guardedEnrollments) GetUnlock(ctx context.Context, principal string) (at time.Time, err error) {
  	err = e.g.do(ctx, Token, func(ctx context.Context) (x error) { at, x = e.inner.GetUnlock(ctx, principal); return })
  	return
  }

  func (e *guardedEnrollments) PutUnlock(ctx context.Context, principal string, at time.Time) error {
  	return e.g.do(ctx, Token, func(ctx context.Context) error { return e.inner.PutUnlock(ctx, principal, at) })
  }
  ```
- `internal/port49d/signin.go`: `lateEnrollments.GetUnlock` uses `l.get()`, and `PutUnlock` uses
  `l.getFresh()`, as `GetEnrollmentMark` and `PutEnrollmentMark` do.

Run `go vet ./...`. It names every other type that implements `store.Enrollments` and now lacks the
two methods: the test doubles in `internal/broker` and `internal/port49d`. Give each the two
methods. A double that embeds `store.Enrollments` needs none. A double written method by method
answers `store.ErrNotFound` from `GetUnlock` and `nil` from `PutUnlock`, unless its test says
otherwise.

- [ ] **Step 4: Run them to verify they pass**

Run: `go test ./internal/store/... ./internal/port49d/ ./internal/broker/ -count=1`
Expected: PASS: `UnlockAlwaysAdvances` on memory, the file, etcd and the sealed layer, and
`TestTheDaemonCannotReachAnUnlock`.

- [ ] **Step 5: Commit**

```bash
git add internal/store internal/port49d/signin.go internal/broker
git commit -m "feat: unlock records in the directory store (ul/)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 5: The unlock starts every region's count; one code signs in once

**Files:**
- Modify: `internal/broker/signin.go` (`signInAttempt` :93; `underPrincipalLimit` :292; `succeeded`
  :450; the sign-in :567 and the confirm :807)
- Modify: `internal/broker/signin_admin.go` (`UnlockSignIn` :316)
- Test: `internal/broker/signin_regions_test.go` (new), `internal/broker/signin_admin_test.go`
  (`TestUnlockClearsTheCount`'s expected text)

**Interfaces:**
- Consumes: `Enrollments.GetUnlock`, `PutUnlock` (Task 4).
- Produces:
  - `func attemptKey(principal string, unlockedAt time.Time) string`: `principal:<p>`, or
    `principal:<p>@<unix nanos>` after an unlock.
  - `UnlockSignIn`'s text: `cleared N failed sign-ins for <p> here; every region's count starts again`.

- [ ] **Step 1: Write the failing tests**

Create `internal/broker/signin_regions_test.go`:

```go
package broker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/api"
	"github.com/rhwendt/port49/internal/store"
)

// twoRegions is two brokers, each on its own session store (its own
// fixture's), sharing one directory: a's enrollment store (plan 11a).
func twoRegions(t *testing.T) (a, b *fixture) {
	t.Helper()
	a, _ = newSignInFixture(t)
	b, _ = newSignInFixture(t)
	b.b.Enrollments = a.b.Enrollments
	return a, b
}

// Review Focus 3: one code, presented to two regions at once, signs in
// once: the used step is a compare-and-set on the one directory record.
func TestOneCodeSignsInOnceAcrossRegions(t *testing.T) {
	a, b := twoRegions(t)
	secret := a.enrolled(t, alicePrincipal, "uuid:alice")
	req := api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, secret, a.now), CSR: csrOf(t, newECKey(t))}
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i, f := range []*fixture{a, b} {
		wg.Add(1)
		go func() { defer wg.Done(); codes[i] = f.signIn(t, req).Code }()
	}
	wg.Wait()
	passed := 0
	for _, c := range codes {
		if c == http.StatusOK {
			passed++
		}
	}
	if passed != 1 {
		t.Fatalf("answers %v: one code signed in %d times across two regions", codes, passed)
	}
	// And one after the other: the second region refuses the spent code.
	if w := b.signIn(t, req); w.Code == http.StatusOK {
		t.Fatalf("a spent code signed in again in another region: %s", shown(w))
	}
}

// R15: an unlock in one region starts the count in another: the count is
// regional, the unlock is a directory record.
func TestAnUnlockReachesEveryRegionsCount(t *testing.T) {
	ctx := context.Background()
	a, b := twoRegions(t)
	secret := a.enrolled(t, alicePrincipal, "uuid:alice")
	for range 5 {
		if _, _, err := b.b.Store.NoteSignInAttempt(ctx, alicePrincipalKey, b.b.PasswordSignIn.Window); err != nil {
			t.Fatal(err)
		}
	}
	req := api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, secret, b.now), CSR: csrOf(t, newECKey(t))}
	if w := b.signIn(t, req); w.Code != http.StatusTooManyRequests {
		t.Fatalf("setup: region b did not throttle: %s", shown(w))
	}
	text, err := a.b.UnlockSignIn(ctx, alicePrincipal, "admin_socket uid 0")
	if err != nil || text != "cleared 0 failed sign-ins for "+alicePrincipal+" here; every region's count starts again" {
		t.Fatalf("%q %v", text, err)
	}
	if w := b.signIn(t, req); w.Code != http.StatusOK {
		t.Fatalf("region b after an unlock in region a: %s", shown(w))
	}
}

// failingUnlocks is an enrollment store whose unlock reads fail as a cut
// directory's do.
type failingUnlocks struct{ store.Enrollments }

func (failingUnlocks) GetUnlock(context.Context, string) (time.Time, error) {
	return time.Time{}, store.ErrUnavailable
}

// R16: a sign-in whose directory does not answer is refused 503
// store_unavailable before anything is counted or judged.
func TestASignInWithTheDirectoryCutIsRefused(t *testing.T) {
	f, _ := newSignInFixture(t)
	secret := f.enrolled(t, alicePrincipal, "uuid:alice")
	f.b.Enrollments = failingUnlocks{f.b.Enrollments}
	req := api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))}
	w := f.signIn(t, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("%s", shown(w))
	}
	assertErrorCode(t, w, "store_unavailable")
}

// assertErrorCode checks a refusal's API error code, and nothing of its
// body beyond it.
func assertErrorCode(t *testing.T, w *httptest.ResponseRecorder, code string) {
	t.Helper()
	var e api.Error
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil || e.Error != code {
		t.Fatalf("error %q (%v), want %q", e.Error, err, code)
	}
}
```

`f.signIn` returns the recorder the existing sign-in tests read `.Code` from. If its type is not
`*httptest.ResponseRecorder`, give `assertErrorCode` that type. If the package already has a
helper that reads an API error's code (`grep -n 'func.*errorCode\|api.Error' internal/broker/*_test.go`),
use it and drop `assertErrorCode`.

In `internal/broker/signin_admin_test.go`, `TestUnlockClearsTheCount` expects the new text:
`"cleared 6 failed sign-ins for "+alicePrincipal+" here; every region's count starts again"`.

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/broker/ -run 'AcrossRegions|EveryRegions|DirectoryCut|UnlockClearsTheCount' -count=1`
Expected:
- `TestOneCodeSignsInOnceAcrossRegions` PASSES already: the CAS is on the shared record. Keep it as
  the regression pin.
- `TestAnUnlockReachesEveryRegionsCount` FAILS (region b still 429, or the text differs).
- `TestASignInWithTheDirectoryCutIsRefused` FAILS (the unlock is never read).
- `TestUnlockClearsTheCount` FAILS on the text.

- [ ] **Step 3: Implement**

In `internal/broker/signin.go`:

```go
// attemptKey is the principal's failed-attempt count key under its latest
// unlock (plan 11a, R15). The count is the session store's, so per region;
// the unlock is the directory's, so an unlock moves every region's count to
// a new key at once, and the old counts lapse with their window.
func attemptKey(principal string, unlockedAt time.Time) string {
	if unlockedAt.IsZero() {
		return "principal:" + principal
	}
	return "principal:" + principal + "@" + strconv.FormatInt(unlockedAt.UnixNano(), 10)
}
```

1. Add a field to `signInAttempt`:
   ```go
   	// principalKey is the principal's attempt key under its latest unlock
   	// (unlockedKey); empty before it is read.
   	principalKey string
   ```
2. Add the read:
   ```go
   // unlockedKey reads principal's latest unlock from the directory store
   // and keys the principal's count under it (R15). A directory that does
   // not answer refuses the sign-in 503 store_unavailable, as the second
   // factor's read does: the sign-in needs the directory for its code anyway
   // (R16).
   func (s *signInAttempt) unlockedKey(ctx context.Context, principal string) bool {
   	at, err := s.b.Enrollments.GetUnlock(ctx, principal)
   	switch {
   	case errors.Is(err, store.ErrNotFound):
   	case errors.Is(err, store.ErrEnrollmentStoreLost):
   		s.storeLost(lostWhy(err))
   		return false
   	case err != nil:
   		s.storeUnavailable(principal, "unlock", err, "")
   		return false
   	}
   	s.principalKey = attemptKey(principal, at)
   	return true
   }
   ```
3. `underPrincipalLimit` counts under `s.principalKey`, or `attemptKey(principal, time.Time{})` when
   it is empty. `succeeded` clears the same key.
4. At the sign-in (`if !s.underPrincipalLimit(ctx, cfg, e.Principal) {`) and at the confirm
   (`if !s.underPrincipalLimit(ctx, cfg, principal) {`), call `s.unlockedKey` first:
   `if !s.unlockedKey(ctx, e.Principal) || !s.underPrincipalLimit(ctx, cfg, e.Principal) {`, and the
   same with `principal`.
5. Add `"strconv"` to the imports.

In `internal/broker/signin_admin.go`, replace `UnlockSignIn`'s body from
`n, err := b.Store.ClearSignInAttempts(…)` to its `return`:

```go
	prev, err := b.Enrollments.GetUnlock(ctx, principal)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case errors.Is(err, store.ErrEnrollmentStoreLost):
		return "", fmt.Errorf("broker: the enrollment store is lost (%s): %s", lostWhy(err), lostRemedy)
	case err != nil:
		b.logf("broker: unlocking %s failed: %v", printsafe.Line(principal, 200), err)
		return "", fmt.Errorf("broker: unlocking %s failed: the directory store did not answer, so nothing "+
			"changed: run it again", printsafe.Line(principal, 200))
	}
	// The unlock is the directory's: every region counts under a new key
	// from here (R15).
	if err := b.Enrollments.PutUnlock(ctx, principal, b.Now()); err != nil {
		b.logf("broker: unlocking %s failed: %v", printsafe.Line(principal, 200), err)
		return "", fmt.Errorf("broker: unlocking %s failed: the directory store did not answer, so nothing "+
			"changed: run it again", printsafe.Line(principal, 200))
	}
	// This region's count under the key the unlock replaced, for the record;
	// a failure here costs nothing, the unlock is in force.
	n, err := b.Store.ClearSignInAttempts(ctx, attemptKey(principal, prev))
	if err != nil {
		b.logf("broker: the unlock of %s is in force; this region's old count could not be read: %v",
			printsafe.Line(principal, 200), err)
	}
	b.Log.Emit(decision.Record{TS: b.Now(), Event: decision.EventSignInUnlock, Principal: principal,
		SignInUnlock: &decision.SignInUnlock{Failures: n, Origin: origin}})
	b.say("sign-in: %s cleared %d failed sign-ins for %s here, and started every region's count again", origin, n,
		printsafe.Line(principal, 200))
	return fmt.Sprintf("cleared %d failed sign-ins for %s here; every region's count starts again", n,
		printsafe.Line(principal, 200)), nil
```

- [ ] **Step 4: Run them to verify they pass**

Run: `go test ./internal/broker/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/broker/signin.go internal/broker/signin_admin.go internal/broker/signin_regions_test.go internal/broker/signin_admin_test.go
git commit -m "feat: an unlock starts every region's attempt count; a sign-in reads it from the directory store

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 6: `internal/store/placement`, the router

**Files:**
- Create: `internal/store/placement/placement.go`
- Test: `internal/store/placement/placement_test.go`

**Interfaces:**
- Consumes: `(*store.Marks).Get` (Task 3).
- Produces:
  - `type placement.Directory interface { PutRevocation; GetRevocation; DeleteRevocation; ListRevocations }`,
    with the `store.Store` signatures. `*etcd.Store` and `*memory.Store` satisfy it.
  - `type placement.Config struct { Session store.Store; Directory Directory; Marks *store.Marks; CallTimeout, BulkTimeout time.Duration }`.
  - `func placement.Wrap(c Config) store.Store`.

- [ ] **Step 1: Write the failing tests**

Create `internal/store/placement/placement_test.go`:

```go
package placement

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
)

var t0 = time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)

const alice = "user:alice@example.com"

func clock() time.Time { return t0 }

func wrapped(marks *store.Marks) (s store.Store, session, directory *memory.Store) {
	session, directory = memory.New(clock), memory.New(clock)
	return Wrap(Config{Session: session, Directory: directory, Marks: marks, CallTimeout: time.Second,
		BulkTimeout: time.Second}), session, directory
}

func TestTheMarksAreTheDirectorys(t *testing.T) {
	ctx := context.Background()
	s, session, directory := wrapped(store.NewMarks())
	r := store.Revocation{Kind: store.RevocationPrincipal, Key: alice, At: t0, Origin: "admin_socket uid 0"}
	if err := s.PutRevocation(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err := directory.GetRevocation(ctx, r.Kind, r.Key); err != nil {
		t.Fatalf("the directory lacks the mark: %v", err)
	}
	if _, err := session.GetRevocation(ctx, r.Kind, r.Key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the session store holds a mark: %v", err)
	}
	if rs, err := s.ListRevocations(ctx); err != nil || len(rs) != 1 {
		t.Fatalf("%v %v", rs, err)
	}
	if err := s.DeleteRevocation(ctx, r.Kind, r.Key); err != nil {
		t.Fatal(err)
	}
	if rs, _ := directory.ListRevocations(ctx); len(rs) != 0 {
		t.Fatalf("the lift left %v", rs)
	}
}

// A mark is read from the process's copy, never from the directory: a
// login and a mint in a cut region answer from it (R4, R17).
func TestAMarkIsReadFromTheProcesssCopy(t *testing.T) {
	ctx := context.Background()
	marks := store.NewMarks()
	s, _, directory := wrapped(marks)
	marks.Set(store.Revocation{Kind: store.RevocationCert, Key: "CN=CA|1f", At: t0, Origin: "crl corp"}, true)
	if r, err := s.GetRevocation(ctx, store.RevocationCert, "CN=CA|1f"); err != nil || r.Origin != "crl corp" ||
		!r.At.Equal(t0) {
		t.Fatalf("%+v %v", r, err)
	}
	if err := directory.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: alice, At: t0}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetRevocation(ctx, store.RevocationPrincipal, alice); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a mark the copy has not followed was read: %v", err)
	}
}

// With no copy (the offline revocation), a mark is read from the directory.
func TestWithNoCopyAMarkIsReadFromTheDirectory(t *testing.T) {
	ctx := context.Background()
	s, _, directory := wrapped(nil)
	if err := directory.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: alice, At: t0}); err != nil {
		t.Fatal(err)
	}
	if r, err := s.GetRevocation(ctx, store.RevocationPrincipal, alice); err != nil || !r.At.Equal(t0) {
		t.Fatalf("%+v %v", r, err)
	}
}

// A login carries a mark of the copy into its context and asks the
// session store to compare none: the session store holds no mark, and a
// compare there would refuse every login under one (decision 51).
func TestALoginCarriesACopiedMarkAndComparesNone(t *testing.T) {
	ctx := context.Background()
	marks := store.NewMarks()
	marks.Set(store.Revocation{Kind: store.RevocationPrincipal, Key: alice, At: t0}, true)
	s, _, _ := wrapped(marks)
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	login := store.Context{CtxID: "c1", Principal: alice, Username: "alice", AuthTime: t0.Add(-time.Hour),
		RefreshedAt: t0}
	res, err := store.JoinContext(ctx, s, k, login, t0.Add(-time.Minute), t0, time.Hour,
		store.LoginIndex{Principal: alice, TTL: time.Hour})
	if err != nil {
		t.Fatalf("the login: %v", err)
	}
	if !res.Context.RevokedAt.Equal(t0) {
		t.Fatalf("the context's RevokedAt is %v, want the mark's %v", res.Context.RevokedAt, t0)
	}
}

// hung is a directory that never answers.
type hung struct{}

func (hung) PutRevocation(ctx context.Context, _ store.Revocation) error { <-ctx.Done(); return ctx.Err() }
func (hung) GetRevocation(ctx context.Context, _, _ string) (store.Revocation, error) {
	<-ctx.Done()
	return store.Revocation{}, ctx.Err()
}
func (hung) DeleteRevocation(ctx context.Context, _, _ string) error { <-ctx.Done(); return ctx.Err() }
func (hung) ListRevocations(ctx context.Context) ([]store.Revocation, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// Review Focus 5: a directory write in a cut region fails within the
// directory's call_timeout, as ErrUnavailable, never on the caller's
// minute-long deadline.
func TestADirectoryThatDoesNotAnswerIsBoundedByCallTimeout(t *testing.T) {
	s := Wrap(Config{Session: memory.New(clock), Directory: hung{}, Marks: store.NewMarks(),
		CallTimeout: 100 * time.Millisecond, BulkTimeout: 200 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	start := time.Now()
	err := s.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: alice, At: t0})
	if !errors.Is(err, store.ErrUnavailable) || time.Since(start) > 2*time.Second {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
	if _, err := s.ListRevocations(ctx); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("the list: %v", err)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/store/placement/ -count=1`
Expected: FAIL to compile (`undefined: Wrap`).

- [ ] **Step 3: Implement**

Create `internal/store/placement/placement.go`:

```go
// Package placement is the fixed placement of records between port49's
// two stores (plan 11a; spec §13 decision 51): a store.Store over the
// session store whose revocation marks are the directory store's, and whose
// read of a mark is the process's copy of them.
//
// It is used where the two stores are two: a shared store keeps decision
// 35's atomic login check, and no router.
package placement

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

// Directory is the directory store's revocation half, as the router writes,
// lists, and with no copy reads it.
type Directory interface {
	PutRevocation(ctx context.Context, r store.Revocation) error
	GetRevocation(ctx context.Context, kind, key string) (store.Revocation, error)
	DeleteRevocation(ctx context.Context, kind, key string) error
	ListRevocations(ctx context.Context) ([]store.Revocation, error)
}

// Config is Wrap's.
type Config struct {
	// Session is the session store, sealed and guarded: every method but
	// the revocations'.
	Session store.Store
	// Directory is where the marks are written and listed.
	Directory Directory
	// Marks is the process's copy of the directory's marks, which
	// GetRevocation answers from. Nil reads Directory: the offline
	// revocation, which follows no feed.
	Marks *store.Marks
	// CallTimeout bounds each put, delete and read of Directory, and
	// BulkTimeout its list: a directory that does not answer within one is
	// store.ErrUnavailable. Zero is 500ms and 30s.
	CallTimeout, BulkTimeout time.Duration
}

type placed struct {
	store.Store
	c Config
}

// Wrap is c.Session with the revocation marks placed in c.Directory.
func Wrap(c Config) store.Store {
	if c.CallTimeout <= 0 {
		c.CallTimeout = 500 * time.Millisecond
	}
	if c.BulkTimeout <= 0 {
		c.BulkTimeout = 30 * time.Second
	}
	return &placed{Store: c.Session, c: c}
}

func (p *placed) PutRevocation(ctx context.Context, r store.Revocation) error {
	return bounded(ctx, p.c.CallTimeout, func(ctx context.Context) error { return p.c.Directory.PutRevocation(ctx, r) })
}

func (p *placed) DeleteRevocation(ctx context.Context, kind, key string) error {
	return bounded(ctx, p.c.CallTimeout, func(ctx context.Context) error {
		return p.c.Directory.DeleteRevocation(ctx, kind, key)
	})
}

func (p *placed) ListRevocations(ctx context.Context) (rs []store.Revocation, err error) {
	err = bounded(ctx, p.c.BulkTimeout, func(ctx context.Context) (x error) {
		rs, x = p.c.Directory.ListRevocations(ctx)
		return
	})
	return rs, err
}

// GetRevocation is the copy's mark, or ErrNotFound: a login's and a mint's
// check never waits on the directory (R4). With no copy it reads the
// directory.
func (p *placed) GetRevocation(ctx context.Context, kind, key string) (store.Revocation, error) {
	if p.c.Marks == nil {
		var r store.Revocation
		err := bounded(ctx, p.c.CallTimeout, func(ctx context.Context) (x error) {
			r, x = p.c.Directory.GetRevocation(ctx, kind, key)
			return
		})
		return r, err
	}
	if r, ok := p.c.Marks.Get(kind, key); ok {
		return r, nil
	}
	return store.Revocation{}, store.ErrNotFound
}

// SwapLogin compares no mark: the session store holds none, and the marks a
// login read came from the copy, which it has carried into the context
// already (JoinContext; decision 51). Every request is denied by the copy
// whatever the context says.
func (p *placed) SwapLogin(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration,
	w store.LoginWrite) error {
	w.Marks = nil
	return p.Store.SwapLogin(ctx, k, rev, c, ttl, w)
}

// bounded runs f under d, and names a directory that did not answer within
// it store.ErrUnavailable; a caller that gave up keeps its own error.
func bounded(ctx context.Context, d time.Duration, f func(context.Context) error) error {
	cctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	err := f(cctx)
	if err != nil && ctx.Err() == nil && cctx.Err() != nil && !errors.Is(err, store.ErrUnavailable) {
		return fmt.Errorf("%w: the directory store did not answer within %v", store.ErrUnavailable, d)
	}
	return err
}
```

- [ ] **Step 4: Run them to verify they pass**

Run: `go test ./internal/store/placement/ -count=1 -race`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/placement
git commit -m "feat: internal/store/placement, the marks in the directory store and their copy

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 7: etcd roles per store, and the member count

**Files:**
- Modify: `internal/store/etcd/roles.go`, `internal/store/etcd/keys.go` (`famSnapshot`)
- Create: `internal/store/etcd/members.go`
- Test: `internal/store/etcd/roles_test.go`, `internal/store/etcd/members_test.go` (new)

**Interfaces:**
- Consumes: `famUnlock` (Task 4).
- Produces:
  - the etcd family `famSnapshot = "ds/"` with its two parts `snapMarks = "ds/m/"` and
    `snapBroker = "ds/b/"`, and `snapDaemon = "ds/m/port49d@"` (R19; written in Task 10a), in
    `keys.go`;
  - `type etcd.Scope int`, with the constants `ScopeShared`, `ScopeDirectory` and `ScopeSession`.
  - `func etcd.RolesFor(prefix string, scope Scope) []Grant`; `Roles(prefix)` is
    `RolesFor(prefix, ScopeShared)`.
  - `func (s *Store) CheckIdentityAt(ctx context.Context, broker bool, scope Scope) error`.
  - `func (s *Store) Members(ctx context.Context, per time.Duration) (answering, listed int, err error)`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/store/etcd/roles_test.go`:

```go
// provisionedFor is provisioned with the roles of a keyspace holding
// scope's families (R23).
func provisionedFor(t *testing.T, prefix string, scope Scope) *etcdtest.Server {
	srv := etcdtest.Start(t, etcdtest.Options{TLS: true})
	var grants []etcdtest.Grant
	for _, g := range RolesFor(prefix, scope) {
		grants = append(grants, etcdtest.Grant{Role: g.Role, Key: g.Key, RangeEnd: g.RangeEnd, Write: g.Write})
	}
	srv.EnableAuth(t, grants, map[string][]string{"port49-daemon": {RoleDaemon}, "port49-broker": {RoleBroker}})
	return srv
}

// On a directory keyspace the daemon reads the marks, the ping and the key
// window (R23, R27), and nothing else.
func TestTheDirectoryRolesAreTheMarksAlone(t *testing.T) {
	k := newKeys("/port49/")
	got := RolesFor("/port49/", ScopeDirectory)
	want := []Grant{
		{Role: RoleDaemon, Key: k.family(famMark), RangeEnd: clientv3.GetPrefixRangeEnd(k.family(famMark))},
		{Role: RoleDaemon, Key: k.meta("ping")},
		{Role: RoleDaemon, Key: k.meta("seal_keys")},
		{Role: RoleBroker, Key: k.root, RangeEnd: clientv3.GetPrefixRangeEnd(k.root), Write: true},
	}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("grant %d: %+v, want %+v", i, got[i], want[i])
		}
	}
}

// On a session keyspace the daemon does not read the marks; it reads every
// marks snapshot record, writes its own alone, and has no grant on a
// broker's records (R19, R23; the re-review's N1 and N4).
func TestTheSessionRolesLackTheMarks(t *testing.T) {
	k := newKeys("/port49/")
	reads, writes := false, false
	for _, g := range RolesFor("/port49/", ScopeSession) {
		switch {
		case g.Role != RoleDaemon:
		case g.Key == k.family(famMark):
			t.Fatalf("the session store's daemon role reads the marks: %+v", g)
		case g.Key == k.family(snapMarks) && !g.Write:
			reads = true
		case g.Key == k.family(snapDaemon) && g.Write:
			writes = true
		case strings.HasPrefix(g.Key, k.family(famSnapshot)):
			t.Fatalf("the daemon role reaches a snapshot record past its own and the marks: %+v", g) // roles_test.go imports strings
		}
	}
	if !reads || !writes {
		t.Fatalf("the daemon role reads the marks records %v, writes its own %v", reads, writes)
	}
	for _, g := range RolesFor("/port49/", ScopeShared) {
		if g.Key == k.family(famSnapshot) && g.Role == RoleDaemon {
			t.Fatalf("a shared store's daemon role reaches ds/, which only a split writes: %+v", g)
		}
	}
	if why := k.beyondSessionDaemon(k.family(snapBroker), clientv3.GetPrefixRangeEnd(k.family(snapBroker)), false); why == "" {
		t.Fatal("a daemon read grant on ds/b/ passed the session check")
	}
	if why := k.beyondSessionDaemon(k.family(famSnapshot), clientv3.GetPrefixRangeEnd(k.family(famSnapshot)), false); why == "" {
		t.Fatal("a daemon read grant on all of ds/ passed the session check")
	}
	if why := k.beyondSessionDaemon(k.family(snapMarks), clientv3.GetPrefixRangeEnd(k.family(snapMarks)), false); why != "" {
		t.Fatalf("the daemon's own ds/m/ read grant was refused: %s", why)
	}
	if len(RolesFor("/port49/", ScopeShared)) != len(Roles("/port49/")) {
		t.Fatal("Roles is not the shared scope's")
	}
}

// On a directory keyspace the daemon reads the marks and nothing else, and
// the start check holds it there: the shared roles applied to a directory
// keyspace are refused, as reaching past them.
func TestCheckIdentityAtTheDirectory(t *testing.T) {
	const prefix = "/port49/"
	ctx := context.Background()
	srv := provisionedFor(t, prefix, ScopeDirectory)
	d, b := openAs(t, srv, "port49-daemon", prefix), openAs(t, srv, "port49-broker", prefix)
	if err := d.CheckIdentityAt(ctx, false, ScopeDirectory); err != nil {
		t.Fatalf("the daemon: %v", err)
	}
	if err := b.CheckIdentityAt(ctx, true, ScopeDirectory); err != nil {
		t.Fatalf("the broker: %v", err)
	}
	if _, err := d.ListRevocations(ctx); err != nil {
		t.Fatalf("the daemon lists the marks: %v", err)
	}
	if err := d.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: "user:bob", At: t0}); !errors.Is(err, ErrRefused) {
		t.Fatalf("the daemon wrote a mark: %v", err)
	}
	if _, _, err := d.SealKeys(ctx); err != nil {
		t.Fatalf("the daemon reads the directory's key window (R27): %v", err)
	}
	if _, err := d.GetMembership(ctx, "user:alice@example.com"); !errors.Is(err, ErrRefused) {
		t.Fatalf("the daemon read a pin: %v", err)
	}
	if _, err := d.GetLogout(ctx, "sid 1:i 1:s"); !errors.Is(err, ErrRefused) {
		t.Fatalf("the daemon read a logout: %v", err)
	}
	wide := provisioned(t, prefix)
	dw := openAs(t, wide, "port49-daemon", prefix)
	if err := dw.CheckIdentityAt(ctx, false, ScopeDirectory); !errors.Is(err, ErrNotSeparated) {
		t.Fatalf("the shared roles on a directory keyspace: %v", err)
	}
}

// The re-review's last minor: a session keyspace whose daemon role also
// reads a broker's snapshot records is refused at the daemon's start check,
// naming ds/b/; port49d's start turns it into exit 1 (a *storeFault).
func TestCheckIdentityAtRefusesADaemonReadOfBrokerSnapshots(t *testing.T) {
	const prefix = "/port49/"
	k := newKeys(prefix)
	srv := etcdtest.Start(t, etcdtest.Options{TLS: true})
	var grants []etcdtest.Grant
	for _, g := range append(RolesFor(prefix, ScopeSession), Grant{Role: RoleDaemon, Key: k.family(snapBroker),
		RangeEnd: clientv3.GetPrefixRangeEnd(k.family(snapBroker))}) {
		grants = append(grants, etcdtest.Grant{Role: g.Role, Key: g.Key, RangeEnd: g.RangeEnd, Write: g.Write})
	}
	srv.EnableAuth(t, grants, map[string][]string{"port49-daemon": {RoleDaemon}, "port49-broker": {RoleBroker}})
	d := openAs(t, srv, "port49-daemon", prefix)
	err := d.CheckIdentityAt(context.Background(), false, ScopeSession)
	if !errors.Is(err, ErrNotSeparated) || !strings.Contains(err.Error(), "ds/b/") {
		t.Fatalf("%v, want ErrNotSeparated naming ds/b/", err)
	}
}
```

Create `internal/store/etcd/members_test.go`:

```go
package etcd

import (
	"context"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
)

// Members counts the members etcd lists and those answering at their
// client URL (R21): 3/3, then 2/3 with one stopped.
func TestMembersCountsTheAnswering(t *testing.T) {
	c := etcdtest.StartCluster(t)
	s, err := Open(Config{Endpoints: c.Endpoints, Prefix: etcdtest.Prefix()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()
	if a, l, err := s.Members(ctx, 2*time.Second); err != nil || a != 3 || l != 3 {
		t.Fatalf("%d/%d %v", a, l, err)
	}
	c.Stop(2)
	deadline := time.Now().Add(15 * time.Second)
	for {
		a, l, err := s.Members(ctx, 500*time.Millisecond)
		if err == nil && a == 2 && l == 3 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d/%d %v with one of three stopped", a, l, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/store/etcd/ -run 'DirectoryRoles|SessionRoles|CheckIdentityAt|Members' -count=1`
Expected: FAIL to compile (`undefined: RolesFor`).

- [ ] **Step 3: Implement**

In `internal/store/etcd/roles.go`:

```go
// Scope is which of port49's stores a keyspace holds (plan 11a; spec §13
// decision 51, R23).
type Scope int

const (
	// ScopeShared is a single site's one store: every family.
	ScopeShared Scope = iota
	// ScopeDirectory holds the directory's families alone (R11): rv/, sf/,
	// ul/, mb/, mk/, lo/, meta/enrollments, meta/seal_keys and meta/ping.
	ScopeDirectory
	// ScopeSession holds every other family.
	ScopeSession
)
```

1. Rename the body of `Roles` to `RolesFor(prefix string, scope Scope) []Grant`, and make `Roles`
   `return RolesFor(prefix, ScopeShared)`.
2. In `RolesFor`, build the broker's grant first:
   `broker := Grant{Role: RoleBroker, Key: k.root, RangeEnd: clientv3.GetPrefixRangeEnd(k.root), Write: true}`.
3. For `ScopeDirectory`, return at once:
   ```go
   	if scope == ScopeDirectory {
   		p := k.family(famMark)
   		return []Grant{
   			{Role: RoleDaemon, Key: p, RangeEnd: clientv3.GetPrefixRangeEnd(p)},
   			{Role: RoleDaemon, Key: k.meta("ping")},
   			{Role: RoleDaemon, Key: k.meta("seal_keys")},
   			broker,
   		}
   	}
   ```
4. Otherwise build the grants as before. For `ScopeSession`, the daemon's read families are
   `[]string{famLedger}` instead of `daemonReads`, and it gains two grants: read on every marks
   record, and write on its own (a daemon's key holder can neither delete nor replay a broker's
   record, N1; it has no grant on `ds/b/`, which holds pins and logout keys, N4):
   ```go
   	Grant{Role: RoleDaemon, Key: k.family(snapMarks), RangeEnd: clientv3.GetPrefixRangeEnd(k.family(snapMarks))},
   	Grant{Role: RoleDaemon, Key: k.family(snapDaemon), RangeEnd: clientv3.GetPrefixRangeEnd(k.family(snapDaemon)), Write: true},
   ```
   End with `append(out, broker)`.
5. In `keys.go`, add after `famSignInAttempts`'s line (Task 4 added `famUnlock` there):
   ```go
   	famSnapshot       = "ds/"            // ds/m/<proc>@<host> and ds/b/<proc>@<host>: sealed directory snapshots (plan 11a, R19)
   	snapMarks         = "ds/m/"          // the marks records: every process writes one, port49d reads every one
   	snapBroker        = "ds/b/"          // a broker's logouts and pins: port49-broker's alone
   	snapDaemon        = "ds/m/port49d@"  // the marks records port49d may write
   ```
   and `func (k keys) snapshot(kind, writer string) string { return k.root + famSnapshot + kind + "/" + esc(writer) }`.
   `esc` is `url.PathEscape`, which keeps the `@` of a writer's name, so port49d's own record falls
   under `snapDaemon`.

Factor `CheckIdentity`'s parts so both checks share them:
- the root and unknown-user checks become `func (s *Store) checkUser() error`;
- the `read` and `write` closures become methods `probeRead(ctx, fam string) error` and
  `probeWrite(ctx, fam string) error`;
- the probe loop becomes `func judgeProbes(broker bool, probes []probe) error`, where
  `type probe struct { what string; do func() error }`.

`CheckIdentity`'s body becomes `checkIdentityWith(ctx, broker, need, judged []probe, beyond func(key, end string, write bool) string)`:
its checks; then each of `need`, which must answer for both identities; then `judged` with its
own probes through `judgeProbes` (the broker's must answer, the daemon's must be refused); and its
grants judged by `beyond`. `CheckIdentity` calls it with `nil`, `nil` and `s.k.beyondDaemon`,
unchanged in what it checks.
Then add:

```go
// CheckIdentityAt is CheckIdentity for a keyspace holding scope's families
// (R23). A shared keyspace is checked as CheckIdentity checks one; a session
// keyspace too, where both identities read the marks snapshot records and
// write port49d's own, and the daemon's is refused writing another's or
// reading a broker's (R19; N1, N4). On a
// directory keyspace both identities read the marks and meta/seal_keys; the
// daemon's is refused writing a mark, meta/, a second factor, an unlock, a
// pin, a map key or a logout, and reading a second factor, an unlock, a pin,
// a map key, a logout or meta/enrollments; and its grants reach rv/,
// meta/ping and meta/seal_keys alone (beyondDirectoryDaemon).
func (s *Store) CheckIdentityAt(ctx context.Context, broker bool, scope Scope) error {
	switch scope {
	case ScopeShared:
		return s.CheckIdentity(ctx, broker)
	case ScopeSession:
		return s.checkIdentityWith(ctx, broker, []probe{
			{"reading " + s.k.family(snapMarks), func() error { return s.probeRead(ctx, snapMarks) }},
			{"writing " + s.k.family(snapDaemon), func() error { return s.probeWrite(ctx, snapDaemon) }},
		}, []probe{
			{"writing " + s.k.family(snapMarks) + "port49-broker@", func() error {
				return s.probeWrite(ctx, snapMarks+"port49-broker@")
			}},
			{"reading " + s.k.family(snapBroker), func() error { return s.probeRead(ctx, snapBroker) }},
		}, s.k.beyondSessionDaemon)
	}
	if err := s.checkUser(); err != nil {
		return err
	}
	if err := s.probeRead(ctx, famMark); err != nil {
		return fmt.Errorf("reading %s: %w", s.k.family(famMark), err)
	}
	if _, err := s.tok.Get(ctx, s.k.meta("seal_keys"), clientv3.WithKeysOnly()); err != nil {
		return fmt.Errorf("reading %s: %w", s.k.meta("seal_keys"), unavailable(err))
	}
	probes := []probe{
		{"writing " + s.k.family(famMark), func() error { return s.probeWrite(ctx, famMark) }},
		{"reading " + s.k.family(famMembership), func() error { return s.probeRead(ctx, famMembership) }},
		{"writing " + s.k.family(famMembership), func() error { return s.probeWrite(ctx, famMembership) }},
		{"reading " + s.k.family(famMembershipK), func() error { return s.probeRead(ctx, famMembershipK) }},
		{"writing " + s.k.family(famMembershipK), func() error { return s.probeWrite(ctx, famMembershipK) }},
		{"reading " + s.k.family(famLogout), func() error { return s.probeRead(ctx, famLogout) }},
		{"writing " + s.k.family(famLogout), func() error { return s.probeWrite(ctx, famLogout) }},
		{"reading " + s.k.family(famSecondFactor), func() error { return s.probeRead(ctx, famSecondFactor) }},
		{"writing " + s.k.family(famSecondFactor), func() error { return s.probeWrite(ctx, famSecondFactor) }},
		{"reading " + s.k.family(famUnlock), func() error { return s.probeRead(ctx, famUnlock) }},
		{"writing " + s.k.family(famUnlock), func() error { return s.probeWrite(ctx, famUnlock) }},
		{"writing " + s.k.family(famMeta), func() error { return s.probeWrite(ctx, famMeta) }},
		{"reading " + s.k.enrollmentMark(), func() error {
			_, err := s.tok.Get(ctx, s.k.enrollmentMark(), clientv3.WithKeysOnly())
			return unavailable(err)
		}},
	}
	if err := judgeProbes(broker, probes); err != nil {
		return err
	}
	return s.checkGrantsWith(ctx, broker, s.k.beyondDirectoryDaemon)
}

// beyondDirectoryDaemon says what a grant on [key, end) reaches that the
// daemon's role on a directory keyspace may not: any write, or a read past
// rv/, meta/ping and meta/seal_keys. An empty end is the one key.
func (k keys) beyondDirectoryDaemon(key, end string, write bool) string {
	if write {
		return "writes the directory store, which the broker alone writes"
	}
	marks := k.family(famMark)
	switch {
	case (key == k.meta("ping") || key == k.meta("seal_keys")) && end == "":
		return ""
	case key >= marks && end != "" && end != "\x00" && end <= clientv3.GetPrefixRangeEnd(marks):
		return ""
	}
	return "reads past rv/, meta/ping and meta/seal_keys"
}

// beyondSessionDaemon is beyondDaemon on a session keyspace: the same, but
// a read within ds/m/ and a write within ds/m/port49d@ are the daemon's
// own (R19; N1), and any other grant that reaches into ds/ is refused by
// name (N4): a read of a broker's record would hand the daemon the pins and
// logout keys mb/ and lo/ keep from it.
func (k keys) beyondSessionDaemon(key, end string, write bool) string {
	within := func(fam string) bool {
		p := k.family(fam)
		return key >= p && end != "" && end != "\x00" && end <= clientv3.GetPrefixRangeEnd(p)
	}
	if within(snapDaemon) || !write && within(snapMarks) {
		return ""
	}
	ds := k.family(famSnapshot)
	last := end
	if last == "" {
		last = key + "\x00" // the one key
	}
	if end == "\x00" || key < clientv3.GetPrefixRangeEnd(ds) && last > ds {
		return "reaches into ds/ past the marks records (ds/m/) and its own (ds/m/port49d@): a broker's " +
			"snapshot records (ds/b/) hold pins and logout keys the daemon must not read"
	}
	return k.beyondDaemon(key, end, write)
}
```

`checkGrants(ctx, broker)` becomes `checkGrantsWith(ctx, broker, beyond func(key, end string, write bool) string)`.
`CheckIdentity` calls it with `s.k.beyondDaemon`. The one line that called `s.k.beyondDaemon(...)`
inside it calls `beyond(...)`.

Create `internal/store/etcd/members.go`:

```go
package etcd

import (
	"context"
	"time"
)

// Members is how many members etcd lists, and how many of those answer a
// status read at their first client URL within per (plan 11a, R21: port49
// store status's "3/3 members"). The answer is this client's view: a
// member whose advertised URL it cannot reach does not answer. An error is
// the member list's, and then nothing is counted.
func (s *Store) Members(ctx context.Context, per time.Duration) (answering, listed int, err error) {
	resp, err := s.ctx.MemberList(ctx)
	if err != nil {
		return 0, 0, unavailable(err)
	}
	for _, m := range resp.Members {
		if len(m.ClientURLs) == 0 {
			continue // added, and not yet started
		}
		mctx, cancel := context.WithTimeout(ctx, per)
		_, err := s.ctx.Status(mctx, m.ClientURLs[0])
		cancel()
		if err == nil {
			answering++
		}
	}
	return answering, len(resp.Members), nil
}
```

- [ ] **Step 4: Run them to verify they pass**

Run: `go test ./internal/store/etcd/ -count=1`
Expected: PASS: the new tests, and every existing roles test unchanged.

- [ ] **Step 5: Commit**

```bash
git add internal/store/etcd/roles.go internal/store/etcd/keys.go internal/store/etcd/members.go internal/store/etcd/roles_test.go internal/store/etcd/members_test.go
git commit -m "feat: etcd roles per store (directory, session, shared) and the member count

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 8: `Broker.ReachMark`

**Files:**
- Modify: `internal/broker/revoke.go` (`Revoke`'s token and context loops :287–330)
- Test: `internal/broker/revoke_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  `func (b *Broker) ReachMark(ctx context.Context, r store.Revocation) (tokenKeys int, contexts []store.ContextRef, err error)`.
  Revoke calls it after its mark. In a split, the runner calls it for a mark another region made
  (Task 9).

- [ ] **Step 1: Write the failing test**

Append to `internal/broker/revoke_test.go`:

```go
// ReachMark reaches what a mark made elsewhere names in this broker's
// session store, and writes no mark and no record: the region that made it
// recorded it (plan 11a, R20).
func TestReachMarkReachesWhatAMarkMadeElsewhereNames(t *testing.T) {
	f := newFixture(t, 8)
	ctx := context.Background()
	decodeMint(t, f.post(ctx, f.state(f.alice), `{"devices":["leaf1","nx1"]}`, ""))
	f.liveContext(t, "leaf1", "alice", alice, certKey(f.alice))
	n, refs, err := f.b.ReachMark(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: alice, At: f.now,
		Origin: "admin_socket uid 0"})
	if err != nil || n != 2 || len(refs) != 1 || refs[0].NAS != "leaf1" {
		t.Fatalf("%d %v %v", n, refs, err)
	}
	if c, err := f.st.GetContext(ctx, store.ContextKey{NAS: "leaf1", Username: "alice"}); err != nil ||
		c.RevokedAt.IsZero() {
		t.Fatalf("leaf1's context: %+v %v", c, err)
	}
	for _, dev := range []string{"leaf1", "nx1"} {
		if toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: dev, Username: "alice"}); len(toks) != 0 {
			t.Fatalf("%d unspent token(s) on %s survived", len(toks), dev)
		}
	}
	if _, err := f.st.GetRevocation(ctx, store.RevocationPrincipal, alice); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ReachMark wrote a mark: %v", err)
	}
	if recs := eventsOf(f.records(t), "revoke"); len(recs) != 0 {
		t.Fatalf("ReachMark wrote a record: %v", recs)
	}
}
```

Add `"errors"` to the file's imports if it lacks it.

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/broker/ -run 'ReachMark' -count=1`
Expected: FAIL to compile (`f.b.ReachMark undefined`).

- [ ] **Step 3: Implement**

In `internal/broker/revoke.go`, add:

```go
// ReachMark deletes the unspent tokens r names in this broker's session
// store and marks its live contexts revoked there, as Revoke does after its
// mark (spec §5.1.4): the token keys its index names, each deleted and
// superseded, then the contexts, in two passes, so one a redemption in
// flight wrote is marked too. It writes no mark and no record. In a split
// (plan 11a, R20) the runner applies a mark another region made with it,
// which that region's broker recorded. It returns how many token keys held
// a token or could not be read, the contexts it marked, and the first step
// that did not finish; the steps after it still run.
func (b *Broker) ReachMark(ctx context.Context, r store.Revocation) (tokenKeys int, contexts []store.ContextRef,
	err error) {
	if b.Sessions == nil {
		return 0, nil, errors.New("broker: revocation is not wired (no session manager); nothing was reached")
	}
	note := func(e error) {
		if e != nil && err == nil {
			err = e
		}
	}
	var keys []store.TokenKey
	var kerr error
	if r.Kind == store.RevocationPrincipal {
		keys, kerr = b.Store.TokensByPrincipal(ctx, r.Key)
	} else {
		keys, kerr = b.Store.TokensByCert(ctx, r.Key)
	}
	note(kerr)
	for _, k := range keys {
		// Read first only to count, as the refresh does: an index entry
		// outliving its tokens empties nothing. A read that fails counts.
		toks, cerr := b.Store.Candidates(ctx, k)
		if derr := b.Store.DeleteTokens(ctx, k); derr != nil {
			note(derr)
			continue
		}
		// The delete's own time (M3).
		b.supersede(ctx, k, b.Now())
		if cerr != nil || len(toks) > 0 {
			tokenKeys++
		}
	}
	var issuer, serial string
	if r.Kind == store.RevocationCert {
		i := strings.LastIndexByte(r.Key, '|')
		if i < 0 {
			return tokenKeys, nil, err // CheckRevocation refused such a key; nothing names it
		}
		issuer, serial = r.Key[:i], r.Key[i+1:]
	}
	seen := map[store.ContextRef]bool{}
	for pass := 0; pass < 2; pass++ {
		var refs []store.ContextRef
		var rerr error
		if r.Kind == store.RevocationPrincipal {
			refs, rerr = b.Sessions.RevokeByPrincipal(ctx, r.Key)
		} else {
			refs, rerr = b.Sessions.RevokeByCert(ctx, issuer, serial)
		}
		note(rerr)
		for _, ref := range refs {
			if !seen[ref] {
				seen[ref] = true
				contexts = append(contexts, ref)
			}
		}
	}
	return tokenKeys, contexts, err
}
```

In `Revoke`, replace everything from `var tokenKeys []store.TokenKey` through the end of the
`for pass := 0; pass < 2; pass++ { … }` loop with:

```go
	n, refs, rerr := b.ReachMark(ctx, rep.Mark)
	rep.TokenKeys, rep.Contexts = n, refs
	note(rerr)
```

`rep.Mark`'s kind and key are the request's (`kind`, `key`), and its key is
`store.CertKey(req.Issuer, req.Serial)` for a certificate, so `ReachMark` reaches what the loops
did.

- [ ] **Step 4: Run them to verify they pass**

Run: `go test ./internal/broker/ -count=1`
Expected: PASS: the new test, and every Revoke test unchanged.

- [ ] **Step 5: Commit**

```bash
git add internal/broker/revoke.go internal/broker/revoke_test.go
git commit -m "refactor: Broker.ReachMark, Revoke's reach after its mark

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 8a: Directory membership's pin in the directory store

**Files:**
- Modify: `internal/store/store.go` (`NoExpiry`, `ErrForgotten`; the membership methods' comments
  :1007–1038)
- Modify: `internal/store/etcd/membership.go` (records with no lease; `ErrForgotten`),
  `internal/store/memory/memory.go` (the same: `liveMembershipLocked` :1572, `PutMembership` :1590,
  `liveKeyLocked` :1624, `RefuseMapKeys` :1648, `GetMembership` :1665, `DeleteMembership` :1717,
  the sweep :333)
- Modify: `internal/store/storetest/membership.go`, `internal/store/storetest/storetest.go` (a
  property)
- Modify: `internal/store/placement/placement.go` (a `Members` half, the pin cache, `FollowPins`)
- Modify: `internal/store/etcd/feed.go` (`WatchMemberships`, `Revision`)
- Test: `internal/store/placement/members_test.go` (new), `internal/store/etcd/feed_test.go`

**Interfaces:**
- Consumes: `placement.Wrap` (Task 6); `CheckIdentityAt`'s `mb/` and `mk/` probes (Task 7).
- Produces:
  - `const store.NoExpiry time.Duration = -1`: a membership record or map-key refusal written with
    it carries no lease.
  - `var store.ErrForgotten`: `GetMembership`'s answer for a forget's tombstone. It wraps
    `ErrNotFound`, so `errors.Is(err, store.ErrNotFound)` stays true for every existing caller.
  - `type placement.Members interface { PutMembership; GetMembership; MembershipByKey; RefuseMapKeys; DeleteMembership }`,
    with the `store.Store` signatures. A sealed store over the directory handle
    (`crypt.Wrap(dirRaw, …)`) satisfies it.
  - `placement.Config.Members Members`: nil keeps membership wholly in the session store.
  - `placement.Config.Reachable func() bool`: false skips the directory's membership reads and
    serves the session store's copy. Nil always tries.
  - `placement.Config.Say func(format string, args ...any)`: says once per principal per 10 minutes
    that a cached pin was served, and each pin put back from this region's copy.
  - `type placement.PinFeed interface { Revision(ctx) (uint64, error); WatchMemberships(ctx, after uint64, fn func(principal string, rev uint64), progress func(uint64)) error }`,
    which `*etcd.Store` satisfies.
  - `func placement.FollowPins(ctx context.Context, s store.Store, feed PinFeed, up func(bool), logf func(string, ...any)) error`:
    keeps the router's pin cache current until ctx ends (the caller's goroutine).
  - `(*placed).pinState`, `fillPin`, `dropPin`, `dropPins`, `cachedPin` (package-internal; Task 10a
    adds `SeedPins` beside them).

R13 as ruled (Ryan, 2026-10-17), with membership split by write rate, and amended on the
pre-flight (C1, I2, I3):
- **The directory store** holds the pin record: `mb/<principal>` there carries the entry id (the
  pin), the map keys, `refused`, and the forget's tombstone (`forgotten_at`). It also holds the
  `mk/` index. **Neither has a lease** (`store.NoExpiry`): a pin lives until a forget or a re-pin
  replaces it, a tombstone until a re-pin. A pin with a lease would lapse after
  `Resolver.TTL()` (`max(grace, 24h)`, resolver.go:86) for every active principal, since a refresh
  never rewrites it, and then any entry could take the principal (plan 7g Ruling 3's attack).
- **The session store** holds the whole record as today: DN, username, groups and `verified_at`,
  with a copy of the pin, on the resolver's lease.
- **A read** tells the directory's three answers apart:
  - **pinned**: when this region's record names the same entry, the record with the directory's
    pin, map keys and refusal over it; when it names another entry (a re-pin elsewhere), the pin
    alone, with no groups and no verification time, so grace serves nothing and the next
    verification is held to the new entry (I2);
  - **forgotten** (`ErrForgotten`): the principal is free, wherever it was forgotten;
  - **absent**: never pinned. When this region's record holds a pin, the directory lost it (a
    restore from an older backup): the router writes it back from the record, says so, and serves
    the record. Never "unpinned".
- **A write.** A verification always writes the session record. It writes the directory's pin
  only when the directory's own pin differs (absent, forgotten, another entry, other map keys, or
  another refusal): a first bind, a re-pin after a forget (the same entry included), a changed map
  key, or a refusal. With the directory not answering and the pin not cached, it compares the
  session copy instead: a pinned member's refresh still writes, and anything else is refused
  `store_unavailable`.
- **The cache** never makes a read wait on the directory when the pin is cached (R4).
  `FollowPins` watches the directory's `mb/` family and drops a principal's entry at each change,
  a forget included. Only a miss reads the directory, bounded, and fills the cache. Each
  principal's entry has a generation, bumped by every change the feed brings and every write
  this router makes; a fill read before a bump is dropped (I3), so a stale answer never sits in
  the cache until the principal's next change.
- **A forget** goes to the directory first, and fails closed when the directory does not answer.
  Then it deletes the region's own session record.
- The existing tombstone rule stays: a verification from before the forget is dropped, in the
  directory's `PutMembership`. So no region's in-flight verification writes the old pin back.

- [ ] **Step 1: Write the failing tests**

In `internal/store/storetest/storetest.go`, add
`{"MembershipWithNoExpiryOutlivesAnyTTL", MembershipWithNoExpiryOutlivesAnyTTL},` after
`MembershipTieKeepsTheRefusal`'s entry, and append to `internal/store/storetest/membership.go`:

```go
// MembershipWithNoExpiryOutlivesAnyTTL: a record and its map key written
// with store.NoExpiry stand however far the clock moves, and so does the
// tombstone a forget leaves of one, which GetMembership answers as
// ErrForgotten (an ErrNotFound); a principal never written is ErrNotFound
// and not ErrForgotten; a verification from before the forget never puts
// the pin back (plan 11a, R13).
func MembershipWithNoExpiryOutlivesAnyTTL(t *testing.T, b Backend) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	later := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	k := store.MapKey("san_email", "dave@corp.example.com")
	m := store.Membership{Principal: "user:dave@corp.example.com", EntryID: "guid:d", MapKeys: []string{k},
		VerifiedAt: t0}
	if err := s.PutMembership(ctx, m, store.NoExpiry); err != nil {
		t.Fatal(err)
	}
	later(10 * 365 * 24 * time.Hour)
	if got, err := s.GetMembership(ctx, m.Principal); err != nil || got.EntryID != "guid:d" {
		t.Fatalf("a pin with no expiry, years on: %+v %v", got, err)
	}
	if got, err := s.MembershipByKey(ctx, k); err != nil || got.Principal != m.Principal {
		t.Fatalf("its key, years on: %+v %v", got, err)
	}
	if _, err := s.GetMembership(ctx, "user:erin@corp.example.com"); !errors.Is(err, store.ErrNotFound) ||
		errors.Is(err, store.ErrForgotten) {
		t.Fatalf("never written: %v, want ErrNotFound and not ErrForgotten", err)
	}
	if _, err := s.DeleteMembership(ctx, m.Principal); err != nil {
		t.Fatal(err)
	}
	later(10 * 365 * 24 * time.Hour)
	if _, err := s.GetMembership(ctx, m.Principal); !errors.Is(err, store.ErrForgotten) ||
		!errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the forget's tombstone, years on: %v, want ErrForgotten", err)
	}
	if err := s.PutMembership(ctx, m, store.NoExpiry); err != nil { // verified at t0, before the forget
		t.Fatal(err)
	}
	if _, err := s.GetMembership(ctx, m.Principal); !errors.Is(err, store.ErrForgotten) {
		t.Fatalf("a verification from before the forget put the pin back: %v", err)
	}
}
```

Create `internal/store/placement/members_test.go`:

```go
package placement

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
)

// twoRegions is two routers sharing one directory, each on a session store
// of its own (R13 as ruled).
func twoRegions(reach *bool) (a, b store.Store, sa, sb, dir *memory.Store) {
	sa, sb, dir = memory.New(clock), memory.New(clock), memory.New(clock)
	mk := func(s *memory.Store) store.Store {
		return Wrap(Config{Session: s, Directory: dir, Members: dir, Marks: store.NewMarks(),
			Reachable: func() bool { return reach == nil || *reach }, CallTimeout: time.Second, BulkTimeout: time.Second})
	}
	return mk(sa), mk(sb), sa, sb, dir
}

func member(entry string, at time.Time) store.Membership {
	return store.Membership{Principal: alice, EntryID: entry, Username: "alice", GroupNames: []string{"neteng"},
		MapKeys: []string{"k1"}, VerifiedAt: at}
}

// counting is a directory that counts its pin writes, and refuses one with
// a lease (R13: a directory pin has none).
type counting struct {
	Members
	puts int
}

func (c *counting) PutMembership(ctx context.Context, m store.Membership, ttl time.Duration) error {
	c.puts++
	if ttl != store.NoExpiry {
		return errors.New("a directory pin written with a lease")
	}
	return c.Members.PutMembership(ctx, m, ttl)
}

// A first bind writes the pin to the directory, with no lease and no groups;
// a refresh with the same pin writes the session store alone.
func TestAFirstBindPinsInTheDirectoryAndARefreshDoesNot(t *testing.T) {
	ctx := context.Background()
	sa, dir := memory.New(clock), memory.New(clock)
	writes := &counting{Members: dir}
	a := Wrap(Config{Session: sa, Directory: dir, Members: writes, Marks: store.NewMarks(),
		CallTimeout: time.Second, BulkTimeout: time.Second})
	if err := a.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	pin, err := dir.GetMembership(ctx, alice)
	if err != nil || pin.EntryID != "uuid:1" || len(pin.GroupNames) != 0 || writes.puts != 1 {
		t.Fatalf("the directory's pin: %+v %v after %d write(s) (it holds no groups)", pin, err, writes.puts)
	}
	if err := a.PutMembership(ctx, member("uuid:1", t0.Add(time.Minute)), time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := sa.GetMembership(ctx, alice); err != nil || !got.VerifiedAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("the session's record: %+v %v", got, err)
	}
	if writes.puts != 1 {
		t.Fatalf("a refresh with the same pin wrote the directory (%d writes)", writes.puts)
	}
}

// C1: a pin outlives its principal's session record and any lease: a day
// and more on, with this region's record gone and the cache cold, a read
// still answers the pin, so Resolver.pinned refuses any other entry.
func TestAPinOutlivesItsTTL(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	tick := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	sess, dir := memory.New(tick), memory.New(tick)
	a := Wrap(Config{Session: sess, Directory: dir, Members: dir, Marks: store.NewMarks(),
		CallTimeout: time.Second, BulkTimeout: time.Second})
	if err := a.PutMembership(ctx, member("uuid:1", t0), 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	now = now.Add(48 * time.Hour)
	mu.Unlock()
	a.(*placed).dropPins() // a restart's cold cache
	if _, err := sess.GetMembership(ctx, alice); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("setup: the session record should have lapsed: %v", err)
	}
	got, err := a.GetMembership(ctx, alice)
	if err != nil || got.EntryID != "uuid:1" || !got.VerifiedAt.IsZero() || len(got.GroupNames) != 0 {
		t.Fatalf("%+v %v: want the pin alone, a day on", got, err)
	}
}

// C1: a pin the directory lost (an older backup restored) while this
// region's record holds it is put back from the record, said, and served;
// it is never read as unpinned.
func TestAPinTheDirectoryLostIsPutBackFromTheRegionsRecord(t *testing.T) {
	ctx := context.Background()
	sess, dir := memory.New(clock), memory.New(clock)
	var said []string
	a := Wrap(Config{Session: sess, Directory: dir, Members: dir, Marks: store.NewMarks(),
		Say: func(f string, _ ...any) { said = append(said, f) }, CallTimeout: time.Second, BulkTimeout: time.Second})
	if err := sess.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := a.GetMembership(ctx, alice); err != nil || got.EntryID != "uuid:1" {
		t.Fatalf("%+v %v: want this region's pin", got, err)
	}
	if pin, err := dir.GetMembership(ctx, alice); err != nil || pin.EntryID != "uuid:1" || len(said) != 1 {
		t.Fatalf("the directory's pin: %+v %v, said %d", pin, err, len(said))
	}
}

// One forget, in region a, frees the principal in region b: b's read takes
// the pin from the directory, which has forgotten it.
func TestOneForgetReachesEveryRegion(t *testing.T) {
	ctx := context.Background()
	a, b, _, sb, _ := twoRegions(nil)
	if err := b.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DeleteMembership(ctx, alice); err != nil {
		t.Fatal(err)
	}
	if _, err := sb.GetMembership(ctx, alice); err != nil {
		t.Fatalf("setup: region b's own copy should still be there: %v", err)
	}
	if _, err := b.GetMembership(ctx, alice); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("region b still reads a pin region a forgot: %v", err)
	}
	if err := b.PutMembership(ctx, member("uuid:2", t0.Add(time.Minute)), time.Hour); err != nil {
		t.Fatalf("the re-created entry could not be pinned after the forget: %v", err)
	}
	a.(*placed).dropPin(alice) // what a's FollowPins does at b's re-pin
	if got, _ := a.GetMembership(ctx, alice); got.EntryID != "uuid:2" {
		t.Fatalf("region a reads pin %q, want region b's new one", got.EntryID)
	}
}

// I2: after a forget and a re-pin to another entry in region a, region b's
// read answers the new pin with none of the old entry's groups.
func TestARePinHidesTheOldEntrysFreshness(t *testing.T) {
	ctx := context.Background()
	a, b, _, _, _ := twoRegions(nil)
	if err := b.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DeleteMembership(ctx, alice); err != nil {
		t.Fatal(err)
	}
	other := member("uuid:2", t0.Add(time.Minute))
	other.GroupNames = []string{"ops"}
	if err := a.PutMembership(ctx, other, time.Hour); err != nil {
		t.Fatal(err)
	}
	b.(*placed).dropPin(alice) // b's FollowPins at a's re-pin
	got, err := b.GetMembership(ctx, alice)
	if err != nil || got.EntryID != "uuid:2" || len(got.GroupNames) != 0 || !got.VerifiedAt.IsZero() {
		t.Fatalf("%+v %v: want the new pin with no freshness from the old entry", got, err)
	}
}

// I2: a re-verify of the same entry after a forget pins it again, though
// this region's record already names that entry.
func TestAReVerifyAfterAForgetPinsAgain(t *testing.T) {
	ctx := context.Background()
	a, b, _, _, dir := twoRegions(nil)
	if err := b.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DeleteMembership(ctx, alice); err != nil {
		t.Fatal(err)
	}
	b.(*placed).dropPin(alice)
	if err := b.PutMembership(ctx, member("uuid:1", t0.Add(time.Minute)), time.Hour); err != nil {
		t.Fatal(err)
	}
	if pin, err := dir.GetMembership(ctx, alice); err != nil || pin.EntryID != "uuid:1" {
		t.Fatalf("the directory after the re-verify: %+v %v, want uuid:1 pinned again", pin, err)
	}
}

// racing is a directory whose next pin read runs during() after it reads:
// a feed change landing between a miss's read and its fill.
type racing struct {
	Members
	during func()
}

func (r *racing) GetMembership(ctx context.Context, p string) (store.Membership, error) {
	m, err := r.Members.GetMembership(ctx, p)
	if f := r.during; f != nil {
		r.during = nil
		f()
	}
	return m, err
}

// I3: a fill read before a change the feed brought is not cached: the next
// read goes to the directory and sees the change.
func TestAFillRacedByTheFeedIsNotCached(t *testing.T) {
	ctx := context.Background()
	sess, dir := memory.New(clock), memory.New(clock)
	r := &racing{Members: dir}
	s := Wrap(Config{Session: sess, Directory: dir, Members: r, Marks: store.NewMarks(),
		CallTimeout: time.Second, BulkTimeout: time.Second})
	if err := s.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	r.during = func() {
		if _, err := dir.DeleteMembership(ctx, alice); err != nil { // a forget in another region
			t.Error(err)
		}
		s.(*placed).dropPin(alice) // the feed's delivery of it
	}
	if _, err := s.GetMembership(ctx, alice); err != nil {
		t.Fatalf("the raced read answers what it read: %v", err)
	}
	if s.(*placed).cachedPin(alice) {
		t.Fatal("a fill read before the feed's change was cached")
	}
	if _, err := s.GetMembership(ctx, alice); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the next read did not see the forget: %v", err)
	}
}

// switchable is a directory that answers through Store until hang is set,
// and then never answers, as a blackholed etcd does.
type switchable struct {
	store.Store
	hang bool
}

func (s *switchable) GetMembership(ctx context.Context, p string) (store.Membership, error) {
	if s.hang {
		<-ctx.Done()
		return store.Membership{}, ctx.Err()
	}
	return s.Store.GetMembership(ctx, p)
}

// R4: a pin read is the watched cache's: with the directory blackholed, a
// read of a cached pin answers at once, never waiting on etcd; a change the
// feed brings drops the entry, and the next read goes to the directory.
func TestAPinReadIsTheCaches(t *testing.T) {
	ctx := context.Background()
	sess, dir := memory.New(clock), &switchable{Store: memory.New(clock)}
	s := Wrap(Config{Session: sess, Directory: dir.Store, Members: dir, Marks: store.NewMarks(),
		CallTimeout: 5 * time.Second, BulkTimeout: 5 * time.Second})
	if err := s.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetMembership(ctx, alice); err != nil { // the miss fills the cache
		t.Fatal(err)
	}
	dir.hang = true
	start := time.Now()
	got, err := s.GetMembership(ctx, alice)
	if err != nil || got.EntryID != "uuid:1" || time.Since(start) > 200*time.Millisecond {
		t.Fatalf("%+v %v after %v: a cached pin waited on the directory", got, err, time.Since(start))
	}
	s.(*placed).dropPin(alice) // what FollowPins does at a change
	dir.hang = false
	if _, err := dir.Store.DeleteMembership(ctx, alice); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetMembership(ctx, alice); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after the feed's change the read did not go to the directory: %v", err)
	}
}

// fakePinFeed delivers each principal sent on ch as a change.
type fakePinFeed struct{ ch chan string }

func (f fakePinFeed) Revision(context.Context) (uint64, error) { return 1, nil }
func (f fakePinFeed) WatchMemberships(ctx context.Context, _ uint64, fn func(string, uint64), _ func(uint64)) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case p := <-f.ch:
			fn(p, 2)
		}
	}
}

func TestFollowPinsDropsAChangedPin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, _, _, _, _ := twoRegions(nil)
	if err := a.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	feed := fakePinFeed{ch: make(chan string)}
	up := make(chan bool, 4)
	go FollowPins(ctx, a, feed, func(b bool) { up <- b }, func(string, ...any) {})
	if !<-up { // after the start's dropPins, before the watch
		t.Fatal("the pins watch did not start")
	}
	a.GetMembership(ctx, alice)
	if !a.(*placed).cachedPin(alice) {
		t.Fatal("setup: the read did not fill the cache")
	}
	feed.ch <- alice
	deadline := time.Now().Add(2 * time.Second)
	for a.(*placed).cachedPin(alice) {
		if time.Now().After(deadline) {
			t.Fatal("the feed's change did not drop the cached pin")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// With the directory cut: a pinned member's refresh and read keep working
// from the cached pin, and say so; a first bind and a forget fail closed.
func TestACutDirectoryServesTheCachedPinAndRefusesNewPins(t *testing.T) {
	ctx := context.Background()
	reach := true
	a, _, _, _, _ := twoRegions(&reach)
	var said []string
	a.(*placed).c.Say = func(f string, args ...any) { said = append(said, f) }
	if err := a.PutMembership(ctx, member("uuid:1", t0), time.Hour); err != nil {
		t.Fatal(err)
	}
	reach = false
	if err := a.PutMembership(ctx, member("uuid:1", t0.Add(time.Minute)), time.Hour); err != nil {
		t.Fatalf("a pinned member's refresh during the cut: %v", err)
	}
	if got, err := a.GetMembership(ctx, alice); err != nil || got.EntryID != "uuid:1" || len(said) != 1 {
		t.Fatalf("the cached pin: %+v %v, said %d", got, err, len(said))
	}
	bob := member("uuid:9", t0)
	bob.Principal = "user:bob@example.com"
	if err := a.PutMembership(ctx, bob, time.Hour); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a first bind during the cut: %v, want ErrUnavailable", err)
	}
	if _, err := a.DeleteMembership(ctx, alice); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a forget during the cut: %v, want ErrUnavailable", err)
	}
}
```

Append to `internal/store/etcd/feed_test.go` (`onShared` is `etcd_test.go`'s store on the shared
member):

```go
// The pins feed tells each change to a membership record by its principal,
// a forget's tombstone included, after the revision Revision read.
func TestWatchMembershipsTellsEachChange(t *testing.T) {
	s := onShared(t, func() time.Time { return t0 })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rev, err := s.Revision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 4)
	go s.WatchMemberships(ctx, rev, func(p string, _ uint64) { got <- p }, func(uint64) {})
	m := store.Membership{Principal: "user:alice@example.com", EntryID: "uuid:1", VerifiedAt: t0}
	if err := s.PutMembership(ctx, m, store.NoExpiry); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteMembership(ctx, m.Principal); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		select {
		case p := <-got:
			if p != m.Principal {
				t.Fatalf("told %q", p)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("change %d was not told", i+1)
		}
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/store/... -run 'NoExpiry|Pin|Forget|CachedPin|Raced|RePin|ReVerify|WatchMemberships' -count=1`
Expected: FAIL to compile (`undefined: store.NoExpiry`; `unknown field Members in struct literal`).

- [ ] **Step 3: Records with no lease, the forget told apart, and the pins feed**

In `internal/store/store.go`, beside `TombstoneFloor` (:1184):

```go
// NoExpiry is the ttl of a membership record, or of a refusal of map keys,
// that lives until a forget or a later write replaces it: the directory
// store's pins (plan 11a, R13). Any other ttl is a lease, as before.
const NoExpiry time.Duration = -1

// ErrForgotten is GetMembership's answer for a principal a forget left a
// tombstone for (plan 11a, R13). It is an ErrNotFound, so every caller that
// reads "no record" still does; the directory router tells it from a record
// never written.
var ErrForgotten = fmt.Errorf("%w: forgotten", ErrNotFound)
```

(`store.go` imports `fmt`; add it if it does not.) In the `Store` interface's membership comments
(:1007–1038), add to `PutMembership`'s: "A ttl of NoExpiry writes the record and its keys with no
lease." and to `GetMembership`'s: "A forget's tombstone is ErrForgotten."

In `internal/store/etcd/membership.go`, add:

```go
// expiry is ttl's expiry from now: none, the zero time, for
// store.NoExpiry (plan 11a, R13). commit puts a record with a zero expiry
// with no lease.
func expiry(now time.Time, ttl time.Duration) time.Time {
	if ttl == store.NoExpiry {
		return time.Time{}
	}
	return now.Add(ttl)
}

// alive reports whether a record expiring at exp stands at now: one with no
// expiry always does.
func alive(exp, now time.Time) bool { return exp.IsZero() || exp.After(now) }

// laterExp is the later of two expiries of records that exist, no expiry
// being the latest.
func laterExp(a, b time.Time) time.Time {
	if a.IsZero() || b.IsZero() {
		return time.Time{}
	}
	return laterOf(a, b)
}
```

Then, in the same file:
1. `PutMembership`: `exp := expiry(now, ttl)`, and its live check `alive(r.ExpiresAt, now)`.
2. `registerKey`: `r.ExpiresAt = exp` when `!found`, else `laterExp(r.ExpiresAt, exp)`.
3. `RefuseMapKeys`: `exp := expiry(now, ttl)`, and the same `found` rule for `r.ExpiresAt`.
4. `GetMembership`: the live check `alive(r.ExpiresAt, s.now())`, and a tombstone returns
   `store.ErrForgotten`.
5. `MembershipByKey`: the live check `alive(kr.ExpiresAt, s.now())`.
6. `DeleteMembership`: `!alive(r.ExpiresAt, now) || r.tombstone()`, and
   `exp = laterExp(r.ExpiresAt, exp)`, so a forget of a record with no lease leaves a tombstone
   with none.
7. `MembershipPrincipals`: `alive(r.ExpiresAt, now) && !r.tombstone()`.

In `internal/store/memory/memory.go`, the same, with the three helpers beside `laterOf`:
1. `liveMembershipLocked`: `!alive(e.exp, s.now())`.
2. `liveKeyLocked` returns `(memberKeyEntry, bool)`, false when absent or past
   `alive(e.expires, s.now())`. `PutMembership` and `RefuseMapKeys` set `e.expires = exp` when it
   is false, else `laterExp(e.expires, exp)`; `exp` is `expiry(s.now(), ttl)` in both. Every other
   caller ignores the bool.
3. `GetMembership`: an entry with `forgottenAt` set returns `store.ErrForgotten`.
4. `DeleteMembership`: `exp: laterExp(e.exp, now.Add(store.TombstoneFloor))`.
5. The sweep (:333 and :338): `!alive(e.exp, now)` and `!alive(e.expires, now)`.

In `internal/store/etcd/feed.go`, add:

```go
// Revision is the store's current revision, from a linearizable read's
// header: where a feed that has read nothing begins (placement.FollowPins).
func (s *Store) Revision(ctx context.Context) (uint64, error) {
	resp, err := s.tok.Get(clientv3.WithRequireLeader(ctx), s.k.meta("ping"))
	if err != nil {
		return 0, unavailable(err)
	}
	return uint64(resp.Header.Revision), nil
}

// WatchMemberships calls fn with the principal of every put and delete of
// a membership record after `after` (placement.PinFeed; plan 11a, R13), on
// the token client, requiring a leader as WatchRevocations does; the record
// itself is not read, the cache reads it again. A key that does not parse
// is said and skipped. Progress notifications go to progress. A compacted
// revision is store.ErrCompacted; any other failure ErrUnavailable or
// ErrRefused.
func (s *Store) WatchMemberships(ctx context.Context, after uint64, fn func(principal string, rev uint64),
	progress func(uint64)) error {
	wctx, cancel := context.WithCancel(clientv3.WithRequireLeader(ctx))
	defer cancel()
	prefix := s.k.family(famMembership)
	ch := s.tok.Watch(wctx, prefix, clientv3.WithPrefix(), clientv3.WithRev(int64(after)+1),
		clientv3.WithProgressNotify(), clientv3.WithKeysOnly())
	for resp := range ch {
		if err := resp.Err(); err != nil {
			if resp.CompactRevision > 0 || errors.Is(err, rpctypes.ErrCompacted) {
				return store.ErrCompacted
			}
			return unavailable(err)
		}
		if resp.IsProgressNotify() {
			progress(uint64(resp.Header.Revision))
			continue
		}
		for _, ev := range resp.Events {
			p, err := url.PathUnescape(strings.TrimPrefix(string(ev.Kv.Key), prefix))
			if err != nil {
				s.logf("etcd: the membership key %q does not parse; the pins feed skipped it", ev.Kv.Key)
				continue
			}
			fn(p, uint64(ev.Kv.ModRevision))
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fmt.Errorf("%w: the pins watch ended", store.ErrUnavailable)
}
```

(`feed.go` imports `net/url` and `strings` if it does not already.) On the directory keyspace the
daemon's role cannot watch `mb/` (Task 7); only port49-broker runs `FollowPins`.

Run: `go test ./internal/store/ ./internal/store/memory/ ./internal/store/etcd/ ./internal/store/crypt/ ./internal/store/guard/ -run 'Membership' -count=1`
Expected: PASS: `MembershipWithNoExpiryOutlivesAnyTTL` on memory, etcd, the sealed and the guarded
layers, `TestWatchMembershipsTellsEachChange`, and every existing membership property. (The
placement package compiles in Step 4.)

- [ ] **Step 4: The router's membership half**

In `internal/store/placement/placement.go`, add to the package comment: "Directory membership is
split by write rate (R13): the directory holds the pin, with no lease; the session store the
freshness record." Then add:

```go
// Members is the directory store's membership half (R13): the pin, the map
// keys, refusals and the forget's tombstone, sealed as the session store's.
type Members interface {
	PutMembership(ctx context.Context, m store.Membership, ttl time.Duration) error
	GetMembership(ctx context.Context, principal string) (store.Membership, error)
	MembershipByKey(ctx context.Context, mapKey string) (store.Membership, error)
	RefuseMapKeys(ctx context.Context, mapKeys []string, at time.Time, ttl time.Duration) error
	DeleteMembership(ctx context.Context, principal string) (store.Membership, error)
}
```

Add to `Config`:

```go
	// Members is the directory's membership half; nil keeps membership
	// wholly in the session store (the daemon, which holds none).
	Members Members
	// Reachable is false while the directory is known not to answer: a
	// membership read then serves the session store's copy at once rather
	// than wait CallTimeout. Nil always tries.
	Reachable func() bool
	// Say is told once per principal per 10 minutes that a cached pin was
	// served, and each pin put back from this region's record; nil says
	// nothing.
	Say func(format string, args ...any)
```

and to `placed`: `mu sync.Mutex`, `said map[string]time.Time`, `pins map[string]pinEntry`,
`gens map[string]uint64` and `epoch uint64`, each map made in `Wrap`. Then:

```go
// pinOf is the part of m the directory keeps: the pin, the map keys, the
// refusal and when it was verified, which the tombstone rule compares.
func pinOf(m store.Membership) store.Membership {
	return store.Membership{Principal: m.Principal, EntryID: m.EntryID, MapKeys: m.MapKeys, Refused: m.Refused,
		VerifiedAt: m.VerifiedAt}
}

// pinOnly is a pin with none of its verification's freshness: no groups,
// and no verification time unless it is a refusal, whose time grace names.
// Grace serves nothing from it; Resolver.pinned holds the next
// verification to its entry (I2).
func pinOnly(pin store.Membership) store.Membership {
	out := store.Membership{Principal: pin.Principal, EntryID: pin.EntryID, MapKeys: pin.MapKeys, Refused: pin.Refused}
	if pin.Refused {
		out.VerifiedAt = pin.VerifiedAt
	}
	return out
}

// samePin reports whether a and b hold one pin.
func samePin(a, b store.Membership) bool {
	return a.EntryID == b.EntryID && a.Refused == b.Refused && slices.Equal(a.MapKeys, b.MapKeys)
}

func (p *placed) reachable() bool { return p.c.Reachable == nil || p.c.Reachable() }

// pinState is what the directory says of a principal's pin.
type pinState int

const (
	pinUnknown   pinState = iota // the directory did not answer, and nothing is cached
	pinHeld                      // pinned: pin holds it
	pinForgotten                 // a forget's tombstone: the principal is free
	pinAbsent                    // never pinned
)

// dirPin is the directory's pin for principal: the cache's, else a bounded
// read, filled when no change came between (I3). An error is a directory
// answer other than none or a cut.
func (p *placed) dirPin(ctx context.Context, principal string) (store.Membership, pinState, error) {
	if e, ok := p.cached(principal); ok {
		return e.pin, e.state, nil
	}
	if !p.reachable() {
		return store.Membership{}, pinUnknown, nil
	}
	gen := p.genOf(principal)
	var pin store.Membership
	err := bounded(ctx, p.c.CallTimeout, func(ctx context.Context) (x error) {
		pin, x = p.c.Members.GetMembership(ctx, principal)
		return
	})
	var st pinState
	switch {
	case err == nil:
		st = pinHeld
	case errors.Is(err, store.ErrForgotten):
		st = pinForgotten
	case errors.Is(err, store.ErrNotFound):
		st = pinAbsent
	case errors.Is(err, store.ErrUnavailable):
		return store.Membership{}, pinUnknown, nil
	default:
		return store.Membership{}, pinUnknown, err
	}
	p.fillPin(principal, gen, pinEntry{pin: pin, state: st})
	return pin, st, nil
}

// putPin writes m's pin to the directory with no lease, bounded, failing
// closed, and drops the cached entry: the next read takes the directory's,
// which the tombstone rule may have kept.
func (p *placed) putPin(ctx context.Context, m store.Membership) error {
	if !p.reachable() {
		return fmt.Errorf("%w: the directory store does not answer, so %s cannot be pinned", store.ErrUnavailable,
			printsafe.Line(m.Principal, 300))
	}
	err := bounded(ctx, p.c.CallTimeout, func(ctx context.Context) error {
		return p.c.Members.PutMembership(ctx, pinOf(m), store.NoExpiry)
	})
	p.dropPin(m.Principal)
	return err
}

// PutMembership writes the session's record always, and the directory's
// pin when the directory's own differs: a first bind, a re-pin (the same
// entry after a forget included), a changed map key or a refusal. With the
// directory not answering and the pin not cached, the session copy is
// compared instead: only a pinned member's refresh is taken.
func (p *placed) PutMembership(ctx context.Context, m store.Membership, ttl time.Duration) error {
	if p.c.Members == nil {
		return p.Store.PutMembership(ctx, m, ttl)
	}
	pin, st, err := p.dirPin(ctx, m.Principal)
	if err != nil {
		return err
	}
	switch {
	case st == pinHeld && samePin(pin, m):
	case st == pinUnknown:
		held, herr := p.Store.GetMembership(ctx, m.Principal)
		if herr != nil || !samePin(held, m) {
			return fmt.Errorf("%w: the directory store does not answer, so %s cannot be pinned", store.ErrUnavailable,
				printsafe.Line(m.Principal, 300))
		}
	default:
		if err := p.putPin(ctx, m); err != nil {
			return err
		}
	}
	return p.Store.PutMembership(ctx, m, ttl)
}

// GetMembership is the directory's pin with this region's freshness under
// it (R13). The pin comes from the cache FollowPins keeps (R4): a hit never
// waits on the directory. Forgotten is ErrForgotten, wherever it was
// forgotten. Absent, while this region's record holds a pin, is a pin the
// directory lost: it is put back from the record and the record served. A
// pin to another entry than this region's record answers the pin alone.
// With the directory not answering on a miss, the session's copy is served,
// and said.
func (p *placed) GetMembership(ctx context.Context, principal string) (store.Membership, error) {
	if p.c.Members == nil {
		return p.Store.GetMembership(ctx, principal)
	}
	local, lerr := p.Store.GetMembership(ctx, principal)
	if lerr != nil && !errors.Is(lerr, store.ErrNotFound) {
		return store.Membership{}, lerr
	}
	pin, st, err := p.dirPin(ctx, principal)
	if err != nil {
		return store.Membership{}, err
	}
	switch st {
	case pinForgotten:
		return store.Membership{}, store.ErrForgotten
	case pinAbsent:
		if lerr != nil {
			return store.Membership{}, store.ErrNotFound
		}
		if perr := p.putPin(ctx, local); perr == nil && p.c.Say != nil {
			p.c.Say("directory store: %s's pin (entry %s) was missing from the directory and is put back from this "+
				"region's record", printsafe.Line(principal, 300), printsafe.Line(local.EntryID, 120))
		}
		return local, nil // pinned by this region's record whether or not the put-back landed
	case pinHeld:
		if lerr == nil && local.EntryID == pin.EntryID {
			local.MapKeys, local.Refused = pin.MapKeys, pin.Refused
			return local, nil
		}
		return pinOnly(pin), nil // pinned elsewhere, or re-pinned to another entry (I2)
	}
	if lerr == nil {
		p.sayCached(principal)
	}
	return local, lerr
}

// pinEntry is the router's cached answer for one principal: the
// directory's pin record and its state. FollowPins drops an entry at each
// change, so a hit is never older than the feed's delivery.
type pinEntry struct {
	pin   store.Membership
	state pinState
}

// pinGen is a principal's cache generation: the cache's epoch, which
// dropPins moves, and the principal's own count, which dropPin moves.
type pinGen struct{ epoch, n uint64 }

func (p *placed) cached(principal string) (pinEntry, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.pins[principal]
	return e, ok
}

func (p *placed) genOf(principal string) pinGen {
	p.mu.Lock()
	defer p.mu.Unlock()
	return pinGen{p.epoch, p.gens[principal]}
}

// fillPin caches e for principal unless a change came since gen was read
// (I3): a fill read before a drop never outlives it.
func (p *placed) fillPin(principal string, gen pinGen, e pinEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if gen != (pinGen{p.epoch, p.gens[principal]}) {
		return
	}
	if len(p.pins) >= maxPins {
		clear(p.pins) // a miss refills; bounded memory over a directory of any size
	}
	p.pins[principal] = e
}

// dropPin drops principal's entry and moves its generation.
func (p *placed) dropPin(principal string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.pins, principal)
	if len(p.gens) >= maxPins {
		clear(p.gens)
		p.epoch++ // every fill in flight is dropped; none is wrongly kept
	}
	p.gens[principal]++
}

// dropPins drops every entry, and every fill in flight.
func (p *placed) dropPins() {
	p.mu.Lock()
	defer p.mu.Unlock()
	clear(p.pins)
	clear(p.gens)
	p.epoch++
}

func (p *placed) cachedPin(principal string) bool {
	_, ok := p.cached(principal)
	return ok
}

// maxPins bounds the pin cache and its generations.
const maxPins = 1 << 16

// PinFeed is the directory's membership family as a stream of changes
// (*etcd.Store).
type PinFeed interface {
	Revision(ctx context.Context) (uint64, error)
	WatchMemberships(ctx context.Context, after uint64, fn func(principal string, rev uint64),
		progress func(rev uint64)) error
}

// FollowPins keeps s's pin cache current from feed until ctx ends (R4,
// R13): each change drops its principal's entry. A watch that fails is
// tried again every second from the last revision delivered, the cache
// served meanwhile (a cut); a compacted one, which only a reachable
// directory can say, drops every entry, and misses refill them. up is told
// whether the watch runs. s not a router (a shared store) returns at once.
func FollowPins(ctx context.Context, s store.Store, feed PinFeed, up func(bool), logf func(string, ...any)) error {
	p, ok := s.(*placed)
	if !ok || p.c.Members == nil {
		return nil
	}
	var from uint64
	failing := false
	for {
		if from == 0 {
			rev, err := feed.Revision(ctx)
			if err == nil {
				p.dropPins() // what changed before the watch began is read afresh
				from = rev
			}
		}
		var err error
		if from != 0 {
			up(true)
			err = feed.WatchMemberships(ctx, from, func(principal string, rev uint64) {
				p.dropPin(principal)
				from = max(from, rev)
			}, func(rev uint64) { from = max(from, rev) })
			up(false)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, store.ErrCompacted) {
			from = 0 // reloads: Revision, then every entry dropped
			continue
		}
		if !failing {
			logf("directory store: the membership pins feed stopped (%v); serving the cached pins, trying again every second", err)
			failing = true
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// MembershipByKey is the directory's answer, which knows every region's
// claims and refusals; the session's while the directory does not answer.
func (p *placed) MembershipByKey(ctx context.Context, mapKey string) (store.Membership, error) {
	if p.c.Members == nil || !p.reachable() {
		return p.Store.MembershipByKey(ctx, mapKey)
	}
	var m store.Membership
	err := bounded(ctx, p.c.CallTimeout, func(ctx context.Context) (x error) {
		m, x = p.c.Members.MembershipByKey(ctx, mapKey)
		return
	})
	if errors.Is(err, store.ErrUnavailable) {
		return p.Store.MembershipByKey(ctx, mapKey)
	}
	if err != nil {
		return store.Membership{}, err
	}
	return p.GetMembership(ctx, m.Principal)
}

// RefuseMapKeys is a refusal: the directory's, with no lease, failing
// closed, then the session's.
func (p *placed) RefuseMapKeys(ctx context.Context, mapKeys []string, at time.Time, ttl time.Duration) error {
	if p.c.Members != nil {
		if !p.reachable() {
			return fmt.Errorf("%w: the directory store does not answer, so the refusal is not recorded",
				store.ErrUnavailable)
		}
		if err := bounded(ctx, p.c.CallTimeout, func(ctx context.Context) error {
			return p.c.Members.RefuseMapKeys(ctx, mapKeys, at, store.NoExpiry)
		}); err != nil {
			return err
		}
	}
	return p.Store.RefuseMapKeys(ctx, mapKeys, at, ttl)
}

// DeleteMembership is port49 directory forget: the directory first, failing
// closed, so every region reads the pin forgotten; then this region's copy.
func (p *placed) DeleteMembership(ctx context.Context, principal string) (store.Membership, error) {
	if p.c.Members == nil {
		return p.Store.DeleteMembership(ctx, principal)
	}
	if !p.reachable() {
		return store.Membership{}, fmt.Errorf("%w: the directory store does not answer, so nothing was forgotten",
			store.ErrUnavailable)
	}
	var held store.Membership
	if err := bounded(ctx, p.c.CallTimeout, func(ctx context.Context) (x error) {
		held, x = p.c.Members.DeleteMembership(ctx, principal)
		return
	}); err != nil {
		return store.Membership{}, err
	}
	p.dropPin(principal)
	if local, err := p.Store.DeleteMembership(ctx, principal); err == nil {
		return local, nil // the region's record names more than the pin
	}
	return held, nil
}

// sayCached says, once per principal per 10 minutes, that a cut directory's
// cached pin was served (R13: a region keeps serving a pinned member, and
// says so).
func (p *placed) sayCached(principal string) {
	if p.c.Say == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if t, ok := p.said[principal]; ok && time.Since(t) < 10*time.Minute {
		return
	}
	if len(p.said) > 1024 {
		clear(p.said)
	}
	p.said[principal] = time.Now()
	p.c.Say("directory store: not answering: serving %s's cached directory membership (its pin as this region "+
		"last read it); a forget made elsewhere reaches this region when the directory answers",
		printsafe.Line(principal, 300))
}
```

Imports gain `"slices"`, `"sync"` and `"github.com/rhwendt/port49/internal/printsafe"`.

`TestOneForgetReachesEveryRegion` relies on the memory store's `DeleteMembership` leaving a
tombstone, which `GetMembership` now answers as `ErrForgotten`, and on its `PutMembership` taking a
verification after the tombstone. Both are plan 7g's, kept by Step 3.

- [ ] **Step 5: Run them to verify they pass**

Run: `go test ./internal/store/... -count=1 -race`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/store/store.go internal/store/etcd/membership.go internal/store/memory/memory.go \
  internal/store/storetest internal/store/placement internal/store/etcd/feed.go internal/store/etcd/feed_test.go
git commit -m "feat: directory membership's pin in the directory store with no lease, its freshness per region

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 8b: Back-channel logout records in the directory store, followed into a local copy

**Files:**
- Create: `internal/store/logouts.go`
- Modify: `internal/store/etcd/oidc.go` (`Logouts`, `WatchLogouts`), `internal/store/placement/placement.go`
  (`PutLogout`, `GetLogout`)
- Test: `internal/store/logouts_test.go` (new), `internal/store/etcd/feed_test.go`,
  `internal/store/placement/logouts_test.go` (new)

**Interfaces:**
- Consumes: `placement.Wrap` (Task 6) and its `bounded` and `reachable` (Tasks 6, 8a).
- Produces:
  - `type store.LogoutEntry struct { Logout; Until time.Time }`.
  - `type store.LogoutSet`, with `NewLogoutSet(now func() time.Time)`, `Put(LogoutEntry)` (keeps
    the later `At` and the later `Until`, as `PutLogout` does), `Delete(key)`,
    `Get(key) (Logout, bool)` (a live entry only), `Merge([]LogoutEntry) []LogoutEntry` (a load: it puts each entry,
    keeps the live entries the load lacks, so a snapshot a concurrent Put outran never erases a logout
    (fail closed), and drops the lapsed; it returns the entries it did not hold before, by key and `At`), `All() []LogoutEntry` (the
    live entries) and `Len()` (the live entries only).
  - `type store.LogoutFeed interface { Logouts(ctx) (uint64, []LogoutEntry, error); WatchLogouts(ctx, after uint64, fn func(e LogoutEntry, deleted bool, rev uint64), progress func(uint64)) error }`,
    which `*etcd.Store` satisfies.
  - `func store.FollowLogouts(ctx, feed LogoutFeed, set *LogoutSet, from uint64, on func(LogoutEntry), up func(bool), logf func(string, ...any)) error`.
    `on` is told each put the watch delivers, and each record a load brings that the set did not
    hold (the pre-flight's I4: a reload after a long cut's compaction is reached too). A `from` of
    0 loads first.
  - `placement.Config.Logouts *store.LogoutSet` and
    `placement.Config.LogoutDir interface{ PutLogout(ctx, store.Logout, time.Duration) error }`.
    With both set, `PutLogout` writes the directory and puts the record in the set. With the
    directory not answering, it writes the session store instead: pending. `GetLogout` answers from
    the set, then the session store's pending records.
  - `type placement.PendingLogouts interface { Logouts(ctx) (uint64, []store.LogoutEntry, error); DeleteLogout(ctx, key string) error }`,
    which the session's `*etcd.Store` satisfies.
  - `func placement.ForwardPending(ctx, s store.Store, pending PendingLogouts) (forwarded, left int, err error)`.
  - `func (s *etcd.Store) DeleteLogout(ctx, key string) error`.

R26 (Q1, ruled by the team lead 2026-10-17 under standing autonomy; Ryan may overrule):
- The `lo/` records are the directory's. A logout received in any region refuses, everywhere, every
  mint and refresh it names.
- Each port49-broker loads them before it serves, follows them, and reads them from its own copy (R4).
  A mint never waits on the directory.
- Each region's runner reaches a logout it follows in its own session store (Task 8c): the owners'
  tokens, and the contexts by `sid`, or by owner for a `sub`.
- The owner records (`oo/`, written at every mint) and the logout token's `jti` stay session.
- With the directory cut, a logout is accepted and kept pending (R26 as amended):
  - `PutLogout` writes it to the session store, which in a split holds no other logout record, so
    every record there is pending, and returns nil.
  - `GetLogout` reads the set, then the session store, so this region refuses at once.
  - The logout handler reaches the owners' tokens and sessions as today, and answers 200.
  - `ForwardPending` (below), the runner's duty in Task 9, writes each pending record to the
    directory once it answers, puts it in the set, and deletes it from the session store.

- [ ] **Step 1: Write the failing tests**

Create `internal/store/logouts_test.go`:

```go
package store

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestLogoutSetKeepsTheLaterAndExpires(t *testing.T) {
	now := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	s := NewLogoutSet(func() time.Time { return now })
	s.Put(LogoutEntry{Logout: Logout{Key: "sid 1:i 1:s", At: now, Origin: "a"}, Until: now.Add(time.Hour)})
	s.Put(LogoutEntry{Logout: Logout{Key: "sid 1:i 1:s", At: now.Add(-time.Minute), Origin: "b"}, Until: now.Add(2 * time.Hour)})
	if l, ok := s.Get("sid 1:i 1:s"); !ok || !l.At.Equal(now) || l.Origin != "a" {
		t.Fatalf("%+v %v: the later At stands", l, ok)
	}
	now = now.Add(90 * time.Minute) // past the first Until, inside the second
	if _, ok := s.Get("sid 1:i 1:s"); !ok {
		t.Fatal("the later Until was not kept")
	}
	now = now.Add(time.Hour)
	if _, ok := s.Get("sid 1:i 1:s"); ok {
		t.Fatal("an expired logout is still served")
	}
	fresh := s.Merge([]LogoutEntry{{Logout: Logout{Key: "sub 1:i 1:u", At: now}, Until: now.Add(time.Hour)}})
	if s.Len() != 1 || len(fresh) != 1 || len(s.All()) != 1 {
		t.Fatalf("Merge left %d, told %d new", s.Len(), len(fresh))
	}
	if again := s.Merge(s.All()); len(again) != 0 {
		t.Fatalf("a load of what the set holds told %d as new", len(again))
	}
	s.Delete("sub 1:i 1:u")
	if _, ok := s.Get("sub 1:i 1:u"); ok {
		t.Fatal("a deleted logout is served")
	}
}

// fakeLogoutFeed fails its first load, then holds es; its watch delivers each
// entry sent on ch.
type fakeLogoutFeed struct {
	mu    sync.Mutex
	fails int
	es    []LogoutEntry
	ch    chan LogoutEntry
}

func (f *fakeLogoutFeed) Logouts(context.Context) (uint64, []LogoutEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fails > 0 {
		f.fails--
		return 0, nil, ErrUnavailable
	}
	return 3, f.es, nil
}

func (f *fakeLogoutFeed) WatchLogouts(ctx context.Context, _ uint64, fn func(LogoutEntry, bool, uint64),
	_ func(uint64)) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-f.ch:
			fn(e, false, 4)
		}
	}
}

func TestFollowLogoutsLoadsThenTellsEachPut(t *testing.T) {
	now := time.Now()
	set := NewLogoutSet(time.Now)
	f := &fakeLogoutFeed{fails: 1, ch: make(chan LogoutEntry),
		es: []LogoutEntry{{Logout: Logout{Key: "k1", At: now}, Until: now.Add(time.Hour)}}}
	told := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go FollowLogouts(ctx, f, set, 0, func(e LogoutEntry) { told <- e.Key }, func(bool) {}, func(string, ...any) {})
	select {
	case k := <-told: // I4: what a load brings is told, as a put is
		if k != "k1" {
			t.Fatalf("the load told %q", k)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the load's record was never told")
	}
	f.ch <- LogoutEntry{Logout: Logout{Key: "k2", At: now}, Until: now.Add(time.Hour)}
	if k := <-told; k != "k2" {
		t.Fatalf("told %q", k)
	}
	if _, ok := set.Get("k2"); !ok {
		t.Fatal("the delivered logout is not in the set")
	}
}
```

Create `internal/store/placement/logouts_test.go`:

```go
package placement

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
)

// R26: a logout is written to the directory and read from the set; with the
// directory cut it is accepted, kept pending in the session store, and
// refused here at once.
func TestALogoutIsTheDirectorysAndReadFromTheSet(t *testing.T) {
	ctx := context.Background()
	reach := true
	sess, dir := memory.New(clock), memory.New(clock)
	set := store.NewLogoutSet(clock)
	s := Wrap(Config{Session: sess, Directory: dir, Marks: store.NewMarks(), Logouts: set, LogoutDir: dir,
		Reachable: func() bool { return reach }, CallTimeout: time.Second, BulkTimeout: time.Second})
	l := store.Logout{Key: store.SidKey("https://idp", "s1"), At: t0, Origin: "logout"}
	if err := s.PutLogout(ctx, l, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := dir.GetLogout(ctx, l.Key); err != nil {
		t.Fatalf("the directory lacks the logout: %v", err)
	}
	if _, err := sess.GetLogout(ctx, l.Key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the session store holds a logout: %v", err)
	}
	reach = false
	if got, err := s.GetLogout(ctx, l.Key); err != nil || !got.At.Equal(t0) {
		t.Fatalf("the set's answer with the directory cut: %+v %v", got, err)
	}
	other := store.Logout{Key: store.SidKey("https://idp", "s2"), At: t0}
	if err := s.PutLogout(ctx, other, time.Hour); err != nil {
		t.Fatalf("a logout ingested during the cut: %v, want accepted (pending)", err)
	}
	if _, err := s.GetLogout(ctx, other.Key); err != nil {
		t.Fatalf("a pending logout is not refused here at once: %v", err)
	}
	if _, err := sess.GetLogout(ctx, other.Key); err != nil {
		t.Fatalf("the pending logout is not in the session store: %v", err)
	}
	if _, err := dir.GetLogout(ctx, other.Key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the cut directory took the logout: %v", err)
	}
}

// pendingFake is a session store's pending logouts, over a memory store's
// records (which lists none itself).
type pendingFake struct {
	st   *memory.Store
	keys []string
}

func (p *pendingFake) Logouts(ctx context.Context) (uint64, []store.LogoutEntry, error) {
	var out []store.LogoutEntry
	for _, k := range p.keys {
		if l, err := p.st.GetLogout(ctx, k); err == nil {
			out = append(out, store.LogoutEntry{Logout: l, Until: time.Now().Add(time.Hour)})
		}
	}
	return 1, out, nil
}

func (p *pendingFake) DeleteLogout(_ context.Context, key string) error {
	p.keys = slices.DeleteFunc(p.keys, func(k string) bool { return k == key })
	return nil
}

// The amendment's whole path: region a cut, a logout accepted there and
// pending; the heal; ForwardPending writes it to the directory and clears it;
// region b, whose set the feed then brings it to, refuses the session.
func TestALogoutDuringACutIsForwardedOnTheHealAndRefusedElsewhere(t *testing.T) {
	ctx := context.Background()
	reach := false
	sa, sb, dir := memory.New(clock), memory.New(clock), memory.New(clock)
	setA, setB := store.NewLogoutSet(clock), store.NewLogoutSet(clock)
	a := Wrap(Config{Session: sa, Directory: dir, Marks: store.NewMarks(), Logouts: setA, LogoutDir: dir,
		Reachable: func() bool { return reach }, CallTimeout: time.Second, BulkTimeout: time.Second})
	b := Wrap(Config{Session: sb, Directory: dir, Marks: store.NewMarks(), Logouts: setB, LogoutDir: dir,
		CallTimeout: time.Second, BulkTimeout: time.Second})
	l := store.Logout{Key: store.SidKey("https://idp", "s1"), At: t0, Origin: "backchannel_logout https://idp"}
	if err := a.PutLogout(ctx, l, time.Hour); err != nil {
		t.Fatal(err)
	}
	pending := &pendingFake{st: sa, keys: []string{l.Key}}
	if n, left, err := ForwardPending(ctx, a, pending); err == nil || n != 0 || left != 1 {
		t.Fatalf("forwarded during the cut: %d, %d left, %v", n, left, err)
	}
	if _, err := b.GetLogout(ctx, l.Key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("region b saw the logout during the cut: %v", err)
	}
	reach = true
	if n, left, err := ForwardPending(ctx, a, pending); err != nil || n != 1 || left != 0 {
		t.Fatalf("on the heal: forwarded %d, %d left, %v", n, left, err)
	}
	got, err := dir.GetLogout(ctx, l.Key)
	if err != nil {
		t.Fatalf("the directory lacks the forwarded logout: %v", err)
	}
	setB.Put(store.LogoutEntry{Logout: got, Until: time.Now().Add(time.Hour)}) // what b's FollowLogouts does
	if _, err := b.GetLogout(ctx, l.Key); err != nil {
		t.Fatalf("region b does not refuse the session after the heal: %v", err)
	}
	if len(pending.keys) != 0 {
		t.Fatalf("the forwarded logout is still pending: %v", pending.keys)
	}
}
```

Append to `internal/store/etcd/feed_test.go`:

```go
// The logouts feed: a load at one revision, then each put with its expiry.
func TestLogoutsLoadAndWatch(t *testing.T) {
	s := onShared(t, func() time.Time { return t0 })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.PutLogout(ctx, store.Logout{Key: "sid 1:i 2:s1", At: t0}, time.Hour); err != nil {
		t.Fatal(err)
	}
	rev, es, err := s.Logouts(ctx)
	if err != nil || len(es) != 1 || !es[0].Until.Equal(t0.Add(time.Hour)) {
		t.Fatalf("%v %+v %v", rev, es, err)
	}
	got := make(chan store.LogoutEntry, 1)
	go s.WatchLogouts(ctx, rev, func(e store.LogoutEntry, deleted bool, _ uint64) {
		if !deleted {
			got <- e
		}
	}, func(uint64) {})
	if err := s.PutLogout(ctx, store.Logout{Key: "sub 1:i 2:u1", At: t0}, time.Hour); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-got:
		if e.Key != "sub 1:i 2:u1" {
			t.Fatalf("told %+v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the put was not told")
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/store/ ./internal/store/placement/ ./internal/store/etcd/ -run 'Logout' -count=1`
Expected: FAIL to compile (`undefined: NewLogoutSet`).

- [ ] **Step 3: Implement**

Create `internal/store/logouts.go`:

```go
package store

import (
	"context"
	"errors"
	"sync"
	"time"
)

// LogoutEntry is a back-channel logout's record and when it lapses.
type LogoutEntry struct {
	Logout
	Until time.Time
}

// LogoutSet is a process's copy of the directory store's logout records
// (plan 11a, R26), loaded and followed as the marks are, so a mint's check
// never waits on the directory. It is safe for concurrent use.
type LogoutSet struct {
	mu  sync.RWMutex
	now func() time.Time
	m   map[string]LogoutEntry
}

func NewLogoutSet(now func() time.Time) *LogoutSet {
	return &LogoutSet{now: now, m: map[string]LogoutEntry{}}
}

// Put keeps the later At (with its origin) and the later Until, as
// PutLogout keeps them.
func (s *LogoutSet) Put(e LogoutEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.m[e.Key]; ok {
		if cur.At.After(e.At) {
			e.At, e.Origin = cur.At, cur.Origin
		}
		if cur.Until.After(e.Until) {
			e.Until = cur.Until
		}
	}
	s.m[e.Key] = e
}

func (s *LogoutSet) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
}

// Get is the live logout under key.
func (s *LogoutSet) Get(key string) (Logout, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.m[key]
	if !ok || !s.now().Before(e.Until) {
		return Logout{}, false
	}
	return e.Logout, true
}

// Merge is a load: each entry of es is put as Put does, each live entry
// the load lacks is kept, and each lapsed one is dropped. A load is a snapshot
// that a concurrent Put (an ingestion, a forward) may have outrun, and
// a logout must never be erased by one (fail closed); the cost is a logout
// lingering until its own Until. It returns the entries it did not hold
// before, by key and At, for the runner to reach (I4).
func (s *LogoutSet) Merge(es []LogoutEntry) []LogoutEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	m := make(map[string]LogoutEntry, len(s.m)+len(es))
	for k, e := range s.m {
		if now.Before(e.Until) {
			m[k] = e
		}
	}
	var fresh []LogoutEntry
	for _, e := range es {
		cur, ok := m[e.Key]
		if !ok || !cur.At.Equal(e.At) {
			fresh = append(fresh, e)
		}
		if ok {
			if cur.At.After(e.At) {
				e.At, e.Origin = cur.At, cur.Origin
			}
			if cur.Until.After(e.Until) {
				e.Until = cur.Until
			}
		}
		m[e.Key] = e
	}
	s.m = m
	return fresh
}

// All is every live entry, for a takeover's reach and the directory
// snapshot (R19, R29).
func (s *LogoutSet) All() []LogoutEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := s.now()
	out := make([]LogoutEntry, 0, len(s.m))
	for _, e := range s.m {
		if now.Before(e.Until) {
			out = append(out, e)
		}
	}
	return out
}

// Len counts the live entries, as the operator line says them.
func (s *LogoutSet) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now, n := s.now(), 0
	for _, e := range s.m {
		if now.Before(e.Until) {
			n++
		}
	}
	return n
}

// LogoutFeed is the directory's logout records as a stream.
type LogoutFeed interface {
	Logouts(ctx context.Context) (uint64, []LogoutEntry, error)
	WatchLogouts(ctx context.Context, after uint64, fn func(e LogoutEntry, deleted bool, rev uint64),
		progress func(rev uint64)) error
}

// FollowLogouts keeps set current from feed after from until ctx ends (R26).
// A from of 0 loads first. Each put the watch delivers is put in set and told
// to on (nil tells nothing): the runner reaches it; so is each record a load
// brings that the set did not hold (I4); a delete (the record's lease) is
// dropped. A compacted watch loads again; a failed one is tried
// again every second, from the last change or progress delivered, the set
// served meanwhile. up says whether the watch runs.
func FollowLogouts(ctx context.Context, feed LogoutFeed, set *LogoutSet, from uint64, on func(LogoutEntry),
	up func(bool), logf func(string, ...any)) error {
	failing := false
	for {
		var err error
		if from == 0 {
			var rev uint64
			var es []LogoutEntry
			if rev, es, err = feed.Logouts(ctx); err == nil {
				fresh := set.Merge(es)
				from = max(rev, 1)
				for _, e := range fresh {
					if on != nil {
						on(e)
					}
				}
			}
		}
		if from != 0 {
			up(true)
			err = feed.WatchLogouts(ctx, from, func(e LogoutEntry, deleted bool, rev uint64) {
				from = max(from, rev)
				if deleted {
					set.Delete(e.Key)
					return
				}
				set.Put(e)
				if on != nil {
					on(e)
				}
			}, func(rev uint64) { from = max(from, rev) })
			up(false)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, ErrCompacted) {
			from = 0
			continue
		}
		if !failing {
			logf("store: the logouts feed stopped (%v); serving the logouts this process holds, trying again every second", err)
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

In `internal/store/etcd/oidc.go`, add (`url`, `strings`, `errors`, `rpctypes` and `clientv3` as
`feed.go` imports them):

```go
// Logouts is every live logout record at one revision, which it returns
// (store.LogoutFeed; plan 11a, R26). A record that does not decode is said
// by its key and skipped.
func (s *Store) Logouts(ctx context.Context) (uint64, []store.LogoutEntry, error) {
	prefix := s.k.family(famLogout)
	resp, err := s.tok.Get(clientv3.WithRequireLeader(ctx), prefix, clientv3.WithPrefix())
	if err != nil {
		return 0, nil, unavailable(err)
	}
	now := s.now()
	var out []store.LogoutEntry
	for _, kv := range resp.Kvs {
		e, ok := s.logoutEntry(prefix, kv.Key, kv.Value)
		if ok && now.Before(e.Until) {
			out = append(out, e)
		}
	}
	return uint64(resp.Header.Revision), out, nil
}

// WatchLogouts calls fn for every put and delete of a logout record after
// `after`, as WatchRevocations does for the marks.
func (s *Store) WatchLogouts(ctx context.Context, after uint64, fn func(store.LogoutEntry, bool, uint64),
	progress func(uint64)) error {
	wctx, cancel := context.WithCancel(clientv3.WithRequireLeader(ctx))
	defer cancel()
	prefix := s.k.family(famLogout)
	ch := s.tok.Watch(wctx, prefix, clientv3.WithPrefix(), clientv3.WithRev(int64(after)+1),
		clientv3.WithProgressNotify())
	for resp := range ch {
		if err := resp.Err(); err != nil {
			if resp.CompactRevision > 0 || errors.Is(err, rpctypes.ErrCompacted) {
				return store.ErrCompacted
			}
			return unavailable(err)
		}
		if resp.IsProgressNotify() {
			progress(uint64(resp.Header.Revision))
			continue
		}
		for _, ev := range resp.Events {
			rev := uint64(ev.Kv.ModRevision)
			if ev.Type == clientv3.EventTypeDelete {
				if k, err := url.PathUnescape(strings.TrimPrefix(string(ev.Kv.Key), prefix)); err == nil {
					fn(store.LogoutEntry{Logout: store.Logout{Key: k}}, true, rev)
				}
				continue
			}
			if e, ok := s.logoutEntry(prefix, ev.Kv.Key, ev.Kv.Value); ok {
				fn(e, false, rev)
			}
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fmt.Errorf("%w: the logouts watch ended", store.ErrUnavailable)
}

// DeleteLogout removes the logout record under key: a pending logout the
// runner forwarded to the directory (placement.ForwardPending). None is not
// an error.
func (s *Store) DeleteLogout(ctx context.Context, key string) error {
	_, err := s.tok.Delete(ctx, s.k.logout(key))
	return unavailable(err)
}

// logoutEntry decodes one lo/ key and value, saying by its key alone one
// that does not.
func (s *Store) logoutEntry(prefix string, key, value []byte) (store.LogoutEntry, bool) {
	k, err := url.PathUnescape(strings.TrimPrefix(string(key), prefix))
	var r logoutRec
	if err != nil || json.Unmarshal(value, &r) != nil {
		s.logf("etcd: the logout record at %q does not decode; the logouts feed skipped it", key)
		return store.LogoutEntry{}, false
	}
	return store.LogoutEntry{Logout: store.Logout{Key: k, At: r.At, Origin: r.Origin}, Until: r.ExpiresAt}, true
}
```

In `internal/store/placement/placement.go`, add to `Config`:

```go
	// Logouts is the process's copy of the directory's logout records, and
	// LogoutDir where a logout is written (R26). With both nil, logouts stay
	// the session store's.
	Logouts   *store.LogoutSet
	LogoutDir interface {
		PutLogout(ctx context.Context, l store.Logout, ttl time.Duration) error
	}
```

and:

```go
// PutLogout is a back-channel logout's ingestion: the directory, then this
// process's set, so its own mints refuse at once. With the directory not
// answering it is never lost (R26 as amended): it is written to the session
// store, where every logout record is pending in a split, the line says
// so, and ForwardPending carries it to the directory on the heal. Only a
// session store that fails too is an error.
func (p *placed) PutLogout(ctx context.Context, l store.Logout, ttl time.Duration) error {
	if p.c.Logouts == nil || p.c.LogoutDir == nil {
		return p.Store.PutLogout(ctx, l, ttl)
	}
	err := errNotAnswering
	if p.reachable() {
		err = bounded(ctx, p.c.CallTimeout, func(ctx context.Context) error { return p.c.LogoutDir.PutLogout(ctx, l, ttl) })
	}
	switch {
	case err == nil:
		p.c.Logouts.Put(store.LogoutEntry{Logout: l, Until: time.Now().Add(ttl)})
		return nil
	case !errors.Is(err, store.ErrUnavailable):
		return err
	}
	if err := p.Store.PutLogout(ctx, l, ttl); err != nil {
		return err
	}
	if p.c.Say != nil {
		p.c.Say("directory store: not answering: a back-channel logout was applied in this region and is pending; " +
			"it is forwarded to the directory, and so to every region, once the directory answers")
	}
	return nil
}

var errNotAnswering = fmt.Errorf("%w: the directory store is not answering", store.ErrUnavailable)

// GetLogout is the process's set's answer (R4), then this region's pending
// records: a mint or refresh never waits on the directory.
func (p *placed) GetLogout(ctx context.Context, key string) (store.Logout, error) {
	if p.c.Logouts == nil {
		return p.Store.GetLogout(ctx, key)
	}
	if l, ok := p.c.Logouts.Get(key); ok {
		return l, nil
	}
	return p.Store.GetLogout(ctx, key)
}

// PendingLogouts is the session store's logout records, every one pending
// in a split (the session's *etcd.Store).
type PendingLogouts interface {
	Logouts(ctx context.Context) (uint64, []store.LogoutEntry, error)
	DeleteLogout(ctx context.Context, key string) error
}

// ForwardPending writes each pending logout to the directory, with the
// life it has left, puts it in the set, and deletes it from the session
// store (R26 as amended): the runner's duty while the directory answers.
// It returns how many it forwarded and how many are left; it stops at the
// first the directory does not take. s not a router does nothing.
func ForwardPending(ctx context.Context, s store.Store, pending PendingLogouts) (forwarded, left int, err error) {
	p, ok := s.(*placed)
	if !ok || p.c.Logouts == nil || p.c.LogoutDir == nil {
		return 0, 0, nil
	}
	_, es, err := pending.Logouts(ctx)
	if err != nil {
		return 0, 0, err
	}
	for i, e := range es {
		ttl := time.Until(e.Until)
		if ttl <= 0 {
			_ = pending.DeleteLogout(ctx, e.Key) // lapsed: nothing left to refuse
			continue
		}
		if !p.reachable() {
			return forwarded, len(es) - i, errNotAnswering
		}
		if err := bounded(ctx, p.c.CallTimeout, func(ctx context.Context) error {
			return p.c.LogoutDir.PutLogout(ctx, e.Logout, ttl)
		}); err != nil {
			return forwarded, len(es) - i, err
		}
		p.c.Logouts.Put(e)
		if err := pending.DeleteLogout(ctx, e.Key); err != nil {
			return forwarded, len(es) - i, err
		}
		forwarded++
	}
	return forwarded, 0, nil
}
```

The placement test's memory clock is fixed at `t0`, and the set's `Until` is from `time.Now()`.
Build the set with `clock` (as the test does): `Get` then reads `t0` against
`time.Now().Add(ttl)`, which is later. That is consistent.

- [ ] **Step 4: Run them to verify they pass**

Run: `go test ./internal/store/ ./internal/store/placement/ ./internal/store/etcd/ -count=1 -race`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/logouts.go internal/store/logouts_test.go internal/store/etcd/oidc.go internal/store/etcd/feed_test.go internal/store/placement
git commit -m "feat: back-channel logout records in the directory store, followed into each broker's copy

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 8c: A logout followed from another region reaches this region's sessions

**Files:**
- Modify: `internal/broker/logout.go` (`logoutOne` :300 split; `ReachLogout`), `internal/store/store.go`
  (`ParseOIDCKey`)
- Test: `internal/broker/logout_regions_test.go` (new), `internal/store/oidckey_test.go` (new)

**Interfaces:**
- Consumes: `store.Logout`; `logoutOne`'s steps after `PutLogout`.
- Produces:
  - `func store.ParseOIDCKey(key string) (kind, issuer, value string, ok bool)`, the inverse of
    `OIDCKey`.
  - `func (b *Broker) ReachLogout(ctx context.Context, l store.Logout) (RevokeReport, error)`: the
    reach of `logoutOne` (owners' tokens; contexts by `sid`, or by owner for a `sub`; a `sub`'s
    receipts) in this broker's session store, with no `PutLogout` and no record. Task 9's runner
    calls it for each logout it follows.

- [ ] **Step 1: Write the failing tests**

Create `internal/store/oidckey_test.go`:

```go
package store

import "testing"

func TestParseOIDCKeyInvertsOIDCKey(t *testing.T) {
	for _, c := range [][3]string{{OIDCSid, "https://idp.example.com/realms/corp", "a b:c"}, {OIDCSub, "i", "u-1"}} {
		kind, iss, v, ok := ParseOIDCKey(OIDCKey(c[0], c[1], c[2]))
		if !ok || kind != c[0] || iss != c[1] || v != c[2] {
			t.Fatalf("%v: %q %q %q %v", c, kind, iss, v, ok)
		}
	}
	for _, bad := range []string{"", "sid", "sid 9:short 1:x", "sid 1:i 5:x", "jti 1:i 1:x"} {
		if _, _, _, ok := ParseOIDCKey(bad); ok {
			t.Fatalf("%q parsed", bad)
		}
	}
}
```

Create `internal/broker/logout_regions_test.go`, on the logout tests' own fixture (`oidcLoggedIn`,
`contextRevokedAt`, `logout_test.go`):

```go
package broker

import (
	"context"
	"testing"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
)

// R26: a logout another region ingested reaches this region: the session's
// context marked and the person's unspent tokens deleted, with no logout
// record written here and no revoke record.
func TestReachLogoutReachesThisRegionsSessions(t *testing.T) {
	ctx := context.Background()
	f, iss, _ := oidcLoggedIn(t)
	before := len(eventsOf(f.records(t), decision.EventRevoke))
	key := store.SidKey(iss.URL, "s-sub-alice")
	rep, err := f.b.ReachLogout(ctx, store.Logout{Key: key, At: f.now, Origin: "backchannel_logout " + iss.URL})
	if err != nil || len(rep.Contexts) == 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	if contextRevokedAt(t, f, "leaf1").IsZero() {
		t.Fatal("the session's context was not marked")
	}
	if toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: "nx1", Username: "alice"}); len(toks) != 0 {
		t.Fatal("the person's unspent token on nx1 survived")
	}
	if _, err := f.st.GetLogout(ctx, key); err == nil {
		t.Fatal("ReachLogout wrote a logout record")
	}
	if n := len(eventsOf(f.records(t), decision.EventRevoke)); n != before {
		t.Fatalf("ReachLogout wrote %d revoke record(s)", n-before)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/store/ ./internal/broker/ -run 'ParseOIDCKey|ReachLogout' -count=1`
Expected: FAIL to compile (`undefined: ParseOIDCKey`).

- [ ] **Step 3: Implement**

In `internal/store/store.go`, beside `OIDCKey`:

```go
// ParseOIDCKey is OIDCKey's inverse: the kind, issuer and value of a key
// it made, and false for anything else (plan 11a: a runner reaches a logout
// it followed by its key alone).
func ParseOIDCKey(key string) (kind, issuer, value string, ok bool) {
	kind, rest, found := strings.Cut(key, " ")
	if !found || (kind != OIDCSid && kind != OIDCSub) {
		return "", "", "", false
	}
	part := func(s string) (string, string, bool) {
		n, tail, found := strings.Cut(s, ":")
		l, err := strconv.Atoi(n)
		if !found || err != nil || l <= 0 || l > len(tail) {
			return "", "", false
		}
		return tail[:l], tail[l:], true
	}
	issuer, rest, ok1 := part(rest)
	if !ok1 || !strings.HasPrefix(rest, " ") {
		return "", "", "", false
	}
	value, rest, ok2 := part(rest[1:])
	if !ok2 || rest != "" {
		return "", "", "", false
	}
	return kind, issuer, value, true
}
```

(`store.go` imports `strconv`.)

In `internal/broker/logout.go`, split `logoutOne` after its `PutLogout`. Move everything from
`note := func(err error) {` through the receipts loop into:

```go
// reachLogout is a logout's reach in this broker's session store, by key
// (spec §5.1.4; plan 7h Rulings 22, 24): the owners within domains, their
// tokens, and the contexts by sid, or by owner for a sub, and a sub's
// receipts. It fills rep.
func (b *Broker) reachLogout(ctx context.Context, key string, domains []string, rep *RevokeReport) {
```

with its body exactly the moved lines: `lt.Domains` becomes `domains`, and `rep.` stays `rep.`
through the pointer. The moved lines use `now`, which `logoutOne` declares before `PutLogout`; the
body's first line declares its own, `now := rep.Mark.At`, which `logoutOne` set to its `now` and
`ReachLogout` sets below (the pre-flight's minor 6). `logoutOne` calls `b.reachLogout(ctx, key, lt.Domains, &rep)` where the
lines were, and keeps its record and its line. Then add:

```go
// ReachLogout reaches, in this broker's session store, a logout another
// region ingested (plan 11a, R26): the runner calls it for each logout it
// follows. It writes no logout record and no revoke record; the region that
// ingested the logout recorded it. A key naming no verifier of this broker
// reaches nothing, said.
func (b *Broker) ReachLogout(ctx context.Context, l store.Logout) (RevokeReport, error) {
	kind, issuer, value, ok := store.ParseOIDCKey(l.Key)
	if !ok || b.Identity == nil {
		return RevokeReport{}, fmt.Errorf("broker: a followed logout's key does not name an OIDC session or subject")
	}
	domains := b.Identity.HumanDomains(issuer)
	if len(domains) == 0 {
		return RevokeReport{}, fmt.Errorf("broker: a followed logout names issuer %s, which no human verifier here "+
			"trusts; nothing reached", printsafe.Line(issuer, 200))
	}
	rep := RevokeReport{By: ByLogoutSub, OIDCIssuer: issuer, Sub: value, Request: RevokeRequest{Origin: l.Origin},
		Mark: store.Revocation{At: b.Now()}}
	if kind == store.OIDCSid {
		rep.By, rep.Sid, rep.Sub = ByLogoutSid, value, ""
	}
	b.reachLogout(ctx, l.Key, domains, &rep)
	rep.Unreached = b.unreachedOf(rep.Contexts)
	return rep, rep.Err
}
```

`oidc.Set.HumanDomains(iss)` is the principal_domains of the issuer's human verifiers, which a
logout token's `Domains` is filled from.

- [ ] **Step 4: Run them to verify they pass**

Run: `go test ./internal/store/ ./internal/broker/ -count=1`
Expected: PASS: the new tests, and every existing logout test unchanged.

- [ ] **Step 5: Commit**

```bash
git add internal/store/store.go internal/store/oidckey_test.go internal/broker/logout.go internal/broker/logout_regions_test.go
git commit -m "feat: Broker.ReachLogout, a logout followed from another region reached here

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 9: port49-broker on two stores

**Files:**
- Create: `internal/port49d/storeref.go`, `internal/port49d/fresh.go`
- Modify: `internal/port49d/store.go` (`waitForStore` :143, `attempt` :590, `openIdentity` :640, `identity` :668,
  `checkRoles` :754; `openStores`'s call), `internal/port49d/brokerd.go` (`brokerStores` :83, `openBroker`
  :104, `runBroker`'s marks feed :558 and the runner :435, Task 2's refusal),
  `internal/port49d/runner.go` (`runner` :27, `duties` :171), `internal/port49d/offline.go` (`offlineBroker` :222),
  `internal/port49d/signin.go` (`wirePasswordSignIn`'s handle), `internal/daemon/metrics/metrics.go`
- Modify (tests): `internal/port49d/brokerd_test.go` (the `fleet` struct)
- Test: `internal/port49d/twostores_linux_test.go` (new)

**Interfaces:**
- Consumes:
  - `config.StoresConfig` (Task 2);
  - `store.Marks.Get` and `store.Freshness` (Task 3);
  - `placement.Wrap` (Task 6);
  - `etcd.Scope`, `CheckIdentityAt` (Task 7);
  - `Broker.ReachMark` (Task 8);
  - `placement.Config.Members`, `Reachable` and `Say` (Task 8a);
  - `store.LogoutSet`, `store.FollowLogouts`, `placement.Config.Logouts` and `LogoutDir` (Task 8b);
  - `Broker.ReachLogout` (Task 8c).
- Produces, all in `package port49d`:
  - `type storeRef struct { at string; cfg config.StoreConfig; scope etcdstore.Scope; dir bool }`,
    with `sessionRef(cfg)`, `directoryRef(cfg)` and `(storeRef).certLabel(name string) string`;
  - `attempt(ctx, cfg, ref storeRef, m, out)` and `waitForStore(ctx, cfg, ref storeRef, m, out, again, closed)`;
  - `type dirHandle` (`set`, `get`, `close`; a `placement.Directory`), and `var errNoDirectory`;
  - `var directoryCheckEvery = time.Second`;
  - `keepFresh(ctx, h *dirHandle, fresh *store.Freshness, timeout time.Duration, out io.Writer, proc string)`;
  - `ageText(d time.Duration) string`;
  - the fields `brokerStores.dir *dirHandle` and `brokerStores.fresh *store.Freshness`;
  - the runner's `followed chan store.Revocation`, `(*runner).follow(store.MarkChange)` and
    `(*runner).reachFollowed(ctx)`;
  - the metrics `StoreDirectoryReachable` and `StoreDirectoryConfirmed`;
  - in tests: `rolesMemberScoped`, `(*fleet).twoStores`, `(*fleet).twoStoresOn`, `withDirectory`,
    `addUnderDirectoryEtcd`, `adminSocketOf` and `keysUnder`.

- [ ] **Step 1: Write the failing tests**

In `internal/port49d/brokerd_test.go`, add three fields to `fleet`:

```go
	// dsrv is the directory store's member when the fleet has one of its own
	// (twoStores); dproxy is the broker's way to it and ddproxy the daemon's,
	// so a test cuts either alone.
	dsrv            *etcdtest.Server
	dproxy, ddproxy *etcdtest.Proxy
```

Create `internal/port49d/twostores_linux_test.go`:

```go
package port49d

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/admin"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/store/etcd"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
)

// rolesMemberScoped is a TLS etcd member with the roles of a keyspace
// holding scope's families (plan 11a, R23), and a proxy to it.
func rolesMemberScoped(t *testing.T, scope etcd.Scope) (*etcdtest.Server, *etcdtest.Proxy) {
	t.Helper()
	srv := etcdtest.Start(t, etcdtest.Options{TLS: true})
	var grants []etcdtest.Grant
	for _, g := range etcd.RolesFor("/port49/", scope) {
		grants = append(grants, etcdtest.Grant{Role: g.Role, Key: g.Key, RangeEnd: g.RangeEnd, Write: g.Write})
	}
	srv.EnableAuth(t, grants, map[string][]string{"port49-daemon": {etcd.RoleDaemon}, "port49-broker": {etcd.RoleBroker}})
	return srv, etcdtest.NewProxy(t, strings.TrimPrefix(srv.Endpoint, "https://"))
}

// twoStores gives f a directory store of its own on a member of its own: f's
// store becomes the session store.
func (f *fleet) twoStores(t *testing.T) {
	t.Helper()
	srv, _ := rolesMemberScoped(t, etcd.ScopeDirectory)
	f.twoStoresOn(t, srv)
}

// twoStoresOn is twoStores on a directory member another fleet made: two
// regions sharing one directory. The daemon and the broker each reach it
// through a proxy of their own.
func (f *fleet) twoStoresOn(t *testing.T, srv *etcdtest.Server) {
	t.Helper()
	ep := strings.TrimPrefix(srv.Endpoint, "https://")
	f.dsrv, f.dproxy, f.ddproxy = srv, etcdtest.NewProxy(t, ep), etcdtest.NewProxy(t, ep)
	dc, dk := srv.ClientFiles(t, "port49-daemon")
	bc, bk := srv.ClientFiles(t, "port49-broker")
	withDirectory(t, f.daemon, f.ddproxy, srv, "daemon", dc, dk)
	withDirectory(t, f.broker, f.dproxy, srv, "broker", bc, bk)
}

// withDirectory rewrites the file at path: its stores.directory block
// becomes stores.session, and a directory block before it names the member
// behind proxy, with the identity role (daemon or broker) at cert and key.
func withDirectory(t *testing.T, path string, proxy *etcdtest.Proxy, srv *etcdtest.Server, role, cert, key string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dir := fmt.Sprintf("stores:\n  directory:\n    backend: etcd\n    etcd:\n      endpoints: [https://%s]\n"+
		"      ca_file: %s\n      %s: {cert_file: %s, key_file: %s}\n      call_timeout: 200ms\n  session:\n",
		proxy.Addr(), filepath.Join(srv.Dir, "ca.pem"), role, cert, key)
	body := strings.Replace(string(raw), "stores:\n  directory:\n", dir, 1)
	if body == string(raw) {
		t.Fatalf("%s has no stores.directory block", path)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// addUnderDirectoryEtcd inserts line (no indent, no newline) under the
// directory store's etcd: block, the first in a two-store file.
func addUnderDirectoryEtcd(t *testing.T, path, line string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(string(raw), "    etcd:\n", "    etcd:\n      "+line+"\n", 1)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// adminSocketOf is the admin_socket the config at path names.
func adminSocketOf(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^admin_socket: (\S+)$`).FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatalf("%s names no admin_socket", path)
	}
	return m[1]
}

// keysUnder counts the keys under prefix on srv, read as etcd's root.
func keysUnder(t *testing.T, srv *etcdtest.Server, prefix string) int64 {
	t.Helper()
	resp, err := srv.Client(t, "root").Get(context.Background(), prefix, clientv3.WithPrefix(), clientv3.WithCountOnly())
	if err != nil {
		t.Fatal(err)
	}
	return resp.Count
}

// R11: on two stores port49-broker loads the marks from the directory store
// and writes a revocation's mark there, never in the session store.
func TestABrokerOnTwoStoresMarksInTheDirectory(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	startBroker(t, f.broker, &out, 1)
	waitFor(t, &out, "port49-broker: store: 0 revocation(s) in force from the directory store")
	r, err := ask(adminSocketOf(t, f.broker), admin.Request{Op: "revoke", Principal: "user:alice@example.com"})
	if err != nil || r.Error != "" {
		t.Fatalf("%+v %v", r, err)
	}
	if n := keysUnder(t, f.dsrv, "/port49/v1/rv/"); n != 1 {
		t.Fatalf("%d marks in the directory store, want 1", n)
	}
	if n := keysUnder(t, f.srv, "/port49/v1/rv/"); n != 0 {
		t.Fatalf("%d marks in the session store, want 0", n)
	}
}

// Review Focus 5: with the directory cut, a revocation is refused within the
// directory's call_timeout, saying it could not be recorded, and the
// broker says the directory is not answering.
func TestARevocationWithTheDirectoryCutFailsPromptly(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	startBroker(t, f.broker, &out, 1)
	f.dproxy.Hang(true)
	start := time.Now()
	r, err := ask(adminSocketOf(t, f.broker), admin.Request{Op: "revoke", Principal: "user:alice@example.com"})
	if err != nil || !strings.Contains(r.Error, "could not be recorded") || time.Since(start) > 5*time.Second {
		t.Fatalf("%+v %v after %v", r, err, time.Since(start))
	}
	waitWithin(t, &out, "port49-broker: directory store: not answering", 10*time.Second)
}

// R20: a mark another region made reaches this region's tokens: its runner
// follows it and deletes them from its own session store.
func TestAMarkMadeInAnotherRegionReachesThisRegionsTokens(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	a := splitFleet(t)
	a.twoStores(t)
	a.judged(t)
	c := splitFleet(t)
	c.twoStoresOn(t, a.dsrv)
	c.judged(t)
	startBroker(t, a.broker, &out, 1)
	apiC, _ := startBroker(t, c.broker, &out, 2)
	// Both runners hold their keyspaces before the revocation: a replica that
	// does not run leaves a followed mark to the runner (R29).
	waitCountWithin(t, &out, "port49-broker: runner: took keyspace", 2, 30*time.Second)
	_ = mintOn(t, apiC, c.pki, "leaf1") // held unspent in region c; never printed
	if n := keysUnder(t, c.srv, "/port49/v1/t/"); n != 1 {
		t.Fatalf("setup: %d token record(s) in region c", n)
	}
	r, err := ask(adminSocketOf(t, a.broker), admin.Request{Op: "revoke", Principal: "user:alice@example.com"})
	if err != nil || r.Error != "" {
		t.Fatalf("%+v %v", r, err)
	}
	waitWithin(t, &out, "a revocation of user:alice@example.com made elsewhere reached 1 token key(s)", 30*time.Second)
	if n := keysUnder(t, c.srv, "/port49/v1/t/"); n != 0 {
		t.Fatalf("%d token record(s) left in region c's session store", n)
	}
}

// R5: the enrollment store is the directory store: an unlock written
// through the broker's handle lands in the directory member, under ul/.
func TestPasswordSignInUsesTheDirectoryStore(t *testing.T) {
	srv, proxy := rolesMemberScoped(t, etcd.ScopeDirectory)
	cfg, _ := signInConfig(t, "127.0.0.1:0")
	cfg.Broker.Directory.EnrollmentStore = directory.EnrollmentStore{Backend: config.BackendEtcd}
	cfg.Stores.Directory = config.StoreConfig{Backend: config.BackendEtcd, Etcd: &config.EtcdConfig{
		Endpoints: []string{"https://" + proxy.Addr()}, CallTimeout: 500 * time.Millisecond, BulkTimeout: 5 * time.Second,
		Breaker:     config.EtcdBreaker{Failures: 5, OpenFor: time.Second},
		MaxInFlight: config.EtcdInFlight{Token: 8, Context: 8, Bulk: 2}}}
	raw, err := etcd.Open(etcd.Config{Endpoints: []string{"https://" + proxy.Addr()}, TLS: srv.TLS(t, "port49-broker"),
		Prefix: "/port49/"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	m := metrics.New(prometheus.NewRegistry())
	b := builtSignInBroker(t, cfg, m)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out syncBuffer
	dir := &dirHandle{}
	dir.set(raw)
	wirePasswordSignIn(ctx, cfg, b, signInTestKeys, m, dir, &out)
	if err := b.Enrollments.PutUnlock(ctx, "user:alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	if n := keysUnder(t, srv, "/port49/v1/ul/"); n != 1 {
		t.Fatalf("%d unlock record(s) in the directory store, want 1", n)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/port49d/ -run 'TwoStores|ABrokerOnTwoStores|RevocationWithTheDirectoryCut|AnotherRegion|SignInUsesTheDirectory' -count=1`
Expected: FAIL to compile: `undefined: dirHandle` (Step 3 adds it, and Step 5 makes it
`wirePasswordSignIn`'s handle). Once it compiles and before Step 5, the two-store fleet refuses to
start ("this build serves one store", Task 2's refusal).

- [ ] **Step 3: `storeref.go`, `fresh.go` and the metrics**

Create `internal/port49d/storeref.go`:

```go
package port49d

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/store"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
)

// storeRef is one of port49's two stores as a process opens it (plan 11a;
// decision 51): the config path its lines name, its resolved block, the
// scope its roles are checked against, and whether it is the directory
// store of its own.
type storeRef struct {
	at    string
	cfg   config.StoreConfig
	scope etcdstore.Scope
	dir   bool
}

// sessionRef is the store that serves sessions: the one store when shared.
func sessionRef(cfg config.Config) storeRef {
	scope := etcdstore.ScopeShared
	if !cfg.Stores.Shared {
		scope = etcdstore.ScopeSession
	}
	return storeRef{at: cfg.Stores.SessionPath(), cfg: cfg.Stores.Session, scope: scope}
}

// directoryRef is the directory store of its own, which only a split opens.
func directoryRef(cfg config.Config) storeRef {
	return storeRef{at: "stores.directory", cfg: cfg.Stores.Directory, scope: etcdstore.ScopeDirectory, dir: true}
}

// certLabel is the component label of name's identity on this store in
// port49_store_client_cert_expiry_timestamp_seconds: "daemon" or "broker",
// with "_directory" after it on a directory store of its own.
func (r storeRef) certLabel(name string) string {
	if r.dir {
		return name + "_directory"
	}
	return name
}

// what names the store in a line: "store", or "directory store".
func (r storeRef) what() string {
	if r.dir {
		return "directory store"
	}
	return "store"
}

// dirHandle is the directory store's raw handle as a process holds it: the
// session store's in a shared store, and absent until it first answers on a
// port49d run that serves from the marks it holds (R19). As a
// placement.Directory an absent handle does not answer.
type dirHandle struct{ p atomic.Pointer[etcdstore.Store] }

func (h *dirHandle) set(s *etcdstore.Store) { h.p.Store(s) }
func (h *dirHandle) get() *etcdstore.Store  { return h.p.Load() }

// close closes the handle it holds. A shared store's handle is the session
// store's, closed with it: never call close on one.
func (h *dirHandle) close() {
	if s := h.p.Swap(nil); s != nil {
		s.Close()
	}
}

// errNoDirectory is a directory store this run has not opened yet.
var errNoDirectory = fmt.Errorf("%w: the directory store has not answered since this run began", store.ErrUnavailable)

func (h *dirHandle) PutRevocation(ctx context.Context, r store.Revocation) error {
	if s := h.get(); s != nil {
		return s.PutRevocation(ctx, r)
	}
	return errNoDirectory
}

func (h *dirHandle) GetRevocation(ctx context.Context, kind, key string) (store.Revocation, error) {
	if s := h.get(); s != nil {
		return s.GetRevocation(ctx, kind, key)
	}
	return store.Revocation{}, errNoDirectory
}

func (h *dirHandle) DeleteRevocation(ctx context.Context, kind, key string) error {
	if s := h.get(); s != nil {
		return s.DeleteRevocation(ctx, kind, key)
	}
	return errNoDirectory
}

func (h *dirHandle) ListRevocations(ctx context.Context) ([]store.Revocation, error) {
	if s := h.get(); s != nil {
		return s.ListRevocations(ctx)
	}
	return nil, errNoDirectory
}
```

Create `internal/port49d/fresh.go`:

```go
package port49d

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

// directoryCheckEvery is how often a process reads the directory store to
// confirm its copy (plan 11a, R17); a variable so a test can shorten it.
var directoryCheckEvery = time.Second

// keepFresh reads the directory store every directoryCheckEvery, each read
// within timeout, and tells fresh; it says on out, begun with proc, when the
// directory stops answering and when it answers again, with the copy's age,
// until ctx ends. A handle not yet opened does not answer.
func keepFresh(ctx context.Context, h *dirHandle, fresh *store.Freshness, timeout time.Duration, out io.Writer,
	proc string) {
	t := time.NewTicker(directoryCheckEvery)
	defer t.Stop()
	for {
		err := errNoDirectory
		if s := h.get(); s != nil {
			cctx, cancel := context.WithTimeout(ctx, timeout)
			err = s.Ping(cctx)
			cancel()
		}
		if ctx.Err() != nil {
			return
		}
		age, ok := fresh.Age()
		switch fresh.Checked(err) {
		case store.Stopped:
			fmt.Fprintf(out, "%s: directory store: not answering (%s): serving from the cache %s; revocations, "+
				"lifts, enrollments, unlocks and second-factor resets are refused until it answers\n", proc,
				printsafeErr(err), confirmedText(age, ok))
		case store.Resumed:
			fmt.Fprintf(out, "%s: directory store: answering again; the cache was %s\n", proc, oldText(age, ok))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ageText is d as port49 store status prints a cache age: tenths of a
// second under a minute, whole seconds above.
func ageText(d time.Duration) string {
	if d < time.Minute {
		return strconv.FormatFloat(d.Seconds(), 'f', 1, 64) + "s"
	}
	return d.Round(time.Second).String()
}

func confirmedText(age time.Duration, ok bool) string {
	if !ok {
		return "never confirmed"
	}
	return "confirmed " + ageText(age) + " ago"
}

func oldText(age time.Duration, ok bool) string {
	if !ok {
		return "never confirmed"
	}
	return ageText(age) + " old"
}
```

In `internal/daemon/metrics/metrics.go`, add two fields after `StoreCertExpiry`:

```go
	// StoreDirectoryReachable is 1 while this process's reads of the
	// directory store answer, 0 while they do not (plan 11a; decision 51).
	StoreDirectoryReachable prometheus.Gauge
	// StoreDirectoryConfirmed is when this process last confirmed its copy
	// of the directory store, in Unix seconds: a read answered while its
	// marks feed ran. An alert subtracts it from now.
	StoreDirectoryConfirmed prometheus.Gauge
	// StoreLogoutsPending is how many back-channel logouts this region
	// accepted while the directory store did not answer and has not yet
	// forwarded to it (plan 11a, R26 as amended). No label.
	StoreLogoutsPending prometheus.Gauge
```

Construct them in `New`:

```go
		StoreDirectoryReachable: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_store_directory_reachable",
			Help: "1 while this process's reads of the directory store answer."}),
		StoreDirectoryConfirmed: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "port49_store_directory_confirmed_timestamp_seconds",
			Help: "When this process last confirmed its copy of the directory store (a read answered while its marks feed ran), in Unix seconds."}),
		StoreLogoutsPending: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_store_logouts_pending",
			Help: "Back-channel logouts accepted while the directory store did not answer and not yet forwarded to it."}),
```

Add the three to the registration list beside `m.StoreCertExpiry`.

Add the helper `tellFresh` to `fresh.go`:

```go
// tellFresh has fresh tell m's two directory gauges (plan 11a, R17).
func tellFresh(fresh *store.Freshness, m *metrics.Metrics) {
	fresh.Tell(func(at time.Time) { m.StoreDirectoryConfirmed.Set(float64(at.Unix())) },
		func(r bool) { m.StoreDirectoryReachable.Set(b2f(r)) })
}
```

Import `internal/daemon/metrics` in `fresh.go` for it.

- [ ] **Step 4: Open either store by its `storeRef`**

In `internal/port49d/store.go`:

1. `attempt(ctx, cfg, ref storeRef, m, out)`:
   - reads `e := ref.cfg.Etcd`;
   - names `ref.at + ".etcd.ca_file"` in its CA messages;
   - calls `openIdentity(ctx, cfg, ref, m, out, pool, now, name, id)` and
     `checkRoles(ctx, d, b, e, leaves, ref)`;
   - sets `m.StoreCertExpiry.WithLabelValues(ref.certLabel(name))`;
   - its validity line begins `"%s: %s: the %s's etcd certificate"` with `procOf(cfg), ref.what(), name`.
2. `openIdentity(ctx, cfg, ref storeRef, m, out, pool, now, name, id)`:
   - reads `ref.cfg.Etcd`;
   - calls `identityAt(ref.at+".etcd."+name, id, pool, now)`;
   - begins its lines `proc + ": " + ref.what() + ": "`;
   - wraps its open error as `ref.at + ".etcd." + name`.
3. `waitForStore(ctx, cfg, ref storeRef, m, out, again, closed)`:
   - reads `ref.cfg.Etcd`;
   - makes the feeds' series only when `!ref.dir`;
   - names the store in its lines by `ref.what()` (`"%s: %s: etcd at %s not answering (%v); %s; waiting %s"`);
   - names `ref.at + ".etcd.start_timeout"` in its deadline error.
4. `checkRoles(ctx, d, b, e, leaves, ref storeRef)` calls `d.CheckIdentityAt(cctx, false, ref.scope)`
   and `b.CheckIdentityAt(cctx, true, ref.scope)`. Its messages name `ref.at + ".etcd.daemon"` and
   `ref.at + ".etcd.broker"`, and its "set store.etcd.roles: unenforced" names `ref.at + ".etcd.roles"`.
5. Every existing caller passes `sessionRef(cfg)`: `openStores`, `openBroker`, `offlineBroker`.

- [ ] **Step 5: `openBroker` opens the directory**

In `internal/port49d/brokerd.go`:

1. Add to `brokerStores`:
   ```go
   	// dir is the directory store's raw handle, the broker's identity on it:
   	// the session store's own in a shared store. fresh is how current the
   	// marks this replica follows from it are (plan 11a, R17). logouts is
   	// this replica's copy of the directory's logout records, loaded at
   	// logoutRev (R26).
   	dir       *dirHandle
   	fresh     *store.Freshness
   	logouts   *store.LogoutSet
   	logoutRev uint64
   ```
2. In `openBroker`, delete Task 2's refusal. After `b, err := waitForStore(…)` and the `retry`/`fail`
   closures, open the directory store:
   ```go
   	dirRaw := b
   	if !cfg.Stores.Shared {
   		if dirRaw, err = waitForStore(ctx, cfg, directoryRef(cfg), m, out, false, "nothing is served yet"); err != nil {
   			return fail(err)
   		}
   	}
   ```
   `fail` closes `dirRaw` too when it is not `b`.
3. The marks load reads `store.LoadMarks(lctx, dirRaw, marks, nil)`. Its bound is the directory's
   `BulkTimeout` in a split.
4. The line becomes:
   ```go
   	from := "the store"
   	if !cfg.Stores.Shared {
   		from = "the directory store"
   	}
   	fmt.Fprintf(out, "port49-broker: store: %d revocation(s) in force from %s\n", marks.Len(), from)
   ```
5. After `bs.st = crypt.Wrap(…)`:
   ```go
   	bs.dir = &dirHandle{}
   	bs.dir.set(dirRaw)
   	bs.fresh = store.NewFreshness(time.Now)
   	tellFresh(bs.fresh, m)
   	bs.logouts = store.NewLogoutSet(time.Now)
   	if !cfg.Stores.Shared {
   		de := cfg.Stores.Directory.Etcd
   		// The directory's membership half, sealed as the session's is (R13;
   		// Task 8a): the pin, the map keys, refusals, the forget's tombstone.
   		members := crypt.Wrap(dirRaw, keys, m.CryptOpenFailures, crypt.WithLedger(crypt.NewLedger()), say)
   		// The logouts, loaded before anything is served, as the marks are (R26).
   		if err := retry(func() error {
   			lctx, cancel := context.WithTimeout(ctx, de.BulkTimeout)
   			defer cancel()
   			rev, es, err := dirRaw.Logouts(lctx)
   			if err == nil {
   				bs.logouts.Merge(es) // a merge, not a replace: a load never erases a live logout (8b review I1); Len counts the live (M2)
   				bs.logoutRev = rev
   			}
   			return err
   		}); err != nil {
   			return fail(err)
   		}
   		bs.st = placement.Wrap(placement.Config{Session: bs.st, Directory: dirRaw, Members: members, Marks: marks,
   			Logouts: bs.logouts, LogoutDir: dirRaw,
   			CallTimeout: de.CallTimeout, BulkTimeout: de.BulkTimeout,
   			// Before the first check the directory is tried; after it, its answer rules.
   			Reachable: func() bool { ok, why := bs.fresh.Reachable(); return ok || why == "" },
   			Say:       func(format string, args ...any) { fmt.Fprintf(out, "port49-broker: "+format+"\n", args...) }})
   	}
   ```

In `runBroker`:

1. After `defer bs.raw.Close()`, add `if !cfg.Stores.Shared { defer bs.dir.close() }`.
2. `wirePasswordSignIn(ctx, cfg, brk, keys, m, bs.dir, stderr)`.
3. Build the runner with `followed` in a split:
   ```go
   	if !cfg.Stores.Shared {
   		rn.followed = make(chan store.Revocation, 1024)
   	}
   ```
4. Replace the marks feed's goroutine body with:
   ```go
   		onMark := brk.MarkChanged
   		if !cfg.Stores.Shared {
   			onMark = func(c store.MarkChange) { brk.MarkChanged(c); rn.follow(c) }
   		}
   		store.FollowMarks(ctx, copyingFeed{MarkFeed: bs.dir.get(), copy: marksCopy}, marks, bs.markRev, onMark,
   			func(up bool) { m.StoreFeedUp.WithLabelValues("marks").Set(b2f(up)); bs.fresh.FeedUp(up) },
   			rn.reloadHook(ctx, m.StoreFeedRescans.WithLabelValues("marks")),
   			func(format string, args ...any) { fmt.Fprintf(stderr, "port49-broker: "+format+"\n", args...) })
   ```
5. In a split, follow the pins into the router's cache (Task 8a). `FollowPins` returns at once on a
   shared store:
   ```go
   	wg.Add(1)
   	go func() {
   		defer wg.Done()
   		placement.FollowPins(ctx, bs.st, bs.dir.get(),
   			func(up bool) { m.StoreFeedUp.WithLabelValues("pins").Set(b2f(up)) },
   			func(format string, args ...any) { fmt.Fprintf(stderr, "port49-broker: "+format+"\n", args...) })
   	}()
   ```
6. In a split, follow the logouts into this replica's copy. Each one the watch delivers goes to the
   runner, which reaches it here (Task 8c):
   ```go
   	if !cfg.Stores.Shared {
   		wg.Add(1)
   		go func() {
   			defer wg.Done()
   			store.FollowLogouts(ctx, bs.dir.get(), bs.logouts, bs.logoutRev, rn.followLogout,
   				func(up bool) { m.StoreFeedUp.WithLabelValues("logouts").Set(b2f(up)) },
   				func(format string, args ...any) { fmt.Fprintf(stderr, "port49-broker: "+format+"\n", args...) })
   		}()
   	}
   ```
7. Beside it, keep the copy's freshness:
   ```go
   	dirTimeout := cfg.Stores.Directory.Etcd.CallTimeout
   	wg.Add(1)
   	go func() { defer wg.Done(); keepFresh(ctx, bs.dir, bs.fresh, dirTimeout, stderr, "port49-broker") }()
   ```

In `internal/port49d/runner.go`:

1. Add to `runner`:
   ```go
   	// followed is told each mark the marks feed brings that stands, in a
   	// split (plan 11a, R20): the duties reach it in this region's session
   	// store (reachFollowed). Nil in a shared store, where the broker that
   	// made a mark reached it there.
   	followed chan store.Revocation
   ```
2. Add `follow` and `reachFollowed`:
   ```go
   // follow is the marks feed's tell in a split, after MarkChanged: a mark
   // that stands is queued for the running duties to reach here. A replica
   // that does not run queues nothing, and a full queue drops the mark,
   // said: the marks deny it on every request, and the next takeover
   // applies every mark to the live contexts.
   func (r *runner) follow(c store.MarkChange) {
   	if r.followed == nil || !c.Standing || !r.running() {
   		return
   	}
   	select {
   	case r.followed <- c.Revocation:
   	default:
   		fmt.Fprintf(stderr, "port49-broker: runner: a revocation of %s made elsewhere was not queued to reach this "+
   			"region's tokens (the queue is full); the marks deny it on every request, and the next takeover "+
   			"applies it\n", printsafe.Line(c.Key, 160))
   	}
   }

   // reachFollowed reaches each queued mark in this region's session store
   // (Broker.ReachMark), one line per mark, until ctx ends.
   func (r *runner) reachFollowed(ctx context.Context) {
   	for {
   		select {
   		case <-ctx.Done():
   			return
   		case mark := <-r.followed:
   			n, refs, err := r.brk.ReachMark(ctx, mark)
   			line := fmt.Sprintf("port49-broker: runner: a revocation of %s made elsewhere reached %d token "+
   				"key(s) and %d context(s) here", printsafe.Line(mark.Key, 160), n, len(refs))
   			if err != nil {
   				line += fmt.Sprintf("; not every step finished (%s): the marks deny it on every request, and the "+
   					"next takeover applies it again", printsafe.Line(err.Error(), 300))
   			}
   			fmt.Fprintln(stderr, line)
   		}
   	}
   }
   ```
3. Add the logouts' queue beside the marks':
   ```go
   	// followedLogouts is told each logout the logouts feed brings, in a
   	// split (R26): the duties reach it in this region's session store.
   	followedLogouts chan store.LogoutEntry
   ```
   ```go
   // followLogout queues a logout the feed brought for the running duties,
   // as follow queues a mark; a full queue drops it, said: the logout set
   // refuses its mints and refreshes regardless.
   func (r *runner) followLogout(e store.LogoutEntry) {
   	if r.followedLogouts == nil || !r.running() {
   		return
   	}
   	select {
   	case r.followedLogouts <- e:
   	default:
   		fmt.Fprintln(stderr, "port49-broker: runner: a logout made elsewhere was not queued to reach this region's "+
   			"sessions (the queue is full); its mints and refreshes are refused regardless")
   	}
   }
   ```
   In `reachFollowed`'s `select`, add:
   ```go
   		case l := <-r.followedLogouts:
   			rep, err := r.brk.ReachLogout(ctx, l.Logout)
   			line := fmt.Sprintf("port49-broker: runner: a logout made elsewhere (%s) reached %d token key(s) and "+
   				"%d context(s) here", printsafe.Line(l.Origin, 160), rep.TokenKeys, len(rep.Contexts))
   			if err != nil {
   				line += fmt.Sprintf("; not every step finished (%s)", printsafe.Line(err.Error(), 300))
   			}
   			fmt.Fprintln(stderr, line)
   ```
   In `runBroker`, where `rn.followed` is made, also make
   `rn.followedLogouts = make(chan store.LogoutEntry, 1024)`. The region that ingested a logout
   reaches it twice, once at ingestion and once here. The second finds nothing left, which is
   harmless.
4. Add the pending logouts' forwarding duty (R26 as amended), run beside the others while this
   replica runs:
   ```go
   // forwardingPending forwards this region's pending logouts to the
   // directory every 5s while it answers (placement.ForwardPending), sets
   // port49_store_logouts_pending, and says each pass that forwarded any, and
   // once per run of passes that could not.
   func (r *runner) forwardingPending(ctx context.Context) {
   	said := false
   	for {
   		n, left, err := placement.ForwardPending(ctx, r.st, r.raw)
   		r.m.StoreLogoutsPending.Set(float64(left))
   		r.pending.Store(int64(left))
   		switch {
   		case n > 0:
   			fmt.Fprintf(stderr, "port49-broker: runner: %d pending back-channel logout(s) forwarded to the "+
   				"directory store, and so to every region\n", n)
   			said = false
   		case err != nil && left > 0 && !said:
   			fmt.Fprintf(stderr, "port49-broker: runner: %d back-channel logout(s) pending until the directory store "+
   				"answers (%s); they are applied in this region already\n", left, printsafe.Line(err.Error(), 300))
   			said = true
   		}
   		if !sleepCtx(ctx, 5*time.Second) {
   			return
   		}
   	}
   }
   ```
   `r.raw` is the session store's raw handle: its `Logouts` and `DeleteLogout` (Task 8b) are the
   pending records. `ForwardPending` does nothing on a shared store.
5. In `duties`, after `wg.Add(8)` and its goroutines:
   ```go
   	if r.followed != nil {
   		wg.Add(2)
   		go func() { defer wg.Done(); r.reachFollowed(ctx) }()
   		go func() { defer wg.Done(); r.forwardingPending(ctx) }()
   	}
   ```

In `internal/port49d/offline.go` (`offlineBroker`), after `st := crypt.Wrap(…)`:

```go
	closeAll := func() { b.Close() }
	if !cfg.Stores.Shared {
		d, err := attempt(ctx, cfg, directoryRef(cfg), m, out)
		if err != nil {
			b.Close()
			if errors.Is(err, context.Canceled) {
				return offlineRun{}, errors.New("stopped")
			}
			return offlineRun{}, fmt.Errorf("directory store: %w", err)
		}
		de := cfg.Stores.Directory.Etcd
		// No copy: the offline revocation follows no feed, so a mark is read
		// from the directory.
		st = placement.Wrap(placement.Config{Session: st, Directory: d, CallTimeout: de.CallTimeout,
			BulkTimeout: de.BulkTimeout})
		closeAll = func() { b.Close(); d.Close() }
	}
```

`run.close` becomes `closeAll`.

In `internal/port49d/signin.go`, the enrollment handle is the directory's, read at each open, so a
broker started before the directory answers (Task 10a) wires password sign-in all the same and
answers `store_unavailable` until it does:
1. `wirePasswordSignIn`'s handle parameter becomes `dir *dirHandle`, and its comment says: "dir is
   the directory store's handle, the broker's identity on it (the session store's own in a shared
   store); nil on the memory store." It passes `wireSignIn` a func, nil when `dir` is nil:
   ```go
   	var sh func() store.Enrollments // nil: no shared store
   	if dir != nil {
   		sh = func() store.Enrollments {
   			if s := dir.get(); s != nil {
   				return s
   			}
   			return nil // a nil *Store is not a nil interface
   		}
   	}
   	return wireSignIn(ctx, cfg, b, keys, m, sh, out)
   ```
2. `wireSignIn`'s `shared store.Enrollments` parameter becomes `shared func() store.Enrollments`.
   Its etcd case's `open` reads it at each open:
   ```go
   	open = func() (store.Enrollments, error) {
   		sh := shared()
   		if sh == nil {
   			return nil, errNoDirectory // lateEnrollments opens again at its next interval
   		}
   		return crypt.WrapEnrollments(guard.WrapEnrollments(sh, gc), keys, m.CryptOpenFailures), nil
   	}
   ```
   The case's `where` and its guard config already name `stores.directory` (Task 2).
3. `runBroker` passes `bs.dir`. Every test that passes a store to `wireSignIn` passes
   `func() store.Enrollments { return x }` for it (`signin_recheck_test.go`, `signin_test.go:278`);
   a `nil` stays `nil`. `go vet` names each.

- [ ] **Step 6: Run the tests**

Run: `go test ./internal/port49d/ -count=1`
Expected: PASS: the four new tests, and every existing port49-broker test on one store.

- [ ] **Step 7: Commit**

```bash
git add internal/port49d internal/daemon/metrics/metrics.go
git commit -m "feat: port49-broker on two stores: marks and enrollments in the directory, followed marks reached per region

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 9a: The directory's key check, and one cluster named twice

**Files:**
- Create: `internal/port49d/dirkeys.go`
- Modify: `internal/store/etcd/meta.go` (`ClusterID`), `internal/port49d/storeref.go` (`where`),
  `internal/port49d/brokerd.go` (`openBroker`), `internal/port49d/store.go` (`openDaemon`),
  `internal/port49d/runner.go` (a `dir` field; the hourly recheck)
- Test: `internal/port49d/twostores_linux_test.go`, `internal/store/etcd/meta_test.go`

**Interfaces:**
- Consumes: `storeRef`, `directoryRef`, `dirHandle` (Task 9); `etcd.Store.SealKeys`,
  `PutSealKeys` and `ErrSealKeysUndecodable` (plan 7d); `keyWindow` and `storeFault`
  (`internal/port49d/store.go`).
- Produces:
  - `func (s *etcd.Store) ClusterID(ctx context.Context) (uint64, error)`;
  - `func (r storeRef) where() string`: `etcd <endpoints>, prefix <prefix>`;
  - `func checkDirectoryKeys(ctx, proc string, d *etcdstore.Store, ref storeRef, keys crypt.Keys, out io.Writer, bound time.Duration, write bool) error`;
  - `func checkTwoStores(ctx, cfg config.Config, sess, dir *etcdstore.Store, bound time.Duration) error`;
  - `var directoryKeysRecheckEvery = time.Hour`, and the runner's `dir *dirHandle`.

R27 and R28 (the pre-flight's I1 and minor 11):
- Every region holds one `encryption:` key set. The directory's `meta/seal_keys` records the
  window (ids only) the last port49-broker to start against it held; every port49-broker start
  writes its own, as the session store's start does. A process whose window does not hold the
  record's current id cannot open what that broker seals, and refuses to start, exit 1, naming
  the directory store and the key id. A record that does not decode is said and written over by port49-broker; port49d,
  which cannot write the directory, only says it.
- With the three-step rotation (R27) every process holds both keys at every step, so the record
  naming either never refuses anyone. A region that retired a key another region still seals with
  is refused at its next start, which is the case the check exists for.
- Two blocks that reach one etcd cluster id, with the same prefix or one holding the other, are
  refused at start (R28).

- [ ] **Step 1: Write the failing tests**

Append to `internal/store/etcd/meta_test.go`:

```go
// ClusterID is the cluster's id from a read's header: the same through any
// client of one cluster (plan 11a, R28).
func TestClusterIDIsTheClusters(t *testing.T) {
	s := onShared(t, func() time.Time { return t0 })
	id, err := s.ClusterID(context.Background())
	if err != nil || id == 0 {
		t.Fatalf("%x %v", id, err)
	}
}
```

Append to `internal/port49d/twostores_linux_test.go`:

```go
// R27: a directory last written under a key this configuration does not
// hold refuses port49-broker's start, naming the directory store and the
// key id, never key material.
func TestADirectoryUnderAKeyThisRegionLacksRefusesTheStart(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	if _, err := f.dsrv.Client(t, "root").Put(context.Background(), "/port49/v1/meta/seal_keys",
		`{"current":"key-from-elsewhere","written_at":"2026-10-17T00:00:00Z"}`); err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- runBroker(context.Background(), f.broker) }()
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "the directory store (etcd ") ||
			!strings.Contains(err.Error(), "key-from-elsewhere") ||
			!strings.Contains(err.Error(), "which this configuration does not hold") {
			t.Fatalf("%v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("port49-broker started against a directory under a key it lacks")
	}
}

// R27: port49-broker records its window in the directory store at start.
func TestABrokerRecordsItsKeyWindowInTheDirectory(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	startBroker(t, f.broker, &out, 1)
	if n := keysUnder(t, f.dsrv, "/port49/v1/meta/seal_keys"); n != 1 {
		t.Fatalf("%d key window record(s) in the directory store, want 1", n)
	}
}

// R27: a running runner says, at its recheck, a directory now under a key
// it lacks (a region that rotated out of order).
func TestARunnerSaysADirectoryKeyItLacks(t *testing.T) {
	var out syncBuffer
	e, every := stderr, directoryKeysRecheckEvery
	t.Cleanup(func() { stderr, directoryKeysRecheckEvery = e, every })
	stderr, directoryKeysRecheckEvery = &out, time.Second
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	startBroker(t, f.broker, &out, 1)
	waitWithin(t, &out, "port49-broker: runner: took keyspace", 30*time.Second)
	if _, err := f.dsrv.Client(t, "root").Put(context.Background(), "/port49/v1/meta/seal_keys",
		`{"current":"key-from-elsewhere","written_at":"2026-10-17T00:00:00Z"}`); err != nil {
		t.Fatal(err)
	}
	waitWithin(t, &out, "which this configuration does not hold", 10*time.Second)
}

// R28: stores.directory naming the session store's own cluster and prefix
// through another address is one keyspace, and port49-broker refuses it.
func TestOneClusterNamedTwiceIsRefused(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	f.twoStoresOn(t, f.srv) // the session store's own member, through a proxy of its own
	f.judged(t)
	errc := make(chan error, 1)
	go func() { errc <- runBroker(context.Background(), f.broker) }()
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "reach one etcd cluster") {
			t.Fatalf("%v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("port49-broker started with one keyspace named twice")
	}
}
```

`twoStoresOn(t, f.srv)` reaches the session member, whose roles are the shared scope's. The
broker's grant covers its whole keyspace in either scope, so its role check passes and R28's check
is the one that refuses. The daemon is not started: its shared-scope grants fail the directory's
role check first, which is right, and not what this test is about.

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/store/etcd/ ./internal/port49d/ -run 'ClusterID|KeyThisRegionLacks|KeyWindowInTheDirectory|DirectoryKeyItLacks|NamedTwice' -count=1`
Expected: FAIL to compile (`s.ClusterID undefined`; `undefined: directoryKeysRecheckEvery`).

- [ ] **Step 3: Implement**

In `internal/store/etcd/meta.go`:

```go
// ClusterID is the etcd cluster's id, from a read's header (plan 11a, R28):
// two clients of one cluster read one id, whatever address each names.
func (s *Store) ClusterID(ctx context.Context) (uint64, error) {
	resp, err := s.tok.Get(ctx, s.k.meta("ping"), clientv3.WithKeysOnly())
	if err != nil {
		return 0, unavailable(err)
	}
	return resp.Header.ClusterId, nil
}
```

In `internal/port49d/storeref.go`, add (with `"strings"` imported):

```go
// where names the store's etcd in a line: its endpoints and its prefix.
func (r storeRef) where() string {
	return "etcd " + strings.Join(r.cfg.Etcd.Endpoints, ", ") + ", prefix " + r.cfg.Etcd.Prefix
}
```

Create `internal/port49d/dirkeys.go`:

```go
package port49d

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/store/crypt"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
)

// directoryKeysRecheckEvery is how often a runner on a directory of its own
// reads the directory's key window again (R27); a variable so a test can
// shorten it.
var directoryKeysRecheckEvery = time.Hour

// checkDirectoryKeys is the start's key check on a directory store of its
// own (plan 11a, R27). Every region holds one encryption key set: a window
// that does not hold the current key the directory's meta/seal_keys names
// cannot open what the last broker to start there seals, and the start is
// refused (a *storeFault), naming the store and the key id, never key
// material. A record that does not decode is said; with write
// (port49-broker), it, or no record, is written over with this window, as
// every broker start writes its own. Only an outage is returned besides.
func checkDirectoryKeys(ctx context.Context, proc string, d *etcdstore.Store, ref storeRef, keys crypt.Keys,
	out io.Writer, bound time.Duration, write bool) error {
	rctx, cancel := context.WithTimeout(ctx, bound)
	last, ok, err := d.SealKeys(rctx)
	cancel()
	undecodable := errors.Is(err, etcdstore.ErrSealKeysUndecodable)
	if err != nil && !undecodable {
		return fmt.Errorf("directory store: reading its key window: %w", err)
	}
	held := keys.Current.ID == last.Current || keys.Previous != nil && keys.Previous.ID == last.Current
	if ok && !held {
		id := crypt.LineKeyID(last.Current)
		return &storeFault{fmt.Errorf("%s: crypt: the directory store (%s) was last written by a process whose "+
			"current key is %q, which this configuration does not hold (%s); every region holds the same "+
			"encryption keys (decision 51): add %q to encryption, then start again", proc, ref.where(), id,
			keyWindow(keys), id)}
	}
	if undecodable {
		fmt.Fprintf(out, "%s: crypt: the directory store's key window is unreadable (meta/seal_keys does not "+
			"decode); every region holds the same encryption keys, and this start cannot check that it does\n", proc)
	}
	if !write {
		return nil
	}
	cur := etcdstore.SealKeys{Current: keys.Current.ID, WrittenAt: time.Now().UTC()}
	if keys.Previous != nil {
		cur.Previous = keys.Previous.ID
	}
	pctx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	return d.PutSealKeys(pctx, cur)
}

// checkTwoStores refuses a split whose two blocks reach one etcd cluster
// with the same prefix, or one prefix holding the other (plan 11a, R28):
// one keyspace named two ways (an IP and a DNS name), which the config's
// text compare (R22) cannot see. It reads each cluster's id within bound.
func checkTwoStores(ctx context.Context, cfg config.Config, sess, dir *etcdstore.Store, bound time.Duration) error {
	cctx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	a, err := sess.ClusterID(cctx)
	if err != nil {
		return fmt.Errorf("session store: reading its cluster id: %w", err)
	}
	b, err := dir.ClusterID(cctx)
	if err != nil {
		return fmt.Errorf("directory store: reading its cluster id: %w", err)
	}
	sp := strings.TrimSuffix(cfg.Stores.Session.Etcd.Prefix, "/") + "/"
	dp := strings.TrimSuffix(cfg.Stores.Directory.Etcd.Prefix, "/") + "/"
	if a != b || !strings.HasPrefix(sp, dp) && !strings.HasPrefix(dp, sp) {
		return nil
	}
	return &storeFault{fmt.Errorf("stores.directory (prefix %s) and stores.session (prefix %s) reach one etcd "+
		"cluster (id %x), and one prefix holds the other: they are one keyspace named two ways; omit "+
		"stores.session for a single site, or give the directory a cluster of its own",
		cfg.Stores.Directory.Etcd.Prefix, cfg.Stores.Session.Etcd.Prefix, a)}
}

// recheckDirectoryKeys reads the directory's key window every
// directoryKeysRecheckEvery while the runner runs, and says a window this
// process does not hold, once per change of the record (R27: a region that
// rotated out of order). It never writes.
func (r *runner) recheckDirectoryKeys(ctx context.Context) {
	t := time.NewTicker(directoryKeysRecheckEvery)
	defer t.Stop()
	said := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		d := r.dir.get()
		if d == nil {
			continue
		}
		err := checkDirectoryKeys(ctx, "port49-broker", d, directoryRef(r.cfg), r.keys, io.Discard,
			4*r.cfg.Stores.Directory.Etcd.CallTimeout, false)
		var f *storeFault
		switch {
		case errors.As(err, &f) && f.Error() != said:
			fmt.Fprintf(stderr, "%v; this process keeps running, and password sign-in and pins sealed under that "+
				"key fail here until it holds it\n", f)
			said = f.Error()
		case err == nil:
			said = ""
		}
	}
}
```

In `internal/port49d/brokerd.go`'s `openBroker`, in the split branch Task 9 wrote, right after
`dirRaw` opens:

```go
		de := cfg.Stores.Directory.Etcd
		if err := retry(func() error { return checkTwoStores(ctx, cfg, b, dirRaw, 4*de.CallTimeout) }); err != nil {
			dirRaw.Close()
			return fail(err)
		}
		if err := retry(func() error {
			return checkDirectoryKeys(ctx, "port49-broker", dirRaw, directoryRef(cfg), keys, out, 4*de.CallTimeout, true)
		}); err != nil {
			dirRaw.Close()
			return fail(err)
		}
```

(`retry` retries an outage and returns a `*storeFault` at once; the later `de :=` in Task 9's
block becomes an assignment, or is dropped.)

In `internal/port49d/store.go`'s `openDaemon`, in the `!dc.loaded.Load()` case, right after
`dir.set(dd)`, the same two checks with `"port49d"`, `d` for the session store and `write` false;
a failure closes `dir` and returns `fail(err)`.

In `internal/port49d/runner.go`, add to `runner`:

```go
	// dir is the directory store's handle in a split (plan 11a): the
	// hourly key-window recheck reads it (R27). Nil in a shared store.
	dir *dirHandle
```

`runBroker` sets `rn.dir = bs.dir` when `!cfg.Stores.Shared`. In `duties`, beside Task 9's
`r.followed != nil` block, add one more goroutine to it (`wg.Add(3)`):

```go
		go func() { defer wg.Done(); r.recheckDirectoryKeys(ctx) }()
```

- [ ] **Step 4: Run them to verify they pass**

Run: `go test ./internal/store/etcd/ ./internal/port49d/ -count=1`
Expected: PASS: the five new tests, and every test before.

- [ ] **Step 5: Commit**

```bash
git add internal/store/etcd/meta.go internal/store/etcd/meta_test.go internal/port49d
git commit -m "feat: every region holds the directory's encryption keys, and one cluster named twice is refused

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 10: port49d on two stores

**Files:**
- Modify: `internal/port49d/store.go` (`stores` :51, `openStores` :108, `openDaemon` :216, Task 2's refusal),
  `internal/port49d/main.go` (`run` :688, `runOnce` :751)
- Test: `internal/port49d/twostores_linux_test.go`

**Interfaces:**
- Consumes:
  - from Task 9: `storeRef`, `directoryRef`, `dirHandle`, `keepFresh`, `tellFresh`, `attempt`,
    `waitForStore`;
  - `placement.Wrap` (Task 6);
  - `FollowMarks` from 0 (Task 3).
- Produces:
  - `type directoryCache struct { loaded atomic.Bool; fresh *store.Freshness }`, the process's,
    passed `run → runOnce → openStores`;
  - `stores.dir *dirHandle` and `stores.fresh *store.Freshness`, which Task 12 reads;
  - `openDirectoryLater(ctx, cfg, m, out, dir *dirHandle) bool`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/port49d/twostores_linux_test.go` (add `"github.com/rhwendt/port49/internal/tacacs/wire"` to its imports):

```go
// Review Focus 1: a port49d cut from its directory keeps serving from its
// cache: an open session's commands, and a login with a token minted before
// the cut; port49_store_directory_reachable reads 0; the heal is said.
func TestADaemonCutFromItsDirectoryServesFromItsCache(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	api, _ := startBroker(t, f.broker, &out, 1)
	dev := tacacsClient{t: t, addr: startSplitDaemon(t, f.daemon, &out, 1), key: []byte("run-test-secret")}
	waitFor(t, &out, "port49d: store: 0 revocation(s) in force from the directory store")
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
	tok := mintOn(t, api, f.pki, "leaf1")
	f.ddproxy.Hang(true)
	waitWithin(t, &out, "port49d: directory store: not answering", 10*time.Second)
	for i := 0; i < 3; i++ {
		if !dev.permits("alice", "show", "version") {
			t.Fatalf("a command was refused with the directory cut; log %s", log.String())
		}
	}
	if st := dev.login("alice", tok); st != wire.AuthenStatusPass {
		t.Fatalf("a token minted before the cut did not log in during it: status %d", st)
	}
	if v := metricAt(t, daemonMetrics(t, &out), "port49_store_directory_reachable"); v != 0 {
		t.Fatalf("port49_store_directory_reachable %v with the directory cut", v)
	}
	f.ddproxy.Hang(false)
	waitWithin(t, &out, "port49d: directory store: answering again", 10*time.Second)
}

// Review Focus 1, R17: a revocation made in another region while this one
// is cut does not reach it until the heal, and then does.
func TestAMarkMadeDuringACutReachesTheDaemonOnHeal(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	a := splitFleet(t)
	a.twoStores(t)
	a.judged(t)
	c := splitFleet(t)
	c.twoStoresOn(t, a.dsrv)
	c.judged(t)
	startBroker(t, a.broker, &out, 1)
	apiC, _ := startBroker(t, c.broker, &out, 2)
	dev := tacacsClient{t: t, addr: startSplitDaemon(t, c.daemon, &out, 1), key: []byte("run-test-secret")}
	loginSession(t, dev, mintOn(t, apiC, c.pki, "leaf1"), &log)
	c.dproxy.Hang(true)
	c.ddproxy.Hang(true)
	waitCountWithin(t, &out, "directory store: not answering", 2, 10*time.Second)
	r, err := ask(adminSocketOf(t, a.broker), admin.Request{Op: "revoke", Principal: "user:alice@example.com"})
	if err != nil || r.Error != "" {
		t.Fatalf("%+v %v", r, err)
	}
	time.Sleep(2 * time.Second) // what a feed would need, had region c not been cut
	if !dev.permits("alice", "show", "version") {
		t.Fatal("region c denied the session during the cut: a mark made elsewhere cannot reach it until the heal (R17)")
	}
	c.dproxy.Hang(false)
	c.ddproxy.Hang(false)
	deadline := time.Now().Add(20 * time.Second)
	for dev.permits("alice", "show", "version") {
		if time.Now().After(deadline) {
			t.Fatal("region c's session was still permitted 20s after the heal")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// Review Focus 2, R19: a cold start with the directory cut has no marks to
// serve from: the listeners never open, and it exits at start_timeout.
func TestAColdStartWithTheDirectoryCutStaysDark(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	f.twoStores(t)
	addUnderDirectoryEtcd(t, f.daemon, "start_timeout: 5s")
	f.ddproxy.Hang(true)
	errc := make(chan error, 1)
	go func() { errc <- run(context.Background(), f.daemon) }()
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "stores.directory.etcd.start_timeout") {
			t.Fatalf("%v", err)
		}
	case <-time.After(45 * time.Second):
		t.Fatal("port49d did not give up on a directory that never answered")
	}
	if strings.Contains(out.String(), "port49d: listening on ") {
		t.Fatalf("port49d listened with no marks:\n%s", out.String())
	}
}

// Review Focus 2, R19: a run after a store gone holds its marks, and serves
// from them while the directory is still cut.
func TestARunAfterAStoreGoneServesThroughADirectoryCut(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	api, _ := startBroker(t, f.broker, &out, 1)
	startSplitDaemon(t, f.daemon, &out, 1)
	f.ddproxy.Hang(true)
	f.proxy.Hang(true)
	waitWithin(t, &out, "closing every listener so that devices use their local method", 90*time.Second)
	f.proxy.Hang(false)
	waitCountWithin(t, &out, "port49d: listening on ", 2, 120*time.Second)
	addrs := regexp.MustCompile(`port49d: listening on (127\.0\.0\.1:\d+)`).FindAllStringSubmatch(out.String(), -1)
	dev := tacacsClient{t: t, addr: addrs[len(addrs)-1][1], key: []byte("run-test-secret")}
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
	if !dev.permits("alice", "show", "version") {
		t.Fatalf("a run after a store gone refused a command with the directory still cut; log %s", log.String())
	}
	if !strings.Contains(out.String(), "port49d: directory store: this run serves from the marks it holds") {
		t.Fatalf("the run did not say it serves from its marks:\n%s", out.String())
	}
}
```

`f.proxy.Hang(true)` also cuts the broker's session store. The mint after the heal waits on the
broker's guard, and `mintWith` retries for 30s.

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/port49d/ -run 'DaemonCut|DuringACut|ColdStartWithTheDirectory|RunAfterAStoreGone' -count=1`
Expected: FAIL: port49d refuses the split ("this build serves one store", Task 2's refusal).

- [ ] **Step 3: Implement**

In `internal/port49d/store.go`:

1. Add the process's cache state:
   ```go
   // directoryCache is the process's hold on the directory store's marks
   // (plan 11a, R19), kept across a store gone as the ledger is: whether
   // they were ever loaded, so a run after a store gone serves from them,
   // and how fresh they are.
   type directoryCache struct {
   	loaded atomic.Bool
   	fresh  *store.Freshness
   }
   ```
2. Add to `stores`:
   ```go
   	// dir is the directory store's raw handle (the session store's own in a
   	// shared store; nil on memory), and fresh the marks' freshness: what
   	// port49 store status reads (plan 11a).
   	dir   *dirHandle
   	fresh *store.Freshness
   ```
3. `openStores` and `openDaemon` take `dc *directoryCache` after `authMarks`. Delete Task 2's
   refusal. `openStores`'s etcd branch calls
   `waitForStore(ctx, cfg, sessionRef(cfg), m, out, again, "the listeners stay closed")`.
4. In `openDaemon`, replace the marks-load block, from
   `sayKept := keptSayer(…)` through
   `fmt.Fprintf(out, "port49d: store: %d revocation(s) in force from the store\n", authMarks.Len())`,
   with:
   ```go
   	sayKept := keptSayer(out, "as it starts again after a store gone")
   	dir := &dirHandle{}
   	var markRev uint64
   	loadFrom := func(feed store.MarkFeed, bound time.Duration) error {
   		return retry(func() error {
   			var err error
   			markRev, err = loadDaemonMarks(ctx, feed, authMarks, again, bound, sayKept)
   			return err
   		})
   	}
   	switch {
   	case cfg.Stores.Shared:
   		dir.set(d)
   		if err := loadFrom(d, e.BulkTimeout); err != nil {
   			return fail(err)
   		}
   		fmt.Fprintf(out, "port49d: store: %d revocation(s) in force from the store\n", authMarks.Len())
   	case !dc.loaded.Load():
   		// No marks yet: the listeners stay closed until the directory
   		// answers, up to its start_timeout on a cold start (R19).
   		dd, err := waitForStore(ctx, cfg, directoryRef(cfg), m, out, again, "the listeners stay closed")
   		if err != nil {
   			return fail(err)
   		}
   		dir.set(dd)
   		if err := loadFrom(dd, cfg.Stores.Directory.Etcd.BulkTimeout); err != nil {
   			dir.close()
   			return fail(err)
   		}
   		fmt.Fprintf(out, "port49d: store: %d revocation(s) in force from the directory store\n", authMarks.Len())
   	default:
   		// A run after a store gone holds its marks: it serves from them, and
   		// the follow below opens the directory and loads when it answers (R19).
   		fmt.Fprintf(out, "port49d: directory store: this run serves from the marks it holds (%d) and follows "+
   			"the directory store once it answers\n", authMarks.Len())
   	}
   	dc.loaded.Store(true)
   ```
5. In `follow`, the marks goroutine becomes:
   ```go
   		go func() {
   			defer wg.Done()
   			if dir.get() == nil && !openDirectoryLater(ctx, cfg, m, out, dir) {
   				return
   			}
   			feed := dir.get()
   			store.FollowMarks(ctx, feed, authMarks, markRev, nil,
   				func(up bool) { upOf("marks")(up); dc.fresh.FeedUp(up) },
   				daemonReloadHook(ctx, feed, authMarks, m.StoreFeedRescans.WithLabelValues("marks"),
   					dirBulk, out), logf)
   		}()
   ```
   where `dirBulk` is `cfg.Stores.Directory.Etcd.BulkTimeout` in a split and `e.BulkTimeout` in a
   shared store. Add a third goroutine (`wg.Add(3)`):
   ```go
   		go func() { defer wg.Done(); keepFresh(ctx, dir, dc.fresh, dirCall, out, "port49d") }()
   ```
   where `dirCall` is `cfg.Stores.Directory.Etcd.CallTimeout` in a split and `e.CallTimeout` in a
   shared store.
6. After `daemon := crypt.Wrap(gd, …)`, before `authorStore := daemon`:
   ```go
   	if !cfg.Stores.Shared {
   		de := cfg.Stores.Directory.Etcd
   		daemon = placement.Wrap(placement.Config{Session: daemon, Directory: dir, Marks: authMarks,
   			CallTimeout: de.CallTimeout, BulkTimeout: de.BulkTimeout})
   	}
   ```
7. The returned `stores` sets `dir: dir, fresh: dc.fresh`, and in a split its `close` is
   `func() { d.Close(); dir.close() }`.
8. Add:
   ```go
   // openDirectoryLater opens the directory store once it answers, trying
   // every 5s, on a run that serves from the marks it holds (R19); each new
   // reason is said once. It reports false when ctx ended first.
   func openDirectoryLater(ctx context.Context, cfg config.Config, m *metrics.Metrics, out io.Writer,
   	dir *dirHandle) bool {
   	said := ""
   	for {
   		s, err := attempt(ctx, cfg, directoryRef(cfg), m, out)
   		if err == nil {
   			dir.set(s)
   			return true
   		}
   		if ctx.Err() != nil {
   			return false
   		}
   		if why := err.Error(); why != said {
   			fmt.Fprintf(out, "port49d: directory store: not opened yet (%v); serving from the marks this "+
   				"process holds; trying again every 5s\n", err)
   			said = why
   		}
   		if !sleepCtx(ctx, 5*time.Second) {
   			return false
   		}
   	}
   }
   ```

In `internal/port49d/main.go`:

1. In `run`, beside `authMarks := store.NewMarks()`, add
   `dc := &directoryCache{fresh: store.NewFreshness(time.Now)}`. Pass it to `runOnce`, and from
   `runOnce` to `openStores`.
2. In `runOnce`, once its metrics `m` exist and the store is etcd, call `tellFresh(dc.fresh, m)`.
   The new registry then reads the process's state from its first scrape (Task 3's
   `TestFreshnessTellsANewRunAtOnce`).
3. Every test that calls `openStores` or `runOnce` passes `&directoryCache{fresh: store.NewFreshness(time.Now)}`.
   `go vet` names them.

- [ ] **Step 4: Run them to verify they pass**

Run: `go test ./internal/port49d/ -count=1`
Expected: PASS: the four new tests, Task 9's, and every existing port49d test on one store.

- [ ] **Step 5: Commit**

```bash
git add internal/port49d
git commit -m "feat: port49d on two stores: marks followed from the directory, served from the cache through a cut

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 10a: The directory snapshot, and a runner during a cut

**Files:**
- Modify: `internal/store/fresh.go` (`Seed`, `Snapshot`, `Confirmed`), `internal/store/fresh_test.go`
- Create: `internal/store/etcd/snapshot.go`; Test: `internal/store/etcd/snapshot_test.go`
- Modify: `internal/store/placement/placement.go` (`Config.Expired`; `SeedPins`, `CachedPins`);
  Test: `internal/store/placement/snapshot_test.go` (new)
- Create: `internal/port49d/snapshot.go`
- Modify: `internal/port49d/storeref.go` (`PutLogout` on the handle; `lazyMembers`),
  `internal/port49d/brokerd.go` (`openBroker`, `runBroker`), `internal/port49d/store.go`
  (`openDaemon`, `openDirectoryLater`), `internal/port49d/runner.go` (`takeover`, `duties`; a
  `logouts` field)
- Test: `internal/port49d/twostores_linux_test.go`

**Interfaces:**
- Consumes:
  - `snapMarks`, `snapBroker` and the daemon's `ds/m/` grants (Task 7);
  - `etcd.Store.Revision` (Task 8a); `placement`'s pin cache (Task 8a);
  - `store.LogoutSet.All` (Task 8b);
  - `dirHandle`, `directoryCache`, `openDirectoryLater`, `keepFresh` (Tasks 9, 10);
  - `checkTwoStores`, `checkDirectoryKeys`, the runner's `dir` (Task 9a).
- Produces:
  - `(*store.Freshness).Seed(at time.Time)`, `Snapshot() bool`, `Confirmed() (time.Time, bool)`;
  - `func (s *etcd.Store) PutDirectorySnapshot(ctx, kind, writer string, body []byte, ttl time.Duration) error`
    and `DirectorySnapshots(ctx, kind string) (map[string][]byte, error)`, `kind` being
    `etcd.SnapshotMarks` (`"m"`) or `etcd.SnapshotBroker` (`"b"`);
  - `placement.Config.Expired func() error`; `func placement.SeedPins(s store.Store, pins []store.Membership)`
    and `func placement.CachedPins(s store.Store) []store.Membership`;
  - in `package port49d`: `type marksSnapshot`, `type brokerSnapshot`, `type snapshotView`,
    `type snapshotSource`, `var snapshotEvery`, `var snapshotCeiling`, `writerName`, `sealSnapshot`,
    `loadSnapshots`, `snapFeed`, `keepSnapshot`, `watchCeiling`; `directoryCache.fatal`;
    `type lazyMembers`; `openDirectoryLater` gains `proc` and `check`; the runner's
    `logouts *store.LogoutSet` and `putBackLater`.

R19 as amended and R29 (the pre-flight's I5 and I9, the team lead's ruling: a node must not go
dark because it restarted during a cut):
- **Written.** In a split every port49d and every port49-broker writes its copy to its session
  store every `snapshotEvery` (60s) while that copy is confirmed, as sealed records bound to their
  keys, with a lease of the ceiling:
  - `ds/m/<proc>@<host>`, the **marks record**: the directory revision read first, the confirmed
    time, and the revocation marks. Every process writes one; port49d may read every one.
  - `ds/b/port49-broker@<host>`, the **broker record**: the same revision and time, the logout
    records and the cached pins. Only port49-broker writes or reads it: the daemon's role has no
    grant on `ds/b/` (the pre-flight re-review's N4; `mb/` and `lo/` stay out of its reach).
  - The daemon's role writes `ds/m/port49d@` alone (N1): it cannot delete, or put an old body back
    under, a broker's marks record.
  - Two replicas on one host share their records; either's is current.
- **Read: the union, never the newest alone (N1).** A start in a split tries the directory once.
  When it does not answer, the process opens every marks record younger than the ceiling and
  serves the **union** of their marks (and a broker the union of every broker record's logouts,
  and the newest broker record's pins; a broker needs at least one broker record). A union only
  denies more, so a deleted newer record or a replayed older one lifts nothing while any honest
  record stands, and the broker's records are out of the daemon's reach. The copy's age is the
  newest record's confirmed time. It says so, and serves.
- **The heal (N5).** Once the directory opens, each follow starts from 0: it loads the directory
  afresh, which reconciles every add and lift, then watches. The ceiling and the `(snapshot)` mark
  clear only when that load has succeeded (the marks feed's first `FeedUp(true)`, which a load
  from 0 reaches only after the load); a read that answers before it, or a load that fails, keeps
  them.
- **A deferred check (N2).** When the directory opens after a snapshot start, the key check (R27)
  and the cluster check (R28) run before it is used. A fault there ends the process, exit 1, with
  the check's message: never a store gone, which would open the listeners on the held marks and
  flap.
- **The ceiling.** `session.staleness_ceiling` (4h by default, and 4h when it is off). While a
  process serves a snapshot not yet confirmed live and its age passes the ceiling, it fails
  closed: port49d closes its listeners through its gone path and waits for the directory;
  port49-broker answers every read of its copy `store_unavailable` (`placement.Config.Expired`), so
  every mint, refresh and sign-in is refused. The start line names the ceiling.
- **A runner during a cut (R29).** In a split the takeover lists the standing marks from the
  process's followed copy (`r.marks.All()`), applies them as today, and reaches every standing
  logout in its set. The put-back of `marks.json` runs as its own duty (`putBackLater`), which
  waits for the directory, then re-applies the marks to the kept contexts.

- [ ] **Step 1: Write the failing tests**

Append to `internal/store/fresh_test.go`:

```go
// R19: a copy seeded from a snapshot counts its age from the snapshot's
// confirmed time, and is a snapshot until a live read confirms it.
func TestASeededCopyIsASnapshotUntilConfirmed(t *testing.T) {
	now := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	f := NewFreshness(func() time.Time { return now })
	f.Seed(now.Add(-time.Hour))
	if age, ok := f.Age(); !ok || age != time.Hour || !f.Snapshot() {
		t.Fatalf("age %v %v, snapshot %v", age, ok, f.Snapshot())
	}
	f.Checked(nil) // the feed is not up: no confirmation
	if !f.Snapshot() {
		t.Fatal("a read with the feed down confirmed the snapshot")
	}
	f.FeedUp(true) // a load from 0 succeeded (N5)
	f.Checked(nil)
	if age, _ := f.Age(); age != 0 || f.Snapshot() {
		t.Fatalf("after a live confirmation: age %v, snapshot %v", age, f.Snapshot())
	}
	if at, ok := f.Confirmed(); !ok || !at.Equal(now) {
		t.Fatalf("confirmed %v %v", at, ok)
	}
}

// flakyFeed fails every load while fail is set, and watches until ctx ends.
type flakyFeed struct {
	mu   sync.Mutex
	fail bool
}

func (f *flakyFeed) Revocations(context.Context) (uint64, []Revocation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return 0, nil, ErrUnavailable
	}
	return 7, nil, nil
}

func (f *flakyFeed) WatchRevocations(ctx context.Context, _ uint64, _ func(Revocation, bool, uint64), _ func(uint64)) error {
	<-ctx.Done()
	return ctx.Err()
}

// N5: a snapshot's ceiling stays until a load of the directory succeeds; a
// directory that answers reads while its load fails does not clear it.
func TestAFailedLoadKeepsTheSnapshot(t *testing.T) {
	f := NewFreshness(time.Now)
	f.Seed(time.Now().Add(-time.Hour))
	feed := &flakyFeed{fail: true}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go FollowMarks(ctx, feed, NewMarks(), 0, nil, f.FeedUp, func() error { return nil }, func(string, ...any) {})
	time.Sleep(1500 * time.Millisecond)
	f.Checked(nil) // the directory answers a read
	if !f.Snapshot() {
		t.Fatal("the snapshot was cleared while the load failed")
	}
	feed.mu.Lock()
	feed.fail = false
	feed.mu.Unlock()
	for deadline := time.Now().Add(5 * time.Second); f.Snapshot(); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("a successful load did not clear the snapshot")
		}
	}
}
```

(`fresh_test.go` imports `context` and `sync` for it.)

Create `internal/store/etcd/snapshot_test.go`:

```go
package etcd

import (
	"context"
	"testing"
	"time"
)

// R19: a process's snapshot is one record under its writer, read back with
// every other writer's.
func TestDirectorySnapshotsRoundTrip(t *testing.T) {
	s := onShared(t, func() time.Time { return t0 })
	ctx := context.Background()
	if err := s.PutDirectorySnapshot(ctx, SnapshotMarks, "port49d@host-1", []byte("sealed-1"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.PutDirectorySnapshot(ctx, SnapshotMarks, "port49-broker@host-2", []byte("sealed-2"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.PutDirectorySnapshot(ctx, SnapshotBroker, "port49-broker@host-2", []byte("sealed-3"), time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := s.DirectorySnapshots(ctx, SnapshotMarks)
	if err != nil || len(got) != 2 || string(got["port49d@host-1"]) != "sealed-1" {
		t.Fatalf("%v %v", got, err)
	}
	if b, err := s.DirectorySnapshots(ctx, SnapshotBroker); err != nil || len(b) != 1 {
		t.Fatalf("the broker records: %v %v", b, err)
	}
}
```

Create `internal/store/placement/snapshot_test.go`:

```go
package placement

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
)

// R19: a copy past its ceiling answers every read of it store_unavailable:
// a mark, a logout and a cached pin.
func TestAnExpiredCopyAnswersUnavailable(t *testing.T) {
	ctx := context.Background()
	var expired error
	marks := store.NewMarks()
	marks.Set(store.Revocation{Kind: store.RevocationPrincipal, Key: alice, At: t0}, true)
	s := Wrap(Config{Session: memory.New(clock), Directory: memory.New(clock), Marks: marks,
		Logouts: store.NewLogoutSet(clock), LogoutDir: memory.New(clock), Expired: func() error { return expired },
		CallTimeout: time.Second, BulkTimeout: time.Second})
	if _, err := s.GetRevocation(ctx, store.RevocationPrincipal, alice); err != nil {
		t.Fatalf("before the ceiling: %v", err)
	}
	expired = errors.New("the snapshot is past the ceiling")
	if _, err := s.GetRevocation(ctx, store.RevocationPrincipal, alice); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a mark past the ceiling: %v, want ErrUnavailable", err)
	}
	if _, err := s.GetLogout(ctx, store.SidKey("https://idp", "s1")); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a logout past the ceiling: %v, want ErrUnavailable", err)
	}
}

// R19: the pins a snapshot carries seed the cache, and read back as cached.
func TestSeedPinsFillsTheCache(t *testing.T) {
	ctx := context.Background()
	a, _, _, _, _ := twoRegions(nil)
	SeedPins(a, []store.Membership{{Principal: alice, EntryID: "uuid:1", MapKeys: []string{"k1"}}})
	if !a.(*placed).cachedPin(alice) {
		t.Fatal("a seeded pin is not cached")
	}
	if got := CachedPins(a); len(got) != 1 || got[0].EntryID != "uuid:1" {
		t.Fatalf("%+v", got)
	}
	if got, err := a.GetMembership(ctx, alice); err != nil || got.EntryID != "uuid:1" {
		t.Fatalf("%+v %v", got, err)
	}
}
```

Append to `internal/port49d/twostores_linux_test.go`:

```go
// waitSnapshots waits until srv's session keyspace holds the region's
// first snapshot records: marks records from n processes, and a broker
// record.
func waitSnapshots(t *testing.T, srv *etcdtest.Server, n int64) {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Second); keysUnder(t, srv, "/port49/v1/ds/m/") < n ||
		keysUnder(t, srv, "/port49/v1/ds/b/") < 1; time.Sleep(200 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("fewer than %d marks record(s), or no broker record, were written", n)
		}
	}
}

// Review Focus, R19: port49-broker and port49d restarted during a cut each
// serve from the region's snapshot: a mint answers, and a session's command
// is permitted.
func TestARestartDuringACutServesFromTheSnapshot(t *testing.T) {
	var out, log syncBuffer
	e, o, every := stderr, stdout, snapshotEvery
	t.Cleanup(func() { stderr, stdout, snapshotEvery = e, o, every })
	stderr, stdout, snapshotEvery = &out, &log, time.Second
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	_, stopB := startBroker(t, f.broker, &out, 1)
	_, stopD := runSplitDaemon(t, f.daemon, &out, 1)
	waitSnapshots(t, f.srv, 2)
	f.dproxy.Hang(true)
	f.ddproxy.Hang(true)
	if err := stopD(); errors.Is(err, errDidNotStop) {
		t.Fatal(err)
	}
	if err := stopB(); errors.Is(err, errDidNotStop) {
		t.Fatal(err)
	}
	api, _ := startBroker(t, f.broker, &out, 2)
	dev := tacacsClient{t: t, addr: startSplitDaemon(t, f.daemon, &out, 2), key: []byte("run-test-secret")}
	for _, want := range []string{"port49-broker: directory store: not answering; serving from 2 snapshot(s)",
		"port49d: directory store: not answering; serving from 2 snapshot(s)"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("no %q:\n%s", want, out.String())
		}
	}
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
	if !dev.permits("alice", "show", "version") {
		t.Fatalf("a restart during the cut refused a command; log %s", log.String())
	}
}

// R19: a process serving a snapshot fails closed at the ceiling: port49d
// says so and closes its listeners.
func TestASnapshotPastTheCeilingFailsClosed(t *testing.T) {
	var out syncBuffer
	e, every, ceiling := stderr, snapshotEvery, snapshotCeiling
	t.Cleanup(func() { stderr, snapshotEvery, snapshotCeiling = e, every, ceiling })
	stderr, snapshotEvery = &out, time.Second
	snapshotCeiling = func(config.Config) time.Duration { return 20 * time.Second }
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	startBroker(t, f.broker, &out, 1)
	_, stopD := runSplitDaemon(t, f.daemon, &out, 1)
	waitSnapshots(t, f.srv, 2)
	f.ddproxy.Hang(true)
	if err := stopD(); errors.Is(err, errDidNotStop) {
		t.Fatal(err)
	}
	startSplitDaemon(t, f.daemon, &out, 2)
	waitWithin(t, &out, "port49d: directory store: the snapshot this run serves from is", 60*time.Second)
	waitWithin(t, &out, "past session.staleness_ceiling (20s)", time.Second)
	waitWithin(t, &out, "closing every listener so that devices use their local method", 10*time.Second)
}

// R29: a runner taking over during a cut runs its session duties: the
// takeover finishes (a mint answers), the put-back waits for the directory
// and says so, and lands on the heal.
func TestATakeoverDuringACutRunsTheSessionDuties(t *testing.T) {
	var out syncBuffer
	e, every := stderr, snapshotEvery
	t.Cleanup(func() { stderr, snapshotEvery = e, every })
	stderr, snapshotEvery = &out, time.Second
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	_, stop := startBroker(t, f.broker, &out, 1)
	waitWithin(t, &out, "port49-broker: runner: took keyspace", 30*time.Second)
	waitSnapshots(t, f.srv, 1)
	f.dproxy.Hang(true)
	if err := stop(); errors.Is(err, errDidNotStop) {
		t.Fatal(err)
	}
	api, _ := startBroker(t, f.broker, &out, 2)
	waitCountWithin(t, &out, "port49-broker: runner: took keyspace", 2, 60*time.Second)
	waitWithin(t, &out, "the put-back of broker.state_dir/marks.json waits for the directory store", 30*time.Second)
	_ = mintOn(t, api, f.pki, "leaf1") // the start's mint gate opened: the takeover finished in the cut
	f.dproxy.Hang(false)
	waitWithin(t, &out, "every revocation in broker.state_dir/marks.json is in the store", 60*time.Second)
}
```

Also append:

```go
// N2: a key fault found when the directory opens after a snapshot start
// ends port49d, exit 1, with the check's message; the listeners never open
// again.
func TestADeferredKeyFaultEndsPort49d(t *testing.T) {
	var out syncBuffer
	e, every := stderr, snapshotEvery
	t.Cleanup(func() { stderr, snapshotEvery = e, every })
	stderr, snapshotEvery = &out, time.Second
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	startBroker(t, f.broker, &out, 1)
	_, stopD := runSplitDaemon(t, f.daemon, &out, 1)
	waitSnapshots(t, f.srv, 2)
	f.ddproxy.Hang(true)
	if err := stopD(); errors.Is(err, errDidNotStop) {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- run(context.Background(), f.daemon) }()
	waitCountWithin(t, &out, "port49d: listening on ", 2, 60*time.Second) // served from the snapshots
	if _, err := f.dsrv.Client(t, "root").Put(context.Background(), "/port49/v1/meta/seal_keys",
		`{"current":"key-from-elsewhere","written_at":"2026-10-17T00:00:00Z"}`); err != nil {
		t.Fatal(err)
	}
	f.ddproxy.Hang(false)
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "which this configuration does not hold") {
			t.Fatalf("%v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("port49d kept running with a directory under a key it lacks")
	}
	if n := strings.Count(out.String(), "port49d: listening on "); n != 2 {
		t.Fatalf("the listeners opened %d times; want 2 (the first run, the snapshot run), no flapping", n)
	}
}
```

Add `"context"`, `"errors"` and `"github.com/rhwendt/port49/internal/store/etcd/etcdtest"` to its
imports if they are not there.

Create `internal/port49d/snapshot_test.go`:

```go
package port49d

import (
	"context"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
)

// fakeSnapshots is a session store's snapshot records by kind and writer.
type fakeSnapshots map[string]map[string][]byte

func (f fakeSnapshots) DirectorySnapshots(_ context.Context, kind string) (map[string][]byte, error) {
	return f[kind], nil
}

// N1: port49d serves the union of every marks record: its own record
// deleted, or an older body of it put back, lifts nothing a broker's record
// holds.
func TestTheSnapshotsMarksAreTheirUnion(t *testing.T) {
	keys := signInTestKeys
	now := time.Now()
	a := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:a@example.com", At: now.Add(-2 * time.Hour)}
	b := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:b@example.com", At: now.Add(-time.Minute)}
	seal := func(writer string, conf time.Time, marks ...store.Revocation) []byte {
		raw, err := sealSnapshot(keys, etcdstore.SnapshotMarks, writer,
			marksSnapshot{Writer: writer, Revision: 9, Confirmed: conf, Marks: marks})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	oldDaemon := seal("port49d@h1", now.Add(-time.Hour), a) // an older body, put back by the daemon's key holder
	broker := seal("port49-broker@h2", now.Add(-30*time.Second), a, b)
	for name, recs := range map[string]map[string][]byte{
		"an older body put back": {"port49d@h1": oldDaemon, "port49-broker@h2": broker},
		"its own record deleted": {"port49-broker@h2": broker},
	} {
		v, ok, err := loadSnapshots(context.Background(), fakeSnapshots{etcdstore.SnapshotMarks: recs}, keys, false,
			4*time.Hour, time.Second, io.Discard, "port49d")
		if err != nil || !ok {
			t.Fatalf("%s: %v %v", name, ok, err)
		}
		held := map[string]bool{}
		for _, r := range v.marks {
			held[r.Key] = true
		}
		if !held[a.Key] || !held[b.Key] || !v.confirmed.Equal(now.Add(-30*time.Second)) {
			t.Fatalf("%s: marks %v, confirmed %v; want both marks and the broker's time", name, held, v.confirmed)
		}
	}
	// A record past the ceiling is not served; one that does not open is skipped.
	stale := seal("port49d@h1", now.Add(-5*time.Hour), a, b)
	if _, ok, _ := loadSnapshots(context.Background(), fakeSnapshots{etcdstore.SnapshotMarks: {"port49d@h1": stale,
		"port49d@h3": []byte("not sealed")}}, keys, false, 4*time.Hour, time.Second, io.Discard, "port49d"); ok {
		t.Fatal("a record past the ceiling was served")
	}
}
```

(`snapshot_test.go` imports `io` too. `signInTestKeys` is the port49d tests' key set.)

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/store/ ./internal/store/etcd/ ./internal/store/placement/ ./internal/port49d/ -run 'Seeded|FailedLoadKeeps|DirectorySnapshots|Expired|SeedPins|RestartDuringACut|PastTheCeiling|TakeoverDuringACut|DeferredKeyFault|SnapshotsMarksAreTheirUnion' -count=1`
Expected: FAIL to compile (`f.Seed undefined`; `undefined: snapshotEvery`).

- [ ] **Step 3: Freshness, the record, and the router**

In `internal/store/fresh.go`, add `snapshot bool` to `Freshness`. `FeedUp(true)` clears it
(`if up { f.snapshot = false }`): a feed from 0 reports up only after its load succeeded (Task 3),
and the snapshot start follows from 0 (Step 5), so the flag clears at that load and at nothing
earlier (N5). `Checked` does not touch it. Then add:

```go
// Seed is a copy loaded from a snapshot confirmed at at (plan 11a, R19):
// Age counts from at, and Snapshot reports true until the marks feed's
// load from the directory succeeds (FeedUp). It tells onConfirm, as a
// confirmation does.
func (f *Freshness) Seed(at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.confirmed, f.snapshot = at, true
	if f.onConfirm != nil {
		f.onConfirm(at)
	}
}

// Snapshot reports whether the copy is a snapshot's, not yet reloaded from
// the directory.
func (f *Freshness) Snapshot() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snapshot
}

// Confirmed is when the copy was last confirmed (a snapshot's time while it
// is one), and false before the first.
func (f *Freshness) Confirmed() (time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.confirmed, !f.confirmed.IsZero()
}
```

Create `internal/store/etcd/snapshot.go`:

```go
package etcd

import (
	"context"
	"net/url"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// The two kinds of directory snapshot record (plan 11a, R19): the marks,
// which port49d may read, and a broker's logouts and pins, which it may not.
const (
	SnapshotMarks  = "m"
	SnapshotBroker = "b"
)

// PutDirectorySnapshot writes writer's directory snapshot record of kind
// (plan 11a, R19): body is sealed by the caller; the record lives for ttl,
// so a writer that went away leaves nothing for long.
func (s *Store) PutDirectorySnapshot(ctx context.Context, kind, writer string, body []byte, ttl time.Duration) error {
	_, err := commit(ctx, s.tok, s.tokLeases, nil, []put{{key: s.k.snapshot(kind, writer), val: body,
		exp: s.now().Add(ttl)}})
	return err
}

// DirectorySnapshots is every live snapshot record of kind, by its writer.
// A key that does not parse is said and skipped.
func (s *Store) DirectorySnapshots(ctx context.Context, kind string) (map[string][]byte, error) {
	prefix := s.k.family(famSnapshot) + kind + "/"
	resp, err := s.tok.Get(ctx, prefix, clientv3.WithPrefix())
	if err != nil {
		return nil, unavailable(err)
	}
	out := make(map[string][]byte, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		w, err := url.PathUnescape(strings.TrimPrefix(string(kv.Key), prefix))
		if err != nil {
			s.logf("etcd: the directory snapshot key %q does not parse; skipped", kv.Key)
			continue
		}
		out[w] = kv.Value
	}
	return out, nil
}
```

In `internal/store/placement/placement.go`, add to `Config`:

```go
	// Expired, when it returns an error, fails every read of the process's
	// copy (a mark, a logout, a cached pin) with ErrUnavailable: a copy
	// loaded from a snapshot past its ceiling (R19). Nil never expires.
	Expired func() error
```

and the helper, called first in `GetRevocation`, in `GetLogout` (before the set is read) and in
`GetMembership` (before `dirPin`):

```go
// expired is the copy's ceiling, as an ErrUnavailable; nil while it serves.
func (p *placed) expired() error {
	if p.c.Expired == nil {
		return nil
	}
	if err := p.c.Expired(); err != nil {
		return fmt.Errorf("%w: %v", store.ErrUnavailable, err)
	}
	return nil
}
```

Then:

```go
// SeedPins fills s's pin cache with a snapshot's pins (R19): each as the
// directory held it when the snapshot was written. FollowPins drops them all
// once its watch begins. s not a router does nothing.
func SeedPins(s store.Store, pins []store.Membership) {
	p, ok := s.(*placed)
	if !ok || p.c.Members == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, pin := range pins {
		if len(p.pins) >= maxPins {
			return
		}
		p.pins[pin.Principal] = pinEntry{pin: pin, state: pinHeld}
	}
}

// CachedPins is every pin s's cache holds as pinned, for a snapshot (R19).
func CachedPins(s store.Store) []store.Membership {
	p, ok := s.(*placed)
	if !ok {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]store.Membership, 0, len(p.pins))
	for _, e := range p.pins {
		if e.state == pinHeld {
			out = append(out, e.pin)
		}
	}
	return out
}
```

Run: `go test ./internal/store/ ./internal/store/etcd/ ./internal/store/placement/ -count=1`
Expected: PASS.

- [ ] **Step 4: Write, find and open a snapshot**

Create `internal/port49d/snapshot.go`:

```go
package port49d

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/crypt"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
)

// snapshotEvery is how often a process in a split writes its directory
// snapshot records (plan 11a, R19); a variable so a test can shorten it.
var snapshotEvery = time.Minute

// snapshotCeiling is how old a snapshot may be served (R19):
// session.staleness_ceiling, or its default when it is off; a variable so
// a test can shorten it without shortening the contexts' ceiling.
var snapshotCeiling = func(cfg config.Config) time.Duration {
	if c := cfg.Session.StalenessCeiling; c > 0 {
		return c
	}
	return config.DefaultStalenessCeiling
}

// marksSnapshot is a marks record (ds/m/<writer>): the directory revision
// read before the copy was taken, when the copy was last confirmed, and the
// marks. Every process writes one; port49d reads every one. The store types
// encode by their Go field names: only this code reads it back.
type marksSnapshot struct {
	Writer    string
	Revision  uint64
	Confirmed time.Time
	Marks     []store.Revocation
}

// brokerSnapshot is a broker record (ds/b/<writer>): the logout records and
// the cached pins, which the daemon's role cannot read (N4).
type brokerSnapshot struct {
	Writer    string
	Revision  uint64
	Confirmed time.Time
	Logouts   []store.LogoutEntry
	Pins      []store.Membership
}

// snapshotView is what a start serves from: the union of every record's
// marks (and, for a broker, logouts), the newest broker record's pins, the
// newest confirmed time, and how many records it was made of.
type snapshotView struct {
	marks     []store.Revocation
	logouts   []store.LogoutEntry
	pins      []store.Membership
	confirmed time.Time
	newest    string // the writer of the newest record
	records   int
}

// snapshotSource is a session store's snapshot records (*etcd.Store).
type snapshotSource interface {
	DirectorySnapshots(ctx context.Context, kind string) (map[string][]byte, error)
}

// writerName is this process's snapshot key: proc@host. Two replicas on one
// host share it.
func writerName(proc string) string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		h = "unknown"
	}
	return proc + "@" + h
}

// sealSnapshot seals body as writer's record of kind, bound to its key, so a
// record copied under another key does not open.
func sealSnapshot(keys crypt.Keys, kind, writer string, body any) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return keys.SealBound(raw, []byte("ds/"+kind+"/"+writer))
}

// openSnapshots opens every record of kind in src into fn, skipping one
// that does not open (said by its writer and key id alone) or whose writer
// is not its key's.
func openSnapshots(ctx context.Context, src snapshotSource, keys crypt.Keys, kind string, bound time.Duration,
	out io.Writer, proc string, fn func(writer string, raw []byte) bool) error {
	rctx, cancel := context.WithTimeout(ctx, bound)
	all, err := src.DirectorySnapshots(rctx, kind)
	cancel()
	if err != nil {
		return err
	}
	for w, sealed := range all {
		raw, err := keys.OpenBound(sealed, []byte("ds/"+kind+"/"+w))
		if err != nil || !fn(w, raw) {
			fmt.Fprintf(out, "%s: directory store: the snapshot record %s/%s does not open (key %s); skipped\n", proc,
				kind, printsafe.Line(w, 200), crypt.LineKeyID(crypt.SealedKeyID(sealed)))
		}
	}
	return nil
}

// loadSnapshots is what a start in a cut serves from (R19, N1): the union
// of the marks of every marks record that opens and is younger than
// ceiling, never the newest alone, so a deleted or replayed record lifts
// nothing another record holds. With broker, also the union of every
// broker record's logouts and the newest broker record's pins, and at
// least one broker record is needed. false when nothing young enough opens.
func loadSnapshots(ctx context.Context, src snapshotSource, keys crypt.Keys, broker bool, ceiling,
	bound time.Duration, out io.Writer, proc string) (snapshotView, bool, error) {
	var v snapshotView
	seen := map[[2]string]bool{}
	young := func(at time.Time) bool { return time.Since(at) < ceiling }
	note := func(w string, at time.Time) {
		v.records++
		if at.After(v.confirmed) {
			v.confirmed, v.newest = at, w
		}
	}
	if err := openSnapshots(ctx, src, keys, etcdstore.SnapshotMarks, bound, out, proc, func(w string, raw []byte) bool {
		var b marksSnapshot
		if json.Unmarshal(raw, &b) != nil || b.Writer != w {
			return false
		}
		if !young(b.Confirmed) {
			return true
		}
		note(w, b.Confirmed)
		for _, r := range b.Marks {
			if k := [2]string{r.Kind, r.Key}; !seen[k] {
				seen[k] = true
				v.marks = append(v.marks, r)
			}
		}
		return true
	}); err != nil {
		return snapshotView{}, false, err
	}
	if v.records == 0 {
		return snapshotView{}, false, nil
	}
	if !broker {
		return v, true, nil
	}
	brokers := 0
	var pinsAt time.Time
	if err := openSnapshots(ctx, src, keys, etcdstore.SnapshotBroker, bound, out, proc, func(w string, raw []byte) bool {
		var b brokerSnapshot
		if json.Unmarshal(raw, &b) != nil || b.Writer != w {
			return false
		}
		if !young(b.Confirmed) {
			return true
		}
		brokers++
		v.logouts = append(v.logouts, b.Logouts...) // LogoutSet.Put keeps the later of a key's
		if b.Confirmed.After(pinsAt) {
			v.pins, pinsAt = b.Pins, b.Confirmed
		}
		return true
	}); err != nil {
		return snapshotView{}, false, err
	}
	return v, brokers > 0, nil
}

// snapFeed is a view's marks as a MarkFeed for one load. It never watches.
type snapFeed struct{ v snapshotView }

func (f snapFeed) Revocations(context.Context) (uint64, []store.Revocation, error) {
	return 1, f.v.marks, nil
}

func (f snapFeed) WatchRevocations(context.Context, uint64, func(r store.Revocation, lifted bool, rev uint64),
	func(rev uint64)) error {
	return fmt.Errorf("%w: a snapshot is not watched", store.ErrUnavailable)
}

// snapshotLine is the start's line for a run that serves from v.
func snapshotLine(proc string, v snapshotView, ceiling time.Duration, then string) string {
	return fmt.Sprintf("%s: directory store: not answering; serving from %d snapshot(s), the newest %s's, confirmed "+
		"%s ago: %d revocation(s) in their union; served until it is %s old (session.staleness_ceiling), then %s",
		proc, v.records, printsafe.Line(v.newest, 200), ageText(time.Since(v.confirmed)), len(v.marks), ceiling, then)
}

// keepSnapshot writes this process's snapshot records every snapshotEvery
// while its copy is confirmed live (R19), until ctx ends: the directory's
// revision first, then its marks record, and with brokerTake (nil for
// port49d) its broker record. A write that fails is said once until one
// lands.
func keepSnapshot(ctx context.Context, sess *etcdstore.Store, dir *dirHandle, fresh *store.Freshness,
	keys crypt.Keys, writer string, ttl time.Duration, marks func() []store.Revocation,
	brokerTake func(*brokerSnapshot), out io.Writer, proc string) {
	t := time.NewTicker(snapshotEvery)
	defer t.Stop()
	failing := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		d := dir.get()
		at, ok := fresh.Confirmed()
		if reach, _ := fresh.Reachable(); d == nil || !ok || !reach || fresh.Snapshot() {
			continue // only a copy confirmed live is written
		}
		err := func() error {
			rctx, cancel := context.WithTimeout(ctx, 4*time.Second)
			defer cancel()
			rev, err := d.Revision(rctx)
			if err != nil {
				return err
			}
			sealed, err := sealSnapshot(keys, etcdstore.SnapshotMarks, writer,
				marksSnapshot{Writer: writer, Revision: rev, Confirmed: at, Marks: marks()})
			if err == nil {
				err = sess.PutDirectorySnapshot(rctx, etcdstore.SnapshotMarks, writer, sealed, ttl)
			}
			if err != nil || brokerTake == nil {
				return err
			}
			b := brokerSnapshot{Writer: writer, Revision: rev, Confirmed: at}
			brokerTake(&b)
			if sealed, err = sealSnapshot(keys, etcdstore.SnapshotBroker, writer, b); err != nil {
				return err
			}
			return sess.PutDirectorySnapshot(rctx, etcdstore.SnapshotBroker, writer, sealed, ttl)
		}()
		switch {
		case err != nil && !failing:
			fmt.Fprintf(out, "%s: directory store: the snapshot was not written (%s); the last one written stands\n",
				proc, printsafeErr(err))
			failing = true
		case err == nil:
			failing = false
		}
	}
}

// ceilingErr is the copy's ceiling while it serves a snapshot not yet
// reloaded from the directory (R19, N5): nil before it, the reason after.
func ceilingErr(fresh *store.Freshness, ceiling time.Duration) error {
	if !fresh.Snapshot() {
		return nil
	}
	if age, ok := fresh.Age(); ok && age > ceiling {
		return fmt.Errorf("the snapshot this run serves from is %s old, past session.staleness_ceiling (%s)",
			ageText(age), ceiling)
	}
	return nil
}

// watchCeiling is port49d's ceiling (R19): every second, once the snapshot
// it serves from passes the ceiling, it says so, forgets that it holds a
// cache (dc), and calls gone, which closes the listeners; the next run
// waits for the directory. It returns then, or when ctx ends.
func watchCeiling(ctx context.Context, dc *directoryCache, ceiling time.Duration, gone func(error), out io.Writer) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := ceilingErr(dc.fresh, ceiling); err != nil {
			fmt.Fprintf(out, "port49d: directory store: %v: the listeners close until the directory answers\n", err)
			dc.loaded.Store(false)
			gone(errors.New("directory store: " + err.Error()))
			return
		}
	}
}
```

In `internal/port49d/storeref.go`, add:

```go
// PutLogout writes a logout to the directory (placement.Config.LogoutDir).
func (h *dirHandle) PutLogout(ctx context.Context, l store.Logout, ttl time.Duration) error {
	if s := h.get(); s != nil {
		return s.PutLogout(ctx, l, ttl)
	}
	return errNoDirectory
}

// lazyMembers is the directory's membership half over a handle that may
// open after the start (R19), sealed as the session store's: the sealing
// layer is made at the first call that finds the handle open.
type lazyMembers struct {
	h    *dirHandle
	wrap func(store.Store) store.Store
	mu   sync.Mutex
	of   *etcdstore.Store
	m    store.Store
}

func (l *lazyMembers) get() (store.Store, error) {
	s := l.h.get()
	if s == nil {
		return nil, errNoDirectory
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.of != s {
		l.of, l.m = s, l.wrap(s)
	}
	return l.m, nil
}

func (l *lazyMembers) PutMembership(ctx context.Context, m store.Membership, ttl time.Duration) error {
	s, err := l.get()
	if err != nil {
		return err
	}
	return s.PutMembership(ctx, m, ttl)
}

func (l *lazyMembers) GetMembership(ctx context.Context, p string) (store.Membership, error) {
	s, err := l.get()
	if err != nil {
		return store.Membership{}, err
	}
	return s.GetMembership(ctx, p)
}

func (l *lazyMembers) MembershipByKey(ctx context.Context, k string) (store.Membership, error) {
	s, err := l.get()
	if err != nil {
		return store.Membership{}, err
	}
	return s.MembershipByKey(ctx, k)
}

func (l *lazyMembers) RefuseMapKeys(ctx context.Context, ks []string, at time.Time, ttl time.Duration) error {
	s, err := l.get()
	if err != nil {
		return err
	}
	return s.RefuseMapKeys(ctx, ks, at, ttl)
}

func (l *lazyMembers) DeleteMembership(ctx context.Context, p string) (store.Membership, error) {
	s, err := l.get()
	if err != nil {
		return store.Membership{}, err
	}
	return s.DeleteMembership(ctx, p)
}
```

(`storeref.go` imports `sync` and `time`.)

`openDirectoryLater` (Task 10) becomes
`openDirectoryLater(ctx, cfg, m, out, dir *dirHandle, proc string, check func(*etcdstore.Store) error) error`:
its lines begin with `proc`; once `attempt` opens the store it runs `check` (nil skips it), and a
check that fails closes the store and returns the error, which the caller treats as fatal;
`ctx` ending returns `ctx.Err()`.

- [ ] **Step 5: port49d starts from a snapshot**

In `internal/port49d/store.go`'s `openDaemon`, the `!dc.loaded.Load()` case (Task 10) becomes:

```go
	case !dc.loaded.Load():
		dd, err := attempt(ctx, cfg, directoryRef(cfg), m, out)
		switch {
		case err == nil: // checked and loaded in the block below
		case errors.Is(err, store.ErrUnavailable):
			ceiling := snapshotCeiling(cfg)
			snap, ok, serr := loadSnapshots(ctx, d, keys, false, ceiling, 4*e.CallTimeout, out, "port49d")
			if serr == nil && ok {
				if err := loadFrom(snapFeed{snap}, e.BulkTimeout); err != nil {
					return fail(err)
				}
				markRev = 0 // the follow loads the directory afresh once it opens (N5)
				dc.fresh.Seed(snap.confirmed)
				fmt.Fprintln(out, snapshotLine("port49d", snap, ceiling, "the listeners close"))
				break
			}
			fmt.Fprintf(out, "port49d: directory store at %s: not answering (%v); no snapshot in the session "+
				"store is younger than session.staleness_ceiling (%s)\n", directoryRef(cfg).where(), err, ceiling)
			if dd, err = waitForStore(ctx, cfg, directoryRef(cfg), m, out, again, "the listeners stay closed"); err != nil {
				return fail(err)
			}
		default:
			return fail(err)
		}
		if dd != nil {
			// Task 9a's checkTwoStores and checkDirectoryKeys (write false), then:
			dir.set(dd)
			if err := loadFrom(dd, cfg.Stores.Directory.Etcd.BulkTimeout); err != nil {
				dir.close()
				return fail(err)
			}
			fmt.Fprintf(out, "port49d: store: %d revocation(s) in force from the directory store\n", authMarks.Len())
		}
```

Move Task 9a's two checks into the `dd != nil` block, so either way of opening runs them. In the
snapshot case `markRev` is 0: once the directory opens, the marks follow loads it afresh before it
watches (Task 3), which reconciles every add and lift; that load's `FeedUp(true)` clears the
snapshot and its ceiling, and a load that fails keeps them (N5).

In `follow`, the marks goroutine's `openDirectoryLater` call passes `"port49d"` and a check that
runs `checkTwoStores` and `checkDirectoryKeys` (write false). A check that fails is never a store
gone (N2): a store gone would run again on the held marks, open the listeners and fail again. It
goes to the process instead: `directoryCache` gains `fatal chan error` (made in `run`, buffered
one), the goroutine sends the error there and returns, and `runOnce` selects on `dc.fatal` beside
its other ends and returns the error as its cold start's faults are returned, so `run` returns it
and port49d exits 1 with the check's message. When `dc.fresh.Snapshot()` at the time `follow`
begins, it also starts (`wg.Add(1)`) `watchCeiling(ctx, dc, snapshotCeiling(cfg), gone, out)`.

In a split, `follow` starts one more goroutine:

```go
		go func() {
			defer wg.Done()
			keepSnapshot(ctx, d, dir, dc.fresh, keys, writerName("port49d"), snapshotCeiling(cfg),
				authMarks.All, nil, out, "port49d") // a marks record alone: no broker record (N4)
		}()
```

`openDaemon` takes `keys` already; `follow` reads it from the closure.

- [ ] **Step 6: port49-broker starts from a snapshot**

In `internal/port49d/brokerd.go`'s `openBroker`, the split branch (Tasks 9 and 9a) becomes:

1. `dirRaw, err := attempt(ctx, cfg, directoryRef(cfg), m, out)`.
2. On `nil`: Task 9a's checks, `bs.dir.set(dirRaw)`, and the marks and logouts load from it as in
   Task 9.
3. On `store.ErrUnavailable`: `loadSnapshots(ctx, b, keys, true, snapshotCeiling(cfg), 4*e.CallTimeout, out, "port49-broker")`.
   - Found: `store.LoadMarks(lctx, snapFeed{snap}, marks, nil)`; `bs.markRev = 0` and
     `bs.logoutRev = 0`, so each follow loads the directory afresh once it opens (N5); each of
     `snap.logouts` is `bs.logouts.Put` (the union keeps the later of a key's); `bs.fresh.Seed(snap.confirmed)`;
     and say `snapshotLine("port49-broker", snap, ceiling, "mints and sign-ins are refused")`. The
     pins are seeded after the router is built: `placement.SeedPins(bs.st, snap.pins)`.
   - None: say `port49-broker: directory store at <where>: not answering (<err>); no snapshot in the
     session store is younger than session.staleness_ceiling (<ceiling>)`, then
     `waitForStore(ctx, cfg, directoryRef(cfg), m, out, false, "nothing is served yet")` and on as
     in step 2.
4. Any other error: `fail(err)`.

The router is built over the handle, so it serves before the directory opens:

```go
	bs.st = placement.Wrap(placement.Config{Session: bs.st, Directory: bs.dir,
		Members: &lazyMembers{h: bs.dir, wrap: func(s store.Store) store.Store {
			return crypt.Wrap(s, keys, m.CryptOpenFailures, crypt.WithLedger(crypt.NewLedger()), say)
		}},
		Marks: marks, Logouts: bs.logouts, LogoutDir: bs.dir,
		CallTimeout: de.CallTimeout, BulkTimeout: de.BulkTimeout,
		Reachable: func() bool { ok, why := bs.fresh.Reachable(); return ok || why == "" },
		Expired:   func() error { return ceilingErr(bs.fresh, snapshotCeiling(cfg)) },
		Say:       func(format string, args ...any) { fmt.Fprintf(out, "port49-broker: "+format+"\n", args...) }})
```

`bs.dir` is made before the branch (`bs.dir = &dirHandle{}`), and `fail` closes it.

In `runBroker`, in a split:

1. One goroutine opens the directory when the start did not, and closes `ready` once it is open
   (at once when it already is):
   ```go
   	ready, dirErr := make(chan struct{}), make(chan error, 1)
   	wg.Add(1)
   	go func() {
   		defer wg.Done()
   		if bs.dir.get() == nil {
   			if err := openDirectoryLater(ctx, cfg, m, stderr, bs.dir, "port49-broker", func(s *etcdstore.Store) error {
   				if err := checkTwoStores(ctx, cfg, bs.raw, s, 4*de.CallTimeout); err != nil {
   					return err
   				}
   				return checkDirectoryKeys(ctx, "port49-broker", s, directoryRef(cfg), keys, stderr, 4*de.CallTimeout, true)
   			}); err != nil {
   				if ctx.Err() == nil {
   					dirErr <- err // ends the run: the process exits 1 saying it
   				}
   				return
   			}
   		}
   		close(ready)
   	}()
   ```
   The final `select` gains `case err := <-dirErr: runErr = err`, beside `metricsErr` and
   `brokerErr`.
2. The marks, pins and logouts follows (Task 9, steps 4 to 6) each begin with
   `select { case <-ctx.Done(): return; case <-ready: }` and read `bs.dir.get()` after it.
3. `keepFresh` needs no wait: it reads the handle at each check.
4. The snapshot writer:
   ```go
   	wg.Add(1)
   	go func() {
   		defer wg.Done()
   		keepSnapshot(ctx, bs.raw, bs.dir, bs.fresh, keys, writerName("port49-broker"), snapshotCeiling(cfg),
   			marks.All, func(b *brokerSnapshot) { b.Logouts, b.Pins = bs.logouts.All(), placement.CachedPins(bs.st) },
   			stderr, "port49-broker")
   	}()
   ```
5. `rn.logouts = bs.logouts`.

- [ ] **Step 7: A runner during a cut (R29)**

In `internal/port49d/runner.go`:

1. Add to `runner`:
   ```go
   	// logouts is the followed copy of the directory's logout records in a
   	// split: the takeover reaches every standing one here (R29). Nil in a
   	// shared store.
   	logouts *store.LogoutSet
   ```
2. In `takeover`, in a split (`r.dir != nil`):
   - skip `r.restoreMarks(ctx)` and say, once:
     `port49-broker: runner: the put-back of broker.state_dir/marks.json waits for the directory store; this region's duties run meanwhile`;
   - take `all := r.marks.All()` in place of the `ListRevocations` retry;
   - after `ApplyMarksAtStart` and its line, reach every standing logout:
     ```go
     	if r.logouts != nil {
     		var keys, ctxs int
     		for _, e := range r.logouts.All() {
     			rep, _ := r.brk.ReachLogout(ctx, e.Logout) // each said by its own report's error, if any, below
     			keys, ctxs = keys+rep.TokenKeys, ctxs+len(rep.Contexts)
     		}
     		if n := r.logouts.Len(); n > 0 {
     			fmt.Fprintf(stderr, "port49-broker: runner: %d standing logout(s) reached here: %d token key(s), "+
     				"%d context(s)\n", n, keys, ctxs)
     		}
     	}
     ```
3. Add:
   ```go
   // putBackLater is the takeover's put-back in a split (R29): restoreMarks,
   // which waits for the directory, then the marks applied to the kept
   // contexts again when it put any back.
   func (r *runner) putBackLater(ctx context.Context) {
   	if err := r.restoreMarks(ctx); err != nil {
   		return // ctx ended
   	}
   	select {
   	case r.marksReloaded <- struct{}{}:
   	default:
   	}
   }
   ```
   and start it in `duties` beside Task 9's `r.followed != nil` goroutines (`wg.Add(1)` more):
   `go func() { defer wg.Done(); r.putBackLater(ctx) }()`. `marksReloaded` is the channel the
   duties already drain to apply the marks again after a put-back.

- [ ] **Step 8: Run them to verify they pass**

Run: `go test ./internal/store/... ./internal/port49d/ -count=1`
Expected: PASS: the ten new tests, and every test before.

- [ ] **Step 9: Commit**

```bash
git add internal/store/fresh.go internal/store/fresh_test.go internal/store/etcd/snapshot.go \
  internal/store/etcd/snapshot_test.go internal/store/placement internal/port49d
git commit -m "feat: a process restarted during a directory cut serves from its region's sealed snapshot, to the ceiling

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 11: `port49d store-roles`, one section per store

**Files:**
- Modify: `internal/port49d/storeroles.go` (`storeRolesCmd`; `storeBlocksOf` becomes `storesBlocksOf`;
  Task 2's single-store refusal removed)
- Modify: `internal/store/etcd/roles.go` (`beyondDirectoryDaemon` judges only the grants that reach
  its keyspace)
- Test: `internal/port49d/storeroles_test.go`, `internal/store/etcd/roles_test.go`

**Interfaces:**
- Consumes: `config.StoresBlocks` (Task 2), `etcd.RolesFor` and `Scope` (Task 7).
- Produces: the command's output, one section per store. The lab's `applyRoles` (Task 14) splits it
  at each section's first line, `# port49 roles for the directory store` or
  `# port49 roles for the session store`. A shared store keeps today's single section, header
  included.

- [ ] **Step 1: Write the failing tests**

Append to `internal/port49d/storeroles_test.go`:

```go
// writeTwoStoreRolesConfig is writeStoreRolesConfig with a directory store
// of its own at dir-0 and the session store at sess-0, each naming both
// identities.
func writeTwoStoreRolesConfig(t *testing.T, dir, ca string, d, b [2]string) string {
	t.Helper()
	base := writeRunConfig(t, brokerConfig(t, minimalPolicy).Broker)
	raw, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	block := func(name, ep string) string {
		return "  " + name + ":\n    backend: etcd\n    etcd:\n      endpoints: [https://" + ep + ":2379]\n" +
			"      ca_file: " + ca + "\n      daemon: {cert_file: " + d[0] + ", key_file: " + d[1] + "}\n" +
			"      broker: {cert_file: " + b[0] + ", key_file: " + b[1] + "}\n"
	}
	raw = append(raw, []byte("\nstores:\n"+block("directory", "dir-0")+block("session", "sess-0")+
		"admin_socket: "+filepath.Join(dir, "admin.sock")+"\n")...)
	p := filepath.Join(dir, "port49d.yaml")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// R23: with a directory store of its own, a section per store, each run
// against its own cluster; on the directory the daemon reads rv/ and
// meta/ping alone, and on the session store it is granted no rv/.
func TestStoreRolesPrintsASectionPerStore(t *testing.T) {
	single := storeRolesFixture(t, "port49-daemon", "port49-broker")
	dir := filepath.Dir(single)
	cfg := writeTwoStoreRolesConfig(t, dir, filepath.Join(dir, "ca.pem"),
		[2]string{filepath.Join(dir, "daemon.pem"), filepath.Join(dir, "daemon-key.pem")},
		[2]string{filepath.Join(dir, "broker.pem"), filepath.Join(dir, "broker-key.pem")})
	var out, errb bytes.Buffer
	if code := storeRolesCmd([]string{"--config", cfg}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	text := out.String()
	d := strings.Index(text, "# port49 roles for the directory store")
	s := strings.Index(text, "# port49 roles for the session store")
	if d < 0 || s < d {
		t.Fatalf("the sections:\n%s", text)
	}
	dirPart, sessPart := text[d:s], text[s:]
	for _, want := range []string{
		"ETCDCTL_ENDPOINTS=https://dir-0:2379",
		"etcdctl role grant-permission port49_daemon read --prefix=true /port49/v1/rv/",
		"etcdctl role grant-permission port49_daemon read /port49/v1/meta/ping",
		"etcdctl role grant-permission port49_broker readwrite --prefix=true /port49/v1/",
	} {
		if !strings.Contains(dirPart, want) {
			t.Fatalf("the directory section lacks %q:\n%s", want, dirPart)
		}
	}
	if strings.Contains(dirPart, "/port49/v1/c/") {
		t.Fatalf("the directory section grants the contexts:\n%s", dirPart)
	}
	if !strings.Contains(sessPart, "ETCDCTL_ENDPOINTS=https://sess-0:2379") ||
		strings.Contains(sessPart, "port49_daemon read --prefix=true /port49/v1/rv/") {
		t.Fatalf("the session section:\n%s", sessPart)
	}
}
```

`storeRolesFixture` writes `daemon.pem`, `daemon-key.pem`, `broker.pem`, `broker-key.pem` and
`ca.pem` into the directory beside the config it returns. This test reuses those files.

Delete the tests of the 7d layout and of the enrollment store's own etcd:
`TestStoreRolesStillReadsA7dFile`, `TestStoreRolesWarnsOfAStaleBrokerIdentity`,
`TestStoreRolesNamesAnOwnEnrollmentEtcd` (if Task 2 kept it), and `(*fleet).sevenDFile`. The
`store:` key they rest on is gone (R5).

Append to `internal/store/etcd/roles_test.go`:

```go
// Two keyspaces on one cluster share role names: the daemon's role then
// holds the session store's grants too, and the directory's check judges
// only the grants that reach its own keyspace (R23).
func TestTheDirectoryCheckJudgesItsOwnKeyspace(t *testing.T) {
	k := newKeys("/port49-directory/")
	if why := k.beyondDirectoryDaemon("/port49/v1/t/", "/port49/v1/t0", true); why != "" {
		t.Fatalf("a write on another keyspace: %s", why)
	}
	if why := k.beyondDirectoryDaemon("/port49-directory/v1/t/", "/port49-directory/v1/t0", true); why == "" {
		t.Fatal("a write on the directory keyspace passed")
	}
	if why := k.beyondDirectoryDaemon("", "\x00", false); why == "" {
		t.Fatal("a read of every key passed")
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/port49d/ ./internal/store/etcd/ -run 'StoreRoles|DirectoryCheckJudges' -count=1`
Expected: `TestStoreRolesPrintsASectionPerStore` FAILS (Task 2 refuses a split).
`TestTheDirectoryCheckJudgesItsOwnKeyspace` FAILS on the first case.

- [ ] **Step 3: Implement**

In `internal/store/etcd/roles.go`, begin `beyondDirectoryDaemon` with:

```go
	rootEnd := clientv3.GetPrefixRangeEnd(k.root)
	var reaches bool
	switch end {
	case "": // the one key
		reaches = key >= k.root && key < rootEnd
	case "\x00": // every key from key on
		reaches = key < rootEnd
	default:
		reaches = key < rootEnd && end > k.root
	}
	if !reaches {
		return "" // another keyspace's grant, on a cluster both share
	}
```

In `internal/port49d/storeroles.go`, replace `storeRolesCmd` and `storeBlocksOf` with:

```go
// storeRolesCmd is `port49d store-roles [--config FILE] [--broker-config
// FILE]` (spec §12; plans 7d, 7e, 11a): it prints the etcdctl commands that
// create port49's two roles for each store's keyspace, and a user per
// component named by its certificate's CN: the daemon's from port49d.yaml,
// the broker's from port49-broker.yaml (or from port49d.yaml when it names
// one and --broker-config is not given). One store prints one section; a
// directory store of its own prints a section per store, each to run as
// that cluster's root (R23). It holds no etcd credential and changes
// nothing.
func storeRolesCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("store-roles", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "/etc/port49/port49d.yaml", "path to port49d.yaml")
	brokerPath := fs.String("broker-config", "/etc/port49/port49-broker.yaml", "path to port49-broker.yaml")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: port49d store-roles [--config FILE] [--broker-config FILE]")
		return 2
	}
	brokerGiven := false
	fs.Visit(func(f *flag.Flag) { brokerGiven = brokerGiven || f.Name == "broker-config" })
	dsc, err := storesBlocksOf(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "port49d store-roles:", err)
		return 1
	}
	if dsc.Directory.Etcd == nil {
		fmt.Fprintln(stderr, "port49d store-roles: stores.directory.backend is not etcd; there are no roles to make")
		return 1
	}
	bsc, brokerFile := dsc, *cfgPath
	if brokerGiven || dsc.Directory.Etcd.Broker == nil {
		if bsc, err = storesBlocksOf(*brokerPath); err != nil {
			fmt.Fprintf(stderr, "port49d store-roles: the broker's identity is read from port49-broker.yaml, "+
				"named by --broker-config: %v\n", err)
			return 1
		}
		brokerFile = *brokerPath
	}
	if bsc.Shared != dsc.Shared {
		fmt.Fprintf(stderr, "port49d store-roles: %s and %s disagree on whether stores.session is a store of its "+
			"own\n", *cfgPath, brokerFile)
		return 1
	}
	secs := []rolesSection{{what: "stores.directory", scope: etcdstore.ScopeShared, d: dsc.Directory.Etcd,
		b: bsc.Directory.Etcd}}
	if !dsc.Shared {
		secs = []rolesSection{
			{what: "stores.directory", name: "directory", scope: etcdstore.ScopeDirectory, d: dsc.Directory.Etcd,
				b: bsc.Directory.Etcd},
			{what: "stores.session", name: "session", scope: etcdstore.ScopeSession, d: dsc.Session.Etcd,
				b: bsc.Session.Etcd},
		}
	}
	// Every section is checked before anything is printed: a half-printed
	// script run by etcd's root is worse than none.
	for i := range secs {
		if err := secs[i].check(*cfgPath, brokerFile); err != nil {
			fmt.Fprintln(stderr, "port49d store-roles:", err)
			return 1
		}
	}
	for i, s := range secs {
		if i > 0 {
			fmt.Fprintln(stdout)
		}
		s.print(stdout)
	}
	return 0
}

// rolesSection is one store's roles: its config path, its name in a split
// ("" for one store), its scope, and the daemon's and the broker's blocks.
type rolesSection struct {
	what, name string
	scope      etcdstore.Scope
	d, b       *config.EtcdConfig
	users      map[string]string // role → CN, set by check
}

// check fills users and refuses what the output cannot carry: a missing
// identity, one CN for both, the two files at different keyspaces, and a
// name a shell would read.
func (s *rolesSection) check(cfgPath, brokerFile string) error {
	switch {
	case s.d == nil || s.d.Daemon == (config.EtcdIdentity{}):
		return fmt.Errorf("%s names no %s.etcd.daemon: it is port49d.yaml's", cfgPath, s.what)
	case s.b == nil || s.b.Broker == nil:
		return fmt.Errorf("%s names no %s.etcd.broker; --broker-config is port49-broker.yaml's", brokerFile, s.what)
	case s.d.Prefix != s.b.Prefix:
		return fmt.Errorf("the two files name different keyspaces: %s.etcd.prefix is %q in %s and %q in %s",
			s.what, s.d.Prefix, cfgPath, s.b.Prefix, brokerFile)
	}
	s.users = map[string]string{}
	for _, id := range []struct{ role, path string }{
		{etcdstore.RoleDaemon, s.d.Daemon.CertFile},
		{etcdstore.RoleBroker, s.b.Broker.CertFile},
	} {
		cn, err := commonName(id.path)
		if err != nil {
			return fmt.Errorf("%s: %v", id.path, err)
		}
		s.users[id.role] = cn
	}
	if s.users[etcdstore.RoleDaemon] == s.users[etcdstore.RoleBroker] {
		return fmt.Errorf("%s.etcd.daemon and %s.etcd.broker are both CN %q: each component needs its own "+
			"certificate (decision 35)", s.what, s.what, s.users[etcdstore.RoleDaemon])
	}
	// The output is run by etcd's root in a shell: a name that holds
	// anything a shell reads is refused, never quoted into it (pre-flight
	// M34).
	for _, n := range []struct{ what, v string }{
		{"the daemon certificate's CN", s.users[etcdstore.RoleDaemon]},
		{"the broker certificate's CN", s.users[etcdstore.RoleBroker]},
		{s.what + ".etcd.prefix", s.d.Prefix},
	} {
		if !shellSafe(n.v) {
			return fmt.Errorf("%s %q holds a character outside [A-Za-z0-9._@/-]; nothing printed", n.what, n.v)
		}
	}
	// The endpoints go into a comment's ETCDCTL_ENDPOINTS=…: a URL's ":" and
	// the list's "," are theirs; anything else a shell reads is refused.
	for _, ep := range s.d.Endpoints {
		if !shellSafe(strings.ReplaceAll(ep, ":", "")) {
			return fmt.Errorf("%s.etcd.endpoints %q holds a character outside [A-Za-z0-9.:_@/-]; nothing printed",
				s.what, ep)
		}
	}
	return nil
}

// print writes the section: its header, the roles and their grants, the
// users, and the auth lines.
func (s rolesSection) print(w io.Writer) {
	if s.name == "" {
		fmt.Fprintf(w, "# port49 roles for keyspace %s (plan 7e). Run as etcd's root user, once.\n", s.d.Prefix)
		fmt.Fprintln(w, "# port49_daemon cannot write a revocation mark, so it cannot lift a revocation by")
		fmt.Fprintln(w, "# principal or certificate. The daemon's credential cannot write a mark, meta/, the")
		fmt.Fprintln(w, "# ledger record or the superseded record; port49d holds it alone (plan 7e). Under")
		fmt.Fprintln(w, "# stores.directory.etcd.roles: unenforced the daemon's is as wide as the broker's.")
	} else {
		fmt.Fprintf(w, "# port49 roles for the %s store (%s): keyspace %s. Run these as THAT cluster's root user,\n"+
			"# once (point etcdctl at it: ETCDCTL_ENDPOINTS=%s).\n", s.name, s.what, s.d.Prefix,
			strings.Join(s.d.Endpoints, ","))
		if s.scope == etcdstore.ScopeDirectory {
			fmt.Fprintln(w, "# port49_daemon reads the revocation marks and meta/ping alone; port49_broker holds the keyspace.")
		} else {
			fmt.Fprintln(w, "# port49_daemon holds what a login, an authorization and accounting touch; the marks are the")
			fmt.Fprintln(w, "# directory store's, which it reads there.")
		}
	}
	fmt.Fprintln(w, "# if a role already exists, check it with etcdctl role get first: a grant on a range")
	fmt.Fprintln(w, "# not printed here stays in force.")
	made := map[string]bool{}
	for _, g := range etcdstore.RolesFor(s.d.Prefix, s.scope) {
		if !made[g.Role] {
			fmt.Fprintf(w, "etcdctl role add %s\n", g.Role)
			made[g.Role] = true
		}
		perm := "read"
		if g.Write {
			perm = "readwrite"
		}
		if g.RangeEnd == "" { // one key: no --prefix, or etcd would grant everything under it
			fmt.Fprintf(w, "etcdctl role grant-permission %s %s %s\n", g.Role, perm, g.Key)
			continue
		}
		fmt.Fprintf(w, "etcdctl role grant-permission %s %s --prefix=true %s\n", g.Role, perm, g.Key)
	}
	for _, role := range []string{etcdstore.RoleDaemon, etcdstore.RoleBroker} {
		fmt.Fprintf(w, "etcdctl user add %s --no-password\n", s.users[role])
		fmt.Fprintf(w, "etcdctl user grant-role %s %s\n", s.users[role], role)
	}
	fmt.Fprintln(w, "# then, if auth is not enabled yet: etcdctl user add root --no-password &&")
	fmt.Fprintln(w, "#   etcdctl user grant-role root root && etcdctl auth enable")
}

// storesBlocksOf reads the stores: block of the file at path, checked for
// its shape alone (config.StoresBlocks).
func storesBlocksOf(path string) (config.StoresConfig, error) {
	raw, err := config.ReadRegular(path, config.MaxConfigSize)
	if err != nil {
		return config.StoresConfig{}, err
	}
	return config.StoresBlocks(raw)
}
```

The shared header's last comment line now names `stores.directory.etcd.roles`. Update the expected
text in `TestStoreRolesPrintsTheCommands` to match, and nothing else in it.

Delete `enrollmentEtcdOf` if Task 2 left it.

- [ ] **Step 4: Run them to verify they pass**

Run: `go test ./internal/port49d/ ./internal/store/etcd/ -run 'StoreRoles|Roles|CheckIdentity' -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/port49d/storeroles.go internal/port49d/storeroles_test.go internal/store/etcd/roles.go internal/store/etcd/roles_test.go
git commit -m "feat: port49d store-roles prints a section per store

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 12: `port49 store status`

**Files:**
- Create: `internal/port49d/storestatus.go`, `cmd/port49/store.go`
- Modify: `internal/daemon/admin/admin.go` (`Response`, `Server`, `answer`), `internal/port49d/main.go`
  (port49d's admin server), `internal/port49d/brokerd.go` (port49-broker's), `cmd/port49/main.go` (the
  dispatch and the usage)
- Test: `internal/port49d/storestatus_test.go` (new), `internal/daemon/admin/admin_test.go`,
  `cmd/port49/store_linux_test.go` (new), `internal/port49d/twostores_linux_test.go`

**Interfaces:**
- Consumes:
  - `stores.dir`, `stores.fresh` and `stores.etcd` (Task 10);
  - `brokerStores.dir`, `brokerStores.fresh` and `brokerStores.raw` (Task 9);
  - `(*etcd.Store).Members` and `Ping` (Task 7);
  - `(*store.Freshness).Snapshot` (Task 10a).
- Produces:
  - op `store_status`, answered by both processes;
  - `admin.Response.Degraded bool` (json `degraded`);
  - `admin.Server.StoreStatus func(ctx context.Context) (text string, degraded bool, err error)`;
  - `type roleStatus` and `(roleStatus).line() string`;
  - `type storeStatus`, with `newStoreStatus(cfg config.Config, dir *dirHandle, session *etcdstore.Store, fresh *store.Freshness) *storeStatus`
    and `(*storeStatus).answer(ctx) (string, bool, error)`;
  - `port49 store status [--socket PATH]`, exiting 0, 3 or 1.

- [ ] **Step 1: Write the failing tests**

Create `internal/port49d/storestatus_test.go`:

```go
package port49d

import (
	"testing"
	"time"
)

// R21's lines, exactly.
func TestRoleStatusLines(t *testing.T) {
	for _, c := range []struct {
		s    roleStatus
		want string
	}{
		{roleStatus{role: "directory", backend: "etcd", answering: 3, listed: 3, reachable: true, cache: true,
			age: 400 * time.Millisecond, aged: true}, "directory  etcd    3/3 members  reachable  cache 0.4s"},
		{roleStatus{role: "session", backend: "etcd", answering: 1, listed: 1, reachable: true},
			"session    etcd    1/1 members  reachable"},
		{roleStatus{role: "session", shares: true}, "session    shares the directory store"},
		{roleStatus{role: "directory", backend: "memory"}, "directory  memory  in process"},
		{roleStatus{role: "directory", backend: "etcd", membersErr: true, cache: true, age: 41200 * time.Millisecond,
			aged: true, why: "store: unavailable: context deadline exceeded"},
			"directory  etcd    ?/? members  unreachable  cache 41.2s\n" +
				"           store: unavailable: context deadline exceeded"},
		{roleStatus{role: "directory", backend: "etcd", answering: 1, listed: 3, reachable: true, cache: true},
			"directory  etcd    1/3 members  reachable  cache none"},
		{roleStatus{role: "directory", backend: "etcd", answering: 3, listed: 3, reachable: true, cache: true,
			age: 3*time.Minute + 12*time.Second, aged: true}, "directory  etcd    3/3 members  reachable  cache 3m12s"},
		{roleStatus{role: "directory", backend: "etcd", membersErr: true, cache: true, age: 2 * time.Second, aged: true,
			pending: 2}, "directory  etcd    ?/? members  unreachable  cache 2.0s  2 logouts pending"},
		{roleStatus{role: "directory", backend: "etcd", membersErr: true, cache: true, age: 90 * time.Second, aged: true,
			snapshot: true}, "directory  etcd    ?/? members  unreachable  cache 1m30s (snapshot)"},
	} {
		if got := c.s.line(); got != c.want {
			t.Errorf("%+v:\n got %q\nwant %q", c.s, got, c.want)
		}
	}
}
```

Append to `internal/daemon/admin/admin_test.go` (with the file's existing way of asking a server.
If it has none in a non-linux file, put this test in `admin_linux_test.go` and use its helper):

```go
// store_status answers the process's lines and whether a store did not
// answer; a process that reports no stores says so (plan 11a).
func TestStoreStatusOp(t *testing.T) {
	srv := &Server{Now: time.Now, StoreStatus: func(context.Context) (string, bool, error) {
		return "directory  etcd    ?/3 members  unreachable  cache 1.0s", true, nil
	}}
	r := srv.answer(context.Background(), Request{Op: "store_status"}, 0)
	if r.Error != "" || !r.Degraded || r.Text != "directory  etcd    ?/3 members  unreachable  cache 1.0s" {
		t.Fatalf("%+v", r)
	}
	if r := (&Server{Now: time.Now}).answer(context.Background(), Request{Op: "store_status"}, 0); r.Error == "" {
		t.Fatalf("a server with no StoreStatus answered %+v", r)
	}
}
```

Create `cmd/port49/store_linux_test.go`:

```go
package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/daemon/admin"
)

// serveStatus serves a store_status of text and degraded on a socket of the
// test's own, and returns its path.
func serveStatus(t *testing.T, text string, degraded bool) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "p.sock")
	ln, err := admin.Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := &admin.Server{Now: time.Now, StoreStatus: func(context.Context) (string, bool, error) {
		return text, degraded, nil
	}}
	go srv.Serve(ctx, ln)
	return p
}

func TestStoreStatusExitsByWhatItFound(t *testing.T) {
	ok := "directory  etcd    3/3 members  reachable  cache 0.4s\nsession    shares the directory store"
	var out, errb bytes.Buffer
	if code := run([]string{"store", "status", "--socket", serveStatus(t, ok, false)}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "3/3 members  reachable") {
		t.Fatalf("exit %d, out %q, err %q", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"store", "status", "--socket", serveStatus(t, "directory  etcd    ?/3 members  unreachable", true)},
		&out, &errb); code != 3 {
		t.Fatalf("a store that does not answer exits %d, want 3", code)
	}
	if code := run([]string{"store", "status", "--socket", filepath.Join(t.TempDir(), "none.sock")}, &out, &errb); code != 1 {
		t.Fatalf("no socket exits %d, want 1", code)
	}
}
```

Append to `internal/port49d/twostores_linux_test.go`:

```go
// R21 end to end: port49d answers each store's line, and a cut directory
// is degraded.
func TestStoreStatusOnTwoStores(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	startBroker(t, f.broker, &out, 1)
	startSplitDaemon(t, f.daemon, &out, 1)
	sock := adminSocketOf(t, f.daemon)
	r, err := ask(sock, admin.Request{Op: "store_status"})
	if err != nil || r.Degraded || !strings.Contains(r.Text, "directory  etcd    1/1 members  reachable  cache ") ||
		!strings.Contains(r.Text, "session    etcd    1/1 members  reachable") {
		t.Fatalf("%+v %v", r, err)
	}
	f.ddproxy.Hang(true)
	waitWithin(t, &out, "port49d: directory store: not answering", 10*time.Second)
	r, err = ask(sock, admin.Request{Op: "store_status"})
	if err != nil || !r.Degraded || !strings.Contains(r.Text, "unreachable") {
		t.Fatalf("with the directory cut: %+v %v", r, err)
	}
}
```

In the cut case the member list is read through the hung proxy and fails, so the line reads
`?/? members` (the pre-flight's minor 9). The test checks `unreachable` alone, which is the
linearizable read through the proxy.

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/port49d/ ./internal/daemon/admin/ ./cmd/port49/ -run 'RoleStatusLines|StoreStatus' -count=1`
Expected: FAIL to compile (`undefined: roleStatus`, `unknown field StoreStatus`).

- [ ] **Step 3: Implement**

In `internal/daemon/admin/admin.go`:
1. Add to `Response`:
   ```go
   	// Degraded is a store_status in which a store did not answer; `port49
   	// store status` exits 3 on it (plan 11a, R21).
   	Degraded bool `json:"degraded,omitempty"`
   ```
2. Add to `Server`:
   ```go
   	// StoreStatus answers `port49 store status` (plan 11a, R21): each
   	// store's line as this process sees it, and whether one did not answer.
   	// Nil when the process reports no stores.
   	StoreStatus func(ctx context.Context) (text string, degraded bool, err error)
   ```
3. Add a case to `answer`, before the closing `}` of its switch:
   ```go
   	case "store_status":
   		if s.StoreStatus == nil {
   			return Response{Error: "this process reports no stores"}
   		}
   		ctx, cancel := context.WithTimeout(ctx, s.opTimeout())
   		defer cancel()
   		text, degraded, err := s.StoreStatus(ctx)
   		if err != nil {
   			return Response{Error: err.Error()}
   		}
   		return Response{Text: text, Degraded: degraded}
   ```
4. The unknown-op answer lists `store_status` as well.

Create `internal/port49d/storestatus.go`:

```go
package port49d

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/store"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
)

// roleStatus is one store's line of port49 store status (plan 11a, R21).
type roleStatus struct {
	role, backend     string
	shares            bool // the session store is the directory store
	answering, listed int
	membersErr        bool
	reachable         bool
	why               string
	cache, aged       bool // a directory line carries a cache age; aged: it was ever confirmed
	snapshot          bool // the cache is a snapshot this run started from, not yet confirmed live (R19)
	age               time.Duration
	pending           int // back-channel logouts not yet forwarded to the directory (R26)
}

// line is s as the CLI prints it.
func (s roleStatus) line() string {
	switch {
	case s.shares:
		return fmt.Sprintf("%-9s  shares the directory store", s.role)
	case s.backend == config.BackendMemory:
		return fmt.Sprintf("%-9s  %-6s  in process", s.role, s.backend)
	}
	members := fmt.Sprintf("%d/%d members", s.answering, s.listed)
	if s.membersErr {
		members = "?/? members"
	}
	reach := "reachable"
	if !s.reachable {
		reach = "unreachable"
	}
	l := fmt.Sprintf("%-9s  %-6s  %-11s  %s", s.role, s.backend, members, reach)
	if s.cache {
		age := "none"
		if s.aged {
			age = ageText(s.age)
		}
		if s.snapshot {
			age += " (snapshot)"
		}
		l += "  cache " + age
	}
	if s.pending > 0 {
		l += fmt.Sprintf("  %d logouts pending", s.pending)
	}
	if !s.reachable && s.why != "" {
		l += "\n           " + printsafe.Line(s.why, 300)
	}
	return l
}

// storeStatus is what port49 store status reads in a process: the
// directory store's handle and the session store's (nil on memory), and the
// directory cache's freshness.
type storeStatus struct {
	backend                 string
	shared                  bool
	dir                     *dirHandle
	session                 *etcdstore.Store
	fresh                   *store.Freshness
	dirTimeout, sessTimeout time.Duration
	// pending is the count of logouts this region has not yet forwarded
	// (port49-broker's); nil on port49d, which ingests none.
	pending func() int
}

func newStoreStatus(cfg config.Config, dir *dirHandle, session *etcdstore.Store, fresh *store.Freshness) *storeStatus {
	s := &storeStatus{backend: cfg.Stores.Session.Backend, shared: cfg.Stores.Shared, dir: dir, session: session,
		fresh: fresh}
	if e := cfg.Stores.Directory.Etcd; e != nil {
		s.dirTimeout = e.CallTimeout
	}
	if e := cfg.Stores.Session.Etcd; e != nil {
		s.sessTimeout = e.CallTimeout
	}
	return s
}

// answer reads each store now, each read within its call_timeout, and
// answers the lines and whether a store did not answer.
func (s *storeStatus) answer(ctx context.Context) (string, bool, error) {
	if s == nil || s.backend == config.BackendMemory {
		return roleStatus{role: "directory", backend: config.BackendMemory}.line() + "\n" +
			roleStatus{role: "session", shares: true}.line(), false, nil
	}
	d := s.read(ctx, "directory", s.dir.get(), s.dirTimeout)
	d.cache = true
	d.age, d.aged = s.fresh.Age()
	d.snapshot = s.fresh.Snapshot()
	if s.pending != nil {
		d.pending = s.pending()
	}
	lines, degraded := []string{d.line()}, !d.reachable
	if s.shared {
		lines = append(lines, roleStatus{role: "session", shares: true}.line())
	} else {
		ss := s.read(ctx, "session", s.session, s.sessTimeout)
		lines, degraded = append(lines, ss.line()), degraded || !ss.reachable
	}
	return strings.Join(lines, "\n"), degraded, nil
}

// read is role's line from h: a linearizable read for reachability, then
// the members.
func (s *storeStatus) read(ctx context.Context, role string, h *etcdstore.Store, timeout time.Duration) roleStatus {
	r := roleStatus{role: role, backend: config.BackendEtcd}
	if h == nil {
		r.membersErr, r.why = true, errNoDirectory.Error()
		return r
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	err := h.Ping(cctx)
	cancel()
	if r.reachable = err == nil; err != nil {
		r.why = err.Error()
	}
	mctx, mcancel := context.WithTimeout(ctx, 4*timeout)
	a, l, merr := h.Members(mctx, timeout)
	mcancel()
	r.answering, r.listed, r.membersErr = a, l, merr != nil
	return r
}
```

Wire it:
1. port49d: where `runOnce` builds its `admin.Server`, set
   `StoreStatus: newStoreStatus(cfg, sts.dir, sts.etcd, sts.fresh).answer`. On memory the three are
   nil and the backend is memory, so it answers the memory lines.
2. port49-broker: in `runBroker`'s `asrv`, set `StoreStatus: st.answer`, where
   `st := newStoreStatus(cfg, bs.dir, bs.raw, bs.fresh)` and
   `st.pending = func() int { return int(rn.pending.Load()) }`. `pending atomic.Int64` is a runner
   field that `forwardingPending` sets beside the gauge (`r.pending.Store(int64(left))`).

Create `cmd/port49/store.go`:

```go
package main

import (
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/rhwendt/port49/internal/daemon/admin"
)

// storeCmd is `port49 store` (plan 11a): status asks a process's admin
// socket what each of its stores is.
func storeCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "status" {
		return storeStatusCmd(args[1:], stdout, stderr)
	}
	fmt.Fprint(stderr, usage)
	return 2
}

// storeStatusCmd is `port49 store status` (spec §12; decision 51 R21):
// exit 0 when every store answers, 3 when one does not, 1 when the socket
// does not answer.
func storeStatusCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 store status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", "/run/port49/port49d.sock", "the admin_socket of port49d or port49-broker")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	resp, err := askAdmin(*socket, admin.Request{Op: "store_status"}, 10*time.Second)
	if err != nil {
		fmt.Fprintln(stderr, "port49 store status:", err)
		return 1
	}
	if resp.Error != "" {
		fmt.Fprintln(stderr, "port49 store status:", resp.Error)
		return 1
	}
	fmt.Fprintln(stdout, resp.Text)
	if resp.Degraded {
		return 3
	}
	return 0
}
```

In `cmd/port49/main.go`:
1. Add `case "store": return storeCmd(args[1:], stdout, stderr)` to `run`.
2. Add these usage lines after `port49 keys diagnose`:
   ```
     port49 store status [--socket PATH]
                   (each store as port49d or port49-broker sees it: backend, members, reachable, the
                   directory cache's age; exits 3 when a store does not answer)
   ```

- [ ] **Step 4: Run them to verify they pass**

Run: `go test ./internal/port49d/ ./internal/daemon/admin/ ./cmd/port49/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/port49d/storestatus.go internal/port49d/storestatus_test.go internal/port49d/twostores_linux_test.go internal/port49d/main.go internal/port49d/brokerd.go internal/daemon/admin cmd/port49
git commit -m "feat: port49 store status, each store as the process sees it

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 13: The compose example, the docs sweep, and the gate

**Files:**
- Modify: `deploy/compose/README.md`, `deploy/compose/etcd-init.sh` (if it reads `store:` or
  prints roles for one store), `examples/oxidized/README.md` (`store.etcd.hold_ttl`), and every Go
  comment, test comment or doc line the gate names
- Test: the gate grep below; `make compose-smoke` where Docker is available

**Interfaces:**
- Consumes: everything above.
- Produces: no old key name anywhere but the historical records, and the compose example on
  `stores:`.

- [ ] **Step 1: Find what still names an old key**

Run:
```bash
git grep -nE "$OLDKEYS" -- ':!docs/superpowers/plans/20*' ':!docs/superpowers/plans/README.md' \
  ':!docs/design/*' ':!tests/lab/results' ':!internal/config/stores_test.go'
```

(`OLDKEYS` as Task 1 Step 5 exports it. The two design files are checked by Task 1 Step 5's
script, which skips their records.)

Expected: a list, mostly Go comments (`store.etcd.call_timeout bounds each…`) and
`deploy/compose/README.md`.

- [ ] **Step 2: Rename each by Task 1's table**

- In a comment, name the key as the operator writes it: `stores.session.etcd.X` for a
  session-store key, `stores.directory.etcd.X` for a directory key.
- In a runtime line, build the path from `cfg.Stores.SessionPath()` (Task 2) where the key is the
  session store's.
- In `deploy/compose/README.md`, every `store:` becomes `stores.directory`, the example config
  already moved in Task 2. Add one paragraph:

  > **One store or two.** The example runs one etcd, so `stores.session` is omitted: the session
  > store is the directory store. A deployment in several regions gives `stores.directory` an etcd
  > stretched one member per region and each region's `stores.session` an etcd of its own;
  > `port49d store-roles` then prints a section per cluster. `port49 store status` (inside the
  > port49d container: `docker compose exec port49d port49 store status`) shows each store as port49d
  > sees it.

- If `deploy/compose/etcd-init.sh` reads the store block or applies `port49d store-roles` output,
  it keeps working with one section: the shared store prints today's single section.

- [ ] **Step 3: Run the gate and the suites**

Run the grep from Step 1, and Task 1 Step 5's script.
Expected: no output from either.

Run: `go build ./... && go vet ./... && go test ./... -count=1`
Expected: PASS.

Run (where Docker runs): `make compose-smoke`
Expected: PASS. Where Docker is absent, say so in the task report, and the PR's CI runs it.

- [ ] **Step 4: Commit**

```bash
git add -A deploy internal cmd tests examples docs/design
git commit -m "docs: every config key named as stores: names it; the compose example's note on one store or two

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 14: The three-region harness (L74)

**Files:**
- Create: `tests/lab/regions_test.go` (build tag `lab`): the network, the PKI, the etcd members, the
  processes, the TACACS+ client, the mint, the roles
- Create: `tests/lab/l74_test.go` (build tag `lab`): `TestRegions`, L74's cells, the notes
- Create: `tests/lab/l74_unit_test.go` (build tag `lab`, as `tests/lab/split_unit_test.go` is: it
  calls the lab-tagged helpers, so untagged it would break `go test ./...`; `make lab-unit` runs it
  with `-tags lab`): the pure helpers
- Modify: `Makefile` (a `lab-regions` target), `tests/lab/README.md` (a section)

**Interfaces:**
- Consumes:
  - the binaries `port49d`, `port49-broker` and `port49` (built into a temp dir);
  - `port49d store-roles`' sections (Task 11);
  - `port49 store status` (Task 12);
  - `labGuardAt`, `l66StopSentinel`, `l66DiskFloorMB`, `labcreds`, `firstLine`, `oneLineMax`,
    `freeAddr`, `root`, `pinFileKeyStore` (L67's: `issued_key_store: file` in a CLI's home).
- Produces: `TestRegions`, which writes `tests/lab/results/L74-regions.md` with the evidence under
  `tests/lab/evidence/L74-regions/`; `regionWorld` (with `home` and `guard`), `writeRegionNote`
  (with the processes whose logs are its evidence), and `make lab-regions`. Task 14a adds L75.

The harness's shape (R8; the plan's L74 and L75 rows):
- **The network.** Three namespaces `p49r1..3`, each joined to the host bridge `p49rbr0`
  (10.149.0.1) by a veth. Region i is 10.149.0.(10+i). `tc netem delay 20ms` sits on each region's
  side, so region to region is 40ms round trip and host to region 20ms.
- **The cut.** iptables in region 3's namespace drops its traffic with the other two regions.
  The host still reaches it, so the harness keeps driving it.
- **The directory etcd** has three members, one per namespace, with peers over the bridge.
- **Each region** runs a session etcd of one member on the namespace's own loopback, a
  port49-broker, and a port49d listening on `10.149.0.(10+i):4949`.
- **The client** is the harness on the host. The inventory's one device is `l74-client` at
  10.149.0.1, the bridge address the harness's connections leave from.
- **Lab rules.** `w.guard()` (the STOP sentinel and the disk floor) runs before every cell, and
  before each measured step of the shared cut (c) to (g). Every `port49` CLI run gets
  `HOME=<w.home>`, whose `.port49/config.yaml` says `issued_key_store: file`.

- [ ] **Step 1: Write the failing unit tests**

Create `tests/lab/l74_unit_test.go`:

```go
//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

func TestRegionNetworkCommands(t *testing.T) {
	up := regionNetUp()
	joined := make([]string, len(up))
	for i, c := range up {
		joined[i] = strings.Join(c, " ")
	}
	all := strings.Join(joined, "\n")
	for _, want := range []string{
		"ip link add p49rbr0 type bridge",
		"ip addr add 10.149.0.1/24 dev p49rbr0",
		"ip netns add p49r3",
		"ip netns exec p49r2 ip addr add 10.149.0.12/24 dev p49r2n",
		"ip netns exec p49r1 tc qdisc add dev p49r1n root netem delay 20ms",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("the network lacks %q", want)
		}
	}
	cut := regionCut(3, true)
	if len(cut) != 4 || strings.Join(cut[0], " ") != "ip netns exec p49r3 iptables -I OUTPUT -d 10.149.0.11 -j DROP" {
		t.Fatalf("%v", cut)
	}
	if heal := regionCut(3, false); strings.Join(heal[1], " ") != "ip netns exec p49r3 iptables -D INPUT -s 10.149.0.11 -j DROP" {
		t.Fatalf("%v", heal)
	}
}

func TestInNSRunsAsTheUserWithItsEnvironment(t *testing.T) {
	t.Setenv("USER", "labuser")
	got := strings.Join(inNS("p49r2", []string{"A=1"}, "/bin/etcd", "--name", "d2"), " ")
	if got != "sudo -n ip netns exec p49r2 sudo -n -u labuser -- env A=1 /bin/etcd --name d2" {
		t.Fatalf("%s", got)
	}
}

// The configs the harness writes load as port49d's and port49-broker's
// stores: two stores, the directory across the three regions; port49d's
// waits for the directory with no deadline (L74 f).
func TestRegionConfigsNameTwoStores(t *testing.T) {
	dir := t.TempDir()
	file := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := &regionPKI{ca: file("ca.pem"), daemon: file("d.pem"), daemonKey: file("d-key.pem"), broker: file("b.pem"),
		brokerKey: file("b-key.pem")}
	for _, role := range []string{"daemon", "broker"} {
		body := regionStoresYAML(p, role, regionSessionClient)
		s, err := config.StoresBlocks([]byte(body))
		if err != nil {
			t.Fatalf("%s: %v\n%s", role, err, body)
		}
		if s.Shared || len(s.Directory.Etcd.Endpoints) != 3 || s.Session.Etcd.Endpoints[0] != "https://127.0.0.1:2479" {
			t.Fatalf("%s: %+v", role, s)
		}
		if role == "daemon" && s.Directory.Etcd.StartTimeout != 0 {
			t.Fatalf("port49d's directory start_timeout is %v, want 0 (wait)", s.Directory.Etcd.StartTimeout)
		}
	}
}

func TestApplyRolesSplitsTheSections(t *testing.T) {
	out := "# port49 roles for the directory store (stores.directory): keyspace /port49/. Run these as THAT cluster's root user,\n" +
		"etcdctl role add port49_daemon\n" +
		"# then, if auth is not enabled yet: etcdctl user add root --no-password &&\n" +
		"#   etcdctl user grant-role root root && etcdctl auth enable\n\n" +
		"# port49 roles for the session store (stores.session): keyspace /port49/. Run these as THAT cluster's root user,\n" +
		"etcdctl role add port49_broker\n"
	ran := map[string][]string{}
	ctl := func(target string) func(...string) (string, error) {
		return func(args ...string) (string, error) {
			ran[target] = append(ran[target], strings.Join(args, " "))
			return "OK", nil
		}
	}
	applyRoles(t, out, map[string]func(...string) (string, error){"directory": ctl("directory"), "session": ctl("session")})
	if strings.Join(ran["directory"], "|") != "role add port49_daemon|user add root --no-password|user grant-role root root|auth enable" ||
		strings.Join(ran["session"], "|") != "role add port49_broker" {
		t.Fatalf("%v", ran)
	}
	ran = map[string][]string{}
	applyRoles(t, out, map[string]func(...string) (string, error){"session": ctl("session")})
	if len(ran["directory"]) != 0 || len(ran["session"]) != 1 {
		t.Fatalf("a section with no cluster ran: %v", ran)
	}
}

func TestStatusNames(t *testing.T) {
	if authenStatusName(wire.AuthenStatusPass) != "pass" || authenStatusName(wire.AuthenStatusFail) != "fail" ||
		authorStatusName(wire.AuthorStatusPassAdd) != "permit" || authorStatusName(wire.AuthorStatusFail) != "deny" {
		t.Fatal("status names")
	}
}

func TestRegionNoteShape(t *testing.T) {
	note := regionNote("L74", "port49 on the lab host, three simulated regions", "etcd 3.6.15", "commit abc",
		"spec §15 L74, cell by cell.", []regionRow{{ID: "a", Claim: "c", Observed: "o | p", Agrees: true}}, []string{"x"})
	for _, want := range []string{"# L74 — three simulated regions", "- **Platform:** port49 on the lab host, three simulated regions",
		"- **Capture:** tests/lab/evidence/L74-regions/", "| a | c | o \\| p | yes |", "**Not measured here:**", "- x"} {
		if !strings.Contains(note, want) {
			t.Fatalf("the note lacks %q:\n%s", want, note)
		}
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test -tags lab ./tests/lab/ -run '^(TestRegionNetworkCommands|TestInNSRunsAsTheUserWithItsEnvironment|TestRegionConfigsNameTwoStores|TestApplyRolesSplitsTheSections|TestStatusNames|TestRegionNoteShape)$' -count=1`
Expected: FAIL to compile (`undefined: regionNetUp`).

- [ ] **Step 3: Write `tests/lab/regions_test.go`**

```go
//go:build lab

package lab

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/api"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
)

// The three-region lab (plan 11a; spec §15 L74, L75): three network
// namespaces on a host bridge, tc netem on each region's link, a directory
// etcd stretched one member per region, and in each region a session etcd,
// a port49-broker and a port49d. The TACACS+ client is the harness.
const (
	regionBridge        = "p49rbr0"
	regionHostIP        = "10.149.0.1"
	regionDelay         = "20ms"
	regionSessionClient = "127.0.0.1:2479" // each namespace's own loopback
	regionSessionPeer   = "127.0.0.1:2480"
	regionDevice        = "l74-client"
)

func regionNS(i int) string { return fmt.Sprintf("p49r%d", i) }
func regionIP(i int) string { return fmt.Sprintf("10.149.0.%d", 10+i) }

// regionNetUp is every command that builds the network, in order, each run
// under sudo -n.
func regionNetUp() [][]string {
	cmds := [][]string{
		{"ip", "link", "add", regionBridge, "type", "bridge"},
		{"ip", "addr", "add", regionHostIP + "/24", "dev", regionBridge},
		{"ip", "link", "set", regionBridge, "up"},
	}
	for i := 1; i <= 3; i++ {
		ns, host, peer := regionNS(i), regionNS(i)+"h", regionNS(i)+"n"
		cmds = append(cmds,
			[]string{"ip", "netns", "add", ns},
			[]string{"ip", "link", "add", host, "type", "veth", "peer", "name", peer},
			[]string{"ip", "link", "set", host, "master", regionBridge},
			[]string{"ip", "link", "set", host, "up"},
			[]string{"ip", "link", "set", peer, "netns", ns},
			[]string{"ip", "netns", "exec", ns, "ip", "addr", "add", regionIP(i) + "/24", "dev", peer},
			[]string{"ip", "netns", "exec", ns, "ip", "link", "set", peer, "up"},
			[]string{"ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"},
			[]string{"ip", "netns", "exec", ns, "tc", "qdisc", "add", "dev", peer, "root", "netem", "delay", regionDelay},
		)
	}
	return cmds
}

// regionNetDown removes the network; each is run and its error ignored, so
// what an interrupted run left is removed too. A namespace's veth goes with it.
func regionNetDown() [][]string {
	var cmds [][]string
	for i := 1; i <= 3; i++ {
		cmds = append(cmds, []string{"ip", "netns", "del", regionNS(i)})
	}
	return append(cmds, []string{"ip", "link", "del", regionBridge})
}

// regionCut is the iptables rules in region i's namespace that drop its
// traffic with the other two regions, added (-I) or removed (-D). The host
// still reaches it.
func regionCut(i int, add bool) [][]string {
	op := "-D"
	if add {
		op = "-I"
	}
	var cmds [][]string
	for j := 1; j <= 3; j++ {
		if j == i {
			continue
		}
		cmds = append(cmds,
			[]string{"ip", "netns", "exec", regionNS(i), "iptables", op, "OUTPUT", "-d", regionIP(j), "-j", "DROP"},
			[]string{"ip", "netns", "exec", regionNS(i), "iptables", op, "INPUT", "-s", regionIP(j), "-j", "DROP"})
	}
	return cmds
}

// sudoRun runs each command under sudo -n, stopping at the first error
// unless keepGoing.
func sudoRun(cmds [][]string, keepGoing bool) error {
	for _, c := range cmds {
		out, err := exec.Command("sudo", append([]string{"-n"}, c...)...).CombinedOutput()
		if err != nil && !keepGoing {
			return fmt.Errorf("sudo %s: %v: %s", strings.Join(c, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// inNS is argv run in namespace ns as this user, with env: sudo resets the
// environment, so env carries it.
func inNS(ns string, env []string, argv ...string) []string {
	out := []string{"sudo", "-n", "ip", "netns", "exec", ns, "sudo", "-n", "-u", os.Getenv("USER"), "--", "env"}
	return append(append(out, env...), argv...)
}

// regionPKI is the lab's etcd CA and certificates, and the brokers' lab PKI
// (testpki.WriteLab: the API's server certificate, the lab client's).
type regionPKI struct {
	dir, ca, server, serverKey, root, rootKey string
	daemon, daemonKey, broker, brokerKey     string
	lab                                      string
}

func newRegionPKI(t *testing.T) *regionPKI {
	t.Helper()
	p := &regionPKI{dir: t.TempDir(), lab: t.TempDir()}
	now := time.Now()
	ca, err := testpki.NewCA("L74 etcd CA", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, body []byte) string {
		path := filepath.Join(p.dir, name)
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	p.ca = write("ca.pem", ca.PEM())
	issue := func(leaf testpki.Leaf, name string) (string, string) {
		leaf.NotBefore, leaf.NotAfter = now.Add(-time.Hour), now.Add(24*time.Hour)
		c, err := ca.Issue(leaf)
		if err != nil {
			t.Fatal(err)
		}
		cp, kp, err := testpki.PEMs(c)
		if err != nil {
			t.Fatal(err)
		}
		return write(name+".pem", cp), write(name+"-key.pem", kp)
	}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP(regionHostIP)}
	for i := 1; i <= 3; i++ {
		ips = append(ips, net.ParseIP(regionIP(i)))
	}
	p.server, p.serverKey = issue(testpki.Leaf{CommonName: "etcd", IPs: ips, NoExtKeyUsage: true}, "server")
	p.root, p.rootKey = issue(testpki.Leaf{CommonName: "root", Client: true}, "root")
	p.daemon, p.daemonKey = issue(testpki.Leaf{CommonName: "port49-daemon", Client: true}, "port49-daemon")
	p.broker, p.brokerKey = issue(testpki.Leaf{CommonName: "port49-broker", Client: true}, "port49-broker")
	if err := testpki.WriteLab(p.lab, "alice@example.com", now); err != nil {
		t.Fatal(err)
	}
	return p
}

// regionEtcd is one etcd member, in namespace ns ("" for the host).
type regionEtcd struct {
	ns, name, bin  string
	client, peer   string // host:port
	cluster        string // --initial-cluster
	data, log      string
	pki            *regionPKI
	cmd            *exec.Cmd
	done           chan struct{}
}

func (e *regionEtcd) argv() []string {
	a := []string{filepath.Join(e.bin, "etcd"), "--name", e.name, "--data-dir", e.data,
		"--listen-client-urls", "https://" + e.client, "--advertise-client-urls", "https://" + e.client,
		"--listen-peer-urls", "http://" + e.peer, "--initial-advertise-peer-urls", "http://" + e.peer,
		"--initial-cluster", e.cluster, "--initial-cluster-state", "new",
		"--cert-file", e.pki.server, "--key-file", e.pki.serverKey, "--trusted-ca-file", e.pki.ca, "--client-cert-auth"}
	if e.ns != "" {
		return inNS(e.ns, nil, a...)
	}
	return a
}

func (e *regionEtcd) start(t *testing.T) {
	t.Helper()
	lf, err := os.Create(e.log)
	if err != nil {
		t.Fatal(err)
	}
	a := e.argv()
	e.cmd = exec.Command(a[0], a[1:]...)
	e.cmd.Stdout, e.cmd.Stderr = lf, lf
	if err := e.cmd.Start(); err != nil {
		lf.Close()
		t.Fatalf("INVALID: starting etcd %s: %v", e.name, err)
	}
	e.done = make(chan struct{})
	go func() { e.cmd.Wait(); lf.Close(); close(e.done) }()
	t.Cleanup(e.stop)
}

// stop ends the member: the signal goes to sudo, which passes it on; past
// 15s the member is ended by its data directory, which names it alone.
func (e *regionEtcd) stop() {
	if e.cmd == nil || e.cmd.Process == nil {
		return
	}
	e.cmd.Process.Signal(os.Interrupt)
	select {
	case <-e.done:
	case <-time.After(15 * time.Second):
		_ = exec.Command("sudo", "-n", "pkill", "-f", "--", "--data-dir "+e.data).Run()
		<-e.done
	}
	e.cmd = nil
}

// ctl is etcdctl as etcd's root at endpoints, run where the member runs.
func (e *regionEtcd) ctl(endpoints string, args ...string) (string, error) {
	a := append([]string{filepath.Join(e.bin, "etcdctl"), "--endpoints", endpoints, "--cacert", e.pki.ca,
		"--cert", e.pki.root, "--key", e.pki.rootKey, "--dial-timeout", "3s", "--command-timeout", "5s"}, args...)
	if e.ns != "" {
		a = inNS(e.ns, nil, a...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, a[0], a[1:]...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// regionProc is port49d or port49-broker, in namespace ns ("" for the host).
type regionProc struct {
	name, ns, bin, cfg, log string
	env                     []string
	cmd                     *exec.Cmd
	done                    chan struct{}
	from                    int64 // the log's size at the last start
}

func (p *regionProc) start(t *testing.T) {
	t.Helper()
	lf, err := os.OpenFile(p.log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := lf.Stat(); err == nil {
		p.from = fi.Size()
	}
	a := []string{p.bin, "--config", p.cfg}
	if p.ns != "" {
		a = inNS(p.ns, p.env, a...)
	}
	p.cmd = exec.Command(a[0], a[1:]...)
	if p.ns == "" {
		p.cmd.Env = append(os.Environ(), p.env...)
	}
	p.cmd.Stdout, p.cmd.Stderr = lf, lf
	if err := p.cmd.Start(); err != nil {
		lf.Close()
		t.Fatalf("INVALID: starting %s: %v", p.name, err)
	}
	done := make(chan struct{})
	p.done = done
	go func(cmd *exec.Cmd) { cmd.Wait(); lf.Close(); close(done) }(p.cmd)
}

// stop ends the process as etcd's member is ended, by its config's path past 15s.
func (p *regionProc) stop() {
	if p.cmd == nil || p.cmd.Process == nil {
		return
	}
	p.cmd.Process.Signal(os.Interrupt)
	select {
	case <-p.done:
	case <-time.After(15 * time.Second):
		_ = exec.Command("sudo", "-n", "pkill", "-f", "--", "--config "+p.cfg).Run()
		<-p.done
	}
	p.cmd = nil
}

// said is what the process wrote since its last start.
func (p *regionProc) said() string {
	raw, _ := os.ReadFile(p.log)
	if int64(len(raw)) < p.from {
		return ""
	}
	return string(raw[p.from:])
}

// wait is how long until the process said want since its last start, or an error past d.
func (p *regionProc) wait(want string, d time.Duration) (time.Duration, error) {
	start := time.Now()
	for !strings.Contains(p.said(), want) {
		if time.Since(start) > d {
			return d, fmt.Errorf("%s did not say %q within %v", p.name, want, d)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return time.Since(start), nil
}

// regionStoresYAML is the stores: block for role (daemon or broker): the
// directory across the three regions' members, the session store at session.
// The daemon waits for the directory with no deadline (start_timeout 0), so
// a port49d started during a cut with no snapshot waits, its listeners
// closed (L74 f, its second half).
func regionStoresYAML(p *regionPKI, role, session string) string {
	id, key := p.daemon, p.daemonKey
	if role == "broker" {
		id, key = p.broker, p.brokerKey
	}
	var eps []string
	for i := 1; i <= 3; i++ {
		eps = append(eps, "https://"+regionIP(i)+":2379")
	}
	extraDir, extraSess := "", "      hold_ttl: 15s\n"
	if role == "daemon" {
		extraDir = "      start_timeout: 0\n"
	}
	return fmt.Sprintf("stores:\n  directory:\n    backend: etcd\n    etcd:\n      endpoints: [%s]\n      ca_file: %s\n"+
		"      %s: {cert_file: %s, key_file: %s}\n      call_timeout: 500ms\n%s"+
		"  session:\n    backend: etcd\n    etcd:\n      endpoints: [https://%s]\n      ca_file: %s\n"+
		"      %s: {cert_file: %s, key_file: %s}\n%s",
		strings.Join(eps, ", "), p.ca, role, id, key, extraDir, session, p.ca, role, id, key, extraSess)
}

// lastLine is s's last non-empty line.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// regionClient is the harness's TACACS+ client to one port49d, from the host.
type regionClient struct {
	addr string
	key  []byte
}

func (c regionClient) exchange(typ wire.Type, body []byte) ([]byte, time.Duration, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", c.addr, 5*time.Second)
	if err != nil {
		return nil, time.Since(start), err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	h := wire.Header{MajorVersion: 0xc, Type: typ, SeqNo: 1, SessionID: uint32(time.Now().UnixNano()),
		Length: uint32(len(body))}
	if _, err := conn.Write(append(h.Encode(), wire.Obfuscate(h, c.key, body)...)); err != nil {
		return nil, time.Since(start), err
	}
	hb := make([]byte, wire.HeaderLen)
	if _, err := io.ReadFull(conn, hb); err != nil {
		return nil, time.Since(start), err
	}
	rh, err := wire.DecodeHeader(hb)
	if err != nil {
		return nil, time.Since(start), err
	}
	rb := make([]byte, rh.Length)
	if _, err := io.ReadFull(conn, rb); err != nil {
		return nil, time.Since(start), err
	}
	return wire.Obfuscate(rh, c.key, rb), time.Since(start), nil
}

// login is a PAP login's answer and its reply time. The token is the
// harness's, held in memory; it is never formatted into a line.
func (c regionClient) login(user, token string) (string, time.Duration, error) {
	raw, took, err := c.exchange(wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte(user), Port: []byte("tty1"),
		RemAddr: []byte("192.0.2.74"), Data: []byte(token)}.Encode())
	if err != nil {
		return "", took, err
	}
	r, err := wire.DecodeAuthenReply(raw)
	if err != nil {
		return "", took, err
	}
	return authenStatusName(r.Status), took, nil
}

// command is an authorization's answer and reply time: the session's with
// no words, a command's otherwise.
func (c regionClient) command(user string, words ...string) (string, time.Duration, error) {
	args, priv := [][]byte{[]byte("service=shell"), []byte("cmd=")}, uint8(1)
	if len(words) > 0 {
		args, priv = [][]byte{[]byte("service=shell"), []byte("cmd=" + words[0])}, 15
		for _, w := range words[1:] {
			args = append(args, []byte("cmd-arg="+w))
		}
		args = append(args, []byte("cmd-arg=<cr>"))
	}
	raw, took, err := c.exchange(wire.TypeAuthor, wire.AuthorRequest{AuthenMethod: wire.AuthenMethodTACACSPlus,
		PrivLvl: priv, AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin, User: []byte(user),
		Port: []byte("tty1"), Args: args}.Encode())
	if err != nil {
		return "", took, err
	}
	r, err := wire.DecodeAuthorResponse(raw)
	if err != nil {
		return "", took, err
	}
	return authorStatusName(r.Status), took, nil
}

func authenStatusName(s uint8) string {
	switch s {
	case wire.AuthenStatusPass:
		return "pass"
	case wire.AuthenStatusFail:
		return "fail"
	case wire.AuthenStatusError:
		return "error"
	}
	return fmt.Sprintf("status %d", s)
}

func authorStatusName(s uint8) string {
	switch s {
	case wire.AuthorStatusPassAdd, wire.AuthorStatusPassRepl:
		return "permit"
	case wire.AuthorStatusFail:
		return "deny"
	case wire.AuthorStatusError:
		return "error"
	}
	return fmt.Sprintf("status %d", s)
}

// regionMint mints alice's login token for the l74 device at a broker's
// API, with the lab client certificate. A 503 is tried again for 30s (the
// start's mint gate). The token is returned to be held in memory and
// registered with the leak check; an error never carries the body.
func regionMint(p *regionPKI, brokerAddr string) (string, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(p.lab, testpki.LabClientCert), filepath.Join(p.lab, testpki.LabClientKey))
	if err != nil {
		return "", err
	}
	caPEM, err := os.ReadFile(filepath.Join(p.lab, testpki.LabCA))
	if err != nil {
		return "", err
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{cert}, RootCAs: roots, ServerName: "port49-broker", MinVersion: tls.VersionTLS13}}}
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := client.Post("https://"+brokerAddr+"/v1/tokens", "application/json",
			strings.NewReader(`{"devices":["`+regionDevice+`"]}`))
		if err == nil {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var out api.MintResponse
			switch {
			case resp.StatusCode == http.StatusOK && json.Unmarshal(raw, &out) == nil && len(out.Results) == 1 &&
				out.Results[0].Login != "":
				return out.Results[0].Login, nil
			case resp.StatusCode != http.StatusServiceUnavailable:
				return "", fmt.Errorf("mint at %s: status %d", brokerAddr, resp.StatusCode)
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("mint at %s: no token within 30s (%v)", brokerAddr, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// applyRoles runs each section of `port49d store-roles`' output (Task 11)
// against its cluster, and then the auth lines its last comment names, as
// etcd's root does once per cluster. A section with no cluster in ctl is
// skipped: the directory's roles are made once, by the first region's.
func applyRoles(t *testing.T, out string, ctl map[string]func(args ...string) (string, error)) []string {
	t.Helper()
	var said []string
	target, then := "directory", ""
	var cmds [][]string
	flush := func() {
		for _, part := range strings.Split(then, "&&") {
			if f := strings.Fields(part); len(f) > 1 && f[0] == "etcdctl" {
				cmds = append(cmds, f[1:])
			}
		}
		if run := ctl[target]; run != nil {
			for _, c := range cmds {
				got, err := run(c...)
				said = append(said, fmt.Sprintf("%s: `etcdctl %s`: %s", target, strings.Join(c, " "), firstLine(got)))
				if err != nil {
					t.Fatalf("INVALID: etcdctl %s on the %s store, as store-roles printed it: %v\n%s",
						strings.Join(c, " "), target, err, got)
				}
			}
		}
		cmds, then = nil, ""
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "# port49 roles for the directory store"):
			flush()
			target = "directory"
		case strings.HasPrefix(line, "# port49 roles for the session store"):
			flush()
			target = "session"
		case strings.HasPrefix(line, "etcdctl "):
			cmds = append(cmds, strings.Fields(line)[1:])
		case strings.HasPrefix(line, "# then, if auth is not enabled yet:"):
			then = strings.TrimPrefix(line, "# then, if auth is not enabled yet:")
		case then != "" && strings.HasPrefix(line, "#"):
			then += " " + strings.TrimSpace(strings.TrimPrefix(line, "#"))
		}
	}
	flush()
	return said
}
```

`labGuardAt`, `l66StopSentinel`, `l66DiskFloorMB`, `firstLine`, `oneLineMax`, `freeAddr` and
`root` are the lab package's already. The unit tests build with `-tags lab` (`make lab-unit`), so
they see them.

- [ ] **Step 4: Write `tests/lab/l74_test.go`**

```go
//go:build lab

package lab

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/tests/lab/labcreds"
)

const l74Claim = "spec §15 L74, cell by cell (decision 51: the cache, fail closed, a process with no cache, the runner's reach, port49 store status)."

// regionRow is one cell's line of a note.
type regionRow struct {
	ID, Claim, Observed string
	Agrees              bool
}

// regionNote is a results note in L72's shape.
func regionNote(row, platform, version, run, claim string, rows []regionRow, notMeasured []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s — three simulated regions\n\n- **Date measured:** %s\n- **Platform:** %s\n"+
		"- **Image version:** %s\n- **Capture:** tests/lab/evidence/%s-regions/\n- **Run:** %s\n\n## Claim\n\n%s\n\n"+
		"## Observation\n\n| cell | claim | observed | agrees with decision 51 |\n|---|---|---|---|\n",
		row, time.Now().UTC().Format("2006-01-02"), platform, version, row, run, claim)
	for _, r := range rows {
		agrees := "yes"
		if !r.Agrees {
			agrees = "**no**"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", r.ID, r.Claim, strings.ReplaceAll(r.Observed, "|", "\\|"), agrees)
	}
	if len(notMeasured) > 0 {
		b.WriteString("\n**Not measured here:**\n\n- " + strings.Join(notMeasured, "\n- ") + "\n")
	}
	return b.String()
}

// regionWorld is the run: the PKI, the binaries, the members and processes
// of each region, and every secret the notes must not hold.
type regionWorld struct {
	t                  *testing.T
	dir, etcdBin       string
	port49d, broker    string // binaries
	cli                string // port49
	pki                *regionPKI
	dirMembers, sess   [4]*regionEtcd // indexed 1..3
	brokers, daemons   [4]*regionProc
	encKey, tacacsKey  string
	secrets            []string
	mu                 sync.Mutex
	// home is the $HOME every port49 CLI run gets: its .port49/config.yaml
	// pins issued_key_store: file (pinFileKeyStore), so no run probes the
	// machine's TPM (lab rules). guard is the STOP and disk check, run
	// before every cell.
	home  string
	guard func()
	// leaks are further checks a note and each evidence line must pass:
	// L75 adds the TOTP secrets' and codes' (l67Secrets.leaksIn).
	leaks []func(string) bool
}

func (w *regionWorld) hold(secret string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.secrets = append(w.secrets, secret)
}

func (w *regionWorld) env() []string {
	return []string{"L74_ENC_KEY=" + w.encKey, "L74_TACACS_KEY=" + w.tacacsKey}
}

func (w *regionWorld) client(i int) regionClient {
	return regionClient{addr: regionIP(i) + ":4949", key: []byte(w.tacacsKey)}
}

func (w *regionWorld) adminSock(i int, proc string) string {
	return filepath.Join(w.dir, fmt.Sprintf("r%d-%s.sock", i, proc))
}

// port49 runs the CLI and answers its output, exit code and duration.
func (w *regionWorld) port49(args ...string) (string, int, time.Duration) {
	start := time.Now()
	cmd := exec.Command(w.cli, args...)
	cmd.Env = append(os.Environ(), "HOME="+w.home)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		code = -1
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
	}
	return strings.TrimSpace(string(out)), code, time.Since(start)
}

// mint is a token minted at region i's broker, held and registered.
func (w *regionWorld) mint(i int) string {
	w.t.Helper()
	tok, err := regionMint(w.pki, regionIP(i)+":8443")
	if err != nil {
		w.t.Fatalf("INVALID: %v", err)
	}
	w.hold(tok)
	return tok
}

// session logs alice in at region i with a fresh token and authorizes her
// session, as a device does before her first command.
func (w *regionWorld) session(i int) error {
	st, _, err := w.client(i).login("alice", w.mint(i))
	if err != nil || st != "pass" {
		return fmt.Errorf("region %d login: %s %v", i, st, err)
	}
	if st, _, err := w.client(i).command("alice"); err != nil || st != "permit" {
		return fmt.Errorf("region %d session authorization: %s %v", i, st, err)
	}
	return nil
}

// until is how long until region i's command answers want, polling every
// 100ms, or false past d.
func (w *regionWorld) until(i int, want string, d time.Duration) (time.Duration, bool) {
	start := time.Now()
	for time.Since(start) < d {
		if st, _, _ := w.client(i).command("alice", "show", "version"); st == want {
			return time.Since(start), true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return d, false
}
```

Then the world, the configs and the cells:

```go
// startRegions builds the run (L74's shape): the binaries, the keys, the
// network, the etcd members, the roles, the brokers and the daemons, each
// removed at t's cleanup (in reverse: processes, members, network).
func startRegions(t *testing.T, etcdBin string) *regionWorld {
	t.Helper()
	dir, err := os.MkdirTemp("", "p49l74")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	w := &regionWorld{t: t, dir: dir, etcdBin: etcdBin, pki: newRegionPKI(t), home: filepath.Join(dir, "home"),
		guard: func() {}}
	if err := pinFileKeyStore(w.home); err != nil {
		t.Fatalf("INVALID: the CLI's home: %v", err)
	}
	bins := filepath.Join(dir, "bin")
	build := exec.Command("go", "build", "-o", bins+"/", "./cmd/port49d", "./cmd/port49-broker", "./cmd/port49")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("INVALID: building the binaries: %v\n%s", err, out)
	}
	w.port49d, w.broker, w.cli = filepath.Join(bins, "port49d"), filepath.Join(bins, "port49-broker"),
		filepath.Join(bins, "port49")
	// The encryption key is 32 bytes as written (32 hex characters), as the
	// lab's default is; both are this run's and held for the leak check.
	w.encKey, w.tacacsKey = randomHex(t, 16), randomHex(t, 12)
	w.hold(w.encKey)
	w.hold(w.tacacsKey)

	_ = sudoRun(regionNetDown(), true)
	if err := sudoRun(regionNetUp(), false); err != nil {
		t.Fatalf("INVALID: the network: %v", err)
	}
	t.Cleanup(func() { _ = sudoRun(regionNetDown(), true) })

	var initial []string
	for i := 1; i <= 3; i++ {
		initial = append(initial, fmt.Sprintf("d%d=http://%s:2380", i, regionIP(i)))
	}
	for i := 1; i <= 3; i++ {
		w.dirMembers[i] = &regionEtcd{ns: regionNS(i), name: fmt.Sprintf("d%d", i), bin: etcdBin,
			client: regionIP(i) + ":2379", peer: regionIP(i) + ":2380", cluster: strings.Join(initial, ","),
			data: filepath.Join(dir, fmt.Sprintf("d%d.etcd", i)), log: filepath.Join(dir, fmt.Sprintf("d%d.log", i)),
			pki: w.pki}
		w.sess[i] = &regionEtcd{ns: regionNS(i), name: "s", bin: etcdBin, client: regionSessionClient,
			peer: regionSessionPeer, cluster: "s=http://" + regionSessionPeer,
			data: filepath.Join(dir, fmt.Sprintf("s%d.etcd", i)), log: filepath.Join(dir, fmt.Sprintf("s%d.log", i)),
			pki: w.pki}
	}
	for i := 1; i <= 3; i++ {
		w.dirMembers[i].start(t)
		w.sess[i].start(t)
	}
	health := func(e *regionEtcd) {
		for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(500 * time.Millisecond) {
			if _, err := e.ctl("https://"+e.client, "endpoint", "health"); err == nil {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("INVALID: etcd %s in %s did not answer within 60s; see %s", e.name, e.ns, e.log)
			}
		}
	}
	for i := 1; i <= 3; i++ {
		health(w.dirMembers[i])
		health(w.sess[i])
	}

	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("policy.yaml", regionPolicy())
	write("inventory.yaml", regionInventory())
	for i := 1; i <= 3; i++ {
		dcfg := write(fmt.Sprintf("r%d-port49d.yaml", i), w.daemonYAML(i))
		bcfg := write(fmt.Sprintf("r%d-port49-broker.yaml", i), w.brokerYAML(i))
		out, err := exec.Command(w.port49d, "store-roles", "--config", dcfg, "--broker-config", bcfg).CombinedOutput()
		if err != nil {
			t.Fatalf("INVALID: port49d store-roles for region %d: %v\n%s", i, err, out)
		}
		s := w.sess[i]
		ctl := map[string]func(args ...string) (string, error){
			"session": func(args ...string) (string, error) { return s.ctl("https://"+s.client, args...) }}
		if i == 1 { // the directory's roles are made once
			d := w.dirMembers[1]
			ctl["directory"] = func(args ...string) (string, error) { return d.ctl(w.dirEndpoints(), args...) }
		}
		applyRoles(t, string(out), ctl)
		w.brokers[i] = &regionProc{name: fmt.Sprintf("port49-broker r%d", i), ns: regionNS(i), bin: w.broker,
			cfg: bcfg, log: filepath.Join(dir, fmt.Sprintf("r%d-broker.log", i)), env: w.env()}
		w.daemons[i] = &regionProc{name: fmt.Sprintf("port49d r%d", i), ns: regionNS(i), bin: w.port49d,
			cfg: dcfg, log: filepath.Join(dir, fmt.Sprintf("r%d-port49d.log", i)), env: w.env()}
	}
	for _, procs := range [][4]*regionProc{w.brokers, w.daemons} {
		for i := 1; i <= 3; i++ {
			p := procs[i]
			p.start(t)
			t.Cleanup(p.stop)
			if _, err := p.wait("listening on", 60*time.Second); err != nil {
				t.Fatalf("INVALID: %v\n%s", err, tailOf(p.said(), 2000))
			}
		}
	}
	return w
}

// dirEndpoints is the directory's three client URLs, for etcdctl.
func (w *regionWorld) dirEndpoints() string {
	var eps []string
	for i := 1; i <= 3; i++ {
		eps = append(eps, "https://"+regionIP(i)+":2379")
	}
	return strings.Join(eps, ",")
}

func regionPolicy() string {
	return `scopes:
  - {name: all, match: {}}
roles:
  - {name: admin, privilege: admin, permit: ["**"]}
subjects:
  - {name: alice, identity: ["user:alice@example.com"], username: alice, token_ttl: 900s}
grants:
  - {subject: alice, scope: all, roles: [admin]}
key_groups:
  - {match: {cidr: 10.149.0.0/24}, key_ref: k}
`
}

func regionInventory() string {
	return "devices:\n  - {name: " + regionDevice + ", platform: arista_eos, addresses: [" + regionHostIP + "]}\n"
}

func (w *regionWorld) daemonYAML(i int) string {
	return fmt.Sprintf(`listen: "%[1]s:4949"
metrics_listen: "%[1]s:9049"
inventory_file: %[2]s/inventory.yaml
policy: {file: %[2]s/policy.yaml, watch_interval: 5s}
keys:
  k:
    current: {version: 1, secret_env: L74_TACACS_KEY}
encryption:
  current: {id: l74, secret_env: L74_ENC_KEY}
admin_socket: %[3]s
accounting: {spool_path: %[2]s/r%[4]d-acct.jsonl}
`, regionIP(i), w.dir, w.adminSock(i, "d"), i) + regionStoresYAML(w.pki, "daemon", regionSessionClient)
}

func (w *regionWorld) brokerYAML(i int) string {
	state := filepath.Join(w.dir, fmt.Sprintf("r%d-state", i))
	os.Mkdir(state, 0o700)
	return fmt.Sprintf(`metrics_listen: "%[1]s:9050"
inventory_file: %[2]s/inventory.yaml
key_refs: [k]
encryption:
  current: {id: l74, secret_env: L74_ENC_KEY}
admin_socket: %[3]s
broker:
  listen: "%[1]s:8443"
  tls_cert_file: %[4]s
  tls_key_file: %[5]s
  client_ca_file: %[6]s
  policy_file: %[2]s/policy.yaml
  state_dir: %[7]s
  policy_watch_interval: 5s
  certificate_status: {disabled: true}
`, regionIP(i), w.dir, w.adminSock(i, "b"), filepath.Join(w.pki.lab, testpki.LabServerCert),
		filepath.Join(w.pki.lab, testpki.LabServerKey), filepath.Join(w.pki.lab, testpki.LabCA), state) +
		regionStoresYAML(w.pki, "broker", regionSessionClient)
}
```

(Add `"github.com/rhwendt/port49/internal/testpki"` to `l74_test.go`'s imports.) `w.dir` is a
`os.MkdirTemp("", "p49l74")` made 0700: the processes run as this user, through sudo, in it.

`TestRegions`:

```go
func TestRegions(t *testing.T) {
	guard := func() {
		if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
			t.Fatalf("INVALID: %v", err)
		}
	}
	guard()
	bin := os.Getenv("PORT49_LAB_ETCD_BIN")
	if bin == "" {
		t.Skip("PORT49_LAB_ETCD_BIN names no directory holding etcd and etcdctl v3.6.15")
	}
	w := startRegions(t, bin)
	w.guard = guard
	var rows []regionRow
	var missed []string
	row := func(id, claim, observed string, agrees bool) {
		rows = append(rows, regionRow{ID: id, Claim: claim, Observed: observed, Agrees: agrees})
	}
	guard()
	l74CellA(w, row)
	guard()
	l74CellB(w, row)
	guard()
	l74CellsCToG(w, row)
	guard()
	l74CellH(w, row)
	guard()
	l74CellI(w, row)
	writeRegionNote(t, w, "L74", l74Claim, rows, missed, append(w.brokers[1:], w.daemons[1:]...))
}
```

Each cell function appends one row (cells c to g share one cut, so one function appends five). An
INVALID condition (a setup step that failed, which says nothing about port49) calls
`w.t.Fatalf("INVALID: …")`. A result that is not as the claim says is a row with `Agrees: false`,
never a fatal.

```go
// (a) a login and a command in each region, and their reply times beside
// the round trip between regions.
func l74CellA(w *regionWorld, row func(id, claim, observed string, agrees bool)) {
	var parts []string
	ok := true
	for i := 1; i <= 3; i++ {
		st, took, err := w.client(i).login("alice", w.mint(i))
		cst, ctook, cerr := w.client(i).command("alice")
		parts = append(parts, fmt.Sprintf("region %d: login %s in %v, session authorization %s in %v",
			i, st, took.Round(time.Millisecond), cst, ctook.Round(time.Millisecond)))
		ok = ok && err == nil && cerr == nil && st == "pass" && cst == "permit"
	}
	out, _ := exec.Command("sudo", "-n", "ip", "netns", "exec", regionNS(1), "ping", "-c", "5", "-q", regionIP(2)).CombinedOutput()
	parts = append(parts, "region 1 to region 2: "+lastLine(string(out)))
	row("a", "a login and a command in each region; their reply times beside the round trip between regions",
		strings.Join(parts, "; "), ok)
}

// (b) a revocation in region 1: the time until region 2's and region 3's
// next command is denied; then the lift.
func l74CellB(w *regionWorld, row func(id, claim, observed string, agrees bool)) {
	for i := 2; i <= 3; i++ {
		if err := w.session(i); err != nil {
			w.t.Fatalf("INVALID: %v", err)
		}
	}
	_, code, took := w.port49("revoke", "--socket", w.adminSock(1, "b"), "--principal", "user:alice@example.com")
	d2, ok2 := w.until(2, "deny", 30*time.Second)
	d3, ok3 := w.until(3, "deny", 30*time.Second)
	_, lcode, _ := w.port49("revoke", "--socket", w.adminSock(1, "b"), "--principal", "user:alice@example.com", "--lift")
	row("b", "a revocation made in region 1: the time until region 2's and region 3's next command is denied",
		fmt.Sprintf("revoke exit %d in %v; region 2 denied after %v (%v), region 3 after %v (%v); lift exit %d",
			code, took.Round(time.Millisecond), d2.Round(10*time.Millisecond), ok2, d3.Round(10*time.Millisecond), ok3, lcode),
		code == 0 && ok2 && ok3 && lcode == 0)
}
```

```go
// metrics is region i's port49d's /metrics, "" when it does not answer.
func (w *regionWorld) metrics(i int) string {
	resp, err := http.Get("http://" + regionIP(i) + ":9049/metrics")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return string(raw)
}

// metricOf is the value of the label-less metric name in text, or -1.
func metricOf(text, name string) float64 {
	for _, l := range strings.Split(text, "\n") {
		if v, ok := strings.CutPrefix(l, name+" "); ok {
			if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
				return f
			}
		}
	}
	return -1
}

// firstLineWith is the first line of s holding sub, "" when none does.
func firstLineWith(s, sub string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, sub) {
			return strings.TrimSpace(l)
		}
	}
	return ""
}

// (c) to (g): one cut of region 3, and the heal.
func l74CellsCToG(w *regionWorld, row func(id, claim, observed string, agrees bool)) {
	for _, i := range []int{2, 3} {
		if err := w.session(i); err != nil {
			w.t.Fatalf("INVALID: %v", err)
		}
	}
	pre := w.mint(3)
	// A mark region 3 holds before the cut, for (e)'s lift.
	if _, code, _ := w.port49("revoke", "--socket", w.adminSock(1, "b"), "--principal", "user:carol@example.com"); code != 0 {
		w.t.Fatal("INVALID: carol's revocation before the cut")
	}
	if _, err := w.brokers[3].wait("a revocation of user:carol@example.com made elsewhere reached", 30*time.Second); err != nil {
		w.t.Fatalf("INVALID: %v", err)
	}
	// R19: region 3's port49d and broker have each written a snapshot (every
	// 60s) before the cut, for (f).
	for deadline := time.Now().Add(150 * time.Second); ; time.Sleep(2 * time.Second) {
		js, _ := w.sess[3].ctl("https://"+w.sess[3].client, "get", "--prefix", "/port49/v1/ds/m/", "--count-only", "-w", "json")
		if etcdCount(js) >= 2 {
			break
		}
		if time.Now().After(deadline) {
			w.t.Fatal("INVALID: region 3 wrote no directory snapshots within 150s")
		}
	}
	w.guard()
	if err := sudoRun(regionCut(3, true), false); err != nil {
		w.t.Fatalf("INVALID: the cut: %v", err)
	}
	healed := false
	defer func() {
		if !healed {
			_ = sudoRun(regionCut(3, false), true)
		}
	}()
	if _, err := w.daemons[3].wait("directory store: not answering", 15*time.Second); err != nil {
		w.t.Fatalf("INVALID: %v", err)
	}

	cst, _, _ := w.client(3).command("alice", "show", "version")
	lst, _, _ := w.client(3).login("alice", pre)
	status, code, _ := w.port49("store", "status", "--socket", w.adminSock(3, "d"))
	m := w.metrics(3)
	reach := metricOf(m, "port49_store_directory_reachable")
	age := float64(time.Now().Unix()) - metricOf(m, "port49_store_directory_confirmed_timestamp_seconds")
	row("c", "region 3 cut: an open session's command and a login with a token minted before the cut answered; "+
		"port49 store status and its exit code; the two metrics",
		fmt.Sprintf("command %s; login %s; `port49 store status` exit %d: %s; port49_store_directory_reachable %v; "+
			"confirmed %.0fs ago", cst, lst, code, strings.ReplaceAll(status, "\n", " / "), reach, age),
		cst == "permit" && lst == "pass" && code == 3 && reach == 0)

	w.guard()
	_, rcode, _ := w.port49("revoke", "--socket", w.adminSock(1, "b"), "--principal", "user:alice@example.com")
	time.Sleep(5 * time.Second)
	d3, _, _ := w.client(3).command("alice", "show", "version")
	d2, _, _ := w.client(2).command("alice", "show", "version")
	row("d", "during the cut, a revocation in region 1: region 3's session still permitted (region 2's denied, the control)",
		fmt.Sprintf("revoke exit %d; 5s later region 3 %s, region 2 %s", rcode, d3, d2),
		rcode == 0 && d3 == "permit" && d2 == "deny")

	w.guard()
	out1, c1, t1 := w.port49("revoke", "--socket", w.adminSock(3, "b"), "--principal", "user:bob@example.com")
	out2, c2, t2 := w.port49("revoke", "--socket", w.adminSock(3, "b"), "--principal", "user:carol@example.com", "--lift")
	row("e", "during the cut, port49 revoke and port49 revoke --lift on region 3's broker: each refused, and how long each took",
		fmt.Sprintf("revoke: exit %d in %v: %s; lift: exit %d in %v: %s", c1, t1.Round(time.Millisecond),
			firstLine(out1), c2, t2.Round(time.Millisecond), firstLine(out2)),
		c1 != 0 && c2 != 0 && t1 < 5*time.Second && t2 < 5*time.Second)

	// (f) restarts during the cut serve from region 3's snapshot (R19); with
	// its snapshots deleted, a restarted port49d stays dark until the heal.
	w.guard()
	w.daemons[3].stop()
	w.brokers[3].stop()
	w.brokers[3].start(w.t)
	w.daemons[3].start(w.t)
	_, lerr := w.daemons[3].wait("port49d: listening on", 60*time.Second)
	_, berr := w.brokers[3].wait("port49-broker: listening on", 60*time.Second)
	fst := "no token"
	if tok, merr := regionMint(w.pki, regionIP(3)+":8443"); merr == nil {
		w.hold(tok)
		fst, _, _ = w.client(3).login("alice", tok)
	}
	fstatus, _, _ := w.port49("store", "status", "--socket", w.adminSock(3, "d"))
	w.daemons[3].stop()
	if _, err := w.sess[3].ctl("https://"+w.sess[3].client, "del", "--prefix", "/port49/v1/ds/"); err != nil {
		w.t.Fatalf("INVALID: deleting region 3's snapshots: %v", err)
	}
	w.daemons[3].start(w.t)
	time.Sleep(20 * time.Second)
	said := w.daemons[3].said()
	_, derr := net.DialTimeout("tcp", regionIP(3)+":4949", 2*time.Second)
	row("f", "during the cut, port49d and port49-broker restarted in region 3 serve from its snapshot; with its "+
		"snapshots deleted, a restarted port49d's listeners stay closed until the heal",
		fmt.Sprintf("from the snapshot: port49d listened %v, the broker listened %v, a mint and login: %s, status: %s; "+
			"without: 20s after the restart said it listens %v, a dial to 4949: %v; its line: %s",
			lerr == nil, berr == nil, fst, strings.ReplaceAll(fstatus, "\n", " / "),
			strings.Contains(said, "port49d: listening on"), derr, firstLineWith(said, "no snapshot")),
		lerr == nil && berr == nil && fst == "pass" && strings.Contains(fstatus, "(snapshot)") &&
			!strings.Contains(said, "port49d: listening on") && derr != nil)

	w.guard()
	if err := sudoRun(regionCut(3, false), false); err != nil {
		w.t.Fatalf("INVALID: the heal: %v", err)
	}
	healed = true
	if _, err := w.daemons[3].wait("port49d: listening on", 60*time.Second); err != nil {
		w.t.Fatalf("INVALID: %v", err)
	}
	denied, ok := w.until(3, "deny", 60*time.Second)
	took, lerr := w.brokers[3].wait("a revocation of user:alice@example.com made elsewhere reached", 30*time.Second)
	row("g", "the heal: the time until region 3's session from (d) is denied, and region 3's runner line naming the revocation",
		fmt.Sprintf("denied %v after port49d listened again (%v); runner line after %v: %s",
			denied.Round(10*time.Millisecond), ok, took.Round(10*time.Millisecond),
			firstLineWith(w.brokers[3].said(), "user:alice@example.com made elsewhere reached")),
		ok && lerr == nil)
	for _, p := range []string{"user:alice@example.com", "user:carol@example.com"} {
		w.port49("revoke", "--socket", w.adminSock(1, "b"), "--principal", p, "--lift")
	}
}

// (h) the members port49 store status prints with auth on, from region 1's port49d.
func l74CellH(w *regionWorld, row func(id, claim, observed string, agrees bool)) {
	out, code, _ := w.port49("store", "status", "--socket", w.adminSock(1, "d"))
	row("h", "with auth on, the members port49 store status prints: whether a non-root identity's member list and per-member status answer",
		fmt.Sprintf("exit %d: %s", code, strings.ReplaceAll(out, "\n", " / ")),
		code == 0 && strings.Contains(out, "directory  etcd    3/3 members  reachable"))
}
```

```go
// revisionOf is the highest header revision in `etcdctl endpoint status -w json`'s answer.
func revisionOf(js string) int64 {
	var sts []struct {
		Status struct {
			Header struct {
				Revision int64 `json:"revision"`
			} `json:"header"`
		}
	}
	if json.Unmarshal([]byte(js), &sts) != nil {
		return 0
	}
	var rev int64
	for _, s := range sts {
		rev = max(rev, s.Status.Header.Revision)
	}
	return rev
}

// etcdCount is `etcdctl get --count-only -w json`'s count.
func etcdCount(js string) int64 {
	var r struct {
		Count int64 `json:"count"`
	}
	_ = json.Unmarshal([]byte(js), &r)
	return r.Count
}

// (i) a lift in region 1 during a cut longer than a compaction: region 3's
// runner cannot tell it from a mark a restore lost, and puts it back on the
// heal (R17; plan 7e Ruling 12).
func l74CellI(w *regionWorld, row func(id, claim, observed string, agrees bool)) {
	d := w.dirMembers[1]
	near := "https://" + regionIP(1) + ":2379,https://" + regionIP(2) + ":2379" // the side that keeps its quorum
	w.port49("revoke", "--socket", w.adminSock(1, "b"), "--principal", "user:alice@example.com")
	if _, ok := w.until(3, "deny", 30*time.Second); !ok {
		w.t.Fatal("INVALID: region 3 never denied before the cut")
	}
	if err := sudoRun(regionCut(3, true), false); err != nil {
		w.t.Fatalf("INVALID: the cut: %v", err)
	}
	_, lcode, _ := w.port49("revoke", "--socket", w.adminSock(1, "b"), "--principal", "user:alice@example.com", "--lift")
	st, _ := d.ctl(near, "endpoint", "status", "-w", "json")
	rev := revisionOf(st)
	_, cerr := d.ctl(near, "compact", strconv.FormatInt(rev, 10), "--physical")
	if err := sudoRun(regionCut(3, false), false); err != nil {
		w.t.Fatalf("INVALID: the heal: %v", err)
	}
	took, perr := w.brokers[3].wait("are put back", 60*time.Second)
	cnt, _ := d.ctl(w.dirEndpoints(), "get", "/port49/v1/rv/", "--prefix", "--count-only", "-w", "json")
	n := etcdCount(cnt)
	row("i", "a lift in region 1 during a cut longer than a compaction: whether region 3's runner puts the mark back on the heal",
		fmt.Sprintf("lift exit %d; compacted at revision %d (%v); put-back line after %v: %s; marks in the directory after: %d",
			lcode, rev, cerr, took.Round(10*time.Millisecond), firstLineWith(w.brokers[3].said(), "are put back"), n),
		perr == nil && n == 1)
	w.port49("revoke", "--socket", w.adminSock(1, "b"), "--principal", "user:alice@example.com", "--lift")
}

// writeRegionNote writes tests/lab/results/<row>-regions.md and the
// processes' logs as its evidence, each filtered of every line naming a
// held secret; a note that would hold one fails the test.
func writeRegionNote(t *testing.T, w *regionWorld, row, claim string, rows []regionRow, missed []string,
	procs []*regionProc) {
	t.Helper()
	ver, _ := exec.Command(filepath.Join(w.etcdBin, "etcd"), "--version").Output()
	head, _ := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	note := labcreds.RedactNote(regionNote(row,
		"port49 on the lab host, three simulated regions (network namespaces, tc netem 20ms each way)",
		firstLine(string(ver)), "commit `"+strings.TrimSpace(string(head))+"`, `-run TestRegions`", claim, rows, missed))
	if hits := labcreds.Contains([]byte(note), w.secrets); len(hits) > 0 {
		t.Fatalf("the %s note holds a held secret (%d hit(s)); nothing written", row, len(hits))
	}
	for _, leak := range w.leaks {
		if leak(note) {
			t.Fatalf("the %s note holds a TOTP secret or code; nothing written", row)
		}
	}
	leaky := func(l string) bool {
		if len(labcreds.Contains([]byte(l), w.secrets)) > 0 {
			return true
		}
		for _, leak := range w.leaks {
			if leak(l) {
				return true
			}
		}
		return false
	}
	path := filepath.Join(root, "tests", "lab", "results", row+"-regions.md")
	if err := os.WriteFile(path, []byte(note), 0o644); err != nil {
		t.Fatal(err)
	}
	ev := filepath.Join(root, "tests", "lab", "evidence", row+"-regions")
	if err := os.MkdirAll(ev, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range procs {
		raw, _ := os.ReadFile(p.log)
		var kept []string
		for _, l := range strings.Split(string(raw), "\n") {
			if !leaky(l) {
				kept = append(kept, l)
			}
		}
		name := strings.ReplaceAll(p.name, " ", "-") + ".log"
		if err := os.WriteFile(filepath.Join(ev, name), []byte(strings.Join(kept, "\n")), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("wrote %s", path)
}
```

`l74_test.go`'s imports gain `"encoding/json"`, `"io"`, `"net"`, `"net/http"` and `"strconv"`.
`w.brokers[1:]` is a slice of the `[4]*regionProc` array. L75's harness is Task 14a's: it adds
`l75(t, w)` to `TestRegions`.

- [ ] **Step 5: Run the unit tests and vet**

Run: `go test -tags lab ./tests/lab/ -run '^(TestRegionNetworkCommands|TestInNSRunsAsTheUserWithItsEnvironment|TestRegionConfigsNameTwoStores|TestApplyRolesSplitsTheSections|TestStatusNames|TestRegionNoteShape)$' -count=1 && go vet -tags lab ./tests/lab/... && make lab-unit`
Expected: PASS. `make lab-unit` picks the new unit tests up by their file name.

- [ ] **Step 6: The make target and the README**

In `Makefile`, add `lab-regions` to `.PHONY`, and:

```make
# L74 and L75 (plan 11a): three simulated regions on this host; needs sudo -n,
# PORT49_LAB_ETCD_BIN (etcd v3.6.15) and the L67 directory containers' images.
lab-regions:
	go test -tags lab ./tests/lab/ -run '^TestRegions$$' -count=1 -timeout 120m -v
```

In `tests/lab/README.md`, add a section "L74 and L75: three regions" that says:
- What the harness builds: the three namespaces, the bridge `p49rbr0` on 10.149.0.0/24, netem
  20ms each way, and the cut as iptables in region 3's namespace.
- What it needs: `sudo -n` for `ip`, `tc`, `iptables` and `pkill`; `PORT49_LAB_ETCD_BIN`; and L67's
  directory images.
- That L75's brokers run on the host, and why.
- That 10.149.0.0/24 must be free (`ip -4 route`).
- How to remove a left-over network: `sudo ip netns del p49r1` (and r2, r3), then
  `sudo ip link del p49rbr0`.

- [ ] **Step 7: Commit**

```bash
git add tests/lab/regions_test.go tests/lab/l74_test.go tests/lab/l74_unit_test.go tests/lab/README.md Makefile
git commit -m "test: the three-region harness for L74

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 14a: The L75 harness: three host brokers on one directory

**Files:**
- Create: `tests/lab/l75_test.go` (build tag `lab`): the host brokers, the cells, the note
- Modify: `tests/lab/l74_unit_test.go` (two unit tests), `tests/lab/l74_test.go` (`TestRegions`
  runs L75 after L74)

**Interfaces:**
- Consumes:
  - Task 14's `regionWorld` (with `home`, `guard`, `leaks`), `regionEtcd`, `regionProc`,
    `regionStoresYAML`, `applyRoles`, `writeRegionNote`, `etcdCount`, `firstLineWith`;
  - L67's harness: `startDirectoriesWith`, `l67Prepare`, `l67Password`, `l67TestDir`, `newL67API`,
    `l67Answer`, `l67SecretOf`, `l67Secrets`, `l67Person`, `l67WrongCode`, `localBrokerEnv`,
    `l67MintsOpen`, `l67HostPort`, `labEncKeyDefault`, `platOpenLDAP`, `freeAddr`, `oneLineMax`;
  - `oidctest.Issuer` (`internal/oidc/oidctest`), `oidc.BackchannelLogoutEvent`;
  - `etcdtest.NewProxy` and `(*Proxy).Hang`.
- Produces: `l75(t, w)`, which writes `tests/lab/results/L75-regions.md` with the host brokers' logs
  under `tests/lab/evidence/L75-regions/`; `l75BrokerYAML`, `l75Mint`, `l75Logout`,
  `l75LogoutToken`.

The shape (L75's row; R8, R13, R15, R16, R26):
- **Three host brokers**, `b1..b3`, outside the namespaces: OpenLDAP's ports are published on the
  host's loopback alone, which no namespace reaches. The note says so. Each has a session etcd of
  one member on the host's loopback (`regionEtcd` with `ns: ""`), and all three share L74's
  directory etcd at the members' bridge addresses. `b3` reaches the directory through three
  `etcdtest.Proxy`s, one per member, which the cells hang to cut it.
- **Identity.** Cells (a) to (f): `x509` (a client CA the harness makes: carol's and bob's
  certificates) and `directory_password` for `corp.example.com`. Cell (g): `x509` and an `oidc`
  verifier for `corp.example.com` at an in-process provider (`oidctest.Issuer`), which signs the
  ID tokens and the logout tokens. A password and a provider for one domain are refused together
  (decision 47 D8), so (g) restarts the brokers with the second identity. Keycloak's own sending
  (no retry of a 503) is L45's, already measured; L75 measures port49's path across brokers.
- **Every broker** holds the same `encryption:` key as L74's (`L74_ENC_KEY`): the directory's
  records are sealed with it (R27).
- **Lab rules.** `w.guard()` runs before every cell. Every `port49` CLI run is `w.port49`, with
  `HOME=<w.home>`, whose `.port49/config.yaml` says `issued_key_store: file`. The TOTP secrets and
  every code are registered with an `l67Secrets`, whose `leaksIn` joins `w.leaks`; the people's
  password, every token and every ID token are held with `w.hold`. Nothing prints them.

- [ ] **Step 1: Write the failing unit tests**

Append to `tests/lab/l74_unit_test.go` (its imports gain `"fmt"`, `"time"` and
`"github.com/rhwendt/port49/internal/oidc"`):

```go
// L75's broker config loads as port49-broker's, in both identities: the
// password one for (a) to (f), the provider one for (g).
func TestL75BrokerConfigLoads(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("L74_ENC_KEY", labEncKeyDefault)
	t.Setenv("LAB_DIRECTORY_BIND_PASSWORD", "unit-test-bind-password")
	x := l67TestDir(t, platOpenLDAP)
	p := newRegionPKI(t)
	for _, files := range []string{"ca.pem", "users-ca.pem", "issuer-ca.pem"} {
		if err := os.WriteFile(filepath.Join(dir, files),
			[]byte("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, provider := range []bool{false, true} {
		o := l75Opts{i: 2, dir: dir, x: x, pki: p, session: "127.0.0.1:2579", usersCA: filepath.Join(dir, "users-ca.pem"),
			issuer: "https://127.0.0.1:9", issuerCA: filepath.Join(dir, "issuer-ca.pem"), provider: provider}
		path := filepath.Join(dir, fmt.Sprintf("b2-%v.yaml", provider))
		if err := os.WriteFile(path, []byte(l75BrokerYAML(o)), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.LoadBroker(path)
		if err != nil {
			t.Fatalf("provider %v: %v\n%s", provider, err, l75BrokerYAML(o))
		}
		if cfg.Stores.Shared || cfg.Broker.Directory == nil {
			t.Fatalf("provider %v: a split with a directory, got shared %v", provider, cfg.Stores.Shared)
		}
		if got := cfg.Broker.Identity.PasswordSignIn != nil; got == provider {
			t.Fatalf("provider %v: password sign-in %v", provider, got)
		}
	}
}

// A logout token names the provider, the client, the session and the
// back-channel event, as Keycloak's does (L45).
func TestL75LogoutTokenClaims(t *testing.T) {
	c := l75LogoutClaims("https://idp.example", "port49-cli", "s-1", "jti-1", time.Unix(1000, 0))
	if c["iss"] != "https://idp.example" || c["aud"] != "port49-cli" || c["sid"] != "s-1" || c["jti"] != "jti-1" {
		t.Fatalf("%v", c)
	}
	if _, ok := c["events"].(map[string]any)[oidc.BackchannelLogoutEvent]; !ok {
		t.Fatalf("no back-channel event: %v", c)
	}
}
```

`labEncKeyDefault`, `l67TestDir` and `platOpenLDAP` are the lab's (L67's unit tests use them); the
stand-in CA files are `l67TestDir`'s, which the config loader accepts.

- [ ] **Step 2: Run them to verify they fail**

Run: `go test -tags lab ./tests/lab/ -run '^TestL75' -count=1`
Expected: FAIL to compile (`undefined: l75Opts`).

- [ ] **Step 3: Write `tests/lab/l75_test.go`**

```go
//go:build lab

package lab

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
	"github.com/rhwendt/port49/internal/testpki"
)

const l75Claim = "spec §15 L75, cell by cell (decision 51: unlocks, TOTP fail-closed, membership's pin, " +
	"back-channel logouts across brokers; decision 47 ruling 5)."

// l75Device is the one device L75's brokers mint for.
const l75Device = "l75-device"

// l75Opts is one host broker's config.
type l75Opts struct {
	i                int
	dir              string // the run's directory
	x                *labDir
	pki              *regionPKI
	session          string   // its session member, host:port
	directory        []string // the directory's endpoints as it reaches them; nil: the members'
	usersCA          string   // the client CA file: carol's and bob's certificates
	issuer, issuerCA string   // (g)'s provider
	provider         bool     // (g): the oidc verifier in place of directory_password
}

// l75BrokerYAML is port49-broker.yaml for one host broker: L74's shape with
// L67's directory, an identity per l75Opts.provider, and stores whose
// directory is L74's (through o.directory when set).
func l75BrokerYAML(o l75Opts) string {
	state := filepath.Join(o.dir, fmt.Sprintf("b%d-state", o.i))
	os.Mkdir(state, 0o700)
	human := `      - type: directory_password
        principal_domains: [corp.example.com]
        second_factor: totp
`
	if o.provider {
		human = fmt.Sprintf(`      - type: oidc
        issuer: %s
        client_id: port49-cli
        principal_claim: email
        principal_domains: [corp.example.com]
        ca_file: %s
`, o.issuer, o.issuerCA)
	}
	stores := regionStoresYAML(o.pki, "broker", o.session)
	if o.directory != nil {
		var members []string
		for i := 1; i <= 3; i++ {
			members = append(members, "https://"+regionIP(i)+":2379")
		}
		var via []string
		for _, ep := range o.directory {
			via = append(via, "https://"+ep)
		}
		stores = strings.Replace(stores, strings.Join(members, ", "), strings.Join(via, ", "), 1)
	}
	return fmt.Sprintf(`metrics_listen: "127.0.0.1:0"
inventory_file: %[1]s/l75-inventory.yaml
key_refs: [k]
encryption:
  current: {id: l74, secret_env: L74_ENC_KEY}
admin_socket: %[1]s/b%[2]d.sock
broker:
  listen: "127.0.0.1:0"
  tls_cert_file: %[3]s
  tls_key_file: %[4]s
  policy_file: %[1]s/l75-policy.yaml
  state_dir: %[5]s
  policy_watch_interval: 5s
  certificate_status: {disabled: true}
  identity:
    humans:
      - {type: x509, trust_anchor_file: %[6]s}
%[7]s    issuance: {}
  directory:
    servers:
      - {uri: "ldaps://%[8]s", priority: 100, site: lab}
    site: lab
    ca_file: %[9]s
    bind:
      mechanism: simple
      bind_dn: "%[10]s"
      password_env: LAB_DIRECTORY_BIND_PASSWORD
    base_dn: "%[11]s"
    groups_base_dn: "%[12]s"
    user_filter: "%[13]s"
    group_filter: "%[14]s"
    principal_attribute: mail
    username_attribute: %[15]s
    nested_groups: direct
    grace: 4h
`, o.dir, o.i, filepath.Join(o.pki.lab, testpki.LabServerCert), filepath.Join(o.pki.lab, testpki.LabServerKey), state,
		o.usersCA, human, l67HostPort(o.x.uri), o.x.d.pki.caFile, o.x.bindDN, o.x.baseDN, o.x.groupsBaseDN,
		o.x.userFilter, o.x.groupFilter, o.x.usernameAttr) + stores
}

func l75Policy() string {
	return `scopes:
  - {name: all, match: {}}
roles:
  - {name: admin, privilege: admin, permit: ["**"]}
subjects:
  - {name: carol, identity: ["user:carol@corp.example.com"], username: carol, token_ttl: 900s}
  - {name: bob, identity: ["user:bob@corp.example.com"], username: bob, token_ttl: 900s}
grants:
  - {subject: carol, scope: all, roles: [admin]}
  - {subject: bob, scope: all, roles: [admin]}
key_groups:
  - {match: {cidr: 127.0.0.0/8}, key_ref: k}
`
}

// l75Broker is one host broker: its session member, its process, and for
// b3 the proxies that are its way to the directory.
type l75Broker struct {
	o       l75Opts
	cfg     string
	sess    *regionEtcd
	proc    *regionProc
	proxies []*etcdtest.Proxy
}

// l75Listening is port49-broker's line once its API serves.
var l75Listening = regexp.MustCompile(`port49-broker: listening on (127\.0\.0\.1:\d+)`)

// addr is the API address the broker's last start said.
func (b *l75Broker) addr() string {
	m := l75Listening.FindStringSubmatch(b.proc.said())
	if m == nil {
		return ""
	}
	return m[1]
}

func (b *l75Broker) sock() string { return filepath.Join(b.o.dir, fmt.Sprintf("b%d.sock", b.o.i)) }

// hang cuts b3 from the directory (or heals it), and waits for its line.
func (b *l75Broker) hang(t *testing.T, on bool) {
	t.Helper()
	for _, p := range b.proxies {
		p.Hang(on)
	}
	want := "directory store: not answering"
	if !on {
		want = "directory store: answering again"
	}
	if _, err := b.proc.wait(want, 30*time.Second); err != nil && !on {
		t.Fatalf("INVALID: %v", err)
	}
}

// start writes the config, starts the broker and waits until its mints are open.
func (b *l75Broker) start(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(b.cfg, []byte(l75BrokerYAML(b.o)), 0o600); err != nil {
		t.Fatal(err)
	}
	b.proc.start(t)
	for deadline := time.Now().Add(120 * time.Second); !l67MintsOpen(b.proc.said()); time.Sleep(500 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("INVALID: %s's mints did not open within 120s: %s", b.proc.name, lastLine(b.proc.said()))
		}
	}
}

// l75Client is an HTTP client trusting the lab API's CA, with cert when given.
func l75Client(pki *regionPKI, cert *tls.Certificate) *http.Client {
	caPEM, _ := os.ReadFile(filepath.Join(pki.lab, testpki.LabCA))
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	tc := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	if cert != nil {
		tc.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: tc}}
}

// l75Mint is one mint at addr for l75Device, by the client's certificate or
// by bearer, and its status and error code; a token it returns is held.
func l75Mint(w *regionWorld, c *http.Client, addr, bearer string) (int, string) {
	req, err := http.NewRequest(http.MethodPost, "https://"+addr+"/v1/tokens",
		strings.NewReader(`{"devices":["`+l75Device+`"]}`))
	if err != nil {
		return 0, "request"
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, "unreachable"
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusOK {
		var out api.MintResponse
		if json.Unmarshal(raw, &out) == nil {
			for _, r := range out.Results {
				if r.Login != "" {
					w.hold(r.Login)
				}
			}
		}
		return resp.StatusCode, ""
	}
	var e api.Error
	_ = json.Unmarshal(raw, &e)
	return resp.StatusCode, e.Error
}

// l75LogoutClaims is a back-channel logout token's claims for session sid.
func l75LogoutClaims(iss, client, sid, jti string, now time.Time) map[string]any {
	return map[string]any{"iss": iss, "aud": client, "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
		"jti": jti, "sid": sid, "events": map[string]any{oidc.BackchannelLogoutEvent: map[string]any{}}}
}

// l75Logout posts a logout token to addr's /v1/logout, form-encoded with
// no client certificate, as a provider does, and returns the status.
func l75Logout(c *http.Client, addr, token string) int {
	resp, err := c.Post("https://"+addr+"/v1/logout", "application/x-www-form-urlencoded",
		strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

func l75Random(t *testing.T) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// l75 runs L75's cells on three host brokers sharing w's directory, and
// writes its note.
func l75(t *testing.T, w *regionWorld) {
	pw, err := l67Password()
	if err != nil {
		t.Fatal(err)
	}
	w.hold(pw)
	sec := &l67Secrets{}
	w.leaks = append(w.leaks, sec.leaksIn)
	d := startDirectoriesWith(t, l67Prepare(pw))
	w.hold(d.password)

	// The client CA: carol's and bob's certificates, never written but
	// the CA's file.
	now := time.Now()
	users, err := testpki.NewCA("L75 users CA", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	usersCA := filepath.Join(w.dir, "l75-users-ca.pem")
	if err := os.WriteFile(usersCA, users.PEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	certOf := func(name string) *tls.Certificate {
		c, err := users.Issue(testpki.Leaf{CommonName: name, Emails: []string{name + "@corp.example.com"}, Client: true,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		return &c
	}
	carolCert, bobCert := certOf("carol"), certOf("bob")
	iss := oidctest.NewIssuer(t)
	issCA := filepath.Join(w.dir, "l75-issuer-ca.pem")
	if err := os.WriteFile(issCA, iss.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"l75-policy.yaml": l75Policy(),
		"l75-inventory.yaml": "devices:\n  - {name: " + l75Device + ", platform: arista_eos, addresses: [127.0.0.1]}\n"} {
		if err := os.WriteFile(filepath.Join(w.dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var bs [4]*l75Broker
	env := append(w.env(), localBrokerEnv("")...)
	env = append(env, "LAB_DIRECTORY_BIND_PASSWORD="+d.password)
	for i := 1; i <= 3; i++ {
		client, peer := freeAddr(t), freeAddr(t)
		s := &regionEtcd{name: fmt.Sprintf("l75s%d", i), bin: w.etcdBin, client: client, peer: peer,
			cluster: fmt.Sprintf("l75s%d=http://%s", i, peer), data: filepath.Join(w.dir, fmt.Sprintf("l75s%d.etcd", i)),
			log: filepath.Join(w.dir, fmt.Sprintf("l75s%d.log", i)), pki: w.pki}
		s.start(t)
		o := l75Opts{i: i, dir: w.dir, x: d.openldap, pki: w.pki, session: client, usersCA: usersCA,
			issuer: iss.URL, issuerCA: issCA}
		b := &l75Broker{o: o, cfg: filepath.Join(w.dir, fmt.Sprintf("b%d.yaml", i)), sess: s}
		if i == 3 {
			for m := 1; m <= 3; m++ {
				p := etcdtest.NewProxy(t, regionIP(m)+":2379")
				b.proxies = append(b.proxies, p)
				b.o.directory = append(b.o.directory, p.Addr())
			}
		}
		b.proc = &regionProc{name: fmt.Sprintf("port49-broker l75 b%d", i), bin: w.broker, cfg: b.cfg,
			log: filepath.Join(w.dir, fmt.Sprintf("l75-b%d.log", i)), env: env}
		bs[i] = b
	}
	for i := 1; i <= 3; i++ {
		for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(500 * time.Millisecond) {
			if _, err := bs[i].sess.ctl("https://"+bs[i].sess.client, "endpoint", "health"); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("INVALID: L75's session member %d did not answer within 60s", i)
			}
		}
		// Roles for the session member alone: the directory's were made by L74.
		if err := os.WriteFile(bs[i].cfg, []byte(l75BrokerYAML(bs[i].o)), 0o600); err != nil {
			t.Fatal(err)
		}
		stub := filepath.Join(w.dir, fmt.Sprintf("b%d-port49d.yaml", i))
		if err := os.WriteFile(stub, []byte(strings.Replace(w.daemonYAML(1), regionSessionClient, bs[i].sess.client, 1)),
			0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(w.port49d, "store-roles", "--config", stub, "--broker-config", bs[i].cfg).CombinedOutput()
		if err != nil {
			t.Fatalf("INVALID: port49d store-roles for L75 b%d: %v\n%s", i, err, out)
		}
		s := bs[i].sess
		applyRoles(t, string(out), map[string]func(args ...string) (string, error){
			"session": func(args ...string) (string, error) { return s.ctl("https://"+s.client, args...) }})
		cmd := exec.Command(w.broker, "init-issuer", "--config", bs[i].cfg)
		cmd.Env = append(os.Environ(), env...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("INVALID: port49-broker init-issuer for b%d: %v: %s", i, err, oneLineMax(string(out), 400))
		}
		bs[i].start(t)
		t.Cleanup(bs[i].proc.stop)
	}
	if out, code, _ := w.port49("directory", "init-enrollments", "--socket", bs[1].sock()); code != 0 {
		t.Fatalf("INVALID: init-enrollments: exit %d: %s", code, oneLineMax(out, 300))
	}
	apiOf := func(b *l75Broker) *l67API {
		a, err := newL67API("https://"+b.addr(), filepath.Join(w.pki.lab, testpki.LabCA))
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	unlock := func(at *l75Broker) (string, int, time.Duration) {
		return w.port49("directory", "unlock", "--socket", at.sock(), "user:carol@corp.example.com")
	}

	// Carol enrolls at b1: a sign-in with no code answers 202 and the
	// secret, and her first code confirms it (L67's flow).
	a1 := apiOf(bs[1])
	ans := a1.signIn("carol", pw, "")
	if ans.Status != http.StatusAccepted || ans.Enroll == nil {
		t.Fatalf("INVALID: enrolling carol at b1: %d %s", ans.Status, ans.Error)
	}
	secret, err := l67SecretOf(ans.Enroll.URI)
	if err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	sec.addSecret(secret)
	carol := &l67Person{name: "carol", secret: secret, rec: sec}
	if conf := a1.confirm(ans.Enroll.Handle, carol.code()); conf.Status != http.StatusOK {
		t.Fatalf("INVALID: confirming carol's enrollment: %d %s", conf.Status, conf.Error)
	}
	if _, code, _ := unlock(bs[1]); code != 0 {
		t.Fatal("INVALID: unlocking carol after her enrollment")
	}

	var rows []regionRow
	row := func(id, claim, observed string, agrees bool) {
		rows = append(rows, regionRow{ID: id, Claim: claim, Observed: observed, Agrees: agrees})
	}

	// (a) one code at b1, then the same code at b2.
	w.guard()
	code := carol.code()
	r1 := a1.signIn("carol", pw, code)
	r2 := apiOf(bs[2]).signIn("carol", pw, code)
	row("a", "a code signed in at broker 1 is refused at broker 2 within its step",
		fmt.Sprintf("broker 1: %d; broker 2, the same code: %d %s", r1.Status, r2.Status, r2.Error),
		r1.Status == http.StatusOK && r2.Status == http.StatusUnauthorized)

	// (b) twenty steps: one code to b1 and b2 at once.
	w.guard()
	one := 0
	var pairs []string
	for n := 0; n < 20; n++ {
		code := carol.code()
		var s1, s2 l67Answer
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); s1 = apiOf(bs[1]).signIn("carol", pw, code) }()
		go func() { defer wg.Done(); s2 = apiOf(bs[2]).signIn("carol", pw, code) }()
		wg.Wait()
		if (s1.Status == http.StatusOK) != (s2.Status == http.StatusOK) {
			one++
		}
		pairs = append(pairs, fmt.Sprintf("%d/%d", s1.Status, s2.Status))
	}
	row("b", "one code sent to brokers 1 and 2 at once, twenty steps: pairs with exactly one 200",
		fmt.Sprintf("%d of 20: %s", one, strings.Join(pairs, " ")), one == 20)
	unlock(bs[1])

	// (c) locked out at b2 by wrong codes, unlocked at b1, judged afresh at b2.
	w.guard()
	wrongs := func(b *l75Broker) int {
		for n := 1; n <= 20; n++ {
			c, err := l67WrongCode(carol.secret, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			sec.addCode(c)
			if apiOf(b).signIn("carol", pw, c).Status == http.StatusTooManyRequests {
				return n
			}
		}
		return -1
	}
	lockedAt := wrongs(bs[2])
	_, ucode, _ := unlock(bs[1])
	c3 := apiOf(bs[2]).signIn("carol", pw, carol.code())
	row("c", "locked out at broker 2, unlocked at broker 1: broker 2's next sign-in is judged",
		fmt.Sprintf("broker 2 refused after %d wrong code(s); unlock at broker 1 exit %d; broker 2's next sign-in %d",
			lockedAt, ucode, c3.Status), lockedAt > 0 && ucode == 0 && c3.Status == http.StatusOK)

	// (d) the counts are per broker.
	w.guard()
	var counts []string
	sum := 0
	for i := 1; i <= 3; i++ {
		n := wrongs(bs[i])
		counts = append(counts, fmt.Sprintf("broker %d: %d", i, n))
		sum += max(n-1, 0)
	}
	row("d", "the attempt counts are per broker: failures each takes before it refuses, and the total across three",
		fmt.Sprintf("%s; %d failures in all", strings.Join(counts, ", "), sum), sum > 0)
	unlock(bs[1])

	// (e) b3 cut from the directory: a password sign-in, an unlock and a
	// reset are each refused, promptly.
	w.guard()
	bs[3].hang(t, true)
	start := time.Now()
	e1 := apiOf(bs[3]).signIn("carol", pw, carol.code())
	t1 := time.Since(start)
	o2, c2, t2 := unlock(bs[3])
	o3, c3e, t3 := w.port49("directory", "reset-second-factor", "--socket", bs[3].sock(), "user:carol@corp.example.com")
	bs[3].hang(t, false)
	row("e", "broker 3 cut from the directory: a password sign-in 503 store_unavailable; unlock and "+
		"reset-second-factor refused; how long each took",
		fmt.Sprintf("sign-in %d %s in %v; unlock exit %d in %v: %s; reset exit %d in %v: %s", e1.Status, e1.Error,
			t1.Round(time.Millisecond), c2, t2.Round(time.Millisecond), firstLine(o2), c3e, t3.Round(time.Millisecond),
			firstLine(o3)),
		e1.Status == http.StatusServiceUnavailable && e1.Error == "store_unavailable" && c2 != 0 && c3e != 0)

	// (f) membership's pin across brokers (R13).
	w.guard()
	d1 := w.dirMembers[1]
	pinKey := "/port49/v1/mb/user:carol@corp.example.com" // esc() is url.PathEscape, which keeps : and @
	pinRev := func() int64 {
		js, _ := d1.ctl(w.dirEndpoints(), "get", pinKey, "-w", "json")
		var r struct {
			Kvs []struct {
				ModRevision int64 `json:"mod_revision"`
			} `json:"kvs"`
		}
		if json.Unmarshal([]byte(js), &r) != nil || len(r.Kvs) == 0 {
			return 0
		}
		return r.Kvs[0].ModRevision
	}
	carolC, bobC := l75Client(w.pki, carolCert), l75Client(w.pki, bobCert)
	m1, _ := l75Mint(w, carolC, bs[2].addr(), "")
	rev1 := pinRev()
	_, fcode, _ := w.port49("directory", "forget", "--socket", bs[1].sock(), "user:carol@corp.example.com")
	time.Sleep(2 * time.Second) // b2's pins feed delivers the forget
	m2, _ := l75Mint(w, carolC, bs[2].addr(), "")
	rev2 := pinRev()
	bs[3].hang(t, true)
	_, f3, ft3 := w.port49("directory", "forget", "--socket", bs[3].sock(), "user:carol@corp.example.com")
	m3, _ := l75Mint(w, carolC, bs[3].addr(), "")
	cached := strings.Contains(bs[3].proc.said(), "serving user:carol@corp.example.com's cached directory membership")
	mb, mbErr := l75Mint(w, bobC, bs[3].addr(), "")
	bs[3].hang(t, false)
	row("f", "membership's pin: written once in the directory; a forget at broker 1 re-pins at broker 2's next "+
		"mint; with broker 3 cut, a forget there refused, a pinned member served from the cached pin and said, "+
		"a first bind refused",
		fmt.Sprintf("mint at b2 %d, pin revision %d; forget at b1 exit %d; next mint at b2 %d, pin revision %d; cut: "+
			"forget at b3 exit %d in %v; carol's mint at b3 %d (said %v); bob's first mint at b3 %d %s",
			m1, rev1, fcode, m2, rev2, f3, ft3.Round(time.Millisecond), m3, cached, mb, mbErr),
		m1 == http.StatusOK && rev1 > 0 && fcode == 0 && m2 == http.StatusOK && rev2 > rev1 && f3 != 0 &&
			m3 == http.StatusOK && cached && mb != http.StatusOK)

	// (g) back-channel logouts across brokers (R26), with the provider identity.
	w.guard()
	for i := 1; i <= 3; i++ {
		bs[i].proc.stop()
		bs[i].o.provider = true
		bs[i].start(t)
	}
	plain := l75Client(w.pki, nil)
	idToken := func(sid string) string {
		tok := iss.IDToken(t, "k1", "port49-cli", "sub-carol", time.Now(),
			map[string]any{"email": "carol@corp.example.com", "email_verified": true, "sid": sid})
		w.hold(tok)
		return tok
	}
	logoutToken := func(sid string) string {
		tok := iss.TokenWith(t, "k1", map[string]any{"kid": "k1", "typ": "logout+jwt"},
			l75LogoutClaims(iss.URL, "port49-cli", sid, l75Random(t), time.Now()))
		w.hold(tok)
		return tok
	}
	refusedWithin := func(b *l75Broker, tok string, d time.Duration) (time.Duration, string) {
		start := time.Now()
		for time.Since(start) < d {
			if st, e := l75Mint(w, plain, b.addr(), tok); st == http.StatusUnauthorized {
				return time.Since(start), e
			}
			time.Sleep(200 * time.Millisecond)
		}
		return d, "not refused"
	}
	s1 := "l75-g-" + l75Random(t)
	tok1 := idToken(s1)
	g1, _ := l75Mint(w, plain, bs[2].addr(), tok1)
	lo1 := l75Logout(plain, bs[1].addr(), logoutToken(s1))
	took, why := refusedWithin(bs[2], tok1, 30*time.Second)
	line, _ := bs[2].proc.wait("a logout made elsewhere", 30*time.Second)
	row("g", "a logout received at broker 1 refuses broker 2's mint for that session",
		fmt.Sprintf("mint at b2 %d; logout at b1 %d; b2 refused after %v (%s); b2's runner line after %v: %s",
			g1, lo1, took.Round(10*time.Millisecond), why, line.Round(10*time.Millisecond),
			firstLineWith(bs[2].proc.said(), "a logout made elsewhere")),
		g1 == http.StatusOK && lo1 == http.StatusOK && why == "credential_revoked")

	w.guard()
	s2 := "l75-g-" + l75Random(t)
	tok2 := idToken(s2)
	g2, _ := l75Mint(w, plain, bs[1].addr(), tok2)
	bs[3].hang(t, true)
	lo3 := l75Logout(plain, bs[3].addr(), logoutToken(s2))
	r3, why3 := l75Mint(w, plain, bs[3].addr(), tok2)
	status, scode, _ := w.port49("store", "status", "--socket", bs[3].sock())
	b1st, _ := l75Mint(w, plain, bs[1].addr(), tok2)
	healed := time.Now()
	bs[3].hang(t, false)
	_, ferr := bs[3].proc.wait("pending back-channel logout(s) forwarded", 30*time.Second)
	_, why2 := refusedWithin(bs[1], tok2, 30*time.Second)
	fromHeal := time.Since(healed)
	row("g2", "with broker 3 cut, a logout there is answered 200, refused there at once and pending; broker 1 "+
		"mints for it until the heal, then refuses",
		fmt.Sprintf("mint at b1 %d; logout at b3 %d; b3's mint %d %s; status exit %d: %s; b1's mint during the cut %d; "+
			"forwarded line %v; b1 refused %v after the heal (%s)", g2, lo3, r3, why3, scode,
			strings.ReplaceAll(status, "\n", " / "), b1st, ferr == nil, fromHeal.Round(10*time.Millisecond), why2),
		g2 == http.StatusOK && lo3 == http.StatusOK && r3 == http.StatusUnauthorized &&
			strings.Contains(status, "1 logouts pending") && scode == 3 && b1st == http.StatusOK && ferr == nil &&
			why2 == "credential_revoked")

	var procs []*regionProc
	for i := 1; i <= 3; i++ {
		procs = append(procs, bs[i].proc)
	}
	writeRegionNote(t, w, "L75", l75Claim, rows, []string{
		"the brokers run on the host, not in the namespaces: OpenLDAP's ports are published on the host's loopback alone",
		"Keycloak's own sending of a logout, and that it does not retry a 503: L45's; (g) signs its logout tokens with an in-process provider",
	}, procs)
}
```

In `tests/lab/l74_test.go`'s `TestRegions`, after `writeRegionNote(…"L74"…)`, add:

```go
	guard()
	l75(t, w)
```

(`brokerListening` in `localbroker_test.go` matches port49d's "broker listening on" line, not
port49-broker's, so `l75Listening` is its own.)

- [ ] **Step 4: Run the unit tests and vet**

Run: `go test -tags lab ./tests/lab/ -run '^TestL75' -count=1 && go vet -tags lab ./tests/lab/... && make lab-unit`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/lab/l75_test.go tests/lab/l74_test.go tests/lab/l74_unit_test.go
git commit -m "test: the L75 harness: three host brokers on one directory, cell by cell

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 15: The lab runs, and L74 and L75 closed

**Files:**
- Create: `tests/lab/results/L74-regions.md`, `tests/lab/results/L75-regions.md`,
  `tests/lab/evidence/L74-regions/` and `tests/lab/evidence/L75-regions/` (the host brokers' logs),
  from the run
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§15 rows L74, L75)

**Interfaces:**
- Consumes: Tasks 14 and 14a's harness, run on beehive.
- Produces: the two notes; the rows closed (or left open, saying which cells are not measured).

- [ ] **Step 1: Prepare the run**

On beehive:
1. Check that no other lab run holds the host: single occupant.
2. Make a detached worktree at the branch's head, under `.worktrees/`:
   `git worktree add --detach .worktrees/l74-run HEAD`.
3. Check that `/tmp/port49-STOP-LAB` is absent and that 10.149.0.0/24 is free (`ip -4 route`).
4. Arm a background stall watchdog (`sleep 900; echo WATCHDOG`), and re-arm it on every wake.

- [ ] **Step 2: Run**

Run (in `.worktrees/l74-run`): `PORT49_LAB_ETCD_BIN=<dir> make lab-regions 2>&1 | tee /tmp/claude-1000/l74-run.log`

Expected: PASS, writing `tests/lab/results/L74-regions.md` and `L75-regions.md`.
- An INVALID fatal writes no note. Fix the setup, and run again.
- A row with **no** in "agrees" is a measurement: keep it. Where it contradicts a doc, the doc is
  wrong (Step 3).

- [ ] **Step 3: Read the notes against the claims**

For each row, read the observation against decision 51:
- Every row agrees: go on to Step 4.
- A row disagrees: the doc is wrong. Fix decision 51's text, the design's §13 paragraph or the
  operator notes, cite the note, and say so in the commit message ("L74 (d) contradicts ruling R17's
  …; the doc follows the measurement").
- A cell could not be measured: it is listed under "Not measured here". The row stays open, and
  Step 4 says which cells.

- [ ] **Step 4: Close the rows**

In spec §15, edit each row's Status to
`closed — measured <date>; tests/lab/results/L74-regions.md` (and `L75-regions.md`), followed by one
sentence per cell with its number. For example: "(b) region 2 denied 0.31s and region 3 0.29s after
the revocation; (c) …". This follows the L72 row's style.

The run's worktree is detached, so its notes and evidence are copied into the
`feature/directory-and-session-stores` checkout, where this commit is made, before the worktree is
removed (the pre-flight's minor 14; the labpcap audit fails if the evidence is missing):

```bash
cp .worktrees/l74-run/tests/lab/results/L7[45]-regions.md tests/lab/results/
cp -r .worktrees/l74-run/tests/lab/evidence/L74-regions .worktrees/l74-run/tests/lab/evidence/L75-regions tests/lab/evidence/
```

Each note's Capture line names its own evidence directory (`regionNote`), and L75's holds the three
host brokers' logs, filtered of every held secret.

```bash
git add tests/lab/results/L74-regions.md tests/lab/results/L75-regions.md tests/lab/evidence/L74-regions \
  tests/lab/evidence/L75-regions docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: close lab register entries L74 and L75

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 5: Remove the worktree**

Run: `git worktree remove .worktrees/l74-run`

Run: `ip netns list | grep p49r; ip link show p49rbr0`
Expected: nothing. The harness's cleanup removed the network.

---

### Task 16: The roadmap's record and the carries

**Files:**
- Modify: `docs/superpowers/plans/README.md` (the status paragraph; "Plan 11a"; "Plan 12"; "Plan 13")

**Interfaces:**
- Consumes: everything above.
- Produces: "Plan 11a — As built", and what plans 12 and 13 inherit.

- [ ] **Step 1: Write "Plan 11a — As built"**

Under "## Plan 11a — Directory and session stores", replace its Status line with:
`Status: **executed <date>** (\`2026-10-17-11a-directory-and-session-stores.md\`, branch
\`feature/directory-and-session-stores\`; twenty-two tasks; decision 51; L74 and L75 closed or open
as Task 15 left them)`.

Then add "### Plan 11a — As built", written as Plan 11's is, with:
- what was built, by task, with the commit IDs;
- the rulings as recorded, and any that a review or a lab result changed, with the reason;
- Q1 as ruled (R26, the team lead under standing autonomy, Ryan may overrule), and whether Ryan
  overruled it;
- L74's and L75's results, in a sentence each;
- "Carried forward", the list in Step 2.

- [ ] **Step 2: Carry forward**

Add to "## Plan 12 — Deployment":

```markdown
**Carried from plan 11a** (decision 51):
- Every shape ships a single-site example (`stores.directory` alone) and a multi-region one
  (`stores.directory` stretched one member per region, `stores.session` per region), each with
  `port49d store-roles` run once per cluster. On Kubernetes the stretched directory etcd is three
  StatefulSets (one per cluster) joined across clusters, or VMs; the session etcd is a
  StatefulSet per cluster. Neither is required; systemd and containers are peers.
- The failure matrix includes the cut region (L74): devices keep logging in; directory writes and
  password sign-in refused; `port49 store status` exits 3.
- Alarms: `port49_store_directory_reachable == 0` for 1m (a region cut from the directory: its
  revocations do not arrive); `time() - port49_store_directory_confirmed_timestamp_seconds > 60`
  (the cache is stale, whatever the reason); `port49_store_logouts_pending > 0` for 5m (a cut region
  holds logouts the other regions have not seen); `port49_store_feed_up{feed="marks"} == 0` as
  before.
- The same `encryption:` key material in every region, from one secret, and the three-step
  rotation (R27) as a runbook.
- Backups: each cluster its own. The directory etcd's snapshot (with `port49 directory export` from
  cron beside it, under `umask 077`) and each region's session etcd's snapshot; Velero for a
  Kubernetes-hosted etcd's volumes. One example of each in the operator notes.
- `stores.directory.etcd.call_timeout` sized to the directory's cross-region round trip, and the
  load test's numbers for the directory's reads at a sign-in.
```

Add to "## Plan 13 — User and admin documentation", under **Inherits**: "From plan 11a: a
'Stores' page:
- the two roles, and what each holds;
- the single-site and multi-region recipes;
- a cut region at 3am (the plan's 3am table);
- `port49 store status`;
- `port49 directory forget` in a split (one forget reaches every region; refused during a cut);
- a back-channel logout's reach in every region (R26), and the pending logouts of a cut region;
- a restart during a cut: the snapshot and its ceiling (R19);
- one set of encryption keys everywhere, and the three-step rotation (R27);
- no migration from one store to two: a split starts on fresh stores (R25)."

In the same file, update every forward-looking mention of the removed keys under Plan 12 and Plan
13 (not the historical "As built" sections) by Task 1's table.

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/plans/README.md
git commit -m "docs: plan 11a's record, and what plans 12 and 13 inherit from it

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

## Operator notes (for the pull request body)

- **`stores:` replaces `store:`.** port49 keeps its records in two stores, named by function:
  - `stores.directory`: revocation marks, second factors (with the TOTP used step), the enrollment
    mark, unlocks, back-channel logout records, and directory membership's pins. Written rarely,
    agreed everywhere, and watched and cached by every process.
  - `stores.session`: tokens, login contexts, receipts, attempt counts, membership freshness, and
    everything else.

  Each block takes the old shape: `backend`, `packet_deadline`, `etcd:`. The top-level `store:` key
  and `broker.directory.enrollment_store` are removed, not deprecated: a file that still names
  either is refused as an unknown key (`config: line N: an unknown field`).
- **Single site:** move the old `store:` block under `stores:` as `directory:`, and omit `session:`.
  The session store is then the directory store: one etcd, today's roles, today's behaviour.

  `port49d.yaml`:
  ```yaml
  stores:
    directory:
      backend: etcd
      packet_deadline: 1s
      etcd:
        endpoints: [https://etcd-0.example.net:2379, https://etcd-1.example.net:2379, https://etcd-2.example.net:2379]
        ca_file: /etc/port49/etcd-ca.pem
        prefix: /port49/
        daemon: {cert_file: /etc/port49/etcd-daemon.pem, key_file: /etc/port49/etcd-daemon-key.pem}
  ```
  `port49-broker.yaml`: the same block with
  `broker: {cert_file: /etc/port49/etcd-broker.pem, key_file: /etc/port49/etcd-broker-key.pem}` in
  place of `daemon:`.
- **Several regions:** one etcd stretched across the regions as `stores.directory` (one member per
  region; three or five), and an etcd per region as `stores.session`. In region `us-east`:

  `port49d.yaml`:
  ```yaml
  stores:
    directory:                     # the same in every region
      backend: etcd
      etcd:
        endpoints: [https://dir.us-east.example.net:2379, https://dir.eu-west.example.net:2379, https://dir.ap-south.example.net:2379]
        ca_file: /etc/port49/directory-ca.pem
        prefix: /port49/
        daemon: {cert_file: /etc/port49/directory-daemon.pem, key_file: /etc/port49/directory-daemon-key.pem}
        call_timeout: 1s           # sized to the cross-region round trip
    session:                       # this region's own
      backend: etcd
      packet_deadline: 1s
      etcd:
        endpoints: [https://sess-0.us-east.example.net:2379, https://sess-1.us-east.example.net:2379, https://sess-2.us-east.example.net:2379]
        ca_file: /etc/port49/session-ca.pem
        prefix: /port49/
        daemon: {cert_file: /etc/port49/session-daemon.pem, key_file: /etc/port49/session-daemon-key.pem}
  ```
  `port49-broker.yaml`: the same two blocks with `broker:` identities in place of `daemon:`. A
  directory block of its own takes `endpoints`, `ca_file`, `prefix`, `daemon`, `broker`, `roles`,
  `call_timeout`, `bulk_timeout` and `start_timeout` alone; `packet_deadline` and the session tuning
  keys go under `stores.session`.
  - `port49d store-roles` prints one section per cluster. Run the directory's section **once**,
    against the directory cluster, not once per region; run each region's session section against
    that region's cluster.
  - Each region's port49-broker.yaml lists its own region's Kubernetes clusters.
- **One set of encryption keys everywhere.** The directory's records are sealed with the writing
  broker's `encryption:` key, and every region opens and re-seals them. Give every port49d and
  port49-broker in every region the same `encryption:` block and key material, from the same secret
  in each region's secret store. A process whose keys cannot open the directory does not start:
  `crypt: the directory store (etcd …, prefix /port49/) was last written by a process whose current
  key is "k2", which this configuration does not hold`. Rotate in three steps: (1) every region gets
  the new key as `encryption.previous`; (2) every region makes it `encryption.current`, the old one
  `previous`; (3) once the re-seal line says nothing is left under the old key, retire it everywhere.
- **A region cut off from the directory:**
  - It keeps verifying devices from its session store and its cached revocations. It says so
    ("directory store: not answering … serving from the cache").
  - `port49_store_directory_reachable` reads 0, and
    `port49_store_directory_confirmed_timestamp_seconds` stops moving.
  - It refuses revocations, lifts, enrollments, unlocks, second-factor resets, forgets, first binds
    and password sign-in (503 `store_unavailable`).
  - A revocation made elsewhere during the cut reaches it only when the cut heals. To cut someone
    off there before then, remove their grants from the policy file, or stop port49d in that region.
  - A lift made elsewhere during a cut longer than the directory's compaction, or while a broker was
    down, is put back by that region's runner. Lift it again.
  - **A process restarted during the cut serves from its region's snapshots** (every process writes
    its marks to its session store each minute while it reaches the directory; port49d serves the
    union of every one, and cannot touch a broker's), and says how old they are. A key or cluster
    fault found when the directory answers again ends the process, exit 1.
    It serves until the snapshot is `session.staleness_ceiling` old (4h by default), then fails
    closed: port49d closes its listeners, port49-broker refuses mints and sign-ins. With no
    snapshot that young (a new region), a restarted process stays dark until the directory answers.
  - A runner that takes over during the cut runs every session duty; the put-back of `marks.json`
    and the forwarding of pending logouts wait for the directory.
- **`port49 store status [--socket PATH]`:** each store as port49d (or port49-broker) sees it: the
  backend, `answering/listed members`, reachable or not, the directory cache's age (`(snapshot)`
  while a restarted process serves one), and `N logouts pending`. It exits 3 when a store does not
  answer.
- **Unlocks reach every region:** `port49 directory unlock` writes a directory record, and every
  region's attempt count starts again. Its record's `failures` is the count in the region that
  answered.
- **`port49 directory forget` reaches every region:** a directory membership's pin is a directory
  record with no expiry, its groups and `verified_at` a per-region one. A forget fails closed in a
  cut region, and so does a first bind there; a member already pinned keeps working, and the broker
  says it served the cached pin.
- **Per-region:**
  - An enrollment is confirmed in the region that started it.
  - A kept per-login MFA proof is reused only in its own region.
- **A back-channel logout ends the session in every region:** its record is the directory's, and
  each broker checks mints and refreshes against its own followed copy. With the directory cut, the
  broker accepts the logout, applies it in its own region at once, and keeps it pending; its runner
  forwards it to the directory on the heal, and then every region refuses.
- **No migration from one store to two.** port49 is pre-beta: a split starts on fresh stores (a new
  directory etcd, and a new session etcd per region); no old etcd becomes either. Enrollments can be
  carried with `port49 directory export` and `import`, as between any two stores.
- **After restoring the directory etcd:** a restore from a snapshot older than a
  `port49 directory forget` brings the forgotten pin back, so the re-created entry is refused again
  (`… is pinned to entry … and is now claimed by …`; fail closed). Run each such forget again from
  any region. The runners put back the marks their `marks.json` holds (a lift made since the
  backup comes back too; lift it again).
- **Backups:**
  - The directory etcd: an etcd snapshot, with `port49 directory export` from cron beside it, for
    example `0 * * * * umask 077; port49 directory export --socket /run/port49/port49-broker.sock > /var/backups/port49/enrollments.$(date +\%H).p49`.
  - Each session etcd: its own snapshot.
  - A Kubernetes-hosted etcd: Velero for its volumes.
- **New metrics:** `port49_store_directory_reachable`,
  `port49_store_directory_confirmed_timestamp_seconds` and `port49_store_logouts_pending`, none with
  a label. `port49_store_client_cert_expiry_timestamp_seconds` gains the components
  `daemon_directory` and `broker_directory` with two stores. No new reason code.
