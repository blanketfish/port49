# Pre-beta Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix every Critical and Important finding of the pre-beta review (main `c0ad3498`, 2026-11-05), and the Minors and carried items triaged below, before plan 13 and the `v0.1.0` beta.

**Architecture:**
- **The restore guard goes.** A per-token revision floor replaces it (Task 3).
  - A token key's etcd `CreateRevision` says when it was written. A restored token has one at or below the drop read's header, and a token minted after that read has a higher one.
  - So port49d refuses only the restored tokens, `token_spent` (FAIL), and never takes the global refusal, the scan, the time bound or the purge-lifts case.
  - port49d keeps its witness record and its floor in a file beside the accounting spool, so the floor survives a restart.
- **The runner's restore purge** also deletes the broker's once-only records (Task 4). The broker's other fixes are in Tasks 6, 8, 16 and 18. The policy fixes are in Tasks 7, 11 and 19.
- **The store guard's 3am traps:**
  - a passing health check closes the token and context circuits (Task 12);
  - a call that arrives with its deadline already spent is not a store failure (Task 13);
  - the remaining 5 s loops take the store wait's schedule (Task 15).
- **Release and go-public work** is in Tasks 20 to 23. The docs follow in Tasks 5, 24 and 25.

**Tech Stack:** Go 1.26, `go.etcd.io/etcd/client/v3`, `github.com/prometheus/client_golang`, `gopkg.in/yaml.v3`, all already in go.mod; no new module. Prometheus `promtool` and gitleaks at their Makefile pins. Python setuptools at `packaging/requirements-release.txt`'s pin.

**Spec:**
- The pre-beta review, in `.superpowers/pre-beta/` (not committed; read in place):
  - the findings files `stores.md`, `identity.md`, `devices.md`, `deploy.md` and `policy.md`;
  - `progress.md`, the controller's rulings, which bind;
  - `brief.md`, the security rules, repeated under Global Constraints.
- `docs/design/2026-08-23-policy-engine-spec.md`:
  - §5.5 (`on_missing`, `security_log`);
  - §5.7 (`store_unavailable`, `token_spent`, `credential_mismatch`);
  - §10 ("Source-of-truth write access is privilege-granting");
  - §13 decisions 35, 36, 37, 43 (ruling 13), 51 and 55 (ruling 15);
  - §15 rows L4, L35, L41, L45, L46, L73, L74, L88 and QUAL.
- `docs/design/2026-08-21-port49-design.md`: §12 (failure model), §13 (the restore runbook), §15 (metrics and alarms).
- `docs/superpowers/plans/README.md`:
  - "Plan 12c — As built": its pre-beta list, operator notes and hand-offs;
  - "Pre-beta review (between plan 12c and plan 13)".

## Global Constraints

- Go 1.26+, module `github.com/blanketfish/port49`, `gofmt` and `go vet` clean, no cgo.
- snake_case everywhere it is data: YAML keys, JSON log keys, config, metric names.
- Reason codes are spec §5.7's closed vocabulary (`internal/decision/reasons.go`). This plan adds none. It widens `token_spent` and `credential_mismatch`, and narrows `store_unavailable`, in the spec table first (Task 1).
- The log never holds a token, password, challenge or response. Credentials appear only as `credential_sha256`. No device identity goes in a metric label.
- **No deprecation pre-beta.** Replaced config, code, metrics, alerts and lines are removed outright: no shim, no alias, no "was removed" message.
- **The lab register rules** (CLAUDE.md): a device claim no closed §15 row covers is removed or marked unmeasured, never asserted. A lab result that contradicts a doc fixes the doc, says so in the commit message, and cites the note.
- **Security rules for every implementer, reviewer and lab runner** (repeat them in every brief):
  - never print credential values, secrets, tokens, keys, passwords, TOTP seeds, PINs, hashes (`$6$`, `$9$`, `$aes1$` stay masked), challenges, responses, nonces or signatures;
  - never decode a TACACS+ body by hand: no tcpdump or tshark payload flags, and no hex dumps of pcaps. Task 21's audit decodes in code and prints only file names and counts;
  - every recursive grep excludes `realm.json`, `*.env`, `*-key.pem` and `*.keytab`, and never searches `tests/lab/logs` or `tests/lab/captures`;
  - never read `~/.config/gh-tokens`, `/tmp/port49-lab-tokens.jsonl`, any `.env`, keytab, private-key, `secrets.json`, `admin.env`, `router.db` or `run.env` file, or Ryan's `~/.ssh` or `~/.ansible`.
- Run tests with `TMPDIR=/tmp`, package by package, in the foreground, each call ≤ 600000 ms. Before the branch's final review, run `make test && make vet` and report the real output.
- **Commits:** Conventional Commits, one per step that says "Commit", with an explicit pathspec. Every message ends with `Co-Authored-By: Claude <model name> <noreply@anthropic.com>` and nothing else: no session trailer and no claude.ai link (Task 22 makes CI refuse them).
- **Branch:** `feature/pre-beta-fixes` from main. Each lane below may run in its own worktree, branched from the lane's start point, and merges back in lane order.
- **Lab runs** happen on beehive, under the lab lock, with the stall watchdog. No hardware key is available, so no task here needs one. Copy raw pcaps to main's `tests/lab/captures/` before a lab worktree is removed.

## Rulings and disagreements (planner, 2026-11-05)

The controller's rulings in `progress.md` bind. These are the planner's own calls within them. Each says why. Where a call departs from a reviewer or from the brief, it says so.

1. **The floor's two parts** (Task 3; the moot sections of identity and stores).
   - `floor` is the drop read's header, held until the next drop replaces it. It never refuses a fresh mint, because revisions only rise on one timeline.
   - Without `--bump-revision`, a second restore to a newer snapshot of the old timeline can be unseen. Its witness and header can both sit above the first drop's values and below the old record. So a drop whose header is below the highest header read before it (`high_header`) also sets a `band`: tokens at or below `high_header` whose `MintedAt` is not after the drop read are refused too, for `policy.MaxTokenTTL` + `restoreSkew` (20m) after the read.
   - **Disagreement with identity's text:** it holds the band by revision alone. That refuses every fresh mint on the non-bumped timeline until its revisions pass the old header, which can take hours (a token lockout, the 3am cost this review set out to remove). The `MintedAt` term keeps a fresh mint served.
   - **The residual, stated on the drop line and in the runbook:** on the non-bumped path only, a restored token whose minting broker's clock ran ahead of port49d's, by more than the time from its mint to the drop read, is served. That time is at least the first restore's own length. `--bump-revision` (the runbook) closes it, because then `floor` ≥ `high_header`, and no band is armed.
   - The controller's "a fresh mint is never refused" therefore holds outright with `--bump-revision`. Without it, it holds unless the minting broker's clock is behind port49d's by more than the time since the drop read.
2. **Drop detection also compares the header** (new; neither reviewer proposed it). A linearizable read's header never falls on a live cluster. A header below the highest one read on the current timeline is a restore without `--bump-revision`, even when the witness did not move. It costs nothing and narrows the band's case.
3. **The unjudged hold stays** (identity: "not moot, kept"). After a failed `RestoreRead`, every redemption is refused `store_unavailable` until a read answers.
   - Each run's first pass is made synchronously, before the listeners open, so a run's start has no unjudged window.
   - The hold gets a gauge, `port49_redemption_restore_unjudged`, and a 2m page. It is the one refusal state the new design keeps, and it refuses every token login, so it pages. It is never silent (stores I4, deploy I3).
4. **The 10m page `port49_redemption_restore_guarded` goes**, with both its gauges.
   - The floor refuses only restored tokens, and their users mint again, so it pages nothing.
   - A restore still loses revocations, which the runbook re-issues. A ticket, `port49_store_restore_detected`, says a restore was found.
5. **Where the floor persists** (identity I2). In `restore.json`, beside `accounting.spool_path`.
   - That directory is durable in every shape: the chart's per-replica PVC, the systemd and compose spool path.
   - port49d otherwise has no required state directory, and inventing one would be a config change for nothing.
   - The file has the broker's `witness.json` semantics:
     - a record of another prefix is no record, and is said;
     - an unreadable record is moved aside and makes the first read a drop, which fails closed;
     - an absent record is said once at start.
6. **`meta/purged` is removed entirely** (no-deprecation). port49d no longer reads it, so nothing does.
   - The runner's purge still re-reads the witness before it resets its record.
   - The daemon role loses `purged`. `PutPurged` and `RestoreRead.Purged` go.
7. **The create-only compare on the token put** (identity M2; stores Moot 3 calls it moot). **Fixed anyway** (Task 2). It is one compare. It makes "a token key is written once" an enforced invariant, which the floor reads (`CreateRevision`). It is security-relevant and small. No hedge or own-copy recognition is built, as stores says.
8. **`on_missing: include` on a grant** (policy I1). Taken: the reviewer's simpler alternative, a load refusal. A grant whose scope is `on_missing: include` and whose roles carry a permit, or which sets `max_privilege`, is refused at load.
   - Splitting one scope's semantics by rule type would mean composing half-roles.
   - Spec §5.5 already says a permit-bearing scope means exclude.
   - A deny-only role on an include scope still loads.
9. **`security_log` for deny-bearing attribute scopes** (policy I2). It defaults to `true`. An explicit `security_log: false` loads, and `Lint` reports it as `deny_scope_unlogged`. A refusal would turn the spec's SHOULD into a MUST, and this way the author can still opt out on purpose. `platform_changed` becomes a security change.
10. **The other 5 s loops** (stores: hold "fine at 5 s"; identity: "move to `storeAttemptEvery`"). Taken: all four move to the store wait's schedule and to `outageSayer`. That is one schedule, and it removes up to 5 s from the time mints stay closed after the store returns.
11. **port49d's `inventory.max_removed_percent` under a service** (policy moot). Follow the verdict: with `inventory.service` set, it defaults to 100. A removal denies more, never less, so this weakens no security. The availability guard stays with the service, which counts first.
12. **XR over TCP on an ERROR** (devices I2). QUAL is not a §15 row. So the README's XR ERROR row says "final over TLS (L73)". Over TCP it says the qualification vet saw it final and that no §15 row measured it, and it opens L93. Task 24 may close L93 on beehive.
13. **Moot verdicts followed:**
    - `mfaTokenKey` PutOnce: removed (controller).
    - `issueKey` PutOnce: kept (controller).
    - The lab `synchronize` label: moot (controller). It is recorded in Task 25.
    - The mint's unhedged Put: moot for safety, as stores rules; only ruling 7's compare is built.
    - The `unadmittedHeaderDeadline` and `maxLiveSessions` checks: not moot, kept (devices).
    - The `ProtectSystem=strict` absence: not moot, no change (deploy).
    - The label jobs' log filter: kept (deploy).
    - None of these weakens security.

## Lanes

Tasks are numbered in priority order. Lanes group them by the code they touch, so lanes run in parallel without sharing a file. Within a lane, the order is binding. "After" names a cross-lane dependency, which is a merge of that task first.

| Lane | Tasks, in order | Files it owns |
|---|---|---|
| 0 (first, alone) | 1 | the spec |
| A, restore and runner | 2, 3, 4, 5, 9, 15 (15 after 12) | `internal/store/etcd`, `internal/store/{store,memory,crypt}`, `internal/port49d` (restore, runner, brokerd, store wiring), `internal/daemon/metrics`, `deploy/alerts`, `deploy/failure-matrix.md`, `tests/compose` |
| B, broker and client | 6, 8, 16, 18 | `internal/broker`, `internal/config` (identity), `internal/bundle/document.go`, `cmd/port49`, `internal/agent`, `tests/lab` (OIDC, regions) |
| C, store guard | 12, 13 | `internal/store/guard`, `internal/port49d/health.go` |
| D, daemon protocol | 10, 17 (after 3) | `internal/daemon/{authen,author,acct,server}`, `internal/username`, `internal/decision` |
| E, policy | 7, 11, 19 | `internal/policy`, `internal/bundle/diff.go`, `internal/projection`, `internal/port49d/{coldstart,reload}.go`, `internal/config` (inventory) |
| F, release and go-public | 20, 21, 22, 23 | `clients/python`, `packaging`, `.github/workflows`, `go.mod`, `tests/ci`, `tests/lab/labpcap`, `.gitleaks*`, `docs/superpowers/plans/*` (old plans), personal paths |
| G, alerts and device docs | 14 (after 5), 24 (after 5 and 8) | `deploy/alerts` (after A), `deploy/helm`, `deploy/device-aaa` |
| last | 25 | the roadmap |

Task 15 touches `internal/port49d/store.go` beside Task 12's wiring, so it waits for 12. Task 14 and Task 24 edit files Task 5 rewrites, so they wait for 5. Task 24 also waits for Task 8, which edits the spec's L74 row. Task 1 is the only other spec edit, and it runs first.

**Lab runs:**
- **Task 6:** `make lab-oidc` (L45, L46), re-measured on issuance, on beehive.
- **Task 8:** `make lab-regions`, a new L74 cell (j), on beehive.
- **Task 24 (optional):** a new row, L93, on XRd 26.1.1, on beehive.
- **CI, not lab:** Tasks 5 and 12 rerun the compose failure matrix.
- No task needs a hardware key.

## Review Focus

The five failure modes these fixes imply that a reasonable operator meets first, each pinned by a test in the owning task:

1. **The spool directory is full or read-only, so `restore.json` cannot be saved.** port49d keeps serving, keeps the record in memory, says it once, and saves again each second (Task 3, `TestARecordThatCannotBeSavedKeepsServingAndSaysSoOnce`).
2. **A restored enable token** is refused like a login token. The floor runs on every candidate kind (Task 3, `TestARestoredEnableTokenIsRefusedTokenSpent`).
3. **A port49d on the memory store** never applies a floor, and a token with `Revision` 0 there is served (Task 3, `TestTheMemoryStoreHasNoFloor`).
4. **A shipped example policy uses `on_missing: include` on a grant.** Task 7's refusal would then break `deploy/examples` at load. Every committed policy must still load (Task 7, `TestEveryShippedPolicyLoads`).
5. **A restore found at a run's first pass while the read fails.** The listeners open with redemptions held, the gauge reads 1 before the first device connects, and break-glass (not a token) is unaffected (Task 3, `TestARunWhoseFirstReadFailsOpensHeldAndGauged`).

---

### Task 1: Spec: decision 56 and the §5.7 rows

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`:
  - §5.5's "Two requirements" (~1752);
  - §5.7's rows `store_unavailable` (~2662), `token_spent` (~2665) and `credential_mismatch`, and the decision-log `session` fields;
  - §10's "Source-of-truth write access" (~5989);
  - decision 36's restore-witness paragraph (~8075–8095);
  - decision 55 ruling 15 (~11594);
  - a new decision 56 after decision 55;
  - a new §15 row L93.

- [ ] **Step 1: Write decision 56, "The pre-beta review's fixes (2026-11-05)".** Give one ruling per item. Each ruling states the behaviour and the finding it closes:
  1. **The restore floor**, Task 3's design, word for word from Task 3's Step 3 block. It closes stores C1 and identity I1, I2 and I5 (with ruling 2), stores I4 and deploy I3. It supersedes decision 36's guard sentences ("and so does port49d's own guard … arms no …") and decision 55 ruling 15. Mark both of those "*Superseded by decision 56 ruling 1*" in place, and leave their text otherwise as the record.
  2. The runner's restore purge also deletes the `on/` and `mp/` families.
  3. A revocation made in a region cut from the directory still reaches that region's session store (Task 8).
  4. A person's ID token is never a bearer. A human `oidc` verifier requires `broker.identity.issuance`. This amends decision 43 ruling 13 and retires plan 7h's bearer path for people (Q1).
  5. A grant on an `on_missing: include` scope whose roles carry a permit, or which sets `max_privilege`, is a load error (§5.5).
  6. An attribute scope that delivers a deny defaults to `security_log: true`, and `platform_changed` is a security change (§10).
  7. A passing store health check closes the token and context pools' circuits (amends decision 35).
  8. A call whose caller's deadline had passed before it entered is counted `deadline_on_entry`, not as a store failure (amends decision 35).
  9. A full logout queue owes a rescan of the logout set and never drops a logout's reach.
  10. With `inventory.service` set, port49d's `inventory.max_removed_percent` defaults to 100. The sentence "a deliberate large removal raises both" goes.
  11. A token-shaped username is never logged: `session.username` is empty and `session.username_redacted` is true.
  12. An enable token is refused `credential_mismatch` unless its principal is the escalated context's.
  13. An authorization or accounting packet with `seq_no` other than 1 is a protocol error.
  14. The `mfaTokenKey` once-record is removed (the nonce-bound challenge is taken once already).

- [ ] **Step 2: Edit the §5.7 rows.**
  - `store_unavailable`: delete the restore clause. Add: "or, on `redeem` on etcd, port49d's last read of `meta/witness` failed, so it cannot tell whether the store was restored (`port49_redemption_restore_unjudged`; decision 56 ruling 1)".
  - `token_spent`: add: "or the token's store revision is at or below port49d's restore floor: an etcd restore brought it back (decision 56 ruling 1)".
  - `credential_mismatch`: add the enable case of ruling 12.
  - Add `session.username_redacted` (bool) to the decision-log schema.

- [ ] **Step 3: Edit §5.5 and §10.**
  - §5.5: after "any other scope defaults to `exclude`", add ruling 5's sentence and say why: a grant carries permits, and §5.5's direction for a permit is exclude. Put a mitigation's deny in `attached_roles` on an include scope.
  - §10: replace "Scopes carrying denies SHOULD set `security_log: true`" with ruling 6.

- [ ] **Step 4: Add row L93 to §15, open.**
  - Claim: on IOS XR (XRd 26.1.1) over plain TCP under the reference, whether an authentication ERROR is final.
  - Bound: the device README's XR ERROR row.
  - Platform: XRd.
  - Status: `open`.

- [ ] **Step 5: Commit.**

  `git add docs/design/2026-08-23-policy-engine-spec.md && git commit -m "docs: decision 56, the pre-beta review's fixes"`

---

### Task 2: The store: a token's revision, a create-only put, the once purge, and no `meta/purged`

**Files:**
- Modify:
  - `internal/store/store.go`: `Token` gets `Revision`, and the `Store` interface gets `PurgeOnceRecords`;
  - `internal/store/etcd/tokens.go`: `liveTokens` fills `Revision`, and `PutToken` gets the create-only compare;
  - `internal/store/etcd/oidc.go`: `PurgeOnceRecords`;
  - `internal/store/etcd/meta.go`: remove `PutPurged`, and remove `RestoreRead.Purged` and its read;
  - `internal/store/etcd/roles.go`: `daemonMetaReads` loses `"purged"`, and so does any broker grant on it;
  - `internal/store/memory/memory.go`, `internal/store/crypt/crypt.go` and `internal/store/guard/guard.go` (`PurgeOnceRecords` routed `Bulk`).
- Delete: `LatestTokenExpiry` and `ErrTokenRecord` (`tokens.go:299-345`), and `internal/store/etcd/tokens_expiry_test.go`.
- Test:
  - `internal/store/etcd/tokens_test.go`, or the package's token test file;
  - `internal/store/etcd/oidc_test.go`;
  - `internal/store/crypt/crypt_test.go`;
  - `internal/store/etcd/roles_test.go`;
  - `internal/store/etcd/meta_test.go`.

**Interfaces:**
- Produces:
  - `store.Token.Revision uint64`: "the store revision this token's record was created at (etcd: the key's CreateRevision); 0 on the memory store. Never stored in the record, never sealed".
  - `(store.Store) PurgeOnceRecords(ctx context.Context) (int, error)`: deletes every `on/` and `mp/` record and returns how many. On memory it clears both maps.
  - `etcdstore.RestoreRead{Witness, Header uint64}`: `Purged` is gone.

- [ ] **Step 1: Write the failing tests.**
  - `TestCandidatesCarryTheTokensCreateRevision` (etcd): put two tokens, then `Candidates`. Each `Revision` is nonzero, equals the key's `CreateRevision` read raw, and the later put's is larger.
  - `TestTheSealingLayerKeepsTheRevision` (crypt): a token through `crypt.Wrap` keeps the inner `Revision`.
  - `TestAPutOverAnExistingTokenKeyFailsAndWritesNothing` (etcd):
    - set `beforeTokenTxn` to write the same token key first (a late duplicate);
    - `PutToken` returns an error wrapping `store.ErrConflict` and does not loop;
    - the key's value is the pre-written one.
  - `TestPurgeOnceRecordsDeletesOnceAndProofs` (etcd and memory, through `storetest` if the suite has a hook):
    - `PutOnce` ×2 and `PutMFAProof` ×1, then `PurgeOnceRecords` returns 3;
    - `TakeOnce` then answers not-found;
    - `lo/` and `oo/` records are untouched.
  - `TestTheDaemonRoleReadsNoPurgeRecord` (roles): the daemon role grants no read of `meta/purged`.

- [ ] **Step 2: Run them and see them fail.**

  `TMPDIR=/tmp go test ./internal/store/... -run 'Revision|ExistingTokenKey|PurgeOnce|NoPurgeRecord' -count=1`

  Expected: FAIL. `Revision` and `PurgeOnceRecords` are undefined.

- [ ] **Step 3: Implement.**
  - `liveTokens` sets `t.Revision = uint64(kv.CreateRevision)`.
  - `PutToken`'s `If` gets `clientv3.Compare(clientv3.CreateRevision(s.k.token(k, t.ID)), "=", 0)`.
  - On `!resp.Succeeded`, `PutToken` reads the token key once. If the key exists, it returns the conflict without retrying, because the ID is taken. Otherwise it keeps today's index-moved retry.
  - Comment at `tokens.go:55`: the Txn is never hedged or re-sent, and the compare makes a late copy a refused one, not a second token (stores Moot 3).
  - Delete `LatestTokenExpiry`, `ErrTokenRecord`, `PutPurged` and the `Purged` read.

- [ ] **Step 4: Run the package tests.**

  `TMPDIR=/tmp go test ./internal/store/... -count=1`

  Expected: PASS. Fix the compile errors this leaves in `internal/port49d`: delete `restoreguard.go`'s scan and `RestoreRead.Purged` uses only so the package builds. Task 3 replaces the file, so leave `go vet ./internal/port49d/` to Task 3.

- [ ] **Step 5: Commit.**

  `git add internal/store && git commit -m "feat: a token carries its store revision, its put is create-only, and the once records can be purged"`

---

### Task 3: The restore floor replaces the restore guard

**Files:**
- Create:
  - `internal/port49d/restorefloor.go`;
  - `internal/port49d/restorefloor_test.go`.
- Delete:
  - `internal/port49d/restoreguard.go`;
  - `internal/port49d/restoreguard_test.go`.
- Modify:
  - `internal/port49d/main.go` (~:763 `newRestoreGuard`, ~:1036–1040 `begin` and `keep`, ~:1325–1357 the redeem wiring);
  - `internal/daemon/authen/authen.go` (~:95–136 the `With…` setters, ~:430–455 the redeem checks);
  - `internal/daemon/metrics/metrics.go` (~:490–503 and ~:951–957);
  - `internal/port49d/witness_test.go` (the guard hook tests at ~:440–600).
- Test:
  - `internal/port49d/restorefloor_test.go`;
  - `internal/daemon/authen/authen_test.go` (`TestATokenAtOrBelowTheRedeemFloorIsRefused` at ~:3225 is replaced);
  - `internal/daemon/metrics/metrics_test.go` (~:142, ~:478–500).

**Interfaces:**
- Consumes: `store.Token.Revision` and `etcdstore.RestoreRead{Witness, Header}` (Task 2).
- Produces:
  - in `internal/daemon/authen`:
    ```go
    // RestoreFloor is port49d's restore floor as a redemption asks it.
    type RestoreFloor interface {
        Held() bool                                 // a failed witness read holds every redemption (store_unavailable)
        Restored(t store.Token, now time.Time) bool // t came back with a restore (token_spent)
    }
    func (h *Handler) WithRestoreFloor(f RestoreFloor) *Handler
    ```
    `WithRedeemGuard` and `WithRedeemFloor` are removed.
  - in `internal/port49d`:
    - `newRestoreFloor(out io.Writer, now func() time.Time) *restoreFloor`;
    - `(*restoreFloor) attach(path, prefix string)`, which opens the record on its first call;
    - `(*restoreFloor) begin(m *metrics.Metrics)`;
    - `(*restoreFloor) pass(ctx context.Context, callTimeout time.Duration, read func(context.Context) (etcdstore.RestoreRead, error)) bool`;
    - `(*restoreFloor) keep(ctx context.Context, s *etcdstore.Store, callTimeout time.Duration)`, which follows, passes every `witnessEvery` and saves the record each second;
    - `Held`, `Restored` and `followed(rev uint64)`;
    - the test hooks `floorFollowed` and `floorPassed`, which replace `guardFollowed` and `restorePassed` with the same shape.
  - metrics (per-run registry; values the process holds are set again at `begin`):
    - `RedemptionRestoreUnjudged prometheus.Gauge`, `port49_redemption_restore_unjudged`. Help: "1 while this port49d refuses every token redemption store_unavailable because its last read of meta/witness failed, so it cannot tell whether its store was restored; 0 otherwise."
    - `RedemptionRestoredRefused prometheus.Counter`, `port49_redemption_restored_refused_total`. Help: "Token redemptions refused token_spent because the token's store revision is at or below this port49d's restore floor: an etcd restore brought it back."
    - `StoreRestoreDetected prometheus.Gauge`, `port49_store_restore_detected_timestamp_seconds`. Help: "The Unix time this port49d last found its session store restored from a snapshot, 0 if never: meta/witness or the store's revision fell below what it had read."
    - `RedemptionRestoreGuarded` and `RedemptionRestoreGuardUntil` are removed.

- [ ] **Step 1: Write the failing tests in `restorefloor_test.go`.**

  Use a `floorAt` helper: a floor with a fixed clock, `io.Discard` or a buffer, and a `t.TempDir()` record path. `judge(r, err)` takes the record first, as `pass` does. Tokens are `store.Token{Revision: n, MintedAt: …, ExpiresAt: …}`.

  **Ported probes:**
  - `TestASecondRestoreCarryingAnOldPurgeRefusesItsTokens` (stores probe).
    - Setup: `Saw(1000)`; a read `{Witness: 1000, Header: 1010}`; the restore `{480, 500}` with no bump.
    - After it: floor is 500, band is 1010, and the band runs 20m from now.
    - Then `{985, 990}`, which is not a drop.
    - A token `{Revision: 970, MintedAt: now-2m}` is `Restored`.
    - A token `{Revision: 995, MintedAt: now+1s}` is not.
    - The output never contains "purge".
  - `TestASecondOldTimelineRestoreKeepsTheFirstDropsTokensRefused` (both identity probes, two subtests: `live` and `expired`).
    - Setup: a record of witness 50 and header 55; restore 1 `{10, 29}`; restore 2 `{45, 45}`.
    - A token `{Revision: 44, MintedAt: before restore 1}` is `Restored` in both subtests. The second subtest's first-drop tokens are all expired, which no longer changes anything.

  **Carried over from the final review's tests** (old name → new):
  - `TestAWitnessFollowedDuringTheGuardsReadIsNoDrop` → `TestAWitnessFollowedDuringTheReadIsNoDrop`.
  - `TestAPassTakesTheRecordBeforeItReads` → same name.
  - `TestAFailedReadRefusesRedemptionsUntilOneAnswers` → same name. Also assert the unjudged gauge reads 1, then 0.
  - `TestTheGuardsReadsAreCountedByOutcome` → `TestTheFloorsReadsAreCountedByOutcome` (op `restore_read`).
  - `TestARunAfterAStoreGoneRedeemsOnlyOnceTheStoreIsJudged` → `TestARunJudgesTheStoreBeforeItServes`. `begin`, then the synchronous `pass`: a drop found there is in force before `pass` returns.
  - `TestAWitnessFollowedDuringAGuardedReadIsNoSecondRestore` → `TestAWitnessFollowedDuringAReadAfterADropIsNoSecondRestore`.
  - `TestASecondRestoreJustAfterAScanIsToldOnTheFirstRead` → `TestASecondRestoreIsToldOnTheFirstRead`. The witness falls below the first drop's, and the floor is replaced, not maxed.
  - `TestASecondRestoreAboveTheFirstDropsBaselineStillGuards` → `TestASecondRestoreAboveTheFirstDropsBaselineIsInTheBand`.
  - `TestANewerRestoreWhileGuardedExtendsTheBound` → `TestASecondRestoreReplacesTheFloor`.
  - `TestARestoreAfterATimeLiftIsDetected` → `TestARestoreAfterTheBandEndsIsStillTold`.
  - `TestAFreshMintAfterAnAllExpiredDropNeverArmsTheGuard` and `TestAMintMinutesAfterAnAllExpiredDropNeverGuards` → `TestAFreshMintIsNeverRestored`. Two subtests:
    - bump: drop `{480, 5_000_000_000}` after a header of 1010, so no band is armed, and a token `{Revision: 5_000_000_001}` is served;
    - no bump: a token `{Revision: 600, MintedAt: now+1ms}` is served inside the band.
  - `TestAClockStepBackAfterALiftStillRefusesARestoredToken` → `TestAClockStepBackNeverRevivesARestoredToken`. At now-1h, and at now+1h past the band, a token `{Revision: 400}` is still `Restored`.
  - `TestAQuietStoreRestoreStaysGuardedUntilTheLastTokenExpires` → `TestAQuietStoreRestoreRefusesATokenMintedAfterTheLastWitness`. The witness was last written at 02:00, a token minted at 03:00 has `Revision` 499, and the snapshot is at 03:00:00.4. After the drop at header 500 the token is `Restored`, with no time bound involved.
  - `TestARestoredTokenFromAClockAheadBrokerHoldsTheBound` → `TestTheFloorIgnoresMintedAt`. A token at or below the floor, with any `MintedAt`, including the zero time and now+1h, is `Restored`.
  - `TestTheGuardLineGivesTheSafeWayOut` → `TestTheDropLineSaysWhatIsRefusedAndTheRunbook`. The line names:
    - "token_spent";
    - "a token minted after this read is served";
    - "design §13";
    - "--bump-revision" (on the no-bump path only, with the residual of ruling 1);
    - and no "stop port49d".
  - `witness_test.go`:
    - `TestRestorePassedCountsPasses` → `TestFloorPassedCountsPasses`;
    - `TestTheGuardHooksFireAfterTheirWork` → `TestTheFloorHooksFireAfterTheirWork`.

  **New:**
  - `TestTheFloorSurvivesARestart`. Judge a drop and save, then open a second floor on the same path. The restored token is still `Restored`, and a read of the same witness is no new drop. This closes identity I2.
  - `TestARestartAfterARestoreTellsTheDrop`. Save a record of witness 1000 and header 1010, open a new floor, then a first read `{480, 500}` is a drop.
  - `TestARecordOfAnotherPrefixIsNoRecord` and `TestAnUnreadableRecordMakesTheFirstReadADrop`. The file is moved aside, and the line says that every token in the store is refused once.
  - `TestAnAbsentRecordIsSaidOnce`.
  - `TestTheHeaderFallingIsADrop`. The witness is unchanged at 1000, the header goes 1010 then 900, and that is a drop.
  - `TestARestoredEnableTokenIsRefusedTokenSpent` (Review Focus 2; in `authen_test.go`).
  - `TestTheMemoryStoreHasNoFloor` (Review Focus 3; in `authen_test.go`): a handler built as `main.go` builds it on memory, with no `WithRestoreFloor`, redeems a token whose `Revision` is 0.
  - `TestARecordThatCannotBeSavedKeepsServingAndSaysSoOnce` (Review Focus 1). A read-only directory: `Held` stays false, one line, and the save is retried on the next tick.
  - `TestARunWhoseFirstReadFailsOpensHeldAndGauged` (Review Focus 5).
  - `TestTheRestoreDetectedGaugeIsSetAgainInANewRun`. The process-held time is set into the next run's registry at `begin`.

  **`authen_test.go`:**
  - `TestARestoredTokenIsRefusedTokenSpentAndNotSpent`. The reply is FAIL, the reason `token_spent`, the counter reads 1, the token is still in the store (nothing is written), and a fresh candidate beside it is redeemed.
  - `TestAHeldFloorRefusesStoreUnavailableBeforeAnyLookup`. The reply is ERROR `store_unavailable`, and the `candidates` op counter is unchanged.

  **Removed with their subject** (the scan, the time bound and the purge lift):
  - `TestTheRestoreGuardEntersOnADropAndLeavesOnlyOnAPurge`;
  - `TestAScanThatProvesEveryTokenExpiredGuardsNothing`;
  - `TestASecondRestoreAfterAnAllExpiredDropIsDetected`;
  - `TestAMintAfterTheDropDoesNotExtendTheBound`;
  - `TestABoundThatCannotBeTrustedGuardsUntilThePurge`;
  - `TestTheGuardLineSaysWhenItLifts`;
  - `TestAPassScansWhenAReadCallsForIt`;
  - `TestAGuardedRereadAfterACrossTimelineRestoreKeepsTheLaterBound`;
  - `TestThePassThatWouldLiftScansFirst`;
  - `TestAPassAfterAnAllExpiredDropScansWithTheDropsCutoff`;
  - `TestARereadOfTheSameDropScansAtMostEveryFiveSeconds`;
  - `TestAScanErrorAfterAnAllExpiredDropArmsNoGuardAndIsRetriedAtOnce`;
  - `TestAPassNeverLiftsOnASkippedScan`;
  - `TestASecondRestoreWhileTheScanFailsRefusesUntilAScanAnswers`;
  - `authen_test.go`'s `TestATokenAtOrBelowTheRedeemFloorIsRefused`;
  - `metrics_test.go`'s check that `port49_redemption_restore_guard_until_timestamp_seconds` is registered (~:478–500);
  - `tokens_expiry_test.go`'s two tests (Task 2).

- [ ] **Step 2: Run them and see them fail.**

  `TMPDIR=/tmp go test ./internal/port49d/ ./internal/daemon/authen/ ./internal/daemon/metrics/ -run 'Floor|Restor|Drop|Witness|Held|Record|Header|Mint' -count=1`

  Expected: FAIL, because `newRestoreFloor` and `WithRestoreFloor` are undefined.

- [ ] **Step 3: Implement `restorefloor.go`.**

  The algorithm, which no signature fixes. Decision 56 ruling 1 quotes it.

  ```text
  record (restore.json, owner-only, beside accounting.spool_path; saved each second when changed):
    prefix, witness, header       highest meta/witness ModRevision and read header since the last drop
    high_header                   highest header ever read, across drops
    floor                         the latest drop read's header; 0: none
    band, band_from, band_until   see below; band 0: none
  a pass: take the record, then RestoreRead (Txn, linearizable)
    read error  -> held = true (said once per run of failures; unjudged gauge 1); nothing else changes
    read ok     -> held = false
      drop := unread_record || have && (r.Witness < witness || r.Header < header)
      drop:  floor = r.Header
             band  = max(r.Header, high_header); if band > floor { band_from = now; band_until = now + MaxTokenTTL + restoreSkew } else band = 0
             witness, header = r.Witness, r.Header; high_header = max(high_header, r.Header)
             detected gauge = now; say the drop line
      else:  witness, header, high_header = max with the read
  Restored(t, now) = t.Revision <= floor
                  || band != 0 && now.Before(band_until) && t.Revision <= band && !t.MintedAt.After(band_from)
  ```

  More rules:
  - `Saw` (the follower) raises `witness` only.
  - An absent record says once: "no restore record at <path>: a restore made before this port49d's first read of the store cannot be told; start a broker first after a restore (design §13)".
  - An unreadable record is moved aside, as `openWitness` does, and sets `unread_record`.
  - The drop line, on stderr, says:
    - the witness or header it fell to and from;
    - that tokens at or below revision N are refused `token_spent`, and users mint again;
    - that a token minted after this read is served;
    - on the no-bump path, the band's end time and ruling 1's residual, with "restore with --bump-revision (design §13)";
    - "revocations and marks made after the snapshot are lost: follow the restore runbook (design §13)".
  - `restoreSkew` stays at 5m, its comment rewritten for the band alone. `scanEvery`, `scanResult`, `needsScan`, `scanDue`, `arm`, `expired`, `drop`'s guard, `liftAt`, `bounded`, `why`, `cutoff`, `said` and `checked` all go.

- [ ] **Step 4: Wire it.**
  - `run()`: `restored := newRestoreFloor(stderr, time.Now)`.
  - `runOnce` on etcd:
    - `restored.attach(filepath.Join(filepath.Dir(cfg.Accounting.SpoolPath), "restore.json"), cfg.Stores.Session.Etcd.Prefix)`;
    - `restored.begin(m)`;
    - one synchronous `restored.pass(ctx, callTimeout, sts.etcd.RestoreRead)`;
    - then `go restored.keep(...)`, before the listeners open (~:1416).
  - The authen handler gets `.WithRestoreFloor(restored)` on etcd only.
  - `authen.go`:
    - the `redeemable` check at ~:433 becomes `if s.h.floor != nil && s.h.floor.Held() { return s.storeError(rec) }`;
    - in the candidate loop, a matching `cands[i]` with `s.h.floor.Restored(cands[i], s.h.now())` sets `rec.Principal` and returns `s.fail(ctx, rec, decision.TokenSpent)` after incrementing `RedemptionRestoredRefused`.

- [ ] **Step 5: Run the tests.**

  `TMPDIR=/tmp go test ./internal/port49d/ -run 'Floor|Restor|Drop|Witness|Record|Header|Mint|Held' -count=1`, then `TMPDIR=/tmp go test ./internal/daemon/... -count=1`, then `go vet ./internal/port49d/ ./internal/daemon/...`

  Expected: PASS. Then run all of `./internal/port49d/` (about 9 minutes; timeout 600000).

- [ ] **Step 6: Commit.**

  `git add internal/port49d internal/daemon && git commit -m "feat: a per-token restore floor replaces the restore guard"`

---

### Task 4: The runner's restore purge, and the floor end to end

**Files:**
- Modify: `internal/port49d/runner.go`: `purgeRestored` (~:733) and `markPurged` (~:764), which becomes `confirmPurged`.
- Test:
  - `internal/port49d/brokerd_test.go` (~:2166 and ~:2250);
  - `internal/port49d/runner_test.go` (~:846 and ~:1086);
  - `internal/port49d/witness_test.go` (~:326).

**Interfaces:**
- Consumes: `PurgeOnceRecords` (Task 2), and `restoreFloor` with its record path (Task 3).
- Produces: `(*runner) confirmPurged(ctx context.Context, over uint64) (bool, error)`. It reads `meta/witness` (`r.raw.Witness`), and reports whether its `ModRevision` is still `over`. Only then is the record `Reset`.

- [ ] **Step 1: Write the failing tests.**
  - `TestPort49dRefusesARestoredTokenUntilTheRunnerPurges` becomes `TestPort49dRefusesARestoredTokenAndServesAFreshOne`. Keep the fleet, the snapshot, the redemption and the restore as they are, then check:
    - `waitBrokerMetricAt(..., "port49_store_restore_detected_timestamp_seconds")` is non-zero;
    - the spent token gets FAIL, and the last redeem record's reason is `token_spent`;
    - the `candidates` op counter does move;
    - once broker 3 starts, its purge line is printed, a fresh mint logs in (PASS), and the spent token is still not a PASS.
  - `TestPort49dRefusesARestoredTokenAcrossAStoreGoneUntilThePurge` becomes `TestPort49dRefusesARestoredTokenAcrossAStoreGone`, with the same assertions through the store gone.
  - `TestARestartedPort49dStillRefusesARestoredToken` (new; identity I2).
    - Restore, wait for the drop line, then stop port49d and start a new one on the same config, so the same spool directory.
    - The restored token is FAIL `token_spent` before any broker starts.
    - A control on a fresh spool directory says "no restore record" (that gap is documented, not tested as safe).
  - `TestTheRestorePurgeDeletesTheOnceRecords`: a `PutOnce` before the snapshot, then the restore. After the purge line, `TakeOnce` is not-found.
  - `runner_test.go`: `TestAPurgeDoneOnAnotherStoreWritesNoPurgeRecord` becomes `TestAPurgeUnderAMovedWitnessKeepsTheRecord`. Delete the `meta/purged` assertion at ~:846 from `TestATakeoverPurgesOnceTheBundleJudgedIsInDoubt`.
  - `witness_test.go`: `TestARefusedPurgeRecordLeavesTheWitnessRecordForTheNextPass` becomes `TestAPurgeUnderAMovedWitnessLeavesTheRecordForTheNextPass`.

- [ ] **Step 2: Run them and see them fail.**

  `TMPDIR=/tmp go test ./internal/port49d/ -run 'RestoredToken|OnceRecords|MovedWitness' -count=1 -timeout 600s`

  Expected: FAIL, because `PurgeOnceRecords` is not called and `confirmPurged` is undefined.

- [ ] **Step 3: Implement.**
  - `purgeRestored`: after `PurgeTokens`, `retryCtx(… PurgeOnceRecords …)`. The line adds "; N once-only records (sign-in challenges, proofs, nonces) deleted".
  - `markPurged` is replaced by `confirmPurged`. Its "meta/purged is not written" line becomes "meta/witness changed during the purge, so the store may not be the one purged; the next pass judges it again".

- [ ] **Step 4: Run the tests.** The same command. Expected: PASS.

- [ ] **Step 5: Commit.**

  `git add internal/port49d && git commit -m "feat: the restore purge deletes the once-only records, and the floor is tested end to end"`

---

### Task 5: The floor's alerts, failure matrix, runbook and design text

**Files:**
- Modify:
  - `deploy/alerts/port49.rules.yaml` (~:51–56), `deploy/alerts/port49.rules.test.yaml` and `deploy/alerts/README.md` (~:37);
  - `deploy/helm/port49/files/port49.rules.yaml`, its byte copy;
  - `deploy/failure-matrix.md` (~:15, ~:40);
  - `tests/compose/failmatrix_test.go` (~:703, ~:949–990);
  - `deploy/device-aaa/README.md` (~:69);
  - `docs/design/2026-08-21-port49-design.md`: §13 runbook ~:1774–1840 and §15 ~:2014, ~:2056.

- [ ] **Step 1: Write the failing tests.**
  - In `port49.rules.test.yaml`:
    - `port49_redemption_restore_unjudged` fires at 1 for 2m (page), and not at 1m;
    - `port49_store_restore_detected` fires while `time() - port49_store_restore_detected_timestamp_seconds < 86400` and the gauge is above 0 (ticket);
    - nothing fires on the removed names.
  - In `failmatrix_test.go`, `run("restore_floor", restoreFloor)` replaces `restore_guarded`. The restored token's login is FAIL, a token minted after the restore logs in, and `port49_store_restore_detected_timestamp_seconds` is above 0.
  - `TestEveryAlertNamesARegisteredMetric` and `TestEveryReadmeRowHasARuleAndEveryRuleARow` already exist. They fail until the README and rules agree.

- [ ] **Step 2: Run them and see them fail.**

  `make alerts-check` and `TMPDIR=/tmp go test ./tests/alerts/ -count=1`

  Expected: FAIL. The compose subtest runs in CI only, because no docker runs here.

- [ ] **Step 3: Write the rules and the docs.**
  - **Rules.** Remove `port49_redemption_restore_guarded`. Add the two rules above.
    - The page's summary: "port49d cannot read meta/witness, so it cannot tell whether its store was restored, and refuses every token login (store_unavailable) until it can; check the store and the daemon role's read of meta/witness".
    - The ticket's summary: "port49d found its session store restored from a snapshot: tokens minted before the restore are refused token_spent once (users mint again); revocations and marks made after the snapshot are lost: follow design §13's restore runbook".
    - Copy the file byte for byte to the chart.
  - **The failure matrix's 3am row**, which replaces the `restore_guarded` row:
    - What you see: the drop line and the ticket. Some token logins FAIL `token_spent` once.
    - What the devices do: that one login is refused; a new token logs in; break-glass is as without the restore.
    - What to do: start a broker, which purges, and follow the runbook. No need to stop port49d.
    - Add a row for `port49_redemption_restore_unjudged`.
  - **Design §13 runbook:**
    - step 1 becomes "start a broker before any port49d whose spool directory was lost; port49d's own `restore.json` beside the spool tells the drop otherwise";
    - `--bump-revision` is required. Without it, the band and its residual apply (ruling 1);
    - step 3's token delete stays as the belt to the purge's braces;
    - remove "never restart this port49d", the guard text at ~:1805–1813 and "stop port49d" as the escape.
  - **Design §15:** replace the guard metrics and the alarm with Task 3's three metrics and these two alerts. Add `deadline_on_entry` to the `port49_store_calls_total` outcome values, for Task 13.
  - **`deploy/device-aaa/README.md`:** at ~:69, "Under the restore guard, it waits until port49d is stopped" goes. A restore no longer refuses break-glass.

- [ ] **Step 4: Run the tests.**

  `make alerts-check`, `TMPDIR=/tmp go test ./tests/alerts/ ./tests/compose/ -run 'TestEvery|TestTheChart' -count=1`, then push the lane, so that CI's `compose` job runs `TestFailureMatrix/restore_floor`.

  Expected: PASS.

- [ ] **Step 5: Commit.**

  `git add deploy tests/compose docs/design/2026-08-21-port49-design.md && git commit -m "docs: the restore floor's alerts, failure matrix and runbook replace the guard's"`

---

### Task 6: A person's ID token is never a bearer (identity I4; Q1) — lab run

**Files:**
- Modify:
  - `internal/broker/broker.go` (~:771–782);
  - `internal/config/identity.go` (`checkIssuance` ~:386, and the human verifier load);
  - `internal/broker/issued.go` (`personBearerText` ~:18);
  - the 7h session refresh through the bearer (`internal/broker/sessionrefresh.go`), which is removed for people;
  - `tests/lab/oidc_test.go` and `tests/lab/oidc/` (the L45 and L46 harness, rebuilt on issuance).
- Test:
  - `internal/broker/broker_test.go`;
  - `internal/config/identity_test.go`.

- [ ] **Step 1: Write the failing tests.**
  - `TestAPersonsIDTokenIsRefusedAsABearerOnEveryBroker`, on a broker with `Issuer == nil` and an `oidc` humans verifier: `/v1/tokens` with `Authorization: Bearer <a valid person's ID token from the test IdP>` is 401 `trust_domain_unresolved`, carrying `personBearerText`.
  - `TestAMachinesIDTokenIsStillABearer`: the k8s or machine verifier still mints.
  - `TestAHumanOIDCVerifierRequiresIssuance` (config): `broker.identity.humans: [{kind: oidc, …}]` without `issuance` fails at load. The error names `broker.identity.issuance` and `issuance: {}`.
  - Delete or convert the tests that mint with a person's bearer. Name each one in the commit message.

- [ ] **Step 2: Run them and see them fail.**

  `TMPDIR=/tmp go test ./internal/broker/ ./internal/config/ -run 'Bearer|RequiresIssuance' -count=1`

- [ ] **Step 3: Implement.**
  - Drop `b.Issuer != nil &&` from the case at ~:772.
  - `personBearerText` becomes "a person's ID token is exchanged for a certificate at POST /v1/certificate (`port49 login`), never taken as a bearer (decision 56 ruling 4)".
  - Remove the bearer branch of the person's 7h refresh.
  - `checkIssuance`, or the humans loader, refuses an `oidc` human verifier with no `issuance`.
  - Update every committed config that has such a verifier and no issuance (`git grep -n 'kind: oidc'` under `deploy/`, `tests/`, `examples/`).

- [ ] **Step 4: Run the tests.**

  `TMPDIR=/tmp go test ./internal/broker/ ./internal/config/ ./cmd/... -count=1`

  Expected: PASS.

- [ ] **Step 5: Lab, on beehive.**
  - Rebuild L45 and L46's port49 side on `issuance: {}`, so `port49 login` exchanges the token.
  - `make lab-oidc`. Both rows' assertions hold.
  - Append a "Re-measured on issuance (pre-beta fixes, <date>, <commit>)" section to their results notes, with the capture pointer.
  - The rows stay closed. A failing cell reopens the row and is reported; it is never worked around.

- [ ] **Step 6: Commit.**

  `git add internal/broker internal/config tests/lab deploy && git commit -m "feat: a person's ID token is never a bearer; a human OIDC verifier requires issuance"`

---

### Task 7: A grant on an `on_missing: include` scope is refused at load (policy I1)

**Files:**
- Modify:
  - `internal/policy/load.go` (`buildGrants` ~:1638–1648);
  - every committed policy whose grant sits on an include scope (`git grep -n 'on_missing: include'` under `deploy/`, `tests/`, `docs/` YAML).
- Test: `internal/policy/load_test.go`, and a new `TestEveryShippedPolicyLoads` in `internal/policy`, if none exists.

- [ ] **Step 1: Write the failing tests.**
  - `TestAGrantOnAnIncludeScopeIsRefusedAtLoad`, the probe's YAML (`dc_fabric` include, `dc_admin` with `permit: ["**"]`, a grant to `noc`): `Load` fails. The error names the grant row, `on_missing: include`, "exclude" and "attached_roles", and cites spec §5.5.
  - `TestAGrantWithOnlyAMaxPrivilegeOnAnIncludeScopeIsRefused`: the role has no permit, the grant sets `max_privilege`, and the load is refused.
  - `TestADenyOnlyGrantOnAnIncludeScopeLoads`.
  - `TestTheRefusalForAnUndeclaredOnMissingRecommendsExcludeForAGrant`: the existing refusal's text now says "exclude for a grant; put a mitigation's deny in attached_roles on an include scope".
  - `TestEveryShippedPolicyLoads` (Review Focus 4): every `*.yaml` under `deploy/examples` and `tests/policy` that `policy.Load` accepted at `c0ad3498` still loads.

- [ ] **Step 2: Run them and see them fail.**

  `TMPDIR=/tmp go test ./internal/policy/ -run 'IncludeScope|DenyOnlyGrant|UndeclaredOnMissing|ShippedPolicy' -count=1`

- [ ] **Step 3: Implement** the refusal in `buildGrants`, after the existing `onMissingDeclared` check: `sc.OnMissing == "include"` and (any role has `len(Permit) > 0` or `g.MaxPrivilege != ""`). Fix the fixtures the new test names.

- [ ] **Step 4: Run** `TMPDIR=/tmp go test ./internal/policy/ ./internal/bundle/ ./cmd/port49/ -count=1`. Expected: PASS.

- [ ] **Step 5: Commit.**

  `git add internal/policy deploy tests && git commit -m "fix: a grant on an on_missing include scope is refused at load"`

---

### Task 8: A revoke in a cut region reaches that region's session store (stores I1) — lab run

**Files:**
- Modify: `internal/broker/revoke.go` (~:236–267, and `fallback` ~:482).
- Test:
  - `internal/broker/revoke_test.go`;
  - `tests/lab/regions_test.go` (the L74 harness), with a new cell (j).

**Interfaces:**
- Produces: on `ErrUnrecorded` or `ErrNotRecorded`, `Revoke` still returns the error, but first runs `b.ReachMark(ctx, mark)`. The error text then carries "this region's session store: N token keys deleted and M contexts marked revoked; other regions learn of it at the heal".

- [ ] **Step 1: Write the failing tests.**
  - `TestAnUnrecordedRevokeStillReachesThisRegionsSessionStore`: a fake directory store whose `PutRevocation` fails unavailable, and a session store holding alice's token and live context.
    - `Revoke` returns `ErrUnrecorded`.
    - The token is gone, and the context is marked revoked.
    - The error text holds "1 token keys deleted".
  - `TestANotSentRevokeReachesTooAndSaysSo`: the same, with `ErrNotSent`.
  - `TestTheFallbackNoLongerSaysStopEveryPort49d`: with the reach done, `fallback()` for `port49-broker` offers the policy edit. "stop every port49d" is offered only when the reach failed.

- [ ] **Step 2: Run them and see them fail.**

  `TMPDIR=/tmp go test ./internal/broker/ -run 'Unrecorded|NotSentRevoke|Fallback' -count=1`

- [ ] **Step 3: Implement.** Before each of the two `return RevokeReport{}, fmt.Errorf(... ErrNotRecorded/ErrUnrecorded ...)`, call `ReachMark` and fold its counts and its error into the message. `ReachMark` only denies more and is safe to run twice.

- [ ] **Step 4: Run** `TMPDIR=/tmp go test ./internal/broker/ ./cmd/port49/ -count=1`. Expected: PASS.

- [ ] **Step 5: Lab, on beehive.**
  - Add cell (j) to L74: during a cut, `port49 revoke user:alice` on region 3's broker exits 1 with the reach line, and region 3's open session's next command is denied `credential_revoked` within one command.
  - `make lab-regions`.
  - Add the cell's row to `tests/lab/results/L74-regions.md`, with its capture pointer.
  - Edit L74's §15 claim to name cell (j). It stays closed if (j) passes; if (j) fails, report it.

- [ ] **Step 6: Commit.**

  `git add internal/broker tests/lab docs/design/2026-08-23-policy-engine-spec.md && git commit -m "fix: a revocation made in a cut region reaches that region's session store"`

---

### Task 9: A logout burst never drops a logout's reach (identity I3)

**Files:**
- Modify:
  - `internal/port49d/runner.go` (`followLogout` ~:1093, and the duties' logout pass);
  - `internal/port49d/brokerd.go` (~:652);
  - `internal/daemon/metrics/metrics.go`.
- Test: `internal/port49d/runner_test.go`.

**Interfaces:**
- Produces:
  - `runner.logoutRescanOwed atomic.Bool`;
  - the counter `BrokerLogoutsQueueFull prometheus.Counter`, `port49_broker_logouts_queue_full_total`. Help: "Logouts from another region that found this runner's queue full; each one owes a pass over the whole logout set, which follows."

- [ ] **Step 1: Write the failing test** `TestAFullLogoutQueueOwesARescanThatReachesEverySession`.
  - Use a queue of capacity 2 (make the 1024 a package variable for the test), and 5 logouts followed while the duties are blocked.
  - Once they unblock, all 5 principals' live contexts are marked and their tokens deleted.
  - The counter reads 3.
  - One line is said, not three.

- [ ] **Step 2: Run** `TMPDIR=/tmp go test ./internal/port49d/ -run FullLogoutQueue -count=1`. Expected: FAIL (2 of 5 reached).

- [ ] **Step 3: Implement.**
  - On a full queue, set `logoutRescanOwed`, count, and say once per run of drops: "the logout queue is full; a pass over the whole logout set follows".
  - The duties' loop, when the flag is set, clears it and reaches every entry of `r.logouts` (its loaded set) as `followLogout`'s consumer does, then goes on.

- [ ] **Step 4: Run the same test, then the runner tests.** Expected: PASS.

- [ ] **Step 5: Commit.**

  `git add internal/port49d internal/daemon/metrics && git commit -m "fix: a full logout queue owes a rescan of the logout set instead of dropping a logout's reach"`

---

### Task 10: A token typed as the username is never logged (devices I1)

**Files:**
- Modify:
  - `internal/username/username.go` (new func);
  - `internal/daemon/authen/authen.go` (`newRecord` ~:242);
  - `internal/daemon/author/author.go` (~:265);
  - `internal/daemon/acct/acct.go` (where `Session.Username` is set);
  - `internal/decision` (the `Session` struct gains `UsernameRedacted bool \`json:"username_redacted,omitempty"\``).
- Test:
  - `internal/daemon/authen/authen_test.go`;
  - `internal/daemon/author/author_test.go`;
  - `internal/daemon/acct/acct_test.go`;
  - `internal/username/username_test.go`.

**Interfaces:**
- Produces: `username.Logged(raw string) (name string, redacted bool)`. It returns `"", true` when `token.Parse([]byte(raw))` says the name is token-shaped, and `Canonical(raw), false` otherwise.

- [ ] **Step 1: Write the failing tests.** These are the devices probe, ported.
  - `TestATokenTypedAsTheUsernameIsNeverLogged`, ASCII and PAP subtests:
    - the log contains neither `tok` nor `strings.ToLower(tok)`;
    - the record's `session.username` is `""` and `session.username_redacted` is `true`;
    - the reply is FAIL, as before.
  - The same assertion in author (`TestAnAuthorizationNamingATokenLogsNoUsername`) and acct (`TestAnAccountingRecordNamingATokenLogsNoUsername`).
  - `TestLoggedRedactsOnlyTokenShapedNames`:
    - `alice` gives `alice`, false;
    - a 30-character base62 string gives `""`, true;
    - a 30-character name with `.` gives the canonical name, false.

- [ ] **Step 2: Run them and see them fail.**

  `TMPDIR=/tmp go test ./internal/username/ ./internal/daemon/... -run 'TokenTypedAsTheUsername|NamingAToken|LoggedRedacts' -count=1`

- [ ] **Step 3: Implement** the three call sites. The context key (`store.ContextKey.Username`) still uses the canonical name, because only the log is redacted.

- [ ] **Step 4: Run** `TMPDIR=/tmp go test ./internal/username/ ./internal/daemon/... ./internal/decision/ -count=1`. Expected: PASS.

- [ ] **Step 5: Commit.**

  `git add internal/username internal/daemon internal/decision && git commit -m "fix: a token-shaped username is never written to the decision log"`

---

### Task 11: An SoT edit that lifts a deny is a security record (policy I2)

**Files:**
- Modify:
  - `internal/policy/load.go` (the scope loader ~:1395–1424);
  - `internal/policy/lint.go` (a new finding);
  - `internal/bundle/diff.go` (~:122, ~:165–186).
- Test:
  - `internal/policy/load_test.go`;
  - `internal/policy/lint_test.go`;
  - `internal/bundle/diff_test.go`.

**Interfaces:**
- Produces:
  - `Scope.SecurityLog`, which is true by default when the scope has a match key and delivers a deny: the `onMissingDeclared` refusal's own test (attached roles with a deny, or a grant whose roles carry one);
  - `FindingDenyScopeUnlogged = "deny_scope_unlogged"`, for an explicit `security_log: false` on such a scope.

- [ ] **Step 1: Write the failing tests.**
  - `TestADenyBearingAttributeScopeIsSecurityLoggedByDefault`: the reviewer's `srx_unpatched` scope with no key loads with `SecurityLog == true`.
  - `TestAnExplicitFalseLoadsAndIsLinted`.
  - `TestAScopeLeftByADenyScopeIsASecurityChange` (diff): a device leaving `srx_unpatched` gives `Security: true`.
  - `TestAPlatformChangeIsASecurityChange` (diff, ~:122).

- [ ] **Step 2: Run them and see them fail.**

  `TMPDIR=/tmp go test ./internal/policy/ ./internal/bundle/ -run 'SecurityLogged|ExplicitFalse|DenyScope|PlatformChange' -count=1`

- [ ] **Step 3: Implement.** Keep `security_log` a `*bool` in YAML, so that absent and false differ.

- [ ] **Step 4: Run** `TMPDIR=/tmp go test ./internal/policy/ ./internal/bundle/ ./internal/inventory/ -count=1`. Expected: PASS.

- [ ] **Step 5: Commit.**

  `git add internal/policy internal/bundle && git commit -m "fix: a deny-bearing attribute scope is security-logged by default, and a platform change is a security change"`

---

### Task 12: A passing health check closes the token and context circuits (stores I2)

**Files:**
- Modify:
  - `internal/store/guard/guard.go`;
  - `internal/port49d/health.go` (`health.watch`);
  - `internal/port49d/store.go` (~:643, the health wiring).
- Test:
  - `internal/store/guard/guard_test.go`;
  - `internal/port49d/health_test.go`.

**Interfaces:**
- Produces:
  - `type guard.Closer interface{ CloseCircuits(why string) }`, implemented by what `Wrap` and `WrapRev` return. It closes the `Token` and `Context` pools: `open=false`, `fails=0`, with the existing close line through `g.changed`. It leaves `Bulk` alone.
  - `health.passed func()`, called after every passing check in `watch`.
  - `store.go` keeps the guarded value before `crypt.Wrap`, and sets `passed: func() { closer.CloseCircuits("a store health check passed") }`.

- [ ] **Step 1: Write the failing tests.**
  - `TestCloseCircuitsClosesTokenAndContextNotBulk`: open all three with failures, then `CloseCircuits`. The next token call goes to the store, while bulk is still `circuit_open`, and the gauge reads 0 for token and context.
  - `TestAPassingHealthCheckClosesAnOpenCircuit` (health): an open token pool, then one passing check, then a `Candidates` call is not refused `circuit_open`.

- [ ] **Step 2: Run them and see them fail.**

  `TMPDIR=/tmp go test ./internal/store/guard/ ./internal/port49d/ -run 'CloseCircuits|PassingHealthCheck' -count=1`

- [ ] **Step 3: Implement.**

- [ ] **Step 4: Run** the two packages' tests (port49d in full, timeout 600000). Expected: PASS. Push, so that CI's `compose` job reruns `TestFailureMatrix/leader_dark`. Record its worst round and the counter dump in the commit message (stores carried item: the 17.5 s tail).

- [ ] **Step 5: Commit.**

  `git add internal/store/guard internal/port49d && git commit -m "fix: a passing store health check closes the token and context circuits"`

---

### Task 13: A deadline spent before the call is not a store failure (stores I3)

**Files:**
- Modify: `internal/store/guard/guard.go` (`outcomes` ~:116, `leave` ~:246–256, `do` ~:346–355).
- Test: `internal/store/guard/guard_test.go`.

- [ ] **Step 1: Write the failing tests.**
  - `TestACallArrivingPastItsDeadlineDoesNotOpenTheCircuit`:
    - with `Failures: 5`, make 10 calls whose ctx is already past its deadline;
    - the circuit stays closed;
    - `port49_store_calls_total{outcome="deadline_on_entry"}` reads 10;
    - each call returns an error wrapping `store.ErrUnavailable` and `store.ErrNotSent`.
  - `TestADeadlineStruckMidCallStillCounts`: 5 calls whose deadline strikes inside the store open the circuit, as before.

- [ ] **Step 2: Run** `TMPDIR=/tmp go test ./internal/store/guard/ -run 'PastItsDeadline|MidCall' -count=1`. Expected: FAIL.

- [ ] **Step 3: Implement.**
  - Add `"deadline_on_entry"` to `outcomes`, and to `leave`'s not-counted case beside `"saturated"`.
  - `do`'s early branch uses it.
  - The docs name it already: Task 1 (decision 56 ruling 8) and Task 5 (design §15). This task touches no doc.

- [ ] **Step 4: Run the guard tests and `./tests/alerts/`.** Expected: PASS.

- [ ] **Step 5: Commit.**

  `git add internal/store/guard && git commit -m "fix: a call that arrives past its deadline is counted apart and does not open the circuit"`

---

### Task 14: Alert gaps: a down or unscraped target, and the chart's scrape (deploy I2, M3, M4, M9)

After Task 5.

**Files:**
- Create: `deploy/helm/port49/templates/podmonitor.yaml`.
- Modify:
  - `deploy/alerts/port49.rules.yaml`, `.test.yaml` and `README.md`, and the chart copy;
  - `deploy/helm/port49/values.yaml`, `values.schema.json` and `README.md`;
  - `tests/helm/static_test.go`;
  - the summaries of `port49_oidc_keys_stale` and `port49_tls_device_certificate_renewal_late`.

- [ ] **Step 1: Write the failing tests.**
  - promtool:
    - `port49_target_down` fires on `up{job=~"port49d|port49-broker"} == 0` for 2m (page);
    - `port49_target_absent` fires on `absent(up{job="port49d"}) or absent(up{job="port49-broker"})` for 10m (ticket).
  - `TestPodMonitorRendersWithTheRulesAndSetsTheJobs` (helm): with `prometheusRule.enabled: true` a PodMonitor renders for each workload's metrics port, with a relabeling that sets `job` to `port49d` or `port49-broker`. By default nothing renders.
  - The two summaries:
    - `port49_oidc_keys_stale`'s says "never fetched since this process started, or last fetched over 12h ago";
    - `port49_tls_device_certificate_renewal_late`'s says "the least over certificates verified in the last 24h, so it clears up to a day after the device renews".

- [ ] **Step 2: Run** `make alerts-check && TMPDIR=/tmp go test ./tests/alerts/ ./tests/helm/ -count=1`. Expected: FAIL.

- [ ] **Step 3: Implement.**
  - The README documents the two job names as the rules' parameter.
  - Delete the roadmap's false promise ("the README pairs the rules with `up{job=<broker>} == 0`"). Task 25 records it.
  - Add a NetworkPolicy note to the chart README (M9): the metrics ports listen on every pod address; restrict them with a NetworkPolicy.

- [ ] **Step 4: Run the same.** Expected: PASS.

- [ ] **Step 5: Commit.**

  `git add deploy tests/helm && git commit -m "feat: page on a port49 target down or absent, and render its PodMonitor"`

---

### Task 15: The other 5 s loops take the store wait's schedule (stores M1, M4; carried)

After Tasks 9 and 12.

**Files:**
- Modify:
  - `internal/port49d/brokerd.go` (`startRetryWait`, `startRetry` ~:111–135);
  - `internal/port49d/runner.go` (the hold loop ~:168, ~:184, ~:198, and `retryCtx` ~:780–805);
  - `internal/port49d/store.go` (the late directory open ~:690–705; the `openDaemon` comment ~:365–374).
- Test: `internal/port49d/store_test.go`, `brokerd_test.go` and `runner_test.go`.

**Interfaces:**
- Consumes: `storeWaitAfter`, `jittered`, `outageSayer` and `storeScheduleText` (`store.go:159–230`).
- Produces: `func retryWait(ctx context.Context, failed int, rnd func() float64) bool`. It sleeps `jittered(storeWaitAfter(storeAttemptEvery, failed), rnd())`. All four loops use it and an `outageSayer`.

- [ ] **Step 1: Write the failing tests.**
  - `TestTheBrokersStartRetriesOnTheStoreSchedule`: with an injected `after` and `rnd`, the first ten waits are about 1 s and the 11th about 2 s. Twelve identical failures print one line.
  - The same shape for `TestTheRunnersHoldRetriesOnTheStoreSchedule`, `TestRetryCtxSaysAnOutageOnce` and `TestALateDirectoryOpenRetriesOnTheStoreSchedule`.
  - Delete the tests that pin `startRetryWait` or `5*time.Second`, and name them in the commit.

- [ ] **Step 2: Run** `TMPDIR=/tmp go test ./internal/port49d/ -run 'StoreSchedule|SaysAnOutageOnce' -count=1`. Expected: FAIL.

- [ ] **Step 3: Implement.**
  - Remove `startRetryWait`.
  - The lines say `storeScheduleText` in place of "trying again in 5s" and "every 5s".
  - Fix `openDaemon`'s comment (stores M4).
  - Fix `port49_store_fast_fail_total`'s help text (`internal/daemon/metrics/metrics.go:789`): "counted once per hedged copy". This is the carried item.

- [ ] **Step 4: Run all of `./internal/port49d/`** (timeout 600000). Expected: PASS.

- [ ] **Step 5: Commit.**

  `git add internal/port49d internal/daemon/metrics && git commit -m "fix: the broker's start, the runner's hold and the late directory open retry on the store wait's schedule"`

---

### Task 16: Broker small fixes

This task covers identity M3 and M4, the `mfaTokenKey` removal, and policy M2 and M3.

**Files:**
- Modify:
  - `internal/broker/mfa.go` (~:671, the `mfaTokenKey` PutOnce and its func);
  - the JSON decoders at:
    - `internal/broker/broker.go:417`;
    - `issue.go:160`;
    - `mfa.go:529`;
    - `signin.go:548`;
    - `sessionrefresh.go:124`;
    - `oidcrefresh.go:130`;
    - `adminproof.go:240`;
  - `internal/broker/member.go:29,41,44`;
  - `internal/broker/broker.go:1384` (`deny`) and `:55` (`maxDeviceName`);
  - `internal/bundle/document.go:274` (`NameOK`).
- Test: `internal/broker/*_test.go` and `internal/bundle/document_test.go`.

- [ ] **Step 1: Write the failing tests.**
  - `TestEveryBrokerBodyRefusesTrailingData`: a table over the seven endpoints. A valid body followed by `{}` gives 400 `bad_request`, and the error text names "trailing data".
  - `TestAnIDPMFAProofWritesNoTokenOnceRecord`: after a proof, the store holds no `mfaTokenKey` record. A second use of the same ID token is refused by the spent challenge, as before.
  - `TestBindRefusalsSayWhenToTryAgain`: each 503 detail holds "try again in 30s", and none holds "the agent retries".
  - `TestAByNameNoGrantsDenyCarriesTheBundle`: `rec.Policy.Bundle` is set on `ErrNoGrants`.
  - `TestADeviceNameOver253BytesIsRefusedByTheBundle`: `NameOK` refuses 254, and the broker's and the bundle's limits are one constant.

- [ ] **Step 2: Run** `TMPDIR=/tmp go test ./internal/broker/ ./internal/bundle/ -run 'TrailingData|TokenOnceRecord|TryAgain|NoGrantsDeny|Over253' -count=1`. Expected: FAIL.

- [ ] **Step 3: Implement.**
  - The decoders use the same `dec.Token() == io.EOF` check as `admin_api.go:69`, in one shared helper `decodeOne(dec *json.Decoder, v any) error`.
  - `deny` always sets `Policy{Bundle: pol.Bundle}`.
  - `bundle.MaxDeviceName = 253` is used by both, and the broker's refusal text no longer says "as the inventory names it".

- [ ] **Step 4: Run** `TMPDIR=/tmp go test ./internal/broker/ ./internal/bundle/ ./internal/inventory/ -count=1`. Expected: PASS.

- [ ] **Step 5: Commit.**

  `git add internal/broker internal/bundle && git commit -m "fix: broker bodies refuse trailing data; the idp_mfa once-record, the 503s' retry claim and the 254-byte names go"`

---

### Task 17: Daemon protocol small fixes (devices M2, M3)

After Task 3.

**Files:**
- Modify: `internal/daemon/authen/authen.go` (the enable path's `escalate`) and `internal/daemon/server/conn.go` (~:640–658).
- Test: `internal/daemon/authen/authen_test.go` and `internal/daemon/server/conn_test.go`.

- [ ] **Step 1: Write the failing tests.**
  - `TestAnEnableTokenOfAnotherPrincipalIsRefused`: two principals of one subject; B's enable token presented on A's context is FAIL `credential_mismatch`, the token is unspent, and the context's privilege is unchanged.
  - `TestAuthorAndAcctRefuseASeqNoOtherThanOne`: seq_no 3 on an author packet, and on an acct packet, gets the protocol-error reply path `conn.go` uses for authen, and no handler runs.

- [ ] **Step 2: Run** `TMPDIR=/tmp go test ./internal/daemon/... -run 'EnableTokenOfAnother|SeqNoOtherThanOne' -count=1`. Expected: FAIL.

- [ ] **Step 3: Implement.** Compare `winner.Principal` with `incumbent.Principal` before the redemption.

- [ ] **Step 4: Run** `TMPDIR=/tmp go test ./internal/daemon/... -count=1`. Expected: PASS.

- [ ] **Step 5: Commit.**

  `git add internal/daemon && git commit -m "fix: an enable token must be the escalated principal's, and authorization and accounting hold seq_no to 1"`

---

### Task 18: Client fixes (identity M5; the no-deprecation carried items)

**Files:**
- Modify:
  - `internal/agent/socket.go:41`;
  - `cmd/port49/main.go:195–200`;
  - `cmd/port49/ssh.go` (`legacyPinsHint` ~:360–370 and its call, and the `--known-hosts` flag ~:903–906);
  - `internal/userconfig` (`LegacyPinsPath`, if nothing else uses it);
- Test:
  - `internal/agent/socket_test.go`;
  - `cmd/port49/devices_test.go:550`;
  - `cmd/port49/ssh_fix_test.go:257`.

- [ ] **Step 1: Write the failing tests.**
  - `TestTheTestSocketVariableIsRefusedForASocketAnotherUserOwns`. A socket file whose `Lstat` uid differs from `os.Getuid()`, or a path that is not a socket, makes the dial refused before connecting. Simulate the owner check through an injected `lstat`. A socket the caller owns is dialled.
  - `TestDevicesTrustIsAnUnknownCommand`: exit 2 with the usage text. Nothing mentions "removed in plan 9d".
  - `TestSSHSaysNothingOfAPinsFile` and `TestKnownHostsIsAnUnknownFlag`.
  - Delete `devices_test.go:550`'s and `ssh_fix_test.go:257`'s tests of the removal lines, and name them in the commit.

- [ ] **Step 2: Run** `TMPDIR=/tmp go test ./internal/agent/ ./cmd/port49/ -run 'TestSocket|DevicesTrust|PinsFile|KnownHosts' -count=1`. Expected: FAIL.

- [ ] **Step 3: Implement.** Remove the lines outright.

- [ ] **Step 4: Run** `TMPDIR=/tmp go test ./internal/agent/ ./cmd/port49/ -count=1`. Expected: PASS.

- [ ] **Step 5: Commit.**

  `git add internal/agent cmd/port49 internal/userconfig && git commit -m "fix: the test agent socket must be the caller's, and the devices trust, pins and known-hosts stubs go"`

---

### Task 19: Policy small fixes (policy M1, M4, M5, moot 1)

**Files:**
- Modify:
  - `internal/projection/project.go` (~:240–268);
  - `internal/port49d/coldstart.go` (~:285–300);
  - `internal/config/config.go` (the inventory defaults), and `internal/port49d/reload.go:944`;
  - `internal/policy/scope.go:135` (`composeMarkedFor`, unused: delete it, no-deprecation).
- Test:
  - `internal/projection/project_test.go`;
  - `internal/port49d/coldstart_test.go`;
  - `internal/config/config_test.go`.

- [ ] **Step 1: Write the failing tests.**
  - `TestProjectRechecksTheRenderedRegexes`: inject a rendering fault through a test hook on the ERE join, for example an alternation missing its anchor. `Project` returns an error naming the unsound vector, instead of a "proven" reply.
  - `TestAColdStartWithNoLocalCopySaysWhatItTook`: an empty `state_dir` and mirror. The start line is "no local copy; took bundle <N> published <T> from the service".
  - `TestMaxRemovedPercentDefaultsTo100UnderAService`: with `inventory.service` it is 100; with only `inventory_file` it keeps its old default; an explicit value wins.

- [ ] **Step 2: Run** `TMPDIR=/tmp go test ./internal/projection/ ./internal/port49d/ ./internal/config/ -run 'RenderedRegexes|NoLocalCopy|MaxRemovedPercent' -count=1`. Expected: FAIL.

- [ ] **Step 3: Implement.**
  - `Project` compiles each rendered `allow-commands` and `deny-commands` value with `regexp.CompilePOSIX`, and checks them against `m.probes()` joined by spaces, beside `m.device`.
  - Fix the 12c operator note's `single_device` sentence in the roadmap (policy M1): "a device pinning it is refused admission; a `keys:` or `key_groups` entry naming it is refused at load". Task 25 owns the roadmap, so hand this line to Task 25.

- [ ] **Step 4: Run the three packages** (port49d with timeout 600000). Expected: PASS.

- [ ] **Step 5: Commit.**

  `git add internal/projection internal/port49d internal/config internal/policy && git commit -m "fix: the projection rechecks its rendered regexes; a cold start says what it took; max_removed_percent defaults to 100 under a service"`

---

### Task 20: The release builds (deploy I1, M1, M2, M6)

**Files:**
- Modify:
  - `clients/python/pyproject.toml:15`;
  - `.github/workflows/python.yml` (a new job `build`);
  - `.github/workflows/release.yml` (`cache: false` on every `setup-go`);
  - `go.mod` (`toolchain go1.26.10`);
  - `.goreleaser.yaml` (nfpm `contents`);
  - `Dockerfile` (`/LICENSE`);
  - `clients/ansible/` (the collection's `LICENSE`).
- Create:
  - `clients/python/LICENSE`, a copy of `LICENSE`;
  - `packaging/copyright`.
- Test: `tests/ci/workflows_test.go`, `tests/ci/versions/` and `tests/ci/requirements_test.go`.

- [ ] **Step 1: Write the failing tests.**
  - `TestThePythonProjectHasNoLicenseClassifierBesideItsExpression`: `pyproject.toml` with `license = "…"` has no `License ::` classifier.
  - `TestAPullRequestBuildsWhatTheReleaseBuilds`: `python.yml` has a job running `pip install --require-hashes -r packaging/requirements-release.txt`, `python -m build --no-isolation clients/python` and `ansible-galaxy collection build`.
  - `TestTheGoToolchainMatchesTheDockerfile`: the `toolchain` line equals the Dockerfile comment's patch.
  - `TestReleaseSetupGoNeverRestoresACache`.
  - `TestEveryArtifactCarriesTheLicense`:
    - the wheel's `license-files`;
    - the collection's `LICENSE`;
    - nfpm's `/usr/share/doc/port49-server/copyright`;
    - the Dockerfile's `COPY LICENSE /LICENSE`.
  - The probe, as verification:
    ```
    python3 -I -c "from setuptools.config.pyprojecttoml import apply_configuration; from setuptools.dist import Distribution; apply_configuration(Distribution(), 'clients/python/pyproject.toml')"
    ```
    Before the fix it raises `InvalidConfigError`. Run it from the repo root.

- [ ] **Step 2: Run** `TMPDIR=/tmp go test ./tests/ci/... -count=1` and the probe. Expected: FAIL.

- [ ] **Step 3: Implement.**

- [ ] **Step 4: Run the same.** Expected: PASS, and the probe prints nothing. Push, so that the new `python` job builds the wheel and the collection in CI.

- [ ] **Step 5: Commit.**

  `git add clients packaging .github go.mod .goreleaser.yaml Dockerfile tests/ci && git commit -m "fix: the release's Python build, license files, Go toolchain pin and uncached setup-go"`

---

### Task 21: The committed pcaps are audited in CI (deploy I5; the go-public pcap check)

**Files:**
- Modify: `tests/lab/labpcap/redact.go`, or a new `audit.go`, so that the shape checks `TestCommittedEvidenceMatchesTheCaptures` uses are callable on evidence alone.
- Create: `tests/lab/labpcap/evidence_ci_test.go`.

**Interfaces:**
- Produces:
  - `func AuditEvidence(pcap []byte, opt Options) (EvidenceReport, error)`;
  - `EvidenceReport{CredentialFields, NotFill, TokenShaped, HashShaped int}`. Counts only, with no bytes and no strings.

  `HashShaped` counts the accounting and authorization `cmd` and `arg` values matching:
  - `$1$`, `$5$`, `$6$`, `$9$` or `$aes1$`;
  - `key 7`, `password 7` or `secret 7` followed by hex;
  - `secret 0 `.

- [ ] **Step 1: Write the failing tests.**
  - `TestAuditEvidenceCountsANonFillCredential`: build a synthetic pcap with `synth_test.go`'s helpers whose PAP data is not all `Fill`. `NotFill` is 1, and the error names the field kind only.
  - `TestAuditEvidenceCountsAHashInAnAccountingArg`.
  - `TestCommittedEvidenceHoldsNoCredential`: it runs over `tests/lab/evidence/*.pcap` with no capture needed. For each file it fails with only the file name and the counts. It never skips, because the evidence is committed.

- [ ] **Step 2: Run** `TMPDIR=/tmp go test ./tests/lab/labpcap/ -run 'AuditEvidence|HoldsNoCredential' -count=1`.

  Expected: the first two FAIL (undefined). **If the third fails on committed evidence, stop and report the file names and counts to the lead. Print nothing else, and fix nothing in the pcaps.** That is a finding for Ryan.

- [ ] **Step 3: Implement.** Factor out the existing checks; do not re-decode them differently.

- [ ] **Step 4: Run the package.** Expected: PASS. It runs under `make test`, so it runs in CI.

- [ ] **Step 5: Commit.**

  `git add tests/lab/labpcap && git commit -m "test: the committed pcaps are audited for credentials in CI, without the captures"`

---

### Task 22: No session links in the tree, and gitleaks catches new ones (controller ruling 4; deploy I4)

**Files:**
- Modify:
  - every file `git grep -lE 'claude\.ai/code/session|Claude-Session:[ \t]*https?://'` lists. At `c0ad3498` that is 38 files: 37 under `docs/superpowers/` and `docs/superpowers/handoff-2026-09-18-ser8.md`. CLAUDE.md's rule text names the trailer without a link and is left alone;
  - `.gitleaks.toml` (a new rule);
  - `.gitleaksignore` (the history's fingerprints for that rule);
  - `.github/workflows/leaks.yml`.
- Create: `tests/ci/sessionlinks_test.go`.

- [ ] **Step 1: Write the failing tests** in `tests/ci/sessionlinks_test.go`.
  - `TestTheSessionLinkRuleCatchesALink`:
    - read `.gitleaks.toml` and take the `claude-session-link` rule's `regex = '''…'''` with a small line scan;
    - compile it with `regexp`;
    - assert it matches `"https://claude" + ".ai/code/session_" + strings.Repeat("A", 24)` and `"Claude-" + "Session: https://example.invalid/x"`;
    - assert it does not match CLAUDE.md's sentence "no `Claude-Session:` line and no claude.ai session link".

    Assemble the fixture strings in code, so that no committed file matches.
  - `TestNoSessionLinkInTheTree`: `git ls-files`, skipping the never-read file patterns, then every tracked text file is read and none matches the rule's regex.

- [ ] **Step 2: Run** `TMPDIR=/tmp go test ./tests/ci/ -run SessionLink -count=1`. Expected: FAIL (no rule; 38 files).

- [ ] **Step 3: Implement.**
  - **The rule:**
    ```toml
    [[rules]]
    id = "claude-session-link"
    description = "A Claude Code session link or session trailer; this repository is going public (CLAUDE.md)"
    regex = '''claude\.ai/code/session_[A-Za-z0-9]{8,}|Claude-Session:[ \t]*https?://'''
    keywords = ["claude.ai/code/session", "claude-session"]
    ```
  - **Delete every matching line at HEAD.** A line that only carries the link goes whole. In a quoted commit template, the trailer line goes and the template keeps its other lines. Do not rewrite history (Ryan, 2026-10-15).
  - **The history's hits.** Run `make leaks` with the new rule and `--report-format json --report-path "$CLAUDE_JOB_DIR/tmp/leaks.json"` (redacted). Append every finding's `Fingerprint` for this rule to `.gitleaksignore`, under a comment: "claude-session-link: history before 2026-11-05, not rewritten (Ryan, 2026-10-15)". Print only the count.
  - **CI.** `leaks.yml` also runs `go test ./tests/ci/ -run SessionLink`.

- [ ] **Step 4: Run** `make leaks` and `TMPDIR=/tmp go test ./tests/ci/ -count=1`. Expected: PASS, and gitleaks reports no leak.

- [ ] **Step 5: Commit.**

  `git add .gitleaks.toml .gitleaksignore .github/workflows/leaks.yml tests/ci docs && git commit -m "docs: remove session links from the tree, and gitleaks refuses new ones"`

---

### Task 23: Go-public hygiene (deploy M7, M8; the fork-approval item)

**Files:**
- Modify: the 14 tracked files `git grep -l '/home/rwendt'` lists, among them `Makefile:372`, `tests/lab/clients_test.go:96`, `tests/lab/README.md:967` and `tests/lab/evidence/L48-step_ca.json`.
- Create: `RELEASING.md`.

- [ ] **Step 1: Write the failing test.** `TestNoPersonalPathInTheTree` (`tests/ci`): no tracked file holds `/home/rwendt`. The never-read patterns are skipped. For a committed evidence JSON, rewrite only the path string, never a credential field.

- [ ] **Step 2: Run** `TMPDIR=/tmp go test ./tests/ci/ -run PersonalPath -count=1`. Expected: FAIL.

- [ ] **Step 3: Implement.**
  - In code, use `$HOME` or an env var: `venvPython` becomes `PORT49_LAB_VENV_PYTHON`, defaulting to `$HOME/...`. Scrub the docs.
  - `RELEASING.md` holds the release checklist from plan 12b (`2026-10-27-12b-deployment-release.md:235–238`):
    - the required reviewer on `release`;
    - the `v*` deployment rules on `release`, `pypi` and `galaxy`;
    - `GALAXY_API_KEY` as an environment secret only;
    - the `v*` tag ruleset;
    - fork PR workflows set to "require approval for all outside collaborators".

- [ ] **Step 4: Run the same.** Expected: PASS.

- [ ] **Step 5: Commit.**

  `git add -- $(git grep -l '/home/rwendt' 2>/dev/null) RELEASING.md tests/ci && git commit -m "chore: no personal paths in the tree, and the release checklist is written down"`

  Run the `git grep` before the edits, and pass the files it named.

---

### Task 24: Device pages and the failure matrix (devices I2, I3, M1; stores M2, M3; the carried §15 citations) — optional lab run

After Tasks 5 and 8 (both edit files this task edits: the failure matrix, and the spec's L74 row).

**Files:**
- Modify:
  - `deploy/device-aaa/README.md` (the XR ERROR row ~:140, each platform's "Dark" and "port49 stopped" rows, and "How long a device keeps answering locally");
  - `deploy/failure-matrix.md` (the "One region unavailable" row, and the "Token store unavailable" row);
  - `docs/design/2026-08-23-policy-engine-spec.md` (the L35 and L37 rows' commit citations, and the cap's doc line);
  - `internal/token/minter.go` (a comment beside `m.cap`).

- [ ] **Step 1: Write the failing test.** `TestEveryMatrixRowHasEvidence` (`tests/compose/matrix_evidence_test.go:53`) gains a check that a row citing a closed lab row quotes the cell it rests on. "One region unavailable" then fails until it cites L74 (c) for "the cut region keeps serving", and L4 or L35 for "a refused connection falls through to the next server".

- [ ] **Step 2: Run** `TMPDIR=/tmp go test ./tests/compose/ -run MatrixRowHasEvidence -count=1`. Expected: FAIL.

- [ ] **Step 3: Write the docs.** Each line cites its note.
  - **XR ERROR row.**
    - Over TLS, final (L73, `L73-cisco_xrd.md`).
    - Over TCP: the qualification vet saw break-glass refused (`QUAL-XRd-control-plane-26.1.1-cisco_xrd.md:24`), and no closed §15 row measured it (L93, open).
    - L88 cell c ran inside the device's dead window and did not exercise an ERROR, so the "landed at once" claim goes.
    - Add XR to the README's "ERROR is final" 3am line.
  - **Open sessions while port49 is dark.**
    - For EOS, NX-OS and both Junos images: "While port49 is dark, commands in sessions already open run under local authorization: port49's denies do not apply (L41)".
    - For IOS XE: "refused `% Authorization failed.` (L35, L41)".
    - For XR and SR Linux: "unmeasured".
    - Carry the line to the failure matrix's "Token store unavailable" row.
  - **IOS XE's dead window.** "IOS XE: 30 to 39 s over TCP (L88 f2, f3); 57 to 67 s over TLS after a refused handshake (L73)". "55 s in cell e" goes.
  - **The cap's doc line** (stores M3): a mint whose reply is lost after commit leaves a token nobody holds. It counts toward `max_outstanding` until it expires (≤15m).
  - **The §15 citations.** Re-cite `0eee340`, `20fb9fa`, `2a74f88` and `79812ef` in the L35 and L37 rows to the results notes they produced, or to the merged commits that carry the same change. Find those with `git log --format='%h %s' --grep` on the subject. Check each with `git merge-base --is-ancestor <sha> main`.

- [ ] **Step 4: Run the same test.** Expected: PASS.

- [ ] **Step 5 (optional lab, on beehive): L93.** On XRd 26.1.1 over TCP under the reference, answer a login ERROR with the lab fault switch, then try break-glass.
  - Write `tests/lab/results/L93-cisco_xrd.md` with the platform, image, observation and capture pointer.
  - Close the row, and make the README's TCP line match the measurement.
  - If it is not run, L93 stays open and the line stays "unmeasured".

- [ ] **Step 6: Commit.**

  `git add deploy docs/design internal/token tests/compose tests/lab/results && git commit -m "docs: device pages state XR's ERROR, dark open sessions and IOS XE's dead window from the notes"`

  A lab close is its own commit: `docs: close lab register entries L93`.

---

### Task 25: The roadmap, and the operator notes

**Files:** Modify `docs/superpowers/plans/README.md`, in the Pre-beta review section and the 12c "As built" entry's pre-beta list.

- [ ] **Step 1: Record each pre-beta list item's outcome.** Give the task number that fixed it, or "Left for later" below with its reason. Also:
  - fix the false `up{job=<broker>}` sentence (Task 14) and the `single_device` sentence (Task 19);
  - record the lab `synchronize` item as moot (deploy Moot 1);
  - add the fork-PR approval to the go-public list.

- [ ] **Step 2: Write "Pre-beta fixes — As built".** List the operator-facing notes for the PR body:
  - the restore floor's lines, file, metrics and alerts;
  - the removed metrics and alert;
  - `session.username_redacted`;
  - the config refusals (a human `oidc` verifier without issuance, an include-scope grant);
  - `security_log`'s default;
  - `max_removed_percent`'s default;
  - the new alerts and the PodMonitor;
  - `deadline_on_entry`;
  - the logout counter.

- [ ] **Step 3: Commit.**

  `git add docs/superpowers/plans/README.md && git commit -m "docs: the roadmap records the pre-beta fixes"`

---

## Left for later

Each item has a one-line reason. Items marked "plan 13" are documentation the docs site carries.

**Not fixed:**
- **deploy M5** (more systemd sandboxing): it needs a measured run on the hosted runner's own systemd (L84's host cells). Unmeasured directives could stop a start. Do it before go-public.
- **policy M5** (an `inventory.service.min_published_at` floor): a new key. Task 19 states the cold-start line, which is what the operator needs at 3am. The rest is bounded by the signature.
- **identity P8 and P12** (`--broker-ca-fd` fstat, askpass pidfd test): neither is reachable by an attacker. P8 is the user's own fd.

**Can wait:**
- **Sealing `oo/` and `lo/`** records with principal AAD: a store writer can already delete marks and tokens.
- **The enrollment windows (D2) and `Proven`:** TOFU by design and documented.
- **The detached JWKS save:** a public file, written atomically and owner-only.
- **GSSAPI channel binding:** a hardening feature for the directory.
- **The 24h directory outage revoking directory sessions on restart:** fail-closed. Plan 13 puts it on the 3am page.

**Carried items that can wait:**
- **`supersedeTokens` visiting only token-holding keys:** cost, not safety. It needs the index's atomicity first.
- **`RequestProgress` racing a stream close:** bounded.
- **The single-leg `WatchMemberships` and `WatchLogouts`:** a stall delays by keepalive (12 s), and Task 9 removes the drop behind it.
- **A forgiven member taking load:** bounded by `suspectFor` (15 s).
- **The leader-dark 17.5 s tail:** Task 12 reruns `leader_dark` with the counter dump. If it recurs, it gets its own issue.

**Not judged by the review** (re-judged after Task 12's rerun):
- Task 9 review I1 (`leader_dark` asserts no listener close) and its Minors 1 to 7.
- `TestAnEvictedContextIsNotServedThroughAnOutage`, and the feed-dark member-2 tail.

**Flakes and small items:**
- **The flakes:** `store_hangs` reopen, `TestARunningBrokerSaysALateUnreadableFileOnceAndFollowsTheFix`. Watch for a recurrence. Task 15's schedule change touches the reopen path.
- **The l86 unit test taking `/tmp/port49-lab.lock`:** CI has no contention. Fix it at the next touch of `tests/lab/l60`.
- **The gitleaks pre-commit hook and commit-scoped fingerprints:** the CI history scan is the gate.
- **`Retry-After` with no jitter**, the `testpki` import grouping and the `addSamplerObserved` duplicate loop: cosmetic, and no reviewer judged them.
- **The `l84DiskFloorMB` comment:** a comment.

**Lab and platform:**
- **L90's 32 parallel `ssh` appends to `known_hosts`:** unmeasured, and needs a lab run.
- **GCE cell b's 0.1 ms margin:** a measurement. Rerun at the next load run.
- **L91** (a hardware key) and **the real-Mac `CheckOwned` check:** both need Ryan's hardware.
- **L92** (SR Linux over RFC 9887): the README keeps SR Linux on 49, and the exposure is device-side.
- **SR Linux sending no command authorization:** documented (L76, L88 e). Plan 13's device page leads with it.

**Unchecked by the review:**
- **A `lab:` block in a production `port49d.yaml`:** the start announces it (PR #11).
- **`platforms:` overrides and `policy diff`'s gate:** spec §12's gated keys suggest it gates.
- **`port49_accounting_foreign` paging on every dead window:** which severity is right is a devices call.
- **The `port49` and `port49-server` package conflict:** a packaging choice for Ryan.
- **A key-id collision in `bundle.Open`:** cosmetic, a rotation-docs note for plan 13.
- **A new grant is a reviewer's call, which the gate does not see:** a plan 13 admin-guide line.

## Self-review

Checked against the five findings files, `progress.md` and the brief:

- **Spec coverage.** Every Critical and Important finding has a task:
  - stores C1, and identity I1, I2 and I5 (Tasks 2 to 5);
  - stores I1 (8), I2 (12), I3 (13) and I4 (3, 5);
  - devices I1 (10), I2 and I3 (24);
  - identity I3 (9) and I4 (6);
  - policy I1 (7) and I2 (11);
  - deploy I1 (20), I2 (14), I3 (3, 5), I4 (22) and I5 (21).

  Every Minor is fixed in a task or listed above:
  - stores M1 and M4 (15), M2 and M3 (24);
  - identity M1 (3), M2 (2), M3 and M4 (16), M5 (18);
  - devices M1 (24), M2 and M3 (17);
  - policy M1 (19, 25), M2 and M3 (16), M4 and M5 (19, part), and the carried `composeMarkedFor` (19);
  - deploy M1, M2 and M6 (20), M3, M4 and M9 (14), M5 (left), M7 and M8 (23).
- **Types.**
  - `store.Token.Revision`, `PurgeOnceRecords`, `RestoreRead{Witness, Header}`, `authen.RestoreFloor` and `restoreFloor`'s methods are named once and used with the same names in Tasks 2 to 5.
  - `guard.Closer` is used only by Task 12.
  - `username.Logged` is used only by Task 10.
- **Proportion.** Code blocks are the floor's algorithm, two interfaces and one TOML rule. Everything else is signatures, test names and assertions.
