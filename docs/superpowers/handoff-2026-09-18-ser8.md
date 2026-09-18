# Handoff: plan 1 moves to the SER8 (2026-09-18)

For the first Claude Code session on the new lab machine. Read this, then `CLAUDE.md`, then
the plan `docs/superpowers/plans/2026-09-06-01-protocol-core.md`. The SDD ledger for this
plan is reproduced verbatim in the appendix; it is the recovery map and every ruling is in it.

## Where the work stands

- Branch `feature/protocol-core`, pushed to `origin`, head `c0c83a1`. Never commit code to
  `main`.
- Plan 1 Tasks 1–14 are complete and reviewed. Task 15 (containerlab harness and register
  tests) is committed and partly run:
  - **arista_eos (vEOS 4.32.2F): all six rows measured**, notes in `tests/lab/results/`
    (L1, L2, L5, L6, L8, L10). Their captures are git-ignored and live only in the handoff
    archive (below); each note quotes the bytes it relies on.
  - **juniper_junos: nothing measured.** vJunos-router 23.4R2-S2.1 and vSRX 21.4R3.15 are
    vmhost images (Wind River Linux running Junos as an inner KVM guest). On the WSL2 PC that
    made Junos a fourth-level guest; 35 minutes of boot never reached a login prompt, with
    3 vCPUs pinned near 90% and disk idle. vEOS booted in 57 s on the same host. Note:
    `tests/lab/results/juniper_vjunos-router-inconclusive.md`. The SER8 runs Linux on bare
    metal, so Junos is two-level nested there, which is the normal vMX deployment shape.
- `make test && make vet` are clean at head.

## Set up the SER8 (Ryan, before the session)

1. Linux on bare metal (Ubuntu 24.04 LTS is fine). **Not Windows + WSL2**: the Hyper-V layer
   is what made Junos unbootable. SVM enabled in BIOS. Check: `ls -l /dev/kvm`,
   `cat /sys/module/kvm_amd/parameters/nested` → `1`, `dmesg | grep -i 'nested paging'`.
2. Packages: Docker (native, user in `docker`), containerlab 0.79.0 per the plan's Task 15
   prerequisites (user in `clab_admins`), Go 1.22+, `tcpdump`, `qemu-utils`, `make`, `gh`.
   Passwordless `sudo -n` for the harness (it runs `containerlab` and `setcap`).
3. Images: both handoff files were written to `C:\Users\rhwen\Network Images\` on the old
   PC (not to Google Drive); copy them to the SER8 by Drive, USB, or scp. Load
   `vrnetlab-images-2026-09-18.tar` with `docker load -i`. It holds the three plan-1 images plus the vrnetlab base, including the
   hand-applied vJunos AMD CPU-check patch, so nothing needs rebuilding. If you rebuild
   anyway, the gotchas are in plan 1 Task 15.
4. Management subnet: run the subnet check in Task 15's prerequisites. The topologies use
   `172.100.100.0/24`; if it is taken on the SER8, all eight files it names must change together.
5. Repo: `git clone git@github.com:rhwendt/port49.git ~/git/port49 && git checkout feature/protocol-core`.
6. Restore the local-only state from `port49-handoff-2026-09-18.tar.gz` (same folder):
   ```sh
   cd ~/git/port49 && tar xzf ".../port49-handoff-2026-09-18.tar.gz" \
     .superpowers tests/lab/captures tests/lab/logs
   mkdir -p ~/.claude/projects/-home-$USER-git-port49 && \
     tar xzf ".../port49-handoff-2026-09-18.tar.gz" -C ~/.claude/projects/-home-$USER-git-port49 memory
   ```
   The first restores the SDD workspace (ledger, briefs, reports, review packages) and the
   vEOS captures and logs; the second restores Claude's memory files. The memory directory
   name is derived from the repo path, so adjust it if the repo lives elsewhere.

## Resume in the new session

Tell the agent: "Resume plan 1 with `superpowers:subagent-driven-development`; the ledger is
at `.superpowers/sdd/2026-09-06-01-protocol-core/progress.md`, read its last lines first."
Then, in order:

1. Write-up left over from Task 15: a vSRX inconclusive note (no deploy on the old host; same
   vmhost design as vJunos), a `tests/lab/README.md` paragraph on hosts that cannot boot
   Junos images (WSL2/Hyper-V, the symptom, the bare-metal requirement), and a Makefile fix
   so a failing platform stops the multi-platform loop (the `set -e` in the loop did not).
2. Lab on the SER8: `PORT49_LAB_PLATFORMS=vjunos make lab`, then `vsrx`. Watch the boot with
   `docker logs -f clab-port49-vjunos-srx1`; revisit the 35-minute Junos boot budget in
   `tests/lab/harness_test.go` against the measured bare-metal boot. A device that boots but
   never talks TACACS is a finding: diagnose before trusting a row.
3. Close spec §15 rows whose every listed platform is measured, per the CLAUDE.md procedure
   (`docs: close lab register entries ...`). A row with one platform measured stays open.
4. Task 15 review (BASE `5463b89`), then the final whole-branch review on the most capable
   model (MERGE_BASE `e1f962e`, pointed at the ledger's deferred/parked lines), one fix wave,
   one scoped re-review, then `superpowers:finishing-a-development-branch` (PR to `main`;
   Ryan merges).

## Open call for Ryan (needed before the final review)

vEOS reported `port` as the constant string `ssh` for two concurrent SSH sessions (L1 note).
The design keys login context on `(nas, port)`, so on vEOS a second login overwrites the
first's context and the receipt key `(nas, port, username)` collides for one user's repeated
logins. The Task 15 report (`task-15-report.md` in the workspace) lists the exact lines:
design ~237, 528–535, 616, 763, 1153–1154; spec §13 decision 15 (provisional on L1). This is
a design decision, not a lab fix. The harness works around it by giving every lab login its
own username (`tests/lab/port49d-lab.yaml`).

## Session conventions that bit us

- Commit trailer, verbatim in every subagent dispatch (they otherwise write their own model
  name): `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` plus the
  `Claude-Session:` line the new session provides.
- A SendMessage sent to an implementer mid-round is lost; send follow-ups after its DONE.
  An implementer blocked inside a long `make lab` cannot read messages at all; have it run
  the lab in the background with a log file and wait in bounded `sleep` stretches.
- Model choice: haiku for verbatim transcription tasks, sonnet for handlers, opus for
  credential-path and durability reviews and for the lab.
- Ryan's decisions on the lab so far: one platform at a time; PAUSE means kill, destroy, and
  never relaunch; at most one retry per platform.

## Appendix: SDD ledger as of 2026-09-18

```text
# SDD ledger — plan: docs/superpowers/plans/2026-09-06-01-protocol-core.md

Branch: feature/protocol-core (created from main e1f962e, 2026-09-15). Working in place, no
worktree: repo was docs-only, and Ryan's declared convention is branch + PR.
Spec: docs/design/2026-08-23-policy-engine-spec.md and docs/design/2026-08-21-port49-design.md
(both reachable).

Ruling: work in place on feature/protocol-core rather than a git worktree — Ryan's CLAUDE.md
asks for a branch and a PR, the tree had no code to protect, and the lab harness paths assume
the repo root — costs nothing if wrong beyond re-cloning.

Ruling: Go toolchain on this PC is 1.22.2 at /usr/bin/go (the plan's Tech Stack note about
1.27.1 at /usr/local/go describes the other PC) — go.mod stays `go 1.22`; if a dependency
needs newer, GOTOOLCHAIN=auto may download one — costs a toolchain download if wrong.

## Pre-flight scan
Table in preflight-scan.md (17 mismatches M1–M17 plus unnumbered rubric items). Rulings, each
against the plan text that mandates it; the spec is the authority:

- Ruling M1 (make lab 30m vs 18 VM deploys): harness deploys each topology once per `go test`
  run (shared per-platform deploy) and `make lab` timeout becomes 120m — the plan's own boot
  note makes 30m impossible — costs one Makefile line if wrong. Carry to Task 15.
- Ruling M2 (`Set.Secret` missing from Task 6 Produces): implement `Secret(version int) []byte`
  as Task 6's code has it; Task 14 uses it — no cost. Carry to Task 6.
- Ruling M3 (inline diagnosis strings in Task 14): add `DiagUnadmittedSource =
  "unadmitted_source"` and `DiagMalformedAfterValidation = "malformed_after_validation"` to the
  keyring Diagnosis block in Task 6; spec §10 gets one sentence naming the fifth bucket in the
  branch's docs commit — costs a vocabulary word Ryan may rename. Carry to Tasks 6, 14.
- Ruling M4 (inventory read twice): `config.Load` loads, validates, and builds the admission
  table once and hands the built result to `main`; no second read — costs a small signature
  change in Task 14. Carry to Task 14.
- Ruling M5 (`server.Deps.Store` unused): drop the field — no cost. Carry to Task 14.
- Ruling M6 (L8 filters on a `principal` that is never set/omitempty): L8 measures by outcome —
  seed tokens of each length, log in, PASS means the full length arrived intact, FAIL with
  `credential_mismatch`/`token_not_found` means truncation; no log-field filter — costs nothing.
  Carry to Task 15.
- Ruling M7 (monotonic events on a Gauge): `connections{state}` gauge keeps `open` only; new
  `connection_events_total{event}` counter carries `refused_cap`, `idle_closed`,
  `malformed_backoff` (also fixes "idle/malformed have no metric") — costs a metric rename.
  Carry to Tasks 10, 14.
- Ruling M8 (lab exec paths): harness resolves the repo root to an absolute path and runs
  `<root>/bin/port49d -config <root>/tests/lab/port49d-lab.yaml` with Dir=<root> — no cost.
  Carry to Task 15.
- Ruling M9 (port 49 privileged): harness runs `sudo -n setcap cap_net_bind_service=+ep
  bin/port49d` after build and starts the daemon unprivileged; if setcap fails it reports
  the exact command for the operator — costs a sudo prompt. Carry to Task 15.
- Ruling M10 (vsrx.clab.yml and results/.gitkeep): both are created and committed in Task 15.
- Ruling M11 (brief code not gofmt-clean): implementers run `gofmt -w` after transcribing;
  alignment is not binding, names/values are — no cost. Every dispatch says so.
- Ruling M12a (`TestTypesMatch` asserts nothing): replace with a real assertion of `Canonical`
  — carry to Task 11. M12b/c: Files blocks incomplete; dispatches name the extra files.
- Ruling M13 (SUCCESS after an in-memory channel send is not durable): spec §5.8 and §14 say
  SUCCESS follows a durable spool write, so the plan's spool is wrong. The spool becomes a
  file-backed append log: `Offer` appends the JSON line and fsyncs before returning nil, the
  drain goroutine reads from the file and forwards to the sink, `ErrSpoolFull` on write/sync
  failure or size cap; `acct.Handle` answers ERROR on any `Offer` error (fixes the swallowed
  non-ErrSpoolFull error) — costs fsync latency per record (batching is a later concern) and
  a rewrite of Task 13's spool. Carry to Task 13.
- Ruling M14 (Global Constraints label list vs design §15): design §15 governs; label set is
  {exchange, outcome, reason, diagnosis, key_ref, version, event, verdict, state, op}, no
  device identity; plan line 24 corrected in the docs commit — no cost.
- Ruling M15 (register tests that pass on failed measurement): a register test passes when
  the measurement was made (the exchange happened and the observation was captured) and
  `t.Fatal`s when it is inconclusive; the observed value, either way, is the results note —
  CLAUDE.md's "test passed" means measured, not "behaved as hoped" — costs nothing. Carry to
  Task 15.
- Ruling M16 (hand-rolled itoa/sprintf/replace/indexOf): use strconv/fmt/strings — no cost.
  Carry to Task 14.
- Ruling M17 (permit-all `author.Lab` default in the production binary): no `lab:` block →
  `config.Load` refuses to start with "lab: block is required until the policy engine lands
  (plan 4)"; fail closed at start, not permit-all at 3am — costs a config line in every
  plan-1 deployment. Carry to Task 14.
- Ruling (per-NAS cap test asserts `context.DeadlineExceeded`): assert `errors.Is(err,
  os.ErrDeadlineExceeded)` or a `net.Error` with `Timeout()` — no cost. Carry to Task 14.
- Ruling (vector derivation duplicated in author and acct): `author.ParseArgs` (or a sibling
  exported helper) owns the `cmd==""→nil` rule; acct calls it — no cost. Carry to Task 13.
- Ruling (Emitter drops unmarshalable records silently; main ignores ListenAndServe error):
  Emitter counts drops in a metric or writes one stderr line; main logs and exits on a
  metrics-listener error — carry to Tasks 9, 14.
- Ruling (metrics has no test): Task 10 adds a registration test (fresh registry, `New`
  does not panic, gathered names are snake_case) — no cost. Carry to Task 10.
- Ruling (`policy` absent assertion in Task 9 test is vacuous): drop that assertion — no cost.
  Carry to Task 9.
- Ruling (key `retire_after` and empty-accept CI checks unscheduled): deferred to plan 6
  (inventory/keys); plan's deferred table gains the row in the docs commit — no cost.
- Ruling (line 9 Tech Stack describes the other PC): rewritten in the docs commit.
- Non-defects accepted as scanned: admission before header validate (spec imposes no order);
  `ErrTooManyArgs` unused (leave); `Trie` name for a map (leave, comment says why).

## Tasks

Ruling: Task 1 (scaffold, no interfaces) dispatched concurrently with the pre-flight scan
rather than after it — Task 1 touches only go.mod/Makefile/placeholders; any scan finding
can only bind Tasks 2+ — costs a one-file fix if the scan faults the Makefile.
Task 1: BASE e1f962e; implementer haiku (task-1-impl) → DONE, commit 5558555; review dispatched (haiku).
Task 1: review → spec ❌, 1 Important (plan-mandated): trailer said "Claude Haiku 4.5" not "Claude Fable 5.1".
Ruling: the trailer is the plan's literal text (the session model), not the subagent's own model — CLAUDE.md and the session attribution both name Fable 5.1 — costs nothing if wrong beyond a cosmetic trailer.
Task 1: fix round 1/5 dispatched (resume task-1-impl: amend trailer). Lesson for every later dispatch: state "use this trailer verbatim, not your own model name".
Task 1: fix round 1/5 (1 addressed, 0 open — trailer amended; 5558555 amended to 4084f3d, tree identical per `git diff --stat 5558555 4084f3d` empty)
Ruling: re-review of a commit-message-only amend done by the controller with git (`git log -1 --format=%B` shows the exact trailer; tree diff empty) instead of a reviewer dispatch — there is no code diff to review — costs nothing if wrong.
Task 1: complete (commits e1f962e..4084f3d, review clean after round 1)
Docs commit 3f7c27d: plan line 9, line 24 label set, plan-6 deferral, spec §10 fifth bucket.
Task 2: BASE 4084f3d; implementer haiku (task-2-impl) → committed e2915c3 (docs commit 3f7c27d landed after it; review range is 4084f3d..e2915c3).
Task 2: review (sonnet) → spec ✅, quality Approved, 0 Important.
Task 2: minor (deferred): DecodeHeader accepts len >= 12 (brief-specified); body call sites must slice [:12] explicitly.
Task 2: complete (commits 4084f3d..e2915c3, review clean)
Task 3: BASE 3f7c27d; implementer haiku (task-3-impl).
Task 3: implementer → DONE, commit 75b1b60; review dispatched (sonnet).
Task 3: review (sonnet) → spec ✅, Approved, 0 Important; minors noted (alloc headroom; no n=32 case) — not deferred, cosmetic.
Task 3: complete (commits 3f7c27d..75b1b60, review clean)
Task 4: BASE 75b1b60; implementer haiku (task-4-impl).
Task 4: implementer → DONE, commit bc8663d; review dispatched (sonnet).
Task 4: review (sonnet) → spec ✅, Approved, 0 Important.
Task 4: minor (deferred): Encode() truncates fields >255/>65535 bytes silently (plan-mandated); callers with untrusted-length inputs must bound them.
Task 4: complete (commits 75b1b60..bc8663d, review clean)
Task 5: BASE bc8663d; implementer haiku (task-5-impl).
Task 5: implementer → DONE, commit 642732a; review dispatched (sonnet).
Task 5: review (sonnet) → spec ✅, 1 Important (plan-mandated): argsTotal doc comment describes a nonexistent decodeArgs.
Ruling: the brief's comment is wrong; fix the comment in code (plan text not edited — it is a listing, not a requirement) — costs nothing.
Task 5: minor (deferred): AuthorResponse.Encode lacks the capacity hint AcctReply.Encode has (cosmetic, inherited from brief).
Task 5: fix round 1/5 dispatched (resume task-5-impl: comment fix as a separate commit).
Task 5: fix round 1/5 (1 addressed, 0 open — argsTotal comment; commits 642732a..677d6dc)
Task 5: complete (commits bc8663d..677d6dc, review clean after round 1)
Task 6: BASE 677d6dc; implementer haiku (task-6-impl). Carries rulings M2 (Secret declared) and M3 (two extra Diag constants).
Task 6: implementer → DONE, commit ac3e16d; review dispatched (sonnet).
Task 6: review (sonnet) → spec ❌ (doc only), 1 Important (plan-mandated wording): foreign-Diag comment missing; minor: Secret untested.
Task 6: fix round 1/5 dispatched (resume task-6-impl: block comment + TestSecretNilForRetiredAndUnknown; the minor rides along because the round is happening anyway).
Task 6: fix round 1/5 (2 addressed, 0 open — foreign-Diag comment, Secret test; commits ac3e16d..bb33841)
Task 6: complete (commits 677d6dc..bb33841, review clean after round 1)
Task 7: BASE bb33841; implementer haiku (task-7-impl).
Task 7: implementer → DONE, commit aa728da; review dispatched (sonnet).
Task 7: review (sonnet) → spec ✅ with 1 Important (plan-mandated): tier-3 longest-prefix not reconciled across a device's addresses; first address silently wins.
Ruling: spec §10 says two matches in one tier is a build error naming both; a device whose addresses resolve to different key_refs is refused at Build naming device and both CIDRs (same key_ref via different groups is fine) — the brief's code is wrong; the plan text is a listing, left as is — costs a build refusal on inventories that relied on first-wins.
Task 7: fix round 1/5 dispatched (resume task-7-impl: per-address resolve + agreement check + TestBuildRefusesDisagreeingAddresses).
Task 7: minors folded into round 1: yaml.v3 marked // indirect (go mod tidy); equal-length CIDR overlap path untested.
Task 7: fix round 1/5 (3 addressed, 0 open — cross-address agreement, go mod tidy, overlap test; commits aa728da..75ebf32)
Task 7: complete (commits bb33841..75ebf32, review clean after round 1)
Task 8: BASE 75ebf32; implementer haiku (task-8-impl).
Task 8: implementer → DONE, commit ec4b477; review dispatched (sonnet).
Task 8: review (sonnet) → spec ✅, 2 Important (plan-mandated, brief's reference code): Token.Secret aliased in PutToken/Candidates; no sweep of never-retouched expired keys (unbounded growth).
Ruling: fix both in code — copy secrets at the boundary; opportunistic goroutine-free sweep every 1024 writes via sweepLocked() — the memory store is plan 1's only store and design §8 makes expiry the store's job — costs ~30 lines and one extra map walk per 1024 writes.
Task 8: fix round 1/5 dispatched (resume task-8-impl).
Task 8: minors folded into round 1: constant-time secret compare; tests for reusable redeem and DeleteContext.
Lesson: an addendum sent while an implementer is mid-round is lost (Tasks 7, 8); send follow-ups only after its DONE arrives, or bundle everything in one message.
Task 8: fix round 1/5 (5 addressed, 0 open — aliasing, sweep, constant-time compare, reusable test, DeleteContext test; commits ec4b477..3162669)
Task 8: complete (commits 75ebf32..3162669, review clean after round 1)
Task 9: BASE 3162669; implementer haiku (task-9-impl). Carries rulings: drop vacuous `policy` assertion; Emit reports marshal/write failures to stderr.
Task 9: implementer → DONE, commit 2c83005; review dispatched (sonnet).
Task 9: review (sonnet) → spec ✅, 1 Important (plan-mandated, brief's test): snake_case check does not descend nested objects.
Ruling: fix the test to walk recursively with all nested blocks populated — the snake_case constraint is global and nested tags are where drift would hide — costs nothing.
Task 9: minor (deferred): Record.ServerMsg exists in code but not in the brief's Produces summary (brief-authoring gap; code is right).
Task 9: fix round 1/5 dispatched (resume task-9-impl).
Task 9: fix round 1/5 (1 addressed, 0 open — recursive snake_case check; commits 2c83005..22dee58)
Task 9: minor (deferred): log_test.go assertSnakeCase formats slice index with string(rune(i)); should be strconv.Itoa.
Task 9: complete (commits 3162669..22dee58, review clean after round 1)
Task 10: BASE 22dee58; implementer haiku (task-10-impl). Carries rulings M7 (connection_events_total counter) and metrics registration test.
Task 10: implementer → DONE, commit 9d058c3; review dispatched (sonnet).
Task 10: review (sonnet) → spec ✅, 1 Important: limiter's bad/auth maps grow unbounded (attacker-keyed), no eviction.
Ruling: fix — add `MalformedWindow` to limits.Config (Task 14 surfaces it as `malformed_window`), entries carry last-strike time, sweepLocked every 1024 writes evicts idle entries — same shape as the store sweep; a daemon meant to survive a noisy fleet cannot leak per-source state — costs one new config key.
Task 10: fix round 1/5 dispatched (resume task-10-impl).
Carry to Task 14: config gains `malformed_window` under limits.
Task 10: minor (deferred): metrics_test isLowercaseSnakeCase does not reject leading digit/double or edge underscores; metrics test checks names only, not label sets/types.
Task 10: fix round 1/5 (1 addressed, 0 open — windowed eviction; commits 9d058c3..33a8b2d)
Task 10: minor (deferred): TestSweepEvictsIdleEntries asserts growth after restart, not equality with the base delay.
Ruling (from re-review observation): a zero MalformedWindow/AuthFailureWindow now means "never reset, never swept" — unbounded again by config. Task 14's config.Load must refuse zero for both windows (and supply non-zero defaults when the key is absent) — costs nothing.
Task 10: complete (commits 22dee58..33a8b2d, review clean after round 1)
Task 11: BASE 33a8b2d; implementer sonnet (task-11-impl). Carries ruling M12a (drop TestTypesMatch; real Canonical test).
Carry to Task 14: refuse zero `malformed_window`/`auth_failure_window`; default both when absent.
Task 11: implementer → DONE, commit 73a4579; review dispatched (opus — handler logic, credential paths).
Task 11: review (opus) → spec ❌: (1) Kind checked after match, not filtered before, so a later valid token is never reached; (2) enable START with no enable token yields token_not_found, not token_kind_mismatch; (3) five terminal paths emit no record, no metric, no delay (non-login action, unsupported type, short CHAP data, store errors, wrong-phase CONTINUE). Tail of report pending.
Ruling (1): filter candidates by Kind before verification, as the brief's prose says (its code is wrong).
Ruling (2): per spec §5.7 token_kind_mismatch = "a login token presented at enable, or the reverse": after the kind-filtered set fails, if the credential matches a token of the other kind → token_kind_mismatch, else token_not_found.
Ruling (3): non-login action, unsupported authen_type, wrong-phase CONTINUE → reply ERROR, one redeem record verdict deny reason service_unsupported (spec table row widened); short CHAP Data → FAIL token_not_found with AuthFailure delay; store error (Candidates/RedeemAndReceipt non-NotFound, PutContext) → reply ERROR, one record reason store_unavailable — NEW reason added to spec §5.7 (edited, uncommitted) and to reasons.go in the fix; this is the 3am path and must be visible — costs one vocabulary word Ryan may rename.
Task 11: review tail → 5 Important (redeem record has no identity; PutContext failure = silent PASS; store errors invisible; short CHAP data undelayed/unlogged; kind after match) + minors 6–10 (constant-time; sleep ignores ctx; no terminal session state; ABORT zero Status; CHAP re-prompt = credential_mismatch — tail pending).
Ruling: decision.Session gains `username` (snake_case, omitempty), set on redeem records; Principal stays empty until plan 2 — costs a field.
Ruling: PutContext failure after redeem → ERROR + store_unavailable record, never a silent PASS; StoreOps{op,outcome} incremented on every store call in authen.
Ruling: minors 6–9 folded into round 1 (constant-time, timer+ctx, phaseDone sentinel, ABORT documented: zero Status + done = send nothing).
Task 11: fix round 1/5 dispatched (resume task-11-impl; sonnet).
Carry to Task 14: a zero AuthenReply.Status with done=true means write nothing; StoreOps label values op∈{get_receipt,candidates,redeem,put_context}, outcome∈{ok,not_found,error}.
Task 11: review minors 10–15: CHAP re-prompt reads as credential_mismatch (spec note, deferred); em dash in server_msg; duplicate hashing; test hygiene (PutToken returns discarded, overlapping Canonical tests, no CHAP/ASCII leak assertion); magic strings (token kinds, methods, phase); Canonical("@alice") == "".
Plan: minors 11–15 go to the implementer as a round-1 addendum after its DONE arrives (lesson above); 10 deferred to the final review as a spec wording note.
Task 11: fix round 1 commits 810a953, 7e31469 landed (5 Important + minors 6–9); addendum (minors 11–15) dispatched after DONE.
Task 11: addendum commit 6029e1f landed; re-review (opus) dispatched over 73a4579..6029e1f.
Docs commit (after 6029e1f): spec §5.7 store_unavailable row + service_unsupported redeem meaning.
Task 11: fix round 1/5 (8 addressed, 0 open; commits 73a4579..6029e1f, re-review opus clean, tree verified by reviewer)
Task 11: minor (deferred): CHAP re-prompt of a spent token reads as credential_mismatch (spec wording note); RedeemAndReceipt matches by secret not kind (unreachable with random secrets).
Task 11: complete (commits 33a8b2d..6029e1f + docs 4ea07c6, review clean after round 1)
Carry to Task 14: a packet for a finished authen session (phaseDone) emits one service_unsupported record per packet with no delay — conn should drop the session on done and treat a new START as a new session; anything else on a dead session_id is a malformed strike.
Task 12: BASE 4ea07c6; implementer sonnet (task-12-impl). Carries: exported vector helper for acct; Session.Username on authorize records.
Task 12: implementer → DONE, commit 67caed9 (concern: server_msg suffix with em dash transcribed from listing); review dispatched (sonnet).
Task 12: review (sonnet) → spec ✅ with 2 Important (plan-mandated listings): em dashes in two server_msgs; device-supplied `service` echoed into server_msg.
Ruling: server_msg is ASCII-only and never built from device-supplied bytes (constant strings; the value lives in request.raw) — a console message must not become an injection vector — costs nothing. Carry to plans 4/5 as a standing rule.
Ruling: Lab deny prefix matches on a token boundary (equal, or prefix + space) — costs nothing.
Task 12: fix round 1/5 dispatched (resume task-12-impl; minors Vector test + prefix boundary folded in).
Task 12: fix round 1/5 (4 addressed, 0 open; commits 67caed9..8a45600)
Task 12: complete (commits 4ea07c6..8a45600, review clean after round 1)
Task 13: BASE 8a45600; implementer sonnet (task-13-impl). Carries ruling M13 (file-backed durable spool), the vector-derivation rule (author.Vector), ERROR on any Offer error, Session.Username on account records, StoreOps on GetContext.
Task 13: implementer → DONE, commit eba6cd3; review dispatched (opus — durability + concurrency).
Task 13: review (opus) → spec ✅, durability core sound (no lost-record interleaving); 4 Important error-path items: silent re-emission when Remove fails; O(N²) write-back batching; shutdown spin on persistent read error; new file's directory entry not fsynced. Minors: unmarshalable line not counted; ServerMsg says "spool full" for any error; fixed sleeps in tests; silent error returns.
Ruling: stream the whole .draining file per pass (no write-back; capacity documented as reserved); log every drain error; forwarded-but-stuck file is not re-emitted; shutdown drain gives up after 3 consecutive read failures leaving the file for next start (at-least-once); fsync the parent dir when Offer creates the file — costs a dir fsync per file creation.
Task 13: fix round 1/5 dispatched (resume task-13-impl; minors 5–6 folded in).
Task 13: fix commit 7ceca07 landed (6 addressed by implementer's account). Implementer notes fsync-per-Offer costs ~5 ms each on this WSL2 box (5000 offers ≈ 25 s): follow-up sent to shrink the backlog test to 500 + testing.Short skip. Note for the final review / plan 12 load validation: per-record fsync bounds accounting throughput; group commit is the known follow-up.
Task 13: test-shrink commit 6db98c3 (acct package 4.2 s); re-review (opus) dispatched over eba6cd3..6db98c3.
Task 13: fix round 1/5 (6 addressed, 2 new Important open — read error re-forwards the prefix forever; stuck wedges if .draining vanishes; minors: sleepless shutdown branch, SpoolDepth under-report; commits eba6cd3..6db98c3)
Ruling: drain resumes at a remembered byte offset (bufio.Reader, no hard line cap; >1 MiB line = drop), 3 consecutive failures at one offset → quarantine rename `.draining.failed-<ts>` for an operator; IsNotExist on remove clears stuck — at-least-once stays, duplicates bounded — costs an operator-visible quarantine file.
Task 13: fix round 2/5 dispatched (resume task-13-impl).
Task 13: round-2 commit 1e9f777 (adds go-spew indirect via prometheus testutil in tests); re-review (opus) dispatched over 6db98c3..1e9f777.
Task 13: fix round 2/5 (4 addressed, 1 Important open — the resume test does not exercise the offset; minors: unbounded long-line read, countLines still Scanner-capped, open/seek failures never quarantine, shutdown test name mismatch; commits 6db98c3..1e9f777)
Task 13: minor (deferred): SpoolDepth does not subtract records in a quarantined file (gauge stays non-zero until restart); drainOffset written outside the mutex in the single drainer goroutine (documented invariant).
Task 13: fix round 3/5 dispatched (resume task-13-impl: real offset-resume test with a test-only read-failure hook; bounded line reads; countLines fixed; open failures strike/quarantine; shutdown give-up test).
Task 13: round-3 commit 41f91b4; re-review (sonnet) dispatched over 1e9f777..41f91b4.
Task 13: fix round 3/5 (5 addressed, 0 open; commits 1e9f777..41f91b4, re-review clean)
Task 13: minor (deferred): the initial path→.draining rename failure is not wired into the 3-strike counter (throttled log only).
Task 13: complete (commits 8a45600..41f91b4, review clean after round 3)
Ruling: accounting config key becomes `spool_path` (the file is the spool, not an overflow); `spool_capacity` kept and documented as reserved — a config name that lies is worse than a rename before any deployment exists — costs a plan-text mismatch (listing only).
Task 14: BASE 41f91b4; implementer opus (task-14-impl). Carries M3, M4, M5, M7, M16, M17, DeadlineExceeded, ListenAndServe, malformed_window + zero-window refusal + defaults, ABORT zero status, dead-session handling, spool_path, graceful spool drain on shutdown, inventory-loopback.yaml committed.
Task 14: implementer (opus, task-14-impl) FAILED at Step 11 with "session limit · resets 3:50am America/New_York" — code+tests written but uncommitted, no report. Controller verified `make build && make test && make vet` pass on the uncommitted tree (1390 lines across config/server/main/loopback yaml).
Task 14: fresh finisher dispatched (sonnet, task-14-finish): smoke run, ruling checklist, trace table, report, commit. BASE stays 41f91b4.
Task 14: finisher → DONE, commits 6530588, 4403501; smoke run passed (PAP login over loopback, SIGTERM drains spool); review dispatched (opus).
Task 14: review (opus) → spec ✅ all 14 rulings + constraints met, Approved; 1 Important: a device matching no key group starts the daemon and then fails every packet as a key mismatch. Minors: unadmitted source counted as malformed_backoff; body_sha256 of nothing on header-only paths; body-read timeout uncounted; seq_no wraps at 255; no metric assertions in tests; no recover per connection; seed secrets plaintext in the lab block (plan-mandated, lab-only).
Ruling: config.Load refuses a device whose resolved key_ref is empty, naming it — the config package promises to catch this class at start — costs a start refusal on inventories with uncovered devices.
Task 14: minor (deferred): seed token secrets are plaintext in port49d.yaml's lab block (plan 2's minter replaces seeding).
Task 14: fix round 1/5 dispatched (resume task-14-finish; minors 1–6 folded in).
Note: "per source before global" — limiter has no global connection cap; design §11 wording; carry to the final review as a question for Ryan/plan 12 load work.
Task 14: fix commit 5463b89 landed; re-review (sonnet) dispatched over 4403501..5463b89.
Task 14: fix round 1/5 (7 addressed, 0 open; commits 4403501..5463b89, re-review clean)
Task 14: minor (deferred): no forced-panic test for the per-connection recover (defer order traced sound).
Task 14: complete (commits 41f91b4..5463b89, review clean after round 1)
Task 15: BASE 5463b89; implementer opus (task-15-impl). Carries M1 (one deploy per platform per run; make lab timeout 120m), M6 (L8 by outcome), M8 (absolute repo-root paths), M9 (setcap for port 49), M10 (vsrx topology + results/.gitkeep), M15 (register test passes when measured, fails when inconclusive).
Task 15: host prep — tcpdump installed via apt (was missing); sudo -n passwordless confirmed; images/KVM/clab present. Implementer opus (task-15-impl) dispatched: Steps 1–6 then the real lab run, one platform at a time; non-booting image = finding, not blocker.
Task 15: PAUSED 2026-09-16 ~22:09 local at Ryan's request (needs the machine). Harness committed 6e1696d. Controller killed the running `make lab` (vsrx platform) and port49d, destroyed clab-port49-vsrx; docker ps shows no lab containers, no qemu. vEOS had booted and exchanged real ASCII authentications earlier (decision log tests/lab/logs/decisions-arista_eos.jsonl: leaf1 admitted, key validated, `breakglass` → token_not_found every 15 s — likely the SSH readiness probe). Pause message sent to task-15-impl; its report/PAUSED section may follow. RESUME on Ryan's word: re-dispatch or resume task-15-impl from the report's PAUSED section; results notes and captures on disk are uncommitted.
Task 15: implementer (opus, task-15-impl) did not honor the pause — its `make lab` returned and it relaunched the vsrx platform (~22:09). Ryan asked for force. Controller TaskStop'd task-15-impl (terminated, not resumable), killed make/go test/port49d, destroyed all three topologies; docker shows no clab containers, no qemu. No task-15-report.md was ever written. HEAD 560adfb. Uncommitted: harness_test.go and vjunos-startup.conf edits, six L*-arista_eos.md results notes, captures (git-ignored). RESUME on Ryan's word by dispatching a FRESH implementer from this note (not task-15-impl): first review + commit the uncommitted vEOS notes and harness edits, then `PORT49_LAB_PLATFORMS=vjunos make lab`, then vsrx, then close fully-measured spec §15 rows.
Task 15: RESUMED 2026-09-16 ~22:20 on Ryan's word. Fresh implementer opus (task-15-resume) dispatched from the forced-stop note; BASE for review stays 5463b89. Carries: judge the uncommitted harness/vjunos-conf edits on merit; L10-arista_eos.pcap is empty (24 B) so recapture or mark inconclusive; vJunos captures all empty + decision log empty = nothing measured there, diagnose first; vsrx unmeasured; L1 vEOS finding (both concurrent SSH sessions report port=ssh) contradicts the (nas,port) login identity — cite the note in the doc edit, controller rules on the contradiction. Bound: one platform at a time, make lab in background with log, PAUSE/STOP message = kill+destroy+never relaunch, one retry per platform max.
Ruling: Juniper platforms (vjunos, vsrx) are recorded as inconclusive-on-host for Task 15 on this PC; vEOS is the only measured platform here — both Juniper images are vmhost designs (Wind River Linux running Junos as an inner KVM guest), a fourth-level guest under Hyper-V/WSL2, CPU-bound at ~90% per vCPU with nested paging/SVM already on, 17+ min without reaching login while vEOS took 57 s — costs the Juniper rows staying open until the harness runs on the bare-metal SER8 arriving 2026-09-18 (memory: lab-machine-ser8). Implementer told: let the current vjunos deploy finish and record its timeline, do not deploy vsrx, write inconclusive notes + README paragraph, close no §15 rows, report DONE.
Ryan 2026-09-17 00:58: let the 35-minute vjunos boot run out; if it fails, bench further lab tests until the SER8 is set up. Note: boot budget for Junos is 35m (2e677ff), controller earlier misreported 20m; revisit the budget once a bare-metal boot time is measured.
Task 15: vjunos 35m run ended 01:19 — breakglass never logged in (34m49s), harness declared ready at 35m7s, all six register tests failed on SSH handshake timeouts, every capture 0 lab-subnet packets. The make lab loop then rolled into vsrx despite set -e; controller killed it at 01:20 and destroyed the topology (Ryan: bench further tests until the SER8). Implementer told: write-up only, no make lab / go test -tags lab; fix the Makefile loop so a failing platform stops the run.
Task 15: STOPPED 2026-09-17 01:22 at Ryan's request (task-15-resume TaskStop'd). HEAD c0c83a1, pushed to origin/feature/protocol-core (upstream set). make test && make vet clean. Committed this stretch: bc542ed, 3e5d876 (capture proves what the note quotes; device-only packet counts), 0bfc356 (six arista_eos results notes), 2e677ff (Junos boot budget 35m; config gate gets the whole budget), c0c83a1 (tests/lab/results/juniper_vjunos-router-inconclusive.md). Report: task-15-report.md is partial ("Files changed"/"Concerns" unfilled) but carries the L1 finding's doc citations (design lines 237/616/763/1153-1154, receipt key 528-535; spec decision 15 line 3076).
RESUME POINT (on the SER8, or here for write-up only): (a) vsrx inconclusive note not yet written (no deploy here; same vmhost design); (b) README paragraph on hosts that cannot boot Junos images not yet written; (c) Makefile: a failing platform must stop the multi-platform loop (set -e did not) — not fixed; (d) on the SER8 run `PORT49_LAB_PLATFORMS=vjunos make lab` then `vsrx`, revisit the 35m budget against the measured bare-metal boot, then close §15 rows whose every platform is measured (`docs: close lab register entries ...`); (e) controller ruling still owed on the L1 finding (port=ssh constant across concurrent SSH sessions on vEOS) vs the (nas,port) login-context key — bring to Ryan before the final review; (f) then Task 15 review (BASE 5463b89), final whole-branch review (MERGE_BASE e1f962e), finishing-a-development-branch.
```
