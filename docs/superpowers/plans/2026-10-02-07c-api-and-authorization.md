# Plan 7c: The API and Its Authorization — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put design §17's authorization model on the broker's HTTP API, and close the two items
plans 4b and 7a handed it.
- **Rights.** A principal acts on its own tokens, sessions and decisions; acting on someone else's
  is an `api:` right its subject declares (`revoke_others`, `explain_others`). `sync`, `keys_show`
  and `replay` guard no broker endpoint and are ruled reserved. No right widens a mint or a
  refresh.
- **`POST /v1/tokens/revoke`.**
  - **Self.** A principal ends its own live sessions and deletes its own unspent tokens, everywhere
    or on one `(device, username)`, and leaves no standing mark (7a's carried "self-revocation's
    shape").
  - **Others.** Under `revoke_others` it revokes another principal through 7a's `Broker.Revoke`, a
    standing mark, or ends whatever holds one `(device, username)`. Without the right either form
    is refused 403: the request's form, never the caller's rights, decides what it means.
- **`GET /v1/identity`.** What the broker resolves the caller to: subject, unexpired grants, rights,
  and the connection's clock.
- **`POST /v1/explain`.** A hypothetical decision from the policy in force, about the caller or,
  under `explain_others`, another principal. An unknown device answers exactly as a device with no
  grant does.
- **`/healthz` and `/readyz` on the broker.** Readiness says only whether the broker is serving,
  never store health (design §12).
- **The CLI.** `port49 identity`, `port49 explain` over the agent, and `port49 revoke --mine` and
  `--via-agent`.
- **Plan 4b's candidate reload guard, ruled on.** A policy reload that would take more than
  `inventory.max_removed_percent` of the devices in service out of service is refused, whether by
  refusing admission (as today) or by quarantining them, unless it leaves at least as many devices
  in service as before.
- **Ryan's answer of 2026-10-02.** `broker.revocations_file` is never created by a start: an empty
  or missing volume refuses every start, and `port49d init-revocations`, run once at install as
  port49d's user, creates the file. Decision 32 is amended first, by Task 1.
- **Lab.** The HTTP revocation's three shapes, end to end on the four images 7a measured.

**Architecture:**
- **Authentication.** Every authenticated endpoint but `/v1/refresh` (which re-authenticates)
  goes through one preamble, `Broker.authenticate`, lifted out of the mint. It checks the verified
  certificate, the connection's `max_session_age`, the revocation marks, and the certificate's
  status. A refusal is answered and recorded under the endpoint's own event.
- **Authorization.** `policy.Policy.HasRight(principal, right)` reads the policy in force at each
  request, so a right withdrawn by a reload is gone at the next call.
- **Revocation.**
  - **Self.** `Broker.RevokeOwn` deletes the caller's own tokens one at a time, through a new
    `store.DeleteToken` by ID, so another principal's tokens under a shared `(device, username)`
    are untouched. It marks only the caller's own contexts, by compare-and-set on the policy
    revision read (`SetContextPolicy` with `RevokedAt`), so a context another principal's login
    replaced is never marked.
  - **Key.** `Broker.RevokeKey` is `revoke_others`' `(device, username)` form. The caller's own
    session on one key is `mine` with that key, never a key alone.
  - **Neither leaves a mark.** A revocation of another principal is 7a's `Broker.Revoke`,
    unchanged, its origin `api <caller>`.
- **Explain.** `/v1/explain` reuses `policy.Explain`, the evaluator `port49 explain` runs. The
  broker answers an unknown device as `no_grants_matched` with no platform, and a principal under
  a mark as `credential_revoked`. It returns the rendered, redacted text beside the verdict and
  reason.
- **The guard.** It extends `bundle.CheckAdmission`, which already bounds a policy reload's newly
  refused devices, to count newly quarantined ones at the reload instant. port49d prints its
  refusal redacted (spec §5.8), saying the refused file is still on disk and a restart would load
  it unguarded.
- **Init.** `port49d init-revocations` reads only `broker.revocations_file` from port49d.yaml
  (`config.RevocationsFile`; no secret is resolved, and the path checks `Load` makes are made),
  fences the directory, refuses unless it runs as the directory's owner, and creates the marker and
  an empty file, each exclusively. A file already there that loads is "already initialized", exit
  0, nothing written. A start never creates the file; it still writes the marker beside a file
  that loads, as 7a's start did.

**Tech Stack:**
- Go 1.22 (the module's `go` line).
- The standard library and `prometheus/client_golang`. **No new module dependency.**
- containerlab on beehive for Task 13.

**Spec:**
- `docs/design/2026-08-23-policy-engine-spec.md`:
  - §2: "What a subject may do through the broker API", the rights table.
  - §5.1.3: policy reload, step 1.
  - §5.1.4: revocation as built.
  - §5.7: events, the `revoke` body, reason codes.
  - §12: tooling.
  - §13 decisions 15, 17, 20, 21, 32 (amended here), 33, and the new 34.
  - §14: "API rights".
- Design `docs/design/2026-08-21-port49-design.md`:
  - §12: the failure matrix's revocations-file row; "Store health MUST NOT be wired into the
    readiness probe".
  - §17: surface, errors, requirements ("by default a principal acts only on itself").
  - §19 step 7.
- Roadmap `docs/superpowers/plans/README.md`:
  - "Plan 7", 7c's bullet.
  - "Plan 7a — As built": carried to 7c, and the answered decision on the revocations volume.
  - "Plan 7b — As built": carried to 7c.
  - "Plan 4b": "Hands to plan 7", the candidate reload guard.
- The merged plans 7a (`2026-10-01-07a-revocation-and-broker-limits.md`) and 7b
  (`2026-10-01-07b-session-lifetime-and-cert-status.md`).

**Prerequisite:** plan 7b merged (PR #21, `513e4bd`; `main` at `66faee6`). Branch
`feature/api-and-authorization` off `main` at the commit that adds this file.

## Pre-flight resolution

The pre-flight review (`.superpowers/sdd/2026-10-02-07c-api-and-authorization/preflight-review.md`)
and the controller's rulings (`progress.md`), finding by finding:

- **I1**: re-admission caveat in the Texts (Task 7), Ruling 2, §5.1.4, decision 34, notes; lab re-asks the refused session (Task 13).
- **I2**: a key without `mine` and the right is 403 (Task 8); Rulings 3–4; Task 1 Steps 2, 4, 7–10; CLI (Task 12); lab (Task 13); Review Focus 6.
- **I3**: `refusalLine` (port49d) and `redacted` (`inventory diff`) redact before cutting (Task 10); the `quotesCut` sentence corrected.
- **I4**: `unguardedAtStart` on the refusal line (Task 10); Ruling 8; §5.1.3; decision 34; start guard carried to 7e/12 (Task 14).
- **I5**: `initOwner` refuses unless the euid owns the directory, naming the `sudo -u` line, no chown (Task 2); Ruling 9; decision 32.
- **I6**: init exits 0 over a file that loads, 1 over a bad file or a lost one (Task 2); "never on a start path" in Ruling 9, decision 32, §12, Task 14, notes.
- **I7**: mark kept; `Broker.AdminSocket`/`liftNote` and port49d's start line (Task 8, both tested); Ruling 3; §5.1.4; decision 34.
- **I8**: no `auth` on `revoke deny` and `explain` records; `explain.asked_by_fingerprint` (Tasks 3, 8, 9); Ruling 4; §5.7.
- **I9**: `agent.ErrAgentTooOld`, and `not_supported` for an old broker (Task 11); notes.
- **M1**: Task 13 Consumes fixed (`agentPID` a var; `revokedMint`, `mintRefusal` added; unused `revokeRefusedLine` dropped).
- **M2**: Task 6 adds `noStore.DeleteToken` in `internal/daemon/authen/authen_test.go`, and the file to the commit.
- **M3**: Task 1 Step 9 names the broker's bullet, not the inventory service's.
- **M4**: Task 10 passes `inventory.go`'s existing `now`.
- **M5**: comments in Task 2 (`config.go`, `revocations.go`) and Task 7 (`port49_revocations_total`).
- **M6**: Task 10's test starts from one of four quarantined: release, same, one more of three refused.
- **M7**: Task 9's `TestAScopedCallerLearnsNothingOfADeviceOutsideItsGrants`; Review Focus 7.
- **M8**: `Refused`/`RefusedAtBind` take the path and record its endpoint's event (Task 4); Ruling 4; §5.7.
- **M9**: receipts deleted everywhere, said in `RevokeOwn`'s comment, Ruling 2, §5.1.4, notes.
- **M10**: `createExclusive` (link, never replace), absolute path and relative warning, `ownRevocationsFile` in `RevocationsFile` (Task 2).
- **M11**: `LiftNote` text, `RevokeResponse.Subject` printed, `y/N` on a terminal with `--yes` (Tasks 7, 8, 12).
- **M12**: the start keeps the marker beside a file that loads; test flipped; decision 32 says why (Tasks 1, 2).
- **M13**: the missing-file refusal leads with the volume (Task 2; operator trace).
- **M14**: a net release is never refused (`inServiceCount`); the line says to lower the bound again (Task 10; Ruling 8; §5.1.3; d34).
- **M15**: (a) catalogue deliberate; (b) chose per-policy compiled-program cache `Policy.permitsAlone` over a rate bound, which would need a reason §5.7 lacks (Task 9, d34); (c) `policy.bundle` on the record; (d) dashboard note.
- **M16**: `connection_ends_at`, and the CLI says a device ceiling may end a session sooner (Tasks 4, 12; Ruling 5; §12).
- **M17**: Task 4's pin test comment and Step 2 note.
- **M18**: `ErrRevocationBusy`, bounded wait, `503 revocation_busy` (Task 8); no re-check after the wait, commented; design §17 Errors.
- **M19**: `--list` points at the log (Task 12); burst alert and shell loop (notes); bulk lift to the unassigned list (Task 14).
- **M20**: `port49d` refuses a stray argument (Task 2 Step 5, checked in Step 7); identity record volume (notes).

## What this plan does not do

- **No shared store, and no separate broker process.** The broker still runs inside `port49d` on the
  memory store. `store.DeleteToken` is added to the interface, the memory store and the sealing
  layer, with a `storetest` property plan 7d's etcd backend must pass.
- **No OIDC.** `/v1/logout`, revocation by `sid`, and `/v1/config`'s issuer are plan 7h's. A
  `/v1/tokens/revoke` naming a `sid` is answered `400` saying so.
- **No directory.** A group subject's members are resolved by plan 7g. Until then a right is held
  only through a subject's `identity:` list, as minting is, and `/v1/identity`'s `groups` is empty.
- **No HTTP lift, and no HTTP revocation by certificate.** Both stay `port49 revoke` over
  port49d's admin socket, which only port49d's user and root can reach (Ruling 3).
- **No endpoint for `sync`, `keys_show` or `replay`** (Ruling 1).
- **The two unassigned follow-ups from 7b are not folded in.** Fencing `client_ca_file` and every
  `issuer_file`, and moving `inventory.WriteAtomic` to a leaf package, touch nothing this plan
  builds; they stay unassigned in the roadmap.

## Rulings where the design and spec are silent

Each takes the option that denies more, is written into the tasks named, and is recorded in spec
§13 as decision 34 by Task 1. None needs an owner decision.

1. **Rights.**
   - **What each unlocks.** `revoke_others` unlocks `/v1/tokens/revoke` naming another principal,
     or naming a `(device, username)` key whoever holds it. `explain_others` unlocks `/v1/explain`
     about another principal.
   - **Reserved rights.** `sync`, `keys_show` and `replay` are reserved: a subject may declare
     them, CI reports them and the gate fails on a gain (as today), and they grant nothing,
     because no broker endpoint triggers a sync, renders a key, or reads the log. The inventory
     service authorizes `POST /v1/sync` by its own `syncers` list (spec §10, design §17 internal
     interfaces), not by the policy's `sync`.
   - **No right widens a mint or a refresh.** `/v1/tokens` mints for the connection's principal
     alone, and `/v1/refresh` extends the connection's principal's contexts alone. A refresh is a
     fresh authentication event of the caller's own key (decision 17), so extending another
     principal's session would extend it with no one authenticating. 7b's carried item, `api:`
     rights over `RefreshSession`'s self-only rule, is ruled this way and pinned by a test.
   - **Identity is the caller's.** `/v1/identity` answers the caller alone, whatever its rights.
   - **The policy in force.** Rights are read from the policy in force at each request.
2. **Self-revocation leaves no mark** (7a's carried "self-revocation's shape").
   - **What it does.** `{"mine": true}`, or a principal equal to the caller, ends the caller's own
     sessions:
     - its unspent tokens are deleted one by one by ID;
     - its live contexts are marked revoked by compare-and-set on the revision read, twice, as
       7a's revocation marks twice;
     - its receipts are deleted, everywhere, even when it names one key: the store has no finer
       cut, so a retransmission in flight on another device is answered `token_spent`.
     With a `device` and `username` beside `mine`, it does that on one key only.
   - **Why no mark.** A mark is an operator's lock, which only port49d's user and root lift. A
     principal that marked itself could not lift it, and its agent would end on its next mint.
     With no mark, a token minted after the revocation joins the revoked context at the next login
     and lifts it (decision 15), which is what a principal ending its own sessions wants, **with
     one caveat the response says aloud**: the join lifts the mark for every session open under
     that `(device, username)`. If someone else used the leaked token, the owner's next login on
     that device re-admits that person's session too. So the text tells the caller to close such a
     session on the device (or ask an operator to revoke their principal) before logging in there
     again. The lab records the old session's state after the re-login (Task 13).
   - **Why it is still worth having.** The case is "I pasted a token into a chat": every unspent
     token is gone at once, and every session on a platform that asks about commands is ended.
   - **What it does not touch.** It closes no held connection, since the request arrives on one
     and nothing stops the agent reconnecting. It never marks a context another principal holds
     under a shared username, and never deletes another principal's token under a shared key.
3. **The HTTP revocation's other shapes.**
   - **Another principal** (`revoke_others`) is `Broker.Revoke`, a standing mark exactly as
     `port49 revoke --principal` makes, its origin `api <caller>`. `port49 revoke --list` shows
     who asked. The response names the target's subject, so a typo of a real colleague's address
     is seen at once, and on a terminal the CLI asks `y/N` first (`--yes` skips it).
   - **A `(device, username)` key without `mine`.** Under `revoke_others` it ends whatever holds
     the key: every unspent token under it, and the live context whoever's it is, with no mark.
     Without the right it is refused 403 `api_right_missing` and recorded with the key, never
     narrowed silently to the caller's own: an on-call whose right a reload withdrew minutes ago
     must not read "0 contexts marked" as "bob's session is gone". The caller's own session on one
     key is `{"mine": true, "device", "username"}` (`port49 revoke --mine --device --username`).
   - **What is refused.** A principal and a key together, `mine` beside a principal, an empty
     body, a `sid` (400, "arrives with OIDC, plan 7h"), and an unknown field such as `lift` (400).
   - **What stays on the admin socket.** A lift, and a revocation by certificate. A lift
     re-grants, so it stays with the people who can already rewrite the policy, and a
     certificate's mark needs the issuer and serial read from the certificate (`port49 revoke
     --cert`). The HTTP mark is still allowed with no `admin_socket` (revoking is the safe
     direction), and its text then says lifting it needs port49d stopped, the entry removed from
     `broker.revocations_file`, and a start; port49d's start line says the same.
   - **Busy.** A revocation that cannot take 7a's revocation slot within 10 s (another revocation
     or lift is running) is answered `503 revocation_busy` with `Retry-After`, nothing revoked. The
     right is read before that wait and not again after it, as a mint reads the policy once.
4. **Every call to an authenticated endpoint is one decision record** (design §17).
   - **New events and reason.** Two events are added, `identity` and `explain`, and one reason,
     `api_right_missing` (deny; HTTP 403).
   - **Refused before the body is read.** A call refused this way is recorded under its own event,
     for the reasons and with the meanings a mint has: no trusted certificate, a connection past
     `max_session_age`, a mark, a certificate status that refuses, marks unreadable. The
     listener's refusal as a connection binds is recorded under the event of the path the refused
     request asked for (`/v1/identity`, `/v1/explain`, `/v1/tokens/revoke`), and any other path
     stays `mint`.
   - **The `revoke` record.** It gains `by: self` and `by: key`, with `device` and `username`.
     Its `saved` is present only for a standing mark.
   - **One credential per record.** `auth.fingerprint` and `principal` always describe one
     credential, so a SIEM joining fingerprint to principal never pins one person's probe on
     another's certificate. A `revoke deny api_right_missing` names the target as `principal` (or
     the key as `device`, `username`), carries no `auth`, and names the caller in `origin`.
   - **The `explain` record.** It carries whom it was about (`principal`), no `auth`, who asked
     (`explain.asked_by` and `explain.asked_by_fingerprint`), the device, the bundle that answered
     (`policy.bundle`), and the answer. It never carries the command: the command is the caller's
     text, unvalidated as a decision input, and the record says only that one was asked
     (`explain.command: true`).
5. **`/v1/identity`.** It returns the principal, the method and the certificate's fingerprint, the
   subject, its grants unexpired at the request (scope, roles, `max_privilege`, `expires`), its
   `api:` rights, `groups` (empty until 7g), the connection's `auth_time` and
   `connection_ends_at` (`auth_time` plus `max_session_age`). That is when this connection must
   authenticate again, not when a device session ends: a role's session ceiling on a device may
   end one sooner, and the CLI says so.
   - **No device list.** Scopes are named, not enumerated: the caller can mint for its devices,
     and the API never lists the fleet.
   - **The record.** `identity permit grants_matched` with at least one grant, else `identity deny
     no_grants_matched`.
6. **`/v1/explain`.**
   - **The answer.** It is the broker's own: the policy in force, the mint's ordering (no grant
     before a quarantine or a refusal), then the daemon's evaluator.
   - **No device oracle.** A device the inventory does not name is answered `deny
     no_grants_matched` with the same text as a device the principal has no grant on, and neither
     names a platform.
   - **A principal under a mark** is answered `deny credential_revoked`, since nothing would be
     minted for it.
   - **What is returned.** The rendered text is redacted as `port49 explain`'s is, and session
     attributes are never returned.
   - **A role catalogue, deliberately.** A caller's own denied command returns, in its text,
     `Explanation.WouldPermit`: the names of every role in the policy whose permits would match it,
     held by anyone. That names
     roles, never who holds them or where, and it is the useful answer ("what to ask for").
   - **Cost.** `WouldPermit` matches every role's permits. Each role's permits are compiled once
     per platform per loaded policy and kept (`Policy.permitsAlone`, as `projected` memoizes
     projections), so a denied explain costs a match per role, no compile. That was chosen over a
     per-principal rate bound because a rate refusal would need a reason code §5.7 does not have,
     and every call must be one record.
   - **Bounds.** A command is at most 1024 printable characters.
7. **Health and readiness.**
   - **`/healthz`** answers `200 ok` while the broker's handler answers.
   - **`/readyz`** answers `200 serving` from the moment the broker serves until shutdown begins,
     and `503` with a fixed line before and after.
   - **Never wired in:** the store, certificate status, `port49_revocations_file_failed`. If every
     replica went unready on a store fault, every endpoint would be lost (design §12).
   - **Neither** needs a client certificate, and neither writes a record.
8. **The candidate reload guard (plan 4b, M3) is on, with the bound that exists.**
   - **The rule.** A policy reload, or a policy and inventory reload together, is refused when the
     devices it newly refuses plus the devices it newly quarantines, at the reload instant, are
     more than `inventory.max_removed_percent` (default 10) of the devices in service under the
     policy in force (admitted, and not quarantined).
   - **Why.** Unbounded, one bad edit puts most of the fleet on device-local break-glass (a
     quarantine's close, `tests/lab/results/quarantine-*.md`), which is the shared-password world
     port49 exists to remove.
   - **The cost.** A refused reload also keeps any grant the same edit withdrew. The refusal line
     says `port49 revoke` cuts someone off now, independent of the file.
   - **What is never refused.** A reload after which at least as many devices are in service as
     before it: an incident fix that releases 50 devices and quarantines 5 is a net release, and
     goes in. A reload that only releases quarantined devices is one of these.
   - **The refused file is still on disk.** A start has no policy in force to bound against, so a
     restart (a pod rescheduled, a crash, the next deploy) loads the refused file unguarded. The
     refusal line says so: `broker.policy_file` on disk is not what is serving; revert or fix it
     now. A guard at start against the last bundle in force is carried to plans 7e and 12.
   - **The line is redacted.** A quarantine's cause quotes policy text, so port49d prints the
     refusal through `platform.RedactQuoted` with the redactions of both the policy in force and
     the refused one, as `sayPolicy` does (spec §5.8), and `port49 inventory diff` prints it the
     same way.
   - **One knob, two bounds.** `inventory.max_removed_percent` also bounds inventory syncs, so the
     line says to lower it again once the reload is in force.
   - **What it does not reach.** A quarantine a grant expiry brings on later is not judged at the
     reload; `port49 policy diff` already fails on it in CI. An inventory-only reload stays decision
     20's, quarantining and moving on.
9. **The revocations file is never created by a start** (owner's ruling, 2026-10-02; amends
   decision 32).
   - **At start.** A missing file refuses every start. The message leads with the upgrade case
     (if port49d has run here before, the volume holding it is missing or empty: mount it or
     restore the file), and only then says to run `port49d init-revocations` once on a first
     install, so an operator whose volume did not mount is not steered into creating a file on the
     root filesystem. When the old marker is there, it says the revocations were lost.
   - **The marker beside a file that loads.** A start still writes the marker beside a file that
     loaded with none, as 7a's start did. That creates no revocations file, and it gives a
     config-managed install (file laid down by hand, never inited) the "revocations were lost"
     message if the file later goes missing, rather than "on a first install run init".
   - **`port49d init-revocations [--config FILE]`** runs once, at install, by hand or as a
     one-off job, and never on a start path (an init container, `ExecStartPre=`): wrapped to
     tolerate failure there, it would re-create the file on the next empty volume, the hazard this
     ruling removes. Its exits:
     - The file is there and loads: exit 0, "already initialized", nothing written, so an
       idempotent provisioning step needs no `|| true`.
     - The file is there and does not load: exit 1.
     - The marker is there and the file is not: exit 1, a lost file, never re-created.
     - Neither is there: it creates the marker, then the empty file, 0600 behind the directory
       fence. Each is created exclusively (a temporary file linked to its name, which fails if the
       name appeared), so a check-then-write race cannot replace a file.
   - **As port49d's user.** Init refuses unless the effective uid owns the revocations directory,
     naming the owner: `run as <user>, e.g. sudo -u <user> port49d init-revocations`. A root-run
     init would leave 0600 files that port49d, running as its own user, cannot read, so the first
     start would fail on `permission denied`. It never chowns.
   - **Where it writes.** It prints the absolute path, warns when `broker.revocations_file` is
     relative (resolved against the caller's directory, not port49d's), and makes `Load`'s checks
     that the path is not another file port49d uses (`admin_socket`, the spool, …).
   - **Deliberately empty.** Writing `{"revocations": []}` by hand stays the way to start empty on
     purpose.
10. **The lab measures the HTTP shapes on devices, with no new register row.** The device
    behaviour, a marked context's next command refused and Junos keeping its session, rests on 7a's
    `tests/lab/results/revoke-*.md`. The new claims are the HTTP paths: a self-revocation's re-login
    works with no lift and re-admits the session the revocation ended (decision 15's join,
    recorded), a key revocation by an on-call reaches another principal's session, and a caller
    with no right reaches nothing, by principal or by key. They are written to
    `tests/lab/results/api-revoke-*.md`.

**One reason and two events are added** (spec §5.7, by Task 1 before any code): the reason
`api_right_missing`, and the events `identity` and `explain`. The `revoke` event gains two `by`
values. No other reason code is added.

## Decisions for Ryan

**None for this plan.** Every choice above is a security-first ruling within the design. Two are
worth reading before the merge, because an operator will meet them:
- Ruling 8 makes a small fleet's first quarantining reload a refusal: three devices, one
  quarantined, is 33% against a 10% bound. The remedy is the existing knob.
- Ruling 2 means `port49 revoke --mine` ends sessions but does not lock the principal out, and
  the owner's next login on a device re-admits every session open there under their username.

## What the operator sees

The owner's rule is to trace a mechanism on a bad day first.

- **First install.** `port49d` refuses to start:

  ```
  port49d: broker.revocations_file /var/lib/port49/revocations.json: does not exist: if port49d has
  run here before, the volume holding it is missing or empty: mount it or restore the file; only on
  a first install, run 'port49d init-revocations' once, as port49d's user, with the same --config
  ```

  The operator runs `sudo -u port49 port49d init-revocations --config /etc/port49/port49d.yaml`,
  which prints `port49d: created broker.revocations_file /var/lib/port49/revocations.json with no
  revocations, and its marker …; run this once per install, never on a start path: …`, and starts
  port49d. Run as root by mistake, init refuses and says `run as port49, e.g. sudo -u port49
  port49d init-revocations`; nothing is written. Run again later, it prints `port49d:
  broker.revocations_file … is already initialized; nothing written` and exits 0.
- **3am, the revocations volume did not mount.** The same refusal, never a start with no marks,
  and its first words say to mount the volume. Break-glass works as with port49d stopped. If the
  file was there before and the marker is still beside it, `init-revocations` refuses too: a lost
  file is restored, never re-created.
- **3am, a token was pasted into a chat.** The operator runs `port49 revoke --mine`:

  ```
  ended user:alice@example.com's sessions everywhere at 2026-10-02T03:12:09Z: 2 live context(s)
  marked, the unspent tokens under 3 (device, username) key(s) deleted; nothing stands against
  user:alice@example.com, so a new `port49 token` and login work at once
  your next login on a device re-admits every session open there under your username: if anyone
  else used your token, close their session on the device (or ask an operator to revoke your
  principal) before you log in there again
  ```

  Their open sessions on EOS, NX-OS and IOS-XE refuse the next command (`port49: this session was
  revoked`). A Junos session is named as not reached. `port49 token core-sw01` and a new login work
  at once, and that login re-admits any session still open on core-sw01 under their username
  (decision 15's join), which is why the second line says to close a stranger's first.
- **3am, a stolen laptop, and the on-call holds `revoke_others`.** They run `port49 revoke
  --via-agent --principal user:bob@example.com`. On a terminal it asks `revoke user:bob@example.com
  everywhere? … [y/N]` (`--yes` skips the question). It prints `target: user:bob@example.com
  (subject netops)` and 7a's report, from their own laptop with no SSH to port49d, ending `the lift
  is made on port49d's admin socket (/run/port49/port49d.sock), by port49d's user or root`.
  `port49 revoke --list` on port49d shows `principal user:bob@example.com since … (api
  user:oncall@example.com)`. With no `admin_socket` configured the last line says instead that
  lifting needs port49d stopped, the entry removed from `broker.revocations_file`, and a start.
- **One wedged session.** `port49 revoke --via-agent --device core-sw01 --username bob` ends what
  holds that key. Bob can log in again at once, and that login re-admits any session still open
  there; the report says to close it on the device, and to stop bob, revoke the principal. `port49
  revoke --list` does not show it (nothing stands); it says on stderr that the decision log's
  `revoke` records name such revocations.
- **Someone without the right tries.** `port49 revoke --via-agent --principal user:bob@…` prints
  `port49 revoke: refused: revoking another principal needs the api: revoke_others right, which
  your subject does not declare` and exits 1. By key, `--via-agent --device core-sw01 --username
  bob` is refused the same way, and points at `--mine --device --username` for the caller's own
  session there. The log holds `revoke deny api_right_missing`, naming bob (or the key) as the
  target, the caller in `origin`, and no `auth`.
- **"What can I do?"** `port49 identity` prints the principal, subject, grants, rights, and until
  when this connection lasts. `port49 explain --device core-sw01 --command "reload"` answers from
  the broker's policy in force, with no policy file on the laptop.
- **A policy edit that quarantines most of the fleet:**

  ```
  port49d: policy reload (file changed) refused; still serving … (bundle …): broker.policy_file
  /etc/port49/policy.yaml: the new policy takes 412 of 430 devices in service out of it (95%), more
  than inventory.max_removed_percent (10%): it quarantines 412: core-sw01 (…), …; `port49 policy
  diff` names each cause; the policy in force keeps serving (to cut someone off now, use `port49
  revoke`); if the change is meant, raise inventory.max_removed_percent in port49d.yaml and send
  SIGHUP, which re-reads it with the reload, then lower it again, since it bounds inventory syncs
  too; the refused file is still on disk and is NOT what is serving: a restart of port49d would
  load it with no such bound, so revert or fix it now
  ```

  Each cause is redacted as port49d's other policy lines are. `port49_policy_file_refused` is 1.
  Devices keep being served on the policy in force until port49d restarts.
- **A Kubernetes probe** on the broker port: `GET /readyz` is `200 serving` while it serves, and
  stays 200 through a store outage (alarms say so instead).

## Global Constraints

Copied verbatim from `CLAUDE.md`, "Code conventions":

- Go 1.22+, module `github.com/rhwendt/port49`, `gofmt` and `go vet` clean, no cgo.
- **snake_case everywhere it is data**: YAML keys, JSON log keys, config, metric names.
- Reason codes are the closed vocabulary of spec §5.7 (`internal/decision/reasons.go`).
  Never invent one; add to the spec table first.
- The log never contains a token, password, challenge, or response. Credentials appear only
  as `credential_sha256`. An unvalidated body is never logged.
- No device identity in metric labels.
- Verify before claiming done: run `make test && make vet` and report the real output.

Carried from plans 2–7b, and still binding:

- **Every claim about device behaviour cites a `tests/lab/results/` note or a register row.** Lab
  register rules 1–4 apply. This plan opens no register row (Ruling 10).
- **Security first:** no privilege escalation, no impersonation, no secret in a log, fail closed.
  Where a task leaves a choice, take the one that denies more and say so in the commit.
- **Narrow setters only for live contexts.** The self-revocation marks through `SetContextPolicy`
  (`RevokedAt` alone, a compare-and-set), the key revocation through `SetRevokedAt`. Nothing re-puts
  a context.
- **7a's ordering holds for every revocation:** tokens before contexts, contexts twice. A standing
  mark is made only through `Broker.Revoke`.
- **A peer's or caller's text is printed only through `printsafe.Line`**, cut at 300 bytes, and
  never echoed into a record: a command sent to `/v1/explain` is not logged; a store error is
  logged with `b.logf`, and the API answers a fixed sentence.
- **No API leaks the fleet** (design §17): no answer tells a caller that a device exists unless it
  holds a grant on it, or holds `explain_others` and asked about a principal that does.

New in this plan:

- **No metric label names a principal, a device or a right.** The labels added are closed sets:
  `port49_revocations_total{by}` gains `self` and `key`. API calls are counted by
  `port49_decisions{event,verdict,reason}` alone.
- **The code blocks are written against `66faee6`.** Where the compiler or a test says a block is
  wrong about the tree, fix the block minimally, keep the behaviour the step's test asserts, and say
  so in the task's report and commit. Never weaken a test to make a block pass.
- **Every commit is preceded by `gofmt -w` on the Go files the task touched, then `make build &&
  make test && make vet`.** Report their real output.
- Branch `feature/api-and-authorization`; never commit code to `main`. Name every path in `git
  add`; never `git commit -a` (7a's 9e257ae).
- Commit messages end with:
  ```
  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
  ```

## Review Focus

The input classes the spec implies and no task's happy path exercises, most likely to bite first.
Each has its test in the task named.

1. **A caller with no right names another principal in another spelling.** For example
   `USER:Alice@Example.COM`, or the caller's own principal upper-cased. The target is normalized
   before it is compared with the caller, so the first is refused 403 and the second is a
   self-revocation; neither reaches `Broker.Revoke`. *Task 8,
   `TestARevocationIsComparedAsTheBrokerSpellsIt`.*
2. **A self-revocation racing another principal's login under the shared username.** The replace
   lands between the read and the mark, and the other principal's context is never marked. *Task
   7, `TestRevokeOwnNeverMarksAContextAnotherLoginReplaced`.*
3. **An explain of a device that does not exist and one the caller has no grant on.** The two
   bodies are identical but for the name. *Task 9,
   `TestAnUnknownDeviceIsAnsweredAsOneWithNoGrant`.*
4. **A reload against a fleet that already has a quarantine.** A reload that releases the
   quarantined device and quarantines nothing passes; the policy in force reloaded passes with three
   of four in service; one more quarantined of the three in service (33%) is refused; and a reload
   that releases one quarantined device and quarantines another, leaving as many in service as
   before, passes. *Task 10, `TestCheckAdmissionBoundsAPolicyThatQuarantinesTheFleet`.*
5. **port49d starts on a mounted but empty volume, or `init-revocations` finds a marker with no
   file, or runs as someone other than the directory's owner.** All refuse; nothing is written. An
   init over a file that loads exits 0 and writes nothing. *Task 2, `TestAStartNeverCreatesTheFile`,
   `TestInitRevocationsCreatesOnceAndNeverOverALoss`, `TestInitRevocationsRunsAsTheDirectorysOwner`.*
6. **A caller without `revoke_others` names a `(device, username)` with no `mine`.** Refused 403
   and recorded with the key, never answered as the caller's own sessions there. *Task 8,
   `TestRevokeOthersMarksAPrincipalAndEndsAKey`.*
7. **An explain about a device outside a scoped caller's grants that is quarantined, or refused
   admission.** Answered and recorded exactly as a device that does not exist. *Task 9,
   `TestAScopedCallerLearnsNothingOfADeviceOutsideItsGrants`.*

## Running the lab (Task 13)

The lab host is beehive. The owner has given standing consent for lab runs; the lab is
single-occupant.

**Every run is made from a detached worktree pinned to a commit:** `git worktree add --detach
../port49-lab-7c <sha>`, then `make build` there. Run one platform at a time:
`PORT49_LAB_PLATFORMS=eos`, then `nxos`, `iosxe`, `vjunos`.

**A stall watchdog runs for the whole run** (background, re-armed on every wake). Its signals are
the test log, capture growth and results files, with a 25-minute stall threshold. Match the test
binary exactly: `pgrep -f "^/tmp/go-build[^ ]*/lab\.test"`.

**After every platform,** confirm that no `port49d` holds `172.100.100.1:49`, that no agent is
running (`pgrep -f 'port49 agent'`), and that the topology is destroyed.

**Before removing the worktree,** copy the raw captures from its `tests/lab/captures/` to the main
checkout's `tests/lab/captures/`, then run `make evidence` there. Otherwise main's labpcap audit
fails.

## File Structure

```
docs/design/2026-08-23-policy-engine-spec.md   MOD  d32 amended; §2, §5.1.3, §5.1.4, §5.7, §12, §14, d34 (Task 1)
docs/design/2026-08-21-port49-design.md        MOD  §12 revocations-file row, readiness; §17 surface, errors (Task 1)
internal/config/config.go                      MOD  RevocationsFile(raw), with ownRevocationsFile's checks; comments (Task 2)
cmd/port49d/revocations.go                     MOD  no creation at start; readRevocations; initRevocations, initRevocationsCmd; createExclusive (Task 2)
cmd/port49d/initowner_linux.go, _other.go      NEW  initOwner: init runs as the directory's owner (Task 2)
cmd/port49d/main.go                            MOD  init-revocations dispatch, stray arguments; start line (Task 2); SetReady (Task 5); AdminSocket, start line (Task 8)
tests/lab/harness_test.go, inventory_test.go   MOD  write {"revocations": []} before a start (Task 2)
tests/lab/README.md                            MOD  the by-hand init step (Task 2)
internal/decision/reasons.go, log.go           MOD  api_right_missing; identity, explain; Explain; Revocation fields (Task 3)
internal/policy/load.go                        MOD  Right* constants; HasRight (Task 3); permitsAlone (Task 9)
internal/broker/broker.go                      MOD  authenticate; RefusedAtBind's event; routes; refuseRight; AdminSocket (Tasks 4, 8, 9)
internal/broker/listen.go                      MOD  Refused gains the request's path (Task 4)
internal/broker/identity_api.go                NEW  GET /v1/identity (Task 4)
internal/broker/api/identity.go                NEW  api.Identity (Task 4)
internal/broker/health.go                      NEW  /healthz, /readyz, SetReady (Task 5)
internal/store/store.go, memory, crypt         MOD  DeleteToken (Task 6)
internal/store/storetest/storetest.go          MOD  DeleteTokenRemovesOne (Task 6)
internal/daemon/authen/authen_test.go          MOD  noStore gains DeleteToken (Task 6)
internal/broker/revoke.go                      MOD  By, Key, LiftNote; normalPrincipal; unreachedOf; Text (Task 7); ErrRevocationBusy (Task 8)
internal/daemon/metrics/metrics.go             MOD  port49_revocations_total's help names self and key (Task 7)
internal/broker/revokeown.go                   NEW  RevokeOwn, RevokeKey (Task 7)
internal/broker/revoke_api.go                  NEW  POST /v1/tokens/revoke (Task 8)
internal/broker/api/revoke.go                  NEW  api.RevokeRequest, RevokeResponse (Task 8)
internal/policy/explain.go                     MOD  Explanation.Revoked, Answer; Render's no-grant line; wouldPermit's cache (Task 9)
internal/broker/explain_api.go                 NEW  POST /v1/explain (Task 9)
internal/broker/api/explain.go                 NEW  api.ExplainRequest, ExplainResponse (Task 9)
internal/bundle/diff.go                        MOD  NewlyQuarantined; CheckAdmission(…, now) (Task 10)
cmd/port49d/reload.go, cmd/port49/inventory.go MOD  pass the reload instant; the refusal redacted, and the restart warning (Task 10)
tests/lab/l31_test.go                          MOD  max_removed_percent 100 for its quarantining reload (Task 10)
internal/agent/agent.go, socket.go             MOD  call; Identity, Explain, Revoke; socket routes; Client; ErrAgentTooOld (Task 11)
cmd/port49/main.go, identity.go, policy.go, revoke.go  MOD/NEW  port49 identity; explain and revoke over the agent; --list's pointer (Task 12)
internal/testpki/testpki.go                    MOD  WriteLabWith, LabClientFiles (Task 13)
tests/lab/api_revoke_test.go                   NEW  the HTTP revocation end to end (Task 13)
tests/lab/slice/api-policy.yaml                NEW  the slice policy with an on-call and a peer (Task 13)
tests/lab/results/api-revoke-*.md              NEW  written by the run (Task 13)
docs/superpowers/plans/README.md               MOD  plan 7c as built (Task 14)
```

Fourteen tasks:
- **Task 1** is docs, and comes first: decision 32 is amended before any code, and every later
  task cites the text it writes.
- **Tasks 2–12** are code, and each leaves `make test` green:
  - 2: the revocations file's init;
  - 3: the vocabulary and the rights lookup;
  - 4 and 5: the shared preamble, `/v1/identity`, health;
  - 6 to 8: the store's per-token delete, the self and key revocations, and the endpoint;
  - 9: explain;
  - 10: the reload guard;
  - 11 and 12: the agent and the CLI.
- **Task 13** is the lab, and gates the merge.
- **Task 14** is docs: plan 7c as built.

---

### Task 1: The spec and the design say what plan 7c builds, decision 32 first

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`
- Modify: `docs/design/2026-08-21-port49-design.md`

No code. Each edit names a phrase to find and the text to put after it or in its place: the files
wrap their lines, so search for a phrase rather than a whole sentence. Nothing here asserts device
behaviour beyond what 7a's `tests/lab/results/revoke-*.md` measured.

- [ ] **Step 1: Decision 32, amended for the revocations file.** In §13 decision 32, replace

  ```markdown
  The marks are kept in `broker.revocations_file`, required with a
  broker, read behind the fence with its directory fenced whether or not the file exists, and
  created at the first start beside a marker; after that a missing file, or one that does not
  parse, refuses the start. Revocation is an admin-socket operation open to port49d's user and root;
  the HTTP one, under `api:` rights, is plan 7c's.
  ```

  (match on "created at the first start beside a marker") with

  ```markdown
  The marks are kept in `broker.revocations_file`, required with a
  broker, and read behind the fence with its directory fenced whether or not the file exists. A
  start never creates it: a missing file, or one that does not parse, refuses every start (amended
  2026-10-02 by the owner's ruling on plan 7a's Task 9 review M1: as first built, an unmounted or
  empty volume that passed the fence read as a first install and started with no marks).
  `port49d init-revocations` creates it, empty, beside a marker, once per install, run by hand or
  as a one-off job as the user that owns its directory (port49d's), and never on a start path:
  automation that ran it at every start and tolerated its refusal would re-create the file on the
  next empty volume. It exits 0 writing nothing when the file is there and loads, and refuses when
  the file is there and does not load, or when the marker is there without the file (a loss,
  restored from backup, never re-created). A start still writes the marker beside a file that
  loads with none: that creates no revocations file, and it makes a config-managed file's later
  loss read as a loss rather than as a first install. Writing `{"revocations": []}` by hand stays
  the way to start empty on purpose. Revocation is an admin-socket operation open to port49d's user
  and root, and over HTTP `POST /v1/tokens/revoke` under `api:` rights (plan 7c; decision 34).
  ```

- [ ] **Step 2: §2, the rights table.** Under "**What a subject may do through the broker API.**",
  replace the table and the paragraph after it (from `| Right | Unlocks |` to "…reads like one.")
  with:

  ```markdown
  | Right | Unlocks |
  |---|---|
  | `revoke_others` | `/v1/tokens/revoke` naming another principal (a standing mark), or a `(device, username)` key whoever holds it; by `sid` with OIDC (plan 7h) |
  | `explain_others` | `/v1/explain` for a principal other than the caller |
  | `sync` | reserved: no broker endpoint triggers a sync; the inventory service authorizes `POST /v1/sync` by its own `syncers` list (§10) |
  | `keys_show` | reserved: nothing renders a device key's secret (§12) |
  | `replay` | reserved: no endpoint reads the decision log |

  A reserved right may be declared, and CI reports it and the gate fails on a gain as for any
  other, but it grants nothing until an endpoint it guards exists (§13, decision 34). No right
  reaches `/v1/tokens` or `/v1/refresh`: a mint is for the connection's principal, and a refresh is
  a fresh authentication of the caller's own key (decision 17), so it extends the caller's
  sessions alone. `/v1/identity` answers the caller alone. Rights are read from the policy in force
  at each request, so a right withdrawn by a reload is gone at the next call; a group subject's
  members hold its rights once the directory resolves them (plan 7g).

  `/v1/logout` needs no right, since it authenticates by the identity provider's signature on
  the logout token rather than by a caller. CI reports every subject carrying an `api:` list,
  because it is a grant of authority over other people's sessions and reads like one.
  ```

- [ ] **Step 3: §5.1.3, step 1, the reload bound.** Replace "So is a file that refuses admission to
  more than `inventory.max_removed_percent` of the devices the policy in force admits, or that
  admits no device at all whatever the bound (§10)." with:

  ```markdown
  So is a file that takes more than `inventory.max_removed_percent` of the devices in
  service under the policy in force (admitted, and not quarantined) out of service at the reload,
  counting the devices it newly refuses admission and the devices it newly quarantines together,
  or that admits no device at all whatever the bound (§10; §13 decision 34). A reload after which
  at least as many devices are in service as before it is never refused (a net release), and a
  quarantine a grant expiry brings on later is not judged at the reload (`port49 policy diff`
  fails on it). A refused file also keeps any grant it withdrew: `port49 revoke` cuts a principal
  off whatever the file. A refused file stays on disk, and a start has no policy in force to bound
  against, so a restart would load it unguarded: port49d's refusal line says so, redacted as its
  other policy lines are (§5.8).
  ```

- [ ] **Step 4: §5.1.4, the HTTP revocation.** After the paragraph that begins "**Revocation by
  principal or by certificate, as built (plan 7a" (it ends "…each as a mark of this kind where the
  certificate is still held (see below)."), add:

  ```markdown
  **Over HTTP, as built (plan 7c; §13, decision 34).** `POST /v1/tokens/revoke` takes one of three
  bodies, and is refused 400 for any other (a principal and a key together, `mine` beside a
  principal, a `sid` until plan 7h, an unknown field):

  - **`{"mine": true}`, or a principal equal to the caller's**, ends the caller's own sessions and
    leaves no mark. Its unspent tokens are deleted one by one, so another principal's under a
    shared `(device, username)` stay. Its live contexts are marked by compare-and-set on the
    revision read, so a context another principal's login replaced is never marked, and they are
    marked twice. Its receipts are deleted everywhere, even with a key named: the store has no
    finer cut, so a retransmission in flight on another device is answered `token_spent`. With
    `device` and `username` beside `mine` it does that on that key alone. Nothing stands after it:
    a token minted later joins the context and lifts the mark (decision 15), for every session
    open under that `(device, username)`. So if anyone else used the caller's token, the caller's
    next login on that device re-admits their session too: the response says to close such a
    session on the device, or ask an operator to revoke the principal, before logging in there
    again.
  - **`{"principal": …}` naming another principal**, under `revoke_others`, is the revocation
    above, a standing mark, with origin `api <caller>`; without the right it is refused 403
    `api_right_missing` and recorded. The response names the target's subject. A lift is made on
    port49d's admin socket; with no `admin_socket` configured the response says lifting needs
    port49d stopped, the entry removed from this file, and a start.
  - **`{"device": …, "username": …}`**, under `revoke_others`, ends whatever holds that key: every
    unspent token under it, and its live context whoever's it is, with the owner's receipts. It
    leaves no mark, so the owner's next login on that device re-admits any session still open
    there: the response says to close it on the device. Without the right it is refused 403
    `api_right_missing` and recorded with the key: the request's form, never the caller's rights,
    decides what it means, and the caller's own session on one key is `mine` with the key.

  A lift and a revocation by certificate are the admin socket's alone. One that cannot take the
  revocation slot within 10 s is answered `503 revocation_busy`, nothing revoked. The response
  says what was reached, names the contexts on a platform that never asks about a command, and
  repeats the text `port49 revoke` prints.
  ```

- [ ] **Step 5: §5.7, the events.**
  - Replace "One envelope. Seven decision events," with "One envelope. Nine decision events,".
  - In the events table, after the `revoke` row, add:

    ```markdown
    | `identity` | broker | what `GET /v1/identity` resolved the caller to: `permit grants_matched` when its subject holds a grant unexpired now, else `deny no_grants_matched` (design document §17) |
    | `explain` | broker | a hypothetical decision `POST /v1/explain` answered, about the caller or, under `explain_others`, another principal: its verdict and reason are the answer given, or `deny api_right_missing`. It authorizes nothing, and replay passes over it |
    ```

  - Replace the `revoke` row's text with: "a revocation by principal or by certificate (§5.1.4):
    what it reached, and the live contexts it could not; a revocation lifted; or, over HTTP, a
    principal ending its own sessions (`by: self`) or a `(device, username)` key ended (`by: key`),
    neither leaving a mark".
  - Replace "as the ninth event, `account`" with "as the eleventh event, `account`".
  - Replace "A tenth, `account_gap`" with "A twelfth, `account_gap`".
  - Replace "An eleventh, `inventory_change`" with "A thirteenth, `inventory_change`".

- [ ] **Step 6: §5.7, the `revoke` body and the API records.** In the paragraph that begins "A
  `revoke` record (plan 7a) is written once per revocation or lift that takes force", make three
  edits.

  First, replace `"revocation": {"by", "issuer", "serial", "at",
  "origin", "contexts", "token_keys", "connections", "unreached", "saved", "error"}`: `by` is
  `principal` or `cert`` with:

  ```markdown
  `"revocation": {"by", "issuer", "serial", "device", "username", "at",
  "origin", "contexts", "token_keys", "connections", "unreached", "saved", "error"}`: `by` is
  `principal` or `cert` for a standing mark, `self` for a principal ending its own sessions, and
  `key` for one `(device, username)` ended; `device` and `username` name a `key` revocation's key,
  or a `self` one limited to a key
  ```

  Second, replace "`origin` is who
  asked (`admin_socket uid <n>`, e.g. `admin_socket uid 0`);" with "`origin` is who asked
  (`admin_socket uid <n>`, e.g. `admin_socket uid 0`, or `api <principal>` over HTTP);".

  Third, replace "`saved` whether `broker.revocations_file` was written;" with "`saved` whether
  `broker.revocations_file` was written, present only for a standing mark;".

  After the paragraph, add:

  ```markdown
  A `self` or `key` revocation writes one record each time it runs; its `principal` is the caller
  for `self`, and for `key` the owner of the context it found, if one was read. A record's `auth`
  and `principal` always describe one credential, so a record about someone other than the caller
  carries no `auth`. A `revoke deny api_right_missing` names the target as `principal` (or the key
  as `device` and `username`, with no `principal`), carries no `auth`, and names the caller in
  `origin`. An `explain` record names whom it was about as `principal`, carries no `auth`, names
  the device (no platform where the answer is `no_grants_matched`) and the bundle that answered
  (`policy.bundle`), and has `"explain": {"asked_by", "asked_by_fingerprint", "command",
  "mint_error"}`: `asked_by` and `asked_by_fingerprint` are the caller's principal and certificate,
  `command` is true when a command was asked, and the command itself is never recorded. Where the
  broker would mint no token (`mint_error`, a mint item error), the record has no verdict. An API
  call refused before its body is read, for a reason a mint is refused (`trust_domain_unresolved`,
  `session_expired`, `credential_revoked`, `store_unavailable`, with their `mint` meanings), is
  recorded under its own event: `identity`, `explain`, or `revoke`, the caller as `principal` with
  its `auth`. So is one the broker's listener refuses as the connection binds, by the path the
  refused request named; any other path is recorded `mint`.
  ```

- [ ] **Step 7: §5.7, the reason.** In the reason-code table, after the `revocation_lifted` row,
  add:

  ```markdown
  | `api_right_missing` | `revoke`, `explain`: the caller asked to act on another principal's tokens, sessions or decisions, or on a `(device, username)` whoever holds it, and its subject declares no `api:` right that unlocks it (§2). The API answers 403 `api_right_missing`; nothing is done |
  ```

- [ ] **Step 8: §12, tooling.** After the paragraph that begins "**`port49 revoke (--principal
  <principal>`", replace its last sentence "The HTTP revocation, under `api:`
  rights, is plan 7c's." with nothing, and add after the paragraph:

  ```markdown
  **`port49 revoke --mine [--device <name> --username <name>]`** and **`port49 revoke --via-agent
  [--yes] (--principal <principal> | --device <name> --username <name>)`** send the revocation to
  the broker through the operator's own agent (`POST /v1/tokens/revoke`, §5.1.4), under the
  caller's `api:` rights (§2): `--mine` ends the caller's own sessions, or its session on one key,
  and leaves no mark; `--via-agent --principal` revokes another principal as the admin socket
  does, and needs `revoke_others`; `--via-agent --device --username` ends whatever holds that key,
  and needs `revoke_others` too. `--via-agent --principal` asks `y/N` on a terminal first
  (`--yes` skips it; off a terminal it does not ask), and prints the target's subject from the
  answer. A lift, a certificate and `--list` stay the admin socket's; `--list` shows marks only,
  and says on stderr that a self or key revocation, which leaves none, is named in the decision
  log. Exit codes are as above.

  **`port49 identity [--json]`** prints what the broker resolves the agent's principal to (`GET
  /v1/identity`): subject, grants unexpired now, `api:` rights, and until when this connection
  lasts before it must authenticate again (`connection_ends_at`; a device's own session ceiling may
  end a session sooner).

  **`port49 explain --device <name> [--command "<line>"] [--principal <principal>]`**, with no
  `--policy` and `--inventory`, asks the broker through the agent (`POST /v1/explain`) and prints
  its answer from the policy in force, redacted as the offline form's is; `--principal` naming
  another principal needs `explain_others`, and `--subject` and `--show-attributes` are the offline
  form's alone.

  **`port49d init-revocations [--config <port49d.yaml>]`** creates `broker.revocations_file`,
  empty, and its marker, once per install, behind the directory fence, reading nothing from
  port49d.yaml but that path and the paths it must not collide with (no secret is resolved). It
  runs as the user that owns the file's directory, port49d's, and refuses otherwise, naming that
  user. Run it by hand or as a one-off job at install, never on a start path. It exits 0 when it
  created both, or when the file is already there and loads ("already initialized", nothing
  written); 1 when the file is there and does not load, or the marker is there without it (a lost
  file is restored from backup, or replaced by `{"revocations": []}` on purpose; §13, decision
  32); 2 on usage.
  ```

- [ ] **Step 9: §14, API rights.** Replace the broker's "**API rights**" bullet, the one that
  begins "a principal without `api:` can revoke its own tokens and not another's" (§14 has a
  second, the inventory service's "a reader cannot trigger a sync", which stays), with:

  ```markdown
  - **API rights**: a principal without `api:` can end its own sessions and delete its own
    unspent tokens, never another's, including another principal's under a shared `(device,
    username)`, and never marks a context another login replaced; `revoke_others` unlocks a
    standing mark on another principal and ending any `(device, username)`; `explain_others`
    unlocks explaining another principal; a request without the right, a `(device, username)`
    without `mine` included, is refused 403 `api_right_missing` and recorded with no `auth`; no
    right widens a mint or a refresh; an unknown device, and one outside the caller's grants that
    is quarantined or refused admission, is explained exactly as one with no grant; `/v1/logout`
    succeeds with a valid logout token and no caller rights; every subject carrying `api:` appears
    in the CI report.
  ```

- [ ] **Step 10: §13, decision 34.** After decision 33 (it ends "(§5.1.4, §5.6, §5.7, §12; design
  document §7, §12, §17)"), add:

  ```markdown
  **34. A principal acts on itself unless a right says otherwise, ends its own sessions without a
  mark, and a reload cannot take the fleet out of service.** *Plan 7c, 2026-10-02, rulings where
  the design was silent, each the option that denies more.*

  - **Rights.** `revoke_others` and `explain_others` unlock what §2 says; `sync`, `keys_show` and
    `replay` are reserved and grant nothing, since no broker endpoint they would guard exists. No
    right widens a mint or a refresh, and `/v1/identity` answers the caller alone. Rights are read
    from the policy in force at each request.
  - **Self-revocation.** It deletes the caller's own unspent tokens one by one and marks its own
    contexts by compare-and-set, twice, deletes its receipts everywhere, and leaves no mark, so a
    token minted after it re-admits (decision 15). That re-admission is the join's: it lifts the
    mark for every session open under that `(device, username)`, a stranger's on a leaked token
    included, so the response tells the caller to close such a session on the device, or have an
    operator revoke the principal, before logging in there again. It closes no held connection.
  - **Others.** Another principal under `revoke_others` is a standing mark through the admin
    socket's revocation, its origin `api <caller>`, and the response names the target's subject. A
    `(device, username)` under it is ended whoever holds it, with no mark, and the owner's next
    login there re-admits any session still open, which the response says to close. Without the
    right either form is refused 403: the request's form, not the caller's rights, decides what it
    means, so a withdrawn right fails loudly instead of narrowing to the caller's own; the caller's
    own session on one key is `mine` with the key. A lift and a certificate stay on the admin
    socket; an HTTP mark is still made with no `admin_socket` configured (revoking is the safe
    direction), and the response and port49d's start line say lifting it then needs port49d
    stopped and the file edited.
  - **Records.** Every authenticated call is one record: the events `identity` and `explain` and
    the reason `api_right_missing` are added; a call refused before its body is read, or as its
    connection binds, is recorded under its own event with a mint's reasons; an explain never
    records its command. A record's `auth` and `principal` describe one credential: a record about
    someone other than the caller carries no `auth`, and names the caller in `origin` or in
    `explain.asked_by` and `explain.asked_by_fingerprint`.
  - **Explain.** It answers as the broker mints and the daemon decides, from the policy in force,
    and its record names the bundle. An unknown device is answered exactly as a device with no
    grant, naming no platform, and a principal under a mark is `credential_revoked`. A caller's
    own denied command is answered, in its text, with the name of every role in the whole policy
    whose permits would match it, deliberately: a role catalogue, never who holds a role or where. Each role's permits are compiled once per
    platform per loaded policy, as projections are memoized, so a denied explain costs a match per
    role; a per-principal rate bound was not chosen, since its refusal would need a reason code
    this vocabulary lacks and every call is one record.
  - **Health.** `/healthz` and `/readyz` need no certificate and write no record; readiness is
    serving or not, never the store's health (design document §12).
  - **The reload guard** (plan 4b, M3). A policy reload that newly refuses or newly quarantines,
    together, more than `inventory.max_removed_percent` of the devices in service is refused, the
    policy in force serving on, unless at least as many devices are in service after it as before
    (a net release, which an incident fix often is; it also admits a policy and inventory reload
    that adds devices while quarantining others). The refusal is printed redacted (§5.8), says to
    lower the bound again after a deliberate raise (it bounds inventory syncs too), and says the
    refused file is still on disk and a restart would load it unguarded: a start has no policy in
    force to bound against. An inventory-only reload stays decision 20's.
  - **The revocations file.** A start never creates it (decision 32, amended the same day), and
    `port49d init-revocations` runs once, as the directory's owner, never on a start path.

  (§2, §5.1.3, §5.1.4, §5.7, §12, §14; design document §12, §17)
  ```

- [ ] **Step 11: Design §12, the failure matrix and readiness.** In the "**Revocations file missing
  or refused**" row, replace "(`broker.revocations_file` absent after the first start, unparseable,
  or writable by someone else;" with "(`broker.revocations_file` absent, including on an empty or
  unmounted volume, unparseable, or writable by someone else; port49d never creates it, `port49d
  init-revocations` does, once;". In the same row's last cell, replace "Restore the file, or write
  `{"revocations": []}` on purpose" with "Mount the volume or restore the file, or write
  `{"revocations": []}` on purpose; on a first install, run `port49d init-revocations` once, as
  port49d's user, never on a start path".

  After the paragraph that begins "**Store health MUST NOT be wired into the readiness probe.**",
  add: "The broker's own `/readyz` (plan 7c) follows the same rule: it answers whether the broker
  is serving, and never the store, certificate status, or `broker.revocations_file`'s health,
  which are alarms."

- [ ] **Step 12: Design §17, surface and errors.**
  - Replace the surface line `GET   /healthz  /readyz` with `GET   /healthz  /readyz   unauthenticated; readiness is serving or not, never store health (§12)`.
  - Replace `POST  /v1/tokens/revoke   by principal, OIDC sid, or (device, username); a token is never sent back` with `POST  /v1/tokens/revoke   mine; by principal or (device, username); OIDC sid with plan 7h; a token is never sent back`.
  - In the **Errors** block, add these lines after the `400  bad_request` line:

    ```
    403  api_right_missing                the call names another principal, or a (device, username) whoever holds it, and the caller's subject declares no api: right that unlocks it (plan 7c)
    503  revocation_busy                  another revocation or lift held the revocation slot for 10 s; nothing was revoked; Retry-After (plan 7c)
    ```

  - After the paragraph that begins "**Every call is authorized as a principal, and by default a
    principal acts only on itself.**", add: "As built (plan 7c; policy engine spec §13 decision 34):
    a principal ending its own sessions leaves no standing mark; revoking another principal is the
    admin socket's standing mark, its origin the caller; `sync`, `keys_show` and `replay` are
    reserved until an endpoint they guard exists; and every authenticated call writes one decision
    record."

- [ ] **Step 13: Check the edits and commit.**

  Run: `make test && make vet` (docs only; both must pass unchanged).

  ```bash
  git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
  git commit -m "docs: amend decision 32 and specify plan 7c's API rights, revocation, explain and reload guard

  Decision 32 amended by the owner's ruling of 2026-10-02: port49d never creates
  broker.revocations_file; port49d init-revocations does, once. Decision 34 records
  plan 7c's rulings; spec §5.7 gains the identity and explain events and the
  api_right_missing reason.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 2: A start never creates the revocations file; `port49d init-revocations` does, once

**Files:**
- Modify: `internal/config/config.go` (beside `InventoryBound`, ~line 487; the spool default in
  `Load`, ~line 631; the comments on `BrokerConfig.RevocationsFile`, ~lines 205–212, and on
  `ownRevocationsFile`, ~lines 1155–1160)
- Modify: `cmd/port49d/revocations.go` (`loadRevocations` splits into `readRevocations` and
  itself; `writeMarker`, `saveRevocations` and `restoreRevocations`; new `markerBody`,
  `encodeRevocations`, `createExclusive`, `initRevocations`, `initRevocationsCmd`)
- Create: `cmd/port49d/initowner_linux.go`, `cmd/port49d/initowner_other.go` (`initOwner`)
- Modify: `cmd/port49d/main.go` (`main`, ~line 64; the start line in `run`, ~lines 677–690)
- Modify: `cmd/port49d/revocations_test.go`; `cmd/port49d/broker_test.go` (`brokerConfig`, ~line
  37; the run-level test that waits for "created", ~line 720; the restore test's
  `restoreRevocations` call, ~line 765)
- Create: `cmd/port49d/initowner_linux_test.go`
- Modify: `internal/config/config_test.go`
- Modify: `tests/lab/harness_test.go` (`privatePolicy`, ~line 879), `tests/lab/inventory_test.go`
  (the config at ~line 327), `tests/lab/private_policy_unit_test.go`, `tests/lab/README.md`

Every other `cmd/port49d` test that starts port49d with a broker builds its config through
`brokerConfig` (checked: `admin_linux_test.go`, `certstatus_test.go`, `reload_test.go`,
`run_test.go`, `service_e2e_test.go`, `coldstart_policy_test.go`, `policyfile_test.go`,
`redact_test.go`), so initialising there covers them.

**Interfaces:**
- Consumes: `fence.CheckDir`, `fence.ReadNoLink`, `fence.FileOwner`, `fence.Geteuid` (a var, on
  Linux); `writeMarker`, `saveRevocations`, `markerOf` (all in `cmd/port49d/revocations.go`);
  `config.ReadRegular`, `config.MaxConfigSize`, `ownRevocationsFile`.
- Produces:
  - `func config.RevocationsFile(raw []byte) (string, error)`; `const defaultSpoolPath`
  - `func readRevocations(path string) ([]store.Revocation, error)` (fence, read, parse; writes
    nothing)
  - `func loadRevocations(path string) ([]store.Revocation, error)` (the `created` result is
    gone; it still writes the marker beside a file that loads with none)
  - `func restoreRevocations(ctx context.Context, st store.Store, path string, m *metrics.Metrics) ([]store.Revocation, error)`
  - `func markerBody(abs string) []byte`, `func encodeRevocations(rs []store.Revocation) ([]byte, error)`
  - `func createExclusive(abs string, body []byte) error`
  - `func initOwner(dir string) error`
  - `func initRevocations(path string) (created bool, err error)`
  - `func initRevocationsCmd(args []string, stdout, stderr io.Writer) int`

- [ ] **Step 1: Write the failing tests.** In `cmd/port49d/revocations_test.go`, replace
  `TestTheFirstStartCreatesTheFileAndALaterMissingOneRefuses` with the tests below (its hand-laid
  half is `TestAHandLaidFileLoadsAndGetsAMarker`). Move every other call to the two-result
  signatures: `_, _, err := loadRevocations(…)` becomes `_, err :=` (~lines 118, 125, 148, 180,
  187), `rs, _, err` becomes `rs, err` (~lines 284, 333), and `restoreRevocations` at ~line 163
  likewise. `TestTheDirectoryIsFencedWithOrWithoutTheFile` keeps its last check, that no `.created`
  was written in a refused directory. `TestRevocationsSurviveARestart` (~line 32) can no longer
  start on an empty directory: its first start becomes `if created, err := initRevocations(path);
  err != nil || !created { t.Fatalf("init: %v %v", created, err) }`, and its later restore reads
  `rs, err := restoreRevocations(ctx, after, path, m)` and checks `err != nil || len(rs) != 2`.

  ```go
  // A start never creates the file (spec §13 decision 32, amended
  // 2026-10-02): a fresh directory, or a mounted volume left empty, refuses
  // every start and writes nothing. The refusal leads with the upgrade case,
  // so an operator whose volume did not mount mounts it rather than running
  // the first-install init on an empty mount point (pre-flight M13).
  func TestAStartNeverCreatesTheFile(t *testing.T) {
  	path := filepath.Join(safeDir(t), "revocations.json")
  	for i := 0; i < 2; i++ {
  		_, err := loadRevocations(path)
  		if err == nil || !strings.HasPrefix(err.Error(), "does not exist: if port49d has run here before, the "+
  			"volume holding it is missing or empty") || !strings.Contains(err.Error(), "port49d init-revocations") {
  			t.Fatalf("start %d on an empty directory: %v", i, err)
  		}
  	}
  	for _, p := range []string{path, markerOf(path)} {
  		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
  			t.Fatalf("a start wrote %s: %v", p, err)
  		}
  	}
  }

  // init writes the marker and an empty file, 0600, and a start loads them.
  // Run again over a file that loads, it writes nothing and says so, so a
  // provisioning step may run it twice (pre-flight I6). Over a file that does
  // not load it refuses and leaves it. Over a lost file (the marker still
  // there) it refuses, so it never papers over revocations that were lost; a
  // start then says they were lost.
  func TestInitRevocationsCreatesOnceAndNeverOverALoss(t *testing.T) {
  	path := filepath.Join(safeDir(t), "revocations.json")
  	if created, err := initRevocations(path); err != nil || !created {
  		t.Fatalf("the first init: %v %v", created, err)
  	}
  	for _, p := range []string{path, markerOf(path)} {
  		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
  			t.Fatalf("%s: %v %v", p, fi, err)
  		}
  	}
  	if rs, err := loadRevocations(path); err != nil || len(rs) != 0 {
  		t.Fatalf("the start after init: %v %v", rs, err)
  	}
  	before, err := os.ReadFile(path)
  	if err != nil {
  		t.Fatal(err)
  	}
  	if created, err := initRevocations(path); err != nil || created {
  		t.Fatalf("a second init over a file that loads: %v %v", created, err)
  	}
  	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(before, after) {
  		t.Fatalf("a second init wrote the file: %q %v", after, err)
  	}
  	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
  		t.Fatal(err)
  	}
  	if _, err := initRevocations(path); err == nil || !strings.Contains(err.Error(), "does not load") {
  		t.Fatalf("an init over a file that does not load: %v", err)
  	}
  	if got, _ := os.ReadFile(path); string(got) != "{" {
  		t.Fatalf("init replaced a file that does not load: %q", got)
  	}
  	if err := os.Remove(path); err != nil {
  		t.Fatal(err)
  	}
  	if _, err := initRevocations(path); err == nil || !strings.Contains(err.Error(), "never re-creates a lost file") {
  		t.Fatalf("an init over a lost file: %v", err)
  	}
  	if _, err := loadRevocations(path); err == nil || !strings.Contains(err.Error(), "its marker says") {
  		t.Fatalf("a start after the loss: %v", err)
  	}
  	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
  		t.Fatalf("a refused init or start wrote the file: %v", err)
  	}
  }

  // A file laid down by hand loads, and the start writes the marker beside
  // it, as 7a's start did (spec §13 decision 32; pre-flight M12): that
  // creates no revocations file, and the file's later loss then refuses the
  // start as a loss, never as a first install.
  func TestAHandLaidFileLoadsAndGetsAMarker(t *testing.T) {
  	path := filepath.Join(safeDir(t), "revocations.json")
  	if err := os.WriteFile(path, []byte(`{"revocations": []}`), 0o600); err != nil {
  		t.Fatal(err)
  	}
  	if rs, err := loadRevocations(path); err != nil || len(rs) != 0 {
  		t.Fatalf("%v %v", rs, err)
  	}
  	if _, err := os.Lstat(markerOf(path)); err != nil {
  		t.Fatalf("no marker beside a file that loaded: %v", err)
  	}
  	if err := os.Remove(path); err != nil {
  		t.Fatal(err)
  	}
  	if _, err := loadRevocations(path); err == nil || !strings.Contains(err.Error(), "its marker says") {
  		t.Fatalf("a start after a hand-laid file was lost: %v", err)
  	}
  }

  // init is fenced as a start is: a directory others can write is refused
  // and nothing is written.
  func TestInitRevocationsIsFenced(t *testing.T) {
  	open := safeDir(t)
  	if err := os.Chmod(open, 0o777); err != nil {
  		t.Fatal(err)
  	}
  	path := filepath.Join(open, "revocations.json")
  	if _, err := initRevocations(path); err == nil {
  		t.Fatal("init wrote into a directory others can write")
  	}
  	for _, p := range []string{path, markerOf(path)} {
  		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
  			t.Fatalf("a refused init wrote %s", p)
  		}
  	}
  }

  // A file that appears between init's look and its write is never
  // replaced: the create is a link, which fails on an existing name
  // (pre-flight M10).
  func TestCreateExclusiveNeverReplaces(t *testing.T) {
  	path := filepath.Join(safeDir(t), "revocations.json")
  	if err := os.WriteFile(path, []byte("theirs"), 0o600); err != nil {
  		t.Fatal(err)
  	}
  	if err := createExclusive(path, []byte("ours")); !errors.Is(err, fs.ErrExist) {
  		t.Fatalf("over an existing file: %v", err)
  	}
  	if got, _ := os.ReadFile(path); string(got) != "theirs" {
  		t.Fatalf("replaced: %q", got)
  	}
  	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".revocations.json.init-*")); len(left) != 0 {
  		t.Fatalf("temporary files left: %v", left)
  	}
  }

  // The command reads broker.revocations_file and nothing else: a config
  // whose secrets are not in the environment still inits, and a second run
  // says the file is already initialized, exit 0. One with no broker block is
  // refused, exit 1; stray arguments are usage, exit 2.
  func TestInitRevocationsCmdReadsOnlyThePath(t *testing.T) {
  	dir := safeDir(t)
  	path := filepath.Join(dir, "revocations.json")
  	cfg := filepath.Join(dir, "port49d.yaml")
  	body := "encryption: {current: {id: k1, secret_env: PORT49_TEST_UNSET_SECRET}}\n" +
  		"broker:\n  revocations_file: " + path + "\n"
  	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
  		t.Fatal(err)
  	}
  	var out, errb bytes.Buffer
  	if code := initRevocationsCmd([]string{"--config", cfg}, &out, &errb); code != 0 ||
  		!strings.Contains(out.String(), "created broker.revocations_file "+path) ||
  		!strings.Contains(out.String(), "never on a start path") {
  		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
  	}
  	out.Reset()
  	if code := initRevocationsCmd([]string{"--config", cfg}, &out, &errb); code != 0 ||
  		!strings.Contains(out.String(), path+" is already initialized; nothing written") {
  		t.Fatalf("the second run: code %d stdout %q stderr %q", code, out.String(), errb.String())
  	}
  	if err := os.WriteFile(cfg, []byte("listen: 127.0.0.1:49\n"), 0o600); err != nil {
  		t.Fatal(err)
  	}
  	if code := initRevocationsCmd([]string{"--config", cfg}, &out, &errb); code != 1 ||
  		!strings.Contains(errb.String(), "no broker.revocations_file") {
  		t.Fatalf("no broker block: code %d stderr %q", code, errb.String())
  	}
  	if code := initRevocationsCmd([]string{"extra"}, &out, &errb); code != 2 {
  		t.Fatalf("usage: %d", code)
  	}
  }
  ```

  If the `encryption:` line does not decode against the real schema, use whatever key
  `fileConfig` names for it. The point of the test is a config that `config.Load` would refuse for
  a missing secret and `RevocationsFile` reads. `revocations_test.go` gains the `bytes` and
  `io/fs` imports if it lacks them.

  Create `cmd/port49d/initowner_linux_test.go`:

  ```go
  //go:build linux

  package main

  import (
  	"errors"
  	"os"
  	"path/filepath"
  	"strings"
  	"testing"

  	"github.com/rhwendt/port49/internal/fence"
  )

  // init runs as the revocations directory's owner, port49d's user, or not
  // at all: a root-run init would leave 0600 files port49d cannot read, and
  // the first start would fail on "permission denied" (pre-flight I5). The
  // refusal names the owner and the sudo line, and nothing is written; it
  // never chowns. It is asked before the fence, whose own refusal would say
  // "chown it".
  func TestInitRevocationsRunsAsTheDirectorysOwner(t *testing.T) {
  	path := filepath.Join(safeDir(t), "revocations.json")
  	defer func(f func() int) { fence.Geteuid = f }(fence.Geteuid)
  	fence.Geteuid = func() int { return os.Geteuid() + 1 }
  	_, err := initRevocations(path)
  	if err == nil || !strings.Contains(err.Error(), "e.g. sudo -u ") ||
  		!strings.Contains(err.Error(), " port49d init-revocations") || strings.Contains(err.Error(), "chown") {
  		t.Fatalf("%v", err)
  	}
  	for _, p := range []string{path, markerOf(path)} {
  		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
  			t.Fatalf("a refused init wrote %s", p)
  		}
  	}
  }
  ```

  In `internal/config/config_test.go`:

  ```go
  // RevocationsFile reads the one path init-revocations needs, as strictly as
  // Load decodes, resolves no secret, and refuses a path Load would refuse as
  // another file port49d uses (pre-flight M10).
  func TestRevocationsFileReadsThePathAlone(t *testing.T) {
  	got, err := RevocationsFile([]byte("broker:\n  revocations_file: /var/lib/port49/revocations.json\n"))
  	if err != nil || got != "/var/lib/port49/revocations.json" {
  		t.Fatalf("%q %v", got, err)
  	}
  	if _, err := RevocationsFile([]byte("broker:\n  revocation_file: x\n")); err == nil {
  		t.Fatal("a misspelt key was read as no path")
  	}
  	if _, err := RevocationsFile([]byte("listen: 127.0.0.1:49\n")); err == nil ||
  		!strings.Contains(err.Error(), "no broker.revocations_file") {
  		t.Fatalf("no broker: %v", err)
  	}
  	if _, err := RevocationsFile([]byte("admin_socket: /var/lib/port49/r.json\nbroker:\n" +
  		"  revocations_file: /var/lib/port49/r.json\n")); err == nil || !strings.Contains(err.Error(), "may not be admin_socket") {
  		t.Fatalf("revocations_file over admin_socket: %v", err)
  	}
  }
  ```

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./cmd/port49d/ -run 'TestAStartNeverCreatesTheFile|TestInitRevocations|TestAHandLaid|TestCreateExclusive' && go test ./internal/config/ -run TestRevocationsFileReadsThePathAlone`
  Expected: build failure (`initRevocations`, `initRevocationsCmd`, `createExclusive`,
  `RevocationsFile` undefined; `loadRevocations` returns three values).

- [ ] **Step 3: `config.RevocationsFile`.** In `internal/config/config.go`, lift `Load`'s spool
  default (`c.Accounting.SpoolPath = "/var/lib/port49/acct.jsonl"`, ~line 631) into
  `const defaultSpoolPath = "/var/lib/port49/acct.jsonl"` and use it there. After
  `inventoryBound`:

  ```go
  // RevocationsFile reads broker.revocations_file from a port49d.yaml's bytes,
  // for `port49d init-revocations` (spec §13 decision 32, amended): it resolves
  // no secret, so the command runs where the daemon's environment is not, and
  // decodes as strictly as Load, so a typo is an error, never "no path". It
  // refuses the paths Load refuses (ownRevocationsFile), each read from the
  // same bytes, so init never drops a file where admin_socket, the spool or
  // the policy will be (pre-flight M10).
  func RevocationsFile(raw []byte) (string, error) {
  	var f fileConfig
  	dec := yaml.NewDecoder(bytes.NewReader(raw))
  	dec.KnownFields(true)
  	if err := dec.Decode(&f); err != nil && err != io.EOF {
  		return "", fmt.Errorf("config: %w; check the key spelling against the port49d.yaml schema", decodeFault(err))
  	}
  	if f.Broker == nil || f.Broker.RevocationsFile == "" {
  		return "", errors.New("config: no broker.revocations_file: init-revocations is for a port49d with a broker")
  	}
  	c := Config{InventoryFile: f.InventoryFile, InventoryService: f.InventoryOpts.Service, Accounting: f.Accounting,
  		Lab: f.Lab, AdminSocket: f.AdminSocket}
  	if c.Accounting.SpoolPath == "" {
  		c.Accounting.SpoolPath = defaultSpoolPath
  	}
  	if err := ownRevocationsFile(c, *f.Broker); err != nil {
  		return "", err
  	}
  	return f.Broker.RevocationsFile, nil
  }
  ```

  Add `errors` to the imports if it is not there. If `Config`'s field for the inventory service
  is named otherwise, use `Load`'s assignment from `f.InventoryOpts.Service` as the guide.

  Two comments change (pre-flight M5). `BrokerConfig.RevocationsFile`'s, from "port49d creates it
  at the first start" to its end, becomes: "port49d never creates it: a missing file, or one that
  does not load, refuses every start, and so does a directory others can write (spec §13 decision
  32, amended 2026-10-02). `port49d init-revocations` creates it once per install, as port49d's
  user, beside a marker (<file>.created); a start writes the marker beside a file that loads with
  none. port49d writes the file, 0600 and atomically, after every revocation and lift."
  `ownRevocationsFile`'s "Its marker (<file>.created), which port49d writes too," becomes "Its
  marker (<file>.created), which init-revocations creates and a start writes beside a file that
  loads,".

- [ ] **Step 4: `readRevocations`, `loadRevocations`, and `initRevocations`.** In
  `cmd/port49d/revocations.go`, rename `loadRevocations` to `readRevocations`, replace its comment
  and its not-exist branch, move the marker-writing block after the parse loop into a new
  `loadRevocations`, and return `([]store.Revocation, error)`:

  ```go
  // readRevocations reads the file behind the write fence, its own name never
  // a link (fence.ReadNoLink): whoever could write it could lift a revocation
  // at the next restart. The directory is fenced first, whether or not the
  // file is there (fence.CheckDir). A file that is not there is an error,
  // always: port49d never creates it (spec §13 decision 32, amended
  // 2026-10-02). An unmounted or empty volume that passes the fence would
  // otherwise read as a first install and start with no marks; `port49d
  // init-revocations` creates it, once. The marker beside it only changes what
  // the refusal says: with it, the revocations were lost. Without it, the
  // refusal leads with the volume, then the first install (pre-flight M13).
  // Anything else it cannot read whole is an error. It writes nothing.
  func readRevocations(path string) ([]store.Revocation, error) {
  	if err := fence.CheckDir(path, "revocations file"); err != nil {
  		return nil, err
  	}
  	raw, err := fence.ReadNoLink(path, maxRevocationsFile, "revocations file")
  	if errors.Is(err, fs.ErrNotExist) {
  		switch _, merr := os.Lstat(markerOf(path)); {
  		case merr == nil:
  			return nil, errors.New(`is missing, and its marker says port49d held revocations here; port49d will ` +
  				`not start without them: restore the file, or, if they are truly lost, write {"revocations": []} ` +
  				`on purpose`)
  		case !errors.Is(merr, fs.ErrNotExist):
  			return nil, merr
  		}
  		return nil, errors.New("does not exist: if port49d has run here before, the volume holding it is missing " +
  			"or empty: mount it or restore the file; only on a first install, run 'port49d init-revocations' once, " +
  			"as port49d's user, with the same --config")
  	}
  	if err != nil {
  		return nil, err
  	}
  	// … the decode and the per-entry checks, unchanged, returning (nil, err)
  	// where they returned (nil, false, err) …
  	return out, nil
  }

  // loadRevocations is a start's read (readRevocations), then, when no marker
  // is beside the file that loaded (laid down by config management, or
  // restored onto a new volume), it writes one, as 7a's start did. That
  // creates no revocations file, and it makes the file's later loss refuse
  // the start as a loss rather than read as a first install (spec §13
  // decision 32; pre-flight M12).
  func loadRevocations(path string) ([]store.Revocation, error) {
  	rs, err := readRevocations(path)
  	if err != nil {
  		return nil, err
  	}
  	switch _, err := os.Lstat(markerOf(path)); {
  	case errors.Is(err, fs.ErrNotExist):
  		abs, err := filepath.Abs(path)
  		if err != nil {
  			return nil, err
  		}
  		if err := writeMarker(abs); err != nil {
  			return nil, err
  		}
  	case err != nil:
  		return nil, err
  	}
  	return rs, nil
  }
  ```

  Split the two writers' bodies out, so init writes the same bytes they do:

  ```go
  // markerBody is what the marker beside the file at abs says.
  func markerBody(abs string) []byte {
  	return []byte("port49d created " + filepath.Base(abs) + " at " + decision.FormatTime(time.Now()) + "\n")
  }

  // writeMarker writes the marker beside the file at abs, 0600, atomically.
  func writeMarker(abs string) error {
  	return inventory.WriteAtomic(filepath.Dir(abs), filepath.Base(markerOf(abs)), markerBody(abs), 0o600)
  }

  // encodeRevocations is the file's content for rs.
  func encodeRevocations(rs []store.Revocation) ([]byte, error) {
  	f := revocationsFile{Revocations: []revocationEntry{}}
  	for _, r := range rs {
  		f.Revocations = append(f.Revocations, revocationEntry{Kind: r.Kind, Key: r.Key,
  			At: decision.FormatTime(r.At), Origin: r.Origin})
  	}
  	body, err := json.MarshalIndent(f, "", "  ")
  	if err != nil {
  		return nil, err
  	}
  	return append(body, '\n'), nil
  }

  // saveRevocations writes rs whole, 0600, atomically: a reader sees the old
  // file or the new one.
  func saveRevocations(path string, rs []store.Revocation) error {
  	body, err := encodeRevocations(rs)
  	if err != nil {
  		return err
  	}
  	abs, err := filepath.Abs(path)
  	if err != nil {
  		return err
  	}
  	return inventory.WriteAtomic(filepath.Dir(abs), filepath.Base(abs), body, 0o600)
  }
  ```

  Then add init:

  ```go
  // createExclusive writes body to a new file at abs, 0600, and fails with
  // fs.ErrExist if abs is already there: a temporary file beside it is
  // written and synced, then linked to the name, which, unlike a rename,
  // never replaces a file that appeared after init looked (pre-flight M10).
  // The directory is synced, so the name survives a crash.
  func createExclusive(abs string, body []byte) error {
  	dir := filepath.Dir(abs)
  	tmp, err := os.CreateTemp(dir, "."+filepath.Base(abs)+".init-*") // 0600
  	if err != nil {
  		return err
  	}
  	defer os.Remove(tmp.Name())
  	_, werr := tmp.Write(body)
  	if werr == nil {
  		werr = tmp.Sync()
  	}
  	if cerr := tmp.Close(); werr == nil {
  		werr = cerr
  	}
  	if werr != nil {
  		return werr
  	}
  	if err := os.Link(tmp.Name(), abs); err != nil {
  		return err
  	}
  	d, err := os.Open(dir)
  	if err != nil {
  		return err
  	}
  	defer d.Close()
  	return d.Sync()
  }

  // initRevocations is `port49d init-revocations` (spec §13 decision 32,
  // amended): broker.revocations_file created once per install, empty, by the
  // user that owns its directory (initOwner, asked first, so a root-run init
  // is told to run as that user rather than, by the fence, to chown), behind
  // the directory fence a start applies.
  //
  // created is false, and err nil, when the file is already there and loads:
  // nothing is written, so a provisioning step may run it twice (pre-flight
  // I6). It refuses a file that is there and does not load, and a marker with
  // no file beside it: a loss, which a restore or a deliberate
  // {"revocations": []} answers, never a re-created file. Otherwise it
  // creates the marker, then the file, each exclusively (createExclusive): a
  // crash between the two leaves a marker and no file, which refuses the next
  // start and the next init.
  func initRevocations(path string) (created bool, err error) {
  	abs, err := filepath.Abs(path)
  	if err != nil {
  		return false, err
  	}
  	if err := initOwner(filepath.Dir(abs)); err != nil {
  		return false, err
  	}
  	if err := fence.CheckDir(abs, "revocations file"); err != nil {
  		return false, err
  	}
  	switch _, err := os.Lstat(abs); {
  	case err == nil:
  		if _, err := readRevocations(abs); err != nil {
  			return false, fmt.Errorf("exists and does not load (%v); init never replaces it", err)
  		}
  		return false, nil
  	case !errors.Is(err, fs.ErrNotExist):
  		return false, err
  	}
  	switch _, err := os.Lstat(markerOf(abs)); {
  	case err == nil:
  		return false, fmt.Errorf("is missing, and its marker %s says port49d held revocations here: init never "+
  			`re-creates a lost file; restore it from backup, or write {"revocations": []} on purpose`, markerOf(abs))
  	case !errors.Is(err, fs.ErrNotExist):
  		return false, err
  	}
  	if err := createExclusive(markerOf(abs), markerBody(abs)); err != nil {
  		return false, err
  	}
  	body, err := encodeRevocations(nil)
  	if err != nil {
  		return false, err
  	}
  	if err := createExclusive(abs, body); err != nil {
  		return false, err
  	}
  	return true, nil
  }

  // initRevocationsCmd runs `port49d init-revocations [--config FILE]`. It
  // exits 0 having created the file or found it already there and loading, 1
  // when it would not, and 2 on usage. It prints the absolute path, and warns
  // when the configured one is relative: that resolved against this shell's
  // directory, and port49d resolves it against its own (pre-flight M10).
  func initRevocationsCmd(args []string, stdout, stderr io.Writer) int {
  	flags := flag.NewFlagSet("port49d init-revocations", flag.ContinueOnError)
  	flags.SetOutput(stderr)
  	cfgPath := flags.String("config", "/etc/port49/port49d.yaml", "path to port49d.yaml")
  	if err := flags.Parse(args); err != nil {
  		return 2
  	}
  	if flags.NArg() != 0 {
  		fmt.Fprintln(stderr, "usage: port49d init-revocations [--config FILE]")
  		return 2
  	}
  	raw, err := config.ReadRegular(*cfgPath, config.MaxConfigSize)
  	if err != nil {
  		fmt.Fprintln(stderr, "port49d init-revocations:", err)
  		return 1
  	}
  	path, err := config.RevocationsFile(raw)
  	if err != nil {
  		fmt.Fprintln(stderr, "port49d init-revocations:", err)
  		return 1
  	}
  	abs, err := filepath.Abs(path)
  	if err != nil {
  		fmt.Fprintln(stderr, "port49d init-revocations:", err)
  		return 1
  	}
  	if !filepath.IsAbs(path) {
  		fmt.Fprintf(stderr, "port49d init-revocations: warning: broker.revocations_file %q is relative: it resolved "+
  			"against this shell's directory, to %s, and port49d resolves it against its own; give an absolute "+
  			"path in port49d.yaml\n", path, abs)
  	}
  	created, err := initRevocations(abs)
  	switch {
  	case err != nil:
  		fmt.Fprintf(stderr, "port49d init-revocations: broker.revocations_file %s: %v\n", abs, err)
  		return 1
  	case !created:
  		fmt.Fprintf(stdout, "port49d: broker.revocations_file %s is already initialized; nothing written\n", abs)
  		return 0
  	}
  	fmt.Fprintf(stdout, "port49d: created broker.revocations_file %s with no revocations, and its marker %s; "+
  		"run this once per install, never on a start path: from now on port49d refuses to start if the file "+
  		"goes missing\n", abs, markerOf(abs))
  	return 0
  }
  ```

  Create `cmd/port49d/initowner_linux.go`:

  ```go
  //go:build linux

  package main

  import (
  	"errors"
  	"fmt"
  	"io/fs"
  	"os"
  	"os/user"
  	"strconv"

  	"github.com/rhwendt/port49/internal/fence"
  )

  // initOwner refuses `port49d init-revocations` run by anyone but the owner
  // of dir, the directory that holds broker.revocations_file (pre-flight I5).
  // port49d runs as that user, and a 0600 file another user wrote, root above
  // all, is one port49d cannot read: its first start would fail on
  // "permission denied". The refusal names the owner, by name where the
  // system knows it, and the line to run; it never chowns. A directory that
  // is not there is left to fence.CheckDir to say so.
  func initOwner(dir string) error {
  	fi, err := os.Stat(dir)
  	if errors.Is(err, fs.ErrNotExist) {
  		return nil
  	}
  	if err != nil {
  		return err
  	}
  	uid, ok := fence.FileOwner(fi)
  	if !ok {
  		return fmt.Errorf("the directory %s: cannot read its owner", dir)
  	}
  	euid := fence.Geteuid()
  	if uint32(euid) == uid {
  		return nil
  	}
  	who := strconv.FormatUint(uint64(uid), 10)
  	if u, err := user.LookupId(who); err == nil {
  		who = u.Username
  	}
  	return fmt.Errorf("the directory %s belongs to %s, and this runs as uid %d: port49d, running as %s, could not "+
  		"read what this would write; run as %s, e.g. sudo -u %s port49d init-revocations", dir, who, euid, who, who, who)
  }
  ```

  `os/user` reads `/etc/passwd` without cgo. Create `cmd/port49d/initowner_other.go`:

  ```go
  //go:build !linux

  package main

  // initOwner has nothing to ask off Linux: fence.CheckDir refuses there
  // first, since port49 keeps the revocations file on Linux only.
  func initOwner(string) error { return nil }
  ```

  `restoreRevocations` drops `created`, and its comment's "created is the first start's." goes:

  ```go
  func restoreRevocations(ctx context.Context, st store.Store, path string, m *metrics.Metrics) ([]store.Revocation, error) {
  	rs, err := loadRevocations(path)
  	if err != nil {
  		return nil, err
  	}
  	for i, r := range rs {
  		if err := st.PutRevocation(ctx, r); err != nil {
  			return nil, fmt.Errorf("revocation %d: %w", i, err)
  		}
  	}
  	countRevocations(rs, m)
  	return rs, nil
  }
  ```

  Add `flag`, `io` and `github.com/rhwendt/port49/internal/config` to `revocations.go`'s imports.

- [ ] **Step 5: `main` dispatches it, refuses a stray argument, and the start line.** In
  `cmd/port49d/main.go`:

  ```go
  func main() {
  	// The one subcommand, before the daemon's flags: it reads port49d.yaml for
  	// one path and starts nothing (spec §13 decision 32, amended).
  	if len(os.Args) > 1 && os.Args[1] == "init-revocations" {
  		os.Exit(initRevocationsCmd(os.Args[2:], os.Stdout, os.Stderr))
  	}
  	cfgPath := flag.String("config", "/etc/port49/port49d.yaml", "path to port49d.yaml")
  	flag.Parse()
  	// A subcommand after a flag (port49d --config X init-revocations) would
  	// otherwise start the daemon (pre-flight M20).
  	if flag.NArg() != 0 {
  		fmt.Fprintln(os.Stderr, "usage: port49d [--config FILE], or port49d init-revocations [--config FILE] "+
  			"(the subcommand comes first)")
  		os.Exit(2)
  	}
  	// … unchanged …
  ```

  In `run`, replace the `var created bool … if created { … } else { … }` block with:

  ```go
  		marks, err = restoreRevocations(ctx, brk.Store, cfg.Broker.RevocationsFile, m)
  		if err != nil {
  			stopSpool()
  			<-spoolDone
  			return fmt.Errorf("broker.revocations_file %s: %w", cfg.Broker.RevocationsFile, err)
  		}
  		brk.Persist = persister(brk.Store, cfg.Broker.RevocationsFile, m)
  		fmt.Fprintf(stderr, "port49d: broker: %d revocation(s) in force from %s\n", len(marks),
  			cfg.Broker.RevocationsFile)
  ```

- [ ] **Step 6: Every test and harness that starts port49d inits first.**
  - **`brokerConfig`** (`cmd/port49d/broker_test.go`, ~line 37): build the config into a variable,
    call `if _, err := initRevocations(cfg.Broker.RevocationsFile); err != nil { t.Fatal(err) }`,
    and return it, so every run-level test starts as an initialised install. Its directory is
    `t.TempDir()`, owned by the test's user and closed to others, so `initOwner` and the fence
    pass.
  - **The run-level test** (~line 720) that waits for `"port49d: broker: created
    "+b.RevocationsFile+" (no revocations)"` waits for `"port49d: broker: 0 revocation(s) in force
    from "+b.RevocationsFile` instead.
  - **"a restored mark refuses the mint"** (~line 765): `restoreRevocations` returns two values
    (`if _, err := restoreRevocations(…); err != nil`). It overwrites the file `brokerConfig`
    inited, which is what it means.
  - **The refusal subtests** (~lines 785–822, "a file that does not parse", "a file deleted after
    the first start", "a directory its group can write") point `RevocationsFile` into their own
    `safeDir` and mean to be refused: leave them. Each is still refused, and "a file deleted after
    the first start" now by the marker's message.
  - **`privatePolicy`** (`tests/lab/harness_test.go`). After removing `dst` and its marker, write
    `{"revocations": []}\n` to `dst` at 0600. Change its comment's last sentence to: "It goes in the
    private directory, fresh at every derived config, written empty on purpose: port49d no longer
    creates it (spec §13 decision 32, amended 2026-10-02)."
  - **`tests/lab/private_policy_unit_test.go`**: assert the file exists with that content and no
    `.created` beside it (the derivation writes none; a start does).
  - **`tests/lab/inventory_test.go`**: before the config at ~line 327 is used, write
    `{"revocations": []}\n` at 0600 to `filepath.Join(filepath.Dir(policy), "revocations.json")`.
  - **`tests/lab/README.md`**: in the by-hand slice run, before the first `bin/port49d` start, add
    `bin/port49d init-revocations --config <the derived config>` with one line saying port49d never
    creates the file and init runs once, as the user port49d runs as. The `chmod go-w
    tests/lab/logs` note stays.

- [ ] **Step 7: Run the tests, and check `main`'s guard by hand.**

  Run: `go test ./cmd/port49d/ ./internal/config/ && go vet -tags lab ./tests/lab/ && go test -tags lab ./tests/lab/ -run '^TestPrivatePolicyCopiesABrokerConfigsInventory$' -count=1`
  Expected: PASS. (`make test` runs the lab package's unit tests by the list of names in the
  Makefile; `TestPrivatePolicyCopiesABrokerConfigsInventory` is the one `privatePolicy` has.)

  `main` is not under test. Run `go run ./cmd/port49d --config /nonexistent init-revocations;
  echo $?` and expect the usage line and `2`, not a start that fails on the missing config.

- [ ] **Step 8: Commit.**

  ```bash
  gofmt -w internal/config/config.go cmd/port49d/revocations.go cmd/port49d/initowner_linux.go \
    cmd/port49d/initowner_other.go cmd/port49d/main.go cmd/port49d/*_test.go \
    internal/config/config_test.go tests/lab/harness_test.go tests/lab/inventory_test.go tests/lab/private_policy_unit_test.go
  make build && make test && make vet
  git add internal/config/config.go internal/config/config_test.go cmd/port49d/revocations.go \
    cmd/port49d/initowner_linux.go cmd/port49d/initowner_other.go cmd/port49d/initowner_linux_test.go \
    cmd/port49d/main.go cmd/port49d/revocations_test.go cmd/port49d/broker_test.go tests/lab/harness_test.go \
    tests/lab/inventory_test.go tests/lab/private_policy_unit_test.go tests/lab/README.md
  git commit -m "feat(port49d): never create broker.revocations_file at start; add port49d init-revocations

  An empty or unmounted volume that passed the fence read as a first install and
  started with no marks. A missing file now refuses every start, its message
  leading with the volume. init-revocations creates the file and its marker
  once, exclusively, as the directory's owner; exits 0 writing nothing over a
  file that loads; and refuses over a lost file (spec §13 decision 32, amended
  2026-10-02). A start still writes the marker beside a file that loads.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 3: The vocabulary and the rights lookup

**Files:**
- Modify: `internal/decision/reasons.go`, `internal/decision/log.go`
- Modify: `internal/decision/reasons_test.go`
- Modify: `internal/policy/load.go` (`apiRights`, ~line 210; `SubjectOf`, ~line 1658)
- Modify: `internal/broker/revoke.go` (`recordRevocation`: `Saved` becomes a pointer)
- Test: `internal/policy/rights_test.go` (new)

**Interfaces:**
- Produces:
  - `decision.APIRightMissing Reason = "api_right_missing"`
  - `decision.EventIdentity = "identity"`, `decision.EventExplain = "explain"`
  - `decision.Record.Explain *decision.Explain` (`json:"explain,omitempty"`), and
    `type decision.Explain struct{ AskedBy, AskedByFingerprint string; Command bool; MintError string }`
  - `decision.Revocation.Device`, `.Username string`; `.Saved` becomes `*bool`
  - `policy.RightRevokeOthers`, `RightExplainOthers`, `RightSync`, `RightKeysShow`, `RightReplay`
  - `func (p *policy.Policy) HasRight(principal, right string) bool`

- [ ] **Step 1: Write the failing tests.** In `internal/decision/reasons_test.go` add:

  ```go
  // api_right_missing is in §5.7's vocabulary (plan 7c), so a policy test may
  // expect it and the metrics count it.
  func TestAPIRightMissingIsKnown(t *testing.T) {
  	if !Known(APIRightMissing) || APIRightMissing != "api_right_missing" {
  		t.Fatal("api_right_missing")
  	}
  }

  // An explain record carries who asked, by principal and certificate, and
  // whether a command was asked, never the command (spec §5.7); a revoke
  // record's saved is absent unless it is a standing mark's.
  func TestTheAPIRecordsShapes(t *testing.T) {
  	var b bytes.Buffer
  	l := NewJSONLines(&b)
  	l.Emit(Record{Event: EventExplain, Verdict: VerdictDeny, Reason: NoGrantsMatched,
  		Principal: "user:alice@example.com", Explain: &Explain{AskedBy: "user:bob@example.com",
  			AskedByFingerprint: "sha256:ab12", Command: true}})
  	l.Emit(Record{Event: EventRevoke, Verdict: VerdictDeny, Reason: CredentialRevoked,
  		Revocation: &Revocation{By: "key", Device: "leaf-01", Username: "alice", At: "2026-10-02T03:12:09Z"}})
  	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
  	if !strings.Contains(lines[0], `"explain":{"asked_by":"user:bob@example.com","asked_by_fingerprint":"sha256:ab12",`+
  		`"command":true}`) || strings.Contains(lines[0], `"auth"`) {
  		t.Fatalf("explain: %s", lines[0])
  	}
  	if !strings.Contains(lines[1], `"device":"leaf-01","username":"alice"`) || strings.Contains(lines[1], `"saved"`) {
  		t.Fatalf("revoke: %s", lines[1])
  	}
  }
  ```

  Create `internal/policy/rights_test.go`:

  ```go
  package policy

  import "testing"

  // A right is held through the subject a principal's identity list names
  // (spec §2): a principal no subject names holds none, and a subject holds
  // only what its api: list says.
  func TestHasRightReadsTheSubjectsList(t *testing.T) {
  	p := mustParse(t, `
  scopes: [{name: all_devices, match: {}}]
  roles: [{name: r, privilege: readonly, permit: [show **]}]
  subjects:
    - {name: oncall, identity: ["user:bob@example.com"], username: bob, token_ttl: 60s, api: [revoke_others, sync]}
    - {name: ops, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}
  grants: [{subject: ops, scope: all_devices, roles: [r]}]`)
  	for _, c := range []struct {
  		principal, right string
  		want             bool
  	}{
  		{"user:bob@example.com", RightRevokeOthers, true},
  		{"user:bob@example.com", RightSync, true},
  		{"user:bob@example.com", RightExplainOthers, false},
  		{"user:alice@example.com", RightRevokeOthers, false},
  		{"user:carol@example.com", RightRevokeOthers, false},
  		{"user:BOB@example.com", RightRevokeOthers, false}, // the caller's spelling is the broker's, lower-cased
  	} {
  		if got := p.HasRight(c.principal, c.right); got != c.want {
  			t.Errorf("HasRight(%s, %s) = %v", c.principal, c.right, got)
  		}
  	}
  }
  ```

  `mustParse` is the policy package's existing test helper (`internal/policy/load_test.go:40`).
  `reasons_test.go` gains the `bytes` and `strings` imports if it lacks them.

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/decision/ ./internal/policy/ -run 'TestAPIRightMissingIsKnown|TestTheAPIRecordsShapes|TestHasRightReadsTheSubjectsList'`
  Expected: build failure (undefined `APIRightMissing`, `EventExplain`, `Explain`, `HasRight`,
  `RightRevokeOthers`).

- [ ] **Step 3: The decision vocabulary.** In `internal/decision/reasons.go`, after
  `RevocationLifted`:

  ```go
  	// APIRightMissing: an API call asked to act on another principal's
  	// tokens, sessions or decisions, and the caller's subject declares no
  	// api: right that unlocks it (spec §2, §5.7; design §17). A denial; the
  	// API answers 403 and does nothing.
  	APIRightMissing Reason = "api_right_missing"
  ```

  Add `APIRightMissing` to the end of `reasons`. After `EventRevoke`:

  ```go
  // EventIdentity is GET /v1/identity: what the broker resolved the caller to
  // (design §17; spec §5.7): permit grants_matched, or deny
  // no_grants_matched.
  const EventIdentity = "identity"

  // EventExplain is POST /v1/explain: a hypothetical decision the broker
  // answered, about the caller or, under explain_others, another principal.
  // It authorizes nothing; its verdict and reason are the answer given, or
  // deny api_right_missing. It never carries the command asked (spec §5.7).
  const EventExplain = "explain"
  ```

  In `internal/decision/log.go`, add to `Record` after `Revocation`:

  ```go
  	// Explain is an explain record's own (spec §5.7): who asked, and whether
  	// a command was asked. The command itself is never recorded. An explain
  	// record carries no Auth: its Principal is whom it was about, and the
  	// caller's credential is in AskedByFingerprint (decision 34).
  	Explain *Explain `json:"explain,omitempty"`
  ```

  and after `ContextRef`:

  ```go
  // Explain is what an explain record says of the call beside its answer.
  // AskedBy and AskedByFingerprint are the caller's principal and
  // certificate, kept out of Auth so a record's auth and principal always
  // describe one credential (decision 34). MintError is the mint item error
  // the broker would answer instead of a token; the record then has no
  // verdict.
  type Explain struct {
  	AskedBy            string `json:"asked_by"`
  	AskedByFingerprint string `json:"asked_by_fingerprint,omitempty"`
  	Command            bool   `json:"command,omitempty"`
  	MintError          string `json:"mint_error,omitempty"`
  }
  ```

  In `Revocation`, add `Device string \`json:"device,omitempty"\`` and `Username string
  \`json:"username,omitempty"\`` after `Serial`, and change `Saved bool \`json:"saved"\`` to:

  ```go
  	// Saved is whether broker.revocations_file was written: a standing
  	// mark's alone, absent for a self or key revocation, which writes none.
  	Saved *bool `json:"saved,omitempty"`
  ```

  In `internal/broker/revoke.go`'s `recordRevocation`, replace `Saved: rep.Saved` in the literal
  with nothing, and after it add `saved := rep.Saved; body.Saved = &saved` (Task 7 restricts it to
  a standing mark). Fix any test that built a `decision.Revocation{Saved: true}` literal
  (`grep -rn 'Saved:' internal cmd`).

- [ ] **Step 4: The rights.** In `internal/policy/load.go`, replace `var apiRights = …` with:

  ```go
  // The broker API rights a subject may declare (spec §2). revoke_others and
  // explain_others unlock a broker endpoint; sync, keys_show and replay are
  // reserved: declared, reported by CI and the gate, and granting nothing until
  // an endpoint they guard exists (spec §13 decision 34).
  const (
  	RightRevokeOthers  = "revoke_others"
  	RightExplainOthers = "explain_others"
  	RightSync          = "sync"
  	RightKeysShow      = "keys_show"
  	RightReplay        = "replay"
  )

  var apiRights = []string{RightRevokeOthers, RightExplainOthers, RightSync, RightKeysShow, RightReplay}
  ```

  After `SubjectOf`:

  ```go
  // HasRight reports whether the subject principal resolves to declares right
  // in its api: list (spec §2). A principal no subject names holds none. A
  // group subject's members are resolved through the directory (plan 7g), so
  // until then a right is held through an identity list alone, as a mint is.
  func (p *Policy) HasRight(principal, right string) bool {
  	name, ok := p.byID[principal]
  	if !ok {
  		return false
  	}
  	return slices.Contains(p.subs[name].API, right)
  }
  ```

- [ ] **Step 5: Run the tests.**

  Run: `go test ./internal/decision/ ./internal/policy/ ./internal/broker/`
  Expected: PASS.

- [ ] **Step 6: Commit.**

  ```bash
  gofmt -w internal/decision/*.go internal/policy/load.go internal/policy/rights_test.go internal/broker/revoke.go
  make build && make test && make vet
  git add internal/decision/reasons.go internal/decision/log.go internal/decision/reasons_test.go \
    internal/policy/load.go internal/policy/rights_test.go internal/broker/revoke.go
  git commit -m "feat(decision, policy): add api_right_missing, the identity and explain events, and HasRight

  Spec §5.7 and §2 as Task 1 wrote them. A revoke record's saved is now present
  only where it was set.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 4: One preamble for every authenticated call, `GET /v1/identity`, and no right widens a mint or a refresh

**Files:**
- Modify: `internal/broker/broker.go` (`Handler`, ~line 131; `tokens`, ~lines 200–253;
  `RefusedAtBind`, ~line 475)
- Modify: `internal/broker/listen.go` (`Listener.Refused`, ~line 99; `answerRefused`, ~line 450)
- Create: `internal/broker/identity_api.go`
- Create: `internal/broker/api/identity.go`
- Modify: `internal/broker/fixture_test.go` (a `call` helper)
- Test: `internal/broker/identity_api_test.go` (new)

**Interfaces:**
- Consumes: `Identity`, `b.revocation`, `b.refuseRevokedAs`, `b.certRefusal`, `b.answerRefusal`,
  `b.authTime` (all existing); `decision.EventIdentity` (Task 3).
- Produces:
  - `func (b *Broker) authenticate(w http.ResponseWriter, r *http.Request, event, nothing string) (principal string, cred store.Credential, ok bool)`.
    `nothing` completes "so it … nothing" in the marks-unreadable answer: `"minted nothing"`,
    `"revoked nothing"`, `"explained nothing"`, `"answered nothing"`.
  - `type api.Identity struct{ Principal, Method, Fingerprint, Subject string; Groups []string; Grants []api.IdentityGrant; API []string; AuthTime, ConnectionEndsAt string }`
  - `Listener.Refused func(path, principal string, cred store.Credential, reason decision.Reason)`
    and `func (b *Broker) RefusedAtBind(path, principal string, cred store.Credential, reason decision.Reason)`
    (the refused request's path is new); `func bindEvent(path string) string`. `cmd/port49d/main.go`
    (`bl.Refused = brk.RefusedAtBind`) and `cmd/port49/main_test.go` (~line 399) assign the method
    value and need no edit.
  - `type api.IdentityGrant struct{ Scope string; Roles []string; MaxPrivilege, Expires string }`
  - the route `GET /v1/identity`; the test helper
    `func (f *fixture) call(ctx context.Context, cs *tls.ConnectionState, method, path, body string) *httptest.ResponseRecorder`.

- [ ] **Step 1: Write the failing tests.** Add to `internal/broker/fixture_test.go`:

  ```go
  // call sends one request to path through the broker's handler on a
  // connection whose verified chain is cs. ctx carries the held connection,
  // if the test gives one (withHeldConn).
  func (f *fixture) call(ctx context.Context, cs *tls.ConnectionState, method, path, body string) *httptest.ResponseRecorder {
  	r := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(ctx)
  	r.TLS = cs
  	w := httptest.NewRecorder()
  	f.b.Handler().ServeHTTP(w, r)
  	return w
  }
  ```

  Create `internal/broker/identity_api_test.go`:

  ```go
  package broker

  import (
  	"context"
  	"encoding/json"
  	"net/http"
  	"strings"
  	"testing"
  	"time"

  	"github.com/rhwendt/port49/internal/broker/api"
  	"github.com/rhwendt/port49/internal/decision"
  	"github.com/rhwendt/port49/internal/store"
  )

  // /v1/identity answers the caller with its subject, its grants, its rights
  // and its session's clock, and writes one identity record (design §17;
  // spec §5.7). A query naming someone else changes nothing: the caller is
  // the connection's certificate and nothing else (decision 34).
  func TestIdentityAnswersTheCallerAlone(t *testing.T) {
  	f := newFixture(t, 8)
  	at := f.now.Add(-time.Hour)
  	w := f.call(withHeldConn(context.Background(), at), f.state(f.alice), "GET",
  		"/v1/identity?principal=user:carol@example.com", "")
  	if w.Code != http.StatusOK {
  		t.Fatalf("%d %s", w.Code, w.Body)
  	}
  	var id api.Identity
  	if err := json.Unmarshal(w.Body.Bytes(), &id); err != nil {
  		t.Fatal(err)
  	}
  	if id.Principal != alicePrincipal || id.Subject != "netops" || id.Method != "cert" ||
  		!strings.HasPrefix(id.Fingerprint, "sha256:") || len(id.API) != 0 || len(id.Groups) != 0 {
  		t.Fatalf("%+v", id)
  	}
  	if len(id.Grants) != 1 || id.Grants[0].Scope != "all_devices" || id.Grants[0].MaxPrivilege != "admin" ||
  		strings.Join(id.Grants[0].Roles, " ") != "network_admin no_reload" {
  		t.Fatalf("grants: %+v", id.Grants)
  	}
  	if id.AuthTime != at.UTC().Format(time.RFC3339) || id.ConnectionEndsAt != at.Add(12*time.Hour).UTC().Format(time.RFC3339) {
  		t.Fatalf("clock: %s %s", id.AuthTime, id.ConnectionEndsAt)
  	}
  	recs := eventsOf(f.records(t), "identity")
  	if len(recs) != 1 || recs[0]["verdict"] != "permit" || recs[0]["reason"] != "grants_matched" ||
  		recs[0]["principal"] != alicePrincipal {
  		t.Fatalf("records: %v", recs)
  	}
  	if strings.Contains(w.Body.String(), "leaf1") {
  		t.Fatal("identity listed a device: the API never lists the fleet")
  	}
  }

  // A principal with a subject and no grant, and one no subject names, are
  // told so, recorded deny no_grants_matched.
  func TestIdentityOfAPrincipalWithNoGrant(t *testing.T) {
  	f := newFixture(t, 8)
  	for _, email := range []string{"carol@example.com", "dave@example.com"} {
  		w := f.call(context.Background(), f.state(f.client(t, email, f.now.Add(time.Hour))), "GET", "/v1/identity", "")
  		var id api.Identity
  		if err := json.Unmarshal(w.Body.Bytes(), &id); err != nil || w.Code != 200 || len(id.Grants) != 0 {
  			t.Fatalf("%s: %d %s", email, w.Code, w.Body)
  		}
  	}
  	recs := eventsOf(f.records(t), "identity")
  	if len(recs) != 2 || recs[0]["reason"] != "no_grants_matched" || recs[1]["reason"] != "no_grants_matched" {
  		t.Fatalf("%v", recs)
  	}
  }

  // A call is refused before it is read for what a mint is refused for, and
  // recorded under its own event (spec §5.7; decision 34).
  func TestIdentityIsRefusedAsAMintIs(t *testing.T) {
  	f := newFixture(t, 8)
  	ctx := context.Background()
  	expired := f.client(t, "alice@example.com", f.now.Add(-time.Minute))
  	if w := f.call(ctx, f.state(expired), "GET", "/v1/identity", ""); w.Code != 401 ||
  		!strings.Contains(w.Body.String(), "trust_domain_unresolved") {
  		t.Fatalf("expired: %d %s", w.Code, w.Body)
  	}
  	old := withHeldConn(ctx, f.now.Add(-13*time.Hour))
  	if w := f.call(old, f.state(f.alice), "GET", "/v1/identity", ""); w.Code != 401 ||
  		!strings.Contains(w.Body.String(), "session_expired") {
  		t.Fatalf("past max_session_age: %d %s", w.Code, w.Body)
  	}
  	if err := f.st.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: alicePrincipal,
  		At: f.now, Origin: "test"}); err != nil {
  		t.Fatal(err)
  	}
  	if w := f.call(ctx, f.state(f.alice), "GET", "/v1/identity", ""); w.Code != 401 ||
  		!strings.Contains(w.Body.String(), "credential_revoked") {
  		t.Fatalf("marked: %d %s", w.Code, w.Body)
  	}
  	reasons := map[string]bool{}
  	for _, r := range eventsOf(f.records(t), "identity") {
  		if r["verdict"] != "deny" {
  			t.Fatalf("%v", r)
  		}
  		reasons[r["reason"].(string)] = true
  	}
  	for _, want := range []string{"trust_domain_unresolved", "session_expired", "credential_revoked"} {
  		if !reasons[want] {
  			t.Fatalf("no identity deny %s: %v", want, reasons)
  		}
  	}
  	if n := len(eventsOf(f.records(t), "mint")); n != 0 {
  		t.Fatalf("%d mint records for identity calls", n)
  	}
  }

  // No right widens a mint or a refresh (decision 34; 7b's carried item): a
  // principal holding every right still cannot name another in a mint, and its
  // refresh does not extend another principal's context, even one a stale
  // index entry lists under it. Neither path reads a right, so this passes on
  // 7b's code: it is a regression pin on 7b's self-only rule, against a
  // future rights-aware change to either (pre-flight M17), not a test of
  // this plan's rights code.
  func TestNoRightWidensAMintOrARefresh(t *testing.T) {
  	f := newFixtureWithPolicy(t, 8, strings.Replace(testPolicy, "enable: token, token_ttl: 60s}",
  		"enable: token, token_ttl: 60s, api: [revoke_others, explain_others, sync, keys_show, replay]}", 1))
  	ctx := context.Background()
  	if w := f.post(ctx, f.state(f.alice), `{"devices":["leaf1"],"principal":"user:carol@example.com"}`, ""); w.Code != 400 {
  		t.Fatalf("a mint naming another principal: %d %s", w.Code, w.Body)
  	}
  	carol := "user:carol@example.com"
  	f.liveContextAt(t, "nx1", "carol", carol, "", f.now, f.now.Add(time.Hour))
  	ref := store.ContextRef{NAS: "nx1", Username: "carol"}
  	if err := f.st.IndexContext(ctx, alicePrincipal, "", "", ref, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	f.advance(30 * time.Minute)
  	if _, err := f.b.RefreshSession(ctx, alicePrincipal, store.Credential{Method: "cert"}, f.b.Now()); err != nil {
  		t.Fatal(err)
  	}
  	c, err := f.st.GetContext(ctx, store.ContextKey{NAS: "nx1", Username: "carol"})
  	if err != nil || !c.AuthTime.Equal(f.now.Add(-30*time.Minute)) || !c.RevokedAt.IsZero() {
  		t.Fatalf("carol's context was touched by alice's refresh: %+v %v", c, err)
  	}
  }

  // A request the listener refuses as its connection binds is recorded under
  // the event of the path it asked for, as authenticate records a refusal
  // after the bind (decision 34; pre-flight M8); any other path stays mint.
  func TestARefusalAtBindIsRecordedUnderItsEndpointsEvent(t *testing.T) {
  	f := newFixture(t, 8)
  	cred := store.Credential{Method: "cert", Fingerprint: "sha256:ab12"}
  	for _, path := range []string{"/v1/identity", "/v1/explain", "/v1/tokens/revoke", "/v1/tokens", "/v1/refresh", "/nowhere"} {
  		f.b.RefusedAtBind(path, alicePrincipal, cred, decision.CredentialRevoked)
  	}
  	var got []string
  	for _, r := range f.records(t) {
  		got = append(got, r["event"].(string))
  		if r["reason"] != "credential_revoked" || r["principal"] != alicePrincipal {
  			t.Fatalf("%v", r)
  		}
  	}
  	if want := "identity explain revoke mint mint mint"; strings.Join(got, " ") != want {
  		t.Fatalf("events %v, want %s", got, want)
  	}
  }
  ```

  If `liveContextAt` refuses a principal with no grant on the device (it resolves the blob), it
  writes the all-zero hash for it, as its comment says for a device with no platform; that is
  enough here, since only `AuthTime` is checked.

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/broker/ -run 'TestIdentity|TestNoRightWidens|TestARefusalAtBind'`
  Expected: a build failure (`api.Identity` undefined; `RefusedAtBind` takes no path), then 404s
  from the mux for `/v1/identity`. `TestNoRightWidensAMintOrARefresh` fails only with the file's
  build: on its own it passes on today's code, as its comment says.

- [ ] **Step 3: The preamble.** In `internal/broker/broker.go`, add after `tokens`:

  ```go
  // authenticate is the first step of every authenticated endpoint but the
  // refresh, which re-authenticates (spec §5.6): the caller is the
  // connection's verified certificate (Identity) and nothing in the request;
  // the connection is within max_session_age (decision 17); no revocation
  // stands against the principal or the certificate, read before anything
  // else so a revoked caller is told nothing more (spec §5.1.4); and the
  // certificate's status does not refuse it (decision 33). A caller any of
  // these refuses is answered here, recorded once under event with a mint's
  // reasons and meanings (spec §5.7; decision 34), and ok is false. nothing
  // completes the marks-unreadable answer: "so it minted nothing".
  func (b *Broker) authenticate(w http.ResponseWriter, r *http.Request, event, nothing string) (string, store.Credential, bool) {
  	now := b.Now()
  	authTime := b.authTime(r)
  	principal, cred, err := Identity(r.TLS, now)
  	if err != nil {
  		// A chain the anchor verified is named on the refusal (principal when
  		// it maps to one, the fingerprint always); no chain names no one.
  		b.emit(decision.Record{TS: now, Event: event, Verdict: decision.VerdictDeny,
  			Reason: decision.TrustDomainUnresolved, Principal: principal,
  			Auth: &decision.Auth{Method: "cert", Fingerprint: cred.Fingerprint}})
  		writeError(w, http.StatusUnauthorized, string(decision.TrustDomainUnresolved), err.Error())
  		return "", store.Credential{}, false
  	}
  	if b.MaxSessionAge > 0 && now.Sub(authTime) > b.MaxSessionAge {
  		b.emit(decision.Record{TS: now, Event: event, Verdict: decision.VerdictDeny,
  			Reason: decision.SessionExpired, Principal: principal, Auth: &decision.Auth{Method: cred.Method}})
  		// Closing the connection is what makes the next request a handshake,
  		// and the handshake is the fresh authentication decision 17 requires.
  		w.Header().Set("Connection", "close")
  		writeError(w, http.StatusUnauthorized, string(decision.SessionExpired), fmt.Sprintf(
  			"this connection authenticated at %s, more than max_session_age (%s) ago; authenticate again",
  			authTime.UTC().Format(time.RFC3339), b.MaxSessionAge))
  		return "", store.Credential{}, false
  	}
  	checkCtx, cancelCheck := context.WithTimeout(r.Context(), holdTimeout)
  	rv, revoked, err := b.revocation(checkCtx, principal, cred)
  	cancelCheck()
  	switch {
  	case err != nil:
  		b.emit(decision.Record{TS: now, Event: event, Verdict: decision.VerdictDeny,
  			Reason: decision.StoreUnavailable, Principal: principal, Auth: &decision.Auth{Method: cred.Method}})
  		writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable),
  			"the broker could not read the revocations in force, so it "+nothing+"; try again")
  		return "", store.Credential{}, false
  	case revoked:
  		b.refuseRevokedAs(w, event, now, principal, cred, rv)
  		return "", store.Credential{}, false
  	}
  	statusCtx, cancelStatus := context.WithTimeout(r.Context(), holdTimeout)
  	ref := b.certRefusal(statusCtx, r.TLS, cred)
  	cancelStatus()
  	if ref != nil {
  		b.emit(decision.Record{TS: now, Event: event, Verdict: decision.VerdictDeny, Reason: ref.Reason,
  			Principal: principal, Auth: &decision.Auth{Method: cred.Method, Fingerprint: cred.Fingerprint}})
  		b.answerRefusal(w, r, ref)
  		return "", store.Credential{}, false
  	}
  	return principal, cred, true
  }
  ```

  Replace the top of `tokens`, from `now := b.Now()` through the `certRefusal` block, with:

  ```go
  	principal, cred, ok := b.authenticate(w, r, decision.EventMint, "minted nothing")
  	if !ok {
  		return
  	}
  	now := b.Now()
  	authTime := b.authTime(r)
  ```

  `now` is still used below it (the reservation's store-error record); if the compiler says it is
  not, drop it. Every existing mint test must pass unchanged: the records and answers are the same
  bytes.

  The listener's refusal as a connection binds is recorded under the path's event too (pre-flight
  M8). In `internal/broker/listen.go`, `Listener.Refused` gains the path first:

  ```go
  	// Refused records a request refused as its connection bound, with the
  	// path it asked for and the reason: credential_revoked for a mark, or
  	// Status's. One deny record each, under the path's event (spec §5.7;
  	// decision 34), which port49d sets to Broker.RefusedAtBind. Set it before
  	// the first Accept; nil records nothing.
  	Refused func(path, principal string, cred store.Credential, reason decision.Reason)
  ```

  and `answerRefused`, which has read the request, calls `l.Refused(req.URL.Path, principal, cred,
  reason)`. In `broker.go`, replace `RefusedAtBind`:

  ```go
  // RefusedAtBind records a request the broker's listener refused as its
  // connection bound (Listener.Refused): credential_revoked for a mark on its
  // principal or certificate, or the reason its certificate's status gave.
  // It is the one deny record a call refused after the bind writes, under
  // the event of the path it asked for (bindEvent), counted in
  // port49_decisions (spec §5.7; decision 34).
  func (b *Broker) RefusedAtBind(path, principal string, cred store.Credential, reason decision.Reason) {
  	rec := revokedRecord(b.Now(), principal, cred)
  	rec.Event, rec.Reason = bindEvent(path), reason
  	b.emit(rec)
  }

  // bindEvent is the event a request refused as its connection bound is
  // recorded under: its endpoint's own, and mint for any other path, as
  // before (decision 34).
  func bindEvent(path string) string {
  	switch path {
  	case "/v1/identity":
  		return decision.EventIdentity
  	case "/v1/explain":
  		return decision.EventExplain
  	case "/v1/tokens/revoke":
  		return decision.EventRevoke
  	}
  	return decision.EventMint
  }
  ```

  The path is matched exactly, as the mux routes it, and is never recorded: only the event it
  maps to.

- [ ] **Step 4: The wire type and the handler.** Create `internal/broker/api/identity.go`:

  ```go
  package api

  // Identity is GET /v1/identity: what the broker resolves the caller to
  // (design §17). Groups is empty until the directory (plan 7g). Grants are
  // the subject's unexpired at the request, by scope: never a device list,
  // since the API does not enumerate the fleet.
  type Identity struct {
  	Principal     string          `json:"principal"`
  	Method        string          `json:"method"`
  	Fingerprint   string          `json:"fingerprint,omitempty"`
  	Subject       string          `json:"subject,omitempty"`
  	Groups        []string        `json:"groups"`
  	Grants        []IdentityGrant `json:"grants"`
  	API           []string        `json:"api"`
  	AuthTime      string          `json:"auth_time"`
  	// ConnectionEndsAt is auth_time plus max_session_age: when this
  	// connection must authenticate again. A device's own session ceiling
  	// may end a session sooner (pre-flight M16).
  	ConnectionEndsAt string `json:"connection_ends_at,omitempty"`
  }

  // IdentityGrant is one grant row as the policy declares it.
  type IdentityGrant struct {
  	Scope        string   `json:"scope"`
  	Roles        []string `json:"roles"`
  	MaxPrivilege string   `json:"max_privilege,omitempty"`
  	Expires      string   `json:"expires,omitempty"`
  }
  ```

  Create `internal/broker/identity_api.go`:

  ```go
  package broker

  import (
  	"net/http"
  	"slices"
  	"time"

  	"github.com/rhwendt/port49/internal/broker/api"
  	"github.com/rhwendt/port49/internal/decision"
  )

  // identity is GET /v1/identity (design §17): what the policy in force
  // resolves the caller to. It answers the caller alone: the principal is the
  // connection's, the request names no one, and no right shows another's
  // (spec §2; decision 34). It writes one identity record (spec §5.7).
  func (b *Broker) identity(w http.ResponseWriter, r *http.Request) {
  	principal, cred, ok := b.authenticate(w, r, decision.EventIdentity, "answered nothing")
  	if !ok {
  		return
  	}
  	now, at := b.Now(), b.authTime(r)
  	out := api.Identity{Principal: principal, Method: cred.Method, Fingerprint: cred.Fingerprint,
  		Groups: []string{}, Grants: []api.IdentityGrant{}, API: []string{}, AuthTime: at.UTC().Format(time.RFC3339)}
  	if b.MaxSessionAge > 0 {
  		out.ConnectionEndsAt = at.Add(b.MaxSessionAge).UTC().Format(time.RFC3339)
  	}
  	rec := decision.Record{TS: now, Event: decision.EventIdentity, Verdict: decision.VerdictDeny,
  		Reason: decision.NoGrantsMatched, Principal: principal,
  		Auth: &decision.Auth{Method: cred.Method, Fingerprint: cred.Fingerprint}}
  	pol := b.Policy.Load()
  	if name, ok := pol.SubjectOf(principal); ok {
  		out.Subject = name
  		if sub, ok := pol.Subject(name); ok {
  			out.API = append(out.API, sub.API...)
  			slices.Sort(out.API)
  		}
  		for _, g := range pol.Grants(name) {
  			if !g.Expires.IsZero() && !now.Before(g.Expires) {
  				continue // expired: it selects nothing now
  			}
  			ig := api.IdentityGrant{Scope: g.Scope, Roles: slices.Clone(g.Roles), MaxPrivilege: g.MaxPrivilege}
  			if !g.Expires.IsZero() {
  				ig.Expires = g.Expires.UTC().Format(time.RFC3339)
  			}
  			out.Grants = append(out.Grants, ig)
  		}
  		rec.Policy = &decision.Policy{Bundle: pol.Bundle, Subject: name}
  		if len(out.Grants) > 0 {
  			rec.Verdict, rec.Reason = decision.VerdictPermit, decision.GrantsMatched
  		}
  	}
  	b.emit(rec)
  	writeJSON(w, http.StatusOK, out)
  }
  ```

  In `Handler`, add `mux.HandleFunc("GET /v1/identity", b.identity)`.

- [ ] **Step 5: Run the tests.**

  Run: `go test ./internal/broker/`
  Expected: PASS, the existing mint, refresh and listener tests included.

- [ ] **Step 6: Commit.**

  ```bash
  gofmt -w internal/broker/broker.go internal/broker/listen.go internal/broker/identity_api.go \
    internal/broker/api/identity.go internal/broker/fixture_test.go internal/broker/identity_api_test.go
  make build && make test && make vet
  git add internal/broker/broker.go internal/broker/listen.go internal/broker/identity_api.go \
    internal/broker/api/identity.go internal/broker/fixture_test.go internal/broker/identity_api_test.go
  git commit -m "feat(broker): one preamble for every authenticated call, and GET /v1/identity

  The mint's checks (certificate, max_session_age, marks, certificate status)
  move into authenticate, recorded under the calling endpoint's event, and the
  listener's refusal at bind is recorded under the refused path's event.
  Identity answers the caller alone, with connection_ends_at. A test pins that
  no right widens a mint or a refresh (decision 34).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 5: `/healthz` and `/readyz` on the broker, readiness never the store's health

**Files:**
- Create: `internal/broker/health.go`
- Modify: `internal/broker/broker.go` (`Broker` gains `ready`; `Handler`)
- Modify: `cmd/port49d/main.go` (`run`: `SetReady` beside `rd.serving()` and every `rd.draining()`)
- Test: `internal/broker/health_test.go` (new); `cmd/port49d/broker_test.go` (one run-level check)

**Interfaces:**
- Produces:
  - `const broker.ReadyStarting, broker.ReadyServing, broker.ReadyDraining string`
  - `func (b *Broker) SetReady(state string)`
  - the routes `GET /healthz`, `GET /readyz`

- [ ] **Step 1: Write the failing tests.** Create `internal/broker/health_test.go`:

  ```go
  package broker

  import (
  	"context"
  	"errors"
  	"net/http/httptest"
  	"strings"
  	"testing"

  	"github.com/rhwendt/port49/internal/store"
  )

  // brokenStore fails every call it is asked, so a test can see that nothing
  // it answers depends on the store.
  type brokenStore struct{ store.Store }

  func (brokenStore) GetRevocation(context.Context, string, string) (store.Revocation, error) {
  	return store.Revocation{}, errors.New("store down")
  }

  func (brokenStore) ListRevocations(context.Context) ([]store.Revocation, error) {
  	return nil, errors.New("store down")
  }

  // /healthz is 200 while the handler answers; /readyz is 503 until the
  // broker serves, 200 while it does, 503 from shutdown; neither needs a
  // certificate or writes a record, and a store that fails every call does
  // not move either (design §12; decision 34).
  func TestHealthAndReadiness(t *testing.T) {
  	f := newFixture(t, 8)
  	f.b.Store = brokenStore{f.st}
  	get := func(path string) (int, string) {
  		w := httptest.NewRecorder()
  		f.b.Handler().ServeHTTP(w, httptest.NewRequest("GET", path, nil)) // no TLS at all
  		return w.Code, strings.TrimSpace(w.Body.String())
  	}
  	if code, body := get("/healthz"); code != 200 || body != "ok" {
  		t.Fatalf("healthz: %d %q", code, body)
  	}
  	if code, body := get("/readyz"); code != 503 || body != ReadyStarting {
  		t.Fatalf("readyz before serving: %d %q", code, body)
  	}
  	f.b.SetReady(ReadyServing)
  	if code, body := get("/readyz"); code != 200 || body != ReadyServing {
  		t.Fatalf("readyz serving, store down: %d %q", code, body)
  	}
  	f.b.SetReady(ReadyDraining)
  	if code, body := get("/readyz"); code != 503 || body != ReadyDraining {
  		t.Fatalf("readyz draining: %d %q", code, body)
  	}
  	if f.log.Len() != 0 {
  		t.Fatalf("a probe wrote a record: %s", f.log)
  	}
  }
  ```

  In `cmd/port49d/broker_test.go`, in the run-level test that starts `run` and waits for `"port49d:
  broker listening on "` (the one Task 2 changed to wait for `0 revocation(s) in force`), after the
  first mint add:

  ```go
  		// The broker's readiness, over its own TLS listener with no client
  		// certificate (decision 34).
  		pool := x509.NewCertPool()
  		caPEM, err := os.ReadFile(filepath.Join(pki, testpki.LabCA))
  		if err != nil {
  			t.Fatal(err)
  		}
  		pool.AppendCertsFromPEM(caPEM)
  		hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
  		resp, err := hc.Get("https://" + addr + "/readyz")
  		if err != nil {
  			t.Fatal(err)
  		}
  		body, _ := io.ReadAll(resp.Body)
  		resp.Body.Close()
  		if resp.StatusCode != 200 || strings.TrimSpace(string(body)) != broker.ReadyServing {
  			t.Fatalf("broker /readyz: %d %q", resp.StatusCode, body)
  		}
  ```

  `pki` is the directory that test's `postAsAlice(pki, addr)` already uses; add the imports it
  needs.

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/broker/ -run TestHealthAndReadiness`
  Expected: build failure (`ReadyStarting`, `SetReady` undefined).

- [ ] **Step 3: Implement.** Create `internal/broker/health.go`:

  ```go
  package broker

  import (
  	"fmt"
  	"net/http"
  )

  // The lines /readyz answers (design §17). Readiness is whether the broker
  // serves, and nothing else: store health, certificate status and
  // broker.revocations_file's health are alarms, never readiness, or a store
  // fault would take every replica out at once (design §12; decision 34).
  const (
  	ReadyStarting = "starting: the broker is not serving yet"
  	ReadyServing  = "serving"
  	ReadyDraining = "draining: port49d is shutting down"
  )

  // SetReady sets what /readyz answers: 200 for ReadyServing, 503 with the line
  // for anything else. Before the first call it answers ReadyStarting.
  func (b *Broker) SetReady(state string) { b.ready.Store(&state) }

  // healthz answers 200 while the handler answers. It needs no certificate,
  // reads nothing, and writes no record.
  func (b *Broker) healthz(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") }

  // readyz answers SetReady's state, with no certificate and no record.
  func (b *Broker) readyz(w http.ResponseWriter, _ *http.Request) {
  	why := ReadyStarting
  	if p := b.ready.Load(); p != nil {
  		why = *p
  	}
  	if why == ReadyServing {
  		fmt.Fprintln(w, why)
  		return
  	}
  	http.Error(w, why, http.StatusServiceUnavailable)
  }
  ```

  In `broker.go`, add to `Broker` after `said`:

  ```go
  	// ready is what /readyz answers (SetReady).
  	ready atomic.Pointer[string]
  ```

  with `sync/atomic` imported, and in `Handler`:

  ```go
  	mux.HandleFunc("GET /healthz", b.healthz)
  	mux.HandleFunc("GET /readyz", b.readyz)
  ```

  In `cmd/port49d/main.go`'s `run`, after `go func() { brokerErr <- brokerSrv.Serve(bl) }()`, add
  `brk.SetReady(broker.ReadyServing)`. Beside each `rd.draining()` in the final `select`, add
  `if brk != nil { brk.SetReady(broker.ReadyDraining) }`.

- [ ] **Step 4: Run the tests.**

  Run: `go test ./internal/broker/ ./cmd/port49d/`
  Expected: PASS.

- [ ] **Step 5: Commit.**

  ```bash
  gofmt -w internal/broker/health.go internal/broker/health_test.go internal/broker/broker.go cmd/port49d/main.go cmd/port49d/broker_test.go
  make build && make test && make vet
  git add internal/broker/health.go internal/broker/health_test.go internal/broker/broker.go cmd/port49d/main.go cmd/port49d/broker_test.go
  git commit -m "feat(broker): /healthz and /readyz, readiness never the store's health

  Design §12: a store fault must not take every replica's endpoint out. /readyz
  is serving or not; neither probe needs a certificate or writes a record.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 6: `store.DeleteToken` removes one token by ID

**Files:**
- Modify: `internal/store/store.go` (the interface, after `DeleteTokens`, ~line 423)
- Modify: `internal/store/memory/memory.go` (after `DeleteTokens`, ~line 393)
- Modify: `internal/store/crypt/crypt.go` (after `DeleteTokens`, ~line 245)
- Modify: `internal/store/storetest/storetest.go`
- Modify: `internal/store/memory/memory_test.go`, `internal/store/crypt/crypt_test.go` (call the
  property beside `storetest.TokenIndex`)
- Modify: `internal/daemon/authen/authen_test.go` (`noStore`, ~line 368, which implements
  `store.Store` in full and is asserted to by `var _ store.Store = noStore{}`, ~line 495)

**Interfaces:**
- Produces: `DeleteToken(ctx context.Context, k TokenKey, id string) error` on `store.Store`;
  `func storetest.DeleteTokenRemovesOne(t *testing.T, newStore func() store.Store, now time.Time)`.

- [ ] **Step 1: Write the failing property.** In `internal/store/storetest/storetest.go`, after
  `TokenIndex`:

  ```go
  // DeleteTokenRemovesOne is DeleteToken (plan 7c): it removes the live token
  // with that ID and leaves every other under the key, and every token under
  // every other key; a second delete, an ID never put, and a key with nothing
  // under it are ErrNotFound. A principal ending its own sessions deletes its
  // own tokens this way and never another's under the same (device, username)
  // (spec §5.1.4; decision 34).
  func DeleteTokenRemovesOne(t *testing.T, newStore func() store.Store, now time.Time) {
  	t.Helper()
  	ctx := context.Background()
  	s := newStore()
  	k := store.TokenKey{NAS: "leaf-01", Username: "svc"}
  	other := store.TokenKey{NAS: "leaf-02", Username: "svc"}
  	put := func(k store.TokenKey, id, principal string) {
  		t.Helper()
  		if _, err := s.PutToken(ctx, k, store.Token{ID: id, Secret: []byte("secret-" + id), Kind: store.KindLogin,
  			ExpiresAt: now.Add(time.Minute), Principal: principal, Username: k.Username, MintedAt: now}); err != nil {
  			t.Fatal(err)
  		}
  	}
  	put(k, "a", "spiffe://example.com/a")
  	put(k, "b", "spiffe://example.com/b")
  	put(other, "a", "spiffe://example.com/a")
  	if err := s.DeleteToken(ctx, k, "a"); err != nil {
  		t.Fatal(err)
  	}
  	got, err := s.Candidates(ctx, k)
  	if err != nil || len(got) != 1 || got[0].ID != "b" || got[0].Principal != "spiffe://example.com/b" {
  		t.Fatalf("left under the key: %v %v", got, err)
  	}
  	if got, err := s.Candidates(ctx, other); err != nil || len(got) != 1 {
  		t.Fatalf("another key's token: %v %v", got, err)
  	}
  	for _, c := range []struct {
  		k  store.TokenKey
  		id string
  	}{{k, "a"}, {k, "never"}, {store.TokenKey{NAS: "nowhere", Username: "svc"}, "b"}} {
  		if err := s.DeleteToken(ctx, c.k, c.id); !errors.Is(err, store.ErrNotFound) {
  			t.Fatalf("DeleteToken(%v, %q) = %v, want ErrNotFound", c.k, c.id, err)
  		}
  	}
  }
  ```

  Beside each existing `storetest.TokenIndex(t, …)` call, in `internal/store/memory/memory_test.go`
  and `internal/store/crypt/crypt_test.go`, add a test calling `storetest.DeleteTokenRemovesOne`
  with the same constructor:

  ```go
  func TestDeleteTokenRemovesOne(t *testing.T) {
  	now := time.Now()
  	storetest.DeleteTokenRemovesOne(t, func() store.Store { return New(func() time.Time { return now }) }, now)
  }
  ```

  In `crypt_test.go`, use the constructor its `TokenIndex` test passes.

- [ ] **Step 2: Run it to see it fail.**

  Run: `go test ./internal/store/...`
  Expected: build failure (`DeleteToken` is not a method of the stores).

- [ ] **Step 3: Implement.** In `internal/store/store.go`, after `DeleteTokens`:

  ```go
  	// DeleteToken removes the one live token with this ID under k, and
  	// nothing else: a principal ending its own sessions deletes its own
  	// tokens, never another's under the same (device, username) (spec
  	// §5.1.4; decision 34). ErrNotFound when no live token under k has that
  	// ID. The ID is plaintext (Token.ID), so the sealing layer passes it
  	// through.
  	DeleteToken(ctx context.Context, k TokenKey, id string) error
  ```

  In `internal/store/memory/memory.go`:

  ```go
  // DeleteToken removes the live token with this ID under k, compacting the
  // set as RedeemAndReceipt does, so the removed entry's Secret is not left
  // reachable from the backing array (clearTail).
  func (s *Store) DeleteToken(_ context.Context, k store.TokenKey, id string) error {
  	s.mu.Lock()
  	defer s.mu.Unlock()
  	set := s.live(k)
  	for i, t := range set {
  		if t.ID != id {
  			continue
  		}
  		s.tokens[k] = append(set[:i:i], set[i+1:]...)
  		clearTail(set, i)
  		if len(s.tokens[k]) == 0 {
  			delete(s.tokens, k)
  		}
  		return nil
  	}
  	return store.ErrNotFound
  }
  ```

  In `internal/store/crypt/crypt.go`:

  ```go
  // DeleteToken carries no sealed field: the key and the plaintext ID
  // address the record.
  func (w *wrapped) DeleteToken(ctx context.Context, k store.TokenKey, id string) error {
  	return w.inner.DeleteToken(ctx, k, id)
  }
  ```

  Three types implement `store.Store` in full rather than by embedding it: `memory.Store`,
  crypt's `wrapped` (both above), and `noStore` in `internal/daemon/authen/authen_test.go`. Add
  to the last, beside its `DeleteTokens` (~line 379):

  ```go
  func (noStore) DeleteToken(context.Context, store.TokenKey, string) error {
  	panic("store called")
  }
  ```

  Every other double (`author.FaultStore`, the broker's and the server's test stores) embeds
  `store.Store` and needs nothing. `go build ./... && go vet ./...` names any type this list
  missed.

- [ ] **Step 4: Run the tests.**

  Run: `go test ./internal/store/... ./internal/daemon/authen/ && go build ./...`
  Expected: PASS.

- [ ] **Step 5: Commit.**

  ```bash
  gofmt -w internal/store/store.go internal/store/memory/memory.go internal/store/crypt/crypt.go \
    internal/store/storetest/storetest.go internal/store/memory/memory_test.go internal/store/crypt/crypt_test.go \
    internal/daemon/authen/authen_test.go
  make build && make test && make vet
  git add internal/store/store.go internal/store/memory/memory.go internal/store/crypt/crypt.go \
    internal/store/storetest/storetest.go internal/store/memory/memory_test.go internal/store/crypt/crypt_test.go \
    internal/daemon/authen/authen_test.go
  git commit -m "feat(store): DeleteToken removes one token by ID, with a storetest property

  A principal ending its own sessions must not delete another principal's tokens
  under a shared (device, username); DeleteTokens has no finer cut.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 7: A principal ends its own sessions without a mark, and `revoke_others` ends a key

**Files:**
- Create: `internal/broker/revokeown.go`
- Modify: `internal/broker/revoke.go` (`RevokeReport` gains `By`, `Key`; `normal` calls
  `normalPrincipal`; `Revoke` and `Lift` set `By`; `unreachedOf` lifted out of `Revoke`;
  `recordRevocation` and `Text` learn `self` and `key`; `LiftNote`)
- Modify: `internal/daemon/metrics/metrics.go` (`Revocations`' comment, ~line 151, and help,
  ~line 377: the `by` label gains `self` and `key`; pre-flight M5)
- Test: `internal/broker/revokeown_test.go` (new)

**Interfaces:**
- Consumes: `store.DeleteToken` (Task 6), `store.SetContextPolicy` with `ContextPolicy{RevokedAt}`,
  `store.SetRevokedAt`, `store.DeleteTokens`, `store.DeleteReceiptsByPrincipal`, `b.supersede`,
  `b.detach`, `sessionOnly`.
- Produces:
  - `const ByPrincipal = store.RevocationPrincipal`, `ByCert = store.RevocationCert`,
    `ByOwn = "self"`, `ByKey = "key"`
  - `RevokeReport.By string`, `RevokeReport.Key store.TokenKey`, `RevokeReport.LiftNote string`
  - `func (b *Broker) RevokeOwn(ctx context.Context, principal string, only *store.TokenKey, origin string) RevokeReport`
  - `func (b *Broker) RevokeKey(ctx context.Context, k store.TokenKey, origin string) RevokeReport`
  - `func normalPrincipal(p string) (string, error)`
  - `func (b *Broker) unreachedOf(refs []store.ContextRef) []store.ContextRef`

- [ ] **Step 1: Write the failing tests.** Create `internal/broker/revokeown_test.go`:

  ```go
  package broker

  import (
  	"context"
  	"errors"
  	"strings"
  	"sync"
  	"testing"
  	"time"

  	"github.com/prometheus/client_golang/prometheus/testutil"

  	"github.com/rhwendt/port49/internal/store"
  )

  // Two principals under one subject share its username, so their tokens
  // and their context share (device, username) keys: the shape a self
  // revocation must not reach across.
  const sharedPolicy = `
  scopes:
    - {name: all_devices, match: {}}
  roles:
    - {name: network_admin, privilege: admin, permit: ["**"]}
  subjects:
    - {name: netops, identity: ["user:alice@example.com", "user:alice2@example.com"], username: alice, token_ttl: 60s}
    - {name: oncall, identity: ["user:bob@example.com"], username: bob, token_ttl: 60s, api: [revoke_others]}
  grants:
    - {subject: netops, scope: all_devices, roles: [network_admin], max_privilege: admin}
  `

  const alice2 = "user:alice2@example.com"

  // mintFor mints one token on device for the certificate's principal and
  // fails the test unless it is a permit.
  func (f *fixture) mintFor(t *testing.T, email, device string) {
  	t.Helper()
  	c := f.client(t, email, f.now.Add(time.Hour))
  	r := decodeMint(t, f.post(context.Background(), f.state(c), `{"devices":["`+device+`"]}`, ""))
  	if len(r.Results) != 1 || r.Results[0].Verdict != "permit" {
  		t.Fatalf("mint for %s on %s: %v", email, device, r.Results)
  	}
  }

  func tokensOf(t *testing.T, f *fixture, k store.TokenKey) map[string]int {
  	t.Helper()
  	toks, err := f.st.Candidates(context.Background(), k)
  	if err != nil {
  		t.Fatal(err)
  	}
  	out := map[string]int{}
  	for _, tk := range toks {
  		out[tk.Principal]++
  	}
  	return out
  }

  // RevokeOwn deletes the caller's own tokens and marks the caller's own
  // contexts, and nothing of another principal's under the same key; it
  // leaves no mark, so the caller mints again at once (spec §5.1.4;
  // decision 34).
  func TestRevokeOwnTakesOnlyTheCallersOwn(t *testing.T) {
  	f := newFixtureWithPolicy(t, 8, sharedPolicy)
  	ctx := context.Background()
  	f.mintFor(t, "alice@example.com", "leaf1")
  	f.mintFor(t, "alice2@example.com", "leaf1")
  	f.mintFor(t, "alice@example.com", "nx1")
  	f.liveContext(t, "leaf1", "alice", alice2, "")          // alice2's context on the shared key
  	f.liveContext(t, "nx1", "alice", alicePrincipal, "")    // alice's own
  	if err := f.st.IndexContext(ctx, alicePrincipal, "", "", store.ContextRef{NAS: "leaf1", Username: "alice"},
  		time.Hour); err != nil { // a stale entry: alice once held leaf1's context
  		t.Fatal(err)
  	}
  	rep := f.b.RevokeOwn(ctx, alicePrincipal, nil, "api "+alicePrincipal)
  	if rep.Err != nil || rep.By != ByOwn || rep.TokenKeys != 2 || len(rep.Contexts) != 1 ||
  		rep.Contexts[0] != (store.ContextRef{NAS: "nx1", Username: "alice"}) {
  		t.Fatalf("%+v", rep)
  	}
  	if got := tokensOf(t, f, store.TokenKey{NAS: "leaf1", Username: "alice"}); got[alicePrincipal] != 0 || got[alice2] != 1 {
  		t.Fatalf("leaf1's tokens after: %v", got)
  	}
  	if c, _ := f.st.GetContext(ctx, store.ContextKey{NAS: "leaf1", Username: "alice"}); !c.RevokedAt.IsZero() {
  		t.Fatal("alice2's context was marked by alice's self-revocation")
  	}
  	if c, _ := f.st.GetContext(ctx, store.ContextKey{NAS: "nx1", Username: "alice"}); c.RevokedAt.IsZero() {
  		t.Fatal("alice's own context was not marked")
  	}
  	if _, err := f.st.GetRevocation(ctx, store.RevocationPrincipal, alicePrincipal); !errors.Is(err, store.ErrNotFound) {
  		t.Fatalf("a self-revocation left a mark: %v", err)
  	}
  	f.mintFor(t, "alice@example.com", "leaf1") // nothing stands against her
  }

  // With a key it reaches that key alone.
  func TestRevokeOwnOnOneKey(t *testing.T) {
  	f := newFixtureWithPolicy(t, 8, sharedPolicy)
  	ctx := context.Background()
  	f.mintFor(t, "alice@example.com", "leaf1")
  	f.mintFor(t, "alice@example.com", "nx1")
  	f.liveContext(t, "leaf1", "alice", alicePrincipal, "")
  	f.liveContext(t, "nx1", "alice", alicePrincipal, "")
  	k := store.TokenKey{NAS: "leaf1", Username: "alice"}
  	rep := f.b.RevokeOwn(ctx, alicePrincipal, &k, "api "+alicePrincipal)
  	if rep.TokenKeys != 1 || len(rep.Contexts) != 1 || rep.Key != k {
  		t.Fatalf("%+v", rep)
  	}
  	if got := tokensOf(t, f, store.TokenKey{NAS: "nx1", Username: "alice"}); got[alicePrincipal] != 1 {
  		t.Fatalf("nx1's token was taken: %v", got)
  	}
  	if c, _ := f.st.GetContext(ctx, store.ContextKey{NAS: "nx1", Username: "alice"}); !c.RevokedAt.IsZero() {
  		t.Fatal("nx1's context was marked")
  	}
  }

  // replacingStore lets one GetContext of key read what was there, then puts
  // another principal's context over it before the caller's write: a login
  // that replaced the context between the read and the mark.
  type replacingStore struct {
  	store.Store
  	key  store.ContextKey
  	with store.Context
  	once sync.Once
  }

  func (s *replacingStore) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
  	c, err := s.Store.GetContext(ctx, k)
  	if k == s.key {
  		s.once.Do(func() { _ = s.Store.PutContext(ctx, k, s.with, time.Hour) })
  	}
  	return c, err
  }

  // A self-revocation never marks a context another principal's login
  // replaced after it was read: the mark is a compare-and-set on the policy
  // revision read, and the read again finds it is not the caller's (Review
  // Focus 2; decision 34).
  func TestRevokeOwnNeverMarksAContextAnotherLoginReplaced(t *testing.T) {
  	f := newFixtureWithPolicy(t, 8, sharedPolicy)
  	ctx := context.Background()
  	f.liveContext(t, "leaf1", "alice", alicePrincipal, "")
  	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
  	f.b.Store = &replacingStore{Store: f.st, key: k,
  		with: store.Context{CtxID: "ctx_alice2", Principal: alice2, Username: "alice", PrivLvl: 1, AuthTime: f.now}}
  	rep := f.b.RevokeOwn(ctx, alicePrincipal, nil, "api "+alicePrincipal)
  	if len(rep.Contexts) != 0 {
  		t.Fatalf("reported a context marked: %+v", rep)
  	}
  	c, err := f.st.GetContext(ctx, k)
  	if err != nil || c.Principal != alice2 || !c.RevokedAt.IsZero() {
  		t.Fatalf("alice2's replacing context: %+v %v", c, err)
  	}
  }

  // RevokeKey, revoke_others' key form, takes everything under the key
  // whoever's it is, with the owner's receipts, and leaves no mark.
  func TestRevokeKeyTakesEverythingUnderTheKey(t *testing.T) {
  	f := newFixtureWithPolicy(t, 8, sharedPolicy)
  	ctx := context.Background()
  	f.mintFor(t, "alice@example.com", "leaf1")
  	f.mintFor(t, "alice2@example.com", "leaf1")
  	f.liveContext(t, "leaf1", "alice", alice2, "")
  	k := store.TokenKey{NAS: "leaf1", Username: "alice"}
  	rep := f.b.RevokeKey(ctx, k, "api user:bob@example.com")
  	if rep.Err != nil || rep.By != ByKey || rep.TokenKeys != 1 || len(rep.Contexts) != 1 || rep.Request.Principal != alice2 {
  		t.Fatalf("%+v", rep)
  	}
  	if got := tokensOf(t, f, k); len(got) != 0 {
  		t.Fatalf("tokens left: %v", got)
  	}
  	if c, _ := f.st.GetContext(ctx, store.ContextKey{NAS: "leaf1", Username: "alice"}); c.RevokedAt.IsZero() {
  		t.Fatal("the context was not marked")
  	}
  	if rs, _ := f.st.ListRevocations(ctx); len(rs) != 0 {
  		t.Fatalf("a key revocation left a mark: %v", rs)
  	}
  }

  // Each writes one revoke record (spec §5.7): by self or key, the origin,
  // the key, no saved; and counts port49_revocations_total by self or key.
  func TestSelfAndKeyRevocationsAreRecorded(t *testing.T) {
  	f := newFixtureWithPolicy(t, 8, sharedPolicy)
  	ctx := context.Background()
  	f.liveContext(t, "leaf1", "alice", alicePrincipal, "")
  	k := store.TokenKey{NAS: "leaf1", Username: "alice"}
  	f.b.RevokeOwn(ctx, alicePrincipal, &k, "api "+alicePrincipal)
  	f.b.RevokeKey(ctx, k, "api user:bob@example.com")
  	recs := eventsOf(f.records(t), "revoke")
  	if len(recs) != 2 {
  		t.Fatalf("%v", recs)
  	}
  	for i, by := range []string{"self", "key"} {
  		rv := recs[i]["revocation"].(map[string]any)
  		if recs[i]["verdict"] != "deny" || recs[i]["reason"] != "credential_revoked" || rv["by"] != by ||
  			rv["device"] != "leaf1" || rv["username"] != "alice" || rv["saved"] != nil {
  			t.Fatalf("%s: %v", by, recs[i])
  		}
  	}
  	if recs[0]["principal"] != alicePrincipal || recs[0]["revocation"].(map[string]any)["origin"] != "api "+alicePrincipal {
  		t.Fatalf("self: %v", recs[0])
  	}
  	for _, by := range []string{"self", "key"} {
  		if n := testutil.ToFloat64(f.b.Metrics.Revocations.WithLabelValues(by, "applied")); n != 1 {
  			t.Fatalf("port49_revocations_total{by=%s} = %v", by, n)
  		}
  	}
  }

  // What port49 revoke prints for each.
  func TestSelfAndKeyRevocationsSayWhatTheyDid(t *testing.T) {
  	at := time.Date(2026, 10, 2, 3, 12, 9, 0, time.UTC)
  	own := RevokeReport{By: ByOwn, Request: RevokeRequest{Principal: alicePrincipal}, Mark: store.Revocation{At: at},
  		Contexts: []store.ContextRef{{NAS: "leaf1", Username: "alice"}, {NAS: "srx1", Username: "alice"}},
  		Unreached: []store.ContextRef{{NAS: "srx1", Username: "alice"}}, TokenKeys: 3}
  	want := "ended user:alice@example.com's sessions everywhere at 2026-10-02T03:12:09Z: 2 live context(s) marked, " +
  		"the unspent tokens under 3 (device, username) key(s) deleted; nothing stands against " +
  		"user:alice@example.com, so a new `port49 token` and login work at once\n" +
  		"your next login on a device re-admits every session open there under your username: if anyone else used " +
  		"your token, close their session on the device (or ask an operator to revoke your principal) before you " +
  		"log in there again\n" +
  		"not reached, on a platform that never asks port49 about a command (close these on the device): srx1 (alice)"
  	if got := own.Text(); got != want {
  		t.Fatalf("self:\n%s\nwant\n%s", got, want)
  	}
  	key := RevokeReport{By: ByKey, Key: store.TokenKey{NAS: "leaf1", Username: "alice"},
  		Request: RevokeRequest{Principal: alice2}, Mark: store.Revocation{At: at}, TokenKeys: 1,
  		Contexts: []store.ContextRef{{NAS: "leaf1", Username: "alice"}}}
  	if got := key.Text(); !strings.HasPrefix(got, "ended the session on leaf1 (alice), user:alice2@example.com's, at "+
  		"2026-10-02T03:12:09Z: 1 live context(s) marked, the unspent tokens under 1 key(s) deleted; no revocation "+
  		"stands, so its owner can mint and log in again (to stop that, revoke the principal)\n"+
  		"the owner's next login on leaf1 re-admits any session still open on it under alice; close it on the device") {
  		t.Fatalf("key: %s", got)
  	}
  	// A standing mark made over HTTP says where it is lifted (decision 34).
  	mark := RevokeReport{By: ByPrincipal, Request: RevokeRequest{Principal: alice2},
  		Mark: store.Revocation{Kind: store.RevocationPrincipal, At: at}, LiftNote: "the lift is made on X"}
  	if got := mark.Text(); !strings.HasSuffix(got, "\nthe lift is made on X") {
  		t.Fatalf("mark: %s", got)
  	}
  }
  ```

  The fixture's devices are `leaf1` (arista_eos), `nx1` (cisco_nxos) and `bare`. `liveContext`
  writes a context indexed under the principal given.

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/broker/ -run 'TestRevokeOwn|TestRevokeKey|TestSelfAndKey'`
  Expected: build failure (`RevokeOwn`, `RevokeKey`, `ByOwn`, `ByKey`, `RevokeReport.By` undefined).

- [ ] **Step 3: `RevokeReport`, `normalPrincipal`, `unreachedOf`.** In `internal/broker/revoke.go`:

  ```go
  // What a revocation named (spec §5.7's revoke body, "by"). A principal's
  // or a certificate's is a standing mark (Revoke, Lift); a principal ending
  // its own sessions (RevokeOwn) and one (device, username) ended
  // (RevokeKey) leave none (decision 34).
  const (
  	ByPrincipal = store.RevocationPrincipal
  	ByCert      = store.RevocationCert
  	ByOwn       = "self"
  	ByKey       = "key"
  )
  ```

  Add to `RevokeReport` after `Request`:

  ```go
  	// By is what the revocation named (ByPrincipal, ByCert, ByOwn, ByKey).
  	By string
  	// Key is the (device, username) a ByKey revocation, or a ByOwn one
  	// limited to one key, named.
  	Key store.TokenKey
  	// LiftNote says where a standing mark made over HTTP is lifted: the
  	// endpoint sets it from Broker.AdminSocket (decision 34), and Text prints
  	// it after the mark's own text. Empty from the admin socket, whose
  	// caller is already there.
  	LiftNote string
  ```

  Lift `normal`'s principal branch into a function, and have `normal` call it:

  ```go
  // normalPrincipal is p as Identity spells it: user: and the lower-cased
  // email, the mapping being case-insensitive by construction. One that is
  // not printable ASCII, has no known prefix, or nothing after it, is refused
  // (pre-flight I2, M16). The HTTP endpoints compare a caller to a principal
  // a request names only after this, so no spelling makes another principal
  // read as the caller, or the caller as another (decision 34).
  func normalPrincipal(p string) (string, error) {
  	if len(p) > 1024 || strings.IndexFunc(p, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
  		return "", fmt.Errorf("%w: a principal is printable ASCII", ErrBadRevocation)
  	}
  	for _, pre := range principalPrefixes {
  		if strings.HasPrefix(strings.ToLower(p), pre) && len(p) > len(pre) {
  			return pre + strings.ToLower(p[len(pre):]), nil
  		}
  	}
  	return "", fmt.Errorf("%w: a principal begins %s, as the log names it (user:alice@example.com)",
  		ErrBadRevocation, strings.Join(principalPrefixes, " or "))
  }
  ```

  ```go
  	case req.Principal != "":
  		p, err := normalPrincipal(req.Principal)
  		if err != nil {
  			return req, "", "", err
  		}
  		req.Principal = p
  		return req, store.RevocationPrincipal, p, nil
  ```

  Replace `Revoke`'s closing loop over `rep.Contexts` (the one that builds `rep.Unreached`) with
  `rep.Unreached = b.unreachedOf(rep.Contexts)`, and add:

  ```go
  // unreachedOf is each of refs on a platform that never asks about a command,
  // which keeps the live session whatever its context says (spec §13 decision
  // 21), or on a device the inventory gives no platform, assumed to, as the
  // refresh assumes.
  func (b *Broker) unreachedOf(refs []store.ContextRef) []store.ContextRef {
  	pol := b.Policy.Load()
  	var out []store.ContextRef
  	for _, ref := range refs {
  		if dev, ok := pol.Device(ref.NAS); !ok || dev.Platform == "" || sessionOnly(pol, dev.Platform) {
  			out = append(out, ref)
  		}
  	}
  	return out
  }
  ```

  In `Revoke`, set `By: kind` in `rep := RevokeReport{…}`. In `Lift`, set `By: cur.Kind`.

  `recordRevocation` keys on `rep.By`:

  ```go
  func (b *Broker) recordRevocation(now time.Time, rep RevokeReport, verdict string, reason decision.Reason, outcome string) {
  	body := &decision.Revocation{By: rep.By, At: decision.FormatTime(rep.Mark.At), Origin: rep.Request.Origin,
  		Contexts: len(rep.Contexts), TokenKeys: rep.TokenKeys, Connections: rep.Connections}
  	rec := decision.Record{TS: now, Event: decision.EventRevoke, Verdict: verdict, Reason: reason, Revocation: body}
  	switch rep.By {
  	case ByCert:
  		body.Issuer, body.Serial = rep.Request.Issuer, rep.Request.Serial
  	default:
  		rec.Principal = rep.Request.Principal // ByKey: the context's owner, when one was read
  	}
  	if rep.Key != (store.TokenKey{}) {
  		body.Device, body.Username = rep.Key.NAS, rep.Key.Username
  	}
  	if rep.By == ByPrincipal || rep.By == ByCert {
  		saved := rep.Saved // a standing mark's file; self and key write none
  		body.Saved = &saved
  	}
  	for _, ref := range rep.Unreached {
  		body.Unreached = append(body.Unreached, decision.ContextRef{Device: ref.NAS, Username: ref.Username})
  	}
  	if rep.Err != nil {
  		body.Error = printsafe.Line(rep.Err.Error(), 300)
  	}
  	b.emit(rec)
  	b.Metrics.Revocations.WithLabelValues(rep.By, outcome).Inc()
  }
  ```

  `Text` splits on `By`. Rename the current body of `Text` to `markText`, take its two trailing
  blocks (`len(r.Unreached) > 0 …` and `r.SaveErr`/`r.Err`) out of it, and write:

  ```go
  // Text is what port49 revoke prints for a revocation: for a standing mark,
  // a warning first when the principal may be misspelled, what was revoked and
  // what it reached; for a self or key revocation, what it ended and that
  // nothing stands; then, for all, the contexts it could not reach and
  // anything that did not finish.
  func (r RevokeReport) Text() string {
  	var b strings.Builder
  	at := r.Mark.At.UTC().Format(time.RFC3339)
  	switch r.By {
  	case ByOwn:
  		where := "everywhere"
  		if r.Key != (store.TokenKey{}) {
  			where = fmt.Sprintf("on %s (%s)", r.Key.NAS, r.Key.Username)
  		}
  		fmt.Fprintf(&b, "ended %s's sessions %s at %s: %d live context(s) marked, the unspent tokens under %d "+
  			"(device, username) key(s) deleted; nothing stands against %s, so a new `port49 token` and login work "+
  			"at once", r.Request.Principal, where, at, len(r.Contexts), r.TokenKeys, r.Request.Principal)
  		// A login joins the context it shares and lifts its mark for every
  		// session on that (device, username) (spec §5.6; decision 15), a
  		// stranger's on a leaked token included (pre-flight I1).
  		b.WriteString("\nyour next login on a device re-admits every session open there under your username: if " +
  			"anyone else used your token, close their session on the device (or ask an operator to revoke your " +
  			"principal) before you log in there again")
  	case ByKey:
  		owner := ""
  		if r.Request.Principal != "" {
  			owner = ", " + r.Request.Principal + "'s,"
  		}
  		fmt.Fprintf(&b, "ended the session on %s (%s)%s at %s: %d live context(s) marked, the unspent tokens "+
  			"under %d key(s) deleted; no revocation stands, so its owner can mint and log in again (to stop that, "+
  			"revoke the principal)", r.Key.NAS, r.Key.Username, owner, at, len(r.Contexts), r.TokenKeys)
  		fmt.Fprintf(&b, "\nthe owner's next login on %s re-admits any session still open on it under %s; close it "+
  			"on the device", r.Key.NAS, r.Key.Username)
  	default:
  		b.WriteString(r.markText())
  		if r.LiftNote != "" {
  			b.WriteString("\n" + r.LiftNote)
  		}
  	}
  	if len(r.Unreached) > 0 {
  		var names []string
  		for _, ref := range r.Unreached {
  			names = append(names, fmt.Sprintf("%s (%s)", ref.NAS, ref.Username))
  		}
  		fmt.Fprintf(&b, "\nnot reached, on a platform that never asks port49 about a command (close these on the "+
  			"device): %s", strings.Join(names, ", "))
  	}
  	if r.SaveErr != nil {
  		fmt.Fprintf(&b, "\nNOT saved to broker.revocations_file (%v): this is in force now, and a restart of "+
  			"port49d forgets it", r.SaveErr)
  	}
  	if r.Err != nil && (r.By == ByPrincipal || r.By == ByCert) {
  		fmt.Fprintf(&b, "\nincomplete: %v; the mark is in force and refuses every new mint, but until a run "+
  			"finishes, unspent tokens may still log in on a device (up to their TTL) and unmarked contexts keep "+
  			"authorizing — run the same command again, which repeats every step", r.Err)
  	} else if r.Err != nil {
  		fmt.Fprintf(&b, "\nincomplete: %v; what it reached is ended, and the rest still works: run the same "+
  			"command again, which repeats every step", r.Err)
  	}
  	return b.String()
  }
  ```

  Every existing `Text` test must pass unchanged: the mark's text is the same bytes, and
  `LiftNote` is empty on the admin socket's path.

  In `internal/daemon/metrics/metrics.go`, `Revocations`' comment becomes "port49_revocations_total{by,
  outcome}: revocations by what they named, principal or cert (a standing mark), self (a principal
  ending its own sessions) or key (one (device, username) ended), and outcome: applied, partial
  (a later step failed) or lifted (spec §5.1.4; decision 34)", and its `Help` "Revocations by what
  they named (principal, cert, self, key) and outcome." The label set is closed; no principal,
  device or right is a label.

- [ ] **Step 4: `RevokeOwn` and `RevokeKey`.** Create `internal/broker/revokeown.go`:

  ```go
  package broker

  import (
  	"context"
  	"errors"
  	"fmt"
  	"time"

  	"github.com/rhwendt/port49/internal/decision"
  	"github.com/rhwendt/port49/internal/store"
  )

  // ownRevokeTries bounds how often a self-revocation reads a context again
  // after its compare-and-set lost to another write.
  const ownRevokeTries = 3

  // RevokeOwn ends principal's own live sessions and deletes its own unspent
  // tokens, everywhere or on the one key only names, and leaves no mark:
  // nothing stands against principal after it, and a token minted later joins
  // the revoked context and lifts it (spec §5.1.4, §5.6; decisions 15, 34).
  // It is what a principal may do to itself with no api: right.
  //
  // It never reaches another principal's, even under a shared (device,
  // username): tokens are deleted one by one by ID, only those the caller
  // minted (DeleteToken), and a context is marked by compare-and-set on the
  // policy revision read, only while it is the caller's (revokeOwnContext).
  // As Revoke does, tokens go before contexts and contexts are marked twice,
  // so a redemption in flight is caught; then the caller's receipts are
  // deleted, everywhere, even when only names one key: the store holds no
  // finer cut, so a retransmission in flight on another device is answered
  // token_spent (pre-flight M9). It closes no held connection: with no mark
  // the agent reconnects, and the request arrives on one.
  //
  // It runs to the end on a context detached from the caller and bounded by
  // RevokeTimeout, as Revoke does once it holds its slot, so a dropped
  // request never leaves it half done. A store error is the report's Err,
  // and the steps after it still run. One revoke record is written.
  func (b *Broker) RevokeOwn(ctx context.Context, principal string, only *store.TokenKey, origin string) RevokeReport {
  	ctx, cancel := b.detach(ctx)
  	defer cancel()
  	now := b.Now()
  	rep := RevokeReport{By: ByOwn, Request: RevokeRequest{Principal: principal, Origin: origin},
  		Mark: store.Revocation{At: now}}
  	note := func(err error) {
  		if err != nil && rep.Err == nil {
  			rep.Err = err
  		}
  	}
  	var keys []store.TokenKey
  	if only != nil {
  		rep.Key, keys = *only, []store.TokenKey{*only}
  	} else {
  		var err error
  		keys, err = b.Store.TokensByPrincipal(ctx, principal)
  		note(err)
  	}
  	for _, k := range keys {
  		toks, err := b.Store.Candidates(ctx, k)
  		if err != nil {
  			note(err)
  			continue
  		}
  		deleted := false
  		for _, t := range toks {
  			if t.Principal != principal {
  				continue
  			}
  			switch err := b.Store.DeleteToken(ctx, k, t.ID); {
  			case err == nil:
  				deleted = true
  			case !errors.Is(err, store.ErrNotFound): // gone since: spent, or expired
  				note(err)
  			}
  		}
  		if deleted {
  			// An idempotent retry of a mint from before now is minted
  			// afresh, not answered with a token that no longer exists.
  			b.supersede(k, b.Now())
  			rep.TokenKeys++
  		}
  	}
  	seen := map[store.ContextRef]bool{}
  	for pass := 0; pass < 2; pass++ {
  		var refs []store.ContextRef
  		if only != nil {
  			refs = []store.ContextRef{{NAS: only.NAS, Username: only.Username}}
  		} else {
  			var err error
  			refs, err = b.Store.ContextsByPrincipal(ctx, principal)
  			note(err)
  		}
  		for _, ref := range refs {
  			marked, err := b.revokeOwnContext(ctx, principal, ref, now)
  			note(err)
  			if marked && !seen[ref] {
  				seen[ref] = true
  				rep.Contexts = append(rep.Contexts, ref)
  			}
  		}
  	}
  	if _, err := b.Store.DeleteReceiptsByPrincipal(ctx, principal); err != nil {
  		note(err)
  	}
  	rep.Unreached = b.unreachedOf(rep.Contexts)
  	outcome := "applied"
  	if rep.Err != nil {
  		outcome = "partial"
  	}
  	b.recordRevocation(now, rep, decision.VerdictDeny, decision.CredentialRevoked, outcome)
  	return rep
  }

  // revokeOwnContext marks the context at ref revoked at at while it is
  // principal's, by compare-and-set on the policy revision it read
  // (SetContextPolicy with RevokedAt alone), so a context another principal's
  // login replaced in between is read again and left (decision 34). marked is
  // true when it is principal's and revoked at at or later. A context that
  // will not open is left, since whose it is cannot be read; its error is
  // returned.
  func (b *Broker) revokeOwnContext(ctx context.Context, principal string, ref store.ContextRef, at time.Time) (bool, error) {
  	k := store.ContextKey{NAS: ref.NAS, Username: ref.Username}
  	for try := 0; try < ownRevokeTries; try++ {
  		c, err := b.Store.GetContext(ctx, k)
  		switch {
  		case errors.Is(err, store.ErrNotFound):
  			return false, nil
  		case err != nil:
  			return false, err
  		case c.Principal != principal:
  			return false, nil
  		case !c.RevokedAt.IsZero() && !c.RevokedAt.Before(at):
  			return true, nil
  		}
  		switch err := b.Store.SetContextPolicy(ctx, k, c.PolicyRev, store.ContextPolicy{RevokedAt: at}); {
  		case err == nil:
  			return true, nil
  		case errors.Is(err, store.ErrConflict):
  			continue // written since it was read: read again, decide again
  		case errors.Is(err, store.ErrNotFound):
  			return false, nil
  		default:
  			return false, err
  		}
  	}
  	return false, fmt.Errorf("broker: the context on %s (%s) kept changing; run the revocation again", ref.NAS,
  		ref.Username)
  }

  // RevokeKey ends whatever holds one (device, username), whoever's it is:
  // every unspent token under it, its live context marked twice, and the
  // owner's receipts deleted, with no mark (spec §5.1.4; decision 34). It is
  // revoke_others' key form, so the endpoint calls it only for a caller
  // holding that right. A context that will not open is still marked, as a
  // revocation by certificate marks it (session.Manager): SetRevokedAt needs
  // no key. The owner's receipts are deleted everywhere, the store holding
  // no finer cut, which errs toward denying (session.Manager's mark).
  func (b *Broker) RevokeKey(ctx context.Context, k store.TokenKey, origin string) RevokeReport {
  	ctx, cancel := b.detach(ctx)
  	defer cancel()
  	now := b.Now()
  	rep := RevokeReport{By: ByKey, Key: k, Request: RevokeRequest{Origin: origin}, Mark: store.Revocation{At: now}}
  	note := func(err error) {
  		if err != nil && rep.Err == nil {
  			rep.Err = err
  		}
  	}
  	toks, cerr := b.Store.Candidates(ctx, k)
  	if err := b.Store.DeleteTokens(ctx, k); err != nil {
  		note(err)
  	} else {
  		b.supersede(k, b.Now())
  		if cerr != nil || len(toks) > 0 {
  			rep.TokenKeys = 1
  		}
  	}
  	ck := store.ContextKey{NAS: k.NAS, Username: k.Username}
  	for pass := 0; pass < 2; pass++ {
  		c, err := b.Store.GetContext(ctx, ck)
  		switch {
  		case errors.Is(err, store.ErrNotFound):
  			continue
  		case err != nil:
  			note(err)
  		case c.Principal != "":
  			rep.Request.Principal = c.Principal
  		}
  		switch err := b.Store.SetRevokedAt(ctx, ck, now); {
  		case err == nil:
  			if len(rep.Contexts) == 0 {
  				rep.Contexts = []store.ContextRef{{NAS: k.NAS, Username: k.Username}}
  			}
  		case !errors.Is(err, store.ErrNotFound):
  			note(err)
  		}
  	}
  	if rep.Request.Principal != "" {
  		if _, err := b.Store.DeleteReceiptsByPrincipal(ctx, rep.Request.Principal); err != nil {
  			note(err)
  		}
  	}
  	rep.Unreached = b.unreachedOf(rep.Contexts)
  	outcome := "applied"
  	if rep.Err != nil {
  		outcome = "partial"
  	}
  	b.recordRevocation(now, rep, decision.VerdictDeny, decision.CredentialRevoked, outcome)
  	return rep
  }
  ```

- [ ] **Step 5: Run the tests.**

  Run: `go test ./internal/broker/`
  Expected: PASS, 7a's revocation tests included.

- [ ] **Step 6: Commit.**

  ```bash
  gofmt -w internal/broker/revoke.go internal/broker/revokeown.go internal/broker/revokeown_test.go \
    internal/daemon/metrics/metrics.go
  make build && make test && make vet
  git add internal/broker/revoke.go internal/broker/revokeown.go internal/broker/revokeown_test.go \
    internal/daemon/metrics/metrics.go
  git commit -m "feat(broker): RevokeOwn ends a principal's own sessions without a mark; RevokeKey ends one key

  A self-revocation deletes the caller's own tokens by ID and marks its own
  contexts by compare-and-set on the revision read, so nothing of another
  principal's under a shared (device, username) is reached (decision 34). Each
  text says the owner's next login on a device re-admits what is still open
  there (decision 15's join).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 8: `POST /v1/tokens/revoke`, self-only by default

**Files:**
- Create: `internal/broker/revoke_api.go`
- Create: `internal/broker/api/revoke.go`
- Modify: `internal/broker/broker.go` (`Broker` gains `AdminSocket`; `Handler`; `refuseRight`)
- Modify: `internal/broker/revoke.go` (`ErrRevocationBusy`, wrapped by `Revoke`'s busy error)
- Modify: `cmd/port49d/main.go` (`brk.AdminSocket`; the no-`admin_socket` start line, ~line 873)
- Modify: `cmd/port49d/admin_linux_test.go` (the start-line test, ~line 276; the admin-socket
  run, ~line 160)
- Test: `internal/broker/revoke_api_test.go` (new)

**Interfaces:**
- Consumes: `b.authenticate` (Task 4); `policy.HasRight`, `policy.RightRevokeOthers` (Task 3);
  `b.RevokeOwn`, `b.RevokeKey`, `normalPrincipal`, `ByPrincipal`, `ByKey`, `RevokeReport.LiftNote`
  (Task 7); `b.Revoke`, `b.acquireRevoke`, `holdTimeout` (7a and before); `Policy.SubjectOf`.
- Produces:
  - `type api.RevokeRequest struct{ Mine bool; Principal, Device, Username, Sid string }`
  - `type api.RevokeResponse struct{ By, Principal, Subject, Device, Username string; Standing bool; At string; Contexts, TokenKeys, Connections int; Unreached []api.SessionRef; Saved *bool; Incomplete, Text string }`
  - `type api.SessionRef struct{ Device, Username string }`
  - `func (r RevokeReport) response() api.RevokeResponse`
  - `func (b *Broker) answerRevocation(w http.ResponseWriter, pol *policy.Policy, rep RevokeReport, origin string)`
  - `func (b *Broker) refuseRight(w http.ResponseWriter, rec decision.Record, right, what string)`
  - `Broker.AdminSocket string`; `func (b *Broker) liftNote() string`
  - `var broker.ErrRevocationBusy error`
  - the route `POST /v1/tokens/revoke`

- [ ] **Step 1: Write the failing tests.** Create `internal/broker/revoke_api_test.go`:

  ```go
  package broker

  import (
  	"context"
  	"encoding/json"
  	"errors"
  	"net/http/httptest"
  	"strings"
  	"testing"
  	"time"

  	"github.com/rhwendt/port49/internal/broker/api"
  	"github.com/rhwendt/port49/internal/store"
  )

  func (f *fixture) revokeAs(t *testing.T, email, body string) *httptest.ResponseRecorder {
  	t.Helper()
  	return f.call(context.Background(), f.state(f.client(t, email, f.now.Add(time.Hour))), "POST",
  		"/v1/tokens/revoke", body)
  }

  func decodeRevoke(t *testing.T, w *httptest.ResponseRecorder) api.RevokeResponse {
  	t.Helper()
  	if w.Code != 200 {
  		t.Fatalf("%d %s", w.Code, w.Body)
  	}
  	var r api.RevokeResponse
  	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
  		t.Fatal(err)
  	}
  	return r
  }

  // A caller with no right cannot revoke another principal: 403
  // api_right_missing, one record naming the target and, in origin, the
  // caller, with no auth (one credential per record; decision 34), and the
  // target untouched (design §17).
  func TestRevokingAnotherNeedsTheRight(t *testing.T) {
  	f := newFixtureWithPolicy(t, 8, sharedPolicy)
  	ctx := context.Background()
  	f.mintFor(t, "alice@example.com", "leaf1")
  	w := f.revokeAs(t, "carol@example.com", `{"principal":"user:alice@example.com"}`)
  	if w.Code != 403 || !strings.Contains(w.Body.String(), `"error":"api_right_missing"`) ||
  		!strings.Contains(w.Body.String(), "revoke_others") {
  		t.Fatalf("%d %s", w.Code, w.Body)
  	}
  	recs := eventsOf(f.records(t), "revoke")
  	if len(recs) != 1 || recs[0]["reason"] != "api_right_missing" || recs[0]["principal"] != alicePrincipal ||
  		recs[0]["auth"] != nil || recs[0]["revocation"].(map[string]any)["origin"] != "api user:carol@example.com" {
  		t.Fatalf("%v", recs)
  	}
  	if got := tokensOf(t, f, store.TokenKey{NAS: "leaf1", Username: "alice"}); got[alicePrincipal] != 1 {
  		t.Fatalf("alice's token was taken: %v", got)
  	}
  	if _, err := f.st.GetRevocation(ctx, store.RevocationPrincipal, alicePrincipal); !errors.Is(err, store.ErrNotFound) {
  		t.Fatal("a refused revocation left a mark")
  	}
  }

  // The target is spelled as the broker spells it before it is compared with
  // the caller: another principal in capitals is still another, and the
  // caller's own in capitals is still the caller's (Review Focus 1).
  func TestARevocationIsComparedAsTheBrokerSpellsIt(t *testing.T) {
  	f := newFixtureWithPolicy(t, 8, sharedPolicy)
  	if w := f.revokeAs(t, "carol@example.com", `{"principal":"USER:Alice@Example.COM"}`); w.Code != 403 {
  		t.Fatalf("another principal in capitals: %d %s", w.Code, w.Body)
  	}
  	r := decodeRevoke(t, f.revokeAs(t, "alice@example.com", `{"principal":"USER:Alice@Example.COM"}`))
  	if r.By != "self" || r.Standing {
  		t.Fatalf("the caller's own in capitals: %+v", r)
  	}
  }

  // {"mine": true}, or the caller's own principal, is a self-revocation: no
  // mark, and the caller mints at once after it.
  func TestMineIsASelfRevocation(t *testing.T) {
  	f := newFixtureWithPolicy(t, 8, sharedPolicy)
  	f.mintFor(t, "alice@example.com", "leaf1")
  	r := decodeRevoke(t, f.revokeAs(t, "alice@example.com", `{"mine":true}`))
  	if r.By != "self" || r.Standing || r.TokenKeys != 1 || r.Saved != nil ||
  		!strings.Contains(r.Text, "nothing stands against user:alice@example.com") ||
  		!strings.Contains(r.Text, "close their session on the device") {
  		t.Fatalf("%+v", r)
  	}
  	f.mintFor(t, "alice@example.com", "leaf1")
  	r = decodeRevoke(t, f.revokeAs(t, "alice@example.com", `{"mine":true,"device":"leaf1","username":"alice"}`))
  	if r.By != "self" || r.Device != "leaf1" || r.Username != "alice" || r.TokenKeys != 1 {
  		t.Fatalf("mine on one key: %+v", r)
  	}
  }

  // Under revoke_others, another principal is a standing mark with the caller
  // as its origin, the answer naming the target's subject and where the mark
  // is lifted, and the target's next mint is refused; a key is ended whoever
  // holds it. Without the right a key is refused 403 and recorded with the
  // key, never narrowed to the caller's own there (Review Focus 6;
  // pre-flight I2); the caller's own on one key is mine with the key, which
  // reaches nothing of alice's.
  func TestRevokeOthersMarksAPrincipalAndEndsAKey(t *testing.T) {
  	f := newFixtureWithPolicy(t, 8, sharedPolicy)
  	ctx := context.Background()
  	f.mintFor(t, "alice@example.com", "leaf1")
  	f.liveContext(t, "leaf1", "alice", alicePrincipal, "")
  	if w := f.revokeAs(t, "carol@example.com", `{"device":"leaf1","username":"alice"}`); w.Code != 403 ||
  		!strings.Contains(w.Body.String(), `"error":"api_right_missing"`) {
  		t.Fatalf("a peer's key revocation: %d %s", w.Code, w.Body)
  	}
  	recs := eventsOf(f.records(t), "revoke")
  	if len(recs) != 1 || recs[0]["reason"] != "api_right_missing" || recs[0]["principal"] != nil || recs[0]["auth"] != nil {
  		t.Fatalf("the peer's refusal: %v", recs)
  	}
  	if rv := recs[0]["revocation"].(map[string]any); rv["by"] != "key" || rv["device"] != "leaf1" ||
  		rv["username"] != "alice" || rv["origin"] != "api user:carol@example.com" {
  		t.Fatalf("the peer's refusal: %v", rv)
  	}
  	own := decodeRevoke(t, f.revokeAs(t, "carol@example.com", `{"mine":true,"device":"leaf1","username":"alice"}`))
  	if own.By != "self" || own.TokenKeys != 0 || own.Contexts != 0 {
  		t.Fatalf("the peer's own on alice's key: %+v", own)
  	}
  	if got := tokensOf(t, f, store.TokenKey{NAS: "leaf1", Username: "alice"}); got[alicePrincipal] != 1 {
  		t.Fatalf("the peer reached alice's token: %v", got)
  	}
  	key := decodeRevoke(t, f.revokeAs(t, "bob@example.com", `{"device":"leaf1","username":"alice"}`))
  	if key.By != "key" || key.TokenKeys != 1 || key.Contexts != 1 || key.Standing || key.Principal != alicePrincipal ||
  		key.Subject != "netops" {
  		t.Fatalf("bob's key revocation: %+v", key)
  	}
  	mark := decodeRevoke(t, f.revokeAs(t, "bob@example.com", `{"principal":"user:alice@example.com"}`))
  	if mark.By != "principal" || !mark.Standing || mark.Saved == nil || mark.Subject != "netops" ||
  		!strings.Contains(mark.Text, "port49d has no admin_socket configured: lifting this needs port49d stopped") {
  		t.Fatalf("bob's revocation of alice: %+v", mark)
  	}
  	rv, err := f.st.GetRevocation(ctx, store.RevocationPrincipal, alicePrincipal)
  	if err != nil || rv.Origin != "api user:bob@example.com" {
  		t.Fatalf("the mark: %+v %v", rv, err)
  	}
  	if w := f.post(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, ""); w.Code != 401 ||
  		!strings.Contains(w.Body.String(), "credential_revoked") {
  		t.Fatalf("alice's mint after the mark: %d %s", w.Code, w.Body)
  	}
  	f.b.AdminSocket = "/run/port49/port49d.sock"
  	again := decodeRevoke(t, f.revokeAs(t, "bob@example.com", `{"principal":"`+alice2+`"}`))
  	if !strings.HasSuffix(again.Text, "the lift is made on port49d's admin socket (/run/port49/port49d.sock), "+
  		"by port49d's user or root") {
  		t.Fatalf("a mark with an admin socket: %s", again.Text)
  	}
  }

  // A body naming no form, two forms, a sid, a lift, or a malformed device is
  // refused 400, and nothing is revoked or recorded.
  func TestARevocationBodyIsOneForm(t *testing.T) {
  	f := newFixtureWithPolicy(t, 8, sharedPolicy)
  	for body, want := range map[string]string{
  		`{}`: "name", `{"principal":"user:alice@example.com","device":"leaf1","username":"alice"}`: "not both",
  		`{"mine":true,"principal":"user:alice@example.com"}`: "not both",
  		`{"sid":"9c2b"}`: "OIDC", `{"principal":"user:alice@example.com","lift":true}`: "not a revocation request",
  		`{"device":"leaf 1","username":"alice"}`: "printable", `{"device":"leaf1"}`: "name",
  		`{"principal":"alice@example.com"}`: "begins user:",
  	} {
  		w := f.revokeAs(t, "bob@example.com", body)
  		if w.Code != 400 || !strings.Contains(w.Body.String(), want) {
  			t.Errorf("%s: %d %s", body, w.Code, w.Body)
  		}
  	}
  	if n := len(eventsOf(f.records(t), "revoke")); n != 0 {
  		t.Fatalf("%d revoke records for refused bodies", n)
  	}
  }

  // A revocation the store cannot record is 503 with a fixed sentence; the
  // store's error goes to the process log, not to the caller.
  func TestAMarkThatCannotBeWrittenIs503(t *testing.T) {
  	f := newFixtureWithPolicy(t, 8, sharedPolicy)
  	f.b.Store = putRevocationFails{f.st}
  	w := f.revokeAs(t, "bob@example.com", `{"principal":"user:alice@example.com"}`)
  	if w.Code != 503 || !strings.Contains(w.Body.String(), "store_unavailable") ||
  		strings.Contains(w.Body.String(), "disk on fire") || w.Header().Get("Retry-After") == "" {
  		t.Fatalf("%d %s", w.Code, w.Body)
  	}
  }

  type putRevocationFails struct{ store.Store }

  func (putRevocationFails) PutRevocation(context.Context, store.Revocation) error {
  	return errors.New("disk on fire")
  }

  // A revocation that waits out its bound behind another revocation or lift
  // is 503 revocation_busy, nothing revoked, never "could not be recorded"
  // (pre-flight M18).
  func TestABusyRevocationIs503(t *testing.T) {
  	f := newFixtureWithPolicy(t, 8, sharedPolicy)
  	defer func(d time.Duration) { holdTimeout = d }(holdTimeout)
  	holdTimeout = 50 * time.Millisecond
  	release, err := f.b.acquireRevoke(context.Background())
  	if err != nil {
  		t.Fatal(err)
  	}
  	defer release()
  	w := f.revokeAs(t, "bob@example.com", `{"principal":"user:alice@example.com"}`)
  	if w.Code != 503 || !strings.Contains(w.Body.String(), `"error":"revocation_busy"`) ||
  		w.Header().Get("Retry-After") == "" {
  		t.Fatalf("%d %s", w.Code, w.Body)
  	}
  	if _, err := f.st.GetRevocation(context.Background(), store.RevocationPrincipal, alicePrincipal); !errors.Is(err, store.ErrNotFound) {
  		t.Fatal("a busy revocation left a mark")
  	}
  }
  ```

  `sharedPolicy`, `mintFor`, `tokensOf` and `alice2` are Task 7's. `carol@example.com` is in no
  subject of `sharedPolicy`; she holds no right. `holdTimeout` is a var (`broker.go`, ~line 863)
  that `engine_test.go` already shortens the same way.

  In `cmd/port49d/admin_linux_test.go`, rename `TestRunWithABrokerAndNoAdminSocketSaysRevokeIsUnavailable`
  to `TestRunWithABrokerAndNoAdminSocketSaysWhatRevocationCanDo`, its comment to "A broker with no
  admin_socket says once, at start, that an HTTP revocation is made but nothing can lift it, and
  how to cut someone off meanwhile (pre-flight I7).", and its check to:

  ```go
  	if n := strings.Count(out.String(), "port49d: broker: no admin_socket: a revocation over HTTP"); n != 1 ||
  		strings.Contains(out.String(), "port49 revoke is unavailable") {
  		t.Fatalf("said %d times: %q", n, out.String())
  	}
  ```

  In `TestRunRevokesListsAndLiftsOverTheAdminSocket`, after its first wait for the listener, add
  `if strings.Contains(out.String(), "no admin_socket:") { t.Fatalf("said with an admin socket: %q", out.String()) }`.

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/broker/ -run 'TestRevokingAnother|TestARevocationIs|TestMineIs|TestRevokeOthers|TestARevocationBody|TestAMarkThatCannot|TestABusyRevocation' && go test ./cmd/port49d/ -run 'TestRunWithABrokerAndNoAdminSocket'`
  Expected: build failure (`api.RevokeResponse`, `AdminSocket` undefined), then 404s, and the old
  start line.

- [ ] **Step 3: The wire types.** Create `internal/broker/api/revoke.go`:

  ```go
  package api

  // RevokeRequest is POST /v1/tokens/revoke (design §17; spec §5.1.4). Exactly
  // one form: Mine (alone, or with Device and Username for the caller's own
  // on one key); Principal; or Device and Username (whoever holds the key,
  // under revoke_others). Sid is refused until OIDC (plan 7h). A token is
  // never sent: the broker finds what to revoke itself.
  type RevokeRequest struct {
  	Mine      bool   `json:"mine,omitempty"`
  	Principal string `json:"principal,omitempty"`
  	Device    string `json:"device,omitempty"`
  	Username  string `json:"username,omitempty"`
  	Sid       string `json:"sid,omitempty"`
  }

  // SessionRef names a live session by device and device-facing username.
  type SessionRef struct {
  	Device   string `json:"device"`
  	Username string `json:"username"`
  }

  // RevokeResponse says what a revocation reached. By is principal (a
  // standing mark), self or key (neither leaves one). Subject is the policy
  // subject the revoked principal, or the key's owner, resolves to, so a
  // misspelt colleague is seen at once; empty for self, or when no subject
  // names the principal. Saved is a standing mark's alone: whether
  // broker.revocations_file was written. Incomplete is set when a step did
  // not finish; running the same request again repeats every step. Text is
  // what port49 revoke prints.
  type RevokeResponse struct {
  	By          string       `json:"by"`
  	Principal   string       `json:"principal,omitempty"`
  	Subject     string       `json:"subject,omitempty"`
  	Device      string       `json:"device,omitempty"`
  	Username    string       `json:"username,omitempty"`
  	Standing    bool         `json:"standing"`
  	At          string       `json:"at"`
  	Contexts    int          `json:"contexts"`
  	TokenKeys   int          `json:"token_keys"`
  	Connections int          `json:"connections"`
  	Unreached   []SessionRef `json:"unreached"`
  	Saved       *bool        `json:"saved,omitempty"`
  	Incomplete  string       `json:"incomplete,omitempty"`
  	Text        string       `json:"text"`
  }
  ```

- [ ] **Step 4: The busy error.** In `internal/broker/revoke.go`, after `ErrBadRevocation`:

  ```go
  // ErrRevocationBusy is a revocation that could not take revokeSem before
  // its ctx ended: another revocation or lift was running, and this one did
  // nothing (decision 34). The HTTP endpoint answers it 503 revocation_busy.
  var ErrRevocationBusy = errors.New("broker: another revocation or lift is still running")
  ```

  and `Revoke`'s busy return wraps it, with the same bytes as today:

  ```go
  		return RevokeReport{}, fmt.Errorf("%w, so nothing was revoked by this one (%w); "+fallback,
  			ErrRevocationBusy, err)
  ```

  (Go 1.20's `fmt.Errorf` takes two `%w`.) `Lift` is the admin socket's alone and is left as it is.

- [ ] **Step 5: The handler.** Create `internal/broker/revoke_api.go`:

  ```go
  package broker

  import (
  	"context"
  	"encoding/json"
  	"errors"
  	"io"
  	"net/http"
  	"strings"
  	"time"

  	"github.com/rhwendt/port49/internal/broker/api"
  	"github.com/rhwendt/port49/internal/decision"
  	"github.com/rhwendt/port49/internal/policy"
  	"github.com/rhwendt/port49/internal/store"
  )

  // maxDeviceUsername bounds a device-facing username a request names: a
  // generous bound on what any platform takes, and what a record may carry.
  const maxDeviceUsername = 64

  // errIncomplete stands in, on the wire, for the store error that stopped a
  // step: the caller is told to run it again, and the process log says what
  // failed (Global Constraints).
  var errIncomplete = errors.New("a step did not finish (port49d's log says which)")

  // errNotSaved stands in, on the wire, for broker.revocations_file's write
  // error.
  var errNotSaved = errors.New("port49d's log says why")

  // tokensRevoke is POST /v1/tokens/revoke (design §17; spec §5.1.4; decision
  // 34). The caller acts on itself unless its subject declares revoke_others,
  // and the request's form, never the caller's rights, decides what it means:
  //
  //   - mine, or a principal that is the caller's: RevokeOwn, everywhere or,
  //     with a device and username, on that key alone, leaving no mark;
  //   - another principal: revoke_others, then 7a's Revoke, a standing mark
  //     whose origin is the caller; without the right, 403 api_right_missing;
  //   - a (device, username) without mine: revoke_others, then RevokeKey,
  //     whoever holds it; without the right, 403 api_right_missing, never the
  //     caller's own there (pre-flight I2): a right a reload withdrew minutes
  //     ago fails loudly, rather than reporting "0 contexts marked" to an
  //     on-call who believes someone else's session is gone.
  //
  // A principal is compared with the caller only as the broker spells it
  // (normalPrincipal), so no spelling crosses the line either way. The right
  // is read once, from the policy in force, before Revoke waits for its slot,
  // and not again after the wait, as a mint reads the policy once (pre-flight
  // M18). A lift and a revocation by certificate are the admin socket's alone.
  func (b *Broker) tokensRevoke(w http.ResponseWriter, r *http.Request) {
  	caller, _, ok := b.authenticate(w, r, decision.EventRevoke, "revoked nothing")
  	if !ok {
  		return
  	}
  	var req api.RevokeRequest
  	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<10))
  	dec.DisallowUnknownFields()
  	if err := dec.Decode(&req); err != nil {
  		writeError(w, http.StatusBadRequest, "bad_request", "the body is not a revocation request: "+
  			"name mine, a principal, or a device and a username (a lift is port49d's admin socket's)")
  		return
  	}
  	origin := "api " + caller
  	byKey := req.Device != "" || req.Username != ""
  	switch {
  	case req.Sid != "":
  		writeError(w, http.StatusBadRequest, "bad_request", "revocation by OIDC sid arrives with OIDC (plan 7h); "+
  			"revoke the principal")
  		return
  	case req.Mine && req.Principal != "", byKey && req.Principal != "":
  		writeError(w, http.StatusBadRequest, "bad_request", "name mine, a principal, or a device and a username, not both")
  		return
  	case !req.Mine && !byKey && req.Principal == "", byKey && (req.Device == "" || req.Username == ""):
  		writeError(w, http.StatusBadRequest, "bad_request", "name mine, a principal, or a device and a username "+
  			"(both, for one key)")
  		return
  	case byKey && (!deviceName(req.Device) || !deviceUsername(req.Username)):
  		writeError(w, http.StatusBadRequest, "bad_request", "a device is its inventory name and a username the "+
  			"device-facing one, each printable ASCII with no spaces")
  		return
  	}
  	pol := b.Policy.Load()
  	mayOthers := pol.HasRight(caller, policy.RightRevokeOthers)
  	if byKey {
  		k := store.TokenKey{NAS: req.Device, Username: req.Username}
  		switch {
  		case req.Mine:
  			b.answerRevocation(w, pol, b.RevokeOwn(r.Context(), caller, &k, origin), origin)
  		case mayOthers:
  			b.answerRevocation(w, pol, b.RevokeKey(r.Context(), k, origin), origin)
  		default:
  			b.refuseRight(w, decision.Record{TS: b.Now(), Event: decision.EventRevoke,
  				Revocation: &decision.Revocation{By: ByKey, Device: k.NAS, Username: k.Username,
  					At: decision.FormatTime(b.Now()), Origin: origin}},
  				policy.RightRevokeOthers, "ending a (device, username) whoever holds it")
  		}
  		return
  	}
  	if req.Mine {
  		b.answerRevocation(w, pol, b.RevokeOwn(r.Context(), caller, nil, origin), origin)
  		return
  	}
  	target, err := normalPrincipal(req.Principal)
  	if err != nil {
  		writeError(w, http.StatusBadRequest, "bad_request", strings.TrimPrefix(err.Error(), "broker: "))
  		return
  	}
  	if target == caller {
  		b.answerRevocation(w, pol, b.RevokeOwn(r.Context(), caller, nil, origin), origin)
  		return
  	}
  	if !mayOthers {
  		b.refuseRight(w, decision.Record{TS: b.Now(), Event: decision.EventRevoke, Principal: target,
  			Revocation: &decision.Revocation{By: ByPrincipal, At: decision.FormatTime(b.Now()), Origin: origin}},
  			policy.RightRevokeOthers, "revoking another principal")
  		return
  	}
  	// The wait for the revocation slot is bounded; once Revoke holds it, it
  	// runs to the end detached from this request (Revoke's comment).
  	wait, cancel := context.WithTimeout(r.Context(), holdTimeout)
  	defer cancel()
  	rep, err := b.Revoke(wait, RevokeRequest{Principal: target, Origin: origin})
  	switch {
  	case errors.Is(err, ErrBadRevocation):
  		writeError(w, http.StatusBadRequest, "bad_request", strings.TrimPrefix(err.Error(), "broker: "))
  	case errors.Is(err, ErrRevocationBusy):
  		w.Header().Set("Retry-After", "5")
  		writeError(w, http.StatusServiceUnavailable, "revocation_busy", "another revocation or lift is still "+
  			"running, so nothing was revoked; try again")
  	case err != nil:
  		// The mark was not written, so nothing was revoked: Revoke's own
  		// error names the store's fault and the fallback, for port49d's log.
  		b.logf("broker: a revocation of %s asked by %s was not made: %v", target, caller, err)
  		w.Header().Set("Retry-After", "10")
  		writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable), "the revocation could not "+
  			"be recorded, so nothing was revoked; try again, or ask an operator to run `port49 revoke` on port49d")
  	default:
  		rep.LiftNote = b.liftNote()
  		b.answerRevocation(w, pol, rep, origin)
  	}
  }

  // liftNote says where a standing mark made over HTTP is lifted: port49d's
  // admin socket, or, with none configured, the only way there is
  // (pre-flight I7). Revoking stays allowed without one: it is the safe
  // direction.
  func (b *Broker) liftNote() string {
  	if b.AdminSocket == "" {
  		return "port49d has no admin_socket configured: lifting this needs port49d stopped, the entry removed " +
  			"from broker.revocations_file, and a start"
  	}
  	return "the lift is made on port49d's admin socket (" + b.AdminSocket + "), by port49d's user or root"
  }

  // answerRevocation writes rep, with a step's store error, and a standing
  // mark's file error, replaced by fixed ones on the wire and said whole in
  // port49d's log: neither is the caller's to read. It names the subject the
  // revoked principal, or the key's owner, resolves to in pol (pre-flight
  // M11), so a typo of a real colleague's address is seen at once.
  func (b *Broker) answerRevocation(w http.ResponseWriter, pol *policy.Policy, rep RevokeReport, origin string) {
  	if rep.Err != nil {
  		b.logf("broker: a revocation (%s, by %s) did not finish: %v", rep.By, origin, rep.Err)
  		rep.Err = errIncomplete
  	}
  	if rep.SaveErr != nil {
  		b.logf("broker: a revocation (%s, by %s) was not saved to broker.revocations_file: %v", rep.By, origin,
  			rep.SaveErr)
  		rep.SaveErr = errNotSaved
  	}
  	out := rep.response()
  	if rep.By != ByOwn && rep.Request.Principal != "" {
  		out.Subject, _ = pol.SubjectOf(rep.Request.Principal)
  	}
  	writeJSON(w, http.StatusOK, out)
  }

  // response is rep's wire form (api.RevokeResponse), Subject aside.
  func (r RevokeReport) response() api.RevokeResponse {
  	out := api.RevokeResponse{By: r.By, Principal: r.Request.Principal, Standing: r.By == ByPrincipal || r.By == ByCert,
  		At: r.Mark.At.UTC().Format(time.RFC3339), Contexts: len(r.Contexts), TokenKeys: r.TokenKeys,
  		Connections: r.Connections, Unreached: []api.SessionRef{}, Text: r.Text()}
  	if r.Key != (store.TokenKey{}) {
  		out.Device, out.Username = r.Key.NAS, r.Key.Username
  	}
  	for _, ref := range r.Unreached {
  		out.Unreached = append(out.Unreached, api.SessionRef{Device: ref.NAS, Username: ref.Username})
  	}
  	if out.Standing {
  		saved := r.Saved
  		out.Saved = &saved
  	}
  	if r.Err != nil {
  		out.Incomplete = r.Err.Error()
  	}
  	return out
  }

  // deviceUsername reports whether s can be a device-facing username: 1 to
  // maxDeviceUsername bytes of printable ASCII, no spaces.
  func deviceUsername(s string) bool {
  	return s != "" && len(s) <= maxDeviceUsername &&
  		strings.IndexFunc(s, func(r rune) bool { return r < 0x21 || r > 0x7e }) < 0
  }
  ```

  In `internal/broker/broker.go`, add to `Broker`:

  ```go
  	// AdminSocket is port49d's admin_socket, where a revocation is lifted;
  	// empty when none is configured. Only the HTTP revocation's answer reads
  	// it, to say where its mark is lifted (decision 34).
  	AdminSocket string
  ```

  add to `Handler` `mux.HandleFunc("POST /v1/tokens/revoke", b.tokensRevoke)`, and after `emit`:

  ```go
  // refuseRight answers a call that would act on another principal, or on a
  // (device, username) whoever holds it, without the api: right that
  // unlocks it: 403 api_right_missing, and rec, the one deny record. rec
  // names whom the call was about and, in origin or explain.asked_by, who
  // asked; it carries no auth, so a record's auth and principal always
  // describe one credential (spec §5.7; decision 34). what says what was
  // asked, for the answer. Nothing is done.
  func (b *Broker) refuseRight(w http.ResponseWriter, rec decision.Record, right, what string) {
  	rec.Verdict, rec.Reason, rec.Auth = decision.VerdictDeny, decision.APIRightMissing, nil
  	b.emit(rec)
  	writeError(w, http.StatusForbidden, string(decision.APIRightMissing), fmt.Sprintf(
  		"%s needs the api: %s right, which your subject does not declare (spec §2)", what, right))
  }
  ```

  In `cmd/port49d/main.go`'s admin-socket block, beside `brk.RevokeTimeout = admin.OpTimeout`, add
  `brk.AdminSocket = cfg.AdminSocket`. Replace the no-`admin_socket` line (~line 873) with:

  ```go
  	if brk != nil && cfg.AdminSocket == "" {
  		fmt.Fprintln(stderr, "port49d: broker: no admin_socket: a revocation over HTTP (port49 revoke --via-agent, "+
  			"under api: revoke_others) is made, but none can be lifted, nor a certificate revoked, short of stopping "+
  			"port49d and editing broker.revocations_file; set admin_socket. To cut someone off meanwhile, remove "+
  			"their grants from broker.policy_file")
  	}
  ```

- [ ] **Step 6: Run the tests.**

  Run: `go test ./internal/broker/ ./cmd/port49d/`
  Expected: PASS.

- [ ] **Step 7: Commit.**

  ```bash
  gofmt -w internal/broker/revoke_api.go internal/broker/api/revoke.go internal/broker/broker.go \
    internal/broker/revoke.go internal/broker/revoke_api_test.go cmd/port49d/main.go cmd/port49d/admin_linux_test.go
  make build && make test && make vet
  git add internal/broker/revoke_api.go internal/broker/api/revoke.go internal/broker/broker.go \
    internal/broker/revoke.go internal/broker/revoke_api_test.go cmd/port49d/main.go cmd/port49d/admin_linux_test.go
  git commit -m "feat(broker): POST /v1/tokens/revoke, self-only unless revoke_others

  mine (or the caller's own principal) ends the caller's sessions with no mark,
  on one key with a device and username; another principal under revoke_others
  is 7a's standing mark, its origin the caller, its answer naming the target's
  subject and where it is lifted; a (device, username) is ended whoever holds
  it under revoke_others. Without the right either is 403 api_right_missing and
  one record with no auth. A busy slot is 503 revocation_busy. port49d's start
  line says an HTTP mark cannot be lifted without admin_socket (decision 34).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 9: `POST /v1/explain`, from the policy in force, never a device oracle

**Files:**
- Modify: `internal/policy/explain.go` (`Explanation.Revoked`; `Answer`; `Render`'s revoked and
  no-grant lines; `wouldPermit` reads compiled programs from `permitPrograms`)
- Modify: `internal/policy/load.go` (`Policy` gains `permitsAlone`, beside `projected`, ~line 91)
- Create: `internal/broker/explain_api.go`
- Create: `internal/broker/api/explain.go`
- Modify: `internal/broker/broker.go` (`Handler`)
- Test: `internal/policy/explain_test.go` (add), `internal/broker/explain_api_test.go` (new)

**Interfaces:**
- Consumes: `b.authenticate` (Task 4); `b.refuseRight(w, rec, right, what)` (Task 8);
  `normalPrincipal` (Task 7); `policy.Policy.Explain`, `Explanation.Redacted`, `Explanation.Render`,
  `Policy.Redactions`, `Policy.Quarantined`, `Policy.Admitted`; `b.revocation`.
- Produces:
  - `Explanation.Revoked time.Time`
  - `func (e policy.Explanation) Answer() (verdict string, reason decision.Reason, mintError string)`
  - `Policy.permitsAlone sync.Map`; `func (p *Policy) permitPrograms(platformName string) (map[string]*engine.Program, error)`
  - `type api.ExplainRequest struct{ Device, Command, Principal string }`
  - `type api.ExplainResponse struct{ Principal, Subject, Device, Platform, Verdict, Reason, MintError, Text string }`
  - the route `POST /v1/explain`

- [ ] **Step 1: Write the failing tests.** Add to `internal/policy/explain_test.go`:

  ```go
  // Answer is the one verdict and reason an explanation gives, in Render's
  // order, or the mint error the broker would answer instead (plan 7c).
  func TestAnswerIsRendersVerdict(t *testing.T) {
  	at := time.Date(2026, 10, 2, 3, 0, 0, 0, time.UTC)
  	for _, c := range []struct {
  		e       Explanation
  		verdict string
  		reason  decision.Reason
  		mintErr string
  	}{
  		{Explanation{Revoked: at}, "deny", decision.CredentialRevoked, ""},
  		{Explanation{Refused: "no_key_group"}, "deny", decision.DeviceUnknown, ""},
  		{Explanation{Quarantined: true}, "deny", decision.DeviceQuarantined, ""},
  		{Explanation{NoGrants: true}, "deny", decision.NoGrantsMatched, ""},
  		{Explanation{MintError: "attribute_too_long"}, "", "", "attribute_too_long"},
  	} {
  		v, r, m := c.e.Answer()
  		if v != c.verdict || r != c.reason || m != c.mintErr {
  			t.Errorf("%+v: %s %s %s", c.e, v, r, m)
  		}
  	}
  	var b strings.Builder
  	Explanation{Subject: "user:alice@example.com", Device: "leaf1", Revoked: at}.Render(&b, false)
  	if !strings.HasPrefix(b.String(), "deny credential_revoked\n  a revocation stands against user:alice@example.com "+
  		"since 2026-10-02T03:00:00Z") {
  		t.Fatalf("%q", b.String())
  	}
  	b.Reset()
  	Explanation{Subject: "ops", Device: "leaf1", NoGrants: true}.Render(&b, false)
  	if got := b.String(); strings.Contains(got, "()") || !strings.Contains(got, "selects leaf1;") {
  		t.Fatalf("a no-grant answer with no platform: %q", got)
  	}
  }

  // wouldPermit compiles each role's permits once per platform per policy and
  // keeps them (spec §13 decision 34; pre-flight M15): a second denied explain
  // on the platform compiles nothing and gives the same answer.
  func TestWouldPermitCompilesOncePerPlatform(t *testing.T) {
  	p := mustParse(t, `
  scopes: [{name: all_devices, match: {}}]
  roles: [{name: ops, privilege: admin, permit: ["reload **"]}, {name: ro, privilege: readonly, permit: [show **]}]
  subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
  grants: [{subject: s, scope: all_devices, roles: [ro]}]`)
  	first, err := p.wouldPermit("reload now", "arista_eos")
  	if err != nil || strings.Join(first, " ") != "ops" {
  		t.Fatalf("%v %v", first, err)
  	}
  	second, err := p.wouldPermit("reload now", "arista_eos")
  	n := 0
  	p.permitsAlone.Range(func(any, any) bool { n++; return true })
  	if err != nil || strings.Join(second, " ") != "ops" || n != 1 {
  		t.Fatalf("%v %v; %d platform(s) compiled", second, err, n)
  	}
  }
  ```

  Create `internal/broker/explain_api_test.go`:

  ```go
  package broker

  import (
  	"context"
  	"encoding/json"
  	"net/http/httptest"
  	"strings"
  	"testing"
  	"time"

  	"github.com/rhwendt/port49/internal/broker/api"
  	"github.com/rhwendt/port49/internal/policy"
  	"github.com/rhwendt/port49/internal/store"
  )

  // explainPolicy is testPolicy with an on-call who may explain others,
  // added to its subjects list after carol's.
  var explainPolicy = strings.Replace(testPolicy, "username: carol, token_ttl: 60s}\n",
  	"username: carol, token_ttl: 60s}\n"+
  		`  - {name: oncall, identity: ["user:bob@example.com"], username: bob, token_ttl: 60s, api: [explain_others]}`+"\n", 1)

  func (f *fixture) explainAs(t *testing.T, email, body string) *httptest.ResponseRecorder {
  	t.Helper()
  	return f.call(context.Background(), f.state(f.client(t, email, f.now.Add(time.Hour))), "POST", "/v1/explain", body)
  }

  func decodeExplain(t *testing.T, w *httptest.ResponseRecorder) api.ExplainResponse {
  	t.Helper()
  	if w.Code != 200 {
  		t.Fatalf("%d %s", w.Code, w.Body)
  	}
  	var r api.ExplainResponse
  	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
  		t.Fatal(err)
  	}
  	return r
  }

  // A caller explains itself: the broker's answer from the policy in force,
  // the daemon's evaluator, and one explain record that names who asked, by
  // principal and certificate, and the bundle that answered, carries no
  // auth, and never the command (spec §5.7; decision 34).
  func TestExplainAnswersTheCallerAndNeverLogsTheCommand(t *testing.T) {
  	f := newFixtureWithPolicy(t, 8, explainPolicy)
  	r := decodeExplain(t, f.explainAs(t, "alice@example.com", `{"device":"leaf1","command":"reload now"}`))
  	if r.Principal != alicePrincipal || r.Subject != "netops" || r.Platform != "arista_eos" || r.Verdict != "deny" ||
  		r.Reason != "no_permit_dominates_deny" || !strings.HasPrefix(r.Text, "deny no_permit_dominates_deny") {
  		t.Fatalf("%+v", r)
  	}
  	if s := decodeExplain(t, f.explainAs(t, "alice@example.com", `{"device":"leaf1"}`)); s.Verdict != "permit" ||
  		s.Reason != "context_matched" {
  		t.Fatalf("the session: %+v", s)
  	}
  	recs := eventsOf(f.records(t), "explain")
  	if len(recs) != 2 || recs[0]["reason"] != "no_permit_dominates_deny" || recs[0]["principal"] != alicePrincipal {
  		t.Fatalf("%v", recs)
  	}
  	ex := recs[0]["explain"].(map[string]any)
  	if ex["asked_by"] != alicePrincipal || ex["command"] != true ||
  		!strings.HasPrefix(ex["asked_by_fingerprint"].(string), "sha256:") || recs[0]["auth"] != nil {
  		t.Fatalf("%v", recs[0])
  	}
  	if pol, _ := recs[0]["policy"].(map[string]any); pol["bundle"] != f.b.Policy.Load().Bundle {
  		t.Fatalf("the record does not name the bundle that answered: %v", recs[0])
  	}
  	if strings.Contains(f.log.String(), "reload now") {
  		t.Fatal("the log holds the command explain was asked")
  	}
  }

  // An unknown device is answered exactly as a device the caller has no grant
  // on: the same verdict, reason and text but for the name, and no platform
  // (design §17; Review Focus 3).
  func TestAnUnknownDeviceIsAnsweredAsOneWithNoGrant(t *testing.T) {
  	f := newFixtureWithPolicy(t, 8, explainPolicy)
  	known := decodeExplain(t, f.explainAs(t, "carol@example.com", `{"device":"leaf1"}`))
  	unknown := decodeExplain(t, f.explainAs(t, "carol@example.com", `{"device":"nosuch"}`))
  	if known.Platform != "" || unknown.Platform != "" || known.Reason != "no_grants_matched" ||
  		strings.ReplaceAll(known.Text, "leaf1", "X") != strings.ReplaceAll(unknown.Text, "nosuch", "X") {
  		t.Fatalf("known %+v\nunknown %+v", known, unknown)
  	}
  	for _, r := range eventsOf(f.records(t), "explain") {
  		if d := r["device"].(map[string]any); d["platform"] != "" && d["platform"] != nil {
  			t.Fatalf("a no-grant record named a platform: %v", r)
  		}
  	}
  }

  // A scoped caller asking about a device outside its grants that is
  // quarantined, or refused admission, is answered and recorded exactly as
  // about a device that does not exist (Review Focus 7; pre-flight M7).
  // Explain judges no grant before a quarantine or a refusal, as the mint
  // does; a reordering would tell a caller which devices exist and what state
  // they are in. nx1 is cisco_nxos, which defines no @loopback, so alice's
  // grant quarantines it (TestAQuarantinedDeviceIsRefusedAtMint); bare lies
  // outside the key group's range, so it is refused admission; carol's grant
  // selects arista_eos alone.
  func TestAScopedCallerLearnsNothingOfADeviceOutsideItsGrants(t *testing.T) {
  	f := newFixture(t, 8)
  	body := `
  scopes: [{name: all_devices, match: {}}, {name: eos, match: {platform: arista_eos}, on_missing: exclude}]
  roles: [{name: r, permit: ["**"], deny: [interface @loopback]}]
  subjects:
    - {name: c, identity: "user:carol@example.com", username: carol, token_ttl: 60s}
    - {name: s, identity: "user:alice@example.com", username: alice, token_ttl: 60s}
  grants: [{subject: s, scope: all_devices, roles: [r]}, {subject: c, scope: eos, roles: [r]}]
  key_groups: [{match: {cidr: 172.100.100.0/27}, key_ref: k}]
  `
  	pol, err := policy.Parse([]byte(body), policy.Env{Devices: f.b.Policy.Load().Devices(), Now: f.b.Now(),
  		KeyRefs: []string{"k"}})
  	if err != nil {
  		t.Fatal(err)
  	}
  	f.b.Policy.Swap(pol)
  	if _, q := pol.Quarantined("nx1", f.b.Now()); !q {
  		t.Fatal("the fixture does not quarantine nx1")
  	}
  	if r, _ := pol.Admitted("bare"); r.Refused == "" {
  		t.Fatal("the fixture does not refuse bare admission")
  	}
  	unknown := decodeExplain(t, f.explainAs(t, "carol@example.com", `{"device":"nosuch"}`))
  	if unknown.Reason != "no_grants_matched" || unknown.Platform != "" {
  		t.Fatalf("unknown: %+v", unknown)
  	}
  	for _, name := range []string{"nx1", "bare"} {
  		got := decodeExplain(t, f.explainAs(t, "carol@example.com", `{"device":"`+name+`"}`))
  		got.Device, got.Text = "nosuch", strings.ReplaceAll(got.Text, name, "nosuch")
  		if got != unknown {
  			t.Fatalf("%s:\n%+v\nunknown:\n%+v", name, got, unknown)
  		}
  	}
  	recs := eventsOf(f.records(t), "explain")
  	if len(recs) != 3 {
  		t.Fatalf("%d explain records", len(recs))
  	}
  	var same []string
  	for _, r := range recs {
  		delete(r, "ts")
  		r["device"].(map[string]any)["name"] = "nosuch"
  		raw, _ := json.Marshal(r) // map keys sorted
  		same = append(same, string(raw))
  	}
  	if same[1] != same[0] || same[2] != same[0] {
  		t.Fatalf("records differ but for the name:\n%s", strings.Join(same, "\n"))
  	}
  }

  // Explaining another principal needs explain_others: without it, 403 and
  // one deny api_right_missing record naming the target and who asked, with
  // no auth (decision 34); with it, the target's answer, and a target under a
  // mark is credential_revoked.
  func TestExplainingAnotherNeedsTheRight(t *testing.T) {
  	f := newFixtureWithPolicy(t, 8, explainPolicy)
  	if w := f.explainAs(t, "carol@example.com", `{"device":"leaf1","principal":"USER:alice@example.com"}`); w.Code != 403 ||
  		!strings.Contains(w.Body.String(), "explain_others") {
  		t.Fatalf("%d %s", w.Code, w.Body)
  	}
  	recs := eventsOf(f.records(t), "explain")
  	if len(recs) != 1 || recs[0]["reason"] != "api_right_missing" || recs[0]["principal"] != alicePrincipal ||
  		recs[0]["explain"].(map[string]any)["asked_by"] != "user:carol@example.com" || recs[0]["auth"] != nil {
  		t.Fatalf("%v", recs)
  	}
  	if r := decodeExplain(t, f.explainAs(t, "bob@example.com", `{"device":"leaf1","principal":"user:alice@example.com"}`)); r.Verdict != "permit" || r.Subject != "netops" {
  		t.Fatalf("bob explaining alice: %+v", r)
  	}
  	if err := f.st.PutRevocation(context.Background(), store.Revocation{Kind: store.RevocationPrincipal,
  		Key: alicePrincipal, At: f.now, Origin: "test"}); err != nil {
  		t.Fatal(err)
  	}
  	if r := decodeExplain(t, f.explainAs(t, "bob@example.com", `{"device":"leaf1","principal":"user:alice@example.com"}`)); r.Verdict != "deny" || r.Reason != "credential_revoked" {
  		t.Fatalf("explaining a revoked principal: %+v", r)
  	}
  }

  // A command is printable and bounded; a secret typed into one never comes
  // back unredacted, nor reaches the log.
  func TestExplainBoundsAndRedactsTheCommand(t *testing.T) {
  	f := newFixtureWithPolicy(t, 8, explainPolicy)
  	for _, body := range []string{`{"device":"leaf1","command":"show\u0007version"}`,
  		`{"device":"leaf1","command":"` + strings.Repeat("a", 1025) + `"}`, `{"device":""}`, `{"device":"leaf1","x":1}`} {
  		if w := f.explainAs(t, "alice@example.com", body); w.Code != 400 {
  			t.Errorf("%.60s: %d %s", body, w.Code, w.Body)
  		}
  	}
  	w := f.explainAs(t, "alice@example.com", `{"device":"leaf1","command":"username bob secret Hunter2"}`)
  	if w.Code != 200 || strings.Contains(w.Body.String(), "Hunter2") || strings.Contains(f.log.String(), "Hunter2") {
  		t.Fatalf("%d %s\nlog: %s", w.Code, w.Body, f.log)
  	}
  }
  ```

  The last test rests on the built-in redaction pattern for `username … secret …` on
  `arista_eos` (spec §5.7's example). If the built-in set does not cover it there, use the secret
  form the built-in patterns do cover for that platform (`platform.BuiltInRedactor("arista_eos")`
  lists them), and keep the assertion.

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/policy/ -run 'TestAnswerIsRendersVerdict|TestWouldPermitCompilesOncePerPlatform' && go test ./internal/broker/ -run 'TestExplain|TestAnUnknownDevice|TestAScopedCaller'`
  Expected: build failure (`Revoked`, `Answer`, `permitsAlone`, `api.ExplainResponse` undefined).

- [ ] **Step 3: The explanation's answer.** In `internal/policy/explain.go`, add to `Explanation`
  after `Refused`:

  ```go
  	// Revoked is set by the broker when a revocation stands against the
  	// principal (spec §5.1.4): nothing would be minted for it, so nothing
  	// else is filled in but Subject (the principal) and Device.
  	Revoked time.Time
  ```

  After `MintCheck`, add:

  ```go
  // Answer is the explanation's one verdict and reason, as the broker would
  // mint and the daemon decide, in Render's order; or the mint item error the
  // broker would answer instead of a token, with no verdict.
  func (e Explanation) Answer() (verdict string, reason decision.Reason, mintError string) {
  	switch {
  	case !e.Revoked.IsZero():
  		return decision.VerdictDeny, decision.CredentialRevoked, ""
  	case e.Refused != "":
  		return decision.VerdictDeny, decision.DeviceUnknown, ""
  	case e.Quarantined:
  		return decision.VerdictDeny, decision.DeviceQuarantined, ""
  	case e.NoGrants:
  		return decision.VerdictDeny, decision.NoGrantsMatched, ""
  	case e.MintError != "":
  		return "", "", e.MintError
  	case e.Command == "":
  		return decision.VerdictPermit, e.Resolution.Blob.SessionReason(), ""
  	case e.Outcome.Permit:
  		return decision.VerdictPermit, e.Outcome.Reason, ""
  	}
  	return decision.VerdictDeny, e.Outcome.Reason, ""
  }
  ```

  At the top of `Render`, before `if e.Refused != ""`:

  ```go
  	if !e.Revoked.IsZero() {
  		fmt.Fprintf(w, "deny %s\n  a revocation stands against %s since %s: the broker mints nothing for it until "+
  			"an operator lifts it (port49 revoke --lift)\n", decision.CredentialRevoked, e.Subject,
  			e.Revoked.UTC().Format(time.RFC3339))
  		return
  	}
  ```

  In `Render`'s `e.NoGrants` branch, name the platform only when there is one:

  ```go
  	if e.NoGrants {
  		on := e.Device
  		if e.Platform != "" {
  			on += " (" + e.Platform + ")"
  		}
  		fmt.Fprintf(w, "deny %s\n  %s holds no grant whose scope selects %s; attached roles never add a "+
  			"device (spec §5.5)\n", decision.NoGrantsMatched, e.Subject, on)
  		return
  	}
  ```

  `port49 explain`'s offline output is unchanged wherever the platform is known; check its tests.

  `wouldPermit` compiles every role's permits on each call, which a denied explain would make a
  CPU lever for any granted principal (pre-flight M15). Keep the programs per platform on the
  `Policy`, as `projected` keeps projections. In `internal/policy/load.go`, after `projected`:

  ```go
  	// permitsAlone memoizes wouldPermit's programs, keyed by platform: each
  	// role's permits alone, compiled once per policy (a Policy is one
  	// bundle, never changed once loaded), so a denied explain matches and
  	// compiles nothing (spec §13 decision 34). The key is a device's
  	// platform, a set the inventory bounds, never a caller's text.
  	permitsAlone sync.Map
  ```

  In `internal/policy/explain.go`, replace `wouldPermit` with:

  ```go
  // wouldPermit lists every role whose permits alone match the command on this
  // platform, held or not: what to ask for (spec §13 decision 34 records that
  // this names roles from the whole policy, deliberately).
  func (p *Policy) wouldPermit(line, platformName string) ([]string, error) {
  	progs, err := p.permitPrograms(platformName)
  	if err != nil {
  		return nil, err
  	}
  	raw, _ := p.commandRaw(line, platformName)
  	var out []string
  	for name, prog := range progs {
  		if len(prog.Command(raw).Permits) > 0 {
  			out = append(out, name)
  		}
  	}
  	sort.Strings(out)
  	return out, nil
  }

  // permitPrograms is every role's permits alone compiled for platformName,
  // compiled at the first call and kept (permitsAlone). An error is not kept,
  // so it is said again at the next call.
  func (p *Policy) permitPrograms(platformName string) (map[string]*engine.Program, error) {
  	if v, ok := p.permitsAlone.Load(platformName); ok {
  		return v.(map[string]*engine.Program), nil
  	}
  	dialect := p.dialect(platformName)
  	progs := make(map[string]*engine.Program, len(p.roles))
  	for name, r := range p.roles {
  		// This blob is never minted; Compile only needs a bundle named.
  		b := engine.Blob{Version: engine.Version, Bundle: "explain", Platform: platformName, Classes: dialect.EntityClasses,
  			Normalize: p.normalizeFor(platformName)}
  		for _, rule := range r.Permit {
  			missing, err := missingClass(rule, dialect.EntityClasses)
  			if err != nil {
  				return nil, fmt.Errorf("role %q: %w", name, err)
  			}
  			if !missing {
  				b.Rules = append(b.Rules, engine.Rule{Verdict: engine.Permit, Rule: rule, Role: name})
  			}
  		}
  		prog, err := engine.Compile(b)
  		if err != nil {
  			return nil, fmt.Errorf("role %q: %w", name, err)
  		}
  		progs[name] = prog
  	}
  	stored, _ := p.permitsAlone.LoadOrStore(platformName, progs)
  	return stored.(map[string]*engine.Program), nil
  }
  ```

  The compile loop is today's, moved; a `*engine.Program` is read-only once compiled, as every
  context's program is shared across requests.

- [ ] **Step 4: The wire types and the handler.** Create `internal/broker/api/explain.go`:

  ```go
  package api

  // ExplainRequest is POST /v1/explain (design §17): one hypothetical
  // decision on Device, about the caller or, under explain_others,
  // Principal. An empty Command is the session.
  type ExplainRequest struct {
  	Device    string `json:"device"`
  	Command   string `json:"command,omitempty"`
  	Principal string `json:"principal,omitempty"`
  }

  // ExplainResponse is its answer: the verdict and reason the broker and the
  // daemon would give (spec §5.7), or MintError where the broker would mint
  // no token; and Text, as port49 explain renders it, redacted. Platform is
  // empty where the answer is no_grants_matched, so no answer says which
  // devices exist.
  type ExplainResponse struct {
  	Principal string `json:"principal"`
  	Subject   string `json:"subject,omitempty"`
  	Device    string `json:"device"`
  	Platform  string `json:"platform,omitempty"`
  	Verdict   string `json:"verdict,omitempty"`
  	Reason    string `json:"reason,omitempty"`
  	MintError string `json:"mint_error,omitempty"`
  	Text      string `json:"text"`
  }
  ```

  Create `internal/broker/explain_api.go`:

  ```go
  package broker

  import (
  	"context"
  	"encoding/json"
  	"fmt"
  	"io"
  	"net/http"
  	"strings"

  	"github.com/rhwendt/port49/internal/broker/api"
  	"github.com/rhwendt/port49/internal/decision"
  	"github.com/rhwendt/port49/internal/policy"
  	"github.com/rhwendt/port49/internal/store"
  )

  // maxExplainCommand bounds a command explain is asked: a line a person
  // types, with room.
  const maxExplainCommand = 1024

  // explain is POST /v1/explain (design §17; decision 34): the broker's
  // answer for one device, from the policy in force, as it would mint and the
  // daemon decide (policy.Explain, the evaluator port49 explain runs). It is
  // about the caller unless the request names another principal, which needs
  // explain_others. A device the inventory does not name is answered exactly
  // as one the principal has no grant on, and neither names a platform: the
  // API tells no caller which devices exist. A principal under a mark is
  // credential_revoked. One explain record, which names the bundle that
  // answered and never holds the command.
  func (b *Broker) explain(w http.ResponseWriter, r *http.Request) {
  	caller, cred, ok := b.authenticate(w, r, decision.EventExplain, "explained nothing")
  	if !ok {
  		return
  	}
  	var req api.ExplainRequest
  	dec := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
  	dec.DisallowUnknownFields()
  	if err := dec.Decode(&req); err != nil || !deviceName(req.Device) || !commandLine(req.Command) {
  		writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf("name a device (1 to %d printable ASCII "+
  			"characters) and, if you like, a command of at most %d printable characters", maxDeviceName,
  			maxExplainCommand))
  		return
  	}
  	about := caller
  	if req.Principal != "" {
  		p, err := normalPrincipal(req.Principal)
  		if err != nil {
  			writeError(w, http.StatusBadRequest, "bad_request", "the principal is not one the broker spells: "+
  				"user: and an email, as the log names it")
  			return
  		}
  		about = p
  	}
  	now := b.Now()
  	pol := b.Policy.Load()
  	// No auth: principal is whom it was about, and the caller's credential
  	// is in explain.asked_by_fingerprint, so a record's auth and principal
  	// always describe one credential (decision 34; pre-flight I8).
  	rec := decision.Record{TS: now, Event: decision.EventExplain, Principal: about,
  		Device: &decision.Device{Name: req.Device}, Policy: &decision.Policy{Bundle: pol.Bundle},
  		Explain: &decision.Explain{AskedBy: caller, AskedByFingerprint: cred.Fingerprint, Command: req.Command != ""}}
  	if about != caller && !pol.HasRight(caller, policy.RightExplainOthers) {
  		b.refuseRight(w, rec, policy.RightExplainOthers, "explaining another principal")
  		return
  	}
  	ctx, cancel := context.WithTimeout(r.Context(), holdTimeout)
  	rv, revoked, err := b.revocation(ctx, about, store.Credential{})
  	cancel()
  	if err != nil {
  		rec.Verdict, rec.Reason = decision.VerdictDeny, decision.StoreUnavailable
  		b.emit(rec)
  		writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable),
  			"the broker could not read the revocations in force, so it explained nothing; try again")
  		return
  	}
  	e, err := explanationOf(pol, about, req.Device, req.Command, now)
  	if err != nil {
  		b.logf("broker: explaining %s on %q: %v", about, req.Device, err)
  		writeError(w, http.StatusInternalServerError, "broker_error",
  			"the broker could not explain this; tell the operator")
  		return
  	}
  	if revoked {
  		e = policy.Explanation{Subject: about, Device: req.Device, Command: req.Command, Revoked: rv.At}
  	}
  	verdict, reason, mintErr := e.Answer()
  	rec.Verdict, rec.Reason = verdict, reason
  	rec.Device.Platform = e.Platform
  	rec.Explain.MintError = mintErr
  	if reason == "" {
  		b.Log.Emit(rec) // a mint error is no decision, and is not counted as one
  	} else {
  		b.emit(rec)
  	}
  	var text strings.Builder
  	e.Redacted(pol.Redactions()).Render(&text, false)
  	writeJSON(w, http.StatusOK, api.ExplainResponse{Principal: about, Subject: e.Subject, Device: req.Device,
  		Platform: e.Platform, Verdict: verdict, Reason: string(reason), MintError: mintErr, Text: text.String()})
  }

  // explanationOf is pol's answer for principal on device. A device the
  // inventory does not name is no_grants_matched, built here because
  // policy.Explain names a missing device (an offline tool's operator holds
  // the inventory); a no-grant answer carries no platform.
  func explanationOf(pol *policy.Policy, principal, device, line string, now time.Time) (policy.Explanation, error) {
  	subject, ok := pol.SubjectOf(principal)
  	if !ok {
  		subject = principal
  	}
  	if _, ok := pol.Device(device); !ok {
  		return policy.Explanation{Subject: subject, Device: device, Command: line, NoGrants: true}, nil
  	}
  	e, err := pol.Explain("", principal, device, line, now)
  	if err != nil {
  		return e, err
  	}
  	if e.NoGrants {
  		e.Platform = ""
  	}
  	return e, nil
  }

  // commandLine reports whether s can be a command explain is asked: at most
  // maxExplainCommand bytes of printable ASCII and spaces. Empty is the
  // session.
  func commandLine(s string) bool {
  	return len(s) <= maxExplainCommand && strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r > 0x7e }) < 0
  }
  ```

  Add `time` to the imports. In `Handler`, add `mux.HandleFunc("POST /v1/explain", b.explain)`.

  For a principal no subject names, `policy.Explain` answers `NoGrants` with `Subject` set to the
  principal; `explanationOf` blanks its platform as for any no-grant answer.

- [ ] **Step 5: Run the tests.**

  Run: `go test ./internal/policy/ ./internal/broker/ ./cmd/port49/`
  Expected: PASS, `port49 explain`'s offline tests included.

- [ ] **Step 6: Commit.**

  ```bash
  gofmt -w internal/policy/explain.go internal/policy/explain_test.go internal/policy/load.go \
    internal/broker/explain_api.go internal/broker/api/explain.go internal/broker/broker.go \
    internal/broker/explain_api_test.go
  make build && make test && make vet
  git add internal/policy/explain.go internal/policy/explain_test.go internal/policy/load.go \
    internal/broker/explain_api.go internal/broker/api/explain.go internal/broker/broker.go \
    internal/broker/explain_api_test.go
  git commit -m "feat(broker): POST /v1/explain from the policy in force, never a device oracle

  An unknown device, and one outside a scoped caller's grants that is quarantined
  or refused admission, is answered as one with no grant, naming no platform;
  another principal needs explain_others; a principal under a mark is
  credential_revoked; the record names who asked and the bundle, carries no auth,
  and never the command. Each role's permits are compiled once per platform per
  policy (decision 34).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 10: The candidate reload guard: a policy reload cannot quarantine the fleet

**Files:**
- Modify: `internal/bundle/diff.go` (`CheckAdmission`, ~line 266; new `NewlyQuarantined`,
  `inService`, `inServiceCount`)
- Modify: `cmd/port49d/reload.go` (the two `CheckAdmission` calls, ~lines 530 and 890; the two
  refusal lines, ~lines 552 and 911; new `refusalLine`, `unguardedAtStart`)
- Modify: `cmd/port49/inventory.go` (the two `CheckAdmission` calls, ~lines 158 and 164; new
  `redacted`)
- Modify: `tests/lab/l31_test.go` (its quarantining reload's derived config)
- Test: `internal/bundle/diff_test.go`, `cmd/port49d/reload_test.go`

**Interfaces:**
- Consumes: `policy.Policy.Quarantined(name string, now time.Time) (string, bool)`,
  `Policy.Admitted`, `Policy.AdmissionAssessed`, `Policy.Redactions`, `NewlyRefused`, `admitsNone`,
  `names`, `nameList`; `platform.RedactQuoted`; `oneLine`, `quotesCut` (`cmd/port49d`).
- Produces:
  - `type bundle.Quarantined struct{ Device, Cause string }`
  - `func bundle.NewlyQuarantined(old, new *policy.Policy, now time.Time) []bundle.Quarantined`
  - `func bundle.CheckAdmission(old, new *policy.Policy, maxRemovedPercent int, now time.Time) error`
    (the new `now` parameter)
  - `func refusalLine(err error, pols ...*policy.Policy) string`, `const unguardedAtStart`
    (`cmd/port49d`); `func redacted(err error, pols ...*policy.Policy) error` (`cmd/port49`)

- [ ] **Step 1: Write the failing tests.** In `internal/bundle/diff_test.go`, change the existing
  `CheckAdmission(old, x, n)` calls to `CheckAdmission(old, x, n, time.Now())`, and add:

  ```go
  // A policy that takes more than the bound of the devices in service out of
  // service, by quarantining them, is refused, naming each, the remedy, and
  // the knob's other use, as one that refuses admission is (plan 4b's
  // candidate guard; spec §13 decision 34). Against a fleet that already has
  // a quarantine (Review Focus 4; pre-flight M6): a release passes; the
  // policy in force reloaded passes; one more of the three in service
  // quarantined is 33% and refused; and a reload that releases one and
  // quarantines another, leaving as many in service as before, passes
  // (pre-flight M14).
  func TestCheckAdmissionBoundsAPolicyThatQuarantinesTheFleet(t *testing.T) {
  	now := time.Now()
  	devs := []admission.Device{dev("a", "10.0.3.1", nil), dev("b", "10.0.3.2", nil),
  		dev("c", "10.0.3.3", map[string]string{"site": "campus"}), dev("d", "10.0.3.4", map[string]string{"site": "dc1"})}
  	// quarantineOn caps an admin role at operator on the named scopes'
  	// grants: it lands above its ceiling's level on arista_eos, so every
  	// device those scopes select is quarantined.
  	quarantineOn := func(t *testing.T, scopes ...string) *policy.Policy {
  		t.Helper()
  		text := strings.Replace(withScopes, "roles: [{name: r, privilege: readonly, permit: [show **]}]",
  			"roles: [{name: r, privilege: readonly, permit: [show **]}, {name: big, privilege: admin, permit: [show **]}]", 1)
  		for _, sc := range scopes {
  			text = strings.Replace(text, "scope: "+sc+", roles: [r]}", "scope: "+sc+", roles: [big], max_privilege: operator}", 1)
  		}
  		p, err := Parse([]byte(text), admission.Inventory{Devices: devs}, policy.Env{})
  		if err != nil {
  			t.Fatal(err)
  		}
  		return p
  	}
  	good := mustBundle(t, devs...)
  	all := quarantineOn(t, "all_devices", "campus", "dc")
  	dc := quarantineOn(t, "dc")                 // d out: a, b, c in service
  	dcCampus := quarantineOn(t, "dc", "campus") // c and d out: a, b in service
  	campus := quarantineOn(t, "campus")         // c out: a, b, d in service
  	for name, c := range map[string]struct {
  		p   *policy.Policy
  		out string
  	}{"all": {all, "a b c d"}, "dc": {dc, "d"}, "dc and campus": {dcCampus, "c d"}, "campus": {campus, "c"}} {
  		var out []string
  		for _, d := range devs {
  			if _, q := c.p.Quarantined(d.Name, now); q {
  				out = append(out, d.Name)
  			}
  		}
  		if strings.Join(out, " ") != c.out {
  			t.Fatalf("the %s fixture quarantines %v, not %s", name, out, c.out)
  		}
  	}
  	err := CheckAdmission(good, all, 10, now)
  	if err == nil || !strings.Contains(err.Error(), "takes 4 of 4 devices in service out of it") ||
  		!strings.Contains(err.Error(), "it quarantines 4: a (") || !strings.Contains(err.Error(), "port49 revoke") ||
  		!strings.Contains(err.Error(), "raise inventory.max_removed_percent") ||
  		!strings.Contains(err.Error(), "then lower it again, since it bounds inventory syncs too") {
  		t.Fatalf("the whole fleet: %v", err)
  	}
  	if err := CheckAdmission(good, all, 100, now); err != nil {
  		t.Fatalf("the bound off: %v", err)
  	}
  	if err := CheckAdmission(dc, good, 10, now); err != nil {
  		t.Fatalf("(a) a reload that releases the quarantine and quarantines nothing: %v", err)
  	}
  	if err := CheckAdmission(dc, dc, 10, now); err != nil || len(NewlyQuarantined(dc, dc, now)) != 0 {
  		t.Fatalf("(b) the policy in force again, three of four in service: %v", err)
  	}
  	err = CheckAdmission(dc, dcCampus, 10, now)
  	if err == nil || !strings.Contains(err.Error(), "takes 1 of 3 devices in service out of it (33%)") ||
  		!strings.Contains(err.Error(), "it quarantines 1: c (") {
  		t.Fatalf("(c) one more of the three in service: %v", err)
  	}
  	if err := CheckAdmission(campus, dc, 10, now); err != nil {
  		t.Fatalf("(d) c released and d quarantined, three in service before and after: %v", err)
  	}
  	if got := NewlyQuarantined(good, all, now); len(got) != 4 || got[0].Device != "a" || got[0].Cause == "" {
  		t.Fatalf("NewlyQuarantined: %+v", got)
  	}
  }
  ```

  The fixture claims what quarantines; its first loop checks the claim. If a cap at operator does
  not quarantine on `arista_eos` here, use the edit the policy package's quarantine tests use, so
  the loop passes; never weaken the assertions after it.

  In `cmd/port49d/reload_test.go`:

  ```go
  // A policy edit that would quarantine more than inventory.max_removed_percent
  // of the devices in service is refused: the policy in force keeps serving,
  // the alarm is up, and the line names the cause and the remedy, and says
  // the refused file is still on disk and a restart would load it unguarded
  // (decision 34; pre-flight I4). With the bound off it applies, and the
  // device is quarantined live.
  func TestAReloadThatQuarantinesTheFleetIsRefused(t *testing.T) {
  	rig := newReloadRig(t, minimalPolicy)
  	before := rig.b.Policy.Load().Source
  	rig.write(t, unmappedLevel+strings.Replace(minimalPolicy, "privilege: admin", "privilege: unmapped", 1))
  	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
  	if rig.b.Policy.Load().Source != before {
  		t.Fatal("a reload quarantining the whole fleet was applied")
  	}
  	if testutil.ToFloat64(rig.m.PolicyFileRefused) != 1 {
  		t.Fatal("port49_policy_file_refused")
  	}
  	if out := rig.out.String(); !strings.Contains(out, "it quarantines 1: leaf1") ||
  		!strings.Contains(out, "raise inventory.max_removed_percent") ||
  		!strings.Contains(out, "is NOT what is serving: a restart of port49d would load it with no such bound") {
  		t.Fatalf("stderr: %s", out)
  	}
  	rig.r.cfg.MaxRemovedPercent = 100
  	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
  	if _, q := rig.b.Policy.Quarantined("leaf1", rig.now); !q {
  		t.Fatal("with the bound off the reload applies and quarantines leaf1")
  	}
  }

  // A refused reload's line is redacted with the redactions of both the
  // policy in force and the refused one before it reaches stderr, a log, and
  // only then are its quoted values cut, so a cut never leaves a secret's
  // head (spec §5.8; pre-flight I3): a quarantine's cause quotes policy text.
  func TestARefusedReloadsLineIsRedacted(t *testing.T) {
  	pol := newReloadRig(t, minimalPolicy).b.Policy.Load()
  	err := errors.New(`it quarantines 1: leaf1 (role r: "username bob secret Hunter2Hunter2Hunter2Hunter2Hunter2Hunter2Hunter2")`)
  	if line := refusalLine(err, pol, nil); strings.Contains(line, "Hunter2") || !strings.Contains(line, "leaf1") {
  		t.Fatalf("%s", line)
  	}
  }
  ```

  `unmappedLevel` is `TestAQuarantinedDeviceDoesNotStopTheStart`'s fixture
  (`cmd/port49d/broker_test.go`). `rig.r.reload(ctx, trigger)` stands for whatever `SIGHUP`
  calls on the reloader; `TestSIGHUPLoadsAtOnce` names it. The rig has no `cfgPath`, so `SIGHUP`
  keeps `r.cfg.MaxRemovedPercent` (`rereadBound`). The admission-refusal test in
  `cmd/port49d/reload_inventory_test.go` (the one asserting "refuses admission to 2 of 3 devices",
  ~line 416) drives the same `CheckAdmission` path through a reload; if this rig's reload does not
  reach `load` (a pending inventory taking it to `loadBoth`), mirror that test's setup. The
  redaction test rests on a built-in pattern (`platform.AllRedactions`) covering `username …
  secret …`; if none does, quote a value one of the built-in patterns covers, and keep the
  assertion. `reload_test.go` gains the `errors` import if it lacks it.

- [ ] **Step 2: Run them to see them fail.**

  Run: `go test ./internal/bundle/ ./cmd/port49d/ -run 'TestCheckAdmission|TestAReloadThatQuarantines|TestARefusedReloadsLine'`
  Expected: build failure (four-argument `CheckAdmission`, `NewlyQuarantined`, `refusalLine`
  undefined).

- [ ] **Step 3: Implement.** In `internal/bundle/diff.go`, replace `CheckAdmission`:

  ```go
  // Quarantined is a device a reload would quarantine, with the cause the new
  // policy gives.
  type Quarantined struct {
  	Device string
  	Cause  string
  }

  // inService reports whether p serves name at now: admitted (on a policy that
  // assesses admission), and not quarantined.
  func inService(p *policy.Policy, name string, now time.Time) bool {
  	if r, _ := p.Admitted(name); r.Refused != "" && p.AdmissionAssessed() {
  		return false
  	}
  	_, q := p.Quarantined(name, now)
  	return !q
  }

  // inServiceCount is how many of its devices p serves at now.
  func inServiceCount(p *policy.Policy, now time.Time) int {
  	n := 0
  	for _, d := range p.Devices() {
  		if inService(p, d.Name, now) {
  			n++
  		}
  	}
  	return n
  }

  // NewlyQuarantined is every device, by name, that old serves at now and new
  // admits and quarantines at now, with new's cause: what a policy reload
  // would take out of service by its joint check (spec §10; plan 4b's
  // candidate guard, decision 34). A device new refuses is NewlyRefused's.
  func NewlyQuarantined(old, new *policy.Policy, now time.Time) []Quarantined {
  	var out []Quarantined
  	for _, d := range new.Devices() {
  		if _, inOld := old.Admitted(d.Name); !inOld || !inService(old, d.Name, now) {
  			continue
  		}
  		if r, _ := new.Admitted(d.Name); r.Refused != "" && new.AdmissionAssessed() {
  			continue
  		}
  		if cause, q := new.Quarantined(d.Name, now); q {
  			out = append(out, Quarantined{Device: d.Name, Cause: cause})
  		}
  	}
  	sort.Slice(out, func(i, j int) bool { return out[i].Device < out[j].Device })
  	return out
  }

  // reloadRemedy ends a guard refusal: what serves meanwhile, how to cut
  // someone off now, and how to apply the change on purpose, then undo the
  // raise, since the same bound holds inventory syncs (pre-flight M14).
  const reloadRemedy = "if the change is meant, raise inventory.max_removed_percent in port49d.yaml and send " +
  	"SIGHUP, which re-reads it with the reload, then lower it again, since it bounds inventory syncs too"

  // CheckAdmission is a policy reload's bound (plan 6a, N1; plan 4b's
  // candidate guard, decision 34). Key groups and the joint check are policy,
  // so one edit can take the fleet out of service: a refused device's
  // contexts are revoked and its tokens deleted (I2), and a quarantined
  // device's connections are closed, so it falls to its local method
  // (tests/lab/results/quarantine-*.md). Unbounded, one bad edit puts the
  // fleet on break-glass. It refuses a policy that newly refuses and newly
  // quarantines, together, more than maxRemovedPercent of the devices old
  // serves at now, naming them, unless new serves at least as many devices at
  // now as old does: a net release, as an incident fix that releases fifty
  // and quarantines five is, is never refused (pre-flight M14). A quarantine
  // an expiry brings on later is not judged here (port49 policy diff fails on
  // it). An inventory-only reload is Check's, and quarantines as decision 20
  // says. A cause quotes policy text: whoever prints the error redacts it
  // (spec §5.8).
  func CheckAdmission(old, new *policy.Policy, maxRemovedPercent int, now time.Time) error {
  	if err := admitsNone("policy", new, false); err != nil {
  		return err
  	}
  	was := inServiceCount(old, now)
  	refused := NewlyRefused(old, new)
  	quarantined := NewlyQuarantined(old, new, now)
  	gone := len(refused) + len(quarantined)
  	if was == 0 || maxRemovedPercent >= 100 || gone*100 <= was*maxRemovedPercent || inServiceCount(new, now) >= was {
  		return nil
  	}
  	if len(quarantined) == 0 {
  		return fmt.Errorf("the new policy refuses admission to %d of %d devices (%d%%), more than "+
  			"inventory.max_removed_percent (%d%%): %s; check key_groups, or, %s",
  			len(refused), was, len(refused)*100/was, maxRemovedPercent, names(refused), reloadRemedy)
  	}
  	msg := fmt.Sprintf("the new policy takes %d of %d devices in service out of it (%d%%), more than "+
  		"inventory.max_removed_percent (%d%%):", gone, was, gone*100/was, maxRemovedPercent)
  	if len(refused) > 0 {
  		msg += fmt.Sprintf(" it refuses admission to %d: %s (check key_groups);", len(refused), names(refused))
  	}
  	q := make([]string, len(quarantined))
  	for i, d := range quarantined {
  		q[i] = fmt.Sprintf("%s (%s)", d.Device, d.Cause)
  	}
  	msg += fmt.Sprintf(" it quarantines %d: %s; `port49 policy diff` names each cause", len(quarantined), nameList(q))
  	return errors.New(msg + "; the policy in force keeps serving (to cut someone off now, use `port49 revoke`); " +
  		reloadRemedy)
  }
  ```

  The refusal-only message is the old one, word for word, with ", then lower it again, since it
  bounds inventory syncs too" appended, so the existing tests and the operator's runbook text
  hold. Add `sort` to the imports if it is not there.

  A cause is policy text, and neither printer redacts today: port49d's `load` prints the error
  through `oneLine` alone (`reload.go`, ~line 911), and `loadBoth` through `oneLine(quotesCut{…})`,
  which cuts quoted values and redacts none (its comment says a load error quotes no rule text;
  the guard's causes do). In `cmd/port49d/reload.go`:

  ```go
  // refusalLine is a refused reload's error on one line for stderr, a log:
  // every quoted value a rule of any of pols marks secret is redacted first,
  // as sayPolicy redacts a quarantine's cause, then each is cut to maxQuoted
  // (quotesCut), so a cut never leaves a secret's head (spec §5.8;
  // pre-flight I3). The guard's causes quote policy text, so the policy in
  // force and the refused one are both given; a nil one (a file that did not
  // parse) is skipped.
  func refusalLine(err error, pols ...*policy.Policy) string {
  	line := err.Error()
  	for _, p := range pols {
  		if p != nil {
  			line = platform.RedactQuoted(p.Redactions(), line)
  		}
  	}
  	return oneLine(quotesCut{errors.New(line)})
  }

  // unguardedAtStart ends the line of a reload the guard refused (pre-flight
  // I4): the refused file stays on disk, and a start has no policy in force to
  // bound against, so a pod rescheduled, a crash or the next deploy would
  // load it and take the devices out of service the guard just kept in.
  const unguardedAtStart = "; the refused file is still on disk and is NOT what is serving: a restart of port49d " +
  	"would load it with no such bound, so revert or fix it now"
  ```

  In `load`, the refusal line becomes:

  ```go
  		said := refusalLine(err, old, pol)
  		if forAdmission {
  			said += unguardedAtStart
  		}
  		fmt.Fprintf(stderr, "port49d: policy reload (%s) refused; still serving %s (bundle %s): %s\n", trigger,
  			old.Source, old.Bundle, said)
  ```

  In `loadBoth`, note whether the error is the guard's (`guarded := false`; after
  `err = bundle.CheckAdmission(old, pol, r.cfg.MaxRemovedPercent, r.now())`, `guarded = err !=
  nil`), and print `refusalLine(err, old, pol)`, plus `unguardedAtStart` when `guarded`, in place
  of `oneLine(quotesCut{err})`. Pass the reloader's clock, `r.now()`, as `CheckAdmission`'s new
  argument at both calls. Add the `platform` import if `reload.go` lacks it.

  In `cmd/port49/inventory.go`, pass the function's existing `now` (`now := time.Now()`, ~line
  121, which `bundle.Diff` already uses) at both calls, so the diff and the bound judge one
  instant (pre-flight M4), and redact what CI prints:

  ```go
  // redacted is err with every quoted value a rule of pols marks secret
  // redacted (spec §5.8): the reload guard's causes quote policy text, and
  // this output is a CI log (pre-flight I3).
  func redacted(err error, pols ...*policy.Policy) error {
  	if err == nil {
  		return nil
  	}
  	line := err.Error()
  	for _, p := range pols {
  		line = platform.RedactQuoted(p.Redactions(), line)
  	}
  	return errors.New(line)
  }
  ```

  The two closures become `func(mid *policy.Policy) error { return redacted(bundle.CheckAdmission(old,
  mid, bound, now), old, mid) }` and `… redacted(bundle.CheckAdmission(mid, new, bound, now), mid,
  new) …`. Add the `platform` import. The diff runs offline, so its text says nothing of a restart.

- [ ] **Step 4: The lab harness that reloads into a quarantine.** `tests/lab/l31_test.go` replaces
  `broker.policy_file` with `tests/lab/quarantine-sync/policy.yaml`, which quarantines the lab
  device: one device of one, which the guard now refuses (no device is in service after it, so it
  is no net release). Give that run's derived config `inventory: {max_removed_percent: 100}` (or
  add the key under an `inventory:` block the base config already has). Add a comment saying the
  run measures a quarantine, so the guard is off for it (decision 34), and that L31's results
  stand: the change only keeps its reload in force under the new bound. Search the other lab tests
  for a reload into a quarantining policy (`grep -rln 'quarantine' tests/lab/*_test.go`) and do the
  same where one is found. An inventory reload (the `quarantine-sync` bundle through the service in
  `l29_test.go`) is not bounded by this and needs nothing.

- [ ] **Step 5: Run the tests.**

  Run: `go test ./internal/bundle/ ./cmd/port49d/ ./cmd/port49/ && go vet -tags lab ./tests/lab/`
  Expected: PASS.

- [ ] **Step 6: Commit.**

  ```bash
  gofmt -w internal/bundle/diff.go internal/bundle/diff_test.go cmd/port49d/reload.go cmd/port49d/reload_test.go \
    cmd/port49/inventory.go tests/lab/l31_test.go
  make build && make test && make vet
  git add internal/bundle/diff.go internal/bundle/diff_test.go cmd/port49d/reload.go cmd/port49d/reload_test.go \
    cmd/port49/inventory.go tests/lab/l31_test.go
  git commit -m "feat(bundle): bound a policy reload's newly quarantined devices with its newly refused ones

  Plan 4b's candidate reload guard, ruled on (decision 34): a policy edit that
  would put more than inventory.max_removed_percent of the devices in service on
  break-glass is refused, the policy in force serving on, unless as many devices
  are in service after it as before. The refusal is redacted, says to lower the
  bound again after a deliberate raise, and says the refused file is still on
  disk and a restart would load it unguarded. L31's lab harness turns the bound
  off for the quarantine it measures.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 11: The agent carries identity, explain and revoke over the held connection

**Files:**
- Modify: `internal/agent/agent.go` (new `call`, `APIError`, `Identity`, `Explain`, `Revoke`;
  `Handler` gains three routes)
- Modify: `internal/agent/socket.go` (`Client.Identity`, `Client.Explain`, `Client.Revoke`, and
  their shared `roundTrip`)
- Test: `internal/agent/agent_test.go`

**Interfaces:**
- Consumes: `api.Identity` (Task 4), `api.RevokeRequest`, `api.RevokeResponse` (Task 8),
  `api.ExplainRequest`, `api.ExplainResponse` (Task 9); `a.do`, `a.refusedReconnect`,
  `sessionOver`, `unavailable`, `drain`, `a.end` (existing).
- Produces:
  - `type agent.APIError struct{ Status int; Code, Detail string }` (an `error`)
  - `func (a *Agent) Identity(ctx context.Context) (api.Identity, error)`
  - `func (a *Agent) Explain(ctx context.Context, req api.ExplainRequest) (api.ExplainResponse, error)`
  - `func (a *Agent) Revoke(ctx context.Context, req api.RevokeRequest) (api.RevokeResponse, error)`
  - the socket routes `GET /identity`, `POST /explain`, `POST /revoke`
  - `func (c *Client) Identity(ctx context.Context) (api.Identity, error)`,
    `Explain(ctx, api.ExplainRequest) (api.ExplainResponse, error)`,
    `Revoke(ctx, api.RevokeRequest) (api.RevokeResponse, error)`
  - `var agent.ErrAgentTooOld error` (pre-flight I9)

- [ ] **Step 1: Write the failing tests.** `agent_test.go`'s `newRealRig` (~line 1212) serves a
  real `broker.Broker` over TLS and connects an agent to it, with alice's live context on `leaf1`.
  Add:

  ```go
  // socketFor serves r's agent on a private socket and returns a Client on
  // it, as TestTheClientRefreshesOverTheSocket does.
  func socketFor(t *testing.T, a *Agent) *Client {
  	t.Helper()
  	p := filepath.Join(shortDir(t), "s", "agent.sock")
  	ln, err := Listen(p)
  	if err != nil {
  		t.Fatal(err)
  	}
  	srv := &http.Server{Handler: a.Handler()}
  	go func() { _ = srv.Serve(ln) }()
  	t.Cleanup(func() { _ = srv.Close() })
  	return NewClient(p)
  }

  // The agent carries identity, explain and revoke over the session's held
  // connection, through its socket, and hands a broker refusal back as it
  // came: 403 api_right_missing is an *APIError the CLI can name, and a
  // credential_revoked ends the session as a mint's does.
  func TestTheAgentCarriesTheAPI(t *testing.T) {
  	r := newRealRig(t)
  	ctx := context.Background()
  	c := socketFor(t, r.a)
  	id, err := c.Identity(ctx)
  	if err != nil || id.Principal != "user:alice@example.com" {
  		t.Fatalf("identity: %+v %v", id, err)
  	}
  	ex, err := c.Explain(ctx, api.ExplainRequest{Device: "leaf1"})
  	if err != nil || ex.Verdict == "" || ex.Text == "" {
  		t.Fatalf("explain: %+v %v", ex, err)
  	}
  	_, err = c.Explain(ctx, api.ExplainRequest{Device: "leaf1", Principal: "user:carol@example.com"})
  	var ae *APIError
  	if !errors.As(err, &ae) || ae.Status != 403 || ae.Code != "api_right_missing" {
  		t.Fatalf("explaining another without the right: %v", err)
  	}
  	rv, err := c.Revoke(ctx, api.RevokeRequest{Mine: true})
  	if err != nil || rv.By != "self" || rv.Standing {
  		t.Fatalf("revoke mine: %+v %v", rv, err)
  	}
  	if _, err := c.Identity(ctx); err != nil {
  		t.Fatalf("the session after a self-revocation: %v", err) // no mark: it goes on
  	}
  	if err := r.st.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal,
  		Key: "user:alice@example.com", At: r.clock(), Origin: "test"}); err != nil {
  		t.Fatal(err)
  	}
  	_, err = c.Identity(ctx)
  	var revoked *RevokedError
  	if !errors.As(err, &revoked) || !errors.Is(err, ErrSessionOver) {
  		t.Fatalf("identity under a mark: %v", err)
  	}
  }
  ```

  The mark is put straight into the store, with no listener told, so the held connection carries
  the next call and the broker's `authenticate` refuses it, as a mark that lands after the agent's
  connection bound is refused (spec §5.1.4).

  An agent lives for `max_session_age`, so after an upgrade the running one predates these routes,
  and its mux answers a plain-text 404 (pre-flight I9). Add:

  ```go
  // A CLI newer than the running agent: the agent's mux has no route for the
  // call, and the client says to log in again, never "the broker refused"
  // (pre-flight I9).
  func TestAnOlderAgentIsNamedNotBlamedOnTheBroker(t *testing.T) {
  	p := filepath.Join(shortDir(t), "s", "agent.sock")
  	ln, err := Listen(p)
  	if err != nil {
  		t.Fatal(err)
  	}
  	srv := &http.Server{Handler: http.NewServeMux()} // an agent with none of the new routes
  	go func() { _ = srv.Serve(ln) }()
  	t.Cleanup(func() { _ = srv.Close() })
  	_, err = NewClient(p).Identity(context.Background())
  	var ae *APIError
  	if !errors.Is(err, ErrAgentTooOld) || errors.As(err, &ae) || !strings.Contains(err.Error(), "port49 login") {
  		t.Fatalf("%v", err)
  	}
  }
  ```

- [ ] **Step 2: Run it to see it fail.**

  Run: `go test ./internal/agent/ -run 'TestTheAgentCarriesTheAPI|TestAnOlderAgentIsNamed'`
  Expected: build failure (`Client.Identity`, `APIError`, `ErrAgentTooOld` undefined).

- [ ] **Step 3: The agent's call.** In `internal/agent/agent.go`, after `post`:

  ```go
  // APIError is a broker answer that is neither a 200, nor a refusal that ends
  // the session (sessionOver), nor a 503 to retry (unavailable): its status,
  // the API's code (design §17's Errors) and the broker's detail.
  type APIError struct {
  	Status int
  	Code   string
  	Detail string
  }

  func (e *APIError) Error() string { return "agent: the broker refused: " + e.Code + ": " + e.Detail }

  // call sends one request on the held connection and decodes a 200 into out.
  // A refusal that ends the session ends it here, as a mint's does; a 503 is
  // unavailable's error; anything else is an *APIError. A transport failure
  // is tried once more on a new connection, as post does: every call made
  // through it is safe to repeat (identity and explain read; a revocation
  // made again reaches what the first did not, and stands as before).
  func (a *Agent) call(ctx context.Context, method, path string, in, out any) error {
  	select {
  	case <-a.done:
  		return ErrSessionOver
  	default:
  	}
  	if ends := a.SessionEndsAt(); ends.IsZero() || !a.now().Before(ends) {
  		return ErrSessionOver
  	}
  	var body []byte
  	if in != nil {
  		var err error
  		if body, err = json.Marshal(in); err != nil {
  			return err
  		}
  	}
  	var resp *http.Response
  	for attempt := 1; ; attempt++ {
  		var rd io.Reader = http.NoBody
  		if in != nil {
  			rd = bytes.NewReader(body)
  		}
  		req, err := http.NewRequestWithContext(ctx, method, a.broker+path, rd)
  		if err != nil {
  			return err
  		}
  		if in != nil {
  			req.Header.Set("Content-Type", "application/json")
  		}
  		if resp, err = a.do(req); err == nil {
  			break
  		}
  		a.client.CloseIdleConnections()
  		if over := a.refusedReconnect(err); over != nil {
  			return over
  		}
  		if attempt == 2 {
  			var hup *hangUpError
  			if errors.As(err, &hup) {
  				return hup
  			}
  			return fmt.Errorf("agent: the broker at %s is unreachable: %w", a.broker, err)
  		}
  	}
  	defer drain(resp.Body)
  	if resp.StatusCode == http.StatusOK {
  		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
  			return fmt.Errorf("agent: the broker's answer: %w", err)
  		}
  		return nil
  	}
  	var e api.Error
  	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&e)
  	if over := sessionOver(resp.StatusCode, e); over != nil {
  		a.end(over)
  		return over
  	}
  	if busy := unavailable(resp, e); busy != nil {
  		return busy
  	}
  	if resp.StatusCode == http.StatusNotFound && e.Error == "" {
  		// The broker's mux has no such route: a port49d older than this
  		// agent (pre-flight I9).
  		return &APIError{Status: http.StatusNotFound, Code: "not_supported", Detail: fmt.Sprintf(
  			"the broker at %s does not serve %s: it runs a port49d older than this port49", a.broker, path)}
  	}
  	return &APIError{Status: resp.StatusCode, Code: e.Error, Detail: e.Detail}
  }

  // Identity is GET /v1/identity: what the broker resolves this session's
  // principal to (design §17).
  func (a *Agent) Identity(ctx context.Context) (api.Identity, error) {
  	var out api.Identity
  	return out, a.call(ctx, http.MethodGet, "/v1/identity", nil, &out)
  }

  // Explain is POST /v1/explain: a hypothetical decision from the broker's
  // policy in force (design §17).
  func (a *Agent) Explain(ctx context.Context, req api.ExplainRequest) (api.ExplainResponse, error) {
  	var out api.ExplainResponse
  	return out, a.call(ctx, http.MethodPost, "/v1/explain", req, &out)
  }

  // Revoke is POST /v1/tokens/revoke under this session's principal's rights
  // (spec §5.1.4). A self-revocation leaves no mark, so the session goes on;
  // a revocation of this session's own principal by another is answered
  // credential_revoked at the next call, which ends it.
  func (a *Agent) Revoke(ctx context.Context, req api.RevokeRequest) (api.RevokeResponse, error) {
  	var out api.RevokeResponse
  	return out, a.call(ctx, http.MethodPost, "/v1/tokens/revoke", req, &out)
  }
  ```

  In `Handler`, add three routes and a shared writer:

  ```go
  	mux.HandleFunc("GET /identity", func(w http.ResponseWriter, r *http.Request) {
  		out, err := a.Identity(r.Context())
  		answer(w, out, err)
  	})
  	mux.HandleFunc("POST /explain", func(w http.ResponseWriter, r *http.Request) {
  		var req api.ExplainRequest
  		dec := json.NewDecoder(io.LimitReader(r.Body, 1<<16))
  		dec.DisallowUnknownFields()
  		if err := dec.Decode(&req); err != nil {
  			writeJSON(w, http.StatusBadRequest, api.Error{Error: "bad_request", Detail: "not an explain request"})
  			return
  		}
  		out, err := a.Explain(r.Context(), req)
  		answer(w, out, err)
  	})
  	mux.HandleFunc("POST /revoke", func(w http.ResponseWriter, r *http.Request) {
  		var req api.RevokeRequest
  		dec := json.NewDecoder(io.LimitReader(r.Body, 1<<16))
  		dec.DisallowUnknownFields()
  		if err := dec.Decode(&req); err != nil {
  			writeJSON(w, http.StatusBadRequest, api.Error{Error: "bad_request", Detail: "not a revocation request"})
  			return
  		}
  		out, err := a.Revoke(r.Context(), req)
  		answer(w, out, err)
  	})
  ```

  ```go
  // answer writes one API call's result to the socket: out on success; a
  // session that is over as POST /token says it (410, the revocation's own
  // code kept); a broker refusal with its own status and body, so the client
  // rebuilds the *APIError; anything else 502 with the agent's error.
  func answer(w http.ResponseWriter, out any, err error) {
  	var revoked *RevokedError
  	var refused *APIError
  	switch {
  	case err == nil:
  		writeJSON(w, http.StatusOK, out)
  	case errors.As(err, &revoked):
  		writeJSON(w, http.StatusGone, api.Error{Error: "credential_revoked", Detail: revoked.Detail})
  	case errors.Is(err, ErrSessionOver):
  		writeJSON(w, http.StatusGone, api.Error{Error: "session_over", Detail: err.Error()})
  	case errors.As(err, &refused):
  		writeJSON(w, refused.Status, api.Error{Error: refused.Code, Detail: refused.Detail})
  	default:
  		writeJSON(w, http.StatusBadGateway, api.Error{Error: "broker_error", Detail: err.Error()})
  	}
  }
  ```

  Update `Handler`'s comment to name the three routes.

- [ ] **Step 4: The client.** In `internal/agent/socket.go`:

  ```go
  // ErrAgentTooOld is a call the running agent has no route for: it was
  // started by a port49 older than this one, and lives until max_session_age
  // (pre-flight I9).
  var ErrAgentTooOld = errors.New("agent: your agent (started before this port49) does not carry this command; " +
  	"run `port49 login` again")

  // roundTrip asks the agent one API call: a 200 decodes into out; a 410 is
  // the session's end (a revocation's own error, or ErrSessionOver); a 404
  // with no API code is the agent's own mux, which predates the route
  // (ErrAgentTooOld); a 4xx with the broker's code is an *APIError; anything
  // else names the agent's error.
  func (c *Client) roundTrip(ctx context.Context, method, path string, in, out any) error {
  	var rd io.Reader = http.NoBody
  	if in != nil {
  		body, err := json.Marshal(in)
  		if err != nil {
  			return err
  		}
  		rd = bytes.NewReader(body)
  	}
  	req, err := http.NewRequestWithContext(ctx, method, "http://agent"+path, rd)
  	if err != nil {
  		return err
  	}
  	if err := c.checkDir(); err != nil {
  		return err
  	}
  	resp, err := c.http.Do(req)
  	if err != nil {
  		return fmt.Errorf("%w at %s: %v", ErrNoAgent, c.socket, err)
  	}
  	defer resp.Body.Close()
  	if resp.StatusCode == http.StatusOK {
  		return json.NewDecoder(resp.Body).Decode(out)
  	}
  	var e api.Error
  	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&e)
  	switch {
  	case resp.StatusCode == http.StatusGone && e.Error == "credential_revoked":
  		return &RevokedError{Detail: e.Detail}
  	case resp.StatusCode == http.StatusGone:
  		return fmt.Errorf("%w%s", ErrSessionOver, strings.TrimPrefix(e.Detail, ErrSessionOver.Error()))
  	case resp.StatusCode == http.StatusNotFound && e.Error == "":
  		return ErrAgentTooOld
  	case resp.StatusCode >= 400 && resp.StatusCode < 500:
  		return &APIError{Status: resp.StatusCode, Code: e.Error, Detail: e.Detail}
  	}
  	return errors.New(e.Detail)
  }

  // Identity asks the agent what the broker resolves its principal to.
  func (c *Client) Identity(ctx context.Context) (api.Identity, error) {
  	var out api.Identity
  	return out, c.roundTrip(ctx, http.MethodGet, "/identity", nil, &out)
  }

  // Explain asks the agent for the broker's explanation.
  func (c *Client) Explain(ctx context.Context, req api.ExplainRequest) (api.ExplainResponse, error) {
  	var out api.ExplainResponse
  	return out, c.roundTrip(ctx, http.MethodPost, "/explain", req, &out)
  }

  // Revoke asks the agent to send a revocation under its principal's rights.
  func (c *Client) Revoke(ctx context.Context, req api.RevokeRequest) (api.RevokeResponse, error) {
  	var out api.RevokeResponse
  	return out, c.roundTrip(ctx, http.MethodPost, "/revoke", req, &out)
  }
  ```

  A `503` the broker sent reaches the client as the agent's 502 `broker_error` with
  `unavailable`'s text, which already says to try again and when. A broker older than the agent
  reaches the client as `answer`'s 404 with the code `not_supported`, an `*APIError` naming the
  broker, so the two upgrade orders read differently.

- [ ] **Step 5: Run the tests.**

  Run: `go test ./internal/agent/`
  Expected: PASS.

- [ ] **Step 6: Commit.**

  ```bash
  gofmt -w internal/agent/agent.go internal/agent/socket.go internal/agent/agent_test.go
  make build && make test && make vet
  git add internal/agent/agent.go internal/agent/socket.go internal/agent/agent_test.go
  git commit -m "feat(agent): carry identity, explain and revoke over the held connection

  One call path for the API: a refusal that ends the session ends it, a 503 is
  retried by the caller, and a broker refusal such as 403 api_right_missing
  comes back to the CLI as an APIError. An agent older than the CLI is named
  as such, with the fix (port49 login), not reported as a broker refusal.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 12: `port49 identity`, `port49 explain` over the agent, and `port49 revoke --mine` and `--via-agent`

**Files:**
- Create: `cmd/port49/identity.go`
- Modify: `cmd/port49/main.go` (`usage`; `run` dispatches `identity`)
- Modify: `cmd/port49/policy.go` (`explainCmd`: the agent form)
- Modify: `cmd/port49/revoke.go` (`revokeCmd`: the agent forms and the question; new
  `revokeOverAgent`, `confirmRevoke`; `askRevoke`: `--list`'s pointer to the log)
- Test: `cmd/port49/api_linux_test.go` (new); `cmd/port49/revoke_linux_test.go` (`--list`'s
  pointer, ~line 95); `cmd/port49/main_test.go` (usage checks, if it has them)

**Interfaces:**
- Consumes: `agent.Client.Identity`, `.Explain`, `.Revoke`, `agent.APIError`,
  `agent.RevokedError`, `agent.ErrNoAgent` (Task 11); `unprefixed`.
- Produces:
  - `func identityCmd(args []string, stdout, stderr io.Writer) int`
  - `func printIdentity(w io.Writer, id api.Identity)`
  - `func revokeOverAgent(socket string, req api.RevokeRequest, stdout, stderr io.Writer) int`
  - `var confirmIn io.Reader`, `var confirmTTY func() bool`;
    `func confirmRevoke(principal string, stderr io.Writer) bool`

- [ ] **Step 1: Write the failing tests.** Create `cmd/port49/api_linux_test.go`:

  ```go
  //go:build linux

  package main

  import (
  	"bytes"
  	"strings"
  	"testing"
  	"time"
  )

  // The CLI's API commands, through a real agent to a real broker: identity
  // says who the session is and until when its connection lasts; explain
  // answers from the broker with no policy file; revoke --mine ends the
  // caller's own sessions with no mark, so a token mints at once after it;
  // revoking another principal, or a key without --mine, without the right is
  // refused, exit 1, saying which right and, for a key, the --mine form; a
  // key with neither --mine nor --via-agent is usage.
  func TestTheCLIReachesTheAPIThroughTheAgent(t *testing.T) {
  	l := newLabBroker(t, time.Hour)
  	sock := privateSocket(t)
  	t.Cleanup(func() { stopAgentAt(sock) })
  	t.Setenv(runCLIEnv, "1")
  	var out, errb bytes.Buffer
  	if code := run(append([]string{"login"}, l.flags(sock)...), &out, &errb); code != 0 {
  		t.Fatalf("login: %d %s %s", code, out.String(), errb.String())
  	}
  	cli := func(args ...string) (int, string, string) {
  		out.Reset()
  		errb.Reset()
  		code := run(args, &out, &errb)
  		return code, out.String(), errb.String()
  	}
  	if code, so, se := cli("identity", "--socket", sock); code != 0 ||
  		!strings.Contains(so, "principal  user:alice@example.com") || !strings.Contains(so, "subject    s") ||
  		!strings.Contains(so, "all_devices [r]") || !strings.Contains(so, "api        (none") ||
  		!strings.Contains(so, "this connection lasts until") {
  		t.Fatalf("identity: %d %q %q", code, so, se)
  	}
  	if code, so, se := cli("explain", "--socket", sock, "--device", "leaf1", "--command", "show version"); code != 0 ||
  		!strings.HasPrefix(so, "permit permit_dominates") {
  		t.Fatalf("explain: %d %q %q", code, so, se)
  	}
  	if code, _, se := cli("explain", "--socket", sock, "--device", "leaf1", "--subject", "s"); code != 2 ||
  		!strings.Contains(se, "--subject") {
  		t.Fatalf("explain --subject over the agent: %d %q", code, se)
  	}
  	if code, so, se := cli("revoke", "--mine", "--agent-socket", sock); code != 0 ||
  		!strings.Contains(so, "ended user:alice@example.com's sessions everywhere") {
  		t.Fatalf("revoke --mine: %d %q %q", code, so, se)
  	}
  	if code, so, se := cli("token", "--socket", sock, "leaf1"); code != 0 || so == "" {
  		t.Fatalf("a token after revoke --mine: %d %q %q", code, so, se)
  	}
  	if code, _, se := cli("revoke", "--via-agent", "--principal", "user:carol@example.com", "--agent-socket", sock); code != 1 ||
  		!strings.Contains(se, "needs the api: revoke_others right") {
  		t.Fatalf("revoking another without the right: %d %q", code, se)
  	}
  	if code, _, se := cli("revoke", "--via-agent", "--device", "leaf1", "--username", "alice", "--agent-socket", sock); code != 1 ||
  		!strings.Contains(se, "needs the api: revoke_others right") || !strings.Contains(se, "--mine --device leaf1 --username alice") {
  		t.Fatalf("a key without the right: %d %q", code, se)
  	}
  	if code, _, se := cli("revoke", "--device", "leaf1", "--username", "alice", "--agent-socket", sock); code != 2 ||
  		!strings.Contains(se, "--mine") {
  		t.Fatalf("a key with neither --mine nor --via-agent: %d %q", code, se)
  	}
  	if code, _, se := cli("revoke", "--via-agent", "--lift", "--principal", "user:carol@example.com"); code != 2 ||
  		!strings.Contains(se, "admin socket") {
  		t.Fatalf("--lift over the agent: %d %q", code, se)
  	}
  }
  ```

  The `permit permit_dominates` line is what `Render` prints for a permitted command; if the
  policy's `**` permit renders another reason, assert the first word, `permit`.

  Add, in the same file:

  ```go
  // --via-agent --principal asks before it marks someone, on a terminal only;
  // a no sends nothing, and --yes skips the question (pre-flight M11). The
  // socket names no agent, so a request that is sent says so.
  func TestRevokeViaAgentAsksOnATerminal(t *testing.T) {
  	defer func(in io.Reader, tty func() bool) { confirmIn, confirmTTY = in, tty }(confirmIn, confirmTTY)
  	confirmTTY = func() bool { return true }
  	sock := filepath.Join(t.TempDir(), "none.sock")
  	args := []string{"revoke", "--via-agent", "--principal", "user:bob@example.com", "--agent-socket", sock}
  	var out, errb bytes.Buffer
  	confirmIn = strings.NewReader("n\n")
  	if code := run(args, &out, &errb); code != 1 || !strings.Contains(errb.String(), "[y/N]") ||
  		!strings.Contains(errb.String(), "nothing was revoked") || strings.Contains(errb.String(), "no agent at") {
  		t.Fatalf("declined: %d %q", code, errb.String())
  	}
  	errb.Reset()
  	confirmIn = strings.NewReader("")
  	if code := run(append(args, "--yes"), &out, &errb); code != 1 || strings.Contains(errb.String(), "[y/N]") ||
  		!strings.Contains(errb.String(), "no agent at") {
  		t.Fatalf("--yes: %d %q", code, errb.String())
  	}
  	errb.Reset()
  	confirmTTY = func() bool { return false }
  	if code := run(args, &out, &errb); code != 1 || strings.Contains(errb.String(), "[y/N]") {
  		t.Fatalf("off a terminal: %d %q", code, errb.String())
  	}
  }
  ```

  `api_linux_test.go` gains the `io` and `path/filepath` imports. In `revoke_linux_test.go`, the
  successful `--list` (~line 95) also asserts `strings.Contains(errb.String(), "leaves no mark and
  is not listed")`.

- [ ] **Step 2: Run it to see it fail.**

  Run: `go test ./cmd/port49/ -run 'TestTheCLIReachesTheAPIThroughTheAgent|TestRevokeViaAgentAsksOnATerminal'`
  Expected: build failure (`confirmIn`, `confirmTTY` undefined), then `identity` a usage error,
  exit 2.

- [ ] **Step 3: `port49 identity`.** Create `cmd/port49/identity.go`:

  ```go
  package main

  import (
  	"context"
  	"encoding/json"
  	"errors"
  	"flag"
  	"fmt"
  	"io"
  	"strings"

  	"github.com/rhwendt/port49/internal/agent"
  	"github.com/rhwendt/port49/internal/broker/api"
  )

  // identityCmd is `port49 identity` (spec §12): what the broker resolves the
  // agent's principal to (GET /v1/identity).
  func identityCmd(args []string, stdout, stderr io.Writer) int {
  	fs := flag.NewFlagSet("port49 identity", flag.ContinueOnError)
  	fs.SetOutput(stderr)
  	socket := fs.String("socket", agent.SocketPath(), "the agent's socket")
  	asJSON := fs.Bool("json", false, "print the broker's answer as JSON")
  	if err := fs.Parse(args); err != nil {
  		return 2
  	}
  	if fs.NArg() != 0 {
  		fmt.Fprint(stderr, usage)
  		return 2
  	}
  	id, err := agent.NewClient(*socket).Identity(context.Background())
  	switch {
  	case errors.Is(err, agent.ErrNoAgent):
  		fmt.Fprintf(stderr, "port49 identity: no agent at %s; run 'port49 login'\n", *socket)
  		return 1
  	case err != nil:
  		fmt.Fprintln(stderr, "port49 identity:", unprefixed(err))
  		return 1
  	}
  	if *asJSON {
  		enc := json.NewEncoder(stdout)
  		enc.SetIndent("", "  ")
  		_ = enc.Encode(id)
  		return 0
  	}
  	printIdentity(stdout, id)
  	return 0
  }

  // printIdentity says who the session is, one fact a line.
  func printIdentity(w io.Writer, id api.Identity) {
  	fmt.Fprintf(w, "principal  %s (%s %s)\n", id.Principal, id.Method, id.Fingerprint)
  	subject := id.Subject
  	if subject == "" {
  		subject = "(none: no subject names this principal, so nothing is minted for it)"
  	}
  	fmt.Fprintf(w, "subject    %s\n", subject)
  	if len(id.Groups) > 0 {
  		fmt.Fprintf(w, "groups     %s\n", strings.Join(id.Groups, ", "))
  	}
  	if len(id.Grants) == 0 {
  		fmt.Fprintln(w, "grants     (none)")
  	}
  	for i, g := range id.Grants {
  		label := "grants    "
  		if i > 0 {
  			label = "          "
  		}
  		line := g.Scope + " [" + strings.Join(g.Roles, " ") + "]"
  		if g.MaxPrivilege != "" {
  			line += " max_privilege " + g.MaxPrivilege
  		}
  		if g.Expires != "" {
  			line += " expires " + g.Expires
  		}
  		fmt.Fprintf(w, "%s %s\n", label, line)
  	}
  	rights := "(none: you act on your own tokens and sessions alone)"
  	if len(id.API) > 0 {
  		rights = strings.Join(id.API, ", ")
  	}
  	fmt.Fprintf(w, "api        %s\n", rights)
  	fmt.Fprintf(w, "session    authenticated %s", id.AuthTime)
  	if id.ConnectionEndsAt != "" {
  		// max_session_age's end for this connection, not a device session's:
  		// a role's ceiling on a device may end one sooner (pre-flight M16).
  		fmt.Fprintf(w, "; this connection lasts until %s (a device's own session ceiling may end a session "+
  			"sooner)", id.ConnectionEndsAt)
  	}
  	fmt.Fprintln(w)
  }
  ```

  In `main.go`'s `run`, add `case "identity": return identityCmd(args[1:], stdout, stderr)`.

- [ ] **Step 4: `port49 explain` over the agent.** In `cmd/port49/policy.go`'s `explainCmd`, add
  `socket := fs.String("socket", agent.SocketPath(), "the agent's socket, when no --policy is given")`
  beside the other flags. After `fs.Parse`, before the existing usage check:

  ```go
  	// With neither file it asks the broker, through the agent, from the policy
  	// in force (POST /v1/explain; decision 34). --subject and the session
  	// attributes are the offline form's alone.
  	if files.policy == "" && files.inventory == "" {
  		switch {
  		case *subject != "":
  			fmt.Fprintln(stderr, "port49 explain: --subject needs --policy and --inventory; over the broker name a "+
  				"--principal, or nobody for yourself")
  			return 2
  		case *attrs:
  			fmt.Fprintln(stderr, "port49 explain: --show-attributes needs --policy and --inventory")
  			return 2
  		case *device == "" || fs.NArg() != 0:
  			fmt.Fprint(stderr, usage)
  			return 2
  		}
  		e, err := agent.NewClient(*socket).Explain(context.Background(),
  			api.ExplainRequest{Device: *device, Command: *command, Principal: *principal})
  		var refused *agent.APIError
  		switch {
  		case errors.Is(err, agent.ErrNoAgent):
  			fmt.Fprintf(stderr, "port49 explain: no agent at %s; run 'port49 login', or give --policy and --inventory\n", *socket)
  			return 1
  		case errors.As(err, &refused) && refused.Code == "api_right_missing":
  			fmt.Fprintln(stderr, "port49 explain: refused: explaining another principal needs the api: explain_others "+
  				"right, which your subject does not declare")
  			return 1
  		case err != nil:
  			fmt.Fprintln(stderr, "port49 explain:", unprefixed(err))
  			return 1
  		}
  		fmt.Fprint(stdout, e.Text)
  		return 0
  	}
  ```

  Add the `context`, `errors`, `agent` and `api` imports to `policy.go` as needed.

- [ ] **Step 5: `port49 revoke` over the agent.** In `cmd/port49/revoke.go`'s `revokeCmd`, add the
  flags:

  ```go
  	mine := fs.Bool("mine", false, "end your own sessions and delete your own unspent tokens, through your agent; leaves no mark")
  	viaAgent := fs.Bool("via-agent", false, "send the revocation to the broker through your agent, under your api: rights")
  	device := fs.String("device", "", "with --mine or --via-agent: one device, by its inventory name")
  	username := fs.String("username", "", "with --device: the device-facing username")
  	agentSocket := fs.String("agent-socket", agent.SocketPath(), "your agent's socket")
  	yes := fs.Bool("yes", false, "with --via-agent --principal: do not ask before revoking")
  ```

  After `fs.Parse` and the `NArg` check:

  ```go
  	if *mine || *viaAgent || *device != "" || *username != "" {
  		switch {
  		case *list || *lift || *certFile != "" || *issuer != "" || *serial != "":
  			fmt.Fprintln(stderr, "port49 revoke: over the broker a revocation names --mine, --principal, or "+
  				"--device and --username; lifting, listing and certificates are port49d's admin socket's (--socket)")
  			return 2
  		case *mine && *viaAgent, *mine && *principal != "":
  			fmt.Fprintln(stderr, "port49 revoke: --mine names yourself; use --via-agent --principal for another")
  			return 2
  		case (*device == "") != (*username == ""):
  			fmt.Fprintln(stderr, "port49 revoke: --device and --username go together")
  			return 2
  		case !*mine && !*viaAgent:
  			// A key means one thing whatever the caller's rights (pre-flight I2).
  			fmt.Fprintln(stderr, "port49 revoke: --device and --username go with --mine (your own session there) "+
  				"or --via-agent (whoever's, under api: revoke_others)")
  			return 2
  		case !*mine && (*principal == "") == (*device == ""):
  			fmt.Fprintln(stderr, "port49 revoke: --via-agent names --principal, or --device and --username")
  			return 2
  		}
  		if *viaAgent && *principal != "" && !*yes && confirmTTY() && !confirmRevoke(*principal, stderr) {
  			fmt.Fprintln(stderr, "port49 revoke: nothing was revoked")
  			return 1
  		}
  		return revokeOverAgent(*agentSocket, api.RevokeRequest{Mine: *mine, Principal: *principal,
  			Device: *device, Username: *username}, stdout, stderr)
  	}
  ```

  And:

  ```go
  // revokeOverAgent sends a revocation to the broker through the agent, under
  // the caller's api: rights (spec §5.1.4, §12). It prints what the broker
  // says it reached and exits as port49 revoke does: 0 done, 1 refused or
  // unreachable, 3 in force but incomplete or, for a standing mark, unsaved.
  func revokeOverAgent(socket string, req api.RevokeRequest, stdout, stderr io.Writer) int {
  	rep, err := agent.NewClient(socket).Revoke(context.Background(), req)
  	var refused *agent.APIError
  	var revoked *agent.RevokedError
  	switch {
  	case errors.Is(err, agent.ErrNoAgent):
  		fmt.Fprintf(stderr, "port49 revoke: no agent at %s; run 'port49 login'\n", socket)
  		return 1
  	case errors.As(err, &refused) && refused.Code == "api_right_missing" && req.Principal != "":
  		fmt.Fprintln(stderr, "port49 revoke: refused: revoking another principal needs the api: revoke_others "+
  			"right, which your subject does not declare")
  		return 1
  	case errors.As(err, &refused) && refused.Code == "api_right_missing":
  		fmt.Fprintf(stderr, "port49 revoke: refused: ending a (device, username) whoever holds it needs the api: "+
  			"revoke_others right, which your subject does not declare; for your own session there, use --mine "+
  			"--device %s --username %s\n", req.Device, req.Username)
  		return 1
  	case errors.As(err, &revoked):
  		fmt.Fprintln(stderr, "port49 revoke:", unprefixed(err))
  		return 1
  	case err != nil:
  		fmt.Fprintln(stderr, "port49 revoke:", unprefixed(err))
  		return 1
  	}
  	if rep.By != "self" && rep.Principal != "" {
  		// Whom the broker revoked, by the policy's subject, so a misspelt
  		// colleague is seen at once (pre-flight M11).
  		subject := "no subject in the policy in force names it"
  		if rep.Subject != "" {
  			subject = "subject " + rep.Subject
  		}
  		fmt.Fprintf(stdout, "target: %s (%s)\n", rep.Principal, subject)
  	}
  	fmt.Fprintln(stdout, rep.Text)
  	if rep.Incomplete != "" || (rep.Saved != nil && !*rep.Saved) {
  		return 3
  	}
  	return 0
  }
  ```

  The question, asked only on a terminal, so a script never hangs on it:

  ```go
  // confirmIn and confirmTTY are where port49 revoke --via-agent --principal
  // asks before it puts a standing mark on someone from a laptop (pre-flight
  // M11): the terminal, and only when stdin is one. Swapped in tests.
  var (
  	confirmIn  io.Reader = os.Stdin
  	confirmTTY           = func() bool {
  		fi, err := os.Stdin.Stat()
  		return err == nil && fi.Mode()&os.ModeCharDevice != 0
  	}
  )

  // confirmRevoke asks whether to revoke principal, on stderr, and reads one
  // line: y or yes goes on, anything else, an empty line or EOF included,
  // does not.
  func confirmRevoke(principal string, stderr io.Writer) bool {
  	fmt.Fprintf(stderr, "revoke %s everywhere? It is a standing mark: every mint by it is refused until it is "+
  		"lifted on port49d's admin socket. [y/N] ", principal)
  	line, _ := bufio.NewReader(confirmIn).ReadString('\n')
  	switch strings.ToLower(strings.TrimSpace(line)) {
  	case "y", "yes":
  		return true
  	}
  	return false
  }
  ```

  `--list` shows marks only; a self or key revocation leaves none (pre-flight M19). In
  `askRevoke`, after a successful `revocations` answer is printed, add on stderr, so stdout stays
  the list a script reads:

  ```go
  	if req.Op == "revocations" {
  		fmt.Fprintln(stderr, "port49 revoke: a self or key revocation (--mine, or --via-agent --device) leaves no "+
  			"mark and is not listed: port49d's decision log names each (event revoke, revocation.by self or key)")
  	}
  ```

  Add the `bufio`, `context`, `agent` and `api` imports to `revoke.go`. The admin-socket path below
  is otherwise unchanged.

- [ ] **Step 6: The usage text.** In `main.go`'s `usage`, after the `port49 refresh` line:

  ```
    port49 identity [--json] [--socket PATH]
  ```

  After the offline `port49 explain` lines:

  ```
    port49 explain --device NAME [--command "LINE"] [--principal ID] [--socket PATH]
                   (asks the broker through your agent; --principal another needs api: explain_others)
  ```

  After the `port49 revoke … --list` lines:

  ```
    port49 revoke --mine [--device NAME --username NAME] [--agent-socket PATH]
    port49 revoke --via-agent [--yes] (--principal PRINCIPAL | --device NAME --username NAME) [--agent-socket PATH]
                  (through your agent, under your api: rights; --mine leaves no mark; --via-agent needs
                  api: revoke_others, and asks first on a terminal unless --yes)
  ```

  Update the package comment's first paragraph to say `identity`, and `explain` without files,
  ask the broker through the agent.

- [ ] **Step 7: Run the tests.**

  Run: `go test ./cmd/port49/`
  Expected: PASS, the offline `explain` and admin-socket `revoke` tests included.

- [ ] **Step 8: Commit.**

  ```bash
  gofmt -w cmd/port49/identity.go cmd/port49/main.go cmd/port49/policy.go cmd/port49/revoke.go cmd/port49/api_linux_test.go \
    cmd/port49/revoke_linux_test.go
  make build && make test && make vet
  git add cmd/port49/identity.go cmd/port49/main.go cmd/port49/policy.go cmd/port49/revoke.go cmd/port49/api_linux_test.go \
    cmd/port49/revoke_linux_test.go
  git commit -m "feat(port49): identity, explain over the agent, and revoke --mine and --via-agent

  The HTTP API from the operator's own laptop: who the broker says they are, an
  explanation from the policy in force with no policy file, and a revocation
  under their api: rights. A key means one thing whatever the rights; a mark on
  someone else is asked about on a terminal and names the target's subject.
  Lift, list and certificates stay the admin socket's; --list points at the log
  for revocations that leave no mark.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 13: (lab, on beehive) The HTTP revocation end to end on four images

**Files:**
- Modify: `internal/testpki/testpki.go` (`WriteLabWith`, `LabClientFiles`; `WriteLab` calls
  `WriteLabWith`)
- Test: `internal/testpki/testpki_test.go` (add)
- Modify: `tests/lab/revoke_test.go` (`revokeAgent` delegates to a new `personAgent`)
- Create: `tests/lab/slice/api-policy.yaml`
- Create: `tests/lab/api_revoke_test.go`
- Created by the run: `tests/lab/results/api-revoke-<platform>.md`,
  `tests/lab/evidence/api-revoke-<platform>.pcap` (through `l.capture` and `make evidence`)

**Interfaces:**
- Consumes: the lab harness (`eachPlatform`, `l.derivedConfig`, `l.stopDaemon`,
  `l.startDaemonWith`, `l.awaitTACACS`, `l.configPath`, `l.capture`, `l.mark`, `l.shell`,
  `l.loginWithin`, `l.waitForRecords`, `l.recordsSince`, `l.result`); 7a's `revokeOutcome`,
  `revokeCLI`, `redeemReason`, `agentEnded`, `revokedMint`, `mintRefusal` (all in
  `tests/lab/revoke_test.go`); `l29Mint`, `l29Cell`; `sha`, `str`, `sub`, `summarize`,
  `sliceRecords`; `sliceUser`, `sliceEmail`, `slicePrincipal`, `slicePKIDir`, `sliceBrokerURL`; and
  `agentPID`, the regexp var (`tests/lab/slice_test.go:54`) that `personAgent` keeps using to read
  the pid off `port49 login`'s output. `revokeRefusedLine` is 7a's and this run does not use it.
- Produces:
  - `func testpki.WriteLabWith(dir, email string, others []string, now time.Time) error`
  - `func testpki.LabClientFiles(email string) (cert, key string)`
  - `func personAgent(t *testing.T, cert, key string) (sock string, pid int, stop func())`

**What it measures** (no register row; Ruling 10). The device side of a marked context rests on
7a's `tests/lab/results/revoke-*.md`. This run measures, on each image, that the HTTP shapes reach
it as claimed.

- **A peer with no right reaches nothing.** carol's `port49 revoke --via-agent --principal alice` is
  refused 403 and recorded, and so is her `--via-agent --device <node> --username slice01`, the
  key form without the right (never narrowed to her own there); alice's next command still runs.
- **A self-revocation, then a re-login.** alice's `port49 revoke --mine` makes her open session's
  next command refused, on the per-command platforms. Her unspent token logs in nowhere
  (`token_not_found`). A token she mints after it logs in at once with no lift (decision 15's join).
  That login joins the context the open session shares, so the session `--mine` refused runs its
  next command again: the re-admission the report warns of, measured and recorded.
- **An on-call ends one key.** bob, with `revoke_others`, runs `port49 revoke --via-agent --device
  <node> --username slice01`. alice's session on the new login refuses its next command, and she
  logs in again at once.
- **An on-call revokes the principal.** bob's `--via-agent --principal alice` is 7a's revocation
  from his laptop: refused, and alice's agent ends on `credential_revoked`. `port49 revoke --list`
  on the admin socket shows `(api user:bob@slice.port49.test)`. A lift there, and a login works.
- **On Junos** the open session keeps what it had at login, and every report names it not
  reached.

- [ ] **Step 1: The lab PKI writes more than one person.** Add to `internal/testpki/testpki_test.go`:

  ```go
  // WriteLabWith writes one client certificate per extra email beside the
  // first's, under LabClientFiles' names, from the same CA.
  func TestWriteLabWithWritesEachPerson(t *testing.T) {
  	dir := t.TempDir()
  	if err := WriteLabWith(dir, "alice@lab.test", []string{"bob@lab.test"}, time.Now()); err != nil {
  		t.Fatal(err)
  	}
  	cert, key := LabClientFiles("bob@lab.test")
  	if cert != "client-bob.pem" || key != "client-bob-key.pem" {
  		t.Fatalf("%s %s", cert, key)
  	}
  	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, cert), filepath.Join(dir, key))
  	if err != nil {
  		t.Fatal(err)
  	}
  	leaf, err := x509.ParseCertificate(pair.Certificate[0])
  	if err != nil || len(leaf.EmailAddresses) != 1 || leaf.EmailAddresses[0] != "bob@lab.test" {
  		t.Fatalf("%v %v", leaf.EmailAddresses, err)
  	}
  	if fi, err := os.Stat(filepath.Join(dir, key)); err != nil || fi.Mode().Perm() != 0o600 {
  		t.Fatalf("key mode: %v %v", fi, err)
  	}
  }
  ```

  Run `go test ./internal/testpki/` and see it fail (undefined). Then in `testpki.go`:

  ```go
  // LabClientFiles names the certificate and key WriteLabWith writes for an
  // extra person: client-<local part>.pem and client-<local part>-key.pem.
  func LabClientFiles(email string) (cert, key string) {
  	local, _, _ := strings.Cut(email, "@")
  	return "client-" + local + ".pem", "client-" + local + "-key.pem"
  }

  // WriteLabWith is WriteLab with a client certificate for each of others
  // too, from the same CA, under LabClientFiles' names: the lab's on-call
  // and peer beside its operator (plan 7c).
  func WriteLabWith(dir, email string, others []string, now time.Time) error {
  	// … WriteLab's body, unchanged, then for each of others:
  	//	c, err := ca.Issue(Leaf{CommonName: o, Emails: []string{o}, Client: true,
  	//		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
  	//	certName, keyName := LabClientFiles(o)
  	//	files[certName], files[keyName] = PEMs(c)
  	// before the files are written.
  }

  // WriteLab writes the vertical slice's lab PKI … (its comment, unchanged).
  func WriteLab(dir, email string, now time.Time) error { return WriteLabWith(dir, email, nil, now) }
  ```

  Write `WriteLabWith`'s body out in full: WriteLab's, with the loop the comment shows. Add
  `strings` to the imports. Run `go test ./internal/testpki/` and see it pass.

- [ ] **Step 2: The lab policy.** Create `tests/lab/slice/api-policy.yaml`: a copy of
  `tests/lab/slice/policy.yaml`, with a first comment line saying it is for
  `TestAPIRevokeEndToEnd` (plan 7c), and these two entries added to its `subjects:` list after
  `slice_operator`:

  ```yaml
    # The on-call: no grant on any device, and the right to revoke others (spec §2).
    - {name: slice_oncall, identity: ["user:bob@slice.port49.test"], username: slice02, token_ttl: 60s,
       api: [revoke_others]}
    # A peer: no grant and no right. What it asks of anyone else is refused.
    - {name: slice_peer, identity: ["user:carol@slice.port49.test"], username: slice03, token_ttl: 60s}
  ```

  Check it loads: `bin/port49 policy test --policy tests/lab/slice/api-policy.yaml --inventory
  tests/lab/inventory-lab.yaml` (or the inventory the slice tests load) exits as
  `tests/lab/slice/policy.yaml` does.

- [ ] **Step 3: An agent for any person.** In `tests/lab/revoke_test.go`, rename `revokeAgent`'s
  body into:

  ```go
  // personAgent starts `port49 login` with cert and key (paths under the slice
  // PKI directory) on a fresh private socket and returns its socket, its pid,
  // and a stop that ends it only if it is still running (pre-flight I4).
  func personAgent(t *testing.T, cert, key string) (sock string, pid int, stop func())
  ```

  It holds `revokeAgent`'s code with `testpki.LabClientCert` and `testpki.LabClientKey` replaced by
  `cert` and `key`. Then:

  ```go
  func revokeAgent(t *testing.T) (string, int, func()) {
  	return personAgent(t, testpki.LabClientCert, testpki.LabClientKey)
  }
  ```

  Add, beside `revokeCLI`:

  ```go
  // agentRevoke runs `port49 revoke` with args against the agent at sock, and
  // returns what it printed and its exit code.
  func agentRevoke(sock string, args ...string) (string, int) {
  	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
  	defer cancel()
  	cmd := exec.CommandContext(ctx, filepath.Join(root, "bin", "port49"),
  		append(append([]string{"revoke"}, args...), "--agent-socket", sock)...)
  	cmd.Dir = root
  	out, err := cmd.CombinedOutput()
  	code := 0
  	var ee *exec.ExitError
  	if errors.As(err, &ee) {
  		code = ee.ExitCode()
  	} else if err != nil {
  		code = -1
  	}
  	return strings.TrimSpace(string(out)), code
  }
  ```

- [ ] **Step 4: The lab test.** Create `tests/lab/api_revoke_test.go`:

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

  	"github.com/rhwendt/port49/internal/testpki"
  )

  const (
  	oncallEmail = "bob@slice.port49.test"
  	peerEmail   = "carol@slice.port49.test"
  )

  const apiRevokeClaim = "The HTTP revocation (`POST /v1/tokens/revoke`, plan 7c; spec §5.1.4, §13 decision 34) reaches " +
  	"a live SSH session as the admin socket's does, under the caller's api: rights: a peer with no right who names " +
  	"the operator is refused 403 api_right_missing and the operator's next command still runs; the operator's " +
  	"`port49 revoke --mine` refuses the open session's next command on a platform that authorizes each command (Junos " +
  	"keeps what it had at login and the report names it), refuses the unspent token token_not_found, and leaves no " +
  	"mark, so a token minted after it logs in at once, and that login re-admits the session the revocation refused, " +
  	"whose next command runs again (decision 15's join; the report says to close such a session first); a peer's key " +
  	"revocation without the right is refused 403 as well; an on-call holding revoke_others ends the operator's session by " +
  	"(device, username) with no mark, and the operator logs in again at once; and the on-call's revocation of the " +
  	"principal is a standing mark with the on-call as its origin, which ends the operator's agent until a lift."

  func TestAPIRevokeEndToEnd(t *testing.T) {
  	eachPlatform(t, func(t *testing.T, l *lab) {
  		var failed []string
  		fail := func(format string, args ...any) { failed = append(failed, fmt.Sprintf(format, args...)) }
  		sessionOnly := strings.HasPrefix(l.p.name, "juniper_")

  		pki := filepath.Join(root, slicePKIDir)
  		if err := testpki.WriteLabWith(pki, sliceEmail, []string{oncallEmail, peerEmail}, time.Now()); err != nil {
  			t.Fatal(err)
  		}
  		brokerYAML, err := os.ReadFile(filepath.Join(root, "tests", "lab", "slice", "broker.yaml"))
  		if err != nil {
  			t.Fatal(err)
  		}
  		brokerYAML = []byte(strings.Replace(string(brokerYAML), "tests/lab/slice/policy.yaml",
  			"tests/lab/slice/api-policy.yaml", 1))
  		socket := filepath.Join(root, "tests", "lab", "logs", "api-revoke-admin.sock")
  		cfg, err := l.derivedConfig("api-revoke", platformSessionAttributes[l.p.name],
  			string(brokerYAML)+"\nadmin_socket: "+socket+"\n")
  		if err != nil {
  			t.Fatal(err)
  		}
  		// … stop the lab daemon, start this one, await TACACS+, and put the lab
  		// config back on return: TestRevokeEndToEnd's block, as it is …
  		stop := l.capture(t, "api-revoke")
  		defer stop()
  		off := l.mark()

  		aliceSock, alicePID, stopAlice := personAgent(t, testpki.LabClientCert, testpki.LabClientKey)
  		defer stopAlice()
  		bobCert, bobKey := testpki.LabClientFiles(oncallEmail)
  		bobSock, _, stopBob := personAgent(t, bobCert, bobKey)
  		defer stopBob()
  		carolCert, carolKey := testpki.LabClientFiles(peerEmail)
  		carolSock, _, stopCarol := personAgent(t, carolCert, carolKey)
  		defer stopCarol()

  		// 1. A live session, and an unspent token beside it.
  		_, tok1 := l29Mint(aliceSock, l.p.node)
  		_, tok2 := l29Mint(aliceSock, l.p.node)
  		if tok1 == "" || tok2 == "" {
  			t.Fatal("alice's agent minted no token")
  		}
  		sh, err := l.shell(sliceUser, tok1)
  		if err != nil {
  			t.Fatalf("SSH login: %v\nrecords:%s", err, summarize(l.recordsSince(off)))
  		}
  		defer sh.Close()

  		// 2. The peer, with no right, names alice: refused, and her session goes on.
  		peerText, peerCode := agentRevoke(carolSock, "--via-agent", "--principal", slicePrincipal)
  		if peerCode != 1 || !strings.Contains(peerText, "needs the api: revoke_others right") {
  			fail("the peer's revocation of alice: exit %d: %s", peerCode, peerText)
  		}
  		// The key form without the right is refused too, never answered as
  		// carol's own sessions there (pre-flight I2).
  		peerKeyText, peerKeyCode := agentRevoke(carolSock, "--via-agent", "--device", l.p.node, "--username", sliceUser)
  		if peerKeyCode != 1 || !strings.Contains(peerKeyText, "needs the api: revoke_others right") {
  			fail("the peer's key revocation: exit %d: %s", peerKeyCode, peerKeyText)
  		}
  		afterPeer := revokeOutcome(l.p.name, sh, "show version", fail, "after the peer's refused revocations")
  		if !strings.HasPrefix(afterPeer, "printed its output") {
  			fail("alice's session after the peer's refused revocations: %s", afterPeer)
  		}

  		// 3. alice ends her own sessions.
  		mineText, mineCode := agentRevoke(aliceSock, "--mine")
  		if mineCode != 0 || !strings.Contains(mineText, "nothing stands against "+slicePrincipal) ||
  			!strings.Contains(mineText, "close their session on the device") {
  			fail("revoke --mine: exit %d: %s", mineCode, mineText)
  		}
  		if sessionOnly != strings.Contains(mineText, "not reached") {
  			fail("revoke --mine's report and the platform disagree on reach: %s", mineText)
  		}
  		afterMine := revokeOutcome(l.p.name, sh, "show version", fail, "after revoke --mine")
  		switch {
  		case sessionOnly && !strings.HasPrefix(afterMine, "printed its output"):
  			fail("Junos: the open session did not keep what it had at login: %s", afterMine)
  		case !sessionOnly && !strings.HasPrefix(afterMine, "refused"):
  			fail("the next command after revoke --mine was not refused: %s", afterMine)
  		}
  		if _, err := l.loginWithin(sliceUser, tok2, 60*time.Second, "show version"); err == nil {
  			fail("the token minted before revoke --mine still logged in")
  		}
  		recs := l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
  			return redeemReason(rs, sha(tok2)) != ""
  		})
  		tok2Reason := redeemReason(recs, sha(tok2))
  		if tok2Reason != "token_not_found" {
  			fail("the old token's login was refused %q, not token_not_found", tok2Reason)
  		}
  		if agentEnded(alicePID) {
  			fail("alice's agent ended on a self-revocation, which leaves no mark")
  		}
  		_, tok3 := l29Mint(aliceSock, l.p.node)
  		sh3, err := l.shell(sliceUser, tok3)
  		reLogin := "logged in"
  		if err != nil {
  			fail("a login with a token minted after revoke --mine: %v", err)
  			reLogin = "refused: " + err.Error()
  		} else {
  			defer sh3.Close()
  			if out := revokeOutcome(l.p.name, sh3, "show version", fail, "on the new login"); !strings.HasPrefix(out, "printed its output") {
  				fail("the new login's command: %s", out)
  			}
  		}
  		// The new login joined the context the old session shares and lifted its
  		// mark (decision 15): the session --mine refused runs again. This is what
  		// the report's second line warns of (pre-flight I1); recorded as found.
  		afterReLogin := revokeOutcome(l.p.name, sh, "show version", fail, "the old session after the re-login")
  		if !strings.HasPrefix(afterReLogin, "printed its output") {
  			fail("the session --mine refused did not run again after the re-login (decision 15's join): %s", afterReLogin)
  		}

  		// 4. The on-call ends alice's session on this device by key.
  		keyText, keyCode := agentRevoke(bobSock, "--via-agent", "--device", l.p.node, "--username", sliceUser)
  		if keyCode != 0 || !strings.Contains(keyText, "ended the session on "+l.p.node+" ("+sliceUser+")") {
  			fail("the on-call's key revocation: exit %d: %s", keyCode, keyText)
  		}
  		if sh3 != nil {
  			afterKey := revokeOutcome(l.p.name, sh3, "show version", fail, "after the key revocation")
  			if !sessionOnly && !strings.HasPrefix(afterKey, "refused") {
  				fail("the next command after the on-call's key revocation was not refused: %s", afterKey)
  			}
  		}
  		_, tok4 := l29Mint(aliceSock, l.p.node)
  		afterKeyLogin := "logged in and ran show version"
  		if _, err := l.loginWithin(sliceUser, tok4, 150*time.Second, "show version"); err != nil {
  			fail("a login after the key revocation: %v", err)
  			afterKeyLogin = "refused: " + err.Error()
  		}

  		// 5. The on-call revokes the principal: a standing mark, his origin.
  		markText, markCode := agentRevoke(bobSock, "--via-agent", "--principal", slicePrincipal)
  		if markCode != 0 || !strings.Contains(markText, "every mint by "+slicePrincipal+" is refused") {
  			fail("the on-call's revocation of alice: exit %d: %s", markCode, markText)
  		}
  		listText, _ := revokeCLI(socket, "--list")
  		if !strings.Contains(listText, "(api user:"+oncallEmail+")") {
  			fail("port49 revoke --list does not name the on-call as the origin: %s", listText)
  		}
  		agentSaid, agentGone, _ := revokedMint(aliceSock, alicePID, l.p.node, "the principal's", fail)
  		liftText, ok := revokeCLI(socket, "--lift", "--principal", slicePrincipal)
  		if !ok {
  			fail("the lift on the admin socket: %s", liftText)
  		}
  		sock2, _, stopAlice2 := personAgent(t, testpki.LabClientCert, testpki.LabClientKey)
  		defer stopAlice2()
  		_, tok5 := l29Mint(sock2, l.p.node)
  		liftLogin := "logged in and ran show version"
  		if _, err := l.loginWithin(sliceUser, tok5, 150*time.Second, "show version"); err != nil {
  			fail("a login after the lift: %v", err)
  			liftLogin = "refused: " + err.Error()
  		}

  		recs = l.waitForRecords(off, 60*time.Second, func(rs []map[string]any) bool {
  			return len(sliceRecords(rs, "revoke", "")) >= 6
  		})
  		bys := map[string]int{}
  		for _, r := range recs {
  			if str(r, "event") == "revoke" {
  				bys[str(sub(r, "revocation"), "by")+" "+str(r, "reason")]++
  			}
  		}
  		for _, want := range []string{"principal api_right_missing", "key api_right_missing", "self credential_revoked",
  			"key credential_revoked", "principal credential_revoked", "principal revocation_lifted"} {
  			if bys[want] == 0 {
  				fail("no revoke record %q: %v", want, bys)
  			}
  		}
  		gone := map[bool]string{true: "exited", false: "**kept running** (stopped by the test)"}
  		obs := fmt.Sprintf("| Step | What happened |\n|---|---|\n"+
  			"| carol (no right): `port49 revoke --via-agent --principal %s` | exit %d: %s |\n"+
  			"| carol (no right): `--via-agent --device %s --username %s` | exit %d: %s |\n"+
  			"| alice's `show version` after both | %s |\n"+
  			"| alice: `port49 revoke --mine` | exit %d; report below |\n"+
  			"| alice's `show version` in the same session after it | %s |\n"+
  			"| a login with a token minted before it, unspent | refused, `%s` |\n"+
  			"| a login with a token minted after it | %s |\n"+
  			"| the session `--mine` refused, after that login | %s |\n"+
  			"| bob (revoke_others): `--via-agent --device %s --username %s` | exit %d; report below |\n"+
  			"| a login after the key revocation | %s |\n"+
  			"| bob: `--via-agent --principal %s` | exit %d; `--list` names `api user:%s` |\n"+
  			"| alice's agent's next mint | %s: %s; the agent %s |\n"+
  			"| a lift on the admin socket, a new agent, a mint and a login | %s |\n\n"+
  			"Revoke records by `by` and reason: %v.\n\n"+
  			"`port49 revoke --mine` printed:\n\n```\n%s\n```\n\n"+
  			"The key revocation:\n\n```\n%s\n```\n\n"+
  			"The principal's:\n\n```\n%s\n```\n",
  			slicePrincipal, peerCode, l29Cell(peerText), l.p.node, sliceUser, peerKeyCode, l29Cell(peerKeyText), afterPeer,
  			mineCode, afterMine, tok2Reason, reLogin, afterReLogin,
  			l.p.node, sliceUser, keyCode, afterKeyLogin, slicePrincipal, markCode, oncallEmail,
  			mintRefusal(agentSaid), l29Cell(agentSaid), gone[agentGone], liftLogin, bys, mineText, keyText, markText)
  		if len(failed) > 0 {
  			obs += "\n**Not as the claim says:**\n\n- " + strings.Join(failed, "\n- ") + "\n"
  		}
  		l.result(t, "api-revoke", apiRevokeClaim, obs)
  		if len(failed) > 0 {
  			t.Fatalf("%d step(s) not as claimed (the note records them): %v\nrecords:%s", len(failed), failed, summarize(recs))
  		}
  	})
  }
  ```

  Two parts are written out by copying, not referenced. The daemon block in the middle is
  `TestRevokeEndToEnd`'s, from `if err := l.stopDaemon()` through its `defer` that puts the lab
  config back. Write it out in full here. `l.capture`'s stop must run before the note is written,
  as `TestRevokeEndToEnd` arranges with its session close and accounting wait; copy that block
  too.

  `revokedMint`'s fourth argument names what was revoked, for its failure lines. `agentEnded` is
  7a's 10-second wait for a pid to exit: here it must say **no**, and it is asked right after the
  self-revocation. `agentRevoke` runs `port49 revoke` with no terminal on stdin, so
  `--via-agent --principal` asks nothing (Task 12).

- [ ] **Step 5: Compile it without the lab.**

  Run: `go vet -tags lab ./tests/lab/ && make build && make test && make vet`
  Expected: PASS.

- [ ] **Step 6: Commit the harness.**

  ```bash
  gofmt -w internal/testpki/testpki.go internal/testpki/testpki_test.go tests/lab/revoke_test.go tests/lab/api_revoke_test.go
  git add internal/testpki/testpki.go internal/testpki/testpki_test.go tests/lab/revoke_test.go \
    tests/lab/api_revoke_test.go tests/lab/slice/api-policy.yaml
  git commit -m "test(lab): the HTTP revocation's three shapes end to end

  A peer with no right, by principal and by key; a self-revocation, its re-login,
  and the old session's state after it; an on-call's key revocation and principal
  revocation, on the four images 7a measured; results to
  tests/lab/results/api-revoke-<platform>.md.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

- [ ] **Step 7: Run it on beehive** ("Running the lab", above). Pin the worktree to Step 6's
  commit, start the stall watchdog, and run:

  ```bash
  PORT49_LAB_PLATFORMS=eos    go test -tags lab -run TestAPIRevokeEndToEnd -timeout 60m -v ./tests/lab/
  PORT49_LAB_PLATFORMS=nxos   go test -tags lab -run TestAPIRevokeEndToEnd -timeout 60m -v ./tests/lab/
  PORT49_LAB_PLATFORMS=iosxe  go test -tags lab -run TestAPIRevokeEndToEnd -timeout 60m -v ./tests/lab/
  PORT49_LAB_PLATFORMS=vjunos go test -tags lab -run TestAPIRevokeEndToEnd -timeout 60m -v ./tests/lab/
  ```

  Use the variable and the platform names `TestRevokeEndToEnd`'s 7a run used, if they differ.
  After each platform, check that no `port49d` holds `172.100.100.1:49`, that no agent runs, and
  that the topology is destroyed.

  **If a step fails:** the note records it under "Not as the claim says". Stop and diagnose it
  (`superpowers:systematic-debugging`) before any fix. A result that contradicts the spec makes the
  spec wrong (lab rule 4): fix the doc in Task 14, citing the note.

- [ ] **Step 8: Commit the results.** In the lab worktree, run `make evidence` so the `.pcap`
  evidence is cut from the raw captures. Copy `tests/lab/results/api-revoke-*.md` and
  `tests/lab/evidence/api-revoke-*.pcap` into the feature branch's worktree, and the raw captures
  into the main checkout's `tests/lab/captures/`. Commit on the feature branch, the message body
  saying for each platform PASS or what differed, with its image version:

  ```bash
  git add tests/lab/results/api-revoke-*.md tests/lab/evidence/api-revoke-*.pcap
  git commit -m "test(lab): the HTTP revocation on vEOS, the N9Kv, the C8000V and vJunos-router

  vEOS 4.31.2F: PASS. N9Kv 10.4(2)F: PASS. C8000V 17.13.01a: PASS.
  vJunos-router 23.4R2-S2.1: PASS (the open session kept what it had; named not reached).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

  Write what the run found, not this example: a platform that did not pass says what differed.

---

### Task 14: Plan 7c as built

**Files:**
- Modify: `docs/superpowers/plans/README.md` (the status line; "Plan 7c — As built" after "Plan 7b —
  As built"; the Plan 7c bullet; "Carried, for later plans")
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`, `docs/design/2026-08-21-port49-design.md`,
  only where Task 13's notes contradict them (lab rule 4)

- [ ] **Step 1: Check the lab against the docs.** Read each `tests/lab/results/api-revoke-*.md`.
  Where a note contradicts §5.1.4's "Over HTTP, as built" or decision 34, fix the doc, cite the
  note, and say so in the commit message (lab rule 4). This plan closes no register row and opens
  none.

- [ ] **Step 2: Write "Plan 7c — As built"** in the roadmap, after "Plan 7b — As built", in its
  form:
  - task by task, what differs from this plan's text, with commits;
  - the rulings as made (decision 34), with any amendment;
  - the lab, platform by platform, citing each note;
  - the operator notes, from "Operator-facing notes" below, amended by what was built;
  - "Carried, for later plans". At least:
    - **7d**: `storetest.DeleteTokenRemovesOne` for the etcd backend; the self-revocation's
      compare-and-set on the backend's `SetContextPolicy`.
    - **7e**: `/healthz` and `/readyz` on the broker's own process; the revocations file's init in
      the broker's deployment, run once at install and never on a start path; a reload guard at
      start, against the last bundle in force, so a restart cannot load a file the guard refused
      (pre-flight I4).
    - **7g**: rights held through a group subject.
    - **7h**: `/v1/tokens/revoke` by `sid`; `/v1/logout`.
    - **12**: the deployment's `port49d init-revocations` step: once, at install, by hand or as a
      one-off job, as port49d's user, and never in an init container or `ExecStartPre=` (a
      tolerated failure there re-creates the file on the next empty volume, the hazard decision
      32's amendment removes); the small-fleet note on the reload guard; the guard at start, as
      for 7e.
  - Under "Unassigned follow-ups": a bulk lift (`port49 revoke --lift --origin "api <principal>"`),
    so recovery from a mass revocation by a compromised `revoke_others` certificate is one command,
    not one lift per victim (pre-flight M19; the shell loop in the operator notes until then).

  Update the status line ("**7c written 2026-10-02** …") with executed, reviewed and merged as
  they happen, and the "Plan 7c" bullet with "As built" pointing at the section.

- [ ] **Step 3: Commit.**

  ```bash
  git add docs/superpowers/plans/README.md
  # plus the spec and design, by path, if Step 1 changed them
  git commit -m "docs: plan 7c as built

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

## Operator-facing notes (for the pull request body)

For plan 13's docs. Amend these with what was built before the pull request is opened.

- **Breaking: port49d no longer creates `broker.revocations_file`.**
  - **First install.** Run `sudo -u port49 port49d init-revocations --config
    /etc/port49/port49d.yaml` once, as the user port49d runs as (the owner of the file's
    directory). Run as anyone else, root included, it refuses and names that user: a root-written
    0600 file is one port49d cannot read. It reads only that path from the config, so no secret
    needs to be in the environment, and it refuses a path that is another file port49d uses. Give
    `broker.revocations_file` an absolute path; a relative one draws a warning.
  - **Once, at install, never on a start path.** Run it by hand or as a one-off job. Do not put it
    in an init container or an `ExecStartPre=`: wrapped to tolerate its refusal there, it would
    re-create the file on the next empty volume, the very hazard this change removes. Run again,
    it exits 0 (`already initialized; nothing written`) when the file is there and loads, so an
    idempotent provisioning step needs no `|| true`.
  - **What a start does.** A missing file refuses every start, so an unmounted or empty volume can
    never start port49d with no revocations. The message leads with mounting the volume.
  - **Upgrading.** An install that already has the file changes nothing; a start still writes the
    marker beside it if it has none.
  - **After a loss.** If the file is lost, restore it from backup. `init-revocations` refuses over
    a marker it left (exit 1), and `{"revocations": []}` written by hand is the deliberate way to
    start empty.
- **Upgrade: agents started before this release.** An agent lives for `max_session_age`, and one
  started by the old `port49` has no `identity`, `explain` or `revoke` route. The new CLI says
  `your agent (started before this port49) does not carry this command; run 'port49 login' again`.
- **New: `port49 identity`.** It prints whom the broker resolves you to: subject, grants
  (unexpired, by scope), `api:` rights, and until when this connection lasts
  (`connection_ends_at`, `max_session_age` from the authentication); a device's own session
  ceiling may end a session sooner. `--json` prints the broker's answer. Each call writes an
  `identity` record, so do not put it in a shell prompt.
- **New: `port49 explain` without `--policy`/`--inventory`.**
  - **What it does.** It asks the broker through your agent, from the policy in force, and prints
    what the offline form prints, redacted. For a denied command it names every role in the policy
    that would permit it (what to ask for), never who holds one.
  - **Another principal.** `--principal` naming someone else needs `api: [explain_others]`.
  - **Offline only.** `--subject` and `--show-attributes` stay the offline form's.
  - **Dashboards.** `explain` records carry hypothetical verdicts: a panel of denials, or of
    `port49_decisions` with `verdict="deny"`, should filter `event!="explain"`.
- **New: `port49 revoke --mine`.**
  - **What it does.** It ends your own live sessions and deletes your unspent tokens (one device
    with `--device` and `--username`), and your receipts everywhere.
  - **No lock.** It leaves no mark: `port49 token` and a login work at once after it. Use it when
    a token leaked.
  - **Close a stranger's session first.** Your next login on a device re-admits every session open
    there under your username, a stranger's on your leaked token included. If anyone else used
    your token, close their session on the device, or ask an operator to revoke your principal,
    before you log in there again. The report says so.
  - **Junos sessions** keep what they had at login and are named in the report; close them on
    the device.
- **New: `port49 revoke --via-agent --principal P`** (needs `api: [revoke_others]`).
  - **What it does.** It is the admin socket's revocation, from your laptop, through your agent.
    On a terminal it asks `[y/N]` first (`--yes` skips it), and it prints `target: P (subject …)`,
    so a typo of a real colleague's address is seen at once.
  - **The record.** `port49 revoke --list` and the `revoke` record name you as `origin: api
    <you>`.
  - **Lifting** stays the admin socket's, as does `--cert`; the report names the socket. With no
    `admin_socket` configured, the mark is still made, the report and port49d's start line say so,
    and lifting it needs port49d stopped, the entry removed from `broker.revocations_file`, and a
    start.
  - **Watch for a burst.** Alert on `rate(port49_revocations_total{by="principal",outcome="applied"}[5m])`
    above your normal: a compromised `revoke_others` certificate can mark every human. Revoke that
    certificate on the admin socket, then lift its marks; until a bulk lift exists:

    ```
    port49 revoke --list | awk '$1 == "principal" && /\(api user:oncall@example\.com\)$/ {print $2}' |
      while read -r p; do port49 revoke --lift --principal "$p"; done
    ```
  - **Busy.** If another revocation or lift holds the slot for 10 s, the answer is `503
    revocation_busy` and nothing was revoked; run it again.
- **New: `port49 revoke --via-agent --device D --username U`** (needs `api: [revoke_others]`).
  - **What it does.** It ends whatever holds that key, with no mark, so the owner can log in again;
    revoke the principal to stop that. The owner's next login there re-admits any session still
    open on it: close it on the device.
  - **Without the right** it is refused 403, never narrowed to your own sessions there. For your
    own session on one device, use `--mine --device D --username U`.
  - **Not in `--list`.** A self or key revocation leaves no mark, so `--list` does not show it; it
    says so on stderr, and the decision log's `revoke` records (`revocation.by` `self` or `key`)
    name each.
- **`api:` rights now mean something.**
  - **What they unlock.** `revoke_others` and `explain_others` act on other people. `sync`,
    `keys_show` and `replay` are reserved and grant nothing yet.
  - **What no right does.** No right lets anyone mint or refresh for another principal.
  - **The gate.** A right gained fails `port49 policy diff` unless a test asserts the subject's
    whole `api:` list, as before. Every subject with `api:` is in the CI report.
- **New: the policy reload guard.**
  - **What is refused.** A policy edit that would take more than `inventory.max_removed_percent`
    (default 10) of the devices in service out of service, by refusing admission or by
    quarantining, is refused. `port49_policy_file_refused` goes to 1, and the policy in force keeps
    serving. The line names each device and cause, redacted.
  - **The refused file is still on disk.** A restart (pod rescheduled, crash, next deploy) loads it
    with no bound and takes those devices out of service. Revert or fix it at once; the line says
    so.
  - **Small fleets.** One quarantined device of three is 33%. Raise the bound and send `SIGHUP`
    for a deliberate change, then lower it again: the same bound holds inventory syncs.
  - **A refused edit keeps any grant it withdrew.** `port49 revoke` cuts a principal off whatever
    the file says.
  - **What is never refused.** A reload after which at least as many devices are in service as
    before, such as an incident fix that releases many and quarantines a few.
- **New broker endpoints.**
  - `GET /v1/identity`, `POST /v1/explain` and `POST /v1/tokens/revoke`, each authenticated as
    `/v1/tokens` is.
  - `GET /healthz` and `GET /readyz`, with no certificate. `/readyz` is `200 serving` while the
    broker serves, and stays 200 through a store outage, by design (design §12); watch the alarms.
  - **New API errors:** `403 api_right_missing`; `503 revocation_busy`.
- **New records.**
  - `identity permit grants_matched` and `identity deny no_grants_matched`.
  - `explain <the answer>`, with `explain.asked_by` and `explain.asked_by_fingerprint`, the
    `policy.bundle` that answered, and never the command.
  - `revoke deny api_right_missing`, naming the target (or the key) and the caller in `origin`.
  - `revoke` with `by: self` or `by: key`, `device` and `username`, and `origin: api <principal>`.
  - A record about someone other than the caller carries no `auth`: `auth` and `principal` always
    describe one credential, so a join of fingerprint to principal stays true.
  - A call refused before it is read, or as its connection binds, is recorded under its own
    event, with the mint's reasons.
- **Metrics.** `port49_revocations_total{by}` gains `self` and `key`. `port49_decisions` counts the
  new events.

## Self-review against the spec

- **Design §17, "by default a principal acts only on itself":**
  - mint: Task 4's test;
  - revoke: Tasks 7 and 8;
  - explain: Task 9;
  - identity: Task 4;
  - refresh: Task 4's test, Ruling 1.
- **Design §17 surface:** `/v1/tokens/revoke` (Task 8), `/v1/identity` (Task 4), `/v1/explain`
  (Task 9), `/healthz` and `/readyz` (Task 5). `/v1/logout` and `sid` are plan 7h's, refused 400 by
  Task 8.
- **Design §17, "Every call is a decision record":** Ruling 4; Tasks 4, 8 and 9 record every
  authenticated call, refusals included. `/v1/config` and the probes are unauthenticated and
  record none, as before.
- **Design §17, "Errors are typed, and never leak fleet data":**
  - explain on an unknown device (Task 9, Review Focus 3);
  - identity lists scopes, never devices (Task 4);
  - a peer's key revocation is refused 403, and its own form on the key (`mine`) reaches and reports
    nothing of another's (Task 8);
  - store errors reach the process log, not the caller (Task 8).
- **Design §12, readiness:** Ruling 7; Task 5's test with a store that fails every call.
- **Spec §2 rights table:** every right is ruled (Ruling 1, Task 1 Step 2); `HasRight` (Task 3).
- **Spec §5.1.4 and decision 32:**
  - the standing mark is 7a's `Broker.Revoke`, unchanged (Task 8);
  - decision 32 is amended first (Task 1 Step 1);
  - the init (Task 2).
- **Spec §5.7:**
  - the reason and the two events are in the spec (Task 1) before the code (Task 3);
  - no other reason is added: an explain's answer reuses the vocabulary, and an API refusal
    before the body uses the mint's reasons.
- **Spec §14, API rights:** Tasks 7, 8 and 9 assert each clause but `/v1/logout` (plan 7h).
- **Roadmap, 7a carried:** the HTTP revocation over `Broker.Revoke` (Task 8); self-revocation's
  shape (Ruling 2, Task 7); the revocations volume (Ruling 9, Tasks 1 and 2).
- **Roadmap, 7b carried:** the HTTP revocation (Task 8); `api:` rights over `RefreshSession`'s
  self-only rule (Ruling 1, Task 4's test).
- **Roadmap, 4b:** the candidate reload guard, weighed and ruled on (Ruling 8, Task 10).
- **Lab rules:** no device claim without a note. The device behaviour rests on 7a's `revoke-*.md`;
  the HTTP shapes get `api-revoke-*.md` (Task 13); no register row opens or closes.
- **Placeholder scan:** Tasks 2, 13 and 14 carry instructions that name code to carry over rather
  than restate. Each says what to copy and from where:
  - `loadRevocations`' unchanged parse loop;
  - `WriteLabWith`'s body;
  - `TestRevokeEndToEnd`'s daemon and capture blocks;
  - Task 14's as-built text, which only the execution can write.
- **Type consistency:** these names are used in more than one task, and match:
  - `authenticate(w, r, event, nothing)`;
  - `RefusedAtBind(path, principal, cred, reason)` (Task 4; port49d and `cmd/port49`'s test assign
    the method value);
  - `RevokeOwn(ctx, principal, *store.TokenKey, origin)`, `RevokeKey(ctx, store.TokenKey, origin)`;
  - `ByOwn`/`ByKey` = `self`/`key`; `RevokeReport.LiftNote` (Task 7) set by Task 8;
  - `refuseRight(w, rec, right, what)` (Task 8, used by Task 9);
  - `api.RevokeRequest{Mine, Principal, Device, Username, Sid}`; `api.RevokeResponse.Subject`
    (Task 8, printed by Task 12);
  - `api.Identity.ConnectionEndsAt` / `connection_ends_at` (Task 4, printed by Task 12);
  - `decision.Explain.AskedByFingerprint` (Task 3, set by Task 9);
  - `api.ExplainResponse.Text`;
  - `initRevocations(path) (created bool, err error)` (Task 2, called by `brokerConfig`);
  - `CheckAdmission(old, new, max, now)`;
  - `agent.ErrAgentTooOld`, `agent.APIError` (Task 11, read by Task 12).
