# Plan 7a: Revocation That Reaches Everything, and a Broker Listener One Client Cannot Fill — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the security debts plans 2 and 3 carried into plan 7 that need no shared-store
backend. Two concurrent requests under one `Idempotency-Key` can no longer both mint: the broker
reserves the key for every device of a batch, atomically, before its first mint. The broker's
listener completes each TLS handshake itself, counts every failure by reason, resets a source that
holds too many connections not yet authenticated, and closes a principal's oldest held connection
when it opens one too many, so neither one address nor one certificate can lock other operators
out of `port49 login`. And a revocation by principal or by certificate reaches everything: a
standing mark refuses every mint it names, checked before and after the mint's token writes; the
held broker connections it names are closed; live contexts are marked; receipts are deleted; and
unspent tokens are deleted through a new token index (plan 2's "largest remaining hole in
revocation"). An operator revokes and lifts with `port49 revoke` over the admin socket, the marks
survive a restart in `broker.revocations_file`, and every revocation is one `revoke` record naming
the live contexts it could not reach. A lab run takes a revocation end to end on four images.

**Architecture:** The store interface gains three groups of methods, each with a `storetest`
property every backend must pass (plan 7d builds the shared backend; this plan builds the memory
store's and the sealing layer's): the idempotency reservation (`ReserveIdempotency`,
`CompleteIdempotency`, `ReleaseIdempotency`), the token index (`IndexToken`, `TokensByPrincipal`,
`TokensByCert`) and the revocation marks (`PutRevocation`, `GetRevocation`, `DeleteRevocation`,
`ListRevocations`). The minter reserves a batch's key (`Minter.Reserve`) and indexes every token
before writing it. A new `broker.Listener` sits between `broker.Limit` and `http.Server`: a
background loop accepts, admits by source, handshakes under the broker's TLS config with a
deadline, binds the connection to its principal, and hands `http.Server` only connections whose
handshake is done; it is also the registry a revocation closes held connections through. The
broker gains `Revoke` and `Lift`, a mark check at mint, a `revoke` decision event and a
`revocation_lifted` reason (spec §5.7, edited first). `port49d` loads the marks from
`broker.revocations_file` at start, writes them after every change, and answers two new admin
socket operations, which `port49 revoke` sends.

**Tech Stack:** Go 1.22 (the module's `go` line: `min`, `max`, `context.WithoutCancel` and
`slices` are available; range-over-func and `maps.Keys` iterators are not), the standard library
(`crypto/tls`, `net`, `net/netip`, `net/http`), `prometheus/client_golang` (already a
dependency). containerlab on the lab host (beehive) for Task 12. **No new module dependencies.**

**Spec:** `docs/design/2026-08-23-policy-engine-spec.md` §5.1.4 (credential identity and
revocation), §5.6 (teardown row 2, "Where these controls do not reach"), §5.7 (events, reason
codes), §12 (tooling), §13 decisions 15, 17, 21 and the new 32. Design
`docs/design/2026-08-21-port49-design.md` §7 (the certificate path's held connection), §11
(listener limits, "per source before global"), §12 (the store record table; failure matrix), §17
(idempotency, write-once, internal interfaces), §19 step 7. Roadmap
`docs/superpowers/plans/README.md`, "Plan 7" (its carried items and the split into 7a–7h), "Plan
2" ("Owed by plan 3 or plan 7"), "Plan 4b" ("Hands to plan 7").

**Prerequisite:** plan 6c merged (PR #19, `888b1d5`; `main` at `7d32a91`). Branch
`feature/revocation-and-broker-limits` off `main` at the commit that adds this file.

## What this plan does not do

- **No shared store.** Which backend plan 7d builds is Decision D1 (roadmap, "Plan 7"), the owner's
  to make. Nothing here depends on it: every new store method is added to the interface, the memory
  store and the sealing layer, with a `storetest` property the chosen backend must pass.
- **No HTTP revocation and no `api:` rights.** `POST /v1/tokens/revoke`, self-only by default, is
  plan 7c's, over this plan's `Broker.Revoke`. Here revocation is an admin-socket operation.
- **No CRL, OCSP or OIDC logout.** They arrive in plans 7b and 7h as marks of the kind this plan
  builds.
- **No change to the policy refresh.** A refresh never lifts a mark (unchanged), and its records
  gaining the `unreached` field the `revoke` record carries is plan 7b's.
- **No global connection cap.** `broker.MaxConns` (256) stays the only global cap, as plan 12
  carries for the TACACS+ listener.

## Rulings where the design is silent

Each takes the option that denies more, is written into the tasks named, and is recorded in spec
§13 as decision 32 by Task 1. None needs an owner decision.

1. **A batch reserves its key for every device before its first mint.** `Minter.Reserve` writes a
   pending record per device (`idemScope(key, device)`), put-if-absent. A record under another body
   refuses the whole batch `409 idempotency_conflict`; a pending one under the same body refuses it
   `409 idempotency_in_progress` (`Retry-After: 1`), and nothing is minted for either; what this
   request had reserved is released. A completed record under the same body is replayed, as today.
   A reservation lives `token.ReservationTTL` (1 minute; a mint's store calls are bounded at 10 s by
   `holdTimeout`), and is completed with the response or released when its device is refused, by
   its holder and no other (`CompleteIdempotency` is a compare-and-set on the holder). A batch that
   names a device twice is refused `400 bad_request`. The agent waits out `in_progress`, retrying
   the same key once a second for up to 15 s. Tasks 2, 3.
2. **The listener completes each TLS handshake itself, within 10 s, and counts every failure by
   reason:** `untrusted_chain` (the anchor did not verify the client's chain, expiry included),
   `identity_refused` (the chain verified and `Identity` refused it), `server_cert_refused` (the
   client refused the broker's certificate), `timeout`, `client_closed`, and `protocol` (anything
   else, plain HTTP included), in `port49_broker_tls_handshake_failures_total{reason}`. One process
   log line per reason per 10 s names the source and the error, cut and made printable; the next
   line says how many it held back. Task 6.
3. **Per source, before per principal, before global** (design §11's rule). A source address holds
   at most `broker.max_pending_conns_per_source` (default 16) connections not yet bound to a
   principal: handshaking, or certificate-less for `/v1/config`. The next is reset at accept,
   counted (`event="source_cap_refused"`) and said. A principal holds at most
   `broker.max_conns_per_principal` (default 4) held connections; a new one closes that principal's
   **oldest connection of the same certificate** if it holds one past the cap, and otherwise its
   oldest (`event="principal_cap_evicted"`), so a flood from one certificate churns its own slots
   and never its owner's other certificate (pre-flight I3). Never refusing the newest is the 3am
   choice: a laptop that slept four times holds four dead connections until `max_session_age`, and
   refusing the fifth would lock its owner out. One certificate can then hold four slots, not 256.
   Two limits are accepted and said: a source is one address, so an IPv6 client rotating within its
   /64 is a new source per address (M14); and the global cap (`Limit`, 256) is taken before the
   per-source check, so at global saturation new connections wait in the kernel backlog rather than
   being reset per source (M15). Plan 12 owns the global cap. Task 6.
4. **A revocation is a standing mark, and it stands until an operator lifts it.** A principal's
   mark refuses every mint by that principal, on any connection and with any certificate; a
   certificate's, every mint made with it. It does not expire: the agent reconnects on its own with
   the same key file, so a mark that a fresh handshake or a clock could outlive would be undone
   without anyone acting. The operator lifts it with `port49 revoke --lift`. A principal is
   normalized as `Identity` spells it (`user:` and the lower-cased email) and one without a known
   prefix is refused; a mark that no subject in the policy in force names, or that reaches nothing,
   is still written (deny more) but its output warns first that the spelling may be wrong
   (pre-flight I2). Tasks 5, 7, 8.
5. **The mark is written first, then everything it names is reached**, in this order (pre-flight
   I1): held broker connections closed; **unspent tokens deleted** through the token index; live
   contexts marked and receipts deleted (`session.Manager`); then **a second context pass** that
   re-reads the context index and marks anything a redemption wrote between the first pass and the
   token delete. Tokens go before contexts because a token redeemed on a device with no live context
   writes a fresh, unrevoked context (the `session` package comment's hole); the second pass catches
   a redemption already in flight. What remains, a context written after the second pass from a
   token removed before the delete, is a window of one redemption's store round trip, named in the
   `session` comment as plan 7d's to close atomically. A mark that cannot be written revokes nothing
   and says so, naming the fallback (remove the principal's grants from `broker.policy_file`, live
   within two watch intervals, or stop port49d); a later step that fails leaves the mark in force, is
   named on the record and in the output, and the command can be run again, repeating every step.
   The listener is told of every mark (`Revoked`), and a connection whose certificate or principal is
   marked is closed when it binds, counted `revoked_refused`, without a store read at the handshake.
   Task 8.
6. **A mint reads the marks before anything else and again after its last token write**, and a
   mark that appeared in between deletes what the mint wrote and answers `credential_revoked`. The
   revocation writes its mark before it reads the token index; the mint writes the index before the
   tokens and reads the mark after them: whichever reads the other's write, no token minted under a
   revoked credential survives. A store error on the first read refuses the mint `store_unavailable`;
   on the second it refuses the mint and leaves the tokens it wrote (never returned to anyone, so
   unusable, and found by any revocation's own index pass) rather than delete every token under the
   key, an earlier mint's included (M7). Task 7.
7. **Every token is indexed by principal and by certificate before it is written**, and a mint
   whose index write fails is refused (`store_unavailable`): an unindexed token is one no revocation
   can find. Task 4.
8. **The marks are persisted in `broker.revocations_file`**, required with a `broker:` block,
   written atomically at 0600 after every change, and read behind the write fence at start
   (`fence.ReadNoLink`). Its directory is fenced whether or not the file exists (`fence.CheckDir`),
   and a missing directory refuses the start. "Never written" is told from "deleted" (pre-flight
   C1): at the first start, with the directory fenced and neither the file nor its marker
   `<revocations_file>.created` present, port49d writes the marker and then `{"revocations": []}`,
   and says so loudly (`created … (no revocations); if this is not a first install, stop port49d and
   restore the file`); on every later start, the marker present, a missing file refuses the start
   (`restore it, or write {"revocations": []} on purpose`). The residual is a whole directory lost
   with its marker (a volume that did not mount over an empty mount point), which reads as a first
   install; the start line is what says so. A file that does
   not parse refuses the start too, since a port49d that forgot a revocation would mint for a stolen
   certificate again; devices then find port49d unreachable, as with port49d stopped. A write that
   fails leaves the mark in force, says so (`port49_revocations_file_failed` is 1), and is retried
   by the next change or a repeat of the command. The file may not be any other path port49d reads
   or writes (compared as absolute paths, M13). Tasks 9, 10.
9. **Revocation is an admin-socket operation.** `port49 revoke` asks over `admin_socket` (0600,
   `SO_PEERCRED`, port49d's user and root: plan 6a owner decision 2), the same people who can
   already rewrite the policy file and cut anyone's access within seconds, so it grants no new
   power. The record names the uid that asked. The admin socket stays off by default (plan 6a owner
   decision 2); with a `broker:` block and no `admin_socket`, port49d says at start that `port49
   revoke` is unavailable and names the live fallback (M20). Tasks 10, 11.
10. **The store's marks are read at mint, not at the TLS handshake.** `port49 login` touches no
    store (design §12's failure matrix: "Token store unavailable — New session ✓"). The listener
    holds an in-memory copy of the marks (Ruling 5), so a revoked operator's `port49 login` is
    refused at the agent's first request: the listener completes the handshake, answers `401
    credential_revoked` with the mark's time, records a `mint deny credential_revoked`, and closes,
    which ends the agent's session with the broker's detail. A mark that lands after the agent's
    connection bound refuses its next mint the same way. Task 7; fixA.
    *Revised 2026-10-01 after the Task 12 lab (fixA; spec §13 decision 32 amended, citing
    `tests/lab/results/revoke-*.md`). As first written, a revoked operator's login succeeded and was
    refused at its first mint, and the listener closed a marked connection at bind unanswered (Ruling
    5), which on three of four images left the agent running.*

**One event and one reason are added** (spec §5.7, by Task 1 before any code): the event
`revoke`, `deny credential_revoked` for a revocation and `permit revocation_lifted` for a lift; and
`credential_revoked` gains its `mint` meaning. No other reason code is added.

## Decisions for Ryan

**None for this plan.** Decision D1, the shared store's backend, is plan 7d's and is set out with a
recommendation in the roadmap's "Plan 7" section; this plan is ordered before it on purpose and
builds nothing that depends on it. Whether `admin_socket` should default on when a `broker:` block
is present is plan 6a owner decision 2's to revisit; this plan leaves it off and says so at start
(M20).

## Revised after the pre-flight review (2026-10-01)

The pre-flight review
(`.superpowers/sdd/2026-10-01-07a-revocation-and-broker-limits/preflight-review.md`) found one
critical, seven important and twenty-three minor problems. Each is fixed below with the review's
fix unless the line says otherwise; one minor is rebutted. The task text carries every fix.

- **C1** (a missing file or directory read as "no revocations", bypassing the fence): Ruling 8;
  Task 9 adds `fence.CheckDir`, the first-start creation with a marker, and four tests.
- **I1** (contexts marked before tokens deleted): Ruling 5; Task 8 reorders to tokens, contexts,
  then a second context pass, with a gated-store test; Task 1's spec text and decision 32 say so;
  the residual window goes into the `session` package comment.
- **I2** (an unnormalized principal reads as success): Ruling 4; Task 8's `normal()` lower-cases
  after `user:` and refuses an unknown prefix; `Revoke` warns when no subject names the principal
  or nothing was reached.
- **I3** (a revoked certificate evicts its owner): Rulings 3 and 5; Task 6 evicts by certificate
  first and holds a mark set (`Revoked`); Tasks 8 and 9 feed it.
- **I4, I5, M18** (the lab test): Task 12 polls for the agent's exit, stops only a running agent,
  requires `token_not_found` on the old token's login, and waits for two records.
- **I6** (the lab file in a group-writable directory): Task 9 makes `privatePolicy` rewrite
  `revocations_file` into the private directory; Task 12 drops its `os.Remove`.
- **I7** (no run-level restart test): Task 9 adds `TestRunRestoresRevocationsBeforeTheBrokerServes`
  with a marked file, a corrupt file, and a directory others can write.
- **Minors:** M1 (fingerprint prefix) Task 7; M2 (`TestIdempotentReplay`) Task 3; M3 (imports)
  Task 11; M4 (race) Task 11; M5 (an abandoned replay is taken over by compare-and-set, or
  `in_progress`) Task 3; M6 (the index outlives its token by a minute) Task 4; M7 (a failed
  post-check leaves the tokens) Ruling 6, Task 7; M9 (the lift's unsaved wording) Task 8; M10
  (`port49 revoke` exits 3 on a partial or unsaved result, from `admin.Response.Partial`) Tasks 10,
  11; M11 (the fallback named) Task 8; M12 (no panic path: `Revoke` errors without `Sessions`, the
  admin handler recovers) Tasks 8, 10; M13 (more paths, absolute) Task 9; M14, M15 (limits said)
  Ruling 3; M16 (a negative serial) and M17 (colons) Task 8; M19 (a matrix row) Task 1; M20 (a start
  line) Task 10; M21 (wrapped anchors) Task 1; M22 (thrashing) operator notes; M23 (the serial shown
  as compared) Task 8.
- **M8 rebutted:** a certificate revocation that finds no live context leaves a receipt, but with no
  live context a retransmission is answered `token_spent`, not replayed (spec §5.6: a receipt
  replays only while its `ctx_id` is the live context's), so the receipt replays nothing; said in
  `Revoke`'s comment.

## What the operator sees

The owner's rule is to trace a mechanism on a bad day first.

- **Normal day:** port49d says at start `port49d: broker: 0 revocation(s) in force from
  /var/lib/port49/revocations.json` and `port49d: broker listening on 10.0.0.5:8449`. Operators log in
  and mint as before. `port49_broker_connections{state="held"}` is the number of agents connected.
- **3am, a laptop is stolen:** `sudo port49 revoke --principal user:alice@example.com` prints

  ```
  revoked user:alice@example.com at 2026-10-02T03:12:09Z: 3 live context(s) marked, the unspent
  tokens under 2 (device, username) key(s) deleted, 1 held broker connection(s) closed; every
  mint by user:alice@example.com is refused until `port49 revoke --lift --principal
  user:alice@example.com`
  not reached, on a platform that never asks port49 about a command (close these on the device):
  edge-mx01 (alice)
  ```

  Her next command on an EOS, NX-OS or IOS-XE session is refused (`credential_revoked`, `port49:
  this session was revoked - log in again`). The Junos shell keeps what it had at login, which is
  why the line names it. The thief's agent reconnects and is answered `credential_revoked` as its
  connection binds, which ends it (Ruling 10, revised). In the
  morning, once her CA has revoked the stolen certificate and issued a new one: `port49 revoke
  --cert stolen.pem` (or `--cert-issuer` and `--cert-serial`), then `port49 revoke --lift --principal
  user:alice@example.com`, and she logs in with the new certificate.
- **A revocation runs into a store error part-way:** the mark is in force and the output ends
  `incomplete: …; the mark is in force — run the same command again, which repeats every step`.
  `port49_revocations_total{outcome="partial"}` counts it.
- **The revocations file cannot be written (disk full, a read-only mount):** `NOT saved to
  broker.revocations_file (…): the revocation is in force now, and a restart of port49d forgets
  it`; `port49_revocations_file_failed` is 1 until a later write succeeds. Fix the disk, then run
  `port49 revoke --list` and repeat the revocation, which writes the file again.
- **Someone edits or corrupts the revocations file:** port49d refuses to start, naming the file and
  the fault; a file another user could write, or a directory another user could write, is refused by
  the fence like the policy file. **The file goes missing** (deleted, or a volume that did not
  mount): port49d refuses to start (`… is missing; port49d will not start without the revocations
  it held: restore it, or write {"revocations": []} on purpose`). Either way devices find port49d
  unreachable and break-glass works as with port49d stopped. Restore it from backup, or write
  `{"revocations": []}` on purpose and revoke again.
- **First install:** `port49d: broker: created /var/lib/port49/revocations.json (no revocations);
  if this is not a first install, stop port49d and restore the file`.
- **A revocation names a principal no subject names** (a typo, a missing `user:`, an address in
  capitals): the output begins `no subject in the policy in force names user:alce@example.com; the
  broker spells a certificate's principal user:<lower-case email>, so check the spelling`. Capitals
  are lowered for you; a principal without `user:` is refused.
- **A store write fails at the mark:** `the revocation could not be recorded, so nothing was revoked
  …; remove the principal's grants from broker.policy_file (live within two watch intervals), or
  stop port49d`.
- **A thief keeps opening connections with a revoked certificate:** each is closed as it binds
  (`event="revoked_refused"`), and the owner's renewed certificate keeps its connection.
- **`admin_socket` is not set:** port49d says at start `port49d: broker: port49 revoke is
  unavailable: set admin_socket; until then, cut someone off by removing their grants from
  broker.policy_file`.
- **The certificate's issuer is typed in another spelling:** the output says `nothing was found
  under this certificate; if it is in use, its issuer is likely spelled differently from the broker's
  (RFC 2253, as Go prints it: CN=Corp Issuing CA,O=Example): use --cert FILE`. The mark stands,
  harmlessly, until lifted.
- **A client floods the broker from one address:** after 16 connections not yet authenticated, the
  rest are reset at accept; `port49d: broker: reset a connection from 192.0.2.7: it holds 16
  connections not yet authenticated (broker.max_pending_conns_per_source)`, once per 10 s, and
  `port49_broker_connection_events_total{event="source_cap_refused"}` climbs. Logged-in operators,
  bound to their principals, are not counted against the source.
- **An agent's `--broker-ca` is wrong, or the broker's certificate expired:**
  `port49_broker_tls_handshake_failures_total{reason="server_cert_refused"}` climbs, and one line per
  10 s names a source. **A user's certificate expired:** `reason="untrusted_chain"` and the line says
  `x509: certificate has expired`.
- **One operator opens a fifth connection:** the oldest is closed, said once per 10 s
  (`principal_cap_evicted`). Their agent reconnects on its next mint if it was the one closed.
- **Two retries of one batch overlap:** the second is answered `409 idempotency_in_progress`;
  the agent waits a second and asks again, and gets the first's tokens, replayed.

## Global Constraints

Copied verbatim from `CLAUDE.md`, "Code conventions":

- Go 1.22+, module `github.com/blanketfish/port49`, `gofmt` and `go vet` clean, no cgo.
- **snake_case everywhere it is data**: YAML keys, JSON log keys, config, metric names.
- Reason codes are the closed vocabulary of spec §5.7 (`internal/decision/reasons.go`).
  Never invent one; add to the spec table first.
- The log never contains a token, password, challenge, or response. Credentials appear only
  as `credential_sha256`. An unvalidated body is never logged.
- No device identity in metric labels.
- Verify before claiming done: run `make test && make vet` and report the real output.

Carried from plans 2–6c, and still binding:

- **Every claim about device behaviour cites a `tests/lab/results/` note or a register row.** A
  claim cited to an open row is unmeasured; do not "fix" a doc to assert it (CLAUDE.md, lab
  register rules 1–4).
- **Security first:** no privilege escalation, no impersonation, no secret in a log, fail closed.
  Where a task leaves a choice, take the one that denies more and say so in the commit.
- **Narrow setters only for live contexts.** Nothing here writes a context except through
  `session.Manager`, which uses `SetRevokedAt` (monotonic) and `DeleteReceiptsByPrincipal`.

New in this plan:

- **No metric label names a principal, a certificate or a device.** The new labels are closed
  sets: `reason` (Ruling 2's six), `event` (`source_cap_refused`, `principal_cap_evicted`,
  `revoked_closed`, `revoked_refused`), `state` (`pending`, `held`), `outcome`, `by` (`principal`, `cert`).
- **A revocation record and a process-log line may name a principal, a certificate's issuer and
  serial, and a source address**: identity, not credential (spec §5.1.4). Never a token, never an
  idempotency key's holder, never a response body.
- **A peer's text is printed only through `printsafe.Line`**, cut at 300 bytes: a TLS error can
  quote a client certificate's subject.
- **The code blocks are written against `7d32a91`.** Where the compiler or a test says a block is
  wrong about the tree (a helper's name, an import, a field the block assumed), fix the block
  minimally, keep the behaviour the step's test asserts, and say so in the task's report and its
  commit. Never weaken a test to make a block pass.
- **Every commit is preceded by `gofmt -w` on the Go files the task touched, then `make build &&
  make test && make vet`.** Report their real output.
- Branch `feature/revocation-and-broker-limits`; never commit code to `main`.
- Commit messages end with:
  ```
  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  ```

## Running the lab (Task 12)

The lab host is beehive. The owner has given standing consent for lab runs; the lab is
single-occupant, so nothing else runs a topology while Task 12 does.

**Every lab run is made from a detached worktree pinned to a commit** (plan 6b Task 19): `git
worktree add --detach ../port49-lab-7a <sha>`, `make build` there, and run from there. The note
names the commit. Copy the run's raw captures into the main checkout's `tests/lab/captures/` before
removing the worktree, or the labpcap audit fails.

The run follows plan 5b's "Running the lab": one platform at a time
(`PORT49_LAB_PLATFORMS=eos`, then `nxos`, `iosxe`, `vjunos`), the harness's boot budgets, a deadline
on every read, and **a stall watchdog run by the controller for the whole run** (no new line in the
test log, no capture growth and no results file for 25 minutes is a stall), which on a stall
destroys the topology and kills `bin/port49d`, any `port49 agent` and any `tcpdump` on
`tests/lab/captures`. Match the test binary exactly: `pgrep -f "^/tmp/go-build[^ ]*/lab\.test"`.
After every run confirm that no `port49d` holds `172.100.100.1:49`, no agent is running, and the
topology is destroyed. Task 12 runs `make evidence` and commits the redacted captures under
`tests/lab/evidence/`.

## File Structure

```
docs/design/2026-08-23-policy-engine-spec.md   MOD  §5.1.4, §5.6 row 2, §5.7, §12, §13 d32 (Task 1)
docs/design/2026-08-21-port49-design.md        MOD  §12 table and matrix, §17 requirements (Task 1)
internal/store/store.go                        MOD  Idempotency.Holder/Pending; the reservation, token
                                                    index and revocation methods; Revocation (Tasks 2, 4, 5)
internal/store/memory/memory.go                MOD  their memory implementations (Tasks 2, 4, 5)
internal/store/crypt/crypt.go                  MOD  sealing a completed record; pass-throughs (Tasks 2, 4, 5)
internal/store/storetest/storetest.go          MOD  IdempotencyReservesOnce, TokenIndex, RevocationMarks
internal/daemon/authen/authen_test.go          MOD  noStore gains the ten methods (Tasks 2, 4, 5)
internal/token/minter.go                       MOD  Reserve, Release, Reservation; IndexToken first (Tasks 3, 4)
internal/broker/broker.go                      MOD  reservation; mark checks; Sessions, Conns, Persist (Tasks 3, 7)
internal/agent/agent.go                        MOD  waits out in_progress; ends on credential_revoked (Tasks 3, 7)
internal/broker/listen.go                      NEW  Listener: handshakes, source and principal caps (Task 6)
internal/broker/server.go                      MOD  ConnContext reads the accept time; limitedConn.NetConn (Task 6)
internal/daemon/metrics/metrics.go             MOD  the broker and revocation metrics (Tasks 3, 6, 8)
internal/decision/reasons.go, log.go           MOD  EventRevoke, RevocationLifted, Record.Revocation (Task 8)
internal/broker/revoke.go                      NEW  Revoke, Lift, the report's text (Task 8)
internal/config/config.go                      MOD  revocations_file, the two caps (Task 9)
cmd/port49d/revocations.go                     NEW  the file, restore, persist, the admin ops (Tasks 9, 10)
cmd/port49d/main.go                            MOD  the listener, Sessions, the marks at start (Tasks 9, 10)
tests/lab/slice/broker.yaml, quarantine/broker.yaml, inventory_test.go   MOD  revocations_file (Task 9)
internal/daemon/admin/admin.go, peer_*.go      MOD  ops revoke and revocations; the peer's uid (Task 10)
cmd/port49/revoke.go, main.go, keys.go         NEW/MOD  port49 revoke; askAdmin shared (Task 11)
tests/lab/revoke_test.go                       NEW  revocation end to end (Task 12)
tests/lab/results/revoke-*.md                  NEW  written by the lab run (Task 12)
docs/superpowers/plans/README.md               MOD  plan 7a as built (Task 13)
```

Thirteen tasks:
- **Task 1** is docs, and comes first: every later task cites the text it writes.
- **Tasks 2–11** are code. Every one leaves `make test` green. Tasks 2, 4 and 5 are the store; 3 and
  4 the minter; 6 the listener; 7 and 8 the broker's revocation; 9–11 port49d, the admin socket and
  the tool.
- **Task 12** is a lab run of revocation end to end on four images. It gates the merge.
- **Task 13** is docs: plan 7a as built.

---

### Task 1: The spec and the design say what plan 7a builds, before the code does

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`
- Modify: `docs/design/2026-08-21-port49-design.md`

No code. Each edit is given as the text to find and the text to put in its place, or the text a new
paragraph goes after. Three anchors are wrapped across lines in the files, so search for a phrase
from them rather than the whole sentence (M21): spec §12's "A secret that is all lowercase hex and
64 characters or fewer passes the shape." (lines ~5396–5397; the same sentence is in §10 at ~4110,
so take the §12 one, after `keys diagnose`); design §12's "an atomic remove-and-write … and MUST be
reachable" (~1235); design §17's "…would otherwise silently receive tokens for the wrong devices."
(~1570). Nothing here asserts device behaviour: Task 12 measures the end-to-end run,
and what a device does with a `credential_revoked` FAIL is already cited where the spec says it.

- [ ] **Step 1: §5.1.4, revocation as built.** After the paragraph that begins "**Consequence for
  the store.**" and ends "That obligation previously covered tokens alone.", add:

  ```markdown
  **Revocation by principal or by certificate, as built (plan 7a; §13, decision 32).** An operator
  revokes with `port49 revoke` over port49d's admin socket (§12), naming a principal, or one
  certificate by its issuer and serial. A revocation is a **standing mark**, kept in the store and
  in `broker.revocations_file`, so a restart forgets none, and it stands until an operator lifts it
  (`port49 revoke --lift`). A principal's mark refuses every mint by that principal, on any
  connection and with any certificate; a certificate's refuses every mint made with it. It does not
  expire, because the agent reconnects with the same key on its own, and a mark a fresh handshake
  could outlive would be undone without anyone acting.

  The mark is written first, and then the revocation reaches everything it names, in this order:
  the held broker connections are closed; the unspent tokens are deleted, through
  `tokens_by_principal` and `tokens_by_cert`, indexes the minter writes before each token, so no
  token exists that a revocation cannot find; every live context indexed under the principal or the
  certificate is marked `revoked_at` (§5.6, teardown row 2) and the receipts of the principals behind
  them are deleted; and the context index is read and marked a second time. Tokens go before
  contexts because a token redeemed on a device with no live context writes a fresh context the
  revocation never saw; the second pass catches a redemption that was in flight. A redemption that
  removed its token before the delete and writes its context after the second pass is a window of one
  store round trip, which the shared store (plan 7d) closes atomically. Deleting by certificate
  deletes every unspent token under each `(device, username)` key that certificate minted under, the
  same principal's other certificates' included: the store holds no finer cut, and the error is
  toward denying. A principal is compared as `Identity` spells it, `user:` and the lower-cased email.
  The broker's listener holds the marks in memory too, so a connection made with a revoked
  certificate is closed as it binds, and cannot close its owner's other connections. A mint reads the marks before
  anything else and again after its last token write, and deletes what it wrote if a mark appeared:
  whichever of a mint and a revocation reads the other's write, no token minted under a revoked
  credential survives. The store's marks are read at mint, not at the TLS handshake: `port49 login`
  touches no store (design document §12). A revoked operator's `port49 login` is refused
  `credential_revoked` at the agent's first request, from the listener's copy, which ends the
  agent's session (Ruling 10, revised; Task 1 wrote the first version). Each revocation is one `revoke`
  record (§5.7) naming what it reached and the live contexts it could not, on a platform that never
  asks about a command (§13, decision 21). Revocation by an OIDC `sid` or `sub` arrives with plan 7h,
  and from a CRL or an OCSP response with plan 7b, each as a mark of this kind.
  ```

- [ ] **Step 2: §5.6, teardown row 2.** In the row that begins `| 2 | **Revocation** — OIDC
  back-channel logout by`, replace

  ```markdown
  **Revocation** — OIDC back-channel logout by `sid` or `sub`; a certificate appearing on a CRL or OCSP response by issuer and serial;
  ```

  with

  ```markdown
  **Revocation** — an operator's `port49 revoke`, by principal or by certificate (§5.1.4); OIDC back-channel logout by `sid` or `sub`; a certificate appearing on a CRL or OCSP response by issuer and serial;
  ```

  and in the same row's authority cell replace "authoritative: from the identity layer (§5.1.4)," with
  "authoritative: from an operator or the identity layer (§5.1.4),".

- [ ] **Step 3: §5.7, the events.** Replace "One envelope. Six decision events, one at each point a
  decision is made, plus four report" with "One envelope. Seven decision events, one at each point a
  decision is made, plus four report". In the table under it, after the row that begins `| \`refresh\` |
  broker |`, add:

  ```markdown
  | `revoke` | broker | a revocation by principal or by certificate (§5.1.4): what it reached, and the live contexts it could not; or a revocation lifted |
  ```

- [ ] **Step 4: §5.7, the `revoke` record.** After the paragraph that begins "A `mint deny
  trust_domain_unresolved` for a client certificate the trust anchor verified" and ends "A
  connection with no verified chain names no one.", add:

  ```markdown
  A `revoke` record (plan 7a) is written once per `port49 revoke`: `deny credential_revoked` for a
  revocation, `permit revocation_lifted` for a lift. Its `principal` is the revoked principal when
  the revocation is by principal. Its body is `"revocation": {"by", "issuer", "serial", "at",
  "origin", "contexts", "token_keys", "connections", "unreached", "saved", "error"}`: `by` is
  `principal` or `cert`; `issuer` and `serial` name a certificate (the serial in lower-case hex);
  `at` is when the mark took force, an earlier mark's time when one already stood; `origin` is who
  asked (`admin_socket uid 0`); `contexts` how many live contexts were marked; `token_keys` how many
  `(device, username)` keys had their unspent tokens deleted; `connections` how many held broker
  connections were closed; `unreached` each marked context, `{"device", "username"}`, on a platform
  that never asks about a command, or on a device the inventory gives no platform, so an incident
  responder knows which sessions to close on the device (§5.6, "Where these controls do not
  reach"); `saved` whether `broker.revocations_file` was written; and `error` the first step that
  did not finish, while the mark stands. A count of zero is absent. A `mint deny
  credential_revoked` names whose credential it was as `trust_domain_unresolved` does: `principal`,
  and `auth.fingerprint`.
  ```

- [ ] **Step 5: §5.7, the reason codes.** In the `credential_revoked` row, after "or a
  retransmission answered while the context it names is revoked (§5.6)", add "; on `mint`, a
  revocation by principal or by this certificate stands (§5.1.4), so nothing is minted and the
  connection is closed; on `revoke`, a revocation's own record". After the `credential_revoked` row,
  add:

  ```markdown
  | `revocation_lifted` | `revoke`: an operator lifted a revocation (§5.1.4). Mints by the principal or certificate are made again; a context the revocation marked stays revoked until a login whose token was minted after the lift joins it (§5.6) |
  ```

- [ ] **Step 6: §12, the tooling.** After the paragraph ending "A secret that is all lowercase hex
  and 64 characters or fewer passes the shape." (the `keys diagnose`, `keys show` paragraph), add:

  ```markdown
  **`port49 revoke (--principal <principal> | --cert <file> | --cert-issuer <dn> --cert-serial
  <hex>) [--lift]`** and **`port49 revoke --list`** ask port49d, over `admin_socket`, to revoke a
  principal or one certificate, to lift a revocation, or to list those in force (§5.1.4). The
  socket answers port49d's user and root alone, the people who can already rewrite the policy. A
  revocation prints what it reached and names each live context on a platform it cannot reach;
  `--cert` reads the issuer and serial from the certificate itself, in the spelling the broker
  compares, which is safer than typing a distinguished name. The HTTP revocation, under `api:`
  rights, is plan 7c's.
  ```

- [ ] **Step 7: §13, decision 32.** After decision 31's paragraph (it ends "`port49 inventory
  export` verifies the bundle's signature before it writes.") and before "### Deferred, with
  reasons", add:

  ```markdown
  **32. A revocation is a standing mark that reaches everything, and the broker's listener is
  bounded per source and per principal.** *Plan 7a, 2026-10-01, rulings where the design was
  silent, each the option that denies more.* A batch reserves its `Idempotency-Key` for every
  device, put-if-absent, before its first mint; a duplicate still minting is answered `409
  idempotency_in_progress` and never minted for; a reservation lives a minute and is completed or
  released by its holder alone. The broker's listener completes each TLS handshake itself, within
  10 s, and counts every failure by reason (`untrusted_chain`, `identity_refused`,
  `server_cert_refused`, `timeout`, `client_closed`, `protocol`). A source holds at most
  `broker.max_pending_conns_per_source` (16) connections not yet bound to a principal, and the next
  is reset at accept; a principal holds at most `broker.max_conns_per_principal` (4) held
  connections, and a new one closes the oldest of its own certificate, else the principal's oldest,
  so dead connections never lock their owner out, one certificate cannot fill the listener, and a
  flood from one certificate churns only its own slots. A source is one address (an IPv6 /64 is not
  one source), and the global cap is taken before the per-source check, so at global saturation
  connections wait in the backlog; plan 12 owns the global cap. A revocation by principal or by
  certificate is a mark that stands until an operator lifts it, because the agent reconnects on its
  own. A principal is compared as the broker spells it (`user:` and the lower-cased email), and a
  mark no subject names is written with a warning. The mark is written first; then held connections
  are closed, unspent tokens deleted, contexts marked and receipts deleted, and the contexts read and
  marked a second time, catching a redemption in flight; the broker's listener holds the marks in
  memory and closes a marked certificate's or principal's connection as it binds. A mint reads the
  marks before anything else and after its last token write, and deletes what it wrote if one
  appeared. The minter indexes every token by principal and by certificate before writing it, and
  refuses the mint if it cannot. The marks are kept in `broker.revocations_file`, required with a
  broker, read behind the fence with its directory fenced whether or not the file exists, and
  created at the first start beside a marker; after that a missing file, or one that does not
  parse, refuses the start. Revocation is an admin-socket operation open to port49d's user and root;
  the HTTP one, under `api:` rights, is plan 7c's. The marks are read at mint, not at the handshake,
  so `port49 login` still touches no store. (§5.1.4, §5.7, §12; design document §11, §12, §17)
  ```

- [ ] **Step 8: Design §12, the store table.** After the row that begins `| idempotency record |`,
  add:

  ```markdown
  | idempotency reservation | the idempotency record, `pending`, with a random holder | broker, put-if-absent before the batch's first mint; completed or released by its holder alone | broker | 1 minute, or the completed record's | no — it holds no response |
  | `tokens_by_principal`, `tokens_by_cert` | principal; `(issuer, serial)` → set of `(nas, username)` | broker, before each token | broker, on revocation | the token's TTL | no |
  | revocation mark | `(principal, key)` or `(cert, (issuer, serial))` | broker, on `port49 revoke`; also kept in `broker.revocations_file` | broker, at every mint | none: until an operator lifts it | no — identity, no credential |
  ```

  In the paragraph that begins "**Requirement:** the store MUST provide atomic match-and-delete with
  TTL, an atomic remove-and-write for the token-to-receipt replacement (below)", replace "an atomic
  remove-and-write for the token-to-receipt replacement (below), and MUST be reachable" with "an
  atomic remove-and-write for the token-to-receipt replacement (below), an atomic put-if-absent for
  the idempotency reservation with a compare-and-set on its holder, and MUST be reachable".

- [ ] **Step 9: Design §12, the failure matrix.** In the row `| **Operator credential lost** | ✗ |
  ✗ | ✓ existing logins persist | ✗ |`, replace "✓ existing logins persist" with "✓ existing logins
  persist, until `port49 revoke` ends them where the platform asks about each command (policy engine
  spec §5.1.4; a Junos session keeps what it had at login, and the revocation names it)". After the
  row that begins `| **Policy file refused**`, add (M19):

  ```markdown
  | **Revocations file missing or refused** (`broker.revocations_file` absent after the first start, unparseable, or writable by someone else; policy engine spec §5.1.4) | ✗ port49d does not start | ✗ → device-local break-glass, as with port49d stopped (spec §15 L4; `tests/lab/results/L4-error-*.md`) | ✗ commands fall to local authorization, as with port49d stopped | ✗. Unlike a refused policy file, nothing keeps serving: a port49d that forgot a revocation would mint for a stolen certificate again. Restore the file, or write `{"revocations": []}` on purpose |
  ```

- [ ] **Step 10: Design §17, idempotency.** In the paragraph that begins "**Idempotency is
  mandatory, not a convenience.**", after its last sentence ("…would otherwise silently receive tokens
  for the wrong devices."), add: "Two requests under one key must not both mint: the broker reserves
  the key for every device of a batch, put-if-absent, before it mints the first, so a concurrent
  duplicate is answered `409 idempotency_in_progress` and a different body `409
  idempotency_conflict`, and the reservation is completed with the response, or released when its
  device is refused, by the request that holds it and no other (plan 7a)."

- [ ] **Step 11: Design §17, the listener and revocation.** After the paragraph that begins
  "**Batch is capped and the caller pages.**", add:

  ```markdown
  **The broker's listener is limited per source and per principal, before globally** (§11's rule).
  The broker completes each TLS handshake itself, within 10 s, and counts every failure by reason.
  One source address holds a bounded number of connections not yet bound to a principal, and the
  next is reset at accept; one principal holds a bounded number of held connections, and a new one
  closes the oldest of its own certificate, else the principal's oldest, so an operator whose laptop
  slept is never locked out by their own dead connections, and one certificate cannot hold every
  slot for `max_session_age` (plan 7a). A revoked certificate's connection is closed as it binds.

  **A revocation reaches the held connection.** A revoked principal's or certificate's held
  connections are closed, and every mint it would make is refused, before and after the mint's token
  writes, until an operator lifts the revocation: otherwise a token minted after the revocation
  would lift it at the next login (policy engine spec §5.6, §13 decision 15; plan 7a).
  ```

- [ ] **Step 12: Check and commit.** Run `make test && make vet` (docs only: they must still pass).

  ```bash
  git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
  git commit -m "docs: revocation marks, the revoke event, and the broker listener's limits (plan 7a)

  Spec §5.1.4, §5.6 row 2, §5.7 (the revoke event, revocation_lifted, credential_revoked on mint),
  §12 (port49 revoke), §13 decision 32; design §12's store table, requirement and failure matrix,
  §17's idempotency reservation, listener limits and revocation.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
  ```

### Task 2: The store reserves an idempotency key atomically

**Files:**
- Modify: `internal/store/store.go` (`ErrConflict`'s comment; `Idempotency`; the `Store` interface after
  `GetIdempotency`)
- Modify: `internal/store/memory/memory.go` (after `GetIdempotency`)
- Modify: `internal/store/crypt/crypt.go` (after `GetIdempotency`)
- Modify: `internal/store/storetest/storetest.go` (new `IdempotencyReservesOnce`)
- Modify: `internal/daemon/authen/authen_test.go` (`noStore`)
- Test: `internal/store/memory/memory_test.go`, `internal/store/crypt/crypt_test.go`

**Interfaces:**
- Consumes: `store.ErrConflict`, `memory.idemKey`, `crypt.wrapped.keys`, `crypt.wrapped.openErr`.
- Produces:
  - `store.Idempotency` gains `Holder string` and `Pending bool`.
  - `ReserveIdempotency(ctx context.Context, principal, key string, rec Idempotency) (Idempotency, bool, error)`
  - `CompleteIdempotency(ctx context.Context, principal, key, expect string, rec Idempotency) error`
  - `ReleaseIdempotency(ctx context.Context, principal, key, holder string) error`
  - `storetest.IdempotencyReservesOnce(t *testing.T, newStore func() store.Store, now time.Time)`

`PutIdempotency` and `GetIdempotency` stay in the interface for the tests that plant a record and
read one back; after Task 3 the minter calls neither.

- [ ] **Step 1: Write the property.** Add to `internal/store/storetest/storetest.go` (it already
  imports `context`, `errors`, `fmt`, `sync`, `testing`, `time` and `store`):

  ```go
  // IdempotencyReservesOnce is design §17's "a retry that reaches a different
  // replica MUST behave identically" made a store property (plan 7a): of many
  // concurrent reservations under one key exactly one wins, and every loser
  // sees the winner's pending record; a completion is a compare-and-set on the
  // holder; a release takes only its own pending reservation; and a key is
  // scoped to its principal.
  //
  // newStore returns a fresh store whose clock returns now.
  func IdempotencyReservesOnce(t *testing.T, newStore func() store.Store, now time.Time) {
  	t.Helper()
  	const principal, key, racers = "user:alice@example.com", "01J\x00leaf-01", 32
  	ctx := context.Background()
  	s := newStore()
  	pending := func(holder string) store.Idempotency {
  		return store.Idempotency{BodyHash: "h1", Holder: holder, Pending: true, ExpiresAt: now.Add(time.Minute)}
  	}
  	start := make(chan struct{})
  	won := make(chan string, racers)
  	var wg sync.WaitGroup
  	for i := 0; i < racers; i++ {
  		holder := fmt.Sprintf("holder-%02d", i)
  		wg.Add(1)
  		go func() {
  			defer wg.Done()
  			<-start
  			cur, ok, err := s.ReserveIdempotency(ctx, principal, key, pending(holder))
  			switch {
  			case err != nil:
  				t.Error(err)
  			case ok:
  				won <- holder
  			case !cur.Pending || cur.BodyHash != "h1" || cur.Holder == "":
  				t.Errorf("a losing reservation must see the winner's pending record: %+v", cur)
  			}
  		}()
  	}
  	close(start)
  	wg.Wait()
  	close(won)
  	var winners []string
  	for h := range won {
  		winners = append(winners, h)
  	}
  	if len(winners) != 1 {
  		t.Fatalf("%d concurrent reservations of one key won: %v", len(winners), winners)
  	}
  	winner := winners[0]

  	if err := s.ReleaseIdempotency(ctx, principal, key, "someone-else"); err != nil {
  		t.Fatal(err)
  	}
  	if _, ok, _ := s.ReserveIdempotency(ctx, principal, key, pending("late")); ok {
  		t.Fatal("a release by another holder removed the reservation")
  	}
  	done := store.Idempotency{BodyHash: "h1", Holder: winner, Response: []byte(`{"login":"x"}`),
  		ExpiresAt: now.Add(time.Hour)}
  	if err := s.CompleteIdempotency(ctx, principal, key, "someone-else", done); !errors.Is(err, store.ErrConflict) {
  		t.Fatalf("a completion by another holder: %v, want ErrConflict", err)
  	}
  	if err := s.CompleteIdempotency(ctx, principal, key, winner, done); err != nil {
  		t.Fatal(err)
  	}
  	cur, ok, err := s.ReserveIdempotency(ctx, principal, key, pending("after"))
  	if err != nil || ok || cur.Pending || cur.Holder != winner || string(cur.Response) != `{"login":"x"}` {
  		t.Fatalf("after completion a reservation must find the completed record: %+v %v %v", cur, ok, err)
  	}
  	if err := s.ReleaseIdempotency(ctx, principal, key, winner); err != nil {
  		t.Fatal(err)
  	}
  	if _, ok, _ := s.ReserveIdempotency(ctx, principal, key, pending("after-release")); ok {
  		t.Fatal("a release removed a completed record")
  	}
  	// Taking over a completed record (a replay the minter abandons) is a
  	// compare-and-set on the old holder too.
  	again := done
  	again.Holder, again.Response = "next", []byte(`{"login":"y"}`)
  	if err := s.CompleteIdempotency(ctx, principal, key, winner, again); err != nil {
  		t.Fatalf("replacing a completed record by its holder: %v", err)
  	}
  	if err := s.CompleteIdempotency(ctx, principal, "never-reserved", "", done); !errors.Is(err, store.ErrConflict) {
  		t.Fatalf("completing a key nobody reserved: %v, want ErrConflict", err)
  	}
  	if _, ok, err := s.ReserveIdempotency(ctx, "user:bob@example.com", key, pending("bob")); err != nil || !ok {
  		t.Fatalf("another principal under the same key is its own record: %v %v", ok, err)
  	}
  }
  ```

- [ ] **Step 2: Call it, and test expiry where the clock moves.** In
  `internal/store/memory/memory_test.go`, after the test that calls `storetest.RevocationIsMonotonic`,
  add:

  ```go
  func TestIdempotencyReservesOnce(t *testing.T) {
  	now := time.Unix(1_757_041_495, 0)
  	storetest.IdempotencyReservesOnce(t, func() store.Store { return New(func() time.Time { return now }) }, now)
  }

  // A reservation a dead broker left behind expires: past it a retry
  // reserves afresh, and the dead holder can no longer complete or release
  // what is now someone else's.
  func TestAnExpiredReservationIsNobodys(t *testing.T) {
  	now := time.Unix(1_757_041_495, 0)
  	s := New(func() time.Time { return now })
  	ctx := context.Background()
  	res := func(h string) store.Idempotency {
  		return store.Idempotency{BodyHash: "h1", Holder: h, Pending: true, ExpiresAt: now.Add(time.Minute)}
  	}
  	if _, ok, _ := s.ReserveIdempotency(ctx, "user:alice", "k", res("dead")); !ok {
  		t.Fatal("first reservation")
  	}
  	now = now.Add(time.Minute)
  	if _, ok, err := s.ReserveIdempotency(ctx, "user:alice", "k", res("retry")); err != nil || !ok {
  		t.Fatalf("a reservation past its expiry must not stand: %v %v", ok, err)
  	}
  	if err := s.CompleteIdempotency(ctx, "user:alice", "k", "dead",
  		store.Idempotency{BodyHash: "h1", Holder: "dead", ExpiresAt: now.Add(time.Hour)}); !errors.Is(err, store.ErrConflict) {
  		t.Fatalf("the dead holder completed the retry's reservation: %v", err)
  	}
  	if err := s.ReleaseIdempotency(ctx, "user:alice", "k", "dead"); err != nil {
  		t.Fatal(err)
  	}
  	if cur, ok, _ := s.ReserveIdempotency(ctx, "user:alice", "k", res("third")); ok || cur.Holder != "retry" {
  		t.Fatalf("the dead holder released the retry's reservation: %+v %v", cur, ok)
  	}
  }
  ```

  In `internal/store/crypt/crypt_test.go`, after `TestJoinRacesRevocationThroughTheSealingLayer`, add:

  ```go
  func TestIdempotencyReservesOnceThroughTheSealingLayer(t *testing.T) {
  	now := time.Unix(1_757_041_495, 0)
  	storetest.IdempotencyReservesOnce(t, func() store.Store {
  		return Wrap(memory.New(func() time.Time { return now }), keys(), nil)
  	}, now)
  }

  // A completed record holds the minted tokens, so the inner store sees it
  // sealed; a reservation holds no response, and one that tries to carry one
  // is refused rather than written in clear.
  func TestACompletedReservationIsSealed(t *testing.T) {
  	ctx := context.Background()
  	inner := memory.New(time.Now)
  	s := Wrap(inner, keys(), nil)
  	exp := time.Now().Add(time.Hour)
  	if _, ok, err := s.ReserveIdempotency(ctx, "user:alice", "k",
  		store.Idempotency{BodyHash: "b", Holder: "h", Pending: true, ExpiresAt: exp}); err != nil || !ok {
  		t.Fatalf("%v %v", ok, err)
  	}
  	if err := s.CompleteIdempotency(ctx, "user:alice", "k", "h",
  		store.Idempotency{BodyHash: "b", Holder: "h", Response: []byte(`{"login":"p49_x"}`), ExpiresAt: exp}); err != nil {
  		t.Fatal(err)
  	}
  	if r, _ := inner.GetIdempotency(ctx, "user:alice", "k"); r.Response != nil || len(r.Sealed) == 0 {
  		t.Fatalf("the inner store holds the response in clear: %+v", r)
  	}
  	cur, ok, err := s.ReserveIdempotency(ctx, "user:alice", "k",
  		store.Idempotency{BodyHash: "b", Holder: "h2", Pending: true, ExpiresAt: exp})
  	if err != nil || ok || string(cur.Response) != `{"login":"p49_x"}` {
  		t.Fatalf("a reservation must find the completed record opened: %+v %v %v", cur, ok, err)
  	}
  	if _, _, err := s.ReserveIdempotency(ctx, "user:alice", "k2",
  		store.Idempotency{BodyHash: "b", Holder: "h", Pending: true, Response: []byte("x"), ExpiresAt: exp}); err == nil {
  		t.Fatal("a reservation carrying a response was written")
  	}
  }
  ```

- [ ] **Step 3: Run them to see them fail.**
  `go test ./internal/store/... -run 'Reserv|Idempotency' -count=1`
  Expected: FAIL to compile (`ReserveIdempotency` undefined).

- [ ] **Step 4: The interface.** In `internal/store/store.go`, replace `ErrConflict`'s comment with:

  ```go
  // ErrConflict is a compare-and-set refused because the record is no longer
  // the one the caller read: SwapContext's context, written by another writer
  // since, expired, or appeared where none was; or CompleteIdempotency's
  // record, no longer held by the caller (plan 7a). Nothing was written. The
  // caller reads again and decides again; JoinContext is the loop that does.
  ```

  Replace the `Idempotency` type with:

  ```go
  type Idempotency struct {
  	BodyHash  string
  	Response  []byte // sealed — it contains the minted tokens (design §17)
  	ExpiresAt time.Time
  	Sealed    []byte
  	// Holder is the request that reserved the record (ReserveIdempotency):
  	// random, never logged, and kept when the record is completed, so a
  	// completion is a compare-and-set on it (CompleteIdempotency).
  	Holder string
  	// Pending is a reservation whose mint has not finished. It carries no
  	// Response; a request that finds it is told to retry, and nothing is
  	// minted for it (design §17).
  	Pending bool
  }
  ```

  In the `Store` interface, after `GetIdempotency`, add:

  ```go
  	// ReserveIdempotency writes rec under (principal, key) when no live
  	// record is there, in one atomic step, and reports true. When one is, it
  	// writes nothing and returns that record and false. Two concurrent
  	// requests under one key therefore cannot both pass (design §17).
  	ReserveIdempotency(ctx context.Context, principal, key string, rec Idempotency) (Idempotency, bool, error)
  	// CompleteIdempotency replaces the live record under (principal, key)
  	// with rec only while that record's Holder is expect; otherwise it writes
  	// nothing and returns ErrConflict. An expired reservation, or one another
  	// request has taken since, is never overwritten.
  	CompleteIdempotency(ctx context.Context, principal, key, expect string, rec Idempotency) error
  	// ReleaseIdempotency deletes the record under (principal, key) only
  	// while it is a pending reservation held by holder; anything else stays.
  	ReleaseIdempotency(ctx context.Context, principal, key, holder string) error
  ```

- [ ] **Step 5: The memory store.** In `internal/store/memory/memory.go`, replace `GetIdempotency`
  with the version below and add the three methods after it:

  ```go
  // liveIdemLocked is the live record under k, deleting one past its expiry.
  func (s *Store) liveIdemLocked(k string) (store.Idempotency, bool) {
  	r, ok := s.idem[k]
  	if !ok {
  		return store.Idempotency{}, false
  	}
  	if !r.ExpiresAt.After(s.now()) {
  		delete(s.idem, k)
  		return store.Idempotency{}, false
  	}
  	return r, true
  }

  // GetIdempotency returns the record written under (principal, key), or
  // ErrNotFound if it is absent, expired, or was written under a different
  // principal.
  func (s *Store) GetIdempotency(_ context.Context, principal, key string) (store.Idempotency, error) {
  	s.mu.Lock()
  	defer s.mu.Unlock()
  	if r, ok := s.liveIdemLocked(idemKey(principal, key)); ok {
  		return r, nil
  	}
  	return store.Idempotency{}, store.ErrNotFound
  }

  // ReserveIdempotency is design §17's put-if-absent: under the one lock, a
  // live record is returned untouched and only its absence is written.
  func (s *Store) ReserveIdempotency(_ context.Context, principal, key string, rec store.Idempotency) (store.Idempotency, bool, error) {
  	s.mu.Lock()
  	defer s.mu.Unlock()
  	k := idemKey(principal, key)
  	if cur, ok := s.liveIdemLocked(k); ok {
  		return cur, false, nil
  	}
  	s.idem[k] = rec
  	s.wroteLocked()
  	return store.Idempotency{}, true, nil
  }

  // CompleteIdempotency writes rec over the live record only while that
  // record's holder is expect.
  func (s *Store) CompleteIdempotency(_ context.Context, principal, key, expect string, rec store.Idempotency) error {
  	s.mu.Lock()
  	defer s.mu.Unlock()
  	k := idemKey(principal, key)
  	if cur, ok := s.liveIdemLocked(k); !ok || cur.Holder != expect {
  		return store.ErrConflict
  	}
  	s.idem[k] = rec
  	s.wroteLocked()
  	return nil
  }

  // ReleaseIdempotency deletes holder's own pending reservation and nothing
  // else.
  func (s *Store) ReleaseIdempotency(_ context.Context, principal, key, holder string) error {
  	s.mu.Lock()
  	defer s.mu.Unlock()
  	k := idemKey(principal, key)
  	if cur, ok := s.liveIdemLocked(k); ok && cur.Pending && cur.Holder == holder {
  		delete(s.idem, k)
  	}
  	return nil
  }

  // wroteLocked counts a write and sweeps every sweepEvery writes, as every
  // writer here does.
  func (s *Store) wroteLocked() {
  	s.writes++
  	if s.writes%sweepEvery == 0 {
  		s.sweepLocked()
  	}
  }
  ```

  (`wroteLocked` is new; the existing writers keep their inline counting. Tasks 4 and 5 use it.)

- [ ] **Step 6: The sealing layer.** In `internal/store/crypt/crypt.go`, after `GetIdempotency`, add:

  ```go
  // ReserveIdempotency passes a reservation through: it holds no response, so
  // there is nothing to seal, and one that tries to carry a response is
  // refused rather than written in clear. A completed record it finds is
  // opened, as GetIdempotency opens one.
  func (w *wrapped) ReserveIdempotency(ctx context.Context, principal, key string, rec store.Idempotency) (store.Idempotency, bool, error) {
  	if len(rec.Response) != 0 {
  		return store.Idempotency{}, false, errors.New("crypt: a reservation carries no response")
  	}
  	cur, ok, err := w.inner.ReserveIdempotency(ctx, principal, key, rec)
  	if err != nil || ok || cur.Pending {
  		return cur, ok, err
  	}
  	resp, err := w.keys.Open(cur.Sealed)
  	if err != nil {
  		return store.Idempotency{}, false, w.openErr("idempotency", err)
  	}
  	cur.Response, cur.Sealed = resp, nil
  	return cur, false, nil
  }

  // CompleteIdempotency seals the response, which holds the minted tokens
  // (design §17), before the compare-and-set below.
  func (w *wrapped) CompleteIdempotency(ctx context.Context, principal, key, expect string, rec store.Idempotency) error {
  	s, err := w.keys.Seal(rec.Response)
  	if err != nil {
  		return err
  	}
  	rec.Response, rec.Sealed = nil, s
  	return w.inner.CompleteIdempotency(ctx, principal, key, expect, rec)
  }

  // ReleaseIdempotency touches no sealed field.
  func (w *wrapped) ReleaseIdempotency(ctx context.Context, principal, key, holder string) error {
  	return w.inner.ReleaseIdempotency(ctx, principal, key, holder)
  }
  ```

- [ ] **Step 7: The test double.** In `internal/daemon/authen/authen_test.go`, after `noStore`'s
  `GetIdempotency`, add:

  ```go
  func (noStore) ReserveIdempotency(context.Context, string, string, store.Idempotency) (store.Idempotency, bool, error) {
  	panic("store called")
  }
  func (noStore) CompleteIdempotency(context.Context, string, string, string, store.Idempotency) error {
  	panic("store called")
  }
  func (noStore) ReleaseIdempotency(context.Context, string, string, string) error {
  	panic("store called")
  }
  ```

- [ ] **Step 8: Run them.** `go test ./internal/store/... ./internal/daemon/authen/ -count=1 -race`
  Expected: PASS. Then `gofmt -w` the touched files, `make build && make test && make vet`.

- [ ] **Step 9: Commit.**

  ```bash
  git add internal/store internal/daemon/authen/authen_test.go
  git commit -m "feat(store): reserve an idempotency key atomically, complete it by its holder

  ReserveIdempotency is put-if-absent; CompleteIdempotency a compare-and-set on the holder;
  ReleaseIdempotency takes only its own pending reservation. storetest.IdempotencyReservesOnce
  is the property every backend must pass, run against memory and through the sealing layer.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
  ```

---

### Task 3: A batch reserves its key before its first mint, and a duplicate in flight mints nothing

**Files:**
- Modify: `internal/token/minter.go` (`Request`; `Conflict` removed; `Mint`'s idempotency; new
  `Reserve`, `Release`, `Reservation`, `ErrIdempotencyInProgress`, `ReservationTTL`)
- Modify: `internal/broker/broker.go` (`tokens`, `mintOne`)
- Modify: `internal/daemon/metrics/metrics.go` (`BrokerIdempotency`)
- Modify: `internal/agent/agent.go` (`Mint` waits out `idempotency_in_progress`)
- Test: `internal/token/minter_test.go`, `internal/broker/broker_test.go`,
  `internal/agent/agent_test.go`, `internal/daemon/metrics/metrics_test.go`

**Interfaces:**
- Consumes: Task 2's `ReserveIdempotency`, `CompleteIdempotency`, `ReleaseIdempotency`.
- Produces:
  - `token.ErrIdempotencyInProgress`, `token.ReservationTTL = time.Minute`
  - `type Reservation struct { Key, Holder string; Found map[string]store.Idempotency; reserved []string }`
  - `func (m *Minter) Reserve(ctx context.Context, principal, key string, devices []string, bodyHash string) (*Reservation, error)` (nil, nil for an empty key)
  - `func (m *Minter) Release(ctx context.Context, principal string, res *Reservation)`
  - `token.Request` loses `IdempotencyKey`; gains `Reservation *Reservation` (keeps `BodyHash`).
  - `(*Minter).Conflict` is removed.
  - `metrics.Metrics.BrokerIdempotency *prometheus.CounterVec`:
    `port49_broker_idempotency_refusals_total{outcome}`, outcome ∈ `conflict`, `in_progress`, `store_error`.
  - API error code `idempotency_in_progress` (HTTP 409, `Retry-After: 1`). Not a §5.7 reason: like
    `idempotency_conflict` and `bad_request` it is the API's own, and no decision record carries it.

- [ ] **Step 1: The minter's tests.** In `internal/token/minter_test.go`:

  Add a helper after `subject()`:

  ```go
  // reserved is req with a fresh reservation of key for its device, as the
  // broker takes one per request before it mints.
  func reserved(t *testing.T, m *Minter, req Request, key string) Request {
  	t.Helper()
  	res, err := m.Reserve(context.Background(), req.Subject.Principal, key, []string{req.Device}, req.BodyHash)
  	if err != nil {
  		t.Fatalf("reserving %q for %s: %v", key, req.Device, err)
  	}
  	req.Reservation = res
  	return req
  }
  ```

  Rewrite each test that sets `IdempotencyKey: "…"`: drop the field and pass the request through
  `reserved(t, m, req, "…")` immediately before each `m.Mint` (one fresh reservation per call, as the
  broker takes one per request). `TestOneIdempotencyKeyAcrossDevicesDoesNotCross` reserves per
  device the same way. `TestIdempotentReplay`'s last step (it sets `BodyHash = "h2"` and expects
  `Mint` to return `ErrIdempotencyConflict`, `minter_test.go:133-137`) becomes an assertion that
  `m.Reserve(ctx, p, "01J", []string{req.Device}, "h2")` returns `ErrIdempotencyConflict` (M2). Delete `TestConflictIsReadOnly` (Reserve's tests below replace it). Replace
  `failingStore`'s two methods with:

  ```go
  func (f *failingStore) ReserveIdempotency(ctx context.Context, principal, key string, rec store.Idempotency) (store.Idempotency, bool, error) {
  	if f.getErr != nil {
  		return store.Idempotency{}, false, f.getErr
  	}
  	return f.Store.ReserveIdempotency(ctx, principal, key, rec)
  }

  func (f *failingStore) CompleteIdempotency(ctx context.Context, principal, key, expect string, rec store.Idempotency) error {
  	if f.putErr != nil {
  		return f.putErr
  	}
  	return f.Store.CompleteIdempotency(ctx, principal, key, expect, rec)
  }
  ```

  `TestIdempotencyStoreFailureIsNotAMiss` now asserts on `Reserve`: with `getErr` set, `m.Reserve`
  returns an error that is not `store.ErrNotFound`, no token is minted, and nothing is logged; with
  `getErr` cleared, `reserved(...)` then `Mint` mints. `TestUndecodableIdempotencyRecordIsNamedOnTheMintRecord`
  plants the record with `st.Store.PutIdempotency(…, idemScope("01J", req.Device), …)` before
  `reserved(t, m, req, "01J")`. Then add:

  ```go
  // A batch reserves every device before the first is minted: a record under
  // another body on any device refuses the whole batch, and one still being
  // minted refuses it as in progress. Either way what this call reserved is
  // given back, so a corrected retry is not refused by its own leftovers.
  func TestReserveRefusesTheWholeBatchAndGivesBackWhatItTook(t *testing.T) {
  	m, st, _ := minter(t)
  	ctx := context.Background()
  	p := subject().Principal
  	if _, ok, err := st.ReserveIdempotency(ctx, p, idemScope("01J", "leaf-02"),
  		store.Idempotency{BodyHash: "other", Holder: "x", ExpiresAt: time.Now().Add(time.Hour)}); err != nil || !ok {
  		t.Fatal(ok, err)
  	}
  	if _, err := m.Reserve(ctx, p, "01J", []string{"leaf-01", "leaf-02"}, "h1"); !errors.Is(err, ErrIdempotencyConflict) {
  		t.Fatalf("another body on the second device: %v", err)
  	}
  	if _, ok, _ := st.ReserveIdempotency(ctx, p, idemScope("01J", "leaf-01"),
  		store.Idempotency{BodyHash: "h1", Holder: "y", Pending: true, ExpiresAt: time.Now().Add(time.Minute)}); !ok {
  		t.Fatal("the refused batch kept its reservation of the first device")
  	}
  	// leaf-01 is now pending under "y": the same body is in progress.
  	if _, err := m.Reserve(ctx, p, "01J", []string{"leaf-01"}, "h1"); !errors.Is(err, ErrIdempotencyInProgress) {
  		t.Fatalf("a pending record under the same body: %v", err)
  	}
  	if res, err := m.Reserve(ctx, p, "", []string{"leaf-01"}, "h1"); res != nil || err != nil {
  		t.Fatalf("no key reserves nothing: %+v %v", res, err)
  	}
  }

  // A device refused after it was reserved is released, so a retry once the
  // refusal is fixed is not answered "in progress"; a completed one is not.
  func TestReleaseGivesBackOnlyWhatDidNotComplete(t *testing.T) {
  	m, st, _ := minter(t)
  	ctx := context.Background()
  	req := Request{Subject: subject(), Device: "leaf-01", TTL: time.Minute, BodyHash: "h1"}
  	res, err := m.Reserve(ctx, req.Subject.Principal, "01J", []string{"leaf-01", "leaf-02"}, "h1")
  	if err != nil {
  		t.Fatal(err)
  	}
  	req.Reservation = res
  	if _, err := m.Mint(ctx, req); err != nil {
  		t.Fatal(err)
  	}
  	m.Release(ctx, req.Subject.Principal, res)
  	if cur, err := st.GetIdempotency(ctx, req.Subject.Principal, idemScope("01J", "leaf-01")); err != nil || cur.Pending {
  		t.Fatalf("the minted device's record: %+v %v", cur, err)
  	}
  	if _, err := st.GetIdempotency(ctx, req.Subject.Principal, idemScope("01J", "leaf-02")); !errors.Is(err, store.ErrNotFound) {
  		t.Fatalf("the unminted device's reservation was not released: %v", err)
  	}
  }

  // A replay the minter abandons (its tokens superseded) is taken over by a
  // compare-and-set before anything is minted, so two such retries cannot
  // both mint: the second is told the first is in progress (pre-flight M5).
  func TestAnAbandonedReplayIsTakenOverBeforeItMints(t *testing.T) {
  	m, st, _ := minter(t)
  	ctx := context.Background()
  	req := Request{Subject: subject(), Device: "leaf-01", TTL: time.Minute, BodyHash: "h1"}
  	if _, err := m.Mint(ctx, reserved(t, m, req, "01J")); err != nil {
  		t.Fatal(err)
  	}
  	req.SupersededAt = time.Now().Add(time.Second) // a refresh deleted those tokens
  	a, b := reserved(t, m, req, "01J"), reserved(t, m, req, "01J") // both found the completed record
  	if _, err := m.Mint(ctx, a); err != nil {
  		t.Fatalf("the first abandoned replay: %v", err)
  	}
  	if _, err := m.Mint(ctx, b); !errors.Is(err, ErrIdempotencyInProgress) && !errors.Is(err, ErrIdempotencyConflict) {
  		t.Fatalf("the second abandoned replay minted: %v", err)
  	}
  	if c, _ := st.Candidates(ctx, store.TokenKey{NAS: "leaf-01", Username: subject().Username}); len(c) != 2 {
  		t.Fatalf("%d tokens: the first mint and one re-mint, not two", len(c))
  	}
  }

  // An idempotent mint without a reservation is a broker bug, refused.
  func TestMintRefusesAKeyWithoutAReservation(t *testing.T) {
  	m, _, _ := minter(t)
  	req := Request{Subject: subject(), Device: "leaf-01", TTL: time.Minute, BodyHash: "h1",
  		Reservation: &Reservation{Key: "01J"}}
  	if _, err := m.Mint(context.Background(), req); err == nil {
  		t.Fatal("a reservation with no holder minted")
  	}
  }
  ```

- [ ] **Step 2: The broker's tests.** In `internal/broker/broker_test.go`, add:

  ```go
  // gatedStore holds every PutToken until gate is closed, so two requests can
  // be made to overlap at the mint.
  type gatedStore struct {
  	store.Store
  	entered chan struct{}
  	gate    chan struct{}
  }

  func (g *gatedStore) PutToken(ctx context.Context, k store.TokenKey, t store.Token) (int, error) {
  	select {
  	case g.entered <- struct{}{}:
  	default:
  	}
  	<-g.gate
  	return g.Store.PutToken(ctx, k, t)
  }

  // gate puts the fixture's minter over a gatedStore and returns it.
  func (f *fixture) gate() *gatedStore {
  	g := &gatedStore{Store: f.st, entered: make(chan struct{}, 1), gate: make(chan struct{})}
  	f.b.Minter = token.NewMinter(g, decision.NewJSONLines(f.log), rand.Reader, token.TagKey([]byte("k")), f.b.Now, 8)
  	return g
  }

  // Design §17: two requests under one key cannot both mint. Under the same
  // body the second is told the first is in progress, and a retry after it
  // completes is its replay; under another body it is a conflict. Exactly one
  // mint is made either way.
  func TestTwoRequestsUnderOneKeyMintOnce(t *testing.T) {
  	for _, tc := range []struct{ second, wantErr string }{
  		{`{"devices":["leaf1"]}`, "idempotency_in_progress"},
  		{`{"devices":["leaf1"],"enable":true}`, "idempotency_conflict"},
  	} {
  		t.Run(tc.wantErr, func(t *testing.T) {
  			f := newFixture(t, 8)
  			g := f.gate()
  			first := make(chan *httptest.ResponseRecorder, 1)
  			go func() { first <- f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "01J") }()
  			<-g.entered
  			w := f.post(context.Background(), f.state(f.alice), tc.second, "01J")
  			if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), tc.wantErr) {
  				t.Fatalf("the overlapping request: %d %s", w.Code, w.Body.String())
  			}
  			if tc.wantErr == "idempotency_in_progress" && w.Header().Get("Retry-After") != "1" {
  				t.Fatalf("Retry-After: %q", w.Header().Get("Retry-After"))
  			}
  			close(g.gate)
  			a := decodeMint(t, <-first)
  			toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"})
  			if len(toks) != 1 { // the first request asks no enable token
  				t.Fatalf("%d tokens stand for leaf1; one mint makes one login token", len(toks))
  			}
  			if tc.wantErr == "idempotency_in_progress" {
  				b := decodeMint(t, f.post(context.Background(), f.state(f.alice), tc.second, "01J"))
  				if b.Results[0].Login != a.Results[0].Login {
  					t.Fatal("the retry after completion must be the first request's replay")
  				}
  			}
  		})
  	}
  }

  // A device refused by policy gives its reservation back: the same key and
  // body, retried after the grant is added, mints rather than being answered
  // in progress for a minute.
  func TestARefusedDeviceReleasesItsReservation(t *testing.T) {
  	f := newFixture(t, 8)
  	carol := f.client(t, "carol@example.com", f.now.Add(time.Hour))
  	if r := decodeMint(t, f.post(context.Background(), f.state(carol), `{"devices":["leaf1"]}`, "01K")); r.Results[0].Verdict != "deny" {
  		t.Fatalf("carol has no grant: %+v", r)
  	}
  	if _, ok, err := f.st.ReserveIdempotency(context.Background(), "user:carol@example.com", "01K\x00leaf1",
  		store.Idempotency{BodyHash: "x", Holder: "probe", Pending: true, ExpiresAt: f.now.Add(time.Minute)}); err != nil || !ok {
  		t.Fatalf("the denied device's reservation is still held: %v %v", ok, err)
  	}
  }

  // A batch that names a device twice is refused before anything is reserved.
  func TestABatchNamingADeviceTwiceIsRefused(t *testing.T) {
  	f := newFixture(t, 8)
  	w := f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1","leaf1"]}`, "01L")
  	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "twice") {
  		t.Fatalf("%d %s", w.Code, w.Body.String())
  	}
  }
  ```

  (Add `net/http`, `net/http/httptest`, `crypto/rand`, `github.com/blanketfish/port49/internal/token` and
  `github.com/blanketfish/port49/internal/store` to the imports where `broker_test.go` lacks them.)

- [ ] **Step 3: The agent's test.** In `internal/agent/agent_test.go`, add a test against a broker
  stub (follow the file's existing stub-server helper; if it has none, use
  `httptest.NewUnstartedServer` with a TLS config from `testpki`, as its other tests do): the stub
  answers the first two `POST /v1/tokens` `409 {"error":"idempotency_in_progress"}` and the third
  `200` with one permit item for the device, recording each request's `Idempotency-Key`. Set
  `inProgressDelay = 10 * time.Millisecond` for the test (restore it after). Assert that `Mint`
  returns the item, the stub saw three requests, and all three carried the same key. A second case
  answers `idempotency_in_progress` every time and asserts `Mint` returns an error naming
  `idempotency_in_progress` after `inProgressRetries + 1` requests.

- [ ] **Step 4: Run them to see them fail.**
  `go test ./internal/token/ ./internal/broker/ ./internal/agent/ -count=1`
  Expected: FAIL to compile (`Reservation`, `Reserve` undefined).

- [ ] **Step 5: The minter.** In `internal/token/minter.go`:

  After `ErrIdempotencyConflict`, add:

  ```go
  // ErrIdempotencyInProgress is a request under an idempotency key that
  // another request, under the same body, is still minting (design §17).
  // Nothing is minted; the caller retries and is answered from the first
  // request's record once it completes.
  var ErrIdempotencyInProgress = errors.New("token: a request under this idempotency key is still being minted")

  // ReservationTTL is how long a reservation stands with its mint unfinished.
  // A broker that dies mid-mint leaves one behind; past this a retry mints
  // afresh, and the record says the first attempt's tokens went unrecorded.
  // A mint's store calls are bounded at ten seconds (the broker's
  // holdTimeout), so a minute is long for a live mint and short for a retry.
  const ReservationTTL = time.Minute

  // Reservation is a request's hold on its idempotency key, one record per
  // device (idemScope), taken for the whole batch before any device is minted
  // (Reserve).
  type Reservation struct {
  	Key, Holder string
  	// Found is, by device, a completed record under the key and this body:
  	// Mint replays it, unless a policy change or a revocation deleted its
  	// tokens since.
  	Found    map[string]store.Idempotency
  	reserved []string
  }
  ```

  In `Request`, replace

  ```go
  	// IdempotencyKey is scoped per device, not per key alone — see idemScope.
  	// A caller may send one key for a whole batch, which is what design §17's
  	// POST /v1/tokens does, and each device still gets its own record.
  	IdempotencyKey, BodyHash string
  ```

  with

  ```go
  	// Reservation is the request's hold on its idempotency key (Reserve),
  	// nil for a request without one. The key is scoped per device, not per
  	// key alone — see idemScope: design §17 sends one key for a whole batch,
  	// and each device gets its own record. BodyHash is the request body's.
  	Reservation *Reservation
  	BodyHash    string
  ```

  and in `SupersededAt`'s comment replace "when a policy refresh last deleted" with "when a policy
  refresh or a revocation last deleted".

  Replace `Conflict` (the function and its comment) with:

  ```go
  // Reserve takes key for every device in one pass, before any is minted
  // (design §17; plan 7a): a record under another body is
  // ErrIdempotencyConflict, one still pending under this body is
  // ErrIdempotencyInProgress, and either gives back what this call reserved
  // and refuses the whole batch. A store failure does the same and is
  // returned wrapped. A completed record under this body is kept in Found for
  // Mint to replay. An empty key reserves nothing and returns nil.
  func (m *Minter) Reserve(ctx context.Context, principal, key string, devices []string, bodyHash string) (*Reservation, error) {
  	if key == "" {
  		return nil, nil
  	}
  	var b [16]byte
  	if _, err := io.ReadFull(m.rand, b[:]); err != nil {
  		return nil, err
  	}
  	res := &Reservation{Key: key, Holder: hex.EncodeToString(b[:]), Found: map[string]store.Idempotency{}}
  	rec := store.Idempotency{BodyHash: bodyHash, Holder: res.Holder, Pending: true,
  		ExpiresAt: m.now().Add(ReservationTTL)}
  	for _, device := range devices {
  		cur, ok, err := m.store.ReserveIdempotency(ctx, principal, idemScope(key, device), rec)
  		switch {
  		case err != nil:
  			m.Release(ctx, principal, res)
  			return nil, fmt.Errorf("token: reserving the idempotency key: %w", err)
  		case ok:
  			res.reserved = append(res.reserved, device)
  		case cur.BodyHash != bodyHash:
  			m.Release(ctx, principal, res)
  			return nil, ErrIdempotencyConflict
  		case cur.Pending:
  			m.Release(ctx, principal, res)
  			return nil, ErrIdempotencyInProgress
  		default:
  			res.Found[device] = cur
  		}
  	}
  	return res, nil
  }

  // Release gives back every reservation res took whose mint did not
  // complete. A completed one is no longer pending and is left alone, so the
  // broker calls this for the whole batch once the batch is answered.
  func (m *Minter) Release(ctx context.Context, principal string, res *Reservation) {
  	if res == nil {
  		return
  	}
  	for _, device := range res.reserved {
  		_ = m.store.ReleaseIdempotency(ctx, principal, idemScope(res.Key, device), res.Holder)
  	}
  }
  ```

  In `Mint`, replace the whole block that begins `if r.IdempotencyKey != "" {` and ends before
  `ttl := r.TTL` with:

  ```go
  	// expect is the holder the record is completed against: the reservation
  	// this request took, or, for a replay abandoned below, the holder of the
  	// record read, which the new record replaces and nothing else may.
  	var expect string
  	if res := r.Reservation; res != nil {
  		if res.Holder == "" {
  			return Result{}, errors.New("token: an idempotent mint without a reservation (Minter.Reserve)")
  		}
  		expect = res.Holder
  		if rec, ok := res.Found[r.Device]; ok {
  			var prev Result
  			uerr := json.Unmarshal(rec.Response, &prev)
  			switch {
  			case uerr != nil:
  				// A record that will not decode is a mint that cannot be
  				// replayed. Mint — the caller gets working tokens — and say
  				// the replay was abandoned, or this is silent.
  				idemErr = "idempotency record did not decode; minted again rather than replayed"
  			case !r.SupersededAt.IsZero() && !prev.MintedAt.After(r.SupersededAt):
  				// Its tokens were deleted since, by a policy change or a
  				// revocation: replayed, the caller would hold a token no
  				// device accepts. A record from before MintedAt was kept has
  				// a zero one, and is not replayed either.
  				idemErr = "idempotency record names tokens a policy change or a revocation deleted; minted again rather than replayed"
  			default:
  				return prev, nil
  			}
  			// Take the record over before minting, by compare-and-set on the
  			// holder read: of two retries that both abandon this replay, one
  			// takes it and the other is told it is in progress, so they
  			// cannot both mint (pre-flight M5).
  			if err := m.store.CompleteIdempotency(ctx, r.Subject.Principal, idemScope(res.Key, r.Device), rec.Holder,
  				store.Idempotency{BodyHash: r.BodyHash, Holder: res.Holder, Pending: true,
  					ExpiresAt: m.now().Add(ReservationTTL)}); err != nil {
  				if errors.Is(err, store.ErrConflict) {
  					return Result{}, ErrIdempotencyInProgress
  				}
  				return Result{}, fmt.Errorf("token: taking over the idempotency record: %w", err)
  			}
  		}
  	}
  ```

  (The takeover leaves `expect` as `res.Holder`: the record is now this request's pending
  reservation, completed below as any other. The broker answers `ErrIdempotencyInProgress` from
  `Mint` as it does from `Reserve`: in `mintOne`, a `Mint` error that `errors.Is` it makes the
  whole request `409 idempotency_in_progress`, so `mintOne` returns `(api.MintItem, error)` for that
  one case, and `tokens` answers it as it answers `Reserve`'s.)

  and replace the block that begins `if r.IdempotencyKey != "" {` after the mints (the
  `PutIdempotency` call) with:

  ```go
  	if res := r.Reservation; res != nil {
  		body, _ := json.Marshal(out)
  		// The tokens are minted and about to be returned, so this cannot
  		// become a refusal. It is the moment the caller's next retry stops
  		// being safe, and the only moment anything knows.
  		if perr := m.store.CompleteIdempotency(ctx, r.Subject.Principal, idemScope(res.Key, r.Device), expect,
  			store.Idempotency{BodyHash: r.BodyHash, Response: body, ExpiresAt: expires, Holder: res.Holder}); perr != nil {
  			idemErr = "idempotency record not written; a retry on this key will mint again"
  		}
  	}
  ```

  (The block assumes `Mint`'s result variable is `res` today; rename the minted `Result` to `out`
  throughout `Mint` so it does not shadow the reservation, keeping every other line's behaviour.)

- [ ] **Step 6: The metric.** In `internal/daemon/metrics/metrics.go`, beside `BrokerItemErrors`, add
  the field

  ```go
  	// port49_broker_idempotency_refusals_total{outcome}: mint requests refused
  	// whole at their Idempotency-Key (design §17; plan 7a): "conflict" (another
  	// body under the key), "in_progress" (the same body still minting), and
  	// "store_error" (the reservation could not be read or written).
  	BrokerIdempotency *prometheus.CounterVec
  ```

  construct it beside `BrokerItemErrors`

  ```go
  		BrokerIdempotency: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_broker_idempotency_refusals_total",
  			Help: "Mint requests refused whole at their Idempotency-Key, by outcome."}, []string{"outcome"}),
  ```

  and add `m.BrokerIdempotency` to `reg.MustRegister`. In `metrics_test.go` touch it
  (`m.BrokerIdempotency.WithLabelValues("conflict").Inc()`) and expect
  `"port49_broker_idempotency_refusals_total"`.

- [ ] **Step 7: The broker.** In `internal/broker/broker.go`'s `tokens`:

  Replace the device-name loop with:

  ```go
  	seen := make(map[string]bool, len(req.Devices))
  	for _, name := range req.Devices {
  		if !deviceName(name) {
  			writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf(
  				"a device name is 1 to %d printable ASCII characters, as the inventory names it", maxDeviceName))
  			return
  		}
  		if seen[name] {
  			// One record per device under the key: a second mention would
  			// find this request's own reservation and refuse the batch.
  			writeError(w, http.StatusBadRequest, "bad_request", "a device is named twice in one request")
  			return
  		}
  		seen[name] = true
  	}
  ```

  Replace the conflict pre-check loop (the comment beginning "A conflict on any device refuses the
  whole batch" and its `for` loop) with:

  ```go
  	// Every device's record is reserved before the first is minted (design
  	// §17; plan 7a), atomically: two requests under one key cannot both pass,
  	// and a conflict on any device refuses the whole batch before a token, a
  	// permit record or a candidate-cap slot exists for a pair it never
  	// returns. A record exists only where this principal has minted, so the
  	// answer tells it nothing about inventory.
  	reserveCtx, cancelReserve := context.WithTimeout(r.Context(), holdTimeout)
  	res, err := b.Minter.Reserve(reserveCtx, principal, key, req.Devices, bodyHash)
  	cancelReserve()
  	switch {
  	case errors.Is(err, token.ErrIdempotencyConflict):
  		b.Metrics.BrokerIdempotency.WithLabelValues("conflict").Inc()
  		writeConflict(w)
  		return
  	case errors.Is(err, token.ErrIdempotencyInProgress):
  		b.Metrics.BrokerIdempotency.WithLabelValues("in_progress").Inc()
  		w.Header().Set("Retry-After", "1")
  		writeError(w, http.StatusConflict, "idempotency_in_progress", "a request under this Idempotency-Key "+
  			"is still being minted; retry it under the same key, and it is answered from that request's result "+
  			"(design §17)")
  		return
  	case err != nil:
  		b.Metrics.BrokerIdempotency.WithLabelValues("store_error").Inc()
  		b.emit(decision.Record{TS: now, Event: decision.EventMint, Verdict: decision.VerdictDeny,
  			Reason: decision.StoreUnavailable, Principal: principal, Auth: &decision.Auth{Method: cred.Method}})
  		writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable),
  			"the broker could not reserve the Idempotency-Key, so it minted nothing; retry under the same key")
  		return
  	}
  	// Whatever this request does not complete is given back, so a retry is
  	// not answered "in progress" by its own leftovers. Its own deadline: the
  	// caller may have hung up.
  	defer func() {
  		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), holdTimeout)
  		defer cancel()
  		b.Minter.Release(ctx, principal, res)
  	}()
  ```

  In the mint loop, the `if errors.Is(err, token.ErrIdempotencyConflict)` branch becomes
  `token.ErrIdempotencyInProgress` (Mint's takeover of an abandoned replay, pre-flight M5): release
  the hold, count `BrokerIdempotency{outcome="in_progress"}`, and answer exactly as the `Reserve`
  case above (`409 idempotency_in_progress`, `Retry-After: 1`). Pass `res` to `mintOne` in place of
  `key`:

  ```go
  func (b *Broker) mintOne(ctx context.Context, pol *policy.Policy, principal string, cred store.Credential,
  	authTime time.Time, name string, req api.MintRequest, res *token.Reservation, bodyHash string) (api.MintItem, error)
  ```

  pass `Reservation: res, BodyHash: bodyHash` in its `token.Request` in place of `IdempotencyKey:
  key, BodyHash: bodyHash`, and make its `case errors.Is(err, token.ErrIdempotencyConflict):` branch
  `case errors.Is(err, token.ErrIdempotencyInProgress):`, still returning the error. Update its
  comment: "The only error it returns is ErrIdempotencyInProgress, which is the whole request's;
  every other refusal is an item." Add to `TestTwoRequestsUnderOneKeyMintOnce` the abandoned-replay
  case: mint under `01S`, mark `leaf1`/`alice` superseded (set `f.b.superseded =
  map[store.TokenKey]time.Time{{NAS: "leaf1", Username: "alice"}: f.now.Add(time.Second)}` under
  `f.b.mu`; Task 7's `supersede` does not exist yet), gate the store, and send two retries under `01S`: one mints, the other is `409
  idempotency_in_progress`.

- [ ] **Step 8: The agent.** In `internal/agent/agent.go`, factor the transport loop of `Mint`
  (from `var resp *http.Response` through the end of the `for attempt := 1; ; attempt++` loop) into

  ```go
  // post sends one mint request under key, retrying a transport failure once
  // on a new connection, exactly as Mint did before plan 7a; the refusals
  // that end the session end it here.
  func (a *Agent) post(ctx context.Context, body []byte, key string) (*http.Response, error)
  ```

  with the loop's body unchanged (its `return api.MintItem{}, X` lines become `return nil, X`). Then,
  in `Mint`, after `key` is made:

  ```go
  	var resp *http.Response
  	for wait := 0; ; wait++ {
  		if resp, err = a.post(ctx, body, key); err != nil {
  			return api.MintItem{}, err
  		}
  		if resp.StatusCode != http.StatusConflict {
  			break
  		}
  		var e api.Error
  		_ = json.NewDecoder(resp.Body).Decode(&e)
  		drain(resp.Body)
  		if e.Error != "idempotency_in_progress" || wait >= inProgressRetries {
  			return api.MintItem{}, fmt.Errorf("agent: the broker answered %s: %s %s", resp.Status, e.Error, e.Detail)
  		}
  		// The first try under this key is still minting at the broker (a
  		// lost response, retried by post): wait for it and be answered
  		// from it, under the same key (design §17).
  		select {
  		case <-ctx.Done():
  			return api.MintItem{}, ctx.Err()
  		case <-time.After(inProgressDelay):
  		}
  	}
  	defer drain(resp.Body)
  ```

  and add beside `connectTimeout`:

  ```go
  // inProgressRetries and inProgressDelay bound how long Mint waits for a
  // first try still minting under its key: fifteen seconds, past the
  // broker's ten-second bound on a mint's store calls. Vars so a test can
  // shorten them.
  var (
  	inProgressRetries = 15
  	inProgressDelay   = time.Second
  )
  ```

  Add `"idempotency_in_progress": "the broker is still minting an earlier try of this request"` to
  `ItemError.Error`'s table.

- [ ] **Step 9: Run them.** `go test ./internal/token/ ./internal/broker/ ./internal/agent/ ./internal/daemon/metrics/ -count=1 -race`
  Expected: PASS, the existing `TestIdempotency` and `TestAConflictLaterInTheBatchMintsNothing`
  included (their behaviour is unchanged). Then `gofmt -w`, `make build && make test && make vet`;
  `cmd/port49d`'s `mintSeeds` must still compile (it sets no key; if it set `IdempotencyKey`, drop it).

- [ ] **Step 10: Commit.**

  ```bash
  git add internal/token internal/broker internal/agent internal/daemon/metrics
  git commit -m "feat(broker): reserve a batch's idempotency key before its first mint

  Two requests under one key no longer both mint: Minter.Reserve takes every device's record
  put-if-absent, a duplicate still minting is 409 idempotency_in_progress (the agent waits it
  out under the same key), another body is 409 idempotency_conflict, and whatever is not
  completed is released. A batch naming a device twice is refused.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
  ```

---

### Task 4: Every token is indexed by principal and by certificate before it is written

**Files:**
- Modify: `internal/store/store.go` (interface)
- Modify: `internal/store/memory/memory.go` (two maps, the methods, the sweep)
- Modify: `internal/store/crypt/crypt.go` (pass-throughs)
- Modify: `internal/store/storetest/storetest.go` (`TokenIndex`)
- Modify: `internal/token/minter.go` (`Mint` indexes first)
- Modify: `internal/daemon/authen/authen_test.go` (`noStore`)
- Test: `internal/store/memory/memory_test.go`, `internal/store/crypt/crypt_test.go`,
  `internal/token/minter_test.go`

**Interfaces:**
- Consumes: `store.CertKey(issuer, serial string) string`, `memory.(*Store).wroteLocked` (Task 2).
- Produces:
  - `IndexToken(ctx context.Context, principal, certKey string, k TokenKey, ttl time.Duration) error`
  - `TokensByPrincipal(ctx context.Context, principal string) ([]TokenKey, error)`
  - `TokensByCert(ctx context.Context, certKey string) ([]TokenKey, error)`
  - Both readers return the keys sorted by `(NAS, Username)`.
  - `storetest.TokenIndex(t *testing.T, newStore func() store.Store, now time.Time)`

- [ ] **Step 1: The property.** Add to `storetest.go`:

  ```go
  // TokenIndex is what a revocation needs to find a principal's, or a
  // certificate's, unspent tokens without a keyspace scan (plan 7a): keys come
  // back sorted, one entry per key however often it is indexed, an empty
  // principal or certificate is never an index key, and one principal's or
  // certificate's keys are its own.
  func TokenIndex(t *testing.T, newStore func() store.Store, now time.Time) {
  	t.Helper()
  	ctx := context.Background()
  	s := newStore()
  	const alice, bob = "user:alice@example.com", "user:bob@example.com"
  	certA := store.CertKey("CN=Corp CA", "3f9a01")
  	leaf2 := store.TokenKey{NAS: "leaf-02", Username: "alice"}
  	leaf1 := store.TokenKey{NAS: "leaf-01", Username: "alice"}
  	for _, k := range []store.TokenKey{leaf2, leaf1, leaf2} {
  		if err := s.IndexToken(ctx, alice, certA, k, time.Minute); err != nil {
  			t.Fatal(err)
  		}
  	}
  	if err := s.IndexToken(ctx, bob, "", store.TokenKey{NAS: "leaf-01", Username: "bob"}, time.Minute); err != nil {
  		t.Fatal(err)
  	}
  	got, err := s.TokensByPrincipal(ctx, alice)
  	if err != nil || len(got) != 2 || got[0] != leaf1 || got[1] != leaf2 {
  		t.Fatalf("alice's keys: %v %v", got, err)
  	}
  	if got, err := s.TokensByCert(ctx, certA); err != nil || len(got) != 2 {
  		t.Fatalf("the certificate's keys: %v %v", got, err)
  	}
  	if got, err := s.TokensByCert(ctx, ""); err != nil || len(got) != 0 {
  		t.Fatalf("an empty certificate key indexed %v (%v): every certificate-less login would share it", got, err)
  	}
  	if got, _ := s.TokensByPrincipal(ctx, "user:carol@example.com"); len(got) != 0 {
  		t.Fatalf("a principal with no token: %v", got)
  	}
  }
  ```

- [ ] **Step 2: Call it, and expiry.** In `memory_test.go`:

  ```go
  func TestTokenIndex(t *testing.T) {
  	now := time.Unix(1_757_041_495, 0)
  	storetest.TokenIndex(t, func() store.Store { return New(func() time.Time { return now }) }, now)
  }

  // An index entry lives as long as the longest token written under it, and
  // then drops out: a principal's keys do not accumulate for good.
  func TestATokenIndexEntryExpiresWithItsLongestToken(t *testing.T) {
  	now := time.Unix(1_757_041_495, 0)
  	s := New(func() time.Time { return now })
  	ctx := context.Background()
  	k := store.TokenKey{NAS: "leaf-01", Username: "alice"}
  	_ = s.IndexToken(ctx, "user:alice", "", k, 10*time.Minute)
  	_ = s.IndexToken(ctx, "user:alice", "", k, time.Minute) // never shortens it
  	now = now.Add(5 * time.Minute)
  	if got, _ := s.TokensByPrincipal(ctx, "user:alice"); len(got) != 1 {
  		t.Fatalf("at 5m: %v", got)
  	}
  	now = now.Add(5 * time.Minute)
  	if got, _ := s.TokensByPrincipal(ctx, "user:alice"); len(got) != 0 {
  		t.Fatalf("at 10m: %v", got)
  	}
  }
  ```

  In `crypt_test.go`, `TestTokenIndexThroughTheSealingLayer` calls `storetest.TokenIndex` over
  `Wrap(memory.New(...), keys(), nil)`, as Task 2's does.

- [ ] **Step 3: The minter's test.** In `minter_test.go`:

  ```go
  // indexFailingStore fails IndexToken.
  type indexFailingStore struct{ *memory.Store }

  func (indexFailingStore) IndexToken(context.Context, string, string, store.TokenKey, time.Duration) error {
  	return errors.New("store: connection refused")
  }

  // A token is indexed before it is written, so none exists that a
  // revocation cannot find; an index that cannot be written refuses the mint
  // and writes no token (plan 7a).
  func TestEveryTokenIsIndexedBeforeItIsWritten(t *testing.T) {
  	m, st, _ := minter(t)
  	ctx := context.Background()
  	sub := subject()
  	sub.Credential = store.Credential{Method: "cert", Issuer: "CN=Corp CA", Serial: "3f9a01"}
  	if _, err := m.Mint(ctx, Request{Subject: sub, Device: "leaf-01", TTL: time.Minute}); err != nil {
  		t.Fatal(err)
  	}
  	k := store.TokenKey{NAS: "leaf-01", Username: sub.Username}
  	if got, _ := st.TokensByPrincipal(ctx, sub.Principal); len(got) != 1 || got[0] != k {
  		t.Fatalf("by principal: %v", got)
  	}
  	if got, _ := st.TokensByCert(ctx, store.CertKey("CN=Corp CA", "3f9a01")); len(got) != 1 || got[0] != k {
  		t.Fatalf("by certificate: %v", got)
  	}

  	bad := indexFailingStore{memory.New(time.Now)}
  	m2 := NewMinter(bad, decision.NewJSONLines(&bytes.Buffer{}), rand.Reader, TagKey([]byte("k")), time.Now, 3)
  	if _, err := m2.Mint(ctx, Request{Subject: sub, Device: "leaf-01", TTL: time.Minute}); err == nil {
  		t.Fatal("a mint whose index failed was not refused")
  	}
  	if c, _ := bad.Candidates(ctx, k); len(c) != 0 {
  		t.Fatalf("an unindexed token was written: %d", len(c))
  	}
  }
  ```

- [ ] **Step 4: Run to see them fail.** `go test ./internal/store/... ./internal/token/ -count=1`
  Expected: FAIL to compile.

- [ ] **Step 5: The interface.** In `store.go`'s `Store`, after `ActivePrincipals`, add:

  ```go
  	// IndexToken records that principal, and the certificate certKey
  	// (CertKey), hold an unspent token under k, until ttl from now, keeping
  	// the later expiry where one is already recorded. The minter writes it
  	// before the token, so no token exists that a revocation cannot find
  	// (plan 7a). An empty principal or certKey skips that index, as
  	// IndexContext does. An entry outliving its token costs a revocation one
  	// DeleteTokens on an empty key.
  	IndexToken(ctx context.Context, principal, certKey string, k TokenKey, ttl time.Duration) error
  	// TokensByPrincipal and TokensByCert are the keys under which the
  	// principal, or the certificate, holds or held an unspent token, sorted
  	// by (NAS, Username).
  	TokensByPrincipal(ctx context.Context, principal string) ([]TokenKey, error)
  	TokensByCert(ctx context.Context, certKey string) ([]TokenKey, error)
  ```

- [ ] **Step 6: The memory store.** In `memory.go`, add to `Store`

  ```go
  	// tokensByPrincipal and tokensByCert are the token indexes (plan 7a):
  	// each key's set of TokenKeys, each with the expiry of the longest token
  	// indexed under it. Plaintext, as the context indexes are.
  	tokensByPrincipal map[string]map[store.TokenKey]time.Time
  	tokensByCert      map[string]map[store.TokenKey]time.Time
  ```

  initialise both in `New`, sweep both in `sweepLocked` beside the context indexes with
  `sweepTokenIndex(s.tokensByPrincipal, now)` and `sweepTokenIndex(s.tokensByCert, now)`, and add:

  ```go
  func (s *Store) IndexToken(_ context.Context, principal, certKey string, k store.TokenKey, ttl time.Duration) error {
  	s.mu.Lock()
  	defer s.mu.Unlock()
  	exp := s.now().Add(ttl)
  	for _, idx := range []struct {
  		m   map[string]map[store.TokenKey]time.Time
  		key string
  	}{{s.tokensByPrincipal, principal}, {s.tokensByCert, certKey}} {
  		if idx.key == "" {
  			continue
  		}
  		set := idx.m[idx.key]
  		if set == nil {
  			set = make(map[store.TokenKey]time.Time)
  			idx.m[idx.key] = set
  		}
  		if exp.After(set[k]) {
  			set[k] = exp
  		}
  	}
  	s.wroteLocked()
  	return nil
  }

  func (s *Store) TokensByPrincipal(_ context.Context, principal string) ([]store.TokenKey, error) {
  	s.mu.Lock()
  	defer s.mu.Unlock()
  	return liveTokenKeys(s.tokensByPrincipal[principal], s.now()), nil
  }

  func (s *Store) TokensByCert(_ context.Context, certKey string) ([]store.TokenKey, error) {
  	s.mu.Lock()
  	defer s.mu.Unlock()
  	return liveTokenKeys(s.tokensByCert[certKey], s.now()), nil
  }

  // liveTokenKeys is set's unexpired keys, sorted by (NAS, Username).
  func liveTokenKeys(set map[store.TokenKey]time.Time, now time.Time) []store.TokenKey {
  	var out []store.TokenKey
  	for k, exp := range set {
  		if exp.After(now) {
  			out = append(out, k)
  		}
  	}
  	sort.Slice(out, func(i, j int) bool {
  		if out[i].NAS != out[j].NAS {
  			return out[i].NAS < out[j].NAS
  		}
  		return out[i].Username < out[j].Username
  	})
  	return out
  }

  // sweepTokenIndex is sweepIndex for the token indexes.
  func sweepTokenIndex(idx map[string]map[store.TokenKey]time.Time, now time.Time) {
  	for k, set := range idx {
  		for tk, exp := range set {
  			if !exp.After(now) {
  				delete(set, tk)
  			}
  		}
  		if len(set) == 0 {
  			delete(idx, k)
  		}
  	}
  }
  ```

- [ ] **Step 7: The sealing layer.** In `crypt.go`, beside `ActivePrincipals`:

  ```go
  // IndexToken, TokensByPrincipal and TokensByCert are plaintext indexes, as
  // the context indexes are (the package comment): revocation must not depend
  // on the encryption key.
  func (w *wrapped) IndexToken(ctx context.Context, principal, certKey string, k store.TokenKey, ttl time.Duration) error {
  	return w.inner.IndexToken(ctx, principal, certKey, k, ttl)
  }

  func (w *wrapped) TokensByPrincipal(ctx context.Context, principal string) ([]store.TokenKey, error) {
  	return w.inner.TokensByPrincipal(ctx, principal)
  }

  func (w *wrapped) TokensByCert(ctx context.Context, certKey string) ([]store.TokenKey, error) {
  	return w.inner.TokensByCert(ctx, certKey)
  }
  ```

  In `authen_test.go`'s `noStore`, add the three methods, each `panic("store called")`.

- [ ] **Step 8: The minter.** In `Mint`, after the candidate-cap check and before `mintedAt :=
  m.now()`, add:

  ```go
  	// Indexed before it is written: a token no index names is one no
  	// revocation can find, so a failed index write refuses the mint (plan
  	// 7a). The entry is stamped by the store's clock before the token's
  	// expiry is computed, a remote store's later still, so it is given a
  	// minute past the token's TTL: an index that expires a moment before its
  	// token would hide that token from a revocation (pre-flight M6).
  	certKey := ""
  	if c := r.Subject.Credential; c.Issuer != "" && c.Serial != "" {
  		certKey = store.CertKey(c.Issuer, c.Serial)
  	}
  	if err := m.store.IndexToken(ctx, r.Subject.Principal, certKey, key, ttl+time.Minute); err != nil {
  		return Result{}, fmt.Errorf("token: indexing the token for revocation: %w", err)
  	}
  ```

  The broker already answers a `Mint` error other than the cap `store_unavailable` per item; nothing
  changes there.

- [ ] **Step 9: Run them.** `go test ./internal/store/... ./internal/token/ ./internal/broker/ ./internal/daemon/authen/ -count=1 -race`
  Expected: PASS. Then `gofmt -w`, `make build && make test && make vet`.

- [ ] **Step 10: Commit.**

  ```bash
  git add internal/store internal/token internal/daemon/authen/authen_test.go
  git commit -m "feat(store): index every token by principal and certificate before it is written

  tokens_by_principal and tokens_by_cert let a revocation find a principal's or a certificate's
  unspent tokens; the minter writes the index first and refuses the mint when it cannot.
  storetest.TokenIndex is the property every backend must pass.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
  ```

---

### Task 5: The store holds revocation marks

**Files:**
- Modify: `internal/store/store.go` (`Revocation`, its kinds, the interface)
- Modify: `internal/store/memory/memory.go`
- Modify: `internal/store/crypt/crypt.go`
- Modify: `internal/store/storetest/storetest.go` (`RevocationMarks`)
- Modify: `internal/daemon/authen/authen_test.go` (`noStore`)
- Test: `internal/store/memory/memory_test.go`, `internal/store/crypt/crypt_test.go`

**Interfaces:**
- Produces:
  - `const store.RevocationPrincipal = "principal"`, `store.RevocationCert = "cert"`
  - `type store.Revocation struct { Kind, Key string; At time.Time; Origin string }`
  - `PutRevocation(ctx context.Context, r Revocation) error`
  - `GetRevocation(ctx context.Context, kind, key string) (Revocation, error)` (`ErrNotFound` for none)
  - `DeleteRevocation(ctx context.Context, kind, key string) error`
  - `ListRevocations(ctx context.Context) ([]Revocation, error)` (sorted by `(Kind, Key)`)
  - `storetest.RevocationMarks(t *testing.T, newStore func() store.Store, now time.Time)`

- [ ] **Step 1: The property.** Add to `storetest.go`:

  ```go
  // RevocationMarks is the mark a revocation leaves (spec §5.1.4; plan 7a): it
  // stands until it is deleted; a second put of the same key keeps the first
  // whole, so a repeat neither moves its time nor its origin; a principal's
  // and a certificate's marks are kept apart; and the list is sorted.
  func RevocationMarks(t *testing.T, newStore func() store.Store, now time.Time) {
  	t.Helper()
  	ctx := context.Background()
  	s := newStore()
  	alice := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: now,
  		Origin: "admin_socket uid 0"}
  	cert := store.Revocation{Kind: store.RevocationCert, Key: store.CertKey("CN=Corp CA", "3f9a01"),
  		At: now.Add(time.Second), Origin: "admin_socket uid 0"}
  	if _, err := s.GetRevocation(ctx, alice.Kind, alice.Key); !errors.Is(err, store.ErrNotFound) {
  		t.Fatalf("no mark yet: %v", err)
  	}
  	for _, r := range []store.Revocation{cert, alice} {
  		if err := s.PutRevocation(ctx, r); err != nil {
  			t.Fatal(err)
  		}
  	}
  	again := alice
  	again.At, again.Origin = now.Add(time.Hour), "admin_socket uid 1000"
  	if err := s.PutRevocation(ctx, again); err != nil {
  		t.Fatal(err)
  	}
  	got, err := s.GetRevocation(ctx, alice.Kind, alice.Key)
  	if err != nil || !got.At.Equal(now) || got.Origin != alice.Origin {
  		t.Fatalf("a repeat revocation moved the mark: %+v %v", got, err)
  	}
  	if _, err := s.GetRevocation(ctx, store.RevocationCert, alice.Key); !errors.Is(err, store.ErrNotFound) {
  		t.Fatalf("a principal's mark answered for a certificate: %v", err)
  	}
  	list, err := s.ListRevocations(ctx)
  	if err != nil || len(list) != 2 || list[0].Kind != store.RevocationCert || list[1].Key != alice.Key {
  		t.Fatalf("list: %+v %v", list, err)
  	}
  	if err := s.DeleteRevocation(ctx, alice.Kind, alice.Key); err != nil {
  		t.Fatal(err)
  	}
  	if _, err := s.GetRevocation(ctx, alice.Kind, alice.Key); !errors.Is(err, store.ErrNotFound) {
  		t.Fatalf("a lifted mark stands: %v", err)
  	}
  	if err := s.DeleteRevocation(ctx, alice.Kind, alice.Key); err != nil {
  		t.Fatalf("lifting a mark twice: %v", err)
  	}
  }
  ```

- [ ] **Step 2: Call it.** `TestRevocationMarks` in `memory_test.go` and
  `TestRevocationMarksThroughTheSealingLayer` in `crypt_test.go`, shaped as Task 2's. Add to
  `memory_test.go`:

  ```go
  // A mark does not expire however far the clock moves: only a delete lifts
  // it (spec §13, decision 32).
  func TestARevocationMarkNeverExpires(t *testing.T) {
  	now := time.Unix(1_757_041_495, 0)
  	s := New(func() time.Time { return now })
  	ctx := context.Background()
  	_ = s.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice", At: now})
  	for i := 0; i < sweepEvery; i++ { // through a sweep
  		_ = s.PutBlob(ctx, fmt.Sprintf("b%d", i), []byte("x"), time.Second)
  	}
  	now = now.Add(10 * 365 * 24 * time.Hour)
  	if _, err := s.GetRevocation(ctx, store.RevocationPrincipal, "user:alice"); err != nil {
  		t.Fatalf("a mark expired: %v", err)
  	}
  }
  ```

- [ ] **Step 3: Run to see them fail.** `go test ./internal/store/... -run Revocation -count=1`
  Expected: FAIL to compile.

- [ ] **Step 4: The type and the interface.** In `store.go`, after `CertKey`:

  ```go
  // Revocation kinds (spec §5.1.4; plan 7a).
  const (
  	RevocationPrincipal = "principal"
  	RevocationCert      = "cert"
  )

  // Revocation is a standing refusal of a principal, or of one certificate
  // by CertKey(issuer, serial): every mint it names is refused until an
  // operator deletes it (spec §5.1.4, §13 decision 32). It never expires. It
  // is plaintext, as the indexes are: it names identity and holds no
  // credential, and revocation must not depend on the encryption key.
  type Revocation struct {
  	Kind string
  	Key  string
  	// At is when the mark took force. A second put of the same key keeps the
  	// first mark whole: the refusal has stood since then.
  	At time.Time
  	// Origin says who asked: "admin_socket uid 0".
  	Origin string
  }
  ```

  and in `Store`, after `GetIdempotency`'s group:

  ```go
  	// PutRevocation puts r in force. An existing mark for (r.Kind, r.Key) is
  	// kept whole: a repeat never moves its time or origin, and never lifts.
  	PutRevocation(ctx context.Context, r Revocation) error
  	// GetRevocation is the mark in force for (kind, key), or ErrNotFound.
  	GetRevocation(ctx context.Context, kind, key string) (Revocation, error)
  	// DeleteRevocation lifts the mark for (kind, key); none is not an error.
  	DeleteRevocation(ctx context.Context, kind, key string) error
  	// ListRevocations is every mark in force, sorted by (Kind, Key).
  	ListRevocations(ctx context.Context) ([]Revocation, error)
  ```

- [ ] **Step 5: The memory store.** Add the field `revocations map[[2]string]store.Revocation`
  (initialised in `New`; never swept) and:

  ```go
  func (s *Store) PutRevocation(_ context.Context, r store.Revocation) error {
  	s.mu.Lock()
  	defer s.mu.Unlock()
  	k := [2]string{r.Kind, r.Key}
  	if _, ok := s.revocations[k]; !ok {
  		s.revocations[k] = r
  	}
  	s.wroteLocked()
  	return nil
  }

  func (s *Store) GetRevocation(_ context.Context, kind, key string) (store.Revocation, error) {
  	s.mu.Lock()
  	defer s.mu.Unlock()
  	if r, ok := s.revocations[[2]string{kind, key}]; ok {
  		return r, nil
  	}
  	return store.Revocation{}, store.ErrNotFound
  }

  func (s *Store) DeleteRevocation(_ context.Context, kind, key string) error {
  	s.mu.Lock()
  	defer s.mu.Unlock()
  	delete(s.revocations, [2]string{kind, key})
  	return nil
  }

  func (s *Store) ListRevocations(_ context.Context) ([]store.Revocation, error) {
  	s.mu.Lock()
  	defer s.mu.Unlock()
  	out := make([]store.Revocation, 0, len(s.revocations))
  	for _, r := range s.revocations {
  		out = append(out, r)
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

- [ ] **Step 6: The sealing layer and the double.** In `crypt.go`, four pass-throughs under one
  comment ("Revocation marks are plaintext: identity, no credential, and revocation must not depend
  on the encryption key."). In `noStore`, four methods panicking.

- [ ] **Step 7: Run them.** `go test ./internal/store/... ./internal/daemon/authen/ -count=1 -race`
  Expected: PASS. Then `gofmt -w`, `make build && make test && make vet`.

- [ ] **Step 8: Commit.**

  ```bash
  git add internal/store internal/daemon/authen/authen_test.go
  git commit -m "feat(store): revocation marks that stand until lifted

  PutRevocation keeps an existing mark whole, GetRevocation, DeleteRevocation and a sorted
  ListRevocations; plaintext and never expiring. storetest.RevocationMarks is the property every
  backend must pass.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
  ```

---

### Task 6: The broker's listener handshakes itself, counts every failure, and bounds each source and each principal

**Files:**
- Create: `internal/broker/listen.go`
- Modify: `internal/broker/server.go` (`Server`'s doc and `ConnContext`; `limitedConn.NetConn`)
- Modify: `internal/daemon/metrics/metrics.go` (three metrics)
- Test: `internal/broker/listen_test.go` (new), `internal/broker/server_test.go`
  (`startServerLogging` serves through the listener), `internal/daemon/metrics/metrics_test.go`

**Interfaces:**
- Consumes: `broker.Identity`, `broker.Limit`, `store.CertKey`, `printsafe.Line(s string, limit int) string`.
- Produces:
  - `type ListenerLimits struct { MaxPendingPerSource, MaxPerPrincipal int; HandshakeTimeout time.Duration }`
  - `var DefaultListenerLimits = ListenerLimits{MaxPendingPerSource: 16, MaxPerPrincipal: 4, HandshakeTimeout: 10 * time.Second}`
  - `func NewListener(inner net.Listener, cfg *tls.Config, lim ListenerLimits, m *metrics.Metrics, now func() time.Time, logf func(format string, args ...any)) *Listener`
  - `(*Listener).Accept() (net.Conn, error)` (a `*tls.Conn` whose handshake is done), `Close() error`, `Addr() net.Addr`
  - `(*Listener).CloseHeld(match func(principal, certKey string) bool) int` (Task 8 calls it)
  - `(*Listener).Revoked(kind, key string, on bool)`: the listener's in-memory copy of the marks;
    a connection whose principal or certificate is marked is closed as it binds,
    `event="revoked_refused"` (Tasks 8 and 9 feed it; pre-flight I3)
  - `type ConnCloser interface { CloseHeld(match func(principal, certKey string) bool) int; Revoked(kind, key string, on bool) }` (in `listen.go`)
  - Past `MaxPerPrincipal`, `bind` closes the oldest connection of the same certificate, else the
    principal's oldest.
  - metrics: `BrokerHandshakeFailures` (`port49_broker_tls_handshake_failures_total{reason}`),
    `BrokerConnectionEvents` (`port49_broker_connection_events_total{event}`), `BrokerConnections`
    (`port49_broker_connections{state}`, a gauge).
- Serving becomes `srv.Serve(NewListener(Limit(ln, MaxConns), srv.TLSConfig, lim, m, now, logf))`;
  `ServeTLS` still works for a caller without the listener (one test keeps it).

`http.Server` handshakes a `*tls.Conn` itself only if the handshake is not done; a connection the
listener hands it is done, so `r.TLS` is filled as before and nothing about the handler changes.
`acceptedAt` reads the accept time through `tls.Conn.NetConn()`, so `auth_time` is still stamped
before the handshake (plan 3, Decided 2).

- [ ] **Step 1: The metrics' test.** In `metrics_test.go`, touch
  `m.BrokerHandshakeFailures.WithLabelValues("timeout").Inc()`,
  `m.BrokerConnectionEvents.WithLabelValues("source_cap_refused").Inc()` and
  `m.BrokerConnections.WithLabelValues("held").Set(1)`, and expect
  `"port49_broker_tls_handshake_failures_total"`, `"port49_broker_connection_events_total"` and
  `"port49_broker_connections"`.

- [ ] **Step 2: The listener's tests.** Create `internal/broker/listen_test.go`:

  ```go
  package broker

  import (
  	"bufio"
  	"context"
  	"crypto/tls"
  	"crypto/x509"
  	"errors"
  	"fmt"
  	"io"
  	"net"
  	"net/http"
  	"strings"
  	"testing"
  	"time"

  	"github.com/prometheus/client_golang/prometheus/testutil"

  	"github.com/blanketfish/port49/internal/store"
  	"github.com/blanketfish/port49/internal/testpki"
  )

  // serveThrough serves f's broker behind a Listener with lim, its lines to
  // logf (nil drops them), and returns the address and the listener.
  func serveThrough(t *testing.T, f *fixture, lim ListenerLimits, logf func(string, ...any)) (string, *Listener) {
  	t.Helper()
  	now := f.b.Now()
  	srvCert, err := f.ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
  		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)})
  	if err != nil {
  		t.Fatal(err)
  	}
  	srv, err := f.b.Server("127.0.0.1:0", srvCert, f.ca.Pool())
  	if err != nil {
  		t.Fatal(err)
  	}
  	raw, err := net.Listen("tcp", "127.0.0.1:0")
  	if err != nil {
  		t.Fatal(err)
  	}
  	if logf == nil {
  		logf = func(string, ...any) {}
  	}
  	bl := NewListener(Limit(raw, MaxConns), srv.TLSConfig, lim, f.b.Metrics, f.b.Now, logf)
  	go func() { _ = srv.Serve(bl) }()
  	t.Cleanup(func() { _ = srv.Close() })
  	return raw.Addr().String(), bl
  }

  func logTo(b *lockedBuffer) func(string, ...any) {
  	return func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }
  }

  // eventually waits up to 5s for cond: the listener's counters move on its
  // own goroutines.
  func eventually(t *testing.T, what string, cond func() bool) {
  	t.Helper()
  	deadline := time.Now().Add(5 * time.Second)
  	for !cond() {
  		if time.Now().After(deadline) {
  			t.Fatalf("within 5s: %s", what)
  		}
  		time.Sleep(10 * time.Millisecond)
  	}
  }

  // held opens a connection presenting cert and asks /v1/config on it,
  // leaving it open: an agent's held connection.
  func held(t *testing.T, f *fixture, addr string, cert tls.Certificate) (*tls.Conn, *bufio.Reader) {
  	t.Helper()
  	c, err := tls.Dial("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: f.ca.Pool(),
  		MinVersion: tls.VersionTLS13})
  	if err != nil {
  		t.Fatal(err)
  	}
  	t.Cleanup(func() { c.Close() })
  	br := bufio.NewReader(c)
  	ask(t, c, br)
  	return c, br
  }

  func ask(t *testing.T, c *tls.Conn, br *bufio.Reader) {
  	t.Helper()
  	if _, err := io.WriteString(c, "GET /v1/config HTTP/1.1\r\nHost: broker\r\n\r\n"); err != nil {
  		t.Fatal(err)
  	}
  	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
  	resp, err := http.ReadResponse(br, nil)
  	if err != nil || resp.StatusCode != 200 {
  		t.Fatalf("/v1/config on a held connection: %v %v", resp, err)
  	}
  	_, _ = io.Copy(io.Discard, resp.Body)
  	resp.Body.Close()
  }

  // closedByPeer reports whether the broker closed c: a read that fails with
  // anything but a timeout.
  func closedByPeer(c net.Conn) bool {
  	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
  	_, err := c.Read(make([]byte, 1))
  	var ne net.Error
  	return err != nil && !(errors.As(err, &ne) && ne.Timeout())
  }

  func (f *fixture) gauge(state string) float64 {
  	return testutil.ToFloat64(f.b.Metrics.BrokerConnections.WithLabelValues(state))
  }

  // Every way a handshake fails is counted by its reason (spec §13 decision
  // 32), and the first of each is said with its source and its error.
  func TestHandshakeFailuresAreCountedByReason(t *testing.T) {
  	f := newFixture(t, 8)
  	errs := &lockedBuffer{}
  	lim := DefaultListenerLimits
  	lim.HandshakeTimeout = 300 * time.Millisecond
  	addr, _ := serveThrough(t, f, lim, logTo(errs))
  	count := func(reason string) float64 {
  		return testutil.ToFloat64(f.b.Metrics.BrokerHandshakeFailures.WithLabelValues(reason))
  	}
  	try := func(cfg *tls.Config) {
  		c, err := tls.Dial("tcp", addr, cfg)
  		if err == nil {
  			closedByPeer(c) // TLS 1.3: the broker refuses a client certificate after the client's Finished
  			c.Close()
  		}
  	}
  	now := f.b.Now()
  	other, err := testpki.NewCA("someone else's CA", now.Add(-time.Hour), now.Add(48*time.Hour))
  	if err != nil {
  		t.Fatal(err)
  	}
  	mallory, err := other.Issue(testpki.Leaf{CommonName: "m", Emails: []string{"alice@example.com"}, Client: true,
  		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
  	if err != nil {
  		t.Fatal(err)
  	}
  	try(&tls.Config{RootCAs: f.ca.Pool(), MinVersion: tls.VersionTLS13,
  		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &mallory, nil }})
  	eventually(t, "untrusted_chain counted", func() bool { return count("untrusted_chain") == 1 })

  	two, err := f.ca.Issue(testpki.Leaf{CommonName: "two", Emails: []string{"a@example.com", "b@example.com"},
  		Client: true, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
  	if err != nil {
  		t.Fatal(err)
  	}
  	try(&tls.Config{Certificates: []tls.Certificate{two}, RootCAs: f.ca.Pool(), MinVersion: tls.VersionTLS13})
  	eventually(t, "identity_refused counted", func() bool { return count("identity_refused") == 1 })

  	try(&tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS13}) // trusts no broker
  	eventually(t, "server_cert_refused counted", func() bool { return count("server_cert_refused") == 1 })

  	silent, err := net.Dial("tcp", addr)
  	if err != nil {
  		t.Fatal(err)
  	}
  	defer silent.Close()
  	eventually(t, "timeout counted", func() bool { return count("timeout") == 1 })

  	gone, err := net.Dial("tcp", addr)
  	if err != nil {
  		t.Fatal(err)
  	}
  	gone.Close()
  	eventually(t, "client_closed counted", func() bool { return count("client_closed") == 1 })

  	plain, err := net.Dial("tcp", addr)
  	if err != nil {
  		t.Fatal(err)
  	}
  	_, _ = io.WriteString(plain, "GET /v1/config HTTP/1.1\r\nHost: broker\r\n\r\n")
  	closedByPeer(plain)
  	plain.Close()
  	eventually(t, "protocol counted", func() bool { return count("protocol") == 1 })

  	errs.waitFor(t, "failed (untrusted_chain)")
  	errs.waitFor(t, "unknown authority")
  	errs.waitFor(t, "2 email SANs")
  }

  // One reason's line is said once per 10s; the next says how many it held
  // back, so a flood is one line, not a flood of lines.
  func TestAReasonIsSaidOncePerTenSeconds(t *testing.T) {
  	f := newFixture(t, 8)
  	errs := &lockedBuffer{}
  	addr, _ := serveThrough(t, f, DefaultListenerLimits, logTo(errs))
  	for i := 0; i < 3; i++ {
  		c, err := net.Dial("tcp", addr)
  		if err != nil {
  			t.Fatal(err)
  		}
  		c.Close()
  	}
  	eventually(t, "three counted", func() bool {
  		return testutil.ToFloat64(f.b.Metrics.BrokerHandshakeFailures.WithLabelValues("client_closed")) == 3
  	})
  	if n := strings.Count(errs.String(), "failed (client_closed)"); n != 1 {
  		t.Fatalf("%d lines for three failures inside 10s:\n%s", n, errs.String())
  	}
  	f.advance(11 * time.Second)
  	c, err := net.Dial("tcp", addr)
  	if err != nil {
  		t.Fatal(err)
  	}
  	c.Close()
  	errs.waitFor(t, "(2 more like it since")
  }

  // A source holds at most MaxPendingPerSource connections not yet bound to
  // a principal; the next is reset at accept, and a slot freed is a slot
  // again (spec §13 decision 32).
  func TestOneSourceHoldsAtMostItsPendingCap(t *testing.T) {
  	f := newFixture(t, 8)
  	errs := &lockedBuffer{}
  	lim := DefaultListenerLimits
  	lim.MaxPendingPerSource = 2
  	addr, _ := serveThrough(t, f, lim, logTo(errs))
  	var raws []net.Conn
  	for i := 0; i < 2; i++ {
  		c, err := net.Dial("tcp", addr)
  		if err != nil {
  			t.Fatal(err)
  		}
  		defer c.Close()
  		raws = append(raws, c)
  	}
  	eventually(t, "two pending", func() bool { return f.gauge("pending") == 2 })
  	third, err := net.Dial("tcp", addr)
  	if err != nil {
  		t.Fatal(err)
  	}
  	defer third.Close()
  	if !closedByPeer(third) {
  		t.Fatal("a third connection from the source was held, not reset")
  	}
  	eventually(t, "source_cap_refused counted", func() bool {
  		return testutil.ToFloat64(f.b.Metrics.BrokerConnectionEvents.WithLabelValues("source_cap_refused")) == 1
  	})
  	errs.waitFor(t, "max_pending_conns_per_source")
  	raws[0].Close()
  	eventually(t, "one pending", func() bool { return f.gauge("pending") == 1 })
  	c, _ := held(t, f, addr, f.alice) // admitted again, and bound: not pending
  	defer c.Close()
  	if f.gauge("held") != 1 {
  		t.Fatalf("held %v", f.gauge("held"))
  	}
  }

  // A principal holds at most MaxPerPrincipal held connections, and a new one
  // closes its oldest, never the newest: dead connections from a laptop that
  // slept must not lock its owner out. Another principal is untouched.
  func TestAPrincipalPastItsCapLosesItsOldest(t *testing.T) {
  	f := newFixture(t, 8)
  	lim := DefaultListenerLimits
  	lim.MaxPerPrincipal = 2
  	addr, _ := serveThrough(t, f, lim, nil)
  	carol := f.client(t, "carol@example.com", f.now.Add(time.Hour))
  	cc, cbr := held(t, f, addr, carol)
  	first, _ := held(t, f, addr, f.alice)
  	second, sbr := held(t, f, addr, f.alice)
  	third, tbr := held(t, f, addr, f.alice)
  	if !closedByPeer(first) {
  		t.Fatal("alice's oldest connection was not closed")
  	}
  	eventually(t, "principal_cap_evicted counted", func() bool {
  		return testutil.ToFloat64(f.b.Metrics.BrokerConnectionEvents.WithLabelValues("principal_cap_evicted")) == 1
  	})
  	ask(t, second, sbr)
  	ask(t, third, tbr)
  	ask(t, cc, cbr)
  	eventually(t, "three held", func() bool { return f.gauge("held") == 3 })
  }

  // A revoked certificate cannot evict its owner: past the cap the same
  // certificate's oldest goes first, and once the broker has told the
  // listener of the mark, the certificate's connections are closed as they
  // bind, so ten of them never touch the renewed certificate's (pre-flight I3).
  func TestARevokedCertificateNeverEvictsItsOwner(t *testing.T) {
  	f := newFixture(t, 8)
  	lim := DefaultListenerLimits
  	lim.MaxPerPrincipal = 2
  	addr, bl := serveThrough(t, f, lim, nil)
  	renewed := f.client(t, "alice@example.com", f.now.Add(2*time.Hour))
  	rc, rbr := held(t, f, addr, renewed)
  	// Before any mark: the stolen certificate's flood churns its own slots.
  	for i := 0; i < 5; i++ {
  		held(t, f, addr, f.alice)
  	}
  	ask(t, rc, rbr)
  	stolenKey := store.CertKey(f.alice.Leaf.Issuer.String(), f.alice.Leaf.SerialNumber.Text(16))
  	bl.Revoked(store.RevocationCert, stolenKey, true)
  	for i := 0; i < 10; i++ {
  		c, err := tls.Dial("tcp", addr, &tls.Config{Certificates: []tls.Certificate{f.alice}, RootCAs: f.ca.Pool(),
  			MinVersion: tls.VersionTLS13})
  		if err == nil {
  			if !closedByPeer(c) {
  				t.Fatal("a revoked certificate's connection was held")
  			}
  			c.Close()
  		}
  	}
  	ask(t, rc, rbr)
  	if got := testutil.ToFloat64(f.b.Metrics.BrokerConnectionEvents.WithLabelValues("revoked_refused")); got != 10 {
  		t.Fatalf("revoked_refused %v", got)
  	}
  	bl.Revoked(store.RevocationCert, stolenKey, false)
  	c, br := held(t, f, addr, f.alice) // lifted: it binds again
  	ask(t, c, br)
  }

  // CloseHeld closes what its match names, by principal or by certificate,
  // and nothing else; a revocation calls it (Task 8).
  func TestCloseHeldClosesWhatItNames(t *testing.T) {
  	f := newFixture(t, 8)
  	addr, bl := serveThrough(t, f, DefaultListenerLimits, nil)
  	carol := f.client(t, "carol@example.com", f.now.Add(time.Hour))
  	a1, _ := held(t, f, addr, f.alice)
  	a2, _ := held(t, f, addr, f.alice)
  	cc, cbr := held(t, f, addr, carol)
  	if n := bl.CloseHeld(func(p, _ string) bool { return p == "user:alice@example.com" }); n != 2 {
  		t.Fatalf("closed %d, want alice's 2", n)
  	}
  	if !closedByPeer(a1) || !closedByPeer(a2) {
  		t.Fatal("alice's connections are open")
  	}
  	ask(t, cc, cbr)
  	carolKey := store.CertKey(carol.Leaf.Issuer.String(), carol.Leaf.SerialNumber.Text(16))
  	if n := bl.CloseHeld(func(_, ck string) bool { return ck == carolKey }); n != 1 || !closedByPeer(cc) {
  		t.Fatalf("closing carol's certificate closed %d", n)
  	}
  	if got := testutil.ToFloat64(f.b.Metrics.BrokerConnectionEvents.WithLabelValues("revoked_closed")); got != 3 {
  		t.Fatalf("revoked_closed %v", got)
  	}
  	eventually(t, "none held", func() bool { return f.gauge("held") == 0 })
  }

  // Closing the listener closes what it has not handed over — connections
  // still handshaking — and wakes Accept with net.ErrClosed, so Shutdown is not
  // held by a handshake that never finishes.
  func TestClosingTheListenerClosesWhatItHolds(t *testing.T) {
  	f := newFixture(t, 8)
  	addr, bl := serveThrough(t, f, DefaultListenerLimits, nil)
  	c, err := net.Dial("tcp", addr)
  	if err != nil {
  		t.Fatal(err)
  	}
  	defer c.Close()
  	eventually(t, "one pending", func() bool { return f.gauge("pending") == 1 })
  	if err := bl.Close(); err != nil {
  		t.Fatal(err)
  	}
  	if !closedByPeer(c) {
  		t.Fatal("a handshaking connection outlived the listener")
  	}
  	if _, err := bl.Accept(); !errors.Is(err, net.ErrClosed) {
  		t.Fatalf("Accept after Close: %v", err)
  	}
  }

  // TestShutdownReturnsWithEverySlotHeld, through the listener.
  func TestShutdownReturnsThroughTheListenerWithEverySlotHeld(t *testing.T) {
  	f := newFixture(t, 8)
  	now := f.b.Now()
  	srvCert, err := f.ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
  		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)})
  	if err != nil {
  		t.Fatal(err)
  	}
  	srv, err := f.b.Server("127.0.0.1:0", srvCert, f.ca.Pool())
  	if err != nil {
  		t.Fatal(err)
  	}
  	raw, err := net.Listen("tcp", "127.0.0.1:0")
  	if err != nil {
  		t.Fatal(err)
  	}
  	served := make(chan struct{})
  	go func() {
  		_ = srv.Serve(NewListener(Limit(raw, 2), srv.TLSConfig, DefaultListenerLimits, f.b.Metrics, f.b.Now, nil))
  		close(served)
  	}()
  	t.Cleanup(func() { _ = srv.Close() })
  	held(t, f, raw.Addr().String(), f.alice)
  	held(t, f, raw.Addr().String(), f.alice)
  	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
  	defer cancel()
  	go func() { _ = srv.Shutdown(ctx) }()
  	select {
  	case <-served:
  	case <-time.After(5 * time.Second):
  		t.Fatal("Serve did not return after Shutdown with every slot held")
  	}
  }
  ```

  (`NewListener` takes a nil `logf` as "say nothing".) In `server_test.go`, make
  `startServerLogging` serve through the listener: keep its certificate and `f.b.Server` lines, and
  replace its `srv.ErrorLog = errLog` … `go func() { _ = srv.ServeTLS(ln, "", "") }()` lines with

  ```go
  	srv.ErrorLog = errLog
  	ln, err := net.Listen("tcp", "127.0.0.1:0")
  	if err != nil {
  		t.Fatal(err)
  	}
  	logf := func(string, ...any) {}
  	if errLog != nil {
  		logf = errLog.Printf
  	}
  	go func() { _ = srv.Serve(NewListener(Limit(ln, MaxConns), srv.TLSConfig, DefaultListenerLimits, f.b.Metrics, f.b.Now, logf)) }()
  ```

  so every existing test (`TestACertificateFromAnotherCAFailsTheHandshake` waits for "unknown
  authority", `TestAnExpiredCertificateFailsTheHandshakeAndTheLogSaysExpired` for "expired",
  `TestACertificateThatMapsToNoPrincipalFailsTheHandshake` for "2 email SANs") now reads the
  listener's line. `TestShutdownReturnsWithEverySlotHeld` keeps `ServeTLS(Limit(...))`.

- [ ] **Step 3: Run them to see them fail.** `go test ./internal/broker/ ./internal/daemon/metrics/ -count=1`
  Expected: FAIL to compile (`NewListener` undefined).

- [ ] **Step 4: The metrics.** In `metrics.go`, beside `BrokerItemErrors`:

  ```go
  	// port49_broker_tls_handshake_failures_total{reason}: handshakes the
  	// broker's listener did not complete (spec §13 decision 32): reason is
  	// untrusted_chain, identity_refused, server_cert_refused, timeout,
  	// client_closed or protocol.
  	BrokerHandshakeFailures *prometheus.CounterVec
  	// port49_broker_connection_events_total{event}: source_cap_refused (reset
  	// at accept, its source holding max_pending_conns_per_source),
  	// principal_cap_evicted (a principal's oldest held connection closed for
  	// its newest), revoked_closed (closed by a revocation), revoked_refused
  	// (closed at bind: its certificate or principal is marked).
  	BrokerConnectionEvents *prometheus.CounterVec
  	// port49_broker_connections{state}: pending (not yet bound to a
  	// principal: handshaking, or certificate-less) and held.
  	BrokerConnections *prometheus.GaugeVec
  ```

  constructed

  ```go
  		BrokerHandshakeFailures: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_broker_tls_handshake_failures_total",
  			Help: "TLS handshakes the broker's listener did not complete, by reason."}, []string{"reason"}),
  		BrokerConnectionEvents: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_broker_connection_events_total",
  			Help: "Broker connections refused at accept or closed by the broker, by event."}, []string{"event"}),
  		BrokerConnections: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "port49_broker_connections",
  			Help: "Broker connections open now: pending (not yet bound to a principal) and held."}, []string{"state"}),
  ```

  and registered.

- [ ] **Step 5: The listener.** Create `internal/broker/listen.go`:

  ```go
  package broker

  import (
  	"context"
  	"crypto/tls"
  	"errors"
  	"fmt"
  	"io"
  	"net"
  	"net/netip"
  	"sync"
  	"syscall"
  	"time"

  	"github.com/blanketfish/port49/internal/daemon/metrics"
  	"github.com/blanketfish/port49/internal/printsafe"
  	"github.com/blanketfish/port49/internal/store"
  )

  // ListenerLimits are the broker listener's bounds (design §11's "per source
  // before global", §17; spec §13 decision 32).
  type ListenerLimits struct {
  	// MaxPendingPerSource caps the connections one source address holds that
  	// are not bound to a principal: handshaking, or certificate-less for
  	// /v1/config. Past it the next connection from the address is reset at
  	// accept. An authenticated operator's held connection is not counted, so
  	// a NAT'd office is not capped by its own logged-in operators.
  	MaxPendingPerSource int
  	// MaxPerPrincipal caps one principal's held connections. A new one closes
  	// that principal's oldest: refusing the newest would lock out an operator
  	// whose laptop slept with connections the broker still holds.
  	MaxPerPrincipal int
  	// HandshakeTimeout bounds a TLS handshake.
  	HandshakeTimeout time.Duration
  }

  // DefaultListenerLimits are port49d's defaults (broker.max_pending_conns_per_source,
  // broker.max_conns_per_principal).
  var DefaultListenerLimits = ListenerLimits{MaxPendingPerSource: 16, MaxPerPrincipal: 4,
  	HandshakeTimeout: 10 * time.Second}

  // ConnCloser is the listener as a revocation sees it (Broker.Conns):
  // CloseHeld closes the held connections a mark names, and Revoked keeps the
  // listener's in-memory copy of the marks, by (store.Revocation kind, key),
  // which refuses a marked connection as it binds.
  type ConnCloser interface {
  	CloseHeld(match func(principal, certKey string) bool) int
  	Revoked(kind, key string, on bool)
  }

  // sayEvery is how often one reason's line is said: a flood is one line and
  // a count, never a flood of lines.
  const sayEvery = 10 * time.Second

  // Listener accepts from inner, completes each TLS handshake itself, and
  // hands http.Server only connections whose handshake is done (spec §13
  // decision 32). Doing the handshake here is what lets every failure be
  // counted by its reason, a connection be charged to its source until it is
  // bound to a principal, and a principal's held connections be counted,
  // capped, and closed by a revocation (CloseHeld).
  type Listener struct {
  	inner net.Listener
  	cfg   *tls.Config
  	lim   ListenerLimits
  	m     *metrics.Metrics
  	now   func() time.Time
  	logf  func(format string, args ...any)

  	ready     chan *tls.Conn
  	done      chan struct{}
  	closeOnce sync.Once

  	mu sync.Mutex
  	// pending is, by source, the connections not bound to a principal.
  	pending map[netip.Addr]int
  	// open is every connection not yet closed, true once it is handed to
  	// Accept's caller, which then owns its close.
  	open map[*trackedConn]bool
  	// held is, by principal, its bound connections, oldest first.
  	held map[string][]*trackedConn
  	// marked is the broker's marks, by (kind, key), kept by Revoked.
  	marked map[[2]string]bool
  	lines  map[string]*lineLimit
  }

  // Revoked puts a mark in the listener's copy, or takes it out (on false):
  // Broker.Revoke, Broker.Lift and port49d's start-up restore call it.
  func (l *Listener) Revoked(kind, key string, on bool) {
  	l.mu.Lock()
  	defer l.mu.Unlock()
  	if on {
  		l.marked[[2]string{kind, key}] = true
  	} else {
  		delete(l.marked, [2]string{kind, key})
  	}
  }

  type lineLimit struct {
  	last time.Time
  	held int
  }

  // trackedConn is one accepted connection. principal, certKey and gone are
  // under the listener's mu.
  type trackedConn struct {
  	net.Conn
  	l          *Listener
  	acceptedAt time.Time
  	src        netip.Addr
  	principal  string
  	certKey    string
  	gone       bool
  	closeOnce  sync.Once
  }

  // NewListener starts accepting from inner at once; connections whose
  // handshake is done wait for Accept. cfg is the broker's (Broker.Server's
  // TLSConfig). logf says the listener's lines; nil says nothing.
  func NewListener(inner net.Listener, cfg *tls.Config, lim ListenerLimits, m *metrics.Metrics, now func() time.Time,
  	logf func(format string, args ...any)) *Listener {
  	if logf == nil {
  		logf = func(string, ...any) {}
  	}
  	l := &Listener{inner: inner, cfg: cfg, lim: lim, m: m, now: now, logf: logf,
  		ready: make(chan *tls.Conn), done: make(chan struct{}),
  		pending: map[netip.Addr]int{}, open: map[*trackedConn]bool{}, held: map[string][]*trackedConn{},
  		marked: map[[2]string]bool{}, lines: map[string]*lineLimit{}}
  	go l.acceptLoop()
  	return l
  }

  func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

  // Accept returns a connection whose handshake is done, or net.ErrClosed
  // once the listener is closed.
  func (l *Listener) Accept() (net.Conn, error) {
  	select {
  	case tc := <-l.ready:
  		return tc, nil
  	case <-l.done:
  		return nil, net.ErrClosed
  	}
  }

  // Close stops accepting, closes inner (which wakes a Limit waiting for a
  // slot), and closes every connection not yet handed to Accept's caller:
  // http.Server's Shutdown waits for nothing it does not know about, and a
  // handshake that never finishes must not outlive the listener.
  func (l *Listener) Close() error {
  	var err error
  	l.closeOnce.Do(func() {
  		close(l.done)
  		err = l.inner.Close()
  		l.mu.Lock()
  		var stray []*trackedConn
  		for c, handed := range l.open {
  			if !handed {
  				stray = append(stray, c)
  			}
  		}
  		l.mu.Unlock()
  		for _, c := range stray {
  			_ = c.Close()
  		}
  	})
  	return err
  }

  func (l *Listener) acceptLoop() {
  	var delay time.Duration
  	for {
  		raw, err := l.inner.Accept()
  		if err != nil {
  			select {
  			case <-l.done:
  				return
  			default:
  			}
  			if errors.Is(err, net.ErrClosed) {
  				_ = l.Close()
  				return
  			}
  			// As net/http's Serve does for a failing Accept (EMFILE among
  			// them): back off, up to a second, and go on.
  			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
  			l.say("accept", "port49d: broker: accept failed: %v; retrying in %s", err, delay)
  			time.Sleep(delay)
  			continue
  		}
  		delay = 0
  		if c := l.admit(raw); c != nil {
  			go l.handshake(c)
  		}
  	}
  }

  // admit charges raw to its source, or resets it when the source already
  // holds MaxPendingPerSource connections not bound to a principal.
  func (l *Listener) admit(raw net.Conn) *trackedConn {
  	src := sourceOf(raw.RemoteAddr())
  	l.mu.Lock()
  	if l.pending[src] >= l.lim.MaxPendingPerSource {
  		l.mu.Unlock()
  		reset(raw)
  		l.m.BrokerConnectionEvents.WithLabelValues("source_cap_refused").Inc()
  		l.say("source_cap", "port49d: broker: reset a connection from %s: it holds %d connections not yet "+
  			"authenticated (broker.max_pending_conns_per_source)", src, l.lim.MaxPendingPerSource)
  		return nil
  	}
  	c := &trackedConn{Conn: raw, l: l, acceptedAt: l.now(), src: src}
  	l.pending[src]++
  	l.open[c] = false
  	l.mu.Unlock()
  	l.gauge()
  	return c
  }

  // handshake completes c's TLS handshake within HandshakeTimeout, binds it
  // to its principal when it presented a certificate, and hands it to Accept.
  func (l *Listener) handshake(c *trackedConn) {
  	tc := tls.Server(c, l.cfg)
  	ctx, cancel := context.WithTimeout(context.Background(), l.lim.HandshakeTimeout)
  	err := tc.HandshakeContext(ctx)
  	cancel()
  	if err != nil {
  		l.refuse(c, tc, handshakeReason(err), err)
  		return
  	}
  	if cs := tc.ConnectionState(); len(cs.PeerCertificates) > 0 {
  		// The handshake's VerifyConnection ran Identity a moment ago; this
  		// reads the same answer, which a clock step alone could change.
  		principal, cred, err := Identity(&cs, l.now())
  		if err != nil {
  			l.refuse(c, tc, "identity_refused", err)
  			return
  		}
  		if !l.bind(c, principal, store.CertKey(cred.Issuer, cred.Serial)) {
  			_ = tc.Close()
  			return
  		}
  	}
  	l.mu.Lock()
  	if _, ok := l.open[c]; ok {
  		l.open[c] = true
  	}
  	l.mu.Unlock()
  	select {
  	case l.ready <- tc:
  	case <-l.done:
  		_ = tc.Close()
  	}
  }

  // refuse counts and says a failed handshake, and closes the connection.
  // The error can quote a client certificate's subject, so it is made
  // printable and cut.
  func (l *Listener) refuse(c *trackedConn, tc *tls.Conn, reason string, err error) {
  	l.m.BrokerHandshakeFailures.WithLabelValues(reason).Inc()
  	l.say("handshake_"+reason, "port49d: broker: TLS handshake from %s failed (%s): %s", c.src, reason,
  		printsafe.Line(err.Error(), 300))
  	_ = tc.Close()
  }

  // handshakeReason is the closed set of spec §13 decision 32.
  func handshakeReason(err error) string {
  	var verify *tls.CertificateVerificationError
  	var op *net.OpError
  	var ne net.Error
  	switch {
  	case errors.As(err, &verify):
  		return "untrusted_chain"
  	case errors.Is(err, ErrUntrusted):
  		return "identity_refused"
  	case errors.As(err, &op) && op.Op == "remote error":
  		// The client sent an alert: it refused the broker's certificate.
  		return "server_cert_refused"
  	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
  		return "timeout"
  	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) ||
  		errors.Is(err, syscall.EPIPE):
  		return "client_closed"
  	}
  	return "protocol"
  }

  // bind moves c from its source's pending count to its principal's held
  // connections, closing the principal's oldest past MaxPerPrincipal. It
  // reports false when c was closed under it.
  func (l *Listener) bind(c *trackedConn, principal, certKey string) bool {
  	l.mu.Lock()
  	if c.gone {
  		l.mu.Unlock()
  		return false
  	}
  	l.unpendLocked(c.src)
  	c.principal, c.certKey = principal, certKey
  	if l.marked[[2]string{store.RevocationPrincipal, principal}] || l.marked[[2]string{store.RevocationCert, certKey}] {
  		// A revoked principal or certificate is refused here, from the
  		// broker's in-memory copy of the marks (Revoked): no store read at
  		// the handshake (spec §13 decision 32), and a revoked certificate
  		// never gets to close its owner's connections (pre-flight I3). It
  		// was never added to held, so forget, at the Close below, has
  		// nothing to take back from the principal.
  		c.gone = true
  		delete(l.open, c)
  		l.mu.Unlock()
  		l.m.BrokerConnectionEvents.WithLabelValues("revoked_refused").Inc()
  		l.say("revoked_refused", "port49d: broker: closed a connection from %s as it bound: %s or its "+
  			"certificate is revoked", c.src, principal)
  		l.gauge()
  		return false
  	}
  	held := append(l.held[principal], c)
  	var evicted *trackedConn
  	if len(held) > l.lim.MaxPerPrincipal {
  		// The oldest of the same certificate goes first, so a flood from one
  		// certificate churns its own slots and never its owner's other
  		// certificate's (pre-flight I3); otherwise the principal's oldest.
  		i := 0
  		for j, h := range held[:len(held)-1] {
  			if h.certKey == certKey {
  				i = j
  				break
  			}
  		}
  		evicted = held[i]
  		held = append(held[:i:i], held[i+1:]...)
  	}
  	l.held[principal] = held
  	l.mu.Unlock()
  	if evicted != nil {
  		l.m.BrokerConnectionEvents.WithLabelValues("principal_cap_evicted").Inc()
  		l.say("principal_cap", "port49d: broker: %s opened more than %d held connections "+
  			"(broker.max_conns_per_principal); its oldest, from %s and open since %s, is closed", principal,
  			l.lim.MaxPerPrincipal, evicted.src, evicted.acceptedAt.UTC().Format(time.RFC3339))
  		_ = evicted.Close()
  	}
  	l.gauge()
  	return true
  }

  // CloseHeld closes every held connection match names, and returns how many
  // (spec §5.1.4: a revocation reaches the held connection).
  func (l *Listener) CloseHeld(match func(principal, certKey string) bool) int {
  	l.mu.Lock()
  	var hit []*trackedConn
  	for _, conns := range l.held {
  		for _, c := range conns {
  			if match(c.principal, c.certKey) {
  				hit = append(hit, c)
  			}
  		}
  	}
  	l.mu.Unlock()
  	for _, c := range hit {
  		_ = c.Close()
  	}
  	if len(hit) > 0 {
  		l.m.BrokerConnectionEvents.WithLabelValues("revoked_closed").Add(float64(len(hit)))
  	}
  	return len(hit)
  }

  // Close closes the connection and, once, gives back what it was charged.
  func (c *trackedConn) Close() error {
  	err := c.Conn.Close()
  	c.closeOnce.Do(func() { c.l.forget(c) })
  	return err
  }

  func (l *Listener) forget(c *trackedConn) {
  	l.mu.Lock()
  	c.gone = true
  	delete(l.open, c)
  	if c.principal == "" {
  		l.unpendLocked(c.src)
  	} else {
  		conns := l.held[c.principal]
  		for i, h := range conns {
  			if h == c {
  				conns = append(conns[:i:i], conns[i+1:]...)
  				break
  			}
  		}
  		if len(conns) == 0 {
  			delete(l.held, c.principal)
  		} else {
  			l.held[c.principal] = conns
  		}
  	}
  	l.mu.Unlock()
  	l.gauge()
  }

  func (l *Listener) unpendLocked(src netip.Addr) {
  	if l.pending[src]--; l.pending[src] <= 0 {
  		delete(l.pending, src)
  	}
  }

  func (l *Listener) gauge() {
  	l.mu.Lock()
  	pending, held := 0, 0
  	for _, n := range l.pending {
  		pending += n
  	}
  	for _, conns := range l.held {
  		held += len(conns)
  	}
  	l.mu.Unlock()
  	l.m.BrokerConnections.WithLabelValues("pending").Set(float64(pending))
  	l.m.BrokerConnections.WithLabelValues("held").Set(float64(held))
  }

  // say logs a line at most once per reason per sayEvery; the next line says
  // how many it held back.
  func (l *Listener) say(reason, format string, args ...any) {
  	now := l.now()
  	l.mu.Lock()
  	ll := l.lines[reason]
  	if ll == nil {
  		ll = &lineLimit{}
  		l.lines[reason] = ll
  	}
  	if !ll.last.IsZero() && now.Sub(ll.last) < sayEvery {
  		ll.held++
  		l.mu.Unlock()
  		return
  	}
  	held := ll.held
  	ll.last, ll.held = now, 0
  	l.mu.Unlock()
  	line := fmt.Sprintf(format, args...)
  	if held > 0 {
  		line += fmt.Sprintf(" (%d more like it since the last such line)", held)
  	}
  	l.logf("%s", line)
  }

  // sourceOf is the connection's source address; one it cannot read is the
  // zero address, which every such connection shares.
  func sourceOf(a net.Addr) netip.Addr {
  	if a == nil {
  		return netip.Addr{}
  	}
  	ap, err := netip.ParseAddrPort(a.String())
  	if err != nil {
  		return netip.Addr{}
  	}
  	return ap.Addr().Unmap()
  }

  // reset closes c with a TCP reset, as port49d refuses a TACACS+ source at
  // Accept (spec §10): nothing is held, and the client learns at once. The
  // outermost connection is the one closed, so Limit's slot comes back.
  func reset(c net.Conn) {
  	for inner := c; inner != nil; {
  		if tcp, ok := inner.(*net.TCPConn); ok {
  			_ = tcp.SetLinger(0)
  			break
  		}
  		u, ok := inner.(interface{ NetConn() net.Conn })
  		if !ok {
  			break
  		}
  		inner = u.NetConn()
  	}
  	_ = c.Close()
  }

  // acceptedAt is when the listener accepted c, before its handshake: the
  // connection's auth_time (plan 3, Decided 2). A connection that did not come
  // through a Listener — ServeTLS in a test — is stamped now, as before.
  func acceptedAt(c net.Conn, now func() time.Time) time.Time {
  	if tc, ok := c.(*tls.Conn); ok {
  		if t, ok := tc.NetConn().(*trackedConn); ok {
  			return t.acceptedAt
  		}
  	}
  	return now()
  }
  ```

  The `say("accept", …)` line reads `l.now()`; nothing else in the listener depends on a moving
  clock.

- [ ] **Step 6: The server.** In `server.go`: replace `ConnContext`'s closure with
  `func(ctx context.Context, c net.Conn) context.Context { return withHeldConn(ctx, acceptedAt(c, b.Now)) }`;
  add to `limitedConn`

  ```go
  // NetConn is the connection under the slot, for reset's SetLinger.
  func (c *limitedConn) NetConn() net.Conn { return c.Conn }
  ```

  and replace the first paragraph of `Server`'s comment ("Server serves the broker over mutual TLS
  on addr; call ServeTLS(Limit(ln, MaxConns), "", "").") with:

  ```go
  // Server serves the broker over mutual TLS on addr; serve it with
  // srv.Serve(NewListener(Limit(ln, MaxConns), srv.TLSConfig, limits, …)), which
  // completes each handshake itself and bounds each source and each principal
  // (spec §13 decision 32). ServeTLS still works and bounds neither.
  ```

  and in the paragraph that begins "ConnContext stamps each connection's auth_time at accept", note
  that the stamp is the listener's accept time (`acceptedAt`).

- [ ] **Step 7: Run them.** `go test ./internal/broker/ ./internal/daemon/metrics/ -count=1 -race`
  Expected: PASS, every pre-existing server test included. Then `gofmt -w`,
  `make build && make test && make vet`.

- [ ] **Step 8: Commit.**

  ```bash
  git add internal/broker internal/daemon/metrics
  git commit -m "feat(broker): a listener that handshakes itself and bounds each source and principal

  Every failed handshake is counted by reason (port49_broker_tls_handshake_failures_total) and
  said once per reason per 10s; a source holds at most 16 connections not yet authenticated
  (reset at accept past it); a principal holds at most 4 held connections, and a new one closes
  the oldest of its certificate, else its oldest. CloseHeld closes what a revocation names, and
  Revoked keeps an in-memory copy of the marks that refuses a marked connection as it binds.
  auth_time is still the accept time.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
  ```

---

### Task 7: A mint refuses a revoked caller, before and after its token writes

**Files:**
- Modify: `internal/broker/broker.go` (`tokens`; new `revocation`, `refuseRevoked`, `unmint`, `supersede`)
- Modify: `internal/agent/agent.go` (a `credential_revoked` 401 ends the session)
- Test: `internal/broker/revocation_mint_test.go` (new), `internal/agent/agent_test.go`

**Interfaces:**
- Consumes: Task 5's `GetRevocation`, `store.RevocationPrincipal`, `store.RevocationCert`;
  `decision.CredentialRevoked` (exists); Task 3's `gatedStore` and `(*fixture).gate()`.
- Produces:
  - `func (b *Broker) revocation(ctx context.Context, principal string, cred store.Credential) (store.Revocation, bool, error)`
  - `func (b *Broker) supersede(k store.TokenKey, at time.Time)` (Task 8 uses it)
  - A `401 {"error":"credential_revoked"}` answer with `Connection: close`, and a `mint deny
    credential_revoked` record with `principal` and `auth.fingerprint`.

- [ ] **Step 1: The broker's tests.** Create `internal/broker/revocation_mint_test.go`:

  ```go
  package broker

  import (
  	"context"
  	"errors"
  	"net/http"
  	"strings"
  	"testing"
  	"time"

  	"github.com/blanketfish/port49/internal/store"
  )

  func (f *fixture) revoke(t *testing.T, kind, key string) {
  	t.Helper()
  	if err := f.st.PutRevocation(context.Background(), store.Revocation{Kind: kind, Key: key, At: f.b.Now(),
  		Origin: "test"}); err != nil {
  		t.Fatal(err)
  	}
  }

  // A principal's mark refuses every mint by it: 401 credential_revoked, the
  // connection closed, one record naming whose credential it was, and
  // nothing minted (spec §5.1.4).
  func TestARevokedPrincipalMintsNothing(t *testing.T) {
  	f := newFixture(t, 8)
  	f.revoke(t, store.RevocationPrincipal, "user:alice@example.com")
  	w := f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "")
  	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), `"credential_revoked"`) ||
  		w.Header().Get("Connection") != "close" {
  		t.Fatalf("%d %v %s", w.Code, w.Header(), w.Body.String())
  	}
  	if toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"}); len(toks) != 0 {
  		t.Fatalf("%d tokens minted for a revoked principal", len(toks))
  	}
  	recs := eventsOf(f.records(t), "mint")
  	if len(recs) != 1 || recs[0]["reason"] != "credential_revoked" || recs[0]["principal"] != "user:alice@example.com" ||
  		recs[0]["auth"].(map[string]any)["fingerprint"] != "sha256:"+fingerprint(f.alice) { // M1
  		t.Fatalf("records: %v", recs)
  	}
  }

  // A certificate's mark refuses that certificate and no other: the same
  // principal with a new certificate mints.
  func TestARevokedCertificateMintsNothingAndAnotherDoes(t *testing.T) {
  	f := newFixture(t, 8)
  	f.revoke(t, store.RevocationCert, store.CertKey(f.alice.Leaf.Issuer.String(), f.alice.Leaf.SerialNumber.Text(16)))
  	if w := f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, ""); w.Code != http.StatusUnauthorized {
  		t.Fatalf("the revoked certificate: %d %s", w.Code, w.Body.String())
  	}
  	renewed := f.client(t, "alice@example.com", f.now.Add(time.Hour))
  	if r := decodeMint(t, f.post(context.Background(), f.state(renewed), `{"devices":["leaf1"]}`, "")); r.Results[0].Verdict != "permit" {
  		t.Fatalf("a new certificate for the same principal: %+v", r)
  	}
  }

  // revocationFailingStore cannot read the marks.
  type revocationFailingStore struct{ store.Store }

  func (revocationFailingStore) GetRevocation(context.Context, string, string) (store.Revocation, error) {
  	return store.Revocation{}, errors.New("store: connection refused")
  }

  // Marks that cannot be read refuse the mint store_unavailable: a store that
  // cannot say whether a credential is revoked mints for no one.
  func TestUnreadableMarksMintNothing(t *testing.T) {
  	f := newFixture(t, 8)
  	f.b.Store = revocationFailingStore{f.st}
  	w := f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "")
  	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "store_unavailable") {
  		t.Fatalf("%d %s", w.Code, w.Body.String())
  	}
  	if toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"}); len(toks) != 0 {
  		t.Fatal("minted with the marks unreadable")
  	}
  }

  // A revocation that lands while a mint is writing its tokens: the mint
  // reads the marks again after its last write, deletes what it wrote, and
  // answers credential_revoked, so no token minted under a revoked credential
  // survives whichever of the two read the other's write first (spec §5.1.4).
  // A replay of that request after a lift mints afresh.
  func TestARevocationDuringAMintDeletesWhatItWrote(t *testing.T) {
  	f := newFixture(t, 8)
  	g := f.gate()
  	answered := make(chan int, 1)
  	go func() {
  		answered <- f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "01R").Code
  	}()
  	<-g.entered
  	f.revoke(t, store.RevocationPrincipal, "user:alice@example.com")
  	close(g.gate)
  	if code := <-answered; code != http.StatusUnauthorized {
  		t.Fatalf("the mint a revocation overtook answered %d", code)
  	}
  	k := store.TokenKey{NAS: "leaf1", Username: "alice"}
  	if toks, _ := f.st.Candidates(context.Background(), k); len(toks) != 0 {
  		t.Fatalf("%d token(s) survived the revocation", len(toks))
  	}
  	if err := f.st.DeleteRevocation(context.Background(), store.RevocationPrincipal, "user:alice@example.com"); err != nil {
  		t.Fatal(err)
  	}
  	f.advance(time.Second)
  	r := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "01R"))
  	if toks, _ := f.st.Candidates(context.Background(), k); r.Results[0].Verdict != "permit" || len(toks) != 1 {
  		t.Fatalf("after the lift the same key must mint afresh, not replay a deleted token: %+v, %d live", r, len(toks))
  	}
  }
  ```

- [ ] **Step 2: The agent's test.** In `agent_test.go`, a stub broker answering `POST /v1/tokens`
  `401 {"error":"credential_revoked","detail":"this principal was revoked at …"}`: `Mint` returns an
  error wrapping `ErrSessionOver` whose text carries the detail, `Done()` is closed, and the next
  `Mint` returns `ErrSessionOver` without a request.

- [ ] **Step 3: Run them to see them fail.** `go test ./internal/broker/ ./internal/agent/ -run 'Revok|Unreadable' -count=1`
  Expected: FAIL (mints succeed; the agent does not end).

- [ ] **Step 4: The broker.** In `broker.go`'s `tokens`, after the `MaxSessionAge` check and before
  the body is read, add:

  ```go
  	// A revocation stands against the principal, or this certificate, until
  	// an operator lifts it (spec §5.1.4). It is read before anything else, so
  	// a revoked caller is told nothing more, and again after the last token
  	// write, below. Marks that cannot be read mint for no one.
  	checkCtx, cancelCheck := context.WithTimeout(r.Context(), holdTimeout)
  	rv, revoked, err := b.revocation(checkCtx, principal, cred)
  	cancelCheck()
  	switch {
  	case err != nil:
  		b.emit(decision.Record{TS: now, Event: decision.EventMint, Verdict: decision.VerdictDeny,
  			Reason: decision.StoreUnavailable, Principal: principal, Auth: &decision.Auth{Method: cred.Method}})
  		writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable),
  			"the broker could not read the revocations in force, so it minted nothing; try again")
  		return
  	case revoked:
  		b.refuseRevoked(w, now, principal, cred, rv)
  		return
  	}
  ```

  Replace the end of `tokens` (from the last `release()` through `writeJSON(w, http.StatusOK, resp)`)
  with:

  ```go
  	release()
  	// A revocation that landed while this request minted may have read the
  	// token index before these tokens were indexed; reading the marks again
  	// now, after the last token write, closes that: whichever of the two
  	// read the other's write, no token survives (spec §5.1.4). Its own
  	// deadline, without the caller's cancel: a caller that hung up must not
  	// leave its tokens behind.
  	afterCtx, cancelAfter := context.WithTimeout(context.WithoutCancel(r.Context()), holdTimeout)
  	defer cancelAfter()
  	if rv, revoked, err := b.revocation(afterCtx, principal, cred); err != nil || revoked {
  		if err != nil {
  			// The tokens stay: they are never returned to anyone, so no one
  			// can present them, and a revocation's own index pass finds them.
  			// Deleting here would take an earlier mint's tokens under the same
  			// key with them (pre-flight M7).
  			b.emit(decision.Record{TS: b.Now(), Event: decision.EventMint, Verdict: decision.VerdictDeny,
  				Reason: decision.StoreUnavailable, Principal: principal, Auth: &decision.Auth{Method: cred.Method}})
  			writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable), "the broker could not "+
  				"confirm that no revocation landed during this mint, so it returns nothing; try again")
  			return
  		}
  		b.unmint(afterCtx, resp.Results)
  		b.refuseRevoked(w, b.Now(), principal, cred, rv)
  		return
  	}
  	writeJSON(w, http.StatusOK, resp)
  ```

  and add:

  ```go
  // revocation is the mark refusing this caller, if any: one on the
  // principal, then one on the certificate (spec §5.1.4). A certificate with
  // no issuer or serial is never a mark's key.
  func (b *Broker) revocation(ctx context.Context, principal string, cred store.Credential) (store.Revocation, bool, error) {
  	keys := [][2]string{{store.RevocationPrincipal, principal}}
  	if cred.Issuer != "" && cred.Serial != "" {
  		keys = append(keys, [2]string{store.RevocationCert, store.CertKey(cred.Issuer, cred.Serial)})
  	}
  	for _, k := range keys {
  		rv, err := b.Store.GetRevocation(ctx, k[0], k[1])
  		switch {
  		case err == nil:
  			return rv, true, nil
  		case !errors.Is(err, store.ErrNotFound):
  			return store.Revocation{}, false, err
  		}
  	}
  	return store.Revocation{}, false, nil
  }

  // refuseRevoked answers a caller a revocation stands against: 401
  // credential_revoked, the connection closed so nothing more rides it, and
  // one mint record naming whose credential it was (spec §5.7).
  func (b *Broker) refuseRevoked(w http.ResponseWriter, now time.Time, principal string, cred store.Credential,
  	rv store.Revocation) {
  	b.emit(decision.Record{TS: now, Event: decision.EventMint, Verdict: decision.VerdictDeny,
  		Reason: decision.CredentialRevoked, Principal: principal,
  		Auth: &decision.Auth{Method: cred.Method, Fingerprint: cred.Fingerprint}})
  	what := "this principal"
  	if rv.Kind == store.RevocationCert {
  		what = "this certificate"
  	}
  	w.Header().Set("Connection", "close")
  	writeError(w, http.StatusUnauthorized, string(decision.CredentialRevoked), fmt.Sprintf(
  		"%s was revoked at %s; nothing is minted for it until an operator lifts the revocation "+
  			"(port49 revoke --lift)", what, rv.At.UTC().Format(time.RFC3339)))
  }

  // unmint deletes the unspent tokens under every key a refused request
  // minted under, and marks each key superseded, so a replay of the request
  // is minted afresh rather than handed a token that no longer exists.
  func (b *Broker) unmint(ctx context.Context, items []api.MintItem) {
  	now := b.Now()
  	for _, it := range items {
  		if it.Verdict != decision.VerdictPermit {
  			continue
  		}
  		k := store.TokenKey{NAS: it.Device, Username: it.Username}
  		if err := b.Store.DeleteTokens(ctx, k); err != nil {
  			b.logf("broker: deleting the tokens a revoked mint wrote under %q on %q: %v; they expire at their TTL",
  				it.Username, it.Device, err)
  		}
  		b.supersede(k, now)
  	}
  }

  // supersede records that k's unspent tokens were deleted at at, keeping
  // the later of two (token.Request.SupersededAt).
  func (b *Broker) supersede(k store.TokenKey, at time.Time) {
  	b.mu.Lock()
  	defer b.mu.Unlock()
  	if b.superseded == nil {
  		b.superseded = map[store.TokenKey]time.Time{}
  	}
  	if at.After(b.superseded[k]) {
  		b.superseded[k] = at
  	}
  }
  ```

  Update `superseded`'s field comment: "superseded is, by (device, username), when a refresh or a
  revocation last deleted its unspent tokens".

- [ ] **Step 5: The agent.** In `agent.go`'s 401 switch, add:

  ```go
  			case "credential_revoked":
  				// An operator revoked this principal or this certificate
  				// (spec §5.1.4): nothing this session holds will mint again.
  				over = fmt.Errorf("%w: %s", ErrSessionOver, e.Detail)
  ```

  and add "A 401 credential_revoked ends it too." to `Mint`'s comment.

- [ ] **Step 6: Run them.** `go test ./internal/broker/ ./internal/agent/ -count=1 -race`
  Expected: PASS. Then `gofmt -w`, `make build && make test && make vet`.

- [ ] **Step 7: Commit.**

  ```bash
  git add internal/broker internal/agent
  git commit -m "feat(broker): refuse a revoked principal or certificate at every mint

  The marks are read before anything else and again after the last token write; a mark that
  appeared in between deletes what the mint wrote. 401 credential_revoked closes the connection
  and ends the agent's session. Unreadable marks mint for no one.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
  ```

---

### Task 8: `Broker.Revoke` reaches everything a mark names, and `Lift` lifts it

**Files:**
- Create: `internal/broker/revoke.go`
- Modify: `internal/broker/broker.go` (`Broker` gains `Sessions`, `Conns`, `Persist`)
- Modify: `internal/decision/reasons.go` (`EventRevoke`, `RevocationLifted`)
- Modify: `internal/decision/log.go` (`Record.Revocation`, `Revocation`, `ContextRef`)
- Modify: `internal/daemon/metrics/metrics.go` (`Revocations`, `RevocationsInForce`, `RevocationsFileFailed`)
- Modify: `internal/session/session.go` (the package comment: the residual window, pre-flight I1)
- Test: `internal/broker/revoke_test.go` (new), `internal/broker/fixture_test.go` (Sessions),
  `internal/decision/reasons_test.go` (unchanged; it checks the new constant is `Known`),
  `internal/daemon/metrics/metrics_test.go`

**Interfaces:**
- Consumes: `session.Manager.RevokeByPrincipal(ctx, principal) ([]store.ContextRef, error)`,
  `RevokeByCert(ctx, issuer, serial) ([]store.ContextRef, error)`; Task 4's `TokensByPrincipal`,
  `TokensByCert`; Task 5's marks; Task 6's `ConnCloser`; Task 7's `supersede`; refresh.go's
  `sessionOnly(p *policy.Policy, platform string) bool`.
- Produces:
  - `Broker` fields `Sessions *session.Manager`, `Conns ConnCloser`, `Persist func(context.Context) error`
  - `type RevokeRequest struct { Principal, Issuer, Serial, Origin string }`
  - `type RevokeReport struct { Request RevokeRequest; Mark store.Revocation; Contexts, Unreached []store.ContextRef; TokenKeys, Connections int; Saved bool; SaveErr, Err error; Unnamed bool }`; `func (r RevokeReport) Partial() bool`
  - `var ErrBadRevocation, ErrNotRevoked error`
  - `func (b *Broker) Revoke(ctx context.Context, req RevokeRequest) (RevokeReport, error)`
  - `func (b *Broker) Lift(ctx context.Context, req RevokeRequest) (RevokeReport, error)`
  - `func (r RevokeReport) Text() string`, `func (r RevokeReport) LiftedText() string`,
    `func RevocationsText(rs []store.Revocation) string`
  - `decision.EventRevoke = "revoke"`, `decision.RevocationLifted Reason = "revocation_lifted"`,
    `decision.Record.Revocation *decision.Revocation`
  - metrics `Revocations` (`port49_revocations_total{by,outcome}`, outcome ∈ `applied`, `partial`,
    `lifted`), `RevocationsInForce` (`port49_revocations_in_force{by}`), `RevocationsFileFailed`
    (`port49_revocations_file_failed`).

- [ ] **Step 1: The fixture.** In `fixture_test.go`'s `newFixture`, add `Sessions:
  session.New(f.st, clock, time.Hour, time.Hour)` to the `Broker` literal (import
  `internal/session`), and add:

  ```go
  // liveContext writes a live context for principal under (device, username),
  // indexed by principal and certificate, as a redemption would.
  func (f *fixture) liveContext(t *testing.T, device, username, principal, certKey string) {
  	t.Helper()
  	ctx := context.Background()
  	k := store.ContextKey{NAS: device, Username: username}
  	if err := f.st.PutContext(ctx, k, store.Context{CtxID: "ctx_" + device, Principal: principal, Username: username,
  		PrivLvl: 1, AuthTime: f.now, RefreshedAt: f.now}, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	if err := f.st.IndexContext(ctx, principal, "", certKey, store.ContextRef{NAS: device, Username: username},
  		time.Hour); err != nil {
  		t.Fatal(err)
  	}
  }

  func certKey(c tls.Certificate) string {
  	return store.CertKey(c.Leaf.Issuer.String(), c.Leaf.SerialNumber.Text(16))
  }
  ```

  (Rename Task 6's `carolKey` computation to `certKey(carol)` if you like; the behaviour is the same.)

- [ ] **Step 2: The tests.** Create `internal/broker/revoke_test.go`:

  ```go
  package broker

  import (
  	"context"
  	"errors"
  	"net/http"
  	"strings"
  	"testing"

  	"github.com/prometheus/client_golang/prometheus/testutil"

  	"github.com/blanketfish/port49/internal/store"
  )

  // fakeConns stands in for the Listener: the held connections are (principal,
  // certKey) pairs, CloseHeld drops those match names, and marked is what
  // Revoked was told.
  type fakeConns struct {
  	held   [][2]string
  	marked map[[2]string]bool
  }

  func (c *fakeConns) Revoked(kind, key string, on bool) {
  	if c.marked == nil {
  		c.marked = map[[2]string]bool{}
  	}
  	c.marked[[2]string{kind, key}] = on
  }

  func (c *fakeConns) CloseHeld(match func(principal, certKey string) bool) int {
  	var kept [][2]string
  	n := 0
  	for _, h := range c.held {
  		if match(h[0], h[1]) {
  			n++
  		} else {
  			kept = append(kept, h)
  		}
  	}
  	c.held = kept
  	return n
  }

  const alicePrincipal = "user:alice@example.com"

  // A revocation by principal reaches everything (spec §5.1.4): the mark,
  // the held connection, every live context, every unspent token, the
  // record naming the context it cannot reach, and the next mint.
  func TestRevokingAPrincipalReachesEverything(t *testing.T) {
  	f := newFixture(t, 8)
  	ctx := context.Background()
  	conns := &fakeConns{held: [][2]string{{alicePrincipal, certKey(f.alice)}, {"user:carol@example.com", "x"}}}
  	saved := 0
  	f.b.Conns = conns
  	f.b.Persist = func(context.Context) error { saved++; return nil }
  	decodeMint(t, f.post(ctx, f.state(f.alice), `{"devices":["leaf1","nx1"]}`, ""))
  	f.liveContext(t, "leaf1", "alice", alicePrincipal, certKey(f.alice))
  	f.liveContext(t, "bare", "alice", alicePrincipal, certKey(f.alice))

  	rep, err := f.b.Revoke(ctx, RevokeRequest{Principal: alicePrincipal, Origin: "admin_socket uid 0"})
  	if err != nil || rep.Err != nil || rep.SaveErr != nil {
  		t.Fatalf("%+v %v", rep, err)
  	}
  	if rep.Mark.Kind != store.RevocationPrincipal || !rep.Mark.At.Equal(f.now) || len(rep.Contexts) != 2 ||
  		rep.TokenKeys != 2 || rep.Connections != 1 || !rep.Saved || saved != 1 {
  		t.Fatalf("report: %+v (saved %d)", rep, saved)
  	}
  	if len(rep.Unreached) != 1 || rep.Unreached[0].NAS != "bare" {
  		t.Fatalf("a device the inventory gives no platform is not reached: %+v", rep.Unreached)
  	}
  	if c, err := f.st.GetContext(ctx, store.ContextKey{NAS: "leaf1", Username: "alice"}); err != nil || !c.RevokedAt.Equal(f.now) {
  		t.Fatalf("leaf1's context: %+v %v", c, err)
  	}
  	for _, dev := range []string{"leaf1", "nx1"} {
  		if toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: dev, Username: "alice"}); len(toks) != 0 {
  			t.Fatalf("%d unspent token(s) on %s survived", len(toks), dev)
  		}
  	}
  	if len(conns.held) != 1 || conns.held[0][0] != "user:carol@example.com" {
  		t.Fatalf("held connections left: %v", conns.held)
  	}
  	if !conns.marked[[2]string{store.RevocationPrincipal, alicePrincipal}] {
  		t.Fatal("the listener was not told of the mark")
  	}
  	recs := eventsOf(f.records(t), "revoke")
  	if len(recs) != 1 || recs[0]["verdict"] != "deny" || recs[0]["reason"] != "credential_revoked" ||
  		recs[0]["principal"] != alicePrincipal {
  		t.Fatalf("revoke records: %v", recs)
  	}
  	body := recs[0]["revocation"].(map[string]any)
  	if body["by"] != "principal" || body["contexts"] != float64(2) || body["token_keys"] != float64(2) ||
  		body["connections"] != float64(1) || body["saved"] != true || body["origin"] != "admin_socket uid 0" {
  		t.Fatalf("revocation body: %v", body)
  	}
  	if un := body["unreached"].([]any); len(un) != 1 || un[0].(map[string]any)["device"] != "bare" {
  		t.Fatalf("unreached: %v", body["unreached"])
  	}
  	if w := f.post(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, ""); w.Code != http.StatusUnauthorized {
  		t.Fatalf("a mint after the revocation: %d", w.Code)
  	}
  	if got := testutil.ToFloat64(f.b.Metrics.Revocations.WithLabelValues("principal", "applied")); got != 1 {
  		t.Fatalf("port49_revocations_total{by=principal,outcome=applied} = %v", got)
  	}
  	text := rep.Text()
  	for _, want := range []string{"revoked user:alice@example.com", "2 live context(s) marked", "bare (alice)",
  		"port49 revoke --lift --principal user:alice@example.com"} {
  		if !strings.Contains(text, want) {
  			t.Fatalf("the text lacks %q:\n%s", want, text)
  		}
  	}
  }

  // A revocation by certificate reaches what that certificate minted and
  // logged into, and leaves the same principal's other certificate alone. A
  // serial typed in another case or with 0x is the same certificate, and a
  // repeat keeps the first mark's time.
  func TestRevokingACertificateReachesThatCertificateAlone(t *testing.T) {
  	f := newFixture(t, 8)
  	ctx := context.Background()
  	renewed := f.client(t, "alice@example.com", f.now.Add(2*time.Hour))
  	decodeMint(t, f.post(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, ""))
  	decodeMint(t, f.post(ctx, f.state(renewed), `{"devices":["nx1"]}`, ""))
  	f.liveContext(t, "leaf1", "alice", alicePrincipal, certKey(f.alice))
  	f.liveContext(t, "nx1", "alice", alicePrincipal, certKey(renewed))

  	req := RevokeRequest{Issuer: f.alice.Leaf.Issuer.String(), Serial: f.alice.Leaf.SerialNumber.Text(16), Origin: "t"}
  	rep, err := f.b.Revoke(ctx, req)
  	if err != nil || len(rep.Contexts) != 1 || rep.Contexts[0].NAS != "leaf1" || rep.TokenKeys != 1 {
  		t.Fatalf("%+v %v", rep, err)
  	}
  	if toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: "nx1", Username: "alice"}); len(toks) != 1 {
  		t.Fatal("the other certificate's token was deleted")
  	}
  	if w := f.post(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, ""); w.Code != http.StatusUnauthorized {
  		t.Fatalf("the revoked certificate minted: %d", w.Code)
  	}
  	if r := decodeMint(t, f.post(ctx, f.state(renewed), `{"devices":["leaf1"]}`, "")); r.Results[0].Verdict != "permit" {
  		t.Fatalf("the other certificate: %+v", r)
  	}
  	rec := eventsOf(f.records(t), "revoke")[0]
  	if _, named := rec["principal"]; named || rec["revocation"].(map[string]any)["serial"] != req.Serial {
  		t.Fatalf("a certificate's record names no principal and the serial: %v", rec)
  	}
  	f.advance(time.Minute)
  	again := req
  	again.Serial = "0X" + strings.ToUpper(req.Serial)
  	rep2, err := f.b.Revoke(ctx, again)
  	if err != nil || rep2.Mark.Key != rep.Mark.Key || !rep2.Mark.At.Equal(rep.Mark.At) {
  		t.Fatalf("the same certificate in another spelling: %+v %v", rep2.Mark, err)
  	}
  }

  type markFailingStore struct{ store.Store }

  func (markFailingStore) PutRevocation(context.Context, store.Revocation) error {
  	return errors.New("store: connection refused")
  }

  // A mark that cannot be written revokes nothing, and says so: nothing below
  // it may run without the mark that keeps a mint from undoing it.
  func TestAMarkThatCannotBeWrittenRevokesNothing(t *testing.T) {
  	f := newFixture(t, 8)
  	f.b.Store = markFailingStore{f.st}
  	f.liveContext(t, "leaf1", "alice", alicePrincipal, certKey(f.alice))
  	if _, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alicePrincipal}); err == nil ||
  		!strings.Contains(err.Error(), "nothing was revoked") {
  		t.Fatalf("%v", err)
  	}
  	if c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf1", Username: "alice"}); !c.RevokedAt.IsZero() {
  		t.Fatal("a context was marked without the mark")
  	}
  	if len(eventsOf(f.records(t), "revoke")) != 0 {
  		t.Fatal("a revocation that did not happen was recorded")
  	}
  }

  type indexFailingStore struct{ store.Store }

  func (indexFailingStore) TokensByPrincipal(context.Context, string) ([]store.TokenKey, error) {
  	return nil, errors.New("store: i/o timeout")
  }

  // A step that fails after the mark leaves the mark in force, and the
  // report, the record, the metric and the text say what was missed.
  func TestAPartialRevocationSaysWhatItMissed(t *testing.T) {
  	f := newFixture(t, 8)
  	f.b.Store = indexFailingStore{f.st}
  	rep, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alicePrincipal})
  	if err != nil || rep.Err == nil {
  		t.Fatalf("%+v %v", rep, err)
  	}
  	if _, err := f.st.GetRevocation(context.Background(), store.RevocationPrincipal, alicePrincipal); err != nil {
  		t.Fatalf("the mark is not in force: %v", err)
  	}
  	if body := eventsOf(f.records(t), "revoke")[0]["revocation"].(map[string]any); !strings.Contains(body["error"].(string), "i/o timeout") {
  		t.Fatalf("record: %v", body)
  	}
  	if got := testutil.ToFloat64(f.b.Metrics.Revocations.WithLabelValues("principal", "partial")); got != 1 {
  		t.Fatalf("partial: %v", got)
  	}
  	if !strings.Contains(rep.Text(), "incomplete:") || !strings.Contains(rep.Text(), "run the same command again") {
  		t.Fatal(rep.Text())
  	}
  }

  // A revocation the file could not keep is in force and says a restart
  // forgets it.
  func TestAnUnsavedRevocationSaysARestartForgetsIt(t *testing.T) {
  	f := newFixture(t, 8)
  	f.b.Persist = func(context.Context) error { return errors.New("no space left on device") }
  	rep, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alicePrincipal})
  	if err != nil || rep.Saved || rep.SaveErr == nil || !strings.Contains(rep.Text(), "NOT saved") {
  		t.Fatalf("%+v %v\n%s", rep, err, rep.Text())
  	}
  }

  // Lifting removes the mark, is recorded permit revocation_lifted, and the
  // principal mints again; lifting what is not in force is ErrNotRevoked.
  func TestLiftingARevocation(t *testing.T) {
  	f := newFixture(t, 8)
  	ctx := context.Background()
  	if _, err := f.b.Revoke(ctx, RevokeRequest{Principal: alicePrincipal}); err != nil {
  		t.Fatal(err)
  	}
  	rep, err := f.b.Lift(ctx, RevokeRequest{Principal: alicePrincipal, Origin: "admin_socket uid 0"})
  	if err != nil || !strings.Contains(rep.LiftedText(), "lifted") {
  		t.Fatalf("%+v %v", rep, err)
  	}
  	recs := eventsOf(f.records(t), "revoke")
  	if len(recs) != 2 || recs[1]["verdict"] != "permit" || recs[1]["reason"] != "revocation_lifted" {
  		t.Fatalf("%v", recs)
  	}
  	if r := decodeMint(t, f.post(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, "")); r.Results[0].Verdict != "permit" {
  		t.Fatalf("after the lift: %+v", r)
  	}
  	if _, err := f.b.Lift(ctx, RevokeRequest{Principal: alicePrincipal}); !errors.Is(err, ErrNotRevoked) {
  		t.Fatalf("lifting twice: %v", err)
  	}
  }

  // A revocation names a principal or a certificate, exactly one, in a form
  // a mark can hold.
  func TestABadRevocationIsRefused(t *testing.T) {
  	f := newFixture(t, 8)
  	for _, req := range []RevokeRequest{
  		{},
  		{Principal: alicePrincipal, Issuer: "CN=x", Serial: "1"},
  		{Issuer: "CN=x"},
  		{Serial: "1"},
  		{Principal: "user:alice\n@example.com"},
  		{Issuer: "CN=x", Serial: "not-hex"},
  		{Issuer: "CN=x\x00", Serial: "1"},
  		{Principal: "alice@example.com"}, // no prefix (pre-flight I2)
  		{Principal: "admin:alice"},
  	} {
  		if _, err := f.b.Revoke(context.Background(), req); !errors.Is(err, ErrBadRevocation) {
  			t.Errorf("%+v: %v", req, err)
  		}
  	}
  	f.b.Sessions = nil
  	if _, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alicePrincipal}); err == nil {
  		t.Fatal("a broker with no Sessions revoked rather than refusing (M12)")
  	}
  }

  // A principal is compared as Identity spells it: an address in capitals
  // marks the lower-case key, and a principal no subject names is still
  // marked, behind a warning that the spelling may be wrong (pre-flight I2).
  func TestAPrincipalIsSpelledAsTheBrokerSpellsIt(t *testing.T) {
  	f := newFixture(t, 8)
  	ctx := context.Background()
  	if _, err := f.b.Revoke(ctx, RevokeRequest{Principal: "user:Alice@Example.COM"}); err != nil {
  		t.Fatal(err)
  	}
  	if _, err := f.st.GetRevocation(ctx, store.RevocationPrincipal, alicePrincipal); err != nil {
  		t.Fatalf("the mark is not under the lower-case key: %v", err)
  	}
  	rep, err := f.b.Revoke(ctx, RevokeRequest{Principal: "user:alce@example.com"})
  	if err != nil {
  		t.Fatal(err)
  	}
  	if !strings.HasPrefix(rep.Text(), "no subject in the policy in force names user:alce@example.com") {
  		t.Fatalf("no warning first:\n%s", rep.Text())
  	}
  	if _, err := f.st.GetRevocation(ctx, store.RevocationPrincipal, "user:alce@example.com"); err != nil {
  		t.Fatal("the mark must still be written (deny more)")
  	}
  }

  // A serial is taken as openssl prints it, with colons, and a negative one
  // as Text(16) gives it (pre-flight M16, M17).
  func TestASerialIsTakenInTheSpellingsOperatorsHave(t *testing.T) {
  	for in, want := range map[string]string{"3F:9A:01": "3f9a01", "0x003f9a01": "3f9a01", "-1F": "-1f", "0": "0"} {
  		got, _, _, err := RevokeRequest{Issuer: "CN=x", Serial: in}.normal()
  		if err != nil || got.Serial != want {
  			t.Errorf("%q: %q %v, want %q", in, got.Serial, err, want)
  		}
  	}
  }

  // tokenGatedStore holds DeleteTokens until gate closes, so a redemption can
  // land between the token pass and the context pass.
  type tokenGatedStore struct {
  	store.Store
  	entered chan struct{}
  	gate    chan struct{}
  }

  func (g *tokenGatedStore) DeleteTokens(ctx context.Context, k store.TokenKey) error {
  	select {
  	case g.entered <- struct{}{}:
  	default:
  	}
  	<-g.gate
  	return g.Store.DeleteTokens(ctx, k)
  }

  // A token redeemed while the revocation runs, on a device with no live
  // context, writes a fresh context the first context read never saw; the
  // second context pass marks it (pre-flight I1; the session package
  // comment's hole).
  func TestAContextARedemptionWritesMidRevocationIsMarked(t *testing.T) {
  	f := newFixture(t, 8)
  	ctx := context.Background()
  	decodeMint(t, f.post(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, ""))
  	g := &tokenGatedStore{Store: f.st, entered: make(chan struct{}, 1), gate: make(chan struct{})}
  	f.b.Store = g
  	done := make(chan RevokeReport, 1)
  	go func() {
  		rep, _ := f.b.Revoke(ctx, RevokeRequest{Principal: alicePrincipal})
  		done <- rep
  	}()
  	<-g.entered
  	// The daemon's redemption, as authen writes it: join (a fresh context,
  	// none being live) and index.
  	k := store.ContextKey{NAS: "nx1", Username: "alice"}
  	login := store.Context{CtxID: "ctx_mid", Principal: alicePrincipal, Username: "alice", PrivLvl: 1,
  		AuthTime: f.now, RefreshedAt: f.now}
  	if _, err := store.JoinContext(ctx, f.st, k, login, f.now.Add(-time.Minute), f.now, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	if err := f.st.IndexContext(ctx, alicePrincipal, "", certKey(f.alice), store.ContextRef{NAS: "nx1", Username: "alice"},
  		time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	close(g.gate)
  	rep := <-done
  	if c, err := f.st.GetContext(ctx, k); err != nil || c.RevokedAt.IsZero() {
  		t.Fatalf("the context written mid-revocation is live and unrevoked: %+v %v", c, err)
  	}
  	if len(rep.Contexts) != 1 || rep.Contexts[0].NAS != "nx1" {
  		t.Fatalf("the report must count the second pass's context: %+v", rep.Contexts)
  	}
  }
  ```

  (Add `time` to the imports.) In `metrics_test.go`, touch and expect the three new metrics
  (`port49_revocations_total`, `port49_revocations_in_force`, `port49_revocations_file_failed`).

- [ ] **Step 3: Run them to see them fail.** `go test ./internal/broker/ -run 'Revok|Lift|Mark|Unsaved' -count=1`
  Expected: FAIL to compile.

- [ ] **Step 4: The decision vocabulary.** In `reasons.go`, add after `CredentialRevoked`'s
  declaration (keeping the file's comment style):

  ```go
  	// RevocationLifted: a revoke record for an operator lifting a revocation
  	// (spec §5.1.4, §5.7). A permit.
  	RevocationLifted Reason = "revocation_lifted"
  ```

  add `RevocationLifted` to `reasons`, and after `EventRefresh`:

  ```go
  // EventRevoke is a revocation by principal or by certificate, or one lifted
  // (spec §5.1.4, §5.7): deny credential_revoked, or permit revocation_lifted.
  const EventRevoke = "revoke"
  ```

  In `log.go`, add to `Record` after `Change`:

  ```go
  	// Revocation is the revoke record's body (spec §5.7).
  	Revocation *Revocation `json:"revocation,omitempty"`
  ```

  and after `Change`'s type:

  ```go
  // Revocation is what a revocation reached (spec §5.7): identity, never a
  // credential. A count of zero is absent.
  type Revocation struct {
  	By          string       `json:"by"`
  	Issuer      string       `json:"issuer,omitempty"`
  	Serial      string       `json:"serial,omitempty"`
  	At          string       `json:"at"`
  	Origin      string       `json:"origin,omitempty"`
  	Contexts    int          `json:"contexts,omitempty"`
  	TokenKeys   int          `json:"token_keys,omitempty"`
  	Connections int          `json:"connections,omitempty"`
  	Unreached   []ContextRef `json:"unreached,omitempty"`
  	Saved       bool         `json:"saved"`
  	Error       string       `json:"error,omitempty"`
  }

  // ContextRef names a live context without its ctx_id, which is sealed.
  type ContextRef struct {
  	Device   string `json:"device"`
  	Username string `json:"username"`
  }
  ```

- [ ] **Step 5: The metrics.** In `metrics.go`:

  ```go
  	// port49_revocations_total{by, outcome}: revocations by principal or by
  	// cert, applied, partial (the mark in force, a later step failed) or
  	// lifted (spec §5.1.4).
  	Revocations *prometheus.CounterVec
  	// port49_revocations_in_force{by}: marks standing now.
  	RevocationsInForce *prometheus.GaugeVec
  	// port49_revocations_file_failed: 1 while the last write of
  	// broker.revocations_file failed, so a restart would forget a mark.
  	RevocationsFileFailed prometheus.Gauge
  ```

  constructed with the names above (labels `by`, `outcome`; `by`), help text "Revocations by
  principal or certificate, by outcome.", "Revocation marks in force now.", "1 while
  broker.revocations_file could not be written; a restart would forget a revocation.", and
  registered.

- [ ] **Step 6: The broker's fields.** In `broker.go`'s `Broker`, after `Redact`:

  ```go
  	// Sessions marks a revoked principal's or certificate's live contexts
  	// and deletes their receipts (Revoke). Required for Revoke.
  	Sessions *session.Manager
  	// Conns closes a revoked principal's or certificate's held connections:
  	// the Listener this broker is served through. Nil closes none.
  	Conns ConnCloser
  	// Persist writes the marks in force to broker.revocations_file after
  	// every change. Nil keeps them in the store alone.
  	Persist func(context.Context) error
  ```

  and change the type's comment from "Every field is required." to "Every field is required but
  Redact, Conns and Persist."

- [ ] **Step 7: Revoke and Lift.** Create `internal/broker/revoke.go`:

  ```go
  package broker

  import (
  	"context"
  	"errors"
  	"fmt"
  	"strings"
  	"time"
  	"unicode/utf8"

  	"github.com/blanketfish/port49/internal/decision"
  	"github.com/blanketfish/port49/internal/printsafe"
  	"github.com/blanketfish/port49/internal/store"
  )

  // ErrBadRevocation is a revocation that names neither a principal nor a
  // certificate, or both, or one in a form no mark can hold.
  var ErrBadRevocation = errors.New("broker: a revocation names a principal, or a certificate's issuer and serial; exactly one")

  // ErrNotRevoked is a lift of a revocation that is not in force.
  var ErrNotRevoked = errors.New("broker: no such revocation is in force")

  // RevokeRequest is one revocation or lift (spec §5.1.4): of a principal, or
  // of one certificate by its issuer (RFC 2253, as Go prints it) and serial
  // (hex). Origin says who asked, for the record.
  type RevokeRequest struct {
  	Principal      string
  	Issuer, Serial string
  	Origin         string
  }

  // RevokeReport is what a revocation reached. Err is the first step after
  // the mark that did not finish: the mark stands, and the request can be run
  // again. SaveErr is broker.revocations_file's write. Unnamed is set when no
  // subject in the policy in force names the principal (pre-flight I2).
  type RevokeReport struct {
  	Request     RevokeRequest
  	Mark        store.Revocation
  	Contexts    []store.ContextRef
  	Unreached   []store.ContextRef
  	TokenKeys   int
  	Connections int
  	Saved       bool
  	SaveErr     error
  	Err         error
  	Unnamed     bool
  }

  // principalPrefixes are the forms Identity and the policy give a principal
  // (spec §2). Only user: is minted for today; the others are refused until
  // their verifier exists, rather than marked under a key nothing spells.
  var principalPrefixes = []string{"user:"}

  // normal checks req and puts it in the form a mark holds (pre-flight I2,
  // M16, M17): a principal as Identity spells it, user: and the lower-cased
  // email (the mapping is case-insensitive by construction), refusing one
  // without that prefix; an issuer of valid UTF-8 with no control character;
  // a serial in lower-case hex as big.Int.Text(16) prints it, which is what
  // Identity records: colons, a 0x and leading zeros are dropped, and a
  // leading - (a negative serial, which Go 1.22 still accepts) is kept.
  func (req RevokeRequest) normal() (RevokeRequest, string, string, error) {
  	byCert := req.Issuer != "" || req.Serial != ""
  	switch {
  	case (req.Principal != "") == byCert:
  		return req, "", "", ErrBadRevocation
  	case req.Principal != "":
  		if len(req.Principal) > 1024 || strings.IndexFunc(req.Principal, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
  			return req, "", "", fmt.Errorf("%w: a principal is printable ASCII", ErrBadRevocation)
  		}
  		for _, p := range principalPrefixes {
  			if strings.HasPrefix(strings.ToLower(req.Principal), p) {
  				req.Principal = p + strings.ToLower(req.Principal[len(p):])
  				return req, store.RevocationPrincipal, req.Principal, nil
  			}
  		}
  		return req, "", "", fmt.Errorf("%w: a principal begins %s, as the log names it (user:alice@example.com)",
  			ErrBadRevocation, strings.Join(principalPrefixes, " or "))
  	case req.Issuer == "" || req.Serial == "":
  		return req, "", "", fmt.Errorf("%w: a certificate is named by its issuer and its serial, both", ErrBadRevocation)
  	}
  	if len(req.Issuer) > 2048 || !utf8.ValidString(req.Issuer) ||
  		strings.IndexFunc(req.Issuer, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
  		return req, "", "", fmt.Errorf("%w: the issuer has a control character or is not UTF-8", ErrBadRevocation)
  	}
  	s := strings.ReplaceAll(strings.ToLower(req.Serial), ":", "")
  	neg := strings.HasPrefix(s, "-")
  	s = strings.TrimLeft(strings.TrimPrefix(strings.TrimPrefix(s, "-"), "0x"), "0")
  	if s == "" {
  		s, neg = "0", false
  	}
  	if len(s) > 64 || strings.Trim(s, "0123456789abcdef") != "" {
  		return req, "", "", fmt.Errorf("%w: a serial is hexadecimal", ErrBadRevocation)
  	}
  	if neg {
  		s = "-" + s
  	}
  	req.Serial = s
  	return req, store.RevocationCert, store.CertKey(req.Issuer, req.Serial), nil
  }

  // Revoke puts a mark in force and reaches everything it names (spec
  // §5.1.4, §13 decision 32). The mark is written first: from then on every
  // mint it names is refused, on every connection, and a mint that raced it
  // reads it again after its last token write (tokens). A mark that cannot be
  // written revokes nothing and is the error, naming the fallback. Then, in
  // order (pre-flight I1): the listener is told of the mark and the held
  // connections it names are closed; its unspent tokens are deleted, key by
  // key, through the token index; its live contexts are marked and its
  // principals' receipts deleted (session.Manager); and the context index is
  // read and marked again. Tokens go before contexts because a token redeemed
  // on a device with no live context writes a fresh context (the session
  // package comment); the second pass marks one a redemption in flight wrote.
  // A failure after the mark is the report's Err, the mark standing.
  //
  // A revocation by certificate that finds no live context deletes no
  // receipt (session.Manager reads the principals off the contexts). That
  // replays nothing: with no live context a retransmission is answered
  // token_spent, not from its receipt (spec §5.6).
  func (b *Broker) Revoke(ctx context.Context, req RevokeRequest) (RevokeReport, error) {
  	req, kind, key, err := req.normal()
  	if err != nil {
  		return RevokeReport{}, err
  	}
  	if b.Sessions == nil {
  		// A wiring fault, said rather than panicked on: the admin socket's
  		// goroutine shares the process with TACACS+ (M12).
  		return RevokeReport{}, errors.New("broker: revocation is not wired (no session manager); nothing was revoked")
  	}
  	now := b.Now()
  	if err := b.Store.PutRevocation(ctx, store.Revocation{Kind: kind, Key: key, At: now, Origin: req.Origin}); err != nil {
  		return RevokeReport{}, fmt.Errorf("broker: the revocation could not be recorded, so nothing was revoked (%w); "+
  			"cut access another way: remove the principal's grants from broker.policy_file (live within two watch "+
  			"intervals), or stop port49d", err)
  	}
  	rep := RevokeReport{Request: req, Mark: store.Revocation{Kind: kind, Key: key, At: now, Origin: req.Origin}}
  	if got, err := b.Store.GetRevocation(ctx, kind, key); err == nil {
  		rep.Mark = got // an earlier mark stands, with its own time
  	}
  	if kind == store.RevocationPrincipal {
  		_, named := b.Policy.Load().SubjectOf(key)
  		rep.Unnamed = !named
  	}
  	note := func(err error) {
  		if err != nil && rep.Err == nil {
  			rep.Err = err
  		}
  	}
  	rep.Saved, rep.SaveErr = b.persist(ctx)
  	if b.Conns != nil {
  		b.Conns.Revoked(kind, key, true)
  		rep.Connections = b.Conns.CloseHeld(func(principal, certKey string) bool {
  			if kind == store.RevocationPrincipal {
  				return principal == key
  			}
  			return certKey == key
  		})
  	}
  	var tokenKeys []store.TokenKey
  	if kind == store.RevocationPrincipal {
  		tokenKeys, err = b.Store.TokensByPrincipal(ctx, key)
  	} else {
  		tokenKeys, err = b.Store.TokensByCert(ctx, key)
  	}
  	note(err)
  	for _, k := range tokenKeys {
  		if err := b.Store.DeleteTokens(ctx, k); err != nil {
  			note(err)
  			continue
  		}
  		b.supersede(k, now)
  		rep.TokenKeys++
  	}
  	seen := map[store.ContextRef]bool{}
  	for pass := 0; pass < 2; pass++ {
  		var refs []store.ContextRef
  		if kind == store.RevocationPrincipal {
  			refs, err = b.Sessions.RevokeByPrincipal(ctx, key)
  		} else {
  			refs, err = b.Sessions.RevokeByCert(ctx, req.Issuer, req.Serial)
  		}
  		note(err)
  		for _, ref := range refs {
  			if !seen[ref] {
  				seen[ref] = true
  				rep.Contexts = append(rep.Contexts, ref)
  			}
  		}
  	}
  	pol := b.Policy.Load()
  	for _, ref := range rep.Contexts {
  		// A platform that never asks about a command keeps the live session
  		// whatever its context says (spec §13 decision 21), and a device the
  		// inventory gives no platform is assumed to, as the refresh assumes.
  		if dev, ok := pol.Device(ref.NAS); !ok || dev.Platform == "" || sessionOnly(pol, dev.Platform) {
  			rep.Unreached = append(rep.Unreached, ref)
  		}
  	}
  	outcome := "applied"
  	if rep.Err != nil {
  		outcome = "partial"
  	}
  	b.recordRevocation(now, rep, decision.VerdictDeny, decision.CredentialRevoked, outcome)
  	return rep, nil
  }

  // Lift removes a mark. The contexts it marked stay revoked until a login
  // whose token was minted after the lift joins them (spec §5.6).
  func (b *Broker) Lift(ctx context.Context, req RevokeRequest) (RevokeReport, error) {
  	req, kind, key, err := req.normal()
  	if err != nil {
  		return RevokeReport{}, err
  	}
  	cur, err := b.Store.GetRevocation(ctx, kind, key)
  	switch {
  	case errors.Is(err, store.ErrNotFound):
  		return RevokeReport{}, ErrNotRevoked
  	case err != nil:
  		return RevokeReport{}, fmt.Errorf("broker: reading the revocation: %w", err)
  	}
  	if err := b.Store.DeleteRevocation(ctx, kind, key); err != nil {
  		return RevokeReport{}, fmt.Errorf("broker: the revocation could not be lifted, and stands: %w", err)
  	}
  	if b.Conns != nil {
  		b.Conns.Revoked(kind, key, false)
  	}
  	rep := RevokeReport{Request: req, Mark: cur}
  	rep.Saved, rep.SaveErr = b.persist(ctx)
  	b.recordRevocation(b.Now(), rep, decision.VerdictPermit, decision.RevocationLifted, "lifted")
  	return rep, nil
  }

  // persist writes the marks in force to broker.revocations_file.
  func (b *Broker) persist(ctx context.Context) (bool, error) {
  	if b.Persist == nil {
  		return false, nil
  	}
  	if err := b.Persist(ctx); err != nil {
  		return false, err
  	}
  	return true, nil
  }

  func (b *Broker) recordRevocation(now time.Time, rep RevokeReport, verdict string, reason decision.Reason, outcome string) {
  	body := &decision.Revocation{By: rep.Mark.Kind, At: decision.FormatTime(rep.Mark.At), Origin: rep.Request.Origin,
  		Contexts: len(rep.Contexts), TokenKeys: rep.TokenKeys, Connections: rep.Connections, Saved: rep.Saved}
  	rec := decision.Record{TS: now, Event: decision.EventRevoke, Verdict: verdict, Reason: reason, Revocation: body}
  	if rep.Mark.Kind == store.RevocationPrincipal {
  		rec.Principal = rep.Request.Principal
  	} else {
  		body.Issuer, body.Serial = rep.Request.Issuer, rep.Request.Serial
  	}
  	for _, ref := range rep.Unreached {
  		body.Unreached = append(body.Unreached, decision.ContextRef{Device: ref.NAS, Username: ref.Username})
  	}
  	if rep.Err != nil {
  		body.Error = printsafe.Line(rep.Err.Error(), 300)
  	}
  	b.emit(rec)
  	b.Metrics.Revocations.WithLabelValues(rep.Mark.Kind, outcome).Inc()
  }

  // what names the revoked credential for a person. A serial is shown as
  // the broker compares it: lower-case hex, no colons, no leading zeros
  // (M23).
  func (r RevokeReport) what() string {
  	if r.Mark.Kind == store.RevocationPrincipal {
  		return r.Request.Principal
  	}
  	return fmt.Sprintf("the certificate issuer=%q serial=%s (as the broker compares it)", r.Request.Issuer,
  		r.Request.Serial)
  }

  // flags are the port49 revoke flags that name the same credential.
  func (r RevokeReport) flags() string {
  	if r.Mark.Kind == store.RevocationPrincipal {
  		return "--principal " + r.Request.Principal
  	}
  	return fmt.Sprintf("--cert-issuer %q --cert-serial %s", r.Request.Issuer, r.Request.Serial)
  }

  // Partial reports whether the revocation or lift is in force but did not
  // finish or was not saved: `port49 revoke` exits 3 on it (M10).
  func (r RevokeReport) Partial() bool { return r.Err != nil || r.SaveErr != nil }

  // Text is what `port49 revoke` prints for a revocation: a warning first when
  // the principal may be misspelled, what was revoked and what it reached,
  // the contexts it could not reach, then anything that did not finish.
  func (r RevokeReport) Text() string {
  	var b strings.Builder
  	nothing := len(r.Contexts) == 0 && r.TokenKeys == 0 && r.Connections == 0
  	if r.Mark.Kind == store.RevocationPrincipal && (r.Unnamed || nothing) {
  		lead := "nothing was found under " + r.Request.Principal
  		if r.Unnamed {
  			lead = "no subject in the policy in force names " + r.Request.Principal
  		}
  		fmt.Fprintf(&b, "%s; the broker spells a certificate's principal user:<lower-case email>, so check the "+
  			"spelling (the mark is written anyway)\n", lead)
  	}
  	mints := "by " + r.Request.Principal
  	if r.Mark.Kind == store.RevocationCert {
  		mints = "with this certificate"
  	}
  	fmt.Fprintf(&b, "revoked %s at %s: %d live context(s) marked, the unspent tokens under %d (device, username) "+
  		"key(s) deleted, %d held broker connection(s) closed; every mint %s is refused until `port49 revoke --lift %s`",
  		r.what(), r.Mark.At.UTC().Format(time.RFC3339), len(r.Contexts), r.TokenKeys, r.Connections, mints, r.flags())
  	if r.Mark.Kind == store.RevocationCert && nothing {
  		b.WriteString("\nnothing was found under this certificate; if it is in use, its issuer is likely spelled " +
  			"differently from the broker's (RFC 2253, as Go prints it: CN=Corp Issuing CA,O=Example): use --cert FILE")
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
  	if r.Err != nil {
  		fmt.Fprintf(&b, "\nincomplete: %v; the mark is in force — run the same command again, which repeats every "+
  			"step", r.Err)
  	}
  	return b.String()
  }

  // LiftedText is what `port49 revoke --lift` prints. An unsaved lift is the
  // reverse of an unsaved revocation: a restart puts the revocation back (M9).
  func (r RevokeReport) LiftedText() string {
  	var b strings.Builder
  	fmt.Fprintf(&b, "lifted the revocation of %s (in force since %s); mints are made for it again. Contexts it "+
  		"marked stay revoked until a login with a token minted from now joins them", r.what(),
  		r.Mark.At.UTC().Format(time.RFC3339))
  	if r.SaveErr != nil {
  		fmt.Fprintf(&b, "\nNOT saved to broker.revocations_file (%v): the lift is in force now, and a restart of "+
  			"port49d puts the revocation back", r.SaveErr)
  	}
  	return b.String()
  }

  // RevocationsText is what `port49 revoke --list` prints.
  func RevocationsText(rs []store.Revocation) string {
  	if len(rs) == 0 {
  		return "no revocation is in force"
  	}
  	var lines []string
  	for _, r := range rs {
  		what := "principal " + r.Key
  		if r.Kind == store.RevocationCert {
  			i := strings.LastIndex(r.Key, "|")
  			what = fmt.Sprintf("certificate issuer=%q serial=%s", r.Key[:i], r.Key[i+1:])
  		}
  		lines = append(lines, fmt.Sprintf("%s since %s (%s)", what, r.At.UTC().Format(time.RFC3339), r.Origin))
  	}
  	return strings.Join(lines, "\n")
  }
  ```

  (`RevocationsText` assumes `store.CertKey` joins with `|` and a serial holds none, which `normal`
  guarantees for every mark it writes. `SubjectOf(id) (string, bool)` is `policy.Policy`'s, as
  `tokens` uses it.)

  Replace the paragraph of `internal/session/session.go`'s package comment that begins "What
  revocation here does NOT do: it does not delete the principal's unredeemed tokens." with:

  ```go
  // What revocation here does NOT do: delete the principal's unredeemed
  // tokens. The broker does that, through the token index, before it calls
  // RevokeByPrincipal or RevokeByCert, and calls them twice (broker.Revoke,
  // plan 7a): a token deleted first cannot redeem into a fresh context the
  // marking missed, and the second pass marks a context a redemption already
  // in flight wrote. One window remains: a redemption that removed its token
  // before the broker's delete and writes its context after the second pass,
  // one store round trip wide. It writes a fresh context with no revoked_at.
  // Closing it needs the redemption and the revocation to meet atomically in
  // the store, which is plan 7d's.
  ```

- [ ] **Step 8: Run them.** `go test ./internal/broker/ ./internal/decision/ ./internal/daemon/metrics/ -count=1 -race`
  Expected: PASS. Then `gofmt -w`, `make build && make test && make vet`.

- [ ] **Step 9: Commit.**

  ```bash
  git add internal/broker internal/decision internal/daemon/metrics internal/session
  git commit -m "feat(broker): Revoke and Lift, reaching every connection, context and token a mark names

  The mark first, then the listener told and the held connections closed, the unspent tokens
  deleted through the token index, and the live contexts marked twice (a redemption in flight is
  caught); principals normalized as Identity spells them; one revoke record (deny credential_revoked, or permit
  revocation_lifted) naming what was reached and each context on a platform that never asks
  about a command. A mark that cannot be written revokes nothing.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
  ```

---

### Task 9: port49d serves the broker through the listener and keeps the marks across a restart

**Files:**
- Modify: `internal/fence/fence_linux.go`, `internal/fence/fence_other.go` (new `CheckDir`)
- Modify: `internal/config/config.go` (`BrokerConfig`; `Load`'s broker checks)
- Create: `cmd/port49d/revocations.go`
- Modify: `cmd/port49d/main.go` (`run`: the marks at start, `Sessions`, `Persist`, the listener and
  its copy of the marks)
- Modify: `tests/lab/slice/broker.yaml`, `tests/lab/quarantine/broker.yaml`,
  `tests/lab/inventory_test.go` (its two broker blocks): `revocations_file`
- Modify: `tests/lab/harness_test.go` (`privatePolicy` rewrites `revocations_file` into the private
  directory, pre-flight I6)
- Test: `internal/fence/fence_linux_test.go`, `internal/config/broker_test.go`,
  `internal/config/config_test.go` (its two inline broker blocks), `cmd/port49d/revocations_test.go`
  (new), `cmd/port49d/broker_test.go` (`brokerConfig`, `writeRunConfig`, the run-level restart test),
  `tests/lab/private_policy_unit_test.go`

**Interfaces:**
- Consumes: Tasks 5, 6, 8; `fence.ReadNoLink(path string, max int64, what string) ([]byte, error)`;
  `inventory.WriteAtomic(dir, name string, body []byte, mode os.FileMode) error`;
  `decision.FormatTime`.
- Produces:
  - `func fence.CheckDir(path, what string) error`: the directory that holds (or will hold) `path`
    exists, holds no refused link on the way, and is writable by this process's user or root alone.
  - `config.BrokerConfig.RevocationsFile string` (`revocations_file`, required),
    `MaxConnsPerPrincipal int` (`max_conns_per_principal`, default 4, 1–64),
    `MaxPendingConnsPerSource int` (`max_pending_conns_per_source`, default 16, 1–256)
  - `func loadRevocations(path string) (rs []store.Revocation, created bool, err error)`
  - `func saveRevocations(path string, rs []store.Revocation) error`
  - `func restoreRevocations(ctx context.Context, st store.Store, path string, m *metrics.Metrics) ([]store.Revocation, bool, error)`
  - `func persister(st store.Store, path string, m *metrics.Metrics) func(context.Context) error`
  - `func countRevocations(rs []store.Revocation, m *metrics.Metrics)`
  - The file: `{"revocations": [{"kind", "key", "at", "origin"}]}`, 0600, written atomically; its
    marker `<file>.created`, written once, before the file, at the first start (pre-flight C1).

- [ ] **Step 1: The fence's test.** In `internal/fence/fence_linux_test.go`, add:

  ```go
  // CheckDir asks the directory's question whether or not the file is there:
  // a missing file must not skip it (plan 7a, pre-flight C1).
  func TestCheckDirAsksOfTheDirectoryAlone(t *testing.T) {
  	dir := t.TempDir() // 0700, ours
  	if err := CheckDir(filepath.Join(dir, "absent.json"), "revocations file"); err != nil {
  		t.Fatalf("a private directory with no file yet: %v", err)
  	}
  	if err := CheckDir(filepath.Join(dir, "missing", "absent.json"), "revocations file"); err == nil {
  		t.Fatal("a missing directory passed")
  	}
  	open := filepath.Join(dir, "open")
  	if err := os.Mkdir(open, 0o700); err != nil {
  		t.Fatal(err)
  	}
  	if err := os.Chmod(open, 0o777); err != nil {
  		t.Fatal(err)
  	}
  	if err := CheckDir(filepath.Join(open, "absent.json"), "revocations file"); err == nil ||
  		!strings.Contains(err.Error(), "writable by others") {
  		t.Fatalf("a directory others can write: %v", err)
  	}
  }
  ```

- [ ] **Step 2: The config's tests.** In `internal/config/broker_test.go`, add
  `  revocations_file: /var/lib/port49/revocations.json` to `brokerBlock`, `"revocations_file"` to
  `TestABrokerBlockMissingAKeyIsRefused`'s list, and:

  ```go
  // The two caps default, and are bounded rather than clamped (spec §13
  // decision 32).
  func TestTheBrokerConnectionCapsAreBounded(t *testing.T) {
  	c, err := loadWith(t, brokerBlock)
  	if err != nil || c.Broker.MaxConnsPerPrincipal != 4 || c.Broker.MaxPendingConnsPerSource != 16 {
  		t.Fatalf("defaults: %+v %v", c.Broker, err)
  	}
  	for _, extra := range []string{"  max_conns_per_principal: 65\n", "  max_conns_per_principal: -1\n",
  		"  max_pending_conns_per_source: 257\n", "  max_pending_conns_per_source: -1\n"} {
  		key := strings.TrimSpace(strings.SplitN(extra, ":", 2)[0])
  		if _, err := loadWith(t, brokerBlock+extra); err == nil || !strings.Contains(err.Error(), "broker."+key) {
  			t.Errorf("%q: %v", extra, err)
  		}
  	}
  }

  // The revocations file is port49d's own state: it may be no other path
  // port49d reads or writes, compared as absolute paths (pre-flight M13).
  func TestTheRevocationsFileIsItsOwn(t *testing.T) {
  	for _, other := range []string{"/etc/port49/policy.yaml", "/etc/port49/broker-key.pem",
  		"/etc/port49/broker.pem", "/etc/port49/clients-ca.pem", "/etc/port49/../port49/policy.yaml"} {
  		block := strings.Replace(brokerBlock, "/var/lib/port49/revocations.json", other, 1)
  		if _, err := loadWith(t, block); err == nil || !strings.Contains(err.Error(), "broker.revocations_file") {
  			t.Errorf("revocations_file %s: %v", other, err)
  		}
  	}
  	block := strings.Replace(brokerBlock, "/var/lib/port49/revocations.json", "/var/lib/port49/acct.jsonl", 1)
  	if _, err := loadWith(t, block+"accounting: {spool_path: /var/lib/port49/acct.jsonl}\n"); err == nil {
  		t.Error("revocations_file is the accounting spool")
  	}
  }
  ```

  (If `sample` already carries an `accounting:` block, put the spool path there instead of appending
  a second one.) Add `revocations_file: r` to the two inline broker blocks in `config_test.go` (the
  lines ending `client_ca_file: ca, policy_file: p}`).

- [ ] **Step 3: The file's tests.** Create `cmd/port49d/revocations_test.go`:

  ```go
  package main

  import (
  	"context"
  	"os"
  	"path/filepath"
  	"strings"
  	"testing"
  	"time"

  	"github.com/prometheus/client_golang/prometheus"
  	"github.com/prometheus/client_golang/prometheus/testutil"

  	"github.com/blanketfish/port49/internal/daemon/metrics"
  	"github.com/blanketfish/port49/internal/store"
  	"github.com/blanketfish/port49/internal/store/memory"
  )

  func newMetrics() *metrics.Metrics { return metrics.New(prometheus.NewRegistry()) }

  // A mark put in force before a restart is in force after it: the file is
  // what a restart reads back (spec §13 decision 32).
  func TestRevocationsSurviveARestart(t *testing.T) {
  	ctx := context.Background()
  	path := filepath.Join(safeDir(t), "revocations.json")
  	if _, created, err := restoreRevocations(ctx, memory.New(time.Now), path, newMetrics()); err != nil || !created {
  		t.Fatalf("first start: %v %v", created, err)
  	}
  	at := time.Date(2026, 10, 2, 3, 12, 9, 0, time.UTC)
  	before := memory.New(time.Now)
  	for _, r := range []store.Revocation{
  		{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: at, Origin: "admin_socket uid 0"},
  		{Kind: store.RevocationCert, Key: store.CertKey("CN=Corp CA,O=Example", "3f9a01"), At: at, Origin: "admin_socket uid 0"},
  	} {
  		if err := before.PutRevocation(ctx, r); err != nil {
  			t.Fatal(err)
  		}
  	}
  	if err := persister(before, path, newMetrics())(ctx); err != nil {
  		t.Fatal(err)
  	}
  	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
  		t.Fatalf("the file: %v %v", fi, err)
  	}
  	after := memory.New(time.Now)
  	m := newMetrics()
  	rs, created, err := restoreRevocations(ctx, after, path, m)
  	if err != nil || created || len(rs) != 2 {
  		t.Fatalf("%d %v %v", len(rs), created, err)
  	}
  	got, err := after.GetRevocation(ctx, store.RevocationPrincipal, "user:alice@example.com")
  	if err != nil || !got.At.Equal(at) || got.Origin != "admin_socket uid 0" {
  		t.Fatalf("%+v %v", got, err)
  	}
  	if testutil.ToFloat64(m.RevocationsInForce.WithLabelValues("cert")) != 1 {
  		t.Fatal("port49_revocations_in_force{by=cert}")
  	}
  }

  // The first start writes the marker, then an empty file, and says so; a
  // later start that finds the file gone refuses, because "never written" and
  // "deleted" are no longer the same thing (pre-flight C1).
  func TestTheFirstStartCreatesTheFileAndALaterMissingOneRefuses(t *testing.T) {
  	path := filepath.Join(safeDir(t), "revocations.json")
  	rs, created, err := loadRevocations(path)
  	if err != nil || !created || len(rs) != 0 {
  		t.Fatalf("first start: %v %v %v", rs, created, err)
  	}
  	for _, p := range []string{path, path + ".created"} {
  		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
  			t.Fatalf("%s: %v %v", p, fi, err)
  		}
  	}
  	if _, created, err := loadRevocations(path); err != nil || created {
  		t.Fatalf("second start: %v %v", created, err)
  	}
  	if err := os.Remove(path); err != nil {
  		t.Fatal(err)
  	}
  	if _, _, err := loadRevocations(path); err == nil || !strings.Contains(err.Error(), "is missing") {
  		t.Fatalf("a deleted file after the first start: %v", err)
  	}
  }

  // The directory is fenced whether or not the file exists: a missing
  // directory, or one others can write, refuses the start before "missing"
  // can mean anything (pre-flight C1).
  func TestTheDirectoryIsFencedWithOrWithoutTheFile(t *testing.T) {
  	if _, _, err := loadRevocations(filepath.Join(safeDir(t), "missing", "revocations.json")); err == nil {
  		t.Fatal("a missing directory read as no revocations")
  	}
  	open := safeDir(t)
  	if err := os.Chmod(open, 0o777); err != nil {
  		t.Fatal(err)
  	}
  	if _, _, err := loadRevocations(filepath.Join(open, "revocations.json")); err == nil {
  		t.Fatal("a missing file in a directory others can write read as no revocations")
  	}
  }

  // A file port49d cannot read whole refuses the start: a port49d that
  // forgot a revocation would mint for a stolen certificate again.
  func TestARevocationsFileThatDoesNotLoadRefusesTheStart(t *testing.T) {
  	for name, body := range map[string]string{
  		"not json":      "{",
  		"unknown field": `{"revocations":[],"extra":1}`,
  		"unknown kind":  `{"revocations":[{"kind":"sid","key":"x","at":"2026-10-02T03:12:09Z","origin":"o"}]}`,
  		"empty key":     `{"revocations":[{"kind":"principal","key":"","at":"2026-10-02T03:12:09Z","origin":"o"}]}`,
  		"bad time":      `{"revocations":[{"kind":"principal","key":"user:a@b","at":"yesterday","origin":"o"}]}`,
  		"control char":  `{"revocations":[{"kind":"principal","key":"user:a\n@b","at":"2026-10-02T03:12:09Z","origin":"o"}]}`,
  	} {
  		path := filepath.Join(safeDir(t), "revocations.json")
  		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
  			t.Fatal(err)
  		}
  		if _, _, err := loadRevocations(path); err == nil {
  			t.Errorf("%s: loaded", name)
  		}
  	}
  }

  // The file decides who is refused, so it is read behind the fence: one
  // another user could write is refused, and so is a link in its name.
  func TestARevocationsFileOthersCouldWriteIsRefused(t *testing.T) {
  	dir := safeDir(t)
  	path := filepath.Join(dir, "revocations.json")
  	if err := os.WriteFile(path, []byte(`{"revocations":[]}`), 0o600); err != nil {
  		t.Fatal(err)
  	}
  	if err := os.Chmod(path, 0o622); err != nil {
  		t.Fatal(err)
  	}
  	if _, _, err := loadRevocations(path); err == nil {
  		t.Fatal("a world-writable revocations file loaded")
  	}
  	link := filepath.Join(dir, "linked.json")
  	if err := os.Symlink(path, link); err != nil {
  		t.Fatal(err)
  	}
  	if _, _, err := loadRevocations(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
  		t.Fatalf("a link: %v", err)
  	}
  }

  // A write that fails raises port49_revocations_file_failed; the next that
  // succeeds lowers it.
  func TestAFailedWriteIsAlarmed(t *testing.T) {
  	m := newMetrics()
  	st := memory.New(time.Now)
  	if err := persister(st, filepath.Join(safeDir(t), "missing", "revocations.json"), m)(context.Background()); err == nil {
  		t.Fatal("a write into a missing directory succeeded")
  	}
  	if testutil.ToFloat64(m.RevocationsFileFailed) != 1 {
  		t.Fatal("not alarmed")
  	}
  	if err := persister(st, filepath.Join(safeDir(t), "revocations.json"), m)(context.Background()); err != nil {
  		t.Fatal(err)
  	}
  	if testutil.ToFloat64(m.RevocationsFileFailed) != 0 {
  		t.Fatal("not cleared")
  	}
  }
  ```

  In `broker_test.go`, give `brokerConfig`'s `BrokerConfig` `RevocationsFile: filepath.Join(dir,
  "revocations.json"), MaxConnsPerPrincipal: 4, MaxPendingConnsPerSource: 16`, and add
  `  revocations_file: %s` (with `b.RevocationsFile`) to `writeRunConfig`'s broker block.

- [ ] **Step 4: The run-level restart test** (pre-flight I7). In `cmd/port49d/broker_test.go`, add:

  ```go
  // run restores the marks before the broker serves a request, and refuses
  // to start on a file it cannot load or a directory others can write: the
  // wiring is the point of the file, and a unit test of loadRevocations
  // would pass with the restore moved after Serve (pre-flight I7).
  func TestRunRestoresRevocationsBeforeTheBrokerServes(t *testing.T) {
  	t.Run("a mark in the file refuses the first mint", func(t *testing.T) {
  		var out syncBuffer
  		e := stderr
  		t.Cleanup(func() { stderr = e })
  		stderr = &out
  		b := brokerConfig(t, minimalPolicy).Broker
  		if err := os.WriteFile(b.RevocationsFile+".created", []byte("x\n"), 0o600); err != nil {
  			t.Fatal(err)
  		}
  		if err := os.WriteFile(b.RevocationsFile, []byte(`{"revocations":[{"kind":"principal",`+
  			`"key":"user:alice@example.com","at":"2026-10-02T03:12:09Z","origin":"admin_socket uid 0"}]}`), 0o600); err != nil {
  			t.Fatal(err)
  		}
  		cfgPath := writeRunConfig(t, b)
  		ctx, cancel := context.WithCancel(context.Background())
  		done := make(chan error, 1)
  		go func() { done <- run(ctx, cfgPath) }()
  		t.Cleanup(func() {
  			cancel()
  			select {
  			case <-done:
  			case <-time.After(10 * time.Second):
  			}
  		})
  		waitFor(t, &out, "port49d: broker: 1 revocation(s) in force from "+b.RevocationsFile)
  		waitFor(t, &out, "port49d: broker listening on ")
  		addr := regexp.MustCompile(`port49d: broker listening on (\S+)`).FindStringSubmatch(out.String())[1]
  		pki := filepath.Dir(b.ClientCAFile)
  		alice, err := tls.LoadX509KeyPair(filepath.Join(pki, testpki.LabClientCert), filepath.Join(pki, testpki.LabClientKey))
  		if err != nil {
  			t.Fatal(err)
  		}
  		pool := x509.NewCertPool()
  		caPEM, _ := os.ReadFile(b.ClientCAFile)
  		pool.AppendCertsFromPEM(caPEM)
  		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{alice},
  			RootCAs: pool, MinVersion: tls.VersionTLS13, ServerName: "127.0.0.1"}}}
  		resp, err := c.Post("https://"+addr+"/v1/tokens", "application/json", strings.NewReader(`{"devices":["leaf1"]}`))
  		if err != nil {
  			t.Fatal(err)
  		}
  		body, _ := io.ReadAll(resp.Body)
  		resp.Body.Close()
  		if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(body), "credential_revoked") {
  			t.Fatalf("the first mint after a restart with alice revoked: %s %s", resp.Status, body)
  		}
  	})
  	for name, prepare := range map[string]func(t *testing.T, b *config.BrokerConfig){
  		"a file that does not parse": func(t *testing.T, b *config.BrokerConfig) {
  			_ = os.WriteFile(b.RevocationsFile+".created", []byte("x\n"), 0o600)
  			if err := os.WriteFile(b.RevocationsFile, []byte("{"), 0o600); err != nil {
  				t.Fatal(err)
  			}
  		},
  		"a file deleted after the first start": func(t *testing.T, b *config.BrokerConfig) {
  			if err := os.WriteFile(b.RevocationsFile+".created", []byte("x\n"), 0o600); err != nil {
  				t.Fatal(err)
  			}
  		},
  		"a directory others can write": func(t *testing.T, b *config.BrokerConfig) {
  			if err := os.Chmod(filepath.Dir(b.RevocationsFile), 0o777); err != nil {
  				t.Fatal(err)
  			}
  		},
  	} {
  		t.Run(name, func(t *testing.T) {
  			b := brokerConfig(t, minimalPolicy).Broker
  			// Its own directory, so the chmod case does not loosen the
  			// directory holding the policy and the PKI.
  			own := safeDir(t)
  			b.RevocationsFile = filepath.Join(own, "revocations.json")
  			prepare(t, b)
  			out, err := runExpectingRefusal(t, writeRunConfig(t, b))
  			if err == nil || !strings.Contains(err.Error(), "broker.revocations_file "+b.RevocationsFile) {
  				t.Fatalf("run: %v", err)
  			}
  			if strings.Contains(out, "listening") {
  				t.Fatalf("stderr claims a listener is up: %q", out)
  			}
  		})
  	}
  }
  ```

  (Imports as `admin_linux_test.go` has them: `crypto/tls`, `crypto/x509`, `io`, `net/http`,
  `regexp`, `testpki`. If `brokerConfig`'s directory is `t.TempDir()`'s 0700, the first subtest's
  file passes the fence as written.)

- [ ] **Step 5: The lab's private copy** (pre-flight I6). In `tests/lab/private_policy_unit_test.go`,
  give the broker block `"  revocations_file: tests/lab/logs/revocations-slice.json\n"`, plant a stale
  `filepath.Join(dir, "revocations.json")` and its `.created` marker before the call, and require
  that the output holds `"\n  revocations_file: "+filepath.Join(dir, "revocations.json")+"\n"` and
  that neither stale file is left. In `tests/lab/harness_test.go`'s `privatePolicy`, after the
  `policy_file` copy succeeds, add:

  ```go
  	// The revocations file is port49d's own state behind the same fence
  	// (plan 7a): tests/lab/logs is 0775 under the desktop umask and would
  	// refuse the start, and a mark one run left would refuse the next run's
  	// mints. It goes in the private directory, fresh at every derived
  	// config: the first start creates it (pre-flight I6).
  	if i := strings.Index(cfg, "  revocations_file: "); i >= 0 {
  		j := strings.Index(cfg[i:], "\n")
  		if j < 0 {
  			j = len(cfg) - i
  		}
  		dst := filepath.Join(dir, "revocations.json")
  		for _, p := range []string{dst, dst + ".created"} {
  			if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
  				return "", err
  			}
  		}
  		cfg = cfg[:i] + "  revocations_file: " + dst + cfg[i+j:]
  	}
  ```

  `tests/lab/inventory_test.go`'s two blocks already write into the run's private directory: give
  each a `revocations_file:` there, beside its `policy_file:`. In `tests/lab/slice/broker.yaml` and
  `tests/lab/quarantine/broker.yaml` add `  revocations_file: tests/lab/logs/revocations.json` (the
  value is rewritten by `privatePolicy`; the line must exist for `config.Load`). Check the lab
  package with `go vet -tags lab ./tests/lab/`.

- [ ] **Step 6: Run them to see them fail.** `go test ./internal/fence/ ./internal/config/ ./cmd/port49d/ -run 'CheckDir|Revocation|Caps|ItsOwn|AFailedWrite|FirstStart|Fenced' -count=1`
  Expected: FAIL to compile.

- [ ] **Step 7: The fence.** In `internal/fence/fence_linux.go`, after `ReadNoLink`:

  ```go
  // CheckDir asks Read's question of the directory that holds, or will hold,
  // path: it exists, every link on the way to it passes the fence, and it is
  // writable by this process's user or root alone. It is asked whether or not
  // the file is there, so a missing file in a directory others can write is
  // refused rather than read as "nothing yet" (plan 7a, pre-flight C1).
  func CheckDir(path, what string) error {
  	abs, err := filepath.Abs(path)
  	if err != nil {
  		return err
  	}
  	dir, err := resolvePolicyPath(filepath.Dir(abs))
  	if err != nil {
  		return err
  	}
  	d, di, err := openDir(dir)
  	if err != nil {
  		return err
  	}
  	defer d.Close()
  	return writableByUsAlone("the directory "+dir+", holding the "+what, di)
  }
  ```

  and in `fence_other.go`:

  ```go
  // CheckDir refuses off Linux, as Read does.
  func CheckDir(_ string, what string) error {
  	return errors.New("port49 keeps " + what + " on Linux only: the check of who could write it is Linux's")
  }
  ```

- [ ] **Step 8: The config.** In `config.go`'s `BrokerConfig`, after `PolicyWatchInterval`:

  ```go
  	// RevocationsFile is where port49d keeps the revocations `port49 revoke`
  	// puts in force (plan 7a), so a restart forgets none. Required. Its
  	// directory must exist and be writable by port49d's user or root alone,
  	// and the file's own name may not be a link. port49d creates it at the
  	// first start, with a marker beside it (<file>.created); after that a
  	// missing file, or one that does not load, refuses the start, and so does
  	// a directory others can write (spec §13 decision 32). port49d writes it,
  	// 0600 and atomically, after every revocation and lift.
  	RevocationsFile string `yaml:"revocations_file"`
  	// MaxConnsPerPrincipal caps one principal's held broker connections; a
  	// new one closes the oldest of its certificate, else the principal's
  	// oldest (spec §13 decision 32). Default 4; 1 to 64.
  	MaxConnsPerPrincipal int `yaml:"max_conns_per_principal"`
  	// MaxPendingConnsPerSource caps the broker connections one address holds
  	// that are not bound to a principal; the next is reset. Default 16; 1 to
  	// 256.
  	MaxPendingConnsPerSource int `yaml:"max_pending_conns_per_source"`
  ```

  and in `BrokerConfig`'s comment replace "Certificate revocation is plan 7." with "To end a
  principal's or a certificate's sessions at once, use `port49 revoke` over `admin_socket` (plan
  7a)." In `Load`, add `{"broker.revocations_file", b.RevocationsFile}` to the required list, and after
  the `PolicyWatchInterval` check:

  ```go
  		// orI maps 0 alone to the default, so a negative value reaches the
  		// bound and is refused.
  		b.MaxConnsPerPrincipal = orI(b.MaxConnsPerPrincipal, 4)
  		if b.MaxConnsPerPrincipal < 1 || b.MaxConnsPerPrincipal > 64 {
  			return Config{}, fmt.Errorf("config: broker.max_conns_per_principal must be between 1 and 64; got %d",
  				b.MaxConnsPerPrincipal)
  		}
  		b.MaxPendingConnsPerSource = orI(b.MaxPendingConnsPerSource, 16)
  		if b.MaxPendingConnsPerSource < 1 || b.MaxPendingConnsPerSource > 256 {
  			return Config{}, fmt.Errorf("config: broker.max_pending_conns_per_source must be between 1 and 256; got %d",
  				b.MaxPendingConnsPerSource)
  		}
  		// port49d's own state may be no other path it reads or writes,
  		// compared as absolute paths (pre-flight M13): written over the policy
  		// or a key it would destroy it, and a file shared with another writer
  		// is not the record of revocations.
  		revAbs, err := filepath.Abs(b.RevocationsFile)
  		if err != nil {
  			return Config{}, fmt.Errorf("config: broker.revocations_file: %w", err)
  		}
  		others := []struct{ key, path string }{
  			{"broker.policy_file", b.PolicyFile}, {"broker.tls_cert_file", b.TLSCertFile},
  			{"broker.tls_key_file", b.TLSKeyFile}, {"broker.client_ca_file", b.ClientCAFile},
  			{"inventory_file", f.InventoryFile}, {"accounting.spool_path", c.Accounting.SpoolPath},
  			{"admin_socket", f.AdminSocket},
  		}
  		if c.Lab != nil {
  			others = append(others, struct{ key, path string }{"lab.seed_token_file", c.Lab.SeedTokenFile},
  				struct{ key, path string }{"lab.fault_file", c.Lab.FaultFile})
  		}
  		for _, o := range others {
  			if o.path == "" {
  				continue
  			}
  			if oAbs, err := filepath.Abs(o.path); err == nil && oAbs == revAbs {
  				return Config{}, fmt.Errorf("config: broker.revocations_file is port49d's own state and may not be "+
  					"%s", o.key)
  			}
  		}
  ```

  and, after `checkService` has set `c.InventoryService`, refuse a `broker.revocations_file`
  inside its `StateDir` or `MirrorDir` (`within(dir, revAbs)`, the helper `checkService` already
  uses) with the same message naming the key: the service and port49d rewrite those directories'
  files. (`c.Accounting.SpoolPath` is defaulted at the top of `Load`, before the broker block, so the
  comparison sees the default `/var/lib/port49/acct.jsonl` too.)

- [ ] **Step 9: The file.** Create `cmd/port49d/revocations.go`:

  ```go
  package main

  import (
  	"bytes"
  	"context"
  	"encoding/json"
  	"errors"
  	"fmt"
  	"io/fs"
  	"os"
  	"path/filepath"
  	"strings"
  	"sync"
  	"time"
  	"unicode/utf8"

  	"github.com/blanketfish/port49/internal/daemon/metrics"
  	"github.com/blanketfish/port49/internal/decision"
  	"github.com/blanketfish/port49/internal/fence"
  	"github.com/blanketfish/port49/internal/inventory"
  	"github.com/blanketfish/port49/internal/store"
  )

  // revocationsFile is broker.revocations_file (plan 7a): the marks in force,
  // so a restart forgets none. snake_case, like every file port49 writes.
  type revocationsFile struct {
  	Revocations []revocationEntry `json:"revocations"`
  }

  type revocationEntry struct {
  	Kind   string `json:"kind"`
  	Key    string `json:"key"`
  	At     string `json:"at"`
  	Origin string `json:"origin"`
  }

  const maxRevocationsFile = 1 << 20

  // markerOf is the file that says revocations_file was created once, so a
  // missing file beside it was lost, not never written (pre-flight C1).
  func markerOf(path string) string { return path + ".created" }

  // loadRevocations reads the file behind the write fence, its own name never
  // a link (fence.ReadNoLink): whoever could write it could lift a revocation
  // at the next restart. The directory is fenced first, whether or not the
  // file is there (fence.CheckDir): a missing directory, or one others can
  // write, refuses the start. With neither the file nor its marker present it
  // is the first start: the marker is written, then an empty file, and
  // created is true. With the marker present a missing file refuses the
  // start. Anything else it cannot read whole is an error, which refuses it.
  func loadRevocations(path string) ([]store.Revocation, bool, error) {
  	if err := fence.CheckDir(path, "revocations file"); err != nil {
  		return nil, false, err
  	}
  	raw, err := fence.ReadNoLink(path, maxRevocationsFile, "revocations file")
  	if errors.Is(err, fs.ErrNotExist) {
  		switch _, merr := os.Lstat(markerOf(path)); {
  		case merr == nil:
  			return nil, false, errors.New(`is missing; port49d will not start without the revocations it held: ` +
  				`restore it, or write {"revocations": []} on purpose`)
  		case !errors.Is(merr, fs.ErrNotExist):
  			return nil, false, merr
  		}
  		abs, err := filepath.Abs(path)
  		if err != nil {
  			return nil, false, err
  		}
  		// The marker first: a crash between the two leaves a marker and no
  		// file, which refuses the next start, never one that reads as new.
  		if err := inventory.WriteAtomic(filepath.Dir(abs), filepath.Base(markerOf(abs)),
  			[]byte("port49d created "+filepath.Base(abs)+" at "+decision.FormatTime(time.Now())+"\n"), 0o600); err != nil {
  			return nil, false, err
  		}
  		if err := saveRevocations(abs, nil); err != nil {
  			return nil, false, err
  		}
  		return nil, true, nil
  	}
  	if err != nil {
  		return nil, false, err
  	}
  	var f revocationsFile
  	dec := json.NewDecoder(bytes.NewReader(raw))
  	dec.DisallowUnknownFields()
  	if err := dec.Decode(&f); err != nil {
  		return nil, false, fmt.Errorf("does not load as a revocations file (%v); port49d will not start without "+
  			`the revocations it holds: restore it, or write {"revocations": []} on purpose`, err)
  	}
  	out := make([]store.Revocation, 0, len(f.Revocations))
  	for i, e := range f.Revocations {
  		at, err := time.Parse(time.RFC3339Nano, e.At)
  		switch {
  		case e.Kind != store.RevocationPrincipal && e.Kind != store.RevocationCert:
  			return nil, false, fmt.Errorf("revocation %d: kind must be principal or cert", i)
  		case e.Key == "" || len(e.Key) > 4096 || !utf8.ValidString(e.Key) ||
  			strings.IndexFunc(e.Key, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0:
  			return nil, false, fmt.Errorf("revocation %d: its key is empty, too long, or not printable", i)
  		case err != nil:
  			return nil, false, fmt.Errorf("revocation %d: at is not an RFC 3339 time", i)
  		}
  		out = append(out, store.Revocation{Kind: e.Kind, Key: e.Key, At: at, Origin: e.Origin})
  	}
  	return out, false, nil
  }

  // saveRevocations writes rs whole, 0600, atomically: a reader sees the old
  // file or the new one.
  func saveRevocations(path string, rs []store.Revocation) error {
  	f := revocationsFile{Revocations: []revocationEntry{}}
  	for _, r := range rs {
  		f.Revocations = append(f.Revocations, revocationEntry{Kind: r.Kind, Key: r.Key,
  			At: decision.FormatTime(r.At), Origin: r.Origin})
  	}
  	body, err := json.MarshalIndent(f, "", "  ")
  	if err != nil {
  		return err
  	}
  	abs, err := filepath.Abs(path)
  	if err != nil {
  		return err
  	}
  	return inventory.WriteAtomic(filepath.Dir(abs), filepath.Base(abs), append(body, '\n'), 0o600)
  }

  // restoreRevocations puts every mark in the file in force in st, before
  // the broker serves a request, counts them, and returns them for the
  // listener's copy. created is the first start's.
  func restoreRevocations(ctx context.Context, st store.Store, path string, m *metrics.Metrics) ([]store.Revocation, bool, error) {
  	rs, created, err := loadRevocations(path)
  	if err != nil {
  		return nil, false, err
  	}
  	for _, r := range rs {
  		if err := st.PutRevocation(ctx, r); err != nil {
  			return nil, false, err
  		}
  	}
  	countRevocations(rs, m)
  	return rs, created, nil
  }

  // persister is Broker.Persist: it lists every mark in force and writes the
  // file, one writer at a time and listing under the lock, so the last write
  // holds every mark put before it.
  func persister(st store.Store, path string, m *metrics.Metrics) func(context.Context) error {
  	var mu sync.Mutex
  	return func(ctx context.Context) error {
  		mu.Lock()
  		defer mu.Unlock()
  		rs, err := st.ListRevocations(ctx)
  		if err == nil {
  			countRevocations(rs, m)
  			err = saveRevocations(path, rs)
  		}
  		if err != nil {
  			m.RevocationsFileFailed.Set(1)
  			return fmt.Errorf("%s: %w", path, err)
  		}
  		m.RevocationsFileFailed.Set(0)
  		return nil
  	}
  }

  func countRevocations(rs []store.Revocation, m *metrics.Metrics) {
  	n := map[string]int{store.RevocationPrincipal: 0, store.RevocationCert: 0}
  	for _, r := range rs {
  		n[r.Kind]++
  	}
  	for by, c := range n {
  		m.RevocationsInForce.WithLabelValues(by).Set(float64(c))
  	}
  }
  ```

- [ ] **Step 10: The wiring.** In `cmd/port49d/main.go`'s `run`:

  Replace the three lines `// Plan 7's broker exposes Refresh, …` through `_ = sessions` with:

  ```go
  	// The broker marks a revoked principal's or certificate's live contexts
  	// through the Manager (plan 7a); Refresh behind /v1/refresh is plan 7b's.
  	sessions := session.New(st, time.Now, cfg.ContextIdleTTL, cfg.Session.IndexTTL)
  ```

  After `buildBroker` returns (and after `persistStart`), add:

  ```go
  	var marks []store.Revocation
  	if brk != nil {
  		brk.Sessions = sessions
  		// Every mark in the file is in force before the broker serves a
  		// request: a port49d that forgot a revocation would mint for a stolen
  		// certificate again (spec §13 decision 32).
  		var created bool
  		marks, created, err = restoreRevocations(ctx, st, cfg.Broker.RevocationsFile, m)
  		if err != nil {
  			stopSpool()
  			<-spoolDone
  			return fmt.Errorf("broker.revocations_file %s: %w", cfg.Broker.RevocationsFile, err)
  		}
  		brk.Persist = persister(st, cfg.Broker.RevocationsFile, m)
  		if created {
  			fmt.Fprintf(stderr, "port49d: broker: created %s (no revocations); if this is not a first install, "+
  				"stop port49d and restore the file\n", cfg.Broker.RevocationsFile)
  		} else {
  			fmt.Fprintf(stderr, "port49d: broker: %d revocation(s) in force from %s\n", len(marks),
  				cfg.Broker.RevocationsFile)
  		}
  	}
  ```

  Where the broker's listener is bound (`if bln, err = net.Listen("tcp", brokerSrv.Addr)`), after the
  bind succeeds, add:

  ```go
  		// Capped globally, so connections to the broker cannot take the file
  		// descriptors the TACACS+ listener needs (pre-flight F1), and per
  		// source and per principal before that (spec §13 decision 32). It
  		// accepts from now; Serve below takes what it has handshaken. It is
  		// given the marks restored above before it accepts anything, so a
  		// revoked certificate is closed at bind from the first connection.
  		bl = broker.NewListener(broker.Limit(bln, broker.MaxConns), brokerSrv.TLSConfig,
  			broker.ListenerLimits{MaxPendingPerSource: cfg.Broker.MaxPendingConnsPerSource,
  				MaxPerPrincipal: cfg.Broker.MaxConnsPerPrincipal,
  				HandshakeTimeout: broker.DefaultListenerLimits.HandshakeTimeout},
  			m, time.Now, func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) })
  		for _, r := range marks {
  			bl.Revoked(r.Kind, r.Key, true)
  		}
  		brk.Conns = bl
  ```

  declaring `var bl *broker.Listener` beside `var bln net.Listener`, and replace
  `go func() { brokerErr <- brokerSrv.ServeTLS(broker.Limit(bln, broker.MaxConns), "", "") }()` and
  its comment with `go func() { brokerErr <- brokerSrv.Serve(bl) }()`. (`NewListener` starts its
  accept loop at once; a connection that binds in the moment before the `Revoked` loop runs is
  still refused at its first mint, which reads the store.) The error paths that close `bln` stay:
  closing it ends the listener's accept loop, which closes the listener.

- [ ] **Step 11: Run them.** `go test ./internal/fence/ ./internal/config/ ./cmd/port49d/ -count=1 -race`
  Expected: PASS, every `run` test included (they now serve through the listener and create the
  revocations file at their first start). Then `go vet -tags lab ./tests/lab/`, `gofmt -w`,
  `make build && make test && make vet`.

- [ ] **Step 12: Commit.**

  ```bash
  git add internal/fence internal/config cmd/port49d tests/lab/slice/broker.yaml tests/lab/quarantine/broker.yaml \
    tests/lab/inventory_test.go tests/lab/harness_test.go tests/lab/private_policy_unit_test.go
  git commit -m "feat(port49d): serve the broker through its listener and keep revocations across restarts

  broker.revocations_file is required with a broker; its directory is fenced whether or not
  the file exists; the first start creates it beside a marker, and after that a missing file,
  one that does not load, or a directory others can write refuses the start. It is written
  atomically after every change, raising port49_revocations_file_failed when it cannot be.
  The listener gets the restored marks. broker.max_conns_per_principal (4) and
  broker.max_pending_conns_per_source (16) bound it. The lab keeps the file in its private
  directory.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
  ```

---

### Task 10: The admin socket revokes, lifts and lists

**Files:**
- Modify: `internal/daemon/admin/admin.go` (`Request`, `RevokeOp`, `Server`, `handle`, `answer`)
- Modify: `internal/daemon/admin/peer_linux.go`, `peer_other.go` (`peerAllowed` returns the uid)
- Modify: `cmd/port49d/revocations.go` (`adminRevoke`, `adminRevocations`)
- Modify: `cmd/port49d/main.go` (the admin server's two funcs; its start line)
- Test: `internal/daemon/admin/admin_test.go`, `cmd/port49d/admin_linux_test.go`

**Interfaces:**
- Consumes: Task 8's `Revoke`, `Lift`, `Text`, `LiftedText`, `RevocationsText`.
- Produces:
  - `admin.Request` gains `Principal`, `CertIssuer`, `CertSerial string` (`principal`,
    `cert_issuer`, `cert_serial`) and `Lift bool` (`lift`); ops `revoke` and `revocations`.
  - `type admin.RevokeOp struct { Principal, Issuer, Serial string; Lift bool; UID uint32 }`
  - `admin.Server` gains `Revoke func(context.Context, RevokeOp) (text string, partial bool, err error)`
    and `Revocations func(context.Context) (string, error)`.
  - `admin.Response` gains `Partial bool` (`partial`): a revocation or lift in force but incomplete or
    unsaved (`RevokeReport.Partial`), which `port49 revoke` exits 3 on (pre-flight M10).
  - `admin.Server.handle` recovers a panic, so nothing on the admin path can end port49d (M12).
  - `func peerAllowed(c net.Conn) (uint32, error)`; `func (s *Server) answer(req Request, uid uint32) Response`
  - `func adminRevoke(brk *broker.Broker) func(context.Context, admin.RevokeOp) (string, bool, error)`
  - `func adminRevocations(st store.Store) func(context.Context) (string, error)`

- [ ] **Step 1: The admin package's tests.** In `admin_test.go`, every `s.answer(req)` becomes
  `s.answer(req, 0)`, the unknown-op test expects "the ops are keys_diagnose, revoke and
  revocations", and add:

  ```go
  // revoke and revocations reach the funcs port49d gives, with the uid that
  // asked; without a broker they are refused, saying why.
  func TestRevokeOpsReachTheBroker(t *testing.T) {
  	var got RevokeOp
  	s := &Server{Held: &keyring.Held{}, Now: time.Now,
  		Revoke: func(_ context.Context, op RevokeOp) (string, bool, error) { got = op; return "revoked it", op.Lift, nil },
  		Revocations: func(context.Context) (string, error) { return "no revocation is in force", nil }}
  	r := s.answer(Request{Op: "revoke", Principal: "user:alice@example.com"}, 1000)
  	if r.Text != "revoked it" || got.Principal != "user:alice@example.com" || got.UID != 1000 || got.Lift {
  		t.Fatalf("%+v %+v", r, got)
  	}
  	if r := s.answer(Request{Op: "revoke", CertIssuer: "CN=Corp CA", CertSerial: "3f9a01", Lift: true}, 0); !r.Partial {
  		t.Fatalf("a partial answer must say so: %+v", r)
  	}
  	if got.Issuer != "CN=Corp CA" || got.Serial != "3f9a01" || !got.Lift {
  		t.Fatalf("%+v", got)
  	}
  	// A panic behind an op answers an error and leaves port49d running (M12).
  	boom := &Server{Held: &keyring.Held{}, Now: time.Now,
  		Revoke:      func(context.Context, RevokeOp) (string, bool, error) { panic("boom") },
  		Revocations: func(context.Context) (string, error) { return "", nil }}
  	if r := boom.answer(Request{Op: "revoke", Principal: "user:a@b"}, 0); !strings.Contains(r.Error, "internal error") {
  		t.Fatalf("%+v", r)
  	}
  	if r := s.answer(Request{Op: "revocations"}, 0); r.Text != "no revocation is in force" {
  		t.Fatalf("%+v", r)
  	}
  	none := &Server{Held: &keyring.Held{}, Now: time.Now}
  	if r := none.answer(Request{Op: "revoke", Principal: "user:a@b"}, 0); !strings.Contains(r.Error, "runs no broker") {
  		t.Fatalf("%+v", r)
  	}
  }
  ```

- [ ] **Step 2: port49d's run test.** In `cmd/port49d/admin_linux_test.go`, add a test shaped as
  `TestRunAnswersKeysDiagnoseOverTheAdminSocket` (same setup: `brokerConfig`, `writeRunConfig`,
  `withAdminSocket`, `run` in a goroutine, `waitFor` the two listening lines), then:

  ```go
  	pki := filepath.Dir(b.ClientCAFile) // brokerConfig wrote the lab PKI there (testpki.WriteLab)
  	alice, err := tls.LoadX509KeyPair(filepath.Join(pki, testpki.LabClientCert), filepath.Join(pki, testpki.LabClientKey))
  	if err != nil {
  		t.Fatal(err)
  	}
  	pool := x509.NewCertPool()
  	caPEM, _ := os.ReadFile(b.ClientCAFile)
  	pool.AppendCertsFromPEM(caPEM)
  	brokerAddr := regexp.MustCompile(`port49d: broker listening on (\S+)`).FindStringSubmatch(out.String())[1]
  	dial := func() *tls.Conn {
  		c, err := tls.Dial("tcp", brokerAddr, &tls.Config{Certificates: []tls.Certificate{alice}, RootCAs: pool,
  			MinVersion: tls.VersionTLS13, ServerName: "127.0.0.1"})
  		if err != nil {
  			t.Fatal(err)
  		}
  		t.Cleanup(func() { c.Close() })
  		return c
  	}
  	mint := func(c *tls.Conn) int {
  		body := `{"devices":["leaf1"]}`
  		fmt.Fprintf(c, "POST /v1/tokens HTTP/1.1\r\nHost: broker\r\nContent-Type: application/json\r\n"+
  			"Content-Length: %d\r\n\r\n%s", len(body), body)
  		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
  		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
  		if err != nil {
  			return 0
  		}
  		// Read to the end, so a second request on this connection starts
  		// at a response boundary and a 0 can only mean the broker closed it.
  		_, _ = io.Copy(io.Discard, resp.Body)
  		resp.Body.Close()
  		return resp.StatusCode
  	}
  	revoke := func(req admin.Request) admin.Response {
  		t.Helper()
  		c, err := net.Dial("unix", socket)
  		if err != nil {
  			t.Fatal(err)
  		}
  		defer c.Close()
  		json.NewEncoder(c).Encode(req)
  		var r admin.Response
  		if err := json.NewDecoder(c).Decode(&r); err != nil {
  			t.Fatal(err)
  		}
  		return r
  	}
  	heldConn := dial()
  	if code := mint(heldConn); code != 200 {
  		t.Fatalf("a mint before the revocation: %d", code)
  	}
  	r := revoke(admin.Request{Op: "revoke", Principal: "user:alice@example.com"})
  	if r.Error != "" || !strings.Contains(r.Text, "1 held broker connection(s) closed") {
  		t.Fatalf("%+v", r)
  	}
  	if code := mint(heldConn); code != 0 {
  		t.Fatalf("the held connection still answered after the revocation: %d", code)
  	}
  	if code := mint(dial()); code != http.StatusUnauthorized {
  		t.Fatalf("a new connection after the revocation: %d", code)
  	}
  	raw, err := os.ReadFile(b.RevocationsFile)
  	if err != nil || !strings.Contains(string(raw), `"user:alice@example.com"`) || !strings.Contains(string(raw), "uid") {
  		t.Fatalf("the file: %s %v", raw, err)
  	}
  	if r := revoke(admin.Request{Op: "revocations"}); !strings.Contains(r.Text, "principal user:alice@example.com since") {
  		t.Fatalf("%+v", r)
  	}
  	if r := revoke(admin.Request{Op: "revoke", Principal: "user:alice@example.com", Lift: true}); r.Error != "" {
  		t.Fatalf("%+v", r)
  	}
  	if code := mint(dial()); code != 200 {
  		t.Fatalf("a mint after the lift: %d", code)
  	}
  ```

  (`b` is the `*config.BrokerConfig` the test passed to `writeRunConfig`, which writes
  `b.RevocationsFile` as `revocations_file` (Task 9). `minimalPolicy` grants
  `user:alice@example.com`, the lab PKI's client, every device, and `writeRunConfig`'s inventory
  names `leaf1`.)

- [ ] **Step 3: Run them to see them fail.** `go test ./internal/daemon/admin/ ./cmd/port49d/ -run 'Revoke' -count=1`
  Expected: FAIL to compile.

- [ ] **Step 4: The admin package.** In `admin.go`: update the package comment ("serves one
  read-only operation, keys_diagnose" becomes "serves keys_diagnose, which is read-only, and revoke
  and revocations (plan 7a), which put a revocation in force or lift it: the same people can already
  rewrite the policy file and cut anyone's access"). Add to `Request`:

  ```go
  	// Principal, CertIssuer and CertSerial name what op "revoke" revokes,
  	// or with Lift lifts (plan 7a): a principal, or a certificate, not both.
  	Principal  string `json:"principal,omitempty"`
  	CertIssuer string `json:"cert_issuer,omitempty"`
  	CertSerial string `json:"cert_serial,omitempty"`
  	Lift       bool   `json:"lift,omitempty"`
  ```

  add

  ```go
  // RevokeOp is one `port49 revoke`, with the uid that asked (SO_PEERCRED),
  // which the revoke record names as its origin.
  type RevokeOp struct {
  	Principal, Issuer, Serial string
  	Lift                      bool
  	UID                       uint32
  }

  // opTimeout bounds a revocation, which walks every live context and token
  // key of what it revokes.
  const opTimeout = 60 * time.Second
  ```

  and to `Server`:

  ```go
  	// Revoke and Revocations answer `port49 revoke` (plan 7a). Nil when
  	// port49d runs no broker; the ops are then refused, saying so.
  	Revoke      func(ctx context.Context, op RevokeOp) (text string, partial bool, err error)
  	Revocations func(ctx context.Context) (string, error)
  ```

  and to `Response`:

  ```go
  	// Partial is a revocation or lift in force that did not finish or was
  	// not saved; `port49 revoke` exits 3 on it (plan 7a).
  	Partial bool `json:"partial,omitempty"`
  ```

  In `handle`, take the uid (`uid, err := peerAllowed(c)`), and after the request is decoded, for
  `revoke` and `revocations` extend the deadline: `_ = c.SetDeadline(time.Now().Add(opTimeout + 5*time.Second))`;
  then `_ = enc.Encode(s.answer(req, uid))`. Replace `answer` with:

  ```go
  func (s *Server) answer(req Request, uid uint32) (resp Response) {
  	// The admin socket's goroutines share the process with TACACS+: a
  	// panic behind an op is an answer, never the end of port49d (M12).
  	defer func() {
  		if r := recover(); r != nil {
  			log.Printf("port49d: admin socket: op %q failed: %v", printsafe.Line(req.Op, 40), r)
  			resp = Response{Error: "internal error; port49d's log says what"}
  		}
  	}()
  	switch req.Op {
  	case "keys_diagnose":
  		assigned := ""
  		if s.Assigned != nil {
  			assigned = s.Assigned(req.Device)
  		}
  		now := s.Now()
  		f, ok := keyring.Diagnose(s.Held, s.Keys, req.Device, assigned, now)
  		if !ok {
  			return Response{Error: fmt.Sprintf("port49d holds no unvalidated packet from %q since it started", req.Device)}
  		}
  		return Response{Text: f.Text(now), Finding: &f}
  	case "revoke", "revocations":
  		if s.Revoke == nil || s.Revocations == nil {
  			return Response{Error: "port49d runs no broker (no broker: block in port49d.yaml), so there is nothing to revoke"}
  		}
  		ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
  		defer cancel()
  		var text string
  		var partial bool
  		var err error
  		if req.Op == "revocations" {
  			text, err = s.Revocations(ctx)
  		} else {
  			text, partial, err = s.Revoke(ctx, RevokeOp{Principal: req.Principal, Issuer: req.CertIssuer,
  				Serial: req.CertSerial, Lift: req.Lift, UID: uid})
  		}
  		if err != nil {
  			return Response{Error: err.Error()}
  		}
  		return Response{Text: text, Partial: partial}
  	}
  	return Response{Error: "unknown op; the ops are keys_diagnose, revoke and revocations"}
  }
  ```

  (Add `log` and `internal/printsafe` to `admin.go`'s imports; the op name is the caller's text, so
  it is cut and made printable.) In `peer_linux.go`, `peerAllowed` returns `(uint32, error)`: `return cred.Uid, uidAllowed(cred.Uid,
  uint32(os.Geteuid()))`, and `0, err` on each earlier failure; in `peer_other.go`, `return 0,
  errNeedsLinux`.

- [ ] **Step 5: port49d's two funcs.** Append to `cmd/port49d/revocations.go`:

  ```go
  // adminRevoke is the admin socket's revoke op over brk (plan 7a). The
  // record's origin is the uid the socket read off the caller.
  func adminRevoke(brk *broker.Broker) func(context.Context, admin.RevokeOp) (string, bool, error) {
  	return func(ctx context.Context, op admin.RevokeOp) (string, bool, error) {
  		req := broker.RevokeRequest{Principal: op.Principal, Issuer: op.Issuer, Serial: op.Serial,
  			Origin: fmt.Sprintf("admin_socket uid %d", op.UID)}
  		if op.Lift {
  			rep, err := brk.Lift(ctx, req)
  			if err != nil {
  				return "", false, err
  			}
  			return rep.LiftedText(), rep.Partial(), nil
  		}
  		rep, err := brk.Revoke(ctx, req)
  		if err != nil {
  			return "", false, err
  		}
  		return rep.Text(), rep.Partial(), nil
  	}
  }

  // adminRevocations is the admin socket's revocations op.
  func adminRevocations(st store.Store) func(context.Context) (string, error) {
  	return func(ctx context.Context) (string, error) {
  		rs, err := st.ListRevocations(ctx)
  		if err != nil {
  			return "", err
  		}
  		return broker.RevocationsText(rs), nil
  	}
  }
  ```

  In `main.go`, where the admin server is built, add `if brk != nil { srv.Revoke, srv.Revocations =
  adminRevoke(brk), adminRevocations(st) }` before `go srv.Serve(ctx, aln)`, and change its start
  line to `port49d: admin socket on %s (port49 keys diagnose, port49 revoke)`. With a broker and no
  `admin_socket`, say instead, once at start (pre-flight M20):

  ```go
  	if brk != nil && cfg.AdminSocket == "" {
  		fmt.Fprintln(stderr, "port49d: broker: port49 revoke is unavailable: set admin_socket; until then, cut "+
  			"someone off by removing their grants from broker.policy_file")
  	}
  ```

  and add to Step 2's run test, or a sibling, a start with no `admin_socket` whose stderr holds
  `port49 revoke is unavailable`.

- [ ] **Step 6: Run them.** `go test ./internal/daemon/admin/ ./cmd/port49d/ -count=1 -race`
  Expected: PASS. Then `gofmt -w`, `make build && make test && make vet`.

- [ ] **Step 7: Commit.**

  ```bash
  git add internal/daemon/admin cmd/port49d
  git commit -m "feat(admin): revoke, lift and list revocations over the admin socket

  Ops revoke and revocations reach Broker.Revoke, Lift and the marks in force; the record's
  origin is the caller's uid (SO_PEERCRED). Without a broker the ops say there is nothing to
  revoke.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
  ```

---

### Task 11: `port49 revoke`

**Files:**
- Create: `cmd/port49/revoke.go`
- Modify: `cmd/port49/keys.go` (`keysDiagnose` uses the shared `askAdmin`)
- Modify: `cmd/port49/main.go` (`run`'s switch; `usage`)
- Test: `cmd/port49/revoke_linux_test.go` (new); `cmd/port49/keys_diagnose_linux_test.go` (unchanged,
  must pass)

**Interfaces:**
- Consumes: Task 10's ops and `admin.Request`.
- Produces:
  - `func revokeCmd(args []string, stdout, stderr io.Writer) int`
  - `func askAdmin(socket string, req admin.Request, wait time.Duration) (admin.Response, error)`
  - Usage lines:
    `port49 revoke [--socket PATH] (--principal PRINCIPAL | --cert FILE | --cert-issuer DN --cert-serial HEX) [--lift]`
    and `port49 revoke [--socket PATH] --list`, with the note `(exits 3 when the revocation is in
    force but incomplete or not saved)`.
  - Exit codes: 0 done, 1 refused or unreachable, 2 usage, 3 in force but partial (M10).

- [ ] **Step 1: The test.** Create `cmd/port49/revoke_linux_test.go`:

  ```go
  //go:build linux

  package main

  import (
  	"bytes"
  	"context"
  	"encoding/pem"
  	"os"
  	"path/filepath"
  	"strings"
  	"sync"
  	"testing"
  	"time"

  	"github.com/blanketfish/port49/internal/daemon/admin"
  	"github.com/blanketfish/port49/internal/keyring"
  	"github.com/blanketfish/port49/internal/testpki"
  )

  // port49 revoke sends one op to the admin socket and prints its answer;
  // --cert reads the issuer and serial the broker compares from the file.
  func TestRevokeAsksTheAdminSocket(t *testing.T) {
  	socket := filepath.Join(t.TempDir(), "port49d.sock")
  	ln, err := admin.Listen(socket)
  	if err != nil {
  		t.Fatal(err)
  	}
  	ctx, cancel := context.WithCancel(context.Background())
  	defer cancel()
  	// got is written by the admin server's goroutine and read here; the
  	// socket gives the race detector no happens-before edge (M4).
  	var mu sync.Mutex
  	var got []admin.RevokeOp
  	last := func() admin.RevokeOp {
  		mu.Lock()
  		defer mu.Unlock()
  		return got[len(got)-1]
  	}
  	partial := false
  	srv := &admin.Server{Held: &keyring.Held{}, Now: time.Now,
  		Revoke: func(_ context.Context, op admin.RevokeOp) (string, bool, error) {
  			mu.Lock()
  			defer mu.Unlock()
  			got = append(got, op)
  			return "revoked it", partial, nil
  		},
  		Revocations: func(context.Context) (string, error) { return "no revocation is in force", nil }}
  	go srv.Serve(ctx, ln)

  	var out, errb bytes.Buffer
  	if code := run([]string{"revoke", "--socket", socket, "--principal", "user:alice@example.com"}, &out, &errb); code != 0 ||
  		strings.TrimSpace(out.String()) != "revoked it" {
  		t.Fatalf("exit %d: %q %q", code, out.String(), errb.String())
  	}

  	now := time.Now()
  	ca, err := testpki.NewCA("Corp Issuing CA", now.Add(-time.Hour), now.Add(time.Hour))
  	if err != nil {
  		t.Fatal(err)
  	}
  	leaf, err := ca.Issue(testpki.Leaf{CommonName: "alice", Emails: []string{"alice@example.com"}, Client: true,
  		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
  	if err != nil {
  		t.Fatal(err)
  	}
  	certFile := filepath.Join(t.TempDir(), "alice.pem")
  	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Leaf.Raw}), 0o644); err != nil {
  		t.Fatal(err)
  	}
  	out.Reset()
  	if code := run([]string{"revoke", "--socket", socket, "--cert", certFile, "--lift"}, &out, &errb); code != 0 {
  		t.Fatalf("exit %d: %q", code, errb.String())
  	}
  	if op := last(); op.Issuer != leaf.Leaf.Issuer.String() || op.Serial != leaf.Leaf.SerialNumber.Text(16) || !op.Lift {
  		t.Fatalf("%+v", op)
  	}

  	out.Reset()
  	if code := run([]string{"revoke", "--socket", socket, "--list"}, &out, &errb); code != 0 ||
  		!strings.Contains(out.String(), "no revocation is in force") {
  		t.Fatalf("exit %d: %q", code, out.String())
  	}
  	mu.Lock()
  	partial = true
  	mu.Unlock()
  	if code := run([]string{"revoke", "--socket", socket, "--principal", "user:alice@example.com"}, &out, &errb); code != 3 {
  		t.Fatalf("a partial revocation must exit 3, got %d", code)
  	}
  	for _, bad := range [][]string{
  		{"revoke", "--socket", socket},
  		{"revoke", "--socket", socket, "--principal", "user:a@b", "--cert-serial", "1", "--cert-issuer", "CN=x"},
  		{"revoke", "--socket", socket, "--cert", certFile, "--cert-serial", "1"},
  		{"revoke", "--socket", socket, "--list", "--principal", "user:a@b"},
  		{"revoke", "--socket", socket, "--cert-serial", "1"},
  	} {
  		if code := run(bad, &out, &errb); code != 2 {
  			t.Errorf("%v: exit %d", bad, code)
  		}
  	}
  	errb.Reset()
  	if code := run([]string{"revoke", "--socket", socket + ".missing", "--principal", "user:a@b"}, &out, &errb); code != 1 ||
  		!strings.Contains(errb.String(), "is admin_socket set") {
  		t.Fatalf("exit %d: %q", code, errb.String())
  	}
  }
  ```

- [ ] **Step 2: Run it to see it fail.** `go test ./cmd/port49/ -run Revoke -count=1`
  Expected: FAIL (`port49 revoke` prints the usage and exits 2).

- [ ] **Step 3: The shared dial.** In `keys.go`, replace the dial, encode and decode in
  `keysDiagnose` with a call to a new function, placed in `revoke.go`:

  ```go
  // askAdmin sends req to port49d's admin socket and returns its one answer,
  // waiting at most wait. The socket answers port49d's user and root alone.
  func askAdmin(socket string, req admin.Request, wait time.Duration) (admin.Response, error) {
  	c, err := net.DialTimeout("unix", socket, 5*time.Second)
  	if err != nil {
  		return admin.Response{}, fmt.Errorf("%v (is admin_socket set in port49d.yaml, and are you port49d's user "+
  			"or root?)", err)
  	}
  	defer c.Close()
  	_ = c.SetDeadline(time.Now().Add(wait))
  	if err := json.NewEncoder(c).Encode(req); err != nil {
  		return admin.Response{}, err
  	}
  	var resp admin.Response
  	if err := json.NewDecoder(c).Decode(&resp); err != nil {
  		return admin.Response{}, err
  	}
  	return resp, nil
  }
  ```

  `keysDiagnose` then reads `resp, err := askAdmin(*socket, admin.Request{Op: "keys_diagnose", Device:
  fs.Arg(0)}, 10*time.Second)`, printing `port49 keys diagnose: <err>` and exiting 1 on an error,
  as before; `TestKeysDiagnoseAsksTheAdminSocket` must still pass unchanged. Trim the imports
  `keys.go` no longer uses (`net`, `encoding/json`, unless other code there needs them; M3).

- [ ] **Step 4: The command.** Create `cmd/port49/revoke.go` (with `askAdmin` above):

  ```go
  package main

  import (
  	"crypto/x509"
  	"encoding/json"
  	"encoding/pem"
  	"errors"
  	"flag"
  	"fmt"
  	"io"
  	"net"
  	"os"
  	"time"

  	"github.com/blanketfish/port49/internal/daemon/admin"
  )

  // revokeCmd is `port49 revoke` (spec §12; plan 7a): it asks port49d, over
  // its admin socket, to revoke or lift a principal or one certificate, or to
  // list the revocations in force.
  func revokeCmd(args []string, stdout, stderr io.Writer) int {
  	fs := flag.NewFlagSet("port49 revoke", flag.ContinueOnError)
  	fs.SetOutput(stderr)
  	socket := fs.String("socket", "/run/port49/port49d.sock", "port49d's admin_socket")
  	principal := fs.String("principal", "", "the principal, as the log names it: user:alice@example.com")
  	certFile := fs.String("cert", "", "a PEM file holding the certificate; its issuer and serial are read from it")
  	issuer := fs.String("cert-issuer", "", "the certificate's issuer, as the broker spells it (RFC 2253: CN=…,O=…)")
  	serial := fs.String("cert-serial", "", "the certificate's serial, in hex")
  	lift := fs.Bool("lift", false, "lift the revocation instead")
  	list := fs.Bool("list", false, "list the revocations in force")
  	if err := fs.Parse(args); err != nil {
  		return 2
  	}
  	if fs.NArg() != 0 {
  		fmt.Fprint(stderr, usage)
  		return 2
  	}
  	req := admin.Request{Op: "revoke", Principal: *principal, CertIssuer: *issuer, CertSerial: *serial, Lift: *lift}
  	if *certFile != "" {
  		if *issuer != "" || *serial != "" {
  			fmt.Fprintln(stderr, "port49 revoke: --cert, or --cert-issuer and --cert-serial; not both")
  			return 2
  		}
  		c, err := readCertificate(*certFile)
  		if err != nil {
  			fmt.Fprintln(stderr, "port49 revoke:", err)
  			return 1
  		}
  		req.CertIssuer, req.CertSerial = c.Issuer.String(), c.SerialNumber.Text(16)
  	}
  	byCert := req.CertIssuer != "" || req.CertSerial != ""
  	switch {
  	case *list:
  		if *principal != "" || byCert || *lift {
  			fmt.Fprintln(stderr, "port49 revoke: --list takes no principal, certificate or --lift")
  			return 2
  		}
  		req = admin.Request{Op: "revocations"}
  	case (*principal != "") == byCert:
  		fmt.Fprintln(stderr, "port49 revoke: name a principal (--principal), or a certificate (--cert, or "+
  			"--cert-issuer and --cert-serial); one of the two")
  		return 2
  	case byCert && (req.CertIssuer == "" || req.CertSerial == ""):
  		fmt.Fprintln(stderr, "port49 revoke: a certificate is named by --cert-issuer and --cert-serial, both")
  		return 2
  	}
  	resp, err := askAdmin(*socket, req, 70*time.Second)
  	if err != nil {
  		fmt.Fprintln(stderr, "port49 revoke:", err)
  		return 1
  	}
  	if resp.Error != "" {
  		fmt.Fprintln(stderr, "port49 revoke:", resp.Error)
  		return 1
  	}
  	fmt.Fprintln(stdout, resp.Text)
  	if resp.Partial {
  		// In force, but not finished or not saved: a script must not read
  		// this as done (pre-flight M10).
  		return 3
  	}
  	return 0
  }

  // readCertificate is the first certificate in a PEM file. A certificate is
  // public; it is read as a plain file.
  func readCertificate(path string) (*x509.Certificate, error) {
  	raw, err := os.ReadFile(path)
  	if err != nil {
  		return nil, err
  	}
  	for rest := raw; ; {
  		var blk *pem.Block
  		if blk, rest = pem.Decode(rest); blk == nil {
  			return nil, errors.New(path + " holds no PEM certificate")
  		}
  		if blk.Type == "CERTIFICATE" {
  			return x509.ParseCertificate(blk.Bytes)
  		}
  	}
  }
  ```

  In `main.go`, add `case "revoke": return revokeCmd(args[1:], stdout, stderr)` to `run`'s switch,
  and the two usage lines after `port49 keys diagnose [--socket PATH] DEVICE`.

- [ ] **Step 5: Run them.** `go test ./cmd/port49/ -count=1 -race`
  Expected: PASS. Then `gofmt -w`, `make build && make test && make vet`.

- [ ] **Step 6: Commit.**

  ```bash
  git add cmd/port49
  git commit -m "feat(cli): port49 revoke, over the admin socket

  Revoke or lift a principal or one certificate (--cert reads the issuer and serial the broker
  compares), or list the revocations in force. keys diagnose and revoke share one admin dial.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
  ```

---

### Task 12: (lab, on beehive) A revocation end to end on vEOS, the N9Kv, the C8000V and vJunos-router

**Files:**
- Create: `tests/lab/revoke_test.go` (`//go:build lab`)
- Create (by the run): `tests/lab/results/revoke-arista_eos.md`, `revoke-cisco_nxos.md`,
  `revoke-cisco_iosxe.md`, `revoke-juniper_vjunos-router.md`; the redacted captures under
  `tests/lab/evidence/`

**Interfaces:**
- Consumes: the lab harness (`eachPlatform`, `derivedConfig`, `stopDaemon`, `startDaemonWith`,
  `awaitTACACS`, `configPath`, `capture`, `mark`, `waitForRecords`, `recordsSince`, `summarize`,
  `result`, `shell`, `loginWithin`); plan 6b's `l29Mint`, `l29Outcome`, `l29Refused`, `l29Cell`,
  `labShell.runOrEnd`; plan 3's `agentPID`, `sliceBrokerURL`, `sliceRecords`, `str`, `sub`, `sha`; the slice's `slicePKIDir`, `sliceEmail`, `slicePrincipal`, `sliceUser`,
  `platformSessionAttributes`; `bin/port49 revoke` (Task 11).

**No register row.** What this run depends on of the devices is measured already: a FAIL on a
command keeps the session and refuses the command (the slice's denied command,
`tests/lab/results/slice-*.md`; L4's per-command FAIL, `L4-error-*.md`), a refused token login is
refused (the slice), and a Junos session never asks about a command once open (spec §13 decision 21;
L17, `L17-juniper_*.md`). The run is the end-to-end check of the mechanism this plan builds, as the
slice and spec §14's quarantine through a sync were. If it contradicts a doc, the doc is wrong
(register rule 4): fix it, cite the note, and say so in the commit.

- [ ] **Step 1: The test.** Create `tests/lab/revoke_test.go`:

  ```go
  //go:build lab

  package lab

  import (
  	"context"
  	"errors"
  	"fmt"
  	"os"
  	"os/exec"
  	"path/filepath"
  	"strconv"
  	"strings"
  	"syscall"
  	"testing"
  	"time"

  	"github.com/blanketfish/port49/internal/testpki"
  )

  const revokeClaim = "A revocation by principal or by certificate (`port49 revoke` over the admin socket, plan " +
  	"7a; spec §5.1.4) reaches a live SSH session and everything behind it: on a platform that authorizes each " +
  	"command the session's next command is refused and the session stays open; on Junos the open session keeps " +
  	"what it had at login (spec §13 decision 21), and the revocation names it as not reached; a token minted " +
  	"before the revocation and not yet spent is deleted, so its login is refused token_not_found; the agent's " +
  	"next mint is refused credential_revoked, which ends the agent; and after a lift a new login works."

  // revokeCLI runs bin/port49 revoke with args against socket and returns
  // its output and whether it exited 0.
  func revokeCLI(socket string, args ...string) (string, bool) {
  	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
  	defer cancel()
  	out, err := exec.CommandContext(ctx, filepath.Join(root, "bin", "port49"),
  		append([]string{"revoke", "--socket", socket}, args...)...).CombinedOutput()
  	return strings.TrimSpace(string(out)), err == nil
  }

  // revokeAgent is l29Agent with the agent's pid: a revocation ends the
  // agent on its own, and the run must see that it did (pre-flight I4).
  // stop ends it only if it is still running.
  func revokeAgent(t *testing.T) (sock string, pid int, stop func()) {
  	t.Helper()
  	pki := filepath.Join(root, slicePKIDir)
  	dir, err := os.MkdirTemp("", "p49revoke")
  	if err != nil {
  		t.Fatal(err)
  	}
  	sock = filepath.Join(dir, "a", "agent.sock")
  	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
  	defer cancel()
  	out, err := exec.CommandContext(ctx, filepath.Join(root, "bin", "port49"), "login", "--broker", sliceBrokerURL,
  		"--cert", filepath.Join(pki, testpki.LabClientCert), "--key", filepath.Join(pki, testpki.LabClientKey),
  		"--broker-ca", filepath.Join(pki, testpki.LabCA), "--socket", sock).CombinedOutput()
  	m := agentPID.FindSubmatch(out)
  	if err != nil || m == nil {
  		os.RemoveAll(dir)
  		t.Fatalf("port49 login: %v\n%s", err, out)
  	}
  	pid, _ = strconv.Atoi(string(m[1]))
  	return sock, pid, func() {
  		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
  			t.Errorf("stopping the agent (pid %d): %v", pid, err)
  		}
  		os.RemoveAll(dir)
  	}
  }

  // agentEnded waits up to 10 s for pid to exit.
  func agentEnded(pid int) bool {
  	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
  		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
  			return true
  		}
  	}
  	return false
  }

  // redeemReason is the reason on the last redeem record for sliceUser with
  // the token whose sha256 is sum, or "" for none.
  func redeemReason(recs []map[string]any, sum string) string {
  	reason := ""
  	for _, r := range sliceRecords(recs, "redeem", "") {
  		if str(sub(r, "auth"), "credential_sha256") == sum {
  			reason = str(r, "reason")
  		}
  	}
  	return reason
  }

  func TestRevokeEndToEnd(t *testing.T) {
  	eachPlatform(t, func(t *testing.T, l *lab) {
  		var failed []string
  		fail := func(format string, args ...any) { failed = append(failed, fmt.Sprintf(format, args...)) }
  		sessionOnly := strings.HasPrefix(l.p.name, "juniper_")

  		pki := filepath.Join(root, slicePKIDir)
  		if err := testpki.WriteLab(pki, sliceEmail, time.Now()); err != nil {
  			t.Fatal(err)
  		}
  		brokerYAML, err := os.ReadFile(filepath.Join(root, "tests", "lab", "slice", "broker.yaml"))
  		if err != nil {
  			t.Fatal(err)
  		}
  		socket := filepath.Join(root, "tests", "lab", "logs", "revoke-admin.sock")
  		// The revocations file is rewritten into the derived config's private
  		// directory, fresh at each start (privatePolicy; pre-flight I6).
  		cfg, err := l.derivedConfig("revoke", platformSessionAttributes[l.p.name],
  			string(brokerYAML)+"\nadmin_socket: "+socket+"\n")
  		if err != nil {
  			t.Fatal(err)
  		}
  		if err := l.stopDaemon(); err != nil {
  			t.Fatal(err)
  		}
  		if err := l.startDaemonWith(cfg, true); err != nil {
  			t.Fatalf("port49d would not start with the broker and the admin socket: %v", err)
  		}
  		if err := l.awaitTACACS(); err != nil {
  			t.Fatal(err)
  		}
  		defer func() {
  			if err := l.stopDaemon(); err != nil {
  				t.Errorf("could not stop the revoke daemon: %v", err)
  				return
  			}
  			std, err := l.configPath()
  			if err != nil {
  				t.Fatalf("derive this platform's daemon config: %v", err)
  			}
  			if err := l.startDaemonWith(std, true); err != nil {
  				t.Fatalf("could not put port49d back on the lab config: %v", err)
  			}
  		}()
  		stop := l.capture(t, "revoke")
  		defer stop()
  		off := l.mark()

  		// 1. A live session, and an unspent token beside it.
  		sock, pid, stopAgent := revokeAgent(t)
  		defer stopAgent()
  		_, tok1 := l29Mint(sock, l.p.node)
  		said, tok2 := l29Mint(sock, l.p.node)
  		if tok1 == "" || tok2 == "" {
  			t.Fatalf("the agent minted no token before the revocation: %s", said)
  		}
  		sh, err := l.shell(sliceUser, tok1)
  		if err != nil {
  			t.Fatalf("SSH login with the first token: %v\nrecords:%s", err, summarize(l.recordsSince(off)))
  		}
  		defer sh.Close()
  		before := l29Outcome(l.p.name, sh, "show version", fail, "before the revocation")

  		// 2. Revoke the principal.
  		revokedText, ok := revokeCLI(socket, "--principal", slicePrincipal)
  		if !ok {
  			fail("port49 revoke --principal: %s", revokedText)
  		}
  		if sessionOnly != strings.Contains(revokedText, "not reached") {
  			fail("the revocation's not-reached line: %q", revokedText)
  		}
  		after := l29Outcome(l.p.name, sh, "show version", fail, "after the revocation")
  		switch {
  		case sessionOnly && !strings.HasPrefix(after, "printed its output"):
  			fail("Junos: the open session did not keep what it had at login: %s", after)
  		case !sessionOnly && !strings.HasPrefix(after, "refused"):
  			fail("the next command was not refused: %s", after)
  		}
  		// The old token must be gone, not merely refused at the join: a
  		// token the revocation failed to delete is refused credential_revoked
  		// too, on this device, because its context is marked (pre-flight I5).
  		if _, err := l.loginWithin(sliceUser, tok2, 60*time.Second, "show version"); err == nil {
  			fail("the token minted before the revocation still logged in")
  		}
  		recs := l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
  			return redeemReason(rs, sha(tok2)) != ""
  		})
  		tok2Reason := redeemReason(recs, sha(tok2))
  		if tok2Reason != "token_not_found" {
  			fail("the old token's login was refused %q, not token_not_found: the token was not deleted", tok2Reason)
  		}
  		agentSaid, tok3 := l29Mint(sock, l.p.node)
  		if tok3 != "" || !strings.Contains(agentSaid, "revoked") {
  			fail("the agent's mint after the revocation: %q (a token: %v)", agentSaid, tok3 != "")
  		}
  		agentGone := agentEnded(pid)
  		if !agentGone {
  			fail("the agent (pid %d) was still running 10 s after its mint was refused credential_revoked", pid)
  		}

  		// 3. Lift, and a new login works.
  		liftText, ok := revokeCLI(socket, "--lift", "--principal", slicePrincipal)
  		if !ok {
  			fail("port49 revoke --lift: %s", liftText)
  		}
  		sock2, pid2, stopAgent2 := revokeAgent(t)
  		defer stopAgent2()
  		_, tok4 := l29Mint(sock2, l.p.node)
  		liftLogin := "no token"
  		if tok4 != "" {
  			if _, err := l.loginWithin(sliceUser, tok4, 150*time.Second, "show version"); err != nil {
  				fail("a login after the lift: %v", err)
  				liftLogin = "refused: " + err.Error()
  			} else {
  				liftLogin = "logged in and ran show version"
  			}
  		} else {
  			fail("no token after the lift")
  		}

  		// 4. Revoke the certificate the agent holds: its next mint is refused,
  		// and the agent ends.
  		certText, ok := revokeCLI(socket, "--cert", filepath.Join(pki, testpki.LabClientCert))
  		if !ok {
  			fail("port49 revoke --cert: %s", certText)
  		}
  		certSaid, tok5 := l29Mint(sock2, l.p.node)
  		if tok5 != "" || !strings.Contains(certSaid, "revoked") {
  			fail("the agent's mint after the certificate's revocation: %q", certSaid)
  		}
  		if !agentEnded(pid2) {
  			fail("the agent (pid %d) was still running after the certificate's revocation", pid2)
  		}
  		if out, ok := revokeCLI(socket, "--lift", "--cert", filepath.Join(pki, testpki.LabClientCert)); !ok {
  			fail("lifting the certificate: %s", out)
  		}

  		// The principal's revoke and lift name the principal; the
  		// certificate's name none, so they are counted by event (M18).
  		recs = l.waitForRecords(off, 60*time.Second, func(rs []map[string]any) bool {
  			return len(sliceRecords(rs, "revoke", "")) >= 2
  		})
  		certRevokes := 0
  		for _, r := range recs {
  			if str(r, "event") == "revoke" && str(sub(r, "revocation"), "by") == "cert" {
  				certRevokes++
  			}
  		}
  		if len(sliceRecords(recs, "revoke", "credential_revoked")) == 0 {
  			fail("no revoke record for the principal")
  		}
  		if certRevokes < 2 {
  			fail("%d revoke records for the certificate, not its revocation and its lift", certRevokes)
  		}
  		if !sessionOnly && len(sliceRecords(recs, "authorize_command", "credential_revoked")) == 0 {
  			fail("no authorize_command deny credential_revoked")
  		}
  		if len(sliceRecords(recs, "mint", "credential_revoked")) < 2 {
  			fail("fewer than two mint deny credential_revoked records")
  		}
  		obs := fmt.Sprintf("| Step | What happened |\n|---|---|\n"+
  			"| `show version` before the revocation | %s |\n"+
  			"| `port49 revoke --principal %s` | %s |\n"+
  			"| `show version` in the same session after it | %s |\n"+
  			"| a login with a token minted before it, unspent | refused, `%s` |\n"+
  			"| the agent's next mint | %s; the agent %s |\n"+
  			"| `port49 revoke --lift`, then a new agent, a mint and a login | %s |\n"+
  			"| `port49 revoke --cert` (the agent's certificate), then the agent's mint | %s |\n\n"+
  			"Records: %d revoke for the principal, %d for the certificate, %d authorize_command deny "+
  			"credential_revoked, %d mint deny credential_revoked.",
  			before, slicePrincipal, l29Cell(revokedText), after, tok2Reason, l29Cell(agentSaid),
  			map[bool]string{true: "exited", false: "**kept running**"}[agentGone], liftLogin, l29Cell(certSaid),
  			len(sliceRecords(recs, "revoke", "")), certRevokes,
  			len(sliceRecords(recs, "authorize_command", "credential_revoked")),
  			len(sliceRecords(recs, "mint", "credential_revoked")))
  		if len(failed) > 0 {
  			obs += "\n\n**Not as the claim says:**\n\n- " + strings.Join(failed, "\n- ")
  		}
  		l.result(t, "revoke", revokeClaim, obs)
  		if len(failed) > 0 {
  			t.Fatalf("%d step(s) not as claimed (the note records them): %v\nrecords:%s", len(failed), failed, summarize(recs))
  		}
  	})
  }
  ```

  Where a helper's name or signature differs on the tree (they are plan 3's and plan 6b's:
  `agentPID`, `sliceBrokerURL`, `str`, `sub`, `sha`, `sliceRecords`), fix the call minimally and say
  so in the report. A `redeem` record carries `auth.credential_sha256`, the hash of the presented
  token (spec §5.7), which is how the old token's login is told from another; compare it in the
  form the slice's `sliceObservation` joins a redeem to a mint by (bare hex from `sha`, or with the
  record's prefix if it carries one). Then
  `go vet -tags lab ./tests/lab/`.

- [ ] **Step 2: Pin, build, arm the watchdog.** `git worktree add --detach ../port49-lab-7a <sha>`
  (the commit with Step 1), `make build` there. Arm the stall watchdog (Running the lab, above)
  before the first deploy, and re-arm it after every wake.

- [ ] **Step 3: Run each platform.** From the worktree, one at a time:
  `PORT49_LAB_PLATFORMS=eos go test -tags lab ./tests/lab/ -run TestRevokeEndToEnd -count=1 -timeout 45m -v`,
  then `nxos`, `iosxe`, `vjunos` (each under `sg docker -c` if the session predates the docker
  group). After each, confirm no `port49d` holds `172.100.100.1:49`, no agent runs, the topology is
  destroyed, and read the note: a `**Not as the claim says:**` section is a finding to triage, never
  a pass.

- [ ] **Step 4: Evidence.** Copy the run's raw captures to the main checkout's
  `tests/lab/captures/`, run `make evidence` there, and confirm the labpcap audit passes. Remove the
  worktree.

- [ ] **Step 5: Commit.**

  ```bash
  git add tests/lab/revoke_test.go tests/lab/results/revoke-*.md tests/lab/evidence/
  git commit -m "test(lab): a revocation end to end on vEOS, the N9Kv, the C8000V and vJunos-router

  port49 revoke refused the next command of a live session on the three per-command platforms
  and left the Junos session as it was, naming it; an unspent token was deleted (token_not_found); the
  agent's next mint was refused credential_revoked and the agent exited; a lift let a new login through; a revoked
  certificate stopped minting. Run at <sha>.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
  ```

  (Write the message from what the notes say, not from this text, where they differ.)

---

### Task 13: Plan 7a as built

**Files:**
- Modify: `docs/superpowers/plans/README.md` (the status line; a "Plan 7a — As built" section after
  "Plan 7"'s split)
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`, `docs/design/2026-08-21-port49-design.md`
  only where Task 12's notes contradict them (register rule 4)

- [ ] **Step 1: The as-built section.** Under "Plan 7", after the D1 paragraph, add "### Plan 7a —
  As built": the branch, the ledger path, what differs from this plan's text task by task, the
  final review and fix wave, the rulings as made (decision 32, with any amendment), Task 12's
  outcome per image with its note, the operator notes below as amended, and "Carried, for later
  plans": to 7b, the refresh records' `unreached` field and CRL/OCSP marks; to 7c, the HTTP
  revocation over `Broker.Revoke` and self-revocation's shape (a principal revoking its own tokens
  without a standing mark); to 7d, `storetest.IdempotencyReservesOnce`, `TokenIndex` and
  `RevocationMarks` for the chosen backend, whether `broker.revocations_file` stays once the
  store persists, and the revocation's residual window (a redemption that removed its token before
  the delete and writes its context after the second pass), closed atomically in the store; to 7e, the listener and the marks in the separate broker process.

- [ ] **Step 2: The status line.** In the roadmap's status paragraph, after "7a written 2026-10-01
  (…)", add "; **executed <date>** on `feature/revocation-and-broker-limits`, reviewed per task and
  whole-branch (Plan 7a — As built, below)", and the merge when it happens.

- [ ] **Step 3: Check and commit.** `make test && make vet`.

  ```bash
  git add docs/superpowers/plans/README.md docs/design
  git commit -m "docs: plan 7a as built

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
  ```

---

## Operator-facing notes (for the pull request body)

- **New: `port49 revoke`.** `sudo port49 revoke --principal user:alice@example.com` ends a
  principal's sessions now: its held broker connections are closed, its live contexts revoked
  (the next command is refused on EOS, NX-OS and IOS-XE), its unspent tokens and receipts deleted,
  and every later mint refused until `port49 revoke --lift --principal …`. `--cert FILE` (or
  `--cert-issuer DN --cert-serial HEX`) does the same for one certificate, leaving the principal's
  other certificates working. `port49 revoke --list` shows what is in force. Junos sessions keep
  what they had at login; the output names each so you can close it on the device.
- **Turn on `admin_socket`.** Revocation is over port49d's admin socket (0600; port49d's user and
  root). It is off by default; set `admin_socket: /run/port49/port49d.sock` in `port49d.yaml`.
- **New required key: `broker.revocations_file`.** Where port49d keeps revocations so a restart
  forgets none (for example `/var/lib/port49/revocations.json`). port49d writes it; it and its
  directory must exist and be writable by port49d's user or root alone, and its name may not be a
  link. port49d creates it at the first start, with a marker `<file>.created` beside it; after that
  a missing file, or one that does not load, stops port49d starting: restore it, or write
  `{"revocations": []}` on purpose and revoke again. Back up both files with port49d's state.
  `port49_revocations_file_failed` is 1 while it cannot be written; alert on it.
- **`port49 revoke` exits 3** when the revocation is in force but incomplete or not saved to the
  file, so a script can tell; it shows a certificate's serial as the broker compares it (lower-case
  hex, no leading zeros), and accepts it with colons, `0x`, or a leading `-`.
- **A revocation does not expire.** The agent reconnects with the same key on its own, so only a
  lift undoes a revocation. For a stolen laptop: revoke the principal now; when the CA has issued a
  new certificate, revoke the old one by `--cert` and lift the principal.
- **New broker limits:** `broker.max_conns_per_principal` (default 4: a fifth held connection closes
  that principal's oldest) and `broker.max_pending_conns_per_source` (default 16 connections not yet
  authenticated per address; the next is reset). Logged-in operators behind one NAT are not counted
  against the source. Each agent holds one connection, so run at most four agents per principal or
  raise the cap: a fifth makes them close each other in turn, and on a hardware key each reconnect
  costs a touch. A source is one address; an IPv6 client rotating within its /64 counts as many.
- **New metrics:** `port49_broker_tls_handshake_failures_total{reason}` (`untrusted_chain`,
  `identity_refused`, `server_cert_refused`, `timeout`, `client_closed`, `protocol`),
  `port49_broker_connection_events_total{event}` (`source_cap_refused`, `principal_cap_evicted`,
  `revoked_closed`, `revoked_refused`), `port49_broker_connections{state}` (`pending`, `held`),
  `port49_broker_idempotency_refusals_total{outcome}`, `port49_revocations_total{by,outcome}`,
  `port49_revocations_in_force{by}`, `port49_revocations_file_failed`. A climb in
  `server_cert_refused` means agents do not trust the broker's certificate (a wrong `--broker-ca`, or
  an expired broker certificate).
- **New decision record:** `revoke` (`deny credential_revoked`, or `permit revocation_lifted`), one
  per `port49 revoke`, naming what it reached and the sessions it could not; `mint deny
  credential_revoked` names the principal and the certificate's fingerprint.
- **API:** `409 idempotency_in_progress` (with `Retry-After: 1`) when a request is retried under its
  `Idempotency-Key` while the first is still minting; the agent waits it out. A batch naming a device
  twice is `400 bad_request`. A revoked caller's connection is answered `401 credential_revoked` as
  it binds, with one `mint deny credential_revoked` record, and closed.
- **`port49 login` is refused for a revoked operator:** the agent's first request is answered `401
  credential_revoked`, and `port49 login` (or `port49 agent`) prints "… was revoked at <time>" and
  exits. A mark that lands after the agent's connection bound refuses its next mint, which ends the
  agent with the same reason; the next `port49 token` finds no agent. port49d says the refusal on
  stderr (rate-limited) and counts it (`revoked_refused`, `port49_decisions`).

## Self-review against the spec

- **Carried items (roadmap, "Plan 7"):** the atomic put-if-absent reservation — Tasks 2, 3; per-source
  limits on the broker listener — Task 6; a TLS handshake failure counter — Task 6; a per-principal
  cap — Task 6; a revocation reaching the held connection, refusing mints — Tasks 6, 7, 8; revocation
  deleting unspent tokens (plan 2's "largest remaining hole", plan 4b's "Hands to plan 7") — Tasks 4,
  8; revocation records naming the contexts they could not reach (decision 21, plan 4b I1) — Task 8;
  the store two processes can reach — **not built, by design**: Decision D1 (roadmap), with the
  interface and `storetest` properties built here for it. The rest of plan 7's carried list is
  assigned to 7b–7h in the roadmap's split.
- **Spec §5.1.4** (revocation by certificate, `issuer`/`serial`): Tasks 5, 8; by `sid`/`sub`: 7h.
  **§5.6 row 2**: Task 1, Task 8. **§5.7**: the event and reason, Task 1 first, Task 8 in code; no
  reason code invented. **§12**: `port49 revoke`, Tasks 1, 11. **§13 decision 15** (a token minted
  after a revocation lifts it): the mark keeps the broker from minting one until a lift, Task 7.
  **Decision 17** (the session is the held connection): unchanged; `auth_time` still the accept time,
  Task 6. **Decision 21**: the unreached list, Task 8; the Junos phase of Task 12.
- **Design §11** (per source before global): Task 6. **§12** (store record table, failure matrix):
  Task 1; the reservation, token index and marks, Tasks 2, 4, 5. **§17** (idempotency; every call a
  decision record; no API keys): Tasks 3, 7, 8.
- **Hard rules:** snake_case keys and metric names throughout (`revocations_file`,
  `max_conns_per_principal`, `token_keys`, `port49_broker_tls_handshake_failures_total`); no metric
  label names a device, a principal or a certificate; the log carries identity (principal, issuer,
  serial, fingerprint) and never a token, a reservation's holder or a response; a peer's text is
  printed only through `printsafe.Line`.
- **Placeholder scan:** every code step carries its code; the two places that send the implementer to
  the tree (Task 3's agent stub helper, Task 12's lab helpers) name the existing helpers to follow.
- **Type consistency:** `Reservation`/`Reserve`/`Release` (Task 3) as used by the broker; `ConnCloser`
  (Task 6, `CloseHeld` and `Revoked`) as `Broker.Conns` (Task 8) and fed at start (Task 9); `RevokeRequest`/`RevokeReport`/`Text`/`LiftedText`/
  `RevocationsText` (Task 8) as used in Tasks 10 and 11; `admin.RevokeOp`, `Server.Revoke`'s `(string, bool, error)` and `Response.Partial` (Task 10) as used in
  Task 11; `loadRevocations`/`restoreRevocations`' `created` result (Task 9); the store methods' signatures (Tasks 2, 4, 5) as called in Tasks 3, 4, 7, 8, 9.
